/**
 * Built-Output Reference Checker
 *
 * Validates that every locally-referenced asset in the BUILT pages
 * (dist/index.html, dist/404.html) actually resolves to a file inside dist/.
 *
 * Why this exists separately from check-references.js:
 *   check-references.js validates the SOURCE index.html against the SOURCE
 *   tree, and it only looks at images/links. It does NOT look at <script src>
 *   or <link rel="stylesheet">, and it cannot see how the build copies/rewrites
 *   assets. In 2026-05 a vite-plugin-static-copy v3->v4 major bump silently
 *   changed `dest` semantics, double-nesting every script to
 *   dist/style/js/style/js/... The source check still passed, so the build
 *   shipped a dist where every <script src="style/js/..."> 404'd in production
 *   (carousel, lightbox, masonry and scroll-to-top all dead). This check closes
 *   that gap: it runs against the real built output and fails the build if any
 *   referenced asset is missing.
 *
 * It also checks internal links (<a href>) on the built pages, so an edit that
 * breaks navigation never reaches S3: a local link must resolve to a file in
 * dist/ ("/" and "dir/" mean the index.html there), and a "#section" link --
 * same-page or page-qualified ("index.html#about", "/#about") -- must name an
 * element id that exists on the page it points to.
 *
 * References resolve the way a browser resolves them against the page URL, so
 * "../" can never climb out of dist/ (the site root has no parent), and the
 * resolved file must sit inside dist/: a file outside the published artifact
 * (e.g. ../package.json) is never counted as present.
 */

import { parse } from 'node-html-parser';
import { readFileSync, existsSync, statSync } from 'fs';
import { resolve, sep } from 'path';

const projectRoot = process.cwd();
const distRoot = resolve(projectRoot, 'dist');

// Stand-in origin for browser-style URL resolution of a page's references.
const SITE = 'https://site.invalid/';

// Built pages whose references must all resolve inside dist/.
const PAGES = ['index.html', '404.html'];

// link rel values that point at a fetched local asset (vs. external hints like
// preconnect/dns-prefetch/canonical, which name origins/URLs, not dist files).
const ASSET_LINK_RELS = new Set([
  'stylesheet',
  'icon',
  'shortcut icon',
  'apple-touch-icon',
  'mask-icon',
  'preload',
  'modulepreload',
  'manifest',
]);

function isExternalOrInline(path) {
  // Any URL scheme (https:, mailto:, tel:, sms:, data:, ...; case-insensitive) or
  // protocol-relative //host is not a dist file; neither is a same-page #fragment.
  return /^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith('//') || path.startsWith('#');
}

/**
 * Resolve an HTML reference on `page` the way a browser would (relative to the
 * page URL; query string and fragment dropped) to an absolute path inside dist/.
 * Returns { file, fragment } or null when it cannot name a dist file.
 */
function resolveDistRef(ref, page) {
  let url;
  try {
    url = new URL(ref.trim(), SITE + page);
  } catch {
    return null; // unparseable URL: reported as missing
  }
  // "\\host/x" and "/\\host/x" are another host to a browser: not a dist file.
  if (url.origin !== new URL(SITE).origin) return { external: true };
  let relative;
  try {
    relative = decodeURIComponent(url.pathname.slice(1)); // "my%20photo.jpg" is the file "my photo.jpg"
  } catch {
    return null; // malformed %-escape: reported as missing
  }
  // "/" or "dir/" is the index.html in that directory.
  const file = resolve(distRoot, relative === '' || relative.endsWith('/') ? `${relative}index.html` : relative);
  if (file !== distRoot && !file.startsWith(distRoot + sep)) return null; // outside the published artifact
  let fragment = url.hash.slice(1);
  try {
    fragment = decodeURIComponent(fragment);
  } catch {
    // malformed %-escape: compare it as written (reported if no id matches)
  }
  return { file, fragment };
}

// Element ids (and <a name>) on a parsed page: the targets a "#fragment" can name.
function anchorIds(root) {
  const ids = new Set(root.querySelectorAll('[id]').map(el => el.getAttribute('id')));
  for (const el of root.querySelectorAll('a[name]')) ids.add(el.getAttribute('name'));
  return ids;
}

const idCache = new Map();
function idsOfFile(file) {
  if (!idCache.has(file)) idCache.set(file, anchorIds(parse(readFileSync(file, 'utf-8'))));
  return idCache.get(file);
}

function parseSrcset(srcset) {
  if (!srcset) return [];
  return srcset
    .split(',')
    .map(entry => entry.trim().split(/\s+/)[0]) // path is first token; descriptor (800w/2x) follows
    .filter(Boolean);
}

function extractReferences(html) {
  const root = parse(html);
  const refs = [];
  const push = (type, path) => {
    if (path) refs.push({ type, path });
  };

  // Scripts and stylesheets/preloads — the asset classes the source checker
  // never inspected, and exactly what the static-copy regression broke.
  for (const s of root.querySelectorAll('script[src]')) push('script src', s.getAttribute('src'));
  for (const l of root.querySelectorAll('link[href]')) {
    const rel = (l.getAttribute('rel') || '').trim().toLowerCase();
    if (ASSET_LINK_RELS.has(rel)) push(`link rel=${rel}`, l.getAttribute('href'));
  }

  // Images and <picture> sources.
  for (const img of root.querySelectorAll('img')) {
    push('img src', img.getAttribute('src'));
    for (const p of parseSrcset(img.getAttribute('srcset'))) push('img srcset', p);
  }
  for (const source of root.querySelectorAll('source')) {
    for (const p of parseSrcset(source.getAttribute('srcset'))) push('source srcset', p);
  }

  // Template background-image hook used across this theme.
  for (const el of root.querySelectorAll('[data-image-src]')) push('data-image-src', el.getAttribute('data-image-src'));

  // Internal links: other pages, lightbox full-size images, downloads.
  for (const a of root.querySelectorAll('a[href]')) push('a href', a.getAttribute('href'));

  return refs;
}

// Same-page "#section" links whose target id is not on the page. A bare "#" is a
// script hook (no target), so it is allowed.
function brokenAnchors(root) {
  const ids = anchorIds(root);
  const broken = [];
  for (const a of root.querySelectorAll('a[href^="#"]')) {
    let frag = a.getAttribute('href').slice(1);
    try {
      frag = decodeURIComponent(frag);
    } catch {
      // malformed %-escape: compare it as written (reported if no id matches)
    }
    if (frag && !ids.has(frag)) broken.push({ type: 'a href (anchor)', path: `#${frag}` });
  }
  return broken;
}

function checkPage(page) {
  const htmlPath = resolve(distRoot, page);
  if (!existsSync(htmlPath)) {
    // 404.html is optional; index.html is mandatory.
    if (page === 'index.html') {
      return { page, fatal: `Built page missing: dist/${page} (did the build run?)`, missing: [], checked: 0 };
    }
    return null;
  }

  const html = readFileSync(htmlPath, 'utf-8');
  const refs = extractReferences(html);
  const seen = new Set();
  const missing = brokenAnchors(parse(html));

  for (const ref of refs) {
    if (isExternalOrInline(ref.path)) continue;
    const key = `${ref.path}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const target = resolveDistRef(ref.path, page);
    if (target && target.external) continue;
    // Must be a file: S3 serves no directory listing for "dir" without a trailing slash.
    if (!target || !existsSync(target.file) || !statSync(target.file).isFile()) {
      missing.push(ref);
      continue;
    }
    // A link to "#section" on another (or the same) built page: the id must exist there.
    if (ref.type === 'a href' && target.fragment && /\.html?$/i.test(target.file) && !idsOfFile(target.file).has(target.fragment)) {
      missing.push({ type: 'a href (anchor)', path: ref.path });
    }
  }

  return { page, fatal: null, missing, checked: seen.size };
}

function main() {
  console.log('Checking built-output references in dist/...\n');

  if (!existsSync(distRoot)) {
    console.error('No dist/ directory found. Run `npm run build` first.');
    process.exit(1);
  }

  const results = PAGES.map(checkPage).filter(Boolean);
  let totalChecked = 0;
  let totalMissing = 0;
  let fatal = false;

  for (const result of results) {
    if (result.fatal) {
      console.error(`  ${result.fatal}`);
      fatal = true;
      continue;
    }
    totalChecked += result.checked;
    console.log(`  dist/${result.page}: ${result.checked} local references`);
    for (const ref of result.missing) {
      totalMissing++;
      console.error(`    MISSING: ${ref.path}  [${ref.type}]`);
    }
  }

  console.log('');

  if (fatal || totalMissing > 0) {
    console.error(
      `Built-output reference check FAILED: ${totalMissing} missing asset(s) or link(s). ` +
        `The build produced a dist that references files it did not emit, or links ` +
        `to a #section that is not on the page — these would break in production. ` +
        `Check vite.config.js static-copy dest paths and the page's links/ids.`
    );
    process.exit(1);
  }

  console.log(`All ${totalChecked} built references resolve inside dist/ - no broken assets.`);
  process.exit(0);
}

main();
