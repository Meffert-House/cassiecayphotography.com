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
 */

import { parse } from 'node-html-parser';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

const projectRoot = process.cwd();
const distRoot = resolve(projectRoot, 'dist');

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
  return (
    /^(https?:)?\/\//.test(path) || // http(s):// or protocol-relative //
    path.startsWith('#') ||
    path.startsWith('data:') ||
    path.startsWith('mailto:') ||
    path.startsWith('tel:') ||
    path.startsWith('javascript:') ||
    path.startsWith('blob:')
  );
}

/**
 * Resolve an HTML reference to an absolute path inside dist/.
 * Strips query strings and fragments; treats a leading "/" as dist-root.
 */
function resolveDistPath(ref) {
  const clean = ref.split('#')[0].split('?')[0].trim();
  if (!clean) return null;
  const relative = clean.startsWith('/') ? clean.slice(1) : clean;
  return resolve(distRoot, relative);
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

  return refs;
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
  const missing = [];

  for (const ref of refs) {
    if (isExternalOrInline(ref.path)) continue;
    const key = `${ref.path}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const target = resolveDistPath(ref.path);
    if (!target || !existsSync(target)) {
      missing.push(ref);
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
      `Built-output reference check FAILED: ${totalMissing} missing asset(s). ` +
        `The build produced a dist that references files it did not emit — ` +
        `these would 404 in production. Check vite.config.js static-copy dest paths.`
    );
    process.exit(1);
  }

  console.log(`All ${totalChecked} built references resolve inside dist/ - no broken assets.`);
  process.exit(0);
}

main();
