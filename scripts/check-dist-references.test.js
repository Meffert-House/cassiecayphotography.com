/**
 * Tests for check-dist-references.js: each case builds a throwaway project with a
 * dist/ and runs the checker there (it reads dist/ from the working directory).
 * Run: npm test
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHECKER = join(dirname(fileURLToPath(import.meta.url)), 'check-dist-references.js');

// files: { 'dist/index.html': '...', 'package.json': '...' } -> { status, output }
function runChecker(files) {
  const root = mkdtempSync(join(tmpdir(), 'dist-check-'));
  try {
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), body);
    }
    const r = spawnSync(process.execPath, [CHECKER], { cwd: root, encoding: 'utf-8' });
    return { status: r.status, output: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const page = body => `<!doctype html><html><head><title>t</title></head><body>${body}</body></html>`;

test('a page whose links and assets all resolve passes', () => {
  const r = runChecker({
    'dist/index.html': page('<section id="about"></section><a href="#about">a</a><a href="/">home</a><img src="images/a.jpg">'),
    'dist/images/a.jpg': 'x',
  });
  assert.equal(r.status, 0, r.output);
});

test('../ cannot reach a repository file outside dist/', () => {
  const r = runChecker({ 'dist/index.html': page('<a href="../package.json">p</a>'), 'package.json': '{}' });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /MISSING: \.\.\/package\.json/);
});

test('an escaped ../ (..%2f) cannot reach outside dist/ either', () => {
  const r = runChecker({ 'dist/index.html': page('<img src="..%2fpackage.json">'), 'package.json': '{}' });
  assert.equal(r.status, 1, r.output);
});

test('../ inside dist/ resolves like a browser (clamped at the site root)', () => {
  const r = runChecker({ 'dist/index.html': page('<img src="../images/a.jpg">'), 'dist/images/a.jpg': 'x' });
  assert.equal(r.status, 0, r.output);
});

test('page-qualified #fragment to a missing id fails', () => {
  for (const href of ['index.html#missing', '/#missing', '/index.html#missing', './index.html?x=1#missing']) {
    const r = runChecker({ 'dist/index.html': page(`<section id="about"></section><a href="${href}">x</a>`) });
    assert.equal(r.status, 1, `${href}: ${r.output}`);
    assert.match(r.output, /a href \(anchor\)/, href);
  }
});

test('page-qualified #fragment to an existing id passes, also on another page', () => {
  const r = runChecker({
    'dist/index.html': page('<section id="about"></section><a href="index.html#about">a</a><a href="/#about">b</a>'),
    'dist/404.html': page('<a href="/index.html#about">back</a><a href="index.html#contact">c</a><a name="contact"></a>'),
  });
  assert.equal(r.status, 1, r.output); // #contact is an <a name> on 404.html, not on index.html
  assert.match(r.output, /index\.html#contact/);
  const ok = runChecker({
    'dist/index.html': page('<section id="about"></section><a href="index.html#about">a</a>'),
    'dist/404.html': page('<a href="/index.html#about">back</a>'),
  });
  assert.equal(ok.status, 0, ok.output);
});

test('a #fragment on a non-HTML asset is not checked as an anchor', () => {
  const r = runChecker({ 'dist/index.html': page('<a href="docs/guide.pdf#page=2">pdf</a>'), 'dist/docs/guide.pdf': 'x' });
  assert.equal(r.status, 0, r.output);
});

test('a missing linked page still fails', () => {
  const r = runChecker({ 'dist/index.html': page('<a href="gone.html#x">x</a>') });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /MISSING: gone\.html#x/);
});

test('a link to a directory without a trailing slash fails (no file there)', () => {
  const r = runChecker({ 'dist/index.html': page('<a href="images">x</a>'), 'dist/images/a.jpg': 'x' });
  assert.equal(r.status, 1, r.output);
});

test('backslash host forms point at another host, not at dist/', () => {
  const r = runChecker({ 'dist/index.html': page('<img src="\\\\cdn.example/x.jpg"><img src="/\\cdn.example/y.jpg">') });
  assert.equal(r.status, 0, r.output);
});
