import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'node-html-parser';

const generator = fileURLToPath(new URL('./generate-sitemap.js', import.meta.url));
const image = 'images-optimized/jpeg/full/cassiecay-F1.jpg';
function fixture(html, includeImage = true) {
  const root = mkdtempSync(join(tmpdir(), 'photo-sitemap-'));
  try {
    mkdirSync(join(root, 'dist', dirname(image)), { recursive: true });
    if (html !== null) writeFileSync(join(root, 'dist/index.html'), html);
    if (includeImage) writeFileSync(join(root, 'dist', image), 'photo');
    const result = spawnSync(process.execPath, [generator], { cwd: root, encoding: 'utf8' });
    return { ...result, read: name => readFileSync(join(root, 'dist', name), 'utf8'), root };
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}
const portfolio = links => `<section id="portfolio"><div class="portfolio-item">${links}</div></section>`;

test('image sitemap lists only unique, published portfolio links with supported fields', () => {
  const f = fixture(`<a href="images-optimized/jpeg/full/orphan.jpg">outside gallery</a>${portfolio(`<a href="${image}">one</a><a href="/${image}">duplicate</a><a href="https://other.example/photo.jpg">external</a>`)}`);
  try {
    assert.equal(f.status, 0, f.stderr);
    const xml = f.read('image-sitemap.xml');
    assert.equal((xml.match(/<image:loc>/g) || []).length, 1);
    assert.ok(xml.includes(`https://cassiecayphotography.com/${image}`));
    assert.doesNotMatch(xml, /orphan|other\.example|caption|geo_location|lastmod/);
    assert.doesNotMatch(f.read('page-sitemap.xml') + f.read('sitemap.xml'), /lastmod|priority|changefreq/);
    assert.match(f.read('page-sitemap.xml'), /<loc>https:\/\/cassiecayphotography.com\/<\/loc>/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

for (const [name, html, includeImage] of [
  ['missing build', null, true],
  ['empty gallery', portfolio(''), true],
  ['missing published image', portfolio(`<a href="${image}">photo</a>`), false],
]) {
  test(`sitemap generation fails for ${name}`, () => {
    const f = fixture(html, includeImage);
    try { assert.equal(f.status, 1); assert.match(f.stderr, /Sitemap generation failed/); }
    finally { rmSync(f.root, { recursive: true, force: true }); }
  });
}

test('structured offers match the visible menu and currency, including hourly event pricing', () => {
  const html = parse(readFileSync(new URL('../index.html', import.meta.url), 'utf8'));
  const data = html.querySelectorAll('script[type="application/ld+json"]').map(script => JSON.parse(script.text));
  const business = data.find(item => item['@type'] === 'LocalBusiness');
  const services = data.find(item => item['@type'] === 'Service');
  assert.equal(services.provider['@id'], business['@id']);
  const offers = services.hasOfferCatalog.itemListElement;
  const headings = html.querySelectorAll('#services h3');
  assert.equal(offers.length, headings.length);
  headings.forEach((heading, index) => {
    const offer = offers[index];
    assert.equal(offer.itemOffered.name, heading.text);
    const visiblePrice = heading.parentNode.querySelector('.lead').text;
    const price = offer.priceSpecification || offer;
    assert.equal(price.price, visiblePrice.match(/\$(\d+\.\d{2})/)[1]);
    assert.equal(price.priceCurrency, 'USD');
    assert.equal(price.unitCode === 'HUR', visiblePrice.includes('per hour'));
  });
});
