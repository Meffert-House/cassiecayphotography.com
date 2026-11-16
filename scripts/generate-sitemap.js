/** Generate canonical page and image sitemaps from the built portfolio. */
import { SitemapStream, streamToPromise } from 'sitemap';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parse } from 'node-html-parser';

const SITE_URL = 'https://cassiecayphotography.com';
const DIST_DIR = 'dist';

async function generateSitemap() {
  const htmlPath = resolve(DIST_DIR, 'index.html');
  // Missing build output must fail, rather than publish an index pointing to a
  // missing image sitemap or silently discard the site's portfolio.
  const html = parse(readFileSync(htmlPath, 'utf8'));
  const images = new Set();
  for (const link of html.querySelectorAll('#portfolio .portfolio-item a[href]')) {
    const url = new URL(link.getAttribute('href'), `${SITE_URL}/`);
    if (url.origin !== SITE_URL || !url.pathname.startsWith('/images-optimized/jpeg/full/')) continue;
    if (!existsSync(resolve(DIST_DIR, url.pathname.slice(1)))) {
      throw new Error(`Portfolio image missing from build: ${url.pathname}`);
    }
    images.add(url.href);
  }
  if (images.size === 0) throw new Error(`No portfolio image links found in ${htmlPath}`);

  const stream = new SitemapStream({ hostname: SITE_URL, xmlns: { image: true } });
  // Google supports image:loc; the former caption/geo_location tags are retired.
  stream.write({ url: '/', img: [...images].map(url => ({ url })) });
  stream.end();
  writeFileSync(resolve(DIST_DIR, 'image-sitemap.xml'), await streamToPromise(stream));

  // Omit optional lastmod: a rebuild (including dependency-only changes) does
  // not establish when the page or its images were significantly updated.
  writeFileSync(resolve(DIST_DIR, 'page-sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${SITE_URL}/</loc></url>
</urlset>`);
  writeFileSync(resolve(DIST_DIR, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>${SITE_URL}/page-sitemap.xml</loc></sitemap>
  <sitemap><loc>${SITE_URL}/image-sitemap.xml</loc></sitemap>
</sitemapindex>`);
  console.log(`Generated canonical page and image sitemaps (${images.size} portfolio images).`);
}

export { generateSitemap };
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  generateSitemap().catch(error => {
    console.error('Sitemap generation failed:', error);
    process.exitCode = 1;
  });
}
