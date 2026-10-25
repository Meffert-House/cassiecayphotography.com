# Cassie Cay Photography - Project Instructions

Photography portfolio site for Cassie Cay Photography (Cassie Meffert). Single-page static site built with Vite, deployed to AWS S3/CloudFront.

## Commands

```bash
npm ci                     # Install dependencies (use this, not npm install)
npm run dev                # Local dev server (localhost:3000)
npm run build              # prebuild (image optimization) -> vite build -> postbuild (sitemap + dist validation)
npm run preview             # Serve the built dist/ locally
npm run validate:html      # HTML structural validation (dup IDs, malformed attrs)
npm run validate:refs      # Check source references resolve in the source tree
npm run validate:dist      # Check built dist/ pages reference no missing assets (runs in postbuild)
npm run validate:images    # Check image sizes (non-blocking)
npm run validate:staged    # Combined HTML + reference validation with friendly errors (runs pre-commit via husky)
```

There is no test framework. The validation scripts above serve as the test suite. Always run `npm ci && npm run build && npm run validate:html && npm run validate:refs` before opening PRs.

`validate:dist` runs automatically after every `npm run build` (via `postbuild`) and fails the build if a built page references a script/stylesheet/image that the build did not emit -- the guard added after a `vite-plugin-static-copy` major bump silently double-nested asset paths and 404'd the entire JS layer in production. `validate:refs` (source-level) cannot catch that class of bug; `validate:dist` (output-level) can.

`npm run build` also runs `prebuild` (`scripts/optimize-images.js`) first, so a full build re-derives `images-optimized/` from `images/` every time -- expect it to take a while if source images changed.

## Architecture

**Single HTML entry point.** `index.html` is the entire site -- all sections (hero, portfolio, services, about, contact, etc.) live in one file, no client-side routing or templating. `404.html` is the only other page. Both are declared as separate Rollup inputs in `vite.config.js`.

**Styling is not run through PostCSS by Vite's normal pipeline.** `style/style.css` is a large, hand-authored stylesheet (Bootstrap + custom rules) copied to `dist/` as a static asset via `vite-plugin-static-copy`, *not* imported/bundled by Vite. `postcss.config.js` (PurgeCSS + autoprefixer + cssnano) exists for a separate optimization pass -- when touching CSS, check whether that pass needs re-running/re-verifying, since PurgeCSS's safelist is the only thing keeping JS-toggled classes (Bootstrap offcanvas/modal, Muuri grid, GLightbox, Embla) from being stripped.

**Vendor JS is external, not bundled.** Bootstrap, Embla Carousel, GLightbox, and Muuri (`style/js/*.js`) are marked `external` in Rollup config and copied as static files, loaded via `<script>` tags in `index.html`. Only `style/js/custom-scripts.js` is site-specific logic, and it gets a content-hash query string (`?v=<md5>`) injected at build time by the `cacheBustStaticScripts` Vite plugin in `vite.config.js`, since it's served as a static file rather than a fingerprinted bundle.

**Image pipeline is a build-time, source-controlled transform, not a CMS.** `scripts/optimize-images.js` reads `images/` (originals) and generates `images-optimized/` with AVIF/WebP/JPEG variants at `full/1800w/1200w/800w` widths -- this runs as `prebuild` locally and also as the separate `process-images.yml` GitHub Actions workflow when new photos are pushed. `images-optimized/` is what actually ships (copied wholesale via static-copy); `images/` originals are *not* deployed. New photos are dropped in `new-photos/{hero,portfolio,services}/` for processing -- see `EDITING-GUIDE.md` for the non-technical workflow Cassie follows.

**Design system source of truth lives outside the code.** `PRODUCT.md` (strategy/brand) and `DESIGN.md` (colors, typography, components) define the visual system; `DESIGN.json` is a structured/machine-readable export of the same tokens. Read `PRODUCT.md` and `DESIGN.md` before any visual change.

**Pre-commit validation is layered for a non-technical maintainer.** `.husky/pre-commit` runs `validate:staged`, which combines HTML structural validation and reference checking with plain-language error output, since Cassie (the site owner) edits `index.html` directly through GitHub's web UI as described in `EDITING-GUIDE.md`.

## Key Conventions

- **Conventional commits**: `type(scope): description` (e.g., `fix(gallery): correct lightbox z-index`)
- **Do NOT modify `infrastructure/`** -- CDK stacks are managed separately
- **Do NOT modify `images/`** -- image processing is handled by the `process-images.yml` workflow
- **Image optimization**: New photos go through `process-images.yml` which handles resizing, WebP conversion, and HTML snippet generation
- **Single-page site**: `index.html` is the main entry point. Stylesheets in `style/`, JS in `style/js/` and inline in `index.html`.
- **Deployment**: Auto-deploys to AWS via GitHub Actions on push to `main`

## Design Context

Strategic and visual design context lives at the project root:

- `PRODUCT.md` -- strategic (audience, brand personality, anti-references, design principles)
- `DESIGN.md` -- visual (color tokens, typography, components); the source of truth for the site's visual system

**Register**: brand (photography portfolio; design IS the product).
**Audience**: Madison-area families arriving via referral.
**Outcome**: credibility layer for word-of-mouth, not a hard-sell funnel.

Five design principles (full version in `PRODUCT.md`):

1. The photos are the argument
2. Trust is built quietly
3. Bright, not moody
4. Local, not generic
5. Cassie is a real human, not a logo

For design work, read `PRODUCT.md` and `DESIGN.md` first -- they define the strategy and the visual system to hold changes against.

## AWS Configuration

**IMPORTANT:** This is a personal project deployed to a personal AWS account, NOT a Roundhouse business account.

Before running any AWS or CDK commands, set the AWS profile:

```bash
export AWS_PROFILE=personal
```

| Setting | Value |
|---------|-------|
| AWS Account ID | 241654197557 |
| AWS Profile | `personal` |
| Region | us-east-1 |

## Infrastructure

The CDK infrastructure is in the `infrastructure/` directory.

### Deploy Infrastructure

```bash
export AWS_PROFILE=personal
cd infrastructure
npm install
npx cdk bootstrap aws://241654197557/us-east-1
npx cdk deploy --all
```

### Stacks

- `CassiePhotoGitHubOidcStack` - GitHub OIDC provider and deployment role
- `CassiePhotoStaticSiteStack` - S3, CloudFront, Route53, ACM certificate

## Deployment

The site auto-deploys via GitHub Actions when pushing to `main`. The workflow uses OIDC authentication (no AWS credentials stored in GitHub).

Manual deployment is not typically needed, but if required:

```bash
export AWS_PROFILE=personal
aws s3 sync . s3://cassiecayphotography.com-site-content \
  --exclude ".git/*" --exclude ".github/*" --exclude "infrastructure/*"
```

## Domain

- Domain: cassiecayphotography.com
- DNS: Route 53 (in personal AWS account)

## Google Analytics (GA4)

| Setting | Value |
|---------|-------|
| Measurement ID | `G-TQDYZMGR2H` |
| GA4 Property ID | 269447426 |
| GCP Quota Project | `cassiecayphotographycom` |
| Dashboard | https://analytics.google.com/analytics/web/#/a485983p269447426/reports/intelligenthome |

Use the `/analytics` command (`.claude/commands/analytics.md`) to query GA4 data via API.
