---
name: Cassie Cay Photography
description: Madison-area family photographer's portfolio; bright, airy, joyful
colors:
  primary: "#98bec8"
  primary-hover: "#84acb6"
  primary-pale: "#e5eff1"
  primary-deep: "#4a7783"
  primary-deep-hover: "#3a606a"
  ink-heading: "#404040"
  ink-body: "#606060"
  ink-muted: "#888888"
  surface-bright: "#ffffff"
  surface-dark: "#181818"
  surface-darker: "#151515"
  surface-darkest: "#111111"
typography:
  hero:
    fontFamily: "liebegerda, Georgia, serif"
    fontSize: "clamp(30px, 5vw, 50px)"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "normal"
  display:
    fontFamily: "Montserrat, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: "38px"
    letterSpacing: "-0.5px"
  headline:
    fontFamily: "Montserrat, sans-serif"
    fontSize: "26px"
    fontWeight: 700
    lineHeight: "36px"
    letterSpacing: "-0.5px"
  title:
    fontFamily: "Montserrat, sans-serif"
    fontSize: "18px"
    fontWeight: 700
    lineHeight: "28px"
    letterSpacing: "normal"
  body:
    fontFamily: "Muli, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: "28px"
    letterSpacing: "normal"
  label:
    fontFamily: "Montserrat, sans-serif"
    fontSize: "13px"
    fontWeight: 700
    lineHeight: "1"
    letterSpacing: "normal"
rounded:
  none: "0"
  sm: "4px"
  full: "30px"
spacing:
  xs: "10px"
  sm: "20px"
  md: "30px"
  lg: "150px"
components:
  button-primary:
    backgroundColor: "{colors.primary-deep}"
    textColor: "{colors.surface-bright}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "17px 25px"
  button-primary-hover:
    backgroundColor: "{colors.primary-deep-hover}"
    textColor: "{colors.surface-bright}"
    rounded: "{rounded.none}"
    padding: "17px 25px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.primary}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "17px 25px"
  button-ghost-hover:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface-bright}"
    rounded: "{rounded.none}"
    padding: "17px 25px"
  filter-pill:
    backgroundColor: "transparent"
    textColor: "{colors.ink-muted}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "0"
  filter-pill-active:
    backgroundColor: "transparent"
    textColor: "{colors.primary}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "0"
  navbar-over-hero:
    backgroundColor: "transparent"
    textColor: "{colors.surface-bright}"
    typography: "{typography.title}"
  navbar-scrolled:
    backgroundColor: "{colors.surface-bright}"
    textColor: "{colors.ink-heading}"
    typography: "{typography.title}"
  form-input:
    backgroundColor: "{colors.surface-bright}"
    textColor: "{colors.ink-body}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "12px 15px"
---

# Design System: Cassie Cay Photography

## 1. Overview

**Creative North Star: "The Saturday Morning Album"**

The site reads like a family photo album on a Saturday morning. Slow, considered, light-filled. A stranger's handwriting in the captions. Pages that turn one at a time. The photographs were taken by someone who knows you. The album was bound by someone who cares. Nothing on the page is in a hurry, nothing is selling you a package, nothing reads as commodity.

The system rejects two specific failure modes named in PRODUCT.md. First, the Squarespace-template photographer aesthetic (Brine, Foster, Wells, and their imitators) which has saturated the market with serif-logo-over-hero-photo, three-column services grids, and Instagram embed footers. Second, the bargain or chain studio aesthetic (Walmart, JCPenney, Olan Mills) with watermarked thumbnails and "package pricing" tables. Both fail for the same reason: anonymity. The strongest counter-design move on this site is unmistakable personhood. Cassie's face, voice, and words sit on the page; the chrome stays out of the way.

Visually the system is quiet. Pure Linen Page surfaces and Album Cover dark surfaces. A single accent in Madison Lakeshore seafoam carries every interactive state. Three fonts, three jobs, no decoration. The photographs do the heavy lifting; the frame is honest.

**Key Characteristics:**
- Album metaphor: page-by-page, considered, intimate, sentimental without saccharine
- One accent (Madison Lakeshore #98bec8); no secondary or tertiary color roles
- Three-font system: Liebe Gerda (hero wordmark only), Montserrat (chrome), Muli (body)
- Flat by default; depth comes from photographs, not chrome
- Quiet utility: UI is the frame, photos are the picture
- Local-not-generic: Madison and Waunakee, not "any photographer in any city"

## 2. Colors: The Album Palette

A single accent (seafoam) sits inside a neutral album-page palette. There is no secondary or tertiary color role; everything else is ink and paper.

### Primary
- **Madison Lakeshore** (`#98bec8`): the only accent in the system. Carries link color, button fill, filter-pill active state, focus borders on form inputs, navbar nav-link hover and active states. Named for the Madison lakes (Mendota, Monona) that define the city Cassie shoots in. The seafoam is the page-decoration ink, never used on photographs as overlays or as gradients.
- **Lakeshore at Dusk** (`#84acb6`): the same hue stepped down for button hover, deeper interactive state. The accent slows when you touch it.
- **First Light** (`#e5eff1`): the palest tint of the same hue. Used for text-selection background. Reserved for restrained ambient highlight; never a section background.
- **Lake at Twilight** (`#4a7783`): the contrast-safe button fill. Same Lakeshore hue family stepped dark enough that white text clears WCAG AA (4.86:1). Used wherever chrome needs white-on-color and the bright Madison Lakeshore would fail contrast.
- **Lake at Midnight** (`#3a606a`): button hover for Lake at Twilight. Same hue, one step deeper (6.83:1, AAA-grade on white).

### Neutral
- **Caption Ink** (`#404040`): the darkest type color. Headings, navbar text on light surfaces, lead paragraphs. A handwritten-caption darkness, never pure black.
- **Soft Slate** (`#606060`): body paragraph text. The medium grey of typed reading copy.
- **Pencil Note** (`#888888`): muted secondary type. Filter-pill inactive state, meta labels. The lightest legible ink.
- **Linen Page** (`#ffffff`): primary surface. The white of the album page.
- **Album Cover** (`#181818`): dark sectional wrapper background, used on the About and Portfolio sections. The dark cloth-bound book cover that lets bright photographs pop.
- **Cloth Binding** (`#151515`): the footer surface, slightly deeper than the cover.
- **Inner Spine** (`#111111`): the sub-footer, the deepest surface in the system. Reserved for the very bottom.

### Named Rules

**The One-Accent Rule.** The Madison Lakeshore hue family is the only accent family on the site. No second color joins. No gradient, no co-accent for "variety", no "hover blue" that diverges from the brand hue. State and contrast variation happen within the family (`#98bec8` → `#84acb6` → `#4a7783` → `#3a606a`), never by introducing a new hue.

**The Contrast-Locked Accent Rule.** Madison Lakeshore (`#98bec8`) is the surface presence of the brand, but its lightness fails WCAG AA on white text and on white as text. For any chrome that requires text contrast (button fills, focus indicators, body-text link color on light backgrounds), reach for Lake at Twilight (`#4a7783`), which clears 4.86:1 on white. The bright accent stays decorative; the deep accent does the readable work. Two shades of one accent, never two accents.

**The Photograph-Is-Not-A-Surface Rule.** Madison Lakeshore never overlays a photograph. It does not tint a hero image, never bleeds over a portrait, never appears as a duotone treatment. The seafoam belongs to chrome (links, buttons, pills, borders); the photographs belong to themselves.

**The Album-Page Rule.** Linen Page (#ffffff) is paper. Album Cover (#181818) is binding. They alternate by section, never blend. There is no "soft grey background" intermediate surface; sections are either bright or dark.

## 3. Typography

**Display script:** Liebe Gerda (Adobe Typekit, italic) — hero wordmark only.
**Title sans:** Montserrat (locally hosted; weights 400/500/700).
**Body sans:** Muli (Google Fonts; weights 300/400/600/700).

**Character:** A script-italic wordmark opens the album cover. Below it, a no-fuss Montserrat carries every label, button, and section title. Muli does the reading. Three fonts, three jobs, no overlap.

### Hierarchy
- **Hero** (Liebe Gerda italic, 700, clamp(30px, 5vw, 50px), line-height 1): the wordmark "Cassie Cay Photography" on the hero. Appears nowhere else in the system.
- **Display** (Montserrat 700, 28px / 38px, letter-spacing -0.5px): section titles ("A Little About Me", "Featured Photos", "Services", "Contact").
- **Headline** (Montserrat 700, 26px / 36px, letter-spacing -0.5px): h1 fallback when not the section title.
- **Title** (Montserrat 700, 18px / 28px): smaller titles, navbar nav-link, section-title-upper variant when uppercased.
- **Body** (Muli 400, 16px / 28px, color Soft Slate): paragraphs, default text. Cap line length at 65 to 75 characters; Bootstrap container widths roughly land here at desktop.
- **Lead** (Montserrat 400-500, 18-20px): introductory paragraph in About (`.lead.larger`).
- **Label** (Montserrat 700, 13px / 1, often uppercase): buttons, filter-pills, hero tagline (with letter-spacing 3px).

### Named Rules

**The Three-Font Rule.** The system uses exactly three fonts: Liebe Gerda for the hero wordmark, Montserrat for all chrome (nav, buttons, section titles, filter pills, labels), and Muli for body reading text. No fourth font joins. No fifth font sneaks in because "this section is special".

**The Wordmark-Only Rule.** Liebe Gerda italic is reserved for "Cassie Cay Photography" on the hero. It does not appear in section titles, decorative pull-quotes, taglines, section ornament, or anywhere else. The wordmark is the only place this font has earned its place.

**The Uppercase Chrome Rule.** Buttons, filter pills, the hero tagline, and the navbar use uppercase Montserrat. This is the signal "this is interactive chrome or a label". Body copy, headings, and lead paragraphs are sentence case. Uppercase and sentence case never mix in the same component.

## 4. Elevation

The system is flat. Buttons have no shadow at rest. Portfolio items have no card shadow. The hero is a full-bleed photograph; nothing floats above it. The only shadow in the entire system is a 1-pixel hairline that appears on the navbar when the page scrolls past the hero (`box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1)`), so the navbar stays legible against content beneath it.

Depth is conveyed by the photographs themselves. A portrait composed with shallow depth-of-field, a hero crop with natural-light atmosphere, a portfolio thumbnail with real spatial recession: that is where the z-axis lives. The chrome refuses to compete.

### Shadow Vocabulary
- **Navbar Hairline** (`box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1)`): appears only when the navbar scrolls into solid state. The single permitted shadow.

### Named Rules

**The Photograph-Carries-The-Z-Axis Rule.** Depth comes from the photograph, not the UI. Buttons sit flat on the page. Cards sit flat on the page. The only allowed shadow is the navbar hairline on scroll. If a designer reaches for a card shadow, the right answer is almost always "use a bigger photograph instead".

**The No-Glassmorphism Rule.** Backdrop-filter blur is forbidden on cards, modals, overlays, and the navbar. Glass surfaces age fast and read as decorative; the album does not have a glass page.

## 5. Components

### Buttons
- **Shape:** square corners (radius 0). The theme exposes `.btn-rounded` (4px) and `.btn-full-rounded` (30px) variants. Both are forbidden on this site.
- **Primary:** Lake at Twilight fill (`#4a7783`), Linen Page text (`#ffffff`), Montserrat 700 13px uppercase, padding 17px / 25px, margin-bottom 10px, margin-right 5px when grouped. Lake at Twilight (not Madison Lakeshore) is the button fill so that white text clears WCAG AA contrast.
- **Hover / Focus:** background transitions to Lake at Midnight (`#3a606a`) over 150ms ease-in-out. No box-shadow on focus; the color change is the affordance.
- **Sizes:** `.btn-s` 15px / 23px padding, `.btn-l` 19px / 30px padding.
- **Ghost (`.btn-border`):** transparent fill, 2px Madison Lakeshore border, Madison Lakeshore text. Hover fills with the accent.

### Filter Pills (portfolio category filter)
- **Style:** Montserrat 700 13px uppercase, no background, no border, no padding. Spaced by 20px horizontal margin between siblings.
- **State:** default text in Pencil Note (`#888`). Active and hover shift to Madison Lakeshore. No underline, no fill, no chip outline.
- **Separator:** a 3-pixel circle (`background: rgba(21, 21, 21, 0.25)`) sits between each pill via `::after`. The last item omits the dot. Distinctive system signature; carry forward in future filter UIs on this site.

### Cards / Portfolio Items
- **Layout:** Muuri grid, 4 columns at >= 1024px, 3 columns at 768-1023px, 2 columns at 575-767px, 1 column below that. No gutters between cells (`calc(25% - 0px)`); photographs sit edge-to-edge.
- **Background:** the photograph itself. There is no card body, no border, no shadow, no caption strip. A figure wraps a picture wraps an anchor that opens GLightbox.
- **Hover overlay:** `.overlay.overlay2` provides a subtle dimming on hover, a hint that the photograph is clickable. No icon, no caption, no zoom button.
- **Border:** none.
- **Internal Padding:** none.

### Inputs / Form Fields
- **Style:** Bootstrap defaults, with focus border in Madison Lakeshore (`border-color: #98bec8`). White background, Soft Slate text, 4-pixel border radius (`{rounded.sm}`).
- **Focus:** border-color shifts to Madison Lakeshore. No glow, no transform.
- **Error:** browser-native Constraint Validation API messages; no custom red banner.
- **reCAPTCHA Enterprise badge** is hidden via `.grecaptcha-badge { visibility: hidden; }` per Google's guidance for inline branding.

### Navigation
- **Over hero (transparent state):** background `none`, nav-link color Linen Page (`#ffffff`), Montserrat 700 13px uppercase with letter-spacing normal. Logo image (`cassiecaylogobw2`) sits at left, padding 25px top and bottom.
- **Scrolled (solid state):** background Linen Page, nav-link color Caption Ink (`#404040`), the single permitted Navbar Hairline shadow underneath.
- **Mobile:** hamburger trigger opens an off-canvas drawer (`offcanvas-start`) with vertical nav-links at 0.8rem 1.5rem padding.
- **Items:** Home, About, Portfolio, Services, Schedule, Contact. The duplicate "Schedule" / "Contact" anchors both point at `#contact`.

### Hero Overlay (signature component)
- **Position:** absolute, vertically centered, anchored 40px from the right edge. Text right-aligned. Not centered, not bottom-anchored, not bleeding across the full width.
- **Content:** Liebe Gerda italic wordmark ("Cassie Cay Photography") above an uppercase Montserrat 500 13-16px tagline ("Madison, Wisconsin Portrait Photographer") with letter-spacing 3px.
- **Color:** Linen Page (`#ffffff`) over the photograph. No text-shadow, no scrim. The photo is composed for the overlay.
- **Behavior:** the embla slider underneath crossfades over 800ms ease-in-out. The overlay stays put; only the photograph behind it changes.

### Named Rules

**The One-Action Rule.** Each section has at most one button. Contact has "Send Message". About has no button. Portfolio has no button. The hero has no button. Buttons appear only where action is genuinely required, which on this site means the contact form alone.

**The Square-Button Rule.** Buttons are square (radius 0). The `.btn-rounded` and `.btn-full-rounded` theme variants are forbidden. Square reads as honest, photographic, and album-page-edge. Rounded reads as a 2014 SaaS landing page.

**The Hero-Stays-Right Rule.** The hero overlay is right-anchored. It does not migrate to center, to bottom, to left, or to a card with a backdrop blur. The right-anchored position is the distinctive identity gesture of this site.

## 6. Do's and Don'ts

### Do:

- **Do** keep the Madison Lakeshore hue family as the only accent family on the site. Madison Lakeshore (`#98bec8`) is the decorative surface (links, borders, decorative hover, active filter pills, form-input focus border). Lake at Twilight (`#4a7783`) is the contrast-safe text-bearing variant (button fills, white-on-color chrome). Same hue, two jobs.
- **Do** let photographs carry the page. Crop wide. Place them on Linen Page or against Album Cover dark wrappers. Give them whole-screen moments. The photographs are the argument.
- **Do** reserve Liebe Gerda italic for the "Cassie Cay Photography" wordmark on the hero. Nowhere else.
- **Do** use Montserrat 700 uppercase for chrome that needs label-like presence: nav, buttons, section titles, filter pills, hero tagline.
- **Do** use Muli for everything readable: paragraphs, captions, list items.
- **Do** honor `prefers-reduced-motion`: the hero slider stops crossfading and serves a static image; GLightbox transitions become instant.
- **Do** write subject-specific alt text on every photograph. "Tender mother kisses sleeping newborn baby with coral bow in bright Madison Wisconsin portrait session" beats "image" every time.
- **Do** keep the navbar transparent over the hero and let it transition to solid Linen Page with the hairline shadow on scroll. Both states are honest.
- **Do** keep the hero overlay anchored to the right edge of the photograph at 40px (15px on mobile). It is a signature.

### Don't:

- **Don't** use the Squarespace-template photographer aesthetic. No serif-logo-over-centered-hero-photo, no three-column services grid with stock icons, no Instagram embed footer. PRODUCT.md names Brine, Foster, and Wells; refuse any pattern that reads as one of those templates.
- **Don't** use the bargain or chain studio aesthetic. No watermarked thumbnails, no "package pricing" tables, no JCPenney-mall posing language in copy, no heavy-retouch skin softening, no fake fabric backdrops.
- **Don't** introduce gradient text (`background-clip: text` over a gradient background). Single solid color always.
- **Don't** introduce side-stripe borders (`border-left` or `border-right` greater than 1px as a colored accent on cards, callouts, list items, or alerts). Use full borders, background tints, or nothing.
- **Don't** introduce glassmorphism. No `backdrop-filter: blur(...)` on cards, modals, overlays, or the navbar.
- **Don't** introduce a hero video loop. The embla still-image crossfade is the entire hero motion vocabulary.
- **Don't** introduce parallax-fade hero copy. The hero overlay is static and right-anchored.
- **Don't** introduce scripty wedding-blog typography in section titles, decorative quotes, or chrome. Liebe Gerda stays on the wordmark; nowhere else.
- **Don't** introduce a fourth font.
- **Don't** add a button to a section that doesn't need one. Trust is built quietly; the site is a credibility layer, not a conversion funnel.
- **Don't** introduce a card shadow, a portfolio-thumbnail shadow, a hover-lift transform, or any "elevation" beyond the single permitted Navbar Hairline.
- **Don't** introduce hero metric templates (big number, small label, supporting stats). This is a photography portfolio, not a SaaS landing page.
- **Don't** introduce duplicate same-sized service cards with icon plus heading plus body. PRODUCT.md's anti-references explicitly call this out.
