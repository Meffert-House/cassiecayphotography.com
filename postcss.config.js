import purgecss from '@fullhuman/postcss-purgecss'
import autoprefixer from 'autoprefixer'
import cssnano from 'cssnano'

// PurgeCSS trims the unused bulk of full Bootstrap from the bundled stylesheet.
// The risk on this site is classes that never appear in the HTML because they are
// toggled by JS or injected by a library at runtime (Bootstrap offcanvas/collapse,
// Muuri grid, GLightbox lightbox, Embla, the sticky-header clone). Two defenses:
//   1. Scan the vendor JS too -- Bootstrap/Muuri/GLightbox reference their own class
//      names as string literals there, so PurgeCSS discovers most of them.
//   2. A generous safelist as a backstop. Over-keeping only costs a few KB; under-
//      keeping breaks an interaction, so this errs toward keeping.
const purge = purgecss({
  content: [
    './index.html',
    './404.html',
    './style/js/**/*.js',
  ],
  // Capture Bootstrap-style class tokens (word chars, hyphens, colons, slashes).
  defaultExtractor: (content) => content.match(/[A-Za-z0-9-_/:]+(?<!:)/g) || [],
  safelist: {
    standard: [
      'active', 'show', 'showing', 'hide', 'hiding', 'fade', 'collapse',
      'collapsing', 'collapsed', 'disabled', 'mobile', 'fixed', 'is-selected',
      'is-active', 'loaded', 'open', 'html', 'body',
    ],
    deep: [
      /^offcanvas/, /^modal/, /^collaps/, /^dropdown/, /^carousel/, /^navbar/,
      /^banner--/, /^embla/, /^quote-/, /^muuri/, /^filter-/, /^portfolio/,
      /^nav-wrapper/, /^hamburger/, /^btn/, /^scroll/, /^hero-/, /^skip-/,
      /^glightbox/, /^gslide/, /^goverlay/, /^gprev/, /^gnext/, /^gclose/,
      /^gbtn/, /^gloader/, /^gcontainer/, /^gslider/, /^gdesc/, /^desc-/,
      /^zoomable/, /^dragging/, /^gscrollbar/, /^gfade/, /^gzoom/,
    ],
    greedy: [
      /muuri/, /glightbox/, /gslide/, /goverlay/, /offcanvas/, /modal/,
      /embla/, /backdrop/, /is-selected/, /is-active/,
    ],
  },
})

export default {
  plugins: [
    purge,
    autoprefixer(),
    cssnano({
      preset: ['default', {
        // Preserve important comments (licenses)
        discardComments: {
          removeAll: false,
        },
      }],
    }),
  ],
}
