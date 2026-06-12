/**
 * Custom Scripts - Cassie Cay Photography
 * Extracted from scripts.js - only includes initializations used by the site
 *
 * Phase 7 JavaScript Cleanup - Created 2026-01-20
 * Phase 15 jQuery Removal - Converted to vanilla JS 2026-01-21
 */
document.addEventListener('DOMContentLoaded', function() {
    'use strict';
    /*-----------------------------------------------------------------------------------*/
    /*	HERO SLIDER (Embla Carousel) — honors prefers-reduced-motion, WCAG 2.2.2 pause
    /*-----------------------------------------------------------------------------------*/
    var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var heroSlider = document.querySelector('.hero-slider');
    if (heroSlider) {
        var viewportNode = heroSlider.querySelector('.embla__viewport');
        var slides = heroSlider.querySelectorAll('.embla__slide');
        var pauseBtn = heroSlider.querySelector('.hero-pause');

        // Skip autoplay plugin entirely under reduced motion
        var emblaPlugins = [];
        if (!prefersReducedMotion) {
            emblaPlugins.push(EmblaCarouselAutoplay({
                delay: 6000,
                stopOnInteraction: false,
                stopOnMouseEnter: false,
                playOnInit: true
            }));
        }

        var emblaApi = EmblaCarousel(
            viewportNode,
            {
                loop: true,
                watchDrag: false  // No manual navigation per requirements (Embla v7+ renamed `draggable`)
            },
            emblaPlugins
        );

        // Handle fade effect via CSS class
        function setSelectedClass() {
            var selected = emblaApi.selectedScrollSnap();
            slides.forEach(function(slide, index) {
                if (index === selected) {
                    slide.classList.add('is-selected');
                } else {
                    slide.classList.remove('is-selected');
                }
            });
        }

        emblaApi.on('select', setSelectedClass);
        setSelectedClass(); // Set initial state

        // Hero pause / play control (WCAG 2.2.2 — autoplay > 5s needs user control)
        if (pauseBtn) {
            if (prefersReducedMotion) {
                // Nothing to pause; hide the control
                pauseBtn.hidden = true;
            } else {
                pauseBtn.addEventListener('click', function() {
                    var autoplay = emblaApi.plugins().autoplay;
                    if (!autoplay) return;
                    var paused = pauseBtn.getAttribute('aria-pressed') === 'true';
                    if (paused) {
                        autoplay.play();
                        pauseBtn.setAttribute('aria-pressed', 'false');
                        pauseBtn.setAttribute('aria-label', 'Pause hero slideshow');
                    } else {
                        autoplay.stop();
                        pauseBtn.setAttribute('aria-pressed', 'true');
                        pauseBtn.setAttribute('aria-label', 'Play hero slideshow');
                    }
                });
            }
        }
    }
    /*-----------------------------------------------------------------------------------*/
    /*	STICKY HEADER (Vanilla JS - replaces Headhesive)
    /*-----------------------------------------------------------------------------------*/
    (function() {
        var navbar = document.querySelector('.navbar');
        if (!navbar) return;

        // Create sentinel at activation point (350px from top)
        var sentinel = document.createElement('div');
        sentinel.id = 'sticky-sentinel';
        sentinel.style.cssText = 'position:absolute;top:350px;height:1px;width:100%;pointer-events:none;';
        document.body.insertBefore(sentinel, document.body.firstChild);

        // Clone navbar for sticky version. DESIGN.md §5 specifies the scrolled
        // state is light theme (Linen Page background + Caption Ink text + hairline
        // shadow), so the cloned navbar swaps inverse-text/nav-wrapper-dark for
        // nav-wrapper-light. Without this, the clone inherits the hero's inverse
        // styling and renders white-on-white once it sticks.
        var clone = navbar.cloneNode(true);
        clone.classList.add('banner--clone', 'fixed', 'nav-wrapper-light');
        clone.classList.remove('absolute', 'nav-wrapper-dark', 'inverse-text');
        document.body.insertBefore(clone, document.body.firstChild);

        // Update cloned hamburger to target the shared offcanvas (not a clone)
        var cloneHamburger = clone.querySelector('.hamburger');
        if (cloneHamburger) {
            cloneHamburger.setAttribute('data-bs-toggle', 'offcanvas');
            cloneHamburger.setAttribute('data-bs-target', '#offcanvasNav');
        }

        // Observe sentinel for sticky activation
        var stickyObserver = new IntersectionObserver(function(entries) {
            var entry = entries[0];
            if (!entry.isIntersecting) {
                clone.classList.add('banner--stick');
                clone.classList.remove('banner--unstick');
            } else {
                clone.classList.remove('banner--stick');
                clone.classList.add('banner--unstick');
            }
        }, { threshold: 0 });

        stickyObserver.observe(sentinel);

        // Scroll direction detection for show/hide (NAV-03)
        var lastScrollY = 0;
        var ticking = false;

        function onScroll() {
            var currentScrollY = window.pageYOffset;

            if (clone.classList.contains('banner--stick')) {
                if (currentScrollY > lastScrollY && currentScrollY > 400) {
                    clone.classList.add('banner--hidden');
                } else {
                    clone.classList.remove('banner--hidden');
                }
            }

            lastScrollY = currentScrollY;
            ticking = false;
        }

        window.addEventListener('scroll', function() {
            if (!ticking) {
                requestAnimationFrame(onScroll);
                ticking = true;
            }
        }, { passive: true });
    })();
    /*-----------------------------------------------------------------------------------*/
    /*	OFFCANVAS NAVIGATION (Mobile drawer navigation)
    /*-----------------------------------------------------------------------------------*/
    (function() {
        var offcanvasEl = document.getElementById('offcanvasNav');
        if (!offcanvasEl) return;

        // Get offcanvas instance
        var offcanvasInstance = bootstrap.Offcanvas.getOrCreateInstance(offcanvasEl);

        // Sync hamburger icon state with offcanvas show/hide
        offcanvasEl.addEventListener('show.bs.offcanvas', function() {
            document.querySelectorAll('.hamburger.animate').forEach(function(btn) {
                btn.classList.add('active');
            });
        });

        offcanvasEl.addEventListener('hide.bs.offcanvas', function() {
            document.querySelectorAll('.hamburger.animate').forEach(function(btn) {
                btn.classList.remove('active');
            });
        });

        // Close offcanvas when navigation link is clicked
        offcanvasEl.querySelectorAll('.nav-link').forEach(function(link) {
            link.addEventListener('click', function() {
                offcanvasInstance.hide();
            });
        });
    })();
    /*-----------------------------------------------------------------------------------*/
    /*	QUOTE SLIDER (Embla — replaced Swiper 5.3.6 to drop the ~140KB custom-plugins
    /*	bundle that existed only for this 3-quote carousel). Clickable dots, no autoplay,
    /*	matching the previous behavior.
    /*-----------------------------------------------------------------------------------*/
    document.querySelectorAll('.quote-embla').forEach(function(element) {
        var viewport = element.querySelector('.embla__viewport');
        var dotsNode = element.querySelector('.quote-dots');
        if (!viewport || typeof EmblaCarousel === 'undefined') return;

        var quoteApi = EmblaCarousel(viewport, { loop: true });

        // Build one dot button per slide
        var dotNodes = [];
        if (dotsNode) {
            dotsNode.innerHTML = quoteApi.scrollSnapList().map(function(_, i) {
                return '<button type="button" class="quote-dot" role="tab" aria-label="Go to quote ' + (i + 1) + '"></button>';
            }).join('');
            dotNodes = Array.prototype.slice.call(dotsNode.querySelectorAll('.quote-dot'));
            dotNodes.forEach(function(dot, i) {
                dot.addEventListener('click', function() { quoteApi.scrollTo(i); });
            });
        }

        function updateDots() {
            var selected = quoteApi.selectedScrollSnap();
            dotNodes.forEach(function(dot, i) {
                var active = i === selected;
                dot.classList.toggle('is-active', active);
                dot.setAttribute('aria-selected', active ? 'true' : 'false');
            });
        }

        quoteApi.on('select', updateDots);
        quoteApi.on('reInit', updateDots);
        updateDots();
    });
    /*-----------------------------------------------------------------------------------*/
    /*	IMAGE ICON HOVER
    /*-----------------------------------------------------------------------------------*/
    document.querySelectorAll('.overlay > a, .overlay > span').forEach(function(el) {
        el.insertAdjacentHTML('afterbegin', '<span class="bg"></span>');
    });
    /*-----------------------------------------------------------------------------------*/
    /*	GLIGHTBOX (replaced LightGallery - Phase 8) — honors prefers-reduced-motion
    /*-----------------------------------------------------------------------------------*/
    var lightbox = GLightbox({
        selector: '.light-gallery a',
        touchNavigation: true,
        loop: true,
        closeOnOutsideClick: true,
        keyboardNavigation: true,
        slideEffect: prefersReducedMotion ? 'none' : 'fade',
        openEffect: prefersReducedMotion ? 'none' : 'zoom',
        closeEffect: prefersReducedMotion ? 'none' : 'zoom'
    });
    /*-----------------------------------------------------------------------------------*/
    /*	PORTFOLIO GRID (Muuri - replaced Cubeportfolio in Phase 11)
    /*-----------------------------------------------------------------------------------*/
    var portfolioGrid = document.getElementById('portfolio-grid');
    var grid = null;

    if (portfolioGrid) {
        // Portfolio imgs now carry intrinsic width/height attrs, so Muuri can
        // size cells from the aspect-ratio hint before image bytes arrive.
        // That means we can KEEP loading="lazy" on every gallery image and let
        // the browser eager-load only what enters the viewport. LCP win is
        // substantial on mobile (was ~76 images eager; now ~8-12 above-fold).

        // Initialize Muuri grid — honors prefers-reduced-motion
        grid = new Muuri('#portfolio-grid', {
            items: '.portfolio-item',
            layout: {
                fillGaps: true,      // Enable masonry-style packing (PORT-06)
                horizontal: false,
                alignRight: false,
                alignBottom: false
            },
            showDuration: prefersReducedMotion ? 0 : 300,
            hideDuration: prefersReducedMotion ? 0 : 200,
            layoutDuration: prefersReducedMotion ? 0 : 300,
            visibleStyles: {
                opacity: 1,
                transform: 'scale(1)'
            },
            hiddenStyles: {
                opacity: 0,
                transform: prefersReducedMotion ? 'scale(1)' : 'scale(0.5)'
            }
        });

        // Wait for images to load, then refresh layout
        // This ensures Muuri calculates correct heights for masonry
        var images = portfolioGrid.querySelectorAll('img');
        var loadedCount = 0;
        var totalImages = images.length;

        function onImageLoad() {
            loadedCount++;
            // Refresh layout after each batch of images loads
            if (loadedCount === totalImages || loadedCount % 10 === 0) {
                grid.refreshItems().layout();
            }
        }

        images.forEach(function(img) {
            if (img.complete) {
                onImageLoad();
            } else {
                img.addEventListener('load', onImageLoad);
                img.addEventListener('error', onImageLoad); // Count errors too
            }
        });

        var emptyState = document.getElementById('portfolio-empty');

        // Filter function with GLightbox integration + empty-state toggle (PORT-02, PORT-04)
        function filterPortfolio(category) {
            grid.filter(function(item) {
                if (category === '*') return true;
                var categoryClass = category.replace('.', '');
                return item.getElement().classList.contains(categoryClass);
            }, {
                onFinish: function() {
                    // Show empty-state message when no items match the filter
                    if (emptyState) {
                        var visibleCount = grid.getItems().filter(function(i) {
                            return i.isVisible();
                        }).length;
                        emptyState.hidden = visibleCount > 0;
                    }
                    // Delay lightbox reload to ensure DOM updates complete
                    setTimeout(function() {
                        lightbox.reload();
                    }, 50);
                }
            });
        }

        // Bind filter button click handlers — buttons carry aria-pressed for screen readers (PORT-02)
        document.querySelectorAll('.filter-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var category = this.getAttribute('data-filter');

                // Update active class + aria-pressed across all filter buttons
                document.querySelectorAll('.filter-btn').forEach(function(b) {
                    b.classList.remove('active');
                    b.setAttribute('aria-pressed', 'false');
                });
                this.classList.add('active');
                this.setAttribute('aria-pressed', 'true');

                // Apply filter with optional View Transitions enhancement (PORT-05)
                if (document.startViewTransition) {
                    document.startViewTransition(function() {
                        filterPortfolio(category);
                    });
                } else {
                    filterPortfolio(category);
                }
            });
        });

        // Debounced resize handler for responsive layout
        var resizeTimer;
        window.addEventListener('resize', function() {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function() {
                grid.refreshItems().layout();
            }, 200);
        });
    }
    /*-----------------------------------------------------------------------------------*/
    /*	BACKGROUND IMAGE
    /*-----------------------------------------------------------------------------------*/
    document.querySelectorAll('.bg-image').forEach(function(el) {
        var bg = 'url(' + el.dataset.imageSrc + ')';
        el.style.backgroundImage = bg;
    });
    /*-----------------------------------------------------------------------------------*/
    /*	PARALLAX MOBILE
    /*-----------------------------------------------------------------------------------*/
    // Feature-detect touch / no-hover devices instead of sniffing the (increasingly
    // frozen) userAgent string. Touch devices can't do fixed-attachment parallax well,
    // so they get the .mobile fallback.
    if (window.matchMedia('(hover: none) and (pointer: coarse)').matches) {
        document.querySelectorAll('.image-wrapper').forEach(function(el) {
            el.classList.add('mobile');
        });
    }
    /*-----------------------------------------------------------------------------------*/
    /*	ONEPAGE HEADER OFFSET
    /*-----------------------------------------------------------------------------------*/
    var navbarEl = document.querySelector('.navbar:not(.banner--clone)');
    var header_height = navbarEl ? navbarEl.offsetHeight : 0;
    var shrinked_header_height = 68;
    document.querySelectorAll('.onepage section').forEach(function(el) {
        el.style.paddingTop = shrinked_header_height + 'px';
        el.style.marginTop = '-' + shrinked_header_height + 'px';
    });
    var firstSection = document.querySelector('.onepage section:first-of-type');
    if (firstSection) {
        firstSection.style.paddingTop = header_height + 'px';
        firstSection.style.marginTop = '-' + header_height + 'px';
    }
	/*-----------------------------------------------------------------------------------*/
    /*	ONEPAGE NAV LINKS
    /*-----------------------------------------------------------------------------------*/
    var empty_a = document.querySelectorAll('.onepage .navbar ul.navbar-nav a[href="#"]');
    empty_a.forEach(function(a) {
        a.addEventListener('click', function(e) {
            e.preventDefault();
        });
    });
    /*-----------------------------------------------------------------------------------*/
    /*  SCROLL TO TOP (Vanilla JS - replaces scrollUp jQuery plugin)
    /*-----------------------------------------------------------------------------------*/
    (function() {
        // Create scroll-to-top button element
        var scrollUpBtn = document.createElement('div');
        scrollUpBtn.id = 'scrollUp';
        scrollUpBtn.innerHTML = '<a href="#" class="btn btn-circle btn-dark" aria-label="Scroll to top"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5,12 12,5 19,12"/></svg></a>';

        // Set initial hidden state (positioning handled by CSS)
        scrollUpBtn.style.opacity = '0';
        scrollUpBtn.style.visibility = 'hidden';
        scrollUpBtn.style.position = 'fixed';
        scrollUpBtn.style.transition = 'opacity 300ms ease, visibility 300ms ease';
        scrollUpBtn.style.zIndex = '9999';

        // Create sentinel element for IntersectionObserver at 300px from top
        var sentinel = document.createElement('div');
        sentinel.id = 'scroll-up-sentinel';
        sentinel.style.cssText = 'position:absolute;top:300px;height:1px;width:100%;pointer-events:none;';
        document.body.insertBefore(sentinel, document.body.firstChild);

        // Use IntersectionObserver to show/hide button
        var scrollObserver = new IntersectionObserver(function(entries) {
            var entry = entries[0];
            if (!entry.isIntersecting) {
                // Scrolled past 300px - show button
                scrollUpBtn.style.opacity = '1';
                scrollUpBtn.style.visibility = 'visible';
            } else {
                // Near top - hide button
                scrollUpBtn.style.opacity = '0';
                scrollUpBtn.style.visibility = 'hidden';
            }
        }, { threshold: 0 });

        scrollObserver.observe(sentinel);

        // Add click handler with accessibility support
        scrollUpBtn.addEventListener('click', function(e) {
            e.preventDefault();
            var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            window.scrollTo({
                top: 0,
                behavior: prefersReducedMotion ? 'instant' : 'smooth'
            });
        });

        // Append button to body
        document.body.appendChild(scrollUpBtn);
    })();
});
