# Google Business Profile — Setup & Optimization

The single highest-impact lead lever for a local photographer. For local search,
ranking weight is roughly **proximity 55% / GBP signals 32% / reviews 16–20% /
on-page 19%** — and the website can't influence the Map Pack, only the GBP can.
Businesses with photos get ~42% more direction requests and ~35% more website
clicks than those without.

Everything below is paste-ready and matches the website's standardized NAP so
Google reads one consistent business entity. **Keep these identical across the
GBP, the website (`index.html` JSON-LD), and `llms.txt`** — drift weakens ranking.

---

## 1. Claim & verify (Cassie must do this — needs her Google account)

1. Go to https://business.google.com → "Add your business."
2. Business name: **Cassie Cay Photography** (exactly — no city/keywords appended; that violates Google's naming rules and can get the profile suspended).
3. When asked "Do you serve customers at your location?" choose **"I deliver goods and services to my customers"** → this makes it a **service-area business** (no public street address shown, correct for a home-based photographer).
4. Service area: add **Waunakee, Madison, Middleton, Sun Prairie, DeForest, Verona, Fitchburg, Windsor** (Dane County towns — matches the 80km `areaServed` in the site schema).
5. Verify ownership (Google will offer postcard, phone, or email/video — pick whatever it shows). **The profile won't rank until verified.**

---

## 2. Core profile fields (paste-ready)

| Field | Value |
|-------|-------|
| **Name** | Cassie Cay Photography |
| **Primary category** | Photographer |
| **Additional categories** | Portrait Studio · Wedding Photographer · Photography Service |
| **Website** | https://cassiecayphotography.com |
| **Email** | cassiecayphoto@gmail.com |
| **Service area** | Waunakee + Madison/Dane County (see list above) |
| **Phone** | _(optional — add a number if Cassie wants calls; if not, leave blank and let the website form be the contact path)_ |

> Primary category is one of the strongest ranking signals — it should reflect
> the bulk of the work. "Photographer" is the broad correct primary; the
> additional categories widen which searches you surface for.

### Business description (≤ 750 chars — paste as-is)

> Cassie Cay Photography is a Waunakee and Madison, Wisconsin photographer
> specializing in bright, natural-light family, newborn, senior, and milestone
> portraits. Cassie (a Madison-area mom herself) keeps sessions relaxed and real
> — genuine laughter over stiff posing — so your photos look like the day you
> actually lived. Outdoor and in-home sessions across Dane County: Waunakee,
> Madison, Middleton, Sun Prairie, DeForest, and Verona. Newborn, family,
> first-birthday and cake-smash milestones, high school seniors, and couples.
> View the gallery and get in touch at cassiecayphotography.com.

---

## 3. Services (mirror the website — this matters)

Google now cross-references GBP services against matching content on your site.
Add each as a **Service** in the GBP "Services" section so they align with the
site's Services section and schema:

- Family Photography
- Newborn Photography
- Fresh 48 Session
- Milestone / First Birthday / Cake Smash
- Senior Portraits
- Couples & Engagement
- Wedding & Event Photography

---

## 4. Photos (a ranking factor *and* the conversion hook)

- Upload **15–25** of the strongest portfolio images (pull from `images-optimized/jpeg/full/` — the same shots already on the site).
- Cover a spread: family, newborn, senior, milestone, couples — Google favors variety and volume.
- Set a warm, bright **cover photo** and a clear **logo** (`cassiecaylogobw2`).
- Add a few new photos **monthly** — active profiles outrank dormant ones.
- Geo-relevance: shots that read as Wisconsin (seasons, local spots) reinforce the local signal.

---

## 5. Reviews (16–20% of ranking — the biggest controllable lever)

- After each session, send the client the GBP review short-link ("Get more reviews" in the dashboard generates it). A simple text: *"So glad we got to work together! If you have a minute, a quick Google review really helps other Madison families find me: [link]"*
- **Respond to ≥ 80% of reviews** — businesses that do see a measurable ranking bump. A warm one-liner is enough.
- Aim for a steady trickle (a few per month) rather than a burst — natural velocity is what Google rewards.
- These reviews can later be mirrored on the website as testimonials (see the separate testimonials task).

---

## 6. Posts & Q&A (cheap, brand-safe activity signals)

- **Posts:** one short update every 1–2 weeks — a recent session, a seasonal mini-session opening, a favorite frame. Keep it warm, not salesy (matches the brand: no "limited spots!" hustle).
- **Q&A:** seed 3–5 questions yourself and answer them:
  - "Where do you photograph sessions?" → Waunakee, Madison, and across Dane County, outdoors or in-home.
  - "Do you photograph newborns at home?" → Yes, in-home and studio newborn sessions.
  - "How far in advance should I book?" → [Cassie's answer]
  - "What should we wear?" → [Cassie's answer]

---

## 7. Ongoing (15 min/month)

- [ ] Add 2–4 new photos
- [ ] Post 1–2 updates
- [ ] Request reviews from recent clients
- [ ] Respond to every new review + any new Q&A
- [ ] Confirm NAP still matches the website (name, email, service area, social links)

---

## Why this beats more website work

The site's on-page SEO is already strong (clean schema, fast, descriptive alt
text). For a referral + local-search business, the next gains live in GBP and
reviews — not in more markup. This profile is also where the secondary
"local Google searcher" audience (from PRODUCT.md) actually discovers Cassie.
