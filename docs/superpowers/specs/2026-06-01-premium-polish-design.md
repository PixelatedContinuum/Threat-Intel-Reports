# Design — Premium Polish ("boogie" pass)

**Date:** 2026-06-01
**Status:** Approved (direction signed off via the brainstorm visual companion — `premium.html`).
**Branch:** `site-premium-polish`
**Repo:** `Threat-Intel-Reports` (GitHub Pages, deploys from `main` on push).

## Why
The site is a sales surface for sponsors, so it should read as **sleek/premium**, not merely clean. The approved approach: keep the minimal, high-contrast, accessible base and add a thin layer of refined detail — gradient accents, a soft glow, lifted depth, and a richer hover. On-brand for a cyber-intel site; never busy.

## Scope — CSS only (`assets/css/custom.css`), no markup change
All four changes are appended to / override existing rules via cascade order. They apply site-wide where the selectors appear (the hero is home-only; the card glow is everywhere a clickable `.hl-card` renders — home grid + all three listings + related-report cards).

1. **Hero accent glow** — `.hl-home-hero::before` paints a soft blue radial glow behind the headline (`z-index:-1`, contained within the hero width so it can't cause horizontal scroll).
2. **Gradient headline** — `.hl-home-hero__title` becomes a `white → #79c0ff` gradient via `background-clip: text` (same technique already used by the live 404 code). Stays high-contrast/readable; overrides the prior solid white with `color: transparent !important` + `-webkit-text-fill-color`.
3. **Lifted metric pills** — `.hl-cred-pill` gains a subtle vertical gradient (`#1d1d1d → #161616`) + soft shadow for depth.
4. **Premium card-glow hover** — `a.hl-card:hover` upgrades the prior plain shadow to a blue-tinted glow + `translateY(-3px)`: `box-shadow: 0 10px 34px rgba(88,166,255,0.13), 0 6px 18px rgba(0,0,0,0.45)`.

## Deliberately unchanged
- **Section headers** and **report headings** stay as they are (white text on their existing accent bars) — the user reviewed colored-heading options and preferred the current treatment; text-matching-the-bar read off.
- **Report page bodies/structure** — untouched; reports inherit only the global card-glow on related cards (and the already-shipped bright text).
- The gradient headline is a **hero-only signature** element; page-header titles stay solid white to avoid clashing with the green/red section accents on the detections/IOC listings.

## Verification (post-deploy)
1. Home hero: soft glow visible behind the headline; headline renders as a white→blue gradient (not invisible — confirms `background-clip` support path); metric pills have subtle depth.
2. Hover a card on the home grid and on `/reports/`: blue-tinted glow + lift.
3. Body text + readability unchanged (contrast preserved).

## Risk (low)
- `background-clip: text` is already in production (404 code), so the gradient-text path is proven on this site.
- Glow is `pointer-events:none` and width-contained — no layout/scroll impact.
