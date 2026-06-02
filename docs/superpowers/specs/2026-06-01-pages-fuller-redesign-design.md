# Fuller redesign — /subscribe/, /consulting/, /support/

**Date:** 2026-06-01
**Status:** Approved (mockups reviewed in visual companion)
**Scope:** Premium redesign of the three "audience" pages, extending the hero/header
vocabulary (gradient accent titles, soft glows, hover-lift) to interactive components.
Both-balanced: premium feel **and** obvious action.

## Approach

Elevate-in-place + a small set of new reusable premium components. Keep page structures
sound; upgrade their components; tighten copy. Cohesive with the just-shipped premium headers.

## New component vocabulary (added to `assets/css/custom.css`)

Accent supplied per-instance via inline `style="--acc: #hex"`. `color-mix` enhancements use
**repeated-property fallbacks** (solid value first, color-mix override second — dropped as a
unit if unsupported) so nothing renders invisible/broken. Gradient titles are wrapped in
`@supports (color-mix)` with a solid fallback (same pattern as the page/post headers).

| Class | Purpose |
|---|---|
| `.hl-panel` (+ `--featured`, `__head`, `__chip`, `__eyebrow`, `__title`, `__body`, `__desc`) | Elevated content panel: gradient wash, accent border-left, corner glow, hover-lift, gradient title |
| `.hl-cta` (+ `--ghost`), `.hl-cta-row`, `.hl-cta-note` | Premium CTA button: gradient fill + glow + lift (solid-accent fallback); ghost variant |
| `.hl-feat-grid`, `.hl-feat` (+ `__dot`, `__stat`, `__title`, `__desc`) | Feature / stat tiles (3-up), glowing accent dot |
| `.hl-link-card` (+ `__title`, `__desc`) | Compact cross-link card with accent border + hover-lift |
| `.hl-grid-2` | 2-col responsive grid for panels |
| `.hl-feed-url` (+ `__label`, `__val`) | On-brand terminal-style feed URL row |

## Per-page changes

**/subscribe/** — 3 delivery options become `.hl-panel`s (RSS green / Email blue / X neutral)
with icon chips + gradient titles; RSS uses `.hl-feed-url` + a copy button; Email frames the
existing embedded newsletter form; "What You'll Receive" becomes a `.hl-feat-grid`
(Reports blue / Detections green / IOC red).

**/consulting/** — Retainer = featured `.hl-panel` in **gold** (`#b8902f`, distinct from the
blue page-header). 8 services become a `.hl-grid-2` of panels, each a **distinct hue**:
Malware=red, AI=purple, IR=orange, SOC=blue, Detection=green, Threat-Model=teal `#2dd4bf`,
TI-Util=pink `#f472b6`, Training=yellow. **"AI & Automation in SecOps" → "AI Systems &
Workflow Engineering"** (purple), reframed around building/engineering AI systems & workflows
generally (not SecOps-specific, not "automation"). Background (credentials) kept as a panel;
Get-in-Touch ends on a `.hl-cta`. Service copy tightened.

**/support/** — Donate becomes a green `.hl-panel` with gradient "Sponsor on GitHub" + ghost
"PayPal"; "What Goes Into Each Report" becomes a `.hl-feat-grid` (Multiple days / A month or
more / Out of pocket); Consulting + Sponsorship cross-links become a `.hl-grid-2` of
`.hl-link-card`s ("More Ways to Help").

## Preserved / out of scope

- Shared components untouched: `.hl-prose-section`, `.hl-support-cta*` (used by the
  `support-cta.html` include on report pages), `.hl-section-header`, page-header.
- The embedded newsletter form (eocampaign1) stays — only its container is restyled.
- New brand accents introduced: teal `#2dd4bf`, pink `#f472b6` (purple/yellow already exist
  in tag/severity sets) — the cost of making 8 services visually distinct.
- Page-specific old CSS that becomes fully unused (`.hl-subscribe-option*`,
  `.hl-service-card*`/`.hl-service-grid`) is removed after grep-confirming no other usage.

© 2026 Joseph. All rights reserved.
