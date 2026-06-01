# Site Brand & Polish Refresh — Design Spec

**Date:** 2026-06-01
**Repo:** Threat-Intel-Reports (Jekyll, remote theme `sylhare/Type-on-Strap`), live at https://the-hunters-ledger.com
**Branch:** `feature/brand-refresh`
**Status:** Approved design — ready for implementation plan

---

## 1. Goal & context

The owner has an incoming sponsor and wants the site to read as cleaner and more professional, with the **logo as the centerpiece concern**. The original logo was a self-made 1.45 MB raster banner (`logo.png`) dropped full-width into the **middle of the home-page body**, with the persistent nav showing only a plain text brand. The site itself already has a mature, well-built dark design system (custom `hl-*` tokens, a feature-rich `post.html` with TOC/scroll-spy/progress/IOC panels). This is therefore a **brand-and-polish layer over a solid site — not a structural redesign.**

Scope chosen by owner: **broader refresh** (logo + home page + light inner-page consistency).

## 2. Background — current state

- **Logo:** `assets/images/logo.png` (2079×577, **1.45 MB**) — wordmark + pink target-in-triangle icon + low-poly network background + pink border, all baked into one flat raster. Referenced only by `index.md:8` via `<img class="hl-masthead">`.
- **Nav brand:** `_includes/default/navbar.liquid` renders `<a class="hl-nav__brand">{{ site.title }}</a>` — plain white text, no mark. Nav (`.hl-nav`) is `96px` tall, sticky, `#0d1117`.
- **Home page:** `index.md` opens with the masthead `<img>` then `.hl-hero` (title + description), then Latest Reports, Mission, Navigate, etc.
- **Fonts:** site loads **no custom web font** (theme default typography; `font-family` only `inherit`/`Courier New` in custom.css).
- **Favicon:** `assets/images/favicon.ico` — **1.44 MB** (!), linked in `_includes/default/head.liquid:25`.
- **Social/OG image:** `assets/images/header.png` (**1.63 MB**) — referenced by `_config.yml:13` (`header_feature_image`) and used as the default `og:image` / `twitter:image` in `head.liquid:76,94`. Still shows the **old** pink-triangle logo, so shared links preview the brand we are replacing.
- **Palette tokens** (`custom.css :root`): page `#111111`, nav/card `#0d1117`/`#1a1a1a`, text `#eeeeee`/`#aaaaaa`, accent blue `--hl-accent-blue: #58a6ff`, severity + accent colors.

## 3. Decisions locked (validated via visual mockups)

1. **Concept C — Editorial Wordmark** (type-led, no icon). Chosen over a reticle icon (A) and an H+L ledger monogram (B). Rationale: reads as a serious *publication*, which is what the site is; nothing to maintain as a raster; cleanest in the nav.
2. **Wordmark treatment (V2):** both lines white, "THE HUNTER'S" brightened and slightly tightened so it no longer reads as faint; "LEDGER" remains the emphasis through size + weight. Blue masthead rule + blue colophon dot.
3. **Placement:** wordmark lives in the **nav bar, top-left**, on every page (replaces the text brand). The home-page masthead banner is **removed entirely**.
4. **Home page = Option X** (lead with the value proposition). No logo repeated in the body; the brand lives only in the nav. Chosen over a branded hero band (Y) because repeating the wordmark just below the nav is redundant.
5. **Accent color:** keep existing blue `#58a6ff` (already woven through links, low-severity, card bars). Revisitable later as a one-token swap.

## 4. Detailed design

### 4.1 Wordmark (nav lockup)

Replace the text brand in `navbar.liquid` with a structured lockup; style in `custom.css`. Live HTML text (accessible, editable), not an image.

```
[ rule ]  THE HUNTER'S      <- top line
          LEDGER •           <- main line (• = colophon dot)
```

| Element | Spec (nav size) |
|---|---|
| Rule | `width:3px; height:30px; border-radius:2px; background:linear-gradient(180deg,#58a6ff,#1f6feb)` |
| Top line "THE HUNTER’S" | Space Grotesk 500, `11px`, `letter-spacing:.22em`, uppercase, color `#f0f6fc` |
| Main line "LEDGER" | Space Grotesk 700, `17px`, `letter-spacing:.12em`, uppercase, color `#ffffff`, `line-height:1` |
| Colophon dot | `6px` square, `border-radius:2px`, `background:#58a6ff`, after LEDGER, gap `7px`, baseline-aligned |
| Stack gap | `3px` between the two lines; lockup gap (rule→text) `11px` |

- Use a typographic apostrophe `’` (U+2019) in "THE HUNTER’S".
- Markup stays a single `<a href="/">` for accessibility; add `aria-label="The Hunter's Ledger — home"`.
- **Mobile (≤700px):** keep the stacked lockup; scale main → ~`15px`, top → ~`9px`. Verify it fits the wrapped nav.

### 4.2 Nav bar

- Reduce `.hl-nav` height `96px → 70px` to suit the compact lockup.
- `post.html` measures `.hl-nav` `offsetHeight` at runtime for the reading-progress track and mobile-TOC offset, so a height change is self-adjusting — **but must be re-verified** on a report page (sticky TOC + progress bar alignment).

### 4.3 Home page (Option X)

In `index.md`:
- **Remove** the `<img class="hl-masthead">` line.
- **Replace** the `.hl-hero` block with a value-prop hero:
  - Eyebrow: "Threat Intelligence" (accent `#58a6ff`, uppercase, tracked, ~12px).
  - H1: "Original Threat Intelligence Research" (Space Grotesk 700, large).
  - Lede: keep existing description copy.
  - Chips row: `Original research` · `Free forever` · `IOCs + detections included` (pill style, `--hl-bg-card` bg, `--hl-border-card`, accent keyword).
- Everything below (Latest Reports → Mission → Navigate → Sponsors → Contributing → About → Resources) is unchanged.
- New CSS: `.hl-home-hero` (eyebrow/h1/lede/chips). Remove `.hl-masthead` rule.

### 4.4 Typography — self-hosted display font

- Self-host **Space Grotesk** weights **500** and **700** as `woff2` under `assets/fonts/`. License: SIL OFL 1.1 — bundle `OFL.txt`. No third-party font requests (fits the site's no-tracking posture: `cookie_consent: false`, no GA configured).
- `@font-face` with `font-display: swap`; `<link rel="preload" as="font" type="font/woff2" crossorigin>` for both weights in `head.liquid`.
- **Apply to display/brand type only:** nav wordmark, `.hl-home-hero` eyebrow + H1, `section-header` labels, and report `.hl-post-header__title` + eyebrow (for cross-page consistency).
- **Body text unchanged.**
- Fallback stack: `'Space Grotesk','Segoe UI',system-ui,-apple-system,Arial,sans-serif`.

### 4.5 Favicon

- Replace the **1.44 MB** `favicon.ico` with a small modern set built from an "**HL**" mark on the dark rounded tile (`#161b22`, accent strokes), echoing the wordmark family.
- Deliverables: `favicon.svg` (hand-authored, primary), `favicon-32.png`, `apple-touch-icon.png` (180×180). A small (≤16 KB) `favicon.ico` is **optional legacy fallback only** — modern browsers are covered by the SVG + PNGs, so it may be dropped if rasterization is unavailable.
- Update `head.liquid`: `icon type=image/svg+xml` + `icon 32×32 png` + `apple-touch-icon`. Update/retire `_config.yml:favicon` accordingly.

### 4.6 Social / Open Graph image

- Regenerate `assets/images/header.png` as a **1200×630** card: dark bg (`#0d1117` + subtle grid/texture), the wordmark lockup, tagline ("Original threat intelligence research for the defender community"). Optimize to **~150 KB**.
- Keep the **same filename** (`header.png`) so `_config.yml` and the OG/Twitter meta in `head.liquid` keep working with no reference changes.

### 4.7 Inner report / detection pages — light touch only

- Inherit the new nav + favicon automatically.
- Apply the display font to `.hl-post-header__title` + eyebrow (4.4).
- **No changes** to TOC, scroll-spy, reading progress, copy buttons, IOC/detection panels, related-reads, sponsor banner, or body typography — all already strong.

### 4.8 Cleanup

- Delete `assets/images/logo.png` (1.45 MB) after the `index.md` img is removed.
- Remove old `favicon.ico` (replaced).
- Remove `.hl-masthead` CSS rule.
- Net asset reduction ≈ **4.5 MB** (logo + old favicon + OG bloat).

## 5. Files affected

| File | Change |
|---|---|
| `_includes/default/navbar.liquid` | Replace text brand with wordmark lockup markup |
| `assets/css/custom.css` | Nav height; `.hl-nav__brand` lockup styles; `.hl-home-hero`; `@font-face`; remove `.hl-masthead`; apply display font to headings/labels |
| `index.md` | Remove masthead `<img>`; replace `.hl-hero` with value-prop hero + chips |
| `_includes/default/head.liquid` | Font preloads; favicon link set |
| `_config.yml` | Favicon path (if changed); `header_feature_image` unchanged (regenerated in place) |
| `assets/fonts/` (new) | Space Grotesk 500/700 woff2 + `OFL.txt` |
| `assets/images/favicon.svg` + PNGs (new) | New favicon set |
| `assets/images/header.png` | Regenerated OG card (same name) |
| `assets/images/logo.png`, old `favicon.ico` | Deleted |

## 6. Out of scope

Report structure/content; the TOC & IOC/detection panels; sponsor system (`_data/sponsors.yml`, sponsor banner, `site-sponsors.html`); URLs/permalinks; color palette tokens; body typography; the email-capture form.

## 7. Open implementation details (resolve during planning)

1. **Rasterization toolchain** for favicon PNGs + the OG PNG (e.g., ImageMagick `convert`, `rsvg-convert`, or Inkscape). If none is available locally, ship the hand-authored `favicon.svg` (covers ~93% of browsers) + author PNGs via an available tool, or hand the SVGs to the owner to export. Do **not** `pip install` at runtime (per project platform rules).
2. **Space Grotesk woff2 acquisition** — download the two weights (OFL) and self-host; confirm exact glyph coverage for the wordmark.
3. **Mobile wordmark fit** at the ≤700px breakpoint (wrapped nav).

## 8. Verification plan

- Build locally with `bundle exec jekyll serve` if Ruby/Jekyll is available; otherwise high-fidelity preview via the brainstorm visual companion using the real CSS.
- Check: nav wordmark on home + a report + a detection page; home hero with banner gone; favicon in the tab; report-page sticky TOC + reading-progress alignment after the nav-height change; mobile (≤700px) nav.
- Final review on `feature/brand-refresh` **before** merge/push to `main` (push = live GitHub Pages deploy). Do not push without owner approval.
