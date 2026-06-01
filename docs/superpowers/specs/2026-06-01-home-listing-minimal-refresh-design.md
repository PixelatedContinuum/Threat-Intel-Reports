# Design — Home + Listing Minimal Refresh & Site-Wide Body Contrast

**Date:** 2026-06-01
**Status:** Approved (all directions signed off via the brainstorm visual companion).
**Branch:** `site-refresh-home-listings`
**Repo:** `Threat-Intel-Reports` (GitHub Pages, deploys from `main` on push).

## Overview

A minimal, streamlined pass over the **home page** and the three **listing pages**, plus a **site-wide body-text contrast** change for readability/accessibility. Keeps the existing identity, colors, and all content — the goal is "more professional, less cluttered," not a re-theme. Reuses components already shipped in the About refresh (the credential-pill strip).

### Goals
1. **Home hero** — fold "free" into the lede; replace the 3 generic chips with minimal metric pills (live catalog counts); show 4 Latest cards (fill the 2×2).
2. **Lower home** — trim boxes, consolidate sections (Mission as clean prose; "Navigate"→"Explore"; merge "About the Analyst" + "Contributing" into one compact "About & Connect"; light Resources).
3. **Site-wide body contrast** — bright `#eeeeee` body text; grey only for small meta; color only for highlights/links. (Accessibility: the site owner is dyslexic and high contrast materially improves focus.)
4. **Listings** — bright text (from #3) + a subtle card hover (lift + accent border + shadow), which also applies to the home Latest grid.

### Preserve / out of scope
- **Content/copy kept.** Only deliberate edits: the hero lede gains a "free and open…" clause, and the section label "Navigate" → "Explore." No report/detection/IOC page content changes (the contrast change brightens report blockquotes/h4/captions — an improvement, verified below).
- **Colors/identity kept.** No palette change beyond the body-text token.
- **No `?v=` bump** — the listing-filter JS is untouched; `custom.css` propagates via GitHub Pages caching as prior CSS deploys did.

---

## Component 1 — Home hero (`index.md` hero block)

Replace the current hero (title + lede + 3 `.hl-chip`) with: same title, an expanded lede that folds in "free," and a **metric-pill strip reusing the About `.hl-creds-strip` / `.hl-cred-pill` components** (no new CSS — already in `custom.css`). Counts are computed **live** from the catalog so they never go stale.

```liquid
{% assign n_reports = site.data.catalog.entries | where_exp: "e", "e.report_url" | size %}
{% assign n_det = site.data.catalog.entries | where_exp: "e", "e.detection_url" | size %}
{% assign n_ioc = site.data.catalog.entries | where_exp: "e", "e.ioc_url" | size %}
<div class="hl-home-hero">
  <h1 class="hl-home-hero__title">Original Threat Intelligence Research</h1>
  <p class="hl-home-hero__lede">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Free and open: published by a solo analyst for the defender community, with no paywall or signup.</p>
  <div class="hl-creds-strip">
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#58a6ff;"></span><strong>{{ n_reports }}</strong>&nbsp;Reports</span>
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#4ade80;"></span><strong>{{ n_det }}</strong>&nbsp;Detections</span>
    <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#f87171;"></span><strong>{{ n_ioc }}</strong>&nbsp;IOC Feeds</span>
  </div>
</div>
```

The old `.hl-home-hero__chips` block is removed. (The `.hl-chip` CSS stays in `custom.css` — still used elsewhere — but the home hero no longer renders chips.)

**Latest Reports grid:** change the loop from `limit: 3` to `limit: 4` so the 2-column grid fills as a clean 2×2.
```liquid
{% for e in latest limit: 4 %}{% include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags %}{% endfor %}
```

---

## Component 2 — Lower home (`index.md`, Mission → Resources)

### 2a. Mission — clean prose, disclaimer folded in
Replace the `.hl-prose-section` Mission box **and** the standalone `.hl-note` disclaimer box with a single clean prose block. Keep the `{% include section-header.html label="Mission" accent="#58a6ff" %}` line.

```html
<div class="hl-mission">
  <p>Most threat intelligence fails defenders in one of two ways. It is either too shallow to be actionable — headlines dressed up as analysis — or technically rigorous but locked behind paywalls, stripped of indicators, and written for researchers rather than the people responding at 2am.</p>
  <p>The Hunter's Ledger exists to fill that gap. Every report here is built from original research: real samples, real infrastructure, real detections. The goal is intelligence that a defender can open, read, and act on the same day — with IOCs ready to ingest, detection rules ready to deploy, and analysis deep enough to actually understand what a threat does and how to stop it.</p>
  <p class="hl-mission__close">All of it is free. Defenders should not have to pay to defend.</p>
  <div class="hl-mission__note">Not a collection of open-source intel reports, IOCs, or TTPs — findings are from original research, though they may overlap with known threats.</div>
</div>
```

### 2b. "Navigate" → "Explore"
Change the section-header label only: `{% include section-header.html label="Explore" accent="#4ade80" %}`. The 4 `.hl-nav-tile` entries (Reports / Hunting Detections / IOC Feeds / Behind the Reports) are unchanged.

### 2c. "About the Analyst" + "Contributing" → "About & Connect"
Remove the standalone **Contributing** section (its `section-header` + `.hl-prose-section`) and the three stacked full-width `.hl-card` blocks under "About the Analyst." Replace with one section: a compact 3-up tile row (reusing `.hl-nav-tile`) + a one-line contribute note.

```html
{% include section-header.html label="About & Connect" accent="#f97316" %}
<div class="hl-tile-row3">
  <a href="{{ '/about-me/' | relative_url }}" class="hl-nav-tile"><div class="hl-nav-tile__title">About Me →</div><div class="hl-nav-tile__desc">Background &amp; how to reach me</div></a>
  <a href="{{ '/consulting/' | relative_url }}" class="hl-nav-tile"><div class="hl-nav-tile__title">Consulting →</div><div class="hl-nav-tile__desc">Malware analysis, IR &amp; detection services</div></a>
  <a href="{{ '/support/' | relative_url }}" class="hl-nav-tile"><div class="hl-nav-tile__title">Support →</div><div class="hl-nav-tile__desc">Help keep the research free</div></a>
</div>
<div class="hl-contribute">Have original research, detections, or IOCs to share? Reach out at <a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a> — findings can be posted on your behalf as a co-author or attributed however you prefer.</div>
```

### 2c-bis. Preserve the Sponsors block
The conditional **Current Sponsors** block (`{% if active_site_sponsors %}` … `{% include site-sponsors.html %}` … `{% endif %}`) is left intact and keeps its position — after **Explore**, before **About & Connect**. Do not remove or alter it; it renders only when a monthly sponsor is active.

New lower-home section order: Mission → Explore → *(Sponsors, conditional)* → About & Connect → Resources.

### 2d. Resources — light inline links
Replace the Resources `.hl-prose-section` with a light inline link row (keep the section-header).
```html
<div class="hl-resources"><a href="https://attack.mitre.org/">MITRE ATT&amp;CK</a> &nbsp;·&nbsp; <a href="https://github.com/SigmaHQ/sigma">Sigma Rules</a> &nbsp;·&nbsp; <a href="https://virustotal.github.io/yara/">YARA</a></div>
```

---

## Component 3 — Site-wide body-text contrast (`custom.css`)

**Principle:** body/prose text = bright `#eeeeee`; grey (`#888`) only for small meta (dates, card meta, filter counts, read-time, eyebrow labels); color only for highlights/links.

**Edits:**
1. In `:root`, bump the body token: `--hl-text-secondary: #aaaaaa;` → `--hl-text-secondary: #eeeeee;`
2. `.hl-nav-tile__desc` — `color: var(--hl-text-muted);` → `color: var(--hl-text-secondary);`
3. `.hl-404__desc` — `color: var(--hl-text-muted);` → `color: var(--hl-text-secondary);`
4. Bump the dim tier too: `--hl-text-dim: #555555;` → `#888888;`. This brightens the readable items on the old `#555` tier (TOC sub-section links, read-time, Share button, footer line, filter empty-state) in one edit. Net effect: the four text tiers collapse to two — `#eeeeee` body and `#888` meta — exactly the target system.
5. Keep `--hl-text-muted` (#888) as the meta color (now equal to dim). Consulting's `.hl-service-card__body` is already `--hl-text-primary` (verified bright — no change). Secondary pages (consulting / support / sponsor / behind-the-reports) use the standard components and inherit all of the above automatically — no per-page edits.

**Blast radius (verified safe — all become brighter, none dimmer):** the token change brightens, site-wide, everything currently on `--hl-text-secondary`: the home hero lede, subscribe descriptions, filter chip-button text, related-card text, and — on report pages — analyst-note **blockquote** text, `h4` subheads, and figcaptions. Report paragraph/list/heading body is already `--hl-text-primary` (#eeeeee), so it is unchanged. Net effect: prose that was `#aaaaaa` becomes `#eeeeee`; nothing gets darker.

> **Note:** this makes `--hl-text-secondary` equal to `--hl-text-primary` (both #eeeeee). That redundancy is intentional and harmless — one token edit brightens all body prose at once. Hierarchy is carried by size/weight and the Space Grotesk display font, not by dim text.

---

## Component 4 — Card hover polish (`custom.css`)

Add a subtle, professional hover to `.hl-card` (applies to catalog cards on all three listings **and** the home Latest grid):
```css
.hl-card { transition: border-color 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease; }
.hl-card:hover { border-color: var(--hl-accent-blue) !important; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(0,0,0,0.38); }
```
The listing page-headers already use `--hl-text-primary` for their description, so they need no contrast change.

---

## New CSS to append to `custom.css`

```css
/* ===== Home: Mission (clean prose) ===== */
.hl-mission { color: var(--hl-text-secondary); font-size: 0.98em; line-height: 1.7; max-width: 70ch; margin-bottom: 0.5rem; }
.hl-mission p { margin: 0 0 14px; }
.hl-mission__close { color: var(--hl-text-primary); font-weight: 600; }
.hl-mission__note { margin-top: 16px; font-size: 0.85em; color: var(--hl-text-secondary); font-style: italic;
  border-left: 2px solid var(--hl-border-card); padding-left: 12px; }

/* ===== Home: About & Connect 3-up tile row ===== */
.hl-tile-row3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 9px; margin-bottom: 14px; }
.hl-contribute { font-size: 0.88em; color: var(--hl-text-secondary); line-height: 1.6; }
.hl-contribute a { color: var(--hl-accent-blue); }

/* ===== Home: Resources inline links ===== */
.hl-resources { font-size: 0.92em; color: var(--hl-text-muted); }
.hl-resources a { color: var(--hl-accent-blue); text-decoration: none; }
.hl-resources a:hover { text-decoration: underline; }

/* ===== Card hover (listings + home grid) ===== */
.hl-card { transition: border-color 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease; }
.hl-card:hover { border-color: var(--hl-accent-blue) !important; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(0,0,0,0.38); }

@media (max-width: 700px) { .hl-tile-row3 { grid-template-columns: 1fr; } }
```
(`.hl-creds-strip` / `.hl-cred-pill` already exist from the About refresh — reused for the hero metrics, no new CSS.)

---

## Files touched
| File | Change |
|---|---|
| `index.md` (home) | hero (lede + metric pills + `limit: 4`); Mission prose; Explore label; About & Connect; Resources |
| `assets/css/custom.css` | `--hl-text-secondary` → `#eeeeee`; `.hl-nav-tile__desc` + `.hl-404__desc` → secondary; append the new component + hover CSS |
| `docs/superpowers/specs/2026-06-01-home-listing-minimal-refresh-design.md` | this spec |

No edits needed to the three listing `index.md` pages or `catalog-card.html` — they inherit the bright text + card hover automatically from `custom.css`.

## Deployment & verification
- Work on `site-refresh-home-listings`; commit per component (stage only my files — unrelated untracked files remain). **No push without explicit OK.**
- **Post-deploy (live):** (1) home hero shows metric pills with live counts + 4 Latest cards; (2) lower home shows Mission prose, Explore tiles, the 3-up About & Connect + contribute line, light Resources; (3) body prose is bright `#eeeeee` site-wide (home lede, a report's analyst-note blockquote); (4) cards lift/outline on hover on home + listings; (5) the three listing pages render bright + hover. Spot-check a report to confirm the brighter blockquotes/captions read well (no regression).

## Risks (low)
- **Over-brightening / flat feel:** mitigated by size/weight/font hierarchy; the `#eeeeee` level is the owner's explicit accessibility preference. Calibratable to `#d4d4d4` by changing one token if it reads heavy.
- **Report blockquotes/captions brighten:** verified as an improvement, not a regression (they were `#aaaaaa`).
