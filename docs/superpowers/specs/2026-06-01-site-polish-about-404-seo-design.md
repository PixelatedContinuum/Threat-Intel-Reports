# Design — About Polish, Branded 404, Article JSON-LD, Image Lazy-Loading

**Date:** 2026-06-01
**Status:** Approved (visual mockups signed off via the brainstorm visual companion; technical approach approved).
**Branch:** `site-polish-about-404-seo`
**Repo:** `Threat-Intel-Reports` (GitHub Pages, deploys live from `main` on push).

## Overview

Four site-enhancement items from the 2026-06-01 polish menu, plus one review that resulted in no change. None of these alter how reports *function* (TOC, Detection/IOC panels, copy/share buttons, read-time, related-reports, syntax highlighting are all untouched). Two are cosmetic page changes a visitor sees (About, 404); two are invisible SEO/perf upgrades (JSON-LD, lazy-load).

### Goals
1. **About-page polish** — tighter header, a credentials strip, a cleaner experience timeline.
2. **Branded 404** — replace GitHub's generic 404 with an on-brand, threat-intel-themed page.
3. **Article JSON-LD on reports** — make reports eligible for richer Google results; fix a latent `og:type` bug.
4. **Image lazy-loading** — defer below-the-fold report images for faster initial load.

### Out of scope
- **Email-capture script** (`eocampaign1.com`): reviewed (it loads an EmailOctopus popup on every page via `default.html`, duplicating the dedicated `/subscribe/` page + footer link). **Decision: keep as-is. No change.**
- JSON-LD on detection pages: **not now** — reports only.

### Cross-cutting implementation note — colors/tokens
The CSS below uses literal hex values that match the site's *rendered* palette (verified by rendering the mockups against the live `custom.css`). Before adding, the implementer should **read `assets/css/custom.css`** and reuse any existing CSS custom-properties/tokens (card bg, border, muted text, accent colors) if they are defined, falling back to these hexes. New rules are appended to `custom.css`. All new class names are prefixed (`.hl-creds-strip`, `.hl-cred-pill`, `.hl-timeline*`, `.hl-404*`) so they cannot collide with existing styles.

No `?v=` cache-bust is needed — `custom.css` is referenced as a plain `<link>` in `head.liquid` (only `listing-filter.js` is `?v`-versioned, and it is not touched).

---

## Component 1 — About-page polish

**File:** `about-me/index.md` (markup) + `assets/css/custom.css` (new rules).

### 1a. Tighter header
Change the existing `hl-page-header` block:
- `label`: `About Me` → `About`
- `title`: `Joseph Harrison · SOC Operations Lead & Threat Intelligence Researcher` → `Joseph Harrison`
- `desc`: `Background, credentials, and ways to connect.` → `SOC Operations Lead &amp; Threat Intelligence Researcher`

```html
<div class="hl-page-header" style="border-left-color: #58a6ff;">
  <div class="hl-page-header__label" style="color: #58a6ff;">About</div>
  <div class="hl-page-header__title">Joseph Harrison</div>
  <div class="hl-page-header__desc">SOC Operations Lead &amp; Threat Intelligence Researcher</div>
</div>
```

### 1b. Credentials strip (Style A — pills)
Insert immediately **after** the header block, **before** the `Who I Am` section-header:

```html
<div class="hl-creds-strip">
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#f97316;"></span><strong>GCFA</strong></span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#58a6ff;"></span><strong>M.S. Cybersecurity</strong></span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#4ade80;"></span><strong>Ernst &amp; Young</strong>&nbsp;·&nbsp;SOC Operations Lead</span>
  <span class="hl-cred-pill"><span class="hl-cred-pill__dot" style="background:#58a6ff;"></span><strong>U.S. Air Force</strong>&nbsp;·&nbsp;Veteran</span>
</div>
```

### 1c. Experience timeline
Replace the **three** `hl-prose-section` blocks (EY, Raytheon, USAF) under the `Experience` section-header with a single timeline. **Keep the `{% include section-header.html label="Experience" accent="#4ade80" %}` line.** Carry the existing role descriptions over verbatim (do not drop substantive content — e.g. EY's "Original research … feeds directly into hunting operations" sentence stays).

```html
<div class="hl-timeline">
  <div class="hl-timeline__item">
    <div class="hl-timeline__dot" style="background:#4ade80;"></div>
    <div class="hl-timeline__role">SOC Operations Lead <span class="hl-timeline__org">· Ernst &amp; Young (EY)</span></div>
    <div class="hl-timeline__desc">Leading threat detection and response operations across large enterprise managed security accounts. Responsibilities span threat hunting, detection engineering, DFIR investigations, CTI collaboration, and AI/automation across a large multi-client practice. Detection engineering work includes building custom SIEM and EDR detection logic and signatures tailored to client environments, and directing end-to-end IR investigations to determine scope and impact. Original research and detection content from The Hunter's Ledger feeds directly into hunting operations and client-facing intelligence work.</div>
  </div>
  <div class="hl-timeline__item">
    <div class="hl-timeline__dot" style="background:#58a6ff;"></div>
    <div class="hl-timeline__role">Systems Engineer II <span class="hl-timeline__org">· Raytheon Technologies</span></div>
    <div class="hl-timeline__desc">Security modernization, system hardening, and compliance across IT and OT environments prior to moving into full-time cybersecurity operations.</div>
  </div>
  <div class="hl-timeline__item">
    <div class="hl-timeline__dot" style="background:#58a6ff;"></div>
    <div class="hl-timeline__role">Systems Administrator <span class="hl-timeline__org">· United States Air Force</span></div>
    <div class="hl-timeline__desc">Unit cybersecurity liaison responsible for triaging and escalating security incidents, administering access controls for classified operational systems, and enforcing least-privilege principles across a 100-person unit.</div>
  </div>
</div>
```

### 1d. CSS to append to `custom.css`
```css
/* ===== About: credentials strip (pills) ===== */
.hl-creds-strip { display:flex; flex-wrap:wrap; gap:10px; margin:18px 0 6px; }
.hl-cred-pill { display:inline-flex; align-items:center; gap:9px; padding:9px 15px;
  border:1px solid #30363d; border-radius:9px; background:#161b22; font-size:0.9rem; color:#c9d1d9; }
.hl-cred-pill__dot { width:7px; height:7px; border-radius:50%; flex:none; }
.hl-cred-pill strong { color:#f0f6fc; font-weight:600; }

/* ===== About: experience timeline ===== */
.hl-timeline { position:relative; margin:8px 0 2px; padding-left:24px; }
.hl-timeline::before { content:''; position:absolute; left:6px; top:7px; bottom:9px; width:2px; background:#21262d; }
.hl-timeline__item { position:relative; padding:0 0 20px; }
.hl-timeline__item:last-child { padding-bottom:0; }
.hl-timeline__dot { position:absolute; left:-24px; top:4px; width:12px; height:12px;
  border-radius:50%; border:3px solid #0d1117; box-sizing:border-box; }
.hl-timeline__role { font-family:'Space Grotesk',system-ui,sans-serif; font-weight:600; color:#f0f6fc; font-size:1.02rem; }
.hl-timeline__org { color:#8b949e; font-weight:500; }
.hl-timeline__desc { margin-top:6px; color:#c9d1d9; font-size:0.92rem; line-height:1.58; }
```

---

## Component 2 — Branded 404

**New file:** `404.html` at repo root. **CSS:** `.hl-404*` appended to `custom.css`.

GitHub Pages automatically serves `/404.html` for any unknown path. `layout: default` gives it the real nav + footer (so all standard navigation is available in addition to the in-body buttons).

```html
---
layout: default
permalink: /404.html
title: Page Not Found
---
<div class="hl-404">
  <div class="hl-404__code">404</div>
  <div class="hl-404__title">No artifacts found at this path</div>
  <div class="hl-404__desc">The page you're after moved, was never indexed, or the link has gone stale. Pick the hunt back up from one of these.</div>
  <div class="hl-404__log"><span class="m">GET</span> <span id="hl-404-path">/</span> &nbsp;—&nbsp; <span class="s">404 NOT FOUND</span></div>
  <div class="hl-404__actions">
    <a class="hl-404__btn hl-404__btn--primary" href="{{ '/reports/' | relative_url }}">Browse Reports →</a>
    <a class="hl-404__btn hl-404__btn--ghost" href="{{ '/' | relative_url }}">Home</a>
    <a class="hl-404__btn hl-404__btn--ghost" href="{{ '/subscribe/' | relative_url }}">Subscribe</a>
  </div>
</div>
<script>
  (function () {
    var el = document.getElementById('hl-404-path');
    if (el) el.textContent = (location.pathname || '/') + (location.search || '');
  })();
</script>
```

### CSS to append to `custom.css`
```css
/* ===== Branded 404 ===== */
.hl-404 { max-width:680px; margin:0 auto; padding:64px 24px 80px; text-align:center; }
.hl-404__code { font-family:'Space Grotesk',system-ui,sans-serif; font-weight:700;
  font-size:clamp(5rem,17vw,9.5rem); line-height:0.86; letter-spacing:-0.04em;
  background:linear-gradient(180deg,#79c0ff 0%,#1f6feb 100%);
  -webkit-background-clip:text; background-clip:text; color:transparent; }
.hl-404__title { font-family:'Space Grotesk',system-ui,sans-serif; font-size:1.65rem; font-weight:600;
  color:#f0f6fc; margin:18px 0 0; letter-spacing:-0.01em; }
.hl-404__desc { color:#8b949e; font-size:1.02rem; line-height:1.62; margin:14px auto 0; max-width:500px; }
.hl-404__log { display:inline-block; margin:28px 0 0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:0.82rem; color:#8b949e; background:#010409; border:1px solid #21262d; border-radius:7px; padding:10px 15px; }
.hl-404__log .m { color:#79c0ff; }
.hl-404__log .s { color:#f87171; font-weight:600; }
.hl-404__actions { display:flex; flex-wrap:wrap; gap:12px; justify-content:center; margin:34px 0 0; }
.hl-404__btn { display:inline-flex; align-items:center; gap:7px; padding:11px 20px; border-radius:9px;
  font-size:0.92rem; font-weight:600; text-decoration:none; border:1px solid transparent; transition:all .15s; }
.hl-404__btn--primary { background:#1f6feb; color:#fff; }
.hl-404__btn--primary:hover { background:#388bfd; }
.hl-404__btn--ghost { background:#161b22; color:#c9d1d9; border-color:#30363d; }
.hl-404__btn--ghost:hover { border-color:#58a6ff; color:#f0f6fc; }
```

---

## Component 3 — Article JSON-LD + og:type fix

### 3a. New include `_includes/structured-data.liquid`
Emits `TechArticle` JSON-LD. Uses `jsonify` on every string (report titles can contain quotes/colons) and `date_to_xmlschema` for ISO-8601 dates.

```liquid
{%- comment -%} TechArticle JSON-LD for report pages. Included from head.liquid for reports only. {%- endcomment -%}
{%- assign _img = page.thumbnail | default: page["feature-img"] | default: site.header_feature_image -%}
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": {{ page.title | jsonify }},
  "description": {{ page.description | default: site.description | jsonify }},
  "image": {{ _img | absolute_url | jsonify }},
  "datePublished": {{ page.date | date_to_xmlschema | jsonify }},
  "dateModified": {{ page.last_updated | default: page.date | date_to_xmlschema | jsonify }},
  "author": { "@type": "Person", "name": "Joseph Harrison", "url": {{ '/about-me/' | absolute_url | jsonify }} },
  "publisher": {
    "@type": "Organization",
    "name": "The Hunter's Ledger",
    "logo": { "@type": "ImageObject", "url": {{ '/assets/images/apple-touch-icon.png' | absolute_url | jsonify }} }
  },
  "mainEntityOfPage": { "@type": "WebPage", "@id": {{ page.url | absolute_url | jsonify }} }{% if page.category %},
  "articleSection": {{ page.category | jsonify }}{% endif %}
}
</script>
```

### 3b. `head.liquid` — include for reports only + remove the og:type bug
In `_includes/default/head.liquid`:

1. **Remove** the buggy manual og:type block (currently ~lines 79–81). `page.layout == post` compares to the undefined variable `post` (not the string `"post"`), so it always renders and reports get `og:type=website` while `{% seo %}` independently emits `article` — a conflicting duplicate.
   ```liquid
   {% unless page.layout == post %}
   <meta property="og:type" content="website" />
   {% endunless %}
   ```
   Deleting it makes `{% seo %}` (jekyll-seo-tag) the single owner of `og:type` (it emits `article` for posts, `website` otherwise).

2. **Add**, immediately after the `{% seo %}` line, the reports-only structured-data include:
   ```liquid
   {% if page.layout == "post" and page.url contains "/reports/" %}{% include structured-data.liquid %}{% endif %}
   ```
   `page.url contains "/reports/"` selects reports and excludes `/hunting-detections/` detection pages.

---

## Component 4 — Image lazy-loading (`loading="lazy"`)

GitHub Pages runs no custom build plugins, so the native HTML attribute (present at parse time) is the correct, reliable approach — not runtime JS.

### 4a. Existing report images (this repo)
Add `loading="lazy"` to every `<img …>` in `reports/**/*.md` that does not already have a `loading=` attribute. Implemented as a **reviewed scripted edit** (`python`, idempotent: skip any `<img` that already contains `loading=`). Scope = `reports/**/*.md` only (report bodies + embedded SVG infographics, which are `<img src="*.svg">`). Do **not** touch `_includes`/`_layouts` images (sponsor logos, related-card markup). The diff is reviewed before commit; the attribute is inert.

### 4b. Future reports (AIAgents_Workflows skills — not git)
Add `loading="lazy"` to the canonical `<figure><img …>` block wherever it is templated, so new reports ship with it:
- `.claude/skills/hunters-ledger-publish/SKILL.md` (figure-block reference)
- `.claude/skills/report-screenshot-placement/` (figure-block the skill inserts)
- `.claude/skills/report-infographics/` (SVG `<img>` embed block)

Canonical updated block:
```html
<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/[slug]/[filename].png" | relative_url }}" alt="...">
  <figcaption><em>Figure N: …</em></figcaption>
</figure>
```

---

## Files touched

**`Threat-Intel-Reports` (branch `site-polish-about-404-seo`):**
| File | Change |
|---|---|
| `about-me/index.md` | header, creds strip, experience timeline |
| `404.html` | new file |
| `assets/css/custom.css` | append `.hl-creds-strip` / `.hl-cred-pill` / `.hl-timeline*` / `.hl-404*` |
| `_includes/structured-data.liquid` | new include (TechArticle JSON-LD) |
| `_includes/default/head.liquid` | include structured-data for reports; remove buggy og:type block |
| `reports/**/*.md` | add `loading="lazy"` to `<img>` (bulk, idempotent) |
| `docs/superpowers/specs/2026-06-01-site-polish-about-404-seo-design.md` | this spec |
| `docs/superpowers/plans/2026-06-01-site-polish-about-404-seo-plan.md` | implementation plan (next) |

**`AIAgents_Workflows` (not git):** the three skill figure-block updates in 4b.

## Deployment & verification

- All repo work on `site-polish-about-404-seo`, committed per component (stage files explicitly — the working tree has unrelated untracked files that must NOT be swept in). **No `git push` without explicit user OK.**
- **Pre-push verification** (no local Jekyll): re-render `about-me` and `404` against the branch files in the visual companion; validate the JSON-LD with Google's Rich Results Test using a sample report's rendered `<head>`.
- **Post-deploy verification** (live site, after the user pushes):
  1. `/about-me/` shows the pill strip + timeline; header is tightened.
  2. A random bad URL (e.g. `/nope`) serves the branded 404 with the path filled into the log line; the three buttons resolve.
  3. View-source a report: one `TechArticle` JSON-LD block, valid; exactly one `og:type` (`article`), no `website` duplicate.
  4. A report's `<img>` tags carry `loading="lazy"`; images appear on scroll; page renders identically.

## Risks (all low, reversible)
- **og:type:** removing the manual block relies on `{% seo %}` emitting og:type (it does) — confirmed at post-deploy step 3.
- **JSON-LD validity:** validated with Rich Results Test pre-push; worst case Google ignores it (no reader/ranking harm).
- **Lazy-load bulk edit:** idempotent scripted change, reviewed diff, inert attribute. Report intros are text so the first images are below the fold — no LCP regression.
- **CSS:** all new classes are prefixed — no collision/regression on other pages.
