# Monetization: Donation & Sponsorship Design

**Date:** 2026-04-06
**Status:** Approved
**Approach:** B — Support page + `_data/sponsors.yml`

---

## Overview

Add a PayPal donation button and sponsorship infrastructure to The Hunter's Ledger. The implementation touches four areas: a new Support page, a data file for sponsor management, a post-footer donation CTA on all posts, and a `sponsored_by` banner system for individual reports.

---

## Files Changed

| File | Action |
|---|---|
| `support.md` | Create — new support page |
| `about-me/index.md` | Modify — bump position from 6 to 7 |
| `_data/` | Create directory — does not exist yet in the repo |
| `_data/sponsors.yml` | Create — tier definitions and sponsor entries |
| `_includes/support-cta.html` | Create — post-footer donation card |
| `_layouts/post.html` | Modify — include sponsored_by banner and CTA |
| `assets/css/custom.css` | Modify — styles for all new components |

**Implementation sequencing note:** `about-me/index.md` must be bumped to position 7 in the same commit that creates `support.md` at position 6. The navbar uses a simple `sort: 'position'` with no collision handling — if both pages temporarily hold position 6, display order is undefined. Treat this as an atomic change.

---

## Section 1: Support Page (`support.md`)

- Front matter: `layout: page`, `title: Support`, `position: 6`
- `about-me/index.md` position updated to 7 so it remains last in nav
- Navbar picks it up automatically via existing position-sorted nav logic

### Page sections (top to bottom):

**1. Donate**
- Heading: "Support Independent Research"
- Copy: short paragraph explaining the site is independently run, no corporate backing, no paywalls
- PayPal button linking to `https://www.paypal.me/thehuntersledger`
- Note that one-time donations are supported via PayPal.me

**2. Consulting & Advisory**
- 3-4 sentence teaser describing services (threat model review, retainer advisory, custom research)
- Links to the future `/consulting/` page (stub link for now)

**3. Cost of Running This**
- Honest, non-pity breakdown: hosting, tooling, time per report (8-15 hours)
- Framed as context, not guilt — keeps the tone professional

**4. Sponsorship Tiers**
- Three tiers rendered from `_data/sponsors.yml`:
  - **Report Sponsor** — logo + link on a single report via `sponsored_by:` front matter
  - **Multi-Report Sponsor** — logo + link across a defined set of reports via `sponsored_by:` front matter on each report
  - **Monthly Sponsor** — logo on the Support page only; per-report presence is editorial (author adds `sponsored_by:` to relevant reports manually)
- Each tier shows current active sponsors (if any) followed by dashed placeholder slots with muted "— available —" text
- Contact email below tiers for sponsorship inquiries

---

## Section 2: Sponsor Data (`_data/sponsors.yml`)

The `_data/` directory does not currently exist and must be created. Jekyll requires this directory at the repo root for data files to be loaded.

Two top-level keys:

```yaml
tiers:
  - id: report
    name: Report Sponsor
    description: "Logo and link featured on a single research report."
    slots: 3
  - id: multi-report
    name: Multi-Report Sponsor
    description: "Logo and link across a defined set of reports."
    slots: 2
  - id: monthly
    name: Monthly Sponsor
    description: "Logo on the Support page. Author adds sponsored_by: to relevant reports each month."
    slots: 1

sponsors: []
```

Each sponsor entry (when added) will have:
```yaml
sponsors:
  - id: acme-corp
    name: Acme Corp
    logo: /assets/images/sponsors/acme-corp.png
    url: https://example.com
    tier: monthly
```

Report front matter references a sponsor by id:
```yaml
sponsored_by: acme-corp
```

The `sponsored_by` field is used by all three tiers — Report Sponsor (one report), Multi-Report Sponsor (multiple reports), and Monthly Sponsor (author-selected reports). The mechanism is identical regardless of tier.

---

## Section 3: Post-Footer Donation CTA (`_includes/support-cta.html`)

- Appears at the bottom of **all posts** — both reports and hunting-detections pages
- The `unless page.path contains "hunting-detections"` exclusion is **not** applied — CTA shows on all post layout pages
- Styled as a dark card matching the existing `.hl-card` aesthetic
- Content:
  - Heading: "Support Independent Threat Research"
  - Copy: "If this report was useful, consider supporting the work that goes into it."
  - PayPal button linking to `https://www.paypal.me/thehuntersledger`
  - Muted secondary link: "Other ways to support →" pointing to `/support/`

---

## Section 4: Sponsored By Banner (`post.html` + CSS)

- When a post has `sponsored_by: <id>` in front matter, a small banner renders outside `.hl-post-body`, immediately before its opening tag
- Banner looks up the sponsor entry in `site.data.sponsors.sponsors` by id using a Liquid `where` filter
- When `sponsored_by` is absent, nothing renders — zero visual impact on unsponsored posts
- Styled to be visually distinct but not dominant — muted, professional

### Banner HTML structure:

```html
<div class="hl-sponsor-banner">
  <span class="hl-sponsor-banner__label">Sponsored by</span>
  <a class="hl-sponsor-banner__name" href="{{ sponsor.url }}">
    {% if sponsor.logo %}
    <img class="hl-sponsor-banner__logo" src="{{ sponsor.logo }}" alt="{{ sponsor.name }}">
    {% else %}
    {{ sponsor.name }}
    {% endif %}
  </a>
</div>
```

- `.hl-sponsor-banner__label` — static "Sponsored by" prefix text
- `.hl-sponsor-banner__name` — wraps the logo or name text; links to sponsor URL
- `.hl-sponsor-banner__logo` — sponsor logo image (optional; falls back to name text if absent)

---

## Section 5: `post.html` Modification Map

The following shows the intended element order in `post.html` after modifications, from the post header through the CTA:

```
<div class="hl-post-header"> ... </div>          ← existing, unchanged

{% if page.sponsored_by %}                         ← NEW: sponsor banner (outside hl-post-body)
  <div class="hl-sponsor-banner"> ... </div>
{% endif %}

<div class="hl-post-body">
  <details class="hl-post-toc-mobile"> ... </details>
  <div id="hl-toc-spacer"> ... </div>
  <div class="hl-post-content"> ... </div>         ← existing content
  <aside class="hl-post-toc"> ... </aside>
</div>

{% include support-cta.html %}                     ← NEW: donation CTA (outside hl-post-body)

{% assign rp_pool = ... %}                         ← existing "Continue Reading" block
{% if rp_list.size > 0 %}
  <div class="hl-related"> ... </div>
{% endif %}

{% unless page.path contains "hunting-detections" %}
  <div class="hl-quicklinks"> ... </div>           ← existing quicklinks (unchanged)
{% endunless %}
```

The sponsored_by banner sits just above `.hl-post-body` (outside it). The CTA sits between the closing of `.hl-post-body` and the "Continue Reading" block.

---

## Styling (`assets/css/custom.css`)

New CSS classes needed:

| Class | Purpose |
|---|---|
| `.hl-support-cta` | Post-footer donation card container |
| `.hl-support-cta__heading` | Card heading |
| `.hl-support-cta__body` | Copy text |
| `.hl-support-cta__btn` | PayPal donate button |
| `.hl-support-cta__secondary` | "Other ways to support" muted link |
| `.hl-sponsor-banner` | Sponsored-by banner on posts |
| `.hl-sponsor-banner__label` | Static "Sponsored by" prefix text |
| `.hl-sponsor-banner__name` | Wraps logo or name text; links to sponsor URL |
| `.hl-sponsor-banner__logo` | Sponsor logo image |
| `.hl-support-section` | Section wrapper on support page |
| `.hl-tier-grid` | Grid of sponsorship tier cards |
| `.hl-tier-card` | Individual tier card |
| `.hl-tier-card__placeholder` | Dashed "— available —" sponsor slot |

All new styles follow the existing dark theme variables and naming conventions already in `custom.css`.

---

## Out of Scope

The following were considered and explicitly excluded:

- GitHub Sponsors integration
- Paid/premium IOC feed tier
- PDF gated downloads
- Recurring donations via PayPal.me (not natively supported)
- Consulting page content (separate checklist item, stub link only)
