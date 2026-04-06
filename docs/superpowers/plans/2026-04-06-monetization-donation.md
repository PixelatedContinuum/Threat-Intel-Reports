# Monetization: Donation & Sponsorship Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a PayPal donation button, support page, post-footer CTA, and sponsorship tier infrastructure to The Hunter's Ledger Jekyll site.

**Architecture:** Five independent file changes committed in sequence. The support page and about-me position bump are committed atomically (same commit) to avoid a nav collision. All other tasks can be committed independently. No local build tool is available — verification is done by pushing to GitHub and checking `https://the-hunters-ledger.com` via GitHub Pages.

**Tech Stack:** Jekyll (GitHub Pages), Liquid templating, HTML, CSS custom properties, `_data/` YAML files.

**Spec:** `docs/superpowers/specs/2026-04-06-monetization-donation-design.md`

---

## Chunk 1: Data layer and includes

### Task 1: Create `_data/sponsors.yml`

**Files:**
- Create: `_data/sponsors.yml` (directory must be created first — it does not exist)

The `_data/` directory must exist at the repo root for Jekyll to load data files. Create it, then create the YAML file.

- [ ] **Step 1: Create the `_data/` directory and `sponsors.yml`**

Create `_data/sponsors.yml` with this exact content:

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

- [ ] **Step 2: Verify the file is valid YAML**

Run: `python -c "import yaml; yaml.safe_load(open('C:/Users/josep/Documents/GitHub/Threat-Intel-Reports/_data/sponsors.yml'))" && echo OK`

Expected: `OK` with no errors. If Python is not available, visually confirm no tab characters (use spaces only) and that `sponsors: []` is on its own line.

- [ ] **Step 3: Commit**

```bash
git add _data/sponsors.yml
git commit -m "feat: add sponsor data file with tier definitions"
```

---

### Task 2: Create `_includes/support-cta.html`

**Files:**
- Create: `_includes/support-cta.html`

This is the post-footer donation card. It has no Liquid logic — it's pure HTML. It will be included in `post.html` in Task 4.

- [ ] **Step 1: Create `_includes/support-cta.html`**

```html
<div class="hl-support-cta">
  <div class="hl-support-cta__heading">Support Independent Threat Research</div>
  <p class="hl-support-cta__body">If this report was useful, consider supporting the work that goes into it.</p>
  <div class="hl-support-cta__actions">
    <a class="hl-support-cta__btn" href="https://www.paypal.me/thehuntersledger" target="_blank" rel="noopener noreferrer">Donate via PayPal</a>
    <a class="hl-support-cta__secondary" href="/support/">Other ways to support →</a>
  </div>
</div>
```

- [ ] **Step 2: Commit**

```bash
git add _includes/support-cta.html
git commit -m "feat: add post-footer support CTA include"
```

---

## Chunk 2: Support page and nav

### Task 3: Create `support.md` and bump `about-me` to position 7 (atomic)

**Files:**
- Create: `support.md`
- Modify: `about-me/index.md` — front matter `position: 6` → `position: 7`

These two changes **must be in the same commit**. The navbar sorts by `position` with no collision handling. If both pages hold `position: 6` at the same time (even briefly between deploys), the display order is undefined.

- [ ] **Step 1: Edit `about-me/index.md` front matter**

Change line 6 from:
```yaml
position: 6
```
To:
```yaml
position: 7
```

- [ ] **Step 2: Create `support.md`**

Create `support.md` at the repo root with this content. Follow the pattern of `subscribe.md` and `about-me/index.md` for page structure.

```markdown
---
title: Support
layout: page
permalink: /support/
position: 6
---

<div class="hl-page-header" style="border-left-color: #4ade80;">
  <div class="hl-page-header__label" style="color: #4ade80;">Support the Work</div>
  <div class="hl-page-header__title">Keep This Research Independent</div>
  <div class="hl-page-header__desc">The Hunter's Ledger is run by a single researcher. No corporate backing, no paywalls, no ads. Your support keeps it that way.</div>
</div>

{% include section-header.html label="Donate" accent="#4ade80" %}

<div class="hl-support-section">
  <div class="hl-prose-section">
    <div class="hl-prose-section__body">
      Every report on this site is the product of original research — hands-on malware analysis, open-directory hunts, and detection engineering done on personal time and personal resources. Hosting, tooling, and the time it takes to do it right all have real costs. If the research has been useful to you or your team, a donation directly supports more of it.
    </div>
  </div>
  <div class="hl-support-donate">
    <a class="hl-support-cta__btn" href="https://www.paypal.me/thehuntersledger" target="_blank" rel="noopener noreferrer">Donate via PayPal</a>
    <p class="hl-support-donate__note">One-time donations via PayPal.me. Every contribution is appreciated.</p>
  </div>
</div>

{% include section-header.html label="Consulting & Advisory" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Available for threat model reviews, retainer advisory, and custom threat intelligence research. Work is scoped around your environment and threat profile — not generic frameworks. Engagements are kept selective to maintain quality and independence.<br><br>
    <a href="/consulting/">View consulting services →</a>
  </div>
</div>

{% include section-header.html label="Cost of Running This" accent="#f97316" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#f97316;"></div>
    What Goes Into Each Report
  </div>
  <div class="hl-prose-section__body">
    A typical report takes <strong>8 to 15 hours</strong> of active research time — static and dynamic malware analysis, infrastructure pivoting, detection rule development, and structured write-up. Tools like sandboxes, threat intel platforms, and reverse engineering environments carry ongoing costs. The domain, hosting, and delivery infrastructure add to that each month.<br><br>
    None of this is paywalled because the research is more valuable when it reaches defenders directly. But it is not free to produce.
  </div>
</div>

{% include section-header.html label="Sponsorship Tiers" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Organizations can sponsor individual reports, a batch of reports, or on a monthly basis. Sponsors receive logo placement and a link on sponsored content. Sponsorship does not influence research conclusions or methodology — editorial independence is non-negotiable.
  </div>
</div>

{% assign tiers = site.data.sponsors.tiers %}
{% assign sponsors = site.data.sponsors.sponsors %}

<div class="hl-tier-grid">
  {% for tier in tiers %}
  <div class="hl-tier-card">
    <div class="hl-tier-card__name">{{ tier.name }}</div>
    <div class="hl-tier-card__desc">{{ tier.description }}</div>
    <div class="hl-tier-card__slots">
      {% assign tier_sponsors = sponsors | where: "tier", tier.id %}
      {% for sponsor in tier_sponsors %}
      <div class="hl-tier-card__sponsor">
        {% if sponsor.logo %}
        <img class="hl-tier-card__logo" src="{{ sponsor.logo }}" alt="{{ sponsor.name }}">
        {% endif %}
        {% if sponsor.url %}
        <a href="{{ sponsor.url }}" target="_blank" rel="noopener noreferrer" class="hl-tier-card__sponsor-name">{{ sponsor.name }}</a>
        {% else %}
        <span class="hl-tier-card__sponsor-name">{{ sponsor.name }}</span>
        {% endif %}
      </div>
      {% endfor %}
      {% assign filled = tier_sponsors | size %}
      {% assign remaining = tier.slots | minus: filled %}
      {% for i in (1..remaining) %}
      <div class="hl-tier-card__placeholder">— available —</div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}
</div>

<p class="hl-support-contact">To discuss sponsorship, reach out at <a href="mailto:contact@the-hunters-ledger.com">contact@the-hunters-ledger.com</a>.</p>
```

- [ ] **Step 3: Commit both files atomically**

```bash
git add support.md about-me/index.md
git commit -m "feat: add support page and bump about-me to position 7"
```

- [ ] **Step 4: Push and verify nav order**

```bash
git push
```

After GitHub Pages finishes building (typically 1-2 minutes), visit `https://the-hunters-ledger.com` and confirm the navbar reads: Home · Reports · Detections · IOC Feeds · Subscribe · **Support** · About Me

---

## Chunk 3: Post layout modifications

### Task 4: Modify `_layouts/post.html`

**Files:**
- Modify: `_layouts/post.html`

Two insertions into `post.html`:
1. **Sponsored-by banner** — immediately before `<div class="hl-post-body">` (currently line 28)
2. **Support CTA include** — between `</div>` (close of `.hl-post-body`, currently line 41) and `{% assign rp_pool` (currently line 43)

- [ ] **Step 1: Insert the sponsored-by banner before `.hl-post-body`**

In `_layouts/post.html`, find this line (currently around line 28):
```html
<div class="hl-post-body">
```

Insert this block **immediately before** it:
```liquid
{% if page.sponsored_by %}
{% assign sponsor = site.data.sponsors.sponsors | where: "id", page.sponsored_by | first %}
{% if sponsor %}
<div class="hl-sponsor-banner">
  <span class="hl-sponsor-banner__label">Sponsored by</span>
  {% if sponsor.url %}<a class="hl-sponsor-banner__name" href="{{ sponsor.url }}" target="_blank" rel="noopener noreferrer">{% else %}<span class="hl-sponsor-banner__name">{% endif %}
    {% if sponsor.logo %}<img class="hl-sponsor-banner__logo" src="{{ sponsor.logo }}" alt="{{ sponsor.name }}">{% else %}{{ sponsor.name }}{% endif %}
  {% if sponsor.url %}</a>{% else %}</span>{% endif %}
</div>
{% endif %}
{% endif %}
```

- [ ] **Step 2: Insert the support CTA include**

Find this block (currently lines 41-43):
```
</div>

{% assign rp_pool
```

Insert `{% include support-cta.html %}` between the closing `</div>` and the `{% assign rp_pool` line, so it reads:

```
</div>

{% include support-cta.html %}

{% assign rp_pool
```

- [ ] **Step 3: Commit**

```bash
git add _layouts/post.html
git commit -m "feat: add sponsored-by banner and support CTA to post layout"
```

- [ ] **Step 4: Push and verify CTA appears on posts**

```bash
git push
```

After Pages builds, open any report (e.g., a recent one from `/reports/` or `/hunting-detections/`). Confirm:
- A "Support Independent Threat Research" card appears below the article body, above "Continue Reading"
- The card has a "Donate via PayPal" button and an "Other ways to support →" link
- The `sponsored_by` banner does **not** appear (no post has it set yet)

---

## Chunk 4: Styling

### Task 5: Add CSS to `assets/css/custom.css`

**Files:**
- Modify: `assets/css/custom.css` (append new sections at the end of the file, currently 1931 lines)

- [ ] **Step 1: Append the support CTA styles**

Add at the end of `assets/css/custom.css`:

```css
/* ============================================================
   SUPPORT CTA — post-footer donation card
   ============================================================ */

.hl-support-cta {
  background: var(--hl-bg-card);
  border: 1px solid var(--hl-border-card);
  border-left: 4px solid var(--hl-accent-green);
  border-radius: 6px;
  padding: 20px 24px;
  margin: 2.5rem 0;
}

.hl-support-cta__heading {
  color: var(--hl-text-primary);
  font-size: 1em;
  font-weight: 700;
  margin: 0 0 8px;
}

.hl-support-cta__body {
  color: var(--hl-text-secondary);
  font-size: 0.88em;
  line-height: 1.6;
  margin: 0 0 16px;
}

.hl-support-cta__actions {
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}

.hl-support-cta__btn {
  display: inline-block;
  background: var(--hl-accent-green);
  color: #111111 !important;
  font-size: 0.85em;
  font-weight: 700;
  padding: 9px 18px;
  border-radius: 5px;
  text-decoration: none !important;
  transition: opacity 0.15s;
  white-space: nowrap;
}

.hl-support-cta__btn:hover {
  opacity: 0.85;
  text-decoration: none !important;
}

.hl-support-cta__secondary {
  color: var(--hl-text-muted) !important;
  font-size: 0.82em;
  text-decoration: none !important;
  transition: color 0.15s;
}

.hl-support-cta__secondary:hover {
  color: var(--hl-text-secondary) !important;
  text-decoration: none !important;
}

/* ============================================================
   SPONSOR BANNER — per-post sponsored-by header
   ============================================================ */

.hl-sponsor-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 5px;
  padding: 9px 16px;
  margin-bottom: 1.5rem;
}

.hl-sponsor-banner__label {
  color: var(--hl-text-muted);
  font-size: 0.72em;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  white-space: nowrap;
}

.hl-sponsor-banner__name,
.hl-sponsor-banner__name:visited {
  color: var(--hl-text-secondary) !important;
  font-size: 0.85em;
  font-weight: 600;
  text-decoration: none !important;
  display: flex;
  align-items: center;
  gap: 8px;
  transition: color 0.15s;
}

.hl-sponsor-banner__name:hover {
  color: var(--hl-text-primary) !important;
}

.hl-sponsor-banner__logo {
  height: 20px;
  width: auto;
  object-fit: contain;
  vertical-align: middle;
}

/* ============================================================
   SUPPORT PAGE — sections, donate block, tier grid
   ============================================================ */

.hl-support-section {
  margin-bottom: 1.5rem;
}

.hl-support-donate {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-top: 14px;
  padding: 16px 18px;
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 5px;
}

.hl-support-donate__note {
  color: var(--hl-text-muted);
  font-size: 0.8em;
  margin: 0;
}

/* Tier grid */
.hl-tier-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 2rem;
}

@media (max-width: 700px) {
  .hl-tier-grid {
    grid-template-columns: 1fr;
  }
}

.hl-tier-card {
  background: var(--hl-bg-card);
  border: 1px solid var(--hl-border-card);
  border-radius: 6px;
  padding: 16px;
}

.hl-tier-card__name {
  color: var(--hl-accent-blue);
  font-size: 0.82em;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 6px;
}

.hl-tier-card__desc {
  color: var(--hl-text-muted);
  font-size: 0.78em;
  line-height: 1.5;
  margin-bottom: 14px;
}

.hl-tier-card__slots {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.hl-tier-card__sponsor {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 4px;
}

.hl-tier-card__logo {
  height: 18px;
  width: auto;
  object-fit: contain;
}

.hl-tier-card__sponsor-name,
.hl-tier-card__sponsor-name:visited {
  color: var(--hl-text-secondary) !important;
  font-size: 0.82em;
  font-weight: 600;
  text-decoration: none !important;
}

.hl-tier-card__sponsor-name:hover {
  color: var(--hl-text-primary) !important;
}

.hl-tier-card__placeholder {
  padding: 8px 10px;
  border: 1px dashed var(--hl-border-row);
  border-radius: 4px;
  color: var(--hl-text-dim);
  font-size: 0.78em;
  text-align: center;
  letter-spacing: 0.05em;
}

.hl-support-contact {
  color: var(--hl-text-muted);
  font-size: 0.8em;
  margin-top: 0.75rem;
}
```

- [ ] **Step 2: Commit**

```bash
git add assets/css/custom.css
git commit -m "feat: add CSS for support CTA, sponsor banner, and support page"
```

- [ ] **Step 3: Push and do a full visual verification**

```bash
git push
```

After Pages builds, verify the following:

**Support page (`/support/`):**
- Green left-border page header
- Donate section with green PayPal button
- Consulting teaser with link
- "Cost of Running This" section with orange accent
- Three-column tier grid with "— available —" placeholder slots in each tier

**Any report post:**
- "Support Independent Threat Research" green-bordered card appears below the article, above "Continue Reading"
- Card has PayPal button and secondary link
- Card appears on hunting-detections pages too

**Navbar:**
- Order is: Home · Reports · Detections · IOC Feeds · Subscribe · Support · About Me

**Sponsored-by banner (manual test):**
- Temporarily add `sponsored_by: nonexistent-id` to any post's front matter and push
- Confirm no banner appears (the `{% if sponsor %}` guard handles a missing id gracefully)
- Remove the test front matter and push again

---

## Post-Implementation: Adding a Real Sponsor

When you land a sponsor, the workflow is:

1. Add a logo image to `assets/images/sponsors/<sponsor-id>.png`
2. Add an entry to `_data/sponsors.yml`:
   ```yaml
   sponsors:
     - id: acme-corp
       name: Acme Corp
       logo: /assets/images/sponsors/acme-corp.png
       url: https://example.com
       tier: report
   ```
3. Add `sponsored_by: acme-corp` to the front matter of the sponsored report(s)
4. Commit and push — the banner renders on the post and the slot fills in on the support page automatically
