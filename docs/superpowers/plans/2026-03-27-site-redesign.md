# Site Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign The Hunter's Ledger Jekyll site with a consistent dark card system — severity bars, colored tag badges, and page-appropriate layouts — across all six public-facing pages.

**Architecture:** Add a custom CSS file for the design system, four reusable Liquid include components, then update each page to use them. The Jekyll remote theme (Type-on-Strap) is preserved; only the CSS hook and page content change.

**Tech Stack:** Jekyll (GitHub Pages), Liquid templates, plain CSS, Markdown

---

## Chunk 1: Setup — CSS injection + design system

### Task 1: Add `.superpowers/` to `.gitignore`

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Check whether `.gitignore` exists**

```bash
cat .gitignore 2>/dev/null || echo "no .gitignore"
```

- [ ] **Step 2: Add `.superpowers/` entry**

If `.gitignore` does not exist, create it. If it exists, append the line.

```bash
grep -qF ".superpowers/" .gitignore || echo ".superpowers/" >> .gitignore
```

- [ ] **Step 3: Verify**

```bash
grep ".superpowers" .gitignore
```

Expected: `.superpowers/`

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore .superpowers brainstorm directory"
```

---

### Task 2: Override theme `head.liquid` to inject custom CSS

The site uses the `sylhare/Type-on-Strap` remote theme. To add a custom stylesheet, override `_includes/default/head.liquid` (the same pattern already used for `_includes/default/navbar.liquid`).

**Files:**
- Create: `_includes/default/head.liquid`

- [ ] **Step 1: Fetch the theme's current `head.liquid`**

Open the Type-on-Strap repository on GitHub and navigate to `_includes/default/head.liquid`. Copy the raw file contents. The file is in the `sylhare/Type-on-Strap` repo, same branch the `remote_theme` config points to.

- [ ] **Step 2: Create local override and add CSS link**

Create `_includes/default/head.liquid` with the theme's full content, then add the following line immediately before the closing `</head>` tag:

```html
<link rel="stylesheet" href="{{ '/assets/css/custom.css' | relative_url }}">
```

- [ ] **Step 3: Verify file exists and contains the link**

```bash
grep "custom.css" _includes/default/head.liquid
```

Expected: the link tag appears.

- [ ] **Step 4: Commit**

```bash
git add _includes/default/head.liquid
git commit -m "feat: override head.liquid to load custom CSS"
```

---

### Task 3: Create the design system CSS

**Files:**
- Create: `assets/css/custom.css`

- [ ] **Step 1: Create `assets/css/custom.css`**

```css
/* ============================================================
   The Hunter's Ledger — Design System
   ============================================================ */

/* --- Tokens ------------------------------------------------- */
:root {
  --hl-bg-page:      #111111;
  --hl-bg-card:      #1a1a1a;
  --hl-bg-row:       #161616;
  --hl-border-card:  #2a2a2a;
  --hl-border-row:   #222222;
  --hl-text-primary: #eeeeee;
  --hl-text-muted:   #888888;
  --hl-text-dim:     #555555;
  --hl-accent-blue:  #58a6ff;
  --hl-sev-high:     #ff4444;
  --hl-sev-high-lbl: #ff6666;
  --hl-sev-med:      #f97316;
  --hl-sev-med-lbl:  #fb923c;
  --hl-accent-green: #4ade80;
  --hl-accent-red:   #f87171;
  --hl-text-secondary: #aaaaaa;
}

/* --- Featured card grid ------------------------------------- */
.hl-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
  margin-bottom: 2rem;
}

.hl-card {
  background: var(--hl-bg-card);
  border: 1px solid var(--hl-border-card);
  border-radius: 6px;
  overflow: hidden;
  text-decoration: none;
  display: block;
  color: inherit;
  transition: border-color 0.15s;
}
.hl-card:hover { border-color: #444; text-decoration: none; }

.hl-card__inner {
  padding: 12px;
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.hl-card__bar {
  width: 3px;
  min-height: 52px;
  border-radius: 2px;
  flex-shrink: 0;
  margin-top: 2px;
}

.hl-card__meta {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 3px;
}

.hl-card__title {
  color: var(--hl-text-primary);
  font-size: 0.85rem;
  font-weight: 600;
  line-height: 1.35;
  margin: 0 0 8px;
}

/* --- Compact row list --------------------------------------- */
.hl-row-list {
  display: flex;
  flex-direction: column;
  gap: 5px;
  margin-bottom: 2rem;
}

.hl-row {
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 4px;
  display: flex;
  align-items: stretch;
  overflow: hidden;
  text-decoration: none;
  color: inherit;
  transition: border-color 0.15s;
}
.hl-row:hover { border-color: #333; text-decoration: none; }

.hl-row__bar {
  width: 2px;
  flex-shrink: 0;
}

.hl-row__body {
  padding: 7px 10px;
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.hl-row__left { flex: 1; }

.hl-row__title {
  color: #dddddd;
  font-size: 0.8rem;
  font-weight: 500;
  margin: 0;
}

.hl-row__date {
  color: var(--hl-text-dim);
  font-size: 0.65rem;
  text-transform: uppercase;
  flex-shrink: 0;
}

/* --- Tag badges -------------------------------------------- */
.hl-tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 4px;
}

.hl-tag {
  font-size: 0.65rem;
  padding: 1px 5px;
  border-radius: 3px;
  border: 1px solid;
  white-space: nowrap;
}

.hl-tag--blue   { background: #1f6feb33; color: #58a6ff; border-color: #1f6feb55; }
.hl-tag--red    { background: #b91c1c33; color: #f87171; border-color: #b91c1c55; }
.hl-tag--green  { background: #16653433; color: #4ade80; border-color: #16653455; }
.hl-tag--purple { background: #7c3aed33; color: #c084fc; border-color: #7c3aed55; }
.hl-tag--yellow { background: #3a3a1a;   color: #facc15; border-color: #aaaa2255; }

/* --- Severity bar colors ----------------------------------- */
.hl-sev--high { background: var(--hl-sev-high); }
.hl-sev--med  { background: var(--hl-sev-med); }
.hl-sev--info { background: #333333; }

/* --- Section header ---------------------------------------- */
.hl-section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: #aaaaaa;
  border-bottom: 1px solid var(--hl-border-row);
  padding-bottom: 6px;
  margin: 1.5rem 0 12px;
}

.hl-section-header__bar {
  width: 2px;
  height: 12px;
  border-radius: 1px;
  flex-shrink: 0;
}

/* --- Page header card -------------------------------------- */
.hl-page-header {
  background: linear-gradient(135deg, var(--hl-bg-card), #0d1117);
  border: 1px solid var(--hl-border-card);
  border-radius: 6px;
  padding: 16px 20px;
  margin-bottom: 1.5rem;
}

.hl-page-header__label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  margin-bottom: 4px;
}

.hl-page-header__title {
  color: var(--hl-text-primary);
  font-size: 1.1rem;
  font-weight: 700;
  margin: 0 0 6px;
}

.hl-page-header__desc {
  color: var(--hl-text-muted);
  font-size: 0.82rem;
  line-height: 1.5;
  margin: 0;
}

/* --- Prose section card ------------------------------------ */
.hl-prose-section {
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 5px;
  padding: 12px 16px;
  margin-bottom: 10px;
}

.hl-prose-section__label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #aaaaaa;
  margin-bottom: 8px;
}

.hl-prose-section__bar {
  width: 2px;
  height: 12px;
  border-radius: 1px;
}

.hl-prose-section__body {
  color: var(--hl-text-muted);
  font-size: 0.85rem;
  line-height: 1.6;
  margin: 0;
}

.hl-prose-section__body a {
  color: var(--hl-accent-blue);
}

/* --- Nav tile grid ----------------------------------------- */
.hl-nav-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 1.5rem;
}

.hl-nav-tile {
  background: var(--hl-bg-row);
  border: 1px solid var(--hl-border-row);
  border-radius: 5px;
  padding: 10px 12px;
  text-decoration: none;
  display: block;
  transition: border-color 0.15s;
}
.hl-nav-tile:hover { border-color: #333; text-decoration: none; }

.hl-nav-tile__title {
  color: var(--hl-accent-blue);
  font-size: 0.8rem;
  font-weight: 600;
  margin: 0 0 3px;
}

.hl-nav-tile__desc {
  color: var(--hl-text-dim);
  font-size: 0.7rem;
  margin: 0;
}

/* --- Note / callout box ------------------------------------ */
.hl-note {
  background: #1a1a0d;
  border: 1px solid #3a3a1a;
  border-radius: 5px;
  padding: 10px 14px;
  margin-bottom: 10px;
}

.hl-note__label {
  color: #facc15;
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}

.hl-note__body {
  color: var(--hl-text-muted);
  font-size: 0.8rem;
  line-height: 1.5;
  margin: 0;
}

/* --- Logo / hero area -------------------------------------- */
.hl-hero {
  display: flex;
  align-items: center;
  gap: 16px;
  background: linear-gradient(135deg, var(--hl-bg-card), #0d1117);
  border: 1px solid var(--hl-border-card);
  border-left: 3px solid var(--hl-sev-high);
  border-radius: 6px;
  padding: 16px 20px;
  margin-bottom: 1.5rem;
}

.hl-hero__logo {
  width: 64px;
  height: 64px;
  object-fit: contain;
  flex-shrink: 0;
}

.hl-hero__label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--hl-sev-high-lbl);
  margin-bottom: 4px;
}

.hl-hero__title {
  color: var(--hl-text-primary);
  font-size: 1.1rem;
  font-weight: 700;
  margin: 0 0 6px;
}

.hl-hero__desc {
  color: var(--hl-text-muted);
  font-size: 0.82rem;
  line-height: 1.5;
  margin: 0;
}

/* --- "View all" link --------------------------------------- */
.hl-view-all {
  display: block;
  text-align: right;
  color: var(--hl-accent-blue);
  font-size: 0.8rem;
  margin-bottom: 1.5rem;
  text-decoration: none;
}
.hl-view-all:hover { text-decoration: underline; }

/* --- Responsive -------------------------------------------- */
@media (max-width: 600px) {
  .hl-grid,
  .hl-nav-grid {
    grid-template-columns: 1fr;
  }
  .hl-hero {
    flex-direction: column;
    align-items: flex-start;
  }
}
```

- [ ] **Step 2: Verify file was created**

```bash
wc -l assets/css/custom.css
```

Expected: 120+ lines

- [ ] **Step 3: Commit**

```bash
git add assets/css/custom.css
git commit -m "feat: add design system CSS"
```

---

## Chunk 2: Liquid include components

### Task 4: Create `_includes/tag-badge.html`

This is a single-tag renderer called by `report-card.html` and `report-row.html`.

**Files:**
- Create: `_includes/tag-badge.html`

Parameter: `include.tag` — a single tag string (e.g. `"MaaS"`, `"Sigma"`, `"IP"`)

Tag → color class mapping:

| Tag values (case-insensitive) | Class |
|---|---|
| c2, rat, ip, hash, maas | `hl-tag--blue` |
| webshell, rce, threat, toolkit, ransomware | `hl-tag--red` |
| open dir, domain, sigma, cryptominer, scanner | `hl-tag--green` |
| loader, suricata, yara, stealer | `hl-tag--purple` |
| anything else | `hl-tag--blue` (fallback) |

- [ ] **Step 1: Create the file**

```liquid
{% assign t = include.tag | strip %}
{% assign tl = t | downcase %}
{% if tl == "c2" or tl == "rat" or tl == "ip" or tl == "hash" or tl == "maas" %}
  <span class="hl-tag hl-tag--blue">{{ t }}</span>
{% elsif tl == "webshell" or tl == "rce" or tl == "threat" or tl == "toolkit" or tl == "ransomware" %}
  <span class="hl-tag hl-tag--red">{{ t }}</span>
{% elsif tl == "open dir" or tl == "domain" or tl == "sigma" or tl == "cryptominer" or tl == "scanner" %}
  <span class="hl-tag hl-tag--green">{{ t }}</span>
{% elsif tl == "loader" or tl == "suricata" or tl == "yara" or tl == "stealer" %}
  <span class="hl-tag hl-tag--purple">{{ t }}</span>
{% elsif tl == "note" or tl == "warning" %}
  <span class="hl-tag hl-tag--yellow">{{ t }}</span>
{% else %}
  <span class="hl-tag hl-tag--blue">{{ t }}</span>
{% endif %}
```

- [ ] **Step 2: Verify**

```bash
cat _includes/tag-badge.html
```

Expected: file contains the `if/elsif` chain shown above.

- [ ] **Step 3: Commit**

```bash
git add _includes/tag-badge.html
git commit -m "feat: add tag-badge include component"
```

---

### Task 5: Create `_includes/section-header.html`

**Files:**
- Create: `_includes/section-header.html`

Parameters: `include.label` (required text), `include.accent` (optional CSS color, defaults to `#aaaaaa`)

- [ ] **Step 1: Create the file**

```liquid
{% assign accent = include.accent | default: "#aaaaaa" %}
<div class="hl-section-header">
  <div class="hl-section-header__bar" style="background: {{ accent }};"></div>
  {{ include.label }}
</div>
```

- [ ] **Step 2: Verify**

```bash
grep "hl-section-header" _includes/section-header.html
```

Expected: line containing `hl-section-header__bar`

- [ ] **Step 3: Commit**

```bash
git add _includes/section-header.html
git commit -m "feat: add section-header include component"
```

---

### Task 6: Create `_includes/report-card.html`

**Files:**
- Create: `_includes/report-card.html`

Parameters:

| Parameter | Required | Example |
|---|---|---|
| `title` | yes | `"ZeroTrace MaaS Operation"` |
| `date` | yes | `"Mar 2026"` |
| `severity` | no | `"high"` or `"med"` |
| `tags` | no | `"MaaS,C2,Open Dir"` |
| `url` | yes | `"/reports/zerotrace-74-0-42-25-20260316/"` |

- [ ] **Step 1: Create the file**

```liquid
{% assign sev_bar   = "hl-sev--info" %}
{% assign sev_color = "#aaaaaa" %}
{% assign sev_label = "" %}
{% if include.severity == "high" %}
  {% assign sev_bar   = "hl-sev--high" %}
  {% assign sev_color = "#ff6666" %}
  {% assign sev_label = "HIGH" %}
{% elsif include.severity == "med" %}
  {% assign sev_bar   = "hl-sev--med" %}
  {% assign sev_color = "#fb923c" %}
  {% assign sev_label = "MED" %}
{% endif %}

<a href="{{ include.url | relative_url }}" class="hl-card">
  <div class="hl-card__inner">
    <div class="hl-card__bar {{ sev_bar }}"></div>
    <div>
      <div class="hl-card__meta" style="color: {{ sev_color }};">
        {% if sev_label != "" %}{{ sev_label }} · {% endif %}{{ include.date }}
      </div>
      <div class="hl-card__title">{{ include.title }}</div>
      {% if include.tags %}
        {% assign tag_list = include.tags | split: "," %}
        <div class="hl-tags">
          {% for tag in tag_list %}
            {% include tag-badge.html tag=tag %}
          {% endfor %}
        </div>
      {% endif %}
    </div>
  </div>
</a>
```

- [ ] **Step 2: Verify**

```bash
cat _includes/report-card.html
```

Expected: file exists and contains `hl-card`, `tag-badge.html` include, and the severity logic.

- [ ] **Step 3: Commit**

```bash
git add _includes/report-card.html
git commit -m "feat: add report-card include component"
```

---

### Task 7: Create `_includes/report-row.html`

**Files:**
- Create: `_includes/report-row.html`

Parameters: same as `report-card.html`

- [ ] **Step 1: Create the file**

```liquid
{% assign sev_bar = "hl-sev--info" %}
{% if include.severity == "high" %}
  {% assign sev_bar = "hl-sev--high" %}
{% elsif include.severity == "med" %}
  {% assign sev_bar = "hl-sev--med" %}
{% endif %}

<a href="{{ include.url | relative_url }}" class="hl-row">
  <div class="hl-row__bar {{ sev_bar }}"></div>
  <div class="hl-row__body">
    <div class="hl-row__left">
      <div class="hl-row__title">{{ include.title }}</div>
      {% if include.tags %}
        {% assign tag_list = include.tags | split: "," %}
        <div class="hl-tags">
          {% for tag in tag_list %}
            {% include tag-badge.html tag=tag %}
          {% endfor %}
        </div>
      {% endif %}
    </div>
    <div class="hl-row__date">{{ include.date }}</div>
  </div>
</a>
```

- [ ] **Step 2: Verify**

```bash
grep "hl-row" _includes/report-row.html
```

Expected: lines containing `hl-row__bar`, `hl-row__body`, `hl-row__title`

- [ ] **Step 3: Commit**

```bash
git add _includes/report-row.html
git commit -m "feat: add report-row include component"
```

---

## Chunk 3: Reports page + Homepage

### Task 8: Rewrite `reports/index.md`

**Files:**
- Modify: `reports/index.md`

Featured grid: March 2026 (2) + February 2026 (3) = 5 reports
List: January 2026 and older = 9 reports

- [ ] **Step 1: Replace the file contents entirely**

```markdown
---
title: Reports
layout: page
permalink: /reports/
position: 2
---

{% include section-header.html label="Recent Reports" accent="#ff4444" %}

<div class="hl-grid">
{% include report-card.html title="ZeroTrace Multi-Family MaaS Operation — Open Directory Exposure at 74.0.42.25" date="Mar 2026" severity="high" tags="MaaS,C2,Open Dir" url="/reports/zerotrace-74-0-42-25-20260316/" %}
{% include report-card.html title="Open Directory Exposure: Sliver C2 Toolchain with ScareCrow Loader (45.94.31.220)" date="Mar 2026" severity="high" tags="C2,Loader" url="/reports/sliver-open-directory/" %}
{% include report-card.html title="Webserver Compromise Kit 91.236.230.250" date="Feb 2026" severity="high" tags="Webshell,RCE" url="/reports/webserver-compromise-kit-91-236-230-250/" %}
{% include report-card.html title="Remcos RAT OpenDirectory Campaign — Technical Analysis & Business Risk Assessment" date="Feb 2026" severity="med" tags="RAT,Open Dir" url="/reports/remcos-opendirectory/" %}
{% include report-card.html title="NsMiner: Multi-Stage Cryptojacking Operation" date="Feb 2026" severity="med" tags="Cryptominer" url="/reports/nsminer-cryptojacker/" %}
</div>

{% include section-header.html label="All Reports" accent="#444444" %}

<div class="hl-row-list">
{% include report-row.html title="Arsenal-237 New Files: Advanced Toolkit Analysis" date="Jan 2026" severity="high" tags="Toolkit,Ransomware" url="/reports/Arsenal-237-New-Files/" %}
{% include report-row.html title="Arsenal-237: Threat Actor R&D Repository Exposed" date="Jan 2026" severity="high" tags="Toolkit,RAT" url="/reports/109.230.231.37-Executive-Overview/" %}
{% include report-row.html title="Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm — Technical Deep-Dive" date="Dec 2025" severity="med" tags="RAT" url="/reports/dual-rat-analysis/" %}
{% include report-row.html title="PULSAR RAT (server.exe) — Technical Analysis & Business Risk Assessment" date="Dec 2025" severity="med" tags="RAT" url="/reports/PULSAR-RAT/" %}
{% include report-row.html title="Hybrid Loader/Stealer Ecosystem Masquerading as Sogou" date="Nov 2025" severity="med" tags="Loader,Stealer" url="/reports/Hybrid-Loader-Stealer-Sogou/" %}
{% include report-row.html title="Houselet.exe — The Go-Based Loader Masquerading as PlayStation Remote Play" date="Nov 2025" severity="med" tags="Loader" url="/reports/malware-analysis-houselet/" %}
{% include report-row.html title="AdvancedRouterScanner" date="Oct 2025" severity="med" tags="Scanner" url="/reports/AdvancedRouterScanner/" %}
{% include report-row.html title="From Webshells to The Cloud" date="Oct 2025" severity="high" tags="Webshell,RCE" url="/reports/webshells-to-the-cloud/" %}
{% include report-row.html title="Quasar + XWorm + PowerShell Report" date="Oct 2025" severity="med" tags="RAT,C2" url="/reports/quasar-xworm-powershell/" %}
</div>

*Reports are © Joseph. All rights reserved — free to read, but reuse requires written permission.*
```

- [ ] **Step 2: Verify the file was written and front matter is intact**

```bash
head -8 reports/index.md
```

Expected: front matter block with `title: Reports`, `permalink: /reports/`.

- [ ] **Step 3: Commit**

```bash
git add reports/index.md
git commit -m "feat: redesign reports index with card grid and row list"
```

---

### Task 9: Rewrite `index.md` (Homepage)

The homepage gets: a hero banner with the site logo, a 2-card preview of the latest reports, a mission bullet list, and a 4-tile nav grid. Before starting, the user should add their logo image to `assets/images/logo.png` (or whichever filename they use — update the `src` in the hero section accordingly).

**Files:**
- Modify: `index.md`

- [ ] **Step 1: Add the logo image to the repo**

Copy your logo image file into `assets/images/`. Name it something clear, e.g. `logo.png`. Then verify it is there:

```bash
ls assets/images/
```

Note the exact filename — you will use it in Step 2.

- [ ] **Step 2: Replace the file contents entirely**

Replace `logo.png` in the hero block with the actual logo filename from step 1.

```markdown
---
layout: page
permalink: /
position: 1
---

<div class="hl-hero">
  <img src="{{ '/assets/images/logo.png' | relative_url }}" alt="The Hunter's Ledger logo" class="hl-hero__logo">
  <div>
    <div class="hl-hero__label">The Hunter's Ledger</div>
    <div class="hl-hero__title">Original Threat Intelligence Research</div>
    <div class="hl-hero__desc">Hands-on malware analysis turned into structured, evidence-based intelligence — technically deep enough to trust, clear enough to act on. Published by a solo analyst for the defender community.</div>
  </div>
</div>

{% include section-header.html label="Latest Reports" accent="#ff4444" %}

<div class="hl-grid">
{% include report-card.html title="ZeroTrace Multi-Family MaaS Operation — Open Directory Exposure at 74.0.42.25" date="Mar 2026" severity="high" tags="MaaS,C2,Open Dir" url="/reports/zerotrace-74-0-42-25-20260316/" %}
{% include report-card.html title="Open Directory Exposure: Sliver C2 Toolchain with ScareCrow Loader (45.94.31.220)" date="Mar 2026" severity="high" tags="C2,Loader" url="/reports/sliver-open-directory/" %}
</div>

<a href="{{ '/reports/' | relative_url }}" class="hl-view-all">View all reports →</a>

{% include section-header.html label="Mission" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    <ul>
      <li>Share reproducible research and technical reports from original investigations and hunting</li>
      <li>Provide IOCs formatted for direct ingestion into threat hunting and detection engineering workflows</li>
      <li>Map findings to MITRE ATT&CK techniques to give defenders a common language</li>
      <li>Publish detection logic — Sigma, YARA, Suricata — written to public repository submission standards</li>
      <li>Publish findings while they're still relevant, not months after threats are already active</li>
    </ul>
  </div>
</div>

<div class="hl-note">
  <div class="hl-note__label">Note</div>
  <div class="hl-note__body">This is not a collection of open source intel reports, IOCs, or TTPs. Findings are from original research, though they may overlap with known threats.</div>
</div>

{% include section-header.html label="Navigate" accent="#58a6ff" %}

<div class="hl-nav-grid">
  <a href="{{ '/reports/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Reports →</div>
    <div class="hl-nav-tile__desc">Malware analysis & reverse engineering notes</div>
  </a>
  <a href="{{ '/hunting-detections/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Hunting Detections →</div>
    <div class="hl-nav-tile__desc">Sigma, YARA, and Suricata rules</div>
  </a>
  <a href="{{ '/ioc-feeds/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">IOC Feeds →</div>
    <div class="hl-nav-tile__desc">Indicators ready for your SIEM or EDR</div>
  </a>
  <a href="{{ '/behind-the-reports/' | relative_url }}" class="hl-nav-tile">
    <div class="hl-nav-tile__title">Behind the Reports →</div>
    <div class="hl-nav-tile__desc">How the intelligence is produced</div>
  </a>
</div>

{% include section-header.html label="Contributing" accent="#4ade80" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    Contributions are welcome. Fork the repo and submit a PR with new reports, detections, or IOCs. Follow the <a href="{{ '/report-templates/' | relative_url }}">report format</a> for consistency. Or reach out directly — findings can be posted on your behalf as a co-author.
  </div>
</div>

{% include section-header.html label="Resources" accent="#555555" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__body">
    <a href="https://attack.mitre.org/">MITRE ATT&CK</a> &nbsp;·&nbsp;
    <a href="https://github.com/SigmaHQ/sigma">Sigma Rules</a> &nbsp;·&nbsp;
    <a href="https://virustotal.github.io/yara/">YARA</a>
  </div>
</div>
```

- [ ] **Step 3: Verify front matter**

```bash
head -5 index.md
```

Expected: `layout: page`, `permalink: /`, `position: 1`

- [ ] **Step 4: Commit**

```bash
git add index.md assets/images/
git commit -m "feat: redesign homepage with hero, latest reports preview, and nav grid"
```

---

## Chunk 4: Remaining pages

### Task 10: Rewrite `hunting-detections/index.md`

Tags on detection rows show rule types (Sigma, YARA, Suricata). Group tags per detection based on what rule files exist.

**Files:**
- Modify: `hunting-detections/index.md`

- [ ] **Step 1: Replace the file contents entirely**

```markdown
---
title: Hunting Detections
layout: page
permalink: /hunting-detections/
position: 3
---

<div class="hl-page-header" style="border-left-color: #4ade80;">
  <div class="hl-page-header__label" style="color: #4ade80;">Hunting Detections</div>
  <div class="hl-page-header__title">Sigma, YARA &amp; Suricata Rules</div>
  <div class="hl-page-header__desc">Detection logic from original research, mapped to MITRE ATT&amp;CK. Free to use in your environment under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% include section-header.html label="All Detections" accent="#4ade80" %}

<div class="hl-row-list">
{% include report-row.html title="Detection Rules — ZeroTrace Multi-Family MaaS Operation" date="Mar 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/opendirectory-74-0-42-25-20260316-detections" %}
{% include report-row.html title="Detection Rules — Sliver C2 / ScareCrow Loader Open Directory Kit" date="Mar 2026" severity="high" tags="Sigma,Suricata" url="/hunting-detections/sliver-open-directory-detections" %}
{% include report-row.html title="Detection Rules — Webserver Compromise Kit 91.236.230.250" date="Feb 2026" severity="high" tags="Sigma,YARA,Suricata" url="/hunting-detections/webserver-compromise-kit-91-236-230-250-detections" %}
{% include report-row.html title="Detection Rules — Remcos RAT OpenDirectory Campaign" date="Feb 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/remcos-opendirectory-campaign" %}
{% include report-row.html title="Detection Rules — NsMiner Cryptojacker" date="Feb 2026" severity="med" tags="Sigma" url="/hunting-detections/nsminer-cryptojacker" %}
{% include report-row.html title="Arsenal-237 New Files: full_test_enc.exe (Advanced Rust Ransomware)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-full_test_enc-exe" %}
{% include report-row.html title="Arsenal-237 New Files: new_enc.exe (Human-Operated Rust Ransomware)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-new_enc-exe" %}
{% include report-row.html title="Arsenal-237 New Files: dec_fixed.exe (Ransomware Decryptor)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-dec_fixed-exe" %}
{% include report-row.html title="Arsenal-237 New Files: enc_c2.exe (Rust Ransomware with Tor C2)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-enc_c2-exe" %}
{% include report-row.html title="Arsenal-237 New Files: chromelevator.exe (Browser Credential Theft)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-chromelevator-exe" %}
{% include report-row.html title="Arsenal-237 New Files: nethost.dll (DLL Hijacking Persistence)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-nethost-dll" %}
{% include report-row.html title="Arsenal-237 New Files: rootkit.dll (Kernel-Mode Rootkit)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-rootkit-dll" %}
{% include report-row.html title="Arsenal-237 New Files: BdApiUtil64.sys (Vulnerable Baidu Driver)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-BdApiUtil64-sys" %}
{% include report-row.html title="Arsenal-237 New Files: lpe.exe (Privilege Escalation)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-lpe-exe" %}
{% include report-row.html title="Arsenal-237 New Files: killer_crowdstrike.dll (CrowdStrike-Specific Termination)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-killer-crowdstrike-dll" %}
{% include report-row.html title="Arsenal-237 New Files: killer.dll (BYOVD Process Termination)" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/arsenal-237-killer-dll" %}
{% include report-row.html title="Arsenal-237: enc/dec Ransomware Family" date="Jan 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/enc-dec-ransomware-family" %}
{% include report-row.html title="Arsenal-237: uac_test.exe" date="Jan 2026" severity="med" tags="Sigma" url="/hunting-detections/uac-test-exe" %}
{% include report-row.html title="Arsenal-237: FleetAgentFUD.exe" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/fleetagentfud-exe" %}
{% include report-row.html title="Arsenal-237: FleetAgentAdvanced.exe" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/fleetagentadvanced-exe" %}
{% include report-row.html title="Arsenal-237: agent_xworm_v2.exe (XWorm RAT v2.4.0)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-xworm-v2-exe" %}
{% include report-row.html title="Arsenal-237: agent_xworm.exe (XWorm RAT v6)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-xworm-exe" %}
{% include report-row.html title="Arsenal-237: agent.exe (PoetRAT)" date="Jan 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/agent-exe" %}
{% include report-row.html title="Detection Rules — Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm" date="Dec 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/dual-rat-analysis" %}
{% include report-row.html title="Detection Rules — PULSAR RAT (server.exe)" date="Dec 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/PULSAR-RAT" %}
{% include report-row.html title="Hybrid Loader/Stealer Ecosystem Masquerading as Sogou" date="Nov 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/Hybrid-Loader-Stealer-Sogou" %}
{% include report-row.html title="Houselet.exe — Go-Based Loader Masquerading as PlayStation Remote Play" date="Nov 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/malware-analysis-houselet" %}
{% include report-row.html title="AdvancedRouterScanner" date="Oct 2025" severity="med" tags="Sigma" url="/hunting-detections/AdvancedRouterScanner" %}
{% include report-row.html title="From Webshells to The Cloud" date="Oct 2025" severity="high" tags="Sigma,YARA" url="/hunting-detections/webshells-to-the-cloud" %}
{% include report-row.html title="QuasarRAT + XWorm + PowerShell Loader" date="Oct 2025" severity="med" tags="Sigma,YARA" url="/hunting-detections/quasar-xworm-detections" %}
</div>
```

- [ ] **Step 2: Verify**

```bash
head -8 hunting-detections/index.md
```

Expected: front matter with `title: Hunting Detections`, `permalink: /hunting-detections/`.

- [ ] **Step 3: Commit**

```bash
git add hunting-detections/index.md
git commit -m "feat: redesign hunting-detections index with row list"
```

---

### Task 11: Rewrite `ioc-feeds/index.md`

Tags on IOC feed rows show indicator types (IP, Hash, Domain). Review each linked JSON file to confirm which types each feed contains and update tags accordingly.

**Files:**
- Modify: `ioc-feeds/index.md`

- [ ] **Step 1: Replace the file contents entirely**

```markdown
---
title: IOC Feeds
layout: page
permalink: /ioc-feeds/
position: 4
---

<div class="hl-page-header" style="border-left-color: #f87171;">
  <div class="hl-page-header__label" style="color: #f87171;">IOC Feeds</div>
  <div class="hl-page-header__title">Indicators of Compromise</div>
  <div class="hl-page-header__desc">Structured feeds ready for ingestion into your SIEM, EDR, or CTI platform. Licensed under <strong>CC BY-NC 4.0</strong>.</div>
</div>

{% include section-header.html label="All Feeds" accent="#f87171" %}

<div class="hl-row-list">
{% include report-row.html title="ZeroTrace Multi-Family MaaS Operation — IOC Feed" date="Mar 2026" severity="high" tags="IP,Hash,Domain" url="/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" %}
{% include report-row.html title="Sliver C2 / ScareCrow Loader Open Directory — IOC Feed" date="Mar 2026" severity="high" tags="IP,Hash" url="/ioc-feeds/sliver-open-directory-iocs.json" %}
{% include report-row.html title="Webserver Compromise Kit 91.236.230.250 — IOC Feed" date="Feb 2026" severity="high" tags="IP,Hash,Domain" url="/ioc-feeds/webserver-compromise-kit-91-236-230-250-iocs.json" %}
{% include report-row.html title="Remcos RAT OpenDirectory Campaign — IOC Feed" date="Feb 2026" severity="med" tags="IP,Hash" url="/ioc-feeds/remcos-opendirectory-campaign.json" %}
{% include report-row.html title="NsMiner Cryptojacker — IOC Feed" date="Feb 2026" severity="med" tags="IP,Hash" url="/ioc-feeds/nsminer-cryptojacker.json" %}
{% include report-row.html title="Arsenal-237 New Files: full_test_enc.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-full_test_enc-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: new_enc.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-new_enc-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: dec_fixed.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-dec_fixed-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: enc_c2.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-enc_c2-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: chromelevator.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-chromelevator-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: nethost.dll — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-nethost-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: rootkit.dll — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-rootkit-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: BdApiUtil64.sys — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-BdApiUtil64-sys.json" %}
{% include report-row.html title="Arsenal-237 New Files: lpe.exe — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-lpe-exe.json" %}
{% include report-row.html title="Arsenal-237 New Files: killer_crowdstrike.dll — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" %}
{% include report-row.html title="Arsenal-237 New Files: killer.dll — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/arsenal-237-killer-dll.json" %}
{% include report-row.html title="Arsenal-237: enc/dec Ransomware Family — IOC Feed" date="Jan 2026" severity="high" tags="Hash" url="/ioc-feeds/enc-dec-ransomware-family.json" %}
{% include report-row.html title="Arsenal-237: uac_test.exe — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/uac-test-exe.json" %}
{% include report-row.html title="Arsenal-237: FleetAgentFUD.exe — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/fleetagentfud-exe.json" %}
{% include report-row.html title="Arsenal-237: FleetAgentAdvanced.exe — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/fleetagentadvanced-exe.json" %}
{% include report-row.html title="Arsenal-237: agent_xworm_v2.exe — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/agent-xworm-v2-exe.json" %}
{% include report-row.html title="Arsenal-237: agent_xworm.exe — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/agent-xworm-exe.json" %}
{% include report-row.html title="Arsenal-237: agent.exe (PoetRAT) — IOC Feed" date="Jan 2026" severity="med" tags="Hash" url="/ioc-feeds/agent-exe.json" %}
{% include report-row.html title="Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm — IOC Feed" date="Dec 2025" severity="med" tags="Hash" url="/ioc-feeds/dual-rat-analysis.json" %}
{% include report-row.html title="PULSAR RAT (server.exe) — IOC Feed" date="Dec 2025" severity="med" tags="Hash" url="/ioc-feeds/PULSAR-RAT.json" %}
{% include report-row.html title="Hybrid Loader/Stealer Ecosystem Masquerading as Sogou — IOC Feed" date="Nov 2025" severity="med" tags="Hash,IP" url="/ioc-feeds/Hybrid-Loader-Stealer-Sogou.json" %}
{% include report-row.html title="Houselet.exe — IOC Feed" date="Nov 2025" severity="med" tags="Hash" url="/ioc-feeds/malware-analysis-houselet.json" %}
{% include report-row.html title="AdvancedRouterScanner — IOC Feed" date="Oct 2025" severity="med" tags="IP,Hash" url="/ioc-feeds/AdvancedRouterScanner.json" %}
{% include report-row.html title="From Webshells to The Cloud — IOC Feed" date="Oct 2025" severity="high" tags="IP,Hash" url="/ioc-feeds/webshells-to-the-cloud.json" %}
{% include report-row.html title="QuasarRAT + XWorm + PowerShell Loader — IOC Feed" date="Oct 2025" severity="med" tags="Hash,IP" url="/ioc-feeds/quasar-xworm-powershell.json" %}
</div>
```

- [ ] **Step 2: Verify**

```bash
head -8 ioc-feeds/index.md
```

- [ ] **Step 3: Commit**

```bash
git add ioc-feeds/index.md
git commit -m "feat: redesign ioc-feeds index with row list"
```

---

### Task 12: Rewrite `about-me/index.md`

**Files:**
- Modify: `about-me/index.md`

- [ ] **Step 1: Replace the file contents entirely**

```markdown
---
title: About Me
date: '2025-11-17'
layout: page
permalink: /about-me/
hide: true
---

<div class="hl-page-header" style="border-left-color: #58a6ff;">
  <div class="hl-page-header__label" style="color: #58a6ff;">About Me</div>
  <div class="hl-page-header__title">Solo Analyst · Threat Intelligence Researcher</div>
  <div class="hl-page-header__desc">Background, work, and ways to connect.</div>
</div>

{% include section-header.html label="Background" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#58a6ff;"></div>
    Story
  </div>
  <div class="hl-prose-section__body">
    <a href="https://hunt.io/blog/interview-joseph-harrison-threat-detection">From Munitions to Malware: Interview with Joseph Harrison About His Path to Threat Intelligence</a> — Hunt.io
  </div>
</div>

{% include section-header.html label="Work" accent="#4ade80" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#4ade80;"></div>
    Conference Talk
  </div>
  <div class="hl-prose-section__body">
    <a href="https://conf.splunk.com/files/2025/recordings/SEC1929.mp4">Rebooting Splunk UEBA: Leveraging the New UEBA's AI/ML Models</a> — Splunk .conf25
  </div>
</div>

{% include section-header.html label="Connect" accent="#58a6ff" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#58a6ff;"></div>
    LinkedIn
  </div>
  <div class="hl-prose-section__body">
    <a href="https://www.linkedin.com/in/josephrharrison">linkedin.com/in/josephrharrison</a>
  </div>
</div>

{% include section-header.html label="How This Site Is Built" accent="#f97316" %}

<div class="hl-prose-section">
  <div class="hl-prose-section__label">
    <div class="hl-prose-section__bar" style="background:#f97316;"></div>
    Workflow
  </div>
  <div class="hl-prose-section__body">
    Curious about the AI-assisted workflow behind every report? I built a multi-agent system from the ground up — agents, skill frameworks, automated hooks, and quality gates — to produce threat intelligence that is timely, evidence-based, and worth acting on.<br><br>
    <a href="{{ '/behind-the-reports/' | relative_url }}">Behind the Reports: How a Solo Analyst Uses AI Agents to Produce Timely, Trustworthy Threat Intelligence →</a>
  </div>
</div>
```

- [ ] **Step 2: Verify**

```bash
head -8 about-me/index.md
```

- [ ] **Step 3: Commit**

```bash
git add about-me/index.md
git commit -m "feat: redesign about-me page with prose section cards"
```

---

### Task 13: Rewrite `behind-the-reports/index.md` header area

This page has long prose content that should not be replaced. Only the top of the file gets the styled page header. The existing prose sections get a light visual treatment via `hl-prose-section` wrappers on the main section headings. The body text of each section stays unchanged.

**Files:**
- Modify: `behind-the-reports/index.md`

- [ ] **Step 1: Read the current file to identify section headings**

```bash
grep "^## " behind-the-reports/index.md
```

Note all `##` headings — these become the `hl-prose-section__label` entries.

- [ ] **Step 2: Add a styled page header at the top (after front matter)**

Add the following block immediately after the `---` closing the front matter, before the first `##` heading:

```html
<div class="hl-page-header" style="border-left-color: #f97316;">
  <div class="hl-page-header__label" style="color: #f97316;">Behind the Reports</div>
  <div class="hl-page-header__title">How a Solo Analyst Uses AI Agents to Produce Timely, Trustworthy Threat Intelligence</div>
  <div class="hl-page-header__desc">The workflow, the design decisions, and why it was built.</div>
</div>
```

Leave all existing `##` section headings and prose content completely unchanged below this block.

- [ ] **Step 3: Verify the header was inserted**

```bash
head -20 behind-the-reports/index.md
```

Expected: front matter, then the `hl-page-header` div, then the existing content.

- [ ] **Step 4: Commit**

```bash
git add behind-the-reports/index.md
git commit -m "feat: add styled page header to behind-the-reports page"
```

---

### Task 14: Final check — push and verify GitHub Pages build

- [ ] **Step 1: Verify all expected files exist**

```bash
ls _includes/tag-badge.html _includes/report-card.html _includes/report-row.html _includes/section-header.html _includes/default/head.liquid assets/css/custom.css
```

Expected: all six files listed without errors.

- [ ] **Step 2: Check for any obvious Liquid syntax errors**

```bash
grep -rn "{%" _includes/report-card.html _includes/report-row.html | grep -v "endif\|endfor\|else\|assign\|if\|for\|include" | head -20
```

Expected: no unmatched tags or obvious errors flagged.

- [ ] **Step 3: Push to GitHub**

```bash
git push origin main
```

- [ ] **Step 4: Monitor the GitHub Actions build**

Go to the repository on GitHub → Actions tab. Wait for the Pages build to complete (typically 1–2 minutes). If the build fails, read the error log and fix the reported issue before continuing.

- [ ] **Step 5: Spot-check the live site**

Visit the following pages and verify they render correctly:
- `/` — homepage: hero with logo, 2 report cards, nav tiles
- `/reports/` — featured grid (5 cards) + row list (9 rows)
- `/hunting-detections/` — page header + row list
- `/ioc-feeds/` — page header + row list
- `/about-me/` — page header + prose sections
- Click one featured card and one row to confirm links work
