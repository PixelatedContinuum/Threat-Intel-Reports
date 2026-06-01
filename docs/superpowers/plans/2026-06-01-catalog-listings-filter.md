# Catalog-Backed Listings + In-Page Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. This is a static Jekyll site — no unit-test suite, so "verify" steps are grep / count-parity / visual-companion checks. No local Jekyll build is available (no Ruby).

**Goal:** Drive all three listing pages + the home "Latest" from a single `_data/catalog.yml`, and add an in-page filter bar (search + tag chips) matching the approved demo — ending the 4-file manual upkeep and the drift.

**Architecture:** One data file is the source of truth. Two new includes (`catalog-card.html`, `listing-filter.html`) + one small JS file render and filter. The four listing surfaces become Liquid loops. No file moves, no URL changes.

**Tech Stack:** Jekyll/Liquid, hand-written CSS, vanilla JS. Acceptance bar: visual + interaction must match the approved mockup (`.superpowers/brainstorm/8232-*/content/reports-filter.html`).

**Spec:** `docs/superpowers/specs/2026-06-01-catalog-listings-filter-design.md`

**Constraints:** Windows + Git Bash, `python` (not `python3`). Branch `feature/catalog-listings` (carries the eyebrow commit). Do NOT push to `main` without explicit approval.

---

## File Structure

| File | Responsibility |
|---|---|
| `_data/catalog.yml` | NEW — single source of truth (one entry per item) |
| `_includes/catalog-card.html` | NEW — render one item as a filterable `.hl-card` with `data-*` attrs |
| `_includes/listing-filter.html` | NEW — search box + auto chips + count + empty state + script tag |
| `assets/js/listing-filter.js` | NEW — client-side filter (search + multi-tag OR) |
| `reports/index.md` | rewrite: blue page-header + filter + catalog loop |
| `hunting-detections/index.md` | rewrite: keep green page-header + filter + catalog loop |
| `ioc-feeds/index.md` | rewrite: keep red page-header + filter + catalog loop |
| `index.md` | "Latest" loops catalog (newest 3 reports) |
| `assets/css/custom.css` | filter-bar + chip styles + severity-meta-by-data-attr; remove orphaned `.hl-row*` if unused |
| `_includes/report-card.html`, `report-row.html` | retire (replaced by catalog-card) |

---

## Task 1: Build `_data/catalog.yml`

**Files:** Create `_data/catalog.yml`.

Build from the three current index pages (`reports/index.md`, `hunting-detections/index.md`, `ioc-feeds/index.md`). **One entry per item.** Merge a campaign's report/detection/IOC rows into a single entry carrying `report_url` + `detection_url` + `ioc_url`. Items that exist only as detection/IOC (the granular Arsenal-237 files) become entries with no `report_url`.

**Rules:**
- `date`: ISO `YYYY-MM-DD`. Derive the day from the slug where present (e.g., `...-20260517` → `2026-05-17`); for slugs without a day, use the first of the displayed month (e.g., "Jan 2026" → `2026-01-15` is acceptable only if no slug date — prefer slug dates).
- `severity`: copy from the existing include (`critical|high|med|low`).
- `tags`: shared list per entry. Where a campaign's detection or IOC row currently carries materially different tags than its report, add `detection_tags:` / `ioc_tags:` overrides; otherwise reconcile to one `tags` list.
- Titles: store the **base** title (the report's title form, or the cleanest campaign title). Listings normalize per type, so do NOT pre-prefix "Detection Rules —" or suffix "— IOC Feed". Use `detection_title:` / `ioc_title:` only when normalization would be wrong.
- **Fix drift:** the OpenStrike "Expanded Toolkit / New Files 2026-04-08" entry and the "Beacon Toolkit / 172.105.0.126" entry are TWO distinct items — keep their IPs/labels correct (the current `/ioc-feeds/` mislabels the New-Files feed as `172.105.0.126`).

- [ ] **Step 1: Write the file**

Schema (header + first entries shown; transcribe ALL items the same way):
```yaml
# Single source of truth for /reports/, /hunting-detections/, /ioc-feeds/ and the home "Latest".
# One entry per item. An entry appears in a listing iff it has that listing's *_url.
entries:
  - title: "CVE-2026-41940 cPanel Harvester Toolkit (216.126.227.49)"
    date: 2026-05-17
    severity: high
    tags: [CVE Exploit, Cred Theft, Phishing, Open Dir]
    report_url: /reports/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517/
    detection_url: /hunting-detections/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517-detections
    ioc_url: /ioc-feeds/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517-iocs.json
  - title: "BellaMain Turkish PhaaS Panel (79.137.192.3)"
    date: 2026-05-16
    severity: high
    tags: [PhaaS, Phishing, Cred Theft, Open Dir]
    report_url: /reports/bellamain-turkish-phaas-79-137-192-3-20260516/
    detection_url: /hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections
    ioc_url: /ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json
  # ... continue for every report (26), every detection (42), every IOC feed (42),
  # merging shared campaigns into single entries and keeping Arsenal-237 granular
  # files as detection+ioc-only entries.
```

- [ ] **Step 2: Verify count parity (nothing dropped)**

Run:
```bash
cd /c/Users/josep/Documents/GitHub/Threat-Intel-Reports
echo "catalog report_url:    $(grep -c 'report_url:'    _data/catalog.yml)   (expect 26)"
echo "catalog detection_url: $(grep -c 'detection_url:' _data/catalog.yml)   (expect 42)"
echo "catalog ioc_url:       $(grep -c 'ioc_url:'       _data/catalog.yml)   (expect 42)"
echo "--- current page counts for comparison ---"
echo "reports listing items:    $(grep -c 'report-card.html\|report-row.html' reports/index.md)"
echo "detections listing items: $(grep -c 'report-card.html\|report-row.html' hunting-detections/index.md)"
echo "iocs listing items:       $(grep -c 'report-card.html\|report-row.html' ioc-feeds/index.md)"
```
Expected: catalog `report_url` count == reports listing items (26); detection/ioc counts match their pages (42 each). If a number is off, a row was missed or duplicated — reconcile before continuing.

- [ ] **Step 3: Commit**
```bash
git add _data/catalog.yml
git commit -m "Add _data/catalog.yml — single source of truth for all listings"
```

---

## Task 2: `catalog-card.html` include

**Files:** Create `_includes/catalog-card.html`.

- [ ] **Step 1: Write the include**
```liquid
{%- comment -%} One filterable listing card. Params: url, title, date (ISO), severity, tags (array). {%- endcomment -%}
{%- assign sevlabel = include.severity | upcase -%}
{%- if include.severity == "med" -%}{%- assign sevlabel = "MED" -%}{%- endif -%}
<a href="{{ include.url | relative_url }}" class="hl-card hl-catalog-card"
   data-title="{{ include.title | downcase | escape }}"
   data-tags="{{ include.tags | join: '|' | downcase | escape }}"
   data-sev="{{ include.severity }}">
  <div class="hl-card__inner">
    <div class="hl-card__bar hl-sev--{{ include.severity }}"></div>
    <div>
      <div class="hl-card__meta hl-catalog-card__meta">{{ sevlabel }} &middot; {{ include.date | date: "%b %Y" }}</div>
      <div class="hl-card__title">{{ include.title }}</div>
    </div>
  </div>
  {%- if include.tags -%}
  <div class="hl-tags hl-card__tags">
    {%- for t in include.tags -%}{%- include tag-badge.html tag=t -%}{%- endfor -%}
  </div>
  {%- endif -%}
</a>
```

- [ ] **Step 2: Verify** — `grep -n "hl-catalog-card\|data-tags\|data-title" _includes/catalog-card.html` shows the attrs. (No render check possible locally; validated in Task 9.)

- [ ] **Step 3: Commit**
```bash
git add _includes/catalog-card.html
git commit -m "Add catalog-card include (filterable card with data-* attrs)"
```

---

## Task 3: Filter bar include + JS

**Files:** Create `_includes/listing-filter.html`, `assets/js/listing-filter.js`.

- [ ] **Step 1: Write `assets/js/listing-filter.js`** (mirrors the approved demo)
```javascript
(function () {
  var bar = document.querySelector('[data-listing-filter]');
  var grid = document.querySelector('[data-filter-grid]');
  if (!bar || !grid) return;
  var cards = [].slice.call(grid.querySelectorAll('.hl-catalog-card'));
  var search = bar.querySelector('.hl-filter__search');
  var chips = [].slice.call(bar.querySelectorAll('.hl-chip-btn'));
  var count = bar.querySelector('[data-filter-count]');
  var empty = bar.querySelector('[data-filter-empty]');
  var allChip = bar.querySelector('.hl-chip-btn[data-tag=""]');
  var active = {};
  function activeTags() { return Object.keys(active); }
  function apply() {
    var term = (search && search.value || '').trim().toLowerCase();
    var tags = activeTags();
    var shown = 0;
    cards.forEach(function (c) {
      var ctags = (c.getAttribute('data-tags') || '').split('|');
      var mt = tags.length === 0 || tags.some(function (t) { return ctags.indexOf(t) > -1; });
      var mq = !term || (c.getAttribute('data-title') || '').indexOf(term) > -1;
      var vis = mt && mq;
      c.style.display = vis ? '' : 'none';
      if (vis) shown++;
    });
    if (count) count.textContent = 'Showing ' + shown + ' of ' + cards.length;
    if (empty) empty.hidden = shown !== 0;
  }
  chips.forEach(function (ch) {
    ch.addEventListener('click', function () {
      var t = ch.getAttribute('data-tag');
      if (t === '') { active = {}; chips.forEach(function (x) { x.classList.remove('is-on'); }); allChip.classList.add('is-on'); }
      else {
        allChip.classList.remove('is-on');
        if (active[t]) { delete active[t]; ch.classList.remove('is-on'); } else { active[t] = 1; ch.classList.add('is-on'); }
        if (activeTags().length === 0) allChip.classList.add('is-on');
      }
      apply();
    });
  });
  if (search) search.addEventListener('input', apply);
  var reset = bar.querySelector('[data-filter-reset]');
  if (reset) reset.addEventListener('click', function () {
    active = {}; if (search) search.value = '';
    chips.forEach(function (x) { x.classList.remove('is-on'); });
    allChip.classList.add('is-on'); apply();
  });
  apply();
})();
```

- [ ] **Step 2: Write `_includes/listing-filter.html`** (chips auto-built from tags with count ≥ 3; no `push` filter — uses string accumulation for Jekyll-Liquid compatibility)
```liquid
{%- comment -%} Filter bar. Params: entries (filtered+sorted), tag_field (optional), placeholder. {%- endcomment -%}
{%- assign tagbag = "" -%}
{%- for e in include.entries -%}
  {%- assign etags = e.tags -%}
  {%- if include.tag_field -%}{%- assign ov = e[include.tag_field] -%}{%- if ov -%}{%- assign etags = ov -%}{%- endif -%}{%- endif -%}
  {%- assign joined = etags | join: "|" -%}
  {%- assign tagbag = tagbag | append: "|" | append: joined -%}
{%- endfor -%}
{%- assign tagarr = tagbag | remove_first: "|" | split: "|" -%}
{%- assign uniq = tagarr | uniq | sort -%}
<div class="hl-filter" data-listing-filter>
  <input class="hl-filter__search" type="text" placeholder="{{ include.placeholder | default: 'Search by name…' }}" aria-label="Filter list" autocomplete="off">
  <div class="hl-filter__chips">
    <button type="button" class="hl-chip-btn is-on" data-tag="">All</button>
    {%- for u in uniq -%}
      {%- assign cnt = 0 -%}
      {%- for t in tagarr -%}{%- if t == u -%}{%- assign cnt = cnt | plus: 1 -%}{%- endif -%}{%- endfor -%}
      {%- if u != "" and cnt >= 3 -%}<button type="button" class="hl-chip-btn" data-tag="{{ u | downcase }}">{{ u }}</button>{%- endif -%}
    {%- endfor -%}
  </div>
  <div class="hl-filter__count" data-filter-count></div>
  <div class="hl-filter__empty" data-filter-empty hidden>No items match that filter. <button type="button" class="hl-filter__reset" data-filter-reset>Clear filters</button></div>
</div>
<script defer src="{{ '/assets/js/listing-filter.js' | relative_url }}"></script>
```

- [ ] **Step 3: Commit**
```bash
git add _includes/listing-filter.html assets/js/listing-filter.js
git commit -m "Add in-page listing filter (search + auto tag chips) include + JS"
```

---

## Task 4: Filter + card CSS

**Files:** Modify `assets/css/custom.css` (append a new section near the listing/card styles).

- [ ] **Step 1: Append the styles**
```css
/* --- Listing filter bar ------------------------------------ */
.hl-filter { margin: 0 0 4px; }
.hl-filter__search {
  width: 100%; background: #0d1117; border: 1px solid var(--hl-border-card);
  border-radius: 8px; padding: 11px 14px; color: var(--hl-text-primary);
  font-family: inherit; font-size: 0.95rem; outline: none;
}
.hl-filter__search:focus { border-color: var(--hl-accent-blue); }
.hl-filter__search::placeholder { color: #6e7681; }
.hl-filter__chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.hl-chip-btn {
  font-family: inherit; font-size: 0.8rem; color: var(--hl-text-secondary);
  background: var(--hl-bg-card); border: 1px solid var(--hl-border-card);
  border-radius: 999px; padding: 5px 13px; cursor: pointer; transition: all 0.12s;
}
.hl-chip-btn:hover { border-color: #3d4756; color: var(--hl-text-primary); }
.hl-chip-btn.is-on { background: rgba(88,166,255,0.16); border-color: var(--hl-accent-blue); color: #cfe3ff; }
.hl-filter__count { font-size: 0.75rem; color: var(--hl-text-muted); margin: 13px 2px; letter-spacing: 0.02em; }
.hl-filter__empty { font-size: 0.9rem; color: var(--hl-text-muted); padding: 28px; text-align: center; border: 1px dashed var(--hl-border-card); border-radius: 8px; }
.hl-filter__reset { background: none; border: none; color: var(--hl-accent-blue); cursor: pointer; font: inherit; padding: 0; }
/* severity-colored meta on catalog cards */
.hl-catalog-card[data-sev="critical"] .hl-catalog-card__meta { color: #ef4444; }
.hl-catalog-card[data-sev="high"]     .hl-catalog-card__meta { color: #fb923c; }
.hl-catalog-card[data-sev="med"]      .hl-catalog-card__meta { color: #facc15; }
.hl-catalog-card[data-sev="low"]      .hl-catalog-card__meta { color: #60a5fa; }
```

- [ ] **Step 2: Verify & commit**
```bash
grep -n "hl-filter__search\|hl-chip-btn\|hl-catalog-card\[data-sev" assets/css/custom.css
git add assets/css/custom.css
git commit -m "Style listing filter bar + chips + severity-colored card meta"
```

---

## Task 5: Rewrite `/reports/index.md`

**Files:** Replace `reports/index.md` body (keep front matter).

- [ ] **Step 1: Write the new file**
```liquid
---
title: Reports
layout: page
permalink: /reports/
position: 2
---

<div class="hl-page-header" style="border-left-color: #58a6ff;">
  <div class="hl-page-header__label" style="color: #58a6ff;">Reports</div>
  <div class="hl-page-header__title">Threat Intelligence Reports</div>
  <div class="hl-page-header__desc">Original malware analysis and reverse engineering — each report ships with detection rules and machine-readable indicators. Filter by tag or search by name.</div>
</div>

{% assign report_entries = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=report_entries placeholder="Search reports by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in report_entries %}{% include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags %}{% endfor %}
</div>

*Reports are © Joseph. All rights reserved — free to read, but reuse requires written permission.*
```

- [ ] **Step 2: Commit**
```bash
git add reports/index.md
git commit -m "Reports listing: page-header + filter + catalog-driven loop"
```

---

## Task 6: Rewrite `/hunting-detections/` and `/ioc-feeds/`

**Files:** Replace bodies of `hunting-detections/index.md` and `ioc-feeds/index.md` (keep front matter + existing page-headers).

- [ ] **Step 1: Write `hunting-detections/index.md`**
```liquid
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

{% assign det_entries = site.data.catalog.entries | where_exp: "e", "e.detection_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=det_entries tag_field="detection_tags" placeholder="Search detections by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in det_entries %}
  {% if e.detection_title %}{% assign dtitle = e.detection_title %}{% else %}{% assign dtitle = e.title | prepend: "Detection Rules — " %}{% endif %}
  {% assign dtags = e.detection_tags | default: e.tags %}
  {% include catalog-card.html url=e.detection_url title=dtitle date=e.date severity=e.severity tags=dtags %}
{% endfor %}
</div>
```

- [ ] **Step 2: Write `ioc-feeds/index.md`**
```liquid
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

{% assign ioc_entries = site.data.catalog.entries | where_exp: "e", "e.ioc_url" | sort: "date" | reverse %}

{% include listing-filter.html entries=ioc_entries tag_field="ioc_tags" placeholder="Search IOC feeds by name…" %}

<div class="hl-grid" data-filter-grid>
{% for e in ioc_entries %}
  {% if e.ioc_title %}{% assign ititle = e.ioc_title %}{% else %}{% assign ititle = e.title | append: " — IOC Feed" %}{% endif %}
  {% assign itags = e.ioc_tags | default: e.tags %}
  {% include catalog-card.html url=e.ioc_url title=ititle date=e.date severity=e.severity tags=itags %}
{% endfor %}
</div>
```

- [ ] **Step 3: Commit**
```bash
git add hunting-detections/index.md ioc-feeds/index.md
git commit -m "Detections + IOC listings: catalog-driven loops + filter (titles normalized)"
```

---

## Task 7: Home "Latest" from catalog

**Files:** Modify `index.md` — replace the two hand-listed report cards under "Latest Reports".

- [ ] **Step 1: Find the current block** — `grep -n "Latest Reports\|report-card.html\|hl-grid" index.md` to locate the `<div class="hl-grid"> … </div>` after the "Latest Reports" section header.

- [ ] **Step 2: Replace that grid** with:
```liquid
<div class="hl-grid">
{% assign latest = site.data.catalog.entries | where_exp: "e", "e.report_url" | sort: "date" | reverse %}
{% for e in latest limit: 3 %}{% include catalog-card.html url=e.report_url title=e.title date=e.date severity=e.severity tags=e.tags %}{% endfor %}
</div>
```
(Leave the `{% include section-header.html label="Latest Reports" accent="#ff4444" %}` and the "View all reports →" link unchanged.)

- [ ] **Step 3: Commit**
```bash
git add index.md
git commit -m "Home: Latest Reports pulls newest 3 from catalog"
```

---

## Task 8: Retire old includes + orphaned CSS

**Files:** Delete `_includes/report-card.html`, `_includes/report-row.html`; modify `assets/css/custom.css` if `.hl-row*` is now unused.

- [ ] **Step 1: Confirm no remaining references**
```bash
cd /c/Users/josep/Documents/GitHub/Threat-Intel-Reports
grep -rn "report-card.html\|report-row.html" _includes _layouts index.md reports ioc-feeds hunting-detections 2>/dev/null || echo "no include refs — safe to retire"
grep -rn "hl-row\b\|hl-row-list\|hl-row__" _includes _layouts *.md reports hunting-detections ioc-feeds 2>/dev/null || echo "no hl-row markup remains"
```
Expected: no include refs; no `hl-row` markup. (If `hl-row` still appears anywhere, do NOT remove its CSS.)

- [ ] **Step 2: Delete the includes**
```bash
git rm _includes/report-card.html _includes/report-row.html
```

- [ ] **Step 3: Remove orphaned `.hl-row*` CSS** — only if Step 1 showed no `hl-row` markup. Locate with `grep -n "hl-row" assets/css/custom.css` and delete the `.hl-row`, `.hl-row__bar`, `.hl-row__body`, `.hl-row__left`, `.hl-row__title`, `.hl-row__date`, `.hl-row-list` rule blocks (and any mobile overrides). If unsure any rule is shared, leave it.

- [ ] **Step 4: Commit**
```bash
git add -A
git commit -m "Retire report-card/report-row includes (replaced by catalog-card)"
```

---

## Task 9: Verification pass

- [ ] **Step 1: Reference integrity + parity**
```bash
cd /c/Users/josep/Documents/GitHub/Threat-Intel-Reports
echo "report_url=$(grep -c 'report_url:' _data/catalog.yml) detection_url=$(grep -c 'detection_url:' _data/catalog.yml) ioc_url=$(grep -c 'ioc_url:' _data/catalog.yml)"
grep -rn "report-card.html\|report-row.html" . --include=*.md --include=*.html 2>/dev/null | grep -v docs/ || echo "no stale include refs"
```
Expect report/detection/ioc counts = 26 / 42 / 42; no stale include refs.

- [ ] **Step 2: Visual-companion preview** — render a listing page using the **actual** generated catalog entries + the real `catalog-card`/`listing-filter` CSS + JS, and confirm it matches the approved demo (search narrows; chips multi-select OR; "All" clears; count + empty state work; page-header present). Restart the companion server if needed.

- [ ] **Step 3: Spot-check title normalization** — in the preview, a detection item reads "Detection Rules — {title}", an IOC item reads "{title} — IOC Feed", and the OpenStrike mislabel is fixed.

- [ ] **Step 4: Hand off** — `git log --oneline main..feature/catalog-listings`, summarize, and invoke **superpowers:finishing-a-development-branch**. Do NOT merge/push to `main` without explicit approval. (This deploy also carries the eyebrow commit `b756859`.)

---

## Self-Review (completed during planning)

- **Spec coverage:** catalog schema (T1), catalog-card (T2), filter include+JS (T3), CSS (T4), reports page + new page-header (T5), detections/iocs pages + title normalization + per-type tags (T6), home Latest→3 (T7), retire old includes + drift fix in T1 (T8), parity + demo-match verification (T9). All §5–§7 mapped.
- **Placeholder scan:** includes/JS/CSS/pages are complete code. T1's catalog body is a transcription task (source = the three index pages, fully available) gated by the parity check — not a logic placeholder.
- **Naming consistency:** `[data-listing-filter]`, `[data-filter-grid]`, `[data-filter-count]`, `[data-filter-empty]`, `[data-filter-reset]`, `.hl-chip-btn.is-on`, `.hl-catalog-card`, `data-title`/`data-tags`/`data-sev` used identically across the include, JS, and CSS. Liquid avoids the non-Jekyll `push` filter (uses string accumulation). `where_exp` + `sort` + `reverse` consistent across all four loops.
