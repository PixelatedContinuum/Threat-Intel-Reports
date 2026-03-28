# Site Redesign — Design Spec
**Date:** 2026-03-27
**Status:** Approved

---

## Overview

Redesign The Hunter's Ledger (Jekyll / Type-on-Strap dark theme) with a consistent visual identity across all pages. The design uses a dark card system with colored severity bars and tag badges. Each page type gets a layout appropriate to its content while sharing the same color system, typography, and components.

No changes to the GitHub-based publishing workflow. Everything is file-based — commit and push as usual.

---

## Design System

### Color Palette (CSS custom properties)

| Token | Value | Usage |
|---|---|---|
| `--bg-page` | `#111111` | Page background |
| `--bg-card` | `#1a1a1a` | Featured card background |
| `--bg-row` | `#161616` | Compact row background |
| `--border-subtle` | `#222222` | Row/card borders |
| `--border-card` | `#2a2a2a` | Featured card borders |
| `--text-primary` | `#eeeeee` | Headings, titles |
| `--text-secondary` | `#aaaaaa` | Section labels |
| `--text-muted` | `#888888` | Body text, descriptions |
| `--text-dim` | `#555555` | Dates in list rows |
| `--accent-blue` | `#58a6ff` | Links, navigation tiles |
| `--sev-high` | `#ff4444` | HIGH severity bar |
| `--sev-high-label` | `#ff6666` | HIGH severity label text |
| `--sev-med` | `#f97316` | MEDIUM severity bar |
| `--sev-med-label` | `#fb923c` | MEDIUM severity label text |
| `--accent-green` | `#4ade80` | Hunting Detections accent |
| `--accent-red` | `#f87171` | IOC Feeds accent |

### Tag Badge Colors

Tags use a semi-transparent background with a tinted border and matching text color:

| Tag type | Background | Border | Text |
|---|---|---|---|
| C2 / RAT / IP / Hash | `#1f6feb33` | `#1f6feb55` | `#58a6ff` |
| Webshell / Threat | `#b91c1c33` | `#b91c1c55` | `#f87171` |
| Open Dir / Domain / Sigma | `#16653433` | `#16653455` | `#4ade80` |
| Loader / Suricata | `#7c3aed33` | `#7c3aed55` | `#c084fc` |
| Note / Warning | `#3a3a1a` (bg) | `#3a3a1a` | `#facc15` |

### Severity Bar

A 2–3px wide left border on cards and rows, color-coded by severity:
- `HIGH` → `--sev-high` (`#ff4444`)
- `MEDIUM` → `--sev-med` (`#f97316`)
- Informational / no severity → `#333333`

---

## Components (Liquid Includes)

### `_includes/report-card.html`

Featured card for the 2-column grid. Parameters:

| Parameter | Description | Example |
|---|---|---|
| `title` | Report title | `"ZeroTrace MaaS Operation"` |
| `date` | Display date | `"Mar 2026"` |
| `severity` | `high`, `med`, or omit | `"high"` |
| `tags` | Comma-separated tag list | `"MaaS,C2,Open Dir"` |
| `url` | Link to report | `"/reports/zerotrace-..."` |

Usage:
```liquid
{% include report-card.html title="ZeroTrace MaaS Operation" date="Mar 2026" severity="high" tags="MaaS,C2" url="/reports/zerotrace-74-0-42-25-20260316/" %}
```

### `_includes/report-row.html`

Compact row for the list section below the featured grid, and for Hunting Detections / IOC Feeds pages. Parameters:

| Parameter | Description | Example |
|---|---|---|
| `title` | Item title | `"NsMiner Cryptojacking"` |
| `date` | Display date | `"Feb 2026"` |
| `severity` | `high`, `med`, or omit | `"med"` |
| `tags` | Comma-separated | `"Sigma,YARA"` |
| `url` | Link | `"/hunting-detections/nsminer/"` |

Usage:
```liquid
{% include report-row.html title="NsMiner Cryptojacking Detections" date="Feb 2026" severity="med" tags="Sigma,YARA" url="/hunting-detections/nsminer-cryptojacker/" %}
```

### `_includes/section-header.html`

Reusable section divider label. Parameters: `label` (text), `accent` (CSS color value, optional).

---

## Files Created / Modified

| File | Action | Notes |
|---|---|---|
| `assets/css/custom.css` | **Create** | All design system styles |
| `_includes/report-card.html` | **Create** | Featured card component |
| `_includes/report-row.html` | **Create** | Compact row component |
| `_includes/section-header.html` | **Create** | Section label component |
| `reports/index.md` | **Modify** | Replace text lists with includes |
| `index.md` | **Modify** | New homepage layout |
| `hunting-detections/index.md` | **Modify** | Replace text list with row includes |
| `ioc-feeds/index.md` | **Modify** | Replace text list with row includes |
| `about-me/index.md` | **Modify** | Styled prose layout |
| `behind-the-reports/index.md` | **Modify** | Styled prose layout |
| `.gitignore` | **Modify** | Add `.superpowers/` |

---

## Page Layouts

### Reports — `reports/index.md`

1. **Featured section** — "Recent Reports" heading + 2-column grid of `report-card` includes for the newest 4–6 reports
2. **List section** — "All Reports" heading + `report-row` includes for all remaining reports, newest first, no month grouping needed

When a new report is published: move the oldest featured card down to the list section and add the new report as a featured card at the top.

### Homepage — `index.md`

1. **Intro banner** — dark card with red left accent, site title, one-sentence description
2. **Latest Reports** — 2-column grid showing the 2 most recent featured cards + "→ View all reports" link
3. **Mission** — bullet list in current style, visually consistent
4. **Navigate** — 2×2 grid of nav tiles linking to Reports, Hunting Detections, IOC Feeds, Behind the Reports

Remove: Repository Structure section, Report Format section, Usage section, License section (these belong on their respective pages, not the homepage). Keep: Contributing section, Resources section (condensed).

### Hunting Detections — `hunting-detections/index.md`

1. **Page header card** — green left accent, title, license note
2. **All Detections** — `report-row` includes for every detection file. Tags show rule types (Sigma, YARA, Suricata).

### IOC Feeds — `ioc-feeds/index.md`

1. **Page header card** — red left accent, title, license note
2. **All Feeds** — `report-row` includes for every IOC feed. Tags show indicator types (IP, Hash, Domain, URL).

### About Me — `about-me/index.md`

1. **Page header card** — blue left accent, name/role
2. **Content sections** — each section (Background, Focus Areas, Contact) wrapped in a styled `--bg-row` card with a small colored left accent and uppercase section label

### Behind the Reports — `behind-the-reports/index.md`

Same prose layout as About Me. Section cards match the content structure of the existing page.

---

## Maintenance — Adding a New Report

When a new report is published:

1. Add the report files as usual
2. In `reports/index.md`: add a new `report-card` include at the top of the featured grid
3. If the grid already has 6 cards, move the oldest one down to the list section as a `report-row` include
4. In `index.md`: update the 2 homepage preview cards to show the latest 2 reports
5. Add corresponding `report-row` includes to `hunting-detections/index.md` and `ioc-feeds/index.md`

---

## Out of Scope

- Individual report page styling (those use `layout: post` from the theme — consistent as-is)
- Theme replacement or forking Type-on-Strap
- Pagination or filtering
- Search functionality
- Dark/light mode toggle
