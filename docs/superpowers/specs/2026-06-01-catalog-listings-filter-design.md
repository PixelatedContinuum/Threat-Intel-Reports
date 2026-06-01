# Catalog-Backed Listings + In-Page Filter — Design Spec

**Date:** 2026-06-01
**Repo:** Threat-Intel-Reports (Jekyll, remote theme Type-on-Strap), live at https://the-hunters-ledger.com
**Branch:** `feature/catalog-listings` (off `main`, which already carries the home-eyebrow-removal commit `b756859` — that fix ships with this branch)
**Status:** Approved design — ready for implementation plan
**Builds on:** the shipped brand refresh (same `hl-*` design system + self-hosted Space Grotesk)

---

## 1. Goal & context

Track A of the post-refresh polish. Two user-selected tracks merge here because they share one foundation:

- **Consistency:** `/reports/` lacks the `.hl-page-header` its siblings have; all listings are hand-maintained across four files, which causes drift.
- **Search + tag filtering:** add an in-page filter bar (search-as-you-type + clickable tag chips) to each listing.

The root cause of the drift *and* the blocker for tag filtering is the same — no single data source. So we introduce a **`_data/catalog.yml` source of truth**: the lightweight slice of a collections refactor, with **no file moves and no URL changes**.

## 2. Current state

- `/reports/`, `/hunting-detections/`, `/ioc-feeds/`, and the home "Latest Reports" each hand-list items via `{% include report-card/report-row %}` with title/date/severity/tags/url copy-pasted. Publishing a campaign means editing **four** files.
- `/hunting-detections/` and `/ioc-feeds/` open with `.hl-page-header`; **`/reports/` does not** (it starts at a `section-header`).
- Tags render as non-clickable badges (`tag-badge.html`).
- The theme ships `simple-jekyll-search` (unused) — this design does **not** use it; the in-page filter is custom vanilla JS.
- **Observed drift:** the `/ioc-feeds/` entry "OpenStrike Expanded Toolkit (172.105.0.126)" is mislabeled — that IP is the *Beacon* Toolkit; the detections page correctly labels the same feed "(New Files 2026-04-08)."

## 3. Decisions locked (validated with the user)

- Single `_data/catalog.yml` source of truth.
- One entry per item, carrying up to three type-URLs; titles normalized per type.
- In-page filter bar UX (search + multi-tag OR chips + live count + empty state), client-side vanilla JS — validated via interactive mockup.
- Chips auto-generated from tags appearing in **≥3 items** on that page; rarer tags reachable via the search box.
- A single filterable list per page, **newest first** — replaces the manual "Recent / All" split.
- No file moves, no URL changes.

## 4. Catalog schema

`_data/catalog.yml`:

```yaml
entries:
  - title: "CVE-2026-41940 cPanel Harvester Toolkit (216.126.227.49)"
    date: 2026-05-17                 # ISO YYYY-MM-DD, sortable; displayed as "May 2026"
    severity: high                   # critical | high | med | low
    tags: [CVE Exploit, Cred Theft, Phishing, Open Dir]
    report_url: /reports/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517/
    detection_url: /hunting-detections/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517-detections
    ioc_url: /ioc-feeds/opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517-iocs.json

  - title: "Arsenal-237 New Files: rootkit.dll (Kernel-Mode Rootkit)"
    date: 2026-01-15
    severity: critical
    tags: [Rootkit, Evasion]
    detection_url: /hunting-detections/arsenal-237-rootkit-dll
    ioc_url: /ioc-feeds/arsenal-237-rootkit-dll.json
    # no report_url -> appears only in the detections + IOC listings
```

**Rules:**
- An entry appears in a listing **iff** it has that listing's URL (`report_url` / `detection_url` / `ioc_url`).
- `date` is ISO `YYYY-MM-DD` for sorting; displayed via Jekyll `date` filter as `%b %Y`.
- `tags` is shared across the entry's listings (campaign-level). Optional `detection_tags` / `ioc_tags` override it for the rare case where a deliverable's tags differ meaningfully.
- Optional `detection_title` / `ioc_title` override the normalized title for edge cases.

## 5. Rendering

### 5.1 Listing pages
Each of the three index pages replaces its hand-written includes with a single loop over `site.data.catalog.entries`:

| Page | Filter | Link | Title | Tags |
|---|---|---|---|---|
| `/reports/` | has `report_url` | `report_url` | `title` | `tags` |
| `/hunting-detections/` | has `detection_url` | `detection_url` | `detection_title` \| default `"Detection Rules — " + title` | `detection_tags` \| default `tags` |
| `/ioc-feeds/` | has `ioc_url` | `ioc_url` | `ioc_title` \| default `title + " — IOC Feed"` | `ioc_tags` \| default `tags` |

- Sort by `date` descending.
- Each page renders: `.hl-page-header` (reports = `#58a6ff`, detections = `#4ade80`, iocs = `#f87171` — keep existing colors) → filter bar → the filterable card list.
- A new include **`catalog-card.html`** renders one card (severity bar, meta = `SEV · Mon YYYY`, normalized title, tag badges) and stamps `data-title` (lowercased), `data-tags` (lowercased, `|`-joined), and `data-sev` for the filter JS. Reuses existing `.hl-card` styling.

### 5.2 Filter bar
- New include **`listing-filter.html`**: a search `<input>`, a chip row, a live count, an empty-state element.
- **Chips** are generated at build time from the tags present in *this page's* entries: count occurrences, render a chip for each tag with **count ≥ 3** (sorted by count desc), plus a leading "All" chip.
- **Client JS** (`assets/js/listing-filter.js`, loaded only on listing pages):
  - text search = case-insensitive substring over `data-title`;
  - tag chips = multi-select OR over `data-tags`;
  - "All" clears; live count `"Showing X of Y"`; empty-state toggle.
  - ~40 lines, no external library. (Mirrors the validated mockup.)

### 5.3 Home "Latest"
`index.md` "Latest Reports" loops catalog entries with `report_url`, sorted by date desc, **first 3** (was 2, hand-listed), rendered with `catalog-card.html`.

## 6. Migration (one-time)

1. Build `_data/catalog.yml` from the current three index pages: one entry per campaign, merging its report/detection/IOC rows. Granular Arsenal-237 detection/IOC files become their own entries (no `report_url`).
2. Derive `date` (ISO) from each item's slug date where present, else the displayed month.
3. Reconcile report/detection/IOC tags into a shared `tags` list; add `*_tags` / `*_title` overrides only where a deliverable meaningfully differs.
4. Fix drift during migration (e.g., the OpenStrike IOC label).
5. Rewrite the three index pages + the home "Latest" loop.
6. Retire `report-card.html` and `report-row.html` if fully replaced by `catalog-card.html`; remove the now-unused `.hl-row*` CSS **only after** confirming nothing else uses it.
7. **Count parity check:** each listing must show the same number of items as before (nothing dropped).

## 7. Files affected

| File | Change |
|---|---|
| `_data/catalog.yml` | **NEW** — source of truth |
| `_includes/catalog-card.html` | **NEW** — one card + filter `data-*` attrs |
| `_includes/listing-filter.html` | **NEW** — search box + chips + count + empty state |
| `assets/js/listing-filter.js` | **NEW** — client-side filter |
| `reports/index.md` | rewrite to loop catalog; add page-header + filter |
| `hunting-detections/index.md` | rewrite to loop catalog; keep page-header; add filter |
| `ioc-feeds/index.md` | rewrite to loop catalog; keep page-header; add filter |
| `index.md` | "Latest" loops catalog (newest 3 reports) |
| `assets/css/custom.css` | filter-bar + chip styles; card `data-*`; remove orphaned `.hl-row*` / report-card CSS only if fully unused |
| `_includes/report-card.html`, `report-row.html` | retire if fully replaced |

## 8. Out of scope

Report/detection bodies; the post template; global nav search; sponsor / about / support pages; URL or permalink changes; Jekyll collections / file moves.

## 9. Open implementation details (resolve during planning)

- Exact `date` backfill per entry (slug date vs. month-only).
- Card density for the longer lists (detections ≈ 36) — tune padding or a compact card variant.
- Liquid tag-count for chips: compute per page (loop + counters, or `group_by`); confirm the approach renders correctly.
- Whether IOC `.json` URLs should open in a new tab (they currently are raw files) — preserve current behavior.

## 10. Verification

- No local Jekyll build → verify via the visual companion (rendered listing + working filter) and on the branch before deploy.
- **Count parity:** each listing shows the same item count as today.
- Reference integrity: retired includes removed cleanly; no broken links; URLs unchanged.
- Filter behavior matches the approved demo (search + multi-tag OR + count + empty state).
- The home-eyebrow commit (`b756859`) rides out with this branch's deploy.
