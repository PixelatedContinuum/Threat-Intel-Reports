# Social Card Generator

Auto-generates the 1200×630 link-preview cards shown when a report URL is shared
(LinkedIn / X / Slack / Discord / iMessage). One card per report, severity-coded,
in The Hunter's Ledger brand.

## Usage

```bash
python tools/social-card/generate_card.py <report-dir>      # one report -> assets/images/cards/<slug>.png
python tools/social-card/generate_card.py --all             # every report
python tools/social-card/ensure_thumbnail.py <report-dir>   # add `thumbnail:` front-matter line (idempotent)
python tools/social-card/ensure_thumbnail.py --all
python tools/social-card/tests/test_cardlib.py              # tests (plain python, no pytest needed)
```

`<report-dir>` is the folder name under `reports/`; the slug is read from the report's `permalink`.

## What's on the card

| Element | Source |
|---|---|
| Title | report front matter `title` |
| Kicker | `category` (uppercased) → first `_data/catalog.yml` tag → `THREAT INTELLIGENCE` |
| Severity (spine + pill) | `_data/catalog.yml` entry `severity` |
| Date | report front matter `date` |
| Subtitle | report front matter `description` (one line, word-boundary truncated) |

IOCs are intentionally **not** shown (content decision 2026-06-02).

## How it reaches the live preview

`ensure_thumbnail.py` adds `thumbnail: /assets/images/cards/<slug>.png` to the report
front matter. `_includes/default/head.liquid` turns `page.thumbnail` into `og:image`,
`twitter:image`, and a `summary_large_image` Twitter card — no per-report template edit.
Platforms cache previews; force a re-scrape (LinkedIn Post Inspector, opengraph.xyz,
Facebook Sharing Debugger) after deploy.

## Files / deps

- `cardlib.py` — data extraction + Pillow rendering + thumbnail insertion (the library)
- `generate_card.py`, `ensure_thumbnail.py` — CLIs
- `SpaceGrotesk.ttf` — brand display font (SIL OFL 1.1), build-time only, not served
- Requires: Python 3, Pillow, PyYAML

## Changing the design

Palette / fonts / layout constants and `render_card` live in `cardlib.py` and mirror the
site's `assets/css/custom.css` tokens. Edit, then `generate_card.py --all` to re-render.
Reference mockups and the full design spec are in the workflow repo at
`Projects/hunters-ledger-site/preview-mockups/`.
