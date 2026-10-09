# Hand-off: site enhancements, where things stand and what is next

**Date:** 2026-10-09, end of the first enhancement session
**Site repo:** `PixelatedContinuum/Threat-Intel-Reports`, work goes straight to `main` (Joseph, 2026-10-09)
**Tracker:** `PixelatedContinuum/ai-workflows`, `tasks/`; the next session's task is filed there and points here

---

## Read this first: how the site is built and shipped now

- **Deploy is GitHub Actions**, `.github/workflows/pages.yml`. A push to `main` builds, runs the
  unit tests and source-side gates (a separate job, not blocking deploy), indexes the site with
  Pagefind, and deploys. Roughly two minutes to live. Check the Actions tab after every push.
- **The Wire** comes from the `wire-data` branch (one orphan commit, rewritten hourly by the
  generator on LXC-102). `_data/wire.yml` is NOT committed on `main`. For a local build or the
  wire gate run `npm run wire:pull` in `tools/report-tooling` first. GitHub's "wire-data had
  recent pushes" banner is cosmetic; never open a pull request from that branch.
- **Local build works here:** `gem install --user-install github-pages` once, then
  `export GEM_HOME=$(ruby -e 'puts Gem.user_dir'); export PATH="$GEM_HOME/bin:$PATH"; export LANG=C.UTF-8 LC_ALL=C.UTF-8; JEKYLL_ENV=production jekyll build -d <scratch>/_site`
  (about 20 s). Build into the scratchpad, never into the repo; `.sass-cache/` and `_site/` are
  ignored but check `git status` before committing.
- **Search index locally:** `npm install pagefind@1.3.0` in a scratch dir, then
  `npx pagefind --site <scratch>/_site`. Expect "Indexed 197 pages" (grows as reports publish).
- **Screenshots locally:** `npm install playwright-core@1.49.1` in a scratch dir, launch with
  `executablePath: '/opt/pw-browsers/chromium'`, serve the build with `python3 -m http.server`
  from inside `_site`. Use `devices['iPhone 13']` for a real phone render; a desktop viewport at
  phone width is NOT a phone render. Stop the server with `fuser -k <port>/tcp`, not `pkill -f`
  (that matches and kills the calling shell).
- **Tests and gates:** `cd tools/report-tooling && npm test` (790 tests) and
  `node tools/git-hooks/precommit.js` after `git add -A`. Both must be green before a push.
- **Cache-busting is load-bearing.** Markup and script ship as pairs: `listing-filter.js?v=11`,
  `ioc-table.js?v=3`, `nav-drawer.js?v=1`; bump the number when the script changes. The
  stylesheet link is versioned per build automatically (`custom.css?v=<build revision>`).
- **Catalog tags** follow `_data/tags.yml`; `check-tags.js` fails a commit on an alias spelling.
  **Report categories** are one of twelve values listed on `/report-templates/`.
- **No em dashes** in anything written for the site or commit messages (house rule).
- The agent conventions for the tracker repo are in its `AGENTS.md`: every commit there names a
  task (`T-NNNN`), `task.py` writes the notes, `git commit --only <paths>`.

## What shipped today (all live)

1. The fourteen review fixes (licence wording, dead vendor scripts off, highlighter self-hosted,
   Twitter card, metadata, tag vocabulary and gate, twelve categories, skip link, tag-aware
   Continue Reading, inline styles moved, Liquid-mangled GUID fixed).
2. Wire moved off `main`; Actions deploy; `_data/wire.yml` removed; `wire:pull` helper (T-0194).
3. Full-text search (Pagefind), deep-linkable listing filters with clickable tag badges, IOC
   feed tables with Confidence, Action and FP-risk columns and a Defang toggle (T-0196).
4. Navigation drawer on every device (blue "Menu" button, logo, search field at the right),
   search results styled as section-coloured cards, Need Help and Search out of the bar.

## Verified only by emulation, worth a real-device glance

- Drawer open and close, the phone search field opening over the bar, the Pagefind UI
  theming. Joseph checked the phone once after the cache fix and liked it; no further report.
- Pre-existing: the large vertical gaps between wrapped nav links on phones no longer matter
  (links are in the drawer); the old `.hl-nav__links` rules were deleted in the 2026-10-09
  tidy-up (T-0198).

## Data points surfaced by the new IOC columns (author's call, not a bug in the viewer)

- `cloudsync-assembler-toolkit-91-197-98-188`: two domains carry confidence `EXCLUDED` yet sit
  in the exportable table (`aka1.hopto.org`, `johnathon-yerrow.sahs.ac.zw`).
- `arsenal-237-enc_c2-exe`: a registry row with confidence `NOT OBSERVED - SINGLE-RUN MODEL`.
- Nine objects corpus-wide have boolean `false_positive_risk`; they render as no value.

## Shipped since the first session: the threat actor index (T-0197, 2026-10-09)

- `/actors/` lists every UTA designation with a published report; `/actors/<id>/` is a profile:
  status, the published confidence figures, summary, the reports that are about it and the
  ones that merely name it (discovered, never hand-listed), detection, IOC and STIX links per
  report, the host the assigning report is named for, tooling, the ATT&CK techniques the
  primary reports map, and related designations with the published relation.
- The record is `_data/actors.yml` (hand-written; everything in it is a summary of the linked
  report). Each entry also carries `targeting` (region and sector categories, never a victim
  name) and `identifiers` (actor-OWNED artifacts the operator chose or made: handles, channels,
  operator brands and domains, wallets, bot ids, personas, operator C2). Victim names are never
  a field. `tools/report-tooling/generate-actors.js` writes `_data/actors_index.yml` and the stub
  pages, `link-actors.js` links every bare designation in reports and detection pages (304
  mentions across 26 files, HTML anchors so raw HTML blocks render too), and `check-actors.js`
  gates all of it; it runs in the pre-commit hook and in the Actions `gates` job. Rules of the
  gate: a bare mention with a page FAILS; a designation a published report names with no entry
  FAILS; an actor whose only report is unlisted gets no page (UTA-2026-022 today) and is named
  as absent on purpose; and every `identifiers[].value` must be printed verbatim in one of that
  actor's own PUBLISHED reports, or it FAILS. That last rule is the safety contract: the page
  carries no claim the public reports do not already make, and since every published report has
  cleared the victim-naming gate, an identifier that passes cannot be a victim's. Values a
  report withholds (UTA-2026-019's build-host and messaging ids, UTA-2026-020's FOFA account,
  UTA-2026-021's kit-author Telegram id) stay off.
- When a report publishes a new designation: add its entry to `_data/actors.yml` (figures,
  targeting and identifiers from the report, not the vault file), then
  `node generate-actors.js && node link-actors.js`. When an embargoed report goes live,
  uncomment its catalog entry, drop `unlisted`, add the actor entry, regenerate, link. This is
  now a documented publish step: `hunters-ledger-publish` Step 4f in the ai-workflows repo, with
  a checklist item, a 1j verify-table row and the go-live flip updated to match.
- Not done, by choice: the one HIGH named actor in the corpus (the GHOST kit author) has no
  profile; the index is UTA-only. A `kind: named` entry would be a small extension of the same
  layout if wanted. The ATT&CK section lists techniques per actor; the site-wide heatmap and
  Navigator layer belong to backlog item 2.

## Shipped since: technique and family cross-reference pages, heatmap, Navigator layer (T-0198, 2026-10-09)

- `/techniques/<id>/` (283 pages) lists every published report (with the confidence the report's
  own table states and the tactic it filed the technique under), every detection page whose
  coverage names it (with the rule names) and every tracked actor whose reports map it, plus the
  MITRE link. `/techniques/` is the site-wide heatmap: the ATT&CK matrix in strip order, one cell
  per technique shaded by score (reports plus rules, through two CSS custom properties, no
  script), a filter, a most-mapped list, and the Navigator layer download at
  `assets/data/attack-navigator-layer.json` (one entry per technique and tactic, scored, each
  comment linking back to the page). Technique ids on actor profiles, in the detection pages'
  coverage tables and in the coverage strip's chips now link to the technique page.
- `/families/<slug>/` (46 pages) lists every report, YARA rule (by `family` metadata, rule names
  shown), IOC feed (by `family` field) and actor profile (by `tooling`) that names the family, under
  one canonical spelling. `/families/` is a card grid filterable by kind. The vocabulary is
  `_data/families.yml` (hand-written: name, kind, aliases, optional catalog tags and a summary);
  a label it does not know is listed under `unmapped` in `_data/family_index.yml` (44 today,
  mostly operator-toolkit descriptions and exploit labels, which are not families), never guessed
  into a page. Matching also strips parentheticals and splits a label on `/` or ` + ` when every
  part is known, so `KAIDO (Quasar RAT fork)` and `NjRAT/XWorm` resolve without aliases.
- Tooling: `tools/report-tooling/lib/xref.js` (pure, 11 tests), `generate-xref.js` (writes
  `_data/attack_index.yml`, `_data/family_index.yml`, the stubs and the layer; removes a stub
  nothing indexes), `check-xref.js` (regenerate-and-diff on all four outputs; a vocabulary entry
  nothing published matches FAILS so an empty page never ships). Routed by `staged-gate.js` on
  every input (reports, detection pages, feeds, catalog, actor data, detection ATT&CK tables, the
  ATT&CK TSV, the vocabulary and its own outputs), in the pre-commit hook and the Actions `gates`
  job. Published sources only, by construction: an unlisted report contributes nothing. Layouts
  `_layouts/technique.html` and `_layouts/family.html`; accents amber (`#fb923c`) and teal
  (`#2dd4bf`); search sections Techniques and Families; nav positions 2.8 and 2.9.
- Publish step: `hunters-ledger-publish` Step 4g (ai-workflows), with a checklist item, a 1k
  verify-table row, the staging list and the go-live flip updated. The only hand-written part is
  a `_data/families.yml` entry or alias when a report names a family the vocabulary lacks.
- Verified: 813 unit tests, both gates, a local github-pages build (every technique, family,
  actor, report, detection and feed link on the built site resolves), Pagefind (552 pages),
  Playwright desktop and iPhone 13 screenshots, the heatmap filter and the family kind chips
  exercised, the strip chips confirmed as anchors. Actions run 22 green (cross-reference pages) and run 23 green (the three tidy-ups).
- Left open: a per-actor Navigator layer download on the profile (the site-wide layer exists now,
  so it is a small addition); a named-actor entry kind; `_data/families.yml` wants a glance
  whenever a report names a family that is new to the site.

## Shipped since: the tidy-ups (T-0198, 2026-10-09)

- Dead `.hl-nav__links` rules deleted (five blocks). The nine PNG screenshots over 200 KB are
  lossless WebP, pixel-identical to the PNGs (checked on all nine) and 2.2 MB down to 0.8 MB.
  `assets/css/custom.css` is now `assets/css/custom.scss` with empty front matter, so Jekyll's
  Sass converter (already `compressed` in `_config.yml`) writes the published
  `/assets/css/custom.css` at 129 KB instead of 212 KB; the path and the link in `head.liquid`
  are unchanged, the source is still plain CSS, and the two scripts and the test that read the
  source now read the `.scss`. Verified by rule and media-query counts matching outside comments
  and a report page rendering identically on desktop and phone.
- Local build note, corrected: in this cloud container `jekyll build --safe` fails on the
  `seo` tag and the remote theme's SCSS fails on the default locale; what works is
  `github-pages build -d <scratch>/_site` with `LANG=C.UTF-8 LC_ALL=C.UTF-8 RUBYOPT=-Eutf-8`
  and `PAGES_REPO_NWO` set (about 45 s).

## The backlog, ranked

Each item is self-contained. The first three are the ones Joseph was leaning toward.

1. **Threat actor index.** DONE 2026-10-09, see above. Left open: a named-actor entry kind,
   and a per-actor Navigator layer download once item 2 builds the site-wide layer.
2. **Technique and family cross-reference pages.** DONE 2026-10-09, see above. Left open: the
   per-actor Navigator layer download.
3. **Consolidated YARA and Sigma feeds**, modelled on `feeds/suricata/`: one file per engine
   with stable identifiers and a withdrawn-rule changelog, regenerated from
   `_data/detection_manifests.yml` (every rule already has a hash and tier there). Also a
   `rules/` directory in SigmaHQ layout for git consumers.
4. **MISP feed and STIX manifest.** MISP feeds are static files (`manifest.json` plus per-event
   JSON), buildable from the STIX bundles in `stix/`; a `stix/manifest.json` with hash and
   modified time per bundle lets platforms poll instead of pulling the zip.
5. **Quick wins.** `?q=` on the IOC Feeds page so a tool can deep-link one indicator; Research
   versus News chips on the Wire (listing-filter.js already supports a `data-kind` axis, the
   page renders no chips for it) and a Wire-only RSS feed; per-report revision history (seven
   reports carry `last_updated` with nothing shown); a "cite this report" box; detections-only
   Atom feed and a JSON Feed; `Dataset` structured data on IOC and STIX pages.
6. **Tidy-ups.** DONE 2026-10-09, see above.

## How to start the next session

1. Attach both repos (`Threat-Intel-Reports` and `ai-workflows`). In ai-workflows run
   `/usr/bin/python3 .claude/scripts/task.py show <the open task id>`; it points back here.
2. Pick one backlog item, log start on that task, work on site `main`, verify with the local
   build and screenshots, push, confirm the Actions run is green, log the commit, close.
3. For anything that changes the generator or the LXC-102 container, hand it to a session on
   Joseph's host; a cloud session cannot reach the LAN.
