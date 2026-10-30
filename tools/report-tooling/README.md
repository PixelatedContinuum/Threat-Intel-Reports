# Report tooling tests

Unit tests and live-corpus verification for `assets/js/attack-coverage.js` and
`assets/js/glossary.js`.

    npm install
    npm test          # unit tests against fixtures
    npm run verify    # fetch every live report and check the real corpus

`npm run verify` reports PASS, FAIL, or NOT CHECKED per report, for the ATT&CK strip
and the glossary separately. A report that could not be fetched is NOT CHECKED with
the reason attached, never a pass. Exit codes are 0 PASS, 1 FAIL, 2 NOT CHECKED.

**The corpus is every directory under `reports/`, not every entry in
`_data/catalog.yml`.** Those sets differ: a report published preview-style is live at
its URL but deliberately commented out of the catalog so it stays off the listing
pages. Defining the corpus from the catalog would silently skip exactly those
reports, which carry the strip and the glossary like any other. The run prints the
listed and unlisted counts and names the unlisted ones.

`node check-report.js <report.md | https://url>` gates one report. The markdown form
checks the ATT&CK strip only and reports the glossary as NOT CHECKED, because
extracted tables carry none of the elements the glossary exclusion list is about.

`node lib/check-glossary.js <body.html>` checks one saved page for glossary marks in
places they must never appear.

**Tabbed-report tooling** (design-v4 checks 5.1 to 5.3). A tabbed report carries one
`{: .hl-tab-<token>}` line directly under each `##` heading's tier line, and the layout
renders the tabs from it.

| Script | Input | What it proves |
|---|---|---|
| `node propose-tabs.js <path to index.md \| folder \| slug> [--write]` | a report (a path may be the vault copy), or every report with no argument; a bare `--write` refuses with exit 2 | proposes the design-v4 section 3 tab for each `##` from its heading text (name, tier-3 teardown, span, then the report template's own headings), prints the line to paste and counts the headings it cannot place; `--write` inserts the lines, leaves an existing one alone, warns when some headings got no line (a partial write is by design and check-tabs then fails the report), and preserves the file's line endings (CRLF stays CRLF; a mixed file is refused) |
| `node check-tabs.js [--require] <report.md \| https://url> [--against <report.md>]` | a report | `--require` makes a report with no tab tags a FAIL (exit 1): use it on every new report, which ships tabbed. Without it: all-or-none, the seven known tokens, the line directly after the tier line, one tab per section, and no heading id equal to `one-page` or `tab-<token>`. Any `hl-tab-` outside a fenced block makes the report tabbed (the layout's trigger is that substring), and a misplaced one FAILS with its line number and what kramdown does with it. Without `--require` an untagged report is PASS with a reason; a partly tagged one FAILS |
| `node check-report-text.js --baseline <url-or-file> --page <url-or-file> [--width 1280,390] [--control] [--control-teardown]` | the pre-tagging article and the tabbed page | design-v4 check 5.2 in Chrome over `lib/cdp.js`: one-page mode, `[data-rv-chrome]`, `script`, `style` and `title` stripped, an ORDERED word diff (a moved paragraph or section FAILS), the `h2`/`h3` id sequence equal to the baseline's, every baseline article id present exactly once (not only headings), matching counts for headings, tables, rows, figures, teardowns, details, code blocks, links and lists, and a FAIL when the words left fall under 90% of the baseline's. `--control` deletes one body paragraph and `--control-teardown` one paragraph inside a closed `details.hl-teardown`; both must be caught |

**The new-report gate (T-0500.1.9).** One command before the preview push of a NEW report, from
a folder that may sit outside this checkout (`threat-intel-vault/reports/<slug>/`):

    bash tools/report-tooling/new-report-gates.sh <report folder holding index.md> [--out DIR] [--baseline-md FILE]

It renders the folder twice with `render-report.rb` (tagged, and untagged with the tab lines
stripped), serves both from `lib/gate-server.js`, then prints one PASS, FAIL or NOT CHECKED line
each for `check-tabs --require`, `check-report-text` at 1280 and 390 against the untagged
render, its two deletion controls (each must exit 1) and `check-browser-report` on the tagged
render. `--baseline-md FILE` renders that baseline from another copy of the report (the vault's,
while the site copy is checked), so a paragraph lost in between shows as missing. Exit 0 only when every line is PASS; 1 on any FAIL; 2 when only NOT CHECKED remain. It
needs ruby with the jekyll, jekyll-seo-tag, kramdown-parser-gfm and sass gems, openssl, a
Chrome, and network to the live site for the theme's `main.css` and `main.min.js`; when one is
missing the gates that need it are NOT CHECKED and the script says which (`--help`).

The completeness check reads the baseline with scripting disabled, because the published
article carries inline scripts that add a "Copy" button to every `<pre>` at runtime and
those words are not report text; the tabbed page is read with its own script running,
because that is what is being checked.

**Run `npm run verify` after every edit to `_data/glossary.yml`.** A new term applies
to every published report at once, with no per-report review.

The glossary sweep runs the matcher in Node against the fetched HTML, so it is valid
before the module ships and will catch a bad exclusion pre-push. It does **not** prove
the module loads and runs in a browser; only opening a report does that.

---

## The pre-commit machinery gate

Activate it once per clone:

    git config core.hooksPath tools/git-hooks

The hook lives at `tools/git-hooks/pre-commit` and is tracked in the repo, so the rules
are reviewable in a diff. It is **not** installed into `.git/hooks/` and is inert until
the config above is set, which keeps the unattended Wire generator free of a gate that
could block its 15-minute push (it publishes to the `wire-data` branch via
`tools/wire/push-wire-data.sh`, never to main; see `.github/workflows/pages.yml`).

**What it is for.** The publish skill gates every surface for a campaign that ships
through it, Steps 1a to 1f before the push and `npm run verify` after. Nothing gated the
edits that are *not* a publish: a detection-tiering backfill, a redaction sweep, a bulk
correction across published feeds. Those invalidate a generated artifact without
regenerating it, and until the next campaign ships nobody finds out.

It routes on staged paths, so a commit touching only prose runs nothing and says so:

| Staged | Runs | Catches |
|---|---|---|
| `hunting-detections/*.md`, `_data/detection_manifests.yml` | `check-detection-manifest.js` | manifest stale against source |
| `ioc-feeds/*.json`, `_data/catalog.yml`, `assets/data/ioc-index.json` | `check-ioc-index.js` | index stale, embargoed feed leaking |
| `ioc-feeds/*.json`, `_data/catalog.yml`, `_data/ioc_tables.yml`, `reports/*/index.md`, the stubs | `check-ioc-tables.js` | viewer tables stale, a stub surviving after re-embargo, a regenerated table that silently drops a previously published row |
| `_data/wire.yml` | `check-wire.js` | malformed or description-bearing wire data |

`_data/wire.yml` is no longer committed (it lives on the `wire-data` branch and the Pages
workflow copies it in at build time), so the wire gate and a local Jekyll preview both need
`npm run wire:pull` first; without it the gate reports NOT CHECKED and the page renders as
unavailable, neither of which is a defect.
| `_data/catalog.yml`, `_data/tags.yml` | `check-tags.js` | a retired tag spelling, case drift, a tag the vocabulary does not know |
| `reports/*/index.md` | `check-report.js` on the changed reports only | orphaned figure-nav anchors, partly-marked tiers, broken strip |
| `_data/glossary.yml` | nothing runnable | prints the post-push sweep as owed |

**FAIL blocks the commit. NOT CHECKED warns and allows.** Blocking on NOT CHECKED would
make an absent `node_modules` un-committable, and the answer to that is a permanent
`--no-verify` habit, which costs the whole gate. NOT CHECKED is never folded into PASS
and always carries its reason and its remedy.

**It cannot replace `npm run verify`, and does not try to.** `verify-corpus.js` fetches
the live site, so running it from a pre-commit hook would check the *previously
published* build, which by construction does not contain the change being committed. It
would pass, and pass for the wrong reason. The glossary's render side, the picker's rule
binding and anything about appearance still need the published build, and the hook prints
them as owed rather than implying coverage.

`node check-detection-manifest.js` gates `_data/detection_manifests.yml` on its own. It
regenerates the manifest in memory and diffs it against the committed file, the same
regenerate-and-diff approach `check-ioc-index.js` uses. Line endings and a trailing
newline are not drift.

`node check-tags.js` gates the catalog's `tags:` lists (and the `detection_tags` /
`ioc_tags` / `stix_tags` overrides, when present) against the vocabulary in `_data/tags.yml`.
The listing filter and the badge colour lookup both compare tag strings exactly, so
"Open Dir" and "OpenDirectory" were two tags to the site and neither reached the chip
threshold on its own. A retired alias, a case or whitespace drift on a canonical tag, or a
tag listed twice on one entry FAILS and names the exact spelling to use. A tag the
vocabulary does not know only WARNS, so a genuinely new tag can be typed first and added
to `_data/tags.yml` deliberately rather than pushed into a near-miss of an existing one.

`node generate-ioc-tables.js` writes `_data/ioc_tables.yml` and one stub page per PUBLISHED
feed under `ioc-feeds/<slug>/`, and REMOVES a stub whose feed is no longer published.
`node check-ioc-tables.js` gates both by regenerate-and-diff. Only published feeds get a
page: the three embargoed campaigns keep their raw JSON, which is live-but-unlisted by
design, and gain no rendered surface.

It also enforces design v4 check 5, "IOC tables lose nothing": the regenerated table is
compared row by row with the previously published one (`--against <file>`, or `git show
HEAD:_data/ioc_tables.yml` by default) and a row that disappears FAILS unless one of the
bounded excuses applies:

- **the same value under another type or case, and the action survives.** The surviving
  row must be in the same feed's block, and when the removed row carried an action the
  surviving row must carry the same action (case-insensitive). A retype that drops
  `BLOCK` is `UNEXPLAINED`, detail "action lost". Case-insensitive value matching is
  allowed only for the hash types and `domain`/`hostname`: a URL, path, filename or
  pattern is compared exactly, because a URL path's case is part of the URL.
- **the feed itself says the value is not an indicator**, in `non_indicators`,
  `explicitly_excluded` or `metadata.reference`. Only the indicator VALUE fields count:
  string items, and the `value`/`values`/`indicator`/`url`/hash-shaped keys of object
  items. `reason`, `note`, `description` and `warning` text never exempts a row.
- **the whole feed is gone and that is legitimate**: its JSON is absent from `ioc-feeds/`,
  or the feed is embargoed by `lib/catalog-status.js` (the generator's own rule). A feed
  whose JSON is present and published (or whose status is `unknown`) that produces no
  block is `UNEXPLAINED`, class "feed dropped while published". That is the shape an
  extraction regression leaves, and regenerate-and-diff cannot see it.

Regenerate-and-diff alone cannot see any of this: a generation that is correct and
narrower matches the feeds perfectly while a hunt pivot goes missing, which is the
direction the E7 work failed in twice. Every removed row is printed with its reason class
and a count per class. The comparison runs whether or not the working table differs from
HEAD, so a regeneration that removes a row is named on the "identical to HEAD" path too
rather than left to the staleness half. `--after <file>` replaces the new side for
reproducing a comparison and for the control that must fail; the staleness half still
reads the real table, so a copy cannot make a stale table look current.

**Zero is not a pass.** A previous side with no rows (an empty mapping, a scalar file, an
entry with no rows) is NOT CHECKED, exit 2: there is no denominator, so "0 removed" would
be a category error. A new side with 0 rows while the previous has rows FAILS even where
each feed's disappearance would otherwise be excused.

**Baseline boundary, stated.** The previous table is the last PUBLISHED one. A lossy table
that is committed becomes the next run's baseline and this checker cannot see that
(design-v4 check 5 decision D9, rejected as out of scope): enforcement is the pre-commit
hook (`lib/staged-gate.js`) and publish step 1g, both of which run this checker before a
table is committed or deployed. A HEAD with no `_data/ioc_tables.yml` yet (the first
commit that adds one) is a stated SKIP, and a git failure is NOT CHECKED, never a pass.

**Exemptions are read from the working-tree feed**, deliberately: a feed edit that adds an
exclusion is a reviewed change to the feed in the same commit, and reading HEAD instead
would let a working-tree exclusion excuse a row while the committed feed still calls it an
indicator. The reviewer reads the feed diff alongside this gate's output.

`node generate-actors.js` writes `_data/actors_index.yml`, one stub page per designation
under `actors/<id>/` and, beside each stub, that actor's ATT&CK Navigator layer
(`actors/<id>/attack-navigator-layer.json`, the per-actor counterpart of the site-wide layer,
scored by how many reports about the actor map each technique) from the hand-written
`_data/actors.yml`, the catalog and the reports: every published report that names a
designation, and the ATT&CK techniques the primary reports map (read with the same parser as
the coverage strip). It REMOVES a stub, with its layer, whose designation left the data file. An entry with
`kind: named` is an actor a report attributes to a self-identifying handle at HIGH or DEFINITE
(so no UTA was assigned): slug id, `name` as the report prints it, mentions found by exact
strings and never linked in prose, same identifiers rule. `node link-actors.js` turns every bare `UTA-YYYY-NNN` in a published report or
detection page into a link to its actor page (idempotent; code, headings, tags and existing
links are left alone). `node check-actors.js` gates all of it: regenerate-and-diff on the index,
the stubs and the layers, a FAIL on a bare mention that has a page, and a FAIL on a designation a published
report names with no entry. A designation whose only report is unlisted gets no entry and no
page until go-live, and the gate names it as absent on purpose.

`node generate-xref.js` writes the cross-reference pages: `_data/attack_index.yml` and one stub
per ATT&CK technique under `techniques/<id>/` (from the reports' mapping tables, the generated
detection tables in `_data/detection_attack.yml` and the per-actor lists in
`_data/actors_index.yml`), `_data/family_index.yml` and one stub per family under
`families/<slug>/` (from the hand-written vocabulary `_data/families.yml` matched against the
YARA `family` metadata, the feeds' `family` fields, the catalog tags and the actors' tooling), and
the site-wide Navigator layer at `assets/data/attack-navigator-layer.json`. Published sources
only. A technique id outside the ATT&CK catalog and a family label outside the vocabulary are
listed by name under `unresolved` and `unmapped`, never guessed into a page; a vocabulary entry
nothing published matches FAILS, so an empty page never ships. `node check-xref.js` gates the two
indexes, the layer and the stubs by regenerate-and-diff.

`node generate-misp-feed.js` writes the MISP feed under `feeds/misp/`: `manifest.json`, one
`<uuid>.json` per published campaign and `hashes.csv`, in the MISP feed format that MISP pulls
natively and OpenCTI reads through its MISP feed connector. One event per catalog entry: the
indicators from the campaign's STIX bundle (Indicator objects only; a bare observable, which is
how a do-not-block value travels, is left out), the Suricata, YARA and Sigma rules from its
detection page (through `lib/parse-detections.js`, the tier deciding `to_ids`), the CVEs the
bundle names, links to the report, the detection page, the bundle and the IOC feed, and tags
(`tlp:clear`, ATT&CK galaxy, catalog topics, UTA actors). UUIDs are UUIDv5 under one fixed
namespace, derived from the slug and the attribute's type and value, so a rebuild never
re-issues one. `feeds/misp/_state.json` (not published) keeps each event's content hash and
last-changed timestamp; a timestamp moves only when the hash does, and a campaign that leaves
the catalog is recorded as withdrawn there and must be itemised in `feeds/misp/changelog.md`.
`node check-misp-feed.js` gates all of it; `validate-misp-feed.py` loads every event with
PyMISP (the Actions `gates` job runs it; locally `pip install pymisp` first).

`node generate-stix-manifest.js` writes `stix/manifest.json`: every published bundle with its
URL, SHA-256, size, object and indicator counts and modified time, plus the zip, so a platform
can poll one file and fetch only what changed. `node check-stix-manifest.js` gates it.

| `_data/actors.yml`, `_data/actors_index.yml`, `actors/*/index.md`, `actors/*/attack-navigator-layer.json`, `_data/catalog.yml`, `reports/*/index.md`, `hunting-detections/*.md` | `check-actors.js` | index, a page or a layer stale, a bare designation unlinked, a designation with no entry |
| `_data/families.yml`, `_data/attack_index.yml`, `_data/family_index.yml`, `techniques/*/index.md`, `families/*/index.md`, `assets/data/attack-navigator-layer.json`, plus every input above and `ioc-feeds/*.json` | `check-xref.js` | an index, the layer or a page stale, a vocabulary entry nothing published matches |
| `feeds/misp/*`, `stix/*.json`, `hunting-detections/*.md`, `reports/*/index.md`, `_data/catalog.yml`, the ATT&CK TSV | `check-misp-feed.js` | an event, the manifest or hashes.csv stale; content changed without its timestamp moving; a withdrawn event the changelog does not itemise |
| `stix/*.json`, `stix/*.zip`, `stix/manifest.json`, `_data/catalog.yml` | `check-stix-manifest.js` | the manifest stale against a bundle, the zip or the catalog |

Nothing here is published: `_config.yml` excludes `tools/*` from the Jekyll build.
