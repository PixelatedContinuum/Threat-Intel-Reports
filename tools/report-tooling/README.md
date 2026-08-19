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
the config above is set, which keeps the unattended Wire timer on LXC-102 free of a gate
that could block its twice-daily commit.

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
| `_data/wire.yml` | `check-wire.js` | malformed or description-bearing wire data |
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

Nothing here is published: `_config.yml` excludes `tools/*` from the Jekyll build.
