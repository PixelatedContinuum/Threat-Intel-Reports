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

Nothing here is published: `_config.yml` excludes `tools/*` from the Jekyll build.
