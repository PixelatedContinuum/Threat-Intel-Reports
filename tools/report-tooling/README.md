# Report tooling tests

Unit tests and live-corpus verification for `assets/js/attack-coverage.js` and
`assets/js/glossary.js`.

    npm install
    npm test          # unit tests against fixtures
    npm run verify    # fetch all 41 live report URLs and check the real corpus

`npm run verify` reports PASS, FAIL, or NOT CHECKED per report. A report that could
not be fetched is NOT CHECKED with the reason attached, never a pass.

Nothing here is published: `_config.yml` excludes `tools/*` from the Jekyll build.
