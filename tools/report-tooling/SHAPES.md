# ATT&CK mapping-table shapes the parser recognises

`assets/js/attack-coverage.js` parses the rendered DOM, not markdown, because this list is
not statically enumerable. It began at seven. Two more were found during implementation, and
the `rowspan` one would have published a report claiming 11 techniques where it documents 47.

When a ninth appears, follow the playbook at the end of this file. Do not weaken the gate.

| # | Header | First seen in |
|---|---|---|
| 1 | `Tactic / Technique \| Name \| Evidence` | current house format, 14 tables |
| 2 | `Tactic / Technique \| Name \| Conf. \| Evidence` | current house format, 4-col variant |
| 3 | `Tactic \| Technique \| Evidence` | legacy, ID and name share a cell |
| 4 | `Tactic \| Technique ID \| Technique Name \| Evidence` | legacy |
| 5 | `Tactic \| Technique ID \| Technique Name \| Evidence Observed` | legacy |
| 6 | `Tactic \| Technique ID \| Technique Name \| Confidence \| Key Evidence` | legacy |
| 7 | `Tactic \| Technique ID \| Technique Name \| Component \| Confidence` | zerotrace-74-0-42-25-20260316 |
| 8 | any shape using `rowspan` on the Tactic column | PULSAR-RAT |

## Deliberately rejected, not shapes

These carry technique IDs but are not mapping tables. `findMappingTables` rejects any table
where no tactic resolves, so they correctly produce no strip.

- Detection-coverage tables, e.g. `Rule Type | Count | MITRE Techniques Covered | Overall FP Risk`,
  whose cells hold comma-separated ID lists and which have no Tactic column.
- `Technique | Evidence | Confidence` with the ID in parentheses
  (opendirectory-45-130-148-125-20260430). `parseRow` reads its rows perfectly well, but with no
  Tactic column nothing resolves, so a tactic-organised strip cannot be built from it. It was
  listed as a recognised shape until 2026-08-17, which was wrong: being readable is not the same
  as producing a strip.
- Any other technique table with no Tactic column at all. A strip that is entirely Unmapped is
  noise rather than honesty.

## How the publish gate scopes all of this

`check-report.js` decides what to hold to the mapping standard using a CANDIDATE test: a table
counts iff a header cell matches `/^\s*tactic/i`, or `parseTable` already yields at least one
technique. Non-candidates are ignored entirely, with no ID scan and no contribution to any count,
which is what lets the rejected shapes above coexist with a strict gate.

The header half of that test is load-bearing. Scoping the ID scan only to tables the parser
ACCEPTED would be simpler and would be wrong, because it hides a total parse failure: a table
whose tactic cells are bold resolves zero tactics, so it would be dropped as "not a mapping
table" and its silently lost techniques would report PASS. That is exactly what nsminer-cryptojacker
did: bold tactic cells, zero tactics resolved, all 7 techniques lost. So a declared Tactic column
pulls a table into scope whether or not anything parsed.

That failure was a local-extraction bug rather than a parser one. `lib/extract-tables.js` emitted
`**Execution**` literally where kramdown renders `<strong>Execution</strong>`, so the live page
always parsed correctly and only the markdown path lost the table. Cell-level inline markdown
(`**bold**`, `*italic*`, `_italic_`, `` `code` ``) is now converted, because the parser compares
`textContent` exactly.

## Known limits

- `colspan` is not expanded. One corpus table uses it and it is not a mapping table.
- `rowspan="0"` (span to end of section) is treated as `1`. Not present in the corpus.
- `confidenceColumnIndex` reads the header row's own cells, so a header using `rowspan` would
  desynchronise it from grid columns. No corpus table does this today.
- **OPEN, one corpus false positive.** A tactic-SUMMARY table has a Tactic column but no
  technique IDs at all, so it is pulled in as a candidate and then fails for yielding no
  techniques. The only instance is PULSAR-RAT's "ATT&CK Tactic Coverage Analysis"
  (`Tactic | Techniques Observed | Coverage Level | Business Impact`), where the middle column
  holds counts (3, 4, 3, 4) rather than IDs. That report is correct as written and its real
  mapping table parses all 47 techniques with nothing missing. Distinguishing it from a genuine
  total failure needs a decision, not an improvised rule: the discriminator would be that the
  table declares zero technique IDs, so nothing can have been lost. Left failing on purpose
  rather than relaxed unilaterally.
- The local markdown path and the live path can legitimately disagree when a report's raw HTML
  is malformed. `reports/quasar-xworm-powershell/index.md` line 189 opens its table with curly
  quotes, `<table class=”professional-table”>`. jsdom recovers the table, so the local path reads
  5 techniques, while kramdown does not accept the tag as an HTML block, so the live page has no
  `<table>` element there at all and reads 0. Running both paths is what surfaces this class of
  defect; neither parser is wrong.

## Playbook when the gate reports a new shape

1. `node check-report.js <path> --verbose` prints the raw cell text that failed to resolve.
2. Add a fixture reproducing it to `test/fixtures/tables.js`.
3. Extend `assets/js/attack-coverage.js` until it passes, all existing tests still green.
4. Re-run the corpus sweep and diff **per technique, not by totals**. The invariant is
   additions only, never removals. A totals-only comparison cannot tell a gain from a swap.
5. Add the shape to the table above.
