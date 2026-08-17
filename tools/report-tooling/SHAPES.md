# ATT&CK mapping-table shapes the parser recognises

`assets/js/attack-coverage.js` parses the rendered DOM, not markdown, because this list is
not statically enumerable. It began at seven. The eighth and ninth were both found during
implementation, and the ninth would have published a report claiming 11 techniques where it
documents 47.

When a tenth appears, follow the playbook at the end of this file. Do not weaken the gate.

| # | Header | First seen in |
|---|---|---|
| 1 | `Tactic / Technique \| Name \| Evidence` | current house format, 14 tables |
| 2 | `Tactic / Technique \| Name \| Conf. \| Evidence` | current house format, 4-col variant |
| 3 | `Tactic \| Technique \| Evidence` | legacy, ID and name share a cell |
| 4 | `Tactic \| Technique ID \| Technique Name \| Evidence` | legacy |
| 5 | `Tactic \| Technique ID \| Technique Name \| Evidence Observed` | legacy |
| 6 | `Tactic \| Technique ID \| Technique Name \| Confidence \| Key Evidence` | legacy |
| 7 | `Tactic \| Technique ID \| Technique Name \| Component \| Confidence` | zerotrace-74-0-42-25-20260316 |
| 8 | `Technique \| Evidence \| Confidence`, ID in parentheses | opendirectory-45-130-148-125-20260430 |
| 9 | any shape using `rowspan` on the Tactic column | PULSAR-RAT |

## Deliberately rejected, not shapes

These carry technique IDs but are not mapping tables. `findMappingTables` rejects any table
where no tactic resolves, so they correctly produce no strip.

- Detection-coverage tables, e.g. `Rule Type | Count | MITRE Techniques Covered | Overall FP Risk`,
  whose cells hold comma-separated ID lists and which have no Tactic column.
- Any technique table with no Tactic column at all. A tactic-organised strip cannot be built
  from one, and a strip that is entirely Unmapped is noise rather than honesty.

## Known limits

- `colspan` is not expanded. One corpus table uses it and it is not a mapping table.
- `rowspan="0"` (span to end of section) is treated as `1`. Not present in the corpus.
- `confidenceColumnIndex` reads the header row's own cells, so a header using `rowspan` would
  desynchronise it from grid columns. No corpus table does this today.

## Playbook when the gate reports a new shape

1. `node check-report.js <path> --verbose` prints the raw cell text that failed to resolve.
2. Add a fixture reproducing it to `test/fixtures/tables.js`.
3. Extend `assets/js/attack-coverage.js` until it passes, all existing tests still green.
4. Re-run the corpus sweep and diff **per technique, not by totals**. The invariant is
   additions only, never removals. A totals-only comparison cannot tell a gain from a swap.
5. Add the shape to the table above.
