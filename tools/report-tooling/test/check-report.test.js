'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { checkMarkdown } = require('../check-report.js');

const GOOD = [
  '| Tactic / Technique | Name | Evidence |',
  '|---|---|---|',
  '| Execution / T1059.004 | Unix Shell | interactive bash |',
  '| Persistence / T1505.003 | Web Shell | plugin dir |'
].join('\n');

const ROWSPAN = [
  '<table><thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th></tr></thead>',
  '<tbody>',
  '<tr><td rowspan="2">Initial Access</td><td>T1566.001</td><td>Spearphishing Attachment</td></tr>',
  '<tr><td>T1189</td><td>Drive-by Compromise</td></tr>',
  '</tbody></table>'
].join('\n');

const NO_TACTIC = [
  '| Technique | Evidence |',
  '|---|---|',
  '| T1071.001 | HTTPS beaconing |'
].join('\n');

// Rule Type / Count / MITRE Techniques Covered / Overall FP Risk, as published in
// ai-agent-frameworks-2026-05-23 and three others. Carries IDs, is not a mapping.
const DETECTION_COVERAGE = [
  '| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |',
  '|---|---|---|---|',
  '| YARA | 8 rules | T1574.006, T1014, T1564.001 | LOW to MEDIUM |',
  '| Sigma | 12 rules | T1071.001, T1027 | LOW to HIGH (per rule) |'
].join('\n');

// A declared Tactic column whose value is not an ATT&CK tactic. Nothing resolves,
// so the author's mapping did not survive.
const BOGUS_TACTIC = [
  '| Tactic | Technique ID | Technique Name | Evidence |',
  '|---|---|---|---|',
  '| Fabrication | T1059.004 | Unix Shell | interactive bash |'
].join('\n');

// opendirectory-157-180-101-47, line 741. The retired ID is an aside in the
// evidence cell, not a second declared technique.
const RETIRED_MENTION = [
  '| Tactic / Technique | Name | Evidence |',
  '|---|---|---|',
  '| Defense Evasion / T1686 | Disable or Modify System Firewall | ' +
    'INPUT --dport 19923 rule; nat OUTPUT rewritten. Formerly T1562.004 |'
].join('\n');

// nsminer-cryptojacker, line 146. Bold tactic cells.
const BOLD_TACTIC = [
  '| Tactic | Technique ID | Technique Name | Evidence |',
  '|---|---|---|---|',
  '| **Execution** | T1204.002 | User Execution: Malicious File | User runs `IMG001.exe`. |',
  '| **Persistence** | T1547.001 | Registry Run Keys | implied by the NSIS installer |'
].join('\n');

test('a clean mapping table passes', () => {
  const r = checkMarkdown(GOOD, 'good.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.techniques, 2);
  assert.strictEqual(r.unmapped, 0);
  assert.deepStrictEqual(r.missing, []);
});

test('a report with no technique IDs passes rather than reporting NOT CHECKED', () => {
  const r = checkMarkdown('# A report\n\nNo ATT&CK content here.\n', 'empty.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.tables, 0);
  assert.strictEqual(r.techniques, 0);
});

test('rowspan is handled, so a merged tactic cell does not fail the gate', () => {
  const r = checkMarkdown(ROWSPAN, 'rowspan.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.techniques, 2);
  assert.strictEqual(r.unmapped, 0);
});

// A technique table with no Tactic column is a deliberately rejected shape, not a
// gap. It declares no tactic column and resolves no tactic, so a tactic-organised
// strip cannot be built from it and there is nothing for the gate to compare.
test('a technique table with no Tactic column is ignored rather than failed', () => {
  const r = checkMarkdown(NO_TACTIC, 'notactic.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.tables, 0);
  assert.strictEqual(r.techniques, 0);
  assert.deepStrictEqual(r.missing, []);
});

test('a detection-coverage table is ignored, contributing to no count', () => {
  const r = checkMarkdown(DETECTION_COVERAGE, 'coverage.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.tables, 0);
  assert.strictEqual(r.techniques, 0);
  assert.deepStrictEqual(r.missing, []);
});

// The counterpart to the two tests above, and the reason the candidate rule keys
// on the HEADER rather than on what the parser accepted. Scoping the scan to
// accepted tables would report this shape as PASS while every technique in it was
// silently lost.
test('a candidate table that resolves nothing fails rather than being skipped', () => {
  const r = checkMarkdown(BOGUS_TACTIC, 'bogus.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.tables, 1);
  assert.match(r.problems.join(' '), /yielded no techniques/i);
});

test('a retired-ID aside in an evidence cell is not a declared ID', () => {
  const r = checkMarkdown(RETIRED_MENTION, 'retired.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.techniques, 1);
  assert.deepStrictEqual(r.missing, []);
});

test('bold tactic cells parse, so the table keeps every technique', () => {
  const r = checkMarkdown(BOLD_TACTIC, 'bold.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.tables, 1);
  assert.strictEqual(r.techniques, 2);
  assert.strictEqual(r.unmapped, 0);
  assert.deepStrictEqual(r.missing, []);
  assert.deepStrictEqual(
    r.layer.techniques.map((t) => t.tactic).sort(),
    ['execution', 'persistence']
  );
});

test('IDs mentioned in prose outside any table are not a mapping-table gap', () => {
  const r = checkMarkdown(GOOD + '\n\nStray mention of T9999.001 outside any table.\n', 'x.md');
  assert.strictEqual(r.status, 'PASS');
});

test('the layer is validated, not just generated', () => {
  const r = checkMarkdown(GOOD, 'good.md');
  assert.strictEqual(r.layer.versions.layer, '4.5');
  assert.strictEqual(r.layer.techniques.length, 2);
  r.layer.techniques.forEach((t) => {
    assert.match(t.techniqueID, /^T\d{4}(\.\d{3})?$/);
    assert.match(t.tactic, /^[a-z][a-z-]+$/);
  });
});

test('a bare confidence word never reaches a layer comment', () => {
  const bad = [
    '| Tactic | Technique ID | Technique Name | Component | Confidence |',
    '|---|---|---|---|---|',
    '| Execution | T1059.004 | Unix Shell | | HIGH |'
  ].join('\n');
  const r = checkMarkdown(bad, 'bad.md');
  if (r.status === 'FAIL') {
    assert.match(r.problems.join(' '), /confidence word/i);
  } else {
    r.layer.techniques.forEach((t) => {
      assert.ok(!/^(HIGH|MODERATE|LOW|DEFINITE)\.?$/i.test((t.comment || '').trim()),
        'a bare confidence word must never reach a layer comment');
    });
  }
});
