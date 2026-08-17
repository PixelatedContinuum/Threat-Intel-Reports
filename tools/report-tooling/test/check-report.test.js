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

test('a table with IDs but no resolvable tactic fails, naming the missing IDs', () => {
  const r = checkMarkdown(NO_TACTIC, 'notactic.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.ok(r.missing.includes('T1071.001'));
  assert.match(r.problems.join(' '), /no mapping table/i);
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
