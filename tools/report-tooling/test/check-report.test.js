'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
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

// The PULSAR-RAT shape, reduced. Before rowspan support this parsed as
// 1 mapped and 2 unmapped. The gate must FAIL that state rather than
// reporting that a strip rendered successfully.
const PULSAR_SHAPE = [
  '<table>',
  '<thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th>',
  '<th>Implementation</th><th>Confidence</th></tr></thead>',
  '<tbody>',
  '<tr><td rowspan="3">Initial Access</td><td>T1566.001</td><td>Spearphishing Attachment</td>',
  '<td>email delivery</td><td>MODERATE</td></tr>',
  '<tr><td>T1566.002</td><td>Spearphishing Link</td><td>open dir link</td><td>CONFIRMED</td></tr>',
  '<tr><td>T1189</td><td>Drive-by Compromise</td><td>compromised sites</td><td>LOW</td></tr>',
  '</tbody></table>'
].join('\n');

test('the rowspan shape that would have shipped a wrong strip now passes', () => {
  const r = checkMarkdown(PULSAR_SHAPE, 'pulsar.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.techniques, 3, 'all three rows, not just the span starter');
  assert.strictEqual(r.unmapped, 0);
  r.layer.techniques.forEach((t) => assert.strictEqual(t.tactic, 'initial-access'));
});

test('an unmapped technique is a FAIL, since that is what the old bug looked like', () => {
  const halfBroken = [
    '| Tactic / Technique | Name | Evidence |',
    '|---|---|---|',
    '| Execution / T1059.004 | Unix Shell | ok |',
    '| Nonsense Tactic / T1055 | Injection | not a real tactic |'
  ].join('\n');
  const r = checkMarkdown(halfBroken, 'half.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no resolvable tactic/i);
});

// Part A's refinement. A Tactic-headed table whose technique column holds
// counts rather than IDs is not a mapping table and must be skipped, not failed.
test('a tactic-summary table declaring no technique IDs is skipped, not failed', () => {
  const summary = [
    '| Tactic | Techniques Observed | Coverage Level | Business Impact |',
    '|---|---|---|---|',
    '| Initial Access | 3 | Comprehensive | High |',
    '| Execution | 4 | Comprehensive | High |'
  ].join('\n');
  const r = checkMarkdown(summary, 'summary.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.tables, 0, 'a table with zero declared IDs is not a mapping table');
});

// The guard on Part A's safety argument. If emphasis could hide an ID from the
// raw scan, the zero-ID skip would become a hole. It cannot: emphasis markers
// are non-word characters, so the word boundary still matches.
test('emphasis never hides a declared ID from the raw scan', () => {
  const bolded = [
    '| Tactic | Technique ID | Technique Name |',
    '|---|---|---|',
    '| **Execution** | **T1204.002** | User Execution |'
  ].join('\n');
  const r = checkMarkdown(bolded, 'bold.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.techniques, 1);
  assert.strictEqual(r.layer.techniques[0].techniqueID, 'T1204.002');
});

/* The gate's honesty about ITSELF, which is a different question from every test
   above. Those ask whether the gate reads a report correctly. This one asks what
   the gate says when it cannot run at all.

   jsdom, the parser and lib/extract-tables.js used to be required bare at module
   top level, so a tree without node_modules threw MODULE_NOT_FOUND and exited 1.
   Exit 1 is the FAIL code, meaning "this report's ATT&CK content is wrong", so a
   broken install manufactured an accusation against a report that was fine. See
   the guard comment in check-report.js and homelab-soc/docs/gate-honesty-contract.md.

   The failure is exercised for real rather than mocked: the three source files
   are copied into a temp tree with no node_modules and the copy runs as a
   subprocess, which is exactly what an operator meets after a fresh clone. */
const TOOLING = path.join(__dirname, '..');
const SITE = path.join(TOOLING, '..', '..');

function buildTempGate() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-attack-gate-'));
  const tooling = path.join(root, 'tools', 'report-tooling');
  fs.mkdirSync(path.join(tooling, 'lib'), { recursive: true });
  fs.mkdirSync(path.join(root, 'assets', 'js'), { recursive: true });
  fs.copyFileSync(path.join(TOOLING, 'check-report.js'), path.join(tooling, 'check-report.js'));
  fs.copyFileSync(
    path.join(TOOLING, 'lib', 'extract-tables.js'),
    path.join(tooling, 'lib', 'extract-tables.js')
  );
  fs.copyFileSync(
    path.join(SITE, 'assets', 'js', 'attack-coverage.js'),
    path.join(root, 'assets', 'js', 'attack-coverage.js')
  );
  const report = path.join(root, 'report.md');
  fs.writeFileSync(report, GOOD + '\n', 'utf8');
  return { root, gate: path.join(tooling, 'check-report.js'), report };
}

function runGate(gate, args, extraEnv) {
  const env = Object.assign({}, process.env, extraEnv || {});
  // A NODE_PATH inherited from the ambient environment would resolve jsdom from
  // outside the temp tree and silently defeat the point of the test.
  if (!extraEnv || !extraEnv.NODE_PATH) delete env.NODE_PATH;
  return spawnSync(process.execPath, [gate].concat(args), { encoding: 'utf8', env: env });
}

test('a dependency that will not load is NOT CHECKED and exits 2, never a FAIL against the report', () => {
  const t = buildTempGate();
  try {
    const r = runGate(t.gate, [t.report]);
    assert.strictEqual(r.status, 2,
      'exit 2 is NOT CHECKED; 1 would accuse the report and 0 would clear it');
    assert.match(r.stdout, /NOT CHECKED/);

    // The reason must name the real cause. Node's own first line of output is
    // "node:internal/modules/cjs/loader:1424", which tells an operator nothing.
    assert.match(r.stdout, /cannot find module/i);
    assert.match(r.stdout, /npm ci/, 'the reason must carry the remedy');
    assert.doesNotMatch(r.stdout, /node:internal/,
      'a Node stack-frame header is not a reason');
    assert.doesNotMatch(r.stderr, /MODULE_NOT_FOUND/,
      'the load failure must be caught, not thrown at the operator');

    const j = runGate(t.gate, [t.report, '--json']);
    assert.strictEqual(j.status, 2);
    const parsed = JSON.parse(j.stdout);
    assert.strictEqual(parsed.status, 'NOT CHECKED');
    assert.ok(parsed.reason && parsed.reason.length > 0,
      'NOT CHECKED without a reason is not an honest result');
    assert.match(parsed.reason, /cannot find module/i);

    /* Vacuity guard. Without this, a gate that exited 2 unconditionally would
       satisfy every assertion above. The SAME copied gate, handed a resolvable
       jsdom, has to check the report and clear it. */
    const ok = runGate(t.gate, [t.report], { NODE_PATH: path.join(TOOLING, 'node_modules') });
    assert.strictEqual(ok.status, 0, 'with deps resolvable the same gate must actually run');
    assert.doesNotMatch(ok.stdout, /NOT CHECKED/);
    assert.match(ok.stdout, /^PASS/);
  } finally {
    fs.rmSync(t.root, { recursive: true, force: true });
  }
});

/* The same inversion wearing a different error type. A dependency can resolve
   and still export nothing usable, which throws a TypeError rather than
   MODULE_NOT_FOUND and so exits 1 on its own path back to blaming the report. */
test('a dependency that resolves but exports nothing usable is NOT CHECKED too', () => {
  const t = buildTempGate();
  try {
    // jsdom stays resolvable through NODE_PATH, which isolates this to the
    // parser: it loads cleanly and hands back an object the gate cannot use.
    fs.writeFileSync(
      path.join(t.root, 'assets', 'js', 'attack-coverage.js'),
      'module.exports = {};\n',
      'utf8'
    );
    const env = { NODE_PATH: path.join(TOOLING, 'node_modules') };
    const r = runGate(t.gate, [t.report, '--json'], env);
    assert.strictEqual(r.status, 2, 'exit 2, not the uncaught-TypeError exit 1');
    assert.doesNotMatch(r.stderr, /TypeError/, 'the gate must catch this, not throw it');
    const parsed = JSON.parse(r.stdout);
    assert.strictEqual(parsed.status, 'NOT CHECKED');
    assert.match(parsed.reason, /unusable/i);
    assert.match(parsed.reason, /attack-coverage/i, 'the reason must name what is broken');
  } finally {
    fs.rmSync(t.root, { recursive: true, force: true });
  }
});
