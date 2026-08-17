'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const fixtures = require('./fixtures/tables.js');
const AC = require('../../../assets/js/attack-coverage.js');

function firstTable(html) {
  return new JSDOM('<body>' + html + '</body>').window.document.querySelector('table');
}

function firstBodyCells(html) {
  const row = firstTable(html).querySelectorAll('tbody tr')[0];
  return row.querySelectorAll('td, th');
}

test('tacticSlug converts display names to ATT&CK shortnames', () => {
  assert.strictEqual(AC.tacticSlug('Command and Control'), 'command-and-control');
  assert.strictEqual(AC.tacticSlug('Defense Evasion'), 'defense-evasion');
  assert.strictEqual(AC.tacticSlug('Reconnaissance'), 'reconnaissance');
});

test('parseRow returns an array of every technique in the row', () => {
  const withId = AC.parseRow(firstBodyCells(fixtures.current3col), -1);
  assert.ok(Array.isArray(withId), 'parseRow must return an array');
  assert.strictEqual(withId.length, 1);

  const withoutId = AC.parseRow(firstBodyCells(fixtures.notAnAttackTable), -1);
  assert.ok(Array.isArray(withoutId), 'parseRow must return an array when no ID is present');
  assert.strictEqual(withoutId.length, 0);
});

test('parses the current 3-column shape', () => {
  const r = AC.parseTable(firstTable(fixtures.current3col));
  assert.strictEqual(r.techniques.length, 2);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1595.002',
    tactic: 'Reconnaissance',
    name: 'Vulnerability Scanning',
    confidence: 'HIGH',
    evidence: 'Endpoint/CVE probing'
  });
  assert.deepStrictEqual(r.techniques[1], {
    id: 'T1110.003',
    tactic: 'Credential Access',
    name: 'Password Spraying',
    confidence: 'MODERATE',
    evidence: 'single-password spray (MODERATE)'
  });
});

test('parses the current 4-column shape', () => {
  const r = AC.parseTable(firstTable(fixtures.current4col));
  assert.strictEqual(r.techniques.length, 2);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1055.002',
    tactic: 'Defense Evasion',
    name: 'Portable Executable Injection',
    confidence: 'HIGH',
    evidence: 'RW to RX'
  });
  assert.deepStrictEqual(r.techniques[1], {
    id: 'T1583.003',
    tactic: 'Resource Development',
    name: 'Virtual Private Server',
    confidence: 'MODERATE',
    evidence: 'AS35682'
  });
});

test('parses legacy shape with ID and name sharing a cell', () => {
  const r = AC.parseTable(firstTable(fixtures.legacyIdInTechnique));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1059.004',
    tactic: 'Execution',
    name: 'Unix Shell',
    confidence: 'HIGH',
    evidence: 'Interactive bash captured'
  });
});

test('parses legacy shape with separate ID and name columns', () => {
  const r = AC.parseTable(firstTable(fixtures.legacySplitIdName));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1505.003',
    tactic: 'Persistence',
    name: 'Web Shell',
    confidence: 'HIGH',
    evidence: 'WordPress plugin-dir shell'
  });
});

test('parses all remaining shapes without loss', () => {
  const expected = {
    legacyEvidenceObserved: {
      id: 'T1046',
      tactic: 'Discovery',
      name: 'Network Service Discovery',
      confidence: 'HIGH',
      evidence: 'Subdomain enumeration'
    },
    legacy5colConfidence: {
      id: 'T1213',
      tactic: 'Collection',
      name: 'Data from Information Repositories',
      confidence: 'LOW',
      evidence: 'CKAN harvest'
    },
    legacy5colComponent: {
      id: 'T1486',
      tactic: 'Impact',
      name: 'Data Encrypted for Impact',
      confidence: 'HIGH',
      evidence: 'enc.exe'
    }
  };
  Object.keys(expected).forEach((k) => {
    const r = AC.parseTable(firstTable(fixtures[k]));
    assert.strictEqual(r.techniques.length, 1, k + ' should yield one technique');
    assert.deepStrictEqual(r.techniques[0], expected[k], k + ' parsed wrong');
  });
});

test('evidence is the component cell, never the confidence word', () => {
  const r = AC.parseTable(firstTable(fixtures.componentThenConfidence));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1583.001',
    tactic: 'Resource Development',
    name: 'Acquire Infrastructure: Domains',
    confidence: 'HIGH',
    evidence: 'chainconnects.net, adminxyzhosting.com'
  });
});

test('an ID in trailing parentheses leaves a real name, not a bracket', () => {
  const r = AC.parseTable(firstTable(fixtures.parenthesisedId));
  assert.strictEqual(r.techniques.length, 0, 'no tactic column, so nothing maps');
  assert.strictEqual(r.unmapped.length, 1);
  assert.deepStrictEqual(r.unmapped[0], {
    id: 'T1562.001',
    tactic: null,
    name: 'AMSI bypass via reflection',
    confidence: 'HIGH',
    evidence: 'reflection concatenation'
  });
});

test('every ID in a multi-ID cell is returned', () => {
  const r = AC.parseTable(firstTable(fixtures.multiIdCoverage));
  assert.strictEqual(r.techniques.length, 0, 'coverage tables carry no tactic');
  assert.deepStrictEqual(
    r.unmapped.map((t) => t.id),
    ['T1505.003', 'T1027.013', 'T1070', 'T1056', 'T1119']
  );
  r.unmapped.forEach((t) => {
    assert.strictEqual(t.tactic, null);
    assert.strictEqual(t.name, '', 'a list of IDs has no single technique name');
    assert.strictEqual(t.evidence, 'LOW\u2013MEDIUM');
  });
});

test('an empty confidence cell falls back to the inline marker', () => {
  const r = AC.parseTable(firstTable(fixtures.emptyConfidenceCell));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.techniques[0].confidence, 'MODERATE');
  assert.strictEqual(r.techniques[0].evidence, 'single-password spray (MODERATE)');
});

test('a Configuration column is not a confidence column', () => {
  const r = AC.parseTable(firstTable(fixtures.configurationColumn));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1486',
    tactic: 'Impact',
    name: 'Data Encrypted for Impact',
    confidence: 'MODERATE',
    evidence: 'enc.exe over SMB (MODERATE)'
  });
});

test('the ID is located at its real offset, not an earlier substring', () => {
  const r = AC.parseTable(firstTable(fixtures.idPrecededByFalseMatch));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1059',
    tactic: 'Execution',
    name: 'Command-Line Interface',
    confidence: 'HIGH',
    evidence: 'cmd.exe spawn'
  });
});

test('a row-header th keeps both the tactic and the confidence column', () => {
  const r = AC.parseTable(firstTable(fixtures.rowHeaderTactic));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.unmapped.length, 0);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1213',
    tactic: 'Collection',
    name: 'Data from Information Repositories',
    confidence: 'LOW',
    evidence: 'CKAN harvest'
  });
});

test('tfoot rows are not data rows', () => {
  const r = AC.parseTable(firstTable(fixtures.tfootTotals));
  assert.deepStrictEqual(r.techniques.map((t) => t.id), ['T1059.004']);
  assert.strictEqual(r.unmapped.length, 0);
});

test('a nested table contributes neither rows nor cells', () => {
  const r = AC.parseTable(firstTable(fixtures.nestedTableInCell));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.unmapped.length, 0, 'the nested row is not a data row');
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1505.003',
    tactic: 'Persistence',
    name: 'Web Shell',
    confidence: 'HIGH',
    evidence: 'WordPress plugin-dir shell note see T1486 for the follow-on'
  });
});

test('a table with no technique IDs yields nothing', () => {
  const r = AC.parseTable(firstTable(fixtures.notAnAttackTable));
  assert.strictEqual(r.techniques.length, 0);
  assert.strictEqual(r.unmapped.length, 0);
});

test('a row with no resolvable tactic lands in unmapped', () => {
  const r = AC.parseTable(firstTable(fixtures.missingTactic));
  assert.strictEqual(r.techniques.length, 0);
  assert.strictEqual(r.unmapped.length, 1);
  assert.deepStrictEqual(r.unmapped[0], {
    id: 'T1071.001',
    tactic: null,
    name: 'HTTPS beaconing',
    confidence: 'HIGH',
    evidence: 'HTTPS beaconing'
  });
});
