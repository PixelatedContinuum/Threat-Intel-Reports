'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const fixtures = require('./fixtures/tables.js');
const AC = require('../../../assets/js/attack-coverage.js');

function firstTable(html) {
  return new JSDOM('<body>' + html + '</body>').window.document.querySelector('table');
}

test('tacticSlug converts display names to ATT&CK shortnames', () => {
  assert.strictEqual(AC.tacticSlug('Command and Control'), 'command-and-control');
  assert.strictEqual(AC.tacticSlug('Defense Evasion'), 'defense-evasion');
  assert.strictEqual(AC.tacticSlug('Reconnaissance'), 'reconnaissance');
});

test('parses the current 3-column shape', () => {
  const r = AC.parseTable(firstTable(fixtures.current3col));
  assert.strictEqual(r.techniques.length, 2);
  assert.deepStrictEqual(
    { id: r.techniques[0].id, tactic: r.techniques[0].tactic, name: r.techniques[0].name },
    { id: 'T1595.002', tactic: 'Reconnaissance', name: 'Vulnerability Scanning' }
  );
});

test('parses legacy shape with ID and name sharing a cell', () => {
  const r = AC.parseTable(firstTable(fixtures.legacyIdInTechnique));
  assert.strictEqual(r.techniques[0].id, 'T1059.004');
  assert.strictEqual(r.techniques[0].tactic, 'Execution');
  assert.strictEqual(r.techniques[0].name, 'Unix Shell');
});

test('parses legacy shape with separate ID and name columns', () => {
  const r = AC.parseTable(firstTable(fixtures.legacySplitIdName));
  assert.strictEqual(r.techniques[0].id, 'T1505.003');
  assert.strictEqual(r.techniques[0].tactic, 'Persistence');
  assert.strictEqual(r.techniques[0].name, 'Web Shell');
});

test('parses all remaining shapes without loss', () => {
  ['legacyEvidenceObserved', 'legacy5colConfidence', 'legacy5colComponent'].forEach((k) => {
    const r = AC.parseTable(firstTable(fixtures[k]));
    assert.strictEqual(r.techniques.length, 1, k + ' should yield one technique');
    assert.ok(r.techniques[0].tactic, k + ' should resolve a tactic');
  });
});
