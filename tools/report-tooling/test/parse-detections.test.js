'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const P = require('../lib/parse-detections.js');

const SIMPLE = [
  '## YARA Rules',
  '### Detection Rules',
  '#### First Rule',
  '**Tier:** Detection',
  '**Robustness:** 3',
  '**Confidence:** HIGH',
  '**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application)',
  '```yara',
  'rule ONE { condition: true }',
  '```',
  '#### Second Rule',
  '**Tier:** Hunting',
  '**Robustness:** 2',
  '```yara',
  'rule TWO { condition: true }',
  '```',
  '## Sigma Rules',
  '#### Sigma One',
  '**Tier:** Detection',
  '```yaml',
  'title: Something',
  '```'
].join('\n');

test('parses rules with engine, tier and metadata', () => {
  const r = P.parse(SIMPLE, 'demo');
  assert.strictEqual(r.rules.length, 3);
  assert.deepStrictEqual(r.unresolved, []);
  assert.strictEqual(r.rules[0].name, 'First Rule');
  assert.strictEqual(r.rules[0].engine, 'yara');
  assert.strictEqual(r.rules[0].tier, 'Detection');
  assert.strictEqual(r.rules[0].robustness, 3);
  assert.strictEqual(r.rules[0].confidence, 'HIGH');
  assert.deepStrictEqual(r.rules[0].attack, ['T1190']);
  assert.strictEqual(r.rules[2].engine, 'sigma');
});

test('fence indices count every fence in page order', () => {
  const r = P.parse(SIMPLE, 'demo');
  assert.deepStrictEqual(r.rules.map((x) => x.fence), [0, 1, 2]);
});

/* Three corpus files open an engine section with a fence that is not a rule.
   Positional pairing would offset every rule in the file by one. */
test('a non-rule fence before the first heading is skipped, not paired', () => {
  const src = [
    '## YARA Rules',
    '```text',
    'this is an explanatory block, not a rule',
    '```',
    '#### Real Rule',
    '**Tier:** Detection',
    '```yara',
    'rule REAL { condition: true }',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 1);
  assert.strictEqual(r.rules[0].name, 'Real Rule');
  assert.strictEqual(r.rules[0].fence, 1, 'points at the second fence on the page');
  assert.match(r.rules[0].head, /^rule REAL/);
});

/* Convention 1. arsenal-237-rootkit-dll documents a retired rule under a heading,
   with a Status block and prose explaining where its coverage went. It is not a
   rule with a missing body, so it must not be reported as one. */
test('a heading with no Tier is prose, neither published nor reported', () => {
  const src = [
    '## Sigma Rules',
    '#### Some Rule - RETIRED 2026-07-30',
    '**Status:** Retired. Superseded by the correlation pair in the companion file.',
    'Several paragraphs explaining why it was withdrawn.',
    '#### Real Rule',
    '**Tier:** Detection',
    '```yaml',
    'title: Real',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 1);
  assert.strictEqual(r.rules[0].name, 'Real Rule');
  assert.deepStrictEqual(r.unresolved, [], 'a retirement note is not an unresolved rule');
});

/* Convention 2. Two headings in the corpus carry three Tier lines over one fence,
   because the fence holds a correlation rule with its two base rules. */
test('several Tier lines under one heading yield one rule at the highest tier', () => {
  const src = [
    '## Sigma Rules',
    '#### Bundled Correlation',
    '**Tier:** Hunting',
    '**Robustness:** 2',
    '**Tier:** Hunting',
    '**Tier:** Detection',
    '```yaml',
    'title: Base One',
    '---',
    'title: Base Two',
    '---',
    'title: The Correlation',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 1, 'one entry per heading, not one per tier line');
  assert.strictEqual(r.rules[0].tier, 'Detection', 'highest tier wins, since that is what alerts');
  assert.deepStrictEqual(r.rules[0].tier_raw, ['Hunting', 'Hunting', 'Detection']);
  assert.strictEqual((r.rules[0].body.match(/^title:/gm) || []).length, 3);
});

test('a single correlation tier string normalises on its leading word', () => {
  const src = [
    '## Sigma Rules',
    '#### Correlation Rule',
    '**Tier:** Hunting (correlation rule) - bundled below with its 2 required non-alerting base rules',
    '```yaml',
    'title: The Correlation',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 1);
  assert.strictEqual(r.rules[0].tier, 'Hunting');
  assert.match(r.rules[0].tier_raw[0], /correlation rule/);
});

/* Convention 3. One corpus rule carries full metadata and a note saying its YAML
   lives in the correlation block above, because Sigma requires base rules to
   resolve within the same document. It has no fence of its own by necessity. */
test('a rule with a tier but no fence is cross-referenced, not unresolved', () => {
  const src = [
    '## Sigma Rules',
    '#### Base Rule Documented Separately',
    '**Tier:** Hunting',
    '**Robustness:** 1',
    '#### Real Rule',
    '**Tier:** Detection',
    '```yaml',
    'title: Real',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 2, 'it stays in the manifest so the reader still sees it');
  assert.deepStrictEqual(r.unresolved, [], 'a known state is not a failure');
  const x = r.rules[0];
  assert.strictEqual(x.name, 'Base Rule Documented Separately');
  assert.strictEqual(x.cross_referenced, true);
  assert.strictEqual(x.fence, null);
  assert.strictEqual(x.head, null);
  assert.strictEqual(r.rules[1].cross_referenced, false, 'an ordinary rule is not flagged');
});

test('an unrecognised tier is reported rather than bucketed', () => {
  const src = [
    '## Sigma Rules',
    '#### Odd One',
    '**Tier:** Experimental',
    '```yaml',
    'title: x',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 0);
  assert.strictEqual(r.unresolved.length, 1);
  assert.match(r.unresolved[0].reason, /Experimental/);
  assert.match(r.unresolved[0].reason, /Detection or Hunting/);
});

test('headings outside an engine section are ignored', () => {
  const src = [
    '## Coverage Gaps',
    '#### Not A Rule',
    '**Tier:** Detection',
    '```text',
    'not a rule body',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.deepStrictEqual(r.rules, []);
  assert.deepStrictEqual(r.unresolved, []);
});

test('head is whitespace-normalised and capped at 48 characters', () => {
  const r = P.parse(SIMPLE, 'demo');
  assert.ok(r.rules[0].head.length <= 48);
  assert.doesNotMatch(r.rules[0].head, /\s{2,}/);
});

test('a fence inside a section is never confused with a heading in its body', () => {
  const src = [
    '## Sigma Rules',
    '#### Real Rule',
    '**Tier:** Detection',
    '```yaml',
    '# the line below must not be read as a heading',
    '#### not a heading',
    'title: Real',
    '```'
  ].join('\n');
  const r = P.parse(src, 'demo');
  assert.strictEqual(r.rules.length, 1);
  assert.match(r.rules[0].body, /not a heading/);
});
