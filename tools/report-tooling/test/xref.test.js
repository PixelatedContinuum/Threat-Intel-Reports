'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const X = require('../lib/xref.js');

const VOCAB = `
families:
  - family: XWorm
    kind: rat
    aliases: [Xworm, XwormLoader]
  - family: Quasar RAT
    kind: rat
    aliases: [QuasarRAT]
  - family: NjRAT
    kind: rat
  - family: KAIDO
    kind: rat
  - family: Sliver
    kind: c2-framework
    tags: [Sliver]
    summary: A C2.
  - family: chisel
    kind: tunnel
`;

const CATALOG = {
  '/reports/one/': { title: 'One', date: '2026-03-01', tags: ['Sliver', 'RAT'],
    detection_url: '/hunting-detections/one-detections', ioc_url: '/ioc-feeds/one-iocs.json' },
  '/reports/two/': { title: 'Two', date: '2026-05-01', tags: ['RAT'],
    detection_url: '/hunting-detections/two-detections' }
};

const CAT = {
  version: '19.2',
  byId: {
    'T1059.001': { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', tactics: ['Execution'] },
    'T1105': { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', tactics: ['Command and Control'] },
    'T1055': { id: 'T1055', name: 'Process Injection', tactic: 'Stealth', tactics: ['Stealth', 'Privilege Escalation'] }
  }
};
const ORDER = ['Execution', 'Privilege Escalation', 'Stealth', 'Command and Control'];

function reports() {
  return [
    { url: '/reports/one/', title: 'One', date: '2026-03-01', body: 'one', unlisted: false },
    { url: '/reports/two/', title: 'Two', date: '2026-05-01', body: 'two', unlisted: false },
    { url: '/reports/secret/', title: 'Secret', date: '2026-06-01', body: 'secret', unlisted: true }
  ];
}
function attack(body) {
  if (body === 'one') return [{ id: 'T1059.001', tactic: 'Execution', name: 'PowerShell', confidence: 'HIGH' },
    { id: 'T1059.001', tactic: 'Execution', name: 'dup', confidence: 'HIGH' },
    { id: 'T9999', tactic: 'Execution', name: 'Not real', confidence: 'LOW' }];
  if (body === 'two') return [{ id: 'T1055', tactic: 'Stealth', name: 'Process Injection', confidence: 'MODERATE' }];
  return [{ id: 'T1105', tactic: 'Command and Control', name: 'Ingress', confidence: 'HIGH' }];
}
const DET_ATTACK = {
  'one-detections': { rows: [{ tactic: 'Execution', id: 'T1059.001', name: 'PowerShell', rules: 'a, b', count: 2 },
    { tactic: 'Command and Control', id: 'T1105', name: 'Ingress Tool Transfer', rules: 'c', count: 1 }] },
  'secret-detections': { rows: [{ tactic: 'Execution', id: 'T1059.001', name: 'PowerShell', rules: 'z', count: 1 }] }
};
const ACTORS_INDEX = { actors: [
  { id: 'UTA-2026-002', attack: [{ id: 'T1059.001' }] },
  { id: 'UTA-2026-001', attack: [{ id: 'T1059.001' }, { id: 'T1055' }] }
] };

/* ---- vocabulary ------------------------------------------------------- */

test('parseFamilies validates kind, dedups names and slugs, and refuses a shared alias', function () {
  const p = X.parseFamilies(VOCAB);
  assert.deepEqual(p.problems, []);
  assert.equal(p.families.length, 6);
  assert.equal(p.families[1].slug, 'quasar-rat');
  const bad = X.parseFamilies(`
families:
  - family: A
    kind: spaceship
  - family: a
  - family: B
    aliases: [shared]
  - family: C
    aliases: [shared]
  - family: "!!!"
`);
  assert.ok(bad.problems.some(function (m) { return /kind must be one of/.test(m); }));
  assert.ok(bad.problems.some(function (m) { return /duplicate family name/.test(m); }));
  assert.ok(bad.problems.some(function (m) { return /alias "shared" is also claimed by B/.test(m); }));
  assert.ok(bad.problems.some(function (m) { return /empty url slug/.test(m); }));
});

test('familyMatcher: whole label, then parentheticals stripped, then every part of a split label', function () {
  const m = X.familyMatcher(X.parseFamilies(VOCAB).families);
  const names = function (l) { return m(l).map(function (f) { return f.name; }); };
  assert.deepEqual(names('XWorm'), ['XWorm']);
  assert.deepEqual(names('xworm'), ['XWorm']);
  assert.deepEqual(names('XwormLoader'), ['XWorm']);
  assert.deepEqual(names('KAIDO (Quasar RAT fork)'), ['KAIDO']);
  assert.deepEqual(names('NjRAT/XWorm (Bladabindi variant)'), ['NjRAT', 'XWorm']);
  assert.deepEqual(names('QuasarRAT/Xworm'), ['Quasar RAT', 'XWorm']);
  assert.deepEqual(names('KAIDO (Quasar RAT fork) + XWorm (v5)'), ['KAIDO', 'XWorm']);
  // Half a label known maps nothing: the unknown half would be hidden otherwise.
  assert.deepEqual(names('GSocket/THC backdoor kit'), []);
  assert.deepEqual(names('Unattributed. No family label is supported'), []);
});

/* ---- reading labels ------------------------------------------------------ */

test('detectionFamiliesFromText reads family metadata per fenced YARA rule, by rule name', function () {
  const md = [
    'Prose with family = "NotARule" outside a fence is ignored.',
    '```yara',
    'rule One_A {',
    '  meta:',
    '    family = "XWorm"',
    '  condition: true',
    '}',
    'private rule One_B {',
    '  meta:',
    '    family = "XWorm"',
    '}',
    'rule One_C {',
    '  meta:',
    '    family = "KAIDO (Quasar RAT fork)"',
    '}',
    '```'
  ].join('\n');
  assert.deepEqual(X.detectionFamiliesFromText(md), {
    XWorm: ['One_A', 'One_B'],
    'KAIDO (Quasar RAT fork)': ['One_C']
  });
});

test('feedFamiliesFromJson collects metadata.primary_family and every family field, once each', function () {
  const labels = X.feedFamiliesFromJson({
    metadata: { primary_family: 'Sliver' },
    indicators: [{ value: 'x', family: 'Sliver' }, { value: 'y', family: 'XWorm' },
      { value: 'z', family: '' }, { nested: { family: 'KAIDO' } }]
  });
  assert.deepEqual(labels.sort(), ['KAIDO', 'Sliver', 'XWorm']);
});

/* ---- the technique index ------------------------------------------------- */

test('buildAttack indexes published reports, published detection pages and actors, in catalog order', function () {
  const ix = X.buildAttack(reports(), CATALOG, DET_ATTACK, ACTORS_INDEX,
    { attack: attack, catalog: CAT, tacticOrder: ORDER, tacticSlug: X.familySlug,
      compareId: function (a, b) { return a < b ? -1 : 1; } });
  assert.deepEqual(ix.problems, []);
  assert.equal(ix.attack_version, '19.2');
  // The unlisted report's T1105 report row is absent; its detection rows are
  // absent too (no catalog entry carries secret-detections).
  const ids = ix.techniques.map(function (t) { return t.id; });
  assert.deepEqual(ids, ['T1055', 'T1059.001', 'T1105']);
  const ps = ix.techniques[1];
  assert.equal(ps.name, 'PowerShell');
  assert.equal(ps.reports.length, 1, 'a report maps a technique once however many rows carry it');
  assert.equal(ps.reports[0].confidence, 'HIGH');
  assert.equal(ps.detections.length, 1);
  assert.equal(ps.detections[0].count, 2);
  assert.equal(ps.rule_count, 2);
  assert.equal(ps.score, 3);
  assert.deepEqual(ps.actors, ['UTA-2026-001', 'UTA-2026-002']);
  assert.equal(ps.url, '/techniques/T1059.001/');
  assert.equal(ps.mitre_url, 'https://attack.mitre.org/techniques/T1059/001/');
  const itt = ix.techniques[2];
  assert.equal(itt.reports.length, 0, 'the unlisted report is not a source');
  assert.equal(itt.detections.length, 1);
  // The unresolved id is named, not dropped and not paged.
  assert.deepEqual(ix.unresolved, [{ id: 'T9999', mentions: 1 }]);
  assert.equal(ix.max_score, 3);
});

test('buildAttack lists a multi-tactic technique under each of its tactics, in strip order', function () {
  const ix = X.buildAttack(reports(), CATALOG, DET_ATTACK, ACTORS_INDEX,
    { attack: attack, catalog: CAT, tacticOrder: ORDER, tacticSlug: X.familySlug });
  assert.deepEqual(ix.tactics.map(function (t) { return t.name; }), ORDER);
  const pe = ix.tactics[1], st = ix.tactics[2];
  assert.deepEqual(pe.techniques, ['T1055']);
  assert.deepEqual(st.techniques, ['T1055']);
  assert.equal(ix.tactics[0].rule_count, 2);
});

test('buildAttack FAILS on a technique whose tactic has no column', function () {
  const ix = X.buildAttack(reports(), CATALOG, DET_ATTACK, ACTORS_INDEX,
    { attack: attack, catalog: CAT, tacticOrder: ['Execution'] });
  assert.ok(ix.problems.some(function (m) { return /no heatmap column/.test(m) && /T1055/.test(m); }));
});

test('navigatorLayer carries one entry per technique and tactic, scored, with the site url', function () {
  const ix = X.buildAttack(reports(), CATALOG, DET_ATTACK, ACTORS_INDEX,
    { attack: attack, catalog: CAT, tacticOrder: ORDER });
  const layer = X.navigatorLayer(ix, { site: 'https://example.test', tacticSlug: X.familySlug });
  assert.equal(layer.domain, 'enterprise-attack');
  assert.equal(layer.versions.attack, '19');
  assert.equal(layer.techniques.length, 4, 'T1055 appears under both of its tactics');
  const ps = layer.techniques.filter(function (t) { return t.techniqueID === 'T1059.001'; })[0];
  assert.equal(ps.tactic, 'execution');
  assert.equal(ps.score, 3);
  assert.match(ps.comment, /https:\/\/example\.test\/techniques\/T1059\.001\//);
  assert.equal(layer.gradient.maxValue, 3);
});

/* ---- the family index ---------------------------------------------------- */

test('buildFamilies joins rules, feeds, tags and tooling, names unmapped labels and fails an empty family', function () {
  const fams = X.parseFamilies(VOCAB).families;
  const det = {
    'one-detections': { 'XWorm': ['One_A', 'One_B'], 'QuasarRAT/Xworm': ['One_C'], 'Mystery': ['One_D'] },
    'two-detections': { 'KAIDO (Quasar RAT fork)': ['Two_A'] },
    'secret-detections': { 'XWorm': ['Z'] }
  };
  const feeds = { 'one-iocs.json': ['XWorm', 'Odd thing'], 'secret-iocs.json': ['XWorm'] };
  const actors = [{ id: 'UTA-2026-001', tooling: ['Sliver', 'chisel'] }, { id: 'UTA-2026-002', tooling: ['Chisel', 'Mimikatz'] }];
  const ix = X.buildFamilies(fams, det, feeds, CATALOG, actors);
  const by = {};
  ix.families.forEach(function (f) { by[f.name] = f; });

  assert.equal(by.XWorm.rule_count, 3, 'two direct rules and the Xworm half of a split label');
  assert.equal(by.XWorm.detections.length, 2);
  assert.equal(by.XWorm.feed_count, 1);
  assert.deepEqual(by.XWorm.reports.map(function (r) { return r.url; }), ['/reports/one/']);
  assert.equal(by['Quasar RAT'].rule_count, 1);
  assert.equal(by.KAIDO.rule_count, 1);
  assert.deepEqual(by.KAIDO.reports.map(function (r) { return r.url; }), ['/reports/two/']);
  // Sliver: by tag only.
  assert.equal(by.Sliver.rule_count, 0);
  assert.deepEqual(by.Sliver.reports.map(function (r) { return r.url; }), ['/reports/one/']);
  assert.deepEqual(by.Sliver.actors, ['UTA-2026-001']);
  // chisel: by tooling only, both spellings.
  assert.deepEqual(by.chisel.actors, ['UTA-2026-001', 'UTA-2026-002']);
  assert.deepEqual(by.chisel.tooling_labels, ['chisel', 'Chisel']);
  assert.equal(by.chisel.url, '/families/chisel/');
  // The unlisted page and feed contribute nothing.
  assert.ok(!by.XWorm.detections.some(function (d) { return /secret/.test(d.url); }));
  // Unmapped labels are named with where they came from; tooling is not reported.
  assert.deepEqual(ix.unmapped, [
    { label: 'Mystery', where: ['detection one-detections'] },
    { label: 'Odd thing', where: ['feed one-iocs.json'] }
  ]);
  // NjRAT matches nothing published, so the vocabulary entry is a problem.
  assert.ok(ix.problems.some(function (m) { return /family "NjRAT" matches nothing published/.test(m); }));
  assert.equal(ix.problems.length, 1);
});

/* ---- outputs ------------------------------------------------------------ */

test('stubs carry the layout, the lookup key and the permalink the generator removes by', function () {
  const t = X.stubTechnique({ id: 'T1059.001', name: 'PowerShell' });
  assert.match(t, /^---\nlayout: technique\n/);
  assert.match(t, /technique_id: "T1059\.001"/);
  assert.match(t, /permalink: \/techniques\/T1059\.001\//);
  assert.ok(t.indexOf(X.TECHNIQUE_MARKER) > -1);
  const f = X.stubFamily({ name: 'Quasar RAT', slug: 'quasar-rat' });
  assert.match(f, /family_slug: "quasar-rat"/);
  assert.match(f, /permalink: \/families\/quasar-rat\//);
  assert.ok(f.indexOf(X.FAMILY_MARKER) > -1);
});

test('the YAML writers round-trip through js-yaml with the same shape', function () {
  const yaml = require('js-yaml');
  const ix = X.buildAttack(reports(), CATALOG, DET_ATTACK, ACTORS_INDEX,
    { attack: attack, catalog: CAT, tacticOrder: ORDER });
  const doc = yaml.load(X.toYamlAttack(ix));
  assert.equal(doc.techniques.length, 3);
  assert.equal(doc.tactics.length, 4);
  assert.deepEqual(doc.unresolved, [{ id: 'T9999', mentions: 1 }]);
  const fx = X.buildFamilies(X.parseFamilies(VOCAB).families, {}, {}, CATALOG,
    [{ id: 'UTA-2026-001', tooling: ['XWorm', 'Quasar RAT', 'NjRAT', 'KAIDO', 'chisel'] }]);
  const fdoc = yaml.load(X.toYamlFamilies(fx));
  assert.equal(fdoc.families.length, 6);
  assert.deepEqual(fdoc.unmapped, []);
});
