'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const M = require('../lib/misp-feed.js');

const BUNDLE = {
  type: 'bundle', id: 'bundle--1', objects: [
    { type: 'indicator', pattern_type: 'stix', name: 'C2 host', pattern: "[ipv4-addr:value = '203.0.113.7']", x_opencti_score: 95 },
    { type: 'indicator', pattern_type: 'stix', name: 'Weak domain', description: 'Shared hosting, context only', pattern: "[domain-name:value = 'example.test']", x_opencti_score: 40 },
    { type: 'indicator', pattern_type: 'stix', name: 'Dropper', pattern: "[file:hashes.'SHA-256' = '" + 'a'.repeat(64) + "']", x_opencti_score: 95 },
    { type: 'indicator', pattern_type: 'stix', name: 'Dropper again', pattern: "[file:hashes.'SHA-256' = '" + 'a'.repeat(64) + "']", x_opencti_score: 95 },
    { type: 'indicator', pattern_type: 'stix', name: 'Odd', pattern: "[windows-registry-key:key = 'HKLM\\\\Software\\\\X']", x_opencti_score: 80 },
    { type: 'indicator', pattern_type: 'yara', name: 'Rule in STIX', pattern: 'rule x { condition: true }' },
    { type: 'domain-name', value: 'pool.example.test' },
    { type: 'intrusion-set', name: 'UTA-2026-001' },
    { type: 'vulnerability', name: 'CVE-2026-0001' },
    { type: 'vulnerability', name: 'not a cve' },
    { type: 'attack-pattern', name: 'PowerShell', external_references: [{ source_name: 'mitre-attack', external_id: 'T1059.001' }] }
  ]
};
const RULES = [
  { name: 'Det rule', engine: 'sigma', tier: 'Detection', robustness: 2, confidence: 'HIGH', attack: ['T1059.001', 'T1105'], hash: 'abcd1234', body: 'title: Det rule\ndetection: {}' },
  { name: 'Hunt rule', engine: 'suricata', tier: 'Hunting', robustness: 1, confidence: 'MODERATE', attack: [], hash: 'ef012345', body: 'alert tcp any any -> any any (msg:"x"; sid:1;)' },
  { name: 'Correlation', engine: 'sigma', tier: 'Detection', robustness: 2, confidence: 'HIGH', attack: [], hash: null, body: null, cross_referenced: true }
];
const ENTRY = { title: 'Example campaign', date: '2026-09-01', severity: 'high', tags: ['RAT', 'Open Dir'],
  report_url: '/reports/example/', detection_url: '/hunting-detections/example-detections',
  stix_url: '/stix/example.json', ioc_url: '/ioc-feeds/example-iocs.json' };
const NAMES = { 'T1059.001': 'PowerShell', 'T1105': 'Ingress Tool Transfer' };

function build() { return M.buildEvent({ entry: ENTRY, slug: 'example', bundle: BUNDLE, rules: RULES, attackNames: NAMES }); }

test('uuid5 matches the reference implementation and is stable per slug, type and value', function () {
  assert.equal(M.uuid5('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'python.org'), '886313e1-3b8a-5372-9b90-0c9aee199e5d');
  assert.equal(M.eventUuid('example'), M.eventUuid('example'));
  assert.notEqual(M.eventUuid('example'), M.eventUuid('example2'));
  assert.notEqual(M.attributeUuid('example', 'domain', 'a.test'), M.attributeUuid('example', 'url', 'a.test'));
});

test('slugOf names an entry by its report, else its detection page, else its feed', function () {
  assert.equal(M.slugOf(ENTRY), 'example');
  assert.equal(M.slugOf({ detection_url: '/hunting-detections/thing-detections' }), 'thing');
  assert.equal(M.slugOf({ ioc_url: '/ioc-feeds/thing-iocs.json' }), 'thing');
  assert.equal(M.slugOf({ title: 'x' }), null);
});

test('STIX indicators become typed attributes; bare observables, rule indicators and odd patterns are handled as documented', function () {
  const s = M.attributesFromStix(BUNDLE, 'example');
  const by = {};
  s.attributes.forEach(function (a) { (by[a.type] = by[a.type] || []).push(a); });
  assert.equal(by['ip-dst'][0].value, '203.0.113.7');
  assert.equal(by['ip-dst'][0].to_ids, true);
  assert.equal(by['ip-dst'][0].category, 'Network activity');
  assert.equal(by.domain[0].to_ids, false, 'a score below the threshold is context, not a blocklist entry');
  assert.match(by.domain[0].comment, /Shared hosting, context only/);
  assert.match(by.domain[0].comment, /confidence 40\/100/);
  assert.equal(by.sha256.length, 2, 'dedupe happens in buildEvent, not here');
  assert.equal(by['stix2-pattern'].length, 1, 'an unrecognised pattern is kept whole');
  assert.deepEqual(s.unmapped.length, 1);
  assert.ok(!s.attributes.some(function (a) { return a.value === 'pool.example.test'; }), 'an observable with no indicator is not an attribute');
  assert.ok(!s.attributes.some(function (a) { return a.type === 'yara'; }), 'rules come from the detection page, not the bundle');
  assert.deepEqual(s.actors, ['UTA-2026-001']);
  assert.deepEqual(s.cves, ['CVE-2026-0001']);
  assert.deepEqual(s.attack, { 'T1059.001': 'PowerShell' });
});

test('rules become yara, sigma and snort attributes with the tier deciding to_ids; a bodyless rule is skipped by name', function () {
  const r = M.attributesFromRules(RULES, 'https://x.test/hunting-detections/example-detections/', NAMES);
  assert.equal(r.attributes.length, 2);
  const det = r.attributes[0], hunt = r.attributes[1];
  assert.equal(det.type, 'sigma'); assert.equal(det.to_ids, true); assert.equal(det.category, 'Payload installation');
  assert.match(det.comment, /^Det rule \| TIER: Detection \| robustness 2 \| confidence HIGH \| ATT&CK T1059\.001, T1105 \| rule hash abcd1234 \| https:/);
  assert.deepEqual(det.tags.map(function (t) { return t.name; }), ['hunters-ledger:tier="Detection"']);
  assert.equal(hunt.type, 'snort'); assert.equal(hunt.to_ids, false); assert.equal(hunt.category, 'Network activity');
  assert.deepEqual(r.skipped, ['Correlation']);
  assert.deepEqual(Object.keys(r.attack).sort(), ['T1059.001', 'T1105']);
});

test('buildEvent joins links, indicators, CVEs and rules, dedupes, tags and sorts deterministically', function () {
  const ev = build();
  assert.equal(ev.uuid, M.eventUuid('example'));
  assert.equal(ev.info, 'Example campaign');
  assert.equal(ev.date, '2026-09-01');
  assert.equal(ev.threat_level_id, 1);
  assert.equal(ev.analysis, 2);
  const types = ev.attributes.map(function (a) { return a.type; });
  assert.deepEqual(types, ['link', 'link', 'link', 'link', 'vulnerability', 'sha256', 'domain', 'ip-dst', 'stix2-pattern', 'snort', 'sigma']);
  assert.equal(ev.attributes.filter(function (a) { return a.type === 'sha256'; }).length, 1, 'the duplicate hash collapsed');
  const tags = ev.tags.map(function (t) { return t.name; });
  assert.deepEqual(tags, [
    'tlp:clear', 'hunters-ledger:topic="RAT"', 'hunters-ledger:topic="Open Dir"', 'hunters-ledger:actor="UTA-2026-001"',
    'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"', 'misp-galaxy:mitre-attack-pattern="Ingress Tool Transfer - T1105"'
  ]);
  ev.attributes.forEach(function (a) { assert.equal(a.uuid, M.attributeUuid('example', a.type, a.value)); });
  assert.deepEqual(ev.notes.skipped, ['Correlation']);
  // The same inputs give the same event, byte for byte.
  assert.equal(JSON.stringify(build()), JSON.stringify(ev));
});

test('an unknown severity is threat level 4 and a missing name leaves the technique untagged but noted', function () {
  const ev = M.buildEvent({ entry: Object.assign({}, ENTRY, { severity: null }), slug: 'example', bundle: BUNDLE, rules: RULES, attackNames: { 'T1059.001': 'PowerShell' } });
  assert.equal(ev.threat_level_id, 4);
  assert.ok(!ev.tags.some(function (t) { return /T1105/.test(t.name); }));
  assert.ok(ev.notes.unmapped.some(function (n) { return /T1105/.test(n); }));
});

test('stamp keeps a timestamp while content is unchanged, bumps it when content moves, and records withdrawals', function () {
  const ev1 = build();
  const first = M.stamp([ev1], null, 1700000000);
  assert.equal(ev1.timestamp, 1700000000);
  assert.deepEqual(first.added, ['example']);
  assert.equal(first.state.events[ev1.uuid].first_published, '2023-11-14');
  // Same content later: nothing moves.
  const ev2 = build();
  const second = M.stamp([ev2], first.state, 1800000000);
  assert.equal(ev2.timestamp, 1700000000);
  assert.deepEqual(second.unchanged, ['example']);
  assert.deepEqual(second.changed, []);
  // Content changes: the timestamp follows, first_published does not.
  const ev3 = build(); ev3.attributes.pop(); ev3.attributes.forEach(function () {});
  const third = M.stamp([ev3], second.state, 1900000000);
  assert.equal(ev3.timestamp, 1900000000);
  assert.deepEqual(third.changed, ['example']);
  assert.equal(third.state.events[ev3.uuid].first_published, '2023-11-14');
  // The campaign disappears: withdrawn, uuid retained, never reused.
  const fourth = M.stamp([], third.state, 2000000000);
  assert.deepEqual(fourth.newlyWithdrawn, ['example']);
  assert.equal(fourth.withdrawn[0].uuid, ev1.uuid);
  assert.equal(fourth.withdrawn[0].last_timestamp, 1900000000);
  assert.deepEqual(Object.keys(fourth.state.events), []);
  // And it stays withdrawn on the next run.
  const fifth = M.stamp([], fourth.state, 2100000000);
  assert.equal(fifth.withdrawn.length, 1);
  assert.deepEqual(fifth.newlyWithdrawn, []);
});

test('contentHash ignores timestamps and moves with any subscriber-visible field', function () {
  const a = build(), b = build();
  a.timestamp = 1; b.timestamp = 2;
  assert.equal(M.contentHash(a), M.contentHash(b));
  b.attributes[0].comment += '!';
  assert.notEqual(M.contentHash(a), M.contentHash(b));
  const c = build(); c.tags.push({ name: 'x', colour: '#000' });
  assert.notEqual(M.contentHash(a), M.contentHash(c));
});

test('manifest, event JSON and hashes.csv carry the feed-format shape', function () {
  const ev = build();
  M.stamp([ev], null, 1700000000);
  const man = M.manifest([ev]);
  assert.deepEqual(Object.keys(man), [ev.uuid]);
  assert.deepEqual(Object.keys(man[ev.uuid]), ['Orgc', 'Tag', 'info', 'date', 'analysis', 'threat_level_id', 'timestamp']);
  assert.deepEqual(man[ev.uuid].Orgc, M.ORGC);
  const ej = M.eventJson(ev);
  assert.equal(ej.Event.uuid, ev.uuid);
  assert.equal(ej.Event.published, true);
  assert.equal(ej.Event.timestamp, 1700000000);
  assert.equal(ej.Event.Attribute.length, ev.attributes.length);
  const sig = ej.Event.Attribute.filter(function (a) { return a.type === 'sigma'; })[0];
  assert.deepEqual(Object.keys(sig), ['uuid', 'type', 'category', 'value', 'to_ids', 'comment', 'timestamp', 'Tag']);
  const link = ej.Event.Attribute[0];
  assert.ok(!('Tag' in link), 'no empty Tag arrays');
  const csv = M.hashesCsv([ev]).trim().split('\n');
  assert.equal(csv.length, ev.attributes.length);
  csv.forEach(function (l) { assert.match(l, new RegExp('^[0-9a-f]{32},' + ev.uuid + '$')); });
  assert.ok(csv.indexOf(M.md5('203.0.113.7') + ',' + ev.uuid) > -1);
  assert.deepEqual(csv, csv.slice().sort(), 'sorted, so a rebuild is diff-stable');
});

test('changelogCovers is a plain slug search', function () {
  assert.equal(M.changelogCovers('## 2026-10-09: withdrew example\n', 'example'), true);
  assert.equal(M.changelogCovers('', 'example'), false);
});
