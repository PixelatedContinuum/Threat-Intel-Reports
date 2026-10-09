'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const A = require('../lib/actors.js');

const GOOD = `
actors:
  - id: UTA-2026-001
    status: active
    first_observed: 2026-02-28
    last_updated: 2026-03-01
    type: Sliver operator
    motivation: Cybercrime
    confidence: { distinct_actor: MODERATE, distinct_actor_pct: 68, named_actor: INSUFFICIENT }
    summary: One.
    primary_host: 203.0.113.1
    tooling: [Sliver]
    reports:
      primary: [/reports/one/]
    related:
      - id: UTA-2026-002
        relation: Shares a provider only.
  - id: UTA-2026-002
    status: active
    first_observed: 2026-04-03
    last_updated: 2026-04-03
    type: Second operator
    motivation: Unknown
    confidence: { distinct_actor: null, distinct_actor_pct: null, named_actor: INSUFFICIENT }
    summary: Two.
    primary_host: 203.0.113.2
    reports:
      primary: [/reports/two/]
`;

const CATALOG = `
entries:
  - title: "Report One"
    date: 2026-03-01
    severity: high
    report_url: /reports/one/
    detection_url: /hunting-detections/one-detections
    ioc_url: /ioc-feeds/one-iocs.json
  - title: "Report Two"
    date: 2026-04-03
    severity: med
    report_url: /reports/two/
  # - title: "Embargoed"
  #   report_url: /reports/three/
`;

function report(slug, body, fm) {
  const head = Object.assign({ title: 'T ' + slug, date: '2026-01-01', permalink: '/reports/' + slug + '/' }, fm || {});
  const fmText = Object.keys(head).map(k => k + ': ' + (head[k] === true ? 'true' : JSON.stringify(head[k]))).join('\n');
  return A.describeReport(slug, '---\n' + fmText + '\n---\n' + body);
}

test('parseActors accepts a well-formed record and rejects the shapes that matter', () => {
  const ok = A.parseActors(GOOD);
  assert.deepEqual(ok.problems, []);
  assert.equal(ok.actors.length, 2);

  const bad = A.parseActors(`
actors:
  - id: UTA-26-1
    status: live
    first_observed: yesterday
    last_updated: 2026-01-01
    type: x
    summary: y
    confidence: { distinct_actor: MAYBE, named_actor: INSUFFICIENT }
    reports: { primary: [] }
    related: [{ id: UTA-2026-099, relation: r }]
`);
  const text = bad.problems.join('\n');
  assert.match(text, /id must look like/);
  assert.match(text, /status must be one of/);
  assert.match(text, /first_observed must be/);
  assert.match(text, /distinct_actor must be one of/);
  assert.match(text, /reports.primary must list/);
  assert.match(text, /related UTA-2026-099 has no entry/);
});

test('publication reads both signals and never guesses', () => {
  const cat = A.parseCatalog(CATALOG);
  assert.equal(A.publication(report('one', 'x'), cat), 'published');
  assert.equal(A.publication(report('three', 'x', { unlisted: true }), cat), 'embargoed');
  assert.equal(A.publication(report('four', 'x'), cat), 'unknown');
  assert.equal(A.publication(report('one', 'x', { unlisted: true }), cat), 'conflict');
});

test('build lists primary reports first, discovers mentions, and withholds an embargoed designation', () => {
  const actors = A.parseActors(GOOD).actors;
  const cat = A.parseCatalog(CATALOG);
  const reports = [
    report('one', 'about UTA-2026-001, UTA-2026-001 again, and a nod to UTA-2026-002'),
    report('two', 'about UTA-2026-002 only'),
    report('three', 'embargoed UTA-2026-003 and UTA-2026-001', { unlisted: true })
  ];
  const ix = A.build(actors, reports, cat, {
    attack: body => body.indexOf('UTA-2026-001') > -1 ? [{ id: 'T1059.001', tactic: 'Execution', name: 'PowerShell' }] : [],
    catalogNames: { 'T1059.001': 'Command and Scripting Interpreter: PowerShell' }
  });
  assert.deepEqual(ix.problems, []);
  assert.deepEqual(ix.embargoed, ['UTA-2026-003']);
  const one = ix.entries[0];
  assert.equal(one.id, 'UTA-2026-001');
  // The unlisted report names it too, and must not appear.
  assert.deepEqual(one.reports.map(r => r.url), ['/reports/one/']);
  assert.equal(one.reports[0].role, 'primary');
  assert.equal(one.reports[0].mentions, 2);
  assert.equal(one.reports[0].title, 'Report One');
  assert.equal(one.reports[0].detection_url, '/hunting-detections/one-detections');
  assert.equal(one.attack.length, 1);
  assert.equal(one.attack[0].name, 'Command and Scripting Interpreter: PowerShell');
  assert.deepEqual(one.tactics, ['Execution']);
  const two = ix.entries[1];
  assert.deepEqual(two.reports.map(r => r.url + ':' + r.role), ['/reports/two/:primary', '/reports/one/:mentions']);
  // Techniques come from primary reports only; report one is a mention for two.
  assert.equal(two.attack.length, 0);
});

test('build fails on a primary report that is unlisted or never names the actor, and on an unknown designation in a published report', () => {
  const actors = A.parseActors(GOOD).actors;
  const cat = A.parseCatalog(CATALOG);
  const ix = A.build(actors, [
    report('one', 'names nobody'),
    report('two', 'UTA-2026-002 and the stray UTA-2026-077')
  ], cat);
  const text = ix.problems.join('\n');
  assert.match(text, /UTA-2026-001: primary report \/reports\/one\/ never names/);
  assert.match(text, /UTA-2026-077 is named in \/reports\/two\/ but has no entry/);

  const ix2 = A.build(actors, [report('one', 'UTA-2026-001', { unlisted: true }), report('two', 'UTA-2026-002')], cat);
  assert.match(ix2.problems.join('\n'), /publication signals disagree for \/reports\/one\//);
});

test('toYaml is deterministic and carries the generated marker; stub carries the layout marker', () => {
  const actors = A.parseActors(GOOD).actors;
  const cat = A.parseCatalog(CATALOG);
  const reports = [report('one', 'UTA-2026-001'), report('two', 'UTA-2026-002')];
  const a = A.toYaml(A.build(actors, reports, cat));
  const b = A.toYaml(A.build(actors, reports, cat));
  assert.equal(a, b);
  assert.match(a, /^# Auto-generated/);
  const s = A.stub(actors[0]);
  assert.ok(s.indexOf(A.STUB_MARKER) > -1);
  assert.match(s, /permalink: \/actors\/UTA-2026-001\//);
  assert.match(s, /actor_id: "UTA-2026-001"/);
});

test('linkify links bare mentions of known designations and nothing else', () => {
  const known = { 'UTA-2026-001': true };
  const md = [
    '---', 'title: UTA-2026-001 in the front matter', '---',
    'Plain UTA-2026-001 here, **bold UTA-2026-001**, (UTA-2026-001).',
    '## Heading UTA-2026-001',
    'Linked [UTA-2026-001](/x/) and <a href="/y/">UTA-2026-001</a> stay.',
    'Code `UTA-2026-001` stays; INSUFFICIENT (<50%) then UTA-2026-001 links.',
    '<img alt="alt text UTA-2026-001',
    'continued UTA-2026-001" src="x"> after UTA-2026-001',
    '| UTA-2026-001 | in a table cell |',
    '```yara', 'campaign = "UTA-2026-001"', '```',
    'Unknown UTA-2026-002 stays; XUTA-2026-001 stays; UTA-2026-0011 stays.'
  ].join('\n');
  const r = A.linkify(md, known);
  assert.equal(r.count, 6);
  const L = '<a href="/actors/UTA-2026-001/">UTA-2026-001</a>';
  assert.ok(r.text.indexOf('Plain ' + L + ' here, **bold ' + L + '**, (' + L + ').') > -1);
  assert.ok(r.text.indexOf('## Heading UTA-2026-001') > -1);
  assert.ok(r.text.indexOf('[UTA-2026-001](/x/)') > -1);
  assert.ok(r.text.indexOf('<a href="/y/">UTA-2026-001</a>') > -1);
  assert.ok(r.text.indexOf('`UTA-2026-001`') > -1);
  assert.ok(r.text.indexOf('(<50%) then ' + L) > -1);
  assert.ok(r.text.indexOf('alt="alt text UTA-2026-001\ncontinued UTA-2026-001" src="x"> after ' + L) > -1);
  assert.ok(r.text.indexOf('| ' + L + ' | in a table cell |') > -1);
  assert.ok(r.text.indexOf('campaign = "UTA-2026-001"') > -1);
  assert.ok(r.text.indexOf('Unknown UTA-2026-002 stays; XUTA-2026-001 stays; UTA-2026-0011 stays.') > -1);
  assert.ok(r.text.indexOf('title: UTA-2026-001 in the front matter') > -1);
  const again = A.linkify(r.text, known);
  assert.equal(again.count, 0);
  assert.equal(again.text, r.text);
});

test('a primary report without its own ATT&CK table falls back to its detection page mapping', () => {
  const actors = A.parseActors(GOOD).actors;
  const cat = A.parseCatalog(CATALOG);
  const reports = [report('one', 'UTA-2026-001'), report('two', 'UTA-2026-002')];
  const ix = A.build(actors, reports, cat, {
    attack: () => [],
    detectionAttack: { 'one-detections': { rows: [{ tactic: 'Execution', id: 'T1059', name: 'Command and Scripting Interpreter' }] } }
  });
  const one = ix.entries[0];
  assert.equal(one.attack.length, 1);
  assert.equal(one.attack[0].source, 'detections');
  assert.equal(one.attack[0].link, '/hunting-detections/one-detections');
  // Report two has no detection page, so nothing to fall back to.
  assert.equal(ix.entries[1].attack.length, 0);
});
