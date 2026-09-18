'use strict';

var test = require('node:test');
var assert = require('node:assert');
var G = require('../generate-ioc-index.js');

var CATALOG = [
  'entries:',
  '  #  - title: "Held"',
  '  #    ioc_url: /ioc-feeds/held-iocs.json',
  '  - title: "Live One"',
  '    date: 2026-07-28',
  '    severity: high',
  '    report_url: /reports/live-one/',
  '    detection_url: /hunting-detections/live-one-detections',
  '    ioc_url: /ioc-feeds/live-one-iocs.json'
].join('\n');

// Both signals must agree, so the held campaign is also unlisted in front matter.
var UNLISTED = { 'held': true };

// Shape A: indicators at the TOP level, the layout of 55 of 57 feeds.
var FEED_TOP = {
  metadata: { campaign: 'Live One' },
  file_hashes: { sha256: [{ value: 'a'.repeat(64), context: 'dropper' }] },
  network_indicators: { ips: ['185.38.150.7:9999'], domains: ['Bot.GriboStress.PRO'] },  // a real one; example.com is benign-suppressed
  behavioral_indicators: ['Isolate infected systems from the network']
};

// Shape B: nested under `iocs`, the layout of the other 2.
var FEED_NESTED = {
  iocs: { network: [{ value: 'evil[.]test', context: 'C2 server' }] }
};

function build(feeds, cat, unl) {
  return G.build(feeds, cat || CATALOG, unl || UNLISTED);
}

test('indicators are extracted from a top-level feed', function () {
  var idx = build({ 'live-one-iocs.json': FEED_TOP });
  assert.ok(idx.indicators['sha256:' + 'a'.repeat(64)], 'hash indexed');
  assert.ok(idx.indicators['ipv4:185.38.150.7'], 'ip indexed with port stripped');
  assert.ok(idx.indicators['domain:bot.gribostress.pro'], 'domain lowercased');
});

test('indicators are extracted from a nested feed too', function () {
  var idx = build({ 'live-one-iocs.json': FEED_NESTED });
  assert.ok(idx.indicators['domain:evil.test'], 'nested and defanged');
});

test('prose in an indicator list is not indexed', function () {
  var idx = build({ 'live-one-iocs.json': FEED_TOP });
  assert.ok(Object.keys(idx.indicators).join(' ').indexOf('Isolate') === -1,
    'remediation advice must not be indexed');
});

test('the role comes from context where present', function () {
  var idx = build({ 'live-one-iocs.json': FEED_NESTED });
  assert.equal(idx.indicators['domain:evil.test'][0].role, 'C2 server');
});

test('EMBARGOED feeds contribute nothing, and are reported', function () {
  var idx = build({ 'held-iocs.json': FEED_TOP });
  assert.deepEqual(Object.keys(idx.indicators), [], 'no indicators from an embargoed feed');
  assert.deepEqual(idx.coverage.embargoed, ['held-iocs.json']);
  assert.deepEqual(idx.coverage.indexed, []);
});

test('a half-completed go-live is a conflict and still withholds', function () {
  // Catalog uncommented, front matter still unlisted.
  var idx = build({ 'live-one-iocs.json': FEED_TOP }, CATALOG,
                   { 'held': true, 'live-one': true });
  assert.deepEqual(Object.keys(idx.indicators), [], 'must withhold, not leak');
  assert.equal(idx.conflicts.length, 1);
  assert.equal(idx.conflicts[0].slug, 'live-one');
});

test('an unknown feed contributes nothing, and is reported separately', function () {
  var idx = build({ 'mystery-iocs.json': FEED_TOP });
  assert.deepEqual(Object.keys(idx.indicators), []);
  assert.deepEqual(idx.coverage.unknown, ['mystery-iocs.json']);
});

test('a published feed yielding nothing is reported, not silently dropped', function () {
  var idx = build({ 'live-one-iocs.json': { notes: ['nothing here'] } });
  assert.deepEqual(idx.coverage.empty, ['live-one-iocs.json']);
});

test('report metadata is joined once, not repeated per indicator', function () {
  var idx = build({ 'live-one-iocs.json': FEED_TOP });
  var slug = idx.indicators['ipv4:185.38.150.7'][0].report;
  assert.equal(idx.reports[slug].title, 'Live One');
  assert.equal(idx.reports[slug].severity, 'high');
  assert.equal(idx.reports[slug].detection_url, '/hunting-detections/live-one-detections');
});

test('counts reconcile with the data', function () {
  var idx = build({ 'live-one-iocs.json': FEED_TOP });
  assert.equal(idx.counts.indicators, Object.keys(idx.indicators).length);
  assert.equal(idx.counts.reports, Object.keys(idx.reports).length);
});

test('an indicator in two reports lists both', function () {
  var CAT2 = CATALOG + '\n' + [
    '  - title: "Live Two"',
    '    date: 2026-08-01',
    '    severity: med',
    '    report_url: /reports/live-two/',
    '    ioc_url: /ioc-feeds/live-two-iocs.json'
  ].join('\n');
  var idx = build({
    'live-one-iocs.json': { network_indicators: { ips: ['1.2.3.4'] } },
    'live-two-iocs.json': { network_indicators: { ips: ['1.2.3.4'] } }
  }, CAT2);
  assert.equal(idx.indicators['ipv4:1.2.3.4'].length, 2);
  assert.equal(idx.counts.multi_report, 1);
});

test('an unparseable feed does not crash the build', function () {
  var idx = build({ 'live-one-iocs.json': { __unparseable: 'Unexpected token' } });
  assert.deepEqual(idx.coverage.empty, ['live-one-iocs.json']);
});

test('signal-free values never enter the index, and are counted', function () {
  // 8.8.8.8 really is in the Arsenal-237 feed. It is a true statement about the
  // malware and a useless thing to match a defender's logs against.
  var idx = build({ 'live-one-iocs.json': {
    network_indicators: { ips: ['8.8.8.8', '185.38.150.7'], domains: ['github.com'] }
  } });
  assert.ok(!idx.indicators['ipv4:8.8.8.8'], 'public resolver suppressed');
  assert.ok(!idx.indicators['domain:github.com'], 'major platform suppressed');
  assert.ok(idx.indicators['ipv4:185.38.150.7'], 'the real attacker IP is kept');
  assert.equal(idx.counts.suppressed_benign, 2, 'suppression is counted, not silent');
});

/* --- the never-block bucket, 2026-09-13: same fix family as
   lib/ioc-table-extract.js, applied here because this index is a second,
   independent consumer of the same feeds with its own traversal. Removal,
   not marking: a value in this bucket must not become a typed key at all,
   because a script reading Object.keys(idx.indicators) gets the value
   regardless of any warning text sitting beside it. */

test('a never-block value never becomes an ordinary indicator key', function () {
  var idx = build({ 'live-one-iocs.json': {
    network_indicators: { domains: ['evil.test'] },
    hunt_only_never_block: [{ value: 'api.telegram.org', category: 'messaging platform' }]
  } });
  assert.ok(idx.indicators['domain:evil.test'], 'the real indicator is kept');
  assert.ok(!idx.indicators['domain:api.telegram.org'],
    'the never-block value must not become a searchable key');
  assert.ok(idx.never_block['domain:api.telegram.org'], 'but it is recorded separately');
  assert.equal(idx.counts.never_block, 1);
});

test('a never-block value nested in a sub-array with no value field of its own is still found', function () {
  // The seasia-gov-exploitation-toolkit shape: a group note plus a bare array
  // of domains, none carrying their own { value } wrapper.
  var idx = build({ 'live-one-iocs.json': {
    hunt_only_never_block: [{
      note: 'Shared public infrastructure, never block or ship as campaign IOCs',
      domains: ['gsocket.io', 'api.telegram.org', 'discord.com']
    }]
  } });
  assert.deepEqual(Object.keys(idx.indicators), []);
  assert.ok(idx.never_block['domain:api.telegram.org']);
  assert.ok(idx.never_block['domain:gsocket.io']);
  assert.ok(idx.never_block['domain:discord.com']);
  assert.equal(idx.counts.never_block, 3);
});

test('a value in BOTH an ordinary bucket and the never-block bucket resolves toward safety', function () {
  var idx = build({ 'live-one-iocs.json': {
    network_indicators: { ips: ['172.237.149.231'] },
    hunt_only_never_block: [{ value: '172.237.149.231', category: 'shared TDS landing' }]
  } });
  assert.ok(!idx.indicators['ipv4:172.237.149.231'],
    'the ordinary key must be dropped, not kept alongside the never-block one');
  assert.ok(idx.never_block['ipv4:172.237.149.231']);
});

test('the SAME value stays blockable on a DIFFERENT feed that never marked it never-block', function () {
  // The corpus's own edge case (returns/implement-fix.md from this run):
  // http://ip-api.com/line/?fields=hosting is never-block on one feed and an
  // ordinary, independently-judged indicator on another. Never-block on one
  // feed must not erase a different investigation's own finding.
  var CAT2 = CATALOG + '\n' + [
    '  - title: "Live Two"',
    '    date: 2026-08-01',
    '    severity: med',
    '    report_url: /reports/live-two/',
    '    ioc_url: /ioc-feeds/live-two-iocs.json'
  ].join('\n');
  var idx = build({
    'live-one-iocs.json': { network_indicators: { domains: ['evil.test'] },
      hunt_only_never_block: [{ value: 'shared.svc', category: 'shared infra' }] },
    'live-two-iocs.json': { network_indicators: { domains: ['shared.svc'] } }
  }, CAT2);
  assert.ok(idx.indicators['domain:shared.svc'], 'still an ordinary key, via live-two');
  assert.equal(idx.indicators['domain:shared.svc'].length, 1, 'only live-two claims it');
  assert.equal(idx.indicators['domain:shared.svc'][0].report, 'live-two');
  assert.ok(idx.never_block['domain:shared.svc'], 'and live-one still records why it withholds it');
});

test('the benign-value filter does not apply inside the never-block walk', function () {
  // github.com would be suppressed entirely from the ordinary walk. Inside
  // hunt_only_never_block it must still be recorded, with its reason, because
  // the point of this map is to name it, not filter it a second time.
  var idx = build({ 'live-one-iocs.json': {
    hunt_only_never_block: [{ value: 'github.com', category: 'vendor download' }]
  } });
  assert.ok(idx.never_block['domain:github.com']);
  assert.equal(idx.counts.suppressed_benign, 0,
    'the never-block walk must not feed the suppression counter either');
});

test('a feed with never-block content but no ordinary indicators still gets a reports entry', function () {
  var idx = build({ 'live-one-iocs.json': {
    hunt_only_never_block: [{ value: 'api.telegram.org', category: 'messaging platform' }]
  } });
  assert.deepEqual(idx.coverage.empty, [], 'must not be treated as an empty, skipped feed');
  assert.ok(idx.reports['live-one'], 'the report entry must exist so never_block hits can name it');
});

test('a feed with neither ordinary nor never-block content is still counted as empty', function () {
  var idx = build({ 'live-one-iocs.json': { notes: ['nothing indicator-shaped here'] } });
  assert.deepEqual(idx.coverage.empty, ['live-one-iocs.json']);
});

test('a bare BLOCK caveat rating is excluded from the index role', function () {
  var idx = build({ 'live-one-iocs.json': { network_indicators: { ipv4: [
    { value: '198.51.100.1', action: 'BLOCK', false_positive_risk: 'low' }
  ] } } });
  assert.deepEqual(idx.indicators['ipv4:198.51.100.1'], [{ report: 'live-one' }]);
});

test('a rating-prefixed GENUINE caveat survives in the index role, not mistaken for a bare rating', function () {
  // 2026-09-17 second independent review: same narrowing and the same two reviewer-constructed
  // fixtures as test/ioc-table-extract.test.js's matching test, so the search index cannot
  // regress independently of the feed-page table.
  var idx = build({ 'live-one-iocs.json': { network_indicators: { ipv4: [{
    value: '203.0.113.10', action: 'BLOCK',
    notes: 'LOW confidence this is a shared victim VPS; notify victim before blocking'
  }] } } });
  assert.equal(idx.indicators['ipv4:203.0.113.10'][0].role,
    'LOW confidence this is a shared victim VPS; notify victim before blocking');
});
