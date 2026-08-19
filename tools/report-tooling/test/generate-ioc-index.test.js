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
  network_indicators: { ips: ['185.38.150.7:9999'], domains: ['Bot.Example.COM'] },
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
  assert.ok(idx.indicators['domain:bot.example.com'], 'domain lowercased');
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
