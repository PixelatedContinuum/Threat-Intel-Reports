'use strict';

/* Tests for lib/download-targets.js.

   The browser half of the download check cannot be tested here. What can, and
   what has already been wrong once, is the choosing: which page gets driven, and
   whether the numbers taken off a downloaded bundle mean anything.

   Both failure modes are silent. A target with no strict subset makes a broken
   picker pass. A target under disclosure embargo makes a correct gate fail the
   day that campaign is pulled. Neither shows up in a green run. */

var test = require('node:test');
var assert = require('node:assert');
var T = require('../lib/download-targets.js');

/* ---- reading a bundle ---- */

test('YARA rules are counted by their rule declarations', function () {
  var bundle = 'import "pe"\n\nrule Alpha_One {\n  condition: true\n}\n\n' +
    'rule Beta_Two {\n  condition: false\n}\n';
  assert.equal(T.countRules('yara', bundle), 2);
});

test('a deduped import line is not counted as a rule', function () {
  assert.equal(T.countRules('yara', 'import "pe"\nimport "math"\n'), 0);
});

test('Sigma documents are counted by title', function () {
  assert.equal(T.countRules('sigma', 'title: One\nid: a\n---\ntitle: Two\nid: b\n'), 2);
});

test('Suricata rules are counted per line, ignoring comments and blanks', function () {
  var f = 'alert tcp any any -> any any (msg:"a"; sid:1;)\n' +
    '# a comment\n\n' +
    'alert tcp any any -> any any (msg:"b"; sid:2;)\n';
  assert.equal(T.countRules('suricata', f), 2);
});

test('an empty bundle counts zero rather than throwing', function () {
  assert.equal(T.countRules('yara', ''), 0);
  assert.equal(T.countRules('sigma', null), 0);
  assert.equal(T.countRules('suricata', undefined), 0);
});

/* ---- foreign engine detection ---- */

test('a clean YARA bundle reports no foreign engine', function () {
  assert.deepEqual(T.foreignEngineIn('yara', 'rule A {\n condition: true\n}\n'), []);
});

test('Sigma syntax inside a YARA bundle is caught', function () {
  var mixed = 'rule A {\n condition: true\n}\nlogsource:\n  product: windows\n';
  assert.deepEqual(T.foreignEngineIn('yara', mixed), ['sigma']);
});

test('Suricata syntax inside a Sigma bundle is caught', function () {
  var mixed = 'title: X\nlogsource:\n  product: windows\n' +
    'alert tcp any any -> any any (msg:"x"; sid:1;)\n';
  assert.deepEqual(T.foreignEngineIn('sigma', mixed), ['suricata']);
});

test('the word alert inside a rule body does not trip the suricata probe', function () {
  // The probe is anchored at line start and needs the protocol token after it,
  // so prose mentioning an alert cannot fire it.
  var yara = 'rule A {\n  strings:\n    $a = "send an alert to the operator"\n' +
    '  condition: $a\n}\n';
  assert.deepEqual(T.foreignEngineIn('yara', yara), []);
});

/* ---- picking a detection page ---- */

function manifest(over) {
  return Object.assign({
    'published-detections': [
      { name: 'y1', engine: 'yara', tier: 'Detection' },
      { name: 'y2', engine: 'yara', tier: 'Detection' },
      { name: 'y3', engine: 'yara', tier: 'Hunting' },
      { name: 's1', engine: 'sigma', tier: 'Detection' }
    ]
  }, over || {});
}
var CATALOG = [{ detection_url: '/hunting-detections/published-detections' }];

test('a listed page with two engines and a split tier is picked', function () {
  var p = T.pickDetections(manifest(), CATALOG);
  assert.equal(p.key, 'published-detections');
  assert.deepEqual(p.engines, ['sigma', 'yara']);
  assert.equal(p.pick.engine, 'yara');
  assert.equal(p.pick.tier, 'Hunting', 'the smaller tier makes the strictest subset');
  assert.equal(p.pick.subset, 1);
  assert.equal(p.pick.engineTotal, 3);
});

test('an EMBARGOED page is never picked, because the catalog does not list it', function () {
  /* The manifest is generated from every file in hunting-detections/, embargoed
     campaigns included; the catalog comments those out. The first run of this
     check reached for one. A gate leaning on a page that may be pulled fails for
     a reason that has nothing to do with the code. */
  var m = manifest({
    'embargoed-detections': [
      { name: 'y1', engine: 'yara', tier: 'Detection' },
      { name: 'y2', engine: 'yara', tier: 'Hunting' },
      { name: 'y3', engine: 'yara', tier: 'Hunting' },
      { name: 'y4', engine: 'yara', tier: 'Hunting' },
      { name: 's1', engine: 'sigma', tier: 'Detection' },
      { name: 's2', engine: 'sigma', tier: 'Hunting' }
    ]
  });
  // The embargoed one is larger, so it would win on size alone.
  var p = T.pickDetections(m, CATALOG);
  assert.equal(p.key, 'published-detections');
});

test('a page whose engine never splits across tiers is refused', function () {
  /* Without a strict subset, a download that ignored the tier filter would look
     exactly like a correct one, and the check would pass on a broken picker. */
  var m = {
    'flat-detections': [
      { name: 'y1', engine: 'yara', tier: 'Detection' },
      { name: 'y2', engine: 'yara', tier: 'Detection' },
      { name: 's1', engine: 'sigma', tier: 'Detection' }
    ]
  };
  assert.equal(T.pickDetections(m, [{ detection_url: '/hunting-detections/flat-detections' }]), null);
});

test('a single-engine page is refused', function () {
  var m = {
    'one-detections': [
      { name: 'y1', engine: 'yara', tier: 'Detection' },
      { name: 'y2', engine: 'yara', tier: 'Hunting' },
      { name: 'y3', engine: 'yara', tier: 'Hunting' }
    ]
  };
  assert.equal(T.pickDetections(m, [{ detection_url: '/hunting-detections/one-detections' }]), null);
});

test('an empty catalog picks nothing rather than falling back to the manifest', function () {
  assert.equal(T.pickDetections(manifest(), []), null);
});

test('a trailing slash on the catalog url still matches', function () {
  var p = T.pickDetections(manifest(),
    [{ detection_url: '/hunting-detections/published-detections/' }]);
  assert.ok(p, 'the url form must not decide whether a page is reachable');
});

test('a catalog passed as a bare ARRAY is read, not mistaken for its entries method', function () {
  /* The bug this pins: `(catalog && catalog.entries) || catalog` looks like a
     harmless way to accept either shape, but every Array carries an `entries`
     METHOD, so a bare array yields the function, Array.isArray on it is false,
     and the listed map silently stays empty. Nothing is ever picked and the
     whole check reports NOT CHECKED as though the corpus had nothing to offer.
     It survived because _data/catalog.yml is a mapping with an `entries:` key,
     so the working path was the one taken by accident. */
  var asArray = T.pickDetections(manifest(), CATALOG);
  var asMapping = T.pickDetections(manifest(), { entries: CATALOG });
  assert.ok(asArray, 'a bare array catalog must be read');
  assert.ok(asMapping, 'a mapping with entries must be read');
  assert.deepEqual(asArray, asMapping, 'both shapes must give the same answer');
});

test('a catalog of an unusable shape selects nothing rather than throwing', function () {
  assert.equal(T.pickDetections(manifest(), null), null);
  assert.equal(T.pickDetections(manifest(), { entries: 'not-a-list' }), null);
  assert.equal(T.pickDetections(manifest(), 42), null);
});

/* ---- picking a feed and a type ---- */

var TABLES = {
  'small.json': { slug: 'small', page_url: '/ioc-feeds/small/', total: 4,
                  counts: { ipv4: 3, sha256: 1 } },
  'big.json': { slug: 'big', page_url: '/ioc-feeds/big/', total: 100,
                counts: { ipv4: 60, sha256: 39, domain: 1 } },
  'onetype.json': { slug: 'one', page_url: '/ioc-feeds/one/', total: 50,
                    counts: { ipv4: 50 } }
};

test('the largest multi-type feed is picked', function () {
  var f = T.pickFeed(TABLES);
  assert.equal(f.slug, 'big');
});

test('a single-type feed is refused, since a type chip would not narrow anything', function () {
  assert.equal(T.pickFeed({ 'onetype.json': TABLES['onetype.json'] }), null);
});

test('a feed with no page_url is refused', function () {
  // Embargoed feeds are absent from ioc_tables.yml entirely; this covers a
  // malformed entry rather than an embargo.
  assert.equal(T.pickFeed({ 'x.json': { slug: 'x', total: 9, counts: { ipv4: 5, sha256: 4 } } }), null);
});

test('the picked type is the LARGEST that is still a strict subset', function () {
  /* The smallest type gives the strictest narrowing but is usually one row, and
     a one-row export would look plausible even from a filter that did nothing. */
  assert.equal(T.pickType(T.pickFeed(TABLES)), 'ipv4');
});

test('a type covering the whole feed is never picked as the filter', function () {
  var f = { types: ['ipv4', 'sha256'], total: 50, counts: { ipv4: 50, sha256: 0 } };
  assert.notEqual(T.pickType(f), 'ipv4');
});
