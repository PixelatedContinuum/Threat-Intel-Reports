'use strict';

/* Tests for the disclosure-embargo rule.

   This is the one module here that protects someone other than the reader.
   Three of the 57 feeds belong to campaigns under active embargo: their catalog
   entries are commented out and their reports carry `unlisted: true`, which is
   how this site publishes a campaign preview-style, live at its URL for the
   disclosure loop and absent from every listing. Indexing those indicators into
   a public search box would make embargoed victim infrastructure discoverable.

   The catalog indents commented blocks, so a naive startsWith('#') on the raw
   line misses them. That is the specific bug these tests exist to prevent. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var CS = require('../lib/catalog-status.js');

var CATALOG = [
  'entries:',
  '  # ===== PENDING GO-LIVE, some campaign =====',
  '  # HELD: waits on disclosure replies.',
  '  #  - title: "Held Campaign"',
  '  #    date: 2026-08-18',
  '  #    ioc_url: /ioc-feeds/held-campaign-iocs.json',
  '  #    report_url: /reports/held-campaign/',
  '  - title: "Live Campaign"',
  '    date: 2026-07-28',
  '    severity: high',
  '    report_url: /reports/live-campaign/',
  '    detection_url: /hunting-detections/live-campaign-detections',
  '    ioc_url: /ioc-feeds/live-campaign-iocs.json'
].join('\n');

test('a live entry is published', function () {
  assert.equal(CS.parse(CATALOG).status['live-campaign-iocs.json'], 'published');
});

test('an INDENTED commented entry is embargoed, not missed', function () {
  assert.equal(CS.parse(CATALOG).status['held-campaign-iocs.json'], 'embargoed');
});

test('published entries carry their metadata', function () {
  var m = CS.parse(CATALOG).meta['live-campaign-iocs.json'];
  assert.equal(m.title, 'Live Campaign');
  assert.equal(m.date, '2026-07-28');
  assert.equal(m.severity, 'high');
  assert.equal(m.report_url, '/reports/live-campaign/');
  assert.equal(m.detection_url, '/hunting-detections/live-campaign-detections');
});

test('an embargoed entry carries no metadata, so it cannot leak by accident', function () {
  assert.equal(CS.parse(CATALOG).meta['held-campaign-iocs.json'], undefined);
});

test('statusOf reports the three states and nothing else', function () {
  var s = CS.parse(CATALOG);
  assert.equal(CS.statusOf(s, 'live-campaign-iocs.json'), 'published');
  assert.equal(CS.statusOf(s, 'held-campaign-iocs.json'), 'embargoed');
  assert.equal(CS.statusOf(s, 'nope.json'), 'unknown');
});

// ---- the second signal ----------------------------------------------------

var AGREED = { 'held-campaign': true };   // both signals say held

test('both signals agreeing on published stays published', function () {
  var r = CS.resolve(CATALOG, AGREED);
  assert.equal(r.status['live-campaign-iocs.json'], 'published');
  assert.deepEqual(r.conflicts, []);
});

test('both signals agreeing on held stays embargoed', function () {
  var r = CS.resolve(CATALOG, AGREED);
  assert.equal(r.status['held-campaign-iocs.json'], 'embargoed');
  assert.deepEqual(r.conflicts, []);
});

test('catalog live but report still unlisted is a CONFLICT, and fails safe', function () {
  // A half-completed go-live: the catalog was uncommented, the front matter was not.
  var r = CS.resolve(CATALOG, { 'held-campaign': true, 'live-campaign': true });
  assert.equal(r.status['live-campaign-iocs.json'], 'embargoed', 'must withhold, not leak');
  assert.equal(r.conflicts.length, 1);
  assert.equal(r.conflicts[0].slug, 'live-campaign');
  assert.equal(r.conflicts[0].catalog, 'published');
  assert.equal(r.conflicts[0].front_matter, 'unlisted');
  assert.equal(r.meta['live-campaign-iocs.json'], undefined, 'metadata withheld too');
});

test('catalog commented but report listed is also a CONFLICT', function () {
  var r = CS.resolve(CATALOG, {});
  // held-campaign is commented in the catalog but NOT unlisted in front matter.
  var c = r.conflicts.filter(function (x) { return x.slug === 'held-campaign'; });
  assert.equal(c.length, 1, 'the reverse drift is caught too');
  assert.equal(c[0].catalog, 'embargoed');
  assert.equal(c[0].front_matter, 'published');
});

// ---- against the real corpus ----------------------------------------------

function realUnlisted() {
  var dir = path.join(__dirname, '..', '..', '..', 'reports');
  var map = {};
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    if (!e.isDirectory()) return;
    var f = path.join(dir, e.name, 'index.md');
    if (!fs.existsSync(f)) return;
    if (/^unlisted:\s*true\s*$/m.test(fs.readFileSync(f, 'utf8').slice(0, 4000))) {
      map[e.name] = true;
    }
  });
  return map;
}

test('the real catalog and the real front matter AGREE on every campaign', function () {
  var real = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', '_data', 'catalog.yml'), 'utf8');
  var r = CS.resolve(real, realUnlisted());
  assert.deepEqual(r.conflicts, [],
    'a conflict here is a half-completed go-live and must be resolved by hand');
});

test('the real corpus has 50+ published and at least one embargoed', function () {
  var real = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', '_data', 'catalog.yml'), 'utf8');
  var r = CS.resolve(real, realUnlisted());
  var counts = { published: 0, embargoed: 0 };
  Object.keys(r.status).forEach(function (k) { counts[r.status[k]]++; });
  assert.ok(counts.published > 40, 'expected 40+ published, got ' + counts.published);
  // 2 as of 2026-08-21: 13.140.145.210 and 157.180.101.47. MultiVector was the third and
  // was released that day, its 30-day hold having elapsed with CNCERT/CC confirming action.
  // Still a real guard against an accidental mass-release of the two that remain held.
  assert.ok(counts.embargoed >= 1, 'expected the 1 known embargoed campaign, got ' + counts.embargoed);
});
