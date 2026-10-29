'use strict';

/* The pilot feed's counts, pinned.

   Design v4 E7 and design v3 D8: the pilot's entry in `_data/ioc_tables.yml` held
   25 rows and 28 values it could not type, against the 41 indicator entries its
   report says the feed carries (report section 15: "2 full SHA-256 file hashes,
   9 address and port entries over the three operator servers, 4 URLs, 12 file
   paths, 1 mutex, 1 TLS certificate, 3 service fingerprints, 6 relay network
   signatures, 2 behavioural patterns and 1 operator host-name fingerprint").

   This file pins the repaired shape against the REAL feed rather than a fixture,
   because the defect was a property of this feed's own schema: filenames that look
   like domains, a certificate serial that looks like a sha1, nine address entries
   that differ only by port, and twelve prose entries with no value shape at all.
   A fixture reproducing four hand-picked cases would not have caught the four it
   did not think of.

   The denominator: the 41 entry objects in the feed's ten indicator containers
   (the ten the report names). `countEntries` below counts them from the file, so
   this test fails if the feed grows or shrinks rather than silently passing.

   Control: `AdvancedRouterScanner.json`'s entry is unchanged by this fix (see the
   report, tasks/runs/T-0500.1/build/p6-report.md). It is not asserted here
   because it is a corpus-wide property, not a unit of the extractor. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var X = require('../lib/ioc-table-extract.js');

var ROOT = path.join(__dirname, '..', '..', '..');
var SLUG = 'opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015';
var FEED = path.join(ROOT, 'ioc-feeds', SLUG + '-iocs.json');

/* The ten containers the report's own sentence counts, and nothing else. */
function countEntries(doc) {
  var n = 0;
  n += (doc.file_hashes.sha256 || []).length;
  n += (doc.network_indicators.ipv4 || []).length;
  n += (doc.network_indicators.urls || []).length;
  n += (doc.host_indicators.file_paths || []).length;
  n += (doc.host_indicators.mutex_names || []).length;
  n += (doc.tls_certificates || []).length;
  n += (doc.service_fingerprints || []).length;
  n += (doc.network_signatures || []).length;
  n += (doc.behavioral_indicators || []).length;
  n += (doc.operator_fingerprints || []).length;
  return n;
}

var doc = JSON.parse(fs.readFileSync(FEED, 'utf8'));
var summary = X.summarise(doc);

test('THE PILOT ENTRY CARRIES ONE ROW PER INDICATOR ENTRY THE FEED DECLARES, PLUS ITS TWO FILE NAMES AND TWO CERTIFICATE SERIALS', function () {
  assert.equal(countEntries(doc), 41,
    'the feed no longer declares 41 indicator entries; the count this test pins moved');
  /* 41 + the two `file_hashes.sha256[].filename` rows. A filename beside a hash is
     the common pivot (Rubeus, SweetPotato) where the hash is the exact-build pivot;
     the first review measured 179 such names absent from the whole table when the
     label rule suppressed them, and the lead restored the row. The denominator
     stays the feed's 41 entries; the two names are additional rows over it.
     + the certificate's `serial` and `earlier_serial` (fix round 2): serials are
     hunt pivots, so they are rows of their own typed `pattern`. */
  assert.equal(summary.rows.length, 45,
    'rows: ' + summary.rows.length + ' against ' + countEntries(doc) +
    ' feed entries + 2 filenames + 2 certificate serials');
});

test('no pilot row is untyped: every value the feed declares has a type', function () {
  assert.equal(summary.untyped, 0, 'untyped values left: ' + summary.untyped);
});

test('the type histogram is the report\'s own breakdown, measured', function () {
  var counts = {};
  summary.rows.forEach(function (r) { counts[r.type] = (counts[r.type] || 0) + 1; });
  assert.deepEqual(counts, {
    ipv4: 9,       // 3 hosts + 6 host:port entries
    url: 4,
    sha256: 3,     // 2 file hashes + the TLS certificate's fingerprint
    path: 12,
    filename: 2,   // dump2.sh and Relay.java.new, the two hash entries' names
    pattern: 15    // 3 service fingerprints, 6 network signatures, 2 behaviours,
                   // 1 mutex, 1 host-name fingerprint, + the 2 certificate serials
  });
});

test('a filename beside a hash keeps its own row, with the hash entry\'s confidence and action', function () {
  var names = summary.rows.filter(function (r) { return r.type === 'filename'; })
    .map(function (r) { return r.value; }).sort();
  /* Original case: neither name classifies as a filename in ioc-classify.js
     (`.new` is not in its extension list and `.sh` is deliberately left a domain
     there), so both keep the case the feed wrote. A name that DOES classify as a
     filename is lower-cased by the classifier and typed here with that value, so
     one file is never two rows (test/ioc-tables-fix1.test.js). */
  assert.deepEqual(names, ['Relay.java.new', 'dump2.sh']);
  /* ioc-classify lower-cases a filename, and this row takes that normalised value so
     one name is one row wherever it was typed (see the corpus test for the duplicate
     case this prevents). */
  names.forEach(function (n) {
    var row = summary.rows.filter(function (r) { return r.type === 'filename' && r.value === n; })[0];
    assert.equal(row.confidence, 'DEFINITE', n + ' lost the hash entry\'s confidence');
  });
});

test('a filename that looks like a domain is a filename, not a blockable domain', function () {
  // `dump2.sh` and `Relay.java.new` are the sha256 entries' `filename` fields; the
  // old shape rule read `label.label` as a domain.
  var domains = summary.rows.filter(function (r) { return r.type === 'domain'; });
  assert.deepEqual(domains, [], 'domains left in the pilot: ' +
    domains.map(function (r) { return r.value; }).join(', '));
});

test('\'Relay.java\' is a path from the file_paths container, not a domain', function () {
  var row = summary.rows.filter(function (r) { return r.value === 'Relay.java'; })[0];
  assert.ok(row, 'Relay.java is missing from the rows');
  assert.equal(row.type, 'path');
});

test('a certificate serial is a pattern row carrying its field label, never a sha1', function () {
  /* Fix round 2 (lead, 2026-10-29): a serial is a hunt pivot, so it keeps a row.
     It is NOT typed sha1: 40 hex is a shape, not the fact, and a serial pasted into
     a file-hash hunt can never match. `pattern` needs no new hue. The context names
     the field because the value itself is opaque. */
  var want = [
    { v: doc.tls_certificates[0].serial, ctx: 'TLS certificate serial' },
    { v: doc.tls_certificates[0].earlier_serial, ctx: 'earlier serial' }
  ];
  want.forEach(function (w) {
    var hit = summary.rows.filter(function (r) { return r.value === w.v; });
    assert.equal(hit.length, 1, 'the certificate serial ' + w.v + ' is not exactly one row');
    assert.equal(hit[0].type, 'pattern', 'a serial is not a sha1: ' + JSON.stringify(hit[0]));
    assert.equal(hit[0].context, w.ctx, 'the serial row lost its field label');
    assert.equal(hit[0].action, 'HUNT', 'the serial row lost the certificate entry\'s action');
  });
});

test('the certificate fingerprint row says it is one', function () {
  var v = doc.tls_certificates[0].sha256;
  var r = summary.rows.filter(function (row) { return row.value === v; })[0];
  assert.ok(r, 'the certificate fingerprint has no row');
  assert.equal(r.type, 'sha256');
  assert.equal(r.context, 'TLS certificate fingerprint');
});

test('the nine address entries survive as nine rows, port included', function () {
  var ips = summary.rows.filter(function (r) { return r.type === 'ipv4'; })
    .map(function (r) { return r.value; }).sort();
  assert.deepEqual(ips, ['209.99.185.148', '209.99.185.148:8080', '209.99.185.148:8146',
    '38.180.16.98', '38.180.16.98:53', '38.180.16.98:9090', '38.180.16.98:9443',
    '38.180.196.193', '38.180.196.193:8899']);
});

test('all thirteen prose-shape entries are rows, with the feed\'s own action and confidence', function () {
  var pat = summary.rows.filter(function (r) { return r.type === 'pattern'; });
  /* 13 prose entries plus the 2 certificate serials, which share the type. */
  assert.equal(pat.length, 15);
  assert.equal(pat.filter(function (r) { return r.confidence; }).length, 15,
    'a pattern row lost its confidence');
  assert.equal(pat.filter(function (r) { return r.action; }).length, 15,
    'a pattern row lost its action');
});

test('the observer note: the two file hashes have no action in the feed, so none is shown', function () {
  /* The report's IOC table marks the relay source "HUNT, BLOCK"; the feed's hash
     objects carry no `action` key at all (checked: keys are value, filename, type,
     confidence, description, false_positive_note). The table must not invent one,
     and this test records the gap so a later feed fix is visible here. */
  var hashes = summary.rows.filter(function (r) { return r.type === 'sha256'; });
  var fileHashes = hashes.filter(function (r) { return r.value.length === 64; });
  assert.equal(fileHashes.length, 3, 'expected 2 file hashes and the certificate hash');
  fileHashes.forEach(function (r) {
    var isCert = r.value === doc.tls_certificates[0].sha256;
    if (isCert) { assert.equal(r.action, 'HUNT'); return; }
    assert.equal(r.action, null, 'an action appeared for ' + r.value +
      ' -- if the feed was fixed, update this test and the report');
  });
});
