'use strict';

/* Routing for the pre-commit machinery gate.

   The hook exists for edits that never invoke the publish skill: a detection-tiering
   backfill, a redaction sweep, a bulk correction across published feeds. Those bypass
   Steps 1a-1f entirely, so nothing regenerates the artifacts they invalidate.

   Routing on staged paths keeps the hook proportional. A commit touching only prose
   runs nothing, and says so rather than staying silent. */

var test = require('node:test');
var assert = require('node:assert');
var SG = require('../lib/staged-gate.js');

function ids(p) { return p.checks.map(function (c) { return c.id; }).sort(); }

test('a commit staging nothing relevant runs no checks', function () {
  var p = SG.plan(['README.md', '_config.yml', 'assets/css/custom.css']);
  assert.deepEqual(p.checks, []);
  assert.deepEqual(p.reports, []);
});

test('a detection edit routes to the manifest gate', function () {
  var p = SG.plan(['hunting-detections/acme-detections.md']);
  assert.deepEqual(ids(p), ['manifest']);
});

test('a DELETED detection file still routes to the manifest gate', function () {
  // A deletion makes the manifest stale exactly as an edit does. Filtering
  // deletions out of the staged list would skip the check that catches it.
  var p = SG.plan(['hunting-detections/gone-detections.md'], { existing: [] });
  assert.deepEqual(ids(p), ['manifest']);
});

test('an IOC feed edit routes to the index, the viewer tables AND the safety gate',
  function () {
    // A feed edit is the only way an unblockable value reaches the published
    // product, so it always routes to the blocklist-safety check.
    var p = SG.plan(['ioc-feeds/acme-iocs.json']);
    assert.deepEqual(ids(p), ['feed-hygiene', 'ioc-index', 'ioc-tables']);
  });

test('a catalog edit routes to both, because publication status gates both',
  function () {
    var p = SG.plan(['_data/catalog.yml']);
    assert.deepEqual(ids(p), ['ioc-index', 'ioc-tables']);
  });

test('A REPORT EDIT ROUTES TO THE VIEWER TABLES, because front matter is half the signal',
  function () {
    // `unlisted: true` is the other half of the publication signal. A go-live that
    // flips only the front matter must still reach the gate that would notice.
    var p = SG.plan(['reports/acme/index.md'], { existing: ['reports/acme/index.md'] });
    assert.deepEqual(ids(p), ['ioc-tables']);
  });

test('a surviving viewer stub routes to its own gate', function () {
  var p = SG.plan(['ioc-feeds/acme/index.md'], { existing: ['ioc-feeds/acme/index.md'] });
  assert.deepEqual(ids(p), ['ioc-tables']);
});

test('staging a generated artifact by hand still gates it', function () {
  // Someone hand-editing the manifest or the index is the case the gate most
  // needs to catch, so the artifact triggers its own check.
  assert.deepEqual(ids(SG.plan(['_data/detection_manifests.yml'])), ['manifest']);
  assert.deepEqual(ids(SG.plan(['assets/data/ioc-index.json'])), ['ioc-index']);
});

test('a wire data edit routes to the wire gate', function () {
  assert.deepEqual(ids(SG.plan(['_data/wire.yml'])), ['wire']);
});

test('a report edit routes to that report only, not the corpus', function () {
  var p = SG.plan(['reports/acme/index.md'], { existing: ['reports/acme/index.md'] });
  assert.deepEqual(p.reports, ['reports/acme/index.md']);
});

test('a DELETED report is not checked, because there is no file to read', function () {
  var p = SG.plan(['reports/gone/index.md'], { existing: [] });
  assert.deepEqual(p.reports, []);
});

test('a figure inside a report directory routes nothing at all', function () {
  var p = SG.plan(['reports/acme/fig-2.png'], { existing: ['reports/acme/fig-2.png'] });
  assert.deepEqual(ids(p), []);
  assert.deepEqual(p.reports, []);
});

test('a glossary edit produces an owed-sweep notice, never a check', function () {
  // The render side needs published HTML, which does not exist at commit time.
  // Claiming a check here would be the vacuous pass this repo has shipped twice.
  var p = SG.plan(['_data/glossary.yml']);
  assert.deepEqual(p.checks, []);
  assert.equal(p.owed.length, 1);
  assert.match(p.owed[0], /glossary/i);
  assert.match(p.owed[0], /npm run verify/);
});

test('one check is queued once however many files trigger it', function () {
  var p = SG.plan([
    'hunting-detections/a-detections.md',
    'hunting-detections/b-detections.md',
    'hunting-detections/c-detections.md'
  ]);
  assert.deepEqual(ids(p), ['manifest']);
});

test('a mixed commit queues every check it touches, deduplicated', function () {
  var p = SG.plan([
    'hunting-detections/a-detections.md',
    'ioc-feeds/a-iocs.json',
    '_data/catalog.yml',
    '_data/wire.yml',
    '_data/glossary.yml',
    'reports/one/index.md',
    'reports/two/index.md',
    'README.md'
  ], { existing: ['reports/one/index.md', 'reports/two/index.md'] });
  assert.deepEqual(ids(p), ['feed-hygiene', 'ioc-index', 'ioc-tables', 'manifest', 'wire']);
  assert.deepEqual(p.reports.sort(), ['reports/one/index.md', 'reports/two/index.md']);
  assert.equal(p.owed.length, 1);
});

test('every queued check carries the reason it was queued, for the hook output', function () {
  var p = SG.plan(['hunting-detections/acme-detections.md']);
  assert.match(p.checks[0].why, /hunting-detections/);
  assert.ok(p.checks[0].label);
});

test('backslash paths are accepted, since git on Windows can hand them over', function () {
  var p = SG.plan(['hunting-detections\\acme-detections.md']);
  assert.deepEqual(ids(p), ['manifest']);
});
