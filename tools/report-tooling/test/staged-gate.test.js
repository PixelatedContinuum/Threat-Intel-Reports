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
  var p = SG.plan(['README.md', '_config.yml', 'assets/css/custom.scss']);
  assert.deepEqual(p.checks, []);
  assert.deepEqual(p.reports, []);
});

test('a detection edit routes to the manifest AND the ATT&CK-table gate', function () {
  // Both derive from the same markdown. The ATT&CK tables derive from the
  // manifest in turn, so an edit that moves one moves the other.
  var p = SG.plan(['hunting-detections/acme-detections.md']);
  assert.deepEqual(ids(p), ['actors', 'detection-attack', 'manifest', 'misp', 'xref']);
});

test('a DELETED detection file still routes to the manifest gate', function () {
  // A deletion makes the manifest stale exactly as an edit does. Filtering
  // deletions out of the staged list would skip the check that catches it.
  var p = SG.plan(['hunting-detections/gone-detections.md'], { existing: [] });
  assert.deepEqual(ids(p), ['actors', 'detection-attack', 'manifest', 'misp', 'xref']);
});

test('an IOC feed edit routes to the index, the viewer tables AND the safety gate',
  function () {
    // A feed edit is the only way an unblockable value reaches the published
    // product, so it always routes to the blocklist-safety check.
    var p = SG.plan(['ioc-feeds/acme-iocs.json']);
    assert.deepEqual(ids(p),
      ['embargo-artifacts', 'feed-attack', 'feed-hygiene', 'ioc-index', 'ioc-tables', 'xref']);
  });

test('a catalog edit routes to the index, the viewer tables AND the tag gate',
  function () {
    // Publication status gates the first two; the tag vocabulary gates the third,
    // because the catalog is the only place a retired spelling can come back.
    var p = SG.plan(['_data/catalog.yml']);
    assert.deepEqual(ids(p), ['actors', 'ioc-index', 'ioc-tables', 'misp', 'stix-manifest', 'tags', 'xref']);
  });

test('a vocabulary edit routes to the tag gate, not the catalog alone', function () {
  /* Retiring a spelling in _data/tags.yml is only true once every catalog entry
     still carrying it has moved. Routing on the catalog alone would let the
     vocabulary change land with the gate never asked. */
  assert.deepEqual(ids(SG.plan(['_data/tags.yml'])), ['tags']);
});

test('A REPORT EDIT ROUTES TO THE VIEWER TABLES, because front matter is half the signal',
  function () {
    // `unlisted: true` is the other half of the publication signal. A go-live that
    // flips only the front matter must still reach the gate that would notice.
    var p = SG.plan(['reports/acme/index.md'], { existing: ['reports/acme/index.md'] });
    assert.deepEqual(ids(p), ['actors', 'embargo-artifacts', 'ioc-tables', 'misp', 'xref']);
  });

test('a surviving viewer stub routes to its own gate', function () {
  var p = SG.plan(['ioc-feeds/acme/index.md'], { existing: ['ioc-feeds/acme/index.md'] });
  assert.deepEqual(ids(p), ['ioc-tables']);
});

test('staging a generated artifact by hand still gates it', function () {
  // Someone hand-editing the manifest or the index is the case the gate most
  // needs to catch, so the artifact triggers its own check.
  assert.deepEqual(ids(SG.plan(['_data/detection_manifests.yml'])),
    ['detection-attack', 'manifest']);
  assert.deepEqual(ids(SG.plan(['assets/data/ioc-index.json'])), ['ioc-index']);
  assert.deepEqual(ids(SG.plan(['_data/detection_attack.yml'])), ['detection-attack', 'xref']);
  // An ATT&CK version bump rewrites the catalog and nothing else. Without this
  // route the 57 generated tables would go stale with every gate still green.
  assert.deepEqual(ids(SG.plan(['tools/report-tooling/data/attack-techniques.tsv'])),
    ['actors', 'detection-attack', 'misp', 'xref']);
});

test('a wire data edit routes to the wire gate', function () {
  assert.deepEqual(ids(SG.plan(['_data/wire.yml'])), ['wire']);
});

test('a wire PAGE edit routes to the wire gate too', function () {
  /* check-wire.js reads wire/index.md as well as the data file, because the day
     filter is only correct while the page derives each row's day once. Routing
     on the data file alone would let an edit that re-derives it, or drops
     data-day, commit with the gate never running. */
  assert.deepEqual(ids(SG.plan(['wire/index.md'])), ['wire']);
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
  assert.deepEqual(ids(p), ['actors', 'detection-attack', 'manifest', 'misp', 'xref']);
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
  assert.deepEqual(ids(p),
    ['actors', 'detection-attack', 'embargo-artifacts', 'feed-attack', 'feed-hygiene', 'ioc-index',
     'ioc-tables', 'manifest', 'misp', 'stix-manifest', 'tags', 'wire', 'xref']);
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
  assert.deepEqual(ids(p), ['actors', 'detection-attack', 'manifest', 'misp', 'xref']);
});

/* --- STIX bundle safety trigger, 2026-09-14 ---------------------------------

   Not a CHECKS entry: the gate is a cross-repo Python script, executed in
   precommit.js the way checkVictimNaming runs its own. This only tests the
   ROUTING flag; the execution is proven end to end with a real git commit,
   not here (see returns/wire-the-gate.md). */

test('an ioc-feeds edit wants the bundle-safety gate', function () {
  var p = SG.plan(['ioc-feeds/acme-iocs.json']);
  assert.equal(p.wantBundleSafety, true);
});

test('a stix bundle edit wants the bundle-safety gate too, not either alone', function () {
  var p = SG.plan(['stix/acme.json']);
  assert.equal(p.wantBundleSafety, true);
  // stix/ also feeds the MISP feed and the STIX manifest (2026-10-09), and
  // nothing else: a bundle edit must not drag the viewer or picker gates in.
  assert.deepEqual(ids(p), ['misp', 'stix-manifest']);
});

test('a staged path that is neither ioc-feeds nor stix does not want it', function () {
  var p = SG.plan(['README.md', '_data/catalog.yml', 'reports/acme/index.md'],
                   { existing: ['reports/acme/index.md'] });
  assert.equal(p.wantBundleSafety, false);
});

test('a non-json file under stix/ does not want it, matching the other json-only routes', function () {
  var p = SG.plan(['stix/README.md']);
  assert.equal(p.wantBundleSafety, false);
});

test('a mixed commit still wants it exactly once, alongside everything else', function () {
  var p = SG.plan([
    'hunting-detections/a-detections.md',
    'ioc-feeds/a-iocs.json',
    'stix/a.json',
    '_data/wire.yml'
  ]);
  assert.equal(p.wantBundleSafety, true);
  assert.deepEqual(ids(p),
    ['actors', 'detection-attack', 'embargo-artifacts', 'feed-attack', 'feed-hygiene', 'ioc-index',
     'ioc-tables', 'manifest', 'misp', 'stix-manifest', 'wire', 'xref']);
});

test('the actor index routes on its record, its generated index, a stub page, its Navigator layer, the catalog, a report and a detection page', function () {
  // Every input the index derives from, plus its own outputs (the index, the
  // stub and the per-actor layer), so a bare designation added to a report
  // lands with its link rather than at the next campaign publish. A stylesheet
  // edit does not route here.
  ['_data/actors.yml', '_data/actors_index.yml', 'actors/UTA-2026-001/index.md',
   'actors/UTA-2026-001/attack-navigator-layer.json',
   '_data/catalog.yml', 'reports/acme/index.md', 'hunting-detections/acme-detections.md',
   'tools/report-tooling/data/attack-techniques.tsv'].forEach(function (path) {
    assert.ok(ids(SG.plan([path], { existing: [path] })).indexOf('actors') > -1, path);
  });
  assert.deepEqual(ids(SG.plan(['_data/actors.yml'])), ['actors', 'xref']);
  assert.deepEqual(ids(SG.plan(['actors/index.md', 'assets/css/custom.scss'])), []);
});

test('the technique and family pages route on the vocabulary, their generated indexes, a stub, the layer, a feed and every actor-index input', function () {
  // The cross-reference pages derive from everything the actor index does plus
  // the family vocabulary, the feeds and the generated detection tables, and
  // write stubs and the Navigator layer. Any of those staged routes here, so a
  // page never lists less than the site publishes. The two listing pages and a
  // stylesheet do not route here.
  ['_data/families.yml', '_data/attack_index.yml', '_data/family_index.yml',
   'techniques/T1059.001/index.md', 'families/xworm/index.md',
   'assets/data/attack-navigator-layer.json', '_data/detection_attack.yml',
   '_data/actors.yml', '_data/actors_index.yml', '_data/catalog.yml',
   'reports/acme/index.md', 'hunting-detections/acme-detections.md', 'ioc-feeds/acme-iocs.json',
   'tools/report-tooling/data/attack-techniques.tsv'].forEach(function (path) {
    assert.ok(ids(SG.plan([path], { existing: [path] })).indexOf('xref') > -1, path);
  });
  assert.deepEqual(ids(SG.plan(['_data/families.yml'])), ['xref']);
  assert.deepEqual(ids(SG.plan(['techniques/index.md', 'families/index.md', 'assets/js/heatmap-filter.js', 'assets/css/custom.scss'])), []);
});

test('the MISP feed routes on its own files, a STIX bundle, a detection page, a report, the catalog and the ATT&CK catalog; the STIX manifest on a bundle, the zip, itself and the catalog', function () {
  ['feeds/misp/manifest.json', 'feeds/misp/hashes.csv', 'feeds/misp/_state.json',
   'feeds/misp/1f43fcef-df62-50b8-8069-16415d068ed7.json', 'stix/acme.json', 'hunting-detections/acme-detections.md',
   'reports/acme/index.md', '_data/catalog.yml', 'tools/report-tooling/data/attack-techniques.tsv'].forEach(function (path) {
    assert.ok(ids(SG.plan([path], { existing: [path] })).indexOf('misp') > -1, path);
  });
  ['stix/acme.json', 'stix/hunters-ledger-stix-bundles.zip', 'stix/manifest.json', '_data/catalog.yml'].forEach(function (path) {
    assert.ok(ids(SG.plan([path], { existing: [path] })).indexOf('stix-manifest') > -1, path);
  });
  assert.deepEqual(ids(SG.plan(['feeds/misp/changelog.md'])), ['misp']);
  assert.deepEqual(ids(SG.plan(['feeds/suricata/changelog.md', 'stix/index.md', 'assets/css/custom.scss'])), []);
});

