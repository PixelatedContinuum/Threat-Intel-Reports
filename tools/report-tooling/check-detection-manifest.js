#!/usr/bin/env node
'use strict';

/* Gates _data/detection_manifests.yml against hunting-detections/.

   Exit codes match the rest of the tooling: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..');
var OUT = path.join(ROOT, '_data', 'detection_manifests.yml');

var CK, GEN;
try {
  CK = require('./lib/check-detection-manifest.js');
  GEN = require('./generate-detection-manifests.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var committed = null;
try { committed = fs.readFileSync(OUT, 'utf8'); } catch (e) { committed = null; }

var gen;
try {
  gen = GEN.run({ dryRun: true });
} catch (e) {
  console.log('NOT CHECKED  could not rebuild the manifest for comparison: ' + e.message);
  process.exit(2);
}

var r = CK.check(committed, gen);
if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }

console.log(r.status + '  ' + OUT);
r.notes.forEach(function (n) { console.log('   note  ' + n); });
r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
process.exit(r.status === 'PASS' ? 0 : 1);
