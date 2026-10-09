#!/usr/bin/env node
'use strict';

/* Gates stix/manifest.json by regenerate-and-diff: a bundle re-written without
   the manifest following it would hand a poller a stale hash, which is the one
   thing the manifest exists to prevent.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var GEN;
try { GEN = require('./generate-stix-manifest.js'); }
catch (e) { console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.'); process.exit(2); }

var gen = GEN.run({ dryRun: true });
if (gen.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + gen.reason); process.exit(2); }
var problems = gen.problems.slice();
if (gen.status !== 'FAIL') {
  var cur = null;
  try { cur = fs.readFileSync(GEN.MANIFEST, 'utf8'); } catch (e) { cur = null; }
  if (cur === null) { console.log('NOT CHECKED  stix/manifest.json is absent. Run `node generate-stix-manifest.js`.'); process.exit(2); }
  if (cur !== gen.text) problems.push('stix/manifest.json is stale against the bundles, the zip or the catalog. Run `node generate-stix-manifest.js`.');
}
if (problems.length) {
  console.log('FAIL  ' + GEN.MANIFEST);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(1);
}
console.log('PASS  ' + GEN.MANIFEST);
console.log('   note  ' + gen.count + ' bundles');
process.exit(0);
