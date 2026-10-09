#!/usr/bin/env node
'use strict';

/* Gates the threat actor index: _data/actors_index.yml and the stub pages
   against _data/actors.yml, the catalog and the reports, by regenerate-and-diff
   (the approach check-ioc-tables.js and check-detection-manifest.js use), and
   the reports against the index: a bare designation that has a page but is not
   linked to it is a FAIL, because `node link-actors.js` fixes it in one step
   and an unlinked mention is the defect this feature exists to remove.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var A, GEN, CDM, L;
try {
  A = require('./lib/actors.js');
  GEN = require('./generate-actors.js');
  CDM = require('./lib/check-detection-manifest.js');   // shared normalise + diff
  L = require('./link-actors.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var gen;
try { gen = GEN.run({ dryRun: true }); }
catch (e) {
  console.log('NOT CHECKED  could not rebuild the index for comparison: ' + e.message);
  process.exit(2);
}
if (gen.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + gen.reason); process.exit(2); }

var problems = gen.problems.slice();

if (gen.status !== 'FAIL') {
  if (!gen.actors) {
    console.log('NOT CHECKED  the generator produced 0 actor pages, so this run verified nothing.');
    process.exit(2);
  }
  var committed = null;
  try { committed = fs.readFileSync(A.INDEX_FILE, 'utf8'); } catch (e) { committed = null; }
  if (committed === null) {
    console.log('NOT CHECKED  _data/actors_index.yml is absent or unreadable. Run `node generate-actors.js`.');
    process.exit(2);
  }
  var a = CDM.normalise(committed), b = CDM.normalise(gen.yaml);
  if (a !== b) {
    var d = CDM.firstDivergence(a, b);
    problems.push('_data/actors_index.yml is stale against the reports and the catalog: ' +
      (d ? 'first differs at line ' + d.line + ' (committed ' + d.committedLines +
           ' lines, regenerated ' + d.freshLines + ')' : 'differs in length only') +
      '. Run `node generate-actors.js` and stage the result.');
  }
  (gen.stubs || []).forEach(function (s) {
    problems.push('actor page for ' + s + ' is missing or stale: a link to it would 404 or ' +
      'render the wrong page. Run `node generate-actors.js`.');
  });
  (gen.removed || []).forEach(function (s) {
    problems.push('DISCLOSURE: a page for ' + s + ' is still on disk but the designation is no ' +
      'longer in _data/actors.yml. Run `node generate-actors.js` to remove it.');
  });

  var links = L.run({ dryRun: true });
  if (links.status === 'NOT CHECKED') {
    console.log('NOT CHECKED  ' + links.reason);
    process.exit(2);
  }
  links.files.forEach(function (f) {
    if (!f.count) return;
    problems.push(f.count + ' bare mention(s) of a designation with a page in ' + f.path +
      '. Run `node link-actors.js` to link them.');
  });
}

if (problems.length) {
  console.log('FAIL  ' + A.INDEX_FILE);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(1);
}

console.log('PASS  ' + A.INDEX_FILE);
console.log('   note  ' + gen.actors + ' actor pages, ' + gen.techniques + ' technique rows');
if (gen.embargoed && gen.embargoed.length) {
  console.log('   note  absent on purpose (named only in unlisted reports): ' + gen.embargoed.join(', '));
}
process.exit(0);
