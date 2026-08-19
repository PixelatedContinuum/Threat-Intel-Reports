#!/usr/bin/env node
'use strict';

/* Gates _data/ioc_tables.yml AND the stub pages against ioc-feeds/ + the catalog.

   Regenerate-and-diff, the same approach check-ioc-index.js and
   check-detection-manifest.js use: if rebuilding changes it, what is committed
   is stale.

   This generator writes TWO things, so both are checked. A manifest that matches
   while a stub is missing serves a 404 from a listing card; a stub that survives
   after its campaign went back under embargo serves a rendered page for content
   that is supposed to be off every listing. The second is the one that matters.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var OUT = path.join(ROOT, '_data', 'ioc_tables.yml');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');

var GEN, CDM;
try {
  GEN = require('./generate-ioc-tables.js');
  CDM = require('./lib/check-detection-manifest.js');   // shared normalise + diff
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var gen;
try { gen = GEN.run({ dryRun: true }); }
catch (e) {
  console.log('NOT CHECKED  could not rebuild the tables for comparison: ' + e.message);
  process.exit(2);
}

if (gen.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + gen.reason); process.exit(2); }

var problems = gen.problems.slice();

if (gen.status !== 'FAIL') {
  if (!gen.tables) {
    console.log('NOT CHECKED  the generator produced 0 tables, so this run verified nothing.');
    process.exit(2);
  }

  var committed = null;
  try { committed = fs.readFileSync(OUT, 'utf8'); } catch (e) { committed = null; }
  if (committed === null) {
    console.log('NOT CHECKED  _data/ioc_tables.yml is absent or unreadable. ' +
      'Run `node generate-ioc-tables.js`.');
    process.exit(2);
  }

  var a = CDM.normalise(committed), b = CDM.normalise(gen.yaml);
  if (a !== b) {
    var d = CDM.firstDivergence(a, b);
    problems.push('_data/ioc_tables.yml is stale against ioc-feeds/: ' +
      (d ? 'first differs at line ' + d.line + ' (committed ' + d.committedLines +
           ' lines, regenerated ' + d.freshLines + ')' : 'differs in length only') +
      '. Run `node generate-ioc-tables.js` and stage the result.');
  }

  /* The dry run reports which stubs it WOULD write and which it WOULD remove.
     Either being non-empty means what is on disk does not match what is
     published. The removals are the safety-relevant half. */
  (gen.stubs || []).forEach(function (s) {
    problems.push('missing stub page for "' + s + '": a listing card would 404. ' +
      'Run `node generate-ioc-tables.js`.');
  });
  (gen.removed || []).forEach(function (s) {
    problems.push('DISCLOSURE: a stub page for "' + s + '" is still on disk but the feed ' +
      'is no longer published. Run `node generate-ioc-tables.js` to remove it.');
  });
}

if (problems.length) {
  console.log('FAIL  ' + OUT);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(1);
}

console.log('PASS  ' + OUT);
console.log('   note  ' + gen.tables + ' feed pages, ' + gen.rows + ' indicators');
if (gen.skipped) {
  console.log('   note  skipped ' + gen.skipped.embargoed + ' embargoed, ' +
    gen.skipped.unknown + ' unknown, ' + gen.skipped.empty + ' with nothing typed');
}
process.exit(0);
