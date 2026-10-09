#!/usr/bin/env node
'use strict';

/* Gates the cross-reference pages: _data/attack_index.yml, _data/family_index.yml,
   the Navigator layer and the stub pages under techniques/ and families/
   against the reports, detection pages, feeds, catalog, actors and the family
   vocabulary, by regenerate-and-diff (as check-actors.js does). A stale index
   means a technique or family page lists less than the site publishes, or
   links to a page that no longer exists.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');

var X, GEN, CDM;
try {
  X = require('./lib/xref.js');
  GEN = require('./generate-xref.js');
  CDM = require('./lib/check-detection-manifest.js');   // shared normalise + diff
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

function compare(file, fresh, label) {
  var committed = null;
  try { committed = fs.readFileSync(file, 'utf8'); } catch (e) { committed = null; }
  if (committed === null) {
    console.log('NOT CHECKED  ' + label + ' is absent or unreadable. Run `node generate-xref.js`.');
    process.exit(2);
  }
  var a = CDM.normalise(committed), b = CDM.normalise(fresh);
  if (a !== b) {
    var d = CDM.firstDivergence(a, b);
    problems.push(label + ' is stale against the corpus: ' +
      (d ? 'first differs at line ' + d.line + ' (committed ' + d.committedLines +
           ' lines, regenerated ' + d.freshLines + ')' : 'differs in length only') +
      '. Run `node generate-xref.js` and stage the result.');
  }
}

if (gen.status !== 'FAIL') {
  if (!gen.techniques) {
    console.log('NOT CHECKED  the generator produced 0 technique pages, so this run verified nothing.');
    process.exit(2);
  }
  compare(X.ATTACK_INDEX, gen.attackYaml, '_data/attack_index.yml');
  compare(X.FAMILY_INDEX, gen.familyYaml, '_data/family_index.yml');
  compare(X.LAYER_FILE, gen.layerJson, 'assets/data/attack-navigator-layer.json');
  gen.stubs.forEach(function (s) {
    problems.push('page ' + s + ' is missing or stale: a link to it would 404 or render the wrong page. ' +
      'Run `node generate-xref.js`.');
  });
  gen.removed.forEach(function (s) {
    problems.push('page ' + s + ' is still on disk but nothing indexes it any more. ' +
      'Run `node generate-xref.js` to remove it.');
  });
}

if (problems.length) {
  console.log('FAIL  ' + X.ATTACK_INDEX);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(1);
}

console.log('PASS  ' + X.ATTACK_INDEX);
console.log('   note  ' + gen.techniques + ' technique pages, ' + gen.families + ' family pages');
if (gen.unresolved.length) {
  console.log('   note  ' + gen.unresolved.length + ' technique id(s) not in the ATT&CK catalog carry no page: ' +
    gen.unresolved.map(function (u) { return u.id; }).join(', '));
}
if (gen.unmapped.length) {
  console.log('   note  ' + gen.unmapped.length + ' family label(s) outside _data/families.yml carry no page (named in _data/family_index.yml)');
}
process.exit(0);
