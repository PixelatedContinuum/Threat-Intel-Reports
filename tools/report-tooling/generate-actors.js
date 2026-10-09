#!/usr/bin/env node
'use strict';

/* Writes _data/actors_index.yml and one stub page per actor in _data/actors.yml,
   and REMOVES a stub whose designation is no longer in the data file or whose
   reports are no longer published. Same shape as generate-ioc-tables.js: the
   hand-written record is the input, the derived index and the pages are output,
   and check-actors.js gates both by regenerate-and-diff.

   Run after any change to _data/actors.yml, _data/catalog.yml, a report's
   ATT&CK table or a report's mentions of a designation.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var A, deps = null, depsReason = null, DETECTION_ATTACK = null;
try {
  A = require('./lib/actors.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}
try {
  var AC = require(path.join(A.ROOT, 'assets', 'js', 'attack-coverage.js'));
  var CAT = require('./lib/attack-catalog.js');
  deps = {
    JSDOM: require('jsdom').JSDOM,
    extractTables: require('./lib/extract-tables.js').extractTables,
    AC: AC,
    tacticOrder: AC.TACTIC_ORDER,
    compareId: CAT.compareId,
    catalog: CAT.load()
  };
} catch (e) {
  depsReason = e.message;
}

function existingStubs() {
  var out = {};
  var entries;
  try { entries = fs.readdirSync(A.ACTOR_DIR, { withFileTypes: true }); }
  catch (e) { return out; }
  entries.forEach(function (e) {
    if (!e.isDirectory()) return;
    var p = path.join(A.ACTOR_DIR, e.name, 'index.md');
    try {
      if (fs.readFileSync(p, 'utf8').indexOf(A.STUB_MARKER) > -1) out[e.name] = p;
    } catch (err) { /* not a stub */ }
  });
  return out;
}

function run(opts) {
  opts = opts || {};
  var empty = { tables: 0, yaml: null, stubs: [], removed: [], embargoed: [], actors: 0, techniques: 0 };
  if (depsReason) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'ATT&CK parsing is unavailable: ' + depsReason +
      '. Run `npm ci` in tools/report-tooling.', problems: [] }, empty);
  }
  var actorsText, catText, reports;
  try {
    actorsText = fs.readFileSync(A.ACTORS_FILE, 'utf8');
    catText = fs.readFileSync(A.CATALOG_FILE, 'utf8');
    reports = A.readReports(A.REPORT_DIR);
  } catch (e) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'could not read the corpus: ' + e.message, problems: [] }, empty);
  }
  if (!reports.length) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'no reports found under ' + A.REPORT_DIR, problems: [] }, empty);
  }
  var parsed = A.parseActors(actorsText);
  if (parsed.problems.length) {
    return Object.assign({ status: 'FAIL', reason: null, problems: parsed.problems }, empty);
  }
  var names = {};
  Object.keys(deps.catalog.byId).forEach(function (id) { names[id] = deps.catalog.byId[id].name; });
  var detectionAttack = {};
  try {
    detectionAttack = require('js-yaml').load(fs.readFileSync(path.join(A.ROOT, '_data', 'detection_attack.yml'), 'utf8')) || {};
  } catch (e) {
    return Object.assign({ status: 'NOT CHECKED', reason: '_data/detection_attack.yml could not be read: ' + e.message, problems: [] }, empty);
  }
  var index = A.build(parsed.actors, reports, A.parseCatalog(catText), {
    attack: function (body) { return A.attackFor(body, deps); },
    catalogNames: names,
    detectionAttack: detectionAttack,
    compareId: deps.compareId,
    tacticOrder: deps.tacticOrder
  });
  if (index.problems.length) {
    return Object.assign({ status: 'FAIL', reason: null, problems: index.problems }, empty);
  }

  var text = A.toYaml(index);
  var have = existingStubs();
  var wanted = {}, wrote = [], removed = [];
  parsed.actors.forEach(function (a) { wanted[a.id] = a; });

  if (!opts.dryRun) {
    fs.writeFileSync(A.INDEX_FILE, text, 'utf8');
    parsed.actors.forEach(function (a) {
      var dir = path.join(A.ACTOR_DIR, a.id);
      var p = path.join(dir, 'index.md');
      var body = A.stub(a);
      var cur = null;
      try { cur = fs.readFileSync(p, 'utf8'); } catch (e) { cur = null; }
      if (cur === body) return;
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(p, body, 'utf8');
      wrote.push(a.id);
    });
    Object.keys(have).forEach(function (s) {
      if (wanted[s]) return;
      fs.rmSync(path.dirname(have[s]), { recursive: true, force: true });
      removed.push(s);
    });
  } else {
    parsed.actors.forEach(function (a) {
      var p = path.join(A.ACTOR_DIR, a.id, 'index.md');
      var cur = null;
      try { cur = fs.readFileSync(p, 'utf8'); } catch (e) { cur = null; }
      if (cur !== A.stub(a)) wrote.push(a.id);
    });
    Object.keys(have).forEach(function (s) { if (!wanted[s]) removed.push(s); });
  }

  var techniques = index.entries.reduce(function (n, e) { return n + e.attack.length; }, 0);
  return {
    status: 'PASS', reason: null, problems: [],
    actors: index.entries.length, techniques: techniques, yaml: text,
    stubs: wrote, removed: removed, embargoed: index.embargoed
  };
}

module.exports = { run: run, existingStubs: existingStubs };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  console.log(r.status + '   ' + r.actors + ' actor pages, ' + r.techniques + ' technique rows' +
    (dry ? '   (dry run, nothing written)' : ''));
  if (r.embargoed && r.embargoed.length) {
    console.log('   absent on purpose (named only in unlisted reports): ' + r.embargoed.join(', '));
  }
  if (r.stubs && r.stubs.length) console.log('   stubs written: ' + r.stubs.join(', '));
  if (r.removed && r.removed.length) console.log('   stubs REMOVED (no longer in the data file): ' + r.removed.join(', '));
  r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(r.status === 'PASS' ? 0 : 1);
}
