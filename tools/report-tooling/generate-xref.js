#!/usr/bin/env node
'use strict';

/* Writes the cross-reference pages: _data/attack_index.yml and one stub page
   per ATT&CK technique under techniques/, _data/family_index.yml and one stub
   per family in _data/families.yml under families/, and the site-wide
   Navigator layer at assets/data/attack-navigator-layer.json. A stub whose
   technique or family is no longer indexed is REMOVED. Same shape as
   generate-actors.js: the inputs are files the site already gates, the index
   and the pages are output, and check-xref.js gates both by regenerate-and-diff.

   Run after any change to a report's ATT&CK table, a detection page, an IOC
   feed, _data/catalog.yml, _data/actors.yml, _data/families.yml or the ATT&CK
   catalog TSV.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var X, A, yaml, deps = null, depsReason = null;
try {
  X = require('./lib/xref.js');
  A = require('./lib/actors.js');
  yaml = require('js-yaml');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}
try {
  var AC = require(path.join(X.ROOT, 'assets', 'js', 'attack-coverage.js'));
  var CAT = require('./lib/attack-catalog.js');
  deps = {
    JSDOM: require('jsdom').JSDOM,
    extractTables: require('./lib/extract-tables.js').extractTables,
    AC: AC,
    tacticOrder: AC.TACTIC_ORDER,
    tacticSlug: AC.tacticSlug,
    compareId: CAT.compareId,
    catalog: CAT.load()
  };
} catch (e) {
  depsReason = e.message;
}

var SITE = 'https://the-hunters-ledger.com';
var FEED_DIR = path.join(X.ROOT, 'ioc-feeds');

/* The report strip's parser, keeping the confidence column the actor index
   drops: a technique page shows each report's own confidence for the mapping. */
function attackFor(body) {
  var html = deps.extractTables(body).join('\n');
  var doc = new deps.JSDOM('<body>' + html + '</body>').window.document;
  var tables = doc.querySelectorAll('table');
  var out = [];
  for (var i = 0; i < tables.length; i++) {
    var p = deps.AC.parseTable(tables[i]);
    p.techniques.forEach(function (t) {
      out.push({ id: t.id, tactic: t.tactic, name: t.name || '', confidence: t.confidence || null });
    });
  }
  return out;
}

function existingStubs(dir, marker) {
  var out = {};
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (e) { return out; }
  entries.forEach(function (e) {
    if (!e.isDirectory()) return;
    var p = path.join(dir, e.name, 'index.md');
    try {
      if (fs.readFileSync(p, 'utf8').indexOf(marker) > -1) out[e.name] = p;
    } catch (err) { /* not a stub */ }
  });
  return out;
}

/* Write each wanted stub whose text differs, remove each stub no longer
   wanted; in a dry run only report what would change. */
function syncStubs(dir, marker, wanted, dryRun) {
  var have = existingStubs(dir, marker);
  var wrote = [], removed = [];
  Object.keys(wanted).forEach(function (key) {
    var p = path.join(dir, key, 'index.md');
    var cur = null;
    try { cur = fs.readFileSync(p, 'utf8'); } catch (e) { cur = null; }
    if (cur === wanted[key]) return;
    if (!dryRun) {
      fs.mkdirSync(path.join(dir, key), { recursive: true });
      fs.writeFileSync(p, wanted[key], 'utf8');
    }
    wrote.push(key);
  });
  Object.keys(have).forEach(function (key) {
    if (wanted[key]) return;
    if (!dryRun) fs.rmSync(path.dirname(have[key]), { recursive: true, force: true });
    removed.push(key);
  });
  return { wrote: wrote, removed: removed };
}

function run(opts) {
  opts = opts || {};
  var empty = { attackYaml: null, familyYaml: null, layerJson: null, techniques: 0, families: 0,
    stubs: [], removed: [], unresolved: [], unmapped: [], problems: [] };
  if (depsReason) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'ATT&CK parsing is unavailable: ' + depsReason +
      '. Run `npm ci` in tools/report-tooling.' }, empty);
  }
  var famText, actorsText, catText, reports, detectionAttack, actorsIndex, detectionFamilies, feedFamilies;
  try {
    famText = fs.readFileSync(X.FAMILIES_FILE, 'utf8');
    actorsText = fs.readFileSync(A.ACTORS_FILE, 'utf8');
    catText = fs.readFileSync(A.CATALOG_FILE, 'utf8');
    reports = A.readReports(A.REPORT_DIR);
    detectionAttack = yaml.load(fs.readFileSync(X.DETECTION_ATTACK, 'utf8')) || {};
    actorsIndex = yaml.load(fs.readFileSync(X.ACTORS_INDEX, 'utf8')) || {};
    detectionFamilies = X.readDetectionFamilies(A.DETECTION_DIR);
    feedFamilies = X.readFeedFamilies(FEED_DIR);
  } catch (e) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'could not read the corpus: ' + e.message }, empty);
  }
  if (!reports.length) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'no reports found under ' + A.REPORT_DIR }, empty);
  }
  var fams = X.parseFamilies(famText);
  var actors = A.parseActors(actorsText);
  var problems = fams.problems.concat(actors.problems);
  if (problems.length) return Object.assign({ status: 'FAIL', reason: null }, empty, { problems: problems });

  var catalogByUrl = A.parseCatalog(catText);
  var attack = X.buildAttack(reports, catalogByUrl, detectionAttack, actorsIndex, {
    attack: attackFor, catalog: deps.catalog, tacticOrder: deps.tacticOrder,
    tacticSlug: deps.tacticSlug, compareId: deps.compareId
  });
  var families = X.buildFamilies(fams.families, detectionFamilies, feedFamilies, catalogByUrl, actors.actors);
  problems = attack.problems.concat(families.problems);
  if (problems.length) return Object.assign({ status: 'FAIL', reason: null }, empty, { problems: problems });
  if (!attack.techniques.length) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'no published report or detection page maps a technique, so there is nothing to index' }, empty);
  }

  var attackYaml = X.toYamlAttack(attack);
  var familyYaml = X.toYamlFamilies(families);
  var layer = X.navigatorLayer(attack, { site: SITE, tacticSlug: deps.tacticSlug });
  var layerJson = JSON.stringify(layer, null, 2) + '\n';

  var wantT = {}, wantF = {};
  attack.techniques.forEach(function (t) { wantT[t.id] = X.stubTechnique(t); });
  families.families.forEach(function (f) { wantF[f.slug] = X.stubFamily(f); });

  if (!opts.dryRun) {
    fs.writeFileSync(X.ATTACK_INDEX, attackYaml, 'utf8');
    fs.writeFileSync(X.FAMILY_INDEX, familyYaml, 'utf8');
    fs.mkdirSync(path.dirname(X.LAYER_FILE), { recursive: true });
    fs.writeFileSync(X.LAYER_FILE, layerJson, 'utf8');
  }
  var t = syncStubs(X.TECHNIQUE_DIR, X.TECHNIQUE_MARKER, wantT, !!opts.dryRun);
  var f = syncStubs(X.FAMILY_DIR, X.FAMILY_MARKER, wantF, !!opts.dryRun);

  return {
    status: 'PASS', reason: null, problems: [],
    attackYaml: attackYaml, familyYaml: familyYaml, layerJson: layerJson,
    techniques: attack.techniques.length, families: families.families.length,
    stubs: t.wrote.map(function (k) { return 'techniques/' + k; }).concat(f.wrote.map(function (k) { return 'families/' + k; })),
    removed: t.removed.map(function (k) { return 'techniques/' + k; }).concat(f.removed.map(function (k) { return 'families/' + k; })),
    unresolved: attack.unresolved, unmapped: families.unmapped
  };
}

module.exports = { run: run, existingStubs: existingStubs };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  console.log(r.status + '   ' + r.techniques + ' technique pages, ' + r.families + ' family pages' +
    (dry ? '   (dry run, nothing written)' : ''));
  if (r.unresolved.length) {
    console.log('   note  ' + r.unresolved.length + ' technique id(s) not in the ATT&CK catalog, listed under `unresolved`, no page: ' +
      r.unresolved.map(function (u) { return u.id; }).join(', '));
  }
  if (r.unmapped.length) {
    console.log('   note  ' + r.unmapped.length + ' family label(s) the vocabulary does not know, listed under `unmapped`, no page');
  }
  if (r.stubs.length) console.log('   stubs written: ' + r.stubs.join(', '));
  if (r.removed.length) console.log('   stubs REMOVED (no longer indexed): ' + r.removed.join(', '));
  r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(r.status === 'PASS' ? 0 : 1);
}
