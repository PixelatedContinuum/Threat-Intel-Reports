#!/usr/bin/env node
'use strict';

/* Links every bare "UTA-YYYY-NNN" in the reports and the detection pages to
   its actor page, for designations that HAVE a page (an entry in
   _data/actors.yml whose reports are published). Idempotent; a mention
   already linked, inside code, inside a tag or inside another link is left
   alone (lib/actors.js linkify has the rules).

   The report keeps saying exactly what it said: only link markup is added.
   Nothing links to a designation without a page, so an embargoed actor's
   mentions stay plain text until go-live, and nothing links from an unlisted
   report either, since the actor page would then list it back.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. `--dry-run` reports counts only. */

var fs = require('node:fs');
var path = require('node:path');

var A;
try { A = require('./lib/actors.js'); }
catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

function pageFiles() {
  var out = [];
  fs.readdirSync(A.REPORT_DIR, { withFileTypes: true }).forEach(function (e) {
    if (e.isDirectory()) out.push({ path: path.join(A.REPORT_DIR, e.name, 'index.md'), kind: 'report' });
  });
  fs.readdirSync(A.DETECTION_DIR).forEach(function (f) {
    if (/\.md$/.test(f) && f !== 'index.md') out.push({ path: path.join(A.DETECTION_DIR, f), kind: 'detection' });
  });
  return out.filter(function (f) { return fs.existsSync(f.path); });
}

function run(opts) {
  opts = opts || {};
  var actorsText, catText, reports;
  try {
    actorsText = fs.readFileSync(A.ACTORS_FILE, 'utf8');
    catText = fs.readFileSync(A.CATALOG_FILE, 'utf8');
    reports = A.readReports(A.REPORT_DIR);
  } catch (e) {
    return { status: 'NOT CHECKED', reason: 'could not read the corpus: ' + e.message, files: [] };
  }
  var parsed = A.parseActors(actorsText);
  if (parsed.problems.length) return { status: 'FAIL', problems: parsed.problems, files: [] };
  var catalog = A.parseCatalog(catText);
  var index = A.build(parsed.actors, reports, catalog);
  if (index.problems.length) return { status: 'FAIL', problems: index.problems, files: [] };

  // Designations only. A named actor's handle is an ordinary word in prose
  // and is never rewritten into a link (lib/actors.js says why).
  var known = {};
  index.entries.forEach(function (e) { if (e.kind !== 'named') known[e.id] = true; });

  var files = [];
  pageFiles().forEach(function (f) {
    var md = fs.readFileSync(f.path, 'utf8');
    var fm = A.frontMatter(md).fm;
    // An unlisted page never links out: its mentions stay plain text.
    if (fm.unlisted === true) return;
    var r = A.linkify(md, known);
    var rel = path.relative(A.ROOT, f.path);
    files.push({ path: rel, count: r.count });
    if (r.changed && !opts.dryRun) fs.writeFileSync(f.path, r.text, 'utf8');
  });
  return { status: 'PASS', problems: [], files: files };
}

module.exports = { run: run };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  if (r.status === 'FAIL') { r.problems.forEach(function (p) { console.log('   FAIL  ' + p); }); process.exit(1); }
  var total = 0, touched = 0;
  r.files.forEach(function (f) { if (f.count) { touched++; total += f.count; console.log('   ' + f.count + '\t' + f.path); } });
  console.log((dry ? 'DRY RUN  ' : 'PASS  ') + total + ' mention(s) ' + (dry ? 'would be' : '') + ' linked across ' +
    touched + ' file(s) of ' + r.files.length + ' scanned');
  process.exit(0);
}
