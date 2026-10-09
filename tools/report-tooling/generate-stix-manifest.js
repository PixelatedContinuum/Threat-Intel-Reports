#!/usr/bin/env node
'use strict';

/* Writes stix/manifest.json: one row per PUBLISHED STIX bundle with its url,
   SHA-256, size, object and indicator counts and the report's modified time,
   plus the same for the all-bundles zip, so a platform can poll one small file
   and fetch only what changed instead of pulling the zip. Published means the
   catalog lists the bundle; a bundle on disk the catalog does not list is not
   in the manifest (the embargo gate owns that case).

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');
var crypto = require('node:crypto');

var A, yaml;
try { A = require('./lib/actors.js'); yaml = require('js-yaml'); }
catch (e) { console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.'); process.exit(2); }

var STIX_DIR = path.join(A.ROOT, 'stix');
var MANIFEST = path.join(STIX_DIR, 'manifest.json');
var ZIP = 'hunters-ledger-stix-bundles.zip';
var SITE = 'https://the-hunters-ledger.com';

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function dateStr(v) { return v instanceof Date ? v.toISOString().slice(0, 10) : String(v || ''); }

function build() {
  var catText = fs.readFileSync(A.CATALOG_FILE, 'utf8');
  var entries = (yaml.load(catText) || {}).entries || [];
  var bundles = [], problems = [];
  entries.forEach(function (e) {
    if (!e.stix_url) return;
    var file = String(e.stix_url).split('/').pop();
    var p = path.join(STIX_DIR, file);
    var buf;
    try { buf = fs.readFileSync(p); } catch (err) { problems.push('catalog lists ' + e.stix_url + ' but ' + p + ' is missing'); return; }
    var bundle;
    try { bundle = JSON.parse(buf.toString('utf8')); } catch (err) { problems.push(file + ' is not valid JSON: ' + err.message); return; }
    var objects = bundle.objects || [];
    var report = objects.filter(function (o) { return o.type === 'report'; })[0];
    var modified = objects.reduce(function (m, o) { return o.modified && o.modified > m ? o.modified : m; }, '');
    bundles.push({
      slug: e.report_url ? String(e.report_url).replace(/^\/reports\//, '').replace(/\/$/, '') : file.replace(/\.json$/, ''),
      title: String(e.title),
      date: dateStr(e.date),
      file: file,
      url: SITE + e.stix_url,
      report_url: e.report_url ? SITE + e.report_url : null,
      bundle_id: bundle.id || null,
      report_id: report ? report.id : null,
      sha256: sha256(buf),
      bytes: buf.length,
      objects: objects.length,
      indicators: objects.filter(function (o) { return o.type === 'indicator'; }).length,
      modified: modified || (report ? report.modified : null)
    });
  });
  bundles.sort(function (a, b) { return a.date === b.date ? (a.slug < b.slug ? -1 : 1) : (a.date < b.date ? 1 : -1); });
  var zip = null;
  try {
    var zbuf = fs.readFileSync(path.join(STIX_DIR, ZIP));
    zip = { file: ZIP, url: SITE + '/stix/' + ZIP, sha256: sha256(zbuf), bytes: zbuf.length };
  } catch (e) { problems.push('the all-bundles zip stix/' + ZIP + ' is missing'); }
  var text = JSON.stringify({
    spec: 'The Hunters Ledger STIX 2.1 bundle manifest: poll this file, compare sha256 per bundle, fetch what changed.',
    license: 'CC BY 4.0',
    count: bundles.length,
    zip: zip,
    bundles: bundles
  }, null, 2) + '\n';
  return { text: text, bundles: bundles, problems: problems };
}

function run(opts) {
  opts = opts || {};
  var b;
  try { b = build(); } catch (e) { return { status: 'NOT CHECKED', reason: e.message, problems: [], text: null, count: 0 }; }
  if (b.problems.length) return { status: 'FAIL', reason: null, problems: b.problems, text: null, count: b.bundles.length };
  if (!b.bundles.length) return { status: 'NOT CHECKED', reason: 'the catalog lists no STIX bundle', problems: [], text: null, count: 0 };
  if (!opts.dryRun) fs.writeFileSync(MANIFEST, b.text, 'utf8');
  return { status: 'PASS', reason: null, problems: [], text: b.text, count: b.bundles.length };
}

module.exports = { run: run, MANIFEST: MANIFEST };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  console.log(r.status + '   ' + r.count + ' bundles in stix/manifest.json' + (dry ? '   (dry run, nothing written)' : ''));
  r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(r.status === 'PASS' ? 0 : 1);
}
