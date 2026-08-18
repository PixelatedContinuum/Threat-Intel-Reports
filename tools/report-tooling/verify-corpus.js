'use strict';

/* Sweeps every published report through the real gate.

   This exists because a term added to _data/glossary.yml applies to all
   published reports the moment it is committed, with no per-report review. The
   per-report gate covers new reports; only a sweep covers a glossary edit.

   Reports PASS, FAIL, or NOT CHECKED per report and never folds the third into
   the first. A run that checked nothing says so and exits 2. */

var path = require('node:path');
var fs = require('node:fs');

var CR = require('./check-report.js');
var SD = require('./lib/sweep-detections.js');
var JSDOM = require('jsdom').JSDOM;

var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');
var ROOT = path.join(__dirname, '..', '..');
var REPORTS_DIR = path.join(ROOT, 'reports');
var CATALOG = path.join(ROOT, '_data', 'catalog.yml');

/* The corpus is every report DIRECTORY, not every catalog entry.

   Those two sets differ, and the difference is load-bearing. A report published
   preview-style is live at its URL but deliberately commented out of
   _data/catalog.yml so it stays off the listing pages. Defining the corpus from
   the catalog would silently skip exactly those reports, and they carry the
   glossary and the strip like any other, so a mark landing inside a rule body
   on one of them is just as visible to whoever holds the link.

   Silently narrowing coverage while printing a clean summary is the failure this
   whole tool exists to catch, so the unlisted ones are swept and named. */
function reportSlugs() {
  return fs.readdirSync(REPORTS_DIR, { withFileTypes: true })
    .filter(function (e) {
      return e.isDirectory() && fs.existsSync(path.join(REPORTS_DIR, e.name, 'index.md'));
    })
    .map(function (e) { return e.name; })
    .sort();
}

// Uncommented entries only, so a preview report reads as unlisted rather than listed.
function listedPaths() {
  var src = fs.readFileSync(CATALOG, 'utf8');
  var out = {};
  var re = /^[^#\n]*?\breport_url:\s*(\S+)\s*$/gm;
  var m;
  while ((m = re.exec(src))) out[m[1].replace(/^["']|["']$/g, '')] = true;
  return out;
}

function pad(s, n) { return String(s).padEnd(n); }

(async function () {
  var slugs, listed;
  try {
    slugs = reportSlugs();
  } catch (e) {
    console.log('NOT CHECKED  could not enumerate ' + REPORTS_DIR + ': ' + e.message);
    process.exit(2);
  }
  try {
    listed = listedPaths();
  } catch (e) {
    // A missing catalog costs the listed/unlisted split, not the sweep itself.
    listed = null;
    console.log('note: could not read ' + CATALOG + ' (' + e.message +
      '), so the listed/unlisted split is unavailable');
  }

  if (!slugs.length) {
    console.log('NOT CHECKED  no report directories found under ' + REPORTS_DIR +
      ', so this run verified nothing');
    process.exit(2);
  }

  var urls = slugs.map(function (s) { return BASE + '/reports/' + s + '/'; });
  var unlisted = listed
    ? slugs.filter(function (s) { return !listed['/reports/' + s + '/']; })
    : [];

  console.log('Sweeping ' + urls.length + ' reports at ' + BASE);
  if (listed) {
    console.log(Object.keys(listed).length + ' listed in the catalog, ' +
      unlisted.length + ' live but unlisted' +
      (unlisted.length ? ': ' + unlisted.join(', ') : ''));
  }
  console.log('');

  var counts = { PASS: 0, FAIL: 0, 'NOT CHECKED': 0 };
  var glossCounts = { PASS: 0, FAIL: 0, 'NOT CHECKED': 0 };
  var figCounts = { PASS: 0, FAIL: 0, 'NOT CHECKED': 0 };
  var figEntries = 0, figChips = 0, figSilent = 0;
  var techniques = 0, unmapped = 0, marks = 0, tables = 0;
  var attention = [];

  for (var i = 0; i < urls.length; i++) {
    var r = await CR.checkUrl(urls[i]);
    counts[r.status] = (counts[r.status] || 0) + 1;

    var g = r.glossary || { status: 'NOT CHECKED', reason: 'no glossary verdict recorded' };
    glossCounts[g.status] = (glossCounts[g.status] || 0) + 1;

    var fnv = r.figureNav || { status: 'NOT CHECKED', reason: 'no figure-nav verdict recorded' };
    figCounts[fnv.status] = (figCounts[fnv.status] || 0) + 1;
    figEntries += fnv.entries || 0;
    figChips += fnv.chips || 0;
    if (fnv.status === 'PASS' && !fnv.entries) figSilent++;

    techniques += r.techniques || 0;
    unmapped += r.unmapped || 0;
    tables += r.tables || 0;
    marks += g.marks || 0;

    var slug = urls[i].replace(BASE, '');
    var tail = r.status === 'NOT CHECKED' ? r.reason
      : (r.tables || 0) + 't ' + (r.techniques || 0) + 'tech ' + (g.marks || 0) + 'gloss' +
        (g.status === 'PASS' ? '' : '  glossary ' + g.status);
    console.log(pad(r.status, 12) + pad(slug, 62) + tail);

    if (r.status !== 'PASS') attention.push(slug + ': ' + ((r.problems || []).join('; ') || r.reason));
    if (g.status === 'NOT CHECKED') attention.push(slug + ': glossary NOT CHECKED, ' + g.reason);
    if (fnv.status === 'NOT CHECKED') attention.push(slug + ': figure-nav NOT CHECKED, ' + fnv.reason);
    if (fnv.status === 'FAIL') attention.push(slug + ': figure-nav FAIL, ' + (fnv.problems || []).join('; '));
  }

  // Source side: is the manifest consistent with the markdown it came from?
  var det = SD.sweepSource();
  console.log('');
  console.log('== detection manifest (source) ==');
  console.log(det.status.padEnd(12) + det.files + ' files, ' + det.rules +
    ' rules, ' + det.xref + ' cross-referenced');
  if (det.reason) console.log('  reason: ' + det.reason);
  det.problems.slice(0, 10).forEach(function (p) { console.log('  ' + p); });

  // Page side: does it still describe what kramdown actually rendered?
  var live = await SD.sweepRendered(BASE, JSDOM);
  console.log('');
  console.log('== detection manifest (rendered pages) ==');
  console.log(live.status.padEnd(12) + live.pages + ' pages, ' + live.bound +
    ' rules bound, ' + live.xref + ' cross-referenced, ' + live.mismatched + ' mismatched');
  if (live.reason) console.log('  reason: ' + live.reason);
  live.problems.slice(0, 10).forEach(function (p) { console.log('  ' + p); });

  console.log('\n== corpus ==');
  console.log('reports checked      ' + urls.length +
    (listed ? ' (' + (urls.length - unlisted.length) + ' listed, ' +
      unlisted.length + ' live but unlisted)' : ''));
  console.log('PASS / FAIL / NOT CHECKED   ' + counts.PASS + ' / ' + counts.FAIL +
    ' / ' + counts['NOT CHECKED']);
  console.log('glossary P/F/NC      ' + glossCounts.PASS + ' / ' + glossCounts.FAIL +
    ' / ' + glossCounts['NOT CHECKED']);
  console.log('mapping tables       ' + tables);
  console.log('techniques           ' + techniques);
  console.log('unmapped techniques  ' + unmapped);
  console.log('glossary marks       ' + marks);
  console.log('figure-nav P/F/NC    ' + figCounts.PASS + ' / ' + figCounts.FAIL +
    ' / ' + figCounts['NOT CHECKED']);
  console.log('figure-nav declared  ' + figEntries + ' figures, ' + figChips + ' chips');
  // Printed as a COUNT, never as silence. "chips everywhere" and "chips nowhere
  // and nothing complained" must not look identical in this summary.
  console.log('reports declaring 0  ' + figSilent);

  if (attention.length) {
    console.log('\n== needs attention ==');
    attention.forEach(function (a) { console.log('  ' + a); });
  }

  // FAIL outranks NOT CHECKED, because a real defect is more urgent than an
  // unverified report, but neither can ever exit 0.
  if (counts.FAIL || figCounts.FAIL || det.status === 'FAIL' || live.status === 'FAIL') process.exit(1);
  if (counts['NOT CHECKED'] || glossCounts['NOT CHECKED'] || figCounts['NOT CHECKED'] ||
      det.status === 'NOT CHECKED' || live.status === 'NOT CHECKED') process.exit(2);
  process.exit(0);
})();
