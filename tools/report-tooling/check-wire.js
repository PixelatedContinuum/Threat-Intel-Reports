#!/usr/bin/env node
'use strict';

/* CLI for the wire gate. Reads the two data files, prints one verdict, exits
   0 PASS, 1 FAIL, 2 NOT CHECKED.

   Missing dependencies are NOT CHECKED with the remedy named, never a pass. A
   fresh clone has no node_modules, and a gate that silently passed in that state
   would be worse than one that plainly did not run. */

var path = require('node:path');
var fs = require('node:fs');
var cp = require('node:child_process');

var ROOT = path.join(__dirname, '..', '..');
var WIRE = path.join(ROOT, '_data', 'wire.yml');
var SOURCES = path.join(ROOT, '_data', 'wire-sources.yml');
var PAGE = path.join(ROOT, 'wire', 'index.md');
var INCLUDES = path.join(ROOT, '_includes');
var SCSS = path.join(ROOT, 'assets', 'css', 'custom.scss');
var FEED = path.join(ROOT, 'wire', 'cves.xml');
var VULNS_FEED = path.join(ROOT, 'wire', 'vulns.xml');
// T-0532 part S: the Details file page pair, the row include they share, the renderer.
var DETAILS_NKEV = path.join(ROOT, 'wire', 'details-nkev.json');
var DETAILS_CVES = path.join(ROOT, 'wire', 'details-cves.json');
var DETAILS_ROW_INCLUDE = path.join(ROOT, '_includes', 'wire-details-row.html');
var DETAILS_JS = path.join(ROOT, 'assets', 'js', 'wire-details.js');

var yaml, CW;
try {
  yaml = require('js-yaml');
  CW = require('./lib/check-wire.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message +
    '. Run `npm ci` in tools/report-tooling, then re-run this gate.');
  process.exit(2);
}

function load(p) {
  try { return yaml.load(fs.readFileSync(p, 'utf8')); }
  catch (e) { return null; }
}

/* What origin holds, which is the only thing that can say whether an old local
   wire.yml means a stopped generator or just a checkout nobody pulled.

   The authoritative copy is `wire.yml` at the tip of origin/wire-data: the
   generator force-pushes one orphan commit there every 15 minutes, and the Pages
   workflow (.github/workflows/pages.yml) copies it into _data/ at build time.
   origin/main:_data/wire.yml is the pre-cutover location and is read as a
   fallback so this gate keeps working during the transition and on a clone
   that predates it. Returns null on any failure, and null means unknown,
   never healthy.

   Set WIRE_GATE_NO_FETCH=1 to read the refs already in the clone without going
   to the network, which is what a CI job on a fresh clone wants (the workflow
   fetches wire-data itself, then runs this). */
function remoteWire() {
  if (!process.env.WIRE_GATE_NO_FETCH) {
    try {
      cp.execFileSync('git', ['fetch', 'origin', '--quiet',
        '+refs/heads/main:refs/remotes/origin/main',
        '+refs/heads/wire-data:refs/remotes/origin/wire-data'],
        { cwd: ROOT, stdio: 'ignore', timeout: 30000 });
    } catch (e) {
      // wire-data may not exist yet; fall back to fetching main alone before giving up.
      try {
        cp.execFileSync('git', ['fetch', 'origin', 'main', '--quiet'],
          { cwd: ROOT, stdio: 'ignore', timeout: 30000 });
      } catch (e2) {
        return null; // offline, no remote, or an auth prompt: origin is unknown
      }
    }
  }
  var refs = ['origin/wire-data:wire.yml', 'origin/main:_data/wire.yml'];
  for (var i = 0; i < refs.length; i++) {
    try {
      var out = cp.execFileSync('git', ['show', refs[i]],
        { cwd: ROOT, encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024,
          stdio: ['ignore', 'pipe', 'ignore'] });   // a missing ref is expected, not news
      var m = /^generated_at:[ \t]*(\S+)/m.exec(out);
      if (m) return { generated_at: m[1], ref: refs[i] };
    } catch (e) {
      // ref absent in this clone; try the next
    }
  }
  return null;
}

var doc = load(WIRE);
var srcDoc = load(SOURCES);
var sources = srcDoc && srcDoc.sources ? srcDoc.sources : null;

if (!srcDoc) {
  console.log('note: could not read ' + SOURCES +
    ', so unclassified sources cannot be reported');
}

var r = CW.check(doc, sources, Date.now(), remoteWire());

if (r.status === 'NOT CHECKED') {
  console.log('NOT CHECKED  ' + r.reason);
  process.exit(2);
}

var head = r.status + '  ' + WIRE;
if (r.counts) {
  head += '  (' + r.counts.total + ' items: ' + r.counts.research +
    ' research, ' + r.counts.news + ' news, ' + r.counts.vuln + ' vuln digest; ' +
    r.counts.vulns + ' nKEV rows, ' + r.counts.cves + ' CVEs rows)';
}
console.log(head);

r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
if (r.warnings.length) {
  console.log('   WARN  unclassified source(s), add to _data/wire-sources.yml: ' +
    r.warnings.join(', '));
}
// Never FAIL lines: pages.yml drops wire.yml on any non-stale FAIL, and a
// Vulnerabilities-tab fault must not take the headlines down with it.
(r.vulnWarnings || []).forEach(function (w) { console.log('   WARN  vulns: ' + w); });
(r.cveWarnings || []).forEach(function (w) { console.log('   WARN  cves: ' + w); });

/* The data is only half of it. The page decides how each row's day is derived,
   and the day filter is only correct while that derivation happens once. */
var pageSrc = null;
try { pageSrc = fs.readFileSync(PAGE, 'utf8'); } catch (e) { pageSrc = null; }
var includes = {};
// Every wire-* include on disk: the page gate follows the chain the page actually names, and a
// name it needs that is not here is NOT CHECKED there (review F4).
var incNames = [];
try { incNames = fs.readdirSync(INCLUDES).filter(function (n) { return /^wire-.*\.html$/.test(n); }); } catch (e) { incNames = []; }
incNames.forEach(function (n) {
  try { includes[n] = fs.readFileSync(path.join(INCLUDES, n), 'utf8'); } catch (e) { /* left absent: the page gate says NOT CHECKED */ }
});
var p = CW.checkPage(pageSrc, includes);
console.log(p.status + '  ' + PAGE + (p.status === 'PASS' ? '  (day derived once, cache-bust present)' : ''));
if (p.reason) console.log('   ' + p.reason);
p.problems.forEach(function (x) { console.log('   FAIL  ' + x); });

/* The tab CSS: the no-:has fallback is a property of the whole rule block. */
var scssSrc = null;
try { scssSrc = fs.readFileSync(SCSS, 'utf8'); } catch (e) { scssSrc = null; }
var feedSrc = null;
try { feedSrc = fs.readFileSync(FEED, 'utf8'); } catch (e) { feedSrc = null; }
var fd = CW.checkCvesFeed(feedSrc);
console.log(fd.status + '  ' + FEED + (fd.status === 'PASS' ? '  (every output escaped, sources and the cve.now score note present)' : ''));
if (fd.reason) console.log('   ' + fd.reason);
fd.problems.forEach(function (x) { console.log('   FAIL  ' + x); });
var vf = null;
try { vf = fs.readFileSync(VULNS_FEED, 'utf8'); } catch (e) { vf = null; }
var fvn = CW.checkVulnsFeed(vf);
console.log(fvn.status + '  ' + VULNS_FEED + (fvn.status === 'PASS' ? '  (every output escaped for XML)' : ''));
if (fvn.reason) console.log('   ' + fvn.reason);
fvn.problems.forEach(function (x) { console.log('   FAIL  ' + x); });
var tc = CW.checkTabCss(scssSrc);
console.log(tc.status + '  ' + SCSS + (tc.status === 'PASS' ? '  (every tab-hiding rule is a :has() rule)' : ''));
if (tc.reason) console.log('   ' + tc.reason);
tc.problems.forEach(function (x) { console.log('   FAIL  ' + x); });

/* The Details surface (T-0532 part S): the two JSON pages and the row include they
   share are held to jsonify for every value; the renderer to no markup sink; the
   page to the toggles, the wrapper and the versioned data-details URLs. */
function readOr(pathF) {
  try { return fs.readFileSync(pathF, 'utf8'); } catch (e) { return null; }
}
var detailsChecks = [
  ['wire/details-nkev.json', CW.checkDetailsJsonPage(readOr(DETAILS_NKEV)), '(every value emitted through jsonify)'],
  ['wire/details-cves.json', CW.checkDetailsJsonPage(readOr(DETAILS_CVES)), '(every value emitted through jsonify)'],
  ['_includes/wire-details-row.html', CW.checkDetailsJsonPage(readOr(DETAILS_ROW_INCLUDE)), '(every value emitted through jsonify)'],
  ['assets/js/wire-details.js', CW.checkDetailsScript(readOr(DETAILS_JS)), '(text nodes and validated hrefs only)'],
  ['page: Details structure', CW.checkDetailsPage(pageSrc), '(nKEV and CVEs toggles first in the row, none on headlines, the wrapper filter item, versioned data-details)']
];
var anyNotChecked = false;
var anyDetailsFail = false;
detailsChecks.forEach(function (c) {
  console.log(c[1].status + '  ' + c[0] + (c[1].status === 'PASS' ? '  ' + c[2] : ''));
  if (c[1].reason) console.log('   ' + c[1].reason);
  c[1].problems.forEach(function (x) { console.log('   FAIL  ' + x); });
  if (c[1].status === 'FAIL') anyDetailsFail = true;
  if (c[1].status === 'NOT CHECKED') anyNotChecked = true;
});

if (r.status === 'PASS' && p.status === 'PASS' && tc.status === 'PASS' && fd.status === 'PASS' && fvn.status === 'PASS' &&
    !anyDetailsFail) {
  if (anyNotChecked) process.exit(2);
  process.exit(0);
}
// A page-side FAIL starts with "FAIL  <path>" in the log, which pages.yml reads as a bug on main.
if (r.status === 'FAIL' || p.status === 'FAIL' || tc.status === 'FAIL' || fd.status === 'FAIL' || fvn.status === 'FAIL') process.exit(1);
// NOT CHECKED on the page or the CSS alone is not a pass, and is not a FAIL either.
process.exit(2);
