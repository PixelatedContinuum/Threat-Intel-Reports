'use strict';

/* Publish gate for the ATT&CK coverage strip.
   Asks "did we understand everything the author wrote?", not "did a strip render?".
   A gate asking the latter passes a report whose strip claims 11 techniques where
   the table documents 47, which is exactly the defect this exists to catch. */

var path = require('node:path');
var fs = require('node:fs');
var { JSDOM } = require('jsdom');
var AC = require(path.join(__dirname, '..', '..', 'assets', 'js', 'attack-coverage.js'));
var { extractTables } = require('./lib/extract-tables.js');

var TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
var TECH_ONE = /\bT\d{4}(?:\.\d{3})?\b/;
var TACTIC_SLUGS = new Set(AC.TACTIC_ORDER.map(AC.tacticSlug));
var BARE_CONF = /^(HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT)\.?$/i;
var TACTIC_HEADER = /^\s*tactic/i;

// Row and cell scoping matches the parser's, so a nested table is not read as
// data here either.
var ROWS = ':scope > thead > tr, :scope > tbody > tr, :scope > tr';
var CELLS = ':scope > td, :scope > th';
var HEADER_CELLS = ':scope > thead > tr > th, :scope > tbody > tr > th, :scope > tr > th';

function idsIn(text) {
  return new Set((text.match(TECH_RE) || []));
}

/* A table is a CANDIDATE mapping table when the author signalled a Tactic
   column, or when the parser already reads a technique out of it. Anything else
   is ignored outright: it gets no ID scan and contributes to no count. That
   correctly drops the two shapes SHAPES.md rejects by design, detection-coverage
   tables (Rule Type | Count | MITRE Techniques Covered | Overall FP Risk) and
   technique tables with no Tactic column, both of which carry IDs without being
   ATT&CK mappings.

   The header half of the test is what keeps the gate honest. Scoping the ID scan
   to tables the parser ACCEPTED would be simpler and would be wrong, because it
   makes a total parse failure invisible: a table whose tactic cells are bold
   resolves zero tactics, so it would be dropped as "not a mapping table" and its
   silently lost techniques would report PASS. A total-failure shape is precisely
   what this gate exists to catch, so a declared Tactic column pulls the table
   into scope whether or not anything parsed. */
function hasTacticHeader(t) {
  var ths = t.querySelectorAll(HEADER_CELLS);
  for (var i = 0; i < ths.length; i++) {
    if (TACTIC_HEADER.test(ths[i].textContent || '')) return true;
  }
  return false;
}

/* Declared IDs are ROW-SCOPED. In each row the first cell carrying a technique
   ID ends the scan, and only cells 0..that one count as declared. Evidence and
   implementation columns come after it, so a historical aside such as
   "Formerly T1562.004" in an evidence cell is correctly not a declared ID and
   does not fail a report that is right as written.

   The compound-cell defence survives this, because a cell reading
   "T1071.001/004" IS the technique-ID cell and therefore sits inside the scanned
   range.

   Cells are joined with a separator, never read as the row's textContent:
   textContent concatenates adjacent cells with nothing between them, so
   "Execution" + "T1059.004" reads as "ExecutionT1059.004" and the leading word
   boundary never matches. */
function declaredIds(t) {
  var out = new Set();
  [].forEach.call(t.querySelectorAll(ROWS), function (row) {
    var cs = row.querySelectorAll(CELLS);
    for (var i = 0; i < cs.length; i++) {
      if (TECH_ONE.test(cs[i].textContent || '')) {
        var text = [].slice.call(cs, 0, i + 1).map(function (c) {
          return c.textContent || '';
        }).join(' | ');
        idsIn(text).forEach(function (id) { out.add(id); });
        return;
      }
    }
  });
  return out;
}

function checkDom(doc, label) {
  var problems = [], missing = [];
  var techniques = 0, unmapped = 0, declared = 0;
  var layer = null;
  var parsedIds = new Set();

  // Parse every table once, then keep only the candidates. Deriving the
  // candidate set from the same parse the checks below use keeps discovery and
  // checking from drifting apart.
  var candidates = [];
  [].forEach.call(doc.body.querySelectorAll('table'), function (t) {
    var p = AC.parseTable(t);
    if (!p.techniques.length && !hasTacticHeader(t)) return;

    var ids = declaredIds(t);

    /* A Tactic-headed table that declares ZERO technique IDs anywhere (for
       example PULSAR-RAT's "ATT&CK Tactic Coverage Analysis" table, whose
       Techniques Observed column holds counts such as 3 and 4, never an ID)
       is not a mapping table. Skip it outright, exactly as a non-candidate
       table is skipped: it is not counted in `tables`, and it cannot fail
       rule 1 below.

       This is safe because rule 1 exists to catch a table whose techniques
       the PARSER could not read, which is what the bold-emphasis defect
       looked like: a real mapping table whose IDs were present in the markup
       but the parser failed to extract them. Formatting can never hide an ID
       from this raw scan, because emphasis markers are non-word characters,
       so \bT1204\b still matches inside **T1204.002**. A table with
       genuinely zero declared IDs therefore cannot be concealing techniques
       the parser lost, so it is not the shape rule 1 exists to catch. */
    if (!p.techniques.length && ids.size === 0) return;

    candidates.push({ el: t, parsed: p, ids: ids });
  });

  candidates.forEach(function (c) {
    var t = c.el, p = c.parsed;
    p.label = AC.labelForTable(t);
    var name = p.label || 'unlabelled table';
    techniques += p.techniques.length;
    unmapped += p.unmapped.length;

    var own = new Set();
    p.techniques.concat(p.unmapped).forEach(function (x) {
      parsedIds.add(x.id);
      own.add(x.id);
    });

    // A candidate that resolves nothing is either a tenth shape or a parse that
    // has collapsed. Either way the author's mapping did not survive, and that
    // is the loudest possible failure, not a table to quietly skip.
    if (!p.techniques.length) {
      problems.push('candidate mapping table yielded no techniques in "' + name + '"');
    }
    if (p.unmapped.length) {
      problems.push(p.unmapped.length + ' technique(s) with no resolvable tactic in "' + name + '"');
    }

    var gaps = [];
    c.ids.forEach(function (id) {
      declared++;
      if (own.has(id)) return;
      gaps.push(id);
      if (missing.indexOf(id) === -1) missing.push(id);
    });
    if (gaps.length) {
      problems.push('IDs declared in "' + name + '" but not parsed: ' + gaps.join(', '));
    }

    var l = AC.toNavigatorLayer(p, { reportTitle: label });
    layer = layer || l;
    if (l.versions.layer !== '4.5') problems.push('layer version is ' + l.versions.layer);
    l.techniques.forEach(function (e) {
      if (!/^T\d{4}(\.\d{3})?$/.test(e.techniqueID)) problems.push('malformed id ' + e.techniqueID);
      if (!TACTIC_SLUGS.has(e.tactic)) problems.push('unknown tactic slug ' + e.tactic);
      if (BARE_CONF.test((e.comment || '').trim())) {
        problems.push('layer comment for ' + e.techniqueID + ' is a bare confidence word');
      }
    });
  });

  return {
    status: problems.length ? 'FAIL' : 'PASS',
    tables: candidates.length,
    techniques: techniques,
    unmapped: unmapped,
    declaredIds: declared,
    parsedIds: parsedIds.size,
    missing: missing,
    problems: problems,
    layer: layer
  };
}

function checkMarkdown(md, label) {
  var html = extractTables(md).join('\n');
  var doc = new JSDOM('<body>' + html + '</body>').window.document;
  var r = checkDom(doc, label || 'report');
  r.path = label || 'report';
  return r;
}

function checkFile(file) {
  var md;
  try { md = fs.readFileSync(file, 'utf8'); }
  catch (e) { return { status: 'NOT CHECKED', path: file, reason: e.message, problems: [], missing: [] }; }
  return checkMarkdown(md, file);
}

async function checkUrl(url) {
  var html;
  try {
    var res = await fetch(url);
    if (!res.ok) return { status: 'NOT CHECKED', path: url, reason: 'HTTP ' + res.status, problems: [], missing: [] };
    html = await res.text();
  } catch (e) {
    return { status: 'NOT CHECKED', path: url, reason: e.message, problems: [], missing: [] };
  }
  var doc = new JSDOM(html).window.document;
  var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
  if (!body) return { status: 'NOT CHECKED', path: url, reason: 'no report body container', problems: [], missing: [] };
  var wrapper = new JSDOM('<body></body>').window.document;
  wrapper.body.innerHTML = body.innerHTML;
  var r = checkDom(wrapper, url);
  r.path = url;
  return r;
}

module.exports = { checkMarkdown: checkMarkdown, checkFile: checkFile, checkUrl: checkUrl };

if (require.main === module) {
  (async function () {
    var args = process.argv.slice(2);
    var target = args.filter(function (a) { return a.indexOf('--') !== 0; })[0];
    var asJson = args.indexOf('--json') !== -1;
    var verbose = args.indexOf('--verbose') !== -1;
    if (!target) {
      console.error('usage: node check-report.js <report.md | https://url> [--json] [--verbose]');
      process.exit(2);
    }
    var r = /^https?:\/\//.test(target) ? await checkUrl(target) : checkFile(target);
    if (asJson) {
      console.log(JSON.stringify(r, function (k, v) { return k === 'layer' ? undefined : v; }, 2));
    } else {
      var tail = r.status === 'NOT CHECKED' ? r.reason
        : r.status === 'PASS' ? r.tables + ' tables, ' + r.techniques + ' techniques, ' + r.unmapped + ' unmapped'
        : r.problems.join('; ');
      console.log(r.status.padEnd(12) + r.path + '   ' + tail);
      if (verbose && r.problems.length) r.problems.forEach(function (p) { console.log('    ' + p); });
    }
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
