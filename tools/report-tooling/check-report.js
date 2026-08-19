'use strict';

/* Publish gate for the ATT&CK coverage strip.
   Asks "did we understand everything the author wrote?", not "did a strip render?".
   A gate asking the latter passes a report whose strip claims 11 techniques where
   the table documents 47, which is exactly the defect this exists to catch. */

var path = require('node:path');
var fs = require('node:fs');

/* Dependency guard, and why it is here.

   These three requires used to sit bare at module top level. When one of them
   cannot resolve, Node throws MODULE_NOT_FOUND before any status object exists,
   and the process exits 1 with a raw stack trace. Exit 1 is this gate's FAIL
   code, and its documented meaning is "this report's ATT&CK content is wrong".
   So a missing node_modules made the gate blame the author's report for the
   gate's own brokenness, and sent them hunting a table defect that was never
   there.

   That is the inversion homelab-soc/docs/gate-honesty-contract.md exists to
   prevent. The contract's rule is that NOT CHECKED is never folded into PASS.
   Folding it into FAIL is the same class of lie and arguably worse, because a
   manufactured accusation costs the author real time, while a false reassurance
   is at least quiet. A gate that could not run says so, names the reason, and
   exits 2.

   Loading inside a try leaves the module usable rather than dead: every entry
   point below returns a NOT CHECKED result carrying DEPS_REASON instead of
   throwing. */
var JSDOM = null;
var AC = null;
var extractTables = null;
var DEPS_REASON = null;

/* Node's thrown output opens with its own stack-frame header, the useless
   "node:internal/modules/cjs/loader:1424" line. An operator needs the Error line
   instead, so read e.message, and for the overwhelmingly common cause, a
   dependency that was never installed, name the remedy alongside it. */
function dependencyReason(e) {
  var msg = String((e && e.message) || e || 'unknown error').split('\n')[0].trim();
  var missing = (e && e.code === 'MODULE_NOT_FOUND') || /cannot find module/i.test(msg);
  return missing
    ? 'gate dependency did not load: ' + msg + '. Run `npm ci` in tools/report-tooling.'
    : 'gate dependency did not load: ' + msg;
}

try {
  JSDOM = require('jsdom').JSDOM;
  AC = require(path.join(__dirname, '..', '..', 'assets', 'js', 'attack-coverage.js'));
  extractTables = require('./lib/extract-tables.js').extractTables;
} catch (e) {
  DEPS_REASON = dependencyReason(e);
}

/* A require can also resolve and still hand back something unusable, when a
   half-written install or a renamed export leaves the binding undefined. That
   throws a TypeError rather than MODULE_NOT_FOUND, either just below at
   TACTIC_SLUGS or later inside a check, and lands back at the same uncaught
   exit 1 this guard exists to eliminate. Same failure wearing a different
   error type, so it gets the same NOT CHECKED answer. */
if (!DEPS_REASON) {
  var unusable =
    typeof JSDOM !== 'function' ? 'jsdom did not export JSDOM'
    : typeof extractTables !== 'function' ? 'lib/extract-tables.js did not export extractTables'
    : !AC || !Array.isArray(AC.TACTIC_ORDER) || typeof AC.tacticSlug !== 'function'
      ? 'attack-coverage.js did not export TACTIC_ORDER and tacticSlug'
    : null;
  if (unusable) DEPS_REASON = 'gate dependency loaded but is unusable: ' + unusable + '.';
}

/* The glossary checker gets its OWN guard rather than joining the block above.
   A broken glossary module must not disable the strip gate, and a strip-side
   dependency failure must not silently mark the glossary as fine. Each claim
   reports its own state, which is the gate-honesty contract applied per check
   rather than per run. */
var CG = null;
var GLOSS_REASON = null;
try {
  CG = require('./lib/check-glossary.js');
  if (!CG || typeof CG.glossaryProblems !== 'function') {
    throw new Error('check-glossary.js loaded but exports no glossaryProblems');
  }
} catch (e) {
  GLOSS_REASON = 'glossary checker did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim();
}

var GLOSS_MARKDOWN_REASON =
  'markdown path has no rendered body; glossary verified post-push against the live URL';

function glossaryNotChecked(reason) {
  return { status: 'NOT CHECKED', reason: reason, marks: 0 };
}

/* And the figure-nav checker gets its own, for the same reason. Unlike the
   glossary this one IS fully checkable from markdown, because it derives the
   anchors the site will generate rather than needing a rendered body. */
var CFN = null;
var FIGNAV_REASON = null;
try {
  CFN = require('./lib/check-figure-nav.js');
  if (!CFN || typeof CFN.checkMarkdown !== 'function') {
    throw new Error('check-figure-nav.js loaded but exports no checkMarkdown');
  }
} catch (e) {
  FIGNAV_REASON = 'figure-nav checker did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim();
}

function figureNavNotChecked(reason) {
  return { status: 'NOT CHECKED', reason: reason, problems: [], entries: 0, chips: 0 };
}

/* And the tier checker gets its own, same reasoning again. */
var CTIER = null;
var TIERS_REASON = null;
try {
  CTIER = require('./lib/check-tiers.js');
  if (!CTIER || typeof CTIER.checkMarkdown !== 'function') {
    throw new Error('check-tiers.js loaded but exports no checkMarkdown');
  }
} catch (e) {
  TIERS_REASON = 'tier checker did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim();
}

function tiersNotChecked(reason) {
  return { status: 'NOT CHECKED', reason: reason, problems: [], marked: 0, unmarked: 0,
           byTier: { 1: 0, 2: 0, 3: 0 } };
}

/* Reported against whichever path the caller asked about, so the operator sees
   what was skipped as well as why. */
function depsNotChecked(p) {
  return { status: 'NOT CHECKED', path: p, reason: DEPS_REASON, problems: [], missing: [],
           glossary: glossaryNotChecked('gate dependencies did not load, so nothing was verified'),
           figureNav: figureNavNotChecked('gate dependencies did not load, so nothing was verified'),
           tiers: tiersNotChecked('gate dependencies did not load, so nothing was verified') };
}

var TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
var TECH_ONE = /\bT\d{4}(?:\.\d{3})?\b/;
// Keyed on DEPS_REASON, not on AC being truthy: a stub exporting {} is truthy
// and would throw here at load, which is the exit 1 the guard above exists to
// stop. Past that check AC is known usable, so this is safe.
var TACTIC_SLUGS = DEPS_REASON ? null : new Set(AC.TACTIC_ORDER.map(AC.tacticSlug));
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
  if (DEPS_REASON) return depsNotChecked(label || 'report');
  var html = extractTables(md).join('\n');
  var doc = new JSDOM('<body>' + html + '</body>').window.document;
  var r = checkDom(doc, label || 'report');
  r.path = label || 'report';
  // extractTables yields ONLY the tables, so the pre, a and heading elements the
  // exclusion list is about are not in this DOM at all. Reporting PASS here would
  // claim a check that never ran.
  r.glossary = glossaryNotChecked(GLOSS_MARKDOWN_REASON);

  /* The figure-nav check needs the RAW markdown, not the extracted tables: it
     reads the front matter and derives the heading anchors, so unlike the
     glossary it is complete on this path rather than deferred to the URL. */
  r.figureNav = FIGNAV_REASON ? figureNavNotChecked(FIGNAV_REASON) : CFN.checkMarkdown(md, label);
  if (r.figureNav.status === 'FAIL') {
    r.status = 'FAIL';
    r.problems = (r.problems || []).concat(r.figureNav.problems);
  }

  r.tiers = TIERS_REASON ? tiersNotChecked(TIERS_REASON) : CTIER.checkMarkdown(md, label);
  if (r.tiers.status === 'FAIL') {
    r.status = 'FAIL';
    r.problems = (r.problems || []).concat(r.tiers.problems);
  }
  return r;
}

function checkFile(file) {
  if (DEPS_REASON) return depsNotChecked(file);
  var md;
  try { md = fs.readFileSync(file, 'utf8'); }
  catch (e) { return { status: 'NOT CHECKED', path: file, reason: e.message, problems: [], missing: [],
                       glossary: glossaryNotChecked('report could not be read'),
                       figureNav: figureNavNotChecked('report could not be read'),
                       tiers: tiersNotChecked('report could not be read') }; }
  return checkMarkdown(md, file);
}

async function checkUrl(url) {
  if (DEPS_REASON) return depsNotChecked(url);
  var html;
  try {
    var res = await fetch(url);
    if (!res.ok) return { status: 'NOT CHECKED', path: url, reason: 'HTTP ' + res.status, problems: [], missing: [],
                          glossary: glossaryNotChecked('report body was not retrieved'),
                          figureNav: figureNavNotChecked('report body was not retrieved'),
                          tiers: tiersNotChecked('report body was not retrieved') };
    html = await res.text();
  } catch (e) {
    return { status: 'NOT CHECKED', path: url, reason: e.message, problems: [], missing: [],
             glossary: glossaryNotChecked('report body was not retrieved'),
             figureNav: figureNavNotChecked('report body was not retrieved'),
             tiers: tiersNotChecked('report body was not retrieved') };
  }
  var doc = new JSDOM(html).window.document;
  var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
  if (!body) return { status: 'NOT CHECKED', path: url, reason: 'no report body container', problems: [], missing: [],
                      glossary: glossaryNotChecked('report body was not retrieved'),
                      figureNav: figureNavNotChecked('report body was not retrieved'),
                      tiers: tiersNotChecked('report body was not retrieved') };
  var wrapper = new JSDOM('<body></body>').window.document;
  wrapper.body.innerHTML = body.innerHTML;
  var r = checkDom(wrapper, url);
  r.path = url;

  /* AFTER checkDom, never before. markTerms inserts span elements into the body,
     and running it first would let glossary marks perturb the table parse this
     gate's primary claim depends on. */
  if (GLOSS_REASON) {
    r.glossary = glossaryNotChecked(GLOSS_REASON);
  } else {
    var g = CG.glossaryProblems(wrapper.body, wrapper, null);
    r.glossary = { status: g.status, marks: g.marks, reason: g.reason };
    if (g.problems.length) {
      r.problems = r.problems.concat(g.problems);
      r.status = 'FAIL';
    }
  }

  /* The FULL document, not the wrapper. The figure_nav JSON block the layout
     emits sits outside .hl-post-content, so a wrapper built from that container
     alone carries the figures but not the declaration, and the check would read
     every report as declaring nothing. */
  if (FIGNAV_REASON) {
    r.figureNav = figureNavNotChecked(FIGNAV_REASON);
  } else {
    r.figureNav = CFN.checkDom(doc, url);
    if (r.figureNav.status === 'FAIL') {
      r.status = 'FAIL';
      r.problems = r.problems.concat(r.figureNav.problems);
    }
  }

  /* The full document again, because the tier classes live on the h2s inside
     .hl-post-content and the wrapper preserves them, but reading the same source
     as figure-nav keeps the two verdicts describing one page. */
  if (TIERS_REASON) {
    r.tiers = tiersNotChecked(TIERS_REASON);
  } else {
    r.tiers = CTIER.checkDom(doc, url);
    if (r.tiers.status === 'FAIL') {
      r.status = 'FAIL';
      r.problems = r.problems.concat(r.tiers.problems);
    }
  }
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
      var gloss = r.glossary || glossaryNotChecked('no glossary verdict recorded');
      var tail = r.status === 'NOT CHECKED' ? r.reason
        : r.status === 'PASS' ? r.tables + ' tables, ' + r.techniques + ' techniques, ' +
            r.unmapped + ' unmapped, glossary ' + gloss.status +
            ', figure-nav ' + (r.figureNav || {}).status +
            ', tiers ' + (r.tiers || {}).status
        : r.problems.join('; ');
      console.log(r.status.padEnd(12) + r.path + '   ' + tail);
      if (verbose && r.problems.length) r.problems.forEach(function (p) { console.log('    ' + p); });
    }
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
