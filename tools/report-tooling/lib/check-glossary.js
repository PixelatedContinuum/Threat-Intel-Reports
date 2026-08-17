'use strict';

/* Verifies the SHIPPED glossary module against a real rendered report body.

   The question here is never "is this report wrong?". A definition surfacing
   inside a rule body, a heading or a link is a defect in assets/js/glossary.js
   or in _data/glossary.yml, and the author of the report cannot fix it. Saying
   otherwise repeats the inversion documented at length in check-report.js's own
   dependency guard, where a missing jsdom made the gate accuse an author of a
   table defect that was never there. Every problem string below therefore names
   the module and the term file as the fix site. */

var path = require('node:path');
var fs = require('node:fs');

var ROOT = path.join(__dirname, '..', '..', '..');
var TERM_FILE = path.join(ROOT, '_data', 'glossary.yml');

var G = null;
var DEPS_REASON = null;
try {
  G = require(path.join(ROOT, 'assets', 'js', 'glossary.js'));
  if (!G || typeof G.markTerms !== 'function') {
    throw new Error('glossary.js loaded but exports no markTerms');
  }
} catch (e) {
  var msg = String((e && e.message) || e || 'unknown error').split('\n')[0].trim();
  DEPS_REASON = 'glossary module did not load: ' + msg;
}

var EXCLUDED_ANCESTOR_RE = /^(CODE|PRE|A|KBD|SAMP|SCRIPT|STYLE|SUMMARY|H[1-6])$/;

var FIX_SITE = 'glossary marked a term inside an excluded element, which is a defect in ' +
  'assets/js/glossary.js or _data/glossary.yml and not in this report: ';

function strip(s) { return s.trim().replace(/^["']|["']$/g, ''); }

/* Minimal reader for the flat list-of-maps shape _data/glossary.yml uses, which
   avoids adding a YAML dependency to the site repo. If that file ever grows
   nested structures this must be replaced with a real parser, and the Python
   validation in the term-file task would not catch it on its own. */
function loadTerms(file) {
  var src = fs.readFileSync(file || TERM_FILE, 'utf8');
  var terms = [];
  var cur = null;
  src.split(/\r?\n/).forEach(function (raw) {
    var line = raw.replace(/\s+$/, '');
    if (!line || /^\s*#/.test(line)) return;
    var start = line.match(/^- term:\s*(.+)$/);
    if (start) { cur = { term: strip(start[1]), aliases: [] }; terms.push(cur); return; }
    if (!cur) return;
    var kv = line.match(/^\s+(\w+):\s*(.*)$/);
    if (!kv) return;
    if (kv[1] === 'short') cur.short = strip(kv[2]);
    if (kv[1] === 'case_sensitive') cur.case_sensitive = kv[2].trim() === 'true';
    if (kv[1] === 'once_per_report') cur.once_per_report = kv[2].trim() === 'true';
    if (kv[1] === 'aliases') {
      cur.aliases = (kv[2].match(/"[^"]*"/g) || []).map(function (s) { return s.slice(1, -1); });
    }
  });
  return terms;
}

function offendingAncestor(mark, body) {
  var n = mark.parentNode;
  while (n && n.nodeType === 1 && n !== body) {
    if (EXCLUDED_ANCESTOR_RE.test(n.tagName)) return n.tagName.toLowerCase();
    if (n.hasAttribute && n.hasAttribute('data-no-gloss')) return 'data-no-gloss';
    n = n.parentNode;
  }
  return null;
}

/* Runs the real matcher over a real rendered body, then asserts nothing landed
   somewhere the exclusion list forbids. Returns PASS, FAIL, or NOT CHECKED with
   a reason. NOT CHECKED is never folded into PASS. */
function glossaryProblems(body, doc, terms) {
  if (DEPS_REASON) {
    return { status: 'NOT CHECKED', reason: DEPS_REASON, marks: 0, problems: [] };
  }
  var list;
  try {
    list = terms || loadTerms();
  } catch (e) {
    return {
      status: 'NOT CHECKED', marks: 0, problems: [],
      reason: 'term file could not be read: ' +
        String((e && e.message) || e).split('\n')[0].trim()
    };
  }
  if (!list.length) {
    return { status: 'NOT CHECKED', reason: 'term file yielded no entries', marks: 0, problems: [] };
  }

  G.markTerms(body, list, doc);

  var marks = body.querySelectorAll('.hl-gloss');
  var bad = [];
  [].forEach.call(marks, function (m) {
    var where = offendingAncestor(m, body);
    if (where) bad.push(where + ' contains the marked term "' + m.textContent + '"');
  });

  var unique = bad.filter(function (v, i) { return bad.indexOf(v) === i; });
  var problems = unique.length ? [FIX_SITE + unique.slice(0, 5).join('; ')] : [];
  return {
    status: problems.length ? 'FAIL' : 'PASS',
    marks: marks.length,
    problems: problems
  };
}

module.exports = {
  loadTerms: loadTerms,
  glossaryProblems: glossaryProblems,
  EXCLUDED_ANCESTOR_RE: EXCLUDED_ANCESTOR_RE,
  DEPS_REASON: DEPS_REASON
};

/* A command line, so the Python gate driver can exercise this end to end the
   same way it exercises check-report.js, and so the author has a manual tool.
   Takes a path to an HTML fragment or full document. */
if (require.main === module) {
  var target = process.argv.slice(2).filter(function (a) { return a.indexOf('--') !== 0; })[0];
  if (!target) {
    console.error('usage: node lib/check-glossary.js <body.html>');
    process.exit(2);
  }
  var JSDOM = null;
  try { JSDOM = require('jsdom').JSDOM; }
  catch (e) {
    console.log('NOT CHECKED   ' + target + '   jsdom did not load: ' +
      String(e.message).split('\n')[0] + '. Run `npm ci` in tools/report-tooling.');
    process.exit(2);
  }
  var html;
  try { html = fs.readFileSync(target, 'utf8'); }
  catch (e) {
    console.log('NOT CHECKED   ' + target + '   ' + e.message);
    process.exit(2);
  }
  var d = new JSDOM(html).window.document;
  var body = d.querySelector('.hl-post-content') || d.body;
  var r = glossaryProblems(body, d, null);
  var tail = r.status === 'NOT CHECKED' ? r.reason
    : r.status === 'PASS' ? r.marks + ' marks, 0 in excluded elements'
    : r.problems.join('; ');
  console.log(r.status.padEnd(12) + ' ' + target + '   ' + tail);
  process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
}
