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
var TACTIC_SLUGS = new Set(AC.TACTIC_ORDER.map(AC.tacticSlug));
var BARE_CONF = /^(HIGH|MODERATE|LOW|DEFINITE|INSUFFICIENT)\.?$/i;

function idsIn(text) {
  return new Set((text.match(TECH_RE) || []));
}

function checkDom(doc, label) {
  var tables = AC.findMappingTables(doc.body);
  var problems = [], missing = [];
  var techniques = 0, unmapped = 0;
  var layer = null;
  var parsedIds = new Set(), rawIds = new Set();

  // Raw IDs come only from tables, never from prose. A technique mentioned in a
  // sentence is not a mapping-table gap.
  //
  // Read cell by cell, never the table's whole textContent. textContent
  // concatenates adjacent cells with no separator, which breaks the ID regex at
  // BOTH ends: "Execution" + "T1059.004" reads as "ExecutionT1059.004" where the
  // leading word boundary never matches and the ID vanishes, and "T1059.004" +
  // "Unix Shell" reads as "T1059.004Unix" where the trailing boundary fails and
  // the ID truncates to the parent "T1059". Either one corrupts the very
  // comparison this gate exists to make, the first by hiding a real gap and the
  // second by inventing one. Same trap that the parser's own discovery step
  // documents.
  [].forEach.call(doc.body.querySelectorAll('table'), function (t) {
    var text = [].map.call(t.querySelectorAll('td, th'), function (c) {
      return c.textContent || '';
    }).join(' | ');
    idsIn(text).forEach(function (id) { rawIds.add(id); });
  });

  tables.forEach(function (t) {
    var p = AC.parseTable(t);
    p.label = AC.labelForTable(t);
    techniques += p.techniques.length;
    unmapped += p.unmapped.length;
    p.techniques.concat(p.unmapped).forEach(function (x) { parsedIds.add(x.id); });
    if (p.unmapped.length) {
      problems.push(p.unmapped.length + ' technique(s) with no resolvable tactic in "' +
        (p.label || 'unlabelled table') + '"');
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

  rawIds.forEach(function (id) { if (!parsedIds.has(id)) missing.push(id); });
  if (missing.length) problems.push('IDs in source but not parsed: ' + missing.join(', '));
  if (rawIds.size && !tables.length) {
    problems.push('technique IDs present but no mapping table was discovered');
    rawIds.forEach(function (id) { if (missing.indexOf(id) === -1) missing.push(id); });
  }

  return {
    status: problems.length ? 'FAIL' : 'PASS',
    tables: tables.length,
    techniques: techniques,
    unmapped: unmapped,
    rawIds: rawIds.size,
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
