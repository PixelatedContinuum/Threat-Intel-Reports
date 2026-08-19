'use strict';

/* Authoring aid for the register-tier markers. Prints every h2 of a report in
   order with a proposed tier, how that proposal was reached, and the exact line
   to paste under the heading.

   It proposes; it never decides. Deriving tiers from section names was measured
   across the corpus and failed: a deliberately generous keyword list left 40% of
   sections unclassified and not one report clean, because deep sections carry
   names like "Technical Analysis", "How This Investigation Unfolded" and
   "Dynamic / Behavioral Analysis". That measurement is the whole reason the
   marker is authored, so this tool exists to make the author fast, not to
   replace them.

   Two proposal sources, always labelled so the author can see which they are
   trusting:

     name  the canonical mapping in report-structure-template
     span  the corpus shape. 31 of 38 classifiable reports run Tier 1, then 2,
           then the Tier 3 teardown, then back to Tier 2 for the reference
           apparatus. So an unnamed heading sitting between two confident
           neighbours of the same tier inherits it.

   Anything still unresolved prints "?" and is COUNTED in the summary. A silent
   zero would make an interrupted pass look finished. */

var fs = require('node:fs');
var path = require('node:path');
var CT = require('./lib/check-tiers.js');
var KS = require('./lib/kramdown-slug.js');

var ROOT = path.join(__dirname, '..', '..');
var REPORTS = path.join(ROOT, 'reports');

var T1 = [
  /\bbluf\b/, /bottom line up front/, /executive summary/, /operational brief/,
  /business risk/, /^risk assessment/, /key takeaways/, /executive overview/
];
var T3 = [
  /capabilit(y|ies) deep/, /deep[- ]dive/, /static analysis/, /dynamic/, /behavioral/,
  /behavioural/, /technical teardown/, /technical analysis/, /exploitation (mechanics|toolkit)/,
  /reverse engineer/, /malware analysis/
];
var T2 = [
  /technical classification/, /threat intelligence/, /mitre/, /att&ck/, /attck/,
  /indicators of compromise/, /\bioc\b/, /detection/, /response/, /threat actor/,
  /references/, /confidence/, /campaign scope/, /infrastructure/, /coverage gaps/,
  /\bgaps\b/, /attribution/, /recommendation/, /\bfaq\b/, /cohort context/,
  /appendix/, /calibration/, /victimolog/, /disclosure/
];

function byName(text) {
  var s = text.toLowerCase();
  for (var i = 0; i < T3.length; i++) if (T3[i].test(s)) return 3;
  for (var j = 0; j < T1.length; j++) if (T1[j].test(s)) return 1;
  for (var k = 0; k < T2.length; k++) if (T2[k].test(s)) return 2;
  return null;
}

/* An unnamed heading between two confident neighbours of the SAME tier inherits
   it. Deliberately conservative: a heading between a 2 and a 3 gets nothing,
   because that is exactly the boundary the author needs to place. */
function bySpan(proposals, i) {
  var before = null, after = null;
  for (var a = i - 1; a >= 0; a--) if (proposals[a].tier) { before = proposals[a].tier; break; }
  for (var b = i + 1; b < proposals.length; b++) if (proposals[b].tier) { after = proposals[b].tier; break; }
  if (before && after && before === after) return before;
  if (before && after === null) return before;
  return null;
}

function proposeFor(md) {
  var scan = CT.scanMarkdown(md.replace(/^---\r?\n[\s\S]*?\r?\n---/, ''));
  var proposals = scan.headings.map(function (h) {
    return {
      text: h.text,
      existing: h.tier,
      sameLine: h.sameLine,
      tier: h.tier ? Number(h.tier) : byName(h.text),
      how: h.tier ? 'set' : (byName(h.text) ? 'name' : null)
    };
  });
  proposals.forEach(function (p, i) {
    if (p.tier) return;
    var s = bySpan(proposals, i);
    if (s) { p.tier = s; p.how = 'span'; }
  });
  return proposals;
}

var args = process.argv.slice(2);
var only = args.filter(function (a) { return a.indexOf('--') !== 0; })[0];

var slugs = fs.readdirSync(REPORTS, { withFileTypes: true })
  .filter(function (e) { return e.isDirectory(); })
  .map(function (e) { return e.name; })
  .filter(function (n) { return !only || n === only; })
  .sort();

if (only && !slugs.length) {
  console.error('no report directory named ' + only);
  process.exit(2);
}

var totals = { set: 0, name: 0, span: 0, none: 0, reports: 0, done: 0 };

slugs.forEach(function (slug) {
  var file = path.join(REPORTS, slug, 'index.md');
  if (!fs.existsSync(file)) return;
  var md = fs.readFileSync(file, 'utf8');
  var proposals = proposeFor(md);
  if (!proposals.length) return;

  totals.reports++;
  var already = proposals.every(function (p) { return p.existing; });
  if (already) totals.done++;

  if (only || !already) {
    console.log('');
    console.log('===== ' + slug + '  (' + proposals.length + ' sections' +
      (already ? ', already marked' : '') + ') =====');
  }

  proposals.forEach(function (p) {
    if (p.how === 'set') totals.set++;
    else if (p.how === 'name') totals.name++;
    else if (p.how === 'span') totals.span++;
    else totals.none++;

    if (!only && already) return;
    var mark = p.tier ? String(p.tier) : '?';
    var how = p.how === 'set' ? '(already set)' : p.how ? '(' + p.how + ')' : '(NEEDS A DECISION)';
    console.log('  T' + mark + ' ' + how.padEnd(20) + p.text.slice(0, 72));
    if (p.sameLine) {
      console.log('       !! same-line marker: move it to its OWN line below the heading, or the');
      console.log('          class is dropped and the anchor is corrupted');
    }
    if (!p.existing && p.tier) console.log('       {: .hl-tier-' + p.tier + '}');
  });
});

console.log('');
console.log('reports scanned      ' + totals.reports + ' (' + totals.done + ' already fully marked)');
console.log('already set          ' + totals.set);
console.log('proposed by name     ' + totals.name);
console.log('proposed by span     ' + totals.span);
console.log('NEED A DECISION      ' + totals.none);
