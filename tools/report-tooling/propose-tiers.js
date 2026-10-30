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
var RT = require('./lib/report-target.js');

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
var applyAt = args.indexOf('--apply');
var applyList = applyAt !== -1 ? args[applyAt + 1] : null;
var only = args.filter(function (a) {
  return a.indexOf('--') !== 0 && a !== applyList;
})[0];

/* --apply writes the markers. It takes the tier for EVERY h2 in order, and
   refuses a list whose length does not match, because a short list would mark
   the wrong sections and a silent partial pass is the defect the gate exists to
   catch. Idempotent: a heading that already carries a marker is left alone. */
function applyTiers(slug, list, file) {
  var md = fs.readFileSync(file, 'utf8');
  var tiers = String(list).split(',').map(function (t) { return t.trim(); });

  var lines = md.split(/\r?\n/);
  var fenced = false;
  var seen = 0;
  var frontEnd = -1;
  for (var f = 1; f < lines.length; f++) { if (lines[f] === '---') { frontEnd = f; break; } }

  var heads = [];
  for (var i = frontEnd + 1; i < lines.length; i++) {
    if (/^\s*(```|~~~)/.test(lines[i])) { fenced = !fenced; continue; }
    if (fenced) continue;
    if (/^##\s+\S/.test(lines[i])) heads.push(i);
  }

  if (heads.length !== tiers.length) {
    console.error('refusing to apply: ' + slug + ' has ' + heads.length +
      ' sections but ' + tiers.length + ' tiers were given');
    process.exit(1);
  }
  for (var t = 0; t < tiers.length; t++) {
    if (!/^[123]$/.test(tiers[t])) {
      console.error('refusing to apply: "' + tiers[t] + '" is not 1, 2 or 3');
      process.exit(1);
    }
  }

  // Insert from the bottom up so earlier indices stay valid.
  var added = 0, skipped = 0;
  for (var h = heads.length - 1; h >= 0; h--) {
    var at = heads[h];
    var next = lines[at + 1] === undefined ? '' : lines[at + 1];
    if (/^\{:\s*\.hl-tier-[123]\s*\}\s*$/.test(next.trim())) { skipped++; continue; }
    lines.splice(at + 1, 0, '{: .hl-tier-' + tiers[h] + '}');
    added++;
  }
  fs.writeFileSync(file, lines.join('\n'), 'utf8');
  console.log(slug + ': ' + added + ' markers written, ' + skipped + ' already present');
}

/* A bare --write, or --apply with no target, refuses (T-0500.1.9, audit R01):
   neither may run across the corpus. --write is not a mode of this tool; the
   writing mode is --apply <tiers>. */
if (args.indexOf('--write') !== -1) {
  console.error('refusing --write: propose-tiers.js writes with --apply <comma list of tiers> ' +
    'and a named target, never across the corpus.');
  process.exit(2);
}
if (applyAt !== -1 && !applyList) {
  console.error('refusing --apply with no tier list: --apply <comma list of 1, 2 or 3, one per section>.');
  process.exit(2);
}
if ((applyAt !== -1) && !only) {
  console.error('refusing --apply with no target: name one report (path to index.md or folder name).');
  process.exit(2);
}

var targets;
if (only) {
  var t = RT.resolveTarget(only, REPORTS);
  if (t.error) { console.error(t.error); process.exit(2); }
  if (!fs.existsSync(t.file)) { console.error('no index.md at ' + t.file); process.exit(2); }
  targets = [t];
} else {
  targets = fs.readdirSync(REPORTS, { withFileTypes: true })
    .filter(function (e) { return e.isDirectory(); })
    .map(function (e) { return e.name; })
    .sort()
    .map(function (n) { return { mode: 'name', slug: n, file: path.join(REPORTS, n, 'index.md') }; });
}

if (applyList) {
  applyTiers(targets[0].mode === 'path' ? targets[0].file : targets[0].slug, applyList, targets[0].file);
  process.exit(0);
}

var totals = { set: 0, name: 0, span: 0, none: 0, reports: 0, done: 0 };

targets.forEach(function (target) {
  var slug = target.mode === 'path' ? target.file : target.slug;
  var file = target.file;
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
