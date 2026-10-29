#!/usr/bin/env node
'use strict';

/* Authoring aid for the report TAB markers (design-v4 section 3, E2): prints
   every h2 of a report in order with a proposed tab, how that proposal was
   reached, and the exact line to paste under the tier line.

   It proposes; it never decides. The writer keeps or overrides every line, the
   same contract propose-tiers.js runs under.

   Three proposal sources, always labelled so the writer can see what they are
   trusting:

     name   the default mapping in design-v4 section 3: heading text against the
            seven tabs' own vocabulary (BLUF/Executive Summary to Overview,
            Infrastructure/Timeline to Infrastructure and timeline, and so on)
     tier3  a Tier 3 section is a capability or walkthrough teardown, and the
            design puts those in the Attack chain tab. This is the weakest of
            the three and is labelled as such: a Tier 3 section that is really a
            victim teardown needs the writer to move it.
     span   the corpus shape, as in propose-tiers: an unnamed heading sitting
            between two placed neighbours on the SAME tab inherits it. Nothing
            else is guessed.

   Anything still unresolved prints "?" and is COUNTED in the summary, because a
   silent zero would make an interrupted pass look finished. `check-tabs.js`
   fails a report with any untagged section, so the count is also the work left.

   --write inserts the lines. It is idempotent (an existing tab line is left
   alone, so a writer's override survives a re-run) and it refuses to write a
   list it cannot place in full, naming the sections that need a decision: a
   partial write leaves a report the tab gate fails, which is the designed
   workflow but must never look like a finished backfill. */

var fs = require('node:fs');
var path = require('node:path');
var CT = require('./lib/check-tiers.js');
var TT = require('./check-tabs.js');

var ROOT = path.join(__dirname, '..', '..');
var REPORTS = path.join(ROOT, 'reports');

/* The design-v4 section 3 default mapping, most specific first. Order is
   load-bearing: "Executive Summary" must reach Overview before the confidence
   rule sees "Summary", and "MITRE ATT&CK Mapping" must reach Attack chain
   before any generic rule sees "Mapping". */
var RULES = [
  // Attack chain: the tradecraft and its walkthroughs.
  ['chain', /technical classification/],
  ['chain', /attack chain/],
  ['chain', /kill chain/],
  ['chain', /\bmitre\b/],
  ['chain', /\batt&?ck\b/],
  ['chain', /process tree/],
  ['chain', /walk[- ]?through/],
  ['chain', /teardown/],
  ['chain', /capabilit(y|ies)/],
  ['chain', /exploitation|exploit(ed|ation)? mechanics/],
  ['chain', /\btactics\b|\bttps?\b/],

  // Victims and impact. Deliberately NOT a bare /victim/: the pilot's section 10
  // is "The Finance Secretariat, the Saved-Page Victims and the Suppliers", a
  // walkthrough whose subtitle names victims, and the pilot maps it to the
  // Attack chain. "victim grading" is the design's own wording.
  ['victims', /victim grading/],
  ['victims', /victimolog/],
  ['victims', /^victims?$/],
  ['victims', /^the victims$/],
  ['victims', /victim (count|tally|list|table|overview|population)/],
  ['victims', /who (was|were) hit/],
  ['victims', /how far .*got/],
  ['victims', /notification/],
  ['victims', /affected (organi[sz]ations?|parties|sectors?)/],
  ['victims', /\bimpact\b/],

  // Infrastructure and timeline.
  ['timeline', /infrastructure/],
  ['timeline', /timeline/],
  ['timeline', /chronolog/],
  ['timeline', /public record/],
  ['timeline', /\bhosting\b/],
  ['timeline', /\bdomains?\b/],

  // Attribution.
  ['attribution', /threat actor/],
  ['attribution', /actor assessment/],
  ['attribution', /attribution/],

  // Indicators and detections.
  ['indicators', /indicators? of compromise/],
  ['indicators', /\biocs?\b/],
  ['indicators', /detection/],
  ['indicators', /hunting/],
  ['indicators', /response guidance/],
  ['indicators', /response orientation/],
  ['indicators', /defen[cs]e|defender|hardening/],
  ['indicators', /\bmitigations?\b/],
  ['indicators', /sigma|suricata|yara/],

  // Confidence and gaps: the reference apparatus.
  ['confidence', /confidence/],
  ['confidence', /\bgaps?\b/],
  ['confidence', /caveat/],
  ['confidence', /references?/],
  ['confidence', /appendi(x|ces)/],
  ['confidence', /acknowledg/],
  ['confidence', /\bsources?\b/],
  ['confidence', /methodology/],
  ['confidence', /limitations?/],
  ['confidence', /calibration/],
  ['confidence', /further reading/],
  ['confidence', /^license$|^licen[cs]e\b/],

  // Overview, last because its names are the most generic.
  ['overview', /\bbluf\b/],
  ['overview', /bottom line up front/],
  ['overview', /operational brief/],
  ['overview', /executive (summary|overview)/],
  ['overview', /key takeaways/],
  ['overview', /risk assessment/],
  ['overview', /business impact/],
  ['overview', /^overview$/],
  ['overview', /^summary$/]
];

function byName(text) {
  var s = String(text).toLowerCase();
  for (var i = 0; i < RULES.length; i++) if (RULES[i][1].test(s)) return RULES[i][0];
  return null;
}

/* An unplaced heading between two placed neighbours on the SAME tab inherits it.
   Deliberately conservative: a heading between two different tabs gets nothing,
   because that boundary is exactly what the writer has to decide. */
function bySpan(proposals, i) {
  var before = null, after = null;
  for (var a = i - 1; a >= 0; a--) if (proposals[a].tab) { before = proposals[a].tab; break; }
  for (var b = i + 1; b < proposals.length; b++) if (proposals[b].tab) { after = proposals[b].tab; break; }
  if (before && after && before === after) return before;
  return null;
}

function proposeFor(md) {
  var scan = TT.scanMarkdown(md);
  var proposals = scan.headings.map(function (h) {
    return {
      text: h.text,
      tier: h.tier,
      existing: h.tab,
      sameLine: /^#{2}\s+.*\{:?\s*\.hl-tab-/.test('## ' + h.text),
      tab: null,
      how: null
    };
  });

  proposals.forEach(function (p) {
    if (p.existing) { p.tab = p.existing; p.how = 'set'; return; }
    var n = byName(p.text);
    if (n) { p.tab = n; p.how = 'name'; }
  });

  proposals.forEach(function (p) {
    if (p.tab) return;
    if (String(p.tier) === '3') { p.tab = 'chain'; p.how = 'tier3'; }
  });

  proposals.forEach(function (p, i) {
    if (p.tab) return;
    var s = bySpan(proposals, i);
    if (s) { p.tab = s; p.how = 'span'; }
  });

  return proposals;
}

/* --write inserts the markers, from the bottom up so earlier line numbers stay
   valid. A heading that already carries a tab line keeps it. */
function writeTabs(file, proposals) {
  var md = fs.readFileSync(file, 'utf8');
  var lines = md.split(/\r?\n/);
  var fenced = false;
  var heads = [];
  var frontEnd = -1;
  for (var f = 1; f < lines.length; f++) { if (lines[f] === '---') { frontEnd = f; break; } }
  for (var i = frontEnd + 1; i < lines.length; i++) {
    if (/^\s*(```|~~~)/.test(lines[i])) { fenced = !fenced; continue; }
    if (fenced) continue;
    if (/^##\s+\S/.test(lines[i])) heads.push(i);
  }

  if (heads.length !== proposals.length) {
    console.error('refusing to write: ' + file + ' has ' + heads.length +
      ' sections but ' + proposals.length + ' were proposed. Re-run and check the file.');
    return { error: true };
  }

  var added = 0, kept = 0, unplaced = 0;
  for (var h = heads.length - 1; h >= 0; h--) {
    var p = proposals[h];
    var at = heads[h];
    if (p.existing) { kept++; continue; }
    if (!p.tab) { unplaced++; continue; }

    // After the tier line when there is one, directly after the heading when
    // there is not (check-tabs.js reports the missing tier as an advisory).
    var insertAt = at + 1;
    var j = at + 1;
    while (j < lines.length && !lines[j].trim()) j++;
    if (j < lines.length && CT.TIER_RE.test(lines[j])) insertAt = j + 1;
    else insertAt = at + 1; // no tier line: directly under the heading

    lines.splice(insertAt, 0, '{: .hl-tab-' + p.tab + '}');
    added++;
  }
  fs.writeFileSync(file, lines.join('\n'), 'utf8');
  return { added: added, kept: kept, unplaced: unplaced };
}

function main() {
  var args = process.argv.slice(2);
  var write = args.indexOf('--write') !== -1;
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

  var totals = { set: 0, name: 0, tier3: 0, span: 0, none: 0, reports: 0, done: 0, headings: 0 };
  var unplacedAll = [];

  slugs.forEach(function (slug) {
    var file = path.join(REPORTS, slug, 'index.md');
    if (!fs.existsSync(file)) return;
    var md = fs.readFileSync(file, 'utf8');
    var proposals = proposeFor(md);
    if (!proposals.length) return;

    totals.reports++;
    totals.headings += proposals.length;
    var already = proposals.every(function (p) { return p.existing; });
    if (already) totals.done++;

    if (write && (only || !already)) {
      var w = writeTabs(file, proposals);
      if (w.error) process.exit(1);
      console.log(slug + ': ' + w.added + ' tab lines written, ' + w.kept +
        ' already present, ' + w.unplaced + ' left unplaced');
      if (w.unplaced) {
        console.log('  WARNING: ' + w.unplaced + ' section(s) got no line, so check-tabs.js will ' +
          'FAIL this report until a writer tags them.');
      }
      return;
    }

    if (only || !already) {
      console.log('');
      console.log('===== ' + slug + '  (' + proposals.length + ' sections' +
        (already ? ', already tagged' : '') + ') =====');
    }

    proposals.forEach(function (p) {
      if (p.how === 'set') totals.set++;
      else if (p.how === 'name') totals.name++;
      else if (p.how === 'tier3') totals.tier3++;
      else if (p.how === 'span') totals.span++;
      else {
        totals.none++;
        unplacedAll.push({ slug: slug, text: p.text });
      }

      if (!only && already) return;
      var mark = p.tab || '?';
      var how = p.how === 'set' ? '(already set)' : p.how ? '(' + p.how + ')' : '(NEEDS A DECISION)';
      console.log('  ' + mark.padEnd(12) + how.padEnd(20) + p.text.slice(0, 72));
      if (p.sameLine) {
        console.log('       !! same-line marker: move it to its OWN line below the tier line, or the');
        console.log('          class is dropped and the anchor is corrupted');
      }
      if (!p.existing && p.tab) console.log('       {: .hl-tab-' + p.tab + '}');
    });
  });

  if (write) {
    console.log('');
    console.log('reports written      ' + totals.reports);
    return;
  }

  console.log('');
  console.log('reports scanned      ' + totals.reports + ' (' + totals.done + ' already fully tagged)');
  console.log('sections             ' + totals.headings);
  console.log('already set          ' + totals.set);
  console.log('proposed by name     ' + totals.name);
  console.log('proposed as tier 3   ' + totals.tier3);
  console.log('proposed by span     ' + totals.span);
  console.log('NEED A DECISION      ' + totals.none);
  if (unplacedAll.length) {
    console.log('');
    console.log('headings the script could not place:');
    unplacedAll.forEach(function (u) { console.log('  ' + u.slug + '  ' + u.text); });
  }
}

module.exports = {
  TOKENS: TT.TOKENS,
  RULES: RULES,
  byName: byName,
  bySpan: bySpan,
  proposeFor: proposeFor,
  writeTabs: writeTabs
};

if (require.main === module) main();
