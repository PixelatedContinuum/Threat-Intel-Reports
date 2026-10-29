#!/usr/bin/env node
'use strict';

/* Verifies a report's TAB marking, the input the tabbed report layout runs on
   (design-v4 section 3 and check 5.1; build-contract.md "Checks").

   The marker is a second kramdown BLOCK IAL on the line directly after the tier
   line:

       ## 13. MITRE ATT&CK Mapping
       {: .hl-tier-2}
       {: .hl-tab-chain}

   That form, and only that form, merges the tab class onto the h2 while leaving
   the generated anchor byte-identical. Three neighbouring forms are refused,
   each for a measured reason (design-v4 section 3, scout-workflow.md:16-44):

   - one merged line `{: .hl-tier-2 .hl-tab-chain}` is accepted by kramdown but
     FAILS check-tiers, whose TIER_RE requires the tier class alone on its line;
   - the tag on the heading line is treated as heading text, so the id becomes
     `13-mitre-attck-mapping--hl-tab-chain` and every old link to the section
     breaks;
   - a tab line anywhere but directly under the tier line attaches to whatever
     block precedes it, not to the heading, so the section silently keeps no tab.

   The vocabulary is fixed (TOKENS below). An unknown token is a FAIL, not a new
   tab: the layout only knows these seven.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. A report
   with no tab lines at all is PASS with a reason, exactly as check-tiers treats
   an unmarked report: it is simply not a tabbed report, and there is nothing to
   verify. A report with SOME sections tagged is FAIL, because the layout would
   put the untagged ones nowhere.

   The heading-id rule is here rather than in the browser check because it is a
   property of the markdown: no heading id may be `one-page` or `tab-<token>`,
   since those two names belong to the layout's own panels. The pilot's
   quasar-xworm-powershell report has `### Overview`, whose id is `overview`,
   which is exactly why panels carry the `tab-` prefix; this check keeps the
   prefix free. */

var fs = require('node:fs');
var path = require('node:path');
var CT = require('./lib/check-tiers.js');
var KS = require('./lib/kramdown-slug.js');

var TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];

var TAB_RE = /^\{:\s*\.hl-tab-([0-9A-Za-z_-]+)\s*\}\s*$/;
// Same-line forms, all of which kramdown declines to parse as an IAL on a heading.
var SAME_LINE_RE = /^#{2}\s+.*\{:?\s*\.hl-tab-[0-9A-Za-z_-]+\s*\}\s*$/;
// A tab class merged onto another IAL line (usually the tier line).
var MERGED_RE = /\{:[^}]*\.hl-tab-[0-9A-Za-z_-]+/;

var SAME_LINE_FIX = 'the tab marker must sit on its OWN line, directly after the tier line. ' +
  'kramdown does not parse a same-line brace on a heading as an IAL: it applies no class and ' +
  'slugs the brace text into the anchor, which breaks every link to that section.';

var RESERVED_PREFIX = 'tab-';
var RESERVED_ID = 'one-page';

function verdict(status, reason, extra) {
  var v = {
    status: status,
    reason: reason || null,
    problems: [],
    tagged: 0,
    unmarked: 0,
    byTab: {},
    sequence: [],
    advisories: []
  };
  TOKENS.forEach(function (t) { v.byTab[t] = 0; });
  Object.keys(extra || {}).forEach(function (k) { v[k] = extra[k]; });
  return v;
}

/* Every h2 in source order with the tab its following lines declare, the
   placement problem if it has one, and any heading-id collision in the file.

   Fenced blocks are skipped for the same reason check-tiers and
   kramdown-slug.js skip them: a quoted shell prompt is not a heading. */
function scanMarkdown(md) {
  var src = String(md).replace(/^---\r?\n[\s\S]*?\r?\n---/, '');
  var lines = src.split(/\r?\n/);
  var out = [];
  var fenced = false;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s*(```|~~~)/.test(line)) { fenced = !fenced; continue; }
    if (fenced) continue;

    var sameLine = SAME_LINE_RE.test(line);
    var h = line.match(/^##\s+(.*\S)\s*$/);
    if (!h) continue;

    if (sameLine) {
      out.push({
        text: h[1], tier: null, tab: null, placed: false,
        problems: ['"' + h[1] + '": ' + SAME_LINE_FIX]
      });
      continue;
    }

    /* The block under the heading: the next non-blank line and everything after
       it up to the next blank line. kramdown accepts a blank line between a
       block and its IAL, so the tier line is the next NON-BLANK line (same rule
       as check-tiers); the tab line must then be the very next line. */
    var run = [];
    var k = i + 1;
    while (k < lines.length && !lines[k].trim()) k++;
    while (k < lines.length && lines[k].trim()) { run.push({ index: k, line: lines[k] }); k++; }

    var tier = null, tierAt = -1;
    for (var r = 0; r < run.length; r++) {
      var tm = run[r].line.match(CT.TIER_RE);
      if (tm) { tier = tm[1]; tierAt = r; break; }
      // A merged IAL line carries both classes and matches no TIER_RE.
      if (MERGED_RE.test(run[r].line) && /\.hl-tier-/.test(run[r].line)) {
        tierAt = r;
        tier = (run[r].line.match(/\.hl-tier-([0-9A-Za-z_-]+)/) || [])[1] || null;
        break;
      }
    }

    var tabAt = -1, tab = null, tabCount = 0;
    var problems = [];
    for (var t = 0; t < run.length; t++) {
      if (MERGED_RE.test(run[t].line) && !TAB_RE.test(run[t].line)) {
        problems.push('"' + h[1] + '": the tab class is merged onto another IAL line ' +
          '("' + run[t].line.trim() + '"). kramdown accepts that, but check-tiers requires the ' +
          'tier class alone on its line, and the build contract puts the tab on the line ' +
          'DIRECTLY AFTER it. Write two lines.');
        tabCount++;
        continue;
      }
      var m = run[t].line.match(TAB_RE);
      if (m) {
        tabCount++;
        if (tabAt === -1) { tabAt = t; tab = m[1]; }
      }
    }

    if (tabCount > 1) {
      problems.push('"' + h[1] + '": ' + tabCount + ' tab lines sit under this heading; a section ' +
        'belongs to exactly one tab. Keep one.');
    }

    if (tabAt !== -1) {
      var expected = tierAt === -1 ? 0 : tierAt + 1;
      if (tabAt !== expected) {
        problems.push('"' + h[1] + '": the tab line is not directly after the tier line. ' +
          (tierAt === -1
            ? 'It must be the first line under the heading.'
            : 'It must be the line immediately after "' + run[tierAt].line.trim() + '"; ' +
              'kramdown attaches a line further down to the block above it, not to the heading.'));
      }
      // A tab line after the block's IAL group: attached to the body, not the heading.
      var later = -1;
      for (var s = k; s < lines.length; s++) {
        if (/^#{1,6}\s+/.test(lines[s])) break;
        if (/^\s*(```|~~~)/.test(lines[s])) break;
        if (TAB_RE.test(lines[s])) { later = s; break; }
      }
      if (later !== -1) {
        problems.push('"' + h[1] + '": a second tab line sits at line ' + (later + 1) +
          ' of the section body, where kramdown attaches it to the paragraph above it. ' +
          'Only the line directly after the tier line counts.');
      }
    }

    out.push({
      text: h[1],
      tier: tier,
      tab: tab,
      placed: tabAt !== -1 && problems.length === 0,
      problems: problems
    });
  }

  return { headings: out, ids: KS.headings(src) };
}

/* The rule set, shared by the markdown and DOM paths so they cannot drift. */
function validate(headings, ids, opts) {
  opts = opts || {};
  var problems = [];
  var advisories = [];
  var byTab = {};
  TOKENS.forEach(function (t) { byTab[t] = 0; });
  var tagged = 0;
  var unmarked = [];
  var sequence = [];

  headings.forEach(function (h) {
    (h.problems || []).forEach(function (p) { problems.push(p); });
    if (h.tab === null || h.tab === undefined) { unmarked.push(h.text); return; }
    if (TOKENS.indexOf(h.tab) === -1) {
      problems.push('"' + h.text + '" declares hl-tab-' + h.tab + ', and the only tokens are ' +
        TOKENS.join(', ') + '. The layout draws no panel for any other name.');
      return;
    }
    byTab[h.tab]++;
    tagged++;
    sequence.push({ tab: h.tab, text: h.text });
    if (!h.tier) {
      advisories.push('"' + h.text + '" carries a tab line but no tier line above it. The tab ' +
        'gate accepts that, but check-tiers will fail the section until it is tiered.');
    }
  });

  // Heading ids the layout owns. `one-page` is the one-page mode fragment and
  // `tab-<token>` is a panel id; a heading taking either one would capture the
  // link the layout emits.
  (ids || []).forEach(function (h) {
    if (h.slug === RESERVED_ID) {
      problems.push('heading "' + h.text + '" renders the id "' + RESERVED_ID + '", which the ' +
        'one-page mode owns. Rename the heading.');
    } else if (h.slug.indexOf(RESERVED_PREFIX) === 0) {
      problems.push('heading "' + h.text + '" renders the id "' + h.slug + '", which collides ' +
        'with the layout\'s own `tab-` panel ids. Rename the heading.');
    }
  });

  var total = headings.length;
  var anyTab = tagged > 0 || problems.length > 0;

  // Nothing tagged at all is not a defect: it is a report without tabs.
  if (!anyTab) {
    return verdict('PASS', 'no tab tags declared', {
      problems: [], tagged: 0, unmarked: unmarked.length, byTab: byTab,
      sequence: [], advisories: []
    });
  }

  /* All or nothing. A partly tagged report is the likely output of an
     interrupted backfill, and the layout would leave the untagged sections in
     no tab at all: on the tabbed page they would not be reachable. */
  if (unmarked.length) {
    problems.push(unmarked.length + ' of ' + total + ' sections carry no tab tag, so the tabbed ' +
      'page would put them in no tab: ' +
      unmarked.slice(0, 6).map(function (t) { return '"' + t + '"'; }).join(', ') +
      (unmarked.length > 6 ? ', and ' + (unmarked.length - 6) + ' more' : ''));
  }

  return verdict(problems.length ? 'FAIL' : 'PASS', null, {
    problems: problems,
    tagged: tagged,
    unmarked: unmarked.length,
    byTab: byTab,
    sequence: sequence,
    advisories: advisories
  });
}

function checkMarkdown(src, label) {
  var scan;
  try { scan = scanMarkdown(src); }
  catch (e) {
    return verdict('NOT CHECKED', 'report could not be scanned: ' +
      String(e.message).split('\n')[0]);
  }
  return validate(scan.headings, scan.ids, { label: label });
}

/* The rendered page carries the merged class, so placement cannot be re-checked
   here; all-or-none, the vocabulary and the id rule can, and those are what a
   stale build gets wrong. */
function checkDom(doc, label) {
  var body = doc.querySelector('.hl-post-content') || doc.body;
  if (!body) return verdict('NOT CHECKED', 'no report body container');

  var hs = body.querySelectorAll('h2');
  var headings = [];
  for (var i = 0; i < hs.length; i++) {
    var cls = String(hs[i].className || '');
    var m = cls.match(/\bhl-tab-([0-9A-Za-z_-]+)\b/);
    headings.push({ text: (hs[i].textContent || '').trim(), tab: m ? m[1] : null, placed: true });
  }

  var all = body.querySelectorAll('h1,h2,h3,h4,h5,h6');
  var ids = [];
  for (var j = 0; j < all.length; j++) {
    if (all[j].id) ids.push({ text: (all[j].textContent || '').trim(), slug: all[j].id });
  }

  var r = validate(headings, ids, { label: label });
  r.advisories.push('placement was not checked: the rendered page carries the merged class, so ' +
    'run this gate on the markdown for the line-directly-after-the-tier-line rule');
  return r;
}

module.exports = {
  TOKENS: TOKENS,
  TAB_RE: TAB_RE,
  scanMarkdown: scanMarkdown,
  validate: validate,
  checkMarkdown: checkMarkdown,
  checkDom: checkDom
};

/* Command line. Exit 0 PASS, 1 FAIL, 2 NOT CHECKED, as check-tiers.js does.
   --against exists for the same reason it does there: a URL check alone is
   vacuous in the minutes after a push, because Pages still serves the previous
   build and an untagged previous build passes truthfully. */
if (require.main === module) {
  var argv = process.argv.slice(2);
  var againstAt = argv.indexOf('--against');
  var against = againstAt !== -1 ? argv[againstAt + 1] : null;
  var target = argv.filter(function (a) {
    return a.indexOf('--') !== 0 && a !== against;
  })[0];
  if (!target) {
    console.error('usage: node check-tabs.js <report.md|https://...> [--against <report.md>]');
    process.exit(2);
  }

  function report(r, label) {
    var tail = r.status === 'PASS'
      ? (r.reason || r.tagged + ' sections tagged (' + TOKENS.filter(function (t) {
        return r.byTab[t] > 0;
      }).map(function (t) { return t + ' ' + r.byTab[t]; }).join(', ') + ')')
      : r.status === 'NOT CHECKED' ? r.reason : r.problems.join('; ');
    console.log(r.status.padEnd(12) + ' ' + label + '   ' + tail);
    if (r.sequence && r.sequence.length) {
      console.log('  tab sequence (document order): ' + r.sequence.map(function (s) {
        return s.tab + ' ' + s.text;
      }).join(' | '));
    }
    (r.advisories || []).forEach(function (a) { console.log('  ADVISORY: ' + a); });
  }

  (async function () {
    var r;
    if (/^https?:\/\//.test(target)) {
      var JSDOM;
      try { JSDOM = require('jsdom').JSDOM; }
      catch (e) {
        console.log('NOT CHECKED  ' + target + '  jsdom did not load: ' +
          String(e.message).split('\n')[0] + '. Run npm ci in tools/report-tooling.');
        process.exit(2);
      }
      var html;
      try {
        var res = await fetch(target);
        if (!res.ok) { console.log('NOT CHECKED  ' + target + '  HTTP ' + res.status); process.exit(2); }
        html = await res.text();
      } catch (e) {
        console.log('NOT CHECKED  ' + target + '  ' + e.message);
        process.exit(2);
      }
      r = checkDom(new JSDOM(html).window.document, target);
      if (against && r.status === 'PASS') {
        var expected;
        try { expected = checkMarkdown(fs.readFileSync(against, 'utf8'), against); }
        catch (e) {
          console.log('NOT CHECKED  ' + target + '  --against source could not be read: ' + e.message);
          process.exit(2);
        }
        if (expected.tagged !== r.tagged) {
          console.log('NOT CHECKED  ' + target + '   the page tags ' + r.tagged +
            ' sections while ' + against + ' tags ' + expected.tagged +
            '. The published build is almost certainly older than the source; ' +
            'wait for the Pages build and run this again.');
          process.exit(2);
        }
      }
    } else {
      var src;
      try { src = fs.readFileSync(target, 'utf8'); }
      catch (e) { console.log('NOT CHECKED  ' + target + '  ' + e.message); process.exit(2); }
      r = checkMarkdown(src, target);
    }
    report(r, target);
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
