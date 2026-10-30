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

   THE TRIGGER IS A CLASS ON AN h2, NOT THE BARE STRING (fix round 2). The
   layout's trigger is a complete `hl-tab-<token>` class on an `<h2>` opening tag
   in the rendered content (build-contract.md line 12, `_layouts/post.html`), so
   the checker cannot afford to read only the IAL form for PLACEMENT: a tab line
   after a blank line, a tab line in a section body, a tab line under a
   blank-separated heading, a tab class merged onto the tier line and a tab brace
   on the heading line all FAIL, because kramdown puts the class on a paragraph,
   on the wrong element or into the anchor, and the heading keeps no tab. Every
   line outside a fenced block is read and every occurrence of the marker is
   classified, with its line number and what kramdown does with it.

   A report that merely WRITES the string `hl-tab-` in prose or in a fenced block
   is an ADVISORY, not a FAIL. The layout keys on the class kramdown emits, not on
   the substring, so a sentence quoting `hl-tab-chain` in a paragraph or a shell
   prompt renders as ordinary text and the page stays on the old layout. The
   round-1 checker FAILed it on the strength of a substring trigger the layout no
   longer has (round-2 review F2, P3). The advisory names the line so a writer can
   see that no class is applied there.

   The vocabulary is fixed (TOKENS below). An unknown token is a FAIL, not a new
   tab: the layout only knows these seven.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. A report
   with no tab marking anywhere is PASS with a reason, exactly as check-tiers
   treats an unmarked report: it is simply not a tabbed report, and there is
   nothing to verify. A report with SOME sections tagged is FAIL, because the
   layout would put the untagged ones nowhere.

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
var SAME_LINE_RE = /^#{1,6}\s+.*\{:?\s*\.hl-tab-[0-9A-Za-z_-]+\s*\}\s*$/;
// A tab class merged onto another IAL line (usually the tier line).
var MERGED_RE = /\{:[^}]*\.hl-tab-/;
// Any occurrence at all: the layout's trigger, and the reason every line is read.
var ANY_RE = /hl-tab-/;

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
    misplaced: [],
    advisories: []
  };
  TOKENS.forEach(function (t) { v.byTab[t] = 0; });
  Object.keys(extra || {}).forEach(function (k) { v[k] = extra[k]; });
  return v;
}

/* Every h2 in source order with the tab declared on the line the contract puts
   it, every `hl-tab-` occurrence that is somewhere else (with its line), and any
   heading-id collision in the file.

   Fenced blocks are skipped for the same reason check-tiers and
   kramdown-slug.js skip them: a quoted shell prompt is not a heading. */
function scanMarkdown(md) {
  var src = String(md);
  var offset = 0;
  var fm = src.match(/^---\r?\n[\s\S]*?\r?\n---/);
  if (fm) {
    // Replaced by its own newlines so a reported line number is the file's.
    offset = (fm[0].match(/\n/g) || []).length;
    src = src.slice(fm[0].length);
  }
  var lines = src.split(/\r?\n/);
  function at(i) { return i + offset + 1; }

  var fenced = new Array(lines.length);
  var inFence = false;
  for (var f = 0; f < lines.length; f++) {
    if (/^\s*(```|~~~)/.test(lines[f])) { fenced[f] = true; inFence = !inFence; continue; }
    fenced[f] = inFence;
  }

  function isHeading(i) { return /^##\s+\S/.test(lines[i] || ''); }
  function headingText(i) {
    var m = (lines[i] || '').match(/^##\s+(.*\S)\s*$/);
    return m ? m[1] : (lines[i] || '').trim();
  }

  var placed = {};          // line index -> { heading: line index, token }
  var misplaced = [];       // { line, why }
  var advisories = [];
  var fencedMentions = [];

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!ANY_RE.test(line)) continue;
    if (fenced[i]) { fencedMentions.push(at(i)); continue; }

    // A heading line carrying the brace: kramdown keeps it as heading text.
    if (SAME_LINE_RE.test(line)) {
      misplaced.push({
        line: at(i),
        why: '"' + headingText(i) + '": ' + SAME_LINE_FIX
      });
      continue;
    }
    if (/^#{1,6}\s+/.test(line)) {
      // Not an IAL brace (that case is above): the marker is plain text in a
      // heading. kramdown applies no class from heading text, so the page stays
      // untabbed; the string is visible in the heading and its anchor.
      advisories.push('the string "hl-tab-" is written in the heading at line ' + (at(i)) +
        '. kramdown applies no class from heading text, so this does not tab the page; ' +
        'the string is part of the heading text and its anchor.');
      continue;
    }

    if (TAB_RE.test(line)) {
      var token = line.match(TAB_RE)[1];
      // A second tab line directly under the first: both apply to the heading,
      // and a section belongs to exactly one tab.
      if (placed[i - 1]) {
        misplaced.push({
          line: at(i),
          why: 'the tab line at line ' + (at(i)) + ' is a second tab line under the same heading; ' +
            'a section belongs to exactly one tab'
        });
        continue;
      }
      if (i >= 1 && isHeading(i - 1)) {
        placed[i] = { heading: i - 1, token: token };
        continue;
      }
      if (i >= 2 && CT.TIER_RE.test(lines[i - 1]) && isHeading(i - 2)) {
        placed[i] = { heading: i - 2, token: token };
        continue;
      }
      // Everything else is misplaced, and the message names what the render does.
      var above = -1;
      if (i >= 2 && CT.TIER_RE.test(lines[i - 1])) above = i - 2;
      else if (i >= 1) above = i - 1;
      var aboveLine = above === -1 ? '' : (lines[above] || '');
      var why;
      if (/^(###|####|#####|######)\s/.test(aboveLine)) {
        why = 'the tab line at line ' + (at(i)) + ' sits under an h3 ("' + aboveLine.trim() + '"); ' +
          'tabs work on `##` chapters, so no panel is drawn for this section';
      } else if (i >= 2 && CT.TIER_RE.test(lines[i - 1]) && !lines[i - 2].trim()) {
        why = 'the tab line at line ' + (at(i)) + ' follows the tier line, but a blank line sits ' +
          'between the heading and that tier line (line ' + (at(i - 1)) + '), so kramdown attaches both ' +
          'classes to the paragraph below the heading and the heading keeps none';
      } else if (i >= 1 && !lines[i - 1].trim()) {
        why = 'the tab line at line ' + (at(i)) + ' is separated from the block above it by a blank ' +
          'line, so kramdown attaches the class to the next paragraph and the heading keeps no tab';
      } else {
        why = 'the tab line at line ' + (at(i)) + ' is not directly after the heading or its tier ' +
          'line, so kramdown attaches the class to the block above it and no heading gets a tab';
      }
      misplaced.push({ line: at(i), why: why });
      continue;
    }

    // Not a tab IAL line, but the marker string is present. A tab class merged
    // onto another IAL line still FAILs (check-tiers requires the tier class
    // alone, and the contract puts the tab on its own line). Any other
    // occurrence is prose: kramdown applies no class there, so it does not tab
    // the page and is an ADVISORY, not a FAIL.
    if (MERGED_RE.test(line) && /\.hl-tier-/.test(line)) {
      misplaced.push({
        line: at(i),
        why: 'the tab class is merged onto the tier line at line ' + (at(i)) + ' ("' + line.trim() +
          '"). kramdown accepts that, but check-tiers requires the tier class alone on its line, ' +
          'and the build contract puts the tab on the line DIRECTLY AFTER it. Write two lines.'
      });
    } else {
      advisories.push('the string "hl-tab-" appears at line ' + (at(i)) + ' in text that is not a ' +
        'tab IAL line ("' + line.trim().slice(0, 80) + '"). kramdown applies no class there, so ' +
        'the layout does not treat the report as tabbed: this is prose or code, not a tab tag.');
    }
  }

  if (fencedMentions.length) {
    advisories.push('the string "hl-tab-" appears in a fenced block at line(s) ' +
      fencedMentions.slice(0, 6).join(', ') + (fencedMentions.length > 6
        ? ' and ' + (fencedMentions.length - 6) + ' more' : '') +
      '. No class is applied there, so this is code, not a tab tag, and the page stays untabbed.');
  }

  var out = [];
  for (var h = 0; h < lines.length; h++) {
    if (fenced[h] || !isHeading(h)) continue;

    var tier = (CT.TIER_RE.test(lines[h + 1] || '')) ? (lines[h + 1].match(CT.TIER_RE)[1]) : null;
    // A tier line that exists but is separated from its heading by a blank line:
    // kramdown attaches both classes to the paragraph below, so the heading keeps
    // neither. propose-tabs must not write a tab line there and report success.
    var tierDetached = tier === null && /^\s*$/.test(lines[h + 1] || '') &&
      CT.TIER_RE.test(lines[h + 2] || '');
    var tabLine = -1;
    if (tier !== null && placed[h + 2]) tabLine = h + 2;
    else if (tier === null && placed[h + 1]) tabLine = h + 1;

    out.push({
      text: headingText(h),
      line: at(h),
      tier: tier,
      tierDetached: tierDetached,
      tab: tabLine === -1 ? null : placed[tabLine].token,
      placed: tabLine !== -1
    });
  }

  return { headings: out, ids: KS.headings(src), misplaced: misplaced, advisories: advisories };
}

/* The rule set, shared by the markdown and DOM paths so they cannot drift. */
function validate(headings, ids, opts) {
  opts = opts || {};
  var problems = [];
  var advisories = (opts.advisories || []).slice();
  var byTab = {};
  TOKENS.forEach(function (t) { byTab[t] = 0; });
  var tagged = 0;
  var unmarked = [];
  var sequence = [];

  /* Placement problems come first and always FAIL: they are the difference
     between "the class is on the h2" and "kramdown put it on a paragraph while
     the layout went tabbed". */
  (opts.misplaced || []).forEach(function (m) { problems.push(m.why); });

  headings.forEach(function (h) {
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
  var misplaced = (opts.misplaced || []).length;
  var anyTab = tagged > 0 || misplaced > 0 || problems.length > 0;

  /* --require (T-0500.1.9, J1): the tabbed layout is the default for a new
     report, so a report with no tab tag at all is a FAIL, not "a report without
     tabs". A report with no sections is the same failure: nothing was scanned. */
  if (opts.require && !anyTab) {
    return verdict('FAIL', null, {
      problems: [total
        ? 'no tab tags declared: 0 of ' + total + ' sections carry a {: .hl-tab-...} line, and ' +
          '--require says a new report is tabbed. Run propose-tabs.js <index.md> --write, then ' +
          'check every proposal.'
        : '--require was given and the report has no ## sections to tag'],
      tagged: 0, unmarked: unmarked.length, byTab: byTab, sequence: [], advisories: advisories
    });
  }

  // Nothing tagged at all is not a defect: it is a report without tabs.
  if (!anyTab) {
    return verdict('PASS', 'no tab tags declared', {
      problems: [], tagged: 0, unmarked: unmarked.length, byTab: byTab,
      sequence: [], advisories: advisories
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
    misplaced: opts.misplaced || [],
    advisories: advisories
  });
}

function checkMarkdown(src, label, opts) {
  var scan;
  try { scan = scanMarkdown(src); }
  catch (e) {
    return verdict('NOT CHECKED', 'report could not be scanned: ' +
      String(e.message).split('\n')[0]);
  }
  return validate(scan.headings, scan.ids, {
    label: label, misplaced: scan.misplaced, advisories: scan.advisories,
    require: !!(opts && opts.require)
  });
}

/* The rendered page carries the merged class, so placement cannot be re-checked
   line by line here; all-or-none, the vocabulary, the id rule and a tab class on
   a non-heading element can, and those are what a stale build gets wrong. */
function checkDom(doc, label, opts) {
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

  /* The rendered counterpart of the markdown rule: a tab class the merge put on
     anything but an h2 is the shape the round-1 probes produced. */
  var misplaced = [];
  var carrying = body.querySelectorAll('[class*="hl-tab-"]');
  for (var k = 0; k < carrying.length; k++) {
    if (String(carrying[k].tagName).toLowerCase() !== 'h2') {
      misplaced.push({
        line: null,
        why: 'a rendered <' + String(carrying[k].tagName).toLowerCase() + '> carries the tab class "' +
          String(carrying[k].className) + '"; kramdown applied the marker to a block that is not ' +
          'the section heading, so the section itself has no tab'
      });
    }
  }

  var r = validate(headings, ids, { label: label, misplaced: misplaced, require: !!(opts && opts.require) });
  r.advisories.push('placement was not checked line by line: the rendered page carries the merged ' +
    'class, so run this gate on the markdown for the line-directly-after-the-tier-line rule');
  return r;
}

module.exports = {
  TOKENS: TOKENS,
  TAB_RE: TAB_RE,
  MERGED_RE: MERGED_RE,
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
  var requireTabs = argv.indexOf('--require') !== -1;
  var target = argv.filter(function (a) {
    return a.indexOf('--') !== 0 && a !== against;
  })[0];
  if (!target) {
    console.error('usage: node check-tabs.js [--require] <report.md|report folder|https://...> [--against <report.md>]');
    console.error('  --require  a report that declares no tab tags is a FAIL (exit 1), not a PASS:');
    console.error('             use it on every NEW report, which ships tabbed.');
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
      r = checkDom(new JSDOM(html).window.document, target, { require: requireTabs });
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
      var file = target;
      try { if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.md'); }
      catch (e) { /* the read below names the problem */ }
      try { src = fs.readFileSync(file, 'utf8'); }
      catch (e) { console.log('NOT CHECKED  ' + target + '  ' + e.message); process.exit(2); }
      r = checkMarkdown(src, target, { require: requireTabs });
    }
    report(r, target);
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
