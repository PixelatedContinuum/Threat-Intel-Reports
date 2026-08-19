'use strict';

/* Verifies a report's register-tier marking, the input the Brief / Analyst / Full
   switch runs on.

   The marker is a kramdown BLOCK IAL on the line after each h2:

       ## 4. The Wider Target Landscape
       {: .hl-tier-2}

   That form, and only that form, applies the class while leaving the generated
   anchor byte-identical. Every same-line variant (`## H {: .c}`, `## H {.c}`)
   applies NO class and slugs the brace text straight into the id, which would
   silently rewrite anchors across the corpus and break every figure_nav chip and
   every reader's heading permalink. Measured on a live probe page, not inferred,
   and it is the single most expensive mistake this convention invites, so it has
   its own check and its own message.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. A report
   with no markers at all is PASS with a reason: the switch simply does not
   render, and there is nothing to verify. */

var path = require('node:path');
var fs = require('node:fs');

var TIER_RE = /^\{:\s*\.hl-tier-([0-9A-Za-z_-]+)\s*\}\s*$/;
// Same-line forms, both of which kramdown declines to parse as an IAL on a heading.
var SAME_LINE_RE = /^(#{2})\s+.*\{:?\s*\.hl-tier-[0-9A-Za-z_-]+\s*\}\s*$/;
var VALID = { '1': 1, '2': 1, '3': 1 };

var SAME_LINE_FIX = 'the marker must sit on the FOLLOWING line, on its own. ' +
  'kramdown does not parse a same-line brace on a heading as an IAL: it applies no ' +
  'class and slugs the brace text into the anchor, which breaks every link to that ' +
  'section.';

function verdict(status, reason, problems, marked, byTier, unmarked) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    marked: marked || 0,
    unmarked: unmarked || 0,
    byTier: byTier || { 1: 0, 2: 0, 3: 0 }
  };
}

/* Every h2 in source order with the tier its following line declares, plus any
   same-line misuse spotted on the way. Fenced blocks are skipped for the same
   reason kramdown-slug.js skips them: a quoted shell prompt is not a heading. */
function scanMarkdown(md) {
  var lines = String(md).split(/\r?\n/);
  var out = [];
  var sameLine = [];
  var fenced = false;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s*(```|~~~)/.test(line)) { fenced = !fenced; continue; }
    if (fenced) continue;

    if (SAME_LINE_RE.test(line)) {
      sameLine.push(line.replace(/^##\s+/, '').trim());
      out.push({ text: line.replace(/^##\s+/, '').trim(), tier: null, sameLine: true });
      continue;
    }

    var h = line.match(/^##\s+(.*\S)\s*$/);
    if (!h) continue;

    // The marker is the next NON-BLANK line. kramdown accepts a blank line
    // between a block and its IAL, so the checker does too.
    var tier = null;
    for (var j = i + 1; j < lines.length; j++) {
      if (!lines[j].trim()) continue;
      var m = lines[j].match(TIER_RE);
      if (m) tier = m[1];
      break;
    }
    out.push({ text: h[1], tier: tier, sameLine: false });
  }
  return { headings: out, sameLine: sameLine };
}

/* The rule set, shared by both paths so they cannot drift. */
function validate(headings) {
  var problems = [];
  var byTier = { 1: 0, 2: 0, 3: 0 };
  var marked = 0;
  var unmarked = [];

  headings.forEach(function (h) {
    if (h.sameLine) {
      problems.push('"' + h.text + '": ' + SAME_LINE_FIX);
      return;
    }
    if (h.tier === null) { unmarked.push(h.text); return; }
    if (!VALID[h.tier]) {
      problems.push('"' + h.text + '" declares hl-tier-' + h.tier +
        ', and the only values are hl-tier-1, hl-tier-2 and hl-tier-3');
      return;
    }
    byTier[h.tier]++;
    marked++;
  });

  var total = headings.length;

  // Nothing marked at all is not a defect, it is a report without the switch.
  if (!marked && !problems.length) {
    return { status: 'PASS', reason: 'no tier markers declared', problems: [],
             marked: 0, unmarked: unmarked.length, byTier: byTier };
  }

  /* All or nothing. A partly marked report is the likely output of an
     interrupted backfill, and it renders a Brief view that silently drops
     whichever sections were never reached. */
  if (unmarked.length) {
    problems.push(unmarked.length + ' of ' + total + ' sections carry no tier marker, so a ' +
      'filtered view would silently drop them: ' +
      unmarked.slice(0, 6).map(function (t) { return '"' + t + '"'; }).join(', ') +
      (unmarked.length > 6 ? ', and ' + (unmarked.length - 6) + ' more' : ''));
  }

  if (marked && !byTier[1]) {
    problems.push('no section is marked Tier 1, so the Brief view would render an empty page');
  }

  var distinct = [1, 2, 3].filter(function (t) { return byTier[t] > 0; }).length;
  if (marked && distinct < 2) {
    problems.push('every marked section is the same tier, so Brief, Analyst and Full would be ' +
      'identical and the control would promise a choice it cannot deliver. Either tier the ' +
      'report properly or remove the markers.');
  }

  return {
    status: problems.length ? 'FAIL' : 'PASS',
    reason: null, problems: problems,
    marked: marked, unmarked: unmarked.length, byTier: byTier
  };
}

function frontMatterStripped(md) {
  return String(md).replace(/^---\r?\n[\s\S]*?\r?\n---/, '');
}

function checkMarkdown(src, label) {
  var scan;
  try { scan = scanMarkdown(frontMatterStripped(src)); }
  catch (e) {
    return verdict('NOT CHECKED', 'report could not be scanned: ' +
      String(e.message).split('\n')[0]);
  }
  var r = validate(scan.headings);
  return verdict(r.status, r.reason, r.problems, r.marked, r.byTier, r.unmarked);
}

function checkDom(doc, label) {
  var body = doc.querySelector('.hl-post-content') || doc.body;
  if (!body) return verdict('NOT CHECKED', 'no report body container');

  var hs = body.querySelectorAll('h2');
  var headings = [];
  for (var i = 0; i < hs.length; i++) {
    var cls = String(hs[i].className || '');
    var m = cls.match(/\bhl-tier-([0-9A-Za-z_-]+)\b/);
    headings.push({
      text: (hs[i].textContent || '').trim(),
      tier: m ? m[1] : null,
      sameLine: false
    });
  }
  var r = validate(headings);
  return verdict(r.status, r.reason, r.problems, r.marked, r.byTier, r.unmarked);
}

module.exports = {
  scanMarkdown: scanMarkdown,
  validate: validate,
  checkMarkdown: checkMarkdown,
  checkDom: checkDom,
  TIER_RE: TIER_RE
};

/* Command line, so the gate driver and the author can run this directly.
   --against <report.md> exists for the same reason it does on check-figure-nav:
   a URL check alone is vacuous in the minutes after a push, because Pages still
   serves the previous build and an unmarked previous build passes truthfully. */
if (require.main === module) {
  var argv = process.argv.slice(2);
  var againstAt = argv.indexOf('--against');
  var against = againstAt !== -1 ? argv[againstAt + 1] : null;
  var target = argv.filter(function (a) {
    return a.indexOf('--') !== 0 && a !== against;
  })[0];
  if (!target) {
    console.error('usage: node lib/check-tiers.js <report.md|https://...> [--against <report.md>]');
    process.exit(2);
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
        if (expected.marked !== r.marked) {
          console.log('NOT CHECKED  ' + target + '   the page marks ' + r.marked +
            ' sections while ' + against + ' marks ' + expected.marked +
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
    var tail = r.status === 'PASS'
      ? (r.reason || r.marked + ' sections marked (T1 ' + r.byTier[1] +
         ', T2 ' + r.byTier[2] + ', T3 ' + r.byTier[3] + ')')
      : r.status === 'NOT CHECKED' ? r.reason : r.problems.join('; ');
    console.log(r.status.padEnd(12) + ' ' + target + '   ' + tail);
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
