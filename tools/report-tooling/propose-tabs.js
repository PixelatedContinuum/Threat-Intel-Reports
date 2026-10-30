#!/usr/bin/env node
'use strict';

/* Authoring aid for the report TAB markers (design-v4 section 3, E2): prints
   every h2 of a report in order with a proposed tab, how that proposal was
   reached, and the exact line to paste under the tier line.

   It proposes; it never decides. The writer keeps or overrides every line, the
   same contract propose-tiers.js runs under.

   Four proposal sources, always labelled so the writer can see what they are
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
     template  the report template's own headings that none of the above reaches
            ("What Is [Malware Name]?", Recommendations, Delivery Method ...,
            Future Evolution ..., FAQ, Component Inventory). A last pass that never
            moves a proposal the other three made; see TEMPLATE_RULES.

   WHICH REPORT. `propose-tabs.js <path to an index.md>` (or the folder that holds
   one) works on any report markdown, the vault copy threat-intel-vault/reports/
   <slug>/index.md included; the old form, a bare folder name under this checkout's
   reports/, still works. With no argument it prints proposals for the whole corpus,
   and `--write` with no argument REFUSES (exit 2): a write needs a named report.

   Anything still unresolved prints "?" and is COUNTED in the summary, because a
   silent zero would make an interrupted pass look finished. `check-tabs.js`
   fails a report with any untagged section, so the count is also the work left.

   --write inserts the lines, and it is PARTIAL BY DESIGN: a section it could not
   place gets no line, the run prints a WARNING with the count, and
   check-tabs.js then fails that report until a writer tags the rest. It is
   idempotent (an existing tab line is left alone, so a writer's override
   survives a re-run). It refuses to write in exactly three cases: the file's
   section count no longer matches the proposals (the file changed under it), the
   file mixes CRLF and LF line endings, and the file contains a lone carriage
   return (a `\r` that is not followed by `\n`). Otherwise line endings are
   PRESERVED: a CRLF file comes back CRLF, so a Windows-saved report does not turn
   into a whole-file diff.

   A HEADING AND ITS TIER LINE SEPARATED BY A BLANK LINE GET NO TAB LINE (fix
   round 2). kramdown attaches both block IALs to the paragraph below such a
   heading, so the heading keeps neither class; writing a tab line under the tier
   line would report success and leave a section the gate then FAILs (round-2
   review F3). The run says so per section and counts it, rather than writing a
   line that cannot work. Move the tier line directly under the heading and
   re-run. */

var fs = require('node:fs');
var path = require('node:path');
var CT = require('./lib/check-tiers.js');
var TT = require('./check-tabs.js');
var RT = require('./lib/report-target.js');

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

/* The report template's own headings that no rule above reaches (T-0500.1.9, audit
   T06: 5 of the 19 headings in report-structure-template were unplaced, and the
   gate fails a report until every section has a tab). A SEPARATE, LAST pass, run
   only on a heading that name, tier3 and span all left unplaced, so adding these
   cannot move any proposal that already exists (measured on the corpus: the
   proposals that changed were all "?" before). design-v4 section 3 lists none of
   them, so each is a default the writer keeps or overrides, labelled "template":
     "What Is [Malware Name]?"   is the template's Technical Classification section
     "Delivery Method ... & Initial Access Vectors" is tradecraft, with the chain
     "[N]. Component Inventory"  inventories the toolkit's parts, so the chain
     "Recommendations"           is response orientation, with detections
     "Future Evolution & Threat Trends", "Frequently Asked Questions" are reference
      apparatus with no tab of their own: Confidence and gaps. */
var TEMPLATE_RULES = [
  ['chain', /^(\[?\d+\]?\.\s*)?what is\b[^?]*\?\s*$/],
  ['chain', /initial access/],
  ['chain', /\bdelivery (method|mechanism|vector|chain)s?\b/],
  ['chain', /component inventory/],
  ['indicators', /recommendations?/],
  ['confidence', /future (evolution|outlook)|threat trends/],
  ['confidence', /frequently asked|\bfaq\b/]
];

function byTemplate(text) {
  var s = String(text).toLowerCase();
  for (var i = 0; i < TEMPLATE_RULES.length; i++) if (TEMPLATE_RULES[i][1].test(s)) return TEMPLATE_RULES[i][0];
  return null;
}

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
      detachedTier: !!h.tierDetached,
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

  proposals.forEach(function (p) {
    if (p.tab) return;
    var t = byTemplate(p.text);
    if (t) { p.tab = t; p.how = 'template'; }
  });

  return proposals;
}

/* The dominant line ending, or null when the file cannot be rewritten safely.
   `eolRefusal` names which of the two reasons applies, so the message does not
   claim a mixed file when a lone carriage return is the problem (F4). */
function detectEol(md) {
  var crlf = (md.match(/\r\n/g) || []).length;
  var lf = (md.match(/\n/g) || []).length;
  var loneCr = (md.match(/\r(?!\n)/g) || []).length;
  if (loneCr) return null;
  if (crlf === 0) return '\n';
  if (crlf === lf) return '\r\n';
  return null;
}

function eolRefusal(md) {
  var loneCr = (md.match(/\r(?!\n)/g) || []).length;
  if (loneCr) {
    return 'contains ' + loneCr + ' lone carriage return(s), a "\\r" that is not followed by "\\n"';
  }
  var crlf = (md.match(/\r\n/g) || []).length;
  var lf = (md.match(/\n/g) || []).length;
  if (crlf && crlf !== lf) return 'mixes CRLF and LF line endings';
  return null;
}

/* --write inserts the markers, from the bottom up so earlier line numbers stay
   valid. A heading that already carries a tab line keeps it. */
function writeTabs(file, proposals) {
  var md = fs.readFileSync(file, 'utf8');
  var refusal = eolRefusal(md);
  var eol = refusal ? null : detectEol(md);
  if (!eol) {
    console.error('refusing to write: ' + file + ' ' + (refusal || 'has no usable line ending') +
      '. Normalise it to one ending first (the site enforces LF through .gitattributes), ' +
      'or the rewrite would change every line.');
    return { error: true };
  }
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

  var added = 0, kept = 0, unplaced = 0, detached = 0;
  for (var h = heads.length - 1; h >= 0; h--) {
    var p = proposals[h];
    var at = heads[h];
    if (p.existing) { kept++; continue; }
    // A tier line below a blank line does not attach to the heading, so a tab
    // line written after it lands on a paragraph. Say so; do not write.
    if (p.detachedTier) { detached++; continue; }
    if (!p.tab) { unplaced++; continue; }

    // After the tier line when it is DIRECTLY below the heading, directly after
    // the heading when there is no tier line (check-tabs.js reports the missing
    // tier as an advisory).
    var insertAt = at + 1;
    if (CT.TIER_RE.test(lines[at + 1] || '')) insertAt = at + 2;

    lines.splice(insertAt, 0, '{: .hl-tab-' + p.tab + '}');
    added++;
  }
  fs.writeFileSync(file, lines.join(eol), 'utf8');
  return { added: added, kept: kept, unplaced: unplaced, detached: detached,
    eol: eol === '\r\n' ? 'CRLF' : 'LF' };
}

function main() {
  var args = process.argv.slice(2);
  var write = args.indexOf('--write') !== -1;
  var only = args.filter(function (a) { return a.indexOf('--') !== 0; })[0];

  /* A bare --write used to tag every untagged report in the corpus. It now
     refuses: writing needs a named target (T-0500.1.9, audit W04). */
  if (write && !only) {
    console.error('refusing --write with no target: it would tag the whole corpus. ' +
      'Name one report: node propose-tabs.js <path to index.md or report folder name> --write');
    process.exit(2);
  }

  var targets;
  if (only) {
    var t = RT.resolveTarget(only, REPORTS);
    if (t.error) {
      console.error(t.error);
      process.exit(2);
    }
    if (!fs.existsSync(t.file)) {
      console.error('no index.md at ' + t.file);
      process.exit(2);
    }
    targets = [t];
  } else {
    targets = fs.readdirSync(REPORTS, { withFileTypes: true })
      .filter(function (e) { return e.isDirectory(); })
      .map(function (e) { return e.name; })
      .sort()
      .map(function (n) { return { mode: 'name', slug: n, file: path.join(REPORTS, n, 'index.md') }; });
  }

  var totals = { set: 0, name: 0, tier3: 0, span: 0, template: 0, none: 0, reports: 0, done: 0, headings: 0 };
  var unplacedAll = [];

  targets.forEach(function (target) {
    var slug = target.mode === 'path' ? target.file : target.slug;
    var file = target.file;
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
        ' already present, ' + w.unplaced + ' left unplaced, ' + w.detached +
        ' skipped for a detached tier line (line endings kept: ' + w.eol + ')');
      if (w.unplaced) {
        console.log('  WARNING: ' + w.unplaced + ' section(s) got no line, so check-tabs.js will ' +
          'FAIL this report until a writer tags them.');
      }
      if (w.detached) {
        console.log('  WARNING: ' + w.detached + ' section(s) got no line because a blank line ' +
          'sits between the heading and its tier line. kramdown attaches both classes to the ' +
          'paragraph below such a heading, so a tab line there cannot stick: move the tier line ' +
          'directly under the heading and re-run.');
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
      else if (p.how === 'template') totals.template++;
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
      if (p.detachedTier) {
        console.log('       !! a blank line separates this heading from its tier line: kramdown');
        console.log('          attaches both classes to the paragraph below, so no tab line is');
        console.log('          written; move the tier line directly under the heading');
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
  console.log('proposed by template ' + totals.template);
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
  TEMPLATE_RULES: TEMPLATE_RULES,
  byTemplate: byTemplate,
  byName: byName,
  bySpan: bySpan,
  proposeFor: proposeFor,
  detectEol: detectEol,
  eolRefusal: eolRefusal,
  writeTabs: writeTabs
};

if (require.main === module) main();
