'use strict';

/* Reproduces the heading IDs the site actually generates, which is how every
   anchor a figure_nav entry points at comes to exist.

   Derived empirically against 1034 live headings across the 17 reports carrying
   infographics, because reasoning about it from kramdown's source gets it wrong.
   Four facts, none of them guessable:

   1. OUTSIDE a <details> block, nothing is stripped from the front. Punctuation
      is DELETED and each surviving space becomes exactly one hyphen, so runs of
      hyphens are real: "4. Technical Analysis — Static Findings" keeps both
      spaces around the vanished em dash and becomes
      "4-technical-analysis--static-findings". 996 of 996 headings.

   2. INSIDE a <details markdown="1"> block, kramdown's own generate_id runs
      instead and it STRIPS leading non-letters, so the same shape of heading
      loses its number: "8.1 Logback insertFromJNDI, CVE-2021-42550" becomes
      "logback-insertfromjndi-cve-2021-42550". 38 of 38 headings. Applying rule 1
      inside a teardown is wrong on every one of them, and applying rule 2
      outside is wrong on 796.

   3. Underscores survive rule 1 but NOT rule 2. OUTSIDE a teardown, "4.7 pe_03 —
      HijackLoader" keeps its underscore as "47-pe_03--hijackloader". INSIDE one,
      kramdown's real generate_id also strips underscores along with the leading
      digits, so the same heading text loses both: "4.7 pe_03: HijackLoader /
      Penguish / Rugmi Proper" renders as "pe03-hijackloader--penguish--rugmi-proper",
      and "5.1 PowerShell Collector Script (`turkish-instana_local_collector.ps1`)"
      renders as "powershell-collector-script-turkish-instanalocalcollectorps1",
      confirmed against the live page 2026-09-17. The original empirical pass
      behind rule 3 never happened to hit an underscored heading inside a
      teardown, so it generalized a same-outside/inside claim that was only ever
      tested outside; `lib/check-figure-nav.js` shares this module, so it agreed
      with its own wrong answer on both of those pages until fixed.

   4. Letters outside ASCII survive too. "6.2 miss.asp — Ghost小组 full-feature"
      keeps the CJK, so the character class must be Unicode-aware.

   5. A slug colliding with an earlier one gains a counter, and the FIRST use
      stays bare: three "Executive Impact Summary" headings become
      "executive-impact-summary", then "-1", then "-2".

   An explicit "{#custom-id}" attribute on the heading overrides all of it. */

var TRAILING_IAL = /\s*\{:?\s*#([^}\s]+)[^}]*\}\s*$/;

function kramdownSlug(text, inDetails) {
  var raw = String(text == null ? '' : text);

  // An author-set id wins outright; nothing below applies.
  var ial = raw.match(TRAILING_IAL);
  if (ial) return ial[1];

  var s = raw
    .replace(/`([^`]*)`/g, '$1')             // inline code renders as its text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1') // links render as their label
    .replace(/<[^>]+>/g, '');                // inline HTML is stripped

  // Rule 2. Only inside a teardown: strip the leading non-letter prefix (the
  // "N.M " numbering) AND underscores, matching kramdown's real generate_id.
  // Confirmed against the live page 2026-09-17 on two headings, both losing
  // their underscore only when they sit inside a <details> block.
  if (inDetails) s = s.replace(/^[^\p{L}]+/u, '').replace(/_/g, '');

  s = s.trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, '')       // delete, never substitute
    .trim();

  s = s.replace(/ /g, '-');                  // one hyphen per space, runs preserved
  return s || 'section';
}

/* Every heading slug in a report's markdown, in document order, each slugged
   under the rule that applies where it sits.

   All six levels are scanned, not only the h2 and h3 a chip usually targets,
   because rule 5's counter is shared across every level. One report opens nine
   h2s, fifty h3s and twenty-six h4s, several of them named "Deep Technical
   Analysis", and its ninth such heading is "-5" only because the h4s in between
   consumed the earlier numbers. Counting h2 and h3 alone puts every later
   collision on that page one or more off.

   Fenced blocks are skipped because a report quoting a shell prompt or a YAML
   comment would otherwise contribute phantom anchors, and a phantom anchor makes
   the checker accept a typo. */
function headingSlugs(md) {
  return headings(md).map(function (h) { return h.slug; });
}

function headings(md) {
  var out = [];
  var fenced = false;
  var depth = 0;
  var seen = {};

  /* Rule 5. The first use of a slug stays bare and each later collision takes
     the next counter, so a report repeating "Analyst Notes" under every family
     still gets one anchor per heading. */
  function unique(slug) {
    if (!(slug in seen)) { seen[slug] = 0; return slug; }
    seen[slug] += 1;
    var candidate = slug + '-' + seen[slug];
    while (candidate in seen) { seen[slug] += 1; candidate = slug + '-' + seen[slug]; }
    seen[candidate] = 0;
    return candidate;
  }
  String(md).split(/\r?\n/).forEach(function (line) {
    if (/^\s*(```|~~~)/.test(line)) { fenced = !fenced; return; }
    if (fenced) return;
    depth += (line.match(/<details/g) || []).length;
    depth -= (line.match(/<\/details>/g) || []).length;
    if (depth < 0) depth = 0;
    var m = line.match(/^(#{1,6})\s+(.*\S)\s*$/);
    if (m) {
      out.push({
        level: m[1].length,
        text: m[2].replace(TRAILING_IAL, '').trim(),
        inDetails: depth > 0,
        slug: unique(kramdownSlug(m[2], depth > 0))
      });
    }
  });
  return out;
}

module.exports = { kramdownSlug: kramdownSlug, headingSlugs: headingSlugs, headings: headings };
