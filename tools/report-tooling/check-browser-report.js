#!/usr/bin/env node
'use strict';

/* Drives a published report in a real browser.

   Three claim-matrix rows sat at NO GATE with the same sentence in different
   clothes: nothing proves the glossary tooltip renders, that a figure-nav chip
   click scrolls and opens the teardown it points at, or that the register switch
   hides a section and its TOC entry. All three are BUILT BY JAVASCRIPT AT
   RUNTIME: a fetched report contains no `.hl-viewswitch` and no `.hl-fignav` at
   all, only the tier markers and figures they are built from: so every check
   that reads fetched HTML is looking at the inputs and calling them the output.

   jsdom cannot close the gap either: it has no layout, so every rect is zero,
   which is exactly what defeated the glossary's edge-flip measurement.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. A missing browser, an unreachable site or
   a report that carries none of the machinery is NOT CHECKED with the reason
   named, never a pass.

   Run: node check-browser-report.js [slug] [--shots <dir>] [--md <report.md>]
        `--md` must be followed by a path: with none it is a usage error (exit 2),
        never a silent fallback to the site or vault copy (fix round 2, D4).
   Env: HL_CHROME, HL_SITE_BASE */

var path = require('node:path');
var fs = require('node:fs');
var https = require('node:https');

var ROOT = path.join(__dirname, '..', '..');
var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');

var args = process.argv.slice(2);
var shotsDir = null;
var si = args.indexOf('--shots');
if (si > -1) { shotsDir = args[si + 1]; args.splice(si, 2); }
var mdArg = null;
var mi = args.indexOf('--md');
if (mi > -1) {
  mdArg = args[mi + 1];
  /* `--md` as the last argument used to leave mdArg undefined, the truthiness
     test at readAuthored fell through, and the gate compared against whichever
     copy happened to resolve instead of the file the caller named (review 2,
     A11). A named file that is not named is a usage error. */
  if (!mdArg || /^--/.test(mdArg)) {
    console.log('usage: node check-browser-report.js [slug] [--shots <dir>] [--md <report.md>]');
    console.log('NOT CHECKED  --md was given with no path after it, so the file the caller ' +
      'meant to compare against is unknown; nothing was compared.');
    process.exit(2);
  }
  args.splice(mi, 2);
}
var slug = args[0] || null;

function notChecked(reason) {
  console.log('NOT CHECKED  ' + reason);
  process.exit(2);
}

var CDP, SERVER, TRIAGE, yaml, KS, CTABS;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  TRIAGE = require('./lib/console-triage.js');
  yaml = require('js-yaml');
  KS = require('./lib/kramdown-slug.js');
  CTABS = require('./check-tabs.js');
} catch (e) {
  notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.');
}

function fetchText(url) {
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { 'user-agent': 'hl-browser-check' } }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(url + ' returned HTTP ' + res.statusCode));
      }
      var b = '';
      res.setEncoding('utf8');
      res.on('data', function (d) { b += d; });
      res.on('end', function () { resolve(b); });
    }).on('error', reject);
  });
}

/* Pick a report that actually exercises ALL of the machinery, not merely the
   first in the catalog.

   A report with no tier markers lets every register-switch check pass by finding
   nothing to hide, and a report that declares no figure_nav turns three chip
   checks into NOT CHECKED. 17 of the corpus declare figure_nav and 41 carry
   tiers, so one with both is easy to find and is the only kind that verifies
   anything. Scoring prefers both, then depth. */
function pickSlug() {
  if (slug) return slug;
  var cat;
  try {
    cat = yaml.load(fs.readFileSync(path.join(ROOT, '_data', 'catalog.yml'), 'utf8'));
  } catch (e) { return null; }
  /* Array first, explicitly. Every Array has an `entries` METHOD, so the
     familiar `(cat && cat.entries) || cat` yields a function for a bare array
     and silently selects nothing. See lib/download-targets.js for the full note.
     _data/catalog.yml is a mapping with an `entries:` key, which is why this
     shape has worked. */
  var entries = Array.isArray(cat) ? cat
    : (cat && Array.isArray(cat.entries) ? cat.entries : []);
  var best = null, bestScore = -1;
  entries.forEach(function (e) {
    if (!e || !e.report_url) return;
    var s = String(e.report_url).replace(/^\/reports\//, '').replace(/\/$/, '');
    var md = path.join(ROOT, 'reports', s, 'index.md');
    if (!fs.existsSync(md)) return;
    var text = fs.readFileSync(md, 'utf8');
    var tiers = (text.match(/hl-tier-/g) || []).length;
    if (!tiers) return;
    // Carrying figure_nav is worth more than any amount of extra depth.
    var score = tiers + (/^figure_nav:/m.test(text) ? 10000 : 0);
    if (score > bestScore) { bestScore = score; best = s; }
  });
  return best;
}

/* ---------- the authored report (fix rounds 1 and 2) ----------

   The tabbed page cannot be its own expectation. At 8a44adf the gate took the
   expected section list and order from the page's own `--rv-order` blocks, so a
   section deleted from the source (round-1 mutant 1) and two sections swapped in
   the source (mutant 2) both PASSed 51/51: the page agreed with itself. The
   authored markdown is the record of what the report says, so the expected
   sections, their order, every h2/h3 id, every heading's text and every h3's
   parent section are read from it.

   RESOLUTION ORDER (fix round 2, D3): `--md <path>` when given, then THE VAULT
   COPY `threat-intel-vault/reports/<slug>/index.md`, then this checkout's site
   copy `reports/<slug>/index.md`. The vault copy is the authored record the site
   copy is built from, so it wins: the round-2 review (A8) showed that a markdown
   copy which had already lost a section compared clean against the page built
   from it. The site copy is used only when no vault copy exists (the
   `-tabbed-preview` slug), and the authored line says `expectation from the site
   copy; no vault copy` so that is visible rather than assumed.

   When BOTH copies exist their bodies must agree line for line, front matter and
   the `{: .hl-tab-…}` lines stripped from each (the vault copy carries tags the
   site copy may not yet): a copy-stage loss is invisible to a page built from the
   same copy, so the gate FAILs naming the first differing line.

   Every row that depends on the authored report is NOT CHECKED when no markdown
   resolves, never satisfied from the page's own sections (fix round 2, D2). */

var TAB_IAL_LINE = /^\s*\{:\s*\.hl-tab-[a-z]+\s*\}\s*$/;

function reportPaths(s) {
  return {
    site: path.join(ROOT, 'reports', s, 'index.md'),
    vault: path.join(ROOT, '..', '..', 'threat-intel-vault', 'reports', s, 'index.md')
  };
}

function splitFrontMatter(md) {
  var text = String(md);
  var m = text.match(/^---\r?\n[\s\S]*?\r?\n---[ \t]*(?:\r?\n|$)/);
  if (!m) return { body: text, offset: 0 };
  return { body: text.slice(m[0].length), offset: (m[0].match(/\n/g) || []).length };
}

/* The body as numbered lines, with the two things that legitimately differ
   between the site copy and the vault copy removed: the front matter and the
   `{: .hl-tab-…}` line under each heading. Trailing whitespace is not content;
   everything else is compared byte for byte. */
function bodyLines(md) {
  var fm = splitFrontMatter(md);
  var out = [];
  String(fm.body).split(/\r?\n/).forEach(function (line, i) {
    if (TAB_IAL_LINE.test(line)) return;
    out.push({ line: fm.offset + i + 1, text: line.replace(/\s+$/, '') });
  });
  return out;
}

function firstBodyDifference(siteLines, vaultLines) {
  var n = Math.max(siteLines.length, vaultLines.length);
  for (var i = 0; i < n; i++) {
    var s = siteLines[i] ? siteLines[i].text : undefined;
    var v = vaultLines[i] ? vaultLines[i].text : undefined;
    if (s === v) continue;
    return {
      bodyLine: i + 1,
      siteLine: siteLines[i] ? siteLines[i].line : null,
      vaultLine: vaultLines[i] ? vaultLines[i].line : null,
      site: s,
      vault: v
    };
  }
  return null;
}

/* Both sides of a heading-text comparison go through the same normaliser:
   kramdown renders inline constructs to text and converts straight quotes to
   typographic ones, so "the Bank's Own Proxy" in the markdown and "the Bank’s
   Own Proxy" on the page are the same heading. Formatting is what this drops;
   the words, digits and punctuation have to survive it unchanged. */
var TYPOGRAPHIC = {
  '\u2018': "'", '\u2019': "'", '\u201a': "'", '\u201b': "'",
  '\u201c': '"', '\u201d': '"', '\u201e': '"', '\u201f': '"',
  '\u2013': '-', '\u2014': '-', '\u2026': '...', '\u00a0': ' '
};

function normaliseHeadingText(s) {
  var t = String(s == null ? '' : s);
  t = t.replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1');   // image -> its alt text
  t = t.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');     // link -> its label
  t = t.replace(/\[([^\]]*)\]\[[^\]]*\]/g, '$1');    // reference link -> label
  t = t.replace(/\[\^[^\]]*\]/g, '');                // footnote marker
  t = t.replace(/`([^`]*)`/g, '$1');                 // inline code -> its text
  t = t.replace(/<[^>]+>/g, '');                     // inline html
  t = t.replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1');
  t = t.replace(/(^|[\s(])_([^_]+)_(?=[\s).,;:!?]|$)/g, '$1$2');
  t = t.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  t = t.replace(/[\u2018\u2019\u201a\u201b\u201c\u201d\u201e\u201f\u2013\u2014\u2026\u00a0]/g,
    function (c) { return TYPOGRAPHIC[c]; });
  return t.replace(/\s+/g, ' ').trim();
}

function readAuthored(s) {
  var where = reportPaths(s);
  var chosen = null, source = null, note = '';
  if (mdArg) {
    if (!fs.existsSync(mdArg)) return { path: mdArg, source: 'md', error: 'the --md file does not exist' };
    chosen = mdArg; source = 'md';
    note = 'expectation from --md ' + mdArg;
  } else if (fs.existsSync(where.vault)) {
    chosen = where.vault; source = 'vault';
    note = 'expectation from the vault copy ' + where.vault;
  } else if (fs.existsSync(where.site)) {
    chosen = where.site; source = 'site';
    note = 'expectation from the site copy; no vault copy';
  } else {
    return {
      path: null, source: null,
      error: 'no report markdown found (--md, the vault copy or reports/' + s + '/index.md)'
    };
  }

  var md;
  try { md = fs.readFileSync(chosen, 'utf8'); }
  catch (e) { return { path: chosen, source: source, error: 'could not be read: ' + e.message }; }

  /* The site copy against the vault copy, when both are present. An explicit
     --md is a deliberate choice of a different file (the probes point it at a
     doctored copy on purpose), so it never enters this comparison. */
  var compare = null;
  if (source === 'vault' && fs.existsSync(where.site)) {
    var siteMd = null, siteError = null;
    try { siteMd = fs.readFileSync(where.site, 'utf8'); }
    catch (e) { siteError = e.message; }
    compare = siteError
      ? { readable: false, error: siteError, sitePath: where.site, vaultPath: where.vault, diff: null }
      : {
        readable: true, sitePath: where.site, vaultPath: where.vault,
        diff: firstBodyDifference(bodyLines(siteMd), bodyLines(md))
      };
    if (compare.diff) {
      note += '; the site copy DIFFERS at body line ' + compare.diff.bodyLine;
    } else if (compare.readable) {
      note += '; the site copy matches it';
    }
  }

  var all = KS.headings(md);
  var h2 = all.filter(function (h) { return h.level === 2; });
  var ids = all.filter(function (h) { return h.level === 2 || h.level === 3; });
  var scan = CTABS.scanMarkdown(md);
  var tabs = null;
  var anyTab = scan.headings.some(function (h) { return !!h.tab; });
  if (anyTab && scan.headings.length === h2.length) {
    tabs = {};
    scan.headings.forEach(function (h, i) { if (h.tab) tabs[h2[i].slug] = h.tab; });
  }
  /* Which section each h3 sits in, taken in document order: the authored h3
     belongs to the nearest preceding h2 (D8). */
  var parents = {};
  var currentH2 = null;
  all.forEach(function (h) {
    if (h.level === 2) { currentH2 = h.slug; return; }
    if (h.level === 3 && currentH2) parents[h.slug] = currentH2;
  });
  var text = {};
  ids.forEach(function (h) { text[h.slug] = h.text; });
  return {
    path: chosen,
    source: source,
    note: note,
    sitePath: where.site,
    vaultPath: where.vault,
    compare: compare,
    h2: h2.map(function (h) { return h.slug; }),
    ids: ids.map(function (h) { return h.slug; }),
    text: text,
    parents: parents,
    tabs: tabs,
    sections: scan.headings.map(function (h, i) {
      return { text: h.text, tab: h.tab || null, id: h2[i] ? h2[i].slug : null };
    })
  };
}

function firstAuthoredIdForTab(authored, token) {
  if (!authored || !authored.tabs) return null;
  for (var i = 0; i < authored.h2.length; i++) {
    if (authored.tabs[authored.h2[i]] === token) return authored.h2[i];
  }
  return null;
}

function countOf(list, value) {
  return list.filter(function (x) { return x === value; }).length;
}

/* The first place two ordered lists disagree, named, so a swapped or moved
   section reports the two ids rather than a bare count. */
function firstOrderDifference(expected, actual) {
  var n = Math.max(expected.length, actual.length);
  for (var i = 0; i < n; i++) {
    if (expected[i] !== actual[i]) {
      return 'first difference at position ' + (i + 1) + ': the report has "' +
        (expected[i] === undefined ? '(nothing)' : expected[i]) + '", the page has "' +
        (actual[i] === undefined ? '(nothing)' : actual[i]) + '"';
    }
  }
  return null;
}

var results = [];
function check(name, pass, detail) {
  results.push({ name: name, pass: pass });
  console.log('   ' + (pass ? 'PASS  ' : 'FAIL  ') + name);
  if (detail) console.log('         ' + detail);
}

/* ---------- tabbed reports (design-v4 check 5.4, section 4a) ----------

   A tabbed page retires the register switch (E3), so the five register
   assertions above are replaced here rather than added to: on a tabbed page the
   switch does not exist, and the checks that would find it absent would fail a
   page that is working exactly as designed. The layout emits the tab class from
   kramdown onto each h2, so the FETCHED html says which kind of page this is
   before any browser sees it. An untabbed page takes the old branch untouched:
   that is the control, and its verdict lines are diffed before/after a change
   to this file.

   Every assertion below reads the built DOM through lib/cdp.js. The tab bar,
   panels and views are built by hl-report-tabs.js at runtime, so a check that
   read the fetched HTML would be reading the inputs and calling them output.

   THE REPORT IS THE EXPECTATION, NOT THE PAGE (fix rounds 1 and 2). The expected
   section list, its order, every h2/h3 id, every heading's text, every h3's
   parent section and every section's tab come from the authored markdown
   (`--md`, else the vault copy, else the site copy), never from the page's own
   `--rv-order` or its DOM: at 8a44adf a section deleted from the source and two
   sections swapped in the source both PASSed, because the gate compared the page
   with itself. When no markdown resolves, every row that depends on it (sections,
   ids, order, print, deep links, tab assignment, heading text, h3 parents) is
   NOT CHECKED with that reason; none of them is satisfied from the page. The
   deep-link sampler reads each panel's first `h2` without an `[id]` filter and
   FAILs when that heading has no id, rather than skipping to the next heading
   that has one.

   NOTHING LOST, NOTHING HIDDEN, NOTHING MOVED (fix round 2, D5 to D8). The page
   may not lose a section from view (one-page mode must paint every authored h2
   and every block up to the next h2: no display:none, no visibility
   hidden/collapse, no zero opacity on it or an ancestor, no zero-sized box, not
   moved outside the document), may not move a section into another tab (the
   `hl-tab-` line under each h2 says which panel its heading must be in), may not
   rename a heading while keeping its id (authored text against page text), and
   may not move an h3 into another section (authored parent against page parent).
   Closed `<details>` bodies are exempt from the render check, as in
   check-report-text.js: the reader opens the teardown. */

var TAB_TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
/* 4a's four mobile sizes plus the desktop one 5.4 names. Order matters only for
   the log; 812x375 is a landscape phone and gets the tablet layout. */
var TAB_VIEWPORTS = [
  [1280, 900, 'desktop'],
  [768, 1024, 'tablet'],
  [812, 375, 'landscape phone'],
  [390, 844, 'phone'],
  [360, 800, 'small phone']
];

function isTabbedHtml(html) {
  var tags = String(html).match(/<h2[^>]*>/g) || [];
  return tags.some(function (t) { return /class="[^"]*\bhl-tab-[a-z]/.test(t); });
}

async function setViewport(page, width, height) {
  /* The same emulation Playwright's `newContext({viewport, hasTouch})` uses for
     a resized desktop viewport: metrics override, touch on, mobile layout off.
     `mobile: true` would change how the viewport meta is applied and would not
     be the thing part 1 was verified against. */
  await page.send('Emulation.setDeviceMetricsOverride', {
    width: width, height: height, deviceScaleFactor: 1, mobile: false
  });
  await page.send('Emulation.setTouchEmulationEnabled', {
    enabled: width < 1024, maxTouchPoints: 5
  });
  await CDP.sleep(150);
}

async function gotoAndWait(page, url) {
  await page.send('Page.navigate', { url: url });
  var ready = await page.waitFor('.hl-rv-ready', 8000);
  await CDP.sleep(150);
  return ready;
}

/* One expression for the page-level horizontal-scroll gate.

   `documentElement.scrollWidth` alone is not enough here: the theme sets
   `html { overflow-x: clip }`, which keeps scrollWidth equal to the viewport
   while a too-wide element is silently cut off. A clipped 900 px box is a worse
   defect than a scrollbar, so two facts are read:

   - canScroll: after scrolling right, did the document actually move?
   - escaped: how many painted elements extend past the viewport WITHOUT a
     horizontal scroll/clip ancestor between them and <body>. Elements inside a
     declared scroll box (`.hl-rv-source-table`, `.hl-rv-table-wrap`) are
     contained by design and are not counted; html's own clip is deliberately
     not treated as containment, or it would hide every overflow it causes.

   Both must be clean. */
var OVERFLOW_EXPR = '(function(){' +
  'var de=document.documentElement,client=de.clientWidth;' +
  'window.scrollTo(9999,window.scrollY);var sx=Math.round(window.scrollX);window.scrollTo(0,window.scrollY);' +
  'var escaped=[],all=document.body.querySelectorAll("*");' +
  'for(var i=0;i<all.length;i++){var e=all[i],r=e.getBoundingClientRect();' +
  'if(r.width<=0&&r.height<=0)continue;' +
  'if(r.right<=client+1&&r.left>=-1)continue;' +
  'var a=e.parentElement,clipped=false;' +
  'while(a&&a!==document.body){var c=getComputedStyle(a);' +
  'if(/auto|scroll|hidden|clip/.test(c.overflowX)){clipped=true;break}a=a.parentElement}' +
  'if(!clipped)escaped.push({tag:e.tagName,cls:String(e.className||"").slice(0,40),' +
  'left:Math.round(r.left),right:Math.round(r.right)});}' +
  'return {client:client,scrollW:de.scrollWidth,scrollX:sx,escaped:escaped.length,' +
  'first:escaped.slice(0,4)};})()';

/* Every authored section, rendered, in one-page mode (fix round 2, D5).

   The round-2 probes hid one section four ways and all four PASSed 53/53: the
   body under a `display:none` heading (x1), the block under `visibility:hidden`
   (x2), the block at `opacity:0` (x3), and the block moved to `left:-10000px`
   (x4). Each read only asked whether the heading had a box, so a section whose
   text the reader cannot see was counted as shown.

   So each `.hl-rv-source` block is measured as a whole -- its h2 and every
   sibling up to the next h2, which is exactly what the tab script put in one
   wrapper -- and every one of those elements must be painted:

   - display is not `none` on it or any ancestor (display does not inherit, so
     the walk is what catches a hidden wrapper);
   - its own computed `visibility` is neither `hidden` nor `collapse`
     (visibility DOES inherit, so the computed value already reflects the
     ancestors, and an explicit `visibility:visible` below a hidden ancestor is
     correctly not a defect);
   - the product of `opacity` up the chain is above 0 (opacity does not inherit);
   - it has a non-zero box, and it is not entirely outside the document's
     horizontal extent (a block parked at left:-10000px has right <= 0).

   Closed `<details>` bodies are exempt by construction: only the top-level
   blocks of a section are measured, and a closed teardown's own `<summary>` and
   box are rendered while its body is the reader's to open (check-report-text.js
   exempts the same nodes). Blocks are listed rather than sampled, because a
   gate that prints four of thirty-two failures is how the round-2 review found
   the overflow row hiding rows. */
var SECTION_RENDER_EXPR = '(function(){' +
  'var client=document.documentElement.clientWidth;' +
  'function why(el){' +
  'var out=[];' +
  'for(var a=el;a;a=a.parentElement){var cs=getComputedStyle(a);' +
  'var who=(a===el?"itself":a.tagName.toLowerCase()+(a.id?"#"+a.id:""));' +
  'if(cs.display==="none")out.push("display:none on "+who);}' +
  'var own=getComputedStyle(el);' +
  'if(own.visibility==="hidden"||own.visibility==="collapse")out.push("visibility:"+own.visibility);' +
  'var op=1;for(var b=el;b;b=b.parentElement){var c2=getComputedStyle(b);' +
  'op*=parseFloat(c2.opacity);if(!(op>0)){out.push("opacity "+c2.opacity+" on "+(b===el?"itself":b.tagName.toLowerCase()+(b.id?"#"+b.id:"")));break;}}' +
  'var r=el.getBoundingClientRect();' +
  'if(r.width<=0&&r.height<=0)out.push("no box (0x0)");' +
  'else if(r.right<=0||r.left>=client)out.push("outside the document horizontally ("+Math.round(r.left)+".."+Math.round(r.right)+" of 0.."+client+")");' +
  'return out;}' +
  'var out={client:client,sections:{},count:0};' +
  '[].slice.call(document.querySelectorAll(".hl-rv-source")).forEach(function(block){' +
  'var h=block.querySelector("h2");if(!h||!h.id)return;' +
  'var kids=[].slice.call(block.children),bad=[];' +
  'kids.forEach(function(el){var rs=why(el);if(!rs.length)return;' +
  'bad.push((el===h?"heading":el.tagName.toLowerCase()+(el.className?"."+String(el.className).split(" ")[0]:""))+" ("+rs.join(", ")+")");});' +
  'out.count++;out.sections[h.id]={blocks:kids.length,bad:bad};});' +
  'return out;})()';


/* 44 px targets in chrome, measured the same way part 1 measured 1,562 of them:
   every rendered control inside a [data-rv-chrome] region plus the tab bar,
   with every dashboard fold opened first so a control cannot hide inside a
   closed <details>. getClientRects() is the visibility test, not computed
   display: a control in a hidden panel reports its own display as inline and
   would otherwise count as visible. */
function targetsExpr(token) {
  return '(function(){var t=' + JSON.stringify(token) + ';' +
    'var panel=document.getElementById("tab-"+t);' +
    'if(!panel)return null;' +
    'panel.querySelectorAll(".hl-rv-view details").forEach(function(d){d.open=true;});' +
    'var controls=[].slice.call(panel.querySelectorAll("[data-rv-chrome] :is(a,button,input,select,summary),[data-rv-chrome]:is(a,button,input,select,summary)"))' +
    '.concat([].slice.call(document.querySelectorAll(".hl-rv-bar :is(a,button)")));' +
    'var seen=new Set(),visible=[];' +
    'controls.forEach(function(e){if(seen.has(e))return;seen.add(e);' +
    'if(!e.getClientRects().length)return;' +
    'if(getComputedStyle(e).visibility==="hidden")return;visible.push(e);});' +
    'var small=visible.map(function(e){var r=e.getBoundingClientRect();' +
    'return {tag:e.tagName,cls:String(e.className||"").slice(0,40),' +
    'text:(e.textContent||"").trim().slice(0,40),w:Math.round(r.width),h:Math.round(r.height)};})' +
    '.filter(function(e){return e.w<43.99||e.h<43.99;});' +
    'return {count:visible.length,small:small.slice(0,8),smallCount:small.length};})()';
}

/* Design v6 (T-0500.1.7): nothing in chrome is set below 13 px. Joseph has complained about small
   text, and a mono micro-label is the easiest thing to let shrink, so the floor is measured on every
   tab, not assumed from the stylesheet. Every text node under the generated regions is read at its
   computed size: the tab bar, the header, the sponsor strip, the panel heads and every [data-rv-chrome]
   node in the tab (permalinks, table tools, the whole data view). Text drawn by CSS content (the
   SECTION nn label, DATA VIEW, the tab dots) is not a text node, so every element in those regions is
   also asked for its ::before and ::after. The report's own prose is not measured here: it is the
   author's text and is set larger. getClientRects() decides visibility, as in the 44 px count. */
var CHROME_FLOOR_PX = 12.99;
function chromeTextExpr(token) {
  return '(function(t){var panel=document.getElementById("tab-"+t);if(!panel)return null;' +
    'panel.querySelectorAll(".hl-rv-view details").forEach(function(d){d.open=true;});' +
    'var roots=[].slice.call(document.querySelectorAll(".hl-rv-bar,.hl-post-header,.hl-rvsp"))' +
    '.concat([].slice.call(panel.querySelectorAll("[data-rv-chrome],.hl-rv-panel-head")));' +
    'var heads=[].slice.call(panel.querySelectorAll(".hl-rv-source > h2,.hl-rv-source.hl-rv-nohead"));' +
    'var seen=new Set(),count=0,small=[],pseudo=0;' +
    'function vis(el){return !!el&&el.getClientRects().length>0&&getComputedStyle(el).visibility!=="hidden";}' +
    'roots.forEach(function(root){var w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT),n;' +
    'while((n=w.nextNode())){if(!/\\S/.test(n.nodeValue)||seen.has(n))continue;seen.add(n);' +
    'var el=n.parentElement;if(!vis(el))continue;count++;var px=parseFloat(getComputedStyle(el).fontSize);' +
    'if(px<' + CHROME_FLOOR_PX + ')small.push({px:px,what:(n.nodeValue.trim()).slice(0,30),cls:String(el.className||el.tagName).slice(0,30)});}});' +
    'var els=[];roots.concat(heads).forEach(function(r){els.push(r);[].slice.call(r.querySelectorAll("*")).forEach(function(e){els.push(e);});});' +
    'var done=new Set();els.forEach(function(el){if(done.has(el))return;done.add(el);if(!vis(el))return;' +
    '["::before","::after"].forEach(function(ps){var c=getComputedStyle(el,ps);' +
    'if(!c.content||c.content==="none"||c.content==="normal"||c.content==="\\"\\"")return;' +
    'if(c.display==="none")return;pseudo++;var px=parseFloat(c.fontSize);' +
    'if(px<' + CHROME_FLOOR_PX + ')small.push({px:px,what:ps+" "+c.content.slice(0,24),cls:String(el.className||el.tagName).slice(0,30)});});});' +
    'return {count:count,pseudo:pseudo,small:small.slice(0,8),smallCount:small.length};})(' + JSON.stringify(token) + ')';
}

/* The selected tab is told apart from the others by more than its aria state: its label and underline
   take the tab's accent while an idle tab is muted with no underline, and every tab carries its own
   accent dot (CSS content on ::before). Seven tabs, five clean site hues: at least six distinct dots. */
var TAB_LOOK_EXPR = '(function(){var tabs=[].slice.call(document.querySelectorAll("[role=tab]"));' +
  'return tabs.map(function(b){var c=getComputedStyle(b),d=getComputedStyle(b,"::before");' +
  'return {id:b.id,selected:b.getAttribute("aria-selected")==="true",color:c.color,' +
  'line:c.borderBottomColor,lineW:parseFloat(c.borderBottomWidth),dot:d.backgroundColor,dotW:parseFloat(d.width)};});})()';
function tabLookVerdict(tabs) {
  if (!tabs || tabs.length < 2) return { notChecked: true, ok: false, detail: 'fewer than two tabs were rendered, so nothing could be compared' };
  var clear = function (c) { return !c || c === 'transparent' || /^rgba\(\s*0,\s*0,\s*0,\s*0\s*\)$/.test(c); };
  var sel = tabs.filter(function (t) { return t.selected; });
  var idle = tabs.filter(function (t) { return !t.selected; });
  var why = [];
  if (sel.length !== 1) why.push(sel.length + ' tabs selected');
  else {
    if (sel[0].lineW < 2 || clear(sel[0].line)) why.push('selected tab has no underline (' + sel[0].lineW + 'px ' + sel[0].line + ')');
    if (idle.some(function (t) { return t.color === sel[0].color; })) why.push('an idle tab has the selected tab\'s label colour ' + sel[0].color);
    if (idle.some(function (t) { return !clear(t.line); })) why.push('an idle tab is underlined');
  }
  var dots = tabs.map(function (t) { return t.dot; });
  if (tabs.some(function (t) { return !(t.dotW > 0) || clear(t.dot); })) why.push('a tab has no accent dot');
  var distinct = dots.filter(function (d, i) { return dots.indexOf(d) === i; }).length;
  if (distinct < 6) why.push('only ' + distinct + ' distinct dot colours across ' + tabs.length + ' tabs');
  return { notChecked: false, ok: why.length === 0, why: why, distinct: distinct,
    detail: tabs.length + ' tabs: selected ' + (sel[0] ? sel[0].id + ' ' + sel[0].color + ' with a ' + sel[0].lineW + 'px ' + sel[0].line + ' line' : 'none') +
      '; ' + distinct + ' distinct dot colours' + (why.length ? '; ' + why.join('; ') : '') };
}

/* Keyboard, measured with real key events. A synthetic KeyboardEvent dispatched
   from evaluate() proves the listener, not focusability: a tab that is 0x0 or
   outside the layout would still "pass". Input.dispatchKeyEvent goes through
   the browser's own focus handling, and the focused element is read back. */
async function pressKey(page, key, code, vk) {
  for (var type of ['keyDown', 'keyUp']) {
    await page.send('Input.dispatchKeyEvent', {
      type: type, key: key, code: code,
      windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk
    });
  }
  await CDP.sleep(120);
}

/* A real pointer click on an item that is already on screen, without asking the
   page to scroll first.

   `page.click` runs scrollIntoView({block:'center'}) before measuring. For a
   link inside the sticky tab bar's menu, that scrolls the PAGE, which moves the
   sticky bar and its menu, and the hit test then lands on whatever slid under
   the old coordinates. The menu is brought on screen by the caller, so measure
   and dispatch are done on one settled layout instead. */
async function clickMenuLink(page, href) {
  var sel = '.hl-rv-menu a[href="' + href + '"]';
  var pt = await page.json('(function(){' +
    'var a=document.querySelector(' + JSON.stringify(sel) + ');' +
    'if(!a)return null;var r=a.getBoundingClientRect();' +
    'var x=r.x+r.width/2,y=r.y+r.height/2;var hit=document.elementFromPoint(x,y);' +
    'return {x:x,y:y,ok:!!hit&&(hit===a||a.contains(hit)),' +
    'hit:hit?hit.tagName:null,top:Math.round(r.top)};})()');
  if (!pt || !pt.ok) {
    // Name the geometry rather than clicking blind; the caller reports it.
    return pt;
  }
  await page.send('Input.dispatchMouseEvent', {
    type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1
  });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1
  });
  await CDP.sleep(200);
  return pt;
}

function selectedTabExpr() {
  return '(function(){var a=document.querySelector("[role=tab][aria-selected=true]");' +
    'return {id:a?a.id:null,focus:document.activeElement&&document.activeElement.id};})()';
}

/* The tab whose view holds the primary list its summary line counts. The first
   integer in the summary is the builder's headline figure (tiles, victim rows,
   stages, dated events, hypotheses, indicator chips, judgments), so counting
   the same elements is a real reconciliation rather than a text match. */
var TAB_PRIMARY = {
  overview: '.hl-rv-tile',
  victims: '#victims tbody tr',
  chain: '.hl-rv-stage',
  timeline: '.hl-rv-marker',
  attribution: '#hypotheses tbody tr',
  indicators: '.hl-rv-chips li',
  confidence: '#judgments tbody tr'
};

/* A 25-date chronology spanning two years, from design-v4 5.4. It is derived
   from the page under test rather than authored: every table whose first header
   reads Date/Time/When has its rows replaced, so the label-thinning path runs
   over 25 real candidates instead of the handful a short chronology has. */
function timelineFixtureHtml(html) {
  var rows = [];
  for (var i = 0; i < 25; i++) {
    var d = new Date(Date.UTC(2024, 10, 15) + i * 30 * 86400000).toISOString().slice(0, 10);
    rows.push('<tr><td>' + d + '</td><td>Fixture observation ' + (i + 1) + '</td></tr>');
  }
  var done = false;
  var out = String(html).replace(/<table[\s\S]*?<\/table>/g, function (block) {
    if (done || !/<th[^>]*>\s*(?:Date|Time|When)[^<]*<\/th>/i.test(block)) return block;
    if (!/<tbody>/i.test(block)) return block;
    done = true;
    return block.replace(/(<tbody>)[\s\S]*?(<\/tbody>)/i, '$1' + rows.join('') + '$2');
  });
  return done ? out : null;
}

/* ---------- 4a: the tab bar, and the targets 4a names (p7) ----------------

   WHY THESE ROWS EXIST. design-v4 4a's "Gates added for mobile" asks for two
   things this file did not assert, both found by the deepseek review of the
   pilot (review_e74f3dcbe2074ad1, V3 task task_b933cd7c01a04024):

   1. every tab reachable from the TAB BAR at 768x1024 and 812x375. The
      per-viewport loop below cannot cover it: it stops at
      `if (width >= 700) continue;`, which is correct for the phone-only
      dashboard-card rules and wrong for the bar, and the tab rows that do run
      everywhere ask about URL fragments, keyboard and the phone Sections menu,
      never whether a tab has a box on screen at those two sizes.

   2. the 44 by 44 count covered `[data-rv-chrome]` controls and the bar only,
      so the teardown summaries 4a names and the in-tab section navigation were
      never measured at any width.

   The lead measured both by hand on the live preview (p5-report.md, "After the
   deepseek review") because the gate asserted neither. Measured by hand is not
   a gate: the next layout change is then verified by nobody.

   THREE THINGS KEEP THESE ROWS HONEST.

   - The page is scrolled only so the sticky bar is on screen. A tab that needs
     an INNER box scrolled (a tab list with `overflow:hidden` and a fixed width)
     is exactly what 4a forbids -- "nothing hidden off-screen", one tap to
     anywhere -- so clipping ancestors are measured, not scrolled away.
   - A click has to MOVE the selection. Each tab is measured after a different
     tab has been selected by fragment, so a click that never reached the bar
     cannot pass by leaving the already-selected tab in place.
   - A row that measured nothing is NOT CHECKED, never a pass. The bar is built
     by hl-report-tabs.js, so a controller that never ran leaves a page where
     "every tab is fine" is true only because there are no tabs. */

var MIN_TARGET_PX = 43.99;

/* 4a's two sizes for the bar, and the two it names for the 44 px count (390 is
   its phone width; 768 its tablet). */
var TAB_BAR_VIEWPORTS = [[768, 1024, 'tablet'], [812, 375, 'landscape phone']];
var TAB_TARGET_VIEWPORTS = [[390, 844, 'phone'], [768, 1024, 'tablet']];

/* One tab's geometry, read the way a finger meets it: scroll the PAGE so the
   sticky bar is on screen (never an inner scroller), then require a real box,
   inside the viewport width, and inside every clipping ancestor between the
   tab and the document. Rounding is whole pixels because a rect comparison
   against a fractional client width is noise at 767.5. */
function tabGeomExpr(id) {
  return '(function(id){' +
    'var t=document.getElementById(id);if(!t)return {found:false};' +
    'var bar=t.closest(".hl-rv-bar")||t.parentElement;' +
    'var br=bar.getBoundingClientRect();' +
    'if(br.top<2||br.bottom>innerHeight-2){' +
    'if(bar.scrollIntoView)bar.scrollIntoView({block:"center",behavior:"instant"});}' +
    'var r=t.getBoundingClientRect();' +
    'var client=document.documentElement.clientWidth;' +
    'var clips=[];' +
    'for(var a=t.parentElement;a&&a!==document.documentElement;a=a.parentElement){' +
    'var c=getComputedStyle(a);' +
    'if(!/auto|scroll|hidden|clip/.test(c.overflowX))continue;' +
    'var ar=a.getBoundingClientRect();' +
    'if(r.left>=ar.left-1&&r.right<=ar.right+1)continue;' +
    'clips.push({cls:"."+String(a.className||a.tagName).split(" ")[0],' +
    'left:Math.round(ar.left),right:Math.round(ar.right)});}' +
    'return {found:true,id:id,text:(t.textContent||"").trim().slice(0,40),' +
    'w:Math.round(r.width),h:Math.round(r.height),' +
    'left:Math.round(r.left),right:Math.round(r.right),client:client,' +
    'rects:t.getClientRects().length,clips:clips,' +
    'barTop:Math.round(br.top),barH:Math.round(br.height),innerH:innerHeight};})(' +
    JSON.stringify(id) + ')';
}

/* Where a click at the middle of that tab would land. A clipped or covered tab
   fails here with the element that would take the tap, rather than dispatching
   a click into whatever slid over it. */
function tabHitExpr(id) {
  return '(function(id){var t=document.getElementById(id);if(!t)return null;' +
    'var r=t.getBoundingClientRect();' +
    'var x=Math.round(r.left+r.width/2),y=Math.round(r.top+r.height/2);' +
    'var hit=document.elementFromPoint(x,y);' +
    'return {x:x,y:y,ok:!!hit&&(hit===t||t.contains(hit)),' +
    'hit:hit?(hit.tagName+"."+String(hit.className||"").split(" ")[0]):null};})(' +
    JSON.stringify(id) + ')';
}

var TAB_CLICK_STATE_EXPR = '(function(){' +
  'var sel=document.querySelector("[role=tab][aria-selected=true]");' +
  'var shown=[].slice.call(document.querySelectorAll("[role=tabpanel]"))' +
  '.filter(function(p){return !p.hidden;});' +
  'return {selected:sel?sel.id:null,shown:shown.map(function(p){return p.id;})};})()';

/* The verdict for one tab in row A. PURE, so a test can feed it the four
   measurements a layout mutant changes without launching a browser. */
function tabReachVerdict(token, geom, hit, after) {
  var id = 'tabbtn-' + token;
  if (!geom || !geom.found) return { ok: false, why: id + ': no tab element on the page' };
  var why = [];
  if (!geom.rects || geom.w <= 0 || geom.h <= 0) {
    why.push('rendered with no box (' + geom.w + 'x' + geom.h + ')');
  }
  if (geom.h < MIN_TARGET_PX) why.push('only ' + geom.h + ' px high, under 44');
  (geom.clips || []).forEach(function (c) {
    why.push('clipped by ' + c.cls + ' (' + c.left + '..' + c.right +
      '), so the reader cannot see all of it');
  });
  if (geom.left < -1 || geom.right > geom.client + 1) {
    why.push('outside the viewport width (' + geom.left + '..' + geom.right +
      ' of 0..' + geom.client + ')');
  }
  if (!hit || !hit.ok) {
    why.push('a tap at the middle of the tab would land on ' +
      ((hit && hit.hit) || 'nothing') + ', not on the tab');
  } else if (!after) {
    why.push('the tap was dispatched but the resulting state could not be read');
  } else {
    if (after.selected !== id) {
      why.push('the tap selected ' + (after.selected || 'nothing') + ', not ' + id);
    }
    if (after.shown.length !== 1 || after.shown[0] !== 'tab-' + token) {
      why.push('after the tap the shown panel(s) were ' +
        (after.shown.join(', ') || 'none') + ', not tab-' + token);
    }
  }
  return { ok: why.length === 0, why: why.length ? id + ': ' + why.join('; ') : '' };
}

/* Row B's measurements for one tab: every teardown summary in the panel, and
   every section link in the panel's section navigation. The in-tab contents
   list starts collapsed on a phone, and a link the reader has not opened yet is
   still the size it will be when they do, so it is opened for the measurement
   and put back. */
function tabTargetExpr(token) {
  return '(function(t){' +
    'var p=document.getElementById("tab-"+t);if(!p)return null;' +
    'function dims(e){var r=e.getBoundingClientRect();' +
    'return {text:(e.textContent||"").trim().replace(/\\s+/g," ").slice(0,44),' +
    'w:Math.round(r.width),h:Math.round(r.height),rects:e.getClientRects().length};}' +
    'var toc=[].slice.call(p.querySelectorAll(".hl-rv-contents"));' +
    'var reopened=[];toc.forEach(function(d){if(!d.open){d.open=true;reopened.push(d);}});' +
    'var sums=[].slice.call(p.querySelectorAll("details.hl-teardown > summary")).map(dims);' +
    'var nav=[].slice.call(p.querySelectorAll(".hl-rv-contents nav a")).map(dims);' +
    'toc.forEach(function(d){if(reopened.indexOf(d)>-1)d.open=false;});' +
    'return {sums:sums,nav:nav};})(' + JSON.stringify(token) + ')';
}

/* The verdict for one row-B group at one width. PURE for the same reason as
   tabReachVerdict, and it carries the denominator: how many were measured, how
   many the page holds, and whether the two agree. A group measured 0 times is
   NOT CHECKED, never a pass, and elements the page holds but no tab panel
   contains are named rather than dropped. */
function targetRowVerdict(rows, docTotal, tabs) {
  var small = [], unrendered = [];
  (rows || []).forEach(function (r) {
    if (!r.rects) unrendered.push(r);
    else if (r.w < MIN_TARGET_PX || r.h < MIN_TARGET_PX) small.push(r);
  });
  var failed = small.concat(unrendered);
  var uncovered = Math.max(0, (docTotal || 0) - (rows || []).length);
  var measured = (rows || []).length;
  var detail;
  if (!measured) {
    detail = '0 were measured: no such element was found in any of the ' + tabs +
      ' tabs, so this row measured nothing' +
      (docTotal ? ' (the page holds ' + docTotal + ', all outside the tab panels)' : '');
  } else {
    detail = measured + ' of ' + docTotal + ' measured across ' + tabs + ' tabs, ' +
      small.length + ' under 44, ' + unrendered.length + ' not rendered' +
      (failed.length ? ': ' + failed.map(function (r) {
        return '"' + r.text + '" ' + r.w + 'x' + r.h + (r.rects ? '' : ' (not rendered)');
      }).join(' | ') : '') +
      (uncovered ? '; ' + uncovered + ' the page holds were not inside any tab panel, ' +
        'so they were not measured' : '');
  }
  return { notChecked: measured === 0, ok: measured > 0 && failed.length === 0 && uncovered === 0, detail: detail };
}

/* v6: the selected tab is distinguishable and every tab has its own accent dot, at desktop width where the tab strip shows. */
async function tabLookRows(page, url) {
  var name = 'the selected tab is distinguished by label colour and underline, and every tab carries its own accent dot';
  await setViewport(page, 1280, 900);
  if (!(await gotoAndWait(page, url))) {
    check('NOT CHECKED: ' + name, false, 'the tab controller never built at 1280x900 (no .hl-rv-ready), so nothing was measured');
    return;
  }
  await page.evaluate('location.hash="#tab-chain"');
  await CDP.sleep(150);
  var v = tabLookVerdict(await page.json(TAB_LOOK_EXPR));
  if (v.notChecked) check('NOT CHECKED: ' + name, false, v.detail);
  else check(name, v.ok, v.detail);
}

/* Design v6.1 (T-0500.1.7), Joseph's review of the v6 preview: "no clear separation between anything" and "the text is too small".
   Two rows. (1) The top of the page is a stack of separate containers: each adjacent pair is at least 24 px apart (23.5 allows for
   sub-pixel layout), each is a bordered panel on a surface that is not the page's own, and the tab row and the reading toolbar are on
   different surfaces. (2) The type scale: the report's prose stays 18 px, and at desktop widths tab names are 17 px, secondary text and
   table cells 16 px, mono micro-labels 14 px; on a phone secondary text and table cells keep a 15 px floor. Both are measured in the
   browser, not read from the stylesheet. The verdicts are pure so a test can drive each to FAIL. */
var PANEL_GAP_MIN_PX = 23.5;
var PANEL_COMPONENTS = [
  ['report band', '.hl-rv-reportband__in', true],
  ['header', '.hl-post-header', true],
  ['report sponsor', '.hl-rvsp--report', true],
  ['tab row', '.hl-rv-tabs', true],
  ['toolbar', '.hl-rv-mobile-line', true],
  ['tab title', '.hl-rv-panel:not([hidden]) .hl-rv-panel-head', false],
  ['data view', '.hl-rv-panel:not([hidden]) .hl-rv-view', true],
  ['first section panel', '.hl-rv-panel:not([hidden]) .hl-rv-source', true]
];
var PANEL_EXPR = '(function(){var COMPS=' + JSON.stringify(PANEL_COMPONENTS) + ';' +
  'var page=getComputedStyle(document.body).backgroundColor;' +
  'function vis(e){return !!e&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'var out=[];COMPS.forEach(function(c){var e=[].slice.call(document.querySelectorAll(c[1])).filter(vis)[0];if(!e)return;' +
  'var r=e.getBoundingClientRect(),cs=getComputedStyle(e);out.push({name:c[0],boxed:c[2],top:r.top+scrollY,bottom:r.bottom+scrollY,' +
  'border:parseFloat(cs.borderTopWidth)+parseFloat(cs.borderLeftWidth),bg:cs.backgroundColor,image:cs.backgroundImage!=="none"});});' +
  'return {page:page,items:out};})()';
function panelStackVerdict(m) {
  if (!m || !m.items || m.items.length < 4) return { notChecked: true, ok: false, detail: 'fewer than four top components were found, so no gap was measured' };
  var items = m.items.slice().sort(function (a, b) { return a.top - b.top; });
  var clear = function (c) { return !c || c === 'transparent' || /^rgba\(\s*0,\s*0,\s*0,\s*0\s*\)$/.test(c); };
  var why = [], gaps = [];
  for (var i = 0; i < items.length; i++) {
    var it = items[i];
    if (it.boxed) {
      if (!(it.border >= 1)) why.push(it.name + ' has no border');
      if (it.bg === m.page && !it.image) why.push(it.name + ' is on the page surface ' + it.bg);
      if (clear(it.bg) && !it.image) why.push(it.name + ' has no surface of its own');
    }
    if (i > 0) {
      /* a report sponsor is the attached foot of the header panel (one box), so it is not a gap to measure */
      var prev = items[i - 1], gap = it.top - prev.bottom;
      if (it.name === 'report sponsor' && prev.name === 'header') { if (Math.abs(gap) > 1.5) why.push('the report sponsor is not attached to the header (' + gap.toFixed(1) + ' px)'); continue; }
      gaps.push(prev.name + '->' + it.name + ' ' + gap.toFixed(1));
      if (gap < PANEL_GAP_MIN_PX) why.push(prev.name + ' to ' + it.name + ' is ' + gap.toFixed(1) + ' px apart');
    }
  }
  var tabs = items.filter(function (x) { return x.name === 'tab row'; })[0], bar = items.filter(function (x) { return x.name === 'toolbar'; })[0];
  if (tabs && bar && tabs.bg === bar.bg) why.push('the tab row and the toolbar are on one surface ' + bar.bg);
  return { notChecked: false, ok: why.length === 0, why: why, gaps: gaps, detail: items.length + ' components, gaps ' + gaps.join(', ') + (why.length ? '; ' + why.join('; ') : '') };
}
var TYPE_SPEC = [
  /* [name, selector, desktop min px, phone min px, kind] */
  ['Executive Summary prose', 'LONGP:.hl-rv-panel:not([hidden]) .hl-rv-source > p', 18, 17],
  ['tab name', '.hl-rv-tabs button .hl-rv-tab-full', 17, null],
  ['tab minutes', '.hl-rv-tabs button .hl-rv-tab-time', 14, null],
  ['section panel heading', '.hl-rv-panel:not([hidden]) .hl-rv-source > h2', 20, 18],
  ['data-view summary line', '.hl-rv-panel:not([hidden]) .hl-rv-view-summary p', 16, 15],
  ['stat tile label', '.hl-rv-panel:not([hidden]) .hl-rv-tile > span:not(.hl-rv-tile-destination):not(.hl-rv-value)', 16, 15],
  ['stat tile link', '.hl-rv-panel:not([hidden]) .hl-rv-tile-destination', 14, 14],
  ['how-counted note', '.hl-rv-panel:not([hidden]) .hl-rv-tile-note', 16, 15],
  ['table cell', '.hl-rv-panel:not([hidden]) .hl-rv-source td', 16, 15],
  ['table header', '.hl-rv-panel:not([hidden]) .hl-rv-source th', 14, 14],
  ['toolbar text', '.hl-rv-current-section', 16, 15],
  ['toolbar mono label', '.hl-rv-current', 14, null],
  ['header mono label', '.hl-post-header__badge', 14, 14],
  ['sponsor mono label', '.hl-rvsp__label', 14, 14],
  ['header resource button', '.hl-quicklinks .hl-quicklink__label', 16, 15]
];
var TYPE_EXPR = '(function(){var SPEC=' + JSON.stringify(TYPE_SPEC) + ';' +
  'function vis(e){return e.getClientRects().length>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'return SPEC.map(function(c){var sel=c[1],els;if(sel.indexOf("LONGP:")===0){var e=[].slice.call(document.querySelectorAll(sel.slice(6))).filter(function(x){return vis(x)&&x.textContent.length>200;})[0];els=e?[e]:[];}' +
  'else els=[].slice.call(document.querySelectorAll(sel)).filter(vis);' +
  'return {name:c[0],n:els.length,px:els.length?Math.min.apply(null,els.map(function(e){return parseFloat(getComputedStyle(e).fontSize);})):null};});})()';
function typeScaleVerdict(rows, phone) {
  if (!rows || !rows.length) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  var why = [], measured = 0, listed = [];
  rows.forEach(function (r, i) {
    var min = phone ? TYPE_SPEC[i][3] : TYPE_SPEC[i][2];
    if (min == null) return;
    if (!r.n || r.px == null) return; /* an element absent from this tab is not a failure; the count below says how many were measured */
    measured++;
    listed.push(r.name + ' ' + r.px);
    if (r.px < min - 0.01) why.push(r.name + ' is ' + r.px + ' px, floor ' + min);
  });
  if (measured < 8) return { notChecked: true, ok: false, detail: 'only ' + measured + ' of the type-scale elements were found, so the scale was not measured' };
  return { notChecked: false, ok: why.length === 0, why: why, detail: measured + ' elements measured (' + listed.join(', ') + ')' + (why.length ? '; ' + why.join('; ') : '') };
}
async function panelRows(page, url) {
  var states = [[1280, 900, 'desktop 1280', false], [390, 844, 'phone 390', true]];
  for (var i = 0; i < states.length; i++) {
    var w = states[i][0], h = states[i][1], label = states[i][2], phone = states[i][3];
    await setViewport(page, w, h);
    var nameA = 'the top of the page is separate panels, each at least 24 px apart, on their own surfaces';
    var nameB = 'text is on the v6.1 scale: tab names 17, secondary and table text 16, mono labels 14, phone floor 15';
    if (!(await gotoAndWait(page, url))) {
      check('NOT CHECKED: ' + label + ': ' + nameA, false, 'the tab controller never built, so nothing was measured');
      check('NOT CHECKED: ' + label + ': ' + nameB, false, 'the tab controller never built, so nothing was measured');
      continue;
    }
    var tabsMeasured = [];
    for (var t = 0; t < 2; t++) {
      var token = TAB_TOKENS[t === 0 ? 0 : 2]; /* overview (tiles, lead) and chain (tables, filters) */
      await page.evaluate('location.hash="#tab-' + token + '"');
      await CDP.sleep(250);
      await page.evaluate('window.scrollTo(0,0)');
      await CDP.sleep(150);
      var pv = panelStackVerdict(await page.json(PANEL_EXPR));
      if (pv.notChecked) check('NOT CHECKED: ' + label + ' ' + token + ': ' + nameA, false, pv.detail);
      else check(label + ' ' + token + ': ' + nameA, pv.ok, pv.detail);
      await page.evaluate('document.querySelectorAll(".hl-rv-view details").forEach(function(d){d.open=true;})');
      var tv = typeScaleVerdict(await page.json(TYPE_EXPR), phone);
      if (tv.notChecked) check('NOT CHECKED: ' + label + ' ' + token + ': ' + nameB, false, tv.detail);
      else check(label + ' ' + token + ': ' + nameB, tv.ok, tv.detail);
    }
  }
}

/* T-0500.1.8, reworked 2026-10-30 (Joseph's decision, amendment 1): the gold featured band at the top of the page is the REPORT sponsor
   (the page's sponsored_by), labelled "This report is sponsored by"; a report with no sponsor has no band at all. The Monthly (site) sponsor is
   the site's own Sponsors rail (rows below) and, when no report sponsor exists, the gold card at each tab foot. There is no sponsor mark on the
   reading line in either case. One row, measured in the browser at 1280 and 390 on two tabs. With a report sponsor: the band has the gold 4px
   left bar and the dark gradient, the label in gold, a visible tagline and a visible, real "Visit" element (aria-hidden, inside the sponsor's
   link, inside the panel; with several sponsors, logos only), and the tab-foot card is the report card (tab accent, no gold, no Visit). With no
   report sponsor: no band is in the DOM, and the tab-foot card is the gold featured card. A page with no sponsor at all draws none of it.
   The verdict is pure so a test can drive each failure. */
var GOLD_BAR = 'rgb(184, 144, 47)';
var GOLD_LABEL = 'rgb(212, 167, 58)';
var FEATURED_LABEL = "Featured sponsor of The Hunter's Ledger";
var BAND_LABEL = 'This report is sponsored by';
var FEATURED_EXPR = '(function(){' +
  'function vis(e){if(!e)return false;var cs=getComputedStyle(e);return e.getClientRects().length>0&&cs.visibility!=="hidden"&&cs.display!=="none"&&e.getBoundingClientRect().height>0;}' +
  'function one(sel,root){return [].slice.call((root||document).querySelectorAll(sel)).filter(vis)[0]||null;}' +
  'function measure(root,k){if(!root)return null;var r=root.getBoundingClientRect(),cs=getComputedStyle(root);' +
  'var lab=root.querySelector(k.label),items=[].slice.call(root.querySelectorAll(k.item));' +
  'return {w:r.width,h:r.height,barW:parseFloat(cs.borderLeftWidth),bar:cs.borderLeftColor,image:cs.backgroundImage!=="none",' +
  'cls:root.className,text:root.textContent.replace(/\\s+/g," ").trim(),' +
  'label:lab?lab.textContent.trim():null,labelVisible:vis(lab),labelColor:lab?getComputedStyle(lab).color:null,' +
  'many:root.classList.contains("hl-rvsp__zone--many")||!!root.querySelector(".hl-rvsp__zone--many")||root.classList.contains("is-many"),' +
  'items:items.length,withTagline:items.filter(function(i){return i.hasAttribute("data-tagline")||!!i.querySelector(k.tag);}).length,' +
  'taglines:[].slice.call(root.querySelectorAll(k.tag)).map(function(e){return {vis:vis(e),len:e.textContent.trim().length};}),' +
  'ctas:[].slice.call(root.querySelectorAll(k.cta)).map(function(e){var b=e.getBoundingClientRect();return {vis:vis(e),text:e.textContent.trim(),ariaHidden:e.getAttribute("aria-hidden"),inLink:!!e.closest("a[href]"),' +
  'inside:b.left>=r.left-1&&b.right<=r.right+1&&b.top>=r.top-1&&b.bottom<=r.bottom+1,tag:e.tagName};})};}' +
  'var band=one(".hl-rv-reportband__in"),card=one(".hl-rv-panel:not([hidden]) .hl-rv-sponsor-card");' +
  'var b=measure(band,{label:".hl-rv-reportband__label",item:".hl-rvsp__item",tag:".hl-rvsp__tagline",cta:".hl-rvsp__cta"});' +
  'if(b)b.many=!!document.querySelector(".hl-rv-reportband__in.hl-rvsp__zone--many");' +
  'var c=measure(card,{label:".hl-rv-sponsor-card__label",item:".hl-rv-sponsor-card__item",tag:".hl-rv-sponsor-card__tagline",cta:".hl-rv-sponsor-card__cta"});' +
  'if(c){c.isReport=card.classList.contains("is-report");' +
  'var pr=document.createElement("span");pr.style.cssText="color:var(--acc);position:absolute;visibility:hidden";card.appendChild(pr);' +
  'c.acc=getComputedStyle(card).getPropertyValue("--acc").trim()?getComputedStyle(pr).color:null;card.removeChild(pr);}' +
  'return {reportSponsors:document.querySelectorAll(".hl-rvsp--report .hl-rvsp__item").length,siteItems:document.querySelectorAll(".hl-sponsor-rail .hl-sponsor-rail__item").length,band:b,bandInDom:!!document.querySelector(".hl-rv-reportband"),card:c,' +
  'markPresent:!!document.querySelector(".hl-rv-sponsor-mark,.hl-rv-sponsor-mark__label")};})()';
function featuredPanelWhy(name, p, expectGold, label) {
  var why = [];
  if (!p) { why.push(name + ' was not found'); return why; }
  var gold = p.barW >= 4 && p.bar === GOLD_BAR;
  if (expectGold) {
    if (!gold) why.push(name + ' has no 4px gold left bar (' + p.barW + 'px ' + p.bar + ')');
    if (!p.image) why.push(name + ' has no gradient panel fill');
    if (p.label !== label) why.push(name + ' label is ' + JSON.stringify(p.label) + ', not "' + label + '"');
    else if (!p.labelVisible) why.push(name + ' label is not visible');
    else if (p.labelColor !== GOLD_LABEL) why.push(name + ' label is ' + p.labelColor + ', not gold ' + GOLD_LABEL);
    var shownTaglines = p.taglines.filter(function (t) { return t.vis && t.len > 0; }).length;
    var shownCtas = p.ctas.filter(function (c) { return c.vis; }).length;
    if (p.many) {
      if (shownTaglines) why.push(name + ' shows ' + shownTaglines + ' tagline(s) with several sponsors (logos only expected)');
      if (shownCtas) why.push(name + ' shows ' + shownCtas + ' Visit element(s) with several sponsors (logos only expected)');
    } else {
      if (!p.withTagline) why.push(name + ' has no sponsor tagline in the markup, so no tagline could be measured');
      else if (shownTaglines < p.withTagline) why.push(name + ' shows ' + shownTaglines + ' of ' + p.withTagline + ' tagline(s)');
      if (!p.ctas.length) why.push(name + ' has no Visit element');
      p.ctas.forEach(function (c) {
        if (!c.vis) why.push(name + ' Visit element is not visible');
        if (!/^Visit\b/.test(c.text)) why.push(name + ' Visit element reads ' + JSON.stringify(c.text));
        if (c.ariaHidden !== 'true') why.push(name + ' Visit element is not aria-hidden (it would double the link name)');
        if (!c.inLink) why.push(name + ' Visit element is not inside the sponsor link');
        if (!c.inside) why.push(name + ' Visit element sits outside the panel');
        if (c.tag !== 'SPAN') why.push(name + ' Visit element is a ' + c.tag + ', not the span the markup carries');
      });
    }
  } else {
    if (gold) why.push(name + ' has the gold bar on a report sponsor');
    if (p.image) why.push(name + ' has a gradient fill on a report sponsor');
    if (/Featured/i.test(p.text)) why.push(name + ' says "Featured" on a report sponsor');
    if (p.ctas.length) why.push(name + ' carries a Visit element on a report sponsor');
    /* the report card keeps the active tab's accent: a 4px left bar whose colour is the panel's --acc. An accent that could not be read is NOT CHECKED, never a pass. */
    if (!p.acc) return { notChecked: true, why: why.concat(name + ': the active tab accent (--acc) could not be read, so the bar colour was not compared') };
    if (!(p.barW >= 4)) why.push(name + ' has no 4px left bar in the tab accent (' + p.barW + 'px ' + p.bar + ')');
    else if (p.bar !== p.acc) why.push(name + ' left bar is ' + p.bar + ', not the active tab accent ' + p.acc);
  }
  return why;
}
function featuredSponsorVerdict(m) {
  if (!m) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  var why = [], measured = [], accUnread = false;
  if (m.markPresent) why.push('a sponsor mark is on the reading line (Joseph removed it for both sponsor kinds)');
  if (m.reportSponsors === 0) {
    /* no report sponsor: no band at all, and the gold card is the site sponsor's */
    if (m.bandInDom || m.band) why.push('a band is drawn on a page with no report sponsor');
    if (m.siteItems === 0 && m.card) why.push('a tab-foot card is drawn with no sponsor on the page');
    if (m.siteItems === 0) {
      return { notChecked: false, ok: why.length === 0, none: true, why: why, detail: 'no sponsor on this page: 0 panels expected, ' + ((m.bandInDom || m.band ? 1 : 0) + (m.markPresent ? 1 : 0) + (m.card ? 1 : 0)) + ' drawn' + (why.length ? '; ' + why.join('; ') : '') };
    }
    measured.push('no band');
    if (!m.card) why.push('the tab-foot card was not found with ' + m.siteItems + ' site sponsor(s) on the page');
    else if (m.card.isReport) why.push('the tab-foot card is the report-sponsor card with no report sponsor');
    else { measured.push('tab-foot card'); why = why.concat(featuredPanelWhy('the tab-foot card', m.card, true, FEATURED_LABEL)); }
  } else {
    if (!m.band) why.push('the report band was not found with ' + m.reportSponsors + ' report sponsor(s) on the page'); else { measured.push('report band'); why = why.concat(featuredPanelWhy('the report band', m.band, true, BAND_LABEL)); }
    if (!m.card) why.push('the tab-foot card was not found'); else if (!m.card.isReport) why.push('the tab-foot card is the featured site card although the page has a report sponsor'); else { var rw = featuredPanelWhy('the report-sponsor card', m.card, false); if (rw.notChecked) { accUnread = true; why = why.concat(rw.why); } else { measured.push('tab-foot card (report)'); why = why.concat(rw); } }
  }
  if (accUnread && !why.some(function (w) { return !/could not be read/.test(w); })) return { notChecked: true, ok: false, detail: why.join('; ') };
  if (!measured.length) return { notChecked: true, ok: false, detail: 'a sponsor is on the page but no featured-sponsor element could be measured' };
  return { notChecked: false, ok: why.length === 0, why: why, detail: (m.reportSponsors === 0 ? 'site sponsor, no report sponsor' : 'report sponsor') + ': ' + measured.join(', ') + ' measured' + (why.length ? '; ' + why.join('; ') : '') };
}
async function featuredSponsorRows(page, url) {
  var states = [[1280, 900, 'desktop 1280'], [390, 844, 'phone 390']];
  var name = 'the report sponsor is the gold band (none without one), the Monthly sponsor the gold tab-foot card, and no sponsor mark sits on the reading line';
  for (var i = 0; i < states.length; i++) {
    await setViewport(page, states[i][0], states[i][1]);
    if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + states[i][2] + ': ' + name, false, 'the tab controller never built, so nothing was measured'); continue; }
    for (var t = 0; t < 2; t++) {
      var token = TAB_TOKENS[t === 0 ? 0 : 2];
      await page.evaluate('location.hash="#tab-' + token + '"');
      await CDP.sleep(250);
      await page.evaluate('window.scrollTo(0,0)');
      await CDP.sleep(150);
      var fv = featuredSponsorVerdict(await page.json(FEATURED_EXPR));
      if (fv.notChecked) check('NOT CHECKED: ' + states[i][2] + ' ' + token + ': ' + name, false, fv.detail);
      else check(states[i][2] + ' ' + token + ': ' + name, fv.ok, fv.detail);
    }
  }
}

/* T-0500.1.8: the site's Sponsors rail on a tabbed page. Where the left gutter fits it (viewport 1600 and up) it is the site's fixed card,
   at least 16 px clear of the 1200 px column and inside the viewport; below that it is the site's in-flow strip under the navbar, above the
   report, not hidden. The expected mode is stated per viewport, so a rail that is hidden, or fixed where the gutter is too narrow, FAILS. */
var RAIL_STATES = [[1280, 900, 'strip'], [1440, 900, 'strip'], [1600, 900, 'fixed'], [1920, 1080, 'fixed'], [2560, 1300, 'fixed'], [390, 844, 'strip']];
var RAIL_CLEAR_MIN_PX = 16;
var RAIL_EXPR = '(function(){var r=document.querySelector(".hl-sponsor-rail"),col=document.querySelector(".hl-report-page");' +
  'if(!r||!col)return {present:false};var cs=getComputedStyle(r),b=r.getBoundingClientRect(),c=col.getBoundingClientRect();' +
  'var items=[].slice.call(r.querySelectorAll(".hl-sponsor-rail__item")).filter(function(i){var x=i.getBoundingClientRect();return x.width>0&&x.height>0;}).length;' +
  'return {present:true,display:cs.display,visibility:cs.visibility,position:cs.position,left:b.left,right:b.right,top:b.top,bottom:b.bottom,width:b.width,height:b.height,' +
  'colLeft:c.left,colRight:c.right,colTop:c.top,vw:document.documentElement.clientWidth,iw:innerWidth,visibleItems:items,allItems:r.querySelectorAll(".hl-sponsor-rail__item").length};})()';
function railVerdict(m, expect) {
  if (!m || !m.present) return { notChecked: true, ok: false, detail: 'no Sponsors rail is in the page, so there was nothing to place' };
  var why = [];
  if (m.display === 'none' || m.visibility === 'hidden' || !m.width || !m.height) why.push('the rail is hidden (display ' + m.display + ', ' + m.width + 'x' + m.height + ')');
  else {
    if (m.visibleItems < m.allItems || !m.visibleItems) why.push(m.visibleItems + ' of ' + m.allItems + ' sponsor card(s) are visible');
    if (expect === 'fixed') {
      if (m.position !== 'fixed') why.push('the rail is ' + m.position + ', not fixed in the gutter');
      var clear = m.colLeft - m.right;
      if (clear < RAIL_CLEAR_MIN_PX) why.push('the rail is ' + clear.toFixed(1) + ' px from the column (at least ' + RAIL_CLEAR_MIN_PX + ' needed)');
      if (m.left < 0) why.push('the rail starts at ' + m.left.toFixed(1) + ' px, outside the viewport');
      if (m.width < 120 || m.width > 200.5) why.push('the rail is ' + m.width.toFixed(1) + ' px wide (120 to 200 expected)');
    } else {
      if (m.position === 'fixed') why.push('the rail is fixed at a width where the gutter does not fit it; the site strip is expected');
      if (m.bottom > m.colTop + 1) why.push('the strip ends at ' + m.bottom.toFixed(1) + ' px, below the top of the report (' + m.colTop.toFixed(1) + ')');
      if (m.height > 160) why.push('the strip is ' + m.height.toFixed(1) + ' px tall, not a strip');
    }
  }
  var clearTxt = m.colLeft - m.right;
  return { notChecked: false, ok: why.length === 0, why: why, detail: expect + ' mode: position ' + m.position + ', ' + m.width.toFixed(1) + 'x' + m.height.toFixed(1) + ' px at x ' + m.left.toFixed(1) + ' to ' + m.right.toFixed(1) + ', column starts at ' + m.colLeft.toFixed(1) + (expect === 'fixed' ? ' (clear ' + clearTxt.toFixed(1) + ' px)' : '') + ', ' + m.visibleItems + ' of ' + m.allItems + ' card(s) visible' + (why.length ? '; ' + why.join('; ') : '') };
}
async function sponsorRailRows(page, url) {
  var name = 'the site Sponsors rail is the fixed gutter card where the gutter fits it and the site strip where it does not, never hidden';
  for (var i = 0; i < RAIL_STATES.length; i++) {
    var s = RAIL_STATES[i];
    await setViewport(page, s[0], s[1]);
    if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + s[0] + 'x' + s[1] + ': ' + name, false, 'the tab controller never built, so nothing was measured'); continue; }
    await page.evaluate('window.scrollTo(0,0)');
    await CDP.sleep(200);
    var rv = railVerdict(await page.json(RAIL_EXPR), s[2]);
    if (rv.notChecked) check('NOT CHECKED: ' + s[0] + 'x' + s[1] + ': ' + name, false, rv.detail);
    else check(s[0] + 'x' + s[1] + ' (' + s[2] + '): ' + name, rv.ok, rv.detail);
  }
}

/* T-0500.1.7.1: the share icon in the header box's top-right corner (Joseph, 2026-10-30). Geometry at three widths: present, labelled, a 44 px
   target inside the header box and in its corner, overlapping neither the eyebrow line, the title nor the resource buttons, keyboard-focusable with
   a visible focus ring, with an aria-live region beside it. Behaviour at one width: with no share sheet a click writes the page address to the
   clipboard and says "Link copied" in view; with a share sheet it calls it with the page address and does not touch the clipboard. */
var SHARE_VIEWPORTS = [[1280, 900], [768, 1024], [390, 844]];
var SHARE_EXPR = '(function(){var h=document.querySelector(".hl-report-page .hl-post-header"),b=document.querySelector(".hl-rv-share-btn");' +
  'function R(e){var r=e.getBoundingClientRect();return {l:r.left,t:r.top,r:r.right,b:r.bottom,w:r.width,h:r.height};}' +
  'function vis(e){var r=e.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'if(!h)return {header:false};var out={header:true,hdr:R(h),present:!!b,shareStillThere:!!document.querySelector(".hl-share-btn")};if(!b)return out;' +
  'out.btn=R(b);out.label=b.getAttribute("aria-label");out.tag=b.tagName;out.type=b.type;out.disabled=b.disabled;out.tabIndex=b.tabIndex;out.inHeader=h.contains(b);' +
  'var others=[].slice.call(h.querySelectorAll(".hl-post-header__eyebrow > *,.hl-post-header__title,.hl-quicklinks .hl-quicklink,.hl-quicklinks .hl-cta")).filter(vis);' +
  'out.checked=others.length;out.overlaps=others.filter(function(e){var o=R(e);return o.l<out.btn.r-0.5&&o.r>out.btn.l+0.5&&o.t<out.btn.b-0.5&&o.b>out.btn.t+0.5;}).map(function(e){return (e.className||e.tagName).toString().split(" ")[0];});' +
  'var live=document.querySelector(".hl-rv-share [role=status][aria-live]");out.live=!!live;out.liveText=live?live.textContent:null;' +
  'b.focus();var cs=getComputedStyle(b);out.focused=document.activeElement===b;out.outlineStyle=cs.outlineStyle;out.outlineWidth=parseFloat(cs.outlineWidth);out.focusVisible=b.matches(":focus-visible");b.blur();' +
  'return out;})()';
function shareGeometryVerdict(m) {
  if (!m || !m.header) return { notChecked: true, ok: false, detail: 'no report header was found, so nothing was measured' };
  var why = [];
  if (m.shareStillThere) why.push('the old Share button is still in the resource row');
  if (!m.present) { why.push('there is no share icon button in the header'); return { notChecked: false, ok: false, why: why, detail: why.join('; ') }; }
  if (m.label !== 'Share this report') why.push('aria-label is ' + JSON.stringify(m.label) + ', not "Share this report"');
  if (m.tag !== 'BUTTON' || m.type !== 'button') why.push('it is a ' + m.tag + ' (type ' + m.type + '), not a type=button button');
  if (m.btn.w < 44 - 0.5 || m.btn.h < 44 - 0.5) why.push('the target is ' + m.btn.w.toFixed(1) + 'x' + m.btn.h.toFixed(1) + ' px, under 44');
  if (!m.inHeader || m.btn.l < m.hdr.l || m.btn.r > m.hdr.r + 0.5 || m.btn.t < m.hdr.t || m.btn.b > m.hdr.b) why.push('it is not inside the header box');
  var fromRight = m.hdr.r - m.btn.r, fromTop = m.btn.t - m.hdr.t;
  if (fromRight > 16 || fromTop > 16) why.push('it is not in the top-right corner (' + fromRight.toFixed(1) + ' px from the right edge, ' + fromTop.toFixed(1) + ' px from the top)');
  if (m.overlaps.length) why.push('it overlaps ' + m.overlaps.join(', '));
  if (m.disabled || m.tabIndex < 0 || !m.focused) why.push('it cannot take keyboard focus (tabIndex ' + m.tabIndex + ', focused ' + m.focused + ')');
  else if (m.outlineStyle === 'none' || !(m.outlineWidth >= 2) || !m.focusVisible) why.push('no visible focus ring (outline ' + m.outlineStyle + ' ' + m.outlineWidth + 'px, :focus-visible ' + m.focusVisible + ')');
  if (!m.live) why.push('no aria-live status region beside it');
  return { notChecked: false, ok: why.length === 0, why: why, detail: 'icon ' + m.btn.w.toFixed(0) + 'x' + m.btn.h.toFixed(0) + ' px, ' + fromRight.toFixed(1) + ' px from the right and ' + fromTop.toFixed(1) + ' px from the top of the header box, ' + m.checked + ' neighbouring element(s) checked for overlap, focus ring ' + m.outlineWidth + 'px' + (why.length ? '; ' + why.join('; ') : '') };
}
function shareBehaviourVerdict(m) {
  if (!m) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  var why = [];
  if (!m.href) why.push('the page address was not read');
  if (m.writes.length !== 1 || m.writes[0] !== m.href) why.push('the clipboard got ' + JSON.stringify(m.writes) + ', not the page address');
  if (m.status !== 'Link copied') why.push('the live region says ' + JSON.stringify(m.status) + ', not "Link copied"');
  if (!m.statusVisible) why.push('"Link copied" is not drawn in view');
  if (m.shares.length !== 1 || !m.shares[0] || m.shares[0].url !== m.href) why.push('with a share sheet present it was called with ' + JSON.stringify(m.shares) + ', not the page address');
  if (m.writesAfterShare !== m.writes.length) why.push('with a share sheet present the clipboard was written as well');
  return { notChecked: false, ok: why.length === 0, why: why, detail: 'no share sheet: clipboard written ' + m.writes.length + ' time(s), status ' + JSON.stringify(m.status) + (m.statusVisible ? ' in view' : ' NOT in view') + '; share sheet present: called ' + m.shares.length + ' time(s), clipboard written ' + (m.writesAfterShare - m.writes.length) + ' more time(s)' + (why.length ? '; ' + why.join('; ') : '') };
}
async function shareRows(page, url) {
  var nameA = 'the share icon is a labelled 44 px button in the header box corner, clear of the eyebrow, title and buttons, with a focus ring';
  var nameB = 'clicking the share icon copies the page address and says "Link copied", or hands it to the share sheet when there is one';
  for (var i = 0; i < SHARE_VIEWPORTS.length; i++) {
    var w = SHARE_VIEWPORTS[i][0], h = SHARE_VIEWPORTS[i][1];
    await setViewport(page, w, h);
    if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameA, false, 'the tab controller never built, so nothing was measured'); continue; }
    await page.evaluate('window.scrollTo(0,0)');
    await CDP.sleep(200);
    var gv = shareGeometryVerdict(await page.json(SHARE_EXPR));
    if (gv.notChecked) check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameA, false, gv.detail);
    else check(w + 'x' + h + ': ' + nameA, gv.ok, gv.detail);
  }
  await setViewport(page, 1280, 900);
  if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + nameB, false, 'the tab controller never built, so nothing was measured'); return; }
  await page.evaluate('window.scrollTo(0,0)');
  var m = await page.json('(function(){var st={writes:[],shares:[]};window.__rvShare=st;' +
    'Object.defineProperty(navigator,"share",{value:undefined,configurable:true});' +
    'Object.defineProperty(navigator,"clipboard",{value:{writeText:function(t){st.writes.push(t);return Promise.resolve();}},configurable:true});' +
    'var b=document.querySelector(".hl-rv-share-btn");if(!b)return null;b.click();return {started:true};})()');
  if (!m) { check(nameB, false, 'there is no share icon button to click'); return; }
  await CDP.sleep(400);
  var afterCopy = await page.json('(function(){var s=document.querySelector(".hl-rv-share-status"),r=s?s.getBoundingClientRect():null;' +
    'return {href:location.href,writes:window.__rvShare.writes.slice(),status:s?s.textContent:null,statusVisible:!!r&&r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight&&r.left>=0&&r.right<=innerWidth};})()');
  var afterShare = await page.json('(function(){var st=window.__rvShare;Object.defineProperty(navigator,"share",{value:function(d){st.shares.push({url:d.url,title:d.title});return Promise.resolve();},configurable:true});' +
    'document.querySelector(".hl-rv-share-btn").click();return {shares:st.shares.slice(),writes:st.writes.length};})()');
  var bv = shareBehaviourVerdict({ href: afterCopy.href, writes: afterCopy.writes, status: afterCopy.status, statusVisible: afterCopy.statusVisible, shares: afterShare.shares, writesAfterShare: afterShare.writes });
  check(nameB, bv.ok, bv.detail);
}

/* T-0500.1.7.1: the MISP button. A tabbed report renders the same MISP quick link a normal report does (one lookup in _layouts/post.html against
   _data/misp_events.yml, matched on the page's URL): when the lookup finds an event there is a MISP button in the header's button row, linking to
   that event; when it finds none there is no button and nothing else in its place. The expectation is read from the data file for the page's own
   URL, so a page whose URL has no event is checked for the absence, and the Share button is gone in both. */
function mispEventFor(pathname) {
  try {
    var doc = (yaml || require('js-yaml')).load(fs.readFileSync(path.join(ROOT, '_data', 'misp_events.yml'), 'utf8'));
    var ev = (doc && doc.events || []).filter(function (e) { return e.report_url === pathname; })[0];
    return ev ? ev.event_url : null;
  } catch (e) { return undefined; }
}
var MISP_EXPR = '(function(){function vis(e){var r=e.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'var h=document.querySelector(".hl-report-page .hl-post-header"),links=[].slice.call(document.querySelectorAll(".hl-quicklinks a.hl-quicklink")).filter(function(a){return /^MISP\\b/.test((a.querySelector(".hl-quicklink__label")||{}).textContent||"");});' +
  'var a=links[0]||null,r=a?a.getBoundingClientRect():null;' +
  'return {count:links.length,shareStillThere:!!document.querySelector(".hl-share-btn"),found:!!a,href:a?a.getAttribute("href"):null,target:a?a.target:null,rel:a?a.rel:null,' +
  'label:a?a.getAttribute("aria-label"):null,cls:a?a.className:null,visible:a?vis(a):false,w:r?r.width:0,h:r?r.height:0,inHeader:!!(a&&h&&h.contains(a)),' +
  'inRow:!!(a&&a.closest(".hl-quicklinks")),icon:!!(a&&a.querySelector(".hl-quicklink__icon svg"))};})()';
function mispVerdict(m, expectedHref, pathname) {
  if (!m) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  if (expectedHref === undefined) return { notChecked: true, ok: false, detail: '_data/misp_events.yml could not be read, so it is not known whether this page has an event' };
  var why = [];
  if (m.shareStillThere) why.push('the old Share button is still in the resource row');
  if (expectedHref === null) {
    if (m.found) why.push('a MISP button is drawn although _data/misp_events.yml has no event for ' + pathname);
    return { notChecked: false, ok: why.length === 0, none: true, why: why, detail: 'no MISP event for ' + pathname + ' in _data/misp_events.yml: 0 buttons expected, ' + m.count + ' drawn' + (why.length ? '; ' + why.join('; ') : '') };
  }
  if (!m.found) why.push('the data has a MISP event for ' + pathname + ' but no MISP button is drawn');
  else {
    if (m.count !== 1) why.push(m.count + ' MISP buttons (1 expected)');
    if (m.href !== expectedHref) why.push('it links to ' + m.href + ', not the event ' + expectedHref);
    if (m.target !== '_blank' || !/noopener/.test(m.rel || '')) why.push('it does not open in a new tab with noopener (' + m.target + ', ' + m.rel + ')');
    if (!/MISP event for this report/.test(m.label || '')) why.push('its aria-label is ' + JSON.stringify(m.label));
    if (!/\bhl-quicklink\b/.test(m.cls || '') || !m.inRow || !m.icon) why.push('it is not the normal report markup (class ' + m.cls + ', in the quicklinks row ' + m.inRow + ', icon ' + m.icon + ')');
    if (!m.visible) why.push('it is not visible');
    if (!m.inHeader) why.push('it is not in the header box');
    if (m.w < 43.5 || m.h < 43.5) why.push('it is ' + m.w.toFixed(1) + 'x' + m.h.toFixed(1) + ' px, under 44');
  }
  return { notChecked: false, ok: why.length === 0, why: why, detail: 'MISP event ' + expectedHref + ': ' + m.count + ' button(s), ' + m.w.toFixed(0) + 'x' + m.h.toFixed(0) + ' px' + (why.length ? '; ' + why.join('; ') : '') };
}
async function mispRows(page, url) {
  var name = 'the header button row has the MISP button when the page has a MISP event, and no Share button';
  /* the page's own URL is its canonical link (Jekyll's page.url, the thing the layout's lookup matches); a local render served at another path
     still names the URL it stands for. With no canonical link the request path is the best available answer. */
  var states = [[1280, 900], [390, 844]];
  for (var i = 0; i < states.length; i++) {
    await setViewport(page, states[i][0], states[i][1]);
    if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + states[i][0] + 'x' + states[i][1] + ': ' + name, false, 'the tab controller never built, so nothing was measured'); continue; }
    await page.evaluate('window.scrollTo(0,0)');
    await CDP.sleep(150);
    var canonical = await page.json('(function(){var l=document.querySelector("link[rel=canonical]");return l?l.href:null;})()');
    var pathname = new URL(canonical || url).pathname;
    var expected = mispEventFor(pathname);
    var v = mispVerdict(await page.json(MISP_EXPR), expected, pathname);
    if (v.notChecked) check('NOT CHECKED: ' + states[i][0] + 'x' + states[i][1] + ': ' + name, false, v.detail);
    else check(states[i][0] + 'x' + states[i][1] + ': ' + name, v.ok, v.detail);
  }
}

/* T-0500.1.9 (Joseph 2026-10-30, audit H07 and F2): the ATT&CK coverage strip and the Navigator layer download are back on tabbed pages. On a
   tabbed report whose Attack chain tab holds an ATT&CK mapping table (a table whose header names a Tactic and whose rows carry technique IDs,
   found here WITHOUT the strip's own parser so a page that never loaded attack-coverage.js cannot excuse itself), the Attack chain panel draws
   one coverage strip per such table: every tactic bar of the strip (15), a count of more than 0 techniques, the strip marked as generated
   chrome so the completeness gate does not count its words, and a "Navigator layer" button that, clicked, offers a .json file whose layer lists
   techniques. A report with no such table is NOT CHECKED, never a pass. The control serves the same page with the attack-coverage.js script tag
   removed and requires this row to FAIL on it. */
var ATTACK_STRIP_EXPR = '(async function(){' +
  'function vis(e){var r=e.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'var panel=document.getElementById("tab-chain");' +
  'var tables=[].slice.call(document.querySelectorAll(".hl-post-content table")).filter(function(t){var h=t.rows[0]?t.rows[0].textContent:"";return /tactic/i.test(h)&&/\\bT\\d{4}/.test(t.textContent);});' +
  'var strips=[].slice.call(document.querySelectorAll(".hl-attack"));' +
  'var mine=strips.filter(function(x){return panel&&panel.contains(x);});var st=mine[0]||null;' +
  'var exp=st?[].slice.call(st.querySelectorAll(".hl-attack__export")):[];var btn=exp[0]||null;' +
  'var dl=null;if(btn){var cap=null,old=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){cap={href:this.href,download:this.download};};' +
  'try{btn.click();}finally{HTMLAnchorElement.prototype.click=old;}' +
  'if(cap){try{var j=JSON.parse(await (await fetch(cap.href)).text());dl={file:cap.download,techniques:(j.techniques||[]).length,domain:j.domain||null};}catch(e){dl={file:cap.download,error:String(e)};}}else dl={error:"clicking the button offered no file"};}' +
  'var cnt=st?(st.querySelector(".hl-attack__count")||{}).textContent||"":"";var n=cnt.match(/(\\d+) techniques/);' +
  'return JSON.stringify({mappingTables:tables.length,tablesInChain:tables.filter(function(t){return panel&&panel.contains(t);}).length,panelFound:!!panel,' +
  'strips:strips.length,inChain:mine.length,chrome:mine.filter(function(x){return x.hasAttribute("data-rv-chrome");}).length,' +
  'segs:st?st.querySelectorAll(".hl-attack__seg").length:0,techniques:n?Number(n[1]):0,count:cnt,' +
  'visible:st?vis(st):false,exportCount:exp.length,exportVisible:btn?vis(btn):false,exportText:btn?btn.textContent.trim():null,download:dl});})()';
function attackStripVerdict(m) {
  if (!m) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  if (!m.panelFound) return { notChecked: true, ok: false, detail: 'the page has no Attack chain panel (#tab-chain), so there is nothing to look in' };
  if (!m.mappingTables) return { notChecked: true, ok: false, detail: 'no ATT&CK mapping table (a Tactic column with technique IDs) on this report, so no strip is expected' };
  var why = [];
  if (!m.tablesInChain) why.push('the ATT&CK mapping table is not in the Attack chain tab, so the strip cannot be there');
  if (m.inChain < 1) why.push('no coverage strip is drawn in the Attack chain tab although the report has ' + m.mappingTables + ' ATT&CK mapping table(s) (' + m.strips + ' strip(s) on the whole page)');
  else {
    if (m.chrome !== m.inChain) why.push(m.inChain - m.chrome + ' strip(s) are not marked data-rv-chrome, so the completeness gate would count their words as report text');
    if (m.segs !== 15) why.push('the strip has ' + m.segs + ' tactic bars (15 expected)');
    if (!(m.techniques > 0)) why.push('the strip counts ' + m.techniques + ' techniques (' + JSON.stringify(m.count) + ')');
    if (!m.visible) why.push('the strip is not painted');
    if (m.exportCount !== 1) why.push(m.exportCount + ' Navigator layer buttons in the strip (1 expected)');
    else {
      if (!/Navigator layer/.test(m.exportText || '')) why.push('the download button reads ' + JSON.stringify(m.exportText));
      if (!m.exportVisible) why.push('the Navigator layer button is not painted');
      if (!m.download || m.download.error) why.push('the Navigator layer button offered no usable file (' + (m.download ? m.download.error : 'no result') + ')');
      else if (!/\.json$/.test(m.download.file || '') || !(m.download.techniques > 0)) why.push('the download is ' + JSON.stringify(m.download.file) + ' with ' + m.download.techniques + ' technique(s) in its layer');
    }
  }
  return { notChecked: false, ok: why.length === 0, why: why, detail: m.inChain + ' strip(s) in the Attack chain tab of ' + m.mappingTables + ' mapping table(s), ' + m.segs + ' bars, ' + m.techniques + ' techniques' + (m.download && m.download.file ? ', download ' + m.download.file + ' with ' + m.download.techniques + ' technique(s)' : '') + (why.length ? '; ' + why.join('; ') : '') };
}
function attackStripControlHtml(html) {
  var out = String(html).replace(/<script\b[^>]*attack-coverage\.js[^>]*><\/script>/, '');
  return out === html ? null : out;
}
async function attackStripRows(page, url, html) {
  var name = 'the Attack chain tab draws the ATT&CK coverage strip with a working Navigator layer download';
  var states = [[1280, 900], [390, 844]];
  for (var i = 0; i < states.length; i++) {
    await setViewport(page, states[i][0], states[i][1]);
    var label = states[i][0] + 'x' + states[i][1] + ': ' + name;
    if (!(await gotoAndWait(page, url + '#tab-chain'))) { check('NOT CHECKED: ' + label, false, 'the tab controller never built, so nothing was measured'); continue; }
    await CDP.sleep(250);
    var v = attackStripVerdict(JSON.parse(await page.evaluate(ATTACK_STRIP_EXPR)));
    if (v.notChecked) check('NOT CHECKED: ' + label, false, v.detail);
    else check(label, v.ok, v.detail);
  }
  /* The control: the same page with attack-coverage.js removed. The row above must FAIL on it, or the row cannot see a missing strip. */
  var cname = 'control: the strip row FAILS on a copy of the page without attack-coverage.js';
  var ctl = attackStripControlHtml(html);
  if (!ctl) { check('NOT CHECKED: ' + cname, false, 'the fetched page has no attack-coverage.js script tag to remove, so there is no strip to take away'); return; }
  var cpath = new URL(url).pathname + '__no-attack-strip/';
  var csrv = await SERVER.start({ [cpath]: ctl }, { root: ROOT, base: BASE });
  try {
    await setViewport(page, 1280, 900);
    if (!(await gotoAndWait(page, csrv.origin + cpath + '#tab-chain'))) { check('NOT CHECKED: ' + cname, false, 'the tab controller never built on the control copy'); return; }
    await CDP.sleep(250);
    var cv = attackStripVerdict(JSON.parse(await page.evaluate(ATTACK_STRIP_EXPR)));
    if (cv.notChecked) check('NOT CHECKED: ' + cname, false, cv.detail);
    else check(cname, !cv.ok && /no coverage strip is drawn/.test(cv.why.join(' ')), 'the row said: ' + (cv.ok ? 'PASS (it cannot see a missing strip)' : cv.why.join('; ')));
  } finally {
    csrv.close();
  }
  await restoreReportPage(page, url);
}

/* T-0500.1.7.1: the timeline marks (Joseph, 2026-10-30: "a pretty good amount larger") and their legend. At 1280 and 768 the swim-lane dots are at
   least 32 px (30 on a phone width) and their numbers at least 18 px; at 390 the vertical list's dots are at least 24 px and its numbers 18 px.
   No two marks overlap, no mark overlaps an axis date, and every event is present as a mark, as a dated list item and as a row of the table. The
   legend's four swatches carry the same paint as the dots of the same kind (or, with no dot of that kind on this report, the status colour the
   dots would take), and none is grey. */
var TIMELINE_VIEWPORTS = [[1280, 900], [768, 1024], [390, 844]];
var STATUS_QUALITIES = ['given', 'year-inferred', 'range', 'disputed'];
var TIMELINE_EXPR = '(function(){function vis(e){var r=e.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(e).visibility!=="hidden";}' +
  'function R(e){var r=e.getBoundingClientRect();return {l:r.left,t:r.top,r:r.right,b:r.bottom,w:r.width,h:r.height};}' +
  'function paint(e){var cs=getComputedStyle(e),bg=cs.backgroundColor;return /^rgba\\(0, 0, 0, 0\\)$|^transparent$/.test(bg)?cs.borderTopColor:bg;}' +
  'var Q=' + JSON.stringify(STATUS_QUALITIES) + ';' +
  'var sw=[].slice.call(document.querySelectorAll(".hl-rv-marker > .hl-rv-symbol")).filter(vis);' +
  'var vsw=[].slice.call(document.querySelectorAll(".hl-rv-vertical-marker > .hl-rv-symbol")).filter(vis);' +
  'var dots=sw.length?sw:vsw;var horizontal=sw.length>0;' +
  'var nums=[].slice.call(document.querySelectorAll(horizontal?".hl-rv-marker > span:last-child":".hl-rv-vnum")).filter(vis).map(function(e){return parseFloat(getComputedStyle(e).fontSize);});' +
  'var marks=[].slice.call(document.querySelectorAll(horizontal?".hl-rv-marker":".hl-rv-vertical-marker")).filter(vis).map(R);' +
  'var axis=[].slice.call(document.querySelectorAll(".hl-rv-axis span")).filter(vis).map(R);' +
  'var kinds={};Q.forEach(function(q){var d=dots.filter(function(e){return e.parentNode.classList.contains("hl-rv-"+q);})[0];kinds[q]=d?paint(d):null;});' +
  'var dotList=dots.map(function(e){var k=null;Q.forEach(function(q){if(e.parentNode.classList.contains("hl-rv-"+q))k=q;});return {q:k,paint:paint(e)};});' +
  'var markEls=[].slice.call(document.querySelectorAll(horizontal?".hl-rv-marker":".hl-rv-vertical-marker")).filter(vis);' +
  'var numberList=markEls.map(function(mk){var e=horizontal?mk.querySelector(":scope > span:last-child"):(mk.querySelector(".hl-rv-vnum")||(mk.parentNode&&mk.parentNode.querySelector(".hl-rv-vnum")));if(!e)return {present:false};var cs=getComputedStyle(e),r=e.getBoundingClientRect();var clipped=/inset\\(\\s*(50|100)%/.test(cs.clipPath||"")||(cs.clip&&/rect\\(0(px)?, 0(px)?, 0(px)?, 0(px)?\\)/.test(cs.clip));return {present:true,w:r.width,h:r.height,visibility:cs.visibility,display:cs.display,opacity:parseFloat(cs.opacity),clipped:!!clipped,text:e.textContent.trim(),fs:parseFloat(cs.fontSize)};});' +
  'var refs={};[["given","--rv-ok"],["year-inferred","--rv-warn"],["range","--rv-warn"],["disputed","--rv-bad"]].forEach(function(p){var s=document.createElement("span");s.style.color="var("+p[1]+")";document.body.appendChild(s);refs[p[0]]=getComputedStyle(s).color;s.remove();});' +
  'var legend=Q.map(function(q){var it=document.querySelector(".hl-rv-timeline-legend .hl-rv-legend-item.hl-rv-"+q),s=it?it.querySelector(".hl-rv-symbol"):null;return {q:q,found:!!s,visible:s?vis(s):false,paint:s?paint(s):null,w:s?s.getBoundingClientRect().width:0,h:s?s.getBoundingClientRect().height:0};});' +
  'return {vw:innerWidth,horizontal:horizontal,dotCount:dots.length,dotMin:dots.length?Math.min.apply(null,dots.map(function(e){var r=e.getBoundingClientRect();return Math.min(r.width,r.height);})):null,' +
  'numMin:nums.length?Math.min.apply(null,nums):null,numCount:nums.length,marks:marks,axis:axis,kinds:kinds,dots:dotList,numbers:numberList,refs:refs,legend:legend,' +
  'events:document.querySelectorAll(".hl-rv-vertical-timeline li").length,markerTotal:document.querySelectorAll(".hl-rv-marker").length,' +
  'dated:[].slice.call(document.querySelectorAll(".hl-rv-vertical-timeline .hl-rv-date")).filter(function(e){return e.textContent.trim().length>0;}).length,' +
  'tableRows:document.querySelectorAll(".hl-rv-chronology-table tbody tr").length};})()';
function overlapPairs(rects) {
  var hits = 0;
  for (var i = 0; i < rects.length; i++) for (var j = i + 1; j < rects.length; j++) {
    var a = rects[i], b = rects[j];
    if (a.l < b.r - 1 && a.r > b.l + 1 && a.t < b.b - 1 && a.b > b.t + 1) hits++;
  }
  return hits;
}
function timelineVerdict(m) {
  if (!m || !m.dotCount) return { notChecked: true, ok: false, detail: 'no timeline mark was visible, so no size was measured' };
  var why = [];
  var minDot = m.horizontal ? (m.vw >= 700 ? 32 : 28) : 24;
  if (m.dotMin < minDot - 0.01) why.push('the smallest mark is ' + m.dotMin.toFixed(1) + ' px (at least ' + minDot + ' expected)');
  if (!Array.isArray(m.numbers) || !m.numbers.length || m.numbers.length !== m.marks.length) return { notChecked: true, ok: false, detail: 'the event numbers could not be measured for every mark (' + (Array.isArray(m.numbers) ? m.numbers.length : 'none') + ' number(s) against ' + m.marks.length + ' mark(s))' };
  var badNums = [];
  m.numbers.forEach(function (n, i) {
    var f = [];
    if (!n || !n.present) f.push('missing');
    else {
      if (!(n.w > 0 && n.h > 0)) f.push('zero-size box');
      if (n.visibility === 'hidden' || n.visibility === 'collapse') f.push('visibility hidden');
      if (n.display === 'none') f.push('display none');
      if (n.clipped) f.push('clipped to nothing');
      if (n.opacity === 0) f.push('transparent');
      if (!n.text) f.push('empty text');
      if (!(n.fs >= 18 - 0.01)) f.push('font ' + n.fs + ' px, at least 18 expected');
    }
    if (f.length) badNums.push('event number ' + (i + 1) + ' is ' + f.join(', '));
  });
  if (badNums.length) why.push(badNums.length + ' of ' + m.numbers.length + ' event number(s) not present and legible: ' + badNums.slice(0, 4).join('; '));
  if (m.numMin == null) why.push('no event number was measured'); else if (m.numMin < 18 - 0.01) why.push('the smallest event number is ' + m.numMin + ' px (at least 18 expected)');
  var hits = overlapPairs(m.marks);
  if (hits) why.push(hits + ' pair(s) of marks overlap');
  var axisHits = 0;
  m.marks.forEach(function (mk) { m.axis.forEach(function (ax) { if (mk.l < ax.r - 1 && mk.r > ax.l + 1 && mk.t < ax.b - 1 && mk.b > ax.t + 1) axisHits++; }); });
  if (axisHits) why.push(axisHits + ' mark(s) overlap a date label');
  if (!m.events || m.events !== m.tableRows) why.push(m.events + ' dated list item(s) against ' + m.tableRows + ' table row(s)');
  if (m.markerTotal !== m.tableRows) why.push(m.markerTotal + ' swim-lane mark(s) against ' + m.tableRows + ' table row(s)');
  if (m.dated !== m.events) why.push(m.dated + ' of ' + m.events + ' list items carry their date');
  return { notChecked: false, ok: why.length === 0, why: why, detail: (m.horizontal ? 'swim lanes' : 'vertical list') + ': ' + m.dotCount + ' mark(s), smallest ' + m.dotMin.toFixed(1) + ' px, numbers from ' + m.numMin + ' px, ' + m.marks.length + ' box(es) and ' + m.axis.length + ' date label(s) checked for overlap, ' + m.events + ' events against ' + m.tableRows + ' table rows' + (why.length ? '; ' + why.join('; ') : '') };
}
function legendVerdict(m) {
  if (!m || !m.legend) return { notChecked: true, ok: false, detail: 'nothing was measured' };
  if (!Array.isArray(m.dots) || m.dots.length !== m.dotCount || m.dots.some(function (d) { return !d || !d.q || !d.paint; })) return { notChecked: true, ok: false, detail: 'not every timeline dot could be measured (' + (Array.isArray(m.dots) ? m.dots.length : 'none') + ' of ' + m.dotCount + ', or a dot of no known kind)' };
  var why = [], compared = 0, vsToken = 0, refSet = {};
  Object.keys(m.refs).forEach(function (k) { refSet[m.refs[k]] = true; });
  m.legend.forEach(function (it) {
    if (!it.found || !it.visible) { why.push('the ' + it.q + ' swatch is missing or hidden'); return; }
    if (it.w < 14 || it.h < 14) why.push('the ' + it.q + ' swatch is ' + it.w.toFixed(0) + 'x' + it.h.toFixed(0) + ' px');
    var same = m.dots.filter(function (d) { return d.q === it.q; });
    if (same.length) { compared += same.length; var off = same.filter(function (d) { return d.paint !== it.paint; }); if (off.length) why.push('the ' + it.q + ' swatch is ' + it.paint + ' but a ' + it.q + ' dot is ' + off[0].paint + ' (' + off.length + ' of ' + same.length + ' differ)'); }
    else { vsToken++; if (it.paint !== m.refs[it.q]) why.push('the ' + it.q + ' swatch is ' + it.paint + ', not the status colour ' + m.refs[it.q] + ' (no ' + it.q + ' dot on this report to compare)'); }
    if (!refSet[it.paint]) why.push('the ' + it.q + ' swatch (' + it.paint + ') is not a status colour (grey or black)');
  });
  return { notChecked: false, ok: why.length === 0, why: why, detail: m.legend.length + ' swatch(es): ' + compared + ' compared with a dot of the same kind, ' + vsToken + ' with the status colour (no such dot on this report)' + (why.length ? '; ' + why.join('; ') : '') };
}
async function timelineRows(page, url) {
  var nameA = 'the timeline marks are large (dots 32 px, numbers 18 px; smaller on a phone), never overlap, and every event is present';
  var nameB = 'the timeline legend swatches carry the same colours as the dots';
  for (var i = 0; i < TIMELINE_VIEWPORTS.length; i++) {
    var w = TIMELINE_VIEWPORTS[i][0], h = TIMELINE_VIEWPORTS[i][1];
    await setViewport(page, w, h);
    if (!(await gotoAndWait(page, url))) { check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameA, false, 'the tab controller never built, so nothing was measured'); check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameB, false, 'the tab controller never built, so nothing was measured'); continue; }
    await page.evaluate('location.hash="#tab-timeline"');
    await CDP.sleep(450);
    /* on a phone the data view starts folded: open it, as a reader would, before measuring */
    await page.evaluate('(function(){var b=document.querySelector("#tab-timeline .hl-rv-view-summary button");if(b&&b.getAttribute("aria-expanded")==="false")b.click();})()');
    await CDP.sleep(450);
    var m = await page.json(TIMELINE_EXPR);
    var tv = timelineVerdict(m), lv = legendVerdict(m);
    if (tv.notChecked) check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameA, false, tv.detail); else check(w + 'x' + h + ': ' + nameA, tv.ok, tv.detail);
    if (lv.notChecked) check('NOT CHECKED: ' + w + 'x' + h + ': ' + nameB, false, lv.detail); else check(w + 'x' + h + ': ' + nameB, lv.ok, lv.detail);
  }
}

/* Row A, at the two sizes 4a names for the bar. */
async function tabBarRows(page, url) {
  for (var v = 0; v < TAB_BAR_VIEWPORTS.length; v++) {
    var width = TAB_BAR_VIEWPORTS[v][0], height = TAB_BAR_VIEWPORTS[v][1];
    var vlabel = TAB_BAR_VIEWPORTS[v][2];
    var rowName = 'every tab is rendered in the bar, at least 44 px high, and a tap selects it';
    await setViewport(page, width, height);
    /* setViewport already turns touch on below 1024; state it here so this row
       cannot silently change meaning if that threshold ever moves. */
    await page.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    if (!(await gotoAndWait(page, url))) {
      check('NOT CHECKED: ' + width + 'x' + height + ': ' + rowName, false,
        'the tab controller never built at this viewport (no .hl-rv-ready), so no tab ' +
        'could be measured');
      continue;
    }
    var measuredA = 0, badA = [];
    for (var t = 0; t < TAB_TOKENS.length; t++) {
      var token = TAB_TOKENS[t], id = 'tabbtn-' + token;
      /* A DIFFERENT tab first, so the tap below has to move the selection. */
      var other = TAB_TOKENS[(t + 3) % TAB_TOKENS.length];
      await page.evaluate('location.hash=' + JSON.stringify('#tab-' + other));
      await CDP.sleep(120);
      var geom = await page.json(tabGeomExpr(id));
      if (geom && geom.found) measuredA++;
      var hit = null, after = null;
      if (geom && geom.found && geom.rects && geom.w > 0 && geom.h > 0 &&
          !(geom.clips || []).length) {
        hit = await page.json(tabHitExpr(id));
        if (hit && hit.ok) {
          await page.send('Input.dispatchMouseEvent', {
            type: 'mousePressed', x: hit.x, y: hit.y, button: 'left', clickCount: 1
          });
          await page.send('Input.dispatchMouseEvent', {
            type: 'mouseReleased', x: hit.x, y: hit.y, button: 'left', clickCount: 1
          });
          await CDP.sleep(220);
          after = await page.json(TAB_CLICK_STATE_EXPR);
        }
      }
      var verdict = tabReachVerdict(token, geom, hit, after);
      if (!verdict.ok) badA.push(width + 'x' + height + ' ' + verdict.why);
    }
    var detailA = measuredA + ' of ' + TAB_TOKENS.length + ' tabs measured at ' +
      width + 'x' + height + ' (' + vlabel + ') with touch emulation, each inside the ' +
      'viewport width and at least 44 px high, a real tap selecting it and showing its ' +
      'own panel' + (badA.length ? '; ' + badA.length + ' failing: ' + badA.join(' | ') : '');
    if (!measuredA) {
      check('NOT CHECKED: ' + width + 'x' + height + ': ' + rowName, false,
        'no element with a tab id was on the page, so this row measured nothing; the ' +
        'bar is built by hl-report-tabs.js and it did not build one here');
    } else {
      check(width + 'x' + height + ': ' + rowName, badA.length === 0, detailA);
    }
  }
}

/* Row B, at 390 and 768, selecting each tab in turn so a hidden panel's
   summaries and links are measured rather than skipped. On a phone the
   dashboard view opens as a collapsed card, so it is opened with its own
   control first, the same route the chrome-target loop uses. */
async function tabTargetRows(page, url) {
  for (var v = 0; v < TAB_TARGET_VIEWPORTS.length; v++) {
    var width = TAB_TARGET_VIEWPORTS[v][0], height = TAB_TARGET_VIEWPORTS[v][1];
    await setViewport(page, width, height);
    if (!(await gotoAndWait(page, url))) {
      check('NOT CHECKED: ' + width + ' px: the teardown summaries and section links ' +
        'are at least 44 by 44 px', false,
        'the tab controller never built at ' + width + 'x' + height +
        ' (no .hl-rv-ready), so nothing was measured');
      continue;
    }
    var sums = [], links = [];
    for (var t = 0; t < TAB_TOKENS.length; t++) {
      var token = TAB_TOKENS[t];
      await page.evaluate('location.hash=' + JSON.stringify('#tab-' + token));
      await CDP.sleep(100);
      var card = false;
      if (width < 700) {
        card = await page.json('(function(t){var b=document.getElementById("hl-rv-view-"+t);' +
          'return b?b.hidden:false;})(' + JSON.stringify(token) + ')');
        if (card) {
          await page.click('#hl-rv-toggle-' + token);
          await CDP.sleep(140);
        }
      }
      var m = await page.json(tabTargetExpr(token));
      if (m) {
        sums = sums.concat(m.sums);
        links = links.concat(m.nav);
      }
      if (card) {
        await page.click('#hl-rv-toggle-' + token);
        await CDP.sleep(80);
      }
    }
    var doc = await page.json('(function(){return {' +
      'sums:document.querySelectorAll("details.hl-teardown > summary").length,' +
      'nav:document.querySelectorAll(".hl-rv-contents nav a").length};})()');
    var sumV = targetRowVerdict(sums, doc.sums, TAB_TOKENS.length);
    var linkV = targetRowVerdict(links, doc.nav, TAB_TOKENS.length);
    var sumName = 'every teardown summary in every tab is at least 44 by 44 px';
    var linkName = 'every section link in every tab\'s section navigation is at least ' +
      '44 by 44 px';
    if (sumV.notChecked) {
      check('NOT CHECKED: ' + width + ' px: ' + sumName, false, sumV.detail);
    } else {
      check(width + ' px: ' + sumName, sumV.ok, sumV.detail);
    }
    if (linkV.notChecked) {
      check('NOT CHECKED: ' + width + ' px: ' + linkName, false, linkV.detail);
    } else {
      check(width + ' px: ' + linkName, linkV.ok, linkV.detail);
    }
  }
}

async function tabbedChecks(page, opts) {
  var url = opts.url;

  if (!(await page.waitFor('.hl-rv-ready', 8000))) {
    check('the tab controller built its tabs at all', false,
      'no .hl-rv-ready after 8s: the fetched page carries hl-tab- classes but ' +
      'hl-report-tabs.js did not finish, so nothing below could be measured');
    return;
  }

  /* ---- the authored report is the expectation (fix rounds 1 and 2) -------
     Read once, before any tab state changes: which sections exist, in what
     order, every heading id and text, which panel each heading was put in, and
     which section each h3 sits in. A section deleted from the source or two
     sections swapped in the source leave the page perfectly self-consistent,
     which is exactly why the page's own order cannot be the expectation. */
  var pageHeads = await page.json('(function(){' +
    'function headText(h){var t="";' +
    '[].slice.call(h.childNodes).forEach(function(n){' +
    'if(n.nodeType===3){t+=n.nodeValue;return;}' +
    'if(n.nodeType!==1)return;' +
    'if(n.matches(".hl-rv-permalink,[data-rv-chrome]"))return;' +
    't+=n.textContent;});return t.replace(/\\s+/g," ").trim();}' +
    'var hs=[].slice.call(document.querySelectorAll(".hl-rv-source h2"));' +
    'var ids=[].slice.call(document.querySelectorAll(".hl-rv-source [id]"));' +
    'var text={},section={},panel={},heads=[];' +
    '[].slice.call(document.querySelectorAll(".hl-rv-source h2[id],.hl-rv-source h3[id]"))' +
    '.forEach(function(h){heads.push(h.id);' +
    'text[h.id]=headText(h);' +
    'var b=h.closest(".hl-rv-source");var bh=b?b.querySelector("h2"):null;' +
    'section[h.id]=bh?bh.id:null;' +
    'var p=h.closest(".hl-rv-panel");panel[h.id]=p?p.id.replace(/^tab-/,""):null;});' +
    'return {h2:hs.map(function(h){return h.id||null;}),' +
    'h2text:hs.map(function(h){return (h.textContent||"").trim().slice(0,70);}),' +
    'allIds:ids.map(function(e){return e.id;}),heads:heads,text:text,section:section,' +
    'panel:panel,sources:document.querySelectorAll(".hl-rv-source").length};})()');
  var authored = opts.authored;
  var noAuthoredReason = (authored && authored.error) || 'no markdown path resolved for this slug';

  /* D3: when the vault copy is the expectation, the site copy must match it. A
     page built from a copy that already lost a section agrees with itself. */
  if (authored && authored.compare && authored.compare.readable === false) {
    check('NOT CHECKED: the site copy of the report matches the vault copy line for line', false,
      'the site copy ' + authored.compare.sitePath + ' exists but could not be read: ' +
      authored.compare.error + ', so the two copies were not compared');
  } else if (authored && authored.compare) {
    var cmp = authored.compare;
    check('the site copy of the report matches the vault copy line for line', !cmp.diff,
      cmp.diff
        ? 'the site copy ' + cmp.sitePath + ' differs from the vault copy ' + cmp.vaultPath +
          ' at body line ' + cmp.diff.bodyLine + ' (site line ' + cmp.diff.siteLine +
          ', vault line ' + cmp.diff.vaultLine + '): site says ' +
          JSON.stringify(cmp.diff.site === undefined ? '(nothing)' : cmp.diff.site) +
          ', the vault says ' + JSON.stringify(cmp.diff.vault === undefined ? '(nothing)' : cmp.diff.vault)
        : 'both copies agree line for line: ' + cmp.sitePath + ' and ' + cmp.vaultPath +
          ', front matter and hl-tab lines stripped');
  }

  if (authored && authored.h2 && authored.h2.length) {
    var missH2 = authored.h2.filter(function (id) { return pageHeads.h2.indexOf(id) === -1; });
    var dupH2 = authored.h2.filter(function (id) { return countOf(pageHeads.h2, id) > 1; });
    var extraH2 = pageHeads.h2.map(function (id, i) {
      return { id: id, text: pageHeads.h2text[i] };
    }).filter(function (x) { return !x.id || authored.h2.indexOf(x.id) === -1; });
    check('the page shows every section of the authored report',
      missH2.length === 0 && dupH2.length === 0 && pageHeads.h2.length === authored.h2.length,
      (missH2.length ? missH2.length + ' authored section(s) missing from the page: ' +
          missH2.map(function (id) { return '"' + id + '"'; }).join(', ') + '. ' : '') +
      (dupH2.length ? 'repeated section(s): ' + dupH2.join(', ') + '. ' : '') +
      (extraH2.length ? 'headings the report does not have: ' +
          extraH2.map(function (x) {
            return x.id ? '"' + x.id + '"' : '(no id) "' + x.text + '"';
          }).join(', ') +
          '. ' : '') +
      pageHeads.h2.length + ' of ' + authored.h2.length + ' authored sections in the DOM');

    var missHeads = authored.ids.filter(function (id) { return pageHeads.allIds.indexOf(id) === -1; });
    var dupHeads = authored.ids.filter(function (id) { return countOf(pageHeads.allIds, id) > 1; });
    check('every authored h2 and h3 heading id is on the page exactly once',
      missHeads.length === 0 && dupHeads.length === 0,
      (missHeads.length ? missHeads.length + ' authored heading id(s) absent from the page: ' +
          missHeads.map(function (id) { return '#' + id; }).join(', ') +
          ' (an old link to it is dead). ' : '') +
      (dupHeads.length ? 'repeated id(s): ' + dupHeads.join(', ') + '. ' : '') +
      authored.ids.length + ' authored h2/h3 ids, ' + pageHeads.allIds.length + ' ids in the article');

    /* D7: the heading with an id must still SAY what the report says. A renamed
       heading keeps its anchor and reads as a de-identified or re-scoped section
       (round-2 probe x6 changed "17. Notification" to "17. Alerts"). */
    var textChecked = 0, textBad = [];
    authored.ids.forEach(function (id) {
      if (pageHeads.text[id] === undefined) return; // the id row above already names the absence
      textChecked++;
      var want = normaliseHeadingText(authored.text[id]);
      var got = normaliseHeadingText(pageHeads.text[id]);
      if (want !== got) {
        textBad.push('#' + id + ': the report says ' + JSON.stringify(authored.text[id]) +
          ', the page says ' + JSON.stringify(pageHeads.text[id]));
      }
    });
    check('every authored heading reads the same as the page heading with that id',
      textBad.length === 0,
      textChecked + ' of ' + authored.ids.length + ' authored h2/h3 headings read' +
      (textBad.length ? ': ' + textBad.length + ' renamed: ' + textBad.join(' | ') : ''));

    /* D8: an h3 belongs to the h2 above it. Round-2 probe x8 moved "Where to
       look first" into section 17 and the page still passed, because presence
       was all that was asked. */
    var parentChecked = 0, parentBad = [];
    Object.keys(authored.parents).forEach(function (id) {
      if (pageHeads.section[id] === undefined) {
        parentBad.push('#' + id + ': not on the page at all');
        return;
      }
      parentChecked++;
      if (pageHeads.section[id] !== authored.parents[id]) {
        parentBad.push('#' + id + ': the report puts it under "' + authored.parents[id] +
          '", the page puts it under "' + (pageHeads.section[id] || '(no section)') + '"');
      }
    });
    check('every authored h3 sits under its own section on the page',
      parentBad.length === 0,
      parentChecked + ' of ' + Object.keys(authored.parents).length + ' authored h3 parents read' +
      (parentBad.length ? ': ' + parentBad.join(' | ') : ''));

    /* D6: the `{: .hl-tab-<token>}` line under each h2 names the panel its
       heading must be in. Round-2 probe x5 swapped one section's tab class and
       the page PASSed: presence and order were asked, membership was not. */
    if (authored.tabs) {
      var tagged = authored.h2.filter(function (id) { return !!authored.tabs[id]; });
      var untagged = authored.h2.filter(function (id) { return !authored.tabs[id]; });
      var tabBad = [];
      tagged.forEach(function (id) {
        if (pageHeads.panel[id] === undefined) {
          tabBad.push('#' + id + ': not on the page at all');
          return;
        }
        if (pageHeads.panel[id] !== authored.tabs[id]) {
          tabBad.push('#' + id + ': the report puts it in the ' + authored.tabs[id] +
            ' tab, the page puts it in ' +
            (pageHeads.panel[id] ? 'the ' + pageHeads.panel[id] + ' tab' : 'no panel'));
        }
      });
      check('every section sits in the tab its report line names', tabBad.length === 0,
        tagged.length + ' of ' + authored.h2.length + ' authored tab assignments read' +
        (untagged.length ? '; ' + untagged.length + ' section(s) carry no tab line: ' +
          untagged.join(', ') : '') +
        (tabBad.length ? ': ' + tabBad.length + ' in the wrong tab: ' + tabBad.join(' | ') : ''));
    } else {
      check('NOT CHECKED: every section sits in the tab its report line names', false,
        'this markdown carries no hl-tab line under its h2s (or the tab scan and the ' +
        'heading list do not line up), so no section\'s tab could be compared with the page');
    }
  } else {
    check('NOT CHECKED: the page shows every section of the authored report', false,
      noAuthoredReason + ', so the section list was not compared with the report; ' +
      pageHeads.h2.length + ' h2 headings in the article');
    check('NOT CHECKED: every authored h2 and h3 heading id is on the page exactly once', false,
      noAuthoredReason + ', so the heading ids were not compared with the report; ' +
      pageHeads.allIds.length + ' ids in the article');
    check('NOT CHECKED: every authored heading reads the same as the page heading with that id', false,
      noAuthoredReason + ', so the heading text was not compared with the report');
    check('NOT CHECKED: every authored h3 sits under its own section on the page', false,
      noAuthoredReason + ', so the section each h3 belongs to is not known');
    check('NOT CHECKED: every section sits in the tab its report line names', false,
      noAuthoredReason + ', so which tab each section belongs to is not known');
  }

  /* ---- ARIA, once: viewport-independent by design ------------------------ */
  var aria = await page.json('(function(){' +
    'var tabs=[].slice.call(document.querySelectorAll("[role=tab]"));' +
    'var panels=[].slice.call(document.querySelectorAll("[role=tabpanel]"));' +
    'var sel=tabs.filter(function(t){return t.getAttribute("aria-selected")==="true";});' +
    'var unlinked=tabs.filter(function(t){var p=document.getElementById(t.getAttribute("aria-controls")||"");' +
    'return !p||p.getAttribute("role")!=="tabpanel"||p.getAttribute("aria-labelledby")!==t.id;});' +
    // An orphan panel matters as much as an orphan tab: the panel exists, holds
    // the report's sections, and no control can reach it.
    'var orphan=panels.filter(function(p){var t=document.getElementById(p.getAttribute("aria-labelledby")||"");' +
    'return !t||t.getAttribute("role")!=="tab"||t.getAttribute("aria-controls")!==p.id;});' +
    'var roving=tabs.filter(function(t){return (t.getAttribute("aria-selected")==="true")!==(t.getAttribute("tabindex")==="0");});' +
    'var shown=panels.filter(function(p){return !p.hidden;});' +
    'return {tablist:!!document.querySelector("[role=tablist]"),' +
    'tabs:tabs.map(function(t){return t.id;}),panels:panels.map(function(p){return p.id;}),' +
    'selected:sel.map(function(t){return t.id;}),unlinked:unlinked.map(function(t){return t.id;}),' +
    'roving:roving.length,orphan:orphan.map(function(p){return p.id;}),' +
    'shown:shown.map(function(p){return p.id;})};})()');
  var expectTabs = TAB_TOKENS.map(function (t) { return 'tabbtn-' + t; });
  var expectPanels = TAB_TOKENS.map(function (t) { return 'tab-' + t; });
  check('the tablist is built with one tab and one panel per token',
    aria.tablist && aria.tabs.length === 7 && aria.panels.length === 7 &&
    expectTabs.every(function (id, i) { return aria.tabs[i] === id; }) &&
    expectPanels.every(function (id, i) { return aria.panels[i] === id; }),
    aria.tabs.length + ' tabs, ' + aria.panels.length + ' panels: ' +
      (aria.tabs.join(' ') || 'none'));
  check('every tab controls its own panel and every panel is labelled by its tab',
    aria.unlinked.length === 0 && aria.orphan.length === 0 && aria.roving === 0,
    (aria.unlinked.length ? 'unreachable tab(s): ' + aria.unlinked.join(', ') + '. ' : '') +
    (aria.orphan.length ? 'orphan panel(s) no tab reaches: ' + aria.orphan.join(', ') + '. ' : '') +
    (!aria.unlinked.length && !aria.orphan.length
      ? '7 of 7 aria-controls/aria-labelledby pairs resolve; roving tabindex matches selection'
      : 'roving tabindex mismatches: ' + aria.roving));
  check('exactly one tab is selected and exactly its panel is shown',
    aria.selected.length === 1 && aria.shown.length === 1 &&
    aria.shown[0] === aria.selected[0].replace('tabbtn-', 'tab-'),
    'selected ' + (aria.selected[0] || 'none') + ', shown ' + (aria.shown[0] || 'none'));

  /* ---- keyboard, with real key events ----------------------------------- */
  var keys = [
    ['ArrowRight', 'ArrowRight', 39, 'victims'],
    ['End', 'End', 35, 'confidence'],
    ['Home', 'Home', 36, 'overview'],
    ['ArrowLeft', 'ArrowLeft', 37, 'confidence']
  ];
  await page.evaluate('document.getElementById("tabbtn-overview").focus()');
  await CDP.sleep(100);
  var keyRows = [];
  var keyOk = true;
  for (var k = 0; k < keys.length; k++) {
    await pressKey(page, keys[k][0], keys[k][1], keys[k][2]);
    var now = await page.json(selectedTabExpr());
    var ok = now.id === 'tabbtn-' + keys[k][3] && now.focus === now.id;
    keyOk = keyOk && ok;
    keyRows.push(keys[k][0] + ' -> ' + (now.id || 'none') +
      (now.focus === now.id ? ', focused' : ', FOCUS ' + (now.focus || 'none')));
  }
  check('keyboard arrows, Home and End select and focus the right tab',
    keyOk, keyRows.join(' | '));

  /* ---- old links keep working (design-v4 section 4 and check 5.3) --------

     Every heading id is unchanged, so a URL with any heading id must open that
     section's tab, open any teardown around it and scroll to it. Cold load and
     an in-session hashchange are both real entry points (a social post opens
     cold; an in-report cross-link fires hashchange). A sample of three ids was
     the design's floor; this walks the FIRST heading of every tab, plus one id
     inside a collapsed teardown, and prints the denominator. */
  await setViewport(page, 1280, 900);
  await gotoAndWait(page, url);
  /* The first heading of each tab. The panel's own first h2 is read WITHOUT an
     `[id]` filter, because filtering on `[id]` silently skipped past a heading
     whose id was removed and sampled the next one (round-1 mutant 5a: the
     deep-link check PASSed 7 of 7 while the first heading of the chain tab had no
     id at all). When the authored markdown carries tab tags, the expected id is
     the report's own first heading for that tab and a page that starts elsewhere
     is a failure, not a different sample. */
  var deepPage = await page.json('(function(){var out=[];' +
    TAB_TOKENS.map(function (t) {
      return 'var p=document.getElementById("tab-' + t + '");' +
        'var h=p?p.querySelector(".hl-rv-source h2"):null;' +
        'out.push({token:' + JSON.stringify(t) + ',id:h?(h.id||null):null,' +
        'text:h?(h.textContent||"").trim().slice(0,60):null});';
    }).join('') +
    'return out;})()');
  var deep = [];
  var deepBad = [];
  if (!opts.authoredKnown || !opts.authored.tabs) {
    /* D2: with no authored expectation this row cannot be satisfied, and it used
       to PASS by sampling 7 of 7 headings the page had chosen itself (round-2
       review, A7). The page's own first headings are printed as a diagnostic and
       are not accepted as the expectation. */
    check('NOT CHECKED: a cold link to a heading id opens that section\'s tab and scrolls to it', false,
      (!opts.authoredKnown
        ? 'the authored report could not be read, so which heading each tab must start with ' +
          'is not known'
        : 'the markdown carries no hl-tab line under its h2s, so which heading opens each ' +
          'tab is not authored') +
      '; the page\'s own tab-first headings (printed, not compared) are ' +
      deepPage.map(function (r) {
        return r.token + ': ' + (r.id ? '#' + r.id : '(no id)');
      }).join(', '));
  } else {
    deepPage.forEach(function (row) {
      var expected = firstAuthoredIdForTab(opts.authored, row.token);
      if (!row.id) {
        deepBad.push('#' + (expected || 'tab-' + row.token) + ': the first heading of the ' +
          row.token + ' tab has no id (' + (row.text || 'no heading') +
          '), so an old link to that section cannot be followed; the sampler will not ' +
          'skip to a later heading');
        return;
      }
      if (expected && row.id !== expected) {
        deepBad.push('#' + expected + ': the report\'s first ' + row.token +
          ' heading is missing from the page; the tab starts at #' + row.id + ' instead');
        return;
      }
      deep.push({ token: row.token, id: expected || row.id });
    });
    var deepRows = [];
    for (var d = 0; d < deep.length; d++) {
      await gotoAndWait(page, url + '#' + deep[d].id);
      var hit = await waitForReveal(page, deep[d].id);
      deepRows.push('#' + deep[d].id + ' -> ' + (hit.panel || 'none'));
      if (!(hit.found && hit.panel && hit.hidden === false && hit.top !== null &&
            hit.top >= -2 && hit.top < 900)) {
        deepBad.push('#' + deep[d].id + ': panel ' + (hit.panel || 'none') +
          ', hidden ' + hit.hidden + ', top ' + hit.top);
      }
    }
    check('a cold link to a heading id opens that section\'s tab and scrolls to it',
      deep.length === TAB_TOKENS.length && deepBad.length === 0,
      deep.length + ' of ' + TAB_TOKENS.length + ' tab-first heading ids sampled' +
      (deepBad.length ? '; ' + deepBad.length + ' failing: ' + deepBad.join(' | ') :
        ': ' + deepRows.join(', ')));
  }

  /* One id inside a collapsed teardown. A report may carry no id inside its own
     teardowns (the pilot has 14 closed teardowns and none with an id), in which
     case the first closed <details> that does hold one is used and named, and a
     synthetic id inside a source teardown is exercised as a hashchange, the same
     route part 1 used for this case. */
  var teardown = await page.evaluate('(function(){' +
    'var lists=[".hl-rv-source details:not([open])",".hl-post-content details:not([open])"];' +
    'for(var l=0;l<lists.length;l++){var ds=document.querySelectorAll(lists[l]);' +
    'for(var i=0;i<ds.length;i++){var e=ds[i].querySelector("[id]");if(!e)continue;' +
    'var p=e.closest(".hl-rv-panel");' +
    'return {id:e.id,token:p?p.id.replace(/^tab-/,""):null,cls:String(ds[i].className||""),' +
    'source:l===0};}}' +
    'return null;})()');
  if (!teardown) {
    check('NOT CHECKED: an id inside a collapsed teardown', false,
      'this report has no id inside a closed <details>, so the reveal path was not exercised');
  } else {
    await gotoAndWait(page, url + '#' + teardown.id);
    var td = await waitForReveal(page, teardown.id);
    check('a cold link to an id inside a collapsed teardown opens the tab and the teardown',
      td.panel === 'tab-' + teardown.token && td.hidden === false && td.open === true &&
      td.top !== null && td.top < 1280,
      '#' + teardown.id + ' (' + (teardown.cls || 'details') + ') -> ' + td.panel +
        ', details ' + (td.open ? 'open' : 'STILL CLOSED') + ', top ' + td.top);
    if (!teardown.source) {
      /* Name the synthetic round trip, rather than letting a dashboard fold
         stand in silently for a report teardown. */
      var synth = await page.evaluate('(function(){' +
        'var d=document.querySelector(".hl-rv-source details:not([open])");if(!d)return null;' +
        'var e=d.querySelector("p,li,tr,td")||d;e.id="p3-fixture-teardown-id";' +
        'var p=d.closest(".hl-rv-panel");return {id:e.id,token:p?p.id.replace(/^tab-/,""):null};})()');
      if (!synth) {
        check('NOT CHECKED: a synthetic id inside a report teardown', false,
          'no closed source teardown to place one in');
      } else {
        await page.evaluate('location.hash=' + JSON.stringify('#' + synth.id));
        var sd = await waitForReveal(page, synth.id);
        check('a synthetic id inside a report teardown reveals tab, teardown and position on hashchange',
          sd.panel === 'tab-' + synth.token && sd.hidden === false && sd.open === true &&
          sd.top !== null && sd.top >= 0 && sd.top < 1280,
          'synthetic #' + synth.id + ' -> ' + sd.panel + ', details ' +
            (sd.open ? 'open' : 'STILL CLOSED') + ', top ' + sd.top +
            ' (the report has no id of its own inside a teardown)');
      }
    }
  }

  /* ---- per viewport: selection, overflow, targets ----------------------- */
  var states = [];
  var overflowBad = [];
  var selectBad = [];
  var targetTotal = 0, targetSmall = 0, targetStates = 0;
  var textTotal = 0, textPseudo = 0, textSmallList = [], textStates = 0;

  for (var v = 0; v < TAB_VIEWPORTS.length; v++) {
    var width = TAB_VIEWPORTS[v][0], height = TAB_VIEWPORTS[v][1], vlabel = TAB_VIEWPORTS[v][2];
    await setViewport(page, width, height);
    if (!(await gotoAndWait(page, url))) {
      check('the tab controller builds at ' + width + 'x' + height, false,
        'no .hl-rv-ready at ' + vlabel);
      continue;
    }
    for (var t = 0; t < TAB_TOKENS.length; t++) {
      var token = TAB_TOKENS[t];
      await page.evaluate('location.hash=' + JSON.stringify('#tab-' + token));
      await CDP.sleep(90);
      var sel = await page.json(selectedTabExpr());
      var of = await page.json(OVERFLOW_EXPR);
      states.push({
        width: width, height: height, token: token,
        selected: sel.id, scrollW: of.scrollW, client: of.client, scrollX: of.scrollX,
        escaped: of.escaped, first: of.first
      });
      if (sel.id !== 'tabbtn-' + token) {
        selectBad.push(width + 'x' + height + ' #tab-' + token + ' -> ' +
          (sel.id || 'nothing selected'));
      }
      if (of.scrollX !== 0 || of.escaped !== 0 || of.scrollW > of.client + 1) {
        overflowBad.push(width + 'x' + height + ' ' + token + ': ' + of.escaped +
          ' escaped element(s), scrollX ' + of.scrollX + ', scrollWidth ' +
          of.scrollW + ' of ' + of.client +
          (of.first.length ? ' [' + of.first.map(function (e) {
            return e.tag + '.' + (e.cls || '-') + ' ' + e.left + '..' + e.right;
          }).join('; ') + ']' : ''));
      }
      /* On a phone the view body starts collapsed, so its controls would not be
         measured at all. Open the card with its own control, measure, close it
         again: 4a asks for the dashboard views' targets, and a control that only
         appears after one tap is still a tap target. */
      if (width < 700) {
        await page.click('#hl-rv-toggle-' + token);
        await CDP.sleep(80);
      }
      var tg = await page.json(targetsExpr(token));
      if (tg) {
        targetStates++;
        targetTotal += tg.count;
        targetSmall += tg.smallCount;
        if (tg.smallCount) {
          check(width + ' ' + token + ': every chrome target is at least 44 by 44',
            false, tg.smallCount + ' of ' + tg.count + ' under 44: ' +
            tg.small.map(function (e) {
              return e.tag + '.' + (e.cls || '-') + ' "' + e.text + '" ' + e.w + 'x' + e.h;
            }).join('; '));
        }
      }
      var tx = await page.json(chromeTextExpr(token));
      if (tx) {
        textStates++;
        textTotal += tx.count;
        textPseudo += tx.pseudo;
        tx.small.forEach(function (e) {
          textSmallList.push(width + ' ' + token + ': ' + e.px + 'px "' + e.what + '" (' + e.cls + ')');
        });
        if (tx.smallCount > tx.small.length) textSmallList.push(width + ' ' + token + ': ' + (tx.smallCount - tx.small.length) + ' more');
      }
      if (width < 700) {
        await page.click('#hl-rv-toggle-' + token);
        await CDP.sleep(60);
      }
    }

    /* One-page mode: every section, in the AUTHORED report's order, no sideways
       scroll. Comparing the page's one-page order with the page's own --rv-order
       (the shape before fix round 1) passed a source where two sections had been
       swapped, because the controller assigns --rv-order from that same DOM. */
    await page.evaluate('location.hash="#one-page"');
    await CDP.sleep(120);
    var one = await page.json('(function(){' +
      'var ids=[].slice.call(document.querySelectorAll(".hl-rv-source h2")).map(function(h){return h.id;});' +
      'var shown=[].slice.call(document.querySelectorAll(".hl-rv-source h2")).filter(function(h){' +
      'var r=h.getBoundingClientRect();return r.width>0||r.height>0;}).length;' +
      'return {onepage:document.documentElement.classList.contains("hl-onepage"),' +
      'ids:ids,shown:shown};})()');
    var oneOf = await page.json(OVERFLOW_EXPR);
    states.push({ width: width, height: height, token: 'one-page', selected: 'one-page',
      scrollW: oneOf.scrollW, client: oneOf.client, scrollX: oneOf.scrollX,
      escaped: oneOf.escaped, first: oneOf.first });
    if (!opts.authoredKnown) {
      check('NOT CHECKED: ' + width + ' one-page section order', false,
        'the authored report could not be read, so the page\'s order was not compared with ' +
        'the report\'s; ' + one.shown + ' of ' + one.ids.length + ' sections painted');
    } else {
      var orderDiff = firstOrderDifference(opts.reportOrder, one.ids);
      check(width + ' one-page shows every section in the report\'s order',
        one.onepage && one.ids.length === opts.sectionCount &&
        orderDiff === null && one.shown === opts.sectionCount,
        one.shown + ' of ' + opts.sectionCount + ' sections painted, ' + one.ids.length +
          ' in the DOM' + (one.onepage ? '' : ', NOT in one-page mode') +
          (orderDiff ? '; OUT OF REPORT ORDER: ' + orderDiff : ''));
    }
    if (oneOf.scrollX !== 0 || oneOf.escaped !== 0 || oneOf.scrollW > oneOf.client + 1) {
      overflowBad.push(width + 'x' + height + ' one-page: ' + oneOf.escaped +
        ' escaped element(s), scrollWidth ' + oneOf.scrollW + ' of ' + oneOf.client);
    }

    /* D5: one-page mode is where the written report lives, so every section and
       every block up to the next h2 must be PAINTED there -- not merely present
       in the DOM. The four round-2 hiding probes all passed a rect count over
       headings alone; this measures the blocks themselves. */
    var render = await page.json(SECTION_RENDER_EXPR);
    if (!opts.authoredKnown) {
      check('NOT CHECKED: ' + width + ' one-page renders every authored section and block', false,
        'the authored report could not be read, so the section list is not known; ' +
        render.count + ' section blocks were examined');
    } else {
      var noBlock = opts.authored.h2.filter(function (id) { return !render.sections[id]; });
      var notShown = [];
      opts.authored.h2.forEach(function (id) {
        var sec = render.sections[id];
        if (sec && sec.bad.length) notShown.push('"' + id + '": ' + sec.bad.join('; '));
      });
      check(width + ' one-page renders every authored section and every block in it',
        noBlock.length === 0 && notShown.length === 0,
        (noBlock.length ? noBlock.length + ' authored section(s) have no section element on the ' +
            'page: ' + noBlock.map(function (id) { return '"' + id + '"'; }).join(', ') + '. ' : '') +
        (notShown.length ? notShown.length + ' of ' + opts.authored.h2.length +
            ' section(s) not rendered: ' + notShown.join(' | ')
          : opts.authored.h2.length + ' of ' + opts.authored.h2.length +
            ' sections rendered, heading and every block, at this width'));
    }
    await page.evaluate('location.hash="#tab-overview"');
    await CDP.sleep(80);

    /* ---- phone-only gates (4a) ----------------------------------------- */
    if (width >= 700) continue;

    /* Views open as a compact card: collapsed body, a figure line, and a
       control that expands the same view in place. The first integer in the
       line is reconciled against the count of the elements it summarises. */
    var cards = [];
    var cardProblems = [];
    for (var c = 0; c < TAB_TOKENS.length; c++) {
      var ct = TAB_TOKENS[c];
      await page.evaluate('location.hash=' + JSON.stringify('#tab-' + ct));
      await CDP.sleep(80);
      var before = await page.json('(function(t){var panel=document.getElementById("tab-"+t);' +
        'var sum=panel.querySelector(".hl-rv-view-summary p");' +
        'var body=panel.querySelector(".hl-rv-view-body");' +
        'var toggle=document.getElementById("hl-rv-toggle-"+t);' +
        'var tables=[].slice.call(panel.querySelectorAll(".hl-rv-table"));' +
        'return {line:sum?sum.textContent.trim():"",hidden:body?body.hidden:null,' +
        'expanded:toggle?toggle.getAttribute("aria-expanded"):null,' +
        'controls:toggle?toggle.getAttribute("aria-controls"):null,' +
        'bodyId:body?body.id:null,' +
        'wideTables:tables.filter(function(x){return x.getBoundingClientRect().width>panel.clientWidth+1;}).length,' +
        'tables:tables.length};})(' + JSON.stringify(ct) + ')');
      var panelWidth = await page.json('(function(){var panel=document.getElementById("tab-' +
        ct + '");return panel.clientWidth;})()');
      await page.click('#hl-rv-toggle-' + ct);
      await CDP.sleep(120);
      var after = await page.json('(function(t){var panel=document.getElementById("tab-"+t);' +
        'var sum=panel.querySelector(".hl-rv-view-summary p");' +
        'var body=panel.querySelector(".hl-rv-view-body");' +
        'var toggle=document.getElementById("hl-rv-toggle-"+t);' +
        'return {line:sum?sum.textContent.trim():"",hidden:body?body.hidden:null,' +
        'h:body?Math.round(body.getBoundingClientRect().height):0,' +
        'expanded:toggle?toggle.getAttribute("aria-expanded"):null};})(' +
        JSON.stringify(ct) + ')');
      var primary = await page.json('(function(sel){var n=0;' +
        'try{n=document.querySelectorAll("#tab-' + ct + ' " + sel).length;}catch(e){n=-1;}' +
        'return n;})(' + JSON.stringify(TAB_PRIMARY[ct]) + ')');
      var m = before.line.match(/\d+/);
      var primaryCount = primary;
      cards.push({ token: ct, line: before.line, count: primaryCount,
        wide: before.wideTables, tables: before.tables, panelW: panelWidth });
      if (before.hidden !== true || before.expanded !== 'false' ||
          before.controls !== before.bodyId || !before.line) {
        cardProblems.push(ct + ': hidden=' + before.hidden + ' aria-expanded=' +
          before.expanded + ' line="' + before.line.slice(0, 40) + '"');
      }
      if (!/\d/.test(before.line) || !primaryCount || !m) {
        check('NOT CHECKED: the ' + width + ' px ' + ct + ' card states a headline figure',
          false, 'summary "' + before.line.slice(0, 80) + '" has no integer to reconcile, ' +
            'or the view holds none of the elements it counts (' + primaryCount + ')');
      } else {
        var first = Number(m[0]);
        check(width + ' px ' + ct + ': the expanded card shows the figure it counts',
          after.hidden === false && after.h > 0 && after.expanded === 'true' &&
          after.line === before.line && primaryCount === first,
          'summary "' + first + '" vs ' + primaryCount + ' ' + TAB_PRIMARY[ct] +
            '; collapsed h=' + (before.hidden ? 0 : 'shown') + ', expanded h=' + after.h +
            ', line unchanged=' + (after.line === before.line));
      }
      if (before.wideTables) {
        cardProblems.push(ct + ': ' + before.wideTables + ' of ' + before.tables +
          ' dashboard tables wider than the ' + panelWidth + ' px panel');
      }
      await page.click('#hl-rv-toggle-' + ct);
      await CDP.sleep(60);
    }
    check(width + ' px: every view opens as a compact card',
      cardProblems.length === 0, cardProblems.join('; ') ||
      '7 of 7 views collapsed with a figure line and an aria-controls toggle');
    check(width + ' px: no dashboard table is wider than the screen',
      cards.every(function (x) { return x.wide === 0; }),
      cards.map(function (x) { return x.token + ' ' + (x.tables - x.wide) + '/' + x.tables; }).join(', ') +
      ' dashboard tables fit');

    /* Sections menu: every tab one tap away, nothing off-screen. Scroll to the
       top first so the sticky bar and its menu are in their resting position;
       after a tall view has been expanded and collapsed the page can sit tens
       of thousands of px down, and the menu then opens over a moving layout.
       Start on a tab that is NOT the one the menu click must select, so a
       selection that never moved cannot pass. */
    await page.evaluate('location.hash="#tab-chain"');
    await CDP.sleep(100);
    await page.evaluate('window.scrollTo(0,0)');
    await CDP.sleep(150);
    await page.click('.hl-rv-mobile-line button');
    await CDP.sleep(150);
    /* The bar is in normal flow until the page scrolls past it, and the menu is
       anchored under the bar. At the very top the menu can start halfway down
       the first screen and run past the fold, which is not the state a reader
       taps in (the bar is sticky and the reader is always scrolled). Bring the
       bar to its stuck position first, then the whole menu is on screen. */
    await page.evaluate('(function(){var b=document.querySelector(".hl-rv-bar");' +
      'window.scrollTo(0, Math.round(b.getBoundingClientRect().top + window.scrollY) + 1);})()');
    await CDP.sleep(200);
    var menu = await page.json('(function(){var m=document.querySelector(".hl-rv-menu");' +
      'if(!m)return null;var items=[].slice.call(m.querySelectorAll("a"));' +
      'var r=m.getBoundingClientRect();' +
      'return {hidden:m.hidden,items:items.map(function(a){return a.getAttribute("href");}),' +
      'h:Math.round(r.height),top:Math.round(r.top),bottom:Math.round(r.bottom),' +
      'viewport:innerHeight};})()');
    var wantMenu = TAB_TOKENS.map(function (t) { return '#tab-' + t; }).concat(['#one-page']);
    check(width + ' px: the Sections menu lists every tab and one-page, all on screen',
      !!menu && menu.hidden === false && menu.h > 0 && menu.bottom <= menu.viewport + 1 &&
      wantMenu.every(function (h) { return menu.items.indexOf(h) !== -1; }),
      menu ? menu.items.length + ' entries, ' + menu.top + '..' + menu.bottom + ' of ' +
        menu.viewport + ' px: ' + menu.items.join(' ') : 'no menu built');
    /* The first menu entry, which is at the top of the list and therefore on
       screen in every state, and a different tab from the one selected above. */
    var beforeMenu = await page.json(selectedTabExpr());
    var picked = await clickMenuLink(page, '#tab-overview');
    if (!picked || !picked.ok) {
      // One named fallback, so a geometry quirk in the sticky bar cannot make
      // the gate silent about whether the menu works.
      try { await page.click('.hl-rv-menu a[href="#tab-overview"]'); } catch (e) { /* reported below */ }
      await CDP.sleep(150);
    }
    var viaMenu = await page.json(selectedTabExpr());
    check(width + ' px: a tab chosen from the Sections menu becomes the selected tab',
      viaMenu.id === 'tabbtn-overview' && beforeMenu.id === 'tabbtn-chain',
      'selected ' + (beforeMenu.id || 'nothing') + ' before, ' +
      (viaMenu.id || 'nothing') + ' after; pointer ' +
      (picked && picked.ok ? 'at ' + Math.round(picked.x) + ',' + Math.round(picked.y)
        : 'geometry fallback (' + JSON.stringify(picked) + ')'));
    await page.evaluate('location.hash="#tab-overview"');
    await CDP.sleep(80);
  }

  check('every tab is selected by its own URL fragment at all five viewports',
    selectBad.length === 0,
    (TAB_TOKENS.length * TAB_VIEWPORTS.length) + ' fragment selections across ' +
    TAB_VIEWPORTS.map(function (x) { return x[0] + 'x' + x[1]; }).join(', ') +
    (selectBad.length
      ? ': ' + selectBad.length + ' of ' + (TAB_TOKENS.length * TAB_VIEWPORTS.length) +
        ' failing: ' + selectBad.join(' | ')
      : ''));
  check('no page-level horizontal scroll on any tab or in one-page mode',
    overflowBad.length === 0,
    states.length + ' tab/viewport states at ' + TAB_VIEWPORTS.map(function (x) {
      return x[0] + 'x' + x[1];
    }).join(', ') + (overflowBad.length
      ? ': ' + overflowBad.length + ' of ' + states.length + ' states escape: ' +
        overflowBad.join(' | ')
      : ''));
  check('every chrome target is at least 44 by 44 px',
    targetSmall === 0,
    targetTotal + ' control measurements across ' + targetStates +
    ' tab/viewport states with dashboard folds open, ' + targetSmall + ' under 44');
  if (!textStates || textTotal + textPseudo === 0) {
    check('NOT CHECKED: no chrome text is under 13 px on any tab at any viewport', false,
      '0 text nodes or generated labels were measured, so this row measured nothing');
  } else {
    check('no chrome text is under 13 px on any tab at any viewport',
      textSmallList.length === 0,
      textTotal + ' chrome text nodes and ' + textPseudo + ' generated labels measured across ' + textStates +
      ' tab/viewport states with dashboard folds open, ' + textSmallList.length + ' under 13 px' +
      (textSmallList.length ? ': ' + textSmallList.slice(0, 8).join(' | ') : ''));
  }
  await tabLookRows(page, url);
  await panelRows(page, url);
  await featuredSponsorRows(page, url);
  await sponsorRailRows(page, url);
  await shareRows(page, url);
  await mispRows(page, url);
  await timelineRows(page, url);
  await attackStripRows(page, url, opts.html);

  /* ---- 4a: the bar at 768/812x375, and the targets 4a names (p7) -------- */
  await tabBarRows(page, url);
  await tabTargetRows(page, url);

  /* ---- JavaScript off and print ---------------------------------------- */
  await setViewport(page, 1280, 900);
  await page.send('Emulation.setScriptExecutionDisabled', { value: true });
  await page.send('Page.navigate', { url: url });
  await CDP.sleep(1200);
  var noJs = await page.json('(function(){' +
    'var hs=[].slice.call(document.querySelectorAll(".hl-post-content h2"));' +
    'return {ids:hs.map(function(h){return h.id;}),' +
    'shown:hs.filter(function(h){var r=h.getBoundingClientRect();return r.width>0||r.height>0;}).length,' +
    'panels:document.querySelectorAll(".hl-rv-panel").length};})()');
  var noJsOf = await page.json(OVERFLOW_EXPR);
  if (!opts.authoredKnown) {
    check('NOT CHECKED: with JavaScript off, every section in the report\'s order', false,
      'the authored report could not be read, so the no-JS page was not compared with it; ' +
      noJs.shown + ' of ' + noJs.ids.length + ' sections painted');
  } else {
    var noJsDiff = firstOrderDifference(opts.reportOrder, noJs.ids);
    check('with JavaScript off every section is present and in the report\'s order',
      noJs.panels === 0 && noJs.ids.length === opts.sectionCount &&
      noJsDiff === null && noJs.shown === opts.sectionCount,
      noJs.shown + ' of ' + opts.sectionCount + ' sections painted, ' + noJs.panels +
        ' tab panels built' + (noJsDiff ? '; OUT OF REPORT ORDER: ' + noJsDiff : '') +
        (noJsOf.escaped ? ', ' + noJsOf.escaped + ' escaped element(s)' : ''));
  }
  await page.send('Emulation.setScriptExecutionDisabled', { value: false });

  await setViewport(page, 1280, 900);
  await gotoAndWait(page, url);
  await page.evaluate('location.hash="#tab-chain"');
  await CDP.sleep(120);
  await page.send('Emulation.setEmulatedMedia', { media: 'print' });
  await page.evaluate('window.dispatchEvent(new Event("beforeprint"))');
  await CDP.sleep(250);
  var printed = await page.json('(function(){' +
    'var hs=[].slice.call(document.querySelectorAll(".hl-rv-source h2"));' +
    'return {shown:hs.filter(function(h){var r=h.getBoundingClientRect();return r.width>0||r.height>0;}).length,' +
    'closed:[].slice.call(document.querySelectorAll(".hl-rv-source details")).filter(function(d){return !d.open;}).length};})()');
  await page.send('Emulation.setEmulatedMedia', { media: 'screen' });
  await page.evaluate('window.dispatchEvent(new Event("afterprint"))');
  await CDP.sleep(250);
  var restored = await page.json(selectedTabExpr());
  if (!opts.authoredKnown) {
    /* D2: "every section" is only defined by the report. The page's own count
       (19 of 19) used to satisfy this row with no authored expectation at all. */
    check('NOT CHECKED: print shows every section with every teardown open, then restores the tab', false,
      'the authored report could not be read, so "every section" was not defined; the page ' +
      'printed ' + printed.shown + ' painted h2 heading(s) with ' + printed.closed +
      ' teardown(s) closed, and after print selected ' + (restored.id || 'nothing'));
  } else {
    check('print shows every section with every teardown open, then restores the tab',
      printed.shown === opts.sectionCount && printed.closed === 0 &&
      restored.id === 'tabbtn-chain',
      printed.shown + ' of ' + opts.sectionCount + ' sections painted, ' +
        printed.closed + ' teardowns left closed; after print selected ' +
        (restored.id || 'nothing'));
  }

  /* ---- the 25-date timeline fixture (5.4) ------------------------------- */
  var fixture = timelineFixtureHtml(opts.html);
  if (!fixture) {
    check('NOT CHECKED: the 25-date timeline fixture', false,
      'the fetched page has no Date/Time/When table to build the fixture from');
    await restoreReportPage(page, url);
    return;
  }
  var fixturePath = new URL(url).pathname + '__timeline-fixture/';
  var fsrv = await SERVER.start({ [fixturePath]: fixture }, { root: ROOT, base: BASE });
  try {
    var thin = [];
    var vertical = null;
    for (var f = 0; f < 3; f++) {
      var fw = [1280, 768, 390][f];
      await setViewport(page, fw, 900);
      var ok = await gotoAndWait(page, fsrv.origin + fixturePath + '#tab-timeline');
      if (!ok) {
        thin.push({ width: fw, error: 'tab controller did not build on the fixture' });
        continue;
      }
      if (fw < 480) {
        await page.click('#hl-rv-toggle-timeline');
        await CDP.sleep(200);
        vertical = await page.json('(function(){' +
          'var ls=[].slice.call(document.querySelectorAll("#tab-timeline .hl-rv-vertical-timeline li"));' +
          'return {count:ls.length,shown:ls.filter(function(x){' +
          'var r=x.getBoundingClientRect();return r.width>0||r.height>0;}).length};})()');
      } else {
        await CDP.sleep(250);
        thin.push(await page.json('(function(){' +
          'var e=document.querySelector("#tab-timeline .hl-rv-axis");if(!e)return {width:' + fw + ',missing:true};' +
          'var boxes=[].slice.call(e.children).filter(function(n){return !n.hidden;})' +
          '.map(function(n){return n.getBoundingClientRect();});' +
          'return {width:' + fw + ',candidates:Number(e.dataset.candidates),drawn:Number(e.dataset.drawn),' +
          'overlaps:boxes.filter(function(x,i){return boxes.some(function(y,j){' +
          'return j>i&&x.left<y.right&&x.right>y.left;});}).length};})()'));
      }
    }
    var horiz = thin.filter(function (x) { return !x.missing && !x.error; });
    if (!horiz.length) {
      check('NOT CHECKED: the 25-date timeline fixture', false,
        'no .hl-rv-axis on the fixture (the page builds no dated chronology view): ' +
        JSON.stringify(thin));
    } else {
      check('the 25-date fixture thins its labels and none of the kept labels overlap',
        horiz.every(function (x) { return x.candidates === 25 && x.drawn > 0 &&
          x.drawn < 25 && x.overlaps === 0; }),
        horiz.map(function (x) {
          return x.width + 'px: ' + x.drawn + ' of ' + x.candidates +
            ' drawn, ' + x.overlaps + ' overlapping';
        }).join('; '));
      check('below 480 px the 25-date fixture turns vertical with every event',
        !!vertical && vertical.shown === 25,
        vertical ? vertical.shown + ' of 25 events painted vertically' : 'no vertical list built');
    }
  } finally {
    fsrv.close();
  }
  await restoreReportPage(page, url);
}

/* The figure-nav and glossary checks below run on the live page after this
   branch, and this branch navigates to fixtures at five viewports. Hand it back
   at the size the gate opened it, on the report itself, on its first tab. */
async function restoreReportPage(page, url) {
  await setViewport(page, 1280, 900);
  await gotoAndWait(page, url);
  await page.evaluate('location.hash="#tab-overview"');
  await CDP.sleep(120);
  /* The figure-nav chips are report content and live in whichever tab their
     section belongs to, so the shared chip checks below would measure a 0 px
     element inside a hidden panel. A reader reaches them by opening that tab;
     the gate does the same. On the pilot this is the chain tab. */
  await revealPanelContaining(page, '.hl-fignav');
}

/* Where an id ended up: which panel, whether that panel is shown, whether an
   enclosing teardown is open, and how far from the viewport top. */
function revealStateExpr(id) {
  return '(function(id){var e=document.getElementById(id);' +
    'var p=e?e.closest(".hl-rv-panel"):null;var d=e?e.closest("details"):null;' +
    'var r=e?e.getBoundingClientRect():null;' +
    'return {panel:p?p.id:null,hidden:p?p.hidden:null,open:d?d.open:null,' +
    'top:r?Math.round(r.top):null,found:!!e};})(' + JSON.stringify(id) + ')';
}

/* The tab switch, the panel move and the scroll run on a hashchange handler and
   a requestAnimationFrame, and the chain panel is tens of thousands of px tall,
   so a fixed sleep can read the DOM before the scroll has happened. Poll for the
   settled state instead, bounded, and return the last read honestly if it never
   settles. */
async function waitForReveal(page, id, timeoutMs) {
  var deadline = Date.now() + (timeoutMs || 5000);
  var last = null;
  for (;;) {
    last = await page.json(revealStateExpr(id));
    if (last && last.found && last.hidden === false && last.open !== false &&
        last.top !== null && last.top >= -2 && last.top < 600) return last;
    if (Date.now() > deadline) return last;
    await CDP.sleep(120);
  }
}

/* Open the tab that holds the first match, so a later check measures a painted
   element rather than a hidden one. Returns the token, or null when the match is
   already in the shown panel or does not exist. */
async function revealPanelContaining(page, selector) {
  var token = await page.evaluate('(function(){var e=document.querySelector(' +
    JSON.stringify(selector) + ');if(!e)return null;' +
    'var p=e.closest(".hl-rv-panel");' +
    'if(!p||!p.hidden)return null;return p.id.replace(/^tab-/,"");})()');
  if (!token) return null;
  await page.evaluate('location.hash=' + JSON.stringify('#tab-' + token));
  await CDP.sleep(150);
  return token;
}



/* Everything this file measures on first read of the page -- the register
   switch, the figure-nav chips, the TOC -- is BUILT BY JAVASCRIPT after load,
   and `CDP.open()` only waits a FIXED settle (opts.settle, default 2500ms)
   before handing back a page handle. That is a guess, not a measurement, and
   on a cold HTTP cache it is sometimes wrong.

   Measured 2026-09-22, the SAME report run twice back to back with nothing
   else changed:

     run 1  14 H2 sections on load, 0 of 43 TOC items hidden by the brief
            register  -> both register-switch checks FAIL
     run 2  13 H2 sections on load, 11 of 64 TOC items hidden by the brief
            register  -> both PASS

   The H2 count differs, the TOC link count differs, and even the register's
   own computed reading time differs between runs. That is not flakiness in
   the check, it is the page still assembling itself at read time: run 1
   measured a DOM that had not finished building.

   The fix is not a longer fixed sleep -- that only narrows the window, it
   does not close it, and it makes every run slower whether or not the page
   needed the extra time. Instead, poll `inputs` (the same five counts
   already printed below) until two CONSECUTIVE reads agree, bounded by a
   deadline. Two matching reads in a row is the cheapest signal available
   that the mutations driving these numbers (tier markers, figures,
   teardowns, headings, TOC links) have stopped, without asserting anything
   further about what "finished" means for a page this file does not own.

   This must not turn into a check that can no longer FAIL. A report that
   genuinely never builds the machinery (wrong slug, a broken bundle) holds
   at zero for every count, and zero agrees with zero on the very next read
   -- it settles almost immediately and still reports zero, so the existing
   "carries none of the machinery" branch below fires exactly as before.
   Waiting only changes the answer for a page that is still CHANGING; it
   never invents a value for one that is genuinely, permanently absent. */
var INPUTS_EXPR = '(function(){return {' +
  'tiers: document.querySelectorAll("[class*=hl-tier-]").length,' +
  'figures: document.querySelectorAll(".hl-post-content figure").length,' +
  'teardowns: document.querySelectorAll("details.hl-teardown").length,' +
  'headings: document.querySelectorAll(".hl-post-content h2").length,' +
  'tocLinks: document.querySelectorAll("#hl-toc-list a").length};})()';

async function waitForStableInputs(page) {
  var pollMs = 250;
  var deadlineMs = 8000; // matches CDP.waitFor's own default deadline
  var start = Date.now();
  var prevStr = null;
  var reads = 0;
  var cur;
  for (;;) {
    cur = await page.json(INPUTS_EXPR);
    reads++;
    var curStr = JSON.stringify(cur);
    var elapsed = Date.now() - start;
    if (curStr === prevStr) {
      return { inputs: cur, settled: true, waitedMs: elapsed, reads: reads };
    }
    prevStr = curStr;
    if (elapsed >= deadlineMs) {
      // Report what was last seen, honestly labelled as unsettled, rather
      // than silently treating a deadline hit as a clean read.
      return { inputs: cur, settled: false, waitedMs: elapsed, reads: reads };
    }
    await CDP.sleep(pollMs);
  }
}

/* Defect 2, mine, from wiring this an hour ago: one blocked request yields
   TWO console-triage records (a network failure and a console log entry),
   so the same excluded URL printed its full multi-sentence reason twice in
   a row. That is not a counting bug -- `triaged.total` and the three bucket
   lengths must keep counting every record, exactly as before -- it is a
   PRINTING bug: the same fact stated twice, at full length, is unreadable.

   Grouping happens HERE, not in lib/console-triage.js: the module's counts
   stay one-record-per-event (that is what the summary line's three numbers
   mean), and only this on-screen listing collapses duplicates by URL. */
function groupExcludedForDisplay(rows) {
  var order = [];
  var byKey = {};
  (rows || []).forEach(function (row) {
    var key = row.url || '(no url)';
    if (!byKey[key]) {
      byKey[key] = { url: row.url, why: row.why, count: 0 };
      order.push(key);
    }
    byKey[key].count++;
  });
  return order.map(function (key) { return byKey[key]; });
}

var EXCLUDED_REASON_MAX = 140;
function renderExcludedGroup(g) {
  var reason = g.why.length > EXCLUDED_REASON_MAX
    ? g.why.slice(0, EXCLUDED_REASON_MAX - 3) + '...'
    : g.why;
  return (g.url || '(no url)') + (g.count > 1 ? '  (x' + g.count + ')' : '') +
    '  -- ' + reason;
}

async function main() {
  var s = pickSlug();
  if (!s) notChecked('no report slug given and none could be picked from _data/catalog.yml');

  var html;
  try {
    html = await fetchText(BASE + '/reports/' + s + '/');
  } catch (e) {
    notChecked('could not fetch /reports/' + s + '/ (' + e.message + '), so nothing ' +
      'was verified in a browser.');
  }

  var srv = await SERVER.start({ ['/reports/' + s + '/']: html }, { root: ROOT, base: BASE });
  var page;
  try {
    page = await CDP.open(srv.origin + '/reports/' + s + '/', { height: 1600 });
  } catch (e) {
    srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }

  /* Name the BROWSER, by brand, not only the engine string it reports over
     CDP. Brave identifies itself as `Chrome/153.x` because it is Chromium
     based, so every run of this gate printed `Chrome/...` and looked like it
     had run Chrome. A run that silently used a different browser than the
     checks were written against is the failure underneath every other one
     here, and it is invisible unless the harness says so out loud. */
  console.log('browser: ' + page.label);
  console.log('report:  ' + s);

  try {
    /* Everything below is built at runtime, so first prove the INPUTS exist.
       A report carrying no tier markers and no figures would let every check
       below pass by finding nothing, which is the shape of failure this whole
       convention exists to stop. */
    var settleResult = await waitForStableInputs(page);
    var inputs = settleResult.inputs;
    console.log('inputs:  ' + JSON.stringify(inputs));
    console.log('settle:  ' + (settleResult.settled
      ? 'stable after ' + settleResult.waitedMs + 'ms (' + settleResult.reads + ' reads)'
      : 'DEADLINE HIT after ' + settleResult.waitedMs + 'ms (' + settleResult.reads +
        ' reads); the page may still have been changing when this measured it'));
    console.log('');

    if (!inputs.tiers && !inputs.figures) {
      check('NOT CHECKED: this report carries none of the machinery', false,
        'no tier markers and no figures, so nothing here could be verified. ' +
        'Pass a slug that has them.');
      throw new Error('__notchecked__');
    }

    /* A published report embeds third-party resources a reader's browser
       fetches from someone else's origin: a Cloudflare analytics beacon and a
       newsletter form. Neither is a report module, and a privacy browser
       refuses the beacon by design.

       WHY THIS MOVED OUT OF A TEXT MATCH, measured 2026-09-22. The old list
       tested the console message TEXT, and a blocked subresource's text is
       exactly `Failed to load resource: net::ERR_CONNECTION_REFUSED` with no
       URL in it at all. So the URL-shaped entries in that list (eocampaign1,
       and the rest) could never match anything, and this check failed on all 43
       reports. The URL was available the whole time; cdp.js was discarding it.

       The decision now runs on ORIGIN first and NAME second, in
       lib/console-triage.js. A failure on the page's own origin can never be
       excluded by any naming rule, which is the property that lets a genuinely
       refused first-party module still fail loudly while a named third-party
       beacon is excluded. Adding /ERR_CONNECTION_REFUSED/ to a tolerance list
       instead would have blinded this check to exactly the failure it exists
       for, because Brave spells a blocked request with that same string.

       ALL THREE BUCKETS ARE PRINTED, INCLUDING ZEROS, so an empty bucket is
       distinguishable from one nobody measured, and every exclusion is named
       on screen rather than inferred from a count.
       See homelab-soc/docs/gate-honesty-contract.md. */
    var triaged = TRIAGE.triage(page.consoleErrorDetails(), srv.origin);
    console.log('   console  ' + triaged.total + ' error(s) on ' + srv.origin + ': ' +
      triaged.firstParty.length + ' first-party, ' + triaged.excluded.length +
      ' excluded by name, ' + triaged.unexplained.length + ' unexplained');
    groupExcludedForDisplay(triaged.excluded).forEach(function (g) {
      console.log('   note     excluded  ' + renderExcludedGroup(g));
    });
    /* Both buckets fail. An unexplained THIRD-PARTY error is not waved through:
       exclusion is by name, so an origin nobody has named is a thing to look at
       rather than a thing to assume is someone else's problem. */
    var failing = triaged.firstParty.concat(triaged.unexplained);
    check('no script error blocked the report modules', failing.length === 0,
      failing.length ? failing.length + ' failing error(s), first 3: ' +
        TRIAGE.renderFailing(failing).slice(0, 3).join(' | ') +
        (srv.misses.length ? '  [assets not served: ' + srv.misses.join(', ') + ']' : '')
        : 'clean: 0 first-party, 0 unexplained, ' + triaged.excluded.length +
          ' third-party error(s) excluded by name');

    // ---------- the register switch, or the tabs that replace it ----------
    var tabbed = isTabbedHtml(html);
    if (tabbed) {
      /* Report order read from the page is a DIAGNOSTIC only now: the expected
         sections and order come from the authored markdown (see readAuthored). */
      var pageOrder = await page.evaluate('(function(){' +
        'var blocks=[].slice.call(document.querySelectorAll(".hl-rv-source"));' +
        'blocks.sort(function(a,b){return parseFloat(a.style.getPropertyValue("--rv-order"))-' +
        'parseFloat(b.style.getPropertyValue("--rv-order"));});' +
        'return blocks.map(function(b){var h=b.querySelector("h2");return h&&h.id;})' +
        '.filter(Boolean);})()');
      var authored = readAuthored(s);
      if (authored.error) {
        console.log('authored: NOT READ  ' + authored.error);
      } else {
        console.log('authored: ' + authored.path + '  (' + authored.h2.length + ' h2, ' +
          authored.ids.length + ' h2/h3 heading ids' +
          (authored.tabs ? ', tab tags read' : ', no tab tags in the markdown') + ')');
        console.log('expectation: ' + authored.note);
      }
      var authoredKnown = !!(authored && !authored.error && authored.h2.length);
      console.log('page:    tabbed; the register switch is not built here, so its ' +
        'assertions are replaced by the tab assertions (design-v4 5.4)');
      console.log('page:    ' + pageOrder.length + ' section blocks in the page\'s own order ' +
        '(diagnostic only; the expected sections and their order come from the authored report)');
      await tabbedChecks(page, {
        url: srv.origin + '/reports/' + s + '/',
        html: html,
        authored: authoredKnown ? authored : null,
        authoredKnown: authoredKnown,
        pageOrder: pageOrder,
        /* D2: no fallback. With no authored report the count and order are NOT
           KNOWN, and every row that needs them records NOT CHECKED rather than
           comparing the page with itself. */
        sectionCount: authoredKnown ? authored.h2.length : 0,
        reportOrder: authoredKnown ? authored.h2 : []
      });
    } else {
      // ---------- the register switch ----------
      var vs = await page.computed('.hl-viewswitch', ['display']);
      check('the register switch is BUILT and painted, not just declared',
        vs && vs._present && vs.display !== 'none' && vs._w > 50,
        vs && vs._present ? 'rendered ' + vs._w + 'x' + vs._h + ' from ' + inputs.tiers +
          ' tier markers' : 'ABSENT: the control never got built from ' + inputs.tiers + ' markers');

      var btns = await page.json('[].slice.call(document.querySelectorAll(".hl-viewswitch__btn"))' +
        '.map(function(b){return b.textContent.trim();})');
      check('it offers all three registers', btns.length === 3, btns.join(' | ') || 'none');

      var openH2 = await page.visibleCount('.hl-post-content h2');
      // Click the FIRST (most restrictive) register with a real pointer.
      await page.click('.hl-viewswitch__btn');
      await CDP.sleep(350);
      var briefH2 = await page.visibleCount('.hl-post-content h2');
      check('picking the briefest register actually hides sections',
        briefH2 < openH2 && briefH2 > 0,
        openH2 + ' H2 sections visible on load, ' + briefH2 + ' after picking "' +
          (btns[0] || '?') + '"');

      if (inputs.tocLinks) {
        /* Measured by the `hidden` ATTRIBUTE that register-switch.js actually sets
           on each `<li>`, not by rendered area.

           Two wrong measures were tried first and both gave confident wrong
           answers. Counting visible `<a>` reported 53 of 53 visible however many
           items were hidden, because computed `display` is the element's own value
           and does not inherit `none` from an ancestor. Counting rendered `<li>`
           then reported 0 of 53, because the TOC panel is collapsed by default, so
           every item has zero area whatever the register. The attribute is the
           mechanism and it is unambiguous in both states. */
        var toc = await page.json('(function(){var li=document.querySelectorAll("#hl-toc-list li");' +
          'var h=0;[].forEach.call(li,function(e){if(e.hasAttribute("hidden"))h++;});' +
          'return {total:li.length,hidden:h};})()');
        check('the TOC narrows with the page rather than pointing at hidden sections',
          toc.hidden > 0 && toc.hidden < toc.total,
          toc.hidden + ' of ' + toc.total + ' TOC items hidden in the brief register');
      } else {
        check('NOT CHECKED: this report renders no TOC to narrow', false,
          'the TOC needs 3+ H2s; this report has ' + inputs.headings);
      }

      // Restore the fullest register for the checks below.
      await page.evaluate('(function(){var b=document.querySelectorAll(".hl-viewswitch__btn");' +
        'if(b.length)b[b.length-1].click();})()');
      await CDP.sleep(350);
      var restored = await page.visibleCount('.hl-post-content h2');
      check('returning to the full register restores every section',
        restored === openH2, restored + ' of ' + openH2 + ' sections back');
    }

    // ---------- figure-nav chips ----------
    var fignav = await page.json('(function(){var r=document.querySelector(".hl-fignav");' +
      'if(!r)return null;var c=getComputedStyle(r);var b=r.getBoundingClientRect();' +
      'var chips=[].slice.call(r.querySelectorAll("a"));' +
      'return {display:c.display,w:Math.round(b.width),chips:chips.length,' +
      'colors:chips.slice(0,3).map(function(a){return getComputedStyle(a).color;}),' +
      'targets:chips.map(function(a){return a.getAttribute("href");})};})()');
    if (!fignav) {
      check('NOT CHECKED: this report declares no figure-nav chips', false,
        inputs.figures + ' figures present but no chip row was built; only reports ' +
        'declaring figure_nav get one');
    } else {
      check('the figure-nav chips are built and painted',
        fignav.display !== 'none' && fignav.w > 50 && fignav.chips > 0,
        fignav.chips + ' chips, ' + fignav.w + 'px wide');

      /* The chips once shipped in the theme's link colour because
         `.hl-post-content a` is marked important and no test read CSS. */
      var themeLink = await page.evaluate(
        'getComputedStyle(document.querySelector(".hl-post-content a")).color');
      check('a chip is not painted in the theme link colour',
        fignav.colors.length > 0 && fignav.colors.some(function (c) { return c !== themeLink; }),
        'chips ' + fignav.colors.join(', ') + ' vs body links ' + themeLink);

      /* A real click must move the page to the chip's own target and, if that
         target sits inside a collapsed teardown, open it.

         The target is read from the chip's href, NOT from location.hash. The
         chips are ordinary anchors, but the smooth-scroll animation means the
         hash and the final scroll position both arrive late, and an earlier
         version of this check read an empty hash and called a working feature
         broken. The href is known before the click and cannot race. */
      var targetId = decodeURIComponent(String(fignav.targets[0] || '').slice(1));
      var before = await page.evaluate('Math.round(scrollY)');
      await page.click('.hl-fignav a');
      // Smooth scrolling is on, so the journey takes real time.
      await CDP.sleep(1200);
      var after = await page.json('(function(){var t=document.getElementById(' +
        JSON.stringify(targetId) + ');if(!t)return {found:false,y:Math.round(scrollY)};' +
        'var d=t.closest("details");var r=t.getBoundingClientRect();' +
        'return {found:true,y:Math.round(scrollY),top:Math.round(r.top),' +
        'inView:r.top>-120&&r.top<innerHeight,' +
        'inDetails:!!d,detailsOpen:d?d.open:null};})()');
      check('a real click on a chip scrolls to its target',
        after.found && after.y !== before,
        'scrollY ' + before + ' -> ' + after.y + ', target #' + targetId +
          (after.found ? '' : ' NOT FOUND IN DOM'));
      check('and the target lands in view, its teardown opened if it was collapsed',
        after.inView === true && after.detailsOpen !== false,
        'target ' + after.top + 'px from the viewport top; enclosing teardown: ' +
          (after.inDetails ? (after.detailsOpen ? 'open' : 'STILL CLOSED') : 'none'));
    }

    // ---------- the glossary ----------
    /* Same reason as the chips above: measure a mark in a shown tab. */
    if (tabbed) await revealPanelContaining(page, '.hl-gloss');
    var gloss = await page.json('(function(){var m=document.querySelectorAll(".hl-gloss");' +
      'if(!m.length)return {marks:0};var e=m[0];var r=e.getBoundingClientRect();' +
      'return {marks:m.length,term:e.textContent.trim(),' +
      'title:e.getAttribute("data-hl-gloss")||e.getAttribute("title")||"",' +
      'w:Math.round(r.width),borderBottom:getComputedStyle(e).borderBottomStyle};})()');
    if (!gloss.marks) {
      check('NOT CHECKED: this report carries no glossary marks', false,
        'no .hl-gloss elements were created, so the tooltip could not be exercised');
    } else {
      check('glossary terms are marked in the rendered page',
        gloss.marks > 0 && gloss.w > 0,
        gloss.marks + ' marks, first is "' + gloss.term + '"');
      check('a mark is visually distinguished, not silently inert',
        gloss.borderBottom !== 'none' || !!gloss.title,
        'border-bottom: ' + gloss.borderBottom + ', tooltip text: ' +
          (gloss.title ? 'present' : 'ABSENT'));

      /* The tooltip lives in `.hl-gloss::after`, hidden at opacity 0 and
         visibility hidden until :hover or :focus. Read BOTH: an earlier version
         of this check also consulted `::before`, which has no rule at all and so
         computes to opacity 1 always, and that made the check pass on a page
         where the tooltip never opened. A gate that cannot fail is not a gate. */
      var tipState = function () {
        return page.json('(function(){var a=getComputedStyle(' +
          'document.querySelector(".hl-gloss"),"::after");' +
          'return {opacity:a.opacity,visibility:a.visibility,' +
          'hasText:(a.content||"none").length>8};})()');
      };
      var closed = await tipState();
      check('the definition is hidden until asked for',
        parseFloat(closed.opacity) === 0 || closed.visibility === 'hidden',
        'at rest: opacity ' + closed.opacity + ', visibility ' + closed.visibility);

      await page.forcePseudo('.hl-gloss', ['hover']);
      await CDP.sleep(250);
      var open = await tipState();
      check('hovering a term reveals its definition',
        parseFloat(open.opacity) > 0 && open.visibility === 'visible' && open.hasText,
        'hovered: opacity ' + open.opacity + ', visibility ' + open.visibility +
          ', definition text ' + (open.hasText ? 'present' : 'MISSING'));

      // The CSS binds :focus as well, which is what a keyboard reader gets.
      await page.forcePseudo('.hl-gloss', []);
      await CDP.sleep(150);
      await page.forcePseudo('.hl-gloss', ['focus']);
      await CDP.sleep(250);
      var focused = await tipState();
      check('and focusing it does the same, so it is reachable without a mouse',
        parseFloat(focused.opacity) > 0 && focused.visibility === 'visible',
        'focused: opacity ' + focused.opacity + ', visibility ' + focused.visibility);
      await page.forcePseudo('.hl-gloss', []);
    }

    if (shotsDir) {
      fs.mkdirSync(shotsDir, { recursive: true });
      await page.evaluate('window.scrollTo(0,0)');
      await CDP.sleep(400);
      console.log('   shot  ' + await page.screenshot(path.join(shotsDir, 'report-top.png')));
    }
  } catch (e) {
    if (e.message !== '__notchecked__') throw e;
  } finally {
    page.close();
    srv.close();
  }

  var failed = results.filter(function (r) { return !r.pass; });
  var notCheckedRows = failed.filter(function (r) { return /^NOT CHECKED/.test(r.name); });
  console.log('\n' + (failed.length ? (failed.length === notCheckedRows.length ? 'NOT CHECKED' : 'FAIL') : 'PASS') +
    '  /reports/' + s + '/ in a real browser  (' +
    (results.length - failed.length) + '/' + results.length + ' checks)');
  if (!failed.length) process.exit(0);
  process.exit(failed.length === notCheckedRows.length ? 2 : 1);
}

/* Defect: a crash here used to erase a FAIL that `results` already recorded.
   Example measured directly: a first-party module (register-switch.js) made
   genuinely unreachable correctly fails "no script error blocked the report
   modules", but the missing module then leaves `.hl-viewswitch__btn` never
   built, so the later `page.click('.hl-viewswitch__btn')` throws. That
   exception is not the `__notchecked__` sentinel, so it escapes the try/catch
   inside main() (see the rethrow there) and lands here -- and this handler
   used to call `notChecked(...)` unconditionally, reporting exit 2 for a run
   that had already found a real defect. Per
   homelab-soc/docs/gate-honesty-contract.md the three states (PASS/FAIL/NOT
   CHECKED) must stay distinguishable; a recorded FAIL must never be
   relabelled NOT CHECKED just because something else broke afterward.

   The fix reads `results` -- the same array `check()` has been pushing into
   all along -- for any row that is a genuine failure (not one of the
   'NOT CHECKED: ...'-named rows check() also uses to record an early,
   legitimate NOT CHECKED branch). If one exists, the run already failed
   before it crashed: print every recorded failure, print the crash message
   too (the reason the run aborted early is still information and must not
   be suppressed), and exit 1. Only when NOTHING has failed yet does a crash
   here still mean NOT CHECKED, exactly as before -- so the sentinel path
   (which never reaches this handler at all; it is caught and handled inside
   main() itself) and the "crashed before any check ran" path are both
   unchanged. */
/* Everything above is reachable from `node --test` as pure functions: the CLI
   entry point runs only when this file is the program, so a test can require it
   and exercise the authored-report resolution, the body comparison and the
   heading-text normaliser without opening a browser. */
if (require.main === module) {
  main().catch(function (e) {
    var recordedFailures = results.filter(function (r) {
      return !r.pass && !/^NOT CHECKED/.test(r.name);
    });
    if (recordedFailures.length) {
      console.log('\nFAIL  the run aborted early: ' + recordedFailures.length +
        ' check(s) had already failed before the crash below.');
      recordedFailures.forEach(function (r) { console.log('   FAIL  ' + r.name); });
      console.log('\ncrash: ' + e.message);
      process.exit(1);
    }
    notChecked('the browser check errored before finishing: ' + e.message);
  });
} else {
  module.exports = {
    readAuthored: readAuthored,
    reportPaths: reportPaths,
    bodyLines: bodyLines,
    firstBodyDifference: firstBodyDifference,
    normaliseHeadingText: normaliseHeadingText,
    isTabbedHtml: isTabbedHtml,
    TAB_TOKENS: TAB_TOKENS,
    TAB_VIEWPORTS: TAB_VIEWPORTS,
    /* p7: the 4a rows the deepseek review found missing, and the pure
       verdicts behind them, so a test can prove each row can fail. */
    MIN_TARGET_PX: MIN_TARGET_PX,
    TAB_BAR_VIEWPORTS: TAB_BAR_VIEWPORTS,
    tabLookVerdict: tabLookVerdict,
    panelStackVerdict: panelStackVerdict,
    featuredSponsorVerdict: featuredSponsorVerdict,
    FEATURED_EXPR: FEATURED_EXPR,
    railVerdict: railVerdict,
    RAIL_EXPR: RAIL_EXPR,
    RAIL_STATES: RAIL_STATES,
    shareGeometryVerdict: shareGeometryVerdict,
    shareBehaviourVerdict: shareBehaviourVerdict,
    SHARE_EXPR: SHARE_EXPR,
    mispVerdict: mispVerdict,
    mispEventFor: mispEventFor,
    MISP_EXPR: MISP_EXPR,
    timelineVerdict: timelineVerdict,
    legendVerdict: legendVerdict,
    TIMELINE_EXPR: TIMELINE_EXPR,
    typeScaleVerdict: typeScaleVerdict,
    TYPE_SPEC: TYPE_SPEC,
    PANEL_EXPR: PANEL_EXPR,
    TYPE_EXPR: TYPE_EXPR,
    chromeTextExpr: chromeTextExpr,
    CHROME_FLOOR_PX: CHROME_FLOOR_PX,
    TAB_TARGET_VIEWPORTS: TAB_TARGET_VIEWPORTS,
    tabGeomExpr: tabGeomExpr,
    tabHitExpr: tabHitExpr,
    tabTargetExpr: tabTargetExpr,
    tabReachVerdict: tabReachVerdict,
    targetRowVerdict: targetRowVerdict,
    attackStripVerdict: attackStripVerdict,
    attackStripControlHtml: attackStripControlHtml,
    ATTACK_STRIP_EXPR: ATTACK_STRIP_EXPR
  };
}
