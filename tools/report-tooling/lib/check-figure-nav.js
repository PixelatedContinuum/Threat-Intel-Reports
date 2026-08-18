'use strict';

/* Verifies a report's figure_nav declaration two ways.

   The markdown path runs before commit. It derives the anchors the site will
   generate using the rule in kramdown-slug.js, so an anchor typo is caught
   without a build. That matters more here than anywhere else in this tooling: a
   bad anchor scrolls nowhere and throws nothing, so it is invisible in every log
   and to every green test suite, and the only other thing that would notice is a
   reader who clicked.

   The DOM path runs after push against the real page, and additionally drives
   the SHIPPED figure-nav.js over the real body, so the verdict covers the module
   the reader actually gets rather than a description of it.

   PASS, FAIL and NOT CHECKED, with the third never folded into the first. A
   report declaring nothing is PASS with a reason, because there is genuinely
   nothing to verify and calling that NOT CHECKED would drown the sweep in noise
   from the reports carrying no graphic at all. A report declaring something that
   could not be read is NOT CHECKED. */

var path = require('node:path');
var fs = require('node:fs');

var KS = require('./kramdown-slug.js');

var ROOT = path.join(__dirname, '..', '..', '..');

/* Its own guard, not a shared one. A broken figure-nav module must not disable
   the strip gate, and a strip-side failure must not mark this claim as fine. */
var FN = null;
var DEPS_REASON = null;
try {
  FN = require(path.join(ROOT, 'assets', 'js', 'figure-nav.js'));
  if (!FN || typeof FN.render !== 'function') {
    throw new Error('figure-nav.js loaded but exports no render');
  }
} catch (e) {
  DEPS_REASON = 'figure-nav module did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim();
}

function strip(s) { return String(s).trim().replace(/^["']|["']$/g, ''); }

function frontMatter(md) {
  var m = String(md).match(/^---\r?\n([\s\S]*?)\r?\n---/);
  return m ? m[1] : '';
}

/* Minimal reader for the one nested shape figure_nav uses. A real YAML parser is
   not worth a dependency in the site repo, and the checker asserts on the
   result, so a shape this cannot read surfaces as a FAIL rather than a silent
   zero. Returns null when the key is absent, which is deliberately distinct from
   an empty array meaning the key is present but declares nothing. */
function parseFigureNav(front) {
  var lines = String(front).split(/\r?\n/);
  var i = 0;
  while (i < lines.length && !/^figure_nav:\s*$/.test(lines[i])) i++;
  if (i >= lines.length) return null;
  i++;
  var entries = [];
  var cur = null;
  var inParts = false;
  for (; i < lines.length; i++) {
    var line = lines[i];
    if (!line.trim()) continue;
    if (/^\S/.test(line)) break;              // back to column zero, the key is over
    var img = line.match(/^\s*-\s*image:\s*(.+)$/);
    if (img) {
      cur = { image: strip(img[1]), parts: [] };
      entries.push(cur);
      inParts = false;
      continue;
    }
    if (!cur) continue;
    if (/^\s*parts:\s*$/.test(line)) { inParts = true; continue; }
    var lab = line.match(/^\s*-\s*label:\s*(.+)$/);
    if (lab && inParts) { cur.parts.push({ label: strip(lab[1]), anchor: null }); continue; }
    var anc = line.match(/^\s*anchor:\s*(.+)$/);
    if (anc && cur.parts.length) cur.parts[cur.parts.length - 1].anchor = strip(anc[1]);
  }
  return entries;
}

/* Figure image basenames in source order. The src is a Liquid expression with
   nested quotes, so this matches the path inside the block rather than trying to
   parse the attribute, which an attribute regex gets wrong on every figure in
   the corpus. */
function figureImages(md) {
  var out = [];
  String(md).replace(/<figure[\s\S]*?<\/figure>/g, function (block) {
    var m = block.match(/\/assets\/images\/[^"'\s)]*?\/([^/"'\s)]+\.svg)/);
    if (m) out.push(m[1]);
    return block;
  });
  return out;
}

function verdict(status, reason, problems, entries, chips) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    entries: entries || 0,
    chips: chips || 0
  };
}

var SLUG_HINT = 'Anchors are generated heading ids: outside a teardown nothing is ' +
  'stripped and each space becomes one hyphen so runs of hyphens are real, while ' +
  'INSIDE a <details> block the leading number is stripped. Run ' +
  'node propose-figure-nav.js <slug> to print every heading with its real anchor.';

/* The rule set, shared by both paths so they cannot drift. `images` is the list
   of figure basenames available, `anchors` a map of the ids that exist. */
function validate(entries, images, anchors) {
  var problems = [];
  var chips = 0;

  entries.forEach(function (e, idx) {
    var where = 'figure_nav[' + idx + ']' + (e && e.image ? ' (' + e.image + ')' : '');

    if (!e || !e.image) { problems.push(where + ' declares no image'); return; }

    var matches = images.filter(function (n) { return n === e.image; }).length;
    if (matches === 0) {
      problems.push(where + ': no figure on this page uses that image, so the chips ' +
        'would never render. Check the filename against the figure block.');
      return;
    }
    if (matches > 1) {
      problems.push(where + ': ' + matches + ' figures use that image, so the chips ' +
        'would attach ambiguously. Rename one, or drop the entry.');
      return;
    }

    var parts = e.parts || [];
    if (parts.length < 2) {
      problems.push(where + ' declares ' + parts.length + ' part(s), and an entry needs ' +
        'at least two, because a one-chip row is a link pretending to be navigation.');
      return;
    }

    var seenLabel = {};
    var distinct = {};
    parts.forEach(function (p, j) {
      var pw = where + ' part[' + j + ']';
      if (!p || !p.label) { problems.push(pw + ' has no label'); return; }
      if (seenLabel[p.label]) problems.push(pw + ': duplicate label "' + p.label + '"');
      seenLabel[p.label] = 1;

      if (!p.anchor || p.anchor.charAt(0) !== '#') {
        problems.push(pw + ' ("' + p.label + '") has no anchor, or one missing its leading #');
        return;
      }
      var id = p.anchor.slice(1);
      var decoded = id;
      try { decoded = decodeURIComponent(id); } catch (err) { decoded = id; }
      if (!anchors[id] && !anchors[decoded]) {
        problems.push(pw + ' ("' + p.label + '") points at #' + id +
          ', which is not a heading on this page. ' + SLUG_HINT);
        return;
      }
      distinct[anchors[id] ? id : decoded] = 1;
      chips++;
    });

    if (Object.keys(distinct).length < 2) {
      problems.push(where + ' resolves to fewer than two distinct sections, so every ' +
        'chip would go to the same place. Omit the entry for a graphic whose parts ' +
        'are all explained in one section.');
    }
  });

  return { problems: problems, chips: chips };
}

function checkMarkdown(src, label) {
  var entries;
  try { entries = parseFigureNav(frontMatter(src)); }
  catch (e) {
    return verdict('NOT CHECKED', 'front matter could not be parsed: ' +
      String(e.message).split('\n')[0]);
  }
  if (entries === null) return verdict('PASS', 'no figure_nav declared', [], 0, 0);
  if (!entries.length) {
    return verdict('FAIL', null, ['figure_nav is declared but empty; remove the key ' +
      'rather than leaving it with no entries'], 0, 0);
  }

  var anchors = {};
  KS.headings(src).forEach(function (h) { anchors[h.slug] = 1; });
  var r = validate(entries, figureImages(src), anchors);

  return verdict(r.problems.length ? 'FAIL' : 'PASS', null, r.problems, entries.length, r.chips);
}

function checkDom(doc, label) {
  var raw = doc.getElementById('hl-figure-nav');
  if (!raw) return verdict('PASS', 'no figure_nav declared', [], 0, 0);

  var entries;
  try { entries = JSON.parse(raw.textContent); }
  catch (e) {
    return verdict('FAIL', null, ['the figure_nav JSON block on the page is not valid ' +
      'JSON: ' + String(e.message).split('\n')[0]], 0, 0);
  }
  if (!entries || !entries.length) {
    return verdict('FAIL', null, ['figure_nav is declared but empty'], 0, 0);
  }

  var body = doc.querySelector('.hl-post-content') || doc.body;

  var images = [];
  var imgs = body.querySelectorAll('figure img[src]');
  for (var i = 0; i < imgs.length; i++) {
    images.push(String(imgs[i].getAttribute('src')).split('#')[0].split('?')[0].split('/').pop());
  }

  var anchors = {};
  var ided = doc.querySelectorAll('[id]');
  for (var j = 0; j < ided.length; j++) anchors[ided[j].id] = 1;

  var r = validate(entries, images, anchors);

  /* Drive the real module. A declaration can be perfectly valid while the
     shipped renderer still puts nothing on the page, and that gap is exactly
     what checking only the DATA would miss. */
  if (DEPS_REASON) {
    return verdict('NOT CHECKED', DEPS_REASON, r.problems, entries.length, r.chips);
  }
  var renderable = entries.filter(function (e) {
    return e && e.image && e.parts && e.parts.length &&
      images.filter(function (n) { return n === e.image; }).length === 1;
  }).length;
  var rendered = FN.render(body, entries, doc);
  if (rendered !== renderable) {
    r.problems.push('the shipped figure-nav.js rendered ' + rendered + ' of ' + renderable +
      ' bindable chip rows, which is a defect in assets/js/figure-nav.js rather than ' +
      'in this report');
  }

  return verdict(r.problems.length ? 'FAIL' : 'PASS', null, r.problems, entries.length, r.chips);
}

module.exports = {
  frontMatter: frontMatter,
  parseFigureNav: parseFigureNav,
  figureImages: figureImages,
  validate: validate,
  checkMarkdown: checkMarkdown,
  checkDom: checkDom,
  DEPS_REASON: DEPS_REASON
};

/* A command line, so the gate driver can exercise this end to end and the author
   has a manual tool. Takes a report path or a published URL. */
if (require.main === module) {
  var target = process.argv.slice(2).filter(function (a) { return a.indexOf('--') !== 0; })[0];
  if (!target) {
    console.error('usage: node lib/check-figure-nav.js <report.md|https://...>');
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
        if (!res.ok) {
          console.log('NOT CHECKED  ' + target + '  HTTP ' + res.status);
          process.exit(2);
        }
        html = await res.text();
      } catch (e) {
        console.log('NOT CHECKED  ' + target + '  ' + e.message);
        process.exit(2);
      }
      r = checkDom(new JSDOM(html).window.document, target);
    } else {
      var src;
      try { src = fs.readFileSync(target, 'utf8'); }
      catch (e) { console.log('NOT CHECKED  ' + target + '  ' + e.message); process.exit(2); }
      r = checkMarkdown(src, target);
    }
    var tail = r.status === 'PASS'
      ? (r.reason || r.entries + ' figures, ' + r.chips + ' chips')
      : r.status === 'NOT CHECKED' ? r.reason : r.problems.join('; ');
    console.log(r.status.padEnd(12) + ' ' + target + '   ' + tail);
    process.exit(r.status === 'PASS' ? 0 : r.status === 'FAIL' ? 1 : 2);
  })();
}
