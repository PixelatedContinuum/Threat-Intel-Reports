#!/usr/bin/env node
'use strict';

/* Proves the tabbed report holds every word of the report it replaces
   (design-v4 check 5.2; build-contract.md "Checks").

   The claim: the visible text of the tabbed page in one-page mode, minus
   everything the layout adds (marked `data-rv-chrome`: dashboard views, tab
   controls, masthead, hero, footer) and minus `script`, `style` and `title`,
   equals the baseline article. Zero words missing, zero added. A paragraph lost
   while inserting tab tags therefore shows as missing, which is the whole point
   of the check.

   THE BASELINE is the report as published before tagging: for a migrated report
   the live page's article body fetched before its layout switches; for a new
   report the untagged render of the same markdown. `--page` is the tabbed page.
   Both may be a URL or a local file.

   IN CHROME, over lib/cdp.js, because the tabbed page's panels and views are
   built by JavaScript at runtime and jsdom has no layout, no computed styles and
   no real page. A missing browser is NOT CHECKED with the reason named, never a
   pass.

   TOKENISATION. Text is the article root's `textContent` with runs of whitespace
   collapsed, which is exactly what BeautifulSoup's `get_text()` plus
   `' '.join(split())` produced when the prototype's completeness numbers were
   measured (tasks/runs/T-0500.1/proto-full-build/check_complete.py). Both
   documents are read the same way, so a token merge at an element boundary
   affects both equally and cannot hide a deleted paragraph; the `--control` run
   proves that on the real page. The alternative (insert a space at every block
   boundary) is a better tokeniser in the abstract and gives 15,669 words on this
   pair instead of the prototype's measured 15,648, so it would not reproduce the
   number this gate is required to reproduce.

   SCRIPTS OFF FOR THE BASELINE, ON FOR THE PAGE. The published article carries
   inline scripts that add a "Copy" button to every `<pre>` at runtime. With
   scripting on, the saved live page's article reads 15,648 words / 98,404 chars /
   43 links against the prototype's 15,648 / 98,400 / 19: the extra links are
   figure-nav chips and IOC copy buttons the script builds. "The report as
   published before tagging" is the server HTML, so the baseline is read with
   scripting disabled; the tabbed page is read with its own script running,
   because the panels and views it builds are what is being checked.

   PANEL NAMES ARE NEVER READ. The check compares text and counts, not panel ids,
   so it is indifferent to the prototype's bare tokens and the build's `tab-`
   prefix.

   THE VERDICT IS A WORD MULTISET, NOT A SEQUENCE. "Zero words missing, zero
   added" is a claim about the words held, and the contract's panel grouping makes
   tab order the DOM order, so an ordered comparison fails every correct tabbed
   page (on the prototype it calls 1,435 correctly held words missing). The
   ordered diff is still computed and printed when words really are missing, and
   the out-of-report-order count is printed as an advisory; section order is
   check-browser-report.js's business.

   `--control` deletes one paragraph from the page under test and requires the
   comparison to FAIL with exactly that paragraph's word count missing. A check
   whose own control does not fire is NOT CHECKED, never PASS.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. With --control the mutated page's verdict
   is printed and the exit code follows that verdict (1), as the gate would for a
   real loss; the CONTROL line says whether the control fired as designed.

   Run: node check-report-text.js --baseline <url-or-file> --page <url-or-file>
          [--width 1280,390] [--control]
   Env: HL_CHROME (see lib/cdp.js) */

var path = require('node:path');
var fs = require('node:fs');
var url = require('node:url');

var COUNTS = [
  ['headings', 'h1,h2,h3,h4,h5,h6'],
  ['tables', 'table'],
  ['rows', 'tr'],
  ['figures', 'figure'],
  ['images', 'img'],
  ['teardowns', 'details.hl-teardown'],
  ['details', 'details'],
  ['code blocks', 'pre'],
  ['links', 'a[href]'],
  ['lists', 'ul,ol']
];

var COUNTS_JSON = JSON.stringify(COUNTS);

/* One round trip per document. Removes what the layout adds, then reads the text
   and the counts from the same DOM state, so a strip cannot be reported against
   a different tree than the one that was measured. */
var EXTRACT_JS = '(function(){' +
  'var root=document.querySelector(".hl-post-content")||document.querySelector("main")||document.body;' +
  'if(!root)return JSON.stringify({error:"no article root"});' +
  'var chrome=0;' +
  '[].slice.call(root.querySelectorAll("[data-rv-chrome]")).forEach(function(e){' +
  'if(e.parentNode){e.parentNode.removeChild(e);chrome++;}});' +
  '[].slice.call(root.querySelectorAll("script,style,title")).forEach(function(e){' +
  'if(e.parentNode)e.parentNode.removeChild(e);});' +
  'var counts={};' +
  COUNTS_JSON + '.forEach(function(p){counts[p[0]]=root.querySelectorAll(p[1]).length;});' +
  'var hs=[].slice.call(root.querySelectorAll("h1,h2,h3,h4,h5,h6"));' +
  'var ids=hs.map(function(h){return h.id;}).filter(Boolean);' +
  'var text=(root.textContent||"").replace(/\\s+/g," ").trim();' +
  'var where=root.tagName.toLowerCase()+(root.id?"#"+root.id:"")+' +
  '(root.className?"."+String(root.className).split(" ")[0]:"");' +
  'return JSON.stringify({text:text,counts:counts,ids:ids,root:where,chrome:chrome,' +
  'href:location.href,' +
  'words:text?text.split(" ").length:0,chars:text.length});' +
'})()';

var DELETE_PARA_JS = '(function(){' +
  'var root=document.querySelector(".hl-post-content")||document.querySelector("main")||document.body;' +
  'var ps=[].slice.call(root.querySelectorAll("p"));' +
  'for(var i=0;i<ps.length;i++){' +
  'var w=(ps[i].textContent||"").replace(/\\s+/g," ").trim();' +
  'var n=w?w.split(" ").length:0;' +
  'if(n>=20){ps[i].parentNode.removeChild(ps[i]);' +
  'return JSON.stringify({words:n,text:w.slice(0,120)});}}' +
  'return JSON.stringify({words:0,text:null});' +
'})()';

function countsJson() {
  return JSON.stringify(COUNTS);
}

function withOnePage(target) {
  if (/^https?:\/\//.test(target)) return target.replace(/#.*$/, '') + '#one-page';
  var abs = path.resolve(target);
  return url.pathToFileURL(abs).href + '#one-page';
}

/* The claim this gate makes is "zero words missing, zero added", which is a
   property of the words held, not of their order. So the verdict rests on a
   word MULTISET difference: exact, linear, and indifferent to where a section
   sits.

   Order is measured too, and reported, but it is not a failure here. The build
   contract's panel grouping wraps each h2 and its siblings into a per-tab
   section, "grouped by token, report order inside each panel", so a correct
   tabbed page's DOM is TAB order, not report order. The full-text prototype is
   the same: its section 17 (Notification, Victims) sits directly after section 3,
   and section 6 (Infrastructure, Infrastructure and timeline) after the Attack
   chain sections, so an ordered comparison calls 1,435 correctly held words
   "missing" and 1,435 "added". A gate that fails every correct tabbed page is a
   gate people learn to ignore. Section order and one-page stacking are
   check-browser-report.js's business (design-v4 checks 4 and E4).

   The ordered diff is still computed, and printed when words really are missing
   or added, because "which paragraph" is the question a writer asks. */
function multisetDiff(a, b) {
  var counts = new Map();
  for (var i = 0; i < a.length; i++) counts.set(a[i], (counts.get(a[i]) || 0) + 1);
  for (var j = 0; j < b.length; j++) counts.set(b[j], (counts.get(b[j]) || 0) - 1);

  var missing = 0, added = 0, missingSample = [], addedSample = [];
  counts.forEach(function (n, w) {
    if (n > 0) {
      missing += n;
      if (missingSample.length < 12) missingSample.push('"' + w + '" x' + n);
    } else if (n < 0) {
      added += -n;
      if (addedSample.length < 12) addedSample.push('"' + w + '" x' + (-n));
    }
  });
  return { missing: missing, added: added, missingSample: missingSample, addedSample: addedSample };
}

/* A word-level ordered diff, used for the "which words" line and the order
   measurement. Common prefix and suffix are trimmed first (cheap, and it makes
   the identical case O(1)), then a Myers diff runs on the middle. Myers is
   bounded: a pair that differs in more than MAX_D places falls back to "the
   middle is all missing and added", flagged `approximate`, because a gate that
   hangs on a bad pair is worse than one that says how it counted. */
var MAX_D = 3000;

function diffWords(a, b) {
  var pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  var suf = 0;
  while (suf < a.length - pre && suf < b.length - pre &&
         a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;

  var am = a.slice(pre, a.length - suf);
  var bm = b.slice(pre, b.length - suf);

  if (!am.length && !bm.length) {
    return { missing: 0, added: 0, ops: [], approximate: false };
  }
  if (!am.length || !bm.length) {
    return {
      missing: am.length, added: bm.length,
      ops: am.length ? [{ op: 'del', words: am.slice(0, 12) }] : [{ op: 'add', words: bm.slice(0, 12) }],
      approximate: false
    };
  }

  var N = am.length, M = bm.length;
  var max = Math.min(N + M, MAX_D);
  var off = max + 1;
  var v = new Int32Array(2 * max + 3);
  var trace = [];

  for (var d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (var k = -d; k <= d; k += 2) {
      var x;
      if (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
      else x = v[off + k - 1] + 1;
      var y = x - k;
      while (x < N && y < M && am[x] === bm[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= N && y >= M) {
        return backtrack(trace, am, bm, d, off);
      }
    }
  }

  return {
    missing: N, added: M,
    ops: [{ op: 'del', words: am.slice(0, 12) }, { op: 'add', words: bm.slice(0, 12) }],
    approximate: true
  };
}

function backtrack(trace, a, b, dEnd, off) {
  var x = a.length, y = b.length;
  var missing = 0, added = 0, ops = [];
  for (var d = dEnd; d > 0; d--) {
    var v = trace[d];
    var k = x - y;
    var prevK = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? k + 1 : k - 1;
    var prevX = v[off + prevK];
    var prevY = prevX - prevK;
    while (x > prevX && y > prevY) { x--; y--; }
    if (x === prevX) {
      added++;
      if (ops.length < 12) ops.push({ op: 'add', word: b[y - 1] });
      y--;
    } else {
      missing++;
      if (ops.length < 12) ops.push({ op: 'del', word: a[x - 1] });
      x--;
    }
    x = prevX;
    y = prevY;
  }
  return { missing: missing, added: added, ops: ops, approximate: false };
}

/* Every baseline id must exist exactly once on the page. Returned as a list of
   problems, empty when clean. */
function checkIds(baselineIds, pageIds) {
  var seen = {};
  pageIds.forEach(function (id) { seen[id] = (seen[id] || 0) + 1; });
  var problems = [];
  baselineIds.forEach(function (id) {
    var n = seen[id] || 0;
    if (n === 0) problems.push('id "' + id + '" is missing from the page');
    else if (n > 1) problems.push('id "' + id + '" appears ' + n + ' times on the page');
  });
  return problems;
}

function compare(base, page) {
  var aw = base.text ? base.text.split(' ') : [];
  var bw = page.text ? page.text.split(' ') : [];
  var ms = multisetDiff(aw, bw);
  var seq = diffWords(aw, bw);

  var countProblems = [];
  COUNTS.forEach(function (p) {
    var k = p[0];
    if (base.counts[k] !== page.counts[k]) {
      countProblems.push(k + ' ' + base.counts[k] + ' baseline vs ' + page.counts[k] + ' page');
    }
  });

  var idProblems = checkIds(base.ids, page.ids);

  var pass = ms.missing === 0 && ms.added === 0 &&
    countProblems.length === 0 && idProblems.length === 0;

  /* Words held but not in report order. Meaningful only when nothing is missing
     or added; otherwise the ordered diff is just the same loss counted twice. */
  var outOfOrder = (!ms.missing && !ms.added && (seq.missing || seq.added))
    ? seq.missing + seq.added : 0;

  return {
    status: pass ? 'PASS' : 'FAIL',
    missing: ms.missing,
    added: ms.added,
    missingSample: ms.missingSample,
    addedSample: ms.addedSample,
    outOfOrder: outOfOrder,
    approximate: seq.approximate,
    ops: seq.ops,
    words: { baseline: aw.length, page: bw.length },
    chars: { baseline: base.chars, page: page.chars },
    counts: { baseline: base.counts, page: page.counts },
    countProblems: countProblems,
    ids: { baseline: base.ids.length, page: page.ids.length, problems: idProblems }
  };
}

function line(r, label) {
  console.log('  ' + label.padEnd(9) + r.words.baseline + ' words, ' + r.chars.baseline +
    ' chars  ->  ' + r.words.page + ' words, ' + r.chars.page + ' chars');
  console.log('  words     missing ' + r.missing + ', added ' + r.added +
    ' (counts, so a section that moved is not counted twice)' +
    (r.approximate ? '  [APPROXIMATE: the pair differs in more than ' + MAX_D + ' places]' : ''));
  if (r.outOfOrder) {
    console.log('  order     ' + r.outOfOrder + ' words out of report order (advisory: the panel ' +
      'grouping makes tab order the DOM order; section order is the browser check\'s)');
  }
  var pairs = COUNTS.map(function (p) {
    var k = p[0];
    return k + ' ' + r.counts.page[k] + '/' + r.counts.baseline[k];
  });
  console.log('  counts    page/baseline: ' + pairs.join(', '));
  console.log('  ids       ' + r.ids.page + ' on the page, ' + r.ids.baseline + ' in the baseline, ' +
    (r.ids.problems.length ? r.ids.problems.length + ' problem(s)' : 'all present exactly once'));
  r.countProblems.forEach(function (p) { console.log('  COUNT     ' + p); });
  r.ids.problems.forEach(function (p) { console.log('  ID        ' + p); });
  if (r.missingSample.length || r.addedSample.length) {
    if (r.missingSample.length) console.log('  missing   ' + r.missingSample.join(' '));
    if (r.addedSample.length) console.log('  added     ' + r.addedSample.join(' '));
  }
  if (r.missing || r.added) {
    if (r.ops.length) {
      console.log('  diff      ' + r.ops.map(function (o) {
        return (o.op === 'del' ? '-' : '+') + (o.word !== undefined ? o.word : (o.words || []).join(' '));
      }).join(' | '));
    }
  }
}

async function main() {
  var argv = process.argv.slice(2);
  function arg(name) {
    var i = argv.indexOf(name);
    return i === -1 ? null : argv[i + 1];
  }
  var baselineArg = arg('--baseline');
  var pageArg = arg('--page');
  var widthArg = arg('--width') || '1280';
  var control = argv.indexOf('--control') !== -1;

  if (!baselineArg || !pageArg) {
    console.error('usage: node check-report-text.js --baseline <url-or-file> --page <url-or-file> ' +
      '[--width 1280,390] [--control]');
    process.exit(2);
  }
  if (!fs.existsSync(baselineArg) && !/^https?:\/\//.test(baselineArg)) {
    console.log('NOT CHECKED  baseline not found: ' + baselineArg);
    process.exit(2);
  }
  if (!fs.existsSync(pageArg) && !/^https?:\/\//.test(pageArg)) {
    console.log('NOT CHECKED  page not found: ' + pageArg);
    process.exit(2);
  }

  var CDP;
  try { CDP = require('./lib/cdp.js'); }
  catch (e) {
    console.log('NOT CHECKED  lib/cdp.js did not load: ' + e.message);
    process.exit(2);
  }

  var widths = String(widthArg).split(',').map(function (w) { return parseInt(w, 10); })
    .filter(function (w) { return w > 0; });
  if (!widths.length) {
    console.log('NOT CHECKED  --width carried no usable width');
    process.exit(2);
  }

  var all = [];

  /* One browser at a time, each on its own debugging port.

     MEASURED 2026-10-29: opening the baseline and the page in two browsers that
     both defaulted to port 9377 made the second launch attach to the FIRST
     browser's target list, because the first had not finished exiting and the
     port was still held. Both extractions then ran against the same document and
     the check reported a perfect match between a page and itself, which is the
     worst possible false pass. Sequential launches on distinct ports remove the
     race; the location check below is the tripwire that would catch it again.

     SCRIPTS OFF FOR THE BASELINE, ON FOR THE PAGE, and both halves are measured.
     The live page carries inline scripts inside the article that add a "Copy"
     button to every <pre> and the figure-nav chips at runtime: with scripting on,
     its article reads 15,648 words / 98,404 chars / 43 links, against the
     prototype's 15,648 / 98,400 / 19. Those numbers came from the SERVER HTML,
     which is what "the report as published before tagging" means, and they are
     what the prototype's own completeness run measured with BeautifulSoup. So
     the baseline is read with scripting disabled (the article exactly as
     published), and the page is read with its own script running, because the
     tabbed page builds its panels and views at runtime and that is what is being
     checked. */
  for (var wi = 0; wi < widths.length; wi++) {
    var width = widths[wi];
    console.log('');
    console.log('== ' + width + 'px ==');

    async function openDoc(target, port, scripts) {
      var pg;
      try {
        pg = await CDP.open(scripts ? withOnePage(target) : 'about:blank',
          { width: width, height: 1400, port: port, settle: scripts ? 3000 : 500 });
        if (!scripts) {
          await pg.send('Emulation.setScriptExecutionDisabled', { value: true });
          await pg.send('Page.navigate', { url: withOnePage(target) });
          await CDP.sleep(2500);
        }
      } catch (e) {
        console.log('NOT CHECKED  ' + e.message);
        process.exit(2);
      }
      return pg;
    }

    var base, pg;
    try {
      var bp = await openDoc(baselineArg, 9410 + wi * 2, false);
      try {
        base = JSON.parse(await bp.evaluate(EXTRACT_JS));
      } finally { bp.close(); }
      if (base.error) { console.log('NOT CHECKED  baseline: ' + base.error); process.exit(2); }

      var pp = await openDoc(pageArg, 9411 + wi * 2, true);
      try {
        pg = JSON.parse(await pp.evaluate(EXTRACT_JS));
        if (pg.error) { console.log('NOT CHECKED  page: ' + pg.error); process.exit(2); }
        if (control) {
          var del = JSON.parse(await pp.evaluate(DELETE_PARA_JS));
          if (del.words) {
            pg.control = JSON.parse(await pp.evaluate(EXTRACT_JS));
            pg.controlDelete = del;
          }
        }
      } finally { pp.close(); }
    } catch (e) {
      console.log('NOT CHECKED  ' + String(e.message || e).split('\n')[0]);
      process.exit(2);
    }

    console.log('  baseline  ' + base.root + '  (' + base.chrome + ' chrome nodes stripped)');
    console.log('  page      ' + pg.root + '  (' + pg.chrome + ' chrome nodes stripped)');
    if (base.href === pg.href) {
      console.log('NOT CHECKED  both browsers read ' + base.href + '; one launch attached to the ' +
        'other\'s target, so this run compared a document with itself');
      process.exit(2);
    }

    var r = compare(base, pg);
    line(r, 'text');
    console.log('  ' + r.status);

    if (control) {
      if (!pg.controlDelete || !pg.controlDelete.words) {
        console.log('CONTROL NOT CHECKED  the page has no paragraph of 20 words or more to delete');
        process.exit(2);
      }
      var rc2 = compare(base, pg.control);
      line(rc2, 'control');
      var fired = rc2.status === 'FAIL' && rc2.missing === pg.controlDelete.words;
      console.log('  CONTROL   deleted a ' + pg.controlDelete.words + '-word paragraph ("' +
        String(pg.controlDelete.text).slice(0, 60) + '..."): verdict ' + rc2.status + ', ' +
        rc2.missing + ' missing, ' + rc2.added + ' added  ->  ' + (fired ? 'FIRED' : 'DID NOT FIRE'));
      if (!fired) {
        console.log('NOT CHECKED  the control did not fire: this check cannot be trusted on this pair');
        process.exit(2);
      }
      r = rc2;
      r.control = { deleted: pg.controlDelete.words, fired: true };
    }

    all.push({ width: width, r: r });
  }

  var failed = all.filter(function (a) { return a.r.status !== 'PASS'; });
  console.log('');
  console.log((failed.length ? 'FAIL' : 'PASS') + '  ' +
    (failed.length
      ? failed.map(function (a) { return a.width + 'px: ' + a.r.missing + ' missing, ' +
          a.r.added + ' added'; }).join('; ')
      : 'every word, count and id matches at ' + all.map(function (a) { return a.width + 'px'; }).join(' and ')));
  process.exit(failed.length ? 1 : 0);
}

module.exports = {
  COUNTS: COUNTS,
  EXTRACT_JS: EXTRACT_JS,
  diffWords: diffWords,
  multisetDiff: multisetDiff,
  checkIds: checkIds,
  compare: compare,
  withOnePage: withOnePage
};

if (require.main === module) {
  main().catch(function (e) {
    console.log('NOT CHECKED  ' + String(e.message || e).split('\n')[0]);
    process.exit(2);
  });
}
