#!/usr/bin/env node
'use strict';

/* Proves the tabbed report holds every word of the report it replaces, in the
   report's order (design-v4 check 5.2; build-contract.md "Checks").

   The claim: the visible text of the tabbed page in ONE-PAGE MODE, minus
   everything the layout adds (marked `data-rv-chrome`: dashboard views, tab
   controls, masthead, hero, footer) and minus `script`, `style` and `title`,
   equals the baseline article, word for word and in order. Zero words missing,
   zero added. A paragraph lost while inserting tags therefore shows as missing,
   a moved paragraph shows as missing and added, and a section out of place
   FAILs, which is the whole point of the check.

   THE BASELINE is the report as published before tagging: for a migrated report
   the live page's article body fetched before its layout switches; for a new
   report the untagged render of the same markdown. `--page` is the tabbed page.
   Both may be a URL or a local file.

   IN CHROME, over lib/cdp.js, because the tabbed page's panels and views are
   built by JavaScript at runtime and jsdom has no layout, no computed styles and
   no real page. A missing browser is NOT CHECKED with the reason named, never a
   pass.

   ORDER IS THE VERDICT (fix round 1). One-page mode restores report order: the
   layout records each section's original index and puts every section back in
   that order (`_layouts/post.html` + `assets/js/hl-report-tabs.js`, `mode(true)`),
   so the comparison is ordered. Measured reasons, so nobody re-litigates it:

   - a tab-grouped DOM without an order restore reads 2,870 words out of report
     order on the full-text prototype, because its one-page mode re-appends the
     blocks in the order they were captured, which is tab order. The prototype is
     expected to FAIL this gate for that reason alone; part 1's tagged render is
     the page that must pass.
   - the multiset ("same words, anywhere") verdict let a moved paragraph, a moved
     section and a swapped "not X" PASS, which is what the round-1 review found.

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

   IDS. Every `id` inside the baseline article must exist exactly once in the
   page's article (not only heading ids: the live article carries `cite` and
   `hl-cite-text`, and a heading-only rule let both vanish), must not also be
   carried by a generated `data-rv-chrome` element (that would steal the anchor),
   and the `h2`/`h3` id sequence must equal the baseline's, in order.

   THE 90% FLOOR. If the words left on the page after stripping `data-rv-chrome`
   fall under 90% of the baseline's, the page FAILs even when the strips happen to
   make both sides agree: a chrome mark on an element that holds report text
   removes it from the page only, and without the floor a badly marked panel can
   vanish from the page while the counts still line up.

   PANEL NAMES ARE NEVER READ. The check compares text, counts, ids and id order,
   not panel ids, so it is indifferent to the prototype's bare tokens and the
   build's `tab-` prefix.

   CONTROLS. `--control` deletes one paragraph from the body of the page under
   test and requires FAIL with exactly that paragraph's word count missing.
   `--control-teardown` deletes one paragraph INSIDE a CLOSED
   `details.hl-teardown` and requires the same: text inside a closed details is
   still read by `textContent`, and the control proves the gate sees it. A control
   whose known positive does not fire is NOT CHECKED, never PASS. If the page has
   no closed teardown, `--control-teardown` is NOT CHECKED with that reason rather
   than silently deleting from an open one.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. With a control the mutated page's verdict
   is printed and the exit code follows that verdict (1), as the gate would for a
   real loss; the CONTROL line says whether the control fired as designed.

   Run: node check-report-text.js --baseline <url-or-file> --page <url-or-file>
          [--width 1280,390] [--control] [--control-teardown]
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

/* One round trip per document. Removes what the layout adds, then reads the
   text, counts, ids and id order from the same DOM state, so a strip cannot be
   reported against a different tree than the one that was measured. */
var EXTRACT_JS = '(function(){' +
  'var root=document.querySelector(".hl-post-content")||document.querySelector("main")||document.body;' +
  'if(!root)return JSON.stringify({error:"no article root"});' +
  'var chrome=0,chromeIds=[];' +
  '[].slice.call(root.querySelectorAll("[data-rv-chrome]")).forEach(function(e){' +
  'if(e.id)chromeIds.push(e.id);' +
  '[].slice.call(e.querySelectorAll("[id]")).forEach(function(x){if(x.id)chromeIds.push(x.id);});' +
  'if(e.parentNode){e.parentNode.removeChild(e);chrome++;}});' +
  '[].slice.call(root.querySelectorAll("script,style,title")).forEach(function(e){' +
  'if(e.parentNode)e.parentNode.removeChild(e);});' +
  'var seen={},chromeUnique=chromeIds.filter(function(id){if(seen[id])return false;seen[id]=1;return true;});' +
  'var counts={};' +
  COUNTS_JSON + '.forEach(function(p){counts[p[0]]=root.querySelectorAll(p[1]).length;});' +
  'var all=[].slice.call(root.querySelectorAll("[id]"));' +
  'var ids=all.map(function(e){return e.id;}).filter(Boolean);' +
  // The h2/h3 sequence is the report's section order, which one-page mode restores.
  'var idSeq=[].slice.call(root.querySelectorAll("h2[id],h3[id]")).map(function(h){return h.id;});' +
  'var text=(root.textContent||"").replace(/\\s+/g," ").trim();' +
  'var where=root.tagName.toLowerCase()+(root.id?"#"+root.id:"")+' +
  '(root.className?"."+String(root.className).split(" ")[0]:"");' +
  'return JSON.stringify({text:text,counts:counts,ids:ids,idSeq:idSeq,chromeIds:chromeUnique,' +
  'root:where,chrome:chrome,href:location.href,' +
  'words:text?text.split(" ").length:0,chars:text.length});' +
'})()';

var DELETE_PARA_JS = '(function(){' +
  'var root=document.querySelector(".hl-post-content")||document.querySelector("main")||document.body;' +
  'var ps=[].slice.call(root.querySelectorAll("p"));' +
  'for(var i=0;i<ps.length;i++){' +
  // A paragraph inside generated chrome (a dashboard view's "how counted" line)
  // is not report text: deleting it changes nothing the comparison reads, so the
  // control would not fire and would look like a broken gate.
  'if(ps[i].closest("[data-rv-chrome]"))continue;' +
  'var w=(ps[i].textContent||"").replace(/\\s+/g," ").trim();' +
  'var n=w?w.split(" ").length:0;' +
  'if(n>=20){ps[i].parentNode.removeChild(ps[i]);' +
  'return JSON.stringify({words:n,text:w.slice(0,120)});}}' +
  'return JSON.stringify({words:0,text:null,why:"the page has no report paragraph of 20 words or more"});' +
'})()';

/* The control for text a reader does not see until a teardown is opened. It must
   delete from a CLOSED details, because a gate that only reads rendered text
   would pass without it; textContent reads closed details, and this proves it on
   the real page. `wasOpen` is reported so an open teardown cannot stand in for a
   closed one. */
var DELETE_TEARDOWN_JS = '(function(){' +
  'var root=document.querySelector(".hl-post-content")||document.querySelector("main")||document.body;' +
  'var ds=[].slice.call(root.querySelectorAll("details.hl-teardown"));' +
  'ds=ds.filter(function(d){return !d.closest("[data-rv-chrome]");});' +
  'if(!ds.length)return JSON.stringify({words:0,text:null,why:"the page has no details.hl-teardown"});' +
  'var pick=null,wasOpen=null;' +
  'for(var i=0;i<ds.length;i++){if(!ds[i].open){pick=ds[i];wasOpen=false;break;}}' +
  'if(!pick){pick=ds[0];wasOpen=!!pick.open;}' +
  'var ps=[].slice.call(pick.querySelectorAll("p"));' +
  'for(var j=0;j<ps.length;j++){' +
  'var w=(ps[j].textContent||"").replace(/\\s+/g," ").trim();' +
  'var n=w?w.split(" ").length:0;' +
  'if(n>=20){ps[j].parentNode.removeChild(ps[j]);' +
  'return JSON.stringify({words:n,text:w.slice(0,120),wasOpen:wasOpen});}}' +
  'return JSON.stringify({words:0,text:null,wasOpen:wasOpen,' +
  'why:"the teardown holds no paragraph of 20 words or more"});' +
'})()';

function withOnePage(target) {
  if (/^https?:\/\//.test(target)) return target.replace(/#.*$/, '') + '#one-page';
  var abs = path.resolve(target);
  return url.pathToFileURL(abs).href + '#one-page';
}

/* The ordered word diff is the verdict, so this is the number the gate prints.
   The multiset is kept beside it only to tell "these words are gone" from "these
   words are here but in the wrong place": when the multiset is clean and the
   ordered diff is not, every difference is a move. */
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

/* A word-level ordered diff: the report's words against the page's, in order.
   Common prefix and suffix are trimmed first (cheap, and it makes the identical
   case O(1)), then a Myers diff runs on the middle. Myers is bounded: a pair
   that differs in more than MAX_D places falls back to "the middle is all
   missing and added", flagged `approximate`, because a gate that hangs on a bad
   pair is worse than one that says how it counted. */
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

/* The h2/h3 sequence is the section order one-page mode restores. A moved
   section, a swapped section and a deleted section all show here, whatever the
   word counts say. */
function checkSequence(baselineSeq, pageSeq) {
  if (!baselineSeq || !pageSeq) {
    return ['the h2/h3 id sequence was not measured on ' +
      (!baselineSeq ? 'the baseline' : 'the page') + ', so section order is NOT CHECKED'];
  }
  var i = 0;
  while (i < baselineSeq.length && i < pageSeq.length && baselineSeq[i] === pageSeq[i]) i++;
  if (i === baselineSeq.length && i === pageSeq.length) return [];
  return ['the h2/h3 id sequence differs at position ' + (i + 1) + ': baseline "' +
    (baselineSeq[i] === undefined ? '(end)' : baselineSeq[i]) + '" vs page "' +
    (pageSeq[i] === undefined ? '(end)' : pageSeq[i]) + '" (' + baselineSeq.length +
    ' baseline vs ' + pageSeq.length + ' page)'];
}

function compare(base, page) {
  var aw = base.text ? base.text.split(' ') : [];
  var bw = page.text ? page.text.split(' ') : [];
  var ms = multisetDiff(aw, bw);
  var seq = diffWords(aw, bw);

  /* Words held but not in report order: the multiset agrees and the sequence
     does not, so every difference is a move, not a loss. */
  var reordered = (!ms.missing && !ms.added && (seq.missing || seq.added))
    ? seq.missing + seq.added : 0;

  /* The floor is not a second opinion on the word diff: it is the tripwire for a
     chrome mark on an element that holds report text, which strips that text from
     the page only. Measured against the baseline, never against the page. */
  var floor = Math.ceil(aw.length * 0.9);
  var floorProblem = null;
  if (bw.length < floor) {
    floorProblem = 'the page holds ' + bw.length + ' words after stripping data-rv-chrome, ' +
      (aw.length ? (Math.round((bw.length / aw.length) * 1000) / 10) : 0) + '% of the baseline\'s ' +
      aw.length + ', under the 90% floor (' + floor + ' words): a data-rv-chrome mark on an ' +
      'element that holds report text strips it from the page only';
  }

  var countProblems = [];
  COUNTS.forEach(function (p) {
    var k = p[0];
    if (base.counts[k] !== page.counts[k]) {
      countProblems.push(k + ' ' + base.counts[k] + ' baseline vs ' + page.counts[k] + ' page');
    }
  });

  var idProblems = checkIds(base.ids, page.ids);
  (page.chromeIds || []).forEach(function (id) {
    if (base.ids.indexOf(id) !== -1) {
      idProblems.push('id "' + id + '" is carried by a generated (data-rv-chrome) element, so ' +
        'the link that should reach the report element lands on the layout\'s own control');
    }
  });

  var seqProblems = checkSequence(base.idSeq, page.idSeq);

  var problems = [];
  if (seq.missing || seq.added) {
    problems.push(seq.missing + ' words missing and ' + seq.added + ' added, in report order');
  }
  if (reordered) {
    problems.push(reordered + ' words out of report order: every word is still present, but ' +
      'a paragraph or section sits where the report does not put it');
  }
  if (floorProblem) problems.push(floorProblem);
  countProblems.forEach(function (p) { problems.push('count: ' + p); });
  idProblems.forEach(function (p) { problems.push('id: ' + p); });
  seqProblems.forEach(function (p) { problems.push(p); });

  var pass = problems.length === 0;

  return {
    status: pass ? 'PASS' : 'FAIL',
    problems: problems,
    missing: seq.missing,
    added: seq.added,
    multiset: { missing: ms.missing, added: ms.added },
    missingSample: ms.missingSample,
    addedSample: ms.addedSample,
    reordered: reordered,
    outOfOrder: reordered,
    approximate: seq.approximate,
    ops: seq.ops,
    words: { baseline: aw.length, page: bw.length },
    floor: floor,
    floorProblem: floorProblem,
    chars: { baseline: base.chars, page: page.chars },
    counts: { baseline: base.counts, page: page.counts },
    countProblems: countProblems,
    ids: { baseline: base.ids.length, page: page.ids.length, problems: idProblems },
    idSeq: { baseline: (base.idSeq || []).length, page: (page.idSeq || []).length, problems: seqProblems }
  };
}

function line(r, label) {
  console.log('  ' + label.padEnd(9) + r.words.baseline + ' words, ' + r.chars.baseline +
    ' chars  ->  ' + r.words.page + ' words, ' + r.chars.page + ' chars');
  console.log('  words     missing ' + r.missing + ', added ' + r.added +
    ' (ordered, in report order: a moved paragraph counts as both)' +
    (r.approximate ? '  [APPROXIMATE: the pair differs in more than ' + MAX_D + ' places]' : ''));
  if (r.reordered) {
    console.log('  order     ' + r.reordered + ' words out of report order, FAIL: the words are ' +
      'all present but not where the report puts them (same words: missing ' + r.multiset.missing +
      ', added ' + r.multiset.added + ')');
  }
  console.log('  floor     ' + r.words.page + ' of ' + r.words.baseline + ' words (' +
    (r.words.baseline ? (Math.round((r.words.page / r.words.baseline) * 1000) / 10) : 0) +
    '%), 90% floor is ' + r.floor + ' words');
  var pairs = COUNTS.map(function (p) {
    var k = p[0];
    return k + ' ' + r.counts.page[k] + '/' + r.counts.baseline[k];
  });
  console.log('  counts    page/baseline: ' + pairs.join(', '));
  console.log('  ids       ' + r.ids.page + ' on the page, ' + r.ids.baseline + ' in the baseline, ' +
    (r.ids.problems.length ? r.ids.problems.length + ' problem(s)' : 'all present exactly once'));
  console.log('  sequence  ' + r.idSeq.page + ' h2/h3 ids on the page, ' + r.idSeq.baseline +
    ' in the baseline' +
    (r.idSeq.problems.length ? ', order differs' : ', same ids in the same order'));
  r.countProblems.forEach(function (p) { console.log('  COUNT     ' + p); });
  r.ids.problems.forEach(function (p) { console.log('  ID        ' + p); });
  r.idSeq.problems.forEach(function (p) { console.log('  ORDER     ' + p); });
  if (r.floorProblem) console.log('  FLOOR     ' + r.floorProblem);
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
  var controlTeardown = argv.indexOf('--control-teardown') !== -1;

  if (!baselineArg || !pageArg) {
    console.error('usage: node check-report-text.js --baseline <url-or-file> --page <url-or-file> ' +
      '[--width 1280,390] [--control] [--control-teardown]');
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

  var controls = [];
  if (control) controls.push('paragraph');
  if (controlTeardown) controls.push('teardown');

  var all = [];

  /* One browser at a time, each on its own debugging port.

     MEASURED 2026-10-29: opening the baseline and the page in two browsers that
     both defaulted to port 9377 made the second launch attach to the FIRST
     browser's target list, because the first had not finished exiting and the
     port was still held. Both extractions then ran against the same document and
     the check reported a perfect match between a page and itself, which is the
     worst possible false pass. A single monotonic port counter, one port per
     launch, removes the race; the location check below is the tripwire that
     would catch it again.

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
  var portSeq = 9400;
  function nextPort() { portSeq += 1; return portSeq; }

  for (var wi = 0; wi < widths.length; wi++) {
    var width = widths[wi];
    console.log('');
    console.log('== ' + width + 'px ==');

    async function openDoc(target, scripts) {
      var pg;
      try {
        pg = await CDP.open(scripts ? withOnePage(target) : 'about:blank',
          { width: width, height: 1400, port: nextPort(), settle: scripts ? 3000 : 500 });
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
      var bp = await openDoc(baselineArg, false);
      try {
        base = JSON.parse(await bp.evaluate(EXTRACT_JS));
      } finally { bp.close(); }
      if (base.error) { console.log('NOT CHECKED  baseline: ' + base.error); process.exit(2); }

      var pp = await openDoc(pageArg, true);
      try {
        pg = JSON.parse(await pp.evaluate(EXTRACT_JS));
        if (pg.error) { console.log('NOT CHECKED  page: ' + pg.error); process.exit(2); }
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

    /* Each control runs on its own fresh load of the page, because deleting two
       paragraphs from one document would conflate the two known positives. */
    if (controls.length) {
      var ctrl = [];
      for (var ci = 0; ci < controls.length; ci++) {
        var kind = controls[ci];
        var del, rc;
        try {
          var cp = await openDoc(pageArg, true);
          try {
            del = JSON.parse(await cp.evaluate(kind === 'teardown'
              ? DELETE_TEARDOWN_JS : DELETE_PARA_JS));
            if (!del.words) {
              console.log('CONTROL NOT CHECKED  ' + del.why);
              process.exit(2);
            }
            if (kind === 'teardown' && del.wasOpen) {
              console.log('CONTROL NOT CHECKED  the only teardown on the page was already open, so ' +
                'this control cannot show that text inside a CLOSED details is counted');
              process.exit(2);
            }
            rc = compare(base, JSON.parse(await cp.evaluate(EXTRACT_JS)));
          } finally { cp.close(); }
        } catch (e) {
          console.log('NOT CHECKED  ' + String(e.message || e).split('\n')[0]);
          process.exit(2);
        }

        line(rc, 'control');
        /* The control must lose exactly the deleted paragraph and nothing else.
           Measured against the clean run on the same page, not against zero:
           on a page that already fails order (the prototype's one-page mode
           re-appends blocks in tab order) the absolute count is not the
           paragraph's length, but the DELTA is. When the ordered diff hits its
           bound, the multiset delta carries the control and says so: a deleted
           contiguous paragraph adds exactly its word count to `missing` there,
           where the ordered diff can no longer localise it. */
        var byMultiset = rc.approximate;
        var beforeMissing = byMultiset ? r.multiset.missing : r.missing;
        var beforeAdded = byMultiset ? r.multiset.added : r.added;
        var afterMissing = byMultiset ? rc.multiset.missing : rc.missing;
        var afterAdded = byMultiset ? rc.multiset.added : rc.added;
        var fired = rc.status === 'FAIL' &&
          afterMissing === beforeMissing + del.words && afterAdded === beforeAdded;
        console.log('  CONTROL   [' + kind + '] deleted a ' + del.words + '-word paragraph ' +
          (kind === 'teardown' ? 'inside a CLOSED details.hl-teardown' : 'from the body') +
          ' ("' + String(del.text).slice(0, 60) + '..."): verdict ' + rc.status + ', ' +
          afterMissing + ' missing (' + beforeMissing + ' before the delete), ' + afterAdded +
          ' added  ->  ' + (fired ? 'FIRED' : 'DID NOT FIRE') +
          (byMultiset ? '  [word order was already out by more than ' + MAX_D +
            ' places, so the control is read on the word counts]' : ''));
        if (!fired) {
          console.log('NOT CHECKED  the control did not fire: this check cannot be trusted on this pair');
          process.exit(2);
        }
        rc.control = { kind: kind, deleted: del.words, fired: true };
        ctrl.push(rc);
      }
      r = ctrl[ctrl.length - 1];
      r.controls = ctrl.map(function (c) { return c.control; });
    }

    all.push({ width: width, r: r });
  }

  var failed = all.filter(function (a) { return a.r.status !== 'PASS'; });
  console.log('');
  console.log((failed.length ? 'FAIL' : 'PASS') + '  ' +
    (failed.length
      ? failed.map(function (a) { return a.width + 'px: ' + a.r.missing + ' missing, ' +
          a.r.added + ' added' +
          (a.r.reordered ? ', ' + a.r.reordered + ' out of order' : '') +
          (a.r.controls ? ' (control: ' + a.r.controls.map(function (c) {
            return c.kind + ' ' + c.deleted + ' words';
          }).join(', ') + ')' : ''); }).join('; ')
      : 'every word, in order, every count, every id and the h2/h3 sequence matches at ' +
        all.map(function (a) { return a.width + 'px'; }).join(' and ')));
  process.exit(failed.length ? 1 : 0);
}

module.exports = {
  COUNTS: COUNTS,
  EXTRACT_JS: EXTRACT_JS,
  DELETE_PARA_JS: DELETE_PARA_JS,
  DELETE_TEARDOWN_JS: DELETE_TEARDOWN_JS,
  diffWords: diffWords,
  multisetDiff: multisetDiff,
  checkIds: checkIds,
  checkSequence: checkSequence,
  compare: compare,
  withOnePage: withOnePage,
  MAX_D: MAX_D
};

if (require.main === module) {
  main().catch(function (e) {
    console.log('NOT CHECKED  ' + String(e.message || e).split('\n')[0]);
    process.exit(2);
  });
}
