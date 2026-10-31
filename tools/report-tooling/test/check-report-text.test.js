'use strict';

/* Unit tests for the completeness gate's decision logic (fix round 1).

   The verdict is ORDERED now: one-page mode restores report order, so a moved
   paragraph, a moved section and swapped words all FAIL. These tests pin that,
   plus the id rules (every article id exactly once, the h2/h3 sequence, no
   generated element stealing an anchor) and the 90% floor. Driving a real
   browser is `check-report-text.js` itself; the CLI runs against the round-1
   mutants are recorded in tasks/runs/T-0500.1/build/p2-report.md. */

var test = require('node:test');
var assert = require('node:assert');
var C = require('../check-report-text.js');

function words(s) { return s.split(' '); }

var ZERO_COUNTS = { headings: 1, tables: 0, rows: 0, figures: 0, images: 0,
  teardowns: 0, details: 0, 'code blocks': 0, links: 0, lists: 0 };

function page(over) {
  var p = {
    text: 'a b c', chars: 5, counts: JSON.parse(JSON.stringify(ZERO_COUNTS)),
    ids: ['x'], idSeq: ['x'], chromeIds: [],
    hidden: { words: 0, nodes: 0, samples: [], noBoxWords: 0, noBoxNodes: 0,
              noBoxSamples: [], collapsedWords: 0 }
  };
  Object.keys(over || {}).forEach(function (k) { p[k] = over[k]; });
  return p;
}

test('identical text has nothing missing and nothing added', function () {
  var d = C.diffWords(words('a b c'), words('a b c'));
  assert.deepStrictEqual([d.missing, d.added], [0, 0]);
});

test('a deleted paragraph is counted as missing, word for word', function () {
  var d = C.diffWords(words('one two three four five six seven'), words('one two six seven'));
  assert.strictEqual(d.missing, 3);
  assert.strictEqual(d.added, 0);
});

test('an inserted word is counted as added, not as a loss', function () {
  var d = C.diffWords(words('one two three'), words('one two new three'));
  assert.strictEqual(d.missing, 0);
  assert.strictEqual(d.added, 1);
});

test('an identical page PASSes', function () {
  var r = C.compare(page({ text: 'a b c' }), page({ text: 'a b c' }));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.missing, 0);
  assert.strictEqual(r.multiset.missing, 0);
});

/* Round-1 review, mutant A (scratch/mutants/A-moved.html): a 134-word paragraph
   moved to the end of main PASSed the multiset gate. It must FAIL now. */
test('a moved paragraph FAILS, and the multiset shows nothing was lost', function () {
  var base = page({ text: 'alpha beta gamma delta epsilon zeta eta theta' });
  var moved = page({ text: 'alpha beta delta epsilon zeta eta theta gamma' });
  var r = C.compare(base, moved);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.multiset.missing, 0);
  assert.strictEqual(r.multiset.added, 0);
  assert.ok(r.missing > 0 && r.added > 0, 'a move is missing and added in report order');
  assert.ok(r.reordered > 0);
  assert.match(r.problems.join(' '), /out of report order/);
});

/* Round-1 review, mutant C (scratch/mutants/C-swapped.html): "may or may not be
   the same actor" became "may or may be not the same actor". Same multiset. */
test('words swapped inside a paragraph FAIL, though the word counts agree', function () {
  var base = page({ text: 'a may or may not be the same actor z' });
  var swapped = page({ text: 'a may or may be not the same actor z' });
  var r = C.compare(base, swapped);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.multiset.missing, 0);
  assert.strictEqual(r.multiset.added, 0);
  assert.ok(r.missing > 0 && r.added > 0);
});

test('a moved section FAILS on the h2/h3 sequence as well as the words', function () {
  var base = page({ text: 'a b c d e f', idSeq: ['s1', 's2', 's3'], ids: ['x', 's1', 's2', 's3'] });
  var swapped = page({ text: 'a b c d e f', idSeq: ['s1', 's3', 's2'], ids: ['x', 's1', 's2', 's3'] });
  var r = C.compare(base, swapped);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.idSeq.problems.length, 1);
  assert.match(r.idSeq.problems[0], /position 2/);
});

test('the id sequence must be measured on both sides, or the run is a FAIL', function () {
  var base = page({});
  var noSeq = page({ idSeq: undefined });
  var r = C.compare(base, noSeq);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.idSeq.problems.join(' '), /not measured/);
});

test('a dropped non-heading id (cite) FAILS; ids are not only headings', function () {
  var base = page({ text: 'a b c', ids: ['heading', 'cite', 'hl-cite-text'], idSeq: ['heading'] });
  var dropped = page({ text: 'a b c', ids: ['heading'], idSeq: ['heading'] });
  var r = C.compare(base, dropped);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.ids.problems.join(' '), /id "cite" is missing/);
  assert.match(r.ids.problems.join(' '), /id "hl-cite-text" is missing/);
});

test('every baseline id must be present exactly once', function () {
  assert.deepStrictEqual(C.checkIds(['a', 'b'], ['a', 'b', 'c']), []);
  assert.match(C.checkIds(['a'], ['b']).join(' '), /"a" is missing/);
  assert.match(C.checkIds(['a'], ['a', 'a']).join(' '), /appears 2 times/);
});

test('a duplicate id on the page is a problem even when every baseline id exists', function () {
  var p = C.checkIds(['a', 'b'], ['a', 'b', 'b']);
  assert.strictEqual(p.length, 1);
  assert.match(p[0], /"b" appears 2 times/);
});

test('a generated element carrying a baseline id FAILS, because it steals the anchor', function () {
  var base = page({ ids: ['cite', 'one'], idSeq: ['one'] });
  var pg = page({ ids: ['cite', 'one'], idSeq: ['one'], chromeIds: ['cite'] });
  var r = C.compare(base, pg);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.ids.problems.join(' '), /data-rv-chrome/);
});

test('under 90% of the baseline words FAILs even when the counts line up', function () {
  var base = page({ text: Array(100).fill('w').join(' '), chars: 199 });
  var short = page({ text: Array(80).fill('w').join(' '), chars: 159 });
  var r = C.compare(base, short);
  assert.strictEqual(r.status, 'FAIL');
  assert.ok(r.floorProblem);
  assert.match(r.floorProblem, /under the 90% floor/);
  assert.strictEqual(r.floor, 90);
});

test('exactly 90% of the baseline words is not a floor failure by itself', function () {
  var base = page({ text: Array(100).fill('w').join(' ') });
  var edge = page({ text: Array(90).fill('w').join(' ') });
  assert.strictEqual(C.compare(base, edge).floorProblem, null);
});

test('case-sensitivity: the h2/h3 sequence is exactly equal, not a prefix', function () {
  assert.deepStrictEqual(C.checkSequence(['a', 'b'], ['a', 'b']), []);
  assert.match(C.checkSequence(['a', 'b'], ['a']).join(' '), /position 2/);
  assert.match(C.checkSequence(['a'], ['a', 'b']).join(' '), /position 2/);
});

test('withOnePage keeps a URL and a path addressable, and adds the fragment once', function () {
  assert.strictEqual(C.withOnePage('https://example.org/r/x/'), 'https://example.org/r/x/#one-page');
  assert.strictEqual(C.withOnePage('https://example.org/r/x/#tab-chain'), 'https://example.org/r/x/#one-page');
  assert.match(C.withOnePage('/tmp/a b/report.html'), /^file:\/\/.*a%20b\/report\.html#one-page$/);
});

test('compare FAILs on a count or id difference as well as on words', function () {
  var base = page({ text: 'a b c' });
  var ok = C.compare(base, page({ text: 'a b c' }));
  assert.strictEqual(ok.status, 'PASS');

  var fewer = page({ text: 'a b c' });
  fewer.counts.tables = 1;
  assert.match(C.compare(base, fewer).countProblems.join(' '), /tables 0 baseline vs 1 page/);

  var noId = page({ text: 'a b c', ids: [], idSeq: [] });
  assert.match(C.compare(base, noId).ids.problems.join(' '), /"x" is missing/);
});

test('the extraction script strips chrome and reads every id and the h2/h3 sequence', function () {
  var js = C.EXTRACT_JS;
  assert.match(js, /data-rv-chrome/);
  assert.match(js, /script,style,title/);
  assert.match(js, /hl-post-content/);
  assert.match(js, /querySelectorAll\("\[id\]"\)/, 'every id must be read, not only headings');
  assert.match(js, /h2\[id\],h3\[id\]/, 'the section order comes from the h2/h3 ids');
  assert.match(js, /chromeIds/, 'ids inside generated chrome are reported');
  // The check must not depend on any panel id, bare token or tab- prefix.
  assert.ok(!/tab-/.test(js), 'EXTRACT_JS must not read panel ids');
});

test('the body control deletes report text, never a paragraph inside generated chrome', function () {
  /* MEASURED 2026-10-29 on part 1's render: the first 20+ word <p> in the
     article root was a dashboard view's "how counted" line, which carries
     data-rv-chrome and is stripped before the comparison, so deleting it left
     the verdict PASS and read as a control that did not fire. */
  assert.match(C.DELETE_PARA_JS, /closest\("\[data-rv-chrome\]"\)/);
  assert.match(C.DELETE_TEARDOWN_JS, /closest\("\[data-rv-chrome\]"\)/);
});

test('the teardown control targets a closed details.hl-teardown and says when none is closed', function () {
  var js = C.DELETE_TEARDOWN_JS;
  assert.match(js, /details\.hl-teardown/);
  assert.match(js, /\.open/);
  assert.match(js, /wasOpen/);
});

/* Round-2 review F1: `textContent` counted text the reader cannot see, so the
   H1 (one table hidden) and H2 (one whole h2 section hidden) mutants PASSed the
   full verdict at 7b422d4 while hiding 307 and 730 article words. Both must FAIL
   now, and the message must name the words and the hiding element. */

test('H1: a hidden table FAILS even though every word is still in textContent', function () {
  var base = page({ text: 'a b c' });
  var mut = page({ hidden: { words: 307, nodes: 28,
    samples: ['table [hidden] display=none visibility=visible :: Risk Dimension'],
    noBoxWords: 0, noBoxNodes: 0, noBoxSamples: [], collapsedWords: 6192 } });
  var r = C.compare(base, mut);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.missing, 0, 'no word is missing: the words are hidden, not gone');
  assert.strictEqual(r.added, 0);
  assert.match(r.problems.join(' '), /307 words are hidden from the reader/);
  assert.match(r.problems.join(' '), /\[hidden\]/);
});

test('H2: a hidden h2 section FAILS, and the closed-teardown words stay exempt', function () {
  var base = page({ text: 'a b c' });
  var mut = page({ hidden: { words: 730, nodes: 49,
    samples: ['p [hidden] display=none visibility=visible :: Three hosted servers carry the operation'],
    noBoxWords: 0, noBoxNodes: 0, noBoxSamples: [], collapsedWords: 6192 } });
  var r = C.compare(base, mut);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /730 words are hidden/);
});

test('text with no rendered box FAILS as well: a clipped or zero-size box hides as surely', function () {
  var r = C.compare(page({ text: 'a b c' }), page({ hidden: {
    words: 0, nodes: 0, samples: [], noBoxWords: 12, noBoxNodes: 1,
    noBoxSamples: ['span :: a clipped sentence'], collapsedWords: 0 } }));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /12 words have no rendered box/);
});

test('words inside a CLOSED details body are exempt by design and do not FAIL', function () {
  var r = C.compare(page({ text: 'a b c' }), page({ hidden: {
    words: 0, nodes: 0, samples: [], noBoxWords: 0, noBoxNodes: 0, noBoxSamples: [],
    collapsedWords: 6192 } }));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('a page whose visibility was never measured FAILs rather than passing silently', function () {
  var p = page({});
  delete p.hidden;
  var r = C.compare(page({}), p);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /visibility was not measured/);
});

test('the extraction script measures visibility per text node and exempts closed teardowns', function () {
  var js = C.EXTRACT_JS;
  assert.match(js, /NodeFilter\.SHOW_TEXT/, 'each text node is measured, not the element tree');
  assert.match(js, /getComputedStyle/);
  assert.match(js, /visibility==="hidden"/);
  assert.match(js, /display==="none"/);
  assert.match(js, /DETAILS/);
  assert.match(js, /getClientRects/, 'a text node with no non-zero box is reported too');
  assert.match(js, /hidden:\{words:/, 'the verdict reads the measurement');
});

/* T-0500.1.11 fix5a: widget chrome. The extraction script is run over real markup (jsdom evaluates the scripts of the include widgets' own classes, a stylesheet
   hides the toggle label the way the site's does, and a Range reports one box so a rendered node is not read as boxless). */
var JSDOM = require('jsdom').JSDOM;
function extract(bodyHtml, css) {
  var dom = new JSDOM('<!doctype html><style>' + (css || '') + '</style><body><div class="hl-post-content">' + bodyHtml + '</div></body>', { runScripts: 'outside-only' });
  dom.window.Range.prototype.getClientRects = function () { return [{ width: 10, height: 10 }]; };
  var out = JSON.parse(dom.window.eval(C.EXTRACT_JS));
  return { out: out, win: dom.window, dom: dom };
}
var IM = '<details class="im-card"><summary><span class="im-toggle" aria-hidden="true"><span class="im-toggle-text im-toggle-text--closed">Open for details</span>' +
  '<span class="im-toggle-text im-toggle-text--open">Close details</span></span></summary><div class="im-detail"><p class="im-why">The service runs as a system task and survives every reboot of the host.</p></div></details>';
var CX = '<details><summary><span class="cx-toggle" aria-hidden="true"><span class="cx-toggle-text cx-toggle-text--closed">Open for evidence and limit</span><span class="cx-toggle-text cx-toggle-text--open">Close</span></span></summary></details>';
var HIDE_OPEN = '.im-toggle-text--open, .cx-toggle-text--open { display: none; }';
test('the hidden state label of an install-modes or capability-axes toggle is widget chrome, not hidden text; both are counted', function () {
  var e = extract(IM + CX, HIDE_OPEN).out;
  assert.strictEqual(e.hidden.words, 0);
  assert.strictEqual(e.widget.labelWords, 3, '"Close details" is 2 words, "Close" is 1');
  assert.strictEqual(e.widget.labelNodes, 2);
  assert.match(e.text, /Close details/, 'the words stay in the text: the baseline holds them too, so the word diff balances');
  assert.strictEqual(C.compare(page({ text: e.text }), page({ text: e.text, hidden: e.hidden, widget: e.widget })).status, 'PASS');
});
test('control: a real sentence hidden inside the same widget still FAILs, whatever the toggle labels do', function () {
  var e = extract(IM.replace('<p class="im-why">', '<p class="im-why" style="display:none">'), HIDE_OPEN).out;
  assert.strictEqual(e.hidden.words, 14);
  assert.strictEqual(e.widget.labelWords, 2);
  var r = C.compare(page({ text: e.text }), page({ text: e.text, hidden: e.hidden }));
  assert.strictEqual(r.status, 'FAIL'); assert.match(r.problems.join(' '), /14 words are hidden/);
});
test('the label exemption is the widget\'s markup, not the word: "Close details" hidden outside an aria-hidden toggle, or in a span of the same class outside .im-toggle, FAILs', function () {
  var e1 = extract('<p style="display:none">Close details</p>', '').out;
  assert.strictEqual(e1.hidden.words, 2);
  var e2 = extract('<span class="im-toggle-text im-toggle-text--open">Close details</span>', HIDE_OPEN).out;
  assert.strictEqual(e2.hidden.words, 2, 'a label class on its own, outside .im-toggle[aria-hidden=true], is not the widget');
  var e3 = extract('<span class="im-toggle"><span class="im-toggle-text im-toggle-text--open">Close details</span></span>', HIDE_OPEN).out;
  assert.strictEqual(e3.hidden.words, 2, 'a toggle that is not declared decorative (aria-hidden) is not exempt');
});
var PT = function (extra) { return '<li class="hl-ptree-item"><details class="hl-ptree-node"><summary>proc</summary>\n<div class="pt-detail">\n<p class="pt-why">The loader unpacks the second stage into a temp directory and runs it at once.</p>\n' +
  '<div class="pt-fact"><span class="pt-fact-key">SHA-256</span><code class="pt-fact-val">1afbe5d9</code>' + (extra === undefined ? '<button type="button" class="pt-copy js-only">copy</button>' : extra) + '</div></div></details></li>'; };
test('the process tree\'s runtime copy button is removed before the text is read: the value reads as the baseline reads it', function () {
  var base = extract(PT('')).out, live = extract(PT()).out;
  assert.strictEqual(base.text.endsWith('SHA-2561afbe5d9'), true);
  assert.strictEqual(live.text, base.text);
  assert.strictEqual(live.widget.copyControls, 1);
  assert.strictEqual(C.compare(page({ text: base.text }), page({ text: live.text, widget: live.widget })).status, 'PASS');
});
test('control: a real word missing inside a process-tree node still FAILs, and a "copy" button outside the widget\'s markup is still added text', function () {
  var base = extract(PT('')).out;
  var lost = extract(PT().replace('runs it at once.', 'runs it at')).out;
  var r = C.compare(page({ text: base.text }), page({ text: lost.text, widget: lost.widget }));
  assert.strictEqual(r.status, 'FAIL'); assert.strictEqual(r.missing, 1, 'the word "once." is the one lost');
  var stray = extract(PT('') + '<p>Value <button class="pt-copy">copy</button></p>').out;
  assert.strictEqual(stray.widget.copyControls, 0, 'a pt-copy button outside .hl-ptree-node .pt-fact is not the widget\'s');
  assert.match(stray.text, /Value copy$/);
});
test('the widget controls delete one real word / hide one real sentence INSIDE a widget, and say so when the page has no such sentence', function () {
  var w = extract(PT());
  var del = JSON.parse(w.win.eval(C.DELETE_WIDGET_WORD_JS));
  assert.strictEqual(del.words, 1);
  assert.match(del.text, /^once\./);
  assert.match(JSON.parse(w.win.eval(C.EXTRACT_JS)).text, /runs it at SHA-256/, 'the last word is gone from the page');
  var h = extract(PT());
  var hid = JSON.parse(h.win.eval(C.HIDE_WIDGET_SENTENCE_JS));
  assert.strictEqual(hid.words, 15); assert.strictEqual(hid.hide, true);
  assert.strictEqual(JSON.parse(h.win.eval(C.EXTRACT_JS)).hidden.words, 15);
  var none = extract('<p>A plain paragraph with no widget in it at all, however long it is made.</p>');
  assert.strictEqual(JSON.parse(none.win.eval(C.DELETE_WIDGET_WORD_JS)).words, 0);
  assert.strictEqual(JSON.parse(none.win.eval(C.HIDE_WIDGET_SENTENCE_JS)).words, 0);
});
