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
