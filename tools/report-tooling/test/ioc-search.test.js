'use strict';

/* Tests for the indicator search on /ioc-feeds/.

   The search narrows the EXISTING feed-card grid rather than rendering its own
   result list, which means two scripts share one grid. They cooperate through a
   `data-veto` attribute plus an `hl:refilter` event, because two scripts both
   writing `style.display` would race and the loser would silently win half the
   time.

   jsdom has no layout, so these prove the SELECTION and the cooperation. How it
   looks stays a browser check. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var ROOT = path.join(__dirname, '..', '..', '..');
var CLASSIFY = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'ioc-classify.js'), 'utf8');
var SEARCH = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'ioc-search.js'), 'utf8');
var FILTER = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'listing-filter.js'), 'utf8');

var INDEX = {
  counts: { indicators: 2, reports: 2, multi_report: 1 },
  reports: { alpha: { title: 'Alpha' }, beta: { title: 'Beta' } },
  indicators: {
    'ipv4:185.38.150.7': [{ report: 'alpha', role: 'C2 server' }],
    'domain:shared.test': [{ report: 'alpha' }, { report: 'beta' }]
  }
};

var PAGE =
  '<div class="hl-iocsearch">' +
    '<textarea class="hl-iocsearch__in"></textarea>' +
    '<button class="hl-iocsearch__clear" hidden>Clear</button>' +
    '<div class="hl-iocsearch__result"></div>' +
    '<div class="hl-iocsearch__detail"></div>' +
  '</div>' +
  '<div class="hl-filter" data-listing-filter>' +
    '<input class="hl-filter__search">' +
    '<div class="hl-filter__chips"><button class="hl-chip-btn is-on" data-tag="">All</button></div>' +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden></div>' +
  '</div>' +
  '<div class="hl-grid" data-filter-grid>' +
    '<a class="hl-card hl-catalog-card" data-slug="alpha" data-title="alpha feed" data-tags=""></a>' +
    '<a class="hl-card hl-catalog-card" data-slug="beta" data-title="beta feed" data-tags=""></a>' +
    '<a class="hl-card hl-catalog-card" data-slug="gamma" data-title="gamma feed" data-tags=""></a>' +
  '</div>';

function build() {
  var dom = new JSDOM('<body>' + PAGE + '</body>', { runScripts: 'outside-only' });
  var w = dom.window;
  w.fetch = function () {
    return Promise.resolve({ ok: true, json: function () { return Promise.resolve(INDEX); } });
  };
  w.eval(CLASSIFY);
  w.eval(FILTER);
  w.eval(SEARCH);
  return w;
}

function type(w, value) {
  var input = w.document.querySelector('.hl-iocsearch__in');
  input.value = value;
  input.dispatchEvent(new w.Event('input', { bubbles: true }));
  // The search debounces, then resolves a promise before dispatching refilter.
  return new Promise(function (r) { setTimeout(r, 300); });
}

function visible(w) {
  return [].slice.call(w.document.querySelectorAll('.hl-catalog-card'))
    .filter(function (c) { return c.style.display !== 'none'; })
    .map(function (c) { return c.getAttribute('data-slug'); });
}

function resultText(w) {
  return w.document.querySelector('.hl-iocsearch__result').textContent;
}

test('all cards show before any search', function () {
  var w = build();
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
});

test('a known indicator narrows the grid to its feed', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.deepEqual(visible(w), ['alpha']);
  assert.match(resultText(w), /appears in 1 feed/);
});

test('an indicator in two feeds shows both cards', async function () {
  var w = build();
  await type(w, 'shared.test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /appears in 2 feeds/);
});

test('a defanged paste matches, because that is how people copy indicators', async function () {
  var w = build();
  await type(w, 'shared[.]test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
});

test('an unknown indicator hides nothing and says so plainly', async function () {
  var w = build();
  await type(w, '203.0.113.99');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma'],
    'a miss must not leave the reader with an empty page');
  assert.match(resultText(w), /does not appear in any published feed/);
});

test('text that is not an indicator at all says that, not "no match"', async function () {
  var w = build();
  await type(w, 'the quick brown fox');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.match(resultText(w), /Nothing in that text looks like an IP, domain, URL or hash/);
});

test('clearing the box restores every card', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.deepEqual(visible(w), ['alpha']);
  await type(w, '');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.equal(resultText(w), '');
});

test('the Clear button restores every card', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  var btn = w.document.querySelector('.hl-iocsearch__clear');
  assert.equal(btn.hidden, false, 'Clear appears once there is something to clear');
  btn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
});

test('the name filter and the indicator search AND together', async function () {
  var w = build();
  await type(w, 'shared.test');           // alpha + beta
  var nameBox = w.document.querySelector('.hl-filter__search');
  nameBox.value = 'beta';
  nameBox.dispatchEvent(new w.Event('input', { bubbles: true }));
  assert.deepEqual(visible(w), ['beta'], 'the two controls must narrow, not fight');
});

test('pasting several indicators unions their feeds', async function () {
  var w = build();
  await type(w, '185.38.150.7 and shared.test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 2/);
});

// Built from a code point rather than an escape: a newline written as a
// backslash escape kept getting mangled by the tooling that authored this file.
var NL = String.fromCharCode(10);
var LIST = ['185.38.150.7', 'shared.test', '203.0.113.99'];

function detailText(w) {
  return w.document.querySelector('.hl-iocsearch__detail').textContent;
}

test('a NEWLINE separated list works, which is how lists are actually pasted', async function () {
  // This is the regression. `<input type="text">` strips newlines from pasted
  // content, so a pasted list collapsed into one string; the concatenation once
  // ended in ".test" and was classified as a single domain, reporting a clean
  // "not in any feed" for a list that was mostly real.
  var w = build();
  await type(w, LIST.join(NL));
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a comma separated list works', async function () {
  var w = build();
  await type(w, '185.38.150.7, shared.test, 203.0.113.99');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a list gets a per-indicator breakdown naming each feed', async function () {
  // Narrowing 54 cards to 21 tells someone who pasted 40 indicators nothing
  // about WHICH of theirs matched. For a list, the breakdown is the answer.
  var w = build();
  await type(w, LIST.join(NL));
  var t = detailText(w);
  assert.match(t, /185\.38\.150\.7/, 'names the matched indicator');
  assert.match(t, /Alpha/, 'names the feed it is in');
  assert.match(t, /1 of your indicators are not in any published feed/,
    'and says how many missed');
});

test('a single indicator gets NO breakdown, the card is enough', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.equal(detailText(w), '');
});

test('a messy real-world paste survives quoting and trailing punctuation', async function () {
  var w = build();
  await type(w, 'src="185.38.150.7", host=shared.test;' + NL + '  203.0.113.99  ');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a very large paste is searched in full and never resizes the box', async function () {
  // The box is a fixed height that scrolls internally: a reader cannot see the
  // whole list, but nothing below it moves and every pasted value is searched.
  var w = build();
  var box = w.document.querySelector('.hl-iocsearch__in');
  var before = box.style.height;
  var many = [];
  for (var i = 0; i < 400; i++) many.push('10.9.' + (i >> 8) + '.' + (i & 255));
  many.push('185.38.150.7');          // one real one buried at the end
  await type(w, many.join(NL));
  assert.equal(box.style.height, before, 'the script must never set a height');
  assert.deepEqual(visible(w), ['alpha'], 'the buried real indicator is still found');
  assert.match(resultText(w), /1 of your 401/);
});

test('the breakdown caps rather than building unbounded DOM', async function () {
  var w = build();
  var many = [];
  for (var i = 0; i < 300; i++) many.push('shared.test');   // dedupes to one
  many.push('185.38.150.7');
  await type(w, many.join(NL));
  // extract() dedupes, so this is 2 unique indicators, both real.
  assert.match(resultText(w), /2 of your 2/);
  assert.ok(w.document.querySelectorAll('.hl-iocsearch__row').length <= 202,
    'the breakdown is bounded');
});
