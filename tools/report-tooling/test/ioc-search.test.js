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
    '<input class="hl-iocsearch__in">' +
    '<button class="hl-iocsearch__clear" hidden>Clear</button>' +
    '<div class="hl-iocsearch__result"></div>' +
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
  assert.match(resultText(w), /does not look like an IP, domain, URL or hash/);
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
  assert.match(resultText(w), /2 of your 2 indicators/);
});
