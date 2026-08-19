'use strict';

/* Tests for assets/js/listing-filter.js, the filter bar shared by /reports/,
   /hunting-detections/, /ioc-feeds/, /stix/ and /wire/.

   It had no test at all until the Wire needed three things from it: a
   configurable item selector, group headings that hide when emptied, and a
   second filter axis. Each of those is a chance to break four existing pages
   silently, so the first block here pins the single-axis catalog-card behaviour
   those pages rely on.

   jsdom has no layout, so these prove the module SELECTS correctly. Whether the
   result looks right stays a browser check, recorded as NO GATE in the matrix. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var SRC = fs.readFileSync(
  path.join(__dirname, '..', '..', '..', 'assets', 'js', 'listing-filter.js'), 'utf8');

function build(html) {
  var dom = new JSDOM('<body>' + html + '</body>', { runScripts: 'outside-only' });
  dom.window.eval(SRC);
  return dom.window;
}

function click(win, el) {
  el.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
}

function visible(win, sel) {
  return [].slice.call(win.document.querySelectorAll(sel))
    .filter(function (e) { return e.style.display !== 'none'; }).length;
}

function bar(rows, extra) {
  return '<div class="hl-filter" data-listing-filter>' +
    '<input class="hl-filter__search">' +
    (extra || '') +
    '<div class="hl-filter__chips">' +
      '<button class="hl-chip-btn is-on" data-tag="">All</button>' +
      '<button class="hl-chip-btn" data-tag="alpha">alpha</button>' +
      '<button class="hl-chip-btn" data-tag="beta">beta</button>' +
    '</div>' +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden></div>' +
    '</div>' + rows;
}

/* ---- the four existing pages: one axis, catalog cards, no groups ---- */

var CARDS =
  '<div class="hl-grid" data-filter-grid>' +
  '<a class="hl-card hl-catalog-card" data-title="first report" data-tags="alpha"></a>' +
  '<a class="hl-card hl-catalog-card" data-title="second report" data-tags="beta"></a>' +
  '<a class="hl-card hl-catalog-card" data-title="third report" data-tags="alpha|beta"></a>' +
  '</div>';

test('default selector still finds catalog cards with no data-filter-item', function () {
  var win = build(bar(CARDS));
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  assert.equal(win.document.querySelector('[data-filter-count]').textContent,
    'Showing 3 of 3');
});

test('a tag chip narrows the catalog cards', function () {
  var win = build(bar(CARDS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  assert.equal(visible(win, '.hl-catalog-card'), 2);
});

test('search matches title and tags together', function () {
  var win = build(bar(CARDS));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'beta';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(visible(win, '.hl-catalog-card'), 2);
});

test('a page with no group headings is unaffected by group handling', function () {
  var win = build(bar(CARDS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  assert.equal(win.document.querySelectorAll('[data-filter-group]').length, 0);
});

/* ---- the Wire: custom selector, group headings, second axis ---- */

var KIND_ROW =
  '<div class="hl-filter__chips hl-filter__chips--kind">' +
  '<button class="hl-chip-btn is-on" data-kind="">All</button>' +
  '<button class="hl-chip-btn" data-kind="research">Research</button>' +
  '<button class="hl-chip-btn" data-kind="news">News</button>' +
  '</div>';

var WIRE =
  '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">' +
  '<div class="hl-wire__day" data-filter-group>Day one</div>' +
  '<a class="hl-wire__item" data-title="alpha research item" data-tags="alpha" data-kind="research"></a>' +
  '<a class="hl-wire__item" data-title="alpha news item" data-tags="alpha" data-kind="news"></a>' +
  '<div class="hl-wire__day" data-filter-group>Day two</div>' +
  '<a class="hl-wire__item" data-title="beta news item" data-tags="beta" data-kind="news"></a>' +
  '</div>';

test('a custom item selector is honoured', function () {
  var win = build(bar(WIRE, KIND_ROW));
  assert.equal(visible(win, '.hl-wire__item'), 3);
  assert.equal(win.document.querySelector('[data-filter-count]').textContent,
    'Showing 3 of 3');
});

test('a day heading hides when the filter empties it', function () {
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="beta"]'));
  assert.equal(visible(win, '.hl-wire__item'), 1);
  assert.equal(visible(win, '[data-filter-group]'), 1, 'day one should be hidden');
});

test('the kind axis filters on its own', function () {
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="research"]'));
  assert.equal(visible(win, '.hl-wire__item'), 1);
  assert.equal(visible(win, '[data-filter-group]'), 1);
});

test('the two axes AND together rather than OR', function () {
  // alpha AND news is one item; OR-ing them would wrongly show three.
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="news"]'));
  assert.equal(visible(win, '.hl-wire__item'), 1);
});

test('chips within one axis OR together', function () {
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="research"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="news"]'));
  assert.equal(visible(win, '.hl-wire__item'), 3);
});

test('the All chip on one axis clears only that axis', function () {
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="news"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind=""]'));
  assert.equal(visible(win, '.hl-wire__item'), 2, 'the tag filter must survive');
});

test('reset clears both axes and the search box', function () {
  var win = build(bar(WIRE, KIND_ROW).replace('data-filter-empty hidden></div>',
    'data-filter-empty hidden><button data-filter-reset></button></div>'));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="news"]'));
  assert.equal(visible(win, '.hl-wire__item'), 1);
  click(win, win.document.querySelector('[data-filter-reset]'));
  assert.equal(visible(win, '.hl-wire__item'), 3);
  assert.equal(visible(win, '[data-filter-group]'), 2);
});

test('a no-match filter hides every row and every heading', function () {
  var win = build(bar(WIRE, KIND_ROW));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'nothing-matches-this';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(visible(win, '.hl-wire__item'), 0);
  assert.equal(visible(win, '[data-filter-group]'), 0);
  assert.equal(win.document.querySelector('[data-filter-empty]').hidden, false);
});

test('the kind axis is inert on a page that renders no kind chips', function () {
  // The four existing listing pages must not gain a phantom second axis.
  var win = build(bar(CARDS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  assert.equal(visible(win, '.hl-catalog-card'), 2);
});
