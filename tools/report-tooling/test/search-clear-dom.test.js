'use strict';

/* T-0552: DOM test for assets/js/search-clear.js, the clear (X) button on every site search box.
   Real markup shapes: a listing filter (.hl-d-search wrapper), the navbar form, a script-added
   ATT&CK table box, and a Pagefind box that must be left alone. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var SCRIPT = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'search-clear.js'), 'utf8');

function page() {
  var dom = new JSDOM('<body>' +
    '<form class="hl-nav__search"><label for="hl-nav-q">s</label><input class="hl-nav__search-input" id="hl-nav-q" type="search"></form>' +
    '<div class="hl-filter" data-listing-filter><div class="hl-d-search"><input class="hl-filter__search" type="text"></div></div>' +
    '<div class="hl-atk-tools" id="tools"></div>' +
    '<div id="hl-search"><input class="pagefind-ui__search-input" type="text"></div>' +
    '<textarea class="hl-iocsearch__in"></textarea>' +
    '</body>', { runScripts: 'outside-only', pretendToBeVisual: true });
  return ready(dom);
}
function ready(dom) {
  return new Promise(function (res) {
    function go() { dom.window.eval(SCRIPT); res(dom.window); }
    if (dom.window.document.readyState === 'loading') dom.window.document.addEventListener('DOMContentLoaded', go);
    else go();
  });
}
function typeInto(w, input, v) {
  input.value = v;
  input.dispatchEvent(new w.Event('input', { bubbles: true }));
}

test('a button appears on the navbar box and the listing box, not on Pagefind or the textarea', async function () {
  var w = await page(), d = w.document;
  assert.equal(d.querySelectorAll('.hl-clr__btn').length, 2);
  assert.ok(d.querySelector('.hl-nav__search > .hl-clr__btn--nav'), 'nav button is the sibling of the box inside the form');
  assert.ok(d.querySelector('.hl-d-search > .hl-clr > .hl-filter__search + .hl-clr__btn'), 'listing box wrapped, button after it');
  assert.equal(d.querySelectorAll('#hl-search button').length, 0);
  assert.equal(d.querySelector('.hl-iocsearch__in').parentNode.tagName, 'BODY');
});

test('the button is a real button with the label, hidden while empty, shown with text', async function () {
  var w = await page(), d = w.document;
  var box = d.querySelector('.hl-filter__search'), btn = d.querySelector('.hl-d-search .hl-clr__btn');
  assert.equal(btn.tagName, 'BUTTON');
  assert.equal(btn.getAttribute('type'), 'button');
  assert.equal(btn.getAttribute('aria-label'), 'Clear search');
  assert.equal(btn.hidden, true);
  typeInto(w, box, 'lazarus');
  assert.equal(btn.hidden, false);
  assert.ok(box.parentNode.classList.contains('is-filled'));
  typeInto(w, box, '');
  assert.equal(btn.hidden, true);
  assert.ok(!box.parentNode.classList.contains('is-filled'));
});

test('click empties the box, fires input (bubbling) and returns focus to the box', async function () {
  var w = await page(), d = w.document;
  var box = d.querySelector('.hl-filter__search'), btn = d.querySelector('.hl-d-search .hl-clr__btn');
  var seen = 0, seenValue = null;
  d.querySelector('.hl-filter').addEventListener('input', function (e) { seen++; seenValue = e.target.value; });
  typeInto(w, box, 'lazarus');
  seen = 0;
  btn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.equal(box.value, '');
  assert.equal(seen, 1, 'one input event reached the filter');
  assert.equal(seenValue, '');
  assert.equal(d.activeElement, box);
  assert.equal(btn.hidden, true);
});

test('the navbar box clears the same way', async function () {
  var w = await page(), d = w.document;
  var box = d.getElementById('hl-nav-q'), btn = d.querySelector('.hl-clr__btn--nav');
  assert.equal(btn.hidden, true);
  typeInto(w, box, 'cobalt');
  assert.equal(btn.hidden, false);
  assert.ok(d.querySelector('.hl-nav__search').classList.contains('is-filled'));
  btn.click();
  assert.equal(box.value, '');
  assert.equal(d.activeElement, box);
});

test('Escape clears a box that has text and is left alone on an empty box', async function () {
  var w = await page(), d = w.document;
  var box = d.querySelector('.hl-filter__search'), n = 0;
  box.addEventListener('input', function () { n++; });
  var esc = function () { var e = new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }); box.dispatchEvent(e); return e; };
  typeInto(w, box, 'abc');
  n = 0;
  var e1 = esc();
  assert.equal(box.value, '');
  assert.equal(n, 1);
  assert.equal(e1.defaultPrevented, true);
  var e2 = esc();
  assert.equal(n, 1, 'no second input event on an empty box');
  assert.equal(e2.defaultPrevented, false, 'Escape on an empty box is not swallowed');
});

test('a box added by a script later gets a button (the ATT&CK table search)', async function () {
  var w = await page(), d = w.document;
  var s = d.createElement('input');
  s.type = 'search'; s.className = 'hl-atk-search';
  d.getElementById('tools').appendChild(s);
  await new Promise(function (r) { setTimeout(r, 20); });
  var btn = d.querySelector('#tools .hl-clr__btn');
  assert.ok(btn, 'button added');
  assert.equal(btn.hidden, true);
  typeInto(w, s, 'T1059');
  assert.equal(btn.hidden, false);
  btn.click();
  assert.equal(s.value, '');
  assert.equal(d.querySelectorAll('#tools .hl-clr__btn').length, 1, 'enhanced once');
});

test('a box that already has a value starts with the button shown', async function () {
  var dom = new JSDOM('<body><div><input class="hl-filter__search" value="seeded"></div></body>', { runScripts: 'outside-only' });
  var w = await ready(dom);
  assert.equal(w.document.querySelector('.hl-clr__btn').hidden, false);
});

test('the browser-native cancel icon is suppressed on the same boxes (CSS)', function () {
  var css = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'css', 'custom.scss'), 'utf8');
  assert.match(css, /\.hl-clr__in::-webkit-search-cancel-button/);
});
