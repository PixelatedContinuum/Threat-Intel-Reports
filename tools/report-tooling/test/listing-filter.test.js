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

/* `url` is the page address the module sees at init. It defaults to a real
   https origin rather than jsdom's about:blank because the module mirrors its
   state into the hash with history.replaceState, and about:blank cannot be a
   base for that. A hash on the url is what a shared link looks like. */
function build(html, url) {
  var dom = new JSDOM('<body>' + html + '</body>', {
    runScripts: 'outside-only',
    url: url || 'https://example.test/reports/'
  });
  dom.window.eval(SRC);
  return dom.window;
}

// jsdom queues hashchange as a task after a location.hash assignment, as a
// browser does, so a test that sets the hash waits one turn before asserting.
function tick() {
  return new Promise(function (r) { setTimeout(r, 0); });
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

/* ---- the day axis: /wire/ only ------------------------------------------

   Reader feedback asked to pick a date and see that day. The rows carry the day
   as data-day, which is the SAME string Liquid used to render the heading above
   them, so nothing here parses a timestamp. That is the point of the fixtures
   below: they carry no date field at all, only data-day, so a module that tried
   to derive the day itself would have nothing to derive it from. */

var DATE_ROW =
  '<div class="hl-filter__date">' +
  '<label class="hl-filter__dim" for="d">Date</label>' +
  '<input class="hl-filter__dateinput" type="date" id="d" data-filter-date>' +
  '<button class="hl-filter__datereset" data-filter-date-clear hidden>Clear date</button>' +
  '</div>';

function wireBar(rows) {
  return '<div class="hl-filter hl-filter--wire" data-listing-filter>' +
    '<input class="hl-filter__search">' +
    '<div class="hl-filter__chips">' +
      '<button class="hl-chip-btn is-on" data-tag="">All</button>' +
      '<button class="hl-chip-btn" data-tag="alpha">alpha</button>' +
      '<button class="hl-chip-btn" data-tag="beta">beta</button>' +
    '</div>' + DATE_ROW +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden>' +
      '<span data-filter-empty-msg></span>' +
      '<button data-filter-reset></button>' +
    '</div>' +
    '</div>' + rows;
}

/* 2026-08-09 sits between these two days and carries nothing, mirroring the
   real corpus where one day inside the 30-day window is empty and seven more
   carry one to three items. The quiet-day case is real, not hypothetical. */
var DAYS =
  '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">' +
  '<div class="hl-wire__day" data-filter-group>Monday</div>' +
  '<a class="hl-wire__item" data-title="newest alpha" data-tags="alpha" data-day="2026-08-10"></a>' +
  '<a class="hl-wire__item" data-title="newest beta" data-tags="beta" data-day="2026-08-10"></a>' +
  '<div class="hl-wire__day" data-filter-group>Saturday</div>' +
  '<a class="hl-wire__item" data-title="older alpha" data-tags="alpha" data-day="2026-08-08"></a>' +
  '</div>';

function pick(win, v) {
  var d = win.document.querySelector('[data-filter-date]');
  d.value = v;
  d.dispatchEvent(new win.Event('change', { bubbles: true }));
  return d;
}

function msg(win) {
  return win.document.querySelector('[data-filter-empty-msg]').textContent;
}

test('picking a date narrows to that day and hides the other heading', function () {
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-10');
  assert.equal(visible(win, '.hl-wire__item'), 2);
  assert.equal(visible(win, '[data-filter-group]'), 1);
  assert.equal(win.document.querySelector('[data-filter-count]').textContent,
    'Showing 2 of 3');
});

test('the day is read from data-day, never derived from a timestamp', function () {
  // No row carries a date or datetime attribute, only data-day. A module that
  // parsed its own day out of a timestamp would have nothing to parse.
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-08');
  assert.equal(visible(win, '.hl-wire__item'), 1);
});

test('the day axis ANDs with a tag chip rather than ORing', function () {
  var win = build(wireBar(DAYS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  pick(win, '2026-08-10');
  // alpha AND 10 Aug is one row; OR-ing them would wrongly show three.
  assert.equal(visible(win, '.hl-wire__item'), 1);
});

test('the day axis ANDs with the search box', function () {
  var win = build(wireBar(DAYS));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'beta';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  pick(win, '2026-08-08');
  assert.equal(visible(win, '.hl-wire__item'), 0, 'no beta row on 8 Aug');
});

test('clearing the date restores every row', function () {
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-08');
  assert.equal(visible(win, '.hl-wire__item'), 1);
  click(win, win.document.querySelector('[data-filter-date-clear]'));
  assert.equal(visible(win, '.hl-wire__item'), 3);
  assert.equal(visible(win, '[data-filter-group]'), 2);
});

test('Clear filters clears the date too', function () {
  // Leaving the date set would make the reset look like it had failed.
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-08');
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('[data-filter-reset]'));
  assert.equal(win.document.querySelector('[data-filter-date]').value, '');
  assert.equal(visible(win, '.hl-wire__item'), 3);
});

test('the clear-date control appears only once a date is set', function () {
  var win = build(wireBar(DAYS));
  var c = win.document.querySelector('[data-filter-date-clear]');
  assert.equal(c.hidden, true, 'hidden with no date set');
  pick(win, '2026-08-10');
  assert.equal(c.hidden, false, 'shown once a date is set');
  click(win, c);
  assert.equal(c.hidden, true, 'hidden again after clearing');
});

test('min and max come from the rendered corpus bounds', function () {
  var win = build(wireBar(DAYS));
  var d = win.document.querySelector('[data-filter-date]');
  assert.equal(d.getAttribute('min'), '2026-08-08');
  assert.equal(d.getAttribute('max'), '2026-08-10');
});

test('a quiet day inside the window and a date outside it read differently', function () {
  // Collapsing these into one message teaches the reader the page is broken.
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-09');
  assert.equal(visible(win, '.hl-wire__item'), 0);
  assert.match(msg(win), /quiet some days/);
  assert.match(msg(win), /9 August 2026/, 'names the date the reader picked');

  pick(win, '2026-06-01');
  assert.equal(visible(win, '.hl-wire__item'), 0);
  assert.match(msg(win), /outside the window/);
  assert.match(msg(win), /8 August 2026 to 10 August 2026/, 'states the real bounds');
});

test('the stated window bounds are not shifted by a timezone', function () {
  // `new Date('2026-08-08')` is UTC midnight and renders as the 7th west of
  // Greenwich, which would print a bound the page does not actually hold.
  var win = build(wireBar(DAYS));
  pick(win, '2026-06-01');
  assert.doesNotMatch(msg(win), /7 August/);
  assert.doesNotMatch(msg(win), /11 August/);
});

test('a non-date filter still gets the generic empty message', function () {
  var win = build(wireBar(DAYS));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'nothing-matches-this';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(msg(win), 'No headlines match that filter.');
});

test('a day that HAS rows is never called quiet just because a chip emptied it', function () {
  /* The defect this pins: a date plus a topic chip returning nothing was
     reported as "The Wire is quiet some days" on a date carrying 20 headlines.
     Blame the date only when the date is the cause. Found by looking at a
     screenshot after every machine check had passed. */
  var win = build(wireBar(DAYS));
  pick(win, '2026-08-10');
  // 10 Aug holds two rows, neither of them tagged gamma.
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'gamma';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(visible(win, '.hl-wire__item'), 0);
  assert.equal(msg(win), 'No headlines match that filter.');
  assert.doesNotMatch(msg(win), /quiet/);
});

test('a chip-emptied day still reports quiet when the day is genuinely empty', function () {
  // The narrowing above must not swallow the real quiet-day case.
  var win = build(wireBar(DAYS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  pick(win, '2026-08-09');
  assert.match(msg(win), /quiet some days/);
});

test('the day axis is inert on a page that renders no date control', function () {
  // The four existing listing pages must not gain a phantom third axis, and
  // their cards carry no data-day at all.
  var win = build(bar(CARDS));
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  assert.equal(visible(win, '.hl-catalog-card'), 2);
});

/* ---- URL state: the filter bar is deep-linkable --------------------------

   State is mirrored into the hash (#q=...&tag=a,b&date=YYYY-MM-DD) so a
   filtered view can be shared as a link. The hash is read before the first
   render and written with replaceState on every apply, never pushState, so
   the back button never walks through someone's typing. */

function href(win) { return win.location.href; }

test('a hash present at load applies q, tags and date before the first render', function () {
  var win = build(wireBar(DAYS), 'https://example.test/wire/#q=alpha&tag=alpha&date=2026-08-10');
  assert.equal(win.document.querySelector('.hl-filter__search').value, 'alpha');
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag="alpha"]').classList.contains('is-on'), true);
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag=""]').classList.contains('is-on'), false);
  assert.equal(win.document.querySelector('[data-filter-date]').value, '2026-08-10');
  assert.equal(visible(win, '.hl-wire__item'), 1);
  assert.equal(win.document.querySelector('[data-filter-count]').textContent,
    'Showing 1 of 3');
});

test('a shared link carrying several tags selects each chip', function () {
  var win = build(bar(CARDS), 'https://example.test/reports/#tag=alpha,beta');
  assert.equal(win.document.querySelectorAll('.hl-chip-btn.is-on').length, 2);
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  assert.equal(win.location.hash, '#tag=alpha,beta');
});

test('a tag in the hash with no chip on the page is ignored silently', function () {
  var win = build(bar(CARDS), 'https://example.test/reports/#tag=alpha,nosuchtag');
  assert.equal(win.document.querySelectorAll('.hl-chip-btn.is-on').length, 1);
  assert.equal(visible(win, '.hl-catalog-card'), 2);
  // The write back normalises the hash to what the page can actually honour.
  assert.equal(win.location.hash, '#tag=alpha');
});

test('an encoded search term in the hash is decoded', function () {
  var win = build(bar(CARDS), 'https://example.test/reports/#q=second%20report');
  assert.equal(win.document.querySelector('.hl-filter__search').value, 'second report');
  assert.equal(visible(win, '.hl-catalog-card'), 1);
});

test('a chip click writes the hash and a second click clears it', function () {
  var win = build(bar(CARDS));
  var alpha = win.document.querySelector('.hl-chip-btn[data-tag="alpha"]');
  click(win, alpha);
  assert.equal(win.location.hash, '#tag=alpha');
  click(win, alpha);
  assert.equal(win.location.hash, '');
  assert.equal(href(win), 'https://example.test/reports/', 'no trailing #');
});

test('the All chip clears the hash entirely', function () {
  var win = build(bar(CARDS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="beta"]'));
  assert.equal(win.location.hash, '#tag=alpha,beta');
  click(win, win.document.querySelector('.hl-chip-btn[data-tag=""]'));
  assert.equal(href(win), 'https://example.test/reports/', 'no trailing #');
});

test('the reset button clears the hash entirely', function () {
  var win = build(wireBar(DAYS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  pick(win, '2026-08-10');
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'newest';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(win.location.hash, '#q=newest&tag=alpha&date=2026-08-10');
  click(win, win.document.querySelector('[data-filter-reset]'));
  assert.equal(href(win), 'https://example.test/reports/', 'no trailing #');
});

test('typing in the search box updates the hash, encoded', function () {
  var win = build(bar(CARDS));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'two words & more';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(win.location.hash, '#q=two%20words%20%26%20more');
  s.value = '';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(href(win), 'https://example.test/reports/');
});

test('the kind axis is written as kind= on a page that renders it', function () {
  var win = build(bar(WIRE, KIND_ROW));
  click(win, win.document.querySelector('.hl-chip-btn[data-kind="news"]'));
  assert.equal(win.location.hash, '#kind=news');
});

test('filtering never adds a history entry', function () {
  var win = build(bar(CARDS));
  var before = win.history.length;
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="beta"]'));
  var s = win.document.querySelector('.hl-filter__search');
  s.value = 'x';
  s.dispatchEvent(new win.Event('input', { bubbles: true }));
  assert.equal(win.history.length, before);
});

test('hashchange re-applies the filter from the new hash', async function () {
  var win = build(bar(CARDS));
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  win.location.hash = '#tag=beta';
  await tick();
  assert.equal(visible(win, '.hl-catalog-card'), 2);
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag="beta"]').classList.contains('is-on'), true);
  // Stepping back to the bare page clears everything.
  win.location.hash = '';
  await tick();
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag=""]').classList.contains('is-on'), true);
});

test('a fragment that is not the filter\'s (the skip link) leaves the filter alone', async function () {
  // _layouts/default.html carries <a href="#main">Skip to content</a> on every page.
  var win = build(bar(CARDS));
  click(win, win.document.querySelector('.hl-chip-btn[data-tag="alpha"]'));
  win.location.hash = '#main';
  await tick();
  assert.equal(visible(win, '.hl-catalog-card'), 2, 'the chip filter survives');
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag="alpha"]').classList.contains('is-on'), true);
});

test('a page opened at #main gets the plain first render', function () {
  var win = build(bar(CARDS), 'https://example.test/reports/#main');
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  assert.equal(win.document.querySelector('[data-filter-count]').textContent, 'Showing 3 of 3');
});

/* ---- tag badges on cards apply the matching chip -------------------------

   Badges are spans INSIDE the card link, so a plain click would open the
   entry. Inside a filter grid they filter instead. */

var BADGED =
  '<div class="hl-grid" data-filter-grid>' +
  '<a class="hl-card hl-catalog-card" href="/reports/one/" data-title="first report" data-tags="alpha|gamma">' +
    '<div class="hl-tags"><span class="hl-tag hl-tag--blue">Alpha</span><span class="hl-tag hl-tag--red"> Gamma </span></div></a>' +
  '<a class="hl-card hl-catalog-card" href="/reports/two/" data-title="second report" data-tags="beta">' +
    '<div class="hl-tags"><span class="hl-tag hl-tag--green">Beta</span></div></a>' +
  '<a class="hl-card hl-catalog-card" href="/reports/three/" data-title="third report" data-tags="alpha|beta">' +
    '<div class="hl-tags"><span class="hl-tag hl-tag--blue">Alpha</span><span class="hl-tag hl-tag--green">Beta</span></div></a>' +
  '</div>' +
  '<p><span class="hl-tag hl-tag--blue" id="outside">Alpha</span></p>';

function badgeClick(win, el) {
  var ev = new win.MouseEvent('click', { bubbles: true, cancelable: true });
  el.dispatchEvent(ev);
  return ev;
}

test('badges inside the filter grid get the affordance at init, others do not', function () {
  var win = build(bar(BADGED));
  var inside = win.document.querySelector('[data-filter-grid] .hl-tag');
  assert.equal(inside.classList.contains('hl-tag--clickable'), true);
  assert.equal(inside.getAttribute('title'), 'Filter by this tag');
  assert.equal(inside.hasAttribute('tabindex'), false, 'no focus stop inside a link');
  var outside = win.document.getElementById('outside');
  assert.equal(outside.classList.contains('hl-tag--clickable'), false);
  assert.equal(outside.hasAttribute('title'), false);
});

test('a badge click with a matching chip toggles the chip and does not navigate', function () {
  var win = build(bar(BADGED));
  var reached = 0;
  win.document.addEventListener('click', function () { reached++; });
  var badge = win.document.querySelector('[data-filter-grid] .hl-tag--blue');
  var ev = badgeClick(win, badge);
  assert.equal(ev.defaultPrevented, true, 'the card link must not be followed');
  assert.equal(reached, 0, 'the click stops at the grid');
  assert.equal(win.location.pathname, '/reports/');
  var chip = win.document.querySelector('.hl-chip-btn[data-tag="alpha"]');
  assert.equal(chip.classList.contains('is-on'), true);
  assert.equal(visible(win, '.hl-catalog-card'), 2);
  assert.equal(win.location.hash, '#tag=alpha');
  // A second click toggles it off again, exactly as the chip would.
  badgeClick(win, badge);
  assert.equal(chip.classList.contains('is-on'), false);
  assert.equal(win.document.querySelector('.hl-chip-btn[data-tag=""]').classList.contains('is-on'), true);
  assert.equal(visible(win, '.hl-catalog-card'), 3);
  assert.equal(win.location.hash, '');
});

test('a badge click with no matching chip puts the badge text in the search box', function () {
  // Gamma is on one entry only, so no chip was rendered for it.
  var win = build(bar(BADGED));
  var badge = win.document.querySelector('[data-filter-grid] .hl-tag--red');
  var ev = badgeClick(win, badge);
  assert.equal(ev.defaultPrevented, true);
  assert.equal(win.document.querySelector('.hl-filter__search').value, 'Gamma', 'trimmed');
  assert.equal(visible(win, '.hl-catalog-card'), 1);
  assert.equal(win.location.hash, '#q=Gamma');
  assert.equal(win.document.querySelectorAll('.hl-chip-btn.is-on').length, 1, 'only All stays on');
});

test('a click on the card itself, not a badge, is left to the browser', function () {
  var win = build(bar(BADGED));
  var ev = badgeClick(win, win.document.querySelector('[data-filter-grid] .hl-catalog-card'));
  assert.equal(ev.defaultPrevented, false);
});

/* ---- the veto is not URL state ------------------------------------------- */

test('data-veto cards stay hidden whatever the hash says, and the hash never mentions veto', function () {
  var win = build(bar(CARDS), 'https://example.test/ioc-feeds/#tag=alpha&veto=0');
  assert.equal(visible(win, '.hl-catalog-card'), 2);
  assert.equal(win.location.hash, '#tag=alpha', 'a foreign key is dropped on write');
  // ioc-search.js marks a card and asks for a re-apply.
  win.document.querySelector('.hl-catalog-card[data-title="first report"]').setAttribute('data-veto', '1');
  win.document.dispatchEvent(new win.CustomEvent('hl:refilter'));
  assert.equal(visible(win, '.hl-catalog-card'), 1);
  assert.doesNotMatch(win.location.hash, /veto/);
  assert.equal(win.location.hash, '#tag=alpha');
  // A hash edit re-applies the filter but cannot lift the veto.
  win.location.hash = '#tag=alpha,beta';
  return tick().then(function () {
    assert.equal(visible(win, '.hl-catalog-card'), 2, 'third plus second; first stays vetoed');
    assert.doesNotMatch(win.location.hash, /veto/);
  });
});
