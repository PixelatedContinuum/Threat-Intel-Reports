'use strict';

/* Tests for the browser gate's own machinery: lib/cdp.js and lib/wire-harness.js.

   These do NOT drive a browser. Driving one is check-browser-wire.js, and its
   value is precisely that it does what no test in this repo could. What is
   testable here is the part that decides whether a run happened at all, and the
   part that builds the page under test.

   Both matter for the same reason. A browser gate that quietly reports success
   when it never found a browser, or that builds a page missing the theme
   stylesheet, is worse than no gate: it converts an unverified claim into a
   green tick. See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var CDP = require('../lib/cdp.js');
var WH = require('../lib/wire-harness.js');
var JSDOM = require('jsdom').JSDOM;

/* ---- findBrowser: the run-or-not decision ---- */

test('an explicit HL_CHROME that exists is used', function () {
  var r = CDP.findBrowser({ HL_CHROME: '/opt/my-chrome' }, function (p) { return p === '/opt/my-chrome'; });
  assert.equal(r.path, '/opt/my-chrome');
  assert.equal(r.error, undefined);
});

test('an HL_CHROME that does not exist is an error, not a fallback', function () {
  /* Falling through to the scan would serve a DIFFERENT browser than the one
     asked for and report the result as if it were that build. */
  // The scenario that matters: the named binary is absent while a candidate on
  // the scan list IS present, so a fallback would silently succeed.
  var r = CDP.findBrowser({ HL_CHROME: '/opt/missing' },
    function (p) { return p !== '/opt/missing'; });
  assert.equal(r.path, undefined);
  assert.match(r.error, /HL_CHROME points at \/opt\/missing/);
});

test('with no env set, a present candidate is found', function () {
  var r = CDP.findBrowser({}, function (p) { return /chrome|chromium/i.test(p); });
  assert.ok(r.path, 'expected a candidate path');
});

test('no browser anywhere reports an error naming the remedy', function () {
  var r = CDP.findBrowser({}, function () { return false; });
  assert.equal(r.path, undefined);
  assert.match(r.error, /HL_CHROME/);
});

test('open() throws a NOT CHECKED error rather than failing, when no browser exists', async function () {
  // The distinction the gate-honesty contract turns on: a run that could not
  // happen is not a run that failed.
  var saved = process.env.HL_CHROME;
  process.env.HL_CHROME = '/definitely/not/a/browser/anywhere';
  try {
    await CDP.open('about:blank');
    assert.fail('expected open() to throw');
  } catch (e) {
    assert.equal(e.notChecked, true, 'must be tagged notChecked, so the CLI can exit 2');
    assert.match(e.message, /does not exist/);
  } finally {
    if (saved === undefined) delete process.env.HL_CHROME;
    else process.env.HL_CHROME = saved;
  }
});

/* ---- wire-harness: the page under test ---- */

function liveLike(rowsHtml) {
  return '<html><head>' +
    '<link rel="stylesheet" href="/assets/css/main.css">' +
    '<script src="/assets/js/main.min.js"></script>' +
    '</head><body>' +
    '<div class="hl-filter" data-listing-filter>' +
    '<input class="hl-filter__search" placeholder="Filter headlines…">' +
    '<div class="hl-filter__chips"><button class="hl-chip-btn" data-tag="">All</button></div>' +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden>No headlines match that filter. ' +
    '<button data-filter-reset>Clear filters</button></div>' +
    '</div>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">' + rowsHtml + '</div>' +
    '</body></html>';
}

var ROWS =
  '<div class="hl-wire__day" data-filter-group>Tuesday 18 August 2026</div>' +
  '<a class="hl-wire__item" data-title="one"></a>' +
  '<a class="hl-wire__item" data-title="two"></a>' +
  '<div class="hl-wire__day" data-filter-group>Sunday 16 August 2026</div>' +
  '<a class="hl-wire__item" data-title="three"></a>';

function parts(over) {
  return Object.assign({
    liveHtml: liveLike(ROWS),
    themeCss: 'body{font-size:1.25em}',
    customCss: '.hl-filter__date{display:flex}',
    filterJs: 'window.__ran=1;'
  }, over || {});
}

test('a day heading is parsed into the ISO day the filter compares against', function () {
  assert.equal(WH.headingToDay('Tuesday 18 August 2026'), '2026-08-18');
  assert.equal(WH.headingToDay('Sunday 6 July 2026'), '2026-07-06', 'single-digit day pads');
  assert.equal(WH.headingToDay('not a date'), null);
});

test('every row is tagged with the day of the heading above it', function () {
  var b = WH.build(JSDOM, parts());
  assert.equal(b.rows, 3);
  assert.deepEqual(b.days, ['2026-08-16', '2026-08-18']);
  assert.deepEqual(b.dayCounts, { '2026-08-18': 2, '2026-08-16': 1 });
});

test('a day inside the span with no rows is reported as a gap', function () {
  // The quiet-day empty state has nothing to exercise without one.
  var b = WH.build(JSDOM, parts());
  assert.deepEqual(b.gaps, ['2026-08-17']);
});

test('the harness carries the date control and the empty-message span', function () {
  var b = WH.build(JSDOM, parts());
  assert.match(b.html, /data-filter-date(?![-a-z])/, 'the date input');
  assert.match(b.html, /data-filter-date-clear/, 'the clear control');
  assert.match(b.html, /data-filter-empty-msg/, 'the reason span');
  assert.match(b.html, /Search headlines, topics, actors/, 'the reworded placeholder');
});

test('the theme stylesheet is in the built page, not just custom.css', function () {
  /* Without it the body computes at 16px instead of 20px, `em` and `rem`
     coincide, and the rem check silently stops being able to tell them apart.
     That happened on the first build of this harness. */
  var b = WH.build(JSDOM, parts());
  assert.match(b.html, /body\{font-size:1\.25em\}/, 'theme sheet missing');
  assert.match(b.html, /\.hl-filter__date\{display:flex\}/, 'custom sheet missing');
});

test('the published stylesheets and scripts are swapped out, not left alongside', function () {
  // Leaving them would load the DEPLOYED module over the working-tree one and
  // silently check the wrong code.
  var b = WH.build(JSDOM, parts());
  assert.doesNotMatch(b.html, /<link[^>]+stylesheet/, 'a published stylesheet survived');
  assert.doesNotMatch(b.html, /<script[^>]+src=/, 'a published script survived');
  assert.match(b.html, /window\.__ran=1;/, 'the working-tree module is not present');
});

test('a page with no rows throws rather than reporting an empty pass', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: liveLike('') }));
  }, /rendered no wire rows/);
});

test('a row before any heading throws rather than being tagged with a guess', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: liveLike('<a class="hl-wire__item"></a>') }));
  }, /before any day heading/);
});

test('an unparseable heading throws rather than dropping that day', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({
      liveHtml: liveLike('<div data-filter-group>Some Day</div><a class="hl-wire__item"></a>')
    }));
  }, /unparseable day heading/);
});

test('a page missing the filter bar throws', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: '<html><body><div data-filter-grid></div></body></html>' }));
  }, /no \[data-listing-filter\]|rendered no wire rows/);
});
