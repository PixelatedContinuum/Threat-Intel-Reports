'use strict';

/* Tests for the two 4a rows p7 added to check-browser-report.js: the tab bar at
   768x1024 and 812x375, and the 44 px count over teardown summaries and the
   in-tab section navigation.

   WHY THESE EXIST. design-v4 4a's "Gates added for mobile" asks for both, and
   the deepseek review of the pilot (review_e74f3dcbe2074ad1) found the gate
   asserted neither: the per-viewport loop skips widths of 700 px and above, and
   the 44 px count covered chrome controls only. A row added to a gate is worth
   nothing until something proves it can FAIL, so every verdict below is driven
   with the measurement a broken layout would produce, not with the good one.

   These do NOT drive a browser. The measurements come from lib/cdp.js at run
   time; what is testable here is the decision made from them, plus one real
   jsdom run of each measurement expression to show that a page with no layout
   (every rect zero) can never satisfy either row. That is the failure mode a
   selector-presence check would have: it would pass on jsdom and pass on a
   page whose bar was never built.

   See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;
var G = require('../check-browser-report.js');

/* ---- the sizes 4a names ------------------------------------------------ */

test('the bar is measured at the two sizes 4a names, not only below 700 px', function () {
  assert.deepEqual(G.TAB_BAR_VIEWPORTS.map(function (v) { return v[0] + 'x' + v[1]; }),
    ['768x1024', '812x375']);
  assert.deepEqual(G.TAB_TARGET_VIEWPORTS.map(function (v) { return v[0] + 'x' + v[1]; }),
    ['390x844', '768x1024']);
});

test('the 44 px floor is 44, not a value that would pass a 43 px target', function () {
  assert.ok(G.MIN_TARGET_PX >= 43.99 && G.MIN_TARGET_PX < 44,
    'a 44 px target measures 43.99.. on a 1x emulation; the floor must sit just under it');
});

/* ---- row A: the tab bar ------------------------------------------------ */

function goodGeom(extra) {
  return Object.assign({
    found: true, w: 120, h: 44, left: 20, right: 140, client: 768,
    rects: 1, clips: [], text: 'Overview'
  }, extra || {});
}

function goodHit() { return { x: 80, y: 40, ok: true, hit: 'SPAN.hl-rv-tab-short' }; }

function goodAfter(token) {
  return { selected: 'tabbtn-' + token, shown: ['tab-' + token] };
}

test('row A passes a tab that is on screen, 44 px high, and selected by the tap', function () {
  var v = G.tabReachVerdict('overview', goodGeom(), goodHit(), goodAfter('overview'));
  assert.equal(v.ok, true, v.why);
  assert.equal(v.why, '');
});

test('row A FAILs a tab that is only 30 px high, naming the tab', function () {
  var v = G.tabReachVerdict('chain', goodGeom({ h: 30 }), goodHit(), goodAfter('chain'));
  assert.equal(v.ok, false);
  assert.match(v.why, /tabbtn-chain/);
  assert.match(v.why, /30 px high/);
  assert.match(v.why, /under 44/);
});

test('row A FAILs a tab clipped by its own bar, naming the clipping box', function () {
  var v = G.tabReachVerdict('confidence', goodGeom({
    left: 600, right: 720, clips: [{ cls: '.hl-rv-tabs', left: 28, right: 328 }]
  }), goodHit(), goodAfter('confidence'));
  assert.equal(v.ok, false);
  assert.match(v.why, /tabbtn-confidence/);
  assert.match(v.why, /clipped by \.hl-rv-tabs \(28\.\.328\)/);
});

test('row A FAILs a tab outside the viewport width', function () {
  var v = G.tabReachVerdict('indicators', goodGeom({ left: 700, right: 900, client: 768 }),
    goodHit(), goodAfter('indicators'));
  assert.equal(v.ok, false);
  assert.match(v.why, /outside the viewport width \(700\.\.900 of 0\.\.768\)/);
});

test('row A FAILs a tab with no box at all, rather than treating presence as rendered', function () {
  var v = G.tabReachVerdict('timeline', goodGeom({ w: 0, h: 0, rects: 0 }), null, null);
  assert.equal(v.ok, false);
  assert.match(v.why, /no box \(0x0\)/);
});

test('row A FAILs when the tap would land on whatever covers the tab, naming it', function () {
  var v = G.tabReachVerdict('victims', goodGeom(),
    { x: 80, y: 40, ok: false, hit: 'HEADER.hl-nav' }, null);
  assert.equal(v.ok, false);
  assert.match(v.why, /would land on HEADER\.hl-nav/);
});

test('row A FAILs a tap that selected a different tab (a click that never arrived)', function () {
  var v = G.tabReachVerdict('attribution', goodGeom(), goodHit(), goodAfter('chain'));
  assert.equal(v.ok, false);
  assert.match(v.why, /selected tabbtn-chain, not tabbtn-attribution/);
});

test('row A FAILs a tap that selected the tab but showed another panel', function () {
  var v = G.tabReachVerdict('timeline', goodGeom(), goodHit(),
    { selected: 'tabbtn-timeline', shown: ['tab-overview'] });
  assert.equal(v.ok, false);
  assert.match(v.why, /shown panel\(s\) were tab-overview, not tab-timeline/);
});

test('row A FAILs a tab id that is not on the page', function () {
  var v = G.tabReachVerdict('overview', { found: false }, null, null);
  assert.equal(v.ok, false);
  assert.match(v.why, /no tab element on the page/);
});

/* ---- row B: teardown summaries and section links ---------------------- */

function target(text, w, h, rects) {
  return { text: text, w: w, h: h, rects: rects === undefined ? 1 : rects };
}

test('row B passes when every measured target is at least 44 by 44, and says how many', function () {
  var rows = [];
  for (var i = 0; i < 14; i++) rows.push(target('Teardown ' + i, 700, 48));
  var v = G.targetRowVerdict(rows, 14, 7);
  assert.equal(v.ok, true, v.detail);
  assert.equal(v.notChecked, false);
  assert.match(v.detail, /^14 of 14 measured across 7 tabs, 0 under 44/);
});

test('row B FAILs a 30 px teardown summary, naming its text and size', function () {
  var rows = [target('The competing hypotheses, why no tracking', 358, 30), target('Other', 358, 48)];
  var v = G.targetRowVerdict(rows, 2, 7);
  assert.equal(v.ok, false);
  assert.match(v.detail, /1 under 44/);
  assert.match(v.detail, /"The competing hypotheses, why no tracking" 358x30/);
});

test('row B FAILs a section link narrower than 44, not only a shorter one', function () {
  var v = G.targetRowVerdict([target('4. Technical Classification', 30, 44)], 1, 7);
  assert.equal(v.ok, false);
  assert.match(v.detail, /30x44/);
});

test('row B FAILs a target it could not render at all, instead of measuring it as fine', function () {
  var v = G.targetRowVerdict([target('Hidden summary', 0, 0, 0)], 1, 7);
  assert.equal(v.ok, false);
  assert.match(v.detail, /not rendered/);
});

test('row B is NOT CHECKED, never a pass, when it measured nothing', function () {
  var v = G.targetRowVerdict([], 0, 7);
  assert.equal(v.notChecked, true);
  assert.equal(v.ok, false);
  assert.match(v.detail, /0 were measured/);
});

test('row B FAILs when the page holds targets no tab panel contained', function () {
  var rows = [target('A', 400, 48), target('B', 400, 48), target('C', 400, 48)];
  var v = G.targetRowVerdict(rows, 5, 7);
  assert.equal(v.ok, false, 'measured 3 of 5 is not a complete count');
  assert.match(v.detail, /3 of 5 measured/);
  assert.match(v.detail, /2 the page holds were not inside any tab panel/);
});

/* ---- the measurement expressions, on a page with no layout ------------

   jsdom has no layout, so every rect is zero. That is exactly the property
   that makes it useful here: if either row could be satisfied by an element
   merely being present, it would be satisfied here. Both must not be. */

var FIXTURE = '<!doctype html><html><body><div class="hl-report-page">' +
  '<nav class="hl-rv-bar"><div class="hl-rv-tabs" role="tablist">' +
  '<button role="tab" id="tabbtn-overview" aria-selected="true">Overview</button>' +
  '</div></nav>' +
  '<section class="hl-rv-panel" id="tab-overview" role="tabpanel">' +
  '<details class="hl-teardown"><summary>The competing hypotheses</summary><p>x</p></details>' +
  '<details class="hl-rv-contents"><summary>In this tab</summary>' +
  '<nav aria-label="In this tab"><a href="#one">1. One</a></nav></details>' +
  '</section></div></body></html>';

function inJsdom(expression) {
  var dom = new JSDOM(FIXTURE, { runScripts: 'outside-only' });
  return JSON.parse(dom.window.eval('JSON.stringify(' + expression + ')'));
}

test('the bar geometry expression returns a real reading, and a layout-less page fails row A', function () {
  var geom = inJsdom(G.tabGeomExpr('tabbtn-overview'));
  assert.equal(geom.found, true, 'the expression must find the tab it was asked for');
  assert.equal(geom.rects, 0);
  var v = G.tabReachVerdict('overview', geom, null, null);
  assert.equal(v.ok, false, 'a tab with no layout must not pass row A');
});

test('the target expression measures the summary and the section link, and zero boxes fail row B', function () {
  var m = inJsdom(G.tabTargetExpr('overview'));
  assert.equal(m.sums.length, 1);
  assert.equal(m.nav.length, 1);
  var v = G.targetRowVerdict(m.sums, 1, 7);
  assert.equal(v.notChecked, false, 'the element was found and measured, even with no box');
  assert.equal(v.ok, false, 'a summary with no box must not pass row B');
});

test('both expressions are wired into the gate, not merely exported', function () {
  var src = fs.readFileSync(path.join(__dirname, '..', 'check-browser-report.js'), 'utf8');
  assert.match(src, /await tabBarRows\(page, url\);/);
  assert.match(src, /await tabTargetRows\(page, url\);/);
  /* The old phone-only skip must not swallow the new bar rows the way it
     swallowed the two sizes 4a names: the guard stays, but the bar rows run
     outside it. */
  assert.match(src, /if \(width >= 700\) continue;/);
});
