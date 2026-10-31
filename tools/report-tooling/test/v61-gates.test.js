'use strict';

/* Tests for the two rows v6.1 (T-0500.1.7) added to check-browser-report.js: the top of the page is separate panels 24 px apart
   on their own surfaces, and the type scale. A row is worth nothing until something proves it can FAIL, so each verdict is driven
   with the measurement a broken layout would produce (the browser itself is not driven here; lib/cdp.js measures at run time).
   See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var G = require('../check-browser-report.js');

var PAGE = 'rgb(17, 17, 17)';
function it(name, top, bottom, over) {
  return Object.assign({ name: name, boxed: name !== 'tab title', top: top, bottom: bottom, border: 1, bg: 'rgb(28, 28, 28)', image: false }, over || {});
}
function good() {
  return { page: PAGE, items: [
    it('site band', 0, 58, { bg: 'rgb(11, 11, 11)' }),
    it('header', 82, 240, { bg: PAGE, image: true }),
    it('tab row', 264, 354, { bg: 'rgb(58, 58, 58)' }),
    it('toolbar', 378, 434, { bg: 'rgb(38, 38, 38)' }),
    it('tab title', 458, 518),
    it('data view', 542, 900)
  ] };
}

test('the panel stack row passes the v6.1 top: 24 px gaps, bordered panels, tab row and toolbar on different surfaces', function () {
  var v = G.panelStackVerdict(good());
  assert.strictEqual(v.ok, true, v.detail);
});
test('the panel stack row FAILS when two components are 16 px apart (the v6 gap)', function () {
  var m = good(); m.items[3].top = 354 + 16; m.items[3].bottom = m.items[3].top + 56;
  var v = G.panelStackVerdict(m);
  assert.strictEqual(v.ok, false); assert.match(v.detail, /tab row to toolbar is 16\.0 px apart/);
});
test('the panel stack row FAILS when the tab row and the toolbar share a surface (what Joseph saw)', function () {
  var m = good(); m.items[2].bg = m.items[3].bg;
  var v = G.panelStackVerdict(m);
  assert.strictEqual(v.ok, false); assert.match(v.detail, /one surface/);
});
test('the panel stack row FAILS for a panel on the page surface or with no border', function () {
  var m = good(); m.items[5].bg = PAGE;
  assert.match(G.panelStackVerdict(m).detail, /data view is on the page surface/);
  m = good(); m.items[5].border = 0;
  assert.match(G.panelStackVerdict(m).detail, /data view has no border/);
});
test('an attached report sponsor is one box with the header; a detached one FAILS', function () {
  var m = good(); m.items.splice(2, 0, it('report sponsor', 240, 320, { bg: 'rgb(38, 38, 38)' })); m.items[3].top = 344; m.items[3].bottom = 434; m.items[4].top = 458;
  var v = G.panelStackVerdict(m); assert.strictEqual(v.ok, true, v.detail);
  m.items[2].top = 270; m.items[2].bottom = 350; m.items[3].top = 374; m.items[3].bottom = 440; m.items[4].top = 464;
  v = G.panelStackVerdict(m); assert.strictEqual(v.ok, false); assert.match(v.detail, /not attached/);
});
test('the panel stack row is NOT CHECKED, never PASS, when it found almost nothing', function () {
  var v = G.panelStackVerdict({ page: PAGE, items: [it('header', 0, 100)] });
  assert.strictEqual(v.notChecked, true); assert.strictEqual(v.ok, false);
  assert.strictEqual(G.panelStackVerdict(null).notChecked, true);
});

function scale(over, phone) {
  return G.TYPE_SPEC.map(function (r, i) {
    var min = phone ? r[3] : r[2];
    return { name: r[0], n: 3, px: over && over[r[0]] !== undefined ? over[r[0]] : (min == null ? 14 : min) };
  });
}
test('the type scale row passes the v6.1 sizes at desktop and phone', function () {
  assert.strictEqual(G.typeScaleVerdict(scale(), false).ok, true);
  assert.strictEqual(G.typeScaleVerdict(scale(), true).ok, true);
});
test('the type scale row FAILS for each v6 size Joseph called too small', function () {
  var cases = { 'tab name': 14.5, 'table cell': 14, 'stat tile label': 14, 'how-counted note': 14, 'toolbar text': 14, 'table header': 13, 'sponsor mono label': 13, 'data-view summary line': 15 };
  Object.keys(cases).forEach(function (k) {
    var v = G.typeScaleVerdict(scale(cases[k] !== undefined ? (function () { var o = {}; o[k] = cases[k]; return o; })() : null), false);
    assert.strictEqual(v.ok, false, k); assert.match(v.detail, new RegExp(k + ' is ' + cases[k].toString().replace('.', '\\.') + ' px'));
  });
});
test('the type scale row keeps a 15 px phone floor: 14 px table text FAILS on a phone, 15 passes', function () {
  assert.strictEqual(G.typeScaleVerdict(scale({ 'table cell': 14 }, true), true).ok, false);
  assert.strictEqual(G.typeScaleVerdict(scale({ 'table cell': 15 }, true), true).ok, true);
});
test('the type scale row is NOT CHECKED when fewer than eight elements were measured', function () {
  var rows = scale(); rows.forEach(function (r, i) { if (i > 5) { r.n = 0; r.px = null; } });
  var v = G.typeScaleVerdict(rows, false); assert.strictEqual(v.notChecked, true); assert.strictEqual(v.ok, false);
});

/* T-0500.1.11 (open-directory-172-105-0-126): the campaign-record block that opens a report is metadata at 16px, not Executive Summary prose.
   The in-page expression is run over a page whose first long paragraph is that block (16px, 213 characters, class hl-rv-nohead) and whose next is
   real prose (18px): the old selector measured the block and FAILED an 18px floor; the shipped one measures the prose. jsdom has no layout, so
   getClientRects is stubbed to "painted" and the font sizes are declared inline. */
test('Executive Summary prose is not the campaign-record block that opens the report (the old selector measured it at 16 px against 18)', function () {
  var { JSDOM } = require('jsdom');
  var long = (n, c) => new Array(n).join(c);
  var html = '<div class="hl-rv-panel"><div class="hl-rv-source hl-rv-nohead"><p style="font-size:16px">' + long(214, 'a') + '</p></div>' +
    '<div class="hl-rv-source"><h2 style="font-size:22px">1. Executive Summary</h2><p style="font-size:18px">' + long(300, 'b') + '</p></div></div>';
  function run(expr) {
    var dom = new JSDOM(html, { runScripts: 'outside-only' });
    dom.window.Element.prototype.getClientRects = function () { return [{ width: 1, height: 1 }]; };
    var rows = JSON.parse(JSON.stringify(dom.window.eval(expr)));
    return rows.filter(function (r) { return r.name === 'Executive Summary prose'; })[0];
  }
  var row = G.TYPE_SPEC.filter(function (r) { return r[0] === 'Executive Summary prose'; })[0];
  assert.match(row[1], /\.hl-rv-source:not\(\.hl-rv-nohead\) > p/);
  assert.strictEqual(run(G.TYPE_EXPR).px, 18, 'the shipped selector measures the prose');
  var oldExpr = G.TYPE_EXPR.split('.hl-rv-source:not(.hl-rv-nohead) > p').join('.hl-rv-source > p');
  assert.notStrictEqual(oldExpr, G.TYPE_EXPR, 'the control copy changed the selector');
  assert.strictEqual(run(oldExpr).px, 16, 'the old selector measures the campaign-record block');
});
