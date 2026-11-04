'use strict';

/* Tests for the two rows v6.1 (T-0500.1.7) added to check-browser-report.js: the top of the page (T-0556 w6a: now attached and ruled, not 24 px panels), and the type scale. A row is worth nothing until something proves it can FAIL, so each verdict is driven
   with the measurement a broken layout would produce (the browser itself is not driven here; lib/cdp.js measures at run time).
   See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var G = require('../check-browser-report.js');

/* T-0556 w6a: the top-of-page row is the concept 3 rule (header, tab row and body attached and separated by rules, nothing overlapping), replacing the v6.1
   24 px gap rule. A component is what PANEL_EXPR measures: name, top, bottom and the visible rule (px) on its top and bottom edge. */
function it(name, top, bottom, over) {
  return Object.assign({ name: name, top: top, bottom: bottom, ruleTop: 0, ruleBottom: 0 }, over || {});
}
function good() {
  return { items: [
    it('header', 82, 380, { ruleBottom: 1 }),
    it('tab row', 380, 428, { ruleBottom: 1 }),
    it('toolbar', 440, 488, { ruleBottom: 1 }),
    it('tab title', 488, 560),
    it('data view', 580, 900)
  ] };
}

test('the top-of-page row passes the concept 3 stack: header, tab row attached at one edge, rules between, a toolbar under 24 px below, nothing overlapping', function () {
  var v = G.panelStackVerdict(good());
  assert.strictEqual(v.ok, true, v.detail);
});
test('control: the row FAILS when the tab row floats 16 px or more below the header (the old separate-panel layout)', function () {
  var m = good(); m.items[1].top = 380 + 16; m.items[1].bottom = 444; m.items[2].top = 456; m.items[2].bottom = 504; m.items[3].top = 504;
  var v = G.panelStackVerdict(m);
  assert.strictEqual(v.ok, false); assert.match(v.detail, /tab row is not attached to the header \(16\.0 px/);
});
test('control: the row FAILS when the tab row lies over the header, or the toolbar over the tab row', function () {
  var m = good(); m.items[1].top = 360; m.items[1].bottom = 408;
  assert.match(G.panelStackVerdict(m).detail, /tab row overlaps header by 20\.0 px/);
  var n = good(); n.items[2].top = 410;
  assert.match(G.panelStackVerdict(n).detail, /toolbar overlaps tab row by 18\.0 px/);
});
test('control: the row FAILS when the header and the tab row have no rule, or the tab row has none under it', function () {
  var m = good(); m.items[0].ruleBottom = 0;
  assert.match(G.panelStackVerdict(m).detail, /no rule between the header and the tab row/);
  m.items[1].ruleTop = 1; assert.strictEqual(G.panelStackVerdict(m).ok, true, 'the tab row\'s own top rule counts as the rule between them');
  var n = good(); n.items[1].ruleBottom = 0; n.items[2].ruleBottom = 0;
  assert.match(G.panelStackVerdict(n).detail, /no rule under the tab row/);
});
test('control: the row FAILS when the toolbar floats 24 px or more below the tab row', function () {
  var m = good(); m.items[2].top = 428 + 30; m.items[2].bottom = 506; m.items[3].top = 506;
  assert.match(G.panelStackVerdict(m).detail, /toolbar floats 30\.0 px below the tab row/);
});
test('the top-of-page row is NOT CHECKED, never PASS, when it found almost nothing or no header and tab row', function () {
  var v = G.panelStackVerdict({ items: [it('header', 0, 100)] });
  assert.strictEqual(v.notChecked, true); assert.strictEqual(v.ok, false);
  assert.strictEqual(G.panelStackVerdict(null).notChecked, true);
  assert.strictEqual(G.panelStackVerdict({ items: [it('toolbar', 0, 40), it('tab title', 40, 80), it('data view', 90, 200)] }).notChecked, true);
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
