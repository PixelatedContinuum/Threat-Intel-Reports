'use strict';

/* Tests for the two rows design v6 (T-0500.1.7) added to check-browser-report.js: no chrome text under
   13 px, and the selected tab told apart from the others with an accent dot on every tab.

   A row added to a gate is worth nothing until something proves it can FAIL, so each verdict is driven with
   the measurement a broken layout would produce. These do not drive a browser: the measurement comes from
   lib/cdp.js at run time. What is testable is the decision, and one jsdom run of the text expression with
   layout stubbed, to show that a 12 px label is counted, a 13 px one is not, and an element with no box
   is never counted. See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var G = require('../check-browser-report.js');

function tab(id, over) {
  return Object.assign({ id: id, selected: false, color: 'rgb(168, 168, 168)', line: 'rgba(0, 0, 0, 0)', lineW: 2, dot: 'rgb(1, 1, 1)', dotW: 7 }, over || {});
}
function good() {
  var dots = ['rgb(163,113,247)', 'rgb(232,121,249)', 'rgb(251,146,60)', 'rgb(88,166,255)', 'rgb(232,121,249)', 'rgb(34,211,238)', 'rgb(45,212,191)'];
  return dots.map(function (d, i) {
    return tab('tabbtn-' + i, i === 2 ? { selected: true, color: 'rgb(251, 146, 60)', line: 'rgb(251, 146, 60)', dot: d } : { dot: d });
  });
}

test('the tab look row passes the v6 tab strip: one underlined accent-coloured tab, seven dots in six hues', function () {
  var v = G.tabLookVerdict(good());
  assert.strictEqual(v.ok, true, v.detail);
  assert.strictEqual(v.distinct, 6);
});
test('the tab look row fails when the selected tab has no underline', function () {
  var t = good(); t[2].line = 'rgba(0, 0, 0, 0)';
  assert.strictEqual(G.tabLookVerdict(t).ok, false);
});
test('the tab look row fails when an idle tab shares the selected label colour', function () {
  var t = good(); t[4].color = t[2].color;
  var v = G.tabLookVerdict(t); assert.strictEqual(v.ok, false); assert.match(v.detail, /label colour/);
});
test('the tab look row fails when an idle tab is underlined, or two tabs are selected', function () {
  var t = good(); t[0].line = 'rgb(163, 113, 247)';
  assert.strictEqual(G.tabLookVerdict(t).ok, false);
  var u = good(); u[0].selected = true;
  assert.strictEqual(G.tabLookVerdict(u).ok, false);
});
test('the tab look row fails when a tab has no dot, or all dots are one colour', function () {
  var t = good(); t[1].dotW = 0;
  assert.strictEqual(G.tabLookVerdict(t).ok, false);
  var u = good().map(function (x) { return Object.assign(x, { dot: 'rgb(88, 166, 255)' }); });
  var v = G.tabLookVerdict(u); assert.strictEqual(v.ok, false); assert.match(v.detail, /distinct dot colours/);
});
test('the tab look row measured nothing, so it is NOT CHECKED, never a pass', function () {
  assert.strictEqual(G.tabLookVerdict([]).notChecked, true);
  assert.strictEqual(G.tabLookVerdict(null).ok, false);
});

function run(html) {
  var dom = new JSDOM('<body>' + html + '</body>', { runScripts: 'outside-only' });
  var w = dom.window;
  w.Element.prototype.getClientRects = function () { return this.hasAttribute('data-nobox') || this.closest('[data-nobox]') ? [] : [{}]; };
  var real = w.getComputedStyle;
  // jsdom has no pseudo-element styles: a stub says there are none, so only the text-node path is exercised here
  w.getComputedStyle = function (el, ps) { return ps ? { content: 'none', display: 'inline', fontSize: '16px' } : real.call(w, el); };
  return JSON.parse(JSON.stringify(w.eval(G.chromeTextExpr('overview'))));
}
var PANEL = '<section id="tab-overview"><div data-rv-chrome style="font-size:%s">Label text</div></section>';
test('the text floor expression counts a 12 px chrome label and not a 13 px one', function () {
  var bad = run(PANEL.replace('%s', '12px'));
  assert.strictEqual(bad.smallCount, 1); assert.strictEqual(bad.small[0].px, 12);
  var ok = run(PANEL.replace('%s', '13px'));
  assert.strictEqual(ok.smallCount, 0); assert.strictEqual(ok.count, 1);
});
test('the text floor expression never counts text with no box, and a missing panel measures nothing', function () {
  var hidden = run('<section id="tab-overview"><div data-rv-chrome data-nobox style="font-size:9px">Hidden</div></section>');
  assert.strictEqual(hidden.count, 0); assert.strictEqual(hidden.smallCount, 0);
  var none = new JSDOM('<body></body>', { runScripts: 'outside-only' }).window.eval(G.chromeTextExpr('overview'));
  assert.strictEqual(none, null);
});
test('the text floor reads the bar and the header as well as the tab panel', function () {
  var r = run('<div class="hl-post-header" style="font-size:11px">Header small</div><div class="hl-rv-bar" style="font-size:14px">Bar fine</div><section id="tab-overview"></section>');
  assert.strictEqual(r.count, 2); assert.strictEqual(r.smallCount, 1);
});
