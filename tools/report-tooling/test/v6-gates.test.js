'use strict';

/* Tests for the two rows design v6 (T-0500.1.7) added to check-browser-report.js: no chrome text under
   13 px, and the selected tab told apart from the others (T-0556 w6a: now the concept 3 rule, see the tab look tests below).

   A row added to a gate is worth nothing until something proves it can FAIL, so each verdict is driven with
   the measurement a broken layout would produce. These do not drive a browser: the measurement comes from
   lib/cdp.js at run time. What is testable is the decision, and one jsdom run of the text expression with
   layout stubbed, to show that a 12 px label is counted, a 13 px one is not, and an element with no box
   is never counted. See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var G = require('../check-browser-report.js');

/* T-0556 w6a: the tab look row is the concept 3 rule (numbered text tabs, one accent underline on the selected tab, no icons), replacing the design D chip rule.
   A tab is what TAB_LOOK_EXPR measures: label colour, box-shadow, the ::before number's content and colour, whether an icon is shown. */
var ACC = 'rgb(88, 166, 255)', UL = ACC + ' 0px -2px 0px 0px inset';
function tab(id, over) {
  return Object.assign({ id: id, selected: false, color: 'rgb(168, 168, 168)', shadow: 'none', numContent: 'counter(hlrvtab)', numColor: 'rgb(168, 168, 168)', iconShown: false }, over || {});
}
function good() {
  return [0, 1, 2, 3, 4, 5, 6].map(function (i) { return i === 2 ? tab('tabbtn-' + i, { selected: true, color: 'rgb(226, 226, 226)', shadow: UL, numColor: ACC }) : tab('tabbtn-' + i); });
}

test('the tab look row (concept 3) passes numbered text tabs with one accent underline on the selected tab', function () {
  var v = G.tabLookVerdict(good());
  assert.strictEqual(v.ok, true, v.detail);
  assert.match(v.detail, /7 tab\(s\), all numbered text: selected tabbtn-2 .* with a 2px /);
});
test('control: the tab look row fails when the selected tab has no underline, or a thin or thick one, or one that is not its number colour', function () {
  var t = good(); t[2].shadow = 'none';
  var v = G.tabLookVerdict(t); assert.strictEqual(v.ok, false); assert.match(v.detail, /no accent underline/);
  var u = good(); u[2].shadow = ACC + ' 0px -1px 0px 0px inset'; assert.match(G.tabLookVerdict(u).detail, /no accent underline/);
  var w = good(); w[2].shadow = ACC + ' 0px -6px 0px 0px inset'; assert.match(G.tabLookVerdict(w).detail, /no accent underline/);
  var x = good(); x[2].numColor = 'rgb(168, 168, 168)'; assert.match(G.tabLookVerdict(x).detail, /not the colour of its number/);
});
test('control: the tab look row fails when an idle tab is underlined, or shares the selected number or label colour', function () {
  var t = good(); t[4].shadow = UL;
  var v = G.tabLookVerdict(t); assert.strictEqual(v.ok, false); assert.match(v.detail, /idle tab \(tabbtn-4\) also has an underline/);
  var u = good(); u[4].numColor = ACC; assert.match(G.tabLookVerdict(u).detail, /selected tab's number colour/);
  var w = good(); w[4].color = w[2].color; assert.match(G.tabLookVerdict(w).detail, /selected tab's label colour/);
});
test('control: the tab look row fails when two tabs are selected, none is, a tab has no number, or a tab still shows an icon', function () {
  var t = good(); t[0].selected = true; assert.match(G.tabLookVerdict(t).detail, /2 tabs selected/);
  var u = good(); u[2].selected = false; assert.match(G.tabLookVerdict(u).detail, /0 tabs selected/);
  var w = good(); w[1].numContent = 'none'; assert.match(G.tabLookVerdict(w).detail, /tabbtn-1 carries no number/);
  var x = good(); x[3].iconShown = true; assert.match(G.tabLookVerdict(x).detail, /tabbtn-3 still shows an icon/);
});
test('the tab look row passes a six-tab report, and a one-tab report says it made no idle comparison', function () {
  assert.strictEqual(G.tabLookVerdict(good().slice(0, 6)).ok, true);
  var one = G.tabLookVerdict([tab('tabbtn-overview', { selected: true, shadow: UL, numColor: ACC })]);
  assert.strictEqual(one.ok, true, one.detail); assert.strictEqual(one.single, true); assert.match(one.detail, /no idle tab exists/);
  assert.strictEqual(G.tabLookVerdict([tab('tabbtn-overview', { selected: true })]).ok, false);
});
test('the tab underline reader takes what Chrome writes and nothing else', function () {
  assert.deepStrictEqual(G.tabUnderline(UL), { color: ACC, thick: 2 });
  assert.strictEqual(G.tabUnderline('none'), null);
  assert.strictEqual(G.tabUnderline('rgba(0, 0, 0, 0.3) 0px 4px 8px 0px'), null);
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

test('T-0556 w6a: the cover texture is excluded from the text floor by class; a small label beside it, and a small aria-hidden pre of another class, still count', function () {
  var tex = '<pre class="c3-cover__tex" aria-hidden="true" style="font-size:11px">0x4f 0x2a</pre>';
  var only = run('<div class="hl-post-header">' + tex + '</div><section id="tab-overview"></section>');
  assert.strictEqual(only.smallCount, 0); assert.strictEqual(only.count, 0);
  var beside = run('<div class="hl-post-header">' + tex + '<b style="font-size:11px">Label</b></div><section id="tab-overview"></section>');
  assert.strictEqual(beside.smallCount, 1);
  var other = run('<div class="hl-post-header"><pre class="other" aria-hidden="true" style="font-size:11px">0x4f</pre></div><section id="tab-overview"></section>');
  assert.strictEqual(other.smallCount, 1);
});
