'use strict';

/* T-0500.1.7.8 finding 1 (v6 review, quarantined): the tab-look row accepted a selected tab that was painted
   in the page fill. It checked the number, the underline's width and colour equality, and the idle colours,
   but nothing asked whether any of it could be seen: a selected tab whose label, number and underline were all
   #111111 on the #111111 bar returned ok:true (P1.triage.md, finding 1).

   The row now measures the fill behind the selected tab (the gate expression walks up through transparent
   parents and returns every background on the way) and FAILS when the label, the number or the underline is
   under 3:1 against that fill. These tests drive both the verdict and the expression. */

var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var G = require('../check-browser-report.js');

var ACC = 'rgb(88, 166, 255)', MUTED = 'rgb(168, 168, 168)', TEXT = 'rgb(238, 238, 238)', FILL = 'rgb(17, 17, 17)';
var UL = ACC + ' 0px -2px 0px 0px inset';

function tab(id, over) {
  return Object.assign({ id: id, selected: false, color: MUTED, shadow: 'none', numContent: 'counter(hlrvtab)', numColor: MUTED, iconShown: false, fills: [FILL] }, over || {});
}
function good() {
  return [0, 1, 2, 3, 4, 5, 6].map(function (i) {
    return i === 2 ? tab('tabbtn-' + i, { selected: true, color: TEXT, shadow: UL, numColor: ACC }) : tab('tabbtn-' + i);
  });
}

test('control: the real concept 3 colours pass the paint row (label #eeeeee 16.3:1, number and underline #58a6ff 7.5:1 on the #111111 bar)', function () {
  var v = G.tabLookVerdict(good());
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, true, v.detail);
  assert.match(v.detail, /label rgb\(238, 238, 238\) 16\.3:1, number rgb\(88, 166, 255\) 7\.5:1, underline rgb\(88, 166, 255\) 7\.5:1 against rgb\(17, 17, 17\)/);
});

test('finding 1: the triage fixture, a selected tab painted #111111 on #111111, FAILS the paint row', function () {
  var t = good();
  t[2].color = FILL; t[2].numColor = FILL; t[2].shadow = FILL + ' 0px -2px 0px 0px inset';
  var v = G.tabLookVerdict(t);
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, false, 'an invisible selected tab passed: ' + v.detail);
  assert.match(v.detail, /label rgb\(17, 17, 17\) is 1\.0:1 against rgb\(17, 17, 17\), under the 3:1 floor/);
  assert.match(v.detail, /number rgb\(17, 17, 17\) is 1\.0:1/);
  assert.match(v.detail, /underline rgb\(17, 17, 17\) is 1\.0:1/);
});

test('finding 1: each part is measured on its own, so one invisible part fails even when the others are painted', function () {
  var label = good(); label[2].color = FILL;
  assert.match(G.tabLookVerdict(label).detail, /label rgb\(17, 17, 17\) is 1\.0:1/);
  var num = good(); num[2].numColor = FILL; num[2].shadow = FILL + ' 0px -2px 0px 0px inset';
  var nv = G.tabLookVerdict(num);
  assert.strictEqual(nv.ok, false, nv.detail);
  assert.match(nv.detail, /number rgb\(17, 17, 17\) is 1\.0:1/);
  var line = good(); line[2].shadow = MUTED + ' 0px -2px 0px 0px inset'; line[2].numColor = MUTED;
  assert.match(G.tabLookVerdict(line).detail, /underline rgb\(168, 168, 168\) 7\.9:1[\s\S]*floor 3:1/, 'muting the underline to #a8a8a8 still clears 3:1, and it is still its number colour');
});

test('finding 1: the fill is composited through transparent parents, not taken from the tab itself', function () {
  var t = good();
  t[2].fills = ['rgba(0, 0, 0, 0)', 'rgb(28, 28, 28)'];
  var v = G.tabLookVerdict(t);
  assert.strictEqual(v.ok, true, v.detail);
  assert.match(v.detail, /against rgb\(28, 28, 28\)/);
  /* the same colours over the page fill fail, so the parent's fill is what is read */
  var u = good();
  u[2].fills = ['rgba(0, 0, 0, 0)', 'rgba(0, 0, 0, 0)'];
  u[2].color = 'rgb(30, 30, 30)';
  assert.strictEqual(G.tabLookVerdict(u).notChecked, true);
});

test('finding 1: a selected tab whose fill cannot be read is NOT CHECKED, never a pass', function () {
  var t = good(); t[2].fills = [];
  var v = G.tabLookVerdict(t);
  assert.strictEqual(v.notChecked, true);
  assert.strictEqual(v.ok, false);
  assert.match(v.detail, /fill behind the selected tab/);
});

test('finding 1: the gate expression returns every background behind each tab, nearest first', function () {
  var dom = new JSDOM('<body style="background-color:#111111"><div style="background-color:transparent"><div class="hl-rv-tabs" style="background-color:#1c1c1c">' +
    '<button role="tab" id="tabbtn-a" aria-selected="true" style="color:#eeeeee;background-color:transparent;box-shadow:inset 0 -2px 0 #58a6ff">A</button>' +
    '<button role="tab" id="tabbtn-b" aria-selected="false" style="color:#a8a8a8;background-color:transparent">B</button></div></div></body>', { runScripts: 'outside-only' });
  var w = dom.window, real = w.getComputedStyle;
  w.getComputedStyle = function (el, ps) {
    if (ps) return { content: 'counter(hlrvtab)', color: el.id === 'tabbtn-a' ? 'rgb(88, 166, 255)' : 'rgb(168, 168, 168)', display: 'none' };
    return real.call(w, el);
  };
  var rows = JSON.parse(JSON.stringify(w.eval(G.TAB_LOOK_EXPR)));
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[0].id, 'tabbtn-a');
  assert.strictEqual(rows[0].fills[0], 'rgba(0, 0, 0, 0)', 'the tab itself is transparent');
  assert.ok(rows[0].fills.indexOf('rgb(28, 28, 28)') > 0, 'the bar fill is in the chain behind it: ' + rows[0].fills.join(' | '));
  assert.ok(rows[0].fills.indexOf('rgb(17, 17, 17)') > rows[0].fills.indexOf('rgb(28, 28, 28)'), 'the page fill is behind the bar');
  /* jsdom keeps a box-shadow as authored; Chrome serialises the inset as "rgb(...) 0px -2px 0px 0px inset", so the row reads
     the underline after that one field is put in Chrome's shape. The fills are the expression's own. */
  var measured = rows.map(function (r) { return r.id === 'tabbtn-a' ? Object.assign({}, r, { shadow: 'rgb(88, 166, 255) 0px -2px 0px 0px inset' }) : r; });
  var v = G.tabLookVerdict(measured);
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, true, v.detail);
  assert.match(v.detail, /against rgb\(28, 28, 28\)/);
});
