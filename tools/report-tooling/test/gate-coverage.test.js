'use strict';

/* T-0500.1.7.8 finding 7 (v6.1 review, quarantined): the prose-measurement rows admitted false PASSes because
   the coverage they claim was never explicit (P1.triage.md, finding 7):
     (a) the type-scale row skipped a row with nothing measured (`if (!r.n || r.px == null) return`), so a tab
         whose Executive Summary prose was never measured PASSed on the other categories;
     (b) the long-paragraph selector took only the FIRST qualifying paragraph (`[0]`), so a second one at 10 px
         was invisible to the row;
     (c) the top-of-page row skipped an absent named component, so a tab with no data view PASSed with it
         unmeasured.

   The fix makes the required coverage explicit. The required sets come from the gate's own tab definitions:
   - hl-report-tabs.js builds every non-inline tab with a `.hl-rv-view` and its `.hl-rv-view-summary p`
     (the data view and its summary line), and every tab panel with a `.hl-rv-panel-head`; PANEL_EXPR's
     header, tab row and toolbar live outside the panels and exist once per page.
   - `rowTabs()` measures the report's first built tab and Attack chain (or the second tab when there is no
     chain). The first built tab is the one holding the report's opening sections, so the prose floor is
     required there and not on a later tab whose sections may all be short.
   - An inline page (`figures: inline`, the `.hl-figs-inline` class the gate already reads) builds no view band,
     so the data view is not required there; its tab head and facts line still are.
   A required element that is absent is NOT CHECKED with its name, never a silent pass. */

var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var G = require('../check-browser-report.js');

function scale(over) {
  return G.TYPE_SPEC.map(function (r) {
    var min = r[2];
    return { name: r[0], n: 3, px: over && over[r[0]] !== undefined ? over[r[0]] : (min == null ? 14 : min) };
  });
}
function item(name, top, bottom, over) {
  return Object.assign({ name: name, top: top, bottom: bottom, ruleTop: 0, ruleBottom: 0 }, over || {});
}
function stack() {
  return { items: [
    item('header', 82, 380, { ruleBottom: 1 }),
    item('tab row', 380, 428, { ruleBottom: 1 }),
    item('toolbar', 440, 488, { ruleBottom: 1 }),
    item('tab title', 488, 560),
    item('data view', 580, 900),
    item('first section', 900, 1200)
  ] };
}

test('(a) finding 7: a tab whose Executive Summary prose was never measured is NOT CHECKED, not a pass on the other categories', function () {
  var rows = scale();
  rows[0].n = 0; rows[0].px = null;   /* the prose row absent, every other category good */
  var v = G.typeScaleVerdict(rows, false, { first: true });
  assert.strictEqual(v.notChecked, true, 'the row passed with its prose unmeasured: ' + v.ok + ' ' + v.detail);
  assert.strictEqual(v.ok, false);
  assert.match(v.detail, /Executive Summary prose/);
});

test('(a) control: the same rows with the prose measured PASS, so the requirement is coverage and not a blanket failure', function () {
  var v = G.typeScaleVerdict(scale(), false, { first: true });
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, true, v.detail);
});

test('(a) finding 7: the required set is stated per tab, and a later tab is not held to the first tab\'s prose', function () {
  var rows = scale(); rows[0].n = 0; rows[0].px = null;
  var v = G.typeScaleVerdict(rows, false, { token: 'chain' });
  assert.strictEqual(v.ok, true, 'the second tab is not required to hold the opening prose: ' + v.detail);
  /* but the elements every built tab has are still required there */
  var noTabName = scale(); noTabName[G.TYPE_SPEC.findIndex(function (r) { return r[0] === 'tab name'; })].n = 0;
  assert.strictEqual(G.typeScaleVerdict(noTabName, false, { token: 'chain' }).notChecked, true);
});

test('(a) finding 7: an inline page is not required to carry the data-view summary it does not build', function () {
  var rows = scale(); var i = G.TYPE_SPEC.findIndex(function (r) { return r[0] === 'data-view summary line'; });
  rows[i].n = 0; rows[i].px = null;
  assert.strictEqual(G.typeScaleVerdict(rows, false, { token: 'overview' }).notChecked, true, 'a dashboard tab is held to it');
  var v = G.typeScaleVerdict(rows, false, { token: 'overview', inline: true });
  assert.strictEqual(v.notChecked, false, 'an inline page builds no view band, so it is not held to its summary line: ' + v.detail);
  assert.strictEqual(v.ok, true, v.detail);
});

/* (b) the long-paragraph measure: two qualifying paragraphs, the second under the floor */
function proseRows(html) {
  var dom = new JSDOM('<body>' + html + '</body>', { runScripts: 'outside-only' });
  dom.window.Element.prototype.getClientRects = function () { return [{ width: 1, height: 1 }]; };
  return JSON.parse(JSON.stringify(dom.window.eval(G.TYPE_EXPR)));
}
var long = function (n, c) { return new Array(n).join(c); };
function source(p1, p2) {
  return '<div class="hl-rv-panel"><div class="hl-rv-source"><h2 style="font-size:24px">1. Executive Summary</h2>' +
    '<p style="font-size:' + p1 + 'px">' + long(240, 'a') + '</p>' +
    (p2 ? '<p style="font-size:' + p2 + 'px">' + long(240, 'b') + '</p>' : '') + '</div></div>';
}

function withProse(html) { var rows = scale(); rows[0] = proseRows(html)[0]; return rows; }

test('(b) finding 7: the prose floor is the minimum over EVERY qualifying paragraph, so a second long paragraph at 10 px FAILS', function () {
  var rows = withProse(source(18, 10));
  var prose = rows[0];
  assert.strictEqual(prose.n, 2, 'the second qualifying paragraph was never seen by the row');
  assert.strictEqual(prose.px, 10, 'the row measured one paragraph, not the floor of all of them');
  var v = G.typeScaleVerdict(rows, false, { first: true });
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, false, v.detail);
  assert.match(v.detail, /Executive Summary prose is 10 px, floor 18/);
});

test('(b) control: two qualifying paragraphs both at 18 px PASS with n=2', function () {
  var rows = withProse(source(18, 18));
  assert.strictEqual(rows[0].n, 2);
  assert.strictEqual(rows[0].px, 18);
  var v = G.typeScaleVerdict(rows, false, { first: true });
  assert.strictEqual(v.ok, true, v.detail);
});

test('(c) finding 7: a tab with no data view is NOT CHECKED, not a pass on the components it does have', function () {
  var m = stack();
  m.items = m.items.filter(function (x) { return x.name !== 'data view'; });   /* seven well-formed components */
  var v = G.panelStackVerdict(m);
  assert.strictEqual(v.notChecked, true, 'the row passed with the data view unmeasured: ' + v.ok + ' ' + v.detail);
  assert.strictEqual(v.ok, false);
  assert.match(v.detail, /data view/);
});

test('(c) control: the same seven components with the data view present PASS, so the requirement is coverage', function () {
  var v = G.panelStackVerdict(stack());
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, true, v.detail);
});

test('(c) finding 7: an inline page is not required to carry the data view it does not build', function () {
  var m = stack();
  m.items = m.items.filter(function (x) { return x.name !== 'data view'; });
  var v = G.panelStackVerdict(m, { inline: true });
  assert.strictEqual(v.notChecked, false, v.detail);
  assert.strictEqual(v.ok, true, v.detail);
});
