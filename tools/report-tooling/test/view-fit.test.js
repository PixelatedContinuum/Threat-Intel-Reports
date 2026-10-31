'use strict';
/* T-0500.1.10.1: the collapsed data-view rows of the browser gate (viewFit in lib/box-fit.js, viewFitRows in check-browser-report.js) and the
   CSS fix they guard. jsdom has no layout, so the in-page expression runs over a page whose boxes are DECLARED (data-box="left,top,right,bottom");
   its logic is real, the geometry is stipulated. The live run of the same expression against the pilot, with its three controls, is the gate. */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const B = require('../lib/box-fit.js');
const G = require('../check-browser-report.js');
const SITE = path.join(__dirname, '../../..');
const CSS = fs.readFileSync(path.join(SITE, 'assets/css/hl-report-tabs.css'), 'utf8');

function layout(html) {
  const dom = new JSDOM('<body><div class="hl-report-page">' + html + '</div></body>', { runScripts: 'outside-only' });
  const w = dom.window, E = w.Element.prototype;
  const box = (el) => { const v = el.getAttribute('data-box'); return v ? v.split(',').map(Number) : null; };
  E.getBoundingClientRect = function () { const b = box(this) || [0, 0, 0, 0]; return { left: b[0], top: b[1], right: b[2], bottom: b[3], width: b[2] - b[0], height: b[3] - b[1] }; };
  const real = w.getComputedStyle.bind(w);
  const PROPS = ['backgroundColor', 'backgroundImage', 'boxShadow', 'display', 'position', 'visibility', 'borderLeftWidth', 'borderRightWidth', 'borderTopWidth', 'borderBottomWidth',
    'borderLeftStyle', 'borderRightStyle', 'borderTopStyle', 'borderBottomStyle', 'borderLeftColor', 'borderRightColor', 'borderTopColor', 'borderBottomColor'];
  w.getComputedStyle = (el, pe) => {
    if (pe) return { content: 'none' };
    const r = real(el), o = {};
    PROPS.forEach(k => { o[k] = r[k]; });
    o.borderBottomLeftRadius = '0px'; o.borderBottomRightRadius = '0px';
    return Object.assign(o, JSON.parse(el.getAttribute('data-cs') || '{}'));
  };
  return { w, run: () => JSON.parse(JSON.stringify(w.eval(B.VIEW_EXPR))), close: () => w.close() };
}
const BAR = (extra) => '<div class="hl-rv-view-summary" data-box="17,209,373,325" data-cs=\'{"backgroundColor":"rgb(30,30,30)"' + (extra || '') + '}\'><p data-box="30,260,360,300">7 stages</p><button id="hl-rv-toggle-chain" aria-expanded="false" data-box="220,220,360,260">Show the view</button></div>';
const BODY = '<div class="hl-rv-view-body" hidden></div>';
const NOTE = (top) => '<p class="hl-rv-curated" data-box="17,' + top + ',373,' + (top + 38) + '">View selections curated for this report.</p>';
const view = (inner, o) => '<section class="hl-rv-view" data-box="16,208,374,' + ((o && o.bottom) || 360) + '">' + inner + '</section>';
const RADIUS = ',"borderBottomLeftRadius":"7px","borderBottomRightRadius":"7px"';

test('the fixed card: a square bar over a note that starts where the bar ends measures clean on both rows', () => {
  const f = layout(view(BAR('') + BODY + NOTE(325)));
  try { const m = f.run(); assert.equal(m.collapsed, 1); assert.equal(m.withNote, 1); assert.deepEqual(m.overlap, []); assert.deepEqual(m.roundedOver, []); assert.equal(m.rounded, 0);
    assert.equal(B.viewVerdict([Object.assign({ label: 'a' }, m)], 'overlap').ok, true); assert.equal(B.viewVerdict([Object.assign({ label: 'a' }, m)], 'rounded').ok, true); } finally { f.close(); }
});
test('the defect Joseph saw: the note 8px up over the bar is an overlap, and a fully rounded bar with the note under it is a rounded fault', () => {
  const f = layout(view(BAR(RADIUS) + BODY + NOTE(317)));
  try {
    const m = f.run();
    assert.equal(m.overlap.length, 1); assert.equal(m.overlap[0].sig, 'div.hl-rv-view-summary'); assert.equal(m.overlap[0].other, 'p.hl-rv-curated'); assert.equal(m.overlap[0].by, 8);
    assert.equal(m.roundedOver.length, 1); assert.equal(m.roundedOver[0].other, 'p.hl-rv-curated'); assert.equal(m.roundedOver[0].radius, 7);
    const st = Object.assign({ label: '390x844 chain' }, m);
    const ov = B.viewVerdict([st], 'overlap'), rv = B.viewVerdict([st], 'rounded');
    assert.equal(ov.ok, false); assert.match(ov.detail, /overlaps its sibling p\.hl-rv-curated by 8px/);
    assert.equal(rv.ok, false); assert.match(rv.detail, /bottom radius of 7px and p\.hl-rv-curated under it/);
  } finally { f.close(); }
});
test('each clause stands alone: the overlap with a square bar fails only the overlap row, a round bar with the note clear of it fails only the rounded row', () => {
  const a = layout(view(BAR('') + BODY + NOTE(317)));
  try { const m = a.run(); assert.equal(m.overlap.length, 1); assert.deepEqual(m.roundedOver, []); } finally { a.close(); }
  const b = layout(view(BAR(RADIUS) + BODY + NOTE(325)));
  try { const m = b.run(); assert.deepEqual(m.overlap, []); assert.equal(m.roundedOver.length, 1); } finally { b.close(); }
});
test('a collapsed bar with nothing under it keeps its full radius and is counted, not faulted', () => {
  const f = layout(view(BAR(RADIUS) + BODY, { bottom: 326 }));
  try { const m = f.run(); assert.deepEqual(m.roundedOver, []); assert.equal(m.rounded, 1); assert.equal(m.roundedAlone, 1); assert.equal(m.withNote, 0);
    assert.match(B.viewVerdict([Object.assign({ label: 'a' }, m)], 'rounded').detail, /1 bars with a rounded bottom corner, 1 of them with nothing under them/); } finally { f.close(); }
});
test('an open view is counted as not collapsed and is not measured; a view in a hidden tab has no box and is not counted; no collapsed view is NOT CHECKED, never a pass', () => {
  const f = layout(view(BAR('').replace('aria-expanded="false"', 'aria-expanded="true"') + BODY + NOTE(317)) + '<section class="hl-rv-view"><div class="hl-rv-view-summary"></div></section>');
  try { const m = f.run(); assert.equal(m.views, 1); assert.equal(m.notCollapsed, 1); assert.equal(m.collapsed, 0); assert.deepEqual(m.overlap, []);
    const v = B.viewVerdict([Object.assign({ label: 'a' }, m)], 'overlap'); assert.equal(v.notChecked, true); assert.equal(v.ok, false); } finally { f.close(); }
  assert.equal(B.viewVerdict([], 'rounded').notChecked, true);
});
test('two unpainted, textless siblings that overlap are not a fault; a painted one over a sibling is, and inline boxes are not compared', () => {
  const f = layout(view(BAR('') + '<div data-box="17,330,373,350"></div><div data-box="17,340,373,360"></div>'));
  try { assert.deepEqual(f.run().overlap, []); } finally { f.close(); }
  const g = layout(view(BAR('') + '<div data-cs=\'{"backgroundColor":"rgb(9,9,9)"}\' data-box="17,330,373,350"></div><div data-box="17,340,373,360"></div>'));
  try { assert.equal(g.run().overlap.length, 1); } finally { g.close(); }
  const h = layout(view(BAR('') + '<p data-box="17,330,373,370"><span data-cs=\'{"display":"inline","backgroundColor":"rgb(9,9,9)"}\' data-box="17,330,373,370">a</span><span data-cs=\'{"display":"inline"}\' data-box="17,340,373,360">b</span></p>'));
  try { assert.deepEqual(h.run().overlap, []); } finally { h.close(); }
});
test('a page without .hl-report-page is not measured', () => {
  const dom = new JSDOM('<p>x</p>', { runScripts: 'outside-only' });
  assert.match(JSON.parse(JSON.stringify(dom.window.eval(B.VIEW_EXPR))).notChecked, /no \.hl-report-page/);
});

test('the gate carries the two rows and the three controls, each restoring the old rule it is named for, and tabbedChecks calls them after the box-fit rows', () => {
  const src = fs.readFileSync(path.join(__dirname, '../check-browser-report.js'), 'utf8');
  assert.ok(src.includes('with each data view collapsed, no visible element of the view overlaps a painted sibling, on every tab at 1280 and 390 px'));
  assert.ok(src.includes('with each data view collapsed, a summary bar with rounded bottom corners has no visible sibling under it, on every tab at 1280 and 390 px'));
  assert.ok(/await boxFitRows\(page, url, opts\.html\);\n  await viewFitRows\(page, url, opts\.html\);/.test(src));
  assert.deepEqual(G.VIEW_CONTROLS.map(c => [c.key, c.vp[0], c.overlap, c.rounded]), [['overlap', 1280, false, true], ['rounded', 390, true, false], ['shipped', 390, false, false]]);
  assert.match(G.VIEW_CONTROLS[0].css, /\.hl-rv-curated\.hl-rv-curated \{ margin-top: -8px !important/);
  assert.match(G.VIEW_CONTROLS[1].css, /border-radius: 7px !important/);
  assert.equal(G.VIEW_CONTROLS[2].css, '\n' + G.VIEW_CONTROLS[0].css.slice(1) + G.VIEW_CONTROLS[1].css.slice(1));
});

test('CSS: the old rules are gone from the shipped sheet and the fixed ones are in it', () => {
  /* the old rules, written as the controls write them, must not be the sheet's own: the sheet's bar rule is conditional on a note being absent */
  assert.doesNotMatch(CSS, /^\.hl-rv-view-summary:has\(button\[aria-expanded="false"\]\) \{ border-bottom: 0; border-radius: 7px; \}/m);
  assert.match(CSS, /\.hl-rv-view:not\(:has\(> \.hl-rv-curated\)\) > \.hl-rv-view-summary:has\(button\[aria-expanded="false"\]\) \{ border-bottom: 0; border-radius: 7px; \}/);
  assert.match(CSS, /\.hl-rv-view > \.hl-rv-curated \{ padding: 0 var\(--rv-pad\) var\(--rv-pad\); margin: -8px 0 0 !important; \}/, 'the open view keeps the note 8px under its body');
  assert.match(CSS, /\.hl-rv-view:has\(> \.hl-rv-view-summary button\[aria-expanded="false"\]\) > \.hl-rv-curated \{ padding-top: 12px; margin-top: 0 !important; \}/);
});

/* fix2: viewVerdict never folds an unmeasured shown view or state into PASS. States are the in-page counts, declared directly. */
const GOODST = (label) => ({ label, views: 1, collapsed: 1, notCollapsed: 0, noBar: 0, withNote: 0, siblingPairs: 3, rounded: 0, roundedAlone: 0, overlap: [], roundedOver: [] });
test('fix2: a view with no bar beside a measured one gives NOT CHECKED on both rows, naming the count', () => {
  const st = [GOODST('a'), Object.assign(GOODST('b'), { views: 2, noBar: 1 })];
  ['overlap', 'rounded'].forEach(w => { const v = B.viewVerdict(st, w); assert.equal(v.notChecked, true); assert.equal(v.ok, false); assert.match(v.detail, /NOT MEASURED: 1 shown view\(s\) with no summary bar/); });
});
test('fix2: a view that was not collapsed beside a measured one gives NOT CHECKED', () => {
  const st = [GOODST('a'), Object.assign(GOODST('b'), { views: 2, notCollapsed: 2 })];
  const v = B.viewVerdict(st, 'overlap'); assert.equal(v.notChecked, true); assert.match(v.detail, /NOT MEASURED: 2 view\(s\) that were not collapsed/);
});
test('fix2: a bad state (never built, or views shown and none collapsed) gives NOT CHECKED; a state with zero shown views does not', () => {
  const dead = B.viewVerdict([GOODST('a'), { label: 'b', notChecked: 'controller never built' }], 'rounded');
  assert.equal(dead.notChecked, true); assert.match(dead.detail, /NOT MEASURED: 1 state/);
  const none = B.viewVerdict([GOODST('a'), { label: 'b', views: 2, collapsed: 0, notCollapsed: 0, noBar: 0 }], 'rounded');
  assert.equal(none.notChecked, true);
  const zero = B.viewVerdict([GOODST('a'), { label: 'c', views: 0, collapsed: 0, notCollapsed: 0, noBar: 0 }], 'rounded');
  assert.equal(zero.ok, true); assert.match(zero.detail, /1 state\(s\) showed no data view \(not a defect\)/);
});
test('fix2: all clean is PASS, and a fault beside a noBar view is still FAIL', () => {
  const clean = B.viewVerdict([GOODST('a'), GOODST('b')], 'overlap'); assert.equal(clean.ok, true); assert.equal(clean.notChecked, undefined);
  const faulty = Object.assign(GOODST('b'), { views: 2, noBar: 1, overlap: [{ kind: 'overlap', sig: 'p', other: 'div', by: 8, wide: 300, view: 'section.hl-rv-view' }] });
  const f = B.viewVerdict([GOODST('a'), faulty], 'overlap'); assert.equal(f.ok, false); assert.equal(f.notChecked, undefined); assert.equal(f.count, 1); assert.match(f.detail, /NOT MEASURED: 1 shown view/);
});
