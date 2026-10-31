'use strict';
/* T-0500.1.9.1: the box-fit rows of the browser gate (lib/box-fit.js, boxFitRows in check-browser-report.js) and the CSS fixes they
   found. jsdom has no layout, so the in-page expression is run over a page whose boxes are DECLARED (data-box="left,top,right,bottom",
   data-cw/ch/sw/sh for client and scroll sizes): the expression's own logic is real, the geometry is stipulated. A live browser run of the
   same expression is the gate itself, with its three controls. */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const B = require('../lib/box-fit.js');
const G = require('../check-browser-report.js');
const SITE = path.join(__dirname, '../../..');
const CSS = fs.readFileSync(path.join(SITE, 'assets/css/hl-report-tabs.css'), 'utf8');

function layout(html) {
  const dom = new JSDOM('<body><div class="hl-report-page" data-box="0,0,400,2000">' + html + '</div></body>', { runScripts: 'outside-only' });
  const w = dom.window, E = w.Element.prototype, num = (el, k, d) => { const v = el.getAttribute(k); return v === null ? d : Number(v); };
  const box = (el) => { const v = el.getAttribute('data-box'); return v ? v.split(',').map(Number) : null; };
  E.getBoundingClientRect = function () { const b = box(this) || [0, 0, 0, 0]; return { left: b[0], top: b[1], right: b[2], bottom: b[3], width: b[2] - b[0], height: b[3] - b[1] }; };
  E.getClientRects = function () { return box(this) ? [this.getBoundingClientRect()] : []; };
  const def = (name, key, f) => Object.defineProperty(E, name, { configurable: true, get() { const b = box(this); return b ? num(this, key, f(b)) : 0; } });
  def('clientWidth', 'data-cw', b => b[2] - b[0]); def('clientHeight', 'data-ch', b => b[3] - b[1]);
  def('scrollWidth', 'data-sw', b => b[2] - b[0]); def('scrollHeight', 'data-sh', b => b[3] - b[1]);
  w.Range.prototype.getClientRects = function () { return []; };
  const real = w.getComputedStyle.bind(w);
  /* jsdom's cascade is partial (no text-overflow, a bare overflow shorthand), so a box may also declare data-cs='{"overflowX":"hidden",...}', laid over what jsdom computes */
  const PROPS = ['display', 'position', 'visibility', 'overflowX', 'overflowY', 'textOverflow', 'whiteSpace', 'marginLeft', 'marginRight', 'marginTop', 'marginBottom',
    'borderLeftWidth', 'borderRightWidth', 'borderTopWidth', 'borderBottomWidth', 'borderLeftStyle', 'borderRightStyle', 'borderTopStyle', 'borderBottomStyle',
    'borderLeftColor', 'borderRightColor', 'borderTopColor', 'borderBottomColor'];
  w.getComputedStyle = (el, pe) => {
    if (pe) return { content: 'none' };
    const r = real(el), o = {};
    PROPS.forEach(k => { o[k] = r[k]; });
    o.overflowX = o.overflowX || 'visible'; o.overflowY = o.overflowY || 'visible';
    return Object.assign(o, JSON.parse(el.getAttribute('data-cs') || '{}'));
  };
  return { w, run: () => JSON.parse(JSON.stringify(w.eval(B.EXPR))), close: () => w.close() };
}
const kinds = (m, key) => m[key].map(f => f.kind + ':' + f.sig);

test('the expression compiles and, on a page with no layout (jsdom), measures nothing and says NOT CHECKED, never a pass', () => {
  const dom = new JSDOM('<div class="hl-report-page"><p>x</p></div>', { runScripts: 'outside-only' });
  const m = JSON.parse(JSON.stringify(dom.window.eval(B.EXPR)));
  assert.equal(m.measured, 0);
  const v = B.verdict([Object.assign({ label: 'x' }, m)], 'hang');
  assert.equal(v.notChecked, true); assert.equal(v.ok, false);
  assert.equal(B.verdict([], 'bar').notChecked, true);
});
test('a page without .hl-report-page is not measured', () => {
  const dom = new JSDOM('<p>x</p>', { runScripts: 'outside-only' });
  assert.match(JSON.parse(JSON.stringify(dom.window.eval(B.EXPR))).notChecked, /no \.hl-report-page/);
});
test('a card whose children lie inside it has no hang-out and no short bar', () => {
  const f = layout('<div class="card" data-box="10,10,390,150" style="border-left:3px solid #f00"><p data-box="20,20,380,60">a</p><p data-box="20,70,380,140">b</p></div>');
  try { const m = f.run(); assert.ok(m.measured >= 3); assert.deepEqual(m.hang, []); assert.deepEqual(m.bars, []); assert.equal(m.barsMeasured, 1); } finally { f.close(); }
});
test('a child outside its parent is a hang-out on the side it leaves by; 1px is tolerated, 1.5px is not', () => {
  const f = layout('<div class="card" data-box="10,10,200,100"><p data-box="20,20,200.9,60">in</p><p class="out" data-box="20,60,260,90">out</p></div>');
  try { const m = f.run(); assert.deepEqual(kinds(m, 'hang'), ['out-of-parent:p.out']); assert.equal(m.hang[0].side, 'right'); assert.equal(m.hang[0].by, 60); } finally { f.close(); }
  const g = layout('<div class="card" data-box="10,10,200,100"><p class="t" data-box="20,20,201.5,60">x</p></div>');
  try { assert.deepEqual(kinds(g.run(), 'hang'), ['out-of-parent:p.t']); } finally { g.close(); }
});
test('a box whose content is wider or taller than it is a spill; 2px of line-box leading is not; a scroller is excluded and counted', () => {
  const f = layout('<div class="a" data-box="0,0,100,50" data-sw="250"></div>' +
    '<div class="b" data-box="0,60,100,110" data-sh="130"></div>' +
    '<div class="lead" data-box="0,120,100,170" data-sh="52"></div>' +
    '<div class="scroll" data-box="0,180,100,230" data-sw="900" data-cs="{&quot;overflowX&quot;:&quot;auto&quot;}"></div>');
  try {
    const m = f.run();
    assert.deepEqual(kinds(m, 'hang').sort(), ['spill-x:div.a', 'spill-y:div.b']);
    assert.equal(m.excluded['scroll container'], 1); assert.equal(m.scrollers, 1);
  } finally { f.close(); }
});
test('ellipsis truncation is excluded and counted, and a hidden clip without an ellipsis is a fault', () => {
  const f = layout('<span class="e" data-cs="{&quot;display&quot;:&quot;block&quot;,&quot;overflowX&quot;:&quot;hidden&quot;,&quot;textOverflow&quot;:&quot;ellipsis&quot;,&quot;whiteSpace&quot;:&quot;nowrap&quot;}" data-box="0,0,100,20" data-sw="300"></span>' +
    '<div class="c" data-cs="{&quot;overflowX&quot;:&quot;hidden&quot;}" data-box="0,30,100,50" data-sw="300"></div>');
  try { const m = f.run(); assert.deepEqual(kinds(m, 'hang'), ['clipped-x:div.c']); assert.equal(m.excluded.ellipsis, 1); } finally { f.close(); }
});
test('an accent edge shorter than its content is a short bar, with how far the content lies past it; a longer edge is not a fault', () => {
  const f = layout('<div class="card" data-box="10,10,390,54" style="border-left:3px solid #f00"><p data-box="20,10,380,60">t</p><p data-box="20,60,380,150">u</p></div>' +
    '<div class="roomy" data-box="10,200,390,300" style="border-left:3px solid #f00"><p data-box="20,210,380,240">t</p></div>');
  try {
    const m = f.run();
    assert.deepEqual(kinds(m, 'bars'), ['bar-short:div.card']);
    assert.equal(m.bars[0].barLen, 44); assert.equal(m.bars[0].after, 96); assert.equal(m.barsMeasured, 2);
  } finally { f.close(); }
});
test('a transparent or frame-like border is not an accent edge', () => {
  const f = layout('<div data-box="10,10,390,54" style="border-left:3px solid transparent"><p data-box="20,10,380,150">t</p></div>' +
    '<div data-box="10,200,390,244" style="border:3px solid #f00"><p data-box="20,210,380,230">t</p></div>');
  try { assert.equal(f.run().barsMeasured, 0); } finally { f.close(); }
});

const st = (label, extra) => Object.assign({ label, measured: 100, scrollers: 0, excluded: {}, hang: [], bars: [], barsMeasured: 5, stripsMeasured: 0 }, extra);
test('verdict: clean states PASS with the unit and the exclusions; a fault FAILS naming the deepest element first; an unmeasured state is reported', () => {
  const ok = B.verdict([st('1280x900 chain', { excluded: { ellipsis: 2, 'scroll container': 3 } }), st('390x844 chain', { excluded: { ellipsis: 1 } })], 'hang');
  assert.equal(ok.ok, true); assert.match(ok.detail, /^0 faults; 200 element measurements in 2 tab\/viewport states with every teardown open; excluded: 3 ellipsis, 3 scroll container/);
  const bad = B.verdict([st('390x844 chain', { hang: [{ kind: 'spill-y', sig: 'div.hl-post-body', path: 'div.hl-post-body', client: 10, scroll: 60 }, { kind: 'out-of-parent', sig: 'strong', path: 'nav.hl-rv-nextprev > a > strong', side: 'bottom', by: 25, parent: 'a' }] }), { label: '360x800', notChecked: 'never built' }], 'hang');
  assert.equal(bad.ok, false); assert.equal(bad.count, 2); assert.match(bad.detail, /^2 fault\(s\) in 2 place\(s\): 390x844 chain: strong \(nav\.hl-rv-nextprev > a > strong\): 25px past the bottom of its a \| 390x844 chain: div\.hl-post-body/);
  assert.match(bad.detail, /NOT MEASURED: 1 state\(s\)/);
});
test('verdict: the bar row counts edges and strips, and a short bar FAILS with its length and how far the content lies past it', () => {
  const ok = B.verdict([st('a', { barsMeasured: 7, stripsMeasured: 2 })], 'bar');
  assert.equal(ok.ok, true); assert.match(ok.detail, /7 accent edges and 2 pseudo-element strips/);
  const bad = B.verdict([st('390x844 chain', { bars: [{ kind: 'bar-short', sig: 'a', path: 'nav.hl-rv-nextprev > a', side: 'left', barLen: 44, before: 0, after: 77.6 }, { kind: 'strip-mismatch', sig: 'a::before', path: 'nav > a', side: 'vertical', barLen: 20, hostLen: 138 }] })], 'bar');
  assert.equal(bad.ok, false); assert.match(bad.detail, /its left edge is 44px long and its content lies 0px before and 77\.6px after it/); assert.match(bad.detail, /a vertical strip 20px long on a host 138px long/);
});
test('verdict: a repeated fault on the same element is one place', () => {
  const f = { kind: 'bar-short', sig: 'a', path: 'p > a', side: 'left', barLen: 44, before: 0, after: 9 };
  const v = B.verdict([st('390x844 chain', { bars: [f] }), st('390x844 chain', { bars: [f] })], 'bar');
  assert.equal(v.count, 2); assert.match(v.detail, /^2 fault\(s\) in 1 place\(s\)/);
});

test('the gate carries the two rows and three controls, each control naming the next/previous card and what each row must do', () => {
  const src = fs.readFileSync(path.join(__dirname, '../check-browser-report.js'), 'utf8');
  assert.ok(src.includes('no element on any tab hangs out of its box, at the five tab viewports with every teardown open'));
  assert.ok(src.includes('every accent edge is as long as the block it marks, at the five tab viewports with every teardown open'));
  assert.ok(/await boxFitRows\(page, url, opts\.html\);/.test(src), 'tabbedChecks calls the rows');
  assert.deepEqual(G.BOX_CONTROLS.map(c => [c.key, c.vp[0], c.hang, c.bar]), [['wide', 1280, false, true], ['short', 1280, true, false], ['shipped', 390, false, false]]);
  G.BOX_CONTROLS.forEach(c => assert.ok(c.css.includes('.hl-rv-nextprev a'), c.key));
});

test('CSS fix 1: in the column list (699px and below) a next/previous card takes its content\'s height, not flex 1 1 0 under a 44px floor', () => {
  const block = CSS.slice(CSS.indexOf('@media (max-width: 699px) {\n  html:has(.hl-report-page) { --rv-pad: 16px;'));
  const end = block.indexOf('\n}\n');
  const m = block.slice(0, end);
  assert.match(m, /\.hl-rv-nextprev \{ flex-direction: column; \}/);
  assert.match(m, /\.hl-report-page \.hl-rv-nextprev a \{ flex: 0 0 auto; \}/);
  assert.match(CSS, /\.hl-report-page \.hl-rv-nextprev a \{ flex: 1 1 0;/, 'the row layout keeps its equal columns');
});
test('CSS fix 2: an h3\'s 44px permalink target lies inside the h3 (10px of bottom padding, and top padding after an h2), the gap under it unchanged at 12px', () => {
  assert.match(CSS, /\.hl-rv-source h3 \{[^}]*margin: 36px 0 2px !important; padding-top: 24px !important; padding-bottom: 10px !important;/);
  assert.match(CSS, /\.hl-rv-source > h2 \+ h3 \{ margin-top: -10px !important; border-top: 0 !important; padding-top: 10px !important; \}/);
});
test('CSS fix 3: the first and last timeline date labels start and end at the rail ends, and a label has no 160px cap it overflows', () => {
  assert.match(CSS, /\.hl-rv-axis span:first-child \{ transform: none; text-align: left; \}/);
  assert.match(CSS, /\.hl-rv-axis span:last-child \{ transform: translateX\(-100%\); text-align: right; \}/);
  assert.doesNotMatch(CSS.match(/\.hl-rv-axis span \{[^}]*\}/)[0], /max-width/);
});
test('CSS fix 4: from 900px to 1179px the seven-column tab row uses 16px labels and 28px of left padding, and the 700 to 899px row is unchanged', () => {
  assert.match(CSS, /@media \(min-width: 900px\) and \(max-width: 1179px\) \{\n  \.hl-report-page \.hl-rv-tabs button \{ font-size: 16px; padding-left: 28px; \}\n\}/);
  assert.match(CSS, /@media \(min-width: 700px\) and \(max-width: 899px\) \{\n  \.hl-rv-tabs \{ display: flex; \}\n  \.hl-report-page \.hl-rv-tabs button \{ flex: 1 1 auto; white-space: nowrap; padding: 14px 6px 10px 24px; \}/);
});
