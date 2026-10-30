'use strict';
/* T-0500.1.7.1 (Joseph, 2026-10-30): larger timeline marks with a legend that takes the dots' colours, the MISP button in place of Share,
   and a share icon in the header box's corner. Static checks on the stylesheet,
   the script run in jsdom, and each browser-gate verdict driven with the measurement a broken layout would give (the browser itself is not
   driven here). See homelab-soc/docs/gate-honesty-contract.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');
const root = path.join(__dirname, '..', '..', '..');
const css = fs.readFileSync(path.join(root, 'assets/css/hl-report-tabs.css'), 'utf8');
const js = fs.readFileSync(path.join(root, 'assets/js/hl-report-tabs.js'), 'utf8');
const layout = fs.readFileSync(path.join(root, '_layouts/post.html'), 'utf8');
const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
function table(headers, rows) { return '<table><thead><tr>' + headers.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>'; }
const ROWS = [['2026-08-20', 'First'], ['2026-09-04 to 2026-09-14', 'Range event'], ['Sep 14 (year inferred)', 'Inferred event'], ['2026-10-01 (disputed)', 'Disputed event'], ['2026-10-14', 'Last']];
function page(phone) {
  const html = TOKENS.map(t => `<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2>` + (t === 'timeline' ? table(['Date', 'Observation'], ROWS) : `<p>Original ${t} words.</p>`)).join('');
  const dom = new JSDOM('<body><div class="hl-report-page"><div class="hl-post-header"><div class="hl-post-header__eyebrow"><span class="hl-post-header__badge">Intrusion</span></div><h1 class="hl-post-header__title">A title</h1><div class="hl-quicklinks"><button class="hl-quicklink" id="hl-detect-tab"><span class="hl-quicklink__label">Detections</span></button></div></div><div class="hl-post-body"><div class="hl-post-content">' + html + '</div></div></div></body>', { url: 'https://example.test/reports/x/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: !!phone, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {}; w.scrollTo = function () {};
  w.eval(js); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return { w, d: w.document };
}

/* ---- the timeline marks and the legend ---- */
test('CSS: the marks are 34px dots with 18px numbers on a desktop and 30px on a phone, and --mark is the one place a status colour is chosen', () => {
  assert.match(css, /\.hl-rv-timeline \{ min-width: 0; --rv-dot: 34px; --rv-num: 18px; --rv-mark-h: 64px; --rv-swatch: 18px; \}/);
  assert.match(css, /@media \(max-width: 699px\) \{\s*\.hl-rv-timeline \{ --rv-dot: 30px; --rv-mark-h: 60px;/);
  assert.match(css, /\.hl-rv-given \{ --mark: var\(--rv-ok\); \}/);
  assert.match(css, /\.hl-rv-year-inferred, \.hl-rv-range \{ --mark: var\(--rv-warn\); \}/);
  assert.match(css, /\.hl-rv-disputed \{ --mark: var\(--rv-bad\); \}/);
  assert.match(css, /\.hl-rv-symbol \{[^}]*width: var\(--rv-dot\); height: var\(--rv-dot\);[^}]*background: var\(--mark, var\(--rv-ok\)\);/);
  assert.match(css, /\.hl-rv-marker > span:last-child \{ font-size: var\(--rv-num\);/);
  assert.match(css, /\.hl-rv-rail \{ position: relative; height: var\(--rv-mark-h\);/);
});
test('CSS: no rule paints the legend swatches grey; they read --mark like the dots', () => {
  const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}@]+)\{([^{}]*)\}/g)].map(m => [m[1].trim(), m[2]]);
  const legendPaint = rules.filter(([sel, decl]) => /hl-rv-timeline-legend[^,]*hl-rv-symbol/.test(sel) && /(^|[;\s])(background|color)\s*:/.test(decl));
  assert.deepEqual(legendPaint.map(r => r[0]), [], 'a rule that paints a legend swatch would let it drift from the dots');
});
test('JS: the legend has the four status swatches, each carrying its quality class; markers and list items carry theirs; the numbers are real elements', () => {
  const f = page(); try {
    const items = [...f.d.querySelectorAll('.hl-rv-timeline-legend .hl-rv-legend-item')];
    assert.deepEqual(items.map(i => [...i.classList].find(c => /^hl-rv-(given|year-inferred|range|disputed)$/.test(c))), ['hl-rv-given', 'hl-rv-year-inferred', 'hl-rv-range', 'hl-rv-disputed']);
    assert.ok(items.every(i => i.querySelector('.hl-rv-symbol') && i.querySelector('.hl-rv-symbol').textContent === ''), 'swatches are drawn shapes, not text glyphs');
    assert.equal(items.map(i => i.textContent).join('|'), 'Given date|Inferred year|Range|Disputed');
    const markers = [...f.d.querySelectorAll('.hl-rv-marker')];
    assert.equal(markers.length, ROWS.length);
    assert.deepEqual(markers.map(m => [...m.classList].find(c => /^hl-rv-(given|year-inferred|range|disputed)$/.test(c))), ['hl-rv-given', 'hl-rv-range', 'hl-rv-year-inferred', 'hl-rv-disputed', 'hl-rv-given']);
    assert.ok(markers.every(m => m.querySelector(':scope > .hl-rv-symbol') && /^\d+$/.test(m.lastElementChild.textContent)));
    assert.ok(markers.every(m => m.querySelector(':scope > .hl-rv-symbol').textContent === ''), 'the mark is a drawn shape, not a text glyph');
    const vlist = [...f.d.querySelectorAll('.hl-rv-vertical-marker')];
    assert.deepEqual(vlist.map(m => [...m.classList].find(c => /^hl-rv-(given|year-inferred|range|disputed)$/.test(c))), markers.map(m => [...m.classList].find(c => /^hl-rv-(given|year-inferred|range|disputed)$/.test(c))));
    assert.equal(vlist[0].querySelector('.hl-rv-vnum').textContent, '1.');
    assert.equal(vlist[0].textContent.replace(/\s+/g, ' ').startsWith('1. First'), true, 'the list item still reads "1. First"');
  } finally { f.w.close(); }
});
test('JS: the mark height the placement uses is read from the stylesheet variable, not a second constant', () => {
  assert.match(js, /getPropertyValue\('--rv-mark-h'\)/);
  assert.equal(/slot \* 52|\* 52 - 8/.test(js), false, 'the old 52px slot is gone');
});

/* ---- Share becomes MISP; the share icon ---- */
test('Liquid: the MISP link is the same lookup and markup normal reports use; the tabbed layout adds nothing of its own', () => {
  assert.ok(layout.includes('{%- assign _misp_ev = site.data.misp_events.events | where: "report_url", page.url | first -%}'));
  assert.ok(layout.includes('<a class="hl-quicklink" href="{{ _misp_ev.event_url }}" target="_blank" rel="noopener noreferrer" aria-label="MISP event for this report (JSON, from the MISP feed)">'));
  assert.equal(/hl_tabbed[^\n]*misp/i.test(layout), false, 'no tabbed-only MISP branch');
});
test('JS: the Share button is gone from the resource row; the share icon is built into the header box, labelled, with a live region', () => {
  const f = page(); try {
    assert.equal(f.d.querySelector('.hl-share-btn'), null);
    assert.equal(/hl-share-btn/.test(js), false);
    const b = f.d.querySelector('.hl-post-header > .hl-rv-share > button.hl-rv-share-btn');
    assert.ok(b); assert.equal(b.getAttribute('aria-label'), 'Share this report'); assert.equal(b.type, 'button');
    assert.ok(b.querySelector('svg[aria-hidden="true"]'));
    const live = f.d.querySelector('.hl-rv-share [role="status"][aria-live="polite"]'); assert.ok(live); assert.equal(live.textContent, '');
    assert.ok(f.d.querySelector('.hl-rv-share').hasAttribute('data-rv-chrome'), 'chrome, so no report word changes');
    assert.equal(f.d.querySelector('.hl-quicklinks').querySelectorAll('.hl-rv-share-btn').length, 0);
  } finally { f.w.close(); }
});
test('JS: with no share sheet a click writes the page address to the clipboard and says "Link copied"; with one it calls it and does not copy', async () => {
  const f = page(); try {
    const writes = [], shares = [];
    Object.defineProperty(f.w.navigator, 'clipboard', { value: { writeText: t => { writes.push(t); return Promise.resolve(); } }, configurable: true });
    f.d.querySelector('.hl-rv-share-btn').click();
    await new Promise(r => f.w.setTimeout(r, 20));
    assert.deepEqual(writes, ['https://example.test/reports/x/']);
    assert.equal(f.d.querySelector('.hl-rv-share-status').textContent, 'Link copied');
    Object.defineProperty(f.w.navigator, 'share', { value: d => { shares.push(d.url); return Promise.resolve(); }, configurable: true });
    f.d.querySelector('.hl-rv-share-btn').click();
    await new Promise(r => f.w.setTimeout(r, 20));
    assert.deepEqual(shares, ['https://example.test/reports/x/']); assert.equal(writes.length, 1, 'no second copy when the share sheet took it');
    assert.equal(/fetch\(|XMLHttpRequest|sendBeacon|utm_/.test(js.slice(js.indexOf('// Share: a 44px icon'), js.indexOf("root.classList.add('hl-rv-ready')"))), false, 'it sends and tracks nothing');
  } finally { f.w.close(); }
});
test('CSS: the share icon is a 44px button in the header corner and the eyebrow keeps clear of it; "Link copied" is drawn only while it has text', () => {
  assert.match(css, /\.hl-report-page \.hl-rv-share \{ position: absolute; top: 8px; right: 8px; z-index: 2; \}/);
  assert.match(css, /\.hl-report-page \.hl-rv-share-btn \{[^}]*width: 44px; height: 44px; padding: 0;/);
  assert.match(css, /\.hl-report-page \.hl-post-header__eyebrow \{[^}]*padding-right: 52px;/);
  assert.match(css, /\.hl-report-page \.hl-post-header \{[^}]*padding: 22px 24px 24px 20px; margin: 0 0 24px; position: relative;/);
  assert.match(css, /\.hl-report-page \.hl-rv-share-status:not\(:empty\) \{ padding: 6px 12px;/);
  assert.equal(/hl-share-btn/.test(css), false, 'the old Share button styling is gone');
});

/* ---- the gate verdicts ---- */
const SHARE = (over) => Object.assign({ header: true, hdr: { l: 360, t: 94, r: 1560, b: 260, w: 1200, h: 166 }, present: true, shareStillThere: false, btn: { l: 1508, t: 102, r: 1552, b: 146, w: 44, h: 44 }, label: 'Share this report', tag: 'BUTTON', type: 'button', disabled: false, tabIndex: 0, inHeader: true, checked: 6, overlaps: [], live: true, liveText: '', focused: true, outlineStyle: 'solid', outlineWidth: 2, focusVisible: true }, over || {});
test('the share icon verdict passes the built geometry and FAILS each defect', () => {
  assert.equal(G.shareGeometryVerdict(SHARE()).ok, true, G.shareGeometryVerdict(SHARE()).detail);
  const bad = (over, re) => { const v = G.shareGeometryVerdict(SHARE(over)); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ present: false }, /no share icon button/);
  bad({ shareStillThere: true }, /old Share button is still/);
  bad({ label: 'Share' }, /aria-label is "Share"/);
  bad({ tag: 'DIV' }, /not a type=button button/);
  bad({ btn: { l: 1508, t: 102, r: 1540, b: 134, w: 32, h: 32 } }, /under 44/);
  bad({ btn: { l: 100, t: 102, r: 144, b: 146, w: 44, h: 44 }, inHeader: false }, /not inside the header box/);
  bad({ btn: { l: 900, t: 102, r: 944, b: 146, w: 44, h: 44 } }, /not in the top-right corner/);
  bad({ overlaps: ['hl-post-header__title'] }, /overlaps hl-post-header__title/);
  bad({ tabIndex: -1, focused: false }, /cannot take keyboard focus/);
  bad({ outlineStyle: 'none', outlineWidth: 0 }, /no visible focus ring/);
  bad({ live: false }, /no aria-live status region/);
  assert.equal(G.shareGeometryVerdict({ header: false }).notChecked, true);
});
test('the share behaviour verdict passes copy and share, and FAILS a wrong address, a missing or unseen "Link copied", and a copy beside the share sheet', () => {
  const B = (over) => Object.assign({ href: 'https://x/r/', writes: ['https://x/r/'], status: 'Link copied', statusVisible: true, shares: [{ url: 'https://x/r/', title: 't' }], writesAfterShare: 1 }, over || {});
  assert.equal(G.shareBehaviourVerdict(B()).ok, true);
  const bad = (over, re) => { const v = G.shareBehaviourVerdict(B(over)); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ writes: [] }, /clipboard got/);
  bad({ writes: ['https://other/'] }, /clipboard got/);
  bad({ status: '' }, /not "Link copied"/);
  bad({ statusVisible: false }, /not drawn in view/);
  bad({ shares: [] }, /share sheet present it was called with/);
  bad({ writesAfterShare: 2 }, /clipboard was written as well/);
});
test('the MISP verdict: the button when the data has an event, nothing when it has none, never Share', () => {
  const href = 'https://misp.example/event.json';
  const M = (over) => Object.assign({ count: 1, shareStillThere: false, found: true, href, target: '_blank', rel: 'noopener noreferrer', label: 'MISP event for this report (JSON, from the MISP feed)', cls: 'hl-quicklink hl-cta', visible: true, w: 100, h: 44, inHeader: true, inRow: true, icon: true }, over || {});
  const none = { count: 0, shareStillThere: false, found: false, w: 0, h: 0 };
  assert.equal(G.mispVerdict(M(), href, '/reports/x/').ok, true);
  const v = G.mispVerdict(none, null, '/reports/x/'); assert.equal(v.ok, true); assert.equal(v.none, true); assert.match(v.detail, /0 buttons expected, 0 drawn/);
  const bad = (m, exp, re) => { const r = G.mispVerdict(m, exp, '/reports/x/'); assert.equal(r.ok, false); assert.match(r.detail, re); };
  bad(none, href, /no MISP button is drawn/);
  bad(M(), null, /has no event for/);
  bad(M({ shareStillThere: true }), href, /old Share button is still/);
  bad(M({ href: 'https://other/' }), href, /links to https:\/\/other\//);
  bad(M({ rel: '' }), href, /new tab with noopener/);
  bad(M({ cls: 'hl-cta' }), href, /not the normal report markup/);
  bad(M({ inHeader: false }), href, /not in the header box/);
  bad(M({ h: 30 }), href, /under 44/);
  bad(M({ count: 2 }), href, /2 MISP buttons/);
  assert.equal(G.mispVerdict(none, undefined, '/reports/x/').notChecked, true);
  assert.equal(typeof G.mispEventFor('/reports/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/'), 'string', 'the pilot report has an event in _data/misp_events.yml');
  assert.equal(G.mispEventFor('/reports/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-tabbed-preview/'), null, 'the preview URL has none');
});
const GREEN = 'rgb(74, 222, 128)', AMBER = 'rgb(250, 204, 21)', RED = 'rgb(248, 113, 113)';
const TL = (over) => Object.assign({ vw: 1280, horizontal: true, dotCount: 10, dotMin: 34, numMin: 18, numCount: 10, marks: [{ l: 0, t: 0, r: 44, b: 64 }, { l: 60, t: 0, r: 104, b: 64 }], axis: [{ l: 0, t: 100, r: 80, b: 120 }], kinds: { given: GREEN, 'year-inferred': AMBER, range: AMBER, disputed: RED }, refs: { given: GREEN, 'year-inferred': AMBER, range: AMBER, disputed: RED },
  legend: [['given', GREEN], ['year-inferred', AMBER], ['range', AMBER], ['disputed', RED]].map(p => ({ q: p[0], found: true, visible: true, paint: p[1], w: 18, h: 18 })), events: 10, markerTotal: 10, dated: 10, tableRows: 10 }, over || {});
test('the timeline verdict passes large marks and FAILS small dots, small numbers, overlaps and missing events', () => {
  assert.equal(G.timelineVerdict(TL()).ok, true, G.timelineVerdict(TL()).detail);
  assert.equal(G.timelineVerdict(TL({ vw: 390, horizontal: false, dotMin: 26, markerTotal: 0 })).ok === false, true, 'a phone list still counts the swim-lane marks: 0 of 10 is a missing mark');
  assert.equal(G.timelineVerdict(TL({ vw: 390, horizontal: false, dotMin: 26, markerTotal: 10 })).ok, true);
  assert.equal(G.timelineVerdict(TL({ vw: 600, dotMin: 30 })).ok, true, 'a phone-width swim lane may be 30');
  const bad = (over, re) => { const v = G.timelineVerdict(TL(over)); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad({ dotMin: 22 }, /smallest mark is 22\.0 px \(at least 32/);
  bad({ vw: 390, horizontal: false, dotMin: 16 }, /at least 24/);
  bad({ numMin: 16 }, /smallest event number is 16 px/);
  bad({ numMin: null }, /no event number was measured/);
  bad({ marks: [{ l: 0, t: 0, r: 44, b: 64 }, { l: 30, t: 10, r: 80, b: 70 }] }, /1 pair\(s\) of marks overlap/);
  bad({ axis: [{ l: 10, t: 40, r: 80, b: 70 }] }, /overlap a date label/);
  bad({ markerTotal: 9 }, /9 swim-lane mark/);
  bad({ events: 9 }, /9 dated list item/);
  bad({ dated: 8 }, /8 of 10 list items carry their date/);
  assert.equal(G.timelineVerdict(TL({ dotCount: 0 })).notChecked, true);
});
test('the legend verdict passes matching colours and FAILS grey, black, a drifted colour, a missing swatch and a tiny one', () => {
  assert.equal(G.legendVerdict(TL()).ok, true, G.legendVerdict(TL()).detail);
  const withLegend = (fn) => { const m = TL(); m.legend = m.legend.map(fn); return G.legendVerdict(m); };
  assert.match(withLegend(i => i.q === 'given' ? Object.assign({}, i, { paint: 'rgb(168, 168, 168)' }) : i).detail, /given swatch is rgb\(168, 168, 168\) but its dots are/);
  assert.match(withLegend(i => i.q === 'disputed' ? Object.assign({}, i, { paint: 'rgb(0, 0, 0)' }) : i).detail, /disputed swatch/);
  assert.match(withLegend(i => i.q === 'range' ? Object.assign({}, i, { paint: GREEN }) : i).detail, /range swatch is rgb\(74, 222, 128\) but its dots are/);
  assert.match(withLegend(i => i.q === 'range' ? Object.assign({}, i, { found: false }) : i).detail, /range swatch is missing/);
  assert.match(withLegend(i => Object.assign({}, i, { w: 6, h: 6 })).detail, /swatch is 6x6 px/);
  /* no dot of a kind on this report: the swatch is compared with the status colour the dots would take */
  const noRange = TL(); noRange.kinds.range = null; assert.equal(G.legendVerdict(noRange).ok, true);
  noRange.legend.find(i => i.q === 'range').paint = RED; assert.match(G.legendVerdict(noRange).detail, /range swatch is rgb\(248, 113, 113\), not the status colour/);
  assert.equal(G.legendVerdict(null).notChecked, true);
});
test('the gate measures through browser expressions that name the elements the verdicts read', () => {
  for (const sel of ['.hl-rv-share-btn', '.hl-post-header__eyebrow', '[role=status][aria-live]']) assert.ok(G.SHARE_EXPR.includes(sel), sel);
  for (const sel of ['.hl-quicklinks a.hl-quicklink', '.hl-share-btn']) assert.ok(G.MISP_EXPR.includes(sel), sel);
  for (const sel of ['.hl-rv-marker > .hl-rv-symbol', '.hl-rv-timeline-legend .hl-rv-legend-item', '.hl-rv-chronology-table tbody tr', '.hl-rv-vnum']) assert.ok(G.TIMELINE_EXPR.includes(sel), sel);
});
