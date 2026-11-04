'use strict';
/* T-0500.1.7.3 chunk c1 (design D, D1 and D2): the plate, the icon tabs, the tab title numeral, the "i" popovers (jsdom, the real script), and the
   pure verdicts of the new browser rows (numerals, plate column, popovers, hidden text) driven to FAIL by the measurement a broken layout gives. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');
const root = path.join(__dirname, '..', '..', '..');
const js = fs.readFileSync(path.join(root, 'assets/js/hl-report-tabs.js'), 'utf8');
const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];

function build(extraHeader) {
  const html = TOKENS.map(t => `<h2 class="hl-tab-${t}" id="${t}-source">${t === 'overview' ? 'Executive Summary' : t}</h2><p>${t === 'overview' ? 'First sentence of the lead. Second sentence of the lead has more words in it to be long. ' + 'filler word '.repeat(40) + 'End.' : 'Original ' + t + ' words.'}</p>`).join('');
  const dom = new JSDOM('<body><div class="hl-report-page"><div class="hl-post-header"><div class="hl-post-header__eyebrow"><span class="hl-post-header__badge">Malware</span></div><h1 class="hl-post-header__title">A title</h1>' + (extraHeader || '') + '</div>' +
    '<div class="hl-quicklinks"><a class="hl-quicklink" href="/d/"><span class="hl-quicklink__icon"></span><span class="hl-quicklink__label">Detections</span></a></div>' +
    '<div class="hl-post-body"><div class="hl-post-content">' + html + '</div></div></div></body>', { url: 'https://example.test/reports/x/', runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(js); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return { w, d: w.document };
}
test('JS: the plate carries meta, title, then a chrome bottom line cut at a sentence end (at most 60 words), and a button column: Read the full report, the page links, Share', () => {
  const f = build('<aside class="hl-rvsp hl-rvsp--report"></aside>'); try {
    const h = f.d.querySelector('.hl-post-header'); const kids = [...h.children].map(e => e.className.split(' ')[0]);
    assert.deepEqual(kids, ['hl-post-header__eyebrow', 'hl-post-header__title', 'hl-rv-bluf', 'hl-quicklinks', 'hl-rvsp'], 'meta, title, bottom line, button column, then the sponsor foot');
    const b = h.querySelector('.hl-rv-bluf'); assert.ok(b.hasAttribute('data-rv-chrome'));
    assert.match(b.textContent, /^First sentence of the lead\.( Second sentence)?/);
    assert.ok(b.textContent.split(/\s+/).length <= 60 || !/Second/.test(b.textContent), 'a lead over 60 words is cut at a sentence end');
    assert.equal(/End\.$/.test(b.textContent), false, 'the long tail is not copied');
    const labels = [...h.querySelectorAll('.hl-rv-actions .hl-quicklink__label')].map(e => e.textContent);
    assert.deepEqual(labels, ['Read the full report', 'Detections', 'Share']);
    assert.equal(h.querySelector('.hl-rv-read').getAttribute('href'), '#one-page');
    f.d.querySelector('.hl-rv-read').click();
  } finally { f.w.close(); }
});
test('JS: a BLUF section supplies the bottom line before the Executive Summary', () => {
  const dom = new JSDOM('<body><div class="hl-report-page"><div class="hl-post-header"><h1 class="hl-post-header__title">T</h1></div><div class="hl-post-body"><div class="hl-post-content"><h2 class="hl-tab-overview" id="a">Executive Summary</h2><p>Not this one.</p><h2 class="hl-tab-overview" id="b">BLUF: The Bottom Line</h2><p>This one is the bottom line.</p></div></div></div></body>', { url: 'https://example.test/r/', runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(js); try { assert.equal(w.document.querySelector('.hl-rv-bluf').textContent, 'This one is the bottom line.'); } finally { w.close(); }
});
test('JS: every tab is an icon box and a label with no numeral and no minutes; the tab title carries the outlined numeral of its place; the numeral is chrome and aria-hidden', () => {
  const f = build(); try {
    const tabs = [...f.d.querySelectorAll('[role=tab]')]; assert.equal(tabs.length, 7);
    tabs.forEach(t => { assert.ok(t.querySelector('.hl-rv-tab-icon svg'), t.id); assert.equal(/\d/.test(t.textContent), false, t.id + ' reads ' + t.textContent); assert.equal(t.querySelector('small, .hl-rv-tab-time'), null); });
    [...f.d.querySelectorAll('.hl-rv-panel-head')].forEach((h, i) => { const n = h.querySelector('.hl-rv-panel-num'); assert.equal(n.textContent, String(i + 1).padStart(2, '0')); assert.equal(n.getAttribute('aria-hidden'), 'true'); assert.ok(n.hasAttribute('data-rv-chrome')); });
    assert.equal(G.numeralVerdict(tabs.map(t => ({ id: t.id, text: t.textContent.trim(), digits: /\d/.test(t.textContent), minutes: !!t.querySelector('small') }))).ok, true);
  } finally { f.w.close(); }
});
const T = (o) => Object.assign({ id: 'tabbtn-overview', text: 'Overview', digits: false, minutes: false }, o || {});
test('the numeral verdict passes clean buttons and FAILS a digit, minutes, or nothing measured', () => {
  assert.equal(G.numeralVerdict([T(), T({ id: 'b', text: 'Attack chain' })]).ok, true);
  assert.match(G.numeralVerdict([T({ text: '01 Overview', digits: true })]).detail, /1 with a numeral/);
  assert.equal(G.numeralVerdict([T({ minutes: true })]).ok, false);
  assert.equal(G.numeralVerdict([]).notChecked, true);
});
const BTN = (label, t, o) => Object.assign({ label, l: 1100, t, r: 1300, b: t + 44, w: 200, h: 44 }, o || {});
const PLATE = (btns, o) => Object.assign({ present: true, iw: 1280, hdr: { l: 180, t: 90, r: 1320, b: 500 }, titleR: 1000, btns }, o || {});
test('the plate-column verdict passes the expected buttons in one column and FAILS a missing link, a different order, a short button, left-edge drift, overlap with the title, or an unreadable front matter', () => {
  const links = G.frontMatterLinks('---\ntitle: x\ndetection_page: /d/\nioc_feed: /i/\nstix_bundle: /s.json\n---\nbody');
  assert.deepEqual(links, { detect: true, ioc: true, stix: true });
  const exp = G.expectedPlateLabels(links, true); assert.deepEqual(exp, ['Read the full report', 'Detections', 'IOC Feed', 'STIX', 'MISP', 'Share']);
  const good = exp.map((l, i) => BTN(l, 100 + i * 50));
  assert.equal(G.plateColumnVerdict(PLATE(good), exp).ok, true, G.plateColumnVerdict(PLATE(good), exp).detail);
  assert.match(G.plateColumnVerdict(PLATE(good.filter(b => b.label !== 'Detections')), exp).detail, /but the page has/);
  assert.match(G.plateColumnVerdict(PLATE(good.slice().reverse()), exp).detail, /but the page has/);
  assert.match(G.plateColumnVerdict(PLATE(good.map(b => Object.assign({}, b, { h: 30 }))), exp).detail, /under 44/);
  assert.match(G.plateColumnVerdict(PLATE(good.map((b, i) => i === 2 ? Object.assign({}, b, { l: 1000 }) : b)), exp).detail, /not one column/);
  assert.match(G.plateColumnVerdict(PLATE(good.map(b => Object.assign({}, b, { l: 900, r: 1100 }))), exp).detail, /inside the title/);
  assert.match(G.plateColumnVerdict(PLATE(good.map((b, i) => Object.assign({}, b, { t: 100 + i * 20, b: 144 + i * 20 }))), exp).detail, /overlaps/);
  assert.equal(G.plateColumnVerdict(PLATE(good), null).notChecked, true);
  assert.equal(G.plateColumnVerdict({ present: false }, exp).notChecked, true);
  assert.equal(G.frontMatterLinks('no front matter'), null);
  assert.deepEqual(G.expectedPlateLabels({ detect: false, ioc: false, stix: false }, false), ['Read the full report', 'Share']);
});
const IROW = (o) => Object.assign({ i: 0, label: 'How counted: 5 orgs', tabIndex: 0, disabled: false, w: 44, h: 44, expanded: 'false', hasPop: true, popHidden: true, popTextLen: 80, popInReport: false, chrome: true }, o || {});
const BOXIN = { l: 20, t: 100, r: 380, b: 400 };
const P1 = (o) => Object.assign({ i: 0, keyOpened: true, tapOpened: true, escCloses: true, box: BOXIN, edgeOpened: true, edgeBox: { l: 20, t: 300, r: 380, b: 600 }, edgeRoom: 8 }, o || {});
const PROBE = (list) => ({ probes: list || [P1()], vw: 390, vh: 844 });
test('the popover verdict passes collapsed, named, focusable buttons that open by key and press and close on Escape, and FAILS each defect', () => {
  assert.equal(G.infoVerdict([IROW()], PROBE()).ok, true);
  const bad = (rows, probe, re) => { const v = G.infoVerdict(rows, probe); assert.equal(v.ok, false); assert.match(v.detail, re); };
  bad([IROW({ label: null })], PROBE(), /no accessible name/);
  bad([IROW({ tabIndex: -1 })], PROBE(), /cannot take focus/);
  bad([IROW({ w: 30 })], PROBE(), /under 44/);
  bad([IROW({ popHidden: false })], PROBE(), /not collapsed at rest/);
  bad([IROW({ popTextLen: 0 })], PROBE(), /not collapsed at rest/);
  bad([IROW({ popInReport: true })], PROBE(), /not generated chrome/);
  bad([IROW()], PROBE([P1({ keyOpened: false })]), /Enter on i #0 did not open/);
  bad([IROW()], PROBE([P1({ tapOpened: false })]), /pointer press on i #0/);
  bad([IROW()], PROBE([P1({ box: { l: 20, t: 100, r: 400, b: 400 } })]), /not inside the viewport/);
  bad([IROW()], PROBE([P1({ escCloses: false })]), /Escape did not close/);
  assert.equal(G.infoVerdict([], PROBE()).notChecked, true);
  bad([IROW()], null, /probe did not run/);
});
test('review F3: the popover verdict checks top and bottom as well as left and right, at the bottom edge too, and probes every button of the tab', () => {
  const bad = (rows, probe, re) => { const v = G.infoVerdict(rows, probe); assert.equal(v.ok, false, v.detail); assert.match(v.detail, re); };
  // the reviewer's case: a 390x844 viewport with the note at [12,900,378,1200] passed the old x-only test
  bad([IROW()], PROBE([P1({ box: { l: 12, t: 900, r: 378, b: 1200 } })]), /bottom 1200 in 390x844/);
  bad([IROW()], PROBE([P1({ box: { l: 12, t: -300, r: 378, b: 40 } })]), /top -300/);
  bad([IROW()], PROBE([P1({ edgeBox: { l: 12, t: 900, r: 378, b: 1200 } })]), /at the bottom edge of the screen is not inside the viewport/);
  bad([IROW()], PROBE([P1({ edgeOpened: false, edgeBox: null })]), /bottom edge of the screen did not open/);
  bad([IROW()], PROBE([P1({ box: null })]), /not drawn/);
  // every button: a second button that never opens fails although the first works
  const two = [IROW({ i: 0 }), IROW({ i: 1 })];
  assert.equal(G.infoVerdict(two, PROBE([P1({ i: 0 }), P1({ i: 1 })])).ok, true);
  bad(two, PROBE([P1({ i: 0 }), P1({ i: 1, keyOpened: false, tapOpened: false, box: null })]), /Enter on i #1 did not open/);
  bad(two, PROBE([P1({ i: 0 })]), /1 of the tab's 2 "i" buttons were probed/);
  const ok = G.infoVerdict(two, PROBE([P1({ i: 0 }), P1({ i: 1 })]));
  assert.match(ok.detail, /2 "i" button\(s\) measured, 2 probed; of those Enter opens 2, a press opens 2, inside the viewport on all four sides 2 \(centred\) and 2 \(at the bottom edge/);
  assert.equal(G.infoFits({ l: 0, t: 0, r: 390, b: 844 }, 390, 844), true); assert.equal(G.infoFits({ l: 0, t: 0, r: 390, b: 845 }, 390, 844), false);
});
test('the hidden-text verdict passes when every report block is drawn and FAILS when one is hidden, and is NOT CHECKED when nothing was measured', () => {
  assert.equal(G.textHiddenVerdict({ sections: 3, measured: 120, hidden: [], hiddenCount: 0 }).ok, true);
  const v = G.textHiddenVerdict({ sections: 3, measured: 120, hidden: ['P A hidden paragraph'], hiddenCount: 1 });
  assert.equal(v.ok, false); assert.match(v.detail, /1 hidden: P A hidden paragraph/);
  assert.equal(G.textHiddenVerdict({ sections: 0, measured: 0, hidden: [], hiddenCount: 0 }).notChecked, true);
});

test('the colour parser reads the color(srgb ...) form Chrome gives a color-mix(): a translucent tint is not a fill, a gold border is gold', () => {
  const t = (id, sel, bg, fg) => ({ id, selected: sel, color: sel ? 'rgb(255, 255, 255)' : 'rgb(214, 214, 214)', border: sel ? 'rgb(1, 2, 3)' : 'rgb(58, 58, 58)', hasIcon: true, iconW: 32, iconBg: bg, iconFg: fg });
  const tabs = [t('a', true, 'rgb(163, 113, 247)', 'rgb(17, 17, 17)'), ...['rgb(232,121,249)', 'rgb(251,146,60)', 'rgb(88,166,255)', 'rgb(34,211,238)', 'rgb(45,212,191)'].map((c, i) => t('b' + i, false, 'color(srgb 0.64 0.44 0.97 / 0.13)', c))];
  assert.equal(G.tabLookVerdict(tabs).ok, true, G.tabLookVerdict(tabs).detail);
  const filled = tabs.map((x, i) => i === 1 ? Object.assign({}, x, { iconBg: 'color(srgb 0.64 0.44 0.97 / 1)' }) : x);
  assert.match(G.tabLookVerdict(filled).detail, /translucent tint/);
  const band = { w: 1200, h: 68, border: 'color(srgb 0.721569 0.564706 0.184314 / 0.6)', borderW: 1, image: false, text: 'Featured sponsor', label: 'Featured sponsor', labelVisible: true, labelColor: 'rgb(244, 233, 200)', many: false, items: 1, withTagline: 1, taglines: [{ vis: true, len: 9 }], ctas: [{ vis: true, text: 'Visit →', ariaHidden: 'true', inLink: true, inside: true, tag: 'SPAN' }] };
  const v = G.featuredSponsorVerdict({ wide: false, reportSponsors: 0, siteItems: 1, band, featCard: null, foot: null, goldBandInDom: false, card: Object.assign({}, band, { isReport: false, label: "Featured sponsor of The Hunter's Ledger" }), markPresent: false });
  assert.equal(v.ok, true, v.detail);
});
