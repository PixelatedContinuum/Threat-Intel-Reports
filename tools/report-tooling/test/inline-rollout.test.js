'use strict';
/* T-0637 (p4): the inline-figures rollout to every published report. The browser gate's rows were written against two reports that both have a stage table and a chronology;
   older reports have neither, or have an ATT&CK table with spanned cells, or a chronology with a date that does not parse. Each row below is driven here on a small page
   in jsdom, in the shape that used to FAIL (now PASS or NOT CHECKED, with the reason), and a control that must still FAIL. The rows themselves run in a real browser. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');

function dom(body, inline) {
  const d = new JSDOM('<!doctype html><html><head><style>* { opacity: 1; }</style></head><body><div class="hl-report-page' + (inline ? ' hl-figs-inline' : '') + '">' + body + '</div></body></html>', { runScripts: 'outside-only', pretendToBeVisual: true });
  // jsdom has no layout: a box has area unless an ancestor is [hidden] or display:none, which is what the gate's expressions read
  d.window.Element.prototype.getBoundingClientRect = function () {
    for (let a = this; a; a = a.parentElement) { if (a.hasAttribute && a.hasAttribute('hidden')) return { width: 0, height: 0, left: 0, right: 0, top: 0, bottom: 0 }; const s = d.window.getComputedStyle(a); if (s.display === 'none') return { width: 0, height: 0, left: 0, right: 0, top: 0, bottom: 0 }; }
    return { width: 100, height: 20, left: 10, right: 110, top: 0, bottom: 20 };
  };
  Object.defineProperty(d.window.document.documentElement, 'clientWidth', { value: 1280 });
  return d.window;
}
const tbl = (heads, rows) => '<table><thead><tr>' + heads.map((h) => '<th>' + h + '</th>').join('') + '</tr></thead><tbody>' + rows.map((r) => '<tr>' + r.map((c) => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>';

test('no report text is hidden at rest: a generated popover note inside the report\'s section is not report text; a hidden authored paragraph still FAILS', () => {
  const body = '<section class="hl-rv-panel" id="tab-chain"><div class="hl-rv-source"><h2 id="a">A</h2><p>The report\'s own paragraph.</p>' +
    '<div class="hl-tbar"><button class="hl-rv-info">i</button><div class="hl-rv-pop" hidden><p class="hl-rv-pn-note">Stage filters use explicit procedure links only.</p></div></div><p>Another authored paragraph.</p></div></section>';
  const w = dom(body, true);
  const m = JSON.parse(JSON.stringify(w.eval(G.TEXT_HIDDEN_EXPR)));
  assert.equal(m.hiddenCount, 0, JSON.stringify(m)); assert.equal(m.skipped, 1);
  const v = G.textHiddenVerdict(m); assert.equal(v.ok, true); assert.match(v.detail, /1 generated popover note\(s\) left out/);
  // control: an authored paragraph hidden
  w.document.querySelector('.hl-rv-source > p').style.display = 'none';
  const c = G.textHiddenVerdict(JSON.parse(JSON.stringify(w.eval(G.TEXT_HIDDEN_EXPR)))); assert.equal(c.ok, false, 'the control must FAIL'); assert.match(c.detail, /1 hidden/);
  // control: a paragraph hidden INSIDE the popover class but not a popover is still measured (the exemption is the popover element, not the word)
  const w2 = dom('<section class="hl-rv-panel"><div class="hl-rv-source"><h2 id="a">A</h2><p class="hl-rv-pn-note" hidden>An authored paragraph that happens to carry the class.</p></div></section>', true);
  assert.equal(JSON.parse(JSON.stringify(w2.eval(G.TEXT_HIDDEN_EXPR))).hiddenCount, 1);
});

test('one-page "every block": the generated slim-bar anchor, facts line and filters are left out of the blocks on an inline page only; an authored block hidden still FAILS', () => {
  const body = '<section class="hl-rv-source"><h2 id="s">S</h2><p>Authored.</p><div class="hl-rv-minibar-anchor" style="display:none"></div><div class="hl-tbar-filters" style="display:none"></div><div class="hl-facts-block" style="display:none"></div></section>';
  const inl = JSON.parse(JSON.stringify(dom(body, true).eval(G.SECTION_RENDER_EXPR)));
  assert.deepEqual(inl.sections.s.bad, [], 'inline: generated elements are not authored blocks'); assert.equal(inl.generated, 3);
  const dash = JSON.parse(JSON.stringify(dom(body, false).eval(G.SECTION_RENDER_EXPR)));
  assert.equal(dash.sections.s.bad.length, 3, 'control: without the inline class nothing is left out');
  const w = dom(body, true); w.document.querySelector('.hl-rv-source > p').style.display = 'none';
  assert.equal(JSON.parse(JSON.stringify(w.eval(G.SECTION_RENDER_EXPR))).sections.s.bad.length, 1, 'control: an authored paragraph hidden');
});

test('linked tactic highlighting: NOT CHECKED when no stage node has a linked row (the dashboard draws no tactic button there); still measured when one has', () => {
  const node = (rows, tactics) => '<li><button class="hl-rv-fnode" data-rv-rows="' + rows + '" data-rv-tactics="' + tactics + '"></button></li>';
  const mk = (nodes) => '<section id="tab-chain"><div class="hl-rv-console"><button class="hl-rv-fchip" data-rv-facet="Tactic" data-rv-value="Execution"></button></div><ol class="hl-rv-flow">' + nodes + '</ol><p class="hl-rv-linkread"></p></section>';
  const none = G.lightVerdict(JSON.parse(JSON.stringify(dom(mk(node('', '') + node('', '')), true).eval(G.CHAINLIGHT_EXPR))), null);
  assert.equal(none.notChecked, true); assert.match(none.detail, /none linked to a procedure row/);
  const zero = G.lightVerdict(JSON.parse(JSON.stringify(dom(mk(''), true).eval(G.CHAINLIGHT_EXPR))), null);
  assert.equal(zero.notChecked, true, 'no stage table at all');
  const linked = JSON.parse(JSON.stringify(dom(mk(node('0,1', 'Execution') + node('', '')), true).eval(G.CHAINLIGHT_EXPR)));
  assert.equal(linked.tactic, 'Execution'); assert.deepEqual(linked.expect, [0]);
  assert.equal(G.lightVerdict(linked, null).ok, false, 'control: a linked stage that is not lit FAILS (nothing lit, one expected)');
  assert.equal(G.lightVerdict(Object.assign({}, linked, { lit: [0] }), { lit: [], litCards: [] }).ok, true);
  // the unflagged dashboard keeps its NOT CHECKED wording (no .hl-figs-inline, no tactic button)
  assert.equal(G.lightVerdict({ tactic: null }, null).notChecked, true);
});

test('placement row: a stage table headed Stage / What the operator does (or What happens) is a stage table; a chronology with a date that does not parse draws no timeline and the row says so', () => {
  const page = (stageHead, dates, drawn) => '<section class="hl-rv-panel" id="tab-chain"><div class="hl-rv-source"><h2 id="c">C</h2>' + tbl(['Stage', stageHead, 'Where'], [['1. A', 'x', 'y']]) + '</div></section>' +
    '<section class="hl-rv-panel" id="tab-timeline"><div class="hl-rv-source"><h2 id="t">T</h2>' + (drawn ? '<figure class="hl-fig hl-fig--timeline"><figcaption>c</figcaption><div class="hl-fig-draw"></div><p class="hl-fig-src">s</p></figure>' : '') + tbl(['Event', 'Timestamp'], dates.map((d, i) => ['e' + i, d])) + '</div></section>';
  for (const head of ['What the operator does', 'What happens', 'What the operator did']) {
    const m = JSON.parse(JSON.stringify(dom(page(head, ['2026-04-23 07:39:46 UTC', '80+'], false), true).eval(G.INLINE_EXPR)));
    assert.equal(m.found.stages, 0, head + ': the stage table is found'); assert.equal(m.found.chron, 1);
    assert.equal(m.chronParses, false);
  }
  const unparsed = JSON.parse(JSON.stringify(dom(page('What happens', ['2026-04-23 07:39:46 UTC', '80+'], false), true).eval(G.INLINE_EXPR)));
  const base = { figs: [], found: Object.assign({}, unparsed.found, { stages: null, attack: null }), facts: [], tiles: 0, rule: null, attribution: false, chronParses: false };
  const ok = G.inlinePlacementVerdict(base, { overview: { tiles: [] } }); assert.equal(ok.ok, true, ok.detail); assert.match(ok.detail, /timeline \(a date does not parse: none drawn\)/);
  const drawn = JSON.parse(JSON.stringify(base)); drawn.figs = [{ kind: 'timeline', next: 1, prevTag: 'P', prevText: '', capOk: true }];
  assert.equal(G.inlinePlacementVerdict(drawn, { overview: { tiles: [] } }).ok, false, 'control: a timeline drawn from a chronology that has an unplaceable date FAILS');
  // every date parses (ISO, or one year named in the table): a timeline is expected, so none drawn FAILS
  const parses = JSON.parse(JSON.stringify(dom(page('What happens', ['2026-04-23 07:39:46 UTC', '2026-04-26'], false), true).eval(G.INLINE_EXPR)));
  assert.equal(parses.chronParses, true);
  assert.equal(G.inlinePlacementVerdict(Object.assign({}, base, { chronParses: true }), { overview: { tiles: [] } }).ok, false, 'control: dates that parse and no timeline drawn FAILS');
  const oneYear = JSON.parse(JSON.stringify(dom(page('What happens', ['Oct 30, 2026', 'Oct 31 (inferred)'], false), true).eval(G.INLINE_EXPR)));
  assert.equal(oneYear.chronParses, true, 'month and day with a single year in the table parse, as the page reads them');
});

test('console rows: NOT CHECKED when the ATT&CK table has cells that span rows (the page draws no console on it); a table that lines up is measured', () => {
  const spanned = { panel: true, inline: true, attackAligned: false, console: false, chips: [], rows: 47 };
  const v = G.consoleVerdict(spanned, null, null, 47); assert.equal(v.notChecked, true); assert.match(v.detail, /cell that spans rows/);
  const t = G.inlineChainTableVerdict(spanned, 47); assert.equal(t.notChecked, true);
  const aligned = Object.assign({}, spanned, { attackAligned: true });
  assert.equal(G.consoleVerdict(aligned, null, null, 47).ok, false, 'control: an aligned table with no console FAILS'); assert.equal(G.inlineChainTableVerdict(aligned, 47).ok, false);
  // the dashboard rows are untouched by the flag
  assert.equal(G.consoleVerdict(Object.assign({}, spanned, { inline: false }), null, null, 47).notChecked, false);
});

test('the strip row exposes the gap pairs a factor of ten apart, which the equal-pitch control needs', () => {
  const mk = (hours) => { const cx = [22]; hours.forEach((h, i) => { cx[i + 1] = cx[i] + 44 + 4 + 6 * Math.log10(1 + h); });
    return { found: true, vw: 1280, figH: 286, vertical: false, lanes: 1, callout: false, pageOverflow: 0, dates: ['2026-01-01 00:00'].concat(hours.map((h, i) => '2026-01-01 ' + String(i + 1).padStart(2, '0') + ':00')), tableRows: hours.length + 1,
      strip: { h: 92, clientW: 1200, scrollW: 1200, ovx: 'auto' }, markers: cx.map((x, i) => ({ ev: i, cx: x, l: x - 22, r: x + 22, t: 100, b: 164, gapH: i ? 1 : null })), labels: [] }; };
  const v = G.inlineTimelineVerdict(mk([1, 1]));
  assert.equal(v.notChecked, false); assert.equal(v.grew, 0, 'two equal gaps: no pair a factor of ten apart'); assert.equal(v.gapsN, 2);
});

test('one-page mode and print bring back the rows the ATT&CK console hid in the report\'s own table (inline); the dashboard page keeps its own behaviour (control)', () => {
  const R = (flag) => {
    const dom = new JSDOM('<div class="hl-page hl-report-page' + (flag ? ' hl-figs-inline' : '') + '"><div class="hl-post-body"><div class="hl-post-content">' +
      '<h2 class="hl-tab-overview" id="s1">1. Summary</h2><p>Bottom line.</p><h2 class="hl-tab-chain" id="s3">2. MITRE ATT&amp;CK Mapping</h2>' +
      tbl(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Evidence'], [['Initial Access / T1190', 'Exploit Public-Facing Application', 'OBSERVED', 'HIGH', 'a'], ['Execution / T1059', 'Command Interpreter', 'INFERRED', 'MODERATE', 'b'], ['Persistence / T1053', 'Scheduled Task', 'OBSERVED', 'HIGH', 'c']]) +
      '</div></div></div>', { runScripts: 'outside-only', pretendToBeVisual: true });
    const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
    w.eval(require('node:fs').readFileSync(require('node:path').join(__dirname, '..', '..', '..', 'assets/js/hl-report-tabs.js'), 'utf8'));
    return w;
  };
  const w = R(true), d = w.document;
  try {
    const rows = [...d.querySelectorAll('#tab-chain .hl-rv-source table')].find((t) => /Tactic/.test(t.tHead.rows[0].cells[0].textContent)).tBodies[0].rows;
    const chip = [...d.querySelectorAll('#tab-chain .hl-rv-console .hl-rv-facets .hl-rv-fchip[data-rv-facet="Status"]')].find((c) => c.dataset.rvValue === 'INFERRED');
    chip.click(); assert.equal([...rows].filter((r) => r.hidden).length, 2, 'the chip hid two rows');
    w.location.hash = '#one-page'; w.dispatchEvent(new w.HashChangeEvent('hashchange'));
    assert.ok(d.documentElement.classList.contains('hl-onepage'));
    assert.equal([...rows].filter((r) => r.hidden).length, 0, 'one-page mode shows every row of the ATT&CK table');
    assert.equal(chip.getAttribute('aria-pressed'), 'false', 'and the console chip is back at rest');
    assert.equal(d.querySelector('.hl-rv-console .hl-rv-count').textContent, '', 'and the count line is empty');
  } finally { w.close(); }
  // control: the same page without the flag is the dashboard: its console filters its own generated copy and one-page mode does not touch that state (unchanged from before this task)
  const w2 = R(false), d2 = w2.document;
  try {
    const chip2 = [...d2.querySelectorAll('.hl-rv-console .hl-rv-facets .hl-rv-fchip[data-rv-facet="Status"]')].find((c) => c.dataset.rvValue === 'INFERRED');
    chip2.click(); assert.equal(chip2.getAttribute('aria-pressed'), 'true');
    w2.location.hash = '#one-page'; w2.dispatchEvent(new w2.HashChangeEvent('hashchange'));
    assert.equal(chip2.getAttribute('aria-pressed'), 'true', 'the dashboard console keeps its state, as before');
  } finally { w2.close(); }
});
