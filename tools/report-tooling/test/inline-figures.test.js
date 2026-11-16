'use strict';
/* T-0637: figures in the text (front matter `figures: inline`). Static checks on the layout switch, the two flagged previews and the stylesheet's scope, a jsdom run of
   hl-report-tabs.js on a small tabbed report with and without the flag (the unflagged page is the control: it keeps its band and draws no figure), and the verdict
   functions of the inline rows in check-browser-report.js driven to PASS and to FAIL. The rows themselves run in a real browser (new-report-gates.sh). */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const script = read('assets/js/hl-report-tabs.js');
const css = read('assets/css/hl-report-tabs.css');
const G = require('../check-browser-report.js');
const PREVIEWS = ['inv-2026-082-agent-platform-command-channel', 'inv-2026-083-federal-ad-credential-access-rig'];
const frontMatter = (md) => md.split(/\n---\n/)[0];

test('the layout adds hl-figs-inline to every tabbed report page unless it says figures: dashboard, and nowhere else', () => {
  // Joseph, 2026-11-15: the inline figures go live on the whole site; `figures: dashboard` is the per-report way back.
  const layout = read('_layouts/post.html');
  assert.match(layout, /hl-report-page\{% unless page\.figures == 'dashboard' %\} hl-figs-inline\{% endunless %\}/);
  assert.equal((layout.match(/hl-figs-inline/g) || []).length, 1, 'one place sets the class');
  assert.equal(/figures/.test(read('_includes/default/head.liquid')), false, 'the head include does not read the switch');
});

test('no report opts back to the dashboard (site rollout, Joseph 2026-11-15); the two first previews still say figures: inline', () => {
  const optedOut = fs.readdirSync(path.join(root, 'reports')).filter((d) => {
    const f = path.join(root, 'reports', d, 'index.md');
    return fs.existsSync(f) && /^figures: dashboard$/m.test(frontMatter(fs.readFileSync(f, 'utf8')));
  });
  assert.deepEqual(optedOut, []);
  for (const d of PREVIEWS) assert.match(frontMatter(read('reports/' + d + '/index.md')), /^figures: inline$/m, d);
});

test('the cache-busters moved with the stylesheet and the script (both carry the same value)', () => {
  const a = read('_layouts/post.html').match(/hl-report-tabs\.js' \| relative_url \}\}\?v=([0-9.]+)/)[1];
  const b = read('_includes/default/head.liquid').match(/hl-report-tabs\.css' \| relative_url \}\}\?v=([0-9.]+)/)[1];
  assert.equal(a, b); assert.equal(a, '20261116.1');
});

test('every rule the inline block adds to the stylesheet is scoped under .hl-figs-inline, so no other report can see it', () => {
  const at = css.lastIndexOf('/*', css.indexOf('T-0637: figures in the text'));
  assert.ok(at > 0, 'the block is marked');
  const block = css.slice(at).replace(/\/\*[\s\S]*?\*\//g, '');
  const preludes = [...block.matchAll(/([^{}]+)\{/g)].map((m) => m[1].trim()).filter((p) => !/^@/.test(p));
  assert.ok(preludes.length > 40, 'the block has rules (' + preludes.length + ')');
  for (const pre of preludes) {
    for (const sel of pre.split(/,(?![^(]*\))/).map((x) => x.trim()).filter(Boolean)) {
      assert.match(sel, /^(\.hl-onepage )?\.hl-report-page\.hl-figs-inline\b/, 'unscoped selector: ' + sel);
    }
  }
});

test('the stylesheet\'s inline block sets no text under the 15px floor and no monospace on a figure caption or source line', () => {
  const block = css.slice(css.lastIndexOf('/*', css.indexOf('T-0637: figures in the text'))).replace(/\/\*[\s\S]*?\*\//g, '');
  for (const m of block.matchAll(/font-size:\s*(\d+(?:\.\d+)?)px/g)) assert.ok(+m[1] >= 15, 'font-size ' + m[0]);
  const cap = block.match(/\.hl-fig > figcaption \{[^}]*\}/)[0]; assert.equal(/mono/.test(cap), false);
  const src = block.match(/\.hl-fig > \.hl-fig-src \{[^}]*\}/)[0]; assert.equal(/mono/.test(src), false);
});

const TAB = (tok, id, title, body) => `<h2 class="hl-tab-${tok}" id="${id}">${title}</h2>${body}`;
const TABLE = (heads, rows) => '<table><thead><tr>' + heads.map((h) => `<th>${h}</th>`).join('') + '</tr></thead><tbody>' + rows.map((r) => '<tr>' + r.map((c) => `<td>${c}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
const REPORT = [
  TAB('overview', 's1', '1. Executive Summary', '<p>The operator got in and stayed three weeks. This is the bottom line.</p>'),
  TAB('victims', 's2', '2. Victims: Who Was Hit', '<p>Graded one row each.</p><p>Of the 3 rows, the grades are 1 ACCESS SHOWN, 1 COMPROMISED, 1 REACHED and 0 LISTED.</p>' + TABLE(['Organisation', 'Grade', 'What the files show'], [['Dept A', 'ACCESS SHOWN', 'x'], ['Org B', 'COMPROMISED', 'y'], ['Org C', 'REACHED', 'z']])),
  TAB('chain', 's3', '3. The Attack Chain', '<p>Three stages.</p>' + TABLE(['Stage', 'What the operator did', 'Where it is shown'], [['1. Mint a token', 'It minted a token.', 'a'], ['2. Relay', 'It relayed.', 'b']]) +
    '<h2 class="hl-tab-chain" id="s3b">4. MITRE ATT&amp;CK Mapping</h2>' + TABLE(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Evidence'], [['Initial Access / T1190', 'Exploit Public-Facing Application', 'OBSERVED', 'HIGH', 'e1'], ['Execution / T1059', 'Command Interpreter', 'INFERRED', 'MODERATE', 'e2'], ['Execution / T1059.004', 'Unix Shell', 'OBSERVED', 'HIGH', 'e3']])),
  TAB('timeline', 's4', '5. Timeline', '<p>Dates are UTC.</p>' + TABLE(['Date', 'Observation'], [['2026-10-30', 'First request'], ['2026-11-02', 'Second request'], ['2026-11-14', 'Last request']])),
  TAB('attribution', 's5', '6. Threat Actor Assessment', '<p>I hold the operator as unidentified.</p>' + TABLE(['Hypothesis', 'Where it stands'], [['A broker', 'Not supported'], ['A crew', 'Open']])),
  TAB('indicators', 's6', '7. Indicators of Compromise', '<p>Sixteen indicators.</p>' + TABLE(['Indicator', 'What it is', 'Confidence', 'Action'], [['198.51.100.7', 'server', 'HIGH', 'block'], ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hash', 'HIGH', 'hunt'], ['C:\\\\Temp\\\\x.exe', 'path', 'LOW', 'hunt']])) +
    '<h2 class="hl-tab-indicators" id="s6b">8. Detection and Hunting Guidance</h2><p>The package carries 3 rules: 1 Sigma (1 detection, 0 hunting) and 2 YARA (1 detection, 1 hunting).</p>',
  TAB('confidence', 's7', '9. Confidence Summary', '<p>Each judgment carries its confidence.</p>' + TABLE(['Claim', 'Confidence', 'What would change it'], [['The server is the operator\'s', 'HIGH', 'a record'], ['It is one crew', 'MODERATE', 'a second case'], ['The date is the first use', 'HIGH', 'an earlier log']]))
].join('');
function page(flag, report, curation) {
  const dom = new JSDOM(`<div class="hl-page hl-report-page${flag ? ' hl-figs-inline' : ''}"><div class="hl-post-body"><div class="hl-post-content">${report || REPORT}</div></div>${curation ? '<script id="hl-report-view-data" type="application/json">' + JSON.stringify(curation) + '</script>' : ''}</div>`, { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  const articleTables = w.document.querySelectorAll('.hl-post-content table').length;
  const articleText = w.document.querySelector('.hl-post-content').textContent.replace(/\s+/g, '');
  w.eval(script);
  assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'), 'the script built the page');
  return { dom, w, d: w.document, articleTables, articleText };
}
const nextTable = (d, el) => [...d.querySelectorAll('.hl-rv-source table')].find((t) => el.compareDocumentPosition(t) & 4);
const heads = (t) => [...t.tHead.rows[0].cells].map((c) => c.textContent);

test('inline page: no band, no card, every report table once, each figure directly before the table it is drawn from', () => {
  const f = page(true);
  try {
    const d = f.d;
    assert.equal(d.querySelectorAll('.hl-rv-view, .hl-rv-tile, .hl-rv-view-summary, .hl-rv-skip-view').length, 0, 'no generated band');
    assert.equal([...d.querySelectorAll('table')].filter((t) => !t.closest('.hl-rv-source')).length, 0, 'no table outside the report\'s sections');
    assert.equal(d.querySelectorAll('.hl-rv-source table').length, f.articleTables, 'one table per report table');
    const kinds = [...d.querySelectorAll('figure.hl-fig')].map((x) => x.className.replace('hl-fig ', ''));
    assert.deepEqual(kinds.sort(), ['hl-fig--chain', 'hl-fig--diamond', 'hl-fig--dist', 'hl-fig--grades', 'hl-fig--heat', 'hl-fig--rules', 'hl-fig--timeline'].sort());
    const before = (cls) => heads(nextTable(d, d.querySelector('figure.' + cls))).join('|');
    assert.match(before('hl-fig--chain'), /^Stage\|/);
    assert.match(before('hl-fig--heat'), /^Tactic \/ Technique\|/);
    assert.match(before('hl-fig--timeline'), /^Date\|/);
    assert.match(before('hl-fig--dist'), /^Claim\|/);
    // the grade strip follows the tally paragraph
    assert.match(d.querySelector('figure.hl-fig--grades').previousElementSibling.textContent, /1 ACCESS SHOWN, 1 COMPROMISED, 0 LISTED|\d+ ACCESS SHOWN.*\d+ LISTED/);
    // the diamond follows the first statement of the attribution section; the rule counts follow the detection paragraph (the section has no table)
    assert.equal(d.querySelector('figure.hl-fig--diamond').previousElementSibling.tagName, 'P');
    assert.match(d.querySelector('figure.hl-fig--rules').previousElementSibling.textContent, /carries 3 rules/);
    // the facts line opens the Overview panel, under the bottom line, with the report's own tile values
    const fb = d.querySelector('#tab-overview .hl-facts-block');
    assert.ok(fb.previousElementSibling.classList.contains('hl-rv-panel-head'));
    const vals = [...fb.querySelectorAll('.hl-fact strong')].map((x) => x.textContent);
    assert.deepEqual(vals, JSON.parse(JSON.stringify(f.w.eval(G.SHAPES_EXPR).overview.tiles)));
    // every figure: a caption first, a source line last, chrome, and no number in the caption
    for (const fig of d.querySelectorAll('figure.hl-fig')) {
      assert.equal(fig.firstElementChild.tagName, 'FIGCAPTION'); assert.ok(fig.lastElementChild.classList.contains('hl-fig-src'));
      assert.ok(fig.hasAttribute('data-rv-chrome') && fig.hasAttribute('data-pagefind-ignore'));
      assert.equal(/^Figure \d/i.test(fig.firstElementChild.textContent), false);
    }
    // the report's own words are unchanged: the sections minus generated chrome read as the article read
    const clone = d.createElement('div'); [...d.querySelectorAll('.hl-rv-source')].forEach((s) => clone.appendChild(s.cloneNode(true)));
    clone.querySelectorAll('[data-rv-chrome]').forEach((n) => n.remove());
    assert.equal(clone.textContent.replace(/\s+/g, ''), f.articleText);
  } finally { f.w.close(); }
});

test('control: the same report without the flag keeps its band, draws no figure and no facts line', () => {
  const f = page(false);
  try {
    assert.ok(f.d.querySelectorAll('.hl-rv-view').length >= 5, 'the dashboard band is built');
    assert.equal(f.d.querySelectorAll('figure.hl-fig, .hl-facts-block, .hl-tbar, .hl-tbar-chip').length, 0);
    assert.ok(f.d.querySelectorAll('.hl-rv-table').length >= 5, 'and it still redraws the tables');
  } finally { f.w.close(); }
});

test('inline page: the grade chips sit in one toolbar with Copy table above the victims table, filter its rows, and one-page mode brings them back', () => {
  const f = page(true);
  try {
    const d = f.d, vt = [...d.querySelectorAll('#tab-victims .hl-rv-source table')][0];
    const bar = vt.closest('.hl-rv-source-table').previousElementSibling;
    assert.ok(bar.classList.contains('hl-tbar') && bar.classList.contains('hl-rv-table-tools'));
    assert.ok([...bar.querySelectorAll('button')].some((b) => b.textContent === 'Copy table'), 'copy joined the toolbar');
    const chips = [...bar.querySelectorAll('.hl-tbar-chip')]; assert.deepEqual(chips.map((c) => c.dataset.rvValue), ['', 'ACCESS SHOWN', 'COMPROMISED', 'REACHED']);
    assert.equal(chips.map((c) => +c.querySelector('strong').textContent).join(','), '3,1,1,1');
    const rows = [...vt.tBodies[0].rows];
    chips[2].click();
    assert.deepEqual(rows.map((r) => r.hidden), [true, false, true]);
    assert.match(bar.querySelector('.hl-tbar-count').textContent, /^Showing 1 of 3 /);
    chips[2].click();
    assert.deepEqual(rows.map((r) => r.hidden), [false, false, false]); assert.equal(bar.querySelector('.hl-tbar-count').textContent, '');
    chips[1].click(); assert.equal(rows.filter((r) => r.hidden).length, 2);
    f.w.location.hash = '#one-page'; f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));
    assert.ok(d.documentElement.classList.contains('hl-onepage'));
    assert.equal(rows.filter((r) => r.hidden).length, 0, 'one-page mode shows every row');
    assert.ok([...chips].every((c) => c.getAttribute('aria-pressed') === String(c.dataset.rvValue === '')), 'and the chips are back at All');
  } finally { f.w.close(); }
});

test('inline page: the ATT&CK table gets the filter console in its own toolbar; a Status chip filters it and a second press clears it', () => {
  const f = page(true);
  try {
    const d = f.d, at = [...d.querySelectorAll('#tab-chain .hl-rv-source table')].find((t) => /Tactic/.test(heads(t)[0]));
    const bar = at.closest('.hl-rv-source-table').previousElementSibling;
    assert.ok(bar.querySelector('.hl-rv-console'), 'the console is on the report\'s own table');
    assert.equal(bar.querySelector('.hl-rv-console h3'), null, 'no panel title: it is a toolbar');
    const rows = [...at.tBodies[0].rows], status = [...bar.querySelectorAll('.hl-rv-facets .hl-rv-fchip[data-rv-facet="Status"]')];
    assert.equal(status.map((c) => c.dataset.rvValue + c.querySelector('strong').textContent).join(','), 'OBSERVED2,INFERRED1');
    status[1].click(); assert.deepEqual(rows.map((r) => r.hidden), [true, false, true]);
    status[1].click(); assert.equal(rows.filter((r) => r.hidden).length, 0);
    // a story procedure chip's target is a row of the report's own table
    const chip = d.querySelector('figure.hl-fig--chain a.hl-rv-procedure');
    if (chip) assert.match(chip.getAttribute('href'), /^#hl-rv-procedures-\d+$/);
  } finally { f.w.close(); }
});

test('inline page: the Indicators tab has the type filter on the indicator table and no chips list, no copied detection paragraph', () => {
  const f = page(true);
  try {
    const it = [...f.d.querySelectorAll('#tab-indicators .hl-rv-source table')][0], bar = it.closest('.hl-rv-source-table').previousElementSibling;
    assert.deepEqual([...bar.querySelectorAll('.hl-tbar-chip')].map((c) => c.dataset.rvValue), ['', 'IP', 'Hash', 'Path']);
    assert.equal(f.d.querySelectorAll('#tab-indicators .hl-rv-chips, #tab-indicators .hl-rv-feed-count, #tab-indicators .hl-rv-note').length, 0);
    assert.match(f.d.querySelector('figure.hl-fig--rules .hl-fig-line').textContent, /Sigma: 1 rules, 1 detection, 0 hunting; YARA: 2 rules, 1 detection, 1 hunting/);
  } finally { f.w.close(); }
});

test('the browser gate\'s inline rows, run on the jsdom page: placement, once, counts and toolbars PASS; each control FAILS', () => {
  const f = page(true);
  try {
    const shapes = JSON.parse(JSON.stringify(f.w.eval(G.SHAPES_EXPR)));
    const m = JSON.parse(JSON.stringify(f.w.eval(G.INLINE_EXPR)));
    const vp = G.inlinePlacementVerdict(m, shapes); assert.equal(vp.ok, true, vp.detail);
    const vo = G.inlineOnceVerdict(m, f.articleTables); assert.equal(vo.ok, true, vo.detail);
    const counts = G.inlineCountsVerdicts(m, shapes); assert.ok(counts.length >= 5, counts.length + ' count rows'); counts.forEach((c) => assert.equal(c.v.ok, true, c.name + ': ' + c.v.detail));
    const tb = JSON.parse(JSON.stringify(f.w.eval(G.INLINE_TOOLBAR_EXPR))).filter((r) => r.chips.length); const vt = G.inlineToolbarVerdict(tb); assert.equal(vt.ok, true, vt.detail);
    // controls
    assert.equal(G.inlineOnceVerdict(m, f.articleTables + 1).ok, false, 'a missing table');
    assert.equal(G.inlineOnceVerdict(Object.assign({}, m, { outside: 1 }), f.articleTables).ok, false, 'a table drawn outside the sections');
    const moved = JSON.parse(JSON.stringify(m)); moved.figs.find((x) => x.kind === 'heat').next = -1;
    assert.equal(G.inlinePlacementVerdict(moved, shapes).ok, false, 'a figure not before its table');
    const missing = JSON.parse(JSON.stringify(m)); missing.figs = missing.figs.filter((x) => x.kind !== 'grades');
    assert.equal(G.inlinePlacementVerdict(missing, shapes).ok, false, 'a figure the report\'s table supports is missing');
    const orphan = JSON.parse(JSON.stringify(m)); orphan.found.attack = null;
    assert.equal(G.inlinePlacementVerdict(orphan, shapes).ok, false, 'a heat map drawn with no ATT&CK table');
    const sq = JSON.parse(JSON.stringify(m)); sq.grade.REACHED = 0;
    assert.equal(G.inlineCountsVerdicts(sq, shapes).find((c) => /grade strip/.test(c.name)).v.ok, false, 'a square short');
    const hc = JSON.parse(JSON.stringify(m)); hc.heat.cells -= 1;
    assert.equal(G.inlineCountsVerdicts(hc, shapes).find((c) => /heat map/.test(c.name)).v.ok, false, 'a heat cell short');
    const rr = JSON.parse(JSON.stringify(tb)); rr[0].chips[1].n += 1;
    assert.equal(G.inlineToolbarVerdict(rr).ok, false, 'chip counts that do not add up');
    assert.equal(G.inlineToolbarVerdict(tb, [{ bi: 0, v: 'x', want: 1, rows: 3, shown: 3, count: '', pressedChips: 1 }]).ok, false, 'a press that shows every row');
    assert.equal(G.inlineToolbarVerdict([]).notChecked, true, 'no toolbar: NOT CHECKED, not PASS');
    assert.equal(G.inlineChainTableVerdict({ panel: true, rows: 3, hiddenRows: 1, attached: true, dashCopies: 0, marks: 0 }, 3).ok, false);
    assert.equal(G.inlineChainTableVerdict({ panel: true, rows: 3, hiddenRows: 0, attached: true, dashCopies: 0, marks: 0 }, 3).ok, true);
    assert.equal(G.inlineChainTableVerdict({ panel: true, rows: 3, hiddenRows: 0, attached: true, dashCopies: 1, marks: 0 }, 3).ok, false, 'a second copy of the table');
    assert.equal(G.inlineChainTableVerdict({ panel: true, rows: 0 }, 0).notChecked, true);
  } finally { f.w.close(); }
});

test('the inline anatomy row FAILS on a figure that is not a panel, has a large radius or a shadow, a number, no source line or text under the floor', () => {
  const ok = { kind: 'grades', capOk: true, srcOk: true, chrome: true, style: { bg: 'rgb(24, 24, 24)', bt: 1, bb: 1, bl: 1, br: 1, rad: '6px', shadow: 'none' }, capPx: 18, srcPx: 15, capFont: 'IBM Plex Sans', srcFont: 'IBM Plex Sans', capTop: 10, drawTop: 40, srcTop: 90, cap: '2 rows by grade' };
  assert.equal(G.inlineAnatomyVerdict({ figs: [ok] }).ok, true);
  const bad = (patch) => G.inlineAnatomyVerdict({ figs: [Object.assign({}, ok, patch)] });
  assert.equal(bad({ style: Object.assign({}, ok.style, { bl: 0, br: 0, bb: 0 }) }).ok, false, 'one hairline above only: not a panel');
  assert.equal(bad({ style: Object.assign({}, ok.style, { bg: 'rgba(0, 0, 0, 0)' }) }).ok, false, 'no fill');
  assert.equal(bad({ style: Object.assign({}, ok.style, { rad: '16px' }) }).ok, false, 'a large radius');
  assert.equal(bad({ style: Object.assign({}, ok.style, { shadow: 'rgba(0, 0, 0, 0.5) 0px 2px 8px' }) }).ok, false, 'a shadow');
  assert.equal(bad({ cap: 'Figure 2: grades' }).ok, false, 'a number that would collide with the author\'s');
  assert.equal(bad({ srcOk: false }).ok, false, 'no source line');
  assert.equal(bad({ srcPx: 13 }).ok, false, 'under the floor');
  assert.equal(bad({ srcFont: 'IBM Plex Mono' }).ok, false, 'monospace');
  assert.equal(G.inlineAnatomyVerdict({ figs: [] }).notChecked, true);
});

// ---- p1b: the four taste fixes -------------------------------------------------------------------------------------------------------------------------------------------
const TL_OLD = TAB('timeline', 's4', '5. Timeline', '<p>Dates are UTC.</p>' + TABLE(['Date', 'Observation'], [['2026-10-30', 'First request'], ['2026-11-02', 'Second request'], ['2026-11-14', 'Last request']]));
assert.ok(REPORT.includes(TL_OLD), 'the fixture report still carries the three-row timeline the p1b tests replace');
// 9 events: a range 6 years back, a 4 year gap, then the busy day (minutes and hours apart), a day, then 10 days
const TL_ROWS = [['2016-03-04 to 2017-03-20', 'cert one'], ['2022-04-13', 'cert two'], ['2026-10-29 01:02:19', 'chisel starts'], ['2026-10-29 01:49:16', 'HEAD test'], ['2026-10-29 01:50:05', 'egress hit'],
  ['2026-10-29 08:57:00', 'capture servers live'], ['2026-10-30 09:55', 'media address'], ['2026-11-01 to 2026-11-04', 'a range inside the days'], ['2026-11-14', 'still open']];
const timelineReport = (rows) => REPORT.replace(TL_OLD, TAB('timeline', 's4', '5. Timeline', '<p>Dates are UTC.</p>' + TABLE(['Date', 'Observation'], rows)));
const px = (el) => parseFloat(el.style.left);

test('inline timeline: one strip of markers in report order, none stacked, no axis and no vertical list; the unflagged page keeps its date-axis lanes (control)', () => {
  const f = page(true, timelineReport(TL_ROWS));
  try {
    const d = f.d, fig = d.querySelector('figure.hl-fig--timeline');
    const mk = [...fig.querySelectorAll('.hl-rv-marker')];
    assert.equal(mk.length, TL_ROWS.length, 'one marker for every chronology row');
    assert.deepEqual(mk.map((b) => +b.dataset.rvEvent), TL_ROWS.map((_, i) => i), 'in report order');
    const xs = mk.map(px);
    assert.ok(xs.every((x, i) => i === 0 || x - xs[i - 1] >= 44 + 4 - 0.01), 'a 44 px slot and at least the 4 px minimum between neighbours: ' + xs.join(','));
    assert.equal(fig.querySelectorAll('.hl-strip').length, 1); assert.equal(fig.querySelectorAll('.hl-rv-axis, .hl-rv-vertical-timeline').length, 0, 'no axis, no vertical list');
    assert.equal(fig.querySelectorAll('.hl-rv-lane').length, 0, 'no empty lane band: a single lane has no lane label');
    assert.equal(fig.querySelector('.hl-strip-track').style.width, (xs[xs.length - 1] + 22 + 4) + 'px');
    // every marker keeps its shape class and its select-to-read behaviour
    assert.deepEqual(mk.map((b) => b.className.replace('hl-rv-marker ', '')), ['hl-rv-range', 'hl-rv-given', 'hl-rv-given', 'hl-rv-given', 'hl-rv-given', 'hl-rv-given', 'hl-rv-given', 'hl-rv-range', 'hl-rv-given']);
    mk[5].click(); assert.match(fig.querySelector('.hl-rv-event').textContent, /^2026-10-29 08:57:00 · Chronology · given: capture servers live$/);
    assert.equal(fig.querySelectorAll('.hl-rv-event-active').length, 1);
    // the source line says what the spacing is
    assert.match(fig.querySelector('.hl-fig-src').textContent, /spacing is not a linear date axis/); assert.match(fig.querySelector('.hl-fig-src').textContent, /6 hours or more/);
  } finally { f.w.close(); }
  const c = page(false, timelineReport(TL_ROWS));
  try {
    assert.ok(c.d.querySelector('.hl-rv-axis'), 'the unflagged page still draws its date axis'); assert.ok(c.d.querySelector('.hl-rv-vertical-timeline'));
    assert.equal(c.d.querySelectorAll('.hl-strip, .hl-strip-gap').length, 0);
    assert.ok([...c.d.querySelectorAll('.hl-rv-marker')].every((b) => /%$/.test(b.style.left)), 'and positions its markers by percent of the date range');
  } finally { c.w.close(); }
});

test('inline timeline: the gap between neighbours grows with the time between them, never below the minimum, and a label says how long from 6 hours up', () => {
  const f = page(true, timelineReport(TL_ROWS));
  try {
    const mk = [...f.d.querySelectorAll('figure.hl-fig--timeline .hl-rv-marker')], xs = mk.map(px);
    const hours = TL_ROWS.map((r, i) => i ? (Date.parse(stampOf(r[0]) + 'Z') - Date.parse(stampOf(TL_ROWS[i - 1][0]) + 'Z')) / 3600000 : null);
    const gaps = xs.map((x, i) => i ? x - xs[i - 1] - 44 : null);
    // monotone: a longer time is never a narrower gap
    for (let a = 1; a < gaps.length; a++) for (let b = 1; b < gaps.length; b++) if (Math.abs(hours[a]) < Math.abs(hours[b])) assert.ok(gaps[a] <= gaps[b] + 0.001, `gap ${a} (${hours[a]} h) is ${gaps[a]} px, gap ${b} (${hours[b]} h) is ${gaps[b]} px`);
    // and it really widens: 4 years against 1 minute
    assert.ok(gaps[2] > gaps[4] + 20, 'four years is drawn much wider than one minute: ' + gaps[2] + ' against ' + gaps[4]);
    // labels: the gaps of 6 hours or more, in the table's own figures
    const labels = [...f.d.querySelectorAll('figure.hl-fig--timeline .hl-strip-gap')].map((g) => [+g.dataset.rvGapFor, g.textContent]);
    assert.deepEqual(labels, [[1, '+6 yr'], [2, '+5 yr'], [5, '+7 h'], [6, '+1 d'], [7, '+2 d'], [8, '+13 d']]);
    // each label is centred between its two markers
    for (const g of f.d.querySelectorAll('figure.hl-fig--timeline .hl-strip-gap')) { const i = +g.dataset.rvGapFor; assert.equal(px(g), (xs[i - 1] + xs[i]) / 2); }
    // no two labels can overlap: neighbouring labelled gaps are far enough apart for the longest label text (8 px a character, 15 px sans)
    const L = [...f.d.querySelectorAll('figure.hl-fig--timeline .hl-strip-gap')].map((g) => ({ c: px(g), w: g.textContent.length * 8 }));
    L.forEach((l, i) => { if (i) assert.ok(l.c - L[i - 1].c >= (l.w + L[i - 1].w) / 2 + 4, 'labels ' + (i - 1) + ' and ' + i + ' clear of each other'); });
  } finally { f.w.close(); }
});
function stampOf(display) { const m = display.match(/(\d{4}-\d{2}-\d{2})(?:[ T]+(\d{2}:\d{2}(?::\d{2})?))?/); return m[1] + 'T' + (m[2] || '00:00'); }

test('inline timeline: curated lanes keep working as rows of one strip sharing the same x positions, and the callout band covers the markers of its window', () => {
  const cur = { timeline_lanes: { rules: [{ label: 'Victim side', pattern: 'HEAD|egress' }], default: 'Operator' }, timeline_callout: { from: '2026-10-29', to: '2026-10-29', label: 'Hands-on window', text: 'Five events in one day.' } };
  const f = page(true, timelineReport(TL_ROWS), cur);
  try {
    const fig = f.d.querySelector('figure.hl-fig--timeline');
    const lanes = [...fig.querySelectorAll('.hl-strip-lane')];
    assert.deepEqual(lanes.map((l) => l.querySelector('h3').textContent), ['Operator', 'Victim side']);
    const per = lanes.map((l) => [...l.querySelectorAll('.hl-rv-marker')].map((b) => +b.dataset.rvEvent));
    assert.deepEqual(per, [[0, 1, 2, 5, 6, 7, 8], [3, 4]]);
    assert.equal(fig.querySelectorAll('.hl-rv-marker').length, TL_ROWS.length, 'every event drawn once');
    const xs = [...fig.querySelectorAll('.hl-rv-marker')].sort((a, b) => a.dataset.rvEvent - b.dataset.rvEvent).map(px);
    assert.ok(xs.every((x, i) => !i || x - xs[i - 1] >= 44), 'one shared x scale: no two events share a slot, in any lane');
    assert.equal(fig.querySelectorAll('.hl-rv-lane-swatch').length, 2, 'two lanes: the lane key is shown');
    // the callout: a band over the markers of the five events of 2026-10-29 (events 2 to 5), in px inside the scrolling track, and its own zoom rail
    const band = fig.querySelector('.hl-rv-callout-band'); assert.ok(band && band.closest('.hl-strip-track'), 'the band is inside the scrolling track');
    assert.equal(parseFloat(band.style.left), xs[2] - 22 - 4); assert.equal(parseFloat(band.style.width), xs[5] - xs[2] + 44 + 8);
    assert.equal(fig.querySelectorAll('.hl-rv-zmark').length, 4, 'the zoom rail redraws the 4 events inside the window');
    assert.match(fig.querySelector('.hl-rv-callout h4').textContent, /Hands-on window/);
  } finally { f.w.close(); }
  const one = page(true, timelineReport(TL_ROWS));
  try { assert.equal(one.d.querySelectorAll('figure.hl-fig--timeline .hl-rv-lane-swatch').length, 0, 'one lane needs no key'); } finally { one.w.close(); }
});

test('the browser gate\'s strip row: PASS on a drawn strip, FAIL on each fault (overlap, reverse order, equal pitch, a missing or wrong label, a missing marker, a tower, a stray vertical list), NOT CHECKED on nothing', () => {
  const rows = TL_ROWS.map((r) => r[0]);
  const hrs = rows.map((r, i) => i ? (Date.parse(stampOf(r) + 'Z') - Date.parse(stampOf(rows[i - 1]) + 'Z')) / 3600000 : null);
  const gapPx = (h) => 4 + 6 * Math.log10(1 + Math.abs(h));
  const cx = [22]; hrs.forEach((h, i) => { if (i) cx[i] = cx[i - 1] + 44 + gapPx(h); });
  const good = () => ({ found: true, vw: 1280, figH: 286, vertical: false, lanes: 1, callout: false, pageOverflow: 0, dates: rows.slice(), tableRows: rows.length,
    strip: { h: 92, clientW: 1200, scrollW: Math.round(cx[cx.length - 1] + 22), ovx: 'auto' },
    markers: cx.map((x, i) => ({ ev: i, cx: x, l: x - 22, r: x + 22, t: 100, b: 164, gapH: hrs[i] })),
    labels: hrs.map((h, i) => (i && Math.abs(h) >= 6) ? { forEv: i, text: G.inlineGapWords(h), gapH: h, l: (cx[i - 1] + cx[i]) / 2 - 16, r: (cx[i - 1] + cx[i]) / 2 + 16, t: 70, b: 90 } : null).filter(Boolean) });
  const v = G.inlineTimelineVerdict(good()); assert.equal(v.ok, true, v.detail);
  const bad = (edit) => { const m = good(); edit(m); return G.inlineTimelineVerdict(m); };
  assert.equal(bad((m) => { m.markers[3].l = m.markers[2].l; m.markers[3].r = m.markers[2].r; m.markers[3].cx = m.markers[2].cx; }).ok, false, 'two markers on top of each other');
  assert.equal(bad((m) => { m.markers.forEach((x, i) => { x.cx = 22 + 60 * (m.markers.length - 1 - i); x.l = x.cx - 22; x.r = x.cx + 22; }); }).ok, false, 'reverse order');
  assert.equal(bad((m) => { m.markers.forEach((x, i) => { x.cx = 22 + 60 * i; x.l = x.cx - 22; x.r = x.cx + 22; }); }).ok, false, 'an equal pitch: it does not widen with time');
  assert.equal(bad((m) => { m.labels.pop(); }).ok, false, 'a long gap without its label');
  assert.equal(bad((m) => { m.labels.push({ forEv: 3, text: '+1 h', gapH: hrs[3], l: 0, r: 10, t: 0, b: 10 }); }).ok, false, 'a label on a short gap');
  assert.equal(bad((m) => { m.labels[0].text = '+9 yr'; }).ok, false, 'a label that says something else than the table');
  assert.equal(bad((m) => { m.markers.pop(); }).ok, false, 'a marker short of the chronology rows');
  assert.equal(bad((m) => { m.strip.h = 900; }).ok, false, 'a tower of a strip'); assert.equal(bad((m) => { m.figH = 1655; }).ok, false, 'a 1,655 px figure');
  assert.equal(bad((m) => { m.vertical = true; }).ok, false, 'a vertical list still shown');
  assert.equal(bad((m) => { m.pageOverflow = 40; }).ok, false, 'a page that scrolls sideways');
  assert.equal(bad((m) => { m.strip.scrollW = 1500; m.strip.ovx = 'visible'; }).ok, false, 'a strip wider than its box that does not scroll');
  assert.equal(bad((m) => { m.markers[1].gapH = 3; }).ok, false, 'an elapsed-time value that is not the table\'s');
  assert.equal(bad((m) => { m.labels[2].l = m.labels[1].l; m.labels[2].r = m.labels[1].r; m.labels[2].t = m.labels[1].t; m.labels[2].b = m.labels[1].b; }).ok, false, 'two labels on top of each other');
  assert.equal(bad((m) => { m.lanes = 2; m.figH = 450; }).ok, true, 'two lanes: the whole-figure bound is not applied, the strip bound is');
  assert.equal(G.inlineTimelineVerdict({ found: false }).notChecked, true); assert.equal(G.inlineTimelineVerdict({ found: true, markers: [] }).notChecked, true);
  // the words: hours under a day, days under two months, months under two years, then years; a backward gap carries a minus
  assert.deepEqual([4 * 8760 + 40, 36, 7, 150 * 24, 30 * 24, 6, 14 * 24, -72].map(G.inlineGapWords), ['+4 yr', '+2 d', '+7 h', '+5 mo', '+30 d', '+6 h', '+14 d', '-3 d']);
});

test('heat map hues: the inline heat map uses the badges\' three status variables (green, yellow, grey), the dashboard\'s keeps its own (control)', () => {
  const f = page(true);
  try {
    const cells = [...f.d.querySelectorAll('figure.hl-fig--heat .hl-rv-cell:not(.hl-rv-cell--sw)')];
    const hue = (e) => e.style.getPropertyValue('--seg');
    const by = {}; cells.forEach((c) => { by[c.dataset.rvStatus] = hue(c); });
    assert.deepEqual(by, { OBSERVED: 'var(--rv-ok)', INFERRED: 'var(--rv-warn)' });
    assert.deepEqual([...f.d.querySelectorAll('figure.hl-fig--heat .hl-rv-cell--sw')].map((s) => [s.dataset.rvStatus, hue(s)]), [['OBSERVED', 'var(--rv-ok)'], ['INFERRED', 'var(--rv-warn)'], ['NOT SHOWN', 'var(--rv-muted)']], 'the legend swatches are the same three');
    // the badges and minibars use the same variables (stylesheet), so the three agree
    assert.match(css, /\.hl-rv-badge\.hl-rv-observed \{ color: var\(--rv-ok\)/); assert.match(css, /\.hl-rv-badge\.hl-rv-inferred \{ color: var\(--rv-warn\)/); assert.match(css, /\.hl-rv-badge\.hl-rv-not-shown \{ color: var\(--rv-muted\)/);
    assert.match(css, /\.hl-rv-cell\[data-rv-status="INFERRED"\] \{ background: repeating-linear-gradient/, 'the hatch stays as the cue that is not a colour');
    assert.match(css, /\.hl-rv-cell\[data-rv-status="NOT SHOWN"\] \{ background: transparent; border: 2px solid var\(--seg\)/, 'and the outline');
  } finally { f.w.close(); }
  const c = page(false);
  try { assert.equal(/#22d3ee|#a371f7/.test([...c.d.querySelectorAll('.hl-rv-cell')].map((e) => e.getAttribute('style') || '').join('')), true, 'the dashboard heat map keeps its cyan and purple'); } finally { c.w.close(); }
});

test('stage ribbon and facts line: the name sits on its own line under the number for every step; an empty status line takes no room; no separator ends a facts line', () => {
  const f = page(true);
  try {
    const steps = [...f.d.querySelectorAll('figure.hl-fig--chain .hl-rv-fnode .hl-rv-fnb')];
    assert.ok(steps.length >= 2);
    assert.ok(steps.every((s) => s.children.length === 2 && s.children[0].classList.contains('hl-rv-fnum') && s.children[1].classList.contains('hl-rv-fnm')), 'number first, name second, in every step');
    assert.match(css, /\.hl-figs-inline \.hl-fig \.hl-rv-fnb \{ flex-direction: column; flex-wrap: nowrap;/);
    assert.match(css, /\.hl-figs-inline \.hl-fig \.hl-rv-flowwrap p\.hl-rv-linkread:empty \{ display: none; \}/);
    assert.equal(f.d.querySelector('figure.hl-fig--chain .hl-rv-linkread').textContent, '', 'it is empty until a press or hover, which is when :empty stops matching');
    // facts: no rule or glyph between items, so a wrapped line cannot end on one
    const block = css.slice(css.lastIndexOf('/*', css.indexOf('T-0637: figures in the text'))).replace(/\/\*[\s\S]*?\*\//g, '');
    const factRules = [...block.matchAll(/(\.hl-report-page\.hl-figs-inline \.hl-fact[^{]*)\{([^}]*)\}/g)].filter((m) => !/strong/.test(m[1]));
    assert.ok(factRules.length >= 2);
    for (const m of factRules) assert.equal(/border-right|border-left|content:/.test(m[2]), false, 'a separator in: ' + m[0]);
    assert.equal(/\|/.test(f.d.querySelector('.hl-facts').textContent), false, 'and none in the text');
    assert.match(block, /\.hl-figs-inline \.hl-facts \{[^}]*gap: 6px 32px/);
  } finally { f.w.close(); }
});
