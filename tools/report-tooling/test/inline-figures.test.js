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

test('the layout adds hl-figs-inline to the report page for figures: inline, and nowhere else', () => {
  const layout = read('_layouts/post.html');
  assert.match(layout, /hl-report-page\{% if page\.figures == 'inline' %\} hl-figs-inline\{% endif %\}/);
  assert.equal((layout.match(/hl-figs-inline/g) || []).length, 1, 'one place sets the class');
  assert.equal(/figures/.test(read('_includes/default/head.liquid')), false, 'the head include does not read the switch');
});

test('exactly the two unlisted previews carry figures: inline (site copies; vault copies too when the vault is beside the checkout)', () => {
  const flagged = fs.readdirSync(path.join(root, 'reports')).filter((d) => {
    const f = path.join(root, 'reports', d, 'index.md');
    return fs.existsSync(f) && /^figures: inline$/m.test(frontMatter(fs.readFileSync(f, 'utf8')));
  }).sort();
  assert.deepEqual(flagged, PREVIEWS);
  for (const d of PREVIEWS) {
    const fm = frontMatter(read('reports/' + d + '/index.md'));
    assert.match(fm, /^unlisted: true$/m, d + ' is an unlisted preview');
    const vault = path.join(root, '..', '..', 'threat-intel-vault', 'reports', d, 'index.md');
    if (fs.existsSync(vault)) assert.match(frontMatter(fs.readFileSync(vault, 'utf8')), /^figures: inline$/m, 'the vault copy of ' + d);
  }
});

test('the cache-busters moved with the stylesheet and the script (both carry the same value)', () => {
  const a = read('_layouts/post.html').match(/hl-report-tabs\.js' \| relative_url \}\}\?v=([0-9.]+)/)[1];
  const b = read('_includes/default/head.liquid').match(/hl-report-tabs\.css' \| relative_url \}\}\?v=([0-9.]+)/)[1];
  assert.equal(a, b); assert.equal(a, '20261115.1');
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
function page(flag) {
  const dom = new JSDOM(`<div class="hl-page hl-report-page${flag ? ' hl-figs-inline' : ''}"><div class="hl-post-body"><div class="hl-post-content">${REPORT}</div></div></div>`, { url: 'https://example.test/report/', runScripts: 'outside-only' });
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

test('the inline anatomy row FAILS on a figure with a box, a fill, a radius, a shadow, a number, no source line or text under the floor', () => {
  const ok = { kind: 'grades', capOk: true, srcOk: true, chrome: true, style: { bg: 'rgba(0, 0, 0, 0)', bt: 1, bb: 0, bl: 0, br: 0, rad: '0px', shadow: 'none' }, capPx: 16, srcPx: 15, capFont: 'IBM Plex Sans', srcFont: 'IBM Plex Sans', capTop: 10, drawTop: 40, srcTop: 90, cap: '2 rows by grade' };
  assert.equal(G.inlineAnatomyVerdict({ figs: [ok] }).ok, true);
  const bad = (patch) => G.inlineAnatomyVerdict({ figs: [Object.assign({}, ok, patch)] });
  assert.equal(bad({ style: Object.assign({}, ok.style, { bl: 1 }) }).ok, false, 'a border box');
  assert.equal(bad({ style: Object.assign({}, ok.style, { bg: 'rgb(34, 34, 34)' }) }).ok, false, 'a fill');
  assert.equal(bad({ style: Object.assign({}, ok.style, { rad: '6px' }) }).ok, false, 'a radius');
  assert.equal(bad({ style: Object.assign({}, ok.style, { shadow: 'rgba(0, 0, 0, 0.5) 0px 2px 8px' }) }).ok, false, 'a shadow');
  assert.equal(bad({ cap: 'Figure 2: grades' }).ok, false, 'a number that would collide with the author\'s');
  assert.equal(bad({ srcOk: false }).ok, false, 'no source line');
  assert.equal(bad({ srcPx: 13 }).ok, false, 'under the floor');
  assert.equal(bad({ srcFont: 'IBM Plex Mono' }).ok, false, 'monospace');
  assert.equal(G.inlineAnatomyVerdict({ figs: [] }).notChecked, true);
});
