'use strict';
/* T-0500.1.7.3 chunk c2 (design D, D3): the Overview's scan layer (jsdom, the real script): tiles with fallbacks, the scan band, the risk bars, the judgments view and the linked
   highlighting, and the pure verdicts of the new browser rows driven to FAIL by the measurement a broken layout gives. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');
const script = fs.readFileSync(path.join(__dirname, '../../../assets/js/hl-report-tabs.js'), 'utf8');

function table(headers, rows) { return '<table><thead><tr>' + headers.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>'; }
function page(sections, opts) {
  opts = opts || {};
  const html = sections.map(([tok, extra, head], i) => `<h2 class="hl-tab-${tok}" id="${tok}-s${i}">${head || tok}</h2>${(extra && extra.p) || '<p>Original ' + tok + ' words.</p>'}${(extra && extra.html) || (typeof extra === 'string' ? extra : '')}`).join('');
  const data = opts.site ? '<script type="application/json" id="hl-report-site-data">' + JSON.stringify(opts.site) + '</script>' : '';
  const dom = new JSDOM(data + '<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>' + (opts.meta || '') + html + '</div></div>', { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: !!opts.phone, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(script); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return { w, d: w.document };
}
const VIC = table(['Organisation', 'Grade', 'Qualifier'], [['A federal social-security agency', 'ACCESS SHOWN', 'x'], ['A state finance secretariat', 'COMPROMISED', 'y'], ['A municipal office', 'REACHED', 'z'], ['A city', 'LISTED', 'w']]);
const ATT = table(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Scope'], [['Initial Access / T1190', 'Exploit Public-Facing Application', 'OBSERVED', 'HIGH', 'a'], ['Execution / T1059.004', 'Unix Shell', 'INFERRED', 'LOW', 'b'], ['Execution / T1072', 'Software Deployment Tools', 'OBSERVED', 'HIGH', 'c']]);
const RISK = table(['Risk Dimension', 'Weight', 'Score', 'Rationale'], [['Data Exfiltration', '20%', '7/10', 'Browser credential theft.'], ['Lateral Movement', '15%', '9/10', 'A CIDR scanner.'], ['<strong>Overall</strong>', '100%', '<strong>8.3/10</strong>', 'HIGH. A complete kill chain.']]);
const RISK_WORDS = table(['Risk Dimension', 'Rating', 'Assessment'], [['Custom Implant', 'HIGH', 'Four generations.'], ['Deployment Status', 'MEDIUM', 'Pre-deployment.'], ['Active C2', 'UNKNOWN', 'No answer.']]);
const JUDG = table(['Claim', 'Confidence', 'What would change it'], [['The agency was reached', 'HIGH', 'A host record.'], ['The bank was reached', 'MODERATE', 'Another record.'], ['Named actor', 'INSUFFICIENT', 'An identity artifact.'], ['Tunnel', 'HIGH', 'A proxy log.']]);
const CHRON = table(['Date', 'Observation'], [['2026-08-20', 'Configuration change'], ['2026-09-14', 'Tunnel start'], ['2026-10-14', 'Ports answer']]);
const txt = n => n.textContent.replace(/\s+/g, ' ').trim();
const tilesOf = f => [...f.d.querySelectorAll('#tab-overview .hl-rv-tile')].map(t => [t.dataset.rvTile, txt(t.querySelector('strong'))]);

test('D3 tiles: a report with a victim grade table and an ATT&CK table keeps the tiles it always had, in order, each of a named kind', () => {
  const f = page([['overview'], ['victims', VIC], ['chain', ATT], ['timeline', CHRON]]);
  try { assert.deepEqual(tilesOf(f), [['inside', '2'], ['techniques', '3'], ['procedures', '3'], ['window', '2026-08-20 to 2026-10-14']]); } finally { f.w.close(); }
});
test('D3 tiles: with no victim table the fallback set is built from what the report has: threat level, overall risk (the table\'s Overall row), techniques, rules, IOC entries; each tile is of a named kind with a source in its note', () => {
  const f = page([['overview', RISK, 'Risk assessment'], ['chain', ATT]], { meta: '<p>Threat Level: CRITICAL</p>', site: { rules: { total: 13, sigma: 5, yara: 0, suricata: 8, detection: 6, hunting: 7 }, iocs: { total: 42, feed_url: '/ioc-feeds/x.json' }, techniques: null, detection_page: '/hunting-detections/x/' } });
  try {
    assert.deepEqual(tilesOf(f), [['threat', 'CRIT.'], ['risk', '8.3/10'], ['techniques', '3'], ['drules', '13'], ['iocs', '42']]);
    f.d.querySelectorAll('#tab-overview .hl-rv-tilecell').forEach(c => { const t = c.querySelector('.hl-rv-tile'); assert.match(txt(c.querySelector('.hl-rv-pop')), /How counted: .+ From .+\./, t.dataset.rvTile); });
    assert.equal(f.d.querySelector('[data-rv-tile=threat]').tagName, 'DIV', 'the threat tile has no destination, so it is not a link');
    assert.equal(f.d.querySelector('[data-rv-tile=iocs]').getAttribute('href'), '/ioc-feeds/x.json');
    const line = txt(f.d.querySelector('#tab-overview .hl-rv-view-summary p')); assert.match(line, /^CRITICAL threat level · 8\.3\/10 risk score · 3 techniques/);
  } finally { f.w.close(); }
});
test('D3 tiles: with no ATT&CK table the techniques come from the detection page, one per row, and say so; a report with nothing to count says the view is unavailable', () => {
  const site = { techniques: { total: 2, tactics: 2, rows: [{ tactic: 'Initial Access', id: 'T1190', name: 'x' }, { tactic: 'Execution', id: 'T1059', name: 'y' }] }, detection_page: '/hunting-detections/x/' };
  const f = page([['overview'], ['indicators']], { meta: '<p>Threat Level: HIGH</p>', site });
  try {
    assert.deepEqual(tilesOf(f), [['threat', 'HIGH'], ['dtech', '2']]);
    assert.match(txt(f.d.querySelector('[data-rv-tile=dtech]').closest('.hl-rv-tilecell').querySelector('.hl-rv-pop')), /the detection page/);
    const cells = f.d.querySelectorAll('#tab-overview .hl-rv-heat .hl-rv-cell'); assert.equal(cells.length, 2, 'one heat cell for each detection technique');
    assert.match(txt(f.d.querySelector('.hl-rv-pn--heat .hl-rv-pn-sub')), /from the detection page/);
  } finally { f.w.close(); }
  const g = page([['overview'], ['chain']]);
  try { assert.equal(tilesOf(g).length, 0); assert.match(txt(g.d.querySelector('#hl-rv-view-overview .hl-rv-unavailable')), /^View unavailable: needs /); } finally { g.w.close(); }
});
test('D3 risk bars: one bar for every source row (the Overall row included), score and weight read from the table, the row\'s own justification beside it, the source table kept', () => {
  const f = page([['overview', RISK, 'Risk assessment']]);
  try {
    const rows = [...f.d.querySelectorAll('#tab-overview .hl-rv-riskrow')];
    assert.equal(rows.length, 3); assert.equal(f.d.querySelectorAll('#tab-overview .hl-rv-riskbar').length, 3);
    assert.deepEqual(rows.map(r => txt(r.querySelector('.hl-rv-riskname'))), ['Data Exfiltration', 'Lateral Movement', 'Overall']);
    assert.deepEqual(rows.map(r => txt(r.querySelector('.hl-rv-riskwhy'))), ['Browser credential theft.', 'A CIDR scanner.', 'HIGH. A complete kill chain.']);
    assert.equal(rows[0].querySelector('.hl-rv-riskbar > i').style.width, '70%'); assert.equal(rows[1].querySelector('.hl-rv-riskbar').getAttribute('aria-label'), '9 out of 10');
    assert.match(txt(rows[0].querySelector('.hl-rv-riskmeta')), /20% weight/); assert.ok(rows[2].classList.contains('is-total'));
    assert.ok(f.d.querySelector('#tab-overview .hl-rv-source table'), 'the source table stays in the report');
    const v = G.riskBarVerdict(JSON.parse(JSON.stringify(f.w.eval(G.RISK_EXPR)))); assert.equal(v.ok, true, v.detail); assert.match(v.detail, /3 bar\(s\) against 3 source row/);
  } finally { f.w.close(); }
});
test('D3 risk bars: a word rating is drawn on a four-step scale and marked as one; an unscored row still has its bar and says so; a table with no score column draws none', () => {
  const f = page([['overview', RISK_WORDS, 'Risk']]);
  try {
    const bars = [...f.d.querySelectorAll('#tab-overview .hl-rv-riskbar')]; assert.deepEqual(bars.map(b => b.dataset.rvScale), ['word', 'word', 'none']);
    assert.match(bars[0].getAttribute('aria-label'), /HIGH rating, drawn on a four-step scale/); assert.equal(bars[2].querySelector('i').style.width, '0%');
  } finally { f.w.close(); }
  const g = page([['overview', table(['Risk Factor', 'Quasar RAT', 'NjRAT'], [['Overall', '8/10 HIGH', '7/10 HIGH']]), 'Risk']]);
  try { assert.equal(g.d.querySelectorAll('.hl-rv-riskrow').length, 0); } finally { g.w.close(); }
});
test('D3 scan band: grade squares (one per victim row, grouped by grade), a legend that adds up, the tactic heat strip (one cell per procedure row) and the compact timeline (one marker per dated row)', () => {
  const f = page([['overview'], ['victims', VIC], ['chain', ATT], ['timeline', CHRON]]);
  try {
    assert.equal(f.d.querySelectorAll('.hl-rv-sq').length, 4);
    assert.deepEqual([...f.d.querySelectorAll('.hl-rv-sq')].map(s => s.dataset.rvGrade), ['ACCESS SHOWN', 'COMPROMISED', 'REACHED', 'LISTED']);
    assert.equal(G.squaresVerdict(JSON.parse(JSON.stringify(f.w.eval(G.SQUARES_EXPR))), 4).ok, true);
    const heat = JSON.parse(JSON.stringify(f.w.eval(G.HEAT_EXPR))); assert.equal(heat.cells, 3); assert.equal(G.heatVerdict(heat, 3).ok, true, G.heatVerdict(heat, 3).detail);
    assert.deepEqual([...f.d.querySelectorAll('.hl-rv-heathead span')].map(txt), ['Initial Access', 'Execution'], 'tactic columns in ATT&CK order');
    assert.equal(f.d.querySelectorAll('.hl-rv-cmark').length, 3);
    assert.equal(f.d.querySelectorAll('.hl-rv-pn--time .hl-rv-cmore').length, 0);
    f.d.querySelector('.hl-rv-cmark').click(); assert.match(txt(f.d.querySelector('.hl-rv-cdetail')), /^2026-08-20 · Configuration change/);
  } finally { f.w.close(); }
});
test('D3 judgments: every row shown in full with its confidence as printed, a chip for each printed level with its count, chips filter this copy only, what would change it beside each row', () => {
  const f = page([['overview'], ['confidence', JUDG]]);
  try {
    const rows = [...f.d.querySelectorAll('#tab-overview .hl-rv-jrow')]; assert.equal(rows.length, 4);
    const chips = [...f.d.querySelectorAll('#tab-overview .hl-rv-jchip')].map(c => txt(c)); assert.deepEqual(chips, ['All 4', 'HIGH 2', 'MODERATE 1', 'INSUFFICIENT 1']);
    assert.equal(f.d.querySelector('#tab-overview .hl-rv-pn--judg').closest('details'), null, 'no fold');
    assert.match(txt(rows[0].querySelector('.hl-rv-jchange')), /What would change it A host record\./);
    const v = G.judgmentsVerdict(JSON.parse(JSON.stringify(f.w.eval(G.JUDG_EXPR))), 4); assert.equal(v.ok, true, v.detail);
    f.d.querySelector('[data-rv-conf=HIGH]').click(); assert.equal(rows.filter(r => !r.hidden).length, 2); assert.match(txt(f.d.querySelector('#tab-overview .hl-rv-pn--judg .hl-rv-count')), /^Showing 2 of 4 judgments$/);
    assert.equal(f.d.querySelectorAll('#tab-confidence .hl-rv-source table tbody tr').length, 4, 'the source table is untouched');
  } finally { f.w.close(); }
  const g = page([['overview'], ['confidence', table(['Finding', 'Confidence'], [['a', 'HIGH'], ['b', 'LOW']])]]);
  try { assert.match(txt(g.d.querySelector('#tab-overview .hl-rv-pn--judg .hl-rv-unstated')), /Not stated in this report's table: what would change each judgment/); assert.equal(g.d.querySelectorAll('#tab-overview .hl-rv-jchange').length, 0); } finally { g.w.close(); }
});
test('C3 judgments chips are grouped: five levels plus one "Other / ranges" chip, the counts add up, each row keeps its printed rating, a grouped chip filters the printed variants together', () => {
  const MIX = table(['Claim', 'Confidence', 'What would change it'], [['a', 'HIGH', 'x'], ['b', 'HIGH-MODERATE', 'x'], ['c', 'MODERATE (capture provenance)', 'x'], ['d', 'LOW-MODERATE', 'x'], ['e', 'MEDIUM', 'x'], ['f', 'High', 'x'], ['g', 'LOW', 'x']]);
  const f = page([['overview'], ['confidence', MIX]]);
  try {
    const chips = [...f.d.querySelectorAll('#tab-overview .hl-rv-jchip')].map(c => txt(c));
    assert.deepEqual(chips, ['All 7', 'HIGH 2', 'LOW 1', 'Other / ranges 4'], 'five levels at most and one Other chip, never one chip per printed string');
    assert.equal(chips.slice(1).reduce((n, c) => n + Number(c.split(' ').pop()), 0), 7, 'the chip counts add up to the row count');
    const words = [...f.d.querySelectorAll('#tab-overview .hl-rv-jword')].map(txt); assert.deepEqual(words, ['HIGH', 'HIGH-MODERATE', 'MODERATE (capture provenance)', 'LOW-MODERATE', 'MEDIUM', 'High', 'LOW'], 'each row keeps its printed rating');
    const v = G.judgmentsVerdict(JSON.parse(JSON.stringify(f.w.eval(G.JUDG_EXPR))), 7); assert.equal(v.ok, true, v.detail);
    f.d.querySelector('[data-rv-conf=OTHER]').click();
    assert.deepEqual([...f.d.querySelectorAll('#tab-overview .hl-rv-jrow')].filter(r => !r.hidden).map(r => r.dataset.rvConf), ['HIGH-MODERATE', 'MODERATE (capture provenance)', 'LOW-MODERATE', 'MEDIUM']);
    const bad = JSON.parse(JSON.stringify(f.w.eval(G.JUDG_EXPR))); bad.labels = ['HIGH', 'HIGH-MODERATE', 'MODERATE'];
    assert.equal(G.judgmentsVerdict(bad, 7).ok, false, 'a chip per printed string FAILS the grouped-chip rule');
    const drift = JSON.parse(JSON.stringify(f.w.eval(G.JUDG_EXPR))); drift.words[1] = 'HIGH';
    assert.equal(G.judgmentsVerdict(drift, 7).ok, false, 'a row whose rating was rewritten FAILS');
  } finally { f.w.close(); }
});
test('D3 linked highlighting: wrapping adds no word, never enters a table, a link, a heading or code, and a key lights exactly its own places; a second press clears', () => {
  const prose = '<p>The agency was ACCESS SHOWN at the A federal social-security agency, and Execution came first. Not reached. The <code>Execution</code> code, <a href="#x">Execution</a>.</p><p>COMPROMISED twice: COMPROMISED.</p>';
  const f = page([['overview', { p: prose }], ['victims', VIC], ['chain', ATT]]);
  try {
    const src = f.d.querySelector('#tab-overview .hl-rv-source:not(.hl-rv-nohead)'); const before = txt(src);
    const hits = [...src.querySelectorAll('.hl-rv-hit')]; const by = {}; hits.forEach(h => by[h.dataset.rvHit] = (by[h.dataset.rvHit] || 0) + 1);
    assert.deepEqual(by, { 'grade:ACCESS SHOWN': 1, 'grade:COMPROMISED': 2, 'org:A federal social-security agency': 1, 'tactic:Execution': 1 }, 'REACHED lower-case prose and code or link text are not wrapped');
    assert.equal(hits.some(h => h.hasAttribute('data-rv-chrome')), false, 'the wrapper is not chrome: the completeness check removes chrome whole, and the words must stay');
    assert.equal(src.querySelectorAll('table .hl-rv-hit, code .hl-rv-hit, a .hl-rv-hit, h2 .hl-rv-hit').length, 0);
    hits.forEach(h => assert.equal(h.children.length, 0));
    const key = f.d.querySelector('[data-rv-key="grade:COMPROMISED"]'); key.click();
    assert.equal(f.d.querySelectorAll('.hl-rv-hit.is-lit').length, 2); assert.equal(key.getAttribute('aria-pressed'), 'true'); assert.match(txt(f.d.querySelector('.hl-rv-linkread')), /^2 places in the summary name COMPROMISED\.$/);
    assert.equal(txt(src), before, 'pressing a key changes no word');
    key.click(); assert.equal(f.d.querySelectorAll('.hl-rv-hit.is-lit').length, 0);
    const probe = JSON.parse(JSON.stringify(f.w.eval(G.LINKPROBE_EXPR))); assert.ok(probe.key && probe.want >= 1);
  } finally { f.w.close(); }
});
test('D3 linked highlighting on a phone: a pinned key shows the "Show in the summary" bar, and Clear unpins', () => {
  const f = page([['overview', { p: '<p>The agency was ACCESS SHOWN.</p>' }], ['victims', VIC], ['chain', ATT]], { phone: true });
  try {
    const bar = f.d.querySelector('.hl-rv-showbar'); assert.ok(bar && bar.hidden);
    f.d.querySelector('[data-rv-key="grade:ACCESS SHOWN"]').click(); assert.equal(bar.hidden, false); assert.match(txt(bar), /1 in the summary: ACCESS SHOWN/);
    assert.equal(bar.querySelector('.hl-rv-showbar-go').textContent, 'Show in the summary');
    bar.querySelector('.hl-rv-showbar-off').click(); assert.equal(bar.hidden, true); assert.equal(f.d.querySelectorAll('.hl-rv-hit.is-lit').length, 0);
  } finally { f.w.close(); }
});
test('D3 failure path: if the enhancement throws, the wrappers go and the report is restored word for word', () => {
  const src = fs.readFileSync(path.join(__dirname, '../../../assets/js/hl-report-tabs.js'), 'utf8');
  assert.match(src, /querySelectorAll\('\.hl-rv-hit'\)\.forEach\(function \(n\) \{ n\.replaceWith\(document\.createTextNode\(n\.textContent\)\); \}\);/);
});

// ---- the verdicts of the new browser rows, each driven to FAIL ----
const RM = (o) => Object.assign({ panel: true, tables: [{ n: 2, names: ['A', 'B'], why: ['x', 'y'] }], rows: [{ name: 'A', why: 'x', bar: true }, { name: 'B', why: 'y', bar: true }], bars: 2, barsWithFill: 2, panelDrawn: true }, o || {});
test('the risk-bar verdict passes the source rows and FAILS a missing row, a missing bar, a changed name, a changed or missing justification, an empty bar; with no source rows it is NOT CHECKED', () => {
  assert.equal(G.riskBarVerdict(RM()).ok, true);
  assert.equal(G.riskBarVerdict(RM({ rows: [{ name: 'A', why: 'x' }], bars: 1, barsWithFill: 1 })).ok, false);
  assert.match(G.riskBarVerdict(RM({ bars: 1, barsWithFill: 1 })).detail, /draws 1 bars, the source tables have 2/);
  assert.match(G.riskBarVerdict(RM({ rows: [{ name: 'A', why: 'x' }, { name: 'Z', why: 'y' }] })).detail, /1 of 2 row names differ/);
  assert.match(G.riskBarVerdict(RM({ rows: [{ name: 'A', why: 'x' }, { name: 'B', why: null }] })).detail, /justification text/);
  assert.match(G.riskBarVerdict(RM({ barsWithFill: 1 })).detail, /no fill element/);
  assert.equal(G.riskBarVerdict(RM({ tables: [] })).notChecked, true); assert.equal(G.riskBarVerdict(null).notChecked, true);
});
test('the heat-strip verdict: one cell per ATT&CK row, else per detection technique; FAILS a dropped cell, a column count that disagrees, a strip drawn from nothing', () => {
  const M = (o) => Object.assign({ panel: true, drawn: true, cells: 3, cols: [{ head: 2, cells: 2 }, { head: 1, cells: 1 }], siteRows: 0 }, o || {});
  assert.equal(G.heatVerdict(M(), 3).ok, true); assert.equal(G.heatVerdict(M({ cells: 2, cols: [{ head: 2, cells: 2 }] }), 3).ok, false);
  assert.match(G.heatVerdict(M({ cols: [{ head: 3, cells: 2 }, { head: 1, cells: 1 }] }), 3).detail, /column 1 states 3 and holds 2/);
  assert.equal(G.heatVerdict(M({ siteRows: 3 }), null).ok, true, 'the detection page\'s rows are the source when the report has no ATT&CK table');
  assert.equal(G.heatVerdict(M({ siteRows: 4 }), 0).ok, false);
  assert.equal(G.heatVerdict(M({ siteRows: 0 }), null).notChecked, true);
});
test('the squares, judgments and tile-source verdicts FAIL the defects they exist for', () => {
  assert.equal(G.squaresVerdict({ panel: true, drawn: true, squares: 4, legend: 4 }, 4).ok, true);
  assert.equal(G.squaresVerdict({ panel: true, drawn: true, squares: 3, legend: 4 }, 4).ok, false); assert.equal(G.squaresVerdict({ panel: true, drawn: true, squares: 4, legend: 3 }, 4).ok, false);
  assert.equal(G.squaresVerdict({ panel: true, drawn: false, squares: 0, legend: 0 }, 0).notChecked, true);
  const J = (o) => Object.assign({ panel: true, drawn: true, rows: 4, hidden: 0, all: 4, sum: 4, folded: false }, o || {});
  assert.equal(G.judgmentsVerdict(J(), 4).ok, true);
  [{ rows: 3 }, { hidden: 1 }, { folded: true }, { all: 3 }, { sum: 3 }].forEach(o => assert.equal(G.judgmentsVerdict(J(o), 4).ok, false, JSON.stringify(o)));
  assert.equal(G.judgmentsVerdict(J(), 0).notChecked, true);
  const T = (o) => Object.assign({ kind: 'risk', value: '8/10', pop: 'How counted: the score. From Section 2, table 1, the Overall row.', hidden: true }, o || {});
  assert.equal(G.tileSourceVerdict([T()]).ok, true);
  assert.equal(G.tileSourceVerdict([T({ pop: 'How counted: a number.' })]).ok, false); assert.equal(G.tileSourceVerdict([T({ kind: null })]).ok, false); assert.equal(G.tileSourceVerdict([T({ hidden: false })]).ok, false);
  assert.equal(G.tileSourceVerdict([]).notChecked, true);
});
test('the linked-highlighting verdict: PASS when a press lights its places and a second clears; FAILS a dead key, an extra lit key, a changed text, a phone with no bar, a button that does not scroll', () => {
  const probe = { hits: 3, key: 'grade:X', want: 2, text: 'T' };
  const press = (o) => Object.assign({ lit: 2, litOther: 0, pressed: 'true', barShown: false, text: 'T' }, o || {});
  assert.equal(G.linkVerdict(probe, press(), { lit: 0 }, false).ok, true);
  assert.equal(G.linkVerdict(probe, press({ lit: 0, pressed: 'false' }), { lit: 0 }, false).ok, false, 'a key whose handler is gone');
  assert.equal(G.linkVerdict(probe, press({ litOther: 1 }), { lit: 0 }, false).ok, false); assert.equal(G.linkVerdict(probe, press({ text: 'U' }), { lit: 0 }, false).ok, false);
  assert.equal(G.linkVerdict(probe, press(), { lit: 1 }, false).ok, false);
  assert.equal(G.linkVerdict(probe, press(), { lit: 0 }, true).ok, false, 'phone, no bar');
  assert.equal(G.linkVerdict(probe, press({ barShown: true }), { lit: 0 }, true, { top: { t: 2000, b: 2020, ih: 800 } }).ok, false, 'the first place is not brought into view');
  assert.equal(G.linkVerdict(probe, press({ barShown: true }), { lit: 0 }, true, { top: { t: 300, b: 320, ih: 800 } }).ok, true);
  assert.equal(G.linkVerdict({ hits: 0, key: null }).notChecked, true);
});
test('the overview card verdict: a report whose only tile is the threat-level word expects no figure in the summary; a figure it should not state, or a missing figure where tiles carry one, still FAILS', () => {
  const ok = G.viewShapeVerdict('overview', true, 'CRITICAL threat level', 1, null, { rows: 1, tiles: ['CRITICAL'], drawnTiles: ['CRITICAL'] });
  assert.equal(ok.ok, true, ok.detail);
  assert.equal(G.viewShapeVerdict('overview', true, '4 threat level', 1, null, { rows: 1, tiles: ['CRITICAL'], drawnTiles: ['CRITICAL'] }).ok, false);
  assert.equal(G.viewShapeVerdict('overview', true, 'CRITICAL threat level', 1, null, { rows: 1, tiles: ['8.3/10'], drawnTiles: ['8.3/10'] }).ok, false, 'a tile with a figure needs the summary to state it');
  assert.equal(G.viewShapeVerdict('overview', true, 'CRITICAL threat level · 8.3/10 risk score', 2, null, { rows: 2, tiles: ['CRITICAL', '8.3/10'], drawnTiles: ['CRITICAL', '8.3/10'] }).ok, true);
});
test('a words-only overview summary must still state its tile: a broken summary line FAILS', () => {
  assert.equal(G.viewShapeVerdict('overview', true, 'x', 1, null, { rows: 1, tiles: ['CRITICAL'], drawnTiles: ['CRITICAL'] }).ok, false);
});
