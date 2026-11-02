'use strict';
/* T-0500.1.7.3 chunk c3 (design D, D4 and D5, the phone icon strip): the Attack chain's filter console, stage flow, chain story and procedure table (jsdom, the real script), and the pure
   verdicts of the new browser rows driven to FAIL by the measurement a broken layout gives. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');
const G = require('../check-browser-report.js');
const script = fs.readFileSync(path.join(__dirname, '../../../assets/js/hl-report-tabs.js'), 'utf8');

function table(headers, rows) { return '<table><thead><tr>' + headers.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>'; }
function page(chainHtml, opts) {
  opts = opts || {};
  const html = ['overview', 'chain'].map(t => `<h2 class="hl-tab-${t}" id="${t}-s">${t}</h2><p>Original ${t} words.</p>${t === 'chain' ? chainHtml : ''}`).join('');
  const dom = new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>' + html + '</div></div>', { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: !!opts.phone, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(script); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return { w, d: w.document };
}
const STAGES = table(['Stage', 'What the operator did', 'Where it is shown'], [['1. Study', 'Cloned the repositories. Active Scanning of the hosts', 'logs'], ['2. Entry', 'Used Exploit Public-Facing Application against the portal', 'output'], ['3. Spread', 'Moved on', 'none']]);
const ATT = table(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Scope'], [
  ['Reconnaissance / T1595', 'Active Scanning', 'OBSERVED', 'HIGH', 'hosts'],
  ['Initial Access / T1190', 'Exploit Public-Facing Application', 'OBSERVED', 'HIGH', 'portal a'],
  ['Initial Access / T1190', 'Exploit Public-Facing Application', 'INFERRED', 'MODERATE', 'portal b'],
  ['Execution / T1059.004', 'Unix Shell', 'NOT SHOWN', 'LOW', 'host']]);
const KEY = table(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Evidence'], [['Initial Access / T1190', 'Exploit Public-Facing Application', 'OBSERVED', 'HIGH', 'The portal request log.'], ['Execution / T1059.004', 'Unix Shell', 'NOT SHOWN', 'LOW', 'Shell history.']]);
const txt = n => n.textContent.replace(/\s+/g, ' ').trim();
const chips = (d, f) => [...d.querySelectorAll('#tab-chain .hl-rv-console .hl-rv-facets .hl-rv-fchip')].filter(c => c.dataset.rvFacet === f).map(c => txt(c));

test('D4 console: one chip for each facet value with its count over the rows, single choice, a press filters and a second clears, the count line shows only while filtered', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    assert.deepEqual(chips(f.d, 'Status'), ['OBSERVED 2', 'INFERRED 1', 'NOT SHOWN 1']);
    assert.deepEqual(chips(f.d, 'Confidence'), ['HIGH 2', 'MODERATE 1', 'LOW 1']);
    assert.deepEqual(chips(f.d, 'Tactic'), ['RECONNAISSANCE 1', 'INITIAL ACCESS 2', 'EXECUTION 1'].map(s => s.charAt(0) + s.slice(1).toLowerCase()).map((s, i) => ['Reconnaissance 1', 'Initial Access 2', 'Execution 1'][i]));
    assert.deepEqual(chips(f.d, 'Shortlist'), ['Carries the case 2']);
    const rows = () => [...f.d.querySelectorAll('#tab-chain .hl-rv-procedures tbody tr')], count = () => txt(f.d.querySelector('#tab-chain .hl-rv-console .hl-rv-count'));
    assert.equal(rows().length, 4); assert.equal(count(), '');
    const obs = [...f.d.querySelectorAll('#tab-chain .hl-rv-console .hl-rv-facets .hl-rv-fchip')].find(c => c.dataset.rvValue === 'OBSERVED');
    obs.click(); assert.equal(rows().filter(r => !r.hidden).length, 2); assert.equal(count(), 'Showing 2 of 4 procedure rows'); assert.equal(obs.getAttribute('aria-pressed'), 'true');
    const hi = [...f.d.querySelectorAll('#tab-chain .hl-rv-console .hl-rv-facets .hl-rv-fchip')].find(c => c.dataset.rvValue === 'MODERATE'); hi.click();
    assert.equal(rows().filter(r => !r.hidden).length, 0, 'facets combine: OBSERVED and MODERATE share no row'); assert.equal(count(), 'Showing 0 of 4 procedure rows');
    obs.click(); hi.click(); assert.equal(count(), ''); assert.equal(rows().filter(r => r.hidden).length, 0);
    const v = G.consoleVerdict(JSON.parse(JSON.stringify(f.w.eval(G.CHAIN_EXPR))), null, null, 4); assert.equal(v.ok, true, v.detail);
  } finally { f.w.close(); }
});
test('D4 stage flow and story: a node and a card for each stage row, each node counts the story rows, joins are only explicit names, and the table marks exactly the key-list rows with their evidence', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    const m = JSON.parse(JSON.stringify(f.w.eval(G.CHAIN_EXPR)));
    assert.equal(m.nodes, 3); assert.equal(m.cards, 3); assert.deepEqual(m.nodeCounts, [1, 2, 0], 'both rows named Exploit Public-Facing Application join Entry by the name found in its text'); assert.deepEqual(m.storyRows, [1, 2, 0]);
    const v = G.flowVerdict(m); assert.equal(v.ok, true, v.detail);
    assert.equal(m.carry, 2); assert.equal(m.ev, 2); assert.equal(m.keySrc, 2); assert.equal(m.keyMatched, 2); assert.equal(m.keyTotal, 2);
    const marked = [...f.d.querySelectorAll('#tab-chain .hl-rv-procedures tr.hl-rv-keyrow')].map(r => txt(r.cells[0]));
    assert.deepEqual(marked, ['Initial Access / T1190', 'Execution / T1059.004'], 'a repeated ID marks the first row with that ID and name, once');
    assert.match(txt(f.d.querySelector('#tab-chain .hl-rv-console .hl-rv-pn-note')), /marks the first row of the full table with the same technique ID and name that no earlier list row marked \(2 of 2 list rows matched\)/);
    const t = G.chainTableVerdict(Object.assign({}, m, { innerW: 800, tidCount: 0 }), 4); assert.equal(t.ok, true, t.detail); // jsdom has no layout: sticky and the monospace face are measured in the browser run
    assert.match(txt(f.d.querySelector('#tab-chain .hl-rv-procedures tr.hl-rv-keyrow .hl-rv-ev')), /EvidenceThe portal request log\./);
  } finally { f.w.close(); }
});
test('D4 linked tactic highlighting: a focused tactic lights the stages whose rows carry it, a pressed one stays, leaving clears; a stage with no linked rows is never lit by inference', () => {
  const f = page(STAGES + ATT);
  try {
    const btn = [...f.d.querySelectorAll('#tab-chain .hl-rv-procedures button.hl-rv-tac')].find(b => b.dataset.rvTactic === 'Reconnaissance');
    btn.dispatchEvent(new f.w.FocusEvent('focusin', { bubbles: true }));
    let lit = JSON.parse(JSON.stringify(f.w.eval(G.CHAINLIGHT_EXPR)));
    assert.deepEqual([...f.d.querySelectorAll('#tab-chain .hl-rv-fnode')].map(n => n.classList.contains('is-linked')), [true, false, false]);
    assert.match(txt(f.d.querySelector('#tab-chain .hl-rv-linkread')), /^Reconnaissance appears in stage 1 /);
    btn.dispatchEvent(new f.w.FocusEvent('focusout', { bubbles: true })); assert.equal(f.d.querySelectorAll('#tab-chain .hl-rv-fnode.is-linked').length, 0);
    btn.click(); assert.equal(btn.getAttribute('aria-pressed'), 'true'); assert.equal(f.d.querySelectorAll('#tab-chain .hl-rv-fnode.is-linked').length, 1);
    btn.click(); assert.equal(f.d.querySelectorAll('#tab-chain .hl-rv-fnode.is-linked').length, 0);
    const ok = G.lightVerdict({ tactic: 'X', expect: [0], lit: [0], litCards: [0], read: '' }, { lit: [], litCards: [] }); assert.equal(ok.ok, true);
    assert.equal(G.lightVerdict({ tactic: 'X', expect: [0], lit: [0, 1], litCards: [0, 1], read: '' }, null).ok, false, 'a stage lit by inference FAILS');
    assert.equal(G.lightVerdict({ tactic: 'X', expect: [0], lit: [], litCards: [], read: '' }, null).ok, false, 'a handler that lights nothing FAILS');
    assert.equal(G.lightVerdict({ tactic: null }, null).notChecked, true);
  } finally { f.w.close(); }
  const g = page(table(['Stage', 'What happens', 'What defenders see'], [['0', 'Delivers a script', 'a process'], ['1', 'Loads a library', 'nothing']]) + table(['Tactic / Technique', 'Name', 'Evidence'], [['Execution / T1059.001', 'PowerShell', 'ev']]));
  try {
    assert.equal(g.d.querySelectorAll('#tab-chain button.hl-rv-tac').length, 0, 'no stage has a linked row, so no tactic button is drawn');
    assert.equal(g.d.querySelectorAll('#tab-chain .hl-rv-fnode').length, 2); assert.match(txt(g.d.querySelector('#tab-chain .hl-rv-fnode')), /Stage 0/);
    assert.equal(G.lightVerdict(JSON.parse(JSON.stringify(g.w.eval(G.CHAINLIGHT_EXPR))), null).notChecked, true);
  } finally { g.w.close(); }
});
test('D4 slim bar: it exists beside the console, hidden at rest, shares one state with it, and the verdict fails a bar that is outside the column or over the margin card', () => {
  const f = page(STAGES + ATT);
  try {
    const mini = f.d.querySelector('#tab-chain .hl-rv-minibar'); assert.ok(mini); assert.equal(mini.hidden, true);
    const mi = mini.querySelector('input'), main = f.d.querySelector('#tab-chain .hl-rv-console .hl-rv-csearch input');
    mi.value = 'portal'; mi.dispatchEvent(new f.w.Event('input')); assert.equal(main.value, 'portal'); assert.equal(txt(f.d.querySelector('#tab-chain .hl-rv-mcount')), 'Showing 2 of 4 procedure rows');
    main.value = ''; main.dispatchEvent(new f.w.Event('input')); assert.equal(mi.value, '');
  } finally { f.w.close(); }
  const ok = { present: true, hidden: false, left: 205, right: 1235, top: 140, colLeft: 205, colRight: 1235, cardRight: 156, barBottom: 126, hasSearch: true };
  assert.equal(G.miniVerdict({ present: true, hidden: true }, ok, { miniValue: 'a', mainValue: 'a' }).ok, true);
  assert.equal(G.miniVerdict({ present: true, hidden: true }, Object.assign({}, ok, { left: 0, right: 1440 }), null).ok, false, 'a full-width bar FAILS');
  assert.equal(G.miniVerdict({ present: true, hidden: true }, Object.assign({}, ok, { left: 100 }), null).ok, false, 'a bar over the card FAILS');
  assert.equal(G.miniVerdict({ present: true, hidden: true }, Object.assign({}, ok, { hidden: true }), null).ok, false, 'a bar that never appears FAILS');
  assert.equal(G.miniVerdict({ present: true, hidden: true }, ok, { miniValue: 'a', mainValue: '' }).ok, false, 'a bar with its own search state FAILS');
  assert.equal(G.miniVerdict({ present: false }, null, null).notChecked, true);
});
test('D4 verdicts: the console, flow and table rows fail on the counts a broken page gives', () => {
  const base = { panel: true, console: true, search: true, chips: [{ f: 'Status', v: 'A', n: 3 }, { f: 'Status', v: 'B', n: 1 }], rows: 4, count: '', stageSrc: 2, nodes: 2, cards: 2, nodeCounts: [1, 1], storyRows: [1, 1], thPos: 'sticky', tidFont: 'ui-monospace', tidCount: 4, carry: 2, ev: 2, keySrc: 2, keyMatched: 2, keyTotal: 2, innerW: 1280 };
  assert.equal(G.consoleVerdict(base, { shown: 3, count: 'Showing 3 of 4 procedure rows', pressed: ['Status:A'] }, { shown: 4, count: '', pressed: [] }, 4).ok, true);
  assert.equal(G.consoleVerdict(Object.assign({}, base, { chips: [{ f: 'Status', v: 'A', n: 3 }] }), null, null, 4).ok, false, 'chip counts that do not add up FAIL');
  assert.equal(G.consoleVerdict(base, { shown: 4, count: '', pressed: [] }, null, 4).ok, false, 'a chip that filters nothing FAILS');
  assert.equal(G.consoleVerdict(Object.assign({}, base, { count: 'Showing 4 of 4 procedure rows' }), null, null, 4).ok, false, 'a count line at rest FAILS');
  assert.equal(G.consoleVerdict(Object.assign({}, base, { rows: 3 }), null, null, 4).ok, false, 'a table that lost a row FAILS');
  assert.equal(G.flowVerdict(Object.assign({}, base, { nodes: 1 })).ok, false); assert.equal(G.flowVerdict(Object.assign({}, base, { nodeCounts: [2, 1] })).ok, false);
  assert.equal(G.flowVerdict(Object.assign({}, base, { stageSrc: 0 })).notChecked, true);
  assert.equal(G.chainTableVerdict(base, 4).ok, true); assert.equal(G.chainTableVerdict(Object.assign({}, base, { carry: 1 }), 4).ok, false); assert.equal(G.chainTableVerdict(Object.assign({}, base, { thPos: 'static' }), 4).ok, false);
  assert.equal(G.chainTableVerdict(Object.assign({}, base, { tidFont: 'Space Grotesk' }), 4).ok, false); assert.equal(G.chainTableVerdict(Object.assign({}, base, { keySrc: 0, carry: 1 }), 4).ok, false, 'a mark with no list FAILS');
});
test('the phone icon strip and the plate edge: the strip names every tab and shows one label; Share starts at the grid edge', () => {
  const ok = { present: true, tabs: 7, named: 7, icons: 7, labelsShown: 1, selected: 1, selectedLabelShown: 1, minW: 44, minH: 52, scrolls: true, menu: true, numerals: 0 };
  assert.equal(G.stripVerdict(ok, 7).ok, true);
  assert.equal(G.stripVerdict(Object.assign({}, ok, { named: 6 }), 7).ok, false, 'a tab with no accessible name FAILS');
  assert.equal(G.stripVerdict(Object.assign({}, ok, { labelsShown: 7 }), 7).ok, false, 'seven labels FAIL');
  assert.equal(G.stripVerdict(Object.assign({}, ok, { menu: false }), 7).ok, false, 'a lost Sections menu FAILS');
  assert.equal(G.stripVerdict(Object.assign({}, ok, { present: false }), 7).ok, false, 'a hidden strip FAILS');
  assert.equal(G.stripVerdict(Object.assign({}, ok, { minW: 40 }), 7).ok, false, 'a 40 px tab FAILS');
  assert.equal(G.plateEdgeVerdict({ present: true, n: 6, minLeft: 34, shareLeft: 34 }).ok, true);
  assert.equal(G.plateEdgeVerdict({ present: true, n: 6, minLeft: 34, shareLeft: 42 }).ok, false, 'Share 8 px in FAILS');
  assert.equal(G.plateEdgeVerdict({ present: true, n: 3, minLeft: 34, colLefts: [34, 198.5], shareLeft: 198.5 }).ok, true, 'Share beside a partner sits on the second column edge');
  assert.equal(G.plateEdgeVerdict({ present: true, n: 3, minLeft: 34, colLefts: [34, 198.5], shareLeft: 206.5 }).ok, false, 'an indent from the second column FAILS');
  assert.equal(G.plateEdgeVerdict({ present: true, n: 6, minLeft: 34, shareLeft: null }).notChecked, true);
});
