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
test('D4 carries-the-case row compares WHICH rows are marked and WHAT they say, not only how many (review F2, T-0500.1.7.3 c5)', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    const measure = () => JSON.parse(JSON.stringify(f.w.eval(G.CHAIN_EXPR)));
    const verdict = (m) => G.chainTableVerdict(Object.assign({}, m, { innerW: 800, tidCount: 0 }), 4);
    const m0 = measure(); assert.equal(verdict(m0).ok, true, verdict(m0).detail);
    assert.deepEqual(m0.drawn.map(d => d.carry), [false, true, false, true]); assert.equal(m0.drawn[1].ev, 'The portal request log.');
    const rows = () => [...f.d.querySelectorAll('#tab-chain .hl-rv-procedures tbody tr')];
    // 1. the mark and its evidence move from the T1190 row to the T1595 row: 2 marked, 2 evidence notes, the console note still says 2 of 2
    const from = rows()[1], to = rows()[0], ix = from.querySelector('.hl-rv-carry').parentNode.cellIndex;
    const a = from.querySelector('.hl-rv-carry'), b = from.querySelector('.hl-rv-ev'); to.cells[ix].appendChild(a); to.cells[ix].appendChild(b);
    const m1 = measure(); assert.equal(m1.carry, 2); assert.equal(m1.ev, 2); assert.equal(m1.keyMatched, 2);
    const v1 = verdict(m1); assert.equal(v1.ok, false, 'counts are unchanged, the wrong row is marked: ' + v1.detail); assert.match(v1.detail, /row 1 \(T1595 Active Scanning\) carries a mark/); assert.match(v1.detail, /row 2 .* should carry the mark/);
    from.cells[ix].appendChild(a); from.cells[ix].appendChild(b);
    assert.equal(verdict(measure()).ok, true, 'put back, it passes again');
    // 2. the evidence text is replaced, counts unchanged
    const p = f.d.querySelector('#tab-chain .hl-rv-procedures .hl-rv-ev p'), was = p.textContent; p.textContent = 'Invented evidence.';
    const m2 = measure(); assert.equal(m2.carry, 2); assert.equal(m2.ev, 2);
    const v2 = verdict(m2); assert.equal(v2.ok, false); assert.match(v2.detail, /shows evidence "Invented evidence\."/);
    p.textContent = was; assert.equal(verdict(measure()).ok, true);
    // 3. the page's mark sits on the right row but the ID drawn there is another technique
    const tid = rows()[3].querySelector('.hl-rv-tid'); tid.textContent = 'T1000';
    const v3 = verdict(measure()); assert.equal(v3.ok, false); assert.match(v3.detail, /is drawn as T1000/);
  } finally { f.w.close(); }
});
test('review F3: an opened "i" note with no room below its button is placed above it, and one that fits neither way is slid inside the screen; both axes, 12px from each edge', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    const w = f.w; Object.defineProperty(w, 'innerWidth', { value: 400, configurable: true }); Object.defineProperty(w, 'innerHeight', { value: 800, configurable: true });
    const btn = f.d.querySelector('.hl-rv-info'), pop = f.d.getElementById(btn.getAttribute('aria-controls'));
    assert.ok(btn && pop, 'the page draws an i button with its note');
    // the geometry is stipulated: the note is 300px tall and 360 wide; the button is 44px tall
    const place = (popTop, left, btnTop) => {
      pop.getBoundingClientRect = () => ({ left, right: left + 360, top: popTop, bottom: popTop + 300, width: 360, height: 300 });
      btn.getBoundingClientRect = () => ({ left: 340, right: 384, top: btnTop, bottom: btnTop + 44, width: 44, height: 44 });
    };
    const open = () => { btn.click(); }; const close = () => { if (!pop.hidden) btn.click(); };
    // 1. room below: nothing moves
    place(200, 20, 160); open(); assert.equal(pop.style.transform, ''); close();
    // 2. no room below (the note would end at 1000 in an 800px screen), room above: placed above the button (its top 6px into the button), 366px from the screen top
    place(700, 20, 660); open(); assert.equal(pop.style.transform, 'translate(0px, -334px)'); close(); assert.equal(pop.style.transform, '', 'closing resets it');
    // 3. no room below, and above is worse (266px short against 212px): stays below and is slid up until it ends 12px above the bottom edge
    place(700, 20, 40); open(); assert.equal(pop.style.transform, 'translate(0px, -212px)'); close();
    // 4. above is less wrong than below but still short (106px against 212px): placed above, then slid down to the 12px margin
    place(700, 20, 200); open(); assert.equal(pop.style.transform, 'translate(0px, -688px)'); close();
    // 5. sideways as before: the note's right edge at 440 in a 400px screen slides left to the 12px margin, no vertical move
    place(200, 80, 160); open(); assert.equal(pop.style.transform, 'translate(-52px, 0px)'); close();
    // 6. both axes at once
    place(700, 80, 660); open(); assert.equal(pop.style.transform, 'translate(-52px, -334px)'); close();
    // 7. the stylesheet caps the note's height to the screen
    const css = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8');
    assert.match(css, /\.hl-rv-pop \{ max-height: calc\(100vh - 24px\);/);
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
  const base = { panel: true, console: true, search: true, chips: [{ f: 'Status', v: 'A', n: 3 }, { f: 'Status', v: 'B', n: 1 }], rows: 4, count: '', stageSrc: 2, nodes: 2, cards: 2, nodeCounts: [1, 1], storyRows: [1, 1], thPos: 'sticky', tidFont: 'ui-monospace', tidCount: 4, carry: 2, ev: 2, keySrc: 2, keyMatched: 2, keyTotal: 2, innerW: 1280,
    srcRows: [{ id: 'T1595', name: 'Active Scanning' }, { id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1190', name: 'Exploit Public-Facing Application' }, { id: 'T1059.004', name: 'Unix Shell' }],
    keyList: [{ id: 'T1190', name: 'Exploit Public-Facing Application', ev: 'The portal request log.' }, { id: 'T1059.004', name: 'Unix Shell', ev: 'Shell history.' }],
    drawn: [{ carry: false, ev: null, id: 'T1595', name: 'Active Scanning' }, { carry: true, ev: 'The portal request log.', id: 'T1190', name: 'Exploit Public-Facing Application' }, { carry: false, ev: null, id: 'T1190', name: 'Exploit Public-Facing Application' }, { carry: true, ev: 'Shell history.', id: 'T1059.004', name: 'Unix Shell' }] };
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
test('review P2 (T-0500.1.7.7): the identity of every drawn procedure row is compared with its source, marked or not', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    const measure = () => JSON.parse(JSON.stringify(f.w.eval(G.CHAIN_EXPR)));
    const verdict = (m) => G.chainTableVerdict(Object.assign({}, m, { innerW: 800, tidCount: 0 }), 4);
    const rows = () => [...f.d.querySelectorAll('#tab-chain .hl-rv-procedures tbody tr')];
    assert.equal(verdict(measure()).ok, true, 'the built table passes');
    assert.equal(rows()[0].classList.contains('hl-rv-keyrow'), false, 'the row under test is not one the report\'s list marks');
    // 1. an UNMARKED row drawn as another technique, counts unchanged: the gate used to compare identities only on marked rows
    const tid = rows()[0].querySelector('.hl-rv-tid'), was = tid.textContent; tid.textContent = 'T1000';
    const v1 = verdict(measure());
    assert.equal(v1.ok, false, 'an unmarked row drawn as another technique must FAIL: ' + v1.detail);
    assert.match(v1.detail, /row 1 \(T1595 Active Scanning\) is drawn as T1000/);
    tid.textContent = was; assert.equal(verdict(measure()).ok, true, 'put back, it passes again');
    // 2. an unmarked row drawn with another name only
    const nm = rows()[0].cells[1], nmWas = nm.textContent; nm.textContent = 'Port Scanning';
    const v2 = verdict(measure());
    assert.equal(v2.ok, false, 'an unmarked row drawn with another name must FAIL: ' + v2.detail);
    assert.match(v2.detail, /is drawn as T1595 Port Scanning/);
    nm.textContent = nmWas;
    // 3. control: a MARKED row whose identity changes still FAILS
    const tid3 = rows()[3].querySelector('.hl-rv-tid'), was3 = tid3.textContent; tid3.textContent = 'T1000';
    const v3 = verdict(measure());
    assert.equal(v3.ok, false, 'control: the marked row identity check still fires'); assert.match(v3.detail, /is drawn as T1000/);
    tid3.textContent = was3; assert.equal(verdict(measure()).ok, true);
    // 4. a report with no carries-the-case list has nothing to mark, but its drawn rows are still compared with the source
    const m = measure(), noKey = Object.assign({}, m, { keySrc: 0, keyList: [], carry: 0, ev: 0, keyMatched: null, keyTotal: 0 });
    assert.equal(verdict(noKey).ok, true, verdict(noKey).detail);
    const wrongRow = Object.assign({}, noKey, { drawn: m.drawn.map((d, i) => i ? d : Object.assign({}, d, { id: 'T1000' })) });
    assert.equal(verdict(wrongRow).ok, false, 'with no key list the drawn identities are checked all the same');
  } finally { f.w.close(); }
});
test('review P2 (T-0500.1.7.7): an open "i" note is refitted when the screen is resized or the page scrolled, and stays inside the viewport', () => {
  const f = page(STAGES + KEY + ATT);
  try {
    const w = f.w; Object.defineProperty(w, 'innerWidth', { value: 400, configurable: true }); Object.defineProperty(w, 'innerHeight', { value: 800, configurable: true });
    const btn = f.d.querySelector('.hl-rv-info'), pop = f.d.getElementById(btn.getAttribute('aria-controls'));
    assert.ok(btn && pop, 'the page draws an i button with its note');
    // the geometry is stipulated, and the note's rectangle follows its own transform the way a real box does
    let at = { popTop: 200, left: 20, btnTop: 160 };
    const shift = () => { const m = /translate\((-?\d+)px, (-?\d+)px\)/.exec(pop.style.transform || ''); return { x: m ? +m[1] : 0, y: m ? +m[2] : 0 }; };
    pop.getBoundingClientRect = () => { const s = shift(); return { left: at.left + s.x, right: at.left + 360 + s.x, top: at.popTop + s.y, bottom: at.popTop + 300 + s.y, width: 360, height: 300 }; };
    btn.getBoundingClientRect = () => ({ left: 340, right: 384, top: at.btnTop, bottom: at.btnTop + 44, width: 44, height: 44 });
    const screen = (h) => Object.defineProperty(w, 'innerHeight', { value: h, configurable: true });
    btn.click(); assert.equal(pop.style.transform, '', 'control: opened with room below, nothing moves');
    // the screen shrinks under the open note (200..500 in 400px): the note is refitted, 12px above the bottom edge
    screen(400); w.dispatchEvent(new w.Event('resize'));
    assert.equal(pop.style.transform, 'translate(0px, -112px)');
    // the screen grows back: the refit clears the transform instead of leaving the smaller screen's slide on it
    screen(800); w.dispatchEvent(new w.Event('resize'));
    assert.equal(pop.style.transform, '');
    // the page scrolls under the open note (now at 700..1000, its button at 660): refitted above the button
    at = { popTop: 700, left: 20, btnTop: 660 }; f.d.dispatchEvent(new w.Event('scroll'));
    assert.equal(pop.style.transform, 'translate(0px, -334px)');
    // a second scroll refits from the note's resting place: 1100..1400 with its button at 1060 does not fit above, so it is slid to end 12px above the bottom edge (488..788),
    // never on top of the first slide, which would have left it at 1100..1400 minus 278
    at = { popTop: 1100, left: 20, btnTop: 1060 }; f.d.dispatchEvent(new w.Event('scroll'));
    assert.equal(pop.style.transform, 'translate(0px, -612px)', 'the refit reads the note untransformed, never its own previous slide');
    btn.click(); assert.equal(pop.hidden, true); assert.equal(pop.style.transform, '', 'closing resets it');
  } finally { f.w.close(); }
});
