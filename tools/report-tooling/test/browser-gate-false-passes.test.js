'use strict';
/* T-0500.1.9 sitefix3: four false passes a cross-provider review found in the browser gate (check-browser-report.js). Each test builds a
   page, runs the REAL hl-report-tabs.js (and attack-coverage.js) over it in jsdom, and feeds what the gate would measure to the gate's own
   verdict, so a test fails exactly when the gate would pass a broken page.
     F1 an irregular table the report HAS was read as "missing" and the notice passed
     F2 a view was checked against itself, so a view that lost a source row and a summary that agreed with it passed
     F3 the ATT&CK row measured the first strip only, and counted the generated copy of the procedure table as a mapping table
     F4 a report with no chronology recorded a PASS for a fixture nothing exercised */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const ASSETS = path.join(__dirname, '../../../assets/js');
const tabsScript = fs.readFileSync(path.join(ASSETS, 'hl-report-tabs.js'), 'utf8');
const attackScript = fs.readFileSync(path.join(ASSETS, 'attack-coverage.js'), 'utf8');
const AC = require(path.join(ASSETS, 'attack-coverage.js'));
const G = require('../check-browser-report.js');

const table = (headers, rows) => '<table><thead><tr>' + headers.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>' +
  rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
const json = (v) => JSON.parse(JSON.stringify(v));

/* sections: [[token, html], ...] in article order. opts.script replaces the layout script, opts.attack runs attack-coverage.js first (as the page does). */
function page(sections, opts) {
  opts = opts || {};
  const html = sections.map(([tok, extra], i) => `<h2 class="hl-tab-${tok}" id="${tok}-s${i}">${tok} ${i}</h2><p>Original ${tok} words.</p>${extra || ''}`).join('');
  const dom = new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>' + html + '</div></div>',
    { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} };
  w.HTMLElement.prototype.scrollIntoView = function () {};
  if (opts.attack) w.eval(attackScript);
  w.eval(opts.script || tabsScript);
  assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'), 'the layout built the page');
  return { w, d: w.document, close() { w.close(); } };
}
const shapes = (f) => json(f.w.eval(G.SHAPES_EXPR));
const facts = (f, tokens) => json(f.w.eval(G.viewFactsExpr(tokens)));
const card = (f, token) => G.cardVerdict(shapes(f)[token], facts(f, [token])[0]);

const VIC = ['Organisation', 'Grade'];
const GOOD_ROWS = [['A', 'ACCESS SHOWN'], ['B', 'REACHED']];
const SHORT_ROWS = [['A', 'ACCESS SHOWN'], ['B']];

// ---------------------------------------------------------------- F1
test('F1: a two-row Organisation / Grade table with one short row is irregular and FAILS; it is not read as a missing table', () => {
  const f = page([['overview'], ['victims', table(VIC, SHORT_ROWS)]]);
  try {
    const s = shapes(f).victims;
    assert.equal(s.shape, false, 'the layout cannot read it');
    assert.equal(s.irregular.length, 1);
    assert.match(s.irregular[0].why, /row 2 has 1 cell\(s\), the header has 2/);
    // the layout showed its documented notice, which is what used to pass
    assert.match(f.d.querySelector('#hl-rv-view-victims .hl-rv-unavailable').textContent, /^View unavailable: needs an Organisation \/ Grade table/);
    const v = card(f, 'victims');
    assert.equal(v.ok, false);
    assert.equal(v.irregular, true);
    assert.match(v.detail, /whose rows are irregular, so the view cannot read it \(table 1 \(Organisation \/ Grade\): row 2 has 1 cell/);
  } finally { f.close(); }
});
test('F1 control: the same table with every row whole is read and PASSES; a table that is genuinely absent still passes its notice (J5)', () => {
  const ok = page([['overview'], ['victims', table(VIC, GOOD_ROWS)]]);
  try { const s = shapes(ok).victims; assert.equal(s.shape, true); assert.deepEqual(s.irregular, []); assert.equal(s.rows, 2); const v = card(ok, 'victims'); assert.equal(v.ok, true, v.detail); } finally { ok.close(); }
  const absent = page([['overview'], ['victims', '<p>Prose only, no table.</p>']]);
  try {
    const s = shapes(absent).victims;
    assert.equal(s.shape, false); assert.deepEqual(s.irregular, []);
    const v = card(absent, 'victims'); assert.equal(v.ok, true, v.detail); assert.equal(v.absent, true);
  } finally { absent.close(); }
});
test('F1: a header-only table, a table with no header cells and a usable table beside an irregular one are all irregular; a table with other headers is not a candidate', () => {
  const headerOnly = page([['overview'], ['victims', '<table><thead><tr><th>Organisation</th><th>Grade</th></tr></thead><tbody></tbody></table>']]);
  try { const s = shapes(headerOnly).victims; assert.equal(s.irregular[0].why, 'no data rows'); assert.equal(card(headerOnly, 'victims').ok, false); } finally { headerOnly.close(); }
  const both = page([['overview'], ['victims', table(VIC, GOOD_ROWS) + table(VIC, SHORT_ROWS)]]);
  try {
    const s = shapes(both).victims;
    assert.equal(s.shape, true, 'the usable table is read'); assert.equal(s.irregular.length, 1, 'and the broken one is still reported'); assert.equal(s.irregular[0].table, 2);
    const v = card(both, 'victims'); assert.equal(v.ok, false, 'a usable table elsewhere in the tab does not excuse the broken one');
  } finally { both.close(); }
  const other = page([['overview'], ['victims', table(['Name', 'Notes'], [['a']]) ]]);
  try { assert.deepEqual(shapes(other).victims.irregular, [], 'headers that match no view are not a candidate'); assert.equal(card(other, 'victims').ok, true); } finally { other.close(); }
});
test('F1: Overview fails when a table it reads is irregular, naming the view that table feeds', () => {
  const f = page([['overview'], ['victims', table(VIC, SHORT_ROWS)], ['chain', table(['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Scope'], [['Execution / T1059', 'x', 'OBSERVED', 'HIGH', 's']])]]);
  try {
    const v = card(f, 'overview');
    assert.equal(v.ok, false); assert.equal(v.irregular, true); assert.match(v.detail, /victims table 1/);
  } finally { f.close(); }
});

// ---------------------------------------------------------------- F2
const ATTACK = ['Tactic / Technique', 'Name', 'Status', 'Conf.', 'Scope'];
function rich(opts) {
  return page([
    ['overview', '<p>Lead sentence.</p>'],
    ['victims', table(VIC, [['A', 'ACCESS SHOWN'], ['B', 'REACHED'], ['C', 'COMPROMISED']])],
    ['chain', table(['Stage', 'What the operator did', 'Evidence'], [['One', 'did a thing that is long enough to read', 'e'], ['Two', 'did another thing', 'f']]) +
      table(ATTACK, [['Execution / T1059.001', 'PowerShell', 'OBSERVED', 'HIGH', 'a'], ['Discovery / T1082', 'System info', 'INFERRED', 'LOW', 'b'], ['Discovery / T1083', 'File discovery', 'OBSERVED', 'HIGH', 'c']])],
    ['timeline', table(['Date', 'Observation'], [['2026-01-01', 'first'], ['2026-02-01', 'second'], ['2026-03-01', 'third']])],
    ['attribution', table(['Hypothesis', 'Where it stands'], [['H1', 'leading'], ['H2', 'rejected']])],
    ['indicators', table(['Indicator', 'Action'], [['1.2.3.4', 'block'], ['evil.example', 'block'], ['abc', 'hunt']])],
    ['confidence', table(['Claim', 'Confidence', 'What would change it'], [['c1', 'HIGH', 'x'], ['c2', 'LOW', 'y']])]
  ], opts);
}
const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
const MUT_DROP = ['function find(tok, required) {', 'models.forEach(function (m) { if (m.rows.length > 1) m.rows = m.rows.slice(0, -1); }); function find(tok, required) {'];

test('F2 control: on the unmutated rich page every view matches its source table, rows and identities', () => {
  const f = rich();
  try {
    const s = shapes(f);
    TOKENS.forEach(t => assert.equal(s[t].shape, true, t));
    assert.equal(s.victims.rows, 3); assert.deepEqual(s.victims.ids, ['A', 'B', 'C']); assert.deepEqual(s.overview.tiles, ['2', '3', '3', '2026-01-01 to 2026-03-01']);
    TOKENS.forEach(t => { const v = card(f, t); assert.equal(v.ok, true, t + ': ' + v.detail); });
  } finally { f.close(); }
});
test('F2: the review repro. A Victims builder that draws one of two source rows, with a summary that says one, FAILS against the source', () => {
  const mutated = tabsScript.replace('var grade = col(victims, /Grade/i), counts = {};', 'victims = Object.assign({}, victims, { rows: victims.rows.slice(0,1) }); var grade = col(victims, /Grade/i), counts = {};');
  assert.notEqual(mutated, tabsScript, 'the mutation applied');
  const f = page([['overview'], ['victims', table(VIC, GOOD_ROWS)]], { script: mutated });
  try {
    const fact = facts(f, ['victims'])[0];
    assert.equal(fact.count, 1); assert.match(fact.line, /^1 organisation rows/);
    assert.equal(f.d.querySelectorAll('#tab-victims .hl-rv-source tbody tr').length, 2, 'the source still has two rows');
    const v = G.cardVerdict(shapes(f).victims, fact);
    assert.equal(v.ok, false); assert.match(v.detail, /summary states 1, the source has 2 rows/); assert.match(v.detail, /draws 1 .*, the source has 2 rows/);
  } finally { f.close(); }
});
test('F2: a layout that drops the last source row from every view, with each summary and Overview agreeing, FAILS for every view', () => {
  const mutated = tabsScript.split(MUT_DROP[0]).join(MUT_DROP[1]);
  assert.notEqual(mutated, tabsScript);
  const f = rich({ script: mutated });
  try {
    TOKENS.forEach(t => {
      const fact = facts(f, [t])[0];
      assert.ok(fact.line, t + ' states a summary the mutated layout agrees with');
      const v = G.cardVerdict(shapes(f)[t], fact);
      assert.equal(v.ok, false, t + ': ' + v.detail);
      assert.equal(v.notChecked, undefined);
    });
    // Overview, on its own terms: the procedure-row tile says 2 where the source has 3
    assert.match(card(f, 'overview').detail, /tile values/);
  } finally { f.close(); }
});
test('F2: a view that draws the right NUMBER of rows but a different row FAILS on identity', () => {
  const mutated = tabsScript.replace('var grade = col(victims, /Grade/i), counts = {};', 'victims = Object.assign({}, victims, { rows: victims.rows.map(function () { return victims.rows[0]; }) }); var grade = col(victims, /Grade/i), counts = {};');
  assert.notEqual(mutated, tabsScript);
  const f = page([['overview'], ['victims', table(VIC, GOOD_ROWS)]], { script: mutated });
  try { const v = card(f, 'victims'); assert.equal(v.ok, false); assert.match(v.detail, /1 of 2 row identities differ from the source \(first: "B"\)/); } finally { f.close(); }
});
test('F2: a shape with no source expectation is NOT CHECKED, never a comparison of the view with itself', () => {
  const v = G.viewShapeVerdict('victims', true, '5 organisation rows', 5, null, {});
  assert.equal(v.notChecked, true); assert.equal(v.ok, false);
  assert.equal(G.viewShapeVerdict('victims', true, '5 organisation rows', 5, null, { rows: 5 }).ok, true);
  assert.equal(G.viewShapeVerdict('victims', true, '4 organisation rows', 4, null, { rows: 5 }).ok, false, 'view and summary agree with each other, not with the source');
});

// ---------------------------------------------------------------- F3
const detect = (f) => f.w.eval('(' + G.attackTablesInPage.toString() + ')(' + JSON.stringify(G.ATTACK_TACTICS) + ')');
test('F3: the gate\'s tactic list is attack-coverage.js\'s own list plus its three aliases', () => {
  assert.deepEqual(G.ATTACK_TACTICS.slice(0, 15), AC.TACTIC_ORDER);
  assert.deepEqual(G.ATTACK_TACTICS.slice(15), ['Priv. Escalation', 'C&C', 'Defense Evasion']);
});
test('F3: mapping tables are found by rule in the report\'s own sections: the generated copy of the procedure table is not a third table, and a table with IDs but no tactic gets no strip', () => {
  const noTactic = table(['Tactic', 'Technique'], [['Misc', 'T1059'], ['Other', 'T1082']]);
  const f = page([['overview'], ['chain', table(ATTACK, [['Execution / T1059.001', 'PS', 'OBSERVED', 'HIGH', 'a'], ['Discovery / T1082', 'x', 'OBSERVED', 'HIGH', 'b']]) +
    table(ATTACK, [['Persistence / T1547', 'y', 'OBSERVED', 'HIGH', 'c']]) + noTactic]], { attack: true });
  try {
    // 3 tables with a Tactic header and technique IDs anywhere on the page, the pre-fix gate's count
    const loose = [...f.d.querySelectorAll('table')].filter(t => /tactic/i.test(t.rows[0].textContent) && /\bT\d{4}/.test(t.textContent));
    const generated = loose.filter(t => t.closest('.hl-rv-view'));
    assert.equal(generated.length, 1, 'the layout draws a copy of the procedure table, which a page-wide discovery counts as another mapping table');
    assert.equal(loose.length, 3, 'two source tables plus that copy: the pre-fix discovery read textContent, which joins adjacent cells ("MiscT1059"), so it also missed the third source table');
    const d = detect(f);
    assert.deepEqual(json([...d.list].map(x => [x.index, x.mapped, !!x.strip])), [[1, true, true], [2, true, true], [3, false, false]]);
    assert.equal(d.list[2].withId, 2, 'the third table carries IDs and is skipped by rule, not by count');
    assert.equal(d.strips.length, 2); assert.equal(d.unpaired, 0);
    assert.equal(d.list.every(x => !x.table.closest('.hl-rv-view')), true, 'no generated table is read');
  } finally { f.close(); }
});
test('F3: with the second strip gone the discovery pairs one strip with one table and the verdict FAILS naming the other', () => {
  const lost = attackScript.replace('findMappingTables(body).forEach(function (table) {', 'findMappingTables(body).slice(0, -1).forEach(function (table) {');
  assert.notEqual(lost, attackScript);
  // build with a mutated attack script by running it in place of the real one
  const build = (src) => { const dom = new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p><h2 class="hl-tab-overview" id="o">o</h2><p>x</p><h2 class="hl-tab-chain" id="c">c</h2>' +
    table(ATTACK, [['Execution / T1059.001', 'PS', 'OBSERVED', 'HIGH', 'a']]) + table(ATTACK, [['Persistence / T1547', 'y', 'OBSERVED', 'HIGH', 'c']]) + '</div></div>', { url: 'https://example.test/r/', runScripts: 'outside-only' });
    const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
    w.eval(src); w.eval(tabsScript); return { w, d: w.document, close() { w.close(); } }; };
  const real = build(attackScript), part = build(lost);
  try {
    assert.equal(real.d.querySelectorAll('.hl-attack').length, 2); assert.equal(part.d.querySelectorAll('.hl-attack').length, 1);
    const asM = (f) => { const d = detect(f); return { sourceBlocks: d.blocks, tablesRead: d.tablesRead, stripsOnPage: d.strips.length, unpaired: d.unpaired,
      tables: d.list.map(x => ({ index: x.index, label: x.label, panel: x.panel, rows: x.rows, withId: x.withId, mapped: x.mapped,
        strip: x.strip ? { chrome: x.strip.hasAttribute('data-rv-chrome'), segs: x.strip.querySelectorAll('.hl-attack__seg').length, techniques: 1, count: '1 techniques', visible: true, exportCount: 1, exportVisible: true, exportText: '↓ Navigator layer', download: { file: 'x.json', techniques: 1 } } : null })) }; };
    const okV = G.attackStripVerdict(asM(real)); assert.equal(okV.ok, true, okV.detail);
    const badV = G.attackStripVerdict(asM(part));
    assert.equal(badV.ok, false); assert.match(badV.why.join(' | '), /mapping table 2 .* has no coverage strip \(1 strip\(s\) on the page for 2 mapping table\(s\)\)/);
  } finally { real.close(); part.close(); }
});

// ---------------------------------------------------------------- F4
test('F4: a report with no chronology gets an injected 25-date fixture the real layout builds a timeline from; the row says it was injected', () => {
  const html = '<html><body><div class="hl-post-content"><h2 class="hl-tab-overview" id="o">Overview</h2><p>x</p><h2 class="hl-tab-chain" id="c">Chain</h2><p>y</p></div></body></html>';
  assert.equal(G.timelineFixtureHtml(html), null, 'the report has no chronology to scale');
  const plan = G.timelineFixturePlan(html, { timeline: { shape: false } });
  assert.equal(plan.kind, 'injected');
  assert.equal((plan.html.match(/Fixture observation/g) || []).length, 25);
  assert.ok(plan.html.indexOf('hl-gate-fixture-chronology') < plan.html.indexOf('id="c"'), 'injected ahead of the first tab section');
  // the layout turns it into a 25-event timeline
  const dom = new JSDOM(plan.html.replace('<html><body>', '<html><body><div class="hl-report-page">').replace('</body>', '</div></body>'), { url: 'https://example.test/r/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(tabsScript);
  try {
    assert.ok(w.document.getElementById('tab-timeline'), 'a timeline tab is built');
    assert.equal(w.document.querySelectorAll('#tab-timeline .hl-rv-marker').length, 25);
    assert.equal(w.document.querySelectorAll('#tab-timeline .hl-rv-axis span').length, 25);
    assert.equal(w.document.querySelectorAll('#tab-timeline .hl-rv-unavailable').length, 0);
  } finally { w.close(); }
});
test('F4: the plan is derived from the report\'s own chronology when it has one; with nothing to scale and nothing to inject it is NOT CHECKED, never a PASS', () => {
  const chron = '<html><body>' + table(['Date', 'Observation', 'Source'], [['2026-01-01', 'x', 'y']]) + '</body></html>';
  assert.equal(G.timelineFixturePlan(chron, { timeline: { shape: true } }).kind, 'derived');
  const none = G.timelineFixturePlan('<html><body><p>no tab sections at all</p></body></html>', { timeline: { shape: false } });
  assert.equal(none.kind, 'none'); assert.equal(none.html, null); assert.match(none.reason, /no tab section to inject one before/);
  const unknown = G.timelineFixturePlan('<html><body><h2 class="hl-tab-chain">c</h2></body></html>', null);
  assert.equal(unknown.kind, 'none');
});
test('F4: the gate no longer has a branch that records a PASS for a fixture it did not exercise', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'check-browser-report.js'), 'utf8');
  assert.equal(/25-date timeline fixture: not applicable/.test(src), false);
  const at = src.indexOf("the 25-date timeline fixture (5.4)");
  const block = src.slice(at, src.indexOf("var fixturePath", at));
  assert.equal(/check\([^;]*,\s*true\s*,/.test(block), false, 'no check(name, true, ...) in the fixture-plan branch');
});

// ---------------------------------------------------------------- the controls the live gate runs, built here
test('the live gate\'s three layout mutations still apply to the real scripts, so no control is NOT CHECKED for want of text', () => {
  assert.ok(G.mutatedTabsScript([G.MUT_DROP_SOURCE_ROW]), 'hl-report-tabs.js still holds the text the source-row control changes');
  assert.ok(G.mutatedTabsScript([G.MUT_NO_THIN]), 'hl-report-tabs.js still holds the text the thinning control changes');
  assert.ok(G.mutatedTabsScript([G.MUT_DROP_LAST_STRIP], 'attack-coverage.js'), 'attack-coverage.js still holds the text the strip control changes');
});
test('the injected control fixture gives a victim table and a procedure table the real layout reads, with two or more rows each', () => {
  const html = '<html><body><div class="hl-report-page"><div class="hl-post-content"><h2 class="hl-tab-overview" id="o">Overview</h2><p>x</p><h2 class="hl-tab-indicators" id="i">I</h2><p>y</p></div></div></body></html>';
  const out = G.controlFixtureHtml(html);
  assert.ok(out); assert.equal(G.controlFixtureHtml('<html><body><p>no tab sections</p></body></html>'), null);
  const dom = new JSDOM(out, { url: 'https://example.test/r/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(tabsScript);
  try {
    const s = json(w.eval(G.SHAPES_EXPR));
    assert.equal(s.victims.shape, true); assert.equal(s.victims.rows, 3); assert.equal(s.overview.attackRows, 3);
    ['victims', 'overview'].forEach(t => { const v = G.cardVerdict(s[t], json(w.eval(G.viewFactsExpr([t])))[0]); assert.equal(v.ok, true, t + ': ' + v.detail); });
  } finally { w.close(); }
});
test('irregularTableHtml removes one data cell from the last row of the chosen table, and the layout then reports that table irregular', () => {
  const html = '<html><body><div class="hl-report-page"><div class="hl-post-content"><h2 class="hl-tab-overview" id="o">Overview</h2><p>x</p><h2 class="hl-tab-victims" id="v">V</h2>' +
    table(['Name', 'Notes'], [['a', 'b']]) + table(VIC, [['A', 'ACCESS SHOWN'], ['B', 'REACHED']]) + '</div></div></body></html>';
  const cands = G.irregularTableCandidates(html, null);
  assert.deepEqual(json(cands.map(c => c.tokens)), [['victims']], 'only the table whose headers a view reads is a candidate');
  assert.equal(cands[0].blockIndex, 1);
  const out = G.irregularTableHtml(html, cands[0]);
  assert.equal((html.match(/<td>/g) || []).length - (out.match(/<td>/g) || []).length, 1, 'exactly one cell removed');
  assert.match(out, /<tr><td>B<\/td><\/tr>/);
  const dom = new JSDOM(out, { url: 'https://example.test/r/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(tabsScript);
  try { const s = json(w.eval(G.SHAPES_EXPR)); assert.equal(s.victims.irregular.length, 1); const v = G.cardVerdict(s.victims, json(w.eval(G.viewFactsExpr(['victims'])))[0]); assert.equal(v.ok, false); assert.equal(v.irregular, true); } finally { w.close(); }
  // the shapes filter: with the report's shapes known, a table for a shape the report lacks is not a candidate
  assert.equal(G.irregularTableCandidates(html, { victims: { shape: false } }).length, 0);
});
