'use strict';
/* T-0500.1.11 (b1fix): the browser gate used a tab the page did not build. inkognito tags no timeline section; the 25-date fixture step
   clicked #hl-rv-toggle-timeline and the whole gate ended "click target not present". Every step now uses only the tabs the page built, and
   says NOT CHECKED (or exercises a gate-supplied fixture and says so) for one it lacks. Each test runs the REAL hl-report-tabs.js over a
   page that has no timeline tab, in jsdom, and drives the gate's own helpers against it. */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const tabsScript = fs.readFileSync(path.join(__dirname, '../../../assets/js/hl-report-tabs.js'), 'utf8');
const G = require('../check-browser-report.js');
const src = fs.readFileSync(path.join(__dirname, '..', 'check-browser-report.js'), 'utf8');

const table = (headers, rows) => '<table><thead><tr>' + headers.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>' +
  rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
/* inkognito's shape: a Date / Event table, but inside a section tagged for Attack chain; nothing is tagged for the timeline */
const noTimelineTab = '<html><body><div class="hl-post-content">' +
  '<h2 class="hl-tab-overview" id="o">Overview</h2><p>x</p>' +
  '<h2 class="hl-tab-chain" id="c">Dynamic analysis</h2>' + table(['Date', 'Event'], [['2026-01-01', 'a'], ['2026-01-09', 'b']]) +
  '<h2 class="hl-tab-confidence" id="k">Confidence</h2><p>y</p></div></body></html>';

function build(html) {
  const dom = new JSDOM(html.replace('<html><body>', '<html><body><div class="hl-report-page">').replace('</body>', '</div></body>'), { url: 'https://example.test/r/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(tabsScript);
  return w;
}
/* a page object with the two methods the helpers use; click throws the way the gate's CDP click does for a missing target */
function pageOf(w) {
  const log = { clicks: [] };
  return { log,
    async evaluate(expr) { return w.eval(expr); },
    async click(sel) { const el = w.document.querySelector(sel); if (!el) throw new Error('click target not present: ' + sel); log.clicks.push(sel); el.click(); } };
}

test('the fixture page really has no timeline tab and no toggle for one (the shape that errored the gate)', () => {
  const w = build(noTimelineTab);
  assert.deepEqual([...w.document.querySelectorAll('[role=tab]')].map(t => t.id), ['tabbtn-overview', 'tabbtn-chain', 'tabbtn-confidence']);
  assert.equal(w.document.getElementById('hl-rv-toggle-timeline'), null);
  assert.ok(w.document.getElementById('hl-rv-toggle-chain'), 'a tab it did build has its toggle');
});

test('clickToggle: a missing toggle is reported false and never thrown; a present one is clicked', async () => {
  const w = build(noTimelineTab), page = pageOf(w);
  await assert.rejects(() => page.click('#hl-rv-toggle-timeline'), /click target not present/, 'the raw click is what used to end the gate');
  assert.equal(await G.clickToggle(page, 'timeline'), false);
  assert.deepEqual(page.log.clicks, [], 'no click was attempted on the absent control');
  assert.equal(await G.clickToggle(page, 'chain'), true);
  assert.deepEqual(page.log.clicks, ['#hl-rv-toggle-chain']);
});

test('hasTab reads the tabs the page built; before the built set is known it falls back to the full list', () => {
  G.setLiveTokens(['overview', 'chain', 'confidence']);
  try {
    assert.equal(G.hasTab('chain'), true); assert.equal(G.hasTab('timeline'), false);
  } finally { G.setLiveTokens(null); }
  assert.equal(G.hasTab('timeline'), true);
});

test('fixture plan: a page with a dated table but no Timeline tab does NOT derive the fixture from it (it would draw nothing); it injects, and the injected one builds the timeline', () => {
  const asked = G.timelineFixturePlan(noTimelineTab, { timeline: { shape: true } }, false);
  assert.equal(asked.kind, 'injected');
  const derived = G.timelineFixturePlan(noTimelineTab, { timeline: { shape: true } });
  assert.equal(derived.kind, 'derived', 'the unqualified call still derives (older callers)');
  assert.equal(build(derived.html).document.getElementById('tab-timeline'), null, 'derived from a chain-tab table: no timeline tab is built, so nothing to click');
  const w = build(asked.html);
  assert.ok(w.document.getElementById('tab-timeline'), 'the injected chronology is tagged for the timeline');
  assert.ok(w.document.getElementById('hl-rv-toggle-timeline'));
  assert.equal(w.document.querySelectorAll('#tab-timeline .hl-rv-marker').length, 25);
  assert.equal(G.timelineFixturePlan(noTimelineTab, { timeline: { shape: true } }, true).kind, 'derived', 'with a Timeline tab the report\'s own table is still used');
});

test('fixture plan: no Timeline tab and no tab section to inject before is NOT CHECKED with the reason, never an error', () => {
  const none = G.timelineFixturePlan('<html><body><p>nothing tagged</p></body></html>', { timeline: { shape: true } }, false);
  assert.equal(none.kind, 'none'); assert.equal(none.html, null);
  assert.match(none.reason, /builds no Timeline tab/);
});

test('every toggle click in the gate goes through clickToggle, and no step names a tab the page may lack', () => {
  const raw = src.match(/page\.click\('#hl-rv-toggle-/g) || [];
  assert.equal(raw.length, 1, 'one raw click remains: the one inside clickToggle');
  assert.equal(/location\.hash="#tab-overview"/.test(src), false, 'restoreReportPage selects the first built tab, not Overview');
  assert.equal(/location\.hash="#tab-timeline"/.test(src.replace(/if \(hasTab\('timeline'\)\) await page\.evaluate\('location\.hash="#tab-timeline"'\);/, '')), false, 'the timeline hash is set only when the tab exists');
  assert.equal(/gotoAndWait\([^;]*'#tab-chain'/.test(src), false, 'the strip rows open the chain tab only when the page built one');
});

test('CSS: on the tabbed layout the "Updated <date>" link takes the date label\'s size, so it is not 0.9em of the 14px recipe (12.6px, under the 13px floor)', () => {
  const css = fs.readFileSync(path.join(__dirname, '../../../assets/css/hl-report-tabs.css'), 'utf8');
  assert.match(css, /\.hl-report-page \.hl-post-header__date \.hl-last-updated \{ font-size: inherit; \}/);
  const scss = fs.readFileSync(path.join(__dirname, '../../../assets/css/custom.scss'), 'utf8');
  assert.match(scss, /\.hl-last-updated \{[^}]*font-size: 0\.9em;/, 'the untagged layout keeps its own 0.9em (this change is the tabbed layout only)');
});
