'use strict';
/* T-0605 lane R: the report-tabs fixes (L01 full severity word, L16 no empty campaign-record block, L17 one numbering style in the "In this tab" rail,
   L18 no label-only Diamond entry), the glossary tooltip placement (L08) and the hero-panel gate (L19). jsdom runs the real scripts; the geometry the
   tooltip and the gate need is stubbed in the test, never invented by the script. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { JSDOM } = require('jsdom');
const script = fs.readFileSync(path.join(__dirname, '../../../assets/js/hl-report-tabs.js'), 'utf8');
const GLOSS = require('../../../assets/js/glossary.js');
const HERO = require('../check-browser-hero.js');

const txt = n => n.textContent.replace(/\s+/g, ' ').trim();
/* A report page with the given source HTML inside .hl-post-content, the real tabs script run over it. */
function build(html, opts) {
  opts = opts || {};
  const dom = new JSDOM('<div class="hl-report-page"><div class="hl-post-content">' + html + '</div></div>', { url: 'https://example.test/report/', runScripts: 'outside-only' });
  const w = dom.window; w.matchMedia = () => ({ matches: false, addEventListener() {} }); w.ResizeObserver = class { observe() {} }; w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(script); assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'), 'the script enhanced the page');
  return { w, d: w.document };
}
const h2 = (tok, id, head) => `<h2 class="hl-tab-${tok}" id="${id}">${head}</h2><p>Words of ${id}.</p>`;
const rail = (d, tab) => [...d.querySelectorAll('#tab-' + tab + ' .hl-rv-side a')].map(a => [txt(a.querySelector('b')), txt(a).slice(txt(a.querySelector('b')).length)]);

/* ---------------- L01 ---------------- */
test('L01: the threat tile prints the whole word CRITICAL, with no abbreviation and nothing stored to restore it', () => {
  const f = build('<p>Threat Level: CRITICAL</p>' + h2('overview', 'o', 'Overview'));
  try {
    const tile = f.d.querySelector('[data-rv-tile=threat]');
    assert.equal(txt(tile.querySelector('strong')), 'CRITICAL');
    assert.equal(tile.dataset.rvFull, undefined, 'the printed value is the value: no CRIT. to expand');
    assert.equal(tile.querySelector('strong').style.getPropertyValue('--hl-rv-chars'), '8', 'the word is sized to fit its tile by its own length');
    assert.doesNotMatch(f.d.body.textContent, /CRIT\./);
  } finally { f.w.close(); }
});

/* ---------------- L16 ---------------- */
test('L16: whitespace before the first h2 opens no campaign-record block; a real leading paragraph still does, labelled and holding its text', () => {
  const blank = build('\n\n' + h2('overview', 'o', 'The report title') + h2('chain', 'c', 'Chain'));
  try {
    assert.equal(blank.d.querySelectorAll('.hl-rv-nohead').length, 0, 'no empty CAMPAIGN RECORD block');
    assert.equal(blank.d.querySelectorAll('.hl-rv-source').length, 2, 'one block per h2');
    assert.ok(blank.d.querySelector('#tab-overview #o'), 'the title section is still in the Overview');
  } finally { blank.w.close(); }
  const lead = build('<p>Campaign Identifier: X-1</p>' + h2('overview', 'o', 'Overview'));
  try {
    const n = lead.d.querySelectorAll('.hl-rv-nohead');
    assert.equal(n.length, 1);
    assert.equal(n[0].dataset.rvSec, 'CAMPAIGN RECORD');
    assert.match(txt(n[0]), /Campaign Identifier: X-1/);
  } finally { lead.w.close(); }
});

test('L16: the whitespace is kept, in report order, inside the first section: nothing the report holds is dropped', () => {
  const f = build('\n  ' + h2('overview', 'o', 'Title'));
  try {
    const first = f.d.querySelector('#tab-overview .hl-rv-source');
    assert.equal(first.firstChild.nodeType, 3);
    assert.match(first.firstChild.textContent, /^\s+$/);
    assert.equal(first.firstElementChild.id, 'o');
  } finally { f.w.close(); }
});

/* ---------------- L17 ---------------- */
test('L17: a rail whose entries all carry a source number prints it, and never leaves "Section N:" in the text', () => {
  const f = build(h2('overview', 'o', 'Overview') + h2('chain', 'a', 'Section 1: First') + h2('chain', 'b', 'Section 12: Twelfth') + h2('chain', 'c', '3. Third'));
  try { assert.deepEqual(rail(f.d, 'chain'), [['01', 'First'], ['12', 'Twelfth'], ['03', 'Third']]); } finally { f.w.close(); }
});

test('L17: a rail that mixes numbered and plain entries prints one style: the plain dot on every entry, the source number out of the text', () => {
  const f = build(h2('overview', 'o', 'Executive Summary') + h2('overview', 'p', 'Section 8: Key Takeaways') + h2('overview', 'q', '10. What Matters Most') + h2('overview', 'r', 'Summary'));
  try {
    const r = rail(f.d, 'overview');
    assert.deepEqual(r, [['·', 'Executive Summary'], ['·', 'Key Takeaways'], ['·', 'What Matters Most'], ['·', 'Summary']]);
    assert.ok(r.every(x => !/^\s*(Section\s+)?\d+\s*[.):]/i.test(x[1])));
  } finally { f.w.close(); }
});

test('L17: the section headings themselves keep their source words', () => {
  const f = build(h2('overview', 'o', 'Section 8: Key Takeaways'));
  try { assert.equal(txt(f.d.getElementById('o')).replace(/§$/, ''), 'Section 8: Key Takeaways'); } finally { f.w.close(); }
});

/* ---------------- L18 ---------------- */
const cards = d => [...d.querySelectorAll('.hl-rv-diamond-card')].map(c => [txt(c.querySelector('h3')), c.querySelector('blockquote') ? txt(c.querySelector('blockquote')) : null, txt(c)]);
test('L18: the Diamond entry skips a bold label paragraph and a lead-in that ends in a colon, and quotes the first statement', () => {
  const f = build(h2('overview', 'o', 'Overview') +
    '<h2 class="hl-tab-attribution" id="a">Section 6: Threat Intelligence &amp; Attribution Context</h2><p><strong>Rust Compilation Artifacts:</strong></p><p>It was built in a Linux Rust environment:</p><p>The operator reused one build path. A second sentence follows.</p>' +
    '<h2 class="hl-tab-chain" id="k">Section 1: Malware Classification</h2><p><b>Classification &amp; Identification:</b></p><p>Not a statement either:</p>');
  try {
    const c = cards(f.d);
    assert.equal(c[0][0], 'Adversary'); assert.equal(c[0][1], 'The operator reused one build path.', 'the first statement, one sentence');
    assert.equal(c[1][0], 'Capability'); assert.equal(c[1][1], null, 'only labels in the section: the honest fallback, not a label with a colon');
    assert.match(c[1][2], /No structured capability statement found/);
    f.d.querySelectorAll('.hl-rv-diamond-card blockquote').forEach(b => assert.doesNotMatch(txt(b), /:$/, 'no entry ends in a colon'));
  } finally { f.w.close(); }
});
test('L18: a paragraph whose first sentence is a statement is kept even when the paragraph ends in a colon', () => {
  const f = build(h2('overview', 'o', 'Overview') + '<h2 class="hl-tab-attribution" id="a">Attribution</h2><p>The actor is unnamed. The evidence is:</p>');
  try { assert.equal(cards(f.d)[0][1], 'The actor is unnamed.'); } finally { f.w.close(); }
});

/* ---------------- L08 ---------------- */
test('L08: tipOffset keeps the tooltip on screen: untouched when it fits, pulled left at the right edge, pinned to the margin on a narrow screen', () => {
  assert.equal(GLOSS.tipOffset(40, 292, 375, 8), 0, 'fits where it is');
  assert.equal(GLOSS.tipOffset(200, 292, 375, 8), 75 - 200, 'left edge moves to 375 - 292 - 8 = 75');
  assert.equal(GLOSS.tipOffset(2, 292, 375, 8), 6, 'a mark under the margin is pushed in to it');
  assert.equal(GLOSS.tipOffset(100, 400, 375, 8), 8 - 100, 'wider than the screen: pinned to the left margin');
  assert.equal(GLOSS.tipOffset(100, 0, 375, 8), 0, 'nothing measurable: no move');
  assert.equal(GLOSS.tipOffset(100, 292, 0, 8), 0);
});
function markIn(opts) {
  const dom = new JSDOM('<body><div class="hl-post-content"><p><span class="hl-gloss hl-gloss--right" tabindex="0" data-gloss="x">C2</span></p></div></body>');
  const w = dom.window, d = w.document, m = d.querySelector('.hl-gloss');
  Object.defineProperty(d.documentElement, 'clientWidth', { value: opts.vw }); Object.defineProperty(d.documentElement, 'clientHeight', { value: opts.vh || 800 });
  m.getClientRects = () => [{ left: opts.left, right: opts.left + 20, top: opts.top || 300, bottom: (opts.top || 300) + 20, width: 20, height: 20 }];
  w.getComputedStyle = () => ({ position: opts.position || 'absolute', width: opts.tipW === undefined ? '292px' : opts.tipW, height: opts.tipH === undefined ? '80px' : opts.tipH });
  return { m, w };
}
test('L08: placeTooltip at 375 px moves a right-flipped tooltip back on screen, drops the flip class, and sets only a custom property', () => {
  const { m } = markIn({ vw: 375, left: 200 });
  assert.equal(GLOSS.placeTooltip(m), true);
  assert.equal(m.classList.contains('hl-gloss--right'), false);
  assert.equal(m.style.getPropertyValue('--hl-gloss-left'), (75 - 200) + 'px');
  assert.equal(m.style.getPropertyValue('--hl-gloss-top'), '', 'room below: stays below');
});
test('L08: placeTooltip opens above the term when there is no room below and room above; the width falls back to the largest when none can be read', () => {
  const low = markIn({ vw: 375, left: 40, top: 740, vh: 800 });
  assert.equal(GLOSS.placeTooltip(low.m), true);
  assert.equal(low.m.style.getPropertyValue('--hl-gloss-top'), '-86px', 'minus the 80px tooltip and the 6px gap');
  const unread = markIn({ vw: 375, left: 300, tipW: 'auto', tipH: 'auto' });
  assert.equal(GLOSS.placeTooltip(unread.m), true);
  assert.equal(unread.m.style.getPropertyValue('--hl-gloss-left'), (375 - 292.5 - 8 - 300) + 'px', 'the largest width is min(320, 78% of 375) = 292.5');
  assert.equal(unread.m.style.getPropertyValue('--hl-gloss-top'), '', 'height unknown: no vertical move');
});
test('L08: a tooltip the page places itself (position: fixed, the report pages) is left alone', () => {
  const { m } = markIn({ vw: 375, left: 200, position: 'fixed' });
  assert.equal(GLOSS.placeTooltip(m), false);
  assert.equal(m.style.getPropertyValue('--hl-gloss-left'), '');
  assert.equal(m.classList.contains('hl-gloss--right'), true, 'its own classes are untouched');
});
test('L08: the stylesheet reads the custom properties with the old values as defaults, and the 320px cap still matches TOOLTIP_MAX_PX', () => {
  const css = fs.readFileSync(path.join(__dirname, '../../../assets/css/custom.scss'), 'utf8');
  const rule = css.match(/\.hl-gloss::after \{[^}]*\}/)[0];
  assert.match(rule, /left: var\(--hl-gloss-left, 0px\)/);
  assert.match(rule, /top: var\(--hl-gloss-top, 1\.5em\)/);
  assert.match(rule, /max-width: min\(320px, 78vw\)/);
  assert.match(css, /\.hl-gloss--right::after \{ left: auto; right: 0; \}/, 'the desktop flip rule is unchanged');
});

/* ---------------- L19 ---------------- */
const sound = () => ({ visible: true, panel: { l: 20, t: 100, r: 240, b: 380 }, vw: 375, vh: 900, scrollY: 500, firstItem: { label: 'YARA', covered: false, hit: null } });
test('L19: panelVerdict passes a panel inside the viewport, uncovered, with the page where it was', () => {
  assert.deepEqual(HERO.panelVerdict(sound(), 500), []);
  assert.deepEqual(HERO.panelVerdict(sound(), 500.4), [], 'under one px of scroll is not a move');
});
test('L19: panelVerdict FAILS a rect outside the viewport on each side, a covered first item, a moved page, an invisible panel and a missing one', () => {
  for (const [name, p] of [['left', { l: -180, t: 100, r: 40, b: 380 }], ['right', { l: 200, t: 100, r: 420, b: 380 }], ['top', { l: 20, t: -50, r: 240, b: 380 }], ['bottom', { l: 20, t: 700, r: 240, b: 1000 }]]) {
    const m = sound(); m.panel = p; const v = HERO.panelVerdict(m, 500);
    assert.equal(v.length, 1, name); assert.match(v[0], /outside the 375x900 viewport/, name);
  }
  const covered = sound(); covered.firstItem = { label: 'YARA', covered: true, hit: 'header.hl-nav' };
  assert.match(HERO.panelVerdict(covered, 500)[0], /first item \(YARA\) is covered by header\.hl-nav/);
  const moved = sound(); moved.scrollY = 759;
  assert.match(HERO.panelVerdict(moved, 500)[0], /page moved 259 px on opening/);
  const gone = sound(); gone.visible = false; assert.deepEqual(HERO.panelVerdict(gone, 500), ['panel not visible after the click']);
  assert.deepEqual(HERO.panelVerdict({ missing: true }, 500), ['panel element not found']);
  const empty = sound(); empty.firstItem = null; assert.match(HERO.panelVerdict(empty, 500)[0], /no link or button/);
});
test('L19: parseArgs reads the site from HL_SITE_DIR or --site, the widths, --only and --limit, and refuses what it does not know', () => {
  assert.deepEqual(HERO.parseArgs([], { HL_SITE_DIR: '/x' }), { site: '/x', only: null, limit: 0, widths: [375, 1280], bad: null });
  const o = HERO.parseArgs(['--site', '/y', '--only', 'enc', '--limit', '3', '--widths', '320,1024'], {});
  assert.deepEqual([o.site, o.only, o.limit, o.widths, o.bad], ['/y', 'enc', 3, [320, 1024], null]);
  assert.match(HERO.parseArgs(['--nope'], {}).bad, /unknown argument/);
  assert.match(HERO.parseArgs(['--widths', 'x'], {}).bad, /widths/);
});
function fakeSite() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-hero-'));
  const put = (rel, body) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), body); };
  put('reports/a/index.html', '<button id="hl-detect-tab"></button><button id="hl-ioc-tab"></button>');
  put('reports/b/c/index.html', '<button id="hl-stix-tab"></button>');
  put('reports/d/index.html', '<p>no hero button on this page</p>');
  put('reports/index.html', '<button id="hl-detect-tab"></button>');
  put('wire/index.html', '<button id="hl-detect-tab"></button>');
  return root;
}
test('L19: listPages names the report pages that carry a hero button, nothing else, and --only narrows it', () => {
  const root = fakeSite();
  try {
    assert.deepEqual(HERO.listPages(root), ['/reports/a/', '/reports/b/c/']);
    assert.deepEqual(HERO.listPages(root, '/c/'), ['/reports/b/c/']);
    assert.deepEqual(HERO.listPages(path.join(root, 'missing')), []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('L19: with no site, an empty site or a bad argument the gate says NOT CHECKED and exits 2, never PASS', () => {
  const run = (args, env) => cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'check-browser-hero.js')].concat(args), { env: Object.assign({}, process.env, { HL_SITE_DIR: '' }, env), encoding: 'utf8' });
  const none = run([]); assert.equal(none.status, 2); assert.match(none.stdout, /^NOT CHECKED/m);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-hero-'));
  try { const r = run(['--site', empty]); assert.equal(r.status, 2); assert.match(r.stdout, /no built report page/); } finally { fs.rmSync(empty, { recursive: true, force: true }); }
  const bad = run(['--bogus']); assert.equal(bad.status, 2); assert.match(bad.stdout, /unknown argument/);
});
