'use strict';
/* T-0500.1.7.4 b2: the home page and the section indexes in design D. Static checks on the page sources, the includes and the stylesheet, plus the
   two includes whose behaviour is logic (the KPI tiles and the topic vocabulary) rendered with Ruby's Liquid. When ruby or the gem is missing those
   cases report NOT CHECKED (skipped with the reason), never PASS. See homelab-soc/docs/gate-honesty-contract.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const css = read('assets/css/custom.scss');
const strip = (s) => s.replace(/\{%-? comment -?%\}[\s\S]*?\{%-? endcomment -?%\}/g, '');
const b2Start = css.indexOf('DESIGN D: HOME AND SECTION INDEXES (T-0500.1.7.4 b2)');
const b3Start = css.indexOf('DESIGN D: ACTOR, FAMILY AND TECHNIQUE PAGES AS DASHBOARDS (T-0500.1.7.4 b3)');
assert.ok(b3Start > b2Start, 'the b3 blocks follow the b2 block');
const b2 = css.slice(css.indexOf('*/', b2Start) + 2, css.lastIndexOf('/*', b3Start));   // the b2 block only; b3 has its own scopes (design-d-b3.test.js)

const RUBY_LIQUID = 'begin; require "liquid"; require "json"; rescue LoadError; exit 3; end';
const haveLiquid = (() => { const r = cp.spawnSync('/usr/bin/ruby', ['-e', RUBY_LIQUID], { encoding: 'utf8' }); return !r.error && r.status === 0; })();
const liquid = (tpl, data) => {
  const script = 'require "liquid"; require "json"; d = JSON.parse(STDIN.read); puts Liquid::Template.parse(d["tpl"]).render(d["data"])';
  const r = cp.spawnSync('/usr/bin/ruby', ['-e', script], { input: JSON.stringify({ tpl, data }), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
};
// a Jekyll include reads include.x; a bare Liquid template has no such object, so the source is rendered with inc.x
const asBare = (src) => strip(src).replace(/include\./g, 'inc.');

const PAGES = { 'index.md': 'home', 'reports/index.md': 'list', 'hunting-detections/index.md': 'list', 'ioc-feeds/index.md': 'list', 'stix/index.md': 'list',
  'wire/index.md': 'wire', 'actors/index.md': 'list', 'techniques/index.md': 'list', 'families/index.md': 'list', 'impact/index.md': 'list' };

test('the ten pages opt in with hl_idx and the layout turns it into the scope class; no other page is scoped', () => {
  for (const [p, kind] of Object.entries(PAGES)) assert.match(read(p), new RegExp('^hl_idx: ' + kind + '$', 'm'), p);
  // b3: the scope class is set from hl_idx (the index pages and the single pages) or from the layout of the dashboards and the IOC feed pages
  assert.match(read('_layouts/page.html'), /class="hl-page\{% if _hl_idx %\} hl-idx hl-idx--\{\{ _hl_idx \}\}\{% endif %\}"/);
  assert.match(read('_layouts/page.html'), /_hl_idx = page\.hl_idx/);
  const others = ['sponsor.md', 'support.md', 'consulting.md', 'subscribe.md', 'pgp.md', 'about-me/index.md', 'changes/index.md', 'search/index.md', 'behind-the-reports/index.md'];
  for (const p of others) assert.match(read(p), /^hl_idx: single$/m, p + ' is a single page (b3): scope hl-idx--single');
});

test('every index page prints its plate through the one include, with the old class names kept', () => {
  for (const p of Object.keys(PAGES)) {
    if (p === 'index.md') continue;
    assert.match(read(p), /\{% include index-header\.html accent="#[0-9a-f]{6}" label="[^"]+" title="[^"]+" desc=(_desc|"[^"]+") %\}/, p);
    assert.equal(/<div class="hl-page-header"/.test(read(p)), false, p + ': no hand-written plate left');
  }
  const inc = read('_includes/index-header.html');
  for (const k of ['hl-page-header', 'hl-page-header__label', 'hl-page-header__title', 'hl-page-header__desc', 'hl-d-plate', '<h1']) assert.ok(inc.includes(k), k);
});

test('the shared filter keeps every hook listing-filter.js reads, adds the counts and the toggle, and stays a data-driven include', () => {
  const inc = strip(read('_includes/listing-filter.html'));
  for (const hook of ['data-listing-filter', 'class="hl-filter__search"', 'class="hl-filter__chips"', 'class="hl-chip-btn is-on" data-tag=""', 'data-filter-count', 'data-filter-empty', 'data-filter-reset', 'data-pagefind-ignore'])
    assert.ok(inc.includes(hook), hook);
  assert.match(inc, /data-tag="\{\{ u \| downcase \}\}">\{\{ u \}\} <b class="hl-chip-btn__n">\{\{ cnt \}\}<\/b>/, 'a chip carries its entry count');
  assert.match(inc, /index-console\.js/);
  const js = read('assets/js/index-console.js');
  assert.equal(/fetch\(|XMLHttpRequest|innerHTML|eval\(/.test(js), false, 'the toggle script only toggles a class and an aria attribute');
  assert.match(js, /aria-expanded/);
});

test('no page loses a filter, a chip or a script: the three hand-written filters keep their data-tag values and the heatmap its ids', () => {
  assert.match(read('actors/index.md'), /data-tag="espionage"/);
  assert.match(read('impact/index.md'), /data-tag="cert-action"/);
  assert.match(read('families/index.md'), /data-tag="\{\{ k \}\}"/);
  assert.match(read('techniques/index.md'), /id="hl-heatmap-q"/);
  assert.match(read('techniques/index.md'), /heatmap-filter\.js/);
  for (const p of ['actors/index.md', 'impact/index.md', 'families/index.md']) assert.match(read(p), /listing-filter\.js[^\n]*\n<script defer src="\{\{ '\/assets\/js\/index-console\.js'/, p);
});

test('gold means sponsorship only: the b2 stylesheet block uses no gold, and the report series set is steel', () => {
  assert.ok(b2.length > 5000, 'the block exists');
  assert.equal(/accent-gold|#b8902f|#d4a73a|245, 158, 11|gold-bright/i.test(b2), false);
  assert.match(b2, /\.hl-idx \.hl-series-cluster \{[^}]*--hl-accent-steel/);
  assert.match(b2, /\.hl-idx \.hl-card__part \{[^}]*var\(--hl-accent-steel\)/);
});

test('the b2 block is scoped: every selector begins with .hl-idx (or is the Wire\'s main.content frame rule), none restyles a bare element or another page type', () => {
  const body = b2.replace(/\/\*[\s\S]*?\*\//g, '');
  const sels = []; let depth = 0; let cur = '';
  for (const ch of body) {
    if (ch === '{') { const t = cur.trim(); if (!t.startsWith('@')) sels.push(t); cur = ''; depth++; }
    else if (ch === '}') { depth--; cur = ''; }
    else if (ch === ';' && depth > 0) { cur = ''; }
    else cur += ch;
  }
  assert.equal(depth, 0, 'braces balance');
  assert.ok(sels.length > 200, 'parsed ' + sels.length + ' selectors');
  const bad = [];
  for (const s of sels) for (const one of s.split(',')) { const t = one.trim(); if (t && !/^\.hl-idx\b/.test(t) && t !== 'main.content:has(.hl-idx--wire)') bad.push(t); }
  assert.deepEqual(bad, []);
});

test('the Wire skin keeps the live colour variables: publisher and topic hues, tinted titles, the hash tabs, and the popover stays inside its row', () => {
  assert.match(b2, /\.hl-idx--wire \.hl-wire__src \{[^}]*color: var\(--wire-src\)/, 'a source name takes its publisher\'s hue');
  assert.match(b2, /\.hl-idx--wire \.hl-wire__item,[^{]*\{[^}]*linear-gradient\(90deg, color-mix\(in srgb, var\(--wire-src\) 6%/, 'a row is washed with its publisher\'s hue');
  assert.match(b2, /\.hl-idx--wire \.hl-wire__title \{[^}]*color-mix\(in srgb, var\(--wire-src\) 30%, #f4f4f4\)/, 'the title is tinted by its publisher');
  assert.match(b2, /--h: var\(--wire-topic, var\(--hl-accent-blue\)\)/, 'a chip takes its topic hue');
  assert.match(b2, /\.hl-idx--wire \.hl-wire__label \{/);
  for (const sel of ['.hl-idx--wire .hl-wtabs:has(#vulns:target) .hl-wtabs__tab--v', '.hl-idx--wire .hl-wtabs:has(#cves :target) .hl-wtabs__tab--c', '.hl-idx--wire .hl-wtabs:has(#vulns :target) .hl-wtabs__tab--h'])
    assert.ok(b2.includes(sel), sel + ' (the selectors of the live hash tabs)');
  assert.match(b2, /\.hl-idx--wire \.hl-vuln__popbody \{[^}]*max-width: min\(26em, calc\(100% - 24px\)\)/, 'a popover is never wider than its row');
  assert.match(b2, /@media \(max-width: 780px\) \{\s*\.hl-idx--wire \.hl-vuln__popbody \{ left: 12px; right: auto; \}/);
  assert.match(b2, /\.hl-idx--wire aside\.hl-legend \{ display: none !important; \}/);
  const wire = read('wire/index.md');
  for (const k of ['href="#headlines"', 'href="#vulns"', 'href="#cves"', 'data-filter-state="query"', 'hl-wire__row', 'data-filter-grid']) assert.ok(wire.includes(k), k);
  assert.equal((wire.match(/include d-icon\.html/g) || []).length, 3, 'one icon per tab');
});

test('the icon include prints a decorative svg only: aria-hidden, no title, no text, nothing for an unknown name', () => {
  const inc = read('_includes/d-icon.html');
  assert.match(inc, /aria-hidden="true" focusable="false"/);
  assert.equal(/<title|<text/.test(inc), false);
  assert.match(inc, /\{%- if _p != "" -%\}/);
  const names = [...inc.matchAll(/\{%- when "(\w+)" -%\}/g)].map((m) => m[1]);
  for (const n of ['report', 'shield', 'target', 'share', 'user', 'family', 'grid', 'heart', 'pulse', 'history', 'flag', 'layers', 'book', 'briefcase', 'search', 'chev', 'alert']) assert.ok(names.includes(n), n);
});

test('KPI include: the tiles are computed from the entries; a severity with no entry leaves its tile out; percentages round from the counts', { skip: haveLiquid ? false : 'NOT CHECKED: ruby + liquid gem not available' }, () => {
  const tpl = asBare(read('_includes/index-kpis.html'));
  const entries = [].concat(Array(2).fill({ severity: 'critical' }), Array(5).fill({ severity: 'high' }), Array(1).fill({ severity: 'med' }));
  const out = liquid(tpl, { inc: { entries, noun: 'reports', label: 'Reports', accent: '#a371f7', topics: 7 } });
  assert.match(out, /--fc: 5;/, 'total, critical, high, medium and topics = 5 tiles (no low tile)');
  assert.match(out, /hl-d-kpi__n">8<\/span><span class="hl-d-kpi__cap">Reports<\/span><span class="hl-d-kpi__note">in the catalog now/);
  assert.match(out, /hl-d-kpi__n">2<\/span><span class="hl-d-kpi__cap">Critical reports<\/span><span class="hl-d-kpi__note">25% of 8/);
  assert.match(out, /hl-d-kpi__n">5<\/span><span class="hl-d-kpi__cap">High reports<\/span><span class="hl-d-kpi__note">63% of 8/);
  assert.match(out, /hl-d-kpi__n">1<\/span><span class="hl-d-kpi__cap">Medium reports<\/span><span class="hl-d-kpi__note">13% of 8/);
  assert.equal(/Low reports/.test(out), false, 'no low entry, no low tile');
  assert.match(out, /hl-d-kpi__n">7<\/span><span class="hl-d-kpi__cap">Topic tags/);
  const none = liquid(tpl, { inc: { entries: [], noun: 'reports', label: 'Reports', topics: 3 } });
  assert.equal(none.trim(), '', 'no entries, no tiles: a zero denominator never renders as a clean row of zeros');
});

test('topic vocabulary include: a tag earns a chip from 3 entries, the chip count is the entry count, the total is exported', { skip: haveLiquid ? false : 'NOT CHECKED: ruby + liquid gem not available' }, () => {
  const tpl = asBare(read('_includes/listing-tags.html')) + '{{ hl_chip_n }}|{{ hl_uniq | join: "," }}';
  const entries = [{ tags: ['A', 'B'] }, { tags: ['A', 'B'] }, { tags: ['A', 'C'] }, { tags: ['B'] }, { tags: ['D'], alt: ['A'] }];
  const out = liquid(tpl, { inc: { entries } }).trim();
  assert.equal(out, '2|A,B,C,D', 'A (3 entries) and B (3 entries) earn chips; C and D (1 each) do not');
  const ov = liquid(tpl, { inc: { entries, tag_field: 'alt' } }).trim();
  assert.equal(ov, '2|A,B,C', 'tag_field overrides an entry\'s tags where it has that field: the last entry\'s D is replaced by A, so D is gone');
});
