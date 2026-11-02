'use strict';
/* T-0500.1.7.4 b3: the detail pages and single pages in design D. Static checks on the layouts, includes and stylesheet, plus the KPI include rendered with
   Ruby's Liquid (NOT CHECKED, skipped with the reason, when ruby or the gem is missing). Gold is design-d-gold.test.js; the built output is checked by the b3 browser
   and completeness runs recorded in tasks/runs/T-0500.1.7.4/build/b3-report.md. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const css = read('assets/css/custom.scss');
const strip = (s) => s.replace(/\{%-? comment -?%\}[\s\S]*?\{%-? endcomment -?%\}/g, '');

const haveLiquid = (() => { const r = cp.spawnSync('/usr/bin/ruby', ['-e', 'begin; require "liquid"; rescue LoadError; exit 3; end'], { encoding: 'utf8' }); return !r.error && r.status === 0; })();
const liquid = (tpl, data) => {
  const script = 'require "liquid"; require "json"; d = JSON.parse(STDIN.read); puts Liquid::Template.parse(d["tpl"]).render(d["data"])';
  const r = cp.spawnSync('/usr/bin/ruby', ['-e', script], { input: JSON.stringify({ tpl, data }), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
};

// the section ids existing #fragment links rely on (decision 4 and the lead's brief)
const SECTIONS = {
  '_layouts/actor.html': ['summary', 'targeting', 'reports', 'identifiers', 'infrastructure', 'attack', 'related'],
  '_layouts/family.html': ['reports', 'detections', 'feeds', 'actors'],
  '_layouts/technique.html': ['reports', 'detections', 'actors'],
};

test('the actor, family and technique layouts keep every section id and print no tabs', () => {
  for (const [file, ids] of Object.entries(SECTIONS)) {
    const src = read(file);
    for (const id of ids) assert.ok(new RegExp('include d-dhead\\.html id="' + id + '"').test(src), file + ' section ' + id);
    assert.equal(/role="tab"|data-tabs|hl-report-tabs/.test(src), false, file + ' has no tabs (decision 4)');
    assert.ok(/include d-sbar\.html/.test(src), file + ' prints the sticky section bar');
    assert.ok(/section-bar\.js/.test(src), file + ' loads the bar script');
  }
});

test('every section of a dashboard has an entry in its bar, one icon and accent each', () => {
  for (const [file, ids] of Object.entries(SECTIONS)) {
    const src = read(file);
    for (const id of ids) assert.ok(new RegExp('include d-sbar-item\\.html id="' + id + '" text="[^"]+" icon="[a-z]+" color="#[0-9a-f]{6}"').test(src), file + ' bar entry ' + id);
  }
});

test('the dashboards print no network indicator of their own and compute their counts from the page lists', () => {
  for (const file of Object.keys(SECTIONS)) {
    const src = strip(read(file));
    assert.equal(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(src), false, file + ': no literal address');
    assert.ok(/\.size/.test(src), file + ' counts lists with .size');
  }
});

test('page.html scopes the dashboards and the IOC feed pages by layout and the single pages by front matter', () => {
  const page = read('_layouts/page.html');
  assert.match(page, /page\.layout == 'actor' or page\.layout == 'family' or page\.layout == 'technique'/);
  assert.match(page, /_hl_idx = 'dash'/);
  assert.match(page, /page\.layout == 'ioc-table'[\s\S]*_hl_idx = 'feed'/);
  for (const p of ['sponsor.md', 'support.md', 'consulting.md', 'subscribe.md', 'about-me/index.md', 'pgp.md', 'behind-the-reports/index.md', 'behind-the-reports/ai-workflow.md', 'behind-the-reports/collection-platform.md', 'behind-the-reports/gates-and-distribution.md', 'changes/index.md', 'search/index.md', 'feeds/misp/index.md']) {
    const src = read(p);
    assert.match(src, /^hl_idx: single$/m, p);
    assert.match(src, /<header class="hl-page-header hl-d-plate"/, p + ' plate');
    assert.match(src, /<h1 class="hl-page-header__title">/, p + ' h1');
  }
  assert.match(read('404.html'), /hl-idx hl-idx--single/);
});

test('the post layout: a report keeps its header byte for byte; only a detection page takes the D plate, the tiles and the bar', () => {
  const post = read('_layouts/post.html');
  assert.ok(post.includes('{%- else %}\n<div class="hl-post-header{% if page.path contains \'hunting-detections\' %} hl-post-header--detect{% endif %}">'));
  const i = post.indexOf('{%- if _is_det0 -%}');
  const j = post.indexOf('{%- else %}\n<div class="hl-post-header');
  assert.ok(i > 0 && j > i, 'the detection branch precedes the report header');
  const det = post.slice(i, j);
  for (const k of ['hl-d-plate', 'hl-d-res', 'hl-d-kpis', 'include d-sbar.html', 'detection_manifests', 'detection_attack']) assert.ok(det.includes(k), k);
  assert.equal(/role="tab"/.test(det), false, 'the detection page stays flat');
  assert.match(post, /section-bar\.js/);
  const ioc = read('_layouts/ioc-table.html');
  for (const k of ['index-header.html', 'hl-d-kpis', 'data-slug="{{ page.ioc_slug }}"', 'data-act="copy"', 'data-act="txt"', 'data-act="csv"', 'data-act="defang"', 'hl-ioctable__filters', 'ioc-table.js']) assert.ok(ioc.includes(k), 'IOC feed layout keeps ' + k);
});

test('the b3 blocks of the stylesheet are scoped: each selector is under a b3 scope or is one of the b3 components', () => {
  const start = css.indexOf('DESIGN D: ACTOR, FAMILY AND TECHNIQUE PAGES AS DASHBOARDS (T-0500.1.7.4 b3)');
  assert.ok(start > 0);
  const body = css.slice(css.lastIndexOf('/*', start)).replace(/\/\*[\s\S]*?\*\//g, '');
  const sels = []; let depth = 0; let cur = '';
  for (const ch of body) {
    if (ch === '{') { const t = cur.trim(); if (!t.startsWith('@')) sels.push(t); cur = ''; depth++; }
    else if (ch === '}') { depth--; cur = ''; }
    else if (ch === ';' && depth > 0) { cur = ''; }
    else cur += ch;
  }
  assert.equal(depth, 0, 'braces balance');
  assert.ok(sels.length > 250, 'parsed ' + sels.length + ' selectors');
  const OK = /^(\.hl-idx--(dash|single|det|feed)\b|\.hl-idx \.(hl-grid--dash|hl-dash-card|hl-d-bh)|\.hl-idx \.hl-d-bh|html:has\(\.hl-sbar\)|\.(hl-sbar|hl-dh|hl-g2e?|hl-g2e__wide|hl-d-bh|hl-chipbar|hl-kc|hl-console|hl-crow|hl-badge|hl-meta|hl-mbar|hl-heat|hl-tgrid|hl-tac|hl-stack|hl-cflegend|hl-dash-card__d|hl-d-res|hl-d-kpi__mv|hl-dh__s|hl-dh__i)|a\.hl-d-kpi|a\.hl-kc|\.hl-d-kpi)/;
  const bad = [];
  for (const s of sels) for (const one of s.split(',')) { const t = one.trim(); if (t && !OK.test(t)) bad.push(t); }
  assert.deepEqual(bad, []);
});

test('the section bar script: marks the section in view, skips a section that is not drawn, needs no library', () => {
  const js = read('assets/js/section-bar.js');
  assert.match(js, /aria-current/);
  assert.match(js, /getClientRects\(\)\.length/);
  assert.equal(/\bjQuery\b|require\(|import /.test(js), false);
  assert.match(css, /\.hl-sbar a\[hidden\]/);
});

test('the dashboards lean B: console rows, meters and an icon bar, one accent per section', () => {
  for (const k of ['.hl-console', '.hl-crow', '.hl-mbar', '.hl-sbar', '.hl-dsec', '.hl-heat', '.hl-tgrid']) assert.ok(css.includes(k + ' ') || css.includes(k + '{') || css.includes(k + ','), k);
  for (const file of Object.keys(SECTIONS)) assert.ok(/<section class="hl-dsec" style="--da: #[0-9a-f]{6};">/.test(read(file)), file + ' one accent per section');
});

test('KPI tile include: a number, a caption, an optional note and link, a four-step ladder', { skip: !haveLiquid && 'NOT CHECKED: ruby or the liquid gem is missing' }, () => {
  const src = strip(read('_includes/d-kpi.html')).replace(/include\./g, 'inc.');
  const a = liquid(src, { inc: { num: 55, cap: 'Techniques', color: '#fb923c', note: 'across 12 tactics', href: '#attack' } });
  assert.match(a, /<a class="hl-d-kpi hl-d-kpi--lk"[^>]*href="#attack"/);
  assert.match(a, /<span class="hl-d-kpi__n">55<\/span>/);
  assert.match(a, /across 12 tactics/);
  const b = liquid(src, { inc: { num: 'HIGH', cap: 'Distinct actor', color: '#4ade80', word: true, lad: 3 } });
  assert.equal((b.match(/<i class="on">/g) || []).length, 3, 'three of four steps filled');
  assert.equal((b.match(/<i>/g) || []).length, 1);
  const c = liquid(src, { inc: { num: 'INSUFFICIENT', cap: 'Named actor', color: '#9ca3af', word: true, lad: 0 } });
  assert.equal((c.match(/<i class="on">/g) || []).length, 0, 'a zero ladder fills nothing');
  assert.match(c, /hl-d-kpi__lad/);
  assert.equal(/<a /.test(c), false, 'no href, no link');
});
