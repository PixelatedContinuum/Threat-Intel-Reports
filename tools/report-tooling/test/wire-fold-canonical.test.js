'use strict';
// T-0565.1.3 (T-0576 settle row 16): wire/index.md's nKEV and CVEs loops skip drawing a
// non-canonical row (no CVE-shaped id, or no ten-character added day), but the skipped row
// still reached _includes/wire-fold-keys.html, so it got a fold key and counted toward
// fold_size: a batch could open on four real rows and print an empty fifth member.
// The fold key include now applies the same canonical test as the page guard.
// Rendered with Ruby's Liquid (the test/design-d-b3.test.js harness pattern); skipped with
// its reason when ruby or the liquid gem is missing.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

const haveLiquid = (() => {
  const r = cp.spawnSync('/usr/bin/ruby', ['-e', 'begin; require "liquid"; rescue LoadError; exit 3; end'], {encoding: 'utf8'});
  return !r.error && r.status === 0;
})();

// Jekyll's push and normalize_whitespace, the two non-stock filters the includes use.
const RUBY = `
require "liquid"; require "json"
module HL
  def push(input, item); Array(input) + [item]; end
  def normalize_whitespace(input); input.to_s.split(/\\s+/).join(" ").strip; end
end
Liquid::Template.register_filter(HL)
d = JSON.parse(STDIN.read)
puts Liquid::Template.parse(d["tpl"]).render(d["data"])
`;
function liquid(tpl, data) {
  const r = cp.spawnSync('/usr/bin/ruby', ['-e', RUBY], {input: JSON.stringify({tpl, data}), encoding: 'utf8'});
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
}

const KEYS_TPL = read('_includes/wire-fold-keys.html') +
  '\nK:{% for k in fold_keys %}[{{ k }}]{% endfor %}\n' +
  'M:{% for t in fold_thresholds %}[{{ t }}]{% endfor %}';
const FOLD_TPL = read('_includes/wire-fold.html');

function keys(rows, mode) {
  const out = liquid(KEYS_TPL, {include: {rows, mode}, wp_unauth_group_min: 2, product_group_min: 5, wp_batch_group_min: 5});
  const list = (re) => [...((out.match(re) || [])[1] || '').matchAll(/\[(.*?)\]/g)].map((m) => m[1]);
  // thresholds are integers; the probe prints them, so hand the renderer numbers back.
  return {keys: list(/K:(.*)/), mins: list(/M:(.*)/).map(Number), out};
}
function fold(rows, k, labels) {
  return liquid(FOLD_TPL, {include: {rows, keys: k.keys, labels, thresholds: k.mins}});
}
// What the page captures for a row: its markup when canonical, an empty string when the
// vok guard is false (wire/index.md:401-403 nKEV, :712-714 CVEs).
const rendered = (rows) => rows.map((r) => (r.vok ? '<div class="hl-vuln">' + r.cve + '</div>' : ''));
const labels = (rows) => rows.map(() => 'Acme CMS CVEs');

// Six CVEs rows, five of them one product on one day; the sixth has no CVE id.
function cveRows(n, badIndex) {
  const rows = [];
  for (let i = 1; i <= n; i++) {
    rows.push({cve: 'CVE-2026-' + String(1000 + i), published: '2026-11-05', vendor: 'Acme', product: 'CMS', signals: ['nuclei'], vok: true});
  }
  if (badIndex !== undefined) rows.splice(badIndex, 0, {cve: '', published: '2026-11-05', vendor: 'Acme', product: 'CMS', signals: ['nuclei'], vok: false});
  return rows;
}
// nKEV rows folded on their event-day batch; the sixth has no added day.
function nkevRows(n, badIndex) {
  const rows = [];
  for (let i = 1; i <= n; i++) {
    rows.push({cve: 'CVE-2026-' + String(2000 + i), added: '2026-11-01', event: '2026-11-02', vendor: 'Acme', product: 'CMS', batch: 'b-2026-11-02', vok: true});
  }
  if (badIndex !== undefined) rows.splice(badIndex, 0, {cve: 'CVE-2026-2099', added: '', event: '2026-11-02', vendor: 'Acme', product: 'CMS', batch: 'b-2026-11-02', vok: false});
  return rows;
}

test('a non-canonical CVEs row gets no fold key and does not count toward the product fold', {skip: !haveLiquid && 'NOT CHECKED: ruby or the liquid gem is absent, so the fold includes were not rendered'}, () => {
  const rows = cveRows(4, 4);
  const k = keys(rows, 'cves');
  const html = fold(rendered(rows), k, labels(rows));
  assert.equal(k.keys[4], '', 'the non-canonical row carries no fold key');
  assert.ok(k.keys.slice(0, 4).every((key) => key === k.keys[0] && key !== ''), 'the four real rows share one product key');
  assert.equal(html.includes('data-filter-batch'), false, 'four real rows are below the five-row product fold');
  assert.equal((html.match(/class="hl-vuln"/g) || []).length, 4);
});

test('control: five canonical CVEs rows of one product still fold, and the batch counts five', {skip: !haveLiquid && 'NOT CHECKED: ruby or the liquid gem is absent, so the fold includes were not rendered'}, () => {
  const rows = cveRows(5);
  const k = keys(rows, 'cves');
  const html = fold(rendered(rows), k, labels(rows));
  assert.ok(k.keys.every((key) => key === k.keys[0] && key !== ''), 'all five rows share one product key');
  assert.match(html, /data-filter-batch="/);
  assert.match(html, /<span data-container-count>5<\/span> Acme CMS CVEs/);
});

test('a non-canonical nKEV row gets no fold key and does not count toward the batch fold', {skip: !haveLiquid && 'NOT CHECKED: ruby or the liquid gem is absent, so the fold includes were not rendered'}, () => {
  const rows = nkevRows(4, 4);
  const k = keys(rows, 'nkev');
  const html = fold(rendered(rows), k, labels(rows));
  assert.equal(k.keys[4], '', 'the non-canonical row carries no fold key');
  assert.ok(k.keys.slice(0, 4).every((key) => key === k.keys[0] && key !== ''), 'the four real rows share one batch key');
  assert.equal(html.includes('data-filter-batch'), false, 'four real rows are below the five-row batch fold');
  assert.equal((html.match(/class="hl-vuln"/g) || []).length, 4);
});

test('control: five canonical nKEV rows of one batch still fold, and the batch counts five', {skip: !haveLiquid && 'NOT CHECKED: ruby or the liquid gem is absent, so the fold includes were not rendered'}, () => {
  const rows = nkevRows(5);
  const k = keys(rows, 'nkev');
  const html = fold(rendered(rows), k, labels(rows));
  assert.ok(k.keys.every((key) => key === k.keys[0] && key !== ''), 'all five rows share one batch key');
  assert.match(html, /data-filter-batch="/);
  assert.match(html, /<span data-container-count>5<\/span> Acme CMS CVEs/);
});

// The fold key now carries its own copy of the page's canonical test, so a change to one
// without the other must fail here rather than silently re-open the gap.
test('the fold key applies the same canonical test as the page guards', () => {
  const page = read('wire/index.md'), keys = read('_includes/wire-fold-keys.html');
  assert.match(page, /assign cve_head = r\.cve \| slice: 0, 4/, 'page nKEV/CVEs guard reads the CVE id head');
  assert.match(page, /if cve_head == "CVE-" and added_len == 10/, 'page nKEV guard requires a ten-character added day');
  assert.match(keys, /assign fold_head = fold_row\.cve \| slice: 0, 4/, 'fold key reads the CVE id head');
  assert.match(keys, /if fold_head == "CVE-"/, 'fold key requires a CVE-shaped id');
  assert.match(keys, /assign fold_added_len = fold_row\.added \| size/, 'fold key reads the added day length');
  assert.match(keys, /if fold_added_len == 10/, 'fold key requires a ten-character added day on the nKEV tab');
});
