'use strict';

/* T-0603 lane B (S7, B11): _data/nav.yml is the only source of the site menu (_includes/default/navbar.liquid reads it for the drawer and the top bar).
   A page's `position:` front matter no longer adds a link, so this test keeps the two from drifting: every nav.yml url is a source page's permalink, and the set of
   pages that still carry `position:` (the home page excepted) is exactly the nav.yml set. */
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const ROOT = path.join(__dirname, '..', '..', '..');
const SKIP = new Set(['.git', 'node_modules', '_site', 'tools', 'docs', 'report-templates', 'threat-intel-vault', '.github']);

function frontMatter(file) {
  const text = fs.readFileSync(file, 'utf8');
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  try { return yaml.load(m[1]) || null; } catch (e) { return null; }
}
function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name) || e.name.startsWith('_') || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(md|html)$/.test(e.name)) out.push(p);
  }
  return out;
}
const pages = walk(ROOT, []).map((f) => ({ f, fm: frontMatter(f) })).filter((x) => x.fm && x.fm.permalink);
const nav = yaml.load(fs.readFileSync(path.join(ROOT, '_data', 'nav.yml'), 'utf8')).pages;

test('nav.yml has entries, each with a url, a label and a colour; the top-bar ranks are unique', () => {
  assert.ok(Array.isArray(nav) && nav.length > 0, 'nav.yml pages: a list');
  for (const n of nav) for (const k of ['url', 'label', 'color']) assert.ok(n[k], `entry ${JSON.stringify(n)} lacks ${k}`);
  const ranks = nav.filter((n) => n.bar !== undefined).map((n) => n.bar);
  assert.strictEqual(new Set(ranks).size, ranks.length, 'two entries share a top-bar rank');
  for (const n of nav) if (n.bar !== undefined) assert.ok(n.bar_label, `bar entry ${n.url} lacks bar_label`);
});
test('every nav.yml url resolves to a source page permalink', () => {
  assert.ok(pages.length > 0, 'no source page was read (denominator 0)');
  const permalinks = new Set(pages.map((p) => p.fm.permalink));
  for (const n of nav) assert.ok(permalinks.has(n.url), `${n.url} is no page's permalink`);
});
test('the pages carrying `position:` (home page excepted) are exactly the nav.yml set', () => {
  const withPos = pages.filter((p) => p.fm.position !== undefined && p.fm.permalink !== '/' && !p.fm.hide).map((p) => p.fm.permalink).sort();
  const inNav = nav.map((n) => n.url).sort();
  assert.deepStrictEqual(withPos, inNav, 'a page gained or lost `position:` without nav.yml, or the reverse');
});
