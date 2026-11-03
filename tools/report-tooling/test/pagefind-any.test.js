'use strict';
/* T-0553: /search/ Section filter combines ticked values with OR. The wrapper assets/js/pagefind-any/pagefind.js cannot load in node
   (it imports the built /pagefind/pagefind.js), so the logic lives in filters.mjs and is tested here; the live counts are the browser check. */
const { test } = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { pathToFileURL } = require('node:url');
const DIR = path.join(__dirname, '../../../assets/js/pagefind-any');
const load = () => import(pathToFileURL(path.join(DIR, 'filters.mjs')).href);

test('two or more values of a filter become { any }', async () => {
  const { anyFilters } = await load();
  assert.deepEqual(anyFilters({ section: ['Reports', 'Detections'] }), { section: { any: ['Reports', 'Detections'] } });
  assert.deepEqual(anyFilters({ section: ['Reports', 'Wire: CVEs', 'STIX'] }), { section: { any: ['Reports', 'Wire: CVEs', 'STIX'] } });
});

test('one value, none and non-array shapes pass through', async () => {
  const { anyFilters } = await load();
  assert.deepEqual(anyFilters({ section: ['Reports'] }), { section: ['Reports'] });
  assert.deepEqual(anyFilters({}), {});
  assert.deepEqual(anyFilters({ section: { any: ['A', 'B'] } }), { section: { any: ['A', 'B'] } });
  assert.equal(anyFilters(undefined), undefined);
  assert.equal(anyFilters(null), null);
});

test('the input is not mutated and the array is copied', async () => {
  const { anyFilters } = await load();
  const inp = { section: ['A', 'B'] }, out = anyFilters(inp);
  assert.deepEqual(inp, { section: ['A', 'B'] });
  out.section.any.push('C');
  assert.deepEqual(inp.section, ['A', 'B']);
});

test('anyOptions rewrites only filters and keeps sort and the rest', async () => {
  const { anyOptions } = await load();
  assert.deepEqual(anyOptions({ filters: { section: ['A', 'B'] }, sort: { date: 'desc' } }), { filters: { section: { any: ['A', 'B'] } }, sort: { date: 'desc' } });
  assert.equal(anyOptions(undefined), undefined);
  const noF = { sort: 1 };
  assert.equal(anyOptions(noF), noF);
});

test('the wrapper re-exports every Pagefind export and routes search, preload and debouncedSearch through anyOptions', () => {
  const src = fs.readFileSync(path.join(DIR, 'pagefind.js'), 'utf8');
  for (const n of ['init', 'options', 'mergeIndex', 'filters', 'destroy', 'search', 'preload', 'debouncedSearch']) assert.match(src, new RegExp('export const ' + n + ' '), n);
  for (const n of ['search', 'preload', 'debouncedSearch']) assert.match(src, new RegExp('export const ' + n + ' = .*anyOptions\\('), n);
});

test('/search/ points PagefindUI at the wrapper folder', () => {
  const md = fs.readFileSync(path.join(__dirname, '../../../search/index.md'), 'utf8');
  assert.match(md, /bundlePath: base \+ '\/assets\/js\/pagefind-any\/'/);
});
