'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { extractTables } = require('../lib/extract-tables.js');

test('converts a pipe table to HTML with thead and tbody', () => {
  const md = [
    '| Tactic / Technique | Name | Evidence |',
    '|---|---|---|',
    '| Execution / T1059.004 | Unix Shell | interactive bash |'
  ].join('\n');
  const out = extractTables(md);
  assert.strictEqual(out.length, 1);
  assert.match(out[0], /^<table>/);
  assert.match(out[0], /<th>Tactic \/ Technique<\/th>/);
  assert.match(out[0], /<td>Execution \/ T1059\.004<\/td>/);
});

test('passes a raw HTML table through untouched', () => {
  const md = 'text\n\n<table><tr><td>Execution / T1059.004</td></tr></table>\n\nmore';
  const out = extractTables(md);
  assert.strictEqual(out.length, 1);
  assert.match(out[0], /<table><tr><td>Execution/);
});

test('finds several tables in one document', () => {
  const md = [
    '| A | B |', '|---|---|', '| T1059 | x |', '',
    'prose here', '',
    '| C | D |', '|---|---|', '| T1055 | y |'
  ].join('\n');
  assert.strictEqual(extractTables(md).length, 2);
});

test('ignores front matter', () => {
  const md = ['---', 'title: "| not | a | table |"', '---', '', 'body'].join('\n');
  assert.strictEqual(extractTables(md).length, 0);
});

test('a pipe block with no separator row is not a table', () => {
  const md = '| this | is | just | prose |\n| and | so | is | this |';
  assert.strictEqual(extractTables(md).length, 0);
});

test('respects escaped pipes inside cells', () => {
  const md = ['| Tactic | Evidence |', '|---|---|',
              '| Execution / T1059.004 | `a \\| b` piped |'].join('\n');
  const out = extractTables(md);
  assert.strictEqual(out[0].match(/<td>/g).length, 2);
  assert.match(out[0], /a \| b/);
});

test('handles a leading and trailing pipe being absent', () => {
  const md = ['Tactic | Name', '---|---', 'Execution / T1059.004 | Unix Shell'].join('\n');
  const out = extractTables(md);
  assert.strictEqual(out.length, 1);
  assert.match(out[0], /<td>Execution \/ T1059\.004<\/td>/);
});
