'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const { extractTables } = require('../lib/extract-tables.js');

// What a cell's cells read as once parsed, which is all the parser ever sees.
function cellText(md) {
  const doc = new JSDOM('<body>' + extractTables(md)[0] + '</body>').window.document;
  return [].map.call(doc.querySelectorAll('tbody td'), (c) => c.textContent);
}

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

test('bold in a cell becomes a strong tag, and the text inside survives', () => {
  const md = ['| Tactic | Evidence |', '|---|---|', '| **Execution** | ran it |'].join('\n');
  assert.match(extractTables(md)[0], /<td><strong>Execution<\/strong><\/td>/);
  assert.deepStrictEqual(cellText(md), ['Execution', 'ran it']);
});

test('italics in a cell become an em tag, in both marker styles', () => {
  const md = ['| Tactic | Evidence |', '|---|---|', '| *Execution* | _observed_ |'].join('\n');
  assert.match(extractTables(md)[0], /<td><em>Execution<\/em><\/td>/);
  assert.deepStrictEqual(cellText(md), ['Execution', 'observed']);
});

test('a backticked span in a cell becomes a code tag', () => {
  const md = ['| Tactic | Evidence |', '|---|---|', '| Execution | runs `IMG001.exe` |'].join('\n');
  assert.match(extractTables(md)[0], /<code>IMG001\.exe<\/code>/);
  assert.deepStrictEqual(cellText(md), ['Execution', 'runs IMG001.exe']);
});

// reports/nsminer-cryptojacker/index.md line 146. Emitted literally, the
// "**Execution**" cell never matches the tactic "Execution", the table stops being
// recognised as a mapping table, and all 7 of its techniques are silently lost.
test('the real nsminer row shape yields a cell reading exactly "Execution"', () => {
  const md = [
    '| Tactic | Technique ID | Technique Name | Evidence |',
    '|---|---|---|---|',
    '| **Execution** | T1204.002 | User Execution: Malicious File | User runs `IMG001.exe`. |'
  ].join('\n');
  const cells = cellText(md);
  assert.strictEqual(cells[0], 'Execution');
  assert.strictEqual(cells[1], 'T1204.002');
});

// Emphasis conversion must not DELETE characters. Underscore emphasis is never
// intraword, so a symbol name keeps every underscore, and a glob or a bare
// asterisk is not an emphasis marker.
test('underscores in identifiers and stray asterisks are left alone', () => {
  const md = [
    '| Tactic | Evidence |', '|---|---|',
    '| Execution | run/sc_loader/veh_loader/dbg_loader and *.exe, *.dll |'
  ].join('\n');
  assert.deepStrictEqual(cellText(md),
    ['Execution', 'run/sc_loader/veh_loader/dbg_loader and *.exe, *.dll']);
});
