'use strict';
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var CFT = require('../lib/check-fact-tables.js');

function doc(rows, header) {
  return '---\ntitle: x\n---\n\n| ' + (header || 'Field | Value') + ' |\n|---|---|\n' +
    rows.map(function (r) { return '| ' + r[0] + ' | ' + r[1] + ' |'; }).join('\n') + '\n';
}
var SHORTV = 'C:\\ProgramData\\WVault.exe';
var LONGV = 'x'.repeat(200);

test('a literal-heavy table passes and is counted as literal', function () {
  var r = CFT.checkMarkdown(doc([['SHA-256', 'a'.repeat(64)], ['Path', SHORTV], ['Size', '442 bytes']]), 'x.md');
  assert.strictEqual(r.status, 'PASS');
  assert.deepStrictEqual([r.tables, r.rows, r.literal, r.prose], [1, 3, 1, 0]);
  assert.strictEqual(r.warnings.length, 0);
});

test('a prose-heavy table warns rather than fails, and is skipped by the renderer', function () {
  var r = CFT.checkMarkdown(doc([['Type', LONGV], ['Targeting', LONGV], ['Size', '442 bytes']]), 'x.md');
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.prose, 1);
  assert.strictEqual(r.problems.length, 0);
  assert.match(r.warnings.join(' '), /prose-heavy/);
});

test('a header with no rows FAILS, because it renders as a bare header', function () {
  var r = CFT.checkMarkdown('---\nt: x\n---\n\n| Field | Value |\n|---|---|\n\ntext\n', 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /no rows/);
});

test('an empty key cell FAILS, because the permalink id collapses to "fact-"', function () {
  var r = CFT.checkMarkdown(doc([['', 'something'], ['Path', SHORTV]]), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /empty key cell/);
});

test('the kin headers are recognised and a three-column table is not', function () {
  assert.strictEqual(CFT.checkMarkdown(doc([['a', 'b']], 'Property | Value')).tables, 1);
  assert.strictEqual(CFT.checkMarkdown(doc([['a', 'b']], 'Attribute | Assessment')).tables, 1);
  var three = '---\nt: x\n---\n\n| Tactic | Name | Evidence |\n|---|---|---|\n| a | b | c |\n';
  assert.strictEqual(CFT.checkMarkdown(three, 'x.md').tables, 0);
});

test('unreadable input is NOT CHECKED, never PASS', function () {
  var r = CFT.checkMarkdown(null, 'gone.md');
  assert.strictEqual(r.status, 'NOT CHECKED');
  assert.match(r.reason, /could not be read/);
});

/* The browser module and this gate carry the same two rubric constants in two
   languages. A silent drift would mean the gate describes a different corpus
   than the reader is served, so it is asserted rather than trusted. */
test('the rubric constants match the shipped browser module', function () {
  var js = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'hl-facts.js'), 'utf8');
  var short = js.match(/var SHORT\s*=\s*(\d+)/);
  var share = js.match(/var LITERAL_SHARE\s*=\s*([\d.]+)/);
  assert.ok(short && share, 'hl-facts.js no longer declares SHORT and LITERAL_SHARE');
  assert.strictEqual(Number(short[1]), CFT.SHORT);
  assert.strictEqual(Number(share[1]), CFT.LITERAL_SHARE);
});
