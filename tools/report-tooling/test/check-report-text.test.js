'use strict';
var test = require('node:test');
var assert = require('node:assert');
var C = require('../check-report-text.js');

function words(s) { return s.split(' '); }

test('identical text has nothing missing and nothing added', function () {
  var d = C.diffWords(words('a b c'), words('a b c'));
  assert.deepStrictEqual([d.missing, d.added], [0, 0]);
});

test('a deleted paragraph is counted as missing, word for word', function () {
  var base = words('one two three four five six seven');
  var page = words('one two six seven');
  var ms = require('../check-report-text.js').diffWords(base, page);
  assert.strictEqual(ms.missing, 3);
  assert.strictEqual(ms.added, 0);
});

test('an inserted word is counted as added, not as a loss', function () {
  var d = C.diffWords(words('one two three'), words('one two new three'));
  assert.strictEqual(d.missing, 0);
  assert.strictEqual(d.added, 1);
});

test('a moved section is not missing and not added in the word counts', function () {
  var d = C.multisetDiff(words('a b c d e f'), words('d e f a b c'));
  assert.strictEqual(d.missing, 0);
  assert.strictEqual(d.added, 0);
  // The ordered diff does see the move, which is why the verdict does not use it.
  var seq = C.diffWords(words('a b c d e f'), words('d e f a b c'));
  assert.ok(seq.missing > 0);
});

test('the diff reports which words it removed', function () {
  var d = C.diffWords(words('alpha beta gamma'), words('alpha gamma'));
  assert.match(JSON.stringify(d.ops), /beta/);
});

test('every baseline id must be present exactly once', function () {
  assert.deepStrictEqual(C.checkIds(['a', 'b'], ['a', 'b', 'c']), []);
  assert.match(C.checkIds(['a'], ['b']).join(' '), /"a" is missing/);
  assert.match(C.checkIds(['a'], ['a', 'a']).join(' '), /appears 2 times/);
});

test('a duplicate id on the page is a problem even when every baseline id exists', function () {
  var p = C.checkIds(['a', 'b'], ['a', 'b', 'b']);
  assert.strictEqual(p.length, 1);
  assert.match(p[0], /"b" appears 2 times/);
});

test('withOnePage keeps a URL and a path addressable, and adds the fragment once', function () {
  assert.strictEqual(C.withOnePage('https://example.org/r/x/'), 'https://example.org/r/x/#one-page');
  assert.strictEqual(C.withOnePage('https://example.org/r/x/#tab-chain'), 'https://example.org/r/x/#one-page');
  assert.match(C.withOnePage('/tmp/a b/report.html'), /^file:\/\/.*a%20b\/report\.html#one-page$/);
});

test('compare PASSes only when words, counts and ids all agree', function () {
  var base = {
    text: 'a b c', chars: 5, counts: { headings: 1, tables: 0, rows: 0, figures: 0, images: 0,
      teardowns: 0, details: 0, 'code blocks': 0, links: 0, lists: 0 }, ids: ['x']
  };
  var page = JSON.parse(JSON.stringify(base));
  var ok = C.compare(base, page);
  assert.strictEqual(ok.status, 'PASS');
  assert.strictEqual(ok.missing, 0);

  var short = JSON.parse(JSON.stringify(page));
  short.text = 'a c';
  short.chars = 3;
  var bad = C.compare(base, short);
  assert.strictEqual(bad.status, 'FAIL');
  assert.strictEqual(bad.missing, 1);

  var fewer = JSON.parse(JSON.stringify(page));
  fewer.counts.tables = 1;
  assert.match(C.compare(base, fewer).countProblems.join(' '), /tables 0 baseline vs 1 page/);

  var noId = JSON.parse(JSON.stringify(page));
  noId.ids = [];
  assert.match(C.compare(base, noId).ids.problems.join(' '), /"x" is missing/);
});

test('a reordered but complete page PASSes and reports the order difference', function () {
  var base = {
    text: 'a b c d e f', chars: 11, counts: { headings: 1, tables: 0, rows: 0, figures: 0,
      images: 0, teardowns: 0, details: 0, 'code blocks': 0, links: 0, lists: 0 }, ids: []
  };
  var page = JSON.parse(JSON.stringify(base));
  page.text = 'd e f a b c';
  var r = C.compare(base, page);
  assert.strictEqual(r.status, 'PASS');
  assert.strictEqual(r.missing, 0);
  assert.ok(r.outOfOrder > 0);
});

test('the extraction script strips chrome, scripts, styles and the title', function () {
  var js = C.EXTRACT_JS;
  assert.match(js, /data-rv-chrome/);
  assert.match(js, /script,style,title/);
  assert.match(js, /hl-post-content/);
  // The check must not depend on any panel id, bare token or tab- prefix.
  assert.ok(!/tab-/.test(js), 'EXTRACT_JS must not read panel ids');
});
