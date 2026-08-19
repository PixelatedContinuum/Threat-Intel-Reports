'use strict';
var test = require('node:test');
var assert = require('node:assert');
var CT = require('../lib/check-tiers.js');
var JSDOM = require('jsdom').JSDOM;

var BODY = '## 1. Brief\n{: .hl-tier-1}\n\ntext\n\n## 2. Tradecraft\n{: .hl-tier-2}\n\ntext\n';
function doc(b) { return '---\ntitle: "t"\n---\n\n' + b; }

test('an unmarked report is PASS with a reason, never NOT CHECKED', function () {
  var r = CT.checkMarkdown(doc('## One\n\ntext\n\n## Two\n\ntext\n'));
  assert.strictEqual(r.status, 'PASS');
  assert.match(r.reason, /no tier markers/);
  assert.strictEqual(r.marked, 0);
});

test('a fully marked report passes and counts its tiers', function () {
  var r = CT.checkMarkdown(doc(BODY));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.marked, 2);
  assert.deepStrictEqual(r.byTier, { 1: 1, 2: 1, 3: 0 });
});

test('partial marking FAILS and names the unmarked heading', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n## 3. Teardown\n\ntext\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /3\. Teardown/);
});

test('an unknown tier value FAILS and names it', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('hl-tier-2', 'hl-tier-4')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /hl-tier-4/);
});

test('no Tier 1 section FAILS, because Brief would render an empty page', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('hl-tier-1', 'hl-tier-3')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /Tier 1/);
});

test('a single tier throughout FAILS, because every view would be identical', function () {
  var r = CT.checkMarkdown(doc('## A\n{: .hl-tier-1}\n\nx\n\n## B\n{: .hl-tier-1}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /identical/);
});

test('a same-line marker FAILS, because it applies no class and corrupts the anchor', function () {
  var r = CT.checkMarkdown(doc('## A {: .hl-tier-1}\n\nx\n\n## B\n{: .hl-tier-2}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /following line/i);
});

test('the bare-brace same-line form is caught too', function () {
  var r = CT.checkMarkdown(doc('## A {.hl-tier-1}\n\nx\n\n## B\n{: .hl-tier-2}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /following line/i);
});

test('headings inside fenced code are not counted', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n```\n## Not A Heading\n```\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('a blank line between heading and marker is still accepted', function () {
  var r = CT.checkMarkdown(doc('## A\n\n{: .hl-tier-1}\n\nx\n\n## B\n{: .hl-tier-2}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('h3 markers are ignored; the switch works on chapters', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n### Sub\n{: .hl-tier-3}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.marked, 2);
});

test('the DOM path reads the classes the site actually rendered', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="a" class="hl-tier-1">A</h2><p>x</p>' +
    '<h2 id="b" class="hl-tier-2">B</h2><p>x</p></div>').window.document;
  var r = CT.checkDom(d);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.marked, 2);
});

test('the DOM path FAILS a page where kramdown applied no class', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="a" class="hl-tier-1">A</h2><p>x</p>' +
    '<h2 id="b">B</h2><p>x</p></div>').window.document;
  assert.strictEqual(CT.checkDom(d).status, 'FAIL');
});

test('an unmarked page is PASS on the DOM path too', function () {
  var d = new JSDOM('<div class="hl-post-content"><h2 id="a">A</h2><p>x</p>' +
    '<h2 id="b">B</h2></div>').window.document;
  var r = CT.checkDom(d);
  assert.strictEqual(r.status, 'PASS');
  assert.match(r.reason, /no tier markers/);
});
