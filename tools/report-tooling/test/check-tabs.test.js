'use strict';
var test = require('node:test');
var assert = require('node:assert');
var CT = require('../check-tabs.js');
var JSDOM = require('jsdom').JSDOM;

var BODY = '## 1. Executive Summary\n{: .hl-tier-1}\n{: .hl-tab-overview}\n\nText.\n\n' +
  '## 2. Indicators of Compromise\n{: .hl-tier-2}\n{: .hl-tab-indicators}\n\nText.\n';
function doc(b) { return '---\ntitle: "t"\n---\n\n' + b; }

test('an untagged report is PASS with a reason, never NOT CHECKED', function () {
  var r = CT.checkMarkdown(doc('## One\n{: .hl-tier-1}\n\ntext\n\n## Two\n{: .hl-tier-2}\n\ntext\n'));
  assert.strictEqual(r.status, 'PASS');
  assert.match(r.reason, /no tab tags/);
  assert.strictEqual(r.tagged, 0);
});

test('a fully tagged report passes and counts each tab', function () {
  var r = CT.checkMarkdown(doc(BODY));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.tagged, 2);
  assert.strictEqual(r.byTab.overview, 1);
  assert.strictEqual(r.byTab.indicators, 1);
  assert.deepStrictEqual(r.sequence.map(function (s) { return s.tab; }), ['overview', 'indicators']);
});

test('one section with no tag FAILS, all-or-none, and names the section', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tab-indicators}\n\n', '')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /1 of 2 sections carry no tab tag/);
  assert.match(r.problems.join(' '), /2\. Indicators of Compromise/);
});

test('an unknown token FAILS and names it', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('hl-tab-indicators', 'hl-tab-iocs')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /hl-tab-iocs/);
  assert.match(r.problems.join(' '), /overview, victims, chain/);
});

test('a tag that is not directly after the tier line FAILS', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tier-2}\n{: .hl-tab-indicators}',
    '{: .hl-tier-2}\n{: .hl-figure-nav}\n{: .hl-tab-indicators}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /not directly after the tier line/);
});

test('a tag merged onto the tier line FAILS, naming the check-tiers rule', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tier-2}\n{: .hl-tab-indicators}',
    '{: .hl-tier-2 .hl-tab-indicators}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /merged onto another IAL line/);
});

test('a same-line tag on the heading FAILS, because it corrupts the anchor', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('## 2. Indicators of Compromise\n{: .hl-tier-2}\n{: .hl-tab-indicators}',
    '## 2. Indicators of Compromise {: .hl-tab-indicators}\n{: .hl-tier-2}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /OWN line/);
});

test('two tab lines under one heading FAIL', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tab-indicators}',
    '{: .hl-tab-indicators}\n{: .hl-tab-chain}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /2 tab lines/);
});

test('a heading id of one-page FAILS', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n## One Page\n{: .hl-tier-2}\n{: .hl-tab-confidence}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /renders the id "one-page"/);
});

test('a heading id starting tab- FAILS, because the layout owns that prefix', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n## Tab Chain\n{: .hl-tier-2}\n{: .hl-tab-confidence}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /renders the id "tab-chain"/);
});

test('a bare token as a heading id is NOT a failure; that is why panels carry tab-', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n## Overview\n{: .hl-tier-2}\n{: .hl-tab-confidence}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('a blank line between the heading and the tier line is still accepted', function () {
  var r = CT.checkMarkdown(doc('## A\n\n{: .hl-tier-1}\n{: .hl-tab-overview}\n\nx\n\n' +
    '## B\n{: .hl-tier-2}\n{: .hl-tab-chain}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('headings inside fenced code are not counted', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n```\n## Not A Heading\n{: .hl-tab-foo}\n```\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
});

test('h3 tab lines are ignored; tabs work on chapters', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n### Sub\n{: .hl-tab-chain}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.tagged, 2);
});

test('a tab line with no tier line is accepted but raises an advisory', function () {
  var r = CT.checkMarkdown(doc('## A\n{: .hl-tab-overview}\n\nx\n\n## B\n{: .hl-tab-chain}\n\nx\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.match(r.advisories.join(' '), /no tier line/);
});

test('the DOM path reads the classes the site actually rendered', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="a" class="hl-tier-1 hl-tab-overview">A</h2><p>x</p>' +
    '<h2 id="b" class="hl-tier-2 hl-tab-chain">B</h2><p>x</p></div>').window.document;
  var r = CT.checkDom(d);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.tagged, 2);
  assert.match(r.advisories.join(' '), /placement was not checked/);
});

test('the DOM path FAILS a page where one h2 carries no tab class', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="a" class="hl-tier-1 hl-tab-overview">A</h2><p>x</p>' +
    '<h2 id="b" class="hl-tier-2">B</h2><p>x</p></div>').window.document;
  assert.strictEqual(CT.checkDom(d).status, 'FAIL');
});

test('the DOM path FAILS a rendered heading id of one-page', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="one-page" class="hl-tier-1 hl-tab-overview">One Page</h2><p>x</p></div>').window.document;
  var r = CT.checkDom(d);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /one-page/);
});
