'use strict';
var test = require('node:test');
var assert = require('node:assert');
var KS = require('../lib/kramdown-slug.js');

test('outside a teardown, nothing is stripped from the front', function () {
  assert.strictEqual(KS.kramdownSlug('1. Executive Summary'), '1-executive-summary');
  assert.strictEqual(KS.kramdownSlug('What Was Found'), 'what-was-found');
});

test('hyphen runs are NOT collapsed, which is the rule most easily got wrong', function () {
  // The em dash vanishes and both spaces around it survive as hyphens.
  assert.strictEqual(KS.kramdownSlug('4. Technical Analysis \u2014 Static Findings'),
    '4-technical-analysis--static-findings');
  assert.strictEqual(KS.kramdownSlug('0. BLUF / Bottom Line Up Front'),
    '0-bluf--bottom-line-up-front');
  assert.strictEqual(KS.kramdownSlug('10. Detection & Response'), '10-detection--response');
});

test('inside a teardown, kramdown strips the leading non-letters instead', function () {
  assert.strictEqual(KS.kramdownSlug('8.1 Logback insertFromJNDI, CVE-2021-42550', true),
    'logback-insertfromjndi-cve-2021-42550');
  // ...and the SAME heading outside one keeps its number. This pair is the finding.
  assert.strictEqual(KS.kramdownSlug('8.1 Logback insertFromJNDI, CVE-2021-42550', false),
    '81-logback-insertfromjndi-cve-2021-42550');
});

test('underscores survive both rules', function () {
  assert.strictEqual(KS.kramdownSlug('4.7 pe_03 \u2014 HijackLoader Proper'),
    '47-pe_03--hijackloader-proper');
  assert.strictEqual(KS.kramdownSlug('4.1 libpam_cache.so LD_PRELOAD rootkit'),
    '41-libpam_cacheso-ld_preload-rootkit');
});

test('letters outside ASCII survive', function () {
  assert.strictEqual(KS.kramdownSlug('6.2 miss.asp \u2014 Ghost\u5c0f\u7ec4 full-feature ASP webshell'),
    '62-missasp--ghost\u5c0f\u7ec4-full-feature-asp-webshell');
});

test('an explicit {#id} attribute overrides everything', function () {
  assert.strictEqual(
    KS.kramdownSlug('13. Investigation Methodology \u2014 Hunt.io Platform {#methodology}'),
    'methodology');
});

test('inline code renders as its text', function () {
  assert.strictEqual(KS.kramdownSlug('5.1 `.url` Internet Shortcuts'),
    '51-url-internet-shortcuts');
});

test('headingSlugs reads every h2 and h3 in document order', function () {
  var md = '---\ntitle: x\n---\n\n## One Thing\n\ntext\n\n### Two Thing\n\n## Three\n';
  assert.deepStrictEqual(KS.headingSlugs(md), ['one-thing', 'two-thing', 'three']);
});

test('headingSlugs ignores hashes inside fenced code blocks', function () {
  var md = '## Real\n\n```\n## Not A Heading\n```\n\n## Also Real\n';
  assert.deepStrictEqual(KS.headingSlugs(md), ['real', 'also-real']);
});

test('headingSlugs applies the teardown rule only inside the teardown', function () {
  var md = '## 1. Outside Section\n\n' +
    '<details markdown="1" class="hl-teardown"><summary>s</summary>\n\n' +
    '### 8.1 Inside Section\n\n</details>\n\n' +
    '### 9.2 Outside Again\n';
  assert.deepStrictEqual(KS.headingSlugs(md),
    ['1-outside-section', 'inside-section', '92-outside-again']);
});

test('a repeated heading takes a counter, and the first use stays bare', function () {
  var md = '## Analyst Notes\n\n## Analyst Notes\n\n## Analyst Notes\n';
  assert.deepStrictEqual(KS.headingSlugs(md),
    ['analyst-notes', 'analyst-notes-1', 'analyst-notes-2']);
});

test('the counter is shared across every heading level, not just h2 and h3', function () {
  // One corpus report reaches "-5" only because its h4s consumed the numbers in
  // between. Counting h2 and h3 alone puts every later collision off by four.
  var md = '### Deep Technical Analysis\n\n#### Deep Technical Analysis\n\n' +
    '#### Deep Technical Analysis\n\n### Deep Technical Analysis\n';
  assert.deepStrictEqual(KS.headingSlugs(md), [
    'deep-technical-analysis',
    'deep-technical-analysis-1',
    'deep-technical-analysis-2',
    'deep-technical-analysis-3'
  ]);
});

test('headings() reports the level so a caller can filter, and slugs all six', function () {
  var hs = KS.headings('# One\n\n## Two\n\n#### Four\n');
  assert.deepStrictEqual(hs.map(function (h) { return h.level; }), [1, 2, 4]);
  assert.deepStrictEqual(hs.map(function (h) { return h.slug; }), ['one', 'two', 'four']);
});
