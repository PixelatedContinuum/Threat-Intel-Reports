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

// ---------------------------------------------------------------- the checker
var CFN = require('../lib/check-figure-nav.js');
var JSDOM = require('jsdom').JSDOM;

function doc(front, bodyMd) {
  return '---\ntitle: "t"\n' + front + '---\n\n' + bodyMd;
}
var TWO_FIGS =
  '## Alpha Section\n\ntext\n\n' +
  '<figure><img src="{{ "/assets/images/s/a.svg" | relative_url }}" alt="x">' +
  '<figcaption>c</figcaption></figure>\n\n' +
  '## Beta Section\n\ntext\n';
var GOOD =
  'figure_nav:\n' +
  '  - image: a.svg\n' +
  '    parts:\n' +
  '      - label: "Alpha"\n' +
  '        anchor: "#alpha-section"\n' +
  '      - label: "Beta"\n' +
  '        anchor: "#beta-section"\n';

test('figureImages reads the path out of the Liquid relative_url wrapper', function () {
  assert.deepStrictEqual(CFN.figureImages(TWO_FIGS), ['a.svg']);
});

test('a report with no figure_nav is PASS, never NOT CHECKED', function () {
  var r = CFN.checkMarkdown(doc('', TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'PASS');
  assert.match(r.reason, /no figure_nav/);
  assert.strictEqual(r.entries, 0);
});

test('a well formed declaration passes and counts its chips', function () {
  var r = CFN.checkMarkdown(doc(GOOD, TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.entries, 1);
  assert.strictEqual(r.chips, 2);
});

test('an anchor that resolves to no heading FAILS', function () {
  var r = CFN.checkMarkdown(doc(GOOD.replace('#beta-section', '#beta-sektion'), TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /beta-sektion/);
});

test('a collapsed hyphen run FAILS, which is the defect this gate exists for', function () {
  var body = '## Four \u2014 Static Findings\n\n' +
    '<figure><img src="/assets/images/s/a.svg"><figcaption>c</figcaption></figure>\n\n' +
    '## Other Thing\n';
  // The real anchor is "four--static-findings" with two hyphens.
  var front = 'figure_nav:\n  - image: a.svg\n    parts:\n' +
    '      - label: "A"\n        anchor: "#four-static-findings"\n' +
    '      - label: "B"\n        anchor: "#other-thing"\n';
  var r = CFN.checkMarkdown(doc(front, body), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /four-static-findings/);
});

test('an anchor written for outside a teardown FAILS when the heading is inside one', function () {
  var body = '## Alpha Section\n\n' +
    '<figure><img src="/assets/images/s/a.svg"><figcaption>c</figcaption></figure>\n\n' +
    '<details markdown="1" class="hl-teardown"><summary>s</summary>\n\n' +
    '### 8.1 Logback insertFromJNDI\n\n</details>\n';
  var front = 'figure_nav:\n  - image: a.svg\n    parts:\n' +
    '      - label: "A"\n        anchor: "#alpha-section"\n' +
    '      - label: "B"\n        anchor: "#81-logback-insertfromjndi"\n';
  var r = CFN.checkMarkdown(doc(front, body), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  // ...and the real one, with the number stripped, passes.
  var ok = front.replace('#81-logback-insertfromjndi', '#logback-insertfromjndi');
  assert.strictEqual(CFN.checkMarkdown(doc(ok, body), 'x.md').status, 'PASS');
});

test('an image that is on no figure FAILS', function () {
  var r = CFN.checkMarkdown(doc(GOOD.replace('image: a.svg', 'image: ghost.svg'), TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /ghost\.svg/);
});

test('an entry whose parts all land on one anchor FAILS as pointless', function () {
  var one = 'figure_nav:\n  - image: a.svg\n    parts:\n' +
    '      - label: "A"\n        anchor: "#alpha-section"\n' +
    '      - label: "B"\n        anchor: "#alpha-section"\n';
  var r = CFN.checkMarkdown(doc(one, TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /distinct/);
});

test('a single-part entry FAILS', function () {
  var one = 'figure_nav:\n  - image: a.svg\n    parts:\n' +
    '      - label: "A"\n        anchor: "#alpha-section"\n';
  var r = CFN.checkMarkdown(doc(one, TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /at least two/);
});

test('duplicate labels within one entry FAIL', function () {
  var r = CFN.checkMarkdown(doc(GOOD.replace('label: "Beta"', 'label: "Alpha"'), TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /duplicate label/i);
});

test('an empty figure_nav key FAILS rather than passing as undeclared', function () {
  var r = CFN.checkMarkdown(doc('figure_nav:\n', TWO_FIGS), 'x.md');
  assert.strictEqual(r.status, 'FAIL');
});

function liveDoc(entries, extraHtml) {
  return new JSDOM(
    '<div class="hl-post-content">' +
    '<h2 id="alpha-section">Alpha Section</h2>' +
    '<figure><img src="/assets/images/s/a.svg"><figcaption>c</figcaption></figure>' +
    '<h2 id="beta-section">Beta Section</h2>' + (extraHtml || '') + '</div>' +
    '<script type="application/json" id="hl-figure-nav">' +
    JSON.stringify(entries) + '<\/script>').window.document;
}
var LIVE_ENTRIES = [{ image: 'a.svg', parts: [
  { label: 'Alpha', anchor: '#alpha-section' },
  { label: 'Beta', anchor: '#beta-section' }] }];

test('the DOM path agrees with the markdown path on a good report', function () {
  var r = CFN.checkDom(liveDoc(LIVE_ENTRIES), 'live');
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.chips, 2);
});

test('the DOM path proves the SHIPPED module actually renders the chips', function () {
  var d = liveDoc(LIVE_ENTRIES);
  CFN.checkDom(d, 'live');
  assert.strictEqual(d.querySelectorAll('.hl-fignav__chip').length, 2);
});

test('a page whose figure is absent FAILS on the DOM path', function () {
  var d = new JSDOM(
    '<div class="hl-post-content"><h2 id="alpha-section">Alpha</h2>' +
    '<h2 id="beta-section">Beta</h2></div>' +
    '<script type="application/json" id="hl-figure-nav">' +
    JSON.stringify(LIVE_ENTRIES) + '<\/script>').window.document;
  var r = CFN.checkDom(d, 'live');
  assert.strictEqual(r.status, 'FAIL');
});

test('a page with no declaration is PASS on the DOM path too', function () {
  var d = new JSDOM('<div class="hl-post-content"><h2 id="x">x</h2></div>').window.document;
  var r = CFN.checkDom(d, 'live');
  assert.strictEqual(r.status, 'PASS');
  assert.match(r.reason, /no figure_nav/);
});
