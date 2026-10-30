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

test('an unknown token FAILS even when it is the report\'s only tab line', function () {
  /* Round-1 probe P6 in the failing direction: an invalid token does not count
     as tagged, so a guard that keys on `tagged` alone would call the report
     untagged and PASS it. */
  var r = CT.checkMarkdown(doc('## One Section\n{: .hl-tier-2}\n{: .hl-tab-Overview}\n\nText.\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /hl-tab-Overview/);
});

test('a tag that is not directly after the tier line FAILS', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tier-2}\n{: .hl-tab-indicators}',
    '{: .hl-tier-2}\n{: .hl-figure-nav}\n{: .hl-tab-indicators}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /not directly after the heading or its tier line/);
});

test('a tag merged onto the tier line FAILS, naming the check-tiers rule', function () {
  var r = CT.checkMarkdown(doc(BODY.replace('{: .hl-tier-2}\n{: .hl-tab-indicators}',
    '{: .hl-tier-2 .hl-tab-indicators}')));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /merged onto the tier line/);
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
  assert.match(r.problems.join(' '), /second tab line/);
  assert.match(r.problems.join(' '), /exactly one tab/);
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

test('a blank line between the heading and the tier line FAILS, because kramdown moves both classes', function () {
  var r = CT.checkMarkdown(doc('## A\n\n{: .hl-tier-1}\n{: .hl-tab-overview}\n\nx\n\n' +
    '## B\n{: .hl-tier-2}\n{: .hl-tab-chain}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /blank line sits between the heading and that tier line/);
});

test('headings inside fenced code are not counted', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n```\n## Not A Heading\n{: .hl-tab-foo}\n```\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.tagged, 2);
  assert.match(r.advisories.join(' '), /fenced block/);
});

test('a tab line under an h3 FAILS: tabs work on chapters, so no panel is drawn', function () {
  var r = CT.checkMarkdown(doc(BODY + '\n### Sub\n{: .hl-tab-chain}\n\nx\n'));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /under an h3/);
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

/* Round-1 review, check-tabs rubric. P1 and P2 PASSed while kramdown 2.5.2 put
   the tab class on a paragraph and the layout's substring trigger was true. The
   two probe files are reproduced verbatim from
   tasks/runs/T-0500.1.2/review/scratch/checktabs/. */
test('P1: a blank line between the tier line and the tab line FAILS with the line number', function () {
  var md = '## First Section\n{: .hl-tier-2}\n\n{: .hl-tab-overview}\n\nBody one.\n\n' +
    '## Second Section\n{: .hl-tier-2}\n\n{: .hl-tab-chain}\n\nBody two.\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /line 8/);
  assert.match(r.problems.join(' '), /blank line/);
  // The blank line means neither heading is tagged, so all-or-none fires too.
  assert.match(r.problems.join(' '), /carry no tab tag/);
});

test('P2: a stray tab line in a section body FAILS with its line, and the report is tabbed', function () {
  var md = '## Only Section\n\nBody text before the stray tag.\n\n{: .hl-tab-chain}\n\nMore body.\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /line 9/);
  assert.match(r.problems.join(' '), /attaches the class to the next paragraph/);
});

/* Round-2 review F2: the layout keys on a complete `hl-tab-<token>` class on an
   h2, not on the bare string, so P3 is ordinary prose and must not FAIL. A
   misplaced tab IAL line still FAILs (P1, P2, P8 above). */
test('P3: the bare string in prose is an ADVISORY, because the layout keys on the heading class', function () {
  var md = '## Only Section\n{: .hl-tier-2}\n\nThe layout keys on the string hl-tab- and this ' +
    'sentence contains it.\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.problems.length, 0);
  assert.strictEqual(r.misplaced.length, 0);
  assert.match(r.advisories.join(' '), /applies no class there/);
  assert.match(r.advisories.join(' '), /line 8/);
  // Untagged is untagged: the section is still reported as carrying no tag.
  assert.strictEqual(r.tagged, 0);
});

test('a heading whose text quotes the string is an advisory too, not a tab', function () {
  var r = CT.checkMarkdown(doc('## Only Section\n{: .hl-tier-2}\n\nx\n\n### The hl-tab- marker\n\ny\n'));
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.match(r.advisories.join(' '), /written in the heading/);
});

test('a tab IAL line in the body still FAILS, so misplaced lines are not downgraded with the prose case', function () {
  var md = '## Only Section\n{: .hl-tier-2}\n{: .hl-tab-overview}\n\nbody\n\n' +
    '## Second\n{: .hl-tier-2}\n{: .hl-tab-chain}\n\ntext\n\n{: .hl-tab-chain}\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'FAIL');
  assert.ok(r.problems.some(function (p) { return /blank line/.test(p); }), r.problems.join(' '));
});

test('P8: a blank line between the heading and the tier line FAILS on the tagged section', function () {
  var md = '## First Section\n\n{: .hl-tier-2}\n{: .hl-tab-overview}\n\nBody.\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /blank line sits between the heading and that tier line/);
});

test('a misplaced tab line is reported with its 1-based line number', function () {
  var md = '## A\n{: .hl-tier-1}\n{: .hl-tab-overview}\n\nx\n\n{: .hl-tab-chain}\n';
  var r = CT.checkMarkdown(doc(md));
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /line 11/);
  assert.strictEqual(r.misplaced.length, 1);
});

test('the DOM path FAILS a tab class kramdown put on a paragraph', function () {
  var d = new JSDOM('<div class="hl-post-content">' +
    '<h2 id="a" class="hl-tier-1 hl-tab-overview">A</h2><p class="hl-tab-chain">x</p></div>').window.document;
  var r = CT.checkDom(d);
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /carries the tab class/);
});

/* T-0500.1.9, J1: --require makes "no tab tags" a FAIL. Without it nothing changes. */
test('--require: a report with no tab tags FAILS, with it absent the same report is PASS', function () {
  var md = doc('## One\n{: .hl-tier-1}\n\ntext\n\n## Two\n{: .hl-tier-2}\n\ntext\n');
  var plain = CT.checkMarkdown(md);
  assert.strictEqual(plain.status, 'PASS');
  var req = CT.checkMarkdown(md, 'x', { require: true });
  assert.strictEqual(req.status, 'FAIL');
  assert.match(req.problems.join(' '), /no tab tags declared: 0 of 2 sections/);
});

test('--require does not change a fully tagged report, and a report with no sections FAILS', function () {
  assert.strictEqual(CT.checkMarkdown(doc(BODY), 'x', { require: true }).status, 'PASS');
  var empty = CT.checkMarkdown(doc('Just prose, no headings.\n'), 'x', { require: true });
  assert.strictEqual(empty.status, 'FAIL');
  assert.match(empty.problems.join(' '), /no ## sections/);
});

test('--require on the command line: exit 1 untagged, exit 0 tagged, exit 0 untagged without the flag', function () {
  var cp = require('node:child_process'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-tabs-'));
  var u = path.join(dir, 'u.md'), g = path.join(dir, 'g.md');
  fs.writeFileSync(u, doc('## One\n{: .hl-tier-1}\n\ntext\n'));
  fs.writeFileSync(g, doc(BODY));
  var cli = path.join(__dirname, '..', 'check-tabs.js');
  var run = function (args) { return cp.spawnSync(process.execPath, [cli].concat(args), { encoding: 'utf8' }).status; };
  assert.strictEqual(run(['--require', u]), 1);
  assert.strictEqual(run([u]), 0);
  assert.strictEqual(run(['--require', g]), 0);
  assert.strictEqual(run(['--require', dir + '/missing.md']), 2);
});
