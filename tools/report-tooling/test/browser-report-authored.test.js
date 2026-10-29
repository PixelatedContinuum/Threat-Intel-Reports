'use strict';

/* Tests for the browser gate's authored-report machinery (fix rounds 1 and 2).

   These do NOT drive a browser; that is check-browser-report.js itself. What is
   testable without one is the part that decides WHAT the page is compared
   against, because that decision is where the gate has been wrong twice:

   - round 1: the expectation came from the page's own DOM, so a section deleted
     from the source and two sections swapped in the source both PASSed;
   - round 2: the site copy was read before the vault copy, so a markdown copy
     that had already lost a section compared clean against a page built from
     the same copy, and `--md` with no path silently fell back to whichever copy
     resolved.

   Every function below is exercised on real corpus files where one exists, and
   on inline strings where the case has to be constructed (a vault copy that
   differs from the site copy cannot be staged in the real vault from a test).

   See homelab-soc/docs/gate-honesty-contract.md: a comparison is only worth
   having if it can name what it compared and what it did not. */

var test = require('node:test');
var assert = require('node:assert');
var path = require('node:path');
var childProcess = require('node:child_process');
var G = require('../check-browser-report.js');

var TOOL = path.join(__dirname, '..');
var REPO = path.join(TOOL, '..', '..');
var PILOT = 'opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015';
var PREVIEW = PILOT + '-tabbed-preview';

/* ---- the tab vocabulary and the viewport list (design-v4 3 and 4a) ---- */

test('the seven tab tokens and the five viewports are the fixed design lists', function () {
  assert.deepEqual(G.TAB_TOKENS,
    ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence']);
  assert.deepEqual(G.TAB_VIEWPORTS.map(function (v) { return v[0] + 'x' + v[1]; }),
    ['1280x900', '768x1024', '812x375', '390x844', '360x800']);
});

/* ---- isTabbedHtml: which branch a fetched page takes ---- */

test('a page whose h2 carries the tab class is tabbed', function () {
  assert.equal(G.isTabbedHtml('<h2 class="hl-tier-2 hl-tab-victims" id="x">x</h2>'), true);
});

test('a page that only quotes the class in prose is not tabbed', function () {
  assert.equal(G.isTabbedHtml('<h2 class="hl-tier-2" id="x">x</h2><p>use hl-tab-victims</p>'), false);
  assert.equal(G.isTabbedHtml('<h2 id="x">hl-tab-overview</h2>'), false);
});

/* ---- the heading-text normaliser (D7) ----

   The page renders markdown to text, so the comparison has to drop formatting
   and the typographic substitutions kramdown makes, while keeping every word,
   digit and real punctuation mark. */

test('typographic quotes, dashes and ellipses normalise to their ascii forms', function () {
  assert.equal(G.normaliseHeadingText('the Bank\u2019s Own Proxy'),
    G.normaliseHeadingText("the Bank's Own Proxy"));
  assert.equal(G.normaliseHeadingText('a \u2014 b \u2013 c \u2026'), G.normaliseHeadingText('a - b - c ...'));
  assert.equal(G.normaliseHeadingText('\u201cquoted\u201d'), G.normaliseHeadingText('"quoted"'));
});

test('inline markdown renders to its text', function () {
  assert.equal(G.normaliseHeadingText('**Bold** and *italic*'), 'Bold and italic');
  assert.equal(G.normaliseHeadingText('`pe_03` keeps its underscore'), 'pe_03 keeps its underscore');
  assert.equal(G.normaliseHeadingText('see [the report](https://example.test/x)'),
    'see the report');
  assert.equal(G.normaliseHeadingText('A &amp; B <span>x</span>'), 'A & B x');
});

test('underscores inside a word are not eaten as emphasis', function () {
  assert.equal(G.normaliseHeadingText('4.7 pe_03 - HijackLoader'), '4.7 pe_03 - HijackLoader');
});

test('whitespace collapses and the text is trimmed', function () {
  assert.equal(G.normaliseHeadingText('  a \n  b\t c  '), 'a b c');
});

test('a renamed heading is not equal to the report heading (the D7 control)', function () {
  assert.notEqual(G.normaliseHeadingText('17. Alerts'), G.normaliseHeadingText('17. Notification'));
});

/* ---- the site copy against the vault copy (D3) ---- */

var SITE_MD = [
  '---',
  'title: "x"',
  'permalink: /reports/x/',
  '---',
  '## 1. Executive Summary',
  '{: .hl-tier-1}',
  '{: .hl-tab-overview}',
  '',
  'Body one.',
  '## 2. Risk Assessment',
  '{: .hl-tier-1}',
  '',
  'Body two.'
].join('\n');

var VAULT_MD = [
  '---',
  'title: "x"',
  'layout: post',
  '---',
  '## 1. Executive Summary',
  '{: .hl-tier-1}',
  '{: .hl-tab-overview}',
  '',
  'Body one.',
  '## 2. Risk Assessment',
  '{: .hl-tier-1}',
  '',
  'Body two.'
].join('\n');

test('front matter and hl-tab lines are stripped from both copies before comparing', function () {
  var diff = G.firstBodyDifference(G.bodyLines(SITE_MD), G.bodyLines(VAULT_MD));
  assert.equal(diff, null, 'a front-matter-only difference must not read as a body difference');
});

test('the hl-tab line present on one side only is not a body difference', function () {
  var vaultTagged = VAULT_MD.replace('{: .hl-tier-1}\n\nBody two.',
    '{: .hl-tier-1}\n{: .hl-tab-victims}\n\nBody two.');
  assert.equal(G.firstBodyDifference(G.bodyLines(SITE_MD), G.bodyLines(vaultTagged)), null);
});

test('a lost section is a body difference, named by line on both sides', function () {
  var vaultMinus17 = VAULT_MD.replace('## 2. Risk Assessment\n{: .hl-tier-1}\n', '');
  var diff = G.firstBodyDifference(G.bodyLines(SITE_MD), G.bodyLines(vaultMinus17));
  assert.ok(diff, 'the missing section must be a difference');
  assert.equal(diff.site, '## 2. Risk Assessment');
  assert.equal(diff.vault, '', 'the vault copy has moved straight on to the blank line');
  assert.equal(diff.siteLine, 10);
  assert.equal(diff.vaultLine, 10, 'both files number the body line that disagrees');
});

test('trailing whitespace on a line is not content', function () {
  var padded = VAULT_MD.replace('Body one.', 'Body one.   ');
  assert.equal(G.firstBodyDifference(G.bodyLines(SITE_MD), G.bodyLines(padded)), null);
});

test('a body line is reported with the file line it came from', function () {
  var lines = G.bodyLines(SITE_MD);
  var first = lines[0];
  assert.equal(first.text, '## 1. Executive Summary');
  /* Four front-matter lines, then the body starts on line 5. */
  assert.equal(first.line, 5);
});

/* ---- the resolution order (D2 and D3) ---- */

test('a slug with no vault copy resolves to the site copy and says so', function () {
  var a = G.readAuthored(PREVIEW);
  assert.equal(a.error, undefined);
  assert.equal(a.source, 'site');
  assert.equal(a.note, 'expectation from the site copy; no vault copy');
  assert.equal(a.compare, null, 'nothing to compare the site copy with');
  assert.equal(a.h2.length, 20);
});

test('the tagged preview markdown carries a tab line for every section', function () {
  var a = G.readAuthored(PREVIEW);
  assert.ok(a.tabs, 'the preview copy is tagged, so its tab assignments are readable');
  assert.equal(Object.keys(a.tabs).length, 20);
  assert.equal(a.tabs['17-notification'], 'victims');
});

/* The vault lives in the workflow repo beside this checkout, not in CI's clone
   of the site repo, so the case is a stated skip there rather than a failure. */
var VAULT_PRESENT = require('node:fs').existsSync(G.reportPaths(PILOT).vault);

test('a slug with a vault copy resolves to the vault copy, compared with the site copy', {
  skip: VAULT_PRESENT ? false : 'no vault copy beside this checkout (CI clones the site repo only)'
}, function () {
  var a = G.readAuthored(PILOT);
  assert.equal(a.error, undefined);
  assert.equal(a.source, 'vault');
  assert.match(a.note, /expectation from the vault copy/);
  assert.ok(a.compare && a.compare.readable === true);
  assert.equal(a.compare.diff, null, 'the published report\'s two copies agree today');
  assert.equal(a.h2.length, 20);
});

test('the published markdown has no tab tags yet, so no tab assignment is invented', function () {
  var a = G.readAuthored(PILOT);
  assert.equal(a.tabs, null);
});

test('every authored h3 is mapped to the h2 above it (D8)', function () {
  var a = G.readAuthored(PREVIEW);
  assert.equal(a.parents['where-to-look-first'], '16-detection-and-hunting-guidance');
  assert.equal(a.parents['the-suppliers-and-the-rest-of-the-named-parties'],
    '3-who-was-hit-and-how-far-the-operator-got');
});

test('a slug with no markdown at all is an error naming every place it looked', function () {
  var a = G.readAuthored('zz-no-markdown-for-this-slug');
  assert.ok(a.error);
  assert.match(a.error, /--md/);
  assert.match(a.error, /vault copy/);
  assert.equal(a.h2, undefined, 'no expectation is invented from nothing');
});

/* ---- `--md` with no path (D4) ---- */

test('--md as the last argument is a usage error, exit 2, never a silent fallback', function () {
  var r = childProcess.spawnSync(process.execPath,
    [path.join(TOOL, 'check-browser-report.js'), PILOT, '--md'], { encoding: 'utf8' });
  assert.equal(r.status, 2, 'stderr/stdout: ' + r.stdout + r.stderr);
  assert.match(r.stdout + r.stderr, /--md was given with no path/);
});
