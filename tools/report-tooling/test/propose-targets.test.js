'use strict';

/* T-0500.1.9 (audit W04, I03, R01): the three authoring proposers take a PATH to
   any report markdown (the vault copy included), and a bare --write refuses
   instead of tagging the corpus. And the report template's own headings all get
   a tab proposal (audit T06). These run the real CLIs. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');
var RT = require('../lib/report-target.js');
var P = require('../propose-tabs.js');

var TOOL = path.join(__dirname, '..');
var REPORTS = path.join(TOOL, '..', '..', 'reports');

function run(script, args) {
  var r = cp.spawnSync(process.execPath, [path.join(TOOL, script)].concat(args), { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function scratch(md) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-propose-'));
  var sub = path.join(dir, 'some-new-report');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(sub, 'index.md'), md);
  return { dir: sub, file: path.join(sub, 'index.md') };
}
var MD = '---\ntitle: "t"\n---\n\n## 1. Executive Summary\n{: .hl-tier-1}\n\ntext\n\n## 2. Indicators of Compromise\n{: .hl-tier-2}\n\ntext\n';

test('resolveTarget: a bare name is the old folder form, a path is the file or its folder', function () {
  var s = scratch(MD);
  assert.strictEqual(RT.resolveTarget(s.file, REPORTS).mode, 'path');
  assert.strictEqual(RT.resolveTarget(s.file, REPORTS).file, s.file);
  assert.strictEqual(RT.resolveTarget(s.dir, REPORTS).file, s.file);
  var name = RT.resolveTarget('opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015-tabbed-preview', REPORTS);
  assert.strictEqual(name.mode, 'name');
  assert.ok(RT.resolveTarget('nope-not-a-report', REPORTS).error);
  assert.match(RT.resolveTarget('/no/such/place/index.md', REPORTS).error, /no such file or folder/);
});

test('propose-tabs reads a markdown path outside the checkout, and --write tags only that file', function () {
  var s = scratch(MD);
  var r = run('propose-tabs.js', [s.file]);
  assert.strictEqual(r.code, 0, r.err);
  assert.match(r.out, /overview/);
  assert.match(r.out, /NEED A DECISION      0/);
  var w = run('propose-tabs.js', [s.file, '--write']);
  assert.strictEqual(w.code, 0, w.err);
  var after = fs.readFileSync(s.file, 'utf8');
  assert.match(after, /\{: \.hl-tab-overview\}/);
  assert.match(after, /\{: \.hl-tab-indicators\}/);
  // The folder form works too, and the result then passes check-tabs --require.
  var c = cp.spawnSync(process.execPath, [path.join(TOOL, 'check-tabs.js'), '--require', s.dir], { encoding: 'utf8' });
  assert.strictEqual(c.status, 0, c.stdout);
});

test('a bare --write refuses with exit 2 on all three proposers and writes nothing', function () {
  var before = cp.spawnSync('git', ['status', '--porcelain', '--', 'reports'], { cwd: path.join(TOOL, '..', '..'), encoding: 'utf8' }).stdout;
  var a = run('propose-tabs.js', ['--write']);
  assert.strictEqual(a.code, 2);
  assert.match(a.err, /refusing --write with no target/);
  var b = run('propose-figure-nav.js', ['--write']);
  assert.strictEqual(b.code, 2);
  assert.match(b.err, /refusing --write/);
  var c = run('propose-tiers.js', ['--write']);
  assert.strictEqual(c.code, 2);
  assert.match(c.err, /refusing --write/);
  var d = run('propose-tiers.js', ['--apply']);
  assert.strictEqual(d.code, 2);
  var after = cp.spawnSync('git', ['status', '--porcelain', '--', 'reports'], { cwd: path.join(TOOL, '..', '..'), encoding: 'utf8' }).stdout;
  assert.strictEqual(after, before, 'no report was touched');
});

test('a path that does not exist is exit 2 naming the path, never a fall back to the corpus', function () {
  ['propose-tabs.js', 'propose-figure-nav.js', 'propose-tiers.js'].forEach(function (t) {
    var r = run(t, ['/no/such/dir/index.md']);
    assert.strictEqual(r.code, 2, t);
    assert.match(r.err, /\/no\/such\/dir\/index\.md/, t);
  });
});

test('propose-tiers and propose-figure-nav also accept a path', function () {
  var s = scratch(MD.replace(/\{: \.hl-tier-\d\}\n/g, ''));
  var t = run('propose-tiers.js', [s.file]);
  assert.strictEqual(t.code, 0, t.err);
  assert.match(t.out, /T1/);
  var ap = run('propose-tiers.js', [s.file, '--apply', '1,2']);
  assert.strictEqual(ap.code, 0, ap.err);
  assert.match(fs.readFileSync(s.file, 'utf8'), /\{: \.hl-tier-2\}/);
  var f = run('propose-figure-nav.js', [s.file]);
  assert.strictEqual(f.code, 0, f.err);
});

/* ---- the report template's own headings (audit T06) ---- */

var FIXTURE = fs.readFileSync(path.join(__dirname, 'fixtures', 'template-headings.tsv'), 'utf8')
  .split('\n').filter(Boolean).map(function (l) { return l.split('\t'); });

function templateMd(rows) {
  return '---\ntitle: "template"\n---\n\n' + rows.map(function (r) {
    return '## ' + r[0] + '\n{: .hl-tier-2}\n\nBody.\n';
  }).join('\n');
}

test('all 19 headings of the report template get a tab proposal, each the one recorded in the fixture', function () {
  assert.strictEqual(FIXTURE.length, 19);
  var props = P.proposeFor(templateMd(FIXTURE));
  assert.strictEqual(props.length, 19);
  var unplaced = props.filter(function (p) { return !p.tab; }).map(function (p) { return p.text; });
  assert.deepStrictEqual(unplaced, [], 'unplaced template headings');
  props.forEach(function (p, i) { assert.strictEqual(p.tab, FIXTURE[i][1], p.text); });
});

test('the five headings audit T06 found unplaced come from the template pass, and a control heading still does not', function () {
  var props = P.proposeFor(templateMd(FIXTURE));
  var fromTemplate = props.filter(function (p) { return p.how === 'template'; }).map(function (p) { return p.text; });
  ['3. What Is [Malware Name]?', '10. Recommendations', 'Delivery Method Analysis & Initial Access Vectors',
    'Future Evolution & Threat Trends', 'Frequently Asked Questions'].forEach(function (h) {
    assert.ok(fromTemplate.indexOf(h) !== -1, h + ' should be placed by the template pass');
  });
  // The control: a heading no rule knows is still unplaced and counted.
  var ctl = P.proposeFor(templateMd(FIXTURE.concat([['Xyzzy Plugh', 'x']])));
  assert.strictEqual(ctl[ctl.length - 1].tab, null);
});

test('the template pass never moves a proposal another pass already made', function () {
  // "Recommendations" inside a run of chain sections is placed by span first, not by the template rule.
  var rows = [['1. Executive Summary'], ['Capability One Walkthrough'], ['Recommendations'], ['Capability Two Walkthrough'], ['Confidence Summary']];
  var props = P.proposeFor(templateMd(rows));
  var rec = props[2];
  assert.strictEqual(rec.how, 'span');
  assert.strictEqual(rec.tab, 'chain');
});

test('the fixture still matches the template when the template is present', function (t) {
  var tpl = path.join(TOOL, '..', '..', '..', '..', '.claude', 'skills', 'report-structure-template', 'references', 'section-templates.md');
  if (!fs.existsSync(tpl)) { t.skip('report-structure-template is not beside this checkout'); return; }
  var heads = fs.readFileSync(tpl, 'utf8').split('\n')
    .filter(function (l) { return /^## /.test(l) && !/^## Section /.test(l); }).map(function (l) { return l.slice(3); });
  assert.deepStrictEqual(heads, FIXTURE.map(function (r) { return r[0]; }),
    'the template headings changed: update test/fixtures/template-headings.tsv and give any new heading a tab rule');
});
