'use strict';

/* T-0603 M37 (A5, S32): the Wire gate run as a PROCESS. The lib tests call check() and checkPage()
   and never see the part that decides the exit code and the last line, which is where a Details FAIL
   once became exit 2 (NOT CHECKED) and a page fault in vulns.xml was read as a data fault.

   Each case builds a scratch root from the real page files (wire/, the wire-* includes, custom.scss,
   wire-details.js, wire-sources.yml) and a synthetic wire.yml (test/fixtures/vedas-wire.yml), copies the
   gate into it, pins Date.now() to ten minutes after the fixture's generated_at so the age check is
   deterministic, and runs `node check-wire.js` with WIRE_GATE_NO_FETCH=1. The first test is the control:
   the untouched root must exit 0 and print three PASS classes, so a failing case below cannot be a
   harness that fails everything. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');

var TOOLING = path.join(__dirname, '..');
var SITE = path.join(TOOLING, '..', '..');
var FIXTURE = fs.readFileSync(path.join(__dirname, 'fixtures', 'vedas-wire.yml'), 'utf8');
var LINE = /^WIRE-VERDICT page=(PASS|FAIL|NOT_CHECKED) data=(PASS|FAIL|NOT_CHECKED) stale=(PASS|FAIL|NOT_CHECKED)$/;

function copy(from, to) {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}

/* Builds the scratch root, applies `mutate(root)`, runs the gate, returns { code, out, last }. */
function run(mutate, wireYml, originYml) {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-wirecli-'));
  try {
    ['wire/index.md', 'wire/cves.xml', 'wire/vulns.xml', 'wire/details-nkev.json', 'wire/details-cves.json',
      'assets/css/custom.scss', 'assets/js/wire-details.js', '_data/wire-sources.yml'
    ].forEach(function (f) { copy(path.join(SITE, f), path.join(root, f)); });
    fs.readdirSync(path.join(SITE, '_includes')).filter(function (n) { return /^wire-.*\.html$/.test(n); })
      .forEach(function (n) { copy(path.join(SITE, '_includes', n), path.join(root, '_includes', n)); });
    var tool = path.join(root, 'tools', 'report-tooling');
    copy(path.join(TOOLING, 'check-wire.js'), path.join(tool, 'check-wire.js'));
    copy(path.join(TOOLING, 'lib', 'check-wire.js'), path.join(tool, 'lib', 'check-wire.js'));
    fs.symlinkSync(path.join(TOOLING, 'node_modules'), path.join(tool, 'node_modules'));
    if (wireYml !== null) fs.writeFileSync(path.join(root, '_data', 'wire.yml'), wireYml === undefined ? FIXTURE : wireYml);
    var gen = /^generated_at:\s*'?([^'\s]+)'?/m.exec(FIXTURE)[1];
    var shim = path.join(root, 'clock.js');
    fs.writeFileSync(shim, 'var t=' + (Date.parse(gen) + 600000) + ';Date.now=function(){return t;};');
    if (mutate) mutate(root);
    if (originYml) {
      // A one-commit repo whose origin/wire-data holds `originYml`: what the gate reads to tell a stopped
      // generator from a clone nobody pulled.
      var g = function (args) {
        cp.execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false'].concat(args),
          { cwd: root, stdio: 'ignore' });
      };
      g(['init', '-q']);
      fs.writeFileSync(path.join(root, 'wire.yml'), originYml);
      g(['add', 'wire.yml']);
      g(['commit', '-q', '-m', 'origin']);
      g(['update-ref', 'refs/remotes/origin/wire-data', 'HEAD']);
      fs.unlinkSync(path.join(root, 'wire.yml'));
    }
    var r = cp.spawnSync(process.execPath, ['-r', shim, 'check-wire.js'], {
      cwd: tool, encoding: 'utf8', env: Object.assign({}, process.env, { WIRE_GATE_NO_FETCH: '1' })
    });
    var lines = r.stdout.replace(/\n+$/, '').split('\n');
    return { code: r.status, out: r.stdout, err: r.stderr, last: lines[lines.length - 1] };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function edit(rel, from, to) {
  return function (root) {
    var p = path.join(root, rel);
    var s = fs.readFileSync(p, 'utf8');
    assert.ok(s.indexOf(from) >= 0, 'the mutation target is present in ' + rel + ': ' + from);
    fs.writeFileSync(p, s.replace(from, to));
  };
}

test('control: the untouched scratch root exits 0 and every class is PASS', function () {
  var r = run(null);
  assert.equal(r.code, 0, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=PASS data=PASS stale=PASS');
  assert.match(r.last, LINE);
});

test('a Details-only FAIL (a markup sink in wire-details.js) exits 1 and is a page fault, not NOT CHECKED', function () {
  var r = run(function (root) {
    fs.appendFileSync(path.join(root, 'assets', 'js', 'wire-details.js'), '\nel.innerHTML = x;\n');
  });
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=FAIL data=PASS stale=PASS');
  assert.match(r.out, /FAIL {2}assets\/js\/wire-details\.js/);
});

test('an unescaped value in a Details JSON page exits 1 as a page fault', function () {
  var r = run(edit('wire/details-nkev.json', '{"generated_at": {{ wire.vulns_generated_at | jsonify }}', '{"generated_at": {{ r.cve | strip }}'));
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=FAIL data=PASS stale=PASS');
});

test('a wire/vulns.xml FAIL exits 1 and is a page fault, never a data fault', function () {
  var r = run(edit('wire/vulns.xml', '{{ site.title | xml_escape }}: The Wire, nKEVs', '{{ site.title | strip }}: The Wire, nKEVs'));
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=FAIL data=PASS stale=PASS');
  assert.match(r.out, /FAIL {2}.*wire\/vulns\.xml/);
});

test('a broken wire/index.md exits 1 and is a page fault', function () {
  var r = run(edit('wire/index.md', '{%- assign day = i.date', '{%- assign dayx = i.date'));
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=FAIL data=PASS stale=PASS');
});

test('a bad VEDAS value in wire.yml exits 1 and is filed under the page class (the build fails, wire.yml is kept)', function () {
  var bad = FIXTURE.replace('    vedas: 1\n', '    vedas: 7\n');
  assert.notEqual(bad, FIXTURE, 'the mutation changed the fixture');
  var r = run(null, bad);
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=FAIL data=PASS stale=PASS');
});

// Unquoted, as the generator writes it: the gate reads origin's copy with a line regex, not a YAML parser.
var OLD = FIXTURE.replace(/^generated_at:.*$/m, 'generated_at: 2026-11-05T02:00:00Z');
var FRESH = FIXTURE.replace(/^generated_at:.*$/m, 'generated_at: 2026-11-05T20:48:28Z');

test('any other value fault in wire.yml stays a data fault (a non-https headline url)', function () {
  var bad = FIXTURE.replace('url: https://example.org/research', 'url: http://example.org/research');
  assert.notEqual(bad, FIXTURE, 'the mutation changed the fixture');
  var r = run(null, bad);
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=PASS data=FAIL stale=PASS');
});

test('a stopped generator (old file, origin no fresher) is the stale class alone: stale=FAIL, page and data PASS', function () {
  var r = run(null, OLD, OLD);
  assert.equal(r.code, 1, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=PASS data=PASS stale=FAIL');
  assert.match(r.out, /^ {3}FAIL {2}stale:/m);
});

test('an old file against a fresh origin is a clone that needs pulling: NOT CHECKED (exit 2), never FAIL', function () {
  var r = run(null, OLD, FRESH);
  assert.equal(r.code, 2, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=PASS data=NOT_CHECKED stale=NOT_CHECKED');
});

test('an old file with origin unreadable is NOT CHECKED (exit 2), never a pass', function () {
  var r = run(null, OLD);
  assert.equal(r.code, 2, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=PASS data=NOT_CHECKED stale=NOT_CHECKED');
});

test('no wire.yml: the page is still checked, and a broken page is FAIL (exit 1), not hidden behind NOT CHECKED', function () {
  var ok = run(null, null);
  assert.equal(ok.code, 2, ok.out);
  assert.equal(ok.last, 'WIRE-VERDICT page=PASS data=NOT_CHECKED stale=NOT_CHECKED');
  var broken = run(edit('wire/vulns.xml', '{{ site.title | xml_escape }}: The Wire, nKEVs', '{{ site.title | strip }}: The Wire, nKEVs'), null);
  assert.equal(broken.code, 1, broken.out);
  assert.equal(broken.last, 'WIRE-VERDICT page=FAIL data=NOT_CHECKED stale=NOT_CHECKED');
});

test('a page file that is absent is NOT CHECKED (exit 2), never a pass', function () {
  var r = run(function (root) { fs.unlinkSync(path.join(root, 'wire', 'cves.xml')); });
  assert.equal(r.code, 2, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=NOT_CHECKED data=PASS stale=PASS');
});

test('a crash inside a check still ends with the verdict line, NOT CHECKED on every class (exit 2)', function () {
  var r = run(function (root) {
    var f = path.join(root, 'tools', 'report-tooling', 'lib', 'check-wire.js');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('function check(doc, sources, now, remote) {', 'function check(doc, sources, now, remote) { throw new Error("boom");'));
  });
  assert.equal(r.code, 2, r.out);
  assert.equal(r.last, 'WIRE-VERDICT page=NOT_CHECKED data=NOT_CHECKED stale=NOT_CHECKED');
});

/* M37, third half. `check-defang.js --site` without `--records` prints "records NOT GATED" and exits 0,
   so a local run reads PASS having skipped the search-record text. pages.yml passes --records, so CI is
   covered; a local run is not. The gate file belongs to another lane, so this expectation is recorded
   as a todo (it runs, and its failure is reported but does not fail the suite) until check-defang.js
   exits 2 in that case; remove `todo` when it does. */
test('check-defang --site without --records is NOT CHECKED (exit 2), not a pass', { todo: 'check-defang.js exits 0 with "records NOT GATED" (T-0603 M37, proposal)' }, function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-wirecli-site-'));
  try {
    fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html><html><head><title>Test page</title></head><body><main><p>Hello reader, nothing to flag here.</p></main></body></html>');
    var r = cp.spawnSync(process.execPath, ['check-defang.js', '--site', dir], { cwd: TOOLING, encoding: 'utf8' });
    assert.match(r.stdout, /records {5}NOT GATED/, 'the harness reached the records line: ' + r.stdout.slice(-300));
    assert.equal(r.status, 2, r.stdout.slice(-300));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
