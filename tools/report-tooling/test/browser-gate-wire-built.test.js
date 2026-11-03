'use strict';

/* T-0500.1.7.4 b3: tests for check-browser-wire.js in BUILT mode (HL_SITE_DIR / an http:// HL_SITE_BASE),
   the three-tab Wire, and the two pieces it adds: lib/wire-harness.js readBuilt() / expectedCount() and
   lib/page-server.js startDir().

   Most of these do not drive a browser. What they can prove is the part that decides what the gate
   examined: the facts it reads from the static markup, the server that hands the page to the browser, and
   that a gate which could not run says NOT CHECKED (exit 2) rather than passing. The one test that does
   launch a browser is opt-in like cdp-isolation-live.test.js (HL_CDP_LIVE_TESTS=1) and says NOT CHECKED
   when skipped; the full damaged-copy control for a real build is
   tasks/runs/T-0500.1.7.4/build/scripts/wire-gate-control.sh. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var http = require('node:http');
var childProcess = require('node:child_process');
var JSDOM = require('jsdom').JSDOM;
var WH = require('../lib/wire-harness.js');
var PS = require('../lib/page-server.js');
var CDP = require('../lib/cdp.js');

var GATE = path.join(__dirname, '..', 'check-browser-wire.js');

function row(cls, attrs, title) {
  return '<div class="' + cls + '" ' + attrs + '><a href="#">' + title + '</a></div>';
}

/* A three-tab page in the shape the template emits, small enough to count by hand:
   Headlines 4 rows over 2 days (3 news, 1 research; 2 tagged ransomware), nKEVs 2, CVEs 1. */
function wirePage(opts) {
  opts = opts || {};
  var headlines =
    '<div class="hl-wire__day" data-filter-group>Monday 2 November 2026</div>' +
    row('hl-wire__row', 'data-title="alpha ransomware gang" data-tags="ransomware|malware" data-kind="news" data-day="2026-11-02"', 'a') +
    row('hl-wire__row', 'data-title="beta" data-tags="malware" data-kind="research" data-day="2026-11-02"', 'b') +
    '<div class="hl-wire__day" data-filter-group>Sunday 1 November 2026</div>' +
    row('hl-wire__row', 'data-title="gamma" data-tags="ransomware" data-kind="news" data-day="' + (opts.badDay || '2026-11-01') + '"', 'c') +
    row('hl-wire__row', 'data-title="delta" data-tags="" data-kind="news" data-day="2026-11-01"', 'd');
  return '<html><body><div class="hl-wtabs"><nav class="hl-wtabs__nav">' +
    '<a class="hl-wtabs__tab hl-wtabs__tab--h" href="#headlines"><span class="hl-wtabs__t">Headlines</span><span class="hl-wtabs__n">4</span></a>' +
    '<a class="hl-wtabs__tab hl-wtabs__tab--v" href="#vulns"><span class="hl-wtabs__t">nKEVs</span><span class="hl-wtabs__n">2</span></a>' +
    '<a class="hl-wtabs__tab hl-wtabs__tab--c" href="#cves"><span class="hl-wtabs__t">CVEs</span><span class="hl-wtabs__n">1</span></a></nav>' +
    '<section id="headlines" class="hl-wtabs__sec"><div data-listing-filter>' +
    '<button class="hl-chip-btn is-on" data-tag="">All</button>' +
    '<button class="hl-chip-btn hl-chip-btn--topic" data-tag="ransomware">ransomware <span class="hl-chip-btn__n">2</span></button>' +
    '<button class="hl-chip-btn" data-kind="">All</button><button class="hl-chip-btn" data-kind="news">News <span class="hl-chip-btn__n">3</span></button></div>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__row">' + headlines + '</div></section>' +
    '<section id="' + (opts.vulnsId || 'vulns') + '" class="hl-wtabs__sec"><div data-listing-filter></div>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-vuln">' +
    '<div class="hl-wire__day" data-filter-group>Monday 2 November 2026 &middot; 2 added</div>' +
    row('hl-vuln', 'id="cve-cve-2026-1" data-title="cve-2026-1 v p" data-list="cisa" data-sev="critical" data-day="2026-11-02"', 'x') +
    row('hl-vuln', 'id="cve-cve-2026-2" data-title="cve-2026-2 v p" data-list="vconly" data-sev="high" data-day="2026-11-02"', 'y') +
    '</div></section>' +
    '<section id="cves" class="hl-wtabs__sec"><div data-listing-filter></div>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-vuln">' +
    '<div class="hl-wire__day" data-filter-group>Monday 2 November 2026 &middot; 1 published</div>' +
    row('hl-vuln', 'id="cves-cve-2026-3" data-title="cve-2026-3 v p" data-sig="msf" data-sev="critical" data-day="2026-11-02"', 'z') +
    '</div></section></div></body></html>';
}

test('readBuilt reads the tabs, rows, days and chips of a three-tab page', function () {
  var f = WH.readBuilt(JSDOM, wirePage());
  assert.deepEqual(f.problems, []);
  assert.deepEqual(f.tabs.map(function (t) { return t.id + ':' + t.label + ':' + t.count; }),
    ['headlines:Headlines:4', 'vulns:nKEVs:2', 'cves:CVEs:1']);
  assert.equal(f.sections.headlines.rows.length, 4);
  assert.equal(f.sections.vulns.rows.length, 2);
  assert.equal(f.sections.cves.rows.length, 1);
  assert.equal(f.sections.headlines.itemSel, '.hl-wire__row');
  assert.deepEqual(f.sections.headlines.days, ['2026-11-01', '2026-11-02']);
  assert.equal(f.sections.headlines.dayCounts['2026-11-02'], 2);
  var chip = f.sections.headlines.chips.filter(function (c) { return c.value === 'ransomware'; })[0];
  assert.equal(chip.axis, 'tag');
  assert.equal(chip.printed, 2);
  assert.equal(f.sections.vulns.rows[0].id, 'cve-cve-2026-1');
});

test('expectedCount follows the filter\'s own rule: chips OR within an axis, axes AND, search is a substring of title|tags', function () {
  var rows = WH.readBuilt(JSDOM, wirePage()).sections.headlines.rows;
  assert.equal(WH.expectedCount(rows, {}, ''), 4);
  assert.equal(WH.expectedCount(rows, { tag: ['ransomware'] }, ''), 2);
  assert.equal(WH.expectedCount(rows, { kind: ['news'] }, ''), 3);
  assert.equal(WH.expectedCount(rows, { tag: ['ransomware'], kind: ['news'] }, ''), 2);
  assert.equal(WH.expectedCount(rows, { tag: ['ransomware', 'malware'] }, ''), 3, 'chips in one axis OR together');
  assert.equal(WH.expectedCount(rows, {}, 'RANSOMWARE'), 2, 'a search term matches title or tags, any case');
  assert.equal(WH.expectedCount(rows, {}, 'zzz'), 0, 'a term that matches nothing leaves nothing: a zero is a result, not an error');
});

test('readBuilt names a tab whose target section is missing, and a row whose data-day disagrees with its heading', function () {
  var f = WH.readBuilt(JSDOM, wirePage({ vulnsId: 'vulns-x' }));
  assert.ok(f.problems.some(function (p) { return /nKEVs.*#vulns.*not a \.hl-wtabs__sec/.test(p); }), f.problems.join('; '));
  assert.equal(f.sections.vulns.present, false);
  assert.equal(f.sections.vulns.rows.length, 0, 'a missing section reads as zero rows; the gate FAILs it through the structure and the "every tab section holds rows" checks (their denominators are the 3 tabs), never through a zero-denominator FAIL');
  var g = WH.readBuilt(JSDOM, wirePage({ badDay: '2026-10-30' }));
  assert.equal(g.sections.headlines.disagreements.length, 1);
  assert.match(g.sections.headlines.disagreements[0], /2026-11-01 heading carries data-day="2026-10-30"/);
});

function get(origin, p) {
  return new Promise(function (resolve, reject) {
    http.get(origin + p, function (res) {
      var b = '';
      res.on('data', function (d) { b += d; });
      res.on('end', function () { resolve({ status: res.statusCode, type: res.headers['content-type'], body: b }); });
    }).on('error', reject);
  });
}

test('startDir serves a built directory as built: index.html for a directory, the right type, a 404 recorded for a miss', async function () {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-startdir-'));
  fs.mkdirSync(path.join(d, 'wire'));
  fs.writeFileSync(path.join(d, 'wire', 'index.html'), '<html>wire</html>');
  fs.writeFileSync(path.join(d, 'x.css'), 'a{}');
  var srv = await PS.startDir(d);
  try {
    var a = await get(srv.origin, '/wire/?q=1');
    assert.equal(a.status, 200);
    assert.equal(a.body, '<html>wire</html>');
    assert.match(a.type, /text\/html/);
    assert.match((await get(srv.origin, '/x.css')).type, /text\/css/);
    var m = await get(srv.origin, '/nope.js');
    assert.equal(m.status, 404);
    assert.deepEqual(srv.misses, ['/nope.js']);
  } finally { srv.close(); }
});

test('startDir never serves outside the directory, however the path is written', async function () {
  var parent = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-startdir-out-'));
  fs.writeFileSync(path.join(parent, 'secret.txt'), 'SECRET');
  var d = path.join(parent, 'site');
  fs.mkdirSync(d);
  fs.writeFileSync(path.join(d, 'ok.txt'), 'ok');
  var srv = await PS.startDir(d);
  try {
    assert.equal((await get(srv.origin, '/ok.txt')).body, 'ok');
    for (var p of ['/../secret.txt', '/%2e%2e/secret.txt', '/..%2fsecret.txt', '/%2e%2e%2fsecret.txt']) {
      var r = await get(srv.origin, p);
      assert.notEqual(r.body, 'SECRET', p + ' reached a file outside the site directory');
    }
  } finally { srv.close(); }
});

test('startDir rejects a path that is not a directory', async function () {
  await assert.rejects(PS.startDir('/definitely/not/a/dir'), /is not a directory/);
});

function runGate(env, args) {
  var e = {};
  Object.keys(process.env).forEach(function (k) { if (!/^HL_/.test(k)) e[k] = process.env[k]; });
  Object.keys(env).forEach(function (k) { e[k] = env[k]; });
  return childProcess.spawnSync(process.execPath, [GATE].concat(args || []), { env: e, encoding: 'utf8', timeout: 120000 });
}

test('GATE: an HL_SITE_DIR that is not a directory is NOT CHECKED (exit 2), never a pass', function () {
  var r = runGate({ HL_SITE_DIR: '/definitely/not/a/dir' });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stdout, /^NOT CHECKED/m);
  assert.match(r.stdout, /not a directory/);
});

test('GATE: an unreachable http:// HL_SITE_BASE is NOT CHECKED (exit 2) with the reason named', function () {
  var r = runGate({ HL_SITE_BASE: 'http://127.0.0.1:1' });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stdout, /^NOT CHECKED\s+could not fetch http:\/\/127\.0\.0\.1:1\/wire\//m);
});

test('GATE: with no browser the BUILT mode is NOT CHECKED (exit 2), not a pass and not a fail', function () {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-gate-nobrowser-'));
  fs.mkdirSync(path.join(d, 'wire'));
  fs.writeFileSync(path.join(d, 'wire', 'index.html'), wirePage());
  var r = runGate({ HL_SITE_DIR: d, HL_CHROME: '/definitely/not/a/browser' });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stdout, /^NOT CHECKED/m);
  assert.match(r.stdout, /HL_CHROME points at/);
});

var LIVE = process.env.HL_CDP_LIVE_TESTS === '1';
var SKIP = LIVE ? false : 'NOT CHECKED: set HL_CDP_LIVE_TESTS=1 to launch the real browser';

test('GATE (real browser): a three-tab page with no scripts and no stylesheet cannot pass, and says why (exit 1)', { skip: SKIP }, function (t) {
  var found = CDP.findBrowser();
  if (!found.path) { t.skip('NOT CHECKED: ' + found.error); return; }
  var d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-gate-bare-'));
  fs.mkdirSync(path.join(d, 'wire'));
  fs.writeFileSync(path.join(d, 'wire', 'index.html'), wirePage());
  var r = runGate({ HL_SITE_DIR: d });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /^FAIL\s+\/wire\/ in a real browser, BUILT mode/m);
  assert.match(r.stdout, /FAIL\s+the filter modules started/);
  assert.doesNotMatch(r.stdout, /^PASS\s+\/wire\//m);
  assert.match(r.stdout, /\[n=\d+ /, 'every check prints its denominator');
});
