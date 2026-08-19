'use strict';

/* Per-feed extraction for the IOC feed viewer.

   The measurement that produced this module: a table built on ioc-classify.js alone
   would have omitted roughly 730 genuine host indicators, because that classifier
   recognises seven atomic types and every one of them is network or file-hash. 348
   filenames, 210 Windows paths, 110 unix paths and 63 registry keys sit in the feeds
   with no way for a reader to know they were dropped.

   So this module is STRICTLY ADDITIVE. It delegates to ioc-classify.js for the seven
   atomic types and adds path, registry and filename on top. That matters because
   ioc-classify.js also governs the public search index and its embargo gate; a second
   implementation of an existing rule would drift silently, whereas adding new types
   on top of a delegated call cannot.

   The agreement test below is the one that pins that property. */

var test = require('node:test');
var assert = require('node:assert');
var X = require('../lib/ioc-table-extract.js');
var C = require('../../../assets/js/ioc-classify.js');

function types(rows) { return rows.map(function (r) { return r.type; }); }
function values(rows) { return rows.map(function (r) { return r.value; }); }

test('atomic types are delegated, not reimplemented', function () {
  var rows = X.extract({ network_indicators: ['185.49.126.140', 'evil.test'],
                         file_hashes: { sha256: ['a'.repeat(64)] } });
  assert.deepEqual(types(rows).sort(), ['domain', 'ipv4', 'sha256']);
});

test('EVERY VALUE ioc-classify CLAIMS IS TYPED IDENTICALLY HERE', function () {
  // The anti-drift property. If this ever fails, the extractor has started
  // second-guessing the shared classifier and the search index will disagree
  // with the table about what an indicator is.
  // Deliberately no public resolver here: those are benign-suppressed by design,
  // so they yield zero rows and would fail this test for the right reason.
  var probes = ['185.49.126.140', 'sub.evil.test', 'https://evil.test/a?b=1',
                'b'.repeat(64), 'c'.repeat(40), 'd'.repeat(32), 'a@b.test',
                'HKLM\\SYSTEM\\Foo', '%TEMP%\\x.exe', '/etc/passwd', 'agent.exe'];
  probes.forEach(function (p) {
    var atomic = C.classify(p);
    if (!atomic) return;               // host-typed or untyped, not this test's business
    var rows = X.extract({ x: [p] });
    assert.equal(rows.length, 1, 'expected one row for ' + p);
    assert.equal(rows[0].type, atomic.type, p + ' typed as ' + rows[0].type);
    assert.equal(rows[0].value, atomic.value, p + ' normalised differently');
  });
});

test('a registry key is typed by its prefix, whatever field it sits in', function () {
  var rows = X.extract({ persistence: [{ service_key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Bprotect' },
                                        { key: 'HKCU\\Software\\Foo' }] });
  assert.deepEqual(types(rows), ['registry', 'registry']);
});

test('a Windows path is typed by drive letter, environment variable or UNC', function () {
  var rows = X.extract({ h: ['C:\\Windows\\Temp\\x.exe',
                             '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WinDefenderSvc.exe',
                             '\\\\host\\share\\x.dll'] });
  assert.deepEqual(types(rows), ['path', 'path', 'path']);
});

test('a unix path is typed from a known system root only', function () {
  var rows = X.extract({ h: ['/etc/ld.so.preload', '/tmp/.hy2_x', '/nonsense/whatever'] });
  assert.deepEqual(types(rows), ['path', 'path']);
});

test('a bare filename with an executable extension is typed', function () {
  var rows = X.extract({ f: ['agent_xworm.exe', 'payload.dll', 'run.ps1'] });
  assert.deepEqual(types(rows), ['filename', 'filename', 'filename']);
});

test('A SINGLE TOKEN IS NEVER TYPED, because curl and wget live there', function () {
  // 1283 values fall in this shape. boatnet.x86 and main_mpsl are real payload
  // names; curl and wget are commands. Nothing separates them by pattern, so the
  // whole bucket is left to the raw JSON and counted as not typed.
  var rows = X.extract({ Commands: ['curl', 'wget', 'adj_time_year'],
                         Payloads: ['main_mpsl'] });
  assert.deepEqual(rows, []);
});

test('long hex is never typed, so a jarm and a decoded blob are not confused', function () {
  var rows = X.extract({ v: ['2ad2ad0002ad2ad00042d42d00000000f78d2dc0ce6e5bbc5b8149a4872356',
                             '1441591352927326259'] });
  assert.deepEqual(rows, []);
});

test('prose is never typed, however indicator-shaped a sentence looks', function () {
  var rows = X.extract({ n: [{ context: 'Dropped by the loader into the Startup folder',
                               confidence: 'HIGH' }] });
  assert.deepEqual(rows, []);
});

test('values are deduplicated within a feed, keeping the first context', function () {
  var rows = X.extract({ a: [{ value: '1.2.3.4', context: 'C2 server' }],
                         b: [{ value: '1.2.3.4', context: 'later mention' }] });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].context, 'C2 server');
});

test('context is carried when present and null when not', function () {
  var rows = X.extract({ a: [{ value: '5.6.7.8', context: 'staging host' }, '9.9.9.9'] });
  var byVal = {};
  rows.forEach(function (r) { byVal[r.value] = r.context; });
  assert.equal(byVal['5.6.7.8'], 'staging host');
  assert.equal(byVal['9.9.9.9'], null);
});

test('signal-free values are suppressed exactly as the search index suppresses them', function () {
  // 8.8.8.8 and friends are in real feeds. The table must not cry wolf either.
  var rows = X.extract({ n: ['8.8.8.8', '127.0.0.1', '185.49.126.140'] });
  assert.deepEqual(values(rows), ['185.49.126.140']);
});

test('THE NOT-TYPED COUNT IS REPORTED, so an omission cannot look like completeness', function () {
  var r = X.summarise({ Commands: ['curl', 'wget'], n: ['185.49.126.140'] });
  assert.equal(r.rows.length, 1);
  assert.ok(r.untyped >= 2, 'expected the two commands counted as not typed, got ' + r.untyped);
});

test('an empty feed yields no rows and says nothing was typed', function () {
  var r = X.summarise({});
  assert.deepEqual(r.rows, []);
  assert.equal(r.untyped, 0);
});

test('rows sort by type then value, so a page diff is stable across runs', function () {
  var a = X.extract({ n: ['evil.test', '1.2.3.4', 'aaa.test'] });
  var b = X.extract({ n: ['aaa.test', 'evil.test', '1.2.3.4'] });
  assert.deepEqual(a, b);
});
