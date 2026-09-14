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

/* --- the never-block bucket: 2026-09-13, closing the leak -------------------

   hunt_only_never_block is real intelligence that must never enter the
   ordinary, exportable row set. The three shapes below are all present in the
   live corpus (see returns/measure-leak.md and returns/surface-fix-plan.md
   from this run): the common reduced object, a group-level note with values
   nested in a sub-array and no `value` field on the object itself (the
   seasia-gov-exploitation-toolkit shape, and the one carrying api.telegram.org
   in production), and a value that also sits in an ordinary bucket, which the
   dedupe rule below must resolve toward safety. */

test('a never-block value is excluded from the ordinary rows entirely', function () {
  var r = X.summarise({ network_indicators: { domains: ['evil.test'] },
                        hunt_only_never_block: [{ value: 'api.telegram.org',
                                                  category: 'messaging platform',
                                                  context: 'Shared platform, do not block' }] });
  assert.deepEqual(values(r.rows), ['evil.test']);
  assert.deepEqual(values(r.neverBlockRows), ['api.telegram.org']);
});

test('a never-block value nested in a sub-array with no value field on its own object is still found', function () {
  // The seasia-gov-exploitation-toolkit shape: a group note plus a bare array
  // of domains, none of which carry their own { value } wrapper.
  var r = X.summarise({
    hunt_only_never_block: [{
      note: 'Shared public infrastructure, never block or ship as campaign IOCs',
      domains: ['gsocket.io', 'api.telegram.org', 'discord.com']
    }]
  });
  assert.deepEqual(values(r.rows), []);
  assert.deepEqual(values(r.neverBlockRows).sort(),
    ['api.telegram.org', 'discord.com', 'gsocket.io']);
  r.neverBlockRows.forEach(function (row) {
    assert.match(row.context, /never block/i);
  });
});

test('a value in BOTH an ordinary bucket and the never-block bucket resolves toward safety', function () {
  var r = X.summarise({
    network_indicators: { ipv4: ['172.237.149.231'] },
    hunt_only_never_block: [{ value: '172.237.149.231', category: 'shared TDS landing' }]
  });
  assert.deepEqual(values(r.rows), [], 'the ordinary row must be dropped, not duplicated');
  assert.deepEqual(values(r.neverBlockRows), ['172.237.149.231']);
});

test('the never-block reason preference order matches the approved list, false_positive_risk first', function () {
  var r = X.summarise({ hunt_only_never_block: [{
    value: '1.2.3.4', context: 'a weaker label', purpose: 'a middling label',
    false_positive_risk: 'the strongest label, chosen over the others'
  }] });
  assert.equal(r.neverBlockRows[0].context, 'the strongest label, chosen over the others');
});

test('a never-block reason is not truncated at the 90-char cap the ordinary role label uses', function () {
  var long = 'This reason is deliberately written to run past ninety characters so the ' +
    'cap that applies to an ordinary indicator label does not apply here.';
  assert.ok(long.length > 90);
  var r = X.summarise({ hunt_only_never_block: [{ value: '1.2.3.4', context: long }] });
  assert.equal(r.neverBlockRows[0].context, long);
});

test('a never-block value with no reason in any preferred field renders the explicit gap string', function () {
  var r = X.summarise({ hunt_only_never_block: [{ value: '1.2.3.4', category: 'author-marked never-block' }] });
  assert.equal(r.neverBlockRows[0].context, 'No reason recorded in the feed');
});

test('the benign-value filter does not apply inside the never-block walk', function () {
  // github.com is in BENIGN_DOMAINS and would be suppressed entirely from the
  // ordinary walk. Inside hunt_only_never_block it must still render, with
  // its recorded reason, because the whole point of this section is to show
  // it, not filter it a second time through an unrelated mechanism.
  var r = X.summarise({ hunt_only_never_block: [{ value: 'github.com', category: 'vendor download' }] });
  assert.deepEqual(values(r.neverBlockRows), ['github.com']);
});

test('a feed with no hunt_only_never_block bucket yields an empty neverBlockRows, not an error', function () {
  var r = X.summarise({ network_indicators: ['1.2.3.4'] });
  assert.deepEqual(r.neverBlockRows, []);
});
