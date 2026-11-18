'use strict';
/* T-0500.1.7.5 P1: a bare IPv6 address in page text is IPV6, not only a literal in a URL (IPV6-URL). The site include
   (_includes/defang-text.html) and assets/js/ioc-classify.js defang an address in text today; before this the static gate passed a page
   that leaked one (control: tasks/runs/T-0500.1.7.5/control-before.log, where the unchanged gate PASSed a page carrying
   `2a01:4f8:c17:1234::1` and `2001:db8:1:2:3:4:5:6`).

   THE SHAPE, the same one the render applies, so a page the lint flags is a page the include can defang: hex groups of 1 to 4 digits,
   2 to 7 colons, no `:::`, at most one `::`, either a `::` or all seven colons written out, no dot, at least one decimal digit. The
   false-positive list below is the other half of the rule: a clock time, a MAC address, a C++/Rust path, a Windows path, an ATT&CK id, a
   hash, a ratio, a bare `::`, a Python slice, and `ip:port` must all stay clean.

   Fixture addresses are documentation ranges (RFC 5737, RFC 3849); the one shape the brief names (`2a01:4f8:c17:1234::1`) is used in the
   table-cell case so the fixture matches the report's own example. Nothing here contacts anything. */
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');
var L = require('../check-defang.js');

var allow = L.makeAllow([]);
function scan(md) { var st = L.newStats(); var f = L.scanFile(md, 't.md', allow, st); return { f: f, st: st }; }
function kinds(r) { return r.f.map(function (x) { return x.kind; }).sort(); }
function line(s) { return L.scanLine(s, allow); }
function tokens(s) { return line(s).flagged.map(function (x) { return x.kind + ' ' + x.token; }); }

test('self-test: the known positives, bare IPv6 and partly defanged IPv6 among them, and their clean twins', function () {
  assert.deepStrictEqual(L.selfTest(), []);
});

test('known positives: a bare IPv6 in a sentence, a table cell and inline code is IPV6, full form and compressed', function () {
  assert.deepStrictEqual(tokens('the staging host answered on 2001:db8:c17:1234::1 overnight.'), ['IPV6 2001[:]db8[:]c17[:]1234[:][:]1']);
  // the brief's own example, in a table cell: the shape a report prints
  var r = scan('# t\n\n| IOC | Note |\n|---|---|\n| 2a01:4f8:c17:1234::1 | relay |\n');
  assert.deepStrictEqual(kinds(r), ['IPV6']);
  assert.strictEqual(r.f[0].token, '2a01[:]4f8[:]c17[:]1234[:][:]1', 'the finding is printed in the canonical [:] form, never copy-ready');
  assert.strictEqual(r.f[0].line, 5);
  assert.deepStrictEqual(tokens('full form 2001:db8:1:2:3:4:5:6 here'), ['IPV6 2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6']);
  assert.deepStrictEqual(tokens('a trailing prefix form 2001:db8::/64 and a bare 2001:db8::'), ['IPV6 2001[:]db8[:][:]', 'IPV6 2001[:]db8[:][:]']);
  assert.deepStrictEqual(tokens('`2001:db8::7` in inline code'), ['IPV6 2001[:]db8[:][:]7']);
  assert.deepStrictEqual(tokens('two of them: 2001:db8::1, and 2001:db8::2.'), ['IPV6 2001[:]db8[:][:]1', 'IPV6 2001[:]db8[:][:]2']);
});

test('a bracketed literal in text is IPV6 too, with its port or prefix; `[::2]` is a Python slice and is not', function () {
  assert.deepStrictEqual(tokens('the endpoint [2001:db8::7]:443 listens'), ['IPV6 [2001[:]db8[:][:]7]:443']);
  assert.deepStrictEqual(tokens('[2001:db8:c17::1]/64 is a prefix'), ['IPV6 [2001[:]db8[:]c17[:][:]1]/64']);
  assert.deepStrictEqual(tokens('slices x[::2], [::2] and a[1:2] are code'), []);
});

test('the defanged form is not flagged and is COUNTED; a raw colon beside a [:] is IPV6-PARTLY-DEFANGED', function () {
  var ok = scan('relay 2a01[:]4f8[:]c17[:]1234[:][:]1 answered\n');
  assert.deepStrictEqual(ok.f, []);
  assert.strictEqual(ok.st.matchedDefanged, 1, 'a defanged address is counted, never silently dropped');
  assert.deepStrictEqual(scan('endpoint [2001[:]db8[:][:]7]:443 fine\n').f, []);
  var partly = scan('cell 2001[:]db8:c17:1234::1 listed\n');
  assert.deepStrictEqual(kinds(partly), ['IPV6-PARTLY-DEFANGED']);
  assert.strictEqual(partly.f[0].token, '2001[:]db8:c17:1234::1', 'as found: the raw colon is the defect the author has to fix');
});

test('private and reserved IPv6 is not flagged, and is counted as private (the isPrivateIPv6 exclusions)', function () {
  var r = scan('loopback ::1, link-local fe80::1, unique-local fd00::1, multicast ff02::1, written out 0:0:0:0:0:0:0:1 and 0:0:0:0:0:0:0:0\n');
  assert.deepStrictEqual(r.f, []);
  assert.strictEqual(r.st.matchedPrivate, 6);
});

test('no false positive on the shapes that only look like an address', function () {
  [
    'the job ran at 10:01:30 and finished 12:30:45',                 /* clock time: two colons, no `::` */
    'NIC aa:bb:cc:dd:ee:ff and AA:BB:CC:DD:EE:FF',                  /* MAC: five colons */
    'std::vector and a::b and ab::cd and foo::bar',                 /* C++/Rust paths: no decimal digit */
    'C:\\Windows\\System32\\drivers\\etc\\hosts and D:\\data',      /* Windows drive paths: one colon */
    'T1055.001, TA0002 and M1036 are ATT&CK ids',                   /* ATT&CK ids: no colon */
    'sha256 ' + 'a'.repeat(64) + ' and md5 ' + 'b'.repeat(32),      /* hashes: no colon */
    'ratios 16:9, 1920:1080 and 3:2:1',                            /* ratios: no `::`, not seven colons */
    'a bare :: and a trailing x:: are not addresses',               /* `::` alone: no digit */
    'version 2026-11-18T10:27:15-05:00 is a timestamp',             /* an ISO timestamp */
    'GET /a HTTP/1.1 200 and a: b: c: d'                            /* log lines */
  ].forEach(function (s) { assert.deepStrictEqual(line(s).flagged, [], JSON.stringify(s)); });
  // `ip:port` on an IPv4: the IPv4 rule reads the address, this one must not add a second finding for the pair
  assert.deepStrictEqual(kinds(scan('host is 203.0.113.5:8080 and 198.51.100.4:22\n')), ['IPV4', 'IPV4']);
});

test('a fragment glued to a preceding character is not an address: the XOR strings in the real report table stay clean', function () {
  /* Found on the built site (tasks/runs/T-0500.1.7.5/site-run-before-fix.log): the reports/rovodev-mirai-matrix-c2-... page prints the
     XOR-0x54 encoded Mirai string `;::17 10t` in a table cell, and `::17` is a valid address by grammar. The page include leaves it raw
     for the same reason the gate now does: the address must be a whole word. This is a regression fixture for the one real-site false
     positive, not an allow-list entry. */
  [
    '| `;::17 10t` | `onnected` (sub-string "CONNECTED") | telnet-brute response check |',
    'x::17 and foo::17 and ;2001:db8::1 and =2001:db8::1 and |2001:db8::1|'
  ].forEach(function (s) { assert.deepStrictEqual(line(s).flagged, [], JSON.stringify(s)); });
  // the same address as a whole word, at the boundaries a page actually writes: space, bracket, quote, bold, and the start of a line
  ['the host 2001:db8::1 answered', '(2001:db8::1)', '"2001:db8::1"', '**2001:db8::1**', '[2001:db8::1]'].forEach(function (s) {
    assert.deepStrictEqual(line(s).flagged.map(function (f) { return f.kind; }), ['IPV6'], JSON.stringify(s));
  });
  assert.deepStrictEqual(line('2001:db8::1').flagged.map(function (f) { return f.kind; }), ['IPV6'], 'a line that starts with the address');
});

test('an IPv6 literal in a URL stays IPV6-URL: one finding, never a second IPV6', function () {
  assert.deepStrictEqual(kinds(scan('fetch http://[2001:db8::7]/payload now\n')), ['IPV6-URL']);
  assert.deepStrictEqual(kinds(scan('fetch hxxp://[2001:db8::7]/payload now\n')), ['IPV6-URL']);
  assert.deepStrictEqual(kinds(scan('socket ws://[2001:db8::7]:9001/ch\n')), ['IPV6-URL']);
  var r = scan('fetch http://[2001:db8::7]/payload now\n');
  assert.strictEqual(r.f.length, 1, 'one finding for the literal, not one for the URL and one for the text');
});

test('an IPv4-mapped address is DECIDED as IPv4, not IPv6: `::ffff:203.0.113.5` must not be counted twice', function () {
  /* The page include leaves a dotted tail to the IPv4 rule (it excludes any candidate holding a dot), so the gate does the same. The address
     is still caught: the IPv4 it carries is flagged, and its own fix (defang the quad) makes the line clean. */
  assert.deepStrictEqual(tokens('mapped ::ffff:203.0.113.5 here'), ['IPV4 203.0.113.5']);
  assert.deepStrictEqual(line('mapped ::ffff:203[.]0[.]113[.]5 here').flagged, []);
});

test('--site: a planted page with a bare IPv6 FAILs as IPV6, and its defanged twin passes (the site gate end to end)', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-v6-'));
  var gate = path.join(__dirname, '..', 'check-defang.js');
  function run(html) {
    fs.writeFileSync(path.join(dir, 'index.html'), '<!DOCTYPE html><html><body><main>' + html + '</main></body></html>');
    return cp.spawnSync(process.execPath, [gate, '--site', dir, '--all', '--pages-only'], { encoding: 'utf8' });
  }
  try {
    var bad = run('<p>the staging host answered on 2a01:4f8:c17:1234::1 overnight</p>');
    assert.strictEqual(bad.status, 1, bad.stdout);
    assert.match(bad.stdout, /FINDING .* IPV6 /);
    assert.doesNotMatch(bad.stdout, /2a01:4f8/, 'the raw address is never printed');
    var good = run('<p>the staging host answered on 2a01[:]4f8[:]c17[:]1234[:][:]1 overnight</p>');
    assert.strictEqual(good.status, 0, good.stdout);
    assert.match(good.stdout, /PASS /);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
