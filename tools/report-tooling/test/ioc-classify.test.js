'use strict';

/* Tests for the shared classifier.

   Every case here comes from a real value measured in the 57 published feeds on
   2026-08-19, not invented. The rejections matter as much as the matches: these
   strings sit in the same JSON lists as real indicators, so a classifier that
   typed by bucket name instead of by value pattern would index remediation
   advice and ATT&CK IDs as if they were indicators. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var C = require('../../../assets/js/ioc-classify.js');

function t(v) { var r = C.classify(v); return r && r.type; }
function v(x) { var r = C.classify(x); return r && r.value; }

test('hashes type by length and never as domains', function () {
  var sha256 = 'f7c4710fd67b0d4639e401180f44324c8c1b74ffe417897650593952abcdef12';
  assert.equal(t(sha256), 'sha256');
  assert.equal(t('a'.repeat(40)), 'sha1');
  assert.equal(t('a'.repeat(32)), 'md5');
  assert.equal(t('a'.repeat(31)), null, '31 hex chars is not a hash');
});

test('hashes fold to lowercase so case never blocks a match', function () {
  assert.equal(v('A'.repeat(64)), 'a'.repeat(64));
});

test('an ipv4 with a port yields the bare ip', function () {
  // Measured: the Infrastructure bucket carries "185.38.150.7:9999".
  assert.equal(t('185.38.150.7:9999'), 'ipv4');
  assert.equal(v('185.38.150.7:9999'), '185.38.150.7');
});

test('an octet out of range is not an ip', function () {
  assert.equal(t('999.1.1.1'), null);
  assert.equal(t('256.0.0.1'), null);
});

test('domains fold to lowercase and drop a trailing dot', function () {
  assert.equal(t('bot.gribostress.pro'), 'domain');
  assert.equal(v('Bot.GriboStress.PRO'), 'bot.gribostress.pro');
  assert.equal(v('example.com.'), 'example.com');
});

test('defanged values refang', function () {
  assert.equal(v('evil[.]com'), 'evil.com');
  assert.equal(t('hxxp://evil.com/a'), 'url');
  assert.equal(v('hxxps://evil[.]com/a'), 'https://evil.com/a');
});

test('urls keep their path case but lowercase the host', function () {
  assert.equal(v('https://Evil.COM/PathCase'), 'https://evil.com/PathCase');
});

test('emails type as email, not as domain', function () {
  assert.equal(t('operator@evil.com'), 'email');
});

test('non-indicators that live in the same lists are rejected', function () {
  // All measured in real feeds.
  assert.equal(t('/apply.cgi'), null);
  assert.equal(t('/boaform/admin/formLogin'), null);
  assert.equal(t('T1082 - System Information Discovery'), null);
  assert.equal(t('Isolate infected systems from the network'), null);
  assert.equal(t('Complete disk wipe and clean OS reinstall'), null);
  assert.equal(t(''), null);
  assert.equal(t(null), null);
});

test('a bare TLD or single label is not a domain', function () {
  assert.equal(t('localhost'), null);
  assert.equal(t('.com'), null);
});

test('extract pulls indicators out of pasted free text', function () {
  var text = 'Aug 19 10:02:11 fw DROP SRC=185.38.150.7 DST=10.0.0.5 ' +
             'url="https://evil.com/a" sha256=' + 'b'.repeat(64) + ', host bot.gribostress.pro.';
  var got = C.extract(text).map(function (x) { return x.type + ':' + x.value; });
  assert.ok(got.indexOf('ipv4:185.38.150.7') > -1, 'ip from a log line');
  assert.ok(got.indexOf('url:https://evil.com/a') > -1, 'url inside quotes');
  assert.ok(got.indexOf('sha256:' + 'b'.repeat(64)) > -1, 'hash after an = sign');
  assert.ok(got.indexOf('domain:bot.gribostress.pro') > -1, 'host with a trailing full stop');
});

test('extract deduplicates and preserves first-seen order', function () {
  var got = C.extract('1.2.3.4 then 1.2.3.4 again then 5.6.7.8');
  assert.deepEqual(got.map(function (x) { return x.value; }), ['1.2.3.4', '5.6.7.8']);
});

test('extract on empty or junk input returns an empty array', function () {
  assert.deepEqual(C.extract(''), []);
  assert.deepEqual(C.extract('the quick brown fox'), []);
});

test('template and redaction placeholders are rejected', function () {
  // Both measured in real feeds, and both were found by the round-trip test
  // rather than by inspection.
  assert.equal(t('http://87.106.143.220:443/bins/Naku.{arch}'), null,
    'a build template is not a concrete indicator');
  assert.equal(t('https://[victim-subdomain].ocpinstana.[victim-domain].com.tr'), null,
    'a REDACTED victim url must never be indexed');
  assert.equal(t('evil.com<script>'), null);
});

test('a defanged paste survives tokenising, which is the common case', function () {
  // Brackets are token delimiters, so refanging has to happen BEFORE the split
  // or "bot[.]example[.]com" is shredded into three useless fragments. This is
  // the single most likely format a defender copies out of a threat report.
  var got = C.extract('beacon to bot[.]example[.]com and hxxp://evil[.]test/a').map(
    function (x) { return x.type + ':' + x.value; });
  assert.ok(got.indexOf('domain:bot.example.com') > -1, 'defanged domain');
  assert.ok(got.indexOf('url:http://evil.test/a') > -1, 'defanged url');
});

test('a parenthesised defang also survives', function () {
  var got = C.extract('contacted evil(.)test').map(function (x) { return x.value; });
  assert.ok(got.indexOf('evil.test') > -1);
});

/* --- the filename type ---------------------------------------------------

   Added 2026-08-19 after measuring the live index: 222 of 1,670 indexed values
   were filenames typed as `domain`, because `payload.dll` satisfies the domain
   grammar exactly as `example.co` does. Among them were chrome.exe, brave.exe,
   msedge.exe, MsMpEng.exe, csfalconservice.exe and csagent.exe, all present on
   ordinary Windows estates. Anyone pasting a process list or an EDR export into
   the public search box was told their environment matched an investigation.

   They are in the feeds for a real reason (the rootkit terminates them), so the
   fix is not to remove them from the feeds. It is to stop calling a filename a
   domain, and to suppress the ubiquitous ones from the index the way 8.8.8.8 is
   already suppressed.

   The extension list deliberately EXCLUDES anything that is also a real TLD:
   .com, .sh, .py and .so all resolve as domains and must keep doing so. A
   filename mistyped as a domain is a display nit; a domain mistyped as a
   filename would stop a real indicator matching, so the ambiguity is resolved
   in the safe direction and recorded. */

test('a filename is typed as a filename, not as a domain', function () {
  assert.deepEqual(C.classify('payload.dll'), { type: 'filename', value: 'payload.dll' });
  assert.deepEqual(C.classify('WinDefenderSvc.exe'),
    { type: 'filename', value: 'windefendersvc.exe' });
  assert.equal(C.classify('bdapiutil64.sys').type, 'filename');
});

test('AN EXTENSION THAT IS ALSO A TLD STAYS A DOMAIN', function () {
  // The safe direction. Losing a real domain match costs more than mislabelling
  // a shell script, and nothing in a bare token separates the two.
  assert.equal(C.classify('tool.com').type, 'domain');
  assert.equal(C.classify('evil.sh').type, 'domain');
  assert.equal(C.classify('grab.py').type, 'domain');
  assert.equal(C.classify('lib.so').type, 'domain');
});

test('a real domain is unaffected by the filename rule', function () {
  assert.equal(C.classify('bot.example.com').type, 'domain');
  assert.equal(C.classify('cdn.evil.test').type, 'domain');
  assert.equal(C.classify('example.co').type, 'domain');
});

test('a path is not a filename, since it carries no bare-token shape', function () {
  assert.equal(C.classify('C:\\Windows\\Temp\\x.exe'), null);
  assert.equal(C.classify('%TEMP%\\svchost_upd.exe'), null);
});

test('filename is listed in TYPES, so consumers can enumerate it', function () {
  assert.ok(C.TYPES.indexOf('filename') > -1);
});

/* --- the filename extension list, checked against IANA -------------------

   The list is hand-curated and must stay that way: it is loaded in the browser,
   so shipping 1,439 TLDs to every reader to decide whether `payload.dll` is a
   file would be absurd. What CAN be automated is the safety property, and this
   is the one that matters. Every entry must NOT be a real TLD, or the classifier
   starts calling live domains filenames and a real indicator stops matching.

   `tools/report-tooling/data/iana-tlds.txt` is a dated snapshot of
   https://data.iana.org/TLD/tlds-alpha-by-domain.txt. Refresh it when adding an
   extension. It caught .ps (Palestine) in the candidate list, which recall alone
   had waved through.

   The deliberate exclusions are asserted too, so nobody "helpfully" adds them
   back: .sh, .py, .so, .md, .pl, .rs, .zip and .mov are all live TLDs, and
   `shinyhunte.rs` in the corpus is a real domain hack rather than a Rust file. */

var TLD_FILE = path.join(__dirname, '..', 'data', 'iana-tlds.txt');

function ianaTlds() {
  if (!fs.existsSync(TLD_FILE)) return null;
  var out = {};
  fs.readFileSync(TLD_FILE, 'utf8').split(String.fromCharCode(10)).forEach(function (l) {
    l = l.trim().toLowerCase();
    if (l && l.charAt(0) !== '#') out[l] = true;
  });
  return Object.keys(out).length ? out : null;
}

function declaredExtensions() {
  var src = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', 'assets', 'js', 'ioc-classify.js'), 'utf8');
  var m = /RX_FILENAME\s*=\s*\/\^[^(]*\(([^)]+)\)/.exec(src);
  assert.ok(m, 'could not read the extension list out of ioc-classify.js');
  return m[1].split('|');
}

test('NO FILENAME EXTENSION IS ALSO A REAL TLD', function () {
  var tlds = ianaTlds();
  if (!tlds) {
    assert.fail('NOT CHECKED: ' + TLD_FILE + ' is missing, so this run verified ' +
      'nothing about TLD collisions. Refresh it from data.iana.org.');
  }
  var collisions = declaredExtensions().filter(function (e) { return tlds[e]; });
  assert.deepEqual(collisions, [],
    'these extensions are live TLDs and will steal real domains: ' + collisions.join(', '));
});

test('the extensions that ARE tlds stay excluded, and stay resolving as domains', function () {
  var tlds = ianaTlds();
  assert.ok(tlds, 'the IANA snapshot is required for this case');
  ['sh', 'py', 'so', 'md', 'pl', 'rs', 'zip', 'mov', 'ps'].forEach(function (e) {
    assert.ok(tlds[e], '.' + e + ' is no longer a TLD; the exclusion may be revisitable');
    assert.equal(C.classify('thing.' + e).type, 'domain',
      'thing.' + e + ' must stay a domain, .' + e + ' is a live TLD');
  });
});

test('the widened list types what the corpus actually carries', function () {
  // Every one of these was sitting in the live index typed as a domain.
  [['svhost.js', 'filename'], ['miss.asp', 'filename'], ['rclone.php', 'filename'],
   ['dolap.rar', 'filename'], ['carriers.tmp', 'filename'], ['boatnet.arm', 'filename'],
   ['boatnet.mips', 'filename'], ['readme.txt', 'filename'], ['price6.doc', 'filename'],
   ['config.json', 'filename'], ['favicon.svg', 'filename']].forEach(function (pair) {
    assert.equal(C.classify(pair[0]).type, pair[1], pair[0]);
  });
});

test('and leaves every real domain in the corpus alone', function () {
  ['pastebin.com', 'ip-api.com', 'stolotov.net', 'evilsoul.xyz', 'hopto.org',
   'shinyhunte.rs', 'openclaw.ai', 'ifconfig.me', 'gsocket.io', 'antipublic.one',
   'webhook.site', 'systemtools.dev'].forEach(function (d) {
    assert.equal(C.classify(d).type, 'domain', d);
  });
});

/* ---- fix-r1 (review finding 1): the display defang that ioc-search.js uses for every value and title it writes ---- */
test('defangValue: a network value by type, in the site forms; any other type as it is; idempotent', () => {
  assert.equal(C.defangValue('203.0.113.9', 'ipv4'), '203[.]0[.]113[.]9');
  assert.equal(C.defangValue('203.0.113.9:8080', 'ipv4'), '203[.]0[.]113[.]9:8080');
  assert.equal(C.defangValue('evil.example.org', 'domain'), 'evil[.]example[.]org');
  assert.equal(C.defangValue('http://a.example.com/x?u=https://b.example.net/', 'url'), 'hxxp://a[.]example[.]com/x?u=hxxps://b[.]example[.]net/');
  assert.equal(C.defangValue('op@evil.example.org', 'email'), 'op[@]evil[.]example[.]org');
  assert.equal(C.defangValue('a'.repeat(64), 'sha256'), 'a'.repeat(64));
  assert.equal(C.defangValue('install.sh', 'filename'), 'install.sh');
  ['203.0.113.9|ipv4', 'https://evil.example.org/a.php|url', 'op@evil.example.org|email', 'evil.example.org|domain'].forEach((x) => {
    const [v, t] = x.split('|'); const once = C.defangValue(v, t);
    assert.equal(C.defangValue(once, t), once, 'idempotent: ' + t);
  });
});
test('defangText: addresses, URLs, hosts and e-mail inside a title are defanged; ordinary words and file names are not', () => {
  const cases = [
    ['BellaMain Turkish PhaaS Panel (79.137.192.3)', 'BellaMain Turkish PhaaS Panel (79[.]137[.]192[.]3)'],
    ['Open Directory at 193.56.255.154 - XiebroC2 v3.1 & Covenant C2', 'Open Directory at 193[.]56[.]255[.]154 - XiebroC2 v3.1 & Covenant C2'],
    ['Toolkit-193.233.202.17-Repository', 'Toolkit-193[.]233[.]202[.]17-Repository'],
    ['see https://evil.example.com/a/b.php, and evil.example.net/x; mail op@evil.example.org.', 'see hxxps://evil[.]example[.]com/a/b[.]php, and evil[.]example[.]net/x; mail op[@]evil[.]example[.]org.'],
    ['PULSAR RAT (server.exe) Technical Analysis', 'PULSAR RAT (server.exe) Technical Analysis'],
    ['Node.js v1.2.3 and 300.1.1.1', 'Node.js v1.2.3 and 300.1.1.1'],
    ['Hybrid Loader/Stealer Ecosystem', 'Hybrid Loader/Stealer Ecosystem'],
    ['already 79[.]137[.]192[.]3 and hxxps://x[.]example[.]com/p', 'already 79[.]137[.]192[.]3 and hxxps://x[.]example[.]com/p']
  ];
  cases.forEach(([i, o]) => { assert.equal(C.defangText(i), o); assert.equal(C.defangText(o), o, 'idempotent: ' + o); });
  assert.equal(C.defangText(null), '');
});

/* ---- fix-r2, review finding S3: the display defang covers IPv6 ---- */
test('S3: defangValue defangs a bare or bracketed IPv6 value and is idempotent; defangText defangs an address in a title but not a time, a MAC or std::string', function () {
  var C = require('../../../assets/js/ioc-classify.js');
  assert.strictEqual(C.defangValue('2001:db8::7', 'ipv6'), '2001[:]db8[:][:]7');
  assert.strictEqual(C.defangValue('2001[:]db8[:][:]7', 'ipv6'), '2001[:]db8[:][:]7');
  assert.strictEqual(C.defangValue('[2001:db8::7]:443', 'endpoint'), '[2001[:]db8[:][:]7]:443');
  assert.strictEqual(C.defangValue('http://[2001:db8::7]/p', 'url'), 'hxxp://[2001[:]db8[:][:]7]/p');
  assert.strictEqual(C.defangValue('pool.evil.test:10032', 'endpoint'), 'pool[.]evil[.]test:10032', 'control: a port colon is kept');
  assert.strictEqual(C.defangText('Beacon to 2001:db8::7, then 2001:db8:: and 2001:db8:1:2:3:4:5:6.'), 'Beacon to 2001[:]db8[:][:]7, then 2001[:]db8[:][:] and 2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6.');
  assert.strictEqual(C.defangText('at 12:30:45 mac aa:bb:cc:dd:ee:ff std::string'), 'at 12:30:45 mac aa:bb:cc:dd:ee:ff std::string', 'control: not addresses');
});
