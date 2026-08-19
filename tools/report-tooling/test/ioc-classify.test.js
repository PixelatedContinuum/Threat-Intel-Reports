'use strict';

/* Tests for the shared classifier.

   Every case here comes from a real value measured in the 57 published feeds on
   2026-08-19, not invented. The rejections matter as much as the matches: these
   strings sit in the same JSON lists as real indicators, so a classifier that
   typed by bucket name instead of by value pattern would index remediation
   advice and ATT&CK IDs as if they were indicators. */

var test = require('node:test');
var assert = require('node:assert');
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
