'use strict';

/* The lookup's credibility is spent on its first false positive.

   Every value pinned here was measured in a real published feed on 2026-08-19
   and every one is a true statement about the malware: Arsenal-237 really did
   contact 8.8.8.8, and the GHOST cryptojacker really does masquerade its
   Hysteria v2 SNI as bing.com. They are still useless to match a defender's
   logs against, because essentially every network contains all of them, and a
   reader who pastes proxy logs and gets four meaningless hits stops trusting
   the page. */

var test = require('node:test');
var assert = require('node:assert');
var B = require('../lib/benign.js');

test('the four measured offenders are suppressed', function () {
  assert.equal(B.isBenign('ipv4', '8.8.8.8'), true, 'Arsenal-237 feed');
  assert.equal(B.isBenign('ipv4', '127.0.0.1'), true, 'two feeds');
  assert.equal(B.isBenign('domain', 'github.com'), true, 'SE-Asia toolkit feed');
  assert.equal(B.isBenign('domain', 'bing.com'), true, 'GHOST SNI masquerade');
});

test('reserved and private ranges are suppressed by rule, not by list', function () {
  ['10.1.2.3', '192.168.1.50', '172.16.0.9', '172.31.255.1', '127.5.5.5',
   '169.254.1.1', '0.0.0.0', '224.0.0.1', '255.255.255.255'].forEach(function (ip) {
    assert.equal(B.isBenign('ipv4', ip), true, ip + ' should be suppressed');
  });
});

test('a routable attacker IP is NOT suppressed', function () {
  ['185.38.150.7', '77.110.96.200', '149.28.112.221', '172.15.0.1', '11.0.0.1']
    .forEach(function (ip) {
      assert.equal(B.isBenign('ipv4', ip), false, ip + ' must stay indexed');
    });
});

test('a subdomain of a benign platform is equally signal-free', function () {
  assert.equal(B.isBenign('domain', 'raw.githubusercontent.com'), true);
  assert.equal(B.isBenign('domain', 'foo.bar.google.com'), true);
});

test('a lookalike domain is NOT suppressed', function () {
  // The whole point of a lookalike is that it is not the real thing.
  assert.equal(B.isBenign('domain', 'github.com.evil.tld'), false);
  assert.equal(B.isBenign('domain', 'g00gle.com'), false);
  assert.equal(B.isBenign('domain', 'notgithub.com'), false);
});

test('a url on a benign host is suppressed, on a hostile host is not', function () {
  assert.equal(B.isBenign('url', 'https://raw.githubusercontent.com/x/y'), true);
  assert.equal(B.isBenign('url', 'http://8.8.8.8/a'), true);
  assert.equal(B.isBenign('url', 'http://185.38.150.7/bins/x'), false);
});

test('hashes and emails are never suppressed, being specific by construction', function () {
  assert.equal(B.isBenign('sha256', 'a'.repeat(64)), false);
  assert.equal(B.isBenign('email', 'anyone@google.com'), false);
});

/* --- filename suppression ------------------------------------------------

   Added 2026-08-19. Before `filename` existed as a type, 222 of 1,670 indexed
   values were filenames the classifier had called domains, chrome.exe,
   MsMpEng.exe, csfalconservice.exe and svchost.exe among them. A defender
   pasting a process list got hits that meant nothing. */

test('a Windows binary carries no signal as a bare filename', function () {
  assert.equal(B.isBenign('filename', 'svchost.exe'), true);
  assert.equal(B.isBenign('filename', 'lsass.exe'), true);
  assert.equal(B.isBenign('filename', 'explorer.exe'), true);
});

test('a mainstream security agent carries no signal either', function () {
  assert.equal(B.isBenign('filename', 'msmpeng.exe'), true);
  assert.equal(B.isBenign('filename', 'csfalconservice.exe'), true);
  assert.equal(B.isBenign('filename', 'sentinelagent.exe'), true);
});

test('a browser is suppressed, being on every desktop estate', function () {
  assert.equal(B.isBenign('filename', 'chrome.exe'), true);
  assert.equal(B.isBenign('filename', 'msedge.exe'), true);
});

test('A GENERIC-LOOKING NAME THAT SHIPS WITH NOTHING STAYS INDEXED', function () {
  // The line is "does its presence carry signal", not "does it look distinctive".
  // Nothing ships agent.exe or payload.exe, so a hit is worth a look.
  assert.equal(B.isBenign('filename', 'agent.exe'), false);
  assert.equal(B.isBenign('filename', 'windefendersvc.exe'), false);
  assert.equal(B.isBenign('filename', 'xmrig.exe'), false);
  assert.equal(B.isBenign('filename', 'mimikatz.exe'), false);
});

test('suppression is exact, so a lookalike is not swept up with it', function () {
  assert.equal(B.isBenign('filename', 'chrome.exe.bak'), false);
  assert.equal(B.isBenign('filename', 'notchrome.exe'), false);
});

test('the filename list is lowercase throughout, matching classifier output', function () {
  B.BENIGN_FILENAMES.forEach(function (f) {
    assert.equal(f, f.toLowerCase(), f + ' is not lowercase');
  });
});
