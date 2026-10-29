'use strict';

/* Fix round 1 controls: the rows the first review found lost, against the REAL
   corpus, plus the action rules the same review found wrong.

   Every test here names its subject and counts its denominator from the feeds
   themselves, so a feed growing does not silently turn a check into a no-op.

   The reviewer's list (tasks/runs/T-0500.1.6/review/haiku-review.result.json):
     assertion 3   179 of 283 hash-labelled filenames absent from the whole table
     assertion 7   45.130.148.125 (metadata.infrastructure.source_ip) lost
     assertion 8   9 BLOCK addresses with no bare row anywhere
     assertion 10  a 40-hex certificate SHA-1 typed sha256
     assertion 13  4 verb-led instructions over 40 characters dropped
     assertion 12  2 long actions carrying a commentary tail

   tls_certificates[].serial and .earlier_serial are deliberately NOT rows (a serial
   is not a file hash); the pilot test pins that. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');

var X = require('../lib/ioc-table-extract.js');

var ROOT = path.join(__dirname, '..', '..', '..');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');

function feed(name) {
  return JSON.parse(fs.readFileSync(path.join(FEED_DIR, name + '-iocs.json'), 'utf8'));
}

function summarise(name) {
  return X.summarise(feed(name));
}

function rowOf(rows, type, value) {
  return rows.filter(function (r) { return r.type === type && r.value === value; })[0];
}

test('every filename beside a hash keeps its own row, corpus-wide', function () {
  var files = fs.readdirSync(FEED_DIR).filter(function (f) { return /-iocs\.json$/.test(f); });
  var objects = 0, misses = [];
  files.forEach(function (f) {
    var doc = JSON.parse(fs.readFileSync(path.join(FEED_DIR, f), 'utf8'));
    var hashes = (doc.file_hashes && typeof doc.file_hashes === 'object') ? doc.file_hashes : {};
    var rows = X.summarise(doc).rows;
    Object.keys(hashes).forEach(function (algo) {
      if (!Array.isArray(hashes[algo])) return;
      hashes[algo].forEach(function (o) {
        if (!o || typeof o.filename !== 'string' || !o.filename.trim()) return;
        objects++;
        /* Case-insensitive: the row carries the feed's case, and the review's own
           "case-only duplicate" class is the same value in another case. A name
           absent in EVERY case is the defect this test exists for. */
        var name = o.filename.trim().toLowerCase();
        var hit = rows.some(function (r) {
          return r.type === 'filename' && r.value.toLowerCase() === name;
        });
        if (!hit) misses.push(f + ': ' + o.filename);
      });
    });
  });
  assert.ok(objects > 800, 'denominator collapsed: ' + objects + ' hash objects carry a filename');
  assert.deepEqual(misses, [], misses.length + ' of ' + objects + ' filenames have no row');
});

test('the names the review called out are rows, with the hash entry\'s action', function () {
  /* flaskc2-postex-toolkit-67-215-232-25, file_hashes.sha256[11] and [13], BLOCK. */
  var rows = summarise('flaskc2-postex-toolkit-67-215-232-25').rows;
  [['rubeus.exe', 'BLOCK'], ['sweetpotato.exe', 'BLOCK']].forEach(function (pair) {
    var r = rowOf(rows, 'filename', pair[0]);
    assert.ok(r, pair[0] + ' is not a row');
    assert.equal(r.action, pair[1], pair[0] + ' lost the entry\'s action');
    assert.equal(r.confidence, 'HIGH', pair[0] + ' lost the entry\'s confidence');
  });
});

test('a name typed by both the extractor and the classifier is ONE row', function () {
  /* `CVE-2026-20817_PoC.exe` sits in a file_hashes entry (BLOCK) and, lower-cased,
     in another container (HUNT). Original-case plus lower-case gave two rows for one
     file; the declared kind now takes ioc-classify's normalised value. */
  var rows = summarise('flaskc2-postex-toolkit-67-215-232-25').rows;
  var hits = rows.filter(function (r) { return r.value.toLowerCase() === 'cve-2026-20817_poc.exe'; });
  assert.equal(hits.length, 1, JSON.stringify(hits));
  assert.equal(hits[0].value, 'cve-2026-20817_poc.exe');
});

test('a BLOCK address keeps a bare row beside every host:port row', function () {
  /* bellamain: 79.137.192.3 at :443 and :80, both BLOCK, no bare entry in the feed. */
  var rows = summarise('bellamain-turkish-phaas-79-137-192-3-20260516').rows;
  ['79.137.192.3', '79.137.192.3:443', '79.137.192.3:80'].forEach(function (v) {
    var r = rowOf(rows, 'ipv4', v);
    assert.ok(r, v + ' is not a row');
    assert.equal(r.action, 'BLOCK', v + ' lost the action');
  });
  /* cloudsync: 91.197.98.188 on three ports, one bare row. */
  var cs = summarise('cloudsync-assembler-toolkit-91-197-98-188').rows;
  var bare = cs.filter(function (r) { return r.type === 'ipv4' && r.value === '91.197.98.188'; });
  assert.equal(bare.length, 1, 'expected exactly one bare row for 91.197.98.188');
  assert.equal(bare[0].action, 'BLOCK');
  ['91.197.98.188:5555', '91.197.98.188:7777', '91.197.98.188:8000'].forEach(function (v) {
    assert.ok(rowOf(cs, 'ipv4', v), v + ' is not a row');
  });
});

test('the addresses the review found without a bare row all have one', function () {
  var nine = [
    ['bellamain-turkish-phaas-79-137-192-3-20260516', '79.137.192.3'],
    ['cloudsync-assembler-toolkit-91-197-98-188', '2.27.248.138'],
    ['cloudsync-assembler-toolkit-91-197-98-188', '91.197.98.188'],
    ['cloudsync-assembler-toolkit-91-197-98-188', '91.92.43.221'],
    ['evilsoul-engine-stealer-maas', '144.172.109.203'],
    ['evilsoul-engine-stealer-maas', '198.1.195.207'],
    ['evilsoul-engine-stealer-maas', '198.1.195.210'],
    ['opendirectory-216-126-227-49-cve-2026-41940-cpanel-harvester-20260517', '216.126.227.49'],
    ['opendirectory-79-137-192-3-20260515', '79.133.180.168']
  ];
  var bad = [];
  nine.forEach(function (pair) {
    var r = rowOf(summarise(pair[0]).rows, 'ipv4', pair[1]);
    if (!r || r.action !== 'BLOCK') bad.push(pair[0] + ' ' + pair[1] + ' -> ' + JSON.stringify(r));
  });
  assert.deepEqual(bad, []);
});

test('metadata.infrastructure is walked for an address, metadata.reference is not', function () {
  var doc = feed('opendirectory-45-130-148-125-20260430');
  assert.equal(doc.metadata.infrastructure.source_ip, '45.130.148.125');
  var rows = X.summarise(doc).rows;
  var bare = rowOf(rows, 'ipv4', '45.130.148.125');
  assert.ok(bare, 'the bare source_ip row is missing');
  assert.ok(rowOf(rows, 'ipv4', '45.130.148.125:80'), ':80 missing');
  assert.ok(rowOf(rows, 'ipv4', '45.130.148.125:8888'), ':8888 missing');
  if (doc.metadata.reference) {
    assert.equal(rowOf(rows, 'url', doc.metadata.reference), undefined,
      'the site\'s own report URL is still a row');
  }
});

test('a hash row\'s type always matches its value length', function () {
  var files = fs.readdirSync(FEED_DIR).filter(function (f) { return /-iocs\.json$/.test(f); });
  var len = { sha256: 64, sha1: 40, md5: 32 }, checked = 0, bad = [];
  files.forEach(function (f) {
    var doc = JSON.parse(fs.readFileSync(path.join(FEED_DIR, f), 'utf8'));
    X.summarise(doc).rows.forEach(function (r) {
      if (!len[r.type]) return;
      checked++;
      if (r.value.length !== len[r.type]) bad.push(f + ': ' + r.type + ' ' + r.value);
    });
  });
  assert.ok(checked > 1000, 'denominator collapsed: ' + checked + ' hash rows');
  assert.deepEqual(bad, []);
});

test('the certificate SHA-1 the review named is typed sha1', function () {
  var rows = summarise('opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817').rows;
  var v = 'aab136e06c94e5616832afa34af096bd6b77151c';
  assert.equal(v.length, 40);
  var r = rowOf(rows, 'sha1', v);
  assert.ok(r, 'the certificate SHA-1 is not a sha1 row: ' + JSON.stringify(rowOf(rows, 'sha256', v)));
});

test('the three korean-claude-openclaw instructions are carried, verb-led, dots and slashes and all', function () {
  var rows = summarise('korean-claude-openclaw-221.150.15.104').rows;
  var want = {
    domain: 'docs.openclaw.ai',
    url: 'https://openclaw.ai/install.sh',
    path: '<project-root>/.claude/settings.local.json'
  };
  Object.keys(want).forEach(function (t) {
    var r = rowOf(rows, t, want[t]);
    assert.ok(r, t + ' ' + want[t] + ' is not a row');
    assert.ok(r.action, t + ' ' + want[t] + ' has no action');
  });
  assert.match(rowOf(rows, 'path', '<project-root>/.claude/settings.local.json').action, /^SWEEP /);
});

test('a verdict badge is the instruction, not a sentence: the two commentary tails are cut', function () {
  var korean = summarise('korean-claude-openclaw-221.150.15.104').rows;
  assert.equal(rowOf(korean, 'url', 'http://221.150.15.104:8080/').action, 'BLOCK EGRESS FROM YOUR ESTATE');
  var opendir = summarise('opendirectory-79-137-192-3-20260515').rows;
  var p = opendir.filter(function (r) {
    return r.type === 'path' && /InstallUtil\.exe$/.test(r.value);
  })[0];
  assert.ok(p, 'the InstallUtil.exe path row is missing');
  assert.equal(p.action, 'MONITOR');
});

test('actionOf: verb-led text keeps separators, SUSPEND is a verb, a command stays null', function () {
  /* A synthetic feed, because the rule is about the action string, not about any
     one report. Values are TEST-NET addresses so classification is unambiguous. */
  var doc = {
    network_indicators: {
      ipv4: [
        { value: '203.0.113.9', action: 'Suspend + cross-reference with example-stack' },
        { value: '203.0.113.10', action: 'Sweep endpoints for .claude/settings.local.json under working directories' },
        { value: '203.0.113.11', action: 'BLOCK EGRESS FROM YOUR ESTATE; THIS IS THE DISCOVERY VECTOR' },
        { value: '203.0.113.12', action: 'wscript.exe /e:jscript %LOCALAPPDATA%\\payload.js' },
        { value: '203.0.113.13', action: 'HUNT' }
      ]
    }
  };
  var rows = X.summarise(doc).rows;
  assert.equal(rowOf(rows, 'ipv4', '203.0.113.9').action, 'SUSPEND + CROSS-REFERENCE WITH EXAMPLE-STACK');
  assert.equal(rowOf(rows, 'ipv4', '203.0.113.10').action,
    'SWEEP ENDPOINTS FOR .CLAUDE/SETTINGS.LOCAL.JSON UNDER WORKING DIRECTORIES');
  assert.equal(rowOf(rows, 'ipv4', '203.0.113.11').action, 'BLOCK EGRESS FROM YOUR ESTATE');
  assert.equal(rowOf(rows, 'ipv4', '203.0.113.12').action, null);
  assert.equal(rowOf(rows, 'ipv4', '203.0.113.13').action, 'HUNT');
});
