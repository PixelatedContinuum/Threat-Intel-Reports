'use strict';

var test = require('node:test');
var assert = require('node:assert');
var CK = require('../lib/check-ioc-index.js');

function doc(over) {
  var d = {
    generated_at: '2026-08-19T14:00:00Z',
    counts: { indicators: 1, reports: 1, multi_report: 0, suppressed_benign: 2 },
    coverage: { indexed: ['live-iocs.json'], embargoed: ['held-iocs.json'], unknown: [], empty: [] },
    conflicts: [],
    reports: { live: { title: 'Live', date: '2026-07-28', severity: 'high', report_url: '/reports/live/' } },
    indicators: { 'ipv4:1.2.3.4': [{ report: 'live', role: 'C2 server' }] }
  };
  return Object.assign(d, over || {});
}
var STATUS = { 'live-iocs.json': 'published', 'held-iocs.json': 'embargoed' };

test('a well-formed index passes', function () {
  var r = CK.check(doc(), STATUS, doc());
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.problems, []);
});

test('the embargoed exclusion is reported as a note, so it stays visible', function () {
  var r = CK.check(doc(), STATUS, doc());
  assert.match(r.notes.join(' '), /held-iocs\.json/);
  assert.match(r.notes.join(' '), /signal-free/);
});

test('an absent index is NOT CHECKED, never PASS', function () {
  assert.equal(CK.check(null, STATUS, doc()).status, 'NOT CHECKED');
});

test('an index with zero indicators is NOT CHECKED', function () {
  var d = doc({ indicators: {}, counts: { indicators: 0, reports: 0, multi_report: 0 } });
  assert.equal(CK.check(d, STATUS, d).status, 'NOT CHECKED');
});

test('AN EMBARGOED CAMPAIGN IN THE REPORTS TABLE FAILS', function () {
  // The safety check. This one protects victims, not correctness.
  var d = doc({ reports: { held: { title: 'Held' }, live: { title: 'Live' } } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /DISCLOSURE/);
});

test('an indicator pointing at an embargoed report FAILS', function () {
  var d = doc({ indicators: { 'ipv4:1.2.3.4': [{ report: 'held' }] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /DISCLOSURE/);
});

test('disagreeing publication signals FAIL rather than being resolved', function () {
  var d = doc({ conflicts: [{ slug: 'live', catalog: 'published', front_matter: 'unlisted' }] });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /CONFLICT/);
});

test('a dangling report slug fails', function () {
  var d = doc({ indicators: { 'ipv4:1.2.3.4': [{ report: 'ghost' }] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /ghost/);
});

test('a published feed missing from every coverage list fails', function () {
  var d = doc({ coverage: { indexed: [], embargoed: ['held-iocs.json'], unknown: [], empty: [] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /live-iocs\.json/);
});

test('a feed with no catalog entry is reported, not treated as safe', function () {
  var d = doc({ coverage: { indexed: ['live-iocs.json'], embargoed: ['held-iocs.json'],
                            unknown: ['mystery-iocs.json'], empty: [] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /mystery/);
});

test('a published feed that yielded nothing fails', function () {
  var d = doc({ coverage: { indexed: ['live-iocs.json'], embargoed: [], unknown: [],
                            empty: ['other-iocs.json'] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /other-iocs\.json/);
});

test('counts disagreeing with the data fail', function () {
  var d = doc({ counts: { indicators: 99, reports: 1, multi_report: 0 } });
  assert.equal(CK.check(d, STATUS, d).status, 'FAIL');
});

test('a malformed indicator key fails', function () {
  var d = doc({ indicators: { 'nonsense-no-colon': [{ report: 'live' }] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /malformed/i);
});

test('an unknown indicator type fails', function () {
  var d = doc({ indicators: { 'registrykey:HKLM': [{ report: 'live' }] } });
  var r = CK.check(d, STATUS, d);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /unknown type/i);
});

test('a stale index fails, by regenerate-and-diff', function () {
  var fresh = doc({ indicators: { 'ipv4:9.9.9.9': [{ report: 'live' }] } });
  var r = CK.check(doc(), STATUS, fresh);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /stale/i);
});
