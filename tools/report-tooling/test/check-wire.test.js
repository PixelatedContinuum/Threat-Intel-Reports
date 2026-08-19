'use strict';

var test = require('node:test');
var assert = require('node:assert');
var CW = require('../lib/check-wire.js');

var NOW = Date.parse('2026-08-19T12:00:00Z');

function doc(over) {
  var d = {
    generated_at: '2026-08-19T07:00:00Z',
    window_days: 30,
    counts: { total: 2, research: 1, news: 1 },
    // Must name a label an item actually carries, or the topic check fires.
    topics: [{ label: 'security', count: 1, color: 3 }],
    label_colors: { security: 3 },
    items: [
      { title: 'A', url: 'https://x.test/a', source: 'AlienVault',
        date: '2026-08-18T10:00:00Z', kind: 'research', labels: [] },
      { title: 'B', url: 'https://x.test/b', source: 'BleepingComputer',
        date: '2026-08-17T10:00:00Z', kind: 'news', labels: ['security'] }
    ]
  };
  return Object.assign(d, over || {});
}

var SOURCES = { AlienVault: 'research', BleepingComputer: 'news' };

test('a well-formed file passes', function () {
  var r = CW.check(doc(), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.problems, []);
});

test('an absent file is NOT CHECKED, never PASS', function () {
  var r = CW.check(null, SOURCES, NOW);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /wire\.yml/);
});

test('a stale generated_at fails', function () {
  // 40 hours old against a twice-daily timer: two consecutive misses.
  var r = CW.check(doc({ generated_at: '2026-08-17T20:00:00Z' }), SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /stale/i);
});

test('exactly one missed run still passes', function () {
  // 30 hours old: one miss tolerated, per the spec's 36-hour threshold.
  var r = CW.check(doc({ generated_at: '2026-08-18T06:00:00Z' }), SOURCES, NOW);
  assert.equal(r.status, 'PASS');
});

test('a description key fails, because that is the copyright limit', function () {
  var d = doc();
  d.items[0].description = 'The publisher blurb that must never ship.';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /description/i);
});

test('a missing required field fails', function () {
  var d = doc();
  delete d.items[1].source;
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /source/);
});

test('an item outside the declared window fails', function () {
  var d = doc();
  d.items[1].date = '2026-06-01T10:00:00Z';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /window/i);
});

test('counts disagreeing with the items fail', function () {
  var r = CW.check(doc({ counts: { total: 9, research: 1, news: 1 } }), SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /counts/i);
});

test('a non-https url fails', function () {
  var d = doc();
  d.items[0].url = 'http://x.test/a';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /https/);
});

test('an unknown kind fails', function () {
  var d = doc();
  d.items[0].kind = 'opinion';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /kind/i);
});

test('a duplicate title fails', function () {
  var d = doc();
  d.items[1].title = 'A';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /duplicate/i);
});

test('an unclassified source warns but does not fail', function () {
  var d = doc();
  d.items[1].source = 'Brand New Blog';
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.warnings, ['Brand New Blog']);
});

test('an empty item list is NOT CHECKED, not a silent pass', function () {
  var r = CW.check(doc({ items: [], counts: { total: 0, research: 0, news: 0 } }),
                   SOURCES, NOW);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /no items/i);
});

test('a topic chip naming a label no item carries fails', function () {
  // A chip that selects nothing is a dead control, and the page renders chips
  // straight from this list without checking them against the items.
  var d = doc({ topics: [{ label: 'nonexistent', count: 3, color: 1 }],
                label_colors: { nonexistent: 1 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /topic chip/i);
});

test('a topic colour outside the CSS palette fails', function () {
  // Renders a chip with no colour variable: it still filters, it just goes
  // grey while every sibling is coloured. Silent visual regression.
  var d = doc({ topics: [{ label: 'security', count: 1, color: 99 }],
                label_colors: { security: 99 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /palette/i);
});

test('a missing topic colour fails', function () {
  var d = doc({ topics: [{ label: 'security', count: 1 }], label_colors: {} });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /palette/i);
});

test('a tag coloured differently from its chip fails', function () {
  var d = doc({ topics: [{ label: 'security', count: 1, color: 3 }],
                label_colors: { security: 7 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /would not match its chip/i);
});

test('a label_colors entry with no chip fails', function () {
  var d = doc({ topics: [{ label: 'security', count: 1, color: 3 }],
                label_colors: { security: 3, orphan: 5 } });
  var r = CW.check(d, SOURCES, NOW);
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /not a topic/i);
});
