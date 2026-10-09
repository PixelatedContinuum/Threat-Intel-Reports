'use strict';

var test = require('node:test');
var assert = require('node:assert');
var CT = require('../lib/check-tags.js');

/* The vocabulary the fixtures check against. Small on purpose: one entry with
   aliases, one without, so each rule has exactly one place to land. */
function vocab(over) {
  var v = {
    tags: [
      { tag: 'Open Dir', color: 'green', aliases: ['OpenDirectory', 'Open Directory'] },
      { tag: 'Stealer', color: 'purple' },
      { tag: 'C2', color: 'blue' }
    ]
  };
  return Object.assign(v, over || {});
}

function catalog(entries) {
  return {
    entries: entries || [
      { title: 'A', date: '2026-01-01', tags: ['Open Dir', 'Stealer'] },
      { title: 'B', date: '2026-01-02', tags: ['C2'] }
    ]
  };
}

test('a well-formed catalog against a well-formed vocabulary passes', function () {
  var r = CT.check(catalog(), vocab());
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.warnings, []);
  assert.deepEqual(r.counts, { entries: 2, tags: 3, unknown: 0 });
});

test('an absent catalog is NOT CHECKED, never PASS', function () {
  var r = CT.check(null, vocab());
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /catalog\.yml/);
});

test('an absent vocabulary is NOT CHECKED, never PASS', function () {
  var r = CT.check(catalog(), null);
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /tags\.yml/);
});

test('a vocabulary with no tags list is NOT CHECKED', function () {
  // A file that parses but holds nothing verifiable is still "nothing was
  // verified", not a clean sweep against an empty set.
  var r = CT.check(catalog(), { tags: 'not a list' });
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /tags\.yml/);
});

test('a catalog tag that is a retired alias fails and names the canonical', function () {
  // The whole point. "OpenDirectory" looked fine in the entry that carried it,
  // and was a different tag to the chip builder and the badge colour lookup.
  var r = CT.check(catalog([
    { title: 'Old Spelling Report', tags: ['OpenDirectory'] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  var text = r.problems.join(' ');
  assert.match(text, /Old Spelling Report/);
  assert.match(text, /"OpenDirectory"/);
  assert.match(text, /use "Open Dir"/);
});

test('an alias is matched case-insensitively and trimmed', function () {
  var r = CT.check(catalog([
    { title: 'A', tags: [' open directory '] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /use "Open Dir"/);
});

test('case drift on a canonical tag fails and names the exact spelling', function () {
  // Badge colour lookup is exact: "stealer" renders grey beside "Stealer".
  var r = CT.check(catalog([
    { title: 'A', tags: ['stealer'] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  var text = r.problems.join(' ');
  assert.match(text, /"stealer"/);
  assert.match(text, /use "Stealer" verbatim/);
});

test('surrounding whitespace on a canonical tag fails the same way', function () {
  var r = CT.check(catalog([
    { title: 'A', tags: ['Open Dir '] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /use "Open Dir" verbatim/);
});

test('an unknown tag warns but does not fail', function () {
  // A genuinely new tag has to be typed somewhere first. Blocking it would push
  // the author to reuse a near-miss, which is the drift this gate exists to stop.
  var r = CT.check(catalog([
    { title: 'New Thing', tags: ['Stealer', 'Brand New Tag'] }
  ]), vocab());
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.problems, []);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /New Thing/);
  assert.match(r.warnings[0], /"Brand New Tag"/);
  assert.match(r.warnings[0], /add it to _data\/tags\.yml or use an existing tag/);
  assert.equal(r.counts.unknown, 1);
});

test('one unknown spelling on several entries counts once', function () {
  var r = CT.check(catalog([
    { title: 'A', tags: ['Novel'] },
    { title: 'B', tags: ['novel'] }
  ]), vocab());
  assert.equal(r.status, 'PASS');
  assert.equal(r.warnings.length, 2);
  assert.equal(r.counts.unknown, 1);
});

test('a duplicate tag within one entry fails', function () {
  // Two identical badges, and the entry counts twice toward the chip threshold.
  var r = CT.check(catalog([
    { title: 'A', tags: ['Stealer', 'C2', 'Stealer'] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /"Stealer" twice/);
});

test('a duplicate that differs only in case is still a duplicate', function () {
  var r = CT.check(catalog([
    { title: 'A', tags: ['Stealer', 'stealer'] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /twice/);
});

test('the override tag fields are checked with the same rules', function () {
  // The listing pages read detection_tags / ioc_tags / stix_tags with a Liquid
  // fallback to tags, so an alias in an override is as live as one in tags.
  var r = CT.check(catalog([
    { title: 'A', tags: ['Stealer'], ioc_tags: ['OpenDirectory'] }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /ioc_tags tag "OpenDirectory"/);
  assert.equal(r.counts.tags, 2);
});

test('an alias claimed twice in the vocabulary fails, naming the entry', function () {
  // The gate would have to pick a winner, and whichever it picked, the other
  // entry's canonical form would be silently wrong.
  var r = CT.check(catalog(), vocab({
    tags: [
      { tag: 'Open Dir', color: 'green', aliases: ['OpenDirectory'] },
      { tag: 'Exposed Dir', color: 'green', aliases: ['opendirectory'] }
    ]
  }));
  assert.equal(r.status, 'FAIL');
  var text = r.problems.join(' ');
  assert.match(text, /"Exposed Dir"/);
  assert.match(text, /already claimed by "Open Dir"/);
});

test('an alias that collides with another canonical tag fails', function () {
  var r = CT.check(catalog(), vocab({
    tags: [
      { tag: 'Open Dir', color: 'green', aliases: ['Stealer'] },
      { tag: 'Stealer', color: 'purple' }
    ]
  }));
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /already claimed/);
});

test('a canonical tag spelled twice fails', function () {
  var r = CT.check(catalog(), vocab({
    tags: [
      { tag: 'Stealer', color: 'purple' },
      { tag: 'stealer', color: 'blue' }
    ]
  }));
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /already claimed by "Stealer"/);
});

test('a colour outside the badge palette fails', function () {
  // Renders a chip with no colour class: grey among coloured siblings.
  var r = CT.check(catalog(), vocab({
    tags: [{ tag: 'Stealer', color: 'orange' }]
  }));
  assert.equal(r.status, 'FAIL');
  var text = r.problems.join(' ');
  assert.match(text, /"Stealer"/);
  assert.match(text, /"orange"/);
  assert.match(text, /blue, red, green, purple, yellow/);
});

test('a missing colour fails', function () {
  var r = CT.check(catalog(), vocab({ tags: [{ tag: 'Stealer' }] }));
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /colour null/);
});

test('a vocabulary entry without a string tag fails', function () {
  var r = CT.check(catalog(), vocab({
    tags: [{ color: 'blue' }, { tag: 'Stealer', color: 'purple' }]
  }));
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /entry 1 has no string `tag`/);
});

test('a tags field that is not a list fails rather than being skipped', function () {
  var r = CT.check(catalog([
    { title: 'A', tags: 'Stealer' }
  ]), vocab());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /not a list/);
});

test('an entry with no tags at all is counted but raises nothing', function () {
  var r = CT.check(catalog([{ title: 'Untagged' }]), vocab());
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.counts, { entries: 1, tags: 0, unknown: 0 });
});

test('the shipped vocabulary is itself well-formed', function () {
  // The real _data/tags.yml, checked against an empty catalog, so that a typo
  // in the vocabulary fails here and not only once a catalog edit happens to
  // route through the gate.
  var fs = require('node:fs');
  var path = require('node:path');
  var yaml = require('js-yaml');
  var src = fs.readFileSync(path.join(__dirname, '..', '..', '..', '_data', 'tags.yml'), 'utf8');
  var r = CT.check({ entries: [] }, yaml.load(src));
  assert.equal(r.status, 'PASS', r.problems.join(' | '));
});
