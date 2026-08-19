'use strict';

/* The manifest staleness gate.

   This suite exists because of a gap found on 2026-08-19: _data/detection_manifests.yml
   was written by exactly one line in the generator and read by NOTHING in the tooling.
   sweepSource() re-derived the manifest and checked that derivation against itself, so a
   committed manifest that had drifted arbitrarily from hunting-detections/ passed every
   gate in the repo. The comment in lib/check-ioc-index.js even claimed the manifest
   already used regenerate-and-diff, which is the belief that let the gap persist.

   So the first test below is the one that matters: a stale manifest must FAIL. */

var test = require('node:test');
var assert = require('node:assert');
var CK = require('../lib/check-detection-manifest.js');

// A committed manifest and the generator verdict that would rebuild it.
var YAML = 'acme-detections:\n  - name: Rule One\n    tier: Detection\n';

function gen(over) {
  return Object.assign({
    status: 'PASS', files: 1, rules: 1, xref: 0, slugs: 1,
    problems: [], yaml: YAML
  }, over || {});
}

test('a manifest matching its source passes', function () {
  var r = CK.check(YAML, gen());
  assert.equal(r.status, 'PASS');
  assert.deepEqual(r.problems, []);
});

test('A STALE MANIFEST FAILS', function () {
  // The check the repo did not have. An edit to hunting-detections/ that never
  // reran the generator leaves the picker serving rules from the previous shape.
  var committed = 'acme-detections:\n  - name: Rule One\n    tier: Hunting\n';
  var r = CK.check(committed, gen());
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /stale/i);
});

test('the failure names the remedy, because the reader is mid-commit', function () {
  var r = CK.check('something else entirely\n', gen());
  assert.match(r.problems.join(' '), /generate-detection-manifests\.js/);
});

test('the failure reports how far apart the two are, not just that they differ', function () {
  var committed = YAML + 'extra-detections:\n  - name: Rule Two\n';
  var r = CK.check(committed, gen());
  assert.match(r.problems.join(' '), /line/i);
});

test('an absent manifest is NOT CHECKED, never PASS', function () {
  var r = CK.check(null, gen());
  assert.equal(r.status, 'NOT CHECKED');
  assert.match(r.reason, /generate-detection-manifests\.js/);
});

test('a generator that could not read its sources is NOT CHECKED, not a clean diff', function () {
  // Both sides empty would compare equal and read as PASS. It must not.
  var r = CK.check('', gen({ status: 'NOT CHECKED', files: 0, rules: 0, yaml: '',
                             reason: '3 file(s) could not be read' }));
  assert.equal(r.status, 'NOT CHECKED');
});

test('a generator reporting zero rules is NOT CHECKED, so an empty corpus cannot read as clean',
  function () {
    var r = CK.check('', gen({ status: 'PASS', files: 0, rules: 0, yaml: '' }));
    assert.equal(r.status, 'NOT CHECKED');
    assert.match(r.reason, /nothing/i);
  });

test('the generator own problems surface as FAIL even when the diff is clean', function () {
  var r = CK.check(YAML, gen({ status: 'FAIL',
    problems: ['acme-detections.md: accounted for 4 Tier lines but the file declares 5.'] }));
  assert.equal(r.status, 'FAIL');
  assert.match(r.problems.join(' '), /Tier lines/);
});

test('a trailing-newline difference alone is not a failure', function () {
  // Editors and git hooks both add and strip these. Failing on one would train
  // the reader to bypass the hook, which costs more than it protects.
  assert.equal(CK.check(YAML + '\n', gen()).status, 'PASS');
});

test('CRLF against LF is not a failure', function () {
  // The vault is CRLF and the site repo is LF-normalised, so a manifest that
  // round-tripped through a Windows editor differs by line ending alone.
  assert.equal(CK.check(YAML.replace(/\n/g, '\r\n'), gen()).status, 'PASS');
});
