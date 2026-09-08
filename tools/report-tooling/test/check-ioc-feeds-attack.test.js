'use strict';

/* The walker that finds bare technique-ID-shaped strings in a feed.

   Only the walker is unit-tested here. Catalog validity (does T1685 exist, does
   T1562.001 not) is already covered by attack-catalog.test.js against the real
   TSV; duplicating that here would be the second implementation this whole gate
   exists to avoid having. */

var test = require('node:test');
var assert = require('node:assert');
var G = require('../check-ioc-feeds-attack.js');

test('finds a bare ID at the top level', function () {
  var out = [];
  G.bareIds({ mitre_attack: 'T1685' }, '', out);
  assert.deepEqual(out, [{ at: 'mitre_attack', id: 'T1685' }]);
});

test('finds every bare ID inside an array, each with its own index in its path', function () {
  var out = [];
  G.bareIds({ techniques: ['T1564.003', 'T1027', 'T1685'] }, '', out);
  assert.deepEqual(out, [
    { at: 'techniques[0]', id: 'T1564.003' },
    { at: 'techniques[1]', id: 'T1027' },
    { at: 'techniques[2]', id: 'T1685' }
  ]);
});

test('does NOT match a composite name-plus-ID string', function () {
  // This is the half the gate cannot reach, named in its own output. A false
  // match here would make the gate claim coverage it does not have.
  var out = [];
  G.bareIds({ technique: 'T1685 - Disable or Modify Tools' }, '', out);
  assert.deepEqual(out, []);
});

test('does NOT match prose that merely mentions a technique ID', function () {
  var out = [];
  G.bareIds({ context: 'See T1685 for background.' }, '', out);
  assert.deepEqual(out, []);
});

test('walks nested objects and reports a dotted path', function () {
  var out = [];
  G.bareIds({ a: { b: { technique_id: 'T1070.004' } } }, '', out);
  assert.deepEqual(out, [{ at: 'a.b.technique_id', id: 'T1070.004' }]);
});

test('a whitespace-padded bare ID still matches, trimmed', function () {
  var out = [];
  G.bareIds({ mitre_attack: ' T1685 ' }, '', out);
  assert.deepEqual(out, [{ at: 'mitre_attack', id: 'T1685' }]);
});
