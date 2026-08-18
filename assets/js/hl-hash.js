/* The Hunter's Ledger: one hash, used by both sides of the detection manifest.

   The generator records a hash of each rule body at publish time and the picker
   recomputes it from the page before trusting the fence index it was given. That
   only works if both compute it identically, so this module is the single
   implementation: the Node parser requires it, and the browser loads it ahead of
   the picker. Two copies would be free to drift, and a drift here reads as every
   rule failing verification.

   Why a hash rather than the opening characters of the rule. A prefix check was
   the first design and measurement killed it: YARA rules in this corpus open
   with a boilerplate comment block, so on 15 of 56 pages two or more rules share
   their first 48 characters, and on the largest page six do. A prefix that
   several rules share cannot detect the off-by-one it exists to detect. Hashing
   the whole body also catches a rule whose content changed while its opening did
   not.

   FNV-1a, 32-bit. Not cryptographic and does not need to be: this detects
   accidental misalignment between a generated manifest and a rendered page, not
   an adversary choosing a collision. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.HLHash = api; }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* Collapses every whitespace run to one space and trims. Kramdown can alter
     trailing whitespace and line endings between the source and the rendered
     page, so hashing raw text would fail on differences no reader can see. */
  function normalise(s) {
    return String(s == null ? '' : s).replace(/\r\n?/g, '\n').trim().replace(/\s+/g, ' ');
  }

  function fnv1a(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      // 32-bit FNV prime multiply, kept in range without BigInt.
      h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
      h = h >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  function ruleHash(body) {
    return fnv1a(normalise(body));
  }

  return { normalise: normalise, fnv1a: fnv1a, ruleHash: ruleHash };
});
