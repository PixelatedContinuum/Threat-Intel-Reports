'use strict';

/* T-0632: the LIVE run of check-browser-wire.js (the default: no HL_SITE_DIR) used to fold a NOT CHECKED
   into FAIL. Its no-quiet-day branch called check(name, false) and the run's own tally counted every
   false as a failure, so a corpus in which every day of the window carried a row exited 1 and read as a
   broken Wire. homelab-soc/docs/gate-honesty-contract.md: NOT CHECKED is its own state, never PASS, never
   FAIL, and a run with a FAIL outranks it.

   The decision is held in lib/wire-live.js so it can be proved here without a browser or a corpus, the
   way lib/gate-ledger.js holds the BUILT verdict (test/browser-defang-core.test.js, "S1 gate-ledger").
   That the gate itself calls these functions is shown by the LIVE run in tasks/runs/T-0632/, not here;
   this file proves the decision they make. Nothing here drives Chromium. */

var test = require('node:test');
var assert = require('node:assert');
var LEDGER = require('../lib/gate-ledger.js');
var LIVE = require('../lib/wire-live.js');

function harness() {
  var lines = [];
  var L = LEDGER.makeLedger(function (l) { lines.push(l); });
  return { L: L, lines: lines, finish: function () { return LIVE.finish(L, function (l) { lines.push(l); }); } };
}

/* The fourteen other LIVE checks of the 2026-11-19 run, reduced to what they contribute here: passes with
   a real denominator where one exists (rows), plain property checks otherwise. */
function ordinaryChecks(h, failOne) {
  h.L.chk('every row on the live page loaded', !failOne, 742, 'rows');
  h.L.chk('picking the busiest day shows exactly its rows under one heading', true, 40, 'rows');
  h.L.plain('the date control renders with real geometry', true);
  h.L.plain('the native picker glyph is legible on the dark field', true);
  h.L.plain('nothing was transmitted while the reader filtered', true);
}

test('T-0632 a LIVE corpus with no quiet day is NOT CHECKED (exit 2), not FAIL (exit 1)', function () {
  var h = harness();
  ordinaryChecks(h, false);
  assert.equal(h.L.verdict().code, 0, 'control: the ordinary checks alone are a PASS, so the next line is what changes the verdict');

  LIVE.quietDay(h.L, null, null);

  var V = h.L.verdict();
  assert.equal(V.notChecked, 1, 'the unexercised empty state is NOT CHECKED');
  assert.equal(V.fails, 0, 'nothing about the page failed');
  assert.deepEqual([V.verdict, V.code], ['NOT CHECKED', 2]);

  var code = h.finish();
  assert.equal(code, 2);
  assert.ok(h.lines.some(function (l) { return /NOT CHECKED {2}a quiet day inside the window says so and names the date/.test(l); }),
    'the check is named as NOT CHECKED in the run log: ' + h.lines.join('\n'));
  assert.ok(h.lines.some(function (l) { return /every day in the corpus currently carries at least one item/.test(l); }),
    'the reason is printed, not just the state');
  assert.match(h.lines.join('\n'), /^NOT CHECKED {2}\/wire\/ in a real browser/m,
    'the summary line leads with NOT CHECKED');
  assert.match(h.lines.join('\n'), /1 NOT CHECKED/, 'the summary line prints the NOT CHECKED count');
  assert.doesNotMatch(h.lines.join('\n'), /^FAIL/m, 'no FAIL is printed anywhere');
});

test('T-0632 one real FAIL still ends the LIVE run at exit 1, and outranks the quiet-day NOT CHECKED', function () {
  var h = harness();
  ordinaryChecks(h, true);            // 741 of 742 rows loaded: a genuine defect of the page
  LIVE.quietDay(h.L, null, null);     // and one check that could not run

  var V = h.L.verdict();
  assert.equal(V.fails, 1);
  assert.equal(V.notChecked, 1);
  assert.deepEqual([V.verdict, V.code], ['FAIL', 1]);

  assert.equal(h.finish(), 1);
  assert.match(h.lines.join('\n'), /^FAIL {2}\/wire\/ in a real browser/m);
  assert.match(h.lines.join('\n'), /4 PASS, 1 FAIL, 1 NOT CHECKED, of 6 checks/,
    'the summary counts all three states, so neither hides behind the other');
});

test('T-0632 control: a corpus with a quiet day passes the check, and a wrong message fails it', function () {
  var ok = harness();
  LIVE.quietDay(ok.L, '2026-11-05', 'No headlines on 5 November 2026. The Wire is quiet some days.');
  assert.deepEqual([ok.L.verdict().verdict, ok.L.verdict().code], ['PASS', 0], 'the branch still passes when it can run');

  var bad = harness();
  LIVE.quietDay(bad.L, '2026-11-05', 'No headlines match that filter.');
  assert.deepEqual([bad.L.verdict().verdict, bad.L.verdict().code], ['FAIL', 1], 'a quiet day that is not named is a real failure');
  assert.match(bad.lines.join('\n'), /No headlines match that filter/, 'the message is quoted in the FAIL detail');
});

test('T-0632 plain(): a LIVE property check has no denominator and is never NOT CHECKED for want of a count', function () {
  var h = harness();
  h.L.plain('the clear-date control appears once a date is set', true);
  assert.deepEqual([h.L.verdict().verdict, h.L.verdict().code, h.L.checks[0].verdict], ['PASS', 0, 'PASS']);
  h.L.plain('the clear-date control is truly invisible before a date is picked', false);
  assert.deepEqual([h.L.verdict().verdict, h.L.verdict().code], ['FAIL', 1]);
  assert.ok(h.lines.some(function (l) { return /\[no denominator\]/.test(l); }),
    'the log says the check carries no count, so a reader is not told it covered items it did not');
});
