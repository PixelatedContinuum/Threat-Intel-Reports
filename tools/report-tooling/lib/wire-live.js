'use strict';

/* The LIVE run's verdict (T-0632), held apart from check-browser-wire.js so `npm test` can prove it
   without a browser or a live corpus, the way lib/gate-ledger.js holds the BUILT verdict.

   Why it needed holding apart: the LIVE branch counted every false as a failure, so a NOT CHECKED
   written as check(name, false) came out as FAIL (exit 1) and told the reader the Wire was broken. On
   2026-11-19 the only "failure" of a 15/16 run was "no empty day inside the current window to
   exercise": the corpus had no quiet day, so the empty state could not be driven at all. The gate
   honesty contract (homelab-soc/docs/gate-honesty-contract.md) makes that NOT CHECKED, its own state,
   beside PASS and FAIL, with a FAIL outranking it.

   quietDay(ledger, quiet, message)  the empty-state branch. `quiet` is the first empty day inside the
                                    window (built.gaps[0]) or null; `message` is the page's own
                                    [data-filter-empty-msg] text when there was a day to drive.
   finish(ledger, log)              the summary line (all three counts) and the exit code: FAIL 1,
                                    NOT CHECKED 2, PASS 0, from the ledger's verdict().

   LIVE drives the Headlines tab only (lib/wire-harness.js `build` takes the first [data-filter-grid]);
   the nKEVs and CVEs tabs are BUILT mode's. */

var QUIET = 'a quiet day inside the window says so and names the date';

function quietDay(ledger, quiet, message) {
  if (!quiet) {
    ledger.skipped(QUIET, 'every day in the corpus currently carries at least one item, so the empty ' +
      'state could not be driven: NOT CHECKED, not a defect of the page');
    return;
  }
  ledger.chk(QUIET, /quiet some days/.test(message), 1, 'quiet day', message);
}

function finish(ledger, log) {
  var V = ledger.verdict();
  log('\n' + V.verdict + '  /wire/ in a real browser  (' + V.passes + ' PASS, ' + V.fails +
    ' FAIL, ' + V.notChecked + ' NOT CHECKED, of ' + V.total + ' checks)');
  return V.code;
}

module.exports = { quietDay: quietDay, finish: finish };
