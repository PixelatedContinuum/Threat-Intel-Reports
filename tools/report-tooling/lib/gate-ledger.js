'use strict';

/* The check ledger of a browser gate (check-browser-wire.js BUILT mode), held apart so `npm test` can prove its verdicts without a browser (T-0500.1.7.4 fix-r2, review finding S1).

   chk(name, pass, n, unit, detail)  one check with its denominator. n is how many things it examined. A check that examined none (n not above zero) is NOT CHECKED, whatever `pass` says:
                                     homelab-soc/docs/gate-honesty-contract.md, "Every gate reports the number of items it verified, and returns NOT CHECKED at zero". It used to be
                                     mapped to FAIL, which reported an unexercised surface as a defect of the page and made a run with nothing to look at read as a broken site.
   skipped(name, why)                a check that could not run: NOT CHECKED.
   verdict()                         FAIL (exit 1) if any check FAILed, else NOT CHECKED (exit 2) if any was NOT CHECKED, else PASS (exit 0). A FAIL outranks a NOT CHECKED. */

function makeLedger(log) {
  var checks = [];
  log = log || function () {};
  function chk(name, pass, n, unit, detail) {
    var verdict = pass ? 'PASS' : 'FAIL';
    if (!(n > 0)) { verdict = 'NOT CHECKED'; detail = 'ZERO DENOMINATOR: nothing was examined. ' + (detail || ''); }
    checks.push({ name: name, verdict: verdict });
    log('   ' + (verdict === 'PASS' ? 'PASS  ' : verdict === 'FAIL' ? 'FAIL  ' : 'NOT CHECKED  ') + name + '  [n=' + (n || 0) + ' ' + unit + ']');
    if (detail) log('         ' + detail);
  }
  function skipped(name, why) {
    checks.push({ name: name, verdict: 'NOT CHECKED' });
    log('   NOT CHECKED  ' + name);
    log('         ' + why);
  }
  function verdict() {
    var fails = checks.filter(function (c) { return c.verdict === 'FAIL'; }).length;
    var ncs = checks.filter(function (c) { return c.verdict === 'NOT CHECKED'; }).length;
    return { verdict: fails ? 'FAIL' : ncs ? 'NOT CHECKED' : 'PASS', code: fails ? 1 : ncs ? 2 : 0, fails: fails, notChecked: ncs, passes: checks.length - fails - ncs, total: checks.length };
  }
  return { checks: checks, chk: chk, skipped: skipped, verdict: verdict };
}

module.exports = { makeLedger: makeLedger };
