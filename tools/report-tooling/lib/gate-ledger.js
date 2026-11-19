'use strict';

/* The check ledger of a browser gate (check-browser-wire.js, both modes), held apart so `npm test` can prove its verdicts without a browser (T-0500.1.7.4 fix-r2, review finding S1).

   chk(name, pass, n, unit, detail)  one check with its denominator. n is how many things it examined. A check that examined none (n not above zero) is NOT CHECKED, whatever `pass` says:
                                     homelab-soc/docs/gate-honesty-contract.md, "Every gate reports the number of items it verified, and returns NOT CHECKED at zero". It used to be
                                     mapped to FAIL, which reported an unexercised surface as a defect of the page and made a run with nothing to look at read as a broken site.
   plain(name, pass, detail)         one check with no denominator: a property of one rendered element (is this control painted, is the console clean). No count of items is the thing
                                     examined, and writing n=1 for every probe would fill the [n=] column with a constant and hide the true zero. It is PASS or FAIL only; a check that
                                     could not run is `skipped`, which keeps NOT CHECKED meaning "not exercised", never "examined nothing".
   skipped(name, why)                a check that could not run: NOT CHECKED.
   verdict()                         FAIL (exit 1) if any check FAILed, else NOT CHECKED (exit 2) if any was NOT CHECKED, else PASS (exit 0). A FAIL outranks a NOT CHECKED. */

function makeLedger(log) {
  var checks = [];
  log = log || function () {};
  function label(verdict) {
    return verdict === 'PASS' ? 'PASS  ' : verdict === 'FAIL' ? 'FAIL  ' : 'NOT CHECKED  ';
  }
  function chk(name, pass, n, unit, detail) {
    var verdict = pass ? 'PASS' : 'FAIL';
    if (!(n > 0)) { verdict = 'NOT CHECKED'; detail = 'ZERO DENOMINATOR: nothing was examined. ' + (detail || ''); }
    checks.push({ name: name, verdict: verdict });
    log('   ' + label(verdict) + name + '  [n=' + (n || 0) + ' ' + unit + ']');
    if (detail) log('         ' + detail);
  }
  function plain(name, pass, detail) {
    var verdict = pass ? 'PASS' : 'FAIL';
    checks.push({ name: name, verdict: verdict });
    log('   ' + label(verdict) + name + '  [no denominator]');
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
  return { checks: checks, chk: chk, plain: plain, skipped: skipped, verdict: verdict };
}

module.exports = { makeLedger: makeLedger };
