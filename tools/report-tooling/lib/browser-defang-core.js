'use strict';

/* The parts of check-browser-defang.js that can be judged without a browser, so `npm test` can hold them (T-0500.1.7.4 fix-r2, review findings S1, S5 and S6).

   - SERIALISE_FN   runs INSIDE the page: it writes the current value of every input and textarea back into the markup, so the scanner (which reads markup, jsdom) can see what a
                    script put in a box. The only text it leaves out is text the READER typed: an element the gate itself typed into (it matches `skip`) whose value is still exactly what
                    the gate typed (`typed`). A page script that rewrote the box, or a box nobody typed into, is judged. (Until fix-r2 `skip` blanked every matching element whatever it held
                    and the scanner never read a value attribute at all, so a script-written raw value in an input passed.)
   - captureExempt  which captured strings are exact by decision 5 and so counted, never judged: a COPY or DOWNLOAD taken from a rule block (<pre>) or, on a detection page, from the rule
                    picker (its "Download selected" bundle). A share is never exempt, and neither is anything else a detection page does: sharing the page title is page metadata, not a rule body.
   - verdictOf      the run's verdict from what was found and what could not be checked: any finding is FAIL (exit 1); otherwise any surface that could not be checked (a zero denominator,
                    an unreadable index, a scenario that did not run) makes the run NOT CHECKED (exit 2); only a run with neither is PASS (exit 0). gate-honesty-contract.md: NOT CHECKED is
                    never folded into PASS. */

var SERIALISE_FN = function (skip, typed, cutSel) {
  Array.prototype.forEach.call(document.querySelectorAll('input,textarea'), function (e) {
    var readers = !!skip && e.matches(skip) && typeof typed === 'string' && e.value === typed;
    if (e.tagName === 'TEXTAREA') e.textContent = readers ? '' : e.value;
    else e.setAttribute('value', readers ? '' : e.value);
  });
  if (!cutSel) return '<!DOCTYPE html>' + document.documentElement.outerHTML;
  // cutSel (the Wire details panels): the page without those panels, and the panels apart, each judged on its own
  var panels = Array.prototype.map.call(document.querySelectorAll(cutSel), function (n) { return n.outerHTML; });
  var c = document.documentElement.cloneNode(true);
  Array.prototype.forEach.call(c.querySelectorAll(cutSel), function (n) { n.textContent = ''; });
  return JSON.stringify({ html: '<!DOCTYPE html>' + c.outerHTML, panels: panels });
};

/* kind: clip / share / blob / exec (what the stubs captured). press: { inPre, inPicker } as the in-page driver recorded them. */
function captureExempt(pageType, press, kind) {
  if (kind === 'share') return false;                                  // a share sends page metadata (title, url) to a third party: always judged
  if (press && press.inPre) return true;                               // a copy or download taken from a rule block
  return pageType === 'detection' && !!(press && press.inPicker);      // the rule picker's bundle, on a detection page only
}

/* o: { findings: [...], unavailable: [ 'reason', ... ] } */
function verdictOf(o) {
  var f = (o.findings || []).length, u = (o.unavailable || []).length;
  if (f) return { status: 'FAIL', code: 1, findings: f, unavailable: u };
  if (u) return { status: 'NOT CHECKED', code: 2, findings: 0, unavailable: u };
  return { status: 'PASS', code: 0, findings: 0, unavailable: 0 };
}

module.exports = { SERIALISE_FN: SERIALISE_FN, captureExempt: captureExempt, verdictOf: verdictOf };
