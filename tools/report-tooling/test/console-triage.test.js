'use strict';

/* Tests for lib/console-triage.js.

   The bug this module fixes never showed up as a failing test, because
   nothing tested the CHOOSING half of check-browser-report.js's console
   check separately from an actual browser run. The exclusion list matched
   URL substrings against console text that carries no URL at all, so every
   report failed and nothing in the corpus caught it. This file is the test
   surface that should have existed.

   Two shapes get the most attention: the CONTROL (a first-party failure
   that must never be excluded, because a control that doesn't fire makes
   every negative in this module worthless -- see CLAUDE.md's YARA-sweep
   control-failure row for why that discipline exists) and the TRAP (a
   first-party URL that merely CONTAINS a benign third party's name, which
   is the whole reason origin is decided before any name is consulted). */

var test = require('node:test');
var assert = require('node:assert');
var T = require('../lib/console-triage.js');

var PAGE_ORIGIN = 'http://127.0.0.1:8080';
var REFUSED = 'Failed to load resource: net::ERR_CONNECTION_REFUSED';

/* ---- the control ---- */

test('CONTROL: a first-party script refused by the browser lands in firstParty', function () {
  // This is the failure the whole gate exists to catch. If this does not
  // fire, every negative result anywhere else in this file is worthless.
  var r = T.triage(
    [{ text: REFUSED, url: PAGE_ORIGIN + '/assets/js/register-switch.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 1, 'the control must fire');
  assert.equal(r.excluded.length, 0);
  assert.equal(r.unexplained.length, 0);
  assert.equal(r.firstParty[0].url, PAGE_ORIGIN + '/assets/js/register-switch.js');
});

/* ---- the trap: origin decides before any name is consulted ---- */

test('TRAP: a first-party URL containing a benign third party name as a substring stays firstParty', function () {
  var r = T.triage(
    [
      { text: REFUSED, url: PAGE_ORIGIN + '/assets/js/eocampaign1.com-shim.js' },
      { text: REFUSED, url: PAGE_ORIGIN + '/vendor/cloudflareinsights.com/beacon.min.js' }
    ],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 2,
    'origin is decided from the URL\'s actual origin, never from a name match against its path');
  assert.equal(r.excluded.length, 0, 'neither may be reclassified by a naming rule');
  assert.equal(r.unexplained.length, 0);
});

/* ---- the two real third parties named in the case notes ---- */

test('the Cloudflare Web Analytics beacon is excluded by origin', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'https://static.cloudflareinsights.com/beacon.min.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 1);
  assert.ok(r.excluded[0].why, 'an excluded row must carry its reason');
  assert.equal(r.firstParty.length, 0);
  assert.equal(r.unexplained.length, 0);
});

test('the EmailOctopus newsletter form origin is excluded by origin', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'https://eocampaign1.com/some/form/asset.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 1);
  assert.ok(r.excluded[0].why);
  assert.equal(r.firstParty.length, 0);
  assert.equal(r.unexplained.length, 0);
});

/* ---- a thrown exception can never be waved through by a text rule ----

   The origin-first guarantee in the module header ("a failure on the page's
   own origin can NEVER be excluded by a naming rule") has a hole: origin can
   only be decided when the error carries a url, and cdp.js records EVERY
   thrown JavaScript exception with `url: null` (there is no url on
   `Runtime.exceptionThrown`'s own event -- see cdp.js's own comment on that
   choice). A thrown exception with no url got judged on text alone, against
   the two text-only rules below, and both of those rules exist for
   `Log.entryAdded` messages, never for a thrown exception. So a first-party
   script that throws, using either rule's wording, was invisible to this
   gate before this fix. Reproduced directly against `triage()` before the
   fix landed: two exception-shaped, url-less records both matched a text
   rule and landed in `excluded`, with zero left in `unexplained`. */

test('a first-party-shaped exception matching the requestStorageAccess text rule is NOT excluded', function () {
  var r = T.triage(
    [{ text: 'Uncaught TypeError: requestStorageAccess is not a function', url: null, source: 'exception' }],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 0,
    'a thrown exception can never be attributed to a third party on text alone');
  assert.equal(r.unexplained.length, 1, 'it must fail loudly instead of vanishing');
  assert.equal(r.firstParty.length, 0, 'it has no url, so it cannot be judged first-party either');
});

test('a first-party-shaped exception matching the third-party-cookie text rule is NOT excluded', function () {
  var r = T.triage(
    [{ text: 'Uncaught Error: third-party cookie handling failed in register-switch', url: null, source: 'exception' }],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 0,
    'a thrown exception can never be attributed to a third party on text alone');
  assert.equal(r.unexplained.length, 1);
  assert.equal(r.firstParty.length, 0);
});

test('a genuine url-less log-entry record (not an exception) is still excluded by text', function () {
  // The two text rules exist for real Log.entryAdded messages -- the
  // storage-access rejection and the cookie-policy notice raised by the
  // embedded EmailOctopus widget -- which is source 'log' or a CDP
  // Log.LogEntry source string, never 'exception'. That legitimate case
  // must keep working exactly as before.
  var r = T.triage(
    [
      { text: 'Uncaught (in promise) DOMException: requestStorageAccess: permission denied', url: null, source: 'log' },
      { text: 'Third-party cookie will be blocked in future Chrome versions', url: null, source: 'javascript' }
    ],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 2, 'a real log-entry record must still be excluded by text');
  assert.equal(r.unexplained.length, 0);
  assert.equal(r.firstParty.length, 0);
});

test('the bucket-sum invariant still holds with a mix of exceptions and log entries', function () {
  var mixed = [
    { text: 'Uncaught TypeError: requestStorageAccess is not a function', url: null, source: 'exception' },
    { text: 'Uncaught (in promise) DOMException: requestStorageAccess: permission denied', url: null, source: 'log' },
    { text: REFUSED, url: PAGE_ORIGIN + '/assets/js/register-switch.js', source: 'network' },
    { text: REFUSED, url: 'https://static.cloudflareinsights.com/beacon.min.js', source: 'network' }
  ];
  var r = T.triage(mixed, PAGE_ORIGIN);
  assert.equal(r.total, mixed.length);
  assert.equal(r.firstParty.length + r.excluded.length + r.unexplained.length, r.total,
    'no error may be silently dropped from all three buckets');
  assert.equal(r.firstParty.length, 1, 'the refused first-party script');
  assert.equal(r.excluded.length, 2, 'the Cloudflare beacon by origin, the genuine log-entry rejection by text');
  assert.equal(r.unexplained.length, 1, 'the exception-shaped requestStorageAccess record');
});

/* ---- an unnamed third party fails, because exclusion is by name ---- */

test('a third-party origin nobody named is unexplained, not excluded', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'https://unknown-cdn.example/x.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.unexplained.length, 1);
  assert.equal(r.excluded.length, 0);
  assert.equal(r.firstParty.length, 0);
});

/* ---- url-less messages: text patterns are the only tool available ---- */

test('a url-less requestStorageAccess message is excluded by text', function () {
  var r = T.triage(
    [{ text: 'Uncaught (in promise) DOMException: requestStorageAccess: permission denied', url: null }],
    PAGE_ORIGIN
  );
  assert.equal(r.excluded.length, 1);
  assert.ok(r.excluded[0].why);
  assert.equal(r.firstParty.length, 0);
  assert.equal(r.unexplained.length, 0);
});

test('a url-less message matching nothing is unexplained', function () {
  var r = T.triage(
    [{ text: 'Uncaught TypeError: Cannot read properties of undefined (reading \'open\')', url: null }],
    PAGE_ORIGIN
  );
  assert.equal(r.unexplained.length, 1, 'a genuine report-module error must fail, not vanish');
  assert.equal(r.excluded.length, 0);
  assert.equal(r.firstParty.length, 0);
});

/* ---- blob: URLs carry their creating origin as a prefix ---- */

test('a blob: URL created by the page under test is firstParty', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'blob:' + PAGE_ORIGIN + '/9b2f1a3c-0000-0000-0000-000000000000' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 1);
  assert.equal(r.excluded.length, 0);
  assert.equal(r.unexplained.length, 0);
});

test('a filesystem: URL created by the page under test is firstParty', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'filesystem:' + PAGE_ORIGIN + '/temporary/download.bin' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 1);
});

/* ---- a bare string input is tolerated ---- */

test('a bare string entry is tolerated and treated as url-less text', function () {
  assert.doesNotThrow(function () { T.triage([REFUSED], PAGE_ORIGIN); });
  var r = T.triage([REFUSED], PAGE_ORIGIN);
  assert.equal(r.total, 1, 'the entry must still be counted');
  // No URL and it matches none of the url-less text rules, so it fails
  // rather than silently disappearing.
  assert.equal(r.unexplained.length, 1);
});

/* ---- port matters ---- */

test('a different PORT on the same host is not first-party', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'http://127.0.0.1:9999/x.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 0, 'origin includes the port; 8080 and 9999 are different origins');
  assert.equal(r.unexplained.length, 1, 'an unnamed origin on the wrong port is still unexplained');
});

/* ---- a third party that merely mentions the page host in its query string ---- */

test('a third-party URL mentioning the page host only in its query string is NOT first-party', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'https://evil.example/?ref=' + encodeURIComponent(PAGE_ORIGIN) }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 0,
    'origin comes from the URL\'s own scheme+host+port, never from substring content');
  assert.equal(r.unexplained.length, 1, 'evil.example is not a named third party');
  assert.equal(r.excluded.length, 0);
});

/* ---- data: and about: are un-attributable, not third-party-and-fine ---- */

test('a data: URL is un-attributable and fails as unexplained, never waved through', function () {
  var r = T.triage(
    [{ text: 'Uncaught SyntaxError', url: 'data:text/javascript,syntax(error' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 0, 'data: has no origin to compare, so it cannot be first-party');
  assert.equal(r.excluded.length, 0, 'un-attributable is not the same claim as third-party-and-therefore-fine');
  assert.equal(r.unexplained.length, 1);
});

test('an about: URL is un-attributable and fails as unexplained', function () {
  var r = T.triage(
    [{ text: REFUSED, url: 'about:blank' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 0);
  assert.equal(r.excluded.length, 0);
  assert.equal(r.unexplained.length, 1);
});

/* ---- the required denominator ---- */

test('REQUIRED DENOMINATOR: total always equals the sum of the three buckets on a mixed input', function () {
  var mixed = [
    { text: REFUSED, url: PAGE_ORIGIN + '/assets/js/register-switch.js' },   // firstParty
    { text: REFUSED, url: PAGE_ORIGIN + '/assets/js/eocampaign1.com-shim.js' }, // firstParty (trap)
    { text: REFUSED, url: 'https://static.cloudflareinsights.com/beacon.min.js' }, // excluded
    { text: REFUSED, url: 'https://eocampaign1.com/form.js' },              // excluded
    { text: 'requestStorageAccess denied', url: null },                     // excluded
    { text: REFUSED, url: 'https://unknown-cdn.example/x.js' },             // unexplained
    { text: 'Uncaught TypeError: boom', url: null },                        // unexplained
    'bare string with no home'                                              // unexplained
  ];
  var r = T.triage(mixed, PAGE_ORIGIN);
  assert.equal(r.total, mixed.length, 'total must equal the input length, nothing dropped');
  assert.equal(r.firstParty.length + r.excluded.length + r.unexplained.length, r.total,
    'no error may be silently dropped from all three buckets');
  assert.equal(r.firstParty.length, 2);
  assert.equal(r.excluded.length, 3);
  assert.equal(r.unexplained.length, 3);
});

test('an empty input reports a zero denominator honestly, not a clean pass by omission', function () {
  var r = T.triage([], PAGE_ORIGIN);
  assert.equal(r.total, 0);
  assert.equal(r.firstParty.length, 0);
  assert.equal(r.excluded.length, 0);
  assert.equal(r.unexplained.length, 0);
});

/* ---- the exclusion list's own discipline: every entry must carry a reason ---- */

test('every default exclusion entry carries a non-empty why', function () {
  assert.ok(T.EXCLUSIONS.length > 0);
  T.EXCLUSIONS.forEach(function (ex) {
    assert.equal(typeof ex.why, 'string');
    assert.ok(ex.why.length > 20, 'a one-word reason is not a recorded reason: ' + JSON.stringify(ex));
    assert.ok(ex.origins || ex.textPattern, 'an exclusion must match on origin or on text, not neither');
  });
});

test('ERR_BLOCKED_BY_CLIENT is deliberately NOT carried forward as a text rule', function () {
  // Under origin-first matching it would be redundant for a named third
  // party (which is now excluded by origin) and actively wrong for a
  // first-party asset blocked for any reason -- exactly the failure this
  // gate exists to catch. A first-party script reported with that text
  // must still fail.
  var r = T.triage(
    [{ text: 'Failed to load resource: net::ERR_BLOCKED_BY_CLIENT', url: PAGE_ORIGIN + '/assets/js/critical.js' }],
    PAGE_ORIGIN
  );
  assert.equal(r.firstParty.length, 1, 'a first-party block must still be caught regardless of error text');
});

/* ---- render helpers: the calling check must be able to print what it excluded ---- */

test('excludedLine renders the URL and the reason', function () {
  var line = T.excludedLine({ url: 'https://static.cloudflareinsights.com/beacon.min.js', why: 'analytics beacon' });
  assert.ok(line.indexOf('https://static.cloudflareinsights.com/beacon.min.js') !== -1);
  assert.ok(line.indexOf('analytics beacon') !== -1);
});

test('failingLine renders the URL and the text for a first-party or unexplained row', function () {
  var line = T.failingLine({ url: PAGE_ORIGIN + '/assets/js/register-switch.js', text: REFUSED });
  assert.ok(line.indexOf(PAGE_ORIGIN + '/assets/js/register-switch.js') !== -1);
  assert.ok(line.indexOf(REFUSED) !== -1);
});

test('failingLine tolerates a url-less row', function () {
  var line = T.failingLine({ url: null, text: 'Uncaught TypeError: boom' });
  assert.ok(line.indexOf('Uncaught TypeError: boom') !== -1);
});

test('renderExcluded and renderFailing produce one line per row', function () {
  var r = T.triage(
    [
      { text: REFUSED, url: 'https://static.cloudflareinsights.com/beacon.min.js' },
      { text: REFUSED, url: PAGE_ORIGIN + '/assets/js/register-switch.js' }
    ],
    PAGE_ORIGIN
  );
  assert.equal(T.renderExcluded(r.excluded).length, 1);
  assert.equal(T.renderFailing(r.firstParty).length, 1);
});

/* ---- extractOrigin, the primitive everything else is built on ---- */

test('extractOrigin returns null for an unparseable string rather than throwing', function () {
  assert.equal(T.extractOrigin('not a url at all'), null);
  assert.equal(T.extractOrigin(''), null);
  assert.equal(T.extractOrigin(null), null);
  assert.equal(T.extractOrigin(undefined), null);
});

test('extractOrigin strips path, query and fragment down to scheme+host+port', function () {
  assert.equal(T.extractOrigin('https://example.com:8443/a/b?c=d#e'), 'https://example.com:8443');
});
