'use strict';

/* Sorting a browser's console errors into "the report is broken" versus
   "a third party we don't care about is broken", without ever letting the
   second swallow the first.

   Measured against the live site 2026-09-22 (see the case notes this module
   was cut from): the check-browser-report.js "no script error blocked the
   report modules" gate failed on EVERY report. The exclusion list it used
   matched against console TEXT, and Brave's block for a subresource comes
   back as the bare string

       Failed to load resource: net::ERR_CONNECTION_REFUSED

   which contains no URL at all. Several exclusion entries were URL
   substrings (an `eocampaign1\.com` pattern, for instance), and a URL
   pattern can never match a string that carries no URL, so those entries
   were dead on arrival and the gate had no way to ever pass. The URL was
   available the whole time on `entry.url` from CDP's `Log.entryAdded`; it
   was simply never looked at.

   This module is deliberately pure: no I/O, no browser, no requires beyond
   the `URL` global (which is a Node builtin, not a module). Everything a
   browser-driving check needs to decide is a matter of comparing strings
   already in hand, and that is exactly the kind of decision that broke
   silently once already and deserves to be tested without a browser. */

/* ---------------------------------------------------------------------
   Origin extraction.

   The load-bearing rule this whole module exists to enforce: origin is
   decided FIRST, from the URL alone, and nothing downstream may override
   it. A refused first-party module is precisely the failure the gate is
   built to catch, so no exclusion rule -- however it is spelled -- may
   reclassify a first-party URL as excluded.

   THE HOLE THIS HAD, closed below. Origin can only be decided when the
   error carries a url, and cdp.js records EVERY thrown JavaScript exception
   with `url: null` -- there is no url on `Runtime.exceptionThrown`'s own
   CDP event, and cdp.js says so and tags the record `source: 'exception'`
   rather than guessing one. A first-party script exception therefore had
   NO origin protection at all and was judged purely on the two text-only
   rules in the exclusion list below, both of which exist for
   `Log.entryAdded` messages (a storage-access rejection, a cookie-policy
   notice), never for a thrown exception. Reproduced directly: an exception
   whose text happened to contain "requestStorageAccess" or "third-party
   cookie" was silently excluded, invisible to the very gate built to catch
   a first-party module that throws. The fix in `matchExclusion` below is
   narrow and structural rather than another name to list: a text-only rule
   is barred from ever matching a record whose `source` is `'exception'`,
   full stop, because a thrown exception came from script executing IN the
   page and can never be attributed to a third party on the strength of its
   text alone.

   RESIDUAL RISK, stated rather than hidden. If a storage-access rejection
   or a cookie-policy notice ever arrives as an unhandled promise rejection
   -- i.e. as `Runtime.exceptionThrown` -- rather than as a `Log.entryAdded`
   entry, this fix stops excluding it and a report would start failing on
   it. That has not been observed: a sweep of 43 of 43 reports on
   2026-09-22 recorded 88 error rows and ZERO matching either text rule, so
   both rules -- and this risk -- are precautionary rather than measured
   against a real occurrence.

   `blob:` and `filesystem:` URLs carry their creating origin as a literal
   PREFIX (e.g. `blob:http://127.0.0.1:8080/9b2f-...`), which matters
   because the site's download surfaces build blob URLs for the files a
   reader saves -- a blob built by the page under test is exactly as
   first-party as the script that built it. Node's own `URL` happens to
   resolve `blob:` origins automatically, but relying on that would leave
   `filesystem:` (which Node treats as opaque and reports as the literal
   string "null") handled inconsistently by nothing but runtime luck.
   Stripping the scheme and re-parsing what's left is explicit and treats
   both schemes the same way on purpose. */
function extractOrigin(rawUrl) {
  if (!rawUrl) return null;
  var url = String(rawUrl);
  if (/^blob:/i.test(url)) return extractOrigin(url.slice('blob:'.length));
  if (/^filesystem:/i.test(url)) return extractOrigin(url.slice('filesystem:'.length));
  try {
    var origin = new URL(url).origin;
    /* `data:` and `about:` URLs are opaque: WHATWG's own algorithm gives
       the literal STRING "null" for `.origin` rather than throwing or
       returning JS `null`. Left unhandled, that string could accidentally
       equal a `pageOrigin` argument someone passed in wrong, and worse, it
       would read as "this error has a known origin" when it does not.
       Un-attributable is not the same claim as first-party OR third-party,
       so it falls through to `null` here and is judged on its exclusion
       rules alone below, never on a same-origin comparison it cannot pass
       honestly either way. */
    return origin === 'null' ? null : origin;
  } catch (e) {
    // A malformed or relative string parses as neither first-party nor a
    // named third party; it is judged on text rules only, same as data:/about:.
    return null;
  }
}

/* ---------------------------------------------------------------------
   The exclusion list.

   Second rule: exclusion is BY NAME. A third-party origin (or, for a
   message that genuinely carries no URL, a text shape) has to be named
   here explicitly, with a stated reason, before its failure stops counting
   against the gate. There is deliberately no catch-all for "any other
   third-party origin" -- an unnamed third party is `unexplained` and fails,
   the same as an unnamed first-party failure, because a catch-all is
   exactly how this list turns into a blanket that swallows a real defect.

   Every entry MUST carry a `why`: what the third party IS, and why its
   failure carries no information about a report module. An entry with no
   recorded reason is the thing `check_rule_ownership`-style discipline
   exists to prevent -- it is how a specific, justified exception quietly
   grows into "ignore everything".

   DESIGN CALL: the old list's `/ERR_BLOCKED_BY_CLIENT/i` text rule is NOT
   carried forward. Under origin-first matching it is redundant for the
   case it was written for (a blocked third party is now excluded by NAME,
   via its origin, not by the generic string every ad-blocker produces),
   and kept as a text rule it would be actively wrong: it would swallow a
   FIRST-PARTY asset blocked for any reason, which is precisely the
   failure this gate exists to catch. Third-party blocks are excluded by
   who they are, not by how the browser phrases blocking them. */
var EXCLUSIONS = [
  {
    origins: ['https://static.cloudflareinsights.com'],
    why: 'Cloudflare Web Analytics beacon, loaded by the Jekyll theme on ' +
      'every page. It is invisible to the reader, is not report content, ' +
      'and is routinely refused by ad/tracker blocking -- including this ' +
      'machine’s own Brave shields, which is how its failure was first ' +
      'observed (net::ERR_CONNECTION_REFUSED, measured 2026-09-22). Its ' +
      'failure says nothing about whether a report module loaded.'
  },
  {
    origins: ['https://eocampaign1.com'],
    why: 'EmailOctopus newsletter subscribe form embedded by the layout, a ' +
      'third-party marketing widget rather than a report module. NOT ' +
      'CURRENTLY OBSERVED FAILING: a sweep of 43 of 43 reports on ' +
      '2026-09-22 recorded 88 error rows and ZERO from this origin, so ' +
      'unlike the Cloudflare beacon this entry is precautionary rather ' +
      'than measured. It is kept because the embed is real and a blocker ' +
      'may refuse it, and its failure would say nothing about whether a ' +
      'report module loaded. Do not cite it as evidence this host is blocked.'
  },
  {
    origins: ['https://csp.withgoogle.com'],
    why: 'Google\'s CSP reporting endpoint. Reached because the EmailOctopus ' +
      'footer widget loads reCAPTCHA unconditionally on every page, and ' +
      'reCAPTCHA frames google.com; the report POST is a third party telling ' +
      'another third party about itself. Vector CONFIRMED by capture ' +
      '(2026-09-22: reCAPTCHA chain fired 184 times across 43 navigations); ' +
      'the causal link to this specific row is inferred at HIGH confidence, ' +
      'not instrumented. Intermittent, roughly 2 occurrences in ~95 page ' +
      'loads, which is exactly often enough to fail this gate at random.'
  },
  {
    /* Deliberately narrow. It requires the google.com framing AND the
       report-only wording, so a first-party CSP problem, or an ENFORCED
       violation of any kind, still fails. A bare /frame-ancestors/ would
       have masked both. */
    textPattern: /Framing 'https:\/\/www\.google\.com\/' violates[\s\S]*report-only/i,
    why: 'The console half of the reCAPTCHA row above, carrying no URL of ' +
      'its own. The directive is REPORT-ONLY, so nothing was blocked and the ' +
      'page behaved exactly as a reader would see it. It concerns a frame ' +
      'the newsletter widget created, never a report module.'
  },
  {
    textPattern: /requestStorageAccess/i,
    why: 'Storage-access API rejection raised by the embedded EmailOctopus ' +
      'widget above. Headless Chrome has no storage-access permission ' +
      'prompt UI to grant or deny, so the call always rejects there; this ' +
      'carries no URL of its own (it is a script-level API rejection, not ' +
      'a resource load), so it cannot be named by origin and is matched on ' +
      'its text instead.'
  },
  {
    textPattern: /third-party cookie/i,
    why: 'Browser-policy warning about third-party cookies, raised by the ' +
      'same embedded widget as the storage-access rejection above. It is a ' +
      'policy notice about the widget’s own cookie use, not a script ' +
      'failure in a report module, and like the storage-access message it ' +
      'carries no URL to name by origin.'
  }
];

/* ---------------------------------------------------------------------
   Tolerate a bare string (some callers just have console text with no
   structured record) by treating it as `{ text, url: null, source: null }`. */
function normalize(raw) {
  if (typeof raw === 'string') return { text: raw, url: null, source: null };
  var e = raw || {};
  return {
    text: e.text != null ? String(e.text) : '',
    url: e.url ? String(e.url) : null,
    source: e.source != null ? e.source : null
  };
}

/* Third rule: match on URL primarily. A text pattern is only ever consulted
   for an error that genuinely carries no URL -- the storage-access and
   third-party-cookie messages are the real examples; nothing else in the
   default list needs one. An error WITH a url is matched purely on its
   origin, never on its text, so a first-party error can never accidentally
   pick up a third-party exclusion's text pattern (or vice versa).

   FOURTH RULE, closing the hole in the file header above: a text pattern
   may NEVER match a record whose `source` is `'exception'`. A thrown
   exception is script executing in the page under test; its text can look
   like anything (including, by coincidence, one of the two phrases the
   text rules key on) and that tells us nothing about who threw it. `null`
   and every other source value (a real `Log.entryAdded` entry's `source`,
   or the `null` a bare string / legacy caller normalizes to) are still
   eligible for a text match exactly as before -- this bars ONE specific,
   named source value, not url-less matching in general. */
function matchExclusion(entry, origin, exclusions) {
  for (var i = 0; i < exclusions.length; i++) {
    var ex = exclusions[i];
    if (origin && Array.isArray(ex.origins) && ex.origins.indexOf(origin) !== -1) {
      return ex;
    }
    if (!entry.url && entry.source !== 'exception' && ex.textPattern && ex.textPattern.test(entry.text)) {
      return ex;
    }
  }
  return null;
}

/* The gate itself.

   `errors` -- array of `{ text, url, source }` records, or bare strings.
   `pageOrigin` -- the local origin the report under test is served from
     (e.g. `http://127.0.0.1:PORT`); everything on it is first-party,
     including a live-site asset the local server is proxying, because it
     is reached back through this origin (see fact 6 in the case notes).
   `exclusions` -- optional override of the default list above, for tests
     or for a future named entry; defaults to `EXCLUSIONS`.

   Returns `{ firstParty, excluded, unexplained, total }`. `total` always
   equals the sum of the three buckets' lengths by construction (every
   error is pushed into exactly one), so a caller can assert that as its
   own denominator check without trusting this module's arithmetic blindly. */
function triage(errors, pageOrigin, exclusions) {
  exclusions = exclusions || EXCLUSIONS;
  var pageOriginNorm = extractOrigin(pageOrigin) || String(pageOrigin || '');

  var firstParty = [];
  var excluded = [];
  var unexplained = [];

  (errors || []).forEach(function (raw) {
    var entry = normalize(raw);
    var origin = extractOrigin(entry.url);

    // RULE ONE, not overridable below: origin decides first.
    if (origin && origin === pageOriginNorm) {
      firstParty.push(entry);
      return;
    }

    var ex = matchExclusion(entry, origin, exclusions);
    if (ex) {
      excluded.push({ text: entry.text, url: entry.url, source: entry.source, why: ex.why });
      return;
    }

    unexplained.push(entry);
  });

  return {
    firstParty: firstParty,
    excluded: excluded,
    unexplained: unexplained,
    total: firstParty.length + excluded.length + unexplained.length
  };
}

/* ---------------------------------------------------------------------
   Rendering. The calling check has to PRINT what it excluded, not just
   count it -- an exclusion list nobody can see is indistinguishable from a
   check that silently passed. One line per row, in both directions. */

function excludedLine(row) {
  return (row.url || '(no url)') + '  -- ' + row.why;
}

function failingLine(row) {
  return (row.url ? row.url + '  ' : '') + row.text;
}

function renderExcluded(rows) {
  return (rows || []).map(excludedLine);
}

function renderFailing(rows) {
  return (rows || []).map(failingLine);
}

module.exports = {
  EXCLUSIONS: EXCLUSIONS,
  extractOrigin: extractOrigin,
  triage: triage,
  excludedLine: excludedLine,
  failingLine: failingLine,
  renderExcluded: renderExcluded,
  renderFailing: renderFailing
};
