#!/usr/bin/env node
'use strict';

/* Drives a published report in a real browser.

   Three claim-matrix rows sat at NO GATE with the same sentence in different
   clothes: nothing proves the glossary tooltip renders, that a figure-nav chip
   click scrolls and opens the teardown it points at, or that the register switch
   hides a section and its TOC entry. All three are BUILT BY JAVASCRIPT AT
   RUNTIME: a fetched report contains no `.hl-viewswitch` and no `.hl-fignav` at
   all, only the tier markers and figures they are built from: so every check
   that reads fetched HTML is looking at the inputs and calling them the output.

   jsdom cannot close the gap either: it has no layout, so every rect is zero,
   which is exactly what defeated the glossary's edge-flip measurement.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. A missing browser, an unreachable site or
   a report that carries none of the machinery is NOT CHECKED with the reason
   named, never a pass.

   Run: node check-browser-report.js [slug] [--shots <dir>]
   Env: HL_CHROME, HL_SITE_BASE */

var path = require('node:path');
var fs = require('node:fs');
var https = require('node:https');

var ROOT = path.join(__dirname, '..', '..');
var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');

var args = process.argv.slice(2);
var shotsDir = null;
var si = args.indexOf('--shots');
if (si > -1) { shotsDir = args[si + 1]; args.splice(si, 2); }
var slug = args[0] || null;

function notChecked(reason) {
  console.log('NOT CHECKED  ' + reason);
  process.exit(2);
}

var CDP, SERVER, TRIAGE, yaml;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  TRIAGE = require('./lib/console-triage.js');
  yaml = require('js-yaml');
} catch (e) {
  notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.');
}

function fetchText(url) {
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { 'user-agent': 'hl-browser-check' } }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(url + ' returned HTTP ' + res.statusCode));
      }
      var b = '';
      res.setEncoding('utf8');
      res.on('data', function (d) { b += d; });
      res.on('end', function () { resolve(b); });
    }).on('error', reject);
  });
}

/* Pick a report that actually exercises ALL of the machinery, not merely the
   first in the catalog.

   A report with no tier markers lets every register-switch check pass by finding
   nothing to hide, and a report that declares no figure_nav turns three chip
   checks into NOT CHECKED. 17 of the corpus declare figure_nav and 41 carry
   tiers, so one with both is easy to find and is the only kind that verifies
   anything. Scoring prefers both, then depth. */
function pickSlug() {
  if (slug) return slug;
  var cat;
  try {
    cat = yaml.load(fs.readFileSync(path.join(ROOT, '_data', 'catalog.yml'), 'utf8'));
  } catch (e) { return null; }
  /* Array first, explicitly. Every Array has an `entries` METHOD, so the
     familiar `(cat && cat.entries) || cat` yields a function for a bare array
     and silently selects nothing. See lib/download-targets.js for the full note.
     _data/catalog.yml is a mapping with an `entries:` key, which is why this
     shape has worked. */
  var entries = Array.isArray(cat) ? cat
    : (cat && Array.isArray(cat.entries) ? cat.entries : []);
  var best = null, bestScore = -1;
  entries.forEach(function (e) {
    if (!e || !e.report_url) return;
    var s = String(e.report_url).replace(/^\/reports\//, '').replace(/\/$/, '');
    var md = path.join(ROOT, 'reports', s, 'index.md');
    if (!fs.existsSync(md)) return;
    var text = fs.readFileSync(md, 'utf8');
    var tiers = (text.match(/hl-tier-/g) || []).length;
    if (!tiers) return;
    // Carrying figure_nav is worth more than any amount of extra depth.
    var score = tiers + (/^figure_nav:/m.test(text) ? 10000 : 0);
    if (score > bestScore) { bestScore = score; best = s; }
  });
  return best;
}

var results = [];
function check(name, pass, detail) {
  results.push({ name: name, pass: pass });
  console.log('   ' + (pass ? 'PASS  ' : 'FAIL  ') + name);
  if (detail) console.log('         ' + detail);
}

/* Everything this file measures on first read of the page -- the register
   switch, the figure-nav chips, the TOC -- is BUILT BY JAVASCRIPT after load,
   and `CDP.open()` only waits a FIXED settle (opts.settle, default 2500ms)
   before handing back a page handle. That is a guess, not a measurement, and
   on a cold HTTP cache it is sometimes wrong.

   Measured 2026-09-22, the SAME report run twice back to back with nothing
   else changed:

     run 1  14 H2 sections on load, 0 of 43 TOC items hidden by the brief
            register  -> both register-switch checks FAIL
     run 2  13 H2 sections on load, 11 of 64 TOC items hidden by the brief
            register  -> both PASS

   The H2 count differs, the TOC link count differs, and even the register's
   own computed reading time differs between runs. That is not flakiness in
   the check, it is the page still assembling itself at read time: run 1
   measured a DOM that had not finished building.

   The fix is not a longer fixed sleep -- that only narrows the window, it
   does not close it, and it makes every run slower whether or not the page
   needed the extra time. Instead, poll `inputs` (the same five counts
   already printed below) until two CONSECUTIVE reads agree, bounded by a
   deadline. Two matching reads in a row is the cheapest signal available
   that the mutations driving these numbers (tier markers, figures,
   teardowns, headings, TOC links) have stopped, without asserting anything
   further about what "finished" means for a page this file does not own.

   This must not turn into a check that can no longer FAIL. A report that
   genuinely never builds the machinery (wrong slug, a broken bundle) holds
   at zero for every count, and zero agrees with zero on the very next read
   -- it settles almost immediately and still reports zero, so the existing
   "carries none of the machinery" branch below fires exactly as before.
   Waiting only changes the answer for a page that is still CHANGING; it
   never invents a value for one that is genuinely, permanently absent. */
var INPUTS_EXPR = '(function(){return {' +
  'tiers: document.querySelectorAll("[class*=hl-tier-]").length,' +
  'figures: document.querySelectorAll(".hl-post-content figure").length,' +
  'teardowns: document.querySelectorAll("details.hl-teardown").length,' +
  'headings: document.querySelectorAll(".hl-post-content h2").length,' +
  'tocLinks: document.querySelectorAll("#hl-toc-list a").length};})()';

async function waitForStableInputs(page) {
  var pollMs = 250;
  var deadlineMs = 8000; // matches CDP.waitFor's own default deadline
  var start = Date.now();
  var prevStr = null;
  var reads = 0;
  var cur;
  for (;;) {
    cur = await page.json(INPUTS_EXPR);
    reads++;
    var curStr = JSON.stringify(cur);
    var elapsed = Date.now() - start;
    if (curStr === prevStr) {
      return { inputs: cur, settled: true, waitedMs: elapsed, reads: reads };
    }
    prevStr = curStr;
    if (elapsed >= deadlineMs) {
      // Report what was last seen, honestly labelled as unsettled, rather
      // than silently treating a deadline hit as a clean read.
      return { inputs: cur, settled: false, waitedMs: elapsed, reads: reads };
    }
    await CDP.sleep(pollMs);
  }
}

/* Defect 2, mine, from wiring this an hour ago: one blocked request yields
   TWO console-triage records (a network failure and a console log entry),
   so the same excluded URL printed its full multi-sentence reason twice in
   a row. That is not a counting bug -- `triaged.total` and the three bucket
   lengths must keep counting every record, exactly as before -- it is a
   PRINTING bug: the same fact stated twice, at full length, is unreadable.

   Grouping happens HERE, not in lib/console-triage.js: the module's counts
   stay one-record-per-event (that is what the summary line's three numbers
   mean), and only this on-screen listing collapses duplicates by URL. */
function groupExcludedForDisplay(rows) {
  var order = [];
  var byKey = {};
  (rows || []).forEach(function (row) {
    var key = row.url || '(no url)';
    if (!byKey[key]) {
      byKey[key] = { url: row.url, why: row.why, count: 0 };
      order.push(key);
    }
    byKey[key].count++;
  });
  return order.map(function (key) { return byKey[key]; });
}

var EXCLUDED_REASON_MAX = 140;
function renderExcludedGroup(g) {
  var reason = g.why.length > EXCLUDED_REASON_MAX
    ? g.why.slice(0, EXCLUDED_REASON_MAX - 3) + '...'
    : g.why;
  return (g.url || '(no url)') + (g.count > 1 ? '  (x' + g.count + ')' : '') +
    '  -- ' + reason;
}

async function main() {
  var s = pickSlug();
  if (!s) notChecked('no report slug given and none could be picked from _data/catalog.yml');

  var html;
  try {
    html = await fetchText(BASE + '/reports/' + s + '/');
  } catch (e) {
    notChecked('could not fetch /reports/' + s + '/ (' + e.message + '), so nothing ' +
      'was verified in a browser.');
  }

  var srv = await SERVER.start({ ['/reports/' + s + '/']: html }, { root: ROOT, base: BASE });
  var page;
  try {
    page = await CDP.open(srv.origin + '/reports/' + s + '/', { height: 1600 });
  } catch (e) {
    srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }

  /* Name the BROWSER, by brand, not only the engine string it reports over
     CDP. Brave identifies itself as `Chrome/153.x` because it is Chromium
     based, so every run of this gate printed `Chrome/...` and looked like it
     had run Chrome. A run that silently used a different browser than the
     checks were written against is the failure underneath every other one
     here, and it is invisible unless the harness says so out loud. */
  console.log('browser: ' + page.label);
  console.log('report:  ' + s);

  try {
    /* Everything below is built at runtime, so first prove the INPUTS exist.
       A report carrying no tier markers and no figures would let every check
       below pass by finding nothing, which is the shape of failure this whole
       convention exists to stop. */
    var settleResult = await waitForStableInputs(page);
    var inputs = settleResult.inputs;
    console.log('inputs:  ' + JSON.stringify(inputs));
    console.log('settle:  ' + (settleResult.settled
      ? 'stable after ' + settleResult.waitedMs + 'ms (' + settleResult.reads + ' reads)'
      : 'DEADLINE HIT after ' + settleResult.waitedMs + 'ms (' + settleResult.reads +
        ' reads); the page may still have been changing when this measured it'));
    console.log('');

    if (!inputs.tiers && !inputs.figures) {
      check('NOT CHECKED: this report carries none of the machinery', false,
        'no tier markers and no figures, so nothing here could be verified. ' +
        'Pass a slug that has them.');
      throw new Error('__notchecked__');
    }

    /* A published report embeds third-party resources a reader's browser
       fetches from someone else's origin: a Cloudflare analytics beacon and a
       newsletter form. Neither is a report module, and a privacy browser
       refuses the beacon by design.

       WHY THIS MOVED OUT OF A TEXT MATCH, measured 2026-09-22. The old list
       tested the console message TEXT, and a blocked subresource's text is
       exactly `Failed to load resource: net::ERR_CONNECTION_REFUSED` with no
       URL in it at all. So the URL-shaped entries in that list (eocampaign1,
       and the rest) could never match anything, and this check failed on all 43
       reports. The URL was available the whole time; cdp.js was discarding it.

       The decision now runs on ORIGIN first and NAME second, in
       lib/console-triage.js. A failure on the page's own origin can never be
       excluded by any naming rule, which is the property that lets a genuinely
       refused first-party module still fail loudly while a named third-party
       beacon is excluded. Adding /ERR_CONNECTION_REFUSED/ to a tolerance list
       instead would have blinded this check to exactly the failure it exists
       for, because Brave spells a blocked request with that same string.

       ALL THREE BUCKETS ARE PRINTED, INCLUDING ZEROS, so an empty bucket is
       distinguishable from one nobody measured, and every exclusion is named
       on screen rather than inferred from a count.
       See homelab-soc/docs/gate-honesty-contract.md. */
    var triaged = TRIAGE.triage(page.consoleErrorDetails(), srv.origin);
    console.log('   console  ' + triaged.total + ' error(s) on ' + srv.origin + ': ' +
      triaged.firstParty.length + ' first-party, ' + triaged.excluded.length +
      ' excluded by name, ' + triaged.unexplained.length + ' unexplained');
    groupExcludedForDisplay(triaged.excluded).forEach(function (g) {
      console.log('   note     excluded  ' + renderExcludedGroup(g));
    });
    /* Both buckets fail. An unexplained THIRD-PARTY error is not waved through:
       exclusion is by name, so an origin nobody has named is a thing to look at
       rather than a thing to assume is someone else's problem. */
    var failing = triaged.firstParty.concat(triaged.unexplained);
    check('no script error blocked the report modules', failing.length === 0,
      failing.length ? TRIAGE.renderFailing(failing).slice(0, 3).join(' | ') +
        (srv.misses.length ? '  [assets not served: ' + srv.misses.join(', ') + ']' : '')
        : 'clean: 0 first-party, 0 unexplained, ' + triaged.excluded.length +
          ' third-party error(s) excluded by name');

    // ---------- the register switch ----------
    var vs = await page.computed('.hl-viewswitch', ['display']);
    check('the register switch is BUILT and painted, not just declared',
      vs && vs._present && vs.display !== 'none' && vs._w > 50,
      vs && vs._present ? 'rendered ' + vs._w + 'x' + vs._h + ' from ' + inputs.tiers +
        ' tier markers' : 'ABSENT: the control never got built from ' + inputs.tiers + ' markers');

    var btns = await page.json('[].slice.call(document.querySelectorAll(".hl-viewswitch__btn"))' +
      '.map(function(b){return b.textContent.trim();})');
    check('it offers all three registers', btns.length === 3, btns.join(' | ') || 'none');

    var openH2 = await page.visibleCount('.hl-post-content h2');
    // Click the FIRST (most restrictive) register with a real pointer.
    await page.click('.hl-viewswitch__btn');
    await CDP.sleep(350);
    var briefH2 = await page.visibleCount('.hl-post-content h2');
    check('picking the briefest register actually hides sections',
      briefH2 < openH2 && briefH2 > 0,
      openH2 + ' H2 sections visible on load, ' + briefH2 + ' after picking "' +
        (btns[0] || '?') + '"');

    if (inputs.tocLinks) {
      /* Measured by the `hidden` ATTRIBUTE that register-switch.js actually sets
         on each `<li>`, not by rendered area.

         Two wrong measures were tried first and both gave confident wrong
         answers. Counting visible `<a>` reported 53 of 53 visible however many
         items were hidden, because computed `display` is the element's own value
         and does not inherit `none` from an ancestor. Counting rendered `<li>`
         then reported 0 of 53, because the TOC panel is collapsed by default, so
         every item has zero area whatever the register. The attribute is the
         mechanism and it is unambiguous in both states. */
      var toc = await page.json('(function(){var li=document.querySelectorAll("#hl-toc-list li");' +
        'var h=0;[].forEach.call(li,function(e){if(e.hasAttribute("hidden"))h++;});' +
        'return {total:li.length,hidden:h};})()');
      check('the TOC narrows with the page rather than pointing at hidden sections',
        toc.hidden > 0 && toc.hidden < toc.total,
        toc.hidden + ' of ' + toc.total + ' TOC items hidden in the brief register');
    } else {
      check('NOT CHECKED: this report renders no TOC to narrow', false,
        'the TOC needs 3+ H2s; this report has ' + inputs.headings);
    }

    // Restore the fullest register for the checks below.
    await page.evaluate('(function(){var b=document.querySelectorAll(".hl-viewswitch__btn");' +
      'if(b.length)b[b.length-1].click();})()');
    await CDP.sleep(350);
    var restored = await page.visibleCount('.hl-post-content h2');
    check('returning to the full register restores every section',
      restored === openH2, restored + ' of ' + openH2 + ' sections back');

    // ---------- figure-nav chips ----------
    var fignav = await page.json('(function(){var r=document.querySelector(".hl-fignav");' +
      'if(!r)return null;var c=getComputedStyle(r);var b=r.getBoundingClientRect();' +
      'var chips=[].slice.call(r.querySelectorAll("a"));' +
      'return {display:c.display,w:Math.round(b.width),chips:chips.length,' +
      'colors:chips.slice(0,3).map(function(a){return getComputedStyle(a).color;}),' +
      'targets:chips.map(function(a){return a.getAttribute("href");})};})()');
    if (!fignav) {
      check('NOT CHECKED: this report declares no figure-nav chips', false,
        inputs.figures + ' figures present but no chip row was built; only reports ' +
        'declaring figure_nav get one');
    } else {
      check('the figure-nav chips are built and painted',
        fignav.display !== 'none' && fignav.w > 50 && fignav.chips > 0,
        fignav.chips + ' chips, ' + fignav.w + 'px wide');

      /* The chips once shipped in the theme's link colour because
         `.hl-post-content a` is marked important and no test read CSS. */
      var themeLink = await page.evaluate(
        'getComputedStyle(document.querySelector(".hl-post-content a")).color');
      check('a chip is not painted in the theme link colour',
        fignav.colors.length > 0 && fignav.colors.some(function (c) { return c !== themeLink; }),
        'chips ' + fignav.colors.join(', ') + ' vs body links ' + themeLink);

      /* A real click must move the page to the chip's own target and, if that
         target sits inside a collapsed teardown, open it.

         The target is read from the chip's href, NOT from location.hash. The
         chips are ordinary anchors, but the smooth-scroll animation means the
         hash and the final scroll position both arrive late, and an earlier
         version of this check read an empty hash and called a working feature
         broken. The href is known before the click and cannot race. */
      var targetId = decodeURIComponent(String(fignav.targets[0] || '').slice(1));
      var before = await page.evaluate('Math.round(scrollY)');
      await page.click('.hl-fignav a');
      // Smooth scrolling is on, so the journey takes real time.
      await CDP.sleep(1200);
      var after = await page.json('(function(){var t=document.getElementById(' +
        JSON.stringify(targetId) + ');if(!t)return {found:false,y:Math.round(scrollY)};' +
        'var d=t.closest("details");var r=t.getBoundingClientRect();' +
        'return {found:true,y:Math.round(scrollY),top:Math.round(r.top),' +
        'inView:r.top>-120&&r.top<innerHeight,' +
        'inDetails:!!d,detailsOpen:d?d.open:null};})()');
      check('a real click on a chip scrolls to its target',
        after.found && after.y !== before,
        'scrollY ' + before + ' -> ' + after.y + ', target #' + targetId +
          (after.found ? '' : ' NOT FOUND IN DOM'));
      check('and the target lands in view, its teardown opened if it was collapsed',
        after.inView === true && after.detailsOpen !== false,
        'target ' + after.top + 'px from the viewport top; enclosing teardown: ' +
          (after.inDetails ? (after.detailsOpen ? 'open' : 'STILL CLOSED') : 'none'));
    }

    // ---------- the glossary ----------
    var gloss = await page.json('(function(){var m=document.querySelectorAll(".hl-gloss");' +
      'if(!m.length)return {marks:0};var e=m[0];var r=e.getBoundingClientRect();' +
      'return {marks:m.length,term:e.textContent.trim(),' +
      'title:e.getAttribute("data-hl-gloss")||e.getAttribute("title")||"",' +
      'w:Math.round(r.width),borderBottom:getComputedStyle(e).borderBottomStyle};})()');
    if (!gloss.marks) {
      check('NOT CHECKED: this report carries no glossary marks', false,
        'no .hl-gloss elements were created, so the tooltip could not be exercised');
    } else {
      check('glossary terms are marked in the rendered page',
        gloss.marks > 0 && gloss.w > 0,
        gloss.marks + ' marks, first is "' + gloss.term + '"');
      check('a mark is visually distinguished, not silently inert',
        gloss.borderBottom !== 'none' || !!gloss.title,
        'border-bottom: ' + gloss.borderBottom + ', tooltip text: ' +
          (gloss.title ? 'present' : 'ABSENT'));

      /* The tooltip lives in `.hl-gloss::after`, hidden at opacity 0 and
         visibility hidden until :hover or :focus. Read BOTH: an earlier version
         of this check also consulted `::before`, which has no rule at all and so
         computes to opacity 1 always, and that made the check pass on a page
         where the tooltip never opened. A gate that cannot fail is not a gate. */
      var tipState = function () {
        return page.json('(function(){var a=getComputedStyle(' +
          'document.querySelector(".hl-gloss"),"::after");' +
          'return {opacity:a.opacity,visibility:a.visibility,' +
          'hasText:(a.content||"none").length>8};})()');
      };
      var closed = await tipState();
      check('the definition is hidden until asked for',
        parseFloat(closed.opacity) === 0 || closed.visibility === 'hidden',
        'at rest: opacity ' + closed.opacity + ', visibility ' + closed.visibility);

      await page.forcePseudo('.hl-gloss', ['hover']);
      await CDP.sleep(250);
      var open = await tipState();
      check('hovering a term reveals its definition',
        parseFloat(open.opacity) > 0 && open.visibility === 'visible' && open.hasText,
        'hovered: opacity ' + open.opacity + ', visibility ' + open.visibility +
          ', definition text ' + (open.hasText ? 'present' : 'MISSING'));

      // The CSS binds :focus as well, which is what a keyboard reader gets.
      await page.forcePseudo('.hl-gloss', []);
      await CDP.sleep(150);
      await page.forcePseudo('.hl-gloss', ['focus']);
      await CDP.sleep(250);
      var focused = await tipState();
      check('and focusing it does the same, so it is reachable without a mouse',
        parseFloat(focused.opacity) > 0 && focused.visibility === 'visible',
        'focused: opacity ' + focused.opacity + ', visibility ' + focused.visibility);
      await page.forcePseudo('.hl-gloss', []);
    }

    if (shotsDir) {
      fs.mkdirSync(shotsDir, { recursive: true });
      await page.evaluate('window.scrollTo(0,0)');
      await CDP.sleep(400);
      console.log('   shot  ' + await page.screenshot(path.join(shotsDir, 'report-top.png')));
    }
  } catch (e) {
    if (e.message !== '__notchecked__') throw e;
  } finally {
    page.close();
    srv.close();
  }

  var failed = results.filter(function (r) { return !r.pass; });
  var notCheckedRows = failed.filter(function (r) { return /^NOT CHECKED/.test(r.name); });
  console.log('\n' + (failed.length ? (failed.length === notCheckedRows.length ? 'NOT CHECKED' : 'FAIL') : 'PASS') +
    '  /reports/' + s + '/ in a real browser  (' +
    (results.length - failed.length) + '/' + results.length + ' checks)');
  if (!failed.length) process.exit(0);
  process.exit(failed.length === notCheckedRows.length ? 2 : 1);
}

/* Defect: a crash here used to erase a FAIL that `results` already recorded.
   Example measured directly: a first-party module (register-switch.js) made
   genuinely unreachable correctly fails "no script error blocked the report
   modules", but the missing module then leaves `.hl-viewswitch__btn` never
   built, so the later `page.click('.hl-viewswitch__btn')` throws. That
   exception is not the `__notchecked__` sentinel, so it escapes the try/catch
   inside main() (see the rethrow there) and lands here -- and this handler
   used to call `notChecked(...)` unconditionally, reporting exit 2 for a run
   that had already found a real defect. Per
   homelab-soc/docs/gate-honesty-contract.md the three states (PASS/FAIL/NOT
   CHECKED) must stay distinguishable; a recorded FAIL must never be
   relabelled NOT CHECKED just because something else broke afterward.

   The fix reads `results` -- the same array `check()` has been pushing into
   all along -- for any row that is a genuine failure (not one of the
   'NOT CHECKED: ...'-named rows check() also uses to record an early,
   legitimate NOT CHECKED branch). If one exists, the run already failed
   before it crashed: print every recorded failure, print the crash message
   too (the reason the run aborted early is still information and must not
   be suppressed), and exit 1. Only when NOTHING has failed yet does a crash
   here still mean NOT CHECKED, exactly as before -- so the sentinel path
   (which never reaches this handler at all; it is caught and handled inside
   main() itself) and the "crashed before any check ran" path are both
   unchanged. */
main().catch(function (e) {
  var recordedFailures = results.filter(function (r) {
    return !r.pass && !/^NOT CHECKED/.test(r.name);
  });
  if (recordedFailures.length) {
    console.log('\nFAIL  the run aborted early: ' + recordedFailures.length +
      ' check(s) had already failed before the crash below.');
    recordedFailures.forEach(function (r) { console.log('   FAIL  ' + r.name); });
    console.log('\ncrash: ' + e.message);
    process.exit(1);
  }
  notChecked('the browser check errored before finishing: ' + e.message);
});
