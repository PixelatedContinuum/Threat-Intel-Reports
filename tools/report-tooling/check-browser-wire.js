#!/usr/bin/env node
'use strict';

/* Drives /wire/ in a real browser and asserts what jsdom cannot reach.

   The claim matrix carried "the Wire page renders and its links resolve" as
   NO GATE, with the note that it closes only with a real browser in the loop.
   This is that browser. It checks computed styles, real pointer input, and that
   the page transmits nothing while a reader filters it.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. A missing browser, an unreachable site or
   an absent dependency is NOT CHECKED with the reason named, never a pass.

   Two modes, chosen by where the page comes from.

   LIVE (the default): fetch https://the-hunters-ledger.com/wire/ and its theme
   sheet, put the working tree's stylesheet and filter module on it
   (lib/wire-harness.js `build`) and drive that. This is the original gate and
   its checks are unchanged; it expects the page's single flat list.

   BUILT (HL_SITE_DIR, or an http:// HL_SITE_BASE): drive a finished Jekyll
   `_site` exactly as built, with nothing substituted and nothing proxied. This
   is the mode for the three-tab Wire (Headlines #headlines, nKEVs #vulns, CVEs
   #cves, switched by :target and :has). Every expected count is read from the
   static HTML (`readBuilt`), so the browser's filtering is asserted against the
   markup the server sent, not against itself. Third-party https requests the
   page makes (analytics, a signup form) are blocked and counted, so the verdict
   never depends on someone else's server being up.

   Every BUILT check prints its denominator, [n=...], and a check whose
   denominator is zero is a FAIL, never a PASS.

   Run: node check-browser-wire.js [--shots <dir>]
   Env: HL_CHROME     path to a Chrome/Chromium binary
        HL_SITE_BASE  defaults to https://the-hunters-ledger.com; an http://127.0.0.1:PORT
                      (or localhost) base selects BUILT mode against a server you started
        HL_SITE_DIR   a built _site directory; the gate serves it itself (BUILT mode)
   e.g. HL_SITE_DIR=/path/to/_site node check-browser-wire.js */

var path = require('node:path');
var fs = require('node:fs');
var https = require('node:https');
var http = require('node:http');

var ROOT = path.join(__dirname, '..', '..');
var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');
var SITE_DIR = process.env.HL_SITE_DIR || '';
var BUILT_MODE = !!SITE_DIR || /^http:\/\//i.test(BASE);

var shotsDir = null;
var ai = process.argv.indexOf('--shots');
if (ai > -1 && process.argv[ai + 1]) shotsDir = process.argv[ai + 1];

function notChecked(reason) {
  console.log('NOT CHECKED  ' + reason);
  process.exit(2);
}

var CDP, HARNESS, SERVER, JSDOM;
try {
  CDP = require('./lib/cdp.js');
  HARNESS = require('./lib/wire-harness.js');
  SERVER = require('./lib/page-server.js');
  JSDOM = require('jsdom').JSDOM;
} catch (e) {
  notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.');
}

function fetchText(url) {
  var get = /^http:/i.test(url) ? http.get : https.get;
  return new Promise(function (resolve, reject) {
    get(url, { headers: { 'user-agent': 'hl-browser-check' } }, function (res) {
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

/* The harness is served over HTTP by lib/page-server.js rather than opened
   from file://, and that module carries the reasons. In short: under file:// the
   page's root-relative asset URLs resolve against the drive root and the font
   request fails CORS outright, filling the console with errors that say nothing
   about the site. This checker had its own copy of that server until the report
   checker needed the same thing; one definition of one rule. */

var results = [];
function check(name, pass, detail) {
  results.push({ name: name, pass: pass });
  console.log('   ' + (pass ? 'PASS  ' : 'FAIL  ') + name);
  if (detail) console.log('         ' + detail);
}

async function runLive() {
  var liveHtml, themeCss;
  try {
    liveHtml = await fetchText(BASE + '/wire/');
    themeCss = await fetchText(BASE + '/assets/css/main.css');
  } catch (e) {
    notChecked('could not fetch the live page or its theme stylesheet (' +
      e.message + '), so nothing was verified in a browser.');
  }

  var built;
  try {
    built = HARNESS.build(JSDOM, {
      liveHtml: liveHtml,
      themeCss: themeCss,
      customCss: fs.readFileSync(path.join(ROOT, 'assets', 'css', 'custom.scss'), 'utf8'),
      filterJs: fs.readFileSync(path.join(ROOT, 'assets', 'js', 'listing-filter.js'), 'utf8')
    });
  } catch (e) {
    notChecked('could not build the harness from the live page: ' + e.message);
  }

  /* Facts come from the corpus, never hardcoded, so this keeps working as the
     Wire rolls forward. The two that matter: a day with the most rows, and a
     day inside the window holding none. */
  var busiest = built.days.slice().sort(function (a, b) {
    return built.dayCounts[b] - built.dayCounts[a];
  })[0];
  var quiet = built.gaps[0] || null;
  var first = built.days[0];
  var last = built.days[built.days.length - 1];

  var srv = await SERVER.start({ '/wire/': built.html }, { root: ROOT, base: BASE });
  var origin = srv.origin;

  var page;
  try {
    page = await CDP.open(origin + '/wire/');
  } catch (e) {
    srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }

  // Brand, not just the Chromium engine string. See check-browser-report.js.
  console.log('browser: ' + page.label);
  console.log('corpus:  ' + built.rows + ' rows over ' + built.days.length +
    ' days (' + first + ' .. ' + last + '), busiest ' + busiest + '=' +
    built.dayCounts[busiest] + ', quiet day ' + (quiet || 'none'));
  console.log('');

  try {
    check('every row on the live page loaded',
      (await page.evaluate('document.querySelectorAll(".hl-wire__item").length')) === built.rows,
      built.rows + ' rows expected');

    /* The published template's own data-day, checked against the published
       page's own day headings. This is the only thing anywhere that sees the
       DEPLOYED template rather than the working tree, and a disagreement is the
       timezone split that carrying the day exists to prevent. Before the filter
       shipped, no row carried the attribute and this reports NOT CHECKED. */
    if (!built.deployed.carriedRows) {
      check('NOT CHECKED: the published page carries no data-day yet', false,
        'nothing to compare against its headings; the working-tree source shape is ' +
        'covered by check-wire.js instead');
    } else {
      check('the published data-day agrees with the published day headings',
        built.disagreements.length === 0,
        built.disagreements.length ? built.disagreements.join('; ')
          : built.deployed.carriedRows + ' of ' + built.rows + ' rows, every one matching');
    }

    var errs = page.consoleErrors();
    check('no script error blocked the filter module', errs.length === 0,
      errs.length ? errs.slice(0, 3).join(' | ') +
        (srv.misses.length ? '  [assets not served: ' + srv.misses.join(', ') + ']' : '')
        : 'clean console');

    // --- the control renders ---
    var di = await page.computed('[data-filter-date]',
      ['display', 'fontSize', 'colorScheme', 'backgroundColor']);
    check('the date control renders with real geometry',
      !!di && di._present && di._w > 60 && di._h > 20,
      di && di._present ? di._w + 'x' + di._h + ', display=' + di.display : 'ELEMENT ABSENT');
    check('the native picker glyph is legible on the dark field',
      di && di.colorScheme === 'dark', 'color-scheme = ' + (di && di.colorScheme));

    /* The `rem` trap. The theme sets body to 1.25em = 20px while `rem` resolves
       against the 16px root, so a rem-sized control renders 22% small. That gap
       exists only while the real theme sheet is in the cascade, so the baseline
       is proved first and reported NOT CHECKED rather than passed if it is not. */
    var bodyFs = parseFloat(await page.evaluate('getComputedStyle(document.body).fontSize'));
    var chipFs = await page.evaluate(
      'getComputedStyle(document.querySelector(".hl-chip-btn")).fontSize');
    if (bodyFs < 19) {
      check('NOT CHECKED: the rem trap needs the real theme cascade', false,
        'body computed at ' + bodyFs + 'px, expected ~20px; em and rem coincide here ' +
        'so this check could not tell them apart');
    } else {
      check('the date control is sized in em like its neighbours, not rem',
        di.fontSize === chipFs,
        'date input ' + di.fontSize + ' vs topic chip ' + chipFs + ' on a ' + bodyFs +
        'px body (the rem path would give 12.8px)');
    }

    /* `display: flex` on the row sets display on its children and overrides the
       `display: none` that the hidden attribute relies on, so a "hidden" control
       in a flex row is plainly visible without an explicit [hidden] rule. */
    var clr = await page.computed('[data-filter-date-clear]', ['display']);
    check('the clear-date control is truly invisible before a date is picked',
      clr._present && clr.display === 'none' && clr._w === 0,
      'display=' + clr.display + ', box ' + clr._w + 'x' + clr._h);

    var mm = await page.json('(function(){var e=document.querySelector("[data-filter-date]");' +
      'return {min:e.getAttribute("min"),max:e.getAttribute("max")};})()');
    check('min and max bound the input to the real corpus',
      mm.min === first && mm.max === last, JSON.stringify(mm));

    // --- filtering ---
    // Everything requested up to here is page load; anything after is not.
    var baseline = page.networkUrls().length;

    async function setDate(v) {
      await page.evaluate('(function(){var e=document.querySelector("[data-filter-date]");' +
        'e.value=' + JSON.stringify(v) + ';e.dispatchEvent(new Event("change",{bubbles:true}));})()');
      await CDP.sleep(150);
    }

    await setDate(busiest);
    var rBusy = await page.visibleCount('.hl-wire__item');
    var dBusy = await page.visibleCount('[data-filter-group]');
    check('picking the busiest day shows exactly its rows under one heading',
      rBusy === built.dayCounts[busiest] && dBusy === 1,
      rBusy + ' rows under ' + dBusy + ' heading (expected ' + built.dayCounts[busiest] + ' under 1)');

    var cnt = await page.evaluate('document.querySelector("[data-filter-count]").textContent');
    check('the count line reports the narrowing',
      cnt === 'Showing ' + built.dayCounts[busiest] + ' of ' + built.rows, '"' + cnt + '"');

    var clr2 = await page.computed('[data-filter-date-clear]', ['display']);
    check('the clear-date control appears once a date is set',
      clr2.display !== 'none' && clr2._w > 20, 'display=' + clr2.display + ' width=' + clr2._w);

    // A real pointer press and release, not el.click().
    await page.click('[data-filter-date-clear]');
    var rAll = await page.visibleCount('.hl-wire__item');
    var dAll = await page.visibleCount('[data-filter-group]');
    var val = await page.evaluate('document.querySelector("[data-filter-date]").value');
    check('a real pointer click on Clear date restores every row',
      rAll === built.rows && dAll === built.days.length && val === '',
      rAll + ' rows, ' + dAll + ' headings, input value "' + val + '"');

    // --- the two empty states ---
    if (quiet) {
      await setDate(quiet);
      var qm = await page.evaluate('document.querySelector("[data-filter-empty-msg]").textContent');
      check('a quiet day inside the window says so and names the date',
        /quiet some days/.test(qm), qm);
    } else {
      check('NOT CHECKED: no empty day inside the current window to exercise', false,
        'every day in the corpus currently carries at least one item');
    }

    await setDate('2020-01-05');
    var om = await page.evaluate('document.querySelector("[data-filter-empty-msg]").textContent');
    check('a date outside the window states the real bounds instead',
      /outside the window/.test(om), om);

    /* The date must not be blamed for another filter's emptiness. A day holding
       headlines that a topic chip removed is not a quiet day, and saying so is
       false. Found by looking at a screenshot after every other check passed. */
    var withTag = built.days.filter(function (d) { return built.dayCounts[d] > 0; })[0];
    await setDate(withTag);
    await page.evaluate('(function(){var s=document.querySelector(".hl-filter__search");' +
      's.value="zzz-no-such-headline";s.dispatchEvent(new Event("input",{bubbles:true}));})()');
    await CDP.sleep(150);
    var fm = await page.evaluate('document.querySelector("[data-filter-empty-msg]").textContent');
    check('a day with headlines is not called quiet when another filter emptied it',
      !/quiet/.test(fm) && /No headlines match that filter/.test(fm),
      withTag + ' holds ' + built.dayCounts[withTag] + ' headlines. message: "' + fm + '"');

    /* --- privacy ---
       The claim is that filtering transmits nothing, not that the page loads no
       assets. So the baseline is everything requested up to the first filter
       interaction, and anything after it is a real transmission. */
    var after = page.networkUrls().slice(baseline).filter(function (u) {
      return u.indexOf('data:') !== 0;
    });
    check('nothing was transmitted while the reader filtered',
      after.length === 0,
      after.length ? after.slice(0, 5).join(', ') :
        'none, against ' + baseline + ' asset requests at page load');

    if (shotsDir) {
      fs.mkdirSync(shotsDir, { recursive: true });
      await page.evaluate('document.querySelector("[data-filter-reset]").click()');
      await setDate(busiest);
      await page.evaluate('window.scrollTo(0,0)');
      await CDP.sleep(400);
      console.log('   shot  ' + await page.screenshot(path.join(shotsDir, 'wire-date-day.png')));
      if (quiet) {
        await setDate(quiet);
        await page.evaluate('window.scrollTo(0,0)');
        await CDP.sleep(400);
        console.log('   shot  ' + await page.screenshot(path.join(shotsDir, 'wire-date-quiet.png')));
      }
    }
  } finally {
    page.close();
    srv.close();
  }

  var failed = results.filter(function (r) { return !r.pass; });
  console.log('\n' + (failed.length ? 'FAIL' : 'PASS') + '  /wire/ in a real browser  (' +
    (results.length - failed.length) + '/' + results.length + ' checks)');
  process.exit(failed.length ? 1 : 0);
}


/* ======================================================================
   BUILT mode: the three-tab Wire, driven as built.
   ====================================================================== */

var LEDGER = require('./lib/gate-ledger.js').makeLedger(function (l) { console.log(l); });   // chk / skipped / verdict: see lib/gate-ledger.js (a zero denominator is NOT CHECKED, not FAIL)
var checks = LEDGER.checks, chk = LEDGER.chk;

/* A step that threw (an element the page was meant to have is not there) is a FAIL of that step,
   not the end of the run: the gate keeps going and says what it could not do. A browser that died
   (e.notChecked) is not the page's fault and still ends the run as NOT CHECKED. */
function aborted(step, e) {
  if (e && e.notChecked) throw e;
  chk(step + ' ran to the end', false, 1, 'steps', 'aborted: ' + String(e && e.message).replace(/\s+/g, ' ').slice(0, 260));
}
var skipped = LEDGER.skipped;

// "rgb(1, 2, 3)" and "color(srgb 0.1 0.2 0.3)" both come out of getComputedStyle; read either as 0-255.
function parseColor(c) {
  var m = String(c).match(/^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/);
  if (m) return [Number(m[1]), Number(m[2]), Number(m[3])];
  m = String(c).match(/^color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
  if (m) return [Number(m[1]) * 255, Number(m[2]) * 255, Number(m[3]) * 255];
  return null;
}
function near(a, b, tol) {
  return !!a && !!b && Math.abs(a[0] - b[0]) <= tol && Math.abs(a[1] - b[1]) <= tol && Math.abs(a[2] - b[2]) <= tol;
}

/* Painted elements that reach past the viewport with no scroll or clip box
   between them and <body>. `html { overflow-x: clip }` hides a too-wide element
   from scrollWidth, so scrollWidth alone cannot be the test (see
   check-browser-report.js OVERFLOW_EXPR, whose test this is). Returns how many
   painted elements were examined, so a page that painted nothing is not clean. */
var OVERFLOW_JS = '(function(){var de=document.documentElement,client=de.clientWidth;' +
  'window.scrollTo(9999,window.scrollY);var sx=Math.round(window.scrollX);window.scrollTo(0,window.scrollY);' +
  'var escaped=[],painted=0,all=document.body.querySelectorAll("*");' +
  'for(var i=0;i<all.length;i++){var e=all[i],r=e.getBoundingClientRect();if(r.width<=0&&r.height<=0)continue;painted++;' +
  'if(r.right<=client+1&&r.left>=-1)continue;var a=e.parentElement,clipped=false;' +
  'while(a&&a!==document.body){var c=getComputedStyle(a);if(/auto|scroll|hidden|clip/.test(c.overflowX)){clipped=true;break}a=a.parentElement}' +
  'if(!clipped)escaped.push(e.tagName+"."+String(e.className||"").slice(0,40)+" "+Math.round(r.left)+".."+Math.round(r.right));}' +
  'return {client:client,scrollX:sx,painted:painted,escaped:escaped.length,first:escaped.slice(0,3)};})()';

async function runBuilt() {
  var srv = null, origin;
  if (SITE_DIR) {
    try { srv = await SERVER.startDir(SITE_DIR); }
    catch (e) { notChecked(e.message); }
    origin = srv.origin;
  } else {
    origin = BASE;
  }

  var html;
  try { html = await fetchText(origin + '/wire/'); }
  catch (e) {
    if (srv) srv.close();
    notChecked('could not fetch ' + origin + '/wire/ (' + e.message + '), so nothing was verified in a browser.');
  }
  var facts;
  try { facts = HARNESS.readBuilt(JSDOM, html); }
  catch (e) { if (srv) srv.close(); notChecked('could not read the page: ' + e.message); }

  var page;
  try { page = await CDP.open('about:blank', { settle: 50 }); }
  catch (e) {
    if (srv) srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }
  var ev = page.evaluate;
  function sleep(ms) { return CDP.sleep(ms); }
  async function until(expr, ms) {
    var end = Date.now() + (ms || 8000);
    for (;;) {
      if (await ev(expr)) return true;
      if (Date.now() > end) return false;
      await sleep(100);
    }
  }
  async function setViewport(w, h) {
    await page.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
    await page.send('Emulation.setTouchEmulationEnabled', { enabled: w < 1024, maxTouchPoints: 5 });
    await sleep(150);
  }

  var S = facts.sections;
  var ids = HARNESS.TAB_IDS;
  var labels = { headlines: 'Headlines', vulns: 'nKEVs', cves: 'CVEs' };

  try {
    /* Third-party https is cut off before the page loads. The pages ask for
       analytics and a signup form; whether those answer says nothing about the
       Wire, and a gate that waited on them would pass or fail with the weather. */
    await page.send('Network.setBlockedURLs', { urls: ['https://*', 'wss://*'] });
    await setViewport(1440, 900);
    await page.send('Page.navigate', { url: origin + '/wire/' });
    // An empty list satisfies every(), so the number of count lines is part of the question.
    var up = await until('!!document.querySelector(".hl-wtabs__tab") && ' +
      'document.querySelectorAll("[data-filter-count]").length===' + ids.length + ' && ' +
      '[].every.call(document.querySelectorAll("[data-filter-count]"), function(e){return /^Showing /.test(e.textContent)})', 15000);
    var barCount = await ev('document.querySelectorAll("[data-filter-count]").length');

    console.log('browser: ' + page.label);
    console.log('site:    ' + (SITE_DIR ? 'HL_SITE_DIR ' + path.resolve(SITE_DIR) : origin) + '  (BUILT mode, nothing substituted)');
    console.log('corpus:  ' + ids.map(function (i) { return labels[i] + ' ' + S[i].rows.length; }).join(', ') +
      ' rows; ' + ids.map(function (i) { return S[i].days.length; }).join('/') + ' days');
    console.log('');

    var shown = function (id) {
      return ev('(function(){var e=document.getElementById(' + JSON.stringify(id) + ');if(!e)return false;' +
        'var r=e.getBoundingClientRect();return getComputedStyle(e).display!=="none"&&r.width>0&&r.height>0;})()');
    };
    var hashNow = function () { return ev('location.hash'); };
    var txt = function (sel) { return ev('(document.querySelector(' + JSON.stringify(sel) + ')||{}).textContent||""'); };
    var vis = function (sel) { return page.visibleCount(sel); };
    var goto = async function (hash) {
      await page.send('Page.navigate', { url: origin + '/wire/' + hash });
      await until('!!document.querySelector(".hl-wtabs__tab")', 8000);
      await sleep(250);
    };
    // A real press-and-release on one filter chip, found by what it filters rather than its position.
    async function clickChip(sec, axis, value) {
      var found = await ev('(function(){var bs=document.querySelectorAll("#' + sec + ' [data-listing-filter] .hl-chip-btn");' +
        'for(var i=0;i<bs.length;i++){var v=bs[i].getAttribute("data-' + axis + '");' +
        'if(v!==null&&v.toLowerCase()===' + JSON.stringify(value) + '){bs[i].setAttribute("data-hlgate","1");return true}}return false})()');
      if (!found) return false;
      await page.click('[data-hlgate="1"]');
      await ev('(function(){var e=document.querySelector("[data-hlgate]");if(e)e.removeAttribute("data-hlgate")})()');
      await sleep(250);
      return true;
    }
    async function setSearch(sec, v) {
      await ev('(function(){var s=document.querySelector("#' + sec + ' .hl-filter__search");s.value=' + JSON.stringify(v) +
        ';s.dispatchEvent(new Event("input",{bubbles:true}))})()');
      await sleep(250);
    }

    /* ---- 1. the page's structure, as sent ---- */
    chk('the page was read and the three tabs name three sections that exist',
      facts.tabs.length === 3 && facts.problems.length === 0 &&
        facts.tabs.map(function (t) { return t.id; }).join() === ids.join(),
      facts.tabs.length, 'tabs',
      facts.tabs.map(function (t) { return t.label + ' ' + t.href; }).join(', ') +
        (facts.problems.length ? '  PROBLEMS: ' + facts.problems.join('; ') : ''));

    var tabNames = facts.tabs.map(function (t) { return t.label; }).join();
    chk('the tabs are named Headlines, nKEVs and CVEs',
      tabNames === 'Headlines,nKEVs,CVEs', facts.tabs.length, 'tabs', 'found: ' + tabNames);

    var empties = ids.filter(function (i) { return !S[i].rows.length; });
    chk('every tab section holds rows',
      empties.length === 0, ids.length, 'tab sections',
      ids.map(function (i) { return i + '=' + S[i].rows.length; }).join(', ') +
        (empties.length ? '  EMPTY: ' + empties.join(', ') : ''));

    var badgeBad = facts.tabs.filter(function (t) {
      var rows = S[t.id] ? S[t.id].rows : [];
      var n = t.id === 'headlines' ? rows.filter(function (r) { return r.kind.indexOf('vuln') < 0; }).length : rows.length;
      return t.count !== n;
    });
    chk('each tab badge counts its section\'s rows (Headlines excludes the vuln digest rows)',
      badgeBad.length === 0, facts.tabs.length, 'tab badges',
      facts.tabs.map(function (t) { return t.label + ' badge ' + t.count; }).join(', ') +
        (badgeBad.length ? '  MISMATCH: ' + badgeBad.map(function (t) { return t.label; }).join(', ') : ''));

    var dis = [];
    ids.forEach(function (i) { dis = dis.concat(S[i].disagreements); });
    var dayRows = ids.reduce(function (a, i) { return a + S[i].rows.length; }, 0);
    chk('every row\'s data-day agrees with the day heading it sits under',
      dis.length === 0, dayRows, 'rows', dis.length ? dis.join('; ') : 'all three tabs');

    /* ---- 2. what loaded ---- */
    chk('the filter modules started (each of the three bars prints a count line)', up, barCount, 'count lines',
      up ? 'every [data-filter-count] reads "Showing N of M"' : barCount + ' count line(s) in the page, expected ' + ids.length +
        ', and each must read "Showing N of M"');

    var loaded = {};
    for (var li = 0; li < ids.length; li++) {
      var id0 = ids[li];
      loaded[id0] = S[id0].itemSel ? await ev('document.querySelectorAll(' + JSON.stringify('#' + id0 + ' ' + S[id0].itemSel) + ').length') : 0;
    }
    var loadBad = ids.filter(function (i) { return loaded[i] !== S[i].rows.length; });
    chk('every row the server sent is in the browser\'s DOM',
      loadBad.length === 0, dayRows, 'rows',
      ids.map(function (i) { return i + ' ' + loaded[i] + '/' + S[i].rows.length; }).join(', '));

    var details = page.consoleErrorDetails();
    // Third-party requests the gate itself cut off (blockedReason "inspector"): counted and named, not an error.
    var external = page.networkFailures().filter(function (f) { return f.blockedReason === 'inspector'; });
    var otherFail = page.networkFailures().filter(function (f) { return f.blockedReason !== 'inspector'; });
    var errs = details.map(function (d) { return d.text + (d.url ? ' @ ' + d.url : ''); })
      .concat(otherFail.map(function (f) { return 'request failed: ' + f.url + ' ' + f.errorText; }));
    var local404 = srv ? srv.misses.slice() : [];
    chk('no script error and no missing asset on the page', errs.length === 0 && local404.length === 0,
      page.networkUrls().length, 'requests',
      errs.length || local404.length ? errs.slice(0, 3).join(' | ') + (local404.length ? '  [404: ' + local404.slice(0, 5).join(', ') + ']' : '')
        : 'clean console; ' + external.length + ' third-party request(s) blocked by the gate and not counted as errors (' +
          external.map(function (f) { return f.url.replace(/^https?:\/\/([^/]+).*$/, '$1'); }).join(', ') + ')');

    // Everything requested up to here is page load. Window A is the tab clicks below; window B, set
    // after the deep links (which reload the page on purpose), is the filtering.
    var baselineA = page.networkUrls().length;
    var afterTabs = [], baselineB = baselineA;

    try {
    /* ---- 3. tabs ---- */
    var initial = {};
    for (var si = 0; si < ids.length; si++) initial[ids[si]] = await shown(ids[si]);
    chk('with no hash the Headlines tab shows and the other two are hidden',
      initial.headlines && !initial.vulns && !initial.cves, ids.length, 'sections',
      JSON.stringify(initial) + ' hash="' + await hashNow() + '"');

    var tabSel = { headlines: '.hl-wtabs__tab--h', vulns: '.hl-wtabs__tab--v', cves: '.hl-wtabs__tab--c' };
    var styleTuple = function () {
      return page.json('[].map.call(document.querySelectorAll(".hl-wtabs__tab"),function(a){var c=getComputedStyle(a);' +
        'return c.backgroundColor+"|"+c.boxShadow+"|"+c.color})');
    };
    for (var ti = 0; ti < ids.length; ti++) {
      var tid = ids[ti];
      await page.click(tabSel[tid]);
      await sleep(350);
      var st = {};
      for (var sj = 0; sj < ids.length; sj++) st[ids[sj]] = await shown(ids[sj]);
      var onlyThis = ids.every(function (k) { return st[k] === (k === tid); });
      var h = await hashNow();
      chk('a real click on the ' + labels[tid] + ' tab shows #' + tid + ', hides the other two and sets the hash',
        onlyThis && h === '#' + tid, ids.length, 'sections',
        JSON.stringify(st) + ' hash="' + h + '"');
      var tup = await styleTuple();
      var others = tup.filter(function (_, k) { return k !== ti; });
      chk('the ' + labels[tid] + ' tab, once selected, is styled apart from the two others',
        tup[ti] !== others[0] && tup[ti] !== others[1], tup.length, 'tabs',
        'selected: ' + tup[ti].slice(0, 90));
    }
    afterTabs = page.networkUrls().slice(baselineA).filter(function (u) { return u.indexOf('data:') !== 0; });

    /* A day, a digest row or a CVE anchor inside a tab opens that tab (the
       :has(... :target) half of the switch), which a tab click never reaches. */
    var deep = [];
    if (S.vulns.rows[0]) deep.push(['vulns', S.vulns.rows[0].id]);
    if (S.cves.rows[0]) deep.push(['cves', S.cves.rows[0].id]);
    if (S.vulns.days[0]) deep.push(['vulns', 'vulns-' + S.vulns.days[0]]);
    var deepBad = [];
    for (var di = 0; di < deep.length; di++) {
      await goto('');
      await ev('location.hash=' + JSON.stringify('#' + deep[di][1]));
      await sleep(300);
      var okT = await shown(deep[di][0]);
      var oneOnly = true;
      for (var dk = 0; dk < ids.length; dk++) if (ids[dk] !== deep[di][0] && await shown(ids[dk])) oneOnly = false;
      if (!okT || !oneOnly) deepBad.push('#' + deep[di][1]);
    }
    chk('a deep link to a CVE row or a day opens the tab that holds it',
      deepBad.length === 0, deep.length, 'deep links', deepBad.length ? 'did not open its tab: ' + deepBad.join(', ') : deep.map(function (d) { return '#' + d[1]; }).join(', '));
    await goto('#headlines');
    baselineB = page.networkUrls().length;

    } catch (e) { aborted('the tab checks', e); }

    try {
    /* ---- 4. computed colour ---- */
    /* Every publisher row takes its --wire-src; the check reads the variable the
       row resolved and compares what the source name and the title actually
       painted. A probe element turns "#fb923c", var() chains and color-mix()
       into the same rgb the browser painted, so nothing is compared as text. */
    var colour = await page.json('(function(){function px(v){var p=document.createElement("span");p.style.color=v;document.body.appendChild(p);var c=getComputedStyle(p).color;p.remove();return c}' +
      'var rows=document.querySelectorAll("#headlines .hl-wire__item");var o={n:rows.length,srcBad:[],noVar:0,pubs:{},colours:{},tc:[]};' +
      'for(var i=0;i<rows.length;i++){var it=rows[i],v=getComputedStyle(it).getPropertyValue("--wire-src").trim();' +
      'var src=it.querySelector(".hl-wire__src"),ti=it.querySelector(".hl-wire__title");if(!v||!src||!ti){o.noVar++;continue}' +
      'var want=px(v),mix=px("color-mix(in srgb, "+v+" 30%, #f4f4f4)");o.colours[want]=1;' +
      'var pub=(it.className.match(/hl-wire__item--src-([\\w-]+)/)||[0,"?"])[1];o.pubs[pub]=1;' +
      'if(getComputedStyle(src).color!==want)o.srcBad.push(pub+" "+getComputedStyle(src).color+" != "+want);' +
      'o.tc.push([getComputedStyle(ti).color,mix])}' +
      'o.pubs=Object.keys(o.pubs);o.colours=Object.keys(o.colours);return o})()');
    var titleBad = 0;
    colour.tc.forEach(function (p) { if (!near(parseColor(p[0]), parseColor(p[1]), 2)) titleBad++; });
    chk('each headline\'s source name is painted in its publisher\'s --wire-src',
      colour.srcBad.length === 0 && colour.noVar === 0, colour.n, 'headline rows',
      colour.pubs.length + ' publishers, ' + colour.colours.length + ' distinct colours' +
        (colour.srcBad.length ? '  WRONG: ' + colour.srcBad.slice(0, 3).join(' | ') : '') +
        (colour.noVar ? '  ' + colour.noVar + ' rows carry no --wire-src or no source/title element' : ''));
    chk('publishers get different colours (a rule that collapses them all to one hue fails)',
      colour.colours.length >= 4 && colour.pubs.length >= 4, colour.pubs.length, 'publishers',
      colour.colours.length + ' distinct --wire-src colours across ' + colour.pubs.length + ' publishers (need at least 4 of each)');
    chk('each headline title is its publisher\'s hue mixed 30% into #f4f4f4',
      titleBad === 0, colour.tc.length, 'titles', titleBad ? titleBad + ' titles off the mix by more than 2/255' : 'within 2/255 of the mix');

    var chipC = await page.json('(function(){function px(v){var p=document.createElement("span");p.style.color=v;document.body.appendChild(p);var c=getComputedStyle(p).color;p.remove();return c}' +
      'var cs=document.querySelectorAll(".hl-wtabs__sec .hl-chip-btn--topic:not(.is-on)");var o={n:cs.length,bad:[],noVar:0,hl:0,hues:{}};' +
      'for(var i=0;i<cs.length;i++){var v=getComputedStyle(cs[i]).getPropertyValue("--wire-topic").trim();if(!v){o.noVar++;continue}' +
      'var want=px(v),got=getComputedStyle(cs[i]).color;if(cs[i].closest("#headlines")){o.hl++;o.hues[want]=1}' +
      'if(got!==want)o.bad.push((cs[i].textContent.trim().slice(0,18))+" "+got+" != "+want)}o.hues=Object.keys(o.hues).length;return o})()');
    chk('each topic chip, not selected, is painted in its --wire-topic',
      chipC.bad.length === 0 && chipC.noVar === 0, chipC.n, 'topic chips (all three tabs)',
      chipC.hl + ' on the Headlines tab in ' + chipC.hues + ' hues' +
        (chipC.bad.length ? '  WRONG: ' + chipC.bad.slice(0, 3).join(' | ') : '') +
        (chipC.noVar ? '  ' + chipC.noVar + ' chips carry no --wire-topic' : ''));
    chk('the Headlines topic chips span several hues',
      chipC.hues >= 4, chipC.hl, 'headline topic chips', chipC.hues + ' distinct hues (need at least 4)');

    } catch (e) { aborted('the colour checks', e); }

    /* ---- 5. filters, each by real clicks, each against the count the static HTML implies ---- */
    var filterCase;
    try {
    var H = S.headlines.rows;
    await page.click('.hl-wtabs__tab--h');
    await sleep(250);
    var hTotal = H.length;
    chk('Headlines opens unfiltered: the count line and the visible rows both equal every row',
      (await txt('#headlines [data-filter-count]')) === 'Showing ' + hTotal + ' of ' + hTotal && (await vis('#headlines .hl-wire__row')) === hTotal,
      hTotal, 'rows', '"' + await txt('#headlines [data-filter-count]') + '"');

    var filterCase = async function (sec, itemSel, rowsAll, name, steps, want, term, extra) {
      for (var k = 0; k < steps.length; k++) {
        var okc = await clickChip(sec, steps[k][0], steps[k][1]);
        if (!okc) { chk(name, false, rowsAll.length, 'rows', 'no chip data-' + steps[k][0] + '="' + steps[k][1] + '" on the page'); return; }
      }
      if (term) await setSearch(sec, term);
      var exp = HARNESS.expectedCount(rowsAll, want, term);
      var got = await vis('#' + sec + ' ' + itemSel);
      var line = await txt('#' + sec + ' [data-filter-count]');
      chk(name, got === exp && line === 'Showing ' + exp + ' of ' + rowsAll.length && exp > 0 && exp < rowsAll.length,
        rowsAll.length, 'rows',
        'expected ' + exp + ' by the markup; visible ' + got + '; count line "' + line + '"' + (extra || ''));
      // back to unfiltered through the controls a reader has
      if (term) await setSearch(sec, '');
      for (var r = steps.length - 1; r >= 0; r--) await clickChip(sec, steps[r][0], '');
      var back = await vis('#' + sec + ' ' + itemSel);
      if (back !== rowsAll.length) {
        chk(name + ': clearing it restores every row', false, rowsAll.length, 'rows', 'visible ' + back);
      }
    };

    // The topic chip with the most rows and one with fewer, so a chip stuck on All cannot pass by luck.
    var topicChips = S.headlines.chips.filter(function (c) { return c.axis === 'tag' && c.value; });
    var t1 = topicChips[0], t2 = topicChips[Math.min(5, topicChips.length - 1)];
    if (t1) {
      var pc = t1.printed;
      await filterCase('headlines', '.hl-wire__row', H, 'a topic chip (' + t1.value + ') narrows Headlines to exactly its rows',
        [['tag', t1.value]], { tag: [t1.value] }, '', '; chip prints ' + pc);
      chk('the topic chip\'s printed count equals the rows the markup tags with it',
        pc === HARNESS.expectedCount(H, { tag: [t1.value] }, ''), topicChips.length, 'topic chips (this one: ' + t1.value + ')', 'printed ' + pc);
    } else skipped('a topic chip narrows Headlines', 'the page renders no topic chip');
    if (t2 && t2 !== t1) {
      await filterCase('headlines', '.hl-wire__row', H, 'a second, smaller topic chip (' + t2.value + ') narrows Headlines to exactly its rows',
        [['tag', t2.value]], { tag: [t2.value] }, '');
    }
    await filterCase('headlines', '.hl-wire__row', H, 'the Kind chip News shows exactly the news rows',
      [['kind', 'news']], { kind: ['news'] }, '');
    await filterCase('headlines', '.hl-wire__row', H, 'the Kind chip Research shows exactly the research rows',
      [['kind', 'research']], { kind: ['research'] }, '');
    if (t1) {
      await filterCase('headlines', '.hl-wire__row', H, 'a topic chip and a Kind chip together show the rows that match both',
        [['tag', t1.value], ['kind', 'research']], { tag: [t1.value], kind: ['research'] }, '');
    }
    await filterCase('headlines', '.hl-wire__row', H, 'searching "ransomware" shows exactly the rows whose title or labels hold it',
      [], {}, 'ransomware');

    await setSearch('headlines', 'zzz-no-such-headline-zzz');
    var emptyMsgVis = await vis('#headlines [data-filter-empty]');
    chk('a search matching nothing shows no rows and the empty message',
      (await vis('#headlines .hl-wire__row')) === 0 && emptyMsgVis > 0 && HARNESS.expectedCount(H, {}, 'zzz-no-such-headline-zzz') === 0,
      hTotal, 'rows', 'visible rows ' + await vis('#headlines .hl-wire__row') + ', empty message boxes ' + emptyMsgVis);
    await setSearch('headlines', '');

    // The date control, still on this tab.
    var busiest = S.headlines.days.slice().sort(function (a, b) { return S.headlines.dayCounts[b] - S.headlines.dayCounts[a]; })[0];
    var geom = await page.computed('#headlines [data-filter-date]', ['display']);
    chk('the date control renders with real geometry', !!geom && geom._present && geom._w > 60 && geom._h > 20, 1, 'controls',
      geom && geom._present ? geom._w + 'x' + geom._h : 'ELEMENT ABSENT');
    var mm = await page.json('(function(){var e=document.querySelector("#headlines [data-filter-date]");return {min:e.getAttribute("min"),max:e.getAttribute("max")}})()');
    chk('min and max bound the date input to the Headlines days',
      mm.min === S.headlines.days[0] && mm.max === S.headlines.days[S.headlines.days.length - 1], S.headlines.days.length, 'days', JSON.stringify(mm));
    async function setDate(v) {
      await ev('(function(){var e=document.querySelector("#headlines [data-filter-date]");e.value=' + JSON.stringify(v) +
        ';e.dispatchEvent(new Event("change",{bubbles:true}))})()');
      await sleep(200);
    }
    await setDate(busiest);
    var rb = await vis('#headlines .hl-wire__row'), db = await vis('#headlines [data-filter-group]');
    chk('picking the busiest day shows exactly its rows under one heading',
      rb === S.headlines.dayCounts[busiest] && db === 1, hTotal, 'rows', busiest + ': ' + rb + ' rows under ' + db + ' heading (expected ' + S.headlines.dayCounts[busiest] + ' under 1)');
    await page.click('#headlines [data-filter-date-clear]');
    var ra = await vis('#headlines .hl-wire__row');
    chk('a real click on Clear date restores every row', ra === hTotal, hTotal, 'rows', ra + ' rows visible');

    } catch (e) { aborted('the Headlines filter checks', e); }

    try {
    // nKEV tab
    var V = S.vulns.rows;
    await page.click('.hl-wtabs__tab--v');
    await sleep(300);
    chk('nKEVs opens unfiltered: the count line and the visible rows both equal every row',
      (await txt('#vulns [data-filter-count]')) === 'Showing ' + V.length + ' of ' + V.length && (await vis('#vulns .hl-vuln')) === V.length,
      V.length, 'rows', '"' + await txt('#vulns [data-filter-count]') + '"');
    var vl = S.vulns.chips.filter(function (c) { return c.axis === 'list' && c.value; })[0];
    if (vl) await filterCase('vulns', '.hl-vuln', V, 'the nKEV list chip (' + vl.value + ') shows exactly its rows', [['list', vl.value]], { list: [vl.value] }, '', '; chip prints ' + vl.printed);
    else skipped('the nKEV list chip', 'the page renders no list chip');
    var vs = S.vulns.chips.filter(function (c) { return c.axis === 'sev' && c.value === 'critical'; })[0];
    if (vs) await filterCase('vulns', '.hl-vuln', V, 'the nKEV severity chip (critical) shows exactly its rows', [['sev', 'critical']], { sev: ['critical'] }, '', '; chip prints ' + vs.printed);
    else skipped('the nKEV severity chip', 'the page renders no critical severity chip');
    if (vl && vs) await filterCase('vulns', '.hl-vuln', V, 'a list chip and a severity chip together show the rows that match both',
      [['list', vl.value], ['sev', 'critical']], { list: [vl.value], sev: ['critical'] }, '');

    } catch (e) { aborted('the nKEV filter checks', e); }

    try {
    // CVEs tab
    var C = S.cves.rows;
    await page.click('.hl-wtabs__tab--c');
    await sleep(300);
    chk('CVEs opens unfiltered: the count line and the visible rows both equal every row',
      (await txt('#cves [data-filter-count]')) === 'Showing ' + C.length + ' of ' + C.length && (await vis('#cves .hl-vuln')) === C.length,
      C.length, 'rows', '"' + await txt('#cves [data-filter-count]') + '"');
    var cs = S.cves.chips.filter(function (c) { return c.axis === 'sig' && c.value; })[0];
    if (cs) await filterCase('cves', '.hl-vuln', C, 'the CVEs signal chip (' + cs.value + ') shows exactly its rows', [['sig', cs.value]], { sig: [cs.value] }, '', '; chip prints ' + cs.printed);
    else skipped('the CVEs signal chip', 'the page renders no signal chip');
    var cv = S.cves.chips.filter(function (c) { return c.axis === 'sev' && c.value === 'critical'; })[0];
    if (cv) await filterCase('cves', '.hl-vuln', C, 'the CVEs severity chip (critical) shows exactly its rows', [['sev', 'critical']], { sev: ['critical'] }, '', '; chip prints ' + cv.printed);
    else skipped('the CVEs severity chip', 'the page renders no critical severity chip');

    } catch (e) { aborted('the CVEs filter checks', e); }

    /* ---- 6. privacy: everything above was tabs and filters ---- */
    var afterFilters = page.networkUrls().slice(baselineB).filter(function (u) { return u.indexOf('data:') !== 0; });
    /* A tab switch paints text that was display:none at load, so a font file the
       first view never needed (the italic face, say) can load then. That is the
       browser fetching a static asset for pixels, with no query string and nothing
       the reader typed. It is listed, not counted; every other request after load,
       and any request carrying a query string, is a transmission. */
    var lazyAsset = function (u) {
      return u.indexOf(origin + '/assets/') === 0 && u.indexOf('?') < 0 && /\.(woff2?|ttf|png|svg|jpe?g|webp)$/i.test(u);
    };
    var afterAll = afterTabs.concat(afterFilters);
    var lazy = afterAll.filter(lazyAsset);
    var sent = afterAll.filter(function (u) { return !lazyAsset(u); });
    chk('nothing was transmitted while the reader switched tabs and filtered',
      sent.length === 0, baselineA + baselineB, 'requests at page load (the two baselines)',
      sent.length ? sent.slice(0, 5).join(', ') : 'none after load, across the tab clicks and every filter step' +
        (lazy.length ? '; ' + lazy.length + ' lazy static asset(s) not counted: ' + lazy.map(function (u) { return u.replace(origin, ''); }).join(', ') : ''));

    var widths = [1440, 390];
    try {
    /* ---- 7. Details toggles and popovers ---- */
    for (var dj = 1; dj < ids.length; dj++) {
      var dsec = ids[dj], dsel = S[dsec].itemSel;
      await page.click(tabSel[dsec]);
      await sleep(300);
      var togg = await ev('document.querySelectorAll("#' + dsec + ' .hl-dt:not([hidden])").length');
      chk('every ' + labels[dsec] + ' row has a visible Details toggle once the script runs',
        togg === S[dsec].rows.length, S[dsec].rows.length, 'rows', togg + ' visible toggles');
      var opened = await ev('(function(){var b=document.querySelector("#' + dsec + ' .hl-dt:not([hidden])");if(!b)return false;b.setAttribute("data-hlgate","1");return true})()');
      if (!opened) { chk('a Details toggle opens its panel on a real click', false, 0, 'toggles', 'no toggle to click'); continue; }
      await page.click('[data-hlgate="1"]');
      var ok = await until('(function(){var p=document.querySelector("#' + dsec + ' .hl-dt__panel");return !!p&&!/^Loading details/.test(p.textContent)&&p.textContent.length>20})()', 5000);
      var ptxt = await ev('(function(){var p=document.querySelector("#' + dsec + ' .hl-dt__panel");return p?p.textContent.slice(0,90):""})()');
      var expd = await ev('document.querySelector("[data-hlgate]").getAttribute("aria-expanded")');
      chk('a real click on a ' + labels[dsec] + ' Details toggle opens a panel with its details',
        ok && expd === 'true' && !/could not be loaded/.test(ptxt), 1, 'toggles', 'aria-expanded=' + expd + ', panel: "' + ptxt + '"');
      await page.click('[data-hlgate="1"]');
      await sleep(200);
      var closed = await ev('!document.querySelector("#' + dsec + ' .hl-dt__panel")&&document.querySelector("[data-hlgate]").getAttribute("aria-expanded")==="false"');
      chk('a second click on the ' + labels[dsec] + ' Details toggle closes the panel', closed, 1, 'toggles', closed ? 'closed' : 'still open');
      await ev('(function(){var e=document.querySelector("[data-hlgate]");if(e)e.removeAttribute("data-hlgate")})()');
    }

    } catch (e) { aborted('the Details toggle checks', e); }

    try {
    var POP_JS = '(function(){var iw=document.documentElement.clientWidth,n=0,over=0,left=0,worst=0;' +
      'document.querySelectorAll(".hl-wtabs__sec details.hl-vuln__pop").forEach(function(d){var b=d.querySelector(".hl-vuln__popbody");if(!b)return;' +
      'var wasOpen=d.open;d.open=true;var q=b.getBoundingClientRect();d.open=wasOpen;if(q.width<=0)return;n++;' +
      'if(q.right>iw+0.5){over++;worst=Math.max(worst,q.right-iw)}if(q.left<-0.5){left++;worst=Math.max(worst,-q.left)}});' +
      'return {iw:iw,n:n,over:over,left:left,worst:Math.round(worst)}})()';
    for (var wi = 0; wi < widths.length; wi++) {
      await setViewport(widths[wi], widths[wi] === 390 ? 844 : 900);
      await goto('#vulns');
      var pe = await page.json(POP_JS);
      chk('every nKEV popover opens inside the viewport at ' + widths[wi] + 'px',
        pe.over === 0 && pe.left === 0, pe.n, 'popovers opened', pe.over + ' past the right edge, ' + pe.left + ' past the left, worst ' + pe.worst + 'px');
      var clicked = await ev('(function(){var s=document.querySelector("#vulns details.hl-vuln__pop > summary");if(!s)return false;s.setAttribute("data-hlgate","1");return true})()');
      if (clicked) {
        await page.click('[data-hlgate="1"]');
        await sleep(250);
        var box = await page.json('(function(){var d=document.querySelector("#vulns details.hl-vuln__pop[open] .hl-vuln__popbody");if(!d)return null;var q=d.getBoundingClientRect();return {w:Math.round(q.width),l:Math.round(q.left),r:Math.round(q.right),iw:document.documentElement.clientWidth}})()');
        chk('a real click on a popover chip opens it, inside the viewport, at ' + widths[wi] + 'px',
          !!box && box.w > 0 && box.l >= 0 && box.r <= box.iw, 1, 'popovers', JSON.stringify(box));
        await ev('(function(){var e=document.querySelector("[data-hlgate]");if(e)e.removeAttribute("data-hlgate");var o=document.querySelector("details.hl-vuln__pop[open]");if(o)o.open=false})()');
      } else {
        chk('a real click on a popover chip opens it', false, 0, 'popovers', 'no popover chip on the nKEV tab');
      }
    }

    } catch (e) { aborted('the popover checks', e); }

    try {
    /* ---- 8. no horizontal overflow, every tab, both widths ---- */
    var shots = [];
    for (var wj = 0; wj < widths.length; wj++) {
      await setViewport(widths[wj], widths[wj] === 390 ? 844 : 900);
      for (var oi = 0; oi < ids.length; oi++) {
        await goto('#' + ids[oi]);
        var ov = await page.json(OVERFLOW_JS);
        chk('no horizontal overflow on ' + labels[ids[oi]] + ' at ' + widths[wj] + 'px',
          ov.escaped === 0 && ov.scrollX === 0 && ov.client === widths[wj], ov.painted, 'painted elements',
          'viewport ' + ov.client + ', document scrolled ' + ov.scrollX + 'px, ' + ov.escaped + ' escaped' + (ov.first.length ? ': ' + ov.first.join(' | ') : ''));
        if (shotsDir) {
          fs.mkdirSync(shotsDir, { recursive: true });
          await ev('window.scrollTo(0,0)');
          await sleep(300);
          shots.push(await page.screenshot(path.join(shotsDir, 'wire-' + ids[oi] + '-' + widths[wj] + '.png')));
        }
      }
    }
    shots.forEach(function (f) { console.log('   shot  ' + f); });
    } catch (e) { aborted('the overflow checks', e); }

  } finally {
    page.close();
    if (srv) srv.close();
  }

  var V = LEDGER.verdict();
  console.log('\n' + V.verdict + '  /wire/ in a real browser, BUILT mode  (' + V.passes + ' PASS, ' + V.fails + ' FAIL, ' + V.notChecked + ' NOT CHECKED, of ' + V.total + ' checks)');
  process.exit(V.code);
}

(BUILT_MODE ? runBuilt() : runLive()).catch(function (e) {
  notChecked('the browser check errored before finishing: ' + e.message);
});
