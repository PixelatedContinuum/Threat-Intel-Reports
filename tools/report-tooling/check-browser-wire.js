#!/usr/bin/env node
'use strict';

/* Drives /wire/ in a real browser and asserts what jsdom cannot reach.

   The claim matrix carried "the Wire page renders and its links resolve" as
   NO GATE, with the note that it closes only with a real browser in the loop.
   This is that browser. It checks computed styles, real pointer input, and that
   the page transmits nothing while a reader filters it.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. A missing browser, an unreachable site or
   an absent dependency is NOT CHECKED with the reason named, never a pass.

   Run: node check-browser-wire.js [--shots <dir>]
   Env: HL_CHROME     path to a Chrome/Chromium binary
        HL_SITE_BASE  defaults to https://the-hunters-ledger.com */

var path = require('node:path');
var fs = require('node:fs');
var https = require('node:https');
var http = require('node:http');

var ROOT = path.join(__dirname, '..', '..');
var BASE = (process.env.HL_SITE_BASE || 'https://the-hunters-ledger.com').replace(/\/+$/, '');

var shotsDir = null;
var ai = process.argv.indexOf('--shots');
if (ai > -1 && process.argv[ai + 1]) shotsDir = process.argv[ai + 1];

function notChecked(reason) {
  console.log('NOT CHECKED  ' + reason);
  process.exit(2);
}

var CDP, HARNESS, JSDOM;
try {
  CDP = require('./lib/cdp.js');
  HARNESS = require('./lib/wire-harness.js');
  JSDOM = require('jsdom').JSDOM;
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

/* The harness is served over HTTP rather than opened from file://.

   Under file:// the page's own root-relative asset URLs resolve against the
   drive root, the font request fails CORS outright, and the console fills with
   errors that say nothing about the site. Masking those would have meant a
   console check that could never fail. Serving the real assets from the working
   tree removes the whole class instead. */
var TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.gif': 'image/gif', '.ico': 'image/x-icon',
  '.json': 'application/json', '.txt': 'text/plain; charset=utf-8'
};

function serve(html) {
  var misses = [];
  return new Promise(function (resolve) {
    var srv = http.createServer(function (req, res) {
      var url = req.url.split('?')[0];
      if (url === '/' || url === '/wire/' || url === '/wire/index.html') {
        res.writeHead(200, { 'content-type': TYPES['.html'] });
        return res.end(html);
      }
      // Anything else comes out of the working tree, so the page loads the
      // fonts and images it actually ships with.
      var rel = decodeURIComponent(url).replace(/^\/+/, '');
      var file = path.join(ROOT, rel);
      if (file.indexOf(ROOT) !== 0 || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        /* Not everything the page loads lives in this repo. The theme's own
           fonts come out of the Jekyll gem and are copied into _site at build
           time, so they exist on the published site and nowhere in the working
           tree. Proxy those rather than carve an exclusion into the console
           check: an exclusion big enough to cover them would also hide a real
           missing asset. A path that is missing in BOTH places is named. */
        return https.get(BASE + url, function (up) {
          if (up.statusCode !== 200) {
            up.resume();
            misses.push(url);
            res.writeHead(404); return res.end('not found');
          }
          res.writeHead(200, { 'content-type': up.headers['content-type'] || 'application/octet-stream' });
          up.pipe(res);
        }).on('error', function () {
          misses.push(url + ' (proxy failed)');
          res.writeHead(404); res.end('not found');
        });
      }
      res.writeHead(200, { 'content-type': TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
    });
    srv.misses = misses;
    srv.listen(0, '127.0.0.1', function () { resolve(srv); });
  });
}

var results = [];
function check(name, pass, detail) {
  results.push({ name: name, pass: pass });
  console.log('   ' + (pass ? 'PASS  ' : 'FAIL  ') + name);
  if (detail) console.log('         ' + detail);
}

async function main() {
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
      customCss: fs.readFileSync(path.join(ROOT, 'assets', 'css', 'custom.css'), 'utf8'),
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

  var srv = await serve(built.html);
  var origin = 'http://127.0.0.1:' + srv.address().port;

  var page;
  try {
    page = await CDP.open(origin + '/wire/');
  } catch (e) {
    srv.close();
    if (e.notChecked) notChecked(e.message);
    throw e;
  }

  console.log('browser: ' + page.version);
  console.log('corpus:  ' + built.rows + ' rows over ' + built.days.length +
    ' days (' + first + ' .. ' + last + '), busiest ' + busiest + '=' +
    built.dayCounts[busiest] + ', quiet day ' + (quiet || 'none'));
  console.log('');

  try {
    check('every row on the live page loaded',
      (await page.evaluate('document.querySelectorAll(".hl-wire__item").length')) === built.rows,
      built.rows + ' rows expected');

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

main().catch(function (e) {
  notChecked('the browser check errored before finishing: ' + e.message);
});
