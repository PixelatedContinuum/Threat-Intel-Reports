#!/usr/bin/env node
'use strict';

/* The site sweep, in a real browser (T-0556 w6): one pass over every kind of page at 390 and 1440 for horizontal scroll and clipped text,
   one computed-colour pass for text contrast (WCAG AA), and a real-keyboard pass for visible focus.

   PAGE KINDS (each picked from the built site, never hardcoded to a slug that may go): home, reports index, a report, its detection page,
   an IOC feed page, the three Wire tabs, actors index, an actor, families index, a family, techniques index, a technique, search, 404,
   about-me, support, sponsor. A kind with no page in the build is NOT CHECKED, named.

   CHECKS (lib/page-sweep.js holds the in-page expressions): per page and width, overflow, clip; per page at 1440 and 390, contrast;
   keyboard: Tab through home, a report, the Wire and search with real key events (Input.dispatchKeyEvent), and at every stop read the
   focused element, whether it is on screen and not covered, and whether anything about it changes between focused and blurred
   (outline, box-shadow, border, background, text colour, decoration). A stop whose style does not change is a FAIL.
   CONTROLS (each must FAIL, or the gate fails): a 2400px box on a copy of the page, a 40px clipping box round long text, #444 text on
   #111, and a link given outline:none with every other focus style cleared.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED.
   Run: HL_SITE_DIR=<built _site> node check-browser-sweep.js [--only overflow,contrast,keyboard] [--json <file>]
   Env: HL_CHROME, HL_SITE_DIR */

var path = require('node:path');
var fs = require('node:fs');

var SITE_DIR = process.env.HL_SITE_DIR || '';
function arg(n) { var i = process.argv.indexOf(n); return i > -1 ? process.argv[i + 1] : null; }
var ONLY = (arg('--only') || 'overflow,contrast,keyboard').split(',');
var JSON_OUT = arg('--json');
function notChecked(reason) { console.log('NOT CHECKED  ' + reason); process.exit(2); }

var CDP, SERVER, SWEEP, LEDGER;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  SWEEP = require('./lib/page-sweep.js');
  LEDGER = require('./lib/gate-ledger.js').makeLedger(function (l) { console.log(l); });
} catch (e) { notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.'); }
if (!SITE_DIR) notChecked('set HL_SITE_DIR to a built _site');
var chk = LEDGER.chk;

function first(dir, pred) {
  var abs = path.join(SITE_DIR, dir);
  if (!fs.existsSync(abs)) return null;
  var names = fs.readdirSync(abs).filter(function (n) { return fs.existsSync(path.join(abs, n, 'index.html')) && pred(n); }).sort();
  return names.length ? '/' + dir + '/' + names[0] + '/' : null;
}
/* the longest report page is the richest one to look at; the Brazil lead report is the w0 reference when present */
function pickReport() {
  var pref = '/reports/opendirectory-38-180-16-98-brazil-public-sector-toolkit-20261015/';
  if (fs.existsSync(path.join(SITE_DIR, pref, 'index.html'))) return pref;
  return first('reports', function () { return true; });
}
function pages() {
  var rep = pickReport();
  var slug = rep ? rep.split('/')[2] : null;
  var det = slug && fs.existsSync(path.join(SITE_DIR, 'hunting-detections', slug, 'index.html')) ? '/hunting-detections/' + slug + '/' : first('hunting-detections', function () { return true; });
  var ioc = slug && fs.existsSync(path.join(SITE_DIR, 'ioc-feeds', slug, 'index.html')) ? '/ioc-feeds/' + slug + '/' : first('ioc-feeds', function () { return true; });
  var list = [
    ['home', '/'], ['reports index', '/reports/'], ['a report', rep], ['its detection page', det], ['an IOC feed page', ioc],
    ['Wire headlines', '/wire/#headlines'], ['Wire nKEVs', '/wire/#vulns'], ['Wire CVEs', '/wire/#cves'],
    ['actors index', '/actors/'], ['an actor', first('actors', function (n) { return /^UTA/.test(n); })],
    ['families index', '/families/'], ['a family', first('families', function () { return true; })],
    ['techniques index', '/techniques/'], ['a technique', first('techniques', function (n) { return /^T\d/.test(n); })],
    ['search', '/search/'], ['404', '/404.html'], ['about-me', '/about-me/'], ['support', '/support/'], ['sponsor', '/sponsor/']
  ];
  return list;
}

async function setViewport(page, w, h) {
  await page.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
  await page.send('Emulation.setTouchEmulationEnabled', { enabled: w < 1024, maxTouchPoints: 5 });
  await CDP.sleep(200);
}
async function load(page, url) {
  var base = url.split('#')[0];
  await page.send('Page.navigate', { url: url });
  await CDP.sleep(900);
  await page.evaluate('document.documentElement.style.scrollBehavior="auto"');
  if (url.indexOf('#') > -1) await page.evaluate('location.hash=' + JSON.stringify(url.slice(url.indexOf('#'))));
  await page.evaluate('(function(){var s=document.createElement("style");s.textContent="*,*::before,*::after{transition:none!important;animation:none!important}";document.head.appendChild(s);document.querySelectorAll("details").forEach(function(d){d.open=true})})()');
  await CDP.sleep(500);
}

/* ---- keyboard ---- */
var FOCUS_FN = 'function tup1(e){var c=getComputedStyle(e);return [c.outlineStyle==="none"?"none":c.outlineStyle+c.outlineWidth+c.outlineColor+c.outlineOffset,c.boxShadow,c.borderTopColor,c.borderBottomColor,c.borderLeftColor,c.borderRightColor,c.backgroundColor,c.color,c.textDecorationLine,c.textDecorationColor].join("|")}' +
  'function tup(e){var t=[],a=e;for(var i=0;i<4&&a&&a!==document.body;i++,a=a.parentElement)t.push(tup1(a));return t.join("||")}';
/* the stop: the element's own focus style, or (a wrapper that draws the ring: a search field, a clear button) one of its three ancestors changing between focused and blurred */
var STOP_EXPR = '(function(){' + FOCUS_FN + ';var e=document.activeElement;if(!e||e===document.body||e===document.documentElement)return{none:true};' +
  'if(!e.__hlStop)e.__hlStop=++window.__hlStopN;var c=getComputedStyle(e);var r=e.getBoundingClientRect();var f=tup(e);var ol=(c.outlineStyle!=="none"&&parseFloat(c.outlineWidth)>0&&!/rgba\\(.*, 0\\)$/.test(c.outlineColor));' +
  'var on=r.width>0&&r.height>0&&r.bottom>0&&r.right>0&&r.left<innerWidth&&r.top<innerHeight;var hit=on?document.elementFromPoint(Math.min(Math.max(r.left+r.width/2,0),innerWidth-1),Math.min(Math.max(r.top+r.height/2,0),innerHeight-1)):null;' +
  'var covered=on&&hit&&hit!==e&&!e.contains(hit)&&!hit.contains(e);' +
  'var native=e.tagName==="INPUT"&&/^(date|time|datetime-local|month|week)$/.test(e.type);var u=f;if(!native){e.blur();u=tup(e);e.focus()}' +
  'return{id:e.__hlStop,tag:e.tagName.toLowerCase(),cls:String(e.getAttribute("class")||"").split(/\\s+/)[0],text:(e.textContent||e.getAttribute("aria-label")||e.value||"").trim().slice(0,28),href:e.getAttribute("href"),outline:ol,outlineDesc:c.outlineStyle+" "+c.outlineWidth+" "+c.outlineColor,changed:f!==u,onScreen:on,covered:!!covered,coveredBy:covered&&hit?hit.tagName.toLowerCase()+"."+String(hit.className).split(" ")[0]:null,native:native,w:Math.round(r.width),h:Math.round(r.height)}})()';

async function tabKey(page, shift) {
  var base = { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9, modifiers: shift ? 8 : 0 };
  await page.send('Input.dispatchKeyEvent', Object.assign({ type: 'keyDown' }, base));
  await page.send('Input.dispatchKeyEvent', Object.assign({ type: 'keyUp' }, base));
  await CDP.sleep(70);
}
async function tabThrough(page, max) {
  await page.evaluate('window.__hlStopN=0;document.documentElement.style.scrollBehavior="auto";document.activeElement&&document.activeElement.blur();window.scrollTo(0,0)');
  var stops = [], last = null, repeats = 0, nones = 0;
  for (var i = 0; i < max; i++) {
    await tabKey(page, false);
    var s = await page.json(STOP_EXPR);
    if (s.none) { if (++nones > 3) break; continue; }   /* a date field's picker or the browser's own bar can take a press: three in a row end the walk */
    nones = 0;
    if (s.id === last) { repeats++; continue; }   /* a date field takes several Tab presses (day, month, year): one stop */
    last = s.id;
    stops.push(s);
  }
  stops.repeats = repeats;
  return stops;
}
function judgeStops(stops) {
  var bad = [], noInd = 0, off = 0, cov = 0;
  stops.forEach(function (s, i) {
    var why = [];
    if (!s.outline && !s.changed && !s.native) { why.push('no visible change'); noInd++; }
    if (!s.onScreen) { why.push('off screen'); off++; }
    if (s.covered) { why.push('covered by ' + s.coveredBy); cov++; }
    if (why.length) bad.push('#' + (i + 1) + ' ' + s.tag + (s.cls ? '.' + s.cls : '') + ' "' + (s.text || s.href || '') + '": ' + why.join(', '));
  });
  return { ok: bad.length === 0, bad: bad, noInd: noInd, off: off, cov: cov };
}

async function main() {
  var srv;
  try { srv = await SERVER.startDir(SITE_DIR); } catch (e) { notChecked(e.message); }
  var origin = srv.origin;
  var page;
  try { page = await CDP.open(origin + '/', { width: 1440, height: 900 }); } catch (e) { srv.close(); if (e.notChecked) notChecked(e.message); throw e; }
  console.log('browser: ' + page.label);
  var PAGES = pages();
  var out = { contrast: {}, overflow: {}, keyboard: {} };
  try {
    PAGES.forEach(function (p) { if (!p[1]) LEDGER.skipped('page kind: ' + p[0], 'no such page in the build'); });
    PAGES = PAGES.filter(function (p) { return !!p[1]; });

    if (ONLY.indexOf('overflow') > -1 || ONLY.indexOf('contrast') > -1) {
      for (var w of [390, 1440]) {
        await setViewport(page, w, w === 390 ? 844 : 900);
        for (var pi = 0; pi < PAGES.length; pi++) {
          var p = PAGES[pi];
          await load(page, origin + p[1]);
          if (ONLY.indexOf('overflow') > -1) {
            var o = await page.json(SWEEP.OVERFLOW_EXPR), c = await page.json(SWEEP.CLIP_EXPR);
            chk('no horizontal scroll or box outside the viewport: ' + p[0] + ' at ' + w + 'px (' + p[1] + ')', SWEEP.overflowOk(o), o.painted, 'painted elements', SWEEP.overflowDetail(o));
            chk('no clipped text: ' + p[0] + ' at ' + w + 'px', c.clipped.length === 0, c.runs, 'text runs', SWEEP.clipDetail(c));
            out.overflow[p[0] + ' ' + w] = { o: o, c: c };
          }
          if (ONLY.indexOf('contrast') > -1) {
            var k = await page.json(SWEEP.CONTRAST_EXPR);
            chk('text contrast reaches WCAG AA: ' + p[0] + ' at ' + w + 'px', k.bad.length === 0, k.runs - k.unmeasured, 'text runs measured', SWEEP.contrastDetail(k));
            out.contrast[p[0] + ' ' + w] = k;
          }
        }
      }
      /* controls, on the home page at 390 */
      await setViewport(page, 390, 844);
      await load(page, origin + '/');
      await page.evaluate('(function(){var d=document.createElement("div");d.style.cssText="width:2400px;height:20px;background:#f0f";document.querySelector("main,body").appendChild(d)})()');
      var co = await page.json(SWEEP.OVERFLOW_EXPR);
      chk('control: a 2400px box fails the overflow check', !SWEEP.overflowOk(co), co.painted, 'painted elements', SWEEP.overflowDetail(co).slice(0, 140));
      await load(page, origin + '/');
      await page.evaluate('(function(){var d=document.createElement("div");d.style.cssText="width:40px;height:20px;overflow:hidden;white-space:nowrap;position:absolute;top:0;left:0";d.textContent="Text that cannot fit in forty pixels";document.body.appendChild(d)})()');
      var cc = await page.json(SWEEP.CLIP_EXPR);
      chk('control: text in a 40px clipping box fails the clip check', cc.clipped.length > 0, cc.runs, 'text runs', SWEEP.clipDetail(cc).slice(0, 140));
      await load(page, origin + '/');
      await page.evaluate('(function(){var d=document.createElement("p");d.style.cssText="color:#444;background:#111;position:absolute;top:0;left:0;margin:0";d.textContent="Dim control sentence";document.body.appendChild(d)})()');
      var ck = await page.json(SWEEP.CONTRAST_EXPR);
      chk('control: #444 text on #111 fails the contrast check', ck.bad.some(function (b) { return b.text === 'Dim control sentence'; }), ck.runs - ck.unmeasured, 'text runs measured', SWEEP.contrastDetail(ck).slice(0, 140));
    }

    if (ONLY.indexOf('keyboard') > -1) {
      await setViewport(page, 1440, 900);
      var KB = [['home', '/', 60], ['a report', pickReport(), 45], ['Wire headlines', '/wire/#headlines', 60], ['search', '/search/', 25]];
      for (var ki = 0; ki < KB.length; ki++) {
        if (!KB[ki][1]) { LEDGER.skipped('keyboard: ' + KB[ki][0], 'no such page'); continue; }
        await load(page, origin + KB[ki][1]);
        var stops = await tabThrough(page, KB[ki][2]);
        var j = judgeStops(stops);
        out.keyboard[KB[ki][0]] = stops;
        chk('keyboard: ' + KB[ki][0] + ', every Tab stop has a visible focus and is on screen and uncovered', j.ok, stops.length, 'Tab stops (capped at ' + KB[ki][2] + ')',
          (j.bad.length ? j.bad.slice(0, 6).join(' | ') : 'none') + '; first stops: ' + stops.slice(0, 3).map(function (s) { return (s.text || s.href || s.tag) + ' [' + s.outlineDesc + ']'; }).join(' ; '));
        if (KB[ki][0] === 'home') {
          var logo = stops.slice(0, 4).filter(function (s) { return /logo|mast|brand/i.test(s.cls + ' ' + s.text) || s.href === '/' || s.href === '/index.html'; });
          chk('keyboard: the logo link is among the first four stops of the home page and shows focus', logo.length > 0 && logo.every(function (s) { return s.outline || s.changed; }), logo.length, 'logo stops', logo.map(function (s) { return s.cls + ' ' + s.outlineDesc; }).join(' ; '));
        }
      }
      /* control: a link with every focus style cleared must be caught */
      await load(page, origin + '/');
      await page.evaluate('(function(){var s=document.createElement("style");s.textContent="a.hl-gate-ctl,a.hl-gate-ctl:focus,a.hl-gate-ctl:focus-visible,a.hl-gate-ctl:hover{outline:none!important;box-shadow:none!important;background:#111!important;color:#fff!important;border:0!important;text-decoration:none!important;transform:none!important}";document.head.appendChild(s);var a=document.createElement("a");a.className="hl-gate-ctl";a.href="#x";a.textContent="focus control";a.style.cssText="position:absolute;top:0;left:0;background:#111;color:#fff;padding:4px";document.body.insertBefore(a,document.body.firstChild)})()');
      var cs = (await tabThrough(page, 4)).filter(function (x) { return x.cls === 'hl-gate-ctl'; });
      var cj = judgeStops(cs);
      chk('control: a link with its focus style removed fails the keyboard check', !cj.ok, cs.length, 'Tab stops', cj.bad.join(' | '));
    }
  } finally {
    page.close();
    srv.close();
  }
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(out, null, 1));
  var V = LEDGER.verdict();
  console.log('\n' + V.verdict + '  site sweep in a real browser  (' + V.passes + ' PASS, ' + V.fails + ' FAIL, ' + V.notChecked + ' NOT CHECKED, of ' + V.total + ' checks)');
  process.exit(V.code);
}

main().catch(function (e) { notChecked('the sweep errored before finishing: ' + e.message + '\n' + e.stack); });
