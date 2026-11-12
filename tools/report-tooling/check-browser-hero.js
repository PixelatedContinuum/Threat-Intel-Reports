#!/usr/bin/env node
'use strict';

/* The hero panels of a report page (Detections, IOC feed, STIX), opened in a real browser at 375 and 1280 (T-0605 L19; T-0603 lane V1
   proposed it). The report gate measures tabs, tiles and views; the three panels that open from the header buttons were checked only by a
   one-off script, and a panel that opened off screen, or under the site header, passed every gate we had.

   WHAT IT CHECKS, per width, each with its denominator (panel openings):
     inside     the panel's rect lies inside the viewport after it opens (left, top, right, bottom)
     uncovered  the first link or button in the panel is the element at its own point: nothing is drawn over the panel's first item
     steady     opening a panel does not move the page (scrollY before and after, the page having been scrolled so the button is mid-screen)
   The page is scrolled with `behavior: "instant"` and settled before the click. The site sets `html { scroll-behavior: smooth }`: a smooth scroll still
   running when the click lands reads as the click moving the page (T-0605 L09 measured exactly that: 24 of 24 clicks on a settled page moved it 0 px,
   24 of 24 clicks during the animation moved it by the animation's remainder).

   CONTROLS, run in the same pass on a copy of the first page that has a panel, each on the same measure and verdict as the real openings and each
   required to FAIL: a panel pushed off the left edge (a one-line injected style), a full-screen layer drawn over the panel, and a click handler that
   scrolls the page. A control that does not fail fails the gate: the check was then reading nothing.

   Pages: every built report page (a file under reports/ that carries a hero button), or those matching --only. A button the page does not have
   (the STIX button is absent on some reports) is counted as absent, never as a pass; a page with no hero button at all is not in the denominator.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. Run: HL_SITE_DIR=<built _site> node check-browser-hero.js [--only <regexp on the URL>] [--limit N] [--widths 375,1280]
   Env: HL_CHROME, HL_SITE_DIR. */

var path = require('node:path');
var fs = require('node:fs');

var PAIRS = [['hl-detect-tab', 'hl-detect-panel', 'Detections'], ['hl-ioc-tab', 'hl-ioc-panel', 'IOC'], ['hl-stix-tab', 'hl-stix-panel', 'STIX']];
var TOL = 1; // px of slack on a rect edge and on the scroll position

function parseArgs(argv, env) {
  var o = { site: (env && env.HL_SITE_DIR) || '', only: null, limit: 0, widths: [375, 1280], bad: null };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i], v = argv[i + 1];
    if (a === '--site') { o.site = v || ''; i++; }
    else if (a === '--only') { o.only = v || ''; i++; }
    else if (a === '--limit') { o.limit = Number(v) || 0; i++; }
    else if (a === '--widths') { o.widths = String(v || '').split(',').map(Number).filter(function (n) { return n > 0; }); i++; }
    else { o.bad = 'unknown argument ' + a; }
  }
  if (!o.widths.length) o.bad = '--widths needs a comma list of widths in px';
  return o;
}

/* A measure is what the page said after the click (see AFTER_FN); the verdict is a list of the ways the opening failed, empty when it is sound. */
function panelVerdict(m, y0) {
  var bad = [];
  if (!m || m.missing) return ['panel element not found'];
  var p = m.panel, vw = m.vw, vh = m.vh;
  if (!m.visible || !(p.r - p.l > 0) || !(p.b - p.t > 0)) return ['panel not visible after the click'];
  if (p.l < -TOL || p.t < -TOL || p.r > vw + TOL || p.b > vh + TOL) bad.push('panel rect [' + p.l + ',' + p.t + ',' + p.r + ',' + p.b + '] is outside the ' + vw + 'x' + vh + ' viewport');
  if (m.firstItem === null) bad.push('panel has no link or button to test');
  else if (m.firstItem.covered) bad.push('first item (' + m.firstItem.label + ') is covered by ' + m.firstItem.hit);
  if (typeof y0 === 'number' && Math.abs(m.scrollY - y0) > TOL) bad.push('page moved ' + (m.scrollY - y0) + ' px on opening');
  return bad;
}

/* The built report pages that carry a hero button, as URL paths. */
function listPages(siteDir, only) {
  var out = [], re = only ? new RegExp(only) : null, root = path.resolve(siteDir, 'reports');
  if (!fs.existsSync(root)) return out;
  (function walk(d) {
    fs.readdirSync(d, { withFileTypes: true }).sort(function (a, b) { return a.name < b.name ? -1 : 1; }).forEach(function (e) {
      var f = path.join(d, e.name);
      if (e.isDirectory()) return walk(f);
      if (e.name !== 'index.html') return;
      var html = fs.readFileSync(f, 'utf8');
      if (!/id="hl-(detect|ioc|stix)-tab"/.test(html)) return;
      var url = '/' + path.relative(path.resolve(siteDir), path.dirname(f)).split(path.sep).join('/') + '/';
      if (url === '/reports/') return; // the index of reports is not a report
      if (!re || re.test(url)) out.push(url);
    });
  })(root);
  return out;
}

/* In-page: the panel after the click. The first item is the first link or button inside it, tested at its own centre (clipped to the panel's rect). */
var AFTER_FN = 'function(bid,pid){var p=document.getElementById(pid),b=document.getElementById(bid);if(!p||!b)return {missing:true};' +
  'var q=p.getBoundingClientRect(),cs=getComputedStyle(p),R=function(r){return {l:Math.round(r.left*10)/10,t:Math.round(r.top*10)/10,r:Math.round(r.right*10)/10,b:Math.round(r.bottom*10)/10}};' +
  'var visible=cs.display!=="none"&&cs.visibility!=="hidden"&&q.width>0&&q.height>0;' +
  'var it=p.querySelector("a[href],button"),first=null;' +
  'if(it){var r=it.getBoundingClientRect(),x=Math.min(Math.max(r.left+r.width/2,q.left+1),q.right-1),y=Math.min(Math.max(r.top+Math.min(r.height/2,10),q.top+1),q.bottom-1);' +
  'var inView=x>=0&&y>=0&&x<=innerWidth&&y<=innerHeight,hit=inView?document.elementFromPoint(x,y):null;' +
  'first={label:(it.textContent||it.getAttribute("aria-label")||it.tagName).replace(/\\s+/g," ").trim().slice(0,30),inView:inView,' +
  'covered:inView&&!!hit&&!p.contains(hit),hit:hit?(hit.tagName.toLowerCase()+(hit.className&&typeof hit.className==="string"?"."+hit.className.split(" ")[0]:"")):null};}' +
  'return {visible:visible,panel:R(q),vw:innerWidth,vh:innerHeight,scrollY:Math.round(scrollY),firstItem:first,expanded:b.getAttribute("aria-expanded")};}';

/* In-page: put the button mid-screen with an instant scroll and report whether it is clickable at its centre. */
var BEFORE_FN = 'function(bid){var b=document.getElementById(bid);if(!b)return {absent:true};var r=b.getBoundingClientRect();if(!(r.width>0&&r.height>0))return {hidden:true};' +
  'b.scrollIntoView({block:"center",behavior:"instant"});return {};}';
var POINT_FN = 'function(bid){var b=document.getElementById(bid),r=b.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2,h=document.elementFromPoint(x,y);' +
  'return {x:x,y:y,ok:!!h&&(h===b||b.contains(h)),hit:h?h.tagName.toLowerCase():null,scrollY:Math.round(scrollY)};}';

function notChecked(reason) { console.log('NOT CHECKED  ' + reason); process.exit(2); }

async function main() {
  var opt = parseArgs(process.argv.slice(2), process.env);
  if (opt.bad) { console.log('usage: HL_SITE_DIR=<built _site> node check-browser-hero.js [--only <regexp>] [--limit N] [--widths 375,1280]'); notChecked(opt.bad); }
  if (!opt.site) notChecked('set HL_SITE_DIR to a built _site (or pass --site)');
  var CDP, SERVER, LEDGER;
  try {
    CDP = require('./lib/cdp.js'); SERVER = require('./lib/page-server.js');
    LEDGER = require('./lib/gate-ledger.js').makeLedger(function (l) { console.log(l); });
  } catch (e) { notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.'); }
  var pages = listPages(opt.site, opt.only);
  if (opt.limit > 0) pages = pages.slice(0, opt.limit);
  if (!pages.length) notChecked('no built report page under ' + opt.site + '/reports carries a hero button' + (opt.only ? ' and matches --only ' + opt.only : ''));
  var srv;
  try { srv = await SERVER.startDir(opt.site); } catch (e) { notChecked(e.message); }
  var page;
  try { page = await CDP.open(srv.origin + pages[0], { width: 1280, height: 900 }); } catch (e) { srv.close(); if (e.notChecked) notChecked(e.message); throw e; }
  console.log('browser: ' + page.label);
  console.log('site: ' + path.resolve(opt.site) + '  pages with a hero button: ' + pages.length + (opt.limit ? ' (limited to the first ' + opt.limit + ')' : '') + '  widths: ' + opt.widths.join(', '));

  async function viewport(w) {
    await page.send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
    await page.send('Emulation.setTouchEmulationEnabled', { enabled: w < 1024, maxTouchPoints: 5 });
    await CDP.sleep(150);
  }
  async function load(url) {
    await page.send('Page.navigate', { url: srv.origin + url });
    await page.waitFor('.hl-rv-actions', 6000);
    await CDP.sleep(500);
  }
  /* Opens one panel with a real pointer click; returns { state: 'absent'|'hidden'|'blocked'|'opened', m, y0 }. */
  async function open(pair) {
    var pre = await page.json('(' + BEFORE_FN + ')(' + JSON.stringify(pair[0]) + ')');
    if (pre.absent) return { state: 'absent' };
    if (pre.hidden) return { state: 'hidden' };
    await CDP.sleep(200);
    var pt = await page.json('(' + POINT_FN + ')(' + JSON.stringify(pair[0]) + ')');
    if (!pt.ok) return { state: 'blocked', detail: 'the ' + pair[2] + ' button is under ' + pt.hit + ' at its centre' };
    await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
    await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
    await CDP.sleep(300);
    var m = await page.json('(' + AFTER_FN + ')(' + JSON.stringify(pair[0]) + ',' + JSON.stringify(pair[1]) + ')');
    return { state: 'opened', m: m, y0: pt.scrollY };
  }
  async function closeAll() {
    await page.evaluate('document.dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}))');
    await CDP.sleep(120);
  }

  try {
    for (var wi = 0; wi < opt.widths.length; wi++) {
      var w = opt.widths[wi];
      await viewport(w);
      var tally = { openings: 0, absent: 0, hidden: 0, blocked: [], inside: [], uncovered: [], steady: [], pagesDone: 0, errors: [] };
      var controlPage = null;
      for (var pi = 0; pi < pages.length; pi++) {
        try {
          await load(pages[pi]);
          for (var k = 0; k < PAIRS.length; k++) {
            var r = await open(PAIRS[k]);
            if (r.state === 'absent') { tally.absent++; continue; }
            if (r.state === 'hidden') { tally.hidden++; continue; }
            if (r.state === 'blocked') { tally.blocked.push(pages[pi] + ' ' + r.detail); tally.openings++; continue; }
            tally.openings++;
            var bad = panelVerdict(r.m, r.y0), tag = pages[pi].replace(/^\/reports\//, '') + ' ' + PAIRS[k][2];
            bad.forEach(function (b) { (/outside|not visible|not found/.test(b) ? tally.inside : /covered|no link/.test(b) ? tally.uncovered : tally.steady).push(tag + ': ' + b); });
            if (!controlPage) controlPage = { url: pages[pi], pair: PAIRS[k] };
            await closeAll();
          }
          tally.pagesDone++;
        } catch (e) { tally.errors.push(pages[pi] + ': ' + String(e.message || e).slice(0, 100)); }
      }
      console.log('\n' + w + ' px: ' + tally.pagesDone + ' of ' + pages.length + ' pages driven, ' + tally.openings + ' panel openings, ' + tally.absent + ' buttons absent, ' + tally.hidden + ' buttons hidden');
      var summarise = function (list) { return list.length ? list.length + ' failed; first ' + Math.min(list.length, 6) + ': ' + list.slice(0, 6).join(' | ') : 'none'; };
      LEDGER.chk('every hero panel opens inside the viewport at ' + w + ' px', tally.inside.length === 0 && tally.errors.length === 0 && tally.blocked.length === 0, tally.openings, 'panel openings',
        summarise(tally.inside.concat(tally.blocked, tally.errors)));
      LEDGER.chk('the first item of every hero panel is uncovered at ' + w + ' px', tally.uncovered.length === 0, tally.openings - tally.blocked.length, 'panel openings', summarise(tally.uncovered));
      LEDGER.chk('opening a hero panel does not move the page at ' + w + ' px', tally.steady.length === 0, tally.openings - tally.blocked.length, 'panel openings', summarise(tally.steady));

      /* controls: the same open, measure and verdict, on a copy of one page with one defect planted; each must FAIL */
      if (controlPage) {
        var CONTROLS = [
          { name: 'a panel pushed off the left edge', want: /outside/, setup: 'var s=document.createElement("style");s.textContent=".hl-rv-resource{left:-400px!important}";document.head.appendChild(s)' },
          { name: 'a full-screen layer over the panel', want: /covered/, setup: 'var s=document.createElement("style");s.textContent=".hl-rv-resource{left:16px!important;top:100px!important}";document.head.appendChild(s);var d=document.createElement("div");d.style.cssText="position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:2147483647;background:transparent";' +
            'document.getElementById(' + JSON.stringify(controlPage.pair[0]) + ').addEventListener("click",function(){setTimeout(function(){document.body.appendChild(d)},0)})' },
          { name: 'a click handler that scrolls the page', want: /moved/, setup: 'document.getElementById(' + JSON.stringify(controlPage.pair[0]) + ').addEventListener("click",function(){window.scrollTo({top:scrollY+300,behavior:"instant"})})' }
        ];
        for (var ci = 0; ci < CONTROLS.length; ci++) {
          var c = CONTROLS[ci], detail, hit = false, n = 0;
          try {
            await load(controlPage.url);
            await page.evaluate('(function(){' + c.setup + '})()');
            var cr = await open(controlPage.pair);
            if (cr.state === 'opened') { n = 1; var cb = panelVerdict(cr.m, cr.y0); hit = cb.some(function (b) { return c.want.test(b); }); detail = hit ? 'failed as designed: ' + cb.join('; ').slice(0, 140) : 'the control did NOT fail (verdict: ' + (cb.join('; ') || 'sound') + ')'; }
            else detail = 'the control page did not open (' + cr.state + ')';
          } catch (e) { detail = 'control errored: ' + String(e.message || e).slice(0, 100); }
          LEDGER.chk('control at ' + w + ' px: ' + c.name + ' fails on a copy with the defect planted', hit, n, 'planted openings', detail);
        }
      } else LEDGER.skipped('controls at ' + w + ' px', 'no panel opened, so there was no page to plant a defect in');
    }
  } finally {
    page.close();
    srv.close();
  }
  var V = LEDGER.verdict();
  console.log('\n' + V.verdict + '  hero panels at ' + opt.widths.join(' and ') + ' px  (' + V.passes + ' PASS, ' + V.fails + ' FAIL, ' + V.notChecked + ' NOT CHECKED, of ' + V.total + ' checks)');
  process.exit(V.code);
}

module.exports = { parseArgs: parseArgs, panelVerdict: panelVerdict, listPages: listPages, PAIRS: PAIRS };
if (require.main === module) main().catch(function (e) { notChecked('the hero gate errored before finishing: ' + e.message); });
