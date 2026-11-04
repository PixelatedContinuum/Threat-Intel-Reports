#!/usr/bin/env node
'use strict';

/* The home page, `/`, in a real browser at 1440 and 390 (T-0556 w6; w6a proposed it: the other browser gates measure the report
   and Wire pages, and the concept 3 home was only ever checked in screenshots).

   WHAT IT CHECKS, each with its denominator:
     overflow       no horizontal scroll and no painted box outside the viewport (lib/page-sweep.js)
     hang           lib/box-fit.js over `.c3-home`: no element whose content is wider or taller than its box, no child outside its parent
     clip           no text run clipped by an ancestor that hides overflow
     heads          every section head (`.c3-sec`): the heading and the "All N reports" link each sit on ONE line; the head wraps as a whole
                    rather than the words inside it
     kicker         the lead panel's kicker: every part on one line, the whole kicker on one row at 390
     lead           the lead panel's title, standfirst and buttons lie inside the panel; buttons are 44px tall
     rows           the Latest research rows: each row's title, meta and summary fit their column and do not meet the cover
     stats          the stats strip: every cell's number and label fit the cell
     lists          the link lists: every link 44px tall, title and count do not overlap
   Every check has a CONTROL run against the same expression on a copy of the page with one defect injected (a 700px nowrap box in the
   stats strip, a 40px section heading, an overlong unbreakable word in a stat cell, a 30px list column). A control that does not fail
   fails the gate: the check was then reading nothing.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. Run: HL_SITE_DIR=<built _site> node check-browser-home.js [--shots <dir>]
   Env: HL_CHROME, HL_SITE_DIR (or HL_SITE_BASE=http://127.0.0.1:PORT for a server you started). */

var path = require('node:path');
var fs = require('node:fs');

var SITE_DIR = process.env.HL_SITE_DIR || '';
var BASE = (process.env.HL_SITE_BASE || '').replace(/\/+$/, '');
var shotsDir = null;
var ai = process.argv.indexOf('--shots');
if (ai > -1 && process.argv[ai + 1]) shotsDir = process.argv[ai + 1];

function notChecked(reason) { console.log('NOT CHECKED  ' + reason); process.exit(2); }

var CDP, SERVER, SWEEP, BOXFIT, LEDGER;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  SWEEP = require('./lib/page-sweep.js');
  BOXFIT = require('./lib/box-fit.js');
  LEDGER = require('./lib/gate-ledger.js').makeLedger(function (l) { console.log(l); });
} catch (e) { notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.'); }
if (!SITE_DIR && !BASE) notChecked('set HL_SITE_DIR to a built _site (or HL_SITE_BASE to a server you started)');
var chk = LEDGER.chk;

/* ---- in-page expressions ---- */

/* how many visual lines a node's text occupies: distinct tops of its client rects (rounded to 3px), over its text runs only */
var LINES_FN = 'function lines(e){var r=document.createRange();r.selectNodeContents(e);var t=[];var rs=r.getClientRects();for(var i=0;i<rs.length;i++){if(rs[i].width<1)continue;var y=Math.round(rs[i].top/3);if(t.indexOf(y)<0)t.push(y)}return t.length}';

var HEADS_EXPR = '(function(){' + LINES_FN + ';var o={n:0,bad:[]};var hs=document.querySelectorAll(".c3-home .c3-sec");' +
  'for(var i=0;i<hs.length;i++){var h=hs[i];var kids=h.children;for(var k=0;k<kids.length;k++){var e=kids[k];if(e.tagName!=="H2"&&e.tagName!=="A")continue;o.n++;var l=lines(e);' +
  'if(l>1)o.bad.push((h.querySelector("h2")||h).textContent.trim().slice(0,24)+": "+e.tagName.toLowerCase()+" \\""+e.textContent.trim().slice(0,24)+"\\" on "+l+" lines")}}return o})()';

var KICKER_EXPR = '(function(){' + LINES_FN + ';var o={n:0,bad:[],rows:0};var ks=document.querySelectorAll(".c3-home .c3-lead .c3-kick");' +
  'for(var i=0;i<ks.length;i++){var k=ks[i];var tops=[];var ch=k.children;for(var j=0;j<ch.length;j++){o.n++;var l=lines(ch[j]);if(l>1)o.bad.push("\\""+ch[j].textContent.trim().slice(0,24)+"\\" on "+l+" lines");' +
  'var y=Math.round(ch[j].getBoundingClientRect().top/3);if(tops.indexOf(y)<0)tops.push(y)}o.rows+=tops.length;if(tops.length>1)o.bad.push("the kicker runs on "+tops.length+" rows")}return o})()';

var LEAD_EXPR = '(function(){var o={n:0,bad:[]};var L=document.querySelector(".c3-home .c3-lead");if(!L)return{n:0,bad:[],missing:true};var lr=L.getBoundingClientRect();' +
  'var els=L.querySelectorAll(".c3-lead__h,.c3-lead__stand,.c3-byline,.c3-btn,.c3-chart__h,.c3-chart__row");' +
  'for(var i=0;i<els.length;i++){var r=els[i].getBoundingClientRect();if(r.width<1)continue;o.n++;if(r.left<lr.left-1||r.right>lr.right+1||r.bottom>lr.bottom+1)o.bad.push(els[i].className+" leaves the panel");' +
  'if(/c3-btn/.test(els[i].className)&&r.height<43.5)o.bad.push("button \\""+els[i].textContent.trim().slice(0,20)+"\\" is "+Math.round(r.height)+"px tall")}return o})()';

var ROWS_EXPR = '(function(){var o={n:0,bad:[]};var rs=document.querySelectorAll(".c3-home .c3-row");' +
  'for(var i=0;i<rs.length;i++){var row=rs[i];var rr=row.getBoundingClientRect();var cov=row.querySelector(".c3-cover");var cr=cov?cov.getBoundingClientRect():null;' +
  'var parts=row.querySelectorAll(".c3-row__k,.c3-row__t,.c3-row__g");for(var j=0;j<parts.length;j++){var p=parts[j];var r=p.getBoundingClientRect();o.n++;' +
  'if(r.right>rr.right+1||r.left<rr.left-1)o.bad.push(p.className+" leaves its row");if(p.scrollWidth>p.clientWidth+1)o.bad.push(p.className+" content "+p.scrollWidth+" in "+p.clientWidth);' +
  'if(cr&&r.left<cr.right-0.5&&r.right>cr.left+0.5&&r.top<cr.bottom-0.5&&r.bottom>cr.top+0.5)o.bad.push(p.className+" overlaps the cover")}}return o})()';

var STATS_EXPR = '(function(){var o={n:0,bad:[]};var cs=document.querySelectorAll(".c3-home .c3-stats a");' +
  'for(var i=0;i<cs.length;i++){var c=cs[i];var cr=c.getBoundingClientRect();var ps=c.querySelectorAll("b,span");for(var j=0;j<ps.length;j++){var p=ps[j];o.n++;' +
  'var r=p.getBoundingClientRect();if(r.right>cr.right+1||r.left<cr.left-1||p.scrollWidth>p.clientWidth+1)o.bad.push("\\""+p.textContent.trim().slice(0,20)+"\\" "+p.scrollWidth+" in "+p.clientWidth)}}return o})()';

var LISTS_EXPR = '(function(){var o={n:0,bad:[]};var as=document.querySelectorAll(".c3-home .c3-cols a");' +
  'for(var i=0;i<as.length;i++){var a=as[i];var r=a.getBoundingClientRect();o.n++;if(r.height<43.5)o.bad.push("\\""+a.textContent.trim().slice(0,20)+"\\" link is "+Math.round(r.height)+"px tall");' +
  'var t=a.querySelector(".c3-li__t"),n=a.querySelector(".c3-li__n");if(t&&n){var tr=t.getBoundingClientRect(),nr=n.getBoundingClientRect();if(tr.right>nr.left+0.5&&tr.bottom>nr.top&&tr.top<nr.bottom)o.bad.push("title and count overlap in \\""+t.textContent.trim().slice(0,20)+"\\"")}' +
  'var all=a.querySelectorAll("*");for(var k=0;k<all.length;k++)if(all[k].getBoundingClientRect().right>r.right+1)o.bad.push(all[k].className+" leaves its link")}return o})()';

/* the controls: one defect each, injected in the page, measured with the same expression */
var CONTROLS = [
  { name: 'overflow', expr: 'overflow', inject: 'var s=document.querySelector(".c3-home .c3-stats");var d=document.createElement("div");d.style.cssText="width:2400px;height:20px;background:#f0f;white-space:nowrap";s.parentNode.insertBefore(d,s)' },
  { name: 'heads', expr: 'heads', inject: 'document.querySelectorAll(".c3-home .c3-sec h2").forEach(function(h){h.style.width="40px";h.style.flex="none"})' },
  { name: 'kicker', expr: 'kicker', inject: 'var k=document.querySelector(".c3-home .c3-lead .c3-kick");k.style.width="40px"' },
  { name: 'stats', expr: 'stats', inject: 'var b=document.querySelector(".c3-home .c3-stats b");b.textContent="Unbreakablewordthatislongerthananystatcell";b.style.whiteSpace="nowrap";b.style.display="block"' },
  { name: 'rows', expr: 'rows', inject: 'var t=document.querySelector(".c3-home .c3-row__t");t.style.whiteSpace="nowrap";t.style.width="2000px";t.style.display="block"' },
  { name: 'lists', expr: 'lists', inject: 'var a=document.querySelector(".c3-home .c3-cols a");a.style.minHeight="0";a.style.height="20px";a.style.padding="0"' },
  { name: 'hang', expr: 'hang', inject: 'var p=document.querySelector(".c3-home .c3-stats span");p.style.display="block";p.style.height="4px";p.style.overflow="visible";p.textContent="a label that is much taller than its four pixel box and hangs out of it"' }
];

async function setViewport(page, w, h) {
  await page.send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: false });
  await page.send('Emulation.setTouchEmulationEnabled', { enabled: w < 1024, maxTouchPoints: 5 });
  await CDP.sleep(200);
}
async function load(page, url) {
  await page.send('Page.navigate', { url: url });
  await page.waitFor('.c3-home', 8000);
  await page.evaluate('(function(){var s=document.createElement("style");s.textContent="*,*::before,*::after{transition:none!important;animation:none!important}";document.head.appendChild(s)})()');
  await CDP.sleep(400);
}

async function measure(page, kind) {
  switch (kind) {
    case 'overflow': return page.json(SWEEP.OVERFLOW_EXPR);
    case 'clip': return page.json(SWEEP.CLIP_EXPR);
    case 'hang': return page.json(BOXFIT.exprFor('.c3-home', { leadingEm: 0.15, srOnly: true }));
    case 'heads': return page.json(HEADS_EXPR);
    case 'kicker': return page.json(KICKER_EXPR);
    case 'lead': return page.json(LEAD_EXPR);
    case 'rows': return page.json(ROWS_EXPR);
    case 'stats': return page.json(STATS_EXPR);
    case 'lists': return page.json(LISTS_EXPR);
  }
}
/* returns { ok, n, detail } for a measurement */
function judge(kind, m) {
  if (kind === 'overflow') return { ok: SWEEP.overflowOk(m), n: m.painted, unit: 'painted elements', detail: SWEEP.overflowDetail(m) };
  if (kind === 'clip') return { ok: m.clipped.length === 0, n: m.runs, unit: 'text runs', detail: SWEEP.clipDetail(m) };
  if (kind === 'hang') {
    if (m.notChecked) return { ok: false, n: 0, unit: 'elements', detail: m.notChecked };
    var v = BOXFIT.verdict([Object.assign({ label: 'home' }, m)], 'hang');
    return { ok: v.ok, n: m.measured, unit: 'elements under .c3-home', detail: v.detail };
  }
  var unit = { heads: 'heading and link texts', kicker: 'kicker parts', lead: 'lead panel parts', rows: 'row parts', stats: 'stat numbers and labels', lists: 'list links' }[kind];
  var extra = kind === 'kicker' ? ' (' + m.rows + ' kicker row(s))' : '';
  return { ok: m.bad.length === 0 && !m.missing, n: m.n, unit: unit, detail: (m.bad.length ? m.bad.slice(0, 5).join(' | ') : 'none') + extra };
}

var NAMES = {
  overflow: 'no horizontal scroll and no box outside the viewport',
  clip: 'no text clipped by an ancestor that hides overflow',
  hang: 'no element hangs out of its box (box fit over the home page)',
  heads: 'each section heading and its link sit on one line',
  kicker: 'the lead kicker is one line, one row',
  lead: 'the lead panel holds its title, standfirst, byline and 44px buttons',
  rows: 'each Latest research row fits its columns and keeps off its cover',
  stats: 'each stats cell holds its number and label',
  lists: 'each link list entry is 44px tall, title clear of count'
};

async function main() {
  var srv = null, origin = BASE;
  if (SITE_DIR) {
    try { srv = await SERVER.startDir(SITE_DIR); } catch (e) { notChecked(e.message); }
    origin = srv.origin;
  }
  var page;
  try { page = await CDP.open(origin + '/', { width: 1440, height: 900 }); } catch (e) { if (srv) srv.close(); if (e.notChecked) notChecked(e.message); throw e; }
  console.log('browser: ' + page.label);
  var KINDS = ['overflow', 'clip', 'hang', 'heads', 'kicker', 'lead', 'rows', 'stats', 'lists'];
  var VPS = [[1440, 900], [390, 844]];
  var controlFailed = [];
  try {
    for (var v = 0; v < VPS.length; v++) {
      var w = VPS[v][0];
      await setViewport(page, w, VPS[v][1]);
      await load(page, origin + '/');
      for (var k = 0; k < KINDS.length; k++) {
        var j = judge(KINDS[k], await measure(page, KINDS[k]));
        chk(NAMES[KINDS[k]] + ' at ' + w + 'px', j.ok, j.n, j.unit, j.detail);
      }
      if (shotsDir) { fs.mkdirSync(shotsDir, { recursive: true }); console.log('   shot  ' + await page.screenshot(path.join(shotsDir, 'home-' + w + '.png'))); }
      /* controls: the same expression over a copy with one defect; it must FAIL */
      for (var c = 0; c < CONTROLS.length; c++) {
        await load(page, origin + '/');
        await page.evaluate('(function(){' + CONTROLS[c].inject + '})()');
        await CDP.sleep(150);
        var cj = judge(CONTROLS[c].expr, await measure(page, CONTROLS[c].expr));
        var ctlName = 'control at ' + w + 'px: ' + CONTROLS[c].name + ' fails on a copy with the defect injected';
        chk(ctlName, !cj.ok, Math.max(cj.n, 1), 'measurements', cj.ok ? 'the control did NOT fail: this check reads nothing' : 'failed as designed: ' + cj.detail.slice(0, 120));
      }
    }
  } finally {
    page.close();
    if (srv) srv.close();
  }
  var V = LEDGER.verdict();
  console.log('\n' + V.verdict + '  / (home) in a real browser at 1440 and 390  (' + V.passes + ' PASS, ' + V.fails + ' FAIL, ' + V.notChecked + ' NOT CHECKED, of ' + V.total + ' checks)');
  process.exit(V.code);
}

main().catch(function (e) { notChecked('the home gate errored before finishing: ' + e.message); });
