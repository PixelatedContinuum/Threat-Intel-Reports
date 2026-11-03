#!/usr/bin/env node
'use strict';

/* The BROWSER half of the defang gate (T-0500.1.7.4 fix-r1; review finding 1 and the sweep it asked for).

   check-defang.js --site reads the built HTML and cannot see what a page's SCRIPTS write after load: the IOC search result sentence, a copy button's clipboard text, the
   Wire details panels, the report tabs' generated views. jsdom runs no script there, and the review's two reproductions (the IOC search echoing a raw address, the IOC
   viewer's Defanged/Live button) were exactly that blind spot. This gate drives a real Chromium over the built site, lets every script run, presses every control that copies,
   shares, downloads or exports, and judges what ended up in the DOM and what was handed to the clipboard, the share sheet and a download, with the SAME scanner and the SAME
   allow data as check-defang.js (lib/defang-site.js makeScanner; a report page is judged against its own allow file).

   node check-browser-defang.js --site <_site dir> [--allow-data FILE] [--only REGEX] [--sample N] [--widths 1280,390] [--out result.json] [--list]
   Env: HL_CHROME  path to a Chrome/Chromium binary.   Browsers run only under the shared lock (flock .../T-0500.1.10/gate.lock node ...).

   WHAT IT DOES, per selected page and width:
     1. loads the page from a local server that serves the built directory and nothing else (third-party https is blocked and counted); installs capture stubs BEFORE any page
        script runs: navigator.clipboard.writeText, navigator.share, URL.createObjectURL (the blob's text is read), document.execCommand('copy');
     2. opens every <details>, expands every collapsed disclosure button, presses (and later un-presses) every button that carries aria-pressed, a filter chip or a toggle in either starting state, and after each of the three passes presses every button whose text, label, title or data-act says copy,
        share, download, export, cite or bibtex (and the picker's "Select all shown" first), reading what each press captured;
     3. per page type: /ioc-feeds/ types a defanged and a raw query (an address, a domain, a URL, a list carrying a withheld value and feeds whose titles carry an address) and
        loads a ?q= link with a raw indicator; the Wire opens every Details panel; /search/ types an address and a name into the site search;
     4. serialises the DOM as it stands (input values written back into the markup, except the IOC search box a query was typed into: that text is the reader's own) and judges
        it with scanDocument: text nodes, tooltip attributes (title, alt, aria-label, placeholder, data-copy, data-gloss), links, the head; and judges every captured string
        line by line.
   EXEMPT BY DECISION 5 (counted, never judged): a copy or download taken from a <pre> (the .hl-copy rule blocks), and any copy or download on a detection page (rule bodies and
   the picker's rule bundle); the machine feed files are not reached by this gate at all.

   EXIT: 0 PASS; 1 FAIL (a raw indicator in the rendered DOM or in a captured string, a page that did not load, or a zero denominator: pages, text nodes or controls);
   2 NOT CHECKED (no browser, a missing dependency, an unreadable site).
   PRINTS: pages, widths, controls pressed by kind, captures by kind and how many were judged and how many exempt, DOM text nodes and tooltip attributes judged, and a CANNOT SEE line.

   THE GATE'S OWN KNOWN POSITIVE is a separate script, tasks/runs/T-0500.1.7.4/build/fix-r1/browser-defang-control.sh: it stages a scratch copy of the site, plants one defect per page (an inline
   script that writes a raw address after load; a copy button whose clipboard text is a raw URL; the share sheet given a raw title; a download whose blob holds a raw domain; the IOC viewer, the
   IOC search and the detection picker as they were before the review; a viewer page whose CSV carries a raw data-fp), runs this gate on those pages and on their clean twins, and requires every
   planted page to be reported for its own defect and every clean twin to pass. Without it a green run could be a gate that sees nothing. */

var path = require('node:path');
var fs = require('node:fs');

function notChecked(reason) { console.log('NOT CHECKED  ' + reason); process.exit(2); }

var CDP, SERVER, SITE;
try {
  CDP = require('./lib/cdp.js');
  SERVER = require('./lib/page-server.js');
  SITE = require('./lib/defang-site.js');
} catch (e) { notChecked(e.message + '. Run `npm ci` in tools/report-tooling, then re-run.'); }

var ROOT = path.join(__dirname, '..', '..');
function arg(name, dflt) { var i = process.argv.indexOf(name); return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : dflt; }
var siteDir = arg('--site', process.env.HL_SITE_DIR || '');
var allowData = arg('--allow-data', path.join(ROOT, '_data', 'defang_allow.yml'));
var only = arg('--only', '') ? new RegExp(arg('--only')) : null;
var sample = Number(arg('--sample', '0')) || 0;
var widths = arg('--widths', '1280').split(',').map(Number).filter(Boolean);
var outFile = arg('--out', '');
var listOnly = process.argv.indexOf('--list') > -1;
if (!siteDir || !fs.existsSync(siteDir)) notChecked('--site <built _site directory> is missing or not a directory (' + siteDir + ').');

/* Page selection. Every page of a type with at most `sample` pages is visited; a bigger type is sampled at even spacing and said so. With --sample 0 every page is visited. */
function selectPages() {
  var rels = SITE.walkHtml(siteDir).map(function (f) { return path.relative(siteDir, f).split(path.sep).join('/'); })
    .filter(function (r) { return !SITE.excluded(r) && (!only || only.test(r)); });
  var byType = {};
  rels.forEach(function (r) { var t = SITE.pageType(r); (byType[t] = byType[t] || []).push(r); });
  var picked = [], notes = [];
  Object.keys(byType).sort().forEach(function (t) {
    var l = byType[t];
    if (sample && l.length > sample) {
      var step = l.length / sample, got = [];
      for (var i = 0; i < sample; i++) got.push(l[Math.floor(i * step)]);
      picked = picked.concat(got); notes.push(t + ': sampled ' + sample + ' of ' + l.length);
    } else { picked = picked.concat(l); notes.push(t + ': all ' + l.length); }
  });
  return { pages: picked, notes: notes, total: rels.length };
}
var sel = selectPages();
if (listOnly) { console.log(sel.pages.join('\n')); console.log('# ' + sel.pages.length + ' of ' + sel.total + ' pages; ' + sel.notes.join('; ')); process.exit(0); }
if (!sel.pages.length) { console.log('FAIL  no page selected (' + sel.total + ' pages in the site): a gate that visits nothing passes nothing'); process.exit(1); }

/* The stubs, installed before the page's own scripts. They record and return, they never write the real clipboard or leave the page. */
var CAPTURE_SRC = '(' + function () {
  var cap = window.__hlcap = { clip: [], share: [], blobs: [], exec: [], errors: [] };
  try {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
      writeText: function (t) { cap.clip.push(String(t)); return Promise.resolve(); },
      readText: function () { return Promise.resolve(''); } } });
  } catch (e) { cap.errors.push('clipboard stub: ' + e.message); }
  try {
    Object.defineProperty(navigator, 'share', { configurable: true, writable: true, value: function (d) { cap.share.push(JSON.stringify(d || {})); return Promise.resolve(); } });
    Object.defineProperty(navigator, 'canShare', { configurable: true, writable: true, value: function () { return true; } });
  } catch (e) { cap.errors.push('share stub: ' + e.message); }
  var orig = URL.createObjectURL;
  URL.createObjectURL = function (b) { try { if (b && b.text) b.text().then(function (t) { cap.blobs.push(t); }); } catch (e) { /* counted below as zero blobs */ } return orig.apply(URL, arguments); };
  var ex = document.execCommand;
  document.execCommand = function (c) {
    if (c === 'copy') {
      var a = document.activeElement, s = '';
      if (a && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT') && a.selectionEnd > a.selectionStart) s = a.value.slice(a.selectionStart, a.selectionEnd);
      cap.exec.push(s || String(window.getSelection()));
    }
    return ex.apply(document, arguments);
  };
} + ')();';

/* In-page driver: opens, expands, presses. Returns one record per press. */
var DRIVE_FN = async function (opts) {
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  var out = { presses: [], expanded: 0, chips: 0, details: 0 };
  var cap = window.__hlcap;
  Array.prototype.forEach.call(document.querySelectorAll('details:not([open])'), function (d) { d.open = true; out.details++; });
  if (opts.expand) {
    Array.prototype.forEach.call(document.querySelectorAll('button[aria-expanded="false"]'), function (b) { try { b.click(); out.expanded++; } catch (e) { /* counted */ } });
    await sleep(200);
  }
  if (opts.chips) {
    // every toggle and filter chip, whichever state it starts in: a button that starts pressed (the old Defanged/Live toggle) is flipped too
    Array.prototype.forEach.call(document.querySelectorAll('button[aria-pressed]'), function (b) { try { b.click(); out.chips++; } catch (e) { /* counted */ } });
    await sleep(250);
  }
  // the picker's checkboxes are selected before its download button can act
  Array.prototype.forEach.call(document.querySelectorAll('.hl-picker__btn[data-act="all"]'), function (b) { try { b.click(); } catch (e) { /* counted */ } });
  await sleep(100);
  var RX = /copy|share|download|export|cite|bibtex|permalink/i;
  var cands = Array.prototype.filter.call(document.querySelectorAll('button,[role="button"]'), function (b) {
    if (b.disabled || b.hasAttribute('hidden')) return false;
    var t = (b.textContent || '') + ' ' + (b.getAttribute('aria-label') || '') + ' ' + (b.title || '') + ' ' + (b.getAttribute('data-act') || '') + ' ' + (b.className || '');
    return RX.test(t);
  });
  for (var i = 0; i < cands.length; i++) {
    var b = cands[i];
    var before = [cap.clip.length, cap.share.length, cap.blobs.length, cap.exec.length];
    var label = String(b.getAttribute('data-act') || b.getAttribute('aria-label') || b.textContent || '').trim().slice(0, 48);
    var cls = String(b.className || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.');
    var inPre = !!b.closest('pre');
    try { b.click(); } catch (e) { out.presses.push({ label: label, cls: cls, error: String(e.message) }); continue; }
    await sleep(140);
    out.presses.push({ label: label, cls: cls, inPre: inPre, clip: cap.clip.slice(before[0]), share: cap.share.slice(before[1]), blobs: cap.blobs.slice(before[2]), exec: cap.exec.slice(before[3]) });
  }
  out.here = location.pathname + location.search;
  return out;
};
var DRIVE_SRC = '(' + DRIVE_FN.toString() + ')';

var SERIALISE_FN = function (skip, cutSel) {
  Array.prototype.forEach.call(document.querySelectorAll('input,textarea'), function (e) {
    if (skip && e.matches(skip)) { if (e.tagName === 'TEXTAREA') e.textContent = ''; else e.setAttribute('value', ''); return; }
    if (e.tagName === 'TEXTAREA') e.textContent = e.value; else e.setAttribute('value', e.value);
  });
  if (!cutSel) return '<!DOCTYPE html>' + document.documentElement.outerHTML;
  // cutSel (the Wire details panels): the page without those panels, and the panels apart, each judged on its own
  var panels = Array.prototype.map.call(document.querySelectorAll(cutSel), function (n) { return n.outerHTML; });
  var c = document.documentElement.cloneNode(true);
  Array.prototype.forEach.call(c.querySelectorAll(cutSel), function (n) { n.textContent = ''; });
  return JSON.stringify({ html: '<!DOCTYPE html>' + c.outerHTML, panels: panels });
};
var SERIALISE_SRC = '(' + SERIALISE_FN.toString() + ')';

function sleep(ms) { return CDP.sleep(ms); }

(async function main() {
  var data = SITE.loadAllowData(allowData);
  var scanner = SITE.makeScanner(allowData);
  var srv, page;
  try { srv = await SERVER.startDir(siteDir); } catch (e) { notChecked('could not serve ' + siteDir + ': ' + e.message); }
  try { page = await CDP.open('about:blank', { settle: 50 }); } catch (e) { srv.close(); if (e.notChecked) notChecked(e.message); throw e; }
  var ev = page.evaluate;
  var T = { pages: 0, loads: 0, loadFails: [], runs: 0, presses: 0, pressErrors: 0, byKind: {}, captures: { clip: 0, share: 0, blobs: 0, exec: 0 }, judged: 0, exempt: 0, extras: 0, blocked: 0,
            consoleThrows: [], findings: [], seen: {}, literals: [], literalCells: 0, stubs: 0, wirePanels: 0, wireKept: 0, wireExemptTokens: {}, perPage: {} };
  var idxJson = null;
  try { idxJson = JSON.parse(fs.readFileSync(path.join(siteDir, 'assets/data/ioc-index.json'), 'utf8')); } catch (e) { /* the search scenario then says NOT CHECKED for itself */ }

  async function navigate(rel, width) {
    await page.send('Emulation.setDeviceMetricsOverride', { width: width, height: 900, deviceScaleFactor: 1, mobile: false });
    await page.send('Emulation.setTouchEmulationEnabled', { enabled: width < 1024, maxTouchPoints: 5 });
    var url = srv.origin + '/' + rel.replace(/index\.html$/, '');
    await page.send('Page.navigate', { url: url });
    var end = Date.now() + 15000, ok = false;
    for (;;) {
      await sleep(150);
      try { if ((await ev('document.readyState')) === 'complete' && (await ev('location.href')).indexOf(srv.origin) === 0) { ok = true; break; } } catch (e) { /* navigating */ }
      if (Date.now() > end) break;
    }
    if (ok) await sleep(450);   // the scripts that build views after load
    return ok;
  }

  /* A captured string, judged unless exempt. kind: clip / share / blob / exec. */
  function judgeCapture(rel, kind, label, text, exempt) {
    T.captures[kind === 'blob' ? 'blobs' : kind]++;
    if (exempt) { T.exempt++; return; }
    T.judged++;
    scanner.scanText(rel, kind + ':' + label, text, T.literals).forEach(function (f) { T.findings.push(f); });
  }
  function judgePresses(rel, pageType, log, note) {
    if (!log || !log.presses) return;
    log.presses.forEach(function (p) {
      T.presses++;
      var k = p.cls || p.label || 'button';
      T.byKind[k] = (T.byKind[k] || 0) + 1;
      if (p.error) { T.pressErrors++; return; }
      var exempt = pageType === 'detection' || p.inPre;
      (p.clip || []).forEach(function (t) { judgeCapture(rel, 'clip', p.label, t, exempt); });
      (p.share || []).forEach(function (t) { judgeCapture(rel, 'share', p.label, t, exempt); });
      (p.blobs || []).forEach(function (t) { judgeCapture(rel, 'blob', p.label, t, exempt); });
      (p.exec || []).forEach(function (t) { judgeCapture(rel, 'exec', p.label, t, exempt); });
    });
  }
  var WIRE_PANEL = '.hl-dt__panel';
  var wireStrings = null;
  // the two fact-sheet files the panels are built from: the nKEVs tab (details-nkev.json) and the CVEs tab (details-cves.json), the same kind of third-party CVE-record text
  try { wireStrings = ['details-nkev.json', 'details-cves.json'].reduce(function (all, f) { return all.concat(SITE.wireDetailsStrings(fs.readFileSync(path.join(siteDir, 'wire', f), 'utf8'))); }, []); } catch (e) { wireStrings = null; }
  async function snapshot(rel, skip) {
    var isWire = SITE.pageType(rel) === 'wire';
    var raw = await ev(SERIALISE_SRC + '(' + JSON.stringify(skip || '') + (isWire ? ',' + JSON.stringify(WIRE_PANEL) : '') + ')');
    var html = raw, panels = [];
    if (isWire) { var o = JSON.parse(raw); html = o.html; panels = o.panels; }
    var found = scanner.scan(rel, html);
    // Wire details panels: judged apart; a finding whose token is a string of wire/details-nkev.json is third-party advisory text and is counted as exempt (lib/defang-site.js, wireDetailsSplit); every other finding in a panel is kept.
    panels.forEach(function (ph) {
      var pf = scanner.scan(rel, '<!DOCTYPE html><html><body>' + ph + '</body></html>');
      if (!wireStrings) { found = found.concat(pf); T.wirePanelNoFile = true; return; }
      var sp = SITE.wireDetailsSplit(pf, wireStrings);
      T.wirePanels++; T.wireKept += sp.kept.length; sp.exempt.forEach(function (f) { T.wireExemptTokens[f.kind + '\u0001' + f.token] = 1; });
      found = found.concat(sp.kept);
    });
    // the scanner returns this state's findings; they must be COLLECTED here (an earlier version judged the DOM and dropped the verdict, so a planted DOM defect was never reported).
    // The same token seen in several states of one page is one finding.
    found.forEach(function (f) {
      var key = [f.page, f.ctx, f.kind, f.token].join('\u0001');
      if (!T.seen[key]) { T.seen[key] = 1; T.findings.push(f); }
    });
    return found;
  }
  async function drive(rel, type, opts) {
    var log = await ev(DRIVE_SRC + '(' + JSON.stringify(opts) + ')');
    judgePresses(rel, type, log, '');
    return log;
  }

  /* ---- per-type scenarios (each snapshot is judged as a page state) ---- */
  async function scenarioIocIndex(rel) {
    if (!idxJson) { T.extras++; console.log('   NOT CHECKED  ioc-index.json unreadable: the search scenario did not run'); return; }
    var keys = Object.keys(idxJson.indicators);
    var pick = function (t) { var k = keys.filter(function (x) { return x.indexOf(t + ':') === 0 && !/^ipv4:(10\.|192\.168\.|127\.)/.test(x); }); return k.map(function (x) { return x.slice(t.length + 1); }); };
    var ips = pick('ipv4'), doms = pick('domain').filter(function (d) { return /^[a-z0-9-]+\.[a-z]{2,}$/.test(d); }), urls = pick('url');
    var titled = Object.keys(idxJson.reports).filter(function (r) { return /\d+\.\d+\.\d+\.\d+/.test(idxJson.reports[r].title); });
    var inTitled = keys.filter(function (k) { return /^(domain|ipv4):/.test(k) && idxJson.indicators[k].some(function (h) { return titled.indexOf(h.report) > -1; }); }).slice(0, 3).map(function (k) { return k.replace(/^[a-z0-9]+:/, ''); });
    var nb = Object.keys(idxJson.never_block || {}).filter(function (k) { return /^(domain|url):/.test(k); }).map(function (k) { return k.replace(/^[a-z0-9]+:/, ''); });
    var queries = [['defanged address', ips[0].replace(/\./g, '[.]')], ['raw address', ips[0]], ['domain', doms[0]], ['URL', urls[0]],
      ['list of five', [ips[0], doms[0], urls[0], ips[1], doms[1]].join('\n')], ['list whose feed titles carry an address', inTitled.join('\n')],
      ['list with a withheld value and a miss', [ips[0], nb[0] || doms[2], 'not-in-any-feed.example.net'].join('\n')]];
    for (var i = 0; i < queries.length; i++) {
      await ev('(function(q){var i=document.querySelector(".hl-iocsearch__in");i.value=q;i.dispatchEvent(new Event("input",{bubbles:true}));})(' + JSON.stringify(queries[i][1]) + ')');
      await sleep(600);
      var res = await ev('document.querySelector(".hl-iocsearch__result").textContent.length');
      T.extras++; (T.perPage[rel].scenarios = T.perPage[rel].scenarios || []).push(queries[i][0] + ' (result ' + res + ' chars)');
      await snapshot(rel, '.hl-iocsearch__in');   // the box holds what was typed: the reader's own text
    }
    // a ?q= link that carries a raw indicator: the page fills the box itself, so the box is judged
    await page.send('Page.navigate', { url: srv.origin + '/ioc-feeds/?q=' + encodeURIComponent([ips[0], doms[0]].join('\n')) });
    await sleep(1200);
    T.extras++; (T.perPage[rel].scenarios = T.perPage[rel].scenarios || []).push('?q= link with a raw address and domain');
    await snapshot(rel, '');
  }
  async function scenarioWire(rel) {
    // a toggle opens or closes its panel, and the expander pass has usually opened them all already: press only the ones that are closed, then count the panels that are open
    var n = await ev('(function(){var b=document.querySelectorAll(".hl-dt"),k=0;b.forEach(function(x){if(x.getAttribute("aria-expanded")!=="true"){k++;try{x.click()}catch(e){}}});return b.length})()');
    await sleep(1800);   // the two details files are fetched once each
    var panels = await ev('document.querySelectorAll(".hl-dt__panel").length');
    T.extras++; (T.perPage[rel].scenarios = T.perPage[rel].scenarios || []).push('Wire details opened: ' + n + ' toggles pressed, ' + panels + ' panels in the DOM');
    if (!n || !panels) T.findings.push({ page: rel, type: 'wire', ctx: 'scenario', kind: 'ZERO-DENOMINATOR', token: 'no Wire details toggle pressed or no panel opened (' + n + '/' + panels + ')' });
    await snapshot(rel, '');
  }
  async function scenarioSearch(rel) {
    var has = await ev('!!document.querySelector("#hl-search input, input[type=search], .pagefind-ui__search-input")');
    var qs = idxJson ? [Object.keys(idxJson.indicators).filter(function (k) { return k.indexOf('ipv4:') === 0; })[0].slice(5), 'xworm'] : ['xworm'];
    for (var i = 0; i < qs.length; i++) {
      if (has) {
        await ev('(function(q){var i=document.querySelector("#hl-search input, input[type=search], .pagefind-ui__search-input");i.focus();i.value=q;i.dispatchEvent(new Event("input",{bubbles:true}));})(' + JSON.stringify(qs[i]) + ')');
        await sleep(2000);
      }
      T.extras++; (T.perPage[rel].scenarios = T.perPage[rel].scenarios || []).push('site search "' + qs[i] + '" (' + (has ? 'typed' : 'NO SEARCH BOX FOUND') + ')');
      await snapshot(rel, 'input');
    }
  }

  var blocked = 0;
  try { await page.send('Network.setBlockedURLs', { urls: ['https://*', 'wss://*'] }); } catch (e) { /* blocking is a courtesy: third parties cannot change a verdict on local content */ }
  try { await page.send('Browser.setDownloadBehavior', { behavior: 'deny' }); } catch (e) { /* a refused download is not a page defect */ }
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: CAPTURE_SRC });

  console.log('check-browser-defang: ' + sel.pages.length + ' of ' + sel.total + ' pages (' + sel.notes.join('; ') + '), widths ' + widths.join('/') + ', site ' + siteDir);
  var started = Date.now();
  for (var pi = 0; pi < sel.pages.length; pi++) {
    var rel = sel.pages[pi], type = SITE.pageType(rel);
    T.pages++;
    for (var wi = 0; wi < widths.length; wi++) {
      var w = widths[wi];
      T.perPage[rel] = T.perPage[rel] || { type: type, runs: 0 };
      var before = T.findings.length;
      var loaded = false;
      // a redirect stub (Jekyll's "Redirecting..." page: a script and a meta refresh to the live host) leaves the local server by design; it is judged as the small static file it is and counted, not driven
      var stub = '';
      try { stub = fs.readFileSync(path.join(siteDir, rel), 'utf8'); } catch (e) { stub = ''; }
      if (stub.length < 2000 && /<title>Redirecting(?:&hellip;|\.\.\.)<\/title>/.test(stub) && /http-equiv="refresh"/.test(stub)) {
        T.stubs++; T.perPage[rel].runs++;
        scanner.scan(rel, stub).forEach(function (f) { T.findings.push(f); });
        continue;
      }
      try { loaded = await navigate(rel, w); } catch (e) { loaded = false; }
      if (!loaded) { T.loadFails.push(rel + ' @' + w); T.findings.push({ page: rel, type: type, ctx: 'load', kind: 'LOAD-FAILED', token: 'the page did not reach readyState complete at ' + w }); continue; }
      T.loads++; T.runs++; T.perPage[rel].runs++;
      // the page's own data-literal cells (hash, filename, path, registry values printed as recorded): a copy or download of them is exact by the same rule the page-wide pass applies
      T.literals = await ev('Array.prototype.map.call(document.querySelectorAll("[data-literal]"),function(e){return {type:e.getAttribute("data-literal"),value:e.textContent.trim()}})') || [];
      T.literalCells += T.literals.length;
      var errs = await ev('window.__hlcap ? window.__hlcap.errors : null');
      if (errs && errs.length) T.findings.push({ page: rel, type: type, ctx: 'stub', kind: 'STUB-FAILED', token: errs.join('; ') });
      // the page as loaded, then after the controls are pressed (two passes: expanders first, then the filter chips too)
      await snapshot(rel, '');
      await drive(rel, type, { expand: true, chips: false });
      await snapshot(rel, '');
      await drive(rel, type, { expand: false, chips: true });    // pass 2: every toggle and chip flipped
      await snapshot(rel, '');
      await drive(rel, type, { expand: false, chips: true });    // pass 3: flipped back, copied again
      if (type === 'ioc-feeds-index') await scenarioIocIndex(rel);
      else if (type === 'wire') await scenarioWire(rel);
      else if (rel === 'search/index.html') await scenarioSearch(rel);
      await snapshot(rel, '');
      T.perPage[rel].findings = (T.perPage[rel].findings || 0) + (T.findings.length - before);
    }
    if ((pi + 1) % 10 === 0) console.log('   ... ' + (pi + 1) + ' of ' + sel.pages.length + ' pages, ' + T.findings.length + ' findings, ' + Math.round((Date.now() - started) / 1000) + ' s');
  }
  var net = page.networkFailures ? page.networkFailures().length : 0;
  page.close(); srv.close();

  var st = scanner.stats;
  var byPage = {};
  T.findings.forEach(function (f) { var k = f.page + ' [' + f.type + ']'; (byPage[k] = byPage[k] || []).push(f); });
  console.log('');
  console.log('redirect stubs     ' + T.stubs + ' page(s) are Jekyll redirect stubs (script + meta refresh to the live host): read as static files, not driven');
  console.log('pages visited      ' + T.loads + ' loads of ' + (T.pages * widths.length) + ' planned (' + T.pages + ' pages x ' + widths.length + ' width(s)); failed to load: ' + T.loadFails.length);
  console.log('DOM states judged  ' + st.pages + ' (page as loaded, after expanders, after chips, after each scenario); text nodes ' + st.textNodes + ', tooltip attributes ' + st.attrs + ', indicator tokens: ' +
              st.matchedFlagged + ' flagged, ' + st.matchedDefanged + ' defanged, ' + st.matchedPrivate + ' private, ' + st.matchedAllowed + ' allowed');
  console.log('controls pressed   ' + T.presses + ' (errors ' + T.pressErrors + '): ' + Object.keys(T.byKind).sort().map(function (k) { return k + ' ' + T.byKind[k]; }).join(', '));
  console.log('captures           clipboard ' + T.captures.clip + ', share sheet ' + T.captures.share + ', downloads (blob text) ' + T.captures.blobs + ', execCommand copy ' + T.captures.exec +
              ' = ' + (T.captures.clip + T.captures.share + T.captures.blobs + T.captures.exec) + '; judged ' + T.judged + ', exempt ' + T.exempt + ' (taken from a <pre> rule block, or on a detection page: decision 5)');
  console.log('literal cells      ' + T.literalCells + ' data-literal cells read across the page loads; a captured line is judged without a value that equals one of them (hash, filename, path, registry as recorded)');
  console.log('wire exemption     ' + (wireStrings ? Object.keys(T.wireExemptTokens).length + ' distinct finding(s) inside Wire details panels exempt (' + T.wirePanels + ' panel states judged apart): the token is a string value of wire/details-nkev.json or wire/details-cves.json (third-party advisory text, lead decision T-0500.1.7.4 fix-r1); ' + T.wireKept + ' panel finding(s) kept as findings' : 'NONE (wire/details-nkev.json or details-cves.json not readable: every finding in a panel is kept)'));
  console.log('scenarios          ' + T.extras + ' (IOC search queries and ?q= link, Wire details, site search)');
  var zero = [];
  if (!T.loads) zero.push('no page loaded');
  if (!st.textNodes) zero.push('no text node judged');
  if (!T.presses) zero.push('no control pressed on any page');
  if (!T.judged) zero.push('no captured string judged (the clipboard stub never fired: it is not proven to work)');
  zero.forEach(function (z) { T.findings.push({ page: '(run)', type: 'run', ctx: 'denominator', kind: 'ZERO-DENOMINATOR', token: z }); byPage['(run) [run]'] = (byPage['(run) [run]'] || []).concat([{ kind: 'ZERO-DENOMINATOR', token: z, ctx: 'denominator' }]); });
  Object.keys(byPage).sort().forEach(function (k) {
    var l = byPage[k], seen = {};
    console.log('FAIL  ' + k + ': ' + l.length);
    l.forEach(function (f) { var line = '        ' + f.kind + ' [' + f.ctx + '] ' + require('./check-defang.js').defangForPrint(String(f.token)).slice(0, 110) + (f.near ? '   near: ' + require('./check-defang.js').defangForPrint(String(f.near)).slice(0, 80) : ''); if (!seen[line] && Object.keys(seen).length < 6) { seen[line] = 1; console.log(line); } });
  });
  if (outFile) fs.writeFileSync(outFile, JSON.stringify({ totals: { pages: T.pages, loads: T.loads, presses: T.presses, captures: T.captures, judged: T.judged, exempt: T.exempt, textNodes: st.textNodes, attrs: st.attrs }, findings: T.findings, perPage: T.perPage }, null, 1));
  var failed = T.findings.length > 0;
  console.log('');
  console.log((failed ? 'FAIL' : 'PASS') + '  ' + (failed ? T.findings.length + ' finding(s) on ' + Object.keys(byPage).length + ' page(s)' : 'no raw network indicator in the rendered DOM of ' + T.loads + ' page loads, in anything copied, shared or downloaded by ' + T.presses + ' presses, or in the IOC search, Wire details and site search scenarios') +
              '. CANNOT SEE: the real system clipboard and share sheet (stubbed: what the page hands them is judged), print and PDF output, hover and keyboard-only states beyond the presses above, browsers other than Chromium, pages and widths not in the selection above, text a third-party script writes (blocked), CSS generated content (::before/::after content: attr()), the machine feed downloads and rule bodies (exact by decision 5).');
  process.exit(failed ? 1 : 0);
})().catch(function (e) { console.log('FAIL  gate crashed: ' + (e && e.stack || e)); process.exit(1); });
