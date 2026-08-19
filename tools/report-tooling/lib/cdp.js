'use strict';

/* A minimal Chrome DevTools Protocol driver, for the checks that jsdom cannot do.

   Every automated check in this repo before this one ran in jsdom, which has no
   layout, no computed styles, no real pointer and no downloads. That left one
   sentence repeated across the claim matrix in different clothes: nothing proves
   it renders, that a click works, that a file arrives. Every appearance defect
   across eleven builds was instead caught by a human looking at a page.

   That was never an effort problem. A headless Chrome for Testing has been
   installed the whole time, and `ws` is all that is needed to drive it, so this
   file exists to close that gap. It deliberately depends on nothing else: no
   Playwright, no Puppeteer, no install step.

   HONESTY. A missing browser is NOT CHECKED with the reason named, never a
   silent pass. See homelab-soc/docs/gate-honesty-contract.md. */

var http = require('node:http');
var fs = require('node:fs');
var childProcess = require('node:child_process');

/* Chrome for Testing ships with the Playwright browser download and is present
   on this workstation. Env override first so a different machine can point at
   its own binary rather than editing this list. */
var CANDIDATES = [
  'C:/Users/josep/AppData/Local/ms-playwright/chromium_headless_shell-1217/chrome-headless-shell-win64/chrome-headless-shell.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/chromium',
  '/usr/bin/google-chrome'
];

/* Returns { path } or { error }.

   An HL_CHROME that is set but does not exist is an ERROR, not a reason to fall
   through to the scan. Falling through would let someone point the gate at a
   specific build, get silently served a different one, and read the result as if
   their build had passed. `exists` is injected so the honesty paths are testable
   without moving files around. */
function findBrowser(env, exists) {
  env = env || process.env;
  exists = exists || fs.existsSync;
  if (env.HL_CHROME) {
    return exists(env.HL_CHROME)
      ? { path: env.HL_CHROME }
      : { error: 'HL_CHROME points at ' + env.HL_CHROME + ', which does not exist.' };
  }
  for (var i = 0; i < CANDIDATES.length; i++) {
    if (exists(CANDIDATES[i])) return { path: CANDIDATES[i] };
  }
  return { error: 'no headless Chrome found. Set HL_CHROME to a Chrome or ' +
    'Chromium binary, or install one, then re-run.' };
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function getJSON(url) {
  return new Promise(function (resolve, reject) {
    http.get(url, function (res) {
      var b = '';
      res.on('data', function (d) { b += d; });
      res.on('end', function () {
        try { resolve(JSON.parse(b)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

/* Opens a page and returns a small handle. Throws a NotChecked-tagged error
   when the environment cannot support the check, so callers can map that to
   exit 2 rather than reporting a pass or a failure. */
async function open(url, opts) {
  opts = opts || {};
  var found = findBrowser();
  if (found.error) {
    var e = new Error(found.error);
    e.notChecked = true;
    throw e;
  }
  var bin = found.path;

  var WebSocket;
  try {
    WebSocket = require('ws');
  } catch (err) {
    var e2 = new Error('the `ws` module is missing. Run `npm ci` in ' +
      'tools/report-tooling, then re-run this gate.');
    e2.notChecked = true;
    throw e2;
  }

  var port = opts.port || 9377;
  var proc = childProcess.spawn(bin, [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
    '--window-size=' + (opts.width || 1280) + ',' + (opts.height || 1400),
    '--remote-debugging-port=' + port,
    '--remote-allow-origins=*',
    'about:blank'
  ], { stdio: 'ignore' });

  var up = null;
  for (var i = 0; i < 80 && !up; i++) {
    try { up = await getJSON('http://127.0.0.1:' + port + '/json/version'); }
    catch (err) { await sleep(250); }
  }
  if (!up) {
    proc.kill();
    var e3 = new Error('the browser started but never opened its debugging port.');
    e3.notChecked = true;
    throw e3;
  }

  var list = await getJSON('http://127.0.0.1:' + port + '/json/list');
  var target = list.filter(function (t) { return t.type === 'page'; })[0];
  var ws = new WebSocket(target.webSocketDebuggerUrl, { perMessageDeflate: false });

  var id = 0;
  var pending = {};
  var networkUrls = [];
  var consoleErrors = [];
  ws.on('message', function (raw) {
    var m = JSON.parse(raw.toString());
    if (m.id && pending[m.id]) { pending[m.id](m); delete pending[m.id]; return; }
    if (m.method === 'Network.requestWillBeSent') networkUrls.push(m.params.request.url);
    if (m.method === 'Runtime.exceptionThrown') {
      consoleErrors.push(m.params.exceptionDetails.text || 'exception');
    }
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
      consoleErrors.push(m.params.entry.text);
    }
  });
  await new Promise(function (r) { ws.on('open', r); });

  function send(method, params) {
    return new Promise(function (resolve) {
      var myId = ++id;
      pending[myId] = resolve;
      ws.send(JSON.stringify({ id: myId, method: method, params: params || {} }));
    });
  }

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');
  await send('Log.enable');
  await send('Page.navigate', { url: url });
  await sleep(opts.settle || 2500);

  async function evaluate(expression) {
    var r = await send('Runtime.evaluate', {
      expression: expression, returnByValue: true, awaitPromise: true
    });
    if (r.result && r.result.exceptionDetails) {
      throw new Error('page threw: ' + r.result.exceptionDetails.text +
        ' while evaluating: ' + expression);
    }
    return r.result.result.value;
  }

  return {
    version: up.Browser,
    binary: bin,
    send: send,
    evaluate: evaluate,
    // Evaluate and parse, so a check can pull a whole object in one round trip.
    json: async function (expression) {
      return JSON.parse(await evaluate('JSON.stringify(' + expression + ')'));
    },
    // Computed style of the first match, the thing jsdom cannot answer at all.
    computed: async function (selector, props) {
      return JSON.parse(await evaluate(
        '(function(){var e=document.querySelector(' + JSON.stringify(selector) + ');' +
        'if(!e)return "null";var c=getComputedStyle(e);var r=e.getBoundingClientRect();' +
        'var o={_present:true,_w:Math.round(r.width),_h:Math.round(r.height)};' +
        JSON.stringify(props || []) + '.forEach(function(p){o[p]=c[p];});' +
        'return JSON.stringify(o);})()'));
    },
    /* Put an element into :hover (or :focus, :active) and leave it there.

       Synthetic mouse moves do NOT produce hover state in headless Chrome. That
       was measured, not assumed: dispatching mouseMoved at the element's exact
       centre, confirmed by elementFromPoint, left `el.matches(":hover")` false
       and the glossary tooltip at opacity 0, through a plain move and through a
       move-away-and-back. `CSS.forcePseudoState` flipped both immediately.

       This matters beyond one tooltip: a hover check built on mouse moves would
       report every CSS-driven hover reveal on the site as broken, and a check
       written to pass anyway would be reporting nothing at all. Pass an empty
       array to release. */
    forcePseudo: async function (selector, classes) {
      var doc = await send('DOM.getDocument', { depth: 1 });
      var found = await send('DOM.querySelector', {
        nodeId: doc.result.root.nodeId, selector: selector
      });
      var nodeId = found.result && found.result.nodeId;
      if (!nodeId) throw new Error('forcePseudo target not present: ' + selector);
      await send('CSS.enable', {});
      await send('CSS.forcePseudoState', {
        nodeId: nodeId, forcedPseudoClasses: classes || []
      });
      return nodeId;
    },

    /* A real pointer press and release at the element's centre, not el.click().

       TWO things here are load-bearing, both learned from a check that reported
       nonsense with total confidence.

       `behavior: "instant"` is required because this site sets
       `html { scroll-behavior: smooth }`. With smooth scrolling, scrollIntoView
       ANIMATES, so a rect read immediately afterwards is the PRE-scroll
       position, and the click lands on whatever happens to sit at those stale
       coordinates. On a long report that put a figure-nav chip click 39,000px
       away from the chip; the page moved, so it looked like the feature had
       worked, and the check failed for a reason that had nothing to do with it.

       And the landing is VERIFIED before dispatching. A mis-click is otherwise
       silent: the event goes somewhere, some handler may run, and the check
       reports on an element nobody meant to touch. */
    click: async function (selector) {
      var pt = await this.json('(function(){var e=document.querySelector(' +
        JSON.stringify(selector) + ');if(!e)return null;' +
        'e.scrollIntoView({block:"center",behavior:"instant"});return null;})()');
      // Re-read after the scroll has been applied, never in the same expression.
      await sleep(120);
      pt = await this.json('(function(){var e=document.querySelector(' +
        JSON.stringify(selector) + ');if(!e)return null;' +
        'var r=e.getBoundingClientRect();var x=r.x+r.width/2,y=r.y+r.height/2;' +
        'var hit=document.elementFromPoint(x,y);' +
        'return {x:x,y:y,onTarget:!!hit&&(hit===e||e.contains(hit)||hit.contains(e)),' +
        'hit:hit?(hit.tagName+"."+(hit.className||"").toString().split(" ")[0]):null};})()');
      if (!pt) throw new Error('click target not present: ' + selector);
      if (!pt.onTarget) {
        throw new Error('click for "' + selector + '" would land on ' + pt.hit +
          ' at (' + Math.round(pt.x) + ',' + Math.round(pt.y) + '); the target is ' +
          'covered or off-screen, so the click was not dispatched');
      }
      await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
      await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: pt.x, y: pt.y, button: 'left', clickCount: 1 });
      await sleep(200);
    },
    /* How many matches are actually RENDERED, measured by box rather than by the
       element's own computed display.

       `getComputedStyle(el).display` reports the element's OWN value and does not
       inherit `none` from an ancestor, so a link inside a hidden list item still
       reports `inline` and counts as visible. That produced a confident false
       failure the first time this ran against a report: the register switch hides
       the `<li>`, all 53 TOC links still reported themselves visible, and the
       check called a working feature broken.

       A zero-area box is the honest signal: only `display: none`, on the element
       or on any ancestor, collapses it. `visibility: hidden` and `opacity: 0`
       keep their box and are deliberately NOT counted as hidden here, because
       they are a different question and the glossary tooltip asks it separately. */
    visibleCount: function (selector) {
      return evaluate('[].slice.call(document.querySelectorAll(' +
        JSON.stringify(selector) + ')).filter(function(e){' +
        'var r=e.getBoundingClientRect();return r.width>0||r.height>0;}).length');
    },
    screenshot: async function (file) {
      var s = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(file, Buffer.from(s.result.data, 'base64'));
      return file;
    },
    networkUrls: function () { return networkUrls.slice(); },
    consoleErrors: function () { return consoleErrors.slice(); },
    close: function () { try { ws.close(); } catch (e) { /* already gone */ } proc.kill(); }
  };
}

module.exports = { open: open, findBrowser: findBrowser, sleep: sleep };
