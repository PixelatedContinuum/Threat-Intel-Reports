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
var os = require('node:os');
var path = require('node:path');
var childProcess = require('node:child_process');

/* Chrome for Testing ships with the Playwright browser download and is present
   on this workstation. Env override first so a different machine can point at
   its own binary rather than editing this list. */
var CANDIDATES = [
  'C:/Users/josep/AppData/Local/ms-playwright/chromium_headless_shell-1217/chrome-headless-shell-win64/chrome-headless-shell.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/brave'
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

/* A blocking sleep with no event-loop yield and no subprocess, used only to
   pace the polling loop below. `Atomics.wait` blocks the calling thread on a
   value that never arrives, so it always times out after `ms`; nothing here
   depends on it interacting with libuv, since removeProfileDirWhenSafe()
   below deliberately never asks OUR OWN process about the browser's state
   (see that function's comment for why). */
function sleepSyncMs(ms) {
  var ia = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(ia, 0, 0, ms);
}

/* Best-effort, but no longer silent, removal of a launch's --user-data-dir.

   MEASURED 2026-09-22. Before this, close() called `proc.kill()` and then
   immediately `fs.rmSync(profileDir, ...)` inside a try/catch that swallowed
   everything. That leaked one directory per gate run -- 109 of them, 119 MB,
   in under an hour -- and the catch being silent meant nobody could tell
   whether rmSync was failing or something else was going on.

   It is not failing. `rmSync` returns cleanly and the directory is genuinely
   gone the instant it runs. The leak is a RACE: `proc.kill()` sends SIGTERM
   and returns immediately, but the browser is not one process, it is a tree
   (measured: 10, for a single `about:blank` launch -- renderer, GPU,
   network service, zygote, crashpad handler and the rest), and killing the
   main one does not make the tree stop executing in the same tick. One of
   those processes is still tearing down in the few milliseconds after
   rmSync runs, and it recreates a `Default/` subdirectory as part of that
   shutdown. A controlled probe confirms the mechanism directly: rmSync
   fired immediately after `proc.kill()` left a recreated directory in 1/1
   trials; the identical rmSync, fired only once every process matching this
   profile had actually stopped running, left nothing behind in 12/12 trials
   across three different kill strategies (SIGTERM to the main process alone,
   SIGKILL to the process group, SIGTERM to the process group) -- so this is
   a timing defect, not a signal-choice defect, and `proc.kill()` did not
   need to change.

   The obvious way to wait -- poll `process.kill(pid, 0)` on our own child
   until it throws ESRCH -- was tried and measured to NOT work from here.
   Node only reaps its own child (clears the zombie so the PID stops
   existing) when its event loop gets to run the SIGCHLD-driven callback,
   and close() is called synchronously by every caller with no `await`; a
   busy-wait that never yields never gives Node that chance. Measured
   directly: a plain child process left in that state read as "alive" for a
   full 2-second test window with zero yields, and only transitioned the
   instant a `setTimeout` let the event loop run. Driving OTHER synchronous
   child_process calls (`spawnSync`) in the busy-wait loop was tried too and
   made no difference -- `spawnSync` does not pump the calling process's own
   event loop either.

   So the check below asks the KERNEL directly, from a freshly spawned,
   unrelated process (`pgrep -f <profileDir>`), rather than asking Node
   about a PID Node itself is responsible for reaping. That sidesteps the
   zombie question entirely: a process's own command line (what `pgrep -f`
   matches against) clears the moment it stops running, whether or not its
   exit status has been collected by a parent, so "no match" is a genuine,
   external signal that nothing tied to this profile is still executing --
   never a signal that depends on this process's own bookkeeping. Measured:
   this check converges in a single ~30ms poll in every trial run, so the
   added wall-clock cost is negligible next to the multi-second settle times
   already elsewhere in this file.

   Three failure shapes, all handled, all visible instead of silent:
   - `pgrep` finds a match: keep polling, bounded by DEADLINE_MS.
   - the deadline passes with a match still present: log it and leave the
     directory in place. Removing it anyway is exactly the race being fixed.
   - `pgrep` itself cannot answer (missing binary, permission error, or
     anything other than its own "no match" exit code of 1): verification is
     not possible on this host, so fall back to one short fixed grace delay
     and then remove anyway, logging that the wait was skipped rather than
     pretending it happened. This is the one path that can still race in
     principle; it only runs on a platform or environment where the
     kernel-level check itself is unavailable. */
var PROFILE_WAIT_DEADLINE_MS = 2000;
var PROFILE_WAIT_POLL_MS = 20;
var PROFILE_WAIT_FALLBACK_GRACE_MS = 250;

function anyProcessMatches(profileDir) {
  try {
    childProcess.execFileSync('pgrep', ['-f', profileDir], { stdio: ['ignore', 'ignore', 'ignore'] });
    return true; // exit 0: pgrep found at least one still-running match
  } catch (e) {
    if (e.status === 1) return false; // pgrep's own "no match" exit code
    return null; // pgrep could not answer at all (missing, EPERM, ...)
  }
}

function removeProfileDirWhenSafe(profileDir, opts) {
  // opts is test-only (mirrors findBrowser's injectable env/exists above): real
  // callers never pass it, so PROFILE_WAIT_DEADLINE_MS stays the effective value
  // in production. It exists so the give-up-and-leave-it-in-place branch can be
  // exercised in a test without an actual 2-second wait.
  opts = opts || {};
  var deadline = Date.now() + (opts.deadlineMs || PROFILE_WAIT_DEADLINE_MS);
  for (;;) {
    var stillRunning = anyProcessMatches(profileDir);
    if (stillRunning === false) break;
    if (stillRunning === null) {
      console.error('hl-cdp: could not verify the browser process had exited ' +
        '(`pgrep` unavailable or unreadable); waiting ' + PROFILE_WAIT_FALLBACK_GRACE_MS +
        'ms as a fallback before removing ' + profileDir);
      sleepSyncMs(PROFILE_WAIT_FALLBACK_GRACE_MS);
      break;
    }
    if (Date.now() > deadline) {
      console.error('hl-cdp: a process still matches ' + profileDir + ' after ' +
        PROFILE_WAIT_DEADLINE_MS + 'ms; leaving the profile directory in place ' +
        'rather than risk removing it out from under a process that has not exited.');
      return;
    }
    sleepSyncMs(PROFILE_WAIT_POLL_MS);
  }
  try {
    fs.rmSync(profileDir, { recursive: true, force: true });
  } catch (e) {
    // Best-effort in EFFECT (never throws past the caller), but no longer
    // silent: a removal that genuinely fails here is worth knowing about.
    console.error('hl-cdp: could not remove ' + profileDir + ': ' + e.message);
  }
}

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

/* ---- brand identification -------------------------------------------------

   Measured 2026-09-22 via CDP against the binary this workstation actually
   runs (`/usr/bin/brave`, backed by `/opt/brave-bin/brave`): `/json/version`
   reports `Browser: Chrome/153.0.8010.48`. That is the CHROMIUM ENGINE
   version. It is not a lie exactly, Brave IS a Chromium build, but every check
   in this repo prints that field verbatim, so every run of this gate has
   LOOKED like it exercised Chrome when the workstation has never had Chrome,
   Chromium or google-chrome installed at all: `command -v` finds none of
   them. `page.version` stays exactly as it is below (three other checks print
   it and one lane depends on the raw string), and this section exists to give
   every caller an HONEST name to print alongside it instead.

   Two independent signals exist and neither is trustworthy alone:

   - The BINARY PATH. Decisive, because it names the executable that is
     actually running, but only as good as the candidate list in CANDIDATES.
   - `navigator.userAgentData.brands`. Populated by the engine itself
     (measured: `[{brand:"Brave",version:"153"},{brand:"Not_A Brand",
     version:"8"},{brand:"Chromium",version:"153"}]`), but it always carries a
     "GREASE" entry (a deliberately meaningless brand string, so a site sniffing
     for an exact brand list breaks instead of special-casing an unlisted one)
     and it always carries "Chromium" too, since every Chromium-family browser
     is honest about its own engine. A naive "first entry" or "any entry" read
     is wrong on both counts.

   Path wins when the two disagree, because a spoofed or absent Client Hints
   API says nothing about what actually launched, while the path is the
   command this file itself passed to `child_process.spawn`. But a disagreement
   is reported, never silently dropped: if the path scan and the runtime ever
   point at different products, that mismatch is itself worth seeing, not a
   detail to resolve by picking one field and throwing the other away. */

/* Order matters: brave / vivaldi / opera / edge are checked BEFORE chrome,
   and chromium is checked last, because a specific-brand path can be mistaken
   for a more generic one if the generic pattern is tried first (a Chrome for
   Testing path such as chrome-headless-shell.exe legitimately matches
   "chrome", but nothing here should ever get the chance to call a Brave path
   Chrome because a looser pattern fired first). Chromium is the fallback: it
   is the name of the open-source engine every one of these ships, so it is
   only correct to report once nothing more specific matched. */
var PATH_BRAND_PATTERNS = [
  ['Brave', /brave/i],
  ['Vivaldi', /vivaldi/i],
  ['Opera', /opera/i],
  ['Edge', /edge/i],
  ['Chrome', /chrome/i],
  ['Chromium', /chromium/i]
];

// Pure: no filesystem, no process, so it is testable on a string alone.
function brandFromPath(binPath) {
  if (!binPath) return null;
  for (var i = 0; i < PATH_BRAND_PATTERNS.length; i++) {
    if (PATH_BRAND_PATTERNS[i][1].test(binPath)) return PATH_BRAND_PATTERNS[i][0];
  }
  return null;
}

/* A GREASE brand looks like `Not_A Brand`, `Not)A;Brand` or ` Not A;Brand`:
   deliberately varying punctuation and spacing release over release so a site
   cannot hard-code one literal string. Stripping every non-letter and
   lowercasing collapses all of those variants to the same "notabrand", which
   is the only check narrow enough to catch the family without also matching
   a real brand name that happens to contain those letters. */
function isGreaseBrand(name) {
  return /^notabrand$/i.test(String(name || '').replace(/[^a-zA-Z]/g, ''));
}

/* Filters GREASE, then prefers a brand that is not literally "Chromium":
   Brave, Edge and the rest all carry a genuine "Chromium" entry alongside
   their own name (they ARE Chromium), so picking the first survivor without
   this preference would report the engine name on every one of them and
   never the brand. Only when nothing but Chromium (and GREASE) survives does
   Chromium become the honest answer, because at that point it is all the
   array actually says. */
function brandFromUaBrands(brands) {
  if (!Array.isArray(brands)) return null;
  var real = brands.filter(function (b) { return b && b.brand && !isGreaseBrand(b.brand); });
  if (!real.length) return null;
  var nonChromium = real.filter(function (b) { return b.brand !== 'Chromium'; });
  var pick = nonChromium[0] || real[0];
  return { name: pick.brand, version: pick.version };
}

/* PURE and testable without launching anything: given a binary path and a
   `userAgentData.brands` array (or null, for an engine/build with no Client
   Hints support at all), returns both readings plus the decisive call.
   Exported below as `brandOf`. */
function brandOf(binPath, uaBrands) {
  var fromPath = brandFromPath(binPath);
  var fromUaObj = brandFromUaBrands(uaBrands);
  var fromUa = fromUaObj ? fromUaObj.name : null;
  return {
    // The decisive name. Path first (see file-header note), UA as a fallback
    // for a binary path this file's pattern list does not recognise, and
    // 'unknown' rather than a guess when neither signal resolved anything.
    brand: fromPath || fromUa || 'unknown',
    fromPath: fromPath,
    fromUa: fromUa,
    uaVersion: fromUaObj ? fromUaObj.version : null,
    // false whenever either side is missing, not just when they conflict:
    // "agreement" should mean both signals were checked and matched.
    agree: !!(fromPath && fromUa && fromPath.toLowerCase() === fromUa.toLowerCase())
  };
}

/* `--version` on the actual binary is the most direct evidence available (for
   Brave, measured: `Brave Browser 153.1.95.102`) and is used as-is rather than
   reparsed, since re-deriving a product name from it would just be a second,
   worse brandFromPath. Wrapped in try/catch with a short timeout: a build that
   does not support `--version`, or one that is slow to answer under whatever
   invoked this gate, degrades to no product string rather than hanging the
   whole check or throwing past its caller. */
function captureProductVersion(bin) {
  try {
    return childProcess.execFileSync(bin, ['--version'], { timeout: 3000, encoding: 'utf8' }).trim();
  } catch (e) {
    return null;
  }
}

/* One line a check can print as-is that states the brand AND flags the engine
   string for what it is, so a reader never again mistakes Chrome/153.x for
   the browser's name. Shape: "Brave Browser 153.1.95.102  [engine
   Chrome/153.0.8010.48, /usr/bin/brave]", or, on a path/UA disagreement,
   the same line with both readings named rather than one silently dropped. */
function buildLabel(brandInfo, productVersion, engineVersion, binPath) {
  var head = productVersion ||
    (brandInfo.brand === 'unknown' ? 'Unknown browser' : brandInfo.brand);
  var disagreement = (brandInfo.fromPath && brandInfo.fromUa && !brandInfo.agree)
    ? ' (binary path says ' + brandInfo.fromPath + ', browser reports ' + brandInfo.fromUa + ')'
    : '';
  return head + disagreement + '  [engine ' + engineVersion + ', ' + binPath + ']';
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

  /* A fresh, isolated --user-data-dir on every launch. Before this, the
     browser was spawned with NO profile flag at all, which means headless
     Chrome/Brave attaches to the CALLER'S REAL, DEFAULT profile directory:
     this gate has been driving the user's live browser profile on every run.

     That is not just a hygiene problem, it is the root cause of a download
     defect measured with a 6-trial controlled probe (one variable changed at
     a time): a shared profile makes EVERY download transfer fully to
     `inProgress 100%` and then flip to `canceled` at the moment Chrome tries
     to commit the file, regardless of headless mode (`--headless` vs
     `--headless=new`) or download mechanism (blob vs. HTTP with
     Content-Disposition): both varied independently and neither moved the
     result. A fresh --user-data-dir, and only that variable, changed 0/3 to
     3/3 completed. The mechanism is the user's live Brave process holding the
     profile's `SingletonLock`; a second Chromium instance pointed at the same
     profile is allowed to browse but is not trusted to finish writing a file
     into it. Download path (`/tmp`, a `~/Downloads` subdirectory, or
     `~/Downloads` itself) made no difference, nor did the absence of any
     Brave `DownloadRestrictions` policy on this host: both were checked and
     ruled out before the profile was identified as decisive.

     Removed in close() once every process using it has actually exited (see
     removeProfileDirWhenSafe() above for why that check is not as simple as
     it sounds). `--no-first-run` and `--no-default-browser-check` suppress
     the first-launch prompts a brand new profile would otherwise show,
     which this gate never has a UI able to dismiss. */
  var profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-cdp-profile-'));
  var proc = childProcess.spawn(bin, [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
    '--window-size=' + (opts.width || 1280) + ',' + (opts.height || 1400),
    '--remote-debugging-port=' + port,
    '--remote-allow-origins=*',
    '--user-data-dir=' + profileDir,
    '--no-first-run',
    '--no-default-browser-check',
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

  /* Richer records, added alongside the two arrays above rather than in
     place of them. `consoleErrors()` and `networkUrls()` are depended on
     elsewhere (check-browser-wire.js `.join(' | ')`s the former; multiple
     checks read the latter) and both MUST keep returning plain strings:
     breaking that shape is a regression, not an enhancement. The detail
     below is new, additive surface for a caller that wants the URL a
     failure actually belongs to instead of just its text. */
  var reqUrlById = {};
  var networkFailures = [];
  var consoleErrorDetails = [];
  // Download lifecycle, keyed by CDP's own guid. See armDownloads() below for
  // how a caller reads "the browser canceled it" out of this.
  var downloadLog = [];

  ws.on('message', function (raw) {
    var m = JSON.parse(raw.toString());
    if (m.id && pending[m.id]) { pending[m.id](m); delete pending[m.id]; return; }
    if (m.method === 'Network.requestWillBeSent') {
      networkUrls.push(m.params.request.url);
      // Kept so a later loadingFailed for this requestId can be joined back
      // to the URL it belongs to: the event itself does not carry one.
      reqUrlById[m.params.requestId] = m.params.request.url;
    }
    if (m.method === 'Network.loadingFailed') {
      networkFailures.push({
        url: reqUrlById[m.params.requestId] || null,
        errorText: m.params.errorText,
        blockedReason: m.params.blockedReason || null,
        type: m.params.type || null
      });
    }
    if (m.method === 'Runtime.exceptionThrown') {
      var excText = m.params.exceptionDetails.text || 'exception';
      consoleErrors.push(excText);
      // No URL on a thrown exception's own event; recorded null rather than
      // guessed at, honestly, from something adjacent like the page URL.
      consoleErrorDetails.push({ text: excText, url: null, source: 'exception' });
    }
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
      consoleErrors.push(m.params.entry.text);
      // Log.entryAdded already carries the entry's OWN url; use it rather
      // than the page's URL, since a console error from a loaded script
      // legitimately points at that script, not at the document.
      consoleErrorDetails.push({
        text: m.params.entry.text,
        url: m.params.entry.url || null,
        source: m.params.entry.source || 'log'
      });
    }
    if (m.method === 'Browser.downloadWillBegin') {
      downloadLog.push({
        guid: m.params.guid, url: m.params.url,
        filename: m.params.suggestedFilename, state: 'pending'
      });
    }
    if (m.method === 'Browser.downloadProgress') {
      var rec = null;
      for (var di = 0; di < downloadLog.length; di++) {
        if (downloadLog[di].guid === m.params.guid) { rec = downloadLog[di]; break; }
      }
      if (!rec) {
        // downloadProgress arrived without a matching downloadWillBegin (seen
        // when the willBegin race loses to the first progress tick); record
        // it anyway rather than dropping the state transition on the floor.
        rec = { guid: m.params.guid, url: null, filename: null, state: null };
        downloadLog.push(rec);
      }
      rec.state = m.params.state;
      rec.totalBytes = m.params.totalBytes;
      rec.receivedBytes = m.params.receivedBytes;
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

  /* Brand identification, gathered once at open() time rather than lazily,
     since it needs a live page to read `navigator.userAgentData` from and
     every caller wants it printed up front (see the checks that log
     `page.version` as their first line). `evaluate` is a hoisted function
     declaration, callable here even though its own definition sits above:
     see the ordinary JS scoping rule, not a special case for this file. */
  var uaBrandsRaw = null;
  try {
    uaBrandsRaw = await evaluate(
      '(navigator.userAgentData && navigator.userAgentData.brands) ? ' +
      'navigator.userAgentData.brands : null'
    );
  } catch (evalErr) {
    // No Client Hints support (or the page threw evaluating it) is a fact
    // about the engine, not a reason to fail brand identification outright;
    // brandOf() falls back to the binary path alone.
    uaBrandsRaw = null;
  }
  var productVersion = captureProductVersion(bin);
  var brandInfo = brandOf(bin, uaBrandsRaw);
  var brandLabel = buildLabel(brandInfo, productVersion, up.Browser, bin);

  return {
    // KEPT EXACTLY AS-IS: the raw `/json/version` Browser string. Three
    // checks print it and one lane depends on it. This is the CHROMIUM
    // ENGINE version, not the brand: see brand / label below for the name.
    version: up.Browser,
    binary: bin,
    // The decisive brand name ('Brave', 'Chrome', 'Chromium', 'unknown', ...).
    brand: brandInfo.brand,
    // Both raw readings, so a disagreement is visible rather than resolved
    // silently in one direction.
    brandFromPath: brandInfo.fromPath,
    brandFromUa: brandInfo.fromUa,
    brandAgree: brandInfo.agree,
    // Raw trimmed `--version` output, or null if it could not be captured.
    productVersion: productVersion,
    // Ready to print as-is: e.g. "Brave Browser 153.1.95.102  [engine
    // Chrome/153.0.8010.48, /usr/bin/brave]".
    label: brandLabel,
    send: send,
    evaluate: evaluate,
    // Evaluate and parse, so a check can pull a whole object in one round trip.
    json: async function (expression) {
      return JSON.parse(await evaluate('JSON.stringify(' + expression + ')'));
    },
    /* Wait until a selector matches, rather than guessing a settle time.

       The picker, the register switch and the figure-nav chips are all BUILT by
       JavaScript after load, so "is it there" and "is it there yet" look
       identical to a single check. A fixed 2500ms settle reported the picker
       absent on a 30-rule page where it appears at about 3s, which reads as a
       feature that never rendered rather than a check that asked too early.
       Returns true if it appeared, false on timeout, so the caller can say
       NOT CHECKED honestly instead of failing. */
    waitFor: async function (selector, timeoutMs) {
      var deadline = Date.now() + (timeoutMs || 8000);
      for (;;) {
        if (await evaluate('!!document.querySelector(' + JSON.stringify(selector) + ')')) {
          return true;
        }
        if (Date.now() > deadline) return false;
        await sleep(200);
      }
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
      var scrollExpr = '(function(){var e=document.querySelector(' +
        JSON.stringify(selector) + ');if(!e)return null;' +
        'e.scrollIntoView({block:"center",behavior:"instant"});return null;})()';
      var measureExpr = '(function(){var e=document.querySelector(' +
        JSON.stringify(selector) + ');if(!e)return null;' +
        'var r=e.getBoundingClientRect();var x=r.x+r.width/2,y=r.y+r.height/2;' +
        'var hit=document.elementFromPoint(x,y);' +
        'return {x:x,y:y,onTarget:!!hit&&(hit===e||e.contains(hit)||hit.contains(e)),' +
        'hit:hit?(hit.tagName+"."+(hit.className||"").toString().split(" ")[0]):null};})()';

      await this.json(scrollExpr);
      // Re-read after the scroll has been applied, never in the same expression.
      await sleep(120);
      var pt = await this.json(measureExpr);
      if (!pt) throw new Error('click target not present: ' + selector);

      /* A layout shift AFTER the scroll moves the target without moving the
         viewport: a lazy `<img>` with no reserved width/height claims its real
         size the moment scrollIntoView brings the viewport near it, and
         everything below it, including the target just centred, slides down
         and off-screen. Measured 2026-09-08: one such image settling after one
         scrollIntoView call moved a real target 699px in under 30ms and left
         it there; waiting longer without re-scrolling never recovered it,
         because the shift is a one-time event, not an animation to sit out.

         A real reader never sees this. `loading="lazy"` fetches with a
         lookahead margin well before the image reaches the fold, so during an
         ordinary scroll the shift resolves while the image is still below the
         visible area. This helper reproduces the failure because it
         TELEPORTS to the target in one jump, landing at the exact moment the
         browser decides the image is now worth fetching, instead of passing
         near it first the way a scrolling reader does.

         So: settle, and if the target has moved, scroll again to correct for
         the drift, before trusting the landing check that follows. Bounded at
         5 rounds (~1s worst case) rather than open-ended, and it gives up as
         soon as position stops changing: a target that has stopped moving
         but is still off-target is genuinely covered or off-screen, not
         mid-settle, and no amount of re-scrolling will fix that. */
      for (var round = 0; round < 5 && !pt.onTarget; round++) {
        var before = pt;
        await this.json(scrollExpr);
        await sleep(200);
        pt = await this.json(measureExpr);
        if (!pt) throw new Error('click target not present: ' + selector);
        if (pt.onTarget) break;
        if (Math.abs(pt.x - before.x) < 2 && Math.abs(pt.y - before.y) < 2) break;
      }

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
    /* Catch what the page hands the reader.

       Both the detection picker and the feed viewer build a Blob, make an object
       URL, set `<a download>` and click it. jsdom has no download at all, so the
       feed viewer's own module keeps a `window.__lastDownloadText` hook purely so
       a test could see SOMETHING. That hook tests the string the page built, not
       the file a reader receives, and those differ whenever the download itself
       is what breaks.

       `behavior: "allow"` rather than `"allowAndName"`, deliberately: allowAndName
       writes every file under a GUID, which would silently discard the filename,
       and the filename is half the claim (an engine-native `.yar` / `.yml` /
       `.rules` is what makes a bundle usable). Both were measured. */
    armDownloads: async function (dir) {
      /* Native separators, always. Chrome accepts a forward-slash downloadPath
         on Windows without complaint and then writes nothing at all: no error,
         no event, an empty directory and every download check reporting
         NOTHING ARRIVED. path.resolve normalises it.

         AND GIVE EACH DOWNLOAD ITS OWN DIRECTORY. Under `behavior: "allow"`
         Chrome does not rename a download whose filename already exists in the
         target directory, it silently DISCARDS it: no file, no event, and the
         page's own "Downloaded N file(s)" note still updates, so the page looks
         like it worked. Proved by repeating a download under a different engine,
         which landed immediately. Re-arm with a fresh sub-directory per download
         rather than deleting between them, which does not work on Windows
         either: the file Chrome just wrote is still held and the unlink fails. */
      dir = path.resolve(dir);
      fs.mkdirSync(dir, { recursive: true });
      // Boundary for canceled(): only downloads that started at or after THIS
      // arm belong to this call, so a second armDownloads() in the same page
      // session (see check-browser-downloads.js's nextDl()) never reports a
      // previous download's cancellation as its own.
      var startLen = downloadLog.length;
      await send('Browser.setDownloadBehavior', {
        behavior: 'allow', downloadPath: dir, eventsEnabled: true
      });
      function complete() {
        return fs.readdirSync(dir).filter(function (f) {
          return !/\.crdownload$/i.test(f);
        });
      }
      return {
        dir: dir,
        // Names present right now. Pass this to waitNew so a second download is
        // never confused with the first.
        snapshot: complete,
        /* Wait for `n` files that were NOT in `before`, each non-empty and stable
           in size across two polls.

           Deleting between downloads was tried first and does not work: on
           Windows the file Chrome has just written is still held, the unlink
           fails silently, and the next wait returns the PREVIOUS download. That
           produced a TXT check reading a CSV. Waiting for genuinely new files
           sidesteps the deletion entirely.

           Size stability matters because Chrome creates the final file and then
           writes into it, so a fast poll can read zero bytes and report a
           content mismatch that is really a race. */
        waitNew: async function (before, n, timeoutMs) {
          var seen = {};
          (before || []).forEach(function (f) { seen[f] = true; });
          var deadline = Date.now() + (timeoutMs || 8000);
          var sizes = {};
          for (;;) {
            var fresh = complete().filter(function (f) { return !seen[f]; });
            var stable = fresh.filter(function (f) {
              var s = fs.statSync(path.join(dir, f)).size;
              var was = sizes[f];
              sizes[f] = s;
              return s > 0 && was === s;
            });
            if (stable.length >= n) {
              return stable.map(function (f) {
                return { name: f, content: fs.readFileSync(path.join(dir, f), 'utf8') };
              });
            }
            if (Date.now() > deadline) {
              // Report whatever arrived, named, rather than pretending to none.
              return fresh.map(function (f) {
                return { name: f, content: fs.readFileSync(path.join(dir, f), 'utf8') };
              });
            }
            await sleep(150);
          }
        },
        /* Distinguishes "the browser refused a download that started" from
           "the page never triggered one": two failures that look identical
           to waitNew() (both return zero files) but mean opposite things
           about what to report. A `Browser.downloadProgress` event reaching
           state 'canceled' means Chrome/Brave itself walked a transfer back
           after starting it: the measured shared-profile SingletonLock
           defect this file's constructor comment describes is exactly this
           shape: inProgress 100% then canceled at commit. That is an
           environment failure, not evidence against the page, and a caller
           seeing it here should report NOT CHECKED rather than FAIL. An empty
           array here with zero files from waitNew() means no download was
           even attempted, which IS a page-side finding worth failing on. */
        canceled: function () {
          return downloadLog.slice(startLen)
            .filter(function (d) { return d.state === 'canceled'; })
            .map(function (d) { return { guid: d.guid, url: d.url, filename: d.filename }; });
        }
      };
    },

    screenshot: async function (file) {
      var s = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(file, Buffer.from(s.result.data, 'base64'));
      return file;
    },
    networkUrls: function () { return networkUrls.slice(); },
    consoleErrors: function () { return consoleErrors.slice(); },
    // New, additive accessors: rich records instead of plain strings. Added
    // because the plain-string form throws away the URL a failure belongs
    // to, and a check chasing down a console error or a failed request has
    // no way to say WHERE it came from without it.
    networkFailures: function () { return networkFailures.slice(); },
    consoleErrorDetails: function () { return consoleErrorDetails.slice(); },
    close: function () {
      try { ws.close(); } catch (e) { /* already gone */ }
      try { proc.kill(); } catch (e) { /* already gone */ }
      // See removeProfileDirWhenSafe() above: this is still synchronous and
      // still best-effort in EFFECT (it never throws past the caller), but
      // it no longer races proc.kill() against the browser's own shutdown,
      // and a removal that genuinely cannot happen is now logged rather
      // than swallowed.
      removeProfileDirWhenSafe(profileDir);
    }
  };
}

module.exports = {
  open: open,
  findBrowser: findBrowser,
  sleep: sleep,
  brandOf: brandOf,
  // Test-only surface for the profile-cleanup race fixed 2026-09-22 (see
  // removeProfileDirWhenSafe's own comment above): exported so the wait/remove
  // and wait/give-up paths can be exercised directly against a real short-lived
  // marker process, without spawning an actual browser.
  removeProfileDirWhenSafe: removeProfileDirWhenSafe
};
