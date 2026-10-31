'use strict';

/* T-0505 / T-0500.1.11: a browser gate run owns its browser.

   The fault: lib/cdp.js asked for debugging port 9377 and probed /json/version on
   it, so a browser left over from an earlier run (or one a parallel run started)
   answered, and the gate drove it. Here:
   - pure logic (DevToolsActivePort, listener probe, liveness);
   - lib/cdp.js against cdp-fixtures/fake-browser.js, which stands in for Chromium;
   - the OLD cdp.js (cdp-fixtures/cdp-before-T-0505.js) against a decoy on 9377, which
     must attach to it (the control that shows the fault), and the new one, which must not;
   - runs ended every way a run can end (SIGTERM, SIGINT, SIGKILL, uncaught error,
     process.exit, a hang past the run budget): no browser process and no profile left.

   Nothing here needs a real browser, so these always run. The same controls against the
   real browser are in cdp-isolation-live.test.js (HL_CDP_LIVE_TESTS=1). */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var childProcess = require('node:child_process');
var CDP = require('../lib/cdp.js');

var FAKE = path.join(__dirname, '..', 'cdp-fixtures', 'fake-browser.js');
var RUNNER = path.join(__dirname, '..', 'cdp-fixtures', 'open-runner.js');
var OLD_CDP = path.join(__dirname, '..', 'cdp-fixtures', 'cdp-before-T-0505.js');
var DECOY_PORT = 9377;

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
function pidAlive(pid) { return CDP.processAlive(pid); }
function profilesMatching(dir) {
  try { childProcess.execFileSync('pgrep', ['-f', 'user-data-dir=' + dir], { stdio: 'ignore' }); return true; }
  catch (e) { return false; }
}
async function until(fn, ms) {
  var end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(100); }
  return !!(await fn());
}

/* Run a function with HL_CHROME (and friends) pointing at the fake browser. */
async function withFake(env, fn) {
  var saved = {};
  var set = Object.assign({ HL_CHROME: FAKE, HL_CDP_PROFILE_PREFIX: 'hl-cdp-unit-' }, env || {});
  Object.keys(set).forEach(function (k) { saved[k] = process.env[k]; process.env[k] = set[k]; });
  try { return await fn(); }
  finally {
    Object.keys(set).forEach(function (k) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    });
  }
}

/* ---------- pure logic ---------- */

test('parseDevToolsActivePort reads the port and the browser id path, and refuses anything else', function () {
  assert.deepStrictEqual(CDP.parseDevToolsActivePort('34759\n/devtools/browser/abc'), { port: 34759, wsPath: '/devtools/browser/abc' });
  assert.deepStrictEqual(CDP.parseDevToolsActivePort('9222\r\n/devtools/browser/x\r\n'), { port: 9222, wsPath: '/devtools/browser/x' });
  assert.deepStrictEqual(CDP.parseDevToolsActivePort('4000'), { port: 4000, wsPath: null });
  [null, '', '\n', 'abc', '0\n/x', '70000\n/x', '12ab\n/x', '-5\n/x'].forEach(function (bad) {
    assert.strictEqual(CDP.parseDevToolsActivePort(bad), null, JSON.stringify(bad));
  });
});

test('probeListener is true for a listening port and false for a closed one', async function () {
  var srv = require('node:net').createServer(function (s) { s.destroy(); });
  await new Promise(function (r) { srv.listen(0, '127.0.0.1', r); });
  var port = srv.address().port;
  assert.strictEqual(await CDP.probeListener(port), true);
  await new Promise(function (r) { srv.close(r); });
  assert.strictEqual(await CDP.probeListener(port), false);
});

test('processAlive: this process is alive, a finished one and a made-up pid are not', async function () {
  assert.strictEqual(CDP.processAlive(process.pid), true);
  var c = childProcess.spawn(process.execPath, ['-e', '0']);
  await new Promise(function (r) { c.on('exit', r); });
  assert.strictEqual(CDP.processAlive(c.pid), false);
  assert.strictEqual(CDP.processAlive(2 ** 22 + 12345), false);
});

/* ---------- lib/cdp.js against the fake browser ---------- */

test('open() lets the browser pick the port, owns the browser, and close() removes it and its profile', async function () {
  await withFake({}, async function () {
    var before = CDP.liveBrowsers();
    var page = await CDP.open('about:blank', { settle: 50 });
    assert.notStrictEqual(page.port, DECOY_PORT);
    assert.ok(page.port > 1024);
    assert.strictEqual(CDP.liveBrowsers(), before + 1);
    assert.ok(pidAlive(page.pid));
    assert.ok(fs.existsSync(page.profileDir));
    assert.strictEqual(await page.evaluate('document.title'), 'OWN');
    page.close();
    assert.strictEqual(CDP.liveBrowsers(), before);
    assert.ok(await until(function () { return !pidAlive(page.pid); }, 3000), 'browser pid still alive after close()');
    assert.strictEqual(fs.existsSync(page.profileDir), false, 'profile left behind');
    assert.strictEqual(profilesMatching(page.profileDir), false);
    page.close(); // idempotent
  });
});

test('two opens at once get different ports, pids and profiles', async function () {
  await withFake({}, async function () {
    var pair = await Promise.all([CDP.open('about:blank', { settle: 50 }), CDP.open('about:blank', { settle: 50 })]);
    try {
      assert.notStrictEqual(pair[0].port, pair[1].port);
      assert.notStrictEqual(pair[0].pid, pair[1].pid);
      assert.notStrictEqual(pair[0].profileDir, pair[1].profileDir);
    } finally { pair.forEach(function (p) { p.close(); }); }
  });
});

test('an explicit opts.port with a listener on it is refused NOT CHECKED and nothing connects to the listener', async function () {
  var logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-iso-'));
  var log = path.join(logDir, 'conn.log');
  await withFake({ HL_FAKE_CONN_LOG: log, HL_FAKE_TITLE: 'DECOY' }, async function () {
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-iso-decoy-'));
    var decoy = childProcess.spawn(FAKE, ['--user-data-dir=' + dir, '--remote-debugging-port=0'], { stdio: 'ignore' });
    try {
      assert.ok(await until(function () { return fs.existsSync(path.join(dir, 'DevToolsActivePort')); }, 5000));
      var decoyPort = CDP.parseDevToolsActivePort(fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8')).port;
      var before = CDP.liveBrowsers();
      await assert.rejects(CDP.open('about:blank', { port: decoyPort, settle: 50 }), function (e) {
        return e.notChecked === true && /already has a listener/.test(e.message);
      });
      assert.strictEqual(CDP.liveBrowsers(), before, 'a browser was launched anyway');
      assert.strictEqual(fs.existsSync(log), false, 'the run connected to the listener it refused');
    } finally {
      decoy.kill('SIGKILL');
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(logDir, { recursive: true, force: true });
    }
  });
});

test('a different browser answering on the reported port is refused, and the launched browser is cleaned up', async function () {
  await withFake({ HL_FAKE_MODE: 'wrong-id' }, async function () {
    var before = CDP.liveBrowsers();
    await assert.rejects(CDP.open('about:blank', { settle: 50 }), function (e) {
      return e.notChecked === true && /different browser/.test(e.message);
    });
    assert.strictEqual(CDP.liveBrowsers(), before);
  });
});

test('a browser that never opens its port is NOT CHECKED after the launch bound, and is cleaned up', async function () {
  await withFake({ HL_FAKE_MODE: 'no-port-file', HL_CDP_LAUNCH_WAIT_MS: '700' }, async function () {
    var t0 = Date.now();
    var before = CDP.liveBrowsers();
    await assert.rejects(CDP.open('about:blank', { settle: 50 }), function (e) {
      return e.notChecked === true && /never opened its debugging port/.test(e.message);
    });
    assert.ok(Date.now() - t0 < 6000, 'took ' + (Date.now() - t0) + 'ms');
    assert.strictEqual(CDP.liveBrowsers(), before);
  });
});

test('a browser that exits at once is NOT CHECKED with the exit named', async function () {
  await withFake({ HL_FAKE_MODE: 'exit-early' }, async function () {
    await assert.rejects(CDP.open('about:blank', { settle: 50 }), function (e) {
      return e.notChecked === true && /exited \(exit code 3\)/.test(e.message);
    });
  });
});

test('a command the browser never answers rejects NOT CHECKED after the send bound', async function () {
  await withFake({ HL_FAKE_MODE: 'hang-eval', HL_CDP_SEND_TIMEOUT_MS: '600' }, async function () {
    // open() itself evaluates once (brand), which hangs: the bound must apply there too.
    var t0 = Date.now();
    await assert.rejects(CDP.open('about:blank', { settle: 50 }), function (e) {
      return e.notChecked === true && /did not answer Runtime\.evaluate within/.test(e.message);
    });
    assert.ok(Date.now() - t0 < 6000);
    assert.strictEqual(CDP.liveBrowsers(), 0 + CDP.liveBrowsers()); // registry reachable
  });
});

test('a browser that dies mid-command rejects the waiting command NOT CHECKED instead of leaving it waiting', async function () {
  await withFake({ HL_FAKE_MODE: 'die-on-eval' }, async function () {
    await assert.rejects(CDP.open('about:blank', { settle: 50 }), function (e) { return e.notChecked === true; });
  });
});

/* ---------- the control that shows the old fault ---------- */

async function startDecoyOn9377() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-iso-decoy-'));
  var env = Object.assign({}, process.env, { HL_FAKE_TITLE: 'DECOY' });
  var decoy = childProcess.spawn(FAKE, ['--user-data-dir=' + dir, '--remote-debugging-port=' + DECOY_PORT], { stdio: 'ignore', env: env });
  var ok = await until(function () {
    try { return CDP.parseDevToolsActivePort(fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8')).port === DECOY_PORT; }
    catch (e) { return false; }
  }, 5000);
  return { ok: ok, stop: function () { decoy.kill('SIGKILL'); fs.rmSync(dir, { recursive: true, force: true }); } };
}

test('CONTROL: with a decoy browser on 9377 the OLD cdp.js attaches to it; the new one drives its own', async function (t) {
  if (await CDP.probeListener(DECOY_PORT)) {
    t.skip('NOT CHECKED: something already listens on 9377 on this host, so the decoy cannot be placed');
    return;
  }
  var decoy = await startDecoyOn9377();
  try {
    assert.ok(decoy.ok, 'the decoy did not come up on 9377');
    await withFake({ HL_FAKE_TITLE: 'OWN' }, async function () {
      var OLD = require(OLD_CDP);
      var oldPage = await OLD.open('about:blank', { settle: 50 });
      var oldTitle;
      try { oldTitle = await oldPage.evaluate('document.title'); } finally { oldPage.close(); }
      assert.strictEqual(oldTitle, 'DECOY', 'the old code was expected to attach to the browser on 9377');

      var page = await CDP.open('about:blank', { settle: 50 });
      try {
        assert.notStrictEqual(page.port, DECOY_PORT);
        assert.strictEqual(await page.evaluate('document.title'), 'OWN');
      } finally { page.close(); }
      // and the new code, told to use 9377, refuses instead of attaching
      await assert.rejects(CDP.open('about:blank', { port: DECOY_PORT, settle: 50 }), function (e) { return e.notChecked === true; });
    });
  } finally { decoy.stop(); }
});

/* ---------- a run ended every way a run can end ---------- */

function startRunner(how, env) {
  var out = '';
  var child = childProcess.spawn(process.execPath, [RUNNER, how], {
    env: Object.assign({}, process.env, { HL_CHROME: FAKE, HL_CDP_PROFILE_PREFIX: 'hl-cdp-unit-' }, env || {}), stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', function (d) { out += d; });
  child.stderr.on('data', function (d) { out += d; });
  var exited = new Promise(function (r) { child.on('exit', function (code, sig) { r({ code: code, sig: sig }); }); });
  return {
    child: child, exited: exited, output: function () { return out; },
    info: async function () {
      assert.ok(await until(function () { return /\{.*"pid"/.test(out); }, 8000), 'runner never printed its browser: ' + out);
      return JSON.parse(out.split('\n').filter(function (l) { return l.indexOf('{') === 0; })[0]);
    }
  };
}

async function assertBrowserGone(info, ms) {
  assert.ok(await until(function () { return !pidAlive(info.pid); }, ms || 5000), 'browser ' + info.pid + ' still alive');
  assert.ok(await until(function () { return !fs.existsSync(info.profileDir); }, ms || 5000), 'profile ' + info.profileDir + ' left behind');
  assert.strictEqual(profilesMatching(info.profileDir), false);
}

[['SIGTERM', 143], ['SIGINT', 130], ['SIGHUP', 129]].forEach(function (c) {
  test('a run stopped by ' + c[0] + ' leaves no browser and no profile', async function () {
    var r = startRunner('hang');
    var info = await r.info();
    assert.ok(pidAlive(info.pid));
    r.child.kill(c[0]);
    var ex = await r.exited;
    assert.strictEqual(ex.code, c[1]);
    await assertBrowserGone(info);
  });
});

test('a run killed with SIGKILL (uncatchable) leaves no browser and no profile: the watchdog ends it', async function () {
  var r = startRunner('hang');
  var info = await r.info();
  assert.ok(pidAlive(info.pid));
  r.child.kill('SIGKILL');
  await r.exited;
  await assertBrowserGone(info, 8000);
});

test('a run that dies of an uncaught error leaves no browser and no profile', async function () {
  var r = startRunner('throw');
  var info = await r.info();
  var ex = await r.exited;
  assert.notStrictEqual(ex.code, 0);
  // At once, not "within the watchdog's poll": the exit hook does this, the watchdog is only the backstop.
  await assertBrowserGone(info, 300);
});

test('a run that calls process.exit with the page still open leaves no browser and no profile', async function () {
  var r = startRunner('exit');
  var info = await r.info();
  var ex = await r.exited;
  assert.strictEqual(ex.code, 0);
  await assertBrowserGone(info, 300);
});

test('a run that hangs past the run budget prints NOT CHECKED, exits 2 and leaves no browser', async function () {
  var r = startRunner('hang', { HL_CDP_RUN_TIMEOUT_MS: '1500' });
  var info = await r.info();
  var t0 = Date.now();
  var ex = await r.exited;
  assert.strictEqual(ex.code, 2);
  assert.ok(Date.now() - t0 < 6000);
  assert.match(r.output(), /NOT CHECKED {2}the browser run did not finish within 2s \(HL_CDP_RUN_TIMEOUT_MS\)/);
  await assertBrowserGone(info);
});

test('a run that closes normally leaves no watchdog behind', async function () {
  var r = startRunner('close');
  var info = await r.info();
  var ex = await r.exited;
  assert.strictEqual(ex.code, 0);
  await assertBrowserGone(info);
  assert.ok(info.watchdog > 0, 'no watchdog was started');
  assert.ok(await until(function () { return !pidAlive(info.watchdog); }, 4000), 'watchdog ' + info.watchdog + ' still running');
});
