'use strict';

/* T-0505: the same controls as cdp-isolation.test.js, against the REAL browser (findBrowser(): HL_CHROME, else
   chromium / chrome / brave). Opt-in, because it launches real browsers:

     flock /home/jharrison/ai-workflows/tasks/runs/T-0500.1.10/gate.lock \
       env HL_CDP_LIVE_TESTS=1 node --test test/cdp-isolation-live.test.js

   Without HL_CDP_LIVE_TESTS=1 every test here is skipped and says so (NOT CHECKED, not passed). */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var childProcess = require('node:child_process');
var CDP = require('../lib/cdp.js');

var LIVE = process.env.HL_CDP_LIVE_TESTS === '1';
var SKIP = LIVE ? false : 'NOT CHECKED: set HL_CDP_LIVE_TESTS=1 to launch the real browser';
var RUNNER = path.join(__dirname, '..', 'cdp-fixtures', 'open-runner.js');
var OLD_CDP = path.join(__dirname, '..', 'cdp-fixtures', 'cdp-before-T-0505.js');
var DECOY_PORT = 9377;

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
async function until(fn, ms) {
  var end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(100); }
  return !!(await fn());
}
function decoyTabs() {
  return new Promise(function (resolve, reject) {
    require('node:http').get('http://127.0.0.1:' + DECOY_PORT + '/json/list', function (res) {
      var b = '';
      res.on('data', function (d) { b += d; });
      res.on('end', function () { try { resolve(JSON.parse(b).filter(function (t) { return t.type === 'page'; })); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}
function pgrepCount(pattern) {
  var r = childProcess.spawnSync('pgrep', ['-f', pattern]);
  return r.status === 0 ? r.stdout.toString().trim().split('\n').length : 0;
}

test('LIVE CONTROL: a real browser on 9377 is driven by the OLD cdp.js, never by the new one', { skip: SKIP }, async function (t) {
  if (await CDP.probeListener(DECOY_PORT)) { t.skip('NOT CHECKED: something already listens on 9377'); return; }
  var found = CDP.findBrowser();
  assert.ok(found.path, found.error);
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-decoy-'));
  var decoy = childProcess.spawn(found.path, ['--headless', '--disable-gpu', '--no-sandbox', '--remote-debugging-port=' + DECOY_PORT,
    '--remote-allow-origins=*', '--user-data-dir=' + dir, '--no-first-run', 'data:text/html,<title>DECOY</title>'],
  { stdio: 'ignore', detached: true });
  try {
    assert.ok(await until(function () { return CDP.probeListener(DECOY_PORT); }, 10000), 'decoy did not listen on 9377');
    await sleep(800);
    /* Which browser did the run drive? The decoy's own tab list says: a run that attached to it
       navigated ITS tab. (A page title is not enough: the run navigates whatever tab it attached
       to, so OWN would read back from either browser.) */
    var before = await decoyTabs();
    assert.match(before[0].url, /DECOY/, 'the decoy tab should start on the DECOY page: ' + before[0].url);

    var OLD = require(OLD_CDP);
    var oldPage = await OLD.open('data:text/html,<title>OLD-RUN</title>', { settle: 300 });
    try { assert.strictEqual(await oldPage.evaluate('document.title'), 'OLD-RUN'); } finally { oldPage.close(); }
    var afterOld = await decoyTabs();
    assert.match(afterOld[0].url, /OLD-RUN/, 'the old code was expected to navigate the decoy tab: ' + afterOld[0].url);

    var page = await CDP.open('data:text/html,<title>NEW-RUN</title>', { settle: 300 });
    try {
      assert.notStrictEqual(page.port, DECOY_PORT);
      assert.strictEqual(await page.evaluate('document.title'), 'NEW-RUN');
    } finally { page.close(); }
    var afterNew = await decoyTabs();
    assert.strictEqual(afterNew[0].url, afterOld[0].url, 'the new code touched the decoy tab: ' + afterNew[0].url);
    await assert.rejects(CDP.open('about:blank', { port: DECOY_PORT, settle: 100 }), function (e) { return e.notChecked === true; });
    assert.ok(await CDP.probeListener(DECOY_PORT), 'the decoy must be untouched by the new code');
  } finally {
    try { process.kill(-decoy.pid, 'SIGKILL'); } catch (e) { /* gone */ }
    try { decoy.kill('SIGKILL'); } catch (e) { /* gone */ }
    await sleep(500);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

[['SIGTERM'], ['SIGINT'], ['SIGKILL']].forEach(function (c) {
  test('LIVE CONTROL: a real-browser run killed with ' + c[0] + ' mid-way leaves no hl-cdp-profile process', { skip: SKIP }, async function () {
    var env = Object.assign({}, process.env); delete env.HL_CHROME;
    var out = '';
    var child = childProcess.spawn(process.execPath, [RUNNER, 'hang'], { env: env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', function (d) { out += d; });
    child.stderr.on('data', function (d) { out += d; });
    var exited = new Promise(function (r) { child.on('exit', r); });
    assert.ok(await until(function () { return /"pid"/.test(out); }, 15000), 'runner never opened the browser: ' + out);
    var info = JSON.parse(out.split('\n').filter(function (l) { return l.indexOf('{') === 0; })[0]);
    var pattern = 'user-data-dir=' + info.profileDir;
    assert.ok(pgrepCount(pattern) > 1, 'expected a browser process tree while the run is open');
    child.kill(c[0]);
    await exited;
    assert.ok(await until(function () { return pgrepCount(pattern) === 0; }, 8000), 'browser processes left: ' + pgrepCount(pattern));
    assert.ok(await until(function () { return !fs.existsSync(info.profileDir); }, 8000), 'profile left behind');
  });
});
