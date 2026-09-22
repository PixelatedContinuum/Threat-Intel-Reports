'use strict';

/* Tests for the browser gate's own machinery: lib/cdp.js and lib/wire-harness.js.

   These do NOT drive a browser. Driving one is check-browser-wire.js, and its
   value is precisely that it does what no test in this repo could. What is
   testable here is the part that decides whether a run happened at all, and the
   part that builds the page under test.

   Both matter for the same reason. A browser gate that quietly reports success
   when it never found a browser, or that builds a page missing the theme
   stylesheet, is worse than no gate: it converts an unverified claim into a
   green tick. See homelab-soc/docs/gate-honesty-contract.md. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var childProcess = require('node:child_process');
var CDP = require('../lib/cdp.js');
var WH = require('../lib/wire-harness.js');
var JSDOM = require('jsdom').JSDOM;

/* ---- findBrowser: the run-or-not decision ---- */

test('an explicit HL_CHROME that exists is used', function () {
  var r = CDP.findBrowser({ HL_CHROME: '/opt/my-chrome' }, function (p) { return p === '/opt/my-chrome'; });
  assert.equal(r.path, '/opt/my-chrome');
  assert.equal(r.error, undefined);
});

test('an HL_CHROME that does not exist is an error, not a fallback', function () {
  /* Falling through to the scan would serve a DIFFERENT browser than the one
     asked for and report the result as if it were that build. */
  // The scenario that matters: the named binary is absent while a candidate on
  // the scan list IS present, so a fallback would silently succeed.
  var r = CDP.findBrowser({ HL_CHROME: '/opt/missing' },
    function (p) { return p !== '/opt/missing'; });
  assert.equal(r.path, undefined);
  assert.match(r.error, /HL_CHROME points at \/opt\/missing/);
});

test('with no env set, a present candidate is found', function () {
  var r = CDP.findBrowser({}, function (p) { return /chrome|chromium/i.test(p); });
  assert.ok(r.path, 'expected a candidate path');
});

test('no browser anywhere reports an error naming the remedy', function () {
  var r = CDP.findBrowser({}, function () { return false; });
  assert.equal(r.path, undefined);
  assert.match(r.error, /HL_CHROME/);
});

test('open() throws a NOT CHECKED error rather than failing, when no browser exists', async function () {
  // The distinction the gate-honesty contract turns on: a run that could not
  // happen is not a run that failed.
  var saved = process.env.HL_CHROME;
  process.env.HL_CHROME = '/definitely/not/a/browser/anywhere';
  try {
    await CDP.open('about:blank');
    assert.fail('expected open() to throw');
  } catch (e) {
    assert.equal(e.notChecked, true, 'must be tagged notChecked, so the CLI can exit 2');
    assert.match(e.message, /does not exist/);
  } finally {
    if (saved === undefined) delete process.env.HL_CHROME;
    else process.env.HL_CHROME = saved;
  }
});

/* ---- brandOf: naming the browser by BRAND, not just the Chromium engine ----

   Pure and testable without launching anything, per the file's own comment:
   these exercise brandFromPath / brandFromUaBrands / brandOf directly, on
   binary-path strings and a userAgentData.brands array, exactly the shape
   check-browser-wire.js and check-browser-downloads.js already print
   page.version + page.label for. Nothing here spawns a browser: see the
   file header above for why that boundary is deliberate. */

// The array measured 2026-09-22 via CDP against the workstation's real Brave.
var BRAVE_UA_BRANDS = [
  { brand: 'Brave', version: '153' },
  { brand: 'Not_A Brand', version: '8' },
  { brand: 'Chromium', version: '153' }
];

test('a Brave binary path is named Brave', function () {
  assert.equal(CDP.brandOf('/usr/bin/brave', null).brand, 'Brave');
  assert.equal(CDP.brandOf('/opt/brave-bin/brave', null).brand, 'Brave');
});

test('a google-chrome path is named Chrome, never Brave or Chromium', function () {
  var r = CDP.brandOf('/usr/bin/google-chrome', null);
  assert.equal(r.brand, 'Chrome');
  assert.notEqual(r.brand, 'Brave');
  assert.notEqual(r.brand, 'Chromium');
});

test('a bare chromium path is named Chromium', function () {
  assert.equal(CDP.brandOf('/usr/bin/chromium', null).brand, 'Chromium');
});

test('the measured Brave userAgentData.brands array names Brave, GREASE filtered, Chromium not winning', function () {
  // Path deliberately withheld (null) to isolate what the UA-brands reading
  // alone resolves to.
  var r = CDP.brandOf(null, BRAVE_UA_BRANDS);
  assert.equal(r.fromUa, 'Brave');
  assert.equal(r.brand, 'Brave');
});

test('a brands array carrying only Chromium and GREASE resolves to Chromium', function () {
  var r = CDP.brandOf(null, [
    { brand: 'Chromium', version: '153' },
    { brand: 'Not_A Brand', version: '8' }
  ]);
  assert.equal(r.fromUa, 'Chromium');
  assert.equal(r.brand, 'Chromium');
});

test('path and UA disagreeing reports BOTH, neither silently dropped', function () {
  // A Chrome-named binary somehow reporting Brave's own UA brands: contrived,
  // but exactly the shape a caller must not resolve by picking one side.
  var r = CDP.brandOf('/usr/bin/google-chrome', BRAVE_UA_BRANDS);
  assert.equal(r.fromPath, 'Chrome', 'the path reading must survive');
  assert.equal(r.fromUa, 'Brave', 'the UA reading must survive');
  assert.equal(r.agree, false);
  // The binary path is decisive per the file's own doctrine.
  assert.equal(r.brand, 'Chrome');
});

test('a path matching no known brand does not crash and reports unknown honestly', function () {
  assert.doesNotThrow(function () { CDP.brandOf('/usr/bin/mystery-browser', null); });
  var r = CDP.brandOf('/usr/bin/mystery-browser', null);
  assert.equal(r.fromPath, null);
  assert.equal(r.fromUa, null);
  assert.equal(r.brand, 'unknown');
});

/* ---- removeProfileDirWhenSafe: the --user-data-dir cleanup race, fixed 2026-09-22 ----

   Real bug, real regression cover, no browser needed. The defect measured
   2026-09-22 (see the function's own comment in lib/cdp.js) was never that
   rmSync failed; it raced a process that had been told to exit but had not
   actually stopped running yet. These tests reproduce that exact shape with
   a real, short-lived marker process standing in for the browser -- `sleep`,
   given the target directory's own path as one of its arguments so
   `pgrep -f <dir>` genuinely matches it while it runs -- rather than mocking
   anything, so what is exercised is the real wait loop against a real
   process the kernel actually schedules. */

function markerFor(dir, seconds) {
  /* `sh -c "sleep <seconds>; : <dir>"`, not `sleep <seconds> <dir>`.

     GNU `sleep` treats every argument as a NUMBER to add to the total delay,
     so a second, non-numeric argument makes it exit immediately with
     "invalid time interval" instead of running for `seconds` -- measured
     directly after this test first failed for the wrong reason (the
     directory really was removed, because the "still-running" marker had
     already exited by the time the check ran).

     Routing the directory's path through a no-op `sh` command instead keeps
     it in `sh`'s OWN argv for the process's whole lifetime -- `sh` blocks on
     its `sleep` child for the full duration before it ever reaches the
     `: <dir>` no-op -- which is exactly what `pgrep -f <dir>` needs to match
     against, without changing how long the marker actually runs. */
  return childProcess.spawn('/bin/sh', ['-c', 'sleep ' + seconds + '; : ' + dir], { stdio: 'ignore' });
}

test('the directory is removed once the process using it has actually exited', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-cdp-profile-test-'));
  var marker = markerFor(dir, 0.1);
  var t0 = Date.now();
  CDP.removeProfileDirWhenSafe(dir);
  var elapsed = Date.now() - t0;
  assert.equal(fs.existsSync(dir), false, 'directory should be gone once the process exited');
  // Loose bound: must not have removed instantly (that would mean it never
  // waited at all), and must not have burned anywhere near the 2s deadline
  // for a process that only ran 100ms.
  assert.ok(elapsed < 1000, 'should not fall through to the full deadline: took ' + elapsed + 'ms');
  marker.kill(); // already exited; best-effort, mirrors production's own style
});

test('a still-running process blocks removal, and the directory is left in place at the deadline', function () {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-cdp-profile-test-'));
  var marker = markerFor(dir, 5); // deliberately outlives the short deadline below
  try {
    var t0 = Date.now();
    CDP.removeProfileDirWhenSafe(dir, { deadlineMs: 80 });
    var elapsed = Date.now() - t0;
    assert.ok(elapsed >= 80, 'should have actually waited out the deadline: took ' + elapsed + 'ms');
    assert.equal(fs.existsSync(dir), true,
      'must NOT remove a directory a process is still using, even after giving up on waiting');
  } finally {
    marker.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/* ---- wire-harness: the page under test ---- */

function liveLike(rowsHtml) {
  return '<html><head>' +
    '<link rel="stylesheet" href="/assets/css/main.css">' +
    '<script src="/assets/js/main.min.js"></script>' +
    '</head><body>' +
    '<div class="hl-filter" data-listing-filter>' +
    '<input class="hl-filter__search" placeholder="Filter headlines…">' +
    '<div class="hl-filter__chips"><button class="hl-chip-btn" data-tag="">All</button></div>' +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden>No headlines match that filter. ' +
    '<button data-filter-reset>Clear filters</button></div>' +
    '</div>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">' + rowsHtml + '</div>' +
    '</body></html>';
}

var ROWS =
  '<div class="hl-wire__day" data-filter-group>Tuesday 18 August 2026</div>' +
  '<a class="hl-wire__item" data-title="one"></a>' +
  '<a class="hl-wire__item" data-title="two"></a>' +
  '<div class="hl-wire__day" data-filter-group>Sunday 16 August 2026</div>' +
  '<a class="hl-wire__item" data-title="three"></a>';

function parts(over) {
  return Object.assign({
    liveHtml: liveLike(ROWS),
    themeCss: 'body{font-size:1.25em}',
    customCss: '.hl-filter__date{display:flex}',
    filterJs: 'window.__ran=1;'
  }, over || {});
}

test('a day heading is parsed into the ISO day the filter compares against', function () {
  assert.equal(WH.headingToDay('Tuesday 18 August 2026'), '2026-08-18');
  assert.equal(WH.headingToDay('Sunday 6 July 2026'), '2026-07-06', 'single-digit day pads');
  assert.equal(WH.headingToDay('not a date'), null);
});

test('every row is tagged with the day of the heading above it', function () {
  var b = WH.build(JSDOM, parts());
  assert.equal(b.rows, 3);
  assert.deepEqual(b.days, ['2026-08-16', '2026-08-18']);
  assert.deepEqual(b.dayCounts, { '2026-08-18': 2, '2026-08-16': 1 });
});

test('a day inside the span with no rows is reported as a gap', function () {
  // The quiet-day empty state has nothing to exercise without one.
  var b = WH.build(JSDOM, parts());
  assert.deepEqual(b.gaps, ['2026-08-17']);
});

test('the harness carries the date control and the empty-message span', function () {
  var b = WH.build(JSDOM, parts());
  assert.match(b.html, /data-filter-date(?![-a-z])/, 'the date input');
  assert.match(b.html, /data-filter-date-clear/, 'the clear control');
  assert.match(b.html, /data-filter-empty-msg/, 'the reason span');
  assert.match(b.html, /Search headlines, topics, actors/, 'the reworded placeholder');
});

test('the theme stylesheet is in the built page, not just custom.css', function () {
  /* Without it the body computes at 16px instead of 20px, `em` and `rem`
     coincide, and the rem check silently stops being able to tell them apart.
     That happened on the first build of this harness. */
  var b = WH.build(JSDOM, parts());
  assert.match(b.html, /body\{font-size:1\.25em\}/, 'theme sheet missing');
  assert.match(b.html, /\.hl-filter__date\{display:flex\}/, 'custom sheet missing');
});

test('the published stylesheets and scripts are swapped out, not left alongside', function () {
  // Leaving them would load the DEPLOYED module over the working-tree one and
  // silently check the wrong code.
  var b = WH.build(JSDOM, parts());
  assert.doesNotMatch(b.html, /<link[^>]+stylesheet/, 'a published stylesheet survived');
  assert.doesNotMatch(b.html, /<script[^>]+src=/, 'a published script survived');
  assert.match(b.html, /window\.__ran=1;/, 'the working-tree module is not present');
});

test('a page with no rows throws rather than reporting an empty pass', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: liveLike('') }));
  }, /rendered no wire rows/);
});

test('a row before any heading throws rather than being tagged with a guess', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: liveLike('<a class="hl-wire__item"></a>') }));
  }, /before any day heading/);
});

test('an unparseable heading throws rather than dropping that day', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({
      liveHtml: liveLike('<div data-filter-group>Some Day</div><a class="hl-wire__item"></a>')
    }));
  }, /unparseable day heading/);
});

test('a page missing the filter bar throws', function () {
  assert.throws(function () {
    WH.build(JSDOM, parts({ liveHtml: '<html><body><div data-filter-grid></div></body></html>' }));
  }, /no \[data-listing-filter\]|rendered no wire rows/);
});

/* ---- once the feature ships, the harness reads it instead of adding it ----

   Injecting unconditionally was right while the day filter was unreleased. The
   moment it deployed, doing so would have built a page with TWO date controls
   and every later assertion would have addressed the injected one rather than
   the one actually shipped, which is the quietest way for a browser gate to
   stop checking anything. */

// A published page: it already carries the control, the span, and its own data-day.
var SHIPPED_BAR =
  '<div class="hl-filter" data-listing-filter>' +
  '<input class="hl-filter__search" placeholder="Search headlines, topics, actors…">' +
  '<div class="hl-filter__chips"><button class="hl-chip-btn" data-tag="">All</button></div>' +
  '<div class="hl-filter__date"><label class="hl-filter__dim">Date</label>' +
  '<input class="hl-filter__dateinput" type="date" data-filter-date>' +
  '<button class="hl-filter__datereset" data-filter-date-clear hidden>Clear date</button></div>' +
  '<div class="hl-filter__count" data-filter-count></div>' +
  '<div class="hl-filter__empty" data-filter-empty hidden>' +
  '<span data-filter-empty-msg>No headlines match that filter.</span>' +
  '<button data-filter-reset>Clear filters</button></div>' +
  '</div>';

function shipped(rowsHtml) {
  return '<html><head></head><body>' + SHIPPED_BAR +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__item">' +
    rowsHtml + '</div></body></html>';
}

var SHIPPED_ROWS =
  '<div class="hl-wire__day" data-filter-group>Tuesday 18 August 2026</div>' +
  '<a class="hl-wire__item" data-day="2026-08-18"></a>' +
  '<a class="hl-wire__item" data-day="2026-08-18"></a>' +
  '<div class="hl-wire__day" data-filter-group>Sunday 16 August 2026</div>' +
  '<a class="hl-wire__item" data-day="2026-08-16"></a>';

test('a shipped page gets exactly one date control, not a second', function () {
  var b = WH.build(JSDOM, parts({ liveHtml: shipped(SHIPPED_ROWS) }));
  var doc = new JSDOM(b.html).window.document;
  assert.equal(doc.querySelectorAll('[data-filter-date]').length, 1);
  assert.equal(doc.querySelectorAll('[data-filter-date-clear]').length, 1);
  assert.equal(doc.querySelectorAll('[data-filter-empty-msg]').length, 1);
  assert.equal(b.deployed.control, true);
  assert.equal(b.deployed.emptyMsg, true);
});

test('a shipped page reports how many rows carry data-day', function () {
  var b = WH.build(JSDOM, parts({ liveHtml: shipped(SHIPPED_ROWS) }));
  assert.equal(b.deployed.carriedRows, 3);
  assert.deepEqual(b.disagreements, []);
});

test('a deployed data-day disagreeing with its own heading is reported', function () {
  /* The timezone split that carrying the day exists to prevent, seen against
     the DEPLOYED template rather than the working tree. */
  var bad = SHIPPED_ROWS.replace('<a class="hl-wire__item" data-day="2026-08-18"></a>',
    '<a class="hl-wire__item" data-day="2026-08-17"></a>');
  var b = WH.build(JSDOM, parts({ liveHtml: shipped(bad) }));
  assert.equal(b.disagreements.length, 1);
  assert.match(b.disagreements[0], /2026-08-18 heading carries data-day="2026-08-17"/);
});

test('a template tagging only some rows is reported, not averaged away', function () {
  // The untagged rows would be invisible to every date a reader picks.
  var partial = SHIPPED_ROWS.replace('<a class="hl-wire__item" data-day="2026-08-16"></a>',
    '<a class="hl-wire__item"></a>');
  var b = WH.build(JSDOM, parts({ liveHtml: shipped(partial) }));
  assert.equal(b.deployed.carriedRows, 2);
  assert.match(b.disagreements.join(' '), /2 of 3 rows carry data-day/);
});

test('a pre-release page still reports nothing carried, so the check says NOT CHECKED', function () {
  var b = WH.build(JSDOM, parts());
  assert.equal(b.deployed.carriedRows, 0);
  assert.equal(b.deployed.control, false);
  assert.deepEqual(b.disagreements, []);
});
