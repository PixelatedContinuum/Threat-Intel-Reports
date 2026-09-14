#!/usr/bin/env node
'use strict';

/* Gates the IOC feeds against values no organisation should ever block.

   The feeds are the machine-readable product. Some people pipe them straight into
   a blocklist without reading a word, which is a reasonable thing to do with a
   feed. A single `api.telegram.org` or `x.duckdns.org` line ingested that way takes
   out a platform, or an entire shared provider, for the whole estate, and nobody
   troubleshooting it ever traces it back here.

   Run with `--fix` to relocate what it finds into `hunt_only_never_block`.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');

var H, U;
try {
  H = require('./lib/feed-hygiene.js');
  U = require('./lib/unblockable.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var FIX = process.argv.indexOf('--fix') !== -1;

var files;
try {
  files = fs.readdirSync(FEED_DIR).filter(function (f) { return /\.json$/i.test(f); }).sort();
} catch (e) {
  console.log('NOT CHECKED  cannot read ' + FEED_DIR + ': ' + e.message);
  process.exit(2);
}
if (!files.length) {
  console.log('NOT CHECKED  no feeds found under ' + FEED_DIR + ', so this run checked nothing');
  process.exit(2);
}

var problems = [], changed = [], scanned = 0, unreadable = [], exemptions = [];

files.forEach(function (f) {
  var raw, doc;
  try { raw = fs.readFileSync(path.join(FEED_DIR, f), 'utf8'); doc = JSON.parse(raw); }
  catch (e) { unreadable.push(f + ': ' + e.message); return; }
  scanned++;

  // A second array per feed, not a shared one: H.scan() only ever pushes onto what it is
  // given, but keeping the accumulation per-file and merging here (rather than passing the
  // same array into every call) keeps this loop's shape identical to how `problems` already
  // works, and means a future per-feed exemption count costs nothing to add.
  var fileExemptions = [];
  var hits = H.scan(doc, fileExemptions);
  fileExemptions.forEach(function (x) {
    exemptions.push({ file: f, value: x.value, path: x.path, reason: x.reason });
  });
  if (!hits.length) return;

  if (FIX) {
    var r = H.migrate(doc);
    // Two spaces and a trailing newline, matching the corpus's existing style.
    fs.writeFileSync(path.join(FEED_DIR, f), JSON.stringify(r.feed, null, 2) + '\n', 'utf8');
    changed.push({ file: f, moved: r.moved, removed: r.removed });
  } else {
    hits.forEach(function (h) {
      problems.push(f + '  ' + h.host + '  (' + h.category + ')  at ' + h.path);
    });
  }
});

/* A run that could not read part of the corpus verified less than it looks like it
   did, so it says so rather than reporting a clean sweep of what it managed. */
if (unreadable.length) {
  console.log('NOT CHECKED  ' + unreadable.length + ' feed(s) could not be parsed, so ' +
    'this run did not cover the whole corpus:');
  unreadable.forEach(function (u) { console.log('   ' + u); });
  process.exit(2);
}

/* The allowlist is silent by construction (a suppressed finding never reaches `problems`),
   so a count nobody sees is not a control, it is an unmonitored exception mechanism that
   happens to be well-intentioned today. This prints on every run, PASS, FAIL or --fix, not
   only when something is actually exempted, so "0 exempted" is as visible as "1 exempted". */
var allowlistSize = Object.keys(H.NON_IDENTIFYING).length;
console.log('allowlist  ' + allowlistSize + ' approved non-identifying value(s) in force, ' +
  exemptions.length + ' exempted this run' + (exemptions.length ? ':' : ''));
exemptions.forEach(function (x) {
  console.log('   exempt   ' + x.value + '  at ' + x.file + ' :: ' + x.path +
    '  (' + x.reason + ')');
});

if (FIX) {
  var total = changed.reduce(function (n, c) { return n + c.moved.length; }, 0);
  var gone = changed.reduce(function (n, c) { return n + c.removed.length; }, 0);
  console.log('FIXED  ' + total + ' relocated to ' + U.BUCKET + ', ' + gone +
    ' victim value(s) REMOVED, across ' + changed.length + ' of ' + scanned + ' feed(s)');
  changed.forEach(function (c) {
    console.log('   ' + c.file);
    c.moved.forEach(function (m) {
      console.log('      moved    ' + m.host + '   (' + m.category + ')');
    });
    c.removed.forEach(function (m) {
      console.log('      REMOVED  ' + m.host + '   (' + m.category + ')');
    });
  });
  process.exit(0);
}

if (problems.length) {
  console.log('FAIL  ' + problems.length + ' value(s) in ' + scanned +
    ' feed(s) that must never reach an automated blocklist');
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  console.log('');
  console.log('Move them to the top-level `' + U.BUCKET + '` bucket, which sits outside');
  console.log('every indicator bucket so an automated consumer never reads it:');
  console.log('   node check-ioc-feeds.js --fix');
  process.exit(1);
}

console.log('PASS  ' + scanned + ' feed(s), no unblockable value in an indicator bucket');
process.exit(0);
