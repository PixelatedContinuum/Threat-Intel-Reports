#!/usr/bin/env node
'use strict';

/* Gates _data/ioc_tables.yml AND the stub pages against ioc-feeds/ + the catalog.

   Regenerate-and-diff, the same approach check-ioc-index.js and
   check-detection-manifest.js use: if rebuilding changes it, what is committed
   is stale.

   This generator writes TWO things, so both are checked. A manifest that matches
   while a stub is missing serves a 404 from a listing card; a stub that survives
   after its campaign went back under embargo serves a rendered page for content
   that is supposed to be off every listing. The second is the one that matters.

   THE NO-LOSS HALF (design v4 check 5, 2026-10-29). Regenerate-and-diff catches a
   STALE table; it cannot catch a CORRECT AND NARROWER regeneration, which is the
   direction this table has actually failed in twice. So the new table is also
   compared row by row with the previously published one: a (feed, value) row that
   was there before and is gone now is a FAIL, unless the value is the same value
   under another type or case AND the surviving row keeps the previous row's action,
   or the feed itself lists it in non_indicators, explicitly_excluded or
   metadata.reference. A whole feed block may disappear only when its JSON is gone
   or the feed is embargoed. Every removed row is printed with its reason class,
   with a count per class (`lib/ioc-table-noloss.js` explains the boundaries and
   the classes).

   Previous table:
     --against <path>       compare against this file (a `git show` redirect, a
                            review's copy, or the pre-task table)
     (default)              `git show HEAD:_data/ioc_tables.yml`. The comparison
                            runs whether or not the working file differs from HEAD:
                            a working table identical to HEAD is still compared
                            against the FRESH regeneration, so a regeneration that
                            removes a row is caught and named here rather than only
                            by the staleness half (D1). A repository with no HEAD
                            table (the first commit that adds one) is a stated skip,
                            and a git failure is NOT CHECKED, never a pass.

   --after <path> exists for reproducing a comparison and for the control that must
   fail: it replaces the new side only. The staleness half still reads the real
   working file, so an --after copy can never make a stale table look current.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');
var cp = require('node:child_process');

var ROOT = path.join(__dirname, '..', '..');
var OUT = path.join(ROOT, '_data', 'ioc_tables.yml');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');

var GEN, CDM, NL, G, CS;
try {
  GEN = require('./generate-ioc-tables.js');
  CDM = require('./lib/check-detection-manifest.js');   // shared normalise + diff
  NL = require('./lib/ioc-table-noloss.js');            // design v4 check 5
  G = require('./generate-ioc-index.js');               // readFeeds / readUnlisted
  CS = require('./lib/catalog-status.js');              // the generator's own status rule
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

function arg(name) {
  var a = process.argv.slice(2);
  for (var i = 0; i < a.length; i++) {
    if (a[i] === name) return i + 1 < a.length ? a[i + 1] : '';
    if (a[i].indexOf(name + '=') === 0) return a[i].slice(name.length + 1);
  }
  return null;
}

function gitShow(rev) {
  return cp.execFileSync('git', ['show', rev], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

/* { status: 'OK', text, source } | { status: 'SAME', text } |
   { status: 'SKIP', reason } | { status: 'NOT CHECKED', reason } */
function previousTable() {
  var explicit = arg('--against');
  if (explicit !== null) {
    if (!explicit) return { status: 'NOT CHECKED', reason: '--against needs a file path' };
    try {
      return { status: 'OK', text: fs.readFileSync(explicit, 'utf8'),
               source: explicit };
    } catch (e) {
      return { status: 'NOT CHECKED',
               reason: 'could not read --against ' + explicit + ': ' + e.message };
    }
  }

  var disk;
  try { disk = fs.readFileSync(OUT, 'utf8'); }
  catch (e) { return { status: 'SKIP', reason: 'the working table is not readable: ' + e.message }; }

  try {
    var head = gitShow('HEAD:_data/ioc_tables.yml');
    if (head === disk) {
      return { status: 'SAME', text: disk, source:
        'git show HEAD:_data/ioc_tables.yml, byte-identical to the working file' };
    }
    return { status: 'OK', text: head, source: 'git show HEAD:_data/ioc_tables.yml' };
  } catch (e) {
    try { cp.execFileSync('git', ['rev-parse', '--git-dir'], { cwd: ROOT, stdio: 'ignore' }); }
    catch (e2) {
      return { status: 'NOT CHECKED',
               reason: 'no git repository at ' + ROOT +
                 ', so the previously published table cannot be read' };
    }
    try { cp.execFileSync('git', ['cat-file', '-e', 'HEAD:_data/ioc_tables.yml'],
                          { cwd: ROOT, stdio: 'ignore' }); }
    catch (e3) {
      return { status: 'SKIP',
               reason: 'HEAD has no _data/ioc_tables.yml, so there is no previously ' +
                 'published table to compare (the first commit that adds one)' };
    }
    return { status: 'NOT CHECKED',
             reason: 'git could not read HEAD:_data/ioc_tables.yml: ' +
               String((e && e.message) || e).split('\n')[0] };
  }
}

/* Runs the check-5 comparison and returns the lines to print plus any problems.
   The new side is the freshly generated table (what a publish would write), so a
   stale working file cannot make the comparison look complete. */
/* The generator's own publication rule, for D3: a feed block may disappear only
   when its JSON is absent or the feed is embargoed. `unknown` (a feed the catalog
   never lists) does NOT excuse a disappearance, and neither does an unreadable
   catalog: the comparison then fails closed rather than guessing. */
var STATUS_CACHE = null;
function statusMap() {
  if (STATUS_CACHE !== null) return STATUS_CACHE;
  try {
    var catText = fs.readFileSync(path.join(ROOT, '_data', 'catalog.yml'), 'utf8');
    var unlisted = G.readUnlisted(path.join(ROOT, 'reports'));
    var resolved = CS.resolve(catText, unlisted);
    STATUS_CACHE = resolved.status || {};
  } catch (e) {
    STATUS_CACHE = {};
  }
  return STATUS_CACHE;
}

function feedState(file) {
  if (!file) return { exists: false, status: null };
  var exists = false;
  try { exists = fs.statSync(path.join(FEED_DIR, file)).isFile(); }
  catch (e) { exists = false; }
  if (!exists) return { exists: false, status: null };
  var map = statusMap();
  return { exists: true, status: map[file] || 'unknown' };
}

function noLoss(freshText) {
  var out = { lines: [], problems: [] };
  var prev = previousTable();

  if (prev.status === 'NOT CHECKED') {
    out.notChecked = prev.reason;
    return out;
  }
  if (prev.status === 'SKIP') {
    out.lines.push('   no-loss  skipped: ' + prev.reason);
    return out;
  }

  var afterText = freshText;
  var afterLabel = 'the regenerated table';
  var afterPath = arg('--after');
  if (afterPath !== null) {
    if (!afterPath) { out.notChecked = '--after needs a file path'; return out; }
    try { afterText = fs.readFileSync(afterPath, 'utf8'); afterLabel = afterPath; }
    catch (e) {
      out.notChecked = 'could not read --after ' + afterPath + ': ' + e.message;
      return out;
    }
  }

  var cmp;
  try {
    cmp = NL.compare(prev.text, afterText, {
      readFeed: function (file) {
        return JSON.parse(fs.readFileSync(path.join(FEED_DIR, file), 'utf8'));
      },
      feedState: feedState
    });
  } catch (e) {
    out.notChecked = 'the comparison could not be made: ' + e.message;
    return out;
  }

  var removedRows = cmp.removed.reduce(function (n, r) { return n + (r.rows || 1); }, 0);

  /* D1: whether the working table equals HEAD or not, the comparison that matters
     is HEAD against the FRESH regeneration. It runs on both paths, and a removed
     row is reported and fails here, with its own counts, rather than being left to
     the staleness half to notice silently. */
  out.lines.push('   no-loss  previous: ' + prev.source + ' (' + cmp.before_feeds +
    ' feeds, ' + cmp.before_rows + ' rows)');
  out.lines.push('   no-loss  now:      ' + afterLabel + ' (' + cmp.after_feeds +
    ' feeds, ' + cmp.after_rows + ' rows)');

  (cmp.fatal || []).forEach(function (f) { out.problems.push(f); });

  if (!cmp.removed.length) {
    out.lines.push('   no-loss  removed 0 rows of ' + cmp.before_rows + ' compared');
    return out;
  }

  var classes = Object.keys(cmp.counts).sort().map(function (k) {
    return (NL.REASONS[k] || k) + ' ' + cmp.counts[k];
  });
  out.lines.push('   no-loss  removed ' + removedRows + ' rows of ' + cmp.before_rows +
    ' compared: ' + classes.join(', '));
  out.lines.push('   no-loss  every removed row, with its reason class:');
  cmp.removed.forEach(function (r) {
    out.lines.push('   no-loss    ' + r.feed + '  ' + r.type + '  ' + r.value +
      '  ->  ' + (NL.REASONS[r.reason] || r.reason) + ' (' + r.detail + ')');
  });

  if (cmp.unexplained) {
    out.problems.push('the regeneration REMOVES ' + cmp.unexplained + ' row' +
      (cmp.unexplained === 1 ? '' : 's') + ' of ' + cmp.before_rows +
      ' previously published, with no reason the feed gives (listed above). ' +
      'Design v4 check 5: IOC tables lose nothing. Restore the rows, or have the ' +
      'feed list the values in non_indicators / explicitly_excluded / ' +
      'metadata.reference, or pass a reviewed --against.');
  }
  return out;
}

var gen;
try { gen = GEN.run({ dryRun: true }); }
catch (e) {
  console.log('NOT CHECKED  could not rebuild the tables for comparison: ' + e.message);
  process.exit(2);
}

if (gen.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + gen.reason); process.exit(2); }

var problems = gen.problems.slice();
var lossLines = [];

if (gen.status !== 'FAIL') {
  if (!gen.tables) {
    console.log('NOT CHECKED  the generator produced 0 tables, so this run verified nothing.');
    process.exit(2);
  }

  var committed = null;
  try { committed = fs.readFileSync(OUT, 'utf8'); } catch (e) { committed = null; }
  if (committed === null) {
    console.log('NOT CHECKED  _data/ioc_tables.yml is absent or unreadable. ' +
      'Run `node generate-ioc-tables.js`.');
    process.exit(2);
  }

  var a = CDM.normalise(committed), b = CDM.normalise(gen.yaml);
  if (a !== b) {
    var d = CDM.firstDivergence(a, b);
    problems.push('_data/ioc_tables.yml is stale against ioc-feeds/: ' +
      (d ? 'first differs at line ' + d.line + ' (committed ' + d.committedLines +
           ' lines, regenerated ' + d.freshLines + ')' : 'differs in length only') +
      '. Run `node generate-ioc-tables.js` and stage the result.');
  }

  /* The dry run reports which stubs it WOULD write and which it WOULD remove.
     Either being non-empty means what is on disk does not match what is
     published. The removals are the safety-relevant half. */
  (gen.stubs || []).forEach(function (s) {
    problems.push('missing stub page for "' + s + '": a listing card would 404. ' +
      'Run `node generate-ioc-tables.js`.');
  });
  (gen.removed || []).forEach(function (s) {
    problems.push('DISCLOSURE: a stub page for "' + s + '" is still on disk but the feed ' +
      'is no longer published. Run `node generate-ioc-tables.js` to remove it.');
  });

  /* Design v4 check 5. Runs on the regenerated table, not the working copy. */
  var loss = noLoss(gen.yaml);
  lossLines = loss.lines;
  if (loss.notChecked) {
    console.log('NOT CHECKED  the no-loss comparison could not run: ' + loss.notChecked);
    process.exit(2);
  }
  problems = problems.concat(loss.problems);
}

if (problems.length) {
  console.log('FAIL  ' + OUT);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  lossLines.forEach(function (l) { console.log(l); });
  process.exit(1);
}

console.log('PASS  ' + OUT);
console.log('   note  ' + gen.tables + ' feed pages, ' + gen.rows + ' indicators');
if (gen.skipped) {
  console.log('   note  skipped ' + gen.skipped.embargoed + ' embargoed, ' +
    gen.skipped.unknown + ' unknown, ' + gen.skipped.empty + ' with nothing typed');
}
lossLines.forEach(function (l) { console.log(l); });
process.exit(0);
