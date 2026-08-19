#!/usr/bin/env node
'use strict';

/* Writes _data/ioc_tables.yml and one stub page per PUBLISHED feed.

   Run after any change under ioc-feeds/ or to _data/catalog.yml, exactly as the
   detection manifest is regenerated after a change under hunting-detections/.
   The pre-commit machinery gate calls the checker beside this file.

   Stubs for feeds that are no longer published, or no longer exist, are REMOVED.
   Leaving one behind would serve a page for a campaign that has gone back under
   embargo, which is the one failure direction that matters here.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');
var REPORT_DIR = path.join(ROOT, 'reports');
var CATALOG = path.join(ROOT, '_data', 'catalog.yml');
var OUT = path.join(ROOT, '_data', 'ioc_tables.yml');

var T, G, CS;
try {
  T = require('./lib/ioc-tables.js');
  G = require('./generate-ioc-index.js');
  CS = require('./lib/catalog-status.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

/* A stub is recognised by its generated marker, so a hand-authored page that
   happens to sit under ioc-feeds/ is never deleted by this script. */
var MARKER = 'layout: ioc-table';

function existingStubs() {
  var out = {};
  var entries;
  try { entries = fs.readdirSync(FEED_DIR, { withFileTypes: true }); }
  catch (e) { return out; }
  entries.forEach(function (e) {
    if (!e.isDirectory()) return;
    var p = path.join(FEED_DIR, e.name, 'index.md');
    try {
      if (fs.readFileSync(p, 'utf8').indexOf(MARKER) > -1) out[e.name] = p;
    } catch (err) { /* not a stub */ }
  });
  return out;
}

function run(opts) {
  opts = opts || {};
  var feeds, catText, unlisted, resolved;
  try {
    feeds = G.readFeeds(FEED_DIR);
    catText = fs.readFileSync(CATALOG, 'utf8');
    unlisted = G.readUnlisted(REPORT_DIR);
    resolved = CS.resolve(catText, unlisted);
  } catch (e) {
    return { status: 'NOT CHECKED', reason: 'could not read the corpus: ' + e.message,
             problems: [], tables: 0, rows: 0, yaml: null, stubs: [], removed: [] };
  }

  if (!Object.keys(feeds).length) {
    return { status: 'NOT CHECKED', reason: 'no feeds found under ' + FEED_DIR +
             ', so this run built nothing', problems: [], tables: 0, rows: 0,
             yaml: null, stubs: [], removed: [] };
  }

  /* A disagreement between the catalog and the front matter is a failure, never
     something to resolve. Guessing either way leaks an embargoed campaign or
     withholds a published one. */
  if ((resolved.conflicts || []).length) {
    return { status: 'FAIL', reason: null, tables: 0, rows: 0, yaml: null,
             stubs: [], removed: [],
             problems: resolved.conflicts.map(function (c) {
               return 'publication signals disagree for ' + (c.feed || c.slug || '(unnamed)') +
                 ': the catalog says ' + (c.catalog || '?') +
                 ' and the report front matter says ' + (c.front_matter || '?') +
                 '. Resolve it in the source, not here: guessing either way ' +
                 'either leaks an embargoed campaign or withholds a published one.';
             }) };
  }

  var built = T.build(feeds, resolved.status, resolved.meta);
  if (built.problems.length) {
    return { status: 'FAIL', reason: null, problems: built.problems,
             tables: 0, rows: 0, yaml: null, stubs: [], removed: [] };
  }

  var slugs = Object.keys(built.tables);
  var rows = slugs.reduce(function (n, s) { return n + built.tables[s].rows.length; }, 0);
  var text = T.toYaml(built.tables);

  var have = existingStubs();
  var wanted = {}, wrote = [], removed = [];
  slugs.forEach(function (k) { wanted[built.tables[k].slug] = true; });

  if (!opts.dryRun) {
    fs.writeFileSync(OUT, text, 'utf8');
    slugs.forEach(function (k) {
      // The DIRECTORY is the clean url slug, never the manifest key: a directory
      // named AdvancedRouterScanner.json would sit at the same path as the feed
      // file of that name and the build would collide.
      var dir = path.join(FEED_DIR, built.tables[k].slug);
      var p = path.join(dir, 'index.md');
      var body = T.stub(k, built.tables[k]);
      var cur = null;
      try { cur = fs.readFileSync(p, 'utf8'); } catch (e) { cur = null; }
      if (cur === body) return;                       // unchanged, keep the mtime
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(p, body, 'utf8');
      wrote.push(built.tables[k].slug);
    });
    Object.keys(have).forEach(function (s) {
      if (wanted[s]) return;
      fs.rmSync(path.dirname(have[s]), { recursive: true, force: true });
      removed.push(s);
    });
  } else {
    slugs.forEach(function (k) {
      if (!have[built.tables[k].slug]) wrote.push(built.tables[k].slug);
    });
    Object.keys(have).forEach(function (s) { if (!wanted[s]) removed.push(s); });
  }

  return {
    status: 'PASS', reason: null, problems: [],
    tables: slugs.length, rows: rows, yaml: text,
    stubs: wrote, removed: removed, skipped: built.skipped
  };
}

module.exports = { run: run, existingStubs: existingStubs, OUT: OUT, MARKER: MARKER };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  console.log(r.status + '   ' + r.tables + ' feed pages, ' + r.rows + ' indicators' +
    (dry ? '   (dry run, nothing written)' : ''));
  if (r.skipped) {
    console.log('   skipped: ' + r.skipped.embargoed + ' embargoed, ' +
      r.skipped.unknown + ' unknown, ' + r.skipped.empty + ' with nothing typed');
  }
  if (r.stubs && r.stubs.length) console.log('   stubs written: ' + r.stubs.length);
  if (r.removed && r.removed.length) {
    console.log('   stubs REMOVED (no longer published): ' + r.removed.join(', '));
  }
  r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(r.status === 'PASS' ? 0 : 1);
}
