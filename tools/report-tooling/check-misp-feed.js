#!/usr/bin/env node
'use strict';

/* Gates the MISP feed under feeds/misp/ by regenerate-and-diff against the
   catalog, the reports, the STIX bundles and the detection pages. Stale means a
   subscriber's next pull would carry less, or older, than the site publishes.
   Beyond staleness it checks the two things only a feed can get wrong: an event
   whose content changed without its timestamp moving (the state file is the
   record; a hash that no longer matches it means the generator was not run),
   and a withdrawn event that the changelog does not itemise.

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var M, GEN;
try {
  M = require('./lib/misp-feed.js');
  GEN = require('./generate-misp-feed.js');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var gen;
try { gen = GEN.run({ dryRun: true }); }
catch (e) {
  console.log('NOT CHECKED  could not rebuild the feed for comparison: ' + e.message);
  process.exit(2);
}
if (gen.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + gen.reason); process.exit(2); }

var problems = gen.problems.slice();

if (gen.status !== 'FAIL') {
  if (!gen.events) {
    console.log('NOT CHECKED  the generator produced 0 events, so this run verified nothing.');
    process.exit(2);
  }
  var state = null;
  try { state = JSON.parse(fs.readFileSync(M.STATE_FILE, 'utf8')); } catch (e) { state = null; }
  if (!state) {
    console.log('NOT CHECKED  feeds/misp/_state.json is absent or unreadable. Run `node generate-misp-feed.js`.');
    process.exit(2);
  }
  if (gen.added.length || gen.changed.length) {
    problems.push('event content changed since the state was written, so a subscriber would see the old timestamp: ' +
      gen.added.concat(gen.changed).join(', ') + '. Run `node generate-misp-feed.js` and stage feeds/misp/.');
  }
  Object.keys(gen.files).forEach(function (f) {
    var cur = null;
    try { cur = fs.readFileSync(path.join(M.FEED_DIR, f), 'utf8'); } catch (e) { cur = null; }
    if (cur === null) problems.push('feeds/misp/' + f + ' is missing. Run `node generate-misp-feed.js`.');
    else if (cur !== gen.files[f]) problems.push('feeds/misp/' + f + ' is stale. Run `node generate-misp-feed.js`.');
  });
  gen.orphans.forEach(function (u) {
    problems.push('feeds/misp/' + u + '.json is on disk but nothing generates it and the state does not record it as withdrawn.');
  });
  gen.removed.forEach(function (s) {
    problems.push('withdrawn event still on disk: ' + s + '. Run `node generate-misp-feed.js` to remove it.');
  });
  var changelog = '';
  try { changelog = fs.readFileSync(M.CHANGELOG_FILE, 'utf8'); } catch (e) { changelog = ''; }
  gen.withdrawn.forEach(function (w) {
    if (!M.changelogCovers(changelog, w.slug)) {
      problems.push('event ' + w.uuid + ' (' + w.slug + ') was withdrawn on ' + w.withdrawn +
        ' but feeds/misp/changelog.md does not name it. A subscriber who matched on it must be able to find out why.');
    }
  });
  // The state on disk must be the state the feed was written from.
  var stateCanon = null;
  try { stateCanon = JSON.stringify(JSON.parse(fs.readFileSync(M.STATE_FILE, 'utf8'))); } catch (e) { stateCanon = null; }
  if (stateCanon !== null && !gen.added.length && !gen.changed.length && stateCanon !== JSON.stringify(gen.state)) {
    problems.push('feeds/misp/_state.json differs from what the feed on disk implies (a withdrawal or a hand edit). Run `node generate-misp-feed.js`.');
  }
}

if (problems.length) {
  console.log('FAIL  ' + M.MANIFEST_FILE);
  problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(1);
}
console.log('PASS  ' + M.MANIFEST_FILE);
console.log('   note  ' + gen.events + ' events, ' + gen.attributes + ' attributes' +
  (gen.withdrawn.length ? ', ' + gen.withdrawn.length + ' withdrawn and itemised' : ''));
if (gen.skippedUnpublished.length) console.log('   note  not published, no event: ' + gen.skippedUnpublished.join(', '));
if (gen.notes.length) console.log('   note  ' + gen.notes.length + ' generator note(s); run `node generate-misp-feed.js --dry-run` to list them');
process.exit(0);
