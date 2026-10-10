#!/usr/bin/env node
'use strict';

/* Writes the MISP feed under feeds/misp/: manifest.json, <event uuid>.json per
   published campaign, hashes.csv, and the generator's own _state.json (content
   hash and last-changed timestamp per event, never published). Removes an
   event file whose campaign is no longer published and records it as withdrawn
   in the state; the gate then requires a changelog entry naming it.

   Inputs, all already gated elsewhere: _data/catalog.yml (which campaigns are
   published and what they link), the reports' front matter (unlisted), the
   STIX bundles (indicators, actors, CVEs, ATT&CK), the detection pages (rules)
   the ATT&CK catalog TSV (technique names) and the pinned MISP galaxy TSV
   (data/misp-galaxy-attack-pattern.tsv, the exact tag values MISP resolves).

   Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');

var M, A, P, CAT, yaml;
try {
  M = require('./lib/misp-feed.js');
  A = require('./lib/actors.js');
  P = require('./lib/parse-detections.js');
  CAT = require('./lib/attack-catalog.js');
  yaml = require('js-yaml');
} catch (e) {
  console.log('NOT CHECKED  ' + e.message + '. Run `npm ci` in tools/report-tooling.');
  process.exit(2);
}

var KEEP = { 'index.md': 1, 'changelog.md': 1, '_state.json': 1, 'manifest.json': 1, 'hashes.csv': 1 };

function readState() {
  try { return JSON.parse(fs.readFileSync(M.STATE_FILE, 'utf8')); } catch (e) { return null; }
}

function existingEventFiles() {
  var out = {};
  var entries;
  try { entries = fs.readdirSync(M.FEED_DIR); } catch (e) { return out; }
  entries.forEach(function (f) {
    if (/^[0-9a-f-]{36}\.json$/.test(f)) out[f.replace(/\.json$/, '')] = path.join(M.FEED_DIR, f);
  });
  return out;
}

function run(opts) {
  opts = opts || {};
  var now = opts.now || Math.floor(Date.now() / 1000);
  var empty = { events: 0, attributes: 0, files: {}, changed: [], added: [], newlyWithdrawn: [], withdrawn: [],
    removed: [], orphans: [], notes: [], problems: [], state: null, skippedUnpublished: [] };
  var catText, reports, catalog, attackNames = {}, galaxyNames = {};
  try {
    catText = fs.readFileSync(A.CATALOG_FILE, 'utf8');
    reports = A.readReports(A.REPORT_DIR);
    var doc = yaml.load(catText) || {};
    catalog = doc.entries || [];
    var cat = CAT.load();
    Object.keys(cat.byId).forEach(function (id) { attackNames[id] = cat.byId[id].name; });
    galaxyNames = M.readGalaxyNames(fs.readFileSync(M.GALAXY_FILE, 'utf8'));
    if (!Object.keys(galaxyNames).length) throw new Error(M.GALAXY_FILE + ' holds no technique');
  } catch (e) {
    return Object.assign({ status: 'NOT CHECKED', reason: 'could not read the corpus: ' + e.message }, empty);
  }
  if (!catalog.length) return Object.assign({ status: 'NOT CHECKED', reason: 'the catalog has no entries' }, empty);
  var catalogByUrl = A.parseCatalog(catText);
  var reportByUrl = {};
  reports.forEach(function (r) { reportByUrl[r.url] = r; });

  var events = [], notes = [], problems = [], skipped = [];
  catalog.forEach(function (e) {
    var slug = M.slugOf(e);
    if (!slug) { problems.push('a catalog entry ("' + e.title + '") has no report, detection or feed url to name it by'); return; }
    if (e.report_url) {
      var r = reportByUrl[e.report_url];
      if (!r) { problems.push(slug + ': the catalog lists ' + e.report_url + ' but no such report exists'); return; }
      var pub = A.publication(r, catalogByUrl);
      if (pub !== 'published') { skipped.push(slug + ' (' + pub + ')'); return; }
    }
    var bundle = null, rules = null;
    if (e.stix_url) {
      var sp = path.join(A.ROOT, String(e.stix_url).replace(/^\//, ''));
      try { bundle = JSON.parse(fs.readFileSync(sp, 'utf8')); }
      catch (err) { problems.push(slug + ': STIX bundle ' + e.stix_url + ' could not be read: ' + err.message); return; }
    }
    if (e.detection_url) {
      var dp = path.join(A.DETECTION_DIR, String(e.detection_url).split('/').pop() + '.md');
      var md;
      try { md = fs.readFileSync(dp, 'utf8'); }
      catch (err) { problems.push(slug + ': detection page ' + e.detection_url + ' could not be read: ' + err.message); return; }
      var parsed = P.parse(md, slug);
      if (parsed.unresolved.length) {
        problems.push(slug + ': ' + parsed.unresolved.length + ' rule(s) with an unrecognised tier; the detection manifest gate owns this');
        return;
      }
      rules = parsed.rules;
    }
    var ev = M.buildEvent({ entry: e, slug: slug, bundle: bundle, rules: rules, attackNames: attackNames, galaxyNames: galaxyNames });
    if (!ev.attributes.some(function (a) { return a.type !== 'link'; })) {
      notes.push(slug + ': no indicator or rule to carry, so no event');
      return;
    }
    if (ev.notes.galaxyMissing.length) {
      problems.push(slug + ': ATT&CK ' + ev.notes.galaxyMissing.join(', ') + ' not in the pinned MISP galaxy, so MISP would not link the tag. ' +
        'Rerun generate-misp-galaxy-names.py, or correct the technique id.');
    }
    ev.attributes.forEach(function (a) {
      if (M.hasAstral(a.value)) {
        problems.push(slug + ': a ' + a.type + ' value carries a character outside the BMP (an emoji?), which a utf8 MISP rejects ' +
          'along with every later attribute in the event. Fix it at the source.');
      }
    });
    ev.notes.unmapped.forEach(function (u) { notes.push(slug + ': kept whole as stix2-pattern or untagged: ' + u); });
    ev.notes.skipped.forEach(function (s) { notes.push(slug + ': rule without a fence of its own, not shipped: ' + s); });
    events.push(ev);
  });
  if (problems.length) return Object.assign({ status: 'FAIL', reason: null }, empty, { problems: problems, notes: notes });
  if (!events.length) return Object.assign({ status: 'NOT CHECKED', reason: 'no published campaign carries an indicator or a rule' }, empty);

  var st = M.stamp(events, readState(), now, { restampAll: !!opts.restampAll });
  if (st.duplicateTimestamps.length) {
    return Object.assign({ status: 'FAIL', reason: null }, empty, { notes: notes, problems: [
      'events share a timestamp, so OpenCTI\'s MISP-feed connector would import only the first of each group: ' +
      st.duplicateTimestamps.join(', ') + '. Run `node generate-misp-feed.js --restamp-all` once.'] });
  }
  var files = {};
  files['manifest.json'] = JSON.stringify(M.manifest(st.events), null, 2) + '\n';
  files['hashes.csv'] = M.hashesCsv(st.events);
  st.events.forEach(function (ev) { files[ev.uuid + '.json'] = JSON.stringify(M.eventJson(ev), null, 2) + '\n'; });
  var stateText = JSON.stringify(st.state, null, 2) + '\n';

  var have = existingEventFiles();
  var removed = [], orphans = [];
  Object.keys(have).forEach(function (u) {
    if (files[u + '.json']) return;
    if (st.state.withdrawn[u]) removed.push(st.state.withdrawn[u].slug + ' (' + u + ')');
    else orphans.push(u);
  });

  if (!opts.dryRun) {
    fs.mkdirSync(M.FEED_DIR, { recursive: true });
    Object.keys(files).forEach(function (f) { fs.writeFileSync(path.join(M.FEED_DIR, f), files[f], 'utf8'); });
    fs.writeFileSync(M.STATE_FILE, stateText, 'utf8');
    Object.keys(have).forEach(function (u) { if (!files[u + '.json']) fs.rmSync(have[u], { force: true }); });
  }
  var attributes = st.events.reduce(function (n, ev) { return n + ev.attributes.length; }, 0);
  return {
    status: 'PASS', reason: null, problems: [], notes: notes,
    events: st.events.length, attributes: attributes, files: files, stateText: stateText, state: st.state,
    changed: st.changed, added: st.added, newlyWithdrawn: st.newlyWithdrawn, withdrawn: st.withdrawn,
    removed: removed, orphans: orphans, skippedUnpublished: skipped, restamped: st.restamped
  };
}

module.exports = { run: run, KEEP: KEEP, existingEventFiles: existingEventFiles };

if (require.main === module) {
  var dry = process.argv.indexOf('--dry-run') !== -1;
  var r = run({ dryRun: dry, restampAll: process.argv.indexOf('--restamp-all') !== -1 });
  if (r.status === 'NOT CHECKED') { console.log('NOT CHECKED  ' + r.reason); process.exit(2); }
  console.log(r.status + '   ' + r.events + ' events, ' + r.attributes + ' attributes' + (dry ? '   (dry run, nothing written)' : ''));
  if (r.restamped) console.log('   restamped (unique timestamps, content unchanged): ' + r.restamped + ' events');
  if (r.added.length) console.log('   added (new timestamp): ' + r.added.join(', '));
  if (r.changed.length) console.log('   changed (timestamp bumped): ' + r.changed.join(', '));
  if (r.newlyWithdrawn.length) console.log('   WITHDRAWN this run, itemise in feeds/misp/changelog.md: ' + r.newlyWithdrawn.join(', '));
  if (r.removed.length) console.log('   event files removed: ' + r.removed.join(', '));
  if (r.orphans.length) console.log('   FAIL  event file(s) in feeds/misp/ that no state entry explains: ' + r.orphans.join(', '));
  if (r.skippedUnpublished.length) console.log('   note  not published, no event: ' + r.skippedUnpublished.join(', '));
  r.notes.forEach(function (n) { console.log('   note  ' + n); });
  r.problems.forEach(function (p) { console.log('   FAIL  ' + p); });
  process.exit(r.status === 'PASS' && !r.orphans.length ? 0 : 1);
}
