#!/usr/bin/env node
'use strict';

/* Gate for bare ATT&CK technique IDs sitting in ioc-feeds/*.json.
 *
 * WHY THIS EXISTS
 * ----------------
 * check-detection-attack.js only ever reads _data/detection_manifests.yml, which is
 * built from hunting-detections/*.md rule metadata. It never walks ioc-feeds/, so a
 * revoked technique ID sitting in a feed's `technique`, `mitre_attack`,
 * `mitre_attack_techniques`, or similarly-named field was invisible to every ATT&CK
 * gate this project has. Measured 2026-09-08: 18 revoked IDs (T1562.001, T1562.002,
 * T1089, all retired by ATT&CK v19.2) sat as coverage claims across 8 feeds, next to
 * a companion commit that fixed the same IDs everywhere else that same day (STIX
 * bundles, detection pages) without ever touching the feeds it had open for an
 * unrelated reason. That is the oversight this gate closes.
 *
 * WHAT IT CHECKS, AND WHAT IT CANNOT
 * -----------------------------------
 * A technique ID sitting in a feed as a BARE STRING ("T1685", not "T1685 - Disable
 * or Modify Tools") is mechanically checkable: does this literal ID exist in the
 * current catalog. That is what this gate does, reusing lib/attack-catalog.js's
 * ID_RE and byId map rather than a second implementation of either.
 *
 * Roughly half the stale entries found in the 2026-09-08 audit were NOT this shape.
 * They were technique_name-style strings ("Impair Defenses: Disable or Modify
 * Tools") with no T-number anywhere in the JSON for a regex to test. This gate
 * cannot see those, and it says so on every run rather than implying full coverage.
 * Closing that half needs either a schema change (every technique_name entry also
 * carries a technique_id) or a fuzzy name-to-catalog match, which risks matching
 * the wrong technique and is exactly the "is this the right ID for this behaviour"
 * judgment call CLAUDE.md and this gate's own design treat as non-mechanizable.
 * See homelab-soc/docs/claim-to-gate-matrix.md for that gap recorded as PARTIAL.
 *
 * WHY WARN, NEVER FAIL
 * ---------------------
 * Remapping a revoked ID to its correct successor is an analyst decision, not an
 * automatic rewrite: v19.2 split T1562 four ways (see
 * feedback_attack_revocation_is_not_one_to_one), so "the ID is unknown" and "the ID
 * is now T1685" are different amounts of work. A hard FAIL here would either block
 * an unrelated commit to an old campaign's feed, or get silenced with
 * `--no-verify`, which loses the signal entirely. check-detection-attack.js already
 * set this precedent for exactly the same reason; this gate follows it.
 *
 * Exit codes: 0 PASS (ran and found nothing to warn about), 2 NOT CHECKED (catalog
 * or feed directory could not be read). This gate never exits 1. A WARN prints and
 * the commit proceeds, same as check-detection-attack.js's unresolved-ID warning.
 */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var FEED_DIR = path.join(ROOT, 'ioc-feeds');

var CATALOG = null;
var DEPS_REASON = null;
try {
  CATALOG = require(path.join(__dirname, 'lib', 'attack-catalog.js'));
} catch (e) {
  DEPS_REASON = 'gate dependency did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim();
}

var catalog = null;
if (!DEPS_REASON) {
  try {
    catalog = CATALOG.load();
  } catch (e) {
    DEPS_REASON = String((e && e.message) || e);
  }
}

function notChecked(reason) {
  console.log('NOT CHECKED  ' + FEED_DIR);
  console.log('   reason  ' + reason);
  process.exit(2);
}

/* Walks a parsed feed and returns every string that is EXACTLY a technique-ID shape
   (CATALOG.ID_RE anchors both ends), with the dotted path it sits at. A composite
   string like "T1685 - Disable or Modify Tools" does not match: that is the half
   this gate cannot reach, named above and in the summary line. */
function bareIds(node, at, out) {
  if (node == null) return;
  if (typeof node === 'string') {
    var s = node.trim();
    if (CATALOG.ID_RE.test(s)) out.push({ at: at, id: s });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach(function (x, i) { bareIds(x, at + '[' + i + ']', out); });
    return;
  }
  if (typeof node !== 'object') return;
  Object.keys(node).forEach(function (k) {
    bareIds(node[k], at ? at + '.' + k : k, out);
  });
}

function main() {
  if (DEPS_REASON) notChecked(DEPS_REASON);

  var files;
  try {
    files = fs.readdirSync(FEED_DIR).filter(function (f) { return /\.json$/i.test(f); }).sort();
  } catch (e) {
    notChecked('cannot read ' + FEED_DIR + ': ' + e.message);
    return;
  }
  if (!files.length) {
    notChecked('no feeds found under ' + FEED_DIR + ', so this run checked nothing');
    return;
  }

  var scanned = 0, unreadable = [], valuesChecked = 0, warnings = [];

  files.forEach(function (f) {
    var raw, doc;
    try { raw = fs.readFileSync(path.join(FEED_DIR, f), 'utf8'); doc = JSON.parse(raw); }
    catch (e) { unreadable.push(f + ': ' + e.message); return; }
    scanned++;

    var found = [];
    bareIds(doc, '', found);
    valuesChecked += found.length;

    found.forEach(function (hit) {
      if (!catalog.byId[hit.id]) {
        warnings.push({ file: f, at: hit.at, id: hit.id });
      }
    });
  });

  // A file this gate could not parse verified less of the corpus than it looks
  // like it did, so it says so rather than reporting a clean sweep of what it
  // managed. Same principle as check-ioc-feeds.js's own unreadable-file handling.
  if (unreadable.length) {
    console.log('NOT CHECKED  ' + unreadable.length + ' feed(s) could not be parsed, so ' +
      'this run did not cover the whole corpus:');
    unreadable.forEach(function (u) { console.log('   ' + u); });
    process.exit(2);
    return;
  }

  console.log('PASS  ' + scanned + ' feed(s), ' + valuesChecked +
    ' bare technique-ID-shaped value(s) checked against ATT&CK ' + catalog.version +
    ' (' + catalog.count + ' techniques)');
  console.log('   note  this gate reads only BARE ID strings ("T1685"), never a name-shaped ' +
    'string ("Impair Defenses: Disable or Modify Tools") with no ID attached. Roughly half ' +
    'of the stale entries found in the 2026-09-08 audit were the second shape and are not ' +
    'covered here; see the PARTIAL row in claim-to-gate-matrix.md.');

  if (warnings.length) {
    console.log('   WARN  ' + warnings.length + ' bare technique ID(s) unknown to ATT&CK ' +
      catalog.version + ', likely revoked and left unmapped in the feed(s) below. This is a ' +
      'WARNING, not a FAIL: remapping a revoked ID is an analyst decision, and the T1562 tree ' +
      'alone split four ways in v19.2, so no automatic rewrite is attempted here.');
    warnings.forEach(function (w) {
      console.log('           ' + w.id + '  ' + w.file + '  at ' + w.at);
    });
  }

  // Never exits 1: see file header. A WARN is printed above and the commit proceeds.
  process.exit(0);
}

if (require.main === module) main();
module.exports = { bareIds: bareIds };
