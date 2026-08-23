#!/usr/bin/env node
'use strict';

/* Gate for _data/detection_attack.yml, the per-detection-page ATT&CK mapping
 * tables that the coverage strip attaches itself to.
 *
 * It checks four things, and reports PASS, FAIL or NOT CHECKED per the
 * gate-honesty contract. NOT CHECKED is never folded into PASS, and never into
 * FAIL either: a gate that could not run must not accuse the author's content.
 *
 *   1. REGENERATE AND DIFF. The committed file is rebuilt in memory from
 *      _data/detection_manifests.yml and compared. A gate that re-derives an
 *      artifact and checks the derivation against ITSELF is not a gate; that
 *      exact hole let the detection manifest drift for a whole build.
 *
 *   2. THE CATALOG'S TACTICS EXIST IN THE STRIP. Every primary tactic in
 *      data/attack-techniques.tsv must appear in TACTIC_ORDER. A tactic the
 *      strip has no bar for silently loses its techniques, which understates
 *      coverage on a page that looks complete. ATT&CK adds tactics (v19 added
 *      Defense Impairment), so this cannot be assumed once and forgotten.
 *
 *   3. EVERY PAGE WITH RULES HAS A TABLE. A detection page whose rules carry
 *      ATT&CK IDs but which produced no rows means the strip will not render
 *      there, which is the condition this whole feature exists to remove.
 *
 *   4. UNRESOLVED IDS ARE NAMED. A technique ID that ATT&CK no longer knows is
 *      reported with the pages that carry it. This is a WARNING, not a FAIL:
 *      the rule content is a human call (a revoked ID needs a real remapping
 *      decision, not an automatic rewrite), but it is never silent, because a
 *      dropped technique makes a page understate its own coverage.
 *
 * Exit codes: 0 PASS, 1 FAIL, 2 NOT CHECKED.
 */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var OUT = path.join(ROOT, '_data', 'detection_attack.yml');

var GEN = null;
var AC = null;
var CATALOG = null;
var DEPS_REASON = null;
try {
  require('js-yaml');
  GEN = require('./generate-detection-attack.js');
  AC = require(path.join(ROOT, 'assets', 'js', 'attack-coverage.js'));
  CATALOG = require(path.join(__dirname, 'lib', 'attack-catalog.js'));
} catch (e) {
  var msg = String((e && e.message) || e).split('\n')[0].trim();
  DEPS_REASON = (e && e.code === 'MODULE_NOT_FOUND') || /cannot find module/i.test(msg)
    ? 'gate dependency did not load: ' + msg + '. Run `npm ci` in tools/report-tooling.'
    : 'gate dependency did not load: ' + msg;
}

function norm(s) { return String(s).replace(/\r\n/g, '\n').trimEnd(); }

function notChecked(reason) {
  console.log('NOT CHECKED  ' + OUT);
  console.log('   reason  ' + reason);
  process.exit(2);
}

function main() {
  if (DEPS_REASON) notChecked(DEPS_REASON);

  if (!fs.existsSync(OUT)) {
    console.log('FAIL  ' + OUT + ' does not exist');
    console.log('   fix  node tools/report-tooling/generate-detection-attack.js');
    process.exit(1);
  }

  var built, text, catalog;
  try {
    built = GEN.build();
    text = GEN.render(built);
    catalog = built.catalog;
  } catch (e) {
    // A malformed or absent catalog is the gate's own problem, not the
    // author's content being wrong, so it is NOT CHECKED rather than FAIL.
    notChecked(String((e && e.message) || e));
  }

  var problems = [];

  // 2. catalog tactics vs the strip's bars
  var orphanTactics = CATALOG.tacticsNotIn(catalog, AC.TACTIC_ORDER);
  if (orphanTactics.length) {
    problems.push('the catalog uses tactic(s) the strip has no bar for: ' +
      orphanTactics.join(', ') +
      '. Add them to TACTIC_ORDER in assets/js/attack-coverage.js and to ' +
      'TACTIC_DISPLAY in generate-attack-catalog.py.');
  }

  // 1. regenerate and diff
  var committed = fs.readFileSync(OUT, 'utf8');
  if (norm(committed) !== norm(text)) {
    problems.push(OUT + ' is stale against _data/detection_manifests.yml. ' +
      'Run node tools/report-tooling/generate-detection-attack.js and commit it.');
  }

  // 3. every page carrying ATT&CK-tagged rules produced a table
  var empty = Object.keys(built.pages).filter(function (k) {
    return built.pages[k].rows.length === 0;
  });
  if (empty.length) {
    problems.push(empty.length + ' detection page(s) produced no technique row, ' +
      'so no strip renders there: ' + empty.join(', '));
  }

  /* 5. THE LOOKUP KEY IS DERIVED TWICE, SO THE TWO RULES ARE CHECKED AGAINST
        EACH OTHER. _layouts/post.html builds the data key in Liquid with
            page.path | split: "/" | last | remove: ".md"
        and this generator builds it from the manifest's own keys. Nothing makes
        those agree by construction, and when they disagree the page simply
        renders no table: no error, no strip, and every gate still green. That
        is precisely how the card slug broke. Mirror the Liquid here and assert
        every detection page resolves. */
  var detDir = path.join(ROOT, 'hunting-detections');
  var missingKey = fs.readdirSync(detDir)
    .filter(function (f) { return /\.md$/.test(f) && f !== 'index.md'; })
    .map(function (f) { return f.split('/').pop().replace(/\.md$/, ''); })
    .filter(function (key) { return !built.pages[key]; });
  if (missingKey.length) {
    problems.push(missingKey.length + ' detection page(s) derive a data key with ' +
      'no entry in ' + path.basename(OUT) + ', so the layout renders no table ' +
      'and no strip for them: ' + missingKey.join(', ') +
      '. Either the generator skipped them or the Liquid key rule in ' +
      '_layouts/post.html no longer matches this one.');
  }

  var pageCount = Object.keys(built.pages).length;
  var rowCount = Object.keys(built.pages).reduce(function (n, k) {
    return n + built.pages[k].rows.length;
  }, 0);

  if (problems.length) {
    console.log('FAIL  ' + OUT);
    problems.forEach(function (p) { console.log('   ' + p); });
    process.exit(1);
  }

  console.log('PASS  ' + OUT);
  console.log('   note  ' + pageCount + ' detection page(s), ' + rowCount +
    ' technique row(s), ATT&CK ' + catalog.version +
    ', ' + AC.TACTIC_ORDER.length + ' tactics');

  // 4. unresolved IDs: always named, never silent, never a pass-by-omission
  var un = Object.keys(built.unresolvedAll).sort(CATALOG.compareId);
  if (un.length) {
    console.log('   WARN  ' + un.length + ' technique ID(s) unknown to ATT&CK ' +
      catalog.version + ', excluded from the tables so those pages understate ' +
      'their coverage:');
    un.forEach(function (id) {
      console.log('           ' + id + '  ' + built.unresolvedAll[id].join(', '));
    });
  }
  process.exit(0);
}

if (require.main === module) main();
