#!/usr/bin/env node
'use strict';

/* Builds _data/detection_attack.yml: one ATT&CK mapping table per detection
   page, rendered by _layouts/post.html.
 *
 * WHY THIS EXISTS
 * ---------------
 * The ATT&CK coverage strip attaches itself to a mapping table. It rendered on
 * 29 of 41 reports and 1 of 57 detection pages, because a detection page states
 * its techniques as per-rule "ATT&CK Coverage:" lines and a per-engine summary
 * whose cells hold comma-separated ID lists. attack-coverage.js deliberately
 * rejects that shape: it has no tactic, so it cannot populate a tactic-organised
 * strip, and a strip that is entirely Unmapped is noise rather than honesty.
 *
 * Six reports made this worse than cosmetic. They tell the reader the full
 * technique table "is maintained alongside the detection rules", and it was on
 * neither page. This generator makes that sentence true.
 *
 * WHY IT READS THE MANIFEST AND NOT THE MARKDOWN
 * ----------------------------------------------
 * _data/detection_manifests.yml already carries every rule's engine, tier and
 * ATT&CK IDs, and check-detection-manifest.js already gates it against the
 * markdown by regenerate-and-diff. Parsing the markdown again here would be a
 * second definition of "what rules exist", which is this codebase's signature
 * failure. Delegating to the manifest makes it structurally impossible for the
 * ATT&CK table and the detection picker to disagree about the rule set.
 *
 * UNRESOLVED TECHNIQUES ARE NAMED, NEVER DROPPED
 * ----------------------------------------------
 * A technique the ATT&CK catalog does not know (a revoked ID, most often) is
 * recorded in `unresolved` and printed by the gate. Silently omitting it would
 * make the page understate its own coverage while looking complete.
 *
 *   node generate-detection-attack.js            write the file
 *   node generate-detection-attack.js --check    print what would change
 *
 * Exit codes: 0 wrote/clean, 1 a real problem, 2 could not run.
 */

var fs = require('node:fs');
var path = require('node:path');

var ROOT = path.join(__dirname, '..', '..');
var OUT = path.join(ROOT, '_data', 'detection_attack.yml');

var yaml = null;
var AC = null;
var CATALOG = null;
var DEPS_REASON = null;
try {
  yaml = require('js-yaml');
  AC = require(path.join(ROOT, 'assets', 'js', 'attack-coverage.js'));
  CATALOG = require(path.join(__dirname, 'lib', 'attack-catalog.js'));
} catch (e) {
  DEPS_REASON = 'gate dependency did not load: ' +
    String((e && e.message) || e).split('\n')[0].trim() +
    '. Run `npm ci` in tools/report-tooling.';
}

function esc(s) {
  return String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/* Rule labels go into a table cell, so a pipe would split the cell and a
   newline would end the row. Both occur in real rule names. */
function cellSafe(s) {
  return String(s == null ? '' : s).replace(/\s+/g, ' ').replace(/\|/g, '/').trim();
}

function build() {
  var manifestPath = path.join(ROOT, '_data', 'detection_manifests.yml');
  var manifest = yaml.load(fs.readFileSync(manifestPath, 'utf8')) || {};
  var catalog = CATALOG.load();
  var order = AC.TACTIC_ORDER;
  var rank = {};
  order.forEach(function (t, i) { rank[t] = i; });

  var pages = {};
  var unresolvedAll = {};

  Object.keys(manifest).sort().forEach(function (key) {
    var rules = manifest[key];
    if (!Array.isArray(rules) || !rules.length) return;

    var byTech = {};
    var unresolved = {};

    rules.forEach(function (rule) {
      var ids = rule && rule.attack;
      if (!Array.isArray(ids)) return;
      ids.forEach(function (raw) {
        var id = String(raw).trim();
        if (!id) return;
        var entry = catalog.byId[id];
        if (!entry) {
          unresolved[id] = true;
          unresolvedAll[id] = unresolvedAll[id] || [];
          if (unresolvedAll[id].indexOf(key) === -1) unresolvedAll[id].push(key);
          return;
        }
        var slot = byTech[id] || (byTech[id] = { entry: entry, rules: [] });
        var label = cellSafe(rule.name) +
          ' (' + String(rule.engine || '?').toUpperCase() +
          (rule.tier ? ', ' + rule.tier : '') + ')';
        if (slot.rules.indexOf(label) === -1) slot.rules.push(label);
      });
    });

    var ids = Object.keys(byTech);
    if (!ids.length && !Object.keys(unresolved).length) return;

    ids.sort(function (a, b) {
      var ta = rank[byTech[a].entry.tactic], tb = rank[byTech[b].entry.tactic];
      if (ta !== tb) return ta - tb;
      return CATALOG.compareId(a, b);
    });

    var tactics = {};
    ids.forEach(function (id) { tactics[byTech[id].entry.tactic] = true; });

    pages[key] = {
      total: ids.length,
      tactics: Object.keys(tactics).length,
      unresolved: Object.keys(unresolved).sort(CATALOG.compareId),
      rows: ids.map(function (id) {
        return {
          tactic: byTech[id].entry.tactic,
          id: id,
          name: byTech[id].entry.name,
          rules: byTech[id].rules.join('; '),
          count: byTech[id].rules.length
        };
      })
    };
  });

  return { pages: pages, unresolvedAll: unresolvedAll, catalog: catalog };
}

function render(built) {
  var out = [];
  out.push('# Generated by tools/report-tooling/generate-detection-attack.js');
  out.push('# Do not edit by hand. Regenerate after any change to hunting-detections/');
  out.push('# or to _data/detection_manifests.yml, then commit both.');
  out.push('# ATT&CK ' + built.catalog.version + ', primary tactic per technique.');
  out.push('');
  Object.keys(built.pages).sort().forEach(function (key) {
    var p = built.pages[key];
    out.push('"' + esc(key) + '":');
    out.push('  total: ' + p.total);
    out.push('  tactics: ' + p.tactics);
    out.push('  unresolved: [' + p.unresolved.map(function (u) {
      return '"' + esc(u) + '"';
    }).join(', ') + ']');
    out.push('  rows:');
    p.rows.forEach(function (r) {
      out.push('    - tactic: "' + esc(r.tactic) + '"');
      out.push('      id: "' + esc(r.id) + '"');
      out.push('      name: "' + esc(r.name) + '"');
      out.push('      rules: "' + esc(r.rules) + '"');
      out.push('      count: ' + r.count);
    });
  });
  return out.join('\n') + '\n';
}

function main() {
  if (DEPS_REASON) {
    console.log('NOT CHECKED  ' + OUT);
    console.log('   reason  ' + DEPS_REASON);
    process.exit(2);
  }
  var built, text;
  try {
    built = build();
    text = render(built);
  } catch (e) {
    console.log('FAIL  could not build the ATT&CK tables: ' +
      String((e && e.message) || e));
    process.exit(1);
  }

  var check = process.argv.indexOf('--check') !== -1;
  var existing = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : null;
  var same = existing !== null &&
    existing.replace(/\r\n/g, '\n').trimEnd() === text.replace(/\r\n/g, '\n').trimEnd();

  var pageCount = Object.keys(built.pages).length;
  var rowCount = Object.keys(built.pages).reduce(function (n, k) {
    return n + built.pages[k].rows.length;
  }, 0);

  if (check) {
    console.log(same ? 'PASS  ' + OUT + ' is current'
                     : 'FAIL  ' + OUT + ' is stale, run generate-detection-attack.js');
  } else {
    fs.writeFileSync(OUT, text, 'utf8');
    console.log('PASS  wrote ' + OUT);
  }
  console.log('   note  ' + pageCount + ' detection page(s), ' + rowCount +
    ' technique row(s), ATT&CK ' + built.catalog.version);

  var un = Object.keys(built.unresolvedAll).sort(CATALOG.compareId);
  if (un.length) {
    console.log('   WARN  ' + un.length + ' technique ID(s) are not in ATT&CK ' +
      built.catalog.version + ' and are excluded from the tables:');
    un.forEach(function (id) {
      console.log('           ' + id + '  in ' + built.unresolvedAll[id].join(', '));
    });
    console.log('         Each is most likely a revoked ID. Fix the rule mapping,');
    console.log('         or regenerate the catalog if ATT&CK moved under us.');
  }
  process.exit(same || !check ? 0 : 1);
}

if (require.main === module) main();
module.exports = { build: build, render: render };
