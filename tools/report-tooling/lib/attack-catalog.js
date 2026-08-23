'use strict';

/* Reads data/attack-techniques.tsv, the committed ATT&CK technique catalog.
 *
 * The file is generated from pySigma's ATT&CK dataset, which is the same data
 * `sigma check` validates hunting-detections/ against. Node cannot read that
 * dataset directly, so the TSV is the handoff, and it is committed so an ATT&CK
 * version bump arrives as a reviewable diff rather than as silently different
 * output on someone's machine.
 *
 * Regenerate with: python tools/report-tooling/generate-attack-catalog.py
 */

var fs = require('node:fs');
var path = require('node:path');

var FILE = path.join(__dirname, '..', 'data', 'attack-techniques.tsv');
var ID_RE = /^T\d{4}(?:\.\d{3})?$/;

/* Numeric, not lexical. Lexical sorting puts T1105 before T1055 and reads as
   scrambled in a published table. */
function compareId(a, b) {
  var pa = /^T(\d{4})(?:\.(\d{3}))?$/.exec(a);
  var pb = /^T(\d{4})(?:\.(\d{3}))?$/.exec(b);
  if (!pa || !pb) return String(a) < String(b) ? -1 : (String(a) > String(b) ? 1 : 0);
  if (pa[1] !== pb[1]) return Number(pa[1]) - Number(pb[1]);
  return Number(pa[2] || 0) - Number(pb[2] || 0);
}

function load(file) {
  var target = file || FILE;
  var raw;
  try {
    raw = fs.readFileSync(target, 'utf8');
  } catch (e) {
    throw new Error('the ATT&CK catalog is missing at ' + target +
      '. Run `python tools/report-tooling/generate-attack-catalog.py`.');
  }

  var byId = Object.create(null);
  var version = null;
  var lineNo = 0;
  var count = 0;

  raw.split(/\r?\n/).forEach(function (line) {
    lineNo++;
    if (!line.trim()) return;
    if (line.charAt(0) === '#') {
      var v = /^#\s*attack_version\s+(\S+)/.exec(line);
      if (v) version = v[1];
      return;
    }
    var f = line.split('\t');
    if (f.length < 3) {
      throw new Error('the ATT&CK catalog is malformed at line ' + lineNo +
        ': expected at least 3 tab-separated fields, got ' + f.length);
    }
    var id = f[0].trim();
    if (!ID_RE.test(id)) {
      throw new Error('the ATT&CK catalog has a bad technique ID at line ' +
        lineNo + ': ' + JSON.stringify(id));
    }
    byId[id] = {
      id: id,
      tactic: f[1].trim(),
      name: f[2].trim(),
      tactics: (f[3] || f[1]).split(',').map(function (s) { return s.trim(); })
    };
    count++;
  });

  if (!version) {
    throw new Error('the ATT&CK catalog carries no "# attack_version" header, so ' +
      'nothing can state which ATT&CK release the tables were built from.');
  }
  if (!count) {
    throw new Error('the ATT&CK catalog at ' + target + ' holds no techniques.');
  }

  return { byId: byId, version: version, count: count };
}

/* The strip groups by TACTIC_ORDER. A catalog tactic missing from that list
   would put its techniques in no bar at all, so the two lists have to be
   asserted equal rather than assumed. Returns the offending names. */
function tacticsNotIn(catalog, tacticOrder) {
  var known = Object.create(null);
  tacticOrder.forEach(function (t) { known[t] = true; });
  var bad = Object.create(null);
  Object.keys(catalog.byId).forEach(function (id) {
    var t = catalog.byId[id].tactic;
    if (!known[t]) bad[t] = true;
  });
  return Object.keys(bad).sort();
}

module.exports = {
  FILE: FILE,
  load: load,
  compareId: compareId,
  tacticsNotIn: tacticsNotIn
};
