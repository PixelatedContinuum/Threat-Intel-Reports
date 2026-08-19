'use strict';

/* Verifies _data/detection_manifests.yml against the source it derives from.

   This closes a gap found on 2026-08-19. The manifest was written by exactly one
   line in generate-detection-manifests.js and read by NOTHING in the tooling:

     - sweepSource() is GEN.run({ dryRun: true }), which re-derives the manifest
       and checks that derivation against itself. It never opens the committed file.
     - sweepRendered() fetches the live pages, so it describes the published build
       rather than the working tree.

   So a committed manifest that had drifted from hunting-detections/ passed every
   gate in the repo, and the picker went on serving whatever shape the manifest was
   last generated at. The failure is invisible from both ends: the source is fine,
   the derivation is fine, and nobody compares them.

   The approach is regenerate-and-diff, the same one check-ioc-index.js uses. If
   rebuilding the manifest changes it, the committed one is stale.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. In particular
   a generator that read no files produces empty YAML, which would compare equal to
   an empty committed file and read as a clean pass. That case is NOT CHECKED. */

function verdict(status, reason, problems, notes) {
  return { status: status, reason: reason || null, problems: problems || [], notes: notes || [] };
}

var REMEDY = 'Run `node generate-detection-manifests.js` in tools/report-tooling and ' +
  'stage the result.';

/* Line endings and a trailing newline are not drift.

   The vault is CRLF and the site repo is LF-normalised, so a manifest that
   round-tripped through a Windows editor differs from a freshly generated one by
   line ending alone. Failing on that would train the reader to bypass the hook,
   which costs more than it protects. */
function normalise(text) {
  return String(text).replace(/\r\n/g, '\n').replace(/\n+$/, '');
}

function firstDivergence(a, b) {
  var la = a.split('\n'), lb = b.split('\n');
  var n = Math.max(la.length, lb.length);
  for (var i = 0; i < n; i++) {
    if (la[i] !== lb[i]) {
      return { line: i + 1, committed: la[i], fresh: lb[i], committedLines: la.length,
               freshLines: lb.length };
    }
  }
  return null;
}

/* `committed` is the manifest file's text, or null if it is absent or unreadable.
   `gen` is the generator's own result, carrying its verdict, its problems and the
   YAML it would have written. */
function check(committed, gen) {
  if (!gen) {
    return verdict('NOT CHECKED', 'the generator returned no result, so nothing was compared.');
  }

  /* A generator that could not read its sources, or read none, cannot be used as
     the reference side of a diff. Both sides would be empty and compare equal. */
  if (gen.status === 'NOT CHECKED') {
    return verdict('NOT CHECKED', 'the generator reported NOT CHECKED (' +
      (gen.reason || 'no reason given') + '), so it cannot be the reference side of a diff.');
  }
  if (!gen.rules) {
    return verdict('NOT CHECKED', 'the generator derived 0 rules from ' + (gen.files || 0) +
      ' file(s), so this run verified nothing.');
  }
  if (typeof gen.yaml !== 'string') {
    return verdict('NOT CHECKED', 'the generator did not return the manifest text, so ' +
      'staleness could not be compared.');
  }

  if (committed === null || committed === undefined) {
    return verdict('NOT CHECKED', '_data/detection_manifests.yml is absent or unreadable. ' +
      REMEDY);
  }

  var problems = [], notes = [];

  // The generator's own findings are real failures regardless of the diff.
  (gen.problems || []).forEach(function (p) { problems.push(p); });

  var a = normalise(committed), b = normalise(gen.yaml);
  if (a !== b) {
    var d = firstDivergence(a, b);
    var where = d
      ? 'first differs at line ' + d.line + ' (committed ' + d.committedLines +
        ' lines, regenerated ' + d.freshLines + ')'
      : 'differs in length only';
    problems.push('_data/detection_manifests.yml is stale against hunting-detections/: ' +
      where + '. ' + REMEDY);
  }

  notes.push(gen.files + ' detection file(s), ' + gen.rules + ' rule(s), ' +
    (gen.xref || 0) + ' cross-referenced');

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, notes);
}

module.exports = { check: check, normalise: normalise, firstDivergence: firstDivergence };
