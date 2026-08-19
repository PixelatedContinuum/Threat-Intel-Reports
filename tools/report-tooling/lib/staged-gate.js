'use strict';

/* Decides which source-side checks a staged change set needs.

   The pre-commit hook exists for edits that never invoke the publish skill: a
   detection-tiering backfill, a redaction sweep, a bulk correction across published
   feeds. Those bypass hunters-ledger-publish Steps 1a-1f entirely, so nothing
   regenerates the artifacts they invalidate, and the picker or the search box goes
   on serving the previous shape.

   Routing keeps the hook proportional. A commit that touches only prose runs
   nothing, and the runner says so rather than staying silent: "ran and found
   nothing to check" and "not installed" must not look alike.

   What is deliberately NOT routed here is anything needing rendered HTML. The
   glossary's render side and the picker's rule binding both need the published
   build, which by construction does not contain the change being committed.
   Checking them here would pass, and pass for the wrong reason. They are reported
   as owed instead. */

function norm(p) { return String(p).replace(/\\/g, '/').replace(/^\.\//, ''); }

var CHECKS = {
  manifest: {
    id: 'manifest',
    label: 'detection manifest',
    cmd: 'check-detection-manifest.js',
    why: 'hunting-detections/ or its manifest is staged'
  },
  'ioc-index': {
    id: 'ioc-index',
    label: 'indicator index',
    cmd: 'check-ioc-index.js',
    why: 'ioc-feeds/, the catalog or the index itself is staged'
  },
  'ioc-tables': {
    id: 'ioc-tables',
    label: 'feed viewer tables',
    cmd: 'check-ioc-tables.js',
    why: 'ioc-feeds/, the catalog or a viewer stub is staged'
  },
  wire: {
    id: 'wire',
    label: 'wire data',
    cmd: 'check-wire.js',
    why: '_data/wire.yml is staged'
  }
};

var OWED_GLOSSARY =
  'glossary: a term applies retroactively to every published report, and the marks ' +
  'can only be checked against rendered HTML. Run `npm run verify` after the push.';

/* `paths` are staged repo-relative paths. `opts.existing` optionally lists which of
   them are still present on disk; when omitted, every path is treated as present.
   Deletions matter differently per check: a deleted detection file still makes the
   manifest stale, but a deleted report has no markdown left to read. */
function plan(paths, opts) {
  opts = opts || {};
  var list = (paths || []).map(norm).filter(Boolean);
  var present = opts.existing ? null : true;
  var existing = {};
  if (opts.existing) opts.existing.map(norm).forEach(function (p) { existing[p] = true; });
  function onDisk(p) { return present === true ? true : !!existing[p]; }

  var want = {}, reports = {}, owed = [];

  list.forEach(function (p) {
    if (/^hunting-detections\/.+\.md$/.test(p) || p === '_data/detection_manifests.yml') {
      want.manifest = true;
    }
    if (/^ioc-feeds\/.+\.json$/.test(p) || p === '_data/catalog.yml' ||
        p === 'assets/data/ioc-index.json') {
      want['ioc-index'] = true;
    }
    /* The viewer tables derive from the same two sources as the index, plus the
       report front matter that carries the other half of the publication signal,
       and the generated stubs themselves. A stub surviving after its campaign
       went back under embargo is the failure this routing exists to reach. */
    if (/^ioc-feeds\//.test(p) || p === '_data/catalog.yml' ||
        p === '_data/ioc_tables.yml' || /^reports\/[^/]+\/index\.md$/.test(p)) {
      want['ioc-tables'] = true;
    }
    if (p === '_data/wire.yml') want.wire = true;
    if (p === '_data/glossary.yml' && owed.indexOf(OWED_GLOSSARY) === -1) owed.push(OWED_GLOSSARY);

    // Only the report body carries the machinery. A figure beside it does not.
    var m = /^reports\/[^/]+\/index\.md$/.exec(p);
    if (m && onDisk(p)) reports[p] = true;
  });

  var checks = Object.keys(CHECKS)
    .filter(function (k) { return want[k]; })
    .map(function (k) { return CHECKS[k]; });

  return { checks: checks, reports: Object.keys(reports), owed: owed };
}

module.exports = { plan: plan, CHECKS: CHECKS };
