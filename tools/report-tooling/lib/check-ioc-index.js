'use strict';

/* Verifies assets/data/ioc-index.json.

   The check that matters most is the embargo one, and it is the only gate in
   this repo that protects someone other than the reader. Three published feeds
   belong to campaigns still under disclosure embargo, live at their URL for the
   people in the loop and kept off every listing. If their indicators reached a
   public search box, victim infrastructure would become discoverable before
   those victims had been told.

   The staleness check is regenerate-and-diff, the same approach the detection
   manifest uses: if rebuilding the index changes it, the committed one is stale.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. */

var C = require('../../../assets/js/ioc-classify.js');

function verdict(status, reason, problems, notes) {
  return { status: status, reason: reason || null, problems: problems || [], notes: notes || [] };
}

function slugOf(file) { return String(file).replace(/-iocs\.json$/, ''); }

/* `doc` is the committed index (or null). `status` maps feed file -> published |
   embargoed | unknown. `fresh` is a freshly built index for the diff. */
function check(doc, status, fresh) {
  if (!doc) {
    return verdict('NOT CHECKED', 'assets/data/ioc-index.json is absent or unparseable. ' +
      'Run `node generate-ioc-index.js` in tools/report-tooling.');
  }
  var inds = doc.indicators || {};
  if (!Object.keys(inds).length) {
    return verdict('NOT CHECKED', 'the index declares no indicators, so this run ' +
      'verified nothing.');
  }

  var problems = [], notes = [];
  var reports = doc.reports || {};
  var cov = doc.coverage || { indexed: [], embargoed: [], unknown: [], empty: [] };

  // --- the safety check -------------------------------------------------
  var embargoed = {};
  Object.keys(status || {}).forEach(function (f) {
    if (status[f] === 'embargoed') embargoed[slugOf(f)] = f;
  });
  Object.keys(reports).forEach(function (slug) {
    if (embargoed[slug]) {
      problems.push('DISCLOSURE: report "' + slug + '" is under embargo but appears ' +
        'in the public index');
    }
  });
  Object.keys(inds).forEach(function (key) {
    (inds[key] || []).forEach(function (hit) {
      if (embargoed[hit.report]) {
        problems.push('DISCLOSURE: indicator "' + key + '" points at embargoed report "' +
          hit.report + '"');
      } else if (!reports[hit.report]) {
        problems.push('indicator "' + key + '" points at unknown report "' + hit.report + '"');
      }
    });
  });

  // A half-completed go-live is resolvable only by a human, so it stops here.
  (doc.conflicts || []).forEach(function (c) {
    problems.push('CONFLICT: "' + c.slug + '" has disagreeing publication signals, ' +
      'catalog says ' + c.catalog + ' and front matter says ' + c.front_matter +
      '. Finish the go-live or revert it.');
  });

  // --- coverage: four ways, never folded --------------------------------
  Object.keys(status || {}).forEach(function (f) {
    if (status[f] !== 'published') return;
    var listed = cov.indexed.indexOf(f) > -1 || cov.embargoed.indexOf(f) > -1 ||
                 cov.unknown.indexOf(f) > -1 || cov.empty.indexOf(f) > -1;
    if (!listed) {
      problems.push('feed "' + f + '" is published but appears in no coverage list, ' +
        'so it was silently skipped');
    }
  });
  (cov.unknown || []).forEach(function (f) {
    problems.push('feed "' + f + '" has no catalog entry at all, so it is neither ' +
      'published nor embargoed and its state is undefined');
  });
  (cov.empty || []).forEach(function (f) {
    problems.push('feed "' + f + '" is published but yielded no indicators');
  });
  if ((cov.embargoed || []).length) {
    notes.push(cov.embargoed.length + ' feed(s) correctly excluded as embargoed: ' +
      cov.embargoed.join(', '));
  }
  if (doc.counts && doc.counts.suppressed_benign) {
    notes.push(doc.counts.suppressed_benign + ' signal-free value(s) suppressed ' +
      '(public resolvers, RFC1918, major platforms)');
  }

  // --- key shape --------------------------------------------------------
  Object.keys(inds).forEach(function (key) {
    var i = key.indexOf(':');
    if (i < 1) { problems.push('malformed indicator key "' + key + '", expected type:value'); return; }
    if (C.TYPES.indexOf(key.slice(0, i)) === -1) {
      problems.push('indicator key "' + key + '" has unknown type "' + key.slice(0, i) + '"');
    }
  });

  // --- counts -----------------------------------------------------------
  var multi = Object.keys(inds).filter(function (k) { return inds[k].length > 1; }).length;
  var c = doc.counts || {};
  if (Number(c.indicators) !== Object.keys(inds).length ||
      Number(c.reports) !== Object.keys(reports).length ||
      Number(c.multi_report) !== multi) {
    problems.push('counts disagree: declared indicators=' + c.indicators + ' reports=' +
      c.reports + ' multi=' + c.multi_report + ', actual ' + Object.keys(inds).length +
      '/' + Object.keys(reports).length + '/' + multi);
  }

  // --- staleness --------------------------------------------------------
  if (fresh) {
    var a = JSON.stringify({ i: doc.indicators, r: doc.reports, c: doc.coverage });
    var b = JSON.stringify({ i: fresh.indicators, r: fresh.reports, c: fresh.coverage });
    if (a !== b) {
      problems.push('stale: regenerating the index produces different content. ' +
        'Run `node generate-ioc-index.js` and commit the result.');
    }
  }

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, notes);
}

module.exports = { check: check };
