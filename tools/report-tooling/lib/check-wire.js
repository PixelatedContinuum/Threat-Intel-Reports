'use strict';

/* Verifies _data/wire.yml, the data behind /wire/.

   The failure this exists for is the quiet one. The timer on LXC-102 dies,
   nothing errors anywhere, and the page keeps serving month-old headlines under
   a name that promises freshness. Nothing in the Jekyll build would notice, and
   neither would a reader.

   PASS, FAIL and NOT CHECKED, the third never folded into the first. A missing
   file and an empty item list both mean this run verified nothing, and both say
   so rather than reporting a clean sweep of zero. See
   homelab-soc/docs/gate-honesty-contract.md. */

// One missed run of a twice-daily timer is tolerated; two consecutive fail.
var STALE_HOURS = 36;
var REQUIRED = ['title', 'url', 'source', 'date', 'kind'];
var KINDS = { research: 1, news: 1 };

function verdict(status, reason, problems, warnings, counts) {
  return {
    status: status,
    reason: reason || null,
    problems: problems || [],
    warnings: warnings || [],
    counts: counts || null
  };
}

function normTitle(t) {
  return String(t || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

/* `doc` is the parsed wire.yml, or null when it could not be read.
   `sources` is the parsed wire-sources.yml `sources` map, or null if absent.
   `now` is epoch ms, injected so the staleness case is testable. */
function check(doc, sources, now) {
  if (!doc) {
    return verdict('NOT CHECKED', 'wire.yml is absent or unparseable. ' +
      'Run wire_export.py on LXC-102 to generate it.');
  }

  var items = doc.items;
  if (!Array.isArray(items) || !items.length) {
    return verdict('NOT CHECKED', 'wire.yml declares no items, so this run ' +
      'verified nothing about the page content.');
  }

  var problems = [];
  var warnings = [];

  var gen = Date.parse(doc.generated_at || '');
  if (!gen) {
    problems.push('generated_at is missing or unparseable: ' + doc.generated_at);
  } else if ((now - gen) / 3600000 > STALE_HOURS) {
    problems.push('stale: generated_at is ' + ((now - gen) / 3600000).toFixed(1) +
      ' hours old, over the ' + STALE_HOURS + '-hour limit. The generator on ' +
      'LXC-102 has missed at least two consecutive runs.');
  }

  var windowDays = Number(doc.window_days);
  if (!windowDays) problems.push('window_days is missing or not a number');
  var oldestAllowed = gen && windowDays ? gen - windowDays * 86400000 : null;

  var seen = Object.create(null);
  var labelsPresent = Object.create(null);
  var nResearch = 0;

  for (var i = 0; i < items.length; i++) {
    var it = items[i] || {};
    var where = 'item ' + (i + 1) + ' (' + String(it.title || '?').slice(0, 48) + ')';

    if (Object.prototype.hasOwnProperty.call(it, 'description')) {
      problems.push(where + ' carries a description field. The Wire aggregates ' +
        'by headline and attribution only; publisher article text must never ship.');
    }

    for (var f = 0; f < REQUIRED.length; f++) {
      if (!it[REQUIRED[f]]) problems.push(where + ' is missing ' + REQUIRED[f]);
    }

    if (it.url && String(it.url).indexOf('https://') !== 0) {
      problems.push(where + ' has a non-https url: ' + it.url);
    }

    if (it.kind && !KINDS[it.kind]) {
      problems.push(where + ' has an unknown kind: ' + it.kind);
    }
    if (it.kind === 'research') nResearch++;

    var d = Date.parse(it.date || '');
    if (it.date && !d) {
      problems.push(where + ' has an unparseable date: ' + it.date);
    } else if (d && oldestAllowed && d < oldestAllowed) {
      problems.push(where + ' is outside the declared ' + windowDays +
        '-day window (' + it.date + ')');
    }

    var key = normTitle(it.title);
    if (key && seen[key]) problems.push(where + ' is a duplicate title');
    if (key) seen[key] = 1;

    (it.labels || []).forEach(function (l) { labelsPresent[String(l)] = 1; });

    if (sources && it.source &&
        !Object.prototype.hasOwnProperty.call(sources, it.source) &&
        warnings.indexOf(it.source) === -1) {
      warnings.push(it.source);
    }
  }

  /* The page renders chips straight from `topics` without checking them against
     the items, so a chip naming a label nothing carries is a control that
     selects an empty page. */
  (doc.topics || []).forEach(function (t) {
    var lab = t && t.label;
    if (lab && !labelsPresent[String(lab)]) {
      problems.push('topic chip "' + lab + '" matches no item label, so the ' +
        'chip would filter the page to nothing');
    }
  });

  var c = doc.counts || {};
  if (Number(c.total) !== items.length ||
      Number(c.research) !== nResearch ||
      Number(c.news) !== items.length - nResearch) {
    problems.push('counts disagree with the item list: declared total=' +
      c.total + ' research=' + c.research + ' news=' + c.news +
      ', actual total=' + items.length + ' research=' + nResearch +
      ' news=' + (items.length - nResearch));
  }

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, warnings.sort(), {
    total: items.length, research: nResearch, news: items.length - nResearch
  });
}

module.exports = { check: check, STALE_HOURS: STALE_HOURS };
