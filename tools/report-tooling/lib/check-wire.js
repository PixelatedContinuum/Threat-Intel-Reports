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
// Hues defined in assets/css/custom.css as .hl-topic-c1 .. .hl-topic-c12.
var PALETTE_SIZE = 12;
// How many tags the page draws per item; the rest are never rendered.
// Two, not three: three left 60% of rows wrapping their tags to a second line.
var DISPLAYED_LABELS = 2;
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
  var lc = doc.label_colors || {};
  (doc.topics || []).forEach(function (t) {
    var lab = t && t.label;
    if (lab && !labelsPresent[String(lab)]) {
      problems.push('topic chip "' + lab + '" matches no item label, so the ' +
        'chip would filter the page to nothing');
    }
    /* The colour is a class suffix the CSS palette defines for 1..PALETTE_SIZE.
       Anything outside that renders a chip with no colour variable set, which
       is a silent visual regression: the chip still works, it just goes grey
       while its siblings are coloured. */
    var col = t && t.color;
    if (!Number.isInteger(col) || col < 1 || col > PALETTE_SIZE) {
      problems.push('topic chip "' + lab + '" has colour ' + JSON.stringify(col) +
        ', which is outside the 1-' + PALETTE_SIZE + ' palette the CSS defines');
    } else if (lab && lc[lab] !== col) {
      problems.push('topic chip "' + lab + '" is colour ' + col +
        ' but label_colors says ' + JSON.stringify(lc[lab]) +
        ', so its tags would not match its chip');
    }
  });

  Object.keys(lc).forEach(function (lab) {
    var v = lc[lab];
    if (!Number.isInteger(v) || v < 1 || v > PALETTE_SIZE) {
      problems.push('label_colors["' + lab + '"] is ' + JSON.stringify(v) +
        ', outside the 1-' + PALETTE_SIZE + ' palette the CSS defines');
    }
  });

  /* A displayed label with no colour renders grey among coloured siblings.
     521 of the 532 labels this page draws are not chip topics, and leaving them
     uncoloured is precisely what made the first build look flat, so an
     unmapped one is a defect rather than a cosmetic gap. */
  var uncoloured = [];
  items.forEach(function (it) {
    (it.labels || []).slice(0, DISPLAYED_LABELS).forEach(function (l) {
      if (!Object.prototype.hasOwnProperty.call(lc, String(l)) &&
          uncoloured.indexOf(String(l)) === -1) {
        uncoloured.push(String(l));
      }
    });
  });
  if (uncoloured.length) {
    problems.push(uncoloured.length + ' displayed label(s) have no colour in ' +
      'label_colors, so they would render grey among coloured siblings: ' +
      uncoloured.slice(0, 6).join(', ') +
      (uncoloured.length > 6 ? ', …' : ''));
  }

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

/* Verifies wire/index.md still derives each row's day EXACTLY ONCE.

   The page groups rows under a day heading and the filter narrows to a picked
   day. Both need the same answer to "which day is this row". _config.yml sets no
   `timezone:`, so a second derivation elsewhere in the stack would not merely be
   redundant, it would disagree: Liquid's `date:` filter formats in the build
   host's zone while `new Date(iso)` in a browser is always UTC, and any headline
   filed within a few hours of midnight would sit under one day's heading and
   inside another day's filter results with nothing to report it.

   So the rule is that `data-day` carries the SAME `day` variable the grouping
   already computed. Re-deriving it in the template would still be internally
   consistent today and would still be a second definition of one rule, which is
   this codebase's signature failure and has now cost four separate defects.

   `src` is the text of wire/index.md, or null when it could not be read. This
   pins template STRUCTURE, not rendered output; that a reader's browser then
   filters correctly is the browser check. */
function checkPage(src) {
  if (src === null || src === undefined) {
    return verdict('NOT CHECKED', 'wire/index.md is absent or unreadable, so ' +
      'nothing was verified about how the page derives each row\'s day.');
  }

  var problems = [];

  // The single derivation that both the heading and the filter must share.
  if (!/\{%-?\s*assign\s+day\s*=\s*i\.date\s*\|\s*date:\s*["']%Y-%m-%d["']/.test(src)) {
    problems.push('the `day` assign from i.date is missing or changed shape, so ' +
      'the grouping and the day filter no longer share one derivation');
  }

  // The row must carry that variable, not its own copy of the expression.
  if (!/data-day="\{\{-?\s*day\s*-?\}\}"/.test(src)) {
    if (/data-day="\{\{[^}]*i\.date/.test(src)) {
      problems.push('data-day re-derives the day from i.date instead of carrying ' +
        'the `day` variable the heading grouping already computed. Two ' +
        'definitions of one rule; use {{ day }}');
    } else {
      problems.push('rows carry no data-day="{{ day }}", so the day filter on ' +
        '/wire/ has nothing to match against and silently shows everything');
    }
  }

  // The heading grouping must still be driven by that same variable.
  if (!/\{%-?\s*if\s+day\s*!=\s*current_day\s*-?%\}/.test(src)) {
    problems.push('day headings are no longer grouped on the `day` variable, so ' +
      'a heading and the rows beneath it can disagree about the date');
  }

  /* The filter module reaches the reader through a versioned URL. Shipping new
     markup against a cached older script is invisible on a fresh browser and
     total on a returning one, which has already happened once here. */
  var v = src.match(/listing-filter\.js[^"]*\?v=(\d+)/);
  if (!v) {
    problems.push('the listing-filter.js tag carries no ?v= cache-bust, so a ' +
      'returning reader can get new markup against the old script');
  }

  return verdict(problems.length ? 'FAIL' : 'PASS', null, problems, [], null);
}

module.exports = { check: check, checkPage: checkPage, STALE_HOURS: STALE_HOURS };
