'use strict';

/* Builds the page the Wire browser check drives.

   WHAT THIS IS AND IS NOT. The rows, the day headings, the label chips and the
   530-item scale come from the page Jekyll actually rendered and published, so
   the check runs at real scale against real content rather than a fixture whose
   author already believed the code worked. Onto that it applies the working
   tree: the local stylesheet, the local filter module, and the markup the
   template change adds.

   So it proves the CSS and the JS behave, at scale, under a real pointer. It
   does NOT prove the deployed template emits what they need. Those are separate
   claims with separate gates: check-wire.js reads wire/index.md for the source
   shape, and the post-publish live sweep sees the real thing. Confusing the two
   would be the same mistake as a gate that re-derives an artifact and checks the
   derivation against itself.

   data-day is the one attribute synthesised here, because the published page
   predates it. It is taken from the day HEADING each row sits beneath, which is
   the rendered ground truth for which day owns that row, not a second opinion
   about how to compute one. */

var MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
  'August', 'September', 'October', 'November', 'December'];

// "Wednesday 19 August 2026" -> "2026-08-19"
function headingToDay(text) {
  var m = String(text).trim().match(/(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})/);
  if (!m) return null;
  var mi = MONTHS.indexOf(m[2]);
  if (mi < 0) return null;
  return m[3] + '-' + String(mi + 1).padStart(2, '0') + '-' +
    String(Number(m[1])).padStart(2, '0');
}

/* `JSDOM` is injected so this module does not care how the caller got it.
   Returns { html, days, dayCounts, gaps, rows } — the facts a check needs to
   assert against, derived from the real corpus rather than hardcoded. */
function build(JSDOM, parts) {
  var dom = new JSDOM(parts.liveHtml);
  var d = dom.window.document;

  var grid = d.querySelector('[data-filter-grid]');
  if (!grid) throw new Error('the fetched page has no [data-filter-grid]');
  var bar = d.querySelector('[data-listing-filter]');
  if (!bar) throw new Error('the fetched page has no [data-listing-filter]');

  var current = null;
  var rows = 0;
  var dayCounts = {};
  /* Once the day filter ships, the fetched page carries its OWN data-day, and
     the synthesis below becomes a CHECK instead: the value the published
     template emitted must equal the day of the heading the row is actually
     sitting under.

     This is the one place anything can see the deployed template, and a
     disagreement here is precisely the timezone split that carrying the day
     rather than deriving it twice exists to prevent. Before the filter shipped
     no row carried the attribute and this stays silent. */
  var disagreements = [];
  var carried = 0;
  var kids = [].slice.call(grid.children);
  for (var i = 0; i < kids.length; i++) {
    var node = kids[i];
    if (node.hasAttribute && node.hasAttribute('data-filter-group')) {
      current = headingToDay(node.textContent);
      if (!current) throw new Error('unparseable day heading: ' + node.textContent);
    } else if (node.classList && node.classList.contains('hl-wire__item')) {
      if (!current) throw new Error('a row appeared before any day heading');
      var was = node.getAttribute('data-day');
      if (was) {
        carried++;
        if (was !== current && disagreements.length < 5) {
          disagreements.push('a row under the ' + current + ' heading carries data-day="' + was + '"');
        }
      }
      node.setAttribute('data-day', current);
      rows++;
      dayCounts[current] = (dayCounts[current] || 0) + 1;
    }
  }
  if (!rows) throw new Error('the fetched page rendered no wire rows');
  /* Partial carriage means the template tags some rows and not others, and the
     untagged ones would be invisible to every date the reader picks. */
  if (carried && carried !== rows) {
    disagreements.push(carried + ' of ' + rows + ' rows carry data-day; the rest would be ' +
      'invisible to the day filter');
  }

  /* --- the filter-bar markup, added only if the published page lacks it ---

     Injecting unconditionally was right while the feature was unreleased. Now
     that it has shipped it would build a page with TWO date controls, and every
     assertion below would silently address the injected one rather than the
     deployed one. */
  var hadControl = !!bar.querySelector('[data-filter-date]');
  if (!hadControl) {
    var chips = bar.querySelector('.hl-filter__chips');
    var dateRow = d.createElement('div');
    dateRow.className = 'hl-filter__date';
    dateRow.innerHTML =
      '<label class="hl-filter__dim" for="hl-wire-date">Date</label>' +
      '<input class="hl-filter__dateinput" type="date" id="hl-wire-date" data-filter-date ' +
      'aria-label="Show only headlines from this date">' +
      '<button type="button" class="hl-filter__datereset" data-filter-date-clear hidden>Clear date</button>';
    chips.insertAdjacentElement('afterend', dateRow);
  }

  var search = bar.querySelector('.hl-filter__search');
  search.setAttribute('placeholder', 'Search headlines, topics, actors…');
  search.setAttribute('aria-label', 'Search headlines, topics and actors');

  var empty = bar.querySelector('[data-filter-empty]');
  var hadMsg = !!empty.querySelector('[data-filter-empty-msg]');
  if (!hadMsg) {
    var resetBtn = empty.querySelector('[data-filter-reset]');
    empty.innerHTML = '<span data-filter-empty-msg>No headlines match that filter.</span> ';
    if (resetBtn) empty.appendChild(resetBtn);
  }

  // --- swap every remote asset for the working tree ---
  [].slice.call(d.querySelectorAll('link[rel="stylesheet"], script[src]'))
    .forEach(function (e) { e.remove(); });
  var script = d.createElement('script');
  script.textContent = parts.filterJs;
  d.body.appendChild(script);

  /* Both sheets go in as raw text AFTER serialisation. Appending them as style
     elements makes jsdom parse them and its CSS parser rejects the minified
     theme sheet outright; only Chrome needs to read these.

     The theme sheet is not optional. Without it the body computes at 16px
     instead of 20px, `em` and `rem` coincide, and the check silently stops being
     able to see the one defect class it most exists for. */
  var css = parts.themeCss + '\n' + parts.customCss;
  var html = dom.serialize().replace('</head>', '<style>' + css + '</style></head>');

  var days = Object.keys(dayCounts).sort();
  var gaps = [];
  var t0 = Date.parse(days[0]);
  var t1 = Date.parse(days[days.length - 1]);
  for (var t = t0; t <= t1; t += 86400000) {
    var iso = new Date(t).toISOString().slice(0, 10);
    if (!dayCounts[iso]) gaps.push(iso);
  }

  return {
    html: html, rows: rows, days: days, dayCounts: dayCounts, gaps: gaps,
    // How much of what is under test the published page already ships, and
    // whether its own data-day agrees with its own headings.
    deployed: { control: hadControl, emptyMsg: hadMsg, carriedRows: carried },
    disagreements: disagreements
  };
}

module.exports = { build: build, headingToDay: headingToDay };
