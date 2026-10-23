(function () {
/* One bar and one grid per instance. /wire/ renders two (Headlines and
   Vulnerabilities), each inside its own [data-filter-scope] section; every
   other page renders one bar and one grid with no scope, which finds the grid
   in the document exactly as before. */
function init(bar) {
  var scope = bar.closest('[data-filter-scope]');
  var grid = (scope || document).querySelector('[data-filter-grid]');
  if (!grid) return;
  // The filterable unit is a catalog card on every listing page and a row on
  // /wire/. A grid names its own selector; the default keeps the four existing
  // pages behaving exactly as they did.
  var cardSel = grid.getAttribute('data-filter-item') || '.hl-catalog-card';
  var cards = [].slice.call(grid.querySelectorAll(cardSel));
  var clusters = [].slice.call(grid.querySelectorAll('[data-series-cluster]'));
  // A group heading (a date row on the Wire) owns every item that follows it
  // until the next heading. Inert on pages that render none.
  var groups = [].slice.call(grid.querySelectorAll('[data-filter-group]'));
  var search = bar.querySelector('.hl-filter__search');
  var count = bar.querySelector('[data-filter-count]');
  var empty = bar.querySelector('[data-filter-empty]');
  // Only /wire/ renders these; on every other page they are null and each date
  // code path below short-circuits.
  var dateInput = bar.querySelector('[data-filter-date]');
  var dateClear = bar.querySelector('[data-filter-date-clear]');
  var emptyMsg = bar.querySelector('[data-filter-empty-msg]');
  // The page's own wording for "nothing matched" (headlines or CVEs).
  var emptyDefault = (emptyMsg && emptyMsg.textContent.trim()) || 'No headlines match that filter.';

  /* The day a row belongs to is CARRIED on the row as data-day, never derived
     here from its timestamp.

     Liquid already computed that exact string to render the row's day heading,
     and _config.yml sets no `timezone:`, so Liquid formats in the build host's
     zone while `new Date(iso)` in a browser is always UTC. Deriving the day a
     second time would file a near-midnight headline under one day's heading and
     inside a different day's filter results, with nothing to report the
     disagreement. Comparing the date input's value against data-day is a plain
     string compare, so no timezone conversion happens anywhere in this path. */
  var dayOf = cards.map(function (c) { return c.getAttribute('data-day'); }).filter(Boolean);
  var distinctDays = Object.keys(dayOf.reduce(function (acc, d) { acc[d] = 1; return acc; }, {})).sort();
  var firstDay = distinctDays.length ? distinctDays[0] : null;
  var lastDay = distinctDays.length ? distinctDays[distinctDays.length - 1] : null;
  // Steer the browser's own picker away from dates the corpus cannot answer.
  if (dateInput && firstDay) {
    dateInput.setAttribute('min', firstDay);
    dateInput.setAttribute('max', lastDay);
  }

  function matchDate(card) {
    if (!dateInput || !dateInput.value) return true;
    return card.getAttribute('data-day') === dateInput.value;
  }

  var MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
    'August', 'September', 'October', 'November', 'December'];
  /* Split rather than Date-parse. `new Date('2026-07-20')` is UTC midnight and
     renders as the 19th for any reader west of Greenwich, which would print a
     window bound the page does not actually hold. */
  function human(d) {
    var p = String(d).split('-');
    return Number(p[2]) + ' ' + MONTHS[Number(p[1]) - 1] + ' ' + p[0];
  }

  /* Landing on nothing has two unrelated causes and they must not read alike.
     One is a genuinely quiet day inside the window (2026-08-09 carried zero
     items in the corpus this was measured against, and seven more days carried
     one to three); the other is a date the Wire never covered. Collapsing them
     into one message teaches the reader that the page is broken. */
  function emptyReason() {
    if (dateInput && dateInput.value && firstDay) {
      var v = dateInput.value;
      if (v < firstDay || v > lastDay) {
        return 'The Wire covers ' + human(firstDay) + ' to ' + human(lastDay) +
          '. That date is outside the window.';
      }
      /* Blame the date only when the date is actually the cause. A day that
         holds rows which some OTHER filter then removed is not a quiet day, and
         saying so is simply false to the reader: 18 August carries 20 headlines,
         and with a topic chip also pressed this once told them the Wire had been
         quiet that day. Caught by looking at a screenshot, after seventeen
         machine checks had passed over it. */
      if (distinctDays.indexOf(v) === -1) {
        return 'No headlines on ' + human(v) + '. The Wire is quiet some days.';
      }
    }
    return emptyDefault;
  }

  // Chip filter dimension (tags). A chip is selected by its data-* attr
  // (data-tag); the matching CARD attribute can differ: chip data-tag maps to
  // card data-tags, so Dim takes an explicit cardAttr. Chips OR-combine within
  // a dimension; the Dim helper stays generic so a second axis can be re-added
  // later. A dimension with no rendered chips is inert (matches everything).
  function Dim(attr, cardAttr, match) {
    var chips = [].slice.call(bar.querySelectorAll('.hl-chip-btn[' + attr + ']'));
    return {
      attr: attr,
      cardAttr: cardAttr || attr,
      // The key this axis uses in the URL hash: data-tag is `tag=`, data-kind
      // is `kind=`. Derived, so a third axis would name itself.
      param: attr.replace(/^data-/, ''),
      chips: chips,
      allChip: bar.querySelector('.hl-chip-btn[' + attr + '=""]'),
      // Chips marked data-default are on when the page opens and after "Clear
      // filters" (the Vulnerabilities tab's "Recent" CVE-age chip). An axis with
      // none starts on All, as every axis did before.
      defaults: chips.filter(function (x) { return x.hasAttribute('data-default'); })
        .map(function (x) { return x.getAttribute(attr).toLowerCase(); }),
      // A range axis matches differently from a tag; see addedWithin().
      match: match || null,
      active: {},
      keys: function () { return Object.keys(this.active); }
    };
  }

  /* "Added" on the Vulnerabilities tab: a chip value is a number of days, and
     a row is inside it when its data-day is fewer than that many days before
     the bar's reference day (data-filter-ref, the day the data was generated).
     Days are compared as UTC calendar dates built from the strings, the same
     no-timezone rule as the date input above. */
  function utcDay(d) {
    var p = String(d || '').split('-');
    return p.length === 3 ? Date.UTC(Number(p[0]), Number(p[1]) - 1, Number(p[2])) : NaN;
  }
  var refDay = utcDay(bar.getAttribute('data-filter-ref') || lastDay);
  function addedWithin(card, keys) {
    var age = (refDay - utcDay(card.getAttribute('data-day'))) / 86400000;
    return keys.some(function (k) { return age < Number(k); });
  }
  /* Axes, in the order a chip row appears. The tag axis is always present. A
     second axis is picked up only when a page actually renders chips for it,
     so the four listing pages that render one row are unaffected. Axes AND
     together: picking a topic and a kind narrows to items matching both. */
  var dims = [Dim('data-tag', 'data-tags')];
  ['data-kind', 'data-list', 'data-sev', 'data-det', 'data-vendor', 'data-age'].forEach(function (a) {
    if (bar.querySelector('.hl-chip-btn[' + a + ']')) dims.push(Dim(a, a));
  });
  if (bar.querySelector('.hl-chip-btn[data-added]')) {
    dims.push(Dim('data-added', 'data-day', addedWithin));
  }

  function matchDim(card, dim) {
    var keys = dim.keys();
    if (keys.length === 0) return true;
    if (dim.match) return dim.match(card, keys);
    var cv = (card.getAttribute(dim.cardAttr) || '').split('|');
    return keys.some(function (k) { return cv.indexOf(k) > -1; });
  }

  /* A whole CVE id searches as a whole id (T-0407): "cve-2026-8877" must not
     also find cve-2026-88771. The "N headlines" link on a vulnerability row
     lands on the Headlines tab with exactly such a term, and its count is of
     exact ids. Any other term is a substring, as before. */
  var CVE_TERM = /^cve-\d{4}-\d{4,}$/;
  function termIn(hay, term) {
    if (!CVE_TERM.test(term)) return hay.indexOf(term) > -1;
    for (var at = hay.indexOf(term); at > -1; at = hay.indexOf(term, at + 1)) {
      if (!/\d/.test(hay.charAt(at + term.length))) return true;
    }
    return false;
  }

  function apply() {
    var term = (search && search.value || '').trim().toLowerCase();
    var shown = 0;
    cards.forEach(function (c) {
      var md = dims.every(function (d) { return matchDim(c, d); });
      // Search matches BOTH the title and the tags, so e.g. "ransomware"
      // surfaces items tagged Ransomware even if it's not in the title.
      var hay = (c.getAttribute('data-title') || '') + '|' + (c.getAttribute('data-tags') || '');
      var mq = !term || termIn(hay, term);
      // An external control (the IOC search on /ioc-feeds/) can veto a card
      // without knowing anything about this module's dimensions. Absent the
      // attribute, which is every other page, this is inert.
      var vetoed = c.getAttribute('data-veto') === '1';
      var vis = md && mq && matchDate(c) && !vetoed;
      // .hl-card carries `display: block !important`, so a plain inline
      // `display:none` is overridden. Set/remove with `important` priority,
      // which sits above author !important in the cascade.
      if (vis) { c.style.removeProperty('display'); }
      else { c.style.setProperty('display', 'none', 'important'); }
      if (vis) shown++;
    });
    // A series cluster is a shell around its member cards — hide the shell
    // (header + box) when the filter has hidden every card inside it.
    clusters.forEach(function (cl) {
      var kids = [].slice.call(cl.querySelectorAll(cardSel));
      var any = kids.some(function (k) { return k.style.display !== 'none'; });
      if (any) { cl.style.removeProperty('display'); }
      else { cl.style.setProperty('display', 'none', 'important'); }
    });
    // A date heading with every row beneath it filtered away would otherwise
    // sit on the page introducing nothing.
    groups.forEach(function (g) {
      var any = false;
      for (var n = g.nextElementSibling; n; n = n.nextElementSibling) {
        if (n.hasAttribute('data-filter-group')) break;
        if (n.matches(cardSel) && n.style.display !== 'none') { any = true; break; }
      }
      if (any) { g.style.removeProperty('display'); }
      else { g.style.setProperty('display', 'none', 'important'); }
    });
    if (count) count.textContent = 'Showing ' + shown + ' of ' + cards.length;
    if (empty) empty.hidden = shown !== 0;
    if (emptyMsg) emptyMsg.textContent = emptyReason();
    // The clear control appears only once there is a date to clear. It sits in
    // a flex row, where `display: flex` on the parent overrides the
    // `display: none` that the hidden attribute relies on, so the CSS carries an
    // explicit [hidden] rule.
    if (dateClear) dateClear.hidden = !(dateInput && dateInput.value);
    writeHash();
  }

  /* Every change to a chip row goes through these two, so a chip click, a tag
     badge click and a hash read all leave the row in the same shape: the All
     chip is on exactly when nothing else on that row is. `wanted` holds
     lowercase values; the Wire renders its chips from the label as spelled, so
     the compare is case-insensitive while dim.active keeps the chip's own
     spelling for matchDim. */
  function setDim(dim, wanted) {
    dim.active = {};
    dim.chips.forEach(function (x) {
      var t = x.getAttribute(dim.attr);
      var on = t !== '' && wanted.indexOf(t.toLowerCase()) > -1;
      if (on) { dim.active[t] = 1; x.classList.add('is-on'); }
      else { x.classList.remove('is-on'); }
    });
    if (dim.allChip && dim.keys().length === 0) dim.allChip.classList.add('is-on');
  }

  function toggleChip(dim, ch) {
    var t = ch.getAttribute(dim.attr);
    if (t === '') { setDim(dim, []); return; }
    var keys = dim.keys().map(function (k) { return k.toLowerCase(); });
    var i = keys.indexOf(t.toLowerCase());
    if (i > -1) keys.splice(i, 1); else keys.push(t.toLowerCase());
    setDim(dim, keys);
  }

  dims.forEach(function (dim) {
    dim.chips.forEach(function (ch) {
      ch.addEventListener('click', function () {
        toggleChip(dim, ch);
        apply();
      });
    });
  });

  /* --- URL state ------------------------------------------------------------

     The bar's state is mirrored into the hash so a filtered view can be handed
     to someone as a link:

         #q=<encoded text>&tag=<a>,<b>&date=YYYY-MM-DD

     plus `kind=` on a page that renders a second chip row. Empty parts are
     omitted, and when nothing is active the hash goes away entirely, so the
     bare page URL stays the one people copy. Tag values are the chip's data-tag
     lowercased; a tag with no chip on this page is ignored on read, since there
     is nothing to press.

     replaceState, never pushState. Every keystroke in the search box is an
     apply(), and a history entry per keystroke would make the back button walk
     through the reader's typing. The hash is read once BEFORE the first
     apply(), so a shared link lands filtered rather than flashing the full list,
     and again on hashchange, which the browser fires when the reader edits the
     URL or steps between two shared links. It does not fire for our own
     replaceState, so write and read never chase each other.

     Not every fragment is ours. The layout's "Skip to content" link lands on
     #main, and a report's TOC links on headings, so a hash that carries none of
     the filter's keys is left alone rather than read as "clear everything".
     Only an EMPTY hash clears, which is what stepping back from a filtered link
     to the bare page looks like.

     The veto ioc-search.js sets on cards is not this bar's state and never
     reaches the hash: it derives from text in a different control that a link
     cannot carry, and apply() reads it fresh from the card each time. */
  var hasHistory = !!(window.history && window.history.replaceState);
  var DATE_SHAPE = /^\d{4}-\d{2}-\d{2}$/;

  /* Where the state lives. The default is the hash, as above, and every page
     but /wire/ keeps it. /wire/ switches its tabs with the hash (#headlines,
     #vulns, a day or a CVE anchor, all CSS :target), so there the bars keep
     their state in the QUERY string instead (data-filter-state="query"), each
     under its own key prefix (data-filter-prefix: none for Headlines, `v` for
     Vulnerabilities), and the hash is left to the tabs. A Headlines link shared
     before the move (#tag=ransomware) is still read once, then rewritten into
     the query. */
  var inQuery = bar.getAttribute('data-filter-state') === 'query';
  var prefix = inQuery ? (bar.getAttribute('data-filter-prefix') || '') : '';
  var legacyHash = false;

  function ownedKeys() {
    return ['q', 'date'].concat(dims.map(function (d) { return d.param; }))
      .map(function (k) { return prefix + k; });
  }

  function decode(s) {
    // A hand-edited `%` the browser could not decode is not worth a thrown
    // error in the middle of init; it reads as nothing.
    try { return decodeURIComponent(s); } catch (e) { return ''; }
  }

  function parseState(raw, pre) {
    var out = { ours: raw === '', q: '', date: '' };
    dims.forEach(function (d) { out[d.param] = null; });   // null: not in the URL
    if (!raw) return out;
    raw.split('&').forEach(function (part) {
      var eq = part.indexOf('=');
      if (eq < 0) return;
      var k = part.slice(0, eq), v = part.slice(eq + 1);
      if (k.indexOf(pre) !== 0) return;
      k = k.slice(pre.length);
      if (k === 'q') { out.q = decode(v); out.ours = true; }
      else if (k === 'date') { out.date = decode(v); out.ours = true; }
      else if (Object.prototype.hasOwnProperty.call(out, k) && k !== 'ours') {
        out.ours = true;
        out[k] = v.split(',').map(decode)
          .map(function (t) { return t.trim().toLowerCase(); })
          .filter(Boolean);
      }
      // Any other key is not ours; it is dropped on the next write.
    });
    return out;
  }

  function readHash() {
    var hash = String(window.location.hash || '').replace(/^#/, '');
    if (!inQuery) return parseState(hash, '');
    // An old shared Headlines link carries its state in the hash. A hash with
    // none of our keys (#vulns, a CVE anchor, #main) is the tabs', not ours.
    if (prefix === '' && hash.indexOf('=') > -1) {
      var old = parseState(hash, '');
      if (old.ours) { legacyHash = true; return old; }
    }
    var q = parseState(String(window.location.search || '').replace(/^\?/, ''), prefix);
    // In the query an absent key means the page's default, never "clear".
    q.ours = true;
    return q;
  }

  function stateToHash() {
    var parts = [];
    var term = (search && search.value || '').trim();
    if (term) parts.push(prefix + 'q=' + encodeURIComponent(term));
    dims.forEach(function (d) {
      var keys = d.keys().map(function (k) { return encodeURIComponent(k.toLowerCase()); });
      var same = keys.length === d.defaults.length &&
        d.defaults.every(function (k) { return keys.indexOf(encodeURIComponent(k)) > -1; });
      if (same) return;   // the default needs no key
      // An axis whose default is not All writes `all` for All, so a link to
      // "include older" survives the trip.
      parts.push(prefix + d.param + '=' + (keys.length ? keys.join(',') : 'all'));
    });
    if (dateInput && dateInput.value) parts.push(prefix + 'date=' + encodeURIComponent(dateInput.value));
    return parts.join('&');
  }

  function writeHash() {
    if (!hasHistory) return;
    var loc = window.location;
    var h = stateToHash();
    var want;
    if (inQuery) {
      // Keep every query key another bar owns; replace only ours.
      var mine = ownedKeys();
      var kept = String(loc.search || '').replace(/^\?/, '').split('&').filter(function (p) {
        return p && mine.indexOf(p.split('=')[0]) === -1;
      });
      if (h) kept.push(h);
      var hash = legacyHash ? '' : loc.hash;
      legacyHash = false;
      want = loc.pathname + (kept.length ? '?' + kept.join('&') : '') + hash;
    } else {
      want = loc.pathname + loc.search + (h ? '#' + h : '');
    }
    if (want === loc.pathname + loc.search + loc.hash) return;
    // A URL the history API refuses (file://, a sandboxed frame) must not stop
    // the filter itself working; the link is a convenience on top of it.
    try { window.history.replaceState(null, '', want); } catch (e) { /* see above */ }
  }

  function applyHash() {
    var s = readHash();
    if (!s.ours) return false;
    if (search) search.value = s.q;
    dims.forEach(function (d) {
      var v = s[d.param];
      if (v === null || v === undefined) v = inQuery ? d.defaults : [];
      else if (v.length === 1 && v[0] === 'all') v = [];
      setDim(d, v);
    });
    // A date the input cannot hold would be coerced to '' by the browser
    // anyway; checking the shape here makes that explicit and testable.
    if (dateInput) dateInput.value = DATE_SHAPE.test(s.date) ? s.date : '';
    apply();
    return true;
  }

  /* A tab, day or CVE anchor landing on a row this bar has hidden (an older
     CVE under the default "Recent", or a filter the reader set) would land on
     nothing. Clear this bar's filters so the target shows, then bring it into
     view. Inert when the hash names nothing inside this grid. */
  function revealTarget() {
    var id = decode(String(window.location.hash || '').replace(/^#/, ''));
    if (!id || id.indexOf('=') > -1) return;
    var el = document.getElementById(id);
    if (!el || !grid.contains(el) || el.style.display !== 'none') return;
    dims.forEach(function (d) { setDim(d, []); });
    if (search) search.value = '';
    if (dateInput) dateInput.value = '';
    apply();
    if (el.scrollIntoView) el.scrollIntoView();
  }

  window.addEventListener('hashchange', function () {
    if (!inQuery) { applyHash(); return; }
    // In query mode the hash belongs to the tabs. Only an old-style filter
    // hash pasted into the address bar is ours to read.
    var h = String(window.location.hash || '');
    if (prefix === '' && h.indexOf('=') > -1) applyHash();
    revealTarget();
  });

  /* --- Tag badges as controls ------------------------------------------------

     A badge on a card sits inside the card's link, so a click on it would open
     the entry. Inside a filter grid it filters instead: the chip whose data-tag
     matches the badge text is toggled exactly as a chip click would, and a tag
     too rare to have earned a chip (fewer than three entries, see
     listing-filter.html) goes into the search box, which already matches on
     tags. The affordance (cursor, title) is set here and not in tag-badge.html,
     because that include also renders badges on report pages, where a badge is
     a label and not a control. No tabindex: a span inside a link is not a
     focus stop, and keyboard users have the chips. */
  var tagDim = dims[0];
  [].slice.call(grid.querySelectorAll('.hl-tag')).forEach(function (b) {
    b.classList.add('hl-tag--clickable');
    b.setAttribute('title', 'Filter by this tag');
  });
  grid.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('.hl-tag') : null;
    if (!b || !grid.contains(b)) return;
    e.preventDefault();
    e.stopPropagation();
    var text = (b.textContent || '').trim();
    var key = text.toLowerCase();
    var chip = null;
    tagDim.chips.forEach(function (ch) {
      var t = ch.getAttribute(tagDim.attr);
      if (t !== '' && t.toLowerCase() === key) chip = ch;
    });
    if (chip) { toggleChip(tagDim, chip); }
    else if (search) { search.value = text; }
    apply();
  });

  // An external control mutates data-veto, then asks for a re-apply.
  document.addEventListener('hl:refilter', apply);

  if (search) search.addEventListener('input', apply);
  // `change` fires when the native picker commits a date; `input` covers typing
  // into the field directly. Both, or a keyboard-entered date does nothing until
  // the field is blurred.
  if (dateInput) {
    dateInput.addEventListener('change', apply);
    dateInput.addEventListener('input', apply);
  }
  if (dateClear) dateClear.addEventListener('click', function () {
    dateInput.value = '';
    apply();
    dateInput.focus();
  });
  var reset = bar.querySelector('[data-filter-reset]');
  if (reset) reset.addEventListener('click', function () {
    dims.forEach(function (d) { setDim(d, d.defaults); });
    if (search) search.value = '';
    // "Clear filters" that left the date set would look like it had failed.
    if (dateInput) dateInput.value = '';
    apply();
  });
  // The first render is the hash's when the page was opened from a shared
  // link; a fragment that is not ours (#main) gets the plain first render.
  dims.forEach(function (d) { setDim(d, d.defaults); });
  if (!applyHash()) apply();
  revealTarget();
}

[].slice.call(document.querySelectorAll('[data-listing-filter]')).forEach(init);
})();
