(function () {
  var bar = document.querySelector('[data-listing-filter]');
  var grid = document.querySelector('[data-filter-grid]');
  if (!bar || !grid) return;
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
    return 'No headlines match that filter.';
  }

  // Chip filter dimension (tags). A chip is selected by its data-* attr
  // (data-tag); the matching CARD attribute can differ: chip data-tag maps to
  // card data-tags, so Dim takes an explicit cardAttr. Chips OR-combine within
  // a dimension; the Dim helper stays generic so a second axis can be re-added
  // later. A dimension with no rendered chips is inert (matches everything).
  function Dim(attr, cardAttr) {
    return {
      attr: attr,
      cardAttr: cardAttr || attr,
      chips: [].slice.call(bar.querySelectorAll('.hl-chip-btn[' + attr + ']')),
      allChip: bar.querySelector('.hl-chip-btn[' + attr + '=""]'),
      active: {},
      keys: function () { return Object.keys(this.active); }
    };
  }
  /* Axes, in the order a chip row appears. The tag axis is always present. A
     second axis is picked up only when a page actually renders chips for it,
     so the four listing pages that render one row are unaffected. Axes AND
     together: picking a topic and a kind narrows to items matching both. */
  var dims = [Dim('data-tag', 'data-tags')];
  if (bar.querySelector('.hl-chip-btn[data-kind]')) {
    dims.push(Dim('data-kind', 'data-kind'));
  }

  function matchDim(card, dim) {
    var keys = dim.keys();
    if (keys.length === 0) return true;
    var cv = (card.getAttribute(dim.cardAttr) || '').split('|');
    return keys.some(function (k) { return cv.indexOf(k) > -1; });
  }

  function apply() {
    var term = (search && search.value || '').trim().toLowerCase();
    var shown = 0;
    cards.forEach(function (c) {
      var md = dims.every(function (d) { return matchDim(c, d); });
      // Search matches BOTH the title and the tags, so e.g. "ransomware"
      // surfaces items tagged Ransomware even if it's not in the title.
      var hay = (c.getAttribute('data-title') || '') + '|' + (c.getAttribute('data-tags') || '');
      var mq = !term || hay.indexOf(term) > -1;
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
  }

  dims.forEach(function (dim) {
    dim.chips.forEach(function (ch) {
      ch.addEventListener('click', function () {
        var t = ch.getAttribute(dim.attr);
        if (t === '') {
          dim.active = {};
          dim.chips.forEach(function (x) { x.classList.remove('is-on'); });
          if (dim.allChip) dim.allChip.classList.add('is-on');
        } else {
          if (dim.allChip) dim.allChip.classList.remove('is-on');
          if (dim.active[t]) { delete dim.active[t]; ch.classList.remove('is-on'); }
          else { dim.active[t] = 1; ch.classList.add('is-on'); }
          if (dim.keys().length === 0 && dim.allChip) dim.allChip.classList.add('is-on');
        }
        apply();
      });
    });
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
    dims.forEach(function (d) {
      d.active = {};
      d.chips.forEach(function (x) { x.classList.remove('is-on'); });
      if (d.allChip) d.allChip.classList.add('is-on');
    });
    if (search) search.value = '';
    // "Clear filters" that left the date set would look like it had failed.
    if (dateInput) dateInput.value = '';
    apply();
  });
  apply();
})();
