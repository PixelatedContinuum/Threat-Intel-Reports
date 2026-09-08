/* The Hunter's Ledger: turns an ATT&CK mapping table into something a reader
   can use instead of scroll past.

   WHY THIS EXISTS. 21 reports carry a `Tactic / Technique | Name | Evidence`
   table, 710 data rows between them, a mean of 34 rows each. The coverage strip
   above each one already summarises the tactics and, on a click, lists the
   technique IDs in that tactic. But the strip and the table were two unconnected
   things: clicking a tactic told you which IDs were in it and left you to find
   those rows yourself in the wall below.

   So this does three things and no more:
     1. search across technique ID, name and evidence, with a live count
     2. clicking a tactic in the strip filters the table to that tactic's rows
     3. the table opens capped at a readable height instead of at full length

   WHY IT ENHANCES RATHER THAN REPLACES. The table is the substrate, not a
   rendering of data held somewhere else. check-report.js parses these tables out
   of the DOM with the very same attack-coverage parser, so moving the rows into
   front matter would have taken 710 rows out of that gate's reach. Filtering
   hides rows with the `hidden` attribute and never rewrites, reorders or removes
   one, so the offline gate reads exactly what it read before and a reader with
   no JavaScript gets the table unchanged.

   Classification comes from attack-coverage.js rather than from re-reading the
   cells here. The corpus carries at least eight mapping-table shapes and ATT&CK
   renamed Defense Evasion to Stealth, so a second parser in this file would be a
   second thing to keep in step. */
(function () {
  'use strict';

  var AC = window.HLAttackCoverage;
  var body = document.querySelector('.hl-post-content') || document.querySelector('.hl-post-body');
  if (!body || !AC || typeof AC.findMappingTables !== 'function') return;

  var CAP = 8;             // rows shown before the reader asks for the rest
  var MIN_TO_ENHANCE = 12; // below this a table is already readable, so leave it alone

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /* The strip is inserted before the table's insertion point, which is the
     enclosing teardown when there is one. Same rule as attack-coverage's
     insertionPointFor, so the two cannot disagree about which strip belongs to
     which table. */
  function stripFor(table) {
    var node = table, anchor = table;
    while (node && node.parentElement) {
      if (node.tagName === 'DETAILS' && node.classList.contains('hl-teardown')) { anchor = node; break; }
      node = node.parentElement;
    }
    var prev = anchor.previousElementSibling;
    return (prev && prev.classList && prev.classList.contains('hl-attack')) ? prev : null;
  }

  function dataRows(table) {
    return [].slice.call(table.querySelectorAll('tr')).filter(function (tr) {
      return !tr.querySelector('th') && tr.querySelector('td');
    });
  }

  function enhance(table) {
    var rows = dataRows(table);
    if (rows.length < MIN_TO_ENHANCE) return;

    var parsed = AC.parseTable(table);
    var groups = (typeof AC.groupByTactic === 'function' && parsed)
      ? AC.groupByTactic(parsed.techniques) : {};

    /* tactic -> the technique ids in it, so a row is selected by the id it
       carries rather than by re-reading its tactic cell */
    var idsByTactic = {};
    Object.keys(groups).forEach(function (t) {
      idsByTactic[t] = (groups[t] || []).map(function (x) { return x.id; });
    });

    var haystacks = rows.map(function (tr) {
      return (tr.textContent || '').toLowerCase().replace(/\s+/g, ' ');
    });

    /* Resolved before the toolbar is inserted. Inserting it makes the toolbar
       the table's previousElementSibling, so looking for the strip afterwards
       finds nothing and the tactic filter silently never binds. */
    var strip = stripFor(table);

    var state = { q: '', tactic: null, expanded: false };

    var tools = el('div', 'hl-atk-tools');
    var search = document.createElement('input');
    search.type = 'search';
    search.className = 'hl-atk-search';
    search.placeholder = 'Search technique, name or evidence';
    search.setAttribute('aria-label', 'Search this ATT&CK mapping table');

    var count = el('span', 'hl-atk-count');
    count.setAttribute('role', 'status');
    count.setAttribute('aria-live', 'polite');

    var filterNote = el('span', 'hl-atk-filter');
    filterNote.hidden = true;

    var more = el('button', 'hl-atk-more');
    more.type = 'button';

    tools.appendChild(search);
    tools.appendChild(filterNote);
    tools.appendChild(count);
    tools.appendChild(more);
    table.parentNode.insertBefore(tools, table);
    table.classList.add('hl-atk-table');

    function matches(i) {
      var tr = rows[i];
      if (state.tactic) {
        var ids = idsByTactic[state.tactic] || [];
        var text = tr.textContent || '';
        var hit = false;
        for (var k = 0; k < ids.length; k++) {
          if (text.indexOf(ids[k]) !== -1) { hit = true; break; }
        }
        if (!hit) return false;
      }
      if (state.q && haystacks[i].indexOf(state.q) === -1) return false;
      return true;
    }

    function apply() {
      var filtering = !!(state.q || state.tactic);
      var shown = 0, eligible = 0;
      for (var i = 0; i < rows.length; i++) {
        var ok = matches(i);
        if (ok) eligible++;
        var capped = !filtering && !state.expanded && eligible > CAP;
        var visible = ok && !capped;
        rows[i].hidden = !visible;
        if (visible) shown++;
      }

      count.textContent = shown === rows.length
        ? rows.length + ' techniques'
        : 'showing ' + shown + ' of ' + rows.length + ' techniques';

      var hiddenByCap = !filtering && !state.expanded && rows.length > CAP;
      more.hidden = filtering;
      more.textContent = state.expanded
        ? 'show fewer'
        : 'show all ' + rows.length;
      if (!hiddenByCap && !state.expanded) more.hidden = true;

      filterNote.hidden = !state.tactic;
      filterNote.textContent = state.tactic ? state.tactic + ' only, clear' : '';
    }

    search.addEventListener('input', function () {
      state.q = search.value.trim().toLowerCase();
      apply();
    });

    more.addEventListener('click', function () {
      state.expanded = !state.expanded;
      apply();
      if (!state.expanded) tools.scrollIntoView({ block: 'nearest' });
    });

    filterNote.addEventListener('click', function () {
      state.tactic = null;
      apply();
    });

    if (strip) {
      /* The strip keeps its own click handler, which lists the technique chips.
         This listens alongside it rather than replacing it, so attack-coverage
         is untouched. A second click on the same tactic clears the filter, which
         is also what the strip does with its own detail panel. */
      strip.addEventListener('click', function (e) {
        var seg = e.target.closest ? e.target.closest('.hl-attack__seg') : null;
        if (!seg || !strip.contains(seg)) return;
        var tactic = seg.getAttribute('data-tactic');
        if (!(idsByTactic[tactic] || []).length) return;
        state.tactic = (state.tactic === tactic) ? null : tactic;
        state.expanded = true;
        apply();
      });
    }

    apply();
  }

  AC.findMappingTables(body).forEach(function (t) {
    try { enhance(t); } catch (err) { /* a broken table must not take the page with it */ }
  });
})();
