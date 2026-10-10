/* The Hunter's Ledger: filters the ATT&CK heatmap on /techniques/ by ID or
   name. Cells are real links in the HTML; this only hides the ones that do not
   match, so a reader with no JavaScript gets the whole matrix.

   The filter is mirrored into the hash as #q=<text> so a filtered view can be
   handed to someone as a link, the same rule listing-filter.js follows:
   replaceState, never pushState (a history entry per keystroke would make the
   back button walk through the typing); the hash goes away when the box is
   empty; a hash that is not ours (the skip link's #main, the page's own
   #most-mapped) is left alone rather than read as "clear". */
(function () {
  'use strict';
  var q = document.getElementById('hl-heatmap-q');
  var map = document.getElementById('hl-heatmap');
  var empty = document.getElementById('hl-heatmap-empty');
  if (!q || !map) return;
  var cells = [].slice.call(map.querySelectorAll('.hl-heatmap__cell'));
  var cols = [].slice.call(map.querySelectorAll('.hl-heatmap__col'));
  var hasHistory = !!(window.history && window.history.replaceState);

  function readHash() {
    var m = /(?:^#|&)q=([^&]*)/.exec(String(window.location.hash || ''));
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (e) { return ''; }
  }

  function writeHash() {
    if (!hasHistory) return;
    var loc = window.location;
    var term = q.value.trim();
    var want = loc.pathname + loc.search + (term ? '#q=' + encodeURIComponent(term) : '');
    if (want === loc.pathname + loc.search + loc.hash) return;
    // Only when the hash is ours or empty: a reader who followed #most-mapped
    // and then typed nothing keeps their anchor.
    if (!term && readHash() === null) return;
    try { window.history.replaceState(null, '', want); } catch (e) { /* the filter still works */ }
  }

  function apply() {
    var needle = q.value.trim().toLowerCase();
    var shown = 0;
    cells.forEach(function (c) {
      var hit = !needle || (c.getAttribute('data-q') || '').indexOf(needle) > -1;
      c.hidden = !hit;
      if (hit) shown++;
    });
    cols.forEach(function (col) {
      var any = col.querySelector('.hl-heatmap__cell:not([hidden])');
      col.classList.toggle('is-empty', !any);
    });
    if (empty) empty.hidden = shown > 0;
  }

  function applyHash() {
    var h = readHash();
    if (h === null) return false;
    q.value = h;
    apply();
    return true;
  }

  q.addEventListener('input', function () { apply(); writeHash(); });
  window.addEventListener('hashchange', applyHash);
  if (!applyHash() && q.value) apply();
})();
