/* The Hunter's Ledger: filters the ATT&CK heatmap on /techniques/ by ID or
   name. Cells are real links in the HTML; this only hides the ones that do not
   match, so a reader with no JavaScript gets the whole matrix. */
(function () {
  'use strict';
  var q = document.getElementById('hl-heatmap-q');
  var map = document.getElementById('hl-heatmap');
  var empty = document.getElementById('hl-heatmap-empty');
  if (!q || !map) return;
  var cells = [].slice.call(map.querySelectorAll('.hl-heatmap__cell'));
  var cols = [].slice.call(map.querySelectorAll('.hl-heatmap__col'));
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
  q.addEventListener('input', apply);
  if (q.value) apply();
})();
