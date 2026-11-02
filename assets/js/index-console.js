/* The mobile "Filter by topic" toggle of a listing's filter console (design D, T-0500.1.7.4 b2).
   Below 1100px the topic chips sit behind this button; it shows how many chips other than "All" are on, and a filter already active when the page
   loads (from the address, which listing-filter.js restores) opens the chips so a hidden filter is never the reason a list looks short.
   Nothing here filters: listing-filter.js owns that, and a page without this script still shows every chip on a wide screen. */
(function () {
  'use strict';
  var consoles = [].slice.call(document.querySelectorAll('.hl-d-cons'));
  consoles.forEach(function (c) {
    var btn = c.querySelector('.hl-d-ftog');
    if (!btn) return;
    var n = btn.querySelector('[data-ftog-n]');
    function active() {
      return [].slice.call(c.querySelectorAll('.hl-chip-btn.is-on')).filter(function (b) {
        return b.hasAttribute('data-tag') && b.getAttribute('data-tag') !== '';
      }).length;
    }
    function label() {
      var k = active();
      if (n) n.textContent = k ? String(k) : '';
      btn.classList.toggle('has-active', k > 0);
    }
    btn.addEventListener('click', function () {
      var open = !c.classList.contains('is-open');
      c.classList.toggle('is-open', open);
      btn.setAttribute('aria-expanded', String(open));
    });
    c.addEventListener('click', function () { setTimeout(label, 0); });
    label();
    if (active() > 0) { c.classList.add('is-open'); btn.setAttribute('aria-expanded', 'true'); }
  });
})();
