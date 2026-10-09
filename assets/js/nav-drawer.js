/* The Hunter's Ledger: navigation drawer.
   Opens the side panel the navbar's menu button points at (aria-controls),
   closes it on the close button, the backdrop, Escape, or a link click, and
   keeps focus sane: it moves into the panel on open and back to the button on
   close. Everything here is an enhancement over markup that already carries
   every link; with scripting off the footer repeats them. */
(function () {
  'use strict';

  var btn = document.querySelector('.hl-nav__menu');
  var drawer = document.getElementById('hl-drawer');
  var backdrop = document.getElementById('hl-drawer-backdrop');
  if (!btn || !drawer || !backdrop) return;

  var closeBtn = drawer.querySelector('.hl-drawer__close');
  var lastFocus = null;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function focusables() {
    return drawer.querySelectorAll('a[href], button:not([disabled])');
  }

  function open() {
    lastFocus = document.activeElement;
    drawer.hidden = false;
    backdrop.hidden = false;
    // Let the browser paint the hidden-to-shown state once before the class
    // that drives the transition lands, or the slide never animates.
    requestAnimationFrame(function () {
      drawer.classList.add('hl-drawer--open');
      backdrop.classList.add('hl-drawer__backdrop--open');
    });
    drawer.setAttribute('aria-hidden', 'false');
    btn.setAttribute('aria-expanded', 'true');
    document.body.classList.add('hl-drawer-locked');
    var first = drawer.querySelector('.hl-drawer__link');
    if (first) first.focus();
  }

  function close() {
    drawer.classList.remove('hl-drawer--open');
    backdrop.classList.remove('hl-drawer__backdrop--open');
    drawer.setAttribute('aria-hidden', 'true');
    btn.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('hl-drawer-locked');
    var done = function () { drawer.hidden = true; backdrop.hidden = true; };
    if (reduce) done(); else setTimeout(done, 220);   // matches the CSS transition
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function isOpen() { return btn.getAttribute('aria-expanded') === 'true'; }

  btn.addEventListener('click', function () { if (isOpen()) close(); else open(); });
  if (closeBtn) closeBtn.addEventListener('click', close);
  backdrop.addEventListener('click', close);
  drawer.addEventListener('click', function (e) {
    var a = e.target.closest ? e.target.closest('a[href]') : null;
    if (a) close();
  });
  document.addEventListener('keydown', function (e) {
    if (!isOpen()) return;
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    // Keep Tab inside the panel while it is open.
    if (e.key === 'Tab') {
      var f = focusables();
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
}());
