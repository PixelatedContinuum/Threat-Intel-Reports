/* Sticky section bar of the actor, family and technique pages (T-0500.1.7.4 b3): marks the section in view. Plain scroll handler, no library.
   Without this script every entry is still a plain #fragment link and nothing is hidden. */
(function () {
  'use strict';
  var bar = document.querySelector('.hl-sbar');
  if (!bar) return;
  var links = [].slice.call(bar.querySelectorAll('a[href^="#"]'));
  var secs = links.map(function (a) {
    var el = document.getElementById(a.getAttribute('href').slice(1));
    return el ? (el.closest('.hl-dsec') || el) : null;
  });
  var cur = -1, ticking = false;
  /* A section whose target is not drawn (the detection picker hides an engine with no rules) gets no bar entry: its link is hidden and the
     grid counts the visible ones. */
  function visible(i) { var el = secs[i]; return !!(el && el.getClientRects().length); }
  function syncVisible() {
    var n = 0;
    links.forEach(function (a, i) { var v = visible(i); a.hidden = !v; if (v) n++; });
    var list = bar.querySelector('.hl-sbar__list');
    if (list && n) list.style.setProperty('--n', n);
    sizeBar();   /* hiding an entry changes the column count and so the bar's height, which the scroll padding reads */
  }
  var lastH = -1;
  function sizeBar() { var h = bar.offsetHeight; if (h !== lastH) { lastH = h; document.documentElement.style.setProperty('--sbh', h + 'px'); } }
  syncVisible();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () { syncVisible(); onScroll(); });
  addEventListener('load', function () { syncVisible(); onScroll(); });   /* the picker script may hide an engine's section after this script ran */
  addEventListener('resize', sizeBar);
  function pick() {
    var off = bar.offsetHeight + (document.querySelector('.hl-nav') ? document.querySelector('.hl-nav').offsetHeight : 0) + 24, idx = 0;
    syncVisible();
    var first = -1, last = -1;
    for (var i = 0; i < secs.length; i++) {
      if (!visible(i)) continue;
      if (first < 0) first = i;
      last = i;
      if (secs[i].getBoundingClientRect().top <= off) idx = i;
    }
    if (first >= 0 && idx < first) idx = first;
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2 && last >= 0) idx = last;
    return idx;
  }
  function set(i) {
    if (i === cur) return;
    cur = i;
    links.forEach(function (a, k) { if (k === i) a.setAttribute('aria-current', 'true'); else a.removeAttribute('aria-current'); });
    var l = links[i], ch = bar.querySelector('.hl-sbar__list');
    if (ch && ch.scrollWidth > ch.clientWidth) { ch.scrollTo({ left: Math.max(0, l.offsetLeft - (ch.clientWidth - l.offsetWidth) / 2) }); }
  }
  function onScroll() { if (ticking) return; ticking = true; requestAnimationFrame(function () { ticking = false; set(pick()); }); }
  addEventListener('scroll', onScroll, { passive: true });
  addEventListener('resize', onScroll);
  links.forEach(function (a, i) { a.addEventListener('click', function () { set(i); }); });
  set(pick());
  window.hlSectionBar = { pick: pick, current: function () { return cur; } };
})();
