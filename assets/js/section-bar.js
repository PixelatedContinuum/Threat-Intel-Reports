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
  function sizeBar() { document.documentElement.style.setProperty('--sbh', bar.offsetHeight + 'px'); }
  sizeBar();
  addEventListener('resize', sizeBar);
  function pick() {
    var off = bar.offsetHeight + (document.querySelector('.hl-nav') ? document.querySelector('.hl-nav').offsetHeight : 0) + 24, idx = 0;
    for (var i = 0; i < secs.length; i++) { if (secs[i] && secs[i].getBoundingClientRect().top <= off) idx = i; }
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) idx = secs.length - 1;
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
