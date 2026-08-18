/* The Hunter's Ledger: infographic navigation chips.
   Appends a row of links under a figure, one per part the report declared in its
   figure_nav front matter, so a reader studying a graphic can reach the section
   that explains any part of it.

   Chips are plain anchors on purpose. That gives keyboard access and focus order
   natively, lets middle-click and copy-link behave, and reuses the layout's own
   capture-phase handler, which already opens any collapsed <details> containing
   the target. The only new behaviour in this module is the destination marker. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.HLFigureNav = api; api.init(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var MARK_CLASS = 'hl-fignav-target';
  var MARK_MS = 1600;

  function basename(src) {
    return String(src || '').split('#')[0].split('?')[0].split('/').pop();
  }

  /* Matching on the basename rather than the whole src is what makes this
     independent of the Liquid `| relative_url` wrapper and of any future baseurl
     change. Every hit is returned so the caller can refuse an ambiguous one
     instead of silently picking the first. */
  function figuresFor(root, image) {
    var figs = root.querySelectorAll('figure');
    var hits = [];
    for (var i = 0; i < figs.length; i++) {
      var img = figs[i].querySelector('img[src]');
      if (img && basename(img.getAttribute('src')) === image) hits.push(figs[i]);
    }
    return hits;
  }

  function buildNav(doc, parts) {
    var nav = doc.createElement('nav');
    nav.className = 'hl-fignav';
    nav.setAttribute('aria-label', 'Jump to the sections shown in this figure');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (!p || !p.label || !p.anchor) continue;
      var a = doc.createElement('a');
      a.className = 'hl-fignav__chip';
      a.setAttribute('href', p.anchor);
      a.textContent = p.label;
      nav.appendChild(a);
    }
    return nav;
  }

  /* Zero matching figures is a dead entry and more than one is ambiguous. Both
     render nothing, because a half-placed chip row is worse than none: it looks
     deliberate and points somewhere arbitrary. */
  function render(body, entries, doc) {
    doc = doc || body.ownerDocument;
    var made = 0;
    var list = entries || [];
    for (var i = 0; i < list.length; i++) {
      var e = list[i];
      if (!e || !e.image || !e.parts || !e.parts.length) continue;
      var hits = figuresFor(body, e.image);
      if (hits.length !== 1) continue;
      if (hits[0].querySelector('.hl-fignav')) continue;
      var nav = buildNav(doc, e.parts);
      if (!nav.firstChild) continue;
      hits[0].appendChild(nav);
      made++;
    }
    return made;
  }

  var markTimer = null;
  var marked = null;

  /* Scrolling into the middle of a long report leaves a reader unsure which
     heading was the target, so the destination says so briefly. */
  function markTarget(el) {
    if (marked && marked.classList) marked.classList.remove(MARK_CLASS);
    if (markTimer) clearTimeout(markTimer);
    el.classList.add(MARK_CLASS);
    marked = el;
    markTimer = setTimeout(function () {
      el.classList.remove(MARK_CLASS);
      if (marked === el) marked = null;
    }, MARK_MS);
  }

  function bindMarking(body, doc) {
    doc = doc || body.ownerDocument;
    body.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('.hl-fignav__chip') : null;
      if (!a) return;
      var href = a.getAttribute('href') || '';
      if (href.charAt(0) !== '#') return;
      var id;
      try { id = decodeURIComponent(href.slice(1)); } catch (err) { id = href.slice(1); }
      var t = doc.getElementById(id) || doc.getElementById(href.slice(1));
      /* No preventDefault anywhere. The browser does the scrolling and the
         layout's own handler opens the teardown; this listener only marks. */
      if (t) markTarget(t);
    });
  }

  function init() {
    var doc = document;
    var body = doc.querySelector('.hl-post-content');
    if (!body) return;
    var raw = doc.getElementById('hl-figure-nav');
    if (!raw) return;
    var entries;
    try { entries = JSON.parse(raw.textContent); } catch (e) { return; }
    if (!entries || !entries.length) return;
    render(body, entries, doc);
    bindMarking(body, doc);
  }

  return {
    basename: basename,
    figuresFor: figuresFor,
    buildNav: buildNav,
    render: render,
    markTarget: markTarget,
    bindMarking: bindMarking,
    init: init,
    MARK_CLASS: MARK_CLASS
  };
});
