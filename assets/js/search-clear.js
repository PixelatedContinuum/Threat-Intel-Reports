/* The Hunter's Ledger: a clear (X) button on every site search box (T-0552).
   One script for the navbar box, every listing filter (.hl-filter__search: reports, detections,
   IOC feeds, STIX, actors, families, techniques, impact, the three Wire tabs) and the ATT&CK table
   search a report page builds with a script (.hl-atk-search): any <input type="search"> or
   .hl-filter__search. Pagefind's own box on /search/ has its own Clear button and is skipped.

   The button is a real <button type="button" aria-label="Clear search">, hidden while the box is
   empty. Clicking it (or pressing Escape in a box that has text) empties the box, fires a bubbling
   `input` event, which is the event every filter script already listens to, so the listing, the
   Wire filters, the URL state and the heatmap all reset through their own code, and returns focus
   to the box. Escape in an empty box is left alone for whatever else listens for it.

   Markup: a box inside the navbar form gets the button as its sibling (the navbar positions the
   box itself); every other box is wrapped in <span class="hl-clr"> and the button goes inside the
   wrapper, so it sits at the box's right end without the page's layout knowing. The wrapper
   carries .is-filled while the box has text. Boxes a script adds later are picked up by a
   MutationObserver; a value written by a script (a restored #hash) is picked up on load,
   pageshow, hashchange and hl:refilter. */
(function () {
  'use strict';

  var SEL = 'input[type="search"], input.hl-filter__search';
  var MARK = 'data-hl-clr';
  var X = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" aria-hidden="true" focusable="false"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>';
  var syncers = [];

  function skip(input) {
    if (input.hasAttribute(MARK)) return true;
    if (input.classList.contains('pagefind-ui__search-input')) return true;
    return !!(input.closest && input.closest('#hl-search, .pagefind-ui'));
  }

  function enhance(input) {
    if (skip(input)) return;
    input.setAttribute(MARK, '');
    var doc = input.ownerDocument;
    var nav = input.closest && input.closest('.hl-nav__search');

    var btn = doc.createElement('button');
    btn.type = 'button';
    btn.className = 'hl-clr__btn' + (nav ? ' hl-clr__btn--nav' : '');
    btn.setAttribute('aria-label', 'Clear search');
    btn.innerHTML = X;
    btn.hidden = true;

    var host;
    if (nav) {
      host = nav;
      input.parentNode.insertBefore(btn, input.nextSibling);
    } else {
      host = doc.createElement('span');
      host.className = 'hl-clr';
      input.parentNode.insertBefore(host, input);
      host.appendChild(input);
      host.appendChild(btn);
    }
    input.classList.add('hl-clr__in');

    function sync() {
      var has = input.value !== '';
      btn.hidden = !has;
      host.classList.toggle('is-filled', has);
    }
    function clear() {
      input.value = '';
      sync();
      input.dispatchEvent(new input.ownerDocument.defaultView.Event('input', { bubbles: true }));
      input.focus();
    }

    // Keep focus in the box on press, so the navbar's :focus-within (which shows the button) holds until the click lands.
    btn.addEventListener('mousedown', function (e) { e.preventDefault(); });
    btn.addEventListener('click', clear);
    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && input.value !== '') {
        e.preventDefault();
        e.stopPropagation();
        clear();
      }
    });
    syncers.push(sync);
    sync();
  }

  function scan(root) {
    if (!root || root.nodeType !== 1) return;
    if (root.matches && root.matches(SEL)) enhance(root);
    var list = root.querySelectorAll ? root.querySelectorAll(SEL) : [];
    for (var i = 0; i < list.length; i++) enhance(list[i]);
  }
  function syncAll() { for (var i = 0; i < syncers.length; i++) syncers[i](); }

  function start() {
    scan(document.body);
    if (window.MutationObserver) {
      new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          for (var j = 0; j < muts[i].addedNodes.length; j++) scan(muts[i].addedNodes[j]);
        }
      }).observe(document.body, { childList: true, subtree: true });
    }
    window.addEventListener('load', function () { syncAll(); setTimeout(syncAll, 0); });
    window.addEventListener('pageshow', syncAll);
    window.addEventListener('hashchange', function () { setTimeout(syncAll, 0); });
    document.addEventListener('hl:refilter', syncAll);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
