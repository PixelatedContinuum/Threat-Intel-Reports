/* ============================================================
   hl-process-tree
   Vanilla enhancement for the HTML process-tree component.
   No dependency, no build step, safe to load with `defer`.

   Everything here is an ENHANCEMENT. With scripting off the tree
   still renders as a nested list of native <details> nodes that
   open and close on their own, so nothing below is load-bearing
   for reading the content.

   It adds exactly three things:
     1. expand all / collapse all
     2. copy-to-clipboard on every literal
     3. deep links, so a report can point at one process
   ============================================================ */
(function () {
  'use strict';

  var roots = document.querySelectorAll('[data-hl-ptree]');
  if (!roots.length) return;

  Array.prototype.forEach.call(roots, function (root) {
    root.classList.add('pt-has-js');

    /* --- a polite announcement channel for copy results ------ */
    var status = root.querySelector('.pt-status');
    if (!status) {
      status = document.createElement('div');
      status.className = 'pt-status';
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      root.appendChild(status);
    }
    var announceTimer = null;
    function announce(msg) {
      status.textContent = msg;
      clearTimeout(announceTimer);
      announceTimer = setTimeout(function () { status.textContent = ''; }, 4000);
    }

    /* --- 1. expand all / collapse all ------------------------ */
    var nodes = function () { return root.querySelectorAll('details.hl-ptree-node'); };

    function setAll(open) {
      Array.prototype.forEach.call(nodes(), function (d) { d.open = open; });
      announce(open
        ? 'All ' + nodes().length + ' nodes expanded. Browser find will now reach every command line and hash.'
        : 'All nodes collapsed.');
    }

    root.addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('[data-pt]') : null;
      if (!btn || !root.contains(btn)) return;
      var action = btn.getAttribute('data-pt');
      if (action === 'expand') setAll(true);
      else if (action === 'collapse') setAll(false);
    });

    /* --- 2. copy to clipboard on every literal ---------------- */
    function copyText(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      /* file:// and older browsers are not a secure context, so fall back */
      return new Promise(function (resolve, reject) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('copy unavailable'));
      });
    }

    Array.prototype.forEach.call(root.querySelectorAll('.pt-fact'), function (fact) {
      var val = fact.querySelector('.pt-fact-val');
      var key = fact.querySelector('.pt-fact-key');
      if (!val || fact.querySelector('.pt-copy')) return;

      var label = key ? key.textContent.trim().toLowerCase() : 'value';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'pt-copy js-only';
      btn.textContent = 'copy';
      btn.setAttribute('aria-label', 'Copy the ' + label);

      btn.addEventListener('click', function () {
        copyText(val.textContent.replace(/\s+$/, '')).then(function () {
          btn.textContent = 'copied';
          announce(label + ' copied to the clipboard.');
          setTimeout(function () { btn.textContent = 'copy'; }, 1600);
        }, function () {
          btn.textContent = 'select it';
          announce('The browser refused clipboard access here. The text is selectable.');
          var r = document.createRange();
          r.selectNodeContents(val);
          var sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(r);
          setTimeout(function () { btn.textContent = 'copy'; }, 2600);
        });
      });

      fact.appendChild(btn);
    });

    /* --- 3. deep links ---------------------------------------- */
    function openTo(el) {
      /* open the node itself and every <details> above it */
      var d = el;
      while (d) {
        if (d.tagName === 'DETAILS') d.open = true;
        d = d.parentElement ? d.parentElement.closest('details') : null;
      }
    }

    function revealFromHash() {
      var id = (location.hash || '').slice(1);
      if (!id) {
        /* the hash was cleared, so drop the marker with it rather than leaving
           a node outlined as "linked" when nothing links to it any more */
        Array.prototype.forEach.call(nodes(), function (d) { d.classList.remove('is-linked'); });
        return;
      }
      var target = root.querySelector('#' + (window.CSS && CSS.escape ? CSS.escape(id) : id));
      if (!target || !target.classList.contains('hl-ptree-node')) return;

      Array.prototype.forEach.call(nodes(), function (d) { d.classList.remove('is-linked'); });
      openTo(target);
      target.classList.add('is-linked');

      var summary = target.querySelector('summary');
      if (summary) {
        summary.setAttribute('tabindex', '-1');
        summary.focus({ preventScroll: true });
      }
      target.scrollIntoView({ block: 'center', behavior: 'auto' });
      announce('Jumped to ' + (summary ? summary.textContent.trim().split('\n')[0] : id) + '.');
    }

    window.addEventListener('hashchange', revealFromHash);
    /* run once on load, after layout has settled */
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', revealFromHash);
    } else {
      revealFromHash();
    }
  });
})();
