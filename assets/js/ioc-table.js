/* IOC feed viewer: filter by type, copy or download what is shown.

   The table is rendered at build time by _layouts/ioc-table.html from
   _data/ioc_tables.yml, so it is complete and readable before this file runs.
   Everything here is additive; with JS off the reader still gets every indicator.

   The one invariant worth naming: WHAT YOU COPY IS WHAT YOU SEE. Every export
   path reads the same visible-row set the filter produced, never the original
   data, because a filtered table that exports the unfiltered set would hand a
   defender a block list they did not ask for and would not notice was wrong.

   Zero chips pressed means NO FILTER, never "match nothing". An empty table that
   looks like a filter result is worse than either. */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else { fn(); }
  }

  function init() {
    var root = document.querySelector('.hl-ioctable');
    if (!root) return;

    var rows = Array.prototype.slice.call(
      root.querySelectorAll('.hl-ioctable__table tbody tr'));
    var chips = Array.prototype.slice.call(root.querySelectorAll('.hl-ioctable__chip'));
    var countEl = root.querySelector('.hl-ioctable__count');
    var clearEl = root.querySelector('.hl-ioctable__clear');
    var slug = root.getAttribute('data-slug') || 'indicators';

    var active = {};

    function activeCount() { return Object.keys(active).length; }

    function shown() {
      return rows.filter(function (tr) { return !tr.hasAttribute('hidden'); });
    }

    function apply() {
      var any = activeCount() > 0;
      rows.forEach(function (tr) {
        var on = !any || active[tr.getAttribute('data-type')];
        if (on) tr.removeAttribute('hidden');
        else tr.setAttribute('hidden', '');
      });
      var n = shown().length;
      if (countEl) {
        countEl.textContent = n + ' shown' +
          (any ? ' of ' + rows.length : '');
      }
      /* Hidden when there is nothing to clear, matching the indicator search's
         own clear control. A button offering to undo a filter that is not
         applied is worse than no button. */
      if (clearEl) clearEl.hidden = !any;
    }

    /* Clearing must unpress every chip as well as unhiding every row. A chip
       left reading pressed over an unfiltered table would make the next click
       FILTER rather than unfilter, which is the opposite of what it looks like
       it would do. */
    function clearAll() {
      active = {};
      chips.forEach(function (c) { c.setAttribute('aria-pressed', 'false'); });
      apply();
    }

    if (clearEl) clearEl.addEventListener('click', clearAll);

    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        var t = chip.getAttribute('data-type');
        if (active[t]) { delete active[t]; chip.setAttribute('aria-pressed', 'false'); }
        else { active[t] = true; chip.setAttribute('aria-pressed', 'true'); }
        apply();
      });
    });

    function valueOf(tr) {
      var c = tr.querySelector('code');
      return c ? c.textContent : '';
    }

    function txt() {
      return shown().map(valueOf).join('\n');
    }

    /* RFC 4180: a field containing a comma, a quote or a newline is quoted, and
       an embedded quote is doubled. Getting this wrong corrupts the row rather
       than failing, which is why it is tested rather than eyeballed. */
    function csvField(s) {
      var v = s == null ? '' : String(s);
      return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }

    function csv() {
      var out = ['value,type,context'];
      shown().forEach(function (tr) {
        out.push([csvField(valueOf(tr)),
                  csvField(tr.getAttribute('data-type') || ''),
                  csvField(tr.getAttribute('data-context') || '')].join(','));
      });
      return out.join('\n');
    }

    function download(text, name, mime) {
      // Exposed for the test suite, which has no real download to observe.
      window.__lastDownloadText = text;
      window.__lastDownloadName = name;
      try {
        var blob = new Blob([text], { type: mime + ';charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 0);
      } catch (e) { /* a blocked download is not worth breaking the page over */ }
    }

    function flash(btn, msg) {
      var was = btn.textContent;
      btn.textContent = msg;
      setTimeout(function () { btn.textContent = was; }, 1400);
    }

    root.addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('.hl-ioctable__btn') : null;
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      if (act === 'copy') {
        var text = txt();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            flash(btn, 'Copied ' + shown().length);
          }, function () { flash(btn, 'Copy failed'); });
        } else { flash(btn, 'Copy unavailable'); }
      } else if (act === 'txt') {
        download(txt(), slug + '-indicators.txt', 'text/plain');
      } else if (act === 'csv') {
        download(csv(), slug + '-indicators.csv', 'text/csv');
      }
    });

    apply();
  }

  ready(init);
}());
