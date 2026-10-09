/* IOC feed viewer: filter by type, defang, copy or download what is shown.

   The table is rendered at build time by _layouts/ioc-table.html from
   _data/ioc_tables.yml, so it is complete and readable before this file runs.
   Everything here is additive; with JS off the reader still gets every indicator.

   The one invariant worth naming: WHAT YOU COPY IS WHAT YOU SEE. Every export
   path reads the same visible-row set the filter produced, never the original
   data, because a filtered table that exports the unfiltered set would hand a
   defender a block list they did not ask for and would not notice was wrong.
   The defang toggle (2026-10-09) rides on the same rule: it rewrites the
   DISPLAYED value, and copy, .txt and .csv read the display, so a defanged
   table exports defanged values and a live one exports live values. The live
   value is kept on the <code> element's data-live attribute so switching the
   toggle off restores it byte for byte rather than re-deriving it.

   Zero chips pressed means NO FILTER, never "match nothing". An empty table that
   looks like a filter result is worse than either. */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else { fn(); }
  }

  /* The types whose value is a network locator and so becomes a live link or a
     resolvable name when pasted. Hashes, paths, filenames, registry keys and
     mutexes are left exactly as they are: there is nothing in them to disarm,
     and a bracket inserted into a path would break the string a hunter pastes.
     ipv6 is listed although the extractor does not emit it today, so a feed
     that gains the type is defanged rather than silently passed through. */
  var DEFANG_TYPES = { ipv4: true, ipv6: true, domain: true, endpoint: true,
                       url: true, email: true };

  function defang(value, type) {
    var s = value;
    if (type === 'url') s = s.replace(/^http(s?)/i, 'hxxp$1');
    if (type === 'email') s = s.replace(/@/g, '[@]');
    return s.replace(/\./g, '[.]');
  }

  function init() {
    var root = document.querySelector('.hl-ioctable');
    if (!root) return;

    var rows = Array.prototype.slice.call(
      root.querySelectorAll('.hl-ioctable__table tbody tr'));
    var chips = Array.prototype.slice.call(root.querySelectorAll('.hl-ioctable__chip'));
    var countEl = root.querySelector('.hl-ioctable__count');
    var clearEl = root.querySelector('.hl-ioctable__clear');
    var defangEl = root.querySelector('.hl-ioctable__btn[data-act="defang"]');
    var slug = root.getAttribute('data-slug') || 'indicators';

    /* Which optional columns this feed's table carries, set by the layout from
       the manifest's has_* flags. The CSV follows the table: a column that is
       not on screen is not in the file, so the header never promises a field
       the feed never recorded. */
    function flag(name) { return root.getAttribute(name) === 'true'; }
    var hasConfidence = flag('data-has-confidence');
    var hasAction = flag('data-has-action');
    var hasFp = flag('data-has-fp-risk');

    var active = {};
    var defanged = false;

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

    /* The live value is recorded once, up front, on EVERY row's <code>, before
       any rewrite can happen. Restoring then reads that attribute rather than
       undoing the substitution, so a value that already carried a bracket or an
       hxxp of its own comes back exactly as the feed recorded it. Hidden rows
       are rewritten too: a row the filter later reveals must already match the
       toggle's state, not the state it had when it was hidden. Only the
       ordinary table's rows are in `rows`; the never-block table is a different
       element the selector above never finds, so the toggle cannot reach it. */
    rows.forEach(function (tr) {
      var c = tr.querySelector('code');
      if (c && !c.hasAttribute('data-live')) c.setAttribute('data-live', c.textContent);
    });

    function applyDefang() {
      rows.forEach(function (tr) {
        var c = tr.querySelector('code');
        if (!c) return;
        var live = c.getAttribute('data-live');
        if (live == null) return;
        var type = tr.getAttribute('data-type');
        c.textContent = (defanged && DEFANG_TYPES[type]) ? defang(live, type) : live;
      });
      if (defangEl) {
        defangEl.setAttribute('aria-pressed', defanged ? 'true' : 'false');
        defangEl.textContent = defanged ? 'Defanged' : 'Defang';
      }
    }

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
      var header = ['value', 'type', 'context'];
      if (hasConfidence) header.push('confidence');
      if (hasAction) header.push('action');
      if (hasFp) header.push('fp_risk');
      var out = [header.join(',')];
      shown().forEach(function (tr) {
        var cells = [csvField(valueOf(tr)),
                     csvField(tr.getAttribute('data-type') || ''),
                     csvField(tr.getAttribute('data-context') || '')];
        if (hasConfidence) cells.push(csvField(tr.getAttribute('data-confidence') || ''));
        if (hasAction) cells.push(csvField(tr.getAttribute('data-action') || ''));
        if (hasFp) cells.push(csvField(tr.getAttribute('data-fp') || ''));
        out.push(cells.join(','));
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
      } else if (act === 'defang') {
        defanged = !defanged;
        applyDefang();
      }
    });

    apply();
  }

  ready(init);
}());
