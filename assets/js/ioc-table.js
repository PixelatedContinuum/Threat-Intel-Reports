/* IOC feed viewer: filter by type, copy or download what is shown.

   The table is rendered at build time by _layouts/ioc-table.html from
   _data/ioc_tables.yml, so it is complete and readable before this file runs.
   Everything here is additive; with JS off the reader still gets every indicator.

   The one invariant worth naming: WHAT YOU COPY IS WHAT YOU SEE. Every export
   path reads the same visible-row set the filter produced, never the original
   data, because a filtered table that exports the unfiltered set would hand a
   defender a block list they did not ask for and would not notice was wrong.

   THE PAGE NEVER SHOWS OR COPIES A LIVE INDICATOR (T-0500.1.7.4 fix-r1, review finding 2;
   Joseph, 2026-11-02, decision 5: "I do not want to risk people clicking on something or
   accidentally pasting it in the wrong way"). Until this change a Defanged/Live button put
   the live values on screen and "Copy shown" copied them. That control is gone, and so is
   the live value it kept in an attribute on every cell: the layout prints every network row
   defanged (_includes/ioc-cell.html), and copy, .txt and .csv read that display, defanged
   once more on the way out (idempotent) so a layout regression could not put a live value
   on the clipboard. The exact values are in the raw JSON feed linked above the table,
   which is unchanged and is what a blocklist should be built from.

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

  /* The export-side guard. The layout has already printed these rows defanged, so for
     those this returns the text it was given; it exists so that the layout is not the
     only thing between a live value and the clipboard. A value that is already defanged
     is put back to plain first, so the result is the same either way. */
  function defang(value, type) {
    var s = String(value).replace(/\[\.\]/g, '.').replace(/\[@\]/g, '@').replace(/\[:\]/g, ':').replace(/\b(h)xx(ps?:\/\/)/gi, '$1tt$2');
    if (type === 'url') s = s.replace(/https?:\/\//gi, function (m) { return m.replace(/tt/i, 'xx'); }); /* every scheme, a URL inside a path included */
    if (type === 'email') s = s.replace(/@/g, '[@]');
    /* IPv6 (fix-r2, review finding S3): the refang above put every [:] back to a colon, so the colons of an address are defanged again here, the form the layout prints
       ("2001[:]db8[:][:]7"). A bare ipv6 value loses all its colons; a bracketed literal ("[2001:db8::7]:443", also inside a url or endpoint) loses the ones inside the brackets and
       keeps the port's. Same rule as HLIocClassify.defangValue (ioc-classify.js), which a test holds equal. */
    if (type === 'ipv6' && s.indexOf('[') === -1) s = s.replace(/:/g, '[:]');
    else s = s.replace(/\[([0-9a-f:.]*:[0-9a-f:.]*)\]/gi, function (m, a) { return '[' + a.replace(/:/g, '[:]') + ']'; });
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

    /* What is on screen, defanged once more for a network row (see defang() above). */
    function valueOf(tr) {
      var c = tr.querySelector('code');
      if (!c) return '';
      var type = tr.getAttribute('data-type');
      return DEFANG_TYPES[type] ? defang(c.textContent, type) : c.textContent;
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
      }
    });

    apply();
  }

  ready(init);
}());
