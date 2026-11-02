/* Indicator search on /ioc-feeds/.

   The feed cards are already the answer for a single indicator, so this narrows
   the existing grid rather than rendering a parallel result list, and the reader
   clicks the card they already recognise.

   A LIST is different. Narrowing 54 cards to 21 tells someone who pasted 40
   indicators almost nothing: they need to know WHICH of theirs matched and which
   did not. So above one indicator, a compact per-indicator breakdown appears
   alongside the narrowing.

   It cooperates with listing-filter.js rather than fighting it: this sets
   `data-veto` on cards that do not contain any pasted indicator, then fires
   `hl:refilter` so the shared module re-applies. Two scripts both writing
   `style.display` would race.

   The input is a TEXTAREA, not an input. `<input type="text">` silently strips
   newlines from pasted content, which collapsed a pasted list into one giant
   string; that string once ended in `.test` and was classified as a single
   domain. Newline-separated is how most people paste a list.

   Matching goes through the SAME ioc-classify.js the index generator used. If
   this normalised differently, every search would quietly return nothing and
   read as "not in any feed".

   WHAT IS DISPLAYED IS DEFANGED (T-0500.1.7.4 fix-r1, review finding 1; Joseph, 2026-11-02, decision 5). Matching uses the refanged value, as before; the result
   sentence, the per-indicator breakdown, the report titles read from the index and the query box filled from a ?q= link all go through
   HLIocClassify.defangValue / defangText, so no network indicator this script writes is live. A raw query the reader types stays as typed in their own box. */
(function () {
  'use strict';
  var root = document.querySelector('.hl-iocsearch');
  if (!root || !window.HLIocClassify) return;

  var C = window.HLIocClassify;
  var input = root.querySelector('.hl-iocsearch__in');
  var clear = root.querySelector('.hl-iocsearch__clear');
  var result = root.querySelector('.hl-iocsearch__result');
  var detail = root.querySelector('.hl-iocsearch__detail');
  var cards = [].slice.call(document.querySelectorAll('.hl-catalog-card[data-slug]'));
  var index = null, loading = null, timer = null;

  /* The breakdown scrolls inside a fixed box, so this cap is only a guard
     against a pathological paste building tens of thousands of DOM rows. The
     card narrowing always covers every match regardless of this. */
  var DETAIL_CAP = 200;

  function load() {
    if (index) return Promise.resolve(index);
    if (loading) return loading;
    loading = fetch('/assets/data/ioc-index.json', { credentials: 'omit' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      }).then(function (j) { index = j; return j; });
    return loading;
  }

  function refilter() { document.dispatchEvent(new CustomEvent('hl:refilter')); }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  /* Everything the script puts on the page goes through one of these two: a classified value by its type, a title (free text) as text. */
  function shownValue(f) { return esc(C.defangValue(f.value, f.type)); }
  function shownTitle(report) { return esc(C.defangText(report)); }

  function clearAll(msg) {
    cards.forEach(function (c) { c.removeAttribute('data-veto'); });
    result.textContent = msg || '';
    result.className = 'hl-iocsearch__result';
    detail.innerHTML = '';
    clear.hidden = !(input.value || '').trim();
    refilter();
  }

  function say(html, kind) {
    result.innerHTML = html;
    result.className = 'hl-iocsearch__result hl-iocsearch__result--' + kind;
  }

  /* Per-indicator breakdown, shown only for a list. For one indicator the card
     narrowing already says everything.

     `withheld` (2026-09-13): indicators that ARE recorded against a feed but sit
     in that feed's `hunt_only_never_block` bucket, so this index deliberately
     does not carry them as an ordinary key. Without this bucket a withheld
     value would silently join `missed` and read as "we have no data", which is
     the exact "empty result is not an absence" failure this project keeps
     writing down: the reader cannot tell absence from a deliberate exclusion. */
  function renderDetail(matched, withheld, missed, idx) {
    var rows = matched.slice(0, DETAIL_CAP).map(function (m) {
      var feeds = idx.indicators[m.type + ':' + m.value].map(function (h) {
        return shownTitle((idx.reports[h.report] || {}).title || h.report);
      });
      return '<li class="hl-iocsearch__row hl-iocsearch__row--hit">' +
        '<code>' + shownValue(m) + '</code>' +
        '<span class="hl-iocsearch__in-feed">' + feeds.join(', ') + '</span></li>';
    });
    var withheldRows = withheld.slice(0, DETAIL_CAP).map(function (w) {
      var feeds = ((idx.never_block || {})[w.type + ':' + w.value] || []).map(function (h) {
        return shownTitle((idx.reports[h.report] || {}).title || h.report);
      });
      return '<li class="hl-iocsearch__row hl-iocsearch__row--withheld">' +
        '<code>' + shownValue(w) + '</code>' +
        '<span class="hl-iocsearch__in-feed">intentionally excluded, see ' +
        feeds.join(', ') + '</span></li>';
    });
    var more = matched.length > DETAIL_CAP
      ? '<li class="hl-iocsearch__row hl-iocsearch__more">and ' +
        (matched.length - DETAIL_CAP) + ' more matched</li>' : '';
    var moreW = withheld.length > DETAIL_CAP
      ? '<li class="hl-iocsearch__row hl-iocsearch__more">and ' +
        (withheld.length - DETAIL_CAP) + ' more intentionally excluded</li>' : '';
    var none = missed.length
      ? '<li class="hl-iocsearch__row hl-iocsearch__row--miss">' + missed.length +
        ' of your indicators are not in any published feed</li>' : '';
    detail.innerHTML = '<ul class="hl-iocsearch__list">' +
      rows.join('') + more + withheldRows.join('') + moreW + none + '</ul>';
  }

  /* --- URL state: ?q= ---------------------------------------------------------

     A tool or a person can deep-link an indicator, or a short list, as
     /ioc-feeds/?q=<indicator>, and the page lands with the search already run.
     The QUERY STRING, not the hash: listing-filter.js owns the hash (its own
     `q=` there is the card-title filter) and it preserves location.search
     when it writes, so the two never overwrite each other. The box is mirrored
     back into ?q= as the reader types (replaceState, never pushState, for the
     same reason the filter gives: a history entry per keystroke would make the
     back button walk through the typing) and the parameter is dropped when the
     box is empty, so the URL in the bar is always the one to copy. Several
     values travel comma- or newline-separated; the classifier splits on both. */
  var hasHistory = !!(window.history && window.history.replaceState);

  function readQuery() {
    var m = /[?&]q=([^&#]*)/.exec(String(window.location.search || ''));
    if (!m) return '';
    // A hand-edited `%` the browser cannot decode reads as nothing, not a throw.
    try { return decodeURIComponent(m[1].replace(/\+/g, ' ')); } catch (e) { return ''; }
  }

  function writeQuery() {
    if (!hasHistory) return;
    var loc = window.location;
    var term = (input.value || '').trim();
    var keep = String(loc.search || '').replace(/^\?/, '').split('&')
      .filter(function (part) { return part && part.indexOf('q=') !== 0; });
    if (term) keep.push('q=' + encodeURIComponent(term));
    var want = loc.pathname + (keep.length ? '?' + keep.join('&') : '') + loc.hash;
    if (want === loc.pathname + loc.search + loc.hash) return;
    // A URL the history API refuses (file://, a sandboxed frame) must not stop
    // the search itself working; the link is a convenience on top of it.
    try { window.history.replaceState(null, '', want); } catch (e) { /* see above */ }
  }

  function run() {
    var raw = (input.value || '').trim();
    clear.hidden = !raw;
    writeQuery();
    if (!raw) { clearAll(''); return; }

    load().then(function (idx) {
      var found = C.extract(raw);
      detail.innerHTML = '';

      if (!found.length) {
        cards.forEach(function (c) { c.removeAttribute('data-veto'); });
        say('Nothing in that text looks like an IP, domain, URL or hash.', 'none');
        refilter();
        return;
      }

      /* `withheld`: recorded against a feed, but sitting in that feed's
         hunt_only_never_block bucket (2026-09-13). Kept apart from `missed` so
         "not in any feed" and "deliberately not listed" never look the same;
         see the header comment on renderDetail(). */
      var slugs = {}, matched = [], withheld = [], missed = [];
      found.forEach(function (f) {
        var key = f.type + ':' + f.value;
        var hits = idx.indicators[key];
        if (hits) {
          matched.push(f);
          hits.forEach(function (h) { slugs[h.report] = 1; });
          return;
        }
        var nb = idx.never_block && idx.never_block[key];
        if (nb) {
          withheld.push(f);
          nb.forEach(function (h) { slugs[h.report] = 1; });
          return;
        }
        missed.push(f);
      });

      if (!matched.length && !withheld.length) {
        cards.forEach(function (c) { c.removeAttribute('data-veto'); });
        say(found.length === 1
          ? '<strong>' + shownValue(found[0]) + '</strong> does not appear in any published feed.'
          : 'None of your ' + found.length + ' indicators appear in any published feed.',
          'none');
        refilter();
        return;
      }

      var n = Object.keys(slugs).length;
      cards.forEach(function (c) {
        if (slugs[c.getAttribute('data-slug')]) c.removeAttribute('data-veto');
        else c.setAttribute('data-veto', '1');
      });

      if (found.length === 1) {
        if (matched.length) {
          say('<strong>' + shownValue(matched[0]) + '</strong> appears in ' + n +
              (n === 1 ? ' feed' : ' feeds') + ' below. Open the card to see the full ' +
              'feed and what else it contains.', 'hit');
        } else {
          say('<strong>' + shownValue(withheld[0]) + '</strong> is recorded in ' + n +
              (n === 1 ? ' feed' : ' feeds') + ' below, but is deliberately left out ' +
              'of this index, because blocking it would affect something legitimate. ' +
              'Open the card to see why.', 'withheld');
        }
      } else {
        var bits = [];
        if (matched.length) {
          bits.push('<strong>' + matched.length + ' of your ' + found.length +
            '</strong> indicators appear in ' + n + (n === 1 ? ' feed' : ' feeds') +
            ' below.');
        } else {
          bits.push('None of your ' + found.length + ' indicators appear as an ' +
            'ordinary indicator in any published feed.');
        }
        if (withheld.length) {
          bits.push(withheld.length + ' ' + (withheld.length === 1 ? 'is' : 'are') +
            ' intentionally left out of this index (blocking would affect ' +
            'something legitimate) but still shown below.');
        }
        say(bits.join(' '), (withheld.length && !matched.length) ? 'withheld' : 'hit');
        renderDetail(matched, withheld, missed, idx);
      }
      refilter();
    })['catch'](function (e) {
      say('Could not load the indicator index (' + e.message + ').', 'none');
    });
  }

  /* The box never resizes itself. Paste a thousand indicators and it stays the
     same height, scrolling internally: you cannot see the whole list, but the
     page below never moves and the search still works on all of it. */
  input.addEventListener('input', function () {
    clearTimeout(timer);
    timer = setTimeout(run, 200);
  });
  // A textarea takes Enter as a newline, which a pasted list needs, so the
  // explicit trigger is the modifier chord.
  input.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { clearTimeout(timer); run(); }
  });
  clear.addEventListener('click', function () {
    input.value = '';
    clearAll('');
    writeQuery();
    input.focus();
  });

  // A shared link lands searched rather than showing the full grid first.
  var linked = readQuery();
  // The box is filled with the DEFANGED form: the matching refangs it again, and a link that carries a live indicator does not put it on the page.
  if (linked) { input.value = C.defangText(linked); run(); }
})();
