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
   read as "not in any feed". */
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
     narrowing already says everything. */
  function renderDetail(matched, missed, idx) {
    var rows = matched.slice(0, DETAIL_CAP).map(function (m) {
      var feeds = idx.indicators[m.type + ':' + m.value].map(function (h) {
        return esc((idx.reports[h.report] || {}).title || h.report);
      });
      return '<li class="hl-iocsearch__row hl-iocsearch__row--hit">' +
        '<code>' + esc(m.value) + '</code>' +
        '<span class="hl-iocsearch__in-feed">' + feeds.join(', ') + '</span></li>';
    });
    var more = matched.length > DETAIL_CAP
      ? '<li class="hl-iocsearch__row hl-iocsearch__more">and ' +
        (matched.length - DETAIL_CAP) + ' more matched</li>' : '';
    var none = missed.length
      ? '<li class="hl-iocsearch__row hl-iocsearch__row--miss">' + missed.length +
        ' of your indicators are not in any published feed</li>' : '';
    detail.innerHTML = '<ul class="hl-iocsearch__list">' +
      rows.join('') + more + none + '</ul>';
  }

  function run() {
    var raw = (input.value || '').trim();
    clear.hidden = !raw;
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

      var slugs = {}, matched = [], missed = [];
      found.forEach(function (f) {
        var hits = idx.indicators[f.type + ':' + f.value];
        if (!hits) { missed.push(f); return; }
        matched.push(f);
        hits.forEach(function (h) { slugs[h.report] = 1; });
      });

      if (!matched.length) {
        cards.forEach(function (c) { c.removeAttribute('data-veto'); });
        say(found.length === 1
          ? '<strong>' + esc(found[0].value) + '</strong> does not appear in any published feed.'
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
        say('<strong>' + esc(matched[0].value) + '</strong> appears in ' + n +
            (n === 1 ? ' feed' : ' feeds') + ' below. Open the card to see the full ' +
            'feed and what else it contains.', 'hit');
      } else {
        say('<strong>' + matched.length + ' of your ' + found.length +
            '</strong> indicators appear in ' + n + (n === 1 ? ' feed' : ' feeds') +
            ' below.', 'hit');
        renderDetail(matched, missed, idx);
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
    input.focus();
  });
})();
