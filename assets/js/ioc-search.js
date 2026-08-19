/* Indicator search on /ioc-feeds/.

   The feed cards are already the answer a reader wants, so this does not render
   its own result list. It narrows the existing grid to the feeds containing the
   indicator, and the reader clicks the card they already recognise to go and
   read the whole feed. One surface, not two.

   It cooperates with listing-filter.js rather than fighting it: this sets
   `data-veto` on cards that do not contain the indicator, then fires
   `hl:refilter` so the shared module re-applies. Two scripts both writing
   `style.display` would race.

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
  var cards = [].slice.call(document.querySelectorAll('.hl-catalog-card[data-slug]'));
  var index = null, loading = null, timer = null;

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

  function refilter() {
    document.dispatchEvent(new CustomEvent('hl:refilter'));
  }

  function reset(msg) {
    cards.forEach(function (c) { c.removeAttribute('data-veto'); });
    result.textContent = msg || '';
    result.className = 'hl-iocsearch__result';
    clear.hidden = !(input.value || '').trim();
    refilter();
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function run() {
    var raw = (input.value || '').trim();
    clear.hidden = !raw;
    if (!raw) { reset(''); return; }

    load().then(function (idx) {
      var found = C.extract(raw);
      if (!found.length) {
        reset('');
        result.textContent = 'That does not look like an IP, domain, URL or hash.';
        result.className = 'hl-iocsearch__result hl-iocsearch__result--none';
        return;
      }

      // Union across everything pasted, so a small list works as well as one value.
      var slugs = {}, matched = [];
      found.forEach(function (f) {
        var hits = idx.indicators[f.type + ':' + f.value];
        if (!hits) return;
        matched.push(f);
        hits.forEach(function (h) { slugs[h.report] = 1; });
      });

      if (!matched.length) {
        cards.forEach(function (c) { c.removeAttribute('data-veto'); });
        result.innerHTML = found.length === 1
          ? '<strong>' + esc(found[0].value) + '</strong> does not appear in any published feed.'
          : 'None of the ' + found.length + ' indicators appear in any published feed.';
        result.className = 'hl-iocsearch__result hl-iocsearch__result--none';
        refilter();
        return;
      }

      var n = Object.keys(slugs).length;
      cards.forEach(function (c) {
        if (slugs[c.getAttribute('data-slug')]) c.removeAttribute('data-veto');
        else c.setAttribute('data-veto', '1');
      });

      var lead = matched.length === 1
        ? '<strong>' + esc(matched[0].value) + '</strong> appears in '
        : matched.length + ' of your ' + found.length + ' indicators appear in ';
      result.innerHTML = lead + n + (n === 1 ? ' feed' : ' feeds') +
        ' below. Open the card to see the full feed and what else it contains.';
      result.className = 'hl-iocsearch__result hl-iocsearch__result--hit';
      refilter();
    })['catch'](function (e) {
      result.textContent = 'Could not load the indicator index (' + e.message + ').';
      result.className = 'hl-iocsearch__result hl-iocsearch__result--none';
    });
  }

  input.addEventListener('input', function () {
    clearTimeout(timer);
    timer = setTimeout(run, 180);
  });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { clearTimeout(timer); run(); }
  });
  clear.addEventListener('click', function () {
    input.value = '';
    reset('');
    input.focus();
  });
})();
