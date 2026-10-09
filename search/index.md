---
title: Search
layout: page
permalink: /search/
position: 4.8
nav_title: Search
description: "Full-text search across every published report, detection page, IOC feed and STIX bundle on The Hunter's Ledger."
---

<div class="hl-page-header" style="--ph-accent: #58a6ff;">
  <div class="hl-page-header__label">Search</div>
  <div class="hl-page-header__title">Search the Ledger</div>
  <div class="hl-page-header__desc">Full-text search across every published report, detection page, IOC feed and STIX bundle. Type an indicator, a technique, a tool name or a phrase; filter by section on the left.</div>
</div>

{%- comment -%}
  The index (/pagefind/) is produced by Pagefind in the deploy workflow, after
  the Jekyll build and before the artifact upload. It does not exist in a local
  `jekyll build`, so the script's onerror shows a plain notice instead of an
  empty box. ?q= in the URL seeds the query and is kept in step with the input
  (replaceState, no history entries), so a result page can be shared or
  bookmarked.
{%- endcomment -%}
<link rel="stylesheet" href="{{ '/pagefind/pagefind-ui.css' | relative_url }}">
<div id="hl-search" class="hl-search"></div>
<p id="hl-search-notice" class="hl-search__notice" hidden></p>
<script>
(function () {
  var mount = document.getElementById('hl-search');
  var notice = document.getElementById('hl-search-notice');
  var base = '{{ site.baseurl }}';

  function say(text) {
    if (!notice) return;
    notice.textContent = text;
    notice.hidden = false;
  }

  function queryFromUrl() {
    try {
      var q = new URLSearchParams(window.location.search).get('q');
      return q ? q.trim() : '';
    } catch (e) { return ''; }
  }

  function syncUrl(q) {
    try {
      var url = new URL(window.location.href);
      if (q) url.searchParams.set('q', q); else url.searchParams.delete('q');
      window.history.replaceState(null, '', url.toString());
    } catch (e) { /* URL API missing: the search still works, the address bar just does not follow it */ }
  }

  var s = document.createElement('script');
  s.src = base + '/pagefind/pagefind-ui.js';
  s.onerror = function () {
    say('The search index is built when the site deploys; it is not available in a local preview.');
  };
  s.onload = function () {
    if (typeof PagefindUI === 'undefined') { s.onerror(); return; }
    var initial = queryFromUrl();
    var ui = new PagefindUI({
      element: '#hl-search',
      showSubResults: true,
      showImages: false,
      excerptLength: 30,
      resetStyles: false,
      translations: {
        placeholder: 'Search reports, detections, IOCs, STIX…',
        clear_search: 'Clear',
        load_more: 'Load more results',
        search_label: 'Search the site',
        filters_label: 'Sections',
        zero_results: 'No results for [SEARCH_TERM]',
        many_results: '[COUNT] results for [SEARCH_TERM]',
        one_result: '[COUNT] result for [SEARCH_TERM]',
        alt_search: 'No results for [SEARCH_TERM]. Showing results for [DIFFERENT_TERM] instead',
        search_suggestion: 'No results for [SEARCH_TERM]. Try one of the following searches:',
        searching: 'Searching for [SEARCH_TERM]…'
      }
    });
    // Keep ?q= in step with the box so a result page can be shared. Delegated
    // on the mount, so it does not matter when the UI renders its input.
    function currentTerm() {
      var input = mount ? mount.querySelector('input.pagefind-ui__search-input') : null;
      return input ? input.value.trim() : '';
    }
    if (mount) {
      mount.addEventListener('input', function () { syncUrl(currentTerm()); });
      mount.addEventListener('click', function (ev) {
        var t = ev.target;
        if (t && t.closest && t.closest('.pagefind-ui__search-clear')) {
          setTimeout(function () { syncUrl(currentTerm()); }, 0);
        }
      });
    }
    if (initial && typeof ui.triggerSearch === 'function') ui.triggerSearch(initial);
  };
  document.head.appendChild(s);
})();
</script>
