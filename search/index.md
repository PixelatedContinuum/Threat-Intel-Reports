---
title: Search
layout: page
permalink: /search/
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

    // Colour each result by the section its URL belongs to, the same palette the
    // listing cards use, and prepend a section chip. Pagefind renders results
    // itself, so this watches the mount and decorates each new result once.
    var SECTIONS = [
      ['/reports/',            'reports',    'Report'],
      ['/hunting-detections/', 'detections', 'Detection Rules'],
      ['/ioc-feeds/',          'ioc',        'IOC Feed'],
      ['/stix/',               'stix',       'STIX'],
      ['/wire/',               'wire',       'The Wire'],
      ['/behind-the-reports/', 'behind',     'Behind the Reports']
    ];
    function decorate(li) {
      if (li.getAttribute('data-hl-section')) return;
      var a = li.querySelector('.pagefind-ui__result-link');
      // The observer can see the <li> before Pagefind has filled it; leave it
      // unmarked so the next mutation, with the link present, decorates it.
      if (!a) return;
      var href = a.getAttribute('href') || '';
      var key = 'pages', label = 'Page';
      for (var i = 0; i < SECTIONS.length; i++) {
        if (href.indexOf(base + SECTIONS[i][0]) === 0) { key = SECTIONS[i][1]; label = SECTIONS[i][2]; break; }
      }
      li.setAttribute('data-hl-section', key);
      li.classList.add('hl-sr', 'hl-sr--' + key);
      var title = li.querySelector('.pagefind-ui__result-inner > .pagefind-ui__result-title');
      if (title) {
        var chip = document.createElement('span');
        chip.className = 'hl-sr__chip';
        chip.textContent = label;
        title.parentNode.insertBefore(chip, title);
      }
    }
    // On a phone the open filter panel pushes the first result below the fold,
    // so it starts collapsed there; one tap opens it. Done once per render.
    var narrow = window.matchMedia && window.matchMedia('(max-width: 640px)').matches;
    function collapseFilters() {
      if (!narrow) return;
      var blocks = mount.querySelectorAll('details.pagefind-ui__filter-block:not([data-hl-collapsed])');
      for (var i = 0; i < blocks.length; i++) { blocks[i].open = false; blocks[i].setAttribute('data-hl-collapsed', '1'); }
    }
    if (mount && window.MutationObserver) {
      var mo = new MutationObserver(function () {
        collapseFilters();
        var items = mount.querySelectorAll('.pagefind-ui__result');
        for (var i = 0; i < items.length; i++) decorate(items[i]);
      });
      mo.observe(mount, { childList: true, subtree: true });
    }
  };
  document.head.appendChild(s);
})();
</script>
