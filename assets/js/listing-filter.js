(function () {
  var bar = document.querySelector('[data-listing-filter]');
  var grid = document.querySelector('[data-filter-grid]');
  if (!bar || !grid) return;
  var cards = [].slice.call(grid.querySelectorAll('.hl-catalog-card'));
  var clusters = [].slice.call(grid.querySelectorAll('[data-series-cluster]'));
  var search = bar.querySelector('.hl-filter__search');
  var chips = [].slice.call(bar.querySelectorAll('.hl-chip-btn'));
  var count = bar.querySelector('[data-filter-count]');
  var empty = bar.querySelector('[data-filter-empty]');
  var allChip = bar.querySelector('.hl-chip-btn[data-tag=""]');
  var active = {};
  function activeTags() { return Object.keys(active); }
  function apply() {
    var term = (search && search.value || '').trim().toLowerCase();
    var tags = activeTags();
    var shown = 0;
    cards.forEach(function (c) {
      var ctags = (c.getAttribute('data-tags') || '').split('|');
      var mt = tags.length === 0 || tags.some(function (t) { return ctags.indexOf(t) > -1; });
      // Search matches BOTH the title and the tags, so e.g. "ransomware"
      // surfaces items tagged Ransomware even if it's not in the title.
      var hay = (c.getAttribute('data-title') || '') + '|' + (c.getAttribute('data-tags') || '');
      var mq = !term || hay.indexOf(term) > -1;
      var vis = mt && mq;
      // .hl-card carries `display: block !important`, so a plain inline
      // `display:none` is overridden. Set/remove with `important` priority,
      // which sits above author !important in the cascade.
      if (vis) { c.style.removeProperty('display'); }
      else { c.style.setProperty('display', 'none', 'important'); }
      if (vis) shown++;
    });
    // A series cluster is a shell around its member cards — hide the shell
    // (header + box) when the filter has hidden every card inside it.
    clusters.forEach(function (cl) {
      var kids = [].slice.call(cl.querySelectorAll('.hl-catalog-card'));
      var any = kids.some(function (k) { return k.style.display !== 'none'; });
      if (any) { cl.style.removeProperty('display'); }
      else { cl.style.setProperty('display', 'none', 'important'); }
    });
    if (count) count.textContent = 'Showing ' + shown + ' of ' + cards.length;
    if (empty) empty.hidden = shown !== 0;
  }
  chips.forEach(function (ch) {
    ch.addEventListener('click', function () {
      var t = ch.getAttribute('data-tag');
      if (t === '') {
        active = {};
        chips.forEach(function (x) { x.classList.remove('is-on'); });
        allChip.classList.add('is-on');
      } else {
        allChip.classList.remove('is-on');
        if (active[t]) { delete active[t]; ch.classList.remove('is-on'); }
        else { active[t] = 1; ch.classList.add('is-on'); }
        if (activeTags().length === 0) allChip.classList.add('is-on');
      }
      apply();
    });
  });
  if (search) search.addEventListener('input', apply);
  var reset = bar.querySelector('[data-filter-reset]');
  if (reset) reset.addEventListener('click', function () {
    active = {};
    if (search) search.value = '';
    chips.forEach(function (x) { x.classList.remove('is-on'); });
    allChip.classList.add('is-on');
    apply();
  });
  apply();
})();
