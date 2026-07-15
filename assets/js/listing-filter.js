(function () {
  var bar = document.querySelector('[data-listing-filter]');
  var grid = document.querySelector('[data-filter-grid]');
  if (!bar || !grid) return;
  var cards = [].slice.call(grid.querySelectorAll('.hl-catalog-card'));
  var clusters = [].slice.call(grid.querySelectorAll('[data-series-cluster]'));
  var search = bar.querySelector('.hl-filter__search');
  var count = bar.querySelector('[data-filter-count]');
  var empty = bar.querySelector('[data-filter-empty]');

  // Independent chip dimensions. Each chip is selected by its own data-* attr
  // (data-tag / data-tier). The matching CARD attribute can differ: chip
  // data-tag maps to card data-tags, so Dim takes an explicit cardAttr.
  // Within a dimension chips OR-combine; ACROSS dimensions they AND-combine
  // (tier=Detection AND tag=RAT). A dimension with no rendered chips is inert
  // (matches everything), so this stays identical to the tags-only page.
  function Dim(attr, cardAttr) {
    return {
      attr: attr,
      cardAttr: cardAttr || attr,
      chips: [].slice.call(bar.querySelectorAll('.hl-chip-btn[' + attr + ']')),
      allChip: bar.querySelector('.hl-chip-btn[' + attr + '=""]'),
      active: {},
      keys: function () { return Object.keys(this.active); }
    };
  }
  var dims = [Dim('data-tag', 'data-tags'), Dim('data-tier')];

  function matchDim(card, dim) {
    var keys = dim.keys();
    if (keys.length === 0) return true;
    var cv = (card.getAttribute(dim.cardAttr) || '').split('|');
    return keys.some(function (k) { return cv.indexOf(k) > -1; });
  }

  function apply() {
    var term = (search && search.value || '').trim().toLowerCase();
    var shown = 0;
    cards.forEach(function (c) {
      var md = dims.every(function (d) { return matchDim(c, d); });
      // Search matches BOTH the title and the tags, so e.g. "ransomware"
      // surfaces items tagged Ransomware even if it's not in the title.
      var hay = (c.getAttribute('data-title') || '') + '|' + (c.getAttribute('data-tags') || '');
      var mq = !term || hay.indexOf(term) > -1;
      var vis = md && mq;
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

  dims.forEach(function (dim) {
    dim.chips.forEach(function (ch) {
      ch.addEventListener('click', function () {
        var t = ch.getAttribute(dim.attr);
        if (t === '') {
          dim.active = {};
          dim.chips.forEach(function (x) { x.classList.remove('is-on'); });
          if (dim.allChip) dim.allChip.classList.add('is-on');
        } else {
          if (dim.allChip) dim.allChip.classList.remove('is-on');
          if (dim.active[t]) { delete dim.active[t]; ch.classList.remove('is-on'); }
          else { dim.active[t] = 1; ch.classList.add('is-on'); }
          if (dim.keys().length === 0 && dim.allChip) dim.allChip.classList.add('is-on');
        }
        apply();
      });
    });
  });

  if (search) search.addEventListener('input', apply);
  var reset = bar.querySelector('[data-filter-reset]');
  if (reset) reset.addEventListener('click', function () {
    dims.forEach(function (d) {
      d.active = {};
      d.chips.forEach(function (x) { x.classList.remove('is-on'); });
      if (d.allChip) d.allChip.classList.add('is-on');
    });
    if (search) search.value = '';
    apply();
  });
  apply();
})();
