/* Reserve title space in CSS, then fit priority chips into the remaining width.
 * Context stays in the DOM and in the search index while collapsed. */
(function () {
  'use strict';
  var seq = 0;
  document.querySelectorAll('.hl-vuln').forEach(function (row) {
    var box = row.querySelector('.hl-vuln__badges');
    if (!box) return;
    var cve = row.classList.contains('hl-vuln--cve');
    var chips = Array.from(box.children);
    function rank(chip) {
      // The CVSS score is what readers look at first: always shown, on both tabs
      // (Joseph 2026-11-06).
      if (chip.matches('.hl-vuln__sev')) return -1;
      if (cve) {
        if (chip.matches('.hl-vuln__w:not(.hl-vuln__w--kev)')) return 0;
        if (chip.matches('.hl-vuln__p--vedas') && (row.dataset.sig || '').split('|').indexOf('epss_vedas') !== -1) return 0;
        if (chip.querySelector('.hl-vuln__p--epss')) return 2;
      } else {
        if (chip.matches('.hl-vuln__b--cisa')) return 0;
        if (chip.matches('.hl-vuln__preauth')) return 1;
        if (chip.matches('.hl-vuln__tool')) return 2;
        if (chip.querySelector('.hl-vuln__p--epss')) return 3;
      }
      return 9;
    }
    chips.sort(function (a, b) { return rank(a) - rank(b); });
    chips.forEach(function (chip) { box.appendChild(chip); });
    row.dataset.title += ' ' + box.textContent.trim().toLowerCase();
    var btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'hl-vuln__more';
    box.id = 'wire-chips-' + (++seq);
    btn.setAttribute('aria-controls', box.id);
    btn.setAttribute('aria-expanded', 'false');
    box.appendChild(btn);
    var expanded = false, busy = false, inView = false;
    function fit(measure) {
      if (busy) return;
      busy = true;
      chips.forEach(function (chip) { chip.hidden = false; });
      btn.hidden = false;
      btn.textContent = '+' + chips.length;
      var budget = measure ? box.clientWidth : 0;
      var buttonWidth = measure ? btn.getBoundingClientRect().width || 48 : 48;
      var gap = measure ? parseFloat(getComputedStyle(box).columnGap) || 5 : 5;
      var used = buttonWidth + gap, kept = 0, overflow = 0, blocked = false, out = [];
      chips.forEach(function (chip) {
        var width = measure ? chip.getBoundingClientRect().width : 0;
        // Offscreen rows use the fallback
        // without reading layout; the viewport observer measures them on arrival.
        // Priority chips come first (sorted above); any later chip that still
        // fits in the measured width stays visible too (Joseph 2026-11-06:
        // "show a few more tags"). Unmeasured rows show the priority chips only.
        // T-0565.1 review (settled under T-0576): once a priority chip (rank 0-8) does not
        // fit, every later chip overflows too, so a lower-priority chip is never shown
        // while a higher one is hidden.
        var r = rank(chip);
        var keep = r < 0 || (!blocked && (budget > 0 && width > 0
          ? used + width + gap <= budget : r < 9 && kept < 4));
        if (keep) { used += width + gap; kept++; }
        else { overflow++; out.push(chip); if (r < 9) blocked = true; }
      });
      // An expanded row whose overflow has emptied (a wider viewport) is collapsed, so
      // a later narrowing hides the overflow again instead of showing it under a '−N'.
      if (overflow === 0) expanded = false;
      out.forEach(function (chip) { chip.hidden = !expanded; });
      btn.hidden = overflow === 0;
      btn.textContent = expanded ? '−' + overflow : '+' + overflow;
      // The accessible name starts with the visible text (WCAG 2.5.3).
      btn.setAttribute('aria-label', btn.textContent + ': ' + (expanded ? 'hide ' : 'show ') + overflow + ' more details');
      btn.setAttribute('aria-expanded', String(expanded));
      box.classList.toggle('is-expanded', expanded);
      busy = false;
    }
    btn.addEventListener('click', function () { expanded = !expanded; fit(inView); });
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && expanded) { expanded = false; fit(inView); }
    });
    if (window.ResizeObserver) {
      var previous = -1;
      new ResizeObserver(function (entries) {
        var width = entries[0].contentRect.width;
        if (width !== previous) { previous = width; if (inView) fit(true); }
      }).observe(box);
    } else window.addEventListener('resize', function () { if (inView) fit(true); });
    fit(false);
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entries) {
        inView = entries[0].isIntersecting;
        if (inView) fit(true);
      }, { rootMargin: '200px' }).observe(row);
    }
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(function () { if (inView) fit(true); });
    }
  });
  // T-0641: the Priority strip's "All N picks" button does what the Priority picks chip does: it clicks
  // that chip, unless the chip is already on. The button is hidden in the markup and shown here, so a
  // page without this script has no dead control.
  document.querySelectorAll('[data-pstrip-chip]').forEach(function (b) {
    var sec = b.closest('.hl-wtabs__sec');
    var chip = sec && sec.querySelector('.hl-chip-btn[data-sig="' + b.getAttribute('data-pstrip-chip') + '"]');
    if (!chip) return;
    b.hidden = false;
    b.addEventListener('click', function () { if (!chip.classList.contains('is-on')) chip.click(); });
  });
  // T-0641: a strip item scrolls to a row that can sit far down the page. Rows above it change height as
  // the scroll brings them into view (chips are fitted when a row arrives), so the first landing misses.
  // Re-land on the row for a couple of seconds, instantly, until the heights settle. Any reader input
  // stops it at once.
  document.querySelectorAll('.hl-pstrip__list a[href^="#"]').forEach(function (a) {
    a.addEventListener('click', function () {
      var id;
      try { id = decodeURIComponent(a.getAttribute('href').slice(1)); } catch (e) { return; }
      var tries = 0, timer = 0, evs = ['wheel', 'touchstart', 'keydown'];
      function stop() {
        window.clearTimeout(timer); tries = 99;
        evs.forEach(function (n) { window.removeEventListener(n, stop); });
      }
      evs.forEach(function (n) { window.addEventListener(n, stop, { passive: true }); });
      (function tick() {
        if (tries >= 25) { stop(); return; }
        var el = document.getElementById(id);
        if (el && tries > 0 && Math.abs(el.getBoundingClientRect().top - 80) > 3) {
          el.scrollIntoView({ block: 'start', behavior: 'instant' });
        }
        tries++;
        timer = window.setTimeout(tick, 100);
      })();
    });
  });
  // listing-filter.js runs first and applies a shared ?cq=/?vq= search before the chip text
  // above joins data-title; re-apply it now (T-0565.1 review, settled under T-0576).
  document.dispatchEvent(new Event('hl:refilter'));
})();
