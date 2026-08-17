/* The Hunter's Ledger: hover glossary.
   Marks the FIRST occurrence of a known term per <h2> section. The exclusion
   list below is load-bearing: a definition surfacing inside a rule body or an
   indicator value is the failure mode this module exists to avoid. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.HLGlossary = api; api.init(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var EXCLUDED_TAGS = {
    CODE: 1, PRE: 1, A: 1, KBD: 1, SAMP: 1, SCRIPT: 1, STYLE: 1, SUMMARY: 1,
    H1: 1, H2: 1, H3: 1, H4: 1, H5: 1, H6: 1
  };

  // Anything that looks like an indicator should never carry a tooltip. This
  // rejects the whole text node, not just the indicator, which is deliberately
  // over-broad: losing one mark in a sentence that quotes an IP is cheap, and a
  // tooltip anchored inside an address is the defect being avoided.
  var INDICATOR_RE = /(\d{1,3}\[?\.\]?){3}\d{1,3}|\b[a-f0-9]{32,64}\b/i;

  // Must stay equal to the max-width in the .hl-gloss::after rule in
  // assets/css/custom.css. Changing one without the other misplaces the flip.
  var TOOLTIP_MAX_PX = 320;

  function isExcluded(node) {
    var n = node.parentNode;
    while (n && n.nodeType === 1) {
      if (EXCLUDED_TAGS[n.tagName]) return true;
      if (n.hasAttribute && n.hasAttribute('data-no-gloss')) return true;
      if (n.classList && n.classList.contains('hl-gloss')) return true;
      n = n.parentNode;
    }
    return false;
  }

  function surfaces(entry) {
    return [entry.term].concat(entry.aliases || []);
  }

  // Longest surface first, so "bulletproof hosting" beats "hosting" when both
  // match at the same position.
  function buildMatchers(terms) {
    var out = [];
    terms.forEach(function (entry) {
      surfaces(entry).forEach(function (s) {
        out.push({
          surface: s,
          entry: entry,
          re: new RegExp('(^|[^A-Za-z0-9_-])(' +
            s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
            ')(?![A-Za-z0-9_-])', entry.case_sensitive ? '' : 'i')
        });
      });
    });
    return out.sort(function (a, b) { return b.surface.length - a.surface.length; });
  }

  function textNodesUnder(el, doc) {
    var walker = doc.createTreeWalker(el, 4 /* NodeFilter.SHOW_TEXT */, null, false);
    var out = [], n;
    while ((n = walker.nextNode())) out.push(n);
    return out;
  }

  // Splits the document into sections at each <h2>, so "first occurrence"
  // means first per section rather than first per page.
  function sections(rootEl) {
    var out = [], current = [];
    [].forEach.call(rootEl.children, function (child) {
      if (child.tagName === 'H2' && current.length) { out.push(current); current = []; }
      current.push(child);
    });
    if (current.length) out.push(current);
    return out.length ? out : [[rootEl]];
  }

  /* Earliest position wins, ties broken by the longer surface.

     Ordering by position rather than by surface length is what lets a single
     paragraph carry two different terms. Taking the longest matching surface
     first would mark a term late in the node, and the scan resumes AFTER the
     mark, so any earlier term in the same node would be skipped forever. */
  function bestMatch(text, matchers, used) {
    var best = null;
    for (var i = 0; i < matchers.length; i++) {
      var m = matchers[i];
      if (used[m.entry.term]) continue;
      var hit = m.re.exec(text);
      if (!hit) continue;
      var at = hit.index + hit[1].length;
      if (!best || at < best.at ||
          (at === best.at && m.surface.length > best.m.surface.length)) {
        best = { m: m, hit: hit, at: at };
      }
    }
    return best;
  }

  function markOne(node, best, doc) {
    var span = doc.createElement('span');
    span.className = 'hl-gloss';
    span.setAttribute('tabindex', '0');
    span.setAttribute('data-gloss', best.m.entry.short);
    span.setAttribute('aria-label', best.m.entry.term + ': ' + best.m.entry.short);
    span.textContent = best.hit[2];

    var after = node.splitText(best.at);
    after.nodeValue = after.nodeValue.slice(best.hit[2].length);
    after.parentNode.insertBefore(span, after);
    return after;
  }

  // Keeps consuming the tail of one text node so several distinct terms in the
  // same paragraph are all marked. The guard bounds a pathological node rather
  // than trusting the loop to always shrink.
  function markInNode(node, matchers, used, usedOnce, doc) {
    var current = node, guard = 0;
    while (current && guard++ < 50) {
      var best = bestMatch(current.nodeValue, matchers, used);
      if (!best) return;
      used[best.m.entry.term] = true;
      if (best.m.entry.once_per_report) usedOnce[best.m.entry.term] = true;
      current = markOne(current, best, doc);
    }
  }

  /* Two scopes, because one rate does not fit every term.

     Most terms mark once per <h2> section: per page is too sparse in a long
     report. But measurement across the published corpus showed six common terms
     producing 56% of all marking, C2 alone averaging eight marks a report. The
     house standard's objection to defining terms a defender already knows
     applies with full force once the marking is that repetitive, and the hover
     exemption holds only while it stays quiet. A term carrying
     once_per_report is therefore explained where the reader first meets it and
     then stops for the rest of the page. */
  function markTerms(rootEl, terms, doc) {
    var matchers = buildMatchers(terms);
    var usedOnce = {};
    sections(rootEl).forEach(function (blocks) {
      var used = {};
      Object.keys(usedOnce).forEach(function (k) { used[k] = true; });
      blocks.forEach(function (block) {
        textNodesUnder(block, doc).forEach(function (node) {
          if (isExcluded(node)) return;
          if (INDICATOR_RE.test(node.nodeValue)) return;
          markInNode(node, matchers, used, usedOnce, doc);
        });
      });
    });
    return rootEl;
  }

  /* True when a tooltip anchored to the mark's left edge would run past the
     right edge of its container. Pure arithmetic on four numbers, so it is
     testable without a layout engine. Zero for either width means nothing was
     measurable, which is the jsdom case, and the honest answer there is "do not
     flip" rather than a guess. */
  function prefersRightAnchor(markLeft, markWidth, containerWidth, tooltipMaxWidth) {
    if (!containerWidth || !tooltipMaxWidth) return false;
    return markLeft + tooltipMaxWidth > containerWidth;
  }

  /* Applies or clears the flip class from real geometry, returning how many
     marks are flipped.

     It TOGGLES rather than only adding, because the decision depends on the
     container width: widen the window and a mark that needed the flip no longer
     does, and a class that only ever accumulated would leave the tooltip
     anchored right for the rest of the session.

     A container of zero width means nothing was measurable, which is the jsdom
     case, and the honest response is to change nothing rather than guess. */
  function applyEdgeClasses(rootEl) {
    var marks = rootEl.querySelectorAll('.hl-gloss');
    if (!marks.length || !rootEl.getBoundingClientRect) return 0;
    var box = rootEl.getBoundingClientRect();
    if (!box.width) return 0;
    var flipped = 0;
    [].forEach.call(marks, function (m) {
      var r = m.getBoundingClientRect();
      if (prefersRightAnchor(r.left - box.left, r.width, box.width, TOOLTIP_MAX_PX)) {
        m.classList.add('hl-gloss--right');
        flipped++;
      } else {
        m.classList.remove('hl-gloss--right');
      }
    });
    return flipped;
  }

  /* Measures only once layout has settled, and again whenever it changes.

     Calling applyEdgeClasses straight from init is wrong even though the script
     is deferred: parsing is done by then, but webfonts have not landed and this
     layout's own inline JS is still moving panels around, so the rects read at
     that moment are not the ones the reader ends up with. Live, that measured
     every mark as needing no flip and applied the class to none of 19 that
     wanted it. Nothing threw and nothing looked wrong, which is why only a
     browser caught it. */
  function scheduleEdgeClasses(rootEl) {
    var run = function () { applyEdgeClasses(rootEl); };
    if (typeof requestAnimationFrame === 'function') requestAnimationFrame(run);
    else run();
    if (document.fonts && document.fonts.ready && document.fonts.ready.then) {
      document.fonts.ready.then(run)['catch'](function () {});
    }
    if (typeof window !== 'undefined' && window.addEventListener) {
      window.addEventListener('load', run);
      var timer = null;
      window.addEventListener('resize', function () {
        if (timer) clearTimeout(timer);
        timer = setTimeout(run, 150);
      });
    }
  }

  function init() {
    var doc = document;
    var body = doc.querySelector('.hl-post-content') || doc.querySelector('.hl-post-body');
    if (!body || body.hasAttribute('data-no-gloss')) return;
    var raw = doc.getElementById('hl-glossary-data');
    if (!raw) return;
    var terms;
    try { terms = JSON.parse(raw.textContent); } catch (e) { return; }
    if (!terms || !terms.length) return;
    markTerms(body, terms, doc);
    scheduleEdgeClasses(body);
  }

  return {
    isExcluded: isExcluded,
    buildMatchers: buildMatchers,
    markTerms: markTerms,
    prefersRightAnchor: prefersRightAnchor,
    applyEdgeClasses: applyEdgeClasses,
    scheduleEdgeClasses: scheduleEdgeClasses,
    init: init
  };
});
