'use strict';

/* Box fit for the tabbed report page (T-0500.1.9.1): does any element of the layout hang out of its box, and is every accent
   bar as long as the block it marks.

   WHY A GATE ROW. Joseph found, by eye on a phone, the "next section" cards (nav.hl-rv-nextprev a) 44px tall with their title and
   subtitle hanging 100px below them, their accent edge a third of their text, and other boxes with content outside them. The gate
   already checked page-level horizontal scroll (OVERFLOW_EXPR in check-browser-report.js): an element that spills DOWN, or sideways
   inside a wide enough page, never moves the page's scroll width, so nothing saw it. jsdom cannot answer either: it has no layout.

   WHAT IT MEASURES, in the page, over every painted element under `.hl-report-page` (the theme's own header and footer sit outside
   it and are not this layout's):

   hang  A  an element whose own content is wider or taller than its box: scrollWidth/scrollHeight past clientWidth/clientHeight by
            more than 2px (line-box leading) where the element is not a scroll container;
         B  a child whose rect lies outside its parent's padding box by more than 1px (an inline parent is walked up to the nearest
            block); an absolutely placed child is measured against its containing block's padding box widened by that block's own
            margin, because a container that reserves a margin for its children (the timeline rail keeps 22px each side for the
            half-width of its end markers) has declared that gutter theirs.
   bar   C  every element with a border side of 2px or more in a visible colour and a thin or absent opposite side (an accent edge):
            every descendant element and text run, in flow, must lie inside the edge's own length (the element's border box on that
            axis) within 1px, or the edge is shorter than what it marks; and every absolutely placed thin pseudo-element strip
            (one side 8px or less, the other 16px or more) must be as long as its host's padding box within 1px.
            A bar LONGER than the text it marks is recorded (slack) but is not a fault: a card stretched to its row's height, or
            a 56px header bar round a one-line heading, is the design.

   WHAT IS EXCLUDED, each with a count, never silently:
     scroll container            overflow auto or scroll on that axis (a table's own scroller, a <pre>) and the children inside it
     form control                an input or select scrolls its own value
     ellipsis                    overflow hidden + text-overflow ellipsis + nowrap: the reader sees the truncation (the sticky bar's
                                 current-section label); the full heading is on the page being read
     line clamp                  overflow hidden + line-clamp: the reader sees the ellipsis on the last line (a sponsor's tagline is
                                 clamped to two lines, .hl-rvsp__tagline; found on the hunt-io sponsor variant of the page at 390px)
     gutter                      a positioned container overhanging by no more than its own margin on that side (the timeline rail)
     unpainted overhang          a box with no background, image or border of its own is judged by the text and painted boxes inside it:
                                 the 44px permalink target of an h3 overlaps the 10px under its line by design (its glyph lies inside
                                 the heading); content that IS painted outside its parent (a card's title below the card) still faults
     position:fixed              placed against the viewport (the back-to-top button, the toast), not a parent
     painted at 2px or less / no size / visibility:hidden   nothing painted, so nothing hangs out
     svg internals               the svg root is measured, its shapes are the drawing
   An unmeasured state is NOT CHECKED, never a pass: a row whose measurement count is zero says so. */

/* In the page. Returns one measurement object per call. Kept in ES5 because the other in-page expressions are. */
function boxFit() {
  var root = document.querySelector('.hl-report-page');
  var excluded = {}, hang = [], bars = [], measured = 0, barsMeasured = 0, stripsMeasured = 0, scrollers = 0;
  function ex(k) { excluded[k] = (excluded[k] || 0) + 1; }
  if (!root) return { notChecked: 'no .hl-report-page on the page', measured: 0 };
  function px(v) { var n = parseFloat(v); return isNaN(n) ? 0 : n; }
  function r1(n) { return Math.round(n * 10) / 10; }
  function sig(e) {
    var c = String(e.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.');
    return e.tagName.toLowerCase() + (c ? '.' + c : '');
  }
  function path(e) {
    var parts = [], n = e;
    for (var i = 0; n && n !== root && i < 4; i++, n = n.parentElement) parts.unshift(sig(n));
    return parts.join(' > ');
  }
  /* What a box PAINTS decides whether content hanging out of it can be seen. An element with no background, image or border of its own
     (a link's 44px hit area, a wrapper) has no edge to hang out of: it is judged by its own text runs and by the painted boxes inside it. */
  function ownPaint(c, tag) {
    if (/^(IMG|SVG|CANVAS|VIDEO|INPUT|SELECT|TEXTAREA|PICTURE|IFRAME)$/i.test(tag)) return true;
    var bg = c.backgroundColor;
    if (c.backgroundImage && c.backgroundImage !== 'none') return true;
    if (bg && bg !== 'transparent' && !/rgba\(.*,\s*0\)$/.test(bg)) return true;
    var sides = ['Left', 'Right', 'Top', 'Bottom'];
    for (var k = 0; k < sides.length; k++) {
      if (px(c['border' + sides[k] + 'Width']) > 0 && c['border' + sides[k] + 'Style'] !== 'none' && !/rgba\(.*,\s*0\)$/.test(c['border' + sides[k] + 'Color'] || '')) return true;
    }
    return !!c.boxShadow && c.boxShadow !== 'none';
  }
  /* the rects of what is painted inside e: its text runs and every descendant that paints a box (in flow; placed elements are checked on their own).
     A descendant that clips or scrolls its content (overflow other than visible) contributes its own box only: what lies beyond it is cut off or
     scrolled, not painted outside. */
  function paintRects(e) {
    var out = [], count = 0;
    function walk(el, top) {
      var ecs = getComputedStyle(el);
      if (/auto|scroll|hidden|clip/.test(ecs.overflowX + ' ' + ecs.overflowY)) { var br = el.getBoundingClientRect(); if (br.width || br.height) out.push(br); return; }
      for (var c = el.firstChild; c && count < 1500; c = c.nextSibling) {
        count++;
        if (c.nodeType === 3) {
          if (!/\S/.test(c.nodeValue)) continue;
          var rg = document.createRange(); rg.selectNodeContents(c);
          [].slice.call(rg.getClientRects()).forEach(function (q) { if (q.width || q.height) out.push(q); });
        } else if (c.nodeType === 1) {
          var ncs = getComputedStyle(c);
          if (ncs.display === 'none' || ncs.visibility === 'hidden' || ncs.position === 'absolute' || ncs.position === 'fixed') continue;
          if (c.namespaceURI === 'http://www.w3.org/2000/svg' && c.tagName.toLowerCase() !== 'svg') continue;
          if (ownPaint(ncs, c.tagName)) { var nr = c.getBoundingClientRect(); if (nr.width || nr.height) out.push(nr); }
          walk(c, false);
        }
      }
    }
    walk(e, true);
    return out;
  }
  var all = root.querySelectorAll('*');
  var SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1, LINK: 1, META: 1, BR: 1, WBR: 1 };
  for (var i = 0; i < all.length; i++) {
    var e = all[i];
    if (SKIP[e.tagName]) continue;
    if (e.namespaceURI === 'http://www.w3.org/2000/svg' && e.tagName.toLowerCase() !== 'svg') { ex('svg internals'); continue; }
    var cs = getComputedStyle(e);
    if (cs.display === 'none' || cs.display === 'contents') continue;
    var rects = e.getClientRects();
    if (!rects.length) continue;
    var r = e.getBoundingClientRect();
    measured++;
    if (r.width <= 2 && r.height <= 2) { ex('painted at 2px or less'); continue; }
    if (r.height < 1 || r.width < 1) { ex('no size'); continue; }
    if (cs.visibility === 'hidden' || cs.visibility === 'collapse') { ex('visibility hidden'); continue; }
    var inline = cs.display === 'inline';

    /* A: own content wider or taller than the box */
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.tagName)) ex('form control');
    else if (!inline && e.clientWidth > 0) {
      var dx = e.scrollWidth - e.clientWidth, dy = e.scrollHeight - e.clientHeight, isScroller = false;
      /* scrollWidth and scrollHeight count unpainted boxes (a hit area that overlaps its heading's padding): the verdict is made on what is painted */
      var painted = null, paintedOk = function (axis) {
        if (!painted) painted = paintRects(e);
        if (!painted.length) return true;
        var r0 = e.getBoundingClientRect();
        return painted.every(function (q) { return axis === 'x' ? q.right <= r0.right - px(cs.borderRightWidth) + 1 : q.bottom <= r0.bottom - px(cs.borderBottomWidth) + 1; });
      };
      if (dx > 2) {
        if (/auto|scroll/.test(cs.overflowX)) isScroller = true;
        else if (/hidden|clip/.test(cs.overflowX) && cs.textOverflow === 'ellipsis' && cs.whiteSpace === 'nowrap') ex('ellipsis');
        else if ((cs.position || 'static') !== 'static' && dx <= px(cs.marginRight) + 1) ex('gutter');
        else if (cs.overflowX === 'visible' && paintedOk('x')) ex('unpainted overhang');
        else hang.push({ kind: cs.overflowX === 'visible' ? 'spill-x' : 'clipped-x', sig: sig(e), path: path(e), client: e.clientWidth, scroll: e.scrollWidth, over: dx });
      }
      if (dy > 2) {
        if (/auto|scroll/.test(cs.overflowY)) isScroller = true;
        else if (/hidden|clip/.test(cs.overflowY) && ((cs.webkitLineClamp && cs.webkitLineClamp !== 'none') || (cs.lineClamp && cs.lineClamp !== 'none'))) ex('line clamp');
        else if (cs.overflowY === 'visible' && paintedOk('y')) ex('unpainted overhang');
        else hang.push({ kind: cs.overflowY === 'visible' ? 'spill-y' : 'clipped-y', sig: sig(e), path: path(e), client: e.clientHeight, scroll: e.scrollHeight, over: dy });
      }
      if (isScroller) { scrollers++; ex('scroll container'); }
    }

    /* B: a child outside its parent's padding box */
    var p = e.parentElement;
    if (cs.position === 'fixed') ex('position:fixed');
    else if (p) {
      var out = null, ph, ocs, orc, gl = 0, gr = 0, gt = 0, gb = 0, boxEl = null;
      if (cs.position === 'absolute') {
        boxEl = e.offsetParent;
        if (boxEl && boxEl !== document.body && boxEl !== document.documentElement && !/^(TD|TH|TABLE)$/.test(boxEl.tagName)) {
          ocs = getComputedStyle(boxEl);
          gl = px(ocs.marginLeft); gr = px(ocs.marginRight); gt = px(ocs.marginTop); gb = px(ocs.marginBottom);
        } else { boxEl = null; ex('absolute child with no element container'); }
      } else {
        boxEl = p;
        while (boxEl && boxEl !== root.parentElement && /^(inline|contents)$/.test(getComputedStyle(boxEl).display)) boxEl = boxEl.parentElement;
        if (boxEl && boxEl !== root.parentElement && boxEl !== document.body) ocs = getComputedStyle(boxEl); else boxEl = null;
      }
      if (boxEl) {
        orc = boxEl.getBoundingClientRect();
        var L = orc.left + px(ocs.borderLeftWidth) - gl, R = orc.right - px(ocs.borderRightWidth) + gr;
        var T = orc.top + px(ocs.borderTopWidth) - gt, Bm = orc.bottom - px(ocs.borderBottomWidth) + gb;
        var list = inline ? [].slice.call(rects) : [r];
        if (!ownPaint(cs, e.tagName)) { list = paintRects(e); if (!list.length) { ex('unpainted box with nothing painted inside'); list = []; } }
        list.forEach(function (q) {
          if (q.width === 0 && q.height === 0) return;
          if (q.left < L - 1) out = out || { side: 'left', by: L - q.left };
          if (q.right > R + 1) out = out || { side: 'right', by: q.right - R };
          if (q.top < T - 1) out = out || { side: 'top', by: T - q.top };
          if (q.bottom > Bm + 1) out = out || { side: 'bottom', by: q.bottom - Bm };
        });
        if (out) {
          var horiz = out.side === 'left' || out.side === 'right';
          if (/auto|scroll/.test(horiz ? ocs.overflowX : ocs.overflowY)) ex('child inside a scroll container');
          else if (horiz && /hidden|clip/.test(ocs.overflowX) && ocs.textOverflow === 'ellipsis' && ocs.whiteSpace === 'nowrap') ex('child inside an ellipsis box');
          else hang.push({ kind: cs.position === 'absolute' ? 'abs-out-of-container' : 'out-of-parent', sig: sig(e), path: path(e), side: out.side, by: r1(out.by), parent: sig(boxEl),
            child: [r1(r.left), r1(r.top), r1(r.right), r1(r.bottom)] });
        }
      }
    }

    /* C: accent edges on a border side */
    ['Left', 'Right', 'Top', 'Bottom'].forEach(function (S) {
      var bw = px(cs['border' + S + 'Width']);
      if (bw < 2 || cs['border' + S + 'Style'] === 'none') return;
      var col = cs['border' + S + 'Color'];
      if (/rgba\(.*,\s*0\)$/.test(col) || col === 'transparent') return;
      var opp = { Left: 'Right', Right: 'Left', Top: 'Bottom', Bottom: 'Top' }[S];
      if (px(cs['border' + opp + 'Width']) * 2 > bw) return;
      var vertical = S === 'Left' || S === 'Right';
      var from = vertical ? r.top : r.left, to = vertical ? r.bottom : r.right, lo = Infinity, hi = -Infinity, n = 0;
      var tw = document.createTreeWalker(e, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, null), nd, guard = 0;
      while ((nd = tw.nextNode()) && guard++ < 1500) {
        var rs;
        if (nd.nodeType === 3) {
          if (!/\S/.test(nd.nodeValue)) continue;
          var rg = document.createRange(); rg.selectNodeContents(nd); rs = rg.getClientRects();
        } else {
          var ncs = getComputedStyle(nd);
          if (ncs.display === 'none' || ncs.position === 'absolute' || ncs.position === 'fixed' || ncs.visibility === 'hidden') continue;
          if (nd.namespaceURI === 'http://www.w3.org/2000/svg' && nd.tagName.toLowerCase() !== 'svg') continue;
          rs = [nd.getBoundingClientRect()];
        }
        for (var q = 0; q < rs.length; q++) {
          var z = rs[q]; if (z.width === 0 && z.height === 0) continue;
          var a = vertical ? z.top : z.left, b = vertical ? z.bottom : z.right;
          if (a < lo) lo = a; if (b > hi) hi = b; n++;
        }
      }
      if (!n) { ex('accent edge on an element with no content'); return; }
      barsMeasured++;
      var before = from - lo, after = hi - to; // positive: content lies past the edge's own length
      if (before > 1 || after > 1) {
        bars.push({ kind: 'bar-short', sig: sig(e), path: path(e), side: S.toLowerCase(), barLen: r1(to - from), before: r1(Math.max(before, 0)), after: r1(Math.max(after, 0)) });
      }
    });

    /* C: thin absolutely placed pseudo-element strips against the host's padding box */
    ['::before', '::after'].forEach(function (pe) {
      var ps = getComputedStyle(e, pe);
      if (!ps || ps.content === 'none' || ps.content === 'normal' || ps.display === 'none' || ps.position !== 'absolute') return;
      var w = px(ps.width), h = px(ps.height);
      var vStrip = w > 0 && w <= 8 && h >= 16, hStrip = h > 0 && h <= 8 && w >= 16;
      if (!vStrip && !hStrip) return;
      if ((cs.position || 'static') === 'static') { ex('pseudo strip on a static host (no containing block to compare)'); return; }
      stripsMeasured++;
      var hostLen = vStrip ? e.clientHeight : e.clientWidth, barLen = vStrip ? h : w;
      if (Math.abs(hostLen - barLen) > 1) bars.push({ kind: 'strip-mismatch', sig: sig(e) + pe, path: path(e), side: vStrip ? 'vertical' : 'horizontal', barLen: r1(barLen), hostLen: hostLen });
    });
  }
  return { measured: measured, scrollers: scrollers, excluded: excluded, hang: hang, bars: bars, barsMeasured: barsMeasured, stripsMeasured: stripsMeasured };
}

var EXPR = '(' + boxFit.toString() + ')()';

function sumExcluded(states) {
  var t = {};
  states.forEach(function (s) { Object.keys(s.excluded || {}).forEach(function (k) { t[k] = (t[k] || 0) + s.excluded[k]; }); });
  return Object.keys(t).sort().map(function (k) { return t[k] + ' ' + k; }).join(', ');
}
function describe(f) {
  var where = f.where || '';
  if (f.kind === 'bar-short') return where + f.sig + ' (' + f.path + '): its ' + f.side + ' edge is ' + f.barLen + 'px long and its content lies ' + f.before + 'px before and ' + f.after + 'px after it';
  if (f.kind === 'strip-mismatch') return where + f.sig + ' (' + f.path + '): a ' + f.side + ' strip ' + f.barLen + 'px long on a host ' + f.hostLen + 'px long';
  if (f.kind === 'out-of-parent' || f.kind === 'abs-out-of-container') return where + f.sig + ' (' + f.path + '): ' + f.by + 'px past the ' + f.side + ' of its ' + f.parent;
  return where + f.sig + ' (' + f.path + '): ' + f.kind + ', content ' + f.scroll + 'px in a box of ' + f.client + 'px';
}
/* states: [{ label, width, view, measured, scrollers, excluded, hang, bars, barsMeasured, stripsMeasured } | { label, notChecked }] */
function verdict(states, which) {
  var good = (states || []).filter(function (s) { return s && !s.notChecked && s.measured > 0; });
  var bad = (states || []).filter(function (s) { return !s || s.notChecked || !(s.measured > 0); });
  if (!good.length) return { notChecked: true, ok: false, detail: 'no state was measured' + (bad.length ? ' (' + bad.map(function (s) { return s && s.notChecked || 'no elements'; }).join('; ') + ')' : '') };
  var key = which === 'bar' ? 'bars' : 'hang', findings = [];
  good.forEach(function (s) { (s[key] || []).forEach(function (f) { findings.push(Object.assign({ where: s.label + ': ' }, f)); }); });
  /* the deepest element first: an outer box that spills because a card inside it does names the card second */
  findings.sort(function (a, b) { return String(b.path).split(' > ').length - String(a.path).split(' > ').length; });
  var elements = good.reduce(function (a, s) { return a + s.measured; }, 0);
  var unit = elements + ' element measurements in ' + good.length + ' tab/viewport states with every teardown open';
  var detail;
  if (which === 'bar') {
    var edges = good.reduce(function (a, s) { return a + (s.barsMeasured || 0); }, 0), strips = good.reduce(function (a, s) { return a + (s.stripsMeasured || 0); }, 0);
    detail = edges + ' accent edges and ' + strips + ' pseudo-element strips checked against their blocks (' + unit + ')';
  } else detail = unit + '; excluded: ' + (sumExcluded(good) || 'none');
  if (bad.length) detail += '; NOT MEASURED: ' + bad.length + ' state(s)';
  if (findings.length) {
    var seen = {}, uniq = [];
    findings.forEach(function (f) { var k = f.kind + '|' + f.sig + '|' + f.where; if (!seen[k]) { seen[k] = 1; uniq.push(f); } });
    return { ok: false, count: findings.length, findings: findings, detail: findings.length + ' fault(s) in ' + uniq.length + ' place(s): ' + uniq.slice(0, 6).map(describe).join(' | ') + (uniq.length > 6 ? ' | +' + (uniq.length - 6) + ' more' : '') + '; ' + detail };
  }
  return { ok: true, count: 0, findings: [], detail: '0 faults; ' + detail };
}

/* ---- T-0500.1.10.1: the collapsed data view ------------------------------------------------------------------------------------
   Joseph, on a phone (live pilot, Attack chain tab): the collapsed "Data view" bar drawn as a fully rounded card with the line
   "View selections curated for this report." hanging under it, touching its bottom edge. Two CSS rules disagreed (the collapsed bar
   was given a full radius and no divider as if nothing followed it; the note was given margin -8px as if the body above it were
   open), and the box-fit rows above missed it twice over: boxFitState opens every view before it measures, and each box fits its own
   content even when two boxes overlap each other.

   WHAT IT MEASURES, with every data view collapsed, in the page, over the views on screen (a view in a hidden tab has no box):
     overlap   two in-flow, non-inline siblings anywhere inside a view whose boxes intersect by more than 1px on both axes, where
               either one paints (a background, image, border, shadow, or a text run of its own): the unpainted note laid over the
               painted bar is the case Joseph saw
     rounded   a summary bar with a rounded bottom corner that has a visible in-flow sibling after it in the view: a card whose first
               row is a closed shape with a row hanging under it
   A view whose button says aria-expanded other than false is counted as not collapsed and not measured; a view with no bar or no
   button is counted and not measured. A bar with nothing under it that keeps its full radius is the design; it is counted
   (roundedAlone), not faulted. An unmeasured state is NOT CHECKED. ES5, like the other in-page expressions. */
function viewFit() {
  var root = document.querySelector('.hl-report-page');
  var o = { views: 0, collapsed: 0, notCollapsed: 0, noBar: 0, withNote: 0, siblingPairs: 0, rounded: 0, roundedAlone: 0, overlap: [], roundedOver: [] };
  if (!root) return { notChecked: 'no .hl-report-page on the page', views: 0 };
  function px(v) { var n = parseFloat(v); return isNaN(n) ? 0 : n; }
  function r1(n) { return Math.round(n * 10) / 10; }
  function sig(e) { var c = String(e.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.'); return e.tagName.toLowerCase() + (c ? '.' + c : ''); }
  var SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1, LINK: 1, META: 1, BR: 1, WBR: 1 };
  function shown(e) {
    if (SKIP[e.tagName]) return null;
    var c = getComputedStyle(e);
    if (c.display === 'none' || c.display === 'contents' || c.visibility === 'hidden' || c.visibility === 'collapse') return null;
    var r = e.getBoundingClientRect();
    return r.width >= 1 && r.height >= 1 ? { c: c, r: r } : null;
  }
  function paints(e, c) {
    if (/^(IMG|SVG|CANVAS|VIDEO|INPUT|SELECT|TEXTAREA|PICTURE|IFRAME)$/i.test(e.tagName)) return true;
    if (c.backgroundImage && c.backgroundImage !== 'none') return true;
    if (c.backgroundColor && c.backgroundColor !== 'transparent' && !/rgba\(.*,\s*0\)$/.test(c.backgroundColor)) return true;
    var S = ['Left', 'Right', 'Top', 'Bottom'];
    for (var k = 0; k < S.length; k++) if (px(c['border' + S[k] + 'Width']) > 0 && c['border' + S[k] + 'Style'] !== 'none' && !/rgba\(.*,\s*0\)$/.test(c['border' + S[k] + 'Color'] || '')) return true;
    if (c.boxShadow && c.boxShadow !== 'none') return true;
    for (var n = e.firstChild; n; n = n.nextSibling) if (n.nodeType === 3 && /\S/.test(n.nodeValue)) return true;
    return false;
  }
  function flow(c) { return c.position !== 'absolute' && c.position !== 'fixed'; }
  var views = root.querySelectorAll('.hl-rv-view');
  for (var i = 0; i < views.length; i++) {
    var v = views[i];
    if (!shown(v)) continue;
    o.views++;
    var bar = null, ch = v.children;
    for (var j = 0; j < ch.length; j++) if (/\bhl-rv-view-summary\b/.test(ch[j].className)) { bar = ch[j]; break; }
    var btn = bar && bar.querySelector('button[aria-expanded]');
    if (!bar || !btn) { o.noBar++; continue; }
    if (btn.getAttribute('aria-expanded') !== 'false') { o.notCollapsed++; continue; }
    o.collapsed++;
    if (v.querySelector(':scope > .hl-rv-curated')) o.withNote++;
    /* overlap: every shown, in-flow, non-inline element in the view against its later siblings */
    var all = [v].concat([].slice.call(v.querySelectorAll('*')));
    for (var a = 0; a < all.length; a++) {
      var A = shown(all[a]);
      if (!A || !flow(A.c) || A.c.display === 'inline') continue;
      for (var f = all[a].nextElementSibling; f; f = f.nextElementSibling) {
        var B = shown(f);
        if (!B || !flow(B.c) || B.c.display === 'inline') continue;
        o.siblingPairs++;
        var ox = Math.min(A.r.right, B.r.right) - Math.max(A.r.left, B.r.left), oy = Math.min(A.r.bottom, B.r.bottom) - Math.max(A.r.top, B.r.top);
        if (ox > 1 && oy > 1 && (paints(all[a], A.c) || paints(f, B.c)))
          o.overlap.push({ kind: 'overlap', sig: sig(all[a]), other: sig(f), by: r1(oy), wide: r1(ox), view: sig(v) });
      }
    }
    /* rounded: the bar's bottom corners against what follows it */
    var bs = getComputedStyle(bar), rad = Math.max(px(bs.borderBottomLeftRadius), px(bs.borderBottomRightRadius));
    var after = null;
    for (var g = bar.nextElementSibling; g; g = g.nextElementSibling) { var G = shown(g); if (G && flow(G.c)) { after = g; break; } }
    if (rad > 0) {
      o.rounded++;
      if (after) o.roundedOver.push({ kind: 'rounded-over-sibling', sig: sig(bar), other: sig(after), radius: rad, view: sig(v) });
      else o.roundedAlone++;
    }
  }
  return o;
}
var VIEW_EXPR = '(' + viewFit.toString() + ')()';

/* states: [{ label, views, collapsed, ... overlap, roundedOver } | { label, notChecked }]; which: 'overlap' | 'rounded' */
function viewVerdict(states, which) {
  var good = (states || []).filter(function (s) { return s && !s.notChecked && s.collapsed > 0; });
  var bad = (states || []).filter(function (s) { return !s || s.notChecked || !(s.collapsed > 0); });
  if (!good.length) return { notChecked: true, ok: false, detail: 'no collapsed data view was measured' + (bad.length ? ' (' + bad.map(function (s) { return s && s.notChecked || 'no collapsed view'; }).join('; ') + ')' : '') };
  var key = which === 'rounded' ? 'roundedOver' : 'overlap', findings = [];
  good.forEach(function (s) { (s[key] || []).forEach(function (f) { findings.push(Object.assign({ where: s.label + ': ' }, f)); }); });
  var sum = function (k) { return good.reduce(function (a, s) { return a + (s[k] || 0); }, 0); };
  var unit = sum('collapsed') + ' collapsed data views in ' + good.length + ' tab/viewport states (' + sum('withNote') + ' with the curated note under the bar)';
  var detail = which === 'rounded'
    ? sum('rounded') + ' bars with a rounded bottom corner, ' + sum('roundedAlone') + ' of them with nothing under them; ' + unit
    : sum('siblingPairs') + ' sibling pairs compared; ' + unit;
  var notC = sum('notCollapsed'); if (notC) detail += '; NOT MEASURED: ' + notC + ' view(s) that were not collapsed';
  if (bad.length) detail += '; NOT MEASURED: ' + bad.length + ' state(s)';
  if (findings.length) {
    var d = findings.slice(0, 4).map(function (f) {
      return f.where + (f.kind === 'overlap' ? f.sig + ' overlaps its sibling ' + f.other + ' by ' + f.by + 'px (' + f.wide + 'px wide) inside ' + f.view
        : f.sig + ' has a bottom radius of ' + f.radius + 'px and ' + f.other + ' under it inside ' + f.view);
    }).join(' | ');
    return { ok: false, count: findings.length, findings: findings, detail: findings.length + ' fault(s): ' + d + (findings.length > 4 ? ' | +' + (findings.length - 4) + ' more' : '') + '; ' + detail };
  }
  return { ok: true, count: 0, findings: [], detail: '0 faults; ' + detail };
}

module.exports = { EXPR: EXPR, boxFit: boxFit, verdict: verdict, describe: describe, VIEW_EXPR: VIEW_EXPR, viewFit: viewFit, viewVerdict: viewVerdict };
