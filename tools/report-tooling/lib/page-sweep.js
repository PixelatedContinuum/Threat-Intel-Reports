'use strict';

/* In-page measurements shared by the home gate (check-browser-home.js) and the site sweep (check-browser-sweep.js), T-0556 w6.
   Each *_EXPR is an ES5 expression string evaluated in the page, like lib/box-fit.js; each returns plain JSON with its own denominator.
   Nothing here decides pass or fail except the verdict helpers at the bottom, which are pure and unit-tested without a browser.

   overflow   page-level horizontal scroll (scrollWidth of html and body past the viewport), and every painted element whose box leaves
              the viewport sideways and is not inside a scroller the reader can scroll (overflow auto or scroll). `overflow-x: clip` on the
              theme's html keeps scrollWidth equal to the viewport while a too-wide box is silently cut, so the boxes are read as well.
   clip       text clipped by an ancestor that hides overflow: the text run's rect lies outside the ancestor's padding box by more than 1px
              and no scroller sits between them. Excluded with a count: aria-hidden subtrees (decoration), text-overflow: ellipsis with
              nowrap (the reader sees the cut), clip-rect screen-reader text.
   contrast   WCAG contrast of every text run's computed colour against the background composited from its ancestors. Large text
              (24px, or 18.66px at weight 700) needs 3, other text 4.5. A run over a background image or gradient cannot be measured by
              compositing and is counted as unmeasured, never as a pass. */

function overflowProbe() {
  var vw = document.documentElement.clientWidth;
  var o = { vw: vw, scrollX: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - vw, painted: 0, escaped: [], inScroller: 0, ariaHidden: 0 };
  var all = document.body.querySelectorAll('*');
  function sig(e) { var c = String(e.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.'); return e.tagName.toLowerCase() + (c ? '.' + c : ''); }
  for (var i = 0; i < all.length; i++) {
    var e = all[i];
    if (/^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|LINK|META|BR|WBR|HEAD)$/.test(e.tagName)) continue;
    var c = getComputedStyle(e);
    if (c.display === 'none' || c.visibility === 'hidden' || c.position === 'fixed') continue;
    var r = e.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    o.painted++;
    if (r.right <= vw + 1 && r.left >= -1) continue;
    var hid = false, scr = false, clipped = false;
    for (var p = e; p && p !== document.documentElement; p = p.parentElement) {
      if (p.getAttribute && p.getAttribute('aria-hidden') === 'true') hid = true;
      if (p === e) continue;
      var pc = getComputedStyle(p);
      if (pc.overflowX === 'auto' || pc.overflowX === 'scroll') { scr = true; break; }
      if (pc.overflowX === 'hidden' || pc.overflowX === 'clip') { var pr = p.getBoundingClientRect(); if (pr.right <= vw + 1 && pr.left >= -1) clipped = true; }
    }
    if (hid) { o.ariaHidden++; continue; }
    if (scr) { o.inScroller++; continue; }
    if (clipped) { o.inScroller++; continue; }
    o.escaped.push(sig(e) + ' ' + Math.round(r.left) + '..' + Math.round(r.right));
  }
  return o;
}

function clipProbe() {
  var o = { runs: 0, clipped: [], ellipsis: 0, ariaHidden: 0, srOnly: 0 };
  var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
  function sig(e) { var c = String(e.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.'); return e.tagName.toLowerCase() + (c ? '.' + c : ''); }
  var rg = document.createRange();
  var n;
  while ((n = w.nextNode())) {
    if (!/\S/.test(n.nodeValue)) continue;
    var e = n.parentElement;
    if (!e || /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|OPTION)$/.test(e.tagName)) continue;
    var cs = getComputedStyle(e);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    rg.selectNodeContents(n);
    var tr = rg.getBoundingClientRect();
    if (tr.width < 1 || tr.height < 1) continue;
    var hid = false, ell = false, sr = false, scr = false, bad = null;
    for (var p = e; p && p !== document.documentElement; p = p.parentElement) {
      var pc = getComputedStyle(p);
      if (p.getAttribute('aria-hidden') === 'true') hid = true;
      if (/rect\(0(px)?,? 0(px)?,? 0(px)?,? 0(px)?\)/.test(pc.clip) || (parseFloat(pc.width) <= 1 && parseFloat(pc.height) <= 1 && pc.overflow === 'hidden')) sr = true;
      if (pc.overflowX === 'auto' || pc.overflowX === 'scroll' || pc.overflowY === 'auto' || pc.overflowY === 'scroll') { scr = true; break; }
      var hx = pc.overflowX === 'hidden' || pc.overflowX === 'clip', hy = pc.overflowY === 'hidden' || pc.overflowY === 'clip';
      if (hx || hy) {
        if (pc.textOverflow === 'ellipsis' || pc.webkitLineClamp !== 'none' && pc.webkitLineClamp) { ell = true; continue; }
        var pr = p.getBoundingClientRect();
        var bw = function (k) { return parseFloat(pc['border' + k + 'Width']) || 0; };
        var L = pr.left + bw('Left'), R = pr.right - bw('Right'), T = pr.top + bw('Top'), B = pr.bottom - bw('Bottom');
        if (!bad && ((hx && (tr.left < L - 1 || tr.right > R + 1)) || (hy && (tr.top < T - 1 || tr.bottom > B + 1)))) bad = sig(p) + ' holds ' + sig(e);
      }
    }
    if (hid) { o.ariaHidden++; continue; }
    if (sr) { o.srOnly++; continue; }
    if (scr) continue;
    o.runs++;
    if (ell && !bad) { o.ellipsis++; continue; }
    if (bad) o.clipped.push(bad + ' "' + n.nodeValue.trim().slice(0, 30) + '"');
  }
  return o;
}

function contrastProbe() {
  var o = { runs: 0, unmeasured: 0, ariaHiddenSkipped: 0, transparent: 0, pageGrid: 0, bad: [] };
  function parse(s) {
    var m = String(s).match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    var a = m[1].split(/[ ,\/]+/).filter(Boolean).map(parseFloat);
    return { r: a[0], g: a[1], b: a[2], a: a.length > 3 && !isNaN(a[3]) ? a[3] : 1 };
  }
  function over(top, bot) {
    var a = top.a + bot.a * (1 - top.a);
    if (a <= 0) return { r: 0, g: 0, b: 0, a: 0 };
    return { r: (top.r * top.a + bot.r * bot.a * (1 - top.a)) / a, g: (top.g * top.a + bot.g * bot.a * (1 - top.a)) / a, b: (top.b * top.a + bot.b * bot.a * (1 - top.a)) / a, a: a };
  }
  function lum(c) {
    function f(v) { v = v / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  }
  function ratio(a, b) { var l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); }
  function sig(e) { var c = String(e.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.'); return e.tagName.toLowerCase() + (c ? '.' + c : ''); }
  function hex(c) { return '#' + [c.r, c.g, c.b].map(function (v) { return ('0' + Math.round(v).toString(16)).slice(-2); }).join(''); }
  var seen = {};
  var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
  var rg = document.createRange();
  var n;
  while ((n = w.nextNode())) {
    if (!/\S/.test(n.nodeValue)) continue;
    var e = n.parentElement;
    if (!e || /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|OPTION|TITLE)$/.test(e.tagName)) continue;
    var cs = getComputedStyle(e);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    rg.selectNodeContents(n);
    var tr = rg.getBoundingClientRect();
    if (tr.width < 1 || tr.height < 1) continue;
    var skip = false, op = 1, layers = [], img = false;
    for (var p = e; p; p = p.parentElement) {
      var pc = getComputedStyle(p);
      if (p.getAttribute && p.getAttribute('aria-hidden') === 'true') { skip = true; break; }
      if (pc.display === 'none') { skip = true; break; }
      op *= parseFloat(pc.opacity);
      if (pc.backgroundImage && pc.backgroundImage !== 'none') { if (p === document.body || p === document.documentElement) o.pageGrid++; else img = true; }   /* the page's own faint grid is read as its flat colour: its lines sit within a few per cent of the page luminance */
      var bg = parse(pc.backgroundColor);
      if (bg && bg.a > 0) { layers.push(bg); if (bg.a >= 1) break; }
    }
    if (skip) { o.ariaHiddenSkipped++; continue; }
    if (e.disabled || (e.closest && e.closest('[disabled]'))) continue;
    if (op < 0.05) { o.transparent = (o.transparent || 0) + 1; continue; }   /* opacity 0: nothing is painted (the back-to-top button before the page scrolls) */
    o.runs++;
    if (img) { o.unmeasured++; continue; }
    var base = { r: 255, g: 255, b: 255, a: 1 };
    for (var k = layers.length - 1; k >= 0; k--) base = over(layers[k], base);
    var fg = parse(cs.color);
    if (!fg) { o.unmeasured++; continue; }
    fg = { r: fg.r, g: fg.g, b: fg.b, a: fg.a * op };
    var eff = over(fg, base);
    var size = parseFloat(cs.fontSize), wt = parseInt(cs.fontWeight, 10) || 400;
    var need = (size >= 24 || (size >= 18.66 && wt >= 700)) ? 3 : 4.5;
    var rt = ratio(eff, base);
    if (rt + 0.005 < need) {
      var key = sig(e) + '|' + hex(eff) + '|' + hex(base);
      if (!seen[key]) { seen[key] = { sig: sig(e), fg: hex(eff), bg: hex(base), ratio: Math.round(rt * 100) / 100, need: need, size: size, n: 0, text: n.nodeValue.trim().slice(0, 40) }; o.bad.push(seen[key]); }
      seen[key].n++;
    }
  }
  /* placeholders and the typed text of fields: a placeholder is not a text node, so it is read from ::placeholder */
  var fields = document.querySelectorAll('input[placeholder], textarea[placeholder]');
  for (var fi = 0; fi < fields.length; fi++) {
    var fe = fields[fi], fcs = getComputedStyle(fe), fr = fe.getBoundingClientRect();
    if (fcs.display === 'none' || fcs.visibility === 'hidden' || fr.width < 1 || fe.type === 'hidden') continue;
    var fl = [], fimg = false;
    for (var fp = fe; fp; fp = fp.parentElement) {
      var fpc = getComputedStyle(fp);
      if (fpc.backgroundImage && fpc.backgroundImage !== 'none' && fp !== document.body && fp !== document.documentElement) fimg = true;
      var fb = parse(fpc.backgroundColor);
      if (fb && fb.a > 0) { fl.push(fb); if (fb.a >= 1) break; }
    }
    o.fields = (o.fields || 0) + 1;
    if (fimg) { o.unmeasured++; continue; }
    var fbase = { r: 255, g: 255, b: 255, a: 1 };
    for (var fk = fl.length - 1; fk >= 0; fk--) fbase = over(fl[fk], fbase);
    var ph = parse(getComputedStyle(fe, '::placeholder').color);
    if (!ph) { o.unmeasured++; continue; }
    var phe = over(ph, fbase), phr = ratio(phe, fbase);
    o.runs++;
    if (phr + 0.005 < 4.5) o.bad.push({ sig: sig(fe) + '::placeholder', fg: hex(phe), bg: hex(fbase), ratio: Math.round(phr * 100) / 100, need: 4.5, size: parseFloat(fcs.fontSize), n: 1, text: fe.getAttribute('placeholder').slice(0, 30) });
  }
  return o;
}

var OVERFLOW_EXPR = '(' + overflowProbe.toString() + ')()';
var CLIP_EXPR = '(' + clipProbe.toString() + ')()';
var CONTRAST_EXPR = '(' + contrastProbe.toString() + ')()';

/* Pure verdict helpers. A probe with nothing measured is NOT CHECKED upstream (the ledger turns n = 0 into it). */
function overflowOk(o) { return !!o && o.scrollX <= 0 && o.escaped.length === 0; }
function overflowDetail(o) {
  return 'viewport ' + o.vw + 'px, document wider by ' + Math.max(0, o.scrollX) + 'px, ' + o.escaped.length + ' box(es) outside it' + (o.escaped.length ? ': ' + o.escaped.slice(0, 4).join(' | ') : '') +
    '; ' + o.inScroller + ' inside a scroller or clipping box, ' + o.ariaHidden + ' decorative (aria-hidden)';
}
function clipDetail(o) {
  return o.clipped.length ? o.clipped.length + ' clipped text run(s): ' + o.clipped.slice(0, 4).join(' | ') : '0 clipped; ' + o.ellipsis + ' ellipsis cut(s) by design, ' + o.ariaHidden + ' decorative runs, ' + o.srOnly + ' screen-reader-only runs left out';
}
function contrastDetail(o) {
  var b = o.bad.slice().sort(function (a, c) { return a.ratio - c.ratio; });
  return (b.length ? b.length + ' failing pair(s): ' + b.slice(0, 6).map(function (x) { return x.sig + ' ' + x.fg + ' on ' + x.bg + ' = ' + x.ratio + ' (need ' + x.need + ', ' + x.size + 'px, x' + x.n + ' "' + x.text + '")'; }).join(' | ') : '0 failing pairs') +
    '; ' + o.unmeasured + ' run(s) over an image or gradient not measured, ' + o.transparent + ' at opacity 0 (not painted), ' + o.ariaHiddenSkipped + ' aria-hidden left out';
}

module.exports = { OVERFLOW_EXPR: OVERFLOW_EXPR, CLIP_EXPR: CLIP_EXPR, CONTRAST_EXPR: CONTRAST_EXPR, overflowOk: overflowOk, overflowDetail: overflowDetail, clipDetail: clipDetail, contrastDetail: contrastDetail };
