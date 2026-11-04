'use strict';

/* The pure verdict helpers of lib/page-sweep.js (T-0556 w6). The in-page expressions need a browser and are exercised by
   check-browser-home.js and check-browser-sweep.js, each with a control that must fail; what is tested here is that the
   helpers never turn an escape or a failing pair into a pass. */

var test = require('node:test');
var assert = require('node:assert');
var W = require('../lib/page-sweep.js');

test('overflowOk fails on a document wider than the viewport and on one box outside it', function () {
  assert.equal(W.overflowOk({ vw: 390, scrollX: 0, painted: 10, escaped: [], inScroller: 0, ariaHidden: 0 }), true);
  assert.equal(W.overflowOk({ vw: 390, scrollX: 12, painted: 10, escaped: [], inScroller: 0, ariaHidden: 0 }), false);
  assert.equal(W.overflowOk({ vw: 390, scrollX: 0, painted: 10, escaped: ['div 16..416'], inScroller: 0, ariaHidden: 0 }), false);
  assert.equal(W.overflowOk(null), false);
});

test('the detail lines carry the numbers a reader needs', function () {
  assert.match(W.overflowDetail({ vw: 390, scrollX: 5, painted: 3, escaped: ['a 0..400'], inScroller: 2, ariaHidden: 1 }), /390px.*5px.*1 box.*a 0\.\.400.*2 inside a scroller.*1 decorative/);
  assert.match(W.clipDetail({ runs: 3, clipped: ['div.x holds p "Long text"'], ellipsis: 0, ariaHidden: 0, srOnly: 0 }), /1 clipped text run/);
  assert.match(W.clipDetail({ runs: 3, clipped: [], ellipsis: 2, ariaHidden: 4, srOnly: 5 }), /0 clipped; 2 ellipsis.*4 decorative.*5 screen-reader/);
  var d = W.contrastDetail({ runs: 5, unmeasured: 1, transparent: 2, ariaHiddenSkipped: 3, bad: [{ sig: 'p.x', fg: '#444444', bg: '#111111', ratio: 1.9, need: 4.5, size: 16, n: 2, text: 'dim' }] });
  assert.match(d, /1 failing pair.*p\.x #444444 on #111111 = 1\.9 \(need 4\.5.*x2 "dim"\).*1 run\(s\) over an image.*2 at opacity 0.*3 aria-hidden/);
  assert.match(W.contrastDetail({ runs: 1, unmeasured: 0, transparent: 0, ariaHiddenSkipped: 0, bad: [] }), /^0 failing pairs/);
});

test('the in-page expressions are self-contained function calls', function () {
  [W.OVERFLOW_EXPR, W.CLIP_EXPR, W.CONTRAST_EXPR].forEach(function (e) {
    assert.match(e, /^\(function \w+\(\)/);
    assert.match(e, /\)\(\)$/);
    assert.doesNotThrow(function () { new Function('return ' + e); });
  });
});
