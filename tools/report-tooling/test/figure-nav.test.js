'use strict';
var test = require('node:test');
var assert = require('node:assert');
var JSDOM = require('jsdom').JSDOM;
var FN = require('../../../assets/js/figure-nav.js');

function docWith(html) {
  return new JSDOM('<div class="hl-post-content">' + html + '</div>').window.document;
}
function fig(name) {
  return '<figure><img loading="lazy" src="/assets/images/slug/' + name +
    '" alt="x"><figcaption>cap</figcaption></figure>';
}
var PARTS = [
  { label: 'One', anchor: '#one' },
  { label: 'Two', anchor: '#two' }
];

test('renders one chip per part into the matching figure', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body, [{ image: 'a.svg', parts: PARTS }], d), 1);
  var chips = body.querySelectorAll('.hl-fignav__chip');
  assert.strictEqual(chips.length, 2);
  assert.strictEqual(chips[0].getAttribute('href'), '#one');
  assert.strictEqual(chips[0].textContent, 'One');
});

test('the chip row lands inside the figure, after the caption', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  var f = body.querySelector('figure');
  assert.strictEqual(f.lastElementChild.tagName, 'NAV');
  assert.strictEqual(f.lastElementChild.previousElementSibling.tagName, 'FIGCAPTION');
});

test('the basename matches regardless of the path in front of it', function () {
  var d = docWith('<figure><img src="/deep/nested/path/a.svg"><figcaption>c</figcaption></figure>');
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body, [{ image: 'a.svg', parts: PARTS }], d), 1);
});

test('an entry naming an image that is not on the page renders nothing', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body, [{ image: 'ghost.svg', parts: PARTS }], d), 0);
  assert.strictEqual(body.querySelectorAll('.hl-fignav').length, 0);
});

test('an ambiguous image matching two figures renders nothing, not an arbitrary one', function () {
  var d = docWith(fig('a.svg') + fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body, [{ image: 'a.svg', parts: PARTS }], d), 0);
  assert.strictEqual(body.querySelectorAll('.hl-fignav').length, 0);
});

test('render is idempotent, so a second call does not double the chips', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  assert.strictEqual(body.querySelectorAll('.hl-fignav').length, 1);
  assert.strictEqual(body.querySelectorAll('.hl-fignav__chip').length, 2);
});

test('the nav carries an accessible label', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  assert.ok(body.querySelector('.hl-fignav').getAttribute('aria-label'));
});

test('malformed entries are skipped rather than thrown on', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body, [null, {}, { image: 'a.svg' },
    { image: 'a.svg', parts: [] }], d), 0);
});

test('a figure whose only usable part is malformed gets no empty nav', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  assert.strictEqual(FN.render(body,
    [{ image: 'a.svg', parts: [{ label: '', anchor: '' }, { label: '', anchor: '' }] }], d), 0);
  assert.strictEqual(body.querySelectorAll('.hl-fignav').length, 0);
});

test('clicking a chip marks its destination heading', function () {
  var d = docWith(fig('a.svg') + '<h3 id="one">One</h3>');
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  FN.bindMarking(body, d);
  body.querySelector('.hl-fignav__chip').dispatchEvent(
    new d.defaultView.MouseEvent('click', { bubbles: true }));
  assert.ok(d.getElementById('one').classList.contains('hl-fignav-target'));
});

test('clicking a chip whose destination is missing does not throw', function () {
  var d = docWith(fig('a.svg'));
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  FN.bindMarking(body, d);
  assert.doesNotThrow(function () {
    body.querySelector('.hl-fignav__chip').dispatchEvent(
      new d.defaultView.MouseEvent('click', { bubbles: true }));
  });
});

test('a chip is a real link, so default navigation is never prevented', function () {
  var d = docWith(fig('a.svg') + '<h3 id="one">One</h3>');
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: PARTS }], d);
  FN.bindMarking(body, d);
  var ev = new d.defaultView.MouseEvent('click', { bubbles: true, cancelable: true });
  body.querySelector('.hl-fignav__chip').dispatchEvent(ev);
  assert.strictEqual(ev.defaultPrevented, false);
});

test('an anchor with a percent-encoded id still resolves', function () {
  var d = docWith(fig('a.svg') + '<h3 id="caf\u00e9">x</h3><h3 id="two">y</h3>');
  var body = d.querySelector('.hl-post-content');
  FN.render(body, [{ image: 'a.svg', parts: [
    { label: 'A', anchor: '#caf%C3%A9' }, { label: 'B', anchor: '#two' }] }], d);
  FN.bindMarking(body, d);
  body.querySelector('.hl-fignav__chip').dispatchEvent(
    new d.defaultView.MouseEvent('click', { bubbles: true }));
  assert.ok(d.getElementById('caf\u00e9').classList.contains('hl-fignav-target'));
});
