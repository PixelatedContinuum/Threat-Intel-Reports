'use strict';

/* Tests for the indicator search on /ioc-feeds/.

   The search narrows the EXISTING feed-card grid rather than rendering its own
   result list, which means two scripts share one grid. They cooperate through a
   `data-veto` attribute plus an `hl:refilter` event, because two scripts both
   writing `style.display` would race and the loser would silently win half the
   time.

   jsdom has no layout, so these prove the SELECTION and the cooperation. How it
   looks stays a browser check. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var ROOT = path.join(__dirname, '..', '..', '..');
var CLASSIFY = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'ioc-classify.js'), 'utf8');
var SEARCH = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'ioc-search.js'), 'utf8');
var FILTER = fs.readFileSync(path.join(ROOT, 'assets', 'js', 'listing-filter.js'), 'utf8');

var INDEX = {
  counts: { indicators: 2, reports: 2, multi_report: 1 },
  reports: { alpha: { title: 'Alpha' }, beta: { title: 'Beta' } },
  indicators: {
    'ipv4:185.38.150.7': [{ report: 'alpha', role: 'C2 server' }],
    'domain:shared.test': [{ report: 'alpha' }, { report: 'beta' }]
  }
};

var PAGE =
  '<div class="hl-iocsearch">' +
    '<textarea class="hl-iocsearch__in"></textarea>' +
    '<button class="hl-iocsearch__clear" hidden>Clear</button>' +
    '<div class="hl-iocsearch__result"></div>' +
    '<div class="hl-iocsearch__detail"></div>' +
  '</div>' +
  '<div class="hl-filter" data-listing-filter>' +
    '<input class="hl-filter__search">' +
    '<div class="hl-filter__chips"><button class="hl-chip-btn is-on" data-tag="">All</button></div>' +
    '<div class="hl-filter__count" data-filter-count></div>' +
    '<div class="hl-filter__empty" data-filter-empty hidden></div>' +
  '</div>' +
  '<div class="hl-grid" data-filter-grid>' +
    '<a class="hl-card hl-catalog-card" data-slug="alpha" data-title="alpha feed" data-tags=""></a>' +
    '<a class="hl-card hl-catalog-card" data-slug="beta" data-title="beta feed" data-tags=""></a>' +
    '<a class="hl-card hl-catalog-card" data-slug="gamma" data-title="gamma feed" data-tags=""></a>' +
  '</div>';

function build(url) {
  var dom = new JSDOM('<body>' + PAGE + '</body>', { runScripts: 'outside-only', url: url || 'http://localhost/ioc-feeds/' });
  var w = dom.window;
  w.fetch = function () {
    return Promise.resolve({ ok: true, json: function () { return Promise.resolve(INDEX); } });
  };
  w.eval(CLASSIFY);
  w.eval(FILTER);
  w.eval(SEARCH);
  return w;
}

function type(w, value) {
  var input = w.document.querySelector('.hl-iocsearch__in');
  input.value = value;
  input.dispatchEvent(new w.Event('input', { bubbles: true }));
  // The search debounces, then resolves a promise before dispatching refilter.
  return new Promise(function (r) { setTimeout(r, 300); });
}

function visible(w) {
  return [].slice.call(w.document.querySelectorAll('.hl-catalog-card'))
    .filter(function (c) { return c.style.display !== 'none'; })
    .map(function (c) { return c.getAttribute('data-slug'); });
}

function resultText(w) {
  return w.document.querySelector('.hl-iocsearch__result').textContent;
}

test('all cards show before any search', function () {
  var w = build();
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
});

test('a known indicator narrows the grid to its feed', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.deepEqual(visible(w), ['alpha']);
  assert.match(resultText(w), /appears in 1 feed/);
});

test('an indicator in two feeds shows both cards', async function () {
  var w = build();
  await type(w, 'shared.test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /appears in 2 feeds/);
});

test('a defanged paste matches, because that is how people copy indicators', async function () {
  var w = build();
  await type(w, 'shared[.]test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
});

test('an unknown indicator hides nothing and says so plainly', async function () {
  var w = build();
  await type(w, '203.0.113.99');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma'],
    'a miss must not leave the reader with an empty page');
  assert.match(resultText(w), /does not appear in any published feed/);
});

test('text that is not an indicator at all says that, not "no match"', async function () {
  var w = build();
  await type(w, 'the quick brown fox');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.match(resultText(w), /Nothing in that text looks like an IP, domain, URL or hash/);
});

test('clearing the box restores every card', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.deepEqual(visible(w), ['alpha']);
  await type(w, '');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.equal(resultText(w), '');
});

test('the Clear button restores every card', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  var btn = w.document.querySelector('.hl-iocsearch__clear');
  assert.equal(btn.hidden, false, 'Clear appears once there is something to clear');
  btn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
});

test('a ?q= deep link lands with the search already run, so a tool can link one indicator', async function () {
  var w = build('http://localhost/ioc-feeds/?q=185.38.150.7');
  await new Promise(function (r) { setTimeout(r, 300); });
  // The box is filled with the DEFANGED form (fix-r1, finding 1): a link that carries a live indicator does not put it on the page; the search refangs it, so the card still narrows.
  assert.equal(w.document.querySelector('.hl-iocsearch__in').value, '185[.]38[.]150[.]7');
  assert.deepEqual(visible(w), ['alpha']);
  assert.match(resultText(w), /appears in 1 feed/);
  assert.equal(w.document.querySelector('.hl-iocsearch__clear').hidden, false);
});

test('a ?q= list is decoded (commas, %0A newlines, + for space) and searched in full', async function () {
  // The hash's q= is the card-title filter (listing-filter.js); "feed" matches
  // every card here, so the two q's coexist and the search still decides.
  var w = build('http://localhost/ioc-feeds/?utm=x&q=185.38.150.7%2C%0Ashared.test+#q=feed');
  await new Promise(function (r) { setTimeout(r, 300); });
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  // Other parameters and the filter's own hash are left alone.
  assert.equal(w.location.search, '?utm=x&q=185%5B.%5D38%5B.%5D150%5B.%5D7%2C%0Ashared%5B.%5Dtest');
  assert.equal(w.location.hash, '#q=feed');
  assert.equal(w.document.querySelector('.hl-filter__search').value, 'feed');
});

test('typing mirrors the box into ?q= and clearing drops it, so the address bar is always the link to copy', async function () {
  var w = build();
  assert.equal(w.location.search, '');
  await type(w, 'shared.test');
  assert.equal(w.location.search, '?q=shared.test');
  assert.equal(w.history.length, 1, 'replaceState, never a history entry per keystroke');
  await type(w, '');
  assert.equal(w.location.search, '');
  await type(w, '185.38.150.7');
  w.document.querySelector('.hl-iocsearch__clear').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.equal(w.location.search, '');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
});

test('a ?q= that is not an indicator says so rather than hiding cards', async function () {
  var w = build('http://localhost/ioc-feeds/?q=hello%20there');
  await new Promise(function (r) { setTimeout(r, 300); });
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.match(resultText(w), /Nothing in that text looks like/);
});

test('the name filter and the indicator search AND together', async function () {
  var w = build();
  await type(w, 'shared.test');           // alpha + beta
  var nameBox = w.document.querySelector('.hl-filter__search');
  nameBox.value = 'beta';
  nameBox.dispatchEvent(new w.Event('input', { bubbles: true }));
  assert.deepEqual(visible(w), ['beta'], 'the two controls must narrow, not fight');
});

test('pasting several indicators unions their feeds', async function () {
  var w = build();
  await type(w, '185.38.150.7 and shared.test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 2/);
});

// Built from a code point rather than an escape: a newline written as a
// backslash escape kept getting mangled by the tooling that authored this file.
var NL = String.fromCharCode(10);
var LIST = ['185.38.150.7', 'shared.test', '203.0.113.99'];

function detailText(w) {
  return w.document.querySelector('.hl-iocsearch__detail').textContent;
}

test('a NEWLINE separated list works, which is how lists are actually pasted', async function () {
  // This is the regression. `<input type="text">` strips newlines from pasted
  // content, so a pasted list collapsed into one string; the concatenation once
  // ended in ".test" and was classified as a single domain, reporting a clean
  // "not in any feed" for a list that was mostly real.
  var w = build();
  await type(w, LIST.join(NL));
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a comma separated list works', async function () {
  var w = build();
  await type(w, '185.38.150.7, shared.test, 203.0.113.99');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a list gets a per-indicator breakdown naming each feed', async function () {
  // Narrowing 54 cards to 21 tells someone who pasted 40 indicators nothing
  // about WHICH of theirs matched. For a list, the breakdown is the answer.
  var w = build();
  await type(w, LIST.join(NL));
  var t = detailText(w);
  assert.match(t, /185\[\.\]38\[\.\]150\[\.\]7/, 'names the matched indicator, defanged');
  assert.match(t, /Alpha/, 'names the feed it is in');
  assert.match(t, /1 of your indicators are not in any published feed/,
    'and says how many missed');
});

test('a single indicator gets NO breakdown, the card is enough', async function () {
  var w = build();
  await type(w, '185.38.150.7');
  assert.equal(detailText(w), '');
});

test('a messy real-world paste survives quoting and trailing punctuation', async function () {
  var w = build();
  await type(w, 'src="185.38.150.7", host=shared.test;' + NL + '  203.0.113.99  ');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.match(resultText(w), /2 of your 3/);
});

test('a very large paste is searched in full and never resizes the box', async function () {
  // The box is a fixed height that scrolls internally: a reader cannot see the
  // whole list, but nothing below it moves and every pasted value is searched.
  var w = build();
  var box = w.document.querySelector('.hl-iocsearch__in');
  var before = box.style.height;
  var many = [];
  for (var i = 0; i < 400; i++) many.push('10.9.' + (i >> 8) + '.' + (i & 255));
  many.push('185.38.150.7');          // one real one buried at the end
  await type(w, many.join(NL));
  assert.equal(box.style.height, before, 'the script must never set a height');
  assert.deepEqual(visible(w), ['alpha'], 'the buried real indicator is still found');
  assert.match(resultText(w), /1 of your 401/);
});

test('the breakdown caps rather than building unbounded DOM', async function () {
  var w = build();
  var many = [];
  for (var i = 0; i < 300; i++) many.push('shared.test');   // dedupes to one
  many.push('185.38.150.7');
  await type(w, many.join(NL));
  // extract() dedupes, so this is 2 unique indicators, both real.
  assert.match(resultText(w), /2 of your 2/);
  assert.ok(w.document.querySelectorAll('.hl-iocsearch__row').length <= 202,
    'the breakdown is bounded');
});

/* --- withheld: never-block values, 2026-09-13 -----------------------------

   idx.never_block mirrors idx.indicators, but for values a feed marks
   hunt_only_never_block. Without this bucket a withheld value would silently
   join `missed` and read as "we have no data on this", the exact "empty
   result is not an absence" failure this project keeps writing down. These
   fixtures add a never_block map only; every test above still runs against
   the original INDEX with no such map, proving the addition is additive. */

var INDEX_NB = Object.assign({}, INDEX, {
  never_block: {
    'domain:api.telegram.org': [{ report: 'alpha', role: 'Shared platform, do not block' }]
  }
});

function buildWith(index, url) {
  var dom = new JSDOM('<body>' + PAGE + '</body>', url ? { runScripts: 'outside-only', url: url } : { runScripts: 'outside-only' });
  var w = dom.window;
  w.fetch = function () {
    return Promise.resolve({ ok: true, json: function () { return Promise.resolve(index); } });
  };
  w.eval(CLASSIFY);
  w.eval(FILTER);
  w.eval(SEARCH);
  return w;
}

test('a withheld value narrows to its feed and says it is intentionally excluded, not "no data"', async function () {
  var w = buildWith(INDEX_NB);
  await type(w, 'api.telegram.org');
  assert.deepEqual(visible(w), ['alpha'], 'the card still narrows so the reader can read why');
  assert.match(resultText(w), /deliberately left out of this index/);
  assert.doesNotMatch(resultText(w), /does not appear in any published feed/,
    'a withheld value must never read the same as a genuine miss');
});

test('a withheld value gets its own result class, not --hit or --none', async function () {
  var w = buildWith(INDEX_NB);
  await type(w, 'api.telegram.org');
  var result = w.document.querySelector('.hl-iocsearch__result');
  assert.ok(result.className.indexOf('--withheld') > -1, result.className);
});

test('a value with no data at all is still a genuine miss, unaffected by never_block existing', async function () {
  var w = buildWith(INDEX_NB);
  await type(w, '203.0.113.99');
  assert.deepEqual(visible(w), ['alpha', 'beta', 'gamma']);
  assert.match(resultText(w), /does not appear in any published feed/);
});

test('a list mixing a real hit, a withheld value and a genuine miss reports all three', async function () {
  var w = buildWith(INDEX_NB);
  await type(w, '185.38.150.7' + NL + 'api.telegram.org' + NL + '203.0.113.99');
  assert.deepEqual(visible(w), ['alpha']);
  var text = resultText(w);
  assert.match(text, /1 of your 3/, 'the matched count still counts only real hits');
  assert.match(text, /1 is intentionally left out/);
  var detail = detailText(w);
  assert.match(detail, /api\[\.\]telegram\[\.\]org/);
  assert.match(detail, /intentionally excluded/);
  assert.match(detail, /1 of your indicators are not in any published feed/);
});

test('a list of ONLY withheld values still narrows the grid and never says "none appear"', async function () {
  var w = buildWith(INDEX_NB);
  await type(w, 'api.telegram.org');
  assert.deepEqual(visible(w), ['alpha']);
});

test('WHAT THE READER SEES WITHOUT THIS FIX: a plain miss is indistinguishable from a withheld value', function () {
  // Documents the failure mode being closed, using the ORIGINAL two-bucket
  // logic directly rather than the shipped code, so this test cannot pass by
  // accident if the withheld branch is ever deleted.
  var idx = INDEX_NB;
  var hits = idx.indicators['domain:api.telegram.org'];
  var nb = idx.never_block['domain:api.telegram.org'];
  assert.equal(hits, undefined, 'api.telegram.org has no ordinary indicators entry');
  assert.ok(nb, 'but it does have a recorded reason not to block it');
});


/* ---- fix-r1, review finding 1: nothing this script writes is a live indicator ----
   The reproduction (tasks/runs/T-0500.1.7.4/build/fix-r1/repro-search.cjs) searched the built /ioc-feeds/ page with a defanged address and read the raw address back in the
   result sentence. Every display path is covered here: the single-indicator sentence for a hit, a withheld value and a miss, the breakdown of a list, the report titles read
   from the index (17 of the 60 real titles carry an address), and the box filled from a ?q= link. Controls: a hash is shown as it is, and the matching itself is unchanged
   (the defanged and the raw query find the same card). Addresses are RFC 5737 / RFC 2606 and the fixture's own. */
var LIVE = /(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+\.(?:test|org|com|net|example)\b|https?:\/\//i;
function everything(w, withBox) {
  // the box holds what the reader typed or pasted: theirs, not the page's; it is read only for a ?q= link, which the page fills
  return w.document.querySelector('.hl-iocsearch__result').textContent + '\n' + w.document.querySelector('.hl-iocsearch__detail').textContent +
    (withBox ? '\n' + w.document.querySelector('.hl-iocsearch__in').value : '');
}
var TITLED = {
  counts: { indicators: 3, reports: 1, multi_report: 0 },
  reports: { alpha: { title: 'Open Directory at 203.0.113.9 and evil.example.net (see https://c2.example.org/x)' } },
  indicators: { 'ipv4:203.0.113.9': [{ report: 'alpha' }], 'domain:evil.example.net': [{ report: 'alpha' }], 'url:https://c2.example.org/x': [{ report: 'alpha' }],
    ['sha256:' + 'a'.repeat(64)]: [{ report: 'alpha' }] },
  never_block: { 'domain:cdn.example.com': [{ report: 'alpha' }] }
};
test('a single indicator is displayed defanged, whether it was typed live or defanged', async function () {
  for (var q of ['203.0.113.9', '203[.]0[.]113[.]9']) {
    var w = buildWith(TITLED);
    await type(w, q);
    assert.match(resultText(w), /203\[\.\]0\[\.\]113\[\.\]9 appears in 1 feed/, q);
    assert.deepEqual(visible(w), ['alpha'], 'matching is unchanged: ' + q + ' still finds the feed');
    assert.doesNotMatch(w.document.querySelector('.hl-iocsearch__result').textContent, LIVE, 'no live indicator in the sentence for ' + q);
  }
});
test('a URL is displayed with hxxp(s) and defanged dots; a miss and a withheld value are defanged too', async function () {
  var w = buildWith(TITLED);
  await type(w, 'https://c2.example.org/x');
  assert.match(resultText(w), /hxxps:\/\/c2\[\.\]example\[\.\]org\/x/);
  await type(w, 'http://never-seen.example.net/p');
  assert.match(resultText(w), /hxxp:\/\/never-seen\[\.\]example\[\.\]net\/p does not appear/);
  assert.doesNotMatch(w.document.querySelector('.hl-iocsearch__result').textContent, LIVE);
  await type(w, 'cdn.example.com');
  assert.match(resultText(w), /cdn\[\.\]example\[\.\]com is recorded in 1 feed/);
  assert.doesNotMatch(w.document.querySelector('.hl-iocsearch__result').textContent, LIVE);
});
test('a list: the breakdown shows defanged values and defanged report titles, and nothing live anywhere', async function () {
  var w = buildWith(TITLED);
  await type(w, ['203.0.113.9', 'evil.example.net', 'https://c2.example.org/x', 'cdn.example.com', '198.51.100.7'].join(NL));
  var t = detailText(w);
  assert.match(t, /203\[\.\]0\[\.\]113\[\.\]9/);
  assert.match(t, /Open Directory at 203\[\.\]0\[\.\]113\[\.\]9 and evil\[\.\]example\[\.\]net \(see hxxps:\/\/c2\[\.\]example\[\.\]org\/x\)/, 'the report title read from the index is defanged');
  assert.match(t, /cdn\[\.\]example\[\.\]com/);
  assert.doesNotMatch(everything(w), LIVE, 'result and breakdown: no live address, name or scheme');
});
test('a ?q= link carrying a live indicator is shown defanged in the box and still searched', async function () {
  var w = build('http://localhost/ioc-feeds/?q=185.38.150.7%2Cshared.test');
  await new Promise(function (r) { setTimeout(r, 300); });
  assert.equal(w.document.querySelector('.hl-iocsearch__in').value, '185[.]38[.]150[.]7,shared[.]test');
  assert.deepEqual(visible(w), ['alpha', 'beta']);
  assert.doesNotMatch(everything(w, true), LIVE);
});
test('control: a hash is displayed as it is', async function () {
  var w = buildWith(TITLED);
  await type(w, 'a'.repeat(64));
  assert.match(resultText(w), new RegExp('a{64} appears in 1 feed'));
});

/* ---- fix-r2, review finding S2: a defanged e-mail in a ?q= link finds the same hit as the raw e-mail ----
   The ?q= link box is filled with the DEFANGED form (op[@]evil[.]example[.]org); extract() turned the [@] brackets into token breaks, so the link searched the e-mail's
   DOMAIN instead of the e-mail and reported it absent from every feed while typing the raw e-mail found it. One e-mail fixture, three routes to it. */
var MAILED = {
  counts: { indicators: 2, reports: 1, multi_report: 0 },
  reports: { alpha: { title: 'Mailer feed' } },
  indicators: { 'email:op@evil.example.org': [{ report: 'alpha' }] }
};
test('S2: a raw e-mail, a typed defanged e-mail and a ?q= link carrying the defanged e-mail all find the same feed, and a miss stays a miss', async function () {
  var wr = buildWith(MAILED);
  await type(wr, 'op@evil.example.org');
  assert.deepEqual(visible(wr), ['alpha'], 'raw e-mail typed (control: this already worked)');
  var wt = buildWith(MAILED);
  await type(wt, 'op[@]evil[.]example[.]org');
  assert.deepEqual(visible(wt), ['alpha'], 'defanged e-mail typed');
  assert.match(resultText(wt), /op\[@\]evil\[\.\]example\[\.\]org appears in 1 feed/);
  var wd = buildWith(MAILED, 'http://localhost/ioc-feeds/?q=' + encodeURIComponent('op[@]evil[.]example[.]org'));
  await new Promise(function (r) { setTimeout(r, 300); });
  assert.equal(wd.document.querySelector('.hl-iocsearch__in').value, 'op[@]evil[.]example[.]org');
  assert.deepEqual(visible(wd), ['alpha'], 'the ?q= link carrying the defanged e-mail finds the same hit as typing the raw e-mail');
  assert.match(resultText(wd), /appears in 1 feed/);
  var wm = buildWith(MAILED);
  await type(wm, 'nobody[@]evil[.]example[.]org');
  assert.match(resultText(wm), /nobody\[@\]evil\[\.\]example\[\.\]org does not appear/, 'a defanged e-mail that is not indexed is reported as that e-mail, not as its domain');
});
