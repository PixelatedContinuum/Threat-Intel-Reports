'use strict';
/* T-0500.1.12 rule 5: the defang-aware completeness mode (`--defang`). Controls required by the brief:
     1. a page with one defanged IP passes against its raw baseline
     2. a page with one defanged IP plus one removed word FAILs
     3. a page where a word was changed into something that is not a defang form FAILs
   and the mode must be off by default (exact comparison), and must count what it normalised.
   Fixture addresses are documentation ranges (RFC 5737), never real infrastructure. */
var test = require('node:test');
var assert = require('node:assert');
var C = require(process.env.CRT_CHECKER || '../check-report-text.js');   // CRT_CHECKER: run the tests against another copy (the old checker, to show they fail)

var ZERO_COUNTS = { headings: 1, tables: 0, rows: 0, figures: 0, images: 0,
  teardowns: 0, details: 0, 'code blocks': 0, links: 0, lists: 0 };
function page(text) {
  return { text: text, chars: text.length, counts: JSON.parse(JSON.stringify(ZERO_COUNTS)),
    ids: ['x'], idSeq: ['x'], chromeIds: [],
    hidden: { words: 0, nodes: 0, samples: [], noBoxWords: 0, noBoxNodes: 0, noBoxSamples: [], collapsedWords: 0 } };
}
var IP = '198.51.100.17', IPD = '198[.]51[.]100[.]17';
var RAW = 'The operator connected to ' + IP + ' over the session and then dropped the loader onto the host before leaving the network';
var DEF = { defang: true };

test('control 1: one defanged IP passes against its raw baseline, and the three tokens are counted', function () {
  var r = C.compare(page(RAW), page(RAW.replace(IP, IPD)), DEF);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.deepStrictEqual(r.defang, { baseline: 0, page: 3 }, 'three [.] tokens normalised on the page, none on the baseline');
});

test('the same pair FAILS without the flag: the mode is opt-in and the default stays exact', function () {
  var r = C.compare(page(RAW), page(RAW.replace(IP, IPD)));
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.defang, null);
});

test('control 2: one defanged IP plus one removed word FAILs, with exactly the removed word missing', function () {
  var p = RAW.replace(IP, IPD).replace(' loader', '');
  var r = C.compare(page(RAW), page(p), DEF);
  assert.strictEqual(r.status, 'FAIL');
  assert.strictEqual(r.missing, 1);
  assert.strictEqual(r.added, 0);
});

test('control 3: a word changed into something that is not a defang form FAILs', function () {
  [
    RAW.replace(IP, '198(dot)51(dot)100(dot)17'),   // a different defang style
    RAW.replace(IP, '198[,]51[.]100[.]17'),          // one wrong bracket
    RAW.replace(IP, '198[dot]51.100.17'),
    RAW.replace('loader', 'l[o]ader'),               // a bracket that is not at a token start
    RAW.replace('loader', '[l]oader[s]'),            // bracket form plus an altered word
    RAW.replace('host', 'ho5t'),                     // a plain edit
    RAW.replace('connected', '[connected]')          // more than one char bracketed
  ].forEach(function (p) {
    var r = C.compare(page(RAW), page(p), DEF);
    assert.strictEqual(r.status, 'FAIL', 'should FAIL: ' + p.slice(0, 80));
  });
});

test('rule 1 forms: hxxp(s), fxp, [@] and [.] all normalise; a bare hxxp word does not', function () {
  var base = 'fetch http://evil.example.com/a and https://evil.example.com/b and ftp://x.example.org then mail user@host.example.net now';
  var def = 'fetch hxxp://evil[.]example[.]com/a and hxxps://evil[.]example[.]com/b and fxp://x[.]example[.]org then mail user[@]host[.]example[.]net now';
  var r = C.compare(page(base), page(def), DEF);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  // 3 schemes + 1 at-sign + 7 dots (2+2+1... counted: evil[.]example[.]com x2 = 4, x[.]example[.]org = 2, host[.]example[.]net = 2) = 3 + 1 + 8
  assert.strictEqual(r.defang.page, 12);
  var r2 = C.compare(page('the hxxp word'), page('the http word'), DEF);
  assert.strictEqual(r2.status, 'FAIL', 'hxxp not followed by :// is a word, not a scheme');
});

test('rule 2 forms: a bracketed first character of a command token normalises; citations and lone brackets do not', function () {
  var base = 'run powershell -ep bypass then reg add and wget x ; sudo chmod 777 and see [1] and [x] and a[b]c';
  var def = 'run [p]owershell -ep bypass then [r]eg add and [w]get x ; sudo [c]hmod 777 and see [1] and [x] and a[b]c';
  var r = C.compare(page(base), page(def), DEF);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.defang.page, 4);
  // a bracket the rules do not allow is a change
  assert.strictEqual(C.compare(page('run powershell now'), page('run powershell[x] now'), DEF).status, 'FAIL');
  assert.strictEqual(C.compare(page('run powershell now'), page('run [po]wershell now'), DEF).status, 'FAIL');
});

test('a baseline that is already defanged normalises the same way (symmetric), and both counts are reported', function () {
  var both = 'seen at 10[.]0[.]0[.]1 earlier';
  var r = C.compare(page(both), page(both), DEF);
  assert.strictEqual(r.status, 'PASS');
  assert.deepStrictEqual(r.defang, { baseline: 3, page: 3 });
});

test('defangNormalise changes only what rules 1 and 2 name', function () {
  var s = 'a[.]b (c)[.] hxxps://x [p]s [@] [1] [.] [a][b] x.y';
  var n = C.defangNormalise(s);
  assert.strictEqual(n.text, 'a.b (c). https://x ps @ [1] . [a][b] x.y');
  assert.strictEqual(n.tokens, 6);
});

/* T-0500.1.12 harden2: links converted to text, derived from the markdown; IPv6 [:] */
function withLinks(p, n) { var q = page(p); q.counts.links = n; return q; }
var MD_LINK = 'The loader came from [Source: github.com/example-actor](https://github.com/example-actor/loader) and the other note is [vendor](https://vendor.example/post).\n';
var MD_TEXT = 'The loader came from Source: github[.]com/example-actor and the other note is [vendor](https://vendor.example/post).\n';
var TXT = 'The loader came from Source: github.com/example-actor and the other note is vendor and then the session ended with no further activity seen';
var TXTD = TXT.replace('github.com', 'github[.]com');

test('links control 1: one link converted to text in the source PASSes with one link fewer on the page', function () {
  var lc = C.linksConverted(MD_LINK, MD_TEXT);
  assert.strictEqual(lc.count, 1);
  var r = C.compare(withLinks(TXT, 2), withLinks(TXTD, 1), { defang: true, linksConverted: lc.count });
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.linksConverted, 1);
});

test('links control 2: one link silently dropped (text kept, the source still links it) FAILs on the link count', function () {
  var lc = C.linksConverted(MD_LINK, MD_LINK);
  assert.strictEqual(lc.count, 0, 'the markdown converted nothing, so nothing may drop');
  var r = C.compare(withLinks(TXT, 2), withLinks(TXT, 1), { defang: true, linksConverted: lc.count });
  assert.strictEqual(r.status, 'FAIL');
  assert.deepStrictEqual(r.countProblems, ['links 2 baseline vs 1 page']);
});

test('links: the allowance is exact, one conversion in the source does not excuse a second link lost on the page', function () {
  var lc = C.linksConverted(MD_LINK, MD_TEXT);
  var r = C.compare(withLinks(TXT, 2), withLinks(TXTD, 0), { defang: true, linksConverted: lc.count });
  assert.strictEqual(r.status, 'FAIL');
  assert.match(r.countProblems[0], /^links 2 baseline vs 0 page/);
});

test('links: a conversion that is not in the source gives no allowance (no markdown, no drop; flag off, no drop)', function () {
  assert.strictEqual(C.compare(withLinks(TXT, 2), withLinks(TXTD, 1), { defang: true }).status, 'FAIL');
  assert.strictEqual(C.compare(withLinks(TXT, 2), withLinks(TXT, 1), { linksConverted: 1 }).status, 'FAIL', 'the count is only honoured in --defang mode');
});

test('links: a link REMOVED together with its text is not a conversion (the words are gone, FAIL)', function () {
  var lc = C.linksConverted(MD_LINK, 'The loader came from and the other note is [vendor](https://vendor.example/post).\n');
  assert.strictEqual(lc.count, 0);
});

test('links: markdown reader: inline, reference, autolink, html; code and images are not links', function () {
  var md = 'a [one](http://a.example/1) b [two][r] c <http://c.example/3> d <a href="http://d.example/4">four</a> e ![img](http://e.example/i.png) f `[code](http://f.example)`\n' +
    '```\n[fence](http://g.example)\n```\n[r]: http://b.example/2 "title"\n[^1]: footnote text\n';
  var got = C.markdownLinks(md).map(function (l) { return l.target; }).sort();
  assert.deepStrictEqual(got, ['http://a.example/1', 'http://b.example/2', 'http://c.example/3', 'http://d.example/4']);
});

test('links: a target that was only defanged stays a link and is not a conversion', function () {
  var lc = C.linksConverted('See [x](http://h.example/p) now\n', 'See [x](hxxp://h[.]example/p) now\n');
  assert.strictEqual(lc.count, 0);
});

test('IPv6 [:] form: normalises on both sides; a lone [:] and a wrong bracket do not', function () {
  var base = 'The operator reached hxxp://x and then http://[2001:db8::7]/p before leaving the host for the day and returning later on';
  var def = base.replace('hxxp://x', 'http://x').replace('[2001:db8::7]', '[2001[:]db8[:][:]7]');
  var r = C.compare(page(base), page(def), DEF);
  assert.strictEqual(r.status, 'PASS', JSON.stringify(r.problems));
  assert.strictEqual(r.defang.page, 3);
  assert.strictEqual(C.compare(page(base), page(def.replace('db8[:]', 'db8[;]')), DEF).status, 'FAIL');
  assert.strictEqual(C.defangNormalise('slice x[:] and y[:]z').text, 'slice x[:] and y[:]z', 'a [:] not between hex or colon characters is left');
  assert.strictEqual(C.defangNormalise('fe80[:][:]1 and ab[:]cd').text, 'fe80::1 and ab:cd');
});

/* T-0500.1.12 r2fix F4: a link inside an HTML comment renders nothing, so it is neither counted nor an allowance */
test('links F4: a phantom link in an HTML comment is not a link; the allowance cannot mask a silently dropped real link', function () {
  var base = '<!-- [phantom](https://actor.invalid/a) -->\nSee [vendor](https://vendor.invalid/b).';
  var page_ = '<!-- phantom -->\nSee [vendor](https://vendor.invalid/b).';
  assert.deepStrictEqual(C.markdownLinks(base).map(function (l) { return l.target; }), ['https://vendor.invalid/b']);
  var lc = C.linksConverted(base, page_);
  assert.strictEqual(lc.count, 0, 'nothing rendered was converted');
  // the page lost the vendor link in rendering while the source still links it: baseline 1 link vs page 0 must FAIL
  var r = C.compare(withLinks(TXT, 1), withLinks(TXT, 0), { defang: true, linksConverted: lc.count });
  assert.strictEqual(r.status, 'FAIL');
  // multi-line comment too
  assert.strictEqual(C.markdownLinks('<!--\n[a](http://x.example/1)\n-->\n[b](http://y.example/2)\n').length, 1);
  // controls: a genuine one-link conversion still PASSes, a silent drop still FAILs
  var lc2 = C.linksConverted(MD_LINK, MD_TEXT);
  assert.strictEqual(lc2.count, 1);
  assert.strictEqual(C.compare(withLinks(TXT, 2), withLinks(TXTD, 1), { defang: true, linksConverted: lc2.count }).status, 'PASS');
  assert.strictEqual(C.compare(withLinks(TXT, 2), withLinks(TXT, 1), { defang: true, linksConverted: C.linksConverted(MD_LINK, MD_LINK).count }).status, 'FAIL');
});
