'use strict';
/* T-0500.1.12 rule 5: the defang-aware completeness mode (`--defang`). Controls required by the brief:
     1. a page with one defanged IP passes against its raw baseline
     2. a page with one defanged IP plus one removed word FAILs
     3. a page where a word was changed into something that is not a defang form FAILs
   and the mode must be off by default (exact comparison), and must count what it normalised.
   Fixture addresses are documentation ranges (RFC 5737), never real infrastructure. */
var test = require('node:test');
var assert = require('node:assert');
var C = require('../check-report-text.js');

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
