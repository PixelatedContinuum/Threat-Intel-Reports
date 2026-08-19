'use strict';

/* The per-feed viewer manifest.

   The embargo cases below are the ones that matter. Three campaigns are live at
   their URL and absent from every listing, which is preview publishing working as
   designed. A rendered page for one of them would be a new public surface for
   content still under disclosure embargo, so the generator must refuse, and must
   refuse for the same reason the search index refuses: BOTH publication signals,
   and a disagreement fails rather than being resolved. */

var test = require('node:test');
var assert = require('node:assert');
var T = require('../lib/ioc-tables.js');

var FEED = {
  network_indicators: [{ value: '185.49.126.140', context: 'C2 server' }, 'evil.test'],
  file_hashes: { sha256: ['a'.repeat(64)] }
};

function feeds(over) {
  return Object.assign({ 'live-iocs.json': FEED, 'held-iocs.json': FEED }, over || {});
}
var STATUS = { 'live-iocs.json': 'published', 'held-iocs.json': 'embargoed' };
var META = { 'live-iocs.json': { title: 'Live Campaign', date: '2026-08-03',
                                 severity: 'high', ioc_url: '/ioc-feeds/live-iocs.json',
                                 report_url: '/reports/live/' } };

test('a published feed gets a table', function () {
  var r = T.build(feeds(), STATUS, META);
  assert.deepEqual(Object.keys(r.tables), ['live']);
  assert.equal(r.tables.live.title, 'Live Campaign');
  assert.equal(r.tables.live.total, 3);
});

test('AN EMBARGOED FEED GETS NO PAGE, AND IS COUNTED', function () {
  var r = T.build(feeds(), STATUS, META);
  assert.equal(r.tables.held, undefined);
  assert.equal(r.skipped.embargoed, 1);
});

test('AN UNKNOWN FEED GETS NO PAGE EITHER, since undefined is not published', function () {
  var r = T.build({ 'mystery-iocs.json': FEED }, {}, {});
  assert.deepEqual(Object.keys(r.tables), []);
  assert.equal(r.skipped.unknown, 1);
});

test('two feeds deriving one page slug is a failure, not a silent overwrite', function () {
  var r = T.build({ 'agent-exe.json': FEED, 'agent-exe-iocs.json': FEED },
                  { 'agent-exe.json': 'published', 'agent-exe-iocs.json': 'published' }, {});
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /same page slug/);
});

test('a feed yielding no typed rows gets no page, and is counted as empty', function () {
  var r = T.build({ 'prose-iocs.json': { notes: ['nothing indicator-shaped here at all'] } },
                  { 'prose-iocs.json': 'published' }, {});
  assert.deepEqual(Object.keys(r.tables), []);
  assert.equal(r.skipped.empty, 1);
});

test('the not-typed count travels with the rows', function () {
  var r = T.build({ 'x-iocs.json': { n: ['185.49.126.140'], Commands: ['curl', 'wget'] } },
                  { 'x-iocs.json': 'published' }, {});
  assert.ok(r.tables.x.untyped >= 2, 'untyped was ' + r.tables.x.untyped);
});

test('per-type counts are emitted, so the filter can label itself', function () {
  var r = T.build(feeds(), STATUS, META);
  assert.deepEqual(r.tables.live.counts, { ipv4: 1, domain: 1, sha256: 1 });
});

test('the URL slug drops -iocs and the extension', function () {
  assert.equal(T.slugOf('cloudsync-91-197-98-188-iocs.json'), 'cloudsync-91-197-98-188');
  assert.equal(T.slugOf('AdvancedRouterScanner.json'), 'AdvancedRouterScanner');
  assert.equal(T.slugOf('my-iocs-collection.json'), 'my-iocs-collection');
});

test('THE MANIFEST KEY MATCHES THE SITE CONVENTION, .json suffix and all', function () {
  // The listing's Liquid does `remove: '-iocs.json'` and generate-ioc-index.js
  // keys its reports the same way, so 27 of the 57 feeds keep a `.json` suffix
  // in their key. That looks wrong and is not: changing it would desynchronise
  // every card's data-slug from the search index that narrows those cards.
  assert.equal(T.keyOf('cloudsync-91-197-98-188-iocs.json'), 'cloudsync-91-197-98-188');
  assert.equal(T.keyOf('AdvancedRouterScanner.json'), 'AdvancedRouterScanner.json');
});

test('key and URL slug are ALLOWED to differ, and the manifest reconciles them', function () {
  var r = T.build({ 'AdvancedRouterScanner.json': FEED },
                  { 'AdvancedRouterScanner.json': 'published' }, {});
  var k = 'AdvancedRouterScanner.json';
  assert.ok(r.tables[k], 'keyed by the site convention');
  assert.equal(r.tables[k].slug, 'AdvancedRouterScanner');
  // The URL is CARRIED, so no Liquid rule has to derive it and none can drift.
  assert.equal(r.tables[k].page_url, '/ioc-feeds/AdvancedRouterScanner/');
});

test('a directory is never named after the key, which would collide with the feed file',
  function () {
    var r = T.build({ 'AdvancedRouterScanner.json': FEED },
                    { 'AdvancedRouterScanner.json': 'published' }, {});
    assert.ok(r.tables['AdvancedRouterScanner.json'].page_url.indexOf('.json/') === -1);
  });

test('the stub carries the manifest key and the carried URL', function () {
  var s = T.stub('live', { title: 'Live Campaign', page_url: '/ioc-feeds/live/' });
  assert.match(s, /ioc_slug: "live"/);
  assert.match(s, /permalink: \/ioc-feeds\/live\//);
  assert.match(s, /layout: ioc-table/);
});

test('a title carrying a quote or a colon survives into the stub', function () {
  var s = T.stub('x', { title: 'CloudSync: An "Assembler\'s" Toolkit' });
  assert.ok(s.indexOf('\\"Assembler') > -1, 'quote not escaped: ' + s);
});

test('YAML round-trips through js-yaml, quotes and colons included', function () {
  var yaml = require('js-yaml');
  var r = T.build({ 'x-iocs.json': { n: [{ value: '185.49.126.140',
                                           context: 'C2: the "main" one' }] } },
                  { 'x-iocs.json': 'published' },
                  { 'x-iocs.json': { title: 'A: B "C"' } });
  var doc = yaml.load(T.toYaml(r.tables));
  assert.equal(doc.x.title, 'A: B "C"');
  assert.equal(doc.x.rows[0].context, 'C2: the "main" one');
  assert.equal(doc.x.rows[0].value, '185.49.126.140');
});

test('a backslash in a path survives YAML, which is why paths are typed at all', function () {
  var yaml = require('js-yaml');
  var win = 'C:' + String.fromCharCode(92) + 'Windows' + String.fromCharCode(92) + 'x.exe';
  var r = T.build({ 'x-iocs.json': { h: [win] } }, { 'x-iocs.json': 'published' }, {});
  var doc = yaml.load(T.toYaml(r.tables));
  assert.equal(doc.x.rows[0].value, win);
  assert.equal(doc.x.rows[0].type, 'path');
});

test('output is stable across runs, so a regeneration diffs cleanly', function () {
  assert.equal(T.toYaml(T.build(feeds(), STATUS, META).tables),
               T.toYaml(T.build(feeds(), STATUS, META).tables));
});
