'use strict';

/* Scanning and relocating unblockable values in a feed.

   The scan and the migration are one module on purpose. If the gate and the fix
   disagreed about what counts, the gate would pass something the migration would
   have moved, and nothing would say so. */

var test = require('node:test');
var assert = require('node:assert');
var H = require('../lib/feed-hygiene.js');
var U = require('../lib/unblockable.js');

function feed(over) {
  return Object.assign({
    metadata: {
      campaign: 'Demo',
      reference: 'https://the-hunters-ledger.com/reports/demo/'
    },
    network_indicators: {
      domains: [
        { value: 'evilsoul.cc', context: 'C2 panel', confidence: 'HIGH' },
        { value: 'api.telegram.org', context: 'exfiltration channel', confidence: 'HIGH' }
      ],
      ips: ['185.49.126.140']
    },
    file_hashes: { sha256: ['a'.repeat(64)] }
  }, over || {});
}

test('an unblockable value in an indicator bucket is found', function () {
  var f = H.scan(feed());
  assert.equal(f.length, 1);
  assert.equal(f[0].host, 'api.telegram.org');
  assert.equal(f[0].category, 'messaging platform');
});

test('THE METADATA BACKLINK TO OUR OWN SITE IS NOT A FINDING', function () {
  // the-hunters-ledger.com appears in 2 feeds, both times as metadata.reference.
  // Flagging it would be a false positive on every feed we publish.
  var hits = H.scan(feed()).map(function (x) { return x.host; });
  assert.ok(hits.indexOf('the-hunters-ledger.com') === -1, hits.join(','));
});

test('the designated bucket is not scanned, or the gate would never go green', function () {
  var f = feed();
  f[U.BUCKET] = [{ value: 'pastebin.com', category: 'paste or code sharing' }];
  var hosts = H.scan(f).map(function (x) { return x.host; });
  assert.ok(hosts.indexOf('pastebin.com') === -1, hosts.join(','));
});

test('real attacker infrastructure is never flagged', function () {
  var hosts = H.scan(feed()).map(function (x) { return x.host; });
  assert.ok(hosts.indexOf('evilsoul.cc') === -1);
});

test('PROSE IS NOT AN INDICATOR', function () {
  // classify() rejects anything with whitespace, so a detection note naming a
  // service is safe and needs no special handling.
  var f = feed({ detection_opportunities: [
    'Monitor for outbound connections to api.telegram.org from server subnets'] });
  assert.deepEqual(H.scan(f).map(function (x) { return x.host; }), ['api.telegram.org'],
    'the prose sentence should not add a second hit');
});

test('a value nested arbitrarily deep is still found', function () {
  var f = feed({ weird: { deeply: { nested: [[{ x: ['icanhazip.com'] }]] } } });
  var hosts = H.scan(f).map(function (x) { return x.host; });
  assert.ok(hosts.indexOf('icanhazip.com') > -1, hosts.join(','));
});

/* --- migration ---------------------------------------------------------- */

test('MIGRATION MOVES THE VALUE OUT OF THE INDICATOR BUCKET', function () {
  var r = H.migrate(feed());
  assert.equal(H.scan(r.feed).length, 0, 'a scan of the migrated feed must be clean');
  var vals = r.feed.network_indicators.domains.map(function (d) { return d.value; });
  assert.deepEqual(vals, ['evilsoul.cc']);
});

test('and records it, with the context it travelled with', function () {
  var r = H.migrate(feed());
  assert.equal(r.feed[U.BUCKET].length, 1);
  assert.deepEqual(r.feed[U.BUCKET][0],
    { value: 'api.telegram.org', category: 'messaging platform',
      context: 'exfiltration channel' });
});

test('the input feed is never mutated', function () {
  var f = feed();
  H.migrate(f);
  assert.equal(f.network_indicators.domains.length, 2, 'the original was modified');
});

test('an entry that existed only to describe the moved value goes with it', function () {
  // Leaving {confidence, context} behind with no value reads as an indicator whose
  // value went missing, which is worse than removing the object.
  var r = H.migrate(feed());
  r.feed.network_indicators.domains.forEach(function (d) {
    assert.ok(d.value, 'an object with no value survived: ' + JSON.stringify(d));
  });
});

test('everything else in the feed survives untouched', function () {
  var r = H.migrate(feed());
  assert.deepEqual(r.feed.file_hashes.sha256, ['a'.repeat(64)]);
  assert.deepEqual(r.feed.network_indicators.ips, ['185.49.126.140']);
  assert.equal(r.feed.metadata.reference,
    'https://the-hunters-ledger.com/reports/demo/');
});

test('AN EXISTING hunt_only_never_block ENTRY IS PRESERVED, not overwritten', function () {
  // One feed already carried this bucket, written by hand before the convention
  // existed. Losing it would be the migration destroying the very thing it copies.
  var f = feed();
  f[U.BUCKET] = [{ value: 'pastebin.com', category: 'paste or code sharing' }];
  var r = H.migrate(f);
  var vals = r.feed[U.BUCKET].map(function (e) { return e.value; });
  assert.ok(vals.indexOf('pastebin.com') > -1, 'the hand-written entry was lost');
  assert.ok(vals.indexOf('api.telegram.org') > -1);
});

test('a hand-written bucket in the older bare-string form is preserved too', function () {
  var f = feed();
  f[U.BUCKET] = { domains: 'api.telegram.org' };
  var r = H.migrate(f);
  assert.ok(r.feed[U.BUCKET].length >= 1);
});

test('one host appearing in several buckets is recorded once', function () {
  var f = feed({ other_indicators: ['api.telegram.org'] });
  var r = H.migrate(f);
  assert.equal(r.feed[U.BUCKET].filter(function (e) {
    return e.value === 'api.telegram.org';
  }).length, 1);
});

test('a feed with nothing to move is returned without the bucket', function () {
  var f = { network_indicators: { domains: ['evilsoul.cc'] } };
  var r = H.migrate(f);
  assert.equal(r.moved.length, 0);
  assert.equal(r.feed[U.BUCKET], undefined,
    'an empty bucket would appear on every clean feed for no reason');
});

test('A PATH-BEARING URL IS LEFT ALONE, being a precise indicator', function () {
  // https://github.com/ is the platform; https://github.com/operator/repo is the
  // operator's own repository and the most useful line in that feed.
  var f = { network_indicators: { urls: ['https://api.telegram.org/bot1/sendDocument',
                                         'https://github.com/Vova75Rus/miner'] } };
  var r = H.migrate(f);
  assert.equal(r.moved.length, 0);
  assert.equal(r.feed.network_indicators.urls.length, 2);
});

test('a bare root url IS moved, since that is the form ingested as a domain block',
  function () {
    var f = { network_indicators: { urls: ['https://ipwho.is/'] } };
    var r = H.migrate(f);
    assert.equal(r.moved.length, 1);
    assert.equal(r.moved[0].host, 'https://ipwho.is/');
  });

test('migrating twice changes nothing the second time', function () {
  var once = H.migrate(feed()).feed;
  var twice = H.migrate(once);
  assert.equal(twice.moved.length, 0);
  assert.deepEqual(twice.feed, once);
});
