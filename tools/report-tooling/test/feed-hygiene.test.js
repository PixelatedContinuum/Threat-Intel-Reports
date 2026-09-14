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

/* --- the strict target-or-victim tier runs regardless of type ----------- */

test('a role:VICTIM value that is not a network type is still found and removed',
  function () {
    // "juniper-JunOS" does not classify as anything: not a hash, url, ipv4, email,
    // filename or domain, and it is not on the NON_IDENTIFYING allowlist either.
    // Before the original fix this whole entry was invisible to both scan() and
    // migrate(), even though role:VICTIM is the STRICT marking. Deliberately NOT
    // "cisco-IOS" here (see the two tests below): this one exists to prove the
    // general untyped-victim-value mechanism still works for anything the
    // allowlist has not specifically approved.
    var f = feed({ network_indicators: { user_agents: [
      { value: 'juniper-JunOS', role: 'VICTIM-generated user agent on all exfil PUTs',
        context: 'the highest-fidelity signal in the case' }
    ] } });

    var hits = H.scan(f);
    assert.equal(hits.length, 1, 'the victim-marked non-network value was not found');
    assert.equal(hits[0].host, 'juniper-JunOS');
    assert.equal(hits[0].category, 'author-marked target or victim');

    var r = H.migrate(f);
    assert.equal(r.removed.length, 1, 'it must be REMOVED, not moved');
    assert.equal(r.removed[0].host, 'juniper-JunOS');
    assert.equal(r.moved.length, 0, 'a victim value must never land in hunt_only_never_block');
    assert.equal(r.feed[U.BUCKET], undefined,
      'removing the only value in this feed should leave no bucket behind');
    assert.equal(H.scan(r.feed).length, 0, 'a scan of the migrated feed must be clean');
  });

/* --- NON_IDENTIFYING allowlist: the reviewed-exception mechanism that replaced the
   per-entry marker design ------------------------------------------------------------ */

test('the real cisco-IOS shape is exempted by the allowlist: no finding, nothing moved',
  function () {
    // The exact fixture (value, role text, context) as it sits in
    // opendirectory-13-140-145-210-weblogic-deserialization-telecom-harvester-20260817-iocs.json.
    // This is the entry the strict tier used to flag before the allowlist, and the case
    // the whole allowlist mechanism was built to answer without touching the source data.
    var f = feed({ network_indicators: { user_agents: [
      { value: 'cisco-IOS', role: 'VICTIM-generated user agent on all 100 exfiltration PUTs',
        confidence: 'DEFINITE', action: 'HUNT',
        notes: 'This is the victim device\'s own user agent, not the operator\'s.' }
    ] } });

    assert.equal(H.scan(f).length, 0,
      'an allowlisted, untyped, role:VICTIM value must not be a finding');

    var r = H.migrate(f);
    assert.equal(r.removed.length, 0, 'an exempted value must not be removed');
    assert.equal(r.moved.length, 0, 'an exempted value must not be moved either');
    assert.deepEqual(r.feed.network_indicators.user_agents[0].value, 'cisco-IOS',
      'the entry must stay exactly where it was, with every field intact');
    assert.equal(r.feed.network_indicators.user_agents[0].role,
      'VICTIM-generated user agent on all 100 exfiltration PUTs', 'the role text is unchanged');
  });

test('scan() records the exemption when given an array to record into', function () {
  var f = feed({ network_indicators: { user_agents: [
    { value: 'cisco-IOS', role: 'VICTIM-generated user agent on all 100 exfiltration PUTs' }
  ] } });
  var exemptions = [];
  var hits = H.scan(f, exemptions);
  assert.equal(hits.length, 0);
  assert.equal(exemptions.length, 1, 'the exemption must be recorded when an array is passed');
  assert.equal(exemptions[0].value, 'cisco-IOS');
  assert.ok(exemptions[0].reason && exemptions[0].reason.length > 0,
    'every allowlist entry must carry a reason, and it must reach the caller');

  // Backward compatibility: the single-argument form (every existing caller) must still
  // work identically and must not throw for lack of an array to push into.
  assert.equal(H.scan(f).length, 0);
});

test('a typed value that is somehow on the allowlist is still removed: the secondary guard',
  function () {
    // NON_IDENTIFYING is exported for exactly this: prove that if a future edit ever adds
    // a domain, IP, URL, email or hash to the list, the entry stays blockable-tier eligible
    // anyway, because the allowlist is only ever consulted when classify() also finds no
    // type. A throwaway key is added and removed so this test cannot leak state into any
    // other test in this file.
    H.NON_IDENTIFYING['8.8.8.8'] = 'TEST ONLY: proves a typed value on the list is not honoured';
    try {
      var f = feed({ network_indicators: { ips: [
        { value: '8.8.8.8', role: 'VICTIM internal resolver, somehow on the allowlist' }
      ] } });
      var hits = H.scan(f);
      assert.equal(hits.length, 1,
        'a typed value must be found even if it is present in NON_IDENTIFYING');
      assert.equal(hits[0].host, '8.8.8.8');
      var r = H.migrate(f);
      assert.equal(r.removed.length, 1, 'a typed value on the list must still be removed');
    } finally {
      delete H.NON_IDENTIFYING['8.8.8.8'];
    }
    assert.equal(Object.prototype.hasOwnProperty.call(H.NON_IDENTIFYING, '8.8.8.8'), false,
      'cleanup must actually have run, or every test after this one is compromised');
  });

test('the two real untyped victim identifiers that broke the marker design are still removed',
  function () {
    // This is the test that encodes WHY the per-entry marker design was rejected in favour
    // of the allowlist. Both values are untyped (classify() returns null for each, per
    // break-constraint-2.md's own measurement) and neither is on NON_IDENTIFYING. A
    // role:VICTIM marking on either must still remove it, exactly as it does today, or this
    // change would have silently reopened the hole staff1 found.
    // network_indicators is overridden to {} in both fixtures, the same guard the
    // "loose never-block tier is UNCHANGED" test above uses: the base fixture's own
    // api.telegram.org bare-match would otherwise add a second, unrelated hit and make
    // this assertion pass or fail for the wrong reason.
    var jwt = feed({ network_indicators: {}, host_indicators: { victim_indicators: [
      { value: '022a1b74-2332-4df5-a76b-60225ffa7ae3', role: 'VICTIM organization API token',
        type: 'stolen_jwt_jti', confidence: 'DEFINITE' }
    ] } });
    var jwtHits = H.scan(jwt);
    assert.equal(jwtHits.length, 1, 'the stolen JWT jti must still be found');
    assert.equal(jwtHits[0].host, '022a1b74-2332-4df5-a76b-60225ffa7ae3');
    assert.equal(H.migrate(jwt).removed.length, 1, 'and still removed');

    var vault = feed({ network_indicators: {}, host_indicators: { victim_indicators: [
      { value: 'XRAOLK4ZIZHJPDWPVEMGPRDXBE', role: 'VICTIM 1Password vault id',
        type: 'stolen_1password_vault_id', confidence: 'DEFINITE' }
    ] } });
    var vaultHits = H.scan(vault);
    assert.equal(vaultHits.length, 1, 'the stolen 1Password vault id must still be found');
    assert.equal(vaultHits[0].host, 'XRAOLK4ZIZHJPDWPVEMGPRDXBE');
    assert.equal(H.migrate(vault).removed.length, 1, 'and still removed');
  });

test('the loose never-block tier is UNCHANGED: a non-network value stays invisible',
  function () {
    // Same shape as the residual-feed-gaps findings (a hash, a registry path, an
    // ASN): marked never-block, but not a domain/url/ipv4, so it correctly stays
    // out of scope for a BLOCKLIST gate. This is the regression test that the fix
    // did not widen the loose tier along with the strict one.
    // network_indicators is overridden (not just added to) so the base fixture's
    // own api.telegram.org bare-match cannot contaminate this assertion.
    var f = feed({ network_indicators: {}, host_indicators: { registry_keys: [
      { value: 'HKCU\\Software\\Run\\WindowsUpdateManager',
        false_positive_risk: 'low, do not block, operator-documented victim-side path' }
    ] } });
    assert.equal(H.scan(f).length, 0, 'a non-network never-block value must stay unflagged');
    var r = H.migrate(f);
    assert.equal(r.moved.length, 0);
    assert.equal(r.removed.length, 0);
  });

test('a role:VICTIM value that IS a network type still works exactly as before',
  function () {
    // Regression check: the fix must not change behaviour for the case that
    // already worked (a victim-marked ipv4), only add coverage for the case that
    // did not.
    var f = feed({ network_indicators: { ips: [
      { value: '10.0.0.9', role: 'TARGET internal address' }
    ] } });
    var r = H.migrate(f);
    assert.equal(r.removed.length, 1);
    assert.equal(r.removed[0].host, '10.0.0.9');
  });

/* --- action: BLOCK outranks a prose never-block phrase, loose tier only ---------- */

test('action: BLOCK stops the loose tier firing, even with a never-block phrase present',
  function () {
    // Real shape from the 2026-09-13 red-team review: an operator CNC listener,
    // action BLOCK, confidence DEFINITE, but a false_positive_risk field that reads
    // "notify victim before blocking" (sequencing, not a prohibition) about the
    // underlying VPS owner, not the malicious value itself.
    var f = feed({ network_indicators: { ips: [
      { value: '165.227.175.161', port: 23, protocol: 'TCP',
        context: 'Naku.arm CNC, parasitic listener on a compromised tourism VPS',
        confidence: 'DEFINITE', action: 'BLOCK',
        false_positive_risk: 'Underlying VPS host belongs to a legitimate tourism '
          + 'platform, notify victim before blocking' }
    ] } });
    assert.equal(H.scan(f).length, 0, 'action: BLOCK must stop the loose tier');
    var r = H.migrate(f);
    assert.equal(r.moved.length, 0);
    assert.equal(r.removed.length, 0);
    assert.deepEqual(r.feed.network_indicators.ips[0].value, '165.227.175.161',
      'the value must stay exactly where it was, with every field intact');
    assert.equal(r.feed.network_indicators.ips[0].port, 23, 'port must survive');
  });

test('action: BLOCK on the apex-domain-caveat shape also stays put',
  function () {
    // Real shape: an operator-created tenant hostname, action BLOCK, confidence
    // HIGH, whose notes warn about the shared APEX domain rather than this value,
    // the exact tenant-hostname-stays-blockable carve-out.
    var f = feed({ network_indicators: { domains: [
      { value: 'mail.evil-tenant.donor-domain.se',
        purpose: 'Operator-created FreeDNS abuse subdomain',
        confidence: 'HIGH', action: 'BLOCK',
        notes: 'Do NOT blocklist apex donor-domain.se, it is a multi-tenant donor domain' }
    ] } });
    assert.equal(H.scan(f).length, 0);
    var r = H.migrate(f);
    assert.equal(r.moved.length + r.removed.length, 0);
  });

test('action: BLOCK does NOT stop the strict role:VICTIM tier',
  function () {
    // The strict tier fires regardless of action on purpose: a victim identity is
    // a disclosure question, and the author may have written BLOCK before
    // realising what the value was.
    var f = feed({ network_indicators: { ips: [
      { value: '10.0.0.9', role: 'VICTIM internal address', action: 'BLOCK' }
    ] } });
    var r = H.migrate(f);
    assert.equal(r.removed.length, 1, 'role:VICTIM must still remove regardless of action');
  });

test('action: MONITOR (or no action) still relocates exactly as before',
  function () {
    // Regression: the override must be specific to BLOCK. MONITOR and "no action
    // field at all" are the shape of every correct move in the red-team's table.
    var f = feed({ network_indicators: { ips: [
      { value: '172.237.149.231', purpose: 'Parklogic shared TDS landing infrastructure',
        confidence: 'MODERATE', action: 'MONITOR',
        false_positive_risk: 'HIGH, shared by all Parklogic customers, do not blocklist '
          + 'the IP without context' },
      { value: '23.106.161.1', confidence: 'LOW',
        false_positive_risk: 'Likely victim/3rd-party. DO NOT block at perimeter '
          + 'without further verification' }
    ] } });
    var hits = H.scan(f).map(function (x) { return x.host; });
    assert.ok(hits.indexOf('172.237.149.231') > -1, 'MONITOR must still relocate');
    assert.ok(hits.indexOf('23.106.161.1') > -1, 'no action field must still relocate');
  });

/* --- migrate() carries the whole original object, not a reduced projection ------ */

test('a moved author-marked object keeps every field, not just value/category/context',
  function () {
    var f = feed({ network_indicators: { ips: [
      { value: '172.237.149.231', purpose: 'Parklogic shared TDS landing infrastructure',
        asn: 'AS63949 Akamai/Linode', confidence: 'MODERATE', action: 'MONITOR',
        false_positive_risk: 'HIGH, shared by all Parklogic customers, do not blocklist '
          + 'the IP without context' }
    ] } });
    var r = H.migrate(f);
    assert.equal(r.feed[U.BUCKET].length, 1);
    var e = r.feed[U.BUCKET][0];
    assert.equal(e.value, '172.237.149.231');
    assert.equal(e.purpose, 'Parklogic shared TDS landing infrastructure', 'purpose was dropped');
    assert.equal(e.asn, 'AS63949 Akamai/Linode', 'asn was dropped');
    assert.equal(e.confidence, 'MODERATE', 'confidence was dropped');
    assert.equal(e.action, 'MONITOR', 'action was dropped');
    assert.equal(e.category, 'author-marked never-block');
  });

test('a removed victim object also keeps every field, in the return value',
  function () {
    // "juniper-JunOS", not "cisco-IOS": this fixture is testing full-field preservation
    // on a REMOVED entry, which requires a value the allowlist does NOT exempt.
    var f = feed({ network_indicators: { user_agents: [
      { value: 'juniper-JunOS', role: 'VICTIM-generated user agent on all exfil PUTs',
        confidence: 'DEFINITE', notes: 'highest-fidelity signal in the case' }
    ] } });
    var r = H.migrate(f);
    assert.equal(r.removed.length, 1);
    assert.equal(r.removed[0].full.confidence, 'DEFINITE', 'confidence was dropped');
    assert.equal(r.removed[0].full.notes, 'highest-fidelity signal in the case',
      'notes was dropped');
  });

test('the bare-string migration path (unrelated to author-marked objects) is unchanged',
  function () {
    // Regression guard: the full-object carry only applies to the author-marked
    // path. api.telegram.org here is caught via the plain SERVICES list on a bare
    // string, and must keep its old {value, category, context} shape exactly.
    var r = H.migrate(feed());
    assert.deepEqual(r.feed[U.BUCKET][0],
      { value: 'api.telegram.org', category: 'messaging platform',
        context: 'exfiltration channel' });
  });
