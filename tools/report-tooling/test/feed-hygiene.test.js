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
      { value: '00000000-1111-4222-8333-444444444444', role: 'VICTIM organization API token',
        type: 'stolen_jwt_jti', confidence: 'DEFINITE' }
    ] } });
    var jwtHits = H.scan(jwt);
    assert.equal(jwtHits.length, 1, 'the stolen JWT jti must still be found');
    assert.equal(jwtHits[0].host, '00000000-1111-4222-8333-444444444444');
    assert.equal(H.migrate(jwt).removed.length, 1, 'and still removed');

    var vault = feed({ network_indicators: {}, host_indicators: { victim_indicators: [
      { value: 'AAAABBBBCCCCDDDDEEEEFFFFGG', role: 'VICTIM 1Password vault id',
        type: 'stolen_1password_vault_id', confidence: 'DEFINITE' }
    ] } });
    var vaultHits = H.scan(vault);
    assert.equal(vaultHits.length, 1, 'the stolen 1Password vault id must still be found');
    assert.equal(vaultHits[0].host, 'AAAABBBBCCCCDDDDEEEEFFFFGG');
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

/* --- IPv4: scan() must not let a non-routable address or a resolver through ------ */

test('A NON-ROUTABLE OR RESOLVER ADDRESS IN AN INDICATOR BUCKET IS FOUND, AN OPERATOR ADDRESS IS NOT',
  function () {
    /* 127.0.0.1:3306 and 10.0.0.5 are the two shapes the real corpus carried
       (T-0318): a loopback SSRF target with a port the classifier types as ipv4,
       and an RFC1918 victim-internal address. The operator address beside them is
       real and must stay blockable, which is the failure this test is really
       guarding against. */
    var f = { network_indicators: { ips: ['127.0.0.1:3306', '10.0.0.5', '185.208.159.182'] } };
    assert.deepEqual(H.scan(f).map(function (x) { return x.host; }),
      ['127.0.0.1', '10.0.0.5']);
    assert.deepEqual(H.scan(f).map(function (x) { return x.category; }),
      ['non-routable address (loopback)', 'non-routable address (private)']);
  });

test('the same values inside the designated bucket are not findings', function () {
  // hunt_only_never_block is where the migration puts them; scanning it would make
  // the gate fail forever on the feed the fix had just cleaned.
  var f = { network_indicators: { ips: ['185.208.159.182'] },
            hunt_only_never_block: ['127.0.0.1:3306', '10.0.0.5'] };
  assert.deepEqual(H.scan(f), []);
});

test('scan() over the arsenal-237 entries T-0318 removed reports both non-blockable addresses',
  function () {
    /* The regression case, inlined: the two entries exactly as the
       arsenal-237-nethost-dll feed shipped them in network_indicators.ips before
       T-0318 (8.8.8.8 marked "URGENT - Block", 127.0.0.1 "STANDARD - Block").
       Inlined rather than read from the workflow repo, so the guard runs in a bare
       clone of this repo instead of skipping, and a skip never reads as a pass. */
    var f = { network_indicators: { ips: [
      { ip_address: '8.8.8.8', port: 53, protocol: 'TCP',
        purpose: 'Primary C2 Target (Proxy Endpoint)', confidence: 'CONFIRMED',
        detection_method: 'Network egress monitoring, Firewall logs',
        blocking_recommendation: 'URGENT - Block at perimeter firewall and endpoint level' },
      { ip_address: '127.0.0.1', port: 53, protocol: 'TCP',
        purpose: 'Secondary C2 Target (Localhost Proxy)', confidence: 'CONFIRMED',
        detection_method: 'Process network monitoring, netstat output',
        blocking_recommendation: 'STANDARD - Block at endpoint level (local proxy prevention)' }
    ] } };
    var hits = H.scan(f).map(function (x) { return x.host; });
    assert.ok(hits.indexOf('127.0.0.1') > -1,
      '127.0.0.1 must be reported, got: ' + hits.join(', '));
    assert.ok(hits.indexOf('8.8.8.8') > -1,
      '8.8.8.8 must be reported, got: ' + hits.join(', '));
  });

/* --- bucket-level markings: a marking on a whole container is inherited by its subtree ---

   T-0322 found a `targeted_assets` bucket whose own `warning` says
   "CONTEXT ONLY - DO NOT BLOCK" while the gate read only per-entry markings, so all 43
   typed values beneath it passed as blockable. These tests pin the bucket rule: the key
   name (victim or loose), a marker string on the container, inheritance down the subtree,
   and the negatives that must NOT become buckets. */

/* scan() and migrate() are one module because they must agree; every bucket fixture below is
   checked through this helper so a future edit to one and not the other fails here. */
function agrees(f) {
  var seen = H.scan(f).map(function (x) { return x.host; }).sort();
  var r = H.migrate(f);
  var acted = r.moved.concat(r.removed).map(function (x) { return x.host; }).sort();
  assert.deepEqual(acted, seen, 'scan() and migrate() must act on the same values');
  assert.deepEqual(H.scan(r.feed), [], 'a scan of the migrated feed must be clean');
  return r;
}

test('A WHOLE-BUCKET VICTIM MARKING IS READ: targeted_assets flags its whole subtree',
  function () {
    // 93.184.216.34 is a global-unicast address and victim-portal.example is no known
    // service, so NOTHING here is flagged on its own: the finding can only come from the
    // bucket marking, which is exactly what this change adds.
    var f = feed({ network_indicators: {}, targeted_assets: {
      warning: 'CONTEXT ONLY - DO NOT BLOCK. These are victim-side and target-side assets.',
      confirmed: ['93.184.216.34'],
      entries: [{ asset: 'victim-portal.example', sector: 'banking' }]
    } });

    var hits = H.scan(f);
    assert.deepEqual(hits.map(function (x) { return x.host; }).sort(),
      ['93.184.216.34', 'victim-portal.example']);
    hits.forEach(function (h) {
      assert.equal(h.category, 'bucket-marked target or victim', h.path);
    });

    var r = agrees(f);
    assert.equal(r.removed.length, 2, 'both are victim values: REMOVED, never relocated');
    assert.equal(r.moved.length, 0, 'a victim value must never land in hunt_only_never_block');
    assert.equal(r.feed.targeted_assets, undefined, 'the emptied bucket goes with its values');
  });

test('a victim bucket whose key says victim but which carries no marker is still read',
  function () {
    // The key-name trigger alone. No warning string anywhere.
    var f = feed({ network_indicators: {}, victim_inventory: ['victim-host.example'] });
    var hits = H.scan(f);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].host, 'victim-host.example');
    assert.equal(hits[0].category, 'bucket-marked target or victim');
    agrees(f);
  });

/* gate2 2026-10-16: a loose bucket covers hashes too. The bucket's own marking is the author
   fencing the whole container off from blocking, and that speaks to every consumer of the feed,
   the hash blocklist included; a hash-ingesting consumer walking the same file reads the same
   list the gate does. So the digest beside the IP is relocated, not left in place. */
test('A LOOSE BUCKET BY NAME relocates network values and hashes',
  function () {
    var digest = 'a'.repeat(64);
    var f = feed({ network_indicators: {}, investigated_and_excluded: {
      note: 'Ruled out as operator infrastructure.',
      ips: ['93.184.216.34'],
      hashes: [digest]
    } });

    var hits = H.scan(f);
    assert.deepEqual(hits.map(function (x) { return x.host; }).sort(),
      ['93.184.216.34', digest].sort(), 'both are blocklist questions under a loose bucket');
    hits.forEach(function (h) { assert.equal(h.category, 'bucket-marked never-block', h.path); });

    var r = agrees(f);
    assert.equal(r.moved.length, 2);
    assert.equal(r.removed.length, 0);
    assert.equal(r.feed[U.BUCKET][0].value, '93.184.216.34');
    assert.ok(r.feed[U.BUCKET][1].value === digest, 'the hash moves out of the bucket');
  });

test('A LOOSE BUCKET BY MARKER STRING alone is read even under an innocuous key',
  function () {
    // The key name matches nothing; only "must not be blocked" in the note does.
    var f = feed({ network_indicators: {}, reviewed_dead_ends: {
      note: 'Assessed and ruled out. These must not be blocked.',
      hosts: ['stolotov.org']
    } });

    var hits = H.scan(f);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].host, 'stolotov.org');
    assert.equal(hits[0].path, 'reviewed_dead_ends.hosts');
    assert.equal(hits[0].category, 'bucket-marked never-block');

    var r = agrees(f);
    assert.equal(r.moved.length, 1);
    assert.equal(r.feed[U.BUCKET][0].value, 'stolotov.org');
    assert.equal(r.feed[U.BUCKET][0].context, 'Assessed and ruled out. These must not be blocked.',
      'a bare string carries the bucket\'s own marker text as its context');
  });

test('a loose bucket MOVES an entry object whole, keeping every field',
  function () {
    var f = feed({ network_indicators: {}, excluded_indicators: {
      note: 'Ruled out; not this operator.',
      entries: [{ indicator: 'shared-host.example', purpose: 'shared hosting', asn: 'AS63949',
                  confidence: 'LOW' }]
    } });
    var r = agrees(f);
    assert.equal(r.moved.length, 1);
    var e = r.feed[U.BUCKET][0];
    assert.equal(e.indicator, 'shared-host.example',
      'the whole entry object is carried, key name and all');
    assert.equal(e.purpose, 'shared hosting', 'purpose was dropped');
    assert.equal(e.asn, 'AS63949', 'asn was dropped');
    assert.equal(e.confidence, 'LOW', 'confidence was dropped');
    assert.equal(e.category, 'bucket-marked never-block');
  });

test('BRAND_IMPERSONATION_TARGETS IS NOT A VICTIM MARKING: "targets" alone flags nothing',
  function () {
    // The operator's own pre-staged subdomains. "targets" in a key name names whom the
    // operator impersonates, an operator fact, not a bystander; reading it as a victim
    // marking would strip the operator's infrastructure out of the feed.
    var f = feed({ network_indicators: {}, brand_impersonation_targets: {
      context: '467+ pre-staged brand-impersonation subdomains under inklens.ru.',
      us_banking_finance: ['wellsfargo.inklens.ru', 'adyen-no-stripe.inklens.ru']
    } });
    assert.deepEqual(H.scan(f), []);
    var r = H.migrate(f);
    assert.equal(r.moved.length + r.removed.length, 0);
    assert.deepEqual(r.feed.brand_impersonation_targets.us_banking_finance,
      ['wellsfargo.inklens.ru', 'adyen-no-stripe.inklens.ru']);
  });

test('a container whose prose carries no never-block phrase is not a bucket', function () {
  var f = feed({ network_indicators: {}, operator_recon_notes: {
    note: 'Passive DNS and certificate-transparency pivots on the operator.',
    hosts: ['cdn.operator-c2.example']
  } });
  assert.deepEqual(H.scan(f), []);
  assert.equal(H.migrate(f).moved.length, 0);
});

test('values under metadata stay unflagged however the feed is shaped', function () {
  var f = feed({ network_indicators: {}, metadata: {
    campaign: 'Demo',
    reference: 'https://the-hunters-ledger.com/reports/demo/',
    notes: 'must not be blocked',
    hosts: ['api.telegram.org']
  } });
  assert.deepEqual(H.scan(f), [], 'metadata is exempt even when it looks like a bucket');
});

test('the strict victim tier outranks a loose bucket: a role:VICTIM entry is REMOVED',
  function () {
    var f = feed({ network_indicators: {}, excluded_indicators: {
      note: 'Ruled out.',
      entries: [{ value: '93.184.216.35', role: 'VICTIM internal host' }]
    } });
    var r = agrees(f);
    assert.equal(r.removed.length, 1, 'the stricter tier wins, so it is removed not moved');
    assert.equal(r.moved.length, 0);
  });

test('an empty-valued bucket is not conjured up by a value beside it', function () {
  // Regression guard: the bucket walk must not leak into a neighbouring ordinary bucket.
  var f = feed({ network_indicators: { ips: ['93.184.216.36'] },
                 victim_inventory: [] });
  assert.deepEqual(H.scan(f), [], 'an operator address beside an empty victim bucket is safe');
});

/* --- gate2, 2026-10-16: two decisions by Joseph (tasks/runs/T-0323/plan.md) ----------------

   1. Inside a LOOSE (never-block) bucket, act on the network types AND the hash types: an
      author who fenced a whole bucket off from blocking meant every consumer of the feed, the
      hash blocklist included. Per-entry markings stay network-only.
   2. An entry object that directly carries `action` starting with BLOCK, inside a loose bucket,
      is ordinary again for its own subtree. It never outranks a victim bucket. */

var VENDOR_SHA256 = 'c'.repeat(64);

test('A LOOSE BUCKET COVERS HASHES TOO: a vendor-binary SHA-256 moves, the filename beside it stays',
  function () {
    /* The opendirectory-62-60-237-100 shape: `known_legitimate_DO_NOT_BLOCKLIST` holds one
       object per genuine signed vendor binary, {hash, filename}, and its own text warns that
       generic hash blocking "would cause massive false positives". The bucket key is loose by
       name; the hash is a blocklist question and moves, the filename is not and stays put. */
    var f = feed({ network_indicators: {}, known_legitimate_DO_NOT_BLOCKLIST: {
      context: 'GENUINE legitimate vendor binaries; do not block',
      wondershare_dlls: [{ hash: VENDOR_SHA256, filename: 'SlideShowEditor.exe' }]
    } });

    var hits = H.scan(f);
    assert.deepEqual(hits.map(function (x) { return x.host; }), [VENDOR_SHA256],
      'only the hash is a blocklist question under a loose bucket');
    assert.equal(hits[0].category, 'bucket-marked never-block');

    var r = agrees(f);
    assert.equal(r.moved.length, 1);
    assert.equal(r.removed.length, 0);
    assert.equal(r.feed[U.BUCKET][0].hash, VENDOR_SHA256);
    assert.equal(r.feed[U.BUCKET][0].filename, 'SlideShowEditor.exe',
      'the whole entry object moves, filename and all');
  });

test('A RANSOMWARE BEHAVIOUR LIST IS NOT A BLOCKLIST: excluded_directories filenames stay',
  function () {
    /* arsenal-237-new_enc-exe.json: `excluded_directories` is the directories a locker skips,
       under a key that matches the loose tier by name. Two of its 23 entries classify as
       filenames (config.msi, windows.old). A filename is neither a network nor a hash blocklist
       entry, so the loose tier must not widen to it. */
    var dirs = ['config.msi', 'windows.old', 'windows', 'appdata', 'boot'];
    var f = feed({ network_indicators: {}, behavioral_iocs: { file_system_behavior: [{
      behavior: 'Directory exclusion from encryption',
      excluded_directories: dirs
    }] } });

    assert.deepEqual(H.scan(f), [], 'a loose bucket of filenames must flag nothing');
    var r = H.migrate(f);
    assert.equal(r.moved.length + r.removed.length, 0);
    assert.deepEqual(r.feed.behavioral_iocs.file_system_behavior[0].excluded_directories, dirs,
      'nothing is relocated out of a behaviour list');
  });

test('AN entry action: BLOCK OUTRANKS A LOOSE BUCKET: the excluded co-tenant C2 stays blockable',
  function () {
    /* The 79.137.192.3 row in plan.md: the bucket name says excluded, the value is a live
       RedLine C2 of an unrelated co-tenant the author decided is malicious and blockable, and
       `action: BLOCK` is the author's per-value decision. It outranks the bucket's loose
       marking for this entry's own subtree, exactly as it already outranks the entry's prose. */
    var f = feed({ network_indicators: {}, co_tenant_exclusions_documented: {
      note: 'Ruled out as this operator.',
      tenants: [{ c2: 'http://79.137.192.3:1516/', action: 'BLOCK',
                  role: 'RedLine C2 of an unrelated co-tenant' }]
    } });

    assert.deepEqual(H.scan(f), [],
      'the author decided this value; a loose bucket must not override it');
    var r = H.migrate(f);
    assert.equal(r.moved.length + r.removed.length, 0);
    assert.equal(r.feed.co_tenant_exclusions_documented.tenants[0].c2,
      'http://79.137.192.3:1516/', 'the entry stays where it is');
  });

test('action: BLOCK DOES NOT OUTRANK A VICTIM BUCKET: a marked victim value is still removed',
  function () {
    /* Victim is a disclosure question, not a blocklist one. The author may have written
       `action: BLOCK` before realising what the value was; the victim tier fires regardless. */
    var f = feed({ network_indicators: {}, victim_inventory: {
      note: 'Victim estate.',
      hosts: [{ value: 'victim-host.example', action: 'BLOCK' }]
    } });

    var hits = H.scan(f);
    assert.deepEqual(hits.map(function (x) { return x.host; }), ['victim-host.example']);
    assert.equal(hits[0].category, 'bucket-marked target or victim');

    var r = agrees(f);
    assert.equal(r.removed.length, 1);
    assert.equal(r.moved.length, 0, 'a victim value must never be relocated');
  });

test('a per-entry VICTIM marking still outranks an action: BLOCK inside a loose bucket',
  function () {
    // Both fields on one entry: the disclosure marking wins, as authorMarkedHuntOnly already
    // encodes for the per-entry case.
    var f = feed({ network_indicators: {}, excluded_indicators: {
      note: 'Ruled out.',
      entries: [{ value: '93.184.216.37', role: 'VICTIM endpoint', action: 'BLOCK' }]
    } });
    var hits = H.scan(f);
    assert.deepEqual(hits.map(function (x) { return x.host; }), ['93.184.216.37']);
    assert.equal(hits[0].category, 'author-marked target or victim');
  });
