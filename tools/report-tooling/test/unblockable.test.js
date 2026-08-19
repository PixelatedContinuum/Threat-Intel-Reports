'use strict';

/* Values no organisation should ever block.

   The feeds are the machine-readable product and some people pipe them straight
   into a blocklist without reading a word. That is a reasonable thing to do with a
   feed, and this module is what makes it safe.

   The suffix cases are the ones that matter most. An exact host in a blocklist
   costs whoever owns that host; a PROVIDER suffix costs every unrelated tenant
   behind it. One `x.duckdns.org` line ingested as a domain-block takes out DuckDNS
   for the whole estate, and nobody troubleshooting that ever traces it back to a
   threat feed. */

var test = require('node:test');
var assert = require('node:assert');
var U = require('../lib/unblockable.js');

test('the services measured in the real feeds are all covered', function () {
  // Every one of these was sitting in a plain indicator bucket on 2026-08-19.
  ['api.telegram.org', 't.me', 'discord.com', 'pastebin.com', 'github.com',
   'raw.githubusercontent.com', 'goproxy.github.io', 'api.ipify.org', 'icanhazip.com',
   'ifconfig.me', 'ip-api.com', 'ip.sb', 'ipwho.is', 'download.anydesk.com',
   'www.amyuni.com', 'serveo.net', 'gsocket.io', 'cdn.gsocket.io', 'webhook.site',
   'web.archive.org', 'api.binance.com', 'intezer.com', 'rebel.com',
   'generativelanguage.googleapis.com', 'open.oppomobile.com', 'www.usom.gov.tr'
  ].forEach(function (h) {
    assert.ok(U.serviceOf(h), h + ' is not covered');
  });
});

test('THE BARE PROVIDER DOMAIN IS FLAGGED, THE TENANT UNDER IT IS NOT', function () {
  /* The distinction that decides whether this module helps or harms.
     `duckdns.org` in a blocklist takes out DuckDNS for the estate.
     `dns4up.duckdns.org` is the hostname the operator registered, and a defender
     should absolutely block it. Getting this backwards would strip the real C2
     hostname out of the feed and leave nothing to match on, which is worse than
     the problem the module exists to solve. */
  [['duckdns.org', 'dynamic dns provider'],
   ['hopto.org', 'dynamic dns provider'],
   ['ngrok-free.app', 'tunnelling provider'],
   ['trycloudflare.com', 'tunnelling provider'],
   ['aliyuncs.com', 'cloud provider'],
   ['myqcloud.com', 'cloud provider']].forEach(function (p) {
    assert.equal(U.serviceOf(p[0]), p[1], p[0] + ' should be flagged');
  });

  ['dns4up.duckdns.org', 'mailmassange.duckdns.org', 'aka1.hopto.org',
   'acf02ac96211.ngrok-free.app', 'tenant-upcoming-great-descending.trycloudflare.com',
   'haimi-file.oss-cn-hangzhou.aliyuncs.com',
   'skillhub-1388575217.cos.ap-guangzhou.myqcloud.com',
   'cs-pgcwufmiws.cn-hangzhou.fcapp.run'].forEach(function (h) {
    assert.equal(U.serviceOf(h), null,
      h + " is the operator's own hostname and must stay blockable");
  });
});

test('A SHARED PROVIDER ENDPOINT IS FLAGGED THROUGHOUT ITS SUBTREE', function () {
  // Here the leftmost label belongs to the PROVIDER, not the attacker: a Cloudflare
  // nameserver serves thousands of zones and gofile's storeN endpoints rotate
  // across every upload.
  [['paloma.ns.cloudflare.com', 'provider nameserver'],
   ['peyton.ns.cloudflare.com', 'provider nameserver'],
   ['ns1.ddos-guard.net', 'provider nameserver'],
   ['ns2.ddos-guard.net', 'provider nameserver'],
   ['store8.gofile.io', 'file hosting endpoint'],
   ['s3.g.s4.mega.io', 'file hosting endpoint'],
   ['g.s4.mega.io', 'file hosting endpoint']].forEach(function (p) {
    assert.equal(U.serviceOf(p[0]), p[1], p[0]);
  });
});

test('ACTUAL ATTACKER INFRASTRUCTURE IS NEVER SWEPT UP', function () {
  // The failure that would matter more than the one this module prevents: a rule
  // broad enough to silence real indicators.
  ['inklens.ru', 'api.inklens.co.uk', 'evilsoul.cc', 'tralalarkefe.com',
   'kaidoo.com.br', 'stolotov.net', 'bikaf.ru', 'zujixiong.cn', 'unloki.ru',
   'c3lestial.fun', 'shinyhunte.rs', 'epgoldsecurity.com', 'bigass.monster',
   'mengchida.com', 'njmaixi.cn'].forEach(function (h) {
    assert.equal(U.serviceOf(h), null, h + ' was wrongly marked unblockable');
  });
});

test('a lookalike of a covered host is not covered', function () {
  // github.com is unblockable; github.com.evil.ru is the attacker's.
  assert.equal(U.serviceOf('github.com.evil.ru'), null);
  assert.equal(U.serviceOf('notpastebin.com'), null);
  assert.equal(U.serviceOf('duckdns.org.attacker.tk'), null);
  assert.equal(U.serviceOf('microsoft.com-app.cc'), null);
});

test('a subdomain of an EXACT-match host is not automatically covered', function () {
  // pastebin.com is exact; nothing legitimate lives at evil.pastebin.com, so the
  // rule stays narrow where a provider suffix is not warranted.
  assert.equal(U.serviceOf('evil.pastebin.com'), null);
  assert.ok(U.serviceOf('pastebin.com'));
});

test('MINING POOLS STAY BLOCKABLE, deliberately', function () {
  // Legitimate businesses, but blocking one breaks nothing an enterprise depends
  // on, and in a cryptojacking investigation the pool is the most actionable line
  // in the whole feed.
  ['pool.supportxmr.com', 'xmrpool.eu', 'auto.c3pool.org', 'cfx.kryptex.network',
   'cfx-asia1.nanopool.org'].forEach(function (h) {
    assert.equal(U.serviceOf(h), null, h + ' must stay blockable');
  });
});

test('A PATH-BEARING URL IS A PRECISE INDICATOR AND STAYS', function () {
  /* The distinction that separates protecting a defender from destroying the
     finding. https://github.com/ is the platform; https://github.com/Vova75Rus/miner
     is the operator's own repository and the most useful line in that feed.
     Blocking the exact URL costs nobody anything. */
  assert.equal(U.unblockable('url', 'https://github.com/Vova75Rus/miner'), null);
  assert.equal(U.unblockable('url', 'https://t.me/inkconnectvpn'), null);
  assert.equal(U.unblockable('url', 'https://pastebin.com/raw/bzg5zj8n'), null);
  assert.equal(U.unblockable('url', 'https://api.telegram.org/bot123/sendMessage'), null);
  assert.equal(U.unblockable('url', 'http://x.duckdns.org:8080/payload.bin'), null);
});

test('a bare host or bare root url is what actually gets ingested as a block', function () {
  assert.ok(U.unblockable('url', 'https://ipwho.is/'));
  assert.ok(U.unblockable('url', 'https://pastebin.com'));
  assert.ok(U.unblockable('url', 'http://icanhazip.com/'));
  assert.ok(U.unblockable('domain', 'api.telegram.org'));
});

test('attacker infrastructure is untouched whether or not it has a path', function () {
  assert.equal(U.unblockable('url', 'https://evilsoul.cc/panel'), null);
  assert.equal(U.unblockable('url', 'https://evilsoul.cc/'), null);
});

test('hashes and file names are never judged by this module', function () {
  assert.equal(U.unblockable('sha256', 'a'.repeat(64)), null);
  assert.equal(U.unblockable('filename', 'agent.exe'), null);
  assert.equal(U.unblockable('ipv4', '185.49.126.140'), null);
});

test('case and a trailing dot do not defeat it', function () {
  assert.ok(U.serviceOf('API.Telegram.ORG'));
  assert.ok(U.serviceOf('api.telegram.org.'));
  assert.ok(U.serviceOf('  api.telegram.org  '));
});

test('nothing empty or malformed throws', function () {
  [null, undefined, '', '   ', '...', 'no-dots'].forEach(function (v) {
    assert.doesNotThrow(function () { U.serviceOf(v); });
  });
});

test('the bucket name matches the convention already in the corpus', function () {
  // One feed invented `hunt_only_never_block` before this module existed. Keeping
  // that exact name means the existing entry needs no migration and the analyst who
  // wrote it recognises the standard as their own.
  assert.equal(U.BUCKET, 'hunt_only_never_block');
});

test('every category label is a short human phrase, since it ships in the feed', function () {
  var all = Object.keys(U.SERVICES).map(function (k) { return U.SERVICES[k]; })
    .concat(Object.keys(U.SUFFIXES).map(function (k) { return U.SUFFIXES[k]; }));
  all.forEach(function (c) {
    assert.ok(c && c.length < 40 && c === c.toLowerCase(), 'bad category: ' + c);
  });
});
