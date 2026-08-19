'use strict';

/* Values that must never sit in an indicator bucket, because someone will block them.

   The IOC feeds are the machine-readable product. They are meant to be ingested
   automatically, and some people will pipe them straight into a blocklist without
   reading a word. That is a reasonable thing to do with a feed and it is what this
   module exists to make safe.

   Measured across the 57 published feeds on 2026-08-19: 63 distinct hosts that no
   organisation should ever block sat in ordinary indicator buckets, across 21 of
   the feeds. Five of them were suppressed from the public search index; none were
   kept out of the feeds themselves. `api.telegram.org`, `pastebin.com`, `github.com`,
   `api.ipify.org`, `download.anydesk.com`, an ngrok tunnel, a DuckDNS host and a
   Cloudflare nameserver were all published as things to match on.

   THE CONVENTION IS NOT NEW. One feed already carried a bucket named
   `hunt_only_never_block` holding `api.telegram.org`, invented by whoever wrote it.
   Another used `investigated_and_excluded`. This module standardises that instinct
   rather than replacing it: the bucket is promoted to TOP LEVEL, so it sits outside
   `network_indicators`, `host_indicators` and `file_hashes`, and a consumer walking
   the indicator buckets never reaches it. Nesting it inside one, as the second feed
   did, defeats the entire point.

   WHAT IS NOT HERE, deliberately:

   - Mining pools. supportxmr, nanopool, c3pool, kryptex and xmrpool are legitimate
     businesses, and blocking them is a reasonable, common and harmless defensive
     action that breaks nothing an enterprise depends on. In a cryptojacking
     investigation the pool is the single most actionable line in the feed, so they
     stay blockable.
   - Victims and their infrastructure. Those cannot be enumerated in advance, because
     they are different every investigation. They are removed by hand and kept out by
     the authoring rules in the `ioc-formatting` skill, and the claim matrix records
     that as ungated rather than pretending otherwise.

   The test for entry is not "is this domain benign" but "would a defender blocking
   this break something their organisation depends on, or block a bystander". */

/* Exact hosts. A subdomain of one of these is NOT covered unless the parent is in
   SUFFIXES below, because `evil.pastebin.com` does not exist but `evil.duckdns.org`
   very much does. */
var SERVICES = {
  // Messaging and social platforms used as C2 or exfil channels.
  'api.telegram.org': 'messaging platform',
  't.me': 'messaging platform',
  'telegram.org': 'messaging platform',
  'discord.com': 'messaging platform',
  'discordapp.com': 'messaging platform',
  'cdn.discordapp.com': 'messaging platform',
  'discord.gg': 'messaging platform',
  'api.telegram.com': 'messaging platform',
  'slack.com': 'messaging platform',

  // Paste and code sharing, used for staging and configuration.
  'pastebin.com': 'paste or code sharing',
  'paste.ee': 'paste or code sharing',
  'hastebin.com': 'paste or code sharing',
  'privatebin.net': 'paste or code sharing',
  'controlc.com': 'paste or code sharing',
  'rentry.co': 'paste or code sharing',
  'github.com': 'paste or code sharing',
  'gist.github.com': 'paste or code sharing',
  'raw.githubusercontent.com': 'paste or code sharing',
  'objects.githubusercontent.com': 'paste or code sharing',
  'goproxy.github.io': 'paste or code sharing',
  'gitlab.com': 'paste or code sharing',
  'bitbucket.org': 'paste or code sharing',
  'codeberg.org': 'paste or code sharing',

  // "What is my IP" services, called by almost every stealer and by ordinary software.
  'api.ipify.org': 'ip lookup service',
  'ipify.org': 'ip lookup service',
  'icanhazip.com': 'ip lookup service',
  'ifconfig.me': 'ip lookup service',
  'ifconfig.co': 'ip lookup service',
  'ip-api.com': 'ip lookup service',
  'ip.sb': 'ip lookup service',
  'ipwho.is': 'ip lookup service',
  'ipinfo.io': 'ip lookup service',
  'wtfismyip.com': 'ip lookup service',
  'checkip.amazonaws.com': 'ip lookup service',
  'checkip.dyndns.org': 'ip lookup service',
  'iplogger.org': 'ip lookup service',
  'freegeoip.app': 'ip lookup service',
  'ipapi.co': 'ip lookup service',

  // File hosting and cloud storage used to stage payloads or receive exfil.
  'gofile.io': 'file hosting',
  'mega.io': 'file hosting',
  'mega.nz': 'file hosting',
  'anonfiles.com': 'file hosting',
  'transfer.sh': 'file hosting',
  'file.io': 'file hosting',
  'dropbox.com': 'file hosting',
  'dl.dropboxusercontent.com': 'file hosting',
  'drive.google.com': 'file hosting',
  'onedrive.live.com': 'file hosting',
  'catbox.moe': 'file hosting',
  'temp.sh': 'file hosting',
  'uguu.se': 'file hosting',
  'bashupload.com': 'file hosting',

  // Vendor download and legitimate software the malware fetches or abuses.
  'download.anydesk.com': 'vendor download',
  'anydesk.com': 'vendor download',
  'www.amyuni.com': 'vendor download',
  'amyuni.com': 'vendor download',
  'downloads.rclone.org': 'vendor download',
  'rclone.org': 'vendor download',
  'nssm.cc': 'vendor download',
  'curl.se': 'vendor download',
  'www.python.org': 'vendor download',
  'nodejs.org': 'vendor download',
  'api.binance.com': 'vendor download',
  'generativelanguage.googleapis.com': 'vendor download',
  'open.oppomobile.com': 'vendor download',
  'web.archive.org': 'vendor download',
  'archive.org': 'vendor download',
  'rebel.com': 'vendor download',
  'intezer.com': 'security vendor',
  'www.virustotal.com': 'security vendor',
  'virustotal.com': 'security vendor',
  'any.run': 'security vendor',
  'www.usom.gov.tr': 'security authority',
  'usom.gov.tr': 'security authority',

  // Tunnelling and remote access, dual-use but never blockable wholesale.
  'serveo.net': 'tunnelling service',
  'gsocket.io': 'tunnelling service',
  'cdn.gsocket.io': 'tunnelling service',
  'localtunnel.me': 'tunnelling service',
  'webhook.site': 'request inspection service',
  'requestbin.com': 'request inspection service',
  'pipedream.net': 'request inspection service',
  'canarytokens.com': 'request inspection service'
};

/* Provider domains whose SUBDOMAIN identifies the attacker, not the provider.

   Only the bare domain is listed, and that is the whole point. `duckdns.org` in a
   blocklist takes out DuckDNS for the estate; `dns4up.duckdns.org` is the hostname
   the operator registered, and a defender should absolutely block it. The same
   holds for an ngrok tunnel, a Cloudflare quick-tunnel, an Alibaba OSS bucket and a
   Firebase app: the leftmost label is the attacker's choice, so the FQDN is a
   precise indicator and blocking it costs nobody else anything.

   Getting this backwards would be the more damaging error. It would strip the real
   C2 hostname out of a feed and leave the defender with nothing to match on, which
   is worse than the problem this module exists to solve. */
var TENANT_NAMESPACES = {
  'ngrok.io': 'tunnelling provider',
  'ngrok-free.app': 'tunnelling provider',
  'ngrok.app': 'tunnelling provider',
  'trycloudflare.com': 'tunnelling provider',
  'loca.lt': 'tunnelling provider',
  'telebit.io': 'tunnelling provider',
  'pagekite.me': 'tunnelling provider',
  'localhost.run': 'tunnelling provider',
  'duckdns.org': 'dynamic dns provider',
  'hopto.org': 'dynamic dns provider',
  'no-ip.org': 'dynamic dns provider',
  'no-ip.biz': 'dynamic dns provider',
  'ddns.net': 'dynamic dns provider',
  'zapto.org': 'dynamic dns provider',
  'sytes.net': 'dynamic dns provider',
  'myftp.org': 'dynamic dns provider',
  'dynu.com': 'dynamic dns provider',
  'dynv6.net': 'dynamic dns provider',
  'nsupdate.info': 'dynamic dns provider',
  'aliyuncs.com': 'cloud provider',
  'myqcloud.com': 'cloud provider',
  'fcapp.run': 'cloud provider',
  'amazonaws.com': 'cloud provider',
  'cloudfront.net': 'cloud provider',
  'blob.core.windows.net': 'cloud provider',
  'workers.dev': 'cloud provider',
  'pages.dev': 'cloud provider',
  'web.app': 'cloud provider',
  'firebaseapp.com': 'cloud provider',
  'netlify.app': 'cloud provider',
  'vercel.app': 'cloud provider',
  'herokuapp.com': 'cloud provider',
  'glitch.me': 'cloud provider',
  'repl.co': 'cloud provider',
  'r2.dev': 'cloud provider'
};

/* Suffixes where EVERY host is the provider's own shared infrastructure, so the
   whole subtree is unblockable. The leftmost label here is assigned by the
   provider and shared across unrelated customers: a Cloudflare nameserver serves
   thousands of zones, and gofile's storeN endpoints rotate across all uploads. */
var SUFFIXES = {
  'ns.cloudflare.com': 'provider nameserver',
  'ddos-guard.net': 'provider nameserver',
  'domaincontrol.com': 'provider nameserver',
  'registrar-servers.com': 'provider nameserver',
  'gofile.io': 'file hosting endpoint',
  's4.mega.io': 'file hosting endpoint'
};

function norm(h) {
  return String(h == null ? '' : h).trim().toLowerCase().replace(/\.$/, '');
}

/* Returns the category string when `host` must never be blocked, else null. */
function serviceOf(host) {
  var h = norm(host);
  if (!h) return null;
  if (SERVICES[h]) return SERVICES[h];
  // Exact only: the bare provider domain is unblockable, a tenant under it is not.
  if (TENANT_NAMESPACES[h]) return TENANT_NAMESPACES[h];
  var keys = Object.keys(SUFFIXES);
  for (var i = 0; i < keys.length; i++) {
    var s = keys[i];
    if (h === s || h.slice(-(s.length + 1)) === '.' + s) return SUFFIXES[s];
  }
  return null;
}

/* Same question, asked of a classified indicator rather than a bare host.

   A URL is judged by its host, but ONLY when it carries no meaningful path. This
   distinction is the difference between protecting a defender and destroying the
   finding:

     https://github.com/                       the platform. Blocking it is a disaster.
     https://github.com/Vova75Rus/miner        the operator's own repository, and the
                                               single most useful line in that feed.

   The same holds for `https://t.me/inkconnectvpn` (the actor's channel),
   `https://pastebin.com/raw/bzg5zj8n` (the dead drop) and
   `https://api.telegram.org/bot<token>/sendDocument` (the bot token). Every one is a
   precise indicator that happens to live on a shared host, and blocking that exact
   URL costs nobody anything.

   So a path-bearing URL stays where it is. What moves is the bare host and the bare
   root, which are the forms that get ingested as a domain block. */
function pathOf(url) {
  var m = /^[a-z]+:\/\/[^\/?#]+([^?#]*)/i.exec(String(url));
  return m ? m[1] : '';
}

function unblockable(type, value) {
  if (type === 'domain') return serviceOf(value);
  if (type === 'url') {
    var host = (/^[a-z]+:\/\/([^\/:?#]+)/i.exec(String(value)) || [])[1];
    if (!host) return null;
    var p = pathOf(value).replace(/^\/+/, '');
    if (p) return null;                 // a real path makes it a precise indicator
    return serviceOf(host);
  }
  return null;
}

module.exports = {
  serviceOf: serviceOf,
  pathOf: pathOf,
  unblockable: unblockable,
  SERVICES: SERVICES,
  TENANT_NAMESPACES: TENANT_NAMESPACES,
  SUFFIXES: SUFFIXES,
  BUCKET: 'hunt_only_never_block'
};
