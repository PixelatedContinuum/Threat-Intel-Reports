'use strict';

/* Values that are never indexed, however a feed records them.

   This exists because the lookup's credibility is spent on its first false
   positive. Measured in the real feeds on 2026-08-19: `8.8.8.8` appears in the
   Arsenal-237 feed, `127.0.0.1` in two feeds, `github.com` in the SE-Asia
   toolkit, and `bing.com` in the GHOST cryptojacker feed as a Hysteria v2 SNI
   masquerade. Every one of those is a true statement about the malware and a
   useless thing to match a defender's logs against, because essentially every
   network contains all four. Someone pasting proxy logs would get four hits,
   none of them meaning anything, and would rightly stop trusting the page.

   The test is not "is this value benign" but "does its presence in a
   defender's logs carry any signal". Suppression happens HERE, on the index
   side only. The page still extracts these from pasted text so they count
   toward "N indicators checked": the reader should see that the value was
   looked at and did not match, rather than silently vanishing.

   Suppressing at index time deliberately does NOT edit the source feeds. A
   feed recording that a sample called 8.8.8.8 for a connectivity check is
   correct and should keep saying so. */

// Rule-based, because these ranges can never be a useful public indicator.
var RESERVED_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^22[4-9]\.|^23\d\./,          // multicast
  /^24\d\.|^25[0-5]\./,          // reserved / broadcast
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./  // CGNAT
];

// Curated, because no rule distinguishes these from any other domain or host.
// Keep it SHORT and defensible: every entry must be something a defender's logs
// almost certainly contain regardless of any compromise.
var BENIGN_DOMAINS = [
  'google.com', 'www.google.com', 'googleapis.com', 'gstatic.com', 'google-analytics.com',
  'microsoft.com', 'www.microsoft.com', 'windows.com', 'windowsupdate.com', 'live.com',
  'office.com', 'office365.com', 'msn.com', 'bing.com', 'msftconnecttest.com',
  'github.com', 'raw.githubusercontent.com', 'githubusercontent.com',
  'cloudflare.com', 'cloudflare-dns.com', 'amazonaws.com', 'cloudfront.net',
  'akamai.net', 'akamaiedge.net', 'apple.com', 'icloud.com',
  'mozilla.org', 'wikipedia.org', 'youtube.com', 'facebook.com', 'twitter.com',
  'digicert.com', 'ocsp.digicert.com', 'verisign.com', 'letsencrypt.org',
  'sectigo.com', 'globalsign.com', 'localhost', 'example.com', 'example.org'
];

var BENIGN_IPS = [
  '8.8.8.8', '8.8.4.4',           // Google DNS
  '1.1.1.1', '1.0.0.1',           // Cloudflare DNS
  '9.9.9.9', '149.112.112.112',   // Quad9
  '208.67.222.222', '208.67.220.220', // OpenDNS
  '4.2.2.1', '4.2.2.2'            // Level3
];

var domainSet = {};
BENIGN_DOMAINS.forEach(function (d) { domainSet[d] = 1; });
var ipSet = {};
BENIGN_IPS.forEach(function (i) { ipSet[i] = 1; });

/* True when `value` of `type` must not enter the index. */
function isBenign(type, value) {
  if (type === 'ipv4') {
    if (ipSet[value]) return true;
    for (var i = 0; i < RESERVED_V4.length; i++) {
      if (RESERVED_V4[i].test(value)) return true;
    }
    return false;
  }
  if (type === 'domain') {
    if (domainSet[value]) return true;
    // A subdomain of a benign platform is equally signal-free.
    for (var d in domainSet) {
      if (domainSet.hasOwnProperty(d) && value.length > d.length &&
          value.slice(-(d.length + 1)) === '.' + d) return true;
    }
    return false;
  }
  if (type === 'url') {
    var m = /^https?:\/\/([^\/:?#]+)/i.exec(value);
    return m ? isBenign('domain', m[1].toLowerCase()) || isBenign('ipv4', m[1]) : false;
  }
  return false;   // hashes and emails are specific by construction
}

module.exports = {
  isBenign: isBenign,
  BENIGN_DOMAINS: BENIGN_DOMAINS,
  BENIGN_IPS: BENIGN_IPS
};
