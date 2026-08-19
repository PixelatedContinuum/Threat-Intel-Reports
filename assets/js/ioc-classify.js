/* Shared indicator classifier for The Hunter's Ledger.

   THIS FILE IS LOADED TWICE, ON PURPOSE. The build-time index generator
   requires it under Node; /lookup/ loads it in the browser. That is the whole
   point: the generator normalises indicators INTO the index and the page
   normalises pasted text BEFORE matching, so if those two ever disagreed, by a
   lowercase, a refang, a stripped port or a trailing dot, the lookup would
   return nothing and present as a clean bill of health. A tool that silently
   tells a defender they are unaffected is worse than no tool. One file makes
   the disagreement impossible rather than merely unlikely.

   Typing is by VALUE PATTERN, never by which JSON key a value was found under.
   Measured reason: across the 57 published feeds the indicators live under 20+
   differently-named buckets, and buckets like `ExploitEndpoints` mix URI paths
   in beside real indicators. Only the value itself is reliable. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) { module.exports = factory(); }
  else { root.HLIocClassify = factory(); }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var RX_SHA256 = /^[a-f0-9]{64}$/i;
  var RX_SHA1   = /^[a-f0-9]{40}$/i;
  var RX_MD5    = /^[a-f0-9]{32}$/i;
  var RX_URL    = /^https?:\/\/\S+$/i;
  var RX_IPV4   = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/;
  var RX_EMAIL  = /^[^@\s]+@([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,24})$/i;
  var RX_DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,24}$/i;

  /* A filename is not a domain, however much `payload.dll` looks like one.

     Measured on the live index 2026-08-19: 222 of 1,670 indexed values were
     filenames typed as `domain`, because they satisfy the domain grammar exactly
     as `example.co` does. Among them chrome.exe, brave.exe, msedge.exe,
     MsMpEng.exe, csfalconservice.exe and csagent.exe, all of which sit on
     ordinary Windows estates. Anyone pasting a process list or an EDR export into
     the public search box was told their environment matched an investigation.

     The extensions below deliberately EXCLUDE any that is also a real TLD: .com,
     .sh, .py and .so all resolve as domains and must keep doing so. Nothing in a
     bare token separates `evil.sh` the script from `evil.sh` the St Helena
     domain, so the ambiguity is resolved in the safe direction: a filename
     mislabelled as a domain is a display nit, a domain mislabelled as a filename
     would stop a real indicator matching. */
  var RX_FILENAME = /^[a-z0-9][a-z0-9._$@~-]*\.(exe|dll|ps1|bat|cmd|vbs|vbe|jar|elf|bin|scr|msi|lnk|sys|hta|wsf|jse|jsp|aspx|ocx|cpl|drv|pyc|apk|deb|rpm|iso|img)$/i;

  function refang(s) {
    return String(s)
      .replace(/\[\.\]/g, '.')
      .replace(/\[:\]/g, ':')
      .replace(/^hxxp/i, 'http');
  }

  /* Trailing punctuation is stripped because pasted text is prose and log
     lines: "host bot.example.com." and 'url="https://x/a",' are both normal. */
  function trim(s) {
    return String(s == null ? '' : s)
      .trim()
      .replace(/^[<("'\[]+/, '')
      .replace(/[>)"'\],;]+$/, '')
      .replace(/\.+$/, '');
  }

  function lowerHost(url) {
    var m = /^(https?:\/\/)([^\/?#]+)(.*)$/i.exec(url);
    return m ? m[1].toLowerCase() + m[2].toLowerCase() + m[3] : url;
  }

  /* Template and redaction placeholders. Measured in the real feeds:
     "http://.../bins/Naku.{arch}" is a build template, and
     "https://[victim-subdomain].ocpinstana.[victim-domain].com.tr" is a
     REDACTED victim URL. Neither is a concrete indicator anyone could match on,
     and the second should never reach a public index at all. Rejecting them in
     the classifier fixes both sides at once: the generator stops indexing them
     and the page stops trying to find them. */
  var RX_PLACEHOLDER = /[{}\[\]<>]/;

  function classify(raw) {
    if (raw == null) return null;
    var s = trim(refang(raw));
    if (!s || /\s/.test(s)) return null;
    if (RX_PLACEHOLDER.test(s)) return null;

    if (RX_SHA256.test(s)) return { type: 'sha256', value: s.toLowerCase() };
    if (RX_SHA1.test(s))   return { type: 'sha1',   value: s.toLowerCase() };
    if (RX_MD5.test(s))    return { type: 'md5',    value: s.toLowerCase() };
    if (RX_URL.test(s))    return { type: 'url',    value: lowerHost(s) };

    var m = RX_IPV4.exec(s);
    if (m) {
      var parts = m[1].split('.');
      for (var i = 0; i < 4; i++) {
        if (parts[i].length > 3 || Number(parts[i]) > 255) return null;
      }
      return { type: 'ipv4', value: m[1] };
    }

    if (RX_EMAIL.test(s))  return { type: 'email',    value: s.toLowerCase() };
    // Before the domain test, or every .exe is a domain.
    if (RX_FILENAME.test(s)) return { type: 'filename', value: s.toLowerCase() };
    if (RX_DOMAIN.test(s)) return { type: 'domain',   value: s.toLowerCase() };
    return null;
  }

  /* Split pasted text into candidate tokens. Whitespace is the primary
     delimiter; quotes, commas, angle brackets and braces are stripped because
     real log lines wrap indicators in them. Slashes are NOT delimiters, or
     every URL would be shredded. */
  function extract(text) {
    var out = [], seen = {};
    /* Refang the WHOLE text before tokenising. Brackets are delimiters, so
       splitting first would shred "bot[.]example[.]com" into three useless
       fragments, and a defanged paste is the single most likely thing a
       defender copies out of a threat report. */
    var tokens = refang(String(text == null ? '' : text)
      .replace(/\[\.\]/g, '.')
      .replace(/\(\.\)/g, '.')
      .replace(/\[:\]/g, ':')
      .replace(/\bhxxp/gi, 'http'))
      .split(/[\s,;<>"'()\[\]{}|]+/);
    for (var i = 0; i < tokens.length; i++) {
      var tok = tokens[i];
      if (!tok) continue;
      var r = classify(tok);
      if (!r && tok.indexOf('=') > -1) {
        // key=value pairs are ubiquitous in log lines.
        r = classify(tok.slice(tok.lastIndexOf('=') + 1));
      }
      if (!r) continue;
      var key = r.type + ':' + r.value;
      if (seen[key]) continue;
      seen[key] = 1;
      out.push({ type: r.type, value: r.value, raw: tok });
    }
    return out;
  }

  return {
    classify: classify,
    extract: extract,
    TYPES: ['sha256', 'sha1', 'md5', 'url', 'ipv4', 'email', 'domain', 'filename']
  };
}));
