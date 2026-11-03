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
  var RX_FILENAME = /^[a-z0-9][a-z0-9._$@~-]*\.(exe|dll|ps1|bat|cmd|vbs|vbe|jse|jar|elf|bin|scr|msi|lnk|sys|hta|wsf|jsp|aspx|asp|php|ocx|cpl|drv|pyc|apk|deb|rpm|iso|img|js|json|xml|html|htm|svg|css|doc|docx|docm|xls|xlsx|xll|csv|txt|log|ini|cfg|conf|rc|url|job|msc|reg|rar|gz|tar|war|dmp|pcap|ndf|old|tmp|png|jpg|jpeg|gif|ttf|woff|sql|arm|mips|mpsl|ppc|x86|x64|yar|yara)$/i;

  function refang(s) {
    return String(s)
      .replace(/\[\.\]/g, '.')
      .replace(/\[:\]/g, ':')
      .replace(/\[@\]/g, '@')
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
      .replace(/\[@\]/g, '@')   /* the e-mail form this site prints (op[@]evil[.]example): without it the brackets are token breaks and the link searches the e-mail's domain instead */
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

  /* --- DISPLAY DEFANG (T-0500.1.7.4 fix-r1, review finding 1) ------------------------------------------------------------------------------------------------------
     Joseph, 2026-11-02, decision 5: every network indicator the site shows is defanged, so nobody clicks one or pastes it live by accident. The page layouts do that at build
     time; text a SCRIPT writes after load (the search result sentence, its per-indicator breakdown, the report titles read from the index) does not pass through the layouts,
     so it goes through these two functions. The classifier keeps matching on the refanged, lowercased form; only what is displayed is defanged.

     The forms are the ones _includes/defang-text.html and the IOC viewer use: http -> hxxp, https -> hxxps, every dot of an address, name or URL -> [.], the @ of an e-mail
     address -> [@]. A hash, a filename or any other type is returned as it is. Both functions are idempotent: a value that is already defanged comes out unchanged. */
  var NETWORK_TYPES = { ipv4: 1, ipv6: 1, domain: 1, endpoint: 1, url: 1, email: 1 };

  function unfang(s) {
    return String(s).replace(/\[\.\]/g, '.').replace(/\[@\]/g, '@').replace(/\[:\]/g, ':').replace(/\b(h)xx(ps?:\/\/)/gi, '$1tt$2');
  }

  /* IPv6 (fix-r2, review finding S3). The colons of an address become [:], the form _includes/defang-text.html prints ("2001[:]db8[:][:]7"). classify() does not emit an ipv6 type, but a
     table cell can carry one and a title can name one, so the display functions handle it. A bracketed literal keeps the brackets and a port after them ("[2001:db8::7]:443" ->
     "[2001[:]db8[:][:]7]:443"); in any other network type only a bracketed literal is touched, so a port, a scheme colon and a time in a path keep theirs. */
  function ipv6Colons(s, type) {
    if (type === 'ipv6' && s.indexOf('[') === -1) return s.replace(/:/g, '[:]');
    return s.replace(/\[([0-9a-f:.]*:[0-9a-f:.]*)\]/gi, function (m, a) { return '[' + a.replace(/:/g, '[:]') + ']'; });
  }

  /* One value of a known type. */
  function defangValue(value, type) {
    var s = String(value == null ? '' : value);
    if (!NETWORK_TYPES[type]) return s;
    s = unfang(s);
    if (type === 'url') s = s.replace(/https?:\/\//gi, function (m) { return m.replace(/tt/i, 'xx'); }); /* every scheme, a URL inside a path included */
    if (type === 'email') s = s.replace(/@/g, '[@]');
    return ipv6Colons(s, type).replace(/\./g, '[.]');
  }

  /* A bare IPv6 address by grammar, not by shape: hex groups of 1 to 4 digits, one optional "::", an optional IPv4 tail, eight groups or fewer with "::". A time (12:30:45), a MAC
     (aa:bb:cc:dd:ee:ff, six groups) and "std::string" are not addresses; "2001:db8::", "::1" and "2001:db8:1:2:3:4:5:6" are. */
  function isIpv6(a) {
    if (!/^[0-9a-f:.]+$/i.test(a) || a.indexOf(':') === -1 || /:::/.test(a)) return false;
    var halves = a.split('::');
    if (halves.length > 2) return false;
    var tail4 = /(\d{1,3}\.){3}\d{1,3}$/.test(a);
    var groups = 0, ok = true;
    halves.forEach(function (h, hi) {
      if (!h) return;
      h.split(':').forEach(function (g, gi, all) {
        if (tail4 && hi === halves.length - 1 && gi === all.length - 1) {
          groups += 2;
          if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(g) || g.split('.').some(function (o) { return Number(o) > 255; })) ok = false;
        } else if (/^[0-9a-f]{1,4}$/i.test(g)) groups++;
        else ok = false;
      });
    });
    if (!ok) return false;
    if (halves.length === 2) return groups <= 7 && /[0-9a-f]/i.test(a);
    return groups === 8;
  }

  function defangIpv4Inside(s) {
    return s.replace(/(^|[^0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9])/g, function (m, pre, ip) {
      var ok = ip.split('.').every(function (o) { return Number(o) <= 255; });
      return ok ? pre + ip.replace(/\./g, '[.]') : m;
    });
  }

  /* Free text: a report title, a sentence. Words are cut at whitespace , ; and |; the punctuation round a word is taken off, the rest is judged by the classifier above,
     exactly as a pasted token is, so what the search would match is what is defanged. A URL without a scheme (host/path) has its host defanged; an IPv4 address inside a
     longer word ("Toolkit-193.233.202.17-Repository") is defanged too. A word that is not an indicator comes back untouched, so a title keeps its own spelling. */
  function defangText(text) {
    return String(text == null ? '' : text).replace(/[^\s,;|]+/g, function (word) {
      var un = unfang(word);
      /* a bare or bracketed IPv6 address (and "[addr]:port") before the generic trimming below, which would cut the trailing colons of "2001:db8::" off as punctuation */
      var m6 = /^([<("'`]*)(\[?)([0-9a-f:.]*[0-9a-f:])(\]?)(:\d{1,5})?([>)"'`,;!?.]*)$/i.exec(un);
      if (m6 && !!m6[2] === !!m6[4] && (m6[2] || !m6[5]) && isIpv6(m6[3])) return m6[1] + defangValue(m6[2] + m6[3] + m6[4], 'ipv6') + (m6[5] || '') + m6[6];
      var lead = /^[<("'`\[]*/.exec(un)[0];
      var rest = un.slice(lead.length);
      var tail = /[>)"'`,;:!?.\]]*$/.exec(rest)[0];
      var core = rest.slice(0, rest.length - tail.length);
      if (!core) return word;
      var k = classify(core);
      if (k && NETWORK_TYPES[k.type]) return lead + defangValue(core, k.type) + tail;
      var slash = core.indexOf('/');
      if (slash > 0) {
        var h = classify(core.slice(0, slash));
        if (h && NETWORK_TYPES[h.type]) return lead + defangValue(core.slice(0, slash), h.type) + core.slice(slash) + tail;
      }
      var inside = defangIpv4Inside(core);
      return inside !== core ? lead + inside + tail : word;
    });
  }

  return {
    classify: classify,
    extract: extract,
    defangValue: defangValue,
    defangText: defangText,
    isIpv6: isIpv6,
    TYPES: ['sha256', 'sha1', 'md5', 'url', 'ipv4', 'email', 'domain', 'filename']
  };
}));
