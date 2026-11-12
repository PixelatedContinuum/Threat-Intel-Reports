'use strict';

/* The RENDERED-page defang check (T-0500.1.7.4, Joseph 2026-11-02: "We should defang everything ... I do not want to risk people clicking on
   something or accidentally pasting it in the wrong way"). check-defang.js reads a report's SOURCE; this module reads the built site
   (`jekyll build` output, `_site`) and covers every NON-REPORT page: the index pages, the actor, family and technique profiles, the IOC viewer,
   the detection pages' prose, the Wire, the single pages.

   node check-defang.js --site <_site dir> [--allow-data FILE] [--all]

   WHAT IT FAILS (exit 1), per page, on the text a reader sees:
     1. a network indicator (URL, IPv4, IPv6 URL, domain on an IANA TLD, e-mail) in a text node or in a tooltip attribute (title, alt,
        aria-label, placeholder, data-copy) that is not defanged and not in the `raw` list of _data/defang_allow.yml. Same scanner and same
        defang forms as the report lint (scanLine): hxxp, [.], [@], [:].
     2. a clickable <a> whose target is an IP address (LINK-IP), whose host is not in the `links` list (LINK-UNLISTED; the Wire is exempt
        from this one because its article links are curated feed publishers, never actor infrastructure), or a mailto: to a mailbox that
        is not ours (LINK-MAILTO).
     3. a raw indicator in a <pre> block of a page that is not a detection page (PRE-OUTSIDE-DETECTION): a <pre> on a detection page is a
        rule body and stays exact (decision 5), anywhere else it is page text.
   A <pre> on a detection page is counted, with its raw indicators, never scanned: that is the one exact-by-design surface the gate reads.

   HEAD (T-0500.1.7.4 ship): the display strings of the <head> are scanned on every page: <title>, the meta content of a title, description or alt name (og:title, twitter:title,
   description, og:description, twitter:description, og:image:alt, twitter:image:alt) and every JSON-LD string except the URL-valued keys (kind HEAD-<KIND>, or HEAD-JSONLD-INVALID).

   NOT SEEN, said in the PASS line: text the page's scripts write after load (jsdom runs no script; check-browser-defang.js reads it in a real browser); the data-title search keys, which keep
   the raw text on purpose (the filter and the search match on it); head URLs (canonical, og:url, og:image, JSON-LD url and @id: own page addresses); the downloadable feed files; hrefs to this
   site's own pages (they hold slugs that carry the campaign's address).

   REPORT PAGES (reports/<slug>/, T-0500.1.7.4 ship) are scanned too: the source lint reads the markdown, this reads what the layout and the page add
   (the title in the header, the citation and BibTeX, the Continue Reading cards, tooltips) and what the markdown became. A report page is judged
   against the allow data PLUS its own tools/report-tooling/defang-allow/<slug>.txt, the list its source lint uses. On a report page:
     - a link to a reference (a vendor, MITRE, NVD, our own pages) is kept: LINK-UNLISTED does not apply, LINK-IP and LINK-MAILTO do;
     - LINK-ACTOR-HOST: a link whose host also appears DEFANGED in the same page's text is a clickable form of a named indicator (unless the
       host+path is under `links` in the allow data, e.g. our own sponsor page);
     - a <pre> marked .hl-copy is rule or copy text and stays exact (counted, never scanned, as the source lint does); any other <pre> (the BibTeX
       block) is page text and is scanned line by line: PRE-IN-REPORT.
   NOT SEEN on a report page, as everywhere: own-site hrefs, head URLs and image paths (the slug carries the address).

   EXCLUDED, counted and printed: the working docs /report-templates/ and the feed changelogs (decision 7), pagefind and asset directories.

   DENOMINATORS: pages scanned and excluded by type, text nodes, indicator-shaped tokens (flagged / defanged / private / allowed),
   attributes, links by class, <pre> blocks and the raw indicators inside them. A run that scanned no text node is NOT CHECKED. */

var fs = require('node:fs');
var path = require('node:path');
var D = require('../check-defang.js');

var TOOLTIP_ATTRS = ['title', 'alt', 'aria-label', 'placeholder', 'data-copy', 'data-gloss'];   // data-gloss: the glossary tooltip the script sets on a term (shown through CSS attr())
var SKIP_TAGS = 'script,style,template,noscript,pre';

function loadAllowData(file) {
  var yaml = require('js-yaml');
  var d = yaml.load(fs.readFileSync(file, 'utf8')) || {};
  var raw = d.raw || {}, links = d.links || [], mailboxes = d.mailboxes || {};
  var lines = [];
  Object.keys(raw).forEach(function (h) {
    var reason = String(raw[h] || '').trim();
    if (!reason) throw new Error('defang_allow.yml raw entry "' + h + '" has no reason');
    lines.push(h + '  # ' + reason.replace(/\n/g, ' '));
  });
  var allow = D.makeAllow([{ name: path.basename(file), text: lines.join('\n') }]);
  if (allow.bad.length) throw new Error('defang_allow.yml raw entries refused: ' + allow.bad.map(function (b) { return b.entry + ' (' + b.kind + ')'; }).join(', '));
  var L = links.map(function (e) {
    if (typeof e !== 'string' || !e.trim()) throw new Error('defang_allow.yml links entry is not a string');
    return e.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');
  });
  var mb = {};
  Object.keys(mailboxes).forEach(function (a) {
    if (!String(mailboxes[a] || '').trim()) throw new Error('defang_allow.yml mailboxes entry "' + a + '" has no reason');
    mb[a.toLowerCase()] = mailboxes[a];
  });
  return { allow: allow, rawText: lines.join('\n'), raw: raw, links: L, mailboxes: mb, rawCount: Object.keys(raw).length, mailboxCount: Object.keys(mb).length };
}

function pageType(rel) {
  var r = '/' + rel.replace(/index\.html$/, '');
  var table = [[/^\/reports\/[^\/]+\/(?:.+\/)?$/, 'report'], [/^\/reports\/$/, 'reports-index'], [/^\/hunting-detections\/[^\/]+\/$/, 'detection'], [/^\/hunting-detections\/$/, 'detections-index'],
    [/^\/ioc-feeds\/[^\/]+\/$/, 'ioc-feed'], [/^\/ioc-feeds\/$/, 'ioc-feeds-index'], [/^\/actors\/[^\/]+\/$/, 'actor'], [/^\/actors\/$/, 'actors-index'],
    [/^\/techniques\/[^\/]+\/$/, 'technique'], [/^\/techniques\/$/, 'techniques-index'], [/^\/families\/[^\/]+\/$/, 'family'], [/^\/families\/$/, 'families-index'],
    [/^\/behind-the-reports\/[^\/]+\/$/, 'behind-step'], [/^\/$/, 'home'], [/^\/wire\/$/, 'wire']];
  for (var i = 0; i < table.length; i++) if (table[i][0].test(r)) return table[i][1];
  return 'single:' + r.replace(/^\/|\/$/g, '');
}

function excluded(rel) {
  var r = '/' + rel.replace(/\\/g, '/');
  if (/^\/(pagefind[^\/]*|assets)\//.test(r)) return 'asset directory';
  if (/^\/feeds\/[^\/]+\/changelog\//.test(r)) return 'feed changelog (decision 7)';
  return null;
}

function walkHtml(root) {
  var out = [];
  (function walk(d) {
    fs.readdirSync(d, { withFileTypes: true }).sort(function (a, b) { return a.name < b.name ? -1 : 1; }).forEach(function (e) {
      var f = path.join(d, e.name);
      if (e.isDirectory()) walk(f);
      else if (/\.html$/i.test(e.name)) out.push(f);
    });
  })(root);
  return out;
}

/* The normalised form a link target is matched on: host + path without scheme, www, query or fragment, lower case. */
function linkKey(href) {
  var m = String(href).trim().match(/^(?:https?:)?\/\/([^\/?#]+)([^?#]*)/i);
  if (!m) return null;
  var host = m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase().replace(/^www\./, '');
  return { host: host, key: host + m[2].replace(/\/+$/, '').toLowerCase() };
}
function linkAllowed(key, links) {
  for (var i = 0; i < links.length; i++) {
    var e = links[i];
    if (key.key === e || key.key.indexOf(e + '/') === 0) return e;
  }
  return null;
}
function isIpHost(host) {
  if (/^\[.*\]$/.test(host)) return !/^\[(::1?|fe80:|fc|fd)/i.test(host);
  var m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  var o = m.slice(1).map(Number);
  if (o.some(function (n) { return n > 255; })) return false;
  return true;
}

function newStats() {
  return { pages: 0, byType: {}, excluded: {}, textNodes: 0, attrs: 0, inputValues: 0, matchedFlagged: 0, matchedDefanged: 0, matchedPrivate: 0, matchedAllowed: 0, allowedBy: {},
    links: { total: 0, relative: 0, anchor: 0, external: 0, externalAllowed: 0, mailto: 0, other: 0, labelSkips: 0, reportRefs: 0 },
    pre: { blocks: 0, lines: 0, rawIndicators: 0, onDetection: 0, offDetection: 0, copyKept: 0, onReport: 0 }, head: { fields: 0, jsonld: 0, tokens: 0 }, literal: { cells: 0, exemptLines: 0, exemptFields: 0 }, unlinked: { n: 0, targets: [] } };
}

/* Scan one parsed document. `JSDOM` is passed in so tests can hand a document directly. */
/* a short window of the line around a finding, for the report (printed defanged by the caller) */
function nearOf(line, token) {
  var i = line.indexOf(String(token).replace(/\[\.\]/g, '.'));
  if (i < 0) i = 0;
  return line.slice(Math.max(0, i - 40), i + String(token).length + 40).replace(/\s+/g, ' ');
}

/* The <head> display strings (T-0500.1.7.4 ship, lead decision 2026-11-02): a reader sees <title> in the tab and in bookmarks, and og:title, og:description, twitter:title,
   twitter:description, the image alt texts and the JSON-LD headline, name and description in every share card. Scanned: the <title>, every <meta content> whose name or property names a
   title, description or alt text, and every string of every JSON-LD block except the URL-valued ones (they are this site's own page addresses, the schema.org context, the licence). URLs
   in <link>, og:url, og:image and canonical stay exact and are not read. A JSON-LD block that does not parse is a finding (HEAD-JSONLD-INVALID), never skipped. */
var JSONLD_URL_KEYS = { '@context': 1, '@id': 1, '@type': 1, url: 1, image: 1, logo: 1, contentUrl: 1, identifier: 1, isBasedOn: 1, license: 1, sameAs: 1, mainEntityOfPage: 1, datePublished: 1, dateModified: 1, encodingFormat: 1 };
function scanHead(doc, rel, type, allow, stats, findings) {
  var head = doc.head;
  if (!head) return;
  var H = stats.head;
  function note(r, ctx, line) {
    H.tokens += r.flagged.length + r.defanged;
    r.flagged.forEach(function (f) { findings.push({ page: rel, type: type, ctx: ctx, kind: 'HEAD-' + f.kind, token: f.token, near: line ? nearOf(line, f.token) : '' }); });
  }
  var t = head.querySelector('title');
  if (t) { H.fields++; note(D.scanLine(t.textContent, allow), 'head:title', t.textContent); }
  Array.prototype.forEach.call(head.querySelectorAll('meta[content]'), function (m) {
    var key = (m.getAttribute('property') || '') + ' ' + (m.getAttribute('name') || '');
    if (!/title|description|alt/i.test(key)) return;
    var v = m.getAttribute('content') || '';
    H.fields++;
    note(D.scanLine(v, allow), 'head:' + key.trim().replace(/\s+/g, '+'), v);
  });
  Array.prototype.forEach.call(head.querySelectorAll('script[type="application/ld+json"]'), function (sc) {
    var j;
    try { j = JSON.parse(sc.textContent); } catch (e) { findings.push({ page: rel, type: type, ctx: 'head:jsonld', kind: 'HEAD-JSONLD-INVALID', token: String(e.message).slice(0, 80) }); return; }
    H.jsonld++;
    (function walk(v, key) {
      if (Array.isArray(v)) return v.forEach(function (x) { walk(x, key); });
      if (v && typeof v === 'object') return Object.keys(v).forEach(function (k) { walk(v[k], k); });
      if (typeof v !== 'string' || JSONLD_URL_KEYS[key]) return;
      H.fields++;
      note(D.scanLine(v, allow), 'head:jsonld:' + key, v);
    })(j, '');
  });
}

/* data-literal cells of the IOC viewer: see _includes/ioc-cell.html. A value is honoured only for these six types and only when it is not shaped like a URL, an e-mail address or an IP address,
   and (fix-r2, review finding S4) only when it is not NETWORK-BEARING: the same test the layout applies before it prints a cell as a literal (_includes/ioc-cell.html), so the layout and
   this gate agree on what a literal is. Network-bearing: a UNC path (two backslashes or two slashes first, "\\\\host.tld\\share"), a "://" anywhere, or an IPv4 address inside the name
   (two adjacent all-digit dot-separated parts of 1 to 3 digits below 256, as in "1468_US_23.106.161.1_28-01-26.cab"). Such a value is not literal: it is judged like prose. */
var LIT_TYPES = { sha256: /^[0-9a-f]{64}$/i, md5: /^[0-9a-f]{32}$/i, sha1: /^[0-9a-f]{40}$/i, filename: null, path: null, registry: null };
function networkBearing(val) {
  if (/^(?:\\\\|\/\/)/.test(val)) return 'starts like a UNC path (two backslashes or two slashes: a host)';
  if (val.indexOf('://') > -1) return 'holds a "://" (a URL)';
  var parts = val.split('.'), prev = false;
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i], isnum = i > 0 && i < parts.length - 1 && /^(?:0|[1-9]\d{0,2})$/.test(p) && Number(p) < 256;
    if (isnum && prev) return 'holds an IPv4 address (two adjacent all-digit dot-separated parts)';
    prev = isnum;
  }
  return '';
}
function literalProblem(ty, val) {
  return !Object.prototype.hasOwnProperty.call(LIT_TYPES, ty) ? 'unknown literal type "' + ty + '"' :
    (LIT_TYPES[ty] && !LIT_TYPES[ty].test(val)) ? 'does not look like a ' + ty :
    /^[a-z][a-z0-9+.-]*:\/\//i.test(val) || /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(val) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(val) ? 'is shaped like a URL, an e-mail address or an IP address' :
    (!LIT_TYPES[ty] && networkBearing(val)) ? 'is network-bearing: ' + networkBearing(val) : '';
}

/* The fields of one captured line, as {value, start, end} spans of the raw line: a CSV row (RFC 4180 quoting, as the viewer writes it) or a tab-separated row; a line with no separator
   is one field. A quoted field's value is unquoted, its span covers the quotes. */
function lineFields(line) {
  var out = [], cur = '', q = false, start = 0;
  for (var i = 0; i < line.length; i++) {
    var c = line[i];
    if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
    else if (c === '"' && cur === '') q = true;
    else if (c === ',' || c === '\t') { out.push({ value: cur, start: start, end: i }); cur = ''; start = i + 1; }
    else cur += c;
  }
  out.push({ value: cur, start: start, end: line.length });
  return out;
}

function scanDocument(doc, rel, data, stats, findings) {
  var type = pageType(rel), isWire = type === 'wire', isDet = type === 'detection', isRep = type === 'report';
  var allow = data.allow;
  function note(r, ctx, line) {
    stats.matchedFlagged += r.flagged.length; stats.matchedDefanged += r.defanged; stats.matchedPrivate += r.privateN; stats.matchedAllowed += r.allowedN;
    Object.keys(r.allowed).forEach(function (e) { stats.allowedBy[e] = (stats.allowedBy[e] || 0) + r.allowed[e]; });
    r.flagged.forEach(function (f) {
      if (f.kind === 'EMAIL' && Object.prototype.hasOwnProperty.call(data.mailboxes || {}, String(f.token).toLowerCase())) { stats.matchedAllowed++; stats.allowedBy['mailbox'] = (stats.allowedBy['mailbox'] || 0) + 1; stats.matchedFlagged--; return; }
      findings.push({ page: rel, type: type, ctx: ctx, kind: f.kind, token: f.token, near: line ? nearOf(line, f.token) : '' });
    });
  }
  scanHead(doc, rel, type, allow, stats, findings);
  var body = doc.body;
  if (!body) return;

  // anchors the include turned into text: not a failure (that is the rule working), but never silent: counted and listed so a reference link nobody put under `links` is seen as a lost link
  Array.prototype.forEach.call(body.querySelectorAll('span.hl-unlinked'), function (sp) {
    stats.unlinked.n++;
    if (stats.unlinked.targets.length < 30) stats.unlinked.targets.push(rel + ' -> ' + D.defangForPrint(sp.getAttribute('data-unlinked') || '').slice(0, 90));
  });

  // links first: classify, and collect the text nodes of reference links that are only their own host name
  var skipNodes = new Set();
  // a report page: the hosts the page itself prints DEFANGED (a named indicator); a link to one of them is a clickable form of it
  var defHosts = null;
  if (isRep) {
    defHosts = new Set();
    var tw = doc.createTreeWalker(body, 4), tn, parts = [];
    while ((tn = tw.nextNode())) { if (!tn.parentElement || !tn.parentElement.closest('script,style,template')) parts.push(tn.nodeValue); }
    (parts.join(' ').match(/[a-z0-9][a-z0-9-]*(?:\[\.\][a-z0-9-]+)+/gi) || []).forEach(function (h) { defHosts.add(h.replace(/\[\.\]/g, '.').toLowerCase().replace(/^www\./, '')); });
  }
  Array.prototype.forEach.call(body.querySelectorAll('a[href]'), function (a) {
    var href = a.getAttribute('href') || '';
    stats.links.total++;
    if (/^#/.test(href)) { stats.links.anchor++; return; }
    if (/^mailto:/i.test(href)) {
      stats.links.mailto++;
      var addr = href.replace(/^mailto:/i, '').split('?')[0].toLowerCase();
      if (!Object.prototype.hasOwnProperty.call(data.mailboxes || {}, addr)) findings.push({ page: rel, type: type, ctx: 'link', kind: 'LINK-MAILTO', token: D.defangForPrint(addr) });
      return;
    }
    var key = linkKey(href);
    if (!key) { if (/^[a-z][a-z0-9+.-]*:/i.test(href)) stats.links.other++; else stats.links.relative++; return; }
    stats.links.external++;
    if (isIpHost(key.host)) { findings.push({ page: rel, type: type, ctx: 'link', kind: 'LINK-IP', token: D.defangForPrint(href) }); return; }
    if (isRep) {
      // a reference (vendor, MITRE, NVD, our own page) stays a link; one that points at a host the page names defanged does not
      var own = linkAllowed(key, data.links);
      if (!own && defHosts.has(key.host.replace(/^www\./, ''))) { findings.push({ page: rel, type: type, ctx: 'link', kind: 'LINK-ACTOR-HOST', token: D.defangForPrint(href) }); return; }
      stats.links.reportRefs++;
      return;
    }
    var ok = isWire ? 'wire-publisher' : linkAllowed(key, data.links);
    if (!ok) { findings.push({ page: rel, type: type, ctx: 'link', kind: 'LINK-UNLISTED', token: D.defangForPrint(href) }); return; }
    stats.links.externalAllowed++;
    // a kept reference link whose label is only its own host name ("patchstack.com") names where it goes: not an indicator
    var label = a.textContent.replace(/\s+/g, ' ').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[\s\u00a0]*[\u2192\u2197\ufe0e]+$/, '').replace(/\/+$/, '').trim();
    if (label && (label === key.host || label === key.key)) {
      stats.links.labelSkips++;
      var w = doc.createTreeWalker(a, 4); var n; while ((n = w.nextNode())) skipNodes.add(n);
    }
  });

  // pre blocks: rule bodies on a detection page (exact by design), page text anywhere else
  Array.prototype.forEach.call(body.querySelectorAll('pre'), function (pre) {
    stats.pre.blocks++;
    if (isRep && pre.closest('.hl-copy, pre.hl-copy')) { stats.pre.copyKept++; return; }
    var lines = pre.textContent.split(/\r?\n/);
    stats.pre.lines += lines.length;
    var raw = 0, tokens = [];
    lines.forEach(function (l) { var r = D.scanLine(l, allow); raw += r.flagged.length; r.flagged.forEach(function (f) { tokens.push(f); }); });
    stats.pre.rawIndicators += raw;
    if (isDet) stats.pre.onDetection++;
    else if (isRep) { stats.pre.onReport++; tokens.forEach(function (f) { findings.push({ page: rel, type: type, ctx: 'pre', kind: 'PRE-IN-REPORT', token: f.token }); }); }
    else {
      stats.pre.offDetection++;
      tokens.forEach(function (f) { findings.push({ page: rel, type: type, ctx: 'pre', kind: 'PRE-OUTSIDE-DETECTION', token: f.token }); });
    }
  });

  // data-literal cells of the IOC viewer: hash, filename, path and registry values print as the feed recorded them (nothing to disarm). Honoured for those six types only, and
  // never for a value shaped like a URL, an e-mail address or an IP address; a hash cell must look like a hash.
  Array.prototype.forEach.call(body.querySelectorAll('[data-literal]'), function (el) {
    var ty = el.getAttribute('data-literal'), val = el.textContent.trim();
    stats.literal.cells++;
    var bad = literalProblem(ty, val);
    if (bad) findings.push({ page: rel, type: type, ctx: 'literal', kind: 'LITERAL-MISUSE', token: D.defangForPrint(val.slice(0, 60)) + ' (' + bad + ')' });
    else { var w2 = doc.createTreeWalker(el, 4), n2; while ((n2 = w2.nextNode())) skipNodes.add(n2); }
  });

  // text nodes
  var walker = doc.createTreeWalker(body, 4);
  var node;
  while ((node = walker.nextNode())) {
    var el = node.parentElement;
    if (!el || el.closest(SKIP_TAGS)) continue;
    if (skipNodes.has(node)) continue;
    stats.textNodes++;
    node.nodeValue.split(/\r?\n/).forEach(function (line) { if (line.trim()) note(D.scanLine(line, allow), 'text', line); });
  }
  // tooltip attributes, and (fix-r2, review finding S5) the value an <input> shows: a script-written box content is displayed text. Not judged: the value of a hidden input, a checkbox, a radio
  // button, a file, image, range or colour control (nothing of it is printed).
  Array.prototype.forEach.call(body.querySelectorAll('*'), function (e) {
    if (e.closest(SKIP_TAGS)) return;
    TOOLTIP_ATTRS.forEach(function (at) {
      var v = e.getAttribute(at);
      if (v) { stats.attrs++; note(D.scanLine(v, allow), 'attr:' + at, v); }
    });
    if (e.tagName === 'INPUT' && !/^(hidden|checkbox|radio|file|image|range|color)$/i.test(e.getAttribute('type') || '')) {
      var iv = e.getAttribute('value');
      if (iv) { stats.attrs++; stats.inputValues = (stats.inputValues || 0) + 1; iv.split(/\r?\n/).forEach(function (l) { if (l.trim()) note(D.scanLine(l, allow), 'attr:value', l); }); }
    }
  });
}

/* The scanner behind scanSite, reusable on HTML that did not come from a file: the browser gate (check-browser-defang.js) hands it the DOM a page has AFTER its scripts ran.
   scan(rel, html) judges one page exactly as scanSite does (page type, the report's own allow file, links, pre blocks, tooltips, head); stats and findings accumulate. */
function makeScanner(dataFile, opts) {
  opts = opts || {};
  var JSDOM = require('jsdom').JSDOM;
  var data = loadAllowData(dataFile);
  var stats = newStats(), findings = [];
  // a report page is judged against the site allow data plus the report's own allow file (the list its source lint reads)
  var repoRoot = path.resolve(path.dirname(dataFile), '..');
  var allowDir = opts.allowDir || path.join(repoRoot, 'tools', 'report-tooling', 'defang-allow');
  var reportsDir = opts.reportsDir || path.join(repoRoot, 'reports');
  var repCache = {};
  // a sub-report page keeps its own permalink (/reports/lpe-exe/) but belongs to the folder it is written in (reports/arsenal-237-new-files/), whose allow file the source lint reads
  var owner = null;
  function ownerOf(rel) {
    if (!owner) {
      owner = {};
      if (fs.existsSync(reportsDir)) fs.readdirSync(reportsDir, { withFileTypes: true }).forEach(function (e) {
        if (!e.isDirectory()) return;
        fs.readdirSync(path.join(reportsDir, e.name)).forEach(function (f) {
          if (!/\.md$/i.test(f)) return;
          var m = fs.readFileSync(path.join(reportsDir, e.name, f), 'utf8').slice(0, 4000).match(/^permalink:\s*['"]?(\S+?)['"]?\s*$/m);
          if (m) owner[m[1].replace(/\/?$/, '/')] = e.name;
        });
      });
    }
    return owner['/' + rel.replace(/index\.html$/, '')] || rel.split('/')[1];
  }
  function reportData(rel) {
    var slug = ownerOf(rel);
    if (repCache[slug]) return repCache[slug];
    var files = [];
    var folder = path.join(reportsDir, slug);
    if (fs.existsSync(folder) && fs.statSync(folder).isDirectory() && fs.existsSync(allowDir)) files = D.autoAllow(folder, allowDir).files;
    var allow = D.makeAllow([{ name: 'defang_allow.yml', text: data.rawText }].concat(files));
    if (allow.bad.length) throw new Error('report allow file for ' + slug + ' refused entries: ' + allow.bad.map(function (b) { return b.entry + ' (' + b.kind + ')'; }).join(', '));
    repCache[slug] = Object.assign({}, data, { allow: allow });
    return repCache[slug];
  }
  function scan(rel, html) {
    var dom = new JSDOM(html);
    stats.pages++;
    var t = pageType(rel); stats.byType[t] = (stats.byType[t] || 0) + 1;
    var before = findings.length;
    scanDocument(dom.window.document, rel, t === 'report' ? reportData(rel) : data, stats, findings);
    dom.window.close();
    return findings.slice(before);
  }
  /* A copied or downloaded text (the clipboard, a share sheet, a blob): every line judged against the allow data of the page it came from. */
  function scanText(rel, ctx, text, literals) {
    var t = pageType(rel), d = t === 'report' ? reportData(rel) : data, out = [];
    // literals: [{type, value}] read from the page's own data-literal cells. A captured line is judged without a field that IS one of them, whole: the line itself (the .txt and the
    // clipboard) or one whole field of a CSV or tab-separated row (fix-r2, review finding S4: the exemption used to cut the literal out of the line wherever it appeared, so a filename
    // literal "evil-host.example.xyz" hid the host of a copied "http://evil-host.example.xyz/a"). Only a value literalProblem accepts counts; anything left in the line is still judged.
    var lits = {};
    (literals || []).forEach(function (l) { if (l.value && !literalProblem(l.type, l.value)) lits[l.value] = 1; });
    String(text).split(/\r?\n/).forEach(function (line) {
      if (!line.trim()) return;
      if (lits[line.trim()]) { stats.literal.exemptLines++; return; }
      // blank the whole fields that are literals, keep every other character where it was: the rest of the line is judged exactly as before
      var kept = line, cuts = lineFields(line).filter(function (f) { return lits[f.value.trim()]; });
      for (var ci = cuts.length - 1; ci >= 0; ci--) { kept = kept.slice(0, cuts[ci].start) + ' ' + kept.slice(cuts[ci].end); stats.literal.exemptFields++; }
      if (!kept.trim()) return;
      D.scanLine(kept, d.allow).flagged.forEach(function (f) { out.push({ page: rel, type: t, ctx: ctx, kind: f.kind, token: f.token, near: nearOf(line, f.token) }); });
    });
    return out;
  }
  return { scan: scan, scanText: scanText, stats: stats, findings: findings, data: data };
}

function scanSite(dir, dataFile, opts) {
  opts = opts || {};
  var sc = makeScanner(dataFile, opts);
  var stats = sc.stats, findings = sc.findings;
  walkHtml(dir).forEach(function (f) {
    var rel = path.relative(dir, f).split(path.sep).join('/');
    var ex = excluded(rel);
    if (ex) { stats.excluded[ex] = (stats.excluded[ex] || 0) + 1; return; }
    if (opts.only && !opts.only.test(rel)) return;
    sc.scan(rel, fs.readFileSync(f, 'utf8'));
  });
  return { stats: stats, findings: findings, data: sc.data };
}

/* Known positives and their clean twins, run before any verdict is believed. Documentation ranges only (RFC 5737, RFC 2606). */
var FIX_BAD = '<html><body><main><p>C2 at 198.51.100.17 and evil-host.example.xyz, mail op@evil-host.example.xyz, fetch http://198.51.100.17/p. <code>203.0.113.9</code></p>' +
  '<p title="198.51.100.77">tip</p><a href="http://198.51.100.17/x">go</a><a href="https://unlisted-vendor.example.net/r">v</a><a href="mailto:op@evil-host.example.xyz">m</a>' +
  '<pre>198.51.100.20 outside a detection page</pre></main></body></html>';
var FIX_GOOD = '<html><body><main><p>C2 at 198[.]51[.]100[.]17 and evil-host[.]example[.]xyz, mail op[@]evil-host[.]example[.]xyz, fetch hxxp://198[.]51[.]100[.]17/p. <code>203[.]0[.]113[.]9</code> ' +
  'and <a href="https://attack.mitre.org/techniques/T1001/">attack.mitre.org</a> kept, <a href="/actors/UTA-2026-001/">198[.]51[.]100[.]17</a> and 10.0.0.1</p>' +
  '<pre>198[.]51[.]100[.]20 outside a detection page</pre></main></body></html>';
function selfTest() {
  var why = [];
  var JSDOM;
  try { JSDOM = require('jsdom').JSDOM; } catch (e) { return ['jsdom did not load: ' + e.message]; }
  var data = { allow: D.makeAllow([{ name: 'self-test', text: 'attack.mitre.org  # reference\n' }]), raw: { 'attack.mitre.org': 'reference', 'the-hunters-ledger.com': 'ours' }, links: ['attack.mitre.org'], mailboxes: { 'intel@the-hunters-ledger.com': 'ours' } };
  function run(html, rel) {
    var st = newStats(), f = [];
    scanDocument(new JSDOM(html).window.document, rel, data, st, f);
    return { f: f, st: st };
  }
  var bad = run(FIX_BAD, 'actors/UTA-2026-001/index.html');
  var want = ['IPV4', 'DOMAIN', 'EMAIL', 'URL', 'LINK-IP', 'LINK-UNLISTED', 'LINK-MAILTO', 'PRE-OUTSIDE-DETECTION'];
  var got = bad.f.map(function (x) { return x.kind; });
  want.forEach(function (k) { if (got.indexOf(k) === -1) why.push('known positive not flagged as ' + k); });
  if (!bad.f.some(function (x) { return x.ctx === 'attr:title'; })) why.push('known positive in a title attribute not flagged');
  var good = run(FIX_GOOD, 'actors/UTA-2026-001/index.html');
  if (good.f.length) why.push('defanged/allowed twin flagged: ' + good.f.map(function (x) { return x.kind + ' ' + D.defangForPrint(x.token); }).join(', '));
  var det = run('<html><body><main><pre>rule X { 198.51.100.20 }</pre></main></body></html>', 'hunting-detections/x-detections/index.html');
  if (det.f.length || det.st.pre.onDetection !== 1 || det.st.pre.rawIndicators !== 1) why.push('a <pre> on a detection page must be counted with its raw indicator and not flagged');
  // a report page: a raw title, citation and BibTeX are flagged; a reference link, a defanged twin and a .hl-copy rule block are not
  var REP_BAD = '<html><body><main><h1>Open Directory 198.51.100.17</h1><p class="hl-cite__text">Harrison, J. <em>Open Directory 198.51.100.17</em></p><pre><code>title = {Open Directory 198.51.100.17}</code></pre>' +
    '<p>C2 evil-host[.]example[.]xyz</p><a href="https://evil-host.example.xyz/x">c2</a><a href="http://198.51.100.17/x">ip</a></main></body></html>';
  var REP_GOOD = '<html><body><main><h1>Open Directory 198[.]51[.]100[.]17</h1><pre><code>title = {Open Directory 198[.]51[.]100[.]17}</code></pre>' +
    '<pre class="hl-copy">rule x { 198.51.100.17 }</pre><p>See <a href="https://unlisted-vendor.example.net/r">the vendor</a>, <a href="https://attack.mitre.org/techniques/T1001/">MITRE</a> and <a href="/reports/x-198.51.100.17/">own page</a>.</p></main></body></html>';
  var rb = run(REP_BAD, 'reports/x/index.html');
  var rbk = rb.f.map(function (x) { return x.kind + ':' + x.ctx; });
  ['IPV4:text', 'PRE-IN-REPORT:pre', 'LINK-IP:link', 'LINK-ACTOR-HOST:link'].forEach(function (k) { if (rbk.indexOf(k) === -1) why.push('report-page known positive not flagged as ' + k); });
  if (rb.f.filter(function (x) { return x.kind === 'IPV4' && x.ctx === 'text'; }).length < 2) why.push('report-page raw title and citation must each be flagged');
  var rg = run(REP_GOOD, 'reports/x/index.html');
  if (rg.f.length) why.push('report-page defanged twin, reference link or .hl-copy block flagged: ' + rg.f.map(function (x) { return x.kind + ' ' + D.defangForPrint(x.token); }).join(', '));
  if (rg.st.pre.copyKept !== 1) why.push('a .hl-copy block on a report page must be counted as kept exact');
  // the <head> display strings: a raw title, og:title, description, image alt and JSON-LD headline are flagged; own-page URLs, the schema.org context and a defanged twin are not; a broken JSON-LD block is a finding
  var HEAD_URLS = '<meta property="og:url" content="https://the-hunters-ledger.com/reports/x-198.51.100.17/"><link rel="canonical" href="https://the-hunters-ledger.com/reports/x-198.51.100.17/">';
  var HEAD_BAD = '<html><head><title>Op 198.51.100.17 | Ledger</title><meta property="og:title" content="Op 198.51.100.17"><meta name="description" content="C2 evil-host.example.xyz">' +
    '<meta name="twitter:image:alt" content="Op 198.51.100.17">' + HEAD_URLS + '<script type="application/ld+json">{"@context":"https://schema.org","headline":"Op 198.51.100.17","url":"https://the-hunters-ledger.com/reports/x-198.51.100.17/"}</script></head><body><main><p>x</p></main></body></html>';
  var HEAD_GOOD = '<html><head><title>Op 198[.]51[.]100[.]17 | Ledger</title><meta property="og:title" content="Op 198[.]51[.]100[.]17"><meta name="description" content="C2 evil-host[.]example[.]xyz">' +
    '<meta name="twitter:image:alt" content="Op 198[.]51[.]100[.]17">' + HEAD_URLS + '<script type="application/ld+json">{"@context":"https://schema.org","headline":"Op 198[.]51[.]100[.]17","url":"https://the-hunters-ledger.com/reports/x-198.51.100.17/","image":"https://the-hunters-ledger.com/assets/images/cards/x-198.51.100.17.png"}</script></head><body><main><p>x</p></main></body></html>';
  var hb = run(HEAD_BAD, 'actors/UTA-2026-001/index.html');
  var hbk = hb.f.map(function (x) { return x.kind + ':' + x.ctx; });
  ['HEAD-IPV4:head:title', 'HEAD-IPV4:head:og:title', 'HEAD-DOMAIN:head:description', 'HEAD-IPV4:head:twitter:image:alt', 'HEAD-IPV4:head:jsonld:headline'].forEach(function (k) { if (hbk.indexOf(k) === -1) why.push('head known positive not flagged as ' + k); });
  if (hb.f.length !== 5) why.push('head fixture: expected exactly 5 findings (own-page URLs and the context are not read), got ' + hb.f.length);
  var hg = run(HEAD_GOOD, 'actors/UTA-2026-001/index.html');
  if (hg.f.length) why.push('head defanged twin flagged: ' + hg.f.map(function (x) { return x.kind + ' ' + D.defangForPrint(x.token); }).join(', '));
  var hj = run('<html><head><script type="application/ld+json">{"headline": </script></head><body><main><p>x</p></main></body></html>', 'actors/UTA-2026-001/index.html');
  if (!hj.f.some(function (x) { return x.kind === 'HEAD-JSONLD-INVALID'; })) why.push('a broken JSON-LD block must be a finding');
  var wire = run('<html><body><main><a href="https://vendor.example.net/post">v</a></main></body></html>', 'wire/index.html');
  if (wire.f.length) why.push('the Wire is exempt from LINK-UNLISTED but was flagged');
  var lab = run('<html><body><main><a href="https://patchstack.com/db/x">patchstack.com</a></main></body></html>', 'actors/index.html');
  if (!lab.f.some(function (x) { return x.kind === 'LINK-UNLISTED'; })) why.push('an unlisted reference link must still be flagged');
  return why;
}

/* The Wire details panels (assets/js/wire-details.js) are written by script from wire/details-nkev.json and wire/details-cves.json (the two tabs' fact sheets): third-party advisory text (version numbers, vendor domains and file names, advisory
   URLs, vendor e-mail addresses), none of it actor infrastructure (decision 5 keeps references as they are). Lead decision, T-0500.1.7.4 fix-r1: the browser gate exempts a finding found
   INSIDE a Wire details panel only when its token is part of a string value of those files. Anything else in a panel (a token the file does not hold), and anything outside a panel, is still
   judged in full. wireDetailsStrings reads the file's string values; wireDetailsSplit sorts a panel's findings into kept and exempt. */
function wireDetailsStrings(jsonText) {
  var out = [];
  (function walk(v) {
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.keys(v).forEach(function (k) { walk(v[k]); });
  })(JSON.parse(jsonText));
  return out;
}
function wireDetailsSplit(findings, strings) {
  var kept = [], exempt = [];
  findings.forEach(function (f) {
    var t = String(f.token || '');
    (t && strings.some(function (s) { return s.indexOf(t) > -1; }) ? exempt : kept).push(f);
  });
  return { kept: kept, exempt: exempt };
}

/* The site-search RECORDS (T-0548): build-search-index.js adds one Pagefind record per Wire row, and Pagefind's bundle (/pagefind/, excluded above) holds their text, so a reader
   sees it as a search-result excerpt. The build writes the records it indexed to a JSON file; this scans every string a reader can see in a result (content and meta title) with the
   scanner that reads the pages (scanLine, the same allow data). `file` is that JSON ({ records: [ { url, content, meta, filters } ] }); a missing or unparseable file, or one with no
   record, throws so the caller reports NOT CHECKED (a zero denominator is never a PASS). */
function scanRecords(file, dataFile) {
  var data = loadAllowData(dataFile);
  var J = JSON.parse(fs.readFileSync(file, 'utf8'));
  var recs = J && Array.isArray(J.records) ? J.records : null;
  if (!recs) throw new Error('search records file has no records array: ' + file);
  var st = { records: recs.length, fields: 0, lines: 0, matchedFlagged: 0, matchedDefanged: 0, matchedPrivate: 0, matchedAllowed: 0, bySection: {} };
  var findings = [];
  recs.forEach(function (r) {
    var sec = (r.meta && r.meta.section) || 'none';
    st.bySection[sec] = (st.bySection[sec] || 0) + 1;
    var fields = [['content', String(r.content || '')], ['meta.title', String((r.meta && r.meta.title) || '')]];
    Object.keys(r.meta || {}).forEach(function (k) { if (k !== 'title' && k !== 'section' && k !== 'date') fields.push(['meta.' + k, String(r.meta[k])]); });
    fields.forEach(function (f) {
      st.fields++;
      f[1].split(/\r?\n/).forEach(function (line) {
        if (!line.trim()) return;
        st.lines++;
        var res = D.scanLine(line, data.allow);
        st.matchedFlagged += res.flagged.length; st.matchedDefanged += res.defanged; st.matchedPrivate += res.privateN; st.matchedAllowed += res.allowedN;
        res.flagged.forEach(function (x) { findings.push({ page: 'search-record ' + String(r.url || '').replace(/^.*#/, '#'), type: 'search-record', ctx: sec + ':' + f[0], kind: 'RECORD-' + x.kind, token: x.token, near: nearOf(line, x.token) }); });
      });
    });
  });
  return { stats: st, findings: findings, data: data };
}

module.exports = { scanRecords: scanRecords, makeScanner: makeScanner, walkHtml: walkHtml, scanSite: scanSite, scanDocument: scanDocument, selfTest: selfTest, loadAllowData: loadAllowData, pageType: pageType, excluded: excluded, newStats: newStats, linkKey: linkKey, linkAllowed: linkAllowed, isIpHost: isIpHost, wireDetailsStrings: wireDetailsStrings, wireDetailsSplit: wireDetailsSplit, _literalProblem: literalProblem };
