#!/usr/bin/env node
'use strict';

/* The defang lint (T-0500.1.12, rules 1, 2, 3 and 5 of tasks/runs/T-0500.1.12/defang-rules.md; Joseph, 2026-10-31:
   "we just do not want it to be easy for people to make a mistake and run something"). Hardened against the cross-provider review
   of 2026-10-31 (Sol, review_a84e0d5e90cc4692): link targets, shared-host allowances, per-line command brackets, IPv6 and the TLD list.

   node check-defang.js <report folder | index.md | any .md> [--allow FILE]... [--allow-dir DIR] [--no-auto-allow] [--all]

   Reads the report SOURCE (a folder: every .md under it, the index and any sub-report pages; a file: that file) and reports

     1. every un-defanged, non-private network indicator a reader sees in the page body: URLs, IPv4 addresses, IPv6 literals in a URL,
        domains and e-mail addresses, in prose, inline code, tables, lists, fenced blocks, LINK TARGETS (inline `](url)`, reference
        definitions, autolinks, href/src attributes: the same rules and allow files as text) and the front-matter fields the page
        renders (everything except the page-identity keys title, description, permalink, slug and the fields that are paths or switches:
        see FM_SKIP). A partly defanged host (`evil[.]example.com`) is reported: the canonical form defangs every dot. A domain is a name
        whose last label is in the IANA root zone (data/iana-tlds.txt, a dated snapshot in the repo, never fetched).
     2. every attacker command block with no bracketed command token (ATTACKER-COMMAND-BLOCK), and every executable line of a command
        block with none (ATTACKER-COMMAND-LINE). A command block is an unmarked fenced block that is shell/PowerShell/batch tagged,
        or holds a line whose first token is a command (COMMANDS) or a cmdlet verb-noun, under ANY language tag: a `json` or `c` tag
        never exempts a line that is a command. The bracket (`[p]owershell`, `[r]eg`) must sit at the COMMAND POSITION: the first token
        of the line, or the first token after `|`, `;`, `&&`, `||`, `(`, `{` or an assignment `=`; a bracket in a comment, a quoted
        argument or the middle of an argument list does not count. A block that is a whole program in a script language (PROGRAM_LANGS:
        python, javascript, ...) is not bracketed line by line; a one-line interpreter invocation inside it is a command like any other.

   Out of scope, as the rules say: a block marked `{: .hl-copy}` (defender content; kramdown puts the IAL on the line directly under
   the closing fence), links and `src` to relative paths and anchors (no host), private addresses (RFC 1918, loopback, link-local,
   0.0.0.0, 224+, and the IPv6 equivalents), and the names in BUILTIN_ALLOW plus any allow file. Allowed hits are COUNTED, per entry,
   in the output: a suppressed indicator is never silent. An attacker URL on a legitimate service (a paste or file-share link) is NOT
   allowed by default: the built-in list holds no hosting, code or storage service.

   ALLOW FILES live in the site repo, at tools/report-tooling/defang-allow/<report folder name>.txt (tools/ is excluded from the
   Jekyll build, so none is published), and are picked up BY SLUG: the folder name of the target (or of the folder holding the
   target .md) names the file, with no flag. defang-allow/_aliases.txt maps a copy whose folder name differs (a vault report
   whose slug differs from the site's) to the site slug: `<other folder name> <site slug>  # reason`. --allow FILE adds more
   files, --allow-dir DIR changes the directory, --no-auto-allow reads only the built-in list (the control: a report that
   needs its file fails without it). The output says which file was read and how many hits each entry suppressed. Every line
   of an allow file needs a reason after `#`; a line without one is NOT CHECKED, never accepted. Two line forms:

     host-or-ip[/path]  # reason       a name that may stay raw. An entry covers ITS host and nothing under it: a subdomain is
                                       allowed only when listed itself. `host/path` covers that path and what lies below it on a
                                       segment boundary; `host/prefix*` is a plain string prefix (`api.telegram.org/bot*`).
     block FILE | FIRST LINE  # reason  one attacker-command-block finding is accepted: the unmarked fenced block in FILE (path
                                       relative to the report folder) whose first non-blank line starts with FIRST LINE. It
                                       suppresses that block's command findings only, never the indicators in the block, is counted
                                       in the output, and FAILs as STALE-BLOCK-EXCEPTION when it matches no block that needs one in a
                                       file read or names a file that does not exist, as BROAD-BLOCK-EXCEPTION when it matches more
                                       than one. A one-file run cannot match another page's exception: NOT CHECKED, printed. FIRST
                                       LINE holds no `#`.

   Guards on allow files: an entry that is a bare public suffix or TLD (co.uk, gov.br, com.tr, com) FAILs as ALLOW-PUBLIC-SUFFIX and
   is not applied. An entry for a MULTI-TENANT host (PATH_TENANT: code hosting, cloud storage, paste and file-share sites, bot and chat
   APIs, archives, social, shorteners) or for a tenant SUFFIX (TENANT_SUFFIX: github.io, amazonaws.com, afraid.org, ddns.net ...) with no
   path scope FAILs as ALLOW-MULTI-TENANT and is not applied: write `github.com/<owner>`, or name one tenant (`itm4n.github.io`).
   An allowed host never excuses a URL whose path carries a real bot id (`/bot<digits>:...`, as on api.telegram.org): BOT-ID-URL.
   A `/bot<token>` placeholder is fine. A bare public suffix in prose (".co.uk" named as a registry) is counted as such, not a host.

   Schemes: http, https, ftp, sftp need the canonical hxxp / hxxps / fxp scheme. ws and wss (WebSocket) keep their scheme and
   take the host defang only (dots of the host to `[.]`). A bare `ws://` or `wss://` with no host is a mention of the scheme,
   not an indicator, and is not flagged; a ws/wss URL whose host has no dot (`localhost`, `{host}`) is not flagged either.
   An IPv6 literal in a URL (`http://[2001:db8::7]/p`, also behind hxxp or ws) is IPV6-URL unless its colons are `[:]`.

   Findings are printed DEFANGED (the lint's own output is not a copy-ready indicator list).

   DENOMINATORS, printed every run (lines are non-blank lines): files, front-matter lines, body lines, fenced blocks (total / marked .hl-copy and skipped /
   scanned), fenced-block lines scanned, indicator-shaped tokens matched (flagged / already defanged / private / allowed), link targets (scanned with a host / with
   none), command-like blocks (fully bracketed / no bracket / bracketed on some lines only) and recognised executable lines, the TLD list size. A run that
   scanned no lines is NOT CHECKED, never PASS.

   SELF-TEST, every run, before the verdict is believed: a known-positive fixture must be flagged on every kind (URL, IPv4, IPv6 URL,
   domain, e-mail, partly defanged host, link target, unmarked attacker block, bare executable line, bare multi-tenant allow entry) and
   its defanged twin must come back clean, or the run is NOT CHECKED. A missing or implausible TLD snapshot is NOT CHECKED too.

   WHAT IT CANNOT SEE (the PASS line says so): deliberate obfuscation by the author (comment and continuation tricks, srcset or entity-encoded schemes, mixed-encoding dot segments, numeric or hex IPv4 hosts); IPv6 outside a URL; a domain whose last label is not in the IANA snapshot (the snapshot
   dates from its first line; refresh it by hand); a command whose first token is not in COMMANDS or a cmdlet; indented (4-space)
   code, which is read as prose; anything rendered by an include or Liquid tag from data outside the file; the rendered page (this is
   a source lint); and whether an allowed name is really benign, since the allow file is a reviewer's claim. A file name or code
   identifier that ends in a TLD word (`install.sh`, `IntPtr.Zero`) is read as a domain: it is allowed by name, with a reason, or
   defanged.

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. Run: node check-defang.js <report folder or index.md> */

var fs = require('node:fs');
var path = require('node:path');

/* ---------- vocabulary ---------- */

/* The DNS root zone, from the dated snapshot in data/iana-tlds.txt (https://data.iana.org/TLD/tlds-alpha-by-domain.txt; refresh it
   by hand, the lint never fetches). TLDS_EXTRA holds the special-use names IANA does not delegate but a report can carry. A name whose
   last label is in neither list is NOT seen by the domain scan: the PASS line says so. */
var TLD_FILE = path.join(__dirname, 'data', 'iana-tlds.txt');
var TLDS_EXTRA = ['onion', 'i2p'];
var _tlds = null;
function getTlds() {
  if (_tlds) return _tlds;
  var set = {}, version = '';
  if (!fs.existsSync(TLD_FILE)) throw new Error('IANA TLD snapshot missing: ' + TLD_FILE + ' (the domain scan has no TLD list; restore data/iana-tlds.txt)');
  fs.readFileSync(TLD_FILE, 'utf8').split(/\r?\n/).forEach(function (l) {
    l = l.trim();
    if (!l) return;
    if (l.charAt(0) === '#') { if (!version) version = l.replace(/^#\s*/, ''); return; }
    set[l.toLowerCase()] = true;
  });
  TLDS_EXTRA.forEach(function (t) { set[t] = true; });
  _tlds = { set: set, count: Object.keys(set).length, version: version };
  return _tlds;
}
function isTld(label) { return Object.prototype.hasOwnProperty.call(getTlds().set, String(label).toLowerCase()); }

/* A public suffix (co.uk, gov.br, com.tr) or a bare TLD (com, .ru) names a whole registry, not a host. An allow entry is matched as a
   suffix, so one such line would let every host under it through; and as a mention in prose it is no host either. Heuristic, not
   the Public Suffix List: a second-level word from PUBLIC_SLD under a two-letter ccTLD, or a single label that is a known TLD or
   two letters. */
var PUBLIC_SLD = 'co com org net gov edu ac or ne go gob mil sch ltd plc nom gv gouv'.split(' '); /* words that are registry levels and not hosts in their own right: not me/id/info/web/nic, which are real hosts under some TLDs */
function isPublicSuffix(name) {
  var labels = String(name).toLowerCase().replace(/^\*?\./, '').split('.');
  if (labels.some(function (l) { return !l; })) return false;
  if (labels.length === 1) return isTld(labels[0]) || /^[a-z]{2}$/.test(labels[0]);
  return labels.length === 2 && PUBLIC_SLD.indexOf(labels[0]) !== -1 && /^[a-z]{2}$/.test(labels[1]);
}

/* Multi-tenant hosts: the account, bucket or channel an URL names is the actor's, not the host's. An allow entry for one of these
   must carry a path scope (`github.com/itm4n`), never the bare host (T-0500.1.12 review, decision 2).
     PATH_TENANT: the tenant sits in the path (code hosting, file sharing, paste sites, bot and chat APIs, archives, social and
       shorteners): the bare host is refused.
     TENANT_SUFFIX: the tenant sits in the subdomain (pages, buckets, tunnels, dynamic DNS): the suffix itself is refused; a named
       tenant (`itm4n.github.io`) is the scope and is listed as itself. */
var PATH_TENANT = ['github.com', 'gist.github.com', 'raw.githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'sourceforge.net',
  'dropbox.com', 'dl.dropboxusercontent.com', 'drive.google.com', 'docs.google.com', 'storage.googleapis.com', 'onedrive.live.com', '1drv.ms',
  'mega.nz', 'mega.io', 'mediafire.com', 'wetransfer.com', 'we.tl', 'transfer.sh', 'file.io', 'gofile.io', 'anonfiles.com', 'catbox.moe',
  'pastebin.com', 'paste.ee', 'hastebin.com', 'rentry.co', 'rentry.org', 'ghostbin.com', 'controlc.com', 'telegra.ph', 'justpaste.it',
  't.me', 'telegram.me', 'api.telegram.org', 'discord.com', 'discord.gg', 'cdn.discordapp.com', 'media.discordapp.net', 'discordapp.com',
  'hooks.slack.com', 'slack.com', 'webhook.site', 'web.archive.org', 'archive.org', 'archive.ph', 'archive.today',
  'medium.com', 'youtube.com', 'youtu.be', 'twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'reddit.com', 'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'cutt.ly', 'rb.gy'];
var TENANT_SUFFIX = ['github.io', 'githubusercontent.com', 'gitlab.io', 'pages.dev', 'workers.dev', 'r2.dev', 'netlify.app', 'vercel.app', 'herokuapp.com',
  'amazonaws.com', 'cloudfront.net', 'blob.core.windows.net', 'azurewebsites.net', 'azureedge.net', 'appspot.com', 'firebaseapp.com', 'web.app',
  'googleusercontent.com', 'sharepoint.com', 'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net',
  'duckdns.org', 'no-ip.com', 'no-ip.org', 'no-ip.biz', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net', 'myftp.org', 'mooo.com', 'dynu.com',
  'dyndns.org', 'dyndns.com', 'afraid.org', 'glitch.me', 'repl.co', 'replit.dev', 'onrender.com', 'fly.dev', 'pythonanywhere.com',
  'wordpress.com', 'blogspot.com', 'tumblr.com', 'weebly.com', 'wixsite.com', 'notion.site', 'linktr.ee'];
/* Returns null when `host` (an allow entry host) needs no path scope, else a description of why it does. */
function multiTenantKind(host) {
  host = String(host).toLowerCase();
  if (PATH_TENANT.indexOf(host) !== -1) return 'a multi-tenant host (the account is in the path)';
  if (TENANT_SUFFIX.indexOf(host) !== -1) return 'a multi-tenant suffix (every tenant lives under it)';
  if (/^s3[.-][a-z0-9.-]*amazonaws\.com$/.test(host)) return 'the S3 service host (path-style URLs put the bucket in the path)';
  return null;
}

/* Names that are not infrastructure of the actor: our own site, RFC 2606 names, the XML/schema namespaces reports quote and
   the MITRE/standards references. Deliberately no hosting, code, paste or storage service: an attacker URL on one of those
   is defanged (rule 1). Anything else a report names as a product goes in an --allow file. */
var BUILTIN_ALLOW = ['the-hunters-ledger.com', 'example.com', 'example.org', 'example.net', 'example.invalid', 'localhost',
  'attack.mitre.org', 'mitre.org', 'w3.org', 'schemas.microsoft.com', 'schemas.xmlsoap.org', 'purl.org', 'xmlsoap.org',
  /* .NET names that end in a TLD word: product/namespace names, not hosts */
  'asp.net', 'system.net', 'system.io', 'vb.net',
  /* the licence link every report footer carries; a reference, never infrastructure */
  'creativecommons.org'];

var SHELL_LANGS = ['powershell', 'ps1', 'pwsh', 'bash', 'sh', 'shell', 'zsh', 'console', 'shell-session', 'cmd', 'bat', 'batch', 'vbs', 'vbscript', 'vba'];
/* Whole-program source: a block that is a program rather than a paste-and-run line is acceptable once its indicators are defanged
   (decision 3, rule 2 of defang-rules.md). A line of it that IS a command (`python -c ...`, `curl ... | python`) is still a command and is
   bracketed. */
var PROGRAM_LANGS = ['python', 'py', 'python3', 'javascript', 'js', 'node', 'typescript', 'ts', 'ruby', 'rb', 'perl', 'php', 'lua', 'go', 'rust', 'rs',
  'c', 'cpp', 'csharp', 'cs', 'java', 'kotlin', 'swift', 'asm', 'nasm', 'r'];
/* Structured data and rules: no first-token reading at block level. A line of one that is a command all the same (a command under a
   `json` tag) makes the block a command block: a language label alone never exempts executable content. */
var DATA_LANGS = ['json', 'yaml', 'yml', 'xml', 'ini', 'toml', 'yara', 'sigma', 'suricata', 'snort', 'sql', 'kql', 'spl', 'html', 'css',
  'diff', 'csv', 'markdown', 'md'];

var COMMANDS = new Set(('powershell pwsh cmd reg regedit schtasks sc net net1 vssadmin wmic wget curl certutil bitsadmin rundll32 regsvr32 ' +
  'mshta cscript wscript msiexec taskkill tasklist icacls cacls takeown attrib bcdedit wevtutil netsh nslookup ping whoami systeminfo ' +
  'ipconfig sudo su chmod chown bash sh zsh dash python python3 perl ruby node rm mv cp cat tar unzip gzip nohup crontab systemctl ' +
  'service iptables ufw kill pkill killall nc ncat netcat ssh scp ssh-keygen base64 openssl dd insmod modprobe export source apt apt-get ' +
  'yum dnf dpkg pip pip3 npm nslookup dig echo cd ls mkdir touch useradd usermod passwd userdel setenforce sed awk grep find xargs ' +
  'history unset eval exec nmap masscan hping3 mimikatz rubeus psexec wsl tftp ftp telnet at start copy del erase rd rmdir move ren ' +
  'type findstr set setx runas gpupdate dsquery nltest klist cmdkey fsutil diskpart format sfc dism mountvol esentutl ntdsutil ' +
  'vssvc wbadmin iex invoke-expression invoke-webrequest invoke-restmethod').split(' '));
/* Interpreter names that open a line of prose as often as a command ("PowerShell Logging (ESSENTIAL):"): command-like only when the
   next token is an option, a quoted or path-like argument, a variable or a cmdlet. */
var LAUNCHERS = new Set('powershell pwsh cmd python python3 node perl ruby bash sh zsh'.split(' '));
/* Words that are also ordinary words in a log or a table ("Start Time", "Type", "Service"): command-like only when the next token
   looks like an argument (starts with - / \\ $ ~ . or a quote, or holds = or :\\). */
var AMBIGUOUS = new Set('at start copy del erase rd rmdir move ren type set find format service source export history exec echo cd ls touch mkdir su dd ftp telnet'.split(' '));
var CMDLET_RE = /^(?:invoke|set|new|get|start|add|remove|out|import|export|enable|disable|install|uninstall|stop|restart|register|unregister|clear|copy|move|test|write|select|send|enter|exit|disconnect|connect|update|expand|compress|convert|find|rename|resolve|save|suspend|resume|wait|use|grant|revoke|block|unblock|protect|unprotect|reset)-[a-z][a-z0-9]*$/i;

/* ---------- helpers ---------- */

function defangForPrint(s) {
  return String(s).replace(/\bhttps?:\/\//gi, function (m) { return m.replace(/tt/i, 'xx'); })
    .replace(/(?<!\[)\.(?!\])/g, '[.]').replace(/@/g, '[@]');
}

function isPrivateIPv4(o) {
  var a = o[0], b = o[1];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a >= 224) return true; /* multicast, reserved, broadcast, subnet masks */
  return false;
}

/* Parse allow files. Every non-comment line needs a reason after `#`. `block FILE | FIRST LINE # reason` is a one-block exception
   for an ATTACKER-COMMAND-BLOCK finding (see the header); anything else is a host or IP that may stay raw, optionally scoped to a
   path (`github.com/itm4n`). A bare multi-tenant host or suffix (`github.com`, `amazonaws.com`) and a bare public suffix are
   refused (`bad`) and not applied. Throws on a line without a reason or a malformed block line: an allowance nobody explained is
   not accepted. */
function makeAllow(files) {
  var entries = BUILTIN_ALLOW.map(function (h) { return { host: h, path: '', raw: h }; }), fromFile = 0, blocks = [], hostReasons = {}, bad = [];
  (files || []).forEach(function (f) {
    /* a path, or { name, text } for a caller that holds the text (the self-test) */
    var fname = typeof f === 'string' ? path.basename(f) : f.name;
    (typeof f === 'string' ? fs.readFileSync(f, 'utf8') : f.text).split(/\r?\n/).forEach(function (raw, n) {
      var hash = raw.indexOf('#');
      var body = (hash < 0 ? raw : raw.slice(0, hash)).trim();
      var reason = hash < 0 ? '' : raw.slice(hash + 1).trim();
      if (!body) return;
      var where = fname + ':' + (n + 1);
      if (!reason) throw new Error('allow entry without a reason (' + where + '): "' + body.slice(0, 60) + '"; write `entry  # why it may stay raw`');
      var bm = body.match(/^block\s+(.+?)\s*\|\s*(.+)$/);
      if (/^block\s/.test(body) && !bm) throw new Error('malformed block exception (' + where + '): expected `block FILE | FIRST LINE  # reason`');
      if (bm) { blocks.push({ file: bm[1].trim(), prefix: bm[2].trim(), reason: reason, src: where, used: 0 }); fromFile++; return; }
      var lowered = body.toLowerCase().replace(/^[a-z]+:\/\//, '');
      var slash = lowered.indexOf('/');
      var host = slash < 0 ? lowered : lowered.slice(0, slash);
      var scope = slash < 0 ? '' : lowered.slice(slash), prefix = false;
      if (/\*$/.test(scope)) { prefix = true; scope = scope.slice(0, -1); } /* `api.telegram.org/bot*`: a plain string prefix, not a path segment */
      scope = scope.replace(/\/+$/, '');
      if (!scope && isPublicSuffix(host)) { bad.push({ entry: host, src: where, kind: 'ALLOW-PUBLIC-SUFFIX' }); return; } /* not active; run() reports it as a FAIL */
      var mt = scope ? null : multiTenantKind(host);
      if (mt) { bad.push({ entry: lowered, src: where, kind: 'ALLOW-MULTI-TENANT', why: mt }); return; }
      entries.push({ host: host, path: scope, prefix: prefix, raw: lowered }); hostReasons[lowered] = reason; fromFile++;
    });
  });
  return { entries: entries, builtin: BUILTIN_ALLOW.length, fromFile: fromFile, blocks: blocks, hostReasons: hostReasons, bad: bad };
}

/* The allow file for a target, found by slug. Returns { files: [paths], note: text }. */
function autoAllow(target, dir) {
  var abs = path.resolve(target);
  var folder = fs.statSync(abs).isDirectory() ? abs : path.dirname(abs);
  var slug = path.basename(folder), site = slug, files = [], note = '';
  var alias = path.join(dir, '_aliases.txt');
  if (fs.existsSync(alias)) {
    fs.readFileSync(alias, 'utf8').split(/\r?\n/).forEach(function (raw, n) {
      var hash = raw.indexOf('#'), body = (hash < 0 ? raw : raw.slice(0, hash)).trim();
      if (!body) return;
      if (hash < 0 || !raw.slice(hash + 1).trim()) throw new Error('alias without a reason (_aliases.txt:' + (n + 1) + ')');
      var parts = body.split(/\s+/);
      if (parts.length !== 2) throw new Error('malformed alias (_aliases.txt:' + (n + 1) + '): expected `<folder name> <site slug>  # reason`');
      if (parts[0] === slug) site = parts[1];
    });
  }
  var f = path.join(dir, site + '.txt');
  if (fs.existsSync(f)) { files.push(f); note = f + (site !== slug ? ' (alias of ' + site + ')' : ''); }
  else note = 'none at ' + f + ' (built-in list only)';
  return { files: files, note: note, slug: slug };
}
/* An allow entry covers ITS host and nothing under it: a subdomain is allowed only when listed itself. A path-scoped entry
   (`github.com/itm4n`) covers that path and what lies below it, on a segment boundary. `urlPath` is the path of the URL or of the text
   token (query and fragment already cut); a token with no path matches no scoped entry. Returns the entry text or null. */
function allowedBy(allow, host, urlPath) {
  host = String(host).toLowerCase();
  var p = String(urlPath || '').toLowerCase().replace(/\/+$/, '');
  for (var i = 0; i < allow.entries.length; i++) {
    var e = allow.entries[i];
    if (host !== e.host) continue;
    if (!e.path) return e.raw;
    /* a dot segment or an encoded dot/slash walks out of the scope a browser or server would resolve (`github.com/itm4n/../Iamem/x`) */
    if (/(?:^|\/)(?:\.|\.\.|%2e|%2e%2e)(?:\/|$)|%2f|%5c|\\/i.test(p)) continue;
    if (e.prefix ? p.indexOf(e.path) === 0 : (p === e.path || p.indexOf(e.path + '/') === 0)) return e.raw;
  }
  return null;
}
/* The path of a URL token, or of the text after a domain token. */
function pathOf(rest) {
  var m = String(rest).match(/^\/[^\s"'<>`|?#]*/);
  return m ? m[0].replace(/[)\]}.,;:*_]+$/, '') : '';
}

/* Split a body line into the text a reader sees and the link targets it carries: inline `](url)`, reference definitions
   (`[id]: url`, not footnotes), and href/src-style attributes. The targets are returned, not dropped: the caller scans them with the
   same rules and allow files as text (T-0500.1.12 review, decision 1). `<scheme://...>` autolinks stay in the text, where the URL scan
   already reads them. */
function splitTargets(line) {
  var targets = [], text = line;
  var rd = text.match(/^(\s*)\[([^\]]+)\]:\s*(<[^>]*>|\S+)(.*)$/);
  if (rd && rd[2].charAt(0) !== '^') { targets.push(rd[3]); return { text: rd[4] || '', targets: targets }; }
  text = text.replace(/\{\{[^}]*\}\}|\{%[^%]*%\}/g, ' '); /* Liquid output/tags (a src="{{ "/assets/.." | relative_url }}" path holds quotes) */
  text = text.replace(/\]\((<[^>]*>|[^)\s]*)(?:\s+"[^"]*")?\)/g, function (m, t) { targets.push(t); return ']'; });
  text = text.replace(/\b(?:href|src|poster|srcset|action|data-href|data-src)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, function (m, d, q) { targets.push(d !== undefined ? d : q); return ' '; });
  return { text: text, targets: targets };
}
/* A target names a host when it has a scheme or is protocol-relative or a mailto; a relative path, an anchor or a Liquid path does not. */
function targetUrl(t) {
  t = String(t).trim().replace(/^<|>$/g, '');
  if (/^\/\/[^\/]/.test(t)) return 'http:' + t;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /^mailto:/i.test(t)) return t;
  return null;
}

/* ---------- indicator scan of one line ---------- */

var URL_RE = /\b(?:https?|ftps?|sftp|wss?):\/\/[^\s"'<>]+/gi;
/* The domain and e-mail shapes take ANY final label; scanLine keeps it only when it is a TLD in the IANA snapshot (isTld). */
var EMAIL_RE = /[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+(?:\[\.\]|\.))+[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9]\b/gi;
var IP_RE = /(?<![\d]|\d\.|\d\[\.\])(\d{1,3})(\[\.\]|\.)(\d{1,3})(\[\.\]|\.)(\d{1,3})(\[\.\]|\.)(\d{1,3})(?!\d|\.\d|\[\.\]\d)/g;
var DOMAIN_RE = /(?<![A-Za-z0-9_\\-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[\.\]|\.))+([A-Za-z][A-Za-z0-9-]*[A-Za-z0-9]|[A-Za-z]{2}))(?![A-Za-z0-9_-]|\.[A-Za-z0-9]|\[\.\][A-Za-z0-9])/gi;
var HXXP_RE = /\b(?:hxxps?|fxp):\/\//gi;
/* A scheme (real or defanged) followed by a bracketed IPv6 literal whose colons are still raw. */
var V6_URL_RE = /\b(?:https?|hxxps?|ftps?|fxp|sftp|wss?):\/\/\[((?:[0-9A-Fa-f.:]|\[:\])*)\](?::\d+)?/gi;

function mask(line, start, end) { return line.slice(0, start) + ' '.repeat(end - start) + line.slice(end); }

/* IPv6 that is not routable infrastructure: loopback, unspecified, link-local, unique-local, multicast. */
function isPrivateIPv6(a) {
  a = String(a).toLowerCase();
  if (a === '::1' || a === '::') return true;
  var first = (a.split(':')[0] || '0');
  var n = parseInt(first || '0', 16);
  if (n >= 0xfe80 && n <= 0xfebf) return true; /* fe80::/10 */
  if (n >= 0xfc00 && n <= 0xfdff) return true; /* fc00::/7 */
  if (n >= 0xff00) return true; /* ff00::/8 */
  return false;
}

/* Returns { flagged: [{kind, token}], defanged: n, privateN: n, allowed: {entry: n} }. */
function scanLine(rawLine, allow) {
  var out = { flagged: [], defanged: 0, privateN: 0, suffixN: 0, allowedN: 0, allowed: {} };
  var line = rawLine, m;
  function noteAllowed(e) { out.allowedN++; out.allowed[e] = (out.allowed[e] || 0) + 1; }

  // 1. URLs with a real scheme. For http, https, ftp and sftp the scheme itself is the violation (canonical form is hxxp), whatever
  //    the host looks like. ws and wss keep their scheme and take the host defang only; a bare `ws://` is no indicator.
  URL_RE.lastIndex = 0;
  var spans = [];
  while ((m = URL_RE.exec(line))) {
    var tok = m[0].replace(/[)\]}.,;:`'"*_]+$/, '');
    var auth = tok.replace(/^[a-z]+:\/\//i, '').split(/[\/?#]/)[0].replace(/^[^@]*@/, '');
    var host = auth.replace(/:\d+$/, '');
    spans.push([m.index, m.index + m[0].length]);
    var isWs = /^wss?:/i.test(tok);
    if (isWs && host === '') continue; /* the scheme named in prose or a block, with no host */
    var oct = (isWs ? host.replace(/\[\.\]/g, '.') : host).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (oct && isPrivateIPv4(oct.slice(1).map(Number))) { out.privateN++; continue; }
    if (/^\[.*\]$/.test(host)) { /* IPv6 literal */
      var v6 = host.slice(1, -1);
      if (/\[:\]/.test(v6) && isWs) { /* ws(s) with the colons defanged: every colon must be, a raw one beside a [:] is a partly defanged host */
        if (v6.replace(/\[:\]/g, '').indexOf(':') !== -1) out.flagged.push({ kind: 'IPV6-URL', token: tok });
        else out.defanged++;
        continue;
      }
      if (isPrivateIPv6(v6)) { out.privateN++; continue; }
      out.flagged.push({ kind: 'IPV6-URL', token: tok });
      continue;
    }
    if (isWs) {
      var rawDots = host.replace(/\[\.\]/g, '');
      if (rawDots.indexOf('.') === -1) { if (host.indexOf('[.]') !== -1) out.defanged++; continue; } /* defanged, or no dot at all */
    }
    var urlPath = pathOf(tok.replace(/^[a-z]+:\/\/[^\/?#]*/i, ''));
    var al = allowedBy(allow, host.replace(/\[\.\]/g, '.'), urlPath);
    if (al) {
      /* an allowed host does not excuse a path that carries a real bot id (api.telegram.org/bot<digits>:...); `<token>` stays fine */
      var bot = tok.match(/\/bot(\d+):/i);
      if (bot) { out.flagged.push({ kind: 'BOT-ID-URL', token: host + '/bot<' + bot[1].length + ' digits>:...' }); continue; }
      noteAllowed(al); continue;
    }
    out.flagged.push({ kind: 'URL', token: tok });
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });

  // 1b. a defanged (or any) scheme in front of an IPv6 literal with raw colons: the literal is the host and it is still whole
  V6_URL_RE.lastIndex = 0;
  spans = [];
  while ((m = V6_URL_RE.exec(line))) {
    if (m[1].replace(/\[:\]/g, '').indexOf(':') === -1 && m[1].indexOf('[:]') === -1) continue; /* not an IPv6 literal */
    spans.push([m.index, m.index + m[0].length]);
    if (m[1].indexOf('[:]') !== -1 && m[1].replace(/\[:\]/g, '').indexOf(':') === -1) { out.defanged++; continue; } /* every colon defanged */
    if (isPrivateIPv6(m[1].replace(/\[:\]/g, ':'))) { out.privateN++; continue; }
    out.flagged.push({ kind: 'IPV6-URL', token: m[0] });
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });

  // 2. e-mail addresses: the canonical form brackets the @
  EMAIL_RE.lastIndex = 0;
  spans = [];
  while ((m = EMAIL_RE.exec(line))) {
    var dom = m[0].split('@')[1].replace(/\[\.\]/g, '.');
    if (!isTld(dom.split('.').pop())) continue;
    spans.push([m.index, m.index + m[0].length]);
    var al2 = allowedBy(allow, dom, '');
    if (al2) { noteAllowed(al2); continue; }
    out.flagged.push({ kind: 'EMAIL', token: m[0] });
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });
  // an e-mail whose @ was defanged: counts as defanged when its host is dotted
  var bracketAt = line.match(/[A-Za-z0-9._%+-]+\[@\][A-Za-z0-9.\-\[\]]+/g);
  if (bracketAt) out.defanged += bracketAt.length;

  // 3. IPv4, raw or with any dot defanged. Flagged when at least one separator is a raw dot.
  IP_RE.lastIndex = 0;
  spans = [];
  while ((m = IP_RE.exec(line))) {
    var o = [m[1], m[3], m[5], m[7]].map(Number);
    if (o.some(function (n) { return n > 255; })) continue;
    /* T-0589: a part written with a leading zero ("030", "00", "01") is not an address: the page include (_includes/defang-text.html) round-trips
       each part through a number and prints such a quad raw, so a version string like 9.4.0.030 is not defanged there; the gate must not flag it.
       A lone "0" is a valid part (10.0.0.1 stays an address). Keep the two sides identical. */
    if ([m[1], m[3], m[5], m[7]].some(function (t) { return t.length > 1 && t.charAt(0) === '0'; })) continue;
    spans.push([m.index, m.index + m[0].length]);
    if (isPrivateIPv4(o)) { out.privateN++; continue; }
    var seps = [m[2], m[4], m[6]];
    if (seps.some(function (s) { return s === '.'; })) {
      var ip = o.join('.'), al3 = allowedBy(allow, ip, '');
      if (al3) { noteAllowed(al3); continue; }
      out.flagged.push({ kind: seps.every(function (s) { return s === '.'; }) ? 'IPV4' : 'IPV4-PARTLY-DEFANGED', token: m[0] });
    } else out.defanged++;
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });

  // 4. domains whose last label is a TLD in the IANA snapshot, raw or with any dot defanged; flagged when at least one dot is raw
  DOMAIN_RE.lastIndex = 0;
  while ((m = DOMAIN_RE.exec(line))) {
    var d = m[1];
    if (!isTld(m[2])) continue;
    // a path-like or Windows-name context is not a host: preceded by a backslash is excluded by the lookbehind; a file
    // name such as `Net.WebClient` ends in no TLD, so it never reaches here.
    var hasRaw = /(^|[^\]])\.(?!\])/.test(d.replace(/\[\.\]/g, '\u0000'));
    var plain = d.replace(/\[\.\]/g, '.').toLowerCase();
    if (!hasRaw) { out.defanged++; continue; }
    if (isPublicSuffix(plain)) { out.suffixN++; continue; } /* a registry named as such (".co.uk"), not a host */
    var rest = line.slice(m.index + m[0].length);
    var al4 = allowedBy(allow, plain, pathOf(rest));
    if (al4) {
      var bot4 = rest.match(/^\/bot(\d+):/i);
      if (bot4) { out.flagged.push({ kind: 'BOT-ID-URL', token: plain + '/bot<' + bot4[1].length + ' digits>:...' }); continue; }
      noteAllowed(al4); continue;
    }
    out.flagged.push({ kind: /\[\.\]/.test(d) ? 'DOMAIN-PARTLY-DEFANGED' : 'DOMAIN', token: d });
  }
  var hx = rawLine.match(HXXP_RE);
  if (hx) out.defanged += hx.length;
  return out;
}

/* ---------- command-like lines ---------- */

/* A bracketed command token: `[p]owershell`, `[r]eg`. */
var BRACKET_TOK = '\\[[A-Za-z0-9.\\/~]\\](?=[A-Za-z0-9._\\/\\\\-])';
var BRACKET_CMD = new RegExp('(^|[\\s("\'`$|;&=,{])' + BRACKET_TOK);

function stripPrompt(l) {
  return l.replace(/^(?:PS\s+[^>]*>|[A-Za-z]:\\[^>]*>|\$\s|>\s|%\s)\s*/, '');
}
function isComment(l) { return /^(#|\/\/|rem\s|::|')/i.test(l.trim()); }

/* The bracket must sit where the shell would read the command name: the first token of the line (after a prompt, `&`, `sudo`-style
   wrappers) or the first token after `|`, `;`, `&&`, `||`, `(`, `{` or an assignment `=` (a PowerShell `$x = [N]ew-Object ...`). A bracket
   in a comment, in a quoted argument or in the middle of an argument list is not a defang of the command and does not count. */
var CMD_AT_START = new RegExp('^[\"\'`]?(?:(?:sudo|doas|nohup|time|exec|env|xargs)\\s+(?:-\\S+\\s+)*)*[&.]?\\s*' + BRACKET_TOK);
var CMD_AFTER_SEP = new RegExp('(?:\\|\\|?|;|&&|&|\\(|\\{|=)\\s*(?:(?:sudo|doas|nohup|time|exec|env|xargs)\\s+(?:-\\S+\\s+)*)*' + BRACKET_TOK);
function cmdPosBracket(line) {
  var l = line.trim();
  if (!l || isComment(l)) return false;
  l = stripPrompt(l);
  if (CMD_AT_START.test(l)) return true;
  /* blank out quoted strings so a separator or bracket inside an argument cannot count */
  var code = l.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, function (q) { return '"' + 'x'.repeat(Math.max(0, q.length - 2)) + '"'; });
  var cut = code.search(/\s#\s/); if (cut >= 0) code = code.slice(0, cut);
  return CMD_AFTER_SEP.test(code);
}
function isAssignment(l) { return /^[\w.$:\[\]-]+\s*[-+*\/|&^:.]?=(?!=)/.test(l) && !/^[A-Za-z]+\s+\S+=/.test(l); }
function lineLooksLikeCommand(line) {
  var l = line.trim();
  if (!l || isComment(l)) return false;
  l = stripPrompt(l);
  if (isAssignment(l)) return false;
  var t = l.split(/\s+/)[0] || '';
  t = t.replace(/^&/, '');
  var br = t.match(/^\[(.)\](.*)$/);
  if (br) t = br[1] + br[2];
  t = t.replace(/^["'`(]+|["'`;)]+$/g, '').toLowerCase().replace(/^.*[\/\\]/, '').replace(/\.(exe|ps1|sh|bat|cmd|com|vbs)$/, '');
  if (!t) return false;
  if (CMDLET_RE.test(t)) return true;
  if (!COMMANDS.has(t)) return false;
  var next = (l.split(/\s+/)[1] || '');
  if (LAUNCHERS.has(t)) return next === '' ? false : (/^(?:[-\/\\$~."'`&{(]|.*[.=]|.*:\\)/.test(next) || CMDLET_RE.test(next));
  if (!AMBIGUOUS.has(t)) return true;
  return /^(?:[-\/\\$~."'`]|.*=|.*:\\)/.test(next);
}

/* One fenced block read as commands. Returns { cmdLines, recognized: [idx], bracketed, bare: [idx], nonEmpty }:
     cmdLines   lines that make the block a command block: a recognised command line, or any non-comment line of a shell-tagged block
     recognized lines that are commands by their first token and are not an argument continuation of the line above
     bracketed  some line carries a bracketed token at command position
     bare       recognised lines with none: rule 2 brackets EACH executable line of a command block */
function analyseBlock(lang, body) {
  var shell = SHELL_LANGS.indexOf(lang) !== -1;
  var r = { cmdLines: 0, recognized: [], bracketed: false, bare: [], nonEmpty: 0 }, cont = false;
  body.forEach(function (bl, bi) {
    var t = bl.trim();
    if (t && !isComment(bl)) r.nonEmpty++;
    var br = cmdPosBracket(bl);
    if (br) r.bracketed = true;
    /* an indented option line (`  /sc once`, `  -Force`) continues the command above; it is an argument list, not a command */
    var optLine = /^\s+(?:\/[A-Za-z?]{1,8}|--?[A-Za-z][\w-]*)(?:\s|$)/.test(bl);
    var rec = !cont && !optLine && lineLooksLikeCommand(bl);
    cont = /(?:\\|`|\^)\s*$/.test(t);
    if (rec) { r.recognized.push(bi); if (!br) r.bare.push(bi); }
    if (rec || (shell && t && !isComment(bl))) r.cmdLines++;
  });
  return r;
}

/* ---------- parsing one markdown file ---------- */

var FM_SKIP = ['title', 'description', 'permalink', 'slug', 'layout', 'hide', 'date', 'last_updated', 'category', 'thumbnail',
  'stix_bundle', 'ioc_feed', 'detection_page', 'sitemap', 'unlisted', 'sponsored_by', 'series', 'series_role', 'series_order',
  'embargo', 'tags', 'image', 'canonical', 'redirect_from'];

function newStats() {
  return { files: 0, fmLines: 0, bodyLines: 0, blocks: 0, blocksCopy: 0, blocksScanned: 0, blockLines: 0,
    matchedFlagged: 0, matchedDefanged: 0, matchedPrivate: 0, matchedSuffix: 0, matchedAllowed: 0, allowedBy: {},
    cmdBlocks: 0, cmdBlocksBracketed: 0, cmdBlocksBare: 0, blockExceptions: 0, cmdBlocksExcepted: [], cmdLines: 0, cmdLinesBare: 0, cmdBlocksLinesBare: 0, linkTargets: 0, linkTargetsNoHost: 0, copyBlockIndicators: 0,
    copyBlocks: [] };
}

function scanFile(text, file, allow, stats) {
  var findings = [];
  stats.files++;
  var lines = text.split(/\r?\n/);
  var i = 0, fmEnd = -1;
  if (lines[0] && /^---\s*$/.test(lines[0])) {
    for (var k = 1; k < lines.length; k++) if (/^---\s*$/.test(lines[k])) { fmEnd = k; break; }
  }
  function record(r, ln, ctx) {
    stats.matchedFlagged += r.flagged.length;
    stats.matchedDefanged += r.defanged;
    stats.matchedPrivate += r.privateN;
    stats.matchedSuffix += r.suffixN;
    stats.matchedAllowed += r.allowedN;
    Object.keys(r.allowed).forEach(function (e) { stats.allowedBy[e] = (stats.allowedBy[e] || 0) + r.allowed[e]; });
    r.flagged.forEach(function (f) { findings.push({ file: file, line: ln, ctx: ctx, kind: f.kind, token: f.token }); });
    return r;
  }
  /* text lines (front matter and body): the visible text AND every link target, each scanned by the same rules and allow files */
  function addText(line, ln, ctx) {
    var sp = splitTargets(line);
    record(scanLine(sp.text, allow), ln, ctx);
    sp.targets.forEach(function (t) {
      var u = targetUrl(t);
      if (u === null) { stats.linkTargetsNoHost++; return; }
      stats.linkTargets++;
      record(scanLine(u, allow), ln, 'link-target');
    });
  }
  function addScan(line, ln, ctx, isBlock) { return record(scanLine(line, allow), ln, ctx); }
  // front matter: every top-level key block except the identity/switch keys
  if (fmEnd > 0) {
    var skipping = false, key = '';
    for (var f = 1; f < fmEnd; f++) {
      var km = lines[f].match(/^([A-Za-z_][A-Za-z0-9_-]*):/);
      if (km) { key = km[1]; skipping = FM_SKIP.indexOf(key) !== -1; }
      if (skipping) continue;
      if (lines[f].trim()) stats.fmLines++;
      addText(lines[f], f + 1, 'front-matter:' + key);
    }
    i = fmEnd + 1;
  }
  // body
  while (i < lines.length) {
    var ln = lines[i];
    var bare = ln.replace(/^(?:\s*>)+/, '');
    var fm = bare.match(/^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+.#-]*)/);
    if (!fm) {
      if (ln.trim()) stats.bodyLines++;
      addText(ln, i + 1, 'body');
      i++;
      continue;
    }
    // fenced block
    var fence = fm[1], lang = (fm[2] || '').toLowerCase(), open = i;
    var j = i + 1, body = [];
    var closeRe = new RegExp('^\\s*' + (fence[0] === '`' ? '`' : '~') + '{' + fence.length + ',}\\s*$');
    while (j < lines.length && !closeRe.test(lines[j].replace(/^(?:\s*>)+/, ''))) { body.push(lines[j].replace(/^(?:\s*>)+ ?/, '')); j++; }
    var closed = j < lines.length;
    var after = closed ? j + 1 : j, ial = '';
    while (after < lines.length && /^\s*\{:[^}]*\}\s*$/.test(lines[after])) { ial += ' ' + lines[after]; after++; }
    var copy = /\.hl-copy(?![A-Za-z0-9_-])/.test(ial);
    stats.blocks++;
    if (copy) {
      stats.blocksCopy++;
      var held = 0;
      body.forEach(function (bl) { held += scanLine(bl, allow).flagged.length; });
      stats.copyBlockIndicators += held;
      stats.copyBlocks.push({ file: file, line: open + 1, lang: lang, lines: body.length, indicators: held,
        first: defangForPrint((body.find(function (x) { return x.trim(); }) || '').trim().slice(0, 70)) });
    } else {
      stats.blocksScanned++;
      body.forEach(function (bl, bi) {
        if (bl.trim()) stats.blockLines++;
        addScan(bl, open + 2 + bi, 'block', true);
      });
      var an = analyseBlock(lang, body);
      var programOrData = PROGRAM_LANGS.indexOf(lang) !== -1 || DATA_LANGS.indexOf(lang) !== -1;
      /* a command block: a recognised command line, or (any tag but a program or data one) a shell-tagged / command-looking block.
         A program or data tag alone never exempts a line that is itself a command. */
      var cmdBlock = programOrData ? an.recognized.length > 0 : an.cmdLines > 0;
      if (cmdBlock && an.nonEmpty > 0) {
        stats.cmdBlocks++;
        stats.cmdLines += an.recognized.length;
        var firstNb = (body.find(function (x) { return x.trim(); }) || '').trim();
        var ex = (allow.blocks || []).filter(function (b) { return b.file === file && firstNb.indexOf(b.prefix) === 0; });
        var wouldFail = !an.bracketed || an.bare.length > 0;
        if (!wouldFail) stats.cmdBlocksBracketed++;
        else if (ex.length) {
          ex.forEach(function (b) { b.used++; });
          stats.blockExceptions++;
          stats.cmdBlocksExcepted.push({ file: file, line: open + 1, reason: ex[0].reason });
        } else if (!an.bracketed) {
          stats.cmdBlocksBare++;
          findings.push({ file: file, line: open + 1, ctx: 'block', kind: 'ATTACKER-COMMAND-BLOCK',
            token: '(' + (lang || 'untagged') + ', ' + body.length + ' lines, ' + an.cmdLines + ' command-like; first: ' +
              defangForPrint((body.find(function (x) { return x.trim() && !isComment(x); }) || '').trim().slice(0, 60)) + ')' });
        } else {
          stats.cmdBlocksLinesBare++;
          an.bare.forEach(function (bi) {
            stats.cmdLinesBare++;
            findings.push({ file: file, line: open + 2 + bi, ctx: 'block', kind: 'ATTACKER-COMMAND-LINE',
              token: '(' + (lang || 'untagged') + ', no bracketed command token on this executable line: ' + defangForPrint(body[bi].trim().slice(0, 60)) + ')' });
          });
        }
      }
    }
    i = (closed ? j + 1 : j);
  }
  return findings;
}

/* ---------- self-test ---------- */

var FIXTURE_BAD = [
  'beacon at http://198.51.100.17:8080/a.ps1 now',
  'host 198.51.100.17 listed',
  'domain evil.example-attacker.com seen',
  'mail ops@evil.example-attacker.com sent',
  'mixed 198[.]51.100[.]17 here',
  'mixed evil[.]example-attacker.com there',
  'socket ws://192.0.2.5:8080/x here',
  'tunnel http://[2001:db8::7]/payload here',
  'script evil-attacker.sh seen',
  'host github.com/Iamem/payload seen'
];
var FIXTURE_GOOD = [
  'beacon at hxxp://198[.]51[.]100[.]17:8080/a.ps1 now',
  'host 198[.]51[.]100[.]17 listed',
  'domain evil[.]example-attacker[.]com seen',
  'mail ops[@]evil[.]example-attacker[.]com sent',
  'private 10.1.2.3 and 192.168.0.9 and 127.0.0.1 fine',
  'socket ws://192[.]0[.]2[.]5:8080/x here',
  'WebSocket (ws://) and `wss://` are named as schemes, ws://localhost:8080/x is no indicator',
  'tunnel hxxp://[2001[:]db8[:][:]7]/payload and http://[::1]:8080/x fine',
  'script evil-attacker[.]sh seen',
  'host github[.]com/Iamem/payload seen'
];
function selfTest() {
  var allow = makeAllow([]), why = [];
  var tl;
  try { tl = getTlds(); } catch (e) { return [e.message]; }
  if (tl.count < 1000 || !isTld('com') || !isTld('sh') || !isTld('xn--p1ai')) why.push('IANA TLD snapshot looks wrong: ' + tl.count + ' names (expected well over 1000, with com, sh, xn--p1ai)');
  var kinds = [['URL'], ['IPV4'], ['DOMAIN'], ['EMAIL'], ['IPV4-PARTLY-DEFANGED'], ['DOMAIN-PARTLY-DEFANGED'], ['URL'], ['IPV6-URL'], ['DOMAIN'], ['DOMAIN']];
  FIXTURE_BAD.forEach(function (l, n) {
    var r = scanLine(l, allow);
    if (!r.flagged.some(function (f) { return f.kind === kinds[n][0]; })) why.push('known positive not flagged as ' + kinds[n][0] + ': ' + defangForPrint(l));
  });
  FIXTURE_GOOD.forEach(function (l) {
    var r = scanLine(l, allow);
    if (r.flagged.length) why.push('defanged/private twin flagged: ' + defangForPrint(l) + ' -> ' + r.flagged.map(function (f) { return f.kind; }).join(','));
  });
  var st = newStats();
  var blk = scanFile('# t\n\n```\npowershell -ep bypass -c "x"\n```\n\n```\n[p]owershell -ep bypass -c "x"\n```\n\n```\npowershell -ep bypass -c "x"\n```\n{: .hl-copy}\n', 'self-test', allow, st);
  if (blk.filter(function (f) { return f.kind === 'ATTACKER-COMMAND-BLOCK'; }).length !== 1 || st.blocksCopy !== 1 || st.cmdBlocksBracketed !== 1) {
    why.push('block fixture: expected 1 bare attacker block, 1 bracketed, 1 .hl-copy skipped; got bare ' + st.cmdBlocksBare + ', bracketed ' + st.cmdBlocksBracketed + ', copy ' + st.blocksCopy);
  }
  // every executable line of a command block carries its own bracket at command position; a bracket in a comment or an argument is none
  var st3 = newStats();
  var f3 = scanFile('```bash\n[r]eg query HKCU\\Software\nreg add HKCU\\Software\\T /v x /d y\n```\n\n```bash\n# [p]owershell\nreg add HKCU\\Software\\T /v x /d "[p]owershell"\n```\n', 'self-test', allow, st3);
  if (f3.filter(function (f) { return f.kind === 'ATTACKER-COMMAND-LINE'; }).length !== 1 || f3.filter(function (f) { return f.kind === 'ATTACKER-COMMAND-BLOCK'; }).length !== 1) {
    why.push('command-line fixture: expected 1 unbracketed line in a partly bracketed block and 1 block whose only bracket is in a comment or an argument; got ' + f3.map(function (f) { return f.kind; }).join(','));
  }
  // link targets are scanned like text: an actor link is a finding, its defanged and relative twins are not
  var st4 = newStats();
  var f4 = scanFile('[x](http://198.51.100.17/p) <a href="http://198.51.100.17/q">y</a>\n\n[z][r]\n\n[r]: http://198.51.100.17/r\n\n[ok](hxxp://198[.]51[.]100[.]17/p) [rel](/a/b) [anchor](#x)\n', 'self-test', allow, st4);
  if (f4.filter(function (f) { return f.kind === 'URL' && f.ctx === 'link-target'; }).length !== 3 || f4.length !== 3) why.push('link fixture: expected 3 link-target URL findings and nothing else; got ' + f4.map(function (f) { return f.kind + '@' + f.ctx; }).join(','));
  // a bare multi-tenant host is refused (and not applied); a path-scoped one covers its path only; no subdomain inheritance
  var mt = makeAllow([{ name: 'self-test', text: 'github.com  # bare\ngithub.com/itm4n  # scoped\nexample-vendor.com  # exact only\n' }]);
  if (mt.bad.length !== 1 || mt.bad[0].kind !== 'ALLOW-MULTI-TENANT' ||
      allowedBy(mt, 'github.com', '/itm4n/PrivescCheck') !== 'github.com/itm4n' || allowedBy(mt, 'github.com', '/Iamem/p') !== null ||
      allowedBy(mt, 'github.com', '') !== null || allowedBy(mt, 'x.example-vendor.com', '') !== null || allowedBy(mt, 'example-vendor.com', '/a') === null) {
    why.push('allow fixture: expected the bare github.com entry refused, github.com/itm4n scoped, no subdomain inheritance');
  }
  // a block exception removes its one finding and nothing else
  var exAllow = makeAllow([]);
  exAllow.blocks.push({ file: 'self-test', prefix: 'powershell -ep bypass', reason: 'self-test', src: 'self-test', used: 0 });
  var st2 = newStats();
  var doc2 = '```\npowershell -ep bypass -c "x"\n```\n\n```\nwget http://198.51.100.17/a\n```\n';
  var f2 = scanFile(doc2, 'self-test', exAllow, st2);
  if (exAllow.blocks[0].used !== 1 || f2.some(function (f) { return f.kind === 'ATTACKER-COMMAND-BLOCK' && f.line === 2; }) || !f2.some(function (f) { return f.kind === 'ATTACKER-COMMAND-BLOCK'; }) || !f2.some(function (f) { return f.kind === 'URL'; })) {
    why.push('block exception fixture: expected the matched block excused (used 1), the other block and its URL still flagged');
  }
  return why;
}

/* ---------- CLI ---------- */

/* A folder target reads the pages Jekyll would publish: index.md, and any other .md that opens with front matter. A .md with none
   (review notes, announcement drafts kept beside a vault report) is not a page; it is counted in `skipped`, never silently dropped. */
function listMd(p, skipped) {
  var st = fs.statSync(p);
  if (st.isFile()) return [p];
  var out = [];
  (function walk(d) {
    fs.readdirSync(d, { withFileTypes: true }).sort(function (a, b) { return a.name < b.name ? -1 : 1; }).forEach(function (e) {
      var f = path.join(d, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules' && e.name[0] !== '.') walk(f); }
      else if (/\.md$/i.test(e.name)) {
        var head = fs.readFileSync(f, 'utf8').slice(0, 8);
        if (e.name.toLowerCase() === 'index.md' || /^---\r?\n/.test(head)) out.push(f);
        else if (skipped) skipped.push(f);
      }
    });
  })(p);
  return out;
}

function run(target, allowFiles, opts) {
  opts = opts || {};
  var allow = makeAllow(allowFiles);
  var stats = newStats(), findings = [];
  var skipped = [];
  var files = listMd(target, skipped);
  files.forEach(function (f) {
    var rel = path.relative(fs.statSync(target).isDirectory() ? target : path.dirname(target), f) || path.basename(f);
    findings = findings.concat(scanFile(fs.readFileSync(f, 'utf8'), rel, allow, stats));
  });
  allow.bad.forEach(function (b) {
    var why = b.kind === 'ALLOW-MULTI-TENANT'
      ? 'is ' + b.why + '; allow it with a path scope (`github.com/<owner>`, `api.telegram.org/bot`) or a named tenant subdomain, never the bare name, so one line cannot pass every tenant'
      : 'is a bare public suffix or TLD; allow entries match one host, and a registry is not one. Allow the host, not the registry';
    findings.push({ file: 'allow file', line: 0, ctx: 'allow', kind: b.kind, token: b.src + ' "' + defangForPrint(b.entry) + '" ' + why });
  });
  // an exception must excuse exactly one block of a file that was read, and must name a file that exists
  var isDir = fs.statSync(target).isDirectory(), base = isDir ? target : path.dirname(target);
  var readRel = files.map(function (f) { return path.relative(base, f) || path.basename(f); });
  var unchecked = [];
  allow.blocks.forEach(function (b) {
    if (readRel.indexOf(b.file) === -1) {
      if (!fs.existsSync(path.join(base, b.file))) {
        findings.push({ file: b.file, line: 0, ctx: 'allow', kind: 'STALE-BLOCK-EXCEPTION', token: b.src + ' names a file that does not exist (' + b.file + '); the exception excuses nothing' });
      } else if (isDir) {
        findings.push({ file: b.file, line: 0, ctx: 'allow', kind: 'STALE-BLOCK-EXCEPTION', token: b.src + ' names a file that exists but is not a page the lint reads (' + b.file + ': no front matter); the exception excuses nothing' });
      } else unchecked.push(b.src + ' -> ' + b.file); /* a one-file run: another page's exception cannot be matched */
      return;
    }
    if (b.used === 0) findings.push({ file: b.file, line: 0, ctx: 'allow', kind: 'STALE-BLOCK-EXCEPTION', token: b.src + ' matches no unmarked command block that needs an exception, starting "' + defangForPrint(b.prefix) + '"' });
    if (b.used > 1) findings.push({ file: b.file, line: 0, ctx: 'allow', kind: 'BROAD-BLOCK-EXCEPTION', token: b.src + ' matches ' + b.used + ' blocks starting "' + defangForPrint(b.prefix) + '"; one exception excuses one block' });
  });
  stats.exceptionsOtherFile = unchecked;
  return { allow: allow, stats: stats, findings: findings, files: files, skipped: skipped };
}

function main() {
  var argv = process.argv.slice(2), target = null, allowFiles = [], all = false, site = null, allowData = null, only = null, records = null;
  var allowDir = path.join(__dirname, 'defang-allow'), autoOn = true;
  for (var a = 0; a < argv.length; a++) {
    if (argv[a] === '--allow') allowFiles.push(argv[++a]);
    else if (argv[a] === '--allow-dir') allowDir = argv[++a];
    else if (argv[a] === '--no-auto-allow') autoOn = false;
    else if (argv[a] === '--all') all = true;
    else if (argv[a] === '--site') site = argv[++a];
    else if (argv[a] === '--allow-data') allowData = argv[++a];
    else if (argv[a] === '--only') only = argv[++a];
    else if (argv[a] === '--records') records = argv[++a];
    else if (argv[a] === '-h' || argv[a] === '--help') { console.log('usage: node check-defang.js <report folder | index.md> [--allow FILE]... [--allow-dir DIR] [--no-auto-allow] [--all]\n       node check-defang.js --site <_site dir> [--allow-data _data/defang_allow.yml] [--only REGEX] [--all]   (the rendered pages: every page type, report pages included)'); process.exit(0); }
    else target = argv[a];
  }
  if (site) return mainSite(site, allowData, only, all, records);
  if (!target) { console.log('NOT CHECKED  usage: node check-defang.js <report folder | index.md> [--allow FILE]... [--all]'); process.exit(2); }
  if (!fs.existsSync(target)) { console.log('NOT CHECKED  not found: ' + target); process.exit(2); }
  for (var af = 0; af < allowFiles.length; af++) if (!allowFiles[af] || !fs.existsSync(allowFiles[af])) { console.log('NOT CHECKED  allow file not found: ' + allowFiles[af]); process.exit(2); }

  var autoNote = 'off (--no-auto-allow); built-in list only', autoFiles = [];
  if (autoOn) {
    try { var au = autoAllow(target, allowDir); autoFiles = au.files; autoNote = au.note; }
    catch (e) { console.log('NOT CHECKED  ' + e.message); process.exit(2); }
  }
  allowFiles = autoFiles.concat(allowFiles);

  var bad = selfTest();
  if (bad.length) { bad.forEach(function (b) { console.log('SELF-TEST  ' + b); }); console.log('NOT CHECKED  the lint failed its own known-positive self-test; no verdict'); process.exit(2); }

  var R;
  try { R = run(target, allowFiles); } catch (e) { console.log('NOT CHECKED  ' + e.message); process.exit(2); }
  var s = R.stats;
  console.log('check-defang: ' + target);
  console.log('  self-test   known positives flagged (URL, IPv4, IPv6 URL, domain on an IANA TLD, e-mail, partly defanged, link target, bare attacker block and line, bare multi-tenant allow entry), defanged twins and private addresses clean');
  console.log('  tld list    ' + getTlds().count + ' names, data/iana-tlds.txt: ' + getTlds().version);
  console.log('  allow file  ' + autoNote + (allowFiles.length > autoFiles.length ? '; plus ' + (allowFiles.length - autoFiles.length) + ' --allow file(s)' : ''));
  console.log('  files       ' + s.files + ' page(s) read (index.md and any .md with front matter)' + (R.skipped.length ? '; ' + R.skipped.length + ' .md without front matter not read (not published): ' + R.skipped.map(function (f) { return path.basename(f); }).join(', ') : ''));
  console.log('  lines       (non-blank) ' + s.fmLines + ' front-matter (identity keys skipped), ' + s.bodyLines + ' body outside fences, ' + s.blockLines + ' inside ' + s.blocksScanned + ' scanned fenced blocks');
  console.log('  blocks      ' + s.blocks + ' fenced: ' + s.blocksCopy + ' marked .hl-copy (defender, kept raw, not scanned for indicators), ' + s.blocksScanned + ' scanned');
  var matched = s.matchedFlagged + s.matchedDefanged + s.matchedPrivate + s.matchedSuffix + s.matchedAllowed;
  console.log('  indicators  ' + matched + ' indicator-shaped tokens matched: ' + s.matchedFlagged + ' un-defanged (flagged), ' + s.matchedDefanged + ' already defanged, ' + s.matchedPrivate + ' private/reserved, ' + s.matchedSuffix + ' bare public suffix (a registry named as such, not a host), ' + s.matchedAllowed + ' allowed');
  var ab = Object.keys(s.allowedBy);
  if (ab.length) console.log('  allowed     ' + R.allow.builtin + ' built-in + ' + R.allow.fromFile + ' file entries; hits suppressed: ' + ab.sort().map(function (e) { return e + ' x' + s.allowedBy[e]; }).join(', '));
  if (s.blockExceptions) console.log('  excepted    ' + s.blockExceptions + ' command-block finding(s) excused by a one-block exception: ' + s.cmdBlocksExcepted.map(function (b) { return b.file + ':' + b.line + ' (' + b.reason + ')'; }).join('; '));
  console.log('  commands    ' + s.cmdBlocks + ' command-like blocks outside .hl-copy: ' + s.cmdBlocksBracketed + ' fully bracketed, ' + s.cmdBlocksBare + ' with no bracketed command token, ' + s.cmdBlocksLinesBare + ' bracketed on some lines but not all (' + s.cmdLinesBare + ' executable line(s) bare of ' + s.cmdLines + ' recognised)');
  console.log('  links       ' + s.linkTargets + ' link target(s) with a host scanned like text (inline, reference, href/src), ' + s.linkTargetsNoHost + ' relative/anchor/Liquid target(s) with no host');
  if (R.stats.exceptionsOtherFile && R.stats.exceptionsOtherFile.length) console.log('  NOT CHECKED ' + R.stats.exceptionsOtherFile.length + ' block exception(s) name another page than the one file scanned: ' + R.stats.exceptionsOtherFile.join('; '));
  if (s.copyBlocks.length) {
    console.log('  .hl-copy    ' + s.copyBlocks.length + ' defender block(s) kept copyable, ' + s.copyBlockIndicators + ' indicator(s) raw inside them (rule 3, defender content):');
    s.copyBlocks.slice(0, all ? undefined : 20).forEach(function (c) { console.log('              ' + c.file + ':' + c.line + ' [' + (c.lang || 'untagged') + ', ' + c.lines + ' lines, ' + c.indicators + ' raw] ' + c.first); });
    if (!all && s.copyBlocks.length > 20) console.log('              (' + (s.copyBlocks.length - 20) + ' more not printed; --all prints them)');
  }
  var total = s.fmLines + s.bodyLines + s.blockLines;
  if (total === 0) { console.log('NOT CHECKED  no line was scanned (zero denominator): ' + target); process.exit(2); }
  var F = R.findings, limit = all ? F.length : 200;
  F.slice(0, limit).forEach(function (f) { console.log('  FINDING     ' + f.file + ':' + f.line + '  ' + f.kind + '  [' + f.ctx + ']  ' + (f.kind === 'ATTACKER-COMMAND-BLOCK' ? f.token : defangForPrint(f.token))); });
  if (F.length > limit) console.log('  (' + (F.length - limit) + ' more findings not printed; --all prints them)');
  var kinds = {};
  F.forEach(function (f) { kinds[f.kind] = (kinds[f.kind] || 0) + 1; });
  var summary = total + ' lines, ' + s.blocks + ' blocks, ' + matched + ' indicator tokens scanned in ' + s.files + ' file(s); allow file: ' +
    (autoFiles.length ? path.basename(autoFiles[0]) : 'none') + ', ' + s.matchedAllowed + ' hit(s) suppressed, ' + s.blockExceptions + ' block exception(s)';
  if (F.length) {
    console.log('FAIL  ' + F.length + ' finding(s) (' + Object.keys(kinds).sort().map(function (k) { return k + ' ' + kinds[k]; }).join(', ') + '); ' + summary);
    process.exit(1);
  }
  console.log('PASS  no un-defanged indicator outside .hl-copy blocks, link targets included, and no attacker command line without a bracketed command token; ' + summary +
    '; CANNOT SEE: deliberate obfuscation by the author (comment and line-continuation tricks, srcset or entity-encoded schemes, mixed-encoding dot segments, numeric or hex IPv4 hosts: the lint guards honest mistakes, not evasion); bare IPv6 text outside a URL; a domain whose last label is not in the IANA snapshot (' + getTlds().count + ' names); a command whose first token is not in COMMANDS; indented (4-space) code; Liquid/include output; the rendered page; whether an allowed name is really benign (the allow file is the reviewer\'s claim)');
  process.exit(0);
}

/* ---------- the rendered non-report pages (lib/defang-site.js) ---------- */

function mainSite(site, allowData, only, all, records) {
  var S = require('./lib/defang-site.js');
  if (!allowData) allowData = path.join(__dirname, '..', '..', '_data', 'defang_allow.yml');
  if (!fs.existsSync(site) || !fs.statSync(site).isDirectory()) { console.log('NOT CHECKED  not a directory: ' + site); process.exit(2); }
  if (!fs.existsSync(allowData)) { console.log('NOT CHECKED  allow data not found: ' + allowData); process.exit(2); }
  var bad = selfTest().concat(S.selfTest());
  if (bad.length) { bad.forEach(function (b) { console.log('SELF-TEST  ' + b); }); console.log('NOT CHECKED  the lint failed its own known-positive self-test; no verdict'); process.exit(2); }
  var R;
  try { R = S.scanSite(site, allowData, { only: only ? new RegExp(only) : null }); } catch (e) { console.log('NOT CHECKED  ' + e.message); process.exit(2); }
  var s = R.stats, F = R.findings;
  // T-0548: the site-search records (Wire rows added to the Pagefind index by build-search-index.js); /pagefind/ is excluded above, so the records the build wrote are the gated input
  var RS = null;
  if (records) {
    if (!fs.existsSync(records)) { console.log('NOT CHECKED  search records file not found: ' + records); process.exit(2); }
    try { RS = S.scanRecords(records, allowData); } catch (e) { console.log('NOT CHECKED  ' + e.message); process.exit(2); }
    F = F.concat(RS.findings);
  }
  console.log('check-defang --site: ' + site);
  console.log('  self-test   known positives flagged (IPv4, domain, e-mail, URL, link to an IP, unlisted link, foreign mailto, raw pre outside a detection page, tooltip attribute), defanged twins, own-page links and a detection rule body clean');
  console.log('  allow data  ' + allowData + ': ' + R.data.rawCount + ' raw names, ' + R.data.mailboxCount + ' own mailboxes, ' + R.data.links.length + ' link entries');
  var types = Object.keys(s.byType).sort().map(function (t) { return t + ' ' + s.byType[t]; });
  console.log('  pages       ' + s.pages + ' scanned: ' + types.join(', '));
  var ex = Object.keys(s.excluded).sort().map(function (k) { return s.excluded[k] + ' ' + k; });
  console.log('  excluded    ' + (ex.length ? ex.join('; ') : 'none'));
  var matched = s.matchedFlagged + s.matchedDefanged + s.matchedPrivate + s.matchedAllowed;
  console.log('  head        ' + s.head.fields + ' <head> display strings scanned (<title>, title, description and alt meta tags, ' + s.head.jsonld + ' JSON-LD blocks parsed), ' + s.head.tokens + ' indicator-shaped tokens in them; URLs in the head are not read');
  console.log('  text        ' + s.textNodes + ' text nodes and ' + s.attrs + ' tooltip attributes scanned (pre, script, style, template excluded)');
  console.log('  indicators  ' + matched + ' indicator-shaped tokens matched: ' + s.matchedFlagged + ' un-defanged (flagged), ' + s.matchedDefanged + ' already defanged, ' + s.matchedPrivate + ' private/reserved, ' + s.matchedAllowed + ' allowed by name');
  var ab = Object.keys(s.allowedBy);
  if (ab.length) console.log('  allowed     hits by name: ' + ab.sort().map(function (e) { return e + ' x' + s.allowedBy[e]; }).join(', '));
  var L = s.links;
  console.log('  links       ' + L.total + ' <a href>: ' + L.relative + ' own-site/relative, ' + L.anchor + ' anchors, ' + L.external + ' external (' + L.externalAllowed + ' kept: listed reference or Wire publisher, ' + L.labelSkips + ' labelled with their own host name; ' + L.reportRefs + ' more on report pages: references, none to a host the page names defanged), ' + L.mailto + ' mailto, ' + L.other + ' other scheme');
  console.log('  pre         ' + s.pre.blocks + ' blocks, ' + s.pre.lines + ' lines: ' + s.pre.onDetection + ' on detection pages kept exact (' + s.pre.rawIndicators + ' raw indicator token(s) inside, rule bodies), ' + s.pre.offDetection + ' elsewhere scanned as page text, ' + s.pre.onReport + ' on report pages scanned the same way; ' + s.pre.copyKept + ' .hl-copy blocks on report pages kept exact');
  console.log('  unlinked    ' + s.unlinked.n + ' <a> rendered as text by the include (an off-site target not under `links` in the allow data)' + (s.unlinked.n ? ':' : ''));
  s.unlinked.targets.forEach(function (t) { console.log('              ' + t); });
  console.log('  literal     ' + s.literal.cells + ' IOC viewer cell(s) marked data-literal (hash, filename, path, registry values, as the feed recorded them), each checked for its type');
  if (RS) {
    var rt = RS.stats;
    console.log('  records     ' + rt.records + ' site-search records (' + Object.keys(rt.bySection).sort().map(function (k) { return k + ' ' + rt.bySection[k]; }).join(', ') + '), ' + rt.fields + ' fields and ' + rt.lines + ' lines scanned: ' + rt.matchedFlagged + ' un-defanged (flagged), ' + rt.matchedDefanged + ' already defanged, ' + rt.matchedPrivate + ' private/reserved, ' + rt.matchedAllowed + ' allowed by name (content and title of each record; the date and section are not text)');
    if (rt.records === 0 || rt.lines === 0) { console.log('NOT CHECKED  the search records file holds no record or no text (zero denominator)'); process.exit(2); }
  } else {
    console.log('  records     NOT GATED: no --records file given, so the text build-search-index.js puts in the search index was not scanned');
  }
  if (s.pages === 0 || s.textNodes === 0) { console.log('NOT CHECKED  no page or no text node was scanned (zero denominator)'); process.exit(2); }
  var limit = all ? F.length : 60;
  var kinds = {}, byType = {};
  F.forEach(function (f) { kinds[f.kind] = (kinds[f.kind] || 0) + 1; byType[f.type] = (byType[f.type] || 0) + 1; });
  F.slice(0, limit).forEach(function (f) { console.log('  FINDING     ' + f.page + '  ' + f.kind + '  [' + f.ctx + ']  ' + D_print(f.token) + (f.near ? '   near: ' + D_print(f.near) : '')); });
  if (F.length > limit) console.log('  (' + (F.length - limit) + ' more findings not printed; --all prints them)');
  if (F.length) {
    console.log('  by type     ' + Object.keys(byType).sort().map(function (t) { return t + ' ' + byType[t]; }).join(', '));
    console.log('FAIL  ' + F.length + ' finding(s) (' + Object.keys(kinds).sort().map(function (k) { return k + ' ' + kinds[k]; }).join(', ') + ') on the rendered pages');
    process.exit(1);
  }
  console.log('PASS  no un-defanged indicator in the visible text of ' + s.pages + ' rendered pages (' + (s.byType.report || 0) + ' of them report pages), no link to an IP or to an unlisted host (a report page: no link to a host it names defanged), no foreign mailto; ' + matched + ' indicator tokens scanned. CANNOT SEE: text a script writes after load (check-browser-defang.js reads that in a real browser); the data-title search keys (raw on purpose); head URLs (canonical, og:url, og:image, JSON-LD url and @id: own page addresses); downloadable feed files; hrefs to this site\'s own pages; rule bodies on detection pages (' + s.pre.onDetection + ' <pre> blocks, exact by decision 5) and the .hl-copy blocks on report pages (' + s.pre.copyKept + ', exact like the source lint reads them); whether an off-site link on a report page is a reference or actor infrastructure beyond the host test (a link to a host the page names defanged, or to an IP); own-page hrefs and image paths (the slug carries the address); whether a name on the raw or links list is really benign (the list is a reviewer\'s claim)');
  process.exit(0);
}
function D_print(t) { return defangForPrint(t); }

module.exports = { isPublicSuffix: isPublicSuffix, allowedBy: allowedBy, getTlds: getTlds, isTld: isTld, analyseBlock: analyseBlock, cmdPosBracket: cmdPosBracket, multiTenantKind: multiTenantKind, autoAllow: autoAllow, scanLine: scanLine, scanFile: scanFile, run: run, makeAllow: makeAllow, newStats: newStats, selfTest: selfTest,
  lineLooksLikeCommand: lineLooksLikeCommand, defangForPrint: defangForPrint, BRACKET_CMD: BRACKET_CMD, BUILTIN_ALLOW: BUILTIN_ALLOW };

if (require.main === module) main();
