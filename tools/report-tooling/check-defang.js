#!/usr/bin/env node
'use strict';

/* The defang lint (T-0500.1.12, rules 1, 2, 3 and 5 of tasks/runs/T-0500.1.12/defang-rules.md; Joseph, 2026-10-31:
   "we just do not want it to be easy for people to make a mistake and run something").

   node check-defang.js <report folder | index.md | any .md> [--allow FILE]... [--all] [--quiet-ok]

   Reads the report SOURCE (a folder: every .md under it, the index and any sub-report pages; a file: that file) and reports

     1. every un-defanged, non-private network indicator a reader sees in the page body: URLs, IPv4 addresses, domains and
        e-mail addresses, in prose, inline code, tables, lists, fenced blocks and the front-matter fields the page renders
        (everything except the page-identity keys title, description, permalink, slug and the fields that are paths or
        switches: see FM_SKIP). A partly defanged host (`evil[.]example.com`) is reported: the canonical form defangs every dot.
     2. every attacker code block with no bracketed command token: an unmarked fenced block whose lines look like commands
        (a shell/PowerShell/batch language tag, or a first token from COMMANDS or a cmdlet verb-noun) and which holds no
        `[p]owershell`-style token. A block with at least one bracketed token passes this test; the lint also prints, as a
        NOTE and never a FAIL, how many command-like lines of such a block are still unbracketed, because rule 2 asks for a
        bracket "on each line" of a command list and "one bracket on the first executable statement" of a script, and a
        lint cannot tell the two apart.

   Out of scope, as the rules say: a block marked `{: .hl-copy}` (defender content; kramdown puts the IAL on the line
   directly under the closing fence), link targets (`](url)`, `href=`, `src=` and the like, reference definitions), private
   addresses (RFC 1918, loopback, link-local, 0.0.0.0, 224+), and the names in BUILTIN_ALLOW plus any `--allow FILE`
   (one name per line, `#` comments; a domain entry also covers its subdomains). Allowed hits are COUNTED, per entry, in the
   output: a suppressed indicator is never silent. An attacker URL on a legitimate service (a paste or file-share link) is NOT
   allowed by default: that is why the built-in list holds no hosting, code or storage service.

   Findings are printed DEFANGED (the lint's own output is not a copy-ready indicator list).

   DENOMINATORS, printed every run (lines are non-blank lines): files, front-matter lines, body lines, fenced blocks (total / marked .hl-copy and skipped /
   scanned), fenced-block lines scanned, indicator-shaped tokens matched (flagged / already defanged / private / allowed),
   command-like blocks (bracketed / not). A run that scanned no lines is NOT CHECKED, never PASS.

   SELF-TEST, every run, before the verdict is believed: a known-positive fixture must be flagged on every kind (URL, IPv4,
   domain, e-mail, partly defanged host, unmarked attacker block) and its defanged twin must come back clean, or the run is
   NOT CHECKED.

   WHAT IT CANNOT SEE (say so wherever the verdict is quoted): IPv6; domains on a TLD outside TLDS_STRONG, and the TLDs that
   double as file extensions (.sh .py .pl .rs .so .md .zip .mov .cc .id .in .is .it .me .to and the like) unless they sit in a
   URL; a command in a block that has no shell tag and whose first token is not in COMMANDS; script languages without a
   command first token (JavaScript, VBA, Python) unless tagged as a shell; indented (4-space) code, which is read as prose;
   anything rendered by an include or Liquid tag from data outside the file; the rendered page (this is a source lint).

   Exit 0 PASS, 1 FAIL, 2 NOT CHECKED. Run: node check-defang.js <report folder or index.md> */

var fs = require('node:fs');
var path = require('node:path');

/* ---------- vocabulary ---------- */

var TLDS_STRONG = ('com net org info biz edu gov mil int io co xyz top online site store shop cloud app dev tech fun vip club work ' +
  'pw tk ml ga cf gq cn ru su ua kz ir kr jp tw vn br mx de fr uk nl eu us ca au pk tr es ch se onion i2p link click live icu cyou ' +
  'buzz rest bond monster sbs cfd lol mobi pro asia ws ai gl ly cx bz xxx space').split(' ');
var TLD_RE = TLDS_STRONG.join('|');

/* Names that are not infrastructure of the actor: our own site, RFC 2606 names, the XML/schema namespaces reports quote and
   the MITRE/standards references. Deliberately no hosting, code, paste or storage service: an attacker URL on one of those
   is defanged (rule 1). Anything else a report names as a product goes in an --allow file. */
var BUILTIN_ALLOW = ['the-hunters-ledger.com', 'example.com', 'example.org', 'example.net', 'example.invalid', 'localhost',
  'attack.mitre.org', 'mitre.org', 'w3.org', 'schemas.microsoft.com', 'schemas.xmlsoap.org', 'purl.org', 'xmlsoap.org',
  /* .NET names that end in a TLD word: product/namespace names, not hosts */
  'asp.net', 'system.net', 'system.io', 'vb.net'];

var SHELL_LANGS = ['powershell', 'ps1', 'pwsh', 'bash', 'sh', 'shell', 'zsh', 'console', 'shell-session', 'cmd', 'bat', 'batch', 'vbs', 'vbscript', 'vba'];
/* Structured data, rules and compiled-language source: never read as "commands" by first token. */
var DATA_LANGS = ['json', 'yaml', 'yml', 'xml', 'ini', 'toml', 'yara', 'sigma', 'suricata', 'snort', 'sql', 'kql', 'spl', 'html', 'css',
  'diff', 'csv', 'c', 'cpp', 'csharp', 'cs', 'java', 'go', 'rust', 'asm', 'python', 'py', 'markdown', 'md'];

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

function makeAllow(files) {
  var entries = BUILTIN_ALLOW.slice(), fromFile = 0;
  (files || []).forEach(function (f) {
    fs.readFileSync(f, 'utf8').split(/\r?\n/).forEach(function (l) {
      l = l.replace(/#.*$/, '').trim().toLowerCase();
      if (l) { entries.push(l); fromFile++; }
    });
  });
  return { entries: entries, builtin: BUILTIN_ALLOW.length, fromFile: fromFile };
}
function allowedBy(allow, host) {
  host = String(host).toLowerCase();
  for (var i = 0; i < allow.entries.length; i++) {
    var e = allow.entries[i];
    if (host === e || host.endsWith('.' + e)) return e;
  }
  return null;
}

/* Strip what the rules put out of scope on a body line: link targets, href/src attributes, reference definitions. */
function stripTargets(line) {
  if (/^\s*\[[^\]]+\]:\s*\S+/.test(line) && !/^\s*\[[^\]]+\]:\s*$/.test(line)) return '';
  return line
    .replace(/\{\{[^}]*\}\}|\{%[^%]*%\}/g, ' ') /* Liquid output/tags (a src="{{ "/assets/.." | relative_url }}" path holds quotes) */
    .replace(/\]\((?:<[^>]*>|[^)\s]*)(?:\s+"[^"]*")?\)/g, ']')
    .replace(/\b(?:href|src|poster|srcset|action|data-href|data-src)\s*=\s*(?:"[^"]*"|'[^']*')/gi, ' ');
}

/* ---------- indicator scan of one line ---------- */

var URL_RE = /\b(?:https?|ftps?|sftp|wss?):\/\/[^\s"'<>]+/gi;
var EMAIL_RE = new RegExp('[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+(?:\\[\\.\\]|\\.))+(?:' + TLD_RE + ')\\b', 'gi');
var IP_RE = /(?<![\d]|\d\.|\d\[\.\])(\d{1,3})(\[\.\]|\.)(\d{1,3})(\[\.\]|\.)(\d{1,3})(\[\.\]|\.)(\d{1,3})(?!\d|\.\d|\[\.\]\d)/g;
var DOMAIN_RE = new RegExp('(?<![A-Za-z0-9_\\\\-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\[\\.\\]|\\.))+(?:' + TLD_RE + '))(?![A-Za-z0-9_(-]|\\.[A-Za-z0-9]|\\[\\.\\][A-Za-z0-9])', 'gi');
var HXXP_RE = /\b(?:hxxps?|fxp):\/\//gi;

function mask(line, start, end) { return line.slice(0, start) + ' '.repeat(end - start) + line.slice(end); }

/* Returns { flagged: [{kind, token}], defanged: n, privateN: n, allowed: {entry: n} }. */
function scanLine(rawLine, allow) {
  var out = { flagged: [], defanged: 0, privateN: 0, allowedN: 0, allowed: {} };
  var line = rawLine, m;
  function noteAllowed(e) { out.allowedN++; out.allowed[e] = (out.allowed[e] || 0) + 1; }

  // 1. URLs with a real scheme. The scheme itself is the violation (canonical form is hxxp), whatever the host looks like.
  URL_RE.lastIndex = 0;
  var spans = [];
  while ((m = URL_RE.exec(line))) {
    var tok = m[0].replace(/[)\]}.,;:`'"*_]+$/, '');
    var auth = tok.replace(/^[a-z]+:\/\//i, '').split(/[\/?#]/)[0].replace(/^[^@]*@/, '');
    var host = auth.replace(/:\d+$/, '');
    spans.push([m.index, m.index + m[0].length]);
    var oct = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (oct && isPrivateIPv4(oct.slice(1).map(Number))) { out.privateN++; continue; }
    if (/^\[.*\]$/.test(host)) { out.privateN++; continue; } /* IPv6 literal: not checked */
    var al = allowedBy(allow, host.replace(/\[\.\]/g, '.'));
    if (al) { noteAllowed(al); continue; }
    out.flagged.push({ kind: 'URL', token: tok });
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });

  // 2. e-mail addresses: the canonical form brackets the @
  EMAIL_RE.lastIndex = 0;
  spans = [];
  while ((m = EMAIL_RE.exec(line))) {
    spans.push([m.index, m.index + m[0].length]);
    var dom = m[0].split('@')[1].replace(/\[\.\]/g, '.');
    var al2 = allowedBy(allow, dom);
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
    spans.push([m.index, m.index + m[0].length]);
    if (isPrivateIPv4(o)) { out.privateN++; continue; }
    var seps = [m[2], m[4], m[6]];
    if (seps.some(function (s) { return s === '.'; })) {
      var ip = o.join('.'), al3 = allowedBy(allow, ip);
      if (al3) { noteAllowed(al3); continue; }
      out.flagged.push({ kind: seps.every(function (s) { return s === '.'; }) ? 'IPV4' : 'IPV4-PARTLY-DEFANGED', token: m[0] });
    } else out.defanged++;
  }
  spans.forEach(function (s) { line = mask(line, s[0], s[1]); });

  // 4. domains on a strong TLD, raw or with any dot defanged; flagged when at least one dot is raw
  DOMAIN_RE.lastIndex = 0;
  while ((m = DOMAIN_RE.exec(line))) {
    var d = m[1];
    // a path-like or Windows-name context is not a host: preceded by a backslash is excluded by the lookbehind; a file
    // name such as `Net.WebClient` ends in no TLD, so it never reaches here.
    var hasRaw = /(^|[^\]])\.(?!\])/.test(d.replace(/\[\.\]/g, '\u0000'));
    var plain = d.replace(/\[\.\]/g, '.').toLowerCase();
    if (!hasRaw) { out.defanged++; continue; }
    var al4 = allowedBy(allow, plain);
    if (al4) { noteAllowed(al4); continue; }
    out.flagged.push({ kind: /\[\.\]/.test(d) ? 'DOMAIN-PARTLY-DEFANGED' : 'DOMAIN', token: d });
  }
  var hx = rawLine.match(HXXP_RE);
  if (hx) out.defanged += hx.length;
  return out;
}

/* ---------- command-like lines ---------- */

var BRACKET_CMD = /(^|[\s("'`$|;&=,{])\[[A-Za-z0-9.\/~]\](?=[A-Za-z0-9._\/\\-])/;

function stripPrompt(l) {
  return l.replace(/^(?:PS\s+[^>]*>|[A-Za-z]:\\[^>]*>|\$\s|>\s|%\s)\s*/, '');
}
function isComment(l) { return /^(#|\/\/|rem\s|::|')/i.test(l.trim()); }
function lineLooksLikeCommand(line) {
  var l = line.trim();
  if (!l || isComment(l)) return false;
  l = stripPrompt(l);
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

/* ---------- parsing one markdown file ---------- */

var FM_SKIP = ['title', 'description', 'permalink', 'slug', 'layout', 'hide', 'date', 'last_updated', 'category', 'thumbnail',
  'stix_bundle', 'ioc_feed', 'detection_page', 'sitemap', 'unlisted', 'sponsored_by', 'series', 'series_role', 'series_order',
  'embargo', 'tags', 'image', 'canonical', 'redirect_from'];

function newStats() {
  return { files: 0, fmLines: 0, bodyLines: 0, blocks: 0, blocksCopy: 0, blocksScanned: 0, blockLines: 0,
    matchedFlagged: 0, matchedDefanged: 0, matchedPrivate: 0, matchedAllowed: 0, allowedBy: {},
    cmdBlocks: 0, cmdBlocksBracketed: 0, cmdBlocksBare: 0, cmdLinesUnbracketedInBracketedBlocks: 0, copyBlockIndicators: 0,
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
  function addScan(line, ln, ctx, isBlock) {
    var r = scanLine(line, allow);
    stats.matchedFlagged += r.flagged.length;
    stats.matchedDefanged += r.defanged;
    stats.matchedPrivate += r.privateN;
    stats.matchedAllowed += r.allowedN;
    Object.keys(r.allowed).forEach(function (e) { stats.allowedBy[e] = (stats.allowedBy[e] || 0) + r.allowed[e]; });
    r.flagged.forEach(function (f) { findings.push({ file: file, line: ln, ctx: ctx, kind: f.kind, token: f.token }); });
    return r;
  }
  // front matter: every top-level key block except the identity/switch keys
  if (fmEnd > 0) {
    var skipping = false, key = '';
    for (var f = 1; f < fmEnd; f++) {
      var km = lines[f].match(/^([A-Za-z_][A-Za-z0-9_-]*):/);
      if (km) { key = km[1]; skipping = FM_SKIP.indexOf(key) !== -1; }
      if (skipping) continue;
      if (lines[f].trim()) stats.fmLines++;
      addScan(stripTargets(lines[f]), f + 1, 'front-matter:' + key, false);
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
      addScan(stripTargets(ln), i + 1, 'body', false);
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
      var cmdLines = 0, bracketed = false, unbr = 0, nonEmpty = 0;
      body.forEach(function (bl, bi) {
        if (bl.trim()) stats.blockLines++;
        addScan(bl, open + 2 + bi, 'block', true);
        if (bl.trim() && !isComment(bl)) nonEmpty++;
        var isCmd = lineLooksLikeCommand(bl);
        if (BRACKET_CMD.test(bl)) bracketed = true;
        if (isCmd || (SHELL_LANGS.indexOf(lang) !== -1 && bl.trim() && !isComment(bl))) { cmdLines++; if (!BRACKET_CMD.test(bl)) unbr++; }
      });
      var cmdBlock = DATA_LANGS.indexOf(lang) === -1 && cmdLines > 0;
      if (cmdBlock && nonEmpty > 0) {
        stats.cmdBlocks++;
        if (bracketed) { stats.cmdBlocksBracketed++; stats.cmdLinesUnbracketedInBracketedBlocks += unbr; }
        else {
          stats.cmdBlocksBare++;
          findings.push({ file: file, line: open + 1, ctx: 'block', kind: 'ATTACKER-COMMAND-BLOCK',
            token: '(' + (lang || 'untagged') + ', ' + body.length + ' lines, ' + cmdLines + ' command-like; first: ' +
              defangForPrint((body.find(function (x) { return x.trim() && !isComment(x); }) || '').trim().slice(0, 60)) + ')' });
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
  'mixed evil[.]example-attacker.com there'
];
var FIXTURE_GOOD = [
  'beacon at hxxp://198[.]51[.]100[.]17:8080/a.ps1 now',
  'host 198[.]51[.]100[.]17 listed',
  'domain evil[.]example-attacker[.]com seen',
  'mail ops[@]evil[.]example-attacker[.]com sent',
  'private 10.1.2.3 and 192.168.0.9 and 127.0.0.1 fine'
];
function selfTest() {
  var allow = makeAllow([]), why = [];
  var kinds = [['URL'], ['IPV4'], ['DOMAIN'], ['EMAIL'], ['IPV4-PARTLY-DEFANGED'], ['DOMAIN-PARTLY-DEFANGED']];
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
  return { allow: allow, stats: stats, findings: findings, files: files, skipped: skipped };
}

function main() {
  var argv = process.argv.slice(2), target = null, allowFiles = [], all = false;
  for (var a = 0; a < argv.length; a++) {
    if (argv[a] === '--allow') allowFiles.push(argv[++a]);
    else if (argv[a] === '--all') all = true;
    else if (argv[a] === '-h' || argv[a] === '--help') { console.log('usage: node check-defang.js <report folder | index.md> [--allow FILE]... [--all]'); process.exit(0); }
    else target = argv[a];
  }
  if (!target) { console.log('NOT CHECKED  usage: node check-defang.js <report folder | index.md> [--allow FILE]... [--all]'); process.exit(2); }
  if (!fs.existsSync(target)) { console.log('NOT CHECKED  not found: ' + target); process.exit(2); }
  for (var af = 0; af < allowFiles.length; af++) if (!allowFiles[af] || !fs.existsSync(allowFiles[af])) { console.log('NOT CHECKED  allow file not found: ' + allowFiles[af]); process.exit(2); }

  var bad = selfTest();
  if (bad.length) { bad.forEach(function (b) { console.log('SELF-TEST  ' + b); }); console.log('NOT CHECKED  the lint failed its own known-positive self-test; no verdict'); process.exit(2); }

  var R = run(target, allowFiles), s = R.stats;
  console.log('check-defang: ' + target);
  console.log('  self-test   known positives flagged on 6 kinds + 1 bare attacker block, defanged twins and private addresses clean');
  console.log('  files       ' + s.files + ' page(s) read (index.md and any .md with front matter)' + (R.skipped.length ? '; ' + R.skipped.length + ' .md without front matter not read (not published): ' + R.skipped.map(function (f) { return path.basename(f); }).join(', ') : ''));
  console.log('  lines       (non-blank) ' + s.fmLines + ' front-matter (identity keys skipped), ' + s.bodyLines + ' body outside fences, ' + s.blockLines + ' inside ' + s.blocksScanned + ' scanned fenced blocks');
  console.log('  blocks      ' + s.blocks + ' fenced: ' + s.blocksCopy + ' marked .hl-copy (defender, kept raw, not scanned for indicators), ' + s.blocksScanned + ' scanned');
  var matched = s.matchedFlagged + s.matchedDefanged + s.matchedPrivate + s.matchedAllowed;
  console.log('  indicators  ' + matched + ' indicator-shaped tokens matched: ' + s.matchedFlagged + ' un-defanged (flagged), ' + s.matchedDefanged + ' already defanged, ' + s.matchedPrivate + ' private/reserved, ' + s.matchedAllowed + ' allowed');
  var ab = Object.keys(s.allowedBy);
  if (ab.length) console.log('  allowed     ' + R.allow.builtin + ' built-in + ' + R.allow.fromFile + ' file entries; hits suppressed: ' + ab.sort().map(function (e) { return e + ' x' + s.allowedBy[e]; }).join(', '));
  console.log('  commands    ' + s.cmdBlocks + ' command-like blocks outside .hl-copy: ' + s.cmdBlocksBracketed + ' with a bracketed token, ' + s.cmdBlocksBare + ' without');
  if (s.cmdLinesUnbracketedInBracketedBlocks) console.log('  NOTE        ' + s.cmdLinesUnbracketedInBracketedBlocks + ' command-like line(s) in blocks that DO have a bracketed token carry none (rule 2: a command list brackets each line, a script one statement; the lint cannot tell them apart)');
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
  var summary = total + ' lines, ' + s.blocks + ' blocks, ' + matched + ' indicator tokens scanned in ' + s.files + ' file(s)';
  if (F.length) {
    console.log('FAIL  ' + F.length + ' finding(s) (' + Object.keys(kinds).sort().map(function (k) { return k + ' ' + kinds[k]; }).join(', ') + '); ' + summary);
    process.exit(1);
  }
  console.log('PASS  no un-defanged indicator outside .hl-copy blocks and no attacker command block without a bracketed token; ' + summary);
  process.exit(0);
}

module.exports = { scanLine: scanLine, scanFile: scanFile, run: run, makeAllow: makeAllow, newStats: newStats, selfTest: selfTest,
  lineLooksLikeCommand: lineLooksLikeCommand, defangForPrint: defangForPrint, BRACKET_CMD: BRACKET_CMD, BUILTIN_ALLOW: BUILTIN_ALLOW };

if (require.main === module) main();
