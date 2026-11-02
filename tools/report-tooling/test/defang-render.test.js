'use strict';
/* T-0500.1.7.4 b1b (Joseph, 2026-11-02, decision 5: defang everything a reader sees on a non-report page, render-time, never in a data file).
   The includes are Liquid and Liquid has no regular expressions, so they are tested the only way that proves them: by BUILDING a scratch Jekyll
   site (the real includes, the real _data/defang_*.yml, a fixture page) and reading the HTML. When the jekyll gem is not on this machine the
   Jekyll cases report NOT CHECKED (skipped with the reason), never PASS (homelab-soc/docs/gate-honesty-contract.md); the static cases always run.
   The second half is the cross-check that matters: every string the includes defang must come back CLEAN from the rendered-page gate
   (lib/defang-site.js), and the same page built WITHOUT the include must FAIL it (the control).
   Fixture addresses and names are documentation ranges (RFC 5737, RFC 2606). */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const yaml = require('js-yaml');
const root = path.join(__dirname, '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const D = require('../check-defang.js');
const S = require('../lib/defang-site.js');

/* ---- static: the data the includes and the gate share ---- */
test('_data/defang_tlds.yml is the IANA snapshot check-defang.js reads (plus onion and i2p): the include and the lint cannot disagree on what a domain is', () => {
  const have = yaml.load(read('_data/defang_tlds.yml'));
  const want = Object.keys(D.getTlds().set).sort();
  assert.deepEqual(Object.keys(have).sort(), want);
  assert.ok(want.length > 1000 && have.com === 1 && have.sh === 1 && have['xn--p1ai'] === 1);
});

test('_data/defang_allow.yml loads under the gate: every raw name and mailbox has a reason, no bare multi-tenant host, links are strings', () => {
  const data = S.loadAllowData(path.join(root, '_data', 'defang_allow.yml'));
  assert.ok(data.rawCount >= 5 && data.links.length >= 5 && data.mailboxCount >= 1);
  assert.deepEqual(data.allow.bad, []);
  const bad = path.join(os.tmpdir(), 'hl-allow-noreason-' + process.pid + '.yml');
  fs.writeFileSync(bad, 'raw:\n  evil.example.org:\nlinks: []\n');
  assert.throws(() => S.loadAllowData(bad), /no reason/, 'control: an entry with no reason is refused');
  fs.writeFileSync(bad, 'raw:\n  github.com: x\nlinks: []\n');
  assert.throws(() => S.loadAllowData(bad), /ALLOW-MULTI-TENANT/, 'control: a bare multi-tenant host is refused');
  fs.unlinkSync(bad);
});

test('the layouts call the shared include: page.html for every non-report page (the Wire keeps its links), post.html for detection pages only', () => {
  const page = read('_layouts/page.html');
  assert.match(page, /include defang-html\.html html=content unlink=false/);
  assert.match(page, /if page\.url == '\/wire\/'/);
  assert.match(page, /\{% elsif page\.url contains '\/report-templates\/' or page\.url contains '\/changelog\/' %\}\{\{ content \}\}\{% else %\}\{% include defang-html\.html html=content %\}\{% endif %\}/, 'the working docs keep their text (decision 7)');
  const post = read('_layouts/post.html');
  assert.match(post, /\{% if page\.path contains 'hunting-detections' %\}\{% include defang-html\.html html=content %\}\{% else %\}\{\{ content \}\}\{% endif %\}/, 'a report keeps {{ content }} untouched');
});

test('post.html defangs a report title wherever the layout prints it (header, citation, BibTeX, Continue Reading cards) and the share sheet takes the visible title', () => {
  const post = read('_layouts/post.html');
  // no raw title is printed by the layout; every print goes through the include (T-0500.1.7.4 ship: a report's title carries the campaign's address)
  assert.doesNotMatch(post, /\{\{\s*page\.title\s*\}\}/, 'page.title printed raw');
  assert.doesNotMatch(post, /\{\{\s*rp\.title\s*\}\}/, 'rp.title printed raw');
  assert.equal((post.match(/include defang-text\.html text=page\.title/g) || []).length >= 3, true, 'both headers and the citation take the include');
  assert.match(post, /include defang-text\.html text=rp\.title/);
  assert.doesNotMatch(post, /title: document\.title/, 'the share sheet must not take the head title');
  const tabs = read('assets/js/hl-report-tabs.js');
  assert.doesNotMatch(tabs, /title: document\.title/, 'the tabbed share button must not take the head title');
});

test('the head display strings go through the include: the SEO tag and the JSON-LD blocks through defang-head.html, the twitter description and the image alt texts through defang-text.html; URLs stay exact', () => {
  const head = read('_includes/default/head.liquid');
  assert.match(head, /include defang-head\.html text=_seo/);
  assert.match(head, /include defang-head\.html text=_sd/);
  assert.match(head, /include defang-text\.html text=_tw_d0/);
  assert.match(head, /include defang-text\.html text=_alt_t/);
  assert.doesNotMatch(head, /content="\{\{ page\.title \| default: site\.title \}\}"/, 'an image alt printed raw');
  const dh = read('_includes/defang-head.html').replace(/\{%- comment -%\}[\s\S]*?\{%- endcomment -%\}/, '');
  assert.match(dh, /headline,name,description,alternativeHeadline/);
  assert.doesNotMatch(dh, /canonical|og:url|og:image"/, 'the include must not touch URLs');
});

test('the IOC viewer: the cell include and assets/js/ioc-table.js agree on which types are network values, and the table starts defanged', () => {
  const js = read('assets/js/ioc-table.js');
  const m = js.match(/var DEFANG_TYPES = \{([^}]*)\}/);
  const jsTypes = Array.from(m[1].matchAll(/(\w+):\s*true/g)).map((x) => x[1]).sort();
  const cell = read('_includes/ioc-cell.html');
  const net = Array.from(cell.match(/\{%- if _ic_t == "ipv4"([^%]*)%\}/)[0].matchAll(/_ic_t == "(\w+)"/g)).map((x) => x[1]).sort();
  assert.deepEqual(net, jsTypes);
  const lit = Array.from(cell.match(/\{%- elsif _ic_t == "sha256"([^%]*)%\}/)[0].matchAll(/_ic_t == "(\w+)"/g)).map((x) => x[1]).sort();
  assert.deepEqual(lit, ['filename', 'md5', 'path', 'registry', 'sha1', 'sha256']);
  const layout = read('_layouts/ioc-table.html');
  assert.match(layout, /data-act="defang" aria-pressed="true">Defanged<\/button>/);
  assert.equal(/<code>\{\{ r\.value \}\}<\/code>/.test(layout), false, 'no cell prints a raw value any more');
  assert.match(layout, /include ioc-cell\.html type=r\.type value=r\.value live=true/);
  assert.match(js, /var defanged = !defangEl \|\| defangEl\.getAttribute\('aria-pressed'\) !== 'false';/);
});

/* ---- Jekyll: the includes executed ---- */
function findJekyll() {
  const cands = [];
  const r = cp.spawnSync('sh', ['-c', 'command -v jekyll'], { encoding: 'utf8' });
  if (r.status === 0 && r.stdout.trim()) cands.push(r.stdout.trim());
  const g = path.join(os.homedir(), '.local', 'share', 'gem', 'ruby');
  if (fs.existsSync(g)) fs.readdirSync(g).forEach((v) => cands.push(path.join(g, v, 'bin', 'jekyll')));
  for (const c of cands) if (fs.existsSync(c)) { const v = cp.spawnSync(c, ['--version'], { encoding: 'utf8' }); if (!v.error && v.status === 0) return c; }
  return null;
}
const JEKYLL = findJekyll();

const TEXT_CASES = [
  ['C2 at 193.233.202.17 and evil-host.example.xyz, mail op@evil-host.example.xyz, fetch http://198.51.100.17:8080/p/a.exe. (203.0.113.9:443) done',
    'C2 at 193[.]233[.]202[.]17 and evil-host[.]example[.]xyz, mail op[@]evil-host[.]example[.]xyz, fetch hxxp://198[.]51[.]100[.]17:8080/p/a.exe. (203[.]0[.]113[.]9:443) done'],
  ['https://the-hunters-ledger.com/x attack.mitre.org ASP.NET intel@the-hunters-ledger.com', 'https://the-hunters-ledger.com/x attack.mitre.org ASP.NET intel@the-hunters-ledger.com'],
  ['ws://198.51.100.17:80/a wss://localhost/x ftp://u:p@a.b.example.org/f', 'ws://198[.]51[.]100[.]17:80/a wss://localhost/x fxp://u:p[@]a[.]b[.]example[.]org/f'],
  ['2001:db8::7 and ws://[2001:db8::7]:80/a and https://[2001:db8::7]/p', '2001[:]db8[:][:]7 and ws://[2001[:]db8[:][:]7]:80/a and hxxps://[2001[:]db8[:][:]7]/p'],
  ['1.2.3 e.g. cmd.exe C:\\foo\\bar.exe 01.2.3.4 300.1.1.1 v4.3.4', '1.2.3 e.g. cmd.exe C:\\foo\\bar.exe 01.2.3.4 300.1.1.1 v4.3.4'],
  ['evil[.]example[.]com hxxp://198[.]51[.]100[.]17/x op[@]evil[.]example[.]com', 'evil[.]example[.]com hxxp://198[.]51[.]100[.]17/x op[@]evil[.]example[.]com'],
  ['Toolkit-198.51.100.17-Repository .evil.example.org, [198.51.100.17] a_b.example.net node-v18.17.0-win-x64.zip', 'Toolkit-198[.]51[.]100[.]17-Repository .evil[.]example[.]org, [198[.]51[.]100[.]17] a_b[.]example[.]net node-v18[.]17[.]0-win-x64[.]zip'],
  ['ip=198.51.100.17&x=1 10.0.0.0/24 host.example.com:8443/x', 'ip=198[.]51[.]100[.]17&x=1 10[.]0[.]0[.]0/24 host[.]example[.]com:8443/x'],
  ['Shadow RAT v2.6.4.0 and V4.3.4.1, reference:url,https://github.com/[your-repo]/x, DownloadFile(http://45.94.31.220:8000/a.exe)', 'Shadow RAT v2[.]6[.]4[.]0 and V4[.]3[.]4[.]1, reference:url,hxxps://github[.]com/[your-repo]/x, DownloadFile(hxxp://45[.]94[.]31[.]220:8000/a.exe)'],
  ['*.evil.example.org and “evil.example.net” (38[.]180.16.98) logs.evil.example.org*', '*.evil[.]example[.]org and “evil[.]example[.]net” (38[.]180[.]16[.]98) logs[.]evil[.]example[.]org*'],
  ['tftp://198.51.100.17/x and atftp://x.example.org/y', 'tftp://198[.]51[.]100[.]17/x and atftp://x[.]example[.]org/y'],
  ['http://web.archive.org/web/2026/https://shinyhunte.rs/p', 'hxxp://web[.]archive[.]org/web/2026/hxxps://shinyhunte[.]rs/p'],
  ['  lead and trail  ', '  lead and trail  '],
  ['ends with newlines 198.51.100.17\n', 'ends with newlines 198[.]51[.]100[.]17\n'],
  ['GHOST Cryptojacker Kit: no indicator here.', 'GHOST Cryptojacker Kit: no indicator here.']
];

function buildSite(pageBody, extra) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-render-'));
  fs.mkdirSync(path.join(dir, 'src', '_includes'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'src', '_data'), { recursive: true });
  for (const f of ['defang-text.html', 'defang-html.html', 'ioc-cell.html']) fs.copyFileSync(path.join(root, '_includes', f), path.join(dir, 'src', '_includes', f));
  for (const f of ['defang_tlds.yml', 'defang_allow.yml']) fs.copyFileSync(path.join(root, '_data', f), path.join(dir, 'src', '_data', f));
  fs.writeFileSync(path.join(dir, 'src', '_config.yml'), 'baseurl: ""\nurl: "https://x.example"\nplugins: []\n');
  Object.keys(extra || {}).forEach((rel) => { fs.mkdirSync(path.dirname(path.join(dir, 'src', rel)), { recursive: true }); fs.writeFileSync(path.join(dir, 'src', rel), extra[rel]); });
  fs.writeFileSync(path.join(dir, 'src', 'index.html'), '---\nlayout: null\n---\n' + pageBody);
  const r = cp.spawnSync(JEKYLL, ['build', '-s', path.join(dir, 'src'), '-d', path.join(dir, 'out')], { encoding: 'utf8', timeout: 90000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  return { dir, out: path.join(dir, 'out'), html: fs.readFileSync(path.join(dir, 'out', 'index.html'), 'utf8') };
}
const cap = (s) => '{% capture t %}{% raw %}' + s + '{% endraw %}{% endcapture %}';

test('defang-text rendered by Jekyll: every form, the allow list, our mailbox, already-defanged words, embedded addresses, whitespace', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const body = TEXT_CASES.map((c, i) => cap(c[0]) + '<!--S' + i + '-->{% include defang-text.html text=t %}<!--E' + i + '-->').join('\n') +
    '\n' + cap('198.51.100.17') + '<!--Sa-->{% include defang-text.html text=t type="ipv4" %}<!--Ea-->' +
    '\n' + cap('https://a.example.org/p.php') + '<!--Sb-->{% include defang-text.html text=t type="url" %}<!--Eb-->' +
    '\n' + cap('op@a.example.org') + '<!--Sc-->{% include defang-text.html text=t type="email" %}<!--Ec-->' +
    '\n' + cap('ghost.sh') + '<!--Sd-->{% include defang-text.html text=t type="filename" %}<!--Ed-->' +
    '\n' + cap('http://web.archive.org/web/1/https://shinyhunte.rs/p') + '<!--Se-->{% include defang-text.html text=t type="url" %}<!--Ee-->';
  const { html } = buildSite(body);
  const got = (k) => html.split('<!--S' + k + '-->')[1].split('<!--E' + k + '-->')[0];
  TEXT_CASES.forEach((c, i) => assert.equal(got(i), c[1], 'case ' + i));
  assert.equal(got('a'), '198[.]51[.]100[.]17');
  assert.equal(got('b'), 'hxxps://a[.]example[.]org/p[.]php');
  assert.equal(got('c'), 'op[@]a[.]example[.]org');
  assert.equal(got('d'), 'ghost.sh', 'a type the viewer does not defang is returned as it is');
  assert.equal(got('e'), 'hxxp://web[.]archive[.]org/web/1/hxxps://shinyhunte[.]rs/p', 'a URL inside a URL is defanged as well');
});

const HTML_CASES = [
  ['<p>C2 at 193.233.202.17 and <code>evil-host.example.xyz</code></p>', '<p>C2 at 193[.]233[.]202[.]17 and <code>evil-host[.]example[.]xyz</code></p>'],
  ['<pre class="highlight"><code>rule x { $a = "198.51.100.17" }</code></pre><p>after 198.51.100.99</p>', '<pre class="highlight"><code>rule x { $a = "198.51.100.17" }</code></pre><p>after 198[.]51[.]100[.]99</p>'],
  ['<script>var a = "x.sh"; if (1<2) {}</script><p>1.2.3.4</p>', '<script>var a = "x.sh"; if (1<2) {}</script><p>1[.]2[.]3[.]4</p>'],
  ['<a href="https://attack.mitre.org/techniques/T1001/">attack.mitre.org</a>', '<a href="https://attack.mitre.org/techniques/T1001/">attack.mitre.org</a>'],
  ['<a href="http://198.51.100.17/x">http://198.51.100.17/x</a> and <a href="https://vendor.example.net/r">vendor.example.net post</a>', '<span class="hl-unlinked" data-unlinked="hxxp://198[.]51[.]100[.]17/x">hxxp://198[.]51[.]100[.]17/x</span> and <span class="hl-unlinked" data-unlinked="hxxps://vendor[.]example[.]net/r">vendor[.]example[.]net post</span>'],
  ['<a href="/actors/UTA-2026-001/">198.51.100.17</a> <a href="#x">1.2.3.4</a>', '<a href="/actors/UTA-2026-001/">198[.]51[.]100[.]17</a> <a href="#x">1[.]2[.]3[.]4</a>'],
  ['<a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a> <a href="mailto:op@evil.example.xyz">op@evil.example.xyz</a>', '<a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a> <span class="hl-unlinked" data-unlinked="mailto:op[@]evil[.]example[.]xyz">op[@]evil[.]example[.]xyz</span>'],
  ['<a href="javascript:void(0)">js 1.2.3.4</a>', '<span class="hl-unlinked" data-unlinked="javascript:void(0)">js 1[.]2[.]3[.]4</span>'],
  ['<a href="https://www.linkedin.com/in/josephrharrison">linkedin.com/in/josephrharrison</a> <a href="https://www.linkedin.com/in/josephrharrison">LinkedIn linkedin.com/x</a>', '<a href="https://www.linkedin.com/in/josephrharrison">linkedin.com/in/josephrharrison</a> <a href="https://www.linkedin.com/in/josephrharrison">LinkedIn linkedin[.]com/x</a>'],
  ['<span title="via openvpn.learn-address.sh and 198.51.100.17" data-title="openvpn.learn-address.sh">a</span> <a href="/x/" aria-label="see evil.example.org">go</a>', '<span title="via openvpn[.]learn-address[.]sh and 198[.]51[.]100[.]17" data-title="openvpn.learn-address.sh">a</span> <a href="/x/" aria-label="see evil[.]example[.]org">go</a>'],
  ['<p><b>Campaign:</b> x-198.51.100.17\n<b>Date:</b> 2026 and 1.2.3.4\n\n<i>z</i> 5.6.7.8 \n</p>', '<p><b>Campaign:</b> x-198[.]51[.]100[.]17\n<b>Date:</b> 2026 and 1[.]2[.]3[.]4\n\n<i>z</i> 5[.]6[.]7[.]8 \n</p>'],
  ['<code data-literal="filename">ghost.sh</code> <code>ghost.sh</code>', '<code data-literal="filename">ghost.sh</code> <code>ghost[.]sh</code>']
];

test('defang-html rendered by Jekyll: text defanged, pre and script untouched, an off-site link kept only when listed, otherwise a span; tooltips and data-literal', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const body = HTML_CASES.map((c, i) => '{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}<!--S' + i + '-->{% include defang-html.html html=h %}<!--E' + i + '-->').join('\n') +
    '\n{% capture h %}{% raw %}<a href="https://vendor.example.net/r">vendor.example.net</a> <a href="http://198.51.100.17/x">x</a>{% endraw %}{% endcapture %}<!--Sw-->{% include defang-html.html html=h unlink=false %}<!--Ew-->';
  const { html } = buildSite(body);
  const got = (k) => html.split('<!--S' + k + '-->')[1].split('<!--E' + k + '-->')[0];
  HTML_CASES.forEach((c, i) => assert.equal(got(i), c[1], 'case ' + i));
  assert.equal(got('w'), '<a href="https://vendor.example.net/r">vendor.example.net</a> <a href="http://198.51.100.17/x">x</a>', 'unlink=false (the Wire) keeps every link and the label that is its own host');
});

test('the rendered-page gate agrees with the includes: what they print is clean, the same page without them FAILs (control), and the gate\'s own self-test passes', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  assert.deepEqual(S.selfTest(), []);
  const raw = TEXT_CASES.filter((c) => c[0] !== c[1]).map((c) => c[0]).join(' ');
  const html = '<p>' + raw.replace(/&amp;/g, '&').replace(/&/g, '&amp;') + '</p><a href="http://198.51.100.17/x">go</a>';
  const defd = '{% capture h %}{% raw %}' + html + '{% endraw %}{% endcapture %}{% include defang-html.html html=h %}';
  const bare = '{% raw %}' + html + '{% endraw %}';
  const run = (out) => cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'check-defang.js'), '--site', out, '--allow-data', path.join(root, '_data', 'defang_allow.yml'), '--all'], { encoding: 'utf8' });
  const good = buildSite(defd), ctl = buildSite(bare);
  const g = run(good.out), c = run(ctl.out);
  assert.equal(g.status, 0, g.stdout);
  assert.match(g.stdout, /^PASS /m);
  assert.equal(c.status, 1, 'the control (the same markup, no include) must FAIL the gate');
  for (const kind of ['IPV4', 'DOMAIN', 'EMAIL', 'URL', 'LINK-IP']) assert.match(c.stdout, new RegExp('FINDING .* ' + kind + ' '), 'control: ' + kind + ' is reported');
});

/* ---- the gate on a fixture site (no Jekyll needed) ---- */
function fixtureSite(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-site-'));
  Object.keys(files).forEach((rel) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), '<html><head><title>1[.]2[.]3[.]4 head metadata is scanned</title></head><body><main>' + files[rel] + '<p>fixture text</p></main></body></html>'); });
  return dir;
}
const gate = (dir, extra) => cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'check-defang.js'), '--site', dir, '--allow-data', path.join(root, '_data', 'defang_allow.yml'), '--all'].concat(extra || []), { encoding: 'utf8' });

test('check-defang --site: a clean fixture PASSes with its denominators, each injected raw indicator FAILs with its kind (the control that fires), exit codes 0 / 1 / 2', () => {
  const clean = fixtureSite({ 'index.html': '<p>Host 198[.]51[.]100[.]17 and <a href="/actors/UTA-2026-001/">198[.]51[.]100[.]17</a> and <a href="https://attack.mitre.org/techniques/T1001/">attack.mitre.org</a></p>',
    'hunting-detections/x-detections/index.html': '<p>prose 198[.]51[.]100[.]17</p><pre>rule a { 198.51.100.17 }</pre>',
    'wire/index.html': '<a href="https://vendor.example.net/post">vendor.example.net</a>' });
  const ok = gate(clean);
  assert.equal(ok.status, 0, ok.stdout);
  assert.match(ok.stdout, /pages\s+3 scanned/);
  assert.match(ok.stdout, /pre\s+1 blocks, 1 lines: 1 on detection pages kept exact \(1 raw indicator token\(s\) inside/);
  assert.match(ok.stdout, /^PASS /m);
  const cases = [
    ['<p>Host 198.51.100.17</p>', 'IPV4'], ['<p>evil.example.xyz</p>', 'DOMAIN'], ['<p>op@evil.example.xyz</p>', 'EMAIL'], ['<p>http://198.51.100.17/p</p>', 'URL'],
    ['<p title="198.51.100.17">x</p>', 'IPV4'], ['<a href="http://198.51.100.17/x">go</a>', 'LINK-IP'], ['<a href="https://unlisted.example.net/x">go</a>', 'LINK-UNLISTED'],
    ['<a href="mailto:op@evil.example.xyz">m</a>', 'LINK-MAILTO'], ['<pre>198.51.100.20</pre>', 'PRE-OUTSIDE-DETECTION'],
    ['<code data-literal="sha256">198.51.100.17</code>', 'LITERAL-MISUSE'], ['<code data-literal="filename">http://198.51.100.17/a</code>', 'LITERAL-MISUSE'], ['<code data-literal="sha256">notahash</code>', 'LITERAL-MISUSE'], ['<code data-literal="pattern">x</code>', 'LITERAL-MISUSE']
  ];
  cases.forEach(([html, kind]) => {
    const r = gate(fixtureSite({ 'index.html': html }));
    assert.equal(r.status, 1, kind + ' must FAIL: ' + r.stdout);
    assert.match(r.stdout, new RegExp('FINDING .* ' + kind + ' '), kind);
  });
  // a literal cell is honoured for its own six types
  const lit = gate(fixtureSite({ 'index.html': '<code data-literal="filename">ghost.sh</code> <code data-literal="sha256">' + 'a'.repeat(64) + '</code>' }));
  assert.equal(lit.status, 0, lit.stdout);
  assert.match(lit.stdout, /literal\s+2 IOC viewer cell/);
  // working docs and changelogs are excluded and said so; a report page is SCANNED (T-0500.1.7.4 ship: it is no longer excluded)
  const ex = gate(fixtureSite({ 'index.html': '<p>x</p>', 'report-templates/index.html': '198.51.100.17', 'feeds/misp/changelog/index.html': '198.51.100.17' }));
  assert.equal(ex.status, 0, ex.stdout);
  assert.match(ex.stdout, /excluded\s+1 feed changelog \(decision 7\); 1 working doc \(decision 7\)/);
  assert.doesNotMatch(ex.stdout, /report page \(source lint\)/);
  // report pages: a raw title, a raw citation, a raw BibTeX block, a link to an IP and a link to a host the page names defanged each FAIL; the clean twin PASSes
  const REP_OK = '<h1>Open Directory 198[.]51[.]100[.]17</h1><p class="hl-cite__text">Harrison, J. <em>Open Directory 198[.]51[.]100[.]17</em>. https://the-hunters-ledger.com/reports/x-198.51.100.17/</p>' +
    '<pre><code>title = {Open Directory 198[.]51[.]100[.]17}</code></pre><pre class="hl-copy">rule x { 198.51.100.17 }</pre><p>C2 evil-host[.]example[.]xyz; see <a href="https://vendor.example.net/r">the vendor</a>.</p>';
  const repGood = gate(fixtureSite({ 'index.html': '<p>x</p>', 'reports/a/index.html': REP_OK }));
  assert.equal(repGood.status, 0, repGood.stdout);
  assert.match(repGood.stdout, /pages\s+2 scanned: .*report 1/);
  const repCases = { 'raw title': ['<h1>Open Directory 198[.]51[.]100[.]17</h1>', '<h1>Open Directory 198.51.100.17</h1>', 'IPV4'],
    'raw citation': ['<em>Open Directory 198[.]51[.]100[.]17</em>', '<em>Open Directory 198.51.100.17</em>', 'IPV4'],
    'raw BibTeX': ['title = {Open Directory 198[.]51[.]100[.]17}', 'title = {Open Directory 198.51.100.17}', 'PRE-IN-REPORT'],
    'link to a host the page names defanged': ['see <a href="https://vendor.example.net/r">', 'see <a href="https://evil-host.example.xyz/x">', 'LINK-ACTOR-HOST'],
    'link to an IP': ['see <a href="https://vendor.example.net/r">', 'see <a href="http://198.51.100.17/x">', 'LINK-IP'] };
  Object.keys(repCases).forEach((name) => {
    const c = repCases[name];
    assert.ok(REP_OK.includes(c[0]), name + ': the control must change something');
    const r = gate(fixtureSite({ 'index.html': '<p>x</p>', 'reports/a/index.html': REP_OK.replace(c[0], c[1]) }));
    assert.equal(r.status, 1, name + ' must FAIL: ' + r.stdout);
    assert.match(r.stdout, new RegExp('FINDING .* ' + c[2] + ' '), name);
  });
  // the include's own output is counted and listed, never silent: an <a> rendered as text shows in the gate output with its defanged target
  const un = gate(fixtureSite({ 'index.html': '<span class="hl-unlinked" data-unlinked="hxxps://vendor[.]example[.]net/r">vendor[.]example[.]net</span>' }));
  assert.equal(un.status, 0, un.stdout);
  assert.match(un.stdout, /unlinked\s+1 <a> rendered as text/);
  assert.match(un.stdout, /index\.html -> hxxps:\/\/vendor\[\.\]example\[\.\]net\/r/);
  // the <head> display strings: a raw tab title, og:title, description and JSON-LD headline each FAIL on any page type; the page's own URLs in the head do not
  const headPage = (title, meta, ld) => '<html><head><title>' + title + '</title>' + meta + '<link rel="canonical" href="https://the-hunters-ledger.com/actors/x-198.51.100.17/"><script type="application/ld+json">' + ld + '</script></head><body><main><p>x</p></main></body></html>';
  const LDOK = '{"@context":"https://schema.org","headline":"Op 198[.]51[.]100[.]17","url":"https://the-hunters-ledger.com/actors/x-198.51.100.17/"}';
  const MOK = '<meta property="og:title" content="Op 198[.]51[.]100[.]17"><meta name="description" content="d">';
  const mk = (rel, html) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-head-')); fs.mkdirSync(path.join(d, path.dirname(rel)), { recursive: true }); fs.writeFileSync(path.join(d, rel), html); return d; };
  const headOk = gate(mk('actors/a/index.html', headPage('Op 198[.]51[.]100[.]17', MOK, LDOK)));
  assert.equal(headOk.status, 0, headOk.stdout);
  assert.match(headOk.stdout, /^  head\s+\d+ <head> display strings scanned/m);
  const headCases = { 'raw <title>': [headPage('Op 198.51.100.17', MOK, LDOK), 'HEAD-IPV4'], 'raw og:title': [headPage('Op 198[.]51[.]100[.]17', MOK.replace('Op 198[.]51[.]100[.]17', 'Op 198.51.100.17'), LDOK), 'HEAD-IPV4'],
    'raw description': [headPage('t', MOK.replace('content="d"', 'content="C2 evil-host.example.xyz"'), LDOK), 'HEAD-DOMAIN'], 'raw JSON-LD headline': [headPage('t', MOK, LDOK.replace('Op 198[.]51[.]100[.]17', 'Op 198.51.100.17')), 'HEAD-IPV4'] };
  ['actors/a/index.html', 'reports/b/index.html', 'hunting-detections/c/index.html', 'index.html'].forEach((rel) => Object.keys(headCases).forEach((name) => {
    const r = gate(mk(rel, headCases[name][0]));
    assert.equal(r.status, 1, name + ' on ' + rel + ' must FAIL: ' + r.stdout);
    assert.match(r.stdout, new RegExp('FINDING .* ' + headCases[name][1] + ' '), name);
  }));
  // our own mailbox is allowed, a foreign one is not
  assert.equal(gate(fixtureSite({ 'index.html': '<a href="mailto:intel@the-hunters-ledger.com">intel@the-hunters-ledger.com</a>' })).status, 0);
  // zero denominator and a missing directory are NOT CHECKED (exit 2), never PASS
  assert.equal(gate(fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-empty-'))).status, 2);
  assert.equal(gate(path.join(os.tmpdir(), 'hl-no-such-dir-' + process.pid)).status, 2);
});

test('check-defang --site: the rendered check prints its denominators and what it cannot see', () => {
  const r = gate(fixtureSite({ 'index.html': '<p>nothing here</p>' }));
  assert.equal(r.status, 0);
  for (const label of ['self-test', 'allow data', 'pages', 'excluded', 'text', 'indicators', 'links', 'pre', 'literal']) assert.match(r.stdout, new RegExp('^  ' + label + '\\s', 'm'), label);
  assert.match(r.stdout, /CANNOT SEE: text a script writes after load; the data-title search keys/);
});
