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
  assert.match(page, /\{% elsif page\.url contains '\/changelog\/' %\}\{\{ content \}\}\{% else %\}\{% include defang-html\.html html=content %\}\{% endif %\}/, 'the working docs keep their text (decision 7)');
  const post = read('_layouts/post.html');
  assert.match(post, /\{% if page\.path contains 'hunting-detections' %\}\{% include defang-html\.html html=content %\}\{% else %\}\{\{ _body \}\}\{% endif %\}/, 'a report body is never run through the defang include; _body is content with an anchor id added to its ATT&CK heading (T-0603 A2)');
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
  // fix-r1 (review finding 2): no button, no live value; a note says the table is defanged and where the exact values are
  assert.equal(/data-act="defang"|btn--toggle/.test(layout), false, 'no Defanged/Live button');
  assert.equal(/data-live|live=true/.test(layout + cell), false, 'no live value kept in the markup');
  assert.match(layout, /class="hl-ioctable__note">Values are shown defanged[^<]*<a href="\{\{ t\.feed_url \| relative_url \}\}">raw JSON<\/a>/);
  assert.equal(/<code>\{\{ r\.value \}\}<\/code>/.test(layout), false, 'no cell prints a raw value any more');
  assert.match(layout, /include ioc-cell\.html type=r\.type value=r\.value %\}/);
  assert.equal(/var defanged\b|applyDefang|data-live/.test(js), false, 'the script has no toggle state and keeps no live value');
  assert.match(js, /return DEFANG_TYPES\[type\] \? defang\(c\.textContent, type\) : c\.textContent;/);
});

test('IOC viewer rows: every data-* attribute the CSV export reads goes through the text defang (fix-r1 sweep: data-fp carried an address and shared-service names raw)', () => {
  const layout = read('_layouts/ioc-table.html');
  for (const [attrName, field] of [['data-context', 'context'], ['data-confidence', 'confidence'], ['data-action', 'action'], ['data-fp', 'fp_risk']]) {
    assert.match(layout, new RegExp('capture _\\w+ %\\}\\{% include defang-text\\.html text=r\\.' + field + ' %\\}\\{% endcapture %\\} ' + attrName + '="\\{\\{ _\\w+ \\| escape \\}\\}"'), attrName + ' is written from a defanged capture');
  }
  assert.equal(/data-(?:confidence|action|fp)="\{\{ r\./.test(layout), false, 'no data-* attribute is written from the raw field');
  assert.equal(/title="\{\{ r\.action/.test(layout), false, 'the action tooltip is not the raw field');
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
  /* T-0589: a part with a leading zero is not an address on either side (the Barracuda ESG version 9.4.0.030 broke the Wire build); 9.4.0.30 is one */
  ['Barracuda ESG 9.4.0.030 and 9.4.0.00 but 9.4.0.30', 'Barracuda ESG 9.4.0.030 and 9.4.0.00 but 9[.]4[.]0[.]30'],
  ['GHOST Cryptojacker Kit: no indicator here.', 'GHOST Cryptojacker Kit: no indicator here.']
];

function buildSite(pageBody, extra) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-render-'));
  fs.mkdirSync(path.join(dir, 'src', '_includes'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'src', '_data'), { recursive: true });
  for (const f of ['defang-text.html', 'defang-html.html', 'defang-head.html', 'ioc-cell.html']) fs.copyFileSync(path.join(root, '_includes', f), path.join(dir, 'src', '_includes', f));
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

test('ioc-cell: a filename, path or registry value that names a host or an address is defanged, not literal; every other literal value is kept exactly (fix-r1, browser gate)', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const CASES = [
    ['path', '\\\\evil-host.example.xyz\\share\\a.exe', '\\\\evil-host[.]example[.]xyz\\share\\a.exe'],
    ['filename', '1468_US_198.51.100.17_28-01-26.cab', '1468_US_198[.]51[.]100[.]17_28-01-26[.]cab'],
    ['path', 'http://evil-host.example.xyz/a', 'hxxp://evil-host[.]example[.]xyz/a'],
    ['filename', 'ghost.sh', null], ['path', '/tmp/oraq.py', null], ['path', 'C:\\Users\\x\\a.exe', null], ['registry', 'HKLM\\SOFTWARE\\Microsoft\\x', null], ['sha256', 'a'.repeat(64), null]
  ];
  const body = CASES.map((c, i) => '<!--S' + i + '-->{% include ioc-cell.html type="' + c[0] + '" value="' + c[1].replace(/\\/g, '\\') + '" %}<!--E' + i + '-->').join('\n');
  const { html } = buildSite(body);
  CASES.forEach((c, i) => {
    const got = html.split('<!--S' + i + '-->')[1].split('<!--E' + i + '-->')[0];
    if (c[2] === null) assert.equal(got, '<code data-literal="' + c[0] + '">' + c[1] + '</code>', 'literal kept: ' + c[1]);
    else assert.equal(got, '<code>' + c[2] + '</code>', 'defanged: ' + c[1]);
  });
});

test('the rendered-page gate agrees with the includes: what they print is clean, the same page without them FAILs (control), and the gate\'s own self-test passes', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  assert.deepEqual(S.selfTest(), []);
  const raw = TEXT_CASES.filter((c) => c[0] !== c[1]).map((c) => c[0]).join(' ');
  const html = '<p>' + raw.replace(/&amp;/g, '&').replace(/&/g, '&amp;') + '</p><a href="http://198.51.100.17/x">go</a>';
  const defd = '{% capture h %}{% raw %}' + html + '{% endraw %}{% endcapture %}{% include defang-html.html html=h %}';
  const bare = '{% raw %}' + html + '{% endraw %}';
  const run = (out) => cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'check-defang.js'), '--site', out, '--allow-data', path.join(root, '_data', 'defang_allow.yml'), '--all', '--pages-only'], { encoding: 'utf8' });
  const good = buildSite(defd), ctl = buildSite(bare);
  const g = run(good.out), c = run(ctl.out);
  assert.equal(g.status, 0, g.stdout);
  assert.match(g.stdout, /^PASS /m);
  assert.equal(c.status, 1, 'the control (the same markup, no include) must FAIL the gate');
  for (const kind of ['IPV4', 'DOMAIN', 'EMAIL', 'URL', 'LINK-IP']) assert.match(c.stdout, new RegExp('FINDING .* ' + kind + ' '), 'control: ' + kind + ' is reported');
});

/* ---- T-0500.1.7.4 review round 2 (lane A): the reviewer's reproductions T1 to T5, each a failing-then-passing case ---- */
const R2_TEXT = [
  // T2/T4: IPv6 in running text, compressed forms that end in "::", a prefix length, a bracketed literal with a port, trailing punctuation
  ['seen 2001:db8:1:: and fe80::1 and ::1 here', 'seen 2001[:]db8[:]1[:][:] and fe80[:][:]1 and [:][:]1 here'],
  ['2001:db8::7 2001:db8:: 2001:db8:1:2:3:4:5:6', '2001[:]db8[:][:]7 2001[:]db8[:][:] 2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6'],
  ['Seen at 2001:db8:1:2:3:4:5:6. Then 2001:db8::.', 'Seen at 2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6. Then 2001[:]db8[:][:].'],
  ['net 2001:db8::/32 and [2001:db8::1]:443 and (2001:db8::1).', 'net 2001[:]db8[:][:]/32 and [2001[:]db8[:][:]1]:443 and (2001[:]db8[:][:]1).'],
  // what is not an address stays as written
  ['Add::Bad std::vector 10:30:45 aa:bb:cc:dd:ee:ff Note: ok', 'Add::Bad std::vector 10:30:45 aa:bb:cc:dd:ee:ff Note: ok'],
  // T5: a half-defanged word is finished from scratch, never skipped, never double-bracketed
  ['op[@]actor-domain.com', 'op[@]actor-domain[.]com'],
  ['mail op[@]a-b.example.org, or op@c[.]example.net now', 'mail op[@]a-b[.]example[.]org, or op[@]c[.]example[.]net now'],
  ['2001[:]db8::7 and host[:]8080', '2001[:]db8[:][:]7 and host[:]8080'],
  ['op[@]actor-domain[.]com 2001[:]db8[:][:]7', 'op[@]actor-domain[.]com 2001[:]db8[:][:]7'],
  // host:port in free text (lane B found the viewer script leaves it raw; the includes defang the host and keep the port)
  ['beacon evil.example.xyz:443 and (evil.example.xyz:80) 198.51.100.17:8080 sub.evil.example.xyz:443.', 'beacon evil[.]example[.]xyz:443 and (evil[.]example[.]xyz:80) 198[.]51[.]100[.]17:8080 sub[.]evil[.]example[.]xyz:443.']
];
const R2_HTML = [
  // T3: an anchor to an actor address is no link in either quote style, unquoted, upper case, with spaces around "=", or broken over lines
  ["<a href='https://198.51.100.17/'>Actor host</a>", '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/">Actor host</span>'],
  ['<a href="https://198.51.100.17/">Actor host</a>', '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/">Actor host</span>'],
  ['<a href=https://198.51.100.18/>unq</a> <a href=/reports/>own</a>', '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]18/">unq</span> <a href=/reports/>own</a>'],
  ["<A HREF='https://198.51.100.17/'>x</A> <a HREF = 'https://198.51.100.18/' >y</a>", '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/">x</span> <span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]18/">y</span>'],
  ['<a href = "https://198.51.100.17/">z</a>', '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/">z</span>'],
  ["<a\n href='https://198.51.100.17/'\n class=\"x\">ml</a>", '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/">ml</span>'],
  // fail closed: an "href=" written inside another attribute, an entity-written scheme, a quote in the target
  ['<a title="see href=https://198.51.100.17/" href="/reports/">t</a>', '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/&quot;" title="see href=hxxps://198[.]51[.]100[.]17/">t</span>'],
  ['<a href="&#104;ttp://198.51.100.17/">e</a>', '<span class="hl-unlinked" data-unlinked="&#104;ttp://198[.]51[.]100[.]17/">e</span>'],
  // the allow list and our own pages are unaffected by the quote style
  ["<a href='https://attack.mitre.org/techniques/T1001/'>mitre</a> <a href='/reports/'>own</a>", "<a href='https://attack.mitre.org/techniques/T1001/'>mitre</a> <a href='/reports/'>own</a>"],
  // T2/T4: IPv6 in a code element, in text, and in title / alt / aria-label tooltips of either quote style
  ['<code>2001:db8::</code> <code>2001:db8::7</code> <p>net 2001:db8::/32</p>', '<code>2001[:]db8[:][:]</code> <code>2001[:]db8[:][:]7</code> <p>net 2001[:]db8[:][:]/32</p>'],
  ['<span title="2001:db8:1:2:3:4:5:6">Hover</span>', '<span title="2001[:]db8[:]1[:]2[:]3[:]4[:]5[:]6">Hover</span>'],
  ["<span title='2001:db8::7 and 198.51.100.17'>Hover</span>", "<span title='2001[:]db8[:][:]7 and 198[.]51[.]100[.]17'>Hover</span>"],
  ['<img alt="host 2001:db8::7" src="/a.png"> <a href="/x/" aria-label="v6 2001:db8::1">go</a>', '<img alt="host 2001[:]db8[:][:]7" src="/a.png"> <a href="/x/" aria-label="v6 2001[:]db8[:][:]1">go</a>']
];
const R2_HEAD = [
  // T1: a JSON string with escaped quotes is defanged to its closing quote; an own-page URL stays exact; the escapes are kept as written
  ['{"headline":"Campaign \\"Blue\\" at 198.51.100.17","url":"https://the-hunters-ledger.com/reports/198.51.100.17/"}', '{"headline":"Campaign \\"Blue\\" at 198[.]51[.]100[.]17","url":"https://the-hunters-ledger.com/reports/198.51.100.17/"}'],
  ['{"name": "A \\"q\\" 198.51.100.17", "description": "d \\\\ 198.51.100.18 and \\"z\\" 198.51.100.19", "url": "https://the-hunters-ledger.com/x/"}', '{"name": "A \\"q\\" 198[.]51[.]100[.]17", "description": "d \\\\ 198[.]51[.]100[.]18 and \\"z\\" 198[.]51[.]100[.]19", "url": "https://the-hunters-ledger.com/x/"}'],
  ['{"headline":"plain 198.51.100.17","description":"two 198.51.100.18 values 198.51.100.19"}', '{"headline":"plain 198[.]51[.]100[.]17","description":"two 198[.]51[.]100[.]18 values 198[.]51[.]100[.]19"}'],
  ['{"headline":"v6 2001:db8::7 \\"q\\" 2001:db8::"}', '{"headline":"v6 2001[:]db8[:][:]7 \\"q\\" 2001[:]db8[:][:]"}']
];

test('review round 2, T1-T5: escaped-quote JSON-LD, IPv6 in text, code and tooltips, single-quoted and other anchor forms, half-defanged words (reviewer reproductions)', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const body = R2_TEXT.map((c, i) => cap(c[0]) + '<!--T' + i + '-->{% include defang-text.html text=t %}<!--U' + i + '-->').join('\n') + '\n' +
    R2_HTML.map((c, i) => '{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}<!--H' + i + '-->{% include defang-html.html html=h %}<!--I' + i + '-->').join('\n') + '\n' +
    R2_HEAD.map((c, i) => '{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}<!--J' + i + '-->{% include defang-head.html text=h %}<!--K' + i + '-->').join('\n') + '\n' +
    cap('2001:db8::7') + '<!--V0-->{% include defang-text.html text=t type="ipv6" %}<!--W0-->\n' +
    cap('http://[2001:db8::7]:80/p') + '<!--V1-->{% include defang-text.html text=t type="url" %}<!--W1-->\n' +
    cap('[2001:db8::7]:443') + '<!--V2-->{% include defang-text.html text=t type="endpoint" %}<!--W2-->\n' +
    cap('[2001:db8::7]:443') + '<!--V4-->{% include defang-text.html text=t type="ipv6" %}<!--W4-->\n' + cap('::ffff:192.0.2.1') + '<!--V5-->{% include defang-text.html text=t type="ipv6" %}<!--W5-->\n' +
    '<!--V3-->{% include ioc-cell.html type="ipv6" value="2001:db8::" %}<!--W3-->';
  const { html } = buildSite(body);
  const got = (a, k) => html.split('<!--' + a + k + '-->')[1].split('<!--' + String.fromCharCode(a.charCodeAt(0) + 1) + k + '-->')[0].replace(/\n$/, '');
  R2_TEXT.forEach((c, i) => assert.equal(got('T', i), c[1], 'text case ' + i));
  R2_HTML.forEach((c, i) => assert.equal(got('H', i), c[1], 'html case ' + i));
  R2_HEAD.forEach((c, i) => assert.equal(got('J', i), c[1], 'head case ' + i));
  assert.equal(got('V', 0), '2001[:]db8[:][:]7', 'a typed ipv6 value');
  assert.equal(got('V', 1), 'hxxp://[2001[:]db8[:][:]7]:80/p', 'a typed url with a bracketed IPv6 host');
  assert.equal(got('V', 2), '[2001[:]db8[:][:]7]:443', 'a typed endpoint with a bracketed IPv6 host');
  assert.equal(got('V', 3), '<code>2001[:]db8[:][:]</code>', 'an ipv6 viewer cell');
  assert.equal(got('V', 4), '[2001[:]db8[:][:]7]:443', 'a typed ipv6 value with a port: only the address loses its colons (the form assets/js/ioc-table.js writes)');
  assert.equal(got('V', 5), '[:][:]ffff[:]192[.]0[.]2[.]1', 'an IPv4-mapped address');
});

/* ---- T-0500.1.7.6 P1: the seven findings of review_5cfea0f481014885 (1-5) and review_731d8e368b194a90 (6-7), each a failing-then-passing case against this include ---- */
const JSDOM = require('jsdom').JSDOM;

test('P1 finding 1: an href that only looks relative ("/\\198.51.100.17/x") is unlinked, because the URL parser reads the backslash as a separator and resolves the address as the host', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const body = '<!--L0-->{% capture h %}{% raw %}<a href="/\\198.51.100.17/x">actor</a> <a href="/reports/">own</a>{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--M0-->';
  const { html } = buildSite(body);
  const got = html.split('<!--L0-->')[1].split('<!--M0-->')[0].replace(/^\n/, '').replace(/\n$/, '');
  // what a browser does with what the include prints: the reviewer resolved the old anchor to https://198.51.100.17/x
  const dom = new JSDOM('<!doctype html><html><body>' + got + '</body></html>', { url: 'https://the-hunters-ledger.com/actors/UTA-2026-001/' });
  const links = Array.from(dom.window.document.querySelectorAll('a[href]')).map((a) => a.href);
  assert.deepEqual(links.filter((h) => h.includes('198.51.100.17')), [], 'no anchor resolves to the actor address; the page resolved ' + JSON.stringify(links));
  assert.deepEqual(links, ['https://the-hunters-ledger.com/reports/'], 'control: the own-page link is still a link');
  assert.equal(got, '<span class="hl-unlinked" data-unlinked="/\\198[.]51[.]100[.]17/x">actor</span> <a href="/reports/">own</a>', 'the address is text, its target defanged');
  // the rendered-page gate sees the lost link and reports it, instead of a link it never looked at
  const g = gate(fixtureSite({ 'actors/x/index.html': got }));
  assert.equal(g.status, 0, g.stdout);
  assert.match(g.stdout, /unlinked\s+1 <a> rendered as text/);
});

test('P1 finding 2: every spelling a browser accepts for a reader-facing attribute is defanged (spaces around "=", upper case, no quote, an input\'s displayed value); a search key stays as written', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const CASES = [
    ['<p title="198.51.100.17">control</p>', '<p title="198[.]51[.]100[.]17">control</p>'],
    ['<p title = "198.51.100.17">spaced</p>', '<p title = "198[.]51[.]100[.]17">spaced</p>'],
    ['<p TITLE="198.51.100.17">upper</p>', '<p TITLE="198[.]51[.]100[.]17">upper</p>'],
    ['<p title=198.51.100.17>unq</p>', '<p title=198[.]51[.]100[.]17>unq</p>'],
    ["<p title = '198.51.100.17'>single</p>", "<p title = '198[.]51[.]100[.]17'>single</p>"],
    ['<img alt="host 198.51.100.17" src="/a.png">', '<img alt="host 198[.]51[.]100[.]17" src="/a.png">'],
    ['<span data-copy="198.51.100.17">x</span>', '<span data-copy="198[.]51[.]100[.]17">x</span>'],
    ['<input value="198.51.100.17">', '<input value="198[.]51[.]100[.]17">'],
    ['<input type="search" value="198.51.100.17">', '<input type="search" value="198[.]51[.]100[.]17">'],
    // controls: what is not displayed or not reader-facing keeps its characters
    ['<input type="hidden" value="198.51.100.17">', '<input type="hidden" value="198.51.100.17">'],
    ['<p data-title="198.51.100.17">search key</p>', '<p data-title="198.51.100.17">search key</p>'],
    ['<p class="x-198.51.100.17">class</p>', '<p class="x-198.51.100.17">class</p>'],
    ['<p title="no indicator here">plain</p>', '<p title="no indicator here">plain</p>'],
    // a tag with more attributes than the walk's steps is copied whole, never cut short
    ['<p title="no indicator here" a1="x" a2="x" a3="x" a4="x" a5="x" a6="x" a7="x" a8="x" a9="x" a10="x" a11="x" a12="x" a13="x" a14="x" a15="x" a16="x" a17="x" a18="x" a19="x" a20="x" a21="x" a22="x" a23="x" a24="x" a25="x" a26="x" a27="x" a28="x" a29="x" a30="x" a31="x" a32="x" a33="x" a34="x" a35="x" a36="x" a37="x" a38="x" a39="x" a40="x" a41="x" a42="x" a43="x" a44="x" a45="x">long</p>', '<p title="no indicator here" a1="x" a2="x" a3="x" a4="x" a5="x" a6="x" a7="x" a8="x" a9="x" a10="x" a11="x" a12="x" a13="x" a14="x" a15="x" a16="x" a17="x" a18="x" a19="x" a20="x" a21="x" a22="x" a23="x" a24="x" a25="x" a26="x" a27="x" a28="x" a29="x" a30="x" a31="x" a32="x" a33="x" a34="x" a35="x" a36="x" a37="x" a38="x" a39="x" a40="x" a41="x" a42="x" a43="x" a44="x" a45="x">long</p>']
  ];
  const body = CASES.map((c, i) => '<!--N' + i + '-->{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--O' + i + '-->').join('\n');
  const { html } = buildSite(body);
  CASES.forEach((c, i) => assert.equal(html.split('<!--N' + i + '-->')[1].split('<!--O' + i + '-->')[0].replace(/^\n/, '').replace(/\n$/, ''), c[1], 'case ' + i));
});

test('P1 finding 5: unlinking an actor anchor keeps the reader-facing parts of it (id, title tooltip), so a reference loses its target and not its context', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const CASES = [
    ["<a href='https://198.51.100.17/' title='Context the reader could hover' id='reference'>Actor host</a>",
      '<span class="hl-unlinked" data-unlinked="hxxps://198[.]51[.]100[.]17/" id="reference" title="Context the reader could hover">Actor host</span>'],
    // the tooltip is defanged by the same walk it would get on a kept anchor
    ['<a href="http://198.51.100.17/x" title="C2 at 198.51.100.17" id="ref-2">host</a>',
      '<span class="hl-unlinked" data-unlinked="hxxp://198[.]51[.]100[.]17/x" id="ref-2" title="C2 at 198[.]51[.]100[.]17">host</span>'],
    // controls: an anchor with no id or title gains neither; a kept anchor is unchanged, attributes in the order it wrote them
    ['<a href="https://vendor.example.net/r">vendor</a>', '<span class="hl-unlinked" data-unlinked="hxxps://vendor[.]example[.]net/r">vendor</span>'],
    ["<a href='https://attack.mitre.org/techniques/T1001/' title='Context' id='mitre'>mitre</a>", "<a href='https://attack.mitre.org/techniques/T1001/' title='Context' id='mitre'>mitre</a>"]
  ];
  const body = CASES.map((c, i) => '<!--P' + i + '-->{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--Q' + i + '-->').join('\n');
  const { html } = buildSite(body);
  CASES.forEach((c, i) => assert.equal(html.split('<!--P' + i + '-->')[1].split('<!--Q' + i + '-->')[0].replace(/^\n/, '').replace(/\n$/, ''), c[1], 'case ' + i));
});

test('P1 finding 3: IPv6 with no decimal digit and the IPv4-mapped form are defanged in running text; a hex-looking word stays as written', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const CASES = [
    ['feed c2 dead:beef::abcd here', 'feed c2 dead[:]beef[:][:]abcd here'],
    ['dead:beef::1 stays covered', 'dead[:]beef[:][:]1 stays covered'],
    ['mapped ::ffff:192.0.2.1 and [::ffff:192.0.2.1]:443', 'mapped [:][:]ffff[:]192[.]0[.]2[.]1 and [[:][:]ffff[:]192[.]0[.]2[.]1]:443'],
    ['at ::ffff:10.0.0.1.', 'at [:][:]ffff[:]10[.]0[.]0[.]1.'],
    ['net 2001:db8::/32 keeps its prefix', 'net 2001[:]db8[:][:]/32 keeps its prefix'],
    // controls: what is not an address keeps every character
    ['Add::Bad std::vector Note: ok', 'Add::Bad std::vector Note: ok'],
    ['and :: and ::1 here', 'and :: and [:][:]1 here'],
    ['v1.2.3.4 and 300.1.1.1 and 10:30:45', 'v1[.]2[.]3[.]4 and 300.1.1.1 and 10:30:45']
  ];
  const body = CASES.map((c, i) => '<!--R' + i + '-->' + cap(c[0]) + '{% include defang-html.html html=t %}' + '<!--S' + i + '-->').join('\n') +
    '\n<!--T0-->{% include ioc-cell.html type="ipv6" value="dead:beef::abcd" %}<!--U0-->' +
    '\n<!--T1-->{% include ioc-cell.html type="ipv6" value="::ffff:192.0.2.1" %}<!--U1-->';
  const { html } = buildSite(body);
  const got = (a, k) => html.split('<!--' + a + k + '-->')[1].split('<!--' + String.fromCharCode(a.charCodeAt(0) + 1) + k + '-->')[0].replace(/^\n/, '').replace(/\n$/, '');
  CASES.forEach((c, i) => assert.equal(got('R', i), c[1], 'case ' + i));
  assert.equal(got('T', 0), '<code>dead[:]beef[:][:]abcd</code>', 'a viewer cell');
  assert.equal(got('T', 1), '<code>[:][:]ffff[:]192[.]0[.]2[.]1</code>', 'a mapped viewer cell');
});

/* ---- T-0677 P1 (T-0500.1.7.6 PROPOSAL 1): text written with HTML entities is the indicator the reader sees ---- */
const ENTITY_CASES = [
  // the forms the review measured: decimal dot, decimal address
  ['C2 at evil&#46;example&#46;xyz and 198&#46;51&#46;100&#46;17 now', 'C2 at evil[.]example[.]xyz and 198[.]51[.]100[.]17 now'],
  // hex dot, in the spellings a browser decodes (lower-case and upper-case x, upper-case hex digits)
  ['evil&#x2e;example&#x2e;xyz', 'evil[.]example[.]xyz'],
  ['evil&#X2e;example&#X2e;xyz', 'evil[.]example[.]xyz'],
  ['evil&#X2E;example&#X2E;xyz', 'evil[.]example[.]xyz'],
  ['evil&#x2E;example&#x2E;xyz', 'evil[.]example[.]xyz'],
  // named dot
  ['evil&period;example&period;xyz', 'evil[.]example[.]xyz'],
  // the colon entity forms, on an IPv6 address
  ['2001&#58;db8&#58;&#58;7', '2001[:]db8[:][:]7'],
  ['2001&#x3a;db8&#x3a;&#x3a;7', '2001[:]db8[:][:]7'],
  ['2001&#X3A;db8&#X3A;&#X3A;7', '2001[:]db8[:][:]7'],
  ['2001&colon;db8&colon;&colon;7', '2001[:]db8[:][:]7'],
  // the entity forms inside running text, with the punctuation around the word
  ['see (evil&#46;example&#46;xyz), then 198&#46;51&#46;100&#46;17.', 'see (evil[.]example[.]xyz), then 198[.]51[.]100[.]17.'],
  // controls: an entity that is neither a dot nor a colon, and prose with no indicator, come out byte-identical
  ['Tom &amp; Jerry&#38; Co &#38; AT&amp;T &lt;note&gt;', 'Tom &amp; Jerry&#38; Co &#38; AT&amp;T &lt;note&gt;'],
  ['the ampersand &#38; and &amp; and &#8212; are ordinary prose', 'the ampersand &#38; and &amp; and &#8212; are ordinary prose'],
  ['AT&amp;T at 198.51.100.17', 'AT&amp;T at 198[.]51[.]100[.]17']
];

test('T-0677 P1: an indicator written with dot or colon entities is defanged (the browser renders it as an ordinary domain or address); entity prose is byte-identical', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const ATTR_CASES = [
    ['<p title="C2 at 198&#46;51&#46;100&#46;17">t</p>', '<p title="C2 at 198[.]51[.]100[.]17">t</p>'],
    ['<p title="evil&#46;example&#46;xyz">t</p>', '<p title="evil[.]example[.]xyz">t</p>'],
    ['<img alt="host evil&#x2e;example&#x2e;xyz" src="/a.png">', '<img alt="host evil[.]example[.]xyz" src="/a.png">'],
    ['<p data-copy="2001&#58;db8&#58;&#58;7">x</p>', '<p data-copy="2001[:]db8[:][:]7">x</p>'],
    ['<input value="evil&period;example&period;xyz">', '<input value="evil[.]example[.]xyz">'],
    // controls: a raw element, a data-literal cell and an entity-prose attribute keep every byte
    ['<pre>evil&#46;example&#46;xyz</pre>', '<pre>evil&#46;example&#46;xyz</pre>'],
    ['<script>var a = "evil&#46;example&#46;xyz";</script>', '<script>var a = "evil&#46;example&#46;xyz";</script>'],
    ['<style>.x::after{content:"evil&#46;example&#46;xyz"}</style>', '<style>.x::after{content:"evil&#46;example&#46;xyz"}</style>'],
    ['<template>evil&#46;example&#46;xyz</template>', '<template>evil&#46;example&#46;xyz</template>'],
    ['<textarea>evil&#46;example&#46;xyz</textarea>', '<textarea>evil&#46;example&#46;xyz</textarea>'],
    ['<code data-literal="filename">evil&#46;example&#46;xyz</code>', '<code data-literal="filename">evil&#46;example&#46;xyz</code>'],
    ['<p title="Tom &amp; Jerry&#38; Co">x</p>', '<p title="Tom &amp; Jerry&#38; Co">x</p>']
  ];
  const body = ENTITY_CASES.map((c, i) => '<!--G' + i + '-->{% include defang-text.html text=\'' + c[0].replace(/'/g, '&#39;') + '\' %}<!--H' + i + '-->').join('\n') + '\n' +
    ENTITY_CASES.map((c, i) => '<!--E' + i + '-->{% capture h %}{% raw %}<p>' + c[0] + '</p>{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--F' + i + '-->').join('\n') + '\n' +
    ATTR_CASES.map((c, i) => '<!--A' + i + '-->{% capture h %}{% raw %}' + c[0] + '{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--B' + i + '-->').join('\n');
  const { html } = buildSite(body);
  const got = (a, k) => html.split('<!--' + a + k + '-->')[1].split('<!--' + String.fromCharCode(a.charCodeAt(0) + 1) + k + '-->')[0].replace(/^\n/, '').replace(/\n$/, '');
  ENTITY_CASES.forEach((c, i) => {
    assert.equal(got('G', i), c[1], 'text case ' + i + ': ' + c[0]);
    assert.equal(got('E', i), '<p>' + c[1] + '</p>', 'html case ' + i + ': ' + c[0]);
  });
  ATTR_CASES.forEach((c, i) => assert.equal(got('A', i), c[1], 'attribute case ' + i + ': ' + c[0]));
});

test('T-0677 P1: what the browser renders for an entity-written indicator is an ordinary domain before the fix and the defanged form after it (jsdom)', (t) => {
  if (!JEKYLL) return t.skip('NOT CHECKED: no jekyll gem on this machine, so the Liquid include was not executed');
  const body = '<!--X0-->{% capture h %}{% raw %}<p>C2 at evil&#46;example&#46;xyz and 198&#46;51&#46;100&#46;17</p>{% endraw %}{% endcapture %}{% include defang-html.html html=h %}<!--Y0-->';
  const { out, html } = buildSite(body);
  const got = html.split('<!--X0-->')[1].split('<!--Y0-->')[0].replace(/^\n/, '').replace(/\n$/, '');
  // the reviewer's measurement: the raw entity form is an ordinary domain to every reader
  const raw = new JSDOM('<!doctype html><html><body><p>C2 at evil&#46;example&#46;xyz and 198&#46;51&#46;100&#46;17</p></body></html>').window.document.body.textContent;
  assert.match(raw, /evil\.example\.xyz and 198\.51\.100\.17/, 'control: the browser reads the entity form as a live domain and address');
  const shown = new JSDOM('<!doctype html><html><body>' + got + '</body></html>').window.document.body.textContent;
  assert.doesNotMatch(shown, /evil\.example\.xyz|198\.51\.100\.17/, 'no readable domain or address survives: ' + shown);
  assert.match(shown, /evil\[\.\]example\[\.\]xyz and 198\[\.\]51\[\.\]100\[\.\]17/);
  // and the rendered-page gate agrees: the raw page is a finding, the include's page is clean
  assert.equal(gate(fixtureSite({ 'index.html': '<p>C2 at evil&#46;example&#46;xyz and 198&#46;51&#46;100&#46;17</p>' })).status, 1, 'control: the gate reports the raw entity form');
  assert.equal(gate(fixtureSite({ 'index.html': got })).status, 0, 'the include output passes the gate');
});

/* ---- the gate on a fixture site (no Jekyll needed) ---- */
function fixtureSite(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-defang-site-'));
  Object.keys(files).forEach((rel) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), '<html><head><title>1[.]2[.]3[.]4 head metadata is scanned</title></head><body><main>' + files[rel] + '<p>fixture text</p></main></body></html>'); });
  return dir;
}
const gate = (dir, extra) => cp.spawnSync(process.execPath, [path.join(__dirname, '..', 'check-defang.js'), '--site', dir, '--allow-data', path.join(root, '_data', 'defang_allow.yml'), '--all', '--pages-only'].concat(extra || []), { encoding: 'utf8' });

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
  const ex = gate(fixtureSite({ 'index.html': '<p>x</p>', 'feeds/misp/changelog/index.html': '198.51.100.17' }));
  assert.equal(ex.status, 0, ex.stdout);
  assert.match(ex.stdout, /excluded\s+1 feed changelog \(decision 7\)/);
  // control (T-0605 L15): the /report-templates/ exemption went with the page, so a page at that path is scanned like any other
  const rt = gate(fixtureSite({ 'index.html': '<p>x</p>', 'report-templates/index.html': '198.51.100.17' }));
  assert.equal(rt.status, 1, rt.stdout);
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
  assert.match(r.stdout, /CANNOT SEE: text a script writes after load \(check-browser-defang\.js reads that in a real browser\); the data-title search keys/);
});
