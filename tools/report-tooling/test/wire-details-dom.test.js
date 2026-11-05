'use strict';

/* T-0532 part S: a DOM smoke test for the Details renderer.

   jsdom cannot reach the browser gates' claims (computed styles, real pointers,
   the network stack), but it can reach the runtime mistakes the text gates
   cannot: does the script initialise on the real markup shape, does a click
   build a panel with the design's lines, are the hrefs the
   fixed-prefix-plus-encoded form, does Escape close it, and do the headlines
   panels read what the page itself holds. The details JSON is stubbed at fetch,
   because in jsdom there is none. */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var JSDOM = require('jsdom').JSDOM;

var RENDERER = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'assets', 'js', 'wire-details.js'), 'utf8');

var NKEV_ROWS = {
  'cve-2026-1001': {
    added: '2026-10-31', title: null, desc: 'The record description.', cwe: ['CWE-79'],
    affected: ['Acme Widget: 1.0 up to and including 2.0'], fixed: '2.1.0',
    kev_due: '2026-11-15', evidence: '2026-10-20', cisa_added: '2026-10-30', disclosed: '2026-10-25',
    gap: 3, msf: ['modules/exploits/linux/http/acme_widget.rb'], edb: [], reports: [],
    reports_more: 0, stories: 2, aliases: ['GHSA-aaaa-bbbb-cccc-dddd', 'EUVD-2026-999001'],
    et_sids: [1234567], nuclei: 'http/cves/2026/CVE-2026-1001.yml', cisa_sigma: [], snort3_sids: [],
    ssvc_expl: 'active', ssvc_auto: 'no', ssvc_impact: 'total',
    cvss: '9.8', cvss_version: '3.1', severity: 'critical', scored_by: 'CNA',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss: '0.004', epss_pct: '0.35', epss_date: '2026-11-01', epss_pre: '0.001', epss_max: '0.004',
    epss_xmodel: '', signals: [], kev_product: null, kev_product_n: 0
  }
};

function build(rows, genAt) {
  return JSON.stringify({ generated_at: genAt || '2026-11-01T19:32:18Z', rows: rows });
}

/* A miniature of the real markup, same classes, data attributes and the real id
   shape: the page's row ids carry the doubled prefix the template writes, so
   id="cve-{{ downcased }}" is "cve-cve-2026-1001". Same here. */
function pageHtml(opts) {
  var hid = opts && opts.headlineId ? ' id="' + opts.headlineId + '"' : '';
  return '<body>' +
    '<section id="headlines" class="hl-wtabs__sec" data-filter-scope>' +
    '<div class="hl-wire" data-filter-grid data-filter-item=".hl-wire__row">' +
    '<div class="hl-wire__day" data-filter-group>2026 October 31</div>' +
    '<div class="hl-wire__row"' + hid + ' data-title="acme widget tipper overheats cve-2026-1001 cve-2026-9999 cve-2026-7777" data-tags="acme|cve-2026-1001|cve-2026-9999|cve-2026-7777" data-labels="Acme|CVE-2026-1001|CVE-2026-9999|CVE-2026-7777" data-kind="research" data-day="2026-10-31">' +
    '<a class="hl-wire__item hl-wire__item--research" href="https://blog.example.acme/setup"><span class="hl-wire__src">Acme</span><span class="hl-wire__title">Acme widget tipper overheats</span></a>' +
    '</div>' +
    '<div class="hl-wire__row" data-title="vulncheck widget wiki ky" data-kind="vuln" data-day="2026-10-31">' +
    '<a class="hl-wire__item hl-wire__item--vuln" href="#vulns-2026-10-31">digest</a>' +
    '</div>' +
    '</div></section>' +
    '<section id="vulns" class="hl-wtabs__sec" data-filter-scope data-details="/wire/details-nkev.json?v=2026-11-01T19:32:18Z">' +
    '<div class="hl-vuln" id="cve-cve-2026-1001" data-title="cve-2026-1001 acme widget" data-day="2026-10-31">' +
    '<button type="button" class="hl-dt" aria-expanded="false" hidden="" title="Show details"><span class="hl-dt__sr">Details</span></button><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/CVE-2026-1001">CVE-2026-1001</a>' +
    '<span class="hl-vuln__vp"><b>Acme</b> Widget</span>' +
    '</div>' +
    '</section>' +
    '<section id="cves" class="hl-wtabs__sec" data-filter-scope data-details="/wire/details-cves.json?v=2026-11-01T19:32:18Z">' +
    '<div class="hl-vuln hl-vuln--cve" id="cves-cve-2026-9999" data-day="2026-10-31">' +
    '<button type="button" class="hl-dt" aria-expanded="false" hidden="" title="Show details"><span class="hl-dt__sr">Details</span></button><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/CVE-2026-9999">CVE-2026-9999</a>' +
    '</div>' +
    '</section></body>';
}

function openDom(rows, opts) {
  opts = opts || {};
  var dom = new JSDOM(pageHtml(opts), { url: 'https://the-hunters-ledger.test/wire/' + (opts.hash || ''), runScripts: 'outside-only' });
  var win = dom.window;
  // jsdom has no layout; record which rows the script asked to scroll into view.
  opts.scrolled = [];
  win.Element.prototype.scrollIntoView = function () { opts.scrolled.push(this.id); };
  win.fetch = function () {
    opts.calls = (opts.calls || 0) + 1;
    if (opts.badFetch) { return Promise.resolve({ ok: false, status: 503, json: function () { return Promise.resolve({}); } }); }
    return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve(JSON.parse(build(rows, opts.genAt))); } });
  };
  win.eval(RENDERER);
  var doc = win.document;
  // init() removes each toggle's hidden attribute
  [].forEach.call(doc.querySelectorAll('.hl-dt'), function (b) {
    assert.equal(b.hasAttribute('hidden'), false, 'the script must remove hidden from every toggle');
  });
  return { dom: dom, opts: opts };
}

function clicks(doc, btn) {
  btn.dispatchEvent(new doc.defaultView.MouseEvent('click', { bubbles: true }));
}
function settle() { return new Promise(function (r) { setTimeout(r, 5); }); }

test('a nKEV row opens the full fact sheet in the design\u2019s fixed order', async function () {
  var env = openDom(NKEV_ROWS);
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cve-cve-2026-1001');
  var btn = rowEl.querySelector('.hl-dt');
  clicks(doc, btn);
  var p = rowEl.querySelector('.hl-dt__panel');
  assert.equal(btn.getAttribute('aria-expanded'), 'true');
  assert.equal(btn.getAttribute('aria-controls'), 'cve-cve-2026-1001-dt');
  assert.match(p.textContent, /Loading details\.\.\./);
  await settle();
  var t = p.textContent;
  ['CVE record', 'Affected and fixed', 'What to do', 'Exploitation', 'Public exploits',
   'Detection', 'Severity', 'Likelihood (EPSS)', 'Links'].forEach(function (h) {
    assert.ok(t.indexOf(h) !== -1, 'missing section heading ' + h);
  });
  assert.match(t, /The record description\./);
  assert.match(t, /From the CVE record, via NVD\./);
  assert.match(t, /Weakness: CWE-79\./);
  var cweLink = [].slice.call(p.querySelectorAll('a')).filter(function (a) { return a.textContent === 'CWE-79'; })[0];
  assert.equal(cweLink.getAttribute('href'), 'https://cwe.mitre.org/data/definitions/79.html');
  assert.match(t, /Acme Widget: 1\.0 up to and including 2\.0/);
  assert.match(t, /Fixed in: 2\.1\.0/);
  assert.match(t, /A fixed version is listed above\./);
  assert.match(t, /CISA's due date for US federal agencies: 2026-11-15\./);
  assert.match(t, /Added to VulnCheck KEV on 2026-10-31\./);
  assert.match(t, /On CISA KEV since 2026-10-30\./);
  assert.match(t, /Earliest citation date: 2026-10-20\./);
  assert.match(t, /NVD published 2026-10-25, 3 days before the KEV add\./);
  // edb is empty in this fixture, so no Exploit-DB group (an empty heading was a defect).
  assert.doesNotMatch(t, /Exploit-DB/);
  assert.match(t, /ET Open: SID 1234567\./);
  assert.match(t, /Nuclei: /);
  assert.match(t, /CVSS v3\.1 base score 9\.8, Critical, scored by the CNA\./);
  assert.match(t, /From the vector: attack vector Network, complexity Low, privileges required None, user interaction None, scope Unchanged, confidentiality High, integrity High, availability High\./);
  assert.match(t, /Exploitation: active\. Automatable: no\. Technical impact: total\. \(CISA's assessment, via cve\.now\)/);
  assert.match(t, /EPSS 0\.004 \(35th percentile\) on 2026-11-01\./);
  assert.match(t, /7 days before the KEV add: 0\.001\./);
  assert.match(t, /Highest in the last 30 days: 0\.004\./);
  assert.match(t, /Wire headlines: 2 naming this CVE\./);
  var nvd = [].filter.call(p.querySelectorAll('a'), function (a) { return a.textContent === 'NVD'; })[0];
  assert.equal(nvd.getAttribute('href'), 'https://nvd.nist.gov/vuln/detail/CVE-2026-1001');
  var observer = [].filter.call(p.querySelectorAll('a'), function (a) { return a.textContent === 'Exploit Observer'; })[0];
  assert.equal(observer.getAttribute('href'), 'https://www.exploit.observer/?keyword=CVE-2026-1001');
  assert.equal(observer.target, '_blank');
  assert.equal(observer.rel, 'noopener noreferrer');
});

test('the CVEs panel says why listed, with the cve.now scoring line', async function () {
  var env = openDom({
    'cve-2026-9999': {
      added: null, published: '2026-10-31', title: 'Widget tipper overheats.', desc: '',
      cwe: [], affected: [], fixed: '2.2.0', kev_due: '', evidence: '', cisa_added: '', disclosed: '',
      msf: [], edb: [], reports: [], reports_more: 0, stories: 0, aliases: [],
      et_sids: [], nuclei: '', cisa_sigma: [], snort3_sids: [], ssvc_expl: '', ssvc_auto: '',
      ssvc_impact: '', cvss: '9.8', cvss_version: '3.1', severity: 'critical',
      scored_by: 'cve.now', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss: '0.9', epss_pct: '0.95', epss_date: '2026-11-01', epss_pre: '', epss_max: '',
      epss_xmodel: '', signals: ['crit_noauth_kev_product', 'epss90'],
      kev_product: 'Widget', kev_product_n: 3
    }
  });
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cves-cve-2026-9999');
  var btn = rowEl.querySelector('.hl-dt');
  clicks(doc, btn);
  var p = rowEl.querySelector('.hl-dt__panel');
  await settle();
  var t = p.textContent;
  assert.match(t, /Why listed/);
  assert.match(t, /Rated Critical \(CVSS 9\.8\) and reachable over the network with no privileges and no user action/);
  assert.match(t, /Widget: CISA has listed 3 earlier CVEs in this product on its KEV catalog\. That is a fact about the product, not about this CVE\./);
  assert.match(t, /FIRST's EPSS puts this CVE in the top 10%/);
  assert.match(t, /Not on VulnCheck KEV or CISA KEV as of 2026-11-01\. Being listed does not mean anyone has been seen exploiting it\./);
  assert.match(t, /CVSS v3\.1 base score 9\.8, Critical, from cve\.now, because our NVD data holds no score for it\./);
  assert.match(t, /EPSS 0\.9 \(95th percentile\) on 2026-11-01\./);
  assert.ok(t.indexOf('7 days before the KEV add') === -1, 'the CVEs tab holds no KEV-add comparison');
  assert.match(t, /Widget tipper overheats\./, 'the row title stands in for the absent record description');
});

test('a scored-by ADP row says so in the design\u2019s words', async function () {
  var env = openDom({
    'cve-2026-1001': Object.assign({}, NKEV_ROWS['cve-2026-1001'], { scored_by: 'ADP' })
  });
  var doc = env.dom.window.document;
  var btn = doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt');
  clicks(doc, btn);
  var p = doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt__panel');
  await settle();
  assert.match(p.textContent, /scored by CISA's ADP\./);
});

test('a failed details fetch shows the failure line, and the next open retries', async function () {
  var opts = { badFetch: true };
  var env = openDom(NKEV_ROWS, opts);
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cve-cve-2026-1001');
  var btn = rowEl.querySelector('.hl-dt');
  clicks(doc, btn);
  await settle();
  assert.match(rowEl.querySelector('.hl-dt__panel').textContent, /Details could not be loaded\./);
  clicks(doc, btn);   // close
  assert.equal(rowEl.querySelector('.hl-dt__panel'), null);
  clicks(doc, btn);   // open again: a fresh fetch, not the cached failure
  await settle();
  assert.equal(opts.calls, 2, 'a failed fetch must retry on the next open');
  assert.match(rowEl.querySelector('.hl-dt__panel').textContent, /Details could not be loaded\./);
});

test('a second click on the toggle closes the panel; Escape closes it too', async function () {
  var env = openDom(NKEV_ROWS);
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cve-cve-2026-1001');
  var btn = rowEl.querySelector('.hl-dt');
  clicks(doc, btn);
  await settle();
  clicks(doc, btn);
  assert.equal(rowEl.querySelector('.hl-dt__panel'), null);
  assert.equal(btn.getAttribute('aria-expanded'), 'false');
  clicks(doc, btn);
  await settle();
  btn.dispatchEvent(new doc.defaultView.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  assert.equal(rowEl.querySelector('.hl-dt__panel'), null);
});

test('an entry the details file does not carry says so in one line', async function () {
  var env = openDom({});   // empty rows map
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cves-cve-2026-9999');
  var btn = rowEl.querySelector('.hl-dt');
  clicks(doc, btn);
  await settle();
  assert.match(rowEl.querySelector('.hl-dt__panel').textContent, /No details in our data for this CVE\./);
});

test('a capped description says the full text is on NVD; a short one does not (Sol round 2 P2)', async function () {
  var capped = Object.assign({}, NKEV_ROWS['cve-2026-1001'], { desc: 'x'.repeat(2997) + '...' });
  var env = openDom({ 'cve-2026-1001': capped });
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cve-cve-2026-1001');
  clicks(doc, rowEl.querySelector('.hl-dt'));
  await settle();
  assert.match(rowEl.querySelector('.hl-dt__panel').textContent, /the full text is on NVD/);
  var env2 = openDom(NKEV_ROWS);
  var doc2 = env2.dom.window.document;
  var row2 = doc2.getElementById('cve-cve-2026-1001');
  clicks(doc2, row2.querySelector('.hl-dt'));
  await settle();
  assert.doesNotMatch(row2.querySelector('.hl-dt__panel').textContent, /the full text is on NVD/);
});

/* T-0548: a link to a Wire row (a site-search result) opens that row's Details pane,
   through the toggle's own click path, and scrolls the row into view. */

var CVE_ROWS = Object.assign({}, NKEV_ROWS, {
  'cve-2026-9999': {
    added: null, published: '2026-10-31', title: 'Widget tipper overheats.', desc: '',
    cwe: [], affected: [], fixed: '2.2.0', kev_due: '', evidence: '', cisa_added: '', disclosed: '',
    msf: [], edb: [], reports: [], reports_more: 0, stories: 0, aliases: [],
    et_sids: [], nuclei: '', cisa_sigma: [], snort3_sids: [], ssvc_expl: '', ssvc_auto: '',
    ssvc_impact: '', cvss: '', cvss_version: '', severity: '', scored_by: '',
    cvss_vector: '', epss: '', epss_pct: '', epss_date: '', epss_pre: '', epss_max: '',
    epss_xmodel: '', signals: [], kev_product: null, kev_product_n: 0
  }
});

function paneOf(doc, rowId) {
  return doc.getElementById(rowId).querySelector('.hl-dt__panel');
}

test('a hash on load opens the nKEV row’s pane and scrolls the row into view', async function () {
  var env = openDom(NKEV_ROWS, { hash: '#cve-cve-2026-1001' });
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cve-cve-2026-1001');
  var btn = rowEl.querySelector('.hl-dt');
  assert.equal(btn.getAttribute('aria-expanded'), 'true', 'the toggle reads expanded');
  assert.equal(env.opts.calls, 1, 'one details fetch, from the same path a click takes');
  assert.match(paneOf(doc, 'cve-cve-2026-1001').textContent, /Loading details\.\.\./);
  await settle();
  assert.match(paneOf(doc, 'cve-cve-2026-1001').textContent, /The record description\./);
  assert.deepEqual(env.opts.scrolled, ['cve-cve-2026-1001']);
  assert.equal(rowEl.style.scrollMarginTop, '', 'a nKEV row keeps the margin custom.scss gives it');
});

test('a hash on load opens the CVEs row’s pane, the CVEs tab’s own renderer', async function () {
  var env = openDom(CVE_ROWS, { hash: '#cves-cve-2026-9999' });
  var doc = env.dom.window.document;
  assert.equal(doc.getElementById('cves-cve-2026-9999').querySelector('.hl-dt').getAttribute('aria-expanded'), 'true');
  await settle();
  var t = paneOf(doc, 'cves-cve-2026-9999').textContent;
  assert.match(t, /Why listed/, 'the CVEs fact sheet, not the nKEV one');
  assert.deepEqual(env.opts.scrolled, ['cves-cve-2026-9999']);
});

test('a hashchange to a row opens its pane, without a reload', async function () {
  var env = openDom(NKEV_ROWS);
  var doc = env.dom.window.document;
  var win = env.dom.window;
  assert.equal(paneOf(doc, 'cve-cve-2026-1001'), null, 'no pane before the hash moves');
  win.location.hash = '#cve-cve-2026-1001';
  await settle();
  await settle();
  assert.equal(doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt').getAttribute('aria-expanded'), 'true');
  await settle();
  assert.match(paneOf(doc, 'cve-cve-2026-1001').textContent, /The record description\./);
  assert.deepEqual(env.opts.scrolled, ['cve-cve-2026-1001']);
});

test('a hash that names nothing on the page does nothing', async function () {
  var env = openDom(NKEV_ROWS, { hash: '#no-such-row' });
  var doc = env.dom.window.document;
  await settle();
  assert.equal(doc.querySelectorAll('.hl-dt__panel').length, 0, 'no pane opened');
  assert.equal(env.opts.calls, undefined, 'no details fetch');
  assert.deepEqual(env.opts.scrolled, []);
  assert.equal(doc.querySelector('.hl-dt').getAttribute('aria-expanded'), 'false');
});

test('a day anchor, a section anchor and a hash later changed to nothing are all no-ops', async function () {
  var env = openDom(NKEV_ROWS, { hash: '#vulns-2026-10-31' });
  var doc = env.dom.window.document;
  await settle();
  assert.equal(doc.querySelectorAll('.hl-dt__panel').length, 0, 'a day heading is not a row');
  var win = env.dom.window;
  win.location.hash = '#vulns';
  await settle();
  win.location.hash = '#';
  await settle();
  assert.equal(doc.querySelectorAll('.hl-dt__panel').length, 0);
  assert.deepEqual(env.opts.scrolled, []);
});

test('a hash to a row whose pane is already open leaves it open', async function () {
  var env = openDom(NKEV_ROWS);
  var doc = env.dom.window.document;
  var win = env.dom.window;
  clicks(doc, doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt'));
  await settle();
  win.location.hash = '#elsewhere';
  await settle();
  win.location.hash = '#cve-cve-2026-1001';
  await settle();
  await settle();
  var btn = doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt');
  assert.equal(btn.getAttribute('aria-expanded'), 'true', 'still expanded, not toggled shut');
  assert.equal(doc.querySelectorAll('#cve-cve-2026-1001 .hl-dt__panel').length, 1, 'one panel, not two');
  assert.equal(env.opts.calls, 1, 'no second fetch for an open pane');
  assert.deepEqual(env.opts.scrolled, ['cve-cve-2026-1001']);
});

test('a headline row lands on its id and has no pane to open', async function () {
  var env = openDom(NKEV_ROWS, { hash: '#h-202610310000-acme-setup', headlineId: 'h-202610310000-acme-setup' });
  var doc = env.dom.window.document;
  await settle();
  assert.deepEqual(env.opts.scrolled, ['h-202610310000-acme-setup'], 'the row is scrolled to');
  assert.equal(doc.querySelectorAll('.hl-dt__panel').length, 0, 'a headline row has no Details pane');
  assert.equal(env.opts.calls, undefined, 'no details fetch for a headline');
  // the sticky nav would cover a headline row that has no scroll margin of its own
  assert.equal(doc.getElementById('h-202610310000-acme-setup').style.scrollMarginTop, '80px');
});

test('the click path still opens and closes a pane after the hash code is in (control)', async function () {
  var env = openDom(NKEV_ROWS);
  var doc = env.dom.window.document;
  var btn = doc.getElementById('cve-cve-2026-1001').querySelector('.hl-dt');
  clicks(doc, btn);
  assert.equal(btn.getAttribute('aria-expanded'), 'true');
  await settle();
  assert.match(paneOf(doc, 'cve-cve-2026-1001').textContent, /The record description\./);
  clicks(doc, btn);
  assert.equal(paneOf(doc, 'cve-cve-2026-1001'), null);
  assert.deepEqual(env.opts.scrolled, [], 'a plain click does not scroll');
});
