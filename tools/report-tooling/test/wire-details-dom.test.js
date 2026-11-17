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
/* T-0667 part D: more rows on one tab, for the cases below. A key is the plain lowercased CVE id
   the details file uses; the page id carries the tab's prefix (cve- on nKEVs, cves- on CVEs). */
function extraRows(keys, prefix) {
  return (keys || []).map(function (k) {
    return '<div class="hl-vuln' + (prefix === 'cves-' ? ' hl-vuln--cve' : '') + '" id="' + prefix + k + '" data-day="2026-10-31">' +
      '<button type="button" class="hl-dt" aria-expanded="false" hidden="" title="Show details"><span class="hl-dt__sr">Details</span></button>' +
      '<a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/' + k.toUpperCase() + '">' + k.toUpperCase() + '</a></div>';
  }).join('');
}
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
    '</div>' + extraRows(opts && opts.nkevKeys, 'cve-') +
    '</section>' +
    '<section id="cves" class="hl-wtabs__sec" data-filter-scope data-details="/wire/details-cves.json?v=2026-11-01T19:32:18Z">' +
    '<div class="hl-vuln hl-vuln--cve" id="cves-cve-2026-9999" data-day="2026-10-31">' +
    '<button type="button" class="hl-dt" aria-expanded="false" hidden="" title="Show details"><span class="hl-dt__sr">Details</span></button><a class="hl-vuln__cve" href="https://nvd.nist.gov/vuln/detail/CVE-2026-9999">CVE-2026-9999</a>' +
    '</div>' + extraRows(opts && opts.cveKeys, 'cves-') +
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
  win.eval(opts.renderer || RENDERER);
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
  ['CVE record', 'Fix', 'Exploitation', 'Public exploits',
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
  assert.doesNotMatch(t, /A fixed version is listed above\./, 'T-0667 D2: the fix is said once');
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
      epss_xmodel: '', signals: ['nuclei', 'et', 'epss90'],
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
  assert.match(t, /A Nuclei template names this CVE/);
  assert.match(t, /An ET Open Suricata rule names this CVE/);
  assert.doesNotMatch(t, /Rated Critical/);
  assert.match(t, /Widget: CISA has listed 3 earlier entries in this product on its KEV catalog\. That is a fact about the product, not about this CVE\./);
  assert.match(t, /FIRST's EPSS puts this CVE in the top 10%/);
  assert.match(t, /Not on VulnCheck KEV or CISA KEV as of 2026-11-01\. Being listed does not mean anyone has been seen exploiting it\./);
  assert.match(t, /CVSS v3\.1 base score 9\.8, Critical, from cve\.now, because our NVD data holds no score for it\./);
  assert.match(t, /EPSS 0\.9 \(95th percentile\) on 2026-11-01\./);
  assert.ok(t.indexOf('7 days before the KEV add') === -1, 'the CVEs tab holds no KEV-add comparison');
  assert.match(t, /Widget tipper overheats\./, 'the row title stands in for the absent record description');
});

test('one earlier KEV CVE in the product reads in the singular', async function () {
  var env = openDom({
    'cve-2026-9999': {
      added: null, published: '2026-10-31', title: 'Widget tipper overheats.', desc: '',
      cwe: [], affected: [], fixed: '2.2.0', kev_due: '', evidence: '', cisa_added: '', disclosed: '',
      msf: [], edb: [], reports: [], reports_more: 0, stories: 0, aliases: [],
      et_sids: [], nuclei: '', cisa_sigma: [], snort3_sids: [], ssvc_expl: '', ssvc_auto: '',
      ssvc_impact: '', cvss: '9.8', cvss_version: '3.1', severity: 'critical',
      scored_by: 'cve.now', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      epss: '0.9', epss_pct: '0.95', epss_date: '2026-11-01', epss_pre: '', epss_max: '',
      epss_xmodel: '', signals: ['nuclei', 'et', 'epss90'],
      kev_product: 'Widget', kev_product_n: 1
    }
  });
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById('cves-cve-2026-9999');
  clicks(doc, rowEl.querySelector('.hl-dt'));
  await settle();
  var t = rowEl.querySelector('.hl-dt__panel').textContent;
  assert.match(t, /Widget: CISA has listed 1 earlier entry in this product on its KEV catalog\./);
  assert.doesNotMatch(t, /1 earlier entries/);
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

/* ===========================================================================
   T-0667 part D: the Details panel, refined (D1 to D5, Joseph's go 2026-11-17).
   Proposal: tasks/runs/T-0667/details-proposal.md.
   D1 new section order; D2 one Fix section; D3 why the row ranks; D4 the exploitation
   timeline on nKEV rows; D5 no repeated EPSS line.
   =========================================================================== */

var BASE_NKEV = NKEV_ROWS['cve-2026-1001'];
var BASE_CVE = CVE_ROWS['cve-2026-9999'];

function nk(over) { return Object.assign({}, BASE_NKEV, over || {}); }
function cv(over) { return Object.assign({}, BASE_CVE, over || {}); }

/* Open one row's panel and return the panel element. */
async function panelFor(rows, rowId, opts) {
  var env = openDom(rows, opts);
  var doc = env.dom.window.document;
  var rowEl = doc.getElementById(rowId);
  clicks(doc, rowEl.querySelector('.hl-dt'));
  await settle();
  return rowEl.querySelector('.hl-dt__panel');
}
function headingsOf(panel) {
  return [].map.call(panel.querySelectorAll('.hl-dt__h'), function (h) { return h.textContent; });
}
function linesOf(panel) {
  return [].map.call(panel.querySelectorAll('.hl-dt__line'), function (p) { return p.textContent; });
}
function pointsOf(panel) {
  return [].map.call(panel.querySelectorAll('.hl-dt__pt'), function (p) { return p.textContent; });
}
function sumPoints(panel) {
  var sum = 0;
  pointsOf(panel).forEach(function (t) {
    var m = /: (\d+) points?$/.exec(t);
    assert.ok(m, 'a point line ends in "N point(s)": ' + t);
    sum += Number(m[1]);
  });
  return sum;
}

var NKEV_ORDER = ['Exploitation', 'Fix', 'Detection', 'Public exploits', 'Severity', 'Likelihood (EPSS)', 'CVE record', 'Links'];
var CVES_ORDER = ['Why listed', 'Fix', 'Detection', 'Public exploits', 'Severity', 'Likelihood', 'CVE record', 'Links'];

test('D1: the nKEVs panel opens with why the row is here, and the CVE record comes after the likelihood', async function () {
  var p = await panelFor({ 'cve-2026-1001': nk() }, 'cve-cve-2026-1001');
  assert.deepEqual(headingsOf(p), NKEV_ORDER);
});

test('D1: the CVEs panel opens with why it is listed, and the CVE record comes after the likelihood', async function () {
  var p = await panelFor({ 'cve-2026-9999': cv() }, 'cves-cve-2026-9999');
  assert.deepEqual(headingsOf(p), CVES_ORDER);
});

test('D1 control: the old order (the CVE record first) fails the order check on both tabs', async function () {
  // The renderer with buildNkevPanel and buildCvesPanel calling secRecord first, as before T-0667.
  var mutated = RENDERER
    .replace('function buildNkevPanel(panel, d, cveId, asOfDay) {\n', 'function buildNkevPanel(panel, d, cveId, asOfDay) {\n  secRecord(panel, d, false);\n')
    .replace('function buildCvesPanel(panel, d, cveId, asOfDay) {\n', 'function buildCvesPanel(panel, d, cveId, asOfDay) {\n  secRecord(panel, d, true);\n');
  assert.notEqual(mutated, RENDERER, 'the mutation must change the renderer');
  var pn = await panelFor({ 'cve-2026-1001': nk() }, 'cve-cve-2026-1001', { renderer: mutated });
  assert.equal(headingsOf(pn)[0], 'CVE record', 'the mutant draws the record first');
  assert.notDeepEqual(headingsOf(pn), NKEV_ORDER.concat(['CVE record']).slice(0, 8), 'sanity');
  assert.notDeepEqual(headingsOf(pn).slice(0, NKEV_ORDER.length), NKEV_ORDER, 'the order check would fail on the mutant (nKEVs)');
  var pc = await panelFor({ 'cve-2026-9999': cv() }, 'cves-cve-2026-9999', { renderer: mutated });
  assert.equal(headingsOf(pc)[0], 'CVE record');
  assert.notDeepEqual(headingsOf(pc).slice(0, CVES_ORDER.length), CVES_ORDER, 'the order check would fail on the mutant (CVEs)');
});

test('D2: one Fix section, and "no fixed version" is said once, on both tabs', async function () {
  var noFix = { fixed: '', affected: ['Acme Widget: 1.0 up to and including 2.0'], kev_due: '' };
  var pn = await panelFor({ 'cve-2026-1001': nk(noFix) }, 'cve-cve-2026-1001');
  var pc = await panelFor({ 'cve-2026-9999': cv({ fixed: '', kev_due: '' }) }, 'cves-cve-2026-9999');
  [pn, pc].forEach(function (p) {
    var heads = headingsOf(p);
    assert.equal(heads.filter(function (h) { return h === 'Fix'; }).length, 1, 'one Fix heading');
    assert.equal(heads.indexOf('Affected and fixed'), -1);
    assert.equal(heads.indexOf('What to do'), -1);
    var said = linesOf(p).filter(function (l) { return /No fixed version in the data I hold/.test(l); });
    assert.equal(said.length, 1, 'the no-fix line appears once: ' + JSON.stringify(said));
    assert.doesNotMatch(p.textContent, /No fixed version in the data I hold\.(?!;)/, 'the second, shorter wording is gone');
  });
  // the affected terms sit in the same section, before the fix line
  var kids = [].slice.call(pn.children);
  var fixAt = kids.findIndex(function (k) { return k.textContent === 'Fix'; });
  assert.equal(kids[fixAt + 1].textContent, 'Acme Widget: 1.0 up to and including 2.0', 'the affected term opens the Fix section');
  assert.match(kids[fixAt + 2].textContent, /^No fixed version in the data I hold/);
});

test('D2: a fixed row names the version once and the CISA due date once, both under Fix', async function () {
  var p = await panelFor({ 'cve-2026-1001': nk() }, 'cve-cve-2026-1001');
  var t = p.textContent;
  assert.equal(t.split('Fixed in: 2.1.0').length - 1, 1);
  assert.equal(t.split("CISA's due date for US federal agencies: 2026-11-15.").length - 1, 1);
  assert.doesNotMatch(t, /A fixed version is listed above/);
  // under the Fix heading, before the next heading
  var kids = [].slice.call(p.children);
  var fixAt = kids.findIndex(function (k) { return k.textContent === 'Fix'; });
  var nextAt = kids.findIndex(function (k, i) { return i > fixAt && /hl-dt__h\b/.test(k.className); });
  var inFix = kids.slice(fixAt + 1, nextAt).map(function (k) { return k.textContent; }).join('|');
  assert.match(inFix, /Fixed in: 2\.1\.0/);
  assert.match(inFix, /CISA's due date/);
});

/* --- D3: the words and points are the chips' own ---------------------------------------- */
function chipTable(blockStartMarker) {
  // wire/index.md: the {% for t in r.<x>_reasons %} ... {% endfor %} block of each tab's chips.
  var md = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'wire', 'index.md'), 'utf8');
  var at = md.indexOf(blockStartMarker);
  assert.ok(at > -1, 'chip block not found: ' + blockStartMarker);
  var end = md.indexOf('{% endfor %}', at);
  var block = md.slice(at, end);
  var out = {};
  var re = /\{% when "([a-z0-9]+)" %\}<span class="hl-pick__chip[^"]*" title="([^"]*)">([^<{]*)<\/span>/g;
  var m;
  while ((m = re.exec(block))) {
    var pts = /Worth (\d) points?/.exec(m[2]);
    out[m[1]] = { label: m[3], pts: pts ? Number(pts[1]) : NaN };
  }
  // The class chip's title and label hold Liquid (the class name), so the pattern above skips it:
  // read its rule from the text instead. Its label is the class name, its points 2 (1 for an OS or browser).
  var cm = /\{% when "class" %\}<span class="hl-pick__chip hl-pick__chip--class" title="[^]*?Worth 2 points, or 1 for an operating system or browser\./.exec(block);
  if (cm) { out['class'] = { label: '(class name)', pts: 2 }; }
  return out;
}

test('D3: every reason line uses the chip’s word and points (nKEV Priority, CVE pick, Just published)', async function () {
  var np = chipTable('{% for t in r.np_reasons %}');
  var pick = chipTable('{% for t in r.pick_reasons %}');
  var fresh = chipTable('{% for t in r.fresh_reasons %}');
  assert.deepEqual(Object.keys(np).sort(), ['cisa', 'class', 'critical', 'fresh', 'noauth', 'tooling'], 'the page chips read for nKEV');
  assert.deepEqual(Object.keys(pick).sort(), ['class', 'critical', 'epss90', 'noauth', 'nomi', 'ssvc', 'tooling']);
  assert.deepEqual(Object.keys(fresh).sort(), ['class', 'critical', 'noauth', 'nomi', 'ssvc']);
  function expectLines(table, reasons, cls) {
    return reasons.map(function (t) {
      var pts = t === 'class' ? (cls === 'Operating system or browser' ? 1 : 2) : table[t].pts;
      var label = t === 'class' ? cls : table[t].label;
      return label + ': ' + pts + (pts === 1 ? ' point' : ' points');
    });
  }
  var npReasons = ['noauth', 'critical', 'class', 'tooling', 'cisa', 'fresh'];
  var pickReasons = ['tooling', 'nomi', 'ssvc', 'epss90', 'noauth', 'critical', 'class'];
  var freshReasons = ['nomi', 'ssvc', 'noauth', 'critical', 'class'];
  var nkRow = nk({ np_rank: 1, np_score: 8, np_reasons: npReasons, np_class: 'Edge and network device' });
  var pkRow = cv({ pick_day: '2026-10-31', pick_score: 10, pick_reasons: pickReasons, pick_class: 'Identity and access', pick_seeded: false });
  var frRow = cv({ fresh: true, fresh_score: 6, fresh_reasons: freshReasons, fresh_class: 'Identity and access' });
  var pn = await panelFor({ 'cve-2026-1001': nkRow }, 'cve-cve-2026-1001');
  assert.deepEqual(pointsOf(pn), expectLines(np, npReasons, 'Edge and network device'));
  var pp = await panelFor({ 'cve-2026-9999': pkRow }, 'cves-cve-2026-9999');
  assert.deepEqual(pointsOf(pp), expectLines(pick, pickReasons, 'Identity and access'));
  var pf = await panelFor({ 'cve-2026-9999': frRow }, 'cves-cve-2026-9999');
  assert.deepEqual(pointsOf(pf), expectLines(fresh, freshReasons, 'Identity and access'));
});

test('D3: on a Priority row the points sum to the row’s score and the total line says so', async function () {
  var row = nk({ np_rank: 4, np_score: 5, np_reasons: ['noauth', 'critical', 'class', 'cisa'], np_class: 'Edge and network device' });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  assert.equal(sumPoints(p), 5, 'the lines add up to np_score');
  assert.equal(pointsOf(p).length, 4);
  assert.ok(linesOf(p).indexOf('Total: 5 points.') > -1);
  assert.match(linesOf(p)[0], /^Why it ranks: Priority/);
  // first section: the rank lines sit right under the Exploitation heading, before the timeline
  assert.equal(headingsOf(p)[0], 'Exploitation');
  var kids = [].slice.call(p.children);
  assert.equal(kids[0].textContent, 'Exploitation');
  assert.match(kids[1].textContent, /^Why it ranks: Priority/);
  assert.ok(kids.findIndex(function (k) { return k.className.indexOf('hl-dt__tot') > -1; }) <
            kids.findIndex(function (k) { return /^Added to VulnCheck KEV/.test(k.textContent); }));
});

test('D3: an operating-system class is 1 point, other classes 2, and the sum still matches', async function () {
  var row = nk({ np_rank: 2, np_score: 5, np_reasons: ['noauth', 'critical', 'class', 'tooling', 'cisa'], np_class: 'Operating system or browser' });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  assert.ok(pointsOf(p).indexOf('Operating system or browser: 1 point') > -1);
  assert.equal(sumPoints(p), 5);
});

test('D3: a Priority pick on the CVEs tab sums to its pick score, under Why listed', async function () {
  var row = cv({ pick_day: '2026-10-31', pick_score: 7, pick_reasons: ['tooling', 'nomi', 'epss90', 'noauth', 'class'], pick_class: 'Identity and access', pick_seeded: false });
  var p = await panelFor({ 'cve-2026-9999': row }, 'cves-cve-2026-9999');
  assert.equal(sumPoints(p), 7);
  assert.ok(pointsOf(p).indexOf('Exploit tooling: 2 points') > -1);
  assert.ok(linesOf(p).indexOf('Total: 7 points when I picked it.') > -1);
  var kids = [].slice.call(p.children);
  assert.equal(kids[0].textContent, 'Why listed');
  assert.match(kids[1].textContent, /^Why it ranks: a Priority pick/);
});

test('D3: a Just published row sums to its score and says there is no evidence of exploitation', async function () {
  var row = cv({ fresh: true, fresh_score: 4, fresh_reasons: ['nomi', 'noauth', 'class'], fresh_class: 'Identity and access' });
  var p = await panelFor({ 'cve-2026-9999': row }, 'cves-cve-2026-9999');
  assert.equal(sumPoints(p), 4);
  assert.ok(linesOf(p).indexOf('Total: 4 points.') > -1);
  assert.match(p.textContent, /Just published, new and unproven, with no evidence of exploitation yet\./);
});

test('D3: a row that is both a pick and Just published explains both', async function () {
  var row = cv({ pick_day: '2026-10-31', pick_score: 3, pick_reasons: ['nomi', 'noauth', 'critical'], pick_class: '', pick_seeded: false,
    fresh: true, fresh_score: 2, fresh_reasons: ['noauth', 'critical'], fresh_class: '' });
  var p = await panelFor({ 'cve-2026-9999': row }, 'cves-cve-2026-9999');
  assert.equal(pointsOf(p).length, 5);
  assert.ok(linesOf(p).indexOf('Total: 3 points when I picked it.') > -1);
  assert.ok(linesOf(p).indexOf('Total: 2 points.') > -1);
});

test('D3: an unranked row gets no rank lines (np_rank 0 at a score of 5; no keys at all; a plain CVE row; a row that is not fresh)', async function () {
  var unranked = nk({ np_rank: 0, np_score: 5, np_reasons: ['noauth', 'critical', 'class', 'tooling'], np_class: 'Edge and network device' });
  var cases = [
    [{ 'cve-2026-1001': unranked }, 'cve-cve-2026-1001', 'unranked at 5+'],
    [{ 'cve-2026-1001': nk() }, 'cve-cve-2026-1001', 'nKEV row with no np keys'],
    [{ 'cve-2026-9999': cv() }, 'cves-cve-2026-9999', 'CVE row with no pick or fresh keys'],
    [{ 'cve-2026-9999': cv({ pick_day: '', pick_score: 0, pick_reasons: [], pick_class: '', pick_seeded: false, fresh: false, fresh_score: 0, fresh_reasons: [], fresh_class: '' }) },
      'cves-cve-2026-9999', 'CVE row with the keys, none earned']
  ];
  for (var i = 0; i < cases.length; i++) {
    var p = await panelFor(cases[i][0], cases[i][1]);
    assert.equal(pointsOf(p).length, 0, cases[i][2] + ': no point lines');
    assert.doesNotMatch(p.textContent, /Why it ranks|Total:/, cases[i][2]);
  }
});

test('D3: reasons on a row that does not hold the rank are not explained (fresh false, no pick day)', async function () {
  var row = cv({ pick_day: '', pick_score: 0, pick_reasons: ['nomi', 'noauth'], pick_class: '', pick_seeded: false,
    fresh: false, fresh_score: 0, fresh_reasons: ['nomi', 'noauth'], fresh_class: '' });
  var p = await panelFor({ 'cve-2026-9999': row }, 'cves-cve-2026-9999');
  assert.equal(pointsOf(p).length, 0);
  assert.doesNotMatch(p.textContent, /Why it ranks|Total:/);
});

test('D3: reasons that do not add up to the score are said, not hidden behind a total', async function () {
  var row = nk({ np_rank: 1, np_score: 9, np_reasons: ['noauth', 'critical'], np_class: '' });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  assert.equal(sumPoints(p), 2);
  assert.ok(linesOf(p).indexOf('These add up to 2 points, but my score for it is 9.') > -1);
  assert.equal(linesOf(p).filter(function (l) { return /^Total:/.test(l); }).length, 0);
});

/* --- D4: the exploitation timeline -------------------------------------------------------- */
function dated(panel) {
  // the dated exploitation lines, with the day each carries, in the order the panel draws them
  var pats = [
    [/^Earliest citation date: (\d{4}-\d{2}-\d{2})\./, 'citation'],
    [/^Added to VulnCheck KEV on (\d{4}-\d{2}-\d{2})\./, 'vulncheck'],
    [/^On CISA KEV since (\d{4}-\d{2}-\d{2})\./, 'cisa'],
    [/^First seen here on (\d{4}-\d{2}-\d{2}),/, 'first_seen']
  ];
  var out = [];
  linesOf(panel).forEach(function (l) {
    pats.forEach(function (pt) { var m = pt[0].exec(l); if (m) out.push({ src: pt[1], day: m[1] }); });
  });
  return out;
}

test('D4: the dated events read in date order: citation, VulnCheck, CISA, first seen here', async function () {
  var row = nk({ added: '2026-11-04', cisa_added: '2026-11-17', first_seen: '2026-11-20', event: '2026-11-20', event_src: 'first_seen',
    evidence: '2026-10-30', canary: false, ransomware: false });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  var ev = dated(p);
  assert.deepEqual(ev.map(function (e) { return e.src; }), ['citation', 'vulncheck', 'cisa', 'first_seen']);
  var days = ev.map(function (e) { return e.day; });
  assert.deepEqual(days, days.slice().sort(), 'the days ascend');
});

test('D4: CISA listing before the VulnCheck add reads first; the same day keeps VulnCheck, then CISA', async function () {
  var p1 = await panelFor({ 'cve-2026-1001': nk({ added: '2026-11-04', cisa_added: '2026-11-01', evidence: '' }) }, 'cve-cve-2026-1001');
  assert.deepEqual(dated(p1).map(function (e) { return e.src; }), ['cisa', 'vulncheck']);
  var p2 = await panelFor({ 'cve-2026-1001': nk({ added: '2026-11-04', cisa_added: '2026-11-04', evidence: '' }) }, 'cve-cve-2026-1001');
  assert.deepEqual(dated(p2).map(function (e) { return e.src; }), ['vulncheck', 'cisa']);
});

test('D4: a CVE not on CISA KEV says so after its dated events; first seen is left out when it names no new day', async function () {
  var row = nk({ added: '2026-11-04', cisa_added: '', first_seen: '2026-11-04', evidence: '' });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  assert.deepEqual(dated(p).map(function (e) { return e.src; }), ['vulncheck']);
  var ls = linesOf(p);
  assert.ok(ls.indexOf('Not on CISA KEV.') > ls.indexOf('Added to VulnCheck KEV on 2026-11-04.'));
  assert.doesNotMatch(p.textContent, /First seen here/);
});

test('D4: canary and ransomware lines show when true, and only then', async function () {
  var both = await panelFor({ 'cve-2026-1001': nk({ canary: true, ransomware: true }) }, 'cve-cve-2026-1001');
  assert.match(both.textContent, /VulnCheck's own canary network recorded exploitation of this CVE\. That is VulnCheck's flag, not a statement from CISA or the vendor\./);
  assert.match(both.textContent, /Marked as used in known ransomware campaigns, by VulnCheck's KEV data or CISA's KEV catalog\./);
  var canaryOnly = await panelFor({ 'cve-2026-1001': nk({ canary: true, ransomware: false }) }, 'cve-cve-2026-1001');
  assert.match(canaryOnly.textContent, /canary network/);
  assert.doesNotMatch(canaryOnly.textContent, /ransomware/);
  var none = await panelFor({ 'cve-2026-1001': nk({ canary: false, ransomware: false }) }, 'cve-cve-2026-1001');
  assert.doesNotMatch(none.textContent, /canary|ransomware/);
  // a string "true" is not a flag
  var str = await panelFor({ 'cve-2026-1001': nk({ canary: 'true', ransomware: 'true' }) }, 'cve-cve-2026-1001');
  assert.doesNotMatch(str.textContent, /canary|ransomware/);
});

test('D4: the cited sources are listed in the panel with their links, and the extra count shows', async function () {
  var row = nk({
    reports: [{ url: 'https://vendor.example/advisory/1', host: 'vendor.example' }, { url: 'https://blog.example.net/post', host: 'blog.example.net' },
      { url: 'http://insecure.example/x', host: 'insecure.example' }],
    reports_more: 2
  });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  var line = linesOf(p).filter(function (l) { return /^VulnCheck's cited reports:/.test(l); })[0];
  assert.ok(line, 'the sources line is there');
  assert.match(line, /vendor\.example, blog\.example\.net \+2 more in VulnCheck KEV\.$/);
  var links = [].filter.call(p.querySelectorAll('a'), function (a) { return /example/.test(a.textContent); });
  assert.deepEqual(links.map(function (a) { return a.getAttribute('href'); }), ['https://vendor.example/advisory/1', 'https://blog.example.net/post']);
  links.forEach(function (a) { assert.equal(a.rel, 'noopener noreferrer nofollow'); assert.equal(a.target, '_blank'); });
  assert.doesNotMatch(p.textContent, /insecure\.example/, 'a non-https report is not shown');
});

test('D4: the timeline, flags and sources sit under Exploitation, in that order', async function () {
  var row = nk({ added: '2026-10-31', cisa_added: '2026-11-02', canary: true, ransomware: true, reports: [{ url: 'https://vendor.example/a', host: 'vendor.example' }] });
  var p = await panelFor({ 'cve-2026-1001': row }, 'cve-cve-2026-1001');
  var ls = linesOf(p);
  var at = function (re) { return ls.findIndex(function (l) { return re.test(l); }); };
  var order = [at(/^Added to VulnCheck KEV/), at(/^On CISA KEV since/), at(/canary network/), at(/ransomware campaigns/), at(/^VulnCheck's cited reports/), at(/^NVD published/)];
  assert.ok(order.every(function (i) { return i > -1; }), JSON.stringify(order));
  assert.deepEqual(order, order.slice().sort(function (a, b) { return a - b; }));
});

/* --- D5: no repeated EPSS line ---------------------------------------------------------- */
test('D5: the "7 days before" EPSS line is absent when it equals today’s value and present when it differs', async function () {
  var same = await panelFor({ 'cve-2026-1001': nk({ epss: '0.004', epss_pre: '0.004' }) }, 'cve-cve-2026-1001');
  assert.doesNotMatch(same.textContent, /7 days before the KEV add/);
  assert.match(same.textContent, /EPSS 0\.004 \(35th percentile\)/, 'the current EPSS line stays');
  var sameFmt = await panelFor({ 'cve-2026-1001': nk({ epss: '0.004', epss_pre: '0.0040' }) }, 'cve-cve-2026-1001');
  assert.doesNotMatch(sameFmt.textContent, /7 days before the KEV add/, 'equal as numbers, written differently');
  var diff = await panelFor({ 'cve-2026-1001': nk({ epss: '0.004', epss_pre: '0.001' }) }, 'cve-cve-2026-1001');
  assert.match(diff.textContent, /7 days before the KEV add: 0\.001\./);
  var lower = await panelFor({ 'cve-2026-1001': nk({ epss: '0.001', epss_pre: '0.004' }) }, 'cve-cve-2026-1001');
  assert.match(lower.textContent, /7 days before the KEV add: 0\.004\./, 'a drop is shown too');
});

/* --- rows from before the new keys still render --------------------------------------------- */
test('old-shape rows (no event, rank or flag keys) render every section with no stray words', async function () {
  var oldNk = Object.assign({}, BASE_NKEV);
  ['event', 'event_src', 'first_seen', 'canary', 'ransomware', 'np_score', 'np_reasons', 'np_class', 'np_rank'].forEach(function (k) { delete oldNk[k]; });
  var oldCv = Object.assign({}, BASE_CVE);
  ['pick_day', 'pick_score', 'pick_reasons', 'pick_class', 'pick_seeded', 'fresh', 'fresh_score', 'fresh_reasons', 'fresh_class'].forEach(function (k) { delete oldCv[k]; });
  var pn = await panelFor({ 'cve-2026-1001': oldNk }, 'cve-cve-2026-1001');
  var pc = await panelFor({ 'cve-2026-9999': oldCv }, 'cves-cve-2026-9999');
  assert.deepEqual(headingsOf(pn), NKEV_ORDER);
  assert.deepEqual(headingsOf(pc), CVES_ORDER);
  [pn, pc].forEach(function (p) { assert.doesNotMatch(p.textContent, /undefined|NaN|\bnull\b/); });
  assert.match(pn.textContent, /Added to VulnCheck KEV on 2026-10-31\./);
  // the same rows with every new key present but empty (the exporter's shape on an unranked, undated row)
  var emptyNk = Object.assign({}, oldNk, { event: '', event_src: '', first_seen: '', canary: false, ransomware: false, np_score: 0, np_reasons: [], np_class: '', np_rank: 0 });
  var pe = await panelFor({ 'cve-2026-1001': emptyNk }, 'cve-cve-2026-1001');
  assert.deepEqual(headingsOf(pe), NKEV_ORDER);
  assert.doesNotMatch(pe.textContent, /undefined|NaN|\bnull\b|Why it ranks|canary|ransomware/);
});

/* --- T-0667 F2 (review r1, fix C): a CISA-only row was never added to VulnCheck KEV --------- */
var CISA_ONLY = { added: '2026-11-16', cisa_added: '2026-11-16', event: '2026-11-16', event_src: 'cisa', first_seen: '', reports: [], reports_more: 0, evidence: '', disclosed: '', gap: '', canary: false, ransomware: false };
test('F2 C: a CISA-only row says it is on CISA KEV and not in VulnCheck KEV as of the generated day, and never "Added to VulnCheck KEV"', async function () {
  var opts = { genAt: '2026-11-17T19:01:26Z' };
  var p = await panelFor({ 'cve-2026-1001': nk(CISA_ONLY) }, 'cve-cve-2026-1001', opts);
  var ls = linesOf(p);
  assert.ok(ls.indexOf('On CISA KEV since 2026-11-16.') > -1, ls.join(' | '));
  assert.ok(ls.indexOf('Not in VulnCheck KEV as of 2026-11-17.') > -1, ls.join(' | '));
  assert.doesNotMatch(p.textContent, /Added to VulnCheck KEV/);
  assert.doesNotMatch(p.textContent, /VulnCheck added it|NVD published it the same day VulnCheck/, 'no VulnCheck-relative gap line');
  // control: the same dates on a row VulnCheck did list (a report cited, event_src vulncheck) keep the VulnCheck line and say nothing of absence
  var c = await panelFor({ 'cve-2026-1001': nk(Object.assign({}, CISA_ONLY, { event_src: 'vulncheck', reports: [{ url: 'https://vendor.example/a', host: 'vendor.example' }] })) }, 'cve-cve-2026-1001', { genAt: opts.genAt });
  assert.match(c.textContent, /Added to VulnCheck KEV on 2026-11-16\./);
  assert.doesNotMatch(c.textContent, /Not in VulnCheck KEV/);
  // each part of the derivation is needed: a later CISA day, a cited report or a source other than cisa is not CISA-only
  [{ cisa_added: '2026-11-17', event: '2026-11-17' }, { reports_more: 3 }, { event_src: 'first_seen' }].forEach(function (o) {
    return panelFor({ 'cve-2026-1001': nk(Object.assign({}, CISA_ONLY, o)) }, 'cve-cve-2026-1001', { genAt: opts.genAt }).then(function (q) {
      assert.match(q.textContent, /Added to VulnCheck KEV on 2026-11-16\./, JSON.stringify(o));
    });
  });
});
test('F2 C mutation control: with the derivation switched off the renderer claims the VulnCheck addition, so the test above measures the derivation', async function () {
  var mutated = RENDERER.replace("return d.event_src === 'cisa' &&", "return false && d.event_src === 'cisa' &&");
  assert.notEqual(mutated, RENDERER, 'mutation anchor');
  var p = await panelFor({ 'cve-2026-1001': nk(CISA_ONLY) }, 'cve-cve-2026-1001', { genAt: '2026-11-17T19:01:26Z', renderer: mutated });
  assert.match(p.textContent, /Added to VulnCheck KEV on 2026-11-16\./);
  assert.doesNotMatch(p.textContent, /Not in VulnCheck KEV/);
});
