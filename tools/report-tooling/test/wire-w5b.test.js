'use strict';
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom'), yaml = require('js-yaml'), CW = require('../lib/check-wire');
const root = path.resolve(__dirname, '../../..');
const page = fs.readFileSync(path.join(root,'wire/index.md'),'utf8');
const includes = Object.fromEntries(fs.readdirSync(path.join(root,'_includes')).filter(n=>/^wire-/.test(n)).map(n=>[n,fs.readFileSync(path.join(root,'_includes',n),'utf8')]));
test('W5b day layout, WordPress reason, index-only nomi and keys have negative controls',()=>{
 assert.equal(CW.checkPage(page,includes).status,'PASS');
 for(const pin of ['group_by: "added"','sort: "prio"','data-sig="wp_unauth"','r.nomi == true','https://github.com/nomi-sec/PoC-in-GitHub/blob/master/','wire-chips.js','8.3%','7.0%','6.4%','123 of 244','50%','after seeing the data']) {
  assert.ok(page.includes(pin),pin); assert.equal(CW.checkPage(page.replace(pin,'removed'),includes).status,'FAIL',pin);
 }
 for(const bad of ['<div data-age-group="old">','<button data-age="recent">Recent</button>','nomi_poc']) assert.equal(CW.checkPage(page+bad,includes).status,'FAIL',bad);
 for(const name of ['legend_html','cves_legend_html']) assert.equal(CW.checkPage(page.replace('{%- capture '+name+' -%}', '{%- capture '+name+' -%}<p>50% because of the data</p>'),includes).status,'FAIL');
});
test('W5b fixture includes full and small WordPress days, context-only nomi and an admitting wp row',()=>{
 const d=yaml.load(fs.readFileSync(path.join(__dirname,'fixtures/w5b-wire.yml'),'utf8'));
 const days=Object.groupBy(d.vulns,r=>r.added);
 assert.ok(Object.values(days).some(rs=>rs.filter(r=>r.batch).length>=20));
 assert.ok(Object.values(days).some(rs=>rs.length<20));
 assert.ok(d.cves.some(r=>r.nomi&&!r.signals.includes('wp_unauth')));
 assert.ok(d.cves.some(r=>r.signals.includes('wp_unauth')));
 assert.ok(d.cves.every(r=>!r.signals.includes('nomi_poc')));
});
test('overflow fallback is native, keyboard accessible, searchable and reversible without layout APIs',()=>{
 const d=new JSDOM('<div class="hl-vuln hl-vuln--cve" data-title="test"><span class="hl-vuln__badges"><span class="hl-vuln__w">WordPress unauthenticated</span><span class="hl-vuln__sev">High</span><span class="hl-vuln__p--nomi">PoC on GitHub</span></span></div>',{runScripts:'outside-only'});
 try {const w=d.window;w.eval(fs.readFileSync(path.join(root,'assets/js/wire-chips.js'),'utf8'));const b=w.document.querySelector('button'), c=w.document.querySelector('.hl-vuln__p--nomi');
 assert.equal(b.type,'button');assert.equal(b.textContent,'+1');assert.equal(c.hidden,true);assert.match(w.document.querySelector('.hl-vuln').dataset.title,/poc on github/);
 b.click();assert.equal(b.getAttribute('aria-expanded'),'true');assert.equal(c.hidden,false);
 b.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape'}));assert.equal(c.hidden,true);assert.equal(b.getAttribute('aria-expanded'),'false');
 }finally{d.window.close();}
});
test('T-0569 the CVEs short line credits A.R.P. Syndicate for VEDAS, and losing it fails',()=>{
 assert.equal(CW.checkPage(page,includes).status,'PASS');
 const pin='&middot; VEDAS exploit maturity from <a href="https://github.com/ARPSyndicate/cve-scores" target="_blank" rel="noopener noreferrer">A.R.P. Syndicate</a> &middot; <a href="{{ \'/wire/cves.xml\'';
 assert.ok(page.includes(pin)); assert.equal(CW.checkPage(page.replace(pin,'&middot; <a href="{{ \'/wire/cves.xml\''),includes).status,'FAIL');
});
test('T-0565.2 Product exploited before filter is pinned, narrows only, and its removal fails the gate',()=>{
 assert.equal(CW.checkPage(page,includes).status,'PASS');
 for(const pin of ['data-sig="kev_product">Product exploited before','kev_product{% endif %}"','Product exploited before</dt><dd>Filter only, never admits']) {
  assert.ok(page.includes(pin),pin); assert.equal(CW.checkPage(page.replace(pin,'removed'),includes).status,'FAIL',pin);
 }
 // It never becomes an admission reason: the shared reason include does not emit it.
 assert.ok(!includes['wire-cve-why.html'].includes('"kev_product"'));
});
