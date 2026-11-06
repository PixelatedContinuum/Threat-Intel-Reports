'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const yaml=require('js-yaml'),{JSDOM}=require('jsdom'),CW=require('../lib/check-wire');
const root=path.resolve(__dirname,'../../..'),read=p=>fs.readFileSync(path.join(root,p),'utf8');
const page=read('wire/index.md'),includes=Object.fromEntries(fs.readdirSync(path.join(root,'_includes')).filter(n=>/^wire-/.test(n)).map(n=>[n,read('_includes/'+n)]));
test('fold policy, reusable renderer and both explanation panels are gate-pinned',()=>{
 assert.equal(CW.checkPage(page,includes).status,'PASS');
 for(const pin of ['assign wp_unauth_group_min = 2','assign product_group_min = 5','id="cves-{{ gname | escape }}" data-day-target="{{ gname | escape }}"','include wire-fold-keys.html rows=group_rows mode="nkev"','include wire-fold-keys.html rows=g.items mode="cves"','include wire-fold.html rows=rendered_rows keys=fold_keys labels=fold_labels thresholds=fold_thresholds','I fold two or more WordPress plugin CVEs admitted only by the no login rule','fold five or more same-day CVEs for the same product into one line'])assert.equal(CW.checkPage(page.replaceAll(pin,'removed'),includes).status,'FAIL',pin);
 // The only bare renderer outputs are HTML captured from rows audited above.
 const bad={...includes,'wire-fold.html':includes['wire-fold.html']+'{{ fold_row.vendor }}'};
 assert.equal(CW.checkPage(page,bad).status,'FAIL');
 assert.doesNotMatch(includes['wire-fold.html'],/wp_unauth|WordPress|cisa|vendor|product/);
 assert.equal((includes['wire-fold-keys.html'].match(/\| url_encode/g)||[]).length,2,'key components must encode delimiters as well as whitespace');
 assert.doesNotMatch(includes['wire-fold-keys.html'],/\| uri_escape/,'URI escaping preserves colons and can collide');
});
test('W5c fixture contains mixed-reason and singleton controls plus normalized product keys',()=>{
 const d=yaml.load(read('tools/report-tooling/test/fixtures/w5c-wire.yml'));
 const result=CW.check(d,null,Date.parse(d.generated_at));assert.equal(result.status,'PASS');assert.deepEqual(result.cveWarnings,[]);
 assert.equal(d.cves.filter(r=>r.published==='2026-11-05'&&r.signals.length===1&&r.signals[0]==='wp_unauth').length,2);
 assert.ok(d.cves.some(r=>r.signals.includes('wp_unauth')&&r.signals.includes('nuclei')));
 assert.equal(d.cves.filter(r=>r.published==='2026-11-04'&&r.signals.includes('wp_unauth')).length,1);
});
test('built W5c folds preserve members, controls, search/filter counts and anchors',{skip:!process.env.HL_W5C_SITE&&'NOT CHECKED: set HL_W5C_SITE to W5c fixture build'},async()=>{
 const dom=new JSDOM(fs.readFileSync(path.join(process.env.HL_W5C_SITE,'wire/index.html'),'utf8'),{url:'https://fixture.test/wire/#cves',runScripts:'outside-only'});
 try{const w=dom.window,d=w.document,scrolled=[];w.Element.prototype.scrollIntoView=function(){scrolled.push(this.id);};w.eval(read('assets/js/listing-filter.js'));
 const folds=[...d.querySelectorAll('#cves [data-filter-batch]')];assert.deepEqual(folds.map(b=>b.querySelectorAll('.hl-vuln').length).sort((a,b)=>a-b),[2,6]);
 for(const id of ['99997','99996'])assert.equal(d.getElementById('cves-cve-2026-'+id).closest('[data-filter-batch]'),null);
 const ids=[...d.querySelectorAll('#cves .hl-vuln')].map(r=>r.id);assert.equal(ids.length,10);assert.equal(new Set(ids).size,10);
 const s=d.querySelector('#cves input'),row=d.getElementById('cves-cve-2026-99998'),batch=row.closest('details');assert.equal(batch.open,false);
 s.value='CVE-2026-99998';s.dispatchEvent(new w.Event('input'));assert.equal(batch.open,true);assert.equal(batch.querySelector('[data-container-count]').textContent,'1');
 s.value='';s.dispatchEvent(new w.Event('input'));await new Promise(r=>w.setTimeout(r,5));
 d.querySelector('#cves button[data-sig="wp_unauth"]').click();assert.equal(batch.open,true);assert.equal(batch.querySelector('[data-container-count]').textContent,'2');
 d.querySelector('#cves button[data-sig=""]').click();batch.open=false;
 w.location.hash='#cves-cve-2026-99998';await new Promise(r=>w.setTimeout(r,10));assert.equal(batch.open,true);
 w.location.hash='#cves-2026-11-05';await new Promise(r=>w.setTimeout(r,10));assert.equal(scrolled.at(-1),'cves-2026-11-05','day anchor targets its heading');
 assert.deepEqual([...d.querySelectorAll('#vulns [data-filter-batch]')].map(b=>b.querySelectorAll('.hl-vuln').length),[20,5]);
 assert.equal(d.getElementById('cve-cve-2026-9305').closest('[data-filter-batch]'),null,'CISA member stays plain');
 for(const row of d.querySelectorAll('#vulns [data-list="cisa"]'))assert.equal(row.closest('[data-filter-batch]'),null);
 for(const row of d.querySelectorAll('#vulns .hl-vuln[data-day="2026-10-11"]'))assert.equal(row.closest('[data-filter-batch]'),null,'four-row day stays plain');
 }finally{dom.window.close();}
});
