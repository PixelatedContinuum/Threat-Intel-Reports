'use strict';
const test=require('node:test'), assert=require('node:assert/strict'), fs=require('fs'), path=require('path');
const yaml=require('js-yaml'), {JSDOM}=require('jsdom'), CW=require('../lib/check-wire');
const root=path.resolve(__dirname,'../../..');
const fixture=yaml.load(fs.readFileSync(path.join(__dirname,'fixtures/w5b-wire.yml'),'utf8'));
test('T-0565 complete contract fixture and invalid-field controls',()=>{
 const check=d=>CW.check(d,null,Date.parse(d.generated_at));
 const r=check(fixture);assert.equal(r.status,'PASS');assert.deepEqual(r.vulnWarnings,[]);assert.deepEqual(r.cveWarnings,[]);
 assert.equal(fixture.vulns.length,46);assert.equal(fixture.cves.length,7);
 const bad=structuredClone(fixture);bad.vulns[0].age_group='old';bad.vulns[1].prio=bad.vulns[0].prio;bad.vulns_counts.age_mid=0;bad.vulns_counts.batches[0].n=19;
 const w=check(bad).vulnWarnings.join(' ');for(const p of [/age_group/,/unique rank/,/age_mid/,/fewer than 20/])assert.match(w,p);
 const retired=structuredClone(fixture);retired.cves[0].signals.push('crit_noauth_kev_product');assert.equal(check(retired).status,'FAIL');
});
test('T-0565 rendered groups, batches, filters, priorities, chips and both anchor forms', {skip:process.env.HL_ARMS_SITE?false:'NOT CHECKED: set HL_ARMS_SITE to the Jekyll contract fixture build'},async()=>{
 const dom=new JSDOM(fs.readFileSync(path.join(process.env.HL_ARMS_SITE,'wire/index.html'),'utf8'),{url:'https://fixture.test/wire/#vulns',runScripts:'outside-only'});
 try{
 const w=dom.window,d=w.document;let scrolled=[];w.Element.prototype.scrollIntoView=function(){scrolled.push(this.id);};
 w.eval(fs.readFileSync(path.join(root,'assets/js/listing-filter.js'),'utf8'));
 const groups=[...d.querySelectorAll('[data-wire-layout="days"]')];assert.ok(groups.length>=3);assert.deepEqual(groups.map(g=>g.querySelector('h2').id),[...groups.map(g=>g.querySelector('h2').id)].sort().reverse());
 groups.forEach(g=>{const ranks=[...g.querySelectorAll('.hl-vuln')].map(r=>+r.dataset.prio);assert.deepEqual(ranks,[...ranks].sort((a,b)=>a-b));});
 const batch=d.querySelector('[data-filter-batch]');assert.equal(batch.open,false);assert.equal(batch.querySelectorAll('.hl-vuln').length,20);batch.querySelector('summary').click();assert.equal(batch.open,true);batch.querySelector('summary').click();assert.equal(batch.open,false);
 const sec=d.getElementById('vulns'), search=sec.querySelector('input'), vis=()=>[...sec.querySelectorAll('.hl-vuln')].filter(r=>r.style.display!=='none');
 search.value='CVE-2026-9207';search.dispatchEvent(new w.Event('input'));assert.equal(batch.open,true);assert.equal(vis().length,1);assert.equal(batch.querySelector('[data-container-count]').textContent,'1');
 search.value='';search.dispatchEvent(new w.Event('input'));await new Promise(r=>w.setTimeout(r,5));assert.equal(batch.open,false);
 for(const [axis,value,n] of [['list','cisa',1],['sev','critical',1],['det','et',2]]){
 sec.querySelector('button[data-'+axis+'="'+value+'"]').click();assert.equal(vis().length,n,axis);sec.querySelector('button[data-'+axis+'=""]').click();assert.equal(vis().length,46);
 }
 // A hidden row target resets only its own bar, opens its enclosing batch and scrolls.
 search.value='no match';search.dispatchEvent(new w.Event('input'));
 w.location.hash='#cve-cve-2026-9207';await new Promise(r=>w.setTimeout(r,10));assert.equal(batch.open,true);assert.equal(vis().length,46);assert.equal(scrolled.at(-1),'cve-cve-2026-9207');
 batch.open=false;w.location.hash='#vulns-2026-10-13';await new Promise(r=>w.setTimeout(r,10));assert.equal(batch.open,true);assert.equal(scrolled.at(-1),'vulns-2026-10-13');
 const c=d.getElementById('cves');for(const arm of ['nuclei','et','msf','edb','epss90','epss_vedas','wp_unauth']){c.querySelector('button[data-sig="'+arm+'"]').click();assert.equal([...c.querySelectorAll('.hl-vuln')].filter(r=>r.style.display!=='none').length,1,arm);c.querySelector('button[data-sig=""]').click();}
 assert.ok(d.querySelector('#cves-cve-2026-9020 .hl-vuln__w--kev'));assert.equal(d.querySelectorAll('[data-sig*="crit_noauth"]').length,0);
 assert.equal(d.querySelectorAll('.hl-vuln .hl-vuln__p--epss').length,53);assert.equal(d.querySelector('#cve-cve-2026-9100 .hl-vuln__p--vedas').textContent,'VEDAS 100%');assert.equal(d.querySelector('#cves-cve-2026-9001 .hl-vuln__p--vedas').textContent,'VEDAS 85%');
 }finally{dom.window.close();}
});

test('T-0565.1 per-day fold minimum is twenty',()=>{
 const template=fs.readFileSync(path.join(root,'wire/index.md'),'utf8');
 assert.match(template,/assign wp_batch_group_min = 20/);
 assert.equal((template.match(/assign wp_batch_group_min =/g)||[]).length,1);
 const rows=fixture.vulns.filter(r=>r.added==='2026-10-11');
 assert.equal(rows.length,4);assert.ok(rows.every(r=>!r.batch));
});
test('T-0565.1 folds a full day and leaves the four-row WordPress day plain', {skip:process.env.HL_ARMS_SITE?false:'NOT CHECKED: set HL_ARMS_SITE to fixture build'},()=>{
 const dom=new JSDOM(fs.readFileSync(path.join(process.env.HL_ARMS_SITE,'wire/index.html'),'utf8')); const d=dom.window.document;
 try { const folds=[...d.querySelectorAll('[data-filter-batch]')];
 assert.deepEqual(folds.map(b=>b.querySelectorAll('.hl-vuln').length),[20]);
 for(const r of fixture.vulns.filter(r=>r.added==='2026-10-11')) assert.equal(d.getElementById('cve-'+r.cve.toLowerCase()).closest('[data-filter-batch]'),null);
 const ids=[...d.querySelectorAll('#vulns .hl-vuln')].map(r=>r.id);assert.equal(ids.length,46);assert.equal(new Set(ids).size,46);
 } finally { dom.window.close(); }
});
