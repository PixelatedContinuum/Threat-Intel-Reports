'use strict';
const test=require('node:test'), assert=require('node:assert/strict'), fs=require('fs'), path=require('path');
const yaml=require('js-yaml'), {JSDOM}=require('jsdom'), CW=require('../lib/check-wire');
const root=path.resolve(__dirname,'../../..');
const fixture=yaml.load(fs.readFileSync(path.join(__dirname,'fixtures/arms-wire.yml'),'utf8'));
test('T-0565 complete contract fixture and invalid-field controls',()=>{
 const check=d=>CW.check(d,null,Date.parse(d.generated_at));
 const r=check(fixture);assert.equal(r.status,'PASS');assert.deepEqual(r.vulnWarnings,[]);assert.deepEqual(r.cveWarnings,[]);
 assert.equal(fixture.vulns.length,26);assert.equal(fixture.cves.length,6);
 const bad=structuredClone(fixture);bad.vulns[0].age_group='old';bad.vulns[1].prio=bad.vulns[0].prio;bad.vulns_counts.age_mid=0;bad.vulns_counts.batches[0].n=19;
 const w=check(bad).vulnWarnings.join(' ');for(const p of [/age_group/,/unique rank/,/age_mid/,/fewer than 20/])assert.match(w,p);
 const retired=structuredClone(fixture);retired.cves[0].signals.push('crit_noauth_kev_product');assert.equal(check(retired).status,'FAIL');
});
test('T-0565 rendered groups, batches, filters, priorities, chips and both anchor forms', {skip:process.env.HL_ARMS_SITE?false:'NOT CHECKED: set HL_ARMS_SITE to the Jekyll contract fixture build'},async()=>{
 const dom=new JSDOM(fs.readFileSync(path.join(process.env.HL_ARMS_SITE,'wire/index.html'),'utf8'),{url:'https://fixture.test/wire/#vulns',runScripts:'outside-only'});
 try{
 const w=dom.window,d=w.document;let scrolled=[];w.Element.prototype.scrollIntoView=function(){scrolled.push(this.id);};
 w.eval(fs.readFileSync(path.join(root,'assets/js/listing-filter.js'),'utf8'));
 const groups=[...d.querySelectorAll('[data-age-group]')];assert.deepEqual(groups.map(g=>g.dataset.ageGroup),['new','mid','old','unknown']);assert.deepEqual(groups.map(g=>g.querySelector('[data-container-count]').textContent),['2','21','2','1']);
 groups.forEach(g=>{const ranks=[...g.querySelectorAll('.hl-vuln')].map(r=>+r.dataset.prio);assert.deepEqual(ranks,[...ranks].sort((a,b)=>a-b));});
 const batch=d.querySelector('[data-filter-batch]');assert.equal(batch.open,false);assert.equal(batch.querySelectorAll('.hl-vuln').length,20);batch.querySelector('summary').click();assert.equal(batch.open,true);batch.querySelector('summary').click();assert.equal(batch.open,false);
 const sec=d.getElementById('vulns'), search=sec.querySelector('input'), vis=()=>[...sec.querySelectorAll('.hl-vuln')].filter(r=>r.style.display!=='none');
 search.value='CVE-2026-9207';search.dispatchEvent(new w.Event('input'));assert.equal(batch.open,true);assert.equal(vis().length,1);assert.equal(batch.querySelector('[data-container-count]').textContent,'1');assert.equal(groups[1].querySelector('[data-container-count]').textContent,'1');
 search.value='';search.dispatchEvent(new w.Event('input'));await new Promise(r=>w.setTimeout(r,5));assert.equal(batch.open,false);
 for(const [axis,value,n] of [['list','cisa',1],['sev','critical',1],['det','et',2],['age','recent',24]]){
 sec.querySelector('button[data-'+axis+'="'+value+'"]').click();assert.equal(vis().length,n,axis);sec.querySelector('button[data-'+axis+'=""]').click();assert.equal(vis().length,26);
 }
 // A hidden row target resets only its own bar, opens its enclosing batch and scrolls.
 search.value='no match';search.dispatchEvent(new w.Event('input'));
 w.location.hash='#cve-cve-2026-9207';await new Promise(r=>w.setTimeout(r,10));assert.equal(batch.open,true);assert.equal(vis().length,26);assert.equal(scrolled.at(-1),'cve-cve-2026-9207');
 batch.open=false;w.location.hash='#vulns-2026-10-13';await new Promise(r=>w.setTimeout(r,10));assert.equal(batch.open,true);assert.equal(scrolled.at(-1),'cve-cve-2026-9200');
 const c=d.getElementById('cves');for(const arm of ['nuclei','et','msf','edb','epss90','epss_vedas']){c.querySelector('button[data-sig="'+arm+'"]').click();assert.equal([...c.querySelectorAll('.hl-vuln')].filter(r=>r.style.display!=='none').length,1,arm);c.querySelector('button[data-sig=""]').click();}
 assert.ok(d.querySelector('#cves-cve-2026-9020 .hl-vuln__w--kev'));assert.equal(d.querySelectorAll('[data-sig*="crit_noauth"]').length,0);
 assert.equal(d.querySelectorAll('.hl-vuln .hl-vuln__p--epss').length,32);assert.equal(d.querySelector('#cve-cve-2026-9100 .hl-vuln__p--vedas').textContent,'Maturity 100%');assert.equal(d.querySelector('#cves-cve-2026-9001 .hl-vuln__p--vedas').textContent,'Maturity 85%');
 }finally{dom.window.close();}
});
