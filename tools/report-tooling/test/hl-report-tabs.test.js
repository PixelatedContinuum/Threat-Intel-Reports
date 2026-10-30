'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
function fixture(phone=false, additions={}){
  let table='<table><thead><tr><th>Stage</th><th>What the operator did</th></tr></thead><tbody><tr><td>Alpha</td><td>Alpha procedure detail</td></tr><tr><td>Beta</td><td>Beta procedure detail</td></tr></tbody></table>';
  table+='<table><thead><tr><th>Tactic / Technique</th><th>Procedure</th><th>Status</th><th>Confidence</th><th>Scope</th></tr></thead><tbody>'+[
    ['Discovery / T1082','Alpha procedure detail','OBSERVED','HIGH','Alpha scope'],
    ['Execution / T1059','Beta procedure detail','INFERRED','MODERATE','Beta scope'],
    ['Discovery / T1018','Unjoined procedure detail','NOT SHOWN','LOW','Unknown scope']
  ].map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  const html=['overview','victims','chain','timeline','attribution','indicators','confidence'].map(t=>`<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2><p>Original ${t} words.</p>${t==='chain'?table:''}${additions[t]||''}`).join('');
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-content">'+html+'</div></div>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:phone,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};
  const original=w.document.querySelector('.hl-post-content').textContent;w.eval(script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  const d=w.document,area=d.querySelector('#tab-chain .hl-rv-filters'),controls={};
  area.querySelectorAll('label').forEach(l=>{controls[l.firstChild.textContent.trim()]=l.querySelector('input,select');});
  function set(label,value){controls[label].value=value;controls[label].dispatchEvent(new w.Event('input'));}
  return {dom,w,d,area,set,original,rows:()=>[...d.querySelectorAll('#procedures tbody tr')],cards:()=>[...d.querySelectorAll('.hl-rv-stage')]};
}
test('visible chain filters constrain generated rows and highlight readable retained stages',()=>{
  const f=fixture();try{
    assert.equal(f.area.closest('details'),null);assert.equal(f.rows().length,3);
    assert.equal(f.area.querySelector('[role=status]').textContent,'Showing 3 of 3 procedure rows');
    const source=f.d.querySelector('#tab-chain .hl-rv-source'),sourceText=source.textContent;
    f.set('Status','OBSERVED');assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,true]);
    assert.equal(f.area.querySelector('[role=status]').textContent,'Showing 1 of 3 procedure rows');
    assert.ok(f.cards()[0].classList.contains('hl-rv-stage-match'));assert.ok(f.cards()[1].classList.contains('hl-rv-stage-muted'));
    assert.equal(f.cards().length,2);assert.ok(f.cards().every(c=>!c.hidden));
    assert.equal(source.textContent,sourceText);assert.equal(source.querySelectorAll('[hidden]').length,0);
    f.area.querySelector('button').click();assert.ok(f.rows().every(r=>!r.hidden));assert.ok(f.cards().every(c=>!c.classList.contains('hl-rv-stage-muted')));
  }finally{f.dom.window.close();}
});
test('stage and tactic filters intersect without inferring joins or recolouring survivors (v6: nothing carries a series colour)',()=>{
  const f=fixture();try{
    // v6 draws chart marks in the tab accent: no row or card carries a per-stage series colour any more
    assert.ok(f.rows().every(r=>r.dataset.rvSeries===undefined)&&f.cards().every(c=>c.dataset.rvSeries===undefined));
    f.set('Stage','Alpha');assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,true]);
    f.set('Tactic','Execution');assert.ok(f.rows().every(r=>r.hidden));assert.equal(f.area.querySelector('[role=status]').textContent,'Showing 0 of 3 procedure rows');
    assert.ok(f.cards().every(c=>c.classList.contains('hl-rv-stage-muted')));
    f.area.querySelector('button').click();f.set('Tactic','Discovery');assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,false]);
    assert.ok(f.rows().every(r=>r.dataset.rvSeries===undefined),'surviving rows are not recoloured');
    f.set('Search procedure rows','no such procedure');assert.ok(f.rows().every(r=>r.hidden));f.area.querySelector('button').click();assert.ok(f.rows().every(r=>!r.hidden));
  }finally{f.dom.window.close();}
});
test('phone expansion exposes filters and filtered one-page mode retains all source text',async()=>{
  const f=fixture(true);try{
    const body=f.d.querySelector('#hl-rv-view-chain');assert.equal(body.hidden,true);assert.equal(f.area.closest('.hl-rv-view-body'),body);
    f.d.querySelector('#hl-rv-toggle-chain').click();assert.equal(body.hidden,false);f.set('Status','INFERRED');f.w.location.hash='#one-page';await new Promise(r=>f.w.setTimeout(r,20));
    assert.ok(f.d.documentElement.classList.contains('hl-onepage'));const clone=f.d.querySelector('.hl-post-content').cloneNode(true);clone.querySelectorAll('[data-rv-chrome]').forEach(e=>e.remove());
    assert.equal(clone.textContent.replace(/\s+/g,' ').trim(),f.original.replace(/\s+/g,' ').trim());assert.equal(clone.querySelectorAll('tr[hidden]').length,0);
    assert.ok([...f.area.querySelectorAll('label,input,select,button,option')].every(e=>e.hasAttribute('data-rv-chrome')));
  }finally{f.dom.window.close();}
});

function table(headers,rows){return '<table><thead><tr>'+headers.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';}
const data={
 overview:'<p>Threat Level: CRITICAL</p>',
 victims:table(['Organisation','Grade','Dated evidence'],[['Alpha Org','ACCESS SHOWN','2026-10-01 exact qualifier'],['Beta Org','COMPROMISED','2026-09-01 qualification']]),
 indicators:table(['Indicator','Confidence','Action'],[['38.180.16[.]98','HIGH','Observe as printed'],['a'.repeat(64),'MODERATE','Exact hash qualifier']]),
 confidence:table(['Claim','Confidence','What would change it'],[['HIGH claim with moderate in its text','HIGH','One'],['Other','MODERATE','Two'],['Range','LOW-MODERATE','Three']]),
 chain:'<details class="hl-teardown"><summary>Technical depth</summary><p>Every original technical word stays.</p>'+table(['One','Two'],[['Retained','HIGH']])+'</details>'
};
test('primary view tables open, victim cards retain all row cells, and all views cite their table sources',()=>{
 const f=fixture(false,data);try{
   assert.equal(f.d.querySelectorAll('.hl-rv-source-footer').length,7);
   assert.ok([...f.d.querySelectorAll('.hl-rv-table-fold')].every(d=>d.open));
   assert.equal(f.d.querySelectorAll('.hl-rv-victim-card').length,2);
   assert.ok(f.d.querySelector('.hl-rv-victim-cards').textContent.includes('2026-10-01 exact qualifier'));
   assert.equal(f.d.querySelectorAll('.hl-rv-skip-view').length,7);
   assert.ok([...f.d.querySelectorAll('.hl-rv-view a')].filter(a=>a.textContent==='Read in the report').every(a=>a.getAttribute('aria-label').length>20));
 }finally{f.dom.window.close();}
});
test('source vocabulary classes preserve original cells and table/column clipboard values preserve whitespace and defanging',async()=>{
 const f=fixture(false,data);try{
   let writes=[];Object.defineProperty(f.w.navigator,'clipboard',{value:{writeText:v=>{writes.push(v);return Promise.resolve();}}});
   const source=f.d.querySelector('#tab-indicators .hl-rv-source');const t=source.querySelector('table');
   assert.ok(t.rows[1].cells[0].classList.contains('hl-rv-indicator-cell'));
   assert.ok(t.rows[1].cells[1].classList.contains('hl-rv-cell-pill'));assert.equal(t.rows[1].cells[1].innerHTML,'HIGH');
   const b=[...source.querySelectorAll('button')].find(b=>b.textContent==='Copy column');b.click();await Promise.resolve();
   assert.equal(writes[0],'Indicator\n38.180.16[.]98\n'+'a'.repeat(64));assert.equal(b.textContent,'Copied');
   assert.equal(f.d.querySelector('[aria-live=polite]').textContent,'Copied as printed.');
   const copy=[...source.querySelectorAll('button')].find(b=>b.textContent==='Copy table');copy.click();await Promise.resolve();
   assert.equal(writes[1],[...t.rows].map(r=>[...r.cells].map(c=>c.textContent).join('\t')).join('\n'));
   await new Promise(r=>f.w.setTimeout(r,1550));assert.equal(b.textContent,'Copy column');
 }finally{f.dom.window.close();}
});
test('type and exact confidence filters constrain only generated copies and do not confuse HIGH inside a claim',()=>{
 const f=fixture(false,data);try{
  const hash=[...f.d.querySelectorAll('.hl-rv-type-filters button')].find(b=>b.textContent==='Hash');hash.click();
  assert.deepEqual([...f.d.querySelectorAll('#indicators tbody tr')].map(r=>r.hidden),[true,false]);
  assert.ok([...f.d.querySelectorAll('.hl-rv-source tr')].every(r=>!r.hidden));
  const high=[...f.d.querySelectorAll('.hl-rv-distribution button')].find(b=>b.textContent==='HIGH · 1');high.click();
  assert.deepEqual([...f.d.querySelectorAll('#judgments tbody tr')].map(r=>r.hidden),[false,true,true]);
 }finally{f.dom.window.close();}
});
test('stage ribbon drives the explicit join filter, phone stage rows expand, and source teardown state survives switches',async()=>{
 const f=fixture(true,data);try{
  assert.ok([...f.d.querySelectorAll('.hl-rv-stage-detail')].every(d=>!d.open));
  f.d.querySelector('.hl-rv-stage-ribbon button').click();assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,true]);
  assert.equal(f.d.querySelector('.hl-rv-stage-detail').open,true);
  const detail=f.d.querySelector('.hl-rv-source .hl-teardown');detail.open=true;
  f.d.querySelector('#tabbtn-overview').click();f.d.querySelector('#tabbtn-chain').click();assert.equal(detail.open,true);
  const collapse=[...f.d.querySelectorAll('#tab-chain .hl-rv-teardown-controls button')].find(b=>/Collapse/.test(b.textContent));collapse.click();assert.equal(detail.open,false);
  assert.equal(detail.querySelector('.hl-rv-teardown-count').textContent,'Teardown · 1 tables · 1 rows');
 }finally{f.dom.window.close();}
});
test('one-page contents retain authored order and previous/next tab cards carry questions and time',async()=>{
 const f=fixture(false,data);try{
  assert.equal(f.d.querySelectorAll('.hl-rv-page-contents a').length,7);
  assert.equal(f.d.querySelectorAll('.hl-rv-nextprev a').length,14);
  const next=f.d.querySelector('#tab-overview .hl-rv-nextprev a[href="#tab-victims"]');assert.ok(next.textContent.includes('Who was hit'));assert.ok(next.textContent.includes('min read'));
  f.w.location.hash='#one-page';await new Promise(r=>f.w.setTimeout(r,20));assert.equal(f.d.querySelector('.hl-rv-page-contents').hidden,false);
  const clone=f.d.querySelector('.hl-post-content').cloneNode(true);clone.querySelectorAll('[data-rv-chrome]').forEach(e=>e.remove());assert.equal(clone.textContent.replace(/\s+/g,' ').trim(),f.original.replace(/\s+/g,' ').trim());
 }finally{f.dom.window.close();}
});

test('tagged newsletter guard holds visible and focusable forms until twenty seconds and while Sections is open',async()=>{
 const include=fs.readFileSync(path.join(__dirname,'../../../_includes/report-subscribe-guard.html'),'utf8');const code=include.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
 const dom=new JSDOM('<body><div class="hl-rv-bar"><button>Sections</button></div></body>',{runScripts:'outside-only'}),w=dom.window,d=w.document;
 try{
  let twenty;w.setTimeout=(callback,ms)=>{assert.equal(ms,20000);twenty=callback;};w.eval(code);
  const form=d.createElement('div');form.className='slide-in-container active';form.dataset.form='newsletter';d.body.appendChild(form);await Promise.resolve();
  assert.equal(d.documentElement.classList.contains('hl-rv-subscribe-held'),true);assert.equal(form.inert,true);
  d.documentElement.classList.add('hl-rv-menu-open');twenty();await Promise.resolve();assert.equal(form.inert,true);
  d.documentElement.classList.remove('hl-rv-menu-open');await Promise.resolve();assert.equal(form.inert,false);assert.equal(d.documentElement.classList.contains('hl-rv-subscribe-held'),false);
  d.documentElement.classList.add('hl-rv-menu-open');await Promise.resolve();assert.equal(form.inert,true);
 }finally{w.close();}
});
