'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
function fixture(phone=false){
  let table='<table><thead><tr><th>Stage</th><th>What the operator did</th></tr></thead><tbody><tr><td>Alpha</td><td>Alpha procedure detail</td></tr><tr><td>Beta</td><td>Beta procedure detail</td></tr></tbody></table>';
  table+='<table><thead><tr><th>Tactic / Technique</th><th>Procedure</th><th>Status</th><th>Confidence</th><th>Scope</th></tr></thead><tbody>'+[
    ['Discovery / T1082','Alpha procedure detail','OBSERVED','HIGH','Alpha scope'],
    ['Execution / T1059','Beta procedure detail','INFERRED','MODERATE','Beta scope'],
    ['Discovery / T1018','Unjoined procedure detail','NOT SHOWN','LOW','Unknown scope']
  ].map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  const html=['overview','victims','chain','timeline','attribution','indicators','confidence'].map(t=>`<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2><p>Original ${t} words.</p>${t==='chain'?table:''}`).join('');
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
test('stage and tactic filters intersect without inferring joins or recolouring survivors',()=>{
  const f=fixture();try{
    const colours=f.rows().map(r=>r.dataset.rvSeries);
    f.set('Stage','Alpha');assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,true]);
    f.set('Tactic','Execution');assert.ok(f.rows().every(r=>r.hidden));assert.equal(f.area.querySelector('[role=status]').textContent,'Showing 0 of 3 procedure rows');
    assert.ok(f.cards().every(c=>c.classList.contains('hl-rv-stage-muted')));
    f.area.querySelector('button').click();f.set('Tactic','Discovery');assert.deepEqual(f.rows().map(r=>r.hidden),[false,true,false]);
    assert.deepEqual(f.rows().map(r=>r.dataset.rvSeries),colours);assert.equal(colours[2],undefined);
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
