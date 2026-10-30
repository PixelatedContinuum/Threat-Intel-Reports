'use strict';
/* Design v6 (T-0500.1.7): the script's part of the panel design. The CSS draws the panels, the script only labels and wraps:
   section labels, the tile note row, the confidence bar, the pairs of short sections and the page accent. Every node it adds is
   chrome, and none of it changes a word of the report. Behaviour runs the real script in jsdom. */
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
function table(headers,rows){return '<table><thead><tr>'+headers.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';}
function sec(tok,id,title,body){return `<h2 class="hl-tab-${tok}" id="${id}">${title}</h2>${body}`;}
const LONG='2026-08-20 to 2026-10-14';
const HTML='<p>Campaign Identifier: X</p>'
  +sec('overview','s1','1. Executive Summary','<p>Original summary words.</p>')
  +sec('overview','s2','2. Scope','<p>Original scope words.</p>')
  +sec('victims','s3','3. Who Was Hit',table(['Organisation','Grade'],[['Alpha Org','ACCESS SHOWN'],['Beta Org','COMPROMISED'],['Gamma Org','REACHED']]))
  +sec('chain','s4','4. Technical Classification',table(['Stage','What the operator did'],[['Alpha','Alpha procedure detail']])+table(['Tactic / Technique','Procedure','Status','Confidence','Scope'],[['Discovery / T1082','Alpha procedure detail','OBSERVED','HIGH','Alpha scope']]))
  +sec('timeline','s6','6. Infrastructure',table(['Date','Observation'],[['2026-08-20','First'],['2026-10-14','Last']]))
  +sec('attribution','s7','7. Actor Assessment','<p>Original actor words.</p>')
  +sec('indicators','s8','8. Indicators','<p>Original indicator words.</p>')
  +sec('confidence','s9','9. Confidence Summary',table(['Claim','Confidence','What would change it'],[['One','HIGH','a'],['Two','HIGH','b'],['Three','MODERATE','c'],['Four','LOW','d']]))
  +sec('confidence','s10','10. References','<p>Original reference words.</p>')
  +sec('confidence','s11','Acknowledgements','<p>Original thanks.</p>');
function fixture(phone=false,html=HTML){
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-body"><div class="hl-post-content">'+html+'</div></div></div>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:phone,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};w.scrollTo=function(){};
  const original=w.document.querySelector('.hl-post-content').textContent.replace(/\s+/g,' ').trim();
  w.eval(script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return {dom,w,d:w.document,original};
}
function reportText(d){const c=d.querySelector('.hl-post-content').cloneNode(true);c.querySelectorAll('[data-rv-chrome]').forEach(e=>e.remove());return c.textContent.replace(/\s+/g,' ').trim();}

test('v6: each section panel carries its mono label as data (SECTION nn, APPENDIX, CAMPAIGN RECORD) and no report word changes',()=>{
  const f=fixture();try{
    const h=id=>f.d.getElementById(id);
    assert.equal(h('s1').dataset.rvSec,'SECTION 01');assert.equal(h('s4').dataset.rvSec,'SECTION 04');assert.equal(h('s10').dataset.rvSec,'SECTION 10');assert.equal(h('s11').dataset.rvSec,'APPENDIX');
    const first=f.d.querySelector('.hl-rv-source');assert.ok(first.classList.contains('hl-rv-nohead'));assert.equal(first.dataset.rvSec,'CAMPAIGN RECORD');
    assert.equal(f.d.querySelectorAll('.hl-rv-nohead').length,1,'only the block with no h2 is the campaign record');
    assert.equal(reportText(f.d),f.original);
  }finally{f.w.close();}
});
test('v6: a stat tile is number, label and destination; its "How counted" note is one cell of the row under the grid, keyed by the tile',()=>{
  const f=fixture();try{
    const tiles=f.d.querySelector('#tab-overview .hl-rv-tiles'),notes=tiles.nextElementSibling;
    assert.ok(notes&&notes.classList.contains('hl-rv-tile-notes'),'the note row follows the tile grid');
    const tl=[...tiles.querySelectorAll('.hl-rv-tile')],cells=[...notes.querySelectorAll('.hl-rv-tile-note')];
    assert.ok(tl.length>=3);assert.equal(cells.length,tl.length,'one note per tile, in tile order');
    tl.forEach((t,i)=>{
      assert.equal(t.querySelector('small'),null,'no note inside the tile');
      assert.match(cells[i].querySelector('small').textContent,/^How counted: /);
      assert.equal(cells[i].querySelector('.hl-rv-tile-note__key').textContent,t.querySelector('.hl-rv-value').textContent+' '+t.querySelector('span').textContent);
      assert.ok(cells[i].hasAttribute('data-rv-chrome')&&notes.hasAttribute('data-rv-chrome'));
    });
    const window_=tl.find(t=>/ to /.test(t.querySelector('.hl-rv-value').textContent));assert.ok(window_.querySelector('.hl-rv-value').textContent.length>8);assert.ok(window_.querySelector('.hl-rv-value').classList.contains('hl-rv-value--long'));
    assert.equal(reportText(f.d),f.original);
  }finally{f.w.close();}
});
test('v6: the confidence bar has one segment per legend button, sized by its count, sits above the legend and is hidden from assistive technology',()=>{
  const f=fixture();try{
    const body=f.d.querySelector('#hl-rv-view-confidence'),bar=body.querySelector('.hl-rv-distbar'),legend=body.querySelector('.hl-rv-distribution');
    assert.ok(bar&&legend);assert.equal(bar.nextElementSibling,legend);assert.equal(bar.getAttribute('aria-hidden'),'true');
    const segs=[...bar.children],btns=[...legend.children];
    assert.equal(segs.length,btns.length);assert.equal(btns.length,3);
    assert.deepEqual(segs.map(s=>s.style.flexGrow),['2','1','1'],'HIGH 2, MODERATE 1, LOW 1 in legend order');
    assert.ok(segs.every(s=>s.hasAttribute('data-rv-chrome')));
    btns[0].click();assert.equal(btns[0].getAttribute('aria-pressed'),'true','the legend is still the filter');
  }finally{f.w.close();}
});
test('v6: two consecutive short sections are paired; sections with a table and the campaign record never are; DOM order is unchanged',()=>{
  const f=fixture();try{
    const half=[...f.d.querySelectorAll('.hl-rv-source.hl-rv-half')].map(e=>e.querySelector('h2').id);
    assert.deepEqual(half,['s1','s2','s10','s11'],'two pairs: Executive Summary + Scope, References + Acknowledgements; every other section has a table or no short neighbour');
    const overview=[...f.d.querySelectorAll('#tab-overview > .hl-rv-source')];
    assert.equal(overview.length,3);assert.equal(overview.filter(e=>e.classList.contains('hl-rv-half')).length,2,'Executive Summary and Scope pair; the campaign record does not');
    assert.ok(overview[0].classList.contains('hl-rv-nohead')&&!overview[0].classList.contains('hl-rv-half'));
    assert.deepEqual([...f.d.querySelectorAll('.hl-rv-source > h2')].map(e=>e.id),['s1','s2','s3','s4','s6','s7','s8','s9','s10','s11']);
    assert.equal(reportText(f.d),f.original);
  }finally{f.w.close();}
});
test('v6: a failed enhancement restores the article and clears the page accent it had already set',()=>{
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-body"><div class="hl-post-content">'+HTML+'</div></div></div>',{url:'https://example.test/report/#tab-victims',runScripts:'outside-only'});
  const w=dom.window;try{
    w.matchMedia=()=>({matches:false,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.scrollTo=function(){};
    let selected=null;const proto=w.HTMLElement.prototype;
    // the cold-load hash opens a tab (the page accent is set), then focusing its panel fails
    proto.focus=function(){selected=w.document.querySelector('.hl-report-page').dataset.rvHue;throw new Error('forced failure after the page accent is set');};
    const original=w.document.querySelector('.hl-post-content').textContent;
    w.eval(script);
    assert.equal(selected,'victims','the accent was set before the failure');
    assert.equal(w.document.documentElement.classList.contains('hl-rv-ready'),false);
    assert.equal(w.document.querySelector('.hl-report-page').dataset.rvHue,undefined,'rollback clears it');
    assert.equal(w.document.querySelector('.hl-post-content').textContent,original);
  }finally{w.close();}
});
