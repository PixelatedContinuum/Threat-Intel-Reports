'use strict';
/* T-0500.1.10: a report whose sections all sit in ONE tab. The layout builds one tab and one panel and no Previous/Next footer (there is
   no other tab to go to), and builds no empty navigation landmark in its place. The browser gate's rows that assumed two tabs (the
   Sections menu row, the tab look row, the three box-fit controls) get a one-tab form, and each verdict is driven to PASS and to FAIL. */
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
const G=require('../check-browser-report.js');

function page(sections){
  const html=sections.map(([tok,extra],i)=>`<h2 class="hl-tab-${tok}" id="${tok}-s${i}">${tok} ${i}</h2><p>Original ${tok} words.</p>${extra||''}`).join('');
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>'+html+'</div></div>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:false,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};
  w.eval(script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return {dom,w,d:w.document};
}
const TEAR='<details class="hl-teardown"><summary>Teardown</summary><table><thead><tr><th>A</th></tr></thead><tbody><tr><td>x</td></tr></tbody></table></details>';

test('a report with every section in one tab builds one tab, one panel and no Previous/Next footer, empty or not',()=>{
  const f=page([['overview'],['overview'],['overview']]);
  try{
    assert.equal(f.d.querySelectorAll('[role=tab]').length,1);
    assert.equal(f.d.querySelectorAll('[role=tabpanel]').length,1);
    assert.equal(f.d.querySelectorAll('.hl-rv-nextprev').length,0,'no footer element at all');
    assert.equal(f.d.querySelectorAll('[aria-label="Read report in order"]').length,0);
    const panel=f.d.getElementById('tab-overview');
    assert.equal(panel.querySelectorAll(':scope > .hl-rv-source h2').length,3,'all three sections are in the one panel');
    const navs=f.w.eval(G.LANDMARK_EXPR);
    assert.ok(navs.length>0,'the page has navigation landmarks to read');
    const v=G.emptyLandmarkVerdict(navs);assert.equal(v.ok,true,v.detail);
  }finally{f.w.close();}
});
test('a report with two tabs still builds a footer, with a card for each other tab',()=>{
  const f=page([['overview'],['chain']]);
  try{
    const cards=[...f.d.querySelectorAll('#tab-overview .hl-rv-nextprev a')].map(a=>a.getAttribute('href'));
    assert.deepEqual(cards,['#tab-chain','#tab-chain']);
    assert.equal(G.emptyLandmarkVerdict(f.w.eval(G.LANDMARK_EXPR)).ok,true);
  }finally{f.w.close();}
});
test('the teardown controls and the sections keep their place in a one-tab panel, in tab view and after a one-page round trip',()=>{
  const f=page([['overview',TEAR],['overview']]);
  try{
    const panel=f.d.getElementById('tab-overview');
    const order=()=>[...panel.children].map(c=>c.className.split(' ')[0]);
    const before=order();
    assert.ok(before.includes('hl-rv-teardown-controls'));
    assert.equal(panel.querySelector('.hl-rv-teardown-controls button')!==null,true,'the expand/collapse buttons exist');
    f.w.location.hash='#one-page';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));
    assert.ok(f.d.documentElement.classList.contains('hl-onepage'));
    f.w.location.hash='#tab-overview';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));
    assert.ok(f.d.documentElement.classList.contains('hl-tabbed'));
    assert.equal(f.d.querySelectorAll('.hl-rv-nextprev').length,0);
    const heads=[...panel.querySelectorAll(':scope > .hl-rv-source h2')].map(h=>h.id);
    assert.deepEqual(heads,['overview-s0','overview-s1'],'sections back in the panel, in their order');
  }finally{f.w.close();}
});
test('the empty-landmark row FAILS on a nav with nothing in it, names it, and is NOT CHECKED when the page has no nav',()=>{
  const f=page([['overview']]);
  try{
    const panel=f.d.getElementById('tab-overview');
    const n=f.d.createElement('nav');n.className='hl-rv-nextprev';n.setAttribute('aria-label','Read report in order');panel.appendChild(n);
    const v=G.emptyLandmarkVerdict(f.w.eval(G.LANDMARK_EXPR));
    assert.equal(v.ok,false);assert.match(v.detail,/Read report in order/);assert.match(v.detail,/#tab-overview/);assert.equal(v.empty.length,1);
  }finally{f.w.close();}
  assert.equal(G.emptyLandmarkVerdict([]).notChecked,true);
  assert.equal(G.emptyLandmarkVerdict(null).ok,false);
});

function tab(o){return Object.assign({id:'tabbtn-overview',selected:true,color:'rgb(163, 113, 247)',line:'rgb(163, 113, 247)',lineW:2,dot:'rgb(163, 113, 247)',dotW:8},o||{});}
test('the tab look row with one tab measures what one tab can show, says it made no comparison, and FAILS when that is wrong',()=>{
  const v=G.tabLookVerdict([tab()]);
  assert.equal(v.notChecked,false);assert.equal(v.single,true);assert.equal(v.ok,true,v.detail);assert.match(v.detail,/no idle tab exists/);
  for(const [what,t,re] of [['not selected',tab({selected:false}),/not selected/],['no underline',tab({lineW:0,line:'rgba(0, 0, 0, 0)'}),/no underline/],['no dot',tab({dotW:0}),/no accent dot/],['clear dot',tab({dot:'rgba(0, 0, 0, 0)'}),/no accent dot/]]){
    const r=G.tabLookVerdict([t]);assert.equal(r.ok,false,what);assert.match(r.detail,re,what);
  }
  assert.equal(G.tabLookVerdict([]).notChecked,true);
});
test('the tab look row with two or more tabs is unchanged: it still needs an idle tab to compare',()=>{
  const two=[tab(),tab({id:'tabbtn-chain',selected:false,color:'rgb(150, 150, 150)',line:'rgba(0, 0, 0, 0)',lineW:0,dot:'rgb(251, 146, 60)'})];
  const v=G.tabLookVerdict(two);assert.equal(v.single,undefined);assert.equal(v.ok,true,v.detail);
  two[1].color=two[0].color;assert.equal(G.tabLookVerdict(two).ok,false);
});

test('the Sections menu row: two tabs start on the other tab; one tab starts in one-page mode, where no tab is selected, and the click must select it',()=>{
  assert.equal(G.menuStartHash('overview','chain'),'#tab-chain');
  assert.equal(G.menuStartHash('overview','overview'),'#one-page');
  assert.equal(G.menuSelectVerdict('tabbtn-chain','tabbtn-overview','overview','chain'),true);
  assert.equal(G.menuSelectVerdict('tabbtn-overview','tabbtn-overview','overview','chain'),false,'a start already on the first tab proves nothing');
  assert.equal(G.menuSelectVerdict('tabbtn-chain','tabbtn-chain','overview','chain'),false,'a selection that never moved');
  assert.equal(G.menuSelectVerdict(null,'tabbtn-overview','overview','overview'),true);
  assert.equal(G.menuSelectVerdict('tabbtn-overview','tabbtn-overview','overview','overview'),false,'one tab: a start with the tab already selected proves nothing');
  assert.equal(G.menuSelectVerdict(null,null,'overview','overview'),false,'the click selected nothing');
});
test('one-page mode of a one-tab page selects no tab, and the menu entry for the tab selects it again (what the row relies on)',()=>{
  const f=page([['overview'],['overview']]);
  try{
    const sel=()=>f.d.querySelector('[role=tab][aria-selected=true]');
    assert.ok(sel());
    f.w.location.hash='#one-page';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));
    assert.equal(sel(),null);
    assert.ok(f.d.querySelector('.hl-rv-menu a[href="#tab-overview"]'));
    f.w.location.hash='#tab-overview';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));
    assert.equal(sel().id,'tabbtn-overview');
  }finally{f.w.close();}
});

test('the box-fit controls put a footer of the layout\'s shape into a copy that has none, and nothing into a copy with no such panel',()=>{
  const f=page([['overview']]);
  try{
    assert.equal(f.d.querySelectorAll('.hl-rv-nextprev a').length,0);
    assert.equal(f.w.eval(G.BOX_INJECT_CARD_EXPR.replace('__TAB__',JSON.stringify('overview'))),true);
    const cards=[...f.d.querySelectorAll('#tab-overview .hl-rv-nextprev a')];
    assert.equal(cards.length,2);
    assert.equal(cards[0].dataset.rvHue,'overview');
    assert.ok(f.d.querySelector('#tab-overview .hl-rv-nextprev').hasAttribute('data-rv-chrome'),'marked chrome, as the layout marks what it builds: the 44px floor keys on it');
    assert.ok(cards.every(c=>c.hasAttribute('data-rv-chrome')&&c.hasAttribute('data-pagefind-ignore')));
    assert.deepEqual([...cards[0].children].map(c=>c.tagName),['SMALL','STRONG','SPAN','SMALL']);
    assert.equal(f.w.eval(G.BOX_INJECT_CARD_EXPR.replace('__TAB__',JSON.stringify('chain'))),false);
  }finally{f.w.close();}
});
