'use strict';
/* T-0500.1.9 (sitefix2): a report that is not the pilot. The layout builds only the tabs that hold a section, and the browser gate's
   verdicts treat a table or sentence shape the report lacks as a notice (J5), not a failure, while a shape the report has whose view is
   wrong still FAILS. Each verdict is driven to PASS and to FAIL here so none of them is a row that cannot fail. */
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
const G=require('../check-browser-report.js');

function table(headers,rows){return '<table><thead><tr>'+headers.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';}
function page(sections,phone){
  const html=sections.map(([tok,extra],i)=>`<h2 class="hl-tab-${tok}" id="${tok}-s${i}">${tok}</h2><p>Original ${tok} words.</p>${extra||''}`).join('');
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>'+html+'</div></div>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:!!phone,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};
  w.eval(script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return {dom,w,d:w.document};
}
const ALL=['overview','victims','chain','timeline','attribution','indicators','confidence'];

test('a report that tags five tabs builds five tabs and five panels, each holding a section, in the fixed order',()=>{
  const f=page([['overview'],['chain'],['attribution'],['indicators'],['confidence']]);
  try{
    const tabs=[...f.d.querySelectorAll('[role=tab]')].map(t=>t.id),panels=[...f.d.querySelectorAll('[role=tabpanel]')].map(p=>p.id);
    assert.deepEqual(tabs,['tabbtn-overview','tabbtn-chain','tabbtn-attribution','tabbtn-indicators','tabbtn-confidence']);
    assert.deepEqual(panels,['tab-overview','tab-chain','tab-attribution','tab-indicators','tab-confidence']);
    f.d.querySelectorAll('[role=tabpanel]').forEach(p=>assert.ok(p.querySelector(':scope > .hl-rv-source'),p.id+' holds a section'));
    assert.equal(f.d.getElementById('tab-victims'),null);assert.equal(f.d.getElementById('tabbtn-timeline'),null);
    // the Sections menu lists the five tabs and one-page, and no link to a tab that was not built
    const hrefs=[...f.d.querySelectorAll('.hl-rv-menu a.hl-rv-menu-item')].map(a=>a.getAttribute('href'));
    assert.deepEqual(hrefs,['#tab-overview','#tab-chain','#tab-attribution','#tab-indicators','#tab-confidence','#one-page']);
    // the previous/next cards wrap among the five
    const cards=[...f.d.querySelectorAll('#tab-overview .hl-rv-nextprev a')].map(a=>a.getAttribute('href'));
    assert.deepEqual(cards,['#tab-confidence','#tab-chain']);
  }finally{f.w.close();}
});
test('keyboard arrows, Home and End move among the tabs that exist',()=>{
  const f=page([['overview'],['chain'],['indicators']]);
  try{
    const key=(el,k)=>el.dispatchEvent(new f.w.KeyboardEvent('keydown',{key:k,bubbles:true,cancelable:true}));
    const sel=()=>f.d.querySelector('[role=tab][aria-selected=true]').id;
    assert.equal(sel(),'tabbtn-overview');
    key(f.d.getElementById('tabbtn-overview'),'ArrowLeft');assert.equal(sel(),'tabbtn-indicators');
    key(f.d.getElementById('tabbtn-indicators'),'ArrowRight');assert.equal(sel(),'tabbtn-overview');
    key(f.d.getElementById('tabbtn-overview'),'End');assert.equal(sel(),'tabbtn-indicators');
    key(f.d.getElementById('tabbtn-indicators'),'Home');assert.equal(sel(),'tabbtn-overview');
  }finally{f.w.close();}
});
test('an old link to a tab this report does not have opens the first tab; a link to a tab it has opens that tab',()=>{
  const f=page([['overview'],['chain'],['indicators']]);
  try{
    const sel=()=>f.d.querySelector('[role=tab][aria-selected=true]').id;
    f.w.location.hash='#tab-indicators';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));assert.equal(sel(),'tabbtn-indicators');
    f.w.location.hash='#tab-victims';f.w.dispatchEvent(new f.w.HashChangeEvent('hashchange'));assert.equal(sel(),'tabbtn-overview');
    assert.equal(f.d.querySelectorAll('[role=tabpanel]:not([hidden])').length,1);
  }finally{f.w.close();}
});
test('the pilot shape keeps all seven tabs',()=>{
  const f=page(ALL.map(t=>[t]));
  try{assert.deepEqual([...f.d.querySelectorAll('[role=tab]')].map(t=>t.id),ALL.map(t=>'tabbtn-'+t));}finally{f.w.close();}
});
test('an overview with nothing to tile still states a summary line, and says the view is unavailable',()=>{
  const f=page([['overview'],['chain']]);
  try{
    const line=f.d.querySelector('#tab-overview .hl-rv-view-summary p').textContent;
    assert.ok(line.length>0);assert.match(f.d.querySelector('#hl-rv-view-overview .hl-rv-unavailable').textContent,/^View unavailable: needs /);
  }finally{f.w.close();}
});
test('the overview line labels each tile by what it is, not by its position, when an earlier tile is absent',()=>{
  const attack=table(['Tactic / Technique','Procedure','Status','Confidence','Scope'],[['Discovery / T1082','p','OBSERVED','HIGH','s'],['Execution / T1059','q','INFERRED','LOW','t']]);
  const f=page([['overview'],['chain',attack]]);
  try{
    const line=f.d.querySelector('#tab-overview .hl-rv-view-summary p').textContent;
    assert.match(line,/^2 techniques · 2 procedure rows$/);assert.doesNotMatch(line,/organisations/);
  }finally{f.w.close();}
});

// ---- the gate's own verdicts ----
test('SHAPES_EXPR reads the report\'s source tables: a shape present is true, one absent is false, per tab',()=>{
  const victims=table(['Organisation','Grade','Qualifier'],[['A','ACCESS SHOWN','x']]);
  const f=page([['overview'],['victims',victims],['chain'],['indicators']]);
  try{
    const s=JSON.parse(JSON.stringify(f.w.eval(G.SHAPES_EXPR)));
    assert.equal(s.victims.shape,true);assert.equal(s.victims.tab,true);
    assert.equal(s.chain.shape,false);assert.equal(s.timeline.tab,false);assert.equal(s.timeline.shape,false);
    assert.equal(s.overview.shape,true,'overview reads the victims table');
    const g=page([['overview'],['chain']]);try{assert.equal(JSON.parse(JSON.stringify(g.w.eval(G.SHAPES_EXPR))).overview.shape,false);}finally{g.w.close();}
    const rows=JSON.parse(JSON.stringify(f.w.eval(G.TAB_SECTIONS_EXPR)));
    assert.deepEqual(rows.map(r=>[r.token,r.sections>0]),[['overview',true],['victims',true],['chain',true],['indicators',true]]);
  }finally{f.w.close();}
});
const NOTICE='View unavailable: needs a Stage / What the operator did table. The full report follows.';
test('viewShapeVerdict: a shape the report lacks PASSES with the notice and FAILS without it or with elements drawn from nothing',()=>{
  assert.equal(G.viewShapeVerdict('chain',false,'0 stages, 0 procedures',0,NOTICE).ok,true);
  assert.equal(G.viewShapeVerdict('chain',false,'0 stages, 0 procedures',0,null).ok,false,'no notice');
  assert.equal(G.viewShapeVerdict('chain',false,'7 stages',7,NOTICE).ok,false,'stages drawn from nothing');
  assert.equal(G.viewShapeVerdict('chain',false,'',0,NOTICE).ok,false,'no summary line');
});
test('viewShapeVerdict: a shape the report has FAILS when the view is wrong and PASSES when its figure reconciles',()=>{
  assert.equal(G.viewShapeVerdict('victims',true,'5 organisation rows',5,null).ok,true);
  assert.equal(G.viewShapeVerdict('victims',true,'4 organisation rows',5,null).ok,false,'figure differs from the rows');
  assert.equal(G.viewShapeVerdict('victims',true,'Victim grades remain in the full report',0,'View unavailable: needs an Organisation / Grade table.').ok,false,'view says missing though the table is there');
  assert.equal(G.viewShapeVerdict('victims',true,'no figure here',5,null).ok,false,'no integer');
  assert.equal(G.viewShapeVerdict('overview',true,'2 techniques · 2 procedure rows',2,null,2).ok,true,'overview reconciles the first tile, not the tile count');
  assert.equal(G.viewShapeVerdict('overview',true,'2 techniques · 9 procedure rows',3,null,9).ok,false);
  assert.equal(G.viewShapeVerdict('timeline',true,'Chronology as printed; date positions unavailable',0,'View unavailable: needs a chronology with parseable dates; original date wording is retained below.').ok,true,'the documented degrade for unparseable dates');
});
test('emptyTabsVerdict: a built tab with no section FAILS; all tabs holding a section PASS; no tab is NOT CHECKED',()=>{
  const ok=[{token:'overview',panel:true,sections:2,headed:1},{token:'chain',panel:true,sections:1,headed:1}];
  assert.equal(G.emptyTabsVerdict(ok).ok,true);
  const bad=ok.concat([{token:'victims',panel:true,sections:0,headed:0}]);
  const v=G.emptyTabsVerdict(bad);assert.equal(v.ok,false);assert.match(v.detail,/empty: victims/);
  assert.equal(G.emptyTabsVerdict([]).notChecked,true);
});
test('tabSetVsReportVerdict: the page builds exactly the tags; an extra, a missing or a mis-ordered tab FAILS; unknown tags are NOT CHECKED',()=>{
  const pt=(a)=>a.map(t=>({token:t,panel:true,sections:1,headed:1}));
  assert.equal(G.tabSetVsReportVerdict(pt(['overview','chain']),['overview','chain']).ok,true);
  assert.match(G.tabSetVsReportVerdict(pt(['overview','victims','chain']),['overview','chain']).detail,/built although no section is tagged for it: victims/);
  assert.match(G.tabSetVsReportVerdict(pt(['overview']),['overview','chain']).detail,/not built: chain/);
  assert.equal(G.tabSetVsReportVerdict(pt(['chain','overview']),['overview','chain']).ok,false);
  assert.equal(G.tabSetVsReportVerdict(pt(['overview']),null).notChecked,true);
  // Overview beyond the tags is allowed only for the campaign record (a block with no heading)
  assert.equal(G.tabSetVsReportVerdict([{token:'overview',panel:true,sections:1,headed:0},{token:'chain',panel:true,sections:1,headed:1}],['chain']).ok,true);
});
test('summarise: a NOT CHECKED row alone ends at exit 2, a FAIL beats it at exit 1, all PASS is exit 0',()=>{
  const P={name:'a',pass:true},N={name:'NOT CHECKED: b',pass:false},F={name:'c',pass:false};
  assert.deepEqual([G.summarise([P,P]).exit,G.summarise([P,P]).label],[0,'PASS']);
  assert.deepEqual([G.summarise([P,N]).exit,G.summarise([P,N]).label,G.summarise([P,N]).notChecked],[2,'NOT CHECKED',1]);
  assert.deepEqual([G.summarise([P,N,F]).exit,G.summarise([P,N,F]).label,G.summarise([P,N,F]).fail],[1,'FAIL',1]);
});
test('timelineFixtureHtml builds from a Date / Observation table only; a Stage / Time / Action table gives null',()=>{
  const chron=table(['Date','Observation','Source'],[['2026-01-01','x','y']]);
  const out=G.timelineFixtureHtml('<html>'+chron+'</html>');
  assert.ok(out);assert.equal((out.match(/Fixture observation/g)||[]).length,25);assert.equal((out.match(/<tr><td>20\d\d-/g)||[]).length,25);
  assert.match(out,/<td>Fixture<\/td><\/tr>/,'the third column is filled so every row has as many cells as headers');
  assert.equal(G.timelineFixtureHtml('<html>'+table(['Stage','Time','Action'],[['1','t','a']])+'</html>'),null);
});
