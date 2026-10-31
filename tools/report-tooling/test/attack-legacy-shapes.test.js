'use strict';
/* T-0500.1.11 (attack-legacy): a report written before the tabbed layout has no Status column in its ATT&CK table, no "What would change it"
   column in its confidence table, and names its stages and hypotheses a little differently. design-v4 E6: a dashboard view appears where its
   table parses, and no report is rewritten to fit. These tests drive the layout and the gate's mirror of it over the legacy shapes the 44
   published reports actually use (measured in tasks/runs/T-0500.1.11/attack-legacy/report.md), and drive every new verdict to PASS and to FAIL. */
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const script=fs.readFileSync(path.join(__dirname,'../../../assets/js/hl-report-tabs.js'),'utf8');
const G=require('../check-browser-report.js');

function table(headers,rows){return '<table><thead><tr>'+headers.map(c=>'<th>'+c+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>';}
function page(sections,src){
  const html=sections.map(([tok,extra],i)=>`<h2 class="hl-tab-${tok}" id="${tok}-s${i}">${tok}</h2><p>Original ${tok} words.</p>${extra||''}`).join('');
  const dom=new JSDOM('<div class="hl-report-page"><div class="hl-post-content"><p>Campaign Identifier: X</p>'+html+'</div></div>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:false,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};
  w.eval(src||script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return {w,d:w.document};
}
const A1=table(['Tactic / Technique','Name','Evidence'],[['Execution / T1059','Command and Scripting Interpreter','NSIS actions run the payload'],['Persistence / T1547.001','Registry Run Keys / Startup Folder','Run key written'],['Persistence / T1547.009','Shortcut Modification','IShellLink changes .lnk files']]);
const A1conf=table(['Tactic / Technique','Name','Conf.','Evidence'],[['Reconnaissance / T1595.002','Vulnerability Scanning','HIGH','Actuator surface'],['Reconnaissance / T1595.003','Wordlist Scanning','HIGH','Path probes']]);
const A2=table(['Tactic','Technique ID','Technique Name','Evidence','Confidence'],[['Execution','T1204.002','User Execution: Malicious File','user runs it','CONFIRMED'],['Persistence','T1053.005','Scheduled Task','task created','CONFIRMED'],['Defense Evasion','T1055.003','Thread Execution Hijacking','inject_thread','LOW']]);
const PILOT=table(['Tactic / Technique','Name','Status','Conf.','Scope'],[['Initial Access / T1190','Exploit Public-Facing Application','OBSERVED','HIGH','Agency GLPI'],['Execution / T1059.004','Unix Shell','INFERRED','LOW','host']]);
const shapes=(f)=>JSON.parse(JSON.stringify(f.w.eval(G.SHAPES_EXPR)));
const drawn=(f)=>({count:f.d.querySelectorAll('#tab-chain #procedures tbody tr').length,ids:[...f.d.querySelectorAll('#tab-chain #procedures tbody tr td:first-child')].map(e=>e.textContent.trim()),unstated:(f.d.querySelector('#hl-rv-view-chain .hl-rv-unstated')||{}).textContent||null});

test('a legacy "Tactic / Technique | Name | Evidence" table builds the chain view: every row, the tactic filter, and a note naming what is not stated',()=>{
  const f=page([['overview'],['chain',A1]]);
  try{
    const d=f.d,rows=[...d.querySelectorAll('#tab-chain #procedures tbody tr')];
    assert.equal(rows.length,3);assert.equal(d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent.includes('Stage'),true,'the missing Stage table is still stated');
    assert.match(d.querySelector('#tab-chain .hl-rv-view-summary p').textContent,/^3 ATT&CK mapping rows, status not stated$/);
    const note=d.querySelector('#hl-rv-view-chain .hl-rv-unstated').textContent;
    assert.match(note,/Not stated in this report's ATT&CK table: Status \(OBSERVED, INFERRED, NOT SHOWN\), Confidence, Scope\./);
    const labels=[...d.querySelectorAll('#hl-rv-view-chain .hl-rv-filters label')].map(l=>l.firstChild.textContent);
    assert.deepEqual(labels,['Search procedure rows'.replace('procedure','mapping'),'Tactic'],'no Status, Confidence or Stage filter with nothing behind it');
    assert.equal(d.querySelectorAll('#hl-rv-view-chain .hl-rv-status-tile').length,0,'no Status tiles: Status is never invented');
    assert.equal(d.querySelectorAll('#hl-rv-view-chain .hl-rv-observed, #hl-rv-view-chain .hl-rv-inferred, #hl-rv-view-chain .hl-rv-not-shown').length,0);
    assert.match(d.querySelector('#tab-overview .hl-rv-view-summary p').textContent,/^3 techniques · 3 mapping rows$/);
    const tactic=[...d.querySelectorAll('#hl-rv-view-chain .hl-rv-filters select')][0];
    assert.deepEqual([...tactic.options].map(o=>o.value),['','Execution','Persistence']);
  }finally{f.w.close();}
});
test('a legacy table with a Conf. column keeps a Confidence filter and says only Status and Scope are not stated',()=>{
  const f=page([['overview'],['chain',A1conf]]);
  try{
    assert.match(f.d.querySelector('#hl-rv-view-chain .hl-rv-unstated').textContent,/ATT&CK table: Status \(OBSERVED, INFERRED, NOT SHOWN\), Scope\./);
    assert.deepEqual([...f.d.querySelectorAll('#hl-rv-view-chain .hl-rv-filters label')].map(l=>l.firstChild.textContent),['Search mapping rows','Confidence','Tactic']);
  }finally{f.w.close();}
});
test('a legacy "Tactic | Technique ID | Technique Name" table builds the same view; the technique ID counted is the ID column, not the tactic',()=>{
  const f=page([['overview'],['chain',A2]]);
  try{
    assert.equal(f.d.querySelectorAll('#tab-chain #procedures tbody tr').length,3);
    assert.match(f.d.querySelector('#tab-overview .hl-rv-view-summary p').textContent,/^3 techniques · 3 mapping rows$/);
    assert.match(f.d.querySelector('#hl-rv-view-chain .hl-rv-unstated').textContent,/Status \(OBSERVED, INFERRED, NOT SHOWN\), Scope\./,'Confidence is in the table, so it is not listed');
    assert.deepEqual([...f.d.querySelectorAll('#hl-rv-view-chain .hl-rv-filters select')][1].options.length>1,true);
  }finally{f.w.close();}
});
test('a Status-bearing table is read exactly as before: Status filter and tiles, no legacy note, no legacy wording',()=>{
  const f=page([['overview'],['chain',PILOT]]);
  try{
    const d=f.d;
    assert.equal(d.querySelectorAll('#hl-rv-view-chain .hl-rv-unstated').length,0);assert.equal(d.querySelectorAll('#hl-rv-view-chain .hl-rv-status-tile').length,3);
    assert.match(d.querySelector('#tab-chain .hl-rv-view-summary p').textContent,/^0 stages, 2 procedures: 1 observed, 1 inferred$/);
    assert.match(d.querySelector('#tab-overview .hl-rv-view-summary p').textContent,/^2 techniques · 2 procedure rows$/);
    assert.deepEqual([...d.querySelectorAll('#hl-rv-view-chain .hl-rv-filters label')].map(l=>l.firstChild.textContent),['Search procedure rows','Status','Confidence','Stage','Tactic']);
  }finally{f.w.close();}
});
test('when a Status-bearing table and a legacy one are both present, the Status table wins',()=>{
  const f=page([['overview'],['chain',A1+PILOT]]);
  try{assert.equal(f.d.querySelectorAll('#tab-chain #procedures tbody tr').length,2);assert.equal(f.d.querySelectorAll('.hl-rv-unstated').length,0);}finally{f.w.close();}
});
test('a table that names Tactic but no Technique, or Techniques Observed, is not an ATT&CK table',()=>{
  const f=page([['overview'],['chain',table(['Tactic','Techniques Observed','Coverage Level'],[['Execution','T1059','High']])+table(['Rule Type','Count','MITRE Techniques Covered'],[['Sigma','4','T1059']])]]);
  try{assert.equal(f.d.querySelectorAll('#procedures').length,0);assert.match(f.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,/^View unavailable/);}finally{f.w.close();}
});
test('legacy stage, confidence and hypothesis tables build their views, and the confidence view says when "what would change it" is absent',()=>{
  const stage=table(['Stage','What happens','What defenders see'],[['0','Operator delivers a beacon','powershell.exe with a long command line'],['1','Beacon reaches the C2','HTTP to one host']]);
  const conf=table(['Finding','Confidence'],[['The builder is one operator\'s','DEFINITE'],['The host is rented','MODERATE']]);
  const conf3=table(['Finding','Confidence','What would change it'],[['One operator','MODERATE','A second tie']]);
  const hyp=table(['Hypothesis','Verdict','Ruling evidence'],[['H1: one crew','Winner','tooling'],['H2: two crews','Rejected','no tie']]);
  const f=page([['overview'],['chain',stage],['attribution',hyp],['confidence',conf]]);
  try{
    assert.equal(f.d.querySelectorAll('#tab-chain .hl-rv-stage').length,2);
    assert.equal(f.d.querySelectorAll('#hypotheses tbody tr').length,2);
    assert.equal(f.d.querySelectorAll('#judgments tbody tr').length,2);
    assert.match(f.d.querySelector('#hl-rv-view-confidence .hl-rv-unstated').textContent,/what would change each judgment/);
  }finally{f.w.close();}
  const g=page([['overview'],['confidence',conf3]]);
  try{assert.equal(g.d.querySelectorAll('#hl-rv-view-confidence .hl-rv-unstated').length,0,'the full table states it, so no note');}finally{g.w.close();}
});

// ---- the gate mirrors the layout, and checks the legacy view against its own source table ----
test('SHAPES_EXPR reads a legacy ATT&CK table: legacy, its rows, its first-column identities and the columns it does not state',()=>{
  for(const [html,rows,absent] of [[A1,3,['Status','Confidence','Scope']],[A1conf,2,['Status','Scope']],[A2,3,['Status','Scope']]]){
    const f=page([['overview'],['chain',html]]);
    try{
      const a=shapes(f).chain.attack;
      assert.equal(a.shape,true);assert.equal(a.legacy,true);assert.equal(a.rows,rows);assert.equal(a.ids.length,rows);assert.deepEqual(a.absent,absent);
      assert.equal(shapes(f).chain.shape,false,'no Stage table');
      assert.equal(shapes(f).overview.attackRows,rows,'Overview counts the legacy rows too');
    }finally{f.w.close();}
  }
  const p=page([['overview'],['chain',PILOT]]);
  try{const a=shapes(p).chain.attack;assert.equal(a.shape,true);assert.equal(a.legacy,false);assert.deepEqual(a.absent,[]);}finally{p.w.close();}
  const none=page([['overview'],['chain']]);
  try{assert.equal(shapes(none).chain.attack.shape,false);}finally{none.w.close();}
});
test('the gate and the layout agree on Overview tiles for every legacy shape (the technique ID is read from the same column)',()=>{
  for(const html of [A1,A1conf,A2]){
    const f=page([['overview'],['chain',html]]);
    try{
      const want=shapes(f).overview.tiles,got=[...f.d.querySelectorAll('#tab-overview .hl-rv-tile strong')].map(e=>e.textContent.trim());
      assert.deepEqual(got,want);assert.equal(want.length,2);
    }finally{f.w.close();}
  }
});
test('the gate checks the legacy chain card against its source table: PASS as built, FAIL on a dropped row, an altered identity, a missing note, or a note on a table that states Status',()=>{
  const f=page([['overview'],['chain',A1]]);
  try{
    const info=shapes(f).chain,fact=(over)=>Object.assign({token:'chain',line:f.d.querySelector('#tab-chain .hl-rv-view-summary p').textContent,count:0,
      notice:f.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:drawn(f)},over);
    const ok=G.cardVerdict(info,fact());assert.equal(ok.ok,true,ok.detail);assert.equal(ok.attackChecked,true);assert.match(ok.detail,/3 of 3 identities match/);
    const d0=drawn(f);
    const dropped=G.cardVerdict(info,fact({attack:{count:2,ids:d0.ids.slice(0,2),unstated:d0.unstated}}));assert.equal(dropped.ok,false);assert.match(dropped.detail,/draws 2 procedure rows, the source table has 3/);
    const swapped=G.cardVerdict(info,fact({attack:{count:3,ids:[d0.ids[0],d0.ids[1],'Impact / T1486'],unstated:d0.unstated}}));assert.equal(swapped.ok,false);assert.match(swapped.detail,/1 of 3 ATT&CK row identities differ/);
    const silent=G.cardVerdict(info,fact({attack:{count:3,ids:d0.ids,unstated:null}}));assert.equal(silent.ok,false);assert.match(silent.detail,/does not say so/);
    const partial=G.cardVerdict(info,fact({attack:{count:3,ids:d0.ids,unstated:'Not stated in this report\'s ATT&CK table: Status.'}}));assert.equal(partial.ok,false);assert.match(partial.detail,/does not name Confidence, Scope/);
    const unread=G.cardVerdict(info,fact({attack:{count:undefined}}));assert.equal(unread.notChecked,true,'a view that was not read is not a pass');
    // a table that states Status carries no note
    const p=page([['overview'],['chain',PILOT]]);
    try{
      const pinfo=shapes(p).chain,pd=drawn(p);
      const pf=(a)=>({token:'chain',line:p.d.querySelector('#tab-chain .hl-rv-view-summary p').textContent,count:0,notice:p.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:a});
      assert.equal(G.cardVerdict(pinfo,pf(pd)).ok,true);
      assert.equal(G.cardVerdict(pinfo,pf({count:pd.count,ids:pd.ids,unstated:'Not stated in this report\'s ATT&CK table: Status.'})).ok,false);
      assert.equal(G.cardVerdict(pinfo,pf({count:1,ids:pd.ids.slice(0,1),unstated:null})).ok,false,'a Status-bearing table that lost a row');
    }finally{p.w.close();}
  }finally{f.w.close();}
});
test('a report with no ATT&CK table draws none: rows from nothing FAIL, none PASS',()=>{
  const f=page([['overview'],['chain']]);
  try{
    const info=shapes(f).chain;const fact=(a)=>({token:'chain',line:'0 stages',count:0,notice:f.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:a});
    assert.equal(G.cardVerdict(info,fact({count:0,ids:[],unstated:null})).ok,true);
    assert.equal(G.cardVerdict(info,fact({count:4,ids:[],unstated:null})).ok,false);
  }finally{f.w.close();}
});
test('CONTROL: the gate\'s own "drop the last source row" mutation of the layout makes the legacy chain card FAIL, and the real layout passes it',()=>{
  const mut=G.mutatedTabsScript([G.MUT_DROP_SOURCE_ROW]);assert.ok(mut,'the layout still contains the text the control changes');
  const check=(src)=>{const f=page([['overview'],['chain',A2]],src);try{
    const info=shapes(f).chain;
    return G.cardVerdict(info,{token:'chain',line:f.d.querySelector('#tab-chain .hl-rv-view-summary p').textContent,count:0,notice:f.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:drawn(f)});
  }finally{f.w.close();}};
  assert.equal(check(null).ok,true);
  const bad=check(mut);assert.equal(bad.ok,false);assert.match(bad.detail,/draws 2 procedure rows, the source table has 3/);
});
test('the layout and the gate agree on a legacy table that is irregular: Overview reports it, the view is unavailable',()=>{
  const ragged=A1.replace('<td>Run key written</td>','');
  const f=page([['overview'],['chain',ragged]]);
  try{
    const s=shapes(f);assert.equal(s.chain.attack.shape,false);assert.ok(s.overview.irregular.some(x=>x.view==='chain (procedure table)'),JSON.stringify(s.overview.irregular));
    assert.equal(f.d.querySelectorAll('#procedures').length,0);
  }finally{f.w.close();}
});
test('hypothesis and confidence tables with the legacy wording are read by the gate the same way the layout reads them',()=>{
  const hyp=table(['Hypothesis','Likelihood','Why ruled'],[['False flag','LOW','no plant artifacts'],['Single crew','HIGH','tooling']]);
  const conf=table(['Claim','Confidence','Basis'],[['DLS is run by X','DEFINITE (96%)','two Tier-1 sources']]);
  const f=page([['overview'],['attribution',hyp],['confidence',conf]]);
  try{
    const s=shapes(f);assert.equal(s.attribution.shape,true);assert.equal(s.attribution.rows,2);assert.equal(s.confidence.shape,true);assert.equal(s.confidence.rows,1);
    assert.equal(f.d.querySelectorAll('#hypotheses tbody tr').length,2);assert.equal(f.d.querySelectorAll('#judgments tbody tr').length,1);
  }finally{f.w.close();}
});
test('a tab with two legacy ATT&CK tables: the view lists the larger and says how many tables and rows it leaves out; the gate requires that sentence',()=>{
  const small=table(['Tactic','Technique ID','Technique Name','Evidence','Confidence'],[['Execution','T1204.002','User Execution','a','HIGH'],['Persistence','T1053.005','Scheduled Task','b','HIGH']]);
  const f=page([['overview'],['chain',small+A2]]);
  try{
    assert.equal(f.d.querySelectorAll('#tab-chain #procedures tbody tr').length,3,'the larger table is listed');
    const note=drawn(f).unstated;assert.match(note,/This tab has 1 other ATT&CK mapping table \(2 rows\) that this view does not list/);
    const a=shapes(f).chain.attack;assert.deepEqual(a.others,[2]);assert.equal(a.rows,3);
    const fact=(u)=>({token:'chain',line:'3 ATT&CK mapping rows, status not stated',count:0,notice:f.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:Object.assign(drawn(f),{unstated:u})});
    const info=shapes(f).chain;
    assert.equal(G.cardVerdict(info,fact(note)).ok,true);
    const silent=G.cardVerdict(info,fact(note.replace(/ This tab has.*$/,'')));assert.equal(silent.ok,false);assert.match(silent.detail,/does not say how many it leaves out/);
  }finally{f.w.close();}
  const g=page([['overview'],['chain',A2]]);
  try{
    const a=shapes(g).chain.attack;assert.deepEqual(a.others,[]);
    const v=G.cardVerdict(shapes(g).chain,{token:'chain',line:'x',count:0,notice:g.d.querySelector('#hl-rv-view-chain .hl-rv-unavailable').textContent,ids:null,tiles:null,attack:Object.assign(drawn(g),{unstated:drawn(g).unstated+' This tab has 1 other ATT&CK mapping table (9 rows) that this view does not list.'})});
    assert.equal(v.ok,false);assert.match(v.detail,/source has none/);
  }finally{g.w.close();}
});
