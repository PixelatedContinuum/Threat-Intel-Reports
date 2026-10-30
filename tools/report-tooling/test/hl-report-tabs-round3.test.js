'use strict';
/* Round 3 (T-0500.1.7): sponsor placements, per-tab hues, accessible names, and the CSS contracts
   the round-3 build depends on. Behaviour tests run the real script in jsdom; the CSS and Liquid
   checks read the shipped files, because jsdom has no layout and no Jekyll. */
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM}=require('jsdom');
const root=path.join(__dirname,'../../..');
const script=fs.readFileSync(path.join(root,'assets/js/hl-report-tabs.js'),'utf8');
const css=fs.readFileSync(path.join(root,'assets/css/hl-report-tabs.css'),'utf8');
const TOKENS=['overview','victims','chain','timeline','attribution','indicators','confidence'];

function item(kind,name,tagline,logo,href){
  return `<a class="hl-rvsp__item" href="${href||'https://example.test/'+name.toLowerCase().replace(/\W+/g,'-')}" data-rv-sponsor="${kind}" data-name="${name}" data-tagline="${tagline}">${logo?`<img class="hl-rvsp__logo" src="${logo}" alt="${name}">`:''}<span class="hl-rvsp__text"><span class="hl-rvsp__name">${name}</span></span></a>`;
}
function bar(report,site){
  return '<aside class="hl-rvsp" data-rv-chrome>'
    +(report.length?'<div class="hl-rvsp__zone hl-rvsp__zone--report"><span class="hl-rvsp__label">Sponsored by</span><div class="hl-rvsp__items">'+report.join('')+'</div></div>':'')
    +(site.length?'<div class="hl-rvsp__zone hl-rvsp__zone--site"><span class="hl-rvsp__label">Supported by</span><div class="hl-rvsp__items">'+site.join('')+'</div></div>':'')
    +'</aside>';
}
function page(sponsors,phone=false){
  const table='<table><thead><tr><th>Stage</th><th>What the operator did</th></tr></thead><tbody><tr><td>Alpha</td><td>Alpha procedure detail</td></tr></tbody></table>'
    +'<table><thead><tr><th>Tactic / Technique</th><th>Procedure</th><th>Status</th><th>Confidence</th><th>Scope</th></tr></thead><tbody><tr><td>Discovery / T1082</td><td>Alpha procedure detail</td><td>OBSERVED</td><td>HIGH</td><td>Alpha scope</td></tr></tbody></table>';
  const html=TOKENS.map(t=>`<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2><p>Original ${t} words.</p>${t==='chain'?table:''}`).join('');
  const dom=new JSDOM('<body>'+sponsors+'<div class="hl-report-page"><div class="hl-post-header"><div class="hl-post-header__eyebrow"></div><div class="hl-quicklinks"><button class="hl-quicklink hl-quicklink--detect-btn" id="hl-detect-tab"><span class="hl-quicklink__label">Detections</span></button><a class="hl-quicklink" href="/x"><span class="hl-quicklink__label">IOC Feed</span></a><button class="hl-quicklink hl-quicklink--stix-btn" id="hl-stix-tab"><span class="hl-quicklink__label">STIX</span></button></div></div><div class="hl-post-body"><div class="hl-post-content">'+html+'</div></div></div></body>',{url:'https://example.test/report/',runScripts:'outside-only'});
  const w=dom.window;w.matchMedia=()=>({matches:phone,addEventListener(){}});w.ResizeObserver=class{observe(){}};w.HTMLElement.prototype.scrollIntoView=function(){};
  const original=w.document.querySelector('.hl-post-content').textContent.replace(/\s+/g,' ').trim();
  w.eval(script);assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'));
  return {dom,w,d:w.document,original};
}
const REPORT=[item('report','Report Sponsor Co','Report tagline','/r.svg')];
const SITE=[item('site','Hunt.io','Monthly tagline','/m1.png')];
const SITE3=[item('site','Monthly One','t1','/m1.png'),item('site','Monthly Two','t2','/m2.png'),item('site','Monthly Three','t3','/m3.png')];
function marks(d){return [...d.querySelectorAll('.hl-rv-sponsor-mark')];}
function names(el){return [...el.querySelectorAll('.hl-rv-sponsor-card__name')].map(n=>n.textContent);}

test('the report sponsor owns the reading-line mark and the tab-foot cards; the Monthly sponsor never appears beside it',()=>{
  const f=page(bar(REPORT,SITE));try{
    assert.equal(marks(f.d).length,1);
    const m=marks(f.d)[0];assert.ok(m.classList.contains('is-report'));assert.equal(m.querySelector('.hl-rv-sponsor-mark__label').textContent,'Sponsored by');
    assert.match(m.getAttribute('aria-label'),/Report Sponsor Co/);assert.doesNotMatch(m.getAttribute('aria-label'),/Hunt/);
    assert.equal(m.closest('.hl-rv-mobile-line')!==null,true);assert.equal(m.getAttribute('rel'),'noopener noreferrer');assert.equal(m.target,'_blank');
    for(const t of TOKENS){
      const panel=f.d.getElementById('tab-'+t),card=panel.querySelector('.hl-rv-sponsor-card');
      assert.ok(card,'card on '+t);assert.deepEqual(names(card),['Report Sponsor Co']);
      assert.equal(card.nextElementSibling.classList.contains('hl-rv-nextprev')||card.nextElementSibling.classList.contains('hl-rv-teardown-controls'),true);
      assert.ok(card.compareDocumentPosition(panel.querySelector('.hl-rv-nextprev'))&f.w.Node.DOCUMENT_POSITION_FOLLOWING,'card before the previous/next cards');
    }
  }finally{f.w.close();}
});
test('with no report sponsor the Monthly sponsors fill the card and one of them, never two, sits on the reading line',()=>{
  const f=page(bar([],SITE3));try{
    assert.equal(marks(f.d).length,1);assert.equal(marks(f.d)[0].querySelector('.hl-rv-sponsor-mark__label').textContent,'Supported by');
    assert.deepEqual(names(f.d.getElementById('tab-overview')),['Monthly One','Monthly Two','Monthly Three']);
    const first=marks(f.d)[0].getAttribute('aria-label');
    f.d.getElementById('tabbtn-victims').click();assert.equal(marks(f.d).length,1);assert.notEqual(marks(f.d)[0].getAttribute('aria-label'),first,'Monthly sponsors take turns by tab');
  }finally{f.w.close();}
});
test('sponsor chrome is excluded from the report text, survives a one-page round trip before the cards, and a page with no sponsors gets none',async()=>{
  const f=page(bar(REPORT,SITE));try{
    f.w.location.hash='#one-page';await new Promise(r=>f.w.setTimeout(r,20));
    const clone=f.d.querySelector('.hl-post-content').cloneNode(true);clone.querySelectorAll('[data-rv-chrome]').forEach(e=>e.remove());
    assert.equal(clone.textContent.replace(/\s+/g,' ').trim(),f.original);
    f.w.location.hash='#tab-chain';await new Promise(r=>f.w.setTimeout(r,20));
    const panel=f.d.getElementById('tab-chain'),kids=[...panel.children],src=kids.findIndex(k=>k.classList.contains('hl-rv-source')),card=kids.findIndex(k=>k.classList.contains('hl-rv-sponsor-card')),np=kids.findIndex(k=>k.classList.contains('hl-rv-nextprev'));
    assert.ok(src>=0&&src<card&&card<np,'source blocks stay before the card after switching back from one page');
    assert.ok([...f.d.querySelectorAll('.hl-rv-sponsor-card,.hl-rv-sponsor-mark')].every(e=>e.hasAttribute('data-rv-chrome')));
  }finally{f.w.close();}
  const none=page('');try{assert.equal(none.d.querySelectorAll('.hl-rv-sponsor-card,.hl-rv-sponsor-mark').length,0);}finally{none.w.close();}
});
test('every tab, panel, card and the bar carry one hue token, and the header actions use the site button recipe with one colour per kind',()=>{
  const f=page(bar([],SITE));try{
    TOKENS.forEach(t=>{assert.equal(f.d.getElementById('tabbtn-'+t).dataset.rvHue,t);assert.equal(f.d.getElementById('tab-'+t).dataset.rvHue,t);});
    assert.equal(new Set(TOKENS.map(t=>f.d.getElementById('tabbtn-'+t).dataset.rvHue)).size,7);
    assert.equal(f.d.querySelector('.hl-rv-bar').dataset.rvHue,'overview');f.d.getElementById('tabbtn-chain').click();assert.equal(f.d.querySelector('.hl-rv-bar').dataset.rvHue,'chain');
    assert.ok([...f.d.querySelectorAll('.hl-rv-nextprev a')].every(a=>TOKENS.includes(a.dataset.rvHue)));
    const q=[...f.d.querySelectorAll('.hl-quicklink')];assert.ok(q.every(a=>a.classList.contains('hl-cta')));
    assert.deepEqual(q.map(a=>a.style.getPropertyValue('--acc')),['#4ade80','#f87171','#22d3ee']);
    assert.ok(f.d.querySelector('.hl-share-btn').classList.contains('hl-cta--ghost'));
    TOKENS.forEach(t=>assert.match(css,new RegExp('\\[data-rv-hue="'+t+'"\\] \\{ --acc: var\\(--rv-hue-'+t+'\\); \\}')));
  }finally{f.w.close();}
});
test('F2: aria-label sits only on elements that can carry one',()=>{
  const f=page(bar([],SITE));try{
    const generic=[...f.d.querySelectorAll('[aria-label]')].filter(e=>/^(DIV|SPAN|P|ARTICLE|LI|UL|SECTION)$/.test(e.tagName)&&!e.getAttribute('role'));
    assert.deepEqual(generic.map(e=>e.className),[],'every generic element with an aria-label has a role');
    assert.ok([...f.d.querySelectorAll('.hl-rv-mini')].every(e=>e.getAttribute('role')==='img'));
    assert.ok(f.d.querySelector('.hl-rv-stage-ribbon').getAttribute('role')==='group');
  }finally{f.w.close();}
});

test('CSS: removed tokens are gone from every theme block, the old strip is hidden, and the pill anchor rule keeps the sticky first column',()=>{
  for(const token of ['--rv-nav','--rv-tab:','--rv-boundary','--rv-accent','--rv-selected-ink'])assert.equal(css.includes(token),false,token+' removed');
  assert.match(css,/body:has\(\.hl-report-page\) \.hl-sponsor-rail \{ display: none !important; \}/);
  assert.match(css,/\.hl-report-page \.hl-rv-source td\.hl-rv-cell-pill \{ position: relative; \}/);
  assert.match(css,/\.hl-report-page \.hl-rv-source-table td\.hl-rv-cell-pill:first-child \{ position: sticky; \}/);
  // the round-1 zeroing of the panel-head h2 padding (it removed the gap to the bar) must not come back
  assert.equal(/\.hl-rv-panel-head h2 \{[^}]*padding:\s*0\s*!important/.test(css),false);
  assert.equal(/max\(14px,\s*1em\)/.test(css),false,'no em-relative chrome size on a 22px content base');
});
test('CSS: desktop type follows the site scale and phones keep the 16px floor',()=>{
  assert.match(css,/@media \(min-width: 1100px\) \{ \.hl-report-page \.hl-post-content \{ font-size: 22px; \} \}/);
  assert.match(css,/\.hl-report-page \.hl-post-content \.hl-rv-source :is\(p, li, blockquote\) \{ font-size: 16px; \}/);
  assert.match(css,/\.hl-report-page \.hl-rv-source :is\(th, td\) \{ font-size: 19\.8px; \}/);
});
test('Liquid: the tabbed layout swaps the banner for the masthead bar, reads the same data, and leaves untagged pages on the old include',()=>{
  const post=fs.readFileSync(path.join(root,'_layouts/post.html'),'utf8');
  assert.ok(post.includes('{% if hl_tabbed %}{% include report-sponsor-bar.html %}{% else %}{% include sponsor-banner.html %}{% endif %}\n<div class="hl-post-body">'));
  const inc=fs.readFileSync(path.join(root,'_includes/report-sponsor-bar.html'),'utf8');
  assert.ok(inc.includes('page.sponsored_by | join: "|;sep;|" | split: "|;sep;|"'),'same normalisation as sponsor-banner.html');
  assert.ok(inc.includes('where: "tier", "monthly" | where: "active", true'),'same Monthly filter as the rail and the footer');
  assert.ok(inc.includes('data-rv-chrome data-pagefind-ignore'));assert.equal(/<script|onclick=|tracking|utm_/.test(inc.replace(/\{%-? comment -%\}[\s\S]*?\{%-? endcomment -%\}/g,'')),false);
});
