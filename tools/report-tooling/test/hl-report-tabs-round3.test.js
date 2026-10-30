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
test('with no report sponsor the Monthly sponsors fill the card and one of them, never two, sits on the reading line, both labelled Site sponsor',()=>{
  const f=page(bar([],SITE3));try{
    assert.equal(marks(f.d).length,1);assert.equal(marks(f.d)[0].querySelector('.hl-rv-sponsor-mark__label').textContent,'Site sponsor');assert.equal(f.d.getElementById('tab-overview').querySelector('.hl-rv-sponsor-card').getAttribute('aria-label'),'Site sponsor');
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
test('v6: every tab, menu entry and next/previous card carries its hue token, the page carries the selected tab\'s, and the header actions keep one colour per kind',()=>{
  const f=page(bar([],SITE));try{
    TOKENS.forEach(t=>{assert.equal(f.d.getElementById('tabbtn-'+t).dataset.rvHue,t);});
    assert.equal(new Set(TOKENS.map(t=>f.d.getElementById('tabbtn-'+t).dataset.rvHue)).size,7);
    const page_=f.d.querySelector('.hl-report-page');assert.equal(page_.dataset.rvHue,'overview');
    f.d.getElementById('tabbtn-chain').click();assert.equal(page_.dataset.rvHue,'chain','the page accent follows the selected tab');
    assert.ok([...f.d.querySelectorAll('.hl-rv-nextprev a')].every(a=>TOKENS.includes(a.dataset.rvHue)));
    assert.ok([...f.d.querySelectorAll('.hl-rv-menu-item[href^="#tab-"]')].every(a=>a.dataset.rvHue===a.getAttribute('href').slice(5)));
    assert.equal(f.d.querySelectorAll('.hl-rv-tile[data-rv-hue], .hl-rv-panel[data-rv-hue], .hl-rv-bar[data-rv-hue]').length,0,'the accent lives on the page, the tab, the menu entry and the card only');
    const q=[...f.d.querySelectorAll('.hl-quicklink')];assert.ok(q.every(a=>a.classList.contains('hl-cta')));
    assert.deepEqual(q.map(a=>a.style.getPropertyValue('--acc')),['#4ade80','#f87171','#22d3ee']);
    assert.ok(f.d.querySelector('.hl-share-btn').classList.contains('hl-cta--ghost'));
    for(const t of TOKENS){
      assert.match(css,new RegExp('--rv-hue-'+t+': #[0-9a-f]{6};'),'token for '+t);
      assert.match(css,new RegExp('\\[data-rv-hue="'+t+'"\\][^{]*\\{ --acc: var\\(--rv-hue-'+t+'\\); \\}'),'rule for '+t);
    }
    assert.equal(new Set(TOKENS.map(t=>css.match(new RegExp('--rv-hue-'+t+': (#[0-9a-f]{6});'))[1])).size>=6,true,'at most one repeated hue: the site has five clean section hues for seven tabs');
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

test('CSS: round-3 tokens, the old strip, the pill and the gradient and shadow looks are gone; no chrome size below 13px',()=>{
  for(const token of ['--rv-nav','--rv-tab:','--rv-boundary','--rv-accent','--rv-selected-ink','--rv-blue','--rv-series','--rv-meaning'])assert.equal(css.includes(token),false,token+' removed');
  assert.match(css,/body:has\(\.hl-report-page\) \.hl-sponsor-rail \{ display: none !important; \}/);
  assert.equal(/td\.hl-rv-cell-pill::after/.test(css),false,'no pill drawn behind a cell');
  // v6.1 (Joseph, 2026-10-30): the site's own gradient highlight is reused for the main titles only (header panel, its title text, the
  // tab title, the section header bars, the data-view bar); bodies, tab cells, the toolbar and the bands stay flat.
  const GRAD_OK=['.hl-report-page .hl-post-header','.hl-report-page .hl-post-header__title','.hl-report-page .hl-rv-panel-head','.hl-report-page .hl-post-content .hl-rv-source > h2','.hl-rv-view-summary'];
  const gradSel=[...css.matchAll(/(?:linear|radial|conic)-gradient\(/g)].map(m=>{const open=css.lastIndexOf('{',m.index),from=Math.max(css.lastIndexOf('}',open),css.lastIndexOf('*/',open)+1);return css.slice(from+1,open).trim().split(',')[0].trim();});
  assert.ok(gradSel.length>=5,'the five site-recipe header gradients are present');
  for(const sel of gradSel)assert.ok(GRAD_OK.includes(sel),'a gradient on a non-header selector: '+sel);
  assert.deepEqual([...css.matchAll(/box-shadow:\s*([^;}]+)/g)].map(m=>m[1].trim()).filter(v=>!/^none( !important)?$/.test(v)),[],'no shadows or glows');
  assert.equal(/max\(14px,\s*1em\)/.test(css),false,'no em-relative chrome size');
  const below=[...css.matchAll(/font-size:\s*(\d+(?:\.\d+)?)px/g)].map(m=>+m[1]).filter(n=>n<14);
  assert.deepEqual(below,[],'every font-size in the file is 14px or more (v6.1 micro-label floor; secondary text rides --rv-fs)');
  assert.match(css,/--rv-fs: 16px;/);assert.match(css,/--rv-fs-mono: 14px;/);
  assert.match(css,/html:has\(\.hl-report-page\) \{ --rv-pad: 16px; --rv-fs: 15px; --rv-fs-mono: 14px; \}/,'phones keep a 15px secondary floor');
  const tok=Number((css.match(/--rv-fs: (\d+)px/)||[])[1]);assert.ok(tok>=16);
  // the same floor for a min-height on a control: the 44px rule names every control kind
  assert.match(css,/:is\(button, input, select, summary, \[role="tab"\], \[data-rv-chrome\] a, \[data-rv-chrome\]:is\(a, button, input, select, summary\)\) \{ min-height: 44px; min-width: 44px; \}/);
  assert.equal(/min-height:\s*(3\d|[0-3]?\d)px/.test(css.replace(/min-height: 0\b/g,'')),false,'no control min-height below 44px (a 0 reset is allowed)');
});
test('CSS: v6.1 type is stated, not inherited: prose 18px (17px on phones), table text 16px (15px phones), mono headers 14px, tab names 17px',()=>{
  assert.match(css,/\.hl-report-page \.hl-post-content \{ width: 100%; max-width: none; min-width: 0; font-size: 18px; line-height: 1\.65;/);
  assert.match(css,/@media \(max-width: 699px\) \{[\s\S]*?\.hl-report-page \.hl-post-content \{ font-size: 17px; \}/);
  assert.match(css,/\.hl-report-page \.hl-post-content :is\(th, td\) \{\s*padding: 10px 14px !important;[^}]*font-size: var\(--rv-fs\) !important;/);
  assert.match(css,/\.hl-report-page \.hl-post-content th \{\s*font-family: var\(--rv-mono\); font-size: var\(--rv-fs-mono\) !important;/);
  assert.match(css,/\.hl-report-page \.hl-rv-tabs button \{[^}]*font-size: 17px;/);
  assert.equal(/\.hl-report-page \.hl-post-content \.hl-rv-source :is\(p, li, blockquote\) \{ font-size/.test(css),false,'prose fills its column at one stated size, with no per-element override');
});
test('CSS: the view states its own text sizes and keeps its tile notes a row under the tiles',()=>{
  assert.match(css,/\.hl-rv-tile > span:not\(\.hl-rv-tile-destination\) \{ font-size: var\(--rv-fs\);/);
  assert.match(css,/\.hl-rv-tile-destination \{[^}]*font-size: var\(--rv-fs-mono\) !important;/);
  assert.match(css,/\.hl-rv-tile-notes \{ order: -2; display: grid;/);
  assert.match(css,/@media \(max-width: 1139px\) \{\s*\.hl-rv-tile-notes \{ grid-template-columns: minmax\(0, 1fr\);[\s\S]*?\.hl-rv-tile-note__key \{ display: inline;/);
  assert.match(css,/\.hl-rv-view-summary::before \{ content: 'DATA VIEW';/);
  assert.match(css,/\.hl-rv-panel > \.hl-rv-half \{ grid-column: auto; \}/);
});
test('Liquid: the tabbed layout swaps the banner for the masthead bar, reads the same data, and leaves untagged pages on the old include',()=>{
  const post=fs.readFileSync(path.join(root,'_layouts/post.html'),'utf8');
  assert.ok(post.includes('{% if hl_tabbed %}{% include report-sponsor-bar.html part="report" %}{% else %}{% include sponsor-banner.html %}{% endif %}\n<div class="hl-post-body">'));
  assert.ok(post.includes('{% if hl_tabbed %}{% include report-sponsor-bar.html part="band" %}{% endif %}\n<div class="hl-post-header'),'the site band is the first thing in the page, before the header');
  const inc=fs.readFileSync(path.join(root,'_includes/report-sponsor-bar.html'),'utf8');
  assert.ok(inc.includes('page.sponsored_by | join: "|;sep;|" | split: "|;sep;|"'),'same normalisation as sponsor-banner.html');
  assert.ok(inc.includes('where: "tier", "monthly" | where: "active", true'),'same Monthly filter as the rail and the footer');
  assert.ok(inc.includes('data-rv-chrome data-pagefind-ignore'));assert.equal(/<script|onclick=|tracking|utm_/.test(inc.replace(/\{%-? comment -%\}[\s\S]*?\{%-? endcomment -%\}/g,'')),false);
});
