'use strict';
/* T-0500.1.12 rule 3: the code-block "Copy code" button is opt-in. Only a block marked `{: .hl-copy}` under its fence gets one,
   on the untabbed layout (the inline script in _layouts/post.html) and on the tabbed one (assets/js/hl-report-tabs.js).
   The fixture is kramdown's real output shape: the IAL class lands on the OUTER div.highlighter-rouge, not on the pre
   (tasks/runs/T-0500.1.12/tool/k.md rendered with kramdown 2.5 GFM + rouge). Control: one marked and one unmarked block must
   give exactly one button, and it must belong to the marked block. */
const {test} = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const {JSDOM} = require('jsdom');
const root = path.join(__dirname, '../../..');
const tabs = fs.readFileSync(path.join(root, 'assets/js/hl-report-tabs.js'), 'utf8');
const layout = fs.readFileSync(path.join(root, '_layouts/post.html'), 'utf8');

function block(lang, marked, body) {
  return `<div class="language-${lang}${marked ? ' hl-copy' : ''} highlighter-rouge"><div class="highlight"><pre class="highlight"><code>${body}</code></pre></div></div>`;
}
const MARKED = block('yaml', true, 'title: defender rule');
const UNMARKED = block('powershell', false, 'powershell -ep bypass');

/* The untabbed script is the first <script> after `{% unless hl_tabbed %}`; it holds no Liquid. */
function untabbedScript() {
  const i = layout.indexOf('{% unless hl_tabbed %}<script>');
  assert.ok(i > 0, 'the untabbed script is where the test expects it');
  const j = layout.indexOf('</script>', i);
  const src = layout.slice(i + '{% unless hl_tabbed %}<script>'.length, j);
  assert.equal(/\{\{|\{%/.test(src), false, 'no Liquid inside the script, so it runs as written');
  return src;
}

function untabbedPage(inner) {
  const dom = new JSDOM('<body><div class="hl-post-content"><h2 id="s">A section</h2>' + inner + '</div></body>', {url: 'https://example.test/report/', runScripts: 'outside-only'});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}});
  w.ResizeObserver = class { observe() {} };
  w.IntersectionObserver = class { observe() {} disconnect() {} };
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(untabbedScript());
  return w;
}

const TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
function tabbedPage(inner) {
  const html = TOKENS.map(t => `<h2 class="hl-tab-${t}" id="${t}-source">${t}</h2><p>Original ${t} words.</p>${t === 'chain' ? inner : ''}`).join('');
  const dom = new JSDOM('<body><div class="hl-report-page"><div class="hl-post-header"><div class="hl-post-header__eyebrow"></div></div><div class="hl-post-body"><div class="hl-post-content">' + html + '</div></div></div></body>', {url: 'https://example.test/report/', runScripts: 'outside-only'});
  const w = dom.window;
  w.matchMedia = () => ({matches: false, addEventListener() {}});
  w.ResizeObserver = class { observe() {} };
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.eval(tabs);
  assert.ok(w.document.documentElement.classList.contains('hl-rv-ready'), 'the tabbed script ran');
  return w;
}

function untabbedButtons(w) { return [...w.document.querySelectorAll('.hl-post-content pre .hl-copy-btn, .hl-post-content .hl-copy-btn')].filter(b => /^Copy$/.test(b.textContent)); }
function tabbedButtons(w) { return [...w.document.querySelectorAll('button')].filter(b => b.textContent === 'Copy code'); }

test('untabbed layout: one marked and one unmarked block give exactly one button, on the marked block', () => {
  const w = untabbedPage(MARKED + UNMARKED);
  try {
    assert.equal(w.document.querySelectorAll('pre').length, 2, 'both blocks are on the page (denominator)');
    const btns = untabbedButtons(w);
    assert.equal(btns.length, 1);
    assert.match(btns[0].closest('pre').textContent, /defender rule/);
    assert.equal(w.document.querySelector('.language-powershell pre').querySelector('button'), null, 'the attacker block has no button');
  } finally { w.close(); }
});

test('tabbed layout: one marked and one unmarked block give exactly one button, on the marked block', () => {
  const w = tabbedPage(MARKED + UNMARKED);
  try {
    assert.equal(w.document.querySelectorAll('pre').length, 2, 'both blocks are on the page (denominator)');
    const btns = tabbedButtons(w);
    assert.equal(btns.length, 1);
    assert.match(btns[0].parentElement.textContent, /defender rule/);
    assert.equal(w.document.querySelector('.language-powershell pre').querySelector('button'), null, 'the attacker block has no button');
  } finally { w.close(); }
});

test('control: the old behaviour (a button on every pre) is what the marker removes, on both layouts', () => {
  // no block marked: zero buttons, the opposite of the earlier "every pre" rule
  const a = untabbedPage(UNMARKED + UNMARKED), b = tabbedPage(UNMARKED + UNMARKED);
  try { assert.equal(untabbedButtons(a).length, 0); assert.equal(tabbedButtons(b).length, 0); } finally { a.close(); b.close(); }
  // every block marked: a button on each
  const c = untabbedPage(MARKED + MARKED), d = tabbedPage(MARKED + MARKED);
  try { assert.equal(untabbedButtons(c).length, 2); assert.equal(tabbedButtons(d).length, 2); } finally { c.close(); d.close(); }
});

test('the marker is also read on a pre or code that carries the class itself (a highlighter-less build)', () => {
  const onPre = '<pre class="hl-copy"><code>defender query</code></pre>';
  const onCode = '<pre><code class="hl-copy">defender query</code></pre>';
  const none = '<pre><code>attacker command</code></pre>';
  for (const make of [untabbedPage, tabbedPage]) {
    const w = make(onPre + onCode + none);
    try {
      const n = make === untabbedPage ? untabbedButtons(w).length : tabbedButtons(w).length;
      assert.equal(n, 2);
    } finally { w.close(); }
  }
});

test('the script cache-buster moved with the change, on the tabbed branch only', () => {
  assert.match(layout, /hl-report-tabs\.js' \| relative_url \}\}\?v=20261031\.5/);
});
