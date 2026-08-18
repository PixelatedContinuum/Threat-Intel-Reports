'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { JSDOM } = require('jsdom');
const D = require('../../../assets/js/detection-picker.js');
const H = require('../../../assets/js/hl-hash.js');

const BODIES = [
  'import "pe"\nrule A { condition: true }',
  'rule B { condition: true }',
  'title: S1'
];

const RULES = [
  { name: 'Yara One', engine: 'yara', tier: 'Detection', fence: 0, hash: H.ruleHash(BODIES[0]) },
  { name: 'Yara Two', engine: 'yara', tier: 'Hunting', fence: 1, hash: H.ruleHash(BODIES[1]) },
  { name: 'Sig One', engine: 'sigma', tier: 'Detection', fence: 2, hash: H.ruleHash(BODIES[2]) }
];

function page(bodies) {
  const blocks = (bodies || BODIES)
    .map((b) => '<pre><code>' + b.replace(/&/g, '&amp;').replace(/</g, '&lt;') + '</code></pre>')
    .join('');
  return new JSDOM('<body><div class="hl-post-content">' + blocks + '</div></body>').window.document;
}

test('binds each rule to the fence its manifest points at', () => {
  const doc = page();
  const bound = D.bind(doc.querySelector('.hl-post-content'), RULES, doc);
  assert.strictEqual(bound.ok.length, 3);
  assert.deepStrictEqual(bound.mismatched, []);
  assert.match(bound.ok[0].body, /rule A/);
});

/* The failure this design exists to prevent. A fence count that drifts by one
   makes every later index point at the wrong rule, silently. */
test('a hash that does not match its fence is refused, not downloaded', () => {
  const doc = page();
  const shifted = RULES.map((r) => Object.assign({}, r, { fence: r.fence + 1 }));
  const bound = D.bind(doc.querySelector('.hl-post-content'), shifted, doc);
  assert.strictEqual(bound.ok.length, 0);
  assert.strictEqual(bound.mismatched.length, 3);
  assert.match(bound.mismatched[0].reason, /does not match/i);
});

/* The reason the check is a hash rather than the opening characters: YARA rules
   in this corpus open with a boilerplate comment, so several rules on a page
   share their first 48 characters and a prefix check would clear the swap. */
test('two rules sharing an opening are still told apart', () => {
  const shared = [
    '/* Yara Rule Set\n   Identifier: Alpha */\nrule A { condition: true }',
    '/* Yara Rule Set\n   Identifier: Beta */\nrule B { condition: false }'
  ];
  const doc = page(shared);
  const rules = [
    { name: 'Alpha', engine: 'yara', tier: 'Detection', fence: 0, hash: H.ruleHash(shared[0]) },
    { name: 'Beta', engine: 'yara', tier: 'Detection', fence: 1, hash: H.ruleHash(shared[1]) }
  ];
  assert.strictEqual(rules[0].hash === rules[1].hash, false, 'the fixture must not be degenerate');
  const swapped = [
    Object.assign({}, rules[0], { fence: 1 }),
    Object.assign({}, rules[1], { fence: 0 })
  ];
  const bound = D.bind(doc.querySelector('.hl-post-content'), swapped, doc);
  assert.strictEqual(bound.mismatched.length, 2, 'a swap is caught even with identical openings');
});

test('a fence index past the end of the page is refused with a reason', () => {
  const doc = page();
  const bound = D.bind(doc.querySelector('.hl-post-content'),
    [Object.assign({}, RULES[0], { fence: 99 })], doc);
  assert.strictEqual(bound.ok.length, 0);
  assert.match(bound.mismatched[0].reason, /does not exist/);
});

/* Its body lives inside an earlier bundle, so it is listed but cannot be taken
   on its own. It must not be reported as a verification failure. */
test('a cross-referenced rule is listed, not selectable, and not a mismatch', () => {
  const doc = page();
  const rules = RULES.concat([
    { name: 'Base Elsewhere', engine: 'sigma', tier: 'Hunting', cross_referenced: true }
  ]);
  const bound = D.bind(doc.querySelector('.hl-post-content'), rules, doc);
  assert.strictEqual(bound.ok.length, 3);
  assert.deepStrictEqual(bound.mismatched, []);
  assert.strictEqual(bound.crossReferenced.length, 1);
  assert.strictEqual(bound.crossReferenced[0].name, 'Base Elsewhere');
});

test('filters by engine and tier', () => {
  assert.strictEqual(D.applyFilters(RULES, { engine: 'yara', tier: null }).length, 2);
  assert.strictEqual(D.applyFilters(RULES, { engine: null, tier: 'Detection' }).length, 2);
  assert.strictEqual(D.applyFilters(RULES, { engine: 'yara', tier: 'Detection' }).length, 1);
  assert.strictEqual(D.applyFilters(RULES, { engine: null, tier: null }).length, 3);
});

/* Six fences in the corpus carry imports. yarac 4.5.5 does accept imports
   between complete rules, so this is the canonical documented form and one copy
   of each import rather than one per rule, not a rescue from a broken file. */
test('YARA bundles hoist and de-duplicate imports', () => {
  const out = D.bundle('yara', [
    { name: 'A', body: 'import "pe"\nrule A { condition: true }' },
    { name: 'B', body: 'import "pe"\nimport "math"\nrule B { condition: true }' }
  ], 'demo-slug');
  const lines = out.split('\n').filter((l) => l.trim());
  const firstRule = lines.findIndex((l) => /^rule /.test(l));
  const imports = lines.filter((l) => /^import /.test(l));
  assert.strictEqual(imports.length, 2, 'de-duplicated');
  imports.forEach((imp) => {
    assert.ok(lines.indexOf(imp) < firstRule, 'every import precedes the first rule');
  });
  assert.match(out, /rule A/);
  assert.match(out, /rule B/);
});

test('a YARA bundle with no imports gains none', () => {
  const out = D.bundle('yara', [{ name: 'A', body: 'rule A { condition: true }' }], 'demo-slug');
  assert.doesNotMatch(out, /^import /m);
});

test('Sigma bundles separate documents so the stream stays valid', () => {
  const out = D.bundle('sigma', [
    { name: 'A', body: 'title: A' },
    { name: 'B', body: 'title: B' }
  ], 'demo-slug');
  assert.strictEqual((out.match(/^---$/gm) || []).length, 1);
  assert.match(out, /title: A[\s\S]*title: B/);
});

test('Suricata bundles concatenate without separators', () => {
  const out = D.bundle('suricata', [
    { name: 'A', body: 'alert tcp any any -> any any (msg:"A"; sid:1;)' },
    { name: 'B', body: 'alert tcp any any -> any any (msg:"B"; sid:2;)' }
  ], 'demo-slug');
  assert.doesNotMatch(out, /^---$/m);
  assert.strictEqual((out.match(/^alert /gm) || []).length, 2);
});

test('every bundle carries attribution', () => {
  const out = D.bundle('suricata', [{ name: 'A', body: 'alert tcp any any -> any any (sid:1;)' }], 'demo-slug');
  assert.match(out, /The Hunters Ledger/);
  assert.match(out, /CC BY 4\.0/);
  assert.match(out, /demo-slug/);
});

test('a Sigma bundle comments its header so the YAML still parses', () => {
  const out = D.bundle('sigma', [{ name: 'A', body: 'title: A' }], 'demo-slug');
  out.split('\n').slice(0, 3).forEach((l) => {
    if (l.trim()) assert.match(l, /^#/, 'header lines must be YAML comments');
  });
});

test('filenames follow slug and engine', () => {
  assert.strictEqual(D.filenameFor('demo-slug', 'yara'), 'demo-slug-yara.yar');
  assert.strictEqual(D.filenameFor('demo-slug', 'sigma'), 'demo-slug-sigma.yml');
  assert.strictEqual(D.filenameFor('demo-slug', 'suricata'), 'demo-slug-suricata.rules');
});

/* One page renders fences two ways. A language Rouge does not highlight comes
   through as a bare pre > code under the content div; a highlighted one is
   wrapped as div.language-x > div.highlight > pre > code. Walking siblings from
   the pre finds the heading in the first shape and nothing in the second, which
   live gave 5 of 22 rules a checkbox. */
test('finds the heading and the block through a Rouge wrapper', () => {
  const doc = new JSDOM([
    '<body><div class="hl-post-content">',
    '<h4>Bare Rule</h4><p>meta</p>',
    '<pre><code>rule A { condition: true }</code></pre>',
    '<h4>Wrapped Rule</h4><p>meta</p>',
    '<div class="language-yaml"><div class="highlight"><pre class="highlight">',
    '<code class="hljs">title: B</code></pre></div></div>',
    '</div></body>'
  ].join('')).window.document;
  const root = doc.querySelector('.hl-post-content');
  const codes = [...root.querySelectorAll('pre > code')];

  assert.strictEqual(D.headingFor(codes[0], root).textContent, 'Bare Rule');
  assert.strictEqual(D.headingFor(codes[1], root).textContent, 'Wrapped Rule',
    'the wrapped shape must resolve too, or its rule gets no checkbox');

  assert.strictEqual(D.blockFor(codes[0], root).tagName, 'PRE');
  assert.strictEqual(D.blockFor(codes[1], root).className, 'language-yaml',
    'hiding must target the wrapper, or filtering leaves an empty box behind');
});

/* Filtering has to remove a whole rule and a whole dead section, not just the
   heading and the code block. On the live multivector page, filtering to
   Suricata left 81 of 104 top-level elements standing: a YARA Rules heading
   introducing nothing, both tier subheadings, and five orphaned metadata
   paragraphs with no rule above them. */
function detectionPage() {
  return new JSDOM([
    '<body><div class="hl-post-content">',
    '<p>Campaign metadata</p>',
    '<hr>',
    '<h2>Detection Coverage Summary</h2>',
    '<p>summary prose</p>',
    '<hr>',
    '<h2>YARA Rules</h2>',
    '<p>All five rules below target the payload class.</p>',
    '<h3>Detection Rules</h3>',
    '<h4>Yara One</h4>',
    '<p>Tier: Detection</p>',
    '<pre><code>rule A { condition: true }</code></pre>',
    '<hr>',
    '<h2>Suricata Signatures</h2>',
    '<p>network prose</p>',
    '<h3>Detection Rules</h3>',
    '<h4>Suri One</h4>',
    '<p>Tier: Detection</p>',
    '<pre><code>alert tcp any any -> any any (sid:1;)</code></pre>',
    '<hr>',
    '<h2>Coverage Gaps</h2>',
    '<p>gaps prose</p>',
    '<h2>License</h2>',
    '<p>licence prose</p>',
    '</div></body>'
  ].join('')).window.document;
}

function visibleText(root, shown, layout) {
  return layout.units
    .filter((u, i) => shown[i])
    .map((u) => u.el.tagName + ':' + (u.el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40));
}

test('filtering to one engine hides the other engine section entirely', () => {
  const doc = detectionPage();
  const root = doc.querySelector('.hl-post-content');
  const codes = [...root.querySelectorAll('pre > code')];
  const ok = [
    { el: codes[0], engine: 'yara', tier: 'Detection', rule: { engine: 'yara', tier: 'Detection' } },
    { el: codes[1], engine: 'suricata', tier: 'Detection', rule: { engine: 'suricata', tier: 'Detection' } }
  ];
  const layout = D.layoutUnits(root, ok);

  const shown = D.visibilityFor(layout, [1]);          // Suricata only
  const text = visibleText(root, shown, layout).join(' | ');

  assert.doesNotMatch(text, /YARA Rules/, 'the dead engine heading goes');
  assert.doesNotMatch(text, /payload class/, 'and its intro prose with it');
  assert.doesNotMatch(text, /Yara One/, 'and the rule heading');
  assert.match(text, /Suricata Signatures/, 'the live engine section stays');
  assert.match(text, /Suri One/);
});

test('a hidden rule takes its metadata paragraphs with it', () => {
  const doc = detectionPage();
  const root = doc.querySelector('.hl-post-content');
  const codes = [...root.querySelectorAll('pre > code')];
  const ok = [
    { el: codes[0], engine: 'yara', tier: 'Detection', rule: {} },
    { el: codes[1], engine: 'suricata', tier: 'Detection', rule: {} }
  ];
  const layout = D.layoutUnits(root, ok);
  const shown = D.visibilityFor(layout, [1]);
  const tierParas = layout.units.filter((u, i) => shown[i] && /^Tier:/.test(u.el.textContent || ''));
  assert.strictEqual(tierParas.length, 1, 'only the surviving rule keeps its metadata');
});

test('page furniture outside the engine sections is never hidden', () => {
  const doc = detectionPage();
  const root = doc.querySelector('.hl-post-content');
  const codes = [...root.querySelectorAll('pre > code')];
  const ok = [
    { el: codes[0], engine: 'yara', tier: 'Detection', rule: {} },
    { el: codes[1], engine: 'suricata', tier: 'Detection', rule: {} }
  ];
  const layout = D.layoutUnits(root, ok);
  const shown = D.visibilityFor(layout, []);           // nothing matches at all
  const text = visibleText(root, shown, layout).join(' | ');
  assert.match(text, /Detection Coverage Summary/);
  assert.match(text, /Coverage Gaps/);
  assert.match(text, /License/);
  assert.doesNotMatch(text, /YARA Rules/);
  assert.doesNotMatch(text, /Suricata Signatures/);
});

test('every rule visible means every element visible', () => {
  const doc = detectionPage();
  const root = doc.querySelector('.hl-post-content');
  const codes = [...root.querySelectorAll('pre > code')];
  const ok = [
    { el: codes[0], engine: 'yara', tier: 'Detection', rule: {} },
    { el: codes[1], engine: 'suricata', tier: 'Detection', rule: {} }
  ];
  const layout = D.layoutUnits(root, ok);
  const shown = D.visibilityFor(layout, [0, 1]);
  assert.strictEqual(shown.filter(Boolean).length, layout.units.length);
});
