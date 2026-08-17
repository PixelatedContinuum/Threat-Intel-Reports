'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { resolveObjectURL } = require('node:buffer');
const { JSDOM } = require('jsdom');
const fixtures = require('./fixtures/tables.js');
const AC = require('../../../assets/js/attack-coverage.js');

function firstTable(html) {
  return new JSDOM('<body>' + html + '</body>').window.document.querySelector('table');
}

function firstBodyCells(html) {
  const row = firstTable(html).querySelectorAll('tbody tr')[0];
  return row.querySelectorAll('td, th');
}

test('tacticSlug converts display names to ATT&CK shortnames', () => {
  assert.strictEqual(AC.tacticSlug('Command and Control'), 'command-and-control');
  assert.strictEqual(AC.tacticSlug('Defense Evasion'), 'defense-evasion');
  assert.strictEqual(AC.tacticSlug('Reconnaissance'), 'reconnaissance');
});

test('parseRow returns an array of every technique in the row', () => {
  const withId = AC.parseRow(firstBodyCells(fixtures.current3col), -1);
  assert.ok(Array.isArray(withId), 'parseRow must return an array');
  assert.strictEqual(withId.length, 1);

  const withoutId = AC.parseRow(firstBodyCells(fixtures.notAnAttackTable), -1);
  assert.ok(Array.isArray(withoutId), 'parseRow must return an array when no ID is present');
  assert.strictEqual(withoutId.length, 0);
});

test('parses the current 3-column shape', () => {
  const r = AC.parseTable(firstTable(fixtures.current3col));
  assert.strictEqual(r.techniques.length, 2);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1595.002',
    tactic: 'Reconnaissance',
    name: 'Vulnerability Scanning',
    confidence: 'HIGH',
    evidence: 'Endpoint/CVE probing'
  });
  assert.deepStrictEqual(r.techniques[1], {
    id: 'T1110.003',
    tactic: 'Credential Access',
    name: 'Password Spraying',
    confidence: 'MODERATE',
    evidence: 'single-password spray (MODERATE)'
  });
});

test('parses the current 4-column shape', () => {
  const r = AC.parseTable(firstTable(fixtures.current4col));
  assert.strictEqual(r.techniques.length, 2);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1055.002',
    tactic: 'Defense Evasion',
    name: 'Portable Executable Injection',
    confidence: 'HIGH',
    evidence: 'RW to RX'
  });
  assert.deepStrictEqual(r.techniques[1], {
    id: 'T1583.003',
    tactic: 'Resource Development',
    name: 'Virtual Private Server',
    confidence: 'MODERATE',
    evidence: 'AS35682'
  });
});

test('parses legacy shape with ID and name sharing a cell', () => {
  const r = AC.parseTable(firstTable(fixtures.legacyIdInTechnique));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1059.004',
    tactic: 'Execution',
    name: 'Unix Shell',
    confidence: 'HIGH',
    evidence: 'Interactive bash captured'
  });
});

test('parses legacy shape with separate ID and name columns', () => {
  const r = AC.parseTable(firstTable(fixtures.legacySplitIdName));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1505.003',
    tactic: 'Persistence',
    name: 'Web Shell',
    confidence: 'HIGH',
    evidence: 'WordPress plugin-dir shell'
  });
});

test('parses all remaining shapes without loss', () => {
  const expected = {
    legacyEvidenceObserved: {
      id: 'T1046',
      tactic: 'Discovery',
      name: 'Network Service Discovery',
      confidence: 'HIGH',
      evidence: 'Subdomain enumeration'
    },
    legacy5colConfidence: {
      id: 'T1213',
      tactic: 'Collection',
      name: 'Data from Information Repositories',
      confidence: 'LOW',
      evidence: 'CKAN harvest'
    },
    legacy5colComponent: {
      id: 'T1486',
      tactic: 'Impact',
      name: 'Data Encrypted for Impact',
      confidence: 'HIGH',
      evidence: 'enc.exe'
    }
  };
  Object.keys(expected).forEach((k) => {
    const r = AC.parseTable(firstTable(fixtures[k]));
    assert.strictEqual(r.techniques.length, 1, k + ' should yield one technique');
    assert.deepStrictEqual(r.techniques[0], expected[k], k + ' parsed wrong');
  });
});

test('evidence is the component cell, never the confidence word', () => {
  const r = AC.parseTable(firstTable(fixtures.componentThenConfidence));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1583.001',
    tactic: 'Resource Development',
    name: 'Acquire Infrastructure: Domains',
    confidence: 'HIGH',
    evidence: 'chainconnects.net, adminxyzhosting.com'
  });
});

test('an ID in trailing parentheses leaves a real name, not a bracket', () => {
  const r = AC.parseTable(firstTable(fixtures.parenthesisedId));
  assert.strictEqual(r.techniques.length, 0, 'no tactic column, so nothing maps');
  assert.strictEqual(r.unmapped.length, 1);
  assert.deepStrictEqual(r.unmapped[0], {
    id: 'T1562.001',
    tactic: null,
    name: 'AMSI bypass via reflection',
    confidence: 'HIGH',
    evidence: 'reflection concatenation'
  });
});

test('every ID in a multi-ID cell is returned', () => {
  const r = AC.parseTable(firstTable(fixtures.multiIdCoverage));
  assert.strictEqual(r.techniques.length, 0, 'coverage tables carry no tactic');
  assert.deepStrictEqual(
    r.unmapped.map((t) => t.id),
    ['T1505.003', 'T1027.013', 'T1070', 'T1056', 'T1119']
  );
  r.unmapped.forEach((t) => {
    assert.strictEqual(t.tactic, null);
    assert.strictEqual(t.name, '', 'a list of IDs has no single technique name');
    assert.strictEqual(t.evidence, 'LOW\u2013MEDIUM');
  });
});

test('an empty confidence cell falls back to the inline marker', () => {
  const r = AC.parseTable(firstTable(fixtures.emptyConfidenceCell));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.techniques[0].confidence, 'MODERATE');
  assert.strictEqual(r.techniques[0].evidence, 'single-password spray (MODERATE)');
});

test('a Configuration column is not a confidence column', () => {
  const r = AC.parseTable(firstTable(fixtures.configurationColumn));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1486',
    tactic: 'Impact',
    name: 'Data Encrypted for Impact',
    confidence: 'MODERATE',
    evidence: 'enc.exe over SMB (MODERATE)'
  });
});

test('the ID is located at its real offset, not an earlier substring', () => {
  const r = AC.parseTable(firstTable(fixtures.idPrecededByFalseMatch));
  assert.strictEqual(r.techniques.length, 1);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1059',
    tactic: 'Execution',
    name: 'Command-Line Interface',
    confidence: 'HIGH',
    evidence: 'cmd.exe spawn'
  });
});

test('a row-header th keeps both the tactic and the confidence column', () => {
  const r = AC.parseTable(firstTable(fixtures.rowHeaderTactic));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.unmapped.length, 0);
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1213',
    tactic: 'Collection',
    name: 'Data from Information Repositories',
    confidence: 'LOW',
    evidence: 'CKAN harvest'
  });
});

test('tfoot rows are not data rows', () => {
  const r = AC.parseTable(firstTable(fixtures.tfootTotals));
  assert.deepStrictEqual(r.techniques.map((t) => t.id), ['T1059.004']);
  assert.strictEqual(r.unmapped.length, 0);
});

test('a nested table contributes neither rows nor cells', () => {
  const r = AC.parseTable(firstTable(fixtures.nestedTableInCell));
  assert.strictEqual(r.techniques.length, 1);
  assert.strictEqual(r.unmapped.length, 0, 'the nested row is not a data row');
  assert.deepStrictEqual(r.techniques[0], {
    id: 'T1505.003',
    tactic: 'Persistence',
    name: 'Web Shell',
    confidence: 'HIGH',
    evidence: 'WordPress plugin-dir shell note see T1486 for the follow-on'
  });
});

test('a table with no technique IDs yields nothing', () => {
  const r = AC.parseTable(firstTable(fixtures.notAnAttackTable));
  assert.strictEqual(r.techniques.length, 0);
  assert.strictEqual(r.unmapped.length, 0);
});

test('a row with no resolvable tactic lands in unmapped', () => {
  const r = AC.parseTable(firstTable(fixtures.missingTactic));
  assert.strictEqual(r.techniques.length, 0);
  assert.strictEqual(r.unmapped.length, 1);
  assert.deepStrictEqual(r.unmapped[0], {
    id: 'T1071.001',
    tactic: null,
    name: 'HTTPS beaconing',
    confidence: 'HIGH',
    evidence: 'HTTPS beaconing'
  });
});

const TWO_ACTOR_PAGE = `
  <h2 id="s11">11. MITRE ATT&CK Mapping</h2>
  <details class="hl-teardown"><summary>Full ATT&CK table</summary>
    <h3>11.1 Operator toolkit</h3>
    ${fixtures.current3col}
    <h3>11.2 Second-actor GSocket kit</h3>
    ${fixtures.legacySplitIdName}
  </details>`;

test('each mapping table is parsed separately and never merged', () => {
  const doc = new JSDOM('<body>' + TWO_ACTOR_PAGE + '</body>').window.document;
  const tables = AC.findMappingTables(doc.body);
  assert.strictEqual(tables.length, 2);

  const first = AC.parseTable(tables[0]);
  const second = AC.parseTable(tables[1]);
  assert.strictEqual(first.techniques.length, 2);
  assert.strictEqual(second.techniques.length, 1);

  const firstIds = first.techniques.map((t) => t.id);
  assert.ok(!firstIds.includes('T1505.003'),
    'second actor technique must not appear in the operator set');
});

test('each table is labelled from its nearest preceding heading', () => {
  const doc = new JSDOM('<body>' + TWO_ACTOR_PAGE + '</body>').window.document;
  const tables = AC.findMappingTables(doc.body);
  assert.strictEqual(AC.labelForTable(tables[0]), '11.1 Operator toolkit');
  assert.strictEqual(AC.labelForTable(tables[1]), '11.2 Second-actor GSocket kit');
});

test('a table inside a teardown inserts the strip above the teardown', () => {
  const doc = new JSDOM('<body>' + TWO_ACTOR_PAGE + '</body>').window.document;
  const table = AC.findMappingTables(doc.body)[0];
  assert.strictEqual(AC.insertionPointFor(table).tagName, 'DETAILS');
});

test('a table with no teardown ancestor inserts directly above itself', () => {
  const doc = new JSDOM('<body><h2>x</h2>' + fixtures.current3col + '</body>').window.document;
  const table = AC.findMappingTables(doc.body)[0];
  assert.strictEqual(AC.insertionPointFor(table).tagName, 'TABLE');
});

// Regression guard on BOTH discovery failures found during implementation.
// Every fixture below was partitioned by running the real parser, not by
// guessing. The REJECT set is the point: all four carry technique IDs, and
// none of them is an ATT&CK mapping table.
test('discovers genuine mapping tables and rejects tactic-less ID tables', () => {
  const MAPPING = [
    'current3col', 'current4col', 'legacyIdInTechnique', 'legacySplitIdName',
    'legacyEvidenceObserved', 'legacy5colConfidence', 'legacy5colComponent',
    'componentThenConfidence', 'emptyConfidenceCell', 'configurationColumn',
    'idPrecededByFalseMatch', 'rowHeaderTactic', 'tfootTotals', 'nestedTableInCell'
  ];
  const REJECT = ['notAnAttackTable', 'missingTactic', 'parenthesisedId', 'multiIdCoverage'];

  MAPPING.forEach((k) => {
    const doc = new JSDOM('<body>' + fixtures[k] + '</body>').window.document;
    assert.strictEqual(AC.findMappingTables(doc.body).length, 1, k + ' should be discovered');
  });
  REJECT.forEach((k) => {
    const doc = new JSDOM('<body>' + fixtures[k] + '</body>').window.document;
    assert.strictEqual(AC.findMappingTables(doc.body).length, 0, k + ' must NOT be discovered');
  });

  // Guards against the partition silently going stale if a fixture is added.
  assert.strictEqual(MAPPING.length + REJECT.length, Object.keys(fixtures).length,
    'every fixture must be classified as MAPPING or REJECT');
});

test('generates a schema-correct Navigator 4.5 layer', () => {
  const parsed = AC.parseTable(firstTable(fixtures.current3col));
  parsed.label = '11.1 Operator toolkit';
  const layer = AC.toNavigatorLayer(parsed, { reportTitle: 'SE-Asia Toolkit' });

  assert.strictEqual(layer.domain, 'enterprise-attack');
  assert.strictEqual(layer.versions.layer, '4.5');
  assert.strictEqual(layer.versions.navigator, '4.9.0');
  assert.strictEqual(layer.versions.attack, '19');
  assert.strictEqual(layer.name, 'SE-Asia Toolkit: 11.1 Operator toolkit');

  const t = layer.techniques.find((x) => x.techniqueID === 'T1595.002');
  assert.strictEqual(t.tactic, 'reconnaissance');
  assert.strictEqual(t.score, 100);
  assert.strictEqual(t.enabled, true);
  assert.ok(t.comment.length > 0);
});

test('confidence maps onto the layer score band', () => {
  const parsed = AC.parseTable(firstTable(fixtures.current4col));
  const layer = AC.toNavigatorLayer(parsed, { reportTitle: 'X' });
  const byId = Object.fromEntries(layer.techniques.map((t) => [t.techniqueID, t.score]));
  assert.strictEqual(byId['T1055.002'], 100);
  assert.strictEqual(byId['T1583.003'], 60);
});

test('unmapped techniques are excluded from the layer, since tactic is unknown', () => {
  const parsed = AC.parseTable(firstTable(fixtures.missingTactic));
  const layer = AC.toNavigatorLayer(parsed, { reportTitle: 'X' });
  assert.strictEqual(layer.techniques.length, 0);
});

test('renders one segment per tactic, including empty ones', () => {
  const doc = new JSDOM('<body></body>').window.document;
  const parsed = AC.parseTable(firstTable(fixtures.current3col));
  const strip = AC.renderStrip(parsed, doc);
  assert.strictEqual(strip.querySelectorAll('[data-tactic]').length, 14);
  const empty = strip.querySelectorAll('[data-tactic][data-count="0"]');
  assert.strictEqual(empty.length, 12, 'two tactics covered, twelve empty');
});

test('renders an unmapped notice only when there are unmapped techniques', () => {
  const doc = new JSDOM('<body></body>').window.document;
  const clean = AC.renderStrip(AC.parseTable(firstTable(fixtures.current3col)), doc);
  assert.strictEqual(clean.querySelector('[data-unmapped]'), null);

  const dirty = AC.renderStrip(AC.parseTable(firstTable(fixtures.missingTactic)), doc);
  assert.strictEqual(dirty.querySelector('[data-unmapped]').getAttribute('data-unmapped'), '1');
});

test('renders nothing at all when a table yields no techniques', () => {
  const doc = new JSDOM('<body></body>').window.document;
  assert.strictEqual(AC.renderStrip(AC.parseTable(firstTable(fixtures.notAnAttackTable)), doc), null);
});

test('a freshly rendered strip shows the prompt', () => {
  const doc = new JSDOM('<body></body>').window.document;
  const strip = AC.renderStrip(AC.parseTable(firstTable(fixtures.current3col)), doc);
  const prompts = strip.querySelectorAll('.hl-attack__prompt');
  assert.strictEqual(prompts.length, 1, 'exactly one prompt is shown');
  assert.ok(prompts[0].textContent.includes('Select a tactic'),
    'the prompt text tells the reader what to do');
  assert.ok(!strip.querySelector('.hl-attack__detail').hasAttribute('hidden'),
    'the detail panel is never hidden, even before any tactic is selected');
  assert.strictEqual(strip.querySelectorAll('.hl-attack__chip').length, 0);
});

// --- Browser wiring -------------------------------------------------------
// init() reads the GLOBAL document, so a test drives the real browser path by
// pointing that global at a jsdom document and dispatching genuine click
// events. Nothing here reimplements the handlers: the assertions run against
// whatever init() actually wired up.

function bootPage(innerHtml, title) {
  const dom = new JSDOM('<body><div class="hl-post-content">' +
    '<h1>' + (title || 'Test Report') + '</h1>' + innerHtml + '</div></body>');
  const hadDoc = 'document' in global;
  const prevDoc = global.document;
  const restore = () => {
    if (hadDoc) global.document = prevDoc;
    else delete global.document;
  };
  global.document = dom.window.document;
  // A throw from init() would otherwise strand the global and make every later
  // test fail for the wrong reason.
  try {
    AC.init();
  } catch (e) {
    restore();
    throw e;
  }
  return { dom: dom, doc: dom.window.document, restore: restore };
}

// `inner` dispatches from a descendant of the segment instead of the segment
// itself. That is what a real click produces, since the bar fill covers most of
// the segment, and it is the path the delegated handler resolves with closest().
function clickSeg(doc, tactic, inner) {
  const seg = doc.querySelector('.hl-attack__seg[data-tactic="' + tactic + '"]');
  assert.ok(seg, 'no segment rendered for tactic ' + tactic);
  const target = inner ? seg.querySelector(inner) : seg;
  assert.ok(target, 'no ' + inner + ' inside the ' + tactic + ' segment');
  target.dispatchEvent(new doc.defaultView.MouseEvent('click', { bubbles: true }));
  return seg;
}

function openTactics(doc) {
  return Array.from(doc.querySelectorAll('.hl-attack__seg.is-open'))
    .map((s) => s.getAttribute('data-tactic'));
}

function chipText(detail) {
  return Array.from(detail.querySelectorAll('.hl-attack__chip')).map((c) => c.textContent);
}

test('init inserts one strip immediately above its mapping table', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const strips = page.doc.querySelectorAll('.hl-attack');
    assert.strictEqual(strips.length, 1, 'exactly one strip for one mapping table');

    const table = page.doc.querySelector('table');
    assert.strictEqual(table.previousElementSibling, strips[0],
      'the strip must sit immediately before the table it summarises');
    assert.strictEqual(strips[0].querySelectorAll('.hl-attack__seg').length, 14);
    const detail = page.doc.querySelector('.hl-attack__detail');
    assert.ok(!detail.hasAttribute('hidden'), 'the detail panel is never hidden, even at init');
    assert.ok(detail.querySelector('.hl-attack__prompt'), 'it opens showing the prompt');
  } finally {
    page.restore();
  }
});

test('clicking a populated segment reveals that tactic chips', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    clickSeg(page.doc, 'Credential Access');

    assert.ok(!detail.hasAttribute('hidden'), 'the detail panel must open');
    assert.deepStrictEqual(openTactics(page.doc), ['Credential Access']);
    assert.strictEqual(
      detail.querySelector('.hl-attack__detailhead').textContent,
      'Credential Access \u00b7 1 technique',
      'the head names the tactic and its technique count');
    assert.deepStrictEqual(chipText(detail), ['T1110.003 Password Spraying']);
    assert.strictEqual(
      detail.querySelector('.hl-attack__chip').getAttribute('data-confidence'), 'MODERATE');
  } finally {
    page.restore();
  }
});

test('clicking the same segment again collapses it', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    clickSeg(page.doc, 'Credential Access');
    assert.ok(!detail.hasAttribute('hidden'), 'precondition: the first click opened it');

    clickSeg(page.doc, 'Credential Access');
    assert.ok(detail.querySelector('.hl-attack__prompt'),
      'the second click must restore the prompt');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__chip').length, 0,
      'no chips remain once the prompt is restored');
    assert.deepStrictEqual(openTactics(page.doc), [], 'no segment stays marked open');
  } finally {
    page.restore();
  }
});

test('clicking a different segment switches rather than accumulating', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    clickSeg(page.doc, 'Credential Access');
    clickSeg(page.doc, 'Reconnaissance', '.hl-attack__fill');

    assert.ok(!detail.hasAttribute('hidden'), 'the detail stays open on the new tactic');
    assert.deepStrictEqual(openTactics(page.doc), ['Reconnaissance'],
      'only the most recently clicked segment is open');
    assert.strictEqual(
      detail.querySelector('.hl-attack__detailhead').textContent,
      'Reconnaissance \u00b7 1 technique');
    assert.deepStrictEqual(chipText(detail), ['T1595.002 Vulnerability Scanning'],
      'the chips belong to the second tactic, not the first');
  } finally {
    page.restore();
  }
});

test('clicking an empty segment opens nothing', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    const impact = page.doc.querySelector('.hl-attack__seg[data-tactic="Impact"]');
    assert.strictEqual(impact.getAttribute('data-count'), '0',
      'precondition: Impact is an uncovered tactic in this fixture');

    clickSeg(page.doc, 'Impact');
    assert.ok(detail.querySelector('.hl-attack__prompt'),
      'an empty tactic must not open an empty box');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__chip').length, 0,
      'no chips remain');
    assert.deepStrictEqual(openTactics(page.doc), []);

    // From a closed strip a dead handler would look identical to the real one,
    // so run the same click against an open strip: the empty tactic has to
    // restore the prompt rather than leave another tactic's chips on screen.
    clickSeg(page.doc, 'Credential Access');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__chip').length, 1,
      'precondition: a populated tactic is open');
    clickSeg(page.doc, 'Impact');
    assert.ok(detail.querySelector('.hl-attack__prompt'),
      'clicking an empty tactic must restore the prompt, not strand the previous chips');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__chip').length, 0,
      'no chips remain');
    assert.deepStrictEqual(openTactics(page.doc), []);
  } finally {
    page.restore();
  }
});

test('clicking a populated tactic replaces the prompt with chips', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    assert.ok(detail.querySelector('.hl-attack__prompt'), 'precondition: the prompt is showing');

    clickSeg(page.doc, 'Credential Access');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__prompt').length, 0,
      'the prompt must be gone once a tactic is selected');
    assert.strictEqual(detail.querySelectorAll('.hl-attack__chip').length, 1,
      'the chip count must equal that tactic\'s technique count');
  } finally {
    page.restore();
  }
});

test('the panel is never hidden across a full click cycle', () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col);
  try {
    const detail = page.doc.querySelector('.hl-attack__detail');
    assert.strictEqual(detail.hasAttribute('hidden'), false, 'never hidden on initial render');

    clickSeg(page.doc, 'Credential Access');
    assert.strictEqual(detail.hasAttribute('hidden'), false,
      'never hidden after opening a populated segment');

    clickSeg(page.doc, 'Credential Access');
    assert.strictEqual(detail.hasAttribute('hidden'), false,
      'never hidden after collapsing that segment again');

    clickSeg(page.doc, 'Impact');
    assert.strictEqual(detail.hasAttribute('hidden'), false,
      'never hidden after clicking a grey segment');
  } finally {
    page.restore();
  }
});

test('the export button downloads a correctly named Navigator layer', async () => {
  const page = bootPage('<h2>11. MITRE ATT&CK Mapping</h2>' + fixtures.current3col,
    'SE-Asia Gov Toolkit');
  const proto = page.dom.window.HTMLAnchorElement.prototype;
  const realClick = proto.click;
  const captured = [];
  // The only stub: jsdom treats a real anchor activation as a navigation it has
  // not implemented. Blob, createObjectURL and the JSON serialisation are all
  // genuine, so the assertions below read the bytes the browser would download.
  proto.click = function () { captured.push({ name: this.download, href: this.href }); };
  try {
    const button = page.doc.querySelector('.hl-attack__export');
    button.dispatchEvent(new page.dom.window.MouseEvent('click', { bubbles: true }));

    assert.strictEqual(captured.length, 1, 'exactly one download triggered');
    const name = captured[0].name;
    assert.ok(/-layer\.json$/.test(name), 'filename must end in -layer.json, got ' + name);
    assert.strictEqual(name, name.toLowerCase(), 'filename must be lowercase, got ' + name);
    assert.ok(!/\s/.test(name), 'filename must carry no whitespace, got ' + name);
    assert.strictEqual(name, 'se-asia-gov-toolkit-11-mitre-att-ck-mapping-layer.json');

    const blob = resolveObjectURL(captured[0].href);
    assert.ok(blob, 'the anchor href must resolve back to the generated blob');
    assert.strictEqual(blob.type, 'application/json');
    const layer = JSON.parse(await blob.text());
    assert.strictEqual(layer.versions.layer, '4.5');
    assert.strictEqual(layer.name, 'SE-Asia Gov Toolkit: 11. MITRE ATT&CK Mapping');
    assert.deepStrictEqual(layer.techniques.map((t) => t.techniqueID),
      ['T1595.002', 'T1110.003']);
  } finally {
    proto.click = realClick;
    page.restore();
  }
});
