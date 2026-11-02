/* Hunter's Ledger report tabs. Progressive enhancement of the unchanged article.
   Source blocks are moved, never copied or rewritten. One-page and print restore
   their original order. Dashboard text is a separate, excluded view of DOM tables. */
(function () {
  'use strict';
  var content = document.querySelector('.hl-report-page .hl-post-content');
  if (!content) return;
  var root = document.documentElement;
  var page = content.closest('.hl-report-page');
  // ALL_TOKENS is the fixed tab order a report may tag; TOKENS (and the arrays indexed with it) is narrowed below to the
  // tabs that hold a section, so a report with nothing tagged for Victims or Timeline gets no empty tab (T-0500.1.9).
  var ALL_TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
  var TOKENS = ALL_TOKENS.slice();
  var NAMES = ['Overview', 'Victims and impact', 'Attack chain', 'Infrastructure and timeline', 'Attribution', 'Indicators and detections', 'Confidence and gaps'];
  var QUESTIONS = ['What happened and how bad is it?', 'Who was hit, and how far did the operator get?', 'How did the operator get in and spread?', 'Which servers, and when did each thing happen?', 'Who is behind it, and what would change my mind?', 'What can a defender deploy today?', "How strong is each finding, and what remains unknown?"];
  var ARIA_LABELS = ['Overview', 'Victims and impact', 'Chain: attack chain', 'Timeline: infrastructure and timeline', 'Actor: attribution', 'IOCs: indicators and detections', 'Confidence and gaps'];
  var SHORT_NAMES = ['Overview', 'Victims', 'Chain', 'Timeline', 'Actor', 'IOCs', 'Confidence'];
  var phone = window.matchMedia('(max-width: 699px)');
  var sourceNodes = Array.from(content.childNodes);
  var headings = Array.from(content.children).filter(function (n) { return n.tagName === 'H2'; });
  function token(h) { return ALL_TOKENS.find(function (t) { return h.classList.contains('hl-tab-' + t); }); }
  // Invalid/partial annotations degrade to the complete server-rendered article.
  if (!headings.length || headings.some(function (h) { return !token(h); })) return;
  if (ALL_TOKENS.some(function (t) { return document.getElementById('tab-' + t) || document.getElementById('tabbtn-' + t); }) || document.getElementById('one-page')) return;
  function text(n) { return (n ? n.textContent : '').replace(/\s+/g, ' ').trim(); }
  function make(tag, cls, value, parent) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (value !== undefined && value !== null) n.textContent = value;
    n.setAttribute('data-rv-chrome', ''); n.setAttribute('data-pagefind-ignore', '');
    if (parent) parent.appendChild(n);
    return n;
  }
  function button(label, parent, action) {
    var b = make('button', '', label, parent); b.type = 'button';
    if (action) b.addEventListener('click', action);
    return b;
  }
  // Design D (T-0500.1.7.3): one stroke icon per fixed tab, the plate's action icons, and the small "i" popover.
  var TAB_ICONS = {
    overview: '<rect x="3" y="3" width="7" height="9" rx="1.6"/><rect x="14" y="3" width="7" height="5" rx="1.6"/><rect x="14" y="12" width="7" height="9" rx="1.6"/><rect x="3" y="16" width="7" height="5" rx="1.6"/>',
    victims: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/>',
    chain: '<circle cx="5" cy="7" r="2.4"/><circle cx="12" cy="17" r="2.4"/><circle cx="19" cy="7" r="2.4"/><path d="M6.6 8.9l3.8 6.2M13.6 15.1l3.8-6.2"/>',
    timeline: '<rect x="3" y="4" width="18" height="6.5" rx="1.8"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.8"/><path d="M7 7.25h.01M7 16.75h.01"/>',
    attribution: '<circle cx="12" cy="8.5" r="3.6"/><path d="M5 20c0-4 3-6.5 7-6.5s7 2.5 7 6.5"/>',
    indicators: '<path d="M4 9h16M4 15h16M10 4L8 20M16 4l-2 16"/>',
    confidence: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/><circle cx="12" cy="17" r="1.3" fill="currentColor"/>'
  };
  function icon(inner, size, parent, cls) {
    var span = make('span', cls || '', null, parent); span.setAttribute('aria-hidden', 'true');
    span.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="' + size + '" height="' + size + '" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" focusable="false">' + inner + '</svg>';
    return span;
  }
  // The small "i" control: the explanatory notes under generated figures ("How counted", where a count is read from) are moved,
  // text unchanged, into a popover that opens on tap or Enter and closes on Escape, a second press or a press elsewhere.
  // The notes stay in the DOM; none of them is report text.
  var openInfo = null, infoSeq = 0;
  function closeInfo(focus) {
    if (!openInfo) return;
    var b = openInfo.btn; openInfo.pop.hidden = true; openInfo.pop.style.transform = ''; b.setAttribute('aria-expanded', 'false'); openInfo = null; if (focus) b.focus();
  }
  /* Keep an open note inside the viewport on both axes (review F3, T-0500.1.7.3 c5): below its button by default; above it when there is no room below and more room above;
     then slid by whatever is still outside, 12px from each screen edge. Only a transform is applied (the note's containing block is not always its button's parent), and the
     stylesheet caps the note's height to the screen, so it can always fit. */
  function fitInfo(pop, btn) {
    var m = 12, r = pop.getBoundingClientRect(), br = btn.getBoundingClientRect(), dx = 0, dy = 0;
    if (r.bottom > innerHeight - m) {
      var above = br.top + 6 - r.height;
      if (above >= m || (m - above) < (r.bottom - (innerHeight - m))) dy = above - r.top;
    }
    if (r.right > innerWidth - m) dx = innerWidth - m - r.right;
    if (r.left + dx < m) dx = m - r.left;
    if (r.bottom + dy > innerHeight - m) dy = innerHeight - m - r.bottom;
    if (r.top + dy < m) dy = m - r.top;
    if (dx || dy) pop.style.transform = 'translate(' + Math.round(dx) + 'px, ' + Math.round(dy) + 'px)';
  }
  function infoButton(host, notes, label) {
    var btn = make('button', 'hl-rv-info', null, host); btn.type = 'button';
    btn.setAttribute('aria-label', label || 'How this is counted'); btn.setAttribute('aria-expanded', 'false');
    var mark = make('span', '', 'i', btn); mark.setAttribute('aria-hidden', 'true');
    var pop = make('div', 'hl-rv-pop', null, host); pop.hidden = true; pop.setAttribute('role', 'note'); pop.id = 'hl-rv-pop-' + (++infoSeq);
    btn.setAttribute('aria-controls', pop.id);
    notes.forEach(function (n) { pop.appendChild(n); });
    btn.addEventListener('click', function (e) {
      e.preventDefault(); e.stopPropagation();
      if (openInfo && openInfo.btn === btn) { closeInfo(false); return; }
      closeInfo(false); pop.hidden = false; btn.setAttribute('aria-expanded', 'true'); openInfo = { btn: btn, pop: pop };
      fitInfo(pop, btn);
    });
    pop.addEventListener('keydown', function (e) { if (e.key === 'Escape') { e.stopPropagation(); closeInfo(true); } });
    btn.addEventListener('keydown', function (e) { if (e.key === 'Escape' && openInfo) { e.stopPropagation(); closeInfo(true); } });
    return btn;
  }
  document.addEventListener('click', function (e) { if (openInfo && !e.target.closest('.hl-rv-pop, .hl-rv-info')) closeInfo(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeInfo(true); });
  function safeHref(h) {
    if (typeof h !== 'string' || /[\\\s\u0000-\u0020\u007f]/.test(h)) return false;
    if (h.charAt(0) === '#') return true;
    var u; try { u = new URL(h, location.origin); } catch (e) { return false; }
    if (h.charAt(0) === '/') return h.charAt(1) !== '/' && u.origin === location.origin;
    return /^https:\/\//i.test(h) && u.protocol === 'https:';
  }
  function link(label, href, parent) {
    if (!safeHref(href)) return make('span', '', label, parent);
    var a = make('a', '', label, parent); a.href = href; return a;
  }
  function sourceLink(model, parent, label) {
    if (model && model.heading) {
      var a = link('Read in the report', '#' + model.heading.id, parent);
      a.setAttribute('aria-label', 'Read in the report: ' + (label || model.headers.join(' / ')) + ': ' + text(model.heading));
    }
  }
  function sourceFooter(parent, sources) {
    var footer = make('p', 'hl-rv-source-footer', 'From: ', parent);
    sources.filter(Boolean).forEach(function (m, i) {
      if (i) make('span', '', '; ', footer);
      link(text(m.heading) + ', table ' + m.index + ' (' + m.headers.join(' / ') + '), ' + m.rows.length + ' rows', '#' + m.heading.id, footer);
    });
    if (!sources.some(Boolean)) make('span', '', 'No matching structured table; full source sections follow.', footer);
  }
  var copyTimers = new WeakMap();
  function copyValue(value, control, status) {
    function fallback() {
      var area = make('textarea', 'hl-rv-copy-fallback', value, document.body);
      area.value = value; area.focus(); area.select();
      status.textContent = 'Clipboard unavailable. Exact printed text selected; use the copy command.';
      area.addEventListener('blur', function () { area.remove(); }, { once: true });
    }
    if (!navigator.clipboard) { fallback(); return; }
    navigator.clipboard.writeText(value).then(function () {
      if (!control.dataset.rvCopyLabel) control.dataset.rvCopyLabel = control.textContent;
      clearTimeout(copyTimers.get(control)); control.textContent = 'Copied';
      status.textContent = 'Copied as printed.';
      copyTimers.set(control, setTimeout(function () { control.textContent = control.dataset.rvCopyLabel; }, 1500));
    }, fallback);
  }
  var live = make('p', 'hl-rv-live', '', content); live.setAttribute('aria-live', 'polite'); live.setAttribute('aria-atomic', 'true');
  function tableCopy(table, parent, column) {
    var tools = make('div', 'hl-rv-table-tools', null, parent);
    function value(col) {
      return Array.from(table.rows).map(function (r) {
        return Array.from(r.cells).filter(function (_, i) { return col === undefined || i === col; }).map(function (c) { return c.textContent; }).join('\t');
      }).join('\n');
    }
    var b = button('Copy table', tools, function () { copyValue(value(), b, live); });
    if (column !== undefined && column >= 0) {
      var c = button('Copy column', tools, function () { copyValue(value(column), c, live); });
      c.setAttribute('aria-label', 'Copy indicator column as printed');
    }
    return tools;
  }

  // figure-nav and attack-coverage run before this deferred script. Mark their generated
  // labels (the figure chips; the ATT&CK coverage strip and its Navigator download, T-0500.1.9)
  // before detaching anything, so rollback retains only report words too.
  content.querySelectorAll('.hl-fignav, .hl-attack').forEach(function (n) { n.setAttribute('data-rv-chrome', ''); n.setAttribute('data-pagefind-ignore', ''); });
  // A failed enhancement must put the exact original nodes back, in report order.
  var originalChrome = new Set(document.querySelectorAll('[data-rv-chrome]'));
  var curation = {};
  var viewData = document.getElementById('hl-report-view-data');
  if (viewData) { try { curation = JSON.parse(viewData.textContent); } catch (e) { console.warn('Report view data unavailable', e); } }
  var sections = [], currentBlock;
  try {
  sourceNodes.forEach(function (n) {
    if (!currentBlock || n.nodeType === 1 && n.tagName === 'H2') {
      // These two structural wrappers deliberately are not chrome: excluding a
      // panel/block would also exclude the unchanged report it contains.
      currentBlock = document.createElement('div'); currentBlock.className = 'hl-rv-source';
      var h = n.nodeType === 1 && n.tagName === 'H2' ? n : null;
      sections.push({ node: currentBlock, token: h ? token(h) : 'overview', heading: h, order: sections.length });
      currentBlock.style.setProperty('--rv-order', sections.length);
      // The panel's header bar prints a mono label from this attribute (CSS content, never report text).
      // A section with an h2 is labelled by its number; the first block, which has no h2, is the campaign record.
      if (h) {
        var num = h.firstChild && h.firstChild.textContent.match(/^\s*(\d+)\./);
        h.setAttribute('data-rv-sec', num ? 'SECTION ' + (num[1].length < 2 ? '0' + num[1] : num[1]) : 'APPENDIX');
      } else { currentBlock.classList.add('hl-rv-nohead'); currentBlock.setAttribute('data-rv-sec', 'CAMPAIGN RECORD'); }
    }
    currentBlock.appendChild(n);
  });
  // Build only the tabs that hold a section, in the fixed order. The campaign-record block (before the first h2) belongs to
  // Overview, so Overview is present whenever the article has anything in it.
  var present = ALL_TOKENS.map(function (t) { return sections.some(function (s) { return s.token === t; }); });
  function narrow(list) { return list.filter(function (_, i) { return present[i]; }); }
  TOKENS = narrow(ALL_TOKENS); NAMES = narrow(NAMES); QUESTIONS = narrow(QUESTIONS); ARIA_LABELS = narrow(ARIA_LABELS); SHORT_NAMES = narrow(SHORT_NAMES);
  var models = [];
  sections.forEach(function (s) {
    s.node.querySelectorAll('table').forEach(function (table, index) {
      // Expand row/col spans without deduplicating procedure rows or dropping cells.
      var matrix = [], trs = Array.from(table.rows);
      trs.forEach(function (tr, ri) {
        if (!matrix[ri]) matrix[ri] = [];
        var col = 0;
        Array.from(tr.cells).forEach(function (cell) {
          while (matrix[ri][col] !== undefined) col++;
          for (var y = 0; y < cell.rowSpan; y++) {
            if (!matrix[ri + y]) matrix[ri + y] = [];
            for (var x = 0; x < cell.colSpan; x++) matrix[ri + y][col + x] = text(cell);
          }
          col += cell.colSpan;
        });
      });
      if (!matrix.length || !table.querySelector('th')) return;
      var headerRows = table.tHead ? table.tHead.rows.length : 1;
      var headers = matrix[headerRows - 1];
      var rows = matrix.slice(headerRows);
      if (!rows.length || rows.some(function (r) { return r.length !== headers.length; })) return;
      models.push({ token: s.token, heading: s.heading, index: index + 1, headers: headers, rows: rows, table: table });
    });
  });
  function find(tok, required) {
    return models.find(function (m) { return m.token === tok && required.every(function (r) { return m.headers.some(function (h) { return r.test(h); }); }); });
  }
  function col(m, re) { return m.headers.findIndex(function (h) { return re.test(h); }); }
  var attack = find('chain', [/Tactic.*Technique/i, /^Status$/i, /Conf/i, /Scope/i]) || models.filter(function (m) { return m.token === 'chain' && m.headers.some(function (h) { return /Tactic.*Technique/i.test(h); }) && m.headers.some(function (h) { return /^Status$/i.test(h); }); }).sort(function (a, b) { return b.rows.length - a.rows.length; })[0];
  // Legacy ATT&CK tables (T-0500.1.11): a report written before the tabbed layout names a tactic and a technique but states no Status. Two shapes
  // carry it: one cell "Tactic / T1059" (Tactic / Technique | Name | Evidence), or a Tactic column beside a Technique (ID) column. The view lists
  // those rows by tactic and says which columns the table does not state; it never infers a Status. A table with a Status column is read as before.
  function legacyAttack(m) {
    if (m.token !== 'chain' || m.headers.some(function (h) { return /^Status$/i.test(h); })) return false;
    return m.headers.some(function (h) { return /Tactic.*Technique/i.test(h); }) ||
      m.headers.some(function (h) { return /^Tactic$/i.test(h); }) && m.headers.some(function (h) { return /^Technique( ID)?$/i.test(h); });
  }
  if (!attack) { attack = models.filter(legacyAttack).sort(function (a, b) { return b.rows.length - a.rows.length; })[0]; if (attack) attack.legacy = true; }
  // Where an ATT&CK table keeps what the view reads. The Status-bearing table keeps the original places (the tactic cell carries the technique ID, the name is column 2);
  // a legacy table is read by its headers, and a column it lacks is -1 (the view then says it is not stated).
  function attackCols(m) {
    if (!m) return null;
    var combined = col(m, /Tactic.*Technique/i);
    if (!m.legacy) return { tactic: combined, id: combined, name: 1, status: col(m, /^Status$/i), conf: col(m, /Conf/i), scope: col(m, /Scope/i) };
    var name = combined >= 0 ? col(m, /^Name$/i) : col(m, /Technique Name/i);
    return { tactic: combined >= 0 ? combined : col(m, /^Tactic$/i), id: combined >= 0 ? combined : col(m, /^Technique( ID)?$/i), name: name, status: -1, conf: col(m, /Conf/i), scope: col(m, /Scope/i) };
  }
  function cell(row, i) { return i >= 0 && row[i] !== undefined ? row[i] : ''; }
  var attackC = attackCols(attack);
  var stages = find('chain', [/^Stage$/i, /What.*did/i]) || find('chain', [/^Stage$|^Phase$/i, /What.*(does|happens)/i]);
  var victims = find('victims', [/Organisation|Organization|Victim/i, /Grade/i]);
  var chronology = find('timeline', [/^Date|^Time|^When/i, /Observation|Event/i]);
  // A legacy confidence table is Finding | Confidence, with or without a column for what would change it; the view says when that column is absent.
  var judgments = find('confidence', [/Claim|Judgment/i, /Confidence/i, /change/i]) || find('confidence', [/Claim|Judgment|Finding/i, /Confidence/i]);
  var indicators = find('indicators', [/^Indicator/i, /Action/i]);
  var hypotheses = find('attribution', [/Hypothesis/i, /stands|Assessment/i]) || find('attribution', [/Hypothesis/i, /Verdict|Consistency|Likelihood|Ruling|Why/i]);
  var calls = find('attribution', [/^Call|Judgment/i, /change/i]);
  var detectionSection = sections.find(function (s) { return s.token === 'indicators' && s.heading && /Detection|Hunting/i.test(text(s.heading)); });
  var detectionParagraph = detectionSection && detectionSection.node.querySelector('p');
  var detectionText = text(detectionParagraph), ruleMatch = detectionText.match(/(\d+) rules\b/);
  var engines = [];
  detectionText.replace(/(\d+) (Sigma|Suricata|YARA) \((\d+) detection, (\d+) hunting\)/g, function (_, total, engine, detection, hunting) { engines.push({ engine: engine, total: +total, detection: +detection, hunting: +hunting }); });
  if (/no YARA/.test(detectionText)) engines.push({ engine: 'YARA', total: 0, detection: 0, hunting: 0 });
  var ruleTotal = ruleMatch && engines.length && engines.every(function (e) { return e.total === e.detection + e.hunting; }) && engines.reduce(function (n, e) { return n + e.total; }, 0) === +ruleMatch[1] ? +ruleMatch[1] : null;
  var indicatorText = sections.filter(function (s) { return s.token === 'indicators'; }).map(function (s) { return text(s.node); }).join(' ');
  var feedMatch = indicatorText.match(/(?:carries|contains) (\d+) operator-side indicator entries/i);
  var victimBlock = sections.find(function (s) { return s.token === 'victims' && s.heading && /Who.*Hit|Victim/i.test(text(s.heading)); });
  var tallyParagraph = victimBlock && Array.from(victimBlock.node.querySelectorAll('p')).find(function (p) { return /\d+ ACCESS SHOWN.*\d+ COMPROMISED.*\d+ REACHED.*\d+ LISTED/.test(text(p)); });
  // ---- Design D, D3 (T-0500.1.7.3): the data the Overview's scan layer reads. Every part is built from the tables and site data this report has; nothing is invented. ----
  var siteData = {}, siteNode = document.getElementById('hl-report-site-data');
  if (siteNode) { try { siteData = JSON.parse(siteNode.textContent) || {}; } catch (e) { console.warn('Report site data unavailable', e); } }
  var RISK_HEAD = /^(Risk (Dimension|Factor)|Dimension)$/i, RISK_SCORE = /^Score|^Rating/i, RISK_WHY = /Rationale|Justification|Business Impact|Assessment|Evidence|Notes?|Key Driver|Explanation/i;
  // The risk assessment tables of the Overview (a report may carry more than one). Header matching is tolerant: the first column names the dimension, one column holds the score or rating.
  var riskTables = models.filter(function (m) { return m.token === 'overview' && col(m, RISK_HEAD) >= 0 && col(m, RISK_SCORE) >= 0; });
  var RISK_WORDS = { LOW: 1, MEDIUM: 2, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
  function parseScore(value) {
    var t = String(value).replace(/\s+/g, ' ').trim(), n = t.match(/^(\d+(?:\.\d+)?)\s*(?:\/\s*(\d+(?:\.\d+)?)|out of\s*(\d+(?:\.\d+)?))?/);
    if (n) return { text: t, num: +n[1], max: +(n[2] || n[3] || 10), rest: t.slice(n[0].length).replace(/^[\s,;:()\-]+|[\s,;:()\-]+$/g, '') };
    var w = t.match(/^(CRITICAL|HIGH|MEDIUM|MODERATE|LOW)\b/i);
    return { text: t, num: NaN, max: 10, word: w ? w[1].toUpperCase() : '', rest: '' };
  }
  function riskRows(m) {
    var nameC = col(m, RISK_HEAD), scoreC = col(m, RISK_SCORE), weightC = col(m, /^Weight/i), sevC = col(m, /^Severity$/i);
    var whyC = m.headers.findIndex(function (h, i) { return i !== nameC && i !== scoreC && i !== weightC && i !== sevC && RISK_WHY.test(h); });
    return m.rows.map(function (r) { return { name: r[nameC], score: parseScore(r[scoreC]), weight: weightC >= 0 ? r[weightC] : '', sev: sevC >= 0 ? r[sevC] : '', why: whyC >= 0 ? r[whyC] : '', total: /^overall\b/i.test(r[nameC]) }; });
  }
  function scoreValue(s) { return String(s.num) + '/' + String(s.max); }
  // The overall score: the table's Overall row, else the one "N out of 10" the risk section's first paragraph states.
  function overallRisk() {
    for (var i = 0; i < riskTables.length; i++) {
      var row = riskRows(riskTables[i]).find(function (r) { return r.total && isFinite(r.score.num); });
      if (row) return { value: scoreValue(row.score), rest: row.score.rest, from: text(riskTables[i].heading) + ', table ' + riskTables[i].index + ', the Overall row', model: riskTables[i], heading: riskTables[i].heading };
    }
    var sec = sections.find(function (s) { return s.token === 'overview' && s.heading && /risk/i.test(text(s.heading)); });
    var para = sec && sec.node.querySelector('p');
    if (!para) return null;
    var found = []; text(para).replace(/(\d+(?:\.\d+)?)\s*(?:\/|out of)\s*10\b/g, function (_, n) { if (found.indexOf(n) < 0) found.push(n); });
    return found.length === 1 ? { value: found[0] + '/10', rest: '', from: text(sec.heading) + ', its first paragraph', model: null, heading: sec.heading } : null;
  }
  var threatLevel = (function () {
    var m = sections.flatMap(function (s) { return Array.from(s.node.children); }).filter(function (n) { return n.tagName === 'P' && /^(Campaign Identifier|Last Updated|Threat Level):/.test(text(n)); })
      .map(text).join(' ').match(/(?:^|\s)Threat Level:\s*(CRITICAL|HIGH|MEDIUM|MODERATE|LOW)\b/i);
    return m ? m[1] : null;
  })();
  function tacticName(value) { return value.replace(/\s*\(?T\d{4}.*$/, '').replace(/\s*[·:|/-]\s*$/, '').trim(); }
  var TACTIC_ORDER = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Stealth', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Defense Impairment', 'Impact'];
  // The chronology as dated events: the date text as printed, the observation, and a coordinate where the date parses (the visible date keeps its own qualifier).
  function chronologyRows(m) {
    var dc = col(m, /^Date|^Time|^When/i), ec = col(m, /Observation|Event/i);
    var years = new Set(m.rows.flatMap(function (x) { return x[dc].match(/\b20\d{2}\b/g) || []; }));
    return m.rows.map(function (r) {
      var display = r[dc], event = r[ec], dates = display.match(/\d{4}-\d{2}-\d{2}/g) || [];
      var quality = /disagree|disput/i.test(display + ' ' + event) ? 'disputed' : /inferred/i.test(display) ? 'year-inferred' : /\bto\b/.test(display) ? 'range' : 'given';
      var start = dates[0];
      if (!start && years.size === 1) { var stamp = Date.parse(display.replace(/\s*\(.*?\)/g, '') + ' ' + Array.from(years)[0]); if (!isNaN(stamp)) start = new Date(stamp).toISOString().slice(0, 10); }
      return { display: display, event: event, quality: quality, when: Date.parse(start), end: dates[1] && quality === 'range' ? Date.parse(dates[1]) : Date.parse(start) };
    });
  }
  var bar = make('nav', 'hl-rv-bar', null);
  bar.setAttribute('aria-label', 'Report sections');
  content.parentNode.insertBefore(bar, content);
  var mobileLine = make('div', 'hl-rv-mobile-line', null, bar);
  var currentLabel = make('span', 'hl-rv-current', NAMES[0], mobileLine);
  var menuButton = button('Sections', mobileLine);
  menuButton.setAttribute('aria-expanded', 'false'); menuButton.setAttribute('aria-controls', 'hl-rv-sections');
  var menu = make('div', 'hl-rv-menu', null, bar); menu.id = 'hl-rv-sections'; menu.hidden = true;
  var tablist = make('div', 'hl-rv-tabs', null, bar); tablist.setAttribute('role', 'tablist'); tablist.setAttribute('aria-label', 'Report tabs');
  var oneLink = link('Read as one page', '#one-page', mobileLine); oneLink.className = 'hl-rv-onepage';
  var panels = [], tabs = [], menuLinks = [], times = [], active = 0, onepage = false;
  var sectionLabel = make('span', 'hl-rv-current-section', '', mobileLine);
  var remaining = make('span', 'hl-rv-remaining', '', mobileLine);
  var prevSection = button('↑', mobileLine, function () { stepSection(-1); }); prevSection.setAttribute('aria-label', 'Previous section');
  var nextSection = button('↓', mobileLine, function () { stepSection(1); }); nextSection.setAttribute('aria-label', 'Next section');
  bar.appendChild(mobileLine);
  var progressTrack = make('div', 'hl-rv-progress-track', null, bar);
  var progressBar = make('div', 'hl-rv-progress-bar', null, progressTrack); progressTrack.setAttribute('aria-hidden', 'true');
  var menuSections = make('nav', 'hl-rv-menu-sections', null, menu); menuSections.setAttribute('aria-label', 'Current tab sections');
  var pageContents = make('details', 'hl-rv-page-contents', null); pageContents.hidden = true;
  make('summary', '', 'Contents', pageContents); var pageNav = make('nav', '', null, pageContents);
  sections.forEach(function (s) { s.node.querySelectorAll('h2[id],h3[id]').forEach(function (h) { var a = link(text(h), '#' + h.id, pageNav); if (h.tagName === 'H3') a.className = 'hl-rv-subsection-link'; }); });
  content.before(pageContents);
  var currentSection = null, navigatingUntil = 0;

  // Sponsors come from server-rendered markup, so the tab-foot card always shows what the page shows. The report
  // sponsor(s) are the "This report is sponsored by" panel (_includes/report-sponsor-bar.html); the site (Monthly)
  // sponsors are the site's own Sponsors rail (_includes/sidebar-sponsors.html, the same Monthly filter), which the
  // tabbed CSS keeps in the left gutter or as the site strip. Joseph, 2026-10-30: there is no sponsor mark on the reading line.
  var reportSponsors = Array.from(document.querySelectorAll('.hl-rvsp--report .hl-rvsp__item')).map(function (el) {
    var img = el.querySelector('img');
    return { name: el.getAttribute('data-name') || '', tagline: el.getAttribute('data-tagline') || '', href: el.getAttribute('href') || '', logo: img ? img.getAttribute('src') || '' : '' };
  });
  var siteSponsors = Array.from(document.querySelectorAll('.hl-sponsor-rail .hl-sponsor-rail__item')).map(function (el) {
    var img = el.querySelector('img'), name = el.querySelector('.hl-sponsor-rail__name'), tagline = el.querySelector('.hl-sponsor-rail__tagline');
    return { name: name ? name.textContent.trim() : '', tagline: tagline ? tagline.textContent.trim() : '', href: el.getAttribute('href') || '', logo: img ? img.getAttribute('src') || '' : '' };
  });
  // The report sponsor alone when there is one (Report tier: no competing logos in the report), else the site
  // (Monthly) sponsors, as the site's: a site sponsor is never presented as this report's sponsor.
  var sponsorPool = reportSponsors.length ? reportSponsors : siteSponsors;
  var sponsorLabel = 'Sponsored by';
  function sponsorLink(s, cls, parent) {
    var a = safeHref(s.href) ? make('a', cls, null, parent) : make('span', cls, null, parent);
    if (a.tagName === 'A') { a.href = s.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; }
    return a;
  }
  function sponsorCard(panel) {
    if (!sponsorPool.length) return;
    // With no report sponsor the card is the site sponsor's gold featured panel; with several site sponsors it shows logos
    // only. A report sponsor's card keeps the tab accent.
    var featured = !reportSponsors.length, many = featured && sponsorPool.length > 1;
    var card = make('aside', 'hl-rv-sponsor-card' + (reportSponsors.length ? ' is-report' : ' is-site' + (many ? ' is-many' : '')), null, panel);
    card.setAttribute('aria-label', reportSponsors.length ? 'Report sponsor' : 'Site sponsor');
    make('p', 'hl-rv-sponsor-card__label', featured ? "Featured sponsor of The Hunter's Ledger" : sponsorLabel, card);
    var items = make('div', 'hl-rv-sponsor-card__items', null, card);
    sponsorPool.forEach(function (s) {
      var a = sponsorLink(s, 'hl-rv-sponsor-card__item', items);
      if (s.logo) { var logo = make('img', '', null, a); logo.src = s.logo; logo.alt = s.name; }
      var t = make('span', 'hl-rv-sponsor-card__text', null, a);
      make('span', 'hl-rv-sponsor-card__name', s.name, t);
      if (s.tagline) make('span', 'hl-rv-sponsor-card__tagline', s.tagline, t);
      if (featured && a.tagName === 'A') { var cta = make('span', 'hl-rv-sponsor-card__cta', 'Visit \u2192', a); cta.setAttribute('aria-hidden', 'true'); }
    });
  }

  var words = sections.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0);
  var time = make('span', 'hl-read-time hl-rv-time', Math.max(1, Math.round(words / 200)) + ' min in full');
  var eyebrow = document.querySelector('.hl-post-header__eyebrow'); if (eyebrow) eyebrow.appendChild(time);
  var menuOne;
  TOKENS.forEach(function (t, i) {
    var group = sections.filter(function (s) { return s.token === t; });
    var mins = Math.max(1, Math.round(group.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0) / 200));
    times.push(mins);
    var tab = button('', tablist, function () { navigateTab(i, true); });
    tab.setAttribute('aria-label', ARIA_LABELS[i]);
    // Design D: an icon box and the label; no numeral and no minutes on the button (the minutes stay on the reading line, the tab title and the title attribute).
    icon(TAB_ICONS[t], 21, tab, 'hl-rv-tab-icon');
    var tabLabel = make('span', 'hl-rv-tab-label', null, tab);
    make('span', 'hl-rv-tab-full', NAMES[i], tabLabel);
    make('span', 'hl-rv-tab-short', SHORT_NAMES[i], tabLabel);
    tab.style.flexGrow = String(Math.min(1.4, 0.72 + NAMES[i].length / 40).toFixed(2));
    tab.dataset.rvHue = t; tab.id = 'tabbtn-' + t; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', 'tab-' + t);
    tab.title = QUESTIONS[i] + ' ' + mins + ' min read';
    tab.addEventListener('keydown', function (e) {
      var n = TOKENS.length, j = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i + n - 1) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
      if (j < 0) return; e.preventDefault(); navigateTab(j, false, true); tabs[j].focus({ preventScroll: true });
    });
    tab.addEventListener('focus', function () { if (!onepage && active !== i) select(i); });
    tabs.push(tab);
    var a = link('', '#tab-' + t, menu); a.className = 'hl-rv-menu-item';
    a.dataset.rvHue = t; make('strong', '', NAMES[i], a); make('span', '', QUESTIONS[i], a); make('small', '', mins + ' min read', a); menuLinks.push(a);
    var panel = document.createElement('section'); panel.className = 'hl-rv-panel'; panel.id = 'tab-' + t;
    panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', tab.id); panel.tabIndex = -1;
    content.appendChild(panel); panels.push(panel);
    var title = make('header', 'hl-rv-panel-head', null, panel);
    var numeral = make('span', 'hl-rv-panel-num', String(i + 1).padStart(2, '0'), title); numeral.setAttribute('aria-hidden', 'true');
    make('h2', '', NAMES[i], title); make('p', '', QUESTIONS[i] + ' · ' + mins + ' min read', title);
    group.forEach(function (s) { panel.appendChild(s.node); });
    // Two consecutive short sections (no table, no figure, under 3000 characters) sit side by side from 1280px;
    // the class only changes the grid column, DOM order is unchanged.
    var short = group.map(function (s) { return !s.node.classList.contains('hl-rv-nohead') && s.node.textContent.length < 3000 && !s.node.querySelector('table, figure, img'); });
    for (var gi = 0; gi < group.length - 1; gi++) {
      if (short[gi] && short[gi + 1]) { group[gi].node.classList.add('hl-rv-half'); group[gi + 1].node.classList.add('hl-rv-half'); gi++; }
    }
  });
  menuOne = link('Read as one page', '#one-page', menu); menuOne.className = 'hl-rv-menu-item'; menu.appendChild(menuSections);
  function closeMenu(focus) { menu.hidden = true; menuButton.setAttribute('aria-expanded', 'false'); root.classList.remove('hl-rv-menu-open'); if (focus) menuButton.focus(); }
  function fillMenuSections() {
    menuSections.replaceChildren();
    visibleSections().forEach(function (s) { link(text(s.heading), '#' + s.heading.id, menuSections); });
  }
  menuButton.addEventListener('click', function () { fillMenuSections(); menu.hidden = !menu.hidden; menuButton.setAttribute('aria-expanded', String(!menu.hidden)); root.classList.toggle('hl-rv-menu-open', !menu.hidden); });
  bar.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenu(true); });
  document.addEventListener('click', function (e) { if (!bar.contains(e.target)) closeMenu(false); });
  function select(i) {
    active = i; currentSection = null; page.dataset.rvHue = TOKENS[i];
    tabs.forEach(function (tab, j) { tab.setAttribute('aria-selected', String(i === j)); tab.tabIndex = i === j ? 0 : -1; panels[j].hidden = i !== j; });
    if (phone.matches && tabs[i] && tablist.scrollWidth > tablist.clientWidth + 1) { var tl = tabs[i].offsetLeft - tablist.offsetLeft - (tablist.clientWidth - tabs[i].offsetWidth) / 2; tablist.scrollLeft = Math.max(0, tl); }
    currentLabel.textContent = NAMES[i]; menuLinks.forEach(function (a, j) { if (j === i) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); closeMenu(false); fillMenuSections(); measureBar(); updateProgress(); clearLink();
  }
  function mode(one) {
    onepage = one; pageContents.hidden = !one; currentSection = null; root.classList.toggle('hl-onepage', one); root.classList.toggle('hl-tabbed', !one);
    if (one) {
      // Lead with the written report in its original order; park the hidden
      // dashboard shells after it, rather than before the article's first word.
      sections.forEach(function (s) { content.insertBefore(s.node, panels[0]); });
      panels.forEach(function (p) { p.hidden = true; });
      tabs.forEach(function (t) { t.setAttribute('aria-selected', 'false'); t.tabIndex = -1; });
      tablist.hidden = true; currentLabel.textContent = 'Read as one page';
      oneLink.textContent = 'Back to tabs'; oneLink.href = '#tab-' + TOKENS[active];
      if (typeof readBtn !== 'undefined' && readBtn) { readBtn.href = '#tab-' + TOKENS[active]; readBtn.querySelector('.hl-quicklink__label').textContent = 'Back to the tabs'; }
    } else {
      sections.forEach(function (s) { var p = panels[TOKENS.indexOf(s.token)]; p.insertBefore(s.node, p.querySelector('.hl-rv-sponsor-card, .hl-rv-nextprev')); });
      tablist.hidden = false; oneLink.textContent = 'Read as one page'; oneLink.href = '#one-page'; select(active);
      if (typeof readBtn !== 'undefined' && readBtn) { readBtn.href = '#one-page'; readBtn.querySelector('.hl-quicklink__label').textContent = 'Read the full report'; }
    }
    closeMenu(false); measureBar(); updateProgress();
  }
  function measureBar() {
    if (!document || !document.documentElement) return;
    root.style.setProperty('--hl-rv-bar-h', mobileLine.offsetHeight + 4 + 'px');
    root.style.setProperty('--hl-rv-tabs-h', Math.max(0, mobileLine.offsetTop - 4) + 'px');
    var nav = document.querySelector('.hl-nav');
    root.style.setProperty('--hl-rv-nav-h', !phone.matches && nav ? nav.offsetHeight + 'px' : '0px');
    if (window.HLGlossary) window.HLGlossary.applyEdgeClasses(content);
  }
  function scrollTopTab() { var body = document.querySelector('.hl-post-body'); window.scrollTo({ top: Math.max(0, body.getBoundingClientRect().top + scrollY - (phone.matches ? 0 : (document.querySelector('.hl-nav') || {}).offsetHeight || 0)), behavior: 'instant' }); }
  function navigateTab(i, scroll, replace) {
    navigatingUntil = Date.now() + 700;
    mode(false); select(i); history[replace ? 'replaceState' : 'pushState'](null, '', '#tab-' + TOKENS[i]);
    if (scroll) scrollTopTab();
  }
  function target(hash) { try { return decodeURIComponent(hash.replace(/^#/, '')); } catch (e) { return hash.slice(1); } }
  function go(hash, scroll) {
    navigatingUntil = Date.now() + 700;
    var id = target(hash);
    if (id === 'one-page') { mode(true); if (scroll) scrollTopTab(); return true; }
    var idx = TOKENS.indexOf(id.replace(/^tab-/, ''));
    if (id.indexOf('tab-') === 0 && idx >= 0) {
      mode(false); select(idx);
      if (scroll) scrollTopTab();
      panels[idx].focus({ preventScroll: true });
      return true;
    }
    // An old link to a tab this report does not have (nothing was tagged for it) opens the first tab instead of doing nothing.
    if (id.indexOf('tab-') === 0 && ALL_TOKENS.indexOf(id.slice(4)) >= 0) { mode(false); select(0); if (scroll) scrollTopTab(); panels[0].focus({ preventScroll: true }); return true; }
    var el = document.getElementById(id); if (!el) return false;
    var panel = el.closest('.hl-rv-panel');
    if (!onepage && panel) { mode(false); select(panels.indexOf(panel)); }
    // Row fragments also expand a phone summary card on cold load.
    var viewBody = el.closest('.hl-rv-view-body');
    if (viewBody && viewBody.hidden) { viewBody.hidden = false; var toggle = document.querySelector('[aria-controls="' + viewBody.id + '"]'); if (toggle) { toggle.textContent = 'Hide the view'; toggle.setAttribute('aria-expanded', 'true'); } }
    // Source blocks can be outside a panel in one-page mode.
    for (var d = el.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true;
    // Dashboard row links must reveal a filtered-out row, too.
    if (el.tagName === 'TR' && el.hidden) { el.hidden = false; el.dispatchEvent(new Event('hl-rv-reveal')); }
    closeMenu(false);
    requestAnimationFrame(function () {
      el.scrollIntoView({ block: 'start', behavior: 'instant' });
      if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1'); el.focus({ preventScroll: true });
      el.classList.add('hl-rv-target'); setTimeout(function () { el.classList.remove('hl-rv-target'); }, 1500);
    });
    return true;
  }
  // Capture also catches figure-nav chips and links containing the full report URL.
  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest && e.target.closest('a[href]'); if (!a || a.hasAttribute('download') || a.target && a.target !== '_self') return;
    var u; try { u = new URL(a.getAttribute('href'), location.href); } catch (x) { return; }
    if (u.origin !== location.origin || u.pathname !== location.pathname || u.search !== location.search || !u.hash) return;
    if (!go(u.hash, true)) return;
    e.preventDefault(); history.pushState(null, '', u.hash);
    // Suppress older delegated smooth-scroll handlers, which race tab visibility.
    e.stopImmediatePropagation();
  }, true);
  window.addEventListener('hashchange', function () { go(location.hash, true); });
  window.addEventListener('popstate', function () { if (!location.hash) { mode(false); select(0); } else go(location.hash, true); });

  function tableFold(parent, label) { var d = make('details', 'hl-rv-table-fold', null, parent); d.open = true; make('summary', '', label, d); return d; }
  function missing(parent, need) { make('p', 'hl-rv-unavailable', 'View unavailable: needs ' + need + '. The full report follows.', parent); }
  function badge(parent, value) {
    // Keep range, compound and off-scale wording intact; never silently rescale.
    var cls = 'hl-rv-badge';
    if (/^(DEFINITE|HIGH|MODERATE|LOW|INSUFFICIENT|OBSERVED|INFERRED|NOT SHOWN)$/.test(value)) cls += ' hl-rv-' + value.toLowerCase().replace(/ /g, '-');
    else cls += ' hl-rv-unscaled';
    return make('span', cls, value, parent);
  }
  function dashTable(parent, m, caption, id) {
    var wrap = make('div', 'hl-rv-table-wrap', null, parent); wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', caption);
    var table = make('table', 'hl-rv-table', null, wrap); table.setAttribute('role', 'table'); if (id) table.id = id;
    make('caption', '', caption, table);
    var thead = make('thead', '', null, table); thead.setAttribute('role', 'rowgroup');
    var tr = make('tr', '', null, thead); tr.setAttribute('role', 'row');
    m.headers.concat(['Source']).forEach(function (h) { var th = make('th', '', h, tr); th.scope = 'col'; th.setAttribute('role', 'columnheader'); });
    var body = make('tbody', '', null, table); body.setAttribute('role', 'rowgroup');
    m.rows.forEach(function (r, ri) {
      var row = make('tr', '', null, body); row.setAttribute('role', 'row'); row.id = 'hl-rv-' + (id || m.token + '-' + m.index) + '-' + (ri + 1);
      r.forEach(function (v, ci) {
        var td = make('td', '', null, row); td.setAttribute('role', 'cell'); td.dataset.label = m.headers[ci];
        if (/Conf|Status|Grade/i.test(m.headers[ci])) badge(td, v); else make('span', '', v, td);
      });
      var source = make('td', '', null, row); source.setAttribute('role', 'cell'); source.dataset.label = 'Source'; sourceLink(m, source, r.slice(0, 2).join(' · '));
    });
    var tools = tableCopy(table, parent, /^Indicator/i.test(m.headers[0]) ? 0 : undefined); wrap.before(tools);
    return table;
  }
  function filters(parent, table, specs, noun, onApply) {
    var area = make('div', 'hl-rv-filters', null, parent), controls = [];
    var label = make('label', '', 'Search ' + noun, area); var input = make('input', '', null, label); input.type = 'search'; controls.push(input);
    specs.forEach(function (s) {
      var l = make('label', '', s.label, area), sel = make('select', '', null, l); controls.push(sel);
      var opt = make('option', '', 'All ' + s.label.toLowerCase(), sel); opt.value = '';
      s.values.forEach(function (v) { var o = make('option', '', v, sel); o.value = v; });
    });
    var rows = Array.from(table.tBodies[0].rows), count = make('p', 'hl-rv-count', '', area); count.setAttribute('role', 'status');
    function apply() {
      var n = 0;
      rows.forEach(function (row) {
        var hit = text(row).toLowerCase().includes(input.value.toLowerCase()) && specs.every(function (s, i) {
          var v = controls[i + 1].value, c = text(row.cells[s.col]);
          if (s.match) return !v || s.match(row, v);
          if (!v) return true;
          if (v === 'Range') return /\b(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)\b/.test(c);
          if (v === 'Unscaled') return !/^(DEFINITE|HIGH|MODERATE|LOW|INSUFFICIENT)$/.test(c) && !/^(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)$/.test(c);
          return c.includes(v);
        });
        row.hidden = !hit; if (hit) n++;
      });
      count.textContent = 'Showing ' + n + ' of ' + rows.length + ' ' + noun;
      if (onApply) onApply(rows.filter(function (r) { return !r.hidden; }), controls.some(function (c) { return !!c.value; }));
    }
    controls.forEach(function (c) { c.addEventListener('input', apply); if (c.tagName === 'SELECT') c.addEventListener('change', apply); });
    button('Reset filters', area, function () { controls.forEach(function (c) { c.value = ''; }); apply(); });
    table.parentElement.before(area); apply();
    rows.forEach(function (r) { r.addEventListener('hl-rv-reveal', function () { controls.forEach(function (c) { c.value = ''; }); apply(); }); });
  }
  // Design D, D4: the filter console. One search box and one row of chips for each facet that has a column behind it (Stage, Tactic, Status, Confidence, and the report's own shortlist when it has one),
  // each chip with its count over every row of the table. Single choice inside a facet, all facets and the search combine. The count line shows only while something is filtered. Once the console has
  // scrolled up under the reading line, a slim sticky bar (search, a Filters button with the facets in a panel, the count and Clear) takes over; both draw from one state.
  function pipsBefore(el, value) {
    if (!PIPS[value] || !el.parentNode) return null;
    var p = make('span', 'hl-rv-pips hl-rv-lv-' + value); p.setAttribute('aria-hidden', 'true'); for (var k = 0; k < 5; k++) make('i', k < PIPS[value] ? 'on' : '', null, p);
    el.parentNode.insertBefore(p, el); return p;
  }
  var consoleSeq = 0;
  function chainConsole(parent, table, specs, noun, onApply) {
    var rows = Array.from(table.tBodies[0].rows), state = { q: '', facet: {} }, seq = ++consoleSeq;
    function pred(row, s, v) {
      if (s.match) return s.match(row, v);
      var c = text(row.cells[s.col]);
      if (v === 'Range') return /\b(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)\b/.test(c);
      if (v === 'Unscaled') return !/^(DEFINITE|HIGH|MODERATE|LOW|INSUFFICIENT)$/.test(c) && !/^(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)$/.test(c);
      return c === v;
    }
    // A facet value with no row behind it is not drawn: a chip that can only give an empty table is not a filter.
    var facets = specs.map(function (s) { return { spec: s, values: s.values.map(function (v) { return { v: v, n: rows.filter(function (r) { return pred(r, s, v); }).length }; }).filter(function (x) { return x.n > 0; }) }; }).filter(function (f) { return f.values.length; });
    var area = make('section', 'hl-rv-pn hl-rv-console hl-rv-filters', null, parent); area.setAttribute('role', 'search'); area.setAttribute('aria-label', 'Search and filter the attack chain');
    var head = make('div', 'hl-rv-pn-head', null, area);
    icon('<path d="M3 5h18l-7 8v6l-4-2v-4z"/>', 17, head, 'hl-rv-eyebrow-icon'); make('h3', 'hl-rv-pn-title', 'Filter the procedures', head);
    make('p', 'hl-rv-pn-sub', 'search, then ' + facets.map(function (f) { return f.spec.label.toLowerCase(); }).join(', '), head);
    var search = make('label', 'hl-rv-csearch', null, area); make('span', '', 'Search ' + noun, search);
    var input = make('input', '', null, search); input.type = 'search'; input.autocomplete = 'off'; input.placeholder = 'Search, for example a technique ID or a host';
    var tog = make('button', 'hl-rv-ftoggle', 'Filters', area); tog.type = 'button'; tog.setAttribute('aria-expanded', 'false'); tog.setAttribute('aria-controls', 'hl-rv-facets-' + seq);
    var facetHost = make('div', 'hl-rv-facets', null, area); facetHost.id = 'hl-rv-facets-' + seq;
    var chips = [];
    function drawFacets(host, extra) {
      facets.forEach(function (f) {
        var fr = make('div', 'hl-rv-fr', null, host), lab = make('b', '', f.spec.label, fr);
        var group = make('div', 'hl-rv-fchips', null, fr); group.setAttribute('role', 'group'); group.setAttribute('aria-label', 'Filter by ' + f.spec.label.toLowerCase());
        f.values.forEach(function (x) {
          var b = make('button', 'hl-rv-fchip', null, group); b.type = 'button'; b.setAttribute('aria-pressed', 'false'); b.dataset.rvFacet = f.spec.label; b.dataset.rvValue = x.v;
          if (f.spec.label === 'Status') b.classList.add('hl-rv-st-' + x.v.toLowerCase().replace(/ /g, '-'));
          make('span', '', x.v, b); b.appendChild(document.createTextNode(' ')); make('strong', '', x.n, b);
          b.addEventListener('click', function () { toggle(f.spec.label, x.v); });
          chips.push(b);
        });
      });
    }
    drawFacets(facetHost);
    var count = make('p', 'hl-rv-count', '', area); count.setAttribute('role', 'status');
    var reset = button('Reset filters', area, function () { state.q = ''; state.facet = {}; apply(); }); reset.hidden = true;
    // the slim bar
    var anchor = make('div', 'hl-rv-minibar-anchor'); anchor.setAttribute('role', 'presentation');
    var mini = make('div', 'hl-rv-minibar', null, anchor); mini.hidden = true; mini.setAttribute('role', 'search'); mini.setAttribute('aria-label', 'Search and filter the attack chain, slim bar');
    var mrow = make('div', 'hl-rv-mrow', null, mini);
    var minput = make('input', '', null, make('label', 'hl-rv-msearch', null, mrow)); minput.type = 'search'; minput.autocomplete = 'off'; minput.placeholder = 'Search ' + noun; minput.setAttribute('aria-label', 'Search ' + noun);
    var mtog = make('button', 'hl-rv-ftoggle hl-rv-mtoggle', 'Filters', mrow); mtog.type = 'button'; mtog.setAttribute('aria-expanded', 'false'); mtog.setAttribute('aria-controls', 'hl-rv-mpanel-' + seq);
    var mbadge = make('strong', '', '', mtog);
    var mcount = make('span', 'hl-rv-mcount', '', mrow); mcount.setAttribute('role', 'status');
    var mclear = button('Clear', mrow, function () { state.q = ''; state.facet = {}; apply(); }); mclear.hidden = true;
    var mpanel = make('div', 'hl-rv-mpanel', null, mini); mpanel.id = 'hl-rv-mpanel-' + seq; mpanel.hidden = true; drawFacets(mpanel);
    tog.addEventListener('click', function () { var o = area.classList.toggle('is-open'); tog.setAttribute('aria-expanded', String(o)); });
    mtog.addEventListener('click', function () { mpanel.hidden = !mpanel.hidden; mtog.setAttribute('aria-expanded', String(!mpanel.hidden)); });
    function toggle(label, value) { var on = state.facet[label] !== value; if (on) state.facet[label] = value; else delete state.facet[label]; apply(); return on; }
    function apply() {
      var n = 0, q = state.q.toLowerCase(), labels = Object.keys(state.facet);
      rows.forEach(function (row) {
        var hit = (!q || text(row).toLowerCase().includes(q)) && facets.every(function (f) { var v = state.facet[f.spec.label]; return !v || pred(row, f.spec, v); });
        row.hidden = !hit; if (hit) n++;
      });
      var filtering = !!q || labels.length > 0;
      chips.forEach(function (b) { b.setAttribute('aria-pressed', String(state.facet[b.dataset.rvFacet] === b.dataset.rvValue)); });
      if (input.value !== state.q) input.value = state.q; if (minput.value !== state.q) minput.value = state.q;
      var line = filtering ? 'Showing ' + n + ' of ' + rows.length + ' ' + noun : '';
      count.textContent = line; mcount.textContent = line; reset.hidden = !filtering; mclear.hidden = !filtering;
      var active = labels.length + (q ? 1 : 0); mbadge.textContent = active ? String(active) : '';
      mtog.setAttribute('aria-label', active ? 'Filters, ' + active + ' active' : 'Filters');
      if (onApply) onApply(rows.filter(function (r) { return !r.hidden; }), filtering, state);
    }
    input.addEventListener('input', function () { state.q = input.value; apply(); }); minput.addEventListener('input', function () { state.q = minput.value; apply(); });
    rows.forEach(function (r) { r.addEventListener('hl-rv-reveal', function () { state.q = ''; state.facet = {}; apply(); }); });
    // The slim bar shows while the console is above the reading line and the table's end is not.
    var watched = null, ticking = false;
    function place() {
      ticking = false;
      var visible = !!area.offsetParent && !!watched && !!watched.offsetParent;
      if (!visible) { if (!mini.hidden) { mini.hidden = true; mpanel.hidden = true; mtog.setAttribute('aria-expanded', 'false'); } return; }
      var cs = getComputedStyle(root), top = (parseFloat(cs.getPropertyValue('--hl-rv-nav-h')) || 0) + (parseFloat(cs.getPropertyValue('--hl-rv-bar-h')) || 56) + 8;
      var a = area.getBoundingClientRect(), w = watched.getBoundingClientRect();
      // while something is filtered or typed the bar stays (a short result must not take the search box away mid-word); it still stops where the view ends, as a sticky box does
      var active = !!state.q || Object.keys(state.facet).length > 0;
      var show = a.bottom < top && (w.bottom > top + 96 || active);
      if (show === mini.hidden) { mini.hidden = !show; if (!show) { mpanel.hidden = true; mtog.setAttribute('aria-expanded', 'false'); } }
    }
    function queue() { if (!ticking) { ticking = true; (window.requestAnimationFrame || function (f) { return setTimeout(f, 16); })(place); } }
    window.addEventListener('scroll', queue, { passive: true }); window.addEventListener('resize', queue);
    apply();
    return { area: area, head: head, anchor: anchor, toggle: toggle, watch: function (el) { watched = el; queue(); } };
  }
  // ---- Design D, D3: the scan band, the risk bars and the judgments view of the Overview, and the linked highlighting between them and the summary prose ----
  var GRADE_HUES = { 'ACCESS SHOWN': '#f87171', COMPROMISED: '#fb923c', REACHED: '#7aa7f0', LISTED: '#6f7681', CURRENT: '#22d3ee', OTHER: '#8a8a8a' };
  var STATUS_HUES = { OBSERVED: '#22d3ee', INFERRED: '#a371f7', 'NOT SHOWN': '#6f7681' };
  var GRADE_ORDER = ['ACCESS SHOWN', 'COMPROMISED', 'REACHED', 'LISTED', 'CURRENT', 'OTHER'];
  var LINK = {};   // key -> { label, terms, cs (case sensitive), els }
  function linkKey(el, key, label, terms, cs) {
    el.dataset.rvKey = key;
    if (!LINK[key]) LINK[key] = { label: label, terms: terms, cs: !!cs, els: [] };
    LINK[key].els.push(el);
  }
  function pnPanel(parent, cls, title, sub, tok, note) {
    var box = make('section', 'hl-rv-pn ' + cls, null, parent); box.setAttribute('role', 'group'); box.setAttribute('aria-label', title);
    var head = make('div', 'hl-rv-pn-head', null, box);
    icon(TAB_ICONS[tok], 17, head, 'hl-rv-eyebrow-icon');
    make('h3', 'hl-rv-pn-title', title, head); make('p', 'hl-rv-pn-sub', sub, head);
    if (note) infoButton(head, [make('p', 'hl-rv-pn-note', note)], 'How counted: ' + title);
    return box;
  }
  function gradeOf(v) { var m = String(v).match(/^(ACCESS SHOWN|COMPROMISED|REACHED|LISTED|CURRENT)/); return m ? m[1] : 'OTHER'; }
  function plainName(v) { return v.replace(/^(?:an?|the)\s+/i, '').replace(/[\s.]+$/, ''); }
  function fromNote(m) { return text(m.heading) + ', table ' + m.index + ', ' + m.rows.length + ' rows'; }
  function scanBand(body) {
    var band = make('div', 'hl-rv-scan', null, body), n = 0;
    if (victims && col(victims, /Grade/i) >= 0) {
      var vg = col(victims, /Grade/i), counts = {};
      victims.rows.forEach(function (r) { var k = gradeOf(r[vg]); counts[k] = (counts[k] || 0) + 1; });
      var pn = pnPanel(band, 'hl-rv-pn--grades', 'Victims by access grade', victims.rows.length + ' organisation rows', 'victims',
        'How counted: one square for each row of the victim table, coloured by that row\'s Grade. From ' + fromNote(victims) + '.');
      var order = GRADE_ORDER.filter(function (k) { return counts[k]; });
      var squares = make('div', 'hl-rv-squares', null, pn); squares.setAttribute('role', 'img');
      squares.setAttribute('aria-label', victims.rows.length + ' organisation rows by grade: ' + order.map(function (k) { return counts[k] + ' ' + k; }).join(', '));
      victims.rows.map(function (r, i) { return { k: gradeOf(r[vg]), i: i }; }).sort(function (a, b) { return GRADE_ORDER.indexOf(a.k) - GRADE_ORDER.indexOf(b.k) || a.i - b.i; })
        .forEach(function (o) { var sq = make('span', 'hl-rv-sq', null, squares); sq.dataset.rvGrade = o.k; sq.style.setProperty('--seg', GRADE_HUES[o.k]); });
      var legend = make('div', 'hl-rv-legend', null, pn); legend.setAttribute('role', 'group'); legend.setAttribute('aria-label', 'Grades');
      order.forEach(function (k) { var b = make('button', 'hl-rv-key', null, legend); b.type = 'button'; b.setAttribute('aria-pressed', 'false'); b.style.setProperty('--seg', GRADE_HUES[k]);
        make('span', 'hl-rv-key-sw', null, b); make('span', 'hl-rv-key-name', k === 'OTHER' ? 'Other grades' : k, b); make('strong', '', counts[k], b); linkKey(b, 'grade:' + k, k, k === 'OTHER' ? [] : [k], true); });
      var top = victims.rows.filter(function (r) { return /^(ACCESS SHOWN|COMPROMISED)$/.test(gradeOf(r[vg])); });
      if (top.length) {
        var list = make('ul', 'hl-rv-orgs', null, pn);
        top.slice(0, 8).forEach(function (r) { var li = make('li', '', null, list), b = make('button', 'hl-rv-org', null, li); b.type = 'button'; b.setAttribute('aria-pressed', 'false');
          make('span', 'hl-rv-org-name', r[0], b); var gk = gradeOf(r[vg]); var pill = make('span', 'hl-rv-org-grade', gk, b); pill.style.setProperty('--seg', GRADE_HUES[gk]);
          var nm = plainName(r[0]); linkKey(b, 'org:' + r[0], r[0], nm.length >= 8 ? [nm] : [], false); });
        if (top.length > 8) make('p', 'hl-rv-pn-more', (top.length - 8) + ' more organisation rows at these two grades are in the Victims tab.', pn);
      }
      make('p', 'hl-rv-linkread', 'Hover or tap a grade or an organisation to light where the summary names it.', pn).setAttribute('role', 'status');
      n++;
    }
    // The tactic heat strip: one column per tactic, one cell per procedure row (status-coloured when the table has Status), else one cell per technique the detection page covers.
    var heat = null, heatSource = '';
    if (attack) heat = attack.rows.map(function (r) { return { tactic: tacticName(cell(r, attackC.tactic)) || 'Unlabelled', status: attackC.status >= 0 ? r[attackC.status] : '', label: cell(r, attackC.id) + ' ' + cell(r, attackC.name) }; });
    else if (siteData.techniques && siteData.techniques.rows && siteData.techniques.rows.length) { heat = siteData.techniques.rows.map(function (r) { return { tactic: r.tactic, status: '', label: r.id + ' ' + r.name }; }); heatSource = 'detection'; }
    if (heat && heat.length) {
      var cols = {}, tacticList = [];
      heat.forEach(function (h) { if (!cols[h.tactic]) { cols[h.tactic] = []; tacticList.push(h.tactic); } cols[h.tactic].push(h); });
      var seen = tacticList.slice(); tacticList.sort(function (a, b) { var x = TACTIC_ORDER.indexOf(a), y = TACTIC_ORDER.indexOf(b); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y) || seen.indexOf(a) - seen.indexOf(b); });
      var hasStatus = !heatSource && attackC.status >= 0;
      var sub = heatSource ? heat.length + ' technique' + (heat.length === 1 ? '' : 's') + ' in ' + tacticList.length + ' tactic' + (tacticList.length === 1 ? '' : 's') + ', from the detection page' : heat.length + (attack.legacy ? ' mapping rows' : ' procedure rows') + ', ' + tacticList.length + ' tactic' + (tacticList.length === 1 ? '' : 's');
      var hp = pnPanel(band, 'hl-rv-pn--heat', heatSource ? 'Techniques by tactic (detection coverage)' : 'Techniques by tactic', sub, 'chain',
        heatSource ? 'How counted: one cell for each technique ID the report\'s detection rules cover, grouped by the tactic the detection page gives it. The report has no ATT&CK mapping table of its own, so every cell is one colour. From the detection page (_data/detection_attack.yml).'
          : 'How counted: one cell for each row of the ATT&CK table, grouped by its Tactic cell' + (hasStatus ? ' and coloured by its Status' : '; the report states no Status, so every cell is one colour') + '. From ' + fromNote(attack) + '.');
      if (hasStatus) {
        var lg = make('div', 'hl-rv-heat-legend', null, hp);
        ['OBSERVED', 'INFERRED', 'NOT SHOWN'].forEach(function (k) { var it = make('span', '', null, lg); var sw = make('span', 'hl-rv-cell hl-rv-cell--sw', null, it); sw.dataset.rvStatus = k; sw.style.setProperty('--seg', STATUS_HUES[k]); make('span', '', k.charAt(0) + k.slice(1).toLowerCase(), it); });
      }
      var scroller = make('div', 'hl-rv-heat', null, hp); scroller.tabIndex = 0; scroller.setAttribute('role', 'region'); scroller.setAttribute('aria-label', 'Tactic heat strip');
      tacticList.forEach(function (tc) {
        var colEl = make('div', 'hl-rv-heatcol', null, scroller);
        var hb = make('button', 'hl-rv-heathead', null, colEl); hb.type = 'button'; hb.setAttribute('aria-pressed', 'false'); hb.setAttribute('aria-label', tc + ', ' + cols[tc].length + ' ' + (heatSource ? 'technique' : 'row') + (cols[tc].length === 1 ? '' : 's'));
        make('strong', '', cols[tc].length, hb); make('span', '', tc, hb); linkKey(hb, 'tactic:' + tc, tc, tc === 'Unlabelled' ? [] : [tc], false);
        var cells = make('div', 'hl-rv-heatcells', null, colEl);
        cols[tc].forEach(function (h) { var c = make('span', 'hl-rv-cell', null, cells); c.title = h.label; if (hasStatus) { c.dataset.rvStatus = h.status; c.style.setProperty('--seg', STATUS_HUES[h.status] || 'var(--acc)'); } });
      });
      make('p', 'hl-rv-linkread', 'Hover or tap a tactic to light the words in the summary that name it.', hp).setAttribute('role', 'status');
      n++;
    }
    if (chronology) {
      var crows = chronologyRows(chronology);
      if (crows.every(function (r) { return !isNaN(r.when); })) {
        var tp = pnPanel(band, 'hl-rv-pn--time', 'Observation window', crows.length + ' dated events, from the chronology', 'timeline',
          'How counted: one marker for each row of the chronology, placed by its printed date (a range sits at its middle). The full chronology, with every date as written, is in the Timeline tab. From ' + fromNote(chronology) + '.');
        var min = Math.min.apply(null, crows.map(function (r) { return r.when; })), max = Math.max.apply(null, crows.map(function (r) { return r.end; }));
        var rail = make('div', 'hl-rv-crail', null, tp), detail = make('p', 'hl-rv-cdetail', 'Select an event to read its date and observation.', tp); detail.setAttribute('role', 'status');
        var marks = crows.map(function (r, i) {
          var b = make('button', 'hl-rv-cmark hl-rv-' + r.quality, null, rail); b.type = 'button'; b.dataset.rvEvent = i; b.setAttribute('aria-pressed', 'false'); b.setAttribute('aria-label', 'Event ' + (i + 1) + ', ' + r.display + ': ' + r.event);
          make('span', '', i + 1, b); b.dataset.start = r.when; b.dataset.end = r.end;
          b.style.left = (max === min ? 50 : 100 * ((r.when + r.end) / 2 - min) / (max - min)) + '%';
          b.addEventListener('click', function () { marks.forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); }); detail.textContent = '';
            make('strong', '', r.display, detail); detail.appendChild(document.createTextNode(' · ' + r.event + ' ')); var more = link('Read it in the Timeline tab', '#' + chronology.heading.id, detail); more.className = 'hl-rv-cmore'; });
          return b;
        });
        var ends = make('div', 'hl-rv-cends', null, tp); make('span', '', crows[0].display, ends); make('span', '', crows[crows.length - 1].display, ends);
        function place() {
          var width = rail.clientWidth; if (!width) return; var slots = [];
          marks.forEach(function (b) { var a = +b.dataset.start, z = +b.dataset.end, x = max === min ? width / 2 : ((a + z) / 2 - min) / (max - min) * width, w = 44, slot = 0;
            while (slots[slot] && slots[slot].some(function (s) { return x - w / 2 < s.r && x + w / 2 > s.l; })) slot++;
            if (!slots[slot]) slots[slot] = []; slots[slot].push({ l: x - w / 2, r: x + w / 2 }); b.style.top = slot * 46 + 'px'; });
          rail.style.height = Math.max(1, slots.length) * 46 + 'px';
        }
        new ResizeObserver(place).observe(rail);
        n++;
      }
    }
    if (!n) band.remove();
  }
  // The risk assessment bars: one bar for every row of each risk table in the Overview, the score and the weight when the table has them, the row's own justification beside it.
  function riskPanel(body) {
    if (!riskTables.length) return;
    var rowsTotal = riskTables.reduce(function (s, m) { return s + m.rows.length; }, 0);
    var pn = pnPanel(body, 'hl-rv-pn--risk', 'Risk assessment', rowsTotal + ' rows' + (riskTables.length > 1 ? ' in ' + riskTables.length + ' tables' : ''), 'confidence',
      'How counted: one bar for each row of the risk table, as long as its score is of its maximum (a word rating such as HIGH is drawn on a four-step scale and marked as one); the weight and the justification are the table\'s own text. The table stays in the report. From ' + riskTables.map(fromNote).join('; ') + '.');
    riskTables.forEach(function (m) {
      var wrap = make('div', 'hl-rv-risk', null, pn); if (riskTables.length > 1) make('h4', 'hl-rv-risk-cap', text(m.heading) + ', table ' + m.index, wrap);
      var list = make('ol', 'hl-rv-dims', null, wrap);
      riskRows(m).forEach(function (r) {
        var li = make('li', 'hl-rv-riskrow' + (r.total ? ' is-total' : ''), null, list), head = make('div', 'hl-rv-riskhead', null, li);
        make('span', 'hl-rv-riskname', r.name, head);
        var sc = make('span', 'hl-rv-riskscore', null, head);
        if (isFinite(r.score.num)) { make('strong', '', String(r.score.num), sc); make('small', '', '/' + r.score.max, sc); } else make('strong', 'hl-rv-riskword', r.score.text, sc);
        var meta = make('span', 'hl-rv-riskmeta', null, head);
        if (r.weight) make('span', '', r.weight + ' weight', meta);
        if (isFinite(r.score.num) && r.score.rest) make('span', 'hl-rv-riskrest', r.score.rest, meta);
        if (r.sev) make('span', 'hl-rv-riskrest', r.sev, meta);
        var bar = make('div', 'hl-rv-riskbar', null, li); bar.setAttribute('role', 'img');
        var fill = make('i', '', null, bar), frac, scale;
        if (isFinite(r.score.num)) { frac = Math.max(0, Math.min(1, r.score.num / (r.score.max || 10))); scale = 'num'; bar.setAttribute('aria-label', r.score.num + ' out of ' + r.score.max); }
        else if (RISK_WORDS[r.score.word]) { frac = RISK_WORDS[r.score.word] / 4; scale = 'word'; bar.setAttribute('aria-label', r.score.word + ' rating, drawn on a four-step scale'); }
        else { frac = 0; scale = 'none'; bar.setAttribute('aria-label', 'No numeric score: ' + r.score.text); }
        bar.dataset.rvScale = scale; fill.style.width = Math.round(frac * 1000) / 10 + '%';
        if (r.why) make('p', 'hl-rv-riskwhy', r.why, li);
      });
    });
  }
  // The judgments view: every row of the judgments table, shown in full, with a chip for each printed confidence and its count; the chips filter this copy only.
  var PIPS = { DEFINITE: 5, HIGH: 4, MODERATE: 3, LOW: 2, INSUFFICIENT: 1 };
  function judgmentsPanel(body) {
    if (!judgments) return;
    var cc = col(judgments, /Confidence/i), nc = col(judgments, /Claim|Judgment|Finding/i), wc = col(judgments, /change/i);
    var pn = pnPanel(body, 'hl-rv-pn--judg', 'Judgments', judgments.rows.length + ' judgments, each with how sure the report is' + (wc >= 0 ? ' and what would change it' : ''), 'confidence',
      'How counted: one row for each row of the judgments table, in the table\'s order, with its confidence as printed. A range or a compound level is a chip of its own and is never rescaled. The Confidence tab keeps the table and its own view. From ' + fromNote(judgments) + '.');
    // Chips group the printed ratings by the five canonical levels plus one "Other / ranges" chip (a range, a compound level or a word off the scale). The row keeps the rating exactly as printed.
    var LEVELS = ['DEFINITE', 'HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT'];
    function levelOf(v) { var u = String(v).trim().toUpperCase(); return LEVELS.indexOf(u) >= 0 ? u : 'OTHER'; }
    var counts = {}; judgments.rows.forEach(function (r) { var k = levelOf(r[cc]); counts[k] = (counts[k] || 0) + 1; });
    var chips = make('div', 'hl-rv-jchips', null, pn); chips.setAttribute('role', 'group'); chips.setAttribute('aria-label', 'Filter judgments by confidence');
    var res = make('p', 'hl-rv-count', '', pn); res.setAttribute('role', 'status');
    var list = make('ol', 'hl-rv-jlist' + (wc < 0 ? ' hl-rv-jlist--two' : ''), null, pn), rows = [];
    function chip(label, value, n) { var b = make('button', 'hl-rv-jchip', null, chips); b.type = 'button'; b.setAttribute('aria-pressed', String(value === '')); b.dataset.rvConf = value; if (PIPS[value]) b.classList.add('hl-rv-lv-' + value);
      make('span', '', label, b); b.appendChild(document.createTextNode(' ')); make('strong', '', n, b);
      b.addEventListener('click', function () { Array.from(chips.children).forEach(function (c) { c.setAttribute('aria-pressed', String(c === b)); });
        var shown = 0; rows.forEach(function (li) { var hit = !value || li.dataset.rvLevel === value; li.hidden = !hit; if (hit) shown++; });
        res.textContent = value ? 'Showing ' + shown + ' of ' + judgments.rows.length + ' judgments' : ''; }); }
    chip('All', '', judgments.rows.length); LEVELS.concat(['OTHER']).forEach(function (v) { if (counts[v]) chip(v === 'OTHER' ? 'Other / ranges' : v, v, counts[v]); });
    judgments.rows.forEach(function (r, i) {
      var li = make('li', 'hl-rv-jrow', null, list); li.dataset.rvConf = r[cc]; li.dataset.rvLevel = levelOf(r[cc]); rows.push(li);
      make('span', 'hl-rv-jn', String(i + 1).padStart(2, '0'), li).setAttribute('aria-hidden', 'true');
      make('p', 'hl-rv-claim', r[nc], li);
      var cf = make('div', 'hl-rv-jconf' + (PIPS[r[cc]] ? ' hl-rv-lv-' + r[cc] : ''), null, li);
      if (PIPS[r[cc]]) { var pips = make('span', 'hl-rv-pips', null, cf); pips.setAttribute('aria-hidden', 'true'); for (var k = 0; k < 5; k++) make('i', k < PIPS[r[cc]] ? 'on' : '', null, pips); }
      make('span', 'hl-rv-jword', r[cc], cf);
      if (wc >= 0) { var ch = make('p', 'hl-rv-jchange', null, li); make('small', '', 'What would change it', ch); ch.appendChild(document.createTextNode(' ' + r[wc])); }
    });
    if (wc < 0) make('p', 'hl-rv-note hl-rv-unstated', 'Not stated in this report\'s table: what would change each judgment. The view lists the rows as printed.', pn);
  }
  // Linked highlighting. The summary prose is the Overview's own source sections. A grade, a tactic or an organisation named in a panel is wrapped, wherever the prose says it, in a plain span
  // (.hl-rv-hit). The span adds no text, no id and no attribute the report reads: it is not marked as chrome because the completeness check removes chrome whole, and the words inside
  // must stay. Hovering or focusing a key in a panel lights its spans; a press pins it. On a phone a pinned key shows a bar that scrolls the first place into view.
  function wrapHits() {
    var keys = Object.keys(LINK).filter(function (k) { return LINK[k].terms.length; });
    if (!keys.length) return;
    var roots = Array.from((panels[0] || document.createElement('div')).querySelectorAll('.hl-rv-source')); if (!roots.length) return;
    function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
    [true, false].forEach(function (cs) {
      var terms = []; keys.forEach(function (k) { if (LINK[k].cs === cs) LINK[k].terms.forEach(function (t) { terms.push({ t: t, k: k }); }); });
      if (!terms.length) return;
      terms.sort(function (a, b) { return b.t.length - a.t.length; });
      var re = new RegExp('(?<![A-Za-z0-9])(' + terms.map(function (x) { return esc(x.t); }).join('|') + ')(?![A-Za-z0-9])', cs ? 'g' : 'gi');
      var byTerm = {}; terms.forEach(function (x) { byTerm[cs ? x.t : x.t.toLowerCase()] = x.k; });
      roots.forEach(function (root) {
        var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: function (nd) {
          if (!nd.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
          for (var p = nd.parentNode; p && p !== root; p = p.parentNode) {
            if (p.nodeType !== 1) continue;
            if (p.hasAttribute('data-rv-chrome') || /^(TABLE|PRE|CODE|A|H1|H2|H3|H4|H5|H6|SUMMARY|BUTTON|SCRIPT|STYLE|TEXTAREA)$/.test(p.tagName) || p.classList.contains('hl-gloss')) return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        } });
        var nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
        nodes.forEach(function (nd) {
          var s = nd.nodeValue, last = 0, frag = null, m; re.lastIndex = 0;
          while ((m = re.exec(s))) {
            if (!frag) frag = document.createDocumentFragment();
            if (m.index > last) frag.appendChild(document.createTextNode(s.slice(last, m.index)));
            var sp = document.createElement('span'); sp.className = 'hl-rv-hit'; sp.dataset.rvHit = byTerm[cs ? m[1] : m[1].toLowerCase()]; sp.textContent = m[1]; frag.appendChild(sp);
            last = m.index + m[1].length;
          }
          if (frag) { if (last < s.length) frag.appendChild(document.createTextNode(s.slice(last))); nd.parentNode.replaceChild(frag, nd); }
        });
      });
    });
  }
  var litKey = null, pinnedKey = null, hoverKey = null, showBar = null;
  function hitsOf(key) { return Array.from(document.querySelectorAll('.hl-rv-hit')).filter(function (s) { return s.dataset.rvHit === key; }); }
  function paintLink() {
    var key = hoverKey || pinnedKey; litKey = key;
    document.querySelectorAll('.hl-rv-hit.is-lit').forEach(function (s) { s.classList.remove('is-lit'); });
    var hits = key ? hitsOf(key) : []; hits.forEach(function (s) { s.classList.add('is-lit'); });
    Object.keys(LINK).forEach(function (k) { LINK[k].els.forEach(function (el) { el.classList.toggle('is-active', k === key); el.setAttribute('aria-pressed', String(k === pinnedKey)); }); });
    document.querySelectorAll('.hl-rv-linkread').forEach(function (p) {
      p.textContent = key ? (LINK[key].terms.length ? (hits.length ? hits.length + ' place' + (hits.length === 1 ? '' : 's') + ' in the summary name ' + LINK[key].label + '.' : 'The summary does not name ' + LINK[key].label + ' in these words.') : 'Nothing to light for ' + LINK[key].label + '.')
        : p.dataset.idle;
    });
    if (showBar) { showBar.hidden = !(phone.matches && pinnedKey && !onepage); if (!showBar.hidden) { showBar.querySelector('.hl-rv-showbar-count').textContent = hits.length ? hits.length + ' in the summary: ' + LINK[pinnedKey].label : 'Not named in the summary: ' + LINK[pinnedKey].label; showBar.querySelector('.hl-rv-showbar-go').disabled = !hits.length; } }
  }
  function clearLink() { hoverKey = null; pinnedKey = null; if (showBar) paintLink(); }
  function wireLinks() {
    var keys = Object.keys(LINK); if (!keys.length) return;
    document.querySelectorAll('.hl-rv-linkread').forEach(function (p) { p.dataset.idle = p.textContent; });
    keys.forEach(function (k) { LINK[k].els.forEach(function (el) {
      el.addEventListener('pointerenter', function (e) { if (e.pointerType === 'mouse') { hoverKey = k; paintLink(); } });
      el.addEventListener('pointerleave', function (e) { if (e.pointerType === 'mouse') { hoverKey = null; paintLink(); } });
      el.addEventListener('focus', function () { hoverKey = k; paintLink(); });
      el.addEventListener('blur', function () { hoverKey = null; paintLink(); });
      el.addEventListener('click', function () { pinnedKey = pinnedKey === k ? null : k; hoverKey = null; paintLink(); });
    }); });
    showBar = make('div', 'hl-rv-showbar', null, document.body); showBar.hidden = true; showBar.setAttribute('role', 'region'); showBar.setAttribute('aria-label', 'Linked highlighting');
    make('span', 'hl-rv-showbar-count', '', showBar);
    var go = button('Show in the summary', showBar, function () { var first = hitsOf(pinnedKey)[0]; if (first) first.scrollIntoView({ block: 'center', behavior: 'instant' }); }); go.className = 'hl-rv-showbar-go';
    var off = button('Clear', showBar, function () { pinnedKey = null; paintLink(); }); off.className = 'hl-rv-showbar-off';
    phone.addEventListener('change', paintLink);
  }
  // A stat tile is the number, its label, a small drawing of what it counts and where it leads (design D, B's panel). Its "How counted" note is the body of
  // the tile's "i" popover, text unchanged, in the DOM; a tile says where its number is read from and is never drawn without a source.
  // opt: kind (the tile's name for the gate), from (the source sentence), href and dest (where it leads when that is not a tab), viz (a drawing: segments or dots), sub (one line of detail).
  function tile(parent, value, label, how, tok, short, opt) {
    opt = opt || {};
    var cellBox = make('div', 'hl-rv-tilecell', null, parent);
    var a = opt.noLink ? make('div', 'hl-rv-tile', null, cellBox) : link('', opt.href || '#tab-' + tok, cellBox); a.className = 'hl-rv-tile'; a.dataset.rvShort = short; if (opt.kind) a.dataset.rvTile = opt.kind;
    var big = make('strong', 'hl-rv-value', value, a); make('span', '', label, a);
    if (String(value).length > 8) big.classList.add('hl-rv-value--long');
    if (opt.viz) {
      var viz = make('span', 'hl-rv-tile-viz' + (opt.viz.dots ? ' hl-rv-tile-viz--dots' : '') + (opt.viz.bar !== undefined ? ' hl-rv-tile-viz--bar' : ''), null, a); viz.setAttribute('aria-hidden', 'true');
      if (opt.viz.bar !== undefined) { var f = make('i', '', null, viz); f.style.width = Math.round(Math.max(0, Math.min(1, opt.viz.bar)) * 100) + '%'; }
      else (opt.viz.parts || []).forEach(function (p) { var s = make('i', p.cls || '', null, viz); s.style.flexGrow = p.n; if (p.hue) s.style.setProperty('--seg', p.hue); });
    }
    if (opt.sub) make('span', 'hl-rv-tile-sub', opt.sub, a);
    var m = { victims: victims, chain: attack, timeline: chronology }[tok];
    var cell = make('p', 'hl-rv-tile-note', null);
    make('span', 'hl-rv-tile-note__key', value + ' ' + label, cell);
    make('small', '', 'How counted: ' + how + (opt.from ? ' From ' + opt.from + '.' : m ? ' From ' + text(m.heading) + ', table ' + m.index + ', ' + m.rows.length + ' rows.' : ' From the detection guidance.'), cell);
    infoButton(cellBox, [cell], 'How counted: ' + value + ' ' + label);
    if (!opt.href && !opt.noLink && m) a.href = '#' + m.heading.id;
    make('span', 'hl-rv-tile-destination', '↗ ' + (opt.dest || NAMES[TOKENS.indexOf(tok)]), a);
  }
  var builders = {
    overview: function (body) {
      var tiles = make('div', 'hl-rv-tiles', null, body), count = 0;
      var destTab = TOKENS.indexOf('indicators') >= 0 ? 'indicators' : 'overview';
      var det = siteData.techniques && siteData.techniques.rows && siteData.techniques.rows.length ? siteData.techniques : null;
      var detPage = siteData.detection_page && safeHref(siteData.detection_page) ? siteData.detection_page : null;
      // A report with a victim grade table and an ATT&CK table (the pilot's data) keeps the tiles it always had, each from its own source: organisations with inside access, techniques, procedure rows,
      // rules and the observation window. Every other report gets the fallback set below, built from the data it has (a victim grade table still gives its organisations tile).
      var rich = !!(victims && attack);
      function segments(map, order) { return order.filter(function (k) { return map[k]; }).map(function (k) { return { n: map[k], hue: GRADE_HUES[k] || STATUS_HUES[k] || 'var(--acc)' }; }); }
      function tacticCounts() { var by = {}; attack.rows.forEach(function (r) { var k = tacticName(cell(r, attackC.tactic)) || 'Unlabelled'; by[k] = (by[k] || 0) + 1; }); return by; }
      function distinctIds() { var ids = new Set(); attack.rows.forEach(function (r) { (cell(r, attackC.id).match(/T\d{4}(?:\.\d{3})?/g) || []).forEach(function (id) { ids.add(id); }); }); return ids; }
      if (victims) {
        var g = col(victims, /Grade/i); var inside = victims.rows.filter(function (r) { return /^(ACCESS SHOWN|COMPROMISED)\b/.test(r[g]); });
        var ins = {}; inside.forEach(function (r) { var k = r[g].match(/^(ACCESS SHOWN|COMPROMISED)/)[1]; ins[k] = (ins[k] || 0) + 1; });
        tile(tiles, inside.length, 'organisations with inside or authenticated access', 'Organisation rows graded ACCESS SHOWN or COMPROMISED in the victim table; qualifiers stay in that tab.', 'victims', 'organisations',
          { kind: 'inside', viz: { dots: true, parts: inside.map(function (r) { return { n: 1, hue: GRADE_HUES[r[g].match(/^(ACCESS SHOWN|COMPROMISED)/)[1]] }; }) }, sub: ['ACCESS SHOWN', 'COMPROMISED'].filter(function (k) { return ins[k]; }).map(function (k) { return ins[k] + ' ' + k.toLowerCase(); }).join(', ') });
        count++;
      }
      if (rich) {
        var bt = tacticCounts(), nt = Object.keys(bt).length, tacticViz = { parts: Object.keys(bt).map(function (k) { return { n: bt[k] }; }) }, tsub = 'across ' + nt + ' tactic' + (nt === 1 ? '' : 's');
        if (attack.legacy) {
          tile(tiles, distinctIds().size, 'distinct technique IDs', 'Distinct IDs in the ATT&CK mapping table; the report states no Status for them.', 'chain', 'techniques', { kind: 'techniques', viz: tacticViz, sub: tsub });
          tile(tiles, attack.rows.length, 'mapping rows', 'Every row of the ATT&CK mapping table, including repeated technique IDs.', 'chain', 'mapping rows', { kind: 'procedures', viz: { parts: [{ n: 1 }] }, sub: 'no Status stated' });
        } else {
          var stat = {}; if (attackC.status >= 0) attack.rows.forEach(function (r) { stat[r[attackC.status]] = (stat[r[attackC.status]] || 0) + 1; });
          tile(tiles, distinctIds().size, 'distinct technique IDs', 'Distinct IDs in the full procedure table.', 'chain', 'techniques', { kind: 'techniques', viz: tacticViz, sub: tsub });
          tile(tiles, attack.rows.length, 'procedure rows', 'Every procedure row, including repeated technique IDs.', 'chain', 'procedure rows',
            { kind: 'procedures', viz: { parts: segments(stat, ['OBSERVED', 'INFERRED', 'NOT SHOWN']) }, sub: ['OBSERVED', 'INFERRED', 'NOT SHOWN'].filter(function (k) { return stat[k]; }).map(function (k) { return stat[k] + ' ' + k.toLowerCase(); }).join(', ') });
        }
        count += 2;
        if (ruleTotal !== null) { tile(tiles, ruleTotal, 'detection and hunting rules', 'Counts in the report detection guidance, reconciled to the engine and tier counts.', 'indicators', 'rules',
          { kind: 'rules', viz: { parts: engines.map(function (e) { return { n: e.total }; }).filter(function (p) { return p.n; }) }, sub: engines.filter(function (e) { return e.total; }).map(function (e) { return e.total + ' ' + e.engine; }).join(', ') }); count++; }
        if (chronology) {
          var dc = col(chronology, /^Date|^Time|^When/i), crow = chronologyRows(chronology), stamps = crow.map(function (r) { return r.when; }).filter(function (v) { return !isNaN(v); });
          var span = stamps.length === crow.length && stamps.length ? Math.round((Math.max.apply(null, crow.map(function (r) { return r.end; })) - Math.min.apply(null, stamps)) / 86400000) : null;
          tile(tiles, chronology.rows[0][dc] + ' to ' + chronology.rows[chronology.rows.length - 1][dc], 'observation window', 'First and last rows in the chronology; not an activity duration.', 'timeline', 'observation window',
            { kind: 'window', viz: { parts: [{ n: 1 }] }, sub: span !== null ? span + ' days between the first and last dated entry' : '' }); count++;
        }
      } else {
        // Fallback set, from the data this report has: threat level, overall risk score, distinct ATT&CK techniques, detection rules, IOC entries. A tile with no source is not drawn.
        if (threatLevel) { tile(tiles, threatLevel, 'threat level', 'The Threat Level line at the top of the report.', 'overview', 'threat level',
          { kind: 'threat', from: 'the report\'s Threat Level line', noLink: true, viz: { parts: [1, 2, 3, 4].map(function (n) { return { n: 1, cls: n <= (RISK_WORDS[threatLevel.toUpperCase()] || 0) ? 'on' : 'off' }; }) } }); count++; }
        var overall = overallRisk();
        if (overall) { var hid = overall.heading && overall.heading.id;
          tile(tiles, overall.value, 'overall risk score', 'The report\'s own overall score for the toolkit or campaign, read as printed; not computed here.', 'overview', 'risk score',
            { kind: 'risk', from: overall.from, href: hid ? '#' + hid : undefined, dest: 'Risk assessment', viz: { bar: parseFloat(overall.value) / (parseFloat(overall.value.split('/')[1]) || 10) }, sub: overall.rest }); count++; }
        if (attack) {
          var ids2 = new Set(); attack.rows.forEach(function (r) { (cell(r, attackC.id).match(/T\d{4}(?:\.\d{3})?/g) || []).forEach(function (id) { ids2.add(id); }); });
          var bt = {}; attack.rows.forEach(function (r) { var k = tacticName(cell(r, attackC.tactic)) || 'Unlabelled'; bt[k] = (bt[k] || 0) + 1; }); var nt = Object.keys(bt).length;
          tile(tiles, ids2.size, 'distinct ATT&CK techniques', 'Distinct IDs in the ATT&CK mapping table' + (attack.legacy ? '; the report states no Status for them.' : '.'), 'chain', 'techniques',
            { kind: 'techniques', viz: { parts: Object.keys(bt).map(function (k) { return { n: bt[k] }; }) }, sub: 'across ' + nt + ' tactic' + (nt === 1 ? '' : 's') }); count++;
        } else if (det) {
          var dt = {}; det.rows.forEach(function (r) { dt[r.tactic] = (dt[r.tactic] || 0) + 1; }); var ndt = Object.keys(dt).length;
          tile(tiles, det.rows.length, 'distinct ATT&CK techniques', 'Techniques the report\'s detection rules cover, one per technique ID; the report has no mapping table of its own.', 'overview', 'techniques',
            { kind: 'dtech', from: 'the detection page (_data/detection_attack.yml)', href: detPage || undefined, dest: 'Detection page', viz: { parts: Object.keys(dt).map(function (k) { return { n: dt[k] }; }) }, sub: 'across ' + ndt + ' tactic' + (ndt === 1 ? '' : 's') + ', from the detection page' }); count++;
        }
        if (ruleTotal !== null) { tile(tiles, ruleTotal, 'detection and hunting rules', 'Counts in the report detection guidance, reconciled to the engine and tier counts.', destTab, 'rules',
          { kind: 'rules', dest: destTab === 'indicators' ? undefined : 'Overview', viz: { parts: engines.map(function (e) { return { n: e.total }; }).filter(function (p) { return p.n; }) }, sub: engines.filter(function (e) { return e.total; }).map(function (e) { return e.total + ' ' + e.engine; }).join(', ') }); count++; }
        else if (siteData.rules && siteData.rules.total > 0) { var sr = siteData.rules;
          tile(tiles, sr.total, 'detection and hunting rules', 'Rules in the report\'s detection page: ' + [['sigma', 'Sigma'], ['yara', 'YARA'], ['suricata', 'Suricata']].filter(function (e) { return sr[e[0]]; }).map(function (e) { return sr[e[0]] + ' ' + e[1]; }).join(', ') + '; ' + sr.detection + ' detection tier, ' + sr.hunting + ' hunting tier.', 'overview', 'rules',
            { kind: 'drules', from: 'the detection page (_data/detection_manifests.yml)', href: detPage || undefined, dest: 'Detection page', viz: { parts: [{ n: sr.detection, hue: 'var(--acc)' }, { n: sr.hunting }].filter(function (p) { return p.n; }) }, sub: sr.detection + ' detection, ' + sr.hunting + ' hunting' }); count++; }
        var feed = siteData.iocs && siteData.iocs.total > 0 ? siteData.iocs : null;
        if (feed || feedMatch) { var n = feed ? feed.total : +feedMatch[1];
          tile(tiles, n, 'IOC entries', feed ? 'Entries in the report\'s IOC feed as the site lists them.' : 'Entries the report says its IOC feed carries.', destTab, 'IOC entries',
            { kind: 'iocs', from: feed ? 'the IOC feed table (_data/ioc_tables.yml)' : 'the report\'s indicator section', href: feed && safeHref(feed.feed_url) ? feed.feed_url : undefined, dest: feed ? 'IOC feed' : undefined }); count++; }
      }
      scanBand(body); riskPanel(body); judgmentsPanel(body);
      if (!count) missing(body, 'a victim grade, procedure, risk, detection, indicator or dated chronology source to count');
      var line = Array.from(tiles.querySelectorAll('.hl-rv-tile')).map(function (t) { return text(t.querySelector('strong')) + ' ' + t.dataset.rvShort; }).join(' · ');
      return line || 'Headline figures remain in the full report';
    },
    victims: function (body) {
      if (!victims) { missing(body, 'an Organisation / Grade table'); return 'Victim grades remain in the full report'; }
      var grade = col(victims, /Grade/i), counts = {};
      victims.rows.forEach(function (r) { var m = r[grade].match(/^(ACCESS SHOWN|COMPROMISED|REACHED|LISTED|CURRENT)/); if (m) counts[m[1]] = (counts[m[1]] || 0) + 1; });
      var denominator = victims.rows.length;
      if (tallyParagraph) { counts = {}; text(tallyParagraph).replace(/(\d+) (ACCESS SHOWN|COMPROMISED|REACHED|LISTED)/g, function (_, n, grade) { counts[grade] = +n; }); denominator = Object.keys(counts).reduce(function (n, g) { return n + counts[g]; }, 0); make('p', 'hl-rv-note', text(tallyParagraph), body); sourceLink(victims, body); }
      else make('p', 'hl-rv-note', 'Grades below count the organisation rows in this table. Wider target tallies and every qualifier remain in the report.', body);
      var bars = make('div', 'hl-rv-grade-bars', null, body);
      Object.keys(counts).forEach(function (g) { var row = make('div', 'hl-rv-grade-row', null, bars); make('span', '', g, row); var track = make('div', 'hl-rv-track', null, row); var fill = make('div', 'hl-rv-fill', null, track); fill.style.width = 100 * counts[g] / denominator + '%'; make('strong', '', counts[g], row); });
      var cards = make('div', 'hl-rv-victim-cards', null, body);
      victims.rows.forEach(function (r) { var card = make('article', 'hl-rv-victim-card', null, cards); make('h3', '', r[0], card); r.slice(1).forEach(function (value, i) { var line = make('p', '', null, card); make('strong', '', victims.headers[i + 1] + ': ', line); if (/Grade/i.test(victims.headers[i + 1])) badge(line, value); else make('span', '', value, line); }); sourceLink(victims, card, r[0]); });
      dashTable(tableFold(body, 'Read all ' + victims.rows.length + ' victim rows and qualifiers'), victims, 'Victim access and qualifiers', 'victims'); return victims.rows.length + ' organisation rows · ' + (tallyParagraph ? 'target tally ' + denominator + ': ' : '') + Object.keys(counts).map(function (g) { return counts[g] + ' ' + g; }).join(' · ');
    },
    chain: function (body) {
      // Design D, D4 (T-0500.1.7.3 c3): stage flow cards, the filter console (chip facets with counts) with a slim sticky bar under the tabs, the chain story with
      // inline procedure rows, and the B-style procedure table. Stage-to-procedure joins are exactly as before: curation, or a technique name found in the stage text. Never inferred from tactic.
      var stageCards = [], stageRows = [], stageDetails = [], flowButtons = [], stageTactics = [];
      var flowWrap = null, ribbon = null, linkRead = null;
      function stageLabel(cellValue, si) {
        var m = String(cellValue).match(/^(\d+)\.\s*(.+)$/);
        if (m) return { n: m[1], name: m[2] };
        if (/^\d+$/.test(String(cellValue).trim())) return { n: String(cellValue).trim(), name: 'Stage ' + String(cellValue).trim() };
        return { n: String(si + 1), name: String(cellValue) };
      }
      if (stages) {
        flowWrap = make('div', 'hl-rv-flowwrap', null, body);
        ribbon = make('ol', 'hl-rv-stage-ribbon hl-rv-flow', null, flowWrap); ribbon.setAttribute('role', 'group'); ribbon.setAttribute('aria-label', 'Filter procedures by stage');
      }
      var cons = null;
      var key = null;   // the report's own list of the techniques that carry the case, when it has one
      if (stages) {
        if (curation.stage_joins) make('p', 'hl-rv-note', 'Stage-to-procedure links: curated for this report.', body);
        var storyHead = make('div', 'hl-rv-story-head', null, body);
        icon(TAB_ICONS.chain, 17, storyHead, 'hl-rv-eyebrow-icon'); make('h3', 'hl-rv-pn-title', 'The chain story', storyHead);
        make('p', 'hl-rv-pn-sub', stages.rows.length + ' stages in the order the report gives them, each with the procedure rows the report links to it', storyHead);
        var wrap = make('div', 'hl-rv-chain-scroll', null, body); wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', 'Attack stages');
        var columns = make('div', 'hl-rv-stages', null, wrap);
        stages.rows.forEach(function (r, si) {
          var lab = stageLabel(r[0], si);
          var card = make('article', 'hl-rv-stage', null, columns); card.setAttribute('data-n', lab.n);
          stageCards.push(card); stageRows.push([]); stageTactics.push([]);
          var detail = make('details', 'hl-rv-stage-detail', null, card); detail.open = !phone.matches; stageDetails.push(detail);
          var heading = make('summary', '', r[0], detail); var nm = String(r[0]).match(/^(\d+\.\s*)(.+)$/); if (nm) { heading.textContent = ''; make('span', 'hl-rv-stage-no', nm[1], heading); heading.appendChild(document.createTextNode(nm[2])); }
          phone.addEventListener('change', function () { detail.open = !phone.matches; });
          card = detail;
          make('p', '', r[1], card);
          if (r[2]) { make('h4', '', stages.headers[2], card); make('p', '', r[2], card); } sourceLink(stages, card);
          // Only explicit shared procedure names join. Never infer a stage from tactic alone.
          if (attack) {
            // Optional editorial joins are supplied only by the current report.
            var joins = curation.stage_joins && curation.stage_joins[r[0]] || [];
            var matches = attack.rows.map(function (a, i) { return { row: a, index: i }; }).filter(function (a) {
              var id = (cell(a.row, attackC.id).match(/T\d{4}(?:\.\d{3})?/) || [])[0];
              var scope = cell(a.row, attackC.scope);
              if (joins.some(function (j) { return id === j.technique && scope.indexOf(j.scope_prefix) === 0; })) return true;
              var name = cell(a.row, attackC.name).toLowerCase(); return name.length >= 12 && (r[1] + ' ' + (r[2] || '')).toLowerCase().includes(name);
            });
            stageRows[si] = matches.map(function (a) { return a.index; });
            stageTactics[si] = matches.map(function (a) { return tacticName(cell(a.row, attackC.tactic)); }).filter(function (v, i, arr) { return v && arr.indexOf(v) === i; });
            var procedureList = matches.length ? tableFold(card, matches.length + ' linked procedure rows') : card;
            make('small', 'hl-rv-stage-count', matches.length + ' linked procedures', heading);
            var counts = ['OBSERVED', 'INFERRED', 'NOT SHOWN'].map(function (status) { return matches.filter(function (a) { return attackC.status >= 0 && a.row[attackC.status] === status; }).length; });
            function mini(parent) { var bar = make('span', 'hl-rv-mini', null, parent); bar.setAttribute('role', 'img'); bar.setAttribute('aria-label', counts.map(function (n, i) { return n + ' ' + ['observed', 'inferred', 'not shown'][i]; }).join(', ')); counts.forEach(function (n, i) { if (n) { var segment = make('span', 'hl-rv-' + ['observed','inferred','not-shown'][i], '', bar); segment.style.flexGrow = String(n); } }); }
            if (!attack.legacy) mini(heading);
            var li = make('li', 'hl-rv-fli', null, ribbon);
            var step = button('', li, function () {
              if (matches.length && cons) cons.toggle('Stage', r[0]);
              detail.open = true; stageCards[si].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }); step.className = 'hl-rv-fnode'; step.setAttribute('aria-pressed', 'false');
            step.setAttribute('aria-label', 'Stage ' + lab.n + ', ' + lab.name + ': ' + matches.length + ' linked procedures. ' + (matches.length ? 'Go to the stage and filter to it.' : 'Go to the stage; no procedure row is linked to it.'));
            var nb = make('span', 'hl-rv-fnb', null, step); make('span', 'hl-rv-fnum', lab.n, nb).setAttribute('aria-hidden', 'true'); make('strong', 'hl-rv-fnm', lab.name, nb);
            if (!attack.legacy) mini(step);
            make('small', 'hl-rv-fct', matches.length + ' linked', step);
            flowButtons.push(step);
            if (!matches.length) make('p', 'hl-rv-count', 'No explicit procedure join supplied; all rows remain in the table below.', card);
            matches.forEach(function (a) {
              var idText = cell(a.row, attackC.id), idM = idText.match(/T\d{4}(?:\.\d{3})?/);
              var chip = link('', '#hl-rv-procedures-' + (a.index + 1), procedureList); chip.className = 'hl-rv-procedure';
              make('span', 'hl-rv-tid', idM ? idM[0] : idText, chip);
              var pn = make('span', 'hl-rv-pname', null, chip);
              make('strong', '', cell(a.row, attackC.name >= 0 ? attackC.name : attackC.tactic), pn);
              var sub = [tacticName(cell(a.row, attackC.tactic)), attackC.scope >= 0 ? a.row[attackC.scope] : ''].filter(Boolean).join(' · ');
              if (sub) make('small', '', sub, pn);
              if (attackC.status >= 0) badge(chip, a.row[attackC.status]);
              if (attackC.conf >= 0) { var cb = badge(chip, a.row[attackC.conf]); pipsBefore(cb, a.row[attackC.conf]); }
            });
          } else { var li0 = make('li', 'hl-rv-fli', null, ribbon); var s0 = button('', li0, function () { stageCards[si].scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }); s0.className = 'hl-rv-fnode'; var nb0 = make('span', 'hl-rv-fnb', null, s0); make('span', 'hl-rv-fnum', lab.n, nb0).setAttribute('aria-hidden', 'true'); make('strong', 'hl-rv-fnm', lab.name, nb0); flowButtons.push(s0); }
        });
        linkRead = make('p', 'hl-rv-linkread', '', flowWrap); linkRead.setAttribute('role', 'status'); linkRead.setAttribute('aria-live', 'polite');
      } else missing(body, 'a Stage / What the operator did table');
      if (attack) {
        // Filters and the live count are visible above both stage cards and the procedure table. Only this generated copy is ever filtered.
        var full = make('section', 'hl-rv-procedures', null, body);
        var table = dashTable(full, attack, attack.legacy ? 'All ATT&CK mapping rows' : 'All ATT&CK procedure rows', 'procedures');
        var tacticCol = attackC.tactic;
        function tactic(value) { return tacticName(value); }
        var tactics = attack.rows.map(function (r) { return tactic(r[tacticCol]); }).filter(function (v, i, a) { return v && a.indexOf(v) === i; });
        var generatedRows = Array.from(table.tBodies[0].rows);
        // The report's own list of the techniques that carry the case (a smaller table of the same shape with Evidence), when it has one. Each list row marks the first full-table row
        // with the same technique ID and name that no earlier list row already marked; the evidence text is the list row's own.
        var keyModel = models.filter(function (m) { return m !== attack && m.token === 'chain' && m.rows.length < attack.rows.length && m.headers.some(function (h) { return /Tactic.*Technique/i.test(h); }) && m.headers.some(function (h) { return /^Status$/i.test(h); }) && m.headers.some(function (h) { return /^Evidence/i.test(h); }); })[0];
        var keyRows = {};
        if (keyModel && !attack.legacy) {
          var kt = col(keyModel, /Tactic.*Technique/i), kn = col(keyModel, /^Name$/i), ke = col(keyModel, /^Evidence/i), claimed = {}, matched = 0;
          keyModel.rows.forEach(function (kr) {
            var kid = (kr[kt].match(/T\d{4}(?:\.\d{3})?/) || [])[0]; if (!kid) return;
            for (var i = 0; i < attack.rows.length; i++) {
              var ar = attack.rows[i];
              if (claimed[i] || (cell(ar, attackC.id).match(/T\d{4}(?:\.\d{3})?/) || [])[0] !== kid || cell(ar, attackC.name).toLowerCase() !== kr[kn].toLowerCase()) continue;
              claimed[i] = true; keyRows[i] = kr[ke]; matched++; break;
            }
          });
          key = { model: keyModel, matched: matched, total: keyModel.rows.length };
          if (!matched) key = null;
        }
        // The table's own cells: the tactic as a button that lights its stages (only when stages with linked rows exist), the technique ID in monospace, a meter beside the confidence, the key mark and its evidence.
        var anyLinks = stageRows.some(function (a) { return a.length; });
        generatedRows.forEach(function (row, ri) {
          var tc = row.cells[tacticCol], tv = text(tc), idM = tv.match(/T\d{4}(?:\.\d{3})?/), tname = tactic(tv);
          if (tc && tname) {
            while (tc.firstChild) tc.removeChild(tc.firstChild);
            if (stages && anyLinks) { var tb = make('button', 'hl-rv-tac', tname, tc); tb.type = 'button'; tb.setAttribute('aria-pressed', 'false'); tb.dataset.rvTactic = tname; tb.title = 'Light the stages this tactic appears in'; }
            else make('span', '', tname, tc);
            if (idM) { tc.appendChild(document.createTextNode(' / ')); make('span', 'hl-rv-tid', idM[0], tc); }
            else if (tv.replace(tname, '').replace(/^[\s/·:|-]+/, '')) tc.appendChild(document.createTextNode(tv.replace(tname, '')));
          }
          if (attackC.conf >= 0) { var cb = row.cells[attackC.conf].querySelector('.hl-rv-badge'); if (cb) pipsBefore(cb, attack.rows[ri][attackC.conf]); }
          if (attackC.id !== attackC.tactic && row.cells[attackC.id]) row.cells[attackC.id].classList.add('hl-rv-tidcell');
          if (keyRows[ri] !== undefined) {
            row.classList.add('hl-rv-keyrow');
            var nc = row.cells[attackC.name >= 0 ? attackC.name : 0], mk = make('span', 'hl-rv-carry', 'Carries the case', nc);
            var ev = make('details', 'hl-rv-ev', null, nc); make('summary', '', 'Evidence', ev); make('p', '', keyRows[ri], ev);
          }
        });
        var specs = [
          { label: 'Status', col: attackC.status, values: ['OBSERVED', 'INFERRED', 'NOT SHOWN'] },
          { label: 'Confidence', col: attackC.conf, values: ['DEFINITE', 'HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT', 'Range', 'Unscaled'] },
          { label: 'Stage', values: stages ? stages.rows.map(function (r) { return r[0]; }) : [], match: function (row, value) { return stageRows[stages.rows.findIndex(function (r) { return r[0] === value; })].includes(generatedRows.indexOf(row)); } },
          { label: 'Tactic', col: tacticCol, values: tactics, match: function (row, value) { return tactic(text(row.cells[tacticCol])) === value; } }
        ];
        if (key) specs.push({ label: 'Shortlist', values: ['Carries the case'], match: function (row) { return row.classList.contains('hl-rv-keyrow'); } });
        // A legacy table has no Status, may have no Confidence, and may have no Stage table to filter by: a filter with nothing behind it is not drawn.
        if (attack.legacy) specs = specs.filter(function (sp) { return sp.label === 'Tactic' || sp.label === 'Stage' && stages || sp.label === 'Confidence' && attackC.conf >= 0; });
        var stageStates = stageCards.map(function (card) { var state = make('p', 'hl-rv-stage-state', '', card); state.setAttribute('role', 'status'); return state; });
        var pinnedTactic = null;
        function lightTactic(name) {
          var any = false;
          stageCards.forEach(function (card, si) { var hit = !!name && stageTactics[si].indexOf(name) >= 0; if (hit) any = true; card.classList.toggle('hl-rv-stage-lit', hit); card.classList.toggle('hl-rv-stage-dim', !!name && !hit); });
          flowButtons.forEach(function (b, si) { var hit = !!name && stageTactics[si] && stageTactics[si].indexOf(name) >= 0; b.classList.toggle('is-linked', hit); b.classList.toggle('is-dim', !!name && !hit); });
          if (ribbon) ribbon.classList.toggle('has-link', !!name);
          if (linkRead) linkRead.textContent = !name ? '' : any ? name + ' appears in stage' + (stageTactics.filter(function (t) { return t.indexOf(name) >= 0; }).length > 1 ? 's ' : ' ') + stageTactics.map(function (t, si) { return t.indexOf(name) >= 0 ? stageLabel(stages.rows[si][0], si).n : null; }).filter(Boolean).join(', ') + ' (by the linked procedure rows)' : name + ' appears in no stage: no linked procedure row has this tactic.';
        }
        function setPinned(name) {
          pinnedTactic = name;
          Array.from(body.querySelectorAll('button.hl-rv-tac')).forEach(function (b) { b.setAttribute('aria-pressed', String(!!name && b.dataset.rvTactic === name)); });
          lightTactic(name);
        }
        body.addEventListener('click', function (e) { var b = e.target.closest && e.target.closest('button.hl-rv-tac'); if (!b) return; setPinned(pinnedTactic === b.dataset.rvTactic ? null : b.dataset.rvTactic); });
        body.addEventListener('mouseover', function (e) { var b = e.target.closest && e.target.closest('button.hl-rv-tac, .hl-rv-fchip[data-rv-facet="Tactic"]'); if (b) lightTactic(b.dataset.rvTactic || b.dataset.rvValue); });
        body.addEventListener('mouseout', function (e) { var b = e.target.closest && e.target.closest('button.hl-rv-tac, .hl-rv-fchip[data-rv-facet="Tactic"]'); if (b) lightTactic(pinnedTactic); });
        body.addEventListener('focusin', function (e) { var b = e.target.closest && e.target.closest('button.hl-rv-tac, .hl-rv-fchip[data-rv-facet="Tactic"]'); if (b) lightTactic(b.dataset.rvTactic || b.dataset.rvValue); });
        body.addEventListener('focusout', function (e) { var b = e.target.closest && e.target.closest('button.hl-rv-tac, .hl-rv-fchip[data-rv-facet="Tactic"]'); if (b) lightTactic(pinnedTactic); });
        cons = chainConsole(body, table, specs, attack.legacy ? 'mapping rows' : 'procedure rows', function (visible, filtering, st) {
          var indices = visible.map(function (r) { return generatedRows.indexOf(r); });
          stageCards.forEach(function (card, si) {
            var hits = stageRows[si].filter(function (ri) { return indices.includes(ri); }).length;
            card.classList.toggle('hl-rv-stage-match', filtering && hits > 0);
            card.classList.toggle('hl-rv-stage-muted', filtering && !hits);
            var step = flowButtons[si]; if (step) { step.setAttribute('aria-pressed', String(!!stages && st.facet.Stage === stages.rows[si][0])); step.classList.toggle('is-match', filtering && hits > 0); step.classList.toggle('is-muted', filtering && !hits); }
            stageStates[si].textContent = !filtering ? '' : hits ? hits + ' linked rows match' : 'No linked rows match';
          });
        });
        var filterArea = cons.area;
        if (flowWrap) flowWrap.after(filterArea); else body.insertBefore(filterArea, body.firstChild);
        filterArea.after(cons.anchor);
        var note = make('p', 'hl-rv-pn-note', 'Stage filters use explicit procedure links only. Unjoined rows stay in the full table. Muted stages remain readable; the written report below is never filtered. Facet counts are over all ' + attack.rows.length + ' rows of table ' + attack.index + '.' +
          (key ? ' "Carries the case" marks the rows of the report\'s own list of the techniques that carry the case (' + text(key.model.heading) + ', table ' + key.model.index + '): each list row marks the first row of the full table with the same technique ID and name that no earlier list row marked (' + key.matched + ' of ' + key.total + ' list rows matched); its Evidence text is the list row\'s own. Where one technique ID has several rows this is the choice made, not a reading of which row the report meant.' : ''));
        infoButton(cons.head, [note], 'How the filters, counts and marks are read');
        var statusTiles = make('div', 'hl-rv-status-tiles', null);
        ['OBSERVED', 'INFERRED', 'NOT SHOWN'].filter(function () { return !attack.legacy; }).forEach(function (value) {
          var n = attack.rows.filter(function (r) { return r[attackC.status] === value; }).length;
          var tile = make('div', 'hl-rv-status-tile hl-rv-' + value.toLowerCase().replace(/ /g, '-'), null, statusTiles);
          make('strong', '', n, tile); badge(tile, value);
          var how = make('small', '', 'How counted: procedure rows with this status. ' + attack.rows.length + ' rows in table ' + attack.index + '.');
          infoButton(tile, [how], 'How counted: ' + value + ' procedure rows'); sourceLink(attack, tile, value + ' procedure rows');
        });
        if (attack.legacy) {
          // Say what the report's table does not hold; never fill a Status in.
          var absent = [attackC.status < 0 && 'Status (OBSERVED, INFERRED, NOT SHOWN)', attackC.conf < 0 && 'Confidence', attackC.scope < 0 && 'Scope'].filter(Boolean);
          // The view reads one table, the largest. Say how many ATT&CK mapping tables of this tab it leaves out, with their rows.
          var others = models.filter(function (m) { return m !== attack && legacyAttack(m); }), otherRows = others.reduce(function (n, m) { return n + m.rows.length; }, 0);
          var unstated = make('p', 'hl-rv-note hl-rv-unstated', 'Not stated in this report\'s ATT&CK table: ' + absent.join(', ') + '. The view lists the report\'s own rows by tactic as printed and does not grade them.' +
            (others.length ? ' This tab has ' + others.length + ' other ATT&CK mapping table' + (others.length > 1 ? 's' : '') + ' (' + otherRows + ' rows) that this view does not list; they are in the report.' : ''), null);
          cons.anchor.after(unstated);
        } else cons.anchor.after(statusTiles);
        // The story and the table sit under the console; the table's own heading is a B eyebrow.
        var thead = make('div', 'hl-rv-story-head hl-rv-table-head', null); full.insertBefore(thead, full.firstChild);
        icon(TAB_ICONS.chain, 17, thead, 'hl-rv-eyebrow-icon'); make('h3', 'hl-rv-pn-title', (attack.legacy ? 'All ' + attack.rows.length + ' ATT&CK mapping rows' : 'All ' + attack.rows.length + ' procedure rows'), thead);
        make('p', 'hl-rv-pn-sub', 'the full table; the tactic buttons light the stages they appear in', thead);
        cons.watch(full);
      } else missing(body, 'a Tactic / Technique, Status and Confidence procedure table');
      if (attack && attack.legacy) return (stages ? stages.rows.length + ' stages, ' : '') + attack.rows.length + ' ATT&CK mapping rows, status not stated';
      var status = attack ? attack.rows.reduce(function (out, r) { var s = r[attackC.status]; out[s] = (out[s] || 0) + 1; return out; }, {}) : {};
      return (stages ? stages.rows.length : 0) + ' stages, ' + (attack ? attack.rows.length : 0) + ' procedures' + (attack ? ': ' + Object.keys(status).map(function (s) { return status[s] + ' ' + s.toLowerCase(); }).join(', ') : '');
    },
    timeline: function (body) {
      if (!chronology) { missing(body, 'a Date / Observation chronology table'); return 'Chronology remains in the full report'; }
      if (!drawTimeline(body, chronology)) return 'Chronology as printed; date positions unavailable'; return chronology.rows.length + ' dated events · ' + chronology.rows[0][col(chronology, /^Date|^Time|^When/i)] + ' to ' + chronology.rows[chronology.rows.length - 1][col(chronology, /^Date|^Time|^When/i)] + ' · date precision preserved';
    },
    attribution: function (body) {
      var diamond = make('div', 'hl-rv-diamond', null, body); make('span', 'hl-rv-diamond-label', 'Diamond Model', diamond);
      [['Adversary', 'attribution', /Threat Actor|Actor Assessment|Attribution/i], ['Capability', 'chain', /classification/i], ['Infrastructure', 'timeline', /infrastructure/i], ['Victim', 'victims', /Who.*Hit|victim|access|impact/i]].forEach(function (v) {
        var block = sections.find(function (s) { return s.token === v[1] && s.heading && v[2].test(text(s.heading)); });
        var p = block && block.node.querySelector('p');
        var card = make('article', 'hl-rv-diamond-card', null, diamond); make('h3', '', v[0], card);
        if (p) { make('blockquote', '', (text(p).match(/^.*?[.!?](?:\s|$)/) || [text(p)])[0].trim(), card); link('Read in the report', '#' + block.heading.id, card).setAttribute('aria-label', 'Read in the report: ' + v[0] + ': ' + text(block.heading)); }
        else make('p', '', 'No structured ' + v[0].toLowerCase() + ' statement found. Read the full sections below.', card);
      });
      if (hypotheses) dashTable(tableFold(body, 'Read all ' + hypotheses.rows.length + ' competing hypotheses'), hypotheses, 'Competing hypotheses', 'hypotheses'); else missing(body, 'a Hypothesis / Where it stands table');
      if (calls) { var secondary = dashTable(tableFold(body, 'What would change each attribution call'), calls, 'Attribution calls and what would change them', 'calls'); secondary.closest('details').open = false; }
      return 'Four Diamond Model vertices' + (hypotheses ? ', ' + hypotheses.rows.length + ' hypotheses' : '');
    },
    indicators: function (body) {
      if (!indicators) { missing(body, 'an Indicator / Action table'); return 'Indicators remain in the full report'; }
      make('p', 'hl-rv-feed-count', 'Printed here: ' + indicators.rows.length + (feedMatch ? ' · in the feed: ' + feedMatch[1] : ' indicator rows'), body);
      var actions = make('div', 'hl-rv-indicator-actions', null, body);
      var feed = Array.from(document.querySelectorAll('a[href]')).find(function (a) { return /\/ioc-feeds\//.test(a.getAttribute('href')); });
      if (feed) link('Open the IOC feed' + (feedMatch ? ' (' + feedMatch[1] + ' entries)' : ''), feed.getAttribute('href'), actions);
      var allCopy = button('Copy these ' + indicators.rows.length + ' (as printed)', actions, function () { copyValue(indicators.rows.map(function (r) { return r[0]; }).join('\n'), allCopy, live); });
      var types = make('div', 'hl-rv-type-filters', null, body); types.setAttribute('role', 'group'); types.setAttribute('aria-label', 'Filter printed indicator types');
      function type(v) { return /^[a-f0-9]{32,128}$/i.test(v) ? 'Hash' : /^(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}(?::\d+)?$/.test(v) ? 'IP' : /[\\/]/.test(v) ? 'Path' : 'Other'; }
      var selectedType = '';
      ['', 'IP', 'Hash', 'Path', 'Other'].filter(function (t) { return !t || indicators.rows.some(function (r) { return type(r[0]) === t; }); }).forEach(function (t) {
        var b = button(t || 'All types', types, function () { selectedType = t; chips.querySelectorAll('li').forEach(function (li, i) { li.hidden = !!t && type(indicators.rows[i][0]) !== t; }); body.querySelectorAll('#indicators tbody tr').forEach(function (row, i) { row.hidden = !!t && type(indicators.rows[i][0]) !== t; }); Array.from(types.children).forEach(function (c) { c.setAttribute('aria-pressed', String(c === b)); }); }); b.setAttribute('aria-pressed', String(!t));
      });
      var chips = make('ul', 'hl-rv-chips', null, body), status = make('p', 'hl-rv-copy-status', '', body); status.setAttribute('role', 'status');
      indicators.rows.forEach(function (r) { var li = make('li', 'hl-rv-chip-item', null, chips); var code = make('code', '', r[0], li); var b = button('Copy', li, function () { copyValue(code.textContent, b, live); }); });
      dashTable(tableFold(body, 'Indicator context, confidence and action'), indicators, 'Highlighted indicators, confidence and action', 'indicators');
      // The report's own detection paragraphs carry count, tier and caveat together.
      var detection = sections.find(function (s) { return s.token === 'indicators' && s.heading && /Detection|Hunting/i.test(text(s.heading)); });
      if (ruleTotal !== null) { var counts = make('ul', 'hl-rv-rulecounts', null, body); engines.forEach(function (e) { var li = make('li', '', null, counts); var a = Array.from(document.querySelectorAll('#hl-detect-panel a[href]')).find(function (a) { return new RegExp(e.engine === 'Suricata' ? 'Suricata' : e.engine, 'i').test(text(a)); }); if (a) link(e.engine + ': ' + e.total + ' rules', a.getAttribute('href'), li); else make('span', '', e.engine + ': ' + e.total + ' rules', li); make('span', '', ', ' + e.detection + ' detection, ' + e.hunting + ' hunting', li); }); }
      sections.filter(function (s) { return s.token === 'indicators'; }).forEach(function (s) { s.node.querySelectorAll('h2[id],h3[id],h4[id]').forEach(function (h) { if (/Where to look first|Response orientation/i.test(text(h))) link(text(h), '#' + h.id, body).className = 'hl-rv-start-here'; }); });
      if (detection) { var p = detection.node.querySelector('p'); if (p) { make('p', 'hl-rv-note', text(p), body); link('Read detection guidance', '#' + detection.heading.id, body); } }
      return indicators.rows.length + (feedMatch ? ' of ' + feedMatch[1] + ' feed indicators' : ' highlighted indicator rows') + (ruleTotal !== null ? ', ' + ruleTotal + ' rules' : '') + ', copied as printed';
    },
    confidence: function (body) {
      if (!judgments) { missing(body, 'a Claim / Confidence / What would change it table'); return 'Confidence and gaps remain in the full report'; }
      var all = tableFold(body, 'Filter all ' + judgments.rows.length + ' judgments');
      var table = dashTable(all, judgments, 'Judgments and what would change them', 'judgments');
      var distribution = make('div', 'hl-rv-distribution', null, body);
      // One thin stacked bar over the legend: a segment per confidence word, as wide as its share. The legend buttons stay the filter.
      var distbar = make('div', 'hl-rv-distbar', null, body); distbar.setAttribute('aria-hidden', 'true');
      all.before(distbar, distribution); distribution.setAttribute('role', 'group'); distribution.setAttribute('aria-label', 'Judgments by confidence as printed');
      var counts = {}; judgments.rows.forEach(function (r) { var v = r[col(judgments, /Confidence/i)]; counts[v] = (counts[v] || 0) + 1; });
      Object.keys(counts).forEach(function (v) { var b = button(v + ' · ' + counts[v], distribution, function () { var input = all.querySelector('select'); input.value = v; input.dispatchEvent(new Event('input')); Array.from(distribution.children).forEach(function (c) { c.setAttribute('aria-pressed', String(c === b)); }); }); var seg = make('span', '', null, distbar); seg.style.flexGrow = counts[v]; seg.style.flexBasis = '0'; seg.title = v + ': ' + counts[v]; b.setAttribute('aria-pressed', 'false'); b.title = v + ': ' + counts[v] + ' of ' + judgments.rows.length + ' judgments'; });
      if (!judgments.headers.some(function (h) { return /change/i.test(h); })) make('p', 'hl-rv-note hl-rv-unstated', 'Not stated in this report\'s table: what would change each judgment. The view lists the rows as printed.', all);
      filters(all, table, [{ label: 'Confidence', col: col(judgments, /Confidence/i), values: Object.keys(counts), match: function (row, value) { return text(row.cells[col(judgments, /Confidence/i)]) === value; } }], 'judgments');
      return judgments.rows.length + ' judgments, including ranges and unscaled wording';
    }
  };
  TOKENS.forEach(function (t, i) {
    var panel = panels[i], head = panel.querySelector('.hl-rv-panel-head');
    var view = make('section', 'hl-rv-view' + (t === 'overview' ? ' hl-rv-view--scan' : ''), null); head.after(view);
    var firstSource = sections.find(function (s) { return s.token === t && s.heading; });
    if (firstSource) { var skip = link('Skip this view', '#' + firstSource.heading.id, panel); skip.className = 'hl-rv-skip-view'; view.before(skip); }
    var summary = make('div', 'hl-rv-view-summary', null, view), line = make('p', '', '', summary);
    icon(TAB_ICONS[t], 17, summary, 'hl-rv-eyebrow-icon');
    var toggle = button('Show the view', summary); toggle.id = 'hl-rv-toggle-' + t;
    var body = make('div', 'hl-rv-view-body', null, view); body.id = 'hl-rv-view-' + t;
    toggle.setAttribute('aria-controls', body.id);
    line.textContent = builders[t](body);
    sourceFooter(body, { overview: [victims, attack, judgments, chronology], victims: [victims], chain: [stages, attack], timeline: [chronology], attribution: [hypotheses, calls], indicators: [indicators], confidence: [judgments] }[t]);
    if ((t === 'overview' || t === 'indicators') && detectionSection) link('Counts from: ' + text(detectionSection.heading) + ', first paragraph', '#' + detectionSection.heading.id, body.querySelector('.hl-rv-source-footer'));
    // Design D: the "how counted" and "from" notes of this view sit behind its "i" in the bar; "Not stated" lines and the curated note stay visible.
    var viewNotes = Array.from(body.querySelectorAll('.hl-rv-note:not(.hl-rv-unstated), .hl-rv-source-footer'));
    if (viewNotes.length) infoButton(summary, viewNotes, 'How this view is counted and where it is read from');
    if (t === 'overview') {
      var overviewLead = body.querySelector('.hl-rv-lead');
      function placeLead() { if (overviewLead) { if (phone.matches) view.before(overviewLead); else body.insertBefore(overviewLead, body.firstChild); } }
      placeLead(); phone.addEventListener('change', placeLead);
    }
    if (t === 'chain' && curation.stage_joins || t === 'timeline' && curation.timeline_lanes) make('p', 'hl-rv-curated', 'View selections curated for this report.', view);
    body.hidden = phone.matches; toggle.textContent = body.hidden ? 'Show the view' : 'Hide the view'; toggle.setAttribute('aria-expanded', String(!body.hidden));
    function sync(open) { body.hidden = !open; toggle.textContent = open ? 'Hide the view' : 'Show the view'; toggle.setAttribute('aria-expanded', String(open)); }
    toggle.addEventListener('click', function () { sync(body.hidden); });
    phone.addEventListener('change', function () { sync(!phone.matches); });
    var first = sections.find(function (s) { return s.token === t && s.heading; });
    if (first) link('Jump to the full sections ↓', '#' + first.heading.id, body).className = 'hl-rv-jump';
    var hs = sections.filter(function (s) { return s.token === t && s.heading; });
    if (hs.length) {
      var toc = make('details', 'hl-rv-contents', null); view.after(toc); toc.open = !phone.matches;
      make('summary', '', 'In this tab', toc); var nav = make('nav', '', null, toc); nav.setAttribute('aria-label', 'In this tab');
      hs.forEach(function (s) { link(text(s.heading), '#' + s.heading.id, nav); });
      phone.addEventListener('change', function () { toc.open = !phone.matches; });
    }
    sponsorCard(panel);
    // The Previous/Next footer exists only when the report has another tab to go to; with one tab it would be an empty labelled landmark.
    var footer = TOKENS.length > 1 ? make('nav', 'hl-rv-nextprev', null, panel) : null; if (footer) footer.setAttribute('aria-label', 'Read report in order');
    function card(j, direction) { var a = link('', '#tab-' + TOKENS[j], footer); a.dataset.rvHue = TOKENS[j]; make('small', '', direction, a); make('strong', '', NAMES[j], a); make('span', '', QUESTIONS[j], a); make('small', '', times[j] + ' min read', a); }
    if (footer) {
      card((i + TOKENS.length - 1) % TOKENS.length, 'Previous');
      card(i < TOKENS.length - 1 ? i + 1 : 0, i < TOKENS.length - 1 ? 'Next' : 'Back to');
    }
    var teardownControls = make('div', 'hl-rv-teardown-controls', null, panel); if (footer) footer.before(teardownControls);
    function teardowns() { return sections.filter(function (s) { return s.token === t; }).flatMap(function (s) { return Array.from(s.node.querySelectorAll('details.hl-teardown')); }); }
    if (teardowns().length) {
      button('Expand all teardowns', teardownControls, function () { teardowns().forEach(function (d) { d.open = true; }); });
      button('Collapse all teardowns', teardownControls, function () { teardowns().forEach(function (d) { d.open = false; }); });
      view.after(teardownControls);
    }
  });
  // Keep all source tables, including those inside closed teardowns, scrollable.
  sections.forEach(function (s) {
    s.node.querySelectorAll('table').forEach(function (table, i) {
      var wrap = document.createElement('div'); wrap.className = 'hl-rv-source-table'; wrap.tabIndex = 0;
      wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', (s.heading ? text(s.heading) : 'Report') + ', table ' + (i + 1));
      table.before(wrap); wrap.appendChild(table);
      var tools = tableCopy(table, s.node, Array.from(table.rows[0].cells).findIndex(function (c) { return /^Indicator/i.test(text(c)); })); wrap.before(tools);
      Array.from(table.rows).forEach(function (row) { Array.from(row.cells).forEach(function (cell, ci) {
        var value = text(cell), h = text(table.rows[0].cells[ci]);
        if (/Conf/i.test(h)) cell.classList.add('hl-rv-confidence-cell');
        if (/^(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}(?::\d+)?$/.test(value)) cell.classList.add('hl-rv-indicator-cell');
        if (/^(DEFINITE|HIGH|MODERATE|LOW|INSUFFICIENT|ACCESS SHOWN|COMPROMISED|REACHED|LISTED|OBSERVED|INFERRED|NOT SHOWN)$/.test(value)) cell.classList.add('hl-rv-cell-pill', 'hl-rv-' + value.toLowerCase().replace(/ /g, '-'));
      }); });
    });
    s.node.querySelectorAll('details.hl-teardown').forEach(function (d) {
      var summary = d.querySelector('summary'), tables = d.querySelectorAll('table'), rows = Array.from(tables).reduce(function (n, t) { return n + Array.from(t.rows).filter(function (r) { return r.querySelector('td'); }).length; }, 0);
      if (summary) make('span', 'hl-rv-teardown-count', 'Teardown · ' + tables.length + ' tables · ' + rows + ' rows', summary);
    });
    s.node.querySelectorAll('h2[id],h3[id]').forEach(function (h) { link('§', '#' + h.id, h).className = 'hl-rv-permalink'; });
    s.node.querySelectorAll('figure img').forEach(function (img) {
      // Keep the original image untouched. A separate full-screen control has no
      // effect on image/link counts once chrome is removed by the text gate.
      var b = button('Open figure full screen', img.parentElement, function () {
        var dialog = make('dialog', 'hl-rv-figure-dialog', null, document.body);
        var close = button('Close figure', dialog, function () { dialog.close(); });
        var full = make('img', '', null, dialog); full.src = img.currentSrc || img.src; full.alt = img.alt;
        dialog.addEventListener('close', function () { dialog.remove(); b.focus(); }); dialog.showModal(); close.focus();
      }); b.className = 'hl-rv-figure-open';
      img.addEventListener('click', function () { b.click(); });
    });
  });
  // The summary's own words, wrapped where a panel key names them; after every other pass has touched the source text.
  wrapHits(); wireLinks();
  function copy(src, status, success, control) {
    if (control) { copyValue(src.textContent, control, status); return; }
    function fallback() { var range = document.createRange(); range.selectNodeContents(src); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); status.textContent = 'Clipboard unavailable. Text selected; use the copy command.'; }
    if (navigator.clipboard) navigator.clipboard.writeText(src.textContent).then(function () { status.textContent = success; }, fallback); else fallback();
  }
  // Citation and code copy controls used to live in the old TOC script.
  var copyStatus = make('p', 'hl-rv-copy-status', '', content); copyStatus.setAttribute('role', 'status');
  content.querySelectorAll('[data-cite-copy]').forEach(function (b) { b.addEventListener('click', function () { var src = document.getElementById(b.dataset.citeCopy); if (src) copy(src, copyStatus, 'Citation copied.', b); }); });
  // Opt-in (T-0500.1.12): only a block the author marked {: .hl-copy} (defender content) gets a button. kramdown puts the class on the
  // outer div.highlighter-rouge, so it is read on the pre, its code, or the two wrappers above it. Attacker blocks are defanged and get none.
  function hlCopyMarked(pre) { var p = pre.parentElement, g = p && p.parentElement; return pre.classList.contains('hl-copy') || !!pre.querySelector(':scope > code.hl-copy') || !!(p && p.classList.contains('hl-copy')) || !!(g && g.classList.contains('hl-copy')); }
  content.querySelectorAll('.hl-rv-source pre').forEach(function (pre) { if (!hlCopyMarked(pre)) return; var b = button('Copy code', pre, function () { copy(pre.querySelector('code') || pre, copyStatus, 'Code copied.', b); }); });
  // Older figure-nav adds its own chips before this deferred script. They are
  // navigation chrome, not words of the report.
  content.querySelectorAll('.hl-fignav').forEach(function (n) { n.setAttribute('data-rv-chrome', ''); n.setAttribute('data-pagefind-ignore', ''); });
  var metadata = sections.flatMap(function (s) { return Array.from(s.node.children); }).filter(function (n) { return n.tagName === 'P' && /^(Campaign Identifier|Last Updated|Threat Level):/.test(text(n)); });
  metadata.forEach(function (p) { p.classList.add('hl-rv-metadata'); });
  var level = metadata.map(text).join(' ').match(/(?:^|\s)Threat Level:\s*(CRITICAL|HIGH|MEDIUM|MODERATE|LOW)\b/i);
  if (level) { var masthead = document.querySelector('.hl-post-header__eyebrow'); if (masthead) make('span', 'hl-rv-threat', 'Threat Level: ' + level[1], masthead); }
  var printStyle = make('style', '', null, document.body);
  var printTitle = text(document.querySelector('.hl-post-header__title'));
  var canonical = document.querySelector('link[rel=canonical]');
  var printUrl = canonical ? canonical.href : location.origin + location.pathname;
  var printDate = text(document.querySelector('.hl-post-header__date'));
  printStyle.textContent = '@page hl-report { @top-left { content: ' + JSON.stringify(printTitle) + '; width: 60%; font: 7pt sans-serif; } @top-right { content: ' + JSON.stringify(printUrl) + '; width: 38%; font: 6pt sans-serif; overflow-wrap: anywhere; } @bottom-left { content: ' + JSON.stringify(printDate) + '; } }';
  // Keep resources in the header: the old fixed dock overlaps the wider report.
  var resources = document.querySelector('.hl-report-page .hl-quicklinks');
  var reportHeader = document.querySelector('.hl-report-page .hl-post-header');
  // Design D, the plate (T-0500.1.7.3). Order: meta line, title, bottom line; the action buttons are a column to the right
  // (Read the full report, then the page's own Detections, IOC feed, STIX and MISP, then Share); the report sponsor is the foot.
  var plateFoot = reportHeader && reportHeader.querySelector('.hl-rvsp--report');
  function intoPlate(node) { if (plateFoot) reportHeader.insertBefore(node, plateFoot); else reportHeader.appendChild(node); }
  // The bottom line is a copy of the report's lead, marked as chrome: the first paragraph of a BLUF section when the Overview has one,
  // else the first paragraph of the first headed Overview section (what the Overview view used to print as its lead). The source stays where it is.
  var leadSection = sections.find(function (s) { return s.token === 'overview' && s.heading && /\bBLUF\b|bottom line/i.test(text(s.heading)) && s.node.querySelector('p'); })
    || sections.find(function (s) { return s.token === 'overview' && s.heading; });
  var leadPara = leadSection && leadSection.node.querySelector('p');
  var bluf = null;
  if (reportHeader && leadPara && text(leadPara)) {
    // A long lead is shown as its first sentences, cut at a sentence end, up to 60 words (always at least the first sentence); the whole paragraph is the first paragraph of the Overview below.
    var leadText = text(leadPara), sentences = leadText.split(/(?<=[.!?])\s+(?=[A-Z0-9"\u201c'])/), shown = sentences[0], k = 1;
    while (k < sentences.length && (shown + ' ' + sentences[k]).split(/\s+/).length <= 60) { shown += ' ' + sentences[k]; k++; }
    bluf = make('p', 'hl-rv-bluf', shown);
    var nWords = shown.split(/\s+/).length;
    bluf.classList.add(nWords > 90 ? 'hl-rv-bluf--xlong' : nWords > 48 ? 'hl-rv-bluf--long' : 'hl-rv-bluf--short');
    var plateTitle = reportHeader.querySelector('.hl-post-header__title');
    if (plateTitle) plateTitle.after(bluf); else intoPlate(bluf);
  }
  var actions = resources || (reportHeader && make('div', 'hl-quicklinks'));
  if (actions && reportHeader) {
    actions.classList.add('hl-rv-actions'); actions.setAttribute('role', 'group'); actions.setAttribute('aria-label', 'Report resources');
    intoPlate(actions);
    var readBtn = make('a', 'hl-quicklink hl-cta hl-rv-read', null); readBtn.href = '#one-page';
    readBtn.innerHTML = '<span class="hl-quicklink__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M6 3H3v10h10v-3M9 3h4v4M13 3L7 9"/></svg></span><span class="hl-quicklink__label">Read the full report</span>';
    actions.prepend(readBtn);
  }
  // The site's own button recipe (custom.scss .hl-cta), one colour per kind: Detections green, IOC feed red, STIX cyan.
  var kindColours = [[/detect/i, '#4ade80'], [/ioc/i, '#f87171'], [/stix/i, '#22d3ee']];
  if (resources) resources.querySelectorAll('.hl-quicklink').forEach(function (a) {
    if (a.classList.contains('hl-rv-read')) return;
    var label = text(a.querySelector('.hl-quicklink__label')) + ' ' + (a.id || ''), kind = kindColours.find(function (k) { return k[0].test(label); });
    a.classList.add('hl-cta'); a.style.setProperty('--acc', kind ? kind[1] : '#58a6ff');
  });
  // Keep the site's resource popovers functional without constructing a TOC.
  var resourcePairs = [['hl-detect-tab', 'hl-detect-panel'], ['hl-ioc-tab', 'hl-ioc-panel'], ['hl-stix-tab', 'hl-stix-panel']];
  function closeResources(except) { resourcePairs.forEach(function (pair) { var b = document.getElementById(pair[0]), p = document.getElementById(pair[1]); if (p && p !== except) { p.classList.remove(pair[1] + '--open'); if (b) b.setAttribute('aria-expanded', 'false'); } }); }
  resourcePairs.forEach(function (pair) {
    var b = document.getElementById(pair[0]), p = document.getElementById(pair[1]); if (!b || !p) return;
    document.body.appendChild(p); p.classList.add('hl-rv-resource');
    b.addEventListener('click', function () { var open = b.getAttribute('aria-expanded') !== 'true'; closeResources(p); b.setAttribute('aria-expanded', String(open)); p.classList.toggle(pair[1] + '--open', open); });
    p.querySelectorAll('.hl-ioc-cpbtn').forEach(function (c) { c.addEventListener('click', function () { var src = c.parentElement.querySelector('.hl-ioc-panel__val'); if (src) copy(src, copyStatus, 'Indicator copied as printed.', c); }); });
  });
  document.addEventListener('click', function (e) { if (!e.target.closest('.hl-quicklinks,.hl-rv-resource')) closeResources(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeResources(); });
  content.addEventListener('pointerover', positionGlossary);
  content.addEventListener('focusin', positionGlossary);
  function positionGlossary(e) {
    var mark = e.target.closest && e.target.closest('.hl-gloss'); if (!mark) return;
    var r = mark.getBoundingClientRect(), w = Math.min(320, innerWidth - 32);
    var h = parseFloat(getComputedStyle(mark, '::after').height) || 160;
    mark.style.setProperty('--hl-rv-tip-x', Math.max(16, Math.min(r.left, innerWidth - w - 16)) + 'px');
    mark.style.setProperty('--hl-rv-tip-y', Math.max(8, Math.min(r.bottom + 8, innerHeight - h - 16)) + 'px');
  }
  var back = button('Back to top of tab', document.body, scrollTopTab); back.className = 'hl-rv-back'; back.hidden = true;
  function backState() { back.hidden = window.scrollY < window.innerHeight || onepage; root.classList.toggle('hl-rv-reading', phone.matches && bar.getBoundingClientRect().top <= 1); }
  window.addEventListener('scroll', backState, { passive: true });
  window.addEventListener('resize', function () { measureBar(); backState(); });
  var beforePrint = null;
  window.addEventListener('beforeprint', function () {
    beforePrint = { one: onepage, details: Array.from(content.querySelectorAll('details')).map(function (d) { return [d, d.open]; }) };
    mode(true); content.querySelectorAll('details').forEach(function (d) { d.open = true; });
  });
  window.addEventListener('afterprint', function () { if (!beforePrint) return; beforePrint.details.forEach(function (p) { p[0].open = p[1]; }); mode(beforePrint.one); beforePrint = null; });
  // A single sticky reading line follows the current tab or one-page source.
  function visibleSections() { return sections.filter(function (s) { return s.heading && (onepage || s.token === TOKENS[active]); }); }
  function stepSection(delta) {
    var list = visibleSections(), index = list.indexOf(currentSection);
    var s = list[Math.max(0, Math.min(list.length - 1, index + delta))];
    if (s) { go('#' + s.heading.id, true); history.pushState(null, '', '#' + s.heading.id); }
  }
  function updateProgress() {
    var list = visibleSections(); if (!list.length) return;
    var top = mobileLine.getBoundingClientRect().bottom + 20;
    var current = list[0]; list.forEach(function (s) { if (s.heading.getBoundingClientRect().top <= top) current = s; });
    if (currentSection !== current) {
      currentSection = current; sectionLabel.textContent = text(current.heading).replace(/§$/, '').trim(); sectionLabel.title = sectionLabel.textContent;
      document.querySelectorAll('.hl-rv-contents a,.hl-rv-page-contents a,.hl-rv-menu-sections a').forEach(function (a) { if (a.hash === '#' + current.heading.id) a.setAttribute('aria-current', 'location'); else a.removeAttribute('aria-current'); });
      if (Date.now() > navigatingUntil && scrollY > bar.offsetTop && !beforePrint) history.replaceState(null, '', '#' + current.heading.id);
    }
    prevSection.disabled = current === list[0]; nextSection.disabled = current === list[list.length - 1];
    var first = list[0].node.getBoundingClientRect().top + scrollY;
    var last = list[list.length - 1].node.getBoundingClientRect().bottom + scrollY;
    var fraction = Math.max(0, Math.min(1, (scrollY + top - first) / Math.max(1, last - first - innerHeight + top)));
    progressBar.style.width = fraction * 100 + '%';
    var total = onepage ? Math.max(1, Math.round(words / 200)) : times[active];
    var left = Math.max(0, Math.ceil(total * (1 - fraction)));
    var description = 'about ' + left + ' min left in this ' + (onepage ? 'report' : 'tab');
    // A span cannot carry aria-label: the visible short form is hidden from assistive technology and the full phrase is hidden text.
    remaining.replaceChildren(); make('span', '', phone.matches ? '~' + left + 'm left' : description, remaining).setAttribute('aria-hidden', 'true'); make('span', 'hl-rv-live', description, remaining); remaining.title = description;
  }
  var progressPending = false;
  function scheduleProgress() { if (!progressPending) { progressPending = true; requestAnimationFrame(function () { progressPending = false; updateProgress(); }); } }
  window.addEventListener('scroll', scheduleProgress, { passive: true });
  window.addEventListener('resize', scheduleProgress, { passive: true });
  new ResizeObserver(scheduleProgress).observe(content);
  if (typeof IntersectionObserver !== 'undefined') {
    var spy = new IntersectionObserver(scheduleProgress, { rootMargin: '-100px 0px -60% 0px' });
    sections.forEach(function (s) { if (s.heading) spy.observe(s.heading); });
  }
  // Share: a 44px icon button in the top-right corner of the header box (Joseph, 2026-10-30). It calls the browser's own share
  // sheet where there is one and otherwise copies the page address, saying "Link copied" in an aria-live region. No request is
  // made and nothing is tracked. It is built here, so with scripts off it is simply absent.
  if (reportHeader && actions) {
    var share = make('div', 'hl-rv-share', null, actions); share.setAttribute('data-rv-chrome', '');
    var shareStatus = make('span', 'hl-rv-share-status', '', share); shareStatus.setAttribute('role', 'status'); shareStatus.setAttribute('aria-live', 'polite');
    var shareButton = button('', share, function () {
      if (navigator.share) { navigator.share({ title: (((document.querySelector('.hl-post-header__title') || {}).textContent || '').trim() || document.title), url: location.href }).catch(function () {}); return; }
      var address = make('span', 'hl-rv-share-url', location.href, reportHeader);
      if (navigator.clipboard) navigator.clipboard.writeText(location.href).then(function () { address.remove(); announceShare('Link copied'); }, function () { copy(address, shareStatus, 'Link copied.'); });
      else copy(address, shareStatus, 'Link copied.');
    });
    shareButton.className = 'hl-quicklink hl-cta hl-rv-share-btn'; shareButton.setAttribute('aria-label', 'Share this report'); shareButton.title = 'Share this report';
    shareButton.innerHTML = '<span class="hl-quicklink__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></span><span class="hl-quicklink__label">Share</span>';
    var shareTimer = 0;
    function announceShare(message) {
      shareStatus.textContent = message;
      clearTimeout(shareTimer); shareTimer = setTimeout(function () { shareStatus.textContent = ''; }, 2600);
    }
  }
  root.classList.add('hl-rv-ready'); mode(false); select(0);
  if (location.hash) go(location.hash, true);
  if (document.fonts) document.fonts.ready.then(function () { measureBar(); if (location.hash) go(location.hash, false); });

  function drawTimeline(parent, m) {
    var rows = chronologyRows(m).map(function (r) {
      var lane = 'Chronology';
      if (curation.timeline_lanes) {
        var rule = curation.timeline_lanes.rules.find(function (x) { return new RegExp(x.pattern, 'i').test(r.event); });
        lane = rule ? rule.label : curation.timeline_lanes.default;
      }
      r.lane = lane; return r;
    });
    make('p', 'hl-rv-note', 'Dates are printed as written. Marker shapes: ● given date, ◆ inferred year, ▰ range, ◌ disputed. ' + (curation.timeline_lanes ? 'Timeline lanes: curated for this report; they group the chronology wording.' : 'Events share a single chronology lane.'), parent);
    var chart = make('div', 'hl-rv-timeline', null, parent), detail = make('p', 'hl-rv-event', 'Select an event to read its date and observation.', parent); detail.setAttribute('role', 'status');
    var lanes = curation.timeline_lanes ? [curation.timeline_lanes.default].concat(curation.timeline_lanes.rules.map(function (r) { return r.label; })).filter(function (v, i, a) { return a.indexOf(v) === i; }) : ['Chronology'];
    function show(r) { chart.querySelectorAll('[data-rv-event]').forEach(function (n) { n.classList.toggle('hl-rv-event-active', +n.dataset.rvEvent === rows.indexOf(r)); }); detail.textContent = r.display + ' · ' + r.lane + ' · ' + r.quality.replace('-', ' ') + ': ' + r.event; }
    var valid = rows.filter(function (r) { return !isNaN(r.when); });
    if (valid.length !== rows.length) { chart.remove(); detail.remove(); missing(parent, 'a chronology with parseable dates; original date wording is retained below'); dashTable(parent, m, 'Chronology as printed', 'chronology'); return false; }
    var min = Math.min.apply(null, valid.map(function (r) { return r.when; })), max = Math.max.apply(null, valid.map(function (r) { return r.end; }));
    var legend = make('div', 'hl-rv-timeline-legend', null, chart);
    lanes.forEach(function (lane, i) { var item = make('span', 'hl-rv-lane-' + i, null, legend); make('span', 'hl-rv-lane-swatch', '', item); make('span', '', lane, item); });
    // The four status swatches are the same shapes as the dots and take their colour from the same quality class (--mark in the stylesheet), so a legend cannot drift from the dots.
    [['given', 'Given date'], ['year-inferred', 'Inferred year'], ['range', 'Range'], ['disputed', 'Disputed']].forEach(function (v) { var item = make('span', 'hl-rv-legend-item hl-rv-' + v[0], null, legend); make('span', 'hl-rv-symbol', '', item); make('span', '', v[1], item); });
    var horizontal = make('div', 'hl-rv-swimlanes', null, chart);
    lanes.forEach(function (lane, li) {
      var band = make('div', 'hl-rv-lane hl-rv-lane-' + li, null, horizontal); make('h3', '', lane, band);
      var rail = make('div', 'hl-rv-rail', null, band);
      rows.forEach(function (r, i) { if (r.lane !== lane) return;
        var b = button('', rail, function () { show(r); }); b.className = 'hl-rv-marker hl-rv-' + r.quality;
        b.dataset.rvEvent = i; b.title = r.display + ': ' + r.event;
        b.setAttribute('aria-label', r.display + ': ' + r.event); b.dataset.start = r.when; b.dataset.end = r.end; b.style.left = (isNaN(r.when) || max === min ? 0 : 100 * ((r.when + r.end) / 2 - min) / (max - min)) + '%';
        make('span', 'hl-rv-symbol', '', b); make('span', '', i + 1, b);
        b.addEventListener('focus', function () { show(r); }); b.addEventListener('mouseenter', function () { show(r); });
      });
      function placeMarkers() {
        var width = rail.clientWidth; if (!width) return;
        var slots = [], step = (parseFloat(getComputedStyle(rail).getPropertyValue('--rv-mark-h')) || 64) + 8;
        Array.from(rail.children).forEach(function (b) {
          var a = +b.dataset.start, z = +b.dataset.end;
          var x = ((a + z) / 2 - min) / (max - min || 1) * width;
          var w = Math.max(44, (z - a) / (max - min || 1) * width);
          var interval = { left: x - w / 2 - 4, right: x + w / 2 + 4 }, slot = 0;
          while (slots[slot] && slots[slot].some(function (s) { return interval.left < s.right && interval.right > s.left; })) slot++;
          if (!slots[slot]) slots[slot] = []; slots[slot].push(interval);
          b.style.top = slot * step + 'px'; b.style.width = w + 'px';
        });
        rail.style.height = Math.max(1, slots.length) * step - 8 + 'px';
      }
      new ResizeObserver(placeMarkers).observe(rail);
    });
    // Measured axis labels: thin candidates using their actual DOM rectangles.
    var axis = make('div', 'hl-rv-axis', null, horizontal);
    valid.forEach(function (r) { var n = make('span', '', r.display, axis); n.style.left = 100 * (r.when - min) / (max - min || 1) + '%'; });
    function thin() {
      var last = -Infinity, drawn = 0;
      Array.from(axis.children).forEach(function (n) { n.hidden = false; var box = n.getBoundingClientRect(); if (box.left < last + 6) n.hidden = true; else { last = box.right; drawn++; } });
      axis.dataset.candidates = valid.length; axis.dataset.drawn = drawn;
    }
    new ResizeObserver(function () { if (axis.getBoundingClientRect().width) thin(); }).observe(axis);
    var vertical = make('ol', 'hl-rv-vertical-timeline', null, chart);
    rows.forEach(function (r, i) {
      var li = make('li', 'hl-rv-lane-' + lanes.indexOf(r.lane), null, vertical); make('span', 'hl-rv-date', r.display, li); li.dataset.rvEvent = i;
      var b = button('', li, function () { show(r); }); b.className = 'hl-rv-vertical-marker hl-rv-' + r.quality;
      b.addEventListener('focus', function () { show(r); }); b.addEventListener('mouseenter', function () { show(r); });
      make('span', 'hl-rv-symbol', '', b); var vtext = make('span', '', null, b); make('span', 'hl-rv-vnum', (i + 1) + '.', vtext); vtext.appendChild(document.createTextNode(' ' + r.event)); make('small', '', r.lane + ' · ' + r.quality.replace('-', ' '), b);
    });
    var tableDetails = make('details', 'hl-rv-chronology-table', null, parent); tableDetails.open = true; make('summary', '', 'Chronology as a table', tableDetails); dashTable(tableDetails, m, 'Every dated event as printed', 'chronology');
    return true;
  }
  } catch (error) {
    // Remove only nodes this enhancement created, including controls within the
    // original source. Existing layout assets and pre-existing chrome survive.
    document.querySelectorAll('.hl-rv-hit').forEach(function (n) { n.replaceWith(document.createTextNode(n.textContent)); });
    document.querySelectorAll('[data-rv-chrome]').forEach(function (n) { if (!originalChrome.has(n)) n.remove(); });
    content.replaceChildren.apply(content, sourceNodes);
    root.classList.remove('hl-rv-ready', 'hl-tabbed', 'hl-onepage', 'hl-rv-reading');
    if (page) delete page.dataset.rvHue;
    console.warn('Report enhancement unavailable; restored the complete article.', error);
  }

})();
