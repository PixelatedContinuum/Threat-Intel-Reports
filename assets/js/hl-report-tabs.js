/* Hunter's Ledger report tabs. Progressive enhancement of the unchanged article.
   Source blocks are moved, never copied or rewritten. One-page and print restore
   their original order. Dashboard text is a separate, excluded view of DOM tables. */
(function () {
  'use strict';
  var content = document.querySelector('.hl-report-page .hl-post-content');
  if (!content) return;
  var root = document.documentElement;
  var TOKENS = ['overview', 'victims', 'chain', 'timeline', 'attribution', 'indicators', 'confidence'];
  var NAMES = ['Overview', 'Victims and impact', 'Attack chain', 'Infrastructure and timeline', 'Attribution', 'Indicators and detections', 'Confidence and gaps'];
  var QUESTIONS = ['What happened and how bad is it?', 'Who was hit, and how far did the operator get?', 'How did the operator get in and spread?', 'Which servers, and when did each thing happen?', 'Who is behind it, and what would change my mind?', 'What can a defender deploy today?', "How strong is each finding, and what remains unknown?"];
  var phone = window.matchMedia('(max-width: 699px)');
  var sourceNodes = Array.from(content.childNodes);
  var headings = Array.from(content.children).filter(function (n) { return n.tagName === 'H2'; });
  function token(h) { return TOKENS.find(function (t) { return h.classList.contains('hl-tab-' + t); }); }
  // Invalid/partial annotations degrade to the complete server-rendered article.
  if (!headings.length || headings.some(function (h) { return !token(h); })) return;
  if (TOKENS.some(function (t) { return document.getElementById('tab-' + t) || document.getElementById('tabbtn-' + t); }) || document.getElementById('one-page')) return;
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
  function sourceLink(model, parent) { if (model && model.heading) link('Read in the report', '#' + model.heading.id, parent); }
  // figure-nav runs before this deferred script. Mark its generated labels
  // before detaching anything, so rollback retains only report words too.
  content.querySelectorAll('.hl-fignav').forEach(function (n) { n.setAttribute('data-rv-chrome', ''); n.setAttribute('data-pagefind-ignore', ''); });
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
    }
    currentBlock.appendChild(n);
  });
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
  var stages = find('chain', [/^Stage$/i, /What.*did/i]);
  var victims = find('victims', [/Organisation|Organization|Victim/i, /Grade/i]);
  var chronology = find('timeline', [/^Date|^Time|^When/i, /Observation|Event/i]);
  var judgments = find('confidence', [/Claim|Judgment/i, /Confidence/i, /change/i]);
  var indicators = find('indicators', [/^Indicator/i, /Action/i]);
  var hypotheses = find('attribution', [/Hypothesis/i, /stands|Assessment/i]);
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
  var bar = make('nav', 'hl-rv-bar', null);
  bar.setAttribute('aria-label', 'Report sections');
  content.parentNode.insertBefore(bar, content);
  var mobileLine = make('div', 'hl-rv-mobile-line', null, bar);
  var currentLabel = make('span', 'hl-rv-current', NAMES[0], mobileLine);
  var menuButton = button('Sections', mobileLine);
  menuButton.setAttribute('aria-expanded', 'false'); menuButton.setAttribute('aria-controls', 'hl-rv-sections');
  var menu = make('div', 'hl-rv-menu', null, bar); menu.id = 'hl-rv-sections'; menu.hidden = true;
  var tablist = make('div', 'hl-rv-tabs', null, bar); tablist.setAttribute('role', 'tablist'); tablist.setAttribute('aria-label', 'Report tabs');
  var oneLink = link('Read as one page', '#one-page', bar); oneLink.className = 'hl-rv-onepage';
  var panels = [], tabs = [], menuLinks = [], active = 0, onepage = false;
  var words = sections.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0);
  var time = make('span', 'hl-read-time hl-rv-time', Math.max(1, Math.round(words / 200)) + ' min in full');
  var eyebrow = document.querySelector('.hl-post-header__eyebrow'); if (eyebrow) eyebrow.appendChild(time);
  var menuOne;
  TOKENS.forEach(function (t, i) {
    var group = sections.filter(function (s) { return s.token === t; });
    var mins = Math.max(1, Math.round(group.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0) / 200));
    var tab = button('', tablist, function () { navigateTab(i, true); });
    tab.setAttribute('aria-label', NAMES[i]);
    make('span', 'hl-rv-tab-full', NAMES[i], tab);
    make('span', 'hl-rv-tab-short', ['Overview', 'Victims', 'Chain', 'Timeline', 'Actor', 'IOCs', 'Confidence'][i], tab);
    tab.id = 'tabbtn-' + t; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', 'tab-' + t);
    tab.title = QUESTIONS[i] + ' ' + mins + ' min read';
    tab.addEventListener('keydown', function (e) {
      var j = e.key === 'ArrowRight' ? (i + 1) % 7 : e.key === 'ArrowLeft' ? (i + 6) % 7 : e.key === 'Home' ? 0 : e.key === 'End' ? 6 : -1;
      if (j < 0) return; e.preventDefault(); navigateTab(j, false, true); tabs[j].focus({ preventScroll: true });
    });
    tab.addEventListener('focus', function () { if (!onepage && active !== i) select(i); });
    tabs.push(tab);
    var a = link('', '#tab-' + t, menu); a.className = 'hl-rv-menu-item';
    make('strong', '', NAMES[i], a); make('span', '', QUESTIONS[i], a); make('small', '', mins + ' min read', a); menuLinks.push(a);
    var panel = document.createElement('section'); panel.className = 'hl-rv-panel'; panel.id = 'tab-' + t;
    panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', tab.id); panel.tabIndex = -1;
    content.appendChild(panel); panels.push(panel);
    var title = make('header', 'hl-rv-panel-head', null, panel);
    make('h2', '', NAMES[i], title); make('p', '', QUESTIONS[i] + ' · ' + mins + ' min read', title);
    group.forEach(function (s) { panel.appendChild(s.node); });
  });
  menuOne = link('Read as one page', '#one-page', menu); menuOne.className = 'hl-rv-menu-item';
  function closeMenu(focus) { menu.hidden = true; menuButton.setAttribute('aria-expanded', 'false'); if (focus) menuButton.focus(); }
  menuButton.addEventListener('click', function () { menu.hidden = !menu.hidden; menuButton.setAttribute('aria-expanded', String(!menu.hidden)); });
  bar.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenu(true); });
  document.addEventListener('click', function (e) { if (!bar.contains(e.target)) closeMenu(false); });
  function select(i) {
    active = i;
    tabs.forEach(function (tab, j) { tab.setAttribute('aria-selected', String(i === j)); tab.tabIndex = i === j ? 0 : -1; panels[j].hidden = i !== j; });
    currentLabel.textContent = NAMES[i]; menuLinks.forEach(function (a, j) { if (j === i) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); closeMenu(false); measureBar();
  }
  function mode(one) {
    onepage = one; root.classList.toggle('hl-onepage', one); root.classList.toggle('hl-tabbed', !one);
    if (one) {
      // Lead with the written report in its original order; park the hidden
      // dashboard shells after it, rather than before the article's first word.
      sections.forEach(function (s) { content.insertBefore(s.node, panels[0]); });
      panels.forEach(function (p) { p.hidden = true; });
      tabs.forEach(function (t) { t.setAttribute('aria-selected', 'false'); t.tabIndex = -1; });
      tablist.hidden = true; currentLabel.textContent = 'Read as one page';
      oneLink.textContent = 'Back to tabs'; oneLink.href = '#tab-' + TOKENS[active];
    } else {
      sections.forEach(function (s) { var p = panels[TOKENS.indexOf(s.token)]; p.insertBefore(s.node, p.querySelector('.hl-rv-nextprev')); });
      tablist.hidden = false; oneLink.textContent = 'Read as one page'; oneLink.href = '#one-page'; select(active);
    }
    closeMenu(false); measureBar();
  }
  function measureBar() {
    root.style.setProperty('--hl-rv-bar-h', bar.offsetHeight + 'px');
    var nav = document.querySelector('.hl-nav');
    root.style.setProperty('--hl-rv-nav-h', !phone.matches && nav ? nav.offsetHeight + 'px' : '0px');
    var toc = panels[active] && panels[active].querySelector('.hl-rv-contents');
    var height = !onepage && toc && getComputedStyle(toc).position === 'sticky' ? toc.offsetHeight : 0;
    root.style.setProperty('--hl-rv-contents-h', height + 'px');
    if (window.HLGlossary) window.HLGlossary.applyEdgeClasses(content);
  }
  function scrollTopTab() { bar.scrollIntoView({ block: 'start', behavior: 'instant' }); }
  function navigateTab(i, scroll, replace) {
    mode(false); select(i); history[replace ? 'replaceState' : 'pushState'](null, '', '#tab-' + TOKENS[i]);
    if (scroll) scrollTopTab();
  }
  function target(hash) { try { return decodeURIComponent(hash.replace(/^#/, '')); } catch (e) { return hash.slice(1); } }
  function go(hash, scroll) {
    var id = target(hash);
    if (id === 'one-page') { mode(true); if (scroll) scrollTopTab(); return true; }
    var idx = TOKENS.indexOf(id.replace(/^tab-/, ''));
    if (id.indexOf('tab-') === 0 && idx >= 0) {
      mode(false); select(idx);
      if (scroll) scrollTopTab();
      panels[idx].focus({ preventScroll: true });
      return true;
    }
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

  function tableFold(parent, label) { var d = make('details', 'hl-rv-table-fold', null, parent); make('summary', '', label, d); return d; }
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
      var source = make('td', '', null, row); source.setAttribute('role', 'cell'); source.dataset.label = 'Source'; sourceLink(m, source);
    });
    return table;
  }
  function filters(parent, table, specs, noun) {
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
          if (!v) return true;
          if (v === 'Range') return /\b(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)\b/.test(c);
          if (v === 'Unscaled') return !/^(DEFINITE|HIGH|MODERATE|LOW|INSUFFICIENT)$/.test(c) && !/^(LOW|MODERATE|HIGH)-(LOW|MODERATE|HIGH)$/.test(c);
          return c.includes(v);
        });
        row.hidden = !hit; if (hit) n++;
      });
      count.textContent = 'Showing ' + n + ' of ' + rows.length + ' ' + noun;
    }
    controls.forEach(function (c) { c.addEventListener('input', apply); });
    button('Reset filters', area, function () { controls.forEach(function (c) { c.value = ''; }); apply(); });
    table.parentElement.before(area); apply();
    rows.forEach(function (r) { r.addEventListener('hl-rv-reveal', function () { controls.forEach(function (c) { c.value = ''; }); apply(); }); });
  }
  function tile(parent, value, label, how, tok) {
    var a = link('', '#tab-' + tok, parent); a.className = 'hl-rv-tile';
    make('strong', 'hl-rv-value', value, a); make('span', '', label, a); make('small', '', 'How counted: ' + how, a);
  }
  var builders = {
    overview: function (body) {
      var tiles = make('div', 'hl-rv-tiles', null, body), count = 0;
      if (victims) { var g = col(victims, /Grade/i); var inside = victims.rows.filter(function (r) { return /^(ACCESS SHOWN|COMPROMISED)\b/.test(r[g]); }).length;
        tile(tiles, inside, 'organisations with inside or authenticated access', 'Organisation rows graded ACCESS SHOWN or COMPROMISED in the victim table; qualifiers stay in that tab.', 'victims'); count++; }
      if (attack) {
        var ids = new Set(); attack.rows.forEach(function (r) { (r[0].match(/T\d{4}(?:\.\d{3})?/g) || []).forEach(function (id) { ids.add(id); }); });
        tile(tiles, ids.size, 'distinct technique IDs', 'Distinct IDs in the full procedure table.', 'chain');
        tile(tiles, attack.rows.length, 'procedure rows', 'Every procedure row, including repeated technique IDs.', 'chain'); count += 2;
      }
      if (ruleTotal !== null) { tile(tiles, ruleTotal, 'detection and hunting rules', 'Counts in the report detection guidance, reconciled to the engine and tier counts.', 'indicators'); count++; }
      if (chronology) { var dc = col(chronology, /^Date|^Time|^When/i);
        tile(tiles, chronology.rows[0][dc] + ' to ' + chronology.rows[chronology.rows.length - 1][dc], 'observation window', 'First and last rows in the chronology; not an activity duration.', 'timeline'); count++; }
      if (!count) missing(body, 'victim, procedure, indicator or dated chronology tables');
      if (judgments && Array.isArray(curation.headline_rows)) {
        var headline = Object.assign({}, judgments, { rows: judgments.rows.filter(function (_, i) { return curation.headline_rows.includes(i); }) });
        dashTable(tableFold(body, 'Headline judgments (curated for this report)'), headline, 'Headline judgments (curated for this report)');
      }
      return count + ' summary figures, from the report tables';
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
      dashTable(tableFold(body, 'Read all ' + victims.rows.length + ' victim rows and qualifiers'), victims, 'Victim access and qualifiers', 'victims'); return victims.rows.length + ' organisation rows, with grades and qualifiers';
    },
    chain: function (body) {
      if (stages) {
        if (curation.stage_joins) make('p', 'hl-rv-note', 'Stage-to-procedure links: curated for this report.', body);
        var wrap = make('div', 'hl-rv-chain-scroll', null, body); wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', 'Attack stages');
        var columns = make('div', 'hl-rv-stages', null, wrap);
        stages.rows.forEach(function (r) {
          var card = make('article', 'hl-rv-stage', null, columns); make('h3', '', r[0], card); make('p', '', r[1], card);
          if (r[2]) { make('h4', '', stages.headers[2], card); make('p', '', r[2], card); } sourceLink(stages, card);
          // Only explicit shared procedure names join. Never infer a stage from tactic alone.
          if (attack) {
            // Optional editorial joins are supplied only by the current report.
            var joins = curation.stage_joins && curation.stage_joins[r[0]] || [];
            var matches = attack.rows.map(function (a, i) { return { row: a, index: i }; }).filter(function (a) {
              var id = (a.row[0].match(/T\d{4}(?:\.\d{3})?/) || [])[0];
              var scope = a.row[col(attack, /Scope/i)] || '';
              if (joins.some(function (j) { return id === j.technique && scope.indexOf(j.scope_prefix) === 0; })) return true;
              var name = a.row[1].toLowerCase(); return name.length >= 12 && (r[1] + ' ' + (r[2] || '')).toLowerCase().includes(name);
            });
            var procedureList = matches.length ? tableFold(card, matches.length + ' linked procedure rows') : card;
            if (!matches.length) make('p', 'hl-rv-count', 'No explicit procedure join supplied; all rows remain in the table below.', card);
            matches.forEach(function (a) { var chip = link(a.row[0] + ' · ' + a.row[1], '#hl-rv-procedures-' + (a.index + 1), procedureList); chip.className = 'hl-rv-procedure'; badge(chip, a.row[col(attack, /^Status$/i)]); badge(chip, a.row[col(attack, /Conf/i)]); make('small', '', a.row[col(attack, /Scope/i)], chip); });
          }
        });
      } else missing(body, 'a Stage / What the operator did table');
      if (attack) {
        var full = tableFold(body, 'Search all ' + attack.rows.length + ' procedure rows');
        var table = dashTable(full, attack, 'All ATT&CK procedure rows', 'procedures');
        filters(full, table, [{ label: 'Status', col: col(attack, /^Status$/i), values: ['OBSERVED', 'INFERRED', 'NOT SHOWN'] }, { label: 'Confidence', col: col(attack, /Conf/i), values: ['HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT'] }], 'procedure rows');
      } else missing(body, 'a Tactic / Technique, Status and Confidence procedure table');
      var status = attack ? attack.rows.reduce(function (out, r) { var s = r[col(attack, /^Status$/i)]; out[s] = (out[s] || 0) + 1; return out; }, {}) : {};
      return (stages ? stages.rows.length : 0) + ' stages, ' + (attack ? attack.rows.length : 0) + ' procedures' + (attack ? ': ' + Object.keys(status).map(function (s) { return status[s] + ' ' + s.toLowerCase(); }).join(', ') : '');
    },
    timeline: function (body) {
      if (!chronology) { missing(body, 'a Date / Observation chronology table'); return 'Chronology remains in the full report'; }
      if (!drawTimeline(body, chronology)) return 'Chronology as printed; date positions unavailable'; return chronology.rows.length + ' dated events, with date precision preserved';
    },
    attribution: function (body) {
      var diamond = make('div', 'hl-rv-diamond', null, body); make('span', 'hl-rv-diamond-label', 'Diamond Model', diamond);
      [['Adversary', 'attribution', /Threat Actor|Actor Assessment|Attribution/i], ['Capability', 'chain', /classification/i], ['Infrastructure', 'timeline', /infrastructure/i], ['Victim', 'victims', /Who.*Hit|victim|access|impact/i]].forEach(function (v) {
        var block = sections.find(function (s) { return s.token === v[1] && s.heading && v[2].test(text(s.heading)); });
        var p = block && block.node.querySelector('p');
        var card = make('article', 'hl-rv-diamond-card', null, diamond); make('h3', '', v[0], card);
        if (p) { make('blockquote', '', (text(p).match(/^.*?[.!?](?:\s|$)/) || [text(p)])[0].trim(), card); link('Read in the report', '#' + block.heading.id, card); }
        else make('p', '', 'No structured ' + v[0].toLowerCase() + ' statement found. Read the full sections below.', card);
      });
      if (hypotheses) dashTable(tableFold(body, 'Read all ' + hypotheses.rows.length + ' competing hypotheses'), hypotheses, 'Competing hypotheses', 'hypotheses'); else missing(body, 'a Hypothesis / Where it stands table');
      if (calls) dashTable(tableFold(body, 'What would change each attribution call'), calls, 'Attribution calls and what would change them', 'calls');
      return 'Four Diamond Model vertices' + (hypotheses ? ', ' + hypotheses.rows.length + ' hypotheses' : '');
    },
    indicators: function (body) {
      if (!indicators) { missing(body, 'an Indicator / Action table'); return 'Indicators remain in the full report'; }
      make('p', 'hl-rv-feed-count', indicators.rows.length + (feedMatch ? ' of ' + feedMatch[1] + ' in the feed' : ' highlighted indicator rows'), body);
      var chips = make('ul', 'hl-rv-chips', null, body), status = make('p', 'hl-rv-copy-status', '', body); status.setAttribute('role', 'status');
      indicators.rows.forEach(function (r) { var li = make('li', '', null, chips); var code = make('code', '', r[0], li); button('Copy', li, function () { copy(code, status, 'Indicator copied as printed (defanged).'); }); });
      dashTable(tableFold(body, 'Indicator context, confidence and action'), indicators, 'Highlighted indicators, confidence and action', 'indicators');
      // The report's own detection paragraphs carry count, tier and caveat together.
      var detection = sections.find(function (s) { return s.token === 'indicators' && s.heading && /Detection|Hunting/i.test(text(s.heading)); });
      if (ruleTotal !== null) { var counts = make('ul', 'hl-rv-rulecounts', null, body); engines.forEach(function (e) { make('li', '', e.engine + ': ' + e.total + ' rules, ' + e.detection + ' detection, ' + e.hunting + ' hunting', counts); }); }
      if (detection) { var p = detection.node.querySelector('p'); if (p) { make('p', 'hl-rv-note', text(p), body); link('Read detection guidance', '#' + detection.heading.id, body); } }
      return indicators.rows.length + (feedMatch ? ' of ' + feedMatch[1] + ' feed indicators' : ' highlighted indicator rows') + (ruleTotal !== null ? ', ' + ruleTotal + ' rules' : '') + ', copied as printed';
    },
    confidence: function (body) {
      if (!judgments) { missing(body, 'a Claim / Confidence / What would change it table'); return 'Confidence and gaps remain in the full report'; }
      var all = tableFold(body, 'Filter all ' + judgments.rows.length + ' judgments');
      var table = dashTable(all, judgments, 'Judgments and what would change them', 'judgments');
      filters(all, table, [{ label: 'Confidence', col: col(judgments, /Confidence/i), values: ['DEFINITE', 'HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT', 'Range', 'Unscaled'] }], 'judgments');
      return judgments.rows.length + ' judgments, including ranges and unscaled wording';
    }
  };
  TOKENS.forEach(function (t, i) {
    var panel = panels[i], head = panel.querySelector('.hl-rv-panel-head');
    var view = make('section', 'hl-rv-view', null); head.after(view);
    var summary = make('div', 'hl-rv-view-summary', null, view), line = make('p', '', '', summary);
    var toggle = button('Show the view', summary); toggle.id = 'hl-rv-toggle-' + t;
    var body = make('div', 'hl-rv-view-body', null, view); body.id = 'hl-rv-view-' + t;
    toggle.setAttribute('aria-controls', body.id);
    line.textContent = builders[t](body);
    if (t === 'overview' && curation.headline_rows || t === 'chain' && curation.stage_joins || t === 'timeline' && curation.timeline_lanes) make('p', 'hl-rv-curated', 'View selections curated for this report.', view);
    body.hidden = phone.matches; toggle.textContent = body.hidden ? 'Show the view' : 'Hide the view'; toggle.setAttribute('aria-expanded', String(!body.hidden));
    function sync(open) { body.hidden = !open; toggle.textContent = open ? 'Hide the view' : 'Show the view'; toggle.setAttribute('aria-expanded', String(open)); }
    toggle.addEventListener('click', function () { sync(body.hidden); });
    phone.addEventListener('change', function () { sync(!phone.matches); });
    var first = sections.find(function (s) { return s.token === t && s.heading; });
    if (first) link('Jump to the full sections ↓', '#' + first.heading.id, body).className = 'hl-rv-jump';
    var hs = sections.filter(function (s) { return s.token === t && s.heading; });
    if (hs.length > 3) {
      var toc = make('details', 'hl-rv-contents', null); view.after(toc); toc.open = !phone.matches;
      make('summary', '', 'In this tab', toc); var nav = make('nav', '', null, toc); nav.setAttribute('aria-label', 'In this tab');
      hs.forEach(function (s) { link(text(s.heading), '#' + s.heading.id, nav); });
      phone.addEventListener('change', function () { toc.open = !phone.matches; });
      toc.addEventListener('toggle', measureBar);
    }
    var footer = make('nav', 'hl-rv-nextprev', null, panel); footer.setAttribute('aria-label', 'Read report in order');
    if (i > 0) link('Previous: ' + NAMES[i - 1], '#tab-' + TOKENS[i - 1], footer);
    if (i < 6) link('Next: ' + NAMES[i + 1], '#tab-' + TOKENS[i + 1], footer);
    else link('Back to Overview', '#tab-overview', footer);
  });
  // Keep all source tables, including those inside closed teardowns, scrollable.
  sections.forEach(function (s) {
    s.node.querySelectorAll('table').forEach(function (table, i) {
      var wrap = document.createElement('div'); wrap.className = 'hl-rv-source-table'; wrap.tabIndex = 0;
      wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', (s.heading ? text(s.heading) : 'Report') + ', table ' + (i + 1));
      table.before(wrap); wrap.appendChild(table);
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
  function copy(src, status, success) {
    function fallback() { var range = document.createRange(); range.selectNodeContents(src); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); status.textContent = 'Clipboard unavailable. Text selected; use the copy command.'; }
    if (navigator.clipboard) navigator.clipboard.writeText(src.textContent).then(function () { status.textContent = success; }, fallback); else fallback();
  }
  // Citation and code copy controls used to live in the old TOC script.
  var copyStatus = make('p', 'hl-rv-copy-status', '', content); copyStatus.setAttribute('role', 'status');
  content.querySelectorAll('[data-cite-copy]').forEach(function (b) { b.addEventListener('click', function () { var src = document.getElementById(b.dataset.citeCopy); if (src) copy(src, copyStatus, 'Citation copied.'); }); });
  content.querySelectorAll('.hl-rv-source pre').forEach(function (pre) { button('Copy code', pre, function () { copy(pre.querySelector('code') || pre, copyStatus, 'Code copied.'); }); });
  // Older figure-nav adds its own chips before this deferred script. They are
  // navigation chrome, not words of the report.
  content.querySelectorAll('.hl-fignav').forEach(function (n) { n.setAttribute('data-rv-chrome', ''); n.setAttribute('data-pagefind-ignore', ''); });
  // Keep resources in the header: the old fixed dock overlaps the wider report.
  var resources = document.querySelector('.hl-report-page .hl-quicklinks');
  var reportHeader = document.querySelector('.hl-report-page .hl-post-header');
  if (resources && reportHeader) reportHeader.appendChild(resources);
  // Keep the site's resource popovers functional without constructing a TOC.
  var resourcePairs = [['hl-detect-tab', 'hl-detect-panel'], ['hl-ioc-tab', 'hl-ioc-panel'], ['hl-stix-tab', 'hl-stix-panel']];
  function closeResources(except) { resourcePairs.forEach(function (pair) { var b = document.getElementById(pair[0]), p = document.getElementById(pair[1]); if (p && p !== except) { p.classList.remove(pair[1] + '--open'); if (b) b.setAttribute('aria-expanded', 'false'); } }); }
  resourcePairs.forEach(function (pair) {
    var b = document.getElementById(pair[0]), p = document.getElementById(pair[1]); if (!b || !p) return;
    document.body.appendChild(p); p.classList.add('hl-rv-resource');
    b.addEventListener('click', function () { var open = b.getAttribute('aria-expanded') !== 'true'; closeResources(p); b.setAttribute('aria-expanded', String(open)); p.classList.toggle(pair[1] + '--open', open); });
    p.querySelectorAll('.hl-ioc-cpbtn').forEach(function (c) { c.addEventListener('click', function () { var src = c.parentElement.querySelector('.hl-ioc-panel__val'); if (src) copy(src, copyStatus, 'Indicator copied as printed.'); }); });
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
  // Reader utilities survive the retirement of the old register/TOC script.
  var progressTrack = make('div', 'hl-progress-track', null, document.body);
  var progressBar = make('div', 'hl-progress-bar', null, document.body);
  progressTrack.setAttribute('aria-hidden', 'true'); progressBar.setAttribute('aria-hidden', 'true');
  function updateProgress() {
    var navHeight = phone.matches ? 0 : (document.querySelector('.hl-nav') || {}).offsetHeight || 0;
    var trackHeight = Math.max(0, innerHeight - navHeight);
    progressTrack.style.top = progressBar.style.top = navHeight + 'px';
    progressTrack.style.height = trackHeight + 'px';
    var total = Math.max(document.body.scrollHeight, root.scrollHeight) - innerHeight;
    progressBar.style.height = (total > 0 ? Math.min(1, scrollY / total) * trackHeight : 0) + 'px';
  }
  window.addEventListener('scroll', updateProgress, { passive: true });
  window.addEventListener('resize', updateProgress, { passive: true });
  new ResizeObserver(updateProgress).observe(content);
  if (eyebrow) {
    var shareStatus = make('span', 'hl-rv-share-status', '', eyebrow); shareStatus.setAttribute('role', 'status');
    var shareButton = button('Share', eyebrow, function () {
      if (navigator.share) { navigator.share({ title: document.title, url: location.href }).catch(function () {}); return; }
      var address = make('span', 'hl-rv-share-url', location.href, eyebrow);
      if (navigator.clipboard) navigator.clipboard.writeText(location.href).then(function () { shareStatus.textContent = 'Link copied.'; address.remove(); }, function () { copy(address, shareStatus, 'Link copied.'); });
      else copy(address, shareStatus, 'Link copied.');
    });
    shareButton.className = 'hl-share-btn'; shareButton.setAttribute('aria-label', 'Share this report');
  }
  // Storage may be disabled; a tip must never prevent the article from loading.
  var showTip = true;
  try { showTip = !sessionStorage.getItem('hl-section-tip'); sessionStorage.setItem('hl-section-tip', '1'); } catch (e) {}
  if (showTip) {
    var toast = make('div', 'hl-toast', null, document.body);
    make('span', 'hl-toast__label', 'Tip', toast);
    make('span', '', 'Use § beside a section heading to open its shareable link, then Share to save your place.', toast);
    var toastTimer;
    function dismissToast() { clearTimeout(toastTimer); toast.classList.remove('hl-toast--visible'); setTimeout(function () { toast.remove(); }, 400); }
    var dismiss = button('×', toast, dismissToast); dismiss.className = 'hl-toast__close'; dismiss.setAttribute('aria-label', 'Dismiss');
    setTimeout(function () { toast.classList.add('hl-toast--visible'); }, 1500); toastTimer = setTimeout(dismissToast, 16500);
  }
  root.classList.add('hl-rv-ready'); mode(false); select(0);
  if (location.hash) go(location.hash, true);
  if (document.fonts) document.fonts.ready.then(function () { measureBar(); if (location.hash) go(location.hash, false); });

  function drawTimeline(parent, m) {
    var dc = col(m, /^Date|^Time|^When/i), ec = col(m, /Observation|Event/i);
    var rows = m.rows.map(function (r) {
      var display = r[dc], event = r[ec], dates = display.match(/\d{4}-\d{2}-\d{2}/g) || [];
      var quality = /disagree|disput/i.test(display + ' ' + event) ? 'disputed' : /inferred/i.test(display) ? 'year-inferred' : /\bto\b/.test(display) ? 'range' : 'given';
      // Infer only the chart coordinate from a single explicitly shared year;
      // the visible date retains its original "year inferred" qualifier.
      var years = new Set(m.rows.flatMap(function (x) { return x[dc].match(/\b20\d{2}\b/g) || []; }));
      var start = dates[0];
      if (!start && years.size === 1) { var stamp = Date.parse(display.replace(/\s*\(.*?\)/g, '') + ' ' + Array.from(years)[0]); if (!isNaN(stamp)) start = new Date(stamp).toISOString().slice(0, 10); }
      var lane = 'Chronology';
      if (curation.timeline_lanes) {
        var rule = curation.timeline_lanes.rules.find(function (r) { return new RegExp(r.pattern, 'i').test(event); });
        lane = rule ? rule.label : curation.timeline_lanes.default;
      }
      return { display: display, event: event, quality: quality, when: Date.parse(start), end: dates[1] && quality === 'range' ? Date.parse(dates[1]) : Date.parse(start), lane: lane };
    });
    make('p', 'hl-rv-note', 'Dates are printed as written. Marker shapes: ● given date, ◆ inferred year, ▰ range, ◌ disputed. ' + (curation.timeline_lanes ? 'Timeline lanes: curated for this report; they group the chronology wording.' : 'Events share a single chronology lane.'), parent);
    var chart = make('div', 'hl-rv-timeline', null, parent), detail = make('p', 'hl-rv-event', 'Select an event to read its date and observation.', parent); detail.setAttribute('role', 'status');
    var lanes = curation.timeline_lanes ? [curation.timeline_lanes.default].concat(curation.timeline_lanes.rules.map(function (r) { return r.label; })).filter(function (v, i, a) { return a.indexOf(v) === i; }) : ['Chronology'];
    function show(r) { detail.textContent = r.display + ' · ' + r.lane + ' · ' + r.quality.replace('-', ' ') + ': ' + r.event; }
    var valid = rows.filter(function (r) { return !isNaN(r.when); });
    if (valid.length !== rows.length) { chart.remove(); detail.remove(); missing(parent, 'a chronology with parseable dates; original date wording is retained below'); dashTable(parent, m, 'Chronology as printed', 'chronology'); return false; }
    var min = Math.min.apply(null, valid.map(function (r) { return r.when; })), max = Math.max.apply(null, valid.map(function (r) { return r.end; }));
    var horizontal = make('div', 'hl-rv-swimlanes', null, chart);
    lanes.forEach(function (lane, li) {
      var band = make('div', 'hl-rv-lane hl-rv-lane-' + li, null, horizontal); make('h3', '', lane, band);
      var rail = make('div', 'hl-rv-rail', null, band);
      rows.forEach(function (r, i) { if (r.lane !== lane) return;
        var b = button('', rail, function () { show(r); }); b.className = 'hl-rv-marker hl-rv-' + r.quality;
        b.setAttribute('aria-label', r.display + ': ' + r.event); b.dataset.start = r.when; b.dataset.end = r.end; b.style.left = (isNaN(r.when) || max === min ? 0 : 100 * ((r.when + r.end) / 2 - min) / (max - min)) + '%';
        make('span', 'hl-rv-symbol', r.quality === 'year-inferred' ? '◆' : r.quality === 'range' ? '▰' : r.quality === 'disputed' ? '◌' : '●', b); make('span', '', i + 1, b);
        b.addEventListener('focus', function () { show(r); }); b.addEventListener('mouseenter', function () { show(r); });
      });
      function placeMarkers() {
        var width = rail.clientWidth; if (!width) return;
        var slots = [];
        Array.from(rail.children).forEach(function (b) {
          var a = +b.dataset.start, z = +b.dataset.end;
          var x = ((a + z) / 2 - min) / (max - min || 1) * width;
          var w = Math.max(44, (z - a) / (max - min || 1) * width);
          var interval = { left: x - w / 2 - 4, right: x + w / 2 + 4 }, slot = 0;
          while (slots[slot] && slots[slot].some(function (s) { return interval.left < s.right && interval.right > s.left; })) slot++;
          if (!slots[slot]) slots[slot] = []; slots[slot].push(interval);
          b.style.top = slot * 52 + 'px'; b.style.width = w + 'px';
        });
        rail.style.height = Math.max(1, slots.length) * 52 - 8 + 'px';
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
      var li = make('li', 'hl-rv-lane-' + lanes.indexOf(r.lane), null, vertical); make('span', 'hl-rv-date', r.display, li);
      var b = button('', li, function () { show(r); }); b.className = 'hl-rv-vertical-marker';
      make('span', 'hl-rv-symbol', r.quality === 'year-inferred' ? '◆' : r.quality === 'range' ? '▰' : r.quality === 'disputed' ? '◌' : '●', b); make('span', '', (i + 1) + '. ' + r.event, b); make('small', '', r.lane + ' · ' + r.quality.replace('-', ' '), b);
    });
    var tableDetails = make('details', 'hl-rv-chronology-table', null, parent); make('summary', '', 'Chronology as a table', tableDetails); dashTable(tableDetails, m, 'Every dated event as printed', 'chronology');
    return true;
  }
  } catch (error) {
    // Remove only nodes this enhancement created, including controls within the
    // original source. Existing layout assets and pre-existing chrome survive.
    document.querySelectorAll('[data-rv-chrome]').forEach(function (n) { if (!originalChrome.has(n)) n.remove(); });
    content.replaceChildren.apply(content, sourceNodes);
    root.classList.remove('hl-rv-ready', 'hl-tabbed', 'hl-onepage', 'hl-rv-reading');
    console.warn('Report enhancement unavailable; restored the complete article.', error);
  }

})();
