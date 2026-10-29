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

  var words = sections.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0);
  var time = make('span', 'hl-read-time hl-rv-time', Math.max(1, Math.round(words / 200)) + ' min in full');
  var eyebrow = document.querySelector('.hl-post-header__eyebrow'); if (eyebrow) eyebrow.appendChild(time);
  var menuOne;
  TOKENS.forEach(function (t, i) {
    var group = sections.filter(function (s) { return s.token === t; });
    var mins = Math.max(1, Math.round(group.reduce(function (n, s) { return n + text(s.node).split(/\s+/).length; }, 0) / 200));
    times.push(mins);
    var tab = button('', tablist, function () { navigateTab(i, true); });
    tab.setAttribute('aria-label', ['Overview', 'Victims and impact', 'Chain: attack chain', 'Timeline: infrastructure and timeline', 'Actor: attribution', 'IOCs: indicators and detections', 'Confidence and gaps'][i]);
    make('span', 'hl-rv-tab-full', NAMES[i], tab);
    make('span', 'hl-rv-tab-short', ['Overview', 'Victims', 'Chain', 'Timeline', 'Actor', 'IOCs', 'Confidence'][i], tab);
    make('small', 'hl-rv-tab-time', mins + ' min', tab);
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
    active = i; currentSection = null;
    tabs.forEach(function (tab, j) { tab.setAttribute('aria-selected', String(i === j)); tab.tabIndex = i === j ? 0 : -1; panels[j].hidden = i !== j; });
    currentLabel.textContent = NAMES[i]; menuLinks.forEach(function (a, j) { if (j === i) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }); closeMenu(false); fillMenuSections(); measureBar(); updateProgress();
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
    } else {
      sections.forEach(function (s) { var p = panels[TOKENS.indexOf(s.token)]; p.insertBefore(s.node, p.querySelector('.hl-rv-nextprev')); });
      tablist.hidden = false; oneLink.textContent = 'Read as one page'; oneLink.href = '#one-page'; select(active);
    }
    closeMenu(false); measureBar(); updateProgress();
  }
  function measureBar() {
    if (!document || !document.documentElement) return;
    root.style.setProperty('--hl-rv-bar-h', mobileLine.offsetHeight + 4 + 'px');
    root.style.setProperty('--hl-rv-tabs-h', Math.max(0, mobileLine.offsetTop - 4) + 'px');
    var nav = document.querySelector('.hl-nav');
    root.style.setProperty('--hl-rv-nav-h', !phone.matches && nav ? nav.offsetHeight + 'px' : '0px');
    var toc = panels[active] && panels[active].querySelector('.hl-rv-contents');
    var height = !onepage && toc && getComputedStyle(toc).position === 'sticky' ? toc.offsetHeight : 0;
    root.style.setProperty('--hl-rv-contents-h', height + 'px');
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
  function tile(parent, value, label, how, tok) {
    var a = link('', '#tab-' + tok, parent); a.className = 'hl-rv-tile';
    make('strong', 'hl-rv-value', value, a); make('span', '', label, a);
    var m = { victims: victims, chain: attack, timeline: chronology }[tok];
    var note = make('small', '', 'How counted: ' + how + (m ? ' From ' + text(m.heading) + ', table ' + m.index + ', ' + m.rows.length + ' rows.' : ' From the detection guidance.'), a);
    if (m) a.href = '#' + m.heading.id;
    make('span', 'hl-rv-tile-destination', '↗ ' + NAMES[TOKENS.indexOf(tok)], a);
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
      var executive = sections.find(function (s) { return s.token === 'overview' && s.heading; });
      var lead = executive && executive.node.querySelector('p');
      if (lead) { var intro = make('div', 'hl-rv-lead', null, body); tiles.before(intro); make('blockquote', '', text(lead), intro); link('Read in the report', '#' + executive.heading.id, intro).setAttribute('aria-label', 'Read in the report: ' + text(executive.heading)); }
      if (judgments && Array.isArray(curation.headline_rows)) {
        var headline = Object.assign({}, judgments, { rows: judgments.rows.filter(function (_, i) { return curation.headline_rows.includes(i); }) });
        var headlineTable = dashTable(tableFold(body, 'Headline judgments (curated for this report)'), headline, 'Headline judgments (curated for this report)'); tiles.before(headlineTable.closest('details'));
      }
      return Array.from(tiles.querySelectorAll('.hl-rv-tile')).map(function (t, i) { return text(t.querySelector('strong')) + ' ' + ['organisations', 'techniques', 'procedure rows', 'rules', 'observation window'][i]; }).join(' · ');
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
      var stageCards = [], stageRows = [], stageDetails = [];
      var ribbon = make('div', 'hl-rv-stage-ribbon', null, body); ribbon.setAttribute('aria-label', 'Filter procedures by stage');
      if (stages) {
        if (curation.stage_joins) make('p', 'hl-rv-note', 'Stage-to-procedure links: curated for this report.', body);
        var wrap = make('div', 'hl-rv-chain-scroll', null, body); wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', 'Attack stages');
        var columns = make('div', 'hl-rv-stages', null, wrap);
        stages.rows.forEach(function (r, si) {
          var card = make('article', 'hl-rv-stage', null, columns);
          if (si < 7) card.dataset.rvSeries = si + 1;
          stageCards.push(card); stageRows.push([]);
          var detail = make('details', 'hl-rv-stage-detail', null, card); detail.open = !phone.matches; stageDetails.push(detail);
          var heading = make('summary', '', r[0], detail);
          phone.addEventListener('change', function () { detail.open = !phone.matches; });
          card = detail;
          make('p', '', r[1], card);
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
            stageRows[si] = matches.map(function (a) { return a.index; });
            var procedureList = matches.length ? tableFold(card, matches.length + ' linked procedure rows') : card;
            make('small', 'hl-rv-stage-count', matches.length + ' linked procedures', heading);
            var counts = ['OBSERVED', 'INFERRED', 'NOT SHOWN'].map(function (status) { return matches.filter(function (a) { return a.row[col(attack, /^Status$/i)] === status; }).length; });
            function mini(parent) { var bar = make('span', 'hl-rv-mini', null, parent); bar.setAttribute('aria-label', counts.map(function (n, i) { return n + ' ' + ['observed', 'inferred', 'not shown'][i]; }).join(', ')); counts.forEach(function (n, i) { if (n) { var segment = make('span', 'hl-rv-' + ['observed','inferred','not-shown'][i], '', bar); segment.style.flexGrow = n; } }); }
            mini(heading);
            var step = button('', ribbon, function () {
              var select = body.querySelector('.hl-rv-filters label:nth-of-type(4) select');
              if (select) { select.value = select.value === r[0] ? '' : r[0]; select.dispatchEvent(new Event('input')); }
              detail.open = true;
            }); step.dataset.rvSeries = si + 1; step.setAttribute('aria-pressed', 'false');
            make('strong', '', r[0], step); make('small', '', matches.length + ' linked', step); mini(step);
            if (!matches.length) make('p', 'hl-rv-count', 'No explicit procedure join supplied; all rows remain in the table below.', card);
            matches.forEach(function (a) { var chip = link(a.row[0] + ' · ' + a.row[1], '#hl-rv-procedures-' + (a.index + 1), procedureList); chip.className = 'hl-rv-procedure'; badge(chip, a.row[col(attack, /^Status$/i)]); badge(chip, a.row[col(attack, /Conf/i)]); make('small', '', a.row[col(attack, /Scope/i)], chip); });
          }
        });
      } else missing(body, 'a Stage / What the operator did table');
      if (attack) {
        // Filters and the live count are visible above both stage cards and the
        // procedure table. Only this generated copy is ever filtered.
        var full = make('section', 'hl-rv-procedures', null, body);
        var table = dashTable(full, attack, 'All ATT&CK procedure rows', 'procedures');
        var tacticCol = col(attack, /Tactic.*Technique/i);
        function tactic(value) { return value.replace(/\s*\(?T\d{4}.*$/, '').replace(/\s*[·:|/-]\s*$/, '').trim(); }
        var tactics = attack.rows.map(function (r) { return tactic(r[tacticCol]); }).filter(function (v, i, a) { return v && a.indexOf(v) === i; });
        var generatedRows = Array.from(table.tBodies[0].rows);
        generatedRows.forEach(function (row, ri) {
          var si = stageRows.findIndex(function (indices) { return indices.includes(ri); });
          if (si >= 0 && si < 7) row.dataset.rvSeries = si + 1;
        });
        var specs = [
          { label: 'Status', col: col(attack, /^Status$/i), values: ['OBSERVED', 'INFERRED', 'NOT SHOWN'] },
          { label: 'Confidence', col: col(attack, /Conf/i), values: ['DEFINITE', 'HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT', 'Range', 'Unscaled'] },
          { label: 'Stage', values: stages ? stages.rows.map(function (r) { return r[0]; }) : [], match: function (row, value) { return stageRows[stages.rows.findIndex(function (r) { return r[0] === value; })].includes(generatedRows.indexOf(row)); } },
          { label: 'Tactic', col: tacticCol, values: tactics, match: function (row, value) { return tactic(text(row.cells[tacticCol])) === value; } }
        ];
        var stageStates = stageCards.map(function (card) { var state = make('p', 'hl-rv-stage-state', '', card); state.setAttribute('role', 'status'); return state; });
        filters(full, table, specs, 'procedure rows', function (visible, filtering) {
          var indices = visible.map(function (r) { return generatedRows.indexOf(r); });
          stageCards.forEach(function (card, si) {
            var hits = stageRows[si].filter(function (ri) { return indices.includes(ri); }).length;
            card.classList.toggle('hl-rv-stage-match', filtering && hits > 0);
            card.classList.toggle('hl-rv-stage-muted', filtering && !hits);
            var step = ribbon.children[si]; if (step) step.setAttribute('aria-pressed', String(filtering && hits > 0));
            stageStates[si].textContent = !filtering ? '' : hits ? hits + ' linked rows match' : 'No linked rows match';
          });
        });
        var filterArea = full.querySelector('.hl-rv-filters');
        ribbon.after(filterArea);
        make('p', 'hl-rv-note', 'Stage filters use explicit procedure links only. Unjoined rows stay in the full table. Muted stages remain readable; the written report below is never filtered.', filterArea);
        var statusTiles = make('div', 'hl-rv-status-tiles', null);
        ['OBSERVED', 'INFERRED', 'NOT SHOWN'].forEach(function (value) {
          var n = attack.rows.filter(function (r) { return r[col(attack, /^Status$/i)] === value; }).length;
          var tile = make('div', 'hl-rv-status-tile hl-rv-' + value.toLowerCase().replace(/ /g, '-'), null, statusTiles);
          make('strong', '', n, tile); badge(tile, value);
          make('small', '', 'How counted: procedure rows with this status. ' + attack.rows.length + ' rows in table ' + attack.index + '.', tile); sourceLink(attack, tile, value + ' procedure rows');
        });
        filterArea.after(statusTiles);
      } else missing(body, 'a Tactic / Technique, Status and Confidence procedure table');
      var status = attack ? attack.rows.reduce(function (out, r) { var s = r[col(attack, /^Status$/i)]; out[s] = (out[s] || 0) + 1; return out; }, {}) : {};
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
      var types = make('div', 'hl-rv-type-filters', null, body); types.setAttribute('aria-label', 'Filter printed indicator types');
      function type(v) { return /^[a-f0-9]{32,128}$/i.test(v) ? 'Hash' : /^(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}(?::\d+)?$/.test(v) ? 'IP' : /[\\/]/.test(v) ? 'Path' : 'Other'; }
      var selectedType = '';
      ['', 'IP', 'Hash', 'Path', 'Other'].filter(function (t) { return !t || indicators.rows.some(function (r) { return type(r[0]) === t; }); }).forEach(function (t) {
        var b = button(t || 'All types', types, function () { selectedType = t; chips.querySelectorAll('li').forEach(function (li, i) { li.hidden = !!t && type(indicators.rows[i][0]) !== t; }); body.querySelectorAll('#indicators tbody tr').forEach(function (row, i) { row.hidden = !!t && type(indicators.rows[i][0]) !== t; }); Array.from(types.children).forEach(function (c) { c.setAttribute('aria-pressed', String(c === b)); }); }); b.setAttribute('aria-pressed', String(!t));
      });
      var chips = make('ul', 'hl-rv-chips', null, body), status = make('p', 'hl-rv-copy-status', '', body); status.setAttribute('role', 'status');
      indicators.rows.forEach(function (r) { var li = make('li', '', null, chips); var code = make('code', '', r[0], li); var b = button('Copy', li, function () { copyValue(code.textContent, b, live); }); });
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
      var distribution = make('div', 'hl-rv-distribution', null, body); all.before(distribution); distribution.setAttribute('aria-label', 'Judgments by confidence as printed');
      var counts = {}; judgments.rows.forEach(function (r) { var v = r[col(judgments, /Confidence/i)]; counts[v] = (counts[v] || 0) + 1; });
      Object.keys(counts).forEach(function (v) { var b = button(v + ' · ' + counts[v], distribution, function () { var input = all.querySelector('select'); input.value = v; input.dispatchEvent(new Event('input')); Array.from(distribution.children).forEach(function (c) { c.setAttribute('aria-pressed', String(c === b)); }); }); b.style.flexGrow = counts[v]; b.style.setProperty('--rv-share', (100 * counts[v] / judgments.rows.length) + '%'); b.setAttribute('aria-pressed', 'false'); b.title = v + ': ' + counts[v] + ' of ' + judgments.rows.length + ' judgments'; });
      filters(all, table, [{ label: 'Confidence', col: col(judgments, /Confidence/i), values: Object.keys(counts), match: function (row, value) { return text(row.cells[col(judgments, /Confidence/i)]) === value; } }], 'judgments');
      return judgments.rows.length + ' judgments, including ranges and unscaled wording';
    }
  };
  TOKENS.forEach(function (t, i) {
    var panel = panels[i], head = panel.querySelector('.hl-rv-panel-head');
    var view = make('section', 'hl-rv-view', null); head.after(view);
    var firstSource = sections.find(function (s) { return s.token === t && s.heading; });
    if (firstSource) { var skip = link('Skip this view', '#' + firstSource.heading.id, panel); skip.className = 'hl-rv-skip-view'; view.before(skip); }
    var summary = make('div', 'hl-rv-view-summary', null, view), line = make('p', '', '', summary);
    var toggle = button('Show the view', summary); toggle.id = 'hl-rv-toggle-' + t;
    var body = make('div', 'hl-rv-view-body', null, view); body.id = 'hl-rv-view-' + t;
    toggle.setAttribute('aria-controls', body.id);
    line.textContent = builders[t](body);
    sourceFooter(body, { overview: [victims, attack, judgments, chronology], victims: [victims], chain: [stages, attack], timeline: [chronology], attribution: [hypotheses, calls], indicators: [indicators], confidence: [judgments] }[t]);
    if ((t === 'overview' || t === 'indicators') && detectionSection) link('Counts from: ' + text(detectionSection.heading) + ', first paragraph', '#' + detectionSection.heading.id, body.querySelector('.hl-rv-source-footer'));
    if (t === 'overview') {
      var overviewLead = body.querySelector('.hl-rv-lead');
      function placeLead() { if (overviewLead) { if (phone.matches) view.before(overviewLead); else body.insertBefore(overviewLead, body.firstChild); } }
      placeLead(); phone.addEventListener('change', placeLead);
    }
    if (t === 'overview' && curation.headline_rows || t === 'chain' && curation.stage_joins || t === 'timeline' && curation.timeline_lanes) make('p', 'hl-rv-curated', 'View selections curated for this report.', view);
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
      toc.addEventListener('toggle', measureBar);
    }
    var footer = make('nav', 'hl-rv-nextprev', null, panel); footer.setAttribute('aria-label', 'Read report in order');
    function card(j, direction) { var a = link('', '#tab-' + TOKENS[j], footer); make('small', '', direction, a); make('strong', '', NAMES[j], a); make('span', '', QUESTIONS[j], a); make('small', '', times[j] + ' min read', a); }
    card((i + 6) % 7, 'Previous');
    card(i < 6 ? i + 1 : 0, i < 6 ? 'Next' : 'Back to');
    var teardownControls = make('div', 'hl-rv-teardown-controls', null, panel); footer.before(teardownControls);
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
  function copy(src, status, success, control) {
    if (control) { copyValue(src.textContent, control, status); return; }
    function fallback() { var range = document.createRange(); range.selectNodeContents(src); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); status.textContent = 'Clipboard unavailable. Text selected; use the copy command.'; }
    if (navigator.clipboard) navigator.clipboard.writeText(src.textContent).then(function () { status.textContent = success; }, fallback); else fallback();
  }
  // Citation and code copy controls used to live in the old TOC script.
  var copyStatus = make('p', 'hl-rv-copy-status', '', content); copyStatus.setAttribute('role', 'status');
  content.querySelectorAll('[data-cite-copy]').forEach(function (b) { b.addEventListener('click', function () { var src = document.getElementById(b.dataset.citeCopy); if (src) copy(src, copyStatus, 'Citation copied.', b); }); });
  content.querySelectorAll('.hl-rv-source pre').forEach(function (pre) { var b = button('Copy code', pre, function () { copy(pre.querySelector('code') || pre, copyStatus, 'Code copied.', b); }); });
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
  // Sponsor names/logos stay in flow; the complete tagline remains on hover/focus.
  document.querySelectorAll('.hl-sponsor-rail__item').forEach(function (a) { var tagline = a.querySelector('.hl-sponsor-rail__tagline'); if (tagline) a.title = text(tagline); });
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
    remaining.textContent = phone.matches ? '~' + left + 'm left' : description; remaining.setAttribute('aria-label', description); remaining.title = description;
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
  if (eyebrow) {
    var shareStatus = make('span', 'hl-rv-share-status', '', eyebrow); shareStatus.setAttribute('role', 'status');
    var shareButton = button('Share', eyebrow, function () {
      if (navigator.share) { navigator.share({ title: document.title, url: location.href }).catch(function () {}); return; }
      var address = make('span', 'hl-rv-share-url', location.href, eyebrow);
      if (navigator.clipboard) navigator.clipboard.writeText(location.href).then(function () { shareStatus.textContent = 'Link copied.'; address.remove(); }, function () { copy(address, shareStatus, 'Link copied.'); });
      else copy(address, shareStatus, 'Link copied.');
    });
    if (resources) resources.appendChild(shareButton);
    shareButton.className = 'hl-share-btn'; shareButton.setAttribute('aria-label', 'Share this report');
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
    function show(r) { chart.querySelectorAll('[data-rv-event]').forEach(function (n) { n.classList.toggle('hl-rv-event-active', +n.dataset.rvEvent === rows.indexOf(r)); }); detail.textContent = r.display + ' · ' + r.lane + ' · ' + r.quality.replace('-', ' ') + ': ' + r.event; }
    var valid = rows.filter(function (r) { return !isNaN(r.when); });
    if (valid.length !== rows.length) { chart.remove(); detail.remove(); missing(parent, 'a chronology with parseable dates; original date wording is retained below'); dashTable(parent, m, 'Chronology as printed', 'chronology'); return false; }
    var min = Math.min.apply(null, valid.map(function (r) { return r.when; })), max = Math.max.apply(null, valid.map(function (r) { return r.end; }));
    var legend = make('div', 'hl-rv-timeline-legend', null, chart);
    lanes.forEach(function (lane, i) { var item = make('span', 'hl-rv-lane-' + i, null, legend); make('span', 'hl-rv-symbol', '━', item); make('span', '', lane, item); });
    ['● Given date', '◆ Inferred year', '▰ Range', '◌ Disputed'].forEach(function (v) { make('span', '', v, legend); });
    var horizontal = make('div', 'hl-rv-swimlanes', null, chart);
    lanes.forEach(function (lane, li) {
      var band = make('div', 'hl-rv-lane hl-rv-lane-' + li, null, horizontal); make('h3', '', lane, band);
      var rail = make('div', 'hl-rv-rail', null, band);
      rows.forEach(function (r, i) { if (r.lane !== lane) return;
        var b = button('', rail, function () { show(r); }); b.className = 'hl-rv-marker hl-rv-' + r.quality;
        b.dataset.rvEvent = i; b.title = r.display + ': ' + r.event;
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
      Array.from(axis.children).forEach(function (n) { n.style.setProperty('--rv-tick-h', Math.max(12, axis.getBoundingClientRect().top - horizontal.getBoundingClientRect().top) + 'px'); n.hidden = false; var box = n.getBoundingClientRect(); if (box.left < last + 6) n.hidden = true; else { last = box.right; drawn++; } });
      axis.dataset.candidates = valid.length; axis.dataset.drawn = drawn;
    }
    new ResizeObserver(function () { if (axis.getBoundingClientRect().width) thin(); }).observe(axis);
    var vertical = make('ol', 'hl-rv-vertical-timeline', null, chart);
    rows.forEach(function (r, i) {
      var li = make('li', 'hl-rv-lane-' + lanes.indexOf(r.lane), null, vertical); make('span', 'hl-rv-date', r.display, li); li.dataset.rvEvent = i;
      var b = button('', li, function () { show(r); }); b.className = 'hl-rv-vertical-marker';
      b.addEventListener('focus', function () { show(r); }); b.addEventListener('mouseenter', function () { show(r); });
      make('span', 'hl-rv-symbol', r.quality === 'year-inferred' ? '◆' : r.quality === 'range' ? '▰' : r.quality === 'disputed' ? '◌' : '●', b); make('span', '', (i + 1) + '. ' + r.event, b); make('small', '', r.lane + ' · ' + r.quality.replace('-', ' '), b);
    });
    var tableDetails = make('details', 'hl-rv-chronology-table', null, parent); tableDetails.open = true; make('summary', '', 'Chronology as a table', tableDetails); dashTable(tableDetails, m, 'Every dated event as printed', 'chronology');
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
