/* The Hunter's Ledger: makes the literal-heavy key/value tables usable.

   WHAT THESE TABLES ACTUALLY ARE, measured rather than assumed. 58 tables and
   429 rows across 24 of 42 reports carry a `Field | Value` header or one of its
   kin (Property | Value, Attribute | Assessment, Field | Assessment,
   Attribute | Value). None of them is a wall: row counts run 3 to 12, median 7
   to 8, so there is nothing here to collapse the way the ATT&CK table needed it.

   What varies is the VALUE. Median length is 46 characters and the longest is
   474. Applying a rubric of "at least 60% of a table's values are 60 characters
   or shorter", 38 tables and 275 rows are literal-heavy and 20 tables with 154
   rows are prose-heavy, carrying whole-sentence campaign-classification and
   operator-profile summaries.

   ONLY THE LITERAL-HEAVY TABLES ARE ENHANCED, and the same rubric that measured
   them is applied here at runtime so the code and the count cannot drift. A copy
   button on a 200-character sentence would be worse than the table it sits in,
   and the prose tables have a real readability problem that a copy button does
   not solve. That is a separate question, deliberately left alone.

   Two things, both of which transfer from the process tree because they are what
   actually made it work:

     1. a copy button on every value, because a hash or a path in a table cell
        currently has to be selected by hand
     2. an id and a permalink on every row, so a report can point at one fact

   WHY NO LIQUID AND NO NEW INCLUDE. Nothing parses these tables: check-report.js
   treats a table as a candidate only when it has a Tactic header or yields
   technique IDs, and these have neither. So the markup is nobody's input and
   there is no gate to keep fed. Enhancing in place reaches every qualifying
   table with no per-report edit and no data migration, and it needs no Liquid at
   a moment when Liquid is the one thing this project cannot yet verify locally.

   The copy button reuses the site's own .hl-copy-btn, so it inherits the
   existing hover and focus reveal and the (hover: none) rules that keep it
   visible and 32px tall on touch. Only `position` is overridden, because the
   original is absolutely positioned against a <pre> and here it sits inline
   after the value where it cannot overlap the text. */
(function () {
  'use strict';

  var body = document.querySelector('.hl-post-content') || document.querySelector('.hl-post-body');
  if (!body) return;

  var KEY_HDR = /^(field|property|attribute)$/i;
  var VAL_HDR = /^(value|assessment)$/i;
  var SHORT = 60;        // a value at or under this counts as short, for the rubric
  var LITERAL_SHARE = 0.6;
  /* WHICH VALUES GET A COPY BUTTON. Not "short ones". Median value length in
     this corpus is 46 characters, so a length test hands a button to almost
     every row, including "36/76" and "Embarcadero Delphi (Turbo Linker)", which
     nobody copies. A wall of buttons is decoration, and decoration is what this
     work exists to remove.

     The report already declares which values are literals: the author wrote them
     in backticks, which kramdown renders as <code>. That is the signal, and it
     is the author's own judgment rather than a heuristic guessing at it. The
     regex is the fallback for a literal someone forgot to mark up. */
  var INDICATOR = /\b[0-9a-f]{32,64}\b|[A-Za-z]:\\|%[A-Z_]+%|https?:\/\/|hxxps?:\/\/|\b\d{1,3}(?:\.\d{1,3}){3}\b|\{[0-9A-Fa-f-]{36}\}/;

  function txt(el) { return (el.textContent || '').replace(/\s+/g, ' ').trim(); }

  function valueCells(t) {
    var out = [];
    [].forEach.call(t.querySelectorAll('tr'), function (tr) {
      if (tr.querySelector('th')) return;
      var tds = tr.querySelectorAll('td');
      if (tds.length >= 2) out.push({ row: tr, key: tds[0], val: tds[1] });
    });
    return out;
  }

  function isFactTable(t) {
    var head = t.querySelector('tr');
    if (!head) return false;
    var cells = head.querySelectorAll('th');
    if (cells.length !== 2) return false;
    return KEY_HDR.test(txt(cells[0])) && VAL_HDR.test(txt(cells[1]));
  }

  /* The rubric, applied at runtime rather than trusted from a measurement made
     once. A prose-heavy table is skipped outright and stays exactly as authored. */
  function isLiteralHeavy(rows) {
    if (!rows.length) return false;
    var short = 0;
    rows.forEach(function (r) { if (txt(r.val).length <= SHORT) short++; });
    return (short / rows.length) >= LITERAL_SHARE;
  }

  function slug(s) {
    return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  }

  var used = {};
  function uniqueId(base) {
    var id = base || 'fact', n = 2;
    while (used[id] || document.getElementById(id)) { id = (base || 'fact') + '-' + n; n++; }
    used[id] = 1;
    return id;
  }

  function copyText(text, done) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); },
                                              function () { done(false); });
      return;
    }
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    document.body.appendChild(ta);
    ta.select();
    var worked = false;
    try { worked = document.execCommand('copy'); } catch (e) { worked = false; }
    document.body.removeChild(ta);
    done(worked);
  }

  var status = document.createElement('div');
  status.className = 'hl-facts-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  body.appendChild(status);
  var statusTimer = null;
  function announce(msg) {
    status.textContent = msg;
    clearTimeout(statusTimer);
    statusTimer = setTimeout(function () { status.textContent = ''; }, 4000);
  }

  function enhanceRow(r) {
    var key = txt(r.key), value = txt(r.val);
    if (!key || !value) return;

    r.row.id = uniqueId('fact-' + slug(key));

    var link = document.createElement('a');
    link.className = 'hl-facts-anchor';
    link.href = '#' + r.row.id;
    link.setAttribute('aria-label', 'Link to ' + key);
    link.textContent = '#';
    r.key.appendChild(link);

    /* the value the button copies is the code span when there is exactly one,
       because "`Apophyge` (operator codename)" should copy Apophyge, not the
       gloss after it */
    var codes = r.val.querySelectorAll('code');
    var copyValue = codes.length === 1 ? txt(codes[0]) : value;
    if (!codes.length && !INDICATOR.test(value)) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'hl-copy-btn hl-facts-copy';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy the value of ' + key);
    btn.addEventListener('click', function () {
      copyText(copyValue, function (worked) {
        btn.textContent = worked ? 'Copied!' : 'Error';
        announce(worked ? key + ' copied to the clipboard.'
                        : 'The browser refused clipboard access.');
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      });
    });
    r.val.appendChild(btn);
  }

  var enhanced = 0;
  [].forEach.call(body.querySelectorAll('table'), function (t) {
    if (!isFactTable(t)) return;
    var rows = valueCells(t);
    if (!isLiteralHeavy(rows)) return;      // prose-heavy, left exactly as authored
    t.classList.add('hl-facts');
    rows.forEach(function (r) {
      try { enhanceRow(r); } catch (e) { /* one bad row must not stop the rest */ }
    });
    enhanced++;
  });
  if (!enhanced) return;

  function reveal() {
    var id = (location.hash || '').slice(1);
    if (!id) {
      /* clearing the hash clears the marker with it, rather than leaving a row
         highlighted as "linked" when nothing links to it any more */
      [].forEach.call(document.querySelectorAll('.hl-facts tr.is-linked'), function (x) {
        x.classList.remove('is-linked');
      });
      return;
    }
    var row = document.getElementById(id);
    if (!row || !row.closest || !row.closest('.hl-facts')) return;
    [].forEach.call(document.querySelectorAll('.hl-facts tr.is-linked'), function (x) {
      x.classList.remove('is-linked');
    });
    row.classList.add('is-linked');
  }
  window.addEventListener('hashchange', reveal);
  reveal();
})();
