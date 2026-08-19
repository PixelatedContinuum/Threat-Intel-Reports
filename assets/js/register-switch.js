/* The Hunter's Ledger: register switch.
   Brief shows Tier 1 only, Analyst adds Tier 2, Full shows everything.

   Full is the default and the on-load state, so a reader who never touches the
   control sees exactly the page that is published today. The switch is purely
   additive; nothing is ever hidden unless it is asked for.

   Tiers come from an authored `hl-tier-N` class on each <h2>, written as a
   kramdown block IAL on the line AFTER the heading. That form leaves the
   generated anchor byte-identical, which is what makes the marking safe on a
   corpus whose anchors are already addressed by figure_nav chips, detection
   links and readers' bookmarks. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  else { root.HLRegisterSwitch = api; api.init(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VIEWS = { brief: 1, analyst: 2, full: 3 };

  /* A button shows its name and its section count on one line; the sentence
     explaining it lives in the strip on the right, describing whichever view is
     active and previewing whichever is hovered or focused. That keeps the whole
     control one line tall while still explaining itself, which a title attribute
     never does for touch or keyboard. */
  /* The names come from the house register-tier vocabulary in CLAUDE.md, not from
     invented shorthand: Tier 1 is the Operational Brief, Tier 2 is Tradecraft and
     Intel, Tier 3 is the Technical Teardown. A reader who has seen one report
     recognises the same three words on the next one. The sentence in the strip
     then says what each view ADDS, which the name alone cannot. */
  var LABELS = [
    ['brief', 'Executive Brief', 'the bottom line and what to do first'],
    ['analyst', 'Tradecraft & Intel', 'adds infrastructure, actor and detection'],
    ['full', 'Full Teardown', 'adds the deep technical analysis']
  ];
  var DESC = { brief: LABELS[0][2], analyst: LABELS[1][2], full: LABELS[2][2] };

  function tierOf(h2) {
    var m = String(h2.className || '').match(/\bhl-tier-([123])\b/);
    return m ? Number(m[1]) : null;
  }

  /* A section is an h2 and every sibling up to the next h2. Hiding the heading
     and leaving the body behind is the defect the detection picker paid for, so
     the unit is the whole section or nothing. Anything before the first h2 is
     page furniture and belongs to no section, so it is never hidden. */
  function sectionsFor(body) {
    var out = [];
    var cur = null;
    var kids = body.children;
    for (var i = 0; i < kids.length; i++) {
      var el = kids[i];
      if (el.tagName === 'H2') {
        cur = { h2: el, tier: tierOf(el), nodes: [el] };
        out.push(cur);
      } else if (cur) {
        cur.nodes.push(el);
      }
    }
    return out;
  }

  function distinctTiers(body) {
    var seen = {};
    var hs = body.querySelectorAll('h2');
    for (var i = 0; i < hs.length; i++) {
      var t = tierOf(hs[i]);
      if (t) seen[t] = 1;
    }
    return Object.keys(seen).length;
  }

  function tocItemsFor(doc, id) {
    var out = [];
    var links = doc.querySelectorAll('#hl-toc-list a[href="#' + id + '"], ' +
      '#hl-toc-list-mobile a[href="#' + id + '"]');
    for (var i = 0; i < links.length; i++) {
      var li = links[i].closest ? links[i].closest('li') : null;
      if (li) out.push(li);
    }
    return out;
  }

  function setHidden(el, on) {
    if (on) el.setAttribute('hidden', '');
    else el.removeAttribute('hidden');
  }

  /* An UNMARKED section is treated as Tier 1, so it can never vanish. The gate
     refuses a partly marked report, but if one ever reaches a reader the failure
     must be a section that stays visible, not one that silently disappears. */
  function apply(doc, view) {
    var body = doc.querySelector('.hl-post-content');
    if (!body) return 0;
    var max = VIEWS[view] || 3;
    var hiddenCount = 0;
    sectionsFor(body).forEach(function (sec) {
      var tier = sec.tier || 1;
      var hide = tier > max;
      for (var i = 0; i < sec.nodes.length; i++) setHidden(sec.nodes[i], hide);
      var items = tocItemsFor(doc, sec.h2.id);
      for (var j = 0; j < items.length; j++) setHidden(items[j], hide);
      if (hide) hiddenCount++;
    });
    /* Says something on load, not only after a click. An empty strip beside three
       buttons reads as a control that has not finished loading. */
    setStatus(doc, view);
    return hiddenCount;
  }

  /* How many sections each view would show, counted from the page itself. An
     unmarked section counts as Tier 1 for the same reason apply() treats it that
     way: it can never be the thing that disappears. */
  function sectionCounts(body) {
    var n = { 1: 0, 2: 0, 3: 0 };
    sectionsFor(body).forEach(function (sec) { n[sec.tier || 1]++; });
    return {
      brief: n[1],
      analyst: n[1] + n[2],
      full: n[1] + n[2] + n[3]
    };
  }

  function plural(n) { return n + ' section' + (n === 1 ? '' : 's'); }

  function buildControl(doc, view, counts) {
    var wrap = doc.createElement('div');
    wrap.className = 'hl-viewswitch';
    wrap.id = 'hl-viewswitch';

    var label = doc.createElement('span');
    label.className = 'hl-viewswitch__label';
    label.textContent = 'Read as';
    wrap.appendChild(label);

    var group = doc.createElement('div');
    group.className = 'hl-viewswitch__group';
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', 'Choose how much of the report to show');

    LABELS.forEach(function (spec) {
      var b = doc.createElement('button');
      b.type = 'button';
      b.className = 'hl-viewswitch__btn';
      b.setAttribute('data-view', spec[0]);
      b.setAttribute('aria-pressed', spec[0] === view ? 'true' : 'false');

      var n = counts ? counts[spec[0]] : null;

      var name = doc.createElement('span');
      name.className = 'hl-viewswitch__btn-name';
      name.textContent = spec[1];
      b.appendChild(name);

      if (n !== null) {
        var cnt = doc.createElement('span');
        cnt.className = 'hl-viewswitch__btn-count';
        cnt.textContent = String(n);
        b.appendChild(cnt);
      }

      // One readable name for assistive tech instead of separate fragments.
      b.setAttribute('aria-label', spec[1] + ': ' + spec[2] +
        (n === null ? '' : ', ' + plural(n)));
      group.appendChild(b);
    });
    wrap.appendChild(group);

    var live = doc.createElement('span');
    live.className = 'hl-viewswitch__status';
    live.id = 'hl-view-status';
    live.setAttribute('aria-live', 'polite');
    wrap.appendChild(live);

    return wrap;
  }

  /* The strip carries the sentence: what the active view shows, or a preview of
     whatever the reader is pointing at. */
  function setStatus(doc, view, preview) {
    var live = doc.getElementById('hl-view-status');
    if (!live) return;
    var body = doc.querySelector('.hl-post-content');
    if (!body) return;
    var counts = sectionCounts(body);
    var which = preview || view;
    live.textContent = (counts[which] || 0) + ' of ' + plural(counts.full) +
      ', ' + (DESC[which] || '');
    if (preview && preview !== view) live.setAttribute('data-preview', '');
    else live.removeAttribute('data-preview');
  }

  function setPressed(doc, view) {
    var btns = doc.querySelectorAll('.hl-viewswitch__btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-pressed',
        btns[i].getAttribute('data-view') === view ? 'true' : 'false');
    }
  }

  /* If an in-page target sits in a hidden section, switch to Full before the
     browser scrolls. Mirrors the teardown opener the layout already ships, and
     it is what stops a figure_nav chip pointing into a hidden tier from
     scrolling nowhere. Returns the view it switched to, or null. */
  function revealFor(doc, id) {
    var el = doc.getElementById(id);
    if (!el) return null;
    var hidden = el.hasAttribute('hidden');
    if (!hidden) {
      var p = el.parentElement;
      while (p && !hidden) { if (p.hasAttribute && p.hasAttribute('hidden')) hidden = true; p = p.parentElement; }
    }
    if (!hidden) return null;
    apply(doc, 'full');
    setPressed(doc, 'full');
    return 'full';
  }

  function viewFromHash(hash) {
    var m = String(hash || '').match(/[#&]view=(brief|analyst|full)\b/);
    return m ? m[1] : null;
  }

  function init() {
    var doc = document;
    var body = doc.querySelector('.hl-post-content');
    if (!body) return;

    /* Two distinct tiers is the floor. With one, every view is identical and the
       control would promise a choice it cannot deliver; with none, the report was
       never marked and gets nothing at all. */
    if (distinctTiers(body) < 2) return;

    var view = viewFromHash(location.hash) || 'full';
    var currentView = view;
    var control = buildControl(doc, view, sectionCounts(body));
    body.insertBefore(control, body.firstChild);
    // Populate the status immediately, so the strip is never blank on load.
    apply(doc, view);
    setPressed(doc, view);

    /* Hover and keyboard focus preview the sentence for the button under the
       pointer, so the reader can compare all three without the control needing
       three lines of its own. */
    ['mouseover', 'focusin'].forEach(function (ev) {
      control.addEventListener(ev, function (e) {
        var b = e.target && e.target.closest ? e.target.closest('.hl-viewswitch__btn') : null;
        if (b) setStatus(doc, currentView, b.getAttribute('data-view'));
      });
    });
    ['mouseleave', 'focusout'].forEach(function (ev) {
      control.addEventListener(ev, function () { setStatus(doc, currentView); });
    });

    control.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('.hl-viewswitch__btn') : null;
      if (!b) return;
      var v = b.getAttribute('data-view');
      currentView = v;
      apply(doc, v);
      setPressed(doc, v);
      try {
        var base = location.href.split('#')[0];
        history.replaceState(null, '', v === 'full' ? base : base + '#view=' + v);
      } catch (err) { /* a blocked history write must not break the switch */ }
    });

    // Capture phase, so the view is corrected before the browser scrolls.
    doc.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('a[href^="#"]') : null;
      if (!a) return;
      var href = a.getAttribute('href') || '';
      if (href.length < 2) return;
      var id;
      try { id = decodeURIComponent(href.slice(1)); } catch (err) { id = href.slice(1); }
      revealFor(doc, id);
    }, true);

    window.addEventListener('hashchange', function () {
      var v = viewFromHash(location.hash);
      if (v) { apply(doc, v); setPressed(doc, v); return; }
      var id;
      try { id = decodeURIComponent(location.hash.slice(1)); } catch (err) { id = location.hash.slice(1); }
      if (id) revealFor(doc, id);
    });

    // The TOC is built by the layout's own inline script, which may not have run
    // yet when a deferred module initialises. Re-apply once on load so a
    // non-default view reaches the TOC entries too.
    window.addEventListener('load', function () {
      var v = viewFromHash(location.hash) || 'full';
      if (v !== 'full') { apply(doc, v); setPressed(doc, v); }
      if (location.hash && !viewFromHash(location.hash)) {
        var id;
        try { id = decodeURIComponent(location.hash.slice(1)); } catch (err) { id = location.hash.slice(1); }
        if (id) revealFor(doc, id);
      }
    });
  }

  return {
    tierOf: tierOf,
    sectionsFor: sectionsFor,
    distinctTiers: distinctTiers,
    buildControl: buildControl,
    sectionCounts: sectionCounts,
    setStatus: setStatus,
    apply: apply,
    revealFor: revealFor,
    viewFromHash: viewFromHash,
    init: init
  };
});
