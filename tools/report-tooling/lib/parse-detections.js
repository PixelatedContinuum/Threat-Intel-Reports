'use strict';

/* Builds the detection-picker manifest from a detection file's MARKDOWN SOURCE.

   Source rather than rendered HTML, because the metadata being read is prose:
   Tier alone carries ten distinct string forms across the corpus. Parsing the
   source also sidesteps every kramdown rendering quirk the ATT&CK strip work
   spent a build fighting.

   A rule's text is the FIRST FENCE AFTER ITS HEADING and before the next
   heading. Positional pairing looks equivalent and is not: three corpus files
   open an engine section with a fence that is not a rule, and pairing by
   position offsets every rule in those files by one.

   Three authoring conventions were found by reading the corpus rather than
   counting it, and each is deliberate, so the parser learns them instead of the
   files being edited to suit the parser:

     1. A heading with no Tier is prose, not a rule. One file documents a
        retired rule that way, with a Status block explaining where its coverage
        went. Reporting it as a rule with a missing body would be wrong.
     2. A heading may carry several Tier lines when its fence holds a
        correlation rule with the base rules it references. The entry takes the
        highest tier, since Detection is what the bundle does once deployed.
        This is why the corpus counts 647 Tier lines against 644 headings.
     3. A rule's body may live in an earlier fence by necessity, because Sigma
        correlation rules must resolve their base rules within the same
        document. Such a rule has no fence of its own and is marked
        cross_referenced, which is a known state and not a failure.

   Only an unrecognised tier value is a failure. */

var ENGINES = {
  'YARA Rules': 'yara',
  'Sigma Rules': 'sigma',
  'Suricata Signatures': 'suricata'
};

var HEAD_LEN = 48;

// Detection outranks Hunting, because a bundle containing a Detection-tier
// correlation alerts once deployed regardless of its base rules' tiers.
var TIER_RANK = { Hunting: 1, Detection: 2 };

/* Tier is normalised on its LEADING WORD, because correlation rules append
   prose such as "(correlation rule) - bundled below with its 2 required
   non-alerting base rules". An unrecognised leading word is reported, never
   bucketed into whichever tier looks closest. */
function normaliseTier(raw) {
  var lead = String(raw || '').trim().split(/[^A-Za-z]/)[0].toLowerCase();
  if (lead === 'detection') return 'Detection';
  if (lead === 'hunting') return 'Hunting';
  return null;
}

function fieldsNamed(lines, name) {
  var re = new RegExp('^\\*\\*' + name + ':\\*\\*\\s*(.*)$');
  var out = [];
  lines.forEach(function (ln) {
    var m = String(ln).match(re);
    if (m) out.push(m[1].trim());
  });
  return out;
}

function firstField(lines, name) {
  var all = fieldsNamed(lines, name);
  return all.length ? all[0] : null;
}

function headOf(body) {
  return String(body).trim().replace(/\s+/g, ' ').slice(0, HEAD_LEN);
}

/* Walks the source once, tracking fence state so nothing inside a fence is ever
   mistaken for a heading. A rule body legitimately contains lines beginning
   with #, so this is load-bearing rather than defensive. */
function scan(src) {
  var events = [];
  var lines = String(src).split(/\r?\n/);
  var inFence = false, fenceIndex = -1, buf = null;
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (/^```/.test(ln)) {
      if (!inFence) {
        inFence = true;
        fenceIndex++;
        buf = [];
        events.push({ type: 'fence', index: fenceIndex, body: buf });
      } else {
        inFence = false;
        buf = null;
      }
      continue;
    }
    if (inFence) { buf.push(ln); continue; }
    if (/^## /.test(ln)) events.push({ type: 'h2', text: ln.slice(3).trim() });
    else if (/^#### /.test(ln)) events.push({ type: 'h4', text: ln.slice(5).trim(), line: i + 1 });
    else events.push({ type: 'text', text: ln });
  }
  return events;
}

function parse(src, slug) {
  var events = scan(src);
  var rules = [], unresolved = [];
  var engine = null, pending = null, meta = [];

  function close(fenceEvent) {
    if (!pending) return;
    var name = pending.text;
    var tiersRaw = fieldsNamed(meta, 'Tier');

    // Convention 1: no Tier means this heading is prose, not a rule.
    if (!tiersRaw.length) { pending = null; meta = []; return; }

    // Convention 2: several Tier lines describe one bundled fence.
    var normalised = tiersRaw.map(normaliseTier);
    var badIndex = normalised.indexOf(null);
    if (badIndex !== -1) {
      unresolved.push({
        name: name, engine: engine, line: pending.line,
        reason: 'unrecognised tier "' + tiersRaw[badIndex] +
                '": expected a value beginning Detection or Hunting'
      });
      pending = null; meta = [];
      return;
    }
    var tier = normalised.reduce(function (best, t) {
      return TIER_RANK[t] > TIER_RANK[best] ? t : best;
    }, normalised[0]);

    var attack = (firstField(meta, 'ATT&CK Coverage') || '').match(/T\d{4}(?:\.\d{3})?/g) || [];
    var rob = firstField(meta, 'Robustness');
    var entry = {
      slug: slug,
      name: name,
      engine: engine,
      tier: tier,
      tier_raw: tiersRaw,
      robustness: rob !== null && rob !== '' && !isNaN(parseInt(rob, 10)) ? parseInt(rob, 10) : null,
      confidence: firstField(meta, 'Confidence'),
      attack: attack,
      cross_referenced: !fenceEvent,
      fence: fenceEvent ? fenceEvent.index : null,
      head: fenceEvent ? headOf(fenceEvent.body.join('\n')) : null,
      body: fenceEvent ? fenceEvent.body.join('\n') : null
    };
    rules.push(entry);
    pending = null;
    meta = [];
  }

  for (var i = 0; i < events.length; i++) {
    var e = events[i];
    if (e.type === 'h2') {
      close(null);              // a section boundary ends any open heading
      engine = ENGINES[e.text] || null;
    } else if (e.type === 'h4') {
      if (engine) { close(null); pending = e; meta = []; }
    } else if (e.type === 'fence') {
      if (engine && pending) close(e);   // first fence after the heading wins
    } else if (pending) {
      meta.push(e.text);
    }
  }
  close(null);

  return { slug: slug, rules: rules, unresolved: unresolved };
}

module.exports = {
  parse: parse,
  normaliseTier: normaliseTier,
  ENGINES: ENGINES,
  HEAD_LEN: HEAD_LEN
};
