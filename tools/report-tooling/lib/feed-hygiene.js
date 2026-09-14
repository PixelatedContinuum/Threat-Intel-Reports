'use strict';

/* Finds and relocates values that must never sit in an indicator bucket.

   One module, two consumers, for the same reason the IOC classifier is shared: the
   gate that FAILS a feed and the migration that FIXES one must agree on what counts,
   or the gate passes something the migration would have moved and nobody notices.

   WHAT COUNTS AS AN INDICATOR BUCKET IS DECIDED BY EXCLUSION, not by an allowlist.
   The feeds have no schema at all: 55 carry indicators at the top level, 2 nest them
   under `iocs`, and there are 50-odd distinct bucket names between them. Any rule
   that named the indicator buckets would silently stop covering the next feed that
   invents a name. So everything is treated as ingestable except the two places that
   are definitionally not indicators:

     metadata               the campaign's own description, including the reference
                            backlink to the report on our own site
     hunt_only_never_block  the designated bucket this module moves things into

   Prose is safe without special handling. `classify()` rejects any string containing
   whitespace, so a detection note reading "monitor for connections to
   api.telegram.org" is never mistaken for a bare indicator. Only standalone values
   are flagged, which is exactly what an automated consumer would extract. */

var C = require('../../../assets/js/ioc-classify.js');
var U = require('./unblockable.js');

var EXEMPT_TOP = { metadata: true, hunt_only_never_block: true };

var NETWORK_TYPES = { domain: true, url: true, ipv4: true };

function isExemptPath(path) {
  return !!EXEMPT_TOP[String(path).split('.')[0]];
}

/* THE AUTHOR'S OWN MARKING IS AUTHORITATIVE, and it predates this module.

   The 13.140.145.210 feed already carried, per entry:

     "role": "TARGET - Citibanamex password-reset endpoint",
     "action": "HUNT",
     "false_positive_risk": true,
     "false_positive_note": "Legitimate bank endpoint. Never block",
     "context": "VICTIM-SIDE endpoint, not operator infrastructure"

   The judgement was right and it was already written down. The only thing that
   failed is that an automated consumer walking `network_indicators.domains` reads
   none of those fields and blocks a Mexican bank's password-reset endpoint along
   with everything else.

   So a static list of well-known services can never be the whole rule. It cannot
   know that an Ecuadorian ministry was the target of THIS campaign; only the
   analyst can. Reading the marking they already write captures exactly the cases a
   list cannot, and it means the standard extends their work rather than replacing
   it. */
function authorMarkedHuntOnly(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;

  /* `action: "HUNT"` is NOT one of these signals, and assuming it was matched 169
     entries including SHA256 hashes and operator IPs. In this project HUNT is the
     detection-TIER vocabulary, Detection versus Hunting, and it says nothing about
     whether blocking would harm a bystander. Neither is a bare
     `false_positive_risk: true`, which sits on mining pools that stay blockable by
     decision. Only two markings actually mean "this is not the operator's". */

  var role = typeof obj.role === 'string' ? obj.role.trim().toUpperCase() : '';
  if (/^(TARGET|VICTIM)\b/.test(role)) return 'author-marked target or victim';

  /* An explicit action: BLOCK outranks a prose never-block phrase, for the LOOSE
     tier only. The red team's 2026-09-13 review of the widening above found two
     misreadings, both the same shape: the author set `action: "BLOCK"` at
     `confidence: "DEFINITE"` or `"HIGH"` on a real operator asset, and the prose
     phrase test fired anyway because it cannot tell a prohibition from a sequencing
     instruction.

       165.227.175.161: `false_positive_risk: "Underlying VPS host belongs to
       GetYourGroup GmbH legitimate tourism platform - notify victim before
       blocking"`, on a CNC listener the author separately marked `action: BLOCK`.
       "Notify victim before blocking" is sequencing (notify, THEN block), not a
       prohibition, and the widened phrase list's `\bnotify victim before
       blocking\b` term read it as one.

       mail.hcjs2.jlengineering.se: `notes: "Do NOT blocklist apex
       jlengineering.se - it is a multi-tenant donor domain"`, on the operator's
       own tenant hostname, `action: BLOCK`. The warning is about the shared APEX
       domain, not this value: exactly the tenant-hostname-stays-blockable carve-out
       `unblockable.js` and `.claude/memory/feedback_ioc_feeds_blocklist_safety.md`
       already document, misapplied to the wrong host by a phrase match with no
       concept of which domain a caveat is actually about.

     The author wrote both fields. The action field is the decision; the prose is a
     caveat about HOW to act on it, not whether to. Trusting the decision field over
     the caveat is not a heuristic that happens to fix two rows: it is what the
     fields mean.

     This check does NOT apply to the strict role: TARGET|VICTIM tier above, which
     already returned by this point. A victim identity is a disclosure question, not
     a blocklist one, and the author may have written `action: BLOCK` before
     realising what the value actually was; the strict tier fires regardless of
     action on purpose. */
  var action = typeof obj.action === 'string' ? obj.action.trim().toUpperCase() : '';
  if (/^BLOCK\b/.test(action)) return null;

  /* The key list matters more than the phrase list, and it was the actual hole.
     Measured across the 57 published feeds on 2026-09-13: `false_positive_risk`
     appears 281 times and was never read, `false_positive_notes` (PLURAL) 5 times,
     and `note` (SINGULAR) 46 times. Only the singular `false_positive_note` and the
     plural `notes` were in this list, so an analyst who wrote "do not block" in any
     of the other three spellings was writing into a field nothing consulted.

     That left 14 values across 5 feeds sitting in blockable buckets carrying their
     author's own do-not-block marking, including bing.com, a victim subdomain URL,
     and AS12735 marked "legitimate Turkish consumer ISP serving millions".

     Reading `false_positive_risk` does NOT reintroduce the bare-`true` failure the
     comment above warns about: it is joined into the prose string and matched for
     phrases, so `false_positive_risk: true` still matches nothing, and the mining
     pools it sits on stay blockable. */
  var prose = ['false_positive_note', 'false_positive_notes', 'false_positive_risk',
               'notes', 'note', 'context', 'description']
    .map(function (k) { return typeof obj[k] === 'string' ? obj[k].toLowerCase() : ''; })
    .join(' ');
  if (/\bnever block\b|\bdo not block\b|\bdon't block\b|\bvictim-side\b|\bnot for blocking\b|\bdo not use for blocking\b|\bdo not blocklist\b|\bdo not preemptively block\b|\bnotify victim before blocking\b|\bnot a malicious destination\b/.test(prose)) {
    return 'author-marked never-block';
  }
  return null;
}

/* The first indicator-shaped string an object directly holds, if any, classified when
   classify() recognises it.

   When nothing classifies, this ALSO returns the first single-token string the object
   holds (no internal whitespace, so prose fields like `context` or `role` are excluded
   by the same test classify() itself applies), with `type: null`. That fallback exists
   for the strict target-or-victim tier below: a value marked as identifying a victim can
   still be a disclosure risk even when it is not shaped like a network indicator at all,
   for example a bare device string such as "cisco-IOS" lifted from a user agent. The
   loose never-block tier does not use the fallback for its own decision, because it still
   gates on `type` being a NETWORK_TYPES member, and `NETWORK_TYPES[null]` is always
   false, so this change is inert for that tier. */
function firstIndicator(obj) {
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var v = obj[keys[i]];
    if (typeof v !== 'string') continue;
    var r = C.classify(v);
    if (r) return { raw: v, value: r.value, type: r.type };
  }
  for (var j = 0; j < keys.length; j++) {
    var v2 = obj[keys[j]];
    if (typeof v2 !== 'string') continue;
    var t = v2.trim();
    if (t && !/\s/.test(t)) return { raw: v2, value: t, type: null };
  }
  return null;
}

/* Walks a parsed feed and returns every unblockable value sitting somewhere an
   automated consumer would read it. */
function scan(feed) {
  var found = [];

  function walk(node, path, parent, key) {
    if (node == null) return;
    if (typeof node === 'string') {
      if (isExemptPath(path)) return;
      var r = C.classify(node);
      if (!r) return;
      var cat = U.unblockable(r.type, r.value);
      if (cat) found.push({ path: path, value: node, host: r.value, category: cat });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(function (x, i) { walk(x, path, node, i); });
      return;
    }
    if (typeof node !== 'object') return;

    /* An object the author marked hunt-only is reported whole, whatever its value
       is, because the judgement is about the entry rather than about the host.

       The two tiers ask different questions and are gated differently on purpose.
       The loose never-block tier is a BLOCKLIST question: a hash, a filename, a
       registry path or an ASN cannot be blocked by a network control in a way that
       harms a bystander, so that tier only ever fires for a NETWORK_TYPES value.
       The strict target-or-victim tier is a DISCLOSURE question, and disclosure does
       not care whether the value looks like a network indicator: a victim-marked
       entry is reported regardless of type, which is what makes a value like
       "cisco-IOS" under a `role: "VICTIM..."` marking visible at all. */
    var marked = authorMarkedHuntOnly(node);
    if (marked && !isExemptPath(path)) {
      var v = firstIndicator(node);
      var isVictim = marked === 'author-marked target or victim';
      if (v && (isVictim || NETWORK_TYPES[v.type])) {
        found.push({ path: path, value: v.raw, host: v.value, category: marked });
        return;
      }
    }

    Object.keys(node).forEach(function (k) {
      walk(node[k], path ? path + '.' + k : k, node, k);
    });
  }

  walk(feed, '', null, null);
  return found;
}

/* Returns a NEW feed object with every unblockable value lifted out of its bucket
   and recorded under `hunt_only_never_block`, preserving the context that travelled
   with it. Never mutates the input.

   An entry is kept rather than deleted because the fact is real intelligence: a
   stealer exfiltrating through Telegram is often the single most useful line in the
   feed. What changes is where it sits, so a consumer walking the indicator buckets
   cannot reach it. */
function migrate(feed) {
  var moved = [], removed = [];
  var seen = {};

  /* A context is only taken from an object that ALSO directly holds an indicator,
     so `{value: "api.telegram.org", context: "exfil channel"}` yields its context
     and the feed's top-level `description` does not. Without that guard the
     campaign blurb cascades down the whole tree and every relocated value carries
     the same paragraph, which is worse than carrying nothing. */
  function contextOf(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
    var holdsIndicator = Object.keys(obj).some(function (k) {
      return typeof obj[k] === 'string' && C.classify(obj[k]);
    });
    if (!holdsIndicator) return null;
    var keys = ['context', 'description', 'role', 'note', 'notes', 'purpose'];
    for (var i = 0; i < keys.length; i++) {
      var v = obj[keys[i]];
      if (typeof v === 'string' && v.trim() && v.length < 200 && !C.classify(v)) {
        return v.trim();
      }
    }
    return null;
  }

  function prune(node, path, ctx) {
    if (node == null) return node;

    if (typeof node === 'string') {
      if (isExemptPath(path)) return node;
      var r = C.classify(node);
      if (!r) return node;
      var cat = U.unblockable(r.type, r.value);
      if (!cat) return node;
      var k = r.value;
      if (!seen[k]) {
        seen[k] = true;
        moved.push({ value: node, host: r.value, category: cat,
                     context: ctx || null, was: path });
      }
      return undefined;                       // caller drops it
    }

    if (Array.isArray(node)) {
      var out = [];
      node.forEach(function (x) {
        var v = prune(x, path, ctx);
        if (v !== undefined) out.push(v);
      });
      return out;
    }

    if (typeof node !== 'object') return node;

    var marked = authorMarkedHuntOnly(node);
    if (marked && !isExemptPath(path)) {
      var mv = firstIndicator(node);
      // Same split as scan(): the strict target-or-victim tier runs regardless of
      // type, because it is a disclosure question rather than a blocklist one; the
      // loose never-block tier stays gated on NETWORK_TYPES exactly as before.
      var mvIsVictim = marked === 'author-marked target or victim';
      if (mv && (mvIsVictim || NETWORK_TYPES[mv.type])) {
        if (!seen[mv.value]) {
          seen[mv.value] = true;
          /* A victim's own address space is not intelligence about the actor, it is
             who got hit, so it is REMOVED rather than relocated. The Ecuador
             investigation carried a telecom's public ranges and a ministry's hosts
             this way, plus RFC1918 addresses from inside the victim estate. Keeping
             those anywhere in a machine-readable feed is a disclosure question
             before it is ever a blocklist one; the finding belongs in the report
             prose, where it has the surrounding context that makes it meaningful.
             Everything else keeps its fact and just changes bucket.

             `full: node` carries the ENTIRE original object, not a {value, category,
             context} projection. All eight of the 2026-09-13 relocations dropped
             every other field: 165.227.175.161 lost `port: 23` and `protocol: "TCP"`,
             its whole value as a control, and 23.106.161.1 landed in
             hunt_only_never_block with no context at all. A value that survives
             without its port is not intelligence that survived. `node` here is
             already a clone (prune() operates on the top-level
             JSON.parse(JSON.stringify(feed)) copy), so storing the reference directly
             is safe: nothing downstream mutates this subtree again after the
             `return undefined` below. */
          var rec = { value: mv.raw, host: mv.value, category: marked,
                      context: contextOf(node), was: path, full: node };
          if (marked === 'author-marked target or victim') removed.push(rec);
          else moved.push(rec);
        }
        return undefined;
      }
    }

    var myCtx = contextOf(node);
    var obj = {}, dropped = 0, kept = 0;
    Object.keys(node).forEach(function (key) {
      var v = prune(node[key], path ? path + '.' + key : key, myCtx);
      if (v === undefined) { dropped++; return; }
      obj[key] = v;
      kept++;
    });

    /* An object that existed only to describe one relocated value goes with it.
       Leaving `{confidence: "HIGH", context: "C2 channel"}` behind with no value is
       worse than removing it: it reads as an indicator whose value went missing. */
    if (dropped && !hasValue(obj)) return undefined;
    return obj;
  }

  // True when anything indicator-shaped survives in this object.
  function hasValue(obj) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var v = obj[keys[i]];
      if (typeof v === 'string' && C.classify(v)) return true;
      if (Array.isArray(v) && v.length) return true;
      if (v && typeof v === 'object' && Object.keys(v).length) return true;
    }
    return false;
  }

  var out = prune(JSON.parse(JSON.stringify(feed)), '', null);
  if (out === undefined) out = {};

  if (moved.length) {
    var existing = out[U.BUCKET];
    var entries = [];
    // Preserve whatever an analyst already put there by hand.
    if (Array.isArray(existing)) entries = existing.slice();
    else if (existing && typeof existing === 'object') entries = [existing];
    else if (typeof existing === 'string') entries = [existing];

    moved.forEach(function (m) {
      /* `m.full` is set only by the author-marked-object path (the bare-string
         path below it in this file has no whole object to carry, just the string
         and its sibling context, so it keeps the {value, category, context} form
         it always had). When present, carry every original field forward and only
         add `category`, rather than reducing to three keys and losing the rest. */
      var e;
      if (m.full) {
        e = Object.assign({}, m.full);
        e.category = m.category;
      } else {
        e = { value: m.host, category: m.category };
        if (m.context) e.context = m.context;
      }
      entries.push(e);
    });
    out[U.BUCKET] = entries;
  }

  return { feed: out, moved: moved, removed: removed };
}

module.exports = { scan: scan, migrate: migrate, EXEMPT_TOP: EXEMPT_TOP,
                   authorMarkedHuntOnly: authorMarkedHuntOnly };
