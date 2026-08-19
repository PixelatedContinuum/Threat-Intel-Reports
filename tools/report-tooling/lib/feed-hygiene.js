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

  var prose = ['false_positive_note', 'notes', 'context', 'description']
    .map(function (k) { return typeof obj[k] === 'string' ? obj[k].toLowerCase() : ''; })
    .join(' ');
  if (/\bnever block\b|\bdo not block\b|\bdon't block\b|\bvictim-side\b/.test(prose)) {
    return 'author-marked never-block';
  }
  return null;
}

/* The first indicator-shaped string an object directly holds, if any. */
function firstIndicator(obj) {
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var v = obj[keys[i]];
    if (typeof v !== 'string') continue;
    var r = C.classify(v);
    if (r) return { raw: v, value: r.value, type: r.type };
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
       is, because the judgement is about the entry rather than about the host. */
    var marked = authorMarkedHuntOnly(node);
    if (marked && !isExemptPath(path)) {
      var v = firstIndicator(node);
      // A hash cannot be blocked in a way that harms anyone, so the marking only
      // matters for values a network control would act on.
      if (v && NETWORK_TYPES[v.type]) {
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
      if (mv && NETWORK_TYPES[mv.type]) {
        if (!seen[mv.value]) {
          seen[mv.value] = true;
          /* A victim's own address space is not intelligence about the actor, it is
             who got hit, so it is REMOVED rather than relocated. The Ecuador
             investigation carried a telecom's public ranges and a ministry's hosts
             this way, plus RFC1918 addresses from inside the victim estate. Keeping
             those anywhere in a machine-readable feed is a disclosure question
             before it is ever a blocklist one; the finding belongs in the report
             prose, where it has the surrounding context that makes it meaningful.
             Everything else keeps its fact and just changes bucket. */
          var rec = { value: mv.raw, host: mv.value, category: marked,
                      context: contextOf(node), was: path };
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
      var e = { value: m.host, category: m.category };
      if (m.context) e.context = m.context;
      entries.push(e);
    });
    out[U.BUCKET] = entries;
  }

  return { feed: out, moved: moved, removed: removed };
}

module.exports = { scan: scan, migrate: migrate, EXEMPT_TOP: EXEMPT_TOP,
                   authorMarkedHuntOnly: authorMarkedHuntOnly };
