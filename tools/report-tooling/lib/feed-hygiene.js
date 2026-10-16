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

/* BUCKET-LEVEL MARKINGS. A marking can be written on a whole container and inherited by
   everything beneath it, not only on a single entry.

   WHY THIS EXISTS (T-0322). `ioc-feeds/multivector-ecommerce-rce-toolkit-192-3-1-116-iocs.json`
   carries a top-level `targeted_assets` bucket whose own `warning` field reads
   "CONTEXT ONLY - DO NOT BLOCK. These are victim-side and target-side assets ...". The
   per-entry machinery above only ever looked at the marking fields OF AN ENTRY, so none of
   the 43 typed values sitting under that bucket (31 domains, 12 IPv4) was seen: the bucket
   was marked, the value was not, and the gate passed every one. The same blind spot covers a
   whole-bucket `exclusions` / `investigated_and_excluded` / `victim_inventory` container.

   The rule has two independent triggers, exactly as specified by this change's brief:

   1. BY KEY NAME. The key the container sits under decides the tier. The victim tier is
      `targeted_assets` exactly, or any key containing `victim` (case-insensitive): the corpus
      carries `victim_inventory`, `victim_indicators`, `internal_victim_ipv4`,
      `victim_infrastructure_do_not_block`, `host_indicators.victim_id_formats`. The loose tier
      is any key containing `exclu`, `not_malicious`, `context_only`, `do_not_block`,
      `never_block`, `do_not_blocklist`, `false_positives` or `benign`. Victim wins when both
      match.

      SHEER `target` IS NOT A VICTIM MARKING. `brand_impersonation_targets`,
      `target_processes` and similar name the thing the operator attacks or impersonates, i.e.
      an operator or malware fact, not a bystander; treating the substring `target` as a victim
      marking would pull operator infrastructure out of the feeds. Only `targeted_assets` is on
      the list, because it is the one key in the corpus whose own text says those values are
      victim-side.

   2. BY A MARKER STRING ON THE CONTAINER. A container that directly holds no classify()-typed
      string, but does carry a never-block phrase under `warning`, `caution`, `note`, `notes`,
      `description`, `context` or `reason`, is a loose bucket. The phrase list is the one
      `authorMarkedHuntOnly` already matches, widened with the phrasings the T-0322 corpus uses:
      `context only`, `must not be blocked`, `do not ingest`, `not indicators of compromise`,
      `do not place in any block rule`.

   WHY A BUCKET IS WIDER THAN AN ENTRY, 2026-10-16. Inside a loose bucket this module acts on
   NETWORK_TYPES AND the hash types (`sha256`, `sha1`, `md5`), while a loose marking on a single
   ENTRY still acts on NETWORK_TYPES only. The asymmetry is the author's intent, not ours: an
   analyst who sets a value aside as "do not block" writes it on one value and is speaking to
   the network consumer in front of them, but an analyst who fences off a WHOLE bucket is
   speaking to every consumer of the feed, the hash blocklist included. The vendor-binary
   hashes in `ioc-feeds/opendirectory-62-60-237-100-20260506-iocs.json`
   `known_legitimate_DO_NOT_BLOCKLIST` are the worked case: 16 SHA-256 of genuine signed
   vendor binaries (Wondershare, Google Updater, Info-ZIP, Qihoo) co-located in the operator
   bundle as camouflage, whose own bucket text warns that generic hash blocking "would cause
   massive false positives". A hash-ingesting consumer walking the file reads the same list the
   gate does, so the bucket's marking has to cover it too. Filenames stay out of the loose tier
   in both places: `excluded_directories` and `excluded_file_types` are ransomware behaviour
   lists (the directories a locker skips), not indicators, and a filename is not a network or a
   hash blocklist entry.

   `action: BLOCK` OUTRANKS A LOOSE BUCKET, not a victim one. An entry object that directly
   carries `action` starting with `BLOCK` is ordinary again for its own subtree inside a loose
   bucket: the author decided that one value, and the precedence is the one
   `authorMarkedHuntOnly` already gives the same field per entry. It never outranks a victim
   bucket, because a victim marking is a disclosure question rather than a blocklist one, and
   the author may have written `action: BLOCK` before realising what the value was.

   NOT CHECKED, AND THIS RULE CANNOT CLOSE IT: a bucket whose key is innocuous AND which carries
   no marker phrase is not seen, and neither is a marking written outside these seven key names
   or phrased in words outside the list. The rule is name- and phrase-based, so it covers the
   shapes the corpus actually uses and nothing else; a container like `assets_2026` holding a
   warning in a field called `disclaimer` would still pass. The gate is a floor, not a proof.

   THE ROOT IS NEVER A BUCKET. Bucketing is only ever triggered from a NAMED container (a string
   key, or a string array index is not a name so arrays do not trigger it), so a feed whose
   top-level `description` happened to say "do not block" cannot turn its entire body into a
   bucket. This is a deliberate limit: the brief's rule 2 is written for a container, and the
   root is not one. */
var VICTIM_TIER = 'victim';
var LOOSE_TIER = 'loose';
var VICTIM_CATEGORY = 'bucket-marked target or victim';
var LOOSE_CATEGORY = 'bucket-marked never-block';

/* The types a LOOSE bucket covers: NETWORK_TYPES plus the hash types. The per-entry loose tier
   still uses NETWORK_TYPES alone (see the header comment above and `authorMarkedHuntOnly`). */
var HASH_TYPES = { sha256: true, sha1: true, md5: true };
function looseTypeActedOn(type) { return !!NETWORK_TYPES[type] || !!HASH_TYPES[type]; }

var BUCKET_LOOSE_KEY_RX =
  /exclu|not_malicious|context_only|do_not_block|never_block|do_not_blocklist|false_positives|benign/i;

var BUCKET_MARKER_KEYS = ['warning', 'caution', 'note', 'notes', 'description', 'context', 'reason'];

/* The same never-block prose test `authorMarkedHuntOnly` applies to an entry's own fields,
   widened for bucket containers. Kept as one regex so a phrase added here is not accidentally
   left out of the container check. */
var NEVER_BLOCK_RX =
  /\bnever block\b|\bdo not block\b|\bdon't block\b|\bvictim-side\b|\bnot for blocking\b|\bdo not use for blocking\b|\bdo not blocklist\b|\bdo not preemptively block\b|\bnotify victim before blocking\b|\bnot a malicious destination\b|\bcontext only\b|\bmust not be blocked\b|\bdo not ingest\b|\bnot indicators of compromise\b|\bdo not place in any block rule\b/;

/* Stricter of two tiers: a victim marking outranks a loose one, because disclosure outranks
   blocklist hygiene (the same split scan() and migrate() already make between their tiers). */
function stricter(a, b) {
  if (a === VICTIM_TIER || b === VICTIM_TIER) return VICTIM_TIER;
  if (a === LOOSE_TIER || b === LOOSE_TIER) return LOOSE_TIER;
  return null;
}

/* The tier a KEY NAME alone assigns, or null. */
function keyBucketTier(key) {
  if (typeof key !== 'string') return null;
  if (key === 'targeted_assets' || /victim/i.test(key)) return VICTIM_TIER;
  if (BUCKET_LOOSE_KEY_RX.test(key)) return LOOSE_TIER;
  return null;
}

/* True when the object directly holds a classify()-typed string, which makes it an entry
   rather than a container. Rule 2 only ever fires for a container. */
function holdsDirectTypedString(obj) {
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    if (typeof obj[keys[i]] === 'string' && C.classify(obj[keys[i]])) return true;
  }
  return false;
}

/* The tier a marker string on the container assigns, or null. */
function markerMarking(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return null;
  if (holdsDirectTypedString(node)) return null;
  for (var i = 0; i < BUCKET_MARKER_KEYS.length; i++) {
    var v = node[BUCKET_MARKER_KEYS[i]];
    if (typeof v === 'string' && NEVER_BLOCK_RX.test(v.toLowerCase())) return LOOSE_TIER;
  }
  return null;
}

/* The public predicate: the tier a container's key and/or its own marker string assigns, or
   null. scan(), migrate() and generate-ioc-index.js all route through this one function so the
   gate, the fix and the search index cannot disagree about what a bucket is. */
function bucketMarking(key, node) {
  var byKey = keyBucketTier(key);
  if (byKey === VICTIM_TIER) return VICTIM_TIER;
  // The marker string is only read off a NAMED container: the root (key null) is never a bucket.
  var byMarker = (typeof key === 'string') ? markerMarking(node) : null;
  return stricter(byKey, byMarker);
}

/* True when the object directly carries `action` starting with BLOCK. The one reading of the
   field, shared by `authorMarkedHuntOnly` (which gives it precedence over an entry's prose) and
   by scanBucket()/pruneBucket() (where it takes an entry back out of a LOOSE bucket's reach) and
   by generate-ioc-index.js (which must index that entry's values as ordinary keys). */
function actionIsBlock(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  var action = typeof obj.action === 'string' ? obj.action.trim().toUpperCase() : '';
  return /^BLOCK\b/.test(action);
}

/* Every directly-held value of `obj` that classifies and meets the tier: all types for a
   victim bucket (a disclosure question), the network and hash types for a loose one (both a
   blocklist question: an automated hash blocklist harms a bystander's vendor binary exactly as
   a network blocklist harms a shared host). Used to treat an entry object as one unit rather
   than descending into it. */
function bucketValues(obj, tier) {
  var out = [];
  Object.keys(obj).forEach(function (k) {
    var v = obj[k];
    if (typeof v !== 'string') return;
    var r = C.classify(v);
    if (!r) return;
    if (tier === VICTIM_TIER || looseTypeActedOn(r.type)) {
      out.push({ raw: v, value: r.value, type: r.type });
    }
  });
  return out;
}

/* Whether the gate acts on a value of `type` sitting under a bucket of `tier`. The single
   place the loose tier's type set is written, so scan(), migrate() and the index cannot
   disagree. `tier` null/undefined (no bucket) never acts. */
function bucketActsOn(tier, type) {
  if (tier === VICTIM_TIER) return true;
  if (tier === LOOSE_TIER) return looseTypeActedOn(type);
  return false;
}

/* Approved exceptions to the strict target-or-victim tier: specific values a human has
   reviewed, in a diff, and confirmed do not identify anyone, despite sitting under an
   entry the author marked `role: TARGET...` or `role: VICTIM...`.

   A PER-ENTRY MARKER WAS THE FIRST DESIGN AND WAS REJECTED. The proposal (gate-mechanics.md,
   2026-09-13) was a boolean field an analyst sets once on the entry itself, honoured wherever
   `classify()` returns no type for the value, on the theory that the untyped space is a safe
   place to allow an override because it can never contain an IP, domain, URL, email or hash.
   staff1 tested that theory against the real module and the real corpus and broke it
   (`break-constraint-2.md`): the untyped space is exactly where stolen-credential identifiers
   live. Two were published in this corpus until 2026-10-16 (withheld since, T-0323): a
   stolen victim JWT token id (a UUID), and a stolen 1Password vault id (26 base32 characters)
   the feed's own text calls resolvable for victim identification. A per-entry marker would
   have let an analyst wave either of those through with the same one-line trust the cisco-IOS
   case deserves, and nothing in the design would have told them apart.

   The list here is a curated, reviewed-once record of approved exceptions, the same pattern
   `unblockable.js` already uses (`SERVICES`, `TENANT_NAMESPACES`, `SUFFIXES`) for the same
   shape of problem: a small number of specific values a human has looked at, not a rule that
   tries to characterise a whole class of safe strings. The "not enumerable" objection to this
   approach conflated two different things: enumerating the CLASS of every non-identifying
   string in the world is genuinely unbounded and was never the ask; recording each APPROVED
   EXCEPTION as it is reviewed is exactly what this object does, one entry at a time, and it
   is no more open-ended than `unblockable.js`'s own lists already are.

   Every entry needs a reason and a date. An entry with neither is not acceptable, because the
   reason is the only thing standing between "reviewed" and "guessed", and there is no
   automated check that can tell those apart after the fact. */
var NON_IDENTIFYING = {
  'cisco-IOS': 'Generic Cisco IOS user-agent string. Identifies a device class shared by ' +
    'millions of routers, not a device, a network or an owner. The opendirectory-13-140-145-210 ' +
    'feed\'s own role text calls it "VICTIM-generated" because the string was pulled from a ' +
    'victim device\'s outbound traffic, but the string itself carries nothing specific to that ' +
    'victim; it would read identically off any Cisco box anywhere. Approved 2026-09-13.'
};

/* SECOND, INDEPENDENT GUARD, NOT THE SAFETY ARGUMENT: a value is only ever read from this
   list when `classify()` also returns no type for it (checked at the call site below via
   `candidate.type === null`). This exists so a later edit that adds a domain, IP, URL, email
   or hash to `NON_IDENTIFYING` above is inert rather than a live hole; it stops that class of
   mistake, it does not justify the list. Do NOT read "untyped" as a proxy for
   "non-identifying" anywhere in this file: the whole reason the per-entry marker design was
   rejected is that untyped values include real victim credential identifiers (the JWT jti and
   the 1Password vault id named above), so an untyped value earns nothing by being untyped. The
   only reason this design is safe is that every entry in `NON_IDENTIFYING` is put there by a
   human, reviewed, in a diff, one at a time. The type check just keeps the blast radius of a
   future mistake to values that were already off-limits to the loose tier for an unrelated
   reason. */

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
function authorMarkedHuntOnly(obj, exemptions, path) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;

  /* `action: "HUNT"` is NOT one of these signals, and assuming it was matched 169
     entries including SHA256 hashes and operator IPs. In this project HUNT is the
     detection-TIER vocabulary, Detection versus Hunting, and it says nothing about
     whether blocking would harm a bystander. Neither is a bare
     `false_positive_risk: true`, which sits on mining pools that stay blockable by
     decision. Only two markings actually mean "this is not the operator's". */

  var role = typeof obj.role === 'string' ? obj.role.trim().toUpperCase() : '';
  if (/^(TARGET|VICTIM)\b/.test(role)) {
    /* Consulted here, at the single choke point both scan() and migrate() already route
       through, so one check covers both consumers the way the header comment on this file
       requires. `firstIndicator` is the same lookup scan()/migrate() use a few lines below
       this function to find the value they would report or relocate; asking it here means
       the allowlist is checked against the exact value that would otherwise surface, not
       against the object's other fields. */
    var candidate = firstIndicator(obj);
    if (candidate && candidate.type === null &&
        Object.prototype.hasOwnProperty.call(NON_IDENTIFYING, candidate.value)) {
      if (exemptions) {
        exemptions.push({ value: candidate.value, path: path,
                           reason: NON_IDENTIFYING[candidate.value] });
      }
      return null;
    }
    return 'author-marked target or victim';
  }

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
  if (actionIsBlock(obj)) return null;

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
   automated consumer would read it.

   `exemptions`, when passed, is an array this function pushes an entry onto every time the
   allowlist above suppresses what would otherwise be a strict-tier finding, so a caller can
   report what was actually exempted in a run rather than the exemption happening silently.
   Existing single-argument callers are unaffected: `exemptions` defaults to undefined, and
   `authorMarkedHuntOnly` only records into it when it is given. The return value is
   unchanged either way, still the plain array of findings it always was. */
function scan(feed, exemptions) {
  var found = [];

  function report(path, raw, host, category) {
    found.push({ path: path, value: raw, host: host, category: category });
  }

  /* Values under a bucket marking, walked at the tier the bucket carries.

     Inside a victim-tier bucket every classify()-typed value is reported, whatever its type,
     because the victim tier is a disclosure question. Inside a loose-tier bucket the network
     AND hash types are, because that tier is a blocklist question and an automated HASH
     blocklist harms a bystander's vendor binary exactly as a network blocklist harms a shared
     host (the 62-60-237-100 `known_legitimate_DO_NOT_BLOCKLIST` case). A filename, registry
     path or ASN is still not, because no blocklist either kind of consumer walks holds one.

     An OBJECT that directly holds a qualifying value is an entry and is the unit: its first
     qualifying value is reported and the object is not descended into, matching the way
     migrate() relocates the whole object. An object with no direct typed value is a container
     and is descended into, which is what lets `investigated_and_excluded: { ips: [...],
     hashes: [...] }` reach the values inside its arrays. */
  function scanBucket(node, path, tier) {
    if (node == null) return;
    if (isExemptPath(path)) return;
    if (typeof node === 'string') {
      var r = C.classify(node);
      if (!r) return;
      if (bucketActsOn(tier, r.type)) {
        report(path, node, r.value, tier === VICTIM_TIER ? VICTIM_CATEGORY : LOOSE_CATEGORY);
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(function (x) { scanBucket(x, path, tier); });
      return;
    }
    if (typeof node !== 'object') return;

    /* A per-entry marking inside a bucket still applies, and the stricter of the two wins.
       This is what keeps an UNTYPED victim identifier reachable: a stolen token id is only
       ever reported through the per-entry firstIndicator() fallback, because it does not
       classify as anything, and without this check a `victim_indicators` bucket would hide
       the very value the allowlist design exists to remove. */
    var marked = authorMarkedHuntOnly(node, exemptions, path);
    if (marked) {
      var mv = firstIndicator(node);
      var mvIsVictim = marked === 'author-marked target or victim';
      if (mv && (mvIsVictim || NETWORK_TYPES[mv.type])) {
        report(path, mv.raw, mv.value, marked);
        return;
      }
    }

    /* `action: BLOCK` on the entry takes it back out of a LOOSE bucket's reach: the author
       decided that value, and the whole subtree is ordinary again. Read AFTER the per-entry
       marking above, so a `role: VICTIM` entry is still reported even beside an
       `action: BLOCK` (victim outranks, per the header comment), and skipped for a victim
       bucket because the tier check fails. See the 79.137.192.3 co-tenant C2 in the plan. */
    if (tier !== VICTIM_TIER && actionIsBlock(node)) {
      walk(node, path, null, null);
      return;
    }

    var vals = bucketValues(node, tier);
    if (vals.length) {
      report(path, vals[0].raw, vals[0].value,
             tier === VICTIM_TIER ? VICTIM_CATEGORY : LOOSE_CATEGORY);
      return;
    }
    Object.keys(node).forEach(function (k) {
      var childTier = stricter(tier, bucketMarking(k, node[k]));
      scanBucket(node[k], path ? path + '.' + k : k, childTier);
    });
  }

  function walk(node, path, parent, key) {
    if (node == null) return;
    if (isExemptPath(path)) return;

    /* A bucket only ever starts at a NAMED container; the root (key null) never is one. */
    if (typeof key === 'string') {
      var tier = bucketMarking(key, node);
      if (tier) { scanBucket(node, path, tier); return; }
    }

    if (typeof node === 'string') {
      var r = C.classify(node);
      if (!r) return;
      var cat = U.unblockable(r.type, r.value);
      if (cat) report(path, node, r.value, cat);
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
    var marked = authorMarkedHuntOnly(node, exemptions, path);
    if (marked && !isExemptPath(path)) {
      var v = firstIndicator(node);
      var isVictim = marked === 'author-marked target or victim';
      if (v && (isVictim || NETWORK_TYPES[v.type])) {
        report(path, v.raw, v.value, marked);
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

  /* The text a bucket carries as its own marker, for a relocated BARE STRING to keep the
     reason it was set aside. Same length discipline as contextOf(): trimmed, and cut short of
     200 characters so one long warning cannot bloat every value it covers. */
  function bucketContext(node) {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return null;
    for (var i = 0; i < BUCKET_MARKER_KEYS.length; i++) {
      var v = node[BUCKET_MARKER_KEYS[i]];
      if (typeof v === 'string' && v.trim() && !C.classify(v)) {
        var t = v.trim();
        return t.length < 200 ? t : t.slice(0, 199);
      }
    }
    return null;
  }

  function bucketRecord(path, raw, value, tier, ctx, full) {
    if (seen[value]) return;
    seen[value] = true;
    var rec = { value: raw, host: value,
                category: tier === VICTIM_TIER ? VICTIM_CATEGORY : LOOSE_CATEGORY,
                context: ctx || null, was: path };
    if (full) rec.full = full;
    if (tier === VICTIM_TIER) removed.push(rec);
    else moved.push(rec);
  }

  /* The bucket counterpart of prune(), walked at the tier the bucket carries. The marking is
     inherited by the whole subtree: a victim entry object is REMOVED whole, a loose one MOVED
     whole with `category` added, and a bare string takes the {value, category, context} shape
     with the bucket's own marker text as its context. The loose tier covers the network AND
     hash types (`bucketValues`), so a vendor-binary SHA-256 under a
     `known_legitimate_DO_NOT_BLOCKLIST` bucket is MOVED, not left for a hash blocklist. An
     `action: BLOCK` entry inside a loose bucket is handed back to the ordinary prune() for its
     own subtree, so the value the author decided on is neither moved nor removed. An emptied
     container is dropped rather than left as a husk, so a bucket that lost every value goes
     with them. */
  function pruneBucket(node, path, tier, bucketCtx) {
    if (node == null) return node;
    if (isExemptPath(path)) return node;
    if (typeof node === 'string') {
      var r = C.classify(node);
      if (!r) return node;
      if (!bucketActsOn(tier, r.type)) return node;
      bucketRecord(path, node, r.value, tier, bucketCtx, null);
      return undefined;
    }
    if (Array.isArray(node)) {
      var out = [];
      node.forEach(function (x) {
        var v = pruneBucket(x, path, tier, bucketCtx);
        if (v !== undefined) out.push(v);
      });
      if (!out.length && node.length) return undefined;
      return out;
    }
    if (typeof node !== 'object') return node;

    /* Per-entry marking first, same as scanBucket(): the stricter of the two wins, and the
       untyped-victim-identifier case is only reachable here. */
    var marked = authorMarkedHuntOnly(node);
    if (marked) {
      var mv = firstIndicator(node);
      var mvIsVictim = marked === 'author-marked target or victim';
      if (mv && (mvIsVictim || NETWORK_TYPES[mv.type])) {
        bucketRecord(path, mv.raw, mv.value, mvIsVictim ? VICTIM_TIER : LOOSE_TIER,
                     contextOf(node) || bucketCtx, node);
        return undefined;
      }
    }

    /* Same precedence as scanBucket(): `action: BLOCK` hands the entry back to the ordinary
       prune() for its own subtree, but only inside a LOOSE bucket (a victim marking is a
       disclosure question and still wins). */
    if (tier !== VICTIM_TIER && actionIsBlock(node)) {
      return prune(node, path, bucketCtx, null);
    }

    var vals = bucketValues(node, tier);
    if (vals.length) {
      bucketRecord(path, vals[0].raw, vals[0].value, tier,
                   contextOf(node) || bucketCtx, node);
      return undefined;
    }

    var obj = {}, dropped = 0;
    Object.keys(node).forEach(function (key) {
      var childTier = stricter(tier, bucketMarking(key, node[key]));
      var childCtx = childTier !== tier ? (bucketContext(node[key]) || bucketCtx) : bucketCtx;
      var v = pruneBucket(node[key], path ? path + '.' + key : key, childTier, childCtx);
      if (v === undefined) { dropped++; return; }
      obj[key] = v;
    });
    if (dropped && !hasValue(obj)) return undefined;
    return obj;
  }

  function prune(node, path, ctx, key) {
    if (node == null) return node;
    if (isExemptPath(path)) return node;

    /* A bucket container is handed to pruneBucket() before any per-entry handling: the
       marking is about everything beneath the container, not about the container's own
       fields. `key` is the name the node sits under, so an ARRAY reached by a bucket key is
       diverted here too. */
    if (typeof key === 'string') {
      var bTier = bucketMarking(key, node);
      if (bTier) return pruneBucket(node, path, bTier, bucketContext(node));
    }

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
        var v = prune(x, path, ctx, null);
        if (v !== undefined) out.push(v);
      });
      return out;
    }

    if (typeof node !== 'object') return node;

    // No `exemptions` array passed here: the allowlist still suppresses a matching entry
    // (that check has no dependency on this argument), only the recording of WHICH value
    // was exempted is skipped. migrate() is the --fix path; the run-level "what was
    // exempted" report belongs to check-ioc-feeds.js's plain scan() pass, which does pass
    // one, not to a run that is already rewriting the feed.
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
      var v = prune(node[key], path ? path + '.' + key : key, myCtx, key);
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

  var out = prune(JSON.parse(JSON.stringify(feed)), '', null, null);
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

// NON_IDENTIFYING is exported for the same reason EXEMPT_TOP already was: check-ioc-feeds.js
// reads its size to report how many approved exceptions are in force, and the test suite
// needs to add a throwaway entry to prove the secondary type guard actually holds.
module.exports = { scan: scan, migrate: migrate, EXEMPT_TOP: EXEMPT_TOP,
                   authorMarkedHuntOnly: authorMarkedHuntOnly,
                   bucketMarking: bucketMarking,
                   stricter: stricter, bucketActsOn: bucketActsOn, actionIsBlock: actionIsBlock,
                   VICTIM_TIER: VICTIM_TIER, LOOSE_TIER: LOOSE_TIER,
                   NON_IDENTIFYING: NON_IDENTIFYING };
