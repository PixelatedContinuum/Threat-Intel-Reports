'use strict';

/* Per-feed extraction for the IOC feed viewer at /ioc-feeds/<slug>/.

   STRICTLY ADDITIVE over assets/js/ioc-classify.js. That module recognises seven
   atomic types, all network or file-hash, and it also governs the public search
   index and its embargo gate. Re-implementing any part of it here would be a
   second implementation of one rule, and those drift silently: the search would
   disagree with the table about what an indicator is, and nothing would say so.

   So every value is offered to ioc-classify.js first, and only what it declines is
   considered for the three host types this module adds: path, registry, filename.
   test/ioc-table-extract.test.js pins that agreement directly.

   Why those three and not more. Sampling every leaf string the atomic classifier
   rejects, filtered to structurally indicator-shaped values:

     filename      348   agent_xworm.exe
     windows path  210   %APPDATA%\...\Startup\WinDefenderSvc.exe
     unix path     110   /etc/ld.so.preload
     registry key   63   HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
     long hex       34   a tls_jarm, a decoded ransom note, a Discord snowflake
     single token 1283   boatnet.x86, main_mpsl, and also curl and wget

   The first four are unambiguous by value pattern. The last two are not: nothing
   separates a Mirai payload name from the string "wget", and nothing separates a
   JARM fingerprint from a hex-decoded blob. Typing them would put `curl` in a feed's
   indicator table, which is worse than omitting it. They are counted as not typed
   and left to the raw JSON, because an omission the page states is honest and an
   omission it hides is not.

   Typing is by VALUE PATTERN, never by bucket name, the same rule that made the
   search index work. This corpus has `location`, `file_path`, `value_data`, `value`
   and `key` all carrying the same kinds of value. */

var C = require('../../../assets/js/ioc-classify.js');
var B = require('./benign.js');

// Fields whose contents are commentary about an indicator, never an indicator.
var PROSE_KEYS = ('context confidence notes evidence description rationale summary ' +
  'tactic technique_name technique_id log_source analyst license severity ' +
  'confidence_level campaign title purpose recommendation action priority ' +
  'direction protocol role tlp pattern query false_positive_risk').split(' ')
  .reduce(function (a, k) { a[k] = 1; return a; }, {});

/* Fields that carry a human label for the value beside them. `context`, `description`,
   `role` and `note` are unchanged from before this fix and keep first priority: an
   existing, genuinely descriptive label must not be displaced by a routine field.
   `false_positive_risk` and plural `notes` are appended as a FALLBACK, consulted only
   when none of the first four matched (absent, too long for the ordinary cap, or itself
   indicator-shaped) -- see CAVEAT_ROLE_KEYS and isBlockCaveatObject below for why. */
var ROLE_KEYS = ['context', 'description', 'role', 'note', 'false_positive_risk', 'notes'];

/* Subset of ROLE_KEYS treated as a BLOCK caveat, not an ordinary label: exempt from the
   90-char cap (mirroring NB_ROLE_MAXLEN's Infinity, so the reason is read in full rather
   than trimmed to fit a hover label) and, unlike the other ROLE_KEYS, only consulted on an
   object the author marked `action: BLOCK` (see isBlockCaveatObject below).

   Both keys are corpus-wide overloaded for purposes that have nothing to do with a
   blockable indicator's caveat. `false_positive_risk` also rates a DETECTION method's own
   noise (253 occurrences corpus-wide, only 26 of them beside a value AND an
   `action: BLOCK`) and, even restricted to that 26, is sometimes just a routine risk
   rating with no bearing on this specific value (`"false_positive_risk": "low"` on every
   entry of one feed, russian-gemini-credential-mill, where a real `context` already says
   more). Plural `notes` is widely used as an ordinary indicator description with no
   relation to blocking at all (181 occurrences, only 39 beside a value AND
   `action: BLOCK`; see e.g. ioc-feeds/PULSAR-RAT.json's `"notes": "Server hosting the
   PULSAR RAT open directory..."`, which has no `action` field at all).

   Two measured false starts, kept here as the reason for both design choices: putting
   the caveat keys FIRST and gating only on presence changed 242 rows in
   `_data/ioc_tables.yml` against an expected ~51 (the overload above); putting them
   first but action-gated still let a routine "low" rating overwrite a genuinely useful
   existing `context` on 10 rows (the shadowing above). Appending them as a low-priority
   fallback, gated on `action: BLOCK`, fixes both: the two worked examples for this task
   (165.227.175.161's `context` is 139 chars, over the ordinary cap, so it still falls
   through to `false_positive_risk`; mail.hcjs2.jlengineering.se has none of the first
   four fields at all, so it falls through to `notes`) keep working, and an existing
   short, useful label is never displaced by a routine rating. */
var CAVEAT_ROLE_KEYS = { false_positive_risk: true, notes: true };

function isBlockCaveatObject(node) {
  var action = typeof node.action === 'string' ? node.action.trim().toUpperCase() : '';
  return /^BLOCK\b/.test(action);
}

/* A bare risk rating (`low`, `NONE`, `LOW (specific operator-controlled domain)`) is a
   detection-noise score, not a defender warning, however it is spelled: `false_positive_risk`
   is corpus-authored as a rating field first, a caveat second, and a bare or rating-prefixed
   value teaches a reader nothing -- `context: low` reads as broken, not as safe-to-ignore.

   HISTORY, kept because it explains why this is shaped the way it is. The first version
   (2026-09-17) excluded any value STARTING with a rating word. Too broad: it also excluded a
   genuine warning that happens to open with one. Independent review then added a six-word
   directive list (DIRECTIVE_RX below) requiring the remainder to name an action before it would
   survive. Also too narrow, and a SECOND independent review proved it the same day: a directive
   list is exactly the failure mode CLAUDE.md names -- "a check built from an enumeration finds
   what is on the enumeration and reports clean on everything else" -- and two genuine warnings
   using words absent from the six ("...operator owns the host", "...escalate to the abuse desk
   first") were silently dropped.

   INVERTED 2026-09-18, because the two failure directions are not equally bad. Carrying a bare
   rating as if it were a caveat is cosmetic noise: a reader sees `low` and learns nothing new.
   Dropping a genuine caveat is a victim harmed, the exact outcome this whole feature exists to
   prevent. So the rule now fails toward CARRYING: `isRatingOnly()` recognises exactly three
   narrow, testable SHAPES as rating-only, and anything else -- including anything this function
   cannot classify -- is carried, never dropped. This is a shape test, not a widened word list,
   which is the actual fix for the failure mode CLAUDE.md names; DIRECTIVE_RX survives only as a
   narrower, secondary net for phrasing already seen to slip past the shape test (see below).

   The three shapes, verified against every one of the 24 real corpus occurrences (22 bare "low"
   or "NONE", one parenthetical, one comma-qualifier -- see
   test/ioc-table-extract.test.js's "isRatingOnly" tests for the exact list):
     1. Bare: the rating word and nothing else ("low", "NONE").
     2. A single parenthetical immediately after the rating word, its interior one plain,
        unpunctuated fragment under 80 characters: "LOW (specific operator-controlled domain)".
     3. A single comma immediately after the rating word, followed by ONE unpunctuated fragment
        under 80 characters: "NONE, confirmed operator-owned infrastructure".
   A second comma, a semicolon, a period, a `!`/`?`, or any separator other than a lone leading
   comma or a single wrapping parenthetical disqualifies the value from shapes 2 and 3, so it
   falls through to "not rating-only" and is carried. Verified against all four of the reviewer's
   constructed genuine warnings across both review rounds: none fits any of the three shapes
   (each either has no comma/paren separator at all, or has more than one clause-boundary mark),
   so all four are now carried.

   WHAT THIS CANNOT COVER, stated because a list-shaped check must say so (CLAUDE.md, "a
   list-shaped check is only as wide as its list"). A genuine directive using an action word
   absent from DIRECTIVE_RX, phrased as a SINGLE comma-led fragment with no further
   clause-boundary punctuation -- e.g. "LOW, escalate to the abuse desk" (one comma, one clean
   fragment, no listed directive word) -- fits shape 3 and would be wrongly excluded. Closing
   that without either a directive word list (the defect this rewrite fixes) or an actual parser
   is not possible with a regex. It is a stated residual risk, not a gap this rule claims to
   close, and it does not exist in the corpus today (checked: none of the 24 real occurrences is
   a single-comma directive fragment). */
var RATING_RX = /^(none|negligible|low|medium|moderate|high|critical)\b/i;
var DIRECTIVE_RX = /\b(notify|do\s*not|don't|never\s+block|before\s+blocking|coordinate)\b/i;

function isRatingOnly(t) {
  var m = RATING_RX.exec(t);
  if (!m) return false;
  var rest = t.slice(m[0].length).trim();
  if (rest === '') return true;                                    // bare: "low", "NONE"

  var paren = /^\(([^()]*)\)$/.exec(rest);
  if (paren) {
    var inner = paren[1];
    return inner.length > 0 && inner.length <= 80 && !/[,;.!?()]/.test(inner);
  }

  if (rest.charAt(0) === ',') {
    var frag = rest.slice(1).trim();
    return frag.length > 0 && frag.length <= 80 && !/[,;.!?()]/.test(frag);
  }

  return false;   // no bounded qualifier shape recognised -> not rating-only -> carry
}

function isRatingShaped(s) {
  var t = s.trim();
  if (DIRECTIVE_RX.test(t)) return false;   // known instruction phrasing always survives
  return isRatingOnly(t);
}

/* The never-block bucket is read a second time, separately, with its own role
   preference (2026-09-13 fix: see the run's surface-fix-plan.md). It is exempt
   from the ordinary walk below, mirroring lib/feed-hygiene.js's own
   `EXEMPT_TOP`, so a value inside it is never also counted as an ordinary row. */
var EXEMPT_TOP = { hunt_only_never_block: true };

/* Preference order for the never-block section's visible reason column.
   `false_positive_risk` first, because where present it is the most direct
   statement of why the value must not be blocked. Unlike ROLE_KEYS above, this
   list has no length cap on the field it picks (see NB_ROLE_MAXLEN): a reason
   explaining why a value cannot be blocked is meant to be read in full, not
   trimmed to fit as a hover label the way an ordinary indicator's context is. */
var NB_ROLE_KEYS = ['false_positive_risk', 'purpose', 'context', 'notes', 'note',
                     'description', 'role'];
var NB_ROLE_MAXLEN = Infinity;

var RX_REGISTRY = /^HK(LM|CU|CR|U|CC|EY_[A-Z_]+)\\/i;
var RX_WIN_PATH = /^(?:[A-Za-z]:\\|%[A-Za-z_][A-Za-z_0-9()]*%|\\\\[^\\])/;
var RX_NIX_PATH = /^\/(etc|usr|tmp|var|opt|home|root|dev|proc|bin|sbin|lib|srv|boot|mnt)\//;

/* Host types, considered only for values ioc-classify.js declined. Order matters:
   a registry key can contain backslashes that also read as a UNC prefix. */
function hostType(s) {
  if (RX_REGISTRY.test(s)) return 'registry';
  if (RX_WIN_PATH.test(s)) return 'path';
  if (RX_NIX_PATH.test(s)) return 'path';
  /* filename is NOT here. ioc-classify.js gained that type on 2026-08-19, so
     delegation already covers it and a rule here would be the second
     implementation this module exists to avoid. */
  return null;
}

var TYPE_ORDER = ['ipv4', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email',
                  'path', 'registry', 'filename'];

function typeRank(t) {
  var i = TYPE_ORDER.indexOf(t);
  return i === -1 ? TYPE_ORDER.length : i;
}

/* Runs the walk once against one root node, with its own role-label preference
   and length cap, honouring `exempt` for a top-level key the caller does not
   want descended into. Returns { rows, untyped, keys }; `keys` is the same
   `type:value` set `rows` was built from, exposed so a caller comparing two
   runs (the ordinary walk and the never-block walk) can dedupe between them
   without re-deriving the key format.

   `suppressBenign` gates the benign-value filter (8.8.8.8, github.com, and
   friends). It is correct for the ordinary walk, whose job is a searchable
   index that should not be noisy with values every network sees. It is wrong
   for the never-block walk: a value like `github.com` sitting in
   `hunt_only_never_block` is there because an analyst recorded a specific
   reason not to block it, and the whole point of the never-block section is
   to show that reason, not to re-apply the noise filter and make the value
   disappear a second time, through a different mechanism, from the one place
   meant to explain it. `summarise()` below calls this twice, with the flag
   set only for the ordinary pass. */
function runWalk(root, roleKeys, roleMaxLen, exempt, suppressBenign) {
  var byKey = {}, order = [], untyped = 0;

  function take(raw, role, roleIsCaveat) {
    if (typeof raw !== 'string') return;
    var s = raw.trim();
    if (!s || s.length > 300) return;

    var atomic = C.classify(s);
    if (atomic) {
      if (suppressBenign && B.isBenign(atomic.type, atomic.value)) return;   // 8.8.8.8 and friends
      return push(atomic.type, atomic.value, role, roleIsCaveat);
    }

    var h = hostType(s);
    if (h) return push(h, s, role, roleIsCaveat);

    /* Not typed. Only count values that plausibly wanted to be an indicator:
       a short, space-free token, or something path- or hash-shaped. Prose, which
       is most of a feed by volume, is not an omission and must not inflate the
       number the page prints. */
    if (s.length <= 120 && (s.indexOf(' ') === -1 || /[\\/]/.test(s))) untyped++;
  }

  /* The SAME value (type:value key) can appear as more than one raw JSON object -- the
     same IP on three different ports, each with its own `notes` -- and `action: BLOCK`
     plus a caveat field can be repeated on every one of them. First-wins on `byKey[k]`
     would silently drop every caveat but the first author happened to write earliest in
     the array (measured: CloudSync's 91.197.98.188 carries three distinct `notes`, one
     per port, and the pre-fix code kept only the first). So a caveat push (`roleIsCaveat`
     true) for an EXISTING key accumulates into `caveats` instead of being dropped, and
     row assembly below joins every distinct one collected, in encounter order. A
     non-caveat push for an existing key is unchanged: first wins, as before this fix. */
  function push(type, value, role, roleIsCaveat) {
    var k = type + ':' + value;
    var existing = byKey[k];
    if (!existing) {
      byKey[k] = {
        type: type, value: value, context: role || null,
        caveats: (roleIsCaveat && role) ? [role] : []
      };
      order.push(k);
      return;
    }
    if (roleIsCaveat && role && existing.caveats.indexOf(role) === -1) {
      existing.caveats.push(role);
    }
  }

  function walk(node, key, role, roleIsCaveat) {
    if (node == null) return;
    if (typeof node === 'string') {
      if (PROSE_KEYS[key]) return;
      return take(node, role, roleIsCaveat);
    }
    if (Array.isArray(node)) {
      node.forEach(function (x) { walk(x, key, role, roleIsCaveat); });
      return;
    }
    if (typeof node !== 'object') return;

    /* An object may label the value beside it. Take the first role-bearing field
       that is prose rather than an indicator, so `context: "C2 server"` becomes the
       label and `context: "1.2.3.4"` does not. */
    var myRole = role;
    var myRoleIsCaveat = roleIsCaveat;
    if (roleMaxLen === Infinity) {
      /* Never-block walk (NB_ROLE_KEYS/NB_ROLE_MAXLEN): the ORIGINAL single-preference
         loop, completely unmodified by anything below. An entry that legitimately lives
         in hunt_only_never_block never carries `action: BLOCK` (feed-hygiene.js keeps a
         BLOCK-marked value OUT of that bucket, corpus-verified: 0 of the never-block
         bucket's objects anywhere carry that action), so the ordinary-walk logic in the
         other branch could never fire here regardless; kept as a fully separate branch
         so the never-block path is provably untouched code, not just untouched by luck. */
      for (var i = 0; i < roleKeys.length; i++) {
        var rv0 = node[roleKeys[i]];
        if (typeof rv0 === 'string' && rv0.trim() && rv0.length < roleMaxLen && !C.classify(rv0)) {
          myRole = rv0.trim();
          break;
        }
      }
    } else {
      /* Ordinary walk: a plain label (context/description/role/note, same priority and
         90-char cap as always) and a BLOCK caveat (false_positive_risk/notes, gated on
         `action: BLOCK`, exempt from the cap, excluding a rating-shaped value) are found
         INDEPENDENTLY and combined, rather than one replacing the other. Fixes the
         under-coverage a fallback-only design left behind (2026-09-17 review): an object
         commonly carries both a short `role` label AND a substantive `notes` caveat (see
         e.g. radius-sync.com in opendirectory-13-140-145-210-weblogic-...json, `role:
         "Operator-owned domain"` beside `notes: "Origin 13.140.145.210 unmasked from the
         operator's own capture log..."`), and a fallback that only fires when the plain
         label is ABSENT lost the caveat on every one of those. */
      var plainRole = null;
      for (var p = 0; p < roleKeys.length; p++) {
        var pk = roleKeys[p];
        if (CAVEAT_ROLE_KEYS[pk]) continue;                 // caveat keys: see below, separately
        var pv = node[pk];
        if (typeof pv === 'string' && pv.trim() && pv.length < roleMaxLen && !C.classify(pv)) {
          plainRole = pv.trim();
          break;
        }
      }

      var caveatText = null;
      if (isBlockCaveatObject(node)) {
        for (var c = 0; c < roleKeys.length; c++) {
          var ck = roleKeys[c];
          if (!CAVEAT_ROLE_KEYS[ck]) continue;
          var cv = node[ck];
          if (typeof cv === 'string' && cv.trim() && !C.classify(cv) && !isRatingShaped(cv)) {
            caveatText = cv.trim();
            break;
          }
        }
      }

      if (caveatText) {
        myRole = plainRole ? (plainRole + ' | ' + caveatText) : caveatText;
        myRoleIsCaveat = true;
      } else if (plainRole) {
        myRole = plainRole;
        myRoleIsCaveat = false;
      }
    }
    Object.keys(node).forEach(function (k) {
      if (exempt && exempt[k]) return;
      walk(node[k], k, myRole, myRoleIsCaveat);
    });
  }

  walk(root, null, null, false);

  var rows = order.map(function (k) {
    var r = byKey[k];
    /* A caveat, if any was collected, always wins over whatever plain (non-caveat)
       context this key's context field holds -- the same priority already established
       within one object, extended across every occurrence of this value. Joined with
       " | " so multiple distinct reasons read as separate sentences, not one run-on. */
    var context = r.caveats.length ? r.caveats.join(' | ') : r.context;
    return { type: r.type, value: r.value, context: context };
  });
  // Stable order, so a regenerated page diffs cleanly rather than reshuffling.
  rows.sort(function (a, b) {
    var d = typeRank(a.type) - typeRank(b.type);
    return d !== 0 ? d : (a.value < b.value ? -1 : a.value > b.value ? 1 : 0);
  });
  return { rows: rows, untyped: untyped, keys: order.slice() };
}

/* Returns { rows, untyped, neverBlockRows }. `untyped` counts values that
   looked like they could have been an indicator and were not typed, so the
   page can state the omission.

   `neverBlockRows` is the feed's `hunt_only_never_block` bucket, walked
   separately with its own role preference (NB_ROLE_KEYS) so its reason text
   survives regardless of shape: a flat `{value, category, context}` object,
   a value nested inside a sub-array under a group-level `note` (the
   seasia-gov-exploitation-toolkit shape, which carries no `value` field of
   its own at all), or the fuller `{value, purpose, notes, ...}` shape a more
   careful relocation can leave behind. `EXEMPT_TOP` keeps this bucket out of
   the ordinary walk entirely, so a never-block value is never also an
   ordinary row by default.

   A value that still ends up in both sets (an incomplete migration, not a
   theoretical case: see revert-bad-relocations.md) is resolved toward safety:
   it is dropped from `rows` and kept in `neverBlockRows` only. A row with no
   reason text in any of NB_ROLE_KEYS renders the literal string 'No reason
   recorded in the feed' rather than a blank context, so the gap is visible
   rather than looking like a rendering bug. */
function summarise(feed) {
  var ordinary = runWalk(feed, ROLE_KEYS, 90, EXEMPT_TOP, true);

  var nbRoot = (feed && typeof feed === 'object') ? feed.hunt_only_never_block : null;
  var nb = (nbRoot != null)
    ? runWalk(nbRoot, NB_ROLE_KEYS, NB_ROLE_MAXLEN, null, false)
    : { rows: [], untyped: 0, keys: [] };

  var nbKeySet = {};
  nb.keys.forEach(function (k) { nbKeySet[k] = true; });
  var rows = ordinary.rows.filter(function (r) { return !nbKeySet[r.type + ':' + r.value]; });

  var neverBlockRows = nb.rows.map(function (r) {
    return { type: r.type, value: r.value,
             context: r.context || 'No reason recorded in the feed' };
  });

  return { rows: rows, untyped: ordinary.untyped, neverBlockRows: neverBlockRows };
}

function extract(feed) { return summarise(feed).rows; }

module.exports = {
  extract: extract, summarise: summarise, hostType: hostType,
  TYPE_ORDER: TYPE_ORDER, EXEMPT_TOP: EXEMPT_TOP,
  NB_ROLE_KEYS: NB_ROLE_KEYS
};
