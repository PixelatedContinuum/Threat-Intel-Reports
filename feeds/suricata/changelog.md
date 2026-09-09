---
title: "Suricata Feed Changelog"
layout: page
permalink: /feeds/suricata/changelog/
---

Changes to the consolidated Suricata feed at
[`/feeds/suricata/hunters-ledger.rules`](/feeds/suricata/hunters-ledger.rules),
distributed as the `suricata-update` source `the-hunters-ledger/open` under registered
SID block `3500000-3509999`.

Rules are added continuously as detections publish, and those additions are not itemised
here. **What is itemised is every rule withdrawn after publication, with the reason.** A
withdrawn SID leaving the feed silently is indistinguishable, from a subscriber's side,
from a rule that was never there. If you ever alerted on a SID listed below, this page is
how you find out what it actually matched.

Withdrawn SIDs are **not reissued**. The number stays burned so that an old alert in
anyone's archive still resolves to the right rule.

**Tier changes are itemised here too, starting with this entry.** A SID moving from
Detection to Hunting (or back) is invisible from the rules file alone: the SID, the content,
and the match all stay exactly the same, and only the `TIER:` annotation in the comment above
the rule changes. If you filter, route, or auto-close differently by tier, that difference
matters as much as a withdrawal does, and it gets the same treatment: dated, named, and
reasoned.

---

## 2026-09-09 — SIDs 3500103 and 3500104 moved Detection to Hunting

**Rules:** `THL ShinyHunters DLS - HTTP Host Header shinyhunte.rs` (SID 3500103, vault SID
9001001) and `THL ShinyHunters DLS - TLS SNI shinyhunte.rs` (SID 3500104, vault SID 9001002)
**Published:** 2026-04-17 · **Tier changed:** 2026-09-09 · **Feed:** 112 rules, unchanged
(tier reclassification only; no SID renumbered, no rule added or removed)

**If you have alerts from these SIDs, they were not false positives, and this is not a
withdrawal.** Every alert either rule produced was a real sighting of a client reaching
`shinyhunte.rs`. Nothing about the underlying match was wrong then and nothing about it is
wrong now. What changed is durability, not correctness: keep treating past alerts from these
two SIDs as genuine sightings.

Each rule's entire selective content is the domain `shinyhunte.rs` itself: `http.host;
content:"shinyhunte.rs"; endswith` for SID 3500103, `tls.sni; content:"shinyhunte.rs";
endswith; nocase` for SID 3500104. Strip that one literal from either rule and nothing else
selects on anything: no secondary content match, no header combination, no behavioral marker
to fall back on. A rule whose whole value is one domain dies silently the day the operator
abandons it, and a subscriber has no way to tell "retired rule" from "rule that just stopped
matching" from the feed alone.

A rule built entirely on one rotating indicator belongs at Hunting tier, where the feed's own
header already says what that means: "Hunting rules are BROAD by design - triage them, do not
alert blind." These two are not broad in the false-positive sense that phrase usually covers,
both carry *False Positives: None known* on their detection page and that has not changed.
They are narrow to the point of fragility, a different way a rule can fail to earn Detection
tier. If your pipeline auto-escalates, auto-suppresses, or excludes from a review queue
differently by tier, and either SID was routed on the assumption it was Detection-grade,
revisit that routing.

The domain itself has not been withdrawn or judged wrong. It remains a durable indicator in
the campaign's own
[IOC feed](/ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json), which is the right
place to match on one rotating domain: an indicator list you control the staleness policy
for, rather than a Suricata Detection-tier rule implying an evasion-resilient signature that
these two never were.

A third Suricata rule from the same campaign, SID 3500105 (`HTTP Request to DLS Content Path
pay_or_leak`), is unaffected and stays at Detection tier: it matches a URI path specific to
the leak site's own structure, not the domain, and that content anchor survives if the
operator moves the site to new infrastructure.

**This tier move is not an aging label, and the two should not be read as the same signal.**
Per the feed's own header, a rule's `date` metadata is a separate, time-based axis: as of this
writing, both SID 3500103 and SID 3500104 carry `date 2026-04-17`, under 6 months old, which
reads CURRENT on that schedule. Hunting tier here is a durability judgment made about the
rule's construction; currency is arithmetic on a date. A rule can be Hunting and CURRENT at
once, exactly as these two are, and neither one implies the other.

---

## 2026-08-21 — SID 3500029 withdrawn

**Rule:** `THL Inkognito KittenX Decommission Tombstone HTTP Response (Infrastructure Pivot Indicator)`
**Published:** 2026-05-16 · **Withdrawn:** 2026-08-21 · **Feed:** 99 rules → 98

**If you ran this rule, treat every alert it produced as a false positive.** No action is
needed beyond updating the feed, which removes it automatically.

The rule matched the three-signal combination `Server: kittenx` + status `404` +
`Content-Length: 148`, on the basis that this was an operator-deployed "decommissioned
domain" fingerprint belonging to the Inkognito fraud operator. It was published carrying
*False Positives: None known*.

That claim was never base-rate tested, and it is wrong. `kittenx` is **VKontakte's web
server banner**. Measured against a 142.7-million-document web-scan corpus:

| Signature | Observations (30d) | On VK's AS47541 |
|---|---:|---:|
| `Server: kittenx` | 7,083 | 6,844 (96.6%) |
| Full triplet (header + 404 + 148 bytes) | 84 | 83 (98.8%) |
| `404` + 148 bytes, no header | 175,432 | — |

The rule fired `$EXTERNAL_NET -> $HOME_NET` on `to_client`, so in any environment it
alerted whenever a user loaded VK-hosted content that returned a 404.

The underlying observation was real: two retired operator domains did serve exactly that
response. The inference drawn from it was not. Both were Russian-hosted and inherited a
platform default rather than carrying anything the operator chose.

**No tightening recovers the rule.** The only element doing discriminating work was the
Server header, and that header belongs to the platform. Excluding VK leaves nothing to
match, and both observed domains are long decommissioned. The rule was cut rather than
narrowed.

A companion Sigma rule (`7f1a3c8b-2d5e-4b9a-8c0f-1e6d3a7b2c4f`) was cut at the same time.
It never reached this feed, which carries Suricata only, but if you pulled it from the
detection page it had a separate and worse defect: its Server-header check had already
been dropped as unsupported in Sigma's `proxy` logsource category, leaving it selecting on
status 404 and a 148-byte body alone.

The two domains remain in the campaign
[IOC feed](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json)
as domain indicators, which is where they always belonged. The campaign's two other
operator fingerprints, the custom `X-Admin-Token` header and Yandex Webmaster ID
`98466329`, were base-rate tested in the same pass and both returned zero against a
passing control. They stand.

Full retraction, including what it costs the attribution:
[§4.6 of the Inkognito report](/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/#46-operator-fingerprint-signatures--yandexgoogle-account-control-asset-hashes-and-one-retraction).

<details markdown="1">
<summary>Why this got published, and what changed as a result</summary>

The report shipped with this listed as a stated assumption rather than a fact. Assumption
(b) held that the tombstone was operator-deployed **and not a default from a third-party
hosting platform**, and said plainly that if it were a platform default, the cross-domain
attribution weight would drop significantly. That is exactly the condition that turned out
to hold, so the assumption is now marked INVALIDATED in the report rather than deleted.

The assumption was written down and the test that would settle it was never run. Naming a
failure mode is not the same as checking for it.

What changed here as a result: a prevalence measurement is now required before any
fingerprint enters an indicator list or a published rule. The check is cheap, it returns a
denominator, and it would have caught this in about a minute. A fingerprint surviving
regeneration says nothing about how many uninvolved hosts it also matches, and that second
question is the one that decides whether a rule is publishable.

</details>
