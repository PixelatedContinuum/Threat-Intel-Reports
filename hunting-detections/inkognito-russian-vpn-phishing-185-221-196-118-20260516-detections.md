---
title: "Detection Rules — Inkognito Russian VPN Phishing & Brand-Impersonation Infrastructure"
date: '2026-05-16'
layout: post
permalink: /hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
thumbnail: /assets/images/cards/inkognito-russian-vpn-phishing-185-221-196-118-20260516.png
hide: true
---

**Campaign:** Inkognito-Russian-VPN-Phishing-185.221.196.118-20260516
**Date:** 2026-05-16
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/inkognito-russian-vpn-phishing-185-221-196-118-20260516/

---

## Detection Coverage Summary

> **Scope note:** Inkognito (UTA-2026-009) is a web-application fraud operation — there are no PE binaries. Detection coverage is entirely at the network, DNS, proxy, and web-content-inspection layers. YARA rules target static web assets (JS bundle, favicon SVG) scraped from the live operator infrastructure. This file does NOT duplicate Cluster A (BellaMain) or Cluster C (Rhadamanthys) detection content from the 2026-05-15 multi-cluster report.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 0 | T1036.005, T1608.005 | 1 |
| Sigma | 2 | 0 | T1566.002, T1656, T1036.005, T1583.001, T1583.004 | 5 |
| Suricata | 1 | 2 | T1583.001, T1583.004, T1071.001 | 6 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The operator's `kittenx` decommission-tombstone signature — Server header value `kittenx` (not a commodity web server) combined with a 404 status and an exact 148-byte body — confirmed on two independently retired domains (`00000xtrading.ru`, `bikaf.ru`) and durable to further infrastructure rotation (Sigma Detection + Suricata Detection).
- The wildcarded `*.inklens.ru` brand-impersonation subdomain query, re-anchored from a static 25-subdomain list to the parent zone so it now covers the operator's full (467+) and still-growing brand-impersonation inventory rather than only the subset enumerated during this investigation (Sigma Detection).
- The INK VPN JS-bundle and favicon YARA rules, re-anchored to a brand/API-string combination and a hash-or-string hybrid respectively, so both survive a routine Vite rebuild rather than depending only on one captured build's exact bytes or hash (YARA Detection).

**Atomics routed to the IOC feed:** 12 of the original file's rule-objects (1 YARA, 5 Sigma, 6 Suricata) each keyed solely on a hardcoded IP, domain, file hash, or verification-ID literal, with no behavioral qualifier surviving the literal's removal. All of these values were already present in [`inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json`](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json) from the original analysis — no feed edits were required. See Coverage Gaps for the full retirement list and reasoning.

---

## YARA Rules

> **Deployment note:** These YARA rules target static web assets served by the Inkognito operator — a JavaScript application bundle and an SVG favicon. They are NOT PE-targeting rules (there are no Inkognito binaries). Deploy in web-proxy DLP pipelines, threat-hunting tools that scan cached web content, or endpoint DLP systems that inspect downloaded files. Memory-scanner deployment is not applicable.

### Detection Rules

#### Inkognito INK VPN JS Bundle (Brand/API String Combination)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Resource Name or Location), T1608.005 (Stage Capabilities: Link Target)
**Confidence:** HIGH
**Rationale:** The original condition required an *exact* filesize match (`== 261587`) alongside the string combination — Vite's content-hashed build filename and exact byte count change on every rebuild, so an exact-size gate is a single-build fingerprint (Robustness 1) despite the string combination looking durable. Re-anchored to a filesize *bound* instead of exact equality; the 5-of-7 string threshold still requires 5 of the 6 non-build-specific markers (API endpoint paths, brand strings, Russian tagline) when the build-hashed filename itself doesn't match, so the rule now survives a routine rebuild rather than only the one captured build (SHA256 preserved in meta for reference).
**False Positives:** None known — the required 5-of-6 combination of operator-specific API paths (`/api/vpn-hosts`, `/api/subscriptions`), brand strings (`INK VPN`, `Inkognito`), and the Russian-language tagline is not plausible in unrelated software.
**Blind Spots:** A full rebrand that changes the API endpoint naming, both brand strings, and the tagline simultaneously would evade; the rule targets the on-disk/cached JS asset, not a memory-only variant.
**Validation:** Fetch the current INK VPN production bundle from the operator's infrastructure — must match 5 of 7; an unrelated JavaScript bundle must NOT fire.
**Deployment:** Web-proxy DLP pipeline; threat-hunting tool HTTP-response body scanning; endpoint DLP on downloaded-file content.

```yara
/*
   Yara Rule Set
   Identifier: Inkognito Fraud Operation — Web Asset Detection
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_Inkognito_JSBundle_VPN_SPA
{
    meta:
        description = "Detects the Inkognito INK VPN Vite/React SPA production JavaScript bundle via a combination of hardcoded API endpoint paths, operator brand strings, and a Russian-language tagline. Anchored on 5 of 6 non-build-specific markers so the rule survives routine Vite rebuilds (the content-hashed output filename changes every build) rather than only the exact bytes of one captured sample."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/"
        date = "2026-05-16"
        hash1 = "8a69fe67a7e9908aa1248c632ffd784033fc4dc613d0b5589279ccc62f717978"
        family = "Inkognito-FraudOperation"
        malware_type = "Web Application Fraud Infrastructure"
        campaign = "Inkognito-Russian-VPN-Phishing-185.221.196.118-20260516"
        id = "44286d43-385c-5646-afcc-1d855cb8dd6b"
    strings:
        $api_auth     = "/api/auth/login" ascii
        $api_vpn      = "/api/vpn-hosts" ascii
        $api_sub      = "/api/subscriptions" ascii
        $brand_ink    = "INK VPN" ascii
        $brand_inkogn = "Inkognito" ascii
        $bundle_name  = "index-CoeWw2zM.js" ascii
        $tagline_ru   = "\xd0\x9d\xd0\xb0\xd0\xb4\xd0\xb5\xd0\xb6\xd0\xbd\xd1\x8b\xd0\xb9 VPN \xd0\xbe\xd1\x82 Inkognito" ascii
    condition:
        filesize < 700KB and
        5 of ($api_auth, $api_vpn, $api_sub, $brand_ink, $brand_inkogn, $bundle_name, $tagline_ru)
}
```

#### Inkognito INK VPN Favicon SVG (Hash-or-Brand-String)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading: Match Legitimate Resource Name or Location)
**Confidence:** HIGH (hash branch) / MODERATE (string branch)
**Rationale:** The condition is a hash-OR-strings hybrid: the exact-hash clause alone would be Robustness 0 (a pure hash, already carried in the IOC feed), but the rule's `or` branch requires three brand markers (`Inkognito`, `INK`, `inkconnect`) simultaneously and remains functional even with the hash clause removed — so the rule as a whole survives the underlying sample changing, unlike a pure-hash rule.
**False Positives:** LOW — the three-marker AND-combination in the string branch is unlikely outside Inkognito-controlled content; the hash branch has no FP risk by construction.
**Blind Spots:** A favicon that drops all three brand markers while changing content would evade the string branch (the hash branch would also miss it, being sample-specific).
**Validation:** Scan the analyzed favicon or any modified variant retaining the three brand markers — must match; an unrelated SVG file must NOT fire.
**Deployment:** Web-proxy DLP pipeline; endpoint DLP on downloaded-file hash/content.

```yara
import "hash"

rule MALW_Inkognito_Favicon_SVG
{
    meta:
        description = "Detects the INK VPN favicon SVG (inkconnect.ru/favicon.svg) by exact SHA256 hash OR, for modified variants, by the simultaneous presence of three Inkognito brand markers in the SVG content."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/"
        date = "2026-05-16"
        hash1 = "53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70"
        family = "Inkognito-FraudOperation"
        malware_type = "Web Application Fraud Infrastructure"
        campaign = "Inkognito-Russian-VPN-Phishing-185.221.196.118-20260516"
        id = "60df7df5-6a62-58de-816b-8e7db27ba08d"
    strings:
        $svg_open     = "<svg" ascii
        $brand_inkogn = "Inkognito" ascii nocase
        $brand_ink    = "INK" ascii
        $inkconnect   = "inkconnect" ascii nocase
    condition:
        filesize < 100KB and
        $svg_open at 0 and
        (
            hash.sha256(0, filesize) == "53b3515fda56dbbd1f8071a9ef3dc3be80cb7994df22ce8afc2e79147e899b70"
            or
            ($brand_inkogn and $brand_ink and $inkconnect)
        )
}
```

---

## Sigma Rules

> **Deployment note:** Sigma rules in this section target DNS resolver logs and web-proxy logs. No Sysmon process-creation rules are included — Inkognito has no on-host malware execution surface. Translate rules to your SIEM query language using pySigma or Sigma CLI before deployment.

### Detection Rules

#### Inkognito Brand-Impersonation Subdomain DNS Query (Wildcard)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1566.002 (Phishing: Spearphishing Link), T1656 (Impersonation), T1036.005 (Masquerading)
**Confidence:** HIGH
**Rationale:** The original rule enumerated 25 specific brand-impersonation subdomains via `QueryName|contains` — a static list that could never catch the remaining 440+ subdomains in the operator's inventory, let alone future additions (Robustness 1). Re-anchored to a wildcard on the parent zone (`QueryName|endswith: '.inklens.ru'`) with a filter excluding the operator's own enumerated DevOps subdomains, so the rule now covers the entire brand-impersonation platform regardless of which specific brand name is queried — a technique-level chokepoint (the platform itself), not an enumerated list.
**False Positives:** Security researchers or threat hunters explicitly querying inklens.ru subdomains for investigation purposes; automated scanner infrastructure probing known-bad domain lists.
**Blind Spots:** Misses entirely if the operator abandons inklens.ru for a new phishing platform domain (an infrastructure-rotation event that would require a rule refresh regardless of rule design); the DevOps filter could itself be evaded if the operator names a new brand-impersonation subdomain with one of the filtered prefixes (currently no evidence of this).
**Validation:** Query any subdomain of inklens.ru (e.g., a brand-impersonation subdomain) — must match; a query for one of the filtered operator DevOps subdomains (e.g., `staging-agent.inklens.ru`) must NOT fire.
**Deployment:** Windows DNS debug logs (Event ID 5158 / DNS Analytic), Zeek dns.log, Sysmon Event ID 22, Cloudflare Gateway, Cisco Umbrella.

```yaml
title: Inkognito Brand-Impersonation Subdomain DNS Query
id: 4a7b2e1d-8f3c-4a5b-9c0d-6e2f1a8b3c7d
status: experimental
description: >-
  Detects DNS queries for any subdomain of inklens.ru, the Inkognito fraud
  operator's (UTA-2026-009) dedicated brand-impersonation phishing platform.
  The operator pre-stages 467+ subdomains targeting Wells Fargo, Tencent,
  AnyDesk, Outlook Web Access 2013, Jenkins, Asana, Tele2, and other
  enterprise/consumer brands, and adds new subdomains continuously.
  Anchored on the wildcard parent zone rather than an enumerated subdomain
  list so the rule survives new subdomain additions; a filter excludes the
  operator's own internal DevOps tooling subdomains (argo-cd, redis-commander,
  staging/uat/prod-prefixed hosts) hosted on the same zone.
references:
    - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026-05-16
tags:
    - attack.initial-access
    - attack.stealth
    - attack.t1566.002
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: dns_query
    product: windows
detection:
    selection_inklens_subdomain:
        QueryName|endswith: '.inklens.ru'
    filter_operator_devops:
        QueryName|startswith:
            - 'argo-cd.'
            - 'redis-commander.'
            - 'redisinsight.'
            - 'staging-agent.'
            - 'staging-analytic.'
            - 'uat-aka.'
            - 'uat-dashboard.'
            - 'prod-aka.'
            - 'integration-cicd.'
            - 'app-admin.'
            - 'vfemea-admin.'
    condition: selection_inklens_subdomain and not filter_operator_devops
falsepositives:
    - Security researchers or threat hunters explicitly querying inklens.ru subdomains for investigation purposes
    - Automated scanner infrastructure probing known-bad domain lists
level: high
```

#### Inkognito Operator KittenX Decommission Tombstone HTTP Response

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1583.004 (Server)
**Confidence:** HIGH
**Rationale:** The original selection included an `r-server: kittenx` field that is not a standard field for Sigma's `proxy` logsource category (W3C/Squid-derived proxy log taxonomies do not expose arbitrary response-header values as a queryable field) — a selection on a non-existent field can never match, so the clause was dead weight. Re-anchored to the two fields the proxy category does support (`sc-status`, `sc-bytes`); the exact 148-byte body size paired with a 404 status remains a reasonably distinctive combination. The full 3-signal signature (status + exact size + the highly distinctive `kittenx` Server header) is captured at the network layer by the companion Suricata rule, which can inspect headers directly.
**False Positives:** Any unrelated web server that happens to return exactly a 404 status with a 148-byte response body (uncommon); security scanners replaying captured Inkognito HTTP responses in test environments.
**Blind Spots:** Without the Server-header check, a coincidental 404/148-byte match on unrelated infrastructure cannot be distinguished at this layer alone — pair with the Suricata rule for full-fidelity confirmation.
**Validation:** Request a decommissioned Inkognito domain — the proxy log must show status 404 and a 148-byte body; an unrelated site's 404 page must NOT coincidentally match both fields.
**Deployment:** Web-proxy logs, Zeek http.log, Suricata (see companion rule for full-signature network-layer detection).

```yaml
title: Inkognito Operator KittenX Decommission Tombstone HTTP Response
id: 7f1a3c8b-2d5e-4b9a-8c0f-1e6d3a7b2c4f
status: experimental
description: >-
  Detects the Inkognito fraud operator's standard HTTP decommission
  tombstone at the proxy-log layer: an HTTP response with status 404 and
  a response body of exactly 148 bytes. Applied to retired Inkognito-
  controlled domains (observed on 00000xtrading.ru and bikaf.ru after
  decommission). The full signature also includes a distinctive Server
  header value (kittenx, not a commodity web server) — see the companion
  Suricata rule for that layer, since standard proxy-log fields do not
  expose arbitrary response headers. Any domain returning this status/size
  combination is a candidate for additional Inkognito infrastructure not
  yet linked to the known brand portfolio.
references:
    - https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/
author: The Hunters Ledger
date: 2026-05-16
tags:
    - attack.resource-development
    - attack.t1583.001
    - attack.t1583.004
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection_kittenx_response:
        sc-status: 404
        sc-bytes: 148
    condition: selection_kittenx_response
falsepositives:
    - Any unrelated web server that happens to return exactly a 404 status with a 148-byte response body
    - Security scanners replaying captured Inkognito HTTP responses in test environments
level: high
```

---

## Suricata Signatures

> **Deployment note:** All HTTP rules use the `http` application-layer keyword with destination port `any` per the workflow standard — Suricata matches by protocol recognition, not port number. Local `sid` placeholders (9001xxx) are unique within this file; the published-feed generator maps them to stable feed SIDs and is not run by this file.

### Detection Rules

#### Inkognito KittenX Decommission Tombstone HTTP Response

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1583.004 (Server)
**Confidence:** HIGH
**Rationale:** The full 3-signal signature — Server header `kittenx` (not a commodity web server, absent from any public open-source project index) combined with a 404 status and an exact 148-byte Content-Length — is a technique-level chokepoint: it is the operator's own custom tooling fingerprint, confirmed on two independently decommissioned domains, and fires regardless of which domain is being retired. This is the single highest-value pivot rule in the campaign.
**False Positives:** None known — "kittenx" is not a known commodity web server; the full triplet has not been observed outside Inkognito infrastructure.
**Blind Spots:** Evaded if the operator changes its decommission tombstone convention (a new Server header value, status, or body size); requires visibility into the HTTP response (plaintext, or TLS-inspecting proxy for HTTPS).
**Validation:** Replay a capture of a decommissioned-domain response carrying the kittenx tombstone — must alert; an unrelated server's 404 page must NOT fire.
**Deployment:** Suricata IDS/IPS at perimeter or inline network tap; Zeek complement via http.log.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL Inkognito KittenX Decommission Tombstone HTTP Response (Infrastructure Pivot Indicator)"; flow:established,to_client; http.response_line; content:"404"; http.header; content:"Server: kittenx"; nocase; content:"Content-Length: 148"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9001002; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-16, reference https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/;)
```

### Hunting Rules

#### Inkognito Custom X-Admin-Token Header in HTTP Request

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1583.004 (Server)
**Confidence:** MODERATE
**Rationale:** `X-Admin-Token` is not defined by any public RFC and is the Inkognito operator's own admin-API authentication primitive, giving it real durability (survives domain rotation) — but the header name itself could plausibly be independently invented by another developer, an acknowledged non-trivial false-positive path rather than a rare one. That combination (durable but not rare-FP) places it in Hunting rather than Detection.
**False Positives:** Internally-developed web applications that independently use X-Admin-Token as a custom auth header name; developer workstations testing API endpoints.
**Deployment:** Suricata IDS/IPS at perimeter or inline; tune to external-only traffic (exclude RFC1918 destinations) before considering promotion to alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Inkognito Custom X-Admin-Token Header in HTTP Request (Admin API Auth Primitive)"; flow:established,to_server; http.header; content:"X-Admin-Token"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9001003; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-16, reference https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/;)
```

#### Inkognito X-Admin-Token in CORS Allow-Headers Response

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1583.004 (Server)
**Confidence:** MODERATE
**Rationale:** Same underlying artifact as the request-header rule, observed instead in the CORS `Access-Control-Allow-Headers` response context — slightly more deliberate (server-controlled CORS configuration rather than any client request) but the header-name collision risk is identical, so it carries the same tier and robustness.
**False Positives:** Internally-developed web applications that independently expose X-Admin-Token in their own CORS configuration; security research or authorized assessment of Inkognito-controlled domains.
**Deployment:** Suricata IDS/IPS at perimeter; requires inline traffic inspection for HTTPS (TLS inspection or plain HTTP).

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL Inkognito X-Admin-Token in CORS Allow-Headers Response (Admin API Auth Primitive)"; flow:established,to_client; http.header; content:"Access-Control-Allow-Headers"; nocase; content:"X-Admin-Token"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9001004; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-16, reference https://the-hunters-ledger.com/hunting-detections/inkognito-russian-vpn-phishing-185-221-196-118-20260516-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (12 of the original file's 20 rule-objects).** Every rule below keyed solely on a hardcoded IP, domain, file hash, or verification-ID literal, with no behavioral qualifier surviving the literal's removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules. All underlying values were already present in [`inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json`](/ioc-feeds/inkognito-russian-vpn-phishing-185-221-196-118-20260516-iocs.json) from the original analysis — no feed edits were required.

- **YARA — `MALW_Inkognito_BrandLogo_PNG`** (1 rule). The rule's only operative condition was `hash.sha256(0, filesize) == <value>`; the PNG-magic-byte check adds no discriminating power (matches any valid PNG). Per the YARA hashes-are-IOCs workflow, a rule whose detection is only a file hash belongs in the IOC feed, not a YARA rule. The hash (`d1ae63c928fd07d51cf79c5165e4431765201ca04a2bee3c309dc00092c4de7c`) is already carried in the feed's `file_hashes.sha256` with full context.
- **Sigma — `sigma_inkognito_dns_operator_domains`** (1 rule). A 7-domain / 6-suffix OR-list (inkconnect.ru, inklens.ru, inklens.co.uk, cryptone.bot, bikaf.ru, unloki.ru, bigass.monster, 00000xtrading.ru) with no shared naming convention or technique-level invariant to re-anchor to — unlike the brand-impersonation subdomains, these are deliberately un-linked brand names, so there is no wildcard salvage path. All domains are already BLOCK-listed in the feed's `network_indicators.domains`.
- **Sigma — `sigma_inkognito_proxy_xadmintoken`** (1 rule). The original selection used `cs-headers`/`sc-headers` fields, which are not part of Sigma's standard `proxy`-category field set (W3C/Squid-derived proxy taxonomies expose connection metadata, not arbitrary header dumps) — a selection on a non-existent field can never match. The underlying signal (custom `X-Admin-Token` header) is genuinely durable and is preserved both in the feed's `operator_fingerprints.custom_http_headers` and as a Suricata Hunting-tier rule pair (network-layer header inspection is well-supported via Suricata's `http.header` sticky buffer, unlike the Sigma proxy-log field set).
- **Sigma — `sigma_inkognito_webcontent_yandex_verification`** (1 rule). Response-BODY content matching (`sc-body|contains`) is not a standard proxy-category field either — and, more fundamentally, this indicator is an OSINT infrastructure pivot (search Censys/Shodan/Google for pages carrying the Yandex Webmaster verification ID), not something enterprise DNS/proxy logs observe from victim browsing activity. This is the same category of indicator as the Google Search Console TXT records documented below and is now treated consistently with them. The verification ID (`98466329`) is preserved in the feed's `operator_fingerprints.search_console_verifications`.
- **Sigma — `sigma_inkognito_proxy_inkconnect_api_auth`** (1 rule). Removing the `r-dns|endswith: inkconnect.ru` domain anchor leaves only `cs-uri-stem|startswith: /api/auth`, which is far too generic (matches any web application's auth endpoint) to stand alone. The domain is already BLOCK-listed in the feed.
- **Sigma — `sigma_inkognito_dns_cryptone`** (1 rule). A bare single-domain `QueryName|contains: cryptone.bot` match. Already BLOCK-listed in the feed.
- **Suricata — `SIG_Inkognito_Via_Caddy_Operator_IPs`** (1 rule, SID 9001005). "Via: 1.1 Caddy" alone is common (Caddy is a widely-used legitimate reverse proxy); the rule's entire discriminating power was the 5-IP source scope (185.221.196.118, 176.124.211.174, 77.239.101.23, 193.46.56.182, 79.137.203.87), functionally equivalent to a pure IP-match rule with decorative content padding. All 5 IPs are already BLOCK-listed in the feed's `network_indicators.ipv4`.
- **Suricata — `SIG_Inkognito_TLS_SNI_Operator_Domains`** (5 rules, SIDs 9001006–9001010). Each was a bare single-domain TLS SNI match (inkconnect.ru, inklens.ru, inklens.co.uk, cryptone.bot, unloki.ru) with no additional qualifier. All 5 domains are already BLOCK-listed in the feed.

**Cut: dead-code Suricata rule (1 rule, SID 9001001 — not an atomic).** The original `SIG_Inkognito_KittenX_Tombstone_Response` section paired two alert rules intended to work together via `flowbits`: SID 9001001 matched any outbound HTTP GET request and set `flowbits:inkognito.kittenx.request` with `flowbits:noalert` (so it never itself alerts), apparently intended to gate SID 9001002's response check. However, SID 9001002 never checks `flowbits:isset,inkognito.kittenx.request` — it alerts independently on the full response signature. SID 9001001 as published therefore matched essentially all HTTP GET traffic, set a flag nothing reads, and alerted on nothing: zero detection value, so it was retired rather than kept as a broken rule. SID 9001002 (the genuine tombstone-response detection) is unaffected and remains Detection-tier.

**Resolved by this backfill: 467+ Subdomain Inventory Partial Coverage.** The original Sigma rule enumerated only the 25 highest-value brand-impersonation subdomains documented in the underlying analysis, with a documented gap noting the full operator inventory exceeds 467 and sketching a wildcard alternative. That wildcard has now been implemented as the rule itself (`Inkognito Brand-Impersonation Subdomain DNS Query`, above) — `QueryName|endswith: '.inklens.ru'` filtered against the operator's known DevOps subdomain prefixes — so this gap is closed. If DNS logging in a given environment cannot support `endswith` wildcard matching, the enumerated-list fallback covers the 25 highest-value brand names documented during the original investigation: wellsfargo, accenture, adyen-no-stripe, asana, tele2, tencent, sina, siri-search, stanley, rafael, anydesk, autodiscover.blog, owa2013, espace-client, swdcdownloads, development-jenkins, signals, connect-pro-portal, democrm, demo-insights, travel, travelid, weatherzone, e-shop, and onlineforms (all `.inklens.ru`).

### Gap: No PE/Binary YARA Rules

**Status:** Intentional — not a gap in detection methodology.

Inkognito has no PE binary samples. The operator runs a web-application stack (Vite/React SPA, nginx + Caddy reverse-proxy, EspoCRM back-office, Marzban Xray/V2Ray panel). There are no executables, DLLs, shellcode stubs, or malware droppers to write YARA binary patterns for. The two remaining YARA rules in this file target web-asset file types (JavaScript bundle, SVG) — this is the correct coverage posture for a web-application fraud operation.

**What would enable binary YARA coverage:** Discovery of a PE binary associated with the Inkognito operator (a VPN client installer, a downloader, or a credential-stealer deployed against phishing victims). None were recovered in this investigation.

### Gap: Live JARM Hash Not Recovered

**Status:** Gap — JARM fingerprinting of operator TLS stack not completed.

JARM (https://github.com/salesforce/jarm) produces a deterministic fingerprint of a TLS server's implementation from its handshake response. The Inkognito operator's nginx + Caddy stack would produce a distinctive JARM hash recoverable by active probing of the live endpoints (185.221.196.118, 176.124.211.174). A JARM hash provides a passive TLS-layer pivot for surfacing additional operator-controlled servers not linked to the known domain/IP inventory.

**What would enable JARM coverage:** Active JARM probe of operator IPs 185.221.196.118 and 176.124.211.174. Note that inklens.ru deliberately rejects non-browser TLS clients (tlsv1 alert internal error) — JARM probing of that host may return a rejection fingerprint rather than the full stack JARM. A JARM lookup on inkconnect.ru (Cloudflare-fronted) would return a Cloudflare JARM, not the operator's backend JARM.

### Gap: BEC Burn-Domain WHOIS SOA Monitoring

**Status:** Partial gap — behavioral indicator documented; automated WHOIS monitoring rule not producible in Sigma/Suricata format.

The operator's BEC burn-domain WHOIS fingerprint (`admin@<domain>.eu` SOA email on .eu domains hosted on Stark Industries AS44477/AS209847) is documented in the underlying analysis but cannot be expressed as a standard Sigma or Suricata rule because WHOIS SOA data is not captured in standard enterprise log sources (DNS logs do not include WHOIS SOA fields).

**What would enable coverage:** Integration with a WHOIS monitoring feed that can alert on new .eu domain registrations where the SOA email matches the `admin@*.eu` pattern AND the authoritative NS points to Stark Industries IP ranges (193.46.56.0/24, 77.239.101.0/24). This is a proactive threat-intel feed task, not an endpoint/network detection task.

### Gap: Search-Console / Webmaster Verification-ID Pivots (Google + Yandex)

**Status:** Gap — infrastructure pivots documented; no standard Sigma/Suricata rule type applicable.

Three operator-controlled site-verification identifiers are high-value pivots for surfacing additional operator-controlled domains where the operator verified the same account: two Google Search Console TXT records (`_Lq_FX-CDt3OmZqq5PNFfmQTZtLSHTNsVkViLTzpTwk` for inkconnect.ru, `xskfj4k4tX_-enfPvu9WrUiWauHFlbuVmyV7thcjwds` for inklens.ru) and one Yandex Webmaster HTML meta-tag verification ID (`98466329` for inklens.ru). None are observable in standard enterprise DNS or proxy logs because they are not triggered by victim browsing activity — they are third-party verification artifacts recoverable only by an active OSINT pivot against the verification provider or an internet-wide scan corpus. (The Yandex ID previously had a standalone Sigma rule attempting HTTP-response-body matching; that rule used a non-standard proxy-category field and has been retired in favor of this consistent gap treatment — see the atomics-routed-to-feed list above.)

**What would enable coverage:** SecurityTrails / Censys TXT-record and HTML-meta-tag reverse-lookup for all three verification strings. New operator domains where the same account is verified would surface as sibling infrastructure.

### Gap: CryptOne Fake Exchange — Origin IP Not Recovered

**Status:** Gap — Cloudflare-fronted origin not demasked.

The CryptOne fake exchange at cryptone.bot is fully Cloudflare-fronted with a Turnstile bot challenge. The operator's origin IP behind the Cloudflare proxy was not recovered from passive DNS history (domain registered 2026-03-02; Cloudflare fronting in place from first observation). The retired Suricata SNI rule (see atomics list above) fired on the Cloudflare edge, not the operator origin — network-layer detection at the edge is preserved via the IOC feed's domain BLOCK entry, but a direct-IP block against the true origin is not available.

**What would enable coverage:** Origin demasking via certificate transparency logs (search for TLS certificates issued to cryptone.bot before Cloudflare fronting was applied — narrow window between the 2026-03-02 registration and first Cloudflare observation), or via HTTP response header fingerprinting that Cloudflare passes through from the origin.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
