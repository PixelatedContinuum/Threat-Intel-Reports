---
title: "Detection Rules — ShinyHunters Data Leak Site (91.215.85.22)"
date: '2026-04-17'
layout: post
permalink: /hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
thumbnail: /assets/images/cards/shinyhunters-dls-91-215-85-22-20260417.png
hide: true
---

**Campaign:** ShinyHunters-DLS-91.215.85.22-20260417<br>
**Date:** 2026-04-17<br>
**Author:** The Hunters Ledger<br>
**License:** CC BY 4.0<br>
**Reference:** https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/

---

## Detection Coverage Summary

This is a Data Leak Site / extortion infrastructure investigation — there are no malware binaries, process trees, or behavioral PCAPs. Detection content targets the artifacts a defender actually encounters: the ransom note and actor-branded taunt filenames appearing on internal file shares, web-proxy hits on the DLS's own content-directory path, PROSPERO bulletproof-hosting range enrichment, and the upstream cloud-identity compromise TTPs (Salesforce OAuth abuse, Okta MFA reset exploitation) that enabled exfiltration across 28+ confirmed victims. Coverage is scoped to indicators that retain analyst value independent of the DLS's current hosting IP or domain; the campaign's bare domain and IP atomics are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1657, T1583.001, T1485 | 0 |
| Sigma | 0 | 4 | T1657, T1485, T1528, T1213, T1566.004, T1098, T1583.003, T1090.003 | 2 |
| Suricata | 3 | 0 | T1583.001, T1657 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the actor-identity domains `shinyhunte.rs` and `pro-spero.ru`, and the DLS host IPs `91.215.85.22` and `91.215.43.200`, are transient infrastructure indicators — both pairs are already carried in [`shinyhunters-dls-91-215-85-22-20260417-iocs.json`](/ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json) rather than as standalone DNS-query or network-connection signatures (each original rule keyed solely on the bare domain or IP, and removing the literal left no behavior to detect). Block them via the feed. See Coverage Gaps for the salvage rewrites that replaced non-durable IP/domain anchors with durable content anchors instead of cutting the rules outright.

---

## YARA Rules

### Detection Rules

#### ShinyHunters DLS Ransom Note (INFORMATION.txt)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1583.001 (Acquire Infrastructure: Domains)
**Confidence:** HIGH
**Rationale:** Exact verbatim phrases from the actor-authored INFORMATION.txt ransom note, combined with .onion mirror addresses or the `pay_or_leak` path token. This wording has persisted unchanged across every analyzed dump and through three PGP key-rotation events (2020–2026) — the actor would have to rewrite their own canonical ransom note to evade it, a materially higher cost than renaming a single binary.
**False Positives:** None known — the verbatim DLS opening phrase is exclusive to ShinyHunters infrastructure. Combining it with the .onion addresses or `pay_or_leak` path eliminates any residual ambiguity.
**Blind Spots:** A full rewrite of the canonical ransom note text would evade this rule; it detects the note file itself, not the exfiltration or delivery mechanism that placed it.
**Validation:** Scan a copy of the DLS INFORMATION.txt ransom note — must match; scan an unrelated ransomware note or generic text file — must NOT match.
**Deployment:** Endpoint AV/EDR on-access scan; CASB / DLP file-content inspection on shared drives and cloud-sync folders; email attachment scanning; forensic memory/disk triage on suspected victim hosts.

```yara
/*
   Yara Rule Set
   Identifier: ShinyHunters DLS — Ransom Note and Identity Artifacts
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_ShinyHunters_RansomNote {
   meta:
      description = "Detects the ShinyHunters Data Leak Site ransom note (INFORMATION.txt) by exact opening phrase and .onion mirror references distributed in actor ransom packages; presence on an enterprise file share is a high-confidence exfiltration indicator"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/"
      date = "2026-04-17"
      family = "ShinyHunters-DLS"
      malware_type = "Extortion/DLS"
      campaign = "ShinyHunters-DLS-91.215.85.22-20260417"
      id = "cec16fca-e975-5ff5-9802-824fd6b03228"
   strings:
      $s1 = "This file has been downloaded from the ShinyHunters Data Leak Site (DLS)" ascii
      $s2 = "leaked on the ShinyHunters DLS because the victim did not pay a ransom" ascii
      $s3 = "shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd.onion" ascii
      $s4 = "shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion" ascii
      $s5 = "toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd.onion" ascii
      $s6 = "pay_or_leak" ascii
   condition:
      filesize < 500KB and
      ($s1 or $s2) and
      (1 of ($s3, $s4, $s5) or $s6)
}
```

#### ShinyHunters Taunt-Filename Naming Convention

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1485 (Data Destruction — adversary-side punitive leak)
**Confidence:** HIGH
**Rationale:** Actor-branded taunt filenames appear in 25+ of 30 DLS archives confirmed in this investigation, most recently in the 2026-04-15 fresh tranche. The rule requires the mandatory `shinyhunters` actor tag AND one of five taunt-phrase variants — a naming convention distinctive to this campaign, not a single one-off filename, so it has continued to hold across many months and dozens of independent victim dumps.
**False Positives:** None known — the compound condition requiring both a taunt-phrase token AND the `shinyhunters` actor tag is sufficiently distinctive; neither component alone is common in legitimate enterprise file naming.
**Blind Spots:** A rebrand of the taunt-phrase convention in future dumps would evade this rule; intended for filename/path-bearing artifacts (archive names, browser download history, LNK targets, directory-listing exports) rather than arbitrary file content.
**Validation:** Scan a file or forensic artifact containing one of the taunt-phrase archive names — must match; scan an unrelated archive filename — must NOT match.
**Deployment:** Endpoint AV/EDR file-name scanning; CASB alerts on cloud-sync folders and SharePoint upload events; DLP filename pattern policies; forensic triage of suspect hosts.

```yara
rule MALW_ShinyHunters_TauntFilename {
   meta:
      description = "Detects ShinyHunters actor-branded taunt filename patterns embedded in archive names and forensic file-path artifacts (browser download history, LNK targets, directory-listing exports); the naming convention has held across 25+ distinct victim-dump archives on this DLS"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/"
      date = "2026-04-17"
      family = "ShinyHunters-DLS"
      malware_type = "Extortion/DLS"
      campaign = "ShinyHunters-DLS-91.215.85.22-20260417"
      id = "b056e217-9545-585c-9439-a1c113a03b93"
   strings:
      $s1 = "shouldve_paid_the_ransom" nocase ascii wide
      $s2 = "should_have_paid_the_ransom" nocase ascii wide
      $s3 = "pay_the_ransom_next_time" nocase ascii wide
      $s4 = "didnt_pay_the_ransom" nocase ascii wide
      $s5 = "you_shouldve_paid" nocase ascii wide
      $actor = "shinyhunters" nocase ascii wide
   condition:
      filesize < 10MB and
      $actor and
      1 of ($s1, $s2, $s3, $s4, $s5)
}
```

### Hunting Rules

#### ShinyHunters Actor Identity — Domain + Collective Name

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1657 (Financial Theft / Extortion)
**Confidence:** HIGH
**Rationale:** Originally this rule also matched on any single one of four PGP fingerprints alone — a hash-style atomic that invalidates on the actor's next key rotation (2 of the 4 are already marked revoked). That branch was removed; the fingerprints remain available for exact-match lookups in the campaign IOC feed. The rule now requires the `shinyhunte.rs` domain AND the self-styled `Scattered LAPSUS$ Hunters` collective name to co-occur — a durable two-string combination — but researchers and TI platforms may legitimately collect documents containing both, so it is scoped to Hunting rather than Detection.
**False Positives:** Threat-intelligence analysts or security researchers collecting actor-identity documents for investigation purposes; add a tuning exclusion for known TI workstations or SIEM enrichment pipelines.
**Deployment:** Endpoint AV/EDR; threat-intelligence collection review; email attachment scanning for PGP key distribution messages.

```yara
rule MALW_ShinyHunters_PGP_Identity {
   meta:
      description = "Detects ShinyHunters actor-identity documents where the shinyhunte.rs domain and the self-styled 'Scattered LAPSUS$ Hunters' collective name co-occur, indicating direct contact with DLS actor identity material such as PGP key exports or signed statements; individual PGP fingerprint matching was removed since a single fingerprint invalidates on each key rotation (see the campaign IOC feed for exact-match fingerprint lookups)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/"
      date = "2026-04-17"
      family = "ShinyHunters-DLS"
      malware_type = "Extortion/DLS"
      campaign = "ShinyHunters-DLS-91.215.85.22-20260417"
      id = "6c559875-8b0e-55ff-a177-c98927430cb8"
   strings:
      $domain = "shinyhunte.rs" ascii
      $collective = "Scattered LAPSUS$ Hunters" ascii
   condition:
      filesize < 200KB and
      $domain and $collective
}
```

#### ShinyHunters Clearnet Identity Page (shinyhunte.rs HTML)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains)
**Confidence:** HIGH
**Rationale:** The shinyhunte.rs clearnet identity page carries distinctive co-occurring markers — the self-styled page title, the full PGP URL path, and the main .onion mirror address. Designed for proxy-cache review, threat-intel collection pipeline scanning, and CASB inspection of cached web content, not real-time endpoint scanning, since web crawlers and researcher browser caches produce meaningful FP volume.
**False Positives:** Web crawlers, threat-intel platforms, and browser-cached content from security researchers; scope deployment to threat-intel collection systems and proxy cache archives rather than production endpoint scanning.
**Deployment:** Threat-intel collection pipeline; proxy cache and TLS-inspection archive review; CASB web-content scanning; SOC web-browsing anomaly investigation.

```yara
rule MALW_ShinyHunters_DLS_HTML {
   meta:
      description = "Detects ShinyHunters clearnet identity page (shinyhunte.rs) HTML artifacts by page title, full PGP URL path, and .onion mirror references co-occurring in HTML content; intended for threat-intel collection review, proxy-cache hunting, and CASB alerting rather than production endpoint blocking"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/"
      date = "2026-04-17"
      family = "ShinyHunters-DLS"
      malware_type = "Extortion/DLS"
      campaign = "ShinyHunters-DLS-91.215.85.22-20260417"
      id = "ae8d24ef-9ee5-5611-9165-f27338ffde7a"
   strings:
      $s1 = "Scattered LAPSUS$ Hunters | DLS" ascii
      $s2 = "ShinyHunters Data Leak Site" ascii
      $s3 = "shinyhunte.rs/newpgp" ascii
      $s4 = "shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd" ascii
      $s5 = "/pay_or_leak/" ascii
   condition:
      filesize < 2MB and
      ($s1 or $s2) and
      1 of ($s3, $s4, $s5)
}
```

---

## Sigma Rules

### Hunting Rules

#### ShinyHunters DLS — Web Proxy Hit on DLS Content Path

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1485 (Data Destruction — adversary-side punitive leak impact)
**Confidence:** HIGH
**Rationale:** Originally OR'd this URI-path selection with a bare-host selection (`91.215.85.22` / `shinyhunte.rs`) that duplicated the atomic domain/IP indicators now retired to the feed. The host branch was removed; the rule now fires on the `/pay_or_leak/` content-directory path or the `INFORMATION.txt` ransom-note filename alone, both specific to the DLS's own web-application structure and valid even if the DLS migrates to new hosting infrastructure. `INFORMATION.txt` is a generic filename in isolation, which keeps this Hunting rather than Detection.
**False Positives:**
- Threat intelligence analysts or security researchers manually retrieving DLS content for analysis
- Automated threat-intel crawler services indexing extortion infrastructure
- A coincidentally-named `INFORMATION.txt` on an unrelated internal or third-party web application
**Deployment:** Web proxy logs (Squid, Zscaler, BlueCoat, Palo Alto); TLS-inspection proxy; CASB URL-filtering logs.

```yaml
title: ShinyHunters DLS — Web Proxy Hit on DLS Content Path
id: f9426448-3e1b-402e-8a1a-996b06c73be0
status: experimental
description: >-
  Detects HTTP proxy requests containing the ShinyHunters DLS
  content-directory path (/pay_or_leak/) or ransom-note filename
  (INFORMATION.txt). These path tokens are specific to the DLS
  web-application structure and remain valid even if the underlying
  hosting IP or domain rotates. A hit from an internal host indicates
  retrieval of ransom materials following extortion contact or active
  exfiltration confirmation by a threat actor using a compromised
  endpoint.
references:
    - https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
author: The Hunters Ledger
date: 2026-04-17
tags:
    - attack.exfiltration
    - attack.impact
    - attack.t1657
    - attack.t1485
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-uri-stem|contains:
            - '/pay_or_leak/'
            - 'INFORMATION.txt'
    condition: selection
falsepositives:
    - Threat intelligence analysts or security researchers manually retrieving DLS content for analysis
    - Automated threat-intel crawler services indexing extortion infrastructure
    - A coincidentally-named INFORMATION.txt on an unrelated internal or third-party web application
level: medium
```

#### ShinyHunters DLS — Salesforce Bulk Export OAuth App Authorization

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1528 (Steal Application Access Token), T1213 (Data from Information Repositories)
**Confidence:** MODERATE — requires Salesforce Shield / Event Monitoring to be enabled; app-name matching depends on how third-party OAuth clients are registered.
**Rationale:** The ShinyHunters 2026 campaign relied on vishing to convince helpdesk staff to authorize Salesforce bulk-export OAuth connected apps. This rule targets ConnectedApp authorization events matching DataLoader/DataExporter/DataImporter/Bulk API name patterns (native Salesforce DataLoader filtered), a durable technique-level anchor, but legitimate ETL/data-migration projects genuinely use apps with these name patterns — real, expected benign hits keep this Hunting.
**False Positives:**
- Legitimate use of Salesforce Data Loader by authorized administrators performing data migrations
- ETL pipeline integrations using Salesforce Bulk API with app names matching these patterns
**Deployment:** Salesforce Shield Event Monitoring (ConnectedApp event type); SIEM ingestion of Salesforce Event Log Files.

```yaml
title: ShinyHunters DLS — Salesforce Bulk Export OAuth App Authorization
id: 8bee360b-081a-4cf0-8448-07d7eb18d84e
status: experimental
description: >-
  Detects Salesforce OAuth connected-application authorizations
  involving DataLoader or DataExporter family app names. The
  ShinyHunters 2026 campaign used vishing to convince helpdesk to
  authorize Salesforce bulk-export OAuth apps, enabling mass CRM data
  exfiltration across 28+ confirmed victims. Targets Salesforce Shield
  Event Monitoring logs (ConnectedApp event type). Note: the native
  Salesforce DataLoader application is filtered; alerts fire on
  third-party or unrecognized DataLoader variants.
references:
    - https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
    - https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_endpoints.htm
author: The Hunters Ledger
date: 2026-04-17
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1528
    - attack.t1213
    - detection.emerging-threats
logsource:
    product: salesforce
    service: event_monitoring
detection:
    selection:
        EventType: 'ConnectedApp'
        AppName|contains:
            - 'DataLoader'
            - 'DataExporter'
            - 'DataImporter'
            - 'Bulk API'
    filter_known_good:
        AppName|contains: 'Salesforce DataLoader'
    condition: selection and not filter_known_good
falsepositives:
    - Legitimate use of Salesforce Data Loader by authorized administrators performing data migrations
    - ETL pipeline integrations using Salesforce Bulk API with app names matching these patterns
level: medium
```

#### ShinyHunters DLS — Okta MFA Factor Deactivation or Unexpected Enrollment

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1566.004 (Phishing: Spearphishing Voice), T1528 (Steal Application Access Token), T1098 (Account Manipulation)
**Confidence:** MODERATE — the individual events are common in legitimate IT operations; the detection value comes from correlating the two events by user within a time window, which standard Sigma syntax cannot express in one rule (see Coverage Gaps).
**Rationale:** As written, this rule fires on either an MFA factor deactivation OR a new factor enrollment individually — both are routine, ubiquitous IT operations with no distinguishing filter, which is genuinely broad. It is kept as a Hunting lead (not Cut) because it gives an analyst the raw material for a manual, time-windowed pivot (deactivate immediately followed by activate for the same user) that reflects the actual ShinyHunters vishing → MFA-takeover TTP — real value for a scheduled hunt, not for real-time alerting.
**False Positives:**
- Legitimate employee MFA resets followed by self-enrollment on a new device
- IT administrators assisting users with routine device replacement
- Bulk MFA enrollment during onboarding campaigns
**Deployment:** Okta System Log ingestion via SIEM; Okta System Log API polling; security data lake with Okta event stream. Run as a scheduled/manual hunt query with time-window grouping by target user ID — not for real-time alert routing.

```yaml
title: ShinyHunters DLS — Okta MFA Factor Deactivation or Unexpected Enrollment
id: ef025d6d-d54d-4db3-87b8-a255895ebafd
status: experimental
description: >-
  Detects Okta MFA factor deactivation or new factor enrollment events
  matching the ShinyHunters vishing TTP: threat actors impersonate
  employees to convince IT support to reset MFA
  (user.mfa.factor.deactivate), then enroll an actor-controlled
  authenticator device (user.mfa.factor.activate). Fires on either
  event individually — MFA resets and enrollments are routine IT
  operations, so this rule is a scoping lead for manual, time-windowed
  correlation review rather than a standalone alert. Correlate both
  event types by target user ID within a 30-minute window before
  escalating.
references:
    - https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
author: The Hunters Ledger
date: 2026-04-17
tags:
    - attack.credential-access
    - attack.persistence
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1566.004
    - attack.t1528
    - attack.t1098
    - detection.emerging-threats
logsource:
    product: okta
    service: system_log
detection:
    selection_reset:
        eventType: 'user.mfa.factor.deactivate'
    selection_enroll:
        eventType: 'user.mfa.factor.activate'
    condition: selection_reset or selection_enroll
falsepositives:
    - Legitimate employee MFA resets followed by self-enrollment on a new device
    - IT administrators assisting users with routine device replacement
    - Bulk MFA enrollment during onboarding campaigns
level: medium
```

#### ShinyHunters DLS — PROSPERO Bulletproof Hosting CIDR Range Access

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1583.003 (Acquire Infrastructure: Virtual Private Server), T1090.003 (Multi-hop Proxy)
**Confidence:** MODERATE — range-level indicator; specificity is lower than IP or domain indicators.
**Rationale:** PROSPERO AS200593 CIDR ranges are shared bulletproof-hosting infrastructure — the DLS sits on 91.215.85.22 within the first prefix, but other threat actors and unrelated services may co-tenant these ranges. This is a context-enrichment indicator for elevating alert priority when combined with other ShinyHunters IOCs, not a standalone actionable alert; `level` stays `low` as originally assessed.
**False Positives:**
- Legitimate services co-hosted on PROSPERO AS200593 — shared bulletproof hosting environment where other tenants may include unrelated or lower-risk operations
- Threat intelligence platform automated scanning of known malicious ranges
**Deployment:** Perimeter firewall / NGFW logs; network flow data (NetFlow/IPFIX); SIEM enrichment pipeline for alert triage.

```yaml
title: ShinyHunters DLS — PROSPERO Bulletproof Hosting CIDR Range Access
id: 5a0f622b-3b12-4811-a857-0eaed858017c
status: experimental
description: >-
  Detects network connections to PROSPERO AS200593 IP prefixes
  associated with ShinyHunters DLS infrastructure and co-hosted
  extortion campaigns. These CIDR blocks are bulletproof-hosting
  ranges shared by multiple threat-actor operations beyond
  ShinyHunters. A lower-fidelity, context-dependent indicator —
  enrich with destination reputation and correlate with other
  ShinyHunters indicators before actioning.
references:
    - https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
author: The Hunters Ledger
date: 2026-04-17
tags:
    - attack.command-and-control
    - attack.resource-development
    - attack.t1583.003
    - attack.t1090.003
    - detection.emerging-threats
logsource:
    product: firewall
detection:
    selection:
        DestinationIp|cidr:
            - '91.215.85.0/24'
            - '91.202.233.0/24'
            - '193.24.123.0/24'
    condition: selection
falsepositives:
    - Legitimate services co-hosted on PROSPERO AS200593 — shared bulletproof hosting environment where other tenants may include unrelated or lower-risk operations
    - Threat intelligence platform automated scanning of known malicious ranges
level: low
```

---

## Suricata Signatures

### Detection Rules

#### ShinyHunters DLS — HTTP Host Header shinyhunte.rs

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1657 (Financial Theft / Extortion)
**Confidence:** HIGH
**Rationale:** Host-header content match in the `http.host` sticky buffer with `endswith` is a durable content anchor — it is independent of the current origin IP and continues to fire if the CDN backend rotates, unlike a destination-IP match. No legitimate enterprise service uses this actor-branded identity domain.
**False Positives:** None known — the domain is actor-exclusive. Suppress by source IP for known threat-intel platform egress ranges.
**Blind Spots:** Evaded if the operator migrates off the shinyhunte.rs domain entirely; misses HTTPS traffic where only the TLS SNI is visible (covered by the companion TLS SNI rule below).
**Validation:** Replay a PCAP of an HTTP request with Host header `shinyhunte.rs` — must alert; ordinary HTTP traffic to unrelated hosts must NOT.
**Deployment:** Network IDS/IPS at perimeter (Suricata/Snort); TLS-inspection proxy with Suricata integration; NDR platforms.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL ShinyHunters DLS - HTTP Host Header shinyhunte.rs"; flow:established,to_server; http.host; content:"shinyhunte.rs"; endswith; classtype:trojan-activity; sid:9001001; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-17, reference https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/, attack_target Client_Endpoint, mitre_tactic_id TA0011, mitre_technique_id T1583.001;)
```

#### ShinyHunters DLS — TLS SNI shinyhunte.rs

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1657 (Financial Theft / Extortion)
**Confidence:** HIGH
**Rationale:** TLS SNI content match captures HTTPS connections to the same actor-identity domain where the HTTP Host header is encrypted and unavailable to the sensor. Same durability profile as the HTTP Host rule above — content-anchored, independent of origin IP.
**False Positives:** None known — the domain is actor-exclusive. Suppress by source IP for known threat-intel platform egress ranges.
**Blind Spots:** Evaded if the operator migrates off the shinyhunte.rs domain entirely; encrypted-SNI (ECH) deployments would hide the SNI value from inspection.
**Validation:** Replay a PCAP of a TLS ClientHello with SNI `shinyhunte.rs` — must alert; ordinary TLS handshakes to unrelated domains must NOT.
**Deployment:** Network IDS/IPS at perimeter (Suricata/Snort); TLS-inspection proxy with Suricata integration; NDR platforms.

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL ShinyHunters DLS - TLS SNI shinyhunte.rs"; flow:established,to_server; tls.sni; content:"shinyhunte.rs"; endswith; nocase; classtype:trojan-activity; sid:9001002; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-17, reference https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/, attack_target Client_Endpoint, mitre_tactic_id TA0011, mitre_technique_id T1583.001;)
```

#### ShinyHunters DLS — HTTP Request to DLS Content Path (pay_or_leak)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion)
**Confidence:** HIGH
**Rationale:** Originally anchored on destination IP `91.215.85.22` with a non-differentiating `http.method; content:"GET"` check — nearly all HTTP requests are GET, so the content check added no real filtering beyond the hardcoded IP (Robustness 0 as written). Salvaged by re-anchoring to the distinctive DLS content-directory URI path `/pay_or_leak/` in the `http.uri` buffer, which the actor would have to restructure their own site to change and which survives hosting-IP or domain rotation entirely. `rev` bumped to `2` to reflect the content change; `sid` preserved for feed-map continuity.
**False Positives:** None known — the path token is a distinctive multi-word string; coincidental collision with unrelated infrastructure is extremely unlikely.
**Blind Spots:** Evaded if the actor restructures the DLS URL scheme; HTTPS traffic where the URI is only visible via TLS decryption/inspection.
**Validation:** Replay a PCAP of an HTTP GET request with URI containing `/pay_or_leak/` — must alert; ordinary HTTP GET requests to unrelated paths must NOT.
**Deployment:** Perimeter IDS/IPS; network tap on internet egress; NDR platform.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL ShinyHunters DLS - HTTP Request to DLS Content Path pay_or_leak"; flow:established,to_server; http.uri; content:"/pay_or_leak/"; classtype:trojan-activity; threshold:type limit,track by_src,count 1,seconds 300; sid:9001003; rev:2; metadata:author The_Hunters_Ledger, date 2026-04-17, reference https://the-hunters-ledger.com/hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/, attack_target Client_Endpoint, mitre_tactic_id TA0040, mitre_technique_id T1657;)
```

> **Community contribution:** The `any` destination port on this rule set was suggested by [Anthony Vigil](https://www.linkedin.com/in/anthony-vigil/), who noted that because app-layer protocol keywords (`http`, `tls`) invoke Suricata's parser by protocol recognition rather than by port, pinning to `80`/`443` adds no fidelity — `any` preserves coverage if the operator migrates the DLS to a non-standard port.

---

## Tor / .onion Indicator Note

ShinyHunters operates three .onion mirrors for the DLS:

| Mirror | Status |
|---|---|
| `shnyhntww34phqoa6dcgnvps2yu7dlwzmy5lkvejwjdo6z7bmgshzayd.onion` | Active (main) |
| `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion` | Active (redirector) |
| `toolatedhs5dtr2pv6h5kdraneak5gs3sxrecqhoufc5e45edior7mqd.onion` | Decommissioned (referenced in stale ransom notes) |

**Practical detection limitations:** Standard network telemetry does not expose .onion hostnames — Tor traffic is encrypted before it leaves the client, and the .onion address is resolved inside the Tor network, not via corporate DNS. As a result:

- DNS query rules will NOT fire for .onion access; the `QueryName` field will contain the Tor guard-node domain or nothing, not the .onion address.
- Network flow data will show connections to Tor guard nodes (port 9001/9030/443), not to the .onion addresses themselves.
- Detection of Tor client activity is more reliable via process-based rules (Tor Browser, `tor.exe` execution) than via network-layer .onion matching.

The .onion addresses are included in the YARA `MALW_ShinyHunters_RansomNote` rule because they appear as plaintext strings within the INFORMATION.txt ransom note — a defender finding that file on a file share will match those strings even without Tor network visibility.

For environments where Tor client execution is prohibited, consider adding a separate Sigma rule targeting `tor.exe` or Tor Browser process creation under `category: process_creation` / `product: windows`.

---

## Coverage Gaps

**Tiering backfill — atomics routed to the IOC feed, salvage rewrites applied.** This file was re-tiered against the project's Detection/Hunting/Cut rubric. Two Sigma rules were retired as standalone detections because they matched only a bare, hardcoded domain or IP with no behavioral context — both indicators are already present in [`shinyhunters-dls-91-215-85-22-20260417-iocs.json`](/ioc-feeds/shinyhunters-dls-91-215-85-22-20260417-iocs.json) and should be blocked via the feed rather than alerted on as a standalone rule:

- **DNS Query for Actor-Controlled Domains** — matched only `QueryName|endswith` for `shinyhunte.rs` / `pro-spero.ru`, a bare-domain selector with no additional log-source context. Already carried in the feed (`network_indicators.domains`).
- **Outbound Connection to DLS IP Infrastructure** — matched only `DestinationIp` for `91.215.85.22` / `91.215.43.200`, a bare-IP selector. Already carried in the feed (`network_indicators.ipv4`).

Three rules were salvaged rather than cut, re-anchoring away from a non-durable atomic onto a durable, campaign-specific artifact:

- **YARA `MALW_ShinyHunters_PGP_Identity`** originally matched on any single one of four PGP fingerprints alone (a hash-style atomic — each fingerprint invalidates on the actor's next key rotation, and 2 of the 4 are already marked revoked). The fingerprint-alone branch was removed; the fingerprints remain available for exact-match lookups in the feed (`identity_artifacts.pgp_fingerprints`). The rule now requires the `shinyhunte.rs` domain AND the `Scattered LAPSUS$ Hunters` collective name to co-occur — a durable content combination — moving from a mixed-confidence rule to a clean Hunting-tier signal.
- **Sigma "Web Proxy Hit on DLS Content Path"** originally OR'd a durable URI-path selection (`/pay_or_leak/`, `INFORMATION.txt`) with a bare-host selection (`91.215.85.22`, `shinyhunte.rs`) that duplicated the two retired atomic rules above. The host branch was removed; the rule now fires on the path tokens alone, which remain valid even if the DLS migrates to new hosting infrastructure.
- **Suricata sid:9001003** originally keyed on destination IP `91.215.85.22` with an `http.method; content:"GET"` check that added no real filtering (nearly all HTTP requests are GET). Re-anchored to the `/pay_or_leak/` URI path in the `http.uri` buffer, which survives IP and domain rotation. `rev` bumped to `2` to reflect the content change; `sid` preserved for feed-map continuity.

The remaining findings below are unchanged from the original analysis and describe technique coverage that could not be expressed as a rule with available evidence.

| Technique | Gap Description | Evidence Needed to Close |
|---|---|---|
| T1195.002 — Supply Chain Compromise (Trivy) | The Trivy/TeamPCP supply-chain vector enabling the europa.zip (European Commission) exfiltration has MODERATE confidence attribution. No YARA or Sigma rule was written for this because the behavioral fingerprint of the Trivy exploit itself is not documented in available analysis. | Forensic artifacts from the Trivy compromise path (malicious Trivy plugin or CI/CD runner logs) would enable a rule targeting the specific exploit behavior. |
| T1567.002 — Exfiltration Over Web Service (cloud storage) | The exfiltration stage (actor moving data from victim Salesforce/SharePoint to actor-controlled cloud storage) leaves behavioral traces in CASB and cloud access logs but no specific destination domains or storage buckets were identified in this investigation. | Destination cloud storage provider details, S3 bucket names, or exfil-tool process artifacts would enable a Sigma rule targeting the staging/exfil step. |
| T1566.004 — Vishing campaign infrastructure | The vishing calls use standard telephony infrastructure (PSTN, VoIP spoofing). No technical artifact from the vishing calls themselves is available for rule-based detection. | Call metadata correlation between helpdesk ticket creation timestamps and incoming calls from specific area codes or VoIP providers would require telephony log integration outside standard SIEM scope. |
| Okta temporal correlation | The Okta MFA Hunting rule fires on individual events (deactivate OR activate) — this single-event breadth is the specific reason the rule is tiered Hunting (manual/scheduled review) rather than Detection. A true time-window correlation rule requiring `user.mfa.factor.deactivate` followed by `user.mfa.factor.activate` for the same `target.id` within 30 minutes is not expressible in standard Sigma syntax. | SIEM-native correlation rules (Splunk ES correlation search, Sentinel analytics rule, Elastic detection rule with sequence support) can implement this; see the rule description for the correlation logic. |

---

## License

Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
