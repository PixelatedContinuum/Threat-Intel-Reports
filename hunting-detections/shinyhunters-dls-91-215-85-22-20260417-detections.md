---
title: "Detection Rules — ShinyHunters Data Leak Site (91.215.85.22)"
date: '2026-04-17'
layout: post
permalink: /hunting-detections/shinyhunters-dls-91-215-85-22-20260417-detections/
hide: true
---

**Campaign:** ShinyHunters-DLS-91.215.85.22-20260417<br>
**Date:** 2026-04-17<br>
**Author:** The Hunters Ledger<br>
**License:** CC BY-NC 4.0<br>
**Reference:** https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 4 | T1657, T1485, T1583.001 | LOW–MEDIUM |
| Sigma | 6 | T1090.003, T1528, T1213, T1566.004, T1583.003, T1657 | LOW–MEDIUM |
| Suricata | 3 | T1090.003, T1583.001, T1657 | LOW |

**Detection philosophy for this campaign:** This is a Data Leak Site / extortion infrastructure case — there are no malware binaries, process trees, or behavioral PCAPs. Detection content targets the artifacts a defender actually encounters: ransom note files appearing on internal file shares (INFORMATION.txt), actor-branded taunt filenames in archive collections, DNS/proxy/firewall hits on actor-controlled infrastructure, and the upstream cloud-identity compromise TTPs (Salesforce OAuth abuse, Okta MFA reset exploitation) that enabled exfiltration across 28+ confirmed victims.

---

## YARA Rules

### Campaign-Level File Artifacts

<!--
    File header block (for standalone .yar extraction):

    Name: ShinyHunters DLS — Ransom Note and Identity Artifacts
    Author: The Hunters Ledger
    Date: 2026-04-17
    Identifier: ShinyHunters-DLS
    Reference: https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
    License: https://creativecommons.org/licenses/by-nc/4.0/
-->

---

**Detection Priority:** HIGH<br>
**Rationale:** Exact verbatim phrases from the actor-distributed INFORMATION.txt ransom note, combined with .onion mirror addresses. A file matching this rule on an enterprise file share is a near-certain indicator that ransom materials have been delivered — either the victim received them from the threat actor or a compromised system retrieved them from the DLS. Near-zero false-positive risk in enterprise environments.<br>
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1583.001 (Acquire Infrastructure: Domains)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — The verbatim DLS opening phrase is exclusive to ShinyHunters infrastructure. Combining it with the .onion addresses or `pay_or_leak` path eliminates any residual ambiguity.<br>
**Deployment:** Endpoint AV/EDR on-access scan; CASB / DLP file-content inspection on shared drives and cloud-sync folders; email attachment scanning; forensic memory/disk triage on suspected victim hosts.

```yara
rule MALW_ShinyHunters_RansomNote
{
    meta:
        description = "Detects ShinyHunters Data Leak Site ransom note (INFORMATION.txt) by exact opening phrase and .onion mirror references distributed in actor ransom packages; presence on an enterprise file share is a high-confidence exfiltration indicator"
        author = "The Hunters Ledger"
        date = "2026-04-17"
        reference = "https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/"
        hash_sha256 = "N/A"
        family = "ShinyHunters-DLS"

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

---

**Detection Priority:** HIGH<br>
**Rationale:** Actor-branded taunt filenames appear in 26 of 30 DLS archives confirmed in this investigation. When an archive or file bearing this naming pattern is found on an enterprise system, it provides direct evidence that ShinyHunters-attributed exfiltrated data has been received, distributed, or accessed on that host. The combination of a taunt phrase AND the `shinyhunters` token keeps FP risk minimal even against broad nocase matching.<br>
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1485 (Data Destruction — adversary-side punitive leak)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — The compound condition requiring both a taunt phrase token AND the `shinyhunters` actor tag is sufficiently distinctive. Neither component alone is common in legitimate enterprise file naming.<br>
**Deployment:** Endpoint AV/EDR file-name scanning; CASB alerts on cloud-sync folders and SharePoint upload events; DLP filename pattern policies; forensic triage of suspect hosts.

```yara
rule MALW_ShinyHunters_TauntFilename
{
    meta:
        description = "Detects ShinyHunters actor-branded taunt filename patterns embedded in archive names and file-system paths; 26 of 30 DLS archives carry this naming convention as actor branding and victim-pressure mechanism"
        author = "The Hunters Ledger"
        date = "2026-04-17"
        reference = "https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/"
        hash_sha256 = "N/A"
        family = "ShinyHunters-DLS"

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

---

**Detection Priority:** MEDIUM<br>
**Rationale:** ShinyHunters PGP fingerprints from four key-rotation events (Empire Market 2020, RaidForums 2020, December 2025 statement, current 2026 key) are distinctive actor-identity artifacts. A document bearing any of these fingerprints found on an enterprise system indicates direct contact with actor-controlled PGP infrastructure. A lower priority than the ransom note rule because researchers and threat-intel platforms may legitimately collect these documents.<br>
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1657 (Financial Theft / Extortion)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** MEDIUM — Threat intelligence analysts and security researchers may collect actor identity documents for investigation purposes. Add a tuning exclusion for known TI workstations or SIEM enrichment pipelines.<br>
**Deployment:** Endpoint AV/EDR; threat-intelligence collection review; email attachment scanning for PGP key distribution messages.

```yara
rule MALW_ShinyHunters_PGP_Identity
{
    meta:
        description = "Detects ShinyHunters actor identity documents by known PGP key fingerprints published on shinyhunte.rs across three key-rotation events (2020 Empire, 2020 RaidForums, 2025-12, 2026 current); presence on an enterprise endpoint indicates direct contact with DLS actor infrastructure"
        author = "The Hunters Ledger"
        date = "2026-04-17"
        reference = "https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/"
        hash_sha256 = "N/A"
        family = "ShinyHunters-DLS"

    strings:
        $s1 = "F4953411767DE71BEDCDABCB76F4E26F7A20978A" ascii
        $s2 = "1FC4D0B1DEE914BB05B57FABF1F1B98A51C989B3" ascii
        $s3 = "828537C15F43F135A8317153CD16A1660CC7CE51" ascii
        $s4 = "E80C1308A09EC1ADC418C3F02578988F69BCA3FC" ascii
        $s5 = "shinyhunte.rs" ascii
        $s6 = "Scattered LAPSUS$ Hunters" ascii

    condition:
        filesize < 200KB and
        (1 of ($s1, $s2, $s3, $s4) or ($s5 and $s6))
}
```

---

**Detection Priority:** MEDIUM<br>
**Rationale:** The shinyhunte.rs clearnet identity page carries distinctive co-occurring markers: the self-styled page title (`Scattered LAPSUS$ Hunters | DLS` confirmed in 2025-10-12 archive.org snapshot), the full PGP URL path, and the main .onion mirror address. This rule is designed for proxy-cache review, threat-intel collection pipeline scanning, and CASB inspection of cached web content — not real-time endpoint scanning.<br>
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** MEDIUM — Web crawlers, threat-intel platforms, and browser-cached content from security researchers may trigger this rule. Scope deployment to threat-intel collection systems and proxy cache archives rather than production endpoint scanning.<br>
**Deployment:** Threat-intel collection pipeline; proxy cache and TLS-inspection archive review; CASB web-content scanning; SOC web-browsing anomaly investigation.

```yara
rule MALW_ShinyHunters_DLS_HTML
{
    meta:
        description = "Detects ShinyHunters clearnet identity page (shinyhunte.rs) HTML artifacts by page title, full PGP URL path, and .onion mirror references co-occurring in HTML content; intended for threat-intel collection review, proxy-cache hunting, and CASB alerting"
        author = "The Hunters Ledger"
        date = "2026-04-17"
        reference = "https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/"
        hash_sha256 = "N/A"
        family = "ShinyHunters-DLS"

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

### Campaign-Level Network and Identity Indicators

---

**Detection Priority:** HIGH<br>
**Rationale:** Any DNS query to `shinyhunte.rs` or `pro-spero.ru` from a managed enterprise endpoint is a strong indicator of direct contact with ShinyHunters-controlled infrastructure. `shinyhunte.rs` is the actor identity domain; `pro-spero.ru` is associated with the PROSPERO bulletproof hosting operator. Neither domain serves legitimate enterprise traffic.<br>
**ATT&CK Coverage:** T1090.003 (Multi-hop Proxy), T1583.001 (Acquire Infrastructure: Domains)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — In enterprise environments, no business-legitimate service uses these domains. Expected FP sources are TI platform crawlers and authorized security researcher workstations — both easily suppressed by allowlist.<br>
**Deployment:** Sysmon Event ID 22 (DNS query) via SIEM; DNS server query logs; EDR DNS telemetry.

```yaml
title: ShinyHunters DLS — DNS Query for Actor-Controlled Domains
id: a1b2c3d4-e5f6-4890-abcd-ef1234567890
status: experimental
description: Detects DNS queries from enterprise endpoints to ShinyHunters-controlled clearnet domains (shinyhunte.rs, pro-spero.ru). A query originating from a managed endpoint indicates direct contact with extortion actor infrastructure — either a victim system retrieving ransom materials or a compromised host beacon-checking actor domains.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.command-and-control
    - attack.exfiltration
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'shinyhunte.rs'
            - 'pro-spero.ru'
    condition: selection
falsepositives:
    - Threat intelligence platforms performing automated domain lookups
    - Security researchers conducting active investigation of ShinyHunters infrastructure
    - Honeypot or sandbox environments conducting threat-intel crawling
level: high
```

---

**Detection Priority:** HIGH<br>
**Rationale:** Direct outbound connections from managed endpoints to 91.215.85.22 (DLS host) or 91.215.43.200 (shinyhunte.rs identity host) are unambiguous signals. No legitimate enterprise software connects to these IPs. A connection indicates a user or automated process is accessing the DLS directly — either to view ransom materials, confirm exfiltration, or as part of a threat actor's operational check.<br>
**ATT&CK Coverage:** T1090.003 (Multi-hop Proxy), T1657 (Financial Theft / Extortion)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — Direct IP connections to these hosts have no legitimate enterprise use case. Security researcher and TI platform exceptions should be allowlisted by source IP.<br>
**Deployment:** Sysmon Event ID 3 (network connection) via SIEM; EDR telemetry; host-based firewall logs.

```yaml
title: ShinyHunters DLS — Outbound Connection to DLS IP Infrastructure
id: b2c3d4e5-f6a7-4901-bcde-f12345678901
status: experimental
description: Detects outbound network connections from managed endpoints to ShinyHunters Data Leak Site IP infrastructure. 91.215.85.22 hosts the clearnet DLS directory; 91.215.43.200 hosts the shinyhunte.rs actor-identity page. A direct connection from a managed endpoint to either IP warrants immediate investigation as a possible exfiltration indicator or ransom-material retrieval.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.command-and-control
    - attack.exfiltration
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '91.215.85.22'
            - '91.215.43.200'
    condition: selection
falsepositives:
    - Threat intelligence platforms performing automated scanning of known threat infrastructure
    - Security researchers actively pivoting on ShinyHunters infrastructure
level: high
```

---

**Detection Priority:** HIGH<br>
**Rationale:** The URL paths `/pay_or_leak/` and `INFORMATION.txt` are exclusive to ShinyHunters extortion infrastructure. An enterprise proxy log showing an internal host requesting either of these paths — on any host — confirms that ransom materials are being retrieved. This is the highest-fidelity network-layer indicator available for this campaign because the path tokens have no overlap with legitimate web services.<br>
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1485 (adversary-side punitive leak impact)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — The URL paths are actor-specific. The `INFORMATION.txt` path alone could match other contexts; the OR condition with `selection_host` anchors to actor-controlled hosts in that branch. Consider tuning to `selection_path AND selection_host` for an even-lower FP variant at the cost of slightly reduced coverage.<br>
**Deployment:** Web proxy logs (Squid, Zscaler, BlueCoat, Palo Alto); TLS-inspection proxy; CASB URL-filtering logs.

```yaml
title: ShinyHunters DLS — Web Proxy Hit on DLS URL Paths
id: c3d4e5f6-a7b8-4012-cdef-123456789012
status: experimental
description: Detects HTTP proxy requests to ShinyHunters DLS URL paths (/pay_or_leak/ directory or INFORMATION.txt ransom note). These paths are exclusive to the ShinyHunters extortion infrastructure at 91.215.85.22 and shinyhunte.rs. A hit from an internal host indicates retrieval of ransom materials following extortion contact or active exfiltration confirmation by a threat actor using a compromised endpoint.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.exfiltration
    - attack.impact
logsource:
    category: proxy
detection:
    selection_path:
        cs-uri-stem|contains:
            - '/pay_or_leak/'
            - 'INFORMATION.txt'
    selection_host:
        cs-host|contains:
            - '91.215.85.22'
            - 'shinyhunte.rs'
    condition: selection_path or selection_host
falsepositives:
    - Threat intelligence analysts or security researchers manually retrieving DLS content for analysis
    - Automated threat-intel crawler services indexing extortion infrastructure
level: high
```

---

**Detection Priority:** MEDIUM<br>
**Rationale:** The ShinyHunters 2026 campaign relied heavily on convincing helpdesk staff — via vishing — to authorize Salesforce bulk-export OAuth connected apps on behalf of threat actors. This rule targets Salesforce Shield / Event Monitoring logs for ConnectedApp authorization events involving DataLoader, DataExporter, DataImporter, or Bulk API app name patterns. The native Salesforce DataLoader is filtered; alerts on unrecognized variants warrant investigation. This is a published detection pattern for the 2026 campaign cluster.<br>
**ATT&CK Coverage:** T1528 (Steal Application Access Token), T1213 (Data from Information Repositories)<br>
**Confidence:** MODERATE — Requires Salesforce Shield / Event Monitoring to be enabled; app name matching depends on how third-party OAuth clients are registered.<br>
**False Positive Risk:** MEDIUM — Legitimate ETL pipelines and data migration projects may use apps with these name patterns. Enrich alerts with user account context and authorization geo-IP before escalating. Maintain an allowlist of known-good OAuth app IDs.<br>
**Deployment:** Salesforce Shield Event Monitoring (ConnectedApp event type); SIEM ingestion of Salesforce Event Log Files.

```yaml
title: ShinyHunters DLS — Salesforce Bulk Export OAuth App Authorization
id: d4e5f6a7-b8c9-4123-defa-234567890123
status: experimental
description: Detects Salesforce OAuth connected application authorizations involving DataLoader or DataExporter family app names. The ShinyHunters 2026 campaign used vishing to convince helpdesk to authorize Salesforce bulk-export OAuth apps, enabling mass CRM data exfiltration across 28+ confirmed victims. This rule targets Salesforce Shield Event Monitoring logs (ConnectedApp event type). Note — the Salesforce native DataLoader application is filtered; alerts will fire on third-party or unrecognized DataLoader variants.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
    - https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_endpoints.htm
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.credential-access
    - attack.collection
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
        AppName|contains:
            - 'Salesforce DataLoader'
    condition: selection and not filter_known_good
falsepositives:
    - Legitimate use of Salesforce Data Loader by authorized administrators performing data migrations
    - ETL pipeline integrations using Salesforce Bulk API with app names matching these patterns
level: medium
```

---

**Detection Priority:** MEDIUM<br>
**Rationale:** ShinyHunters actors used vishing to convince IT helpdesk staff to reset MFA for targeted employee accounts, then immediately enrolled actor-controlled authenticator devices (Okta `user.mfa.factor.deactivate` followed by `user.mfa.factor.activate`). This rule fires on either event individually to prevent misses. For maximum fidelity, implement SIEM correlation: group both event types by target user ID within a 30-minute window. A deactivation without re-enrollment or enrollment without a preceding reset are both worth investigating independently as anomalies.<br>
**ATT&CK Coverage:** T1566.004 (Phishing: Spearphishing Voice), T1528 (Steal Application Access Token), T1098 (Account Manipulation)<br>
**Confidence:** MODERATE — The individual events (MFA reset, MFA enroll) are common in legitimate IT operations; the detection value comes from correlation of the two events by user within a time window, which this rule surfaces the raw material for.<br>
**False Positive Risk:** MEDIUM — Legitimate MFA resets and device enrollments are routine IT operations. Alert volume will be elevated without temporal correlation. Implement SIEM time-window grouping by target user ID to suppress benign occurrences.<br>
**Deployment:** Okta System Log ingestion via SIEM; Okta System Log API polling; security data lake with Okta event stream.

```yaml
title: ShinyHunters DLS — Okta MFA Factor Deactivation or Unexpected Enrollment
id: e5f6a7b8-c9d0-4234-efab-345678901234
status: experimental
description: Detects Okta MFA factor deactivation or new factor enrollment events that match the ShinyHunters vishing TTP. Threat actors impersonate employees to convince IT support to reset MFA (user.mfa.factor.deactivate), then immediately enroll an actor-controlled authenticator device (user.mfa.factor.activate). For maximum fidelity, correlate these two event types by target user ID within a 30-minute window in your SIEM — this rule fires on either event individually to ensure coverage.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.credential-access
    - attack.persistence
    - attack.initial-access
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

---

**Detection Priority:** LOW<br>
**Rationale:** PROSPERO AS200593 CIDR ranges (91.215.85.0/24, 91.202.233.0/24, 193.24.123.0/24) are shared bulletproof hosting infrastructure. The ShinyHunters DLS sits on 91.215.85.22 within the first prefix, but other threat actors and unrelated services may co-tenant these ranges. This is a context-enrichment indicator best used to elevate alert priority when combined with other ShinyHunters IOCs, not as a standalone actionable alert.<br>
**ATT&CK Coverage:** T1583.003 (Acquire Infrastructure: Virtual Private Server), T1090.003 (Multi-hop Proxy)<br>
**Confidence:** MODERATE — Range-level indicator; specificity is lower than IP or domain indicators.<br>
**False Positive Risk:** HIGH as standalone — Shared BPH environment. Use as a corroboration signal alongside Rule 1 (DNS) or Rule 2 (IP) hits, not as a primary alert. Tune to `level: informational` in noisy environments.<br>
**Deployment:** Perimeter firewall / NGF logs; network flow data (NetFlow/IPFIX); SIEM enrichment pipeline for alert triage.

```yaml
title: ShinyHunters DLS — PROSPERO Bulletproof Hosting CIDR Range Access
id: f6a7b8c9-d0e1-4345-fabc-456789012345
status: experimental
description: Detects network connections to PROSPERO AS200593 IP prefixes associated with ShinyHunters DLS infrastructure and co-hosted extortion campaigns. These CIDR blocks are bulletproof hosting ranges and have been observed hosting multiple threat actor operations beyond ShinyHunters. This is a lower-fidelity, context-dependent indicator — enrich with destination reputation and correlate with other ShinyHunters indicators before actioning.
references:
    - https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/
author: The Hunters Ledger
date: 2026/04/17
tags:
    - attack.command-and-control
    - attack.resource-development
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

### Campaign-Level Network Signatures

---

**Detection Priority:** HIGH<br>
**Rationale:** HTTP Host header match to `shinyhunte.rs` captures clearnet identity page access over HTTP; TLS SNI match captures HTTPS connections where the Host header is encrypted. Both indicate a client on the monitored network is reaching the ShinyHunters actor-identity infrastructure. No legitimate enterprise service uses this domain.<br>
**ATT&CK Coverage:** T1583.001 (Acquire Infrastructure: Domains), T1657 (Financial Theft / Extortion)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — Domain is actor-exclusive. The SNI/Host match is exact. Suppress by source IP for known TI platform egress ranges.<br>
**Deployment:** Network IDS/IPS at perimeter (Suricata/Snort); TLS-inspection proxy with Suricata integration; NDR platforms.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"THL ShinyHunters DLS - HTTP Host Header shinyhunte.rs";
    flow:established,to_server;
    http.host;
    content:"shinyhunte.rs";
    endswith;
    nocase;
    classtype:trojan-activity;
    sid:9001001;
    rev:1;
    metadata:author "The Hunters Ledger",
              reference https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/,
              created_at 2026-04-17,
              attack_target Client_Endpoint,
              mitre_tactic_id TA0011,
              mitre_technique_id T1583.001;
)

alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"THL ShinyHunters DLS - TLS SNI shinyhunte.rs";
    flow:established,to_server;
    tls.sni;
    content:"shinyhunte.rs";
    endswith;
    nocase;
    classtype:trojan-activity;
    sid:9001002;
    rev:1;
    metadata:author "The Hunters Ledger",
              reference https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/,
              created_at 2026-04-17,
              attack_target Client_Endpoint,
              mitre_tactic_id TA0011,
              mitre_technique_id T1583.001;
)
```

---

**Detection Priority:** HIGH<br>
**Rationale:** Direct HTTP connections to 91.215.85.22 are unambiguous DLS access attempts. The DLS is currently served on port 80, but the rule deliberately matches any destination port — the `http` protocol keyword invokes Suricata's HTTP parser by protocol recognition, not by port, so pinning to `80` would add no fidelity while blocking the rule from catching an operator-side port migration (for example, if the DLS is moved to 8080/8888 to evade naive blocklists). The nginx autoindex misconfiguration on the server means any path request returns the file listing — a GET to `/` or `/pay_or_leak/` both constitute DLS access. The Host-header match to the IP itself (direct-IP HTTP) is a strong anomaly signal since legitimate web traffic rarely uses direct-IP HTTP to bulletproof hosting IPs.<br>
**ATT&CK Coverage:** T1657 (Financial Theft / Extortion), T1090.003 (Multi-hop Proxy)<br>
**Confidence:** HIGH<br>
**False Positive Risk:** LOW — Direct-IP HTTP connections to this specific address have no enterprise-legitimate use case. The threshold statement limits alert volume for any automated retrieval scenarios.<br>
**Deployment:** Perimeter IDS/IPS; network tap on internet egress; NDR platform.

```
alert http $HOME_NET any -> 91.215.85.22 any (
    msg:"THL ShinyHunters DLS - Direct HTTP Connection to DLS Host 91.215.85.22";
    flow:established,to_server;
    http.method;
    content:"GET";
    classtype:trojan-activity;
    threshold:type limit, track by_src, seconds 300, count 1;
    sid:9001003;
    rev:1;
    metadata:author "The Hunters Ledger",
              reference https://the-hunters-ledger.com/reports/shinyhunters-dls-91-215-85-22-20260417/,
              created_at 2026-04-17,
              attack_target Client_Endpoint,
              mitre_tactic_id TA0040,
              mitre_technique_id T1657;
)
```

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

| Technique | Gap Description | Evidence Needed to Close |
|---|---|---|
| T1195.002 — Supply Chain Compromise (Trivy) | The Trivy/TeamPCP supply-chain vector enabling the europa.zip (European Commission) exfiltration has MODERATE confidence attribution. No YARA or Sigma rule was written for this because the behavioral fingerprint of the Trivy exploit itself is not documented in available analysis. | Forensic artifacts from the Trivy compromise path (malicious Trivy plugin or CI/CD runner logs) would enable a rule targeting the specific exploit behavior. |
| T1567.002 — Exfiltration Over Web Service (cloud storage) | The exfiltration stage (actor moving data from victim Salesforce/SharePoint to actor-controlled cloud storage) leaves behavioral traces in CASB and cloud access logs but no specific destination domains or storage buckets were identified in this investigation. | Destination cloud storage provider details, S3 bucket names, or exfil-tool process artifacts would enable a Sigma rule targeting the staging/exfil step. |
| T1566.004 — Vishing campaign infrastructure | The vishing calls use standard telephony infrastructure (PSTN, VoIP spoofing). No technical artifact from the vishing calls themselves is available for rule-based detection. | Call metadata correlation between helpdesk ticket creation timestamps and incoming calls from specific area codes or VoIP providers would require telephony log integration outside standard SIEM scope. |
| Okta temporal correlation | The Okta MFA rule (Sigma Rule 5) fires on individual events. A true time-window correlation rule requiring `user.mfa.factor.deactivate` followed by `user.mfa.factor.activate` for the same `target.id` within 30 minutes is not expressible in standard Sigma syntax. | SIEM-native correlation rules (Splunk ES correlation search, Sentinel analytics rule, Elastic detection rule with sequence support) can implement this; see the rule description for the correlation logic. |

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
