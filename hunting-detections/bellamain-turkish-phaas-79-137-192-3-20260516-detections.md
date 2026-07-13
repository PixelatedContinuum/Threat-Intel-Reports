---
title: "Detection Rules — BellaMain Turkish PhaaS Panel"
date: '2026-05-16'
layout: post
permalink: /hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
thumbnail: /assets/images/cards/bellamain-turkish-phaas-79-137-192-3-20260516.png
hide: true
---

**Campaign:** BellaMain-TurkishPhaaS-79.137.192.3
**Date:** 2026-05-16
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/bellamain-turkish-phaas-79-137-192-3-20260516/

---

## Detection Coverage Summary

> **Scope note:** All rules cover Cluster A (BellaMain Turkish PhaaS panel + 7 brand-impersonation kits) only. Cluster B (Inkognito) and Cluster C (Rhadamanthys) are covered by previously published detection sets. The evidence base is recovered PHP source code, not PE binaries — detection logic targets server-side artifacts, web-server logs, and network egress, not endpoint process injection or PE characteristics.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 0 | T1505.003, T1027.013, T1070, T1497 | 0 |
| Sigma | 1 | 4 | T1560, T1070, T1518.001, T1102.002, T1041, T1119 | 1 |
| Suricata | 0 | 1 | T1518.001 | 4 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The Wadanz author-pseudonym function pair (`sifreleWadanz`/`sifrecozWadanz`) in `database/fonk.php` — a developer-chosen code identifier that persists across any redeploy of this codebase, near-zero FP (YARA Detection).
- A PHP/web-server process spawning `mysqldump` with a plaintext `-p` password argument — a technique chokepoint independent of any single renameable literal (Sigma Detection).

**Atomics already in the IOC feed (no new entries required):** this campaign's atomic indicators — the panel IP (`79.137.192.3`), both operator domains (`cryptone.bot`, `evotoptan.com`), the obfuscated admin path (`V5VgjLU0jsDe`), and the MySQL credential set — were already present in [`bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json`](/ioc-feeds/bellamain-turkish-phaas-79-137-192-3-20260516-iocs.json) from the original analysis. Five of the original file's rules (1 Sigma, 4 Suricata) keyed solely on one of these values with no behavioral qualifier surviving the literal's removal — no new rule or feed entry was required. See Coverage Gaps for the full accounting of what changed in this pass, including a corrected two-rule Sigma correlation that replaces a rule whose original condition could never match.

---

## YARA Rules

### Detection Rules

#### BellaMain Wadanz Author Functions

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.003 (Web Shell / server-side implant), T1027.013 (Obfuscated Files or Information — custom session cipher)
**Confidence:** HIGH
**Rationale:** `sifreleWadanz`/`sifrecozWadanz` are developer-chosen compiled function names, not per-deployment configuration — they persist across any redeploy or fork of this codebase the same way a namespace root would, unless the code itself is rewritten. Requiring both names together, plus one of two co-located database strings, leaves no single renameable literal carrying the rule.
**False Positives:** None known — the Wadanz pseudonym suffix on these exact function names has not been observed in any legitimate PHP framework or library.
**Blind Spots:** A fork that renames both cipher functions (a genuine code rewrite, not a redeploy) evades this rule; the rule targets on-disk PHP source, not a runtime memory artifact.
**Validation:** Scan the analyzed panel archive or `database/fonk.php` — both function names must match; a legitimate, unrelated PHP session-handling library must NOT fire.
**Deployment:** PHP web-root scanner (ModSecurity, OSSEC file-integrity, ClamAV PHP ruleset), post-incident forensic triage of compromised web servers.

```yara
/*
   Yara Rule Set
   Identifier: BellaMain Turkish PhaaS Panel
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_BellaMain_WadanzFunctions {
   meta:
      description = "Detects BellaMain Turkish PhaaS panel PHP source files containing the author-pseudonym session-cipher function pair sifreleWadanz and sifrecozWadanz in database/fonk.php or any forked copy. The Wadanz suffix is a developer-chosen code identifier that persists across redeployments of this codebase."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
      date = "2026-05-16"
      hash1 = "f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88"
      family = "BellaMain"
      malware_type = "PhaaS Panel"
      campaign = "BellaMain-TurkishPhaaS-79.137.192.3"
      id = "d9dcf08f-9d66-5b41-a9db-57fe529d3780"
   strings:
      $func_enc = "sifreleWadanz" ascii fullword
      $func_dec = "sifrecozWadanz" ascii fullword
      $db_user  = "dbjakartaxdw" ascii fullword
      $db_name  = "jakartaxdw" ascii fullword
   condition:
      filesize < 512KB and
      $func_enc and $func_dec and
      1 of ($db_user, $db_name)
}
```

#### BellaMain Admin Panel and Evidence-Destruction Commands

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.003 (Web Shell), T1070 (Indicator Removal — evidence-destruction command context)
**Confidence:** HIGH
**Rationale:** Salvaged from the original rule, which required the obfuscated admin path `V5VgjLU0jsDe` plus the database user on every match — both are single deployment-specific literals (a redeploy of this codebase can regenerate the admin path and rotate the database credentials, per the rule's own original false-positive note that the path is randomly generated). Reworked into an OR of two branches: two or more of the Telegram-bot evidence-destruction command strings (`/hesapsil`, `/kartsil`, `/girislogsil`) — developer-chosen command-dispatch vocabulary that a redeploy does not regenerate — OR the original admin-path-plus-credential combination, which still confirms an exact copy of this deployment. The command-string branch is what carries the rule to Detection grade.
**False Positives:** None known — `/hesapsil`, `/kartsil`, and `/girislogsil` are bespoke Turkish command strings with no plausible legitimate collision, and the admin-path/credential branch is highly specific to this deployment.
**Blind Spots:** A rebuild that renames two or more of the three command strings AND regenerates the admin path/credentials evades; the rule targets on-disk PHP source, not deployed network paths.
**Validation:** Scan `manager.php` (or the analyzed kit archive) — the two-of-three command-string branch must match independent of the admin path; a legitimate, unrelated PHP application must NOT fire.
**Deployment:** PHP web-root scanner, file-integrity monitoring on web servers, forensic PHP corpus triage.

```yara
rule TOOLKIT_BellaMain_AdminPanel {
   meta:
      description = "Detects BellaMain Turkish PhaaS panel PHP source via two independent anchors: two or more of the Telegram-bot evidence-destruction command strings (/hesapsil, /kartsil, /girislogsil) hardcoded in the bot command-dispatch logic, OR the co-occurrence of the obfuscated admin directory path V5VgjLU0jsDe with the shared MySQL database user dbjakartaxdw. The command-string branch survives a redeploy that regenerates the admin path and database credentials; the second branch confirms an exact copy of this deployment."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
      date = "2026-05-16"
      hash1 = "705793c011fdfe17941700a3bf42eee0ba2ebdc04870ce19779ea528b3565fac"
      family = "BellaMain"
      malware_type = "PhaaS Panel"
      campaign = "BellaMain-TurkishPhaaS-79.137.192.3"
      id = "07c349cc-223e-5d46-a6e7-ffcfc7116f99"
   strings:
      $admin_path = "V5VgjLU0jsDe" ascii
      $db_user    = "dbjakartaxdw" ascii fullword
      $cmd_del1   = "/hesapsil" ascii fullword
      $cmd_del2   = "/kartsil" ascii fullword
      $cmd_del3   = "/girislogsil" ascii fullword
   condition:
      filesize < 512KB and
      ( 2 of ($cmd_del1, $cmd_del2, $cmd_del3) or ($admin_path and $db_user) )
}
```

#### BellaMain Anti-Researcher Canary Strings

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion — anti-researcher variant)
**Confidence:** HIGH
**Rationale:** The Turkish-language troll-response strings are hardcoded response text chosen once by the developer and shared across every kit's `girislog.php` — they persist across redeployment the same way the Wadanz functions do. Requiring 2 of 4 distinctive canary strings, plus one of two secondary markers, keeps the FP floor low even though one secondary marker (`?lg=`) is a common-looking parameter name on its own.
**False Positives:** None known against legitimate software — Turkish profanity/troll strings with this specific combination are not expected in unrelated PHP; a hit on a stored (non-actively-deployed) copy of a BellaMain kit sample is still a true positive for kit provenance, not a false positive.
**Blind Spots:** A fork that rewrites the troll-response text evades; scanning finds the code artifact regardless of whether the kit is actively deployed, so a hit does not by itself confirm live phishing activity.
**Validation:** Scan a recovered kit archive's `girislog.php` — 2 of 4 canary strings plus one secondary marker must match; unrelated PHP session-handling code must NOT fire.
**Deployment:** PHP web-root scanner, threat intel file corpus triage, malware archive scanning; apply analyst triage before treating a hit as an active-deployment indicator.

```yara
rule TOOLKIT_BellaMain_AntiResearcherCanary {
   meta:
      description = "Detects BellaMain Turkish PhaaS kit girislog.php files containing the anti-researcher canary string cluster. The ?lg= GET parameter triggers these strings, causing the kit to fire a Telegram alert with the researcher's IP and user-agent and return a Turkish-language troll response. Presence in a PHP file confirms BellaMain kit provenance regardless of active-deployment status."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
      date = "2026-05-16"
      hash1 = "219cd4f6177a2358ec7f06b230d611f47e1049fcb3e2b44d06ec410b336382b0"
      family = "BellaMain"
      malware_type = "PhaaS Kit"
      campaign = "BellaMain-TurkishPhaaS-79.137.192.3"
      id = "e107e6db-0ca3-5521-9c94-360c9ff55dce"
   strings:
      $sazan_ip    = "Sazan IP" ascii
      $sazan_kod   = "Sazan Kod" ascii
      $sazan_cihaz = "Sazan Cihaz" ascii
      $usom_msg    = "Usom Yedik Atis Stop" ascii
      $ares_alias  = "@AresRS34" ascii
      $lg_param    = "?lg=" ascii
   condition:
      filesize < 512KB and
      2 of ($sazan_ip, $sazan_kod, $sazan_cihaz, $usom_msg) and
      1 of ($ares_alias, $lg_param)
}
```

---

## Sigma Rules

### Detection Rules

#### BellaMain Mysqldump Invocation by PHP Web Process

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1560 (Archive Collected Data — mysqldump output piped to Telegram), T1070 (Indicator Removal — evidence-destruction command context)
**Confidence:** HIGH
**Rationale:** Unchanged from the original rule, which is already technique-anchored: `mysqldump` invoked by a PHP/web-server parent process with a plaintext `-p` password argument is a chokepoint behavior with no single renameable literal — a web application should never legitimately spawn a database-dump utility with credentials on the command line, regardless of how BellaMain itself is renamed or redeployed.
**False Positives:** Legitimate PHP-based database management tools (phpMyAdmin export function) invoked by an administrator; automated backup scripts incorrectly launched from web process context during provisioning or testing.
**Blind Spots:** A rebuild that pipes credentials via a file or environment variable instead of a `-p` command-line flag evades; a bespoke backup wrapper running under a web-server account could coincidentally match.
**Validation:** Trigger the malware's backup/evidence-destruction command — the mysqldump child-process event must match; a scheduled backup job running under a dedicated backup service account (not php/apache2/nginx/httpd) must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-for-Linux process-creation telemetry on PHP web servers.

```yaml
title: BellaMain PhaaS Mysqldump Invocation by PHP Web Process
id: c914e7a2-5b36-4f87-b3d8-2a1e9c047f83
status: experimental
description: >-
  Detects mysqldump invoked with a plaintext -p password argument by a PHP or
  web server parent process. BellaMain's /yedek Telegram command executes
  mysqldump via PHP shell_exec() to produce a SQL backup that is then sent to
  the operator's Telegram channel via sendDocument. Legitimate database backup
  jobs run under dedicated service accounts with credential files rather than
  plaintext -p arguments spawned from a web-server process. This combination
  of parent process (php/php-fpm/apache2/nginx) and mysqldump child with a
  -p flag is a strong behavioral indicator that does not depend on any single
  renameable literal.
references:
    - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: '2026-05-16'
tags:
    - attack.collection
    - attack.t1560
    - attack.stealth
    - attack.t1070
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|contains:
            - 'php'
            - 'apache2'
            - 'nginx'
            - 'httpd'
    selection_child:
        Image|endswith: 'mysqldump'
        CommandLine|contains: '-p'
    condition: selection_parent and selection_child
falsepositives:
    - >-
      Legitimate PHP-based database management tools (phpMyAdmin export
      function) invoked by an administrator — correlate with legitimate admin
      session timestamps and exclude known-good source IPs
    - >-
      Automated backup scripts incorrectly launched from web process context
      during provisioning or testing
level: high
```

### Hunting Rules

#### BellaMain USOM Poll, Telegram Bot Outbound, and Correlations

**Tier:** Hunting
**Robustness:** 1 (both base rules) / 2 (both correlations)
**ATT&CK Coverage:** T1518.001 (Software Discovery: Security Software), T1102.002 (Web Service: Bidirectional Communication), T1041 (Exfiltration Over C2 Channel), T1119 (Automated Collection)
**Confidence:** MODERATE
**Rationale:** Four linked rules published together in one fence because the USOM+Telegram correlation cross-references both base rules below (mirrors the AdaptixC2 beacon-cadence base+correlation co-location pattern already published in `opendirectory-45-130-148-125-20260430-detections.md`, extended here to a 4-rule cluster since one correlation depends on two independent base rules rather than one). The USOM-poll base rule flags a bare HTTP request to the USOM blocklist endpoint — common, legitimate CERT/security-tool behavior with high acknowledged FP risk on its own. The Telegram-bot base rule flags a single HTTP request to `api.telegram.org/bot*` — an unanchored, extremely common event any legitimate Telegram bot integration produces. `level` on both base rules is `low`; neither is intended as a standalone alert. The USOM+Telegram correlation replaces the original single-event rule, whose `selection_usom and selection_telegram` condition required one field (`cs-host`) to simultaneously equal two mutually exclusive values on the same log line — a condition that could never match any event — and is now a proper Sigma temporal correlation across both base rules, grouped by source IP within a 5-minute window matching the paired Suricata signature's 300-second threshold. The burst correlation adds a genuine volumetric anomaly (5+ Telegram Bot API requests in 60 seconds from one host), but its base selector does not verify the calls use distinct bot tokens — a single high-volume legitimate notification bot can trigger it identically to BellaMain's four-bot simultaneous-fire pattern, so `level` is recalibrated from the original `high` to `medium` and the pair moved from Detection to Hunting.
**False Positives:** Turkish CERT partner organizations, security researchers, or security products that legitimately poll the USOM blocklist; any web application with a legitimate Telegram bot integration (order notifications, monitoring alerts, CI/CD pipelines); a host that legitimately both monitors the USOM blocklist and operates an unrelated Telegram notification bot within the same time window; web application platforms with legitimate high-frequency Telegram notification integrations (e.g., e-commerce order-notification bots) firing on concurrent order events — tune by excluding known-legitimate source IPs.
**Deployment:** Egress proxy SIEM with time-window correlation; neither base rule is intended as a standalone alert — hunt-tune both correlations before alerting.

```yaml
title: BellaMain PhaaS USOM Blocklist Poll from Web Server
id: 7c1bb0ba-7d15-4969-a8dd-529d3b6294b9
status: experimental
description: >-
  Detects an HTTP request to the Turkish CERT USOM URL blocklist endpoint
  (www.usom.gov.tr/url-list.txt) originating from a web-server host.
  BellaMain's usmcheck.php polls this list to detect when its own phishing
  kit domains have been blocklisted, then triggers a Telegram kill-switch
  notification. Polling USOM alone is common, legitimate behavior performed
  by CERT partners and security tooling and carries high false-positive risk
  on its own — this base event is intended to feed the paired temporal
  correlation rule (BellaMain PhaaS USOM Poll and Telegram Bot Outbound
  Correlation), which raises confidence only when the same source also
  contacts the Telegram Bot API within a following time window.
references:
    - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
    - https://www.usom.gov.tr/
author: The Hunters Ledger
date: '2026-05-16'
tags:
    - attack.discovery
    - attack.t1518.001
    - detection.emerging-threats
logsource:
    category: proxy
    product: zeek
detection:
    selection:
        cs-host|contains: 'usom.gov.tr'
        cs-uri-stem|contains: 'url-list.txt'
    condition: selection
falsepositives:
    - >-
      Turkish CERT partner organizations, security researchers, or security
      products that legitimately poll the USOM blocklist — this is expected,
      common behavior on its own; the paired correlation rule is required to
      raise confidence
level: low
---
title: BellaMain PhaaS High-Frequency Multi-Bot Telegram Outbound
id: e5f2b847-3a1c-4d96-8e04-7c9d3f2a1b56
status: experimental
description: >-
  Detects an individual outbound HTTPS request to api.telegram.org/bot* from
  a source host. This base event feeds two paired correlation rules: the
  burst-correlation rule below (five or more such requests from a single
  source host within a 60-second window) and the USOM-poll correlation
  below. BellaMain fires multiple specialized bots on each credential hit:
  the admin bot receives the raw credential set, vergibot receives
  national-ID data, and dekontbot and cekimbot handle approval workflows.
  On its own, a single request to the Telegram Bot API is common,
  legitimate traffic produced by many unrelated notification integrations.
references:
    - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: '2026-05-16'
tags:
    - attack.command-and-control
    - attack.t1102.002
    - detection.emerging-threats
logsource:
    category: proxy
    product: zeek
detection:
    selection:
        cs-host: 'api.telegram.org'
        cs-uri-stem|startswith: '/bot'
    condition: selection
falsepositives:
    - >-
      Any web application with a legitimate Telegram bot integration (order
      notifications, monitoring alerts, CI/CD pipelines) — this is common,
      everyday behavior on many web servers
level: low
---
title: BellaMain PhaaS USOM Poll and Telegram Bot Outbound Correlation
id: 5a705984-73aa-47db-b19e-5b0f45b14d0c
status: experimental
correlation:
    type: temporal
    rules:
        - 7c1bb0ba-7d15-4969-a8dd-529d3b6294b9
        - e5f2b847-3a1c-4d96-8e04-7c9d3f2a1b56
    group-by:
        - src_ip
    timespan: 5m
description: >-
  Correlates a USOM blocklist poll with a Telegram Bot API request from the
  same source host within a 5-minute window. Neither event alone is a
  reliable indicator — USOM polling is legitimate CERT/security-tool
  behavior, and a single Telegram Bot API call is common on hosts running
  legitimate notification integrations — but a web server exhibiting both
  behaviors together is the operational fingerprint of BellaMain's
  usmcheck.php blocklist monitor and its Telegram kill-switch notification
  chain.
references:
    - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: '2026-05-16'
tags:
    - attack.discovery
    - attack.t1518.001
    - attack.command-and-control
    - attack.t1102.002
    - detection.emerging-threats
falsepositives:
    - >-
      A host that legitimately both monitors the USOM blocklist and operates
      an unrelated Telegram notification bot within the same time window —
      tune by excluding known-legitimate source IPs
level: medium
---
title: BellaMain PhaaS High-Frequency Multi-Bot Telegram Outbound — Burst Correlation
id: f4c1a936-2d7e-4b58-9a03-6e1f8c52d7ab
status: experimental
correlation:
  type: event_count
  rules:
    - e5f2b847-3a1c-4d96-8e04-7c9d3f2a1b56
  group-by:
    - src_ip
  timespan: 60s
  condition:
    gte: 5
description: >-
  Correlates the base rule BellaMain PhaaS High-Frequency Multi-Bot Telegram
  Outbound to fire when a single source host generates five or more matching
  outbound requests to api.telegram.org/bot* within a 60-second window — a
  volumetric anomaly consistent with BellaMain's automated four-bot exfil
  burst, though the underlying count does not distinguish distinct bot
  tokens from repeated calls to one bot, so a legitimate high-volume
  notification integration can trigger this identically.
references:
    - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: '2026-05-16'
tags:
    - attack.command-and-control
    - attack.t1102.002
    - attack.exfiltration
    - attack.t1041
    - attack.collection
    - attack.t1119
    - detection.emerging-threats
falsepositives:
    - >-
      Web application platforms with legitimate high-frequency Telegram
      notification integrations (e.g., e-commerce order-notification bots)
      firing on concurrent order events — tune threshold or scope to
      web-server segments not expected to run application-layer Telegram
      integrations
level: medium
```

---

## Suricata Signatures

### Hunting Rules

#### BellaMain USOM Blocklist Poll from Web Server (Network Layer)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1518.001 (Software Discovery: Security Software)
**Confidence:** MODERATE
**Rationale:** Corrected from the original, which was titled and rationalized as "USOM Egress Combined with Telegram Outbound" but whose condition only ever implemented the USOM-poll half — Suricata cannot natively express the cross-flow, cross-host-scoped AND-correlation with Telegram traffic that the paired Sigma correlation rule above now implements at the log layer. As a standalone network signal, USOM blocklist polling from a non-CERT-affiliated host has real overlap with legitimate Turkish security tooling (the IOC feed itself flags this URL as HIGH false-positive risk on its own), so this is Hunting, not Detection. `rev` bumped to 2 for the corrected `msg` and reframed rationale.
**False Positives:** Turkish security tools, CERT-affiliated platforms, and threat-intelligence products that legitimately poll the USOM blocklist from any network segment.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; correlate hits with Telegram Bot API traffic from the same source within roughly 5 minutes (see the paired Sigma correlation rule) before treating as a high-confidence lead.

```suricata
alert http $HOME_NET any -> any any (msg:"THL BellaMain-PhaaS USOM Blocklist Poll from Web Server (Security Tool Discovery Indicator)"; flow:established,to_server; http.host; content:"usom.gov.tr"; endswith; http.uri; content:"url-list.txt"; nocase; threshold:type limit,track by_src,count 1,seconds 300; classtype:policy-violation; sid:9001004; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-16, reference https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/;)
```

---

## Coverage Gaps

**Five atomics-only rules retired (1 Sigma, 4 Suricata) — no new feed entries required.** The original Sigma "Admin Panel Path Access" rule and the original Suricata "Admin Panel HTTP GET" (sid 9001001), "C2 Infrastructure TLS SNI" ×2 (sid 9001002/9001003), and "DNS Query for CryptOne Fake-Exchange Domain" (sid 9001005) each keyed solely on one already-cataloged atomic — the admin path `V5VgjLU0jsDe`, the panel IP `79.137.192.3`, or the domains `cryptone.bot`/`evotoptan.com` — with no behavioral qualifier surviving the literal's removal. All of these values were already present in the IOC feed's `host_indicators` / `network_indicators` from the original analysis (confidence DEFINITE–HIGH, action BLOCK/HUNT), so no feed edit was needed; block/monitor them via feed-driven firewall, DNS-sinkhole, and WAF-path policy rather than a standalone signature. One consequence: this file no longer carries a standalone T1071.001 (Application Layer Protocol: Web Protocols) network signature for direct C2/panel HTTPS access, since no protocol-level distinguishing artifact beyond the specific IP/domain was recovered (no distinctive JA4X/JARM anomaly, no reusable self-signed certificate-issuer template comparable to what would justify an infrastructure-rotation-resilient rule). Coverage for that technique is IOC-feed-only going forward.

**Cut: Turkish-Language Role-Bot Telegram DNS Query.** The original rule matched DNS query strings for `girisbot`/`vergibot`/`dekontbot`/`cekimbot`, but its own description acknowledges the premise does not match the actual protocol: Telegram Bot API traffic resolves only `api.telegram.org` in DNS, with the bot identity carried in the numeric token embedded in the HTTPS URL path (`/bot<token>/sendMessage`), not as an independently DNS-resolved bot username. As written, the rule targets a query pattern BellaMain's actual C2 mechanism does not generate, so it provides no real detection value regardless of false-positive tuning. The one bot-related filename independently confirmed in the evidence base — `cekimbot.php` — is already carried in the IOC feed as a file-path indicator; a YARA or file-drop signature for the sibling webhook handlers (`girisbot.php`, `vergibot.php`, `dekontbot.php`) was not built here because no hash, unique internal string, or other distinguishing content beyond the bare filename claim is available in this evidence base. **What would enable a rule:** recovered file hashes or distinctive internal strings for the three unconfirmed webhook handler files.

**Salvaged: USOM Poll + Telegram Bot Outbound (Sigma).** The original combined rule's `selection_usom and selection_telegram` condition required a single field (`cs-host`) to equal two mutually exclusive values on one log line — a condition that could never match any event, regardless of tuning. This is now expressed correctly as a two-rule Sigma temporal correlation (see the Sigma Hunting section above): an independent USOM-poll base rule and a correlation rule that also references the existing Telegram-bot-access base rule, grouped by source IP within a 5-minute window. Both legs remain individually common/benign, so the corrected rule is Hunting-tier, not Detection — this is a genuine improvement in correctness over the original (which could never fire at all), not a downgrade in coverage.

**T1583.003 / T1583.001 — Acquire Infrastructure: VPS and Domains.** Resource Development techniques describe operator actions prior to deploying BellaMain. The evidence (VPS at 79.137.192.3, domains cryptone.bot and evotoptan.com) is IOC-feed-only, per the atomics note above. Creating a behavioral detection rule for infrastructure acquisition requires visibility into registrar/hosting transaction logs that are not available to defenders operating in victim-network or SOC contexts.

**T1566.002 — Phishing: Spearphishing Link.** Phishing link delivery is observed at the victim-browser layer, not the operator-server layer. Detecting BellaMain phishing links in email requires brand-impersonation domain watchlists and URL-pattern rules specific to each of the 7 kit themes (Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, Yurtici Kargo). The 7 kit domains were not recovered from the open directory; only the panel-hosting IP and two operator domains are confirmed. Rule creation for the phishing delivery layer requires additional victim-side URL telemetry (email gateway logs, browser proxy logs) and kit-specific domain lists not present in the current evidence base.

**T1480 — Execution Guardrails.** BellaMain's anti-researcher canary (`?lg=` probe parameter) fires a Telegram alert and returns a troll response, functioning as an active execution guardrail for the kit's credential-capture flow. The YARA rule `TOOLKIT_BellaMain_AntiResearcherCanary` covers the PHP source artifact. A network-layer trigger rule for the canary would require matching the `?lg=` query parameter on each of the 7 kits' page URLs; without confirmed kit deployment domains, this cannot be built with acceptable false-positive risk.

**T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File.** BellaMain's session cookie is encoded via the custom `sifreleWadanz`/`sifrecozWadanz` `base64(gzcompress(serialize()))` pipeline. The YARA rules `TOOLKIT_BellaMain_WadanzFunctions` and `TOOLKIT_BellaMain_AdminPanel` cover the PHP source artifacts implementing this transform (source-code layer, Detection-tier). A network-layer detector for the encoded cookie output itself would require HTTP-layer cookie inspection with a regex matching the base64-of-gzcompressed-serialized-PHP-data pattern; the cookie value varies per session with no fixed-length or fixed-prefix marker observed, so a low-FP network-layer cookie-inspection rule cannot be written from available evidence.

**T1657 — Financial Theft.** BellaMain's revenue mechanism (70/30 TRX/TRON split, Binance TRXTRY rate conversion) is a business-logic-layer behavior that produces no detectable network or host artifact beyond the Telegram C2 traffic already covered. Detection of cryptocurrency payout transactions requires blockchain monitoring (TRON wallet address watchlists) using the specific operator wallet addresses, which were not recovered from the PHP source in this analysis.

**T1036.005 — Masquerading: Match Legitimate Resource Name or Location.** BellaMain kits load legitimate CDN assets (`cdn.dolap.com`, `GTM-K7F5T5N`, New Relic RUM beacons) to increase victim-page fidelity. Detecting masquerading via these CDN assets requires page-similarity analysis outside the scope of static Suricata/Sigma rule sets. The `GTM-K7F5T5N` container ID (in the IOC feed) can be used as a pivot indicator in threat hunting but does not produce a production-ready low-FP detection rule.

**PHP Object Injection surface (unserialize on cookie-supplied data in `sifrecozWadanz`).** The PHP `unserialize()` call on attacker-controlled cookie data is an observed vulnerability surface in BellaMain's session-decryption flow. A content-inspection rule matching a serialized-PHP-object prefix (`O:`) in the cookie would be too broad — it would fire on any legitimate PHP session cookie using object serialization. Evidence required to create a low-FP rule: a confirmed malicious serialized object payload targeting this specific `unserialize()` call, which would allow anchoring on the class name or property structure. Absent exploitation evidence, this surface remains a coverage gap and is recommended for manual analyst inspection during incident triage.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
