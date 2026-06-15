---
title: "Detection Rules — BellaMain Turkish PhaaS Panel"
date: '2026-05-16'
layout: post
permalink: /hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
thumbnail: /assets/images/cards/bellamain-turkish-phaas-79-137-192-3-20260516.png
hide: true
---

**Campaign:** BellaMain-Turkish-PhaaS-79-137-192-3-20260516
**Date:** 2026-05-16
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/bellamain-turkish-phaas-79-137-192-3-20260516/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 3 | T1505.003, T1027.013, T1070, T1056, T1119 | LOW–MEDIUM |
| Sigma | 5 | T1505.003, T1070, T1071.001, T1102.002, T1560, T1518.001 | LOW–MEDIUM |
| Suricata | 4 | T1505.003, T1071.001, T1518.001, T1102.002 | LOW–MEDIUM |

**Scope note:** All rules cover Cluster A (BellaMain Turkish PhaaS panel + 7 brand-impersonation kits) only. Cluster B (Inkognito) and Cluster C (Rhadamanthys) are covered by previously published detection sets. The evidence base is recovered PHP source code, not PE binaries — detection logic targets server-side artifacts, web-server logs, and network egress, not endpoint process injection or PE characteristics.

---

## YARA Rules

### TOOLKIT_BellaMain_WadanzFunctions

**Detection Priority:** HIGH
**Rationale:** Matches the author-pseudonym function-name pair sifreleWadanz/sifrecozWadanz unique to this developer across all BellaMain deployments; vanishingly low FP probability in any production PHP corpus
**ATT&CK Coverage:** T1505.003 (Web Shell / server-side implant), T1027.013 (Obfuscated Files — custom session cipher)
**Confidence:** HIGH
**False Positive Risk:** LOW — the Wadanz pseudonym suffix on these exact function names is not present in any known legitimate PHP framework or library
**Deployment:** PHP web-root scanner (ModSecurity, OSSEC file-integrity, ClamAV PHP ruleset), post-incident forensic triage of compromised web servers

```
/*
    Name: BellaMain PhaaS Panel - Wadanz Author Functions
    Author: The Hunters Ledger
    Date: 2026-05-16
    Identifier: BellaMain Turkish PhaaS V5VgjLU0jsDe
    Reference: https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_BellaMain_WadanzFunctions
{
    meta:
        description = "Detects BellaMain Turkish PhaaS panel PHP source files containing the author-pseudonym session-cipher function pair sifreleWadanz and sifrecozWadanz in database/fonk.php or any forked copy. The Wadanz suffix is the developer identity artifact unique to this codebase."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
        hash_sha256 = "f791fae41cdd3f141221d1783ed4779c839de7fc834ff4fc80a5d7f74b11ff88"
        family = "BellaMain"

    strings:
        $func_enc  = "sifreleWadanz"  ascii
        $func_dec  = "sifrecozWadanz" ascii
        $db_user   = "dbjakartaxdw"   ascii
        $db_name   = "jakartaxdw"     ascii

    condition:
        filesize < 512KB and
        $func_enc and $func_dec and
        1 of ($db_user, $db_name)
}
```

---

### TOOLKIT_BellaMain_AdminPanel

**Detection Priority:** HIGH
**Rationale:** Matches the obfuscated 12-character admin directory string V5VgjLU0jsDe combined with BellaMain MySQL credentials; highly specific to this codebase and its direct forks
**ATT&CK Coverage:** T1505.003 (Web Shell), T1070 (Indicator Removal — command strings for evidence destruction)
**Confidence:** HIGH
**False Positive Risk:** LOW — V5VgjLU0jsDe is a randomly generated admin path; the MySQL credential combination is hardcoded across all 8 BellaMain source files
**Deployment:** PHP web-root scanner, file-integrity monitoring on web servers, forensic PHP corpus triage

```
/*
    Name: BellaMain PhaaS Panel - Admin Path and Credential Strings
    Author: The Hunters Ledger
    Date: 2026-05-16
    Identifier: BellaMain Turkish PhaaS V5VgjLU0jsDe
    Reference: https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_BellaMain_AdminPanel
{
    meta:
        description = "Detects BellaMain Turkish PhaaS panel PHP source files containing the obfuscated admin directory path V5VgjLU0jsDe and the shared MySQL database user dbjakartaxdw. These two indicators co-occurring in PHP source confirm a BellaMain panel instance or direct fork."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
        hash_sha256 = "705793c011fdfe17941700a3bf42eee0ba2ebdc04870ce19779ea528b3565fac"
        family = "BellaMain"

    strings:
        $admin_path = "V5VgjLU0jsDe"    ascii
        $db_user    = "dbjakartaxdw"     ascii
        $db_pass    = "W!@25#8Tb2gxq15" ascii
        $cmd_del1   = "/hesapsil"        ascii
        $cmd_del2   = "/kartsil"         ascii
        $cmd_del3   = "/girislogsil"     ascii

    condition:
        filesize < 512KB and
        $admin_path and $db_user and
        1 of ($db_pass, $cmd_del1, $cmd_del2, $cmd_del3)
}
```

---

### TOOLKIT_BellaMain_AntiResearcherCanary

**Detection Priority:** MEDIUM
**Rationale:** Matches the Turkish-language anti-researcher troll strings (Sazan + Usom Yedik Atis Stop patterns) from kit girislog.php; distinctive but may appear in kit copies at rest rather than active deployments
**ATT&CK Coverage:** T1497 (Virtualization/Sandbox Evasion — anti-researcher variant), T1056 (Input Capture — credential logging context of girislog.php)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — Turkish profanity strings with these specific combinations are highly unlikely in legitimate PHP; however, analyst-held kit samples or threat intel archives may trigger this rule on non-active files
**Deployment:** PHP web-root scanner, threat intel file corpus triage, malware archive scanning; apply analyst triage before automated block action

```
/*
    Name: BellaMain PhaaS Panel - Anti-Researcher Canary Strings
    Author: The Hunters Ledger
    Date: 2026-05-16
    Identifier: BellaMain Turkish PhaaS V5VgjLU0jsDe
    Reference: https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_BellaMain_AntiResearcherCanary
{
    meta:
        description = "Detects BellaMain Turkish PhaaS kit girislog.php files containing the anti-researcher canary string cluster. The ?lg= GET parameter triggers these strings, causing the kit to fire a Telegram alert with researcher IP and UA and return a Turkish-language troll response. Presence in a PHP file confirms BellaMain kit provenance."
        author = "The Hunters Ledger"
        date = "2026-05-16"
        reference = "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/"
        hash_sha256 = "219cd4f6177a2358ec7f06b230d611f47e1049fcb3e2b44d06ec410b336382b0"
        family = "BellaMain"

    strings:
        $sazan_ip     = "Sazan IP"              ascii
        $sazan_kod    = "Sazan Kod"              ascii
        $sazan_cihaz  = "Sazan Cihaz"            ascii
        $usom_msg     = "Usom Yedik Atis Stop"   ascii
        $ares_alias   = "@AresRS34"              ascii
        $lg_param     = "?lg="                   ascii

    condition:
        filesize < 512KB and
        2 of ($sazan_ip, $sazan_kod, $sazan_cihaz, $usom_msg) and
        1 of ($ares_alias, $lg_param)
}
```


---

## Sigma Rules

### BellaMain Admin Panel Path Access

**Detection Priority:** HIGH
**Rationale:** HTTP requests to the obfuscated V5VgjLU0jsDe admin directory are essentially exclusive to BellaMain operators; no legitimate web application uses this path
**ATT&CK Coverage:** T1505.003 (Web Shell — admin panel access), T1078 (Valid Accounts — operator authentication)
**Confidence:** HIGH
**False Positive Risk:** LOW — the 12-character random admin path is not guessable via wordlist; any request to it indicates direct knowledge of the path (operator access or attacker reuse)
**Deployment:** Apache/nginx access log ingestion into SIEM, web proxy HTTP monitoring, WAF log forwarding

```yaml
title: BellaMain PhaaS Admin Panel Path Access
id: a3f7c291-84e2-4d1b-9c5a-f6e8b2d04371
status: test
description: >-
  Detects HTTP GET or POST requests to the BellaMain Turkish PhaaS panel
  obfuscated admin directory V5VgjLU0jsDe. This 12-character random path is
  hardcoded across the BellaMain codebase and is not guessable via common
  wordlists. Any inbound HTTP request to this path on a web server indicates
  either a BellaMain operator accessing the admin panel or an attacker who
  has obtained the path from a compromised deployment.
references:
  - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.persistence
  - attack.command-and-control
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: 'V5VgjLU0jsDe'
  condition: selection
falsepositives:
  - >-
    Legitimate web application with a coincidentally identical path component
    (effectively impossible given path length and character set; treat as
    confirmed BellaMain activity and investigate)
level: high
```

---

### BellaMain USOM Blocklist Polling Combined with Telegram Outbound

**Detection Priority:** HIGH
**Rationale:** A PHP web server polling the Turkish CERT URL blocklist (usom.gov.tr/url-list.txt) while also making outbound Telegram Bot API connections in the same host context is a behavioral fingerprint exclusive to BellaMain's usmcheck.php + manager.php architecture
**ATT&CK Coverage:** T1518.001 (Software Discovery: Security Software — USOM monitoring as security-tool detection), T1102.002 (Web Service: Bidirectional Communication — Telegram C2)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — each indicator individually has legitimate uses; the combination on a single host (non-Turkish-CERT PHP server polling USOM while running Telegram bot connections) narrows FP risk substantially. Tune by scoping to web-server process context.
**Deployment:** Egress proxy log SIEM correlation, Linux auditd syscall monitoring for outbound PHP curl/HTTP, Zeek HTTP log analysis

```yaml
title: BellaMain PhaaS USOM Blocklist Poll and Telegram Bot Outbound
id: b82d1f44-c7a9-4e53-a2f1-9d3c6b08e592
status: test
description: >-
  Detects a web server process making outbound HTTP connections to both the
  Turkish CERT USOM URL blocklist (www.usom.gov.tr/url-list.txt) and the
  Telegram Bot API (api.telegram.org) within the same 5-minute window.
  BellaMain's usmcheck.php polls the USOM list to detect when its phishing
  kit domains are blocklisted, then broadcasts a kill-switch command via
  Telegram. No legitimate web application combines USOM blocklist polling with
  Telegram bot communication. The USOM URL alone is moderate FP risk on
  Turkish security platforms; the Telegram combination is the discriminating
  indicator.
references:
  - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
  - https://www.usom.gov.tr/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.discovery
  - attack.command-and-control
logsource:
  category: proxy
  product: zeek
detection:
  selection_usom:
    cs-host|contains: 'usom.gov.tr'
    cs-uri-stem|contains: 'url-list.txt'
  selection_telegram:
    cs-host|contains: 'api.telegram.org'
    cs-uri-stem|startswith: '/bot'
  condition: selection_usom and selection_telegram
falsepositives:
  - >-
    Turkish CERT partner organizations or security researchers monitoring USOM
    list while simultaneously operating a Telegram notification bot
  - >-
    Security monitoring scripts that legitimately combine USOM polling with
    alerting via Telegram bots (tune by excluding known-legitimate source IPs
    and authorized bot token prefixes)
level: high
```

---

### BellaMain MySQL Evidence Destruction via Telegram Command

**Detection Priority:** HIGH
**Rationale:** mysqldump invoked by a PHP parent process on a web server, or TRUNCATE TABLE statements targeting BellaMain-named tables (girisyapanlar, kartlar, girislog), are specific to BellaMain's /yedek backup-as-exfil and /hesapsil /kartsil /girislogsil evidence-destruction commands
**ATT&CK Coverage:** T1070 (Indicator Removal — TRUNCATE destroys credential and victim-log evidence), T1560 (Archive Collected Data — mysqldump output piped to Telegram)
**Confidence:** HIGH
**False Positive Risk:** LOW — PHP spawning mysqldump with -p plaintext credentials on a web server is unusual; legitimate backup jobs run under dedicated backup accounts, not web-server process context
**Deployment:** Linux auditd / Sysmon-for-Linux process creation events in SIEM, EDR process telemetry on PHP web servers

```yaml
title: BellaMain PhaaS mysqldump Invocation by PHP Web Process
id: c914e7a2-5b36-4f87-b3d8-2a1e9c047f83
status: test
description: >-
  Detects mysqldump invoked with a plaintext -p password argument by a PHP or
  web server parent process. BellaMain's /yedek Telegram command executes
  mysqldump via PHP shell_exec() to produce a SQL backup that is then sent to
  the operator's Telegram channel via sendDocument. Legitimate database backup
  jobs run under dedicated service accounts with credential files rather than
  plaintext -p arguments spawned from a web-server process. This combination
  of parent process (php/php-fpm/apache2/nginx) and mysqldump child with a
  -p flag is a strong behavioral indicator of BellaMain's backup-as-exfil
  capability.
references:
  - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.exfiltration
  - attack.defense-evasion
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

---

### BellaMain Telegram Bot Name Pattern Outbound

**Detection Priority:** MEDIUM
**Rationale:** BellaMain's four-bot architecture uses bot names ending in specific Turkish-language role suffixes (girisbot, vergibot, dekontbot, cekimbot); DNS resolution of these bot names from a web server is a behavioral indicator of BellaMain operator-side activity
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication — multi-bot Telegram exfil), T1041 (Exfiltration Over C2 Channel)
**Confidence:** MODERATE — bot name patterns are operator-chosen and may vary in forks; the structural pattern (Turkish-language role-suffix bot names registered on Telegram) is the indicator, not exact names
**False Positive Risk:** MEDIUM — legitimate Turkish-language Telegram bots may share suffix patterns; tune by combining with web-server source-process context and excluding known-legitimate bot registrations
**Deployment:** DNS resolver log analysis in SIEM, Zeek DNS logs, Pi-hole query logs for web-server egress

```yaml
title: BellaMain PhaaS Turkish-Language Role-Bot Telegram DNS Query
id: d7a3c158-6e92-4b04-9f17-4b2d8e1c5a09
status: experimental
description: >-
  Detects DNS queries for Telegram bot usernames matching the BellaMain
  Turkish-language role-suffix pattern. BellaMain deploys four specialized
  bots with Turkish-language function names: girisbot (login exfil), vergibot
  (national-ID alerts), dekontbot (bank-statement approval), and cekimbot
  (withdrawal approval). These names reflect the PhaaS panel's victim-funnel
  architecture. While individual Turkish-language bot names may appear in
  legitimate contexts, their co-occurrence with web-server process DNS
  queries and the role-suffix pattern is specific to BellaMain. Note: DNS
  queries for api.telegram.org resolve bot traffic generically; individual
  bot names are not DNS-resolved separately in the Telegram API protocol.
  This rule targets cases where bot usernames appear in DNS query strings
  from internal web-server hosts (e.g., via t.me resolution or bot-lookup
  endpoints).
references:
  - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.command-and-control
  - attack.exfiltration
logsource:
  category: dns
  product: zeek
detection:
  selection:
    query|contains:
      - 'girisbot'
      - 'vergibot'
      - 'dekontbot'
      - 'cekimbot'
  condition: selection
falsepositives:
  - >-
    Turkish-language legitimate Telegram bots with similar role-suffix naming
    conventions — validate by correlating with web-server source IP and
    checking for concurrent USOM polling or V5VgjLU0jsDe admin path access
  - >-
    Security researchers probing BellaMain bot names for OSINT purposes
level: medium
```

---

### BellaMain Multi-Bot Telegram Outbound from Web-Server Context

**Detection Priority:** HIGH
**Rationale:** Five or more outbound HTTPS connections to api.telegram.org from a single web-server host within a 60-second window, across multiple distinct /bot URI prefixes, indicates BellaMain's four-bot exfil architecture firing on a credential capture event
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1041 (Exfiltration Over C2 Channel), T1119 (Automated Collection — victim heartbeat AJAX cycle)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — single web servers legitimately run multiple Telegram notification bots; the discriminating factor is five or more distinct bot-token URI prefixes in 60 seconds from a web-server process context (not a general-purpose application server)
**Deployment:** Egress proxy SIEM with time-window correlation, Zeek HTTP log analysis, network-layer egress monitoring on web-server DMZ segments

```yaml
title: BellaMain PhaaS High-Frequency Multi-Bot Telegram Outbound
id: e5f2b847-3a1c-4d96-8e04-7c9d3f2a1b56
status: test
description: >-
  Detects a burst of five or more outbound HTTPS requests to
  api.telegram.org/bot* from a single source host within a 60-second window,
  indicating BellaMain's automated four-bot credential-exfil pipeline
  activating on a victim credential capture. BellaMain fires multiple
  specialized bots simultaneously on each credential hit: the admin bot
  receives the raw credential set, vergibot receives national-ID data, and
  dekontbot and cekimbot handle approval workflows. The resulting burst of
  outbound Telegram API calls to distinct bot-token URIs within a short
  window is a behavioral fingerprint of the PhaaS automation layer.
references:
  - https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/
author: The Hunters Ledger
date: 2026/05/16
tags:
  - attack.command-and-control
  - attack.exfiltration
  - attack.collection
logsource:
  category: proxy
  product: zeek
detection:
  selection:
    cs-host: 'api.telegram.org'
    cs-uri-stem|startswith: '/bot'
  timeframe: 60s
  condition: selection | count() by src_ip > 4
falsepositives:
  - >-
    Web application platforms with legitimate high-frequency Telegram
    notification integrations (e.g., e-commerce order-notification bots)
    firing on concurrent order events — tune threshold or scope to web-server
    segments not expected to run application-layer Telegram integrations
level: high
```


---

## Suricata Signatures

### BellaMain Admin Panel HTTP GET

**Detection Priority:** HIGH
**Rationale:** Inbound HTTP request to the V5VgjLU0jsDe admin path from any source is essentially exclusive to BellaMain operator access; the path is not guessable via common wordlists
**ATT&CK Coverage:** T1505.003 (Web Shell — admin panel access)
**Confidence:** HIGH
**False Positive Risk:** LOW — 12-character random admin directory; any HTTP request matching this URI component should be treated as confirmed BellaMain activity
**Deployment:** Inline IDS/IPS on web-server ingress, edge NDR sensors monitoring HTTP traffic to hosted PHP applications

```
alert http any any -> $HTTP_SERVERS any (
    msg:"THL BellaMain PhaaS Admin Panel Path Access V5VgjLU0jsDe";
    flow:established,to_server;
    http.uri; content:"/V5VgjLU0jsDe/"; nocase;
    classtype:web-application-attack;
    sid:9001001;
    rev:1;
    metadata:
        author "The Hunters Ledger",
        date "2026-05-16",
        mitre_technique "T1505.003",
        reference "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/";
)
```

---

### BellaMain C2 Infrastructure TLS SNI

**Detection Priority:** HIGH
**Rationale:** TLS connections to 79[.]137[.]192[.]3 (defanged) with SNI matching known BellaMain operator domain (cryptone.bot or evotoptan.com) indicate direct operator-infrastructure contact
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols — HTTPS C2), T1505.003 (panel hosting)
**Confidence:** HIGH
**False Positive Risk:** LOW — destination IP is a dedicated VPS hosting only BellaMain infrastructure as of analysis date; TLS SNI matching the operator's fake-exchange brand is not expected in legitimate traffic
**Deployment:** Egress NDR sensors, perimeter firewall with SSL inspection, Zeek-based SIEM TLS log analysis

```
alert tls $HOME_NET any -> 79.137.192.3 any (
    msg:"THL BellaMain C2 Infrastructure TLS Connection to 79.137.192.3";
    flow:established,to_server;
    tls.sni; content:"cryptone"; nocase;
    classtype:trojan-activity;
    sid:9001002;
    rev:1;
    metadata:
        author "The Hunters Ledger",
        date "2026-05-16",
        mitre_technique "T1071.001",
        reference "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/";
)
```

```
alert tls $HOME_NET any -> 79.137.192.3 any (
    msg:"THL BellaMain C2 Infrastructure TLS Connection to 79.137.192.3 evotoptan SNI";
    flow:established,to_server;
    tls.sni; content:"evotoptan"; nocase;
    classtype:trojan-activity;
    sid:9001003;
    rev:1;
    metadata:
        author "The Hunters Ledger",
        date "2026-05-16",
        mitre_technique "T1071.001",
        reference "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/";
)
```

---

### BellaMain USOM Egress Combined with Telegram Outbound (Network Layer)

**Detection Priority:** HIGH
**Rationale:** Network-level correlation of outbound HTTP to usom.gov.tr and outbound HTTPS to api.telegram.org from the same source host within a 300-second window covers BellaMain's usmcheck.php polling cycle; neither connection alone is high-confidence, but the combination from a web-server IP is a strong behavioral fingerprint
**ATT&CK Coverage:** T1518.001 (Software Discovery: Security Software — USOM blocklist polling), T1102.002 (Web Service: Bidirectional Communication)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Turkish security tools and CERT-affiliated platforms legitimately poll USOM; tune by scoping to known web-server IP ranges and excluding CERT/government source prefixes
**Deployment:** Egress NDR sensors, perimeter IDS with flow correlation, Zeek conn.log SIEM analysis

```
alert http $HOME_NET any -> any any (
    msg:"THL BellaMain PhaaS USOM Blocklist Poll from Web Server";
    flow:established,to_server;
    http.host; content:"usom.gov.tr"; endswith; nocase;
    http.uri; content:"url-list.txt"; nocase;
    threshold: type limit, track by_src, count 1, seconds 300;
    classtype:policy-violation;
    sid:9001004;
    rev:1;
    metadata:
        author "The Hunters Ledger",
        date "2026-05-16",
        mitre_technique "T1518.001",
        reference "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/";
)
```

---

### BellaMain DNS Query for CryptOne Fake-Exchange Domain

**Detection Priority:** HIGH
**Rationale:** DNS queries for cryptone.bot from any internal asset indicate direct contact with BellaMain's fake crypto-exchange front; the domain is not used by any legitimate financial service
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1656 (Impersonation — fake crypto exchange)
**Confidence:** HIGH
**False Positive Risk:** LOW — cryptone.bot has no legitimate registration history outside BellaMain infrastructure; any internal DNS resolution of this domain warrants investigation
**Deployment:** DNS resolver-layer IDS/IPS, internal DNS sinkhole policy, Zeek DNS log ingestion into SIEM

```
alert dns $HOME_NET any -> any any (
    msg:"THL BellaMain CryptOne Fake Exchange Domain DNS Query cryptone.bot";
    flow:established;
    dns.query; content:"cryptone.bot"; endswith; nocase;
    classtype:trojan-activity;
    sid:9001005;
    rev:1;
    metadata:
        author "The Hunters Ledger",
        date "2026-05-16",
        mitre_technique "T1071.001",
        reference "https://the-hunters-ledger.com/hunting-detections/bellamain-turkish-phaas-79-137-192-3-20260516-detections/";
)
```


---

## Coverage Gaps

The following MITRE ATT&CK techniques observed in the malware-analyst findings could not be covered with high-confidence detection rules, and the reasons why are documented here.

**T1583.003 / T1583.001 — Acquire Infrastructure: VPS and Domains**
Resource Development techniques describe operator actions prior to deploying BellaMain. The evidence (VPS at 79.137.192.3, domains cryptone.bot and evotoptan.com) is covered by IOC-level network rules already in this file. Creating a behavioral detection rule for infrastructure acquisition requires visibility into registrar/hosting transaction logs that are not available to defenders operating in victim-network or SOC contexts. Coverage: IOC-based Suricata rules provide network-level detection once infrastructure is contacted; no behavioral rule is possible from this evidence base alone.

**T1566.002 — Phishing: Spearphishing Link**
Phishing link delivery is observed at the victim-browser layer, not the operator-server layer. Detecting BellaMain phishing links in email requires brand-impersonation domain watchlists and URL-pattern rules specific to each of the 7 kit themes (Dolap, Letgo, PTT AVM, Sahibinden, Shopier, Turkcell, Yurtici Kargo). The 7 kit domains were not recovered from the open directory; only the panel-hosting IP and two operator domains are confirmed. Rule creation for the phishing delivery layer requires additional victim-side URL telemetry (email gateway logs, browser proxy logs) and kit-specific domain lists that are not present in the current evidence base.

**T1480 — Execution Guardrails**
BellaMain's anti-researcher canary (?lg= probe parameter) fires a Telegram alert and returns a troll response, functioning as an active execution guardrail for the kit's credential-capture flow. The YARA rule TOOLKIT_BellaMain_AntiResearcherCanary covers the PHP source artifact. A Suricata rule for the canary trigger would require matching the ?lg= query parameter in HTTP GET requests to kit pages — this is covered structurally by the admin-path Suricata rule (SID 9001001) but the kit-page ?lg= parameter would require knowing the kit-page URL structure of each of the 7 kits. Without confirmed kit deployment domains, a network-layer canary trigger rule cannot be written without high FP risk.

**T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File**
BellaMain's session cookie is encoded via the custom `sifreleWadanz` / `sifrecozWadanz` `base64(gzcompress(serialize()))` pipeline. The YARA rules TOOLKIT_BellaMain_WadanzFunctions and TOOLKIT_BellaMain_AdminPanel cover the PHP source artifacts implementing this transform. A behavioral detection rule for the encoded output (cookie values matching the base64-of-gzcompressed-serialized-PHP-data pattern) would require HTTP-layer cookie inspection with a regex matching the base64-encoded transform output. The transform key context is the session token (cookie `2tUgyO@H9E!4CuQ`), which is observable but the cookie value itself varies per session. Without a fixed-length or fixed-prefix pattern in the encoded output, a low-FP network-layer cookie-inspection rule cannot be written from available evidence.

**T1657 — Financial Theft**
BellaMain's revenue mechanism (70/30 TRX/TRON split, Binance TRXTRY rate conversion) is a business-logic layer behavior that produces no detectable network or host artifact beyond the Telegram C2 traffic already covered. Detection of cryptocurrency payout transactions requires blockchain monitoring (TRON wallet address watchlists) with the specific operator wallet addresses, which were not recovered from the PHP source in this analysis. Evidence would need to include recovered wallet addresses from the PHP source or Telegram transaction confirmations.

**T1036.005 — Masquerading: Match Legitimate Resource Name or Location**
BellaMain kits load legitimate CDN assets (cdn.dolap.com, GTM-K7F5T5N, New Relic RUM beacons) to increase victim-page fidelity. Detecting masquerading via these CDN assets requires a behavioral rule that fires on pages loading legitimate assets from the listed domains while simultaneously harvesting credentials to a non-legitimate backend. This requires HTTP-layer content inspection with ML-based page-similarity analysis that is outside the scope of static Suricata/Sigma rule sets. The GTM-K7F5T5N container ID (documented in IOC feed) can be used as a pivot indicator in threat hunting but does not produce a production-ready low-FP detection rule.

**PHP Object Injection Surface (unserialize on cookie-supplied data in sifrecozWadanz)**
The PHP unserialize() call on attacker-controlled cookie data is an observed vulnerability surface in BellaMain's session-decryption flow. Creating a detection rule for PHP object injection exploitation requires HTTP-layer inspection of cookie values for serialized PHP object patterns (O: class-name prefix). A Suricata content-inspection rule for this would be:
- `http.cookie; content:"O:"; depth:2;` — but this is extremely broad and would fire on any legitimate PHP session cookie using object serialization.
Evidence required to create a low-FP rule: a confirmed malicious serialized object payload targeting this specific unserialize() call, which would allow anchoring on the class name or property structure. Absent exploitation evidence, this surface is documented as a coverage gap and recommended for manual analyst inspection during incident triage.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
