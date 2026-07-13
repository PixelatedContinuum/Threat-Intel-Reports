---
title: "Detection Rules — FlaskC2-PostEx-Toolkit-67.215.232.25"
date: '2026-06-12'
layout: post
permalink: /hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
thumbnail: /assets/images/cards/flaskc2-postex-toolkit-67-215-232-25.png
hide: true
---

**Campaign:** FlaskC2-PostEx-Toolkit-67.215.232.25
**Date:** 2026-06-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/flaskc2-postex-toolkit-67-215-232-25/

---

## Detection Coverage Summary

A bespoke MSSQL SQL-CLR reverse-shell backdoor (`cmd_exec.dll`), two webshells (a Godzilla-style AES .NET loader and a commodity Ghost小组 ASP shell), and a bespoke Flask C2 panel were staged alongside a public Windows post-exploitation toolkit on a single host. Coverage here is scoped to the bespoke and commodity-configured components; the five operator-recompiled .NET tools (EfsPotato, GodPotato, SweetPotato, Rubeus, SharpSuccessor) are already detected by existing public YARA rules — those rules are referenced in Coverage Gaps rather than re-authored here.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1505.001, T1505.003, T1059.003, T1059.005, T1027.010, T1095, T1620, T1140 | 0 |
| Sigma | 3 | 3 | T1505.001, T1505.003, T1059.003, T1059.005, T1027.010, T1095, T1068 | 1 |
| Suricata | 1 | 2 | T1071.001, T1095, T1105 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- `MSSQL_CLR_Backdoor_CmdExec_Banner` — the operator-specific banner `[*] Connected to SQL Server CLR backdoor` is not present in any public MSSQL CLR reference implementation and evades generic sandboxes and mainstream AV (YARA Detection).
- `MSSQL CLR Backdoor Execution via sqlservr.exe Child cmd.exe` and `IIS Webshell Execution via w3wp.exe Spawning Shell Process` — family-agnostic process-ancestry chokepoints that catch the technique regardless of which specific CLR backdoor or webshell build is used (Sigma Detection).
- Flask C2 `/health` five-field JSON response fingerprint — re-anchored off the staging IP onto `$EXTERNAL_NET` during this pass, so the signature now survives infrastructure rotation (Suricata Detection).

**Atomics routed to the IOC feed:** the staging IP `67.215.232.25` and the six native-tool imphashes (JuicyPotato, PrintSpoofer, RoguePotato, RogueOxidResolver, Netcat nc64, CVE-2026-20817 PoC) were already present in [`flaskc2-postex-toolkit-67-215-232-25-iocs.json`](/ioc-feeds/flaskc2-postex-toolkit-67-215-232-25-iocs.json). The two rules that keyed solely on these hardcoded values — a pure-IP Suricata block and an imphash-only Sigma selector — are retired here; both indicators remain block/hunt-actionable via the feed.

---

## YARA Rules

### Detection Rules

#### cmd_exec.dll — MSSQL CLR Backdoor (Banner Anchor)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**Rationale:** The banner string `[*] Connected to SQL Server CLR backdoor` is a distinctive, operator-authored print string not present in any public MSSQL CLR reference implementation — a "typo banner"-class anchor. Robustness is capped at 2 rather than 3 because the banner is a removable print statement (an operator could strip it in a cleaned build); the paired 2-of-5 supporting-string clause is mostly generic SQLCLR/networking API names and does not itself add durable discrimination.
**False Positives:** None known — the banner string is operator-specific and not found in any legitimate SQL Server assembly.
**Blind Spots:** A rebuild that removes or changes the banner text evades this rule entirely; the companion "Assembly Structure" rule below provides fallback coverage for that scenario.
**Validation:** Scan the analyzed sample (`hash1` below) — the banner plus 2 of the 5 supporting strings must match; a legitimate SQL Server CLR assembly must NOT fire.
**Deployment:** Endpoint AV/EDR, memory scanner, .NET assembly inspection, MSSQL assembly staging directories.

```yara
/*
   Yara Rule Set
   Identifier: FlaskC2-PostEx-Toolkit-67.215.232.25 — MSSQL CLR Backdoor + Webshells
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MSSQL_CLR_Backdoor_CmdExec_Banner {
   meta:
      description = "Detects custom MSSQL SQL-CLR reverse-shell backdoor (cmd_exec.dll) based on operator-specific banner string combined with SQLCLR assembly markers and reverse-shell plumbing strings"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/"
      date = "2026-06-12"
      hash1 = "a7029ef2b6a541ef2b7508e1316d3c2efd3493108975ee457bcdb73043a25262"
      family = "MSSQL CLR Backdoor"
      malware_type = "Backdoor"
      campaign = "FlaskC2-PostEx-Toolkit-67.215.232.25"
      id = "4952ff03-a98c-54d3-9157-3a501e676b81"
   strings:
      $banner   = "[*] Connected to SQL Server CLR backdoor" ascii wide
      $sqlclr1  = "StoredProcedures" ascii wide
      $sqlclr2  = "Microsoft.SqlServer.Server" ascii wide
      $tcpcli   = "TcpClient" ascii wide
      $cmdexec  = "ExecuteCommand" ascii wide
      $slashc   = "cmd.exe" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 64KB and
      $banner and
      2 of ($sqlclr1, $sqlclr2, $tcpcli, $cmdexec, $slashc)
}
```

#### NPCInfoList1.aspx — AES .NET Loader Webshell (Godzilla-Style)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.003 (Web Shell), T1620 (Reflective Code Loading), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH
**Rationale:** The AES-128 key=IV `ca63457538b9b1e0` is hardcoded and reused for both key and initialization vector — an unusual, distinctive configuration artifact not present in stock Godzilla webshells (which derive the key via MD5). Robustness 2 rather than 3: the key is a per-build config constant that a redeployment could rotate, but it is not a filename and requires no combination to carry the rule.
**False Positives:** None known — the specific 16-byte hex string used as both AES key and IV is highly distinctive and not found in legitimate .NET applications.
**Blind Spots:** A redeployment that rotates the AES key evades this rule; memory-only delivery of the class-K payload is not covered (see Coverage Gaps).
**Validation:** Scan the analyzed sample (`hash1` below) — the key string plus at least one of the reflection/crypto API strings must match; a benign .NET application using RijndaelManaged for an unrelated purpose must NOT fire alone (the key literal is required).
**Deployment:** Web server file scanning, IIS directory monitoring, endpoint AV.

```yara
rule Webshell_NPCInfoList1_AES_Loader {
   meta:
      description = "Detects NPCInfoList1.aspx Godzilla-style AES .NET loader webshell based on hardcoded AES-128 key=IV value ca63457538b9b1e0 used for both key and initialization vector"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/"
      date = "2026-06-12"
      hash1 = "eb689aea9673cc025f91d8376da07e849519d19071609a60c193776d8eca8b54"
      family = "Godzilla-style .NET loader webshell"
      malware_type = "Webshell"
      campaign = "FlaskC2-PostEx-Toolkit-67.215.232.25"
      id = "c8c8d323-6db6-565a-a13a-0fd9e927c655"
   strings:
      $aeskey   = "ca63457538b9b1e0" ascii wide
      $asmload  = "Assembly.Load" ascii wide
      $createi  = "CreateInstance" ascii wide
      $aescbc   = "RijndaelManaged" ascii wide
   condition:
      filesize < 32KB and
      $aeskey and
      ($asmload or $createi or $aescbc)
}
```

### Hunting Rules

#### cmd_exec.dll — MSSQL CLR Backdoor (Assembly Structure)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1059.003 (Windows Command Shell), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**Rationale:** Requires four independent clauses (SQLCLR marker, exec-method name, network class, process-output-redirect API) to all hold — a genuine combination, not a single renameable literal. Kept at Hunting rather than Detection because the original assessment flagged real ambiguity: legitimate MSSQL CLR assemblies can use `TcpClient`, and the exec-method clause can be satisfied by the generic `ExecuteCommand` name alone rather than the more distinctive `reverse_shell`/`cmd_exec` names.
**False Positives:** A legitimate MSSQL CLR assembly that combines TCP networking, process spawning with output capture, and a method named `ExecuteCommand` (a common DB-access-layer naming convention) could satisfy all four clauses without being malicious.
**Deployment:** Endpoint AV/EDR, MSSQL assembly inspection, memory scanner — use as a broader corpus sweep alongside the Banner Anchor Detection rule above, not as a standalone alerting rule.

```yara
rule MSSQL_CLR_Backdoor_CmdExec_Assembly_Strings {
   meta:
      description = "Detects MSSQL SQL-CLR reverse-shell assemblies using the stored-procedure-exposed cmd-execution pattern, covering cmd_exec.dll variants where the banner string may be changed"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/"
      date = "2026-06-12"
      hash1 = "a7029ef2b6a541ef2b7508e1316d3c2efd3493108975ee457bcdb73043a25262"
      family = "MSSQL CLR Backdoor"
      malware_type = "Backdoor"
      campaign = "FlaskC2-PostEx-Toolkit-67.215.232.25"
      id = "ad2ab99c-79cd-5cd1-9592-a91cd00c8334"
   strings:
      $sqlclr1  = "Microsoft.SqlServer.Server" ascii wide
      $sqlclr2  = "SqlProcedureAttribute" ascii wide
      $method1  = "reverse_shell" ascii wide
      $method2  = "cmd_exec" ascii wide
      $method3  = "ExecuteCommand" ascii wide
      $tcpcli   = "TcpClient" ascii wide
      $netstr   = "NetworkStream" ascii wide
      $procsi   = "ProcessStartInfo" ascii wide
      $redir    = "RedirectStandardOutput" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 256KB and
      ($sqlclr1 or $sqlclr2) and
      ($method1 or $method2 or $method3) and
      ($tcpcli or $netstr) and
      ($procsi or $redir)
}
```

#### miss.asp — Ghost小组 ASP Webshell (Aatrox Eval Gadget)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.005 (Visual Basic), T1027.010 (Command Obfuscation)
**Confidence:** MODERATE
**Rationale:** The rule's real discriminating power rests on a single operator-chosen literal (`Aatrox`, the webshell's configured password/eval-gadget name, in either of two close variants) — durable against a `Ghost小组` family-wide rebrand but not against this specific deployment choosing a different password. The paired clause (`Ghost` OR `WScript.Shell` OR `Scripting.FileSystemObject`) adds little: the latter two APIs are near-ubiquitous in any ASP webshell, legitimate or not.
**False Positives:** `Ghost小组` alone matches the entire globally-reused public webshell family; `Aatrox` alone is a common League of Legends reference. The combination reduces but does not eliminate FP risk — this is a scoping lead, not an alerting-grade signature.
**Deployment:** Web server file scanning, IIS directory monitoring, endpoint AV — corpus sweep for this specific configured instance.

```yara
rule Webshell_Ghost_Aatrox_ASP {
   meta:
      description = "Detects Ghost small-group (Ghost xiao-zu) ASP webshell variant configured with Aatrox password and eval gadget, as staged in the FlaskC2-PostEx-Toolkit-67.215.232.25 campaign"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/"
      date = "2026-06-12"
      hash1 = "30a11ac0b6828fd1c808c46d1c5ae9a4050b48a2fa7e860d146d871bc7c9bb98"
      family = "Ghost ASP Webshell"
      malware_type = "Webshell"
      campaign = "FlaskC2-PostEx-Toolkit-67.215.232.25"
      id = "33fc80d4-77b7-5790-8ecf-85379a0ddcbb"
   strings:
      $ghost    = "Ghost" ascii wide nocase
      $eval1    = "Execute Session(\"Aatrox\")" ascii wide
      $eval2    = "UserPass=\"Aatrox\"" ascii wide
      $wshhell  = "WScript.Shell" ascii wide
      $fso      = "Scripting.FileSystemObject" ascii wide
   condition:
      filesize < 200KB and
      ($eval1 or $eval2) and
      ($ghost or $wshhell or $fso)
}
```

---

## Sigma Rules

### Detection Rules

#### MSSQL CLR Backdoor — sqlservr.exe Spawning cmd.exe Child

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1059.003 (Windows Command Shell)
**Confidence:** HIGH
**Rationale:** SQL Server does not spawn `cmd.exe` in normal operation. This process-ancestry pairing is a technique chokepoint — it catches ANY SQL-CLR stored procedure that shells out, regardless of which specific backdoor build is used, and survives recompilation or renaming of the CLR assembly itself.
**False Positives:** Legitimate administrative use of `xp_cmdshell` generates the same pattern — baseline and exclude authorized instances. SQL Server maintenance jobs that intentionally invoke `cmd.exe` via CLR or job steps.
**Blind Spots:** A CLR backdoor that shells out via a mechanism other than spawning `cmd.exe` directly (e.g., in-process `Process.Start` of a non-cmd binary) is not covered.
**Validation:** Trigger a SQL-CLR stored procedure that spawns `cmd.exe` — must match; routine SQL Server query execution with no shell spawn must NOT fire.
**Deployment:** Sysmon (Event ID 1), Windows Security Event Log (4688), EDR process telemetry.

```yaml
title: MSSQL CLR Backdoor Execution via sqlservr.exe Child cmd.exe
id: 124c3140-63a5-4f3c-9700-c3893edd971b
status: experimental
description: >-
  Detects cmd.exe spawned as a child of sqlservr.exe, indicating execution of a
  SQL Server CLR stored procedure that runs shell commands. This is the primary
  behavioral signature of the cmd_exec.dll MSSQL CLR reverse-shell backdoor,
  which evades generic sandboxes and most AV engines.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://github.com/evi1ox/MSSQL_BackDoor
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.persistence
    - attack.t1505.001
    - attack.execution
    - attack.t1059.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sqlservr.exe'
        Image|endswith: '\cmd.exe'
    condition: selection
falsepositives:
    - Legitimate administrative use of xp_cmdshell — baseline and exclude authorized instances
    - SQL Server maintenance jobs that intentionally invoke cmd.exe via CLR or job steps
level: high
```

#### MSSQL CLR Assembly Enablement and Reverse-Shell Procedure Registration

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures)
**Confidence:** HIGH
**Rationale:** Tightened during this pass — the original condition OR'd in `CREATE ASSEMBLY` and `EXTERNAL NAME` as standalone triggers, but both phrases appear in ordinary, legitimate SQLCLR deployment activity (custom aggregates, data-type extensions) with no distinguishing filter, which dragged the whole rule toward baseline noise. The rule now keeps only the two genuinely rare/distinctive signals: CLR enablement via `sp_configure` (EventID 15457, disabled by default and rarely toggled in production) and the `reverse_shell` procedure name in `EXTERNAL NAME` registration (zero legitimate use).
**False Positives:** Authorized .NET CLR assembly deployment by DBAs that also happens to enable CLR in the same change window — correlate with change management tickets. Development environments where CLR assemblies are used legitimately.
**Blind Spots:** A build that registers the reverse-shell procedure under a different name than `reverse_shell` evades the second selector; CLR enablement alone (first selector) still provides fallback coverage if the environment doesn't already have CLR enabled.
**Validation:** Trigger CLR enablement via `sp_configure 'clr enabled', 1` or register a procedure via `EXTERNAL NAME` referencing a `reverse_shell` method — either must match; routine SQL Server query activity with CLR already disabled must NOT fire.
**Deployment:** SQL Server Audit / Extended Events, Windows Application Event Log (MSSQL error log integration), SIEM with SQL Server log ingestion.

```yaml
title: MSSQL CLR Backdoor Installation via CREATE ASSEMBLY and Reverse Shell Procedure
id: 68e96847-afed-4fbd-843f-952e22e89f97
status: experimental
description: >-
  Detects SQL Server CLR backdoor installation indicators: enabling CLR
  execution via sp_configure, or registering a stored procedure named
  reverse_shell via EXTERNAL NAME. The reverse_shell procedure name has
  no legitimate use and is a direct indicator of cmd_exec.dll
  installation; CLR enablement alone is rare in production and disabled
  by default.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://www.netspi.com/blog/technical/network-penetration-testing/attacking-sql-server-clr-assemblies/
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.persistence
    - attack.t1505.001
    - detection.emerging-threats
logsource:
    product: windows
    service: application
detection:
    selection_clr:
        Provider_Name|contains: 'MSSQL'
        EventID: 15457
        Message|contains: 'clr enabled'
    selection_reverse_shell:
        Provider_Name|contains: 'MSSQL'
        Message|contains: 'reverse_shell'
    condition: selection_clr or selection_reverse_shell
falsepositives:
    - Authorized .NET CLR assembly deployment by DBAs — correlate with change management tickets
    - Development environments where CLR assemblies are used legitimately
level: high
```

#### IIS Webshell Execution — w3wp.exe Spawning cmd.exe or WScript

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.003 (Windows Command Shell), T1059.005 (Visual Basic)
**Confidence:** HIGH
**Rationale:** IIS worker process spawning a shell interpreter is a well-established, family-agnostic technique chokepoint for webshell command execution — it catches both webshells staged in this campaign (`miss.asp` via `WScript.Shell`, `NPCInfoList1.aspx` via its loaded payload) and any other webshell family exercising the same execution pattern, and survives any campaign-specific renaming.
**False Positives:** Legacy web applications that intentionally invoke shell processes from application code — baseline expected patterns. Authorized IIS management scripts running under the application pool identity.
**Blind Spots:** A webshell that executes entirely in-process (no child process spawn — e.g., pure .NET reflection without a shell hop) is not covered by this rule.
**Validation:** Trigger a webshell command that shells out from `w3wp.exe` — must match; normal IIS request handling with no shell spawn must NOT fire.
**Deployment:** Sysmon (Event ID 1), Windows Security Event Log (4688), EDR process telemetry.

```yaml
title: IIS Webshell Execution via w3wp.exe Spawning Shell Process
id: bb2d9a6a-be5b-47e2-9902-ebbdc4831aa6
status: experimental
description: >-
  Detects IIS worker process (w3wp.exe) spawning cmd.exe or wscript.exe, which
  indicates webshell-based command execution. In the FlaskC2-PostEx-Toolkit
  campaign, both miss.asp (Ghost xiao-zu ASP webshell via WScript.Shell) and
  NPCInfoList1.aspx (Godzilla-style .NET loader) run under w3wp.exe and can
  spawn shell processes when executing operator commands.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.execution
    - attack.t1059.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\w3wp.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\powershell.exe'
    condition: selection
falsepositives:
    - Legacy web applications that intentionally invoke shell processes — baseline expected patterns
    - Authorized IIS management scripts running under the application pool identity
level: high
```

### Hunting Rules

#### MSSQL CLR Backdoor — Outbound TCP Connection from sqlservr.exe

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**Rationale:** Behaviorally durable (no renameable literal — pure process-plus-destination-class logic), but the rule fires on any external connection from `sqlservr.exe`, and three common, legitimate enterprise patterns (replication, linked servers, Database Mail) require environment-specific baselining before this stops being meaningfully noisy. Demoted from the original `high` level to a Hunting scoping lead.
**False Positives:** SQL Server linked servers pointing to external databases. Database Mail (SMTP outbound) — filter by port 25/587. SQL Server replication to external publishers — baseline expected destination IPs.
**Deployment:** Sysmon (Event ID 3), network flow telemetry, EDR network telemetry — baseline per environment before considering promotion to Detection.

```yaml
title: MSSQL sqlservr.exe Initiating Outbound TCP Connection to External Host
id: d04749cf-8423-4bbb-9fdc-cc5035787772
status: experimental
description: >-
  Detects SQL Server process (sqlservr.exe) initiating outbound TCP connections
  to external hosts. In the FlaskC2-PostEx-Toolkit campaign, cmd_exec.dll opens
  a raw reverse-TCP shell from within sqlservr.exe to operator-supplied IP and
  port parameters. Legitimate outbound connections from sqlservr.exe should be
  baselined and filtered.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.persistence
    - attack.t1505.001
    - attack.command-and-control
    - attack.t1095
    - detection.emerging-threats
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\sqlservr.exe'
        Initiated: 'true'
    filter_loopback:
        DestinationIp|startswith:
            - '127.'
            - '::1'
            - '10.'
            - '172.16.'
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - '192.168.'
    condition: selection and not filter_loopback
falsepositives:
    - SQL Server linked servers pointing to external databases
    - Database Mail (SMTP outbound) — filter by port 25/587
    - SQL Server replication to external publishers — baseline expected destination IPs
level: medium
```

#### Webshell Eval Gadget — Aatrox Query Parameter

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1505.003 (Web Shell), T1027.010 (Command Obfuscation)
**Confidence:** MODERATE
**Rationale:** Corrected during this pass — the original rule's `selection_body` clause matched any `POST` to any `.asp` file with no check for the `Aatrox` literal at all, making the rule fire on ordinary classic-ASP form submissions. That clause has been removed; the rule now matches only the genuinely distinctive `Aatrox` query-string parameter. This remains a single operator-chosen literal (this deployment's webshell password/eval-trigger), durable against a family-wide rebrand but not against a different password choice.
**False Positives:** `Aatrox` is a League of Legends champion name and could theoretically appear in legitimate gaming-related web content; highly anomalous as a query parameter against a corporate IIS `.asp` endpoint.
**Deployment:** IIS access logs, SIEM with web server log ingestion, WAF log monitoring.

```yaml
title: Ghost Webshell Aatrox Eval Gadget Parameter in IIS Request
id: f2509a7c-9505-4b23-a2b4-b7619999f327
status: experimental
description: >-
  Detects the Aatrox eval gadget parameter in the query string of IIS
  web requests to .asp files, indicating interaction with the Ghost
  xiao-zu ASP webshell (miss.asp) as staged in the FlaskC2-PostEx-Toolkit
  campaign. The webshell stores and executes arbitrary VBScript via
  Execute Session("Aatrox") when the Aatrox parameter is present.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.stealth
    - attack.t1027.010
    - detection.emerging-threats
logsource:
    category: webserver
    product: iis
detection:
    selection:
        cs-uri-stem|endswith: '.asp'
        cs-uri-query|contains: 'Aatrox'
    condition: selection
falsepositives:
    - >-
      Aatrox is a League of Legends champion name and could theoretically
      appear in legitimate gaming-related web content; highly anomalous
      as a query parameter against a corporate IIS .asp endpoint
level: medium
```

#### CVE-2026-20817 WER LPE PoC — Anomalous WerFault.exe Token Inspection

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** MODERATE
**Rationale:** The process-access pattern (a non-WER process opening `WerFault.exe`'s token) is a genuine, durable technique signal, but the original assessment's own FP Risk of HIGH and narrow applicability window (only relevant on hosts missing the January 2026 cumulative update, and the analyzed sample is a non-weaponized PoC that never achieves elevation) keep this at Hunting rather than Detection.
**False Positives:** EDR and security tooling that monitors WerFault.exe token state. Crash reporting integrations that inspect WerFault process state. Only deploy on unpatched hosts (pre-January 2026 Windows cumulative update) — patched hosts render this moot.
**Deployment:** Sysmon (Event ID 10 — ProcessAccess), EDR process-access telemetry. Deploy only on hosts running Windows 10/11 or Server 2019/2022 without the January 2026 cumulative update, or for retrospective hunting.

```yaml
title: CVE-2026-20817 WER LPE PoC Token Inspection of WerFault.exe
id: ff8ee6c2-d705-4ebf-98bd-6ead3d775ae0
status: experimental
description: >-
  Detects process access events targeting WerFault.exe with token query rights,
  consistent with the CVE-2026-20817 WER ALPC local-privilege-escalation PoC
  present in the FlaskC2-PostEx-Toolkit campaign. The PoC enumerates processes
  looking for WerFault.exe and inspects its token privileges. This rule is
  relevant only on hosts missing the January 2026 Windows cumulative update;
  the sample analyzed is non-weaponized and does not achieve elevation.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://github.com/oxfemale/CVE-2026-20817
    - https://itm4n.github.io/cve-2026-20817-wersvc-eop/
author: The Hunters Ledger
date: '2026-06-12'
tags:
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\WerFault.exe'
        GrantedAccess|contains: '0x20'
    filter_system:
        SourceImage|endswith:
            - '\WerMgr.exe'
            - '\svchost.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_system
falsepositives:
    - EDR and security tooling that monitors WerFault.exe token state
    - Crash reporting integrations that inspect WerFault process state
    - Only deploy on unpatched hosts (pre-January 2026 Windows cumulative update)
level: low
```

---

## Suricata Signatures

### Detection Rules

#### Flask C2 Health Endpoint — Distinctive JSON Field-Combo

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**Rationale:** The `/health` endpoint returns a JSON object with a five-field combination (`active_servers`, `pending_commands`, `completed_commands`, `status`, `timestamp`) not found in any known public C2 framework or web application framework — a genuine protocol/config fingerprint. Re-anchored during this pass: the original rule pinned the destination to the single staging IP, which would blind the signature the moment the operator moves infrastructure; the destination is now `$EXTERNAL_NET`, so the content match — which carries all of the rule's real discrimination — survives infrastructure rotation.
**False Positives:** None known — the specific combination of all five JSON field names in a single response is uniquely characteristic of this C2 implementation.
**Blind Spots:** A rebuild of the C2 panel that changes the `/health` response field names or their combination evades this rule; TLS-terminated traffic without inspection visibility is not covered.
**Validation:** Replay an HTTP response from a live instance of this C2's `/health` endpoint — must alert; an unrelated Werkzeug/Flask application's JSON response must NOT fire.
**Deployment:** Network IDS/IPS, perimeter firewall with DPI capability, SIEM with network flow data.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL FlaskC2-PostEx C2 Health Endpoint Response - Bespoke Flask C2 Active"; flow:established,to_client; file_data; content:"active_servers"; nocase; content:"pending_commands"; nocase; distance:0; content:"completed_commands"; nocase; distance:0; content:"status"; nocase; distance:0; content:"timestamp"; nocase; distance:0; classtype:trojan-activity; sid:9001001; rev:2; metadata:author The_Hunters_Ledger, date 2026-06-12, reference https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;)
```

### Hunting Rules

#### Flask C2 Beacon Endpoint — POST to /api/report

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**Rationale:** `/api/report` is a plausible, generic path segment used by many legitimate telemetry and error-reporting APIs across the internet — a single URI-path literal with no corroborating anchor (no distinctive header, response code, or body pattern). Deployed at a perimeter watching all outbound HTTP (no destination pinning, matching the campaign's intent to survive infrastructure rotation), this is a genuine scoping lead rather than an alerting-grade signature. Corrected the original rule's `msg`, which claimed coverage of `/api/heartbeat` as well — this rule only ever matched `/api/report`.
**False Positives:** Any legitimate application whose API exposes a `/api/report` POST endpoint (common naming convention for telemetry/error-reporting); the `threshold` limits alert volume per source but does not address the underlying path-genericity.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```
alert http $HOME_NET any -> any any (msg:"THL FlaskC2-PostEx C2 Beacon POST to /api/report"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/report"; nocase; classtype:trojan-activity; sid:9001002; rev:2; metadata:author The_Hunters_Ledger, date 2026-06-12, reference https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;)
```

#### Flask C2 Beacon Endpoint — POST to /api/heartbeat

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**Rationale:** `/api/heartbeat` is an extremely common naming convention for health-check/keepalive endpoints across the microservices and monitoring-agent ecosystem — a single URI-path literal with no corroborating anchor. Same durability profile as the `/api/report` sibling rule: no destination pinning, so it survives infrastructure rotation, but the path segment alone is not distinctive enough to clear the Detection precision bar.
**False Positives:** Any legitimate application's heartbeat/keepalive POST endpoint — this is one of the most common REST API path conventions in use; the `threshold` limits alert volume per source but does not address the underlying path-genericity.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```
alert http $HOME_NET any -> any any (msg:"THL FlaskC2-PostEx C2 Beacon POST to /api/heartbeat"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/heartbeat"; nocase; classtype:trojan-activity; sid:9001003; rev:2; metadata:author The_Hunters_Ledger, date 2026-06-12, reference https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;)
```

---

## Coverage Gaps

**Atomics retired from this pass (2 rules).** A Sigma rule matching solely on six native-tool imphashes (T1134.001 — JuicyPotato, PrintSpoofer, RoguePotato, RogueOxidResolver, Netcat nc64, CVE-2026-20817 PoC) and a Suricata pure-IP block on `67.215.232.25` both keyed entirely on hardcoded values with no behavioral qualifier — per the tiering rubric's routing test, removing the literal leaves nothing to detect. All seven underlying values were already present in [`flaskc2-postex-toolkit-67-215-232-25-iocs.json`](/ioc-feeds/flaskc2-postex-toolkit-67-215-232-25-iocs.json) (imphashes under `file_hashes.imphashes` with `action: HUNT`; the IP under `network_indicators.ipv4` with `action: BLOCK`) — no feed edits were required. T1134.001 (Token Impersonation/Theft) is consequently no longer represented by a standalone rule in this file; the capability remains hunt-actionable via the feed.

**T1071.001 — Web Protocols (Flask C2 beacon implant, Type B artifact)**
The beacon implant — the agent binary that POSTs to `/api/report` and `/api/heartbeat` — was not recovered. It is a Type B artifact: operator-pushed to a victim at runtime, never staged in the `:1337` open directory. `VT communicating_files=0` for this IP confirms no sample has been observed beaconing to this C2. Without the implant, no file-level YARA or behavioral Sigma can be authored for the client side. Evidence needed to close this gap: victim endpoint forensics, memory acquisition from a compromised host, or capture of the implant via network proxy on a live victim system.

**T1620 — Reflective Code Loading (NPCInfoList1.aspx class-K payload)**
The in-memory .NET assembly loaded by the Godzilla-style webshell (`class K`) is a Type B artifact — it is AES-128-CBC encrypted in transit and delivered by the operator on demand, never written to disk, and not recoverable from the open directory. The YARA rule authored here detects the *loader* (NPCInfoList1.aspx) but cannot detect the *payload*. Evidence needed: network capture of a POST body to NPCInfoList1.aspx (which would contain the AES-encrypted payload), or victim endpoint memory acquisition.

**T1134.001 + T1068 — Potato Suite (operator-recompiled .NET tools)**
EfsPotato, GodPotato, SweetPotato, Rubeus, and SharpSuccessor were operator-recompiled from source, defeating hash-based detection. Existing public YARA rules already cover these tools via type-lib GUID matching and string-based signatures:
- `HKTL_NET_GUID_SweetPotato` (Neo23x0/signature-base) — SweetPotato
- `tool_efspotato` + `tool_sharpefspotato_strings` (Neo23x0/signature-base) — EfsPotato
- `Windows_Exploit_FakePipe` (Elastic) — EfsPotato/PetitPotam
- GhostPack Rubeus rules (Neo23x0/signature-base) — Rubeus
- These rules fire on the operator-recompiled builds in this campaign (confirmed via VirusTotal)
These rules are not re-authored here to avoid duplication. Deploy the referenced rules from Neo23x0/signature-base.

**T1558.003, T1558.001, T1550.003 — Kerberos Abuse (Rubeus)**
Rubeus behavioral detection (Kerberoasting, Golden Ticket, Pass the Ticket) is covered by existing Sigma rules in the SigmaHQ repository (search `rubeus` in the `windows/process_creation/` rules). These are not re-authored. The operator-recompiled Rubeus binary is identified at the file level by the referenced Neo23x0 rules.

**T1095 — Non-Application Layer Protocol (raw reverse-TCP shell)**
The cmd_exec.dll reverse-shell channel is plaintext raw TCP with no protocol framing, making Suricata application-layer signature matching impractical. The operator supplies the destination IP and port at `EXEC` time (no hardcoded C2), so no IP-based block is possible for the shell channel itself. Detection coverage for this channel relies on the Sigma rule (sqlservr.exe outbound TCP, Hunting tier) rather than Suricata DPI.

**T1021 — Remote Services (lateral movement)**
No specific lateral movement artifacts were recovered from the open directory. Rubeus and SharpSuccessor provide the capability, but no lateral movement commands, target host lists, or SMB/WinRM usage were observed in the static analysis. Coverage relies on existing Kerberos-abuse and SharpSuccessor detection rules in SigmaHQ.

---

## License

Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
