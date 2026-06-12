---
title: "Detection Rules — FlaskC2-PostEx-Toolkit-67.215.232.25"
date: '2026-06-12'
layout: post
permalink: /hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
hide: true
unlisted: true
---

**Campaign:** FlaskC2-PostEx-Toolkit-67.215.232.25
**Date:** 2026-06-12
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/flaskc2-postex-toolkit-67-215-232-25/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 4 | T1505.001, T1505.003, T1620, T1140 | LOW–MEDIUM |
| Sigma | 7 | T1505.001, T1505.003, T1059.003, T1134.001, T1068, T1027.010, T1071.001 | LOW–MEDIUM |
| Suricata | 3 | T1071.001, T1095, T1105 | LOW |

**Scope note:** Detection scope for this campaign covers bespoke and commodity-configured items. The five operator-recompiled .NET tools (EfsPotato, GodPotato, SweetPotato, Rubeus, SharpSuccessor) are already detected by existing public YARA rules — those rules are referenced in the Coverage Gaps section rather than re-authored here.

**Highest-value rule:** `MSSQL_CLR_Backdoor_CmdExec_Banner` — the `cmd_exec.dll` banner string `[*] Connected to SQL Server CLR backdoor` is a high-confidence, operator-specific anchor for a backdoor that evades generic sandboxes (Zenbox 98% harmless) and is scored clean by Microsoft and Kaspersky AV.

---

## YARA Rules

```
/*
   Yara Rule Set
   Identifier: FlaskC2-PostEx-Toolkit-67.215.232.25 — MSSQL CLR Backdoor + Webshells
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/
```

### cmd_exec.dll — MSSQL CLR Backdoor (Banner Anchor — Highest Value)

**Detection Priority:** HIGH
**Rationale:** The banner string `[*] Connected to SQL Server CLR backdoor` is specific to this operator's custom build and is not present in any public MSSQL CLR reference implementation. Combined with SQLCLR namespace markers and reverse-shell plumbing, this rule targets a backdoor that evades generic sandboxes (VT Zenbox 98% harmless) and is scored clean by Microsoft and Kaspersky AV.
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW — the banner string is operator-specific; the combination with SQLCLR attributes is not present in any legitimate SQL Server assembly.
**Deployment:** Endpoint AV/EDR, memory scanner, .NET assembly inspection, MSSQL assembly staging directories

```yara
rule MSSQL_CLR_Backdoor_CmdExec_Banner {
   meta:
      description = "Detects custom MSSQL SQL-CLR reverse-shell backdoor (cmd_exec.dll) based on operator-specific banner string combined with SQLCLR assembly markers and reverse-shell plumbing strings"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

---

### cmd_exec.dll — MSSQL CLR Backdoor (Assembly Structure — Broader Coverage)

**Detection Priority:** MEDIUM
**Rationale:** Catches MSSQL CLR reverse-shell assemblies built from the same public technique (evi1ox/MSSQL_BackDoor, Metasploit mssql_clr_payload pattern) even if the operator changes the banner string. Requires the SQLCLR stored-procedure registration pattern combined with raw TCP socket and hidden cmd.exe execution strings. Will match variants that omit or rename the banner.
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1059.003 (Windows Command Shell), T1095 (Non-Application Layer Protocol)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — legitimate MSSQL CLR assemblies may use TcpClient; the `reverse_shell` or `cmd_exec` method name combined with SqlProcedureAttribute narrows this significantly.
**Deployment:** Endpoint AV/EDR, MSSQL assembly inspection, memory scanner

```yara
rule MSSQL_CLR_Backdoor_CmdExec_Assembly_Strings {
   meta:
      description = "Detects MSSQL SQL-CLR reverse-shell assemblies using the stored-procedure-exposed cmd-execution pattern, covering cmd_exec.dll variants where the banner string may be changed"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

---

### NPCInfoList1.aspx — AES .NET Loader Webshell (Godzilla-Style)

**Detection Priority:** HIGH
**Rationale:** The AES-128 key=IV `ca63457538b9b1e0` is hardcoded in the webshell and used for both key and initialization vector — an unusual, detectable configuration not present in stock Godzilla webshells (which derive the key via MD5). This is the strongest file-level anchor for this specific loader variant.
**ATT&CK Coverage:** T1505.003 (Web Shell), T1620 (Reflective Code Loading), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific 16-byte hex string used as both AES key and IV is highly distinctive and not found in legitimate .NET applications.
**Deployment:** Web server file scanning, IIS directory monitoring, endpoint AV

```yara
rule Webshell_NPCInfoList1_AES_Loader {
   meta:
      description = "Detects NPCInfoList1.aspx Godzilla-style AES .NET loader webshell based on hardcoded AES-128 key=IV value ca63457538b9b1e0 used for both key and initialization vector"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

---

### miss.asp — Ghost小组 ASP Webshell (Aatrox Eval Gadget)

**Detection Priority:** MEDIUM
**Rationale:** Two complementary anchors: the `Ghost小组` gb2312 title identifies the public Chinese ASP webshell family; `Execute Session("Aatrox")` / `UserPass="Aatrox"` are the operator-configured password and stored eval gadget. The eval gadget pattern is particularly valuable because it persists in session across requests.
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.005 (Visual Basic), T1027.010 (Command Obfuscation)
**Confidence:** HIGH (for the Aatrox anchor — commodity reuse of this password is possible)
**False Positive Risk:** MEDIUM — `Ghost小组` alone matches the entire webshell family (globally reused); `Aatrox` alone is a common gaming reference. The combination reduces FP risk substantially. Tune by requiring both anchors if single-anchor FP rate is high.
**Deployment:** Web server file scanning, IIS directory monitoring, endpoint AV

```yara
rule Webshell_Ghost_Aatrox_ASP {
   meta:
      description = "Detects Ghost small-group (Ghost xiao-zu) ASP webshell variant configured with Aatrox password and eval gadget, as staged in the FlaskC2-PostEx-Toolkit-67.215.232.25 campaign"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

### MSSQL CLR Backdoor — sqlservr.exe Spawning cmd.exe Child

**Detection Priority:** HIGH
**Rationale:** SQL Server (`sqlservr.exe`) does not spawn `cmd.exe` in normal operation. A child `cmd.exe` process under `sqlservr.exe` is a strong indicator that a SQL-CLR stored procedure is executing shell commands — the core behavioral signature of cmd_exec.dll. This catches the backdoor at execution time regardless of whether the DLL is on disk.
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1059.003 (Windows Command Shell)
**Confidence:** HIGH
**False Positive Risk:** LOW — legitimate SQL Server workloads do not spawn cmd.exe; administrative scripts that do (e.g., xp_cmdshell) generate the same pattern and should be baselined and excluded via allowlist.
**Deployment:** Sysmon (Event ID 1), Windows Security Event Log (4688), EDR process telemetry

```yaml
title: MSSQL CLR Backdoor Execution via sqlservr.exe Child cmd.exe
id: 124c3140-63a5-4f3c-9700-c3893edd971b
status: test
description: >-
  Detects cmd.exe spawned as a child of sqlservr.exe, indicating execution of a
  SQL Server CLR stored procedure that runs shell commands. This is the primary
  behavioral signature of the cmd_exec.dll MSSQL CLR reverse-shell backdoor,
  which evades generic sandboxes and most AV engines.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://github.com/evi1ox/MSSQL_BackDoor
    - https://attack.mitre.org/techniques/T1505/001/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.persistence
    - attack.t1505.001
    - attack.execution
    - attack.t1059.003
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

---

### MSSQL CLR Backdoor — Outbound TCP Connection from sqlservr.exe

**Detection Priority:** HIGH
**Rationale:** SQL Server initiates outbound TCP connections for replication, linked servers, and mail — but these go to known, expected destinations. An outbound TCP connection to an unknown external IP from `sqlservr.exe` on a non-standard port (not 1433/445/25) indicates a CLR reverse-shell attempting to connect to operator infrastructure.
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW–MEDIUM — requires tuning to exclude known SQL Server replication targets, linked server destinations, and Database Mail SMTP. Most environments have a small, stable set of expected outbound SQL Server connections.
**Deployment:** Sysmon (Event ID 3), network flow telemetry, EDR network telemetry

```yaml
title: MSSQL sqlservr.exe Initiating Outbound TCP Connection to External Host
id: d04749cf-8423-4bbb-9fdc-cc5035787772
status: test
description: >-
  Detects SQL Server process (sqlservr.exe) initiating outbound TCP connections
  to external hosts. In the FlaskC2-PostEx-Toolkit campaign, cmd_exec.dll opens
  a raw reverse-TCP shell from within sqlservr.exe to operator-supplied IP and
  port parameters. Legitimate outbound connections from sqlservr.exe should be
  baselined and filtered.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://attack.mitre.org/techniques/T1505/001/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.persistence
    - attack.t1505.001
    - attack.command-and-control
    - attack.t1095
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
level: high
```

---

### MSSQL CLR Assembly Enablement and Backdoor Installation

**Detection Priority:** HIGH
**Rationale:** The `sp_configure 'clr enabled'` + `CREATE ASSEMBLY` + `CREATE PROCEDURE ... EXTERNAL NAME` sequence is the installation footprint of any SQL-CLR backdoor. The combination of enabling CLR (unusual in production environments), creating an assembly from binary, and registering a procedure named `reverse_shell` is a direct installation signature for cmd_exec.dll. Even without the procedure name, the sequence alone warrants investigation.
**ATT&CK Coverage:** T1505.001 (SQL Stored Procedures)
**Confidence:** HIGH
**False Positive Risk:** LOW — CLR enablement is disabled by default and rarely changed. `CREATE ASSEMBLY` from a binary is a developer or DBA action that should be logged and approved. The procedure name `reverse_shell` in `EXTERNAL NAME` has zero legitimate use.
**Deployment:** SQL Server Audit / Extended Events, Windows Application Event Log (MSSQL error log integration), SIEM with SQL Server log ingestion

```yaml
title: MSSQL CLR Backdoor Installation via CREATE ASSEMBLY and Reverse Shell Procedure
id: 68e96847-afed-4fbd-843f-952e22e89f97
status: test
description: >-
  Detects SQL Server CLR backdoor installation sequence: enabling CLR execution,
  creating an assembly from binary, and registering a stored procedure via
  EXTERNAL NAME. The procedure name reverse_shell in EXTERNAL NAME is a direct
  indicator of cmd_exec.dll installation. Even without the procedure name, this
  sequence in production is high-risk.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://www.netspi.com/blog/technical/network-penetration-testing/attacking-sql-server-clr-assemblies/
    - https://attack.mitre.org/techniques/T1505/001/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.persistence
    - attack.t1505.001
logsource:
    category: application
    product: sql_server
detection:
    selection_clr:
        EventID: 15457
        Message|contains: "clr enabled"
    selection_assembly:
        Message|contains:
            - 'CREATE ASSEMBLY'
            - 'EXTERNAL NAME'
            - 'reverse_shell'
    condition: selection_clr or selection_assembly
falsepositives:
    - Authorized .NET CLR assembly deployment by DBAs — correlate with change management tickets
    - Development environments where CLR assemblies are used legitimately
level: high
```

---

### IIS Webshell Execution — w3wp.exe Spawning cmd.exe or WScript

**Detection Priority:** HIGH
**Rationale:** IIS worker process (`w3wp.exe`) spawning `cmd.exe` or `wscript.exe` is the behavioral hallmark of a webshell executing operator commands. This covers both the `miss.asp` Ghost小组 webshell (which calls `WScript.Shell`) and any cmd-execution webshell deployed to the target IIS server.
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.003 (Windows Command Shell), T1059.005 (Visual Basic)
**Confidence:** HIGH
**False Positive Risk:** LOW–MEDIUM — legitimate applications occasionally spawn cmd.exe from w3wp.exe via legacy code; these should be baselined. Most modern IIS applications do not require shell execution.
**Deployment:** Sysmon (Event ID 1), Windows Security Event Log (4688), EDR process telemetry

```yaml
title: IIS Webshell Execution via w3wp.exe Spawning Shell Process
id: bb2d9a6a-be5b-47e2-9902-ebbdc4831aa6
status: test
description: >-
  Detects IIS worker process (w3wp.exe) spawning cmd.exe or wscript.exe, which
  indicates webshell-based command execution. In the FlaskC2-PostEx-Toolkit
  campaign, both miss.asp (Ghost xiao-zu ASP webshell via WScript.Shell) and
  NPCInfoList1.aspx (Godzilla-style .NET loader) run under w3wp.exe and can
  spawn shell processes when executing operator commands.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://attack.mitre.org/techniques/T1505/003/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.execution
    - attack.t1059.003
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

---

### Webshell Eval Gadget — Aatrox Session Parameter

**Detection Priority:** MEDIUM
**Rationale:** The `Execute Session("Aatrox")` gadget in miss.asp persists the eval backdoor across requests. Detection in IIS access logs or application logs for the `Aatrox` parameter in POST requests to .asp files indicates active webshell interaction with this specific webshell family configured with this password.
**ATT&CK Coverage:** T1505.003 (Web Shell), T1027.010 (Command Obfuscation)
**Confidence:** HIGH (the string is specific; commodity reuse of this password is possible but uncommon)
**False Positive Risk:** MEDIUM — `Aatrox` is a League of Legends champion name and could theoretically appear in legitimate gaming-related web content; in a corporate IIS context it is highly anomalous.
**Deployment:** IIS access logs, SIEM with web server log ingestion, WAF log monitoring

```yaml
title: Ghost Webshell Aatrox Eval Gadget Parameter in IIS Request
id: f2509a7c-9505-4b23-a2b4-b7619999f327
status: test
description: >-
  Detects the Aatrox eval gadget parameter in IIS web requests, indicating
  interaction with the Ghost xiao-zu ASP webshell (miss.asp) as staged in the
  FlaskC2-PostEx-Toolkit campaign. The webshell stores and executes arbitrary
  VBScript via Execute Session("Aatrox") when the Aatrox parameter is present.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://attack.mitre.org/techniques/T1505/003/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.defense-evasion
    - attack.t1027.010
logsource:
    category: webserver
    product: iis
detection:
    selection:
        cs-uri-stem|endswith: '.asp'
        cs-uri-query|contains: 'Aatrox'
    selection_body:
        cs-uri-stem|endswith: '.asp'
        cs-method: 'POST'
    condition: selection or selection_body
falsepositives:
    - Legitimate web applications with parameters containing the string Aatrox — extremely unlikely in corporate IIS environments
level: medium
```

---

### Native Post-Exploitation Tool Execution — Imphash Detection

**Detection Priority:** HIGH
**Rationale:** The six native tools in this toolkit (JuicyPotato, PrintSpoofer, RoguePotato, RogueOxidResolver, nc64, CVE-PoC) carry stable imphashes that survive renaming. Operators frequently rename these tools to evade filename-based detection; imphash-based detection catches them regardless of what the file is called.
**ATT&CK Coverage:** T1134.001 (Token Impersonation/Theft), T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**False Positive Risk:** LOW — these imphashes correspond to specific compiled builds of known privilege-escalation tools with no legitimate use in enterprise environments.
**Deployment:** Sysmon (Event ID 1 with hash enrichment), EDR process telemetry with imphash field

```yaml
title: FlaskC2-PostEx Native Tool Execution by Imphash
id: 617292af-db3a-48e3-b18f-69ed31aef19e
status: test
description: >-
  Detects execution of native post-exploitation tools from the
  FlaskC2-PostEx-Toolkit-67.215.232.25 campaign based on import-table hashes
  (imphash). The covered tools are JuicyPotato (f9a28c45), PrintSpoofer
  (545a8124), RoguePotato (959a8304), RogueOxidResolver (576d6e02), Netcat
  nc64 (567531f0), and CVE-2026-20817 PoC (818cfde6). Imphash-based detection
  survives file renaming.
references:
    - https://the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/
    - https://attack.mitre.org/techniques/T1134/001/
    - https://attack.mitre.org/techniques/T1068/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.privilege-escalation
    - attack.t1134.001
    - attack.t1068
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Imphash|contains:
            - 'f9a28c458284584a93b14216308d31bd'
            - '545a81240793f9ca97306fa5b3ad76df'
            - '959a83047e80ab68b368fdb3f4c6e4ea'
            - '576d6e02a47c807b9063948ee683350c'
            - '567531f08180ab3963b70889578118a3'
            - '818cfde69b098e3348e8c7125e83915f'
    condition: selection
falsepositives:
    - None expected — these imphashes correspond to specific security tool builds with no legitimate enterprise use
level: high
```

---

### CVE-2026-20817 WER LPE PoC — Anomalous WerFault.exe Token Inspection

**Detection Priority:** LOW
**Rationale:** On hosts missing the January 2026 WER patch, the CVE-2026-20817 PoC enumerates processes looking for `WerFault.exe` and opens its token for inspection (`OpenProcessToken` with `TOKEN_QUERY`). This behavior — a non-WER parent process opening WerFault.exe's token — is anomalous. Rule is LOW priority because the vulnerability is patched and the sample is non-weaponized, but retains value on unpatched hosts.
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** MODERATE
**False Positive Risk:** HIGH — security tooling and EDR products legitimately inspect WerFault.exe process tokens; this rule should only be deployed in environments confirmed to be running pre-January-2026 unpatched Windows builds, or for retrospective hunting.
**Deployment:** Sysmon (Event ID 10 — ProcessAccess), EDR process-access telemetry. Deploy only on hosts running Windows 10/11 or Server 2019/2022 without the January 2026 cumulative update.

```yaml
title: CVE-2026-20817 WER LPE PoC Token Inspection of WerFault.exe
id: ff8ee6c2-d705-4ebf-98bd-6ead3d775ae0
status: test
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
    - https://attack.mitre.org/techniques/T1068/
author: The Hunters Ledger
date: 2026-06-12
tags:
    - attack.privilege-escalation
    - attack.t1068
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

### Flask C2 Health Endpoint — Distinctive JSON Field-Combo

**Detection Priority:** HIGH
**Rationale:** The `/health` endpoint of this bespoke Flask C2 returns a JSON object with a highly distinctive field combination (`active_servers`, `pending_commands`, `completed_commands`, `status`, `timestamp`) that is not found in any known public C2 framework or web application framework. This endpoint is unauthenticated and accessible without credentials, making it a reliable network-level detection anchor. The `Werkzeug/3.1.6 Python/3.12.3` Server header provides an additional discriminator.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of all five JSON field names in a single response is uniquely characteristic of this C2 implementation. No known legitimate application or public C2 framework uses this exact field set.
**Deployment:** Network IDS/IPS, perimeter firewall with DPI capability, SIEM with network flow data

```
alert http $HOME_NET any -> 67.215.232.25 any (
    msg:"THL FlaskC2-PostEx C2 Health Endpoint Response - Bespoke Flask C2 Active";
    flow:established,to_client;
    file_data;
    content:"active_servers"; nocase;
    content:"pending_commands"; nocase; distance:0;
    content:"completed_commands"; nocase; distance:0;
    content:"status"; nocase; distance:0;
    content:"timestamp"; nocase; distance:0;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;
    sid:9001001; rev:1;
)
```

---

### Flask C2 Beacon Endpoints — POST-Only API Routes

**Detection Priority:** HIGH
**Rationale:** The `/api/report` and `/api/heartbeat` URIs are the beacon check-in endpoints of this bespoke C2. These POST-only routes do not appear in any public C2 framework, web application, or monitoring tool. Any POST to these paths on any host is suspicious — the rule is written without IP pinning to catch operator infrastructure migration.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW — these URIs are specific to this custom C2 implementation and are not standard REST API paths used by any known legitimate service.
**Deployment:** Network IDS/IPS, perimeter/egress HTTP inspection, proxy logs

```
alert http $HOME_NET any -> any any (
    msg:"THL FlaskC2-PostEx C2 Beacon POST to /api/report or /api/heartbeat";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/api/report"; nocase;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;
    sid:9001002; rev:1;
)

alert http $HOME_NET any -> any any (
    msg:"THL FlaskC2-PostEx C2 Beacon POST to /api/heartbeat";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/api/heartbeat"; nocase;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;
    sid:9001003; rev:1;
)
```

---

### Flask C2 IP Block — All Traffic to Known Infrastructure

**Detection Priority:** HIGH
**Rationale:** The entire campaign infrastructure is co-located on a single IP address (`67.215.232.25`) — the open-directory toolkit cache (`:1337`), the Flask C2 panel (`:8080`), and the opaque second listener (`:5000`). An IP-level block covers all current known operator surfaces. Ports 5222–5455 are excluded per analyst guidance (proxy-era historical tenancy on this IP — different-tenant risk).
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — VirusTotal scores this IP 15/91 malicious. AS36352 (HostPapa/ColoCrossing) is a commodity hosting provider; this IP has no known legitimate service.
**Deployment:** Perimeter firewall, network IDS/IPS, SIEM threat intelligence feeds

```
alert ip $HOME_NET any -> 67.215.232.25 any (
    msg:"THL FlaskC2-PostEx C2 Known Staging Host 67.215.232.25";
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/flaskc2-postex-toolkit-67-215-232-25-detections/;
    threshold:type limit, track by_src, seconds 300, count 1;
    sid:9001004; rev:1;
)
```

---

## Coverage Gaps

The following MITRE ATT&CK techniques observed in analyst findings could not be covered with high-confidence, production-ready detection rules due to missing artifacts or insufficient specific indicators. These are documented limitations of passive open-directory analysis, not failures.

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
The cmd_exec.dll reverse-shell channel is plaintext raw TCP with no protocol framing, making Suricata application-layer signature matching impractical. The operator supplies the destination IP and port at `EXEC` time (no hardcoded C2), so no IP-based block is possible for the shell channel itself. Detection coverage for this channel relies on the Sigma rules (sqlservr.exe outbound TCP) rather than Suricata DPI.

**T1021 — Remote Services (lateral movement)**
No specific lateral movement artifacts were recovered from the open directory. Rubeus and SharpSuccessor provide the capability, but no lateral movement commands, target host lists, or SMB/WinRM usage were observed in the static analysis. Coverage relies on existing Kerberos-abuse and SharpSuccessor detection rules in SigmaHQ.

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.

