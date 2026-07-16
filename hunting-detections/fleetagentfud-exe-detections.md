---
title: "Detection Rules — FleetAgentFUD.exe (WebSocket RAT with FUD Evasion)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/fleetagentfud-exe-detections/
hide: true
redirect_from: /hunting-detections/fleetagentfud-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/fleetagentfud-exe.json

---

## Detection Coverage Summary

FleetAgentFUD.exe is a 17.5 KB .NET-compiled Remote Access Trojan recovered from the same open directory at `109.230.231.37` as the PoetRAT-attributed `agent.exe` payload, part of the broader Arsenal-237 malware-repository exposure. The sample favors a minimal-footprint "Fully Undetectable" (FUD) design: WebSocket-based command and control authenticated with a custom `X-Agent-Secret` header, PowerShell Execution Policy bypass for command execution, repeated clipboard polling for credential theft, and a WebClient-based file-download capability for follow-on payloads.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The single most distinctive network artifact — the `X-Agent-Secret` authentication header — anchors the file's only Detection-tier Suricata signature; the remaining WebSocket protocol indicators are RFC 6455 handshake headers shared by every WebSocket application and do not discriminate this malware from legitimate traffic. Host-based coverage centers on the PowerShell bypass-from-AppData pattern and a clipboard-polling-frequency correlation, both scored Detection; the broader reconnaissance, file-download, and RWX-memory indicators are scoped to Hunting given their documented overlap with legitimate AppData-rooted application behavior. The campaign's one durable atomic — the `109.230.231.37` distribution IP — is carried in the IOC feed rather than as a standalone signature.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 4 | T1071.001, T1059.001, T1685, T1115, T1105, T1082, T1036.005, T1129 | 0 |
| Sigma | 3 | 5 | T1059.001, T1685, T1115, T1204.002, T1105, T1055, T1082, T1033 | 0 |
| Suricata | 1 | 1 | T1071.001 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the distribution IP (`109.230.231.37`) and the sample's SHA256/SHA1/MD5 hashes were already present in [`fleetagentfud-exe.json`](/ioc-feeds/fleetagentfud-exe.json) before this retiering pass. The pure IP-match Suricata signature added no detection value beyond that feed entry and has been retired — see Coverage Gaps for the full reasoning on every retired and retiered rule.

---

## YARA Rules

### Hunting Rules

#### FleetAgentFUD WebSocket C2 Signatures

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** MODERATE
**Rationale:** Two of the condition's three branches rely only on RFC 6455-mandated WebSocket handshake strings (`Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`) combined with moderately generic JSON registration-field names (`machine_id`, `hostname`, `os_version`, `agent_ver`) — none of which are unique to this family, since any .NET application using a WebSocket library emits the same handshake strings. Only the third branch (`all of ($ws*) and any of ($api*)`) forces co-occurrence with the genuinely bespoke `X-Agent-Secret` custom header, but a YARA `or` condition's precision is bounded by its weakest branch, not its strongest — an unrelated WebSocket-using .NET application with basic telemetry fields could satisfy branch one or two without ever touching the distinguishing header. Scored on the logic as written, not the title's "C2 Pattern" claim.
**False Positives:** Legitimate .NET applications using WebSocket-based telemetry, chat, or remote-support features (a real and not-uncommon population) can satisfy the first two branches without any malicious behavior.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates and prioritize review of the `X-Agent-Secret`-corroborated branch.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule FleetAgentFUD_WebSocket_C2_Pattern {
   meta:
      description = "Detects FleetAgentFUD.exe WebSocket C2 implementation via protocol strings, RAT-style JSON registration fields, and the bespoke X-Agent-Secret authentication header. RFC 6455 handshake strings alone are shared by legitimate WebSocket applications — the X-Agent-Secret branch is the only high-confidence path."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/"
      date = "2026-01-12"
      family = "FleetAgentFUD"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "ec392648-d132-4110-b47b-9e53d28f481d"
      hash1 = "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff"
   strings:
      // WebSocket handshake headers
      $ws1 = "Connection: Upgrade" ascii wide
      $ws2 = "Sec-WebSocket-Key: " ascii wide
      $ws3 = "Sec-WebSocket-Version: 13" ascii wide
      $ws4 = "X-Agent-Secret: " ascii wide

      // WebSocket message types
      $msg1 = "\"type\":\"register\"" ascii wide nocase
      $msg2 = "\"type\":\"heartbeat\"" ascii wide nocase
      $msg3 = "machine_id" ascii wide
      $msg4 = "hostname" ascii wide
      $msg5 = "os_version" ascii wide
      $msg6 = "agent_ver" ascii wide

      // Command types
      $cmd1 = "cmd_type" ascii wide
      $cmd2 = "command_id" ascii wide
      $cmd3 = "powershell" ascii wide
      $cmd4 = "sysinfo" ascii wide
      $cmd5 = "clipboard" ascii wide

      // .NET networking APIs
      $api1 = "System.Net.Sockets" ascii
      $api2 = "TcpClient" ascii
      $api3 = "NetworkStream" ascii

   condition:
      uint16(0) == 0x5A4D and
      filesize < 50KB and
      (
         // Moderate match: generic WebSocket headers + registration fields (broad — see Rationale)
         (3 of ($ws*) and 3 of ($msg*)) or

         // Moderate match: WebSocket + command types
         (2 of ($ws*) and 3 of ($cmd*)) or

         // Higher confidence: bespoke X-Agent-Secret header required (all of $ws*) + .NET networking
         (all of ($ws*) and any of ($api*))
      )
}
```

#### FleetAgentFUD PowerShell Execution Policy Bypass Strings

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses), T1059.001 (PowerShell)
**Confidence:** MODERATE
**Rationale:** The two exact-literal branches (`$ps1`, `$ps2`) are distinctive, low-FP command-line templates. The third branch (`$ps3 and ($ps5 or $ps6) and $ps7`) combines three individually common tokens — bare `powershell` (nocase), a bypass flag, and `-W Hidden` — and a YARA `or` condition's overall precision is bounded by its weakest branch. Legitimate software installers and silent-update mechanisms are documented (by this same file's own Sigma rule 1 false-positives list) to launch PowerShell hidden with an execution-policy bypass for routine background tasks, and would embed the identical command-line string as a literal in their own binary.
**False Positives:** Legitimate installers/updaters that silently invoke `powershell -ExecutionPolicy Bypass -WindowStyle Hidden` for background maintenance tasks — a documented, non-trivial population in enterprise Windows environments.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule FleetAgentFUD_PowerShell_Bypass {
   meta:
      description = "Detects FleetAgentFUD.exe PowerShell Execution Policy bypass command-line strings embedded in a .NET binary. The two exact-literal branches are distinctive; the third (bare powershell + bypass flag + hidden-window flag) overlaps with legitimate silent-installer PowerShell invocations."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/"
      date = "2026-01-12"
      family = "FleetAgentFUD"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "f2387fca-b7b5-47ea-a65e-cf2b1ccb420b"
   strings:
      // PowerShell bypass command-line
      $ps1 = "-NoP -NonI -W Hidden -Exec Bypass -C " ascii wide
      $ps2 = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass" ascii wide

      // PowerShell command variations
      $ps3 = "powershell" ascii wide nocase

      // Suspicious PowerShell usage combinations
      $ps5 = "-Exec Bypass" ascii wide
      $ps6 = "-ExecutionPolicy Bypass" ascii wide
      $ps7 = "-W Hidden" ascii wide

   condition:
      uint16(0) == 0x5A4D and
      filesize < 100KB and
      (
         // Exact bypass string match
         $ps1 or
         $ps2 or

         // PowerShell + bypass flags (broader — see Rationale)
         ($ps3 and ($ps5 or $ps6) and $ps7)
      )
}
```

#### FleetAgentFUD FUD RAT Behavioral Pattern

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1115 (Clipboard Data), T1071.001 (Web Protocols), T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1082 (System Information Discovery)
**Confidence:** LOW
**Rationale:** All three branches are built from single common English words or short generic phrases (`clipboard`, `network`, `users`, `processes`, `ShowWindow`) combined via `any of` bucket matching — the weakest possible internal requirement per bucket. None of the three categories (clipboard/WebSocket/PowerShell, WebSocket/recon/download, PowerShell/clipboard/hidden-window) forces a genuinely distinctive string; each is satisfiable by common single-word API/string references that also appear across large amounts of unrelated software (e.g. `ShowWindow` is a near-ubiquitous Win32 GUI import; `network`/`users`/`processes` are near-universal substrings). The three-category combination still filters out most unrelated software, which preserves some triage value, but the rule does not clear the bar for a "sound combination" per the YARA Detection checklist.
**False Positives:** Plausible against legitimate remote-support, clipboard-sync, or IT-automation tooling that combines any two of the three behavior categories (e.g. a WebSocket-based remote-support client with PowerShell remoting).
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule FleetAgentFUD_FUD_RAT_Behavioral_Pattern {
   meta:
      description = "Detects FUD RAT behavioral characteristics via a three-category combination: clipboard access, WebSocket usage, PowerShell execution, system reconnaissance, and file download. Each individual string is a common single word or short API reference — the three-category combination provides broad triage value, not high-confidence detection."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/"
      date = "2026-01-12"
      family = "FleetAgentFUD"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "e123e941-8ccf-4856-abcd-b0e4e58da577"
   strings:
      // Clipboard monitoring
      $clip1 = "Get-Clipboard" ascii wide
      $clip2 = "clipboard" ascii wide nocase

      // WebSocket indicators
      $ws1 = "Sec-WebSocket-Key" ascii wide
      $ws2 = "Connection: Upgrade" ascii wide

      // PowerShell execution
      $ps1 = "powershell" ascii wide nocase
      $ps2 = "-Exec Bypass" ascii wide
      $ps3 = "-ExecutionPolicy Bypass" ascii wide

      // System reconnaissance
      $recon1 = "sysinfo" ascii wide
      $recon2 = "processes" ascii wide
      $recon3 = "network" ascii wide
      $recon4 = "users" ascii wide

      // File download capability
      $dl1 = "DownloadFile" ascii wide
      $dl2 = "WebClient" ascii wide

      // Hidden window execution
      $hide1 = "ShowWindow" ascii
      $hide2 = "WindowStyle Hidden" ascii wide

   condition:
      uint16(0) == 0x5A4D and
      filesize < 50KB and // FUD optimization: small file size
      (
         // Clipboard + WebSocket + PowerShell
         (any of ($clip*) and any of ($ws*) and any of ($ps*)) or

         // WebSocket + Reconnaissance + Download
         (any of ($ws*) and 2 of ($recon*) and any of ($dl*)) or

         // PowerShell + Clipboard + Hidden Window
         (any of ($ps*) and any of ($clip*) and any of ($hide*))
      )
}
```

#### FleetAgent Family Signature

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Masquerading), T1129 (Shared Modules)
**Confidence:** LOW
**Rationale:** The primary branch (`any of $name*`) keys on the malware's own developer-chosen family/namespace name — a coined term with no plausible reason to appear in unrelated software, but (unlike a live C2 protocol field the operator must keep to stay functional) a .NET namespace or assembly name is trivially renamed on the next build compile, which caps this at Robustness 1 rather than 2. The second branch (`2 of $cfg* and any of $ver*`) is meaningfully weaker: `"3.0.0"` is a bare semver string that appears in a large number of unrelated .NET assemblies, and pairing it with generic config-field names (`hostname`, `agent_ver`) does not meaningfully narrow the match. The third branch (masquerade string + 2 generic WinAPI strings) is the most defensible but still relies on common APIs (`VirtualProtect`, `GetProcAddress`) shared by countless legitimate applications.
**False Positives:** The `"3.0.0"` + generic config-field branch risks matching unrelated .NET software using that version string; the masquerade-name branches are lower-risk but evade entirely on a rebrand.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares, cross-reference against the other FleetAgent-family payloads from the same distribution infrastructure.

```yara
rule FleetAgent_Family_General {
   meta:
      description = "Detects FleetAgent malware family characteristics (FUD and Advanced variants) via the family's own namespace/naming strings, configuration field + version pairing, and Microsoft.NET.Runtime masquerading combined with suspicious APIs. Every branch evades on a rebrand or namespace rename; the version-string branch also risks matching unrelated .NET software."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/"
      date = "2026-01-12"
      family = "FleetAgent"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "dd7bcee3-74e4-407f-bfe5-fe12656ef66c"
      related_samples = "FleetAgentAdvanced.exe, FleetAgentFUD.exe"
   strings:
      // Family naming patterns
      $name1 = "FleetAgent" ascii wide nocase
      $name2 = "FleetAgentFUD" ascii wide
      $name3 = "FleetAgentAdvanced" ascii wide
      $name4 = "Microsoft.NET.Runtime" ascii wide // Common masquerading

      // Agent version strings
      $ver1 = "agent_ver" ascii wide
      $ver2 = "3.0.0" ascii wide

      // Configuration variables
      $cfg1 = "machine_id" ascii wide
      $cfg2 = "hostname" ascii wide
      $cfg3 = "agent_ver" ascii wide

      // Common APIs
      $api1 = "VirtualProtect" ascii
      $api2 = "ToBase64String" ascii
      $api3 = "GetProcAddress" ascii

   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         // Direct family name match
         any of ($name*) or

         // Configuration + Version pattern (broad — see Rationale)
         (2 of ($cfg*) and any of ($ver*)) or

         // Microsoft.NET masquerading + suspicious APIs
         ($name4 and 2 of ($api*))
      )
}
```

---

## Sigma Rules

### Detection Rules

#### FleetAgentFUD PowerShell Execution Policy Bypass from AppData

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1685 (Impair Defenses)
**Confidence:** HIGH
**Rationale:** Requires three independent conditions together — `powershell.exe` process creation, a parent process rooted in `\AppData\`, an execution-policy bypass flag combination, AND a hidden-window flag. The added hidden-window requirement (beyond the two-condition subset that Multi-Stage Attack Pattern below reduces to) meaningfully narrows the population: legitimate AppData-rooted software rarely combines bypass flags with a deliberately hidden window.
**False Positives:** Legitimate software installers using PowerShell from AppData (verify digital signature); administrative scripts executed from user directories.
**Blind Spots:** An operator who stages from a non-AppData parent path (Temp, ProgramData) or drops the hidden-window flag evades.
**Validation:** Trigger `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C ...` from an AppData-rooted parent process — must match; the same command from a `C:\Program Files\` parent must NOT fire.
**Deployment:** Sysmon/EDR process-creation telemetry, Windows Security Event ID 4688 with command-line auditing enabled.

```yaml
title: FleetAgentFUD PowerShell Execution Policy Bypass from AppData
id: 662e65e5-b424-40e0-9630-af1d2ccf3b3f
status: experimental
description: Detects PowerShell execution with Execution Policy bypass from suspicious AppData locations (FleetAgentFUD RAT pattern)
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-Exec'
            - 'Bypass'
    selection_parent:
        ParentImage|contains: '\AppData\'
    selection_hidden:
        CommandLine|contains:
            - '-W Hidden'
            - '-WindowStyle Hidden'
    condition: selection_powershell and selection_parent and selection_hidden
falsepositives:
    - Legitimate software installers using PowerShell from AppData (verify digital signature)
    - Administrative scripts executed from user directories (review context)
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.stealth
    - attack.t1685
    - attack.defense-impairment
    - detection.emerging-threats
```

#### FleetAgentFUD Repeated Clipboard Monitoring (Correlation)

**Tier:** Detection (correlation rule) — bundled below with its 1 required base rule, which does not alert on its own
**Robustness:** 2 (correlation) / 1 (base rule individually)
**ATT&CK Coverage:** T1115 (Clipboard Data)
**Confidence:** HIGH
**Rationale:** `Get-Clipboard` is a legitimate, non-renameable PowerShell cmdlet name — unlike a masquerade filename or mutex, an operator cannot rename it away while continuing to use PowerShell for clipboard polling, which gives the base signal real technique-level durability (evadable only by switching to a non-PowerShell clipboard-access method entirely). The correlation's 10-executions-per-hour threshold, grouped by host and user, filters out the occasional legitimate script invocation and isolates a sustained automated-polling pattern that has no common legitimate analog.
**False Positives:** Legitimate clipboard management tools and user productivity automation scripts that poll the clipboard via PowerShell at a comparable frequency — a real but narrow population.
**Blind Spots:** An operator who moves clipboard access to a direct Win32 API call (`GetClipboardData` via P/Invoke) instead of the `Get-Clipboard` cmdlet evades entirely; requires PowerShell Script Block Logging (Event 4104).
**Validation:** Trigger 10+ `Get-Clipboard` script block executions from the same `ComputerName`/`User` within one hour — the correlation must fire; fewer than 10 executions, or executions spread across different users, must NOT trigger the correlation.
**Deployment:** SIEM correlation engine with PowerShell Script Block Logging ingested (1-hour event-count correlation by ComputerName + User).

```yaml
title: PowerShell Get-Clipboard Script Block Execution (Base Rule)
id: b8eb1824-6711-4e88-ab71-46b63250b1a5
name: powershell_get_clipboard_execution
status: experimental
description: >-
  Base rule (not alerting on its own): a single PowerShell Get-Clipboard script
  block execution. Paired with the companion FleetAgentFUD Repeated Clipboard
  Monitoring correlation rule below, which flags repeated executions indicating
  clipboard data theft.
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: 'Get-Clipboard'
    condition: selection
falsepositives:
    - >-
      Legitimate clipboard management tools and user productivity automation scripts.
      Not alerting on its own; reviewed only in combination with the correlation rule.
level: informational
tags:
    - attack.collection
    - attack.t1115
    - detection.emerging-threats
---
title: FleetAgentFUD Repeated Clipboard Monitoring Correlation
id: 75c96f1a-c463-4961-851e-a4ec93b4e5d1
status: experimental
description: >-
  Correlates 10 or more PowerShell Get-Clipboard script block executions by the
  same computer and user within one hour, indicating clipboard data theft
  (FleetAgentFUD credential theft technique). Get-Clipboard is a legitimate,
  non-renameable cmdlet name, giving this correlation real technique-level
  durability beyond a simple literal match.
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
correlation:
    type: event_count
    rules:
        - powershell_get_clipboard_execution
    group-by:
        - ComputerName
        - User
    timespan: 1h
    condition:
        gte: 10
falsepositives:
    - Legitimate clipboard management tools
    - User productivity automation scripts (verify legitimacy)
level: high
tags:
    - attack.collection
    - attack.t1115
    - detection.emerging-threats
```

> **Retiering note:** the correlation's original `level: critical` overstated confidence — a real, if narrow, legitimate-tooling FP population is documented above, which does not meet the "never FP" bar `critical` requires. Demoted to `high`. See Coverage Gaps.

### Hunting Rules

#### FleetAgentFUD File Download to Suspicious Locations

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1204.002 (User Execution: Malicious File)
**Confidence:** MODERATE
**Rationale:** The combination (executable file creation in Public/Temp, from a process rooted in AppData) is a real, durable technique pairing — but AppData is also where a large share of legitimate consumer software (Chrome, Discord, Slack, and most other per-user auto-updating desktop applications) installs and self-updates without admin rights, and many of those updaters legitimately drop new executables/DLLs to Temp during a self-update cycle. This is a common, not rare, false-positive category in real enterprise environments.
**False Positives:** Legitimate AppData-rooted application auto-updaters extracting or staging executables in Temp/Public during a self-update — a common occurrence, not an edge case.
**Deployment:** Sysmon/EDR file-creation telemetry (Event ID 11) correlated with the originating process path; recommended as a scoping lead requiring analyst review of the specific application, not an automated block.

```yaml
title: FleetAgentFUD File Download to Suspicious Locations
id: 85477610-82e0-4256-8906-3fe3109937eb
status: experimental
description: Detects executable file creation in Public/Temp folders from AppData processes (FleetAgentFUD payload download)
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: file_event
detection:
    selection_file:
        TargetFilename|contains:
            - 'C:\Users\Public\'
            - 'C:\Windows\Temp\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.scr'
    selection_process:
        Image|contains: '\AppData\'
    condition: selection_file and selection_process
falsepositives:
    - Software installers extracting temporary files
    - Update mechanisms using Public/Temp folders (common for AppData-rooted auto-updaters)
level: medium
tags:
    - attack.execution
    - attack.t1204.002
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
```

#### FleetAgentFUD RWX Memory Allocation from .NET Executable

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1055 (Process Injection)
**Confidence:** LOW
**Rationale:** RWX memory allocation is a genuine technique-level primitive for shellcode execution, and the rule correctly filters out `Program Files`/`Windows`-rooted processes. However, the rule's own documented false-positive — .NET Just-In-Time (JIT) compilation — is not a narrow edge case: JIT is a normal, continuous part of CLR operation for every .NET application, and the rule has no discriminator (call-stack provenance, memory-region ownership) to separate CLR-internal JIT activity from attacker-injected shellcode execution.
**False Positives:** .NET JIT compilation is a normal, frequent behavior for any .NET application running outside `Program Files`/`Windows` — a near-universal overlap for AppData-rooted .NET software, not a rare exception.
**Deployment:** EDR API-call/behavioral telemetry with CallTrace visibility; treat hits as a scoping lead requiring correlation with other suspicious signals, not a standalone alert.

```yaml
title: FleetAgentFUD RWX Memory Allocation from .NET Executable
id: 1e04bbc1-1f12-41c7-a11d-0cc31e963f60
status: experimental
description: Detects VirtualProtect API calls with RWX permissions from .NET executables (shellcode execution indicator)
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: api_call
detection:
    selection:
        CallTrace|contains: 'VirtualProtect'
        Protection: 'PAGE_EXECUTE_READWRITE'
        Image|contains: '\AppData\'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Windows\'
    condition: selection and not filter_legitimate
falsepositives:
    - .NET Just-In-Time (JIT) compilation (a normal, frequent part of CLR operation, not a rare exception)
    - Legitimate .NET applications using dynamic code generation
level: medium
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055
    - detection.emerging-threats
```

#### FleetAgentFUD PowerShell Bypass from AppData Parent (Broad Variant)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** LOW
**Rationale:** *Retiering finding:* despite its "Multi-Stage Attack Pattern Correlation" title, this rule is not a `correlation:`-type Sigma rule at all — it is a plain two-condition `process_creation` selector, and its two conditions (`powershell.exe` + `-Exec Bypass` command line, parent rooted in AppData) are a strict subset of the Detection-tier PowerShell Execution Policy Bypass rule above, minus that rule's hidden-window requirement. Removing the hidden-window corroborator broadens the match population without adding any new signal, so this rule fires on strictly more (and less-corroborated) activity than its Detection-tier sibling. Tiered Hunting as the broader, lower-confidence companion to that rule rather than published as an independent high-confidence signature.
**False Positives:** The same AppData-rooted PowerShell bypass population as the Detection-tier sibling rule, minus the narrowing effect of the hidden-window requirement — a meaningfully larger population.
**Deployment:** Sysmon/EDR process-creation telemetry; use as a lower-bar scoping companion to the Detection-tier PowerShell bypass rule, not as an independent alert.

```yaml
title: FleetAgentFUD Multi-Stage Attack Pattern Correlation
id: cfe3cad4-9134-4d9e-8681-3199404e6170
status: experimental
description: >-
  Detects PowerShell launched with an execution-policy bypass from a parent process
  running under AppData. Functionally a broader subset of the Detection-tier
  PowerShell Execution Policy Bypass from AppData rule (minus its hidden-window
  requirement) — not an actual multi-source correlation, since Sigma's single-event-source
  model cannot express the original three-stage (process + network + PowerShell)
  design across separate log sources.
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-Exec Bypass'
    selection_parent:
        ParentImage|contains: '\AppData\'
    condition: selection_powershell and selection_parent
falsepositives:
    - Complex legitimate software launching PowerShell from user directories
    - Broader population than the Detection-tier sibling rule (no hidden-window corroborator)
level: medium
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
```

#### FleetAgentFUD Rapid System Reconnaissance (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its 1 required base rule, which does not alert on its own
**Robustness:** 2 (correlation) / 1 (base rule individually)
**ATT&CK Coverage:** T1082 (System Information Discovery), T1033 (System Owner/User Discovery)
**Confidence:** LOW
**Rationale:** Each individual reconnaissance command (`Get-Process`, `ipconfig /all`, `Get-LocalUser`, WMI queries) is a routine, widely-used administrative command — far more common in legitimate IT tooling than the clipboard correlation's `Get-Clipboard` base signal. The parent-path narrowing (AppData/Temp/Public) and the 3-distinct-commands-in-5-minutes threshold add real scoping value, but legitimate deployment/inventory tooling staged in Temp during installation can plausibly batch a comparable command sequence, so this does not clear the Detection precision bar the way the clipboard correlation does.
**False Positives:** System administration scripts and IT inventory tools launched from AppData/Temp/Public during deployment — a real, documented population per the source rule's own false-positives list.
**Deployment:** SIEM correlation engine with process-creation telemetry ingested (5-minute event-count correlation by ComputerName); treat hits as scoping leads.

```yaml
title: FleetAgentFUD Rapid System Reconnaissance Command (Base Rule)
id: 1316ab23-3a9b-40e7-a037-2ec3c4535404
name: fleetagentfud_recon_command
status: experimental
description: >-
  Base rule (not alerting on its own): a single system reconnaissance command
  (sysinfo, processes, network, users, disk) typical of FleetAgentFUD automated
  profiling, launched from a parent process rooted in AppData, Temp, or
  Users\Public — the FleetAgentFUD staging locations. Paired with the companion
  Rapid System Reconnaissance Pattern correlation rule below, which flags 3 or
  more distinct recon commands from the same host in a short window.
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Get-WmiObject Win32_'
            - 'Get-Process'
            - 'Get-LocalUser'
            - 'ipconfig /all'
            - 'Win32_LogicalDisk'
    selection_parent:
        ParentImage|contains:
            - '\AppData\'
            - '\Temp\'
            - '\Users\Public\'
    condition: selection_powershell and selection_parent
falsepositives:
    - >-
      System administration scripts launched from AppData/Temp (e.g. installer
      post-run steps). Not alerting on its own; reviewed only in combination with
      the correlation rule.
    - IT inventory tools staged in Temp during deployment
level: informational
tags:
    - attack.discovery
    - attack.t1082
    - attack.t1033
    - detection.emerging-threats
---
title: FleetAgentFUD Rapid System Reconnaissance Pattern
id: a7b8c9d0-a1b2-4c3d-9e4f-56a7b8c9d0e7
status: experimental
description: >-
  Correlates 3 or more distinct system reconnaissance commands (sysinfo, processes,
  network, users, disk) from the same host within a short window, typical of
  FleetAgentFUD automated profiling. Individual commands are routine IT-administration
  commands; the correlation adds real but limited scoping value.
references:
    - https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
correlation:
    type: event_count
    rules:
        - fleetagentfud_recon_command
    group-by:
        - ComputerName
    timespan: 5m
    condition:
        gte: 3
falsepositives:
    - System administration scripts
    - IT inventory tools
level: medium
tags:
    - attack.discovery
    - attack.t1082
    - attack.t1033
    - detection.emerging-threats
```

> **Retiering note:** the correlation's original `level: high` has been demoted to `medium`, consistent with Hunting-tier level discipline — the underlying commands are common enough in legitimate IT tooling that "rare FP after baselining" is not defensible without additional host-role context. See Coverage Gaps.

---

## Suricata Signatures

### Detection Rules

#### FleetAgentFUD X-Agent-Secret WebSocket Authentication Header

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** HIGH
**Rationale:** `X-Agent-Secret` is a bespoke, attacker-chosen HTTP header name functioning as a custom C2 authentication field — not part of any standard web protocol and not a header any legitimate framework has reason to send. Functions as the campaign's protocol-field anchor, comparable to a distinctive C2 authentication header in other investigations.
**False Positives:** None known — no legitimate framework or library sends a header with this exact name.
**Blind Spots:** Evaded entirely by an operator renaming the header in a future build; requires HTTP traffic visibility (defeated by full end-to-end TLS without inspection unless the connection terminates at an inspecting proxy).
**Validation:** Replay a captured WebSocket handshake request carrying the `X-Agent-Secret` header — must alert; an unrelated HTTP or WebSocket request without that header must NOT fire.
**Deployment:** Network IDS/IPS on egress with HTTP header inspection enabled (TLS decryption required for `wss://` sessions).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL FleetAgentFUD X-Agent-Secret WebSocket Authentication Header (Custom C2 Protocol Indicator)"; flow:established,to_server; http.header_names; content:"X-Agent-Secret"; classtype:trojan-activity; sid:2100022; rev:1; metadata:author The_Hunters_Ledger, date 2026-01-12, reference https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/;)
```

### Hunting Rules

#### FleetAgentFUD Default .NET WebClient User-Agent + WebSocket Upgrade

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** MODERATE
**Rationale:** Each individual signal is common in a different context — the legacy default .NET `WebClient`/`HttpWebRequest` User-Agent string is widely reused by simple, un-customized .NET HTTP tools, and a WebSocket upgrade handshake is common for real-time web applications — but the two together are a genuinely unusual combination: legitimate .NET WebSocket usage typically goes through `ClientWebSocket`, a distinct class that does not carry this legacy default UA. An application manually constructing a raw HTTP upgrade request while still carrying the legacy `WebClient`-family default UA is consistent with a custom-rolled WebSocket implementation built on lower-level networking primitives (matching this family's own `TcpClient`/`NetworkStream` YARA evidence), but this reasoning has not been validated against a goodware corpus, so it is scored as a genuinely close call rather than high confidence.
**False Positives:** A legitimate .NET application that manually constructs a WebSocket upgrade over `HttpWebRequest`/`WebClient` without adopting a modern WebSocket library would also match — a low-probability but unverified edge case.
**Deployment:** Network IDS/IPS on egress with HTTP inspection enabled; treat hits as a scoping lead pending goodware-corpus validation.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT FleetAgentFUD Default .NET WebClient User-Agent + WebSocket Upgrade (Custom C2 Client Indicator)"; flow:established,to_server; http.user_agent; content:"Mozilla/4.0 (compatible|3b| MSIE 6.0|3b| Windows NT 5.2|3b| .NET CLR"; http.header; content:"Connection|3a 20|Upgrade"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:2100023; rev:1; metadata:author The_Hunters_Ledger, date 2026-01-12, reference https://the-hunters-ledger.com/hunting-detections/fleetagentfud-exe-detections/;)
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA compile errors fixed (2 rules).** The PowerShell Execution Policy Bypass Strings rule declared `$ps4 = "Get-Clipboard"` but never referenced it in the condition; the FUD RAT Behavioral Pattern rule declared `$net1 = "System.Net"` and `$net2 = "v4.0.30319"` but never referenced either in the condition. Compile-tested with the real `yarac`: both rules failed with `unreferenced string` errors and never loaded. Since neither string was reachable from any condition branch, removing the dead declarations changes no matching behavior — the corrected rules now compile cleanly and match identically to what the published (broken) originals would have matched had they compiled at all.
- **Sigma correlation level demotions (2 rules).** The Repeated Clipboard Monitoring correlation's original `level: critical` overstated confidence given the documented legitimate clipboard-tooling FP population — demoted to `high`. The Rapid System Reconnaissance Pattern correlation's original `level: high` similarly overstated confidence given how common the underlying individual commands (`Get-Process`, `ipconfig /all`, etc.) are in legitimate IT tooling — demoted to `medium`, consistent with the rule's Hunting tier.
- **Sigma "Multi-Stage Attack Pattern Correlation" re-scoped (source Sigma rule, id `cfe3cad4-9134-4d9e-8681-3199404e6170`).** Despite its title, this rule was never an actual `correlation:`-type Sigma rule — it is a two-condition `process_creation` selector that is a strict subset of the Detection-tier PowerShell Execution Policy Bypass from AppData rule, minus that rule's hidden-window requirement. Scored on the logic as written (Tie-breaker 1), it fires on a broader, less-corroborated population than its Detection-tier sibling. Retiered to Hunting with `level: medium` (from `critical`) rather than published as an independent high-confidence signature; the rule text and `id` are otherwise unchanged.
- **Sigma/YARA level and tier recalibration on documented-FP rules.** The File Download to Suspicious Locations Sigma rule (`level: high` → `medium`) and the RWX Memory Allocation Sigma rule (`level: high` → `medium`) were both retiered from Detection-leaning to Hunting: both carry a source-documented false-positive category (AppData-rooted application auto-updaters; .NET JIT compilation, respectively) that is common rather than rare, which fails the Gate 2 precision bar for Detection and the Gate 4 "rare FP after baselining" criterion for `high`.
- **Sigma base rules restructured as explicit non-alerting building blocks.** The `Get-Clipboard` and system-reconnaissance base rules (feeding the two correlation rules) now carry `name:` fields and are referenced by name from their correlation rules (replacing UUID-only references), matching the project's established correlation-authoring convention. Both base rules' `level` was set to `informational` (from `low`/`medium`) to reflect that they are not intended to alert independently.
- **Suricata pure IP-match rule cut (source sid `2100020`).** `alert tcp $HOME_NET any -> 109.230.231.37 any` carries no content/protocol anchor — textbook Suricata Cut per the project checklist. The IP is already present in `fleetagentfud-exe.json` under `network_indicators.distribution_infrastructure`.
- **Suricata generic WebSocket-handshake rule cut (source sid `2100021`).** The rule anchored solely on three RFC 6455-mandated WebSocket handshake headers (`Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`) with no distinguishing content beyond the protocol's own required fields. Every legitimate WebSocket application — chat, collaboration, and real-time-dashboard tools alike — sends the identical handshake strings; the source file's own Implementation Guidance section already flagged this as needing a User-Agent or certificate whitelist to be usable, confirming it fires on ubiquitous benign traffic with no distinguishing structure. No salvage was possible: the one genuinely distinctive C2 header (`X-Agent-Secret`) is already covered by its own Detection-tier signature, so this rule added no value beyond that existing coverage. Not IOC-routable (no single atomic value to route — the match is a set of RFC-mandated protocol strings, not an indicator).
- **Suricata rules modernized to sticky-buffer syntax.** Both surviving Suricata rules (`sid:2100022`, `sid:2100023`) were rewritten from the legacy `http_header` content-modifier convention to modern sticky buffers (`http.header_names`, `http.user_agent`, `http.header`), and attribution was consolidated into `metadata:` (dropping the source file's broken placeholder `reference:url,github.com/yourusername/...` option), matching current project convention.
- **Suricata `sid` values preserved.** Both surviving rules keep their original local `sid` (`2100022`, `2100023`) unchanged, per project convention that the feed generator maps stable local sids to published SIDs.

### Genuinely Close Calls

- **YARA WebSocket C2 Pattern rule (Hunting, not Cut).** Two of three condition branches rely only on RFC 6455-mandated handshake strings and moderately generic JSON field names, which would be Cut-caliber noise on their own — but the third branch requires the bespoke `X-Agent-Secret` header, and the overall combination still has real triage value distinguishing FleetAgentFUD-family samples from unrelated software at the file level (unlike the network-layer Suricata case, a YARA hit still means "this specific file contains this specific field-name combination," which retains scoping value even where the network-layer equivalent does not). Kept as Hunting rather than Cut.
- **Suricata .NET UA + WebSocket Upgrade rule (Hunting, not Detection).** The reasoning for why this combination is plausibly distinctive (a legacy default UA is inconsistent with the modern `ClientWebSocket` class that legitimate .NET WebSocket usage would normally use) is sound but unverified against a goodware corpus of WebSocket-capable .NET applications. Scored Hunting rather than Detection pending that validation — see "What Would Enable Stronger Coverage" below.

### Atomics Routed to the IOC Feed (Pre-Existing)

- **Suricata "Distribution Infrastructure Connection"** (source sid `2100020`) — pure IP-match rule for `109.230.231.37`. Already present in `fleetagentfud-exe.json` under `network_indicators.distribution_infrastructure.ip`.
- **File hashes** (SHA256 `072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff`, SHA1 `51aa8b08dc67cb91435ce58d4453a8ae5e0dd577`, MD5 `5b37f5fc42384834b7aac5081a5bac85`) — already present in `fleetagentfud-exe.json` under `file_hashes`. No rule in this file depended solely on a hash match (the source file's PowerShell hunting scripts referenced the SHA256 for hash-scanning, but that content type was removed from this file per the current detection-file standard — hash-based lookups belong to the IOC feed, not a hunting-detections rule).

### What Would Enable Stronger Coverage

- **Goodware corpus validation** — none of the four YARA Hunting rules, nor the .NET-UA-plus-Upgrade Suricata Hunting rule, have been run against a broad clean-software corpus (WebSocket-capable .NET applications in particular). A documented zero-FP result is the explicit precondition for reconsidering any of them for Detection tier.
- **Observed C2 session content** — the IOC feed's own `c2_infrastructure` entry documents that WebSocket C2 traffic was never observed in transit (static analysis only); a captured live session would confirm whether the `X-Agent-Secret` header co-occurs with any additional structural marker (a specific URI path, a consistent header ordering) that could tighten the existing Detection-tier Suricata rule or promote the WebSocket C2 Pattern YARA rule's weaker branches.
- **Confirmed threat-actor attribution** — the sample's family confidence is HIGH (95%) but attribution to a specific threat actor is UNKNOWN (custom development, commercial MaaS suspected); a confirmed actor link would allow future rules to target operator-specific infrastructure rather than this build's masquerade-literal and protocol-generic artifact family.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
