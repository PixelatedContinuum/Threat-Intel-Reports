---
title: "Detection Rules — agent_xworm_v2.exe (XWorm RAT v2.4.0)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/agent-xworm-v2-exe-detections/
hide: true
redirect_from: /hunting-detections/agent-xworm-v2-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/agent-xworm-v2-exe.json

---

## Detection Coverage Summary

agent_xworm_v2.exe is a 15.8KB .NET Framework executable identified as XWorm RAT v2.4.0, distributed from an open directory at 109.230.231.37. The malware uses WebSocket-based command-and-control with Base64-encoded traffic, an embedded PowerShell reconnaissance template (process, service, and domain-role enumeration), and a hidden-window execution style. XWorm operates as commodity malware-as-a-service; this build's C2 infrastructure was offline when the sample was recovered, and its live protocol behavior remains unconfirmed, so network-behavioral coverage is limited to what the sample's on-disk and script-block artifacts support.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. Coverage is scoped to the artifacts that retain analyst value once the sample's own hard-coded C2 IP and authentication secret are set aside as feed atomics: the surviving rules split between a durable embedded-PowerShell-template signature (Detection) and broader family and protocol combinations that require analyst review (Hunting). The campaign's atomic indicators (distribution/C2 IP, file hashes, and the literal authentication-secret instance) are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 3 | T1059.001, T1082, T1482, T1057, T1007, T1071.001, T1564.003, T1132.001 | 1 |
| Sigma | 1 | 1 | T1059.001, T1082, T1057, T1007, T1482 | 1 |
| Suricata | 0 | 1 | T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the distribution/C2 IP (`109.230.231.37`), the sample's file hashes (SHA256/SHA1/MD5), and the literal authentication-secret instance (`AgentSec_8hJ3kL6mN9pQ2rS5tU8vW1xY4zA7bC0d`) were already present in [`agent-xworm-v2-exe.json`](/ioc-feeds/agent-xworm-v2-exe.json) before this retiering pass. The single-sample hash-equivalent YARA rule, the pure IP-match Sigma selector, and two of the four original Suricata signatures added no detection value beyond those feed entries and have been retired. See Coverage Gaps for the full reasoning on every retired rule.

---

## YARA Rules

### Detection Rules

#### XWorm v2.x Embedded PowerShell Reconnaissance Command Templates

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1082 (System Information Discovery), T1482 (Domain Trust Discovery), T1057 (Process Discovery), T1007 (System Service Discovery)
**Confidence:** HIGH
**Rationale:** The five strings are literal, multi-token PowerShell invocation templates embedded in the binary (an abbreviated `-NoP -C` flag style chained with specific cmdlet and property sequences), matching the exact reconnaissance commands documented in the sample's confirmed capability analysis. Requiring 3 of 5 distinct multi-word templates makes coincidental co-occurrence in unrelated software implausible. No goodware-corpus scan was run against this specific combination, so confidence is capped at HIGH rather than DEFINITE.
**False Positives:** Some legitimate lightweight remote-administration or health-check tooling could embed similar Get-Process or Get-Service one-liners individually, but the exact abbreviated `-NoP -C` flag style combined with 3 of these 5 specific literal templates together is not expected in unrelated software.
**Blind Spots:** A rebuild that rewrites these template strings (for example, full flag names instead of `-NoP -C`, or a reordered WMI property list) evades detection; the rule targets the embedded template text, not the PowerShell process actually launched.
**Validation:** Scan `agent_xworm_v2.exe` (hash below): must match. An unrelated .NET remote-administration tool using different PowerShell one-liner phrasing must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved 109.230.231.37.

```yara
/*
   Yara Rule Set
   Identifier: XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_XWorm_V2_PowerShell_Recon_Templates {
   meta:
      description = "Detects agent_xworm_v2.exe-class XWorm RAT v2.4.0 samples via embedded PowerShell reconnaissance command templates - literal, abbreviated-flag ('-NoP -C') one-liners for process, service, and domain-role enumeration baked into the binary as string constants."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/"
      date = "2026-01-12"
      hash1 = "f8e7e73bf2b26635800a042e7890a35f7376508f288a1ced3d3e12b173c5cb7e"
      hash2 = "7c624e0b11c817d516f9411972191c4627fd2e53"
      hash3 = "4164a1945d8373255a5cb7e42f05c259"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37"
      id = "1c927802-6eb2-5209-af09-3590a2c9cbf3"
   strings:
      $ps1 = "-NoP -C Get-Process|Sort CPU" ascii wide
      $ps2 = "-NoP -C Get-Service|?{$_.Status -eq 'Running'}" ascii wide
      $ps3 = "-NoP -C Get-WmiObject Win32_ComputerSystem" ascii wide
      $ps4 = "PartOfDomain,Domain,DomainRole" ascii wide
      $ps5 = "Select -First 20 Name,Id,CPU,WS" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 100KB and
      3 of them
}
```

### Hunting Rules

#### XWorm v2.x Family Multi-Signal Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1057 (Process Discovery), T1007 (System Service Discovery), T1564.003 (Hidden Window)
**Confidence:** MODERATE
**Rationale:** This rule keeps the original three-branch structure intact. Branch one anchors on the custom `AgentSec_` secret-naming convention plus WebSocket namespace usage plus a generic decimal version-pattern regex. Branches two and three lean heavily on ubiquitous .NET Framework namespace strings (`mscorlib`, `System.Diagnostics.Process`, `System.Security.Cryptography`) and common WinAPI or method names (`ShowWindow`, `GetConsoleWindow`, `ToBase64String`, `MD5`, `ComputeHash`) that are individually common in unrelated .NET software. Because the condition ORs all three branches together, overall precision is governed by the weakest branch, so the rule is kept at Hunting despite branch one's more distinctive anchor. No goodware-corpus scan was run.
**False Positives:** Branches two and three are expected to co-fire with legitimate .NET utilities that combine process and service discovery, cryptographic hashing, and Base64 encoding, a common combination in monitoring agents, installers, and admin tooling. Branch one's `version_pattern` regex (any `2.N.N` substring) is itself extremely common in embedded .NET version metadata.
**Deployment:** Broad endpoint and EDR scanning sweep, retroactive hunt across file shares. Treat hits outside the `AgentSec_`/WebSocket branch as lower-confidence triage candidates.

```yara
rule MAL_XWorm_V2_Family_Combination {
   meta:
      description = "Detects XWorm RAT v2.x variants via a combination of the operator's AgentSec_ authentication-secret naming convention, WebSocket C2 namespace usage, and a broader fallback combination of .NET framework markers, PowerShell reconnaissance API references, hidden-window stealth calls, and Base64 encoding. The fallback branches are individually common in unrelated .NET software - treat hits outside the AgentSec_/WebSocket branch as lower-confidence."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/"
      date = "2026-01-12"
      hash1 = "f8e7e73bf2b26635800a042e7890a35f7376508f288a1ced3d3e12b173c5cb7e"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37"
      id = "121d800f-9d9a-5289-9bc6-3884e2f89e9b"
   strings:
      $dotnet1 = "System.Net.WebSockets" ascii wide
      $dotnet2 = "System.Diagnostics.Process" ascii wide
      $dotnet3 = "System.Security.Cryptography" ascii wide
      $dotnet4 = "mscorlib" ascii wide

      $version_pattern = /2\.[0-9]\.[0-9]/ ascii wide
      $websocket = "WebSocket" ascii wide nocase
      $agent_sec = "AgentSec_" ascii wide

      $ps1 = "Get-Process" ascii wide nocase
      $ps2 = "Get-Service" ascii wide nocase
      $ps3 = "Win32_ComputerSystem" ascii wide

      $stealth1 = "ShowWindow" ascii wide
      $stealth2 = "GetConsoleWindow" ascii wide
      $encode = "ToBase64String" ascii wide

      $md5 = "MD5" ascii wide
      $hash = "ComputeHash" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         ($dotnet1 and $websocket and $agent_sec and $version_pattern) or
         (2 of ($dotnet*) and 2 of ($ps*) and 1 of ($stealth*) and $encode) or
         ($md5 and $hash and $websocket and 1 of ($ps*))
      )
}
```

#### XWorm AgentSec Authentication Secret Pattern

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols — C2 authentication)
**Confidence:** MODERATE
**Rationale:** The regex generalizes the `AgentSec_` prefix and 40-50 character alphanumeric shape beyond this one build's literal secret value, giving it recurrence value across future builds that share this operator's naming convention. It is a single-criterion match with no corroborating combination, so it is capped at Hunting rather than Detection even though the specific nine-character prefix plus length-bounded random suffix is unlikely to appear in unrelated software.
**False Positives:** Unlikely for unrelated software: the literal `AgentSec_` prefix followed immediately by 40 to 50 alphanumeric characters is not a pattern expected outside this naming convention. Residual risk comes from an unrelated tool coincidentally reusing the same variable or constant naming style.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule MAL_XWorm_AgentSec_Secret_Pattern {
   meta:
      description = "Detects the XWorm AgentSec_ authentication-secret naming pattern - a 9-character literal prefix followed by a 40-50 character alphanumeric secret value, used as this operator's shared C2 authentication credential. Generalizes beyond the specific secret instance observed in agent_xworm_v2.exe to catch future builds sharing this naming convention."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/"
      date = "2026-01-12"
      hash1 = "f8e7e73bf2b26635800a042e7890a35f7376508f288a1ced3d3e12b173c5cb7e"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37"
      id = "9438bdfd-1af1-5dfa-b0ba-d7ed7ecacd58"
   strings:
      $pattern1 = /AgentSec_[0-9A-Za-z]{40,50}/ ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $pattern1
}
```

#### Generic .NET WebSocket C2 Capability Combination

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding)
**Confidence:** LOW
**Rationale:** Every individual string is a standard .NET WebSocket API name or a common English networking term (`Heartbeat`, `Reconnect`, `Frame`). Legitimate .NET applications implementing WebSocket clients (chat, streaming, telemetry, dashboards) are expected to use the same API surface and similar terminology. This is kept as a Hunting-only broad toolkit heuristic; there is no bespoke XWorm-specific anchor beyond the co-occurrence pattern itself.
**False Positives:** Expect co-fire with legitimate .NET WebSocket client or server applications; analyst review of binary provenance is required before treating a hit as malicious.
**Deployment:** Broad endpoint and EDR scanning sweep. Treat hits as triage candidates, not alerts.

```yara
rule SUSP_XWorm_V2_WebSocket_Generic_Combination {
   meta:
      description = "Detects .NET executables combining WebSocket client API usage with C2-adjacent terminology (Heartbeat/Reconnect/Frame) - a broad toolkit-family heuristic matching XWorm v2.x's WebSocket C2 implementation style. Not specific to XWorm; expect co-fire with legitimate .NET WebSocket applications."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/"
      date = "2026-01-12"
      hash1 = "f8e7e73bf2b26635800a042e7890a35f7376508f288a1ced3d3e12b173c5cb7e"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "XWorm-RAT-v2.4.0-OpenDirectory-109.230.231.37"
      id = "95dd3d1d-0d7b-51c2-a09c-ebd45e04b1af"
   strings:
      $ws1 = "System.Net.WebSockets" ascii wide
      $ws2 = "WebSocketState" ascii wide
      $ws3 = "SendAsync" ascii wide
      $ws4 = "ReceiveAsync" ascii wide

      $c2_1 = "Heartbeat" ascii wide nocase
      $c2_2 = "Reconnect" ascii wide nocase
      $c2_3 = "Frame" ascii wide

      $dotnet = "mscorlib" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 200KB and
      $dotnet and
      3 of ($ws*) and
      2 of ($c2_*)
}
```

---

## Sigma Rules

### Detection Rules

#### XWorm v2.x Full PowerShell Reconnaissance Sequence on Same Host

**Tier:** Detection (correlation rule) — bundled below with its 3 required non-alerting base rules
**Robustness:** 3 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1059.001 (PowerShell), T1082 (System Information Discovery), T1057 (Process Discovery), T1007 (System Service Discovery), T1482 (Domain Trust Discovery)
**Confidence:** HIGH
**Rationale:** This is a retiering fix. The original rule fired at `level: high` on any one of three individually common PowerShell fragments via a single `ScriptBlockText` field with a list of contains values (OR semantics), an inflated-level-on-generic-selector defect, since `Win32_ComputerSystem` alone is common in legitimate inventory scripting. Each `-NoP -C ...` fragment is a command-line prefix for a separate `powershell.exe` process launch, not three lines inside one script block, matching the process-spawn pattern the original EDR hunting query targeted (`ProcessCommandLine has "-NoP -C"`). The rule has been restructured into three named base rules on `process_creation`, each matching one literal command-line launch, combined via a temporal correlation requiring all three on the same host within a 5-minute window. No individual command is alerting-grade alone, but a legitimate administrative workflow launching all three of these exact literal one-liners together in that window is implausible; the correlation is what earns Detection-grade precision, not any single fragment.
**False Positives:** Any one base rule alone is common in legitimate inventory or RMM scripting and does not alert. The correlation requiring all three within 5 minutes on the same host is not expected outside this malware's embedded reconnaissance routine.
**Blind Spots:** A rebuild that rewrites one or more of the three literal command fragments, or that spreads the reconnaissance sweep beyond the 5-minute window, evades the correlation. Requires process-creation telemetry (Sysmon Event ID 1 or EDR equivalent).
**Validation:** Trigger all three base process launches on the same host within 5 minutes: the correlation must fire. A host showing only one or two of the three process launches must NOT trigger the correlation.
**Deployment:** SIEM correlation engine with Sysmon/EDR process-creation telemetry ingested (5-minute temporal join on `host.name`).

```yaml
title: XWorm RAT v2.x PowerShell Reconnaissance Process Launch - Get-Process Enumeration (Base Rule)
id: 6fd742c2-b2cd-4c83-be66-06dd562e200d
name: xworm_v2_recon_getprocess
status: experimental
description: >-
  Base rule (not alerting on its own): PowerShell process launched with the
  -NoP -C Get-Process|Sort CPU command-line fragment. Paired with two other
  base rules via the correlation rule below, which flags all three of XWorm
  RAT v2.x's embedded reconnaissance commands launching on the same host in
  a short window.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.execution
  - attack.t1059.001
  - attack.discovery
  - attack.t1057
  - detection.emerging-threats
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-NoP -C Get-Process|Sort CPU'
  condition: selection
falsepositives:
  - >-
    Legitimate inventory or RMM scripting using this exact literal command
    fragment is uncommon but not impossible. Not alerting on its own; reviewed
    only in combination with the two paired base rules.
level: informational
---
title: XWorm RAT v2.x PowerShell Reconnaissance Process Launch - Get-Service Enumeration (Base Rule)
id: 7632ad33-882e-4595-8bf6-42cfbeeef52c
name: xworm_v2_recon_getservice
status: experimental
description: >-
  Base rule (not alerting on its own): PowerShell process launched with the
  -NoP -C Get-Service command-line fragment. Paired with two other base rules
  via the correlation rule below.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.execution
  - attack.t1059.001
  - attack.discovery
  - attack.t1007
  - detection.emerging-threats
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-NoP -C Get-Service|?{$_.Status -eq'
  condition: selection
falsepositives:
  - >-
    Legitimate inventory or RMM scripting using this exact literal command
    fragment is uncommon but not impossible. Not alerting on its own; reviewed
    only in combination with the two paired base rules.
level: informational
---
title: XWorm RAT v2.x PowerShell Reconnaissance Process Launch - Domain Role Enumeration (Base Rule)
id: 7540e848-d3a6-43de-90b7-f55c30b3ffc8
name: xworm_v2_recon_domainrole
status: experimental
description: >-
  Base rule (not alerting on its own): PowerShell process launched with the
  -NoP -C Get-WmiObject Win32_ComputerSystem command-line fragment. Paired
  with two other base rules via the correlation rule below.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.execution
  - attack.t1059.001
  - attack.discovery
  - attack.t1482
  - detection.emerging-threats
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-NoP -C Get-WmiObject Win32_ComputerSystem'
  condition: selection
falsepositives:
  - >-
    Legitimate inventory or RMM scripting using this exact literal command
    fragment is uncommon but not impossible. Not alerting on its own; reviewed
    only in combination with the two paired base rules.
level: informational
---
title: XWorm RAT v2.x Full PowerShell Reconnaissance Sequence on Same Host
id: 4b27faae-f708-4555-930c-c2054c9f060b
status: experimental
description: >-
  Fires when all three of XWorm RAT v2.x's embedded PowerShell reconnaissance
  commands (process enumeration, service enumeration, and domain-role
  discovery via WMI) launch as separate processes on the same host within a
  short window. Each command is a distinct powershell.exe invocation using
  the abbreviated -NoP -C flag combination, matching the malware's documented
  embedded reconnaissance templates. No individual command is alerting-grade
  alone, but a legitimate administrative workflow launching all three of
  these exact literal one-liners together within 5 minutes is implausible.
references:
  - https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.execution
  - attack.t1059.001
  - attack.discovery
  - attack.t1082
  - detection.emerging-threats
correlation:
  type: temporal
  rules:
    - xworm_v2_recon_getprocess
    - xworm_v2_recon_getservice
    - xworm_v2_recon_domainrole
  group-by:
    - host.name
  timespan: 5m
falsepositives:
  - >-
    A coordinated administrative script deliberately running all three
    literal one-liners together within 5 minutes is implausible outside
    this malware's embedded reconnaissance routine.
level: high
```

### Hunting Rules

#### PowerShell Execution from .NET Process in User-Writable Directory

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** MODERATE
**Rationale:** This is a retiering fix, demoted from `level: high`. This is a generic process-ancestry and command-line-flag heuristic, not XWorm-specific, and is a well-documented noise source in real SOC operation: numerous legitimate Electron-based application updaters (Slack, Discord, Teams, VS Code extensions) and RMM or deployment tooling routinely spawn `powershell.exe` with abbreviated flags from AppData or Temp as part of normal update mechanisms. The existing Microsoft/Visual-Studio-signed-path filter narrows this somewhat but does not exclude the broader population of non-Microsoft Electron or RMM updaters. It is kept as Hunting rather than Cut because the `-NoP -C` flag plus user-directory-parent combination is a genuine, non-atomic behavioral lead worth analyst triage.
**False Positives:** Legitimate development tools and software installers or updaters spawning PowerShell helper scripts from AppData or Temp (Electron auto-updaters, RMM agents, browser or messaging-app updaters). The existing filter excludes only Microsoft- and Visual-Studio-branded parent paths.
**Deployment:** Sysmon/EDR process-creation telemetry with parent-child lineage.

```yaml
title: PowerShell Execution from .NET Process in User-Writable Directory
id: caaeb533-e084-40bc-a870-81f8b6c5c4a7
status: experimental
description: >-
  Detects PowerShell execution using the abbreviated -NoP -C flag combination
  from a parent .exe running in a user-writable directory (AppData, Temp, or
  Users), excluding Microsoft- and Visual-Studio-signed paths. This process
  ancestry pattern matches XWorm RAT v2.x's execution style but is not
  XWorm-specific - legitimate Electron-based application updaters and RMM
  tooling commonly spawn PowerShell the same way, so hits require analyst
  review.
references:
    - https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: 'powershell.exe'
        CommandLine|contains: '-NoP -C'
    selection_parent:
        ParentImage|contains:
            - '\AppData\'
            - '\Temp\'
            - '\Users\'
        ParentImage|endswith: '.exe'
    filter:
        ParentImage|contains:
            - 'Microsoft'
            - 'Visual Studio'
    condition: selection_powershell and selection_parent and not filter
falsepositives:
    - >-
      Legitimate Electron-based application auto-updaters (Slack, Discord, Teams,
      VS Code extensions), RMM tooling, and software installers routinely spawn
      PowerShell with abbreviated flags from AppData or Temp.
level: medium
```

---

## Suricata Signatures

### Hunting Rules

#### XWorm AgentSec Authentication Secret Pattern in TCP Payload

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** The sample's confirmed capability analysis lists the `AgentSec_` secret as a high-confidence indicator with expected network visibility, and the regex generalizes beyond this one build's literal secret value to catch future builds sharing the naming convention. However, the sample's C2 channel was never observed live (it was offline when the sample was recovered) and the malware's documented C2 characteristics describe Base64-encoded command and data transmission over WebSocket. If the authentication exchange itself is wrapped in the same encoding, a raw-payload literal match would not fire against real traffic. Given this unconfirmed wire-format risk, the rule is capped at Hunting rather than Detection.
**False Positives:** The `AgentSec_` prefix followed by 40 to 50 alphanumeric characters is not expected in unrelated network traffic. The greater risk here is under-detection (never firing) rather than over-firing, given the unconfirmed encoding.
**Deployment:** Network IDS/IPS on egress and internal segments. Treat hits as a strong lead requiring packet capture review to confirm wire format.

```
alert tcp $HOME_NET any -> any any (msg:"THL HUNT XWormV2-109.230.231.37 AgentSec Authentication Secret Pattern in TCP Payload (Unconfirmed Wire Encoding)"; flow:established,to_server; content:"AgentSec_"; nocase; pcre:"/AgentSec_[0-9A-Za-z]{40,50}/i"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000023; rev:1; metadata:author The_Hunters_Ledger, date 2026-01-12, reference https://the-hunters-ledger.com/hunting-detections/agent-xworm-v2-exe-detections/;)
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA single-sample fingerprint cut (Rule 1, "Agent_Xworm_V2_Specific_Hash").** The original rule's condition required all four of the C2 IP, the literal authentication-secret instance, the version string, and the internal build filename to co-occur (`all of them`), a combination requiring literally every attacker-chosen literal from one specific build, with no behavioral or structural component. Removing any single element, for example a C2 IP rotation, breaks the match entirely. This is the project's canonical single-sample hash-equivalent pattern. All four underlying literals were already present in the IOC feed, so the rule has been cut rather than carried forward.
- **Sigma inflated-level single-token selector rebuilt as a temporal correlation** ("XWorm RAT PowerShell Reconnaissance Command Sequence" became "XWorm v2.x Full PowerShell Reconnaissance Sequence on Same Host"). The original rule fired at `level: high` on any one of three individually common PowerShell fragments via a single `ScriptBlockText` contains list (OR semantics), a Gate 4 inflated-level-on-generic-selector defect, since `Win32_ComputerSystem` alone is common in legitimate inventory scripting. Each `-NoP -C ...` fragment is a command-line prefix for a separate `powershell.exe` process launch (matching the original EDR hunting query's own process-spawn model), not three lines inside one script block, so a same-event "N of" selector would not have matched real telemetry regardless of syntax. The rule has been rebuilt as three non-alerting base rules on `process_creation`, one per literal command launch, joined by a temporal correlation requiring all three on the same host within 5 minutes. This promotes the rule to genuine Detection-grade precision, since the correlation, not any single fragment, is what is actually distinctive to this malware.
- **Sigma level demoted from `high` to `medium`** on the generic PowerShell-parentage rule. "PowerShell Execution from .NET Process in User-Writable Directory" is a non-family-specific heuristic that fires on legitimate Electron-app auto-updaters and RMM tooling spawning PowerShell from AppData with abbreviated flags, a well-documented SOC noise source. The rule's detection logic is unchanged; only its level and tier now reflect this honestly.
- **Suricata WebSocket-upgrade and Base64/"Agent" pattern rules cut for precision failure** (sids `1000022` and `1000024`). Neither rule anchors on anything specific to this campaign: sid `1000022` matches any WebSocket handshake to any destination (ubiquitous in modern legitimate web traffic, including chat widgets, dev-tool hot-reload, and SaaS dashboards); sid `1000024` matches the bare substring "Agent" (a substring of the near-universal HTTP User-Agent header) combined with "WebSocket" and a generic base64-shape PCRE, none of which discriminate this malware from ordinary HTTP or web traffic. Both fail durability (no operator-specific anchor) and precision (fire on ubiquitous benign activity).
- **Suricata AgentSec_ secret-pattern rule (sid `1000023`) capped at Hunting rather than cut.** See the rule's own Rationale above: kept because the sample's confirmed capability analysis documents expected network visibility of this secret, but capped below Detection because the malware's own documented Base64 C2 encoding creates unconfirmed risk that a raw-payload literal match would not fire against real traffic.

### Cut Rules (genuine noise or single-sample fingerprints)

- **YARA "Agent_Xworm_V2_Specific_Hash"** — see Retiering Fixes above. All four underlying literals (C2 IP, authentication-secret instance, version string, internal filename) were already present in the IOC feed.
- **Sigma "XWorm RAT v2.4.0 WebSocket C2 Connection to Known Infrastructure"** (id `f8e7e73b-f2b2-6635-800a-042e7890a35f` in the source file) — a pure `DestinationIp: '109.230.231.37'` selector, structurally identical to the project's canonical Sigma Cut example. The IP is already present in `agent-xworm-v2-exe.json` under `network_indicators.c2_infrastructure.ip`. A prior coverage pass on 2026-07-06, noted in the source file, had already removed a second generic-path/ubiquitous-behavior Sigma rule from this file before this retiering; no recovery of that already-removed rule was attempted.
- **Suricata "Connection to XWorm C2 Server"** (sids `1000020` and `1000021`, an inbound/outbound pair) — pure IP-match rules (`alert tcp $HOME_NET any -> 109.230.231.37 any`, no content or protocol anchor). Textbook Suricata Cut. The IP is already present in the IOC feed.
- **Suricata "WebSocket Upgrade with Suspicious Characteristics"** (sid `1000022`) — no atomic to route; cut for precision failure (fires on any WebSocket handshake to any destination).
- **Suricata "Base64 Encoded WebSocket Payload"** (sid `1000024`) — no atomic to route; cut for precision failure (the "Agent" content anchor is a substring of the near-universal User-Agent HTTP header).

### Atomics Routed to the IOC Feed

- **C2/distribution IP (`109.230.231.37`), file hashes (SHA256, SHA1, MD5), and the literal authentication-secret instance (`AgentSec_8hJ3kL6mN9pQ2rS5tU8vW1xY4zA7bC0d`)** — all already present in [`agent-xworm-v2-exe.json`](/ioc-feeds/agent-xworm-v2-exe.json) under `file_hashes`, `network_indicators.c2_infrastructure.ip`, and `network_indicators.c2_infrastructure.authentication_secret` respectively. No JSON edits were made as part of this migration; presence was verified, not created.

### Unconfirmed C2 Wire Format: Why Network Coverage Stays Thin

The sample's C2 channel was offline when the sample was recovered, and no live session exists to confirm its wire format. The malware's own documented C2 characteristics describe Base64-encoded command and data transmission over WebSocket. Absent a captured session, no protocol-level structure (URI pattern, header combination, frame format) is available to anchor a Suricata Detection or Hunting signature beyond the single AgentSec_ payload-pattern rule retained above, which itself carries the same wire-format uncertainty. This mirrors the disposition applied elsewhere in this project to C2 infrastructure observed only in a pre-activation or unconfirmed state: narrow, honestly-capped coverage until protocol structure is available.

### What Would Enable Stronger Coverage

- **A captured live C2 session** — confirming the actual wire format of the WebSocket handshake and authentication exchange would resolve whether the AgentSec_ Suricata rule fires against real traffic, and would enable a genuine protocol-level Detection signature in place of the current Hunting-only payload-pattern rule.
- **Goodware-corpus validation** — none of the surviving YARA Hunting rules (Family Combination, WebSocket Generic Combination) have been run against a broad clean-software corpus. A documented zero-FP result is the explicit precondition for reconsidering Detection tier on the family-combination rule's AgentSec_/WebSocket branch.
- **A second XWorm v2.x sample sharing the AgentSec_ naming convention** — would confirm whether this is an operator-specific convention (as currently assumed) or a broader XWorm builder-tool convention, sharpening the durability assessment for both the YARA regex rule and the Suricata payload-pattern rule.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
