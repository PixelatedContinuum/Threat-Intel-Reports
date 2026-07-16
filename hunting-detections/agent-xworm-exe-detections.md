---
title: "Detection Rules — agent_xworm.exe (XWorm RAT)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/agent-xworm-exe-detections/
hide: true
redirect_from: /hunting-detections/agent-xworm-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/agent-xworm-exe.json

---

## Detection Coverage Summary

agent_xworm.exe is a 16KB .NET-compiled executable recovered from an open directory at `109.230.231.37`, part of the same Arsenal-237 malware repository exposure documented in the companion agent.exe (PoetRAT-attributed) detection file from the same infrastructure. Family attribution to XWorm RAT sits at HIGH confidence (95%) — code-level constants (`HEARTBEAT_MS`, `GetMachineId`, `BuildFrame`), the `AgentSec_` authentication-secret naming convention, and three embedded PowerShell reconnaissance one-liners match documented XWorm characteristics. XWorm operates as Malware-as-a-Service with builder tooling behind it, so this build's one-off literal values (its exact authentication secret, its unmodified filename) are attacker-rotatable on the next build; coverage below favors the rules anchored to naming conventions and protocol structure that survive a rebuild over the literal-value rules that do not.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. This build's C2 server address was unreachable at discovery — a common pattern for short-lived or rotating XWorm infrastructure — so no live protocol capture is available beyond the authentication-secret handshake format confirmed in the binary's embedded strings; that format anchors the strongest network signature below.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 1 | T1059.001, T1071.001, T1132.001, T1564.003 | 1 |
| Sigma | 0 | 2 | T1059.001, T1105 | 1 |
| Suricata | 1 | 0 | T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the confirmed file hashes (SHA256/SHA1/MD5), the C2 IP (`109.230.231.37`), the literal authentication-secret value, and the `agent_xworm.exe` filename were already present in [`agent-xworm-exe.json`](/ioc-feeds/agent-xworm-exe.json) before this retiering pass. The all-atomics YARA hash-equivalent rule, the IP-match Sigma rule, and the IP-match Suricata signature pair added no detection value beyond those feed entries and have been retired — see Coverage Gaps for the full reasoning on every retired rule.

---

## YARA Rules

### Detection Rules

#### XWorm Embedded PowerShell Reconnaissance Templates

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** HIGH
**Rationale:** Requires 2 of 4 embedded PowerShell one-liner fragments with an unusual flag ordering (`-NoP -C` ahead of the cmdlet chain) and specific cmdlet-and-filter combinations (`Get-Process|Sort CPU`, `Get-Service|?{$_.Status -eq 'Running'}`, `Get-WmiObject Win32_ComputerSystem`, the `PartOfDomain,Domain,DomainRole` field list). These are XWorm's built-in reconnaissance templates rather than operator-configurable values, so they persist across builds that retain this feature — durable to C2 rotation and filename changes, though a rebuild that drops or rewrites these specific templates would evade it.
**False Positives:** None known — this specific flag ordering combined with this specific cmdlet-and-filter phrasing is not a standard PowerShell administration pattern.
**Blind Spots:** A rebuild using PowerShell's standard long-form flags (`-NoProfile -Command`) or different reconnaissance cmdlets evades; the rule targets the executable's embedded string constants, not runtime script-block content.
**Validation:** Scan `agent_xworm.exe` (hash below) — must match; an unrelated PowerShell automation script or admin tool must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_Windows_XWorm_PowerShell_Recon_Templates {
   meta:
      description = "Detects XWorm's embedded PowerShell reconnaissance one-liners: process/CPU enumeration, running-service enumeration, and domain-membership enumeration via WMI, all invoked with the abbreviated -NoP -C flag ordering."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT-Recon-Component"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "feb50486-2a18-4a49-94a1-17e2e6318018"
      hash1 = "0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
   strings:
      $ps1 = "-NoP -C Get-Process|Sort CPU" ascii wide
      $ps2 = "-NoP -C Get-Service|?{$_.Status -eq 'Running'}" ascii wide
      $ps3 = "-NoP -C Get-WmiObject Win32_ComputerSystem" ascii wide
      $ps4 = "PartOfDomain,Domain,DomainRole" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      2 of them
}
```

#### XWorm AgentSec Authentication Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** A capability-abstraction of this build's literal authentication secret: rather than matching the exact 40-character value (a hash-equivalent — see Coverage Gaps), this regex matches the `AgentSec_` naming *convention* plus a length constraint. A future build with a freshly-generated secret still matches; only a rebrand of the prefix itself evades it.
**False Positives:** None known — `AgentSec_` is not a standard credential- or variable-naming convention outside this build family.
**Blind Spots:** A build using a differently-prefixed or differently-structured secret evades; the rule targets the on-disk string, not the runtime authentication exchange (see the companion Suricata signature for the network-observable form of the same pattern).
**Validation:** Scan `agent_xworm.exe` (hash below) — must match; unrelated software using generic terms like "AuthSecret" or "APIKey" without the exact `AgentSec_` prefix must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved 109.230.231.37.

```yara
rule MAL_Windows_XWorm_AgentSec_Authentication_Pattern {
   meta:
      description = "Detects the AgentSec_ authentication-secret naming convention used by this XWorm build family's C2 handshake. Matches the naming pattern rather than one build's literal secret value, so it survives secret rotation across rebuilds."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT-Authentication-Pattern"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "c228a7b7-15c9-4b26-ab4c-09569a1d5ea0"
      hash1 = "0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
   strings:
      $pattern1 = /AgentSec_[0-9A-Za-z]{40,50}/ ascii wide
   condition:
      uint16(0) == 0x5A4D and
      $pattern1
}
```

### Hunting Rules

#### XWorm RAT Capability Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1564.003 (Hide Artifacts: Hidden Window)
**Confidence:** MODERATE
**Rationale:** Three OR'd branches combine XWorm-specific constant/method names (`HEARTBEAT_MS`, `RECONNECT_MS`, `SERVER_HOST`, `AGENT_SECRET`; `HandleCmd`, `GetMachineId`, `GetSysInfo`, `BuildFrame`) with generic .NET framework and WinAPI strings (`System.Net.Sockets`, `ToBase64String`, `ShowWindow`, `TcpClient`). The first branch (config+cmd+net combination) is reasonably distinctive; the second (.NET+stealth+encode+net) leans almost entirely on framework-ubiquitous strings — console-hiding plus Base64 plus TCP networking describes a wide population of legitimate remote-support and automation tooling, not just this family. None of the three branches has been run against a broad clean-software corpus, the explicit precondition for Detection tier on a combination rule this broad. Retained as a Hunting-tier toolkit signature rather than promoted on the strength of the narrower first branch alone.
**False Positives:** Branch 1 (config+cmd+net) is the tightest and least likely to false-positive on unrelated software; Branch 2 (.NET+stealth+encode+net) is expected to co-fire with legitimate .NET remote-access, monitoring, or silent-install tooling that hides its console and communicates over TCP with Base64 framing — a combination not unique to XWorm.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares, email gateway attachment scanning; treat hits as triage candidates, not alerts.

```yara
rule MAL_Windows_XWorm_RAT_Capability_Combination {
   meta:
      description = "Detects XWorm RAT variants via a combination of family-specific constant/method names (HEARTBEAT_MS, RECONNECT_MS, SERVER_HOST, AGENT_SECRET, HandleCmd, GetMachineId, GetSysInfo, BuildFrame) and generic .NET networking/encoding/console-hiding strings. The generic-string branches are broad by design — expect co-fire with legitimate .NET remote-access and automation tooling."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/"
      date = "2026-01-12"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "70dc0a6e-4ca6-4028-bb23-09fdd34169df"
   strings:
      // .NET framework indicators
      $dotnet1 = "System.Net.Sockets" ascii wide
      $dotnet2 = "System.Diagnostics.Process" ascii wide
      $dotnet3 = "System.Security.Cryptography" ascii wide
      $dotnet4 = "mscorlib" ascii wide

      // XWorm configuration constants
      $config1 = "HEARTBEAT_MS" ascii wide
      $config2 = "RECONNECT_MS" ascii wide
      $config3 = "SERVER_HOST" ascii wide
      $config4 = "AGENT_SECRET" ascii wide

      // XWorm command handlers
      $cmd1 = "HandleCmd" ascii wide
      $cmd2 = "GetMachineId" ascii wide
      $cmd3 = "GetSysInfo" ascii wide
      $cmd4 = "BuildFrame" ascii wide

      // Stealth and encoding
      $stealth1 = "ShowWindow" ascii wide
      $stealth2 = "GetConsoleWindow" ascii wide
      $encode1 = "ToBase64String" ascii wide
      $encode2 = "FromBase64String" ascii wide

      // Network operations
      $net1 = "TcpClient" ascii wide
      $net2 = "NetworkStream" ascii wide
      $net3 = "GetStream" ascii wide
      $net4 = "_heartbeatThread" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         // Strong XWorm signature: config + command handlers + network
         (2 of ($config*) and 2 of ($cmd*) and 2 of ($net*)) or

         // Alternative: .NET + stealth + encoding + network
         (2 of ($dotnet*) and 1 of ($stealth*) and 1 of ($encode*) and 2 of ($net*)) or

         // Authentication secret pattern (common across XWorm variants)
         (1 of ($config*) and 1 of ($encode*) and $net4)
      )
}
```

---

## Sigma Rules

### Hunting Rules

#### PowerShell Execution from Suspicious .NET Process

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** LOW
**Rationale:** Combines a PowerShell command-line flag pattern (`-NoP -C`) with a parent-process-location heuristic (AppData/Temp/Users) and a two-vendor exclusion filter. *Retiering note:* the source draft carried this at `level: high` while its own falsepositives field already named "legitimate development tools, software installers" as expected hitters — an honest signal that this sits at Hunting, not Detection (Gate 4). The ParentImage path condition matches nearly any interactively-launched process on a modern Windows host, so the real narrowing comes almost entirely from the command-line flag pattern; the two-vendor filter (Microsoft, Visual Studio) does not cover the much larger population of legitimate installers and automation tools that also invoke PowerShell this way from a user-profile path.
**False Positives:** Software installers, build scripts, and IT automation tooling that invoke PowerShell with abbreviated flags from AppData/Temp/user-profile locations — a common, not rare, pattern.
**Deployment:** SIEM/EDR process-creation telemetry; review parent binary provenance (signer, install context) before treating a hit as malicious.

```yaml
title: PowerShell Execution from Suspicious .NET Process
id: 01027829-5061-9820-bbcd-60efca256c90
status: experimental
description: Detects PowerShell execution from .NET binaries in user-writable directories, a pattern consistent with XWorm's embedded reconnaissance command execution.
references:
    - https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/
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
    - Legitimate development tools, software installers, and administrative scripts that invoke PowerShell with abbreviated flags from a user-profile path.
level: medium
```

#### File Creation Matching XWorm Naming Convention

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** LOW
**Rationale:** A bare `TargetFilename` naming-convention selector — trivially evaded by a custom builder output filename, which XWorm's MaaS builder supports. *Retiering note:* the source draft tagged this `attack.persistence` / `attack.privilege-escalation` / `attack.t1547.001` (Registry Run Keys / Startup Folder), but the selector has no path restriction to a Startup folder or Run-key location — it matches file creation anywhere a matching name appears. The tags did not match the logic (score the logic, not the title); retagged to Ingress Tool Transfer, which is what a naming-pattern match on a freshly-created executable actually evidences. Kept at Hunting rather than Cut because the three-substring family (`xworm`, `xclient`, `agent_xworm`) retains recurrence value against unmodified or default-named deployments, beyond the single `agent_xworm.exe` filename atomic already in the feed.
**False Positives:** Security research and malware-analysis environments; any renamed build defeats this selector entirely.
**Deployment:** Windows file-integrity monitoring, EDR file-creation telemetry; review the full file path and hash of any hit.

```yaml
title: File Creation Matching XWorm Naming Convention
id: 0ec3fca5-8ef8-f0d9-f098-cd749dd209aa
status: experimental
description: Detects creation of executable files matching XWorm's default/observed naming convention (xworm, xclient, agent_xworm). A single-literal naming pattern, trivially evaded by a custom builder output filename — retained as a scoping lead for unmodified or default-named deployments.
references:
    - https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'xworm'
            - 'xclient'
            - 'agent_xworm'
        TargetFilename|endswith: '.exe'
    condition: selection
falsepositives:
    - Security research and malware-analysis environments; a renamed build defeats this selector entirely.
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### XWorm AgentSec Authentication Secret Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** The network-observable form of the same `AgentSec_` naming-convention pattern salvaged in the YARA rule above — the malware's authentication handshake transmits this secret over the wire, per its own C2-authentication design. `content:"AgentSec_"` (9 bytes, bespoke prefix) gates the PCRE rather than the PCRE running unprefiltered, and the pattern survives secret rotation (a fresh per-build secret still matches the prefix-plus-length structure) and C2 IP rotation entirely (no destination anchor).
**False Positives:** None known — `AgentSec_` is not a standard protocol token; the rule does not depend on the current, possibly-offline C2 IP.
**Blind Spots:** A build using a differently-prefixed or differently-structured authentication token evades; requires a completed TCP handshake reaching the authentication exchange, so does not fire on connection attempts alone.
**Validation:** Replay a captured or reconstructed authentication frame containing the `AgentSec_` token — must alert; ordinary TCP traffic containing the substring "Agent" (e.g., HTTP User-Agent headers) must NOT fire.
**Deployment:** Network IDS/IPS at the perimeter and server-segment egress.

```
alert tcp $HOME_NET any -> any any (msg:"THL Arsenal-237 XWorm AgentSec Authentication Secret Pattern (C2 Handshake Indicator)"; flow:to_server,established; content:"AgentSec_"; nocase; pcre:"/AgentSec_[0-9A-Za-z]{40,50}/i"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000013; rev:1; metadata:author The_Hunters_Ledger, date 2026-01-12, reference https://the-hunters-ledger.com/hunting-detections/agent-xworm-exe-detections/;)
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA "XWorm RAT Capability Combination" demoted from `severity = "HIGH"` to Hunting.** No compile defect was found (all wildcard string-group references in the condition correctly match their declared identifiers), but two of the rule's three OR'd branches lean heavily on .NET-framework and WinAPI strings (`System.Net.Sockets`, `ToBase64String`, `ShowWindow`, `TcpClient`) that are common across legitimate .NET networking and remote-access tooling. None of the three branches has been validated against a broad clean-software corpus, the documented precondition for Detection tier on a combination this broad.
- **YARA "PowerShell Reconnaissance Commands" and "AgentSec Authentication Pattern" promoted to Detection.** Both anchor on multi-token or naming-convention matches distinctive enough, and durable enough across rebuilds and secret rotation, to clear the Detection bar; neither depends on the sample's C2 IP or filename.
- **Sigma "PowerShell Execution from Suspicious .NET Process" demoted from `level: high` to `level: medium` and retiered Hunting.** The source draft's own `falsepositives` field already named "legitimate development tools, software installers" as expected hitters — an honest signal the rule belongs in Hunting, not Detection (Gate 4 level discipline).
- **Sigma "File Creation with XWorm Naming Pattern" retagged.** The source draft carried `attack.persistence` / `attack.privilege-escalation` / `attack.t1547.001` (Registry Run Keys / Startup Folder), but the selector has no path restriction to a Startup folder or Run-key location — it is a bare filename-content match with no persistence-location evidence. Retagged to `attack.t1105` (Ingress Tool Transfer), which is what the logic as written actually evidences; retained at Hunting rather than Cut given the three-substring naming family still has scoping value beyond the single filename atomic already in the feed.
- **Suricata "XWorm AgentSec Authentication Secret Pattern" (sid 1000013) carried forward unchanged, tier raised to Detection.** The rule was already structurally sound as authored (content-gated PCRE, `flow` set, no destination-IP dependency) — a `threshold` clause was added for alert-volume hygiene, consistent with the project's other beaconing-adjacent Suricata signatures.

### Cut Rules (genuine noise — not routed to the feed)

- **Suricata "Base64 Encoded C2 Traffic Pattern"** (source sid `1000012`) — cut. The 5-byte `content:"|41 67 65 6e 74|"` anchor is the literal ASCII bytes for "Agent" with no application-layer buffer restriction, so it matches the raw TCP payload of virtually any HTTP flow (every `User-Agent:` header contains that substring). The anchored PCRE (`/^[A-Za-z0-9+\/]{20,}={0,2}$/`) additionally requires the *entire* packet payload to be pure base64 charset with no framing bytes — a condition ordinary packet structure essentially never satisfies. This combination fails both durability-of-purpose and precision, and the pattern is speculative rather than derived from an observed C2 session (the C2 address was unreachable at discovery). Not a routable atomic — there is no concrete indicator value to send to the feed.

### Atomics Routed to the IOC Feed

- **YARA "agent_xworm.exe Specific Hash Detection"** (source Rule 1) — required *all* of the C2 IP string, the literal 40-character authentication secret, and the literal filename to co-occur; removing any one leaves nothing behavioral behind. This is a hash-equivalent — it matches exactly the one known build and adds no detection value beyond the SHA256/SHA1/MD5 hash trio, C2 IP, secret, and filename already present in `agent-xworm-exe.json`.
- **Sigma "XWorm C2 Connection to Known Infrastructure"** (source Rule 1, id `0ec3fca5-8ef8-f0d9-f098-cd749dd209fc`) — a bare `DestinationIp: '109.230.231.37'` selector. Textbook Sigma Cut per the project checklist. Already present in the feed.
- **Suricata "Connection to XWorm C2 Server"** (source sids `1000010` and `1000011`, inbound/outbound pair) — pure IP-match rules (`alert tcp $HOME_NET any -> 109.230.231.37 any`, no content/protocol anchor). Textbook Suricata Cut. Already present in the feed.

### Pre-Existing Gap: Source Rule Numbering

The source file's Sigma section jumps from "Rule 1" directly to "Rule 3" with an embedded coverage note ("Rules matching generic file paths or ubiquitous behaviors were removed as false-positive sources") — a prior edit had already removed a "Rule 2" before this retiering pass. That removal is not reconstructed here; this file's accounting starts from the three Sigma rule blocks actually present in the source.

### What Would Enable Stronger Coverage

- **Goodware corpus validation** — none of the Hunting-tier YARA rule's three branches, nor the two Hunting-tier Sigma rules, have been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition for reconsidering any of them for Detection.
- **A reachable or reconstructed C2 session** — would allow a broader Suricata signature anchored to the frame-based protocol structure (`BuildFrame`) or heartbeat cadence, beyond the authentication-secret token alone.
- **Confirmation of builder-default vs. operator-customized templates** — determining whether the embedded PowerShell reconnaissance one-liners are a fixed XWorm-builder feature (as treated here) or an operator-editable option would sharpen or weaken the family-wide durability claim behind the Detection-tier PowerShell YARA rule.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
