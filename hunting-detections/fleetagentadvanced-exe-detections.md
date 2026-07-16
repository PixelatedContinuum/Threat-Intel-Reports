---
title: "Detection Rules — FleetAgentAdvanced.exe (Multi-Layer Persistence Trojan)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/fleetagentadvanced-exe-detections/
hide: true
redirect_from: /hunting-detections/fleetagentadvanced-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/fleetagentadvanced-exe.json

---

## Detection Coverage Summary

FleetAgentAdvanced.exe is a .NET-compiled dropper/trojan recovered from an open directory at `109.230.231.37`, alongside several other malware families staged on the same distribution infrastructure (agent.exe/PoetRAT, agent_xworm.exe and agent_xworm_v2.exe/NjRAT-XWorm). The codebase does not match any known family (HIGH confidence, 90%) and carries no named threat-actor attribution. The dropper establishes four redundant persistence mechanisms — a Registry Run key, a scheduled task, and two Startup-folder shortcuts — all branded to impersonate a Microsoft .NET Runtime Optimization component, then deploys a secondary payload (RuntimeOptimization.exe) from an embedded, Base64-decoded resource. Its command-and-control channel stays dormant despite confirmed networking and cryptographic capability built into the binary, so no protocol structure is available to anchor a network signature.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. Coverage here is scoped to the artifacts that retain analyst value after retiering: the dropper's internal function-naming convention and a fixed Windows API injection sequence anchor the Detection-tier rules, while the "Microsoft .NET Runtime Optimization" masquerade branding — renameable at will by the operator, and itself an impersonation of a real, common product name rather than a bespoke marker — anchors the Hunting-tier rules instead. The campaign's atomic indicators (the distribution IP and the payload's install path) are carried in the IOC feed rather than as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 1 | T1027, T1547.001, T1053.005, T1055, T1036.005 | 0 |
| Sigma | 1 | 5 | T1055, T1547.001, T1036.005, T1053.005, T1070.004, T1027 | 2 |
| Suricata | 0 | 0 | — | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the distribution IP (`109.230.231.37`) and the RuntimeOptimization.exe payload's install path (`%AppData%\Microsoft\CLR\RuntimeOptimization.exe`, carried as the `location` field on its hash entry) were already present in [`fleetagentadvanced-exe.json`](/ioc-feeds/fleetagentadvanced-exe.json) before this retiering pass. The pure-path Sigma selectors and the pure-IP Suricata signature added no detection value beyond those feed entries and have been retired — see Coverage Gaps for the full reasoning on every retired rule.

---

## YARA Rules

### Detection Rules

#### FleetAgentAdvanced Dropper Hash and Coined Function-Name Combination

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1547.001 (Registry Run Keys / Startup Folder), T1053.005 (Scheduled Task), T1055 (Process Injection)
**Confidence:** HIGH
**Rationale:** Fires on an exact hash match, or on 3 of 6 internal .NET method names — `DropEmbeddedAgent`, `SetPersistence`, `CreateShortcut`, `StartWatchdog`, `RunWatchdog`, `InjectIntoProcess` — that the developer coined for this specific codebase. Unlike the masquerade branding used elsewhere in this dropper, these are bespoke names with no real product to impersonate, so they survive a masquerade rebrand: an operator who renames the "Microsoft .NET Runtime Optimization" persistence branding in a future build does not need to touch these internal method names, and vice versa. *Retiering fix applied:* the source rule declared `$crypto1`, `$crypto2`, `$net1`, `$net2` strings that were never referenced anywhere in the condition — a hard error under the real `yarac` compiler ("unreferenced string"), meaning the original rule never compiled at all. Those unused strings are dropped here rather than wired into the condition post hoc. The source rule's two weaker OR-branches (a config-variable-name pair gated on the masquerade strings, and a single generic Windows API string gated on the masquerade strings) have been moved to the companion Hunting rule below rather than left inside this rule, where either weak branch would have dragged the whole rule's precision down to its lowest common denominator.
**False Positives:** None known for the hash branch (exact-file equality). For the function-name branch: `CreateShortcut` alone is a common .NET method name for legitimate LNK-creation code, but the combination of any 3 of the 6 names — several of which (`SetPersistence`, `InjectIntoProcess`) are not terms a benign application would plausibly name a method — is not expected to co-occur in unrelated software.
**Blind Spots:** A full rebuild renaming the internal method-naming convention evades the function-name branch entirely; only the hash branch would then remain, and only for this exact build.
**Validation:** Scan `FleetAgentAdvanced.exe` (hash below) — must match; an unrelated .NET installer or shortcut-creation utility using only `CreateShortcut` must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved `109.230.231.37`.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/
import "hash"

rule MAL_FleetAgentAdvanced_Dropper_Hash_Function_Combo {
   meta:
      description = "Detects FleetAgentAdvanced.exe dropper via exact file hash, or via a combination of at least 3 of 6 distinctive, operator-coined internal .NET method names (DropEmbeddedAgent, SetPersistence, CreateShortcut, StartWatchdog, RunWatchdog, InjectIntoProcess) that survive a masquerade-branding rebrand."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/"
      date = "2026-01-12"
      hash1 = "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b"
      family = "FleetAgentAdvanced"
      malware_type = "Dropper-Trojan"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "bf7dbbc0-99af-557d-96a8-69a6247efa88"
   strings:
      $func1 = "DropEmbeddedAgent" ascii wide
      $func2 = "SetPersistence" ascii wide
      $func3 = "CreateShortcut" ascii wide
      $func4 = "StartWatchdog" ascii wide
      $func5 = "RunWatchdog" ascii wide
      $func6 = "InjectIntoProcess" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         hash.sha256(0, filesize) == "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b" or
         3 of ($func*)
      )
}
```

### Hunting Rules

#### FleetAgentAdvanced .NET Masquerade Configuration and API Combination

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Masquerading), T1055 (Process Injection)
**Confidence:** LOW
**Rationale:** Fires when 2 of 7 operator-coined configuration-variable names (`EMBEDDED_AGENT`, `INSTALL_NAME`, `STARTUP_NAME`, `WATCHDOG_MUTEX`, `MUTEX_NAME`, `SERVER_HOST`, `AGENT_SECRET`) co-occur with any of the "Microsoft .NET Runtime Optimization" masquerade strings, or when any generic process-injection API string co-occurs with the same masquerade family. Both branches depend entirely on that masquerade-string family for their false-positive control — a naming-convention rebrand defeats both. "Microsoft .NET Runtime Optimization" impersonates a real, common product/vendor name rather than coining a bespoke marker, which is the rubric's own disqualifying case for Detection regardless of what else the branch requires alongside it. *Retiering note:* this is the source rule's two weaker OR-branches, split out from the hash/function-name branches above (which do not depend on this masquerade family and are Detection-eligible on their own).
**False Positives:** Unlikely for the exact two-literal pairing, but not zero — the API-string branch in particular reduces almost entirely to "any of 5 common Windows API names," which is close to universal among binaries that touch process memory; the masquerade-string requirement is doing essentially all of the real filtering in both branches.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares; treat hits as scoping leads for this build family, not alerts.

```yara
rule SUSP_FleetAgentAdvanced_NET_Masquerade_Combination {
   meta:
      description = "Detects .NET executables combining FleetAgentAdvanced-style configuration variable names (WATCHDOG_MUTEX, AGENT_SECRET, EMBEDDED_AGENT, etc.) or generic process-injection API references with the Microsoft .NET Runtime Optimization masquerade strings. Brittle to a masquerade-naming rebrand — treat as a scoping lead, not an alert."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/"
      date = "2026-01-12"
      family = "FleetAgentAdvanced"
      malware_type = "Dropper-Trojan-Masquerade-Component"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "4a8d104a-d581-5c8b-bd16-1c72215b0e87"
   strings:
      $config1 = "EMBEDDED_AGENT" ascii wide
      $config2 = "INSTALL_NAME" ascii wide
      $config3 = "STARTUP_NAME" ascii wide
      $config4 = "WATCHDOG_MUTEX" ascii wide
      $config5 = "MUTEX_NAME" ascii wide
      $config6 = "SERVER_HOST" ascii wide
      $config7 = "AGENT_SECRET" ascii wide

      $persist1 = "RuntimeOptimization.exe" ascii wide
      $persist2 = "Microsoft .NET Runtime Optimization" ascii wide
      $persist3 = "Microsoft\\CLR" ascii wide

      $api1 = "VirtualAllocEx" ascii
      $api2 = "WriteProcessMemory" ascii
      $api3 = "CreateRemoteThread" ascii
      $api4 = "NtUnmapViewOfSection" ascii
      $api5 = "PAGE_EXECUTE_READWRITE" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         (2 of ($config*) and any of ($persist*)) or
         (any of ($api*) and any of ($persist*))
      )
}
```

---

## Sigma Rules

### Detection Rules

#### FleetAgentAdvanced Process Injection from .NET Executable

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055 (Process Injection)
**Confidence:** HIGH
**Rationale:** Requires the classic `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` remote-thread-injection API triad to appear together in a process-access call trace, with the source image running from AppData rather than Program Files. All three API names are fixed Windows API entry points the malware must call to perform this exact injection technique — not an attacker-chosen literal — so the rule survives any rebrand of the dropper's masquerade branding or internal naming. An attacker can only evade it by switching to a materially different injection technique (e.g., `NtMapViewOfSection`-based mapping injection, APC queuing) rather than by renaming anything.
**False Positives:** Legitimate development tools and debuggers from AppData.
**Blind Spots:** Misses injection techniques other than the classic triad (process hollowing via `NtUnmapViewOfSection`, APC-based injection); requires `CallTrace` telemetry (Sysmon Event ID 10 with appropriate configuration).
**Validation:** Trigger the classic injection triad from a process running out of `%AppData%` — must match; the same triad from a process under `\Program Files\` must NOT fire.
**Deployment:** Sysmon process-access monitoring (Event ID 10), EDR API-hooking telemetry.

```yaml
title: FleetAgentAdvanced Process Injection from .NET Executable
id: 1ca5cfa6-f7af-4dde-80b1-87edbf3c637b
status: experimental
description: >-
  Detects the VirtualAllocEx, WriteProcessMemory, CreateRemoteThread process
  injection API sequence in a process-access call trace where the source image
  runs from AppData rather than Program Files.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1055
  - detection.emerging-threats
logsource:
  category: process_access
  product: windows
detection:
  selection:
    SourceImage|contains: '\AppData\'
    CallTrace|contains|all:
      - 'VirtualAllocEx'
      - 'WriteProcessMemory'
      - 'CreateRemoteThread'
  filter_legitimate:
    SourceImage|contains:
      - '\Program Files\'
      - '\Program Files (x86)\'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate development tools and debuggers from AppData
level: high
```

### Hunting Rules

#### FleetAgentAdvanced Persistence with Microsoft .NET Masquerading

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder), T1036.005 (Masquerading)
**Confidence:** LOW
**Rationale:** Requires a Registry Run-key value whose data references "Microsoft", ".NET", and "Runtime" together while also pointing at an AppData path — a combination that does not occur in a legitimate Microsoft .NET Runtime install (those run from Program Files / `Windows\Microsoft.NET\Framework\`, never AppData). *Retiering fix applied:* demoted from the source's Detection-equivalent `level: high` to Hunting/`level: medium`. Requiring an AppData-location anomaly alongside the masquerade words looks like it should raise the bar above a bare masquerade-string selector, but on inspection the AppData-location half is, by itself, extremely common in legitimate consumer software (Dropbox, Discord, Slack, and many other mainstream apps auto-start from AppData via this exact Run-key mechanism) — so the rule's real precision still derives almost entirely from the renameable "Microsoft"/".NET"/"Runtime" branding, not from the location check. See "A Genuinely Close Call" in Coverage Gaps for the full reasoning.
**False Positives:** Unsigned .NET development tools using Microsoft/.NET/Runtime naming in AppData (verify legitimacy); any legitimate AppData-resident auto-start application whose display strings happen to reference all three words.
**Deployment:** Registry auditing, Sysmon Event ID 13 (registry value set), EDR registry-monitoring telemetry; treat hits as scoping leads, not alerts.

```yaml
title: FleetAgentAdvanced Persistence with Microsoft .NET Masquerading
id: ccf14e14-5328-4d1b-98b9-27088663076e
status: experimental
description: >-
  Detects creation of a Registry Run-key value whose data references Microsoft,
  .NET, and Runtime branding together while pointing at an executable in
  AppData — a location legitimate Microsoft .NET Runtime components never use.
  Hunting-tier: the masquerade branding is attacker-chosen and renameable, and
  the AppData-location half of the check is common among legitimate consumer
  auto-start software on its own.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1547.001
  - attack.t1036.005
  - detection.emerging-threats
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
    Details|contains|all:
      - 'Microsoft'
      - '.NET'
      - 'Runtime'
    Details|contains: '\AppData\'
  condition: selection
falsepositives:
  - Unsigned .NET development tools using Microsoft/.NET/Runtime naming in AppData (verify legitimacy)
level: medium
```

#### FleetAgentAdvanced Scheduled-Task Masquerade Creation and task.xml Deletion (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its 2 required non-alerting base rules
**Robustness:** 2 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1070.004 (Indicator Removal: File Deletion)
**Confidence:** LOW — both base signals are individually brittle, masquerade-literal-dependent selectors; the correlation adds real but limited value
**Rationale:** Neither base selector survives a rename on its own — `schtasks.exe /create` alone is routine benign administrative activity, and a bare deletion of a file named `task.xml` has no inherent malicious meaning. But this dropper family creates the masquerade-branded scheduled task and deletes its exported `task.xml` within roughly 120 milliseconds as a deliberate anti-forensics step; a coincidental unrelated program is not expected to reproduce that create-then-delete sequence in a short window. This operationalizes the source draft's two standalone rules as an actual temporal correlation instead of two independently-alerting selectors. *Retiering note:* the source draft published "Quad-Persistence Establishment" (schtasks + masquerade phrase) at `level: high` and "Task.xml Deletion Anti-Forensics" at `level: medium`, each alerting independently. Restructured here into two non-alerting base rules feeding the correlation below, consistent with the durability concern that both selectors' precision derives from the same renameable "Microsoft .NET Runtime Optimization"-family masquerade branding (see "A Genuinely Close Call" in Coverage Gaps).
**False Positives:** A future build renaming both the masquerade phrase and the exported XML filename evades the correlation entirely — both remain the same attacker-chosen naming decision, so this is a scoping lead for this specific build family, not a durable technique-level detector. The base rules inherit their own narrow FP profiles rather than adding new risk.
**Deployment:** SIEM correlation engine with Sysmon process-creation and file-delete telemetry ingested (5-minute temporal join on `host.name`).

```yaml
title: FleetAgentAdvanced-Style .NET Runtime Optimization Scheduled Task Creation (Base Rule)
id: 2e8398f6-7a6a-4a8d-8aa2-f0cbbb346af5
name: fleetagentadvanced_schtasks_masquerade_create
status: experimental
description: >-
  Base rule (not alerting on its own): schtasks.exe invoked with /create and a
  command line referencing the ".NET Runtime Optimization" masquerade phrase.
  Paired with the task.xml-deletion base rule below via the correlation rule,
  which flags the create-then-delete anti-forensics sequence characteristic of
  this dropper family.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.execution
  - attack.t1053.005
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
      - '.NET Runtime Optimization'
  condition: selection
falsepositives:
  - >-
    Legitimate .NET Framework maintenance tasks using this exact phrase are not
    expected — verify digital signature if reviewed in isolation. Not alerting
    on its own; reviewed only in combination with the paired task.xml-deletion
    base rule.
level: informational
---
title: task.xml Deletion by Non-System Process (Base Rule)
id: 047f19e5-e1a1-484c-b825-24fb822125a5
name: fleetagentadvanced_taskxml_deletion
status: experimental
description: >-
  Base rule (not alerting on its own): deletion of a file named exactly
  task.xml by a process outside System32/SysWOW64. Paired with the
  scheduled-task-creation base rule above via the correlation rule below.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.stealth
  - attack.t1070.004
  - detection.emerging-threats
logsource:
  category: file_delete
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\task.xml'
    Image|contains: '.exe'
  filter_legitimate:
    Image|contains:
      - '\System32\'
      - '\SysWOW64\'
  condition: selection and not filter_legitimate
falsepositives:
  - >-
    Legitimate installers or maintenance scripts that export and then delete a
    scheduled-task XML file named task.xml (uncommon). Not alerting on its
    own; reviewed only in combination with the paired scheduled-task-creation
    base rule.
level: informational
---
title: FleetAgentAdvanced-Class Scheduled Task Create-Then-Delete Anti-Forensics Sequence
id: 049f9083-fc9c-4c12-94d0-13538a2cc3cc
status: experimental
description: >-
  Fires when both the ".NET Runtime Optimization" masquerade scheduled-task
  creation and a task.xml deletion by a non-system process are observed on the
  same host within a short window. Neither base signal alone is reliable — the
  masquerade phrase is attacker-chosen and renameable, and a bare task.xml
  deletion has no inherent malicious meaning — but this dropper family creates
  the scheduled task and deletes its exported task.xml within roughly 120
  milliseconds as a deliberate anti-forensics step, a sequence a coincidental
  unrelated program is not expected to reproduce.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.execution
  - attack.stealth
  - attack.t1053.005
  - attack.t1070.004
  - detection.emerging-threats
correlation:
  type: temporal
  rules:
    - fleetagentadvanced_schtasks_masquerade_create
    - fleetagentadvanced_taskxml_deletion
  group-by:
    - host.name
  timespan: 5m
falsepositives:
  - >-
    A future build renaming both the masquerade phrase and the exported XML
    filename evades this correlation entirely — both remain the same
    attacker-chosen naming decision, so this is a scoping lead for this
    specific build family, not a durable technique-level detector.
level: medium
```

#### .NET Dropper with Base64 Embedded Payload Execution

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information)
**Confidence:** MODERATE
**Rationale:** Requires `Convert.FromBase64String` and `File.WriteAllBytes` to co-occur in a process-access call trace — both fixed .NET Base Class Library method names the malware must call to decode and drop its embedded payload, so the rule is durable against any rebrand of masquerade strings or internal naming. It stays at Hunting rather than Detection because the combination itself (decode a Base64 blob, write bytes to disk) is a routine pattern in legitimate installers that unpack bundled or compressed resources at runtime, not a marker unique to malicious payload-dropping.
**False Positives:** Legitimate installers using Base64-encoded resources.
**Deployment:** Sysmon process-access monitoring (Event ID 10), EDR API-hooking telemetry; treat hits as scoping leads requiring analyst review of the specific binary.

```yaml
title: .NET Dropper with Base64 Embedded Payload Execution
id: d45cafee-0934-456d-9471-1cefbe03602a
status: experimental
description: >-
  Detects .NET executables decoding Base64 payloads and writing the decoded
  bytes to disk within the same process-access call trace — a common pattern
  for dropping an embedded secondary payload, also used by legitimate
  installers unpacking bundled resources.
references:
  - https://the-hunters-ledger.com/hunting-detections/fleetagentadvanced-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.stealth
  - attack.t1027
  - detection.emerging-threats
logsource:
  category: process_access
  product: windows
detection:
  selection:
    CallTrace|contains|all:
      - 'FromBase64String'
      - 'WriteAllBytes'
    SourceImage|contains: '.exe'
  filter_legitimate:
    SourceImage|startswith:
      - 'C:\Program Files\'
      - 'C:\Windows\'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate installers using Base64-encoded resources
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA compile error fixed (Dropper Core rule).** The source rule declared `$crypto1`, `$crypto2` (`ToBase64String`/`FromBase64String`) and `$net1`, `$net2` (`FleetAgentAdvanced_final`/`Microsoft.NET.Runtime`) strings that were never referenced anywhere in the condition. The real `yarac` compiler treats an unreferenced string as a hard error, not a warning — the original rule never compiled. The retiered Detection rule above drops these unused strings entirely rather than wiring them into the condition after the fact.
- **YARA Dropper Core rule split into a Detection/Hunting pair.** The source rule's condition OR'd four branches of very different quality together: an exact-hash match, a 3-of-6 coined-function-name combination, a config-variable-pair gated on masquerade strings, and a single generic Windows API string gated on the same masquerade strings. Because the branches are OR'd, any weak branch firing makes the whole rule fire — the two masquerade-gated branches would have dragged the combined rule's precision down regardless of how strong the function-name branch is on its own. The hash and function-name branches (durable, independent of masquerade branding) now form the Detection rule; the two masquerade-dependent branches now form the Hunting rule.
- **Sigma single-item list converted to scalar** (Persistence with Microsoft .NET Masquerading rule): `Details|contains: ['\AppData\']` → `Details|contains: '\AppData\'`, per SigmaHQ's list-of-one convention.
- **Sigma dual-persistence-timing correlation built from two standalone source rules.** The source draft published "Quad-Persistence Establishment" (schtasks.exe + masquerade phrase, `level: high`) and "Task.xml Deletion Anti-Forensics" (`level: medium`) as two independently-alerting rules. Restructured into a temporal correlation (two non-alerting base rules + one correlation rule) that operationalizes the actual anti-forensics behavior documented for this dropper — a scheduled task created with the masquerade phrase, then its exported `task.xml` deleted roughly 120 milliseconds later — rather than leaving two selectors that each alert independently on a renameable literal.
- **Sigma Persistence-with-Masquerading rule demoted from Detection-equivalent (`level: high`) to Hunting (`level: medium`).** See "A Genuinely Close Call" below.
- **All Sigma `status` fields set to `experimental`.** The source mixed `stable` (4 rules) and `experimental` (2 rules); SigmaHQ's status-to-high validator flags `stable`/`test` on rules dated within 60 days, so `experimental` is the correct authoring default across the board.

### Cut Rules (genuine noise — not routed to the feed)

- **YARA "Quad-Persistence Pattern"** — cut. Every string bucket is either a ubiquitous OS path (the Run-key path, the Startup-folder path, `.lnk`) or a generic word (`Microsoft`, `.NET`, `Runtime`, `Optimization`) that appears in the embedded metadata of virtually any .NET Framework binary, masquerading or not. The rule's actual intent — four persistence mechanisms established within roughly 1.3 seconds — is a timing correlation between separate runtime events; static YARA file-content matching has no way to express "these things happened close together in time," only "these strings coexist somewhere in this file." Coverage for the underlying technique now lives in the Sigma correlation rule above, which operates on events and can express the timing.
- **YARA "Task.xml Anti-Forensics Pattern"** — cut. `/create` and `/tn` are standard `schtasks.exe` CLI syntax used by countless legitimate auto-updaters and installers that create scheduled tasks programmatically; `.xml` and `Delete` are near-universal substrings in any .NET binary that touches an XML file or calls `File.Delete` for any reason. Salvage was attempted by mentally stripping the two weakest strings (`.xml`, `Delete`) and keeping only `/create` + `/tn` — the surviving pair is still "any software that creates a scheduled task via the standard CLI," an extremely broad, non-malware-specific behavior with no meaningful pivot value on its own. As with the Quad-Persistence rule, the actual anti-forensics signature is a create-then-delete timing sequence that only an event-based logsource (Sigma) can express; that coverage lives in the correlation rule above.
- **Suricata "Encrypted C2 Pattern from AppData Process"** — cut. The content match (`|17 03|` at offset 0) is the generic TLS Application Data record header present in essentially all TLS-encrypted internet traffic, regardless of what software originated it. The rule's `$HOME_NET any -> $EXTERNAL_NET any` scope has no destination, SNI, JA3/JA4, or header anchor and no `threshold`, so as written it would fire on a large fraction of all outbound HTTPS traffic. The source file's own note acknowledges this malware's C2 channel stays dormant rather than activating on its own, confirming this pattern was speculative rather than derived from an observed session — no salvage is possible without a genuine protocol structure to anchor on.

### Atomics Routed to the IOC Feed

- **Sigma "RuntimeOptimization.exe Execution from AppData"** and **Sigma "RuntimeOptimization.exe File Creation"** — both pure single-path selectors requiring the exact combination `\AppData\Roaming\Microsoft\CLR\` + `RuntimeOptimization.exe`, structurally identical to the project's canonical Sigma Cut example (`Image|endswith: \Client.exe`). Already present in `fleetagentadvanced-exe.json` as the `location` field on the RuntimeOptimization.exe hash entry. A generalized version dropping the specific filename and keeping only the masquerade folder path (`\AppData\Roaming\Microsoft\CLR\`) was considered and rejected — a bare hardcoded path fragment with no further behavioral qualifier is still the same kind of atomic-equivalent selector the two source rules already were, just one component shorter.
- **Suricata "Distribution Infrastructure Connection"** — pure IP-match rule (`alert tcp $HOME_NET any -> 109.230.231.37 any`, no content or protocol anchor). The IP is already present in `fleetagentadvanced-exe.json` under `network_indicators.distribution_infrastructure`. The rule's `reference:url` field also pointed at an unfilled placeholder (`github.com/yourusername/threat-intel/fleetagentadvanced`) rather than a real source — flagged here since it would have been broken regardless of tiering.

### A Genuinely Close Call: Why the Microsoft .NET Masquerade Literals Did Not Reach Detection

The Persistence-with-Masquerading Sigma rule and the scheduled-task correlation both key on the same literal family — "Microsoft", ".NET", "Runtime", "Optimization" — combined with a genuine structural anomaly (a Run-key value pointing at AppData, or `schtasks.exe` invoked with `/create`). The rubric's own durability tie-breaker asks whether a literal is a bespoke, one-off coined string with no plausible reason to appear elsewhere, versus a masquerade of a real, common product name. "Microsoft .NET Runtime Optimization" is unambiguously the latter — impersonating Microsoft's own branding inside a universal OS mechanism (the Run key, the Task Scheduler) is one of the most common malware masquerade conventions in existence, independently reused by countless unrelated families, not a marker unique to this investigation. That is why every rule anchored on this literal family caps at Hunting, regardless of what structural anomaly it is paired with. The YARA Detection rule and the Sigma process-injection Detection rule sit on the other side of that line: `DropEmbeddedAgent`, `SetPersistence`, `InjectIntoProcess`, and the `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` API triad are either bespoke operator-coined names with no real product to impersonate, or fixed OS API entry points the attacker cannot rename at all.

### Dormant C2 — No Network Behavioral Rule Possible

This sample showed zero network activity despite confirmed TCP-client, file-download, and encrypted-channel capability present in the binary. With no observed session, there is no protocol, URI, header, or JA3/JA4 structure available from which to build a Suricata Detection or Hunting signature — only the distribution IP itself, already routed to the feed above. This mirrors the disposition applied elsewhere in this project to C2 infrastructure observed only in a pre-activation state: feed-only coverage until protocol structure is available.

### Capabilities Documented in the IOC Feed Without Dedicated Rule Coverage

The IOC feed lists several statically-confirmed capabilities with no dedicated event-level detection here: application shimming (T1546.011), classic discovery APIs (T1082, T1083, T1057, T1033), local data collection (T1005), and C2-channel exfiltration (T1041). All are CAPA-detected capability findings rather than observed behavior, and each rests on Windows APIs common enough in legitimate software that a static or event-based selector built from them alone would fail Gate 2 precision outright. Behavioral coverage for these requires the capability to actually fire, which this build's dormant C2 withheld.

### What Would Enable Stronger Coverage

- **Observed C2 traffic** — protocol structure from an active session would replace the feed-only IP coverage with a genuine network signature.
- **Goodware corpus validation** — none of the rules above have been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition for reconsidering tier on the Hunting-rated masquerade rules.
- **Confirmation of the create-then-delete timing window against additional samples** — would validate whether the 5-minute correlation timespan chosen here is well-calibrated or could be tightened toward the ~120ms window actually observed.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
