---
title: "Detection Rules — Dual-RAT Campaign: Quasar RAT vs. NjRAT/XWorm"
date: '2025-12-06'
layout: post
permalink: /hunting-detections/dual-rat-analysis-detections/
hide: true
redirect_from: /hunting-detections/dual-rat-analysis
thumbnail: /assets/images/cards/dual-rat-analysis.png
---

**Campaign:** Dual-RAT-185.208.159.182-Quasar-NjRAT
**Date:** 2025-12-06
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/dual-rat-analysis/

---

## Detection Coverage Summary

This campaign covers two distinct .NET RAT families recovered from the same infrastructure (`185.208.159.182`): **Quasar RAT** (`Client.exe`, stealth-oriented) and **NjRAT/XWorm** (`server (1).exe`, installed persistently as `conhost.exe`, resilience-oriented). This file re-tiers the campaign's original rule set into Detection/Hunting per the site's rule-tiering standard. Several original rules carried defects that made them non-functional as written — a `pe.imphash()` gate with no `import "pe"` and a fabricated literal, an invalid `api_call` Sigma logsource with no corresponding Windows telemetry source, and Suricata content matches built from a file hash converted to raw bytes rather than observed protocol data. These are corrected or retired below; each fix is noted in the affected rule's rationale or in Coverage Gaps.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 2 | T1053.005, T1547.001, T1547.009, T1070.004, T1125, T1653, T1102.001 | 0 |
| Sigma | 6 | 5 | T1053.005, T1055.003, T1070.004, T1071.001, T1573, T1547.001, T1547.009, T1102.001 | 0 |
| Suricata | 0 | 2 | T1095, T1573, T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The NjRAT/XWorm triple-persistence YARA signature (all five literal artifacts — `conhost`, `minute /mo 1`, the Run-key path, `Startup\conhost.lnk`, and `schtasks /create` — co-present) and its Sigma correlation counterpart (2-of-3 mechanisms on the same host within a 10-minute window) are the strongest static and behavioral leads in the campaign.
- On the Quasar RAT side, `Client.exe` reliably anchors four separate Detection-tier Sigma rules (scheduled-task creation, remote thread creation into system processes, Zone.Identifier deletion, and C2 connection on TCP 4782) — this filename is the stock output of the public Quasar builder and is retained by unsophisticated operators more often than not.

**Atomics already in the feed:** the C2 IP `185.208.159.182`, port `4782`, the reconnaissance domains (`ipwho.is`, `api.ipify.org`), and the Pastebin dead-drop URL (`https://pastebin.com/raw/bzg5zj8n`) were already present in [`dual-rat-analysis-iocs.json`](/ioc-feeds/dual-rat-analysis-iocs.json) prior to this pass. Two Suricata rules that matched solely on the generic recon domains / the bare Pastebin host (see Coverage Gaps) are counted as atomics routed to that existing feed coverage rather than published as standalone signatures; no new feed entries were required.

---

## Multi-Family Organization

Each rule-type section below (`YARA Rules`, `Sigma Rules`, `Suricata Signatures`) is organized tier-first (`Detection Rules` / `Hunting Rules`); the two families — **Quasar RAT** and **NjRAT/XWorm** — are grouped with bold labels inside each tier subsection rather than duplicating the type heading. The NjRAT/XWorm persistence base rules and their correlation rule are co-located in a single fenced block (SigmaHQ correlation syntax requires the referenced base rules to be present alongside the correlation for evaluation) but are individually tiered — the three base rules are Hunting, the correlation is Detection — as noted in that entry's metadata.

---

## YARA Rules

### Detection Rules

**NjRAT/XWorm**

#### NjRAT/XWorm Triple-Redundant Persistence (Combined Static Signature)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys), T1547.009 (Shortcut Modification)
**Confidence:** HIGH
**Rationale:** Requires all five literal artifacts of the persistence-establishment routine to be present simultaneously: the `conhost` task/file name, the `minute /mo 1` frequency parameter, the exact registry Run-key path, the compound `Startup\conhost.lnk` filename, and the `schtasks /create` invocation. No legitimate, unrelated software plausibly contains all five strings together; an operator would need to rename every one of them in a rebuild to evade.
**False Positives:** None known — the five-string combination has no plausible legitimate collision.
**Blind Spots:** A rebuild that renames the `conhost` artifact and its dependent strings (task name, LNK filename, Run-key value) evades this rule; targets on-disk/in-memory string content, not a memory-only variant that never touches these code paths.
**Validation:** Scan the analyzed sample (`hash1` below) — all five strings must match; unrelated legitimate software must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown .NET binaries.

```yara
/*
   Yara Rule Set
   Identifier: Dual-RAT Campaign - Quasar RAT and NjRAT/XWorm
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule NjRAT_XWorm_Triple_Persistence {
   meta:
      description = "Detects the NjRAT/XWorm variant's triple-redundant persistence establishment routine via the simultaneous presence of its conhost-named scheduled task, registry Run key path, startup LNK filename, and 1-minute task frequency parameter"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/"
      date = "2025-12-06"
      hash1 = "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb"
      hash2 = "944d9e8d6f02375b31908ee05a0164fbb4804108"
      hash3 = "28bf5a76144fbc4b5f7f02dfee4e2c17"
      family = "NjRAT/XWorm"
      malware_type = "RAT"
      campaign = "Dual-RAT-185.208.159.182-Quasar-NjRAT"
      id = "85fbe6d2-865b-5f69-81dd-f0db8bf50511"
   strings:
      $task_name = "conhost" ascii wide
      $task_freq = "minute /mo 1" ascii wide
      $reg_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
      $startup = "Startup\\conhost.lnk" ascii wide
      $schtasks = "schtasks /create" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 150KB and
      all of them
}
```

### Hunting Rules

**Quasar RAT**

#### Quasar RAT Mark-of-the-Web Removal

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1070.004 (Indicator Removal: File Deletion)
**Confidence:** MODERATE
**Rationale:** Requires both a `:Zone.Identifier` alternate-data-stream reference and a `DeleteFile` API reference to be present together — a durable technique-level combination (Zone.Identifier is an OS-defined artifact name, not something the operator chooses), but neither string alone is family-specific, and legitimate MOTW-management utilities (unblock-file tools, some self-extracting installers) can plausibly contain both. Corrected from the original rule, which gated this condition behind `pe.imphash() == "8a3b1d8c…"` — a 66-character literal (not a valid 32-character MD5 imphash) evaluated with no `import "pe"` in the file, a compile-breaking defect; the broken gate has been removed.
**False Positives:** Self-extracting installers or "unblock file" utilities that read and delete Zone.Identifier streams as part of legitimate first-run handling.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown .NET binaries.

```yara
rule Quasar_RAT_MarkOfWeb_Removal {
   meta:
      description = "Detects a process deleting the Zone.Identifier alternate data stream from a file, characteristic of the Quasar RAT sample's Mark-of-the-Web suppression behavior observed in this campaign"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/"
      date = "2025-12-06"
      hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
      hash2 = "dc795961c8e63782fc0f53c08e7ca2e593df99fa"
      hash3 = "b5491b58348600c2766f86a5af2b867f"
      family = "Quasar RAT"
      malware_type = "RAT"
      campaign = "Dual-RAT-185.208.159.182-Quasar-NjRAT"
      id = "a2e913d8-0983-5d36-8bba-d9ddde38b68f"
   strings:
      $zone_stream = ":Zone.Identifier" ascii wide
      $delete_api = "DeleteFile" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      all of them
}
```

**NjRAT/XWorm**

#### NjRAT/XWorm Capability Bucket (VB.NET Baseline + Distinctive Config/API Combination)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1125 (Video Capture), T1653 (Power Settings), T1102.001 (Bidirectional Dead Drop Resolver)
**Confidence:** MODERATE
**Rationale:** Corrected from the original rule, which OR'd across seven buckets of mostly generic strings (`Mutex`, `InstallDir`, bare `Startup`, bare `Run`, bare `conhost`, `webcam`, `microphone`, `keylogger`, `raw/`) — several of which are dangerous as unqualified single-string triggers (`Run` is a 3-character substring that matches an enormous share of all PE strings tables; bare `conhost` collides with the legitimate Windows Console Host binary). Rewritten to require the VB.NET runtime baseline (`Microsoft.VisualBasic` + `System.Windows.Forms`, both present) AND 3-or-more of a tightened 13-item bucket of genuinely distinctive tokens — two builder-specific config-key artifacts (`Groub`, `USBNM`), a rare NT API (`RtlSetProcessIsCritical`), a rare video-capture API (`capCreateCaptureWindowA`), and specific compound strings (`minute /mo 1`, `Startup\conhost.lnk`) rather than their generic bare substrings. Also removed the same broken `pe.imphash()` gate pattern (this file's literal was the sample's own SHA256, not an imphash at all) and widened the filesize bound from 50000 bytes (1.3x the analyzed sample) to 150KB for build-to-build headroom.
**False Positives:** A VB.NET WinForms application is a large legitimate software category; 3-of-13 on the tightened bucket meaningfully narrows this but a coincidental match combining, e.g., video-capture code and a `RtlSetProcessIsCritical` reference in unrelated software cannot be fully excluded.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown VB.NET binaries.

```yara
rule NjRAT_XWorm_Core_Detection {
   meta:
      description = "Detects the NjRAT/XWorm variant analyzed in this campaign via a required VB.NET runtime baseline combined with 3 or more of its distinctive builder config keys, dead-drop markers, or capability API names"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/"
      date = "2025-12-06"
      hash1 = "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb"
      hash2 = "944d9e8d6f02375b31908ee05a0164fbb4804108"
      hash3 = "28bf5a76144fbc4b5f7f02dfee4e2c17"
      family = "NjRAT/XWorm"
      malware_type = "RAT"
      campaign = "Dual-RAT-185.208.159.182-Quasar-NjRAT"
      id = "86a672cb-1ac0-5927-aeee-b8c0a19ce9a7"
   strings:
      $vb1 = "Microsoft.VisualBasic" ascii wide
      $vb2 = "System.Windows.Forms" ascii wide

      $cfg1 = "Groub" ascii fullword
      $cfg2 = "USBNM" ascii fullword
      $cfg3 = "PasteUrl" ascii fullword

      $dd1 = "pastebin.com" ascii
      $dd2 = "iPhone Safari" ascii wide

      $per1 = "minute /mo 1" ascii wide
      $per2 = "Startup\\conhost.lnk" ascii wide

      $crit1 = "RtlSetProcessIsCritical" ascii fullword
      $crit2 = "BSOD" ascii wide fullword

      $slp1 = "SetThreadExecutionState" ascii fullword
      $slp2 = "ES_DISPLAY_REQUIRED" ascii fullword
      $slp3 = "ES_SYSTEM_REQUIRED" ascii fullword

      $surv1 = "capCreateCaptureWindowA" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 150KB and
      all of ($vb*) and
      3 of ($cfg1,$cfg2,$cfg3,$dd1,$dd2,$per1,$per2,$crit1,$crit2,$slp1,$slp2,$slp3,$surv1)
}
```

---

## Sigma Rules

### Detection Rules

**Quasar RAT**

#### Quasar RAT Scheduled Task Persistence via schtasks.exe

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**Rationale:** Corrected from the original rule, which declared `service: security` with `EventID: 106` and a `CommandLine` field — an invalid combination (Event ID 106 is a TaskScheduler-Operational-log "Task Registered" event carrying only `TaskName`/`UserContext`, not the Security log, and it does not carry a `CommandLine` field at all). Re-anchored on the `process_creation` event that genuinely contains this command line: `schtasks.exe` invoked with the task name `"RuntimeBroker"`, an `ONLOGON` trigger, and a reference to `Client.exe` all present together.
**False Positives:** Legitimate administrative scripts that create a scheduled task literally named "RuntimeBroker" with an ONLOGON trigger pointing at a file named Client.exe (an implausible combination in practice).
**Blind Spots:** A rebuild that renames the task or target binary evades; does not cover task creation via the Task Scheduler COM API instead of schtasks.exe.
**Validation:** Trigger the malware's install routine — the schtasks.exe invocation must match; unrelated scheduled-task creation must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Quasar RAT Scheduled Task Persistence via schtasks.exe
id: 06347ef1-4a96-4d80-ba7b-d54d5148ced9
status: experimental
description: >-
  Detects the Quasar RAT client's persistence-establishment routine -
  a scheduled task named "RuntimeBroker" (masquerading as the
  legitimate Windows process) created via schtasks.exe with an ONLOGON
  trigger pointing at Client.exe. Corrected from the original rule,
  which declared an invalid Security-log/EventID 106 combination with
  a CommandLine field that log source does not carry; re-anchored on
  the schtasks.exe process-creation event that actually contains this
  command line.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/tn "RuntimeBroker"'
            - '/sc ONLOGON'
            - 'Client.exe'
    condition: selection
falsepositives:
    - >-
      Legitimate system administration scripts that create a scheduled
      task literally named "RuntimeBroker" with an ONLOGON trigger
      pointing at a file named Client.exe (unlikely combination)
level: high
```

#### Quasar RAT Remote Thread Creation Into System Processes

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1055.003 (Thread Execution Hijacking)
**Confidence:** HIGH
**Rationale:** Corrected from the original rule, which selected on `category: process_creation` with `ParentImage` ending `\Client.exe`, `Image` matching a system-process name, and `CommandLine|contains: 'inject'` — a combination that has no realistic basis (classic thread injection does not spawn a new, literally-named child process with an "inject" command-line argument; `CreateRemoteThread` takes no command-line parameter at all). Re-anchored on the `create_remote_thread` category (Sysmon Event ID 8), which is the log source that genuinely captures this technique, with `SourceImage` ending `\Client.exe` and `TargetImage` matching one of the three process names referenced in the original evidence.
**False Positives:** Legitimate software coincidentally named Client.exe that legitimately injects into explorer.exe, svchost.exe, or dllhost.exe (architecturally possible, not observed).
**Blind Spots:** A rebuild that renames Client.exe evades; does not cover injection into other target processes.
**Validation:** Trigger the malware's injection routine — the create_remote_thread event with this source/target pairing must match; unrelated remote-thread creation must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (Sysmon Event ID 8 telemetry).

```yaml
title: Quasar RAT Remote Thread Creation Into System Processes
id: 6e1ad431-a53d-49ab-b6b0-0f6fb647d3a1
status: experimental
description: >-
  Detects Client.exe (the Quasar RAT sample analyzed in this campaign)
  creating a remote thread in explorer.exe, svchost.exe, or dllhost.exe
  for process-injection-based defense evasion. Corrected from the
  original rule, which selected on the process_creation category with
  a CommandLine "inject" filter - a combination that does not
  correspond to how thread-injection APIs actually generate telemetry;
  re-anchored on the create_remote_thread category (Sysmon Event ID 8),
  which is what genuinely captures this technique.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055.003
    - detection.emerging-threats
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        SourceImage|endswith: '\Client.exe'
        TargetImage|endswith:
            - '\explorer.exe'
            - '\svchost.exe'
            - '\dllhost.exe'
    condition: selection
falsepositives:
    - >-
      Legitimate software coincidentally named Client.exe that
      legitimately injects into explorer.exe, svchost.exe, or
      dllhost.exe (not observed, but architecturally possible)
level: high
```

#### Quasar RAT Mark of the Web Removal

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1070.004 (Indicator Removal: File Deletion)
**Confidence:** HIGH
**Rationale:** Already well-formed in the original file — `TargetFilename` containing the Zone.Identifier ADS name AND `Image` ending `\Client.exe` together is a tight combination. Level raised from the original `medium` to `high` to match its Detection-tier precision (a bare Zone.Identifier deletion alone would be Hunting-grade noise per the site's baseline-FP discipline; the `Image` constraint is what elevates it).
**False Positives:** Legitimate file management tools coincidentally named Client.exe.
**Blind Spots:** A rebuild that renames Client.exe evades.
**Validation:** Trigger the malware's MOTW-suppression routine — the deletion event must match; unrelated Zone.Identifier deletions (e.g. by browsers) must NOT fire, since they are not named Client.exe.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (FileDelete telemetry).

```yaml
title: Quasar RAT Mark of the Web Removal
id: 469751f1-91ad-4b17-8c14-491a019f1f44
status: experimental
description: Detects Zone.Identifier alternate data stream deletion by Client.exe, the Quasar RAT sample analyzed in this campaign, characteristic of Mark-of-the-Web suppression to avoid re-triggering SmartScreen on subsequent executions
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.stealth
    - attack.t1070.004
    - detection.emerging-threats
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|contains: ':Zone.Identifier'
        Image|endswith: '\Client.exe'
    condition: selection
falsepositives:
    - Legitimate file management tools coincidentally named Client.exe
level: high
```

#### Quasar RAT C2 Connection on TCP 4782

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573 (Encrypted Channel)
**Confidence:** HIGH
**Rationale:** Corrected from the original rule, which required the specific C2 IP `185.208.159.182` as an additional AND condition. That atomic is carried in the IOC feed for blocking; this rule keeps only the durable `Image` + `DestinationPort` combination so it still fires if the operator rotates C2 infrastructure while keeping the same builder-default binary name and port.
**False Positives:** Legitimate applications coincidentally named Client.exe using TCP port 4782 (an uncommon, non-standard port).
**Blind Spots:** A rebuild that renames Client.exe or changes the C2 port evades.
**Validation:** Trigger the malware's C2 beacon — the connection event must match; unrelated traffic on port 4782 from a differently-named process must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (network-connection telemetry).

```yaml
title: Quasar RAT C2 Connection on TCP 4782
id: 6e5cd22d-2176-4069-85e6-0fe1075ebf2c
status: experimental
description: >-
  Detects Client.exe, the Quasar RAT sample analyzed in this campaign,
  establishing an outbound connection on TCP port 4782 - this build's
  custom-encrypted C2 channel. Corrected from the original rule, which
  required the specific C2 IP 185.208.159.182 as an AND condition; that
  atomic is carried in the IOC feed for blocking, while this rule keeps
  only the durable Image+port combination so it still fires if the
  operator rotates C2 infrastructure.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1573
    - detection.emerging-threats
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith: '\Client.exe'
        DestinationPort: 4782
        Initiated: 'true'
    condition: selection
falsepositives:
    - >-
      Legitimate applications coincidentally named Client.exe using
      TCP port 4782
level: high
```

**NjRAT/XWorm**

#### NjRAT/XWorm Pastebin Dead-Drop C2 Resolution

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1102.001 (Dead Drop Resolver), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Corrected from the original rule, which OR'd `Image` against two names: `conhost.exe` (the malware's actual installed name) and `server (1).exe` (an artifact of this analysis's own browser download/deduplication naming — not a name the malware itself uses or would reuse in any other infection). The one-off filename has been dropped; `conhost.exe` alone is retained because the legitimate Windows Console Host process does not originate outbound network connections, making a process by that name reaching Pastebin over HTTPS a strong anomaly on its own.
**False Positives:** Unlikely — the legitimate Windows conhost.exe process does not make outbound network connections in normal operation; a coincidentally-named third-party tool reaching Pastebin is the only realistic collision.
**Blind Spots:** A rebuild that installs under a different filename evades.
**Validation:** Trigger the malware's dead-drop resolution — the connection event must match; unrelated legitimate access to Pastebin from a properly-named process (browser, dev tool) must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (network-connection telemetry).

```yaml
title: NjRAT/XWorm Pastebin Dead-Drop C2 Resolution
id: fa059bb8-a203-4528-a3ae-2b4f67b74576
status: experimental
description: >-
  Detects a process named conhost.exe (the NjRAT/XWorm sample's
  installed persistence name in this campaign) making an outbound
  HTTPS connection to pastebin.com to resolve its dead-drop C2
  endpoint. The legitimate Windows conhost.exe process does not
  originate outbound network connections, so this name+destination
  combination is a strong anomaly. Corrected from the original rule,
  which also matched the literal filename "server (1).exe" - an
  artifact of this analysis's own download/deduplication naming, not a
  name the malware itself uses, and dropped here as non-durable.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.command-and-control
    - attack.t1102.001
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith: '\conhost.exe'
        DestinationPort: 443
        DestinationHostname|contains: 'pastebin.com'
        Initiated: 'true'
    condition: selection
falsepositives:
    - >-
      Unlikely; the legitimate Windows conhost.exe process does not
      make outbound network connections in normal operation
level: high
```

#### NjRAT/XWorm Triple-Redundant Persistence — Base Rules + 2-of-3 Correlation

**Tier:** Hunting (3 base rules) / Detection (correlation) — co-located in one fence because SigmaHQ correlation syntax requires the referenced base rules to be evaluated alongside the correlation; see Multi-Family Organization.
**Robustness:** Base rules 1 each (single mechanism, keyed on the renameable "conhost" artifact name in isolation); correlation 2 (2-of-3 independently-renameable mechanisms co-occurring on the same host within a short window is a materially stronger signal than any one alone).
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys), T1547.009 (Shortcut Modification)
**Confidence:** HIGH for the correlation; MODERATE for each base rule individually.
**Rationale:** Decomposed from the original rule, which mixed three different Sysmon event types (Task Scheduler EventID 106, registry EventID 13, file-creation EventID 11) under a single invalid `service: security` logsource with a `condition: 1 of selection*` — a structure Sigma does not support (one rule, one logsource) and that, even read charitably, only required any ONE of the three mechanisms to fire. Rebuilt as three independent base rules on their correct logsource categories (`process_creation` for the schtasks.exe invocation, `registry_set`, `file_event`), each individually a Hunting-tier single-mechanism lead, plus a `type: event_count` correlation that elevates to Detection when 2-or-more of the three co-occur on the same host within 10 minutes — directly reflecting the "triple-redundant, self-healing" persistence behavior documented for this campaign.
**False Positives (base rules, individually):** A scheduled task, registry Run-key value, or Startup-folder shortcut literally named/valued "conhost" from an unrelated source (implausible per-mechanism, but each is a single renameable literal in isolation).
**False Positives (correlation):** Very unlikely — would require 2 of 3 independently-implausible conhost-named artifacts to appear on the same host within the same 10-minute window for an unrelated reason.
**Blind Spots (correlation):** A rebuild that renames the shared "conhost" artifact across all three mechanisms evades the whole cluster; a deployment that only establishes one persistence mechanism (not observed in this campaign) triggers only the Hunting-tier base rule, not the correlation.
**Validation:** Trigger the malware's install routine — 2 of the 3 base events must fire within 10 minutes and the correlation must alert; an environment with one coincidental "conhost"-named artifact but no others must NOT trigger the correlation.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM with correlation-rule support (process-creation, registry, and file-creation telemetry).

```yaml
title: NjRAT/XWorm Persistence - Scheduled Task (Conhost, 1-Minute Interval)
id: e0192277-e076-4aca-b960-ace5c5bb47ee
name: njrat_persist_schtask
status: experimental
description: >-
  Detects creation of a scheduled task named "conhost" running on a
  1-minute recurring interval via schtasks.exe, the first of three
  redundant persistence mechanisms established by the NjRAT/XWorm
  variant analyzed in this campaign. Evaluated together with the
  paired registry Run-key and startup-folder base rules via the
  correlation rule below.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/tn "conhost"'
            - '/sc minute'
            - '/mo 1'
    condition: selection
falsepositives:
    - >-
      Legitimate administrative scripts or monitoring tools that
      create a scheduled task literally named "conhost" on a
      1-minute interval (unusual but not impossible)
level: medium
---
title: NjRAT/XWorm Persistence - Registry Run Key (Conhost)
id: e365a47c-836f-455d-bfc3-0cc3153d4aff
name: njrat_persist_runkey
status: experimental
description: >-
  Detects a registry Run key write referencing conhost.exe, the second
  of three redundant persistence mechanisms established by the
  NjRAT/XWorm variant analyzed in this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run'
        Details|contains: 'conhost.exe'
    condition: selection
falsepositives:
    - >-
      Diagnostic or asset-management tooling that documents or
      whitelists conhost.exe by name in a monitored Run-key context
level: medium
---
title: NjRAT/XWorm Persistence - Startup Folder Shortcut (Conhost.lnk)
id: 6b9f2cbd-895e-4f43-99f9-336ec1643b4a
name: njrat_persist_startup
status: experimental
description: >-
  Detects creation of a Startup-folder shortcut named conhost.lnk, the
  third of three redundant persistence mechanisms established by the
  NjRAT/XWorm variant analyzed in this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.009
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\Startup\conhost.lnk'
    condition: selection
falsepositives:
    - >-
      Unlikely; a legitimate shortcut named exactly conhost.lnk in the
      Startup folder has not been observed
level: medium
---
title: NjRAT/XWorm Triple-Redundant Persistence - 2-of-3 Correlation
id: ca1fba48-5756-40d7-ab90-9fad61dd00b8
status: experimental
description: >-
  Raises confidence to Detection-grade when 2 or more of the three
  NjRAT/XWorm persistence base rules (scheduled task, registry Run
  key, startup-folder shortcut - all referencing the conhost artifact
  name) fire on the same host within a 10-minute window, consistent
  with the triple-redundant persistence routine documented for this
  campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
correlation:
    type: event_count
    rules:
        - njrat_persist_schtask
        - njrat_persist_runkey
        - njrat_persist_startup
    group-by:
        - ComputerName
    timespan: 10m
    condition:
        gte: 2
falsepositives:
    - >-
      Very unlikely; would require 2 of 3 independently-implausible
      conhost-named artifacts to appear on the same host within the
      same 10-minute window for an unrelated reason
level: high
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - attack.t1547.001
    - attack.t1547.009
    - detection.emerging-threats
```

### Hunting Rules

**Campaign-Level**

#### Suspicious Access to Dead-Drop Services from a Non-Browser Process

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1102.001 (Dead Drop Resolver)
**Confidence:** MODERATE
**Rationale:** Already well-formed in the original file. Flags a non-browser, non-chat-client process reaching Pastebin, GitHub raw-content hosting, or Discord — a durable, family-agnostic technique lead that survives infrastructure rotation entirely, but real developer/CI tooling legitimately fetches from these same hosts often enough that this stays a triage-required Hunting signal rather than an alerting-grade Detection rule.
**False Positives:** Legitimate developer access to paste/raw-content services; corporate tooling using GitHub for configuration retrieval.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (network-connection telemetry); pair with the family-specific Detection rules above for attribution before high-confidence alerting.

```yaml
title: Suspicious Access to Dead-Drop Services
id: e5ef6bed-378b-4b30-8a72-2813bf37c310
status: experimental
description: Detects access to common dead-drop services that may indicate C2 infrastructure resolution
author: The Hunters Ledger
date: '2025-12-06'
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|contains:
            - 'pastebin.com'
            - 'githubusercontent.com'
            - 'gist.githubusercontent.com'
            - 'discordapp.com'
            - 'discord.com'
        Initiated: 'true'
    filter_legitimate:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
            - '\teams.exe'
            - '\slack.exe'
            - '\discord.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate developer access to paste services
    - Corporate tools using GitHub for configuration
level: medium
tags:
    - attack.command-and-control
    - attack.t1102.001
    - detection.emerging-threats
```

**NjRAT/XWorm**

#### NjRAT/XWorm AppData-Resident Process Remote Thread Creation

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1055.003 (Thread Execution Hijacking)
**Confidence:** MODERATE
**Rationale:** Corrected from the original rule, which declared a non-existent `api_call` logsource category with a `CallTrace` field searched for the literal string "CreateRemoteThread" — no such category exists in SigmaHQ, and standard Windows telemetry does not expose arbitrary API calls this way (`CallTrace` is populated only by Sysmon Event ID 8 CreateRemoteThread and Event ID 10 ProcessAccess, neither of which records the literal function name as searchable text). Re-anchored on the `create_remote_thread` category, which is the real source for this event. No target-process constraint is carried from the original evidence, so this stays intentionally broad — a generic "AppData-resident process injects a remote thread" heuristic rather than a family-specific rule.
**False Positives:** Legitimate AppData-installed software (auto-updaters, some games, hardware-control utilities) that performs remote thread injection for benign reasons.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (Sysmon Event ID 8 telemetry); triage against process reputation before escalating.

```yaml
title: NjRAT/XWorm AppData-Resident Process Remote Thread Creation
id: a1ea23fd-ff54-4115-bb49-89b7fa7b9cd4
status: experimental
description: >-
  Detects a process running from an AppData path creating a remote
  thread in another process, a generic process-injection technique
  step observed as part of the malware's surveillance/persistence
  chain in this campaign. Corrected from the original rule, which
  declared a non-existent "api_call" logsource category with a
  CallTrace field searched for the literal string "CreateRemoteThread"
  - standard Windows telemetry does not expose API calls this way;
  re-anchored on the create_remote_thread category (Sysmon Event ID 8),
  which is the real source for this event.
references:
    - https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/
author: The Hunters Ledger
date: '2025-12-06'
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055.003
    - detection.emerging-threats
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        SourceImage|contains: '\AppData\'
    condition: selection
falsepositives:
    - >-
      Legitimate AppData-installed software (auto-updaters, some
      games, hardware-control utilities) that performs remote thread
      injection for benign reasons
level: medium
```

---

## Suricata Signatures

### Hunting Rules

**Quasar RAT**

#### Quasar RAT Binary Protocol on TCP 4782

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1573 (Encrypted Channel)
**Confidence:** MODERATE
**Rationale:** Corrected from the original rule, whose `content` match was the file's own SHA256 hash string converted pairs-of-hex-digits into raw bytes and searched for in network traffic — a file digest has no reason to appear in the malware's actual protocol bytes, so that condition could never legitimately fire. No genuine protocol byte pattern was captured in the underlying evidence (only the port and "custom encryption" are documented), so the content match has been removed rather than replaced with another guess. TCP/4782 is the Quasar-family default port, a real but coarse tool-family artifact: anything else on that port also matches.
**False Positives:** Any legitimate or unrelated service that happens to use TCP/4782 (uncommon but not impossible); the `threshold` limits alert volume per source.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4782 (msg:"THL Dual-RAT-Quasar-NjRAT Quasar Binary Protocol C2 on TCP 4782 (RAT C2 Channel)"; flow:established,to_server; dsize:>0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:2100001; rev:2; metadata:author The_Hunters_Ledger, date 2025-12-06, reference https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/;)
```

**NjRAT/XWorm**

#### NjRAT/XWorm Spoofed Mobile Safari User-Agent

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Corrected from the original rule, which mixed a raw (non-sticky-buffer) content match against a "User-Agent: " header prefix with a separate `http.user_agent` sticky-buffer match for "Mobile"/"Safari" — redundant and, if the underlying request is TLS-wrapped, unable to see either buffer in cleartext at all. Rewritten as a single `http.user_agent` sticky-buffer match against the full, dated OS-version substring from the observed UA string (iOS 11.4.1 — an implausible version for genuine 2026-era mobile traffic, and a strong indicator of a hardcoded, non-updating spoofed value rather than a real device). This assumes the request is visible as cleartext HTTP; if the underlying transport is TLS end-to-end, this signature will not see the header at all and only the host-level Sigma coverage above applies.
**False Positives:** A corporate proxy or testing tool that rewrites/replays an old, fixed iPhone Safari User-Agent string for unrelated reasons (uncommon).
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Dual-RAT-Quasar-NjRAT NjRAT-XWorm Spoofed Mobile Safari User-Agent (Dead-Drop C2 Resolution Indicator)"; flow:established,to_server; http.user_agent; content:"iPhone OS 11_4_1 like Mac OS X"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:2100004; rev:2; metadata:author The_Hunters_Ledger, date 2025-12-06, reference https://the-hunters-ledger.com/hunting-detections/dual-rat-analysis-detections/;)
```

---

## Coverage Gaps

**Cut: Quasar RAT Core Detection (YARA).** The original rule OR'd across seven buckets of strings, none of which reliably discriminate this malware from legitimate software: VM-detection words (`VirtualBox`, `VMware`, `QEMU`), anti-debug API names (`Debugger`, `IsDebuggerPresent`), and common injection APIs (`WriteProcessMemory`, `CreateRemoteThread`) are all near-ubiquitous in remote-support, DRM-protected, and anti-cheat software; `schtasks`/`ONLOGON` are generic Task Scheduler vocabulary; and — most seriously — `RuntimeBroker` is the literal name of a real, common Windows system process, meaning this string alone could match legitimate `RuntimeBroker.exe` or any tool that references it. The condition also carried the same `pe.imphash()` compile defect as the surviving MOTW rule (no `import "pe"`, a 66-character literal that is not a valid imphash), and even a fixed gate would not have addressed the underlying precision failure. A capability-abstraction rewrite requiring several categories to co-occur was attempted but did not overcome the genericness of the constituent strings — this pattern (VM-detection + anti-debug + generic injection APIs + surveillance vocabulary) is common enough in legitimate remote-monitoring software that no combination clears the Hunting precision bar. The malware's genuinely distinctive artifacts (the C2 IP, the RuntimeBroker task name as a *specific scheduled-task creation event*, the Zone.Identifier deletion) are covered by dedicated rules above or by the IOC feed. **What would enable a rule:** a verified imphash of the compiled Client.exe binary, or a distinctive namespace/class-name string recovered from decompilation — neither was captured in the original evidence.

**Atomics → feed: Quasar RAT IP Geolocation (Suricata).** The original rule matched Host-header traffic to `ipwho.is` and `api.ipify.org` using a `content:"Host: ipwho.is|Host: api.ipify.org"` construction that is not valid Suricata syntax (the `|...|` delimiters denote a raw hex byte sequence, and `Host: api.ipify.org` is not valid hex) — this would have failed to compile as written. Independent of the syntax defect, both domains are pure atomics: removing either leaves nothing else in the rule to detect, and both are free public IP-geolocation services used by a large volume of unrelated legitimate software, so even a syntactically-corrected version would carry negligible discriminating value as a standalone signature. Both domains were already present in the IOC feed's `reconnaissance_domains` before this pass; no new feed entry was required.

**Atomics → feed: NjRAT/XWorm Pastebin Dead-Drop (Suricata).** The original rule matched `Host: pastebin.com` + a `/raw/` URI path, which (per the campaign evidence) is fetched over HTTPS — the URI path detail is not visible to passive network monitoring of TLS traffic without decryption, only the TLS SNI would be observable, and pastebin.com is too broadly used by legitimate developers/services to serve as a standalone SNI-only indicator. This atomic is functionally superseded by the higher-fidelity host-level "NjRAT/XWorm Pastebin Dead-Drop C2 Resolution" Sigma rule above, which can see the originating process name (`conhost.exe`) and does not depend on decrypting the connection. The dead-drop URL was already present in the IOC feed's `c2_infrastructure.njrat_xworm.dead_drop_url` before this pass; no new feed entry was required.

**Cut: six Sigma rules built on a non-existent `api_call` logsource category.** The original file declared `logsource: category: api_call` with a `CallTrace` field searched for literal API function-name strings (`RtlSetProcessIsCritical`, `SetThreadExecutionState`, `SetWindowsHookEx`, `VirtualAllocEx`) across "NjRAT/XWorm Critical Process Protection," "NjRAT/XWorm Anti-Sleep System Protection," "Suspicious Memory Allocation Patterns," and two of the three "Suspicious API Call Sequence" base rules (Hook Installation, Remote Memory Allocation). No `api_call` category exists in SigmaHQ, and standard Windows/Sysmon telemetry does not expose arbitrary API-function invocations as literal-string-searchable events — `CallTrace` is populated only by Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess), neither of which records the called function's name as free text. None of these four API calls have a native Sysmon-observable proxy, so these five rules — plus the "Suspicious API Call Sequence — Correlation" rule, which depended on two of them by name — are Cut rather than salvaged. The third base rule in that correlation set (Remote Thread Creation, `CreateRemoteThread`) *does* have a real telemetry source and has been salvaged into the "NjRAT/XWorm AppData-Resident Process Remote Thread Creation" Hunting rule above using the correct `create_remote_thread` category. Static coverage for the critical-process-protection and anti-sleep capabilities survives via the NjRAT/XWorm YARA capability-bucket rule (`RtlSetProcessIsCritical`, `SetThreadExecutionState` are both scoring tokens in that rule's condition). **What would enable a Sigma rule for the remaining three:** EDR-specific API-hooking telemetry (vendor-dependent, not portable across SigmaHQ backends) or a confirmed downstream proxy signal — e.g., a `process_access` `GrantedAccess` bitmask pattern for the `VirtualAllocEx`+`PAGE_EXECUTE_READWRITE` case, which was not attempted here without a process anchor to pair it with.

**Cut: High-Frequency Process Creation from Scheduled Task (base + correlation).** The base rule's selection (`ParentImage|contains: 'svchost.exe'` AND `CommandLine|contains: 'taskeng.exe'`) does not correspond to any artifact in this campaign's evidence — the actual observed high-frequency task is the NjRAT/XWorm "conhost" task via schtasks.exe, already covered by the persistence base+correlation rules above — and the selection logic itself is checking the *child* process's own command line for the substring "taskeng.exe," which is not how a legitimate or malicious scheduled-task child process would be invoked. Independent of that logic error, `ParentImage` containing `svchost.exe` alone is satisfied by enormous volumes of ordinary Windows Task Scheduler activity on any host — a textbook check-baseline failure with no salvageable behavioral anchor once the malformed CommandLine check is removed. The correlation rule, which only amplified this base rule's hit count, is Cut alongside it.

**Retired: PowerShell hunting-query sections (7 scripts) and generic Implementation Guidance section.** The original file's "PowerShell Hunting Queries" and "Enhanced PowerShell Hunting Queries" sections contained seven on-demand scripts. Five substantially duplicate detection logic already captured by the Sigma rules above (scheduled-task hunting, Zone.Identifier hunting, triple-persistence hunting, Pastebin dead-drop hunting, dead-drop-service monitoring — the last of these is a narrower version of the "Suspicious Access to Dead-Drop Services" Sigma rule, which already extends it to GitHub/Discord). A sixth ("Memory Injection Detection") overlaps the remote-thread-creation Sigma coverage. The seventh ("Beacon Pattern Analysis") is generic non-standard-port connection triage with no MITRE technique anchor, no campaign-specific indicator, and no realistic false-positive bound (it flags any process with an established connection on a non-80/443 port above 1024) — it does not correspond to a specific, buildable rule and was not carried forward. The file's generic "Implementation Guidance" section (deployment advice for YARA/Sigma/PowerShell/network rules) was likewise removed as non-evidence-specific boilerplate outside the standard detection-file format.

**Permalink note.** This file's permalink has been conformed to `/hunting-detections/dual-rat-analysis-detections/` to match the site-wide `{slug}-detections` convention. The live catalog's `detection_url` currently points at the old `/hunting-detections/dual-rat-analysis` slug; republishing this file requires either a redirect or a catalog update so existing inbound links do not 404.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
