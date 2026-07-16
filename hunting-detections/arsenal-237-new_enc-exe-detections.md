---
title: "Detection Rules — new_enc.exe (Arsenal-237 Ransomware)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-new_enc-exe-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-new_enc-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-Backup-Targeting-Ransomware
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-new_enc-exe.json

---

## Detection Coverage Summary

new_enc.exe is a 64-bit, Rust-compiled ransomware sample from the Arsenal-237 toolkit, deployed manually via command-line arguments (`--pass`, `--folder`, `--file`) rather than through automated propagation. It encrypts files with a hardcoded ChaCha20 key, deletes Volume Shadow Copies to block recovery, and runs a multi-stage service-termination sequence targeting enterprise backup infrastructure (Veritas Backup Exec agents, Veeam, Windows VSS) and database services (SQL Server, Oracle) ahead of encryption. A scheduled task re-displays the ransom note across logons. No command-and-control channel was identified — this build operates offline; a related, C2-enabled sibling build (`enc_c2.exe`) with Tor-based infrastructure is tracked separately.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The Volume Shadow Copy deletion command and the Veritas Backup Exec service-name combination anchor the strongest signatures; several single-build atomics (the campaign tracking ID, the version string, the hardcoded encryption key, the file hashes) were already captured in the IOC feed rather than published as standalone rules, and two speculative network signatures with no supporting evidence in this sample's documented behavior were retired.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 5 | T1489, T1490, T1053.005, T1497.001, T1622, T1518.001 | 5 |
| Sigma | 1 | 3 | T1490, T1489, T1053.005 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** new_enc.exe's SHA256/SHA1/MD5 hashes, the hardcoded ChaCha20 encryption key, the campaign tracking ID (`ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4`), the `v0.5-beta` version string, and the hex-encoded ransom-note header were already present in [`arsenal-237-new_enc-exe.json`](/ioc-feeds/arsenal-237-new_enc-exe.json) before this retiering pass. See Coverage Gaps for the full reasoning on every retired or restructured rule.

---

## YARA Rules

### Detection Rules

#### Veritas Backup Exec Multi-Service Targeting

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1489 (Service Stop), T1490 (Inhibit System Recovery — GxVss specifically integrates with Volume Shadow Copy)
**Confidence:** HIGH
**Rationale:** Requires 3 of 5 distinct Veritas Backup Exec internal service short-names (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr) to co-occur. These are Veritas's own product-internal names, not this campaign's chosen literals — a tool-family artifact that would recur across any ransomware build targeting this specific enterprise backup product, not merely a rename-away-from campaign marker. *Fix applied during retiering:* split from a source rule whose condition let a bare, un-fullword'd match on the single word "veeam" satisfy the same rule alone; that weaker branch is demoted to its own Hunting rule below so it no longer governs this rule's overall precision.
**False Positives:** None known — unrelated software is not expected to reference 3 or more of these specific Veritas internal service short-names together; a Veritas-aware backup-monitoring dashboard mentioning one or two agents by name would not meet the 3-of-5 threshold.
**Blind Spots:** A rebuild that drops or renames 3 or more of the five Gx short-names (e.g., a shift to Veritas's newer product-line naming) evades this rule; targets on-disk string references, not live Service Control Manager activity.
**Validation:** Scan new_enc.exe (hash below) — must match; software referencing only one or two of the five short-names must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-Backup-Targeting-Ransomware
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_Arsenal237_Veritas_BackupExec_Multi_Service_Targeting {
   meta:
      description = "Detects Arsenal-237 ransomware's targeting of Veritas Backup Exec agent services via co-occurrence of at least 3 of 5 distinct Veritas internal service short-names (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr), referenced ahead of service termination to disable enterprise backup and recovery capability before encryption."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "a3f81c2e-4b6d-4a91-8c73-1e5f8a2b6c90"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $gx1 = "GxVss" ascii wide
      $gx2 = "GxBlr" ascii wide
      $gx3 = "GxFWD" ascii wide
      $gx4 = "GxCVD" ascii wide
      $gx5 = "GxCIMgr" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      3 of ($gx*)
}
```

#### Volume Shadow Copy Deletion Command

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1490 (Inhibit System Recovery)
**Confidence:** HIGH
**Rationale:** The exact command string, or the `vssadmin` and `delete shadows` substrings co-occurring, is the canonical VSS anti-recovery command used across dozens of ransomware families. This is a technique-level chokepoint: the attacker cannot achieve VSS-based recovery inhibition via `vssadmin.exe` without invoking this exact CLI syntax, regardless of how the surrounding binary is rebuilt or renamed.
**False Positives:** Legitimate backup-rotation and disk-space-management scripts occasionally invoke `vssadmin delete shadows`; the `/all /quiet` flags are consistent with unattended/automated use but are not unique to malicious use.
**Blind Spots:** Misses WMI-based (`Win32_ShadowCopy.Delete()`) or PowerShell (`Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`) alternatives to the `vssadmin` CLI; a build that shells out through a renamed copy of `vssadmin.exe` or calls the underlying VSS COM API directly evades this string-based check entirely.
**Validation:** Scan new_enc.exe (hash below) — must match; a legitimate script's `vssadmin` invocation that never combines "delete" with "shadows" (e.g., `vssadmin list shadows`) must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares, IR artifact triage.

```yara
rule TOOLKIT_Arsenal237_VSS_Shadow_Copy_Deletion_Command {
   meta:
      description = "Detects the exact 'vssadmin delete shadows /all /quiet' command string, or the vssadmin and delete-shadows substrings co-occurring -- the canonical Volume Shadow Copy Service anti-recovery command used to eliminate Windows' built-in file-recovery mechanism prior to ransomware encryption."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "c9c4d7e2-5f13-48b6-a1d9-2e6b8c4f0a73"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $vss_delete = "vssadmin delete shadows /all /quiet" ascii wide nocase
      $vss_pattern = "vssadmin" ascii wide nocase
      $delete_shadows = "delete shadows" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      ($vss_delete or ($vss_pattern and $delete_shadows))
}
```

### Hunting Rules

#### Veeam Backup Software Bareword Reference

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1489 (Service Stop)
**Confidence:** LOW
**Rationale:** Salvaged from the same source rule as the Veritas combination above. The source condition let a bare, case-insensitive, non-`fullword` match on "veeam" alone satisfy the entire rule with no combination requirement — a single common product-name token that could appear inside longer strings (paths, filenames, unrelated documentation) rather than a distinguishing combination. Kept as a standalone Hunting lead for Veeam Backup targeting rather than folded into the Veritas Detection rule, since the two target unrelated products.
**False Positives:** A bare "veeam" substring can appear in legitimate Veeam-aware backup-management tooling, log analysis scripts, or documentation referencing the product by name.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Arsenal237_Veeam_Backup_Reference {
   meta:
      description = "Detects a bare, case-insensitive reference to 'veeam' with no word boundary -- a weaker standalone signal than the Veritas Gx-service combination, retained as a hunting lead given this ransomware's documented enterprise-backup-disablement behavior."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "b7e2a9d4-1f83-46c5-b2e9-4a7c1e9d3f58"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $veeam = "veeam" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $veeam
}
```

#### RustRansomNoteTask Persistence Marker

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** LOW
**Rationale:** Salvaged from a broader source rule ("Campaign and Version Identifier Detection") whose `any of them` condition let a single-build campaign-tracking ID and a single-release version string trigger the same rule alone — both pure per-build atomics, already carried in the IOC feed, with no combination or behavioral value beyond the ID/version value itself. What survives is the scheduled-task name this build creates to re-display its ransom note persistently across logons — a real, if fully renameable, persistence behavior (T1053.005).
**False Positives:** A legitimate scheduled task coincidentally sharing this exact name is not expected but cannot be fully ruled out.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
rule TOOLKIT_Arsenal237_RustRansomNoteTask_Persistence_Marker {
   meta:
      description = "Detects the RustRansomNoteTask scheduled-task name string used by this ransomware build to re-display its ransom note persistently across user logons. Salvaged from a broader source rule that also let a single-build campaign-tracking ID and a single-release version string trigger the same rule alone -- both pure per-build atomics, already carried in the IOC feed."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "d3f8a1c2-6b4e-4a91-9c73-1d5e8f2a6b91"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $ransom_task = "RustRansomNoteTask" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $ransom_task
}
```

#### Anti-Analysis / Anti-Sandbox Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion: System Checks), T1622 (Debugger Evasion)
**Confidence:** MODERATE
**Rationale:** *Fix applied during retiering:* the source condition let the BIOS-registry-path check and the `IsDebuggerPresent` API string each trigger the entire rule alone with no combination required — both are individually common in legitimate hardware-detection, licensing, and anti-tamper/anti-piracy code, and neither is a distinguishing signal by itself. Rewritten to require each to co-occur with at least one other anti-analysis indicator (a VM-vendor string, the paired sandbox-context terms, or each other). The 3-of-5 VM-vendor and both-of-2 sandbox-context combinations are unchanged from source and remain the strongest branches. The registry-path string itself has also been corrected: the source's escaping resolves to two literal backslash bytes between each path component, which only matches if the compiled binary stores doubled backslashes; the standard single-backslash encoding has been added as a second variant so the rule matches either encoding without assuming which one this build actually uses.
**False Positives:** Legitimate hardware-detection, installer-compatibility, or licensing/anti-tamper software commonly combines 2 or more of these same signal types (e.g., checking both the BIOS vendor string and for a debugger before running). This is a broad technique-class heuristic, not a family-specific one — analyst review of the specific binary is required before treating a hit as malicious.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Arsenal237_AntiAnalysis_Sandbox_Combination {
   meta:
      description = "Detects a combination of anti-analysis indicators: 3 of 5 hypervisor/VM vendor name strings, both sandbox-context keywords together, the BIOS-registry check paired with a VM-vendor string or the IsDebuggerPresent API, or the debugger-presence check paired with a VM-vendor or sandbox-context string. Restructured from a source rule that let the BIOS-registry path and the IsDebuggerPresent API string each trigger the whole rule alone -- both are individually common in legitimate hardware-detection and anti-tamper/licensing code."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "e5d84f60-5103-4eb4-a039-7fb4e82b3d16"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $vm_vbox = "VBOX" ascii wide nocase
      $vm_vmware = "VMWARE" ascii wide nocase
      $vm_qemu = "QEMU" ascii wide nocase
      $vm_xen = "XEN" ascii wide nocase
      $vm_hyperv = "HYPERV" ascii wide nocase

      $sandbox_cuckoo = "cuckoo" ascii wide nocase
      $sandbox_malware = "malware" ascii wide nocase

      $bios_registry1 = "HARDWARE\\DESCRIPTION\\System\\BIOS" ascii wide nocase
      $bios_registry2 = "HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS" ascii wide nocase

      $debugger_check = "IsDebuggerPresent" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         (3 of ($vm_*)) or
         (all of ($sandbox_*)) or
         (($bios_registry1 or $bios_registry2) and (1 of ($vm_*) or $debugger_check)) or
         ($debugger_check and (1 of ($vm_*) or all of ($sandbox_*)))
      )
}
```

#### Analysis Tool Process Awareness

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1518.001 (Software Discovery: Security Software Discovery), T1057 (Process Discovery)
**Confidence:** MODERATE
**Rationale:** Requires 6 of 9 named reverse-engineering/network-analysis tool references to co-occur — a broad anti-analysis technique-class heuristic (checking whether investigator tooling is present) that is common across commodity malware generally and is not specific to this family. *Fix applied during retiering:* the source's bare "ida" string is 3 bytes, under the project's 4-byte specificity floor, and risks matching as a substring inside unrelated words. Replaced with "ida.exe" and "ida64.exe" (both already named individually in the IOC feed's own tool list), and the combination threshold raised from 5-of-8 to 6-of-9 to hold the same proportional bar as the source.
**False Positives:** Legitimate IT asset-inventory scripts, software-catalog tools, or a malware analyst's own pre-configured VM image can reference several of these tool names together; the 6-of-9 threshold reduces but does not eliminate this.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule TOOLKIT_Arsenal237_Analysis_Tool_Process_Awareness {
   meta:
      description = "Detects co-occurrence of at least 6 of 9 named reverse-engineering/network-analysis tool references (procmon, wireshark, x64dbg, ida.exe, ida64.exe, ghidra, dnspy, fiddler, processhacker) -- a broad anti-analysis technique-class heuristic common across commodity malware generally and not specific to this family."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "f1b62d4e-3f81-4c92-8e17-5d9a2c60f1b4"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $procmon = "procmon" ascii wide nocase
      $wireshark = "wireshark" ascii wide nocase
      $x64dbg = "x64dbg" ascii wide nocase
      $ida_exe = "ida.exe" ascii wide nocase
      $ida64_exe = "ida64.exe" ascii wide nocase
      $ghidra = "ghidra" ascii wide nocase
      $dnspy = "dnspy" ascii wide nocase
      $fiddler = "fiddler" ascii wide nocase
      $processhacker = "processhacker" ascii wide nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      6 of them
}
```

#### Rust ChaCha20 Implementation Fingerprint

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** No dedicated ATT&CK technique — compiled-language/family classification signal, not an attacker technique.
**Confidence:** LOW
**Rationale:** *Fix applied during retiering:* the source condition ("2 of them") let the two universal Rust-compilation markers ("core::panicking" and "cargo") alone satisfy the rule with no ChaCha-specific evidence at all — that combination is present in effectively any Rust-compiled executable, malicious or not, since both strings are routine artifacts of the Rust standard library and build toolchain. Rewritten to mandate the ChaCha implementation-specific constant name plus at least one generic marker, so the rule can no longer fire on a Rust binary that lacks the ChaCha-specific string.
**False Positives:** Not characterized against a goodware corpus. "Chacha_256_constant" has not been confirmed absent from unrelated software built on the same or a similar ChaCha20 crate implementation (e.g., Rust's widely-used `rand_chacha` crate, used far beyond ransomware for general-purpose seeded randomness).
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates pending goodware validation, not alerts.

```yara
rule TOOLKIT_Arsenal237_Rust_ChaCha20_Implementation_Fingerprint {
   meta:
      description = "Detects the Chacha_256_constant symbol name from this ransomware's Rust ChaCha20 implementation, required together with at least one generic Rust-compilation marker (core::panicking or cargo). Restructured from a source rule whose 'any 2 of 3' condition let the two generic Rust-compiler markers alone satisfy the rule with no ChaCha-specific evidence, a combination present in effectively any Rust-compiled executable."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      campaign = "Arsenal-237-Backup-Targeting-Ransomware"
      id = "a6e95071-6214-4fc5-b14a-80c5f93c4e27"
      hash1 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
   strings:
      $chacha_const = "Chacha_256_constant" ascii wide
      $rust_std = "core::panicking" ascii wide
      $cargo = "cargo" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $chacha_const and
      1 of ($rust_std, $cargo)
}
```

---

## Sigma Rules

### Detection Rules

#### Volume Shadow Copy Deletion via Vssadmin

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1490 (Inhibit System Recovery)
**Confidence:** HIGH
**Rationale:** `vssadmin delete shadows` is the canonical, technique-level VSS anti-recovery command — a chokepoint the attacker cannot avoid touching to eliminate this specific recovery mechanism via the `vssadmin` CLI. *Fix applied during retiering:* the source `filter` block excluded command lines containing the literal string `VSSADMIN_DELETE_SHADOWS`, a value with no correspondence to any real `vssadmin` command-line syntax — it could never have matched, and so could never have suppressed a real event. Removed for clarity (it was functionally inert either way, since `selection and not filter` collapses to `selection` when the filter never matches). `level: critical` has been demoted to `level: high`: a rare-but-real legitimate false-positive population exists (backup rotation and disk-space-management scripts), which is a `high`, not `critical`, FP profile under the project's level-discipline gate.
**False Positives:** Legitimate backup, disk-space-management, or system-restore maintenance scripts that invoke `vssadmin delete shadows`.
**Blind Spots:** Misses WMI- or PowerShell-based shadow-copy deletion that never invokes `vssadmin.exe` by name; requires process-creation command-line telemetry (Sysmon Event ID 1 or native Security 4688 with command-line auditing enabled).
**Validation:** Trigger a `vssadmin delete shadows /all /quiet` execution — must match; a `vssadmin list shadows` (enumeration only, no deletion) command must NOT fire.
**Deployment:** Sysmon process creation, native Windows Security 4688 with command-line auditing, EDR process telemetry.

```yaml
title: Volume Shadow Copy Deletion via Vssadmin (Ransomware Anti-Recovery Indicator)
id: b8961351-34c4-4a6e-b031-16a6368ae15f
status: experimental
description: >-
  Detects execution of vssadmin with delete and shadows present in the command
  line -- the canonical Volume Shadow Copy Service anti-recovery command used
  by ransomware, including this Arsenal-237 build, to eliminate Windows'
  built-in file-recovery mechanism before encryption begins.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1490
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  condition: selection
falsepositives:
  - Legitimate backup, disk-space-management, or system-restore maintenance scripts that invoke vssadmin delete shadows.
level: high
```

### Hunting Rules

#### RustRansomNoteTask Scheduled Task File Creation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** LOW
**Rationale:** A single, attacker-chosen literal specific to this build; a naming-convention rebrand evades it entirely (Gate 1: durability outranks as-written precision). *Fix applied during retiering:* `level: high` was inflated for a fully renameable single-artifact selector; demoted to `level: medium`, the Hunting-appropriate level for a suspicious-but-brittle lead.
**False Positives:** A legitimate scheduled task using similar naming is not expected but cannot be fully ruled out.
**Deployment:** Linux/Windows file integrity monitoring, Sysmon file-event telemetry, scheduled-task audit logging.

```yaml
title: RustRansomNoteTask Scheduled Task File Creation
id: e803d43f-6b5a-48e1-b25f-9da5e74bca63
status: experimental
description: >-
  Detects creation of a file whose name contains RustRansomNoteTask -- the
  scheduled-task marker this Arsenal-237 build creates for persistent
  re-display of its ransom note across user logons. A single, attacker-chosen
  literal specific to this build; a naming-convention rebrand evades it
  entirely.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.execution
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1053.005
  - detection.emerging-threats
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains: 'RustRansomNoteTask'
  condition: selection
falsepositives:
  - Legitimate system tasks with similar naming are not expected but cannot be fully ruled out.
level: medium
```

#### Arsenal-237 Backup Service Multi-Termination (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its required non-alerting base rule
**Robustness:** 2 (correlation) / 1 (base rule alone)
**ATT&CK Coverage:** T1489 (Service Stop)
**Confidence:** MODERATE
**Rationale:** The source rule's own description stated an unrealizable intent — "3+ distinct backup services to stop within 5 minutes" — that a single-event Sigma selection cannot express, and had been silently downgraded to fire on any single matching service stop. Rebuilt here as a genuine Sigma `value_count` correlation: a base rule (not alerting alone) matching any backup-related service-stop event, paired with a correlation counting distinct `param1` service names per host within a 5-minute window, restoring the originally intended multi-service threshold instead of the silent single-event downgrade. Capped at Hunting rather than Detection: a single product's own coordinated restart (a Backup Exec agent update or reinstall cycling several of its own Gx-prefixed sub-services together) can plausibly satisfy this threshold without any malicious action, and this false-positive rate has not been characterized against real telemetry.
**False Positives:** A legitimate, coordinated backup-infrastructure maintenance window that restarts 3 or more backup-related services within 5 minutes (e.g. a scheduled patch or reinstall cycle touching multiple Veritas Backup Exec Agent sub-services, or a Veeam/VSS component update).
**Deployment:** SIEM correlation engine with Windows System-log Service Control Manager telemetry (EventID 7036) ingested (5-minute temporal join on `host.name`).

```yaml
title: Backup-Related Windows Service Stop Event (Base Rule)
id: c3f6f8f1-2716-4cc1-8eb6-12b9c3bf2c61
name: arsenal237_backup_service_stop
status: experimental
description: >-
  Base rule (not alerting on its own): a Service Control Manager event
  recording that a backup-related service (Veritas Backup Exec agents, Veeam,
  or the Windows Volume Shadow Copy service) has stopped. Paired with the
  value-count correlation rule below, which flags 3 or more distinct
  backup-related services stopping on the same host within a short window --
  the original rule intent this file's source draft could not express as a
  single-event Sigma selection.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1489
  - detection.emerging-threats
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7036
    Provider_Name: 'Service Control Manager'
    param1|contains:
      - 'GxVss'
      - 'GxBlr'
      - 'GxFWD'
      - 'GxCVD'
      - 'GxCIMgr'
      - 'veeam'
      - 'vss'
    param2: 'stopped'
  condition: selection
falsepositives:
  - >-
    Legitimate service maintenance or scheduled backup-system restarts. Not
    alerting on its own -- reviewed only when 3 or more distinct matching
    services stop on the same host within the correlation window.
level: informational
---
title: 3+ Distinct Backup Services Stopped on Same Host Within 5 Minutes
id: d0d88f82-c8e3-42e5-a3c3-34cb8a5fec1b
status: experimental
description: >-
  Fires when 3 or more distinct backup-related services (Veritas Backup Exec
  agents, Veeam, or VSS) stop on the same host within 5 minutes.
  Operationalizes this ransomware's own documented multi-stage
  service-termination sequence -- a single service stop is common maintenance
  noise, but 3 or more distinct backup services stopping together in a tight
  window is a recognized ransomware precursor to encryption.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1489
  - detection.emerging-threats
correlation:
  type: value_count
  rules:
    - arsenal237_backup_service_stop
  group-by:
    - host.name
  timespan: 5m
  condition:
    field: param1
    gte: 3
falsepositives:
  - >-
    A coordinated, legitimate backup-infrastructure maintenance window that
    restarts 3 or more backup-related services within 5 minutes (e.g. a
    scheduled patch cycle across Veritas/Veeam/VSS components).
level: medium
```

#### Arsenal-237 Database Service Multi-Termination (Correlation)

**Tier:** Hunting (correlation rule) — bundled below with its required non-alerting base rule
**Robustness:** 2 (correlation) / 1 (base rule alone)
**ATT&CK Coverage:** T1489 (Service Stop)
**Confidence:** LOW
**Rationale:** Same restructuring as the backup-service correlation above: the source rule's own description stated an unrealizable "2+ distinct database services within 10 minutes" intent that a single-event selection cannot express. Rebuilt as a `value_count` correlation. Held at Hunting with LOWER confidence than the backup-service correlation: "sql" and "oracle" are generic substrings that can each match multiple distinct service display names belonging to a single legitimate product installation (for example, a SQL Server engine service and its companion Agent service both contain "sql" in their display names), so a routine Windows Update or patch cycle touching one database product can plausibly satisfy the 2-distinct-value threshold on its own. *Fix applied during retiering:* the redundant `sqlservr` entry was dropped from the source's service-name list — it is already a substring of `sql` and added no new matching capability.
**False Positives:** Coordinated, legitimate database maintenance (e.g. a Windows Update or SQL Server patch cycle that restarts the database engine and agent services together) within the same 10-minute window.
**Deployment:** SIEM correlation engine with Windows System-log Service Control Manager telemetry (EventID 7036) ingested (10-minute temporal join on `host.name`).

```yaml
title: Database-Related Windows Service Stop Event (Base Rule)
id: f06d6f95-2946-4bb9-b0ff-49921d91922e
name: arsenal237_database_service_stop
status: experimental
description: >-
  Base rule (not alerting on its own): a Service Control Manager event
  recording that a SQL Server or Oracle database-related service has stopped.
  Paired with the value-count correlation rule below, which flags 2 or more
  distinct database services stopping on the same host within a short window.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1489
  - detection.emerging-threats
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7036
    Provider_Name: 'Service Control Manager'
    param1|contains:
      - 'sql'
      - 'oracle'
      - 'ocssd'
      - 'dbsnmp'
    param2: 'stopped'
  condition: selection
falsepositives:
  - >-
    Legitimate database maintenance or scheduled restarts, including routine
    patch cycles. Not alerting on its own -- reviewed only when 2 or more
    distinct matching services stop on the same host within the correlation
    window.
level: informational
---
title: 2+ Distinct Database Services Stopped on Same Host Within 10 Minutes
id: a88a8604-f07b-452b-821e-ecd610edd063
status: experimental
description: >-
  Fires when 2 or more distinct SQL Server or Oracle database-related
  services stop on the same host within 10 minutes. Operationalizes this
  ransomware's documented database-service-termination stage, run to release
  file locks on database files before encryption. Generic service-name
  substrings ("sql", "oracle") carry a real legitimate-maintenance false
  positive population, so this is a hunting lead rather than an
  alerting-grade correlation.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-new_enc-exe-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
  - attack.impact
  - attack.t1489
  - detection.emerging-threats
correlation:
  type: value_count
  rules:
    - arsenal237_database_service_stop
  group-by:
    - host.name
  timespan: 10m
  condition:
    field: param1
    gte: 2
falsepositives:
  - >-
    Coordinated, legitimate database maintenance (e.g. a Windows Update or
    SQL Server patch cycle that restarts the database engine and agent
    services together) within the same 10-minute window.
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA hash-string rule cut (non-functional as written).** The source "file hash detection" rule searched for the hex text of the file's own MD5/SHA1/SHA256 digest as literal ASCII/wide strings inside the file itself, rather than using YARA's hash module (`hash.md5(0, filesize)` / `hash.sha256(0, filesize)`) or an external hash list. A file does not normally contain the hex text of its own hash, so as written this rule would essentially never fire on the sample it was built to detect. All three hash values are correctly carried in the IOC feed as structured hash indicators.
- **YARA ChaCha20 key rule cut (atomic).** The hardcoded encryption key (a hex string plus a redundant 5-character prefix fragment of the same key) is single-build cryptographic material with no combination or behavioral structure — a hash-equivalent per the project's Cut checklist. Already present in the IOC feed under `cryptographic_indicators.encryption_keys`.
- **YARA hex-encoded ransom-note header cut (atomic).** The 46-character hex string is the ASCII-hex encoding of this build's version string plus ransom-note header text; it changes if the version or header text changes, and has no combination partner in the rule. Already present in the IOC feed under `string_based_iocs.hex_encoded_strings`.
- **YARA campaign-identifiers rule split.** The source rule let the campaign tracking ID, the `v0.5-beta` version string, and the `RustRansomNoteTask` scheduled-task name each independently trigger the whole rule via `any of them` — three unrelated single-literal detections bundled under one name. The campaign ID and version string are per-build atomics with no combination or behavioral value (already in the IOC feed); `RustRansomNoteTask` is salvaged into its own standalone Hunting rule, since it represents a real, if brittle, persistence behavior.
- **YARA Veritas-targeting rule split by signal strength.** The source rule let a bare, un-`fullword`'d match on "veeam" alone satisfy the same condition as a 3-of-5 combination across five distinct Veritas Backup Exec internal service short-names. The Gx combination is a genuine tool-family artifact and is promoted to Detection; the bare "veeam" match is a much weaker single-token signal and is demoted to its own Hunting rule.
- **YARA anti-analysis rule restructured.** The source condition let the BIOS-registry-path check and the `IsDebuggerPresent` API string each trigger the entire rule alone — both are individually common in legitimate hardware-detection, licensing, and anti-tamper code. Rewritten to require each to co-occur with at least one other anti-analysis signal. The registry-path string was also corrected: the source's escaping (`HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS`) resolves to two literal backslash bytes between each path component, which would only match if the compiled binary itself stores doubled backslashes; the standard single-backslash encoding has been added as a second variant so the rule matches either encoding without assuming which one the actual sample uses.
- **YARA analysis-tool rule floor fix.** The source's bare `"ida"` string is 3 bytes, under the project's 4-byte specificity floor, and risks matching as a substring of unrelated words. Replaced with `"ida.exe"` and `"ida64.exe"` (both already named individually in the IOC feed's own tool list), and the combination threshold adjusted from 5-of-8 to 6-of-9 to hold the same proportional bar.
- **YARA Rust-family rule fixed (over-broad combinator).** The source's `2 of them` condition let the two universal Rust-compilation markers (`core::panicking` and `cargo`) alone satisfy the rule with no ChaCha-specific evidence at all — a combination present in effectively any Rust-compiled executable, not just this ransomware family. Rewritten to require the ChaCha implementation-specific constant name plus at least one generic marker.
- **Sigma VSS-deletion rule: fabricated filter removed, level demoted.** The source `filter` block excluded command lines containing the literal string `VSSADMIN_DELETE_SHADOWS` — a value with no correspondence to any real `vssadmin` command-line syntax; it could never have suppressed a real event. Removed for clarity. `level: critical` has been demoted to `level: high` per the project's level-discipline gate (a rare-but-real legitimate FP population exists).
- **Sigma backup-service and database-service rules rebuilt as correlations.** Both source rules' own descriptions stated an unrealizable multi-event intent (3+ distinct backup services within 5 minutes; 2+ distinct database services within 10 minutes) that a single-event Sigma selection cannot express, and had been silently downgraded to fire on any single matching service stop. Both have been rebuilt as genuine Sigma `value_count` correlations, restoring the originally intended detection logic. Both land at Hunting rather than Detection given the realistic single-product-restart false-positive path described in each rule's Rationale above. The redundant `sqlservr` substring was also dropped from the database rule's service list — it is already a substring of `sql` and added no new matching capability.
- **Sigma RustRansomNoteTask rule demoted.** `level: high` was inflated for a single, fully attacker-renameable literal; demoted to `level: medium`, the Hunting-appropriate level for a suspicious-but-brittle single-artifact selector.

### Cut Rules (genuine noise — not routed to the feed)

- **Suricata "Arsenal-237 ChaCha20 Ransomware Encryption Pattern"** (source sid `1000001`) — cut. Matches the bare word "ChaCha20" anywhere in HTTP traffic with no sticky buffer and no supporting protocol/context anchor. ChaCha20 is a standard, widely referenced cryptographic algorithm name that appears across legitimate TLS/cipher-suite documentation, software update manifests, and cryptography library traffic — a severe precision failure on its own terms. It is also unsupported by this sample's own documented behavior: new_enc.exe's ChaCha20 usage is local file encryption, not a network protocol, and the IOC feed explicitly records no C2 infrastructure for this build. Not a routable atomic — "ChaCha20" is a generic algorithm name, not an indicator value.
- **Suricata "Arsenal-237 Ransom Note Domain Query"** (source sid `1000002`) — cut. Matches the campaign tracking ID as a DNS-query content string, implying an automated DNS-based transmission mechanism with no support in the source material: the campaign ID's documented purpose is victim/payment-portal tracking (a human-entered identifier), and this build is confirmed to have no C2 infrastructure and to be deployed manually via CLI arguments. The campaign ID value itself is already present in the IOC feed via the YARA-side atomic accounting; no new feed entry is needed regardless of this rule's evidentiary problem.

### No Observed C2 — No Network Behavioral Rule Possible

new_enc.exe is a manually-deployed, offline file encryptor: it is invoked directly with `--pass`/`--folder`/`--file` arguments rather than propagating or beaconing on its own, and the IOC feed's family-relationship data explicitly distinguishes it from the C2-enabled sibling build (`enc_c2.exe`, which uses Tor-based infrastructure). With no documented network channel, no legitimate Suricata Detection or Hunting signature can be built for this sample; both original network signatures were speculative constructs not grounded in observed behavior (see Cut Rules above). Coverage here is host-based only.

### Atomics Already Present in the IOC Feed

- **new_enc.exe SHA256/SHA1/MD5** — the source's own YARA "file hash" rule searched for these values as in-file string matches rather than using a hash module, which would not have functioned as intended regardless of tiering; the values themselves are correctly carried under `file_hashes`.
- **ChaCha20 encryption key (hex)** — already present under `cryptographic_indicators.encryption_keys`.
- **Campaign tracking ID** (`ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4`) — already present under `campaign_identifiers.builder_ids` and `string_based_iocs.malware_family_identifiers`.
- **Version string** (`v0.5-beta`) — already present under `campaign_identifiers.version_identifiers` and `string_based_iocs.malware_family_identifiers`.
- **Hex-encoded ransom-note header** — already present under `string_based_iocs.hex_encoded_strings`.

### Goodware Validation Outstanding

None of the Hunting-tier YARA rules (Veeam bareword, anti-analysis combination, analysis-tool combination, Rust ChaCha20 fingerprint) have been run against a broad clean-software corpus. The anti-analysis and analysis-tool combinations flag a technique class common across commodity malware generally, not specific to this family; the Rust ChaCha20 fingerprint's one distinctive string (`Chacha_256_constant`) has not been confirmed absent from unrelated software built on the same or a similar ChaCha20 crate implementation (e.g., Rust's widely-used `rand_chacha` crate). A documented zero-FP result against such a corpus is the explicit precondition for reconsidering any of these for Detection tier.

### What Would Enable Stronger Coverage

- Goodware corpus validation for the four Hunting-tier YARA rules listed above.
- Confirmation of the BIOS-registry string's actual byte encoding in the compiled sample (single- vs. double-backslash) — both variants are carried in the current rule as a hedge.
- Network/C2 artifacts — this build is confirmed offline; the related `enc_c2.exe` variant's Tor-based C2 channel is the more relevant target for a future network signature.
- A live-telemetry sample of legitimate Backup Exec agent and SQL Server restart cycles, to characterize how often the two Sigma correlation rules' thresholds are met by routine maintenance alone.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
