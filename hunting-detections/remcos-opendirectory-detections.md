---
title: "Detection Rules — Remcos RAT OpenDirectory Campaign"
date: '2026-02-04'
layout: post
permalink: /hunting-detections/remcos-opendirectory-detections/
hide: true
redirect_from: /hunting-detections/remcos-opendirectory-campaign
thumbnail: /assets/images/cards/remcos-opendirectory.png
---

**Campaign:** OpenDirectory-203.159.90.147-Remcos
**Date:** 2026-02-04
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/remcos-opendirectory/

---

## Detection Coverage Summary

Remcos is a commercially-sold remote access trojan (Breaking-Security.Net) widely repurposed as off-the-shelf RAT tooling. This campaign distributed it via an open directory at 203.159.90.147, using a VB6-compiled dropper (`Payload.exe`) to stage a UAC-bypassing, Winlogon-persistent Remcos payload (`Backdoor.exe` / `remcos.exe`) with keylogging, screenshot, audio-recording, clipboard-monitoring, and browser-credential-theft capability. Coverage here is anchored on the family mutex `Remcos_Mutex_Inj` and the Winlogon Userinit hijack — both durable, near-zero-FP indicators — while a number of originally-published rules that keyed on generic Windows APIs, common registry/file paths, or the operator-configurable install folder name have been re-tiered to Hunting or salvaged into tighter mutex-anchored Detection companions. The campaign's C2 IP and download URLs are carried in the IOC feed rather than as standalone network signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 5 | 2 | T1219, T1548.002, T1547.001, T1547.004, T1055, T1056.001, T1113, T1115, T1123, T1070.004 | 0 |
| Sigma | 5 | 3 | T1548.002, T1547.004, T1036, T1055, T1070.004, T1555.003, T1539 | 1 |
| Suricata | 0 | 0 | T1071.001 (C2 — IP-anchored, see feed) | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- Mutex `Remcos_Mutex_Inj` — durable across builds of this RAT family, near-zero FP, and the primary anchor for two YARA Detection rules and the strongest Sigma-adjacent evidence in the campaign.
- Winlogon `Userinit` registry hijack (`HKLM\...\Winlogon\Userinit`) and the resulting suspicious `winlogon.exe` child process — technique-level chokepoints with essentially no legitimate collision, covered by two Detection-tier Sigma rules.

**Atomics routed to the IOC feed:** the C2/distribution IP `203.159.90.147`, its two malware-download URLs, and the sample hashes were already present in [`remcos-opendirectory-iocs.json`](/ioc-feeds/remcos-opendirectory-iocs.json) from the original analysis — three network-only rule candidates (one Sigma, two Suricata rule-objects covering three signatures) that keyed solely on this IP have been retired in favor of the feed entry rather than duplicated as standalone rules. No feed edits were required.

---

## YARA Rules

### Detection Rules

#### Remcos RAT Family Detection

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1219 (Remote Access Software), with secondary coverage of T1056.001 (Keylogging), T1555.003 (Web Browsers), T1113 (Screen Capture)
**Confidence:** HIGH
**False Positives:** None known — every OR-branch requires either the family mutex, the paired product banner + developer string, or a multi-string combination from the RAT's internal C2/keylogging/credential-theft protocol vocabulary; the loosest branch (`8 of them`) still requires at least 3 distinctive Remcos-specific tokens given only 5 of the 22 declared strings are generic Windows terms.
**Blind Spots:** A fully re-branded fork that strips the banner/developer strings, randomizes the mutex, and reworks the internal log/command vocabulary would evade this rule; targets on-disk/in-memory binaries, not network traffic.
**Validation:** Scan either analyzed sample (`hash1`/`hash3` below) — must match via the mutex branch alone; a benign, unrelated Windows executable must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning.

```yara
/*
   Yara Rule Set
   Identifier: Remcos RAT OpenDirectory Campaign (203.159.90.147)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_Remcos_Family_Detection {
   meta:
      description = "Detects Remcos RAT via its mutex, C2 protocol banner, and internal log/command strings - a multi-branch fingerprint covering the commercial Remcos RAT family regardless of build customization"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "32642d64-41b4-5b64-801e-c295f9bfe4a9"
   strings:
      $mutex = "Remcos_Mutex_Inj" ascii wide
      $banner = " * REMCOS v" ascii
      $developer = "Breaking-Security.Net" ascii

      $c2_1 = "Connected to C&C!" ascii
      $c2_2 = "[KeepAlive]" ascii
      $c2_3 = "[DataStart]" ascii

      $keylog_1 = "onlinelogs" ascii
      $keylog_2 = "offlinelogs" ascii
      $keylog_3 = " [Ctrl + V]" ascii
      $keylog_4 = "[Following text has been copied to clipboard:]" ascii
      $keylog_5 = "[Following text has been pasted from clipboard:]" ascii

      $cred_1 = "[Chrome StoredLogins found, cleared!]" ascii
      $cred_2 = "[Firefox StoredLogins cleared!]" ascii
      $cred_3 = "[Chrome Cookies found, cleared!]" ascii

      $persist_1 = "Userinit" ascii
      $persist_2 = "install.bat" ascii
      $persist_3 = "EnableLUA" ascii

      $cmd_1 = "consolecmd" ascii
      $cmd_2 = "remscriptexecd" ascii
      $cmd_3 = "getproclist" ascii

      $api_inject_1 = "VirtualAllocEx" ascii
      $api_inject_2 = "WriteProcessMemory" ascii
      $api_screen = "GdipSaveImageToStream" ascii
      $api_audio = "waveInOpen" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         $mutex or
         ($banner and $developer) or
         (3 of ($c2_*)) or
         (2 of ($keylog_*) and 2 of ($api_*)) or
         (2 of ($cred_*)) or
         (8 of them)
      )
}
```

#### Remcos OpenDirectory Campaign Mutex and Install Artifacts

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control), T1555.003 (Web Browsers), T1070.004 (File Deletion)
**Confidence:** HIGH
**Rationale:** Salvaged from the original campaign-specific rule, which OR'd the durable mutex against the generic window class name `MsgWindowClass` (the underlying IOC feed itself documents this window class as "false_positive_risk: High... confidence: LOW"). Tightened so `$mutex` is now a mandatory AND-term rather than an optional OR-branch, and the two exact-hash OR-clauses were removed — both hashes are already recorded in this rule's own `hash1`/`hash3` meta fields and in the IOC feed, so a redundant in-condition hash check added nothing (see the yara-rule-formatting skill's hash guidance).
**False Positives:** None known — every surviving branch requires the family mutex plus at least one campaign-specific artifact (the literal `remcos` install-path substring, or the exact UAC-bypass command fragment).
**Blind Spots:** A build that randomizes the mutex evades entirely; the install-path/temp-DLL/install.bat branches are brittle on their own (operator-configurable) but are gated behind the mutex requirement here.
**Validation:** Scan either analyzed sample — must match; a benign binary that coincidentally references `EnableLUA` or a Chrome/Firefox path (e.g. a legitimate browser-migration tool) must NOT fire absent the mutex.
**Deployment:** Endpoint AV/EDR file scan, memory scanning.

```yara
rule RAT_Remcos_OpenDirectory_Mutex_Install {
   meta:
      description = "Detects Remcos RAT samples from the OpenDirectory 203.159.90.147 campaign via the family mutex Remcos_Mutex_Inj combined with one of the campaign's UAC-bypass, browser-credential-path, or install/melt artifact combinations"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "393268d2-7545-5cea-ab00-81267cc5747f"
   strings:
      $mutex = "Remcos_Mutex_Inj" ascii wide
      $uac_cmd = "EnableLUA /t REG_DWORD /d 0 /f" ascii wide
      $chrome_path = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
      $firefox_path = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" ascii wide
      $install_path = "\\AppData\\Roaming\\remcos\\remcos.exe" ascii wide
      $temp_dll = "\\Temp\\0.dll" ascii wide
      $install_bat = "install.bat" ascii wide
      $ping_delay = "PING 127.0.0.1 -n 2" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 2MB and
      $mutex and
      (
         $uac_cmd or
         ($chrome_path and $firefox_path) or
         ($install_path and $temp_dll) or
         ($install_bat and $ping_delay)
      )
}
```

#### Remcos UAC Bypass and Persistence

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control), T1547.001 (Registry Run Keys / Startup Folder), T1547.004 (Winlogon Helper DLL)
**Confidence:** HIGH
**Rationale:** Every OR-branch requires either the family mutex or the literal `remcos` substring in the install path — none of the five branches can fire on the generic `Software\...\Run` string alone. Fixed a real defect from the original: the condition had no `filesize` constraint at all.
**False Positives:** None known — the generic `Software\Microsoft\Windows\CurrentVersion\Run` string only contributes when paired with the campaign install path or two other persistence-path strings plus that same install path.
**Blind Spots:** A build using a differently-named install folder AND a randomized mutex evades every branch; targets on-disk artifacts only.
**Validation:** Scan either analyzed sample — must match via the mutex + Winlogon-path branch; a legitimate administrative script referencing the Run key alone (without the campaign install path) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan.

```yara
rule RAT_Remcos_UAC_Bypass_Persistence {
   meta:
      description = "Detects Remcos RAT UAC-bypass and persistence mechanisms via reg.exe EnableLUA modification, Winlogon/Run-key persistence paths, and the mutex Remcos_Mutex_Inj, each branch anchored on the campaign's default install path or the family mutex"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "e53a05eb-deea-575f-bb7d-2a97e8d63bf0"
   strings:
      $uac_cmd_1 = "reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA" ascii wide
      $uac_cmd_2 = "EnableLUA /t REG_DWORD /d 0 /f" ascii wide
      $persist_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
      $persist_2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" ascii wide
      $persist_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii wide
      $install_path = "AppData\\Roaming\\remcos\\remcos.exe" ascii wide
      $melt_1 = "PING 127.0.0.1 -n 2" ascii wide
      $melt_3 = "install.bat" ascii wide
      $remcos_mutex = "Remcos_Mutex_Inj" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         (any of ($uac_cmd_*) and $install_path) or
         (3 of ($persist_*) and $install_path) or
         ($persist_2 and $install_path and $remcos_mutex) or
         ($remcos_mutex and 2 of ($persist_*) and any of ($uac_cmd_*)) or
         ($melt_1 and $melt_3 and $install_path)
      )
}
```

#### Remcos Process Injection (Mutex-Anchored)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055 (Process Injection)
**Confidence:** HIGH
**Rationale:** Split from the original combined injection rule, which OR'd this mutex-anchored branch against two fully-generic branches (a bare 5-of-6 classic injection API cluster, and a `desktop.ini`-triggered branch the IOC feed itself flags "false_positive_risk: High (normal folder operations)... confidence: MODERATE/LOW"). Isolating the mutex-anchored branch as its own rule preserves genuine Detection-grade precision; the generic branches are preserved separately as a Hunting rule below rather than dropped.
**False Positives:** None known — the mutex is a distinctive family identifier not shared with legitimate software.
**Blind Spots:** A build that randomizes the mutex evades this rule (the Hunting-tier generic-API companion below still applies, with higher noise).
**Validation:** Scan either analyzed sample — must match; a legitimate debugger or EDR agent using the same injection APIs but lacking the mutex must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning.

```yara
rule RAT_Remcos_Process_Injection_Mutex_Anchored {
   meta:
      description = "Detects the Remcos RAT process-injection module via the family mutex Remcos_Mutex_Inj combined with 4 or more of its classic injection API imports (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetThreadContext, SetThreadContext, ResumeThread)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "111690c6-c6a5-50fa-8f4b-1ea9c431e4f6"
   strings:
      $api_1 = "VirtualAllocEx" ascii
      $api_2 = "WriteProcessMemory" ascii
      $api_3 = "CreateRemoteThread" ascii
      $api_4 = "GetThreadContext" ascii
      $api_5 = "SetThreadContext" ascii
      $api_6 = "ResumeThread" ascii
      $remcos_mutex = "Remcos_Mutex_Inj" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $remcos_mutex and
      4 of ($api_*)
}
```

#### Remcos Surveillance Module (Log-String Anchored)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1056.001 (Keylogging), T1115 (Clipboard Data)
**Confidence:** HIGH
**Rationale:** Split from the original combined surveillance rule to isolate the two branches anchored on the distinctive `onlinelogs`/`offlinelogs`/`[Ctrl + V]` internal log-naming vocabulary from a fully-generic hook+screen+audio API cluster (preserved separately as a Hunting rule below).
**False Positives:** None known — `onlinelogs`/`offlinelogs` are distinctive internal folder-naming strings not observed in unrelated software.
**Blind Spots:** A build that renames the internal log-folder strings evades this rule.
**Validation:** Scan either analyzed sample — must match; a legitimate clipboard-manager or accessibility tool using `GetClipboardData`/`SetWindowsHookExA` alone (without the log-naming strings) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan.

```yara
rule RAT_Remcos_Surveillance_LogStrings_Anchored {
   meta:
      description = "Detects the Remcos RAT surveillance module via its distinctive internal log-folder naming (onlinelogs/offlinelogs) and clipboard-annotation string combined with keyboard-hook, clipboard, or idle-detection APIs"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "679e4b7b-2853-544e-9fad-c4c867973d02"
   strings:
      $keylog_api_1 = "SetWindowsHookExA" ascii
      $clip_api_1 = "GetClipboardData" ascii
      $activity_1 = "GetLastInputInfo" ascii
      $surv_str_1 = "onlinelogs" ascii
      $surv_str_2 = "offlinelogs" ascii
      $surv_str_3 = "[Ctrl + V]" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         ($keylog_api_1 and $clip_api_1 and 2 of ($surv_str_*)) or
         (3 of ($surv_str_*) and $activity_1)
      )
}
```

### Hunting Rules

#### Remcos Process Injection (Generic API Cluster)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1055 (Process Injection)
**Confidence:** MODERATE
**Rationale:** Every string in this rule is a standard Windows API name or a common process name (`explorer.exe`, `msedge.exe`) or the ubiquitous `desktop.ini` filename — none is Remcos-specific. This is a real, broad injection-technique signal worth analyst triage, but it will also match legitimate debuggers, EDR agents, and other injection-capable software.
**False Positives:** Legitimate debuggers (x64dbg, WinDbg), EDR/AV agents performing their own hooking, game trainers/cheat engines, and other unrelated injection-capable software. The `desktop.ini` branch specifically was flagged in the underlying campaign evidence as "false_positive_risk: High (normal folder operations)."
**Deployment:** Endpoint AV/EDR file scan; broader sweep, not for auto-block.

```yara
rule RAT_Remcos_Process_Injection_Generic_APIs {
   meta:
      description = "Broad hunting rule for a classic process-injection API cluster (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/GetThreadContext/SetThreadContext/ResumeThread) combined with references to explorer.exe/msedge.exe or desktop.ini-triggered injection timing; observed in Remcos RAT samples from this campaign but not anchored on a family-specific string, so it will also match unrelated injection-capable software"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "e3bbbd84-7fb8-5d24-bb57-90ba103a749a"
   strings:
      $api_1 = "VirtualAllocEx" ascii
      $api_2 = "WriteProcessMemory" ascii
      $api_3 = "CreateRemoteThread" ascii
      $api_4 = "GetThreadContext" ascii
      $api_5 = "SetThreadContext" ascii
      $api_6 = "ResumeThread" ascii
      $target_1 = "explorer.exe" ascii wide
      $target_2 = "msedge.exe" ascii wide
      $desktop_ini = "desktop.ini" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         (5 of ($api_*) and 2 of ($target_*)) or
         ($desktop_ini and 4 of ($api_*) and $target_1)
      )
}
```

#### Remcos Surveillance Module (Generic API Cluster)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1056.001 (Keylogging), T1113 (Screen Capture), T1123 (Audio Capture)
**Confidence:** MODERATE
**Rationale:** Requires a keyboard hook, a screen-capture API, and an audio-recording API together in one binary — a suspicious combination, but built entirely from standard Windows Multimedia/GDI+/hooking APIs with no Remcos-specific string.
**False Positives:** Legitimate remote-support tools, employee-monitoring/parental-control software, and screen/voice-recording utilities that combine these same three API categories.
**Deployment:** Endpoint AV/EDR file scan; broader sweep, not for auto-block.

```yara
rule RAT_Remcos_Surveillance_Generic_API_Cluster {
   meta:
      description = "Broad hunting rule for the combined presence of keyboard-hook, screen-capture, and audio-recording APIs (SetWindowsHookExA, GdipSaveImageToStream/BitBlt, waveInOpen/waveInAddBuffer) in one binary; observed in Remcos RAT samples from this campaign but the API combination alone is also used by legitimate remote-support and employee-monitoring software"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/"
      date = "2026-02-04"
      hash1 = "ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82"
      hash2 = "45aa592f3b30ef526e380978338718f540cff5d2"
      hash3 = "04693af3b0a7c9788daba8e35f429ba6"
      family = "Remcos"
      malware_type = "RAT"
      campaign = "OpenDirectory-203.159.90.147-Remcos"
      id = "5525c61f-9bf0-55ef-b6d0-0b15660eef3a"
   strings:
      $keylog_api_1 = "SetWindowsHookExA" ascii
      $screen_api_1 = "GdipSaveImageToStream" ascii
      $screen_api_2 = "BitBlt" ascii
      $audio_api_1 = "waveInOpen" ascii
      $audio_api_2 = "waveInAddBuffer" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      $keylog_api_1 and
      1 of ($screen_api_*) and
      1 of ($audio_api_*)
}
```

---

## Sigma Rules

### Detection Rules

#### Remcos RAT UAC Bypass via EnableLUA Registry Modification (Process)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control)
**Confidence:** HIGH
**False Positives:** Legitimate system administration (rare); enterprise management tools (SCCM, Intune) performing scripted UAC changes — verify digital signature before treating as benign.
**Blind Spots:** Misses a UAC-disable performed by a process other than `reg.exe` (e.g. PowerShell `Set-ItemProperty`) — see the companion registry-state rule below for that angle.
**Validation:** Trigger the malware's UAC-bypass routine — the reg.exe command line must match; unrelated administrative reg.exe usage that doesn't target this exact key/value combination must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Remcos RAT UAC Bypass via EnableLUA Registry Modification
id: 482a813a-346e-450c-8ff7-4b449a26ad7d
status: experimental
description: >-
  Detects UAC bypass by setting the EnableLUA registry value to 0 via
  reg.exe, a technique used by Remcos RAT to disable User Account
  Control ahead of persistence installation
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.privilege-escalation
    - attack.t1548.002
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'ADD'
            - 'HKLM'
            - 'Policies\System'
            - 'EnableLUA'
            - 'REG_DWORD'
            - '/d 0'
    selection_parent:
        ParentImage|endswith: '\cmd.exe'
    condition: all of selection_*
falsepositives:
    - Legitimate system administration (rare)
    - Enterprise management tools (SCCM, Intune) - verify digital signature
level: high
```

#### Remcos RAT Winlogon Userinit Persistence via Registry Modification

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1547.004 (Winlogon Helper DLL)
**Confidence:** HIGH
**False Positives:** Unlikely — no legitimate process modifies this value outside OS installation.
**Blind Spots:** None significant for this exact technique; a persistence mechanism that avoids Userinit entirely (e.g. a Run key alone) is not covered by this rule.
**Validation:** Trigger the malware's persistence routine — the registry write appending a second executable path must match; the legitimate single-value `userinit.exe` write during OS install must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: Remcos RAT Winlogon Userinit Persistence via Registry Modification
id: 208b4736-f00a-44bd-b71e-1230ece13876
status: experimental
description: >-
  Detects modification of the Winlogon Userinit registry value to
  append an additional executable path, a rare persistence technique
  used by Remcos RAT that runs the payload at every user logon before
  the desktop loads
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.004
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
    filter_legitimate:
        Details: 'C:\WINDOWS\system32\userinit.exe,'
    condition: selection and not filter_legitimate
falsepositives:
    - Unlikely (no legitimate process modifies this value outside OS installation)
level: critical
```

#### EnableLUA Registry Value Set to Disable User Account Control (Registry State)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** Reformatted from a retired KQL hunting query (see Coverage Gaps). Complements the process-creation rule above by catching the resulting registry state change regardless of which process or mechanism performed the write, so it still fires if the operator switches from `reg.exe` to PowerShell or a different UAC-disable mechanism.
**False Positives:** Legitimate system administration (rare); enterprise management tools (SCCM, Intune, Group Policy) disabling UAC for legacy application compatibility.
**Blind Spots:** Cannot distinguish which process performed the write; pair with the process-creation rule above for attribution.
**Validation:** Trigger the malware's UAC-bypass routine — the registry value write must match; a system where `EnableLUA` remains at its default value of 1 must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (registry telemetry).

```yaml
title: EnableLUA Registry Value Set to Disable User Account Control
id: 0ce7475a-f0d5-48fe-bd80-629f9df689aa
status: experimental
description: >-
  Detects the EnableLUA registry value under the system UAC policy key
  being set to 0 (disabled), regardless of which process performs the
  write. Complements the reg.exe process-creation detection for the
  same Remcos RAT UAC-bypass technique by catching the resulting
  registry state change if a different mechanism (e.g. PowerShell
  Set-ItemProperty) performs the write.
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.privilege-escalation
    - attack.t1548.002
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Policies\System\EnableLUA'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Legitimate system administration (rare)
    - Enterprise management tools (SCCM, Intune, Group Policy) disabling UAC for legacy application compatibility
level: high
```

#### Remcos RAT File Melting Behavior via install.bat

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1070.004 (File Deletion)
**Confidence:** HIGH
**False Positives:** Custom administrative scripts that happen to reference the same folder name (very rare pattern).
**Blind Spots:** A build using a differently-named install folder evades the `AppData\Roaming\remcos` requirement; misses file-melting performed via a mechanism other than `cmd.exe`.
**Validation:** Trigger the malware's self-deletion routine — the full command-line combination must match; a benign script that pings localhost or deletes files without ALSO referencing this exact folder must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Remcos RAT File Melting Behavior via install.bat
id: 62f7d36c-2d5d-4f21-a6c9-71589b95ddb0
status: experimental
description: >-
  Detects the Remcos RAT self-deletion ("file melting") sequence - a
  cmd.exe command line combining a PING-based delay, a DEL command, a
  start command, and a reference to the campaign's remcos install
  folder, used to remove the install.bat staging script after
  installation completes
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.stealth
    - attack.t1070.004
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\cmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'PING 127.0.0.1'
            - 'DEL'
            - 'start'
            - 'AppData\Roaming\remcos'
    condition: all of selection_*
falsepositives:
    - Custom administrative scripts referencing the same folder name (very rare pattern)
level: high
```

#### Remcos RAT Execution via Winlogon Userinit Hijack (Child Process)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1547.004 (Winlogon Helper DLL)
**Confidence:** HIGH
**False Positives:** Unlikely — `winlogon.exe` legitimately spawns only a small, fixed set of OS helper processes, all excluded by the filter.
**Blind Spots:** A future OS update introducing a new legitimate `winlogon.exe` child not in the filter list could false-positive until the filter is updated.
**Validation:** Trigger the malware's Userinit-hijack persistence — the AppData-sourced child of `winlogon.exe` must match; the three known-legitimate children (`userinit.exe`, `LogonUI.exe`, `dwm.exe`) must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry).

```yaml
title: Remcos RAT Execution via Winlogon Userinit Hijack
id: 78fef00f-cd92-4dcd-8413-c3ed49b56aab
status: experimental
description: >-
  Detects a child process of winlogon.exe launching from %AppData% -
  winlogon.exe legitimately spawns only a small, fixed set of OS helper
  processes, so any other AppData-sourced child is a strong indicator
  of the Userinit-hijack persistence technique used by Remcos RAT
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.004
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\winlogon.exe'
        Image|contains: '\AppData\'
    filter_legitimate:
        Image|endswith:
            - '\userinit.exe'
            - '\LogonUI.exe'
            - '\dwm.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Unlikely
level: critical
```

### Hunting Rules

#### Remcos RAT Execution from Default AppData Install Path

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036 (Masquerading)
**Confidence:** MODERATE
**Rationale:** Retiered from the original file, which titled and described this rule as "Mutex Detection" and claimed the mutex `Remcos_Mutex_Inj` as a "definitive indicator" — but the actual `detection:` logic only ever matched an `Image` path substring. Standard Sysmon/EDR process telemetry has no field for mutex creation, so this rule cannot detect the mutex at all; scored on the logic actually implemented (a path match), not the title. The install folder name is configurable in the Remcos builder, making this a brittle, single-literal indicator.
**False Positives:** Any software that happens to install into a folder literally named `remcos` (coincidental collision); brittle by design — operators can trivially rename this folder via the Remcos builder, evading this indicator entirely on the next build.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-creation telemetry); broader sweep, not for auto-block.

```yaml
title: Remcos RAT Execution from Default AppData Install Path
id: 412f0f16-665a-4623-9e3c-92d98012f77b
status: experimental
description: >-
  Detects process execution from the default Remcos RAT install folder
  (AppData\Roaming\remcos\). This is a path-based indicator, not a
  mutex check - the malware's mutex Remcos_Mutex_Inj cannot be detected
  via standard Sysmon/EDR process telemetry, only via YARA memory
  scanning or EDR-native mutex enumeration. The install folder name is
  configurable in the Remcos builder, so this indicator is brittle
  against operator customization.
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.stealth
    - attack.t1036
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\AppData\Roaming\remcos\'
    condition: selection
falsepositives:
    - >-
      Any software that happens to install into a folder literally
      named "remcos" (coincidental collision)
    - >-
      Brittle by design - operators can trivially rename this folder
      via the Remcos builder, evading this indicator entirely on the
      next build
level: medium
```

#### Suspicious Process Access from AppData to Browser or Explorer Process

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1055 (Process Injection)
**Confidence:** MODERATE
**Rationale:** A real, technique-level process-access pattern (broad or write-capable access rights from a user-writable location into a browser or `explorer.exe`), but the `%AppData%` source scope is common to a large amount of legitimate consumer software, and the target/access-rights combination is not Remcos-specific. Demoted from `high` given the acknowledged FP scenarios below.
**False Positives:** Legitimate software updates from AppData; development/debugging tools.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (process-access telemetry); broader sweep, not for auto-block.

```yaml
title: Suspicious Process Access from AppData to Browser or Explorer Process
id: 320eaf61-97be-4fc8-bee0-cab1d45aba05
status: experimental
description: >-
  Detects a process running from a user-writable %AppData% location
  opening a handle with broad or write-capable access rights to
  explorer.exe or a major browser process - a generic
  process-injection telemetry pattern observed in the Remcos RAT
  process-injection module used against this campaign, but not
  anchored to any Remcos-specific string. The %AppData% source
  location is common to a large amount of legitimate consumer
  software.
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055
    - detection.emerging-threats
logsource:
    category: process_access
    product: windows
detection:
    selection_source:
        SourceImage|contains: '\AppData\'
    selection_target:
        TargetImage|endswith:
            - '\explorer.exe'
            - '\msedge.exe'
            - '\chrome.exe'
            - '\firefox.exe'
    selection_access:
        GrantedAccess:
            - '0x1F0FFF'
            - '0x1FFFFF'
            - '0x1000'
    condition: all of selection_*
falsepositives:
    - Legitimate software updates from AppData
    - Development/debugging tools
level: medium
```

#### Non-Browser Process Accessing Browser Credential Store Files

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1555.003 (Web Browsers), T1539 (Steal Web Session Cookie)
**Confidence:** MODERATE
**Rationale:** A durable, family-agnostic technique detector (accessing Chrome/Firefox credential and cookie files from a non-browser process is a genuine chokepoint), but the campaign's own false-positive list names specific, common categories of legitimate software — password managers and backup tools — that are expected to trigger it. Demoted from `high` to reflect that acknowledged, non-trivial FP volume; the underlying technique detection itself remains high-confidence.
**False Positives:** Password managers (1Password, Bitwarden, LastPass) importing saved browser credentials; backup software performing full user-profile backups.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (file-access telemetry); broader sweep, not for auto-block.

```yaml
title: Non-Browser Process Accessing Browser Credential Store Files
id: 27e252f6-c5d9-4545-ab96-b180ab116a88
status: experimental
description: >-
  Detects access to Chrome or Firefox credential and cookie database
  files by a process other than the browser itself - the technique
  used by the Remcos RAT credential-theft module in this campaign.
  This is a family-agnostic technique detector; legitimate password
  managers and backup software are known to trigger it, so it is
  tiered for hunting rather than direct alerting.
references:
    - https://the-hunters-ledger.com/hunting-detections/remcos-opendirectory-detections/
author: The Hunters Ledger
date: '2026-02-04'
tags:
    - attack.credential-access
    - attack.t1555.003
    - attack.t1539
    - detection.emerging-threats
logsource:
    category: file_access
    product: windows
detection:
    selection_chrome:
        TargetFilename|contains:
            - '\Google\Chrome\User Data\Default\Login Data'
            - '\Google\Chrome\User Data\Default\Cookies'
    selection_firefox:
        TargetFilename|contains: '\Mozilla\Firefox\Profiles\'
        TargetFilename|endswith:
            - '\logins.json'
            - '\cookies.sqlite'
    filter_legitimate:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
    condition: (selection_chrome or selection_firefox) and not filter_legitimate
falsepositives:
    - Password managers (1Password, Bitwarden, LastPass) importing saved browser credentials
    - Backup software performing full user-profile backups
level: medium
```

---

## Suricata Signatures

None of the four originally-published network signatures clear the Detection or Hunting bar as standalone rules. Two bidirectional IP-match signatures and one GET-for-`.exe` signature keyed solely on the campaign IP `203.159.90.147` (all three already carried in the IOC feed as atomics — see Coverage Gaps); the fourth, an HTTP-POST-plus-PNG-magic-byte signature with no host/URI/User-Agent scope, was cut as ubiquitous benign-traffic noise. Full detail on each retirement is in Coverage Gaps below.

---

## Coverage Gaps

**Cut — Remcos VB6 Dropper Detection (YARA).** The original rule's strings were entirely generic VB6-runtime and COM API names (`MSVBVM60.DLL`, `rtcCreateObject2`, `DllFunctionCall`, `rtcShell`, `Scripting.FileSystemObject`) plus a single generic dropped-filename (`0.dll`) — every one of these is standard to *any* VB6-compiled program, malicious or legitimate, and a goodware scan would flag heavily on `MSVBVM60.DLL` alone. No Remcos-specific or even malware-specific string was present; the rule's own title and description ("obfuscated strings and anti-analysis") did not match its actual string content, and no obfuscation/anti-analysis indicator was ever declared. Salvage was attempted (requiring all six strings simultaneously) but even that tightened form adds no distinguishing signal beyond "VB6 program that shells out and touches files," which describes a large amount of legitimate legacy VB6 software. **What would enable a rule:** a distinctive embedded resource name, class name, PDB path, or an actual obfuscation/anti-analysis string from the dropper — none were captured in the original evidence.

**Cut — Remcos HTTP Screenshot Exfiltration (Suricata).** The rule matched an HTTP POST containing the PNG file signature (`89 50 4E 47`) anywhere in the first 4 bytes of the client body, with no host, URI, or User-Agent constraint (`$EXTERNAL_NET any`, unscoped). The PNG magic byte is the standard signature for every PNG file in existence; this pattern matches an enormous volume of entirely legitimate HTTP POST traffic (image-sharing tools, ticketing-system attachments, chat apps, cloud-storage sync, any web app accepting PNG uploads) with no pivot value — an analyst cannot meaningfully triage "every PNG upload on the network." **What would enable a rule:** a distinguishing URI path, Host header, User-Agent, or encoding marker specific to the exfiltration channel — none was captured in the original evidence.

**Atomics routed to the IOC feed (already present, no feed edit required):**
- **Sigma — Remcos Network C2 Communication to 203.159.90.147.** Keyed solely on `DestinationIp: 203.159.90.147`; removing the literal leaves nothing. The IP is already recorded in [`remcos-opendirectory-iocs.json`](/ioc-feeds/remcos-opendirectory-iocs.json) (`network.indicator: 203.159.90.147`, confidence DEFINITE, severity CRITICAL).
- **Suricata — Remcos C2 IP Block (two signatures, sid 1000001/1000002).** A bidirectional pure-IP match (`alert ip $HOME_NET any -> 203.159.90.147 any` / the reverse direction) with no content or protocol anchor at all — the textbook IOC-feed case, not a signature.
- **Suricata — Remcos OpenDirectory Malware Download (sid 1000006).** Combined a generic `GET ... .exe` URI pattern with the campaign IP as the sole discriminator; removing the IP would make this fire on virtually any software download over plain HTTP. Both malware-download URLs (`hxxp://203[.]159[.]90[.]147/Payload.exe`, `hxxp://203[.]159[.]90[.]147/Backdoor.exe`) are already recorded in the feed's network indicators.

**Retired — duplicate SIEM/EDR queries superseded by the Sigma rules above.** The original file included four Splunk SPL queries, four Microsoft Sentinel/Defender KQL queries, and three PowerShell hunting scripts targeting the same techniques already covered by the Sigma rules in this file. Per the project's third-party-intelligence-provider standard, organization-specific SIEM query syntax and interactive PowerShell response scripts are not carried forward into a published, vendor-neutral detection file. Disposition of each:
- SPL "Remcos File Presence" (FileCreate at the install path) and KQL "Remcos Mutex Detection" (also path-based, not mutex, despite its title) — duplicate the retiered "Remcos RAT Execution from Default AppData Install Path" Sigma rule; retired.
- SPL "UAC Disable Command" — a looser wildcard subset of the "UAC Bypass via EnableLUA" process-creation Sigma rule; retired.
- SPL "Userinit Registry Modification" and KQL "Userinit Hijack Detection" — functionally identical to the "Winlogon Userinit Persistence" Sigma rule; retired.
- SPL "Process Injection Sequence" — a subset of the "Suspicious Process Access from AppData" Sigma rule (missing its `GrantedAccess` refinement); retired.
- KQL "UAC Bypass Detection" (registry-state view, `DeviceRegistryEvents`) — genuinely complementary (catches the technique regardless of which process performs the write); reformatted into the new "EnableLUA Registry Value Set to Disable User Account Control" Sigma rule above rather than retired.
- KQL "Remcos Network Connections" — duplicate pure-IP atomic, already covered by the IOC feed; retired.
- PowerShell scripts "Hunt for Remcos Mutex," "Hunt for UAC Disabled," and "Hunt for Userinit Hijack" — interactive, organization-specific incident-response scripts rather than detection content; each technique they check is already covered by a Sigma rule above. Retired.
- Cisco ASA / iptables / Windows Firewall block-rule syntax for `203.159.90.147` — vendor-specific configuration syntax, not detection content, and duplicative of the IP already carried in the IOC feed with a block recommendation. Retired.

**Mutex-based detection has no standard SIEM/EDR log-based equivalent.** `Remcos_Mutex_Inj` is the strongest single indicator in this campaign, but standard Sysmon/EDR process telemetry does not log mutex creation — this is why the original "mutex detection" Sigma rule (and the analogous KQL query) never actually implemented mutex matching despite their titles, and why the mutex's Detection-tier coverage in this file is carried entirely by the YARA rules (file/memory scanning) rather than a Sigma rule. **What would enable a Sigma rule:** EDR-native mutex-enumeration telemetry (where the EDR platform exposes named-object creation as a loggable event), which standard Sysmon does not provide.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
