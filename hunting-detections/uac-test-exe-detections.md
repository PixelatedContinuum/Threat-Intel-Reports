---
title: "Detection Rules — uac_test.exe (UAC Bypass PoC)"
date: '2026-01-12'
layout: post
permalink: /hunting-detections/uac-test-exe-detections/
hide: true
redirect_from: /hunting-detections/uac-test-exe/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/uac-test-exe.json

---

## Detection Coverage Summary

uac_test.exe is a Rust-compiled Windows privilege-escalation proof-of-concept tool recovered from the same open-directory infrastructure at `109.230.231.37` that hosted the PoetRAT-attributed agent.exe and multiple XWorm/FleetAgent RAT variants documented elsewhere in this campaign. Unlike those samples, uac_test.exe carries no persistence mechanism, command-and-control channel, or data-collection capability. It implements two publicly documented User Account Control (UAC) bypass techniques, CMSTPLUA COM interface abuse and Fodhelper registry hijacking, and gates its own bypass routine behind a check for existing administrative privileges: the bypass logic is skipped entirely when the process already holds an elevated token. Its self-narrating console output and its lack of anti-analysis beyond standard compiler defaults are consistent with a security-testing or demonstration build rather than a weaponized dropper, though its presence alongside the RAT variants at the same distribution point keeps it in scope for this campaign's coverage.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive recompilation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. CMSTPLUA and Fodhelper UAC bypass are heavily documented technique classes, so several rules here are deliberately technique-level rather than sample-specific. They are expected to also fire on other tools implementing the same two bypass methods, which is the correct behavior for a signature anchored on something the operator cannot rename or recompile away.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 2 | T1548.002, T1033 | 0 |
| Sigma | 3 | 1 | T1548.002 | 0 |
| Suricata | 0 | 0 | — | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the distribution IP (`109.230.231.37`) and the sample's SHA-256/MD5/SHA-1 hashes were already present in [`uac-test-exe.json`](/ioc-feeds/uac-test-exe.json) before this retiering pass. The two IP-match Suricata signatures added no detection value beyond the feed's IP entry and have been retired; the file hash remains available as a fast-path exact-match branch inside the YARA multi-signal combination rule below, alongside its behavioral logic. See Coverage Gaps for the full reasoning on every retired rule.

---

## YARA Rules

### Detection Rules

#### Generic CMSTPLUA/Fodhelper UAC Bypass Technique Combination

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** Anchors on the OS-level constants the two bypass techniques cannot avoid touching: the ICMLuaUtil/CMSTPLUA interface CLSID (`{6EDD6D74-C007-4E75-B76A-E5740995E24C}`), the CMLUAUTIL and ColorDataProxy elevation CLSIDs, and the Fodhelper `ms-settings\shell\open\command` registry path, each combined with generic supporting COM/registry API or filename strings that widen scope without weakening the anchor. None of these strings are the operator's to choose; abandoning them means abandoning the technique itself, so the rule survives a full recompile or rename of the tool. It is deliberately technique-level rather than sample-specific and is expected to also match other tools implementing the same two bypass methods.
**False Positives:** None known for unrelated software: these GUIDs and the Fodhelper registry path are not expected to appear in benign applications. The rule fires on any tool implementing the same two bypass techniques (other proof-of-concept tools, red-team frameworks, or malware), which is the intended technique-level behavior, not a false positive. Goodware-corpus validation has not been run against this rule; treat as a manual-review precondition before enabling automated blocking.
**Blind Spots:** A bypass implementation using a different, less-documented technique (neither CMSTPLUA nor Fodhelper) evades entirely. The rule inspects on-disk/in-memory strings, not obfuscated or packed variants that encrypt these constants.
**Validation:** Scan a binary embedding the CMSTPLUA CLSID or the Fodhelper registry path alongside the matching COM/registry API calls, must match; an unrelated application that merely references Windows Settings or makes registry API calls without the bypass-specific CLSID/path must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, email gateway attachment scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved 109.230.231.37.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-109.230.231.37-Malware-Repository
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule HKTOOL_UAC_Bypass_CMSTPLUA_Fodhelper_Generic {
   meta:
      description = "Detects generic CMSTPLUA COM interface abuse and Fodhelper registry hijacking UAC bypass techniques via the OS-level CLSIDs and registry path the techniques require, combined with supporting COM/registry API or filename strings. Technique-level: also matches other tools implementing the same two bypass methods, not only uac_test.exe."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/"
      date = "2026-01-12"
      family = "UAC-Bypass-PoC"
      malware_type = "UAC-Bypass-Tool"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "08c799ca-815c-441d-ae91-fe745f4bac6e"
   strings:
      $cmstplua_clsid = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase

      $fodhelper_reg1 = "ms-settings\\shell\\open\\command" ascii wide nocase
      $fodhelper_reg2 = "Software\\Classes\\ms-settings" ascii wide nocase

      $bypass_clsid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" nocase
      $bypass_clsid2 = "{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}" nocase

      $exe_fodhelper = "fodhelper.exe" ascii wide nocase
      $exe_slui = "slui.exe" ascii wide nocase

      $reg_api1 = "RegCreateKeyEx" ascii wide
      $reg_api2 = "RegSetValueEx" ascii wide
      $reg_api3 = "RegOpenKeyEx" ascii wide

      $com_api1 = "CoGetObject" ascii wide
      $com_api2 = "CoCreateInstance" ascii wide
      $com_api3 = "CoInitializeEx" ascii wide

   condition:
      uint16(0) == 0x5A4D and
      (
         ($cmstplua_clsid and (1 of ($com_api*))) or
         (($fodhelper_reg1 or $fodhelper_reg2) and (1 of ($reg_api*))) or
         ((1 of ($bypass_clsid*)) and (1 of ($exe_*)) and (1 of ($reg_api*)))
      )
}
```

### Hunting Rules

#### uac_test.exe Comprehensive Multi-Signal Combination (Hash Match or Behavioral Combination)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** MODERATE
**Rationale:** Every non-hash branch pairs a genuine technique anchor (the CMSTPLUA CLSID, the Fodhelper registry path, or the CMSTPLUA elevation moniker) with two or more of this build's own console/status strings (`$msg_*`, `$com_*`): the transparent, human-readable narration this tool prints at each step ("[+] COM bypass executed!", "[*] Calling CoGetObject with elevation moniker..."). That narration is a hallmark of a demonstration/test build, not of a weaponized tool, and it is exactly the kind of literal an operator drops when hardening a build for real use. Strip the print statements and every behavioral branch here stops firing, leaving only the exact-hash fast path. The Rust compiler-artifact strings (`$rust_lib*`) add no bypass-specific signal of their own; they only confirm the binary is Rust-compiled. Kept at Hunting rather than Cut because the multi-signal combination remains a real, low-noise lead for recurrence of this exact tool or a close derivative that retains its console output.
**False Positives:** None known for the hash-match branch (exact-file equality). The behavioral branches require a technique-specific CLSID/registry-path literal to co-occur with this build's own status-message text, which is not expected in unrelated software; residual risk is limited to a close rebuild of this same PoC that keeps its console output.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares, IR artifact triage on hosts that resolved 109.230.231.37.

```yara
rule HKTOOL_UAC_Test_PoC_Comprehensive {
   meta:
      description = "Detects uac_test.exe and close derivatives via exact hash match or a multi-signal combination of CMSTPLUA/Fodhelper bypass technique anchors, this build's own console/status-message strings, and Rust compilation artifacts. The status-message dependency means a rebuild with console output stripped defeats every behavioral branch; see Coverage Gaps."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/"
      date = "2026-01-12"
      family = "UAC-Bypass-PoC"
      malware_type = "UAC-Bypass-Tool"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "b20d328c-f9af-47fa-acb3-e3ad6d28b130"
      hash1 = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
   strings:
      $hash = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760" nocase

      $clsid_cmstplua = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase
      $elevation_moniker = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase

      $reg_fodhelper = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide nocase

      $msg_uac_test = "UAC Bypass Test - Rust Implementation" ascii
      $msg_admin_already = "[+] Already running as administrator!" ascii
      $msg_no_bypass = "[+] No UAC bypass needed." ascii
      $msg_com_bypass = "[+] COM bypass executed!" ascii
      $msg_com_attempt = "[1] Testing COM-based UAC Bypass (CMSTPLUA)" ascii
      $msg_reg_bypass = "[+] Registry bypass triggered!" ascii
      $msg_reg_attempt = "[2] Testing Registry-based UAC Bypass (fodhelper)" ascii
      $msg_com_success = "[+] *** COM UAC BYPASS SUCCESS! ***" ascii
      $msg_reg_success = "[+] *** REGISTRY UAC BYPASS SUCCESS! ***" ascii

      $com_init = "[*] Initializing COM..." ascii
      $com_moniker = "[*] Creating elevation moniker..." ascii
      $com_cogetobject = "[*] Calling CoGetObject with elevation moniker..." ascii
      $com_interface = "[+] Got ICMLuaUtil interface!" ascii
      $com_shellexec = "[*] Calling ShellExec to run elevated command..." ascii

      $rust_lib1 = "library\\alloc\\src\\string.rs" ascii
      $rust_lib2 = "library\\core\\src\\slice\\memchr.rs" ascii
      $rust_lib3 = "/rustc/" ascii
      $rust_lib4 = "library\\std\\src\\panicking.rs" ascii

      $token1 = "CheckTokenMembership" ascii wide
      $token2 = "AllocateAndInitializeSid" ascii wide
      $token3 = "FreeSid" ascii wide

   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         $hash or
         (
            ($clsid_cmstplua and ($elevation_moniker or $com_init or $com_moniker)) and
            (2 of ($msg_*)) and
            (1 of ($rust_lib*))
         ) or
         (
            ($reg_fodhelper) and
            (2 of ($msg_*)) and
            (1 of ($rust_lib*))
         ) or
         (
            (4 of ($msg_*)) and
            (2 of ($rust_lib*)) and
            (1 of ($token*))
         ) or
         (
            ($clsid_cmstplua or $elevation_moniker) and
            (3 of ($com_*)) and
            (2 of ($msg_*))
         )
      )
}
```

#### Rust-Compiled UAC Bypass Tool (Generic Capability Combination)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control), T1033 (System Owner/User Discovery)
**Confidence:** LOW
**Rationale:** The technique-anchored branch (Rust artifacts plus the CMSTPLUA CLSID or Fodhelper registry path) is durable but is a Rust-scoped subset of the Detection-tier rule above: it adds coverage only for the case where the sample happens to be Rust-compiled. The second branch (two of "UAC", "elevation", "administrator", "bypass", case-insensitive, plus one privilege-check API) has no comparable anchor. Those four words are common in legitimate Windows administration, installer, and permissions-management tooling, and `CheckTokenMembership`/`GetTokenInformation`/`OpenProcessToken` are standard APIs for any program that checks its own privilege level. That branch alone would be a magnet for unrelated Rust software that merely discusses administrator rights, which caps the whole rule at Hunting.
**False Positives:** Expected against legitimate Rust-compiled Windows tooling that checks or discusses administrative privileges (installers, permission managers, admin-rights diagnostic utilities) without implementing an actual bypass; analyst review of the specific binary is required before treating a hit as malicious.
**Deployment:** Broad endpoint/EDR scanning sweep, retroactive hunt across file shares; treat hits as triage candidates, not alerts.

```yara
rule HKTOOL_Rust_Compiled_UAC_Bypass {
   meta:
      description = "Detects Rust-compiled UAC bypass tools via Rust runtime/compiler artifacts combined with either the CMSTPLUA/Fodhelper technique anchors or a broader combination of UAC/elevation/administrator/bypass terminology and privilege-check APIs. The generic-terminology branch is common in legitimate Rust admin tooling; expect co-fire with benign software. Not for alerting."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/"
      date = "2026-01-12"
      family = "UAC-Bypass-PoC"
      malware_type = "UAC-Bypass-Tool"
      campaign = "Arsenal-237-109.230.231.37-Malware-Repository"
      id = "999a63f6-e957-406a-8752-f44887e4d579"
   strings:
      $rust1 = "/rustc/" ascii
      $rust2 = "library\\core\\src" ascii
      $rust3 = "library\\alloc\\src" ascii
      $rust4 = "library\\std\\src" ascii
      $rust5 = "rust_panic" ascii
      $rust6 = "std::panicking" ascii

      $uac1 = "UAC" nocase
      $uac2 = "elevation" nocase
      $uac3 = "administrator" nocase
      $uac4 = "bypass" nocase

      $bypass_clsid = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase
      $bypass_reg = "ms-settings\\shell\\open\\command" ascii wide nocase

      $priv_api1 = "CheckTokenMembership" ascii wide
      $priv_api2 = "GetTokenInformation" ascii wide
      $priv_api3 = "OpenProcessToken" ascii wide

   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      (2 of ($rust*)) and
      (
         ($bypass_clsid or $bypass_reg) or
         ((2 of ($uac*)) and (1 of ($priv_api*)))
      )
}
```

---

## Sigma Rules

### Detection Rules

#### UAC Bypass via Fodhelper Registry Hijacking

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** `HKCU\Software\Classes\ms-settings\shell\open\command` is the exact registry key the Fodhelper hijack technique depends on: fodhelper.exe checks this key on launch and executes whatever `DelegateExecute`/default value it finds there without a UAC prompt. An attacker cannot rename or relocate this key and still be exploiting the Fodhelper technique, so the selector survives any rebuild of the tool creating it. The filter excludes the two legitimate writers of this key (fodhelper.exe itself, and the Settings app), leaving only third-party writers as a strong, low-noise indicator.
**False Positives:** Legitimate system administration or registry-cleanup tooling that touches this exact key (extremely rare); legitimate Windows Settings application activity is excluded by the filter.
**Blind Spots:** Misses UAC bypass techniques that don't use this specific registry key (for example CMSTPLUA, sdclt, eventvwr, or other UACME-catalogued methods). Requires registry-event telemetry (Sysmon Event ID 13 or equivalent).
**Validation:** Trigger creation of a `DelegateExecute` or default value under this exact key from a non-fodhelper/non-SystemSettings process, must match; a Windows Settings application writing its own legitimate configuration under this key must NOT fire.
**Deployment:** Windows registry auditing, Sysmon Event ID 13, EDR registry-event telemetry.

```yaml
title: UAC Bypass via Fodhelper Registry Hijacking
id: 9a2c5b8f-3d1e-4f5a-8c9b-1a2d3e4f5a6b
status: experimental
description: >-
  Detects creation of registry keys under HKCU\Software\Classes\ms-settings\shell\open\command,
  the exact key the Fodhelper UAC bypass technique hijacks. fodhelper.exe reads this key on
  launch and executes its DelegateExecute/default value at the caller's already-elevated
  integrity level, without a UAC prompt. A write to this key from any process other than
  fodhelper.exe or the Settings app itself is a strong indicator of this technique in use.
references:
  - https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1548.002
  - detection.emerging-threats
logsource:
  category: registry_event
  product: windows
  definition: 'Sysmon Event ID 13 (Registry Value Set)'
detection:
  selection:
    TargetObject|contains: '\Software\Classes\ms-settings\shell\open\command'
  filter_legitimate:
    Image|endswith:
      - '\fodhelper.exe'
      - '\SystemSettings.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate system administration or registry cleanup tools (extremely rare)
  - Windows Settings application legitimate use
level: high
```

#### UAC Bypass via CMSTPLUA COM Interface CLSID in Process Command Line

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** *Retiering split:* the source rule OR'd this narrow, durable CLSID-in-CommandLine selector together with a broad `ParentImage: DllHost.exe` plus `IntegrityLevel: High` selector under one `level: high` rule. Scored as written (the tie-breaker rule is to score the logic, not the title), that combined OR condition inherited the weaker branch's precision: DllHost.exe legitimately spawns numerous elevated COM consumers, including some Windows Update components, which the rule's own false-positive note already conceded. Splitting preserves both ideas at their honest tier instead of overclaiming the broad branch or discarding the narrow one. This half keeps the CMSTPLUA interface CLSID (`{6EDD6D74-C007-4E75-B76A-E5740995E24C}`), a constant the operator cannot change without abandoning the technique, isolated in the `CommandLine` field, where its presence indicates a script- or command-line-driven invocation of the same technique this file's YARA rules detect inside compiled binaries. The paired broad selector is retiered separately below as a Hunting rule.
**False Positives:** None known: this exact CLSID is not expected to appear in a legitimate process command line, since COM consumers normally resolve interfaces programmatically rather than passing raw CLSIDs as command-line text.
**Blind Spots:** Compiled-binary implementations of the CMSTPLUA bypass, including uac_test.exe itself (which invokes the interface from within its own code with no relevant command-line arguments), never surface the CLSID in `CommandLine` and are invisible to this rule. It is strongest against script- or one-liner-based implementations (for example PowerShell) of the same technique. Requires process command-line logging (Sysmon Event ID 1 or 4688 with command-line auditing enabled).
**Validation:** Trigger a process launch whose command line contains the literal CLSID string, must match; an unrelated process referencing a different CLSID must NOT fire.
**Deployment:** Sysmon process creation (Event ID 1), Windows Event ID 4688 with command-line auditing, EDR process telemetry.

```yaml
title: UAC Bypass via CMSTPLUA COM Interface CLSID in Process Command Line
id: 7b3c6d9e-4f2a-5e8b-9c1d-2a3e4f5a6b7c
status: experimental
description: >-
  Detects the CMSTPLUA/ICMLuaUtil interface CLSID ({6EDD6D74-C007-4E75-B76A-E5740995E24C})
  appearing literally in a process command line, characteristic of script- or one-liner-based
  invocations of the CMSTPLUA UAC bypass technique. Split from the source rule's broader
  DllHost.exe/IntegrityLevel selector, which is retiered separately as a Hunting rule; see
  Coverage Gaps.
references:
  - https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1548.002
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection_clsid:
    CommandLine|contains: '{6EDD6D74-C007-4E75-B76A-E5740995E24C}'
  condition: selection_clsid
falsepositives:
  - Legitimate COM-based elevation by trusted Windows components is not expected to pass this CLSID as literal command-line text (extremely rare).
level: high
```

#### Suspicious Child Process Spawned by fodhelper.exe

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** HIGH
**Rationale:** fodhelper.exe is a fixed Windows system binary; under normal operation it spawns only the Settings host processes listed in the filter. Any other child process is a direct behavioral consequence of the registry hijack itself, since fodhelper.exe reads the hijacked key and executes whatever it points to at its own elevated integrity, rather than a renameable artifact of any specific tool. The operator cannot avoid this parent/child relationship and still be exploiting this technique. Complements the registry-write rule above by covering the execution-time half of the same technique.
**False Positives:** Windows Settings application launching its own legitimate components (excluded by the filter).
**Blind Spots:** Requires process-creation telemetry with parent/child linkage (Sysmon Event ID 1). Covers only the Fodhelper technique, not CMSTPLUA or other bypass methods.
**Validation:** Trigger fodhelper.exe spawning any process other than SystemSettings.exe/SettingsPageHost.exe, must match; fodhelper.exe launching the Settings app normally must NOT fire.
**Deployment:** Sysmon process creation (Event ID 1), EDR process-ancestry telemetry.

```yaml
title: Suspicious Child Process Spawned by fodhelper.exe
id: 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: experimental
description: >-
  Detects fodhelper.exe spawning a child process other than the Settings host binaries it
  normally launches. fodhelper.exe reads HKCU\Software\Classes\ms-settings\shell\open\command
  and executes whatever it finds there at its own already-elevated integrity level; an
  unexpected child process is the execution-time signature of the Fodhelper UAC bypass.
references:
  - https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1548.002
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\fodhelper.exe'
  filter_legitimate:
    Image|endswith:
      - '\SystemSettings.exe'
      - '\SettingsPageHost.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Windows Settings application launching legitimate components
level: high
```

### Hunting Rules

#### DllHost.exe Spawning Process at High Integrity Level (Potential COM Elevation Abuse)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Confidence:** LOW
**Rationale:** *Retiering split, demoted from the source's `level: high`:* this selector, DllHost.exe as parent with the child process at High integrity and no further discriminator, is the broad half of the source's combined CMSTPLUA rule (see the Detection-tier CLSID rule above for the narrow half). DllHost.exe is a legitimate multi-purpose COM surrogate host; numerous benign elevated-COM scenarios, including some Windows Update components per the rule's own false-positive note, spawn children this way. Per the project's level-discipline tie-breaker, `high`/`critical` on a selector this broad is an inflated-confidence signal, not a metadata typo, and belongs at Hunting with a `medium` level and analyst review rather than automated alerting.
**False Positives:** Legitimate COM-based elevation by trusted Windows components; some Windows Update processes use this exact parent/integrity pattern.
**Deployment:** Sysmon process creation (Event ID 1) with integrity-level logging enabled; hunting sweep, not an alerting rule.

```yaml
title: DllHost.exe Spawning Process at High Integrity Level (Potential COM Elevation Abuse)
id: 09f06ca8-fc43-4c53-a868-3c65eaf85c11
status: experimental
description: >-
  Hunting selector for DllHost.exe spawning a child process at High integrity level, with no
  further discriminator. This is the broad half of the source rule's combined CMSTPLUA
  selector; the narrow, CLSID-anchored half is retiered separately as a Detection rule (see
  the Sigma Detection Rules above). DllHost.exe legitimately hosts numerous elevated COM
  scenarios; expect co-fire with benign activity, including some Windows Update components.
references:
  - https://the-hunters-ledger.com/hunting-detections/uac-test-exe-detections/
author: The Hunters Ledger
date: '2026-01-12'
tags:
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1548.002
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\DllHost.exe'
    IntegrityLevel: 'High'
  condition: selection
falsepositives:
  - Legitimate COM-based elevation by trusted Windows components
  - Some Windows update processes
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Sigma CMSTPLUA rule split (source Rule 2).** The source rule OR'd a narrow, CLSID-anchored `CommandLine` selector together with a broad `ParentImage: DllHost.exe` plus `IntegrityLevel: High` selector under one `level: high` rule. Scored as written, an OR condition inherits its weakest branch's precision, and the broad branch's own false-positive note already conceded it fires on "some Windows update processes." Split into a Detection-tier rule (the CLSID-in-CommandLine selector, which survives rename/rebuild) and a Hunting-tier rule (the DllHost/IntegrityLevel selector, demoted from `level: high` to `level: medium`); see both rules above for full reasoning.
- **Sigma "Suspicious Privilege Escalation Without UAC Consent" cut (source Rule 3).** See Cut Rules below.
- **Suricata "Connection to/from Known Malware Distribution IP" cut (source sids 1000001/1000002).** See Atomics Routed to the IOC Feed below.
- **YARA rule identifiers namespaced with the `HKTOOL_` prefix.** The source names (`UAC_Test_PoC_Comprehensive`, `Generic_UAC_Bypass_Behavior`, `Rust_Compiled_UAC_Bypass`) carried no project naming convention. Renamed with the `HKTOOL_` (hack-tool) prefix used across the project's YARA rule set for confirmed non-malicious security/pentest tooling, consistent with this sample's own HIGH-confidence classification as a proof-of-concept rather than weaponized malware. No string or condition logic was changed by the rename.
- **Unreferenced YARA strings dropped (source Rule 1).** `$antidebug1`, `$antidebug2`, and `$mem1` were defined in the source's `strings:` block but never referenced anywhere in `condition:`, dead weight with no effect on match behavior either way. Removed for clarity; this changes no detection logic.

### Cut Rules (genuine noise, not routed to the feed)

- **Sigma "Suspicious Privilege Escalation Without UAC Consent"** (source Rule 3, id `1c2d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f`): cut. The rule's `condition: selection_elevation and not selection_no_consent and not filter_system` attempts to fire when an EventID 4672 record occurs without a corresponding EventID 4103 record, but a single Sigma event-selection rule matches one event record at a time; `selection_no_consent` (EventID 4103) can never be true for a record that already matched `selection_elevation` (EventID 4672), since one record cannot carry two different EventIDs. `not selection_no_consent` is therefore always true whenever `selection_elevation` matches, a permanent no-op that silently reduces the rule to `selection_elevation and not filter_system`. Expressing "event A fired without a companion event B nearby" requires a Sigma correlation rule (temporal join), not a single selection block. Even setting the dead clause aside, the surviving selector (EventID 4672 with `SeDebugPrivilege` in the privilege list, excluding SYSTEM) is one of the most common baseline-noise events on Windows: any interactive administrator logon generates a 4672 event carrying SeDebugPrivilege, entirely independent of any UAC bypass activity. This is the Sigma checklist's "malware did a benign OS thing" pattern, and the rule's own false-positives list already concedes it fires on "scheduled tasks running with administrative privileges" and "legitimate administrative tools." Fails both durability (not actually keyed to the bypass technique) and precision (ubiquitous benign activity); not a routable atomic, since it is a behavioral logic rule, not an IOC.

### Atomics Routed to the IOC Feed

- **Suricata "Connection to/from Known Malware Distribution IP"** (source sids `1000001` and `1000002`, inbound/outbound pair): pure IP-match rules (`alert ip any any -> 109.230.231.37 any` and the reverse), no content or protocol anchor. Textbook Suricata Cut per the project checklist ("pure IP-match rules... belong in iprep/reputation/dataset, not a signature"). The IP is already present in `uac-test-exe.json` under `network_indicators.distribution_infrastructure.ip`.

### A Close Call: Why the Same CLSIDs Split Across Detection and Hunting

The CMSTPLUA and bypass CLSIDs anchor three different rules in this file at three different outcomes: a YARA Detection rule (bare CLSID plus a generic COM/registry API), a Sigma Detection rule (bare CLSID isolated in `CommandLine`), and, inside the YARA Hunting comprehensive rule, the same CLSID gated behind this build's own console strings. The distinguishing factor is never the CLSID itself; it is always what else the rule requires alongside it. A rule that keys on the CLSID plus generic, technique-adjacent supporting evidence (a COM API call, a registry API call) stays anchored on constants the operator cannot change. A rule that keys on the CLSID plus this specific build's narration text inherits that text's brittleness, since a rebuild with the console output stripped drops straight to the exact-hash fast path. This is expected and intentional: CMSTPLUA/Fodhelper UAC bypass is a heavily documented technique class (UACME alone catalogues dozens of variants), so the Detection-tier rules here are deliberately technique-level and will also fire on other tools implementing the same two methods. That is what a durable, rename-resistant signature is supposed to do, not a reason to withhold coverage.

### No Network Behavioral Signature Possible

uac_test.exe implements no network communication code path. Both of its bypass techniques and its own administrative-privilege gate operate entirely through local COM activation, registry, and token APIs; no socket, HTTP client, or DNS resolution calls are present in the binary. No protocol structure exists from which to build a Suricata signature. The only network-relevant artifact is the distribution point itself, already routed to the feed above.

### Tool Classification: Security-Testing Utility, Not Weaponized Malware

uac_test.exe's own privilege-check gate, which queries `CheckTokenMembership()` before attempting either bypass and skips the bypass routine entirely when the calling process already holds an administrative token, is logic a weaponized dropper has no reason to include: malware seeking privilege escalation does not first check whether escalation is unnecessary and quit if so. Combined with its plain-language console narration and the absence of any persistence, C2, or data-collection code, this supports a HIGH-confidence classification as a security-testing or demonstration tool rather than weaponized malware. That classification does not remove detection value: unauthorized execution of a UAC-bypass tool on a production host is itself a policy-relevant event regardless of the tool author's intent, and the Detection-tier rules in this file are technique-level, so they cover this sample, its close derivatives, and unrelated tools implementing the same two bypass methods equally.

### What Would Enable Stronger Coverage

- **Goodware corpus validation:** none of the rules in this file have been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition the project's YARA checklist sets for full Detection-tier confidence, particularly on the CLSID-anchored rules that are expected to also match unrelated tools implementing the same bypass techniques.
- **Command-line telemetry for compiled-binary CMSTPLUA invocations:** the Sigma CLSID-in-CommandLine rule is blind to compiled implementations, including this sample itself; a telemetry source that surfaces in-process COM activation arguments, not just the launching command line, would close that gap.
- **A captured weaponized/console-stripped derivative:** would confirm or refute the Hunting-tier rules' working assumption that a rebuild without status-message output defeats their behavioral branches.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
