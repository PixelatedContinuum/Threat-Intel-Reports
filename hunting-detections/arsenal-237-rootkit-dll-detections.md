---
title: "Detection Rules — rootkit.dll (Arsenal-237 Defense Evasion Framework)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-rootkit-dll-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-rootkit-dll/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-109.230.231.37-Malware-Repository
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-rootkit-dll.json

---

## Detection Coverage Summary

rootkit.dll is a 64-bit, Rust-compiled defense-evasion framework from the Arsenal-237 malware toolkit, recovered from the same open-directory exposure at `109.230.231.37` as the broader Arsenal-237 repository. Despite its filename, it is not a conventional rootkit: it combines BYOVD (Bring Your Own Vulnerable Driver) privilege escalation via a legitimately-signed Baidu driver (BdApiUtil64.sys), mass termination of more than 20 security products and analysis tools, Unicode-based file-hiding, and API hooking against endpoint security processes.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The rules that reach Detection anchor on the embedded driver's own identity — its real filename and hash, baked into a signed binary the operator cannot alter without breaking the exploit — and on the specific, hard-to-fake combination of many real security-vendor process names appearing together in one file. Two Sigma rules did not survive as originally written: a file-system-stealth selector checked a process `Image` field for a DLL name that can never appear there in real telemetry (a loaded DLL is never its own process image), and a PowerShell-integration rule's over-broad OR condition let it fire on ubiquitous, unrelated PowerShell automation flags with no tie to this campaign — that branch has produced false positives in production deployments. Both are detailed in Coverage Gaps, alongside a salvage that recovered a stronger process-access rule by dropping its own broken source-process clause.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1068, T1685, T1055.001, T1564.001, T1055 | 0 |
| Sigma | 2 | 2 | T1068, T1055.001, T1685, T1059.001 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** rootkit.dll's own hash triad and the BdApiUtil64.sys driver's hash triad were already present in [`arsenal-237-rootkit-dll.json`](/ioc-feeds/arsenal-237-rootkit-dll.json) before this retiering pass. This pass identified no new standalone atomics to route — the fully-cut rule (file-system stealth) failed on broken selector logic rather than being a disguised IOC, and the cut half of the PowerShell rule is a set of generic command-line flags, not an indicator.

---

## YARA Rules

### Detection Rules

#### BYOVD Baidu Driver Embedding

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** Every branch requires the embedded driver's own identity strings — `BdApiUtil64.sys`/`BdApiUtil`, its native registry service path, or its IOCTL structure — extracted from a legitimately-signed third-party driver bundled inside the sample. These strings are baked into the driver's own compiled identity; the operator cannot alter them without breaking the exploit or invalidating the code signature, so the rule survives dropper renaming and infrastructure rotation. One branch (`$driver_signature`, a generic DOS-stub byte pattern) is decorative rather than discriminating — it is always paired with a real driver-name string, so it does not weaken precision, but it adds no detection value on its own.
**False Positives:** Legitimate Baidu software installations (rare in enterprise environments).
**Blind Spots:** Does not fire if a build embeds a different vulnerable driver instead of BdApiUtil64.sys, or if the driver's identity strings are stripped or encrypted before being written to disk.
**Validation:** Compiles clean with yarac; all anchors are ≥4-byte identity strings or hex patterns. No goodware-corpus sweep performed.

```yara
rule Arsenal237_BYOVD_Baidu_Driver
{
    meta:
        description = "Detects embedded BdApiUtil64.sys driver for BYOVD attacks"
        author = "The Hunters Ledger"
        date = "2026-01-26"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/"
        severity = "critical"
        mitre_attack = "T1068"

    strings:
        $driver_name_1 = "BdApiUtil64.sys" wide ascii
        $driver_name_2 = "BdApiUtil" wide ascii
        $baidu_company = "Baidu" wide ascii nocase
        $driver_signature = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }

        // Driver service registry paths
        $reg_service_1 = "SYSTEM\\CurrentControlSet\\Services\\BdApiUtil" wide
        $reg_service_2 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" wide

        // IOCTL codes for driver communication
        $ioctl_pattern = { 44 ?? ?? ?? ?? 00 22 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($driver_name_*) and $baidu_company) or
            ($driver_signature and 1 of ($driver_name_*)) or
            (1 of ($reg_service_*) and 1 of ($driver_name_*)) or
            ($ioctl_pattern and 1 of ($driver_name_*))
        )
}
```

#### Multi-Vendor Security Product Kill-List

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** Each branch requires a broad, multi-vendor spread of real security-product process names — for example 5+ Defender names AND 3+ CrowdStrike names AND 3+ third-party AV names together in one file. These are the actual vendor executable names, not attacker-chosen literals — the operator cannot rename them without losing the ability to target the real processes, so the artifact is durable even though each individual string is a plain filename. Legitimate software has no reason to embed this many distinct security-vendor process names together.
**False Positives:** Legitimate security product updates or uninstallations; system administrator maintenance activities. The single-vendor-deep branch (8+ of one vendor's own process family plus a termination API) has a narrow plausible overlap with that vendor's own repair/update tooling, which is why this sits at `high` rather than `critical`.
**Blind Spots:** Does not fire against a narrowly-targeted killer that terminates fewer than the required breadth/depth thresholds, or one that resolves target processes dynamically rather than embedding their names as strings.
**Validation:** Compiles clean with yarac; all string anchors are ≥4-byte vendor process names. No goodware-corpus sweep performed.

```yara
rule Arsenal237_Security_Product_Killer
{
    meta:
        description = "Detects mass security product termination behavior"
        author = "The Hunters Ledger"
        date = "2026-01-26"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/"
        severity = "high"
        mitre_attack = "T1685"

    strings:
        // Microsoft Defender complete process list
        $def_1 = "MsMpEng.exe" wide ascii nocase
        $def_2 = "MpCmdRun.exe" wide ascii nocase
        $def_3 = "NisSrv.exe" wide ascii nocase
        $def_4 = "SecurityHealthService.exe" wide ascii nocase
        $def_5 = "smartscreen.exe" wide ascii nocase
        $def_6 = "SgrmBroker.exe" wide ascii nocase
        $def_7 = "MpSigStub.exe" wide ascii nocase
        $def_8 = "wscsvc.exe" wide ascii nocase
        $def_9 = "WdNisDrv.sys" wide ascii nocase
        $def_10 = "WdFilter.sys" wide ascii nocase

        // CrowdStrike complete process list
        $cs_1 = "CSFalconService.exe" wide ascii nocase
        $cs_2 = "CSFalconContainer.exe" wide ascii nocase
        $cs_3 = "CSAgent.exe" wide ascii nocase
        $cs_4 = "csagent.sys" wide ascii nocase
        $cs_5 = "CSDeviceControl.exe" wide ascii nocase
        $cs_6 = "CSNamedPipeProxy.exe" wide ascii nocase

        // Third-party AV products
        $av_1 = "ekrn.exe" wide ascii nocase          // ESET
        $av_2 = "avp.exe" wide ascii nocase            // Kaspersky
        $av_3 = "MBAMService.exe" wide ascii nocase    // Malwarebytes
        $av_4 = "ccSvcHst.exe" wide ascii nocase       // Symantec
        $av_5 = "WRSA.exe" wide ascii nocase           // Webroot
        $av_6 = "SophosHealth.exe" wide ascii nocase   // Sophos
        $av_7 = "CylanceSvc.exe" wide ascii nocase     // Cylance
        $av_8 = "SentinelAgent.exe" wide ascii nocase  // Sentinel One

        // Termination APIs
        $api_1 = "ZwTerminateProcess" ascii
        $api_2 = "TerminateProcess" ascii
        $api_3 = "NtTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // High confidence: Multiple vendor targets
            (5 of ($def_*) and 3 of ($cs_*) and 3 of ($av_*)) or

            // Medium confidence: One vendor complete + APIs
            ((8 of ($def_*) or 4 of ($cs_*)) and 1 of ($api_*)) or

            // Broad targeting across vendors
            (3 of ($def_*) and 2 of ($cs_*) and 4 of ($av_*) and 1 of ($api_*))
        )
}
```

### Hunting Rules

#### Comprehensive Multi-Branch Combination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation), T1685 (Disable or Modify Tools), T1055.001 (DLL Injection), T1564.001 (Hidden Files and Directories)
**Confidence:** MODERATE
**Rationale:** This rule unions the logic of the other three YARA rules plus two weaker branches: an analysis-tool-naming branch (3 of procexp.exe/procmon.exe/Wireshark.exe/x64dbg.exe/volatility.exe) and a hex-prologue-plus-API branch whose function patterns are common MSVC compiler prologues and whose APIs (OpenProcess, CreateThread) are near-universal in legitimate software. Because any single branch firing satisfies the whole rule, its overall precision is capped by its weakest branch rather than its strongest, which is why it sits below its narrower siblings despite covering the same ground.
**False Positives:** Software bundling references to multiple analysis/debugging tools (IT asset-inventory or compatibility-checking tools); generic process-manipulation software matching the function-pattern-plus-API branch.
**Deployment note:** Broad scanning sweep; treat hits as triage candidates alongside the narrower Detection-tier rules above, not as a standalone alert.

```yara
rule Arsenal237_Rootkit_DLL_Comprehensive
{
    meta:
        description = "Detects Arsenal-237 rootkit.dll defense evasion framework"
        author = "The Hunters Ledger"
        date = "2026-01-26"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/"
        hash_md5 = "674795d4d4ec09372904704633ea0d86"
        hash_sha1 = "483feeb4e391ae64a7d54637ea71d43a17d83c71"
        hash_sha256 = "e71240f26af1052172b5864cdddb78fcb990d7a96d53b7d22d19f5dfccdf9012"
        severity = "medium"
        mitre_attack = "T1068, T1685, T1055.001, T1564.001"

    strings:
        // Rust runtime signatures
        $rust_panic = "panicked at" ascii
        $rust_runtime = "std::panicking::rust_panic" ascii
        $rust_thread = "std::thread::Builder" ascii

        // Embedded Baidu driver indicators
        $baidu_driver_1 = "BdApiUtil64.sys" wide ascii
        $baidu_driver_2 = "Baidu" wide ascii nocase

        // Security product process targets (Microsoft Defender)
        $defender_1 = "MsMpEng.exe" wide ascii nocase
        $defender_2 = "MpCmdRun.exe" wide ascii nocase
        $defender_3 = "SecurityHealthService.exe" wide ascii nocase
        $defender_4 = "WdNisDrv.sys" wide ascii nocase
        $defender_5 = "WdFilter.sys" wide ascii nocase

        // CrowdStrike targets
        $crowdstrike_1 = "CSFalconService.exe" wide ascii nocase
        $crowdstrike_2 = "CSFalconContainer.exe" wide ascii nocase
        $crowdstrike_3 = "csagent.sys" wide ascii nocase

        // Third-party AV targets
        $av_eset = "ekrn.exe" wide ascii nocase
        $av_kaspersky = "avp.exe" wide ascii nocase
        $av_malwarebytes = "MBAMService.exe" wide ascii nocase
        $av_symantec = "ccSvcHst.exe" wide ascii nocase
        $av_webroot = "WRSA.exe" wide ascii nocase
        $av_sophos = "SophosHealth.exe" wide ascii nocase
        $av_cylance = "CylanceSvc.exe" wide ascii nocase
        $av_sentinel = "SentinelAgent.exe" wide ascii nocase

        // Analysis tool targets
        $analysis_1 = "procexp.exe" wide ascii nocase
        $analysis_2 = "procmon.exe" wide ascii nocase
        $analysis_3 = "Wireshark.exe" wide ascii nocase
        $analysis_4 = "x64dbg.exe" wide ascii nocase
        $analysis_5 = "volatility.exe" wide ascii nocase

        // Core defense evasion functions (hex patterns)
        $func_dispatcher = { 48 83 EC 28 48 8B ?? 48 8B ?? 48 8B ?? 48 85 ?? 74 ?? FF D? }
        $func_thread_create = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B D9 }

        // API imports for defense evasion
        $api_terminate = "ZwTerminateProcess" ascii
        $api_openprocess = "OpenProcess" ascii
        $api_createthread = "CreateThread" ascii
        $api_loaddriver = "ZwLoadDriver" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Strong Rust + BYOVD signature
            (2 of ($rust_*) and 1 of ($baidu_*)) or

            // Multiple security product targets
            (6 of ($defender_*, $crowdstrike_*, $av_*)) or

            // Analysis tool targeting
            (3 of ($analysis_*)) or

            // Function patterns + API imports
            (1 of ($func_*) and 2 of ($api_*)) or

            // Comprehensive detection: Rust + targets + functions
            (1 of ($rust_*) and 3 of ($defender_*, $crowdstrike_*, $av_*) and 1 of ($func_*))
        )
}
```

#### Rust Runtime Plus Process-Manipulation APIs

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation), T1685 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** The source rule's third branch, `5 of ($rust_*)`, fired on Rust-runtime evidence alone — panic strings and allocator/thread symbols present in nearly every non-trivial Rust binary regardless of intent. That branch has been removed as a Retiering Fix (see Coverage Gaps): being Rust-compiled carries no malice signal by itself. The two surviving branches still require Rust evidence to co-occur with process-manipulation or driver-loading APIs (OpenProcess, TerminateProcess, CreateRemoteThread, ZwLoadDriver), a real but broad combination — legitimate Rust-based system utilities and remote-administration tools can plausibly combine these.
**False Positives:** Legitimate Rust-compiled software performing process management, monitoring, or driver interaction (system utilities, some anti-cheat or endpoint agents).
**Deployment note:** Broad scanning sweep; treat hits as triage candidates requiring analyst review of the specific binary's provenance.

```yara
rule Arsenal237_Rust_Compiled_Malware
{
    meta:
        description = "Detects Rust-compiled executables combining runtime evidence with process-manipulation or driver-loading APIs -- a broad toolkit-family heuristic, not specific to any one Arsenal-237 capability"
        author = "The Hunters Ledger"
        date = "2026-01-26"
        reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/"
        severity = "medium"
        mitre_attack = "T1055, T1068, T1685"

    strings:
        $rust_panic = "panicked at" ascii
        $rust_runtime_1 = "std::panicking::rust_panic" ascii
        $rust_runtime_2 = "std::panicking::begin_panic" ascii
        $rust_thread_1 = "std::thread::Builder" ascii
        $rust_thread_2 = "std::thread::spawn" ascii
        $rust_alloc = "alloc::alloc::Global" ascii
        $rust_vec = "alloc::vec::Vec" ascii

        // Cargo/rustc metadata
        $cargo_metadata = ".cargo" ascii
        $rustc_version = "rustc" ascii

        // Suspicious combinations
        $suspicious_1 = "OpenProcess" ascii
        $suspicious_2 = "TerminateProcess" ascii
        $suspicious_3 = "CreateRemoteThread" ascii
        $suspicious_4 = "ZwLoadDriver" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Rust signatures + suspicious APIs
            (3 of ($rust_*) and 2 of ($suspicious_*)) or

            // Cargo metadata + malicious APIs
            ($cargo_metadata and $rustc_version and 2 of ($suspicious_*))
        )
}
```

---

## Sigma Rules

### Detection Rules

#### BdApiUtil64.sys BYOVD Driver Loading

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1068 (Exploitation for Privilege Escalation)
**Confidence:** HIGH
**Rationale:** Matches a real driver-load event against the vulnerable driver's own filename or its file-hash triad. Both anchors are baked into a legitimately-signed third-party binary — the operator cannot change the hash without recompiling a different (unsigned, non-functional-for-this-exploit) driver, and the filename is the driver's own native identity. This is a known LOLDriver; loading it by its true name or hash is the technique's actual chokepoint, not an attacker-chosen artifact.
**False Positives:** Legitimate Baidu software installations (rare in enterprise environments).
**Blind Spots:** Requires driver-load telemetry (Sysmon Event ID 6 or equivalent EDR driver-load logging) to be enabled. Does not fire if the operator substitutes a different vulnerable driver.
**Validation:** Passes `sigma check` against the SigmaHQ validators; hash values verified against the corrected BdApiUtil64.sys hash triad.

```yaml
title: Arsenal-237 BdApiUtil64.sys BYOVD Driver Loading
id: a8c9d4e1-2f3b-4c5d-8e9f-1a2b3c4d5e6f
status: experimental
description: Detects loading of the BdApiUtil64.sys vulnerable driver used for BYOVD privilege escalation, matched on the driver's own filename or its file-hash triad.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/
author: The Hunters Ledger
date: 2026-01-26
tags:
    - attack.privilege-escalation
    - attack.t1068
    - detection.emerging-threats
logsource:
    product: windows
    category: driver_load
detection:
    selection_driver_name:
        ImageLoaded|contains:
            - 'BdApiUtil64.sys'
            - 'BdApiUtil.sys'
    selection_driver_hash:
        Hashes|contains:
            - 'MD5=ced47b89212f3260ebeb41682a4b95ec'
            - 'SHA1=148c0cde4f2ef807aea77d7368f00f4c519f47ef'
            - 'SHA256=47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428'
    condition: selection_driver_name or selection_driver_hash
falsepositives:
    - Legitimate Baidu software installations (rare in enterprise environments)
level: critical
```

#### High-Privilege Process Access to Security Product Processes

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055.001 (DLL Injection)
**Confidence:** HIGH
**Rationale:** Salvaged from the source "API Hooking from DLL Context" rule. The original also required `SourceImage|endswith: '\rootkit.dll'` — but a DLL is never its own process image in Sysmon/EDR telemetry (a loaded DLL shows up as the *hosting* EXE's image, never its own filename), so that clause could never match real telemetry and made the whole rule unfireable. Removing it and keeping the two genuinely durable clauses — a named security-product target plus a full-access or memory-write `GrantedAccess` mask — recovers a rule that is broader (not tied to one build's filename) and more durable (keyed on the actual technique chokepoint) than the original.
**False Positives:** Security software performing legitimate cross-process monitoring of other installed security products; interactive debugging of a security-product process by an analyst or developer.
**Blind Spots:** Requires process-access telemetry (Sysmon Event ID 10 or equivalent). Does not fire against access-rights masks outside the three listed values, or against injection techniques that avoid OpenProcess entirely (e.g., APC-only or thread-hijack primitives that request narrower access).
**Validation:** Passes `sigma check` against the SigmaHQ validators.

```yaml
title: High-Privilege Process Access to Security Product Processes
id: d2e3f4a5-6b7c-8d9e-0f1a-2b3c4d5e6f7a
status: experimental
description: Detects a process opening a handle to a named security-product process (Defender, CrowdStrike Falcon, ESET, Kaspersky) with full or memory-write access rights -- the access pattern that precedes API hooking or code injection into endpoint security software.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/
author: The Hunters Ledger
date: 2026-01-26
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055.001
    - detection.emerging-threats
logsource:
    product: windows
    category: process_access
detection:
    selection_target_security:
        TargetImage|endswith:
            - '\MsMpEng.exe'
            - '\CSFalconService.exe'
            - '\ekrn.exe'
            - '\avp.exe'
    selection_access:
        GrantedAccess:
            - '0x1F0FFF'
            - '0x1FFFFF'
            - '0x1010'
    condition: selection_target_security and selection_access
falsepositives:
    - Security software performing legitimate cross-process monitoring of other installed security products
    - Interactive debugging of a security-product process by an analyst or developer
level: high
```

### Hunting Rules

#### Security Product Process Termination

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** The source rule's intent was a volumetric threshold (3+ Defender, 2+ CrowdStrike, or 3+ third-party terminations within 60 seconds) — Sigma's single-event model cannot express that, so it fires on any one matching termination. The target list is durable (real vendor process names the operator cannot rename), but a single termination event alone has plausible benign explanations, so this is a scoping lead rather than an alert: review for co-occurring terminations of other vendors' processes on the same host in a short window before treating a hit as the mass-termination behavior this rule was built to catch.
**False Positives:** Legitimate security product updates or uninstallations; system administrator maintenance activities.
**Deployment note:** Pair with a correlation search (count by host.name over a short window) to recover the intended volumetric signal; see Coverage Gaps.

```yaml
title: Arsenal-237-Class Security Product Process Termination
id: b9d1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: >-
  Detects termination of a single named security-product process (Defender,
  CrowdStrike Falcon, or a third-party AV/EDR). Fires on any one matching
  termination event; review for co-occurring terminations of other vendors'
  processes on the same host in a short window before treating as a
  mass-termination incident.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/
author: The Hunters Ledger
date: 2026-01-26
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    product: windows
    category: process_termination
detection:
    selection_defender:
        Image|endswith:
            - '\MsMpEng.exe'
            - '\MpCmdRun.exe'
            - '\NisSrv.exe'
            - '\SecurityHealthService.exe'
    selection_crowdstrike:
        Image|endswith:
            - '\CSFalconService.exe'
            - '\CSFalconContainer.exe'
            - '\CSAgent.exe'
    selection_thirdparty:
        Image|endswith:
            - '\ekrn.exe'
            - '\avp.exe'
            - '\MBAMService.exe'
            - '\ccSvcHst.exe'
            - '\SophosHealth.exe'
    condition: selection_defender or selection_crowdstrike or selection_thirdparty
falsepositives:
    - Legitimate security product updates or uninstallations
    - System administrator maintenance activities
level: medium
```

#### PowerShell Execution with rootkit.dll on Parent Command Line

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** LOW
**Rationale:** The source rule combined two independently-triggering clauses via OR: a parent-command-line reference to rootkit.dll, or a set of common PowerShell obfuscation/automation flags (`-enc`, `-EncodedCommand`, `-w hidden`, `-WindowStyle Hidden`, `bypass`) with no requirement that they relate to rootkit.dll at all. That second branch matches ubiquitous, legitimate PowerShell deployment and automation activity industry-wide and has produced false positives in production deployments — it is cut here (see Coverage Gaps). The surviving parent-command-line clause is narrower and still tied to this campaign, but `rootkit.dll` is this build's own filename and can be renamed in a future build, so it remains a brittle, single-literal lead rather than a durable detector.
**False Positives:** Legitimate software or scripts that happen to reference a file literally named rootkit.dll on a PowerShell parent command line (not expected, but not impossible).
**Deployment note:** Scoping lead for this specific build family; a naming-convention change in a future build evades it entirely.

```yaml
title: PowerShell Execution with rootkit.dll on Parent Command Line
id: e3f4a5b6-7c8d-9e0f-1a2b-3c4d5e6f7a8b
status: experimental
description: >-
  Detects powershell.exe or pwsh.exe launched by a parent process whose command
  line references rootkit.dll. rootkit.dll is this build's own filename and can
  be renamed in a future build; treat this as a scoping lead for this specific
  build family, not a durable technique-level detector.
references:
    - https://the-hunters-ledger.com/hunting-detections/arsenal-237-rootkit-dll-detections/
author: The Hunters Ledger
date: 2026-01-26
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_parent:
        ParentCommandLine|contains: 'rootkit.dll'
    condition: selection_powershell and selection_parent
falsepositives:
    - Legitimate software or scripts that happen to reference a file literally named rootkit.dll on a PowerShell parent command line (not expected, but not impossible)
level: medium
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **YARA "Rust-Compiled Malware"** — removed the `(5 of ($rust_*))` branch, which fired on Rust-runtime evidence alone (panic strings, allocator/thread symbols present in nearly every non-trivial Rust binary). Being Rust-compiled carries no malice signal by itself; the two surviving branches still require Rust evidence plus process-manipulation or driver-loading APIs.
- **Sigma "API Hooking from DLL Context" → salvaged and promoted to Detection.** The original required `SourceImage|endswith: '\rootkit.dll'` — a DLL is never its own process image in Sysmon/EDR telemetry, so this clause could never fire on real activity. Removed it and kept the two genuinely durable clauses (named security-product target plus a full-access or memory-write `GrantedAccess` mask), which stand on their own as a stronger, more general rule. Retitled to reflect the generalized scope.
- **Sigma "PowerShell Integration"** — removed the `selection_suspicious` OR-branch (`-enc`, `-EncodedCommand`, `-w hidden`, `-WindowStyle Hidden`, `bypass`), which required no connection to rootkit.dll and matched ubiquitous legitimate PowerShell automation; this branch has produced false positives in production deployments. The narrower `selection_parent` branch (ParentCommandLine references rootkit.dll) survives as Hunting.
- **Sigma "Mass Security Product Termination"** — `level` recalibrated from `high` to `medium` to honestly reflect its single-event trigger and Hunting tier. Its `attack.t1685` / `attack.defense-impairment` tags were verified against the current ATT&CK dataset and kept as-is: `T1685` ("Disable or Modify Tools", tactic `defense-impairment`) is the current technique for this behavior, superseding the older `T1562.001` numbering — every rule in this file citing this behavior uses `T1685` accordingly.
- **YARA "Security Product Killer"** and all other rules touching this behavior — `mitre_attack` uses `T1685` (current), not the deprecated `T1562.001`/`T1089` numbering. `T1089` in particular no longer exists in the current ATT&CK dataset.
- **All reference fields** (YARA `reference =`, Sigma `references:`) repointed from prose or placeholder text to this page's own canonical URL, since no published report exists for this file.

### Cut Rules (genuine noise or broken logic — not routed to the feed)

- **Sigma "rootkit.dll File System Stealth Operations"** (id `2b2e6434-31f4-4d18-8077-a30ca4f77526`) — cut. `selection_dll` checked the file_event `Image` field for `\rootkit.dll`, but `Image` always reflects the launching EXE, never a loaded DLL's own filename — this clause could not fire on real telemetry. Independently, `selection_unicode` matched `TargetFilename` containing `\u`, `%u`, or `\x` — two-character substrings under any useful anchor length; `\u` alone matches almost any path under `C:\Users\...` (the substring "\Users" contains "\u"), making it close to universally true for ordinary per-user file activity. With one clause unfireable and the other near-tautological, no salvage preserves a working, non-noisy selector. Not a routable atomic — this is broken selector logic, not a disguised IOC. No dedicated Sigma rule covers this technique's Unicode file-hiding behavior; the YARA Comprehensive Hunting rule still carries a T1564.001 tag at the static-file level.
- **Sigma "PowerShell Integration" `selection_suspicious` branch** (part of id `e3f4a5b6-7c8d-9e0f-1a2b-3c4d5e6f7a8b`) — cut in place; the rule survives as Hunting on its remaining clause (see Sigma Hunting Rules above). The flags in this branch are standard in a large volume of legitimate IT automation, deployment, and scheduled-task tooling, entirely independent of rootkit.dll. Not a routable atomic — these are generic command-line flags, not indicators.

### Atomics Routed to the IOC Feed

No new atomics were identified in this retiering pass. rootkit.dll's own hash triad and the BdApiUtil64.sys hash triad were already present in `arsenal-237-rootkit-dll.json` prior to this pass.

**IOC feed hash discrepancy (flagged, not modified):** the BdApiUtil64.sys hash values in `arsenal-237-rootkit-dll.json` do not match the corrected hash triad carried in the driver-loading Sigma rule above (`ced47b89.../148c0cde.../47ec51b5...`). The feed's SHA256 value (`e3b0c442...`) is the well-known hash of an empty file, and its MD5/SHA1 values do not correspond to the real driver either. The feed file was not edited as part of this pass; this discrepancy should be corrected in a future IOC-feed maintenance pass.

### Capabilities Without Dedicated Rule Coverage

Registry-based security-policy tampering (T1112), the driver's Windows-service persistence as a live event rather than a static string (T1543.003), and thread-execution hijacking (T1055.003) are documented in the IOC feed's behavioral and registry indicators but have no dedicated event-level Sigma rule here. The BYOVD YARA rule provides static string-presence signal for the driver's service-registry path; live event-level coverage for service creation or registry modification was not built in this pass.

### Family and Toolkit Context

rootkit.dll is one component of the Arsenal-237 toolkit exposed via the open directory at `109.230.231.37`, alongside other components documented elsewhere in this campaign. Despite its filename, static evidence characterizes it as a defense-evasion framework rather than a traditional rootkit: BYOVD privilege escalation, mass security-tool termination, file-hiding, and API hooking, with no kernel-mode code of its own — the kernel-level capability comes entirely from the embedded, legitimately-signed third-party driver.

### What Would Enable Stronger Coverage

- **Volumetric correlation** for the Mass Termination Hunting rule — a Sigma correlation rule counting distinct vendor-family terminations per host within a short window would restore the source's intended multi-vendor, rapid-succession signal and would likely qualify for Detection tier. Not built in this pass, to keep the retiering scoped to the rules as submitted.
- **Goodware-corpus validation** — none of the YARA rules have been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition for reconsidering tier on any Hunting-tier rule here.
- **IOC feed hash correction** — see the discrepancy note above.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
