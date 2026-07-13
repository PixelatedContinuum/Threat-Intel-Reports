---
title: "Detection Rules — OpenStrike Expanded Toolkit (New Files 2026-04-08)"
date: '2026-04-08'
layout: post
permalink: /hunting-detections/new-files-found-20260408-detections/
thumbnail: /assets/images/cards/new-files-found-20260408.png
hide: true
---

**Campaign:** OpenStrike-CSBeacon-Toolkit-172.105.0.126
**Date:** 2026-04-08
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/new-files-found-20260408/

> **Scope note:** These rules cover **only new artifacts and behaviors** discovered in the April 8 expanded analysis of 106 additional files from the same open directory (172.105.0.126:8888). Rules for the originally published seven samples (beacon.exe gen-3, loader chain, Python beacon, CS 3.x tripwired DLL, MALC user-agent, 172.105.0.126:8443 C2 infrastructure) are in the companion file at `/hunting-detections/open-directory-172-105-0-126-20260406-detections/`. Do not deploy both files without deduplication review.

---

## Detection Coverage Summary

OpenStrike is a bespoke Cobalt Strike-derivative toolkit combining a custom-built beacon lineage (gen-1 through gen-4 prototypes), stock Cobalt Strike 3.x/4.4 beacon DLLs wrapped by five custom loaders, a Cobalt Strike Artifact Kit service variant performing EAX-redirect process hollowing, and a CovertVPN Layer 2 bridge module with an embedded WinPcap stack. Coverage here is re-tiered from the original April 8 publication to separate evasion-resilient, alerting-grade rules from broader hunting leads; several rules that keyed solely on a single renameable literal (a hardcoded drop path, a masquerading service name, a Malleable C2 user-agent string) have been retiered from Detection to Hunting even where false-positive risk is low today, because that low FP rate depends on the operator not changing a trivially-changeable value.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 1 | T1071.001, T1573.001, T1041, T1573.002, T1055.003, T1543.003, T1036.004, T1218.011, T1095, T1572, T1129, T1036.005 | 0 |
| Sigma | 2 | 6 | T1055.003, T1218.011, T1036.005, T1543.003, T1129, T1071.001, T1041, T1553.005 | 0 |
| Suricata | 0 | 5 | T1071.001, T1041, T1572, T1095 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The gen-4 beacon's banner string (`[*] OpenStrike Beacon starting...`) combined with its URI format strings and build artifacts, and the Artifact Kit `DceRpcSs`/`MSSE-%d-server` service+pipe combination — both survive a rebuild without source-level rework (YARA/Sigma Detection).
- The EAX-redirect hollowing behavioral pattern (bare `rundll32.exe` spawned by a service process) — a technique-level signature independent of any single sample (Sigma Detection).

**Retiered to Hunting (durability, not precision, is the limiter):** the DLL loader's hardcoded drop path (`C:\Windows\Temp\beacon.dll`), the `DceRpcSs` service name, the Malleable C2 `BOIE9;ENUSSEM` user-agent suffix, and the gen-4 beacon's `/updates`/`/submit` URI scheme are all distinctive today with near-zero false positives, but each is a single value an operator can change in a future build or profile edit without any infrastructure cost — durability, not current false-positive rate, is what caps these at Hunting per the site tiering rubric.

**Cut (routed to existing IOC feed, not re-added):** one Suricata signature matching the stager download URIs (`/au2U`, `/msI4`) scoped to `172.105.0.126:80` has been cut — both full URLs were already present in [`new-files-found-20260408-iocs.json`](/ioc-feeds/new-files-found-20260408-iocs.json) before this backfill, and the rule carried no behavioral content beyond that IP+path combination. No feed edits were required.

---

## YARA Rules

### Detection Rules

#### OpenStrike Gen-4 Beacon

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**Rationale:** The `/updates?id=%08x` and `/submit?id=%08x` URI format strings and the `[*] OpenStrike Beacon starting...` banner are unique to the gen-4 WinHTTP beacon rewrite and do not appear in any known legitimate software; the condition requires either the banner alone or both URI format strings together, plus one of four corroborating build/crypto artifacts. No single renameable literal carries the rule.
**False Positives:** None known — URI format strings with 8-hex-digit IDs and the OpenStrike banner string are specific to this beacon; `ChainingModeCBC` is a BCrypt mode string that does appear in other software but only functions here as corroboration alongside the primary URI/banner anchors.
**Blind Spots:** A full source-level rewrite of the URI scheme and removal of the startup banner would evade this rule; the rule targets the on-disk/in-memory binary, not network traffic (see the companion Suricata/Sigma URI rules for that layer).
**Validation:** Scan `beacon_windows_x64.exe` (hash1 below) — must match; a benign WinHTTP-based application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanner, gateway content inspection.

```yara
/*
    Yara Rule Set
    Identifier: OpenStrike Gen-4 Beacon (beacon_windows_x64.exe)
    Author: The Hunters Ledger
    Source: https://the-hunters-ledger.com/
    License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_OpenStrike_Gen4_Beacon
{
    meta:
        description = "Detects OpenStrike Generation 4 beacon (beacon_windows_x64.exe) by WinHTTP task-poll and output-submit URI format strings containing 8-hex-digit beacon IDs, the shared AES-128-CBC static IV, and the GCC 15.2.0 MinGW build artifact. Gen-4 is 10x smaller than gen-3 (30KB vs 299KB) with a correct Encrypt-then-MAC architecture and SHA256-based key derivation, though key exchange is absent confirming it is a development artifact."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/"
        date = "2026-04-08"
        hash1 = "042761408e83155d24884a72291d9f10803becd790fbcfa6ff65e9e72eb44446"
        hash2 = ""
        hash3 = "b6e01011e2d38855dd6a4b10a79acffe"
        family = "OpenStrike"
        malware_type = "Beacon"
        campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
        id = "aa4bf345-4d6e-5228-9195-9c064fbdeaf7"
    strings:
        $s1 = "/updates?id=%08x" ascii
        $s2 = "/submit?id=%08x" ascii
        $s3 = "abcdefghijklmnop" ascii
        $s4 = "ChainingModeCBC" ascii
        $s5 = "cmd.exe /c %.*s" ascii
        $s6 = "[*] OpenStrike Beacon starting..." ascii
        $s7 = "GCC: (GNU) 15.2.0" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 102400 and
        ($s6 or ($s1 and $s2)) and
        ($s3 or $s4 or $s7 or $s5)
}
```

#### OpenStrike Gen-1 and Gen-2 Prototype Beacons

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.002 (Asymmetric Cryptography — RSA-1024 registration)
**Confidence:** HIGH
**Rationale:** `Cookie: SESSIONID=%d` is the gen-1 identification mechanism absent from any gen-3/gen-4 rule; the RSA-1024 modulus prefix `008cadd72dbf3cc108` is byte-for-byte identical in mini_beacon2.exe and the CS 4.4 Key B ecosystem; the `{ 00 00 BE EF }` magic is the on-wire registration packet header. Requires one of the three protocol/crypto markers AND the GCC 15-win32 compiler string, so the RSA-prefix corroboration alone (theoretically shareable with other RSA-1024 software) never carries the match by itself. Scored Robustness 2 rather than 3 because the compiler-string requirement is a build-toolchain artifact rather than a technique chokepoint.
**False Positives:** None known — `Cookie: SESSIONID=%d` is specific to the gen-1 prototype; the RSA modulus prefix could theoretically appear in other RSA-1024 software but is always corroborated by the GCC 15 compiler string in this rule's condition.
**Blind Spots:** A build using a different compiler toolchain (no `GCC: (GNU) 15-win32` string) evades the rule even if the protocol markers are present.
**Validation:** Scan `mini_beacon.exe` or `mini_beacon2.exe` (hash1 below) — must match; a benign RSA-1024 CNG application built with a different toolchain must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanner.

```yara
rule TOOLKIT_OpenStrike_Proto_Beacons
{
    meta:
        description = "Detects OpenStrike Generation 1 (mini_beacon.exe) and Generation 2 (mini_beacon2.exe) prototype beacons. Gen-1 uses Cookie: SESSIONID=%d format for C2 host identification with no cryptography. Gen-2 adds RSA-1024 BCrypt CNG registration with a binary magic header (0xEFBE0000 big-endian) and host fingerprinting including process name masquerade as svchost.exe. The RSA-1024 modulus prefix is shared with the CS 4.4 Key B ecosystem."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/"
        date = "2026-04-08"
        hash1 = "03492f128fcc3910bda15f393c30ad3e04f5a50de36464d1e24038f49d889324"
        hash2 = ""
        hash3 = ""
        family = "OpenStrike"
        malware_type = "Beacon"
        campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
        id = "4f1cd80b-4395-5c7d-b9c0-1df8d2a4febf"
    strings:
        $s1 = "Cookie: SESSIONID=%d" ascii
        $b1 = { 00 00 BE EF }
        $s2 = "008cadd72dbf3cc108" ascii
        $s3 = "GCC: (GNU) 15-win32" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 102400 and
        ($s1 or $b1 or $s2) and
        $s3
}
```

#### Cobalt Strike Artifact Kit EAX-Redirect Service Variant

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055.003 (Thread Execution Hijacking), T1543.003 (Windows Service), T1036.004 (Masquerade Task or Service), T1218.011 (Rundll32)
**Confidence:** HIGH
**Rationale:** `DceRpcSs` as a service name combined with `\\.\pipe\MSSE-%d-server` is the stock Cobalt Strike Artifact Kit service-variant default — reproducing this combination requires modifying and recompiling the Artifact Kit source, not just editing a config value. No legitimate Windows component uses either string. Corrected from the original: the ATT&CK Coverage previously cited T1055.012 (Process Hollowing), which requires `NtUnmapViewOfSection`; this variant never unmaps the target and instead redirects execution via `SetThreadContext` on a suspended thread, which the MITRE decision tree maps to T1055.003 (Thread Execution Hijacking).
**False Positives:** None known — `DceRpcSs` is not a legitimate Windows service name; `MSSE-%d-server` is the Artifact Kit default; no legitimate Windows binary combines both.
**Blind Spots:** An Artifact Kit build with source-level customization of the service name and pipe-format string evades this rule; the rule targets the on-disk service binary, not the runtime hollowing behavior itself (see the companion Sigma rules for that layer).
**Validation:** Scan `artifact32svc.exe` / `artifact64svc.exe` (hash1 below) — must match; an unrelated legitimate Windows service binary must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanner.

```yara
rule MALW_ArtifactKit_EAXRedirect_Svc
{
    meta:
        description = "Detects Cobalt Strike Artifact Kit service variant (artifact32svc.exe/artifact64svc.exe) that registers as the DceRpcSs service, creates a named pipe matching MSSE-[0-9]+-server for XOR-encoded shellcode delivery, and performs EAX-redirect thread hijacking of a suspended rundll32.exe process. Unlike classic process hollowing, this variant never calls NtUnmapViewOfSection — detection must anchor on SetThreadContext called on suspended threads, or on this binary's static strings."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/"
        date = "2026-04-08"
        hash1 = "701b4f60411a26abfb137f476c9328900843ee5a49780f2fcd23a5cb15498f16"
        hash2 = ""
        hash3 = ""
        family = "CobaltStrike"
        malware_type = "ArtifactKit-Service"
        campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
        id = "951c6e9f-c54d-5e24-8456-8f79aa0411d2"
    strings:
        $s1 = "DceRpcSs" ascii
        $s2 = "\\\\.\\pipe\\MSSE-%d-server" ascii
        $s3 = "rundll32.exe" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 819200 and
        $s1 and $s2 and $s3
}
```

#### CovertVPN Layer 2 Bridge Module

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling), T1543.003 (Windows Service — npf.sys kernel driver)
**Confidence:** HIGH
**Rationale:** `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` is the unpatched AES key config placeholder embedded in covertvpn.dll — a nonsensical 32-character development sentinel with no plausible legitimate collision. The rule requires this placeholder AND at least one of the WinPcap deployment or HTTP-channel corroborating strings, so the config placeholder alone (already highly distinctive) is never the sole gate.
**False Positives:** None known — the 32-character AAAA...HHHH AES placeholder is a development artifact unique to this module; `wpcap.dll` embedded in a non-WinPcap installer binary is anomalous.
**Blind Spots:** A production build that patches the placeholder with a randomized AES key would evade this rule; the rule targets the on-disk module, not the ICMP/TCP/UDP transport channels themselves.
**Validation:** Scan `covertvpn.dll` (hash1 below) — must match; a legitimate WinPcap-based application must NOT fire (it will not carry the AES placeholder).
**Deployment:** Endpoint AV/EDR file scan, memory scanner, DLP gateway.

```yara
rule MALW_CovertVPN_L2Bridge
{
    meta:
        description = "Detects the Cobalt Strike CovertVPN Layer 2 bridge module (covertvpn.dll) by its unpatched 32-character AES key config placeholder (AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH), self-contained WinPcap 4.1.3 deployment strings (npf.sys, wpcap.dll), and HTTP data channel URI (/receive%s). The module embeds npf.sys as a kernel driver in its .data section (~556KB) and supports 5 transport channels: TCP connect/bind, UDP, HTTP, and ICMP echo with 0xDD/0xCC frame markers."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/"
        date = "2026-04-08"
        hash1 = "af688b120db0a3b324e2cd468cfead71b7895a3c815f4026d51ac7fca0cb8ab4"
        hash2 = ""
        hash3 = "3d60ae2e584a1be1c264cfdaa12a5e4d"
        family = "CovertVPN"
        malware_type = "Tunneling-Module"
        campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
        id = "6a349a13-0b67-5316-9af2-d6d7773daf46"
    strings:
        $s1 = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" ascii
        $s2 = "npf.sys" ascii
        $s3 = "wpcap.dll" ascii
        $s4 = "/receive%s" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2097152 and
        $s1 and
        ($s2 or $s3 or $s4)
}
```

### Hunting Rules

#### OpenStrike DLL Loader

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1129 (Shared Modules), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection. The rule's real discriminating power rests on the single hardcoded path `C:\Windows\Temp\beacon.dll` — a one-line source edit in a future build fully evades it. The paired diagnostic format strings (`DLL loaded at %p`, `LoadLibrary failed: %lu`) and the GCC 15-win32 compiler string add negligible durability of their own: both are generic-enough developer print statements and a shared toolchain artifact respectively, so with the path removed the rule would fire on very little that is distinctive. Per the tiering rubric, a rule whose low false-positive rate today derives from one renameable literal is scored on durability, not as-written precision.
**False Positives:** Low today — no legitimate software is known to hardcode a `beacon.dll` load target in `C:\Windows\Temp`; a future OpenStrike build that renames the drop path or the DLL evades entirely.
**Deployment:** Endpoint AV/EDR file scan, memory scanner; treat as a triage lead requiring confirmation from the companion Detection-tier rules or the file-path IOC feed entry.

```yara
rule TOOLKIT_OpenStrike_DllLoader
{
    meta:
        description = "Detects OpenStrike dll_loader.exe, a custom loader that loads a Cobalt Strike beacon DLL from the hardcoded path C:\\Windows\\Temp\\beacon.dll using LoadLibraryA, then enters an infinite Sleep(60000) keepalive loop. Unlike the five in-memory loader variants from the same GCC 15 codebase, this loader drops payload to disk rather than allocating RWX memory. Identified by the hardcoded path, operator diagnostic format strings, and GCC 15-win32 MinGW build artifact. The hardcoded drop path is the rule's primary discriminator and is trivially changed in a future build."
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/"
        date = "2026-04-08"
        hash1 = "b0f0fe97b653e4564db8cf24cbd4cc2cad46f9c6629b67c2f147e647729f5b46"
        hash2 = "811589e4982f25f92725e2bc6646d4e5d1e8b7be"
        hash3 = "b5d391099c1376d81ebdc91b3fc55eae"
        family = "OpenStrike"
        malware_type = "Loader"
        campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
        id = "567d09ec-d040-5c86-afb8-8b6fa860a6b2"
    strings:
        $s1 = "C:\\Windows\\Temp\\beacon.dll" ascii
        $s2 = "DLL loaded at %p" ascii
        $s3 = "LoadLibrary failed: %lu" ascii
        $s4 = "GCC: (GNU) 15-win32" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 204800 and
        $s1 and
        ($s2 or $s3) and
        $s4
}
```

---

## Sigma Rules

### Detection Rules

#### Artifact Kit EAX-Redirect Process Hollowing via Rundll32 No Arguments

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055.003 (Thread Execution Hijacking), T1218.011 (Rundll32)
**Confidence:** HIGH
**Rationale:** `rundll32.exe` spawned with no command-line arguments by `services.exe` is the precise behavioral signature of EAX-redirect hollowing — a technique-level pattern independent of any single sample or build. Legitimate Windows services virtually never spawn `rundll32.exe` without arguments (they always pass a DLL path and entry point). Corrected from the original: the technique tag was the bare parent T1055 with no sub-technique; the rule's own description confirms `SetThreadContext` on a suspended thread with no `NtUnmapViewOfSection` call, which the MITRE decision tree maps to T1055.003 (Thread Execution Hijacking) rather than T1055.012 (Process Hollowing). Added the T1218.011 tag for the Rundll32 execution vehicle, matching the rule's original prose ATT&CK Coverage line that the YAML tags omitted.
**False Positives:** Legitimate Windows services that invoke `rundll32.exe` without arguments (extremely rare; verify by examining the parent service binary path and cross-referencing against asset inventory).
**Blind Spots:** A variant that always passes at least one argument to rundll32 (even a decoy) evades the `not filter_has_args` condition; misses EAX-redirect variants that target a process other than rundll32.
**Validation:** Trigger the Artifact Kit service variant — the bare rundll32 spawn from services.exe must match; a legitimate Windows service invoking rundll32.exe with its normal DLL,entrypoint arguments must NOT fire.
**Deployment:** Endpoint EDR (Sysmon Event ID 1), SIEM.

```yaml
title: Artifact Kit EAX-Redirect Process Hollowing via Rundll32 No Arguments
id: a4f82c19-7b3e-4d56-9e1a-2c5f8b0d3e74
status: experimental
description: >-
  Detects the Cobalt Strike Artifact Kit service variant EAX-redirect
  process hollowing pattern where a Windows service process (services.exe
  parent) spawns rundll32.exe with no command-line arguments. The Artifact
  Kit then performs VirtualAllocEx, WriteProcessMemory, and
  SetThreadContext on the suspended rundll32.exe to redirect execution to
  shellcode via the EAX register. This technique bypasses
  NtUnmapViewOfSection-anchored classic process hollowing detection
  because the original PE is never unmapped.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.privilege-escalation
    - attack.t1055.003
    - attack.stealth
    - attack.t1218.011
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\services.exe'
        Image|endswith: '\rundll32.exe'
    filter_has_args:
        CommandLine|contains: ' '
    condition: selection and not filter_has_args
falsepositives:
    - >-
      Legitimate Windows services that invoke rundll32.exe without
      arguments (extremely rare; verify by examining the parent service
      binary path and cross-referencing against asset inventory)
level: high
```

#### Cobalt Strike Artifact Kit MSSE Named Pipe Creation

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055.003 (Thread Execution Hijacking — shellcode staging via pipe)
**Confidence:** HIGH
**Rationale:** The `MSSE-[number]-server` named pipe pattern is the Cobalt Strike Artifact Kit default pipe name, generated by `GetTickCount() % 9898`. This pipe is created and immediately self-connected within the same process to transfer XOR-encoded shellcode via kernel pipe indirection. No legitimate Windows component creates pipes matching this pattern. Corrected from the original: aligned the technique tag from bare T1055 to T1055.003, consistent with the companion EAX-redirect rundll32 rule (same underlying hollowing chain).
**False Positives:** Unlikely — `MSSE-[0-9]+-server` is Artifact Kit-specific; `startswith \MSSE-` and `endswith -server` together are highly discriminating.
**Blind Spots:** An Artifact Kit build with a source-level customized pipe-name template evades this rule.
**Validation:** Trigger the Artifact Kit service variant's shellcode staging — the pipe creation must match; unrelated legitimate named-pipe creation must NOT fire.
**Deployment:** Endpoint EDR (Sysmon Event ID 17), SIEM.

```yaml
title: Cobalt Strike Artifact Kit MSSE Named Pipe Creation
id: b7c91d3e-5a20-4f88-b2d4-8e1c9a4f6b52
status: experimental
description: >-
  Detects creation of the Cobalt Strike Artifact Kit default named pipe
  pattern MSSE-[number]-server. The Artifact Kit service variant
  (artifact32svc/artifact64svc) creates this pipe to transfer XOR-encoded
  shellcode to the hollowing target via kernel pipe indirection as an AV
  evasion technique. The pipe ID is derived from GetTickCount() modulo
  9898, producing values in the range 0 to 9897. No legitimate Windows
  component creates pipes with this naming pattern.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.privilege-escalation
    - attack.t1055.003
    - attack.stealth
    - detection.emerging-threats
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith: '\MSSE-'
        PipeName|endswith: '-server'
    condition: selection
falsepositives:
    - >-
      Unlikely — MSSE-[0-9]+-server pipe naming is specific to the Cobalt
      Strike Artifact Kit default configuration; no legitimate Windows
      component uses this pattern
level: high
```

### Hunting Rules

#### DceRpcSs Masquerading Service Installation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH (behavior) / triage required (durability)
**Rationale:** Retiered from Detection. `ServiceName: 'DceRpcSs'` is the rule's sole discriminator — `EventID: 7045` alone is an ambient "any service installed" event with no distinguishing value, so nothing behavioral survives if the literal is removed. `DceRpcSs` is not a programmatically-derived toolkit constant (unlike the MSSE pipe pattern, which is generated by `GetTickCount() % 9898`); it reads as an operator/campaign naming choice a future build or deployment can change with a one-line edit. Demoted from `critical` to `medium` to match the tier.
**False Positives:**
- Unlikely today — `DceRpcSs` is not a legitimate Windows service name and has no known collision.
- A future campaign or unrelated actor choosing the same masquerade name would also match; treat a hit as a lead requiring corroboration (binary path, hash) rather than an automatic incident.
**Deployment:** Windows Security/System Event Log (Event ID 7045), SIEM; pair with the YARA Artifact Kit rule for file-level confirmation.

```yaml
title: DceRpcSs Masquerading Service Installation
id: c3d84e7f-2b61-4a99-8f3c-5d7e1b8c2a96
status: experimental
description: >-
  Detects installation of a Windows service named DceRpcSs, which
  masquerades as the legitimate RpcSs (Remote Procedure Call) service.
  The Cobalt Strike Artifact Kit service variant registers under this
  name to blend with built-in Windows services and survive casual
  administrative review. The legitimate RpcSs service name does not
  match DceRpcSs in any Windows version. The service name itself is an
  operator-chosen value and may change in a future build or deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.persistence
    - attack.t1036.005
    - attack.stealth
    - detection.emerging-threats
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'DceRpcSs'
    condition: selection
falsepositives:
    - >-
      Unlikely — DceRpcSs is not a legitimate Windows service name; a
      future campaign or unrelated actor reusing this exact masquerade
      name would also match, so treat a hit as a lead requiring
      corroboration rather than an automatic incident
level: medium
```

#### CovertVPN WinPcap npf.sys Kernel Driver Loaded from Temp Directory

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1543.003 (Windows Service — kernel driver)
**Confidence:** MODERATE
**Rationale:** `npf.sys` is the genuine, unmodified WinPcap kernel driver filename — durable in the sense that it can't be renamed without breaking WinPcap functionality, and not specific to CovertVPN (any tool embedding WinPcap for raw capture would trip it). Retiered from Detection on precision, not durability: the rule's own original false-positive assessment rated this MEDIUM ("legitimate WinPcap/Npcap installers occasionally stage npf.sys in %TEMP% during initial setup before moving to System32\drivers"), which does not clear the "reliably fires on malice, rare FP" bar for Detection. Corrected from the original: the technique tag was T1547.006 (Kernel Modules and Extensions, a Linux/macOS-scoped sub-technique) and carried an orphaned `attack.command-and-control` tactic tag with no paired C2 technique — realigned to T1543.003 (Windows Service), matching the rule's own prose ATT&CK Coverage line and MITRE's Windows-service scoping for kernel-driver services; the T1095 (Non-Application Layer Protocol) claim in the original prose describes the CovertVPN ICMP/raw-capture *capability* the driver enables, not this file-load event itself, so it is not re-added as a tag here.
**False Positives:**
- Legitimate WinPcap or Npcap installers that stage npf.sys in a temporary directory before moving it to System32\drivers (uncommon; verify by checking for a subsequent persistent driver installation in System32\drivers).
**Deployment:** Endpoint EDR (Sysmon Event ID 6), SIEM.

```yaml
title: CovertVPN WinPcap npf.sys Kernel Driver Loaded from Temp Directory
id: d9e05a82-6c34-4b77-a1f5-3e8d2c7b4f01
status: experimental
description: >-
  Detects loading of the npf.sys WinPcap kernel driver from a user
  temporary directory. The Cobalt Strike CovertVPN Layer 2 bridge module
  embeds WinPcap 4.1.3 components (npf.sys x86 and amd64, wpcap.dll,
  Packet.dll) in its .data section and installs npf.sys as a kernel
  driver service from %TEMP% to enable raw packet capture for its ICMP
  and UDP transport channels. Legitimate WinPcap and Npcap installations
  place the driver in System32\drivers, not in user temp directories,
  though some installers do briefly stage there before relocating it.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
    - detection.emerging-threats
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\npf.sys'
    filter_legitimate:
        ImageLoaded|contains:
            - '\System32\drivers\'
            - '\SysWOW64\drivers\'
    condition: selection and not filter_legitimate
falsepositives:
    - >-
      Legitimate WinPcap or Npcap installers that stage npf.sys in a
      temporary directory before moving it to System32\drivers
      (uncommon; verify by checking for a subsequent persistent driver
      installation in System32\drivers)
level: medium
```

#### Cobalt Strike Beacon DLL Dropped to Windows Temp Directory

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1129 (Shared Modules), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection. `TargetFilename: 'C:\Windows\Temp\beacon.dll'` is the rule's entire selection — a single hardcoded path with no process-context qualifier. `beacon.dll` is also the Cobalt Strike Artifact Kit / aggressor-script default output filename used broadly across unrelated CS deployments, so the filename component itself carries less campaign-specific weight than it first appears; a future build renaming either the path or the DLL evades the rule outright. Added the T1036.005 tag to match the rule's own prose ATT&CK Coverage line, which the original YAML omitted.
**False Positives:**
- Unlikely today — the filename `beacon.dll` at this exact path is not used by any known legitimate software.
- Any other Cobalt Strike deployment (unrelated to this campaign) using the same default Artifact Kit output filename and a similar drop path would also match.
**Deployment:** Endpoint EDR (Sysmon Event ID 11), SIEM.

```yaml
title: Cobalt Strike Beacon DLL Dropped to Windows Temp Directory
id: e1f73b45-8d92-4c66-b3e7-4a9f5d1c8b27
status: experimental
description: >-
  Detects creation of a file named beacon.dll in C:\Windows\Temp, the
  hardcoded drop path used by OpenStrike dll_loader.exe. The loader uses
  LoadLibraryA to load the Cobalt Strike beacon DLL from this exact path
  and then enters an infinite Sleep(60000) keepalive loop. beacon.dll is
  also the default Cobalt Strike Artifact Kit output filename used
  broadly across unrelated deployments, so a hit should be treated as a
  triage lead rather than a confirmed OpenStrike indicator on its own.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.execution
    - attack.t1129
    - attack.stealth
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename: 'C:\Windows\Temp\beacon.dll'
    condition: selection
falsepositives:
    - >-
      Unlikely — the filename beacon.dll at this exact path is not used
      by any known legitimate software; however, beacon.dll is the
      default Cobalt Strike Artifact Kit output filename, so any
      unrelated Cobalt Strike deployment using the same default output
      name and a similar drop path would also match
level: medium
```

#### Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent in Proxy Traffic

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection. The `BOIE9;ENUSSEM` suffix is a Malleable C2 profile configuration value — a text field an operator can change per deployment without any infrastructure cost or rebuild, which places it in the same durability bucket as any other single UA-string indicator regardless of today's zero known collisions.
**False Positives:** Unlikely today — `BOIE9;ENUSSEM` does not appear in any known legitimate browser or application user-agent string; a future campaign using a different Malleable profile UA evades this rule entirely.
**Deployment:** Proxy logs, network TAP with HTTP inspection, SIEM.

```yaml
title: Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent in Proxy Traffic
id: f4a82d61-3c57-4e88-9b2f-5e1a7c8d3f49
status: experimental
description: >-
  Detects the Cobalt Strike beacon80.dll Malleable C2 profile User-Agent
  containing the BOIE9;ENUSSEM suffix. The full user-agent string is
  Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0;
  BOIE9;ENUSSEM). This non-standard suffix is injected by the Malleable
  C2 profile configuration and does not appear in genuine Internet
  Explorer 9 browser traffic. This profile is distinct from the
  MALC-suffix profile covered in the companion April 6 detection file.
  The suffix is a profile-configuration value and may change in a future
  deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|contains: 'BOIE9;ENUSSEM'
    condition: selection
falsepositives:
    - >-
      Unlikely — BOIE9;ENUSSEM does not appear in any known legitimate
      browser or application user-agent string; a future campaign using
      a different Malleable C2 profile UA evades this rule entirely
level: medium
```

#### OpenStrike Gen-4 Beacon Task Polling HTTP GET to /updates with Hex Beacon ID

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection. The 8-hex-digit deterministic ID format (a djb2 hash variant of ComputerName XOR PID) is a genuine protocol-design element, more durable than a simple config string — but the original rule's own false-positive assessment ("LOW-MEDIUM ... web applications may legitimately use /updates?id= endpoints ... correlate with ~5-second beaconing interval and POST to /submit?id= for high confidence") states plainly that the rule as written does not reach high confidence standalone. A `threshold` clause controls alert *volume*, not per-match precision, so it does not change this assessment.
**False Positives:** Web applications using `/updates` as an API endpoint with an `id` parameter of exactly 8 lowercase hex characters (uncommon in enterprise environments; verify against known application inventory and require a correlated POST to `/submit?id=` with the same ID before treating as high confidence).
**Deployment:** Proxy logs, SIEM; correlate with the companion `/submit?id=` rule and beaconing-interval analysis before escalating.

```yaml
title: OpenStrike Gen-4 Beacon Task Polling HTTP GET to /updates with Hex Beacon ID
id: a8c35f72-4d19-4b83-9e6a-1c7d5e2b8f30
status: experimental
description: >-
  Detects the OpenStrike Generation 4 beacon (beacon_windows_x64.exe)
  task polling pattern — HTTP GET requests to /updates with an
  8-character lowercase hex beacon ID query parameter. The beacon ID is
  a djb2 hash variant (multiplier 0x1f) of ComputerName XOR'd with PID,
  making it deterministic per host across process restarts. The
  beaconing interval is approximately 5 seconds with 10 percent jitter
  (4500-5500ms base). This rule alone has LOW-MEDIUM precision;
  correlate with a corresponding POST to /submit?id=[same ID] and the
  beaconing interval for high-confidence identification.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
        c-uri|re: '^/updates\?id=[0-9a-f]{8}$'
    condition: selection
falsepositives:
    - >-
      Web applications using /updates as an API endpoint with an id
      parameter of exactly 8 lowercase hex characters (uncommon in
      enterprise environments; verify against known application
      inventory and look for correlated POST to /submit?id=)
level: medium
```

#### OpenStrike Gen-4 Beacon Output Submission HTTP POST to /submit with Hex Beacon ID

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection, mirroring the companion `/updates` polling rule — same URI-scheme durability profile and the same self-admitted LOW-MEDIUM standalone precision requiring correlation with the matched GET for high confidence. Added the T1071.001 tag to match the rule's own prose ATT&CK Coverage line, which the original YAML omitted.
**False Positives:** API endpoints using `/submit` with an `id` parameter of exactly 8 hex characters accepting POST data (uncommon in enterprise environments; correlate with a matched GET to `/updates?id=` for the same ID before treating as high confidence).
**Deployment:** Proxy logs, SIEM; correlate with the companion `/updates?id=` rule.

```yaml
title: OpenStrike Gen-4 Beacon Output Submission HTTP POST to /submit with Hex Beacon ID
id: b2e49c83-5f61-4a77-9d3e-2b8c1a4f7e52
status: experimental
description: >-
  Detects the OpenStrike Generation 4 beacon output submission pattern —
  HTTP POST to /submit with an 8-character lowercase hex beacon ID query
  parameter. Command output is AES-128-CBC encrypted with PKCS7 padding,
  then a 16-byte truncated HMAC-SHA256 tag is appended (Encrypt-then-MAC).
  The beacon ID matches the corresponding GET to /updates?id=[same ID].
  Correlating matched pairs of GET /updates and POST /submit with the
  same 8-hex-digit ID provides higher-confidence identification of an
  active gen-4 beacon session; standalone this rule has LOW-MEDIUM
  precision.
references:
    - https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/
author: The Hunters Ledger
date: 2026-04-08
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
        c-uri|re: '^/submit\?id=[0-9a-f]{8}$'
    condition: selection
falsepositives:
    - >-
      API endpoints using /submit with an id parameter of exactly 8 hex
      characters accepting POST data (uncommon in enterprise
      environments; correlate with matched GET to /updates?id= for the
      same ID to confirm)
level: medium
```

---

## Suricata Signatures

### Hunting Rules

#### OpenStrike Gen-4 Beacon Network Task Poll (GET /updates)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection to align with the companion Sigma rule. The URI is not IP-anchored (matches any `$EXTERNAL_NET` destination, surviving C2 infrastructure rotation) and the 8-hex-digit ID format is a genuine protocol-design element, but standalone URI-pattern precision is the same LOW-MEDIUM the Sigma equivalent documents — `threshold` bounds alert volume, it does not change whether a single match is a true or false positive.
**False Positives:** Web applications using `/updates` as an API endpoint with an 8-lowercase-hex `id` parameter (uncommon in enterprise environments); the `threshold` limits alert volume per source but does not eliminate standalone ambiguity.
**Deployment:** Perimeter IDS/IPS, network TAP; correlate with the companion `/submit` signature before escalating.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenStrike Gen4 Beacon Task Poll GET /updates?id=[hex8]"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/updates?id="; pcre:"/\/updates\?id=[0-9a-f]{8}$/U"; threshold:type limit,track by_src,count 1,seconds 30; classtype:trojan-activity; sid:9002001; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-08, reference https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/;)
```

#### OpenStrike Gen-4 Beacon Output Submission (POST /submit)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection, mirroring the `/updates` polling signature — same URI-scheme durability and the same standalone precision limitation.
**False Positives:** POST requests to a `/submit?id=[8hex]`-shaped endpoint carrying binary content (uncommon in enterprise environments, but not impossible on generic API infrastructure); correlate with the matched GET signature for higher confidence.
**Deployment:** Perimeter IDS/IPS, network TAP; correlate with the companion `/updates` signature.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenStrike Gen4 Beacon Output Submission POST /submit?id=[hex8]"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/submit?id="; pcre:"/\/submit\?id=[0-9a-f]{8}$/U"; threshold:type limit,track by_src,count 1,seconds 60; classtype:trojan-activity; sid:9002002; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-08, reference https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/;)
```

#### Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent Detected

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** Retiered from Detection. The `endswith` anchor to the tail of the User-Agent buffer is correctly implemented (matches the suffix, including the closing paren, not a mid-string substring), and there is no known legitimate collision today — but a Malleable C2 UA string is a profile-configuration value an operator can change per deployment, placing it in the same durability bucket as any other single UA-string indicator.
**False Positives:** Unlikely today — this suffix does not appear in any known legitimate UA string; a future deployment using a different Malleable profile evades this rule entirely.
**Deployment:** Perimeter IDS/IPS, proxy with HTTP user-agent logging.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent Detected"; flow:established,to_server; http.user_agent; content:"BOIE9|3B|ENUSSEM)"; endswith; nocase; classtype:trojan-activity; sid:9002003; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-08, reference https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/;)
```

#### CovertVPN HTTP Data Channel GET /receive Endpoint

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**Rationale:** `/receive` is a single short literal in the HTTP URI, and the rule's own original assessment already rated it MEDIUM false-positive risk ("/receive is a common REST API path segment"). No corroborating content anchor (host, method, body pattern) was available to pair with it for a Detection-grade signature.
**False Positives:** Any unrelated HTTP request whose URI happens to start with the 8-character substring `/receive` (uncommon but not impossible on generic REST/CGI-driven web infrastructure); the `threshold` limits alert volume per source but does not eliminate standalone ambiguity.
**Deployment:** Perimeter IDS/IPS, network TAP with HTTP inspection; hunt-tune before alerting, and correlate with other CovertVPN indicators (npf.sys load, ICMP anomalies).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL CovertVPN HTTP Data Channel GET /receive Endpoint"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/receive"; startswith; threshold:type limit,track by_src,count 3,seconds 60; classtype:trojan-activity; sid:9002005; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-08, reference https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/;)
```

#### CovertVPN ICMP Tunnel Oversized Payload with Data or Keepalive Marker

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling)
**Confidence:** MODERATE
**Rationale:** The oversized-ICMP-echo-plus-fixed-offset-byte-marker pattern is a genuine protocol-level technique signature, durable against IP rotation and binary rename. Retiered from Detection on precision: the rule's own original assessment rated MEDIUM false-positive risk ("large ICMP payloads can occur in legitimate network diagnostics ... assess false positive rate in environments with active network diagnostic tooling"), which does not clear the "rare FP" bar for Detection without environment-specific baselining.
**False Positives:** Legitimate network diagnostic tooling generating large ICMP echo payloads (e.g., `ping -l` on Windows, MTU path discovery) whose payload happens to carry the `0xDD` byte at offset 4; the `threshold` limits alert volume but does not eliminate standalone ambiguity — baseline against diagnostic tooling in the deployment environment before alerting.
**Deployment:** Perimeter IDS/IPS, network TAP (requires ICMP inspection capability).

```
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL CovertVPN ICMP Tunnel Oversized Payload with Data or Keepalive Marker"; itype:8; dsize:>128; byte_test:1,=,0xDD,4; threshold:type limit,track by_src,count 5,seconds 60; classtype:trojan-activity; sid:9002006; rev:1; metadata:author The_Hunters_Ledger, date 2026-04-08, reference https://the-hunters-ledger.com/hunting-detections/new-files-found-20260408-detections/;)
```

> **Deployment note:** A companion signature covering the ICMP keepalive marker (`byte_test:1,=,0xCC,4` in place of `0xDD`) was proposed in the original analysis but never authored as a standalone rule — the data marker (0xDD) and keepalive marker (0xCC) are mutually exclusive per packet, so full coverage requires both. This remains an open item; see Coverage Gaps.

---

## Coverage Gaps

**Cut: Cobalt Strike Stager Download URI /au2U or /msI4 on Port 80.** The original Suricata signature scoped to `172.105.0.126:80` matching the URIs `/au2U` or `/msI4` has been cut. Both the destination IP and the two five-character URI paths are one-off, campaign-specific atomic values with no generalizable structure (unlike the gen-4 `/updates?id=[8-hex]` pattern, this rule carries no format-level regex describing a family of values) — removing either the IP anchor or the exact-string URI match leaves nothing behavioral to detect. Per the tiering rubric's routing test this is a compound atomic, not a signature. Both full URLs (`http://172.105.0.126/au2U`, `http://172.105.0.126/msI4`) were already present in [`new-files-found-20260408-iocs.json`](/ioc-feeds/new-files-found-20260408-iocs.json) before this backfill; no feed edit was required. T1105 (Ingress Tool Transfer) is consequently no longer represented by a standalone Suricata signature in this file — it is covered via the IOC feed URL/IP entries instead.

**CovertVPN ICMP keepalive marker companion signature (0xCC) not authored.** The retained ICMP tunnel signature (sid:9002006) covers only the data-frame marker (`0xDD` at offset 4). The keepalive marker (`0xCC` at the same offset) was identified during analysis and flagged for a companion signature, but that second rule was never actually written in the original publication — only described as a deployment suggestion. It remains unauthored here as well; a future update should add a second signature (`byte_test:1,=,0xCC,4`, matching metadata, next available local sid) to complete ICMP-channel coverage.

**T1055.002 — PE Injection (in-memory loaders).** All five in-memory OpenStrike loaders (beacon_loader, beacon_rdi, beacon_srdi2, beacon_dl, beacon_full) use `VirtualAlloc(RWX)` + memcpy + indirect call or CreateThread. Behavioral rules for VirtualAlloc(RWX) followed by CreateThread exist in multiple threat intelligence feeds and would produce high false positive rates across legitimate software. Rule development would require pairing with the specific GCC 15 compiler artifacts already covered in the YARA file, making a standalone Sigma rule redundant. Memory scanner deployment of the existing YARA rules is the recommended coverage path.

**T1572 — Protocol Tunneling (TCP/UDP CovertVPN channels).** CovertVPN's TCP connect (`t`), TCP bind (`b`), and UDP (`u`) transport channels do not produce protocol-level signatures distinct from generic TCP/UDP traffic. Detection of these channels requires NetFlow anomaly analysis (unusual connection volumes or session durations) rather than signature-based rules. The ICMP and HTTP channels are covered above.

**T1059.007 — JavaScript (social engineering kit).** The `keylogger.js` and `analytics.js` browser-side scripts execute in the browser context and are not visible to endpoint EDR or network IDS without full browser script logging (e.g., Chrome DevTools Protocol telemetry). Rule development requires browser security tooling not available in standard Sysmon or proxy log sources.

**T1112 — Modify Registry (template.vbs AccessVBOM).** The `template.vbs` script modifies `HKEY_CURRENT_USER\Software\Microsoft\Office\[version]\[application]\Security\AccessVBOM` to enable VBA macro execution. A Sigma rule for this registry modification would have high FP risk, as security tools and IT management software routinely modify Office security registry keys. High-confidence detection requires pairing the registry modification with the specific template.vbs script file path, which is not available in this analysis.

**T1056.001 — Keylogging (keylogger.js).** Browser-side JavaScript keylogging has no host-level EDR telemetry visibility in standard Sysmon configurations. Detection is possible only through browser security tooling or DNS/proxy correlation if the credential harvester posts to an observable endpoint.

**T1573.002 — Asymmetric Cryptography (RSA-1024 in gen-2).** The RSA-1024 BCrypt CNG registration in mini_beacon2.exe is covered by the YARA rule for gen-1/gen-2 proto-beacons (Detection-tier, above). A standalone Sigma rule for BCrypt RSA usage would produce unacceptable FP rates across all legitimate software using CNG. No additional rule is warranted.

**CS Port 50050 (Team Server) — Network Coverage.** A Suricata signature for outbound TCP to port 50050 was evaluated and rejected: port 50050 is used by numerous legitimate applications. The SSL certificate hash (`6e8efd85110de376426cde809f25d50ffcbb1d0e39d11c82913757cb277e15dd`) is included in the IOC feed for blocking at the TLS inspection layer, which is the appropriate detection mechanism for team server management traffic.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

