---
title: "Detection Rules — nethost.dll (Arsenal-237 DLL Hijacking Persistence)"
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-nethost-dll-detections/
hide: true
redirect_from: /hunting-detections/arsenal-237-nethost-dll/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
---

**Campaign:** Arsenal-237-New-Files-109.230.231.37
**Date:** 2026-01-27
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**IOC Feed:** https://the-hunters-ledger.com/ioc-feeds/arsenal-237-nethost-dll.json

---

## Detection Coverage Summary

nethost.dll is a 64-bit, Rust-compiled DLL recovered from the Arsenal-237 threat-actor toolkit repository exposed at 109.230.231.37. It functions as the toolkit's command-and-control communication module: a hardcoded proxy target pair, a PowerShell-based command-dispatch layer, and a 14-command control protocol covering reconnaissance, file transfer, and clipboard collection. nethost.dll shares its filename with a legitimate Microsoft .NET hosting component, so coverage here does not key on the bare filename; detection instead anchors on the module's embedded C2 command templates and protocol artifacts.

Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split. The malware's hardcoded proxy targets and the sample's file hashes carry no behavioral value beyond their own literal values, so they are routed to the IOC feed rather than published as standalone signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 1 | T1059.001, T1105, T1020, T1007, T1071.001, T1090, T1082 | 1 |
| Sigma | 1 | 0 | T1059.001 | 0 |
| Suricata | 0 | 0 | — | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Atomics routed to the IOC feed:** the sample's SHA256/MD5/SHA1 and the two hardcoded proxy targets (`8.8.8.8:53` TCP, `127.0.0.1:53` TCP) were already present in [`arsenal-237-nethost-dll.json`](/ioc-feeds/arsenal-237-nethost-dll.json) before this retiering pass. The rules built around them added no detection value beyond those feed entries and have been retired — see Coverage Gaps for the full reasoning on every retired rule, including a dedicated note on why the bare filename cannot anchor a rule.

---

## YARA Rules

### Detection Rules

#### Arsenal-237 NetHost PowerShell C2 Command Templates

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1020 (Automated Exfiltration), T1007 (System Service Discovery)
**Confidence:** HIGH
**Rationale:** Anchors on four embedded PowerShell command-dispatch templates — a service-status enumeration one-liner, a file-download one-liner, a base64 upload-path marker, and a concatenated C2 response-keyword string — none of which depend on a filename, mutex, or IP address. The 3-of-4 threshold tolerates the operator dropping or editing any single template in a future build. Each string carries the empty-quote placeholder syntax of an unfilled command template (`-eq ''`, `-Uri '' -OutFile ''`), a pattern not expected in genuine ad hoc administrative scripting.
**False Positives:** None known — the combination of placeholder-syntax PowerShell templates, a `pathB64:` upload marker, and a concatenated multi-field C2 response-keyword string is not present in legitimate administrative or deployment scripting.
**Blind Spots:** A rebuild using different command templates or a non-PowerShell dispatch layer evades; the rule targets the on-disk module, not an in-memory-only variant. No goodware-corpus scan has been run against this rule.
**Validation:** Scan the captured nethost.dll sample — must match; unrelated PowerShell administration tooling must NOT fire.
**Deployment:** Endpoint AV/EDR file scanning, IR artifact triage, retroactive scan of file shares.

```yara
/*
   Yara Rule Set
   Identifier: Arsenal-237-New-Files-109.230.231.37
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_Arsenal237_NetHost_PowerShell_C2_Templates {
   meta:
      description = "Detects the Arsenal-237 nethost.dll C2 module's embedded PowerShell command-dispatch templates: a service-status enumeration one-liner, a file-download one-liner, a base64 upload-path marker, and a concatenated C2 response-keyword string. Each template carries its unfilled placeholder syntax, distinguishing it from genuine ad hoc administrative scripting."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-nethost-dll-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "C2-Communication-Module"
      campaign = "Arsenal-237-New-Files-109.230.231.37"
      id = "25342642-c59c-491f-ad00-41779cc4c18f"
   strings:
      $ps_service = "Get-Service|?{$_.Status -eq ''}" ascii
      $ps_download = "Invoke-WebRequest -Uri '' -OutFile ''" ascii
      $upload_prefix = "pathB64:" ascii
      $response_keywords = "resultmachine_idsuccess" ascii
   condition:
      uint16(0) == 0x5A4D and
      3 of them
}
```

### Hunting Rules

#### Arsenal-237 NetHost Rust C2 String Combination

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1090 (Proxy), T1082 (System Information Discovery)
**Confidence:** MODERATE
**Rationale:** The primary anchor (`$c2_targets`) is a Rust string-literal-packing artifact — the compiled binary's hardcoded proxy targets `8.8.8.8:53` and `127.0.0.1:53` laid out contiguously with a `ntdll.dll` reference, with no delimiter between them, a byte sequence unlikely to occur outside this exact build. That is also its weakness: per the durability tie-breaker, a literal this specific to the malware's own hardcoded C2 configuration breaks the moment the operator rotates infrastructure in a future compile, so it is scored as build-specific rather than family-durable. The alternate `$env_discovery` branch (COMPUTERNAME/USERNAME queried as adjacent literals) is weaker and more generic on its own. No goodware-corpus validation has been performed for either branch, and the mandatory `$rust_panic`/`$winsock_init` strings are individually common Winsock/Rust-runtime terms — kept as a Hunting lead for this build family, not promoted to Detection.
**False Positives:** Low for the `$c2_targets` branch alone (the concatenated literal is highly specific); higher for the `$env_discovery` branch, since COMPUTERNAME/USERNAME environment-variable enumeration combined with Winsock initialization is not unique to this malware.
**Deployment:** Endpoint AV/EDR file scanning, retroactive scan of file shares, IR artifact triage on hosts with anomalous outbound TCP/53 activity.

```yara
rule SUSP_Arsenal237_NetHost_Rust_C2_String_Combination {
   meta:
      description = "Detects the Arsenal-237 nethost.dll C2 module by its embedded, build-specific hardcoded C2-target string (or an environment-discovery string) combined with Rust-runtime error handling and Winsock-initialization evidence. The c2_targets literal reflects this exact build's compiled hardcoded proxy configuration and breaks if the operator rotates infrastructure in a future compile — treat as a scoping lead for this build family, not a durable signature."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/arsenal-237-nethost-dll-detections/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "C2-Communication-Module"
      campaign = "Arsenal-237-New-Files-109.230.231.37"
      id = "32d2dfd4-59a3-400c-a31e-852fbc0ff5b9"
   strings:
      $c2_targets = "8.8.8.8:53127.0.0.1ntdll.dll" ascii
      $env_discovery = "COMPUTERNAMEUSERNAME" ascii
      $rust_panic = "runtime error" ascii
      $winsock_init = "WSAStartup" ascii
   condition:
      uint16(0) == 0x5A4D and
      ($c2_targets or $env_discovery) and
      ($rust_panic or $winsock_init)
}
```

---

## Sigma Rules

### Detection Rules

#### Arsenal-237 nethost.dll PowerShell Template Execution

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** HIGH
**Rationale:** Requires all three of a PowerShell process launch, a command-line match on one of three prefix-anchored C2 command-dispatch fragments, and a parent process drawn from the module's observed launch chain. Each `CommandLine` selector anchors on the stable prefix of its template rather than the full literal, so the match survives whatever value the C2 substitutes at runtime — this is sound field usage for a process_creation logsource, unlike the companion rule cut below.
**False Positives:** Legitimate system administration scripts that combine these exact command fragments with a parent process from this specific four-item list are not expected.
**Blind Spots:** The four-item parent-process allowlist may miss a future build where the PowerShell child process has a different or renamed parent; a rebuild dropping these specific template fragments evades entirely.
**Validation:** Trigger a PowerShell invocation combining the service-status enumeration or file-download template from one of the four listed parent processes — must match; ordinary interactive administrator PowerShell launched from a shell/terminal parent not in the list must NOT fire.
**Deployment:** PowerShell process-creation telemetry (Sysmon Event ID 1 equivalent), EDR command-line logging.

```yaml
title: Arsenal-237 nethost.dll PowerShell Template Execution
id: cac58909-f05e-45a7-b8b2-d0955ed5fdb0
status: experimental
description: >-
  Detects PowerShell execution combining one of the Arsenal-237 nethost.dll C2
  module's command-dispatch templates (service-status enumeration or file
  download) with a parent process drawn from the module's observed launch
  chain. Each CommandLine selector anchors on the stable prefix of its
  template, so the match survives whatever value the C2 substitutes at
  runtime.
references:
  - https://the-hunters-ledger.com/hunting-detections/arsenal-237-nethost-dll-detections/
author: The Hunters Ledger
date: '2026-01-27'
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    powershell_execution:
        Image|endswith: powershell.exe
    malware_templates:
        CommandLine|contains:
            - 'Get-Service|?{$_.Status -eq'
            - 'Invoke-WebRequest -Uri'
            - 'Select Name,Status|FT'
    suspicious_parent:
        ParentImage|endswith:
            - rundll32.exe
            - regsvcs.exe
            - explorer.exe
            - svchost.exe
    condition: powershell_execution and malware_templates and suspicious_parent
falsepositives:
    - >-
      Legitimate system administration scripts that combine these exact
      command fragments with a parent process from this specific list.
level: high
```

---

## Coverage Gaps

### Retiering Fixes Applied

- **Missing `references:` field added (Sigma Detection rule).** The source Sigma rules carried no `references:` field at all. A single entry pointing at this file's own published URL has been added, satisfying both the project convention and `sigma check`'s reference requirement.
- **Missing `id` meta field added (both surviving YARA rules).** The source YARA rules had no `id` field in their `meta:` block. Fresh UUIDs have been minted for both.
- **YARA condition reordered, logic unchanged.** Both surviving rules now gate on `uint16(0) == 0x5A4D` before string evaluation (cheap check first), matching project convention for scanner performance. The underlying boolean logic is identical to the source.

### Cut Rules (genuine noise — not routed to the feed)

- **YARA "Winsock Initialization Pattern"** (source Rule 4) — cut. Every component is individually ubiquitous in legitimate networking software: the 6-byte wildcard pattern targets a generic `mov [reg+offset], 0x00000202` instruction shape that any Winsock-2.2-initializing program compiles to; `WSASocket` and `connect` are common Winsock API name strings present in essentially all software that opens a raw socket; `COMPUTERNAME` is a near-universal environment variable name. Requiring all four does not rescue the rule — it describes "a Windows program that uses sockets and reads an environment variable," a condition an enormous population of legitimate remote-access, monitoring, and networking tools satisfies. No goodware-corpus validation could plausibly clear this. No atomic value to route — every component is a generic API/pattern reference, not an indicator.
- **YARA "Rust Compilation Signature"** (source Rule 5, source-labeled MEDIUM severity) — cut. `rust_panic`, `std::panic`, and the `assert_eq!`-style assertion message are Rust-toolchain runtime artifacts present in essentially every Rust-compiled binary, malicious or not — "2 of them" only establishes "this is a Rust binary," not "this is malicious." The `$file_size` component compounds the defect: it encodes the value 440,832 as a raw 4-byte pattern searched for as file *content*, rather than using YARA's `filesize` condition keyword — an anti-pattern with high coincidental-match risk that also doesn't test what its own comment claims. No atomic to route; these are compiler-emitted artifacts, not indicators.
- **Sigma "DLL Injection Attempt"** (source Rule 2, id `647b28c9-0fb3-48f7-945b-f2fe08eee8e2`) — cut. The rule's primary `dll_injection` selector checks the `process_creation` `CommandLine` field for API-call syntax (`LoadLibrary*nethost.dll`, `GetProcAddress*WSASocket`) — text that describes a Win32 API call, not something that appears in a process's launch arguments; no real Windows command line is ever invoked this way, so this selector cannot fire. With that branch inert, the rule's actual firing condition collapses to `suspicious_loader and suspicious_dll_path`: a parent process from a list of five of the most common Windows processes (`explorer.exe`, `svchost.exe`, `rundll32.exe`, `regsvcs.exe`, `regasm.exe`) combined with a launched process running from Temp/AppData/Public — a pattern that matches an enormous fraction of ordinary software installs and updates and, critically, never references nethost.dll or DLL injection in any way once the broken clause is removed. There is no clean fix within the `process_creation` logsource — genuine DLL-load detection requires an `image_load` event, a different logsource not present in the original rule, and even a rewrite would inherit the goodware-collision risk described below. No salvage attempted; see "Goodware Collision Risk" below for why a filename-based rewrite would not be safe regardless.
- **Suricata "Suspicious DNS-over-TCP" (Signature 2, sid 1001003)** — cut; the rule is internally self-contradictory and cannot match any traffic as written. `content:"|00|"; depth:1` requires the payload's first byte to be `0x00` (the high byte of a DNS-over-TCP length prefix under 256 bytes — true of the overwhelming majority of ordinary DNS-over-TCP traffic). The unanchored-buffer PCRE `/^[^\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\xff]*$/` is then evaluated against the same payload with no offset or relative modifier, and its `^` anchor requires the very first byte to fall *outside* the `\x00-\x09` range — directly contradicting the `content` match that just required that first byte to be `0x00`. A rule requiring both conditions simultaneously can never fire on any packet. No atomic to route; this was a proposed heuristic, not an observed indicator.

### Atomics Routed to the IOC Feed

- **YARA "Hardcoded File Hash Detection"** (source Rule 1) — the SHA256, MD5, and SHA1 values are legitimate, already-present atomics (Robustness 0 per the tiering rubric: a hash's sole discriminator is the hash itself, regardless of implementation). Separately, the source's mechanism for matching them — treating each hash as a literal ASCII string to search for inside a scanned file — cannot function as file identification: a file's raw bytes do not contain a text copy of their own hash, so as written this branch could only ever match some *other* file that happens to reference the hash's hex text (a report, a hash list, a SIEM export) — never nethost.dll itself. Both the robustness disposition and the mechanism defect point to the same outcome: the hash values belong in the feed, not in a rule. All three are already present in [`arsenal-237-nethost-dll.json`](/ioc-feeds/arsenal-237-nethost-dll.json) under `file_hashes`.
- **Suricata "Connection to C2 Addresses" (Signature 1, sids 1001001 and 1001002)** — pure destination IP:port match rules (`alert tcp any any -> 8.8.8.8 53` / `-> 127.0.0.1 53`), Cut-tier per the project's Suricata checklist regardless of the `content:"GET";http_method` addition on sid 1001001, which adds no discriminating value (`GET` is one of the most common 3-byte strings in all HTTP traffic). `8.8.8.8` is Google's public DNS resolver — one of the most widely used IP addresses on the internet — making a standalone signature against it a severe false-positive risk independent of the usual infrastructure-rotation durability concern. sid 1001002's destination, `127.0.0.1`, is the loopback address: traffic to it never leaves the host's kernel network stack, so a standard network-positioned Suricata sensor (SPAN port or in-line NIC) would never observe this traffic at all — flagged as broken/unfireable from a typical deployment position, independent of the IP-match precision concern. Both `8.8.8.8:53` (TCP) and `127.0.0.1:53` (TCP) are already present in [`arsenal-237-nethost-dll.json`](/ioc-feeds/arsenal-237-nethost-dll.json) under `network_indicators.ips`.

### Goodware Collision Risk: nethost.dll Is a Real Microsoft Filename

nethost.dll is not an attacker-coined name. It ships as part of the official .NET runtime hosting components (the native hosting library used by applications that host the CLR from native code), and Microsoft-built binaries commonly embed their own filename in a version-info resource — meaning the legitimate Microsoft nethost.dll, and any application that references it by name in an import table or `LoadLibrary` call, can plausibly contain the literal text "nethost.dll." This project has already documented one collision of exactly this class: a YARA rule anchored on the bare string "RuntimeBroker" — the name of a genuine Windows system process — in `dual-rat-analysis-detections.md`, cut for the identical reason.

Two rules in the source draft depended on this filename as a discriminator: YARA Rule 1's `$filename = "nethost.dll" nocase` branch (see "Atomics Routed to the IOC Feed" above — since the branch is OR'd against the non-functional hash-text matches, it was, practically speaking, the rule's entire real-world behavior) and Sigma Rule 2's `dll_injection`/`suspicious_dll_path` selectors (see "Cut Rules" above, cut on independent broken-logic grounds as well). No surviving rule in this file keys on the bare filename; both surviving YARA rules and the surviving Sigma rule anchor on the module's C2 command-dispatch and protocol artifacts, none of which the legitimate Microsoft component would contain.

### C2 Protocol Structure Unconfirmed — No Durable Network Signature Beyond the Retired IP Atomics

nethost.dll's hardcoded proxy targets do not correspond to a confirmed, observed C2 protocol exchange. The malware's own analysis assesses the 8.8.8.8 proxy-endpoint role at MODERATE confidence (70%) and a possible test/honeypot-evasion purpose for the target pairing at LOW confidence (50%) — no URI, header, or session structure beyond the destination IP:port pair and a bare `GET` reference is available. The two IP:port atomics are already routed to the feed (above); a Suricata rule keyed on either destination alone would be both non-durable (IP rotation) and, in 8.8.8.8's case, a severe false-positive risk against globally common DNS infrastructure.

### Capabilities Documented in the IOC Feed Without Dedicated Rule Coverage

The IOC feed documents several capabilities with no dedicated event-level coverage here: DLL-load/injection of nethost.dll into a target process (T1055 — the source Sigma selector attempting this coverage matched process-creation command-line text against API-call syntax that never appears in a real command line and could not be salvaged within that logsource; genuine coverage requires `image_load` telemetry or EDR-level injection hooks, neither available in the original evidence); registry-based persistence (documented at only POSSIBLE 40% confidence and explicitly not observed for nethost.dll itself — "nethost.dll itself does not modify registry" per the malware analysis); and the module's broader 14-command C2 set beyond the PowerShell-dispatch subset covered above (process enumeration, network configuration discovery, account discovery, antivirus/firewall discovery, clipboard theft) — none of these leave a distinguishing static string in nethost.dll beyond generic command-name text too common to anchor a rule on its own.

### What Would Enable Stronger Coverage

- **Confirmed C2 protocol structure** — capturing an actual session over the TCP/53 channel (URI path, header pattern, or raw byte structure) would replace the retired IP-only atomics with a genuine, durable Suricata signature.
- **Goodware corpus validation** — neither surviving YARA rule has been run against a broad clean-software corpus; a documented zero-FP result is the explicit precondition for reconsidering the Hunting-tier Rust/C2-string rule for Detection.
- **DLL-load or injection telemetry** — `image_load` (Sysmon Event ID 7) or EDR API-hook telemetry capturing the actual `LoadLibrary`/injection event the source Sigma rule attempted (and failed) to describe via command-line text would enable a genuine injection-detection rule for this component.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
