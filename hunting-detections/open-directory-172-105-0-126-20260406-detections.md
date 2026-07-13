---
title: "Detection Rules — OpenStrike Beacon Toolkit on Open Directory 172.105.0.126"
date: '2026-04-06'
layout: post
permalink: /hunting-detections/open-directory-172-105-0-126-20260406-detections/
thumbnail: /assets/images/cards/open-directory-172-105-0-126-20260406.png
hide: true
---

**Campaign:** OpenStrike-CSBeacon-Toolkit-172.105.0.126
**Date:** 2026-04-06
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/

---

## Detection Coverage Summary

OpenStrike is a custom, purpose-built C2 toolkit — a C implant, a cross-platform Python implant, and a five-stage standalone shellcode loader chain — recovered from an open directory alongside a cracked, self-protected Cobalt Strike 3.x DLL beacon sharing the same operator infrastructure and a custom Malleable C2 profile. Coverage below spans file-level detection of the OpenStrike and Cobalt Strike binaries, a behavioral hunting lead for the Python beacon's in-memory shellcode-staging pattern, and network-layer detection of the shared Malleable C2 user-agent. The campaign's C2 IP/port, loader-chain filenames, and beacon output submission path are single hardcoded literals with no surviving behavioral signal once removed — they are carried in the IOC feed rather than as standalone rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 4 | 0 | T1071.001, T1573.001, T1059.006, T1620 | 0 |
| Sigma | 1 | 1 | T1071.001, T1059.006, T1620 | 3 |
| Suricata | 1 | 0 | T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- OpenStrike Universal Beacon self-identification banner, paired with the RSA-2048 modulus prefix and `/qz99` staging path — hardcoded operator constants with no legitimate collision, unique to this Python implant (YARA Detection).
- Cobalt Strike Malleable C2 `MALC` User-Agent suffix — covered at the file (YARA), proxy-log (Sigma), and network (Suricata) layers; survives full infrastructure rotation since it depends only on the reused Malleable C2 profile, not this campaign's specific IP (Detection, all three engines).

**Atomics routed to the IOC feed:** the C2 destination `172.105.0.126:8443`, the five OpenStrike loader-chain binary names (`run.exe`, `sc_loader.exe`, `veh_loader.exe`, `dbg_loader.exe`, `stager.exe`), and the beacon output submission path `/submit.php` are transient, trivially-renameable indicators — each of the five retired rules keyed solely on one of these hardcoded values, and removing the literal leaves no behavior to detect. All are carried in [`open-directory-172-105-0-126-20260406-iocs.json`](/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json); see Coverage Gaps for detail on each. Block/hunt them via the feed.

---

## Multi-Family Organization

This campaign recovered two distinct code families sharing operator infrastructure: the custom **OpenStrike** toolkit (C beacon, Python beacon, and a five-stage shellcode loader chain) and a co-hosted, cracked **Cobalt Strike 3.x** DLL beacon configured with the same Malleable C2 profile. Rules below are organized by type and tier first; within each tier, rules are grouped under a bold family label.

---

## YARA Rules

### Detection Rules

**OpenStrike**

#### OpenStrike C Beacon Debug Strings + AES/HMAC Crypto Constants

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography)
**Confidence:** HIGH
**False Positives:** None known — the primary anchor requires either the `OpenStrike Beacon starting...` startup banner or the `Registration successful` + `beacon ready` status-message pairing, both distinctive branded strings; the secondary anchor group (`aes_cbc_encrypt`, `hmac_sha256`, the shared AES IV, and the GCC compiler banner) is generic in isolation but never sufficient on its own without the primary clause.
**Blind Spots:** A stripped-logging release build that removes every banner/status print string evades this rule; the generic crypto-function names and compiler banner carry no weight alone.
**Validation:** Scan `beacon.exe` (hash1 below) — must match; a benign C application linking a stock AES/HMAC library must NOT fire (its banner and status strings differ).
**Deployment:** Endpoint AV/EDR file scan, memory scanning of process images matching the beacon's execution pattern.

```yara
/*
   Yara Rule Set
   Identifier: OpenStrike Beacon Toolkit + Cobalt Strike 3.x Tripwired Loader
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_OpenStrike_C_Beacon {
   meta:
      description = "Detects the OpenStrike custom C C2 beacon (beacon.exe) via its operator-written startup/status debug strings, paired with AES-CBC/HMAC-SHA256 crypto function references and the shared MinGW GCC 15 build banner"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/"
      date = "2026-04-06"
      hash1 = "7d6a17754f086b53ee294f5ccd60b0127f921520ce7b64fea0aebb47114fb5d2"
      hash2 = "5ee00147140b084f93d2144c2ee5c0d4d125ff1c"
      hash3 = "96f9adb7ee00c44bc5f523d1f1dc8715"
      family = "OpenStrike"
      malware_type = "C2 Beacon"
      campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
      id = "c5b35b66-2737-5545-a27e-b67969ef4f36"
   strings:
      $s1 = "[*] OpenStrike Beacon starting..." ascii
      $s2 = "[+] Registration successful" ascii
      $s3 = "beacon ready" ascii
      $s4 = "abcdefghijklmnop" ascii
      $s5 = "aes_cbc_encrypt" ascii
      $s6 = "hmac_sha256" ascii
      $compiler = "GCC: (GNU) 15-win32" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 409600 and
      ($s1 or ($s2 and $s3)) and
      ($s4 or $s5 or $s6 or $compiler)
}
```

#### OpenStrike Shellcode Loader Chain Debug Strings

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positives:** None known — the crash-handler and entry-point-discovery debug strings (SEH/VEH exception format strings, INT3-offset messages) are distinctive to this loader family's error-handling code; no legitimate software combination matches these exact format strings together.
**Blind Spots:** A release build that strips debug/crash-handler print statements evades this rule; covers `run.exe` via the `$run` + `$compiler` pairing specifically, since it lacks the SEH/VEH/INT3 strings used by the other four binaries.
**Validation:** Scan `run.exe` (hash1 below), or any of `sc_loader.exe`/`veh_loader.exe`/`dbg_loader.exe`/`stager.exe` — must match; a benign C/C++ application with its own exception-handling debug output must NOT fire (the specific format-string combinations differ).
**Deployment:** Endpoint AV/EDR file scan, memory scanning.

```yara
rule TOOLKIT_OpenStrike_Loader_Chain {
   meta:
      description = "Detects OpenStrike's standalone shellcode loader chain (run.exe, sc_loader.exe, veh_loader.exe, dbg_loader.exe, stager.exe) via operator-written crash-handler and entry-point-discovery debug strings shared across the progressive SEH/VEH/INT3 capability chain, paired with the shared MinGW GCC 15 build banner"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/"
      date = "2026-04-06"
      hash1 = "821f815fab92fee03e2be44ad5370a953db085cd359a99519a2ddb7316b0d273"
      hash2 = "720ea472060e080145927d33e18dca9b8b1eafa5"
      hash3 = "d677794618461b3bf7d405a8297d5df4"
      family = "OpenStrike"
      malware_type = "Shellcode Loader"
      campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
      id = "1c8e4dfb-3f93-5a20-ba24-9896e2c32761"
   strings:
      $veh = "[CRASH] code=0x%08lX RIP=0x%llX" ascii
      $seh = "[!] EXCEPTION code=0x%08lX addr=%p (base+0x%llX)" ascii
      $dbg = "[*] INT3 set at offset %lu (RVA 0x%llX)" ascii
      $run = "[+] %lu @ %p exec" ascii
      $load = "[*] Loading %s" ascii
      $compiler = "GCC: (GNU) 15-win32" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 409600 and
      (($veh and $load) or ($seh and $load) or ($dbg and $load) or ($run and $compiler))
}
```

#### OpenStrike Python Universal Beacon Self-Identification Banner

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.006 (Python), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known — `OpenStrike Universal Beacon` is a self-identifying branded string with no plausible legitimate collision; the RSA-2048 modulus prefix and `/qz99` staging path are hardcoded operator constants.
**Blind Spots:** A rebrand that removes the self-identification banner from the Python source evades this rule; a build using a regenerated RSA keypair changes the modulus prefix (the banner string alone still carries the rule).
**Validation:** Scan `beacon_universal.py` — must match; a benign Python script coincidentally using ctypes and a hardcoded IV must NOT fire (it lacks the OpenStrike banner and campaign-specific constants).
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown Python scripts.

```yara
rule TOOLKIT_OpenStrike_Python_Beacon {
   meta:
      description = "Detects the OpenStrike cross-platform Python beacon (beacon_universal.py) via its self-identification banner, corroborated by the distinctive /qz99 staging URI, the hardcoded RSA-2048 public key modulus prefix, or the paired bof_executor + shared AES IV strings"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/"
      date = "2026-04-06"
      family = "OpenStrike"
      malware_type = "C2 Beacon"
      campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
      id = "8064ca73-601a-5985-a11b-67d1fcd50397"
   strings:
      $desc = "OpenStrike Universal Beacon" ascii
      $bof_key = "bof_executor" ascii
      $iv = "abcdefghijklmnop" ascii
      $rsa_mod = "9f12c9cb6582f379088600e6cdb7ac80" ascii
      $qz99 = "/qz99" ascii
   condition:
      filesize < 204800 and
      $desc and
      ($rsa_mod or $qz99 or ($bof_key and $iv))
}
```

**Cobalt Strike 3.x**

#### Cobalt Strike 3.x Tripwired ReflectiveLoader + MALC Malleable Profile

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols — MALC Malleable C2 profile), T1620 (Reflective Code Loading — tripwired entry point)
**Confidence:** HIGH
**Rationale:** The MALC User-Agent string (`$ua`) is the mandatory anchor — a distinctive, multi-byte Malleable C2 profile artifact with no legitimate collision. The entry-point tripwire bytes (`66 90 CC`) are retained as one option within a 2-of-5 corroborating group backed by four solid string alternatives, since a 3-byte pattern alone is too short to anchor a rule reliably; no match path is carried by the tripwire bytes alone.
**False Positives:** None known — the MALC User-Agent suffix is a distinctive Malleable C2 profile artifact absent from legitimate software; requiring 2 corroborating strings from the original DLL name, ReflectiveLoader export, spawn-to path, shared custom AES IV, or entry-point tripwire bytes further reduces coincidental collision risk.
**Blind Spots:** A rebuilt beacon using a different Malleable C2 profile (no MALC UA) evades this rule entirely; a release build with a default rundll32 spawn-to and unmodified reflective loader would also evade if it additionally used a different profile UA.
**Validation:** Scan `beacon_patched.x64.dll` (hash1 below) — must match; a stock/default Cobalt Strike 3.x beacon DLL with the default Malleable C2 profile must NOT fire (its User-Agent lacks the MALC suffix).
**Deployment:** Endpoint AV/EDR file scan, memory scanning of rundll32.exe-hosted or reflectively-loaded modules.

```yara
rule MALW_CobaltStrike3x_TripwiredReflectiveLoader {
   meta:
      description = "Detects the operator-modified Cobalt Strike 3.x DLL beacon (beacon_patched.x64.dll) sharing this campaign's Malleable C2 profile via its distinctive MALC User-Agent suffix, corroborated by the original DLL name, ReflectiveLoader export, sysnative rundll32 spawn-to path, the shared custom AES IV, or the entry-point tripwire bytes (66 90 CC / xchg ax,ax; int3) that redirect the ReflectiveLoader export RVA to crash standard reflective-injection tooling"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/"
      date = "2026-04-06"
      hash1 = "7a1a7659ec4201ecbca782bcedf9d4079265137279a490368309df3bd39297a4"
      hash2 = "add3893c3652947ff821a6da5fad774cc041bb73"
      hash3 = "2a6a3d499bb3c666f3b4bc5905a866f3"
      family = "CobaltStrike"
      malware_type = "C2 Beacon"
      campaign = "OpenStrike-CSBeacon-Toolkit-172.105.0.126"
      id = "23095eb8-e1a4-565d-a5c9-9c1f45ad4eaf"
   strings:
      $reflective_export = "ReflectiveLoader" ascii
      $original_name = "beacon.x64.dll" ascii
      $tripwire = { 66 90 CC }
      $ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" ascii
      $spawn = "%windir%\\sysnative\\rundll32.exe" ascii
      $aes_iv = "abcdefghijklmnop" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 409600 and
      $ua and
      2 of ($original_name, $reflective_export, $spawn, $aes_iv, $tripwire)
}
```

---

## Sigma Rules

### Detection Rules

**Cobalt Strike 3.x**

#### Cobalt Strike Malleable C2 Profile MALC User-Agent in Proxy Traffic

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** The match is tail-anchored (`endswith: 'MALC)'`) rather than a bare substring, consistent with the sibling Suricata rule's tail-anchored match — this reduces the already-low likelihood of an incidental substring collision.
**False Positives:** Internal applications or monitoring tools with custom user-agent strings ending in the substring `MALC)` (verify against known software inventory before tuning out).
**Blind Spots:** A rebuilt beacon using a different Malleable C2 profile (no MALC suffix) evades this rule entirely; requires proxy logging with full User-Agent header visibility.
**Validation:** Replay proxy logs containing the MALC-suffixed UA — must match; ordinary browser/application traffic must NOT fire.
**Deployment:** Proxy logs, SIEM, network TAP with HTTP inspection.

```yaml
title: Cobalt Strike Malleable C2 Profile MALC User-Agent in Proxy Traffic
id: 9e3c7a15-6f2b-4d84-a1c9-8b5e2d7f3a61
status: experimental
description: >-
  Detects the Cobalt Strike 3.x Malleable C2 profile User-Agent string ending
  in the MALC suffix (full string: Mozilla/5.0 (compatible; MSIE 9.0;
  Windows NT 6.1; WOW64; Trident/5.0; MALC)). This non-standard suffix is a
  distinctive indicator of a configured Malleable C2 profile and does not
  appear in any known legitimate browser or application user-agent string.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/
author: The Hunters Ledger
date: 2026-04-06
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|endswith: 'MALC)'
    condition: selection
falsepositives:
    - >-
      Internal applications or monitoring tools with custom user-agent
      strings ending in the substring MALC) (verify against known software
      inventory before tuning out)
level: high
```

### Hunting Rules

**OpenStrike**

#### OpenStrike Python Beacon Ctypes VirtualAlloc Shellcode Injection

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1620 (Reflective Code Loading)
**Confidence:** HIGH for the technique pairing; MODERATE for false-positive discrimination
**Rationale:** Python interpreter execution combined with command-line references to both `ctypes` and `VirtualAlloc` is a durable technique-level combination — it survives the malware being renamed or rewritten, since it is keyed on the in-memory shellcode-staging technique rather than a filename. Legitimate security-research and automation tooling produce the same combination often enough that it needs analyst triage rather than blind alerting, so `level` is set to medium and the rule sits in Hunting rather than Detection.
**False Positives:**
- Security research tools or CTF scripts using ctypes with VirtualAlloc in Python.
- Legitimate automation scripts performing memory-mapped operations via ctypes.
**Deployment:** Endpoint EDR (Sysmon Event ID 1), script block logging, SIEM; analyst review of hits, filtering by script path or user account in high-noise environments.

```yaml
title: OpenStrike Python Beacon Ctypes VirtualAlloc Shellcode Injection
id: 1d6b4e82-9f3c-4a17-b5d8-2e7c9a6f1b34
status: experimental
description: >-
  Detects a Python process with command-line arguments referencing ctypes
  and VirtualAlloc, matching the OpenStrike beacon_universal.py
  cross-platform shellcode injection pattern. The Python beacon uses
  ctypes.windll to call VirtualAlloc for RWX memory allocation and
  CreateThread for shellcode execution, enabling in-memory payload staging
  without dropping a compiled binary.
references:
    - https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/
author: The Hunters Ledger
date: 2026-04-06
tags:
    - attack.execution
    - attack.t1059.006
    - attack.stealth
    - attack.t1620
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_proc:
        Image|endswith: '\python.exe'
        CommandLine|contains|all:
            - 'ctypes'
            - 'VirtualAlloc'
    condition: selection_proc
falsepositives:
    - Security research tools or CTF scripts using ctypes with VirtualAlloc in Python
    - Legitimate automation scripts performing memory-mapped operations via ctypes
level: medium
```

---

## Suricata Signatures

### Detection Rules

**Cobalt Strike 3.x**

#### Cobalt Strike Malleable C2 MALC User-Agent Detected

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known — MALC is not a known legitimate user-agent substring; `endswith` anchors the match to the tail of the UA buffer for targeted fidelity; `nocase` catches case variants.
**Blind Spots:** A rebuilt beacon using a different Malleable C2 profile (no MALC suffix) evades this rule entirely; requires HTTP header visibility (no effect against fully encrypted/non-HTTP channels).
**Validation:** Replay a PCAP containing the MALC-suffixed UA — must alert; ordinary browser/application HTTP traffic must NOT.
**Deployment:** Perimeter IDS/IPS, proxy with HTTP user-agent logging.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Cobalt Strike Malleable C2 MALC User-Agent Detected"; flow:established,to_server; http.user_agent; content:"MALC)"; endswith; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9001003; rev:3; metadata:author The_Hunters_Ledger, date 2026-04-06, reference https://the-hunters-ledger.com/hunting-detections/open-directory-172-105-0-126-20260406-detections/;)
```

> **Community contribution:** The `endswith` anchor on this rule was suggested by [Anthony Vigil](https://www.linkedin.com/in/anthony-vigil/), who noted that anchoring the content match to the tail of the UA buffer improves targeted fidelity and engine efficiency over a bare substring match.

---

## Coverage Gaps

**C2 IP:Port atomic (2 rules).** A network_connection Sigma selector and a Suricata TCP signature each keyed solely on the C2 destination `172.105.0.126:8443` — a pure IP/port match with no content or behavioral anchor, and removing the literal leaves nothing to detect. The indicator is already carried in [`open-directory-172-105-0-126-20260406-iocs.json`](/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json) (`network_indicators.ipv4`). Block it via the feed; the file-layer YARA rules and the MALC User-Agent Sigma/Suricata rules above provide durable coverage that survives infrastructure rotation.

**Loader-chain binary filenames (1 rule).** A process_creation Sigma selector matched only the five operator-chosen loader filenames (`run.exe`, `sc_loader.exe`, `veh_loader.exe`, `dbg_loader.exe`, `stager.exe`) with no command-line or parent-process qualifier — a pure filename match that a simple rename defeats, and `run.exe` in particular is a generic name carrying real collision risk. All five names are already carried in the feed (`file_hashes.filenames`). The YARA loader-chain rule above provides durable file-layer coverage of the same binaries via crash-handler and entry-point-discovery debug strings, which survive a rename. **What would enable a behavioral rule:** command-line or parent-process telemetry for how these loaders are actually invoked (a consistent staging parent process or argument pattern) — none was captured in the available evidence.

**Beacon output submission path (2 rules).** A Sigma proxy selector and a Suricata HTTP signature both keyed solely on the URI literal `/submit.php` with the GET method — removing the literal leaves an unanchored GET-to-port-8443 match with no distinguishing value (port 8443 is a common alternate-HTTPS port used by many unrelated legitimate applications). The literal is carried in the feed as a new URL entry, `https://172.105.0.126:8443/submit.php`, at MODERATE confidence: the feed's existing `network_indicators.urls` list documents the C beacon's output-submission endpoint as `/submit` (POST, encrypt-then-MAC AES-128-CBC + HMAC-SHA256 envelope) — a plain-path variant without the `.php` extension and using POST rather than GET. The `/submit.php` GET pattern this rule targeted may reflect a distinct observation (the co-hosted Cobalt Strike DLL beacon's GET-based output-accumulator behavior, described elsewhere in the feed as targeting the Malleable C2 `get_uri`) rather than the C beacon's documented `/submit` path — the two are carried as separate feed entries pending reconciliation rather than merged or discarded.

**T1027 / T1027.002 — Obfuscation and Software Packing (OpenStrike).** The OpenStrike loaders do not use a standard commercial packer; entropy-based YARA conditions for the specific shellcode blobs would require per-sample calibration. A rule based on PE section entropy ranges would produce unacceptable FP rates across packed legitimate software. Higher-confidence coverage would require extraction and analysis of additional shellcode blobs to identify a shared byte sequence.

**T1573.001 / T1573.002 — Symmetric and Asymmetric Cryptography (OpenStrike).** The Trinity Protocol (AES-128-CBC + HMAC-SHA256 + RSA-2048) key material is embedded in the binaries but is not unique enough in isolation to warrant a standalone rule beyond the OpenStrike-specific strings already covered above (T1573.001 is folded into the C-beacon YARA rule's secondary anchors). The RSA modulus prefix `9f12c9cb6582f379088600e6cdb7ac80` is covered adequately as a corroborating string in the Python beacon YARA rule; a standalone T1573.002 rule would be redundant.

**T1622 — Debugger Evasion (OpenStrike dbg_loader.exe).** The INT3-based entry-point discovery technique used by dbg_loader.exe is detectable behaviorally only through kernel-level debugger attachment monitoring, which is not available in standard Sysmon or proxy log sources. Detection would require EDR telemetry with API hooking coverage for DebugActiveProcess or WaitForDebugEvent. If such telemetry is available, a Sigma rule targeting dbg_loader.exe spawning a child process after a WaitForDebugEvent call would be viable. (The YARA loader-chain rule above detects the file-level capability to perform this technique; it does not confirm the technique executed.)

**T1497.001 — System Checks / Sandbox Detection (check_ntdll.py).** The check_ntdll.py EDR hook detection utility reads raw ntdll.dll at a specific RVA to detect inline hooks. Coverage would require file-access monitoring with RVA-level granularity not available in standard Windows event logs. Detection is partially covered by the Python ctypes Hunting rule above if check_ntdll.py is invoked via the same Python process, but direct behavioral coverage of the hook-check is not achievable with standard log sources.

**T1132.002 — Non-Standard Encoding (Malleable C2 Transform VM).** The 17-opcode Transform VM encodes C2 traffic in a campaign-specific way. Without a known plaintext anchor derived from the transform bytecode for this specific profile, a Suricata content-based signature for the encoded traffic pattern cannot be written reliably. Network-layer detection of the underlying C2 destination is carried in the IOC feed (`172.105.0.126:8443`) rather than as a standalone IP-match rule — see "C2 IP:Port atomic" above.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
