---
title: "Detection Rules — Open Directory at 193.56.255.154 (XiebroC2 v3.1 and Covenant C2)"
date: '2026-04-03'
layout: post
permalink: /hunting-detections/open-directory-193-56-255-154-xiebroc2-detections/
thumbnail: /assets/images/cards/open-directory-193-56-255-154-xiebroc2.png
hide: true
---

**Campaign:** OpenDirectory-XiebroC2-Covenant-193.56.255.154
**Date:** 2026-04-03
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-193-56-255-154-xiebroc2/

---

## Detection Coverage Summary

This open directory hosted three malicious payloads from a single staging server — a Go-based XiebroC2 v3.1 TCP implant, two builds of a Covenant C2 HTTP GruntStager (one standalone PE, one PowerShell-wrapped), and a non-operational proof-of-concept DLL. Coverage below is organized by rule type and tier; atomic indicators already captured in the IOC feed (the XiebroC2 C2 IP/port and the `main.exe` filename) are not duplicated as standalone rules.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 1 | T1027, T1036, T1055, T1055.012, T1059.001, T1071.001, T1140, T1571, T1573.001, T1573.002, T1620 | 0 |
| Sigma | 2 | 2 | T1059.001, T1059.003, T1071.001, T1140, T1620 | 1 |
| Suricata | 2 | 0 | T1036, T1071.001, T1571 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The `github.com/Ne0nd0g/go-clr` import path, the `WindosVersion` pclntab typo, and the custom RunPE parser error strings are compile-time artifacts baked into any binary built from XiebroC2 3.1 source — they survive AES-key rotation and are the strongest family anchors in the set (YARA Detection).
- The Sigma CLR-load rule (image_load of `mscoree.dll`/`clr.dll` from a non-.NET-host process) requires no filename or campaign-specific literal at all — it detects the underlying reflective-CLR-hosting technique itself and is the most durable rule in this file (Sigma Detection, Robustness 3).

**Atomics routed to the IOC feed:** the XiebroC2 C2 endpoint (`193.56.255.154:4444/TCP`) and the implant filename `main.exe` are transient/host-correlation indicators already present in [`opendirectory-193-56-255-154-20260403-iocs.json`](/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json) — no new feed entries were required. One original Suricata rule (bare IP:port match, no content anchor) and one original Sigma rule (bare `ParentImage: main.exe` match, no injection-specific logic) keyed solely on these values with nothing behavioral surviving their removal; see Coverage Gaps for the full reasoning.

---

## Multi-Family Organization

This campaign involves three malicious payloads from a single staging server:
- **XiebroC2 v3.1** — Go x86 TCP implant (`main.exe`)
- **Covenant C2 GruntStager** — .NET HTTP stager (PE build: `GruntHTTP.exe`; PS build: `GruntHTTP.ps1`)
- **PowerShell Fileless Loader** — Base64+Deflate wrapper delivering Covenant Build 2

Rules are grouped by family within each tier subsection (Detection Rules / Hunting Rules) inside each rule-type section below, per the site-wide type → tier → family layout.

---

## YARA Rules

```
/*
   Yara Rule Set
   Identifier: OpenDirectory Multi-Family MaaS — 193.56.255.154 (XiebroC2 v3.1 / Covenant GruntStager / PowerShell Fileless Loader)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/
```

### Detection Rules

**XiebroC2 v3.1**

#### XiebroC2 v3.1 Go TCP Implant — Source-Code Artifact Combination

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1573.001 (Symmetric Cryptography — AES-128-ECB key), T1620 (Reflective Code Loading — go-clr CLR hosting import), T1055.012 / T1055 (RunPE injection error strings)
**Confidence:** HIGH
**False Positives:** None known — the hand-typed AES key literal, the pclntab typo (`WindosVersion`), the `go-clr` offensive-tool import path, and the custom RunPE parser error strings are all compile-time artifacts embedded only in binaries built from XiebroC2 3.1 source; no legitimate Go binary carries any of them.
**Blind Spots:** A rebuild that simultaneously rotates the AES key, fixes the source typo, and drops the go-clr dependency would evade; the rule targets on-disk/in-memory Go binaries, not a decrypted-traffic-only variant.
**Validation:** Scan a XiebroC2 3.1-lineage sample — 3 of the 8 listed strings must match; a benign Go binary (including one that legitimately embeds .NET interop) must NOT fire.
**Deployment:** Endpoint AV/EDR disk scan, memory scanner targeting live Go processes.

```yara
rule RAT_XiebroC2_v31_Go_TCP_Implant {
   meta:
      description = "Detects XiebroC2 v3.1 Go TCP implant via a combination of hardcoded AES-128-ECB key, source-code typo in its pclntab symbol table (WindosVersion), vendored offensive go-clr CLR hosting library import, and unique RunPE PE-parser error strings. All eight indicators are static compile-time artifacts embedded in any binary built from XiebroC2 3.1 source; the rule requires any 3 to avoid dependence on any single renameable or rotatable literal."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
      date = "2026-04-03"
      family = "XiebroC2"
      malware_type = "RAT"
      campaign = "OpenDirectory-XiebroC2-Covenant-193.56.255.154"
      id = "90df8d57-e457-57d1-b7c5-2b318c32508e"
   strings:
      $s1 = "QWERt_CSDMAHUATW" ascii
      $b1 = { 51 57 45 52 74 5F 43 53 44 4D 41 48 55 41 54 57 }
      $s2 = "main/Helper/sysinfo.WindosVersion" ascii
      $s3 = "github.com/Ne0nd0g/go-clr" ascii
      $s4 = "DOS image header magic string was not MZ" ascii
      $s5 = "PE Signature string was not PE" ascii
      $s6 = "ClientUnstaller" ascii
      $s7 = "NtQueryInformationProcess returned NTSTATUS:" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 25MB and
      3 of ($s1, $b1, $s2, $s3, $s4, $s5, $s6, $s7)
}
```

**Covenant C2 GruntStager**

#### Covenant C2 GruntStager Combined Build Detection

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols — HTTP C2), T1036 (Masquerading — Chrome 41 UA), T1573.002 (Asymmetric Cryptography — RSA key exchange, MODERATE)
**Confidence:** HIGH
**False Positives:** None known — the session token and build ID are GUID/hex-format values unique to this Covenant listener; no legitimate software embeds them.
**Blind Spots:** A newly-configured Covenant listener with a different session token and build ID evades this rule entirely; targets on-disk .NET PE files, not memory-only Grunt payloads that never touch disk.
**Validation:** Scan either GruntStager build — both must match on the shared token+build-ID pair; an unrelated legitimate .NET PE must NOT fire.
**Deployment:** Endpoint AV/EDR disk scan targeting .NET PE files; memory scanner targeting .NET processes performing `Assembly.Load()`.

```yara
rule RAT_Covenant_GruntStager_OpenDirectory {
   meta:
      description = "Detects both Covenant C2 GruntStager builds (the standalone GruntHTTP.exe PE stager and the PE extracted from the GruntHTTP.ps1 PowerShell wrapper) via a shared listener-level session token and build ID, combined with a Covenant framework identifier. Both builds share a single Covenant listener and produce identical values for the token and build ID fields."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
      date = "2026-04-03"
      hash1 = "3aa45ceff7070ae6d183c5aa5f0d771a79c7cf37fe21a3906df976bee497bf20"
      hash2 = "f0f4715a6d7063e7811502e9591f8265af0a2af6"
      hash3 = "7cfe0a039b61ec049b53e8e664036a6e"
      family = "Covenant"
      malware_type = "C2 Stager"
      campaign = "OpenDirectory-XiebroC2-Covenant-193.56.255.154"
      id = "3b6d459e-9f21-5052-b637-19d99758695b"
   strings:
      $s1 = "75db-99b1-25fe4e9afbe58696-320bea73" ascii wide
      $s2 = "a19ea23062db990386a3a478cb89d52e" ascii
      $s3 = "GruntStager" ascii wide
      $s4 = "CovenantCertHash" ascii wide
      $s5 = "// Hello World! {0}" ascii
      $s6 = "SESSIONID=1552332971750" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 50KB and
      $s1 and $s2 and
      1 of ($s3, $s4, $s5, $s6)
}
```

#### Covenant PowerShell Fileless Loader — GruntHTTP.ps1

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1027 (Obfuscated Files — Base64+Deflate payload), T1140 (Deobfuscate/Decode Files or Information), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positives:** None known — the session token is a unique GUID-format value; legitimate PowerShell scripts do not embed Covenant session tokens.
**Blind Spots:** A newly-configured Covenant listener with a different session token evades this exact rule (the four generic decode/load strings alone are still a Hunting-grade technique lead — see the Sigma coverage below); targets `.ps1` script files specifically.
**Validation:** Scan `GruntHTTP.ps1` or an equivalent loader from the same listener — must match; a legitimate PowerShell deployment script that happens to combine Deflate decompression with `Reflection.Assembly::Load()` (rare, but possible) warrants manual review before dismissal.
**Deployment:** Endpoint AV/EDR scan targeting `.ps1` files; AMSI telemetry; PowerShell ScriptBlock logging (Event ID 4104).

```yara
rule MALW_Covenant_PSFilelessLoader_GruntHTTP {
   meta:
      description = "Detects the GruntHTTP.ps1 PowerShell fileless loader that delivers Covenant GruntStager Build 2 via Base64+Deflate decoding and Reflection.Assembly::Load(). Anchored on the hardcoded Covenant session token alongside the decompression and reflective-loading pattern — a combination unique to this loader and not found in legitimate PowerShell scripts."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
      date = "2026-04-03"
      hash1 = "cff2d990f0988e9c90f77d0a62c72ca8e9bf567f0c143fdc3a914dce65edec98"
      hash2 = "a79cd499c68482e73852db2c70d4e06251a29d95"
      hash3 = "ac9b16b8bdf544db92f325a0901c5544"
      family = "Covenant"
      malware_type = "PowerShell Loader"
      campaign = "OpenDirectory-XiebroC2-Covenant-193.56.255.154"
      id = "b0a99479-67aa-5506-a4f2-5b1c7fa901fd"
   strings:
      $s1 = "75db-99b1-25fe4e9afbe58696-320bea73" ascii
      $s2 = "DeflateStream" ascii
      $s3 = "Reflection.Assembly" ascii
      $s4 = "FromBase64String" ascii
      $s5 = "MemoryStream" ascii
   condition:
      filesize < 100KB and
      $s1 and
      all of ($s2, $s3, $s4, $s5)
}
```

### Hunting Rules

**XiebroC2 v3.1**

#### XiebroC2 v3.1 Binary-Patchable Config — Padded-IPv4 Structural Pattern

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1571 (Non-Standard Port — C2 endpoint embedded in binary-patchable config)
**Confidence:** MODERATE
**Rationale:** The original rule keyed solely on the literal `193.56.255.154` padded to a fixed width — since that IP is already an atomic in the IOC feed, and the rule would evade entirely if the operator redeployed with a new C2 host, it failed the durability gate as written. Rewritten as a structural regex matching any dotted-quad IPv4 literal followed by 20+ trailing padding spaces (the actual binary-patchable config technique XiebroC2 3.1 uses so operators can repoint the C2 address without recompiling), paired with a family-specific anchor to hold precision. This version survives a C2 IP change; it is Hunting rather than Detection because the regex has not been validated against a broad goodware corpus.
**False Positives:** Unlikely but unverified — the padded-IPv4 + trailing-space pattern combined with a XiebroC2 source artifact has not been tested against a broad goodware corpus; a benign installer that happens to embed a long space-padded dotted-quad string is theoretically possible.
**Deployment:** Endpoint disk scan; also effective as a memory scan on running Go processes; intended to catch future XiebroC2 3.1-lineage builds regardless of the operator's chosen C2 IP.

```yara
rule RAT_XiebroC2_v31_PaddedConfig_Structural {
   meta:
      description = "Detects XiebroC2 v3.1's binary-patchable configuration format — a space-padded fixed-width IPv4 literal (20+ trailing spaces) paired with a family-specific source artifact. XiebroC2 stores its C2 address as a fixed-width field so operators can binary-patch a new IP into a compiled build without recompilation; this structural pattern is independent of any single C2 IP value and survives infrastructure rotation, unlike a rule anchored on 193.56.255.154 alone."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
      date = "2026-04-03"
      family = "XiebroC2"
      malware_type = "RAT"
      campaign = "OpenDirectory-XiebroC2-Covenant-193.56.255.154"
      id = "116b89d8-ee1b-50f2-b45e-9f09332ddb67"
   strings:
      $re_ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {20,}/ ascii
      $anchor1 = "github.com/Ne0nd0g/go-clr" ascii
      $anchor2 = "main/Helper/sysinfo.WindosVersion" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 25MB and
      $re_ip and 1 of ($anchor1, $anchor2)
}
```

---

## Sigma Rules

### Detection Rules

**XiebroC2 v3.1**

#### XiebroC2 Go Implant Loading Windows CLR at Runtime via Go-Clr

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1620 (Reflective Code Loading — in-process CLR hosting via go-clr)
**Confidence:** HIGH
**False Positives:**
- Legitimate applications built with Go that embed .NET interop via documented COM interop mechanisms (rare but possible in enterprise software)
- Custom in-house Go tooling that intentionally hosts the CLR for legitimate automation purposes
- Security research tools or red team frameworks other than XiebroC2 that use go-clr
**Blind Spots:** Misses XiebroC2 builds that never exercise the go-clr inline-assembly command (pure TCP-shell operation without CLR hosting); an incomplete filter list could mask an unlisted legitimate .NET host process.
**Validation:** Trigger the go-clr inline-assembly command on a XiebroC2 sample — must fire; launching any process in the filter list (`dotnet.exe`, `powershell.exe`, etc.) must NOT fire.
**Deployment:** Sysmon Event ID 7 (ImageLoad); requires Sysmon with ImageLoad enabled.

Corrected from the original: the YAML `tags` block listed `attack.t1055.012` (Process Hollowing) despite the rule's own description and detection logic describing an image-load event of `mscoree.dll`/`clr.dll` — that is T1620 (Reflective Code Loading), not process hollowing (which requires suspended-process creation and entry-point patching, an entirely different Sysmon event covered separately). The tag is corrected below and the unsupported `attack.privilege-escalation` tactic tag (this rule detects in-process CLR hosting, not escalation into a higher-privileged process) is dropped. This is the most durable rule in the file — it does not depend on any filename, IP, or campaign-specific literal.

```yaml
title: XiebroC2 Go Implant Loading Windows CLR at Runtime via Go-Clr
id: a3f7c821-5e4b-4d09-bc21-7f3a9e5c8d04
status: experimental
description: >-
  Detects a Go binary (main.exe) loading mscoree.dll or clr.dll at runtime,
  the behavioral signature of the XiebroC2 v3.1 inline-assembly command
  executing via the vendored go-clr library to host the Windows CLR
  in-process. Legitimate Go binaries do not host the CLR. This event fires
  regardless of whether the .NET assembly payload was written to disk,
  making it effective against fully fileless .NET delivery chains.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/Ne0nd0g/go-clr
author: The Hunters Ledger
date: 2026-04-03
tags:
    - attack.stealth
    - attack.execution
    - attack.t1620
    - detection.emerging-threats
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\mscoree.dll'
            - '\clr.dll'
    filter_legitimate_dotnet_hosts:
        Image|endswith:
            - '\dotnet.exe'
            - '\msbuild.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\csc.exe'
            - '\vbc.exe'
            - '\cmstp.exe'
            - '\installutil.exe'
            - '\regsvcs.exe'
            - '\regasm.exe'
            - '\mscorsvw.exe'
            - '\ngen.exe'
            - '\clrjit.dll'
            - '\dfsvc.exe'
            - '\ieinstal.exe'
            - '\PresentationHost.exe'
    condition: selection and not filter_legitimate_dotnet_hosts
falsepositives:
    - Legitimate applications built with Go that embed .NET interop via documented COM interop mechanisms (rare but possible in enterprise software)
    - Custom in-house Go tooling that intentionally hosts the CLR for legitimate automation purposes
    - Security research tools or red team frameworks other than XiebroC2 that use go-clr
level: high
```

**Covenant C2 GruntStager**

#### Covenant C2 GruntStager HTTP Beacon — Campaign Session Token Detected

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols)
**Confidence:** HIGH
**False Positives:** None known — the session token is a GUID-format value unique to this Covenant listener; it will not appear in legitimate HTTP/proxy traffic.
**Blind Spots:** A newly-configured Covenant listener with a different session token evades this rule; requires proxy logging of the URI query string (not all proxies log this by default).
**Validation:** Replay a captured GruntStager beacon POST — must fire; ordinary HTTP/HTTPS proxy traffic without the token must NOT fire.
**Deployment:** HTTP proxy logs (Squid, Bluecoat, Zscaler, etc.); web gateway telemetry; requires proxy logging of the request URI query string.

Corrected from the original: the condition was `1 of (selection_session_token, selection_ua)` — an OR that let a bare sighting of the Chrome 41/Windows 7 User-Agent *alone*, with no URI or token match, fire the rule at `level: high`. That UA can appear on any legacy enterprise endpoint unrelated to this campaign, so the OR-combination understated the true false-positive rate of the weaker branch. Narrowed to the session-token clause alone (near-zero FP on its own); the UA pattern is retained as corroborating context in the description rather than a live alerting condition. The invalid `product: windows` paired with `category: proxy` (proxy logs are network-appliance logs, not Windows host logs) is also removed, and the field name is corrected from `cs-uri-query` to the real SigmaHQ `category: proxy` taxonomy field `c-uri-query` (confirmed against published proxy rules — `sigma check` rejects the `cs-` prefix as a non-existent field for this logsource).

```yaml
title: Covenant C2 GruntStager HTTP Beacon — Campaign Session Token Detected
id: d9a4b257-3f81-4e7c-b5d8-6c2e9f0a4b73
status: experimental
description: >-
  Detects HTTP requests containing the Covenant C2 listener session token
  75db-99b1-25fe4e9afbe58696-320bea73, hardcoded in both GruntHTTP.exe
  (Build 1) and the PE embedded in GruntHTTP.ps1 (Build 2). This token is a
  listener-level constant that appears in every registration and
  command-exchange request from any host executing either stager build,
  making it the highest-value single network detection for this campaign.
  The Chrome 41 / Windows 7 masquerade User-Agent observed alongside this
  token in the same traffic is additional corroborating context, not a
  required condition for this rule.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/cobbr/Covenant
author: The Hunters Ledger
date: 2026-04-03
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        c-uri-query|contains: 'session=75db-99b1-25fe4e9afbe58696-320bea73'
    condition: selection
falsepositives:
    - No legitimate proxy traffic is expected to contain this specific session token value
level: high
```

### Hunting Rules

**XiebroC2 v3.1**

#### Shell Process Spawned from main.exe (XiebroC2 Implant Parent-Child Pattern)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell)
**Confidence:** MODERATE
**Rationale:** The rule's only discriminator is the parent process filename `main.exe`, a common generic executable name with real potential for legitimate collision (Go/Rust/C build tooling routinely produces binaries with this exact name). The original title claimed "Hidden Window" execution, but Sysmon process-creation telemetry does not expose window-visibility or `CREATE_NO_WINDOW` flags, so the rule is retitled to describe what it actually observes — a parent-child spawn relationship. It clears the bar for a Hunting lead rather than Cut because the child-process-type qualifier (cmd/powershell/pwsh) adds a real, if weak, behavioral signal beyond the bare filename. Demoted from the original `level: high` given the acknowledged MEDIUM false-positive rate.
**False Positives:**
- Legitimate Go-based tooling or software distribution systems named `main.exe` that spawn shell subprocesses as part of normal operation
- Development or build environments where a Go binary named `main.exe` orchestrates build steps via `cmd.exe`
**Deployment:** Sysmon Event ID 1 (ProcessCreate); EDR process tree telemetry; most useful as a secondary pivot on a host already flagged by the YARA/hash-based XiebroC2 detections above, not as a standalone alert.

```yaml
title: Shell Process Spawned from main.exe (XiebroC2 Implant Parent-Child Pattern)
id: c5e1f730-8b24-4c9d-a2e7-3f6b8d1e5c92
status: experimental
description: >-
  Detects a cmd.exe, powershell.exe, or pwsh.exe child process spawned from
  a parent process named main.exe, the parent-child pattern produced when
  the XiebroC2 v3.1 Go implant executes its shell, OSshell, or
  OSpowershell commands. Static and behavioral analysis of the implant
  indicates these shells are spawned with a hidden window
  (CREATE_NO_WINDOW), but Sysmon process-creation telemetry does not
  expose window-visibility flags, so this rule anchors on the parent-child
  relationship alone. main.exe is a common generic filename also produced
  by legitimate Go/Rust/C build tooling, so this is a Hunting-tier lead
  requiring analyst triage, not a high-confidence alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
author: The Hunters Ledger
date: 2026-04-03
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1059.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\main.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate Go-based tooling or software distribution systems named main.exe that spawn shell subprocesses as part of normal operation
    - Development or build environments where a Go binary named main.exe orchestrates build steps via cmd.exe
level: medium
```

**PowerShell Fileless Loader**

#### PowerShell Fileless Loader — Deflate Decode with Reflective Assembly Load

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1140 (Deobfuscate/Decode Files or Information), T1620 (Reflective Code Loading)
**Confidence:** MODERATE
**Rationale:** The four-string combination (`DeflateStream`, `Reflection.Assembly`, `FromBase64String`, `MemoryStream`) co-occurring in one ScriptBlock is a durable, campaign-independent technique fingerprint for reflective in-memory .NET assembly loading — it would survive a full Covenant listener rotation, unlike the token-anchored rule above. However, the combination carries an acknowledged MEDIUM false-positive rate (legitimate software-deployment scripts occasionally combine Deflate decompression with reflective assembly loading), so the original `level: high` overstated confidence for a generic, technique-only selector; demoted to Hunting with a recalibrated `level: medium`. The YARA rule for this same loader (Detection tier, above) carries the high-confidence, campaign-specific coverage. Also corrected: the original tag `attack.t1027.011` (Fileless Storage) does not match the observed behavior — the technique is reflective in-memory *execution*, not fileless *storage* of the payload (the Base64 blob is plainly readable on disk inside the .ps1 file) — replaced with `attack.t1620`.
**False Positives:**
- Legitimate software deployment scripts that compress and load .NET assemblies via PowerShell (uncommon but possible in enterprise environments with custom tooling)
- Security research or red team tooling other than Covenant that uses the same delivery pattern
- PowerShell-based application packaging tools that compress payloads with Deflate and load them reflectively
**Deployment:** PowerShell ScriptBlock Logging (Event ID 4104); requires ScriptBlock logging enabled via Group Policy.

```yaml
title: PowerShell Fileless Loader — Deflate Decode with Reflective Assembly Load
id: e2c8d419-6a37-4f5b-8e90-4d1b7c5e2f85
status: experimental
description: >-
  Detects PowerShell ScriptBlocks combining Base64 decoding, Deflate
  decompression via System.IO.DeflateStream, and reflective in-memory
  execution via Reflection.Assembly::Load() — the technique used by the
  GruntHTTP.ps1 Covenant delivery wrapper analyzed in this campaign. This
  three-stage chain is a durable technique fingerprint independent of any
  specific Covenant listener configuration, but legitimate software
  deployment tooling occasionally combines the same primitives, so this is
  a Hunting-tier lead requiring analyst triage rather than a high-confidence
  alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/cobbr/Covenant
author: The Hunters Ledger
date: 2026-04-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1140
    - attack.t1620
    - detection.emerging-threats
logsource:
    category: ps_script
    product: windows
detection:
    selection_decode_chain:
        ScriptBlockText|contains|all:
            - 'DeflateStream'
            - 'Reflection.Assembly'
            - 'FromBase64String'
            - 'MemoryStream'
    condition: selection_decode_chain
falsepositives:
    - Legitimate software deployment scripts that compress and load .NET assemblies via PowerShell (uncommon but possible in enterprise environments with custom tooling)
    - Security research or red team tooling other than Covenant that uses the same delivery pattern
    - PowerShell-based application packaging tools that compress payloads with Deflate and load them reflectively
level: medium
```

---

## Suricata Signatures

### Detection Rules

**Covenant C2 GruntStager**

#### Covenant GruntStager C2 Beacon — Campaign Session Token in HTTP POST

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known — the session token is a GUID-format value unique to this Covenant listener; will not appear in legitimate traffic.
**Blind Spots:** A newly-configured Covenant listener with a different session token evades this rule; requires HTTP request-body inspection enabled on the sensor (not all deployments enable this by default).
**Validation:** Replay a captured GruntStager beacon POST — must alert; ordinary HTTP POST traffic without the token must NOT.
**Deployment:** Network IDS/IPS inline or tap; HTTP inspection on port 443 (cleartext); requires HTTP body inspection enabled on the sensor.

Corrected from the original: the `http` app-layer rule pinned destination port `443` — Suricata selects the HTTP parser by protocol recognition, not port, so pinning blind-spots any future port migration by the operator; changed to `any`. The old `reference:url,pixelatedcontinuum.github.io/...` line and the non-standard `metadata` schema (`affected_product`, `attack_target`, `created_at`, ...) are replaced with the required `metadata:author The_Hunters_Ledger, date, reference` schema pointing at the current site domain. A `threshold` was added for beacon noise control. `sid` is preserved unchanged from the original publication; `rev` bumped to reflect the logic/metadata change.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenDirectory-XiebroC2-Covenant Covenant GruntStager HTTP C2 Beacon (Campaign Session Token in POST Body)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/en-us/"; startswith; http.request_body; content:"session=75db-99b1-25fe4e9afbe58696-320bea73"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9000101; rev:2; metadata:author The_Hunters_Ledger, date 2026-04-03, reference https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/;)
```

#### Covenant GruntStager Masquerade — Chrome 41 Windows 7 UA on Port 443

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1036 (Masquerading), T1571 (Non-Standard Port — plaintext HTTP on port 443)
**Confidence:** HIGH
**False Positives:** The Chrome 41 UA alone may appear on legacy enterprise endpoints with genuinely outdated browsers; the mandatory combination with the `/en-us/` masquerade URI path (both content matches are ANDed in Suricata by default) substantially narrows this.
**Blind Spots:** A rebuild using a different masquerade UA or URI convention evades this rule; requires the sensor to parse plaintext HTTP on port 443 rather than assuming all port-443 traffic is TLS.
**Validation:** Replay a captured GruntStager probe/beacon request — must alert; modern-browser HTTPS traffic to port 443 must NOT.
**Deployment:** Network IDS/IPS; HTTP inspection on port 443; effective only if the sensor parses plaintext HTTP on port 443 rather than assuming TLS.

Same port and metadata-schema corrections as the rule above.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenDirectory-XiebroC2-Covenant Covenant GruntStager Chrome-41-Windows-7 UA Masquerade on Port 443 (Cleartext HTTP C2 Indicator)"; flow:established,to_server; http.user_agent; content:"Chrome/41.0.2228.0"; nocase; http.uri; content:"/en-us/"; startswith; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9000102; rev:2; metadata:author The_Hunters_Ledger, date 2026-04-03, reference https://the-hunters-ledger.com/hunting-detections/opendirectory-193-56-255-154-20260403-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (2 of the original file's 12 rules).** Two original rules keyed solely on a single hardcoded literal with no behavioral qualifier surviving its removal — per the tiering rubric's routing test, these are IOC-feed entries, not standing rules. Both underlying values were already present in [`opendirectory-193-56-255-154-20260403-iocs.json`](/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json) — no feed edits were required.

- **Suricata "XiebroC2 v3.1 TCP C2 Beacon"** (`alert tcp $HOME_NET any -> 193.56.255.154 4444`) carried no `content` match at all — a pure IP+port match with no protocol anchor, the textbook Suricata Cut/atomics criterion. A salvage to a content-based signature was not possible: the protocol's only structural element is a 4-byte length-prefix field (which varies per packet, not a fixed byte signature) followed by AES-128-ECB ciphertext (pseudo-random per block, no visible structure without decryption). A salvage to a *port-only* Hunting rule (the approach used elsewhere in this workflow when a C2 port is a documented family default, e.g. Quasar's 4782) was also not warranted here — 4444 is not documented as a fixed XiebroC2 default (the malware-analyst's evidence shows it as a per-deployment configurable field), and the rule's own original false-positive note already flags port 4444 alone as carrying moderate FP risk from unrelated legitimate tools (Metasploit's default listener port, some dev tools). The IP:port pair is already tracked as a network indicator in the IOC feed.
- **Sigma "XiebroC2 Process Hollowing via Suspended Child Process Creation"** reduced, on inspection of its actual logic rather than its title, to a bare `ParentImage|endswith: '\main.exe'` selector with no other clause — Sysmon process-creation events do not expose `CreationFlags`, so the rule could not actually check for `CREATE_SUSPENDED` despite the title's claim. Removing the literal filename leaves the condition matching all process creation system-wide, so this is an atomic (filename) match dressed as a technique detection, not a genuine hollowing signature. `main.exe` is already tracked as the XiebroC2 filename in the IOC feed. A companion rule with a real behavioral qualifier (child process type) was salvageable and is retained below as a Hunting-tier lead — see "Shell Process Spawned from main.exe."

The following MITRE ATT&CK techniques were observed in the malware analysis but could not be
covered with high-confidence, low-FP detection rules at this time. Evidence gaps or technique
generality prevent rule creation.

| Technique | Family | Gap Reason | Evidence Needed for Coverage |
|---|---|---|---|
| T1055.012 — Process Hollowing (RunPE suspended-process technique) | XiebroC2 | Sysmon Event ID 1 (process_creation) does not expose `CreationFlags`, so a rule cannot distinguish a `CREATE_SUSPENDED` child from any other child process; the only available discriminator is the parent filename `main.exe`, which is a common generic name with real legitimate-collision risk (see the atomics note above). | EDR telemetry that exposes process `CreationFlags` at creation time, or API-hook/ETW instrumentation capturing the `NtQueryInformationProcess` → `ReadProcessMemory` → entry-point-patch sequence |
| T1055 — Process Injection (CreateRemoteThread shellcode injection) | XiebroC2 | VirtualAllocEx + CreateRemoteThread sequence is generic; without an anchor on main.exe as the source process via EDR process-access telemetry (Sysmon EID 10), a standalone Suricata or Sigma rule would have unacceptable FP rates. Sysmon EID 10 is available but requires the `SourceImage` field to match `main.exe`, which depends on the implant not being renamed. | EDR process-access telemetry (Sysmon EID 10) with `SourceImage: \main.exe` and `GrantedAccess` mask `0x43a` |
| T1572 — Protocol Tunneling (SOCKS5 ReverseProxy) | XiebroC2 | The SOCKS5 reverse proxy traffic is encrypted within the XiebroC2 AES-ECB tunnel; it is not separately distinguishable at the network layer without decrypting the outer XiebroC2 session first. | Decrypted PCAP of port 4444 traffic using key `QWERt_CSDMAHUATW` to identify SOCKS5 framing within the XiebroC2 payload |
| T1113 — Screen Capture | XiebroC2 | Screen capture via GDI APIs is not detectable at the network layer or via process creation events; it would require API-call-level hooking (ETW user-mode) or memory forensics to observe the PNG encoding and exfiltration. | ETW user-mode provider tracing GDI API calls in main.exe process; memory forensics showing GDI bitmap allocations |
| T1573.002 — Asymmetric Cryptography (RSA key exchange) | Covenant | RSA key exchange occurs inside the HTTP POST body which is already captured by the session token Suricata rule; a dedicated RSA pattern rule cannot be written without decrypting TLS (not applicable — traffic is cleartext HTTP, but the RSA key material is opaque base64 data). | Full HTTP body inspection with base64 decode capability to inspect the key exchange payload structure |
| T1041 — Exfiltration Over C2 Channel | XiebroC2 | File exfiltration uses the same AES-ECB encrypted TCP channel as all other C2 traffic; no distinguishing framing or port is used. Exfiltration is only detectable by decrypting the channel or by unusually large outbound data volumes to port 4444. | Netflow anomaly detection on port 4444 sessions with sustained large outbound byte counts (>50KB per session chunk) |
| T1082 / T1033 — System Discovery (victim registration beacon) | XiebroC2 | The 15-field MessagePack registration packet is sent over the encrypted AES-ECB channel; no plaintext indicators are observable at the network layer without decryption. | Decrypted PCAP analysis to fingerprint MessagePack field structure of the ClientInfo registration packet |

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
