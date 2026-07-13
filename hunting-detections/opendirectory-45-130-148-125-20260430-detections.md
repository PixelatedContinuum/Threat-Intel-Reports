---
title: "Detection Rules — AdaptixC2 Open Directory Exposure (45.130.148.125)"
date: '2026-04-30'
layout: post
permalink: /hunting-detections/opendirectory-45-130-148-125-20260430-detections/
thumbnail: /assets/images/cards/opendirectory-45-130-148-125-20260430.png
hide: true
---

**Campaign:** AdaptixC2-OpenDirectory-Toolkit-45.130.148.125
**Date:** 2026-04-30
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/

---

## Detection Coverage Summary

This detection package targets the **AdaptixC2** open-source post-exploitation framework as observed at `45.130.148.125`, plus the operator's bundled commodity toolkit (Ligolo-ng, Ghostpack/SpecterOps post-exploitation utilities). Rules also carry a content-layer split — **stock-framework indicators** (match any operator running stock AdaptixC2 with default-listener configuration: Firefox 20 UA, `X-Beacon-Id` header, default URI paths, RC4 config-blob layout in `.rdata`) versus **operator-specific indicators** (match the 45.130.148.125 operator only: recovered RC4 key, `si_build` build fingerprint, PDB path) — layered underneath the Detection/Hunting fidelity tiers below.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1055, T1055.002, T1059.001, T1071.001, T1090.001, T1572, T1620, T1685 | 1 |
| Sigma | 1 | 6 | T1055, T1055.002, T1059.001, T1069.002, T1071.001, T1087.002, T1090.001, T1482, T1572, T1573.001, T1620, T1685 | 0 |
| Suricata | 1 | 2 | T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- `X-Beacon-Id` HTTP header — hardcoded in AdaptixC2's own source code, not a listener-profile-configurable field; the most durable stock-framework indicator in this package (Suricata Detection).
- AdaptixC2 stock RTTI typeinfo strings (`9Connector`, `13ConnectorHTTP`) combined with the RDI loader export and heartbeat header — a framework source-level combination that survives an operator rebuild (YARA Detection).
- Ligolo-ng's Go module import path (`nicocha30/ligolo-ng/pkg/`) — a tool-level anchor unfakeable without forking and renaming the upstream project (YARA + Sigma Detection).

**Atomics routed to the IOC feed:** the operator's per-listener RC4 config key (`f443b9ce7e0658900f6a7ff0991cdee6`) and the C2 IP `45.130.148.125` are transient indicators, already present in [`opendirectory-45-130-148-125-20260430-iocs.json`](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json) — both rotate on the operator's next rebuild or infrastructure move and carried no incremental detection value once separated from the durable framework-level anchors above. Three rules keyed solely on these two values were cut in favor of the feed. Block them via the feed.

### MITRE ATT&CK Coverage

The IOC feed and rules below address 39 distinct ATT&CK techniques observed in this toolkit. Highest-confidence coverage by tactic:

| Tactic | Techniques |
|---|---|
| Resource Development | T1583.003 Acquire Infrastructure: VPS, T1588.002 Obtain Capabilities: Tool |
| Execution | T1059.001 PowerShell, T1620 Reflective Code Loading |
| Defense Evasion | T1027 Obfuscated Files, T1140 Deobfuscate/Decode, T1132.001 Base64 Encoding, T1685 AMSI Bypass, T1055 / T1055.002 Process Injection (PE), T1574.001 DLL Side-Loading (msupdate.dll) |
| Credential Access | T1003.001 LSASS, T1003.002 SAM, T1003.006 DCSync, T1555 / T1555.003 / T1555.004 Password Stores, T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, T1552.004 Private Keys, T1649 Forge Auth Certs |
| Discovery | T1057 Process, T1082 System Info, T1083 Files/Directories, T1018 Remote Systems, T1087.002 Domain Accounts, T1069.002 Domain Groups, T1482 Domain Trust, T1518.001 Security Software |
| Privilege Escalation | T1068 Exploitation for PrivEsc, T1134.001 Token Impersonation, T1134.002 CreateProcessWithToken |
| Command and Control | T1071.001 HTTP C2, T1573.001 Symmetric Encryption (RC4), T1090.001 Internal Proxy (Ligolo-ng), T1572 Protocol Tunneling, T1105 Ingress Tool Transfer |
| Collection | T1056.001 Keylogging |

### Noise Filtering

Two YARA false-positive clusters were identified during analysis and must be filtered when triaging hunt results:

- **Go-runtime PoetRat false positive** — `MALWARE_RULES: PoetRat_Python` triggers on every Go binary (`agent.exe` / Ligolo-ng, `chisel.exe`, `gopher.x64.exe`). PoetRAT is unrelated to this toolkit.
- **PowerView spyeye false positive** — `MALWARE_RULES: spyeye` triggers on PowerView.ps1 due to a generic byte pattern. PowerView is a commodity AD reconnaissance PowerShell module, not SpyEye banking malware.

---

## YARA Rules

### Detection Rules

#### AdaptixC2 Windows Beacon — Stock Framework Fingerprint

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** `9Connector` and `13ConnectorHTTP` are Itanium-ABI RTTI typeinfo names for AdaptixC2's stock `Connector`/`ConnectorHTTP` transport-plugin classes, and `GetVersions` is the framework's unrenamed RDI loader export — none of these are attacker-configurable; an operator would need to fork and rebuild the AdaptixC2 source itself to remove them. Paired with the `X-Beacon-Id` heartbeat-header string (also framework source-level), this combination survives infrastructure rotation and any listener-profile customization.
**False Positives:** None known — the RTTI typeinfo strings and the `X-Beacon-Id` literal are not present in any known legitimate software; `filesize < 300KB` further scopes the match to the beacon's actual size class.
**Blind Spots:** A forked/patched AdaptixC2 build that strips or renames the RTTI class names and the `X-Beacon-Id` header would evade; memory-only variants that never touch disk need the memory-scan deployment path.
**Validation:** Scan `agent.x64.dll`/`agent.x64.exe`/`msupdate.dll` (hash1 below and its sideload sibling) — must match; an unrelated Windows PE must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning, static triage of unknown MinGW-built PE binaries.

```yara
/*
   Yara Rule Set
   Identifier: AdaptixC2 Operator Toolkit — 45.130.148.125
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_AdaptixC2_Windows_Beacon_Stock
{
    meta:
        description = "Detects AdaptixC2 Windows beacon (DLL/EXE) by stock Itanium-ABI RTTI typeinfo strings, RDI loader export, and heartbeat header — catches any operator running stock AdaptixC2 with default connector names"
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        date = "2026-04-30"
        hash1 = "358edb5d7e3e38c2da0a2ef323a281283aa96d47a8649014d114923b06866c12"
        hash2 = ""
        hash3 = ""
        family = "AdaptixC2"
        malware_type = "C2 Framework Beacon"
        campaign = "AdaptixC2-OpenDirectory-Toolkit-45.130.148.125"
        id = "952a09e1-dbbd-5758-ab76-bb9f215d96b5"

    strings:
        $s1 = "9Connector" ascii
        $s2 = "13ConnectorHTTP" ascii
        $s3 = "GetVersions" ascii
        $s4 = "Mingw-w64 runtime failure:" ascii
        $s5 = "X-Beacon-Id" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 300KB and
        ($s1 and $s2) and
        ($s3 or $s4) and
        $s5
}
```

#### Ligolo-ng v0.8.3 Reverse Tunnel Agent

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**Rationale:** `nicocha30/ligolo-ng/pkg/` is the tool's Go module import path, compiled into every build of the binary — durable at the tool level and unfakeable without forking and renaming the upstream project. Paired with either the release version or the specific build commit, this anchors any current or near-future Ligolo-ng v0.8.x deployment, not only this operator's build.
**False Positives:** None known — Ligolo-ng has no legitimate end-user or enterprise presence; the only expected match is authorized penetration-testing use of the same tool.
**Blind Spots:** A renamed/recompiled fork built under a different Go module path would evade entirely; a future Ligolo-ng release built from a different commit and version string falls outside this rule's `$s2 or $s3` scoping (the import-path anchor `$s1` alone is intentionally not sufficient, to avoid over-broad matching on any tool sharing a similar package layout).
**Validation:** Scan the analyzed `agent.exe` (hash1 below) — must match; an unrelated Go binary must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown Go binaries staged for lateral movement.

```yara
rule MALW_Ligolo_ng_v083_Agent
{
    meta:
        description = "Detects Ligolo-ng v0.8.3 stock reverse-tunnel agent by embedded version string, Go package namespace, and upstream commit hash — operator bundled this for internal-network pivot"
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        date = "2026-04-30"
        hash1 = "4b41f36f82db6da8767a0a1c2997c8242d80b2d10a8f1d28c252a9306ec152b5"
        hash2 = ""
        hash3 = ""
        family = "Ligolo-ng"
        malware_type = "Reverse Tunnel Agent"
        campaign = "AdaptixC2-OpenDirectory-Toolkit-45.130.148.125"
        id = "5f4a72f0-b98c-5719-bf40-edafeb7f7021"

    strings:
        $s1 = "nicocha30/ligolo-ng/pkg/" ascii
        $s2 = "0.8.3" ascii
        $s3 = "913fe64e088d5db2185d392965bf4cd3dd1d9495" ascii

    condition:
        filesize < 15MB and
        $s1 and
        ($s2 or $s3)
}
```

### Hunting Rules

#### AdaptixC2 Operator .NET Injector — si_build Build Fingerprint

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1055 (Process Injection), T1055.002 (PE Injection)
**Confidence:** HIGH (fingerprint) / MODERATE (forward attribution value)
**Rationale:** Both anchors — the Linux PDB path and the bare `si_build` string — reduce to the same underlying literal (the operator's build-directory/project name); an operator who renames that project before rebuilding evades both simultaneously, so this doesn't clear the durability bar for Detection. It retains real hunting value: this exact build-name choice already recurred identically across this operator's dev and production builds, so a future sample carrying the same string would be a strong forward link to this actor's build pipeline.
**False Positives:** None known to date — `si_build` and the `/tmp/si_build/obj/Release/net472/` PDB path are not present in any known legitimate .NET software.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown small .NET assemblies; cross-sample hunting for this operator's build fingerprint in future unrelated submissions.

```yara
rule MALW_AdaptixC2_Operator_Injector_SI
{
    meta:
        description = "Detects the operator-written .NET v4.7.2 SI class CRT injector (injector.dll) by Linux PDB path and build-name placeholder strings — actor-specific fingerprint not present in any AdaptixC2 stock component"
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        date = "2026-04-30"
        hash1 = "5ea265ad3e6429cd2e8d9831360f7e2be9b8ba5a5b32a4a60c5c956a3f8fb285"
        hash2 = ""
        hash3 = ""
        family = "AdaptixC2"
        malware_type = "Process Injector (Operator-Authored)"
        campaign = "AdaptixC2-OpenDirectory-Toolkit-45.130.148.125"
        id = "1d62ef42-8771-50b6-a677-ebe27b2b60f6"

    strings:
        $s1 = "/tmp/si_build/obj/Release/net472/si_build.pdb" ascii
        $s2 = "si_build" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20KB and
        $s1 and $s2
}
```

#### AdaptixC2 PowerShell Loader — AMSI Bypass and SI Injector Invocation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell), T1685 (AMSI Bypass), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**Rationale:** The rule requires all four strings, but only `[SI]::Inject(` is genuinely operator-specific (this actor's custom injector class); the AMSI string-concatenation split, the `*iUtils` reflection target, and the base64 MZ prefix are generic loader-construction technique markers, not unique to this operator. Renaming the `SI` class in a future build breaks the AND condition entirely, so durability caps at Hunting despite very low current false-positive risk.
**False Positives:** None known — the co-occurrence of a string-concatenated AMSI bypass, a class named `SI` with an `Inject` method, and an embedded base64 PE in one script block is considered highly unlikely outside adversary tooling.
**Deployment:** SIEM with PowerShell Script Block Logging (Windows Event ID 4104) ingested; endpoint EDR ScriptBlock telemetry.

```yara
rule MALW_AdaptixC2_PowerShell_Loader_BeaconPS1
{
    meta:
        description = "Detects the operator-written beacon.ps1 PowerShell delivery loader by concatenated AMSI bypass, SI injector invocation, and base64 MZ prefix for inline PE — all four elements must co-occur"
        license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
        author = "The Hunters Ledger"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        date = "2026-04-30"
        hash1 = "b4ffd7ca8f5505fd7b71882c67712e896c9d170a3b3b581baba78ee5d1c2b858"
        hash2 = ""
        hash3 = ""
        family = "AdaptixC2"
        malware_type = "PowerShell Loader (Operator-Authored)"
        campaign = "AdaptixC2-OpenDirectory-Toolkit-45.130.148.125"
        id = "38a6c21a-688f-50cb-80aa-256367744425"

    strings:
        $s1 = "amsi'+'Con'+'text" ascii nocase
        $s2 = "*iUtils" ascii
        $s3 = "[SI]::Inject(" ascii
        $s4 = "TVqQAAMA" ascii

    condition:
        filesize < 512KB and
        $s1 and $s2 and $s3 and $s4
}
```

---

## Sigma Rules

### Detection Rules

#### Ligolo-ng Reverse Tunnel Agent Execution

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**Rationale:** Durable Go CLI/behavioral combination — default process image name, or the tool's `--connect`/`-connect` flag paired with its default port. The original rule also OR'd in a bare SHA256 hash match; that branch was trimmed during this backfill because a hash-only selector is a transient per-sample atomic (Gate 1 Robustness 0) that duplicates the value already tracked in the campaign IOC feed and added no incremental behavioral coverage.
**False Positives:** Authorized security assessment or network administration use of Ligolo-ng — correlate against authorized change records and known red team activity windows; security research and lab environments where Ligolo-ng is used for legitimate network tunneling evaluation.
**Blind Spots:** A renamed binary using a non-default connect port with obfuscated CLI flags evades both surviving branches.
**Validation:** Trigger `ligolo.exe --connect <host>:11601` (or the equivalent default-port connect) — must match; an unrelated executable performing routine outbound TCP connections must NOT fire.
**Deployment:** Endpoint EDR with Sysmon Event ID 1 (Process Creation); pair with the YARA rule above for file-level coverage.

```yaml
title: Ligolo-ng Reverse Tunnel Agent Execution
id: 3f7a2b58-9e04-4c83-a625-1d6b8f4e2a91
status: experimental
description: Detects execution of the Ligolo-ng reverse-tunneling agent by process image name or by command-line connect argument combined with the default port. Ligolo-ng is an open-source TLS-over-TCP reverse proxy tool used by threat actors to create tunnels from a compromised host into internal networks, enabling lateral movement without direct routing. The operator in this campaign deployed the stock upstream v0.8.3 release at commit 913fe64e088d5db2185d392965bf4cd3dd1d9495; the exact file hash for that build is tracked in the campaign IOC feed rather than in this rule's selection logic.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
    - https://github.com/nicocha30/ligolo-ng
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.command-and-control
    - attack.t1572
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_name:
        Image|endswith:
            - '\ligolo.exe'
            - '\ligolo-ng.exe'
    selection_cmdline:
        CommandLine|contains:
            - '--connect'
            - '-connect'
    selection_port:
        CommandLine|contains: ':11601'
    condition: selection_name or (selection_cmdline and selection_port)
falsepositives:
    - Authorized security assessment or network administration use of Ligolo-ng - correlate against authorized change records and known red team activity windows
    - Security research and lab environments where Ligolo-ng is used for legitimate network tunneling evaluation
level: high
```

### Hunting Rules

#### AdaptixC2 PowerShell Loader — AMSI Bypass and SI Injector Invocation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell), T1685 (AMSI Bypass), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**Rationale:** Sigma sibling of the YARA PowerShell-loader rule above — three co-occurring strings are highly specific to this loader, but `[SI]::Inject(` is a renameable literal the operator controls in their own source; a rebuild that renames the injector class evades the rule. Durability caps this at Hunting despite very low current false-positive risk.
**False Positives:** Custom internal PowerShell tooling that coincidentally uses both an AMSI bypass via string concatenation and a class named SI with an Inject method — considered highly unlikely outside of adversary tooling.
**Deployment:** SIEM with PowerShell Script Block Logging (Windows Event ID 4104) ingested; endpoint EDR ScriptBlock telemetry.

```yaml
title: AdaptixC2 PowerShell Loader - AMSI Bypass and SI Injector Invocation
id: a3f1c8e2-7b45-4d91-b832-6e0d9f2c1a74
status: experimental
description: Detects execution of the AdaptixC2 operator beacon.ps1 PowerShell loader by matching the string-concatenated AMSI bypass marker combined with the operator-specific SI injector class invocation and an embedded base64 MZ PE prefix. The concatenation pattern amsi+Con+text evades static AV string signatures; [SI]::Inject( identifies the operator-custom .NET injector loaded in-memory. Co-occurrence of all three strings in a single script block is highly specific to this loader, but the SI class name is a renameable literal the operator controls in their own source - a rebuild that renames it evades the rule. Requires PowerShell Script Block Logging (Event ID 4104).
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.execution
    - attack.stealth
    - attack.defense-impairment
    - attack.t1059.001
    - attack.t1685
    - detection.emerging-threats
logsource:
    product: windows
    category: ps_script
detection:
    selection_amsi:
        ScriptBlockText|contains: "amsi'+'Con'+'text"
    selection_injector:
        ScriptBlockText|contains: '[SI]::Inject('
    selection_base64_mz:
        ScriptBlockText|contains: 'TVqQAAMA'
    condition: selection_amsi and selection_injector and selection_base64_mz
falsepositives:
    - Custom internal PowerShell tooling that coincidentally uses both an AMSI bypass via string concatenation and a class named SI with an Inject method - considered highly unlikely outside of adversary tooling
level: medium
```

#### AdaptixC2 Default Listener — Anomalous Firefox 20 User-Agent with X-Beacon-Id Header

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Encryption — RC4)
**Confidence:** HIGH for the anomaly signal; catches any operator running the framework default, not this operator specifically
**Rationale:** Firefox 20 (February 2013) is anomalous in any 2026 traffic and is the AdaptixC2 default listener UA — but the UA is a listener-profile field the operator can change at will, and the file's own Coverage Gaps documented this exact risk. Standard proxy logsources also don't expose the corroborating `X-Beacon-Id` header, so this rule anchors on the UA alone. Durability and single-field precision cap this at Hunting.
**False Positives:** Legacy embedded systems or industrial control software using a hardcoded Firefox 20 UA string — cross-reference against known asset inventory to exclude.
**Deployment:** Web proxy log pipeline (Squid, Zscaler, Palo Alto URL filtering); Zeek HTTP log ingestion.

```yaml
title: AdaptixC2 Default Listener - Anomalous Firefox 20 User-Agent with X-Beacon-Id Header
id: 7c9d4b81-3e62-4f08-a517-2d8e5a6c0b93
status: experimental
description: Detects outbound HTTP traffic matching the AdaptixC2 stock listener default profile. The Firefox 20 User-Agent (released February 2013) is anomalous in 2026 traffic and is the AdaptixC2 default listener UA string. The X-Beacon-Id header is the AdaptixC2 stock per-agent heartbeat header not used by any known legitimate browser or application, but standard proxy logsource fields do not expose arbitrary request headers, so this rule anchors on the User-Agent string alone; combine with the X-Beacon-Id header at the WAF or full-packet-capture layer for the highest-confidence match. The UA string is a listener-profile field the operator can change at will, so this is a hunting-grade lead rather than an alerting-grade signature on its own.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|contains: 'Firefox/20.0'
    condition: selection
falsepositives:
    - Legacy embedded systems or industrial control software using a hardcoded Firefox 20 UA string - cross-reference against known asset inventory to exclude
level: medium
```

#### AdaptixC2 Beacon — High-Frequency Deterministic HTTP POST Cadence to Stock URIs

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE — timing patterns require log aggregation; FP possible from monitoring agents
**Rationale:** Base selection (POST to two stock/operator-added URI paths) and its correlation rule (>5 requests/30s from one source) are published as a linked pair. The URI paths are listener-profile fields the operator can change at will — the campaign IOC feed itself flags the jQuery URI as MODERATE FP risk "NOT alone" — and >5-requests/30s health-check and CI/CD traffic can produce a similar cadence, so neither the base selection nor the correlation clears the Detection precision bar independently.
**False Positives:** Legitimate health-check endpoints polled at high frequency by infrastructure monitoring agents — add known monitoring source IPs to an allowlist filter; CI/CD pipeline job runners issuing rapid POST requests to status endpoints during build phases.
**Deployment:** Web proxy SIEM with count-by-source aggregation over a 30-second sliding window; Zeek or NGFW flow logs.

```yaml
title: AdaptixC2 Beacon Stock URI POST Request
id: 2e7f5a93-8c14-4b67-d259-1a3f6e8d0c52
status: experimental
description: Base selection for the AdaptixC2 fast-beacon callback pattern - HTTP POST requests to stock AdaptixC2 URI paths (/api/v1/status or /jquery-3.3.1.min.js). Paired with the correlation rule below, which flags more than five such requests from a single source within a 30-second window; the 4-5 second sleep with zero jitter this produces is highly anomalous for production traffic. Both URI paths are listener-profile fields the operator can change at will.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
        cs-uri-stem|contains:
            - '/api/v1/status'
            - '/jquery-3.3.1.min.js'
    condition: selection
falsepositives:
    - Legitimate health-check endpoints polled at high frequency by infrastructure monitoring agents - add known monitoring source IPs to an allowlist filter
    - CI/CD pipeline job runners issuing rapid POST requests to status endpoints during build phases
level: low
---
title: AdaptixC2 Beacon - High-Frequency Deterministic HTTP POST Cadence to Stock URIs
id: 8f4a1c93-6e27-4b58-a910-3d7c2f5b9e46
status: experimental
description: Detects the AdaptixC2 fast-beacon callback pattern - a source IP making more than five HTTP POST requests within 30 seconds to stock AdaptixC2 URI paths. Correlates the base selection rule (AdaptixC2 Beacon Stock URI POST Request, id 2e7f5a93-8c14-4b67-d259-1a3f6e8d0c52) by source IP over a 30-second sliding window; requires a Sigma backend with correlation-rule support.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026-04-30
correlation:
    type: event_count
    rules:
        - 2e7f5a93-8c14-4b67-d259-1a3f6e8d0c52
    group-by:
        - c-ip
    timespan: 30s
    condition:
        gt: 5
level: medium
```

#### Suspicious .NET Assembly Image Load with Operator si_build Build Fingerprint

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1055 (Process Injection), T1055.002 (PE Injection), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**Rationale:** Sigma sibling of the YARA `si_build` rule above — the `si_build` build-placeholder string is a distinctive operator fingerprint, but it is a renameable literal (the operator's own project/build-directory name); a future build that changes the project name evades this rule entirely. Retains the same forward cross-sample hunting value as its YARA counterpart.
**False Positives:** Internal developer tooling where a developer has named a build artifact `si_build` and loaded it via PowerShell — cross-reference against software asset inventory.
**Deployment:** Endpoint EDR with Sysmon Event ID 7 (Image Load) telemetry; endpoint DLL inspection pipeline.

```yaml
title: Suspicious .NET Assembly Image Load with Operator si_build Build Fingerprint
id: 5b8e2d47-1c93-4a76-f018-9b4d7e3c6f85
status: experimental
description: Detects PowerShell loading a .NET DLL image whose PE version metadata contains the operator build-placeholder string si_build. This string appears in CompanyName, FileDescription, InternalName, and OriginalFilename fields of the operator-written injector.dll found in this AdaptixC2 deployment. The string is a Linux-build artifact from /tmp/si_build/ left unredacted in the PE version resource and is not present in any known legitimate software, but it is a renameable literal the operator controls - a future build that changes the project name evades this rule.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.t1055
    - detection.emerging-threats
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\powershell.exe'
        Description|contains: 'si_build'
    filter_legitimate:
        Signed: 'true'
    condition: selection and not filter_legitimate
falsepositives:
    - Internal developer tooling where a developer has named a build artifact si_build and loaded it via PowerShell - cross-reference against software asset inventory
level: medium
```

#### Suspicious Active Directory Reconnaissance Tool Execution

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery)
**Confidence:** HIGH
**Rationale:** SharpHound, PowerView, and ADRecon are stable, long-standing upstream tool/cmdlet names — durable at the tool-family level. Precision, not durability, keeps this in Hunting: all three are equally common in legitimate red-team and penetration-testing engagements, which the rule's own false-positive profile explicitly acknowledges (MEDIUM FP, requires change-management correlation) — the level-`high` originally assigned overstated confidence for a rule with this much acknowledged legitimate overlap.
**False Positives:** Authorized security assessment or red team exercises — correlate against change management records and authorized testing windows; EDR or vulnerability assessment platforms that incorporate BloodHound data collection natively.
**Deployment:** Endpoint EDR with Sysmon Event ID 1 (Process Creation) or equivalent; SIEM process-creation pipeline.

```yaml
title: Suspicious Active Directory Reconnaissance Tool Execution
id: 9a3c6f12-4d87-4e52-b741-8c5f2a9d0e67
status: experimental
description: Detects execution of common Active Directory enumeration tools observed in this AdaptixC2 operator toolkit - SharpHound for BloodHound attack-path mapping, PowerView for PowerSploit AD recon, and ADRecon for comprehensive AD data harvesting. These tools are commodity open-source utilities frequently used by threat actors to identify domain privilege escalation paths, enumerate domain accounts and groups, and map trust relationships prior to lateral movement, but they are equally common in legitimate red-team and penetration-testing engagements.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/PowerShellMafia/PowerSploit
author: The Hunters Ledger
date: 2026-04-30
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.t1482
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection_sharphound:
        Image|endswith: '\SharpHound.exe'
        CommandLine|contains:
            - '-c All'
            - '--CollectionMethods'
            - '-CollectionMethod'
    selection_powerview:
        CommandLine|contains:
            - 'Get-NetDomain'
            - 'Get-NetForest'
            - 'Invoke-BloodHound'
            - 'Get-DomainTrust'
            - 'Get-NetGroupMember'
    selection_adrecon:
        Image|endswith: '\ADRecon.exe'
    condition: selection_sharphound or selection_powerview or selection_adrecon
falsepositives:
    - Authorized security assessment or red team exercises - correlate against change management records and authorized testing windows
    - EDR or vulnerability assessment platforms that incorporate BloodHound data collection natively
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### AdaptixC2 Default Listener X-Beacon-Id Heartbeat Header (Broad, Any IP)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** `X-Beacon-Id` is the AdaptixC2 heartbeat header name as defined in the framework's own source code — not a listener-profile field, so an operator cannot change it without forking and patching AdaptixC2 itself. This is the most durable stock-framework indicator in the whole package and catches any operator running stock AdaptixC2, not only the 45.130.148.125 operator.
**False Positives:** None known — `X-Beacon-Id` is not a standard HTTP header and is not used by any known legitimate application.
**Blind Spots:** A forked/patched AdaptixC2 build that renames the heartbeat header evades entirely; misses non-HTTP transports (TCP, SMB named pipe) that AdaptixC2 also supports.
**Validation:** Replay or observe a beacon heartbeat POST carrying the header — must alert; ordinary HTTP traffic without the header must NOT fire.
**Deployment:** Perimeter IDS/IPS; inline NGFW; east-west network sensor in segmented environments.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Default Listener X-Beacon-Id Heartbeat Header Detected"; flow:established,to_server; http.header_names; content:"X-Beacon-Id"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001002; rev:1;)
```

### Hunting Rules

#### AdaptixC2 Stock Listener URI /api/v1/status with Firefox 20 UA

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH (current traffic); durability limited
**Rationale:** Combines the Firefox 20 stock UA with the default `/api/v1/status` URI on a POST — both fields are AdaptixC2 listener-profile settings the operator can reconfigure at will. The file's own Coverage Gaps section documents this exact risk ("an operator who reads detection reporting will change the UA and URI paths"), so this is a durability-capped Hunting lead rather than a Detection signature.
**False Positives:** Legitimate `/api/v1/status` traffic combined with a coincidental Firefox 20 UA is not realistically expected today, but the combination has no protection against a future listener-profile change.
**Deployment:** Perimeter IDS/IPS; inline NGFW; edge network sensor.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Stock Listener URI Path with Firefox 20 UA"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0 (Windows NT 6.2|3B| rv:20.0) Gecko/20121202 Firefox/20.0"; endswith; http.method; content:"POST"; http.uri; content:"/api/v1/status"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001003; rev:1;)
```

#### AdaptixC2 Operator-Added jQuery URI with Firefox 20 UA

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH (current traffic); durability limited
**Rationale:** The `/jquery-3.3.1.min.js` URI was added by this operator beyond AdaptixC2 stock defaults, but — per the campaign IOC feed's own annotation — this URI carries MODERATE false-positive risk when matched without the destination IP or header context, and remains a listener-profile field the operator can change. Same durability cap as the sibling stock-URI rule above.
**False Positives:** Legitimate jQuery 3.3.1 CDN traffic combined with a coincidental Firefox 20 UA is not realistically expected today, but the URI alone (without the UA pairing) would be a meaningful FP risk — this rule intentionally requires both.
**Deployment:** Perimeter IDS/IPS; edge sensor; proxy with IDS inspection capability.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Operator-Added jQuery URI with Firefox 20 UA"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0 (Windows NT 6.2|3B| rv:20.0) Gecko/20121202 Firefox/20.0"; endswith; http.method; content:"POST"; http.uri; content:"/jquery-3.3.1.min.js"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001004; rev:1;)
```

---

## Coverage Gaps

**Rules cut in favor of the IOC feed (3 of the original 17 rules).** Two Suricata signatures and one YARA rule keyed solely on the operator's per-listener RC4 config key (`f443b9ce7e0658900f6a7ff0991cdee6`) or the C2 IP `45.130.148.125` — both values already carried in [`opendirectory-45-130-148-125-20260430-iocs.json`](/ioc-feeds/opendirectory-45-130-148-125-20260430-iocs.json). No feed edits were required.

- **YARA `MALW_AdaptixC2_Beacon_RC4_Operator_Key`** — required the RC4 key bytes plus the stock RTTI strings already covered by the Detection-tier `MALW_AdaptixC2_Windows_Beacon_Stock` rule; the key is generated per-listener-instance (`ax.random_string(32, hex)`) and rotates on the operator's next rebuild, so stripping it left a strictly weaker duplicate of an existing rule.
- **Suricata SID 5001001 (`AdaptixC2 Operator Beacon C2 Traffic to 45.130.148.125 - Firefox 20 UA`)** — combined the hardcoded destination IP with a bare UA+POST match (no URI). Once the IP is set aside as an atomic, the surviving UA+POST signal is a strict subset of the Hunting-tier URI-qualified rules (SID 5001003/5001004) and less durable than the Detection-tier `X-Beacon-Id` header rule (SID 5001002) — no incremental coverage.
- **Suricata SID 5001005 (`AdaptixC2 Operator RC4 Config Key Bytes in Traffic`)** — matched only the raw 16-byte RC4 key with no other qualifier; the rule's own original write-up already flagged it as "NOT suitable as a persistent production IDS rule (key rotates on operator rebuild)."

The following techniques observed in the malware-analyst findings still cannot be covered with high-confidence, low-FP detection rules given currently available evidence. Each gap is documented with the specific obstacle and the evidence that would enable rule creation.

| Gap | Observed Behavior | Obstacle | Evidence Needed to Close |
|---|---|---|---|
| RC4 key rotation | Operator-specific beacon config uses RC4 key f443b9ce7e0658900f6a7ff0991cdee6 stored plaintext in .rdata | RC4 key is generated per-listener-instance by AdaptixC2 (ax.random_string(32, hex)); a single operator rebuild invalidates all key-based detection — this is why the key-anchored YARA and Suricata rules were cut to the IOC feed rather than kept as rules | Recovery of a second beacon binary from a future operator operation to confirm whether the same key persists or rotates |
| HTTPS-wrapped C2 variant | Current C2 traffic is plaintext HTTP on port 80 with Firefox 20 UA and X-Beacon-Id header | If the operator enables TLS on the AdaptixC2 listener, all Suricata rules matching http.user_agent, http.header_names, and http.uri become blind; TLS SNI or JA3/JA3S fingerprinting would be required | Capture of a TLS-enabled AdaptixC2 session from this or a linked operator; JA3S fingerprint of the AdaptixC2 server TLS stack |
| Operator UA or URI path customization | Stock listener defaults used in this campaign (Firefox 20 UA, /api/v1/status, /updates/check.php, /content.html, /jquery-3.3.1.min.js) | AdaptixC2 listener profile fields are fully configurable; an operator who reads detection reporting will change the UA and URI paths — this is precisely why the UA- and URI-anchored Sigma and Suricata rules are tiered Hunting rather than Detection in this file | The X-Beacon-Id header rule (SID 5001002) is the most durable stock-framework indicator because the header name is defined in the AdaptixC2 source code, not in the listener profile |
| Linux Gopher agent variant (agent.bin ELF) | AdaptixC2 Linux ELF agent bundled in toolkit; post-exploitation capability on Linux hosts confirmed | Sigma rules in this package target Windows logsources exclusively (ps_script, image_load, process_creation); Linux auditd or Sysmon-for-Linux telemetry is required for equivalent coverage | Linux process creation telemetry (auditd EXECVE events or Sysmon-for-Linux Event ID 1) for the gopher ELF agent; behavioral signatures for its MessagePack C2 protocol |
| Alternative AdaptixC2 transports (TCP/SMB) | AdaptixC2 supports TCP and SMB named-pipe transports in addition to HTTP | Current Suricata rules target the HTTP listener exclusively; TCP transport would bypass all http.user_agent and http.header_names rules; SMB transport over named pipe \.\pipe\%08lx would require different detection layer | Capture of TCP or SMB transport traffic from an AdaptixC2 deployment; Sysmon Event ID 17/18 named-pipe telemetry for the SMB transport plumbing |
| Packed SharpHound and lazagne variants | SharpHound.exe (86% entropy, packed) and 10 MB lazagne.exe (97% entropy, IsPacked YARA hit) show operator-applied AV evasion | Hash-based detection is defeated by packing; the underlying tool fingerprints are inaccessible without unpacking; generic high-entropy YARA rules produce excessive FP volume on all packed binaries | Deobfuscation of both samples to recover their underlying strings for specific YARA rules — e.g. unwrapping the ConfuserEx/.NET Reactor-style wrapper on SharpHound.exe and the UPX-style wrapper on the 10 MB lazagne.exe variant |

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
