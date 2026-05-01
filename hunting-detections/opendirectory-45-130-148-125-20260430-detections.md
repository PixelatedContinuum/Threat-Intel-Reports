---
title: "Detection Rules — AdaptixC2 Open Directory Exposure (45.130.148.125)"
date: '2026-04-30'
layout: post
permalink: /hunting-detections/opendirectory-45-130-148-125-20260430-detections/
hide: true
---

**Campaign:** AdaptixC2-OpenDirectory-Toolkit-45.130.148.125
**Date:** 2026-04-30
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/

## Detection Coverage Summary

This detection package targets the **AdaptixC2** open-source post-exploitation framework as observed at `45.130.148.125`, plus the operator's bundled commodity toolkit (Ligolo-ng, Ghostpack/SpecterOps post-exploitation utilities). Rules are organized into two tiers:

- **Stock-framework detections** — match any operator running stock AdaptixC2 with default-listener configuration (Firefox 20 UA, `X-Beacon-Id` header, default URI paths, RC4 config-blob layout in `.rdata`). Broad coverage across the AdaptixC2 user base.
- **Operator-specific detections** — match the 45.130.148.125 operator only (recovered RC4 key `f443b9ce7e0658900f6a7ff0991cdee6`, server-assigned agent IDs `0xbe4c0149` / `0xcb4e6379`, PDB path `/tmp/si_build/...`, `si_build`/`SI` build-fingerprint strings).

### MITRE ATT&CK Coverage

The IOC feed and rules below address 39 distinct ATT&CK techniques observed in this toolkit. Highest-confidence coverage by tactic:

| Tactic | Techniques |
|---|---|
| Resource Development | T1583.003 Acquire Infrastructure: VPS, T1588.002 Obtain Capabilities: Tool |
| Execution | T1059.001 PowerShell, T1620 Reflective Code Loading |
| Defense Evasion | T1027 Obfuscated Files, T1140 Deobfuscate/Decode, T1132.001 Base64 Encoding, T1562.001 AMSI Bypass, T1055 / T1055.002 Process Injection (PE), T1574.002 DLL Side-Loading (msupdate.dll) |
| Credential Access | T1003.001 LSASS, T1003.002 SAM, T1003.006 DCSync, T1555 / T1555.003 / T1555.004 Password Stores, T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, T1552.004 Private Keys, T1649 Forge Auth Certs |
| Discovery | T1057 Process, T1082 System Info, T1083 Files/Directories, T1018 Remote Systems, T1087.002 Domain Accounts, T1069.002 Domain Groups, T1482 Domain Trust, T1518.001 Security Software |
| Privilege Escalation | T1068 Exploitation for PrivEsc, T1134.001 Token Impersonation, T1134.002 CreateProcessWithToken |
| Command and Control | T1071.001 HTTP C2, T1573.001 Symmetric Encryption (RC4), T1090.001 Internal Proxy (Ligolo-ng), T1572 Protocol Tunneling, T1105 Ingress Tool Transfer |
| Collection | T1056.001 Keylogging |

### Noise Filtering

Two YARA false-positive clusters were identified during analysis and must be filtered when triaging hunt results:

- **Go-runtime PoetRat false positive** — `MALWARE_RULES: PoetRat_Python` triggers on every Go binary (`agent.exe` / Ligolo-ng, `chisel.exe`, `gopher.x64.exe`). PoetRAT is unrelated to this toolkit.
- **PowerView spyeye false positive** — `MALWARE_RULES: spyeye` triggers on PowerView.ps1 due to a generic byte pattern. PowerView is a commodity AD reconnaissance PowerShell module, not SpyEye banking malware.

## YARA Rules

```yara
/*
    Name: AdaptixC2 Operator Toolkit — 45.130.148.125
    Author: The Hunters Ledger
    Date: 2026-04-30
    Identifier: AdaptixC2 Windows Beacon + Operator Injector + PowerShell Loader
    Reference: https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule MALW_AdaptixC2_Windows_Beacon_Stock
{
    meta:
        description = "Detects AdaptixC2 Windows beacon (DLL/EXE) by stock Itanium-ABI RTTI typeinfo strings, RDI loader export, and heartbeat header — catches any operator running stock AdaptixC2 with default connector names"
        author = "The Hunters Ledger"
        date = "2026-04-30"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        hash_sha256 = "358edb5d7e3e38c2da0a2ef323a281283aa96d47a8649014d114923b06866c12"
        family = "AdaptixC2"

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

rule MALW_AdaptixC2_Operator_Injector_SI
{
    meta:
        description = "Detects the operator-written .NET v4.7.2 SI class CRT injector (injector.dll) by Linux PDB path and build-name placeholder strings — actor-specific fingerprint not present in any AdaptixC2 stock component"
        author = "The Hunters Ledger"
        date = "2026-04-30"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        hash_sha256 = "5ea265ad3e6429cd2e8d9831360f7e2be9b8ba5a5b32a4a60c5c956a3f8fb285"
        family = "AdaptixC2"

    strings:
        $s1 = "/tmp/si_build/obj/Release/net472/si_build.pdb" ascii
        $s2 = "si_build" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20KB and
        $s1 and $s2
}

rule MALW_AdaptixC2_Beacon_RC4_Operator_Key
{
    meta:
        description = "Detects AdaptixC2 Windows beacon compiled for the 45.130.148.125 operator by matching the recovered RC4 config key (f443b9ce7e0658900f6a7ff0991cdee6) stored plaintext in .rdata alongside encrypted config"
        author = "The Hunters Ledger"
        date = "2026-04-30"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        hash_sha256 = "358edb5d7e3e38c2da0a2ef323a281283aa96d47a8649014d114923b06866c12"
        family = "AdaptixC2"

    strings:
        $b1 = { F4 43 B9 CE 7E 06 58 90 0F 6A 7F F0 99 1C DE E6 }
        $s1 = "9Connector" ascii
        $s2 = "13ConnectorHTTP" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 300KB and
        $b1 and
        ($s1 or $s2)
}

rule MALW_AdaptixC2_PowerShell_Loader_BeaconPS1
{
    meta:
        description = "Detects the operator-written beacon.ps1 PowerShell delivery loader by concatenated AMSI bypass, SI injector invocation, and base64 MZ prefix for inline PE — all three elements must co-occur"
        author = "The Hunters Ledger"
        date = "2026-04-30"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        hash_sha256 = "b4ffd7ca8f5505fd7b71882c67712e896c9d170a3b3b581baba78ee5d1c2b858"
        family = "AdaptixC2"

    strings:
        $s1 = "amsi'+'Con'+'text" ascii nocase
        $s2 = "*iUtils" ascii
        $s3 = "[SI]::Inject(" ascii
        $s4 = "TVqQAAMA" ascii

    condition:
        filesize < 512KB and
        $s1 and $s2 and $s3 and $s4
}

rule MALW_Ligolo_ng_v083_Agent
{
    meta:
        description = "Detects Ligolo-ng v0.8.3 stock reverse-tunnel agent by embedded version string, Go package namespace, and upstream commit hash — operator bundled this for internal-network pivot"
        author = "The Hunters Ledger"
        date = "2026-04-30"
        reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-45-130-148-125-20260430-detections/"
        hash_sha256 = "4b41f36f82db6da8767a0a1c2997c8242d80b2d10a8f1d28c252a9306ec152b5"
        family = "Ligolo-ng"

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

## Sigma Rules

### Rule 1 — AdaptixC2 PowerShell Loader: AMSI Bypass and SI Injector Invocation

**Detection Priority:** HIGH
**Rationale:** Three co-occurring strings (string-concatenated AMSI bypass + operator SI class invocation + base64 MZ prefix) in one script block are highly specific to the beacon.ps1 loader chain; no legitimate software combines these patterns.
**ATT&CK Coverage:** T1059.001 (PowerShell), T1562.001 (AMSI Bypass), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positive Risk:** LOW — the SI class name and concatenated AMSI pattern co-occurrence is operator-specific
**Deployment:** SIEM with PowerShell Script Block Logging (Windows Event ID 4104) ingested; endpoint EDR ScriptBlock telemetry

```yaml
title: AdaptixC2 PowerShell Loader - AMSI Bypass and SI Injector Invocation
id: a3f1c8e2-7b45-4d91-b832-6e0d9f2c1a74
status: test
description: Detects execution of the AdaptixC2 operator beacon.ps1 PowerShell loader by matching the string-concatenated AMSI bypass marker combined with the operator-specific SI injector class invocation and an embedded base64 MZ PE prefix. The concatenation pattern amsi+Con+text evades static AV string signatures; [SI]::Inject( identifies the operator-custom .NET injector loaded in-memory. Co-occurrence of all three strings in a single script block is highly specific to this loader. Requires PowerShell Script Block Logging (Event ID 4104).
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.execution
    - attack.defense-evasion
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
level: high
```

---

### Rule 2 — AdaptixC2 Default Listener: Firefox 20 UA with X-Beacon-Id Header (Proxy)

**Detection Priority:** HIGH
**Rationale:** Firefox 20 (February 2013) is anomalous in any 2026 traffic; X-Beacon-Id is an AdaptixC2-specific heartbeat header not used by any known legitimate software. Combination catches all operators running stock AdaptixC2 with default listener profile.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Encryption — RC4)
**Confidence:** HIGH
**False Positive Risk:** LOW — no legitimate browser or application uses Firefox 20 UA in 2026; X-Beacon-Id is framework-specific
**Deployment:** Web proxy log pipeline (Squid, Zscaler, Palo Alto URL filtering); Zeek HTTP log ingestion

```yaml
title: AdaptixC2 Default Listener - Anomalous Firefox 20 User-Agent with X-Beacon-Id Header
id: 7c9d4b81-3e62-4f08-a517-2d8e5a6c0b93
status: test
description: Detects outbound HTTP traffic matching the AdaptixC2 stock listener default profile. The Firefox 20 User-Agent (released February 2013) is anomalous in 2026 traffic and is the AdaptixC2 default listener UA string. The X-Beacon-Id header is the AdaptixC2 stock per-agent heartbeat header not used by any known legitimate browser or application. Co-occurrence of both indicators identifies any operator running stock AdaptixC2 with default listener configuration.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|contains: 'Firefox/20.0'
        cs-headers|contains: 'X-Beacon-Id'
    condition: selection
falsepositives:
    - Legacy embedded systems or industrial control software using a hardcoded Firefox 20 UA string - cross-reference against known asset inventory to exclude
level: high
```

---

### Rule 3 — AdaptixC2 Beacon: High-Frequency Deterministic HTTP POST Cadence

**Detection Priority:** MEDIUM
**Rationale:** 4–5 second POST cadence with zero jitter to stock C2 URI paths is highly anomalous; most production C2 and all legitimate health-check traffic uses longer or variable intervals. Requires aggregation-capable backend.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE — timing patterns require log aggregation; FP possible from monitoring agents
**False Positive Risk:** MEDIUM — infrastructure monitoring agents may produce similar cadence; tune by source IP allowlist
**Deployment:** Web proxy SIEM with count-by-source aggregation over 30-second sliding window; Zeek or NGFW flow logs

```yaml
title: AdaptixC2 Beacon - High-Frequency Deterministic HTTP POST Cadence to Stock URIs
id: 2e7f5a93-8c14-4b67-d259-1a3f6e8d0c52
status: test
description: Detects the AdaptixC2 fast-beacon callback pattern - a source IP making more than five HTTP POST requests within 30 seconds to stock AdaptixC2 URI paths (/api/v1/status or /jquery-3.3.1.min.js). The 4-5 second sleep with zero jitter produces a deterministic cadence that is highly anomalous for production traffic. Requires proxy log aggregation with count-by-source capability and a 30-second sliding window.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
        cs-uri-stem|contains:
            - '/api/v1/status'
            - '/jquery-3.3.1.min.js'
    condition: selection | count() by c-ip > 5
    timeframe: 30s
falsepositives:
    - Legitimate health-check endpoints polled at high frequency by infrastructure monitoring agents - add known monitoring source IPs to an allowlist filter
    - CI/CD pipeline job runners issuing rapid POST requests to status endpoints during build phases
level: medium
```

---

### Rule 4 — Suspicious .NET Assembly Load with si_build Injector Fingerprint

**Detection Priority:** HIGH
**Rationale:** The si_build string is a unique Linux build-artifact left by the operator in their custom injector.dll. It appears in PE version metadata fields and is not present in any known legitimate software. An unsigned DLL carrying this string loaded by powershell.exe is a definitive operator fingerprint.
**ATT&CK Coverage:** T1055 (Process Injection), T1055.002 (PE Injection), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positive Risk:** LOW — si_build is operator-specific and absent from any legitimate software corpus
**Deployment:** Endpoint EDR with Sysmon Event ID 7 (Image Load) telemetry; endpoint DLL inspection pipeline

```yaml
title: Suspicious .NET Assembly Image Load with Operator si_build Build Fingerprint
id: 5b8e2d47-1c93-4a76-f018-9b4d7e3c6f85
status: test
description: Detects PowerShell loading a .NET DLL image whose PE version metadata contains the operator build-placeholder string si_build. This string appears in CompanyName, FileDescription, InternalName, and OriginalFilename fields of the operator-written injector.dll found in this AdaptixC2 deployment. The string is a Linux-build artifact from /tmp/si_build/ left unredacted in the PE version resource and is not present in any known legitimate software.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        Description|contains: 'si_build'
    filter_legitimate:
        Signed: 'true'
    condition: selection and not filter_legitimate
falsepositives:
    - Internal developer tooling where a developer has named a build artifact si_build and loaded it via PowerShell - cross-reference against software asset inventory
level: high
```

---

### Rule 5 — Suspicious Active Directory Reconnaissance Tool Execution

**Detection Priority:** HIGH
**Rationale:** SharpHound, PowerView, and ADRecon are the three highest-value AD enumeration tools in this operator kit. Execution of any of these in an environment without active authorized red-team activity warrants immediate investigation.
**ATT&CK Coverage:** T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — legitimate red-team and pentest engagements produce identical events; correlate with change management records
**Deployment:** Endpoint EDR with Sysmon Event ID 1 (Process Creation) or equivalent; SIEM process-creation pipeline

```yaml
title: Suspicious Active Directory Reconnaissance Tool Execution
id: 9a3c6f12-4d87-4e52-b741-8c5f2a9d0e67
status: test
description: Detects execution of common Active Directory enumeration tools observed in this AdaptixC2 operator toolkit - SharpHound for BloodHound attack-path mapping, PowerView for PowerSploit AD recon, and ADRecon for comprehensive AD data harvesting. These tools are commodity open-source utilities frequently used by threat actors to identify domain privilege escalation paths, enumerate domain accounts and groups, and map trust relationships prior to lateral movement.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/PowerShellMafia/PowerSploit
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.discovery
logsource:
    product: windows
    category: process_creation
detection:
    selection_sharphound:
        Image|endswith: '\\SharpHound.exe'
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
        Image|endswith: '\\ADRecon.exe'
    condition: selection_sharphound or selection_powerview or selection_adrecon
falsepositives:
    - Authorized penetration testing or red team exercises - correlate against change management records and authorized testing windows
    - EDR or vulnerability assessment platforms that incorporate BloodHound data collection natively
level: high
```

---

### Rule 6 — Ligolo-ng Reverse Tunnel Agent Execution

**Detection Priority:** HIGH
**Rationale:** Ligolo-ng is a dedicated reverse-tunneling tool with no legitimate administrative use case that would appear on a workstation. Detection by process name, connect-argument pattern, or SHA-256 hash of the stock v0.8.3 release provides layered coverage.
**ATT&CK Coverage:** T1090.001 (Internal Proxy), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**False Positive Risk:** LOW — Ligolo-ng has no legitimate end-user presence; authorized pentest use is the only expected FP
**Deployment:** Endpoint EDR with Sysmon Event ID 1 (Process Creation); hash-based blocking in AV/EDR policy

```yaml
title: Ligolo-ng Reverse Tunnel Agent Execution
id: 3f7a2b58-9e04-4c83-a625-1d6b8f4e2a91
status: test
description: Detects execution of the Ligolo-ng reverse-tunneling agent by process image name, command-line connect argument combined with default port, or known file hash for stock v0.8.3. Ligolo-ng is an open-source TLS-over-TCP reverse proxy tool used by threat actors to create tunnels from a compromised host into internal networks, enabling lateral movement without direct routing. The operator in this campaign deployed the stock upstream v0.8.3 release at commit 913fe64e088d5db2185d392965bf4cd3dd1d9495.
references:
    - https://the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/
    - https://github.com/nicocha30/ligolo-ng
author: The Hunters Ledger
date: 2026/04/30
tags:
    - attack.command-and-control
logsource:
    product: windows
    category: process_creation
detection:
    selection_name:
        Image|endswith:
            - '\\ligolo.exe'
            - '\\ligolo-ng.exe'
    selection_cmdline:
        CommandLine|contains:
            - '--connect'
            - '-connect'
    selection_port:
        CommandLine|contains: ':11601'
    selection_hash:
        Hashes|contains: 'SHA256=4B41F36F82DB6DA8767A0A1C2997C8242D80B2D10A8F1D28C252A9306EC152B5'
    condition: selection_name or (selection_cmdline and selection_port) or selection_hash
falsepositives:
    - Authorized penetration testing or network administration use of Ligolo-ng - correlate against authorized change records and known red team activity windows
    - Security research and lab environments where Ligolo-ng is used for legitimate network tunneling evaluation
level: high
```

---

## Suricata Signatures

### Rule 1 — AdaptixC2 Operator C2 Traffic to 45.130.148.125 (Firefox 20 UA, POST)

**Detection Priority:** HIGH
**Rationale:** Combines the operator-specific C2 IP with the AdaptixC2 stock Firefox 20 UA on outbound POST. IP-anchored rules have the highest precision for this operator; will become stale if the operator migrates infrastructure.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Encryption — RC4 payload)
**Confidence:** HIGH
**False Positive Risk:** LOW — no legitimate traffic combines this destination IP with a 2013-era Firefox UA
**Deployment:** NGFW/IDS inline or network tap; Suricata on perimeter or east-west sensor; SOC triage queue

```
alert http $HOME_NET any -> 45.130.148.125 any (msg:"THL - AdaptixC2 Operator Beacon C2 Traffic to 45.130.148.125 - Firefox 20 UA"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0"; endswith; http.method; content:"POST"; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001001; rev:1;)
```

---

### Rule 2 — AdaptixC2 Default Listener X-Beacon-Id Heartbeat Header (Broad, Any IP)

**Detection Priority:** HIGH
**Rationale:** X-Beacon-Id is AdaptixC2-specific and appears in every heartbeat POST from any agent connected to any stock AdaptixC2 listener. This rule catches all operators running stock AdaptixC2, not only the 45.130.148.125 operator.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — X-Beacon-Id is not a standard HTTP header and is not used by any known legitimate application
**Deployment:** Perimeter IDS/IPS; inline NGFW; east-west network sensor in segmented environments

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Default Listener X-Beacon-Id Heartbeat Header Detected"; flow:established,to_server; http.header_names; content:"X-Beacon-Id"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001002; rev:1;)
```

---

### Rule 3a — AdaptixC2 Stock Listener URI /api/v1/status with Firefox 20 UA

**Detection Priority:** HIGH
**Rationale:** Combines the Firefox 20 stock UA with the default /api/v1/status URI path on a POST. URI path alone risks FP on legitimate status endpoints; combining with the 2013-era UA eliminates all realistic FP scenarios.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — Firefox 20 UA eliminates all legitimate /api/v1/status traffic as FP candidates
**Deployment:** Perimeter IDS/IPS; inline NGFW; edge network sensor

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Stock Listener URI Path with Firefox 20 UA"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0"; endswith; http.method; content:"POST"; http.uri; content:"/api/v1/status"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001003; rev:1;)
```

---

### Rule 3b — AdaptixC2 Operator-Added jQuery URI with Firefox 20 UA

**Detection Priority:** HIGH
**Rationale:** The /jquery-3.3.1.min.js URI was added by this operator beyond AdaptixC2 stock defaults. URI path alone is a moderate-FP risk (legitimate jQuery CDN traffic exists); the Firefox 20 UA eliminates all realistic legitimate FP scenarios.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — combination of operator-added URI + 2013-era Firefox UA is highly operator-specific
**Deployment:** Perimeter IDS/IPS; edge sensor; proxy with IDS inspection capability

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Operator-Added jQuery URI with Firefox 20 UA"; flow:established,to_server; http.user_agent; content:"Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0"; endswith; http.method; content:"POST"; http.uri; content:"/jquery-3.3.1.min.js"; nocase; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001004; rev:1;)
```

---

### Rule 4 — AdaptixC2 Operator RC4 Config Key Bytes in Network Traffic (Live-Capture)

**Detection Priority:** MEDIUM
**Rationale:** Matches the 16-byte RC4 key (f443b9ce7e0658900f6a7ff0991cdee6) recovered from the operator-specific beacon config appearing in raw TCP payload. Most useful for live-capture replay analysis or PCAP hunting. The key is per-listener-instance and will rotate on operator rebuild; useful during the active infrastructure window only.
**ATT&CK Coverage:** T1573.001 (Symmetric Encryption — RC4)
**Confidence:** MODERATE — key appears plaintext in .rdata; transmission in this exact form depends on protocol exchange phase
**False Positive Risk:** LOW — 16-byte sequence match in raw TCP is highly specific; benign collision probability is negligible
**Deployment:** Offline PCAP analysis; Suricata in live-capture mode on network tap during active incident; NOT suitable as a persistent production IDS rule (key rotates on operator rebuild)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL - AdaptixC2 Operator RC4 Config Key Bytes in Traffic (45.130.148.125 Operator-Specific)"; flow:established,to_server; content:"|F4 43 B9 CE 7E 06 58 90 0F 6A 7F F0 99 1C DE E6|"; reference:url,the-hunters-ledger.com/reports/opendirectory-45-130-148-125-20260430/; classtype:trojan-activity; sid:5001005; rev:1;)
```

---

## Coverage Gaps

The following techniques observed in the malware-analyst findings cannot be covered with high-confidence, low-FP detection rules given currently available evidence. Each gap is documented with the specific obstacle and the evidence that would enable rule creation.

| Gap | Observed Behavior | Obstacle | Evidence Needed to Close |
|---|---|---|---|
| RC4 key rotation | Operator-specific beacon config uses RC4 key f443b9ce7e0658900f6a7ff0991cdee6 stored plaintext in .rdata | RC4 key is generated per-listener-instance by AdaptixC2 (ax.random_string(32, hex)); a single operator rebuild invalidates all key-based YARA and Suricata rules | Recovery of a second beacon binary from a future operator operation to confirm whether the same key persists or rotates |
| HTTPS-wrapped C2 variant | Current C2 traffic is plaintext HTTP on port 80 with Firefox 20 UA and X-Beacon-Id header | If the operator enables TLS on the AdaptixC2 listener, all Suricata rules matching http.user_agent, http.header_names, and http.uri become blind; TLS SNI or JA3/JA3S fingerprinting would be required | Capture of a TLS-enabled AdaptixC2 session from this or a linked operator; JA3S fingerprint of the AdaptixC2 server TLS stack |
| Operator UA or URI path customization | Stock listener defaults used in this campaign (Firefox 20 UA, /api/v1/status, /updates/check.php, /content.html, /jquery-3.3.1.min.js) | AdaptixC2 listener profile fields are fully configurable; an operator who reads detection reporting will change the UA and URI paths, invalidating all UA- and URI-based Suricata rules | The X-Beacon-Id header rule (SID 5001002) is the most durable stock-framework indicator because the header name is defined in the AdaptixC2 source code, not in the listener profile |
| Linux Gopher agent variant (agent.bin ELF) | AdaptixC2 Linux ELF agent bundled in toolkit; post-exploitation capability on Linux hosts confirmed | Sigma rules in this package target Windows logsources exclusively (ps_script, image_load, process_creation); Linux auditd or Sysmon-for-Linux telemetry is required for equivalent coverage | Linux process creation telemetry (auditd EXECVE events or Sysmon-for-Linux Event ID 1) for the gopher ELF agent; behavioral signatures for its MessagePack C2 protocol |
| Alternative AdaptixC2 transports (TCP/SMB) | AdaptixC2 supports TCP and SMB named-pipe transports in addition to HTTP | Current Suricata rules target the HTTP listener exclusively; TCP transport would bypass all http.user_agent and http.header_names rules; SMB transport over named pipe \.\pipe\%08lx would require different detection layer | Capture of TCP or SMB transport traffic from an AdaptixC2 deployment; Sysmon Event ID 17/18 named-pipe telemetry for the SMB transport plumbing |
| Packed SharpHound and lazagne variants | SharpHound.exe (86% entropy, packed) and 10 MB lazagne.exe (97% entropy, IsPacked YARA hit) show operator-applied AV evasion | Hash-based detection is defeated by packing; the underlying tool fingerprints are inaccessible without unpacking; generic high-entropy YARA rules produce excessive FP volume on all packed binaries | Lab-VM unpacking of both samples (de4dot for SharpHound; upx -d for lazagne) to recover underlying strings for specific YARA rules |

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
