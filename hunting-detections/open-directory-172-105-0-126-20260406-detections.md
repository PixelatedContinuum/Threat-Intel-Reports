---
title: "Detection Rules — OpenStrike Beacon Toolkit on Open Directory 172.105.0.126"
date: '2026-04-06'
layout: post
permalink: /hunting-detections/open-directory-172-105-0-126-20260406-detections/
hide: true
---

**Campaign:** OpenStrike-CSBeacon-Toolkit-172.105.0.126
**Date:** 2026-04-06
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 4 | T1071.001, T1573.001, T1059.006, T1055.001, T1620 | LOW |
| Sigma | 5 | T1071.001, T1041, T1059.006, T1055.001, T1620 | LOW–MEDIUM |
| Suricata | 3 | T1071.001, T1041, T1105 | LOW |

**Rule-to-technique mapping:**

- **RAT_OpenStrike_C_Beacon** (YARA) — beacon.exe custom C implant → T1071.001, T1573.001
- **TOOLKIT_OpenStrike_Loader_Chain** (YARA) — run/sc_loader/veh_loader/dbg_loader/stager → T1059.006, T1055.001
- **MALW_CobaltStrike3x_TripwiredReflectiveLoader** (YARA) — tripwired CS 3.x DLL → T1620, T1055.001
- **TOOLKIT_OpenStrike_Python_Beacon** (YARA) — beacon_universal.py → T1059.006, T1071.001
- **OpenStrike Shellcode Loader Chain Executable Execution** (Sigma) → T1059.006, T1055.001
- **Cobalt Strike Malleable C2 MALC User-Agent** (Sigma) → T1620
- **OpenStrike Python ctypes VirtualAlloc Injection** (Sigma) → T1059.006, T1055.001
- **OpenStrike C2 GET to submit.php** (Sigma) → T1071.001, T1041
- **OpenStrike C2 IP Contact** (Sigma) → T1071.001
- **Cobalt Strike MALC User-Agent** (Suricata) → T1071.001
- **OpenStrike C2 Contact** (Suricata) → T1071.001, T1105
- **OpenStrike GET /submit.php Exfiltration** (Suricata) → T1041

## YARA Rules

```yara
/*
    Name: OpenStrike Beacon Toolkit + Cobalt Strike 3.x TripwiredLoader
    Author: The Hunters Ledger
    Date: 2026-04-06
    Identifier: OpenStrike C2 toolkit recovered from open directory on 172.105.0.126
    Reference: https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_OpenStrike_C_Beacon
{
    meta:
        description = "Detects OpenStrike C beacon (beacon.exe) by unique operator debug strings and hardcoded AES IV, compiled with MinGW GCC 15"
        author = "The Hunters Ledger"
        date = "2026-04-06"
        reference = "https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/"
        hash_sha256 = "7d6a17754f086b53ee294f5ccd60b0127f921520ce7b64fea0aebb47114fb5d2"
        family = "OpenStrike"

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

rule TOOLKIT_OpenStrike_Loader_Chain
{
    meta:
        description = "Detects OpenStrike shellcode loader chain EXEs (run.exe, sc_loader.exe, veh_loader.exe, dbg_loader.exe, stager.exe) by unique operator debug strings and shared MinGW GCC 15 build environment"
        author = "The Hunters Ledger"
        date = "2026-04-06"
        reference = "https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/"
        hash_sha256 = "821f815fab92fee03e2be44ad5370a953db085cd359a99519a2ddb7316b0d273"
        family = "OpenStrike"

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

rule MALW_CobaltStrike3x_TripwiredReflectiveLoader
{
    meta:
        description = "Detects operator-modified Cobalt Strike 3.x DLL beacon where the ReflectiveLoader export RVA is redirected to tripwire bytes 66 90 CC (xchg ax,ax; int3), crashing standard reflective injection tools"
        author = "The Hunters Ledger"
        date = "2026-04-06"
        reference = "https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/"
        hash_sha256 = "7a1a7659ec4201ecbca782bcedf9d4079265137279a490368309df3bd39297a4"
        family = "CobaltStrike"

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
        $tripwire and
        ($reflective_export or $original_name or $ua or $spawn) and
        ($aes_iv or $ua or $original_name)
}

rule TOOLKIT_OpenStrike_Python_Beacon
{
    meta:
        description = "Detects OpenStrike cross-platform Python beacon (beacon_universal.py) by self-identification banner and distinctive staging URI /qz99 or RSA key modulus prefix"
        author = "The Hunters Ledger"
        date = "2026-04-06"
        reference = "https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/"
        family = "OpenStrike"

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
---

## Sigma Rules

### OpenStrike

**Detection Priority:** CRITICAL
**Rationale:** Directly identifies known C2 infrastructure by IP and port; zero tuning required; any match is a confirmed incident indicator.
**ATT&CK Coverage:** T1071.001, T1105
**Confidence:** HIGH
**False Positive Risk:** LOW — IP/port pair is campaign-specific; verify against asset inventory for temporal overlap.
**Deployment:** Host-based EDR network telemetry (Sysmon Event ID 3), SIEM

```yaml
title: OpenStrike Campaign C2 Infrastructure Contact via HTTPS Port 8443
id: 5a8d2f96-c1e4-4b73-8f2a-9d6b3e7c4a18
status: experimental
description: Detects outbound network connections to 172.105.0.126 on port 8443, the confirmed C2 infrastructure for the OpenStrike beacon toolkit and co-hosted Cobalt Strike 3.x beacon. Any connection to this IP on this port should be treated as a high-priority incident indicator, as this IP hosted an open directory of custom offensive tools at time of analysis.
references:
    - https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
author: The Hunters Ledger
date: 2026/04/06
tags:
    - attack.command-and-control
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '172.105.0.126'
        DestinationPort: 8443
    condition: selection
falsepositives:
    - Legitimate services previously or subsequently hosted on 172.105.0.126 port 8443 unrelated to this campaign (verify against asset inventory and threat intel feed expiry)
level: critical
```

---

**Detection Priority:** HIGH
**Rationale:** Detects the GET-to-submit.php data exfiltration pattern unique to OpenStrike's Malleable C2 Transform VM — POST-focused rules miss this traffic entirely.
**ATT&CK Coverage:** T1041, T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — GET requests to /submit.php on port 8443 are not a legitimate application pattern; requires TLS inspection to fire.
**Deployment:** Proxy logs with TLS inspection, SIEM

```yaml
title: OpenStrike C2 Beacon Output Submission via HTTP GET to submit.php
id: 3f7a9c21-84b6-4d1e-a203-6f8e5c9b2a14
status: experimental
description: Detects HTTP GET requests to /submit.php on port 8443, indicative of OpenStrike beacon output submission. Unlike standard C2 beacons that use POST for data exfiltration, OpenStrike encodes command output in GET request URI or headers via a Malleable C2 Transform VM, making it harder to detect with POST-focused rules.
references:
    - https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
author: The Hunters Ledger
date: 2026/04/06
tags:
    - attack.exfiltration
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/submit.php'
        cs-method: 'GET'
        c-port: 8443
    condition: selection
falsepositives:
    - Legitimate web application endpoints using GET requests to paths named submit.php on non-standard ports (uncommon in enterprise environments)
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** OpenStrike loader filenames are operator-assigned and distinctive; any of these five names executing in a production environment warrants immediate investigation.
**ATT&CK Coverage:** T1059.006, T1055.001, T1620
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — sc_loader.exe, veh_loader.exe, dbg_loader.exe, and stager.exe are highly distinctive; run.exe may require hash or parent-process filtering.
**Deployment:** Endpoint EDR (Sysmon Event ID 1), SIEM

```yaml
title: OpenStrike Shellcode Loader Chain Executable Execution
id: 8c2e5f14-3a7d-4b91-9e6c-1d4f8a2b7c53
status: experimental
description: Detects execution of known OpenStrike shellcode loader chain binaries (run.exe, sc_loader.exe, veh_loader.exe, dbg_loader.exe, stager.exe) by process image name. These loaders implement a progressive capability chain from bare shellcode execution to SEH, VEH, INT3-based discovery, and HTTPS network staging, and were recovered from a threat actor open directory at 172.105.0.126.
references:
    - https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
author: The Hunters Ledger
date: 2026/04/06
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\run.exe'
            - '\sc_loader.exe'
            - '\veh_loader.exe'
            - '\dbg_loader.exe'
            - '\stager.exe'
    condition: selection
falsepositives:
    - Red team or penetration testing environments using these exact binary names (unlikely in production; verify against known asset inventory)
    - Legitimate software components coincidentally named run.exe or stager.exe (filter by ParentImage or hash if required)
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The OpenStrike Python beacon is the only known software pairing ctypes with VirtualAlloc in a Windows process context for shellcode injection; this combination is highly specific to this implant.
**ATT&CK Coverage:** T1059.006, T1055.001
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Python scripts invoking ctypes with VirtualAlloc exist in security research contexts; filter by script path or user account in high-noise environments.
**Deployment:** Endpoint EDR (Sysmon Event ID 1), script block logging, SIEM

```yaml
title: OpenStrike Python Beacon ctypes VirtualAlloc Shellcode Injection
id: 1d6b4e82-9f3c-4a17-b5d8-2e7c9a6f1b34
status: experimental
description: Detects a Python process with command line arguments referencing ctypes and VirtualAlloc, matching the OpenStrike beacon_universal.py cross-platform shellcode injection pattern. The Python beacon uses ctypes.windll to call VirtualAlloc for RWX memory allocation and CreateThread for shellcode execution, enabling in-memory payload staging without dropping a compiled binary.
references:
    - https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
author: The Hunters Ledger
date: 2026/04/06
tags:
    - attack.execution
    - attack.defense-evasion
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
    - Security research tools or CTF scripts using ctypes with VirtualAlloc in Python (uncommon in production enterprise environments)
    - Legitimate automation scripts performing memory-mapped operations via ctypes (filter by script path or user context if required)
level: high
```

---

### Cobalt Strike 3.x

**Detection Priority:** HIGH
**Rationale:** The MALC suffix in the Malleable C2 user-agent is not present in any known legitimate browser or application; any proxy match is a high-confidence CS 3.x beacon indicator.
**ATT&CK Coverage:** T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — MALC is not a known legitimate user-agent substring; verify against internal application inventory before suppressing.
**Deployment:** Proxy logs, SIEM, network TAP with HTTP inspection

```yaml
title: Cobalt Strike Malleable C2 Profile MALC User-Agent in Proxy Traffic
id: 9e3c7a15-6f2b-4d84-a1c9-8b5e2d7f3a61
status: experimental
description: Detects the Cobalt Strike 3.x Malleable C2 profile User-Agent string containing the MALC suffix (full string: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)). This non-standard suffix is a distinctive indicator of a configured Malleable C2 profile and does not appear in any known legitimate browser or application user-agent string.
references:
    - https://the-hunters-ledger.com/reports/open-directory-172-105-0-126-20260406/
author: The Hunters Ledger
date: 2026/04/06
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|contains: 'MALC'
    condition: selection
falsepositives:
    - Internal applications or monitoring tools with custom user-agent strings containing the substring MALC (verify against known software inventory before tuning out)
level: high
```

---

## Suricata Signatures

### OpenStrike

**Detection Priority:** CRITICAL
**Rationale:** Direct IP/port match against confirmed C2 infrastructure; fires on any TCP connection to 172.105.0.126:8443 regardless of TLS content — no decryption required.
**ATT&CK Coverage:** T1071.001, T1105
**Confidence:** HIGH
**False Positive Risk:** LOW — destination IP is campaign-specific; any match warrants investigation.
**Deployment:** Perimeter IDS/IPS, network TAP

```
alert tcp $HOME_NET any -> 172.105.0.126 8443 (msg:"THL OpenStrike C2 Infrastructure Contact 172.105.0.126:8443"; flow:established,to_server; flags:S+; sid:9001001; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_06, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_06;)
```

---

**Detection Priority:** HIGH
**Rationale:** GET requests to /submit.php on port 8443 are the OpenStrike command-output exfiltration path; this signature catches the Malleable C2 transform output channel that POST-focused rules miss entirely. Requires TLS inspection.
**ATT&CK Coverage:** T1041, T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — GET to /submit.php on port 8443 has no legitimate application precedent; requires TLS decryption to fire (inline IPS or decrypting proxy).
**Deployment:** Inline IPS with TLS inspection or decrypting proxy feeding Suricata

```
alert http $HOME_NET any -> $EXTERNAL_NET 8443 (msg:"THL OpenStrike C2 Beacon Output GET to /submit.php Port 8443"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/submit.php"; threshold:type limit,track by_src,count 1,seconds 60; sid:9001002; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_06, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_06;)
```

---

### Cobalt Strike 3.x

**Detection Priority:** HIGH
**Rationale:** The MALC user-agent suffix is unique to this Cobalt Strike Malleable C2 profile config; no legitimate browser or application generates this string. Fires at proxy layer — no TLS decryption required when HTTP headers are visible.
**ATT&CK Coverage:** T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — MALC is not a known legitimate UA substring; endswith anchors the match to the tail of the UA buffer for targeted fidelity; nocase added to catch any case variant.
**Deployment:** Perimeter IDS/IPS, proxy with HTTP user-agent logging

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Cobalt Strike Malleable C2 MALC User-Agent Detected"; flow:established,to_server; http.user_agent; content:"MALC)"; endswith; nocase; sid:9001003; rev:2; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_06, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_07;)
```

> **Community contribution:** The `endswith` anchor on this rule was suggested by [Anthony Vigil](https://www.linkedin.com/in/anthony-vigil/), who noted that anchoring the content match to the tail of the UA buffer improves targeted fidelity and engine efficiency over a bare substring match.

---

## Coverage Gaps

The following MITRE ATT&CK techniques were observed in analysis but could not be covered with high-confidence, low-FP detection rules given the available evidence:

**T1027 / T1027.002 — Obfuscation and Software Packing (OpenStrike)**
The OpenStrike loaders do not use a standard commercial packer; entropy-based YARA conditions for the specific shellcode blobs would require per-sample calibration. A rule based on PE section entropy ranges would produce unacceptable FP rates across packed legitimate software. Higher-confidence coverage would require extraction and analysis of additional shellcode blobs to identify a shared byte sequence.

**T1573.001 / T1573.002 — Symmetric and Asymmetric Cryptography (OpenStrike)**
The Trinity Protocol (AES-128-CBC + HMAC-SHA256 + RSA-2048) key material is embedded in the binary but is not unique enough in isolation to write a file-only rule without pairing with other OpenStrike-specific strings (already covered by existing YARA rules). The RSA modulus prefix `9f12c9cb6582f379088600e6cdb7ac80` is covered adequately by TOOLKIT_OpenStrike_Python_Beacon; a standalone rule would be redundant.

**T1622 — Debugger Evasion (OpenStrike dbg_loader.exe)**
The INT3-based entry-point discovery technique used by dbg_loader.exe is detectable behaviorally only through kernel-level debugger attachment monitoring, which is not available in standard Sysmon or proxy log sources. Detection would require EDR telemetry with API hooking coverage for DebugActiveProcess or WaitForDebugEvent. If such telemetry is available, a Sigma rule targeting dbg_loader.exe spawning a child process after a WaitForDebugEvent call would be viable.

**T1497.001 — System Checks / Sandbox Detection (check_ntdll.py)**
The check_ntdll.py EDR hook detection utility reads raw ntdll.dll at RVA 0x316FE to detect inline hooks. Coverage would require file-access monitoring with RVA-level granularity not available in standard Windows event logs. Detection is partially covered by the Python ctypes Sigma rule (OpenStrike Python Beacon ctypes VirtualAlloc Shellcode Injection) if check_ntdll.py is invoked via the same Python process, but direct behavioral coverage of the hook-check is not achievable with standard log sources.

**T1132.002 — Non-Standard Encoding (Malleable C2 Transform VM)**
The 17-opcode Transform VM encodes C2 traffic in a campaign-specific way. Without a known plaintext anchor derived from the transform bytecode for this specific profile, a Suricata content-based signature for the encoded traffic pattern cannot be written reliably. Network-layer detection is covered by the IP/port Suricata rule (sid:9001001) and the Sigma network_connection rule for 172.105.0.126:8443.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
