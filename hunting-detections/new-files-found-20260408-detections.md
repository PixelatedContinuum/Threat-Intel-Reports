---
title: "Detection Rules — OpenStrike Expanded Toolkit (New Files 2026-04-08)"
date: '2026-04-08'
layout: post
permalink: /hunting-detections/new-files-found-20260408-detections/
hide: true
---

**Campaign:** OpenStrike-CSBeacon-Toolkit-172.105.0.126
**Date:** 2026-04-08
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/new-files-found-20260408/

> **Scope note:** These rules cover **only new artifacts and behaviors** discovered in the April 8 expanded analysis of 106 additional files from the same open directory (172.105.0.126:8888). Rules for the originally published seven samples (beacon.exe gen-3, loader chain, Python beacon, CS 3.x tripwired DLL, MALC user-agent, 172.105.0.126:8443 C2 infrastructure) are in the companion file at `/hunting-detections/open-directory-172-105-0-126-20260406-detections/`. Do not deploy both files without deduplication review.

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 5 | T1055.012, T1095, T1572, T1543.003, T1036.004, T1129, T1071.001 | LOW |
| Sigma | 8 | T1055.012, T1218.011, T1543.003, T1036.004, T1095, T1572, T1129, T1036.005, T1071.001, T1041 | LOW–MEDIUM |
| Suricata | 6 | T1071.001, T1095, T1572, T1041, T1105 | LOW |

---

## YARA Rules

### OpenStrike Gen-4 Beacon

**Detection Priority:** HIGH
**Rationale:** The `/updates?id=%08x` and `/submit?id=%08x` URI format strings are unique to the gen-4 WinHTTP beacon rewrite and do not appear in any known legitimate software. Combined with the AES-CBC IV or GCC 15.2.0 compiler string, false positive risk is near zero.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography), T1041 (Exfiltration over C2)
**Confidence:** HIGH
**False Positive Risk:** LOW — URI format strings with 8-hex-digit IDs are specific to this beacon; `ChainingModeCBC` is a BCrypt mode string that does appear in other software but only in combination with the OpenStrike URI patterns here
**Deployment:** Endpoint AV/EDR file scan, memory scanner, gateway content inspection

```yara
/*
    Name: OpenStrike Gen-4 Beacon (beacon_windows_x64.exe)
    Author: The Hunters Ledger
    Date: 2026-04-08
    Identifier: OpenStrike Generation 4 WinHTTP beacon with SHA256 key derivation
    Reference: https://the-hunters-ledger.com/reports/new-files-found-20260408/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_OpenStrike_Gen4_Beacon
{
    meta:
        description = "Detects OpenStrike Generation 4 beacon (beacon_windows_x64.exe) by WinHTTP task-poll and output-submit URI format strings containing 8-hex-digit beacon IDs, the shared AES-128-CBC static IV, and the GCC 15.2.0 MinGW build artifact. Gen-4 is 10x smaller than gen-3 (30KB vs 299KB) with a correct Encrypt-then-MAC architecture and SHA256-based key derivation, though key exchange is absent confirming it is a development artifact."
        author = "The Hunters Ledger"
        date = "2026-04-08"
        hash_sha256 = "042761408e83155d24884a72291d9f10803becd790fbcfa6ff65e9e72eb44446"
        reference = "https://the-hunters-ledger.com/reports/new-files-found-20260408/"
        family = "OpenStrike"

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

---

### OpenStrike Gen-1 and Gen-2 Prototype Beacons

**Detection Priority:** MEDIUM
**Rationale:** `Cookie: SESSIONID=%d` is the gen-1 identification mechanism absent from any gen-3/gen-4 rule. The RSA-1024 modulus prefix `008cadd72dbf3cc108` is byte-for-byte identical in mini_beacon2.exe and the CS 4.4 Key B ecosystem — a shared string that fingerprints both the prototype and the CS DLLs using the same key. The `{ 00 00 BE EF }` magic is the on-wire registration packet header (big-endian 0xEFBE0000 stored in network order).
**ATT&CK Coverage:** T1071.001, T1573.002 (Asymmetric Cryptography — RSA-1024 registration)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — `Cookie: SESSIONID=%d` is specific to gen-1 prototype; RSA modulus prefix could theoretically appear in other RSA-1024 software but requires the GCC 15 compiler string as corroboration
**Deployment:** Endpoint AV/EDR file scan, memory scanner

```yara
/*
    Name: OpenStrike Gen-1/Gen-2 Prototype Beacons
    Author: The Hunters Ledger
    Date: 2026-04-08
    Identifier: OpenStrike mini_beacon (gen-1) and mini_beacon2 (gen-2) prototypes
    Reference: https://the-hunters-ledger.com/reports/new-files-found-20260408/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_OpenStrike_Proto_Beacons
{
    meta:
        description = "Detects OpenStrike Generation 1 (mini_beacon.exe) and Generation 2 (mini_beacon2.exe) prototype beacons. Gen-1 uses Cookie: SESSIONID=%d format for C2 host identification with no cryptography. Gen-2 adds RSA-1024 BCrypt CNG registration with a binary magic header (0xEFBE0000 big-endian) and host fingerprinting including process name masquerade as svchost.exe. The RSA-1024 modulus prefix is shared with the CS 4.4 Key B ecosystem."
        author = "The Hunters Ledger"
        date = "2026-04-08"
        hash_sha256 = "03492f128fcc3910bda15f393c30ad3e04f5a50de36464d1e24038f49d889324"
        reference = "https://the-hunters-ledger.com/reports/new-files-found-20260408/"
        family = "OpenStrike"

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

---

### Cobalt Strike Artifact Kit EAX-Redirect Service Variant

**Detection Priority:** HIGH
**Rationale:** `DceRpcSs` as a service name combined with `\\.\pipe\MSSE-%d-server` is unique to the Cobalt Strike Artifact Kit service variant. No legitimate Windows component uses either string. The triple-AND condition (service name + pipe pattern + rundll32 target) produces extremely low false positive risk. This rule catches the binary on disk or in memory before hollowing executes.
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1543.003 (Windows Service), T1036.004 (Masquerade Task or Service), T1218.011 (Rundll32)
**Confidence:** HIGH
**False Positive Risk:** LOW — `DceRpcSs` is not a legitimate Windows service name; `MSSE-%d-server` is CS Artifact Kit default; no legitimate Windows binary combines both
**Deployment:** Endpoint AV/EDR file scan, memory scanner

```yara
/*
    Name: Cobalt Strike Artifact Kit EAX-Redirect Service Variant
    Author: The Hunters Ledger
    Date: 2026-04-08
    Identifier: artifact32svc.exe / artifact64svc.exe — EAX-redirect process hollowing
    Reference: https://the-hunters-ledger.com/reports/new-files-found-20260408/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule MALW_ArtifactKit_EAXRedirect_Svc
{
    meta:
        description = "Detects Cobalt Strike Artifact Kit service variant (artifact32svc.exe/artifact64svc.exe) that registers as the DceRpcSs service, creates a named pipe matching MSSE-[0-9]+-server for XOR-encoded shellcode delivery, and performs EAX-redirect thread hijacking of a suspended rundll32.exe process. Unlike classic process hollowing, this variant never calls NtUnmapViewOfSection — detection must anchor on SetThreadContext called on suspended threads, or on this binary's static strings."
        author = "The Hunters Ledger"
        date = "2026-04-08"
        hash_sha256 = "701b4f60411a26abfb137f476c9328900843ee5a49780f2fcd23a5cb15498f16"
        reference = "https://the-hunters-ledger.com/reports/new-files-found-20260408/"
        family = "CobaltStrike"

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

---

### CovertVPN Layer 2 Bridge Module

**Detection Priority:** HIGH
**Rationale:** `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH` is the unpatched AES key config placeholder embedded in covertvpn.dll. Any file containing this exact 32-character sentinel combined with npf.sys or wpcap.dll strings is definitively the CovertVPN module or a derivative. The config placeholder is only meaningful in the context of the WinPcap deployment (npf.sys / wpcap.dll) or the HTTP data channel URI (/receive%s).
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling), T1543.003 (Windows Service — npf.sys kernel driver)
**Confidence:** HIGH
**False Positive Risk:** LOW — the 32-character AAAA...HHHH AES placeholder is a development artifact unique to this module; wpcap.dll embedded in a non-WinPcap installer binary is anomalous
**Deployment:** Endpoint AV/EDR file scan, memory scanner, DLP gateway

```yara
/*
    Name: CovertVPN Layer 2 Bridge Module
    Author: The Hunters Ledger
    Date: 2026-04-08
    Identifier: covertvpn.dll — CS CovertVPN L2 bridge with embedded WinPcap stack
    Reference: https://the-hunters-ledger.com/reports/new-files-found-20260408/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule MALW_CovertVPN_L2Bridge
{
    meta:
        description = "Detects the Cobalt Strike CovertVPN Layer 2 bridge module (covertvpn.dll) by its unpatched 32-character AES key config placeholder (AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH), self-contained WinPcap 4.1.3 deployment strings (npf.sys, wpcap.dll), and HTTP data channel URI (/receive%s). The module embeds npf.sys as a kernel driver in its .data section (~556KB) and supports 5 transport channels: TCP connect/bind, UDP, HTTP, and ICMP echo with 0xDD/0xCC frame markers."
        author = "The Hunters Ledger"
        date = "2026-04-08"
        hash_sha256 = "af688b120db0a3b324e2cd468cfead71b7895a3c815f4026d51ac7fca0cb8ab4"
        reference = "https://the-hunters-ledger.com/reports/new-files-found-20260408/"
        family = "CovertVPN"

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

---

### OpenStrike DLL Loader

**Detection Priority:** HIGH
**Rationale:** The hardcoded path `C:\Windows\Temp\beacon.dll` combined with the diagnostic format strings `DLL loaded at %p` and `LoadLibrary failed: %lu` is unique to dll_loader.exe. No legitimate software hardcodes a beacon.dll path in Windows\Temp. The GCC 15 compiler string further anchors this to the OpenStrike build environment.
**ATT&CK Coverage:** T1129 (Shared Modules), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — `beacon.dll` in C:\Windows\Temp is not a path any legitimate software component uses; diagnostic strings are operator-specific
**Deployment:** Endpoint AV/EDR file scan, memory scanner

```yara
/*
    Name: OpenStrike DLL Loader (dll_loader.exe)
    Author: The Hunters Ledger
    Date: 2026-04-08
    Identifier: OpenStrike dll_loader.exe — disk-drop LoadLibraryA outlier loader
    Reference: https://the-hunters-ledger.com/reports/new-files-found-20260408/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_OpenStrike_DllLoader
{
    meta:
        description = "Detects OpenStrike dll_loader.exe, a custom loader that loads a Cobalt Strike beacon DLL from the hardcoded path C:\\Windows\\Temp\\beacon.dll using LoadLibraryA, then enters an infinite Sleep(60000) keepalive loop. Unlike the five in-memory loader variants from the same GCC 15 codebase, this loader drops payload to disk rather than allocating RWX memory. Identified by the hardcoded path, operator diagnostic format strings, and GCC 15-win32 MinGW build artifact."
        author = "The Hunters Ledger"
        date = "2026-04-08"
        hash_sha256 = "820cf45c92b9cce9536ad108fc4b8c1c501bb6f4e30119b1bef0486670de02e4"
        reference = "https://the-hunters-ledger.com/reports/new-files-found-20260408/"
        family = "OpenStrike"

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

### EAX-Redirect Process Hollowing

**Detection Priority:** HIGH
**Rationale:** rundll32.exe spawned with no command-line arguments by services.exe is the precise behavioral signature of EAX-redirect hollowing — services.exe invokes the Artifact Kit service binary, which then spawns a bare rundll32.exe as the hollowing target. Legitimate Windows services virtually never spawn rundll32.exe without arguments (they always pass a DLL path and entry point).
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1218.011 (Rundll32)
**Confidence:** HIGH
**False Positive Risk:** LOW — Windows services invoking bare rundll32.exe with no arguments have no legitimate precedent; verify by reviewing the parent service binary path if any false positives surface
**Deployment:** Endpoint EDR (Sysmon Event ID 1), SIEM

```yaml
title: Artifact Kit EAX-Redirect Process Hollowing via Rundll32 No Arguments
id: a4f82c19-7b3e-4d56-9e1a-2c5f8b0d3e74
status: experimental
description: Detects the Cobalt Strike Artifact Kit service variant EAX-redirect process hollowing pattern where a Windows service process (services.exe parent) spawns rundll32.exe with no command-line arguments. The Artifact Kit then performs VirtualAllocEx, WriteProcessMemory, and SetThreadContext on the suspended rundll32.exe to redirect execution to shellcode via the EAX register. This technique bypasses NtUnmapViewOfSection-anchored classic process hollowing detection because the original PE is never unmapped.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
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
    - Legitimate Windows services that invoke rundll32.exe without arguments (extremely rare; verify by examining the parent service binary path and cross-referencing against asset inventory)
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The MSSE-[number]-server named pipe pattern is the Cobalt Strike Artifact Kit default pipe name, generated by `GetTickCount() % 9898`. This pipe is created and immediately self-connected within the same process to transfer XOR-encoded shellcode via kernel pipe indirection. No legitimate Windows component creates pipes matching this pattern.
**ATT&CK Coverage:** T1055.012 (Process Hollowing — shellcode staging via pipe)
**Confidence:** HIGH
**False Positive Risk:** LOW — MSSE-[0-9]+-server is Artifact Kit-specific; startswith `\MSSE-` and endswith `-server` together are highly discriminating
**Deployment:** Endpoint EDR (Sysmon Event ID 17), SIEM

```yaml
title: Cobalt Strike Artifact Kit MSSE Named Pipe Creation
id: b7c91d3e-5a20-4f88-b2d4-8e1c9a4f6b52
status: experimental
description: Detects creation of the Cobalt Strike Artifact Kit default named pipe pattern MSSE-[number]-server. The Artifact Kit service variant (artifact32svc/artifact64svc) creates this pipe to transfer XOR-encoded shellcode to the hollowing target via kernel pipe indirection as an AV evasion technique. The pipe ID is derived from GetTickCount() modulo 9898, producing values in the range 0 to 9897. No legitimate Windows component creates pipes with this naming pattern.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.defense-evasion
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName|startswith: '\MSSE-'
        PipeName|endswith: '-server'
    condition: selection
falsepositives:
    - None known — MSSE-[0-9]+-server pipe naming is specific to the Cobalt Strike Artifact Kit default configuration; no legitimate Windows component uses this pattern
level: high
```

---

**Detection Priority:** CRITICAL
**Rationale:** The service name `DceRpcSs` is not a legitimate Windows service. It masquerades as the built-in `RpcSs` service (Remote Procedure Call). Any Windows Security Event ID 7045 with ServiceName `DceRpcSs` is unambiguously malicious activity from the Artifact Kit service variant.
**ATT&CK Coverage:** T1543.003 (Windows Service), T1036.004 (Masquerade Task or Service)
**Confidence:** HIGH
**False Positive Risk:** LOW — DceRpcSs is not a Windows built-in service name and does not appear in any known legitimate software
**Deployment:** Windows Security Event Log (Event ID 7045), SIEM

```yaml
title: DceRpcSs Masquerading Service Installation
id: c3d84e7f-2b61-4a99-8f3c-5d7e1b8c2a96
status: experimental
description: Detects installation of a Windows service named DceRpcSs, which masquerades as the legitimate RpcSs (Remote Procedure Call) service. The Cobalt Strike Artifact Kit service variant registers under this name to blend with built-in Windows services and survive casual administrative review. The legitimate RpcSs service name does not match DceRpcSs in any Windows version. Any Event ID 7045 with this service name is a high-confidence incident indicator.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'DceRpcSs'
    condition: selection
falsepositives:
    - None known — DceRpcSs is not a legitimate Windows service name; any match should be treated as a high-confidence incident indicator requiring immediate investigation
level: critical
```

---

**Detection Priority:** HIGH
**Rationale:** npf.sys is the WinPcap kernel driver. Loading it from a user temp directory (AppData\Local\Temp or C:\Windows\Temp) is not normal WinPcap installation behavior — legitimate installations place npf.sys in System32\drivers. The CovertVPN module extracts npf.sys from its embedded .data section and installs it as a service from %TEMP%, making the load path the key discriminator.
**ATT&CK Coverage:** T1543.003 (Windows Service — kernel driver), T1095 (Non-Application Layer Protocol — raw packet capture enablement)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Legitimate WinPcap/Npcap installers occasionally stage npf.sys in %TEMP% during initial setup before moving to System32\drivers; filter by checking whether a persistent System32\drivers\npf.sys installation follows within the same session
**Deployment:** Endpoint EDR (Sysmon Event ID 6), SIEM

```yaml
title: CovertVPN WinPcap npf.sys Kernel Driver Loaded from Temp Directory
id: d9e05a82-6c34-4b77-a1f5-3e8d2c7b4f01
status: experimental
description: Detects loading of the npf.sys WinPcap kernel driver from a user temporary directory. The Cobalt Strike CovertVPN Layer 2 bridge module embeds WinPcap 4.1.3 components (npf.sys x86 and amd64, wpcap.dll, Packet.dll) in its .data section and installs npf.sys as a kernel driver service from %TEMP% to enable raw packet capture for its ICMP and UDP transport channels. Legitimate WinPcap and Npcap installations place the driver in System32\drivers, not in user temp directories.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.persistence
    - attack.command-and-control
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
    - Legitimate WinPcap or Npcap installers that stage npf.sys in a temporary directory before moving it to System32\drivers (uncommon; verify by checking for a subsequent persistent driver installation in System32\drivers)
level: high
```

---

**Detection Priority:** CRITICAL
**Rationale:** The file path `C:\Windows\Temp\beacon.dll` is hardcoded into dll_loader.exe. Any process creating a file at exactly this path is either dll_loader.exe staging its payload or an operator manually dropping a beacon DLL to this location. Neither scenario represents legitimate activity.
**ATT&CK Coverage:** T1129 (Shared Modules), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — beacon.dll at C:\Windows\Temp is not a path used by any known legitimate software; the filename alone at this directory is anomalous
**Deployment:** Endpoint EDR (Sysmon Event ID 11), SIEM

```yaml
title: Cobalt Strike Beacon DLL Dropped to Windows Temp Directory
id: e1f73b45-8d92-4c66-b3e7-4a9f5d1c8b27
status: experimental
description: Detects creation of a file named beacon.dll in C:\Windows\Temp, the hardcoded drop path used by OpenStrike dll_loader.exe. The loader uses LoadLibraryA to load the Cobalt Strike beacon DLL from this exact path and then enters an infinite Sleep(60000) keepalive loop. Writing a payload named beacon.dll to this system-writable directory is a high-confidence indicator of dll_loader.exe staging activity or direct operator file placement.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename: 'C:\Windows\Temp\beacon.dll'
    condition: selection
falsepositives:
    - None known — the filename beacon.dll at this exact path is not used by any known legitimate software; any match should be treated as a high-confidence incident indicator
level: critical
```

---

**Detection Priority:** HIGH
**Rationale:** The `BOIE9;ENUSSEM` suffix is not present in any known legitimate Internet Explorer 9 user-agent string. Genuine IE9 user-agents end with `Trident/5.0)` or include standard locale codes without semicolon-delimited tags. This suffix is injected by the beacon80.dll Malleable C2 profile configuration and makes the agent trivially detectable at the proxy layer.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — BOIE9;ENUSSEM does not appear in any known legitimate browser or application user-agent string; the semicolon-delimited format after Trident/5.0 is not produced by genuine IE9 builds
**Deployment:** Proxy logs, network TAP with HTTP inspection, SIEM

```yaml
title: Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent in Proxy Traffic
id: f4a82d61-3c57-4e88-9b2f-5e1a7c8d3f49
status: experimental
description: Detects the Cobalt Strike beacon80.dll Malleable C2 profile User-Agent containing the BOIE9;ENUSSEM suffix. The full user-agent string is Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUSSEM). This non-standard suffix is injected by the Malleable C2 profile configuration and does not appear in genuine Internet Explorer 9 browser traffic. This profile is distinct from the MALC-suffix profile covered in the companion April 6 detection file.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-user-agent|contains: 'BOIE9;ENUSSEM'
    condition: selection
falsepositives:
    - None known — BOIE9;ENUSSEM does not appear in any known legitimate browser or application user-agent string
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The URI pattern `/updates?id=` followed by exactly 8 lowercase hex characters is the OpenStrike gen-4 task polling format. The beacon polls this endpoint at approximately 5-second intervals. The 8-hex-digit ID is a djb2 hash of ComputerName XOR'd with PID — deterministic per host, useful for correlating multiple alerts to the same infected endpoint.
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — web applications may legitimately use `/updates?id=` endpoints; the 8-hex-digit format constraint reduces but does not eliminate FP risk; correlate with ~5-second beaconing interval and POST to `/submit?id=` for high confidence
**Deployment:** Proxy logs, SIEM

```yaml
title: OpenStrike Gen-4 Beacon Task Polling HTTP GET to /updates with Hex Beacon ID
id: a8c35f72-4d19-4b83-9e6a-1c7d5e2b8f30
status: experimental
description: Detects the OpenStrike Generation 4 beacon (beacon_windows_x64.exe) task polling pattern — HTTP GET requests to /updates with an 8-character lowercase hex beacon ID query parameter. The beacon ID is a djb2 hash variant (multiplier 0x1f) of ComputerName XOR'd with PID, making it deterministic per host across process restarts. The beaconing interval is approximately 5 seconds with 10 percent jitter (4500–5500ms base). Correlate with corresponding POST to /submit?id=[same ID] for high-confidence identification.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
        c-uri|re: '^/updates\?id=[0-9a-f]{8}$'
    condition: selection
falsepositives:
    - Web applications using /updates as an API endpoint with an id parameter of exactly 8 lowercase hex characters (uncommon in enterprise environments; verify against known application inventory and look for correlated POST to /submit?id=)
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** The URI pattern `/submit?id=` followed by exactly 8 hex characters is the OpenStrike gen-4 output submission path. This endpoint receives AES-128-CBC encrypted command output with an appended 16-byte HMAC-SHA256 tag. Correlating this with the matching `/updates?id=` GET for the same beacon ID confirms an active gen-4 beacon session.
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW-MEDIUM — same URI ambiguity as the GET polling rule; combination with `/updates?id=` GET for same ID reduces FP risk significantly
**Deployment:** Proxy logs, SIEM

```yaml
title: OpenStrike Gen-4 Beacon Output Submission HTTP POST to /submit with Hex Beacon ID
id: b2e49c83-5f61-4a77-9d3e-2b8c1a4f7e52
status: experimental
description: Detects the OpenStrike Generation 4 beacon output submission pattern — HTTP POST to /submit with an 8-character lowercase hex beacon ID query parameter. Command output is AES-128-CBC encrypted with PKCS7 padding, then a 16-byte truncated HMAC-SHA256 tag is appended (Encrypt-then-MAC). The beacon ID matches the corresponding GET to /updates?id=[same ID]. Correlating matched pairs of GET /updates and POST /submit with the same 8-hex-digit ID provides high-confidence identification of an active gen-4 beacon session.
references:
    - https://the-hunters-ledger.com/reports/new-files-found-20260408/
author: The Hunters Ledger
date: 2026/04/08
tags:
    - attack.exfiltration
    - attack.command-and-control
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'POST'
        c-uri|re: '^/submit\?id=[0-9a-f]{8}$'
    condition: selection
falsepositives:
    - API endpoints using /submit with an id parameter of exactly 8 hex characters accepting POST data (uncommon in enterprise environments; correlate with matched GET to /updates?id= for the same ID to confirm)
level: high
```

---

## Suricata Signatures

### OpenStrike Gen-4 Beacon Network Signatures

**Detection Priority:** HIGH
**Rationale:** The `/updates?id=` URI with an 8-hex-digit ID at regular 5-second intervals is unique to gen-4 beacon polling. The threshold statement limits alert volume to one alert per source per 30 seconds, preventing alert fatigue from the high beaconing frequency while still capturing every distinct beaconing host.
**ATT&CK Coverage:** T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — the combination of URI pattern and 5-second beaconing interval is highly specific; standalone the URI has medium FP risk mitigated by the threshold
**Deployment:** Perimeter IDS/IPS, network TAP

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenStrike Gen4 Beacon Task Poll GET /updates?id=[hex8]"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/updates?id="; pcre:"/\/updates\?id=[0-9a-f]{8}$/U"; threshold:type limit,track by_src,count 1,seconds 30; sid:9002001; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_08;)
```

---

**Detection Priority:** HIGH
**Rationale:** The `/submit?id=` POST is the gen-4 beacon output exfiltration channel. Any POST to this URI pattern with binary content carries AES-128-CBC encrypted command output. The threshold limits to one alert per source per 60 seconds.
**ATT&CK Coverage:** T1041, T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — POST to `/submit?id=[8hex]` with binary content has no legitimate application precedent in enterprise environments
**Deployment:** Perimeter IDS/IPS, network TAP

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL OpenStrike Gen4 Beacon Output Submission POST /submit?id=[hex8]"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/submit?id="; pcre:"/\/submit\?id=[0-9a-f]{8}$/U"; threshold:type limit,track by_src,count 1,seconds 60; sid:9002002; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_08;)
```

---

**Detection Priority:** HIGH
**Rationale:** The `BOIE9;ENUSSEM` suffix is the beacon80.dll Malleable C2 user-agent. The `endswith` modifier anchors the match to the tail of the User-Agent buffer, preventing false positives from the substring appearing mid-string in a different UA. The closing `)` is included to align the match with the actual end of the UA string.
**ATT&CK Coverage:** T1071.001
**Confidence:** HIGH
**False Positive Risk:** LOW — this suffix does not appear in any known legitimate UA string
**Deployment:** Perimeter IDS/IPS, proxy with HTTP user-agent logging

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Cobalt Strike Malleable C2 BOIE9 IE9 User-Agent Detected"; flow:established,to_server; http.user_agent; content:"BOIE9;ENUSSEM)"; endswith; nocase; sid:9002003; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_08;)
```

---

**Detection Priority:** HIGH
**Rationale:** The stager URIs `/au2U` and `/msI4` on port 80 are the shellcode download endpoints for the two CS HTTP reverse stagers. Any HTTP GET to either URI on 172.105.0.126 is a confirmed stager callback. This signature fires without TLS inspection since the stager uses plain HTTP on port 80.
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — both URIs are campaign-specific random-looking paths on the confirmed C2 IP; the combination is highly discriminating
**Deployment:** Perimeter IDS/IPS, network TAP

```
alert http $HOME_NET any -> 172.105.0.126 80 (msg:"THL Cobalt Strike Stager Download URI /au2U or /msI4 on Port 80"; flow:established,to_server; http.method; content:"GET"; http.uri; pcre:"/^\/(?:au2U|msI4)$/U"; sid:9002004; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Critical, updated_at 2026_04_08;)
```

---

**Detection Priority:** HIGH
**Rationale:** CovertVPN's HTTP transport channel uses `/receive` followed by a session ID as the data retrieval endpoint. Matching the `/receive` prefix on any HTTP GET from internal hosts to external destinations detects the CovertVPN HTTP channel regardless of session ID length or format. Threshold limits alert volume.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1071.001
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — `/receive` is a common REST API path segment; this rule requires correlation with other CovertVPN indicators (npf.sys load, ICMP anomalies) for high-confidence identification; threshold set at 3 per 60 seconds to suppress legitimate single-request traffic
**Deployment:** Perimeter IDS/IPS, network TAP with HTTP inspection

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL CovertVPN HTTP Data Channel GET /receive Endpoint"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/receive"; startswith; threshold:type limit,track by_src,count 3,seconds 60; sid:9002005; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_08;)
```

---

**Detection Priority:** HIGH
**Rationale:** CovertVPN ICMP tunnel traffic is identified by oversized ICMP echo request payloads (>128 bytes) containing 0xDD (data frame) or 0xCC (keepalive) markers at a fixed offset. Standard Windows ping generates 32-byte payloads. Payloads exceeding 128 bytes with these specific marker bytes are anomalous and indicate tunneled Ethernet frame traffic. The `dsize` keyword constrains on payload size; `byte_test` validates the marker byte value.
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — large ICMP payloads can occur in legitimate network diagnostics (ping -l on Windows, MTU path discovery); the 0xDD/0xCC byte test at offset 4 is the discriminating factor; assess false positive rate in environments with active network diagnostic tooling
**Deployment:** Perimeter IDS/IPS, network TAP (requires ICMP inspection capability)

```
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL CovertVPN ICMP Tunnel Oversized Payload with Data or Keepalive Marker"; itype:8; dsize:>128; byte_test:1,=,0xDD,4; threshold:type limit,track by_src,count 5,seconds 60; sid:9002006; rev:1; metadata:affected_product Windows, attack_target Client_Endpoint, created_at 2026_04_08, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2026_04_08;)
```

> **Deployment note:** Deploy a second signature with `byte_test:1,=,0xCC,4` for the keepalive marker (0xCC at offset 4) as a companion rule with sid:9002007. The data marker (0xDD) and keepalive marker (0xCC) are mutually exclusive per packet; two signatures provide complete coverage. Assign sid:9002007 and identical metadata with `msg` updated to `CovertVPN ICMP Tunnel Keepalive Marker`.

---

## Coverage Gaps

The following MITRE ATT&CK techniques observed in the expanded analysis could not be covered with high-confidence, low-FP rules given the available evidence or log source constraints:

**T1055.002 — PE Injection (in-memory loaders)**
All five in-memory OpenStrike loaders (beacon_loader, beacon_rdi, beacon_srdi2, beacon_dl, beacon_full) use `VirtualAlloc(RWX)` + memcpy + indirect call or CreateThread. Behavioral rules for VirtualAlloc(RWX) followed by CreateThread exist in multiple threat intelligence feeds and would produce high false positive rates across legitimate software. Rule development would require pairing with the specific GCC 15 compiler artifacts already covered in the YARA file, making a standalone Sigma rule redundant. Memory scanner deployment of the existing YARA rules is the recommended coverage path.

**T1572 — Protocol Tunneling (TCP/UDP CovertVPN channels)**
CovertVPN's TCP connect (`t`), TCP bind (`b`), and UDP (`u`) transport channels do not produce protocol-level signatures distinct from generic TCP/UDP traffic. Detection of these channels requires NetFlow anomaly analysis (unusual connection volumes or session durations) rather than signature-based rules. The ICMP and HTTP channels are covered above.

**T1059.007 — JavaScript (social engineering kit)**
The `keylogger.js` and `analytics.js` browser-side scripts execute in the browser context and are not visible to endpoint EDR or network IDS without full browser script logging (e.g., Chrome DevTools Protocol telemetry). Rule development requires browser security tooling not available in standard Sysmon or proxy log sources.

**T1112 — Modify Registry (template.vbs AccessVBOM)**
The `template.vbs` script modifies `HKEY_CURRENT_USER\Software\Microsoft\Office\[version]\[application]\Security\AccessVBOM` to enable VBA macro execution. A Sigma rule for this registry modification would have high FP risk, as security tools and IT management software routinely modify Office security registry keys. High-confidence detection requires pairing the registry modification with the specific template.vbs script file path, which is not available in this analysis.

**T1056.001 — Keylogging (keylogger.js)**
Browser-side JavaScript keylogging has no host-level EDR telemetry visibility in standard Sysmon configurations. Detection is possible only through browser security tooling or DNS/proxy correlation if the credential harvester posts to an observable endpoint.

**T1573.002 — Asymmetric Cryptography (RSA-1024 in gen-2)**
The RSA-1024 BCrypt CNG registration in mini_beacon2.exe is covered by the YARA rule for gen-1/gen-2 proto-beacons. A standalone Sigma rule for BCrypt RSA usage would produce unacceptable FP rates across all legitimate software using CNG. No additional rule is warranted.

**CS Port 50050 (Team Server) — Network Coverage**
A Suricata signature for outbound TCP to port 50050 was evaluated and rejected: port 50050 is used by numerous legitimate applications. The SSL certificate hash (`6e8efd85110de376426cde809f25d50ffcbb1d0e39d11c82913757cb277e15dd`) is included in the IOC feed for blocking at the TLS inspection layer, which is the appropriate detection mechanism for team server management traffic.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
