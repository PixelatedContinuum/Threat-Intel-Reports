---
title: "Detection Rules — Open Directory at 193.56.255.154 (XiebroC2 v3.1 and Covenant C2)"
date: '2026-04-03'
layout: post
permalink: /hunting-detections/open-directory-193-56-255-154-xiebroc2-detections/
hide: true
---

**Campaign:** OpenDirectory-XiebroC2-Covenant-193.56.255.154
**Date:** 2026-04-03
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/open-directory-193-56-255-154-xiebroc2/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 4 | T1055.012, T1055, T1620, T1059.001, T1573.001, T1036 | LOW |
| Sigma | 5 | T1620, T1055.012, T1055, T1059.001, T1071.001, T1140, T1027 | LOW–MEDIUM |
| Suricata | 3 | T1071.001, T1573.001, T1571, T1036 | LOW |

---

## Multi-Family Organization

This campaign involves three malicious payloads from a single staging server:
- **XiebroC2 v3.1** — Go x86 TCP implant (`main.exe`)
- **Covenant C2 GruntStager** — .NET HTTP stager (PE build: `GruntHTTP.exe`; PS build: `GruntHTTP.ps1`)
- **PowerShell Fileless Loader** — Base64+Deflate wrapper delivering Covenant Build 2

Rules are grouped by family within each section. Rules covering shared infrastructure or behavior common to both Covenant delivery methods are placed under a Campaign-Level subsection.

---

## YARA Rules

```
/*
    Name: OpenDirectory Multi-Family MaaS — 193.56.255.154
    Author: The Hunters Ledger
    Date: 2026-04-03
    Identifier: XiebroC2 v3.1 / Covenant GruntStager / PowerShell Fileless Loader
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/
```

---

### XiebroC2 v3.1

**Detection Priority:** HIGH  
**Rationale:** Three of the four anchor strings (AES key, typo symbol, go-clr import path) are unique to XiebroC2 3.1 source and cannot appear in legitimate Go binaries. The AES key alone is a definitive indicator — no legitimate software embeds QWERt_CSDMAHUATW as a 16-byte AES key.  
**ATT&CK Coverage:** T1573.001 (AES-ECB key), T1620 (go-clr CLR hosting), T1055.012 / T1055 (RunPE + CreateRemoteThread error strings)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — AES key literal and pclntab typo are not present in any legitimate Go binary; go-clr import path is an offensive-tool-only library  
**Deployment:** Endpoint AV/EDR disk scan, memory scanner targeting live Go processes  

```yara
rule RAT_XiebroC2_v31_Go_TCP_Implant
{
    meta:
        description = "Detects XiebroC2 v3.1 Go TCP implant based on hardcoded AES-128-ECB key, source-code typo in pclntab symbol table (WindosVersion), vendored offensive go-clr CLR hosting library import, and unique RunPE PE parser error strings. All four indicators are static artifacts embedded in any binary compiled from XiebroC2 3.1 source."
        author = "The Hunters Ledger"
        date = "2026-04-03"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
        hash_sha256 = "not_captured_in_triage"
        family = "XiebroC2"

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
        ($s1 or $b1) and
        2 of ($s2, $s3, $s4, $s5, $s6, $s7)
}
```

---

**Detection Priority:** HIGH  
**Rationale:** Space-padded C2 configuration strings are a unique behavioral artifact of XiebroC2's binary-patchable config embedding technique. The 40-byte padded IP string is not a pattern found in legitimate network software.  
**ATT&CK Coverage:** T1571 (Non-Standard Port — port 4444 TCP C2)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — 40-byte space-padded IP combined with padded port "4444" is a structural artifact unique to XiebroC2 config format; not present in legitimate binaries  
**Deployment:** Endpoint disk scan; also effective as a memory scan on running Go processes  

```yara
rule RAT_XiebroC2_v31_PaddedConfig_Build
{
    meta:
        description = "Detects XiebroC2 v3.1 build targeting 193.56.255.154 based on the space-padded C2 IP and port configuration strings embedded verbatim in the binary. XiebroC2 stores configuration as fixed-width space-padded literals to allow binary patching without recompilation, producing a distinctive 40-byte padded IP string not found in legitimate software."
        author = "The Hunters Ledger"
        date = "2026-04-03"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
        hash_sha256 = "not_captured_in_triage"
        family = "XiebroC2"

    strings:
        $s1 = "193.56.255.154                          " ascii
        $s2 = "4444                " ascii
        $s3 = "vps                       " ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 25MB and
        $s1 and $s2
}
```

---

### Covenant C2 GruntStager

**Detection Priority:** HIGH  
**Rationale:** The session token and build ID are listener-level constants shared across both GruntStager builds and appear in every HTTP POST from every infected host. Both the PE and the PowerShell-embedded payload will match this rule.  
**ATT&CK Coverage:** T1071.001 (HTTP C2), T1036 (Chrome 41 UA masquerade), T1573.002 (RSA key exchange — pre-shared key embedded in binary)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — session token and build ID are GUID-format values specific to this Covenant listener; no legitimate software uses these exact strings  
**Deployment:** Endpoint AV/EDR disk scan targeting .NET PE files; memory scanner targeting .NET processes performing Assembly.Load()  

```yara
rule RAT_Covenant_GruntStager_OpenDirectory
{
    meta:
        description = "Detects both Covenant C2 GruntStager builds (GruntHTTP.exe Build 1 and the PE extracted from GruntHTTP.ps1 Build 2) based on shared listener-level session token, build ID, and Covenant-specific namespace strings. Both builds share a single Covenant listener at 193.56.255.154:443 and produce identical values for these fields. Matching either sample confirms active Covenant stager deployment."
        author = "The Hunters Ledger"
        date = "2026-04-03"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
        hash_sha256 = "3aa45ceff7070ae6d183c5aa5f0d771a79c7cf37fe21a3906df976bee497bf20"
        family = "Covenant"

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

---

### PowerShell Fileless Loader

**Detection Priority:** HIGH  
**Rationale:** The session token embedded in the PowerShell script is a campaign-unique constant. Combined with DeflateStream + Reflection.Assembly patterns, this rule is highly specific to the Covenant PS delivery mechanism.  
**ATT&CK Coverage:** T1059.001 (PowerShell), T1027 (Obfuscated Base64+Deflate payload), T1140 (Deobfuscate via DeflateStream), T1620 (Reflective .NET loading)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — the session token is a unique GUID-format value; its combination with DeflateStream decode and Assembly::Load is specific to this loader pattern; legitimate PS scripts do not embed Covenant session tokens  
**Deployment:** Endpoint AV/EDR scan targeting .ps1 files; AMSI telemetry; PowerShell ScriptBlock logging (Event ID 4104)  

```yara
rule MALW_Covenant_PSFilelessLoader_GruntHTTP
{
    meta:
        description = "Detects the GruntHTTP.ps1 PowerShell fileless loader that delivers Covenant GruntStager Build 2 via Base64+Deflate decoding and Reflection.Assembly::Load(). The rule anchors on the hardcoded Covenant session token embedded in the script alongside the decompression and reflective loading pattern — a combination unique to this malicious loader and not found in legitimate PowerShell scripts."
        author = "The Hunters Ledger"
        date = "2026-04-03"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/"
        hash_sha256 = "cff2d990f0988e9c90f77d0a62c72ca8e9bf567f0c143fdc3a914dce65edec98"
        family = "Covenant"

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

---

## Sigma Rules

---

### XiebroC2 v3.1

---

#### Rule 1 — XiebroC2 CLR Load in Non-.NET Go Process

**Detection Priority:** HIGH  
**Rationale:** No legitimate Go binary loads mscoree.dll or clr.dll at runtime. This pattern is exclusively produced by XiebroC2's inline-assembly command, which uses go-clr to host the Windows CLR in-process. Fires on disk and memory artifacts.  
**ATT&CK Coverage:** T1620 (Reflective Code Loading — in-process CLR hosting via go-clr)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — legitimate Go processes never load the CLR; filter excludes all standard .NET host processes; if main.exe is renamed, the ParentImage filter should be broadened to cover Go binaries generically  
**Deployment:** Sysmon Event ID 7 (ImageLoad); requires Sysmon with ImageLoad enabled  

```yaml
title: XiebroC2 Go Implant Loading Windows CLR at Runtime via go-clr
id: a3f7c821-5e4b-4d09-bc21-7f3a9e5c8d04
status: experimental
description: Detects a Go binary (main.exe) loading mscoree.dll or clr.dll at runtime, which is the behavioral signature of XiebroC2 v3.1 executing its inline-assembly command via the vendored go-clr library. Legitimate Go binaries do not host the Windows CLR in-process. This event fires regardless of whether the .NET assembly payload was written to disk, making it effective against fully fileless .NET delivery chains.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/Ne0nd0g/go-clr
author: The Hunters Ledger
date: 2026/04/03
tags:
    - attack.defense-evasion
    - attack.execution
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

---

#### Rule 2 — XiebroC2 Process Hollowing via Suspended Process Creation

**Detection Priority:** HIGH  
**Rationale:** XiebroC2's RunPE implementation creates a process in CREATE_SUSPENDED state (0x4), immediately queries it with NtQueryInformationProcess, and patches the entry point. The sequence of suspended creation followed by memory API calls to the child is the behavioral signature of process hollowing.  
**ATT&CK Coverage:** T1055.012 (Process Hollowing)  
**Confidence:** HIGH  
**False Positive Risk:** MEDIUM — CREATE_SUSPENDED alone is used by some legitimate software (debuggers, process monitors, sandbox tools); this rule requires the XiebroC2-specific parent (main.exe) to reduce FPs; tune ParentImage if the implant is renamed  
**Deployment:** Sysmon Event ID 1 (ProcessCreate); EDR process tree telemetry  

```yaml
title: XiebroC2 Process Hollowing via Suspended Child Process Creation
id: b8d2e94f-7c13-4a8b-91f6-2e5d7b3c6a10
status: experimental
description: Detects XiebroC2 v3.1 executing its RunPE process hollowing technique by identifying suspended child process creation from a parent process named main.exe. XiebroC2 creates target processes with CREATE_SUSPENDED (creationflags 0x4) before performing entry point patching injection. The CreationFlags field value of 4 in Sysmon process creation events is the key discriminator alongside the suspicious parent image name.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
author: The Hunters Ledger
date: 2026/04/03
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\main.exe'
    selection_suspended:
        CreationFlags: '0x4'
    condition: selection_parent and selection_suspended
falsepositives:
    - Legitimate process management software named main.exe that creates suspended child processes (highly unlikely)
    - Security testing tools or debuggers launched from a binary coincidentally named main.exe
level: high
```

---

#### Rule 3 — XiebroC2 Shell Command Execution with Hidden Window

**Detection Priority:** MEDIUM  
**Rationale:** XiebroC2 spawns all shell commands (shell, OSshell, OSpowershell) with CREATE_NO_WINDOW. The combination of main.exe parent with a hidden-window cmd.exe or powershell.exe child is a strong behavioral indicator of C2 command execution.  
**ATT&CK Coverage:** T1059.003 (Windows Command Shell), T1059.001 (PowerShell)  
**Confidence:** HIGH  
**False Positive Risk:** MEDIUM — the parent name main.exe is the primary discriminator; if the implant is renamed by the operator this rule will not fire; hidden-window shell spawning alone is used by some legitimate software installers  
**Deployment:** Sysmon Event ID 1 (ProcessCreate); EDR process tree telemetry  

```yaml
title: XiebroC2 Hidden Window Shell Execution from Go Implant
id: c5e1f730-8b24-4c9d-a2e7-3f6b8d1e5c92
status: experimental
description: Detects XiebroC2 v3.1 executing its shell, OSshell, or OSpowershell commands by identifying hidden-window cmd.exe or powershell.exe child processes spawned from a parent named main.exe. All XiebroC2 command handler shells set CREATE_NO_WINDOW to suppress visible console output on the victim endpoint. This rule targets the parent-child relationship as the primary discriminator.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
author: The Hunters Ledger
date: 2026/04/03
tags:
    - attack.execution
    - attack.defense-evasion
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
    - Development or build environments where a Go binary named main.exe is used to orchestrate build steps via cmd.exe
level: high
```

---

### Covenant C2 GruntStager

---

#### Rule 4 — Covenant GruntStager HTTP C2 Beacon Detection

**Detection Priority:** HIGH  
**Rationale:** The session token 75db-99b1-25fe4e9afbe58696-320bea73 is a listener-level constant shared by both GruntStager builds. Every HTTP POST from every host infected by either stager will contain this token. It is a single- indicator, high-confidence detection that catches both delivery methods simultaneously.  
**ATT&CK Coverage:** T1071.001 (Application Layer Protocol: Web Protocols), T1036 (Masquerading — Microsoft Docs URL and Chrome 41 UA)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — the session token is a GUID-format value unique to this Covenant listener; it will not appear in legitimate HTTP traffic; the Chrome 41 / Windows 7 UA pattern reinforces the signal  
**Deployment:** HTTP proxy logs (Squid, Bluecoat, Zscaler, etc.); web gateway telemetry; requires proxy logging of request body or URI query parameters  

```yaml
title: Covenant C2 GruntStager HTTP Beacon — Campaign Session Token Detected
id: d9a4b257-3f81-4e7c-b5d8-6c2e9f0a4b73
status: experimental
description: Detects HTTP POST requests containing the Covenant C2 listener session token '75db-99b1-25fe4e9afbe58696-320bea73', which is hardcoded in both GruntHTTP.exe (Build 1) and the PE embedded in GruntHTTP.ps1 (Build 2). This token is a listener-level constant that appears in every registration and command-exchange POST from any host executing either stager build. The rule fires on both the PE-based and PowerShell-based delivery variants simultaneously, making it the highest-value single network detection for this campaign.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/cobbr/Covenant
author: The Hunters Ledger
date: 2026/04/03
tags:
    - attack.command-and-control
logsource:
    category: proxy
    product: windows
detection:
    selection_session_token:
        cs-uri-query|contains: 'session=75db-99b1-25fe4e9afbe58696-320bea73'
    selection_ua:
        cs(User-Agent)|contains: 'Chrome/41.0.2228.0'
    condition: 1 of selection_*
falsepositives:
    - No legitimate proxy traffic is expected to contain this specific session token value; the Chrome 41 on Windows 7 User-Agent may appear in legacy browser environments but is an extremely outdated combination that warrants investigation regardless
level: high
```

---

### PowerShell Fileless Loader

---

#### Rule 5 — PowerShell Fileless Loader Decoding and Reflective Assembly Load

**Detection Priority:** HIGH  
**Rationale:** The combination of Base64 decode, DeflateStream decompression, and Reflection.Assembly::Load() in a single ScriptBlock is the exact execution chain of GruntHTTP.ps1. While each element alone has moderate FP risk, all three co-occurring in the same ScriptBlock with a MemoryStream is highly specific to malicious fileless loaders.  
**ATT&CK Coverage:** T1059.001 (PowerShell), T1140 (Deobfuscate/Decode), T1027 (Obfuscated Files), T1620 (Reflective Code Loading)  
**Confidence:** HIGH  
**False Positive Risk:** MEDIUM — legitimate PowerShell automation rarely combines DeflateStream decoding with Reflection.Assembly::Load() in the same block; software deployment scripts occasionally use this pattern; tuning by excluding known-good script hashes is recommended in environments with legitimate use  
**Deployment:** PowerShell ScriptBlock Logging (Event ID 4104); requires ScriptBlock logging enabled in Group Policy  

```yaml
title: PowerShell Fileless Loader — Deflate Decode with Reflective Assembly Load
id: e2c8d419-6a37-4f5b-8e90-4d1b7c5e2f85
status: experimental
description: Detects PowerShell scripts executing the GruntHTTP.ps1 fileless loader pattern — Base64 decoding of a compressed payload via System.IO.DeflateStream followed by Reflection.Assembly::Load() to execute the decompressed PE in memory. This three-stage chain (FromBase64String, DeflateStream, Reflection.Assembly::Load) in a single ScriptBlock is the specific technique used by the Covenant PS delivery wrapper analyzed in this campaign. Firing on Event ID 4104 ScriptBlock logs means this detection is effective even when the .ps1 file is never written to disk.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/
    - https://github.com/cobbr/Covenant
author: The Hunters Ledger
date: 2026/04/03
tags:
    - attack.execution
    - attack.defense-evasion
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
level: high
```

---

## Suricata Signatures

---

### Campaign-Level

---

**Detection Priority:** HIGH  
**Rationale:** The Covenant session token appears in the POST body of every C2 registration and command exchange from both GruntStager builds. This is the highest-value single network indicator in the campaign — one rule catches both delivery variants simultaneously.  
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1036 (Masquerading)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — session token is a GUID-format value unique to this Covenant listener; will not appear in legitimate traffic  
**Deployment:** Network IDS/IPS inline or tap; HTTP inspection on port 443 (cleartext); requires HTTP body inspection enabled on the sensor  

```
alert http $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"THL - Covenant GruntStager C2 Beacon - Campaign Session Token in HTTP POST";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/en-us/"; startswith;
    http.request_body; content:"session=75db-99b1-25fe4e9afbe58696-320bea73";
    classtype:trojan-activity;
    reference:url,pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/;
    sid:9000101; rev:1;
    metadata:affected_product Windows, attack_target Client_Endpoint,
              created_at 2026_04_03, deployment Perimeter,
              malware_family Covenant, signature_severity Major,
              tag C2;
)
```

---

**Detection Priority:** HIGH  
**Rationale:** Cleartext HTTP on port 443 is anomalous in any environment that enforces TLS. The Covenant stager uses HTTP (not HTTPS) on port 443 to bypass port-based access controls while avoiding TLS certificate overhead. The outdated Chrome 41 / Windows 7 User-Agent combination is a strong masquerade signal that does not match any modern browser.  
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1036 (Masquerading), T1571 (Non-Standard Port)  
**Confidence:** HIGH  
**False Positive Risk:** LOW-MEDIUM — the Chrome 41 UA alone may fire on legacy enterprise endpoints with very old browsers; combine with /en-us/ URI pattern to reduce FPs; the UA + path combination is specific to this campaign  
**Deployment:** Network IDS/IPS; HTTP inspection on port 443; effective only if sensor can distinguish plaintext HTTP from TLS on the same port  

```
alert http $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"THL - Covenant GruntStager Masquerade - Chrome 41 Windows 7 UA on Port 443";
    flow:established,to_server;
    http.user_agent; content:"Chrome/41.0.2228.0"; nocase;
    http.uri; content:"/en-us/"; startswith;
    classtype:trojan-activity;
    reference:url,pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/;
    sid:9000102; rev:1;
    metadata:affected_product Windows, attack_target Client_Endpoint,
              created_at 2026_04_03, deployment Perimeter,
              malware_family Covenant, signature_severity Major,
              tag C2;
)
```

---

### XiebroC2 v3.1

---

**Detection Priority:** HIGH  
**Rationale:** XiebroC2 uses a binary TCP protocol with a 4-byte little-endian length prefix followed by AES-128-ECB ciphertext on port 4444. The port is non-standard and directly hardcoded in main.exe. Any TCP session to this IP on port 4444 from an internal host is high-confidence C2 activity.  
**ATT&CK Coverage:** T1573.001 (Encrypted Channel — AES-ECB), T1571 (Non-Standard Port)  
**Confidence:** HIGH  
**False Positive Risk:** LOW — port 4444 TCP to this specific IP is unambiguously C2; port 4444 alone (without IP filter) has moderate FP risk from legitimate tools (Metasploit default, some dev tools); use IP-specific variant first, then consider a broader port-only rule  
**Deployment:** Network IDS/IPS; netflow analysis; requires visibility into outbound TCP on non-standard ports  

```
alert tcp $HOME_NET any -> 193.56.255.154 4444 (
    msg:"THL - XiebroC2 v3.1 TCP C2 Beacon - Known C2 IP Port 4444";
    flow:established,to_server;
    threshold:type both, track by_src, count 1, seconds 300;
    classtype:trojan-activity;
    reference:url,pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-193-56-255-154-20260403-detections/;
    sid:9000103; rev:1;
    metadata:affected_product Windows, attack_target Client_Endpoint,
              created_at 2026_04_03, deployment Perimeter,
              malware_family XiebroC2, signature_severity Critical,
              tag C2;
)
```

---

## Coverage Gaps

The following MITRE ATT&CK techniques were observed in the malware analysis but could not be
covered with high-confidence, low-FP detection rules at this time. Evidence gaps or technique
generality prevent rule creation.

| Technique | Family | Gap Reason | Evidence Needed for Coverage |
|---|---|---|---|
| T1055 — Process Injection (CreateRemoteThread shellcode injection) | XiebroC2 | VirtualAllocEx + CreateRemoteThread sequence is generic; without an anchor on main.exe as the source process via EDR process-access telemetry (Sysmon EID 10), a standalone Suricata or Sigma rule would have unacceptable FP rates. Sysmon EID 10 is available but requires the `SourceImage` field to match `main.exe`, which depends on implant not being renamed. | EDR process-access telemetry (Sysmon EID 10) with `SourceImage: \main.exe` and `GrantedAccess` mask `0x43a` |
| T1572 — Protocol Tunneling (SOCKS5 ReverseProxy) | XiebroC2 | The SOCKS5 reverse proxy traffic is encrypted within the XiebroC2 AES-ECB tunnel; it is not separately distinguishable at the network layer without decrypting the outer XiebroC2 session first. | Decrypted PCAP of port 4444 traffic using key `QWERt_CSDMAHUATW` to identify SOCKS5 framing within the XiebroC2 payload |
| T1113 — Screen Capture | XiebroC2 | Screen capture via GDI APIs is not detectable at the network layer or via process creation events; it would require API-call-level hooking (ETW user-mode) or memory forensics to observe the PNG encoding and exfiltration. | ETW user-mode provider tracing GDI API calls in main.exe process; memory forensics showing GDI bitmap allocations |
| T1573.002 — Asymmetric Cryptography (RSA key exchange) | Covenant | RSA key exchange occurs inside the HTTP POST body which is already captured by the session token Suricata rule; a dedicated RSA pattern rule cannot be written without decrypting TLS (not applicable — traffic is cleartext HTTP, but the RSA key material is opaque base64 data). | Full HTTP body inspection with base64 decode capability to inspect the key exchange payload structure |
| T1041 — Exfiltration Over C2 Channel | XiebroC2 | File exfiltration uses the same AES-ECB encrypted TCP channel as all other C2 traffic; no distinguishing framing or port is used. Exfiltration is only detectable by decrypting the channel or by unusually large outbound data volumes to port 4444. | Netflow anomaly detection on port 4444 sessions with sustained large outbound byte counts (>50KB per session chunk) |
| T1082 / T1033 — System Discovery (victim registration beacon) | XiebroC2 | The 15-field MessagePack registration packet is sent over the encrypted AES-ECB channel; no plaintext indicators are observable at the network layer without decryption. | Decrypted PCAP analysis to fingerprint MessagePack field structure of the ClientInfo registration packet |

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
