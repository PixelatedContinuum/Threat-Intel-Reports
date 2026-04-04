---
title: "Detection Rules — Shadow RAT & XWorm Open Directory Campaign"
date: '2026-04-04'
layout: post
permalink: /hunting-detections/shadow-xworm-opendirectory-detections/
hide: true
---

**Campaign:** OpenDirectory-DualRAT-MaaS-151.245.112.70
**Date:** 2026-04-04
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/shadow-xworm-opendirectory/

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 7 | T1562.001, T1562.006, T1027, T1573.001, T1115, T1542.003 | LOW |
| Sigma | 10 | T1547.001, T1547.009, T1053.005, T1562.001, T1562.004, T1562.006, T1553.005, T1497.001 | LOW–MEDIUM |
| Suricata | 6 | T1071.001, T1573.001, T1497.001 | LOW |

---

## YARA Rules

### Shadow RAT v2.6.4.0

---

**Detection Priority:** HIGH
**Rationale:** Three distinctive namespace strings drawn directly from the Shadow RAT codebase; no legitimate .NET software uses the `Shadow.Common.*` namespace hierarchy. The Costura.Fody marker `costura.shadow.common.dll.compressed` is uniquely associated with this family.
**ATT&CK Coverage:** T1027.002 (.NET Reactor packing), T1573.001 (AES-256 encrypted C2)
**Confidence:** HIGH
**False Positive Risk:** LOW — namespace strings are distinctive and not shared with any known legitimate software
**Deployment:** Endpoint AV/EDR file scan, memory scanner, email gateway attachment scan

```yara
/*
    Name: Shadow RAT v2.6.4.0 — Client Detection Rules
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: Shadow RAT v2.6.4.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_ShadowRAT_v2640_Client
{
    meta:
        description = "Detects Shadow RAT v2.6.4.0 client based on characteristic namespace strings, version constant, and Costura.Fody embedded assembly markers. Shadow RAT is a heavily modified Quasar RAT fork with HVNC, WinRE persistence, crypto clipper, and Kematian stealer integration."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "3a4b0f50ea3eac55e22cbf24d873f9a1632d8f71e1fba91178c539030626ab32"
        family = "ShadowRAT"

    strings:
        $s1 = "Shadow.Common.Messages" ascii wide
        $s2 = "Shadow.Common.Cryptography" ascii wide
        $s3 = "Shadow.Client.Steam" ascii wide
        $s4 = "2.6.4.0" ascii wide
        $s5 = "4c7e33e6-3f73-4b4c-a411-89fe63cdfa1e" ascii wide
        $s6 = "costura.shadow.common.dll.compressed" ascii wide nocase
        $s7 = "Shadow Client" ascii wide
        $s8 = "Shadow Client Startup" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            3 of ($s1, $s2, $s3, $s6) or
            ($s4 and $s5) or
            ($s7 and $s8 and 1 of ($s1, $s2, $s3))
        )
}
```

---

**Detection Priority:** HIGH
**Rationale:** The `Shadow.Common.Cryptography.Aes256` string combined with any two HVNC/WinRE/DNS namespace strings creates a combination unique to the Shadow RAT shared library component. Applicable to both the embedded DLL and any extracted copy on disk.
**ATT&CK Coverage:** T1573.001 (AES-256 crypto), T1542.003 (WinRE namespace presence)
**Confidence:** HIGH
**False Positive Risk:** LOW — `Shadow.Common.Cryptography.Aes256` does not appear in any known legitimate .NET library
**Deployment:** Endpoint file scan, memory scanner (for extracted Costura.Fody assemblies)

```yara
/*
    Name: Shadow RAT v2.6.4.0 — Common DLL
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: Shadow RAT v2.6.4.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_ShadowRAT_CommonDLL
{
    meta:
        description = "Detects Shadow.Common.dll, the shared library component of Shadow RAT containing core message types, AES-256 crypto, and protobuf-net serialization. This DLL is embedded via Costura.Fody and extracted at runtime. Matches on disk and in memory."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
        family = "ShadowRAT"

    strings:
        $s1 = "Shadow.Common.Messages.Monitoring.HVNC" ascii
        $s2 = "Shadow.Common.Messages.FunStuff.GDI" ascii
        $s3 = "Shadow.Common.Messages.ClientManagement.WinRE" ascii
        $s4 = "Shadow.Common.DNS.HostsManager" ascii
        $s5 = "Shadow.Common.Cryptography.Aes256" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $s5 and 2 of ($s1, $s2, $s3, $s4)
}
```

---

**Detection Priority:** HIGH
**Rationale:** The 15-byte AMSI patch shellcode (`B8 57 00 07 80 48 8B 04 24 48 83 C4 08 FF E4`) is a precise byte sequence with essentially zero false positive risk. The asterisk-obfuscation pattern (`.Replace("*", "")` combined with `m*s*i`) is distinctive to this specific obfuscation style.
**ATT&CK Coverage:** T1562.001 (AMSI bypass), T1562.006 (ETW bypass), T1027 (asterisk-padding obfuscation)
**Confidence:** HIGH
**False Positive Risk:** LOW — the AMSI shellcode byte sequence is specific; the obfuscation combination is highly distinctive
**Deployment:** Endpoint AV/EDR file scan, memory scanner

```yara
/*
    Name: Shadow RAT v2.6.4.0 — AMSI + ETW Bypass
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: Shadow RAT v2.6.4.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_ShadowRAT_AMSI_ETW_Bypass
{
    meta:
        description = "Detects Shadow RAT v2.6.4.0 AMSI and ETW bypass chain. AMSI bypass patches AmsiScanBuffer with a 15-byte shellcode returning E_INVALIDARG (0x80070057). ETW bypass patches EtwEventWrite with a single RET instruction. Both API names are obfuscated using asterisk-padding with runtime Replace() deobfuscation to evade static analysis."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "3a4b0f50ea3eac55e22cbf24d873f9a1632d8f71e1fba91178c539030626ab32"
        family = "ShadowRAT"

    strings:
        // AMSI bypass shellcode: mov eax,0x80070057; mov rax,[rsp]; add rsp,8; jmp rsp
        $b1 = { B8 57 00 07 80 48 8B 04 24 48 83 C4 08 FF E4 }
        // Asterisk-padding deobfuscation pattern
        $s1 = ".Replace(\"*\", \"\")" ascii
        // Obfuscated amsi.dll string fragment
        $s2 = "m*s*i" ascii
        // Obfuscated AmsiScanBuffer string fragment
        $s3 = "Buf*f*er" ascii
        // Obfuscated EtwEventWrite string fragment
        $s4 = "EtwEv" ascii
        // Obfuscated ntdll.dll string fragment
        $s5 = "ntdll" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $b1 or
            ($s1 and $s2 and $s3) or
            ($s1 and $s4 and $s5)
        )
}
```

---

**Detection Priority:** HIGH
**Rationale:** `SetClipboardMonitoringEnabled` combined with `SendClipboardData` and two of three cryptocurrency address field names forms a combination with no known legitimate use. This rule targets the Shadow.Common.dll component directly.
**ATT&CK Coverage:** T1115 (clipboard data), T1115 (crypto clipper theft capability)
**Confidence:** HIGH
**False Positive Risk:** LOW — `SetClipboardMonitoringEnabled` is not a Windows API; it is a custom Shadow RAT message handler method name
**Deployment:** Endpoint file scan, memory scanner

```yara
/*
    Name: Shadow RAT v2.6.4.0 — Crypto Clipper Module
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: Shadow RAT v2.6.4.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_ShadowRAT_Crypto_Clipper
{
    meta:
        description = "Detects Shadow RAT crypto clipper module via clipboard monitoring method names paired with multi-currency address fields (BTC/LTC/ETH) in Shadow.Common.dll. Enables real-time substitution of victim cryptocurrency addresses during financial transactions."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
        family = "ShadowRAT"

    strings:
        $s1 = "SetClipboardMonitoringEnabled" ascii wide
        $s2 = "SendClipboardData" ascii wide
        $s3 = "BitcoinAddress" ascii wide
        $s4 = "LitecoinAddress" ascii wide
        $s5 = "EthereumAddress" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $s1 and $s2 and
        2 of ($s3, $s4, $s5)
}
```

---

**Detection Priority:** HIGH
**Rationale:** `DoAddWinREPersistence` and the `Shadow.Common.Messages.ClientManagement.WinRE` namespace string are unique to this malware family. WinRE persistence survives OS reinstallation and is an uncommon technique with limited EDR coverage — detection at the file level is the primary viable layer.
**ATT&CK Coverage:** T1542.003 (Pre-OS Boot: WinRE persistence)
**Confidence:** HIGH
**False Positive Risk:** LOW — method names and namespace are specific to Shadow RAT; no known legitimate software uses these identifiers
**Deployment:** Endpoint file scan, memory scanner

```yara
/*
    Name: Shadow RAT v2.6.4.0 — WinRE Persistence Module
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: Shadow RAT v2.6.4.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_ShadowRAT_WinRE_Persistence
{
    meta:
        description = "Detects Shadow RAT WinRE persistence module via command handler method names and namespace string in Shadow.Common.dll. WinRE persistence survives OS reinstallation and is an uncommon technique with limited EDR behavioral coverage — file-level detection is the primary viable layer."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
        family = "ShadowRAT"

    strings:
        $s1 = "DoAddWinREPersistence" ascii wide
        $s2 = "DoRemoveWinREPersistence" ascii wide
        $s3 = "Shadow.Common.Messages.ClientManagement.WinRE" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($s1 or $s2) and $s3
}
```

---

### XWorm 3.0-5.0

---

**Detection Priority:** HIGH
**Rationale:** The campaign-specific config keys (`PdqPY2fw6ffCVLQ8`, `ZdoNsjYfT6begqDl`) or the group tag `<Xwormmm>` combined with the runtime AES key `Nothing2hide` are directly campaign-specific. The ip-api.com + schtasks + USB.exe combination covers generic XWorm 3.0-5.0 variants beyond this specific campaign.
**ATT&CK Coverage:** T1027 (config encryption), T1497.001 (hosting detection), T1053.005 (schtask persistence), T1091 (USB spread)
**Confidence:** HIGH
**False Positive Risk:** LOW — config key strings and group tag are unique to XWorm builder outputs
**Deployment:** Endpoint AV/EDR file scan, email gateway attachment scan

```yara
/*
    Name: XWorm 3.0-5.0 — Config Detection Rules
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: XWorm 3.0-5.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_XWorm_30_50_Config
{
    meta:
        description = "Detects XWorm 3.0-5.0 builder output based on campaign-specific config AES keys, the group tag <Xwormmm>, ip-api.com hosting detection string, and triple persistence indicators. The config key strings double as process mutexes in XWorm's implementation."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
        family = "XWorm"

    strings:
        // Campaign-specific config AES keys (also used as process mutexes)
        $s1 = "PdqPY2fw6ffCVLQ8" ascii wide
        $s2 = "ZdoNsjYfT6begqDl" ascii wide
        // Runtime C2 encryption key decrypted from config
        $s3 = "Nothing2hide" ascii wide
        // Builder group tag
        $s4 = "<Xwormmm>" ascii wide
        // Anti-analysis hosting check URL
        $s5 = "ip-api.com/line/?fields=hosting" ascii wide
        // Scheduled task persistence argument
        $s6 = "/create /f /sc minute /mo 1" ascii wide
        // USB spread filename
        $s7 = "USB.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            (1 of ($s1, $s2) and ($s3 or $s4)) or
            ($s4 and $s5) or
            ($s5 and $s6 and $s7)
        )
}
```

---

**Detection Priority:** MEDIUM
**Rationale:** The Rijndael-256-ECB + MD5CryptoServiceProvider + FromBase64String combination is characteristic of XWorm's non-standard config encryption. Requiring two of three anti-analysis strings reduces false positive risk against legitimate crypto libraries.
**ATT&CK Coverage:** T1027 (config encryption), T1497.001 (anti-analysis checks)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — individual strings appear in legitimate .NET crypto code; the combination is more distinctive but not unique
**Deployment:** Endpoint AV/EDR file scan; treat as supporting indicator, not standalone confirmation

```yara
/*
    Name: XWorm 3.0-5.0 — Rijndael-256-ECB Crypto Pattern
    Author: The Hunters Ledger
    Date: 2026-04-04
    Identifier: XWorm 3.0-5.0 OpenDirectory 151.245.112.70
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_XWorm_Rijndael256ECB_Crypto
{
    meta:
        description = "Detects XWorm 3.0-5.0 variants using the characteristic Rijndael-256-ECB config encryption with non-standard overlapping MD5 key derivation, combined with anti-analysis indicators. The MD5 hash is copied to a 32-byte key array at offsets 0 and 15 with a single overlap byte — a distinctive non-standard construction consistent across XWorm 3.0-5.0 variants."
        author = "The Hunters Ledger"
        date = "2026-04-04"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/shadow-xworm-opendirectory-detections/"
        hash_sha256 = "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
        family = "XWorm"

    strings:
        $s1 = "RijndaelManaged" ascii wide
        $s2 = "ECB" ascii wide
        $s3 = "MD5CryptoServiceProvider" ascii wide
        $s4 = "FromBase64String" ascii wide
        // Anti-analysis check strings
        $s5 = "Win32_ComputerSystem" ascii wide
        $s6 = "SbieDll" ascii wide
        $s7 = "IsAttached" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $s1 and $s2 and $s3 and $s4 and
        2 of ($s5, $s6, $s7)
}
```

---

## Sigma Rules

### Shadow RAT v2.6.4.0

---

**Detection Priority:** HIGH
**Rationale:** The registry value name `Shadow Client Startup` is unique to Shadow RAT and not used by any known legitimate software. Either the key name or the data path pointing to `\SubDir\` is sufficient for high-confidence detection.
**ATT&CK Coverage:** T1547.001 (Registry Run Keys persistence)
**Confidence:** HIGH
**False Positive Risk:** LOW — value name is distinctive and not shared with legitimate software
**Deployment:** SIEM (Sysmon Event ID 13), EDR registry monitoring

```yaml
title: Shadow RAT Registry Run Key Persistence
id: ff8d332d-4f1f-44d7-89ac-5d4373f4a341
status: test
description: |
    Detects Shadow RAT v2.6.4.0 creating a registry Run key for persistence with the
    characteristic value name "Shadow Client Startup". This value points to the malware
    install path at %APPDATA%\SubDir\Client.exe or %APPDATA%\SubDir\$77Client.exe depending
    on the build variant (staging vs production). Presence of this key indicates an active
    Shadow RAT infection with established persistence.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1547/001/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\CurrentVersion\Run\Shadow Client Startup'
    selection_data:
        Details|contains:
            - '\SubDir\Client.exe'
            - '\SubDir\$77Client.exe'
    condition: selection_key or selection_data
falsepositives:
    - No known legitimate software uses the registry value name "Shadow Client Startup"
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** Shadow RAT loads amsi.dll to resolve and patch AmsiScanBuffer. Legitimate AMSI consumers are filtered; a non-system process loading amsi.dll from a user-writable path is a strong indicator of an AMSI patching attempt.
**ATT&CK Coverage:** T1562.001 (Disable or Modify Tools — AMSI bypass)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — custom development tools or non-standard .NET installations may load amsi.dll from user paths
**Deployment:** SIEM (Sysmon Event ID 7 / image_load), EDR

```yaml
title: AMSI Bypass via Suspicious amsi.dll Load from Non-Standard Path
id: b02fa532-5fdd-4307-9a33-0d5935ffc4d0
status: test
description: |
    Detects potential AMSI bypass attempts where a process loads amsi.dll from outside standard
    system directories. Shadow RAT v2.6.4.0 loads amsi.dll to resolve and patch AmsiScanBuffer
    with 15-byte shellcode returning E_INVALIDARG (0x80070057), effectively blinding in-memory
    .NET scanning. Legitimate AMSI consumers (PowerShell, .NET host processes) load amsi.dll
    from System32 or are explicitly filtered; a non-system, non-IDE process loading amsi.dll
    from a user-writable path is a strong indicator of an AMSI patching attempt.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1562/001/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
    filter_legitimate:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\dotnet.exe'
            - '\csc.exe'
            - '\msbuild.exe'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not (filter_legitimate or filter_system)
falsepositives:
    - Legitimate .NET applications or IDE tooling loading amsi.dll from non-standard installation paths
    - Custom development environments or build pipelines running outside Program Files
    - Security research tools that explicitly load amsi.dll for testing purposes
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** Shadow RAT patches ntdll.dll!EtwEventWrite with a single RET instruction, blinding all ETW-based telemetry from the process. Full process access rights (`0x1FFFFF`) combined with ntdll.dll in the call trace is a strong behavioral indicator of ETW patching.
**ATT&CK Coverage:** T1562.006 (Indicator Blocking — ETW bypass)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — debugging tools and security products legitimately acquire full process access; filter tuning may be required per environment
**Deployment:** SIEM (Sysmon Event ID 10 / process_access), EDR

```yaml
title: ETW Bypass via Process Access to ntdll.dll Memory Region
id: 7e1f94cd-ed21-4cc9-b3d4-4b14308210c0
status: test
description: |
    Detects processes acquiring full memory access rights to another process with call stack
    activity in ntdll.dll, consistent with ETW patching. Shadow RAT v2.6.4.0 patches
    ntdll.dll!EtwEventWrite with a single RET instruction (0xC3) via WriteProcessMemory,
    causing all ETW events from the process to silently return without logging. This blinds
    EDR tools and security monitoring products that rely on ETW for .NET CLR event visibility.
    The GrantedAccess value 0x1FFFFF indicates full process access including write permissions.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1562/006/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x1F0FFF'
        CallTrace|contains: 'ntdll.dll'
    filter_self:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\lsass.exe'
            - '\csrss.exe'
            - '\services.exe'
            - '\winlogon.exe'
            - '\wininit.exe'
    condition: selection and not filter_self
falsepositives:
    - Debugging tools and performance profilers legitimately requesting full process access
    - Application compatibility shims that modify ntdll behavior at runtime
    - Security products performing integrity verification on ntdll.dll
    - Process monitoring tools with deep inspection capabilities
level: high
```

---

**Detection Priority:** HIGH
**Rationale:** Shadow RAT v2.6.4.0 includes a firewall disable command handler. This netsh opmode disable command sequence is rarely issued in managed environments outside deliberate maintenance windows. Context from parent process (if known to be a RAT-installed binary) elevates this to critical.
**ATT&CK Coverage:** T1562.004 (Disable or Modify System Firewall)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — legitimate administrators and IT automation scripts use this command pattern; correlate with other Shadow RAT indicators for confirmation
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR

```yaml
title: Windows Firewall Disabled via netsh opmode Command
id: d7b42f19-3a58-4c82-9e31-0f5b8c2a6d94
status: test
description: |
    Detects Windows Firewall being disabled via netsh.exe using the "firewall set opmode disable"
    command sequence. Shadow RAT v2.6.4.0 includes explicit firewall disable capability in its
    command handler set, allowing operators to suppress host-based network filtering to enable
    unrestricted C2 communication or lateral movement. This command disables all Windows Firewall
    profiles simultaneously and is rarely issued in managed enterprise environments outside of
    explicit maintenance windows.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1562/004/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'firewall'
            - 'set'
            - 'opmode'
            - 'disable'
    condition: selection
falsepositives:
    - Legitimate administrators disabling Windows Firewall during planned maintenance or network reconfiguration
    - IT automation scripts that manage firewall state as part of policy enforcement workflows
    - Software installers that temporarily disable the firewall during service installation
level: high
```

---

### XWorm 3.0-5.0

---

**Detection Priority:** CRITICAL
**Rationale:** A scheduled task running at 1-minute intervals at HIGHEST privilege from %AppData% has no known legitimate use case. This combination of flags is unique to XWorm's triple-redundant persistence implementation.
**ATT&CK Coverage:** T1053.005 (Scheduled Task persistence)
**Confidence:** HIGH
**False Positive Risk:** LOW — no known legitimate software creates 1-minute HIGHEST privilege tasks from AppData
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR

```yaml
title: XWorm Scheduled Task Persistence with One-Minute Execution Interval
id: 94b6c01a-db65-4aa1-82c5-46eebc0c8ee5
status: test
description: |
    Detects XWorm 3.0-5.0 creating a scheduled task that runs every one minute at HIGHEST
    privilege level. This is the most aggressive of XWorm's three redundant persistence
    mechanisms — the one-minute interval provides near-instant re-execution after process
    termination and the HIGHEST privilege flag requests elevated execution context. The task
    name is derived from the install filename (typically "XWormClient") and the action points
    to the malware binary in %AppData%.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1053/005/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.persistence
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/sc minute'
            - '/mo 1'
            - '/rl highest'
    selection_path:
        CommandLine|contains:
            - '\AppData\Roaming\'
    condition: selection_cmd and selection_path
falsepositives:
    - No known legitimate software creates one-minute interval scheduled tasks at HIGHEST privilege from AppData
level: critical
```

---

**Detection Priority:** CRITICAL
**Rationale:** The registry value name `XWormClient` pointing to `%AppData%\Roaming\XWormClient.exe` is a specific artifact of XWorm's default install configuration. No known legitimate software uses this value name.
**ATT&CK Coverage:** T1547.001 (Registry Run Keys persistence)
**Confidence:** HIGH
**False Positive Risk:** LOW — `XWormClient` value name is specific to XWorm family
**Deployment:** SIEM (Sysmon Event ID 13 / registry_set), EDR registry monitoring

```yaml
title: XWorm Registry Run Key Persistence Using Malware Install Name
id: 68182796-ac58-45fa-a2c9-ed2843b5398f
status: test
description: |
    Detects XWorm 3.0-5.0 establishing registry Run key persistence using the value name
    "XWormClient", which matches the malware's default install filename. XWorm uses the
    install filename (without extension) as both the registry value name and the process mutex,
    creating a consistent and distinctive artifact. This is one of three redundant persistence
    mechanisms deployed simultaneously. The value data points to the malware binary in
    %AppData%\Roaming\.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1547/001/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\XWormClient'
        Details|contains: '\AppData\Roaming\XWormClient.exe'
    condition: selection
falsepositives:
    - No known legitimate software uses the registry value name "XWormClient"
level: critical
```

---

**Detection Priority:** MEDIUM
**Rationale:** XWorm creates `XWormClient.lnk` in the Startup folder via WScript.Shell COM automation as its third persistence mechanism. A .lnk file created in the Startup folder by a non-system, non-installer process is abnormal.
**ATT&CK Coverage:** T1547.009 (Shortcut Modification — Startup folder persistence)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — legitimate software installers running from staging directories may create startup shortcuts; correlate with other XWorm indicators
**Deployment:** SIEM (Sysmon Event ID 11 / file_event), EDR

```yaml
title: Executable Shortcut Created in Windows Startup Folder by Non-System Process
id: a3c91e72-8f44-4b19-bd52-1f6a3c9d7e08
status: test
description: |
    Detects creation of a .lnk shortcut file inside the Windows Startup folder by a process
    outside system-managed directories. XWorm 3.0-5.0 creates a startup shortcut at
    %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\XWormClient.lnk via WScript.Shell
    COM automation as one of three redundant persistence mechanisms. Legitimate software
    installers creating startup shortcuts typically run from Program Files; a shortcut created
    by a process running from a user-writable path is a strong indicator of malware persistence.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1547/009/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.persistence
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Microsoft\Windows\Start Menu\Programs\Startup\'
        TargetFilename|endswith: '.lnk'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_legitimate
falsepositives:
    - Software installers running from user-writable staging directories that create startup shortcuts as part of setup
    - Legitimate update managers or tray applications deployed outside Program Files that add startup shortcuts
level: medium
```

---

**Detection Priority:** MEDIUM
**Rationale:** XWorm queries ip-api.com/line/?fields=hosting at startup before any malicious behavior executes. This specific URL parameter is not used in normal browser or application geolocation lookups — it is an operational parameter for hosting/datacenter detection.
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion — System Checks)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — legitimate tools use ip-api.com for geolocation; the non-browser filter reduces but does not eliminate false positives
**Deployment:** SIEM (Sysmon Event ID 22 / dns_query), EDR, DNS monitoring

```yaml
title: Non-Browser Process DNS Query to ip-api.com Hosting Detection Endpoint
id: ce5a51b5-1221-4843-ac57-3fa2b15ffb69
status: test
description: |
    Detects a non-browser process resolving ip-api.com, consistent with XWorm's anti-analysis
    hosting detection check. XWorm 3.0-5.0 queries http://ip-api.com/line/?fields=hosting at
    startup to determine whether the infected machine runs on hosting or datacenter infrastructure.
    If the API returns "true", the malware silently exits via Environment.Exit(0) to evade sandbox
    and researcher environments. A non-browser, non-network-tool process querying this specific
    API is a strong indicator of sandbox evasion behavior.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1497/001/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
    - attack.discovery
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|contains: 'ip-api.com'
    filter_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
            - '\brave.exe'
            - '\opera.exe'
    condition: selection and not filter_browser
falsepositives:
    - Legitimate applications using ip-api.com for geolocation or network diagnostics
    - Network monitoring and IT asset management tools that use ip-api.com as a data source
    - Weather, travel, or location-aware desktop applications performing connectivity checks
level: medium
```

---

### Campaign-Level (Both Families)

---

**Detection Priority:** MEDIUM
**Rationale:** Both Shadow RAT and XWorm remove the Zone.Identifier ADS to bypass SmartScreen. Removal of this ADS by a non-browser, non-system process is abnormal behavior and indicates deliberate MOTW suppression.
**ATT&CK Coverage:** T1553.005 (Subvert Trust Controls — Mark-of-the-Web Bypass)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — download managers and deployment tools sometimes strip Zone.Identifier; environment-specific tuning may be required
**Deployment:** SIEM (Sysmon Event ID 23 / file_event), EDR file monitoring

```yaml
title: Zone.Identifier Alternate Data Stream Removal for SmartScreen Bypass
id: b78a5718-03c3-4e99-ab50-7fd048a70872
status: test
description: |
    Detects deletion of the Zone.Identifier alternate data stream (ADS) from executable files
    by non-browser, non-system processes. Both Shadow RAT and XWorm remove the Mark-of-the-Web
    (MOTW) from their own executables after installation to suppress Windows SmartScreen warnings
    on subsequent executions. Shadow RAT uses FileHelper.DeleteZoneIdentifier; XWorm performs a
    direct ADS stream deletion. Removal of Zone.Identifier by a process other than a browser or
    system tool is abnormal and indicates deliberate MOTW suppression.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1553/005/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
    filter_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
    filter_system:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
    condition: selection and not (filter_browser or filter_system)
falsepositives:
    - Download managers or file transfer utilities that strip Zone.Identifier after checksum verification
    - Software deployment and packaging tools that remove MOTW from downloaded installers during staging
level: medium
```

---

**Detection Priority:** MEDIUM
**Rationale:** XWorm queries Win32_ComputerSystem via WMI to check for VM artifacts. A WMI query containing `Win32_ComputerSystem` where the parent process originates from a user-writable directory is unusual — legitimate WMI inventory tools run from managed system paths.
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion), T1082 (System Information Discovery)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — portable WMI tools or IT scripts placed in AppData by deployment systems may generate this pattern
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR

```yaml
title: WMI Win32_ComputerSystem Query from User-Writable Directory
id: e82e90ce-c1fd-46df-83af-91d73094a63f
status: test
description: |
    Detects WMI queries referencing Win32_ComputerSystem originating from a process whose parent
    executable resides in a user-writable directory (AppData or Temp). XWorm 3.0-5.0 queries
    Win32_ComputerSystem at startup to check the Manufacturer and Model fields for virtual machine
    indicators (VMware, VirtualBox, Hyper-V strings). This is one of six anti-analysis checks
    performed before any malicious behavior executes. Legitimate WMI inventory tools run from
    managed system paths, not user-writable locations.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/shadow-xworm-opendirectory/
    - https://attack.mitre.org/techniques/T1497/001/
author: The Hunters Ledger
date: 2026/04/04
tags:
    - attack.defense-evasion
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmi:
        CommandLine|contains: 'Win32_ComputerSystem'
    selection_suspicious:
        ParentImage|contains:
            - '\AppData\Roaming\'
            - '\AppData\Local\Temp\'
    condition: selection_wmi and selection_suspicious
falsepositives:
    - Legitimate system inventory or asset management tools running WMI queries from user-writable paths (unusual but possible in portable tool deployments)
    - IT automation scripts placed in AppData by software deployment systems
level: medium
```

---

## Suricata Signatures

```
# =============================================================================
# Shadow RAT & XWorm Open Directory Campaign — Suricata Rules
# Campaign: ShadowRAT-XWorm-OpenDirectory-151.245.112.70
# Author: The Hunters Ledger
# Date: 2026-04-04
# License: CC BY-NC 4.0
# Reference: https://the-hunters-ledger.com/reports/shadow-xworm-opendirectory/
# =============================================================================

# ---------------------------------------------------------------------------
# Rule 1: Shadow RAT C2 Communication (151.245.112.70:8990)
#
# Detection Priority: CRITICAL
# Rationale: Direct connection to confirmed C2 IP/port extracted from
#   AES-256 encrypted config. Shadow RAT uses TLS 1.2 with AES-256-CBC
#   and HMAC-SHA256. Any outbound connection to this address is malicious.
# ATT&CK Coverage: T1573.001 (Encrypted Channel), T1071.001 (Web Protocols)
# Confidence: HIGH
# False Positive Risk: LOW — port 8990 on this IP is exclusively Shadow RAT C2
# Deployment: Perimeter firewall/IDS
# ---------------------------------------------------------------------------
alert tcp $HOME_NET any -> 151.245.112.70 8990 (
    msg:"THL TROJAN Shadow RAT v2.6.4.0 C2 Communication to 151.245.112.70:8990";
    flow:established,to_server;
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040401;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity critical, deployment perimeter;
)

# ---------------------------------------------------------------------------
# Rule 2: XWorm C2 Communication (151.245.112.70:7007)
#
# Detection Priority: CRITICAL
# Rationale: Direct connection to confirmed C2 IP/port extracted from
#   Rijndael-256-ECB encrypted XWorm config. Any outbound TCP to this
#   IP:port is malicious.
# ATT&CK Coverage: T1573.001, T1071.001
# Confidence: HIGH
# False Positive Risk: LOW — port 7007 on this IP is exclusively XWorm C2
# Deployment: Perimeter firewall/IDS
# ---------------------------------------------------------------------------
alert tcp $HOME_NET any -> 151.245.112.70 7007 (
    msg:"THL TROJAN XWorm 3.0-5.0 C2 Communication to 151.245.112.70:7007";
    flow:established,to_server;
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040402;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity critical, deployment perimeter;
)

# ---------------------------------------------------------------------------
# Rule 3: XWorm Anti-Analysis Hosting Detection via ip-api.com
#
# Detection Priority: MEDIUM
# Rationale: XWorm queries this specific URL path with the "fields=hosting"
#   parameter at startup to detect sandbox/datacenter environments. This
#   specific query parameter is not used by legitimate browser traffic.
# ATT&CK Coverage: T1497.001 (Virtualization/Sandbox Evasion)
# Confidence: HIGH
# False Positive Risk: MEDIUM — legitimate tools use ip-api.com; the
#   specific /line/?fields=hosting path reduces but does not eliminate FPs
# Deployment: Perimeter IDS, proxy/web gateway
# ---------------------------------------------------------------------------
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"THL TROJAN XWorm Anti-Analysis Hosting Check via ip-api.com";
    flow:established,to_server;
    http.host; content:"ip-api.com"; nocase;
    http.uri; content:"/line/"; content:"fields=hosting";
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040403;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity medium, deployment perimeter;
)

# ---------------------------------------------------------------------------
# Rule 4: DNS Query for harrismanlieb.ink (Active C2 Domain)
#
# Detection Priority: CRITICAL
# Rationale: Active operational domain on C2 server 151.245.112.70.
#   Registered 2026-02-12, ScreenConnect deployed from this domain.
#   DomainTools risk score 100/100. Any internal host resolving this
#   domain should be treated as compromised.
# ATT&CK Coverage: T1071.001 (Web Protocols), T1219 (Remote Access Software)
# Confidence: HIGH
# False Positive Risk: LOW — domain has no known legitimate use
# Deployment: Perimeter IDS, DNS resolver logging
# ---------------------------------------------------------------------------
alert dns $HOME_NET any -> any 53 (
    msg:"THL TROJAN DNS Query for harrismanlieb.ink (Shadow RAT/XWorm Campaign Domain)";
    dns.query; content:"harrismanlieb.ink"; nocase;
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040404;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity critical, deployment perimeter;
)

# ---------------------------------------------------------------------------
# Rule 5: DNS Query for epgoldsecurity.com (Payload Delivery Domain)
#
# Detection Priority: HIGH
# Rationale: Payload delivery domain that hosted the open directory
#   containing all four malware samples. DomainTools risk score 100/100.
#   Any internal host resolving this domain may be downloading malware.
# ATT&CK Coverage: T1071.001
# Confidence: HIGH
# False Positive Risk: LOW — domain has no known legitimate purpose
# Deployment: Perimeter IDS, DNS resolver logging
# ---------------------------------------------------------------------------
alert dns $HOME_NET any -> any 53 (
    msg:"THL TROJAN DNS Query for epgoldsecurity.com (Malware Payload Delivery Domain)";
    dns.query; content:"epgoldsecurity.com"; nocase;
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040405;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity high, deployment perimeter;
)

# ---------------------------------------------------------------------------
# Rule 6: Shadow RAT Potential Fallback C2 (151.245.112.70:3000)
#
# Detection Priority: HIGH
# Rationale: Port 3000 appears as a cleartext port field in the Shadow RAT
#   config. Purpose unconfirmed — may be a default port, reconnection
#   fallback, or legacy config artifact. Treat as supporting indicator.
# ATT&CK Coverage: T1571 (Non-Standard Port)
# Confidence: MODERATE
# False Positive Risk: LOW on this specific IP — port 3000 is commonly
#   used by dev tools but not on this confirmed malicious host
# Deployment: Perimeter firewall/IDS
# ---------------------------------------------------------------------------
alert tcp $HOME_NET any -> 151.245.112.70 3000 (
    msg:"THL TROJAN Shadow RAT Potential Fallback C2 to 151.245.112.70:3000";
    flow:established,to_server;
    reference:url,the-hunters-ledger.com/reports/shadow-xworm-opendirectory/;
    classtype:trojan-activity;
    sid:2026040406;
    rev:1;
    metadata:created_at 2026_04_04, updated_at 2026_04_04, severity high, deployment perimeter;
)
```

---

## MITRE ATT&CK Coverage Map

| Technique ID | Name | Detection Layer | Rule(s) |
|---|---|---|---|
| T1547.001 | Registry Run Keys / Startup Folder | Sigma | Shadow RAT registry persistence; XWorm registry persistence |
| T1547.009 | Shortcut Modification (Startup Folder) | Sigma | XWorm .lnk startup shortcut creation |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Sigma | XWorm 1-minute schtask |
| T1562.001 | Impair Defenses: Disable or Modify Tools (AMSI) | YARA + Sigma | AMSI patch bytes; amsi.dll image load |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | Sigma | Shadow RAT netsh firewall disable |
| T1562.006 | Impair Defenses: Indicator Blocking (ETW) | YARA + Sigma | ETW patch pattern; WriteProcessMemory ntdll |
| T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | Sigma | Zone.Identifier ADS removal |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | YARA + Sigma + Suricata | XWorm anti-analysis; WMI VM detection; ip-api callback |
| T1027 | Obfuscated Files or Information | YARA | Asterisk string obfuscation; Rijndael config encryption |
| T1027.002 | Software Packing | YARA | .NET Reactor + Costura.Fody markers |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | YARA + Suricata | AES-256/Rijndael crypto patterns; C2 port rules |
| T1071.001 | Application Layer Protocol: Web Protocols | Suricata | ip-api.com hosting check; domain DNS rules |
| T1115 | Clipboard Data | YARA | Shadow RAT crypto clipper module |
| T1542.003 | Pre-OS Boot: Bootkit (WinRE) | YARA | Shadow RAT WinRE persistence module |
| T1571 | Non-Standard Port | Suricata | C2 port 8990, 7007, 3000 rules |
| T1082 | System Information Discovery | Sigma | WMI Win32_ComputerSystem query |

---

## Coverage Gaps

The following techniques from the malware-analyst findings could not be covered with high-confidence detection rules. Evidence requirements for future rule development are noted.

**T1055.012 — Process Hollowing (Shadow RAT RunPE)**
Shadow RAT includes `UseRunPE`, `RunPETarget`, and `ExecuteInMemoryDotNet` fields in its config and message handlers. However, behavioral analysis was conducted statically — no sandbox execution confirmed which processes are hollowed or under what command conditions. A behavioral Sigma rule for process hollowing requires observed parent-child process pairs and hollow process characteristics. Coverage pending dynamic analysis confirmation.

**T1572 — Protocol Tunneling via Ngrok**
Shadow RAT includes Ngrok tunnel management capability (path and token fields). The Ngrok binary is not embedded — it must be downloaded or pre-installed by the operator. A detection rule would require the Ngrok binary hash or the specific API endpoint used for tunnel establishment. Coverage pending observation of Ngrok deployment in an active incident.

**T1091 — Replication Through Removable Media (XWorm USB spread)**
XWorm has `USB.exe` as a config field and the USB spread capability is documented in the codebase. However, the propagation mechanism code was not independently confirmed in static analysis of the recovered samples. A file-based Sigma rule (file creation on removable media matching `USB.exe`) or a process_creation rule targeting the spread mechanism requires dynamic analysis confirmation.

**T1102.001 — Dead Drop Resolver (Pastebin fallback)**
Shadow RAT includes a Pastebin dead drop C2 fallback, but the boolean controlling it (`YuMK50gqNyIF4mYC6wcG2HeN`) was `false` in both recovered builds. No Pastebin URLs were observed. A network rule would require observation of an active Pastebin-based C2 URL in a future campaign build.

**T1219 — Remote Access Software (ScreenConnect)**
ScreenConnect was deployed on the C2 server on 2026-03-01 for persistent victim access. However, ScreenConnect is a legitimate RMM product — a detection rule targeting ScreenConnect binary hashes or known C2 relay ports (port 8040) would generate excessive false positives in environments that legitimately use ConnectWise ScreenConnect. Detection should focus on network anomalies (unexpected ScreenConnect traffic from endpoints that have no managed IT justification).
```

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
