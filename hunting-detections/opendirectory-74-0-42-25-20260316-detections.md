---
title: "Detection Rules — ZeroTrace Multi-Family MaaS Operation (Open Directory 74.0.42.25)"
date: '2026-03-17'
layout: post
permalink: /hunting-detections/opendirectory-74-0-42-25-20260316-detections/
hide: true
---

# Detection Rules — ZeroTrace Multi-Family MaaS Operation (Open Directory 74.0.42.25)

**Campaign:** ZeroTrace-MultiFamily-MaaS-74.0.42.25
**Date:** 2026-03-17
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0

---

## YARA Rules

```yara
/*
    Name: OpenDirectory 74.0.42.25 — Multi-Family MaaS Toolkit
    Author: The Hunters Ledger
    Date: 2026-03-17
    Identifier: XWorm V5.6 / PureRAT v4.1.9 / RavenRAT / XwormLoader / Aspdkzb
    Reference: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/
    License: https://creativecommons.org/licenses/by-nc/4.0/
*/

rule RAT_XWorm_V56_Stub
{
    meta:
        description = "Detects XWorm V5.6 VB.NET victim stub by plaintext mutex string, protocol packet delimiter, and distinctive Telegram notification typo strings characteristic of this builder version"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "427f818131c9beb7f8a487cb28fe13e2699db844ac3c9e9ae613fd35113fe77f"
        family = "XWorm"

    strings:
        $s1 = "5tK099W0Z6AMZVxQ" ascii wide
        $s2 = "<Xwormmm>" ascii wide
        $s3 = "XWorm V5.6" ascii wide
        $s4 = "New Clinet : " ascii wide
        $s5 = "Groub : " ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 150KB and
        ($s1 or ($s2 and $s3)) and
        1 of ($s4, $s5)
}

rule TOOLKIT_XWorm_V56_Builder
{
    meta:
        description = "Detects XWorm V5.6 builder and C2 server panel by version string, Telegram skull emoji format string, and sandbox VM detection URL characteristic of the V5.6 build"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "90f58865f265722ab007abb25074b3fc4916e927402552c6be17ef9afac96405"
        family = "XWorm"

    strings:
        $s1 = "XWorm V5.6" ascii wide
        $b1 = { E2 98 A0 20 5B 58 57 6F 72 6D 20 56 35 2E 36 5D }
        $s2 = "New Clinet : " ascii wide
        $s3 = "Groub : " ascii wide
        $s4 = "http://ip-api.com/line/?fields=hosting" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize > 1MB and filesize < 20MB and
        3 of them
}

rule MALW_XwormLoader_ReflectivePE
{
    meta:
        description = "Detects XwormLoader native C++ 11-stage reflective PE loader by NOT-minus-0x3E decryption opcode sequence, .NET Framework LDR path spoof string, and operator-authored decoy comment strings embedded in the binary"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "f5f14b9073f86da926a8ed319b3289b893442414d1511e45177f6915fb4e5478"
        family = "XwormLoader"

    strings:
        $b1 = { F6 D0 2C 3E }
        $s1 = "C:\\Windows\\Microsoft.NET\\Framework" wide
        $s2 = "This is garbage code #" ascii
        $s3 = "Welcome to the random numbers generator!" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 600KB and
        $b1 and
        ($s1 or ($s2 and $s3))
}

rule MALW_Aspdkzb_ConfuserEx_Loader
{
    meta:
        description = "Detects Aspdkzb-family ConfuserEx-protected fileless loader cluster delivering PureRAT v4.1.9 via three-stage in-memory Assembly.Load chain; matched by distinctive internal namespace strings from the loader stages"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "978ead9671e59772eeeb73344fc3b0c068c5168de7f67f738269f5b59e681a9a"
        family = "Aspdkzb"

    strings:
        $s1 = "ConfuserEx" ascii wide
        $s2 = "Faidowra" ascii wide
        $s3 = "Zvafsyattl" ascii wide
        $s4 = "Aspdkzb" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize >= 310KB and filesize <= 330KB and
        $s1 and
        1 of ($s2, $s3, $s4)
}

rule RAT_PureRAT_v419_Payload
{
    meta:
        description = "Detects PureRAT v4.1.9 final stage .NET Reactor-obfuscated payload (Faidowra.dll) by deobfuscated internal namespace strings and MaaS version string characteristic of the v4.1.9 build"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "6b526c29a6961c1f03eeb1ec4ca3a0fdc5680e3f90db013dea8b27d8b63cce57"
        family = "PureRAT"

    strings:
        $s1 = "Faidowra.IO.ModelConfiguration" ascii wide
        $s2 = "ProtoBuf.Strategies.ServerModel" ascii wide
        $s3 = "4.1.9" ascii wide
        $s4 = "OrderChain" ascii wide
        $s5 = "DefinitionChooser" ascii wide
        $s6 = "ProcEnumerator" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 900KB and
        (($s1 and $s2) or ($s3 and 2 of ($s4, $s5, $s6)))
}

rule RAT_RavenRAT_Stub
{
    meta:
        description = "Detects Raven RAT Delphi victim stub by hidden VNC class names from HVNC implementation and cryptocurrency wallet theft target strings; wallet names combined with Run key persistence value reduce false positive risk"
        author = "The Hunters Ledger"
        date = "2026-03-17"
        reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316/"
        hash_sha256 = "a616c5fd9cee76d2df4d2cfec8d8519e6fd2ad605c1942e1e1cbb99aa09a278d"
        family = "RavenRAT"

    strings:
        $s1 = "THiddenVNC" ascii wide
        $s2 = "THiddenVNCThread" ascii wide
        $s3 = "THVNCInputThread" ascii wide
        $s4 = "Exodus" ascii wide
        $s5 = "Atomic Wallet" ascii wide
        $s6 = "Guarda" ascii wide
        $s7 = "Wasabi" ascii wide
        $s8 = "WindowsService" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (($s1 and $s2) or (2 of ($s4, $s5, $s6, $s7) and $s8))
}
```

---

## Sigma Rules

```
# Detection Priority: HIGH
# Rationale: XWorm V5.6 writes operator configuration (Telegram bot token, crypto clipper addresses) to a distinctive registry key; legitimate software does not use HKCU\SOFTWARE\XWorm
# ATT&CK Coverage: T1112 (Modify Registry)
# Confidence: HIGH
# False Positive Risk: LOW — registry key name is malware-specific and not used by any known legitimate software
# Deployment: Windows endpoints with Sysmon EID 13 collection; EDR registry monitoring
```

```yaml
title: XWorm V5.6 Operator Configuration Registry Key Write
id: 2f4dafdd-6eb9-46f5-9ca6-ea704008f8da
status: test
description: >
    Detects registry write events targeting HKCU\SOFTWARE\XWorm, the key used by XWorm V5.6
    to store operator-configured values including Telegram bot token, bot ID, and cryptocurrency
    clipper wallet addresses (BTC, ETH, TRC20). Presence of this key indicates an active or
    recently active XWorm V5.6 infection on the host.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.defense-evasion
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKCU\SOFTWARE\XWorm'
    condition: selection
falsepositives:
    - No known legitimate software uses the HKCU\SOFTWARE\XWorm registry key path
level: high
```

---

```
# Detection Priority: HIGH
# Rationale: vlc_boxed.exe writes a Run key named "vlctask" pointing to %APPDATA%\vlcapp\vlc.exe — a name-collision attack on VLC Media Player; no legitimate VLC installation uses this path or value name
# ATT&CK Coverage: T1547.001 (Boot or Logon Autostart: Registry Run Keys), T1036 (Masquerading)
# Confidence: HIGH
# False Positive Risk: LOW — legitimate VLC installs to %ProgramFiles%; the vlctask/vlcapp path combination is malware-specific
# Deployment: Windows endpoints with Sysmon EID 13 collection; EDR registry monitoring
```

```yaml
title: vlc_boxed.exe DGA Malware Run Key Persistence via VLC Name Masquerade
id: e90b3fbd-823b-4218-a548-6c39376438f4
status: test
description: >
    Detects registry persistence write for vlc_boxed.exe, an Enigma Virtual Box-packed DGA-capable
    malware family that masquerades as VLC Media Player. The malware creates a Run key value named
    'vlctask' pointing to '%APPDATA%\vlcapp\vlc.exe' — a path not used by legitimate VLC
    installations, which install to %ProgramFiles%. Presence of this key indicates successful
    persistence establishment by an unidentified DGA-capable malware family confirmed in this campaign.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\vlctask'
    condition: selection
falsepositives:
    - Legitimate VLC Media Player does not use the vlctask Run key value name or the AppData\vlcapp path; no known false positive scenario for this specific value name
level: high
```

---

```
# Detection Priority: HIGH
# Rationale: Raven RAT (Delphi) creates a Run key value named "WindowsService" in HKCU — a deliberate masquerade concealing a user-mode persistence entry as a Windows system service name
# ATT&CK Coverage: T1547.001 (Boot or Logon Autostart: Registry Run Keys), T1036.004 (Masquerading: Masquerade Task or Service)
# Confidence: HIGH
# False Positive Risk: MEDIUM — "WindowsService" as a HKCU Run value is unusual but could appear in poorly named legitimate software; correlate with process image path outside System32 or Program Files
# Deployment: Windows endpoints with Sysmon EID 13 collection; EDR registry monitoring
```

```yaml
title: Raven RAT Persistence via WindowsService Run Key Masquerade
id: 9ad1fd97-8a23-42fd-8ab6-210999dd6d9c
status: test
description: >
    Detects Raven RAT (custom Delphi RAT developed by the ZeroTrace cluster) establishing
    persistence via a Run key entry named 'WindowsService' under
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run. This value name is a deliberate
    masquerade intended to appear as a legitimate Windows service entry to casual inspection.
    Raven RAT provides keylogging, hidden VNC desktop creation, cryptocurrency wallet theft
    (Exodus, Atomic Wallet, Guarda, Wasabi), and SOCKS proxy capabilities.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\CurrentVersion\Run\WindowsService'
    filter_legitimate:
        Details|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter_legitimate
falsepositives:
    - Poorly named legitimate software that uses 'WindowsService' as a Run key value name; validate that the target binary path is outside System32 and Program Files before actioning
level: high
```

---

```
# Detection Priority: HIGH
# Rationale: The ScreenConnect phishing dropper (Attachment.vbs) spawns msiexec with /quiet ALLUSERS=2 for silent ScreenConnect install — the combination of wscript.exe parent, msiexec child, and ALLUSERS=2 is specific to this phishing delivery chain
# ATT&CK Coverage: T1218.007 (System Binary Proxy Execution: Msiexec), T1059.005 (Command and Scripting Interpreter: Visual Basic), T1566.001 (Phishing: Spearphishing Attachment)
# Confidence: HIGH
# False Positive Risk: MEDIUM — silent MSI installs from wscript.exe are unusual in most enterprise environments but may occur in some software deployment scripts; tune by excluding known-good deployment parent paths
# Deployment: Windows endpoints with Sysmon EID 1 collection; EDR process creation monitoring
```

```yaml
title: ScreenConnect Phishing VBScript Dropper Silent MSI Install Chain
id: c48377bd-0066-4bb0-8cc7-4041cd0a0e54
status: test
description: >
    Detects the ScreenConnect phishing dropper chain where a VBScript (Attachment.vbs) spawns
    msiexec.exe with silent install flags (/quiet ALLUSERS=2) to install ConnectWise ScreenConnect
    without user interaction. The dropper downloads the MSI from the operator distribution domain
    using MSXML2.ServerXMLHTTP.6.0 with SSL verification deliberately bypassed. wscript.exe
    spawning msiexec.exe with ALLUSERS=2 is characteristic of this phishing dropper and is not
    expected behavior in legitimate software deployment from this parent process.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.execution
    - attack.initial-access
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\wscript.exe'
    selection_child:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|all:
            - '/quiet'
            - 'ALLUSERS=2'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate software deployment scripts that invoke msiexec silently from wscript.exe; validate MSI download source URL and installation target domain against known-good deployment infrastructure
level: high
```

---

```
# Detection Priority: MEDIUM
# Rationale: puf.ps1 and sync.ps1 are fileless PE droppers that use -ExecutionPolicy Bypass to load .ps1 scripts containing hex-encoded .NET assemblies loaded via Assembly.Load; specificity comes from non-standard parent process context
# ATT&CK Coverage: T1059.001 (Command and Scripting Interpreter: PowerShell), T1620 (Reflective Code Loading), T1027 (Obfuscated Files or Information)
# Confidence: MODERATE — ExecutionPolicy Bypass is common; specificity requires non-standard parent process correlation
# False Positive Risk: MEDIUM — ExecutionPolicy Bypass is used by legitimate admin tooling; extend filter block for environment-specific known-good parents
# Deployment: Windows endpoints with Sysmon EID 1 collection; EDR process creation monitoring; tune filter block per environment
```

```yaml
title: Fileless PowerShell PE Dropper ExecutionPolicy Bypass from Non-Standard Parent
id: 945438df-0fc1-4861-9ed6-4c66ae11e700
status: test
description: >
    Detects execution of PowerShell with -ExecutionPolicy Bypass loading a .ps1 file from
    non-standard parent processes, consistent with the puf.ps1 and sync.ps1 fileless PE dropper
    chain used in this campaign. These droppers hex-decode an embedded 310KB .NET PE assembly and
    load it entirely in memory via Assembly.Load with no disk write, bypassing file-based detection.
    The rule targets PowerShell spawned by remote access tools, command shells, or scripting
    interpreters not expected to launch PowerShell with policy bypass flags in normal operations.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-ExecutionPolicy'
            - 'Bypass'
            - '.ps1'
    filter_standard_parents:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\services.exe'
            - '\svchost.exe'
            - '\msiexec.exe'
    condition: selection and not filter_standard_parents
falsepositives:
    - Legitimate administrative scripts invoked via remote management tools, scheduled tasks, or software deployment systems; extend filter_standard_parents to include known-good deployment parent images in the target environment
level: medium
```

---

```
# Detection Priority: HIGH
# Rationale: 185.49.126.140 is a confirmed multi-family C2 server hosting XWorm V5.6 (port 5000), PureHVNC (port 8000), and PureRAT v4.1.9 (ports 56001-56003); any outbound connection on these ports is confirmed malicious C2 traffic
# ATT&CK Coverage: T1071.001 (Application Layer Protocol: Web Protocols), T1573.001 (Encrypted Channel: Symmetric Cryptography), T1573.002 (Encrypted Channel: Asymmetric Cryptography)
# Confidence: HIGH
# False Positive Risk: LOW — IP and port combinations are confirmed C2; no legitimate services operate on these ports at this IP
# Deployment: Windows endpoints with Sysmon EID 3 collection; network perimeter sensors; EDR network telemetry
```

```yaml
title: Confirmed Multi-Family C2 Outbound Connection to MaaS Toolkit Infrastructure
id: 40d3065a-71ac-41e9-8726-c76c48c04c9a
status: test
description: >
    Detects outbound network connections to 185.49.126.140 on ports confirmed as active C2
    channels for multiple malware families operated by the same threat actor: port 5000 (XWorm
    V5.6 RAT with AES-128 ECB encrypted protocol), port 8000 (PureHVNC hidden VNC stub), and
    ports 56001-56003 (PureRAT v4.1.9 MaaS RAT with ProtoBuf-over-TLS C2 protocol). All port
    assignments were independently confirmed from separate binary analysis sessions. Any connection
    to this IP on these ports represents confirmed malicious C2 activity warranting immediate
    investigation.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.command-and-control
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '185.49.126.140'
        DestinationPort:
            - 5000
            - 8000
            - 56001
            - 56002
            - 56003
        Initiated: 'true'
    condition: selection
falsepositives:
    - No known legitimate services operate on 185.49.126.140 on these ports; false positive likelihood is negligible for this confirmed malicious IP and port combination
level: critical
```

---

```
# Detection Priority: HIGH
# Rationale: Outbound TCP to adminxyzhosting.com:8041 is the operator-specific ScreenConnect relay port confirmed from Attachment.vbs, 500 pre-generated phishing session URLs, and binary analysis; port 8041 is non-standard for ScreenConnect and not used by any legitimate deployment
# ATT&CK Coverage: T1219 (Remote Access Software), T1071.001 (Application Layer Protocol: Web Protocols)
# Confidence: HIGH
# False Positive Risk: LOW — adminxyzhosting.com is a confirmed malicious operator domain; port 8041 is non-standard for ScreenConnect
# Deployment: Windows endpoints with Sysmon EID 3 collection; DNS-aware network sensors; EDR network telemetry
```

```yaml
title: ScreenConnect Relay Outbound Connection to Malicious Operator Domain on Port 8041
id: e237ddd4-f9bd-48ee-8ebd-623f2fe90198
status: test
description: >
    Detects outbound network connections to adminxyzhosting.com on TCP port 8041, the
    operator-specific ScreenConnect relay endpoint used to maintain persistent remote access to
    victims installed via phishing. ConnectWise ScreenConnect v23.2.9 was confirmed running on
    this domain. Port 8041 is a non-standard ScreenConnect relay port used exclusively by this
    operator; legitimate ScreenConnect installations typically relay on ports 443 or 8040.
    Detection of this connection pattern indicates an unauthorized ScreenConnect session
    established through phishing activity.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/opendirectory-74-0-42-25-20260316-detections/
author: The Hunters Ledger
date: 2026/03/17
tags:
    - attack.command-and-control
    - attack.initial-access
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|endswith: 'adminxyzhosting.com'
        DestinationPort: 8041
        Initiated: 'true'
    condition: selection
falsepositives:
    - No legitimate ConnectWise ScreenConnect deployment is expected on adminxyzhosting.com port 8041; this domain and port combination is confirmed operator-specific malicious infrastructure
level: high
```

---

## Suricata Rules

```
# Detection Priority: HIGH
# Rationale: Any TCP connection to 185.49.126.140:5000 is confirmed XWorm V5.6 C2 traffic; IP and port independently confirmed from decrypted XClient.exe AES-256 ECB configuration
# ATT&CK Coverage: T1071.001 (Application Layer Protocol: Web Protocols), T1573.001 (Encrypted Channel: Symmetric Cryptography)
# Confidence: HIGH
# False Positive Risk: LOW — confirmed malicious C2 IP and port; no legitimate service operates on 185.49.126.140:5000
# Deployment: Network perimeter IDS/IPS, inline sensor on egress paths
```

```
alert tcp $HOME_NET any -> 185.49.126.140 5000 (msg:"THL MaaS Toolkit XWorm V5.6 C2 Communication to Confirmed Operator C2 Server"; flow:established,to_server; threshold:type limit,track by_src,count 1,seconds 300; classtype:trojan-activity; sid:9001001; rev:1; metadata:author "The Hunters Ledger", created_at 2026_03_17, malware_family XWorm, confidence high, mitre_technique T1071.001;)
```

---

```
# Detection Priority: HIGH
# Rationale: PureRAT v4.1.9 sends a fixed 4-byte TCP preamble 0x04000000 before initiating TLS on ports 56001-56003; this preamble is a published behavioral signature independently confirmed from Faidowra.dll binary analysis and Netresec research
# ATT&CK Coverage: T1573.002 (Encrypted Channel: Asymmetric Cryptography), T1071.001 (Application Layer Protocol: Web Protocols)
# Confidence: HIGH
# False Positive Risk: LOW — the specific 4-byte preamble on these non-standard destination ports is characteristic of PureRAT v4.1.9 protocol framing and not observed in legitimate traffic on these ports
# Deployment: Network perimeter IDS/IPS, inline sensor on egress paths; note TLS session prevents payload inspection after the preamble bytes
```

```
alert tcp $HOME_NET any -> 185.49.126.140 [56001,56002,56003] (msg:"THL MaaS Toolkit PureRAT v4.1.9 Protocol Preamble Before TLS to Confirmed C2 Ports"; flow:established,to_server; content:"|04 00 00 00|"; depth:4; threshold:type limit,track by_src,count 1,seconds 300; classtype:trojan-activity; sid:9001002; rev:1; metadata:author "The Hunters Ledger", created_at 2026_03_17, malware_family PureRAT, confidence high, mitre_technique T1573.002;)
```

---

```
# Detection Priority: HIGH
# Rationale: Outbound TCP to port 8041 carrying the hostname adminxyzhosting.com is the operator-specific ScreenConnect relay confirmed from Attachment.vbs, 500 phishing session URLs, and binary analysis; port 8041 is non-standard and not used by any known legitimate ScreenConnect deployment
# ATT&CK Coverage: T1219 (Remote Access Software), T1071.001 (Application Layer Protocol: Web Protocols)
# Confidence: HIGH
# False Positive Risk: LOW — adminxyzhosting.com is a confirmed malicious operator domain; port 8041 is non-standard and not associated with legitimate ScreenConnect infrastructure
# Deployment: Network perimeter IDS/IPS; DNS-aware sensors; egress filtering on corporate gateway
```

```
alert tcp $HOME_NET any -> any 8041 (msg:"THL MaaS Toolkit ScreenConnect Relay to Malicious Operator Domain adminxyzhosting.com"; flow:established,to_server; content:"adminxyzhosting.com"; nocase; threshold:type limit,track by_src,count 1,seconds 300; classtype:policy-violation; sid:9001003; rev:1; metadata:author "The Hunters Ledger", created_at 2026_03_17, malware_family ScreenConnect_Abuse, confidence high, mitre_technique T1219;)
```
