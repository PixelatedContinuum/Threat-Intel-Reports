---
title: Detection Rules - uac_test.exe (UAC Bypass PoC)
date: '2026-01-12'
layout: post
permalink: /hunting-detections/uac-test-exe/
hide: true
---

# Detection Rules – uac_test.exe (UAC Bypass PoC)

## Overview
Comprehensive detection coverage for uac_test.exe UAC bypass proof-of-concept tool includes host-based indicators, process behavior patterns, and registry monitoring signatures. Rules are provided in YARA, Sigma, and EDR query formats for SIEM/EDR integration and proactive threat hunting.

**Tool Type**: UAC Bypass Proof-of-Concept / Security Research Tool
**Severity**: MEDIUM (tool itself) / HIGH (UAC bypass attempts in general)
**Last Updated**: 2026-01-12

---

## Table of Contents

1. [YARA Rules](#yara-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Network Detection](#network-detection)
6. [PowerShell Detection Scripts](#powershell-detection-scripts)
7. [Implementation Guidance](#implementation-guidance)

---

## YARA Rules

### Rule 1: uac_test.exe Comprehensive Detection

```yaml
rule UAC_Test_PoC_Comprehensive {
    meta:
        description = "Detects uac_test.exe UAC bypass PoC tool based on file hash, strings, and behavioral indicators"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"
        tool_type = "UAC Bypass PoC"
        hash = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
        reference = "Open Directory 109.230.231.37 Investigation"
        mitre_attack = "T1548.002"

    strings:
        // File hash identifier (SHA-256)
        $hash = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760" nocase

        // CMSTPLUA COM interface identifiers
        $clsid_cmstplua = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase
        $elevation_moniker = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase

        // Fodhelper registry path
        $reg_fodhelper = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii wide nocase

        // UAC bypass status messages (educational strings)
        $msg_uac_test = "UAC Bypass Test - Rust Implementation" ascii
        $msg_admin_already = "[+] Already running as administrator!" ascii
        $msg_no_bypass = "[+] No UAC bypass needed." ascii
        $msg_com_bypass = "[+] COM bypass executed!" ascii
        $msg_com_attempt = "[1] Testing COM-based UAC Bypass (CMSTPLUA)" ascii
        $msg_reg_bypass = "[+] Registry bypass triggered!" ascii
        $msg_reg_attempt = "[2] Testing Registry-based UAC Bypass (fodhelper)" ascii
        $msg_com_success = "[+] *** COM UAC BYPASS SUCCESS! ***" ascii
        $msg_reg_success = "[+] *** REGISTRY UAC BYPASS SUCCESS! ***" ascii

        // COM initialization strings
        $com_init = "[*] Initializing COM..." ascii
        $com_moniker = "[*] Creating elevation moniker..." ascii
        $com_cogetobject = "[*] Calling CoGetObject with elevation moniker..." ascii
        $com_interface = "[+] Got ICMLuaUtil interface!" ascii
        $com_shellexec = "[*] Calling ShellExec to run elevated command..." ascii

        // Rust compilation artifacts
        $rust_lib1 = "library\\alloc\\src\\string.rs" ascii
        $rust_lib2 = "library\\core\\src\\slice\\memchr.rs" ascii
        $rust_lib3 = "/rustc/" ascii
        $rust_lib4 = "library\\std\\src\\panicking.rs" ascii

        // Anti-debugging API imports (standard for executables)
        $antidebug1 = "IsDebuggerPresent" ascii wide
        $antidebug2 = "SetUnhandledExceptionFilter" ascii wide

        // Memory manipulation APIs (standard for Rust)
        $mem1 = "VirtualProtect" ascii wide

        // Token/privilege check APIs
        $token1 = "CheckTokenMembership" ascii wide
        $token2 = "AllocateAndInitializeSid" ascii wide
        $token3 = "FreeSid" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file signature
        filesize < 500KB and
        (
            $hash or // Known file hash match (highest confidence)
            (
                // High confidence: CMSTPLUA bypass indicators
                ($clsid_cmstplua and ($elevation_moniker or $com_init or $com_moniker)) and
                (2 of ($msg_*)) and
                (1 of ($rust_lib*))
            ) or
            (
                // High confidence: Fodhelper bypass indicators
                ($reg_fodhelper) and
                (2 of ($msg_*)) and
                (1 of ($rust_lib*))
            ) or
            (
                // Medium confidence: Multiple educational strings + Rust compilation
                (4 of ($msg_*)) and
                (2 of ($rust_lib*)) and
                (1 of ($token*))
            ) or
            (
                // Medium confidence: COM bypass strings + token check
                ($clsid_cmstplua or $elevation_moniker) and
                (3 of ($com_*)) and
                (2 of ($msg_*))
            )
        )
}
```

### Rule 2: Generic UAC Bypass Behavior Detection

```yaml
rule Generic_UAC_Bypass_Behavior {
    meta:
        description = "Detects generic UAC bypass techniques (CMSTPLUA + Fodhelper)"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        reference = "MITRE ATT&CK T1548.002"

    strings:
        // CMSTPLUA CLSID (ICMLuaUtil interface)
        $cmstplua_clsid = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase

        // Fodhelper registry paths
        $fodhelper_reg1 = "ms-settings\\shell\\open\\command" ascii wide nocase
        $fodhelper_reg2 = "Software\\Classes\\ms-settings" ascii wide nocase

        // Additional UAC bypass CLSIDs
        $bypass_clsid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" nocase // CMLUAUTIL
        $bypass_clsid2 = "{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}" nocase // ColorDataProxy

        // UAC bypass executable names
        $exe_fodhelper = "fodhelper.exe" ascii wide nocase
        $exe_slui = "slui.exe" ascii wide nocase

        // Registry manipulation APIs
        $reg_api1 = "RegCreateKeyEx" ascii wide
        $reg_api2 = "RegSetValueEx" ascii wide
        $reg_api3 = "RegOpenKeyEx" ascii wide

        // COM APIs
        $com_api1 = "CoGetObject" ascii wide
        $com_api2 = "CoCreateInstance" ascii wide
        $com_api3 = "CoInitializeEx" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            // CMSTPLUA bypass indicators
            ($cmstplua_clsid and (1 of ($com_api*))) or

            // Fodhelper bypass indicators
            (($fodhelper_reg1 or $fodhelper_reg2) and (1 of ($reg_api*))) or

            // Multiple bypass method indicators
            ((1 of ($bypass_clsid*)) and (1 of ($exe_*)) and (1 of ($reg_api*)))
        )
}
```

### Rule 3: Rust-Compiled UAC Bypass Tool Detection

```yaml
rule Rust_Compiled_UAC_Bypass {
    meta:
        description = "Detects Rust-compiled UAC bypass tools based on language artifacts and bypass techniques"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"

    strings:
        // Rust compiler artifacts
        $rust1 = "/rustc/" ascii
        $rust2 = "library\\core\\src" ascii
        $rust3 = "library\\alloc\\src" ascii
        $rust4 = "library\\std\\src" ascii
        $rust5 = "rust_panic" ascii
        $rust6 = "std::panicking" ascii

        // UAC bypass technique indicators
        $uac1 = "UAC" nocase
        $uac2 = "elevation" nocase
        $uac3 = "administrator" nocase
        $uac4 = "bypass" nocase

        // CMSTPLUA or Fodhelper
        $bypass_clsid = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" nocase
        $bypass_reg = "ms-settings\\shell\\open\\command" ascii wide nocase

        // Privilege check APIs
        $priv_api1 = "CheckTokenMembership" ascii wide
        $priv_api2 = "GetTokenInformation" ascii wide
        $priv_api3 = "OpenProcessToken" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        (2 of ($rust*)) and
        (
            ($bypass_clsid or $bypass_reg) or
            ((2 of ($uac*)) and (1 of ($priv_api*)))
        )
}
```

---

## Sigma Detection Rules

### Rule 1: Fodhelper UAC Bypass via Registry Hijacking

```yaml
title: UAC Bypass via Fodhelper Registry Hijacking
id: 9a2c5b8f-3d1e-4f5a-8c9b-1a2d3e4f5a6b
status: stable
description: Detects creation of registry keys associated with Fodhelper UAC bypass technique
references:
    - https://attack.mitre.org/techniques/T1548/002/
    - https://github.com/hfiref0x/UACME
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
tags:
    - attack.privilege_escalation
    - attack.t1548.002
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
    definition: 'Sysmon Event ID 13 (Registry Value Set)'
detection:
    selection:
        EventID: 13
        TargetObject|contains: '\Software\Classes\ms-settings\shell\open\command'
    filter_legitimate:
        Image|endswith:
            - '\fodhelper.exe'
            - '\SystemSettings.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate system administration or registry cleanup tools (extremely rare)
    - Windows Settings application legitimate use
level: high
```

### Rule 2: CMSTPLUA COM Interface UAC Bypass

```yaml
title: UAC Bypass via CMSTPLUA COM Interface Abuse
id: 7b3c6d9e-4f2a-5e8b-9c1d-2a3e4f5a6b7c
status: experimental
description: Detects process elevation via CMSTPLUA COM interface without UAC prompt
references:
    - https://attack.mitre.org/techniques/T1548/002/
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
author: Threat Intelligence Team
date: 2026/01/12
tags:
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    product: windows
    service: security
    definition: 'Windows Security Event ID 4688 (Process Creation)'
detection:
    selection_process:
        EventID: 4688
        ParentProcessName|endswith: '\DllHost.exe'
        TokenElevationType: '%%1937'  # High integrity level
    selection_clsid:
        CommandLine|contains: '{6EDD6D74-C007-4E75-B76A-E5740995E24C}'
    timeframe: 10s
    condition: selection_process or selection_clsid
falsepositives:
    - Legitimate COM-based elevation by trusted Windows components
    - Some Windows update processes
level: high
```

### Rule 3: Privilege Escalation Without UAC Consent

```yaml
title: Suspicious Privilege Escalation Without UAC Consent
id: 1c2d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: stable
description: Detects privilege escalation to High integrity level without corresponding UAC consent event
references:
    - https://attack.mitre.org/techniques/T1548/002/
author: Threat Intelligence Team
date: 2026/01/12
tags:
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    product: windows
    service: security
detection:
    selection_elevation:
        EventID: 4672  # Special Privileges Assigned
        PrivilegeList|contains: 'SeDebugPrivilege'
    selection_no_consent:
        EventID: 4103  # UAC consent
    filter_system:
        SubjectUserName: 'SYSTEM'
    timeframe: 5s
    condition: selection_elevation and not selection_no_consent and not filter_system
falsepositives:
    - Scheduled tasks running with administrative privileges
    - System services launching with elevated privileges
    - Legitimate administrative tools
level: medium
```

### Rule 4: fodhelper.exe Spawning Unexpected Child Process

```yaml
title: Suspicious Child Process Spawned by fodhelper.exe
id: 2a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: stable
description: Detects fodhelper.exe spawning unexpected child processes (potential UAC bypass)
references:
    - https://attack.mitre.org/techniques/T1548/002/
author: Threat Intelligence Team
date: 2026/01/12
tags:
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\fodhelper.exe'
    filter_legitimate:
        Image|endswith:
            - '\SystemSettings.exe'
            - '\SettingsPageHost.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Windows Settings application launching legitimate components
level: high
```

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

**Query 1: Hunt for Fodhelper Registry Hijacking**

```kql
// Hunt for Fodhelper UAC bypass via registry hijacking
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"Software\Classes\ms-settings\shell\open\command"
| where InitiatingProcessFileName !in ("fodhelper.exe", "SystemSettings.exe")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Query 2: Hunt for CMSTPLUA COM Abuse**

```kql
// Hunt for CMSTPLUA COM interface UAC bypass
DeviceProcessEvents
| where ProcessCommandLine contains "DllHost.exe"
    or ProcessCommandLine contains "{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
    or ProcessCommandLine contains "Elevation:Administrator"
| where ProcessIntegrityLevel == "High"
    and InitiatingProcessIntegrityLevel != "High"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

**Query 3: Hunt for fodhelper.exe Spawning Suspicious Processes**

```kql
// Hunt for fodhelper.exe spawning unexpected child processes
DeviceProcessEvents
| where InitiatingProcessFileName =~ "fodhelper.exe"
| where FileName !in ("SystemSettings.exe", "SettingsPageHost.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Query 4: Hunt for UAC Bypass Tool Execution (File Hash)**

```kql
// Hunt for uac_test.exe by file hash
DeviceFileEvents
| where SHA256 == "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
    or MD5 == "36191c81f6b9fa40dceaa4700ff86800"
    or SHA1 == "08feb675d0553f98007c52b7658a725dee22d696"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

**Query 5: Hunt for Privilege Escalation Without UAC Consent**

```kql
// Hunt for privilege escalation without UAC consent event
let ElevationEvents = DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup" or ActionType == "UserAccountModified"
| where AdditionalFields contains "Administrators";
let UACConsent = DeviceEvents
| where ActionType == "UACPromptShown";
ElevationEvents
| join kind=leftanti UACConsent on DeviceName, $left.Timestamp == $right.Timestamp
| project Timestamp, DeviceName, ActionType, AccountName, AdditionalFields
| order by Timestamp desc
```

---

### CrowdStrike Falcon (Event Search)

**Query 1: Fodhelper Registry Hijacking**

```
event_simpleName=RegSetValue RegObjectName="*\\ms-settings\\shell\\open\\command*"
| stats count by aid, ContextTimeStamp, TargetProcessId, ImageFileName, RegValueName, RegValueData
```

**Query 2: CMSTPLUA COM Abuse**

```
event_simpleName=ProcessRollup2 FileName="DllHost.exe" CommandLine="*{6EDD6D74-C007-4E75-B76A-E5740995E24C}*"
| join aid, TargetProcessId [ search event_simpleName=ProcessRollup2 IntegrityLevel="High" ]
| stats count by aid, ContextTimeStamp, CommandLine, ParentProcessId, IntegrityLevel
```

**Query 3: fodhelper.exe Spawning Unexpected Processes**

```
event_simpleName=ProcessRollup2 ParentBaseFileName="fodhelper.exe"
| where FileName!="SystemSettings.exe" AND FileName!="SettingsPageHost.exe"
| stats count by aid, ContextTimeStamp, FileName, CommandLine, ParentCommandLine
```

---

### SentinelOne (Deep Visibility Query)

**Query 1: Fodhelper Registry Modification**

```sql
RegistryKeyPath CONTAINS "ms-settings\shell\open\command"
AND EventType = "Registry Value Set"
AND SrcProcName NOT IN ("fodhelper.exe", "SystemSettings.exe")
```

**Query 2: CMSTPLUMA COM Interface Abuse**

```sql
(SrcProcCmdLine CONTAINS "{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
OR SrcProcCmdLine CONTAINS "Elevation:Administrator")
AND SrcProcIntegrityLevel = "High"
AND SrcProcParentName = "DllHost.exe"
```

**Query 3: File Hash Match**

```sql
SHA256 = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
OR MD5 = "36191c81f6b9fa40dceaa4700ff86800"
```

---

## SIEM Detection Rules

### Splunk SPL

**Alert 1: Fodhelper Registry Hijacking**

```spl
index=windows (EventCode=4657 OR EventCode=13)
| eval uac_bypass_fodhelper=if(like(TargetObject, "%\\ms-settings\\shell\\open\\command%") OR like(registry_path, "%\\ms-settings\\shell\\open\\command%"), "Fodhelper Registry Hijack", null())
| where isnotnull(uac_bypass_fodhelper)
| eval severity="HIGH"
| stats count by _time, host, user, uac_bypass_fodhelper, Image, TargetObject, Details
| sort -_time
```

**Alert 2: CMSTPLUA COM Abuse**

```spl
index=windows EventCode=4688
| where ParentProcessName="*\\DllHost.exe*"
    AND (CommandLine="*{6EDD6D74-C007-4E75-B76A-E5740995E24C}*" OR ProcessIntegrityLevel="High")
| eval severity="HIGH"
| stats count by _time, host, user, ProcessName, CommandLine, ParentProcessName, ProcessIntegrityLevel
| sort -_time
```

**Alert 3: fodhelper.exe Spawning Suspicious Processes**

```spl
index=windows EventCode=4688
| where ParentProcessName="*\\fodhelper.exe"
    AND NOT (ProcessName IN ("*\\SystemSettings.exe", "*\\SettingsPageHost.exe"))
| eval severity="HIGH", description="Potential UAC bypass via fodhelper.exe"
| stats count by _time, host, user, ProcessName, CommandLine, ParentProcessName
| sort -_time
```

**Alert 4: File Hash Detection**

```spl
index=windows (EventCode=15 OR EventCode=11)
| where SHA256="18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
    OR MD5="36191c81f6b9fa40dceaa4700ff86800"
    OR SHA1="08feb675d0553f98007c52b7658a725dee22d696"
| eval severity="MEDIUM", description="uac_test.exe UAC bypass PoC detected"
| stats count by _time, host, user, FileName, FilePath, SHA256
| sort -_time
```

---

### Elastic Security (EQL)

**Rule 1: Fodhelper Registry Hijacking**

```eql
registry where
  registry.path : "*\\Software\\Classes\\ms-settings\\shell\\open\\command*"
  and not process.name : ("fodhelper.exe", "SystemSettings.exe")
```

**Rule 2: CMSTPLUA COM Abuse**

```eql
process where event.type == "start"
  and process.parent.name == "DllHost.exe"
  and (
    process.command_line : "*{6EDD6D74-C007-4E75-B76A-E5740995E24C}*"
    or process.command_line : "*Elevation:Administrator*"
  )
```

**Rule 3: fodhelper.exe Suspicious Child Process**

```eql
process where event.type == "start"
  and process.parent.name == "fodhelper.exe"
  and not process.name : ("SystemSettings.exe", "SettingsPageHost.exe")
```

---

## Network Detection

**Status**: NOT APPLICABLE

uac_test.exe is a local UAC bypass tool with **no network communication capabilities**. Network-based detection is not effective for this specific sample.

However, organizations should monitor the **distribution infrastructure**:

**Distribution IP to Block:**
- **IP Address**: `109.230.231.37`
- **Action**: Block at network perimeter (firewall, proxy, IPS)
- **Reason**: Confirmed malware distribution point serving multiple RAT variants

**Firewall Rule (Example):**
```
deny ip any host 109.230.231.37 any
deny ip host 109.230.231.37 any any
```

**IDS/IPS Signature (Snort):**
```
alert ip any any -> 109.230.231.37 any (msg:"CONNECTION to Known Malware Distribution IP 109.230.231.37"; sid:1000001; rev:1;)
alert ip 109.230.231.37 any -> any any (msg:"CONNECTION from Known Malware Distribution IP 109.230.231.37"; sid:1000002; rev:1;)
```

---

## PowerShell Detection Scripts

### Script 1: Hunt for Fodhelper Registry Keys

```powershell
# Hunt for Fodhelper UAC bypass registry keys across enterprise
# Run with administrative privileges

$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

$results = foreach ($computer in $computers) {
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        try {
            $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
            $key = Invoke-Command -ComputerName $computer -ScriptBlock {
                param($path)
                Get-Item -Path $path -ErrorAction SilentlyContinue
            } -ArgumentList $regPath

            if ($key) {
                [PSCustomObject]@{
                    ComputerName = $computer
                    RegistryKey = $regPath
                    Status = "SUSPICIOUS KEY FOUND"
                    Severity = "HIGH"
                    Timestamp = Get-Date
                }
            }
        } catch {
            # Key not found (normal)
        }
    }
}

$results | Export-Csv -Path "C:\Temp\UAC_Bypass_Hunt_Results.csv" -NoTypeInformation
$results | Where-Object { $_.Status -eq "SUSPICIOUS KEY FOUND" } | Format-Table -AutoSize
```

### Script 2: Hunt for uac_test.exe by File Hash

```powershell
# Hunt for uac_test.exe by SHA-256 hash across file systems
# Run with administrative privileges

$targetHash = "18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760"
$searchPaths = @("C:\Users", "C:\Temp", "C:\Downloads", "C:\ProgramData")

$results = foreach ($path in $searchPaths) {
    Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -eq 285184 } | # File size filter for performance
    ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if ($hash -eq $targetHash) {
            [PSCustomObject]@{
                FileName = $_.Name
                FullPath = $_.FullName
                SHA256 = $hash
                CreationTime = $_.CreationTime
                LastWriteTime = $_.LastWriteTime
                Status = "MATCH FOUND"
                Severity = "MEDIUM"
            }
        }
    }
}

$results | Export-Csv -Path "C:\Temp\UAC_Test_Hash_Hunt.csv" -NoTypeInformation
$results | Format-Table -AutoSize
```

### Script 3: Monitor for UAC Bypass Process Behavior

```powershell
# Real-time monitoring for UAC bypass process behavior
# Requires Sysmon or Event Log auditing enabled

$fodhelperEvents = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1  # Process Creation
} -MaxEvents 1000 | Where-Object {
    $_.Properties[5].Value -like "*fodhelper.exe*" -and  # Parent process
    $_.Properties[4].Value -notlike "*SystemSettings.exe*"  # Child process (exclude legitimate)
}

$cmstpluaEvents = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1
} -MaxEvents 1000 | Where-Object {
    $_.Message -like "*{6EDD6D74-C007-4E75-B76A-E5740995E24C}*" -or
    $_.Message -like "*Elevation:Administrator*"
}

Write-Host "[*] Fodhelper Suspicious Activity: $($fodhelperEvents.Count) events"
Write-Host "[*] CMSTPLUA Suspicious Activity: $($cmstpluaEvents.Count) events"

$fodhelperEvents | Format-Table TimeCreated, Message -AutoSize
$cmstpluaEvents | Format-Table TimeCreated, Message -AutoSize
```

---

## Implementation Guidance

### Deployment Priorities

**Tier 1 - Immediate Deployment (Week 1):**
1. **File Hash Blocking**: Deploy SHA-256 hash to endpoint protection (minutes to implement)
2. **Distribution IP Blocking**: Block 109.230.231.37 at network perimeter (minutes to implement)
3. **Fodhelper Registry Monitoring**: Enable Sysmon Event ID 13 for registry modifications (hours to implement)

**Tier 2 - Short-Term Deployment (Weeks 2-4):**
1. **Sigma Rule Deployment**: Implement Fodhelper and CMSTPLUA Sigma rules in SIEM (1-2 weeks with tuning)
2. **EDR Query Scheduling**: Schedule periodic hunting queries in EDR platform (1 week)
3. **PowerShell Hunting Scripts**: Deploy scheduled tasks for hash hunting (1 week)

**Tier 3 - Strategic Deployment (Months 1-3):**
1. **YARA Rule Integration**: Deploy comprehensive YARA rules to file scanning infrastructure (1 month)
2. **Behavioral Analytics**: Implement privilege escalation without UAC consent detection (2-3 months with tuning)
3. **Process Monitoring**: Enhance EDR policies for fodhelper.exe child process monitoring (1-2 months)

---

### False Positive Management

**Expected False Positive Rate:**
- **Fodhelper Registry Detection**: LOW (0-2 FPs per 10,000 events)
  - Legitimate triggers: Windows Settings application legitimate registry modifications
  - Tuning: Whitelist `SystemSettings.exe` and `SettingsPageHost.exe` as parent processes

- **CMSTPLUA COM Detection**: MEDIUM (5-10 FPs per 10,000 events)
  - Legitimate triggers: Windows Update components, certain system management tools
  - Tuning: Whitelist signed Microsoft binaries, validate digital signatures

- **File Hash Detection**: ZERO (exact hash match, no FPs expected)

**Recommended Tuning Period**: 2-4 weeks of monitoring in alert-only mode before enabling blocking actions

---

### Integration with Existing Security Stack

**SIEM Integration:**
- Import Sigma rules into SIEM platform (Splunk, Elastic, QRadar, Sentinel)
- Schedule correlation searches with 5-minute intervals
- Configure alerts to trigger SOC ticket creation (Tier 2 severity)

**EDR Integration:**
- Deploy hunting queries as scheduled tasks (hourly or daily)
- Configure automated response actions (process termination, quarantine)
- Enable behavioral blocking for UAC bypass techniques

**Endpoint Protection:**
- Add file hash to blocklist (SHA-256: `18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760`)
- Deploy YARA rules to on-access scanning engines
- Enable behavior-based detection for privilege escalation

---

### Response Playbook

**When UAC Bypass Detected:**

1. **Triage (5 minutes):**
   - Verify alert is not false positive
   - Identify affected system and user
   - Determine if execution was successful

2. **Containment (15 minutes):**
   - Isolate affected system from network
   - Terminate suspicious processes
   - Preserve forensic evidence (memory dump, event logs)

3. **Investigation (1-4 hours):**
   - Determine authorization status (authorized security testing vs. unauthorized)
   - Review user activity timeline
   - Check for additional security tools or malware
   - Interview user if appropriate

4. **Remediation (30 minutes):**
   - Delete uac_test.exe from system
   - Verify no Fodhelper registry keys exist
   - Remove prefetch artifacts (optional)
   - Document findings

5. **Post-Incident (1-7 days):**
   - If unauthorized: Enforce acceptable use policies
   - Harden UAC configurations
   - Deploy application control to prevent recurrence
   - Update detection rules based on lessons learned

---

## Testing & Validation

### Detection Rule Testing

**Test Environment Requirements:**
- Isolated Windows 10/11 VM (no network access)
- Sysmon installed and configured
- SIEM/EDR agent deployed
- Administrative privileges for testing

**Test Procedure:**

1. **Baseline Testing**:
   ```powershell
   # Verify no existing detections before test
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=13} -MaxEvents 100
   ```

2. **Positive Test (Fodhelper Registry Modification)**:
   ```powershell
   # Create Fodhelper registry key (DO NOT execute fodhelper.exe)
   New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
   Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe"

   # Verify detection triggered
   Start-Sleep -Seconds 10
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=13} -MaxEvents 10 | Where-Object { $_.Message -like "*ms-settings*" }

   # Cleanup
   Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
   ```

3. **Negative Test (Legitimate Registry Activity)**:
   ```powershell
   # Perform legitimate registry operation that should NOT trigger
   New-Item -Path "HKCU:\Software\TestKey" -Force
   Set-ItemProperty -Path "HKCU:\Software\TestKey" -Name "TestValue" -Value "Test"

   # Verify NO detection triggered
   Remove-Item -Path "HKCU:\Software\TestKey" -Force
   ```

**Expected Results:**
- Positive test: Detection alert within 30 seconds
- Negative test: No detection alert

---

## Metrics & Reporting

### Key Performance Indicators (KPIs)

**Detection Effectiveness:**
- **Mean Time to Detect (MTTD)**: Target < 5 minutes from execution to alert
- **Detection Rate**: Target > 95% for UAC bypass attempts
- **False Positive Rate**: Target < 5% of total alerts

**Response Efficiency:**
- **Mean Time to Respond (MTTR)**: Target < 30 minutes from alert to containment
- **Investigation Completion**: Target < 4 hours from alert to resolution

**Coverage Metrics:**
- **Endpoint Coverage**: % of endpoints with detection rules deployed
- **SIEM Integration**: % of enterprise logs flowing to SIEM
- **EDR Deployment**: % of endpoints with EDR agent installed

### Monthly Reporting Template

```
UAC Bypass Detection Monthly Report - [Month/Year]

Detection Summary:
- Total Alerts: [count]
- True Positives: [count] ([percentage]%)
- False Positives: [count] ([percentage]%)
- Fodhelper Attempts: [count]
- CMSTPLUA Attempts: [count]
- uac_test.exe Detections: [count]

Response Metrics:
- Mean Time to Detect: [minutes]
- Mean Time to Respond: [minutes]
- Successful Containments: [count]/[total] ([percentage]%)

Tuning Activities:
- Rules Modified: [count]
- Whitelists Added: [count]
- False Positive Reduction: [percentage]%

Recommendations:
- [List of recommended improvements]
```

---

## Additional Resources

**MITRE ATT&CK:**
- T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- https://attack.mitre.org/techniques/T1548/002/

**UAC Bypass Research:**
- UACME Project: https://github.com/hfiref0x/UACME
- Enigma0x3 Blog: https://enigma0x3.net/tag/uac-bypass/

**Microsoft Documentation:**
- User Account Control: https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/

**Detection Engineering:**
- Sigma Rules Repository: https://github.com/SigmaHQ/sigma
- YARA Rules Best Practices: https://yara.readthedocs.io/

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.