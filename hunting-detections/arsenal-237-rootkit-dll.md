---
title: Detection Rules - rootkit.dll - Kernel-Mode Rootkit
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-rootkit-dll/
hide: true
---

# Threat Hunting & Detection Rules: rootkit.dll (Defense Evasion Framework)

## Executive Summary

This detection package provides comprehensive hunting and detection capabilities for **rootkit.dll**, an advanced defense evasion framework from the Arsenal-237 malware toolkit. Despite its misleading name, this is NOT a traditional rootkit but rather a sophisticated multi-vector defense neutralization framework that combines BYOVD exploitation, process termination, file system stealth, API hooking, and PowerShell integration.

**Critical Detection Priority: URGENT**
- **Threat Level**: Critical
- **Sophistication**: High (Rust-compiled, multi-vector evasion)
- **Primary TTPs**: BYOVD (T1068), Defense Evasion (T1562.001), Process Injection (T1055.001)
- **Target Scope**: 20+ security products + analysis tools

---

## Table of Contents
1. [YARA Rules](#yara-rules)
2. [Sigma Rules](#sigma-rules)
3. [EDR Detection Queries](#edr-detection-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Threat Hunting Queries](#threat-hunting-queries)
6. [Behavioral Analytics](#behavioral-analytics)
7. [Response Playbook](#response-playbook)

---

## YARA Rules

### Rule 1: Comprehensive rootkit.dll Detection

```yara
rule Arsenal237_Rootkit_DLL_Comprehensive
{
    meta:
        description = "Detects Arsenal-237 rootkit.dll defense evasion framework"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        reference = "Arsenal-237 Malware Toolkit Analysis"
        hash_md5 = "674795d4d4ec09372904704633ea0d86"
        hash_sha1 = "483feeb4e391ae64a7d54637ea71d43a17d83c71"
        hash_sha256 = "e71240f26af1052172b5864cdddb78fcb990d7a96d53b7d22d19f5dfccdf9012"
        severity = "critical"
        mitre_attack = "T1068, T1562.001, T1055.001, T1564.001"

    strings:
        // Rust runtime signatures
        $rust_panic = "panicked at" ascii
        $rust_runtime = "std::panicking::rust_panic" ascii
        $rust_thread = "std::thread::Builder" ascii

        // Embedded Baidu driver indicators
        $baidu_driver_1 = "BdApiUtil64.sys" wide ascii
        $baidu_driver_2 = "Baidu" wide ascii nocase

        // Security product process targets (Microsoft Defender)
        $defender_1 = "MsMpEng.exe" wide ascii nocase
        $defender_2 = "MpCmdRun.exe" wide ascii nocase
        $defender_3 = "SecurityHealthService.exe" wide ascii nocase
        $defender_4 = "WdNisDrv.sys" wide ascii nocase
        $defender_5 = "WdFilter.sys" wide ascii nocase

        // CrowdStrike targets
        $crowdstrike_1 = "CSFalconService.exe" wide ascii nocase
        $crowdstrike_2 = "CSFalconContainer.exe" wide ascii nocase
        $crowdstrike_3 = "csagent.sys" wide ascii nocase

        // Third-party AV targets
        $av_eset = "ekrn.exe" wide ascii nocase
        $av_kaspersky = "avp.exe" wide ascii nocase
        $av_malwarebytes = "MBAMService.exe" wide ascii nocase
        $av_symantec = "ccSvcHst.exe" wide ascii nocase
        $av_webroot = "WRSA.exe" wide ascii nocase
        $av_sophos = "SophosHealth.exe" wide ascii nocase
        $av_cylance = "CylanceSvc.exe" wide ascii nocase
        $av_sentinel = "SentinelAgent.exe" wide ascii nocase

        // Analysis tool targets
        $analysis_1 = "procexp.exe" wide ascii nocase
        $analysis_2 = "procmon.exe" wide ascii nocase
        $analysis_3 = "Wireshark.exe" wide ascii nocase
        $analysis_4 = "x64dbg.exe" wide ascii nocase
        $analysis_5 = "volatility.exe" wide ascii nocase

        // Core defense evasion functions (hex patterns)
        $func_dispatcher = { 48 83 EC 28 48 8B ?? 48 8B ?? 48 8B ?? 48 85 ?? 74 ?? FF D? }
        $func_thread_create = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B D9 }

        // API imports for defense evasion
        $api_terminate = "ZwTerminateProcess" ascii
        $api_openprocess = "OpenProcess" ascii
        $api_createthread = "CreateThread" ascii
        $api_loaddriver = "ZwLoadDriver" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Strong Rust + BYOVD signature
            (2 of ($rust_*) and 1 of ($baidu_*)) or

            // Multiple security product targets
            (6 of ($defender_*, $crowdstrike_*, $av_*)) or

            // Analysis tool targeting
            (3 of ($analysis_*)) or

            // Function patterns + API imports
            (1 of ($func_*) and 2 of ($api_*)) or

            // Comprehensive detection: Rust + targets + functions
            (1 of ($rust_*) and 3 of ($defender_*, $crowdstrike_*, $av_*) and 1 of ($func_*))
        )
}
```

### Rule 2: BYOVD Baidu Driver Detection

```yara
rule Arsenal237_BYOVD_Baidu_Driver
{
    meta:
        description = "Detects embedded BdApiUtil64.sys driver for BYOVD attacks"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        reference = "Arsenal-237 BYOVD Technique"
        severity = "critical"
        mitre_attack = "T1068"

    strings:
        $driver_name_1 = "BdApiUtil64.sys" wide ascii
        $driver_name_2 = "BdApiUtil" wide ascii
        $baidu_company = "Baidu" wide ascii nocase
        $driver_signature = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }

        // Driver service registry paths
        $reg_service_1 = "SYSTEM\\CurrentControlSet\\Services\\BdApiUtil" wide
        $reg_service_2 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" wide

        // IOCTL codes for driver communication
        $ioctl_pattern = { 44 ?? ?? ?? ?? 00 22 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($driver_name_*) and $baidu_company) or
            ($driver_signature and 1 of ($driver_name_*)) or
            (1 of ($reg_service_*) and 1 of ($driver_name_*)) or
            ($ioctl_pattern and 1 of ($driver_name_*))
        )
}
```

### Rule 3: Security Product Mass Termination

```yara
rule Arsenal237_Security_Product_Killer
{
    meta:
        description = "Detects mass security product termination behavior"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        reference = "Arsenal-237 Defense Evasion"
        severity = "critical"
        mitre_attack = "T1562.001, T1089"

    strings:
        // Microsoft Defender complete process list
        $def_1 = "MsMpEng.exe" wide ascii nocase
        $def_2 = "MpCmdRun.exe" wide ascii nocase
        $def_3 = "NisSrv.exe" wide ascii nocase
        $def_4 = "SecurityHealthService.exe" wide ascii nocase
        $def_5 = "smartscreen.exe" wide ascii nocase
        $def_6 = "SgrmBroker.exe" wide ascii nocase
        $def_7 = "MpSigStub.exe" wide ascii nocase
        $def_8 = "wscsvc.exe" wide ascii nocase
        $def_9 = "WdNisDrv.sys" wide ascii nocase
        $def_10 = "WdFilter.sys" wide ascii nocase

        // CrowdStrike complete process list
        $cs_1 = "CSFalconService.exe" wide ascii nocase
        $cs_2 = "CSFalconContainer.exe" wide ascii nocase
        $cs_3 = "CSAgent.exe" wide ascii nocase
        $cs_4 = "csagent.sys" wide ascii nocase
        $cs_5 = "CSDeviceControl.exe" wide ascii nocase
        $cs_6 = "CSNamedPipeProxy.exe" wide ascii nocase

        // Third-party AV products
        $av_1 = "ekrn.exe" wide ascii nocase          // ESET
        $av_2 = "avp.exe" wide ascii nocase            // Kaspersky
        $av_3 = "MBAMService.exe" wide ascii nocase    // Malwarebytes
        $av_4 = "ccSvcHst.exe" wide ascii nocase       // Symantec
        $av_5 = "WRSA.exe" wide ascii nocase           // Webroot
        $av_6 = "SophosHealth.exe" wide ascii nocase   // Sophos
        $av_7 = "CylanceSvc.exe" wide ascii nocase     // Cylance
        $av_8 = "SentinelAgent.exe" wide ascii nocase  // Sentinel One

        // Termination APIs
        $api_1 = "ZwTerminateProcess" ascii
        $api_2 = "TerminateProcess" ascii
        $api_3 = "NtTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // High confidence: Multiple vendor targets
            (5 of ($def_*) and 3 of ($cs_*) and 3 of ($av_*)) or

            // Medium confidence: One vendor complete + APIs
            ((8 of ($def_*) or 4 of ($cs_*)) and 1 of ($api_*)) or

            // Broad targeting across vendors
            (3 of ($def_*) and 2 of ($cs_*) and 4 of ($av_*) and 1 of ($api_*))
        )
}
```

### Rule 4: Rust-Compiled Malware Detection

```yara
rule Arsenal237_Rust_Compiled_Malware
{
    meta:
        description = "Detects Rust-compiled malware from Arsenal-237 toolkit"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        reference = "Arsenal-237 Rust Compilation Pattern"
        severity = "high"

    strings:
        $rust_panic = "panicked at" ascii
        $rust_runtime_1 = "std::panicking::rust_panic" ascii
        $rust_runtime_2 = "std::panicking::begin_panic" ascii
        $rust_thread_1 = "std::thread::Builder" ascii
        $rust_thread_2 = "std::thread::spawn" ascii
        $rust_alloc = "alloc::alloc::Global" ascii
        $rust_vec = "alloc::vec::Vec" ascii

        // Cargo/rustc metadata
        $cargo_metadata = ".cargo" ascii
        $rustc_version = "rustc" ascii

        // Suspicious combinations
        $suspicious_1 = "OpenProcess" ascii
        $suspicious_2 = "TerminateProcess" ascii
        $suspicious_3 = "CreateRemoteThread" ascii
        $suspicious_4 = "ZwLoadDriver" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            // Rust signatures + suspicious APIs
            (3 of ($rust_*) and 2 of ($suspicious_*)) or

            // Strong Rust signature
            (5 of ($rust_*)) or

            // Cargo metadata + malicious APIs
            ($cargo_metadata and $rustc_version and 2 of ($suspicious_*))
        )
}
```

---

## Sigma Rules

### Sigma Rule 1: BdApiUtil64.sys Driver Loading

```yaml
title: Arsenal-237 BdApiUtil64.sys BYOVD Driver Loading
id: a8c9d4e1-2f3b-4c5d-8e9f-1a2b3c4d5e6f
status: experimental
description: Detects loading of BdApiUtil64.sys vulnerable driver for BYOVD attacks
references:
    - Arsenal-237 Malware Toolkit Analysis
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1068
logsource:
    product: windows
    category: driver_load
detection:
    selection_driver_name:
        ImageLoaded|contains:
            - 'BdApiUtil64.sys'
            - 'BdApiUtil.sys'
    selection_driver_hash:
        Hashes|contains:
            - 'MD5=f72386e6b0e87a3245e0d6e4e4c5a1a0'
            - 'SHA1=d8e1c6d0c1c0d6e8c9e0d6e0c1c0d6e8c9e0d6e0'
            - 'SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    selection_sysmon:
        EventID: 6
    condition: selection_sysmon and (selection_driver_name or selection_driver_hash)
falsepositives:
    - Legitimate Baidu software installations (rare in enterprise environments)
level: critical
```

### Sigma Rule 2: Mass Security Process Termination

```yaml
title: Arsenal-237 Mass Security Product Termination
id: b9d1e2f3-4a5b-6c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: Detects mass termination of security products indicating Arsenal-237 rootkit.dll activity
references:
    - Arsenal-237 Defense Evasion Framework
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1089
logsource:
    product: windows
    category: process_termination
detection:
    selection_defender:
        TargetImage|endswith:
            - '\MsMpEng.exe'
            - '\MpCmdRun.exe'
            - '\NisSrv.exe'
            - '\SecurityHealthService.exe'
    selection_crowdstrike:
        TargetImage|endswith:
            - '\CSFalconService.exe'
            - '\CSFalconContainer.exe'
            - '\CSAgent.exe'
    selection_thirdparty:
        TargetImage|endswith:
            - '\ekrn.exe'
            - '\avp.exe'
            - '\MBAMService.exe'
            - '\ccSvcHst.exe'
            - '\SophosHealth.exe'
    timeframe: 60s
    condition: (selection_defender | count(gte 3) or selection_crowdstrike | count(gte 2) or selection_thirdparty | count(gte 3)) within timeframe
falsepositives:
    - Legitimate security product updates or uninstallations
    - System administrator maintenance activities
level: critical
```

### Sigma Rule 3: rootkit.dll File System Stealth Activity

```yaml
title: Arsenal-237 rootkit.dll File System Stealth Operations
id: c1d2e3f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
description: Detects Unicode-based file hiding operations from rootkit.dll
references:
    - Arsenal-237 File System Stealth Technique
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1564.001
logsource:
    product: windows
    category: file_event
detection:
    selection_dll:
        Image|endswith: '\rootkit.dll'
    selection_operations:
        EventID:
            - 11  # File created
            - 23  # File deleted
            - 26  # File modified
    selection_unicode:
        TargetFilename|contains:
            - '\u'
            - '%u'
            - '\x'
    condition: selection_dll and selection_operations and selection_unicode
falsepositives:
    - Legitimate applications using Unicode file names
level: high
```

### Sigma Rule 4: API Hooking from DLL Context

```yaml
title: Arsenal-237 rootkit.dll API Hooking Activity
id: d2e3f4a5-6b7c-8d9e-0f1a-2b3c4d5e6f7a
status: experimental
description: Detects API hooking operations from rootkit.dll via DLL injection
references:
    - Arsenal-237 API Hooking Technique
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055.001
logsource:
    product: windows
    category: process_access
detection:
    selection_source:
        SourceImage|endswith: '\rootkit.dll'
    selection_target_security:
        TargetImage|endswith:
            - '\MsMpEng.exe'
            - '\CSFalconService.exe'
            - '\ekrn.exe'
            - '\avp.exe'
    selection_access:
        GrantedAccess:
            - '0x1F0FFF'  # PROCESS_ALL_ACCESS
            - '0x1FFFFF'  # PROCESS_ALL_ACCESS alternate
            - '0x1010'    # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    selection_sysmon:
        EventID: 10
    condition: selection_sysmon and selection_source and selection_target_security and selection_access
falsepositives:
    - Security software cross-process monitoring
    - Legitimate debugging activities
level: critical
```

### Sigma Rule 5: PowerShell Execution from DLL

```yaml
title: Arsenal-237 rootkit.dll PowerShell Integration
id: e3f4a5b6-7c8d-9e0f-1a2b-3c4d5e6f7a8b
status: experimental
description: Detects PowerShell execution initiated from rootkit.dll context
references:
    - Arsenal-237 PowerShell Integration
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_parent:
        ParentCommandLine|contains: 'rootkit.dll'
    selection_suspicious:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-w hidden'
            - '-WindowStyle Hidden'
            - 'bypass'
    condition: selection_powershell and (selection_parent or selection_suspicious)
falsepositives:
    - Legitimate PowerShell scripts executed by system processes
level: high
```

---

## EDR Detection Queries

### CrowdStrike Falcon Query

```kusto
// Arsenal-237 rootkit.dll BYOVD and Defense Evasion Detection
event_simpleName IN ("DriverLoad", "ProcessRollup2", "ProcessTerminate")
| where (
    // BYOVD driver loading
    (event_simpleName="DriverLoad" AND ImageFileName CONTAINS "BdApiUtil64.sys") OR

    // Mass security process termination
    (event_simpleName="ProcessTerminate" AND
     FileName IN ("MsMpEng.exe", "CSFalconService.exe", "CSAgent.exe", "ekrn.exe",
                  "avp.exe", "MBAMService.exe", "ccSvcHst.exe", "SophosHealth.exe",
                  "CylanceSvc.exe", "SentinelAgent.exe")) OR

    // rootkit.dll process creation or loading
    (event_simpleName="ProcessRollup2" AND
     (CommandLine CONTAINS "rootkit.dll" OR ImageFileName CONTAINS "rootkit.dll"))
)
| stats count() by event_simpleName, aid, ComputerName, UserName, FileName, ImageFileName
| where count > 3  // Multiple terminations within query timeframe
| sort -count
```

### Microsoft Defender for Endpoint (Advanced Hunting)

```kusto
// Arsenal-237 rootkit.dll Multi-Vector Detection
union
(
    // BYOVD driver loading
    DeviceEvents
    | where ActionType == "DriverLoad"
    | where FileName =~ "BdApiUtil64.sys" or InitiatingProcessFileName =~ "BdApiUtil64.sys"
    | project Timestamp, DeviceName, ActionType, FileName, SHA256, InitiatingProcessFileName
),
(
    // Mass security product termination
    DeviceProcessEvents
    | where ActionType == "ProcessTerminated"
    | where FileName in~ ("MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe",
                          "CSFalconService.exe", "CSAgent.exe", "ekrn.exe", "avp.exe",
                          "MBAMService.exe", "SophosHealth.exe", "CylanceSvc.exe")
    | summarize TerminatedProcesses=make_set(FileName), TerminationCount=count()
      by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
    | where TerminationCount >= 3
),
(
    // rootkit.dll file operations
    DeviceFileEvents
    | where FileName =~ "rootkit.dll" or InitiatingProcessFileName =~ "rootkit.dll"
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256
),
(
    // API hooking indicators
    DeviceEvents
    | where ActionType == "CreateRemoteThreadApiCall"
    | where InitiatingProcessFileName contains "rootkit.dll"
    | project Timestamp, DeviceName, ActionType, TargetProcessName, InitiatingProcessFileName
)
| sort by Timestamp desc
```

### Elastic Security (EQL Query)

```eql
// Arsenal-237 rootkit.dll Detection Sequence
sequence by host.id with maxspan=5m
[
  // Step 1: Driver loading
  driver where driver.name == "BdApiUtil64.sys" or
               file.name == "BdApiUtil64.sys"
]
[
  // Step 2: Security process termination
  process where event.action == "termination" and
                process.name in ("MsMpEng.exe", "CSFalconService.exe", "ekrn.exe",
                                 "avp.exe", "MBAMService.exe", "SophosHealth.exe")
]
[
  // Step 3: File hiding or API hooking
  any where (
    (file.name contains "rootkit.dll" and event.action in ("creation", "modification")) or
    (process.thread.Ext.start_address_module contains "rootkit.dll")
  )
]
```

### Splunk SPL Query

```spl
(index=windows sourcetype=WinEventLog:Sysmon)
(
    (EventCode=6 ImageLoaded="*BdApiUtil64.sys*") OR
    (EventCode=1 Image="*rootkit.dll*" OR CommandLine="*rootkit.dll*") OR
    (EventCode=8 SourceImage="*rootkit.dll*" TargetImage IN ("*MsMpEng.exe*", "*CSFalconService.exe*", "*ekrn.exe*", "*avp.exe*")) OR
    (EventCode=10 SourceImage="*rootkit.dll*" GrantedAccess IN ("0x1F0FFF", "0x1FFFFF", "0x1010")) OR
    (EventCode=11 Image="*rootkit.dll*" TargetFilename="*\\u*")
)
| stats count by EventCode, Computer, Image, TargetImage, ImageLoaded, User
| where count > 2
| sort -count
```

---

## SIEM Detection Rules

### Microsoft Sentinel (KQL)

```kusto
// Arsenal-237 rootkit.dll Comprehensive Detection
let BYOVDDriverLoad =
    DeviceEvents
    | where ActionType == "DriverLoad"
    | where FileName has "BdApiUtil64.sys"
    | project TimeGenerated, DeviceName, ActionType, FileName, SHA256;
let SecurityProcessTermination =
    DeviceProcessEvents
    | where ActionType == "ProcessTerminated"
    | where FileName in~ ("MsMpEng.exe", "CSFalconService.exe", "ekrn.exe", "avp.exe",
                          "MBAMService.exe", "SophosHealth.exe", "CylanceSvc.exe", "SentinelAgent.exe")
    | summarize TerminatedProcesses=make_list(FileName), Count=count()
      by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 1m)
    | where Count >= 3;
let RootkitDLLActivity =
    DeviceFileEvents
    | where FileName == "rootkit.dll" or InitiatingProcessFileName == "rootkit.dll"
    | project TimeGenerated, DeviceName, ActionType, FolderPath, FileName;
let APIHooking =
    DeviceEvents
    | where ActionType == "CreateRemoteThreadApiCall"
    | where InitiatingProcessFileName contains "rootkit.dll"
    | project TimeGenerated, DeviceName, TargetProcessName, InitiatingProcessFileName;
union BYOVDDriverLoad, SecurityProcessTermination, RootkitDLLActivity, APIHooking
| summarize DetectionEvents=make_set(ActionType), TotalDetections=count()
  by DeviceName, bin(TimeGenerated, 5m)
| where TotalDetections >= 2
| extend Severity = case(
    TotalDetections >= 4, "Critical",
    TotalDetections >= 3, "High",
    "Medium"
)
| project TimeGenerated, DeviceName, DetectionEvents, TotalDetections, Severity
| sort by TimeGenerated desc
```

### Splunk Enterprise Security

```spl
index=windows (sourcetype=WinEventLog:Sysmon OR sourcetype=WinEventLog:Security)
(
    (EventCode=6 ImageLoaded="*BdApiUtil64.sys*") OR
    (EventCode=1 (Image="*rootkit.dll*" OR CommandLine="*rootkit.dll*")) OR
    (EventCode=8 SourceImage="*rootkit.dll*") OR
    (EventCode=10 SourceImage="*rootkit.dll*" GrantedAccess IN ("0x1F0FFF", "0x1FFFFF")) OR
    (EventCode=4688 NewProcessName IN ("*MsMpEng.exe*", "*CSFalconService.exe*", "*ekrn.exe*"))
)
| eval detection_type=case(
    EventCode=6, "BYOVD_DriverLoad",
    EventCode=1, "Rootkit_ProcessCreation",
    EventCode=8, "RemoteThread_Injection",
    EventCode=10, "ProcessAccess_Hooking",
    EventCode=4688, "SecurityProcess_Activity",
    1=1, "Unknown"
)
| stats count by detection_type, Computer, User, _time
| where count > 2
| eval risk_score=case(
    detection_type="BYOVD_DriverLoad", 100,
    detection_type="RemoteThread_Injection", 95,
    detection_type="ProcessAccess_Hooking", 90,
    detection_type="SecurityProcess_Activity", 85,
    detection_type="Rootkit_ProcessCreation", 95,
    1=1, 50
)
| where risk_score >= 85
| sort -risk_score, -count
| table _time, Computer, User, detection_type, count, risk_score
```

### IBM QRadar

```sql
SELECT
    DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') as EventTime,
    LOGSOURCENAME(logsourceid) as LogSource,
    sourceip,
    destinationip,
    username,
    QIDNAME(qid) as EventName,
    UTF8(payload) as EventDetails
FROM events
WHERE
    (
        -- BYOVD driver loading
        (QIDNAME(qid) ILIKE '%driver%load%' AND UTF8(payload) ILIKE '%BdApiUtil64.sys%') OR

        -- rootkit.dll activity
        (UTF8(payload) ILIKE '%rootkit.dll%') OR

        -- Mass process termination
        (QIDNAME(qid) ILIKE '%process%terminate%' AND
         UTF8(payload) ILIKE ANY ('%MsMpEng.exe%', '%CSFalconService.exe%', '%ekrn.exe%',
                                   '%avp.exe%', '%MBAMService.exe%', '%SophosHealth.exe%')) OR

        -- API hooking indicators
        (QIDNAME(qid) ILIKE '%thread%create%' AND UTF8(payload) ILIKE '%rootkit.dll%')
    )
    AND starttime > CURRENT_TIMESTAMP - 24 HOURS
ORDER BY starttime DESC
```

---

## Threat Hunting Queries

### Hunt 1: BYOVD Driver Deployment Timeline

**Objective**: Identify complete BYOVD attack chain from driver drop to exploitation

```kusto
// Microsoft Defender Advanced Hunting
DeviceFileEvents
| where FileName =~ "BdApiUtil64.sys"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, InitiatingProcessFileName
| join kind=inner (
    DeviceEvents
    | where ActionType == "DriverLoad"
    | where FileName =~ "BdApiUtil64.sys"
) on DeviceName
| join kind=inner (
    DeviceProcessEvents
    | where ActionType == "ProcessTerminated"
    | where FileName in~ ("MsMpEng.exe", "CSFalconService.exe", "ekrn.exe")
) on DeviceName
| project Timestamp, DeviceName, AttackPhase=strcat("File Drop -> Driver Load -> Process Kill"),
          InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

### Hunt 2: Rust-Compiled Malware Discovery

**Objective**: Identify other potential Rust-compiled components from Arsenal-237

```kusto
// Search for Rust runtime signatures in executables
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith ".exe" or FileName endswith ".dll"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine contains "rust" or InitiatingProcessCommandLine contains "std::panicking"
) on DeviceName, FileName
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
| distinct DeviceName, FileName, SHA256
```

### Hunt 3: Security Product Tampering Timeline

**Objective**: Map complete security neutralization sequence

```kusto
// Track security process terminations in temporal sequence
DeviceProcessEvents
| where ActionType == "ProcessTerminated"
| where FileName in~ ("MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe",
                      "CSFalconService.exe", "CSAgent.exe", "ekrn.exe", "avp.exe",
                      "MBAMService.exe", "SophosHealth.exe", "CylanceSvc.exe", "SentinelAgent.exe")
| summarize TerminationEvents=make_list(FileName), FirstTermination=min(Timestamp),
            LastTermination=max(Timestamp), TerminationCount=count()
  by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
| where TerminationCount >= 3
| extend AttackDuration = datetime_diff('second', LastTermination, FirstTermination)
| project DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, TerminationEvents,
          TerminationCount, FirstTermination, LastTermination, AttackDuration
| sort by TerminationCount desc, AttackDuration asc
```

### Hunt 4: File System Stealth Activity

**Objective**: Detect Unicode-based file hiding operations

```kusto
// Identify suspicious Unicode file operations
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed", "FileDeleted")
| where FolderPath contains "\\u" or FolderPath contains "%u" or FileName contains "\\x"
| where InitiatingProcessFileName contains "rootkit.dll" or ProcessVersionInfoOriginalFileName contains "rootkit"
| summarize FileOperations=make_set(ActionType), AffectedFiles=make_set(FileName), Count=count()
  by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, 1h)
| where Count >= 5
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256,
          FileOperations, AffectedFiles, Count
| sort by Count desc
```

### Hunt 5: PowerShell Integration Analysis

**Objective**: Identify PowerShell scripts executed via rootkit.dll

```kusto
// Track PowerShell execution from DLL context
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-EncodedCommand"
        or ProcessCommandLine contains "bypass"
| where InitiatingProcessCommandLine contains "rootkit.dll"
        or InitiatingProcessFileName contains "rootkit"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
| extend DecodedCommand = base64_decode_tostring(extract(@"-enc(?:odedCommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine))
| project Timestamp, DeviceName, ProcessCommandLine, DecodedCommand, InitiatingProcessFileName, AccountName
| sort by Timestamp desc
```

---

## Behavioral Analytics

### Analytic 1: BYOVD Attack Pattern

**Detection Logic:**
```
IF driver_load.driver_name == "BdApiUtil64.sys"
   AND file_event.action == "created"
   AND file_event.file_name == "BdApiUtil64.sys"
   WITHIN 60 seconds
THEN
   ALERT "Arsenal-237 BYOVD Attack Chain Detected"
   SEVERITY: Critical
   CONFIDENCE: High
```

**Implementation (Pseudo-code):**
```python
# Behavioral analytic for BYOVD detection
def detect_byovd_chain(events):
    driver_loads = [e for e in events if e.action == "driver_load" and "BdApiUtil64" in e.driver_name]
    file_creates = [e for e in events if e.action == "file_created" and "BdApiUtil64" in e.file_name]

    for driver_load in driver_loads:
        for file_create in file_creates:
            time_delta = (driver_load.timestamp - file_create.timestamp).total_seconds()
            if 0 <= time_delta <= 60:
                return {
                    "alert": "Arsenal-237 BYOVD Attack Chain",
                    "severity": "Critical",
                    "confidence": "High",
                    "device": driver_load.device_name,
                    "timestamp": driver_load.timestamp,
                    "indicators": {
                        "file_drop": file_create.file_path,
                        "driver_load": driver_load.driver_name,
                        "initiating_process": driver_load.initiating_process
                    }
                }
    return None
```

### Analytic 2: Mass Security Product Termination

**Detection Logic:**
```
IF process_termination.target IN (security_products)
   AND COUNT(DISTINCT process_termination.target) >= 3
   WITHIN 120 seconds
THEN
   ALERT "Arsenal-237 Defense Evasion - Mass Termination"
   SEVERITY: Critical
   CONFIDENCE: High
```

**Security Products List:**
```python
SECURITY_PRODUCTS = [
    "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe",  # Microsoft Defender
    "CSFalconService.exe", "CSAgent.exe", "CSFalconContainer.exe",              # CrowdStrike
    "ekrn.exe", "avp.exe", "MBAMService.exe", "ccSvcHst.exe", "WRSA.exe",      # Third-party AV
    "SophosHealth.exe", "CylanceSvc.exe", "SentinelAgent.exe"
]

def detect_mass_termination(events, timeframe=120):
    terminations = [e for e in events if e.action == "process_terminated"
                    and e.target_process in SECURITY_PRODUCTS]

    # Group by device and time window
    from collections import defaultdict
    device_terminations = defaultdict(list)

    for term in terminations:
        device_terminations[term.device_name].append(term)

    alerts = []
    for device, terms in device_terminations.items():
        # Sort by timestamp
        terms.sort(key=lambda x: x.timestamp)

        # Sliding window detection
        for i, start_term in enumerate(terms):
            window_terms = [t for t in terms[i:]
                           if (t.timestamp - start_term.timestamp).total_seconds() <= timeframe]

            unique_targets = set(t.target_process for t in window_terms)

            if len(unique_targets) >= 3:
                alerts.append({
                    "alert": "Arsenal-237 Defense Evasion - Mass Termination",
                    "severity": "Critical",
                    "confidence": "High",
                    "device": device,
                    "timestamp": start_term.timestamp,
                    "terminated_products": list(unique_targets),
                    "termination_count": len(window_terms),
                    "initiating_process": start_term.initiating_process
                })
                break

    return alerts
```

### Analytic 3: File System Stealth + API Hooking Correlation

**Detection Logic:**
```
IF (file_event.action IN ("created", "modified") AND file_event.unicode_indicator == TRUE)
   AND (process_access.granted_access IN ("0x1F0FFF", "0x1FFFFF")
        AND process_access.target IN security_products)
   WITHIN 300 seconds
   AND source.process == "rootkit.dll"
THEN
   ALERT "Arsenal-237 Multi-Vector Defense Evasion"
   SEVERITY: Critical
   CONFIDENCE: High
```

---

## Response Playbook

### Phase 1: Initial Detection and Containment (0-15 minutes)

**Immediate Actions:**

1. **Isolate Affected Systems**
   ```powershell
   # Disable network adapters via EDR or manual command
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false
   ```

2. **Block File Hashes at Network Perimeter**
   - MD5: `674795d4d4ec09372904704633ea0d86`
   - SHA1: `483feeb4e391ae64a7d54637ea71d43a17d83c71`
   - SHA256: `e71240f26af1052172b5864cdddb78fcb990d7a96d53b7d22d19f5dfccdf9012`
   - BdApiUtil64.sys hashes (see IOC JSON)

3. **Terminate rootkit.dll Process**
   ```powershell
   # Identify and kill rootkit.dll process
   Get-Process | Where-Object {$_.Modules.ModuleName -contains "rootkit.dll"} | Stop-Process -Force
   ```

4. **Unload BdApiUtil64.sys Driver**
   ```powershell
   # Stop and unload vulnerable driver
   sc.exe stop BdApiUtil64
   sc.exe delete BdApiUtil64
   ```

### Phase 2: Evidence Collection (15-60 minutes)

**Forensic Artifacts to Collect:**

1. **Memory Dump**
   ```powershell
   # Using WinPmem or similar
   winpmem_mini_x64.exe memory.dmp
   ```

2. **Process List and Modules**
   ```powershell
   Get-Process | Select-Object Name, Id, Path, Modules | Export-Csv processes.csv
   ```

3. **Driver List**
   ```powershell
   driverquery /v /fo csv > drivers.csv
   Get-WindowsDriver -Online | Export-Csv installed_drivers.csv
   ```

4. **Event Logs**
   ```powershell
   # Export Sysmon logs
   wevtutil epl Microsoft-Windows-Sysmon/Operational sysmon.evtx

   # Export Security logs
   wevtutil epl Security security.evtx

   # Export System logs
   wevtutil epl System system.evtx
   ```

5. **File System Artifacts**
   ```powershell
   # Search for rootkit.dll and BdApiUtil64.sys
   Get-ChildItem -Path C:\ -Recurse -Filter "rootkit.dll" -ErrorAction SilentlyContinue |
       Select-Object FullName, Length, CreationTime, LastWriteTime | Export-Csv rootkit_locations.csv

   Get-ChildItem -Path C:\ -Recurse -Filter "BdApiUtil64.sys" -ErrorAction SilentlyContinue |
       Select-Object FullName, Length, CreationTime, LastWriteTime | Export-Csv driver_locations.csv
   ```

6. **Registry Export**
   ```powershell
   # Export service keys
   reg export "HKLM\SYSTEM\CurrentControlSet\Services" services.reg

   # Export Windows Defender keys
   reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" defender.reg
   ```

### Phase 3: Eradication (1-4 hours)

**Removal Steps:**

1. **Delete rootkit.dll Files**
   ```powershell
   # Remove all instances
   Get-ChildItem -Path C:\ -Recurse -Filter "rootkit.dll" -ErrorAction SilentlyContinue |
       Remove-Item -Force
   ```

2. **Remove BdApiUtil64.sys Driver**
   ```powershell
   # Delete driver files
   Remove-Item "C:\Windows\System32\drivers\BdApiUtil64.sys" -Force -ErrorAction SilentlyContinue
   Remove-Item "$env:TEMP\BdApiUtil64.sys" -Force -ErrorAction SilentlyContinue
   ```

3. **Clean Registry Persistence**
   ```powershell
   # Remove malicious services
   sc.exe delete BdApiUtil64

   # Restore Windows Defender settings
   Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
   ```

4. **Restore Security Products**
   ```powershell
   # Restart security services
   Start-Service -Name WinDefend
   Start-Service -Name SecurityHealthService
   Start-Service -Name Sense  # Microsoft Defender for Endpoint
   ```

### Phase 4: Recovery and Validation (4-24 hours)

**Validation Checks:**

1. **Verify Driver Removal**
   ```powershell
   Get-WindowsDriver -Online | Where-Object {$_.DriverSignature -like "*Baidu*"}
   driverquery | findstr /i "BdApiUtil"
   ```

2. **Confirm Security Product Operation**
   ```powershell
   # Check Defender status
   Get-MpComputerStatus

   # Verify services running
   Get-Service | Where-Object {$_.Name -in @("WinDefend", "SecurityHealthService", "Sense")} |
       Select-Object Name, Status, StartType
   ```

3. **Run Full Security Scan**
   ```powershell
   # Microsoft Defender full scan
   Start-MpScan -ScanType FullScan

   # Update definitions first
   Update-MpSignature
   ```

4. **Check for Additional Artifacts**
   ```powershell
   # Search for Arsenal-237 related files
   $arsenal_keywords = @("killer.dll", "lpe.exe", "chisel", "nethost", "chromelevator")
   foreach ($keyword in $arsenal_keywords) {
       Get-ChildItem -Path C:\ -Recurse -Filter "*$keyword*" -ErrorAction SilentlyContinue
   }
   ```

### Phase 5: Post-Incident Actions

**Recommendations:**

1. **Deploy Detection Rules**
   - Implement all YARA rules in endpoint protection
   - Configure Sigma rules in SIEM
   - Enable EDR behavioral analytics

2. **Harden Systems**
   ```powershell
   # Block vulnerable driver loading
   # Add to HVCI driver blocklist or use Windows Defender Application Control
   ```

3. **Network Segmentation Review**
   - Isolate critical systems
   - Implement micro-segmentation
   - Review firewall rules

4. **Threat Hunting**
   - Search for additional Arsenal-237 components
   - Review historical logs for missed detections
   - Hunt for lateral movement indicators

5. **Update Incident Response Plan**
   - Document lessons learned
   - Update runbooks with Arsenal-237 specifics
   - Conduct tabletop exercise

---

## Detection Effectiveness Matrix

| Detection Method | Coverage | False Positive Rate | Detection Speed | Confidence |
|-----------------|----------|-------------------|----------------|------------|
| YARA - File Hash | High | Very Low | Immediate | Very High |
| YARA - Behavioral | High | Low | Immediate | High |
| Sigma - Driver Load | High | Low | Near Real-time | Very High |
| Sigma - Process Termination | Medium | Medium | Near Real-time | High |
| EDR - BYOVD Chain | High | Very Low | Real-time | Very High |
| EDR - API Hooking | Medium | Medium | Real-time | Medium |
| SIEM - Correlation | High | Low | 1-5 minutes | High |
| Behavioral Analytics | Very High | Low | Real-time | High |

---

## Deployment Priority

**Critical (Deploy Immediately):**
1. YARA Rule: Arsenal237_Rootkit_DLL_Comprehensive
2. YARA Rule: Arsenal237_BYOVD_Baidu_Driver
3. Sigma Rule: BdApiUtil64.sys Driver Loading
4. Sigma Rule: Mass Security Process Termination
5. EDR Query: BYOVD and Defense Evasion Detection

**High (Deploy Within 24 Hours):**
1. YARA Rule: Arsenal237_Security_Product_Killer
2. Sigma Rule: File System Stealth Activity
3. Sigma Rule: API Hooking Detection
4. SIEM Rules: All correlation rules
5. Behavioral Analytic 1: BYOVD Attack Pattern
6. Behavioral Analytic 2: Mass Termination

**Medium (Deploy Within 72 Hours):**
1. YARA Rule: Arsenal237_Rust_Compiled_Malware
2. Sigma Rule: PowerShell Integration
3. All threat hunting queries
4. Behavioral Analytic 3: Multi-Vector Correlation

---

## Testing and Validation

**Safe Testing Methodology:**

1. **YARA Rule Testing**
   ```bash
   # Test against known sample (isolated environment only)
   yara -r arsenal237_rules.yar /path/to/samples/
   ```

2. **Sigma Rule Validation**
   ```bash
   # Convert Sigma rules to target SIEM format
   sigmac -t splunk arsenal237_sigma_rules.yml
   sigmac -t elastalert arsenal237_sigma_rules.yml
   ```

3. **EDR Query Testing**
   - Run queries against historical data first
   - Validate detection accuracy with known benign processes
   - Tune thresholds based on false positive rate

4. **SIEM Correlation Testing**
   - Test with synthetic events before production deployment
   - Validate alert routing and escalation paths
   - Confirm integration with SOAR platforms

---

## Contact and Support

**For Implementation Assistance:**
- Security Operations Center (SOC)
- Threat Intelligence Team
- Incident Response Team

**For False Positive Tuning:**
- Submit feedback with context and evidence
- Include environment details (OS version, security stack)
- Provide sample logs for analysis

---

**Document Version**: 1.0
**Last Updated**: 2026-01-26
**Next Review**: 2026-02-26 or upon new Arsenal-237 variant discovery
