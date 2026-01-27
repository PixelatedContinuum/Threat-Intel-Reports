---
title: Detection Rules - killer.dll (BYOVD Defense Evasion)
date: '2026-01-25'
layout: post
permalink: /hunting-detections/killer-dll/
hide: true
---

# Detection Rules - killer.dll (BYOVD Defense Evasion)

## Overview
Comprehensive detection coverage for killer.dll focuses on BYOVD (Bring Your Own Vulnerable Driver) technique indicators, kernel driver service lifecycle anomalies, IOCTL abuse patterns, and mass security product termination behaviors. Rules are provided in YARA, Sigma, and EDR query formats for immediate deployment.

**Malware Family**: Arsenal-237 BYOVD Defense Evasion Module
**Severity**: CRITICAL
**Attack Chain**: lpe.exe (privilege escalation) -> killer.dll (defense evasion) -> ransomware deployment
**Last Updated**: 2026-01-25

---

## Table of Contents

1. [YARA Rules](#yara-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Network Detection](#network-detection)
6. [Implementation Guidance](#implementation-guidance)
7. [Testing & Validation](#testing--validation)
8. [Maintenance & Updates](#maintenance--updates)

---

## YARA Rules

### Rule 1: killer.dll Comprehensive Detection

```yaml
rule Killer_DLL_BYOVD_Comprehensive {
    meta:
        description = "Detects killer.dll BYOVD defense evasion module based on embedded drivers, configuration table, and behavioral indicators"
        author = "Threat Intelligence Team"
        date = "2026-01-25"
        severity = "CRITICAL"
        malware_family = "Arsenal-237 BYOVD Defense Evasion"
        hash_killerdll = "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
        reference = "Arsenal-237 Open Directory 109.230.231.37 Investigation"
        mitre_attack = "T1562.001, T1068, T1027.009, T1622"

    strings:
        // File hash identifier
        $hash = "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d" nocase

        // Embedded driver signatures (PE headers)
        $mz_header = "MZ" ascii
        $pe_dos_stub = "This program cannot be run in DOS mode" ascii

        // Baidu driver metadata
        $baidu_driver1 = "BdApiUtil64.sys" ascii wide nocase
        $baidu_driver2 = "Baidu Antivirus BdApi Driver" ascii wide
        $baidu_company = "Baidu, Inc." ascii wide
        $baidu_device = "\\\\.\\BdApiUtil" ascii wide

        // Process Explorer driver metadata
        $procexp_driver1 = "ProcExpDriver.sys" ascii wide nocase
        $procexp_driver2 = "PROCEXP152" ascii wide
        $procexp_company = "Sysinternals - www.sysinternals.com" ascii wide
        $procexp_device = "\\\\.\\PROCEXP152" ascii wide

        // IOCTL codes (hex representations)
        $ioctl_baidu = {B4 24 00 80}    // 0x800024B4 (little-endian)
        $ioctl_procexp = {3C 00 35 83}  // 0x8335003C (little-endian)

        // Target security products
        $target1 = "MsMpEng.exe" ascii wide nocase
        $target2 = "ekrn.exe" ascii wide nocase
        $target3 = "avp.exe" ascii wide nocase
        $target4 = "MBAMService.exe" ascii wide nocase
        $target5 = "bdservicehost.exe" ascii wide nocase

        // Service manipulation strings
        $svc1 = "CreateServiceW" ascii wide
        $svc2 = "StartServiceW" ascii wide
        $svc3 = "DeleteService" ascii wide
        $svc4 = "NtUnloadDriver" ascii wide

        // Rust compilation artifacts
        $rust1 = "rustc" ascii
        $rust2 = "cargo" ascii
        $rust3 = "/rustc/" ascii

        // C2 infrastructure
        $c2_url = "http://109.230.231.37:8888/lpe.exe" ascii wide
        $c2_ip = "109.230.231.37" ascii wide

        // Export function (masquerading)
        $export_func = "get_hostfxr_path" ascii

        // Dynamic driver naming pattern
        $driver_charset = "abcdefghijklmnopqrstuvwxyz.sys" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file signature
        (
            $hash or // Known file hash match
            (
                // Embedded driver detection
                (#mz_header >= 2) and // Multiple PE headers (embedded drivers)
                (2 of ($baidu_*)) and
                (2 of ($procexp_*)) and
                (1 of ($ioctl_*))
            ) or
            (
                // Behavioral pattern detection
                (3 of ($target*)) and // Security product targets
                (2 of ($svc*)) and // Service manipulation
                (1 of ($ioctl_*)) and // IOCTL codes
                (1 of ($baidu_* or $procexp_*)) // Driver references
            ) or
            (
                // Configuration and infrastructure
                ($c2_url or $c2_ip) and
                ($export_func) and
                (1 of ($rust*)) and
                (2 of ($target*))
            )
        )
}
```

### Rule 2: Embedded Vulnerable Driver Detection

```yaml
rule Embedded_Vulnerable_Driver_BdApi_ProcExp {
    meta:
        description = "Detects embedded BdApiUtil64.sys or ProcExpDriver.sys within files (BYOVD indicator)"
        author = "Threat Intelligence Team"
        date = "2026-01-25"
        severity = "HIGH"
        technique = "BYOVD - Bring Your Own Vulnerable Driver"

    strings:
        // Baidu driver full path and metadata
        $baidu_full1 = "\\SystemRoot\\System32\\Drivers\\BdApiUtil64.sys" ascii wide nocase
        $baidu_full2 = "Baidu Antivirus BdApi Driver" ascii wide
        $baidu_version = "5.0.3.84333" ascii wide

        // Process Explorer driver full path and metadata
        $procexp_full1 = "\\SystemRoot\\System32\\Drivers\\PROCEXP152.SYS" ascii wide nocase
        $procexp_full2 = "Process Explorer" ascii wide
        $procexp_version = "17.0.7" ascii wide

        // Device symbolic links
        $device_baidu = "\\\\.\\BdApiUtil" ascii wide
        $device_procexp = "\\\\.\\PROCEXP152" ascii wide

        // PE headers indicating embedded drivers
        $mz = "MZ"
        $pe = "PE\x00\x00"

    condition:
        // File contains embedded PE files AND driver metadata
        #mz >= 2 and
        (
            (2 of ($baidu_*)) or
            (2 of ($procexp_*)) or
            (1 of ($device_*) and #mz >= 2)
        )
}
```

### Rule 3: BYOVD Service Creation Pattern

```yaml
rule BYOVD_Service_Creation_Memory {
    meta:
        description = "Detects BYOVD service creation patterns in memory (process hollowing, DLL injection)"
        author = "Threat Intelligence Team"
        date = "2026-01-25"
        severity = "MEDIUM"
        use_case = "Memory scanning, process inspection"

    strings:
        // Service creation API sequence
        $api1 = "OpenSCManagerW" ascii wide
        $api2 = "CreateServiceW" ascii wide
        $api3 = "StartServiceW" ascii wide
        $api4 = "ControlService" ascii wide
        $api5 = "DeleteService" ascii wide

        // Kernel driver type identifier
        $kernel_driver = "SERVICE_KERNEL_DRIVER" ascii wide
        $driver_ext = ".sys" ascii wide nocase

        // Temporary directory paths (common for BYOVD)
        $temp1 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $temp2 = "\\Windows\\Temp\\" ascii wide nocase
        $temp3 = "C:\\Temp\\" ascii wide nocase

    condition:
        3 of ($api*) and
        ($kernel_driver or $driver_ext) and
        1 of ($temp*)
}
```

---

## Sigma Detection Rules

### Rule 1: Kernel Driver Service Creation by Rundll32

```yaml
title: Suspicious Kernel Driver Service Creation by Rundll32
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb0
status: experimental
description: Detects kernel driver service creation by rundll32.exe (BYOVD attack pattern for killer.dll)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer.dll analysis report
    - Arsenal-237 malware toolkit investigation
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.privilege_escalation
    - attack.t1068
logsource:
    product: windows
    category: registry_set
    service: sysmon
detection:
    selection_service_create:
        EventID: 13  # Registry value set (Sysmon)
        TargetObject|contains: '\System\CurrentControlSet\Services\'
        Details|contains: 'SERVICE_KERNEL_DRIVER'
    selection_parent:
        Image|endswith: '\rundll32.exe'
    filter_legitimate:
        # Exclude legitimate Microsoft-signed rundll32 operations
        Signature: 'Microsoft Corporation'
        TargetObject|contains: '\System32\Drivers\'
    condition: selection_service_create and selection_parent and not filter_legitimate
falsepositives:
    - Legitimate software installation via rundll32 (extremely rare for kernel drivers)
    - Administrative scripts using rundll32 for driver deployment (should be reviewed)
level: critical
```

### Rule 2: Mass Security Product Process Termination

```yaml
title: Mass Security Product Process Termination (BYOVD Attack)
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb1
status: experimental
description: Detects simultaneous termination of multiple security products (killer.dll behavior)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer.dll analysis report
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: process_termination
detection:
    selection:
        Image|endswith:
            - '\MsMpEng.exe'
            - '\ekrn.exe'
            - '\avp.exe'
            - '\MBAMService.exe'
            - '\bdservicehost.exe'
            - '\avguard.exe'
            - '\NisSrv.exe'
            - '\vsserv.exe'
    timeframe: 60s
    condition: selection | count(Image) >= 3
falsepositives:
    - Administrator manually stopping multiple security services (should be investigated)
    - Software conflicts causing cascading failures (rare)
level: critical
```

### Rule 3: DeviceIoControl with Malicious IOCTL Codes

```yaml
title: DeviceIoControl Abuse with BYOVD IOCTL Codes
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb2
status: experimental
description: Detects DeviceIoControl calls with IOCTL codes used by killer.dll (0x800024B4, 0x8335003C)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer.dll analysis report
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.privilege_escalation
    - attack.t1068
logsource:
    product: windows
    category: driver_load
    service: etwti  # ETW Threat Intelligence or EDR telemetry
detection:
    selection_ioctl:
        EventID: 1  # API call monitoring (requires ETW or EDR)
        CallStack|contains: 'DeviceIoControl'
        ControlCode:
            - '0x800024B4'  # Baidu driver process termination
            - '0x8335003C'  # Process Explorer driver process termination
    selection_device:
        DevicePath:
            - '\\\\.\\BdApiUtil'
            - '\\\\.\\PROCEXP152'
    condition: selection_ioctl or selection_device
falsepositives:
    - Legitimate use of Sysinternals Process Explorer (if version 17.0.7 - review required)
    - Legitimate Baidu Antivirus software (if installed in environment)
level: critical
```

### Rule 4: Short-Lived Kernel Driver Service

```yaml
title: Short-Lived Kernel Driver Service (BYOVD Cleanup Pattern)
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb3
status: experimental
description: Detects kernel driver services created and deleted within 30 seconds (BYOVD cleanup behavior)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer.dll analysis report
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1070.004
logsource:
    product: windows
    category: service
detection:
    selection_create:
        EventID:
            - 7045  # Service installed
            - 4697  # Service installed (Security log)
        ServiceType: 'kernel mode driver'
    selection_delete:
        EventID: 7040  # Service state changed (stopped/deleted)
        param1: 'demand start'  # Service stopped
    timeframe: 30s
    condition: selection_create and selection_delete
falsepositives:
    - Driver installation testing by IT staff (should be reviewed)
    - Failed driver installations (review for root cause)
level: high
```

### Rule 5: Driver File in Temp Directory

```yaml
title: Kernel Driver File Created in Temp Directory
id: 10eb1fbb-2be3-a09e-efb3-d97112e42bb4
status: experimental
description: Detects .sys driver files created in temp directories (BYOVD staging location)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer.dll analysis report
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1027.009
logsource:
    product: windows
    category: file_event
detection:
    selection:
        EventID: 11  # File created (Sysmon)
        TargetFilename|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
            - '\Temp\'
        TargetFilename|endswith: '.sys'
    filter_legitimate:
        # Exclude known legitimate driver installers
        Image|contains:
            - '\Windows\System32\'
            - '\Program Files\'
        Signature: 'Microsoft Corporation'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate driver installers using temp staging (should extract to System32\Drivers)
    - Hardware vendor driver installers (review publisher signatures)
level: high
```

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

#### Query 1: Hunt for killer.dll File Hash and Execution Chain

```kql
// Hunt for killer.dll file hash and lpe.exe -> killer.dll execution chain
union
(
    // File hash detection
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 == "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
    | extend DetectionMethod = "File Hash Match"
),
(
    // Execution chain: lpe.exe -> rundll32.exe -> killer.dll
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "lpe.exe"
        and FileName =~ "rundll32.exe"
        and ProcessCommandLine has "killer.dll"
    | extend DetectionMethod = "Execution Chain"
),
(
    // Rundll32 loading killer.dll with get_hostfxr_path export
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "rundll32.exe"
        and ProcessCommandLine has_all ("killer.dll", "get_hostfxr_path")
    | extend DetectionMethod = "Export Function Match"
)
| project Timestamp, DeviceName, DetectionMethod, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName
| sort by Timestamp desc
```

#### Query 2: Hunt for BYOVD Service Creation Patterns

```kql
// Hunt for kernel driver service creation by unusual processes
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\System\CurrentControlSet\Services\"
| where RegistryValueData has "SERVICE_KERNEL_DRIVER"
| where InitiatingProcessFileName in~ ("rundll32.exe", "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
    or InitiatingProcessFolderPath has_any ("AppData", "Temp", "Users")
| join kind=inner (
    DeviceFileEvents
    | where FileName endswith ".sys"
    | where FolderPath has_any ("Temp", "AppData")
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
    RegistryKey, RegistryValueData, FileName, FolderPath, SHA256
| sort by Timestamp desc
```

#### Query 3: Hunt for Mass Security Product Termination

```kql
// Detect simultaneous termination of multiple security products
let TargetProcesses = dynamic(["MsMpEng.exe", "ekrn.exe", "avp.exe", "MBAMService.exe",
    "bdservicehost.exe", "avguard.exe", "NisSrv.exe", "vsserv.exe", "SenseCnProxy.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoOriginalFileName in~ (TargetProcesses)
    or FileName in~ (TargetProcesses)
| where ActionType == "ProcessTerminated"
| summarize TerminatedProcesses=make_set(FileName), TerminationCount=count() by
    DeviceName, bin(Timestamp, 1m), InitiatingProcessFileName, InitiatingProcessCommandLine
| where TerminationCount >= 3
| project Timestamp, DeviceName, TerminationCount, TerminatedProcesses,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TerminationCount desc, Timestamp desc
```

#### Query 4: Hunt for DeviceIoControl with Malicious IOCTL Codes

```kql
// Hunt for DeviceIoControl calls with killer.dll IOCTL codes (requires advanced EDR telemetry)
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DeviceIoControlCall"
| where AdditionalFields has_any ("0x800024B4", "0x8335003C", "BdApiUtil", "PROCEXP152")
| extend IOCTLCode = extractjson("$.IoControlCode", AdditionalFields, typeof(string))
| extend DevicePath = extractjson("$.DevicePath", AdditionalFields, typeof(string))
| where IOCTLCode in ("0x800024B4", "0x8335003C")
    or DevicePath has_any ("BdApiUtil", "PROCEXP152")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
    IOCTLCode, DevicePath, AdditionalFields
| sort by Timestamp desc
```

#### Query 5: Hunt for Short-Lived Driver Services

```kql
// Detect kernel driver services with very short lifespan (< 30 seconds)
let ServiceCreations =
    DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where RegistryKey has @"\System\CurrentControlSet\Services\"
    | where RegistryValueData has "SERVICE_KERNEL_DRIVER"
    | project CreationTime=Timestamp, DeviceId, ServiceName=extract(@"Services\\([^\\]+)", 1, RegistryKey),
        CreationProcess=InitiatingProcessFileName;
let ServiceDeletions =
    DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where RegistryKey has @"\System\CurrentControlSet\Services\"
    | where ActionType == "RegistryKeyDeleted"
    | project DeletionTime=Timestamp, DeviceId, ServiceName=extract(@"Services\\([^\\]+)", 1, RegistryKey);
ServiceCreations
| join kind=inner ServiceDeletions on DeviceId, ServiceName
| extend Lifespan_Seconds = datetime_diff('second', DeletionTime, CreationTime)
| where Lifespan_Seconds <= 30 and Lifespan_Seconds >= 0
| project CreationTime, DeletionTime, Lifespan_Seconds, DeviceId, ServiceName, CreationProcess
| sort by Lifespan_Seconds asc
```

### CrowdStrike Falcon (Event Search)

```
// Hunt for killer.dll BYOVD indicators
event_simpleName=ProcessRollup2 OR event_simpleName=ServiceInstalled OR event_simpleName=DriverLoad OR event_simpleName=AsepValueUpdate OR event_simpleName=DnsRequest
| search SHA256Hash="10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
   OR CommandLine="*killer.dll*get_hostfxr_path*"
   OR (ParentBaseFileName="lpe.exe" AND FileName="rundll32.exe")
   OR (ServiceType="KernelModeDriver" AND ImageFileName="*\\Temp\\*.sys")
   OR DriverFileName IN ("BdApiUtil64.sys", "ProcExpDriver.sys", "PROCEXP152.SYS")
   OR DomainName="109.230.231.37"
| table _time, ComputerName, FileName, CommandLine, ServiceName, DriverFileName, SHA256Hash, RemoteAddressIP4
| sort -_time
| head 100
```

### SentinelOne (Deep Visibility Query)

```sql
-- Hunt for BYOVD attack chain and killer.dll indicators
EventType = "Process Creation" OR EventType = "File Creation" OR EventType = "Registry" OR EventType = "Driver Load" OR EventType = "Network"
AND (
    SHA256 = "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"
    OR (ParentProcessName = "lpe.exe" AND ProcessName = "rundll32.exe" AND CommandLine CONTAINS "killer.dll")
    OR (ProcessName = "rundll32.exe" AND CommandLine CONTAINS "get_hostfxr_path")
    OR (RegistryPath CONTAINS "\Services\" AND RegistryValue CONTAINS "SERVICE_KERNEL_DRIVER")
    OR (FilePath CONTAINS "\Temp\" AND FileName ENDS WITH ".sys")
    OR DriverName IN ("BdApiUtil64.sys", "ProcExpDriver.sys", "PROCEXP152.SYS")
    OR DstIP = "109.230.231.37"
)
ORDER BY CreatedAt DESC
LIMIT 500
```

---

## SIEM Detection Rules

### Splunk SPL Queries

#### Query 1: File Hash and Execution Chain Detection

```spl
index=endpoint (sourcetype=file_creation OR sourcetype=process_creation)
| search (
    SHA256="10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d" OR
    (parent_process_name="lpe.exe" AND process_name="rundll32.exe" AND cmdline="*killer.dll*") OR
    (process_name="rundll32.exe" AND cmdline="*get_hostfxr_path*")
)
| eval detection_type=case(
    match(SHA256, "10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d"), "File Hash Match",
    match(parent_process_name, "lpe.exe") AND match(cmdline, "killer.dll"), "Execution Chain",
    match(cmdline, "get_hostfxr_path"), "Export Function Match"
)
| table _time, host, detection_type, process_name, parent_process_name, cmdline, file_path, SHA256, user
| sort -_time
```

#### Query 2: BYOVD Service Creation Detection

```spl
index=windows sourcetype=WinRegistry OR sourcetype=Sysmon
| search (
    registry_path="*\\System\\CurrentControlSet\\Services\\*" AND
    registry_value_data="*SERVICE_KERNEL_DRIVER*" AND
    (process_name IN ("rundll32.exe", "powershell.exe", "cmd.exe") OR
     process_path="*\\AppData\\*" OR process_path="*\\Temp\\*")
)
| table _time, host, process_name, process_path, registry_path, registry_value_data, user
| sort -_time
```

#### Query 3: Mass Security Product Termination

```spl
index=endpoint sourcetype=process_termination
| search process_name IN ("MsMpEng.exe", "ekrn.exe", "avp.exe", "MBAMService.exe", "bdservicehost.exe", "avguard.exe", "NisSrv.exe", "vsserv.exe", "SenseCnProxy.exe")
| bin _time span=1m
| stats dc(process_name) as terminated_products, values(process_name) as products_list by _time, host, parent_process_name, parent_process_path
| where terminated_products >= 3
| sort -terminated_products
| table _time, host, terminated_products, products_list, parent_process_name, parent_process_path
```

#### Query 4: Driver File in Temp Directory

```spl
index=windows (sourcetype=file_creation OR sourcetype=Sysmon)
| search (
    file_path IN ("*\\AppData\\Local\\Temp\\*.sys", "*\\Windows\\Temp\\*.sys", "*\\Temp\\*.sys")
)
| where NOT (
    process_path="*\\System32\\*" OR
    process_path="*\\Program Files\\*" OR
    signature="Microsoft Corporation"
)
| table _time, host, file_name, file_path, file_hash, process_name, process_path, signature, user
| sort -_time
```

### Elastic Stack (EQL/KQL)

#### Query 1: BYOVD Service Creation

```
sequence by host.id with maxspan=30s
[registry where event.action == "modification" and
 registry.path : "*\\System\\CurrentControlSet\\Services\\*" and
 registry.data.strings : "*SERVICE_KERNEL_DRIVER*" and
 process.name : ("rundll32.exe", "powershell.exe", "cmd.exe")]
[file where event.action == "creation" and
 file.extension == "sys" and
 file.path : ("*\\Temp\\*", "*\\AppData\\*")]
[process where event.action == "start" and
 process.name : "services.exe" and
 process.command_line : "*StartService*"]
```

#### Query 2: Mass Process Termination

```
sequence by host.id with maxspan=60s
[process where event.action == "termination" and
 process.name : ("MsMpEng.exe", "ekrn.exe", "avp.exe", "MBAMService.exe", "bdservicehost.exe")]
[process where event.action == "termination" and
 process.name : ("MsMpEng.exe", "ekrn.exe", "avp.exe", "MBAMService.exe", "bdservicehost.exe")]
[process where event.action == "termination" and
 process.name : ("MsMpEng.exe", "ekrn.exe", "avp.exe", "MBAMService.exe", "bdservicehost.exe")]
```

#### Query 3: lpe.exe -> killer.dll Execution Chain

```
sequence by host.id with maxspan=5m
[process where event.action == "start" and
 process.name : "lpe.exe"]
[process where event.action == "start" and
 process.parent.name : "lpe.exe" and
 process.name : "rundll32.exe" and
 process.command_line : "*killer.dll*"]
```

---

## Network Detection

### Suricata/Snort Rules

#### Rule 1: Connection to Arsenal-237 C2 Infrastructure

```
alert tcp $HOME_NET any -> 109.230.231.37 any (
    msg:"MALWARE killer.dll connection to Arsenal-237 C2 infrastructure";
    flow:to_server,established;
    reference:sha256,10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d;
    reference:url,https://github.com/[your-repo]/reports/killer-dll/;
    classtype:trojan-activity;
    sid:2000001;
    rev:1;
)

alert tcp 109.230.231.37 any -> $HOME_NET any (
    msg:"MALWARE killer.dll inbound from Arsenal-237 C2 infrastructure";
    flow:to_client,established;
    reference:sha256,10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d;
    classtype:trojan-activity;
    sid:2000002;
    rev:1;
)
```

#### Rule 2: lpe.exe Download Pattern

```
alert http $HOME_NET any -> any any (
    msg:"MALWARE Arsenal-237 lpe.exe download attempt";
    flow:to_server,established;
    http.uri; content:"/lpe.exe"; nocase;
    http.host; content:"109.230.231.37";
    reference:url,https://github.com/[your-repo]/reports/killer-dll/;
    classtype:trojan-activity;
    sid:2000003;
    rev:1;
)
```

### Firewall Rules

```
# Block Arsenal-237 infrastructure
DENY IP ANY -> 109.230.231.37 ANY
DENY IP 109.230.231.37 -> ANY ANY
LOG ALL connections to/from 109.230.231.37

# Alert on .exe downloads from non-standard ports
ALERT HTTP GET *.exe
    WHERE dest_port NOT IN (80, 443, 8080)
    WHERE source_reputation:LOW OR source_reputation:UNKNOWN
```

---

## Implementation Guidance

### Priority 1: Immediate Deployment (0-24 hours)

1. **Network Blocking**:
   - Block 109.230.231.37 at network perimeter (firewall, proxy)
   - Deploy Suricata/Snort signatures for C2 detection
   - Add to threat intelligence feeds and SIEM watch lists

2. **Hash-Based Detection**:
   - Deploy killer.dll file hash to all EDR platforms
   - Add to application blocklists and antivirus signatures
   - Scan all endpoints retrospectively for hash presence

3. **YARA Rules**:
   - Deploy to endpoint antivirus/EDR systems
   - Scan email attachments and web downloads
   - Execute retroactive filesystem scans on critical servers

### Priority 2: Enhanced Monitoring (24-48 hours)

1. **Sigma Rules**:
   - Deploy all 5 Sigma rules to SIEM platform
   - Configure alerting for CRITICAL severity rules
   - Tune detection sensitivity based on initial false positive rate

2. **EDR Hunting Queries**:
   - Execute all 5 EDR queries across enterprise
   - Focus on high-value targets (domain controllers, file servers, executive systems)
   - Investigate all positive hits with full forensic analysis

3. **Service Creation Monitoring**:
   - Enable Windows Event Log 7045 (Service Installed)
   - Enable Sysmon Event ID 19 (WMI Filter Activity) for service monitoring
   - Configure real-time alerts for kernel driver service creation

### Priority 3: Long-Term Defense (Week 1+)

1. **Driver Blocklisting**:
   - Create WDAC (Windows Defender Application Control) deny policy
   - Block BdApiUtil64.sys and ProcExpDriver.sys by hash
   - Test in pilot group before enterprise deployment
   - Deploy via Group Policy to all Windows endpoints

2. **Behavioral Analytics**:
   - Implement UEBA for anomalous service creation patterns
   - Deploy machine learning models for BYOVD detection
   - Monitor for short-lived kernel driver services (< 30 seconds)

3. **Threat Intelligence Integration**:
   - Add Arsenal-237 IOCs to threat intelligence platform
   - Monitor for infrastructure expansion (new IPs, C2 servers)
   - Track killer.dll variants and tooling evolution

---

## Testing & Validation

### Safe Testing Procedures

**DO NOT**:
- Execute live killer.dll malware on production systems
- Load vulnerable drivers on production endpoints
- Test BYOVD techniques outside isolated lab environments

**DO**:
- Create test files with matching strings (non-malicious test harness)
- Validate YARA rules in isolated lab with actual sample
- Test Sigma rules against historical data before alerting
- Conduct purple team exercises in controlled environments
- Use Windows Event Log simulators for service creation tests

### Validation Checklist

- [ ] YARA rules tested against sample (in isolated lab only)
- [ ] Sigma rules validated in test SIEM environment
- [ ] EDR queries return expected results on test data
- [ ] Network signatures tested in lab environment
- [ ] False positive assessment completed for each rule
- [ ] Alert tuning performed for production deployment
- [ ] Incident response procedures documented
- [ ] SOC team trained on BYOVD attack patterns
- [ ] Escalation paths defined and tested
- [ ] Driver blocklist tested in pilot environment

---

## Maintenance & Updates

**Review Schedule**:
- **Daily**: Monitor alerts for new detections and false positives
- **Weekly**: Tune rules based on false positive feedback
- **Monthly**: Review detection effectiveness and coverage
- **Quarterly**: Update based on Arsenal-237 toolkit evolution
- **As needed**: Update when new BYOVD variants discovered

**Metrics to Track**:
- True positive detection rate by rule
- False positive rate and sources
- Mean time to detect (MTTD) for BYOVD attacks
- Coverage across BYOVD attack chain phases
- Alert volume trends and SOC workload impact

---

## Related Resources

- [killer.dll Main Report]({{ "/reports/killer-dll/" | relative_url }})
- [killer.dll IOC Feed]({{ "/ioc-feeds/killer-dll.json" | relative_url }})
- MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
- MITRE ATT&CK: T1068 - Exploitation for Privilege Escalation
- LOLDrivers Project: https://www.loldrivers.io/

---

**Version:** 1.0
**Last Updated:** 2026-01-25
**Next Review:** 2026-02-25

---
**END OF DETECTION RULES**
