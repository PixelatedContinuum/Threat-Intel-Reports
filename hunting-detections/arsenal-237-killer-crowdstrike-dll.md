---
title: Detection Rules - killer_crowdstrike.dll (CrowdStrike Variant)
date: '2026-01-25'
layout: post
permalink: /hunting-detections/arsenal-237-killer-crowdstrike-dll/
hide: true
---

# Detection Rules - killer_crowdstrike.dll (CrowdStrike-Specific BYOVD Variant)

## Overview

This detection guide focuses on **CrowdStrike Falcon-specific indicators** for the killer_crowdstrike.dll variant. This malware uses **identical BYOVD techniques** as killer.dll but with a kill list specifically targeting CrowdStrike Falcon processes.

**Malware Family**: Arsenal-237 BYOVD Defense Evasion Module (CrowdStrike Variant)
**Severity**: CRITICAL (especially for CrowdStrike customers)
**Variant Relationship**: Reconfigured killer.dll with CrowdStrike-specific targeting
**Attack Chain**: lpe.exe -> killer_crowdstrike.dll -> ransomware deployment
**Last Updated**: 2026-01-25

---

## Detection Strategy

### Priority 1: CrowdStrike-Specific Detections (CRITICAL for Falcon customers)
Focus on **unexpected CrowdStrike process termination** as highest-priority indicator.

### Priority 2: Generic BYOVD Detections
Leverage all killer.dll detection patterns - same IOCTLs, same drivers, same service lifecycle.

**Reference**: See [killer.dll Detection Rules]({{ "/hunting-detections/killer-dll/" | relative_url }}) for complete BYOVD detection coverage.

---

## Table of Contents

1. [CrowdStrike-Specific Detections](#crowdstrike-specific-detections)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [CrowdStrike Falcon Custom IOAs](#crowdstrike-falcon-custom-ioas)
4. [EDR Hunting Queries](#edr-hunting-queries)
5. [SIEM Detection Rules](#siem-detection-rules)
6. [Implementation Guidance](#implementation-guidance)

---

## CrowdStrike-Specific Detections

### Critical Indicator: CrowdStrike Falcon Process Termination

The **PRIMARY indicator** for killer_crowdstrike.dll is unexpected termination of CrowdStrike Falcon processes.

**Target Processes**:
- `CSFalconService.exe` - CrowdStrike Falcon Service
- `csagent.exe` - CrowdStrike Falcon Agent
- `CSFalconContainer.exe` - CrowdStrike Falcon Container

**Detection Logic**:
```
IF (CrowdStrike process terminates unexpectedly)
  AND (parent process is non-standard: rundll32.exe, lpe.exe, or unknown)
  AND (service creation event within 60 seconds)
THEN CRITICAL ALERT - Possible killer_crowdstrike.dll execution
```

---

## Sigma Detection Rules

### Rule 1: CrowdStrike Falcon Process Termination

```yaml
title: Critical - CrowdStrike Falcon Process Termination (killer_crowdstrike.dll)
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: experimental
description: Detects unexpected termination of CrowdStrike Falcon processes (killer_crowdstrike.dll behavior)
author: Threat Intelligence Team
date: 2026/01/25
references:
    - killer_crowdstrike.dll analysis report
    - Arsenal-237 malware toolkit investigation
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: process_termination
detection:
    selection:
        Image|endswith:
            - '\\CSFalconService.exe'
            - '\\csagent.exe'
            - '\\CSFalconContainer.exe'
    filter_legitimate:
        # Exclude legitimate CrowdStrike updates/restarts
        ParentImage: 'C:\\Program Files\\CrowdStrike\\*'
        User: 'NT AUTHORITY\\SYSTEM'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate CrowdStrike Falcon updates or service restarts
    - Administrator manually stopping Falcon service (should be investigated)
level: critical
```

### Rule 2: CrowdStrike Termination + Service Creation Correlation

```yaml
title: CrowdStrike Termination with Suspicious Service Creation
id: b2c3d4e5-f6a7-8901-2345-678901bcdefg
status: experimental
description: Detects CrowdStrike termination correlated with kernel driver service creation (BYOVD attack pattern)
author: Threat Intelligence Team
date: 2026/01/25
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.privilege_escalation
    - attack.t1068
logsource:
    product: windows
    category: correlation
detection:
    selection_termination:
        EventID: 4689  # Process termination
        ProcessName:
            - 'CSFalconService.exe'
            - 'csagent.exe'
            - 'CSFalconContainer.exe'
    selection_service:
        EventID: 7045  # Service installed
        ServiceType: 'kernel mode driver'
    timeframe: 60s
    condition: selection_termination and selection_service
falsepositives:
    - Extremely rare - investigate all matches
level: critical
```

### Rule 3: CrowdStrike Sensor Offline + Driver Loading

```yaml
title: CrowdStrike Sensor Offline with Vulnerable Driver Loading
id: c3d4e5f6-a7b8-9012-3456-789012cdefgh
status: experimental
description: Detects CrowdStrike sensor disconnection correlated with vulnerable driver loading
author: Threat Intelligence Team
date: 2026/01/25
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: correlation
detection:
    selection_sensor:
        Source: 'CrowdStrike'
        EventType: 'SensorOffline'
    selection_driver:
        EventID: 6  # Driver loaded (Sysmon)
        ImageLoaded|contains:
            - 'BdApiUtil64.sys'
            - 'ProcExp'
            - '.sys'
        ImageLoaded|contains: '\\Temp\\'
    timeframe: 60s
    condition: selection_sensor and selection_driver
falsepositives:
    - Network connectivity issues causing sensor offline (without driver loading)
level: critical
```

---

## CrowdStrike Falcon Custom IOAs

### Custom IOA 1: Suspicious Service Creation Targeting Falcon

**Platform**: CrowdStrike Falcon
**Type**: Custom Indicator of Attack (IOA)

**Pattern**:
```
process_name:rundll32.exe AND
command_line:*killer* AND
(child_process_api:CreateServiceW OR child_process_api:StartServiceW) AND
service_type:kernel_mode_driver
```

**Severity**: CRITICAL
**Action**: Block + Alert + Quarantine

### Custom IOA 2: CrowdStrike Process Termination from Unusual Parent

**Pattern**:
```
parent_process:rundll32.exe AND
target_process:(CSFalconService.exe OR csagent.exe OR CSFalconContainer.exe) AND
api_call:TerminateProcess
```

**Severity**: CRITICAL
**Action**: Block + Alert + Isolate Endpoint

### Custom IOA 3: Vulnerable Driver Loading

**Pattern**:
```
file_name:(BdApiUtil64.sys OR ProcExpDriver.sys OR PROCEXP152.SYS) AND
file_path:*\\Temp\\* AND
process_name:services.exe
```

**Severity**: HIGH
**Action**: Block Driver Load + Alert

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

#### Query 1: Hunt for CrowdStrike Process Termination

```kql
// Hunt for unexpected CrowdStrike Falcon process termination
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName in~ ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe")
    or FileName in~ ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe")
| where ActionType == "ProcessTerminated"
| where InitiatingProcessFileName !in~ ("CSFalconService.exe", "CrowdStrike.exe", "falcon-sensor.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| sort by Timestamp desc
```

#### Query 2: CrowdStrike Termination + Service Creation Correlation

```kql
// Correlate CrowdStrike termination with kernel driver service creation
let FalconTermination =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe")
    | where ActionType == "ProcessTerminated"
    | project TerminationTime=Timestamp, DeviceId, TerminatedProcess=FileName;
let ServiceCreation =
    DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where RegistryKey has @"\System\CurrentControlSet\Services\"
    | where RegistryValueData has "SERVICE_KERNEL_DRIVER"
    | project ServiceCreationTime=Timestamp, DeviceId, ServiceName=extract(@"Services\\([^\\]+)", 1, RegistryKey);
FalconTermination
| join kind=inner ServiceCreation on DeviceId
| where (ServiceCreationTime - TerminationTime) between (-60s .. 60s)
| project TerminationTime, ServiceCreationTime, DeviceId, TerminatedProcess, ServiceName
| sort by TerminationTime desc
```

### CrowdStrike Falcon (Event Search)

```
// Hunt for killer_crowdstrike.dll indicators in Falcon
event_simpleName=ProcessRollup2 OR event_simpleName=ServiceInstalled OR event_simpleName=DriverLoad OR event_simpleName=SensorHeartbeat
| search (FileName IN ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe") AND ContextProcessId_decimal!="")
   OR (ServiceType="KernelModeDriver" AND ImageFileName="*\\Temp\\*.sys")
   OR DriverFileName IN ("BdApiUtil64.sys", "ProcExpDriver.sys", "PROCEXP152.SYS")
   OR (ParentBaseFileName="lpe.exe" AND FileName="rundll32.exe" AND CommandLine="*killer*")
| table _time, ComputerName, FileName, CommandLine, ServiceName, DriverFileName, event_simpleName
| sort -_time
```

---

## SIEM Detection Rules

### Splunk SPL Queries

#### Query 1: CrowdStrike Process Termination Detection

```spl
index=endpoint sourcetype=process_termination
| search process_name IN ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe")
| where NOT (parent_process_path="C:\\Program Files\\CrowdStrike\\*" AND user="NT AUTHORITY\\SYSTEM")
| eval severity=if(match(parent_process_name, "(rundll32|lpe)"), "CRITICAL", "HIGH")
| table _time, host, process_name, parent_process_name, parent_process_path, user, severity
| sort -_time
```

#### Query 2: CrowdStrike + Service Creation Correlation

```spl
index=windows (sourcetype=WinRegistry OR sourcetype=process_termination)
| transaction host maxspan=60s
| search (process_name IN ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe") AND
          registry_path="*\\Services\\*" AND registry_value_data="*SERVICE_KERNEL_DRIVER*")
| table _time, host, process_name, registry_path, registry_value_data, parent_process_name
| sort -_time
```

### Elastic Stack (EQL)

#### Query 1: CrowdStrike Termination Sequence

```
sequence by host.id with maxspan=60s
[process where event.action == "termination" and
 process.name in ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe")]
[registry where event.action == "modification" and
 registry.path : "*\\System\\CurrentControlSet\\Services\\*" and
 registry.data.strings : "*SERVICE_KERNEL_DRIVER*"]
```

---

## Implementation Guidance

### For CrowdStrike Falcon Customers (PRIORITY 1)

1. **Deploy CrowdStrike Custom IOAs** (Day 1):
   - Create Custom IOAs for all three patterns above
   - Set action to: Block + Alert + Quarantine
   - Test in pilot group before enterprise deployment

2. **Enable Falcon Behavioral Prevention**:
   - Ensure "Suspicious Service Creation" prevention is enabled
   - Configure "Vulnerable Driver Loading" prevention (if available)
   - Enable "Unusual Process Termination" alerting

3. **Integrate Falcon API with SIEM**:
   - Export Falcon sensor offline events to SIEM
   - Correlate with network/system logs for comprehensive detection
   - Create alert for: Falcon sensor offline + service creation within 60 seconds

4. **CrowdStrike-Specific Hunting**:
   - Query Falcon API for historical process termination events
   - Hunt for csagent.exe/CSFalconService.exe unexpected exits in last 90 days
   - Review sensor offline events for correlation with other suspicious activity

### For All Organizations (PRIORITY 2)

1. **Deploy Generic BYOVD Detections**:
   - Use all detection rules from [killer.dll detection guide]({{ "/hunting-detections/killer-dll/" | relative_url }})
   - Same IOCTLs (0x800024B4, 0x8335003C)
   - Same vulnerable drivers (BdApiUtil64.sys, ProcExpDriver.sys)
   - Same service lifecycle patterns

2. **Network-Level Blocking**:
   - Block Arsenal-237 infrastructure: 109.230.231.37
   - Deploy Suricata/Snort rules for C2 detection
   - Monitor for connections to 109.230.231.37:8888

3. **Driver Blocklisting**:
   - Implement WDAC deny policy for vulnerable drivers
   - Block BdApiUtil64.sys and ProcExpDriver.sys by hash
   - Deploy via Group Policy to all Windows endpoints

---

## Related Resources

- [killer_crowdstrike.dll Main Report]({{ "/reports/killer-crowdstrike-dll/" | relative_url }})
- [killer_crowdstrike.dll IOC Feed]({{ "/ioc-feeds/killer-crowdstrike-dll.json" | relative_url }})
- [killer.dll Detection Rules]({{ "/hunting-detections/killer-dll/" | relative_url }}) (Generic BYOVD patterns)
- [killer.dll Main Report]({{ "/reports/killer-dll/" | relative_url }}) (Parent variant)
- MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools
- CrowdStrike Falcon Documentation: Custom IOA Creation

---

**Version:** 1.0
**Last Updated:** 2026-01-25
**Next Review:** 2026-02-25

---
**END OF DETECTION RULES**
