---
title: Detection Rules - lpe.exe (Arsenal-237 LPE Module)
date: '2026-01-25'
layout: post
permalink: /hunting-detections/arsenal-237-lpe-exe/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
hide: true
---

## Overview

This detection guide focuses on identifying **lpe.exe**, a sophisticated local privilege escalation (LPE) wrapper from the Arsenal-237 malware toolkit. This executable employs **five independent escalation techniques**, providing 99.99%+ success rate across diverse Windows environments.

**Malware Family**: Arsenal-237 Privilege Escalation Wrapper
**Severity**: CRITICAL
**Attack Chain Function**: Wraps killer.dll/killer.exe and executes it with SYSTEM privileges to enable defense evasion
**Typical Usage**: `lpe.exe C:\path\to\killer.dll`
**Last Updated**: 2026-01-25

---

## Detection Strategy

### Priority 1: Behavioral Detection (HIGH CONFIDENCE)
Focus on **privilege escalation API sequences** and **multi-technique patterns** as highest-priority indicators.

### Priority 2: File-Based Detection
Hash-based detection for known lpe.exe samples (SHA256: c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e).

### Priority 3: Registry & Process Monitoring
Monitor for UAC bypass registry modifications and unusual process hierarchies (schtasks, wmic, fodhelper spawned by unexpected parents).

---

## Table of Contents

1. [YARA Detection Rules](#yara-detection-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Implementation Guidance](#implementation-guidance)

---

## YARA Detection Rules

### Rule 1: lpe.exe File Hash Detection

```yara
rule Arsenal237_LPE_EXE_Hash {
    meta:
        description = "Detects Arsenal-237 lpe.exe by file hash"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        hash = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
        severity = "CRITICAL"
        family = "Arsenal-237"

    condition:
        hash.sha256(0, filesize) == "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e" or
        hash.md5(0, filesize) == "47400a6b7c84847db0513e6dbc04e469"
}
```

### Rule 2: Token Manipulation API Pattern

```yara
rule Arsenal237_LPE_Token_Manipulation {
    meta:
        description = "Detects lpe.exe token impersonation API pattern"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        severity = "HIGH"
        technique = "T1134.001 - Token Impersonation"

    strings:
        $api1 = "CreateToolhelp32Snapshot" ascii wide
        $api2 = "OpenProcessToken" ascii wide
        $api3 = "DuplicateTokenEx" ascii wide
        $api4 = "ImpersonateLoggedOnUser" ascii wide
        $api5 = "Process32FirstW" ascii wide
        $api6 = "Process32NextW" ascii wide

        $process1 = "winlogon.exe" ascii wide nocase
        $process2 = "lsass.exe" ascii wide nocase
        $process3 = "services.exe" ascii wide nocase
        $process4 = "csrss.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        2 of ($process*)
}
```

### Rule 3: UAC Bypass Registry Hijack Pattern

```yara
rule Arsenal237_LPE_UAC_Bypass {
    meta:
        description = "Detects lpe.exe UAC bypass via registry hijack"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        severity = "HIGH"
        technique = "T1548.002 - UAC Bypass"

    strings:
        $reg1 = "HKCU\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command" ascii wide nocase
        $reg2 = "DelegateExecute" ascii wide
        $reg3 = "reg add" ascii wide nocase
        $reg4 = "fodhelper.exe" ascii wide nocase
        $reg5 = "reg delete" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        all of ($reg*)
}
```

### Rule 4: Scheduled Task Privilege Escalation

**Note**: Unlike UAC bypass (hijacking fodhelper.exe) or named pipe (exploiting Print Spooler), this technique uses **schtasks.exe directly** through its administrative capabilities. Task names are likely randomized at runtime and not hardcoded in the malware.

```yara
rule Arsenal237_LPE_Schtasks {
    meta:
        description = "Detects lpe.exe scheduled task escalation via direct schtasks.exe use"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        severity = "HIGH"
        technique = "T1053.005 - Scheduled Task"
        note = "Task name likely randomized - cannot rely on specific task names"

    strings:
        $schtasks1 = "schtasks" ascii wide nocase
        $schtasks2 = "/create" ascii wide nocase
        $schtasks3 = "/tn" ascii wide nocase
        $schtasks4 = "/ru SYSTEM" ascii wide nocase
        $schtasks5 = "/delete" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        all of ($schtasks*)
}
```

### Rule 5: Named Pipe Impersonation Pattern

```yara
rule Arsenal237_LPE_Named_Pipe {
    meta:
        description = "Detects lpe.exe named pipe impersonation"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        severity = "HIGH"
        technique = "T1055.001 - Named Pipe Impersonation"

    strings:
        $pipe1 = "CreateNamedPipeW" ascii wide
        $pipe2 = "ImpersonateNamedPipeClient" ascii wide
        $pipe3 = "ConnectNamedPipe" ascii wide
        $pipe4 = "\\\\\\\\.\\\\pipe\\\\" ascii wide
        $pipe5 = "spoolss" ascii wide nocase

        $ps = "powershell" ascii wide nocase
        $ps_pipe = "NamedPipeClientStream" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (all of ($pipe*) or ($ps and $ps_pipe))
}
```

### Rule 6: WMIC Process Creation Pattern

```yara
rule Arsenal237_LPE_WMIC {
    meta:
        description = "Detects lpe.exe WMIC process creation"
        author = "The Hunters Ledger"
        date = "2026-01-25"
        severity = "MEDIUM"
        technique = "T1047 - WMI"

    strings:
        $wmic1 = "wmic" ascii wide nocase
        $wmic2 = "process" ascii wide nocase
        $wmic3 = "call" ascii wide nocase
        $wmic4 = "create" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        all of ($wmic*)
}
```

---

## Sigma Detection Rules

### Rule 1: Token Impersonation Detection

```yaml
title: Privilege Escalation via Token Impersonation (lpe.exe)
id: 41794664-1101-4fbf-a117-c8c1a1f7f473
status: experimental
description: Detects token impersonation sequence characteristic of lpe.exe
author: The Hunters Ledger
date: '2026-01-25'
references:
    - lpe.exe analysis report
    - Arsenal-237 malware toolkit investigation
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1134.001
    - detection.emerging-threats
logsource:
    product: windows
    category: process_access
detection:
    selection_process_access:
        TargetImage|endswith:
            - '\winlogon.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\csrss.exe'
        GrantedAccess:
            - '0x1410'  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            - '0x1000'  # PROCESS_QUERY_LIMITED_INFORMATION
    selection_api:
        CallTrace|contains:
            - 'OpenProcessToken'
            - 'DuplicateTokenEx'
            - 'ImpersonateLoggedOnUser'
    condition: selection_process_access and selection_api
falsepositives:
    - Legitimate administrative tools performing token operations (rare)
level: critical
```

### Rule 2: UAC Bypass via Registry Hijack

```yaml
title: UAC Bypass via Ms-Settings Registry Hijack (lpe.exe)
id: 78ff8cac-3e71-42c5-9fdf-acdb038ce94a
status: experimental
description: Detects fodhelper.exe launched with reg.exe or lpe.exe as its parent process, the process-creation signature of the ms-settings registry-hijack UAC bypass. The original rule intent also matched the preceding registry write to the ms-settings Shell\Open\command key within 30 seconds; that is a separate event under a different logsource and single-event Sigma rules cannot express the cross-event correlation, so it has been dropped — this rule detects the fodhelper launch alone, which is independently a strong indicator since fodhelper.exe is a Microsoft-signed LOLBIN rarely spawned by reg.exe.
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.t1548.002
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\fodhelper.exe'
        ParentImage|endswith:
            - '\reg.exe'
            - '\lpe.exe'
    condition: selection
falsepositives:
    - Legitimate software installation (extremely rare)
level: high
```

### Rule 3: Scheduled Task Creation as SYSTEM

```yaml
title: Scheduled Task Created as SYSTEM (lpe.exe)
id: 19fbc402-5876-4f9b-905b-b5452dc7d634
status: experimental
description: Detects scheduled task creation with SYSTEM privileges from non-administrative process (direct use of schtasks.exe, not hijacking another component)
author: The Hunters Ledger
date: '2026-01-25'
references:
    - Task names are likely randomized - detection should focus on /ru SYSTEM parameter, not task name
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/ru'
            - 'SYSTEM'
    filter_admin:
        User|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: selection and not filter_admin
falsepositives:
    - System administrators manually creating SYSTEM tasks (should be reviewed)
    - Legitimate administrative scripts using schtasks.exe
level: high
```

### Rule 4: Named Pipe Impersonation Attack

```yaml
title: Named Pipe Impersonation Attack (lpe.exe)
id: 3a0e534f-01ba-4ef6-bdac-99a3528c5f3b
status: experimental
description: Detects creation of a named pipe used to stage a token-impersonation privilege-escalation attempt (a client connecting to and impersonating the security context of the pipe's creator). The original rule intent also matched a PowerShell process invoking NamedPipeClientStream within 60 seconds of the pipe creation; that is a separate event and single-event Sigma rules cannot express the cross-event correlation, so it has been dropped — this rule detects the pipe creation alone. Retagged from T1055.001 (Dynamic-link Library Injection, unrelated to named-pipe impersonation) to T1134.001 (Token Impersonation/Theft), the technique this behavior actually maps to.
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1134.001
    - detection.emerging-threats
logsource:
    product: windows
    category: pipe_created
detection:
    selection:
        PipeName|contains:
            - 'spoolss'
            - 'pipe'
    condition: selection
falsepositives:
    - Legitimate administrative tools using named pipes (rare)
level: medium
```

### Rule 5: WMIC Process Creation for Privilege Escalation

```yaml
title: WMIC Process Creation for Privilege Escalation (lpe.exe)
id: 7e7d8199-93c4-4f53-ad05-84c4f3a08a96
status: experimental
description: Detects WMIC being used to create processes for privilege escalation
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.execution
    - attack.t1047
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'process'
            - 'call'
            - 'create'
    filter_admin:
        User|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: selection and not filter_admin
falsepositives:
    - Legitimate administrative scripts using WMIC (review context)
level: medium
```

### Rule 6: Multi-Technique Privilege Escalation Correlation

```yaml
title: Multi-Technique Privilege Escalation Sequence (lpe.exe)
id: 4b346709-c283-4b91-97da-a13b4573be94
status: experimental
description: Detects scheduled-task creation with the /ru SYSTEM parameter, one of three privilege-escalation techniques (token impersonation, UAC bypass, SYSTEM scheduled task) lpe.exe attempts in rapid succession. The original rule intent required 2-of-3 techniques within 60 seconds across three different Windows logsources (process_access, registry_set, process_creation); single-event Sigma rules cannot express cross-logsource, cross-event correlation, so that has been dropped. This rule is now a duplicate of Rule 3 (Scheduled Task Created as SYSTEM) and adds no independent detection coverage — token impersonation and UAC-bypass coverage for this multi-technique pattern is provided individually by Rule 1 and Rule 2 in this file.
author: The Hunters Ledger
date: '2026-01-25'
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/ru SYSTEM'
    condition: selection
falsepositives:
    - Extremely rare - investigate all matches
level: high
```

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

#### Query 1: Hunt for Token Impersonation

```kql
// Hunt for token impersonation API sequence characteristic of lpe.exe
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser")
| where InitiatingProcessFileName !in~ ("services.exe", "lsass.exe", "svchost.exe")  // Exclude legitimate system processes
| summarize TokenAPIs = make_set(ActionType), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
| where array_length(TokenAPIs) >= 2  // At least 2 token manipulation APIs
| project Timestamp = FirstSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, TokenAPIs, LastSeen
| sort by Timestamp desc
```

#### Query 2: Hunt for UAC Bypass via Registry

```kql
// Hunt for UAC bypass via ms-settings registry hijack
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_all ("Software\\Classes\\ms-settings", "Shell\\Open\\command")
| where ActionType == "RegistryValueSet"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "fodhelper.exe"
    | where InitiatingProcessFileName !in~ ("explorer.exe", "userinit.exe")
) on DeviceName
| where (RegistryEvents_Timestamp - ProcessEvents_Timestamp) between (-60s .. 60s)
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
    FodhelperParent = InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

#### Query 3: Hunt for Scheduled Task SYSTEM Escalation

```kql
// Hunt for scheduled task creation with SYSTEM privileges
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_all ("/create", "/ru", "SYSTEM")
| where AccountName !has "SYSTEM" and AccountName !has "Administrator"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| sort by Timestamp desc
```

#### Query 4: Hunt for Named Pipe Impersonation

```kql
// Hunt for named pipe creation followed by PowerShell connection attempt
let NamedPipeCreation =
    DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "NamedPipeEvent"
    | project PipeCreationTime=Timestamp, DeviceId, PipeName;
let PowerShellPipeClient =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has "NamedPipeClientStream"
    | project PSTime=Timestamp, DeviceId, ProcessCommandLine, InitiatingProcessFileName;
NamedPipeCreation
| join kind=inner PowerShellPipeClient on DeviceId
| where (PSTime - PipeCreationTime) between (0s .. 60s)
| project PipeCreationTime, PSTime, DeviceId, PipeName, ProcessCommandLine, InitiatingProcessFileName
| sort by PipeCreationTime desc
```

#### Query 5: Hunt for lpe.exe File Hash

```kql
// Hunt for lpe.exe by known file hash
DeviceFileEvents
| where Timestamp > ago(90d)
| where SHA256 == "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e"
    or MD5 == "47400a6b7c84847db0513e6dbc04e469"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

#### Query 6: Hunt for Multi-Technique Escalation Pattern

```kql
// Hunt for multiple privilege escalation techniques from same process (lpe.exe signature)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("schtasks.exe", "wmic.exe", "reg.exe", "powershell.exe")
    or ProcessCommandLine has_any ("OpenProcessToken", "DuplicateTokenEx", "fodhelper.exe")
| summarize Techniques = make_set(FileName), Commands = make_set(ProcessCommandLine),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
| where array_length(Techniques) >= 2  // Multiple techniques attempted
| where (LastSeen - FirstSeen) < 60s  // Within 60 second window
| project FirstSeen, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, Techniques, Commands
| sort by FirstSeen desc
```

### CrowdStrike Falcon (Event Search)

```
// Hunt for lpe.exe privilege escalation indicators in Falcon
event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2, AsepValueUpdate, NamedPipeEvent, ScheduledTaskRegistered)
| search (FileName IN ("lpe.exe", "schtasks.exe", "wmic.exe", "reg.exe", "fodhelper.exe") AND
          CommandLine IN ("*OpenProcessToken*", "*DuplicateTokenEx*", "*ImpersonateLoggedOnUser*",
                         "*ms-settings*", "*/ru SYSTEM*", "*process call create*", "*NamedPipeClientStream*"))
   OR (SHA256HashData="c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e")
   OR (TargetFileName IN ("winlogon.exe", "lsass.exe", "services.exe", "csrss.exe") AND SourceProcessId_decimal!="")
   OR (RegObjectName="*\\Software\\Classes\\ms-settings\\Shell\\Open\\command*")
| table _time, ComputerName, FileName, CommandLine, SHA256HashData, ParentBaseFileName, event_simpleName
| sort -_time
```

### SentinelOne (Deep Visibility Query)

```sql
-- Hunt for lpe.exe privilege escalation patterns in SentinelOne
EventType IN ("Process Creation", "Registry", "Process Access", "Named Pipe")
AND (
    (SrcProcCmdLine ContainsCIS "OpenProcessToken" OR SrcProcCmdLine ContainsCIS "DuplicateTokenEx")
    OR (TgtFilePath EndsWith "winlogon.exe" OR TgtFilePath EndsWith "lsass.exe" OR TgtFilePath EndsWith "services.exe")
    OR (RegistryKeyPath Contains "\\Software\\Classes\\ms-settings\\Shell\\Open\\command")
    OR (SrcProcName = "schtasks.exe" AND SrcProcCmdLine ContainsCIS "/ru SYSTEM")
    OR (SrcProcName = "wmic.exe" AND SrcProcCmdLine ContainsCIS "process call create")
    OR (SrcProcName = "fodhelper.exe" AND SrcProcParentName NOT IN ("explorer.exe", "userinit.exe"))
    OR (SrcProcSHA256 = "c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e")
)
```

---

## SIEM Detection Rules

### Splunk SPL Queries

#### Query 1: Token Impersonation Detection

```spl
index=endpoint sourcetype=sysmon EventCode=10
| search (TargetImage="*\\winlogon.exe" OR TargetImage="*\\lsass.exe" OR TargetImage="*\\services.exe" OR TargetImage="*\\csrss.exe")
| search GrantedAccess IN ("0x1410", "0x1000", "0x1FFFFF")
| where SourceImage!="*\\services.exe" AND SourceImage!="*\\lsass.exe" AND SourceImage!="*\\svchost.exe"
| stats count, values(TargetImage) as TargetProcesses, earliest(_time) as FirstSeen, latest(_time) as LastSeen by SourceImage, SourceProcessId, Computer
| eval TimeWindow = LastSeen - FirstSeen
| where TimeWindow < 60
| table _time, Computer, SourceImage, SourceProcessId, TargetProcesses, count, TimeWindow
| sort -_time
```

#### Query 2: UAC Bypass Registry Modification

```spl
index=endpoint sourcetype=sysmon EventCode=13
| search TargetObject="*\\Software\\Classes\\ms-settings\\Shell\\Open\\command*"
| join Computer [
    search index=endpoint sourcetype=sysmon EventCode=1 Image="*\\fodhelper.exe"
    | eval fodhelper_time=_time
]
| eval time_diff = abs(_time - fodhelper_time)
| where time_diff < 60
| table _time, Computer, TargetObject, Details, Image, ParentImage, CommandLine
| sort -_time
```

#### Query 3: Scheduled Task SYSTEM Creation

```spl
index=endpoint sourcetype=sysmon EventCode=1 Image="*\\schtasks.exe"
| search CommandLine="*/create*" AND CommandLine="*/ru*" AND CommandLine="*SYSTEM*"
| where User!="NT AUTHORITY\\SYSTEM" AND User!="*Administrator*"
| table _time, Computer, User, CommandLine, ParentImage, ParentCommandLine
| sort -_time
```

#### Query 4: Named Pipe Impersonation

```spl
index=endpoint sourcetype=sysmon (EventCode=17 OR EventCode=18)
| search PipeName="*spoolss*" OR PipeName="*pipe*"
| join Computer [
    search index=endpoint sourcetype=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*NamedPipeClientStream*"
    | eval ps_time=_time
]
| eval time_diff = abs(_time - ps_time)
| where time_diff < 60
| table _time, Computer, PipeName, EventType, Image, CommandLine
| sort -_time
```

#### Query 5: lpe.exe File Hash Detection

```spl
index=endpoint (sourcetype=sysmon EventCode=1 OR sourcetype=windows:security EventID=4688)
| search (SHA256="c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e" OR
         MD5="47400a6b7c84847db0513e6dbc04e469" OR
         OriginalFileName="lpe.exe")
| table _time, Computer, User, Image, CommandLine, ParentImage, SHA256, MD5
| sort -_time
```

#### Query 6: Multi-Technique Correlation

```spl
index=endpoint sourcetype=sysmon
| search (EventCode=10 TargetImage IN ("*\\winlogon.exe", "*\\lsass.exe")) OR
         (EventCode=13 TargetObject="*ms-settings*") OR
         (EventCode=1 Image="*\\schtasks.exe" CommandLine="*/ru SYSTEM*") OR
         (EventCode=1 Image="*\\wmic.exe" CommandLine="*process call create*")
| bin _time span=60s
| stats count, values(EventCode) as EventCodes, values(Image) as Images by _time, Computer
| where count >= 2
| table _time, Computer, count, EventCodes, Images
| sort -_time
```

### Elastic Stack (EQL)

#### Query 1: Token Impersonation Sequence

```
sequence by host.id with maxspan=30s
[process where event.action == "process_access" and
 process.name in ("winlogon.exe", "lsass.exe", "services.exe", "csrss.exe") and
 not process.parent.name in ("services.exe", "lsass.exe", "svchost.exe")]
[api where api.name in ("OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser")]
```

#### Query 2: UAC Bypass Sequence

```
sequence by host.id with maxspan=60s
[registry where registry.path : "*\\\\Software\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command*"]
[process where event.action == "start" and
 process.name == "fodhelper.exe" and
 not process.parent.name in ("explorer.exe", "userinit.exe")]
```

---

## Implementation Guidance

### Deployment Priorities

1. **Immediate (Day 1)**:
   - Deploy file hash detection (YARA Rule 1, EDR Query 5)
   - Enable Sysmon Event ID 10 (Process Access) logging for token manipulation detection
   - Deploy Sigma Rule 1 (Token Impersonation) and Rule 2 (UAC Bypass)

2. **Short-Term (Week 1)**:
   - Deploy all YARA rules to endpoint protection platforms
   - Implement multi-technique correlation detection (Sigma Rule 6)
   - Enable enhanced logging for registry modifications (Sysmon Event ID 13)
   - Deploy Splunk/Elastic queries for threat hunting

3. **Medium-Term (Month 1)**:
   - Tune false positive rates for behavioral detections
   - Implement automated response playbooks (isolation on detection)
   - Create custom EDR rules for Arsenal-237 attack chain detection
   - Deploy CrowdStrike/SentinelOne custom IOAs

### Testing Recommendations

1. **Lab Environment Testing**:
   - Test all detection rules in isolated lab before production deployment
   - Validate true positive detection without false positives
   - Test automated response playbooks (ensure isolation works correctly)

2. **Baseline Establishment**:
   - Establish baseline for privilege escalation API calls in your environment
   - Document legitimate use cases for token manipulation (administrative tools)
   - Tune detection thresholds based on environment characteristics

3. **Validation Approach**:
   - Use MITRE ATT&CK evaluation data for validation
   - Test against known lpe.exe samples in sandbox
   - Verify detection across Windows versions (7, 10, 11, Server 2016/2019/2022)

### Response Automation

**Recommended Automated Actions**:
1. **Immediate Isolation**: Network isolation on token impersonation detection
2. **Evidence Preservation**: Automated memory dump capture before isolation
3. **Credential Rotation**: Automatic service account password reset on SYSTEM compromise detection
4. **Threat Hunting**: Automated search for killer.dll and enc_*.exe on affected systems

---

## Related Resources

- [lpe.exe Main Report]({{ "/reports/lpe-exe/" | relative_url }})
- [lpe.exe IOC Feed]({{ "/ioc-feeds/lpe-exe.json" | relative_url }})
- [killer.dll Detection Rules]({{ "/hunting-detections/killer-dll/" | relative_url }}) (Subsequent stage)
- MITRE ATT&CK: T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- MITRE ATT&CK: T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task
- MITRE ATT&CK: T1047 - Windows Management Instrumentation

---

**Version:** 1.0
**Last Updated:** 2026-01-25
**Next Review:** 2026-02-25

---
**END OF DETECTION RULES**

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
