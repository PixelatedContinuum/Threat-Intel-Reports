---
title: Detection Rules - agent_xworm.exe (XWorm RAT)
date: '2026-01-12'
layout: post
permalink: /hunting-detections/agent-xworm-exe/
hide: true
---

# Detection Rules – agent_xworm.exe (XWorm RAT)

## Overview
Comprehensive detection coverage for agent_xworm.exe, a confirmed XWorm RAT sample with hardcoded C2 infrastructure (109.230.231.37). Rules target file hashes, behavioral patterns, network indicators, and XWorm family characteristics.

**Malware Family**: XWorm RAT
**Severity**: CRITICAL
**Last Updated**: 2026-01-12
**Campaign**: Open Directory 109.230.231.37 Distribution

---

## Table of Contents

1. [YARA Rules](#yara-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Network Detection](#network-detection)
6. [PowerShell Detection](#powershell-detection)
7. [Implementation Guidance](#implementation-guidance)

---

## YARA Rules

### Rule 1: agent_xworm.exe Specific Hash Detection

```yaml
rule Agent_Xworm_Specific_Hash {
    meta:
        description = "Detects agent_xworm.exe by file hash and unique authentication secret"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "CRITICAL"
        malware_family = "XWorm RAT"
        hash_sha256 = "0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
        reference = "Open Directory 109.230.231.37 Investigation"
        mitre_attack = "T1059.001, T1071.001, T1132.001, T1564.003"

    strings:
        $c2_ip = "109.230.231.37" ascii
        $auth_secret = "AgentSec_8hJ3kL6mN9pQ2rS5tU8vW1xY4zA7bC0d" ascii
        $agent_filename = "agent_xworm.exe" ascii nocase

    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize < 100KB and
        all of them
}
```

### Rule 2: XWorm RAT Generic Family Detection

```yaml
rule XWorm_RAT_Generic {
    meta:
        description = "Detects XWorm RAT variants based on common code patterns and capabilities"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        malware_family = "XWorm RAT"
        reference = "XWorm family analysis across v4-v6 variants"

    strings:
        // .NET framework indicators
        $dotnet1 = "System.Net.Sockets" ascii wide
        $dotnet2 = "System.Diagnostics.Process" ascii wide
        $dotnet3 = "System.Security.Cryptography" ascii wide
        $dotnet4 = "mscorlib" ascii wide

        // XWorm configuration constants
        $config1 = "HEARTBEAT_MS" ascii wide
        $config2 = "RECONNECT_MS" ascii wide
        $config3 = "SERVER_HOST" ascii wide
        $config4 = "AGENT_SECRET" ascii wide

        // XWorm command handlers
        $cmd1 = "HandleCmd" ascii wide
        $cmd2 = "GetMachineId" ascii wide
        $cmd3 = "GetSysInfo" ascii wide
        $cmd4 = "BuildFrame" ascii wide

        // Stealth and encoding
        $stealth1 = "ShowWindow" ascii wide
        $stealth2 = "GetConsoleWindow" ascii wide
        $encode1 = "ToBase64String" ascii wide
        $encode2 = "FromBase64String" ascii wide

        // Network operations
        $net1 = "TcpClient" ascii wide
        $net2 = "NetworkStream" ascii wide
        $net3 = "GetStream" ascii wide
        $net4 = "_heartbeatThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Strong XWorm signature: config + command handlers + network
            (2 of ($config*) and 2 of ($cmd*) and 2 of ($net*)) or

            // Alternative: .NET + stealth + encoding + network
            (2 of ($dotnet*) and 1 of ($stealth*) and 1 of ($encode*) and 2 of ($net*)) or

            // Authentication secret pattern (common across XWorm variants)
            (1 of ($config*) and 1 of ($encode*) and $net4)
        )
}
```

### Rule 3: XWorm PowerShell Reconnaissance Commands

```yaml
rule XWorm_PowerShell_Recon_Commands {
    meta:
        description = "Detects XWorm embedded PowerShell reconnaissance commands"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"
        reference = "XWorm PowerShell command templates"

    strings:
        $ps1 = "-NoP -C Get-Process|Sort CPU" ascii wide
        $ps2 = "-NoP -C Get-Service|?{$_.Status -eq" ascii wide
        $ps3 = "-NoP -C Get-WmiObject Win32_ComputerSystem" ascii wide
        $ps4 = "PartOfDomain,Domain,DomainRole" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
```

### Rule 4: XWorm Authentication Secret Pattern

```yaml
rule XWorm_AgentSec_Authentication_Pattern {
    meta:
        description = "Detects XWorm AgentSec authentication secret naming pattern"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        reference = "XWorm authentication mechanism analysis"

    strings:
        $pattern1 = /AgentSec_[0-9A-Za-z]{40,50}/ ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $pattern1
}
```

---

## Sigma Detection Rules

### Rule 1: XWorm C2 Connection to 109.230.231.37

```yaml
title: XWorm RAT C2 Connection to Known Infrastructure
id: 0ec3fca5-8ef8-f0d9-f098-cd749dd209fc
status: stable
description: Detects network connections to known XWorm C2 server 109.230.231.37
author: Threat Intelligence Team
date: 2026/01/12
references:
    - agent_xworm.exe analysis report
    - Open Directory 109.230.231.37 investigation
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1132.001
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationIp: '109.230.231.37'
    condition: selection
falsepositives:
    - Unlikely - IP is confirmed malicious infrastructure
level: critical
```

### Rule 2: .NET Process with Hidden Window and Network Activity

```yaml
title: Suspicious .NET Process with Hidden Console and Network Connection
id: 9d963f85-812f-d02e-382a-48c41fc0387e
status: experimental
description: Detects .NET executables hiding console window while establishing network connections (XWorm behavior)
author: Threat Intelligence Team
date: 2026/01/12
references:
    - XWorm RAT behavioral analysis
tags:
    - attack.defense_evasion
    - attack.t1564.003
    - attack.command_and_control
    - attack.t1071.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_dotnet:
        Image|endswith: '.exe'
        CommandLine|contains: 'v4.0.30319'
    selection_hidden:
        # Process created with hidden window
        WindowStyle|contains:
            - 'Hidden'
            - 'SW_HIDE'
    selection_network:
        # Network connection from process
        NetworkConnection: true
    condition: selection_dotnet and selection_hidden and selection_network
falsepositives:
    - Legitimate .NET applications with background network operations
level: high
```

### Rule 3: PowerShell Execution from Suspicious .NET Process

```yaml
title: PowerShell Spawned by .NET Process from User Directory
id: 01027829-5061-9820-bbcd-60efca256c90
status: experimental
description: Detects PowerShell execution from .NET binaries in user-writable directories (XWorm execution pattern)
author: Threat Intelligence Team
date: 2026/01/12
references:
    - XWorm PowerShell execution capability
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: 'powershell.exe'
        CommandLine|contains: '-NoP -C'
    selection_parent:
        ParentImage|contains:
            - '\AppData\'
            - '\Temp\'
            - '\Users\'
        ParentImage|endswith: '.exe'
    filter:
        ParentImage|contains:
            - 'Microsoft'
            - 'Visual Studio'
    condition: selection_powershell and selection_parent and not filter
falsepositives:
    - Legitimate development tools, software installers
level: high
```

### Rule 4: File Creation with XWorm Naming Pattern

```yaml
title: File Creation with XWorm Naming Pattern
id: 0ec3fca5-8ef8-f0d9-f098-cd749dd209aa
status: experimental
description: Detects creation of files matching XWorm naming patterns (agent_xworm, XClient, etc.)
author: Threat Intelligence Team
date: 2026/01/12
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains:
            - 'xworm'
            - 'xclient'
            - 'agent_xworm'
        TargetFilename|endswith: '.exe'
    condition: selection
falsepositives:
    - Security research, malware analysis environments
level: medium
```

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

#### Query 1: Hunt for File Hashes

```kql
// Hunt for known agent_xworm.exe file hashes
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
   or SHA1 == "0102782950619820bbcd60efca256c907403cfb0"
   or MD5 == "9d963f85812fd02e382a48c41fc0387e"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| sort by Timestamp desc
```

#### Query 2: Hunt for Network Connections to C2

```kql
// Hunt for connections to XWorm C2 infrastructure
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "109.230.231.37"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          RemoteIP, RemotePort, RemoteUrl, LocalIP
| sort by Timestamp desc
```

#### Query 3: Hunt for PowerShell Spawned by .NET Processes

```kql
// Hunt for PowerShell execution from .NET processes in user directories
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-NoP -C"
| where InitiatingProcessFolderPath has_any ("AppData", "Users", "Temp")
| join kind=inner (
    DeviceFileEvents
    | where FolderPath has_any ("AppData", "Users", "Temp")
    | where FileName endswith ".exe"
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessFolderPath, SHA256
| sort by Timestamp desc
```

#### Query 4: Hunt for Base64 Encoded .NET Network Activity

```kql
// Identify .NET executables making network connections from user directories
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("AppData", "Temp", "Users")
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has ".exe"
| join kind=inner (
    DeviceFileEvents
    | where FolderPath has_any ("AppData", "Temp")
    | where FileSize < 100000 // Less than 100KB (XWorm typical size)
) on DeviceId, InitiatingProcessFileName
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, RemoteIP, RemotePort, FileSize, SHA256
| sort by Timestamp desc
```

### CrowdStrike Falcon (Event Search)

```
// Hunt for agent_xworm.exe indicators
event_simpleName=ProcessRollup2 OR event_simpleName=DnsRequest OR event_simpleName=NetworkConnectIP4
| search SHA256Hash="0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
   OR FileName="agent_xworm.exe"
   OR CommandLine="*-NoP -C Get-Process*"
   OR CommandLine="*AgentSec_*"
   OR RemoteAddressIP4="109.230.231.37"
| table _time, ComputerName, FileName, CommandLine, RemoteAddressIP4, SHA256Hash
| sort -_time
```

### SentinelOne (Deep Visibility Query)

```sql
-- Hunt for XWorm RAT behavioral patterns
EventType = "Process Creation" OR EventType = "Network" OR EventType = "File Creation"
AND (
    SHA256 = "0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc"
    OR ProcessName CONTAINS "xworm"
    OR CommandLine CONTAINS "AgentSec_"
    OR CommandLine CONTAINS "-NoP -C Get-Process"
    OR DstIP = "109.230.231.37"
    OR (ProcessName ENDS WITH ".exe" AND FilePath CONTAINS "AppData" AND NetworkConnection = true)
)
ORDER BY CreatedAt DESC
```

---

## SIEM Detection Rules

### Splunk SPL Queries

#### Query 1: File Hash Detection

```spl
index=endpoint (sourcetype=file_creation OR sourcetype=process_creation)
| search (SHA256="0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc" OR
          SHA1="0102782950619820bbcd60efca256c907403cfb0" OR
          MD5="9d963f85812fd02e382a48c41fc0387e")
| table _time, host, process_name, file_path, SHA256, user
| sort -_time
```

#### Query 2: C2 Network Communication

```spl
index=network (sourcetype=firewall OR sourcetype=proxy OR sourcetype=dns)
| search dest_ip="109.230.231.37" OR src_ip="109.230.231.37"
| stats count by _time, src_ip, dest_ip, dest_port, action, user, process_name
| sort -_time
```

#### Query 3: PowerShell Execution from User Directories

```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| search (ScriptBlockText="*-NoP -C Get-Process*" OR
          ScriptBlockText="*-NoP -C Get-Service*" OR
          ScriptBlockText="*-NoP -C Get-WmiObject Win32_ComputerSystem*")
| eval process_path=lower(ParentProcessName)
| where match(process_path, "appdata|temp|users")
| table _time, Computer, ParentProcessName, ScriptBlockText, UserID
| sort -_time
```

#### Query 4: XWorm Behavioral Pattern Detection

```spl
index=endpoint sourcetype=process_creation
| search (process_name="*.exe" AND file_path="*\\AppData\\*" AND network_connection=true)
| search (command_line="*v4.0.30319*" OR command_line="*ShowWindow*")
| table _time, host, process_name, file_path, command_line, network_destination, SHA256
| sort -_time
```

### Elastic Stack (EQL)

#### Query 1: Process Creation with Network Connection

```
sequence by host.id with maxspan=5m
  [process where event.action == "start" and
   process.executable : "*\\AppData\\*" and
   process.pe.imphash : "*"]
  [network where event.action == "connection_attempted" and
   destination.ip == "109.230.231.37"]
```

#### Query 2: PowerShell with Suspicious Parent

```
process where event.action == "start" and
  process.name : "powershell.exe" and
  process.command_line : "*-NoP -C*" and
  process.parent.executable : "*\\AppData\\*" and
  not process.parent.code_signature.valid == true
```

#### Query 3: File Creation in User Directories

```
file where event.action == "creation" and
  file.path : "*\\AppData\\*\\*.exe" and
  file.size < 100000 and
  not (
    file.code_signature.valid == true and
    file.code_signature.subject_name : "Microsoft*"
  )
```

---

## Network Detection

### Suricata/Snort Rules

#### Rule 1: Connection to XWorm C2 Server

```
alert tcp $HOME_NET any -> 109.230.231.37 any (
    msg:"MALWARE XWorm RAT C2 Connection to 109.230.231.37";
    flow:to_server,established;
    reference:sha256,0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc;
    classtype:trojan-activity;
    sid:1000010;
    rev:1;
)

alert tcp 109.230.231.37 any -> $HOME_NET any (
    msg:"MALWARE XWorm RAT C2 Response from 109.230.231.37";
    flow:to_client,established;
    reference:sha256,0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc;
    classtype:trojan-activity;
    sid:1000011;
    rev:1;
)
```

#### Rule 2: Base64 Encoded C2 Traffic Pattern

```
alert tcp $HOME_NET any -> any any (
    msg:"SUSPICIOUS Base64 encoded traffic from user directory process";
    flow:to_server,established;
    content:"|41 67 65 6e 74|"; // "Agent" in hex
    pcre:"/^[A-Za-z0-9+\/]{20,}={0,2}$/";
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:suspicious-traffic;
    sid:1000012;
    rev:1;
)
```

#### Rule 3: XWorm Authentication Secret Pattern

```
alert tcp $HOME_NET any -> any any (
    msg:"MALWARE XWorm AgentSec Authentication Secret Detected";
    flow:to_server,established;
    content:"AgentSec_"; nocase;
    pcre:"/AgentSec_[0-9A-Za-z]{40,50}/i";
    classtype:trojan-activity;
    sid:1000013;
    rev:1;
)
```

### Network Monitoring Recommendations

**Firewall Rules:**
```
# Block known malicious C2 infrastructure
DENY IP ANY -> 109.230.231.37 ANY
DENY IP 109.230.231.37 -> ANY ANY
LOG ALL connections to/from 109.230.231.37

# Monitor for unusual .NET process network activity
ALERT TCP $HOME_NET:$UNPRIVILEGED_PORTS -> ANY:$UNPRIVILEGED_PORTS
    from_process_path:*\AppData\*.exe
    from_process_path:*\Temp\*.exe
```

**DNS Monitoring:**
```
# Alert on DNS queries from suspicious processes (XWorm may use domains in variants)
ALERT DNS query
    FROM process:*\AppData\*\*.exe
    WHERE process NOT IN (browser_list, legitimate_updaters)
```

---

## PowerShell Detection

### Enable PowerShell Logging (GPO Configuration)

**Registry Keys:**
```
# Script Block Logging (Event ID 4104 - CRITICAL for XWorm detection)
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
EnableScriptBlockInvocationLogging = 1

# Module Logging
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
EnableModuleLogging = 1
ModuleNames = *

# Transcription
HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
EnableTranscripting = 1
EnableInvocationHeader = 1
OutputDirectory = C:\PowerShellTranscripts
```

### PowerShell Detection Query (Windows Event Log)

```powershell
# Search for XWorm PowerShell reconnaissance commands
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104  # Script Block Logging
} | Where-Object {
    $_.Message -match '-NoP -C Get-Process|Sort CPU' -or
    $_.Message -match '-NoP -C Get-Service' -or
    $_.Message -match 'Get-WmiObject Win32_ComputerSystem' -or
    $_.Message -match 'AgentSec_'
} | Select-Object TimeCreated, Message, ProcessId | Format-List
```

### Splunk Query for XWorm PowerShell Activity

```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| search (
    ScriptBlockText IN ("*Get-Process|Sort CPU*", "*Get-Service|?{$_.Status*", "*Win32_ComputerSystem*") OR
    ParentProcessName IN ("*agent*.exe", "*xworm*.exe") OR
    ScriptBlockText="*AgentSec_*"
)
| table _time, Computer, ParentProcessName, ScriptBlockText, UserID
| sort -_time
```

---

## Implementation Guidance

### Priority 1: Immediate Deployment (0-24 hours)

1. **Network IOCs** - Add to:
   - Firewall deny lists (109.230.231.37) - CRITICAL
   - IDS/IPS signatures (Suricata/Snort rules)
   - Threat intelligence feeds
   - DNS sinkholes (if applicable)

2. **Hash-Based Detection** - Deploy to:
   - EDR platforms (CrowdStrike, SentinelOne, Microsoft Defender)
   - Antivirus/endpoint protection
   - File integrity monitoring tools
   - Application whitelisting systems (block list)

3. **YARA Rules** - Deploy to:
   - Email gateways (scan attachments)
   - Web proxies (scan downloads)
   - File servers (retroactive scan)
   - EDR systems with YARA support

### Priority 2: Enhanced Monitoring (24-48 hours)

1. **Sigma Rules** - Deploy to:
   - SIEM platforms (Splunk, Elastic, QRadar)
   - Windows Event Log aggregation
   - EDR platforms with Sigma support

2. **PowerShell Logging** - Enable via GPO:
   - Script Block Logging (Event ID 4104) - CRITICAL
   - Module Logging for all modules
   - Transcription logging with centralized storage

3. **EDR Hunting Queries** - Execute on:
   - All endpoints (comprehensive hunt)
   - High-value targets (executives, IT admins, finance)
   - Systems with recent network activity to 109.230.231.37

### Priority 3: Long-Term Monitoring (Week 1+)

1. **Behavioral Analytics**:
   - UEBA for anomalous .NET process behavior
   - Machine learning for XWorm pattern detection
   - Network traffic anomaly detection (Base64-encoded C2)

2. **Threat Intelligence Integration**:
   - Add IOCs to threat intelligence platforms (TIP)
   - Monitor for XWorm family evolution (v6 variants)
   - Track secondary malware (AsyncRAT, LockBit) associated with XWorm

3. **Continuous Improvement**:
   - Review detection effectiveness weekly
   - Tune rules to reduce false positives
   - Update based on XWorm v6 evolution
   - Conduct purple team exercises

---

## Testing & Validation

### Safe Testing Procedures

**DO NOT:**
- Execute live malware on production systems
- Test with actual agent_xworm.exe outside isolated labs
- Disable security controls to test effectiveness

**DO:**
- Create test files with matching strings (non-malicious harness)
- Use YARA rule testing frameworks (yara-ci)
- Validate Sigma rules in test SIEM instances
- Test EDR queries against historical data
- Conduct purple team exercises in controlled environments

### Validation Checklist

- [ ] YARA rules tested against sample (isolated lab only)
- [ ] Sigma rules validated in test SIEM
- [ ] EDR queries return expected results
- [ ] Network signatures tested in lab
- [ ] False positive assessment completed
- [ ] Alert tuning performed
- [ ] Incident response procedures documented
- [ ] SOC team trained on XWorm detection
- [ ] Escalation paths defined

---

## Maintenance & Updates

**Review Schedule:**
- **Daily**: Monitor alerts for new detections and false positives
- **Weekly**: Check for false positives and tune rules
- **Monthly**: Review detection effectiveness (true positive rate)
- **Quarterly**: Update rules based on XWorm family evolution

**Update Procedure:**
1. Monitor threat intelligence for XWorm v6 updates
2. Analyze new samples if discovered
3. Update YARA/Sigma rules with new indicators
4. Re-test in lab environment
5. Deploy updated rules to production
6. Document changes in version control
7. Communicate updates to SOC team

**Metrics to Track:**
- True positive detection rate
- False positive rate by rule
- Mean time to detect (MTTD)
- Coverage across attack chain stages
- Alert volume trends
- Remediation success rate

---

## Related Resources

- [agent_xworm.exe Main Report]({{ "/reports/agent-xworm-exe/" | relative_url }})
- [agent_xworm.exe IOC Feed]({{ "/ioc-feeds/agent-xworm-exe.json" | relative_url }})
- MITRE ATT&CK Framework: https://attack.mitre.org/
- XWorm Family Intelligence: Malpedia, ANY.RUN, Huntress

---

**Version:** 1.0
**Last Updated:** 2026-01-12
**Next Review:** 2026-02-12

---
**END OF DETECTION RULES**
