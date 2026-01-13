---
title: Detection Rules - agent.exe (PoetRAT)
date: '2026-01-12'
layout: post
permalink: /hunting-detections/agent-exe/
hide: true
---

# Detection Rules – agent.exe (PoetRAT)

## Overview
Comprehensive detection coverage for agent.exe includes host-based indicators, process behavior patterns, and network signatures. Rules are provided in YARA and Sigma formats for SIEM/EDR integration and proactive threat hunting.

**Malware Family**: PoetRAT (MODERATE confidence)
**Severity**: CRITICAL
**Last Updated**: 2026-01-12

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

### Rule 1: agent.exe PoetRAT Comprehensive Detection

```yaml
rule Agent_exe_PoetRAT_Comprehensive {
    meta:
        description = "Detects agent.exe PoetRAT malware based on file hashes, strings, and behavioral indicators"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "CRITICAL"
        malware_family = "PoetRAT"
        hash_agent = "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385"
        hash_dropped = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
        reference = "Open Directory 109.230.231.37 Investigation"
        mitre_attack = "T1547.001, T1036.005, T1622, T1056.001, T1573"

    strings:
        // File hash identifiers
        $hash_agent = "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385" nocase
        $hash_windefender = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1" nocase

        // Unique string artifacts
        $str_windefendersvc = "WinDefenderSvc.exe" ascii wide nocase
        $str_defender_update = "WindowsDefenderUpdate" ascii wide nocase
        $str_marker = ".wd_installed" ascii wide

        // Golang compilation artifacts
        $golang_runtime1 = "runtime.main" ascii
        $golang_runtime2 = "runtime.goexit" ascii
        $golang_runtime3 = "go.buildid" ascii
        $golang_runtime4 = "runtime.morestack" ascii

        // Anti-debugging API imports
        $antidebug1 = "NtQueryInformationProcess" ascii wide
        $antidebug2 = "SetConsoleCtrlHandler" ascii wide
        $antidebug3 = "IsDebuggerPresent" ascii wide

        // Cryptographic library indicators
        $crypto1 = "crypto/aes" ascii
        $crypto2 = "crypto/rsa" ascii
        $crypto3 = "crypto/sha" ascii
        $crypto4 = "chacha20" ascii nocase
        $crypto5 = "golang.org/x/crypto" ascii

        // Network capability indicators
        $net1 = "net.Listen" ascii
        $net2 = "net.Dial" ascii
        $net3 = "TCPConn" ascii
        $net4 = "net/http" ascii

        // Registry persistence indicators
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "RegSetValueEx" ascii wide

        // Surveillance capabilities
        $surv1 = "GetAsyncKeyState" ascii wide
        $surv2 = "SetWindowsHookEx" ascii wide
        $surv3 = "GetForegroundWindow" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE file signature
        (
            any of ($hash_*) or // Known file hash match
            (
                (2 of ($str_*)) and // Unique string combination
                (2 of ($golang_*)) and // Golang compilation
                (1 of ($antidebug_*)) and // Anti-debugging
                (1 of ($crypto_*)) // Cryptographic capabilities
            ) or
            (
                (3 of ($golang_*)) and // Strong Golang indicator
                (2 of ($crypto_*)) and // Strong crypto indicator
                (1 of ($str_*)) and // Unique string match
                (1 of ($net_*)) and // Network capability
                (1 of ($surv_*)) // Surveillance capability
            )
        )
}
```

### Rule 2: PoetRAT Persistence Components

```yaml
rule PoetRAT_Persistence_Component {
    meta:
        description = "Detects PoetRAT persistence components (WinDefenderSvc.exe and related files)"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        hash1 = "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"

    strings:
        $defender_svc = "WinDefenderSvc.exe" ascii wide nocase
        $defender_update = "WindowsDefenderUpdate" ascii wide nocase
        $startup_path = "Start Menu\\Programs\\Startup" ascii wide nocase
        $marker_file = ".wd_installed" ascii wide

        // Golang indicators
        $go1 = "Go build ID:" ascii
        $go2 = "runtime.main" ascii
        $go3 = "runtime.goexit" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($defender_svc and $defender_update) or
            ($defender_svc and $startup_path) or
            ($marker_file and any of ($go*))
        )
}
```

### Rule 3: Golang RAT Generic Detection

```yaml
rule Golang_RAT_Generic_Detection {
    meta:
        description = "Detects Golang-compiled RAT with common capabilities (broader detection)"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"
        reference = "Generic Golang RAT detection pattern"

    strings:
        // Golang runtime
        $go_runtime1 = "runtime.main" ascii
        $go_runtime2 = "runtime.goexit" ascii
        $go_runtime3 = "runtime.morestack" ascii
        $go_runtime4 = "go.buildid" ascii

        // RAT capabilities
        $cap_keylog = "GetAsyncKeyState" ascii wide
        $cap_keylog2 = "SetWindowsHookEx" ascii wide
        $cap_rdp = "TermService" ascii wide nocase
        $cap_ps = "powershell" ascii wide nocase
        $cap_service = "CreateService" ascii wide

        // Crypto for C2
        $crypto_aes = "crypto/aes" ascii
        $crypto_tls = "crypto/tls" ascii
        $crypto_modern = "chacha20" ascii nocase

        // Network
        $net_tcp = "net.Dial" ascii
        $net_http = "net/http" ascii
        $net_listen = "net.Listen" ascii

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($go_runtime*)) and
        (2 of ($cap_*)) and
        (1 of ($crypto_*)) and
        (1 of ($net_*))
}
```

---

## Sigma Detection Rules

### Rule 1: WinDefenderSvc Persistence Detection

```yaml
title: Suspicious WinDefenderSvc.exe in Startup Folder
id: e7f9a29d-de30-7aff-f419-1dbc14a97440
status: experimental
description: Detects creation of WinDefenderSvc.exe in user Startup folder (PoetRAT persistence)
author: Threat Intelligence Team
date: 2026/01/12
references:
    - agent.exe analysis report
    - Open Directory 109.230.231.37 investigation
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\Start Menu\Programs\Startup\WinDefenderSvc.exe'
    filter:
        # Exclude legitimate Windows Defender (signed by Microsoft)
        Signature: 'Microsoft Corporation'
        SignatureStatus: 'Valid'
    condition: selection and not filter
falsepositives:
    - Legitimate Windows Defender components (should be signed by Microsoft)
level: critical
```

### Rule 2: Registry Persistence - WindowsDefenderUpdate

```yaml
title: Suspicious Registry Run Key - WindowsDefenderUpdate
id: 4e856041-0182-42c6-2b38-48d63b94c376
status: experimental
description: Detects creation of WindowsDefenderUpdate registry Run key (PoetRAT persistence)
author: Threat Intelligence Team
date: 2026/01/12
references:
    - agent.exe analysis report
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderUpdate'
    filter:
        # Exclude if pointing to legitimate Microsoft-signed binary
        Details|contains: 'C:\Program Files\Windows Defender\'
    condition: selection and not filter
falsepositives:
    - Legitimate Windows Defender update mechanisms (extremely rare)
level: critical
```

### Rule 3: Golang Executable with Anti-Debug and Persistence

```yaml
title: Golang Executable Creating Persistence with Anti-Debug
id: b1d5e55b-1c15-b7cb-8391-38625d9d2efa
status: experimental
description: Detects Golang-compiled executable creating persistence and using anti-debugging
author: Threat Intelligence Team
date: 2026/01/12
references:
    - agent.exe analysis report
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.defense_evasion
    - attack.t1622
logsource:
    product: windows
    category: process_creation
detection:
    selection_golang:
        # Golang executables often have specific characteristics
        Image|contains:
            - 'go.exe'
            - 'runtime.main'
    selection_antidebug:
        CallTrace|contains:
            - 'NtQueryInformationProcess'
            - 'SetConsoleCtrlHandler'
            - 'IsDebuggerPresent'
    selection_persistence:
        CommandLine|contains:
            - '\Startup\'
            - 'CurrentVersion\Run'
            - 'schtasks'
    condition: selection_golang and (selection_antidebug or selection_persistence)
falsepositives:
    - Legitimate Golang applications with anti-tampering protections
level: high
```

### Rule 4: Installation Marker File Detection

```yaml
title: PoetRAT Installation Marker File (.wd_installed)
id: 6b86b273-ff34-fce1-9d6b-804eff5a3f57
status: experimental
description: Detects creation of .wd_installed marker file indicating PoetRAT infection
author: Threat Intelligence Team
date: 2026/01/12
references:
    - agent.exe analysis report
tags:
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\.wd_installed'
        TargetFilename|contains: '\AppData\Local\Temp\'
    condition: selection
falsepositives:
    - Unlikely - very specific naming pattern
level: critical
```

---

## EDR Hunting Queries

### Microsoft Defender for Endpoint (KQL)

#### Query 1: Hunt for agent.exe File Hashes

```kql
// Hunt for known agent.exe and WinDefenderSvc.exe file hashes
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (
    "e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385",
    "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1"
) or SHA1 == "e0fe41acd28cae74d75fcbf2f9309ff523c0f36a"
   or MD5 == "b1d5e55b1c15b7cb839138625d9d2efa"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

#### Query 2: Hunt for Persistence Mechanisms

```kql
// Hunt for WinDefenderSvc.exe in Startup folder or WindowsDefenderUpdate Run key
union
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\Start Menu\Programs\Startup"
    | where FileName =~ "WinDefenderSvc.exe"
    | extend DetectionMethod = "Startup Folder"
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
    | where RegistryValueName =~ "WindowsDefenderUpdate"
    | extend DetectionMethod = "Registry Run Key"
),
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has @"\AppData\Local\Temp"
    | where FileName =~ ".wd_installed"
    | extend DetectionMethod = "Marker File"
)
| project Timestamp, DeviceName, DetectionMethod, FileName, FolderPath, RegistryKey, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp desc
```

#### Query 3: Hunt for Golang Executables with Network Activity

```kql
// Identify Golang executables making network connections from user directories
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any ("AppData", "Users", "Temp")
| where RemoteIPType == "Public"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("runtime.main", "go.exe")
       or FileName has "WinDefenderSvc"
       or FileName has "agent.exe"
) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc
```

#### Query 4: Hunt for Unsigned "Defender" Processes

```kql
// Find unsigned or non-Microsoft-signed processes masquerading as Windows Defender
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("Defender", "WinDefend")
| where not (IsTrusted == true and SignerInfo has "Microsoft")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine, SignerInfo, IsTrusted
| sort by Timestamp desc
```

### CrowdStrike Falcon (Event Search)

```
// Hunt for agent.exe indicators
event_simpleName=ProcessRollup2 OR event_simpleName=DnsRequest OR event_simpleName=NetworkConnectIP4 OR event_simpleName=AsepValueUpdate
| search SHA256Hash IN ("e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385", "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1")
   OR FileName IN ("agent.exe", "WinDefenderSvc.exe")
   OR TargetFileName="*\\Startup\\WinDefenderSvc.exe"
   OR RegistryValueName="WindowsDefenderUpdate"
   OR TargetFileName="*\\.wd_installed"
| table _time, ComputerName, FileName, CommandLine, TargetFileName, RegistryPath, RemoteAddressIP4
| sort -_time
```

### SentinelOne (Deep Visibility Query)

```sql
-- Hunt for PoetRAT persistence and network activity
EventType = "Process Creation" OR EventType = "File Creation" OR EventType = "Registry" OR EventType = "Network"
AND (
    SHA256 IN ("e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385", "4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1")
    OR ProcessName CONTAINS "WinDefenderSvc.exe"
    OR FilePath CONTAINS "\Startup\WinDefenderSvc.exe"
    OR FilePath CONTAINS ".wd_installed"
    OR RegistryPath CONTAINS "WindowsDefenderUpdate"
    OR DstIP = "109.230.231.37"
)
ORDER BY CreatedAt DESC
```

---

## SIEM Detection Rules

### Splunk SPL Queries

#### Query 1: File Hash Detection

```spl
index=endpoint sourcetype=file_creation OR sourcetype=process_creation
| search (SHA256="e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385" OR
          SHA256="4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1" OR
          SHA1="e0fe41acd28cae74d75fcbf2f9309ff523c0f36a" OR
          MD5="b1d5e55b1c15b7cb839138625d9d2efa")
| table _time, host, process_name, file_path, SHA256, user
| sort -_time
```

#### Query 2: Persistence Mechanism Detection

```spl
index=windows (sourcetype=WinRegistry OR sourcetype=file_creation OR sourcetype=Sysmon)
| search (
    (registry_path="*\\CurrentVersion\\Run\\WindowsDefenderUpdate") OR
    (file_path="*\\Startup\\WinDefenderSvc.exe") OR
    (file_name=".wd_installed" file_path="*\\AppData\\Local\\Temp\\*")
)
| eval detection_type=case(
    match(registry_path, "WindowsDefenderUpdate"), "Registry Persistence",
    match(file_path, "Startup"), "Startup Folder Persistence",
    match(file_name, ".wd_installed"), "Installation Marker"
)
| table _time, host, detection_type, registry_path, file_path, file_name, user, process_name
| sort -_time
```

#### Query 3: Network IOC Detection

```spl
index=network sourcetype=firewall OR sourcetype=proxy OR sourcetype=dns
| search dest_ip="109.230.231.37" OR src_ip="109.230.231.37"
| stats count by _time, src_ip, dest_ip, dest_port, action, user, process_name
| sort -_time
```

#### Query 4: Golang RAT Behavioral Detection

```spl
index=endpoint sourcetype=process_creation
| search (
    (process_name="*.exe" AND (cmdline="*runtime.main*" OR cmdline="*go.exe*")) AND
    (file_path="*\\AppData\\*" OR file_path="*\\Temp\\*" OR file_path="*\\Users\\*")
)
| where NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe"))
| table _time, host, process_name, file_path, cmdline, parent_process, user
| sort -_time
```

### Elastic Stack (EQL/KQL)

#### Query 1: Process Creation with Persistence

```
process where event.action == "start" and
(
  process.executable : "*\\Startup\\WinDefenderSvc.exe" or
  process.name : "WinDefenderSvc.exe" or
  process.command_line : "*WindowsDefenderUpdate*"
) and not (
  process.code_signature.valid == true and
  process.code_signature.subject_name == "Microsoft Corporation"
)
```

#### Query 2: Registry Modification for Persistence

```
registry where event.action == "modification" and
  registry.path : "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefenderUpdate"
```

#### Query 3: File Creation in Startup Folder

```
file where event.action == "creation" and
  file.path : "*\\Start Menu\\Programs\\Startup\\WinDefenderSvc.exe" and
  not (
    file.code_signature.valid == true and
    file.code_signature.subject_name == "Microsoft Corporation"
  )
```

#### Query 4: Installation Marker Detection

```
file where event.action == "creation" and
  file.path : "*\\AppData\\Local\\Temp\\.wd_installed"
```

---

## Network Detection

### Suricata/Snort Rules

#### Rule 1: Connection to Distribution IP

```
alert tcp $HOME_NET any -> 109.230.231.37 any (
    msg:"MALWARE PoetRAT agent.exe connection to distribution IP";
    flow:to_server,established;
    reference:sha256,e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)

alert tcp 109.230.231.37 any -> $HOME_NET any (
    msg:"MALWARE PoetRAT agent.exe inbound from distribution IP";
    flow:to_client,established;
    reference:sha256,e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385;
    classtype:trojan-activity;
    sid:1000002;
    rev:1;
)
```

#### Rule 2: Golang C2 Traffic Pattern Detection

```
alert tcp $HOME_NET any -> any any (
    msg:"SUSPICIOUS Golang executable encrypted C2 traffic pattern";
    flow:to_server,established;
    content:"Go"; http_user_agent;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:suspicious-traffic;
    sid:1000003;
    rev:1;
)
```

### Network Monitoring Recommendations

**Firewall Rules:**
```
# Block known malicious distribution IP
DENY IP ANY -> 109.230.231.37 ANY
DENY IP 109.230.231.37 -> ANY ANY
LOG ALL connections to/from 109.230.231.37

# Monitor for unusual ports from user directories
ALERT TCP $HOME_NET:$UNPRIVILEGED_PORTS -> ANY:$UNPRIVILEGED_PORTS
    from_process_path:*\AppData\*
    from_process_path:*\Users\*\Temp\*
```

**Proxy/Web Gateway:**
```
# Block distribution IP in web proxy
DENY URL http://109.230.231.37/*
DENY URL https://109.230.231.37/*

# Alert on executable downloads from suspicious sources
ALERT HTTP GET *.exe
    WHERE source_reputation:LOW OR source_reputation:UNKNOWN
    WHERE size > 100KB AND size < 5MB
```

**DNS Monitoring:**
```
# Monitor for DNS queries from suspicious processes
ALERT DNS query
    FROM process:*\AppData\*\*.exe
    WHERE process NOT IN (trusted_application_list)

# Alert on newly registered domains contacted by executables
ALERT DNS query
    FROM process:*.exe
    WHERE domain_age < 30_days
    WHERE process_path NOT IN (browser_list)
```

---

## PowerShell Detection

### Enable PowerShell Logging (GPO Configuration)

**Registry Keys to Enable:**
```
# Script Block Logging (captures all PowerShell commands)
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
EnableScriptBlockInvocationLogging = 1

# Module Logging
HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
EnableModuleLogging = 1
ModuleNames = *

# Transcription (records all PowerShell activity)
HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
EnableTranscripting = 1
EnableInvocationHeader = 1
OutputDirectory = C:\PowerShellTranscripts
```

### PowerShell Detection Query (Windows Event Log)

```powershell
# Search for PowerShell execution from agent.exe or WinDefenderSvc.exe
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104  # Script Block Logging
} | Where-Object {
    $_.Message -match 'agent\.exe|WinDefenderSvc\.exe|WindowsDefenderUpdate'
} | Select-Object TimeCreated, Message, ProcessId | Format-List
```

### Suspicious PowerShell Patterns (Splunk)

```spl
# Splunk query for suspicious PowerShell from PoetRAT
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
| search (
    ParentProcessName="*agent.exe" OR
    ParentProcessName="*WinDefenderSvc.exe" OR
    ScriptBlockText IN ("*Invoke-WebRequest*", "*DownloadString*", "*IEX*", "*Invoke-Expression*", "*-EncodedCommand*")
)
| table _time, Computer, ParentProcessName, ScriptBlockText, UserID
| sort -_time
```

---

## Implementation Guidance

### Priority 1: Immediate Deployment (0-24 hours)

1. **YARA Rules** - Deploy to:
   - Endpoint antivirus/EDR systems
   - Email gateways (scan attachments)
   - Web proxies (scan downloads)
   - File servers (retroactive scan)

2. **Network IOCs** - Add to:
   - Firewall deny lists (109.230.231.37)
   - IDS/IPS signatures (Suricata/Snort rules)
   - DNS sinkholes (if applicable)
   - Threat intelligence feeds

3. **Hash-Based Detection** - Deploy to:
   - EDR platforms (CrowdStrike, SentinelOne, Microsoft Defender)
   - SIEM alert rules
   - File integrity monitoring tools
   - Application whitelisting systems (block list)

### Priority 2: Enhanced Monitoring (24-48 hours)

1. **Sigma Rules** - Deploy to:
   - SIEM platforms (Splunk, Elastic, QRadar)
   - Windows Event Log aggregation systems
   - EDR platforms with Sigma rule support

2. **EDR Hunting Queries** - Execute on:
   - All endpoints (comprehensive hunt)
   - High-value targets (executives, finance, IT admins)
   - Systems with access to sensitive data
   - Systems recently communicating with 109.230.231.37

3. **PowerShell Logging** - Enable via GPO:
   - Script Block Logging (Event ID 4104)
   - Module Logging for all modules
   - Transcription logging with centralized storage

### Priority 3: Long-Term Monitoring (Week 1+)

1. **Behavioral Analytics** - Implement:
   - UEBA (User and Entity Behavior Analytics) for anomalous activity
   - Machine learning-based detection for Golang malware patterns
   - Network traffic anomaly detection (beaconing, encrypted C2)
   - File creation pattern monitoring in startup directories

2. **Threat Intelligence Integration**:
   - Add IOCs to threat intelligence platforms (TIP)
   - Share indicators with ISACs/ISAOs if appropriate
   - Monitor for infrastructure expansion (new IPs, domains)
   - Track PoetRAT family evolution and new variants

3. **Continuous Improvement**:
   - Review detection effectiveness weekly
   - Tune rules to reduce false positives
   - Update based on threat intelligence evolution
   - Conduct purple team exercises to validate coverage

---

## Testing & Validation

### Safe Testing Procedures

**DO NOT:**
- Execute live malware samples on production systems
- Test detection rules with actual agent.exe malware outside isolated environments
- Disable security controls to test detection effectiveness

**DO:**
- Create test files with matching strings (non-malicious test harness)
- Use YARA rule testing frameworks (yara-ci, YARA Rule Tester)
- Validate Sigma rules in test SIEM instances
- Test EDR queries against historical data before alerting
- Conduct purple team exercises in controlled lab environments

### Validation Checklist

- [ ] YARA rules tested against sample (in isolated lab only)
- [ ] Sigma rules validated in test SIEM environment
- [ ] EDR queries return expected results on test data
- [ ] Network signatures tested in lab environment
- [ ] False positive assessment completed
- [ ] Alert tuning performed
- [ ] Incident response procedures documented
- [ ] SOC team trained on detection alerts
- [ ] Escalation paths defined and tested
- [ ] Remediation playbooks prepared

---

## Maintenance & Updates

**Review Schedule:**
- **Daily**: Monitor alerts for new detections and false positives
- **Weekly**: Check for false positives and tune rules
- **Monthly**: Review detection effectiveness (true positive rate, coverage)
- **Quarterly**: Update rules based on threat intelligence evolution
- **As needed**: Update when new PoetRAT variants discovered

**Update Procedure:**
1. Monitor threat intelligence for PoetRAT family updates
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

## Contact & Support

For questions about these detection rules or to report false positives, contact:
- **Security Operations Center (SOC)**
- **Incident Response Team**
- **Threat Intelligence Team**

**Version:** 1.0
**Last Updated:** 2026-01-12
**Next Review:** 2026-02-12

---

## Related Resources

- [agent.exe Main Report]({{ "/reports/agent-exe/" | relative_url }})
- [agent.exe IOC Feed]({{ "/ioc-feeds/agent-exe.json" | relative_url }})
- MITRE ATT&CK Framework: https://attack.mitre.org/
- PoetRAT Threat Intelligence: Cisco Talos (2020)

---
**END OF DETECTION RULES**
