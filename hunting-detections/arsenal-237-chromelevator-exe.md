---
title: Detection Rules - chromelevator.exe - Browser Credential Theft
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-chromelevator-exe/
hide: true
---

# chromelevator.exe Detection Rules & Hunting Queries

**Malware:** Browser Credential Extraction Tool (Arsenal-237 Campaign)
**Detection Date:** 2026-01-26
**Severity:** CRITICAL

---

## YARA Rules

### Rule 1: Chromelevator Browser Credential Extraction Tool

```yara
rule Chromelevator_Browser_Credential_Extraction {
    meta:
        description = "Detects chromelevator.exe browser credential extraction tool"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        category = "trojan"
        family = "Arsenal-237"

    strings:
        // Primary identifiers
        $filename = "chromelevator.exe" nocase ascii
        $payload = "PAYLOAD_DLL" nocase ascii

        // Browser targeting
        $chrome = "chrome.exe" nocase ascii
        $brave = "brave.exe" nocase ascii
        $edge = "msedge.exe" nocase ascii

        // Functional strings
        $named_pipe = "Named pipe server created" nocase ascii
        $reflective = "ReflectiveLoader" nocase ascii
        $extraction = "Extracted" nocase ascii
        $cookies = "cookies" nocase ascii
        $passwords = "passwords" nocase ascii
        $payments = "payments" nocase ascii

        // Command-line arguments
        $verbose = "--verbose" nocase ascii
        $fingerprint = "--fingerprint" nocase ascii
        $output = "--output-path" nocase ascii
        $help = "--help" nocase ascii

        // API calls
        $create_pipe = "CreateNamedPipeW" nocase ascii
        $connect_pipe = "ConnectNamedPipe" nocase ascii
        $find_resource = "FindResourceW" nocase ascii
        $load_resource = "LoadResource" nocase ascii

    condition:
        // Definite detection: filename + payload + extraction capability
        ($filename and $payload and ($extraction or ($cookies and $passwords))) or

        // Strong detection: multiple browser targets + extraction capability
        (3 of ($chrome, $brave, $edge) and 2 of ($extraction, $cookies, $passwords)) or

        // Behavioral detection: reflective loading + named pipe + browser targeting
        ($reflective and $named_pipe and any of ($chrome, $brave, $edge)) or

        // Command-line argument signature
        (2 of ($verbose, $fingerprint, $output, $help) and any of ($chrome, $brave, $edge))
}
```

### Rule 2: Arsenal-237 Direct Syscall Framework

```yara
rule Arsenal237_Direct_Syscall_Framework {
    meta:
        description = "Detects direct syscall implementation used by Arsenal-237 components"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        category = "evasion"

    strings:
        // Zw* syscall functions (EDR bypass)
        $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
        $zw_write = "ZwWriteVirtualMemory" nocase ascii
        $zw_read = "ZwReadVirtualMemory" nocase ascii
        $zw_protect = "ZwProtectVirtualMemory" nocase ascii
        $zw_create_thread = "ZwCreateThreadEx" nocase ascii
        $zw_open_proc = "ZwOpenProcess" nocase ascii
        $zw_query_proc = "ZwQueryInformationProcess" nocase ascii
        $zw_context = "ZwGetContextThread" nocase ascii
        $zw_set_context = "ZwSetContextThread" nocase ascii
        $zw_resume = "ZwResumeThread" nocase ascii

        // Multiple syscalls indicate framework
        $zw_pattern = /Zw[A-Z][a-zA-Z]+/

    condition:
        // Multiple critical syscalls indicate EDR bypass framework
        (5 of ($zw_alloc, $zw_write, $zw_protect, $zw_create_thread, $zw_open_proc)) or

        // Pattern-based detection of systematic syscall usage
        (all of them and #zw_pattern >= 10)
}
```

### Rule 3: Reflective DLL Injection Pattern

```yara
rule Reflective_DLL_Injection_Framework {
    meta:
        description = "Detects reflective DLL injection implementation"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        category = "execution"

    strings:
        // PE header parsing
        $dos_header = "MZ" at 0
        $nt_header = "PE" at 60
        $pe_sig = { 50 45 00 00 }  // "PE\x00\x00"

        // Reflective loader
        $reflective_loader = "ReflectiveLoader" nocase ascii
        $reflective_export = "reflective" nocase ascii wide

        // PE parsing functions
        $dos_hdr = "DOS" nocase ascii
        $file_hdr = "File" nocase ascii
        $opt_hdr = "Optional" nocase ascii

        // Memory injection indicators
        $alloc = "VirtualAllocEx" nocase ascii
        $write = "WriteProcessMemory" nocase ascii
        $protect = "VirtualProtectEx" nocase ascii
        $create_remote = "CreateRemoteThread" nocase ascii

        // Direct syscall injection
        $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
        $zw_write = "ZwWriteVirtualMemory" nocase ascii
        $zw_protect = "ZwProtectVirtualMemory" nocase ascii
        $zw_create = "ZwCreateThreadEx" nocase ascii

    condition:
        // Reflective DLL loading pattern
        ($reflective_loader and $dos_header and $nt_header) or

        // Reflective injection via direct syscalls
        ($reflective_loader and all of ($zw_alloc, $zw_write, $zw_protect, $zw_create)) or

        // Reflective injection via Windows APIs
        ($reflective_loader and all of ($alloc, $write, $protect, $create_remote))
}
```

---

## Sigma Rules

### Rule 1: Process Creation - chromelevator.exe Execution

```yaml
title: Suspicious Process Creation - chromelevator.exe
description: Detects execution of chromelevator.exe browser credential extraction tool
status: experimental
author: Threat Intelligence Team
date: 2026/01/26
severity: CRITICAL
tags:
  - attack.credential_access
  - attack.t1555.003
  - attack.defense_evasion
  - malware.arsenal237

detection:
  selection_image:
    Image|endswith: 'chromelevator.exe'

  selection_commandline:
    CommandLine|contains:
      - '--verbose'
      - '--fingerprint'
      - '--output-path'

  filter_legitimate:
    ParentImage|contains:
      - 'chrome.exe'
      - 'msedge.exe'
      - 'firefox.exe'

  condition: selection_image and (selection_commandline or 1 of selection_*)

falsepositives:
  - Legitimate browser management tools
  - System administrators testing security

level: critical
```

### Rule 2: Named Pipe Creation - Process Injection C2

```yaml
title: Suspicious Named Pipe Creation - Reflective Injection C2
description: Detects named pipe creation patterns associated with process injection and C2 communication
status: experimental
author: Threat Intelligence Team
date: 2026/01/26
severity: CRITICAL
tags:
  - attack.execution
  - attack.t1055.001
  - attack.command_and_control
  - malware.arsenal237

detection:
  selection_event:
    EventID:
      - 23  # Pipe created
      - 24  # Pipe connected

  selection_pipe_pattern:
    PipeName|contains:
      - '\\.\pipe\'

  selection_source_process:
    Image|endswith:
      - 'chromelevator.exe'
      - 'explorer.exe'  # for credential harvesting variants
      - 'svchost.exe'   # for persistence variants

  filter_legitimate:
    PipeName|contains:
      - 'lsass'
      - 'winlogon'
      - 'winspool'
      - 'netdde'

  condition: selection_event and selection_pipe_pattern and selection_source_process and not filter_legitimate

falsepositives:
  - Legitimate RPC communication
  - Named pipe usage by antivirus/EDR solutions

level: critical
```

### Rule 3: Process Injection Pattern Detection

```yaml
title: Suspicious Process Injection - Memory Allocation Pattern
description: Detects process injection through memory allocation, writing, and thread creation sequence
status: experimental
author: Threat Intelligence Team
date: 2026/01/26
severity: CRITICAL
tags:
  - attack.execution
  - attack.t1055.001
  - attack.defense_evasion

detection:
  selection_target_processes:
    TargetImage|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'
      - 'firefox.exe'

  selection_suspicious_apis:
    EventType:
      - 'CallCreateRemoteThreadApi'
      - 'CallVirtualAllocExApi'
      - 'CallWriteProcessMemoryApi'
      - 'CallVirtualProtectExApi'
    EventID: 10  # Image loaded

  selection_sequence:
    API|contains|all:
      - 'AllocateVirtualMemory'
      - 'WriteVirtualMemory'
      - 'ProtectVirtualMemory'
      - 'CreateThreadEx'

  condition: selection_target_processes and 3 of (selection_suspicious_apis, selection_sequence)

falsepositives:
  - Legitimate software using process injection (installers, debuggers)

level: high
```

### Rule 4: Browser Database Access - Credential Theft

```yaml
title: Suspicious Browser Credential Database Access
description: Detects access to Chrome/Brave/Edge credential databases by non-browser processes
status: experimental
author: Threat Intelligence Team
date: 2026/01/26
severity: CRITICAL
tags:
  - attack.credential_access
  - attack.t1555.003

detection:
  selection_browser_db_access:
    TargetFilename|contains|all:
      - 'User Data'
      - 'Login Data'
    OR:
      - TargetFilename|contains:
          - 'Chrome\\User Data\\Default\\Cookies'
          - 'Brave-Browser\\User Data\\Default\\Cookies'
          - 'Edge\\User Data\\Default\\Cookies'
          - 'Google\\Chrome\\User Data\\Default\\Web Data'

  selection_process_exclusion:
    Image|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'
      - 'firefox.exe'

  filter_system_process:
    User|contains: 'SYSTEM'

  condition: selection_browser_db_access and not (selection_process_exclusion or filter_system_process)

falsepositives:
  - Browser backup/sync tools
  - Password managers accessing browser data
  - System recovery tools

level: high
```

### Rule 5: Direct Syscall Usage Detection

```yaml
title: Suspicious Direct Syscall Usage - EDR Bypass
description: Detects direct syscall invocation bypassing Windows API monitoring
status: experimental
author: Threat Intelligence Team
date: 2026/01/26
severity: CRITICAL
tags:
  - attack.defense_evasion
  - attack.t1622
  - malware.arsenal237

detection:
  selection_syscall_pattern:
    EventID:
      - 8   # CreateRemoteThread
      - 10  # ProcessAccess (syscall-based)

  selection_suspicious_syscalls:
    API|contains|any:
      - 'ZwAllocateVirtualMemory'
      - 'ZwWriteVirtualMemory'
      - 'ZwCreateThreadEx'
      - 'ZwProtectVirtualMemory'
      - 'ZwOpenProcess'

  selection_target:
    TargetImage|endswith:
      - 'chrome.exe'
      - 'brave.exe'
      - 'msedge.exe'

  condition: all of selection_*

falsepositives:
  - System administration tools
  - Debugging tools

level: critical
```

---

## KQL Queries (Kusto Query Language - Azure Sentinel / Defender)

### Query 1: chromelevator.exe Process Creation

```kusto
DeviceProcessEvents
| where ProcessName has "chromelevator.exe"
| where CommandLine contains "--verbose" or CommandLine contains "--output-path" or CommandLine contains "--fingerprint"
| project
    Timestamp,
    DeviceName,
    ProcessId,
    ProcessName,
    CommandLine,
    ParentProcessName,
    AccountName,
    ProcessCommandLine
| order by Timestamp desc
```

### Query 2: Named Pipe Creation by Suspicious Processes

```kusto
DeviceFileEvents
| where FileName has "pipe" and FileName has ".\\pipe\\"
| where InitiatingProcessName has "chromelevator.exe" or InitiatingProcessName has "explorer.exe"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessName has "chromelevator.exe"
) on DeviceId, InitiatingProcessId
| project
    Timestamp,
    DeviceName,
    FileName,
    InitiatingProcessName,
    ActionType,
    AccountName
| order by Timestamp desc
```

### Query 3: Process Injection Detection - Memory Operations Sequence

```kusto
DeviceProcessEvents
| where ProcessName has "chrome.exe" or ProcessName has "brave.exe" or ProcessName has "msedge.exe"
| where ActionType has "VirtualAllocEx" or ActionType has "WriteProcessMemory" or ActionType has "CreateRemoteThread"
| project
    Timestamp,
    DeviceName,
    ProcessName,
    ParentProcessName,
    ActionType,
    AccountName
| order by Timestamp desc
| extend
    InjectionIndicator = iff(ActionType == "VirtualAllocEx", "Allocation",
                      iff(ActionType == "WriteProcessMemory", "Writing",
                      iff(ActionType == "CreateRemoteThread", "Execution", "Unknown")))
| where InjectionIndicator != "Unknown"
```

### Query 4: Browser Database Access by Non-Browser Processes

```kusto
DeviceFileEvents
| where FileName contains_cs @"User Data" and FileName contains_cs @"Login Data"
| where InitiatingProcessName !has_cs "chrome.exe" and
        InitiatingProcessName !has_cs "brave.exe" and
        InitiatingProcessName !has_cs "msedge.exe" and
        InitiatingProcessName !has_cs "firefox.exe"
| where ActionType == "FileRead" or ActionType == "FileModified"
| project
    Timestamp,
    DeviceName,
    FileName,
    InitiatingProcessName,
    InitiatingProcessAccountName,
    ActionType
| order by Timestamp desc
```

### Query 5: Registry Enumeration for Browser Installations

```kusto
DeviceRegistryEvents
| where RegistryKey has "Software\\Google\\Chrome" or
        RegistryKey has "Software\\BraveSoftware" or
        RegistryKey has "Software\\Microsoft\\Edge"
| where InitiatingProcessName has "chromelevator.exe" or
        InitiatingProcessName has_cs "explorer.exe" or
        InitiatingProcessName !in~ ("regedit.exe", "powershell.exe", "cmd.exe")
| project
    Timestamp,
    DeviceName,
    RegistryKey,
    RegistryValueName,
    InitiatingProcessName,
    ActionType,
    AccountName
| order by Timestamp desc
```

---

## Splunk SPL Queries

### Query 1: Process Execution - chromelevator.exe

```spl
index=main sourcetype=WinEventLog:Security EventCode=4688
| search "Process Name"="*chromelevator.exe"
| fields
    _time,
    Computer,
    Process_Name,
    Command_Line,
    ParentProcessName,
    Account_Name
| table _time Computer Process_Name Command_Line ParentProcessName Account_Name
| sort - _time
```

### Query 2: Named Pipe Creation Monitoring

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=23 OR EventCode=24
| search PipeName="\\.\pipe\*"
| search Image="*chromelevator.exe" OR Image="*explorer.exe"
| fields
    _time,
    Computer,
    PipeName,
    Image,
    EventCode
| stats count by Computer, Image, PipeName
| where count > 0
```

### Query 3: Browser Process Memory Operations

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=8
| search TargetImage IN (chrome.exe, brave.exe, msedge.exe, firefox.exe)
| fields
    _time,
    Computer,
    SourceImage,
    TargetImage,
    EventCode,
    GrantedAccess
| where GrantedAccess IN ("0x1fffff", "0x1f0fff", "0x1010")
| table _time Computer SourceImage TargetImage GrantedAccess
| sort - _time
```

### Query 4: Browser Database Access Detection

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=11
| search TargetFilename="*User Data*Login Data" OR TargetFilename="*User Data*Cookies" OR TargetFilename="*User Data*Web Data"
| search Image!="chrome.exe" AND Image!="brave.exe" AND Image!="msedge.exe" AND Image!="firefox.exe"
| fields
    _time,
    Computer,
    Image,
    TargetFilename,
    User
| stats count by Computer, Image, TargetFilename
| where count > 0
```

### Query 5: Registry Activity - Browser Detection

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=13
| search TargetObject IN
    ("*\\Software\\Google\\Chrome\\*",
     "*\\Software\\BraveSoftware\\*",
     "*\\Software\\Microsoft\\Edge\\*")
| search Image="*chromelevator.exe" OR Image="*explorer.exe"
| fields
    _time,
    Computer,
    Image,
    TargetObject,
    Details
| table _time Computer Image TargetObject Details
| sort - _time
```

---

## Elastic/ELK Detection Rules

### Rule 1: Process Execution - chromelevator.exe

```json
{
  "rule": {
    "name": "Process Execution - chromelevator.exe",
    "description": "Detects execution of chromelevator.exe browser credential extraction tool",
    "severity": "CRITICAL",
    "rule_type": "query",
    "index": [
      "logs-endpoint.events.process-*",
      "logs-windows.sysmon_operational-*"
    ],
    "query": "process.name : chromelevator.exe AND (process.args : \"--verbose\" OR process.args : \"--output-path\" OR process.args : \"--fingerprint\")",
    "filters": [
      {
        "match": {
          "host.os.family": "windows"
        }
      }
    ]
  }
}
```

### Rule 2: Named Pipe Creation Detection

```json
{
  "rule": {
    "name": "Named Pipe Creation - Process Injection C2",
    "description": "Detects named pipe creation patterns associated with reflective injection",
    "severity": "CRITICAL",
    "rule_type": "query",
    "index": [
      "logs-endpoint.events.file-*",
      "logs-windows.sysmon_operational-*"
    ],
    "query": "file.path : (\"\\\\*\\\\pipe\\\\*\" OR \"\\\\Device\\\\NamedPipe\\\\*\") AND process.name : (chromelevator.exe OR explorer.exe)",
    "filters": []
  }
}
```

### Rule 3: Process Injection - Memory Pattern

```json
{
  "rule": {
    "name": "Process Injection Detection - Memory Allocation Pattern",
    "description": "Detects suspicious memory allocation and thread creation in browser processes",
    "severity": "CRITICAL",
    "rule_type": "query",
    "index": [
      "logs-endpoint.events.process-*"
    ],
    "query": "target.process.name : (chrome.exe OR brave.exe OR msedge.exe) AND process.api.name : (VirtualAllocEx OR WriteProcessMemory OR VirtualProtectEx OR CreateRemoteThread)",
    "filters": []
  }
}
```

---

## Network Signatures (Suricata/Snort)

### Rule 1: Named Pipe Protocol Pattern

```
alert file-data any any -> any any (msg:"Named Pipe C2 Communication Pattern"; file_data; content:"VERBOSE_"; distance:0; within:10; sid:1000001; rev:1; metadata:policy balanced-ips drop, policy security-ips alert;)
```

### Rule 2: Direct Syscall Indicators in Network Traffic

Note: Direct syscalls do not generate network traffic. This rule would detect C2 communication of extracted credentials if integrated with other campaign components.

```
alert tcp any any -> any any (msg:"Potential Credential Exfiltration - Large Data Transfer"; flow:to_server,established; content:"POST"; http_method; content:"credentials"; http_uri; nocase; classtype:trojan-activity; sid:1000002; rev:1;)
```

---

## Memory Forensics Indicators (Volatility)

### Memory Scan for Injected PAYLOAD_DLL

```bash
volatility -f memory.dump --profile=Win10x64 yarascan -y chromelevator.yar
```

### Direct Syscall Framework Detection in Memory

```bash
volatility -f memory.dump --profile=Win10x64 strings | grep -E "ZwAllocateVirtualMemory|ZwWriteVirtualMemory|ZwCreateThreadEx"
```

### Named Pipe Detection in Memory

```bash
volatility -f memory.dump --profile=Win10x64 psxview | grep chromelevator
volatility -f memory.dump --profile=Win10x64 handles | grep -i pipe
```

---

## Threat Hunting Queries

### Hunting Query 1: Browser Exploitation Indicators

**Objective:** Find systems where browser credential databases are accessed by unusual processes

**Splunk SPL:**
```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=11
| search TargetFilename="*User Data*" AND (TargetFilename="*Login Data" OR TargetFilename="*Cookies" OR TargetFilename="*Web Data")
| where NOT (Image IN (chrome.exe, brave.exe, msedge.exe, firefox.exe, backup.exe, sync.exe))
| stats count by Computer, Image, TargetFilename, User
| where count > 5
```

### Hunting Query 2: Reflective DLL Injection Patterns

**Objective:** Find process memory operations consistent with reflective DLL injection

**Azure Sentinel KQL:**
```kusto
DeviceProcessEvents
| where ActionType in ("CreateRemoteThreadApi", "VirtualAllocExApi", "WriteProcessMemoryApi", "VirtualProtectExApi")
| where TargetImage has "chrome" or TargetImage has "brave" or TargetImage has "edge"
| summarize EventCount = count() by DeviceName, ProcessName, TargetImage
| where EventCount > 10
```

### Hunting Query 3: Registry Enumeration for Browser Installations

**Objective:** Find processes enumerating browser installation registry keys

**Splunk SPL:**
```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=13
| search (TargetObject="*\\Software\\Google\\Chrome\\*" OR TargetObject="*\\Software\\BraveSoftware\\*" OR TargetObject="*\\Software\\Microsoft\\Edge\\*")
| where NOT (Image IN (chrome.exe, brave.exe, msedge.exe, firefox.exe, regedit.exe, powershell.exe, cmd.exe))
| stats count by Image, TargetObject, User
| where count > 3
```

### Hunting Query 4: Suspicious Command-Line Arguments

**Objective:** Find execution of known malware with suspicious command-line patterns

**Azure Sentinel KQL:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine has "--output-path" or ProcessCommandLine has "--verbose" or ProcessCommandLine has "--fingerprint"
| where ProcessName !in ("PowerShell.exe", "cmd.exe", "wscript.exe")
| project
    Timestamp,
    DeviceName,
    ProcessName,
    ProcessCommandLine,
    InitiatingProcessName,
    AccountName
| order by Timestamp desc
```

---

## Incident Response Checklist

When chromelevator.exe is suspected or detected:

- [ ] **Isolation:** Disconnect affected systems from network
- [ ] **Preservation:** Capture memory dumps and full disk forensic images
- [ ] **Termination:** Kill chromelevator.exe processes
- [ ] **Investigation:** Analyze named pipes and data extraction patterns
- [ ] **Scope:** Determine which credentials compromised
- [ ] **Rotation:** Reset passwords for potentially compromised accounts
- [ ] **Monitoring:** Enable enhanced threat hunting for related activity
- [ ] **Escalation:** Alert incident response team and leadership
- [ ] **Recovery:** Decide on rebuild vs. cleanup remediation approach

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
  - T1555.003: Credentials from Web Browsers
  - T1055.001: Process Injection
  - T1622: Debugger Evasion
  - T1027: Obfuscated Files or Information

- Arsenal-237 Campaign Analysis
- chromelevator.exe Technical Analysis Report
- IOC Feed: chromelevator-exe.json

---

**Detection Framework:** Signature-Based (YARA), Behavioral (Sigma, EDR), Log-Based (Splunk, KQL)
**Update Frequency:** Quarterly or as threats evolve
**Maintainer:** Threat Intelligence Team

---
