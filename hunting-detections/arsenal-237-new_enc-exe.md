---
title: Detection Rules - new_enc.exe - Human-Operated Rust Ransomware
date: '2026-01-27'
layout: post
permalink: /hunting-detections/arsenal-237-new_enc-exe/
hide: true
---

# new_enc.exe (Arsenal-237) - Detection Rules & Hunting Queries

**Generated:** 2026-01-26
**Threat Level:** CRITICAL
**Rule Category:** Ransomware Detection

---

## YARA Rules

### Rule 1: new_enc.exe File Hash Detection

```yara
rule new_enc_exe_file_hash {
    meta:
        description = "Detects new_enc.exe Arsenal-237 ransomware by file hash"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        malware_type = "Ransomware"
        family = "Arsenal-237"

    strings:
        $md5 = "a16ba61114fa5a40afce54459bbff21e" wide ascii
        $sha1 = "2c01cefba27c4d3fcb3b450cb8e625e89bc54363" wide ascii
        $sha256 = "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2" wide ascii

    condition:
        any of them
}
```

### Rule 2: Hardcoded ChaCha20 Encryption Key Detection

```yara
rule arsenal_237_chacha20_key {
    meta:
        description = "Detects Arsenal-237 hardcoded ChaCha20 encryption key"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        ioc_type = "Cryptographic Material"
        confidence = "CONFIRMED"

    strings:
        $key_hex = "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b" nocase wide ascii
        $key_pattern = "67e60" nocase  // Partial match for speed

    condition:
        $key_hex or (all of ($key_pattern*))
}
```

### Rule 3: Campaign and Version Identifier Detection

```yara
rule arsenal_237_campaign_identifiers {
    meta:
        description = "Detects Arsenal-237 campaign ID and version strings"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        ioc_type = "Campaign Identifier"

    strings:
        $campaign_id = "ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4" wide ascii
        $version = "v0.5-beta" wide ascii
        $ransom_task = "RustRansomNoteTask" wide ascii

    condition:
        any of them
}
```

### Rule 4: Veritas Backup Exec Agent Targeting Detection

```yara
rule arsenal_237_veritas_targeting {
    meta:
        description = "Detects service names targeting Veritas Backup Exec agents"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        ioc_type = "Enterprise Targeting Indicator"
        confidence = "CONFIRMED"

    strings:
        $gxvss = "GxVss" wide ascii
        $gxblr = "GxBlr" wide ascii
        $gxfwd = "GxFWD" wide ascii
        $gxcvd = "GxCVD" wide ascii
        $gxcimgr = "GxCIMgr" wide ascii
        $veeam = "veeam" wide ascii nocase

    condition:
        (3 of ($gx*)) or $veeam
}
```

### Rule 5: Anti-Recovery Command Detection

```yara
rule arsenal_237_antirecovery_commands {
    meta:
        description = "Detects VSS deletion and anti-recovery commands"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        ioc_type = "Anti-Recovery Indicator"

    strings:
        $vss_delete = "vssadmin delete shadows /all /quiet" wide ascii nocase
        $vss_pattern = "vssadmin" wide ascii nocase
        $delete_shadows = "delete shadows" wide ascii nocase

    condition:
        ($vss_delete) or ($vss_pattern and $delete_shadows)
}
```

### Rule 6: Anti-Analysis Technique Detection

```yara
rule arsenal_237_anti_analysis {
    meta:
        description = "Detects anti-analysis strings and VM detection indicators"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        ioc_type = "Anti-Analysis Indicator"

    strings:
        $vm_vbox = "VBOX" wide ascii nocase
        $vm_vmware = "VMWARE" wide ascii nocase
        $vm_qemu = "QEMU" wide ascii nocase
        $vm_xen = "XEN" wide ascii nocase
        $vm_hyperv = "HYPERV" wide ascii nocase
        $sandbox_cuckoo = "cuckoo" wide ascii nocase
        $sandbox_malware = "malware" wide ascii nocase
        $bios_registry = "HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS" wide ascii nocase
        $debugger_check = "IsDebuggerPresent" wide ascii

    condition:
        (3 of ($vm_*)) or (2 of ($sandbox_*)) or $bios_registry or $debugger_check
}
```

### Rule 7: Hex-Encoded Ransom Note Detection

```yara
rule arsenal_237_hex_ransom_note {
    meta:
        description = "Detects hex-encoded ransom note header"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        ioc_type = "Ransom Note Indicator"

    strings:
        $hex_header = "76302e352d626574610d0a0d0a52616e736f6d2d4944" wide ascii  // v0.5-beta\r\n\r\nRansom-ID

    condition:
        $hex_header
}
```

### Rule 8: Analysis Tool Process Monitoring

```yara
rule arsenal_237_analysis_tool_strings {
    meta:
        description = "Detects strings indicating analysis tool process monitoring"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        ioc_type = "Anti-Analysis Tool Detection"

    strings:
        $procmon = "procmon" wide ascii nocase
        $wireshark = "wireshark" wide ascii nocase
        $x64dbg = "x64dbg" wide ascii nocase
        $ida = "ida" wide ascii nocase
        $ghidra = "ghidra" wide ascii nocase
        $dnspy = "dnspy" wide ascii nocase
        $fiddler = "fiddler" wide ascii nocase
        $processhacker = "processhacker" wide ascii nocase

    condition:
        (5 of them)
}
```

### Rule 9: Rust Ransomware Family Detection

```yara
rule arsenal_237_rust_implementation {
    meta:
        description = "Detects Rust-compiled ransomware characteristics"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        ioc_type = "Family Classification"

    strings:
        $chacha_const = "Chacha_256_constant" wide ascii
        $rust_std = "core::panicking" wide ascii
        $cargo = "cargo" wide ascii

    condition:
        (2 of them)
}
```

---

## Sigma Rules

### Rule 1: VSS Deletion Command Execution

```yaml
title: Volume Shadow Copy Deletion - Ransomware Indicator
id: 0d6cbe7c-6d5f-4b6e-9c2a-8c4b5d3e1f7a
description: Detects execution of vssadmin delete shadows command used by ransomware
status: test
date: 2026-01-26
author: Threat Intelligence Team
references:
    - https://attack.mitre.org/techniques/T1490/
logsource:
    product: windows
    service: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
    filter:
        CommandLine|contains:
            - 'VSSADMIN_DELETE_SHADOWS'  # Legitimate admin activity
    condition: selection and not filter
falsepositives:
    - Legitimate administrative backup operations
level: critical
tags:
    - attack.impact
    - attack.t1490
    - ransomware
    - critical
```

### Rule 2: Backup Service Termination Pattern

```yaml
title: Backup Service Termination - Multiple Services
id: 1e8c3d5a-2b7f-4a9c-b1e6-d3f5a8c2b4e7
description: Detects mass termination of backup services (Veritas, Veeam, VSS)
status: test
date: 2026-01-26
author: Threat Intelligence Team
references:
    - https://attack.mitre.org/techniques/T1489/
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7000  # Service Control Manager
        ServiceName|in:
            - 'GxVss'
            - 'GxBlr'
            - 'GxFWD'
            - 'GxCVD'
            - 'GxCIMgr'
            - 'veeam'
            - 'vss'
        Status: 'stopped'
    timeframe: 5m
    condition: selection | count(ServiceName) > 2
falsepositives:
    - Legitimate service maintenance
    - Scheduled backup system restarts
level: critical
tags:
    - attack.impact
    - attack.t1489
    - ransomware
    - backup
```

### Rule 3: Scheduled Task Creation - Ransom Note

```yaml
title: Scheduled Task Creation - RustRansomNoteTask
id: 3f7a9b2c-5e8d-4c1a-b6f3-7d2e5a8c1b9f
description: Detects creation of RustRansomNoteTask scheduled task
status: test
date: 2026-01-26
author: Threat Intelligence Team
references:
    - https://attack.mitre.org/techniques/T1053.005/
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11  # Image/File created
        TargetFilename|contains: 'RustRansomNoteTask'
    condition: selection
falsepositives:
    - Legitimate system tasks with similar naming
level: high
tags:
    - attack.persistence
    - attack.t1053.005
    - ransomware
```

### Rule 4: Database Service Termination Pattern

```yaml
title: Database Service Termination - Ransomware Pattern
id: 4b2d7e9a-1c5f-3a8b-6d4e-2f7c9a3b5e1d
description: Detects termination of SQL Server and Oracle database services
status: test
date: 2026-01-26
author: Threat Intelligence Team
references:
    - https://attack.mitre.org/techniques/T1489/
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7000
        ServiceName|in:
            - 'sql'
            - 'oracle'
            - 'ocssd'
            - 'dbsnmp'
            - 'sqlservr'
        Status: 'stopped'
    timeframe: 10m
    condition: selection | count(ServiceName) > 1
falsepositives:
    - Legitimate database maintenance
    - Scheduled database restarts
level: high
tags:
    - attack.impact
    - attack.t1489
    - database
    - ransomware
```

---

## Detection Queries

### KQL (Azure Sentinel / Microsoft Defender for Endpoint)

#### Query 1: VSS Deletion Detection

```kql
DeviceProcessEvents
| where ProcessCommandLine contains ("vssadmin" and "delete") or ProcessCommandLine contains "shadowcopy"
| where ProcessName != "explorer.exe"  // Filter out false positives
| project Timestamp, DeviceId, DeviceName, InitiatingProcessName, ProcessName, ProcessCommandLine, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

**Alert Configuration:**
- Severity: CRITICAL
- Trigger: 1 or more matches in 1 hour
- Response: Immediate isolation of affected device

#### Query 2: Backup Service Termination Hunt

```kql
DeviceProcessEvents
| where ProcessName in~ ("net.exe", "sc.exe", "taskkill.exe")
| where ProcessCommandLine contains any ("GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr", "veeam", "vss")
| where ProcessCommandLine contains ("stop", "disable", "delete")
| project Timestamp, DeviceId, DeviceName, InitiatingProcessName, ProcessCommandLine
| order by Timestamp desc
```

**Alert Configuration:**
- Severity: CRITICAL
- Trigger: 1 or more matches
- Response: Verify backup system status immediately

#### Query 3: Veritas Backup Exec Agent Targeting

```kql
DeviceProcessEvents
| where ProcessName in~ ("net.exe", "sc.exe", "powershell.exe")
| where ProcessCommandLine matches regex @"(GxVss|GxBlr|GxFWD|GxCVD|GxCIMgr)"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp desc
```

**Alert Configuration:**
- Severity: CRITICAL
- Context: Enterprise backup targeting indicator

#### Query 4: Scheduled Task Creation - Ransom Note

```kql
DeviceProcessEvents
| where ProcessName =~ "schtasks.exe"
| where ProcessCommandLine contains "RustRansomNoteTask" or ProcessCommandLine contains "Ransom"
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine, InitiatingProcessName
| order by Timestamp desc
```

**Alert Configuration:**
- Severity: HIGH
- Trigger: 1 or more matches
- Indicator: Post-encryption persistence mechanism

#### Query 5: Multi-Service Termination Pattern (Ransomware Signature)

```kql
let ServiceStops =
    DeviceProcessEvents
    | where ProcessName in~ ("net.exe", "sc.exe", "powershell.exe")
    | where ProcessCommandLine contains any ("stop", "disable")
    | where ProcessCommandLine contains any ("sql", "oracle", "vss", "veeam", "backup", "sophos", "msexchange");
ServiceStops
| summarize ServiceCount = dcount(ProcessCommandLine) by DeviceId, bin(Timestamp, 15m)
| where ServiceCount > 3
| project Timestamp, DeviceId, ServiceCount
```

**Alert Configuration:**
- Severity: HIGH
- Pattern: 4+ different services stopped within 15 minutes

### SPL (Splunk)

#### Query 1: VSS Deletion Detection

```spl
index=main sourcetype=WinEventLog:System OR sourcetype=XmlWinEventLog:System
(CommandLine="vssadmin delete shadows*" OR ProcessImage="*vssadmin.exe" AND CommandLine="*delete*" AND CommandLine="*shadows*")
| table _time, host, user, CommandLine, Image, ParentImage
| stats count by host
| where count > 0
```

#### Query 2: Service Termination - Critical Backup Services

```spl
index=main sourcetype=WinEventLog:System
(ServiceName=GxVss OR ServiceName=GxBlr OR ServiceName=GxFWD OR ServiceName=GxCVD OR ServiceName=GxCIMgr OR ServiceName=veeam OR ServiceName=vss)
AND (Status=stopped OR EventCode=7000)
| timechart count by ServiceName
| search count > 0
```

**Alert Configuration:**
```spl
alert_condition: if(count > 0)
alert_type: critical
alert_name: "Backup Service Termination - Arsenal-237 Indicator"
```

#### Query 3: Scheduled Task Creation - RustRansomNoteTask

```spl
index=main sourcetype=WinEventLog:System EventCode=4698
TaskName="*RustRansomNoteTask*"
| table _time, host, TaskName, TaskContent, User
```

#### Query 4: Ransomware Multi-Stage Attack Pattern

```spl
index=main sourcetype=WinEventLog:System
earliest=-1h latest=now
| where (
  (ProcessImage="*vssadmin.exe" AND CommandLine="*delete*") OR
  (ServiceName IN (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr, veeam, vss)) OR
  (CommandLine="*schtasks*" AND CommandLine="*RustRansomNoteTask*")
)
| bucket _time span=10m
| stats count, dc(host) as host_count by _time
| where count > 2
```

---

## Elastic Detection Rules

### Rule 1: VSS Deletion Command Execution

```json
{
  "rule": {
    "id": "vss-deletion-ransomware",
    "type": "query",
    "language": "kuery",
    "query": "process.name:vssadmin.exe AND process.command_line:(\"delete\" AND \"shadows\")",
    "index": ["logs-endpoint.events.process-*"],
    "name": "Volume Shadow Copy Deletion - Ransomware Indicator",
    "description": "Detects execution of VSS deletion commands associated with ransomware",
    "severity": "critical",
    "risk_score": 100,
    "references": ["https://attack.mitre.org/techniques/T1490/"],
    "tags": ["ransomware", "impact", "backup-targeting"]
  }
}
```

### Rule 2: Veritas Backup Agent Termination

```json
{
  "rule": {
    "id": "veritas-backup-termination",
    "type": "query",
    "language": "kuery",
    "query": "process.command_line:(GxVss OR GxBlr OR GxFWD OR GxCVD OR GxCIMgr) AND (net.exe OR sc.exe OR powershell.exe) AND (stop OR disable)",
    "index": ["logs-endpoint.events.process-*"],
    "name": "Veritas Backup Exec Service Termination",
    "description": "Detects termination of Veritas Backup Exec agent services",
    "severity": "critical",
    "risk_score": 99,
    "tags": ["backup-targeting", "enterprise"]
  }
}
```

### Rule 3: Arsenal-237 Campaign Identifier

```json
{
  "rule": {
    "id": "arsenal237-campaign-id",
    "type": "query",
    "language": "kuery",
    "query": "process.command_line:\"ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4\" OR file.name:\"ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4\"",
    "index": ["logs-endpoint.events.*"],
    "name": "Arsenal-237 Campaign Identifier Detection",
    "description": "Detects Arsenal-237 campaign identifier in process or file context",
    "severity": "critical",
    "risk_score": 100
  }
}
```

---

## Network Detection Signatures

### Suricata Rules

#### Rule 1: ChaCha20 Encryption Traffic Pattern

```suricata
alert http any any -> any any (
  msg:"Arsenal-237 ChaCha20 Ransomware Encryption Pattern";
  content:"ChaCha20"; nocase;
  classtype:trojan-activity;
  sid:1000001;
  rev:1;
  priority:1;
  tag:ransomware,encryption;
)
```

#### Rule 2: Ransom Note Delivery Detection

```suricata
alert dns any any -> any 53 (
  msg:"Arsenal-237 Ransom Note Domain Query";
  dns_query; content:"ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4";
  nocase; classtype:trojan-activity;
  sid:1000002; rev:1; priority:2;
)
```

---

## Behavioral Hunting Methodology

### Investigation Steps

**Step 1: Identify Candidate Systems**
1. Query for VSS deletion commands
2. Check for backup service termination patterns
3. Search for scheduled task creation matching pattern
4. Look for diagnostic tool execution patterns

**Step 2: Verify Infection**
1. Confirm presence of new_enc.exe file
2. Validate file hash against known samples
3. Check for RustRansomNoteTask scheduled task
4. Review event logs for anti-analysis evasion patterns

**Step 3: Assess Impact Scope**
1. Identify all affected systems
2. Determine encryption scope and file count
3. Verify backup system status
4. Assess recovery options (offline backups)

**Step 4: Determine Recovery Path**
1. Validate offline backup integrity
2. Assess rebuild vs. aggressive cleanup decision
3. Initiate forensic analysis if required
4. Plan recovery execution timeline

---

## Detection Confidence Levels

| Detection Method | Confidence | False Positive Risk | Recommended Action |
|------------------|------------|-------------------|-------------------|
| **File Hash Match** | CONFIRMED | MINIMAL | Immediate isolation |
| **VSS Deletion Command** | CONFIRMED | LOW | Critical alert |
| **Veritas Service Termination** | CONFIRMED | LOW | Critical alert |
| **Scheduled Task (RustRansomNoteTask)** | CONFIRMED | MINIMAL | High alert |
| **ChaCha20 Key Detection** | CONFIRMED | MINIMAL | Critical alert |
| **Campaign ID Detection** | CONFIRMED | MINIMAL | Critical alert |
| **Multi-Service Termination Pattern** | HIGHLY LIKELY (90%) | MEDIUM | High alert + investigation |
| **VM Detection Strings** | LIKELY (70%) | MEDIUM | Medium alert |
| **Analysis Tool Process Monitoring** | LIKELY (70%) | MEDIUM-HIGH | Medium alert |

---

## Implementation Recommendations

### Priority 1: Immediate Deployment (Critical Rules)
- VSS Deletion Detection
- Veritas Backup Agent Termination
- File Hash Detection
- Campaign Identifier Detection

### Priority 2: Near-Term Deployment (High-Confidence Rules)
- Scheduled Task Creation
- Database Service Termination Pattern
- Multi-Service Termination Pattern

### Priority 3: Ongoing Monitoring (Supporting Rules)
- Anti-Analysis Technique Detection
- Rust Implementation Characteristics
- Behavioral Pattern Matching

### Fine-Tuning Recommendations
1. Adjust alert thresholds based on organizational baseline
2. Implement time-window correlation for multi-event patterns
3. Create custom alert response playbooks for each rule
4. Establish baseline for normal service termination activity
5. Document false positive patterns and refine filters
6. Regular rule validation against new/modified samples

---

**End of Detection Rules Document**
