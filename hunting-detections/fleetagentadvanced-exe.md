---
title: Detection Rules - FleetAgentAdvanced.exe - Multi-Layer Persistence Trojan
date: '2026-01-12'
layout: post
permalink: /hunting-detections/fleetagentadvanced-exe/
hide: true
---

# Detection Rules – FleetAgentAdvanced.exe: Multi-Layer Persistence Trojan

## Overview
Comprehensive detection coverage for FleetAgentAdvanced.exe persistence trojan/dropper and its deployed payload (RuntimeOptimization.exe). Rules target the malware's distinctive quad-persistence architecture, .NET dropper characteristics, and Microsoft .NET masquerading behavior.

**Key Detection Opportunities:**
- Quad-persistence establishment pattern (4 mechanisms within 1.3 seconds)
- schtasks.exe execution followed by task.xml deletion (anti-forensics signature)
- .NET executables creating Microsoft .NET-themed persistence with non-Microsoft signatures
- Startup folder LNK creation targeting AppData\Microsoft\CLR\ paths
- Process injection API sequences from .NET executables

---

## YARA Rules

### FleetAgentAdvanced.exe Core Detection Rules

#### YARA Rule - FleetAgentAdvanced Dropper Signature
```yaml
rule FleetAgentAdvanced_Dropper_Core {
    meta:
        description = "Detects FleetAgentAdvanced.exe dropper based on strings, capabilities, and file characteristics"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        hash1 = "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b"
        severity = "HIGH"
        ref = "Open Directory 109.230.231.37"
        family = "FleetAgentAdvanced"

    strings:
        // Unique function names
        $func1 = "DropEmbeddedAgent" ascii wide
        $func2 = "SetPersistence" ascii wide
        $func3 = "CreateShortcut" ascii wide
        $func4 = "StartWatchdog" ascii wide
        $func5 = "RunWatchdog" ascii wide
        $func6 = "InjectIntoProcess" ascii wide

        // Configuration variables
        $config1 = "EMBEDDED_AGENT" ascii wide
        $config2 = "INSTALL_NAME" ascii wide
        $config3 = "STARTUP_NAME" ascii wide
        $config4 = "WATCHDOG_MUTEX" ascii wide
        $config5 = "MUTEX_NAME" ascii wide
        $config6 = "SERVER_HOST" ascii wide
        $config7 = "AGENT_SECRET" ascii wide

        // Persistence-related strings
        $persist1 = "RuntimeOptimization.exe" ascii wide
        $persist2 = "Microsoft .NET Runtime Optimization" ascii wide
        $persist3 = "Microsoft\\CLR" ascii wide

        // Process injection APIs
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii
        $api5 = "PAGE_EXECUTE_READWRITE" ascii

        // Cryptographic capabilities
        $crypto1 = "ToBase64String" ascii
        $crypto2 = "FromBase64String" ascii

        // .NET Framework indicators
        $net1 = "FleetAgentAdvanced_final" ascii wide
        $net2 = "Microsoft.NET.Runtime" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Strong match: Multiple unique functions
            3 of ($func*) or

            // Moderate match: Configuration + persistence strings
            (2 of ($config*) and any of ($persist*)) or

            // Strong match: Process injection + persistence
            (any of ($api*) and any of ($persist*)) or

            // Definitive match: File hash
            hash.sha256(0, filesize) == "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b"
        )
}
```

#### YARA Rule - RuntimeOptimization.exe Payload Detection
```yaml
rule FleetAgentAdvanced_RuntimeOptimization_Payload {
    meta:
        description = "Detects dropped RuntimeOptimization.exe payload"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        hash1 = "9fc6b69623133f5d6f1f4cda0ec4319300080c9bbaa0f88c93f01eeba84e80e7"
        severity = "HIGH"
        ref = "Dropped payload from FleetAgentAdvanced.exe"
        family = "FleetAgentAdvanced"

    condition:
        uint16(0) == 0x5A4D and
        filesize == 27648 and // 27 KB exact size
        hash.sha256(0, filesize) == "9fc6b69623133f5d6f1f4cda0ec4319300080c9bbaa0f88c93f01eeba84e80e7"
}
```

#### YARA Rule - Quad-Persistence Pattern Detection
```yaml
rule FleetAgentAdvanced_Quad_Persistence_Pattern {
    meta:
        description = "Detects .NET droppers with quad-persistence architecture pattern"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"
        technique = "T1547.001 + T1053.005 - Multiple Persistence Mechanisms"

    strings:
        // Persistence mechanisms
        $reg_run = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
        $startup_folder = "\\\\Start Menu\\\\Programs\\\\Startup" ascii wide
        $schtasks = "schtasks" ascii wide nocase
        $lnk_file = ".lnk" ascii wide

        // Microsoft masquerading
        $ms_mask1 = "Microsoft" ascii wide
        $ms_mask2 = ".NET" ascii wide
        $ms_mask3 = "Runtime" ascii wide
        $ms_mask4 = "Optimization" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        // .NET executable signature
        for any i in (0..filesize-4): (uint32(i) == 0x424A5342) and // BSJB (.NET metadata signature)
        // Persistence mechanisms present
        all of ($reg_run, $startup_folder, $schtasks, $lnk_file) and
        // Microsoft masquerading
        3 of ($ms_mask*)
}
```

#### YARA Rule - Task.xml Anti-Forensics Pattern
```yaml
rule FleetAgentAdvanced_TaskXML_AntiForensics {
    meta:
        description = "Detects malware with task.xml creation and deletion anti-forensics pattern"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "MEDIUM"
        technique = "T1070.004 - Indicator Removal: File Deletion"

    strings:
        $schtasks_create = "/create" ascii wide
        $xml_extension = ".xml" ascii wide
        $task_name = "/tn" ascii wide
        $delete_api = "Delete" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        all of them and
        filesize < 2MB
}
```

---

## Sigma Rules

### FleetAgentAdvanced.exe Detection Rules

#### Sigma Rule - Quad-Persistence Establishment
```yaml
title: FleetAgentAdvanced Quad-Persistence Establishment
id: a1b2c3d4-fleet-quad-persistence-001
status: stable
description: Detects FleetAgentAdvanced quad-persistence mechanism establishment pattern
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: process_creation
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '.NET Runtime Optimization'
    selection_registry:
        EventID: 13
        TargetObject|contains: 'Software\Microsoft\Windows\CurrentVersion\Run'
        Details|contains: 'RuntimeOptimization.exe'
    selection_startup:
        EventID: 11
        TargetFilename|contains|all:
            - '\Start Menu\Programs\Startup\'
            - 'Runtime Optimization'
            - '.lnk'
    timeframe: 5s
    condition: 2 of selection_*
falsepositives:
    - Legitimate .NET Framework maintenance tasks (verify digital signature)
level: high
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.t1053.005
    - fleetagentadvanced
```

#### Sigma Rule - Task.xml Deletion Anti-Forensics
```yaml
title: FleetAgentAdvanced Task.xml Deletion Anti-Forensics
id: b2c3d4e5-fleet-taskxml-deletion-002
status: stable
description: Detects task.xml deletion immediately after scheduled task creation (FleetAgentAdvanced anti-forensics signature)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|endswith: '\task.xml'
        Image|contains: '.exe'
    filter_legitimate:
        Image|contains:
            - '\System32\'
            - '\SysWOW64\'
    condition: selection and not filter_legitimate
falsepositives:
    - Some legitimate installers may use similar patterns
level: medium
tags:
    - attack.defense_evasion
    - attack.t1070.004
    - fleetagentadvanced
```

#### Sigma Rule - RuntimeOptimization.exe Execution from AppData
```yaml
title: FleetAgentAdvanced RuntimeOptimization.exe Execution
id: c3d4e5f6-fleet-runtime-exec-003
status: stable
description: Detects execution of RuntimeOptimization.exe from AppData\Microsoft\CLR\ directory
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains|all:
            - '\AppData\Roaming\Microsoft\CLR\'
            - 'RuntimeOptimization.exe'
    condition: selection
falsepositives:
    - None expected (legitimate .NET runtime optimization uses System32 paths)
level: critical
tags:
    - attack.execution
    - attack.t1204.002
    - fleetagentadvanced
```

#### Sigma Rule - Persistence with Microsoft .NET Masquerading
```yaml
title: FleetAgentAdvanced Microsoft .NET Masquerading Persistence
id: d4e5f6a7-fleet-dotnet-masq-004
status: stable
description: Detects persistence mechanisms using Microsoft .NET naming without valid Microsoft signatures
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
        Details|contains|all:
            - 'Microsoft'
            - '.NET'
            - 'Runtime'
        Details|contains:
            - '\AppData\'
    filter_signed:
        Signature: 'Microsoft Corporation'
        SignatureStatus: 'Valid'
    condition: selection and not filter_signed
falsepositives:
    - Unsigned .NET development tools (verify legitimacy)
level: high
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1547.001
    - attack.t1036.005
    - fleetagentadvanced
```

#### Sigma Rule - Thread Injection from .NET Executable
```yaml
title: FleetAgentAdvanced Process Injection from .NET Executable
id: e5f6a7b8-fleet-injection-005
status: experimental
description: Detects process injection API sequences from .NET executables in AppData
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: api_call
detection:
    selection:
        Image|contains: '\AppData\'
        CallTrace|contains|all:
            - 'VirtualAllocEx'
            - 'WriteProcessMemory'
            - 'CreateRemoteThread'
    filter_legitimate:
        Image|contains:
            - '\Program Files\'
            - '\Program Files (x86)\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate development tools and debuggers from AppData
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
    - fleetagentadvanced
```

---

## PowerShell Hunting Queries

### FleetAgentAdvanced.exe Hunting Queries

#### PowerShell - Hunt for Quad-Persistence Indicators
```powershell
# Hunt for FleetAgentAdvanced quad-persistence mechanisms
function Get-FleetAgentPersistence {
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    Write-Host "[*] Hunting for FleetAgentAdvanced persistence indicators on $ComputerName..." -ForegroundColor Cyan

    $findings = @()

    # Check 1: Registry Run Keys
    Write-Host "`n[+] Checking Registry Run keys..." -ForegroundColor Yellow
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $runKeys = Get-ItemProperty $path -ErrorAction SilentlyContinue
            $runKeys.PSObject.Properties | Where-Object {
                $_.Name -match "\.NET.*Runtime.*Optimization" -or
                $_.Value -match "RuntimeOptimization\.exe"
            } | ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "Registry Run Key"
                    Location = $path
                    Name = $_.Name
                    Value = $_.Value
                    Severity = "CRITICAL"
                    Recommendation = "IMMEDIATE isolation and forensic analysis required"
                }
            }
        }
    }

    # Check 2: Scheduled Tasks
    Write-Host "[+] Checking Scheduled Tasks..." -ForegroundColor Yellow
    Get-ScheduledTask | Where-Object {
        $_.TaskName -match "\.NET.*Runtime.*Optimization" -or
        $_.Actions.Execute -match "RuntimeOptimization\.exe"
    } | ForEach-Object {
        $findings += [PSCustomObject]@{
            Type = "Scheduled Task"
            Location = $_.TaskPath
            Name = $_.TaskName
            Value = $_.Actions.Execute
            Severity = "CRITICAL"
            Recommendation = "IMMEDIATE isolation and forensic analysis required"
        }
    }

    # Check 3: Startup Folder LNK files
    Write-Host "[+] Checking Startup folders..." -ForegroundColor Yellow
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -Filter "*.lnk" -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match "\.NET.*Runtime.*Optimization"
            } | ForEach-Object {
                $findings += [PSCustomObject]@{
                    Type = "Startup Folder LNK"
                    Location = $path
                    Name = $_.Name
                    Value = $_.FullName
                    Severity = "CRITICAL"
                    Recommendation = "IMMEDIATE isolation and forensic analysis required"
                }
            }
        }
    }

    # Check 4: Dropped payload file
    Write-Host "[+] Checking for dropped payload..." -ForegroundColor Yellow
    $payloadPath = "$env:APPDATA\Microsoft\CLR\RuntimeOptimization.exe"
    if (Test-Path $payloadPath) {
        $fileHash = Get-FileHash $payloadPath -Algorithm SHA256
        $findings += [PSCustomObject]@{
            Type = "Dropped Payload File"
            Location = "AppData\Microsoft\CLR\"
            Name = "RuntimeOptimization.exe"
            Value = "SHA256: $($fileHash.Hash)"
            Severity = "CRITICAL"
            Recommendation = "IMMEDIATE isolation and forensic analysis required"
        }
    }

    # Results summary
    Write-Host "`n[*] Hunt Results:" -ForegroundColor Cyan
    if ($findings.Count -eq 0) {
        Write-Host "[+] No FleetAgentAdvanced indicators detected" -ForegroundColor Green
    } else {
        Write-Host "[!] THREAT DETECTED - $($findings.Count) indicator(s) found!" -ForegroundColor Red
        $findings | Format-Table -AutoSize

        Write-Host "`n[!] RECOMMENDED ACTIONS:" -ForegroundColor Red
        Write-Host "    1. ISOLATE system from network immediately" -ForegroundColor Yellow
        Write-Host "    2. Capture memory dump for forensic analysis" -ForegroundColor Yellow
        Write-Host "    3. Execute complete quad-persistence removal OR rebuild system" -ForegroundColor Yellow
        Write-Host "    4. Rotate credentials for all users on this system" -ForegroundColor Yellow
        Write-Host "    5. Hunt other systems for indicators of lateral movement" -ForegroundColor Yellow
    }

    return $findings
}

# Execute hunt
Get-FleetAgentPersistence
```

#### PowerShell - File Hash IOC Check
```powershell
# Check for known FleetAgentAdvanced file hashes
$iocHashes = @{
    "172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b" = "FleetAgentAdvanced.exe (Dropper)"
    "9fc6b69623133f5d6f1f4cda0ec4319300080c9bbaa0f88c93f01eeba84e80e7" = "RuntimeOptimization.exe (Payload)"
}

Write-Host "[*] Scanning for FleetAgentAdvanced file hash IOCs..." -ForegroundColor Cyan

# Scan common malware locations
$scanPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:USERPROFILE\Desktop"
)

$matches = @()
foreach ($path in $scanPaths) {
    if (Test-Path $path) {
        Write-Host "[+] Scanning: $path" -ForegroundColor Yellow
        Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -eq ".exe" } |
        ForEach-Object {
            $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($iocHashes.ContainsKey($hash)) {
                $matches += [PSCustomObject]@{
                    FilePath = $_.FullName
                    FileName = $_.Name
                    SHA256 = $hash
                    Identification = $iocHashes[$hash]
                    Severity = "CRITICAL"
                }
            }
        }
    }
}

if ($matches.Count -gt 0) {
    Write-Host "`n[!] MALWARE DETECTED - $($matches.Count) file(s) match IOC hashes!" -ForegroundColor Red
    $matches | Format-Table -AutoSize
} else {
    Write-Host "`n[+] No IOC hash matches found" -ForegroundColor Green
}
```

#### PowerShell - Task.xml Deletion Detection (Sysmon EventID 23)
```powershell
# Hunt for task.xml deletion events (FleetAgentAdvanced anti-forensics signature)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 |
Where-Object {
    $_.Id -eq 23 -and # FileDelete event
    $_.Message -like "*task.xml*"
} |
Select-Object TimeCreated,
    @{Name="ProcessName";Expression={$_.Properties[4].Value}},
    @{Name="DeletedFile";Expression={$_.Properties[2].Value}},
    @{Name="Severity";Expression={"HIGH - FleetAgentAdvanced anti-forensics pattern"}},
    @{Name="Recommendation";Expression={"Investigate for quad-persistence establishment"}} |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize
```

#### PowerShell - Rapid Persistence Establishment Detection
```powershell
# Detect rapid persistence establishment (4 mechanisms within 5 seconds)
$events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50000 |
Where-Object {
    ($_.Id -eq 13 -and $_.Message -like "*CurrentVersion\Run*") -or # Registry set
    ($_.Id -eq 11 -and $_.Message -like "*Startup*lnk*") -or # File created
    ($_.Id -eq 1 -and $_.Message -like "*schtasks*")  # Process created
} |
Group-Object {$_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")} |
Where-Object { $_.Count -ge 3 } | # 3+ persistence events in same second
ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.Name
        EventCount = $_.Count
        EventTypes = ($_.Group | Select-Object -ExpandProperty Id -Unique) -join ", "
        Severity = "CRITICAL"
        Pattern = "Rapid quad-persistence establishment"
        Recommendation = "Immediate investigation for FleetAgentAdvanced infection"
    }
}

if ($events) {
    Write-Host "[!] Rapid persistence establishment detected!" -ForegroundColor Red
    $events | Format-Table -AutoSize
} else {
    Write-Host "[+] No rapid persistence patterns detected" -ForegroundColor Green
}
```

---

## Network Detection Rules (Suricata/Snort)

### FleetAgentAdvanced.exe Network Detection

#### Suricata Rule - Distribution Infrastructure Connection
```suricata
alert tcp $HOME_NET any -> 109.230.231.37 any (msg:"FleetAgentAdvanced Distribution Infrastructure Connection"; flow:established,to_server; reference:url,github.com/yourusername/threat-intel/fleetagentadvanced; classtype:trojan-activity; sid:2100010; rev:1; priority:1; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity HIGH;)
```

#### Suricata Rule - Encrypted C2 Pattern from AppData Process
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious Encrypted Traffic from AppData Process - Potential FleetAgentAdvanced C2"; flow:established,to_server; content:"|17 03|"; depth:2; offset:0; flowbits:set,encrypted.appdata; reference:url,github.com/yourusername/threat-intel/fleetagentadvanced; classtype:trojan-activity; sid:2100011; rev:1; priority:2; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity MEDIUM;)
```

**Note**: FleetAgentAdvanced.exe exhibited no network activity during analysis. Network detection rules focus on distribution infrastructure and potential encrypted C2 patterns if/when RuntimeOptimization.exe C2 activates.

---

## EDR/SIEM Query Templates

### Splunk SPL Queries

#### SPL - Quad-Persistence Correlation
```spl
index=windows (source=WinEventLog:Security OR source=WinEventLog:Microsoft-Windows-Sysmon/Operational)
(
    (EventCode=13 TargetObject="*\\Run\\*" Details="*RuntimeOptimization.exe*") OR
    (EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*" CommandLine="*.NET Runtime Optimization*") OR
    (EventCode=11 TargetFilename="*\\Startup\\*.lnk" TargetFilename="*Runtime Optimization*")
)
| bucket _time span=5s
| stats count by _time, ComputerName, EventCode, User
| where count >= 2
| eval Severity="CRITICAL", Pattern="Quad-persistence establishment", Recommendation="Immediate isolation and forensic analysis"
| table _time, ComputerName, count, EventCode, Severity, Pattern, Recommendation
```

#### SPL - Task.xml Anti-Forensics Detection
```spl
index=windows source=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=23
TargetFilename="*task.xml"
| eval Severity="HIGH", Pattern="FleetAgentAdvanced anti-forensics", Recommendation="Investigate for quad-persistence"
| table _time, ComputerName, Image, TargetFilename, Severity, Pattern, Recommendation
```

### Microsoft Defender ATP (KQL) Advanced Hunting

#### KQL - FleetAgentAdvanced Persistence Hunt
```kusto
// Hunt for FleetAgentAdvanced quad-persistence indicators
let PersistenceEvents = union
    // Registry Run Keys
    (DeviceRegistryEvents
    | where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
    | where RegistryValueName has ".NET Runtime Optimization"
    | project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueData, InitiatingProcessFileName, PersistenceType = "Registry Run Key"),

    // Scheduled Tasks
    (DeviceProcessEvents
    | where FileName == "schtasks.exe"
    | where ProcessCommandLine has "/create"
    | where ProcessCommandLine has ".NET Runtime Optimization"
    | project Timestamp, DeviceName, ActionType="Scheduled Task Created", ProcessCommandLine, InitiatingProcessFileName, PersistenceType = "Scheduled Task"),

    // Startup Folder Files
    (DeviceFileEvents
    | where FolderPath has @"\Start Menu\Programs\Startup"
    | where FileName has ".NET Runtime Optimization"
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, PersistenceType = "Startup Folder");

PersistenceEvents
| summarize PersistenceCount = count(), PersistenceTypes = make_set(PersistenceType) by DeviceName, bin(Timestamp, 5s)
| where PersistenceCount >= 2 // 2+ persistence mechanisms within 5 seconds
| project Timestamp, DeviceName, PersistenceCount, PersistenceTypes, Severity = "CRITICAL", ThreatName = "FleetAgentAdvanced", Recommendation = "Immediate isolation and forensic analysis"
| order by Timestamp desc
```

#### KQL - RuntimeOptimization.exe Execution Hunt
```kusto
// Hunt for RuntimeOptimization.exe execution from AppData
DeviceProcessEvents
| where FolderPath has @"\AppData\Roaming\Microsoft\CLR\"
| where FileName == "RuntimeOptimization.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
    Severity = "CRITICAL",
    ThreatName = "FleetAgentAdvanced Payload Execution",
    Recommendation = "IMMEDIATE isolation - Active malware execution detected"
| order by Timestamp desc
```

---

## Elastic (EQL) Detection Queries

### EQL - Quad-Persistence Sequence Detection
```eql
sequence by host.name with maxspan=5s
  [registry where registry.path like "*CurrentVersion\\Run*" and registry.data.strings like "*RuntimeOptimization.exe*"]
  [file where file.path like "*Startup*" and file.extension == "lnk"]
  [process where process.name == "schtasks.exe" and process.args like "*/create*"]
```

### EQL - Task.xml Creation and Deletion Pattern
```eql
sequence by host.name, process.entity_id with maxspan=2s
  [process where process.name == "schtasks.exe" and process.args like "*/create*"]
  [file where event.action == "deletion" and file.name == "task.xml"]
```

---

## Implementation Guidance

### YARA Rule Deployment
1. **Compile Rules**: Use `yara` command to compile .yar files into binary format for performance
2. **Test Environment**: Validate rules against known samples in safe environment before production
3. **Integration**: Deploy to EDR solutions supporting YARA (CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender)
4. **Performance**: Monitor false positive rates; adjust string specificity as needed
5. **Versioning**: Track rule versions and maintain change log for tuning

### Sigma Rule Deployment
1. **SIEM Integration**: Use sigmac to convert rules to SIEM-specific query language (Splunk, QRadar, Elastic, ArcSight)
2. **Backend Configuration**: Ensure Windows Event Log collection is enabled (Sysmon highly recommended)
3. **Correlation**: Create correlation rules for multiple detection triggers within time windows
4. **Tuning**: Adjust thresholds based on environment baseline; quad-persistence pattern should be zero false positives
5. **Alerting**: Configure high-severity alerts for CRITICAL-level detections

### PowerShell Hunting Deployment
1. **Execution Policy**: Ensure PowerShell script execution is allowed for security team (`Set-ExecutionPolicy RemoteSigned`)
2. **Logging**: Enable PowerShell module and script block logging for forensic audit trail
3. **Scheduled Execution**: Run hunting queries regularly (daily for critical environments, weekly for lower-risk)
4. **Alert Integration**: Configure automatic alerting for positive findings via email/SIEM/ticketing
5. **Documentation**: Maintain runbook for positive hunt findings response procedures

### Network Rule Deployment
1. **IDS Placement**: Deploy at network perimeter and internal segments for comprehensive coverage
2. **Rule Updates**: Regularly update with new IOC patterns as infrastructure is discovered
3. **Performance Monitoring**: Monitor for impact on network performance; adjust rule specificity if needed
4. **Correlation**: Correlate network detections with host-based detections for high-confidence alerts
5. **Threat Intelligence Integration**: Feed detections into threat intelligence platforms for IOC enrichment

---

## Testing & Validation

### Detection Rule Testing
```powershell
# Test detection coverage against known IOCs
function Test-FleetAgentDetections {
    Write-Host "[*] Testing FleetAgentAdvanced detection coverage..." -ForegroundColor Cyan

    # Test 1: File hash detection
    Write-Host "`n[TEST 1] File hash IOC detection" -ForegroundColor Yellow
    # Create test file with known hash (for testing only - DO NOT execute malware)

    # Test 2: Registry detection
    Write-Host "[TEST 2] Registry persistence detection" -ForegroundColor Yellow
    # Query for test registry entries

    # Test 3: Scheduled task detection
    Write-Host "[TEST 3] Scheduled task detection" -ForegroundColor Yellow
    # Enumerate scheduled tasks with pattern matching

    # Test 4: Startup folder detection
    Write-Host "[TEST 4] Startup folder LNK detection" -ForegroundColor Yellow
    # Check startup folders for test entries

    Write-Host "`n[*] Detection testing complete" -ForegroundColor Cyan
}
```

---

## Additional Behavioral Indicators

### Process Behavior Patterns

#### Sigma Rule - .NET Dropper with Embedded Payload Pattern
```yaml
title: .NET Dropper with Base64 Embedded Payload Execution
id: f6a7b8c9-fleet-base64-payload-006
status: experimental
description: Detects .NET executables decoding Base64 payloads and writing to disk (FleetAgentAdvanced pattern)
author: Threat Intelligence Team
date: 2026/01/12
logsource:
    product: windows
    category: api_call
detection:
    selection:
        CallTrace|contains|all:
            - 'FromBase64String'
            - 'WriteAllBytes'
        Image|contains: '.exe'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Windows\'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate installers using Base64-encoded resources
level: medium
tags:
    - attack.defense_evasion
    - attack.t1027
    - fleetagentadvanced
```

### File System Monitoring

#### Sigma Rule - RuntimeOptimization.exe File Creation
```yaml
title: FleetAgentAdvanced RuntimeOptimization.exe File Creation
id: a7b8c9d0-fleet-file-creation-007
status: stable
description: Detects creation of RuntimeOptimization.exe file in AppData\Microsoft\CLR\ directory
author: Threat Intelligence Team
date: 2026/01/12
logsource:
    product: windows
    category: file_event
detection:
    selection:
        EventID: 11 # File created
        TargetFilename|contains|all:
            - '\AppData\Roaming\Microsoft\CLR\'
            - 'RuntimeOptimization.exe'
    condition: selection
falsepositives:
    - None expected (legitimate .NET components do not use this path)
level: critical
tags:
    - attack.execution
    - attack.t1204.002
    - fleetagentadvanced
```

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.

---

**Report Version**: 1.0
**Last Updated**: 2026-01-12
**Maintained By**: Threat Intelligence Team
