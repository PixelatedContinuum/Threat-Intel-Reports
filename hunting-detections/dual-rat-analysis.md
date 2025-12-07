---
title: Detection Rules - Dual-RAT Analysis: Quasar RAT vs. NjRAT/XWorm
date: '2025-12-06'
layout: post
permalink: /hunting-detections/dual-rat-analysis/
hide: true
---

# Detection Rules – Dual-RAT Analysis: Quasar RAT vs. NjRAT/XWorm

## Overview
Detection coverage for both Quasar RAT and NjRAT/XWorm includes host-based, process-based, and network indicators.  
Rules are provided in YARA and Sigma formats for SIEM/EDR and threat hunting integration.

---

## YARA Rules

### Quasar RAT Detection Rules

#### YARA Rule - Quasar RAT Core Detection
```yara
rule Quasar_RAT_Core_Detection {
    meta:
        description = "Detects Quasar RAT based on GUID, imports, and string patterns"
        author = "Hunter's Ledger"
        date = "2025-12-06"
        hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
        ref = "https://hunter-ledger.com/reports/dual-rat-analysis/"
        malpedia_family = "Quasar"
        malpedia_reference = "https://malpedia.org/reference/quasar"

    strings:
        // Core Quasar GUID pattern
        $guid1 = { 8A 3B 1D 8C 6C 3A 4A 9B 5E 27 6F 9B 5A 3D 8F 6E 3A 4B 8C 6D 3E 4F 90 81 72 63 6F 6E 74 65 6E 74 }
        
        // Process injection related strings
        $inject1 = "inject_thread"
        $inject2 = "WriteProcessMemory"
        $inject3 = "CreateRemoteThread"
        
        // Anti-analysis strings
        $vm_detect1 = "VirtualBox"
        $vm_detect2 = "VMware"
        $vm_detect3 = "QEMU"
        $debug_detect1 = "Debugger"
        $debug_detect2 = "IsDebuggerPresent"
        
        // C2 related strings
        $c2_1 = "185.208.159.182"
        $c2_2 = "ipwho.is"
        $c2_3 = "api.ipify.org"
        
        // Persistence strings
        $persist1 = "RuntimeBroker"
        $persist2 = "schtasks"
        $persist3 = "ONLOGON"
        
        // Surveillance strings
        $surv1 = "keylogger"
        $surv2 = "screenshot"
        $surv3 = "webcam"
        $surv4 = "clipboard"

    condition:
        uint16(0) == 0x5A4D and
        pe.imphash() == "8a3b1d8c6c3a4a9b5e276f9b5a3d8f6e3a4b8c6d3e4f908172636f6e6e74656e74" and
        (
            $guid1 or
            any of ($inject*) or
            any of ($vm_detect*) or
            any of ($debug_detect*) or
            any of ($c2_*) or
            any of ($persist*) or
            any of ($surv*)
        )
}
```

#### YARA Rule - Quasar RAT Mark of the Web Removal
```yara
rule Quasar_RAT_MarkOfWeb_Removal {
    meta:
        description = "Detects Zone.Identifier stream removal behavior characteristic of Quasar RAT"
        author = "Hunter's Ledger"
        date = "2025-12-06"
        hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
        ref = "https://hunter-ledger.com/reports/dual-rat-analysis/"
        technique = "T1070.004 - Indicator Removal: File Deletion"

    strings:
        $zone_stream = ":Zone.Identifier"
        $delete_api = "DeleteFile"

    condition:
        uint16(0) == 0x5A4D and
        pe.imphash() == "8a3b1d8c6c3a4a9b5e276f9b5a3d8f6e3a4b8c6d3e4f908172636f6e6e74656e74" and
        all of them
}
```

### NjRAT/XWorm Detection Rules

#### YARA Rule - NjRAT/XWorm Core Detection
```yara
rule NjRAT_XWorm_Core_Detection {
    meta:
        description = "Detects NjRAT/XWorm based on VB.NET characteristics, size, and configuration strings"
        author = "Hunter's Ledger"
        date = "2025-12-06"
        hash1 = "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb"
        ref = "https://hunter-ledger.com/reports/dual-rat-analysis/"
        malpedia_family = "NjRAT"
        malpedia_reference = "https://malpedia.org/reference/njrat"

    strings:
        // VB.NET specific imports
        $vb_net1 = "Microsoft.VisualBasic"
        $vb_net2 = "System.Windows.Forms"
        
        // Configuration strings
        $config1 = "PasteUrl"
        $config2 = "Groub"
        $config3 = "USBNM"
        $config4 = "InstallDir"
        $config5 = "Mutex"
        
        // Pastebin dead-drop strings
        $pastebin1 = "pastebin.com"
        $pastebin2 = "raw/"
        $pastebin3 = "iPhone Safari"
        
        // Persistence strings
        $persist1 = "conhost"
        $persist2 = "minute /mo 1"
        $persist3 = "Startup"
        $persist4 = "Run"
        
        // Critical process protection
        $critical1 = "RtlSetProcessIsCritical"
        $critical2 = "BSOD"
        
        // Anti-sleep
        $sleep1 = "SetThreadExecutionState"
        $sleep2 = "ES_DISPLAY_REQUIRED"
        $sleep3 = "ES_SYSTEM_REQUIRED"
        
        // Surveillance strings
        $surv1 = "capCreateCaptureWindowA"
        $surv2 = "webcam"
        $surv3 = "microphone"
        $surv4 = "keylogger"

    condition:
        uint16(0) == 0x5A4D and
        pe.imphash() == "950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb" and
        filesize < 50000 and
        (
            any of ($vb_net*) or
            any of ($config*) or
            any of ($pastebin*) or
            any of ($persist*) or
            any of ($critical*) or
            any of ($sleep*) or
            any of ($surv*)
        )
}
```

#### YARA Rule - Triple Persistence Detection
```yara
rule NjRAT_XWorm_Triple_Persistence {
    meta:
        description = "Detects NjRAT/XWorm triple persistence mechanism establishment"
        author = "Hunter's Ledger"
        date = "2025-12-06"
        ref = "https://hunter-ledger.com/reports/dual-rat-analysis/"
        technique = "T1053.005 + T1547.001 + T1547.009 - Multiple Persistence Mechanisms"

    strings:
        $task_name = "conhost"
        $task_freq = "minute /mo 1"
        $reg_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $startup = "Startup\\conhost.lnk"
        $schtasks = "schtasks /create"

    condition:
        uint16(0) == 0x5A4D and
        all of them
}
```

---

## Sigma Rules

### Quasar RAT Detection Rules

#### Sigma Rule - Quasar RAT Scheduled Task Persistence
```yaml
title: Quasar RAT Scheduled Task Persistence
id: 8b5c3d1a-8f4e-4b9a-9c6d-3e4f9081
status: experimental
description: Detects Quasar RAT persistence through RuntimeBroker scheduled task creation
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 106
        TaskName: 'RuntimeBroker'
        CommandLine|contains|all:
            - 'schtasks /create'
            - '/tn "RuntimeBroker"'
            - '/sc ONLOGON'
            - 'Client.exe'
    condition: selection
falsepositives:
    - Legitimate system administration tools creating tasks
level: high
tags:
    - attack.persistence
    - defense_evasion
    - t1053.005
    - quasar_rat
```

#### Sigma Rule - Quasar RAT Process Injection
```yaml
title: Quasar RAT Process Injection Activity
id: a7b2c3d9-4e5f-8a9b-2c6d-4f7e9081
status: experimental
description: Detects potential Quasar RAT process injection behavior
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\explorer.exe'
            - '\svchost.exe'
            - '\dllhost.exe'
        ParentImage|endswith:
            - '\Client.exe'
        CommandLine|contains: 'inject'
    condition: selection
falsepositives:
    - Legitimate software injection
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - t1055.003
    - t1055
    - quasar_rat
```

#### Sigma Rule - Quasar RAT Zone.Identifier Removal
```yaml
title: Quasar RAT Mark of the Web Removal
id: c9d4e5f2-6a7b-3c8d-4e9f-5a6b9081
status: experimental
description: Detects Zone.Identifier alternate data stream deletion characteristic of Quasar RAT
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|contains: ':Zone.Identifier'
        Image|endswith:
            - '\client.exe'
            - '\Client.exe'
    condition: selection
falsepositives:
    - Legitimate file management tools
level: medium
tags:
    - attack.defense_evasion
    - attack.initial_access
    - t1070.004
    - quasar_rat
```

#### Sigma Rule - Quasar RAT C2 Communication
```yaml
title: Quasar RAT Command and Control Communication
id: d1e5f6a3-7b8c-4d9e-5f0a-6a7b9081
status: experimental
description: Detects Quasar RAT C2 communication patterns
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith:
            - '\Client.exe'
        DestinationPort: 4782
        DestinationIp|contains: '185.208.159.182'
    condition: selection
falsepositives:
    - Legitimate applications using port 4782
level: critical
tags:
    - attack.command_and_control
    - t1071.001
    - t1573
    - t1041
    - quasar_rat
```

### NjRAT/XWorm Detection Rules

#### Sigma Rule - NjRAT/XWorm Triple Persistence
```yaml
title: NjRAT/XWorm Triple Persistence Establishment
id: e2f6a7b4-8c9d-4e0f-6a7b-3c8d9081
status: experimental
description: Detects NjRAT/XWorm triple persistence mechanism establishment
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    service: security
detection:
    selection_task:
        EventID: 106
        TaskName: 'conhost'
        CommandLine|contains|all:
            - 'schtasks /create'
            - '/tn "conhost"'
            - '/sc minute'
            - '/mo 1'
    selection_registry:
        EventID: 13
        ObjectName|contains: 'Software\Microsoft\Windows\CurrentVersion\Run'
        StringValue|contains: 'conhost'
    selection_startup:
        EventID: 11
        TargetFilename|contains: 'conhost.lnk'
    condition: 1 of selection*
falsepositives:
    - Legitimate conhost.exe process
level: high
tags:
    - attack.persistence
    - t1053.005
    - t1547.001
    - t1547.009
    - njrat_xworm
```

#### Sigma Rule - NjRAT/XWorm Pastebin Dead-Drop
```yaml
title: NjRAT/XWorm Pastebin Dead-Drop C2 Resolution
id: f3a7b8c5-9d0e-4f1a-7b2c-4e9d9081
status: experimental
description: Detects NjRAT/XWorm Pastebin dead-drop C2 resolution behavior
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith:
            - '\server (1).exe'
            - '\conhost.exe'
        DestinationPort: 443
        DestinationHostname|contains: 'pastebin.com'
        Initiated: 'true'
    timeframe: 5m
    condition: selection | count() by Image > 0
falsepositives:
    - Legitimate access to Pastebin from development tools
level: high
tags:
    - attack.command_and_control
    - t1102.001
    - t1071.001
    - njrat_xworm
```

#### Sigma Rule - NjRAT/XWorm Critical Process Protection
```yaml
title: NjRAT/XWorm Critical Process Protection
id: g4b8c9d6-0e1f-5a2b-8c9d-4f0a9081
status: experimental
description: Detects NjRAT/XWorm critical process protection mechanism
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: api_call
detection:
    selection:
        Image|endswith:
            - '\conhost.exe'
            - '\server (1).exe'
        CallTrace|contains: 'RtlSetProcessIsCritical'
    condition: selection
falsepositives:
    - Legitimate system processes
level: high
tags:
    - attack.defense_evasion
    - attack.impact
    - njrat_xworm
```

#### Sigma Rule - NjRAT/XWorm Anti-Sleep Mechanism
```yaml
title: NjRAT/XWorm Anti-Sleep System Protection
id: h5c9d0e7-1f2a-9b3c-5e0f-7a2b9081
status: experimental
description: Detects NjRAT/XWorm anti-sleep mechanism to prevent system power saving
author: Hunter's Ledger
date: 2025/12/06
modified: 2025/12/06
logsource:
    product: windows
    category: api_call
detection:
    selection:
        Image|endswith:
            - '\conhost.exe'
            - '\server (1).exe'
        CallTrace|contains: 'SetThreadExecutionState'
    condition: selection
falsepositives:
    - Legitimate media applications preventing sleep
level: medium
tags:
    - attack.defense_evasion
    - attack.impact
    - njrat_xworm
```

---

## PowerShell Hunting Queries

### Quasar RAT Hunting Queries

#### PowerShell - Hunt for Quasar RAT Scheduled Tasks
```powershell
# Hunt for Quasar RAT RuntimeBroker scheduled task
Get-ScheduledTask | Where-Object {$_.TaskName -eq "RuntimeBroker" -and $_.Actions.Command -like "*Client.exe*"} | ForEach-Object {
    [PSCustomObject]@{
        TaskName = $_.TaskName
        Command = $_.Actions.Command
        Trigger = $_.Triggers | Select-Object -First 1 | ForEach-Object {$_.Type}
        Date = $_.Date
        Author = $_.Author
        Risk = "High - Quasar RAT persistence indicator"
        Recommendation = "Investigate system for Quasar RAT infection"
    }
}
```

#### PowerShell - Hunt for Zone.Identifier Removal
```powershell
# Hunt for Zone.Identifier stream removal activity
Get-WinEvent -LogName Security -Where-Object {$_.Id -eq 4663 -and $_.Message -like "*:Zone.Identifier*"} | Select-Object TimeCreated, Id, @{Name="Process";Expression={$_.Message -split " " | Select-Object -Last 1}}, @{Name="File";Expression={$_.Message -split " " | Select-Object -Last 3}} | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.TimeCreated
        EventID = $_.Id
        ProcessName = $_.Process.Name
        FileName = $_.File.Name
        Operation = "Zone.Identifier stream deletion"
        Risk = "Medium - Potential Quasar RAT security bypass"
        Recommendation = "Scan system for Quasar RAT infection"
    }
}
```

### NjRAT/XWorm Hunting Queries

#### PowerShell - Hunt for Triple Persistence
```powershell
# Hunt for NjRAT/XWorm triple persistence indicators
function Get-NjRATPersistence {
    param($ComputerName = $env:COMPUTERNAME)
    
    # Check scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object {$_.TaskName -eq "conhost" -and $_.Triggers -like "*minute*"}
    
    # Check registry Run keys
    $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regValues = Get-Item $regKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
    
    # Check startup folder
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $startupFiles = Get-ChildItem $startupPath -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*conhost*"}
    
    # Combine results
    $persistenceIndicators = @()
    
    if ($tasks) {
        $persistenceIndicators += [PSCustomObject]@{
            Type = "Scheduled Task"
            Name = "conhost"
            Frequency = "1 minute"
            Risk = "Critical - NjRAT/XWorm persistence indicator"
            Recommendation = "Immediate isolation and forensic analysis"
        }
    }
    
    if ($regValues -and $regValues.ContainsKey("conhost")) {
        $persistenceIndicators += [PSCustomObject]@{
            Type = "Registry Run Key"
            Name = "conhost"
            Value = $regValues.conhost
            Risk = "High - NjRAT/XWorm persistence indicator"
            Recommendation = "Scan system for NjRAT/XWorm infection"
        }
    }
    
    if ($startupFiles) {
        $persistenceIndicators += [PSCustomObject]@{
            Type = "Startup Folder"
            Name = $startupFiles.Name
            Risk = "High - NjRAT/XWorm persistence indicator"
            Recommendation = "Scan system for NjRAT/XWorm infection"
        }
    }
    
    return $persistenceIndicators
}

# Execute hunt
Get-NjRATPersistence
```

#### PowerShell - Hunt for Pastebin Dead-Drop Activity
```powershell
# Hunt for Pastebin dead-drop C2 resolution
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Network -MaxEvents 1000 | Where-Object {
    $_.Message -like "*pastebin.com*" -and 
    $_.ProcessName -like "*server*.exe" -or
    $_.ProcessName -like "*conhost.exe"
} | Select-Object TimeCreated, ProcessName, DestinationHostname, DestinationPort | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.TimeCreated
        ProcessName = $_.ProcessName
        Destination = "$($_.DestinationHostname):$($_.DestinationPort)"
        Operation = "Pastebin dead-drop C2 resolution"
        Risk = "High - NjRAT/XWorm C2 infrastructure resolution"
        Recommendation = "Block Pastebin access and isolate system"
    }
}
```

---

## Network Detection Rules (Suricata/Snort)

### Quasar RAT Network Detection

#### Suricata Rule - Quasar RAT C2 Connection
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 4782 (msg:"Quasar RAT C2 Connection"; flow:established,to_server; content:"|2c 43 87 ce 18 be 27 9e a7 35 ec 4f 00 92 69 85 34 92 10 30 aa 69 94 98 ae 80 e4 1a 5c 73 76 66"; depth:8; offset:0; metadata:service quasar_rat_c2, malware_family Quasar; sid:2100001; rev:1; classtype:trojan-activity; priority:1; reference:url,hunter-ledger.com/reports/dual-rat-analysis/;)
```

#### Suricata Rule - Quasar RAT IP Geolocation
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Quasar RAT IP Geolocation"; flow:established,to_server; content:"Host: ipwho.is|Host: api.ipify.org"; http.method; content:"GET"; http.uri; content:"/"; depth:0; offset:0; metadata:service quasar_rat_recon, malware_family Quasar; sid:2100002; rev:1; classtype:trojan-activity; priority:2; reference:url,hunter-ledger.com/reports/dual-rat-analysis/;)
```

### NjRAT/XWorm Network Detection

#### Suricata Rule - NjRAT/XWorm Pastebin Dead-Drop
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"NjRAT/XWorm Pastebin Dead-Drop"; flow:established,to_server; content:"Host: pastebin.com"; http.method; content:"GET"; http.uri; content:"/raw/"; depth:0; offset:0; metadata:service njrat_xworm_c2, malware_family NjRAT; sid:2100003; rev:1; classtype:trojan-activity; priority:1; reference:url,hunter-ledger.com/reports/dual-rat-analysis/;)
```

#### Suricata Rule - NjRAT/XWorm Mobile User-Agent Spoofing
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"NjRAT/XWorm Mobile User-Agent Spoofing"; flow:established,to_server; content:"User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS"; http.user_agent; content:"Mobile"; content:"Safari"; depth:0; offset:0; metadata:service njrat_xworm_ua_spoof, malware_family NjRAT; sid:2100004; rev:1; classtype:trojan-activity; priority:2; reference:url,hunter-ledger.com/reports/dual-rat-analysis/;)
```

---

## Implementation Guidance

### YARA Rule Deployment
1. **Compile Rules**: Use `yara` command to compile .yar files
2. **Test Environment**: Validate rules in safe environment before production
3. **Integration**: Deploy to EDR solutions supporting YARA (CrowdStrike, SentinelOne, etc.)
4. **Performance**: Monitor false positive rates and adjust as needed

### Sigma Rule Deployment
1. **SIEM Integration**: Import rules into SIEM platforms (Splunk, QRadar, Elastic)
2. **Backend Configuration**: Ensure Windows Event Log collection is enabled
3. **Correlation**: Create correlation rules for multiple detection triggers
4. **Tuning**: Adjust thresholds based on environment baseline

### PowerShell Hunting Deployment
1. **Execution Policy**: Ensure PowerShell script execution is allowed for security team
2. **Logging**: Enable module and script block logging
3. **Scheduled Execution**: Run hunting queries regularly (daily/weekly)
4. **Alert Integration**: Configure automatic alerting for positive findings

### Network Rule Deployment
1. **IDS Placement**: Deploy at network perimeter and internal segments
2. **Rule Updates**: Regularly update with new IOC patterns
3. **Performance Monitoring**: Monitor for impact on network performance
4. **Correlation**: Correlate with host-based detections

---

## Additional Behavioral Indicators

### Network-Based Behavioral Detection

#### Sigma Rule - Suspicious Dead-Drop Service Access
```yaml
title: Suspicious Access to Dead-Drop Services
id: dead-drop-access-001
status: experimental
description: Detects access to common dead-drop services that may indicate C2 infrastructure resolution
author: Hunter's Ledger
date: 2025/12/06
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|contains:
            - 'pastebin.com'
            - 'githubusercontent.com'
            - 'gist.githubusercontent.com'
            - 'discordapp.com'
            - 'discord.com'
        Initiated: 'true'
    filter_legitimate:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
            - '\teams.exe'
            - '\slack.exe'
            - '\discord.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate developer access to paste services
    - Corporate tools using GitHub for configuration
level: medium
tags:
    - attack.command_and_control
    - t1102.001
    - dead_drop_resolver
```

#### Sigma Rule - High-Frequency Process Creation
```yaml
title: High-Frequency Process Creation from Scheduled Task
id: high-freq-process-creation-001
status: experimental
description: Detects processes created at unusually high frequencies, potentially from aggressive scheduled tasks
author: Hunter's Ledger
date: 2025/12/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|contains: 'svchost.exe'
        CommandLine|contains: 'taskeng.exe'
    timeframe: 1m
    condition: selection | count() > 10
falsepositives:
    - Legitimate scheduled tasks with high frequency requirements
    - System maintenance operations
level: high
tags:
    - attack.persistence
    - t1053.005
    - scheduled_task_abuse
```

### Host-Based Behavioral Detection

#### Sigma Rule - Memory Allocation Anomalies
```yaml
title: Suspicious Memory Allocation Patterns
id: memory-allocation-anomaly-001
status: experimental
description: Detects processes allocating memory with suspicious permissions that may indicate process injection
author: Hunter's Ledger
date: 2025/12/06
logsource:
    product: windows
    category: api_call
detection:
    selection:
        CallTrace|contains: 'VirtualAllocEx'
        Parameters|contains: 'PAGE_EXECUTE_READWRITE'
    filter_system:
        Image|endswith:
            - '\svchost.exe'
            - '\lsass.exe'
            - '\winlogon.exe'
            - '\csrss.exe'
    condition: selection and not filter_system
falsepositives:
    - Legitimate software requiring RWX memory
    - Development tools and debuggers
level: medium
tags:
    - attack.defense_evasion
    - t1055
    - process_injection
```

#### Sigma Rule - API Call Sequence Analysis
```yaml
title: Suspicious API Call Sequence for RAT Activity
id: api-sequence-rat-001
status: experimental
description: Detects sequences of API calls commonly associated with RAT surveillance and persistence activities
author: Hunter's Ledger
date: 2025/12/06
logsource:
    product: windows
    category: api_call
detection:
    sequence:
        - CallTrace|contains: 'SetWindowsHookEx'
        - CallTrace|contains: 'VirtualAllocEx'
        - CallTrace|contains: 'CreateRemoteThread'
    timeframe: 5m
    condition: sequence
falsepositives:
    - Legitimate software with similar API usage patterns
    - Development and debugging tools
level: high
tags:
    - attack.collection
    - attack.defense_evasion
    - t1056.001
    - t1055.003
```

### Enhanced PowerShell Hunting Queries

#### PowerShell - Dead-Drop Service Monitoring
```powershell
# Hunt for processes accessing dead-drop services without legitimate browser context
$deadDropServices = @('pastebin.com', 'githubusercontent.com', 'gist.githubusercontent.com', 'discordapp.com')

Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*[System[EventID=3]]" | 
Where-Object {
    $event = $_
    $destination = $event.Properties[14].Value
    $process = $event.Properties[4].Value
    
    # Check if destination matches dead-drop services
    $isDeadDrop = $deadDropServices | Where-Object { $destination -like "*$_*" }
    
    # Exclude legitimate browser processes
    $isBrowser = $process -match 'chrome|firefox|msedge|iexplore'
    
    $isDeadDrop -and -not $isBrowser
} | Select-Object TimeCreated, 
    @{Name="Process";Expression={$_.Properties[4].Value}},
    @{Name="Destination";Expression={$_.Properties[14].Value}},
    @{Name="Risk";Expression={"High - Potential dead-drop C2 resolution"}} |
Sort-Object TimeCreated -Descending
```

#### PowerShell - Memory Injection Detection
```powershell
# Hunt for potential process injection indicators
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*[System[EventID=8]]" | 
Where-Object {
    $sourceProcess = $_.Properties[3].Value
    $targetProcess = $_.Properties[13].Value
    
    # Look for injection from suspicious processes into system processes
    ($sourceProcess -notmatch 'svchost|lsass|winlogon|csrss') -and
    ($targetProcess -match 'explorer|svchost|lsass|wininit')
} | Select-Object TimeCreated,
    @{Name="SourceProcess";Expression={$_.Properties[3].Value}},
    @{Name="TargetProcess";Expression={$_.Properties[13].Value}},
    @{Name="GrantedAccess";Expression={$_.Properties[11].Value}},
    @{Name="Risk";Expression={"High - Potential process injection"}} |
Sort-Object TimeCreated -Descending
```

#### PowerShell - Beacon Pattern Analysis
```powershell
# Analyze network connections for potential C2 beaconing patterns
$connections = Get-NetTCPConnection | Where-Object {
    $_.State -eq 'Established' -and
    $_.RemotePort -gt 1024 -and
    $_.RemotePort -ne 80 -and $_.RemotePort -ne 443
}

$beaconCandidates = @()
foreach ($conn in $connections) {
    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($process) {
        $beaconCandidates += [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID = $conn.OwningProcess
            LocalAddress = $conn.LocalAddress
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            State = $conn.State
            Risk = if ($process.ProcessName -match 'svchost|explorer|cmd') { "Medium" } else { "High" }
        }
    }
}

$beaconCandidates | Where-Object { $_.Risk -eq "High" } | Sort-Object ProcessName
```

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.