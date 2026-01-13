---
title: Detection Rules - FleetAgentFUD.exe - WebSocket RAT with FUD Evasion
date: '2026-01-12'
layout: post
permalink: /hunting-detections/fleetagentfud-exe/
hide: true
---

# Detection Rules – FleetAgentFUD.exe: WebSocket RAT with FUD Evasion & PowerShell Execution

## Overview
Comprehensive detection coverage for FleetAgentFUD.exe, a "Fully Undetectable" Remote Access Trojan employing WebSocket-based C2, PowerShell Execution Policy bypass, clipboard data theft, and file download capabilities. Rules target the malware's distinctive FUD evasion patterns, WebSocket protocol usage, and PowerShell bypass techniques.

**Key Detection Opportunities:**
- PowerShell Execution Policy bypass pattern (`-Exec Bypass` command-line arguments)
- Repeated clipboard monitoring (Get-Clipboard executed 10+ times per hour)
- WebSocket connection establishment from .NET executables in AppData directories
- .NET WebClient file download activity to Public/Temp folders
- VirtualProtect RWX memory allocation from untrusted processes
- Small file size signature (17,920 bytes exact match)

---

## YARA Rules

### FleetAgentFUD.exe Core Detection Rules

#### YARA Rule - FleetAgentFUD.exe File Hash & Characteristics
```yaml
rule FleetAgentFUD_FileHash_Exact {
    meta:
        description = "Detects FleetAgentFUD.exe by exact file hash and size"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        hash_sha256 = "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff"
        hash_sha1 = "51aa8b08dc67cb91435ce58d4453a8ae5e0dd577"
        hash_md5 = "5b37f5fc42384834b7aac5081a5bac85"
        severity = "CRITICAL"
        ref = "Open Directory 109.230.231.37"
        family = "FleetAgentFUD"

    condition:
        uint16(0) == 0x5A4D and // PE file
        filesize == 17920 and // Exact size match
        hash.sha256(0, filesize) == "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff"
}
```

#### YARA Rule - FleetAgentFUD WebSocket C2 Signatures
```yaml
rule FleetAgentFUD_WebSocket_C2_Pattern {
    meta:
        description = "Detects FleetAgentFUD.exe WebSocket C2 implementation via protocol strings"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        technique = "T1071.001 - Application Layer Protocol: Web Protocols"
        family = "FleetAgentFUD"

    strings:
        // WebSocket handshake headers
        $ws1 = "Connection: Upgrade" ascii wide
        $ws2 = "Sec-WebSocket-Key: " ascii wide
        $ws3 = "Sec-WebSocket-Version: 13" ascii wide
        $ws4 = "X-Agent-Secret: " ascii wide

        // WebSocket message types
        $msg1 = "\"type\":\"register\"" ascii wide nocase
        $msg2 = "\"type\":\"heartbeat\"" ascii wide nocase
        $msg3 = "machine_id" ascii wide
        $msg4 = "hostname" ascii wide
        $msg5 = "os_version" ascii wide
        $msg6 = "agent_ver" ascii wide

        // Command types
        $cmd1 = "cmd_type" ascii wide
        $cmd2 = "command_id" ascii wide
        $cmd3 = "powershell" ascii wide
        $cmd4 = "sysinfo" ascii wide
        $cmd5 = "clipboard" ascii wide

        // .NET networking APIs
        $api1 = "System.Net.Sockets" ascii
        $api2 = "TcpClient" ascii
        $api3 = "NetworkStream" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50KB and
        (
            // Strong match: WebSocket headers + message types
            (3 of ($ws*) and 3 of ($msg*)) or

            // Moderate match: WebSocket + command types
            (2 of ($ws*) and 3 of ($cmd*)) or

            // High confidence: All WebSocket headers + .NET networking
            (all of ($ws*) and any of ($api*))
        )
}
```

#### YARA Rule - PowerShell Execution Policy Bypass Strings
```yaml
rule FleetAgentFUD_PowerShell_Bypass {
    meta:
        description = "Detects FleetAgentFUD.exe PowerShell Execution Policy bypass string"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        technique = "T1562.001 - Impair Defenses + T1059.001 - PowerShell"
        family = "FleetAgentFUD"

    strings:
        // PowerShell bypass command-line
        $ps1 = "-NoP -NonI -W Hidden -Exec Bypass -C " ascii wide
        $ps2 = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass" ascii wide

        // PowerShell command variations
        $ps3 = "powershell" ascii wide nocase
        $ps4 = "Get-Clipboard" ascii wide

        // Suspicious PowerShell usage combinations
        $ps5 = "-Exec Bypass" ascii wide
        $ps6 = "-ExecutionPolicy Bypass" ascii wide
        $ps7 = "-W Hidden" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100KB and
        (
            // Exact bypass string match
            $ps1 or
            $ps2 or

            // PowerShell + bypass flags
            ($ps3 and ($ps5 or $ps6) and $ps7)
        )
}
```

#### YARA Rule - FUD RAT Behavioral Pattern
```yaml
rule FleetAgentFUD_FUD_RAT_Behavioral_Pattern {
    meta:
        description = "Detects FUD RAT behavioral characteristics: small size, WebSocket, clipboard, PowerShell"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        family = "FleetAgentFUD"

    strings:
        // Clipboard monitoring
        $clip1 = "Get-Clipboard" ascii wide
        $clip2 = "clipboard" ascii wide nocase

        // WebSocket indicators
        $ws1 = "Sec-WebSocket-Key" ascii wide
        $ws2 = "Connection: Upgrade" ascii wide

        // PowerShell execution
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-Exec Bypass" ascii wide
        $ps3 = "-ExecutionPolicy Bypass" ascii wide

        // System reconnaissance
        $recon1 = "sysinfo" ascii wide
        $recon2 = "processes" ascii wide
        $recon3 = "network" ascii wide
        $recon4 = "users" ascii wide

        // File download capability
        $dl1 = "DownloadFile" ascii wide
        $dl2 = "WebClient" ascii wide

        // .NET Framework
        $net1 = "System.Net" ascii
        $net2 = "v4.0.30319" ascii

        // Hidden window execution
        $hide1 = "ShowWindow" ascii
        $hide2 = "WindowStyle Hidden" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50KB and // FUD optimization: small file size
        (
            // Clipboard + WebSocket + PowerShell = High confidence FUD RAT
            (any of ($clip*) and any of ($ws*) and any of ($ps*)) or

            // WebSocket + Reconnaissance + Download = RAT functionality
            (any of ($ws*) and 2 of ($recon*) and any of ($dl*)) or

            // PowerShell + Clipboard + Hidden Window = Stealth RAT
            (any of ($ps*) and any of ($clip*) and any of ($hide*))
        )
}
```

#### YARA Rule - FleetAgent Family Signature
```yaml
rule FleetAgent_Family_General {
    meta:
        description = "Detects FleetAgent malware family characteristics (FUD and Advanced variants)"
        author = "Threat Intelligence Team"
        date = "2026-01-12"
        severity = "HIGH"
        family = "FleetAgent"
        related_samples = "FleetAgentAdvanced.exe, FleetAgentFUD.exe"

    strings:
        // Family naming patterns
        $name1 = "FleetAgent" ascii wide nocase
        $name2 = "FleetAgentFUD" ascii wide
        $name3 = "FleetAgentAdvanced" ascii wide
        $name4 = "Microsoft.NET.Runtime" ascii wide // Common masquerading

        // Agent version strings
        $ver1 = "agent_ver" ascii wide
        $ver2 = "3.0.0" ascii wide

        // Configuration variables
        $cfg1 = "machine_id" ascii wide
        $cfg2 = "hostname" ascii wide
        $cfg3 = "agent_ver" ascii wide

        // Common APIs
        $api1 = "VirtualProtect" ascii
        $api2 = "ToBase64String" ascii
        $api3 = "GetProcAddress" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Direct family name match
            any of ($name*) or

            // Configuration + Version pattern
            (2 of ($cfg*) and any of ($ver*)) or

            // Microsoft.NET masquerading + suspicious APIs
            ($name4 and 2 of ($api*))
        )
}
```

---

## Sigma Rules

### FleetAgentFUD.exe Detection Rules

#### Sigma Rule - PowerShell Execution Policy Bypass from AppData
```yaml
title: FleetAgentFUD PowerShell Execution Policy Bypass from AppData
id: a1b2c3d4-fleetfud-powershell-bypass-001
status: stable
description: Detects PowerShell execution with Execution Policy bypass from suspicious AppData locations (FleetAgentFUD RAT pattern)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - '-Exec'
            - 'Bypass'
    selection_parent:
        ParentImage|contains: '\AppData\'
    selection_hidden:
        CommandLine|contains:
            - '-W Hidden'
            - '-WindowStyle Hidden'
    condition: selection_powershell and selection_parent and selection_hidden
falsepositives:
    - Legitimate software installers using PowerShell from AppData (verify digital signature)
    - Administrative scripts executed from user directories (review context)
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1562.001
    - fleetagentfud
```

#### Sigma Rule - Repeated Clipboard Monitoring (Get-Clipboard)
```yaml
title: FleetAgentFUD Clipboard Monitoring - Repeated Get-Clipboard Execution
id: b2c3d4e5-fleetfud-clipboard-monitor-002
status: stable
description: Detects repeated PowerShell Get-Clipboard executions indicating clipboard data theft (FleetAgentFUD credential theft technique)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains: 'Get-Clipboard'
    timeframe: 1h
    condition: selection | count(ComputerName, User) >= 10
falsepositives:
    - Legitimate clipboard management tools
    - User productivity automation scripts (verify legitimacy)
level: critical
tags:
    - attack.collection
    - attack.t1115
    - attack.credential_access
    - fleetagentfud
```

#### Sigma Rule - WebSocket Connection from .NET Executable in AppData
```yaml
title: FleetAgentFUD WebSocket Connection from AppData .NET Executable
id: c3d4e5f6-fleetfud-websocket-appdata-003
status: experimental
description: Detects WebSocket-like network connections from .NET executables in AppData (FleetAgentFUD C2 pattern)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: network_connection
detection:
    selection_image:
        Image|contains: '\AppData\'
        Image|endswith: '.exe'
    selection_port:
        DestinationPort:
            - 80
            - 443
            - 8080
            - 8443
    filter_signed:
        Signature: 'Microsoft Corporation'
        SignatureStatus: 'Valid'
    condition: selection_image and selection_port and not filter_signed
falsepositives:
    - Legitimate .NET applications in AppData (Microsoft Teams, Discord, Slack) - verify digital signature
    - Development/testing tools
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - fleetagentfud
```

#### Sigma Rule - File Download to Public/Temp from Suspicious Process
```yaml
title: FleetAgentFUD File Download to Suspicious Locations
id: d4e5f6a7-fleetfud-file-download-004
status: stable
description: Detects executable file creation in Public/Temp folders from AppData processes (FleetAgentFUD payload download)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: file_event
detection:
    selection_file:
        EventID: 11
        TargetFilename|contains:
            - 'C:\Users\Public\'
            - 'C:\Windows\Temp\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.scr'
    selection_process:
        Image|contains: '\AppData\'
    condition: selection_file and selection_process
falsepositives:
    - Software installers extracting temporary files
    - Update mechanisms using Public/Temp folders
level: high
tags:
    - attack.execution
    - attack.t1204.002
    - attack.command_and_control
    - attack.t1105
    - fleetagentfud
```

#### Sigma Rule - VirtualProtect RWX Memory from .NET Executable
```yaml
title: FleetAgentFUD RWX Memory Allocation from .NET Executable
id: e5f6a7b8-fleetfud-virtualprotect-rwx-005
status: experimental
description: Detects VirtualProtect API calls with RWX permissions from .NET executables (shellcode execution indicator)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: api_call
detection:
    selection:
        CallTrace|contains: 'VirtualProtect'
        Protection: 'PAGE_EXECUTE_READWRITE'
        Image|contains: '\AppData\'
    filter_legitimate:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Windows\'
    condition: selection and not filter_legitimate
falsepositives:
    - .NET Just-In-Time (JIT) compilation (legitimate .NET Framework behavior)
    - Legitimate .NET applications using dynamic code generation
level: high
tags:
    - attack.defense_evasion
    - attack.t1055
    - fleetagentfud
```

#### Sigma Rule - FleetAgentFUD Multi-Stage Attack Correlation
```yaml
title: FleetAgentFUD Multi-Stage Attack Pattern Correlation
id: f6a7b8c9-fleetfud-multistage-006
status: experimental
description: Correlates multiple FleetAgentFUD attack stages within short timeframe (high-confidence detection)
author: Threat Intelligence Team
date: 2026/01/12
modified: 2026/01/12
logsource:
    product: windows
    category: process_creation
detection:
    selection_stage1_process:
        Image|contains: '\AppData\'
        Image|endswith: '.exe'
    selection_stage2_network:
        EventID: 3
        DestinationPort: 443
    selection_stage3_powershell:
        EventID: 1
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-Exec Bypass'
    timeframe: 5m
    condition: selection_stage1_process and selection_stage2_network and selection_stage3_powershell
falsepositives:
    - Complex legitimate software with network access and PowerShell usage
level: critical
tags:
    - attack.execution
    - attack.command_and_control
    - attack.collection
    - fleetagentfud
```

---

## PowerShell Hunting Queries

### FleetAgentFUD.exe Hunting Queries

#### PowerShell - Comprehensive FleetAgentFUD Hunt
```powershell
# FleetAgentFUD.exe Comprehensive Hunting Script
# Detects file hash, PowerShell bypass, clipboard monitoring, and network activity

function Hunt-FleetAgentFUD {
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$Verbose
    )

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "FleetAgentFUD.exe Threat Hunting Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $findings = @()
    $targetHash = "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff"

    # Hunt 1: File Hash Match
    Write-Host "[1/5] Scanning for FleetAgentFUD.exe file hash..." -ForegroundColor Yellow
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:TEMP",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "C:\Users\Public"
    )

    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if ($hash -eq $targetHash) {
                    $findings += [PSCustomObject]@{
                        Type = "FILE_HASH_MATCH"
                        Location = $_.FullName
                        Severity = "CRITICAL"
                        Timestamp = $_.CreationTime
                        Recommendation = "IMMEDIATE isolation - Confirmed FleetAgentFUD.exe"
                    }
                }
            }
        }
    }

    # Hunt 2: PowerShell Execution Policy Bypass Events
    Write-Host "[2/5] Checking PowerShell logs for Execution Policy bypass..." -ForegroundColor Yellow
    $bypassEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Id -eq 4104 -and (
            $_.Message -like "*-Exec*Bypass*" -or
            $_.Message -like "*-ExecutionPolicy*Bypass*"
        )
    }

    if ($bypassEvents.Count -gt 10) {
        $findings += [PSCustomObject]@{
            Type = "POWERSHELL_BYPASS_PATTERN"
            Location = "PowerShell Operational Log"
            Severity = "HIGH"
            Timestamp = ($bypassEvents | Select-Object -First 1).TimeCreated
            Recommendation = "Review PowerShell script block logs for malicious commands"
        }
    }

    # Hunt 3: Clipboard Monitoring Pattern (Get-Clipboard)
    Write-Host "[3/5] Detecting clipboard monitoring activity..." -ForegroundColor Yellow
    $clipboardEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 -and $_.Message -like "*Get-Clipboard*" }

    if ($clipboardEvents.Count -gt 10) {
        $findings += [PSCustomObject]@{
            Type = "CLIPBOARD_MONITORING"
            Location = "PowerShell Operational Log"
            Severity = "CRITICAL"
            Timestamp = ($clipboardEvents | Select-Object -First 1).TimeCreated
            Recommendation = "CREDENTIAL THEFT LIKELY - Rotate all passwords immediately"
        }
    }

    # Hunt 4: Suspicious .NET Executables in AppData
    Write-Host "[4/5] Scanning AppData for suspicious .NET executables..." -ForegroundColor Yellow
    $appDataExes = Get-ChildItem "$env:APPDATA" -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Length -lt 50KB -and # Small file size (FUD optimization)
        $_.CreationTime -gt (Get-Date).AddDays(-30) # Recent files
    }

    foreach ($exe in $appDataExes) {
        # Check if .NET executable
        $fileHeader = Get-Content $exe.FullName -Encoding Byte -TotalCount 1000 -ErrorAction SilentlyContinue
        $isDotNet = $fileHeader -join '' -match 'BSJB' # .NET metadata signature

        if ($isDotNet) {
            $findings += [PSCustomObject]@{
                Type = "SUSPICIOUS_DOTNET_EXECUTABLE"
                Location = $exe.FullName
                Severity = "MEDIUM"
                Timestamp = $exe.CreationTime
                Recommendation = "Analyze with dnSpy or submit to sandbox for behavioral analysis"
            }
        }
    }

    # Hunt 5: Network Connection to Distribution Infrastructure
    Write-Host "[5/5] Checking network logs for C2 infrastructure..." -ForegroundColor Yellow
    # This requires Sysmon EventID 3 or firewall logs
    $networkEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Id -eq 3 -and
        $_.Message -like "*109.230.231.37*" # Distribution infrastructure IP
    }

    if ($networkEvents.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Type = "C2_INFRASTRUCTURE_CONNECTION"
            Location = "Sysmon Network Connection Log"
            Severity = "CRITICAL"
            Timestamp = ($networkEvents | Select-Object -First 1).TimeCreated
            Recommendation = "CONFIRMED C2 connection - Isolate system immediately"
        }
    }

    # Results Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "HUNTING RESULTS" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    if ($findings.Count -eq 0) {
        Write-Host "[+] No FleetAgentFUD.exe indicators detected on $ComputerName" -ForegroundColor Green
        Write-Host "[*] System appears clean" -ForegroundColor Green
    } else {
        Write-Host "[!] THREAT DETECTED - $($findings.Count) indicator(s) found!" -ForegroundColor Red
        $findings | Sort-Object Severity -Descending | Format-Table -AutoSize

        Write-Host "`n[!] RECOMMENDED IMMEDIATE ACTIONS:" -ForegroundColor Red
        Write-Host "    1. ISOLATE system from network (disconnect Ethernet/WiFi)" -ForegroundColor Yellow
        Write-Host "    2. Capture memory dump for forensic analysis" -ForegroundColor Yellow
        Write-Host "    3. Rotate ALL credentials for users on this system" -ForegroundColor Yellow
        Write-Host "    4. Initiate full incident response procedures" -ForegroundColor Yellow
        Write-Host "    5. Hunt other systems for lateral movement indicators" -ForegroundColor Yellow
    }

    return $findings
}

# Execute hunting function
Hunt-FleetAgentFUD -Verbose
```

#### PowerShell - Enterprise-Wide IOC Hunt (Remote Execution)
```powershell
# Enterprise-Wide FleetAgentFUD IOC Hunt via PowerShell Remoting
# Requires: PSRemoting enabled, appropriate credentials

function Hunt-FleetAgentFUD-Enterprise {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,

        [switch]$ExportToCSV
    )

    $results = @()
    $targetHash = "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff"

    Write-Host "[*] Starting enterprise-wide FleetAgentFUD hunt across $($ComputerNames.Count) systems..." -ForegroundColor Cyan

    $scriptBlock = {
        param($Hash)

        $findings = @()

        # Check 1: File hash
        $paths = @("$env:USERPROFILE\Downloads", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA")
        foreach ($p in $paths) {
            if (Test-Path $p) {
                Get-ChildItem $p -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue |
                Where-Object { (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash -eq $Hash } |
                ForEach-Object {
                    $findings += "CRITICAL: File hash match at $($_.FullName)"
                }
            }
        }

        # Check 2: PowerShell bypass events
        $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4104 -and $_.Message -like "*-Exec*Bypass*" }

        if ($psEvents.Count -gt 10) {
            $findings += "HIGH: PowerShell bypass pattern detected ($($psEvents.Count) events)"
        }

        # Check 3: Clipboard monitoring
        $clipEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4104 -and $_.Message -like "*Get-Clipboard*" }

        if ($clipEvents.Count -gt 10) {
            $findings += "CRITICAL: Clipboard monitoring detected ($($clipEvents.Count) events)"
        }

        return $findings
    }

    foreach ($computer in $ComputerNames) {
        Write-Host "[*] Scanning: $computer" -ForegroundColor Yellow

        try {
            if ($Credential) {
                $remoteFindings = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $targetHash -ErrorAction Stop
            } else {
                $remoteFindings = Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList $targetHash -ErrorAction Stop
            }

            if ($remoteFindings.Count -gt 0) {
                foreach ($finding in $remoteFindings) {
                    $results += [PSCustomObject]@{
                        ComputerName = $computer
                        Status = "INFECTED"
                        Finding = $finding
                        Timestamp = Get-Date
                    }
                }
                Write-Host "    [!] THREAT DETECTED on $computer" -ForegroundColor Red
            } else {
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Status = "CLEAN"
                    Finding = "No indicators detected"
                    Timestamp = Get-Date
                }
                Write-Host "    [+] Clean" -ForegroundColor Green
            }
        } catch {
            $results += [PSCustomObject]@{
                ComputerName = $computer
                Status = "ERROR"
                Finding = "Could not connect: $($_.Exception.Message)"
                Timestamp = Get-Date
            }
            Write-Host "    [!] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "ENTERPRISE HUNT SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $infected = ($results | Where-Object { $_.Status -eq "INFECTED" }).Count
    $clean = ($results | Where-Object { $_.Status -eq "CLEAN" }).Count
    $errors = ($results | Where-Object { $_.Status -eq "ERROR" }).Count

    Write-Host "Total Systems Scanned: $($ComputerNames.Count)" -ForegroundColor Cyan
    Write-Host "Infected Systems: $infected" -ForegroundColor $(if ($infected -gt 0) { "Red" } else { "Green" })
    Write-Host "Clean Systems: $clean" -ForegroundColor Green
    Write-Host "Errors: $errors" -ForegroundColor Yellow

    if ($ExportToCSV) {
        $csvPath = "FleetAgentFUD_Hunt_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[*] Results exported to: $csvPath" -ForegroundColor Cyan
    }

    return $results
}

# Example usage:
# $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
# Hunt-FleetAgentFUD-Enterprise -ComputerNames $computers -ExportToCSV
```

---

## Network Detection Rules (Suricata/Snort)

### FleetAgentFUD.exe Network Detection

#### Suricata Rule - Distribution Infrastructure Connection
```suricata
alert tcp $HOME_NET any -> 109.230.231.37 any (msg:"FleetAgentFUD Distribution Infrastructure Connection - CRITICAL"; flow:established,to_server; reference:url,github.com/yourusername/threat-intel/fleetagentfud; classtype:trojan-activity; sid:2100020; rev:1; priority:1; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity CRITICAL;)
```

#### Suricata Rule - WebSocket Upgrade Pattern
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious WebSocket Upgrade from Untrusted Process - Potential FleetAgentFUD C2"; flow:established,to_server; content:"Connection|3a 20|Upgrade"; http_header; content:"Sec-WebSocket-Key"; http_header; content:"Sec-WebSocket-Version|3a 20|13"; http_header; reference:url,github.com/yourusername/threat-intel/fleetagentfud; classtype:trojan-activity; sid:2100021; rev:1; priority:2; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity HIGH;)
```

#### Suricata Rule - Custom Agent Secret Header
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"FleetAgentFUD WebSocket Authentication Header - X-Agent-Secret Detected"; flow:established,to_server; content:"X-Agent-Secret|3a 20|"; http_header; reference:url,github.com/yourusername/threat-intel/fleetagentfud; classtype:trojan-activity; sid:2100022; rev:1; priority:1; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity CRITICAL;)
```

#### Suricata Rule - .NET User-Agent WebSocket Connection
```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious .NET WebClient User-Agent with WebSocket Upgrade - Potential FleetAgentFUD"; flow:established,to_server; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 6.0|3b| Windows NT 5.2|3b| .NET CLR"; http_header; content:"Connection|3a 20|Upgrade"; http_header; reference:url,github.com/yourusername/threat-intel/fleetagentfud; classtype:trojan-activity; sid:2100023; rev:1; priority:2; metadata:created_at 2026_01_12, updated_at 2026_01_12, severity HIGH;)
```

---

## EDR/SIEM Query Templates

### Splunk SPL Queries

#### SPL - FleetAgentFUD Multi-Stage Attack Correlation
```spl
index=windows (source=WinEventLog:Security OR source=WinEventLog:Microsoft-Windows-Sysmon/Operational OR source=WinEventLog:Microsoft-Windows-PowerShell/Operational)
(
    (EventCode=1 Image="*\\powershell.exe" CommandLine="*-Exec*Bypass*" ParentImage="*\\AppData\\*") OR
    (EventCode=4104 ScriptBlockText="Get-Clipboard") OR
    (EventCode=3 Image="*\\AppData\\*" DestinationPort=443) OR
    (EventCode=11 TargetFilename="C:\\Users\\Public\\*.exe" Image="*\\AppData\\*")
)
| bucket _time span=5m
| stats count dc(EventCode) as EventTypes by _time, ComputerName, User
| where EventTypes >= 2
| eval Severity="CRITICAL", ThreatName="FleetAgentFUD Multi-Stage Attack", Recommendation="Immediate isolation and forensic analysis required"
| table _time, ComputerName, User, count, EventTypes, Severity, ThreatName, Recommendation
```

#### SPL - Clipboard Monitoring Detection
```spl
index=windows source=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=4104
ScriptBlockText="Get-Clipboard"
| bucket _time span=1h
| stats count by _time, ComputerName, User
| where count >= 10
| eval Severity="CRITICAL", ThreatName="FleetAgentFUD Clipboard Monitoring", Recommendation="CREDENTIAL THEFT - Rotate all passwords immediately"
| table _time, ComputerName, User, count, Severity, ThreatName, Recommendation
```

#### SPL - PowerShell Execution Policy Bypass Hunt
```spl
index=windows source=WinEventLog:Security EventCode=4688
CommandLine="*-Exec*Bypass*" OR CommandLine="*-ExecutionPolicy*Bypass*"
ParentProcessName="*\\AppData\\*"
| stats count by ComputerName, User, CommandLine, ParentProcessName
| eval Severity=case(
    match(CommandLine, "-W Hidden"), "CRITICAL",
    match(CommandLine, "Get-Clipboard"), "CRITICAL",
    1=1, "HIGH"
)
| table _time, ComputerName, User, CommandLine, ParentProcessName, Severity
```

### Microsoft Defender ATP (KQL) Advanced Hunting

#### KQL - FleetAgentFUD Comprehensive Hunt
```kusto
// Hunt for FleetAgentFUD.exe indicators across multiple data sources
let TargetHash = "072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff";
union
    // File Hash Match
    (DeviceFileEvents
    | where SHA256 == TargetHash
    | project Timestamp, DeviceName, FileName, FolderPath, FileSize, Severity = "CRITICAL", Indicator = "File Hash Match"),

    // PowerShell Bypass
    (DeviceProcessEvents
    | where FileName == "powershell.exe"
    | where ProcessCommandLine has_any ("-Exec Bypass", "-ExecutionPolicy Bypass", "-W Hidden")
    | where InitiatingProcessFolderPath has "AppData"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, Severity = "HIGH", Indicator = "PowerShell Bypass"),

    // Clipboard Monitoring
    (DeviceProcessEvents
    | where FileName == "powershell.exe"
    | where ProcessCommandLine has "Get-Clipboard"
    | summarize ClipboardChecks = count() by DeviceName, bin(Timestamp, 1h), InitiatingProcessFileName
    | where ClipboardChecks >= 10
    | project Timestamp, DeviceName, InitiatingProcessFileName, ClipboardChecks, Severity = "CRITICAL", Indicator = "Clipboard Monitoring"),

    // WebSocket Network Activity
    (DeviceNetworkEvents
    | where InitiatingProcessFolderPath has "AppData"
    | where RemotePort in (80, 443, 8080, 8443)
    | where InitiatingProcessFileName endswith ".exe"
    | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Severity = "MEDIUM", Indicator = "Suspicious Network"),

    // File Download to Suspicious Locations
    (DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FolderPath has_any ("C:\\Users\\Public", "C:\\Windows\\Temp")
    | where FileName endswith ".exe"
    | where InitiatingProcessFolderPath has "AppData"
    | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, Severity = "HIGH", Indicator = "Payload Download")
| order by Timestamp desc
```

#### KQL - FleetAgentFUD Attack Timeline Reconstruction
```kusto
// Reconstruct FleetAgentFUD attack timeline for forensic analysis
let SuspiciousDevices =
    DeviceProcessEvents
    | where FileName == "powershell.exe"
    | where ProcessCommandLine has "Get-Clipboard"
    | distinct DeviceName;
union
    (DeviceProcessEvents
    | where DeviceName in (SuspiciousDevices)
    | where Timestamp > ago(7d)
    | project Timestamp, DeviceName, EventType = "Process", FileName, ProcessCommandLine, InitiatingProcessFileName),

    (DeviceFileEvents
    | where DeviceName in (SuspiciousDevices)
    | where Timestamp > ago(7d)
    | project Timestamp, DeviceName, EventType = "File", FileName, FolderPath, ActionType),

    (DeviceNetworkEvents
    | where DeviceName in (SuspiciousDevices)
    | where Timestamp > ago(7d)
    | project Timestamp, DeviceName, EventType = "Network", InitiatingProcessFileName, RemoteIP, RemotePort)
| order by DeviceName, Timestamp asc
```

---

## Elastic (EQL) Detection Queries

### EQL - PowerShell Bypass + Clipboard Monitoring Sequence
```eql
sequence by host.name with maxspan=10m
  [process where process.name == "powershell.exe" and process.args like "*-Exec*Bypass*" and process.parent.path like "*AppData*"]
  [process where process.name == "powershell.exe" and process.args like "*Get-Clipboard*"]
```

### EQL - Network Connection + File Download Sequence
```eql
sequence by host.name with maxspan=5m
  [network where process.path like "*AppData*" and destination.port in (80, 443)]
  [file where event.action == "creation" and file.path like "*Public*" and file.extension == "exe"]
```

---

## Implementation Guidance

### YARA Rule Deployment
1. **Testing**: Validate rules against known FleetAgentFUD.exe sample before production deployment
2. **Integration**: Deploy to EDR platforms (CrowdStrike, SentinelOne, Defender), file scanning gateways, email security
3. **Performance**: Monitor false positive rates; small file size rule (17,920 bytes) has low FP risk
4. **Versioning**: Track rule versions and maintain change log for tuning

### Sigma Rule Deployment
1. **SIEM Integration**: Use sigmac to convert rules to platform-specific queries (Splunk, Elastic, QRadar)
2. **Log Sources**: Ensure PowerShell logging (EventID 4104), Sysmon (EventID 1, 3, 11), and Security logs (EventID 4688) are enabled
3. **Correlation**: Configure correlation rules for multi-stage attack detection (PowerShell + Network + Clipboard within 10-minute window)
4. **Alerting**: Set CRITICAL-level alerts for clipboard monitoring and file hash matches

### PowerShell Hunting Deployment
1. **Execution Environment**: Run hunting scripts from dedicated security workstation with appropriate credentials
2. **Scheduling**: Execute enterprise-wide hunts weekly (or daily for high-risk environments)
3. **Logging**: Ensure PowerShell Module Logging and Script Block Logging enabled across all systems
4. **Automation**: Integrate hunt results with ticketing system (ServiceNow, Jira) for automated incident creation

### Network Rule Deployment
1. **IDS Placement**: Deploy Suricata/Snort at network perimeter and internal segment boundaries
2. **SSL Inspection**: Enable TLS/SSL decryption to detect WebSocket handshake headers
3. **Tuning**: Monitor false positives from legitimate WebSocket applications (Slack, Teams); whitelist by certificate or User-Agent
4. **Threat Intelligence Integration**: Feed network detections into SIEM for correlation with endpoint indicators

---

## Testing & Validation

### Detection Rule Testing Framework
```powershell
function Test-FleetAgentFUDDetections {
    Write-Host "[*] Testing FleetAgentFUD detection rule coverage..." -ForegroundColor Cyan

    $testResults = @()

    # Test 1: File hash detection
    Write-Host "`n[TEST 1] File hash IOC detection" -ForegroundColor Yellow
    # Verify YARA rule matches target hash
    # Expected: MATCH on 072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff

    # Test 2: PowerShell bypass detection
    Write-Host "[TEST 2] PowerShell Execution Policy bypass detection" -ForegroundColor Yellow
    # Simulate: powershell.exe -Exec Bypass -C "Write-Host 'test'"
    # Expected: Sigma rule triggers on EventID 4688 or 4104

    # Test 3: Clipboard monitoring detection
    Write-Host "[TEST 3] Clipboard monitoring behavioral pattern" -ForegroundColor Yellow
    # Simulate: Execute Get-Clipboard 15 times within 1 hour
    # Expected: Sigma rule triggers after 10+ executions

    # Test 4: Network WebSocket connection
    Write-Host "[TEST 4] WebSocket connection pattern" -ForegroundColor Yellow
    # Simulate: .NET WebClient with WebSocket headers to test server
    # Expected: Suricata rule triggers on Sec-WebSocket-Key header

    # Test 5: File download to Public folder
    Write-Host "[TEST 5] Suspicious file download detection" -ForegroundColor Yellow
    # Simulate: Download test file to C:\Users\Public from AppData process
    # Expected: Sigma rule triggers on EventID 11 (FileCreated)

    Write-Host "`n[*] Detection testing complete" -ForegroundColor Cyan
    Write-Host "[*] Review alerts in SIEM/EDR platform for validation" -ForegroundColor Cyan
}

# Execute validation
Test-FleetAgentFUDDetections
```

---

## Additional Behavioral Indicators

### Process Execution Patterns

#### Sigma Rule - Rapid System Reconnaissance Sequence
```yaml
title: FleetAgentFUD Rapid System Reconnaissance Pattern
id: a7b8c9d0-fleetfud-recon-sequence-007
status: experimental
description: Detects rapid-fire system reconnaissance commands (sysinfo, processes, network, users, disk) typical of FleetAgentFUD automated profiling
author: Threat Intelligence Team
date: 2026/01/12
logsource:
    product: windows
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|any:
            - 'Get-WmiObject Win32_'
            - 'Get-Process'
            - 'Get-LocalUser'
            - 'ipconfig /all'
            - 'Win32_LogicalDisk'
    timeframe: 5m
    condition: selection_powershell | count(ComputerName) >= 3
falsepositives:
    - System administration scripts
    - IT inventory tools
level: high
tags:
    - attack.discovery
    - attack.t1082
    - attack.t1033
    - fleetagentfud
```

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.

---

**Report Version**: 1.0
**Last Updated**: 2026-01-12
**Maintained By**: Threat Intelligence Team
