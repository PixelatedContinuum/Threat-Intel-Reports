--- 
title: Detection Rules - PULSAR RAT (server.exe)
date: '2025-12-01'
layout: post
permalink: "/hunting-detections/PULSAR-RAT/"
hide: true
---

# Pulsar RAT: Detection & Hunting Guide

This document contains extracted detection rules, threat hunting queries, and scripts from the "PULSAR RAT (server.exe): Technical Analysis & Business Risk Assessment" report. Use these artifacts to proactively hunt for and detect this threat in your environment.

---

## YARA Rule for Endpoint Detection

This rule is designed for use with EDR and AV platforms to detect the Pulsar RAT variant and its close derivatives based on unique strings and file characteristics.

```
rule Pulsar_RAT_Critical_Variant {
    meta:
        description = "Detects Pulsar RAT variant (server.exe)"
        author = "Security Operations"
        date = "2025-11-30"
        threat_level = "CRITICAL"
        confidence = "HIGH"
        hash_sha256 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
        reference = "Internal malware analysis report"

    strings:
        // Core Pulsar identifiers
        $pulsar = "Pulsar.Common" wide ascii
        $hvnc = "HVNC" wide ascii
        $keylog = "KeyLogger" wide ascii
        $msgpack = "MessagePackSerializer" wide ascii
        $bcrypt = "BCryptEncrypt" wide ascii

        // Critical persistence indicators
        $winre = "Recovery\OEM\" wide ascii nocase
        $runonce = "CurrentVersion\RunOnce" wide ascii

        // Specific modules
        $remote_desktop = "RemoteDesktop" wide ascii
        $passwords = "Passwords" wide ascii

    condition:
        // PE32 file check
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 

        // File size check (1.5 MB ± margin for variants)
        filesize > 1MB and filesize < 2MB and

        // Core strings must be present
        all of ($pulsar, $hvnc, $keylog, $msgpack, $bcrypt, $winre) and

        // At least 2 surveillance modules
        2 of ($remote_desktop, $passwords)
}
```

---

## SIEM Threat Hunting Queries (Splunk)

Use these queries in your SIEM (e.g., Splunk) to hunt for behavioral indicators of Pulsar RAT activity across your environment.

### Query 1: Hunt for File Hashes

Looks for known malicious file hashes in antivirus, EDR, or Windows event logs.

```
index=av OR index=edr OR index=windows
file_hash IN (
  "b5491b58348600c2766f86a5af2b867f",
  "dc795961c8e63782fc0f53c08e7ca2e593df99fa",
  "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
)
| stats count by host, file_path, file_name, user, _time
| sort - _time
| table _time, host, user, file_path, file_name, count
```

### Query 2: Hunt for Registry Persistence

Searches for modifications to the `RunOnce` registry key, a common persistence mechanism for this RAT.

```
index=windows EventCode=13
TargetObject="*\CurrentVersion\RunOnce*"
| table _time, Computer, TargetObject, Details, User, Image
| sort - _time
```

### Query 3: Hunt for WinRE Access (CRITICAL)

Searches for any access to the critical `Recovery\OEM\` directory, which indicates an attempt at the advanced WinRE persistence technique.

```
index=windows
(file_path="*\Recovery\OEM\*" OR CommandLine="*Recovery\OEM*" OR ObjectName="*\Recovery\OEM\*" OR CommandLine="*mountvol*")
| table _time, Computer, User, file_path, process, CommandLine, ParentImage
| sort - _time
```

### Query 4: Hunt for Headless Command Execution

Identifies suspicious "headless" command execution, often used by malware to run without a visible window.

```
index=windows EventCode=4688
(CommandLine="*conhost*--headless*" OR CommandLine="*cmd.exe*/headless*")
| table _time, Computer, User, CommandLine, ParentImage, ProcessID
| sort - _time
```

### Query 5: Hunt for Browser Credential Access

Finds processes other than legitimate browsers accessing sensitive credential database files.

```
index=windows
(file_path="*Login Data*" OR file_path="*logins.json*" OR file_path="*key4.db*")
NOT (process_name IN ("chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe"))
| table _time, Computer, User, file_path, process_name, process_path, parent_process
| sort - _time
```

### Query 6: Hunt for Suspicious Paste Site Connections

Monitors for connections to paste sites, which the malware uses to retrieve its C2 server configuration.

```
index=proxy OR index=dns OR index=network
(url="*pastebin.com*" OR url="*paste.ee*" OR url="*hastebin.com*" OR hostname="pastebin.com")
| stats count by src_ip, user, url, dest
| where count > 5
| sort - count
```

---

## PowerShell Threat Hunting Scripts

These scripts can be run directly on endpoints to perform read-only checks for specific indicators.

### Script 1: Hunt for File Hash

Scans the C: drive for a file matching the malware's SHA256 hash.

```powershell
# Hunt for specific malware hash across system
# Safe to run - read-only operation

$targetHash = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
Write-Host "Searching for malware hash across system..." -ForegroundColor Cyan
Write-Host "This may take several minutes on large drives..." -ForegroundColor Yellow

$results = @()

Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Progress -Activity "Scanning files" -Status $_.FullName
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($hash.Hash -eq $targetHash) {
            Write-Host "`n[CRITICAL] MALWARE FOUND!" -ForegroundColor Red
            Write-Host "Path: $($_.FullName)" -ForegroundColor Red
            Write-Host "Hash: $($hash.Hash)" -ForegroundColor Red
            $results += $_.FullName
        }
    }

if ($results.Count -eq 0) {
    Write-Host "`n[CLEAR] No matching files found" -ForegroundColor Green
} else {
    Write-Host "`n[ACTION REQUIRED] Found $($results.Count) matching file(s)" -ForegroundColor Red
    Write-Host "Immediately isolate this system from network" -ForegroundColor Red
}
```

### Script 2: Hunt for RunOnce Persistence

Checks common `RunOnce` registry locations for any suspicious entries.

```powershell
# Check registry for suspicious RunOnce entries
# Safe to run - read-only operation

Write-Host "Checking Registry for RunOnce persistence..." -ForegroundColor Cyan

$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

$foundEntries = 0

foreach ($path in $paths) {
    Write-Host "`nChecking: $path" -ForegroundColor Yellow

    if (Test-Path $path) {
        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue

        if ($props) {
            $props.PSObject.Properties |
                Where-Object {$_.Name -notmatch "^PS"} |
                ForEach-Object {
                    Write-Host "  [FOUND] $($_.Name) = $($_.Value)" -ForegroundColor Red
                    $foundEntries++
                }
        } else {
            Write-Host "  [CLEAR] No entries" -ForegroundColor Green
        }
    } else {
        Write-Host "  [INFO] Key does not exist" -ForegroundColor Gray
    }
}

if ($foundEntries -eq 0) {
    Write-Host "`n[RESULT] No RunOnce entries found (normal state)" -ForegroundColor Green
} else {
    Write-Host "`n[WARNING] Found $foundEntries RunOnce entry/entries" -ForegroundColor Yellow
    Write-Host "Review each entry to determine if legitimate or suspicious" -ForegroundColor Yellow
}
```

### Script 3: Safe WinRE Verification (Read-only)

Performs a safe, read-only check to see if a Windows Recovery Environment (WinRE) partition exists and is configured. Requires Administrator privileges.

```powershell
# Safe WinRE partition verification
# READ-ONLY - Does not modify system
# Requires Administrator privileges

Write-Host "WinRE Partition Verification Tool" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check for admin rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Must run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit
}

# Check WinRE configuration
Write-Host "`n[1] Checking WinRE configuration..." -ForegroundColor Yellow
reagentc /info

# Check for recovery partitions
Write-Host "`n[2] Checking for recovery partitions..." -ForegroundColor Yellow
$recoveryPartitions = Get-Partition | Where-Object {$_.Type -eq 'Recovery'}

if ($recoveryPartitions) {
    Write-Host "[FOUND] Recovery partition(s) detected:" -ForegroundColor Yellow
    $recoveryPartitions | Format-Table DiskNumber, PartitionNumber, Size, Type -AutoSize

    Write-Host "`n[WARNING] Recovery partition inspection requires specialized tools" -ForegroundColor Red
    Write-Host "Recommended actions:" -ForegroundColor Yellow
    Write-Host "  1. Do NOT mount partition without forensic guidance" -ForegroundColor White
    Write-Host "  2. Create forensic image first if compromise suspected" -ForegroundColor White
    Write-Host "  3. Engage security specialist for safe inspection" -ForegroundColor White
    Write-Host "  4. Consider full system rebuild if WinRE persistence suspected" -ForegroundColor White
} else {
    Write-Host "[INFO] No recovery partition detected" -ForegroundColor Gray
}

Write-Host "`n[COMPLETE] Verification finished" -ForegroundColor Green
```
---
## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.

```