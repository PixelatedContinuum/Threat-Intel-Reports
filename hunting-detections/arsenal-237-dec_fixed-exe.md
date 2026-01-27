# Arsenal-237 dec_fixed.exe Detection Rules & Hunting Queries

**Classification**: Recovery Tool Detection (LOW Priority)
**Note**: dec_fixed.exe is a RECOVERY TOOL (decryptor), not an attack tool. Detection should focus on victim identification and post-incident forensic investigation, not threat prevention.

---

## YARA Rules

### Rule 1: Exact File Hash Signature

```yara
rule Arsenal237_dec_fixed_exe
{
    meta:
        description = "Arsenal-237 dec_fixed.exe - Per-victim ransomware decryptor"
        malware_family = "Arsenal-237"
        sample_type = "Ransomware Recovery Tool"
        severity = "LOW"
        confidence = "CONFIRMED"
        date_created = "2026-01-26"
        hash_type = "SHA256"

    strings:
        $hash1 = "d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802" nocase

    condition:
        all of them
}
```

### Rule 2: Hardcoded Victim Key Detection

```yara
rule Arsenal237_Victim_Key_Decryptor
{
    meta:
        description = "Arsenal-237 decryptor with victim-specific ChaCha20 key"
        malware_family = "Arsenal-237"
        sample_type = "Ransomware Recovery Tool (Per-Victim)"
        severity = "MEDIUM"
        confidence = "CONFIRMED"
        date_created = "2026-01-26"

    strings:
        $key1 = "1e0d8597856270d1926cfcf252af1b14a776c20b3b50168df9311314202e73ba" nocase
        $key2 = "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b" nocase

    condition:
        1 of them
}
```

### Rule 3: ChaCha20-Poly1305 Implementation Detection

```yara
rule Arsenal237_ChaCha20_Decryption
{
    meta:
        description = "Arsenal-237 ChaCha20-Poly1305 AEAD decryption implementation"
        malware_family = "Arsenal-237"
        cryptographic_algorithm = "ChaCha20-Poly1305"
        standard = "RFC 7539"
        severity = "MEDIUM"
        confidence = "CONFIRMED"
        date_created = "2026-01-26"

    strings:
        $constant1 = "expand 32-byte k" nocase
        $error1 = "Decryption failed - wrong key or corrupted file"
        $error2 = "File corrupted - encrypted size mismatch"

    condition:
        $constant1 and any of ($error*)
}
```

### Rule 4: Decryption Tool Identification

```yara
rule Arsenal237_Decryptor_Tool
{
    meta:
        description = "Arsenal-237 ransomware decryptor with directory traversal"
        malware_family = "Arsenal-237"
        tool_type = "Batch File Decryptor"
        severity = "LOW"
        confidence = "CONFIRMED"
        date_created = "2026-01-26"

    strings:
        $cmd1 = "--folder-a"
        $error1 = "File too small"
        $error2 = "Could not find filename"
        $error3 = "Invalid victim key hex"
        $cleanup = "readme.txt"

    condition:
        $cmd1 and 2 of ($error*) and $cleanup
}
```

### Rule 5: Rust-Compiled Arsenal-237 Tools

```yara
rule Arsenal237_Rust_Compiled
{
    meta:
        description = "Arsenal-237 Rust-compiled ransomware tools (encryptors and decryptors)"
        malware_family = "Arsenal-237"
        compiler = "Rust (rustc)"
        severity = "HIGH"
        confidence = "CONFIRMED"
        date_created = "2026-01-26"

    strings:
        $chacha20_lib = "chacha20" nocase
        $poly1305_lib = "poly1305" nocase
        $hex_lib = "hex" nocase
        $rust_string1 = "expand 32-byte k"
        $rust_string2 = "Decryption failed" nocase

    condition:
        filesize > 900KB and filesize < 1MB and
        all of ($chacha20*, $poly1305*, $hex*) and
        $rust_string1
}
```

---

## Sigma Detection Rules

### Rule 1: Command-Line Execution of dec_fixed.exe

```yaml
title: Arsenal-237 dec_fixed.exe Decryption Tool Execution
id: arsenal-237-dec-fixed-exe-execution
status: experimental
description: Detects execution of Arsenal-237 dec_fixed.exe decryption tool with --folder-a parameter
author: Threat Intelligence Team
date: 2026-01-26
modified: 2026-01-26
tags:
  - ransomware
  - Arsenal-237
  - recovery_tool
  - decryption
logsource:
  product: windows
  service: sysmon
detection:
  selection_process:
    Image|endswith: 'dec_fixed.exe'
    CommandLine|contains: '--folder-a'
  selection_hash:
    Hashes|contains:
      - 'SHA256=d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802'
      - 'MD5=7c5493a0a5df52682a5c2ba433634601'
      - 'SHA1=29014d4d6fc42219cd9cdc130b868382cf2c14c2'
  condition: selection_process or selection_hash
falsepositives:
  - Legitimate victim decryption operations (low probability)
  - Manual testing of recovered decryptor samples
level: medium
severity: low
comment: This is a recovery tool, not an active threat. Detection prioritizes victim identification for post-incident response.
```

### Rule 2: Directory Traversal and Enumeration Pattern

```yaml
title: Arsenal-237 A-Z Directory Enumeration Pattern
id: arsenal-237-directory-traversal-pattern
status: experimental
description: Detects Arsenal-237 characteristic A-Z subdirectory enumeration for encrypted file discovery
author: Threat Intelligence Team
date: 2026-01-26
modified: 2026-01-26
tags:
  - ransomware
  - Arsenal-237
  - discovery
  - directory_traversal
logsource:
  product: windows
  service: sysmon
detection:
  selection_files:
    # Process accessing A-Z subdirectories in sequence
    TargetFilename|contains:
      - ':\A\'
      - ':\B\'
      - ':\C\'
      - ':\D\'
      - ':\E\'
      - ':\F\'
      - ':\G\'
      - ':\H\'
      - ':\I\'
      - ':\J\'
      - ':\K\'
      - ':\L\'
      - ':\M\'
      - ':\N\'
      - ':\O\'
      - ':\P\'
      - ':\Q\'
      - ':\R\'
      - ':\S\'
      - ':\T\'
      - ':\U\'
      - ':\V\'
      - ':\W\'
      - ':\X\'
      - ':\Y\'
      - ':\Z\'
    EventType: CreateFile
  filter_system:
    Image|contains:
      - 'System32'
      - 'Windows'
  condition: selection_files and not filter_system
falsepositives:
  - Batch file operations with organized directory structures
  - Backup software using A-Z organization
  - Development tools with systematic directory access
level: medium
severity: low
comment: Ransomware-specific directory organization pattern, but low false positive threshold given legitimate uses.
```

### Rule 3: Encrypted File Recovery Operations

```yaml
title: Arsenal-237 Encrypted File Recovery (File Deletion Pattern)
id: arsenal-237-encrypted-file-recovery
status: experimental
description: Detects Arsenal-237 encrypted file recovery pattern - readme.txt deletion after file operations
author: Threat Intelligence Team
date: 2026-01-26
modified: 2026-01-26
tags:
  - ransomware
  - Arsenal-237
  - recovery_tool
  - ransomware_cleanup
logsource:
  product: windows
  service: sysmon
detection:
  selection_cleanup:
    EventType: FileDelete
    TargetFilename|endswith: 'readme.txt'
  selection_context:
    # readme.txt deletion following creation of files in same directory
    Image|endswith:
      - 'dec_fixed.exe'
      - 'powershell.exe'
      - 'cmd.exe'
  timespan: 5m
  condition: selection_cleanup and selection_context
falsepositives:
  - Manual cleanup of ransom notes by IT teams
  - Cleanup scripts deleting readme.txt files (common filename)
  - Standard application installations deleting readme files
level: low
severity: low
comment: Low confidence indicator due to generic nature of readme.txt deletion. Use in conjunction with other indicators.
```

### Rule 4: ChaCha20-Poly1305 Cryptographic Operations

```yaml
title: Arsenal-237 ChaCha20-Poly1305 Cryptographic Operations
id: arsenal-237-chacha20-operations
status: experimental
description: Detects ChaCha20-Poly1305 AEAD cryptographic operations consistent with Arsenal-237 tools
author: Threat Intelligence Team
date: 2026-01-26
modified: 2026-01-26
tags:
  - ransomware
  - Arsenal-237
  - cryptography
  - decryption
logsource:
  product: windows
  service: sysmon
detection:
  selection_modules:
    # Rust libraries for ChaCha20-Poly1305 implementation
    ImageLoaded|contains:
      - 'chacha20'
      - 'poly1305'
      - 'aead'
  selection_process:
    ParentImage|endswith:
      - 'cmd.exe'
      - 'powershell.exe'
      - 'explorer.exe'
  filter_system:
    Image|contains:
      - 'System32'
      - 'Windows'
  condition: selection_modules and selection_process and not filter_system
falsepositives:
  - Legitimate cryptographic applications
  - Development environments using cryptographic libraries
  - Security tools performing encryption/decryption
level: low
severity: low
comment: Generic cryptographic indicator with high false positive rate. Most valuable in incident response context.
```

---

## SIEM Hunting Queries

### Splunk SPL Query 1: Process Execution Hunting

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=1
  (process_name=dec_fixed.exe OR command_line="*--folder-a*")
| stats count by host, process_name, command_line, user
| where count > 0
```

**Purpose**: Identify execution of dec_fixed.exe decryption tool
**Priority**: LOW (victim identification for post-incident investigation)
**Expected Result**: Should return zero results in healthy environment; positive result indicates victim recovery operations

### Splunk SPL Query 2: File Access Pattern Detection

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=11
  (TargetFilename="*:\A\*" OR TargetFilename="*:\B\*" OR TargetFilename="*:\C\*")
  earliest=-24h
| stats count by host, Image, TargetFilename
| where count > 50
| eval suspicious=if(count>100, "POSSIBLE", "MONITOR")
```

**Purpose**: Detect A-Z directory enumeration pattern characteristic of Arsenal-237 tools
**Priority**: MEDIUM (behavioral pattern matching)
**Expected Result**: May return legitimate directory access; correlate with other indicators

### Splunk SPL Query 3: Ransom Note Deletion Hunting

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode=23
  TargetFilename="*readme.txt"
| stats count by host, Image, TargetFilename
| where Image!="*explorer.exe" AND Image!="*Windows*"
```

**Purpose**: Detect deletion of readme.txt ransom notes (Arsenal-237 cleanup)
**Priority**: LOW (generic filename, high false positives)
**Expected Result**: Monitor for correlation with other Arsenal-237 indicators

### Splunk SPL Query 4: File Correlation - Creation and Deletion

```spl
index=main sourcetype=WinEventLog:Sysmon EventCode IN (11, 23)
| stats earliest(_time) as first_event, latest(_time) as last_event by host, Image
| where (last_event - first_event) < 300
| table host, Image, first_event, last_event
| eval time_delta=round(last_event - first_event)
```

**Purpose**: Detect rapid file creation followed by deletion (decryption and cleanup pattern)
**Priority**: MEDIUM (behavioral pattern)
**Expected Result**: Suspicious if large number of files created/deleted in <5 minute window

### Elasticsearch/ELK Query 1: Process Execution

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "process.name": "dec_fixed.exe" } },
        { "match": { "process.command_line": "--folder-a" } }
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "host.name", "size": 100 }
    }
  }
}
```

**Purpose**: Elasticsearch query for dec_fixed.exe execution detection
**Priority**: LOW (post-incident victim identification)
**Index**: winlogbeat-* (Windows Event Log data)

### KQL (Azure Sentinel) Query 1: Process Execution

```kql
DeviceProcessEvents
| where FileName == "dec_fixed.exe" and CommandLine contains "--folder-a"
| summarize count() by DeviceName, ProcessCommandLine, Timestamp
| where count_ > 0
```

**Purpose**: Azure Sentinel detection of dec_fixed.exe execution
**Priority**: LOW (victim recovery tool)
**Expected Result**: Should return zero in normal operations; positive indicates post-incident decryption

### KQL (Azure Sentinel) Query 2: File Activity Correlation

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
  and FolderPath contains ":\\"
  and Timestamp > ago(24h)
| summarize file_count=count() by DeviceName, InitiatingProcessFileName
| where file_count > 100
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileDeleted" and FileName == "readme.txt"
  ) on DeviceName
```

**Purpose**: Correlate file creation (decryption) with readme.txt deletion (cleanup)
**Priority**: MEDIUM (behavioral pattern)
**Expected Result**: Detects decryption and cleanup pattern

---

## Network Detection Rules

### Suricata Rule (if dec_fixed.exe performs network operations)

```
# Note: Current analysis shows dec_fixed.exe is OFFLINE (no network activity)
# This rule provided for completeness if variant performs C2 check

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Arsenal-237 Decryptor Network Activity";
    flow:established,to_server;
    http.user_agent|contains:"dec_fixed";
    sid:20260126001;
    rev:1;
    classtype:trojan-activity;
    priority:2;
)
```

**Note**: Current dec_fixed.exe analysis shows NO network activity (fully offline tool).

---

## PowerShell Hunting Script

```powershell
# Arsenal-237 dec_fixed.exe Hunting Script
# Purpose: Search for dec_fixed.exe and Arsenal-237 indicators
# Priority: LOW (post-incident forensics)

[CmdletBinding()]
param(
    [string]$SearchPath = "C:\",
    [switch]$Deep
)

# Define indicators
$sha256 = "d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802"
$md5 = "7c5493a0a5df52682a5c2ba433634601"
$sha1 = "29014d4d6fc42219cd9cdc130b868382cf2c14c2"
$victimKey = "1e0d8597856270d1926cfcf252af1b14a776c20b3b50168df9311314202e73ba"

Write-Host "[*] Arsenal-237 dec_fixed.exe Hunting Script"
Write-Host "[*] Searching: $SearchPath"

# Search for dec_fixed.exe
Write-Host "[+] Searching for dec_fixed.exe..."
$files = Get-ChildItem -Path $SearchPath -Filter "dec_fixed.exe" -Recurse -ErrorAction SilentlyContinue

foreach ($file in $files) {
    Write-Host "[!] FOUND: $($file.FullName)"

    # Calculate hashes
    $fileHash = Get-FileHash -Path $file.FullName
    Write-Host "    SHA256: $($fileHash.Hash)"

    if ($fileHash.Hash -eq $sha256) {
        Write-Host "    [!] MATCH: Known dec_fixed.exe sample!"
    }
}

# Search for Arsenal-237 encrypted files (A-Z subdirectories)
Write-Host "[+] Searching for Arsenal-237 encrypted file pattern..."
$drives = Get-Volume | Where-Object { $_.DriveType -eq "Fixed" } | Select-Object -ExpandProperty DriveLetter

foreach ($drive in $drives) {
    $pattern = "${drive}:\"
    $subdirs = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^[A-Z]$" }

    if ($subdirs.Count -gt 5) {
        Write-Host "[!] POSSIBLE ENCRYPTED FILES: $drive (found A-Z subdirectories)"

        foreach ($subdir in $subdirs) {
            $files = Get-ChildItem -Path $subdir.FullName -File |
                Where-Object { $_.Extension -eq "" -or $_.Extension -match "^\." }

            if ($files.Count -gt 0) {
                Write-Host "    [$($subdir.Name)] - $($files.Count) potential encrypted files"
            }
        }
    }
}

# Search for strings in memory or files
if ($Deep) {
    Write-Host "[+] Searching for ChaCha20-Poly1305 strings (deep scan)..."
    $allFiles = Get-ChildItem -Path $SearchPath -File -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $allFiles) {
        try {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            if ($content -contains "expand 32-byte k") {
                Write-Host "[!] FOUND ChaCha20 constant in: $($file.FullName)"
            }
        }
        catch { }
    }
}

Write-Host "[*] Hunting complete"
```

**Usage**:
```powershell
# Standard search
.\Hunt-Arsenal237-DecFixed.ps1 -SearchPath "C:\Users"

# Deep scan (searches all files)
.\Hunt-Arsenal237-DecFixed.ps1 -SearchPath "C:\" -Deep
```

---

## Windows Event Log Correlation Rule

### Event ID 4688 (Process Creation) + File Operations

**Scenario**: Detect execution of dec_fixed.exe with following file operations

```
Event 4688 - Process Created
  Process Name: dec_fixed.exe
  Command Line: dec_fixed.exe --folder-a <path>
  User: [Any user]

Followed Within 5 Minutes By:
  Event 4663 - File Operations
    File Name: Contains A, B, C, D... Z subdirectories
    Access Mask: Create, Write, Delete
    Process Name: dec_fixed.exe

Followed By:
  Event 4663 - File Delete
    File Name: readme.txt
```

**Interpretation**:
- GREEN: Indicates post-incident victim decryption operations (no threat)
- Requires correlation across multiple events and 5-minute timespan
- Low detection priority but valuable for victim identification and recovery timeline

---

## Advanced Hunting - File Format Detection

### Detect Arsenal-237 Encrypted Files (by structure)

```python
#!/usr/bin/env python3
"""
Arsenal-237 Encrypted File Format Detector
Identifies files matching Arsenal-237 encrypted file format
"""

import os
import hashlib
import struct

def detect_arsenal237_encrypted_file(filepath):
    """
    Check if file matches Arsenal-237 encrypted file format:
    [Encrypted Data] + [16B Auth Tag] + [Encrypted Filename] + [4B Length]
    """

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # Minimum size: 4 (length) + 16 (tag) = 20 bytes
        if len(data) < 20:
            return False

        # Extract filename length from last 4 bytes (little-endian)
        filename_length = struct.unpack('<I', data[-4:])[0]

        # Validate bounds
        if filename_length > 260 or filename_length == 0:
            return False

        # Check structure: data_size + 16 (tag) + filename_size + 4 (length) = total_size
        expected_minimum = 16 + filename_length + 4
        if len(data) < expected_minimum:
            return False

        # Additional check: auth tag should be present
        auth_tag = data[-(4 + filename_length + 16):-(4 + filename_length)]
        if len(auth_tag) != 16:
            return False

        return True

    except Exception as e:
        return False

def scan_directory(root_path):
    """Scan directory for Arsenal-237 encrypted files"""

    results = {
        "encrypted_files": [],
        "a_z_pattern": False,
        "confidence": 0
    }

    # Check for A-Z subdirectories
    subdirs = os.listdir(root_path)
    a_z_count = sum(1 for d in subdirs if d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                    and os.path.isdir(os.path.join(root_path, d)))

    if a_z_count >= 5:
        results["a_z_pattern"] = True
        results["confidence"] += 30

    # Scan files
    for root, dirs, files in os.walk(root_path):
        for file in files:
            filepath = os.path.join(root, file)

            if detect_arsenal237_encrypted_file(filepath):
                results["encrypted_files"].append(filepath)
                results["confidence"] += 10

    # Confidence assessment
    if len(results["encrypted_files"]) > 0:
        results["confidence"] = min(100, results["confidence"])
        results["status"] = "LIKELY ENCRYPTED FILES DETECTED"
    else:
        results["status"] = "NO ARSENAL-237 ENCRYPTED FILES"

    return results

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 arsenal237-detector.py <path>")
        sys.exit(1)

    target_path = sys.argv[1]
    results = scan_directory(target_path)

    print(f"\nArsenal-237 Encrypted File Scan Results")
    print(f"Target: {target_path}")
    print(f"Status: {results['status']}")
    print(f"Confidence: {results['confidence']}%")
    print(f"A-Z Pattern: {'YES' if results['a_z_pattern'] else 'NO'}")
    print(f"Files Found: {len(results['encrypted_files'])}")

    if results["encrypted_files"]:
        print("\nEncrypted Files Detected:")
        for f in results["encrypted_files"][:10]:  # Show first 10
            print(f"  - {f}")
```

---

## Detection Summary

| Detection Method | Priority | Confidence | False Positive Risk | Use Case |
|-----------------|----------|-----------|-------------------|----------|
| Hash-based (SHA256) | MEDIUM | CONFIRMED | VERY LOW | Exact file identification |
| Hardcoded key search | MEDIUM | CONFIRMED | LOW | Victim decryptor identification |
| ChaCha20 constant | MEDIUM | CONFIRMED | MEDIUM | Arsenal-237 tool identification |
| Command-line pattern | LOW | CONFIRMED | LOW | Execution monitoring |
| A-Z directory enumeration | MEDIUM | CONFIRMED | MEDIUM | Behavioral pattern matching |
| readme.txt deletion | LOW | CONFIRMED | HIGH | Post-incident cleanup detection |
| Encrypted file format | HIGH | CONFIRMED | LOW | Victim file identification (offline) |
| Cryptographic operations | LOW | CONFIRMED | HIGH | Generic cryptography detection |

---

## Important Notes

1. **Recovery Tool Priority**: dec_fixed.exe is a RECOVERY TOOL, not an attack tool. Detection should prioritize victim identification and post-incident investigation, not threat prevention.

2. **False Positive Management**: Many indicators (readme.txt deletion, file operations) have legitimate use cases. Correlation across multiple indicators reduces false positives.

3. **Offline Detection**: The hardcoded key and file format checks do not require network monitoring-these are offline forensic indicators.

4. **Incident Response**: If detected, treat as evidence of prior Arsenal-237 infection with successful ransom negotiation. Coordinate with law enforcement.

5. **Victim Support**: Organizations matching the hardcoded key can use this decryptor for complete file recovery.

---

*Report Classification: Detection & Hunting Guide*
*Last Updated: 2026-01-26*
