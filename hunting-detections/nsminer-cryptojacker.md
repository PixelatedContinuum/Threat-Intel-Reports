---
title: Detection Rules - NsMiner Cryptojacker
date: '2026-02-02'
layout: post
permalink: /hunting-detections/nsminer-cryptojacker/
hide: true
---

# Detection Rules - NsMiner Cryptojacker

## Overview

This detection guide focuses on identifying **NsMiner**, a multi-stage cryptojacking malware that uses NSIS droppers, custom FTP downloaders with credential stuffing capabilities, and VMProtect-packed miners. This threat hijacks CPU resources to mine Monero (XMR) cryptocurrency.

**Malware Family**: NsMiner Cryptojacker
**Severity**: HIGH
**Attack Chain Function**: Multi-stage cryptomining operation using credential stuffing attacks against FTP servers for payload distribution
**Primary Components**: NSIS dropper (IMG001.exe), FTP downloader with credential stuffing (tftp.exe), CryptoNight miner (NsCpuCNMiner*.exe)
**Last Updated**: 2026-02-02

---

## Detection Strategy

### Priority 1: Network-Based Detection (HIGH CONFIDENCE)
Focus on **C2 beaconing** to `hrtests.ru` and FTP connections to suspicious IP addresses as highest-priority indicators.

### Priority 2: Behavioral Detection
Monitor for **persistence directory creation** in `%APPDATA%\NsMiner` and unusual FTP activity from non-FTP applications.

### Priority 3: File-Based Detection
Detect NSIS installers with embedded FTP downloaders and VMProtect-packed binaries.

---

## Table of Contents

1. [YARA Detection Rules](#yara-detection-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Implementation Guidance](#implementation-guidance)

---

## YARA Detection Rules

### Rule 1: NsMiner Dropper and Downloader Detection

```yara
rule NsMiner_Dropper_Downloader {
    meta:
        description = "Detects the NsMiner NSIS dropper and the FTP downloader component."
        author = "Gemini Cyber Threat Analysis Team"
        date = "2026-02-02"
        hash1 = "e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145"
        hash2 = "40fe74d3a1116ed8ca64c62feb694327a414059eeaef62c28bc5917e2e991b3d"
        severity = "HIGH"
        family = "NsMiner"
        technique = "T1496 - Resource Hijacking"

    strings:
        // From IMG001.exe (NSIS Dropper)
        $nsis1 = "Nullsoft Scriptable Install System" fullword ascii
        $nsis2 = "NsMiner" fullword wide

        // From tftp.exe (Downloader)
        $ftp1 = "FtpGetFileA" fullword ascii
        $ftp2 = "InternetConnectA" fullword ascii
        $c2_http = "http://hrtests.ru/S.php" fullword ascii
        $c2_ftp_user = "DIOSESFIEL" fullword ascii
        $c2_ftp_pass = "BLUEAIRWOLF" fullword ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        (
            (all of ($nsis*)) or
            (3 of ($ftp*) and 2 of ($c2*))
        )
}
```

### Rule 2: NsMiner Persistence Directory Detection

```yara
rule NsMiner_Persistence_Directory {
    meta:
        description = "Detects files in the NsMiner persistence directory"
        author = "Gemini Cyber Threat Analysis Team"
        date = "2026-02-02"
        severity = "HIGH"

    strings:
        $path1 = "\\AppData\\Roaming\\NsMiner\\" wide ascii
        $path2 = "C:\\Users\\" wide ascii
        $file1 = "NsCpuCNMiner32.exe" fullword wide ascii
        $file2 = "NsCpuCNMiner64.exe" fullword wide ascii
        $file3 = "tftp.exe" fullword wide ascii

    condition:
        uint16(0) == 0x5A4D and // PE file
        ($path1 and ($file1 or $file2 or $file3))
}
```

---

## Sigma Detection Rules

### Rule 1: NsMiner C2 Beaconing Detection

```yaml
title: NsMiner HTTP C2 Beacon to hrtests.ru
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects HTTP beaconing to the NsMiner C2 domain hrtests.ru
author: Gemini Cyber Threat Analysis Team
date: 2026/02/02
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'hrtests.ru/S.php'
        cs-method: 'GET'
    condition: selection
falsepositives:
    - Unlikely, domain is malicious infrastructure
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
```

### Rule 2: NsMiner Persistence Directory Creation

```yaml
title: NsMiner Persistence Directory Creation
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects creation of the NsMiner persistence directory in AppData\Roaming
author: Gemini Cyber Threat Analysis Team
date: 2026/02/02
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\AppData\Roaming\NsMiner\'
    condition: selection
falsepositives:
    - Unlikely, this is a specific malware persistence location
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

### Rule 3: Suspicious FTP Activity from Non-FTP Application

```yaml
title: Suspicious FTP Connection from Non-Standard Application
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects FTP connections from applications not typically associated with FTP
author: Gemini Cyber Threat Analysis Team
date: 2026/02/02
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationPort: 21
        Initiated: 'true'
    filter:
        Image|endswith:
            - '\filezilla.exe'
            - '\winscp.exe'
            - '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate applications using FTP
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.002
```

---

## EDR Hunting Queries

### CrowdStrike Falcon

```
event_simpleName=ProcessRollup2
(FileName="tftp.exe" OR FileName="NsCpuCNMiner32.exe" OR FileName="NsCpuCNMiner64.exe" OR FilePath="*\\NsMiner\\*")
| stats count by ComputerName, FileName, FilePath, SHA256HashData
```

### Microsoft Defender for Endpoint (KQL)

```kql
DeviceProcessEvents
| where FileName in~ ("tftp.exe", "NsCpuCNMiner32.exe", "NsCpuCNMiner64.exe", "IMG001.exe")
    or FolderPath contains "NsMiner"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

### SentinelOne

```
ObjectType = "process" AND (
    ProcessName ContainsCIS "tftp.exe" OR
    ProcessName ContainsCIS "NsCpuCNMiner" OR
    ProcessPath ContainsCIS "NsMiner"
)
```

---

## SIEM Detection Rules

### Splunk SPL - HTTP C2 Beaconing

```splunk
index=proxy OR index=firewall
http_method=GET
url="*hrtests.ru/S.php*"
| stats count by src_ip, user_agent, url
| where count > 1
```

### Splunk SPL - FTP Credential Stuffing Activity

```splunk
index=network
dest_port=21
(dest_ip IN ("162.150.119.10", "136.0.88.10", "45.156.140.10", "214.192.190.10", "235.31.147.10", "56.255.40.10", "85.230.83.10", "251.46.111.10", "63.192.224.10", "202.24.217.10", "134.211.96.10", "223.50.252.10", "13.180.6.10", "116.62.22.10", "94.158.41.10", "252.158.2.10", "110.188.25.10", "141.227.248.10"))
| stats count by src_ip, dest_ip, app
| where count > 5
```

**Note:** These IPs are targets for credential stuffing attacks, not confirmed C2 infrastructure.

### Elastic Security (KQL) - Persistence Detection

```kql
file.path : "*\\AppData\\Roaming\\NsMiner\\*" and event.category : "file"
```

---

## Implementation Guidance

### Deployment Recommendations

1. **Network-Level Blocking**:
   - Block domain `hrtests.ru` and `testswork.ru` at DNS and firewall (confirmed C2 infrastructure)
   - Monitor FTP connections to the listed target IPs (credential stuffing targets)
   - Monitor for DNS queries to blocked domains
   - Consider blocking outbound FTP from non-standard applications

2. **Endpoint Detection**:
   - Deploy YARA rules for file-based scanning
   - Enable EDR behavioral monitoring for FTP activity
   - Monitor `%APPDATA%\Roaming\NsMiner` directory creation

3. **SIEM Correlation**:
   - Create alert rules for C2 beaconing patterns
   - Correlate file creation events with network activity
   - Alert on persistent directory creation + external FTP connections

### Testing and Validation

1. Test YARA rules against known samples
2. Validate Sigma rules generate alerts in test environment
3. Confirm EDR queries return results for known infected hosts
4. Verify SIEM rules don't generate excessive false positives

### Tuning Recommendations

- Adjust detection thresholds based on environment baseline
- Whitelist legitimate FTP applications in Sigma rules
- Tune HTTP beaconing detection for your proxy log format

---

## Related IOCs

For a complete list of Indicators of Compromise, see:
- [NsMiner IOC Feed]({{ "/ioc-feeds/nsminer-cryptojacker.json" | relative_url }})

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
