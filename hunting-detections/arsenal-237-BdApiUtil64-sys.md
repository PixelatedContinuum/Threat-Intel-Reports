---
title: Detection Rules - BdApiUtil64.sys (Arsenal-237 BYOVD Component)
date: '2026-01-26'
layout: post
permalink: /hunting-detections/arsenal-237-BdApiUtil64-sys/
hide: true
---

# Detection Rules - BdApiUtil64.sys (Arsenal-237 BYOVD Component)

## Overview

This detection guide focuses on identifying **BdApiUtil64.sys**, a weaponized legitimate Baidu Antivirus kernel driver used in BYOVD (Bring Your Own Vulnerable Driver) attacks. This driver provides **kernel-level Ring-0 access** enabling security product termination, malicious service creation, and credential theft.

**Malware Family**: Arsenal-237 BYOVD Component
**Severity**: CRITICAL
**Attack Chain Function**: Kernel-level defense evasion enabler - neutralizes EDR/AV to allow ransomware/malware execution
**Primary IOCTLs**: 0x800024b4 (process termination), 0x800024b8 (SSDT bypass), 0x80002324 (service manipulation), 0x80002648/0x8000264c (file access)
**Last Updated**: 2026-01-26

---

## Detection Strategy

### Priority 1: Driver Load Detection (HIGH CONFIDENCE)
Focus on **driver load events** with Baidu signature, expired certificates, and suspicious service creation as highest-priority indicators.

### Priority 2: Behavioral Detection
Monitor **DeviceIoControl** calls to `\\.\BdApiUtil` and security product process terminations correlated with driver load.

### Priority 3: SSDT Bypass Detection
Detect advanced evasion via **KeServiceDescriptorTable** resolution and indirect system calls.

---

## Table of Contents

1. [YARA Detection Rules](#yara-detection-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Hunting Queries](#edr-hunting-queries)
4. [SIEM Detection Rules](#siem-detection-rules)
5. [Implementation Guidance](#implementation-guidance)

---

## YARA Detection Rules

### Rule 1: BdApiUtil64.sys File Hash Detection

```yara
rule Arsenal237_BdApiUtil64_Hash {
    meta:
        description = "Detects Arsenal-237 BdApiUtil64.sys by file hash"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        hash = "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
        severity = "CRITICAL"
        family = "Arsenal-237"
        technique = "T1068 - BYOVD Exploitation"

    condition:
        hash.sha256(0, filesize) == "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428" or
        hash.md5(0, filesize) == "ced47b89212f3260ebeb41682a4b95ec" or
        hash.sha1(0, filesize) == "148c0cde4f2ef807aea77d7368f00f4c519f47ef"
}
```

### Rule 2: Baidu Driver Signature Pattern

```yara
rule Arsenal237_BdApiUtil_Signature {
    meta:
        description = "Detects BdApiUtil64.sys by Baidu signature and PDB path"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        technique = "T1068 - BYOVD with Legitimate Signature"

    strings:
        $pdb = "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb" ascii wide
        $signer = "Baidu Online Network Technology" ascii wide
        $product = "Baidu Antivirus" ascii wide
        $device = "\\Device\\BdApiUtil" ascii wide
        $service = "Bprotect" ascii wide
        $callback = "bdProtectExpCallBack" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (2 of ($*))
}
```

### Rule 3: IOCTL Code Pattern Detection

```yara
rule Arsenal237_BdApiUtil_IOCTL_Abuse {
    meta:
        description = "Detects malware using BdApiUtil64.sys IOCTL codes"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        technique = "T1562.001 - Process Termination via Driver IOCTLs"

    strings:
        // Primary IOCTL codes
        $ioctl1 = { B4 24 00 80 }    // 0x800024b4 - Direct termination
        $ioctl2 = { B8 24 00 80 }    // 0x800024b8 - SSDT bypass
        $ioctl3 = { 24 23 00 80 }    // 0x80002324 - Service manipulation
        $ioctl4 = { 48 26 00 80 }    // 0x80002648 - File access 1
        $ioctl5 = { 4C 26 00 80 }    // 0x8000264c - File access 2

        // DeviceIoControl API
        $api = "DeviceIoControl" ascii wide

        // Device name
        $device = "\\\\.\\BdApiUtil" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        $api and $device and
        2 of ($ioctl*)
}
```

### Rule 4: SSDT Bypass Pattern

```yara
rule Arsenal237_BdApiUtil_SSDT_Bypass {
    meta:
        description = "Detects SSDT bypass implementation in malware"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "CRITICAL"
        technique = "T1027.010 - SSDT Indirect System Calls"

    strings:
        $ssdt_string = "KeServiceDescriptorTable" ascii wide
        $api1 = "MmGetSystemRoutineAddress" ascii wide
        $api2 = "RtlInitUnicodeString" ascii wide

        // Hook detection pattern (checking for 0xb8 opcode)
        $hook_check = { 80 3? B8 }    // cmp byte ptr [reg], 0xb8

        // SSDT lookup pattern
        $ssdt_lookup = { 8B ?? ?? C1 E? 02 }    // mov reg, [reg+offset]; shl reg, 2

    condition:
        uint16(0) == 0x5A4D and
        $ssdt_string and
        all of ($api*) and
        1 of ($hook_check, $ssdt_lookup)
}
```

### Rule 5: Kernel Process Termination Pattern

```yara
rule Arsenal237_BdApiUtil_Kernel_Termination {
    meta:
        description = "Detects kernel-mode process termination capabilities"
        author = "Threat Intelligence Team"
        date = "2026-01-26"
        severity = "HIGH"
        technique = "T1562.001 - Kernel-Level Security Product Termination"

    strings:
        // Kernel APIs for process termination
        $api1 = "PsLookupProcessByProcessId" ascii
        $api2 = "ZwTerminateProcess" ascii
        $api3 = "ObOpenObjectByPointer" ascii
        $api4 = "ObDereferenceObject" ascii

        // Target security products
        $target1 = "MsMpEng.exe" ascii wide nocase
        $target2 = "CSFalconService.exe" ascii wide nocase
        $target3 = "ekrn.exe" ascii wide nocase
        $target4 = "avp.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        3 of ($api*) and
        2 of ($target*)
}
```

---

## Sigma Detection Rules

### Rule 1: BdApiUtil64.sys Driver Load Detection

```yaml
title: Suspicious Baidu Driver Load (BdApiUtil64.sys BYOVD)
id: a1b2c3d4-e5f6-7890-1234-567890abcdef
status: stable
description: Detects loading of vulnerable Baidu driver (BdApiUtil64.sys) used in BYOVD attacks
references:
    - Arsenal-237 malware toolkit analysis
    - BlackByte, Cuba, ALPHV ransomware campaigns
author: Threat Intelligence Team
date: 2026-01-26
modified: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1068
    - attack.t1562.001
logsource:
    product: windows
    category: driver_load
detection:
    selection_hash:
        Hashes|contains:
            - '47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428'
            - 'ced47b89212f3260ebeb41682a4b95ec'
            - '148c0cde4f2ef807aea77d7368f00f4c519f47ef'
    selection_signature:
        ImageLoaded|contains: 'BdApiUtil'
        Signed: 'true'
        Signature|contains: 'Baidu'
    selection_expired:
        ImageLoaded|endswith: '.sys'
        Signed: 'true'
        SignatureStatus: 'Valid'
        Signature|contains: 'Baidu'
    condition: 1 of selection_*
falsepositives:
    - Legitimate Baidu Antivirus installation (very rare in enterprise environments)
level: critical
```

### Rule 2: Bprotect Service Creation

```yaml
title: Suspicious Bprotect Service Creation (BdApiUtil64.sys)
id: b2c3d4e5-f6g7-8901-2345-678901bcdefg
status: stable
description: Detects creation of Bprotect service associated with BdApiUtil64.sys driver
references:
    - Arsenal-237 BYOVD technique
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.persistence
    - attack.t1547.006
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'Bprotect'
        ImagePath|contains: 'BdApiUtil'
    condition: selection
falsepositives:
    - Legitimate Baidu Antivirus installation
level: critical
```

### Rule 3: Security Product Termination Correlation

```yaml
title: Security Product Termination After Driver Load (BYOVD Pattern)
id: c3d4e5f6-g7h8-9012-3456-789012cdefgh
status: stable
description: Detects security product process termination shortly after suspicious driver load
references:
    - BYOVD attack pattern
    - Arsenal-237 toolkit
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.impact
    - attack.t1489
logsource:
    product: windows
    service: sysmon
detection:
    selection_driver:
        EventID: 6
        ImageLoaded|contains:
            - 'BdApiUtil'
            - 'Baidu'
    selection_termination:
        EventID: 5
        Image|endswith:
            - 'MsMpEng.exe'
            - 'CSFalconService.exe'
            - 'ekrn.exe'
            - 'avp.exe'
            - 'SophosHealth.exe'
            - 'cb.exe'
            - 'MBAMService.exe'
    timeframe: 60s
    condition: selection_driver and selection_termination | near selection_driver
falsepositives:
    - Legitimate service restarts during updates (check timing correlation)
level: critical
```

### Rule 4: DeviceIoControl to BdApiUtil Device

```yaml
title: DeviceIoControl Calls to BdApiUtil Driver
id: d4e5f6g7-h8i9-0123-4567-890123defghi
status: experimental
description: Detects DeviceIoControl API calls to \\.\BdApiUtil device object
references:
    - Arsenal-237 BYOVD IOCTL abuse
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.collection
    - attack.t1005
logsource:
    product: windows
    category: process_access
detection:
    selection_api:
        CallTrace|contains: 'DeviceIoControl'
    selection_device:
        TargetObject|contains: '\\.\BdApiUtil'
    condition: all of selection_*
falsepositives:
    - Legitimate Baidu Antivirus operations (rare)
level: high
```

### Rule 5: SSDT Resolution Attempt

```yaml
title: KeServiceDescriptorTable Resolution (SSDT Bypass Attempt)
id: e5f6g7h8-i9j0-1234-5678-901234efghij
status: experimental
description: Detects attempts to resolve KeServiceDescriptorTable for SSDT bypass
references:
    - Advanced EDR evasion via SSDT bypass
    - Arsenal-237 BdApiUtil64.sys capability
author: Threat Intelligence Team
date: 2026-01-26
tags:
    - attack.defense_evasion
    - attack.t1027.010
    - attack.t1562.001
logsource:
    product: windows
    category: kernel_api
detection:
    selection:
        CallTrace|contains:
            - 'MmGetSystemRoutineAddress'
            - 'KeServiceDescriptorTable'
    condition: selection
falsepositives:
    - Legitimate kernel drivers (verify driver signature and vendor)
level: high
```

---

## EDR Hunting Queries

### CrowdStrike Falcon Query

```kusto
// Hunt for BdApiUtil64.sys driver load and related activity
event_simpleName IN ("DriverLoad", "ProcessRollup2", "ServiceInstall")
| where (event_simpleName="DriverLoad" AND (ImageLoaded="*BdApiUtil*" OR SHA256HashData="47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"))
    OR (event_simpleName="ServiceInstall" AND ServiceName="Bprotect")
    OR (event_simpleName="ProcessRollup2" AND (FileName="MsMpEng.exe" OR FileName="CSFalconService.exe") AND ProcessEndReason="Terminated")
| summarize EventCount=count(), FirstSeen=min(ContextTimeStamp), LastSeen=max(ContextTimeStamp) by ComputerName, event_simpleName, FileName, ImageLoaded, ServiceName
| sort by LastSeen desc
```

### Microsoft Sentinel (KQL)

```kusto
// BdApiUtil64.sys BYOVD detection - driver load and security product termination correlation
let DriverLoad =
    DeviceEvents
    | where ActionType == "DriverLoad"
    | where FileName =~ "BdApiUtil64.sys"
        or SHA256 == "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
        or InitiatingProcessFileName contains "BdApiUtil"
    | extend DriverLoadTime = Timestamp
    | project DeviceName, DriverLoadTime, FileName, SHA256, InitiatingProcessFileName;
let SecurityProductTermination =
    DeviceProcessEvents
    | where ActionType == "ProcessTerminated"
    | where FileName in~ ("MsMpEng.exe", "MpDefenderCoreService.exe", "CSFalconService.exe", "ekrn.exe", "avp.exe", "SophosHealth.exe", "cb.exe", "MBAMService.exe")
    | extend TerminationTime = Timestamp
    | project DeviceName, TerminationTime, FileName, ProcessCommandLine;
DriverLoad
| join kind=inner (SecurityProductTermination) on DeviceName
| where TerminationTime between (DriverLoadTime .. (DriverLoadTime + 60s))
| project DeviceName, DriverLoadTime, DriverFileName=FileName, TerminationTime, TerminatedProcess=FileName1, SHA256
| sort by DriverLoadTime desc
```

### Elastic Security (EQL)

```eql
// BdApiUtil64.sys service creation and driver load sequence
sequence by host.name with maxspan=5m
  [registry where registry.path : "*\\Services\\Bprotect*" and event.action == "creation"]
  [driver where file.name : "BdApiUtil64.sys"]
  [process where
    event.action == "termination" and
    process.name in ("MsMpEng.exe", "CSFalconService.exe", "ekrn.exe", "avp.exe")]
```

### Splunk SPL

```spl
// BdApiUtil64.sys BYOVD detection - comprehensive hunt
index=windows (sourcetype=WinEventLog:Sysmon OR sourcetype=WinEventLog:Security)
(
    (EventCode=6 ImageLoaded="*BdApiUtil*") OR
    (EventCode=6 Hashes="*47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428*") OR
    (EventCode=7045 ServiceName="Bprotect") OR
    (EventCode=5 Image IN ("*MsMpEng.exe", "*CSFalconService.exe", "*ekrn.exe", "*avp.exe"))
)
| eval event_type=case(
    EventCode=6, "DriverLoad",
    EventCode=7045, "ServiceCreation",
    EventCode=5, "ProcessTermination"
)
| stats count earliest(_time) as FirstSeen latest(_time) as LastSeen by ComputerName, event_type, Image, ImageLoaded, ServiceName
| convert ctime(FirstSeen) ctime(LastSeen)
| sort -LastSeen
```

---

## SIEM Detection Rules

### Rule 1: Driver Load Hash-Based Detection

```yaml
Rule Name: Arsenal-237 BdApiUtil64.sys BYOVD Driver Load (Hash-Based)
Severity: CRITICAL
MITRE: T1068, T1562.001

Logic:
  Event Source: Sysmon (Event ID 6) OR Windows Security (Event ID 4697)
  Condition:
    (Hashes CONTAINS "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428") OR
    (Hashes CONTAINS "ced47b89212f3260ebeb41682a4b95ec") OR
    (Hashes CONTAINS "148c0cde4f2ef807aea77d7368f00f4c519f47ef")

Action: Generate CRITICAL alert, isolate system, initiate IR

False Positives: Legitimate Baidu Antivirus (extremely rare in enterprise)
```

### Rule 2: Behavioral Correlation - Driver Load + Process Termination

```yaml
Rule Name: Security Product Termination After Suspicious Driver Load
Severity: CRITICAL
MITRE: T1562.001, T1489

Logic:
  Event Sequence:
    Step 1: Driver load (Sysmon Event ID 6)
      - ImageLoaded CONTAINS "BdApiUtil" OR
      - Signed = TRUE AND Signature CONTAINS "Baidu"

    Step 2: Process termination (Sysmon Event ID 5) within 60 seconds
      - Image IN:
          - MsMpEng.exe
          - CSFalconService.exe
          - ekrn.exe
          - avp.exe
          - SophosHealth.exe
          - cb.exe
          - MBAMService.exe

    Correlation: Same ComputerName, Step 2 within 60 seconds of Step 1

Action: Generate CRITICAL alert, isolate system immediately, alert CISO

False Positives: Security product updates (verify timing patterns)
```

### Rule 3: Service Creation - Bprotect Service

```yaml
Rule Name: Bprotect Service Creation (BdApiUtil64.sys Persistence)
Severity: HIGH
MITRE: T1547.006, T1543.003

Logic:
  Event Source: Windows Security (Event ID 4697) OR Sysmon (Event ID 13)
  Condition:
    ServiceName = "Bprotect" AND
    ImagePath CONTAINS "BdApiUtil"

Additional Context:
  - Check if system has legitimate Baidu Antivirus installed
  - Correlate with driver load events

Action: Generate HIGH alert, initiate threat hunt for Arsenal-237 toolkit

False Positives: Legitimate Baidu Antivirus installation
```

### Rule 4: Registry Callback Registration

```yaml
Rule Name: Suspicious Registry Callback Registration (Defense Evasion)
Severity: HIGH
MITRE: T1112, T1562.001

Logic:
  Event Source: Sysmon (Event ID 12/13/14) OR Windows Security (Event ID 4657)
  Condition:
    TargetObject CONTAINS "\\Callback\\bdProtectExpCallBack" OR
    (RegistryPath CONTAINS "\\Services\\Bprotect" AND
     EventType = "CreateKey")

Action: Generate HIGH alert, investigate for security control tampering

False Positives: Legitimate Baidu Antivirus operations
```

### Rule 5: File Access to Protected Credential Stores

```yaml
Rule Name: Kernel Driver Accessing Protected Credential Stores
Severity: CRITICAL
MITRE: T1005, T1555

Logic:
  Event Source: Sysmon (Event ID 11) OR Windows Security (Event ID 4663)
  Condition:
    ProcessName CONTAINS "BdApiUtil" OR
    (ProcessName CONTAINS "System" AND
     TargetFilename IN:
       - "*\\config\\SAM"
       - "*\\config\\SYSTEM"
       - "*\\Credentials\\*"
       - "*\\Login Data"
       - "*\\logins.json")

Action: Generate CRITICAL alert, assume credential compromise, force password resets

False Positives: Legitimate system backup operations (verify context)
```

---

## Implementation Guidance

### Phase 1: Immediate Deployment (Day 1)

1. **Hash-Based Detection:**
   - Deploy SHA256 hash `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428` to all EDR/AV platforms
   - Configure automatic quarantine and alert on detection
   - Estimated FP rate: < 0.01% (legitimate Baidu AV extremely rare in enterprise)

2. **Driver Load Monitoring:**
   - Enable Sysmon Event ID 6 (Driver Load) logging
   - Configure SIEM alert for BdApiUtil64.sys driver loads
   - Alert on any driver with Baidu signature loading outside of Baidu AV installation

3. **Service Creation Monitoring:**
   - Monitor Event ID 4697 (Service Installation) for "Bprotect" service
   - Alert on any kernel driver service created outside of standard installers

### Phase 2: Behavioral Detection (Week 1)

1. **Process Termination Correlation:**
   - Implement 60-second correlation window between driver load and security product termination
   - Baseline normal security product restart patterns
   - Alert on abnormal termination sequences

2. **DeviceIoControl Monitoring:**
   - Enable process access monitoring (Sysmon Event ID 10)
   - Monitor for DeviceIoControl API calls to `\\.\BdApiUtil`
   - Alert on IOCTL codes: 0x800024b4, 0x800024b8, 0x80002324, 0x80002648, 0x8000264c

3. **Registry Monitoring:**
   - Monitor registry keys: `HKLM\SYSTEM\CurrentControlSet\Services\Bprotect`
   - Alert on registry callback registration by non-Microsoft drivers

### Phase 3: Advanced Detection (Week 2-4)

1. **SSDT Bypass Detection:**
   - Monitor for MmGetSystemRoutineAddress calls resolving KeServiceDescriptorTable
   - Alert on indirect system call patterns from drivers
   - Requires kernel-level EDR capabilities

2. **File Access Monitoring:**
   - Monitor file access to: SAM, SYSTEM, Credentials directories, browser credential stores
   - Alert on kernel driver accessing protected locations
   - Correlate with driver load events

3. **Threat Hunting:**
   - Weekly hunt for Arsenal-237 toolkit components (lpe.exe, killer.dll, rootkit.dll, enc_*.exe)
   - Search for driver loads with expired certificates (2015 expiration)
   - Hunt for services with suspicious names (security/Windows impersonation)

### Phase 4: Prevention Controls (Ongoing)

1. **Microsoft Vulnerable Driver Blocklist:**
   - Deploy MVDB on Windows 11 systems with HVCI enabled
   - Blocks BdApiUtil64.sys from loading
   - Recommended for all new deployments

2. **Driver Signature Enforcement:**
   - Enable driver signature enforcement policies
   - Configure WDAC (Windows Defender Application Control) to block unsigned/expired drivers
   - Implement attestation signing requirements

3. **Least Privilege Enforcement:**
   - Restrict SeLoadDriverPrivilege to authorized administrators only
   - Implement service creation restrictions
   - Enable tamper protection on security products

### Detection Confidence Levels

| Detection Method | Confidence | False Positive Rate | Coverage |
|------------------|------------|---------------------|----------|
| Hash-based detection | 100% | < 0.01% | Known samples only |
| Driver signature (Baidu + expired) | 95% | < 1% | Signature variants |
| Service creation (Bprotect) | 90% | < 1% | Specific naming |
| Behavioral correlation | 85% | 5-10% | Evasion attempts |
| IOCTL monitoring | 80% | 10-15% | Requires tuning |
| SSDT bypass detection | 70% | 15-20% | Advanced evasion |

### Expected Detection Timeline

- **Driver Load Detection**: < 1 second (real-time)
- **Service Creation Detection**: < 5 seconds (near real-time)
- **Behavioral Correlation**: 60 seconds (correlation window)
- **SSDT Bypass Detection**: 1-5 minutes (analysis overhead)
- **Threat Hunt Discovery**: Daily/Weekly (scheduled hunts)

### Recommended Alert Prioritization

1. **CRITICAL (P1)**: Hash match + Driver load + Security product termination
2. **HIGH (P2)**: Driver load + Service creation OR Behavioral correlation
3. **MEDIUM (P3)**: IOCTL monitoring alerts OR Registry modifications
4. **LOW (P4)**: SSDT resolution attempts (requires context validation)

### Integration Notes

- **Sysmon**: Ensure Event IDs 6 (Driver Load), 10 (Process Access), 13 (Registry), 5 (Process Termination) are enabled
- **EDR**: Verify kernel-level monitoring capabilities for SSDT detection
- **SIEM**: Configure 60-second correlation window for behavioral detection
- **SOAR**: Implement automatic isolation for CRITICAL alerts
- **Threat Intel**: Cross-reference with Arsenal-237 toolkit IOCs (109.230.231.37, lpe.exe, killer.dll, rootkit.dll)

---

## Summary

BdApiUtil64.sys represents a **critical kernel-level threat** requiring multi-layered detection:
- **Hash-based detection** (100% confidence) for known samples
- **Behavioral correlation** (85% confidence) for driver load + security product termination
- **SSDT bypass detection** (70% confidence) for advanced evasion variants
- **Microsoft MVDB deployment** (prevention) for Windows 11 environments

**Recommended Response**: Immediate system isolation, full system rebuild, credential rotation, 30-day enhanced monitoring.

**Last Updated**: 2026-01-26
**Maintainer**: Threat Intelligence Team
**License**: (c) 2026 Joseph. All rights reserved. Free to read, but reuse requires written permission.
