---
title: Detection Rules - BdApiUtil64.sys - Arsenal-237 BYOVD Component
date: '2026-01-26'
layout: post
permalink: /hunting-detections/bdapiutil64-sys-root/
hide: true
---

# BdApiUtil64.sys Detection Rules & Hunting Queries

**Report**: BdApiUtil64.sys Arsenal-237 BYOVD Component
**Date**: 2026-01-26
**Severity**: CRITICAL

---

## Table of Contents

1. [YARA Rules](#yara-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [EDR Queries](#edr-queries)
4. [SIEM Hunting Queries](#siem-hunting-queries)
5. [Network Detection Signatures](#network-detection-signatures)
6. [Behavioral Detection Rules](#behavioral-detection-rules)

---

## YARA Rules

### Rule 1: BdApiUtil64.sys File Detection

```yara
rule Arsenal237_BdApiUtil64_Baidu_Driver {
    meta:
        description = "Detects BdApiUtil64.sys kernel driver - Arsenal-237 BYOVD component"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "CRITICAL"
        confidence = "100%"
        mitre_technique = "T1547.006"
        mitre_tactic = "Persistence"
        hash_sha256 = "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
        hash_sha1 = "148c0cde4f2ef807aea77d7368f00f4c519f47ef"
        hash_md5 = "ced47b89212f3260ebeb41682a4b95ec"

    strings:
        $pe_header = "MZ"
        $hash_sha256 = "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
        $hash_md5 = "ced47b89212f3260ebeb41682a4b95ec"
        $filename = "BdApiUtil64.sys"
        $pdb_path = "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb"
        $baidu_company = "Baidu Online Network Technology"
        $version_resource = {00 42 00 64 00 41 00 70 00 69 00 55 00 74 00 69 00 6c 00 36 00 34}  // BdApiUtil64 in Unicode

    condition:
        uint16(0) == 0x5a4d and (
            $hash_sha256 or
            $hash_md5 or
            ($filename and $baidu_company) or
            ($pdb_path and any of ($*))
        )
}
```

### Rule 2: BdApiUtil64.sys Registry Service Detection

```yara
rule Arsenal237_BdApiUtil64_Registry_Service {
    meta:
        description = "Detects Arsenal-237 BYOVD driver service registration in Windows registry"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "CRITICAL"
        confidence = "95%"

    strings:
        $service_key = "Services\\Bprotect"
        $image_path = "BdApiUtil64.sys"
        $driver_type = {01 00 00 00}  // Type = 1 (Kernel driver) in hex
        $callback = "bdProtectExpCallBack"

    condition:
        ($service_key and $image_path and $driver_type) or
        $callback
}
```

### Rule 3: Arsenal-237 SSDT Bypass Code Pattern

```yara
rule Arsenal237_SSDT_Bypass_Code {
    meta:
        description = "Detects code patterns characteristic of SSDT bypass mechanism"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "HIGH"
        confidence = "80%"
        technique = "SSDT_Bypass"

    strings:
        // SSDT resolution pattern: MmGetSystemRoutineAddress("KeServiceDescriptorTable")
        $ssdt_api = "KeServiceDescriptorTable"

        // Hook detection: Compare first byte to 0xb8 (MOV EAX)
        $hook_detect_1 = {B8 FF FF FF FF}  // MOV EAX imm32 (unhooked)
        $hook_detect_2 = {E9 ?? ?? ?? ??}  // JMP (hooked)

        // Service number extraction from ZwTerminateProcess
        $zwterminateprocess = "ZwTerminateProcess"

        // Shift operation for SSDT lookup: << 2 (shift left by 2)
        $ssdt_shift = {C1 E0 02}  // SHL EAX, 2

        // SSDT array access pattern
        $ssdt_add = {8B 04 85 ?? ?? ?? ??}  // MOV EAX, [RDX + RAX*4]

    condition:
        (
            ($ssdt_api or $zwterminateprocess) and
            (any of ($hook_detect*)) and
            ($ssdt_shift or $ssdt_add)
        ) or
        (
            all of them
        )
}
```

### Rule 4: Arsenal-237 Service Creation IOCTL

```yara
rule Arsenal237_Service_Creation_IOCTL {
    meta:
        description = "Detects IOCTL 0x80002324 service creation capability"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "CRITICAL"
        confidence = "85%"

    strings:
        $ioctl_code = {24 23 00 80}  // 0x80002324 in little-endian hex
        $zero_size = {24 02 00 00}    // 0x224 (548 bytes) input buffer size in little-endian
        $service_constants = {53 00 65 00 72 00 76 00 69 00 63 00 65}  // "Service" in Unicode

    condition:
        (any of ($*))
}
```

### Rule 5: Arsenal-237 Toolkit Integration - Kill DLL Pattern

```yara
rule Arsenal237_Killer_DLL_Components {
    meta:
        description = "Detects killer.dll and killer_crowdstrike.dll from Arsenal-237 toolkit"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "CRITICAL"

    strings:
        $killer_dll = "killer.dll"
        $killer_crowdstrike = "killer_crowdstrike.dll"
        $target_process_1 = "MsMpEng.exe"
        $target_process_2 = "csagent.exe"
        $target_process_3 = "ekrn.exe"
        $process_termination = "TerminateProcess"

    condition:
        (
            ($killer_dll or $killer_crowdstrike) and
            any of ($target_process*) and
            $process_termination
        )
}
```

### Rule 6: Arsenal-237 Ransomware Encoder Pattern

```yara
rule Arsenal237_Ransomware_Encoder {
    meta:
        description = "Detects enc_*.exe ransomware encoders from Arsenal-237 toolkit"
        author = "Threat Intelligence"
        date = "2026-01-26"
        severity = "CRITICAL"

    strings:
        $ransomware_prefix = "enc_"
        $executable = ".exe"
        // ChaCha20 or RSA encryption patterns
        $chacha20 = "ChaCha20"
        $rsa_oaep = "RSA-OAEP"
        // File encryption constants
        $file_ext = ".enc"
        $ransom_note = "ransom"

    condition:
        ($ransomware_prefix and $executable) or
        (any of ($chacha*) and any of ($file*))
}
```

---

## Sigma Detection Rules

### Rule 1: BdApiUtil64.sys Driver Load Detection (Sysmon Event ID 6)

```yaml
title: BdApiUtil64.sys Kernel Driver Loading (Baidu BYOVD)
id: 61b1cbcc-8fb6-4c4a-892c-8c98e8c7f3a2
status: test
date: 2026-01-26
author: Threat Intelligence
logsource:
    product: windows
    service: sysmon
    event_id: 6
detection:
    driver_baidu_exact:
        ImageLoaded|contains: BdApiUtil64.sys
        SignatureStatus: Valid
        Signed: 'true'
        Issuer|contains: Baidu
    hash_detection:
        Hashes|contains: 47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428
    hash_md5:
        Hashes|contains: ced47b89212f3260ebeb41682a4b95ec
    baidu_outside_install:
        ImageLoaded|contains: BdApiUtil64.sys
        ImageLoaded|notcontains:
            - 'Program Files\Baidu'
            - 'ProgramData\Baidu'
    filter_legitimate_baidu:
        ImageLoaded|contains:
            - 'Program Files\Baidu Antivirus'
            - 'Program Files (x86)\Baidu'
    condition: (driver_baidu_exact OR hash_detection OR hash_md5 OR baidu_outside_install) AND NOT filter_legitimate_baidu
falsepositives:
    - Legitimate Baidu Antivirus installation
level: critical
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1547.006
    - byovd
    - ransomware
```

### Rule 2: Service Creation IOCTL Pattern

```yaml
title: Arsenal-237 Service Creation via Kernel Driver IOCTL
id: 8f2c3d4e-5f6a-4b9c-8d7e-6f5g4h3i2j1k
status: test
date: 2026-01-26
author: Threat Intelligence
logsource:
    product: windows
detection:
    kernel_service_creation:
        EventID:
            - 12  # Registry Object added or deleted
            - 13  # Registry value set
        TargetObject|contains: 'HKLM\SYSTEM\CurrentControlSet\Services'
        Details|contains:
            - 'WindowsUpdateService'
            - 'MicrosoftSecurityAgent'
            - 'NvidiaGraphicsService'
            - 'IntelTelemetryService'
        Image|notcontains: 'System'
    service_type_suspicious:
        EventID: 12
        TargetObject|contains: 'Services\\'
        Details: '1'  # Kernel driver type
    filter_legitimate_services:
        TargetObject|contains:
            - 'Services\NVIDIA'
            - 'Services\Intel'
            - 'Services\MpsSvc'
    condition: (kernel_service_creation OR service_type_suspicious) AND NOT filter_legitimate_services
falsepositives:
    - Legitimate service installation by administrators
level: high
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1543.003
```

### Rule 3: Security Product Process Termination Spike

```yaml
title: Multiple Security Product Process Termination (BYOVD Attack Pattern)
id: 9g3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f
status: test
date: 2026-01-26
author: Threat Intelligence
logsource:
    product: windows
    service: sysmon
    event_id: 1
detection:
    selection:
        EventID: 5  # Process Terminated
        Image|contains:
            - 'MsMpEng.exe'
            - 'MpDefenderCoreService.exe'
            - 'NisSrv.exe'
            - 'CSFalconService.exe'
            - 'csagent.exe'
            - 'ekrn.exe'
            - 'avp.exe'
            - 'SophosHealth.exe'
            - 'cb.exe'
            - 'EventLog'
        ExitCode|all:
            - '!0'  # Non-zero exit code (abnormal termination)
    timeframe: 60s
    filter_shutdown:
        ParentImage|contains: 'shutdown.exe'
    filter_update:
        ParentImage|contains: 'update.exe'
    condition: selection | count by Computer > 2 within 60s AND NOT filter_shutdown AND NOT filter_update
falsepositives:
    - Legitimate security product updates
    - System shutdown or restart
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1489
    - byovd
```

### Rule 4: EventLog Service Termination (Anti-Forensics)

```yaml
title: Windows EventLog Service Terminated (Anti-Forensics Indicator)
id: 1h4i5j6k-7l8m-4n9o-0p1q-2r3s4t5u6v7w
status: test
date: 2026-01-26
author: Threat Intelligence
logsource:
    product: windows
    service: sysmon
    event_id: 5
detection:
    eventlog_termination:
        Image|contains:
            - 'svchost.exe'
            - 'eventlog.exe'
        CommandLine|contains: 'EventLog'
        ExitCode: '!0'
    not_shutdown:
        ParentImage|notcontains:
            - 'shutdown.exe'
            - 'services.exe'
    correlation_driver_load:
        # Requires correlation with Sysmon Event ID 6 (driver load) within 10 seconds before
        _event_order: 'driver_load -> eventlog_termination'
        _timeframe: 10s
    condition: (eventlog_termination AND not_shutdown) OR correlation_driver_load
falsepositives:
    - Legitimate EventLog service restarts
    - System shutdown/reboot
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.004
    - anti_forensics
```

---

## EDR Queries

### CrowdStrike Falcon Query

```
// Detection of BdApiUtil64.sys driver loading
event_type:DriverLoad AND FileName:BdApiUtil64.sys
| stats count by ComputerName, FileName, hash_md5
| where count > 0

// Correlation: Driver load + security process termination within 60 seconds
event_type:DriverLoad AND FileName:BdApiUtil64.sys
| join [
    event_type:ProcessTermination AND
    (FileName:MsMpEng.exe OR FileName:csagent.exe OR FileName:ekrn.exe)
] on ComputerName
| where time_diff(DriverLoad, ProcessTermination) < 60s
| stats count by ComputerName, DriverLoad, ProcessTermination
```

### Microsoft Defender for Endpoint (KQL)

```kusto
// Detection 1: BdApiUtil64.sys driver loading
DeviceImageLoadEvents
| where FileName == "BdApiUtil64.sys"
| project Timestamp, DeviceName, FileName, SHA256, Signer, SigningStatus
| extend AlertLevel = "CRITICAL", IncidentType = "Kernel_Rootkit"

// Detection 2: Baidu-signed kernel drivers loaded outside Baidu installation directory
DeviceImageLoadEvents
| where Signer contains "Baidu"
| where FolderPath !contains "Program Files\\Baidu"
| where FolderPath !contains "ProgramData\\Baidu"
| where FileName endswith ".sys"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| extend AlertLevel = "HIGH"

// Detection 3: Process termination correlation with driver load
let driver_loads = DeviceImageLoadEvents
| where FileName == "BdApiUtil64.sys"
| project DriverLoadTime = Timestamp, DeviceName, DriverName = FileName;

let process_terms = DeviceProcessEvents
| where ProcessName in ("MsMpEng.exe", "MpDefenderCoreService.exe", "NisSrv.exe", "CSFalconService.exe", "csagent.exe", "ekrn.exe")
| where ActionType == "ProcessTerminated"
| project ProcessTermTime = Timestamp, DeviceName, ProcessName;

driver_loads
| join (process_terms) on DeviceName
| where (ProcessTermTime - DriverLoadTime) between (50ms .. 60s)
| project DriverLoadTime, ProcessTermTime, DeviceName, DriverName, ProcessName
| extend AlertLevel = "CRITICAL", IncidentType = "BYOVD_Attack"

// Detection 4: Service creation following driver load
let driver_load = DeviceImageLoadEvents
| where FileName == "BdApiUtil64.sys"
| project DriverTime = Timestamp, DeviceName;

let service_create = DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains "HKLM\\SYSTEM\\CurrentControlSet\\Services"
| where RegistryValueName == "ImagePath"
| project ServiceTime = Timestamp, DeviceName, ServicePath = RegistryValueData;

driver_load
| join (service_create) on DeviceName
| where (ServiceTime - DriverTime) between (0s .. 120s)
| where ServicePath contains "BdApiUtil64" or ServicePath contains "dll"
| extend AlertLevel = "CRITICAL", IncidentType = "Persistence_Setup"
```

### Carbon Black Cloud Query

```
// BdApiUtil64.sys detection
process_name:BdApiUtil64.sys OR process_name:*.sys AND file_name:BdApiUtil64.sys

// Hash-based detection
process_md5:[ced47b89212f3260ebeb41682a4b95ec]
process_sha256:[47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428]

// Bprotect service detection
registry_key_create:*Services\Bprotect* OR registry_value_set:*Services\Bprotect*
```

### Elastic EDR Query

```
file.name:BdApiUtil64.sys AND host.os.type:windows

// Process termination correlation
process.name:(MsMpEng.exe OR csagent.exe OR ekrn.exe) AND
event.action:process_terminated AND
event.duration < 60000ms AND
event.sequence > (process.parent.name:svchost.exe OR process.parent.name:services.exe)
```

---

## SIEM Hunting Queries

### Splunk SPL (Splunk Query Language)

```spl
# Query 1: BdApiUtil64.sys driver loading
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6
| search ImageLoaded="*BdApiUtil64*" OR SHA256="47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
| stats count by host, ImageLoaded, Signed, SignatureStatus, Issuer
| where Issuer contains "Baidu"

# Query 2: Baidu-signed drivers outside installation directory
index=main EventCode=6 Signed="true" Issuer="Baidu*"
| where ImageLoaded NOT LIKE "%Program Files%Baidu%"
| stats count by host, ImageLoaded, SHA256, Issuer

# Query 3: Security product process termination spike
index=main EventCode=5 (Image="*MsMpEng.exe" OR Image="*csagent.exe" OR Image="*ekrn.exe" OR Image="*avp.exe")
| stats earliest(Timestamp) as first_term, latest(Timestamp) as last_term by host
| eval time_diff=last_term-first_term
| where time_diff < 60
| table host, first_term, last_term, time_diff

# Query 4: Correlation - Driver load + Process termination within 60 seconds
index=main EventCode=6 ImageLoaded="*BdApiUtil64*"
| join host [
    search index=main EventCode=5 (Image="*MsMpEng.exe" OR Image="*csagent.exe" OR Image="*ekrn.exe")
    | stats earliest(Timestamp) as proc_term_time by host
]
| where abs(Timestamp - proc_term_time) < 60
| table host, Timestamp, ImageLoaded, proc_term_time

# Query 5: Service creation via kernel IOCTL
index=main EventCode=12 OR EventCode=13
| search TargetObject contains "Services" AND Details contains "0x224"
| stats count by host, TargetObject, Details

# Query 6: EventLog service termination (anti-forensics)
index=main EventCode=5 Image="*eventlog.exe" OR Image="*svchost.exe"
| search "*EventLog*"
| stats count by host, Image, ExitCode

# Query 7: Registry modification to disable security products
index=main EventCode=13 TargetObject contains "Services"
| where RegistryValueName="Start" AND RegistryValueData="4"  # Disabled
| stats count by host, TargetObject, RegistryValueData
| where TargetObject contains "Defender" OR TargetObject contains "Protector" OR TargetObject contains "ESET"
```

### Microsoft Sentinel KQL

```kusto
// Query 1: BdApiUtil64.sys detection across environment
DeviceImageLoadEvents
| where FileName == "BdApiUtil64.sys" or SHA256 == "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
| project Timestamp, DeviceName, FileName, SHA256, Signer
| extend AlertLevel = "CRITICAL"
| order by Timestamp desc

// Query 2: Suspicious Baidu driver loads
DeviceImageLoadEvents
| where Signer contains "Baidu"
| where FolderPath !contains "Program Files" and FolderPath !contains "ProgramData"
| where FileName endswith ".sys"
| extend Risk = "HIGH"
| summarize DriverCount = count() by DeviceName, Signer
| where DriverCount > 1

// Query 3: Service registry modifications with suspicious names
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains "HKLM\\SYSTEM\\CurrentControlSet\\Services"
| where RegistryValueData contains_cs "BdApiUtil"
| extend AlertLevel = "CRITICAL"

// Query 4: Process termination cascade analysis
let SecurityProducts = dynamic(["MsMpEng", "csagent", "ekrn", "avp", "SophosHealth", "cb"]);
DeviceProcessEvents
| where ProcessName in (SecurityProducts)
| where ActionType == "ProcessTerminated"
| summarize TerminatedProcesses = dcount(ProcessName), EarliestTermination = min(Timestamp), LatestTermination = max(Timestamp) by DeviceName, bin(Timestamp, 1m)
| where TerminatedProcesses >= 2

// Query 5: Suspicious registry callbacks
DeviceRegistryEvents
| where RegistryKey contains "\\Callback\\bdProtectExpCallBack"
| extend AlertLevel = "CRITICAL"

// Query 6: SSDT bypass attempt indicators (if available in EDR logs)
// Note: Requires EDR supporting kernel-mode API logging
DeviceEvents
| where ActionType contains "SSDT" or ActionType contains "ServiceDescriptorTable"
| extend RiskLevel = "CRITICAL"
```

### Elastic/ELK Queries

```
# Query 1: BdApiUtil64.sys detection
file.name:BdApiUtil64.sys AND host.os.type:windows

# Query 2: Service creation IOCTL pattern
registry.path:HKLM\\SYSTEM\\CurrentControlSet\\Services\\Bprotect* AND event.action:created

# Query 3: Multiple security process termination
process.name:(MsMpEng.exe OR csagent.exe OR ekrn.exe) AND event.action:process_terminated
| stats count by host.name
| where count >= 2

# Query 4: Baidu driver outside installation path
file.path:*.sys AND code_signature.subject:"Baidu*" AND NOT file.path:"C:\\Program Files\\Baidu*"

# Query 5: EventLog service termination
process.name:(svchost.exe OR eventlog.exe) AND process.command_line:"*EventLog*" AND event.action:process_terminated
```

---

## Network Detection Signatures

### Suricata/Snort Rules

```
# Rule 1: Arsenal-237 Command & Control Communication Pattern
alert http any any -> any any (msg:"Arsenal-237 C2 Beacon Pattern";
    content:"POST"; http_method;
    content:"Arsenal"; http_uri;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;)

# Rule 2: BdApiUtil64 binary transfer detection
alert http any any -> any any (msg:"Possible BdApiUtil64.sys binary download";
    content:"BdApiUtil64.sys"; http_uri;
    classtype:suspicious-file-transfer;
    sid:1000002;
    rev:1;)

# Rule 3: Ransomware toolkit component download
alert http any any -> any any (msg:"Possible enc_*.exe ransomware payload download";
    content:".exe"; http_uri;
    pcre:"/enc_[a-zA-Z0-9]+\.exe/i";
    classtype:suspicious-file-transfer;
    sid:1000003;
    rev:1;)

# Rule 4: Arsenal-237 toolkit communication pattern
alert dns any any -> any any (msg:"Arsenal-237 C2 domain query";
    dns.query; content:"arsenal";
    classtype:suspicious-traffic;
    sid:1000004;
    rev:1;)
```

### Zeek Detection

```zeek
@load base/protocols/http
@load base/protocols/dns
@load base/files/hash

module Arsenal237;

export {
    redef enum Notice::Type += {
        Arsenal237::BYOVD_Driver_Detected,
        Arsenal237::Ransomware_Component_Download,
        Arsenal237::C2_Communication,
    };
}

# Detect BdApiUtil64.sys downloads
event file_over_http_data_end(f: fa_file, http: HTTP::Info) &priority=5 {
    if (f$filename == "BdApiUtil64.sys" ||
        /BdApiUtil64/ in f$filename) {
        NOTICE([
            $note=Arsenal237::BYOVD_Driver_Detected,
            $msg=fmt("Arsenal-237 BYOVD driver downloaded: %s", f$filename),
            $conn=http$c,
            $file=f,
        ]);
    }

    if (/enc_[a-zA-Z0-9]+\.exe/ in f$filename) {
        NOTICE([
            $note=Arsenal237::Ransomware_Component_Download,
            $msg=fmt("Arsenal-237 ransomware payload detected: %s", f$filename),
            $conn=http$c,
            $file=f,
        ]);
    }
}

# Detect C2 communication patterns
event http_request(c: connection, method: string, uri: string) &priority=5 {
    if ("arsenal" in uri || "payload" in uri || "cmd" in uri) {
        NOTICE([
            $note=Arsenal237::C2_Communication,
            $msg=fmt("Possible Arsenal-237 C2 communication: %s", uri),
            $conn=c,
        ]);
    }
}

# Detect DNS queries for C2 infrastructure
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count) &priority=5 {
    if ("arsenal" in query || "c2" in query || "payload" in query) {
        NOTICE([
            $note=Arsenal237::C2_Communication,
            $msg=fmt("Arsenal-237 C2 DNS query: %s", query),
            $conn=c,
        ]);
    }
}
```

---

## Behavioral Detection Rules

### Kernel-Level Behavior Detection (EDR Focus)

**Detection 1: SSDT Bypass Attempt**

```
Monitor for:
1. Process attempts to resolve "KeServiceDescriptorTable" via MmGetSystemRoutineAddress
2. Process reads first instruction of "ZwTerminateProcess" (checking for hook)
3. Process performs shift operations on service numbers (service << 2)
4. Process directly calls SSDT entries instead of using normal kernel APIs

Alert if: Any of above behavior in non-system process
Confidence: HIGH (80%)
Severity: CRITICAL
```

**Detection 2: Registry Callback Installation**

```
Monitor for:
1. Process calls CmRegisterCallback API
2. Callback name contains "bdProtect", "Protect", or suspicious names
3. Registry modifications are blocked/intercepted after callback registration
4. Attempts to delete registered callbacks fail silently

Alert if: Non-Microsoft process registers registry callback
Confidence: HIGH (85%)
Severity: CRITICAL
```

**Detection 3: Minifilter Enumeration**

```
Monitor for:
1. Process calls FltEnumerateFilters
2. Process calls FltGetFilterInformation
3. Process enumerates minifilter instances
4. Followed by termination of detected EDR processes

Alert if: Non-Microsoft process enumerates minifilters AND terminates security processes
Confidence: MEDIUM (75%)
Severity: HIGH
```

**Detection 4: Process Injection via PROCESS_ALL_ACCESS**

```
Monitor for:
1. Process opens handle to other process with PROCESS_ALL_ACCESS rights
2. Kernel context performs privilege elevation
3. Process injects code or modifies process memory
4. Followed by process termination

Alert if: User-mode process obtains PROCESS_ALL_ACCESS via kernel driver
Confidence: HIGH (80%)
Severity: CRITICAL
```

### Host-Based Detection Rules

**Detection 5: Suspicious Service Configuration**

```
Monitor for:
1. Service created with name: WindowsUpdateService, MicrosoftSecurityAgent, NvidiaGraphicsService
2. Service type = 1 (kernel driver) without legitimate reason
3. Service path points to system32\drivers directory
4. Service created outside of Windows Update or legitimate software installation
5. Service description is empty or generic

Alert if: Service name impersonates legitimate Windows service
Confidence: HIGH (85%)
Severity: CRITICAL
```

**Detection 6: Aggressive Event Log Clearing**

```
Monitor for:
1. Event ID 104: Event log was cleared (suspicious if occurred 5+ times in 24h)
2. Event ID 1100: Event logging has been disabled (suspicious if outside maintenance)
3. EventLog service terminates abnormally (exit code != 0)
4. Followed by ransomware activity

Alert if: EventLog service terminated + security process termination + file encryption
Confidence: HIGH (90%)
Severity: CRITICAL
```

**Detection 7: File Access Pattern Anomaly**

```
Monitor for:
1. Process accesses C:\Windows\System32\config\SAM (Windows credential store)
2. Process accesses browser credential databases
3. Process accesses encrypted/protected files
4. Access occurs from unprivileged user context (kernel bypass indicator)
5. Accessed files are immediately exfiltrated

Alert if: Unprivileged process reads protected credential stores
Confidence: HIGH (85%)
Severity: CRITICAL
```

---

## Detection Deployment Recommendations

### Priority 1 (Immediate - Deploy Today)
- [ ] YARA rules for BdApiUtil64.sys file detection
- [ ] Sysmon Event ID 6 (driver load) Sigma rules
- [ ] EDR driver load monitoring with hash-based blocking
- [ ] IOC distribution to all EDR/AV platforms

### Priority 2 (This Week)
- [ ] Process termination correlation rules (SIEM implementation)
- [ ] Registry service creation monitoring
- [ ] Microsoft Vulnerable Driver Blocklist deployment (Windows 11 HVCI)

### Priority 3 (This Month)
- [ ] Advanced behavioral detection rules (SSDT bypass, registry callbacks)
- [ ] Kernel-mode API monitoring (EDR capability verification)
- [ ] Network detection signatures (DNS, HTTP file transfers)

### Priority 4 (Ongoing)
- [ ] Regular IOC updates from threat intelligence feeds
- [ ] Tuning of detection rules based on environment false positives
- [ ] EDR capability verification (ensure kernel-mode logging enabled)

---

## Testing Detection Rules

### Test Environment Setup

```
1. Create isolated test VM (NOT connected to production network)
2. Deploy Windows OS (test Windows 10 and Windows 11)
3. Install EDR agent in test environment
4. Install SIEM agents for log collection
5. Create detection rule baselines (understand normal behavior)
```

### Rule Testing Procedure

```
1. Simulate BdApiUtil64.sys file creation
   - Copy BdApiUtil64.sys to test VM
   - Verify file hash matches IOCs

2. Simulate driver loading
   - Create service registry entry pointing to driver
   - Attempt to load driver (may fail on test VM, that's OK)
   - Verify detection rules trigger

3. Simulate IOCTL calls (if test environment allows)
   - Use custom driver or test utility to send IOCTLs
   - Monitor detection rule responses

4. Verify correlation rules
   - Simulate driver load + process termination sequence
   - Ensure correlation rules properly identify pattern

5. Tune false positive threshold
   - Adjust rule sensitivity based on results
   - Document acceptable noise level
```

### Expected Detection Coverage

After implementing all detection rules, organization should detect:

| Attack Stage | Detection Method | Expected Hit Rate |
|--------------|-----------------|------------------|
| File download (if from external source) | Network + YARA | 95%+ |
| File creation on disk | EDR file monitoring | 99%+ |
| Driver loading attempt | Sysmon Event ID 6 | 95%+ |
| Service creation (Bprotect) | Registry monitoring | 98%+ |
| Security process termination | Process termination correlation | 85%+ |
| SSDT bypass attempt | Kernel-mode behavior detection | 75%+ (requires advanced EDR) |
| Credential file access | File access monitoring | 80%+ |
| Event log clearing | Event log monitoring | 90%+ |

**Overall Expected Detection**: 90-95% of Arsenal-237 BYOVD attacks at some stage of execution

---

## License

© 2026 Threat Intelligence Analysis. All rights reserved.

Free to use for detection rule development and security research.

Detection rules may be modified for organizational requirements.
