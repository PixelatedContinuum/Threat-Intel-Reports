---
title: Detection Rules - enc/dec Ransomware Family
date: '2026-01-18'
layout: post
permalink: /hunting-detections/enc-dec-ransomware-family/
hide: true
---

# Detection Rules – enc/dec Ransomware Family

## Overview
Comprehensive detection coverage for the enc/dec ransomware family includes static file signatures, process behavior patterns, and network indicators. Rules are provided in YARA and Sigma formats for SIEM/EDR integration and proactive threat hunting.

**Malware Family**: enc/dec ransomware
**Severity**: CRITICAL
**Last Updated**: 2026-01-18

**Related Report:** [enc/dec Ransomware Family Analysis](/reports/enc-dec-ransomware-family/)

---

## Table of Contents

1. [YARA Rules](#yara-rules)
2. [Sigma Detection Rules](#sigma-detection-rules)
3. [Threat Hunting Queries](#threat-hunting-queries)
4. [Endpoint Detection Opportunities](#endpoint-detection-opportunities)
5. [Implementation Guidance](#implementation-guidance)

---

## YARA Rules

### Rule 1: ChaCha20 Constant Detection (HIGHEST FIDELITY)

**Description:** Detects the RFC 8439 ChaCha20 initialization constant "expand 32-byte k" which definitively identifies ChaCha20 usage.

**Fidelity:** VERY HIGH (few false positives - legitimate ChaCha20 usage in VPNs, secure messaging)

```yara
rule EncDec_ChaCha20_Constant {
    meta:
        description = "Detects enc/dec ransomware by ChaCha20 constant"
        author = "Threat Intelligence Team"
        date = "2026-01-18"
        malware_family = "enc/dec ransomware"
        confidence = "HIGH"
        severity = "CRITICAL"
        reference = "RFC 8439 ChaCha20 Constant"

    strings:
        $chacha20_constant = "expand 32-byte k" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        $chacha20_constant
}
```

**Detection Context:**
- The ChaCha20 constant is a standardized initialization string defined in RFC 8439
- This custom ChaCha20 implementation uses this constant in its keystream generation
- False positives: Legitimate encryption software (VPN clients, secure messaging apps)
- **Recommended Action:** Correlate with other indicators (VSS deletion, rapid file modification)

---

### Rule 2: VSS Deletion Signature String

**Description:** Detects the unique concatenated string artifact created during Volume Shadow Copy deletion.

**Fidelity:** HIGH (this exact string concatenation is unique to this ransomware family)

```yara
rule EncDec_VSS_Deletion_Signature {
    meta:
        description = "Detects enc/dec ransomware by unique VSS deletion string"
        author = "Threat Intelligence Team"
        date = "2026-01-18"
        malware_family = "enc/dec ransomware"
        confidence = "HIGH"
        severity = "CRITICAL"

    strings:
        // Exact concatenated string found in enc_v2.exe and updated_enc.exe
        $vss_sig = "vssadmindeleteshadows/all/quietwmicshadowcopy" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        $vss_sig
}
```

**Detection Context:**
- This concatenated string is created during VSS deletion command construction
- Reveals the exact commands: `vssadmin delete shadows /all /quiet` and `wmic shadowcopy delete`
- **Recommended Action:** CRITICAL alert - immediate investigation required

---

### Rule 3: Rust Ransomware Artifacts

**Description:** Detects enc/dec Rust ransomware by debug artifacts and operational strings.

**Fidelity:** MEDIUM-HIGH (Rust debug paths are unique, operational strings may have false positives)

```yara
rule EncDec_Rust_Ransomware_Artifacts {
    meta:
        description = "Detects enc/dec Rust ransomware by debug artifacts"
        author = "Threat Intelligence Team"
        date = "2026-01-18"
        malware_family = "enc/dec ransomware"
        confidence = "MEDIUM-HIGH"
        severity = "CRITICAL"

    strings:
        $rust_debug1 = "chacha20_pervictim.rs" ascii wide
        $rust_debug2 = "netusesrc/modules/disks.rs" ascii wide
        $rust_debug3 = "/aead-0.5.2/src/lib.rs" ascii wide
        $rsa_key_marker = "-----BEGIN PUBLIC KEY-----" ascii wide
        $enc_message = "[*] Using RSA+ChaCha20 encryption" ascii wide
        $key_gen = "[*] Generating unique encryption key" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        2 of ($rust_debug*) or
        ($rsa_key_marker and ($enc_message or $key_gen))
}
```

**Detection Context:**
- Rust debug paths: `chacha20_pervictim.rs`, `netusesrc/modules/disks.rs`, `aead-0.5.2/src/lib.rs`
- Operational messages reveal encryption algorithm and key generation
- **Recommended Action:** High-priority investigation, correlate with file modification activity

---

### Rule 4: Anti-Debug Signature

**Description:** Detects the stack-based anti-debugging technique shared across enc/dec toolkit components.

**Fidelity:** MEDIUM (Sleep(1000) pattern may have false positives, use as correlation signal)

```yara
rule EncDec_AntiDebug_Signature {
    meta:
        description = "Detects anti-debug technique shared across enc/dec"
        author = "Threat Intelligence Team"
        date = "2026-01-18"
        malware_family = "enc/dec toolkit (all components)"
        confidence = "MEDIUM"
        severity = "HIGH"
        reference = "Shared across agent.exe, steal_browser.exe, enc/dec ransomware"

    strings:
        // Pattern for stack base check + Sleep(1000) in x64 assembly
        // This is a heuristic - may need tuning for false positive reduction
        $sleep_1000 = { E8 ?? ?? ?? ?? 6A 00 68 E8 03 00 00 }  // Sleep(0x3e8)

    condition:
        uint16(0) == 0x5A4D and  // PE file
        $sleep_1000
}
```

**Detection Context:**
- This anti-debugging loop continuously checks the thread's stack base address
- If stack base changes (debugger attached), malware sleeps for 1 second
- Also serves as sandbox evasion (delays analysis)
- **Recommended Action:** Use as correlation signal with other enc/dec indicators

---

### Rule 5: Comprehensive enc/dec Family Detection

**Description:** Multi-indicator detection rule for enc/dec ransomware family with layered logic.

**Fidelity:** HIGH when ChaCha20 constant detected, MEDIUM when relying on combined indicators

```yara
rule EncDec_enc_dec_Family_Comprehensive {
    meta:
        description = "Comprehensive detection for enc/dec ransomware family"
        author = "Threat Intelligence Team"
        date = "2026-01-18"
        malware_family = "enc/dec ransomware"
        confidence = "HIGH"
        severity = "CRITICAL"

    strings:
        // Cryptographic indicators
        $crypto1 = "expand 32-byte k" ascii wide
        $crypto2 = "-----BEGIN PUBLIC KEY-----" ascii wide

        // System impact indicators
        $impact1 = "vssadmin" ascii wide nocase
        $impact2 = "shadowcopy" ascii wide nocase
        $impact3 = "wmic" ascii wide nocase

        // Rust artifacts
        $rust1 = "chacha20" ascii wide nocase
        $rust2 = ".rs" ascii wide
        $rust3 = "aead" ascii wide

        // Operational strings
        $ops1 = "README" ascii wide nocase
        $ops2 = "decrypt" ascii wide nocase
        $ops3 = "--pass" ascii wide
        $ops4 = "--file" ascii wide
        $ops5 = "--folder" ascii wide

    condition:
        uint16(0) == 0x5A4D and  // PE file
        (
            $crypto1 or  // ChaCha20 constant (highest confidence)
            (
                $crypto2 and  // RSA key
                2 of ($impact*) and  // VSS deletion
                1 of ($rust*)  // Rust implementation
            ) or
            (
                3 of ($ops*) and  // Decryptor operational strings
                1 of ($rust*)  // Rust implementation
            )
        )
}
```

**Detection Context:**
- Layered detection logic: ChaCha20 constant OR (RSA + VSS + Rust) OR (decryptor strings + Rust)
- Detects both encryptors and decryptors
- **Recommended Action:** CRITICAL alert requiring immediate incident response

---

## Sigma Detection Rules

### Rule 1: Volume Shadow Copy Deletion Detection

**Description:** Detects execution of VSS deletion commands via vssadmin.exe or wmic.exe.

**Fidelity:** HIGH (legitimate VSS deletion is rare outside maintenance windows)

```yaml
title: enc/dec Ransomware VSS Deletion Activity
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects Volume Shadow Copy deletion commands consistent with enc/dec ransomware family
references:
    - enc/dec ransomware technical analysis
author: Threat Intelligence Team
date: 2026/01/18
tags:
    - attack.impact
    - attack.t1490
    - attack.inhibit_system_recovery
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'delete'
            - 'shadows'
            - '/all'
    selection_wmic:
        CommandLine|contains|all:
            - 'wmic'
            - 'shadowcopy'
            - 'delete'
    condition: selection_vssadmin or selection_wmic
falsepositives:
    - Legitimate system maintenance (rare)
    - Backup software uninstallation
level: critical
```

**Implementation Notes:**
- Deploy to SIEM for real-time alerting on VSS deletion
- Consider creating exceptions for authorized maintenance windows
- Alert should trigger immediate investigation

---

### Rule 2: Rapid Multi-Drive Enumeration

**Description:** Detects rapid sequential drive access characteristic of ransomware.

**Fidelity:** MEDIUM-HIGH (backup software and inventory tools may false positive)

```yaml
title: enc/dec Ransomware Multi-Drive Enumeration
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects rapid sequential drive enumeration characteristic of enc/dec ransomware
author: Threat Intelligence Team
date: 2026/01/18
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|re: '^[A-Z]:\\.*'
    timeframe: 10s
    condition: selection | count(by Image) > 20  # 20+ drives accessed in 10 seconds
falsepositives:
    - Backup software
    - System inventory tools
    - Legitimate file search utilities
level: high
```

**Implementation Notes:**
- Adjust threshold based on environment (20+ drives in 10 seconds is aggressive)
- Whitelist known backup software and inventory tools
- Correlate with other enc/dec indicators for high-fidelity alerts

---

### Rule 3: ChaCha20 Cryptographic Activity Detection

**Description:** Detects processes exhibiting ChaCha20 cryptographic operation patterns.

**Fidelity:** MEDIUM (legitimate encryption software will false positive)

```yaml
title: enc/dec ChaCha20 Cryptographic Operations
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects processes loading or executing ChaCha20 cryptographic operations
author: Threat Intelligence Team
date: 2026/01/18
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_access
    product: windows
detection:
    selection_strings:
        - Strings|contains: 'expand 32-byte k'  # ChaCha20 constant
        - Strings|contains: 'chacha20'
    selection_memory:
        MemoryAllocation|gt: 100MB  # Large memory allocations for file encryption
        CPUUsage|gt: 80  # High CPU during encryption
    condition: selection_strings and selection_memory
falsepositives:
    - Legitimate encryption software
    - VPN clients using ChaCha20
    - Secure messaging applications (Signal, Wire, etc.)
level: medium
```

**Implementation Notes:**
- Requires EDR with memory scanning and CPU monitoring capabilities
- Whitelist known legitimate ChaCha20 usage (VPNs, messaging apps)
- Best used as correlation signal with other indicators

---

## Threat Hunting Queries

### Hunt 1: enc/dec Infrastructure Communication

**Objective:** Identify systems communicating with enc/dec distribution/C2 infrastructure.

**Fidelity:** VERY HIGH (109.230.231.37 is confirmed malicious infrastructure)

```kql
// Splunk SPL
index=network earliest=-30d
| search dest_ip="109.230.231.37" OR src_ip="109.230.231.37"
| stats count by src_ip, dest_ip, dest_port, _time
| where count > 1

// Microsoft Defender / Sentinel KQL
NetworkCommunicationEvents
| where Timestamp > ago(30d)
| where RemoteIP == "109.230.231.37" or LocalIP == "109.230.231.37"
| summarize Count=count() by DeviceName, RemoteIP, RemotePort, LocalIP
| where Count > 1
```

**Hunting Guidance:**
- Search 30+ days historical data (enc/dec may have long dwell times)
- Any communication to 109.230.231.37 is HIGH PRIORITY investigation
- Check for Xworm RAT C2 traffic patterns (TCP/WebSocket)
- Correlate with file system activity (downloads from this IP)

---

### Hunt 2: Suspicious Rust Executable Execution

**Objective:** Identify Rust-compiled executables with ransomware operational parameters.

**Fidelity:** HIGH when `--pass`, `--file`, `--folder` flags present

```kql
// Splunk SPL
index=endpoint earliest=-7d EventCode=1
| search (Image="*.exe" AND (CommandLine="*--pass*" OR CommandLine="*--folder*"))
| stats count by Image, CommandLine, User, ComputerName

// Microsoft Defender / Sentinel KQL
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName endswith ".exe"
| where ProcessCommandLine contains "--pass" or ProcessCommandLine contains "--folder"
| summarize Count=count() by FileName, ProcessCommandLine, AccountName, DeviceName
```

**Hunting Guidance:**
- `--pass` flag indicates password-protected decryption operation
- `--file` and `--folder` flags indicate encryption/decryption targets
- Check process hash against enc/dec IOC feed
- Review file system activity for mass file modifications

---

### Hunt 3: Volume Shadow Copy Deletion Events

**Objective:** Detect historical VSS deletion activity (may indicate past ransomware execution).

**Fidelity:** HIGH (legitimate VSS deletion is rare)

```kql
// Splunk SPL
index=endpoint earliest=-24h EventCode=1
| search (Image="*vssadmin.exe" AND CommandLine="*delete*shadows*") OR (Image="*wmic.exe" AND CommandLine="*shadowcopy*delete*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage

// Microsoft Defender / Sentinel KQL
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName == "vssadmin.exe" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "shadows")
    or (FileName == "wmic.exe" and ProcessCommandLine contains "shadowcopy" and ProcessCommandLine contains "delete")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Hunting Guidance:**
- Review parent process (InitiatingProcessFileName) - should NOT be user-initiated
- Check for file encryption activity following VSS deletion
- Any detection requires immediate investigation

---

### Hunt 4: High-Volume File Modification Activity

**Objective:** Identify processes performing mass file modifications characteristic of ransomware.

**Fidelity:** MEDIUM-HIGH (depends on threshold - 1000+ files is aggressive)

```kql
// Splunk SPL
index=endpoint earliest=-1h EventCode=4663
| stats dc(ObjectName) as UniqueFiles by SubjectUserName, ProcessName
| where UniqueFiles > 1000  # Modified 1000+ files in 1 hour

// Microsoft Defender / Sentinel KQL
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileModified", "FileCreated")
| summarize UniqueFiles=dcount(FileName) by InitiatingProcessFileName, AccountName, DeviceName
| where UniqueFiles > 1000  # Modified 1000+ files in 1 hour
```

**Hunting Guidance:**
- Adjust threshold based on environment (1000+ files in 1 hour is ransomware-indicative)
- Whitelist known backup processes and user productivity tools
- Investigate file modification patterns (sequential drive access, specific file types)
- Check for preceding VSS deletion activity

---

### Hunt 5: ChaCha20 Constant in Process Memory

**Objective:** Memory scan for ChaCha20 constant in running processes.

**Fidelity:** VERY HIGH when correlated with suspicious process behavior

```kql
// Using YARA scanning via EDR
index=endpoint earliest=-24h
| search yara_rule="EncDec_ChaCha20_Constant"
| table _time, ComputerName, User, ProcessName, ProcessPath, yara_matches

// Manual Memory Scanning
// Tools: Volatility, Process Hacker, custom PowerShell script
// Search process memory for string "expand 32-byte k"
```

**Hunting Guidance:**
- Requires EDR with YARA memory scanning capability OR manual memory forensics
- ChaCha20 constant detection in memory = active encryption process
- Legitimate hits: VPN clients (OpenVPN), secure messaging apps
- Cross-reference with enc/dec file hashes and behavioral indicators

---

## Endpoint Detection Opportunities

### High-Fidelity Detections

**1. ChaCha20 Constant Detection**
- **Method:** Scan process memory and newly written files for "expand 32-byte k"
- **Fidelity:** VERY HIGH (few false positives)
- **Tools:** EDR with YARA scanning, custom memory forensics
- **Recommendation:** Deploy as automated detection rule

**2. VSS Deletion Command Detection**
- **Method:** Monitor vssadmin.exe and wmic.exe process creation with specific parameters
- **Fidelity:** HIGH (legitimate use cases are rare)
- **Tools:** SIEM, EDR process monitoring
- **Recommendation:** CRITICAL alert requiring immediate response

**3. Rust Debug Artifact Detection**
- **Method:** Scan executables for "chacha20_pervictim.rs", "netusesrc/modules/disks.rs"
- **Fidelity:** VERY HIGH (unique to enc/dec)
- **Tools:** Static file scanning with YARA
- **Recommendation:** Deploy across all endpoints

### Behavioral Detections

**4. Rapid Multi-Drive Access**
- **Method:** Detect single process accessing 10+ drive letters within short timeframe
- **Fidelity:** MEDIUM (backup software false positives)
- **Tools:** EDR file activity monitoring
- **Recommendation:** Use threshold tuning, correlate with other indicators

**5. Mass File Modification**
- **Method:** Detect single process modifying 1000+ files across multiple directories
- **Fidelity:** MEDIUM-HIGH (depends on threshold)
- **Tools:** EDR file activity monitoring, SIEM
- **Recommendation:** Whitelist known productivity tools, alert on anomalies

**6. Network Share Enumeration + File Modification**
- **Method:** Detect process enumerating shares followed by mass file modifications
- **Fidelity:** HIGH (combined indicators increase confidence)
- **Tools:** EDR with network and file activity correlation
- **Recommendation:** High-priority alert

### Correlation Signals

**7. VEH Installation Detection**
- **Method:** Monitor AddVectoredExceptionHandler API calls
- **Fidelity:** LOW (many legitimate uses)
- **Tools:** EDR with API monitoring
- **Recommendation:** Use as correlation signal only, NOT standalone alert

**8. Repeated Sleep() Call Pattern**
- **Method:** Detect processes with unusual Sleep(1000ms) patterns
- **Fidelity:** LOW (many legitimate uses)
- **Tools:** EDR with API monitoring
- **Recommendation:** Correlate with stack-checking behavior and other enc/dec indicators

---

## Implementation Guidance

### Deployment Priority

**Phase 1: Critical Infrastructure Protection (Week 1)**
1. **Network Blocking:** Block 109.230.231.37 at perimeter firewalls (IMMEDIATE)
2. **VSS Deletion Detection:** Deploy Sigma Rule 1 to SIEM (CRITICAL)
3. **YARA Rule 1 & 2:** Deploy ChaCha20 constant and VSS signature detection (HIGH FIDELITY)

**Phase 2: Comprehensive Coverage (Weeks 2-4)**
4. **YARA Rules 3-5:** Deploy Rust artifacts, anti-debug, and comprehensive detection
5. **Sigma Rules 2-3:** Deploy multi-drive enumeration and ChaCha20 activity detection
6. **Threat Hunting:** Execute Hunts 1-5 to identify historical compromise

**Phase 3: Continuous Monitoring (Ongoing)**
7. **Threat Hunting Program:** Schedule monthly hunts using provided queries
8. **Detection Tuning:** Adjust thresholds based on false positive rates
9. **IOC Updates:** Monitor for new enc/dec variants and update signatures

### False Positive Management

**Expected False Positives:**

| Detection Rule | False Positive Sources | Mitigation Strategy |
|----------------|------------------------|---------------------|
| ChaCha20 Constant | VPN clients (OpenVPN, WireGuard), secure messaging (Signal) | Whitelist known legitimate applications |
| Multi-Drive Enumeration | Backup software, system inventory tools | Adjust threshold, whitelist known processes |
| ChaCha20 Cryptographic Activity | Encryption software, secure communications | Correlate with other indicators, whitelist legitimate processes |
| VSS Deletion | Scheduled maintenance, backup uninstall | Create maintenance window exceptions |

**Tuning Recommendations:**
- Start with high-sensitivity thresholds, tune down based on false positive volume
- Maintain whitelist of known-good processes generating false positives
- Use correlation logic (multiple indicators = higher confidence alert)
- Prioritize ChaCha20 constant and VSS deletion (highest fidelity)

### Integration Points

**SIEM Integration (Splunk, Sentinel, etc.):**
- Deploy Sigma rules as correlation searches
- Create dashboards for enc/dec indicator tracking
- Configure CRITICAL alerts for VSS deletion and ChaCha20 detection

**EDR Integration (CrowdStrike, SentinelOne, Defender for Endpoint):**
- Deploy YARA rules for static file scanning
- Enable behavioral detection for mass file modification
- Configure process memory scanning for ChaCha20 constant

**Threat Intelligence Platforms:**
- Ingest enc/dec IOC feed (JSON) for automated blocking
- Configure threat hunting workflows using provided queries
- Share detections with industry ISACs

### Operational Playbook

**Alert Response Workflow:**

1. **CRITICAL Alert (VSS Deletion, ChaCha20 Constant):**
   - **Action:** IMMEDIATE isolation of affected system
   - **Timeline:** 0-5 minutes from alert
   - **Next Steps:** Forensic image acquisition, threat hunt for lateral movement

2. **HIGH Alert (Rust Artifacts, Multi-Drive Access):**
   - **Action:** Detailed investigation, correlate with other indicators
   - **Timeline:** 0-30 minutes from alert
   - **Next Steps:** If confirmed enc/dec, escalate to CRITICAL workflow

3. **MEDIUM Alert (Behavioral Anomalies):**
   - **Action:** Analyst review, correlate with threat intelligence
   - **Timeline:** 0-2 hours from alert
   - **Next Steps:** Tune detection or escalate if enc/dec confirmed

### Testing and Validation

**Detection Validation:**
- Test YARA rules against enc/dec samples in isolated environment
- Validate Sigma rules generate alerts for known VSS deletion events
- Execute threat hunting queries against test data to verify query logic

**Continuous Improvement:**
- Review detection performance weekly (true positives, false positives, missed detections)
- Update signatures based on new enc/dec variant discoveries
- Share detection lessons learned with community

---

## Additional Resources

**Related Content:**
- [enc/dec Ransomware Family Analysis](/reports/enc-dec-ransomware-family/) - Complete technical analysis
- [IOC Feed (JSON)](/ioc-feeds/enc-dec-ransomware-family.json) - Machine-readable indicators

**enc/dec Toolkit Components:**
- [agent.exe Detection Rules](/hunting-detections/agent-exe/) - Golang RAT backdoor signatures
- [agent_xworm.exe Detection Rules](/hunting-detections/agent-xworm-exe/) - Xworm RAT v1
- [agent_xworm_v2.exe Detection Rules](/hunting-detections/agent-xworm-v2-exe/) - Xworm RAT v2.4.0
- [FleetAgentAdvanced.exe Detection Rules](/hunting-detections/fleetagentadvanced-exe/) - Persistence dropper
- [uac_test.exe Detection Rules](/hunting-detections/uac-test-exe/) - UAC bypass PoC

**External Resources:**
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware) - Federal ransomware response guidance
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/) - Data Encrypted for Impact
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/) - Inhibit System Recovery

---

**Last Updated:** 2026-01-18
**Version:** 1.0
**Feedback:** Report false positives or detection improvements to threat intelligence team
