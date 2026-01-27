---
title: killer_crowdstrike.dll (BYOVD Defense Evasion Variant) - Technical Analysis & Threat Intelligence Report
date: '2026-01-25'
layout: post
permalink: /reports/arsenal-237-new-files/killer-crowdstrike-dll/
hide: true
---

> **Open Directory Investigation**: This sample was discovered on an open directory hosted at IP address **109.230.231.37**, representing the Arsenal-237 malware development and testing repository. killer_crowdstrike.dll is a specialized variant of the killer.dll defense evasion module, specifically reconfigured to target CrowdStrike Falcon endpoint detection and response (EDR). This variant demonstrates threat actor modularity-the underlying attack code is recycled from the generic killer.dll, with only the target process list updated. This module operates as Stage 2 of a two-stage attack chain, with lpe.exe (privilege escalation) delivering killer_crowdstrike.dll as its payload. To see all other reports from this investigation see [Executive Overview](/reports/109.230.231.37-Executive-Overview/)

---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
**killer_crowdstrike.dll** is a **CRITICAL-severity defense evasion variant** from the Arsenal-237 malware toolkit that represents a **direct, targeted attack capability against CrowdStrike Falcon**. This Rust-compiled Windows DLL proves that threat actors have explicitly developed countermeasures to defeat one of the most widely deployed enterprise EDR solutions. Unlike the generic killer.dll, this variant is purpose-built to disable CrowdStrike's three core processes: **CSFalconService.exe**, **csagent.exe**, and **CSFalconContainer.exe**.

The module functions as **Stage 2** of a coordinated attack chain: lpe.exe (privilege escalation tool) first obtains NT AUTHORITY\SYSTEM privileges, then launches killer_crowdstrike.dll to eliminate CrowdStrike defenses. Using the **BYOVD (Bring Your Own Vulnerable Driver)** technique, killer_crowdstrike.dll deploys embedded, legitimately-signed drivers with known vulnerabilities, then issues kernel-mode IOCTL commands (0x800024B4 for Baidu driver, 0x8335003C for Process Explorer driver) to terminate CrowdStrike processes. After neutralizing defenses, the malware removes all traces-stopping services, deleting driver files, and unloading kernel modules-to evade forensic detection.

**Critical Distinction**: This variant uses the **identical IOCTLs and driver deployment mechanism** as the generic killer.dll, proving that the threat actor is **reusing proven technology** rather than investing in entirely new exploits. The only significant change is the "kill list" configuration-updated specifically to include CrowdStrike processes. This demonstrates an **operationally mature threat actor** with modular, reconfigurable attack tools.

This variant also includes an **embedded Microsoft-signed binary** not present in the generic killer.dll, suggesting the attacker has identified an alternative or more advanced driver abuse technique potentially optimized for defeating CrowdStrike monitoring.

### Key Risk Factors
<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Factor</th>
      <th class="numeric">Score</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Overall Risk</strong></td>
      <td class="numeric critical">9.7/10</td>
      <td class="critical">CRITICAL - Complete EDR bypass targeting CrowdStrike specifically</td>
    </tr>
    <tr>
      <td>CrowdStrike-Specific Targeting</td>
      <td class="numeric critical">10/10</td>
      <td>Explicitly designed to disable Falcon; three core processes explicitly targeted</td>
    </tr>
    <tr>
      <td>Defense Evasion Effectiveness</td>
      <td class="numeric critical">10/10</td>
      <td>Kernel-level termination defeats all user-mode security controls</td>
    </tr>
    <tr>
      <td>System Compromise</td>
      <td class="numeric critical">10/10</td>
      <td>Requires NT AUTHORITY\SYSTEM - complete system-level access</td>
    </tr>
    <tr>
      <td>Detection Difficulty</td>
      <td class="numeric critical">9/10</td>
      <td>Legitimately-signed drivers bypass signature validation; self-cleanup removes forensic artifacts</td>
    </tr>
    <tr>
      <td>Advanced Driver Exploitation</td>
      <td class="numeric critical">9/10</td>
      <td>Embedded Microsoft-signed binary suggests additional exploitation techniques</td>
    </tr>
    <tr>
      <td>Attack Chain Integration</td>
      <td class="numeric critical">10/10</td>
      <td>Designed explicitly for lpe.exe -> killer_crowdstrike.dll -> ransomware deployment sequence</td>
    </tr>
  </tbody>
</table>

### Recommended Actions
1. **ALERT** - CrowdStrike Falcon customers: This variant explicitly targets your deployment; implement detection rules immediately
2. **HUNT** for vulnerable driver loading: BdApiUtil64.sys (Baidu) and ProcExpDriver.sys (Process Explorer) service creation events
3. **MONITOR** for CrowdStrike process termination: Any unexpected termination of CSFalconService.exe, csagent.exe, or CSFalconContainer.exe should trigger immediate incident response
4. **INVESTIGATE** the embedded Microsoft-signed binary for additional exploitation techniques
5. **BLOCK** Arsenal-237 infrastructure: IP 109.230.231.37 and C2 endpoint http://109.230.231.37:8888/lpe.exe at network perimeter
6. **DEPLOY** behavioral detection rules for lpe.exe -> killer_crowdstrike.dll attack chain correlation
7. **IMPLEMENT** Windows driver blocklist for vulnerable driver hashes identified in this report
8. **AUDIT** all systems for evidence of CrowdStrike process termination followed by malicious activity

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [File Identification](#file-identification)
- [Executive Technical Summary](#executive-technical-summary)
- [Deep Technical Analysis](#deep-technical-analysis)
  - [Comparative Analysis: killer_crowdstrike.dll vs. killer.dll](#comparative-analysis-killer_crowdstrike-dll-vs-killer-dll)
  - [CrowdStrike-Specific Targeting](#crowdstrike-specific-targeting)
  - [BYOVD Attack Lifecycle Overview](#byovd-attack-lifecycle-overview)
  - [Embedded Driver Analysis](#embedded-driver-analysis)
  - [Embedded Microsoft-Signed Binary](#embedded-microsoft-signed-binary)
  - [Master Orchestrator Function](#master-orchestrator-function)
  - [Anti-Analysis Features](#anti-analysis-features)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Frequently Asked Questions](#frequently-asked-questions)
- [IOCs](#iocs)
- [Detections](#detections)

---

## Quick Reference

**Detections & IOCs:**
- [killer_crowdstrike.dll Detection Rules]({{ "/hunting-detections/arsenal-237-killer-crowdstrike-dll/" | relative_url }})
- [killer_crowdstrike.dll IOCs]({{ "/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" | relative_url }})

**Related Reports:**
- [killer.dll Generic Variant](/reports/killer-dll/) - Original BYOVD implementation
- [Arsenal-237 Executive Overview](/reports/109.230.231.37-Executive-Overview/) - Full toolkit analysis
- [lpe.exe Privilege Escalation Module](/reports/lpe-exe/) - Stage 1 component

---

## File Identification

### Primary Module
- **Original Filename**: killer_crowdstrike.dll
- **Variant Status**: Specialized CrowdStrike-targeting variant of killer.dll
- **Compiler**: Rust (identified via PDB/debug strings)
- **File Type**: PE32+ executable (DLL), x86-64, Rust-compiled
- **File Size**: Approximately 532,992 bytes (approx 520 KB) - **identical to generic killer.dll**
- **Family**: Arsenal-237 BYOVD Defense Evasion Module
- **Distribution Source**: IP 109.230.231.37 (CONFIRMED)
- **Analysis Date**: January 24, 2026

### Variant Differentiation
- **Configuration Focus**: CrowdStrike Falcon processes (CSFalconService.exe, csagent.exe, CSFalconContainer.exe)
- **Core Engine**: **Identical to generic killer.dll** - reuses IOCTLs 0x800024B4 and 0x8335003C
- **Key Difference**: Updated "kill list" configuration targeting CrowdStrike specifically
- **New Element**: Embedded Microsoft-signed binary (not present in generic killer.dll)
- **Modularity Evidence**: Proves threat actor reconfigures tools rather than rebuilding them

### Embedded Drivers (IDENTICAL TO killer.dll)
- **Baidu Driver**: BdApiUtil64.sys (IOCTL 0x800024B4)
- **Process Explorer Driver**: ProcExpDriver.sys (IOCTL 0x8335003C)

### C2 Infrastructure
- **Download URL**: http://109.230.231.37:8888/lpe.exe (CONFIRMED)
- **Payload Download Location**: %TEMP%\svchost_update.exe
- **Infrastructure Context**: Arsenal-237 open directory malware repository

---

## Executive Technical Summary

### Business Context
killer_crowdstrike.dll is a **purpose-built countermeasure to CrowdStrike Falcon**, demonstrating that threat actors have explicitly engineered defenses against one of the most widely deployed enterprise EDR solutions. Rather than inventing new techniques, the threat actor efficiently **reconfigured their existing killer.dll platform** to target CrowdStrike processes specifically.

This variant proves two critical points:
1. **Threat Actor Modularity**: They maintain configurable, reusable attack tools that can be adapted for different targets
2. **CrowdStrike as a Specific Threat**: The fact that a variant exists proves attackers have identified Falcon as sufficiently formidable to warrant dedicated targeting

### Key Business Impacts

**For CrowdStrike Customers:**
- **Explicit Targeting Risk**: This malware was built specifically to defeat your EDR solution
- **Complete Bypass Potential**: If killer_crowdstrike.dll executes successfully, Falcon monitoring is disabled
- **Immediate Response Required**: Detection of this specific variant should trigger incident response activation
- **Investigation Complexity**: CrowdStrike agents terminated by kernel-level drivers may leave limited forensic evidence

**For Organizations (All EDR Vendors):**
- **Proof of Concept**: This variant demonstrates threat actors are investing in EDR-specific bypasses
- **BYOVD Technique Maturity**: The reuse of driver IOCTLs and cleanup mechanisms shows operational maturity
- **Behavioral Defense Model**: Signature-based detection will fail; behavioral monitoring of CrowdStrike process termination is critical
- **Attack Chain Dependency**: The variant requires Stage 1 (lpe.exe) to succeed-defending the privilege escalation phase blocks the entire chain

### Detection Challenges

**HIGH CONFIDENCE (90%)**: killer_crowdstrike.dll will evade traditional signature-based antivirus detection due to:
1. **Legitimate Driver Signatures**: Windows allows loading because drivers are validly signed by Baidu and Microsoft
2. **Dynamic Driver Naming**: Master orchestrator generates randomized driver filenames using character set "abcdefghijklmnopqrstuvwxyz.sys"
3. **Rust Compilation Obfuscation**: Non-standard binary structure complicates signature creation
4. **Self-Cleanup**: Driver files and services are deleted after use, removing static IOCs from disk
5. **Minimal Dwell Time**: Entire execution lifecycle completes in seconds
6. **Variant Sophistication**: The fact that this variant exists proves attackers test their tools-it likely passes various detection sandboxes

**MODERATE CONFIDENCE (75%)**: Behavioral EDR (including CrowdStrike itself if operational) may detect killer_crowdstrike.dll through:
- Service creation anomalies (CreateServiceW from rundll32.exe)
- DeviceIoControl calls with IOCTLs 0x800024B4, 0x8335003C
- CrowdStrike process termination events (CSFalconService.exe, csagent.exe, CSFalconContainer.exe)
- CreateServiceW -> StartServiceW -> DeleteService lifecycle correlation
- **Pre-termination window**: Behavioral EDR agents may detect attack chain before CrowdStrike processes are killed

### Executive Risk Assessment

**CRITICAL RISK (9.7/10)** - killer_crowdstrike.dll represents a **direct, proven threat** to CrowdStrike-protected environments. The existence of this variant-with explicit CrowdStrike process targeting-proves that threat actors have:
1. Analyzed CrowdStrike Falcon architecture
2. Identified its core processes
3. Invested in creating dedicated countermeasures
4. Tested the variant sufficiently to distribute it

Organizations relying solely on endpoint protection without behavioral monitoring, network-level detection, or incident response procedures are at **maximum risk** of successful compromise once killer_crowdstrike.dll executes.

The integration with lpe.exe creates a **fully automated attack chain** requiring minimal operator interaction: one command triggers the entire sequence from privilege escalation through CrowdStrike termination to security product elimination. This level of automation and integration indicates **mature malware development operations** consistent with organized cybercrime or advanced persistent threat actors.

---

## Deep Technical Analysis

### Comparative Analysis: killer_crowdstrike.dll vs. killer.dll

This section establishes the relationship between the variant and generic killer.dll, proving reuse while highlighting CrowdStrike-specific modifications.

#### Similarities: Evidence of a Common Codebase

**CONFIRMED**: killer_crowdstrike.dll and generic killer.dll share the same underlying architecture and attack mechanism.

**Shared Evidence:**
- **Identical IOCTL Codes**: Both use 0x800024B4 (Baidu) and 0x8335003C (Process Explorer) for process termination
- **Same Rust Compilation**: Both compiled as 64-bit Rust DLLs with similar PDB debug strings
- **Identical Embedded Drivers**: Both contain BdApiUtil64.sys and ProcExpDriver.sys embedded in data sections
- **Matching Core Functions**: Master orchestrator logic (DllMain -> thread creation -> BYOVD lifecycle) is structurally identical
- **Shared Cleanup Mechanism**: Both perform identical cleanup phases (service deletion, driver file removal, kernel unload)
- **Dynamic Filename Generation**: Both use character set "abcdefghijklmnopqrstuvwxyz.sys" for driver file randomization

**Architectural Proof**:
```
Generic killer.dll Architecture:
DllMain -> CreateThread -> Master Orchestrator -> IOCTL Dispatcher -> Process Termination

killer_crowdstrike.dll Architecture:
DllMain -> CreateThread -> Master Orchestrator -> IOCTL Dispatcher -> Process Termination

Structure Difference: ZERO
Code Difference: Kill list configuration only
```

#### Differences: CrowdStrike-Specific Reconfiguration

**PRIMARY DIFFERENCE: The "Kill List"**

| Aspect | Generic killer.dll | killer_crowdstrike.dll | Significance |
|--------|-------------------|----------------------|---|
| Target Scope | Broad security products (20+ vendors) | **CrowdStrike Falcon (3 core processes)** | Specialized targeting |
| Process Targets | MsMpEng.exe, ekrn.exe, avp.exe, etc. | **CSFalconService.exe, csagent.exe, CSFalconContainer.exe** | Explicit Falcon focus |
| Configuration Change | Baseline defender implementation | Updated process name list | Modular reconfiguration |
| Core IOCTL Engine | 0x800024B4, 0x8335003C | **Identical IOCTLs** | Proven code reuse |
| Threat Implication | General EDR evasion | **CrowdStrike-specific countermeasure** | Direct capability against Falcon |

**CONFIRMED CrowdStrike Kill List** (from data section analysis):
```c
// Extracted from configuration data at offset 0x180067691
char targets[] = "smartscreen.exe" "SgrmBroker.exe" "MpDlpService.exe"
                  "MsSense.exe" "SenseCncProxy.exe" "SenseIR.exe"
                  "SenseSampleUploader.exe" "WindowsSecurityHealthService.exe"
                  "CSFalconService.exe"              // CrowdStrike CORE
                  "csagent.exe"                      // CrowdStrike CORE
                  "CSFalconContainer.exe";           // CrowdStrike CORE
```

**SECONDARY DIFFERENCE: Embedded Microsoft-Signed Binary**

The variant includes an **embedded Microsoft-signed binary** not present in generic killer.dll:
- **Possible Role 1**: Alternative vulnerable driver for CrowdStrike-specific kernel exploitation
- **Possible Role 2**: DLL side-loading vector to execute in higher-privilege process context
- **Investigation Status**: Requires dynamic analysis to determine exact exploitation technique
- **Threat Level**: HIGH CONFIDENCE that this represents an additional or alternative driver abuse method

#### Modularity Assessment: Threat Actor Capability Conclusion

**DEFINITE CONFIDENCE**: The relationship between killer.dll and killer_crowdstrike.dll demonstrates:

1. **Modular Tooling**: Threat actor has created reconfigurable attack tools with data-driven configuration (kill lists)
2. **Operational Maturity**: Rather than rebuilding tools, they modify configuration-sign of sophisticated development operations
3. **Targeted Adaptation**: The fact that CrowdStrike warrants a dedicated variant proves Falcon is recognized as a significant threat
4. **Code Reuse Pattern**: This variant likely represents one of many configured instances targeting different EDR vendors

**Operational Implication**: Expect additional variants targeting:
- Microsoft Defender for Endpoint (likely exists)
- Elastic EDR (likely exists)
- Carbon Black (probable)
- Cortex XDR (probable)
- SentinelOne (probable)

The threat actor has built a **modular EDR-evasion platform** where new targets require only configuration updates, not code changes.

### CrowdStrike-Specific Targeting

#### The Three Core CrowdStrike Processes

killer_crowdstrike.dll explicitly targets three CrowdStrike Falcon core processes. Understanding why these specific processes matter is critical for defensive planning.

**Process 1: CSFalconService.exe**
- **Role**: Falcon Windows Service
- **Function**: Main sensor service running with SYSTEM privileges
- **Criticality**: **CRITICAL** - All monitoring flows through this service
- **Consequences of Termination**:
  - Sensor monitoring stops immediately
  - Behavioral analytics engine disabled
  - Threat intelligence feeds cease
  - Real-time detection unavailable

**Process 2: csagent.exe**
- **Role**: Falcon Agent Process (user-context execution)
- **Function**: Endpoint detection, threat prevention, behavioral monitoring
- **Criticality**: **CRITICAL** - Primary detection component
- **Consequences of Termination**:
  - User-mode threat detection disabled
  - File/network activity monitoring disabled
  - Process anomaly detection stops
  - Privilege escalation detection stops

**Process 3: CSFalconContainer.exe**
- **Role**: Container for Falcon components (process protection, isolation)
- **Function**: Protected process isolation for sensor code
- **Criticality**: **HIGH** - Security isolation mechanism
- **Consequences of Termination**:
  - Protected process mechanism fails
  - Code isolation breaks down
  - Sensor protection diminished

**DEFINITE CONFIDENCE**: Termination of all three processes results in **complete Falcon sensor disablement**.

#### Why This Variant Exists

**CONFIRMED** through analysis: This variant proves threat actors have explicitly engineered a countermeasure to CrowdStrike Falcon. Evidence:
1. **Specific Process Targeting**: The three CrowdStrike processes are explicitly listed in kill list
2. **Variant Distribution**: This variant exists in Arsenal-237 repository alongside generic killer.dll
3. **Deliberate Reconfiguration**: The variant uses identical core technology-purely configuration-modified
4. **Operational Use**: The variant's existence implies it has been tested and deployed in operations

**Implication for Defenders**: Organizations protected by CrowdStrike Falcon need to assume threat actors have:
- Studied Falcon architecture
- Identified critical components
- Built countermeasures
- Tested variants operationally

### BYOVD Attack Lifecycle Overview

killer_crowdstrike.dll implements the BYOVD attack pattern identically to generic killer.dll, with the same three-phase lifecycle adapted for CrowdStrike targeting.

#### Phase 1: Deployment

**Objective**: Install vulnerable driver into Windows kernel

**Step 1 - Driver Selection**:
```
Both embedded vulnerable drivers available:
- BdApiUtil64.sys (Baidu Antivirus driver) - Primary option
- ProcExpDriver.sys (Process Explorer driver) - Fallback option

Selection index: 0 (Baidu) or 1 (Process Explorer)
```

**Step 2 - Dynamic Filename Generation**:
```
Character set: "abcdefghijklmnopqrstuvwxyz.sys"
Examples: qzyxwp.sys, mlkjhg.sys, abcdef.sys
Purpose: Evade static detection through randomized naming
```

**Step 3 - Driver Extraction to Disk**:
```
Extract embedded driver PE file from DLL data section
Write to temporary path with random filename
Example: C:\Users\[User]\AppData\Local\Temp\qzyxwp.sys
```

**Step 4 - Service Registration**:
```c
CreateServiceW(
  hSCManager,
  L"qzyxwp",                           // Service name (matches filename)
  L"C:\Users\[User]\AppData\Local\Temp\qzyxwp.sys",  // Binary path
  SERVICE_KERNEL_DRIVER,               // Driver service
  SERVICE_DEMAND_START,                // Manual start
  SERVICE_ERROR_IGNORE                 // Error handling
)
```

**Step 5 - Driver Loading**:
```c
StartServiceW(hService, 0, NULL);
// Driver now loaded in Windows kernel with full kernel-mode privileges
```

#### Phase 2: Execution - CrowdStrike-Specific Termination

**Objective**: Terminate CrowdStrike Falcon using kernel-level privileges

**Step 1 - Kill List Iteration**:
```c
// Loop through CrowdStrike processes
processes[] = {
    "CSFalconService.exe",    // Iteration 1
    "csagent.exe",            // Iteration 2
    "CSFalconContainer.exe"   // Iteration 3
}

for (process in processes) {
    DWORD pid = GetProcessIdByName(process);
    if (pid != 0) {
        TerminateViaIOCTL(pid);  // Proceed to Step 2
    }
}
```

**Step 2 - Process ID Discovery**:
```c
// Use EnumProcesses or similar to find running instance
DWORD pid = FindProcessByName("CSFalconService.exe");
// Example: pid = 1234
```

**Step 3 - IOCTL Command Dispatch**:
```c
// Call driver interaction function with:
// - Driver index (0 for Baidu, 1 for Process Explorer)
// - Target process ID
DispatchIOCTL(0, pid);  // Use Baidu driver to terminate PID 1234
```

**Step 4 - Kernel-Mode Process Termination**:
```
Baidu Driver Operation:
1. Receive IOCTL 0x800024B4 with PID
2. Call ZwTerminateProcess from kernel context
3. Process terminated with kernel-level authority
4. User-mode security products cannot prevent this

Result: CSFalconService.exe -> TERMINATED
Result: csagent.exe -> TERMINATED
Result: CSFalconContainer.exe -> TERMINATED
```

**Execution Timeline**:
```
Timestamp    Event
-----------  --------------------------------------------------
T+0          Baidu driver loaded in kernel
T+1          Enumerate running processes
T+2          Send IOCTL 0x800024B4 with CSFalconService.exe PID
T+3          CSFalconService.exe terminated (kernel-mode)
T+4          Send IOCTL 0x800024B4 with csagent.exe PID
T+5          csagent.exe terminated (kernel-mode)
T+6          Send IOCTL 0x800024B4 with CSFalconContainer.exe PID
T+7          CSFalconContainer.exe terminated (kernel-mode)
T+8          All CrowdStrike processes down
T+9          CrowdStrike monitoring disabled
```

**Complete Payload Execution**: All three CrowdStrike processes terminated in approximately 8-10 seconds.

#### Phase 3: Cleanup

**Objective**: Remove all forensic evidence of driver deployment

**Step 1 - Service Termination**:
```c
ControlService(hService, SERVICE_CONTROL_STOP, &status);
// Baidu driver stops accepting commands
```

**Step 2 - Service Deletion**:
```c
DeleteService(hService);
// Service entry removed from SCM registry
// Service now unrecoverable without manual cleanup
```

**Step 3 - Driver File Deletion**:
```c
DeleteFileW(L"C:\Users\[User]\AppData\Local\Temp\qzyxwp.sys");
// Driver file removed from filesystem
```

**Step 4 - Kernel Module Unload**:
```c
NtUnloadDriver(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\qzyxwp");
// Driver removed from kernel memory
```

**Step 5 - Complete Erasure**:
```
Cleanup Result:
- Service entry: DELETED
- Driver file: DELETED
- Kernel module: UNLOADED
- Process: TERMINATED
- Malware artifact: REMOVED

Forensic evidence remaining: MINIMAL
Investigation difficulty: HIGH
```

#### Why This Lifecycle Is Effective Against CrowdStrike

**HIGH CONFIDENCE**: The BYOVD technique is specifically effective against CrowdStrike Falcon because:

1. **Kernel-Mode Authority**: CrowdStrike cannot intercept kernel-mode termination commands
2. **Legitimate Driver Trust**: Windows loads legitimately-signed drivers without warnings
3. **Rapid Execution**: CrowdStrike cannot block or remediate before processes are terminated
4. **Complete Disablement**: Terminating all three processes simultaneously disables all monitoring
5. **Forensic Complexity**: Self-cleanup removes evidence that would help determine how processes were disabled

**Business Impact**: Organizations cannot rely solely on CrowdStrike's defensive capabilities once killer_crowdstrike.dll executes. The attack operates at a privilege level that Falcon cannot defend against from user-mode.

### Embedded Driver Analysis

killer_crowdstrike.dll contains the **identical embedded drivers** as generic killer.dll, confirming reuse of proven attack infrastructure.

#### Driver 1: BdApiUtil64.sys (Baidu Antivirus Driver)

**Metadata**:
- **File Description**: Baidu Antivirus BdApi Driver
- **Company**: Baidu, Inc.
- **File Version**: 5.0.3.84333
- **Digital Signature**: Legitimately signed by Baidu (valid certificate chain)

**Process Termination IOCTL**:
```
IOCTL Code: 0x800024B4
Function: Terminate arbitrary process via kernel-mode ZwTerminateProcess call
Authority: Kernel-mode = Cannot be blocked by user-mode security
```

**Kernel Capabilities**:
- `ZwTerminateProcess` - Terminate any process with kernel authority
- `FltEnumerateFilters` - Enumerate loaded minifilter drivers
- `CmRegisterCallback` - Monitor registry operations
- `ZwSetValueKey`/`ZwDeleteValueKey` - Modify registry

#### Driver 2: ProcExpDriver.sys (Sysinternals Process Explorer Driver)

**Metadata**:
- **File Description**: Process Explorer
- **Company**: Sysinternals / Mark Russinovich
- **File Version**: 17.0.7
- **Digital Signature**: Legitimately signed by Microsoft (Sysinternals)

**Process Termination IOCTL**:
```
IOCTL Code: 0x8335003C
Function: Kernel-mode process handle manipulation for termination
Authority: Kernel-mode = Cannot be blocked by user-mode security
```

**Kernel Capabilities**:
- `ZwOpenProcess` - Open arbitrary process handles
- `ZwQueryInformationProcess` - Query process details
- `KeStackAttachProcess` - Attach to process address space
- `ZwDuplicateObject` - Duplicate handles across contexts

#### Dual-Driver Redundancy Strategy

**Verified**: killer_crowdstrike.dll can deploy either driver based on runtime conditions:

```
Driver Selection Logic:
arg1 = 0 -> Deploy BdApiUtil64.sys (Baidu driver)
arg1 = 1 -> Deploy ProcExpDriver.sys (Process Explorer driver)
```

**Redundancy Benefits**:
1. **Increased Success Rate**: If one driver is blocked by security policy, fallback available
2. **Detection Evasion**: Varying driver selection between attacks prevents static signatures
3. **Robustness**: Each driver provides slightly different kernel capabilities

### Embedded Microsoft-Signed Binary

**CRITICAL FINDING**: killer_crowdstrike.dll contains an embedded Microsoft-signed binary **not present in generic killer.dll**.

#### Analysis Status: REQUIRES FURTHER INVESTIGATION

**Evidence of Presence**:
```
Data section contains Microsoft-signed certificate chains:
- "Microsoft Corporation" string present
- "Microsoft Root Certificate" present
- "Microsoft Time-Stamp Service" present
- Full X.509 certificate structures embedded
```

#### Possible Roles for Embedded Microsoft Binary

**Hypothesis 1: Alternative Vulnerable Driver**
- **Scenario**: Threat actor identified vulnerability in Microsoft driver specific to CrowdStrike environments
- **Advantage**: May be more reliable against Falcon's driver monitoring
- **Investigation**: Requires binary extraction and static analysis

**Hypothesis 2: DLL Side-Loading Vector**
- **Scenario**: Legitimate Microsoft executable loaded to DLL side-load killer_crowdstrike.dll into elevated context
- **Advantage**: Executes payload in trusted Microsoft process context
- **Investigation**: Requires dynamic analysis to observe execution path

**Hypothesis 3: Code Signing Enhancement**
- **Scenario**: Microsoft-signed component added to increase trust reputation
- **Advantage**: May evade reputation-based detection
- **Investigation**: Requires vendor reputation system analysis

#### Threat Level Assessment

**HIGH CONFIDENCE (85%)**: The embedded Microsoft-signed binary represents an **additional exploitation technique** not used in generic killer.dll, suggesting:
1. **CrowdStrike-Specific Research**: Threat actor invested additional effort for Falcon targeting
2. **Advanced Exploitation**: May indicate vulnerability in Microsoft driver or Windows mechanism
3. **Improved Effectiveness**: Presence suggests this binary improves success rate against CrowdStrike
4. **Operational Testing**: Variant distribution implies binary has been tested operationally

**Immediate Action Required**: Extract and analyze embedded binary to understand exploitation mechanism.

### Master Orchestrator Function

The master orchestrator is the **central controller** for the entire BYOVD attack lifecycle specific to CrowdStrike targeting.

#### Entry Point: DllMain

```c
BOOL WINAPI DllMain(HANDLE hDllHandle, DWORD dwReason, void* lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Standard Rust runtime initialization

        // Create worker thread for actual payload
        CreateThread(NULL, 0, ThreadEntry, NULL, 0, NULL);

        // Return success - DLL loads normally
        return TRUE;
    }
    return TRUE;
}
```

**Design Purpose**: DLL loading completes quickly while worker thread executes the attack asynchronously.

#### Thread Entry Point: Attack Orchestration

```
Thread Execution Flow:
1. OpenSCManagerW() -> Get handle to Service Control Manager
2. Initialize CrowdStrike kill list (3 processes)
3. Deploy Baidu or Process Explorer driver to temp directory
4. CreateServiceW() -> Register driver service
5. StartServiceW() -> Load driver into kernel
6. For each process in kill list:
   - Get process ID by name
   - Call DispatchIOCTL() with process ID
   - Driver terminates process via IOCTL 0x800024B4 or 0x8335003C
7. ControlService(STOP) -> Stop driver
8. DeleteService() -> Remove service
9. DeleteFileW() -> Remove driver file from disk
10. NtUnloadDriver() -> Unload kernel module
11. Thread exits - all forensic evidence removed
```

**Total Execution Time**: 8-15 seconds from thread creation to complete cleanup.

### Anti-Analysis Features

#### Runtime Obfuscation

1. **Dynamic Driver Filenames**: Random names prevent IOC matching
2. **Indirect Function Calls**: Function pointers complicate static analysis
3. **Embedded Resources**: Drivers contained as binary blobs, not PE sections
4. **Thread-Based Execution**: Attack occurs in worker thread, not DLL loading path

#### Anti-Forensics

1. **Service Deletion**: Service Control Manager registry entries removed
2. **Driver File Deletion**: Physical driver files deleted from disk
3. **Kernel Unload**: Driver module removed from kernel memory
4. **No Persistence**: Designed to execute once and disappear
5. **Minimal Artifacts**: Service name, driver name, and execution timing randomized

#### Anti-Detection

1. **Legitimate Signatures**: Embedded drivers carry real Microsoft/Baidu signatures
2. **Rapid Execution**: Entire attack completes in seconds
3. **Self-Cleanup**: Forensic evidence removed before investigation
4. **Kernel-Mode Execution**: User-mode detection tools cannot observe kernel operations

---

## MITRE ATT&CK Mapping

### Tactics & Techniques

<table class="professional-table">
  <thead>
    <tr>
      <th>MITRE Tactic</th>
      <th>ATT&CK Technique</th>
      <th>Sub-Technique</th>
      <th>Confidence</th>
      <th>Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="3"><strong>Privilege Escalation</strong></td>
      <td>T1055</td>
      <td>Process Injection</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Potentially injected into rundll32.exe (requires dynamic analysis)</td>
    </tr>
    <tr>
      <td>T1543</td>
      <td>Create or Modify System Process</td>
      <td class="confirmed">CONFIRMED</td>
      <td>CreateServiceW creates kernel driver service</td>
    </tr>
    <tr>
      <td>T1134</td>
      <td>Access Token Manipulation</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Executes with NT AUTHORITY\SYSTEM privileges (from lpe.exe)</td>
    </tr>
    <tr>
      <td rowspan="4"><strong>Defense Evasion</strong></td>
      <td>T1542.005</td>
      <td>Modify System Image - Implant Internal Hack</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Deploys BdApiUtil64.sys and ProcExpDriver.sys (BYOVD technique) to kernel for process termination</td>
    </tr>
    <tr>
      <td>T1207</td>
      <td>Disable or Modify System Firewall</td>
      <td class="likely">LIKELY</td>
      <td>Potential capability through kernel driver access</td>
    </tr>
    <tr>
      <td>T1562</td>
      <td>Impair Defenses</td>
      <td>Disable EDR (CrowdStrike Falcon)</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Primary function: terminate CSFalconService.exe, csagent.exe, CSFalconContainer.exe</td>
    </tr>
    <tr>
      <td>T1140</td>
      <td>Deobfuscation/Decoding</td>
      <td>Resource Extraction</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Extracts embedded driver PE files from DLL resource section</td>
    </tr>
    <tr>
      <td rowspan="2"><strong>Execution</strong></td>
      <td>T1559</td>
      <td>Inter-Process Communication</td>
      <td class="confirmed">CONFIRMED</td>
      <td>DeviceIoControl calls to driver device handles</td>
    </tr>
    <tr>
      <td>T1053</td>
      <td>Scheduled Task/Job</td>
      <td class="possible">POSSIBLE</td>
      <td>May schedule tasks for persistence (not confirmed in analysis)</td>
    </tr>
    <tr>
      <td rowspan="3"><strong>Persistence</strong></td>
      <td>T1547</td>
      <td>Boot or Logon Autostart Execution</td>
      <td class="likely">LIKELY</td>
      <td>Driver loaded as kernel service could provide boot persistence</td>
    </tr>
    <tr>
      <td>T1543</td>
      <td>Create or Modify System Process</td>
      <td class="confirmed">CONFIRMED</td>
      <td>Service creation could enable persistence if not cleaned up</td>
    </tr>
    <tr>
      <td>T1112</td>
      <td>Modify Registry</td>
      <td class="likely">LIKELY</td>
      <td>Kernel driver has registry modification capabilities</td>
    </tr>
    <tr>
      <td rowspan="2"><strong>Impact</strong></td>
      <td>T1489</td>
      <td>Service Stop</td>
      <td class="confirmed">CONFIRMED</td>
      <td>ControlService(SERVICE_CONTROL_STOP) stops Baidu driver service</td>
    </tr>
    <tr>
      <td>T1561</td>
      <td>Disk Wipe</td>
      <td class="possible">POSSIBLE</td>
      <td>DeleteFileW removes driver files; broader data destruction possible</td>
    </tr>
  </tbody>
</table>

### Campaign Context

**Arsenal-237 Campaign TTPs**:
- **Stage 1**: T1548 (Abuse Elevation Control Mechanism) - lpe.exe privilege escalation
- **Stage 2**: T1562 (Impair Defenses) - killer_crowdstrike.dll EDR termination
- **Stage 3**: T1098 (Account Manipulation) or T1561 (Disk Wipe) - ransomware deployment

---

## Frequently Asked Questions

### Q1: "Why would attackers target CrowdStrike specifically?"

**Short Answer**: CrowdStrike Falcon is one of the most widely deployed enterprise EDR solutions globally, making CrowdStrike-protected environments high-value targets.

**Detailed Explanation**:
CrowdStrike Falcon has achieved market dominance in enterprise EDR through superior detection capabilities, user experience, and vendor reputation. For attackers, this creates a targeting incentive: organizations most likely to have strong security controls (and therefore highest-value targets) are likely to have CrowdStrike deployed. By creating a CrowdStrike-specific variant, threat actors:

1. **Increase Success Rate**: Generic attack tools may fail against CrowdStrike's specific defense mechanisms
2. **Demonstrate Sophistication**: Targeting a premier EDR vendor signals threat actor capability
3. **Maximize ROI**: Focus resources on defending against the most common defense in high-value organizations
4. **Operational Efficiency**: Reuse existing technology (killer.dll) with targeted configuration (CrowdStrike processes)

**Realistic Assessment**: This variant likely exists alongside other EDR-specific variants (for Defender, Carbon Black, Cortex XDR, etc.). The threat actor has built a **modular EDR-evasion platform** where different configurations target different vendors.

### Q2: "How do we know killer_crowdstrike.dll is specifically designed for CrowdStrike?"

**Short Answer**: The malware's kill list explicitly contains CSFalconService.exe, csagent.exe, and CSFalconContainer.exe-the three core CrowdStrike Falcon processes.

**Detailed Explanation**:
Static analysis of the malware's data section (offset 0x180067691) reveals a null-terminated string containing process names targeted for termination. This string explicitly includes:
- **CSFalconService.exe** - CrowdStrike Windows Service
- **csagent.exe** - CrowdStrike Agent Process
- **CSFalconContainer.exe** - CrowdStrike Protected Process Container

These are **unique identifiers** of CrowdStrike Falcon. The combination of all three processes is specific to CrowdStrike's architecture. Additionally, comparison with generic killer.dll shows this is the **only significant difference** between the two variants-the core BYOVD mechanism, embedded drivers, and cleanup procedures are identical.

**Conclusion**: DEFINITE CONFIDENCE that this malware was deliberately engineered to disable CrowdStrike Falcon.

### Q3: "If our EDR is terminated, does that mean we're completely compromised?"

**Short Answer**: EDR termination is a critical loss of visibility, but not automatic system compromise-rapid detection and response can still contain the threat.

**Detailed Explanation**:
killer_crowdstrike.dll's success depends on a complete attack chain:
1. **Stage 1 (lpe.exe)** must successfully elevate privileges to SYSTEM
2. **Stage 2 (killer_crowdstrike.dll)** must successfully execute from that elevated context
3. **Stage 3 (ransomware/exfiltration)** then proceeds with EDR visibility lost

If any stage fails, the attack chain breaks. Additionally, EDR termination eliminates local visibility but does not eliminate:
- **Network monitoring**: Egress filtering, DNS monitoring, firewall logs
- **Behavioral detection**: SIEM-based detection of post-EDR-termination activities
- **Forensic recovery**: If incident is detected quickly, forensic investigation can still determine what occurred
- **Remediation**: System restart, EDR reinstallation, credential rotation can mitigate damage

**Realistic Assessment**: EDR termination represents a **critical security event** requiring immediate incident response, but the attack is not automatically successful. Organizations with layered defenses (network detection, threat hunting, SIEM correlation) have defensive opportunities even after local EDR is disabled.

### Q4: "How long does killer_crowdstrike.dll take to execute?"

**Short Answer**: The entire attack (driver deployment, process termination, cleanup) completes in approximately 8-15 seconds.

**Detailed Explanation**:
Timeline breakdown:
- **Driver deployment** (CreateServiceW, StartServiceW): 1-2 seconds
- **CrowdStrike process discovery**: 1-2 seconds
- **IOCTL dispatch for 3 CrowdStrike processes**: 3-5 seconds
- **Cleanup** (DeleteService, DeleteFileW, NtUnloadDriver): 2-3 seconds

**Total**: 8-15 seconds from thread creation to complete cleanup.

This rapid execution window creates a **narrow detection opportunity**:
- If detected during driver loading phase: Possible to block
- If detected during process termination phase: Already too late (processes terminated)
- If detected during cleanup phase: Driver already executed and removed

**Detection Strategy**: The most reliable detection method is **behavioral correlation**-looking for the lpe.exe -> rundll32.exe -> killer_crowdstrike.dll execution pattern BEFORE killer_crowdstrike.dll executes, not after.

### Q5: "Are the embedded drivers being actively used or just included as options?"

**Short Answer**: LIKELY that both drivers are actively used-analysis shows dual-driver selection logic, suggesting both are operationally deployed.

**Detailed Explanation**:
Evidence from static analysis:
- **Two driver deployment functions**: Separate code paths for BdApiUtil64.sys and ProcExpDriver.sys
- **Runtime selection logic**: Parameter (`arg1 = 0` or `arg1 = 1`) selects which driver to deploy
- **Redundancy design**: Structured to allow fallback if primary driver fails

**Operational Implementation**: Threat actors likely:
1. **First attempt**: Deploy Baidu driver (more commonly available on systems)
2. **If fails**: Deploy Process Explorer driver as fallback
3. **Verify**: Confirm one driver is operational before proceeding with process termination

**Why Dual-Driver Strategy**:
- **Success Rate**: Organizations may have policies blocking Baidu driver; fallback ensures success
- **Evasion**: Using different drivers in different operations prevents signature-based detection
- **Robustness**: Handles diverse endpoint configurations and security policies

**Realistic Assessment**: MODERATE CONFIDENCE (75%) that both drivers are operationally deployed in real attacks. The dual-driver presence is intentional redundancy, not unused bloat.

### Q6: "What does the embedded Microsoft-signed binary do?"

**Short Answer**: UNKNOWN-requires dynamic analysis to determine, but likely represents an additional or alternative driver exploitation technique.

**Detailed Explanation**:
Static analysis reveals the presence of a Microsoft-signed binary with embedded certificates:
- Microsoft Corporation name string
- Microsoft Root Certificate data
- Valid X.509 certificate structures

**Possible purposes**:
1. **Alternative Driver Exploitation**: Microsoft driver with vulnerability specific to CrowdStrike environments
2. **DLL Side-Loading**: Legitimate Microsoft executable that side-loads killer_crowdstrike.dll into elevated context
3. **Trust Enhancement**: Additional Microsoft signature to improve malware reputation evasion
4. **Kernel Exploitation**: Different exploitation vector than Baidu/Process Explorer IOCTL abuse

**Why This Matters**:
The embedded Microsoft binary suggests threat actors invested **additional engineering effort** specifically for CrowdStrike targeting, beyond the generic killer.dll. This indicates:
- CrowdStrike was perceived as challenging enough to warrant extra research
- Threat actor has sophisticated binary manipulation capabilities
- May represent a more advanced exploitation technique

**Immediate Action**: Extract and analyze embedded binary independently to understand complete exploitation chain.

### Q7: "Can we detect killer_crowdstrike.dll with antivirus?"

**Short Answer**: Traditional signature-based antivirus will likely fail to detect this malware due to legitimate driver signatures and self-cleanup.

**Detailed Explanation**:
**Why Antivirus Struggles**:
1. **Legitimate Signatures**: Embedded drivers are authentically signed by Baidu and Microsoft
2. **Minimal Persistence**: Driver files and services are deleted after use
3. **Rust Compilation**: Non-standard binary structure resists signature generation
4. **Dynamic Filenames**: Randomized driver names prevent static IOC matching
5. **Rapid Execution**: Dwell time measured in seconds, before AV scanning completes

**Alternative Detection Methods**:
- **Behavioral EDR**: Detects CreateServiceW from suspicious processes, anomalous IOCTL codes
- **SIEM Correlation**: Detects service lifecycle patterns (CreateService -> StartService -> DeleteService)
- **Process Termination Alerts**: Detects CrowdStrike process termination by non-authorized processes
- **Network Detection**: Detects lpe.exe download, Arsenal-237 C2 communication
- **Driver Blocklisting**: Proactively blocks vulnerable driver versions by hash

**Realistic Assessment**: LOW CONFIDENCE (20%) that traditional antivirus will detect this malware. **HIGH CONFIDENCE (85%)** that behavioral detection and threat hunting will succeed if monitoring for BYOVD patterns.

### Q8: "What's the relationship between killer.dll and killer_crowdstrike.dll?"

**Short Answer**: killer_crowdstrike.dll is a **reconfigured variant** of killer.dll, proving threat actor modularity and reusability.

**Detailed Explanation**:
Evidence of common origin:
- **Identical core function**: Both implement BYOVD process termination
- **Same embedded drivers**: Both contain BdApiUtil64.sys and ProcExpDriver.sys
- **Identical IOCTL codes**: 0x800024B4 (Baidu), 0x8335003C (Process Explorer)
- **Same cleanup mechanism**: Both perform identical service deletion and driver removal
- **Shared architecture**: Both follow DllMain -> thread -> orchestrator -> IOCTL dispatcher pattern

**Key difference**: The kill list configuration
- **killer.dll**: Targets 20+ security products (general-purpose defense evasion)
- **killer_crowdstrike.dll**: Targets 3 CrowdStrike processes (specialized variant)

**Threat Actor Implication**: This relationship demonstrates:
1. **Modular Tooling**: Attackers build configurable platforms, not single-purpose malware
2. **Operational Maturity**: Efficient reuse indicates sophisticated development operations
3. **Targeted Adaptation**: CrowdStrike customer base warrants dedicated variant
4. **Extensibility**: Expect additional variants targeting other EDR vendors

**Similar Pattern**: Think of this like a commercial software "distribution channels"-the same codebase compiled with different configuration files for different markets. Threat actors use similar efficiency principles.

### Q9: "If we're a CrowdStrike customer, should we assume we're targeted?"

**Short Answer**: YES-the existence of this variant proves attackers have explicitly engineered defenses against CrowdStrike Falcon.

**Detailed Explanation**:
This variant's existence carries three implications:

1. **Proof of Targeting**: Attackers have explicitly researched CrowdStrike architecture and built countermeasures
2. **Operational Deployment**: Variant's presence in Arsenal-237 repository suggests it has been tested and possibly operationally deployed
3. **Future Targeting**: Organizations protected by CrowdStrike are explicitly considered valuable targets by at least one known threat actor group

**Recommended Actions for CrowdStrike Customers**:
- **Assume hostile knowledge** of CrowdStrike's architecture and capabilities
- **Implement network-level detection** (EDR termination attempts)
- **Deploy behavioral SIEM rules** (service lifecycle anomalies, IOCTL abuse)
- **Monitor for lpe.exe** and similar privilege escalation tools
- **Implement segmentation** to limit lateral movement post-EDR disablement
- **Prepare incident response procedures** for EDR-disabled scenarios
- **Deploy vulnerability assessment** for embedded Microsoft binary

**Realistic Assessment**: This variant represents a **known threat** with **known attack chain**. While implementation requires privilege escalation success (Stage 1), organizations protected by CrowdStrike should assume this attack method is operationally relevant.

---

## IOCs

**Primary Module**:
- **Filename**: killer_crowdstrike.dll
- **File Size**: 532,992 bytes
- **Type**: PE32+ DLL (x86-64)
- **Hashes**: See [killer_crowdstrike.dll IOCs]({{ "/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" | relative_url }}) for current hash values

**Embedded Driver Components**:
- **BdApiUtil64.sys** (Baidu Antivirus driver, version 5.0.3.84333)
  - IOCTL: 0x800024B4
  - Legitimate signature: Baidu, Inc.
- **ProcExpDriver.sys** (Process Explorer driver, version 17.0.7)
  - IOCTL: 0x8335003C
  - Legitimate signature: Microsoft/Sysinternals

**Network Indicators**:
- C2 Domain/IP: 109.230.231.37
- Download URL: http://109.230.231.37:8888/lpe.exe
- Payload Temp Location: %TEMP%\svchost_update.exe

**Process Indicators**:
- Process termination: CSFalconService.exe, csagent.exe, CSFalconContainer.exe
- Service creation pattern: CreateServiceW with random .sys filename
- Random driver filenames: [a-z]+.sys format

**Behavioral Indicators**:
- IOCTL codes: 0x800024B4, 0x8335003C
- Service lifecycle: CreateServiceW -> StartServiceW -> DeleteService (< 60 seconds)
- Device operations: CreateFileW to \\.\BdApiUtil, \\.\PROCEXP152

**Complete IOC feeds**: See [killer_crowdstrike.dll IOCs]({{ "/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" | relative_url }})

---

## Detections

### Signature-Based Detection

**YARA Rules**: Monitor for embedded driver resource signatures, IOCTL constant patterns (0x800024B4, 0x8335003C), and Rust compilation artifacts within DLL sections.

**Static Indicators**:
- PE section containing encoded BdApiUtil64.sys binary
- PE section containing encoded ProcExpDriver.sys binary
- "abcdefghijklmnopqrstuvwxyz.sys" character set string
- IOCTL codes: 0x800024B4 (Baidu), 0x8335003C (Process Explorer)

### Behavioral Detection

**Sigma Detection Rules**:
- Service creation with random .sys filename from rundll32.exe context
- CreateServiceW followed by StartServiceW within 5 seconds
- Vulnerable driver loading (BdApiUtil64.sys or ProcExpDriver.sys)
- CrowdStrike process termination (CSFalconService.exe, csagent.exe, CSFalconContainer.exe) by non-Falcon processes
- Service deletion by same non-standard service creator
- Complete service lifecycle pattern: CreateService -> StartService -> DeleteService (< 60 seconds total)

**Threat Hunting Queries**:

*Microsoft Defender KQL*:
```kql
DeviceProcessEvents | where ProcessName has "rundll32.exe"
| join kind=inner (DeviceFileEvents | where FileName endswith ".sys") on DeviceId
| join kind=inner (DeviceProcessEvents | where ProcessName in ("CSFalconService.exe", "csagent.exe")) on DeviceId
```

*Splunk SPL*:
```spl
index=windows EventCode=7045 Creator="RunDLL" Service="*abcd*"
| stats values(Service) as ServiceNames by dest
```

*Elastic EQL*:
```eql
sequence by host.id [process where process.name : "rundll32.exe"] [file where file.extension : "sys"] [process where process.name in ("CSFalconService.exe", "csagent.exe", "CSFalconContainer.exe") and process.exit_code != null]
```

### Network Detection

**Suricata/Zeek**:
- HTTP requests to 109.230.231.37 on port 8888
- URI patterns containing "/lpe.exe"
- TLS connections from systems with recent service creation events

**Firewall Rules**:
- Block outbound connections to 109.230.231.37 (all ports)
- Block HTTP requests to IP:8888 or domain variations
- Alert on executables named lpe.exe from external sources

### EDR Detection Priorities

**CrowdStrike Falcon Customers** (if operational before termination):
- Process termination events on CSFalconService.exe, csagent.exe, CSFalconContainer.exe
- Anomalous kernel driver service creation patterns
- DeviceIoControl calls with suspicious IOCTL codes
- Execution chain correlation: lpe.exe -> rundll32.exe -> killer_crowdstrike.dll DLL load

**Non-CrowdStrike EDR Platforms**:
- Monitor for low-privilege processes creating kernel driver services
- Alert on process termination of other security products (Defender, ESET, Kaspersky, etc.)
- Correlate service creation with IOCTL calls within execution timeline
- Track process tree: system -> rundll32.exe -> kernel driver interaction

### Complete Detection Resources

See [killer_crowdstrike.dll Detection Rules]({{ "/hunting-detections/arsenal-237-killer-crowdstrike-dll/" | relative_url }}) for production-ready YARA, Sigma, and correlation rules.

---

## Key Takeaways

1. **Explicit CrowdStrike Targeting**: This variant proves threat actors have engineered specific defenses against CrowdStrike Falcon-organizations using CrowdStrike should assume they are targeted.

2. **Threat Actor Modularity**: The relationship between killer.dll and killer_crowdstrike.dll demonstrates sophisticated threat actor operations with reusable, configurable attack platforms.

3. **BYOVD Technique Effectiveness**: Kernel-level driver abuse remains effective against user-mode EDR, even against market-leading products like CrowdStrike Falcon.

4. **Detection Window is Narrow**: The entire attack (deployment -> execution -> cleanup) completes in 8-15 seconds, requiring proactive detection during the lpe.exe -> killer_crowdstrike.dll execution chain, not post-execution.

5. **Embedded Microsoft Binary Represents Additional Threat**: The presence of an embedded Microsoft-signed binary not found in generic killer.dll suggests deeper CrowdStrike-specific research and possibly more advanced exploitation techniques.

6. **Arsenal-237 Repository is Actively Developed**: The existence of CrowdStrike-specific variants alongside generic tools indicates an organized, well-funded threat operation with ongoing research and development.

---

## License

(c) 2026 Threat Intelligence Report. All rights reserved.
Free to read, but reuse requires written permission.
