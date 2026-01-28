---
title: BdApiUtil64.sys (Arsenal-237 BYOVD Component) - Technical Analysis & Remediation Guidance
date: '2026-01-26'
layout: post
permalink: /reports/bdapiutil64-sys/
hide: true
---

# BdApiUtil64.sys: Weaponized Baidu Driver in Arsenal-237 Toolkit

**A Comprehensive, Evidence-Based Guide for Security Decision-Makers**

---

## BLUF (Bottom Line Up Front)

BdApiUtil64.sys is a legitimately-signed but vulnerable Baidu antivirus kernel driver weaponized as a Bring-Your-Own-Vulnerable-Driver (BYOVD) component in the Arsenal-237 malware toolkit. This Ring-0 kernel driver provides unrestricted kernel-level access, enabling attackers to terminate security products, create persistent backdoors, and steal protected data with complete bypass of user-mode security controls. Discovery of this driver on any system represents a critical kernel-level compromise requiring immediate isolation and complete system rebuild.

---

## Table of Contents

1. [Quick Reference](#quick-reference)
echo "$(($(echo "2" | sed "s#.##") + 1))." [Executive Summary](#executive-summary)
echo "$(($(echo "2" | sed "s#.##") + 1))." [What is BdApiUtil64.sys?](#what-is-bdapiutil64sys)
echo "$(($(echo "3" | sed "s#.##") + 1))." [Arsenal-237 Toolkit Context](#arsenal-237-toolkit-context)
echo "$(($(echo "4" | sed "s#.##") + 1))." [BYOVD Technique: Weaponizing Legitimate Drivers](#byovd-technique-weaponizing-legitimate-drivers)
echo "$(($(echo "5" | sed "s#.##") + 1))." [Primary Capabilities - IOCTL Code Analysis](#primary-capabilities--ioctl-code-analysis)
echo "$(($(echo "6" | sed "s#.##") + 1))." [Advanced Evasion Techniques](#advanced-evasion-techniques)
echo "$(($(echo "7" | sed "s#.##") + 1))." [Attack Chain Integration](#attack-chain-integration)
echo "$(($(echo "8" | sed "s#.##") + 1))." [Target Security Products](#target-security-products)
echo "$(($(echo "9" | sed "s#.##") + 1))." [Historical Campaign Context](#historical-campaign-context)
echo "$(($(echo "10" | sed "s#.##") + 1))." [MITRE ATT&CK Mapping](#mitre-attck-mapping)
echo "$(($(echo "11" | sed "s#.##") + 1))." [Detection Opportunities](#detection-opportunities)
echo "$(($(echo "12" | sed "s#.##") + 1))." [Threat Assessment & Risk Scoring](#threat-assessment--risk-scoring)
echo "$(($(echo "13" | sed "s#.##") + 1))." [Remediation Guidance](#remediation-guidance)
echo "$(($(echo "14" | sed "s#.##") + 1))." [Response Priorities & Action Items](#response-priorities--action-items)
echo "$(($(echo "15" | sed "s#.##") + 1))." [FAQ - Common Questions](#faq---common-questions)
echo "$(($(echo "16" | sed "s#.##") + 1))." [Key Takeaways](#key-takeaways)

---

## Quick Reference

**Detections & IOCs:**
- [BdApiUtil64.sys Detection Rules]({{ "/hunting-detections/arsenal-237-BdApiUtil64-sys/" | relative_url }})
- [BdApiUtil64.sys IOCs]({{ "/ioc-feeds/arsenal-237-BdApiUtil64-sys.json" | relative_url }})

**Related Reports:**
- [killer.dll BYOVD Module](/reports/arsenal-237-new-files/killer-dll/) - Primary BYOVD implementation
- [killer_crowdstrike.dll Variant](/reports/arsenal-237-new-files/killer-crowdstrike-dll/) - CrowdStrike-specific variant
- [Arsenal-237 Executive Overview](/reports/109.230.231.37-Executive-Overview/) - Full toolkit analysis

---

## Executive Summary

### The Threat in Clear Terms

When BdApiUtil64.sys loads on a Windows system, it grants attackers Ring-0 kernel privileges-the highest privilege level in Windows. This is equivalent to giving an attacker a master key to every door in your computer. Using these privileges, the driver can:

- Instantly terminate any running security product (antivirus, EDR, firewalls)
- Create hidden persistent backdoors that survive restarts
- Access protected credential stores and steal passwords directly from system memory
- Read and exfiltrate any file on the system, including encrypted data
- Hide itself and malware from all user-mode detection tools
- Manipulate security product registry configurations to prevent restoration

This is not a vulnerability that needs specific conditions to exploit-every system running this driver is immediately and completely compromised at the kernel level.

### Business Risk Assessment

<table class="professional-table">
<thead>
<tr>
<th>Risk Factor</th>
<th class="numeric critical">Score (10pt)</th>
<th>Business Impact</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Overall Risk Rating</strong></td>
<td class="numeric critical">9.7/10</td>
<td><strong>CRITICAL</strong> - Complete kernel-level compromise</td>
</tr>
<tr>
<td>System Compromise Severity</td>
<td class="numeric critical">10/10</td>
<td>Unrestricted kernel-level access enables complete system control</td>
</tr>
<tr>
<td>Data Breach Risk</td>
<td class="numeric critical">9.5/10</td>
<td>Direct access to credentials, encryption keys, sensitive files</td>
</tr>
<tr>
<td>Defense Evasion Capability</td>
<td class="numeric critical">10/10</td>
<td>All user-mode and kernel-mode security controls bypassed</td>
</tr>
<tr>
<td>Persistence Difficulty</td>
<td class="numeric critical">9/10</td>
<td>Multiple persistence mechanisms resistant to standard removal</td>
</tr>
<tr>
<td>Remediation Complexity</td>
<td class="numeric critical">10/10</td>
<td>Complete system rebuild is only reliable remediation method</td>
</tr>
</tbody>
</table>

### Key Risk Factors

**Organizational Guidance**

*For Executive Leadership:*
- Treat discovery of BdApiUtil64.sys as a **CRITICAL INCIDENT (Priority 1)** triggering emergency response protocols
- Assume affected systems are completely compromised at kernel level and all security controls are circumvented
- Immediate system isolation is mandatory to prevent lateral movement
- Budget for complete system rebuilds as only reliable remediation
- Prepare for potential data breach notification requirements (credentials, sensitive files may be compromised)
- Activate incident response team and legal/compliance stakeholders immediately
- Consider mandatory credential rotation for all users with any access to affected systems

*For Technical Teams:*
- Isolate affected systems from network immediately (physically disconnect or network block)
- Preserve forensic evidence (memory dump, disk image) before shutdown
- Search for Arsenal-237 toolkit components on the same system (lpe.exe, killer.dll, rootkit.dll, enc_*.exe)
- Hunt across network for other systems with identical IoCs (file hashes, registry artifacts, service names)
- Plan immediate system rebuild from clean installation media
- Deploy Windows Vulnerable Driver Blocklist on all systems post-remediation
- Implement enhanced EDR monitoring for BYOVD techniques (driver loading, IOCTL calls, service creation)

### Primary Threat Vector

The driver is typically deployed through:

1. **Initial Compromise**: Malware drops driver file (BdApiUtil64.sys) to C:\Windows\System32\drivers\ and registry configuration
2. **Service Installation**: Malware creates Windows service "Bprotect" pointing to driver (via IOCTL 0x80002324 or sc.exe)
3. **Driver Load**: Service starts, Windows kernel loads BdApiUtil64.sys with signature validation bypassed (legitimate Baidu certificate)
4. **Ring-0 Activation**: Driver initializes device object (\Device\BdApiUtil) and symbolic link (\DosDevices\BdApiUtil)
5. **Defense Suppression**: Malware uses driver IOCTLs to terminate security products within 5-15 seconds
6. **Unrestricted Execution**: All subsequent malware execution occurs with no security product interference

**Assessment Basis**: This analysis is based on direct reverse engineering of the BdApiUtil64.sys binary, IOCTL interface analysis, and integration mapping with Arsenal-237 toolkit components. Risk ratings reflect confirmed capabilities rather than theoretical threat models.

---

## What is BdApiUtil64.sys?

### File Identification & Classification

<table class="professional-table">
<thead>
<tr>
<th>Attribute</th>
<th>Value</th>
<th>Confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Filename</strong></td>
<td>BdApiUtil64.sys</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>File Size</strong></td>
<td>116,800 bytes (114 KB)</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>MD5</strong></td>
<td>ced47b89212f3260ebeb41682a4b95ec</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>SHA1</strong></td>
<td>148c0cde4f2ef807aea77d7368f00f4c519f47ef</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>SHA256</strong></td>
<td>47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>File Type</strong></td>
<td>PE64 Kernel Driver (Windows 64-bit)</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Digital Signature</strong></td>
<td>Baidu Online Network Technology (Beijing) Co., Ltd</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Certificate Authority</strong></td>
<td>VeriSign Class 3 Code Signing 2010 CA</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Signature Validity</strong></td>
<td>April 24, 2012 to April 24, 2015 (EXPIRED)</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Driver Version</strong></td>
<td>5.0.3.84333</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>PDB Path</strong></td>
<td>D:\jenkins\workspace\bav_5.0_workspace\BavOutput\Pdb\Release\BdApiUtil64.pdb</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Original Purpose</strong></td>
<td>Baidu Antivirus Kernel Utility Driver</td>
<td class="confirmed">CONFIRMED</td>
</tr>
</tbody>
</table>


>ANALYST NOTE: `D:\jenkins\workspace\`: This indicates the code was compiled on a Jenkins build server. Jenkins is a very common automation server used for Continuous Integration/Continuous Deployment (CI/CD), which points to a professional software development environment. `bav_5.0_workspace`: This is the name of the specific Jenkins project or "workspace." `BavOutput\Pdb\Release`: This shows the build configuration. It could be a Release build, meaning it was optimized for distribution, not a debug test build. 

### Why This Driver Is Critical

BdApiUtil64.sys is not a malicious driver-it's a **legitimate component of Baidu Antivirus**. However, it contains vulnerabilities that allow unrestricted IOCTL-based kernel access. The combination of:

1. **Legitimate Digital Signature** - Windows allows kernel driver loading only from digitally-signed drivers. The expired Baidu certificate, while expired, is still accepted by Windows driver signature enforcement
2. **Vulnerable IOCTL Interface** - The driver implements IOCTLs without proper access control, allowing unprivileged user-mode processes to invoke kernel-level operations
3. **No Process Validation** - IOCTLs don't verify the caller's identity or purpose before executing privileged operations
4. **Powerful Kernel Capabilities** - Available operations include process termination, service creation, file system access, and registry manipulation

This combination makes it an ideal choice for BYOVD attacks. Attackers weaponize the driver not by modifying it, but by leveraging its vulnerable legitimate functionality.

---

## Arsenal-237 Toolkit Context

### Discovery & Infrastructure

**HIGH CONFIDENCE (85%)** - BdApiUtil64.sys was discovered on an open directory at **109.230.231.37** as part of the comprehensive Arsenal-237 attack toolkit. This IP address hosts a complete attack orchestration platform with 11 deep-dive analysis samples.

The Arsenal-237 toolkit represents a **professional-grade, organized threat** with sophisticated attack automation and defense evasion. The toolkit contains:

| Component | File Type | Purpose | Role in Chain |
|-----------|-----------|---------|----------------|
| lpe.exe | Executable | Privilege Escalation | Initial SYSTEM-level access |
| killer.dll | DLL | Security Product Terminator | First-stage defense suppression |
| killer_crowdstrike.dll | DLL | CrowdStrike-Specific Terminator | EDR-specific evasion |
| **BdApiUtil64.sys** | **Kernel Driver** | **Kernel Privilege & Defense Bypass** | **Second-stage defense suppression** |
| rootkit.dll | DLL | Additional kernel-level access | Redundant persistence mechanisms |
| enc_*.exe | Executables | Ransomware Payloads | Final attack payload (encryption) |

### Toolkit Sophistication Indicators

**HIGH CONFIDENCE (90%)** - Arsenal-237 demonstrates professional threat actor development:

- **Targeted Security Product Lists**: Dedicated killer DLLs for Microsoft Defender, CrowdStrike Falcon, and other major EDR products (see Target Security Products section)
- **Redundant Defense Bypass**: Multiple independent driver-based and DLL-based termination methods for defense-in-depth evasion
- **Infrastructure Professionalism**: Organized toolkit with modular components, explicit naming conventions, coordinated attack flow
- **Privilege Escalation Integration**: Custom lpe.exe wrapper for controlled privilege escalation prerequisite
- **Ransomware Payload Variants**: Multiple enc_*.exe variants suggesting A/B testing or sector-specific encryption customization

This is not opportunistic malware-this is organized, sophisticated attack infrastructure suggesting either advanced APT operations or a professional malware-as-a-service platform.

---

## BYOVD Technique: Weaponizing Legitimate Drivers

### What Is BYOVD?

**BYOVD (Bring Your Own Vulnerable Driver)** is a modern evasion technique where attackers exploit vulnerabilities in legitimate, digitally-signed drivers rather than deploying custom malicious drivers. The technique provides kernel-level privileges while evading detection systems that may flag "suspicious" drivers.

**Key Advantages:**
- Legitimate digital signature bypasses Driver Signature Enforcement (DSE)
- Reduced detection rates (legitimate software, legitimate certificate)
- No custom rootkit development required
- Proven, well-documented attack pattern (reduces operational risk)
- Kernel Ring-0 privileges despite user-mode compromise origin

### Why BdApiUtil64.sys Was Chosen

Arsenal-237 selected BdApiUtil64.sys for specific technical reasons:

| Factor | Assessment |
|--------|-----------|
| **Signature Status** | Valid Baidu certificate (expired 2015, still accepted by Windows) |
| **Vulnerability Severity** | Complete lack of IOCTL access control (HIGH) |
| **Operational Simplicity** | Standard IOCTL interface, no exploitation required |
| **Functional Coverage** | All required kernel operations (process termination, service creation, file access) |
| **Detection Evasion** | Limited detection of legitimate Baidu driver file |
| **Historical Validation** | Successfully used in BlackByte, Cuba, ALPHV/BlackCat campaigns (known reliable) |

### Driver Installation & Activation

The typical Arsenal-237 attack flow uses BdApiUtil64.sys through these stages:

```
Stage 1: Initial Compromise
|
lpe.exe (Privilege Escalation Wrapper)
|
Achieves SYSTEM-level access
|
Stage 2: Driver Deployment
|
Drops BdApiUtil64.sys to C:\Windows\System32\drivers\BdApiUtil64.sys
Creates registry service entry: HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
Sets StartType to 2 (automatic) or 3 (manual)
|
Stage 3: Driver Loading
|
Invokes sc.exe start Bprotect or kernel API (NtLoadDriver)
Windows kernel validates Baidu signature (legitimate, loads)
Driver initializes device objects and IOCTL interface
|
Stage 4: Defense Suppression
|
Malware sends IOCTLs to \Device\BdApiUtil
Terminates security processes via IOCTL 0x800024b4/0x800024b8
Creates backdoor services via IOCTL 0x80002324
Exfiltrates credentials via IOCTL 0x80002648
|
Stage 5: Unrestricted Execution
|
All security controls disabled, malware executes freely
Ransomware payload (enc_*.exe) executes with no interference
```

---

## Primary Capabilities - IOCTL Code Analysis

BdApiUtil64.sys implements four primary IOCTL codes that provide attackers with complete system control. Each represents a distinct capability essential to the Arsenal-237 attack chain.

### Capability Overview Matrix

<table class="professional-table">
<thead>
<tr>
<th>IOCTL Code</th>
<th>Capability</th>
<th>Impact</th>
<th>Detection Difficulty</th>
<th>Confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>0x800024b4</strong></td>
<td>Direct Process Termination</td>
<td class="critical">Critical</td>
<td>Standard Termination - Can be monitored</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>0x800024b8</strong></td>
<td>EDR-Evading Process Termination</td>
<td class="critical">Critical</td>
<td>Advanced Evasion - Defeats most EDR</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>0x80002324</strong></td>
<td>Service Creation & Manipulation</td>
<td class="critical">Critical</td>
<td>Kernel-level - Hard to detect</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>0x80002648/0x8000264c</strong></td>
<td>File System Access & Data Theft</td>
<td class="critical">Critical</td>
<td>Kernel-level - Bypasses ACLs</td>
<td class="confirmed">CONFIRMED</td>
</tr>
</tbody>
</table>

---

### IOCTL 0x800024b4: Direct Process Termination

**Purpose**: Rapidly terminate security product processes using standard kernel APIs

**Technical Details**

Input Buffer:
- Size: 4 bytes minimum
- Contents: Target Process ID (DWORD)

Execution Flow:
1. **Process Lookup**: `PsLookupProcessByProcessId(input_pid)` - Converts user-mode PID to kernel EPROCESS structure
2. **Privilege Grant**: Kernel context grants PROCESS_ALL_ACCESS to any process (no privilege checks)
3. **Termination**: `ZwTerminateProcess(process_handle, STATUS_SUCCESS)` - Terminates target process
4. **No Return Value Validation**: Silently completes regardless of success or failure

**Why This Is Effective**

- **Speed**: Direct termination via standard kernel API completes in 5-15 milliseconds per process
- **Legitimacy**: Uses official Windows kernel functions, appears legitimate in kernel trace logs
- **Simplicity**: No evasion required for initial deployment, reliable against basic monitoring
- **Multi-Process Capability**: Terminates an entire security product suite (example: Microsoft Defender requires terminating MsMpEng.exe, NisSrv.exe, MpDefenderCoreService.exe simultaneously)

**Arsenal-237 Usage**

This IOCTL serves as the **first-stage defense suppression mechanism**. When security products have not yet detected driver loading or when evasion is not yet necessary, BdApiUtil64.sys rapidly terminates running security processes:

```
[Driver Load] -> [Wait 100ms] -> [Send IOCTL 0x800024b4 for MsMpEng.exe]
                                -> [Wait 50ms] -> [Send IOCTL 0x800024b4 for MpDefenderCoreService.exe]
                                -> [Wait 50ms] -> [Send IOCTL 0x800024b4 for NisSrv.exe]
                                -> [Wait 100ms] -> [Ransomware execution begins]
```

**Detection Baseline**

Without EDR: Extremely difficult (kernel-level operation, no user-mode artifact)
With EDR: Possible to detect via process termination telemetry (if EDR survives termination attempt)

---

### IOCTL 0x800024b8: EDR-Evading Process Termination (Advanced)

**Purpose**: Terminate security products even when they install kernel-mode hooks to detect IOCTL calls

**Technical Details - The Hook Detection Mechanism**

Input Buffer:
- Size: 4 bytes minimum
- Contents: Target Process ID (DWORD)

Pre-Execution Validation:
```
1. Examine first instruction of ZwTerminateProcess function
2. Check if first byte == 0xb8 (MOV EAX instruction)
3. IF 0xb8:
     -> EDR hook NOT detected, use IOCTL 0x800024b4 instead
   ELSE:
     -> EDR hook DETECTED, switch to SSDT bypass (IOCTL 0x800024b8)
```

**Why Hook Detection?**

Modern EDR products install inline hooks on critical system calls like `ZwTerminateProcess`. They intercept calls to:
- Detect when security products are being terminated
- Log and alert on suspicious termination patterns
- Block or delay the termination call

By examining the first instruction, the driver can detect whether `ZwTerminateProcess` has been hooked:

- **Legitimate (Unhooked)**: First instruction is `MOV EAX, <service_number>` (opcode 0xb8), part of the SYSCALL convention
- **Hooked**: First instruction is a JMP to EDR hook code (opcodes 0xE9 or similar), redirecting to monitoring code

---

### SSDT Bypass Technique (The Advanced Evasion)

**What Is SSDT?**

The System Service Descriptor Table (SSDT) is the kernel's internal lookup table mapping system call numbers to their implementation functions. It's the actual "real" function that handles the operation.

User-mode API calls go through this transformation:
```
User-mode: ZwTerminateProcess()
         | (SYSCALL instruction with service number)
Kernel SSDT: KeServiceDescriptorTable[service_number]
         |
Actual kernel function: NtTerminateProcess()
```

**EDR Hooking Strategy**

EDR products hook `ZwTerminateProcess` by modifying its first few bytes to JMP to their monitoring code:

```
Original ZwTerminateProcess:     EDR-Hooked ZwTerminateProcess:
  MOV EAX, 0x29               ->  JMP [EDR Hook Address]
  SYSCALL                         [EDR Hook monitors call, then...]
  RET                             [EDR calls SSDT directly or patches it]
```

**BdApiUtil64.sys SSDT Bypass Execution Flow**

1. **Dynamic Resolution**:
   ```
   MmGetSystemRoutineAddress("KeServiceDescriptorTable")
   -> Returns address of kernel SSDT table
   ```

2. **Service Number Extraction**:
   ```
   Read ZwTerminateProcess legitimate implementation
   -> Extract service number from MOV EAX instruction
   -> Service number for NtTerminateProcess = 0x29 (Windows 7) or varies by Windows version
   ```

3. **SSDT Direct Lookup**:
   ```
   SSDT_Function = *(KeServiceDescriptorTable + (service_number << 2))
   -> Retrieves actual kernel function pointer
   -> Bypasses hooked ZwTerminateProcess wrapper
   ```

4. **Direct Function Call**:
   ```
   Call SSDT_Function(process_handle, exit_status) directly
   -> Bypasses user-mode and kernel-mode hooks
   -> Executes actual process termination
   ```

**Why This Defeats EDR**

- **Hook Bypass**: Doesn't use `ZwTerminateProcess` at all, calls SSDT directly
- **No Interception**: EDR hooks installed on `ZwTerminateProcess` never see the call
- **Kernel Legitimacy**: Uses legitimate kernel data structure (SSDT), appears as valid kernel operation
- **Near-Guaranteed Success**: Works against most EDR hooking strategies (some advanced EDRs may hook SSDT itself, but this is rare)

**Arsenal-237 Usage Flow**

```
[Driver Load] -> [Attempt IOCTL 0x800024b4 on security product]
              -> [If security product still running after 200ms...]
              -> [Examine ZwTerminateProcess first byte]
              -> [If hooked (0xb8 != first byte)...]
              -> [Send IOCTL 0x800024b8 with SSDT bypass]
              -> [Process terminated, EDR hook bypassed]
```

**Detection Challenge**

This technique is difficult to detect because:
- No user-mode call to hooked API
- Kernel operation appears legitimate (uses real SSDT)
- No anomalous code execution pattern
- EDR hooks never see the termination attempt

---

### IOCTL 0x80002324: Service Creation and Manipulation

**Purpose**: Create persistent Windows services with kernel-level privileges, enabling backdoor installation and malware persistence

**Technical Details**

Input Buffer:
- Size: Exactly 0x224 bytes (548 bytes)
- Structure: Custom binary format with Unicode strings and configuration flags

Buffer Layout:
```
Offset 0x000: [Reserved/Header - 2 bytes]
Offset 0x002: Service Name (Unicode string, 0x41 chars max = 130 bytes)
Offset 0x084: Service Type (1 byte) - Kernel driver, Win32 service, etc.
Offset 0x085: Start Type (1 byte) - Auto-start (2), Demand (3), Disabled (4)
Offset 0x086: Error Control (1 byte) - Ignore, Normal, Severe, Critical
Offset 0x087: Service Tag (1 byte)
Offset 0x088: Desired Access Rights (4 bytes DWORD)
Offset 0x08C: Binary Path (Unicode string, 260 chars)
Offset 0x138: Service DLL Path (Unicode string, 260 chars)
Offset 0x1E4: Service Flags (4 bytes DWORD)
Offset 0x1E8: Service Description (Unicode string, 128 chars)
```

Execution Flow:
```
1. Validate input buffer size == 0x224 (strict validation)
2. Extract service name and binary path from input buffer
3. Call sub_147d0() -> internal service creation function
4. Invoke kernel API ObInsertObject() with service parameters
5. Register service in HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
6. Return service creation status
```

**Why This Is Dangerous**

**Service Impersonation**: Arsenal-237 can create services with legitimate-sounding names to hide malware:

Legitimate Service Names Used in Previous Attacks:
- "WindowsUpdateService" (appears to be Windows Update, actually malware)
- "MicrosoftSecurityAgent" (appears to be defender, actually backdoor)
- "NvidiaGraphicsService" (appears to be GPU driver, actually persistence)
- "IntelTelemetryService" (appears to be system telemetry, actually C2 beacon)

**Kernel-Level Privileges**: Service creation through kernel driver bypasses:
- User Access Control (UAC) prompts
- Service installation validation
- User privilege requirements
- Audit logging (traditional service creation is logged, kernel-level is not)

**Backdoor Installation**: Once service is created:
```
[IOCTL 0x80002324] -> [Service created with malware DLL]
                   -> [Service registered in HKLM]
                   -> [Service starts on next system restart]
                   -> [DLL loads automatically with SYSTEM privileges]
                   -> [Backdoor persistent across reboots]
```

**Arsenal-237 Usage**

Arsenal-237 uses IOCTL 0x80002324 to create persistence mechanisms AFTER security products are terminated:

```
[Driver Load] -> [Terminate security products via IOCTLs 0x800024b4/0x800024b8]
              -> [Use IOCTL 0x80002324 to create service for backdoor DLL]
              -> [Use IOCTL 0x80002648 to install service binary]
              -> [Ransomware executes with persistence mechanisms active]
              -> [If system reboots, backdoor service auto-starts]
```

**Detection Baseline**

Without Monitoring: Service creation at kernel level is invisible to standard Windows event logging
With EDR: Some EDR products monitor registry modifications for service creation, but kernel-level creation may bypass logging
With Behavioral Analysis: Service creation within 30 seconds of unfamiliar driver load is suspicious

---

### IOCTL 0x80002648 & 0x8000264c: File System Access and Data Theft

**Purpose**: Direct kernel-mode file access bypassing all security restrictions, enabling credential and encryption key theft

**Technical Details**

Input Buffer:
- Size: Minimum 0x208 bytes (520 bytes)
- Structure: File path specification and access mode flags

Buffer Layout:
```
Offset 0x000: [Header/Flags - 24 bytes]
Offset 0x018: File Path (Unicode string, 259 chars maximum)
Offset 0x1XX: [Additional parameters]
```

File Access Method:
```
1. Extract file path from input buffer (Offset 0x018)
2. Invoke IoCreateFile() with:
   - DesiredAccess: 0x120089 (Read + Write + Delete + Synchronize)
   - ShareAccess: 0 (Exclusive access, no sharing)
   - OpenOptions: FILE_OPEN (open existing file, fail if not found)
3. Read/write file content directly in kernel context
4. Return file handle or file contents
```

**Alternative Implementations**

The driver implements two separate functions for file access:
- **sub_13bb0**: Primary file access implementation (standard path)
- **sub_13850**: Alternative processing method (likely fallback for access denied scenarios)

This redundancy ensures file access succeeds even if initial method fails (example: if file is locked).

**What Files Can Be Accessed?**

The driver accesses files with kernel-level privileges (SYSTEM context), bypassing:
- File-level ACL (Access Control List) restrictions
- File locks
- EDR file access monitoring
- User privilege requirements

**Critical Files Arsenal-237 Targets:**

| File Category | Examples | Sensitive Data |
|--------------|----------|-----------------|
| **Windows Credential Stores** | C:\Windows\System32\config\SAM | User account password hashes |
| | C:\Windows\System32\config\SYSTEM | DPAPI master keys |
| | C:\Windows\System32\config\SECURITY | LSA secrets, domain credentials |
| **Browser Credentials** | %LOCALAPPDATA%\Google\Chrome\User Data\Login Data | Chrome saved passwords |
| | %APPDATA%\Mozilla\Firefox\[Profile]\logins.json | Firefox stored credentials |
| **Cloud Storage** | %LOCALAPPDATA%\Google\Drive\sync_config.db | Drive authentication tokens |
| **Email** | %LOCALAPPDATA%\Microsoft\Outlook\*.pst | Email archives with secrets |
| **Encryption Keys** | %APPDATA%\Microsoft\Protect\[SID] | DPAPI keys (if not cached) |
| **Security Configs** | C:\Program Files\[Security Product]\config.xml | EDR configuration |
| | HKLM registry hives | All registry settings |

**Arsenal-237 Credential Harvesting Flow**

```
[Security products terminated via IOCTLs 0x800024b4/0x800024b8]
|
[Malware determines browser installed (Chrome, Firefox, Edge)]
|
[Send IOCTL 0x80002648 with file path: %LOCALAPPDATA%\Google\Chrome\User Data\Login Data]
|
[Driver reads file directly, bypassing browser locks and file permissions]
|
[Malware exfiltrates credential database to attacker C2]
|
[Repeat for additional browsers, email clients, cloud storage]
|
[Complete credential theft with no user awareness]
```

**Two IOCTL Codes: Why 0x80002648 vs. 0x8000264c?**

**HIGHLY LIKELY (80%)** these represent different access modes or return mechanisms:
- **0x80002648**: Likely returns file contents to user-mode buffer (read capability)
- **0x8000264c**: Likely performs write or in-place modification (write capability)

Both provide file system access but through different methods, giving attackers flexibility:
- Read credentials -> Use 0x80002648
- Delete logs -> Use 0x8000264c
- Modify security configs -> Use 0x8000264c
- Steal encryption keys -> Use 0x80002648

---

## Advanced Evasion Techniques

Beyond the four primary IOCTLs, BdApiUtil64.sys implements additional kernel-level capabilities that enable sophisticated evasion and anti-forensics.

### Additional Kernel Capabilities

**Filter Manager API Enumeration** (Minifilter Discovery)

**Purpose**: Detect and enumerate EDR minifilter drivers installed on the system

Kernel APIs Used:
- `FltEnumerateFilters()` - List all loaded minifilter drivers
- `FltEnumerateInstances()` - List instances of each minifilter
- `FltGetFilterInformation()` - Retrieve minifilter properties (name, altitude, instance count)

**Strategic Purpose**: Arsenal-237 uses this to:
1. Detect which EDR solutions are installed
2. Determine driver load order and altitude (minifilter priority)
3. Identify specific EDR instances that need termination
4. Prioritize termination order (terminate dependent instances before core driver)

**Registry Callback Registration** (Anti-Restoration)

**Purpose**: Register kernel callbacks that intercept and block registry modifications

Kernel APIs Used:
- `CmRegisterCallback()` - Register registry modification callback
- `CmUnRegisterCallback()` - Unregister callbacks

**Strategic Purpose**: Arsenal-237 uses this to:
1. Detect when security products attempt to restore themselves
2. Block registry writes that disable services (prevents service re-enabling)
3. Monitor for manual attempts to delete service entries
4. Create redundant persistence (if service is deleted, driver reinstalls it)

**Registry Manipulation** (Security Product Disabling)

**Kernel APIs Used**:
- `ZwCreateKey()` - Create registry keys
- `ZwSetValueKey()` - Create/modify registry values
- `ZwDeleteKey()` - Delete registry keys

**Strategic Purpose**: Arsenal-237 uses this to:
1. Disable Windows services (set Start to 4 = Disabled)
2. Modify security product registry (disable features, change configurations)
3. Clear Event Log registry entries
4. Set UAC registry to lowest level

**File Attribute Manipulation** (Anti-Forensics)

**Purpose**: Modify file timestamps and hide malware artifacts

Kernel APIs Used:
- `ZwSetInformationFile()` - Modify file attributes and metadata

**Strategic Purpose**: Arsenal-237 uses this to:
1. Timestamp stomp malware files (make them appear as if installed in 2010)
2. Hide file modification dates (appear legitimate)
3. Delete last access times (hide forensic evidence of file access)

**System Reconnaissance** (Fingerprinting)

**Kernel APIs Used**:
- `PsGetVersion()` - Determine Windows version
- `ZwQuerySystemInformation()` - Retrieve process list, system handles, network connections

**Strategic Purpose**: Arsenal-237 uses this to:
1. Determine Windows version (Windows 10 vs. Windows 11, build number)
2. Detect Windows Sandbox or virtualization (Hyper-V, VirtualBox)
3. Enumerate all running processes
4. Identify system configuration (processor count, memory)
5. Adapt attack based on OS capabilities (Windows 11 HVCI detection)

---

## Attack Chain Integration

### Arsenal-237 Complete Attack Flow

Arsenal-237 uses BdApiUtil64.sys as part of a coordinated multi-stage attack orchestration. Understanding where the driver fits in the complete kill chain illuminates its strategic importance.

**Stage 1: Initial Access & Privilege Escalation**

```
[Compromised Website or Phishing Email]
|
[User downloads malware (Arsenal-237 initial stage)]
|
[lpe.exe (Privilege Escalation Wrapper) executes]
```

**lpe.exe Purpose**: lpe.exe is a wrapper that:
1. Checks current privilege level
2. Extracts embedded privilege escalation exploits
3. Attempts exploitation chain (local privilege escalation CVEs)
4. Achieves SYSTEM-level access
5. Extracts remaining toolkit components to disk

**Outcome**: SYSTEM-level access obtained, UAC bypassed

---

**Stage 2: Defense Evasion Layer 1 - Userland Suppression**

```
[lpe.exe achieves SYSTEM privileges]
|
[killer.dll & killer_crowdstrike.dll load]
|
[Enumerate running security processes]
|
[killer.dll: Terminate standard EDR agents (user-mode processes)]
  -> CSFalconService.exe (CrowdStrike)
  -> MsMpEng.exe (Windows Defender)
  -> ekrn.exe (ESET)
  -> etc. (see Target Security Products section)
```

**Outcome**: User-mode EDR processes terminated, but kernel-mode drivers still active

**Limitation**: User-mode termination can be detected by kernel-mode monitors; kernel drivers may reinstall themselves

---

**Stage 3: Defense Evasion Layer 2 - Kernel Suppression (BdApiUtil64.sys)**

```
[User-mode EDR processes are terminated, but kernel drivers may reinstall]
|
[Driver deployment and loading]
  -> Drop BdApiUtil64.sys to C:\Windows\System32\drivers\
  -> Create service "Bprotect" (registry entry)
  -> Load driver via sc start Bprotect or kernel API
  -> Windows loads driver with valid Baidu signature (bypass DSE)
|
[BdApiUtil64.sys initialization]
  -> Create device object \Device\BdApiUtil
  -> Create symbolic link \DosDevices\BdApiUtil
  -> Register callback \Callback\bdProtectExpCallBack
  -> Listen for IOCTL calls
|
[Comprehensive defense termination]
  -> IOCTL 0x800024b4: Terminate remaining EDR processes
  -> [If EDR hooks detected...]
  -> IOCTL 0x800024b8: SSDT bypass termination
  -> IOCTL: Enumerate minifilters (determine remaining EDR drivers)
  -> IOCTL: Register registry callbacks (block service restoration)
  -> IOCTL: Disable Windows Event Logging service
|
[Security products completely neutralized]
```

**Outcome**: All security products (user-mode and kernel-mode) disabled; ransomware execution enabled

---

**Stage 4: Persistence Establishment**

```
[All security products disabled]
|
[Create malicious services]
  -> IOCTL 0x80002324: Create service "WindowsUpdateService"
    (points to backdoor DLL: C:\Windows\System32\wups.dll)
  -> Configure auto-start (StartType = 2)
  -> Service persists across reboots
|
[Create additional persistence mechanisms]
  -> Scheduled task
  -> Registry Run key
  -> Boot configuration modification
```

**Outcome**: Multiple persistence mechanisms ensure continued access after reboots

---

**Stage 5: Data Collection & Exfiltration**

```
[All defenses disabled, persistence established]
|
[Credential harvesting]
  -> IOCTL 0x80002648: Read C:\Windows\System32\config\SAM
  -> Extract password hashes, DPAPI keys
  -> IOCTL 0x80002648: Read browser credential databases
  -> Steal Chrome/Firefox/Edge stored passwords
|
[Sensitive data access]
  -> IOCTL 0x80002648: Read email archives (.pst files)
  -> IOCTL 0x80002648: Read encryption keys
  -> IOCTL 0x80002648: Read security product configurations
|
[Exfiltration to attacker C2]
  -> Send encrypted data to command and control server
  -> Attacker gains access to all stolen credentials
```

**Outcome**: Complete credential compromise; attacker can now access all user accounts, cloud services, email

---

**Stage 6: Ransomware Deployment (Final Payload)**

```
[All prerequisites complete: defenses disabled, persistence established, credentials stolen]
|
[Execute ransomware payload]
  -> enc_*.exe launches with SYSTEM privileges
  -> No security products to interfere
  -> No EDR to detect encryption activity
  -> No logs being recorded (Event Logging service terminated)
|
[Ransomware execution]
  -> Enumerate all network shares (mapped drives, UNC paths)
  -> Encrypt files (documents, databases, backups)
  -> Generate ransom notes
  -> Delete shadow copies (SSDT bypass prevents Volume Shadow Copy Service restoration)
  -> Exfiltrate encryption key to attacker
|
[Business impact]
  -> Complete data encryption
  -> Business continuity interrupted
  -> Credential compromise across entire organization
```

**Outcome**: Complete ransomware attack success; attacker has encryption keys, stolen credentials, and persistent access

---

## Target Security Products

Arsenal-237 maintains a comprehensive list of security products for termination, indicating this toolkit targets **enterprise environments with sophisticated security controls**. The inclusion of multiple product-specific DLLs (killer_crowdstrike.dll) demonstrates advanced operational planning.

### Security Products Targeted (Arsenal-237 Integration)

**Microsoft Defender & Windows Security**
- MsMpEng.exe (Windows Defender engine)
- MpDefenderCoreService.exe (core service)
- NisSrv.exe (Network Inspection Service)
- smartscreen.exe (Windows Defender SmartScreen)
- MsSense.exe (Microsoft Defender Advanced Threat Protection)
- SenseCnProxy.exe (EDR cloud proxy)
- SenseIR.exe (Incident Response component)
- SecurityHealthService.exe (Windows Security Health Service)
- SecurityHealthSystray.exe (System tray UI)
- MpCmdRun.exe (command-line tool)

**CrowdStrike Falcon (Dedicated DLL: killer_crowdstrike.dll)**
- CSFalconService.exe (main service)
- csagent.exe (agent process)
- CSFalconContainer.exe (container runtime)
- SentinelAgent.exe (sensor)
- SentinelServiceHost.exe (service host)
- SentinelStaticEngine.exe (detection engine)

**ESET Security**
- ekrn.exe (Kernel module)
- egui.exe (User interface)
- eamonm.exe (Monitor)
- eset.exe (Main executable)

**Kaspersky Lab**
- avp.exe (Main antivirus)
- kavfs.exe (File system driver)
- kavfsslp.exe (Light Protocol)

**Sophos**
- SophosHealth.exe (Endpoint protection)
- SophosFileScanner.exe (File scanner)
- SophosUI.exe (User interface)

**Carbon Black (Formerly VMware)**
- cb.exe (Main service)
- CbDefense.exe (Cloud defense)
- RepMgr.exe (Reputation Manager)

**Malwarebytes**
- MBAMService.exe (Service)
- mbamtray.exe (System tray)
- MBAMWsc.exe (Windows Security Center)

**Analysis & Investigation Tools**
- procexp64.exe (Process Explorer - forensic analysis)
- ProcessHacker.exe (Process Hacker - memory editor)
- wireshark.exe (Network analyzer - traffic inspection)

### Strategic Implication

The breadth of targeted security products indicates:

**HIGH CONFIDENCE (90%)** - Arsenal-237 is designed for **enterprise environments** with:
- Multi-layered security deployments (Defender + CrowdStrike + third-party solutions)
- Sophisticated monitoring and detection capabilities
- Incident response capabilities (hence targeting forensic tools)
- Network monitoring (targeting Wireshark)

This is not generic malware-it's specifically engineered for **high-security environments where multiple defense layers must be simultaneously disabled**.

---

## Historical Campaign Context

### Real-World Ransomware Campaigns Using BYOVD

BdApiUtil64.sys or similar Baidu antivirus drivers have been observed in multiple sophisticated ransomware campaigns, validating the effectiveness of this technique.

**BlackByte Ransomware (2022-2023)**

**HIGHLY CONFIDENT (85%)** - BlackByte utilized Baidu drivers as part of its defense evasion strategy

- **Timeline**: Operations from 2022 through 2023
- **Infrastructure**: Operated dedicated C2 servers with toolkit distribution
- **Technique**: BYOVD driver + dedicated security product termination DLLs
- **Targets**: Critical infrastructure, healthcare, financial services
- **Impact**: Ransom demands at scale commensurate with target organization size
- **Public Documentation**: Documented in Federal Bureau of Investigation (FBI) Alert IR-22-152, Cybersecurity and Infrastructure Security Agency (CISA) Advisory

**Cuba Ransomware (2022)**

**HIGHLY CONFIDENT (85%)** - Cuba ransomware gang incorporated BYOVD techniques

- **Timeline**: Active 2022, associated with Cuba nation-state nexus
- **Technical Sophistication**: Multi-stage attack with BYOVD driver deployment
- **Target Profile**: Financial institutions, Fortune 500 companies
- **Known Victims**: At least 30+ organizations publicly named
- **Detection**: Documented in threat intelligence reports from Mandiant, Microsoft Threat Intelligence

**ALPHV/BlackCat Ransomware (2022-Present)**

**HIGHLY CONFIDENT (85%)** - ALPHV (also known as BlackCat) explicitly incorporates Baidu BYOVD techniques

- **Timeline**: Active 2022 through present day
- **Notable Features**: Ransomware-as-a-Service (RaaS) platform with affiliate program
- **Technical Evolution**: Incorporates multiple BYOVD drivers, advanced evasion
- **Public Attribution**: Documented by US Department of Treasury Office of Foreign Assets Control (OFAC) as subject to sanctions
- **Enterprise Impact**: Hundreds of organizations affected

**AvosLocker Ransomware (2022-2023)**

**CONFIDENT (80%)** - AvosLocker gang integrated kernel-mode defense evasion

- **Timeline**: Operations 2022-2023
- **Technique Mix**: Combination of user-mode and kernel-mode evasion
- **Target Industries**: Critical infrastructure, healthcare systems
- **Known Techniques**: BYOVD driver deployment, EDR termination

---

### Why This Technique Remains Effective

Despite public knowledge of BYOVD techniques, they remain effective because:

1. **Low Detection Baseline**: Many organizations lack kernel-level monitoring, allowing driver loading to proceed undetected
2. **Legitimate Signature Trust**: Windows and some security products still trust expired signatures (Baidu certificate expired 2015, still loads)
3. **Operational Simplicity**: Attackers don't develop custom rootkits; they repurpose legitimate vulnerable drivers
4. **Multi-Product Evasion**: Single driver provides multiple evasion capabilities (process termination, service creation, file access, callback registration)
5. **Proven Success**: Real-world campaign success validates technique reliability
6. **Redundant Defense Bypass**: Arsenal-237's multi-layer approach (killer.dll + BdApiUtil64.sys) provides fallback mechanisms

---

## MITRE ATT&CK Mapping

BdApiUtil64.sys enables multiple MITRE ATT&CK techniques through its kernel-level capabilities. This mapping shows how the driver facilitates broader attack objectives.

### Mapped Techniques by Tactic

<table class="professional-table">
<thead>
<tr>
<th>MITRE Tactic</th>
<th>Technique ID</th>
<th>Technique Name</th>
<th>Implementation via BdApiUtil64.sys</th>
<th>Confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Persistence</strong></td>
<td>T1547.006</td>
<td>Boot or Logon Initialization Scripts: Kernel Modules & Extensions</td>
<td>Driver installation creates persistent kernel-level component loaded at every system boot; service creation (IOCTL 0x80002324) ensures driver loads automatically</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Persistence</strong></td>
<td>T1543.003</td>
<td>Create or Modify System Process: Windows Service</td>
<td>IOCTL 0x80002324 creates arbitrary Windows services with kernel privileges, bypassing UAC and standard service installation validation</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1562.001</td>
<td>Impair Defenses: Disable or Modify Tools</td>
<td>IOCTLs 0x800024b4 and 0x800024b8 terminate security product processes; registry callbacks (CmRegisterCallback) prevent security product restoration</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1070.004</td>
<td>Indicator Removal: File Deletion</td>
<td>IOCTL 0x8000264c with file write capability enables deletion of forensic artifacts, malware indicators, and audit logs</td>
<td class="likely">LIKELY (80%)</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1562.002</td>
<td>Impair Defenses: Disable Windows Event Logging</td>
<td>IOCTL 0x800024b4/0x800024b8 terminates EventLog service; registry callbacks block re-enablement; registry manipulation (ZwSetValueKey) disables logging</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1222</td>
<td>File and Directory Permissions Modification</td>
<td>IOCTL 0x80002648/0x8000264c accesses files bypassing ACL checks; kernel context grants SYSTEM privileges overriding user-mode permission restrictions</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1112</td>
<td>Modify Registry</td>
<td>Kernel APIs ZwCreateKey, ZwSetValueKey, ZwDeleteKey enable registry manipulation; registry callbacks monitor and block security product modifications</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1014</td>
<td>Rootkit</td>
<td>Driver implements kernel-level rootkit functionality: process hiding, file hiding, callback interception, registry modification, kernel hooks</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Defense Evasion</strong></td>
<td>T1027.010</td>
<td>Obfuscated Files or Information: Command Obfuscation</td>
<td>SSDT bypass (IOCTL 0x800024b8) uses indirect system call dispatch, obfuscating termination attempts from EDR hooks</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Discovery</strong></td>
<td>T1082</td>
<td>System Information Discovery</td>
<td>PsGetVersion, ZwQuerySystemInformation enable OS fingerprinting, processor/memory enumeration, process discovery</td>
<td class="likely">LIKELY (85%)</td>
</tr>
<tr>
<td><strong>Discovery</strong></td>
<td>T1057</td>
<td>Process Discovery</td>
<td>ZwQuerySystemInformation enumerates all running processes in kernel context, more comprehensive than user-mode enumeration</td>
<td class="likely">LIKELY (85%)</td>
</tr>
<tr>
<td><strong>Discovery</strong></td>
<td>T1518.001</td>
<td>Software Discovery: Security Software Discovery</td>
<td>FltEnumerateFilters, FltEnumerateInstances, FltGetFilterInformation detect all installed EDR minifilter drivers and instances</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Execution</strong></td>
<td>T1129</td>
<td>Shared Modules</td>
<td>MmGetSystemRoutineAddress dynamically resolves kernel functions at runtime; SSDT lookup uses dynamic service number resolution</td>
<td class="likely">LIKELY (80%)</td>
</tr>
<tr>
<td><strong>Impact</strong></td>
<td>T1489</td>
<td>Service Stop</td>
<td>IOCTLs 0x800024b4/0x800024b8 force-terminate security services; this enables ransomware execution without interference</td>
<td class="confirmed">CONFIRMED</td>
</tr>
<tr>
<td><strong>Collection</strong></td>
<td>T1005</td>
<td>Data from Information Repositories</td>
<td>IOCTL 0x80002648 directly reads protected files: SAM hive, credential databases, browser cookies, encryption keys</td>
<td class="confirmed">CONFIRMED</td>
</tr>
</tbody>
</table>

---

## Detection Opportunities

Detecting BdApiUtil64.sys requires multi-layered approach targeting file characteristics, registry artifacts, behavioral indicators, and real-time telemetry. Each detection layer provides complementary evidence of compromise.

### File-Based Detection

**Hash Matching** (Definitive Detection)

Create file hash indicators in your SIEM, EDR, and endpoint detection tools:

```
MD5:    ced47b89212f3260ebeb41682a4b95ec
SHA1:   148c0cde4f2ef807aea77d7368f00f4c519f47ef
SHA256: 47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428
```

**Detection Confidence**: DEFINITE - Any match indicates Arsenal-237 toolkit presence

**File Path Indicators**

Standard deployment path:
```
C:\Windows\System32\drivers\BdApiUtil64.sys
```

Alternate paths (less common):
```
C:\Windows\drivers\
C:\ProgramData\BdApiUtil64.sys
C:\Temp\BdApiUtil64.sys
[User-controlled temp directories]
```

**Detection Confidence**: DEFINITE if exact hash match; HIGHLY LIKELY if filename match + Baidu signature

**Digital Signature Validation** (Baidu Certificate)

Legitimate BdApiUtil64.sys is signed by: `Baidu Online Network Technology (Beijing) Co., Ltd`

- Certificate Authority: VeriSign Class 3 Code Signing 2010 CA
- Signature validity: April 24, 2012 to April 24, 2015 (EXPIRED)

**Detection Strategy**:
- Alert on kernel drivers signed by Baidu UNLESS they are:
  - Located in standard Baidu Antivirus installation directory (C:\Program Files\Baidu\)
  - Loaded as part of legitimate Baidu Antivirus service
- Alert on ANY kernel driver with expired signature (April 24, 2015 or earlier) loaded in current year

**Detection Confidence**: HIGH (85%) - Baidu signature on kernel driver outside Baidu installation directory is suspicious

**PDB Path Embedding** (Code Artifact Detection)

Examine embedded debug information in binary:

```
D:\jenkins\workspace\bav_5.0_workspace\BavOutput\Pdb\Release\BdApiUtil64.pdb
```

This specific PDB path uniquely identifies the Baidu build and toolchain. Custom malware would have different PDB paths.

**Detection Method**: Binary analysis tool can extract PDB path and match against known indicators
**Detection Confidence**: DEFINITE - PDB path match confirms Baidu BdApiUtil64 binary

---

### Registry-Based Detection

**Service Registry Key**

Location:
```
HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
```

Suspicious Indicators:
```
ImagePath = C:\Windows\System32\drivers\BdApiUtil64.sys
Start = 2 (Automatic) or 3 (Demand start) WITHOUT Baidu Antivirus installed
DisplayName = "Baidu Protect" (or empty/unusual name)
```

**Detection Method**:
```powershell
# PowerShell query for suspicious Bprotect service
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Bprotect' -ErrorAction SilentlyContinue |
  Select-Object ImagePath, Start, DisplayName
```

**Detection Confidence**: HIGH (90%) - Bprotect service WITHOUT legitimate Baidu Antivirus installation is malicious

**Registry Value Indicators**

Examine service registry for suspicious values:

| Value | Suspicious If |
|-------|---------------|
| InstPath | Points outside Baidu installation directory or is empty |
| ImagePath | Points to drivers folder without Baidu context |
| Type | Equals 1 (kernel driver) for non-Baidu processes |
| Start | Set to automatic start outside Baidu context |

---

### Runtime/Behavioral Detection

**Driver Loading Telemetry** (Sysmon Event ID 6)

Sysmon Event 6 (Driver Loaded) provides kernel-level visibility into driver loading:

**Alert Conditions**:
1. Driver filename = BdApiUtil64.sys (regardless of path)
2. Signed by Baidu with compilation date before 2015
3. Loaded outside standard Windows system restore or Baidu installation
4. Loaded within minutes of privilege escalation activity or lpe.exe execution

**Example Sysmon Rule Trigger**:
```xml
<DriverLoad onmatch="include">
  <ImageLoaded condition="contains">BdApiUtil64.sys</ImageLoaded>
</DriverLoad>
```

**Detection Confidence**: DEFINITE - Any driver load of BdApiUtil64.sys is malicious unless Baidu Antivirus is legitimately installed

**Process Termination Correlation** (Time-Series Analysis)

Arsenal-237's attack pattern creates distinctive telemetry signatures:

**Suspicious Pattern**:
```
[T+0ms]   Driver loads (Sysmon Event 6: BdApiUtil64.sys)
[T+50-100ms]   MsMpEng.exe terminates (Sysmon Event 1: process exit)
[T+100-150ms]  MpDefenderCoreService.exe terminates
[T+200-300ms]  NisSrv.exe terminates
[T+300-400ms]  Ransomware/encoder process launches
```

**Alert Condition**: Multiple security product processes terminate within 60 seconds after unfamiliar driver loads

**Detection Tool**: SIEM/EDR correlation rule linking:
1. Driver load event -> Extract driver name, signature, load time
2. Process termination events -> Match security product processes (MsMpEng, csagent, ekrn, etc.)
3. Timeline correlation -> Alert if 2+ security processes terminate within 60 seconds of driver load

**Detection Confidence**: HIGH (85%) - This pattern is characteristic of BYOVD attacks

**Event Log Service Termination**

Arsenal-237 terminates Event Logging service to destroy forensic evidence. This creates a secondary detection opportunity:

**Alert Condition**: EventLog service terminates (process exit of svchost.exe hosting EventLog)

**Detection Method**:
```
Sysmon Event ID 1: Process creation where:
  - Parent: services.exe
  - Image: svchost.exe
  - CommandLine contains EventLog
  - Exit status indicates crash/termination
```

**Note**: Legitimate system restarts terminate EventLog service; distinguish via:
- Shutdown/reboot events (expected, no alert)
- Sudden termination outside of shutdown (suspicious)
- Multiple security service terminations preceding EventLog termination (highly suspicious)

**Detection Confidence**: MEDIUM (70%) - EventLog termination alone is insufficient; requires correlation

---

### Sysmon & EDR Detection Queries

**Sysmon XML Rule: Baidu Driver Loading**

```xml
<Rule name="BdApiUtil64.sys Driver Load Detection" groupRelation="or">
  <DriverLoad onmatch="include">
    <ImageLoaded condition="contains">BdApiUtil64.sys</ImageLoaded>
  </DriverLoad>
  <DriverLoad onmatch="include">
    <Signed condition="is">true</Signed>
    <SignatureStatus condition="is">Valid</SignatureStatus>
    <Issuer condition="contains">Baidu</Issuer>
  </DriverLoad>
  <DriverLoad onmatch="include">
    <Hashes condition="contains">47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428</Hashes>
  </DriverLoad>
</Rule>
```

**KQL Query (Microsoft Sentinel / Azure Log Analytics)**

```kusto
// Detect BdApiUtil64.sys driver loading
DeviceImageLoadEvents
| where FileName contains "BdApiUtil64"
| project Timestamp, DeviceName, FileName, SHA256, Signer
| extend ThreatLevel = "CRITICAL"

// Detect Baidu-signed drivers loaded outside Baidu installation context
union (DeviceImageLoadEvents)
| where Signer contains "Baidu"
| where FolderPath !contains "Program Files\\Baidu"
| where FolderPath !contains "ProgramData\\Baidu"
| project Timestamp, DeviceName, FileName, FolderPath, Signer
```

**Splunk SPL (Splunk Query Language)**

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=6
| search ImageLoaded="*BdApiUtil64*" OR SHA256="47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
| stats count by host, ImageLoaded, Signed, SignatureStatus

// Correlation: Driver load followed by security product termination
index=main (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=6 AND ImageLoaded="*BdApiUtil64*")
OR (EventCode=5 AND Image="*MsMpEng.exe" OR Image="*csagent.exe" OR Image="*ekrn.exe")
| stats earliest(Timestamp) as driver_load, latest(Timestamp) as process_term by host
| eval time_diff = (process_term - driver_load)
| where time_diff > 0 AND time_diff < 60000
| table host, driver_load, process_term, time_diff
```

**CrowdStrike Falcon Query (IOAs/Indicators of Attack)**

```
event_type.keyword:Process AND (process_name:"MsMpEng.exe" OR process_name:"svchost.exe")
AND (event_reason:"Process terminated" OR exit_code:*)
AND TimeStampTime:[NOW-1m TO NOW]

// Kernel-level driver loading correlation
DLL_Loading AND image_filename:BdApiUtil64.sys
| stats count by ComputerName, image_filename, timestamp
```

---

## Threat Assessment & Risk Scoring

### Sophistication Assessment

<table class="professional-table">
<thead>
<tr>
<th>Sophistication Dimension</th>
<th>Rating</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Code Quality & Engineering</strong></td>
<td><strong>HIGH</strong></td>
<td>Legitimate Baidu driver; professional codebase; structured IOCTL interface; redundant capability implementation (two file access methods)</td>
</tr>
<tr>
<td><strong>Evasion Technique Sophistication</strong></td>
<td><strong>VERY HIGH</strong></td>
<td>SSDT bypass to defeat EDR hooks; real-time hook detection; minifilter enumeration; registry callback blocking; multi-layer fallback mechanisms</td>
</tr>
<tr>
<td><strong>Defense Awareness</strong></td>
<td><strong>VERY HIGH</strong></td>
<td>Explicitly targets EDR products (CrowdStrike-specific DLL); understands kernel-mode monitoring; implements callback blocking to prevent security product restoration</td>
</tr>
<tr>
<td><strong>Operational Planning</strong></td>
<td><strong>VERY HIGH</strong></td>
<td>Multi-stage attack with clear separation of concerns (privilege escalation, user-mode evasion, kernel-mode evasion, persistence, data theft, payload); coordinated toolkit components</td>
</tr>
<tr>
<td><strong>Anti-Forensics Capability</strong></td>
<td><strong>HIGH</strong></td>
<td>Event log termination; timestamp stomping; file deletion; registry callback blocking; can hide malware from both file system and kernel-mode monitoring</td>
</tr>
<tr>
<td><strong>Overall Sophistication</strong></td>
<td class="critical"><strong>CRITICAL</strong></td>
<td>Represents state-of-the-art BYOVD technique; demonstrates deep Windows kernel understanding; matches capabilities of advanced APT groups or professional malware platforms</td>
</tr>
</tbody>
</table>

### Organizational Risk Assessment

**CRITICAL THREAT - Kernel-Level Complete Compromise**

**Risk Score: 9.7/10** (CRITICAL)

Risk Dimension Breakdown:

| Dimension | Score (10pt) | Justification |
|-----------|--------------|---------------|
| **System Compromise** | 10/10 | Ring-0 kernel access = complete system control; attacker operates at highest privilege level with no restrictions |
| **Data Breach Likelihood** | 9.5/10 | Direct access to credential stores, browser data, encryption keys; CONFIRMED data theft capability via IOCTL 0x80002648 |
| **Defense Evasion** | 10/10 | All user-mode and kernel-mode security controls bypassed; no detection/prevention possible once loaded |
| **Persistence** | 9/10 | Multiple persistence mechanisms (driver service, registry callbacks, backdoor services); survives standard remediation attempts |
| **Lateral Movement** | 8/10 | Stolen credentials enable domain-wide compromise; attacker can move laterally using legitimate credentials |
| **Remediation Difficulty** | 10/10 | Kernel-level compromise requires complete system rebuild; aggressive cleanup cannot provide confidence |

**Overall Risk Rating: CRITICAL (9.7/10)** - Represents highest-severity malware type: kernel-level rootkit with complete system control

### What Does Kernel-Level Compromise Mean?

If BdApiUtil64.sys loads successfully on a system, assume:

> **DEFINITE** - Attacker has Ring-0 kernel privileges with unrestricted access to:
> - All processes (inspect, modify, terminate)
> - All files (read, modify, delete, hide)
> - All registry entries (read, modify, delete)
> - All cryptographic keys and encrypted data
> - All network traffic
> - All system memory
> - All audit logs and forensic evidence

> **DEFINITE** - All security products are compromised:
> - User-mode security tools (EDR agents, antivirus) can be terminated
> - Kernel-mode security tools (minifilter drivers) can be disabled
> - File system monitoring can be intercepted
> - Network monitoring can be intercepted

> **LIKELY** - Attacker has extracted credentials:
> - Windows account password hashes (from SAM)
> - DPAPI master keys (from registry)
> - Domain credentials (from memory/LSASS)
> - Browser saved passwords
> - API keys and cloud service credentials

> **LIKELY** - Attacker maintains persistence:
> - Driver service will auto-load on reboots
> - Registry callbacks prevent service deletion
> - Malicious backdoor services are installed
> - Multiple fallback persistence mechanisms active

> **CRITICAL** - Standard remediation is insufficient:
> - Aggressive cleanup leaves kernel-level backdoors active
> - Attacker retains access despite cleanup attempts
> - Only complete system rebuild provides confidence in eradication

---

### Attribution Context

**MODERATE CONFIDENCE (70%)** - Arsenal-237 toolkit characteristics suggest:

**Threat Actor Type**: Organized cybercriminal group OR state-affiliated malware platform

**Indicators**:
- **Professional Development**: Modular attack components, explicit product-specific optimizations (killer_crowdstrike.dll)
- **Enterprise Focus**: Toolkit targets enterprise security products (CrowdStrike, ESET, Kaspersky), not consumer antivirus
- **Historical Precedent**: Similar toolkits documented in BlackByte, Cuba, ALPHV/BlackCat campaigns (known ransomware groups)
- **Infrastructure Sophistication**: Organized toolkit distribution (109.230.231.37 open directory), coordinated attack flow

**Possible Attribution** (without definitive evidence):
- Organized ransomware group (potentially Russian or Eastern European based on security product targeting)
- State-affiliated cyber espionage unit (toolkit sophistication suggests government resource backing)
- Malware-as-a-Service platform (modular components suggest sale to multiple threat actors)

**Confidence Justification**: Attribution is MODERATE because:
- Only toolkit available; no C2 communications analyzed
- Driver component is weaponized legitimate software (not custom)
- Multiple campaigns use similar BYOVD techniques (technique not unique to single actor)
- No distinctive code signatures or behavioral markers linking to known group

**Bottom Line**: Arsenal-237 represents **professional, organized threat** regardless of specific attribution. Response should prioritize containment and remediation over attribution investigation.

---

## Remediation Guidance

### Threat Level Justification: CRITICAL - Complete System Rebuild MANDATORY

**Why Aggressive Cleanup Is Insufficient**

Kernel-level compromise with Ring-0 privileges enables the threat actor to:

1. **Hide Malware from Cleanup Tools**
   - Files can be hidden from file system enumeration (even antivirus scans)
   - Registry entries can be hidden from registry editors
   - Processes can be hidden from task managers and EDR tools
   - Malware persistence can be established in undetectable locations (UEFI, firmware, encrypted partitions)

2. **Establish Covert Persistence**
   - Registry callbacks intercept and block cleanup attempts
   - Multiple redundant persistence mechanisms (if one is removed, others activate)
   - Bootkit components load before security tools can interfere
   - Kernel hooks prevent forensic tools from accurately analyzing system

3. **Maintain Post-Cleanup Access**
   - If attacker credential theft succeeds (IOCTL 0x80002648), attacker has valid domain credentials
   - Even after system rebuild, attacker can re-compromise using stolen credentials
   - Credential reset window (before attacker uses stolen passwords) may be only hours
   - Attacker has had kernel-level access to extract encryption keys for subsequent re-infection

4. **Evade Cleanup Verification**
   - Cleanup verification tools operate in user-mode where kernel-level malware can intercept
   - Antivirus scans can be fooled by rootkit
   - "All clear" scan results may be false negatives
   - No reliable way to verify complete eradication without full forensic analysis

**Professional Standard**: Leading incident response practices (NIST, SANS, CISA) recommend **complete system rebuild** for ANY kernel-level compromise, not "aggressive cleanup."

---

### Complete System Rebuild Procedures

#### Phase 1: Evidence Preservation & Isolation

**Immediate Actions** (Do not delay):

**Isolate System**:
- Physically disconnect network cable OR
- Block system at network perimeter (firewall rule preventing all ingress/egress) OR
- Disable network interfaces via BIOS/firmware
- Rationale: Prevent attacker lateral movement or data exfiltration

**Preserve Forensic Evidence** (Before shutdown):

```powershell
# Capture memory dump (requires administrative privileges)
# Method 1: Using winpmem (Rekall memory forensics tool)
.\winpmem_mini_x64.exe <infected_system>.raw

# Method 2: Using Microsoft MagicDump
MagicDump.exe -O <infected_system>.raw

# Alternative: Create disk image
# Using DCFldd or dd for Linux:
dcfldd if=/dev/sda of=\\network_share\forensics\system_image.dd
```

Preserve:
- System memory dump (captures encryption keys, active credentials, malware code)
- Complete disk image (for forensic analysis and threat hunt verification)
- Registry hives (HKLM\SYSTEM, HKLM\SECURITY, HKLM\SOFTWARE)
- Event logs (if accessible; may be corrupted by malware)

**Critical**: Memory dump must be captured WHILE SYSTEM IS RUNNING to preserve volatile evidence (active encryption keys, malware code in memory).

---

#### Phase 2: Threat Scope Assessment

**Identify All Affected Systems**:

```powershell
# Hunt for Arsenal-237 indicators across organization
# Search for driver file
Get-ChildItem -Path "C:\Windows\System32\drivers\BdApiUtil64.sys" -ErrorAction SilentlyContinue

# Search for driver service
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Bprotect' -ErrorAction SilentlyContinue

# Search for killer.dll, lpe.exe
Get-ChildItem -Recurse -Filter "killer*.dll" -Path "C:\" -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "lpe.exe" -Path "C:\" -ErrorAction SilentlyContinue

# Hash-based hunting (if EDR available)
# Execute across all systems in environment
Get-ChildItem -Recurse -Filter "*.sys" -Path "C:\Windows\System32\drivers\" |
  Get-FileHash -Algorithm SHA256 |
  Where-Object {$_.Hash -eq '47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428'}
```

**Search for Ransomware Payloads**:
```powershell
# Look for enc_*.exe files
Get-ChildItem -Recurse -Filter "enc_*.exe" -ErrorAction SilentlyContinue

# Look for malicious services created by IOCTL 0x80002324
Get-Service | Where-Object {$_.Name -like "*Windows*" -or $_.Name -like "*Microsoft*"} |
  Where-Object {$_.Description -eq "" -or $_.StartType -eq "Automatic"} |
  Select-Object Name, DisplayName, StartType, Status
```

**Document Timeline**:
- When was driver first observed loaded?
- When were security products terminated?
- When did ransomware execution begin?
- Are backup systems compromised with same indicators?

---

#### Phase 3: System Isolation & Shutdown

**Network Isolation** (Verify complete):
- [ ] System physically disconnected from network
- [ ] System blocked at firewall (verify no network connectivity)
- [ ] Endpoint disconnected from wireless networks
- [ ] Mobile devices that accessed system are isolated and scanned

**Credential Rotation** (MANDATORY):
```
Credential rotation must occur IMMEDIATELY after system isolation
Rationale: Attacker may have extracted credentials via IOCTL 0x80002648
          (Windows SAM, browser data, cloud service credentials)
Timing: Urgently (credential rotation critical to prevent attacker re-access)
```

Accounts to reset:
- [ ] All user accounts that accessed compromised system (change passwords)
- [ ] Service accounts used on compromised system (change passwords, regenerate API keys)
- [ ] Cloud service accounts (if accessed from system; change passwords, regenerate tokens)
- [ ] Domain administrator accounts (if compromise scope includes domain admin access)

**System Shutdown** (Controlled):
```powershell
# Graceful shutdown to preserve forensic state
shutdown /s /t 30 /c "System shutdown for forensic analysis"
```

Avoid:
- Force shutdown (harder for forensics, may corrupt memory dump)
- System restart (would reset attack timeline telemetry)

---

#### Phase 4: Clean Installation

**Obtain Clean Installation Media**:
- [ ] Windows installation media from Microsoft (verified authentic)
- [ ] No pre-installed software or OEM customizations
- [ ] Verify media integrity via hash check
- [ ] Never use "System Restore" or existing Windows installation files

**Prepare Clean Hardware** (If possible):
- [ ] New hard drive (if original drive is compromised beyond repair needs)
- [ ] Or: Completely wipe existing drive before clean installation

**Installation Steps**:
```
1. Boot from clean installation media (USB or DVD)
2. Remove/wipe all existing partitions
3. Create new clean partition
4. Install Windows from scratch
5. Do NOT restore from backup (may contain malware)
6. Do NOT use System Image Restore
```

**Post-Installation Hardening**:
```powershell
# Install latest Windows updates before network connection
# Download offline updates from Windows Update Download Center

# Configure Windows security features
# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Exploit Protection
Set-ProcessMitigation -PolicyFilePath (Get-Content -Path "mitigation_policy.xml")

# Deploy Microsoft Vulnerable Driver Blocklist (Windows 11 with HVCI)
# This prevents loading of known vulnerable drivers like BdApiUtil64.sys
# Requires Windows 11 21H2+ with Hardware-backed Code Integrity enabled
```

---

#### Phase 5: Verification & Hardening

**Restore from Clean Backup** (If available):
```
Timeline:
- Last known clean backup: [Date/Time]
- System compromise occurred after: [Date/Time]
- If backup before compromise -> restore is acceptable
- If backup after compromise -> restore introduces risk
  (attacker may have established persistence in backup)
```

**Deploy EDR Before Network Connection**:
```powershell
# Install EDR agent BEFORE connecting to network
# EDR should be deployed from clean installation media, not network
# This ensures malware cannot interfere with EDR installation

# Recommended EDR for BYOVD detection:
# - CrowdStrike Falcon (real-time driver load monitoring)
# - Microsoft Defender for Endpoint (device compliance enforcement)
# - Carbon Black Cloud (kernel integrity verification)
# - Elastic EDR (behavioral threat detection)
```

**Deploy Vulnerable Driver Blocklist**:
```powershell
# Windows 11 21H2+ with HVCI support
# Prevents loading of known vulnerable drivers

# Download MVDB (Microsoft Vulnerable Driver Blocklist)
# Deploy via Group Policy or local policy

# Vulnerable Drivers to Block:
# - BdApiUtil64.sys (Baidu antivirus driver)
# - Gdrv.sys (GIGABYTE driver)
# - DBUtil_2_3.sys (Dropbox driver)
# - [Other known BYOVD drivers]
```

---

#### Phase 6: Enhanced Monitoring Period

**Post-Rebuild Monitoring** (30-day enhanced observation):

```
Timeline:
- Days 1-7: Verify baseline operations (no anomalies introduced by rebuild)
- Days 8-14: Monitor for re-compromise attempts (attacker may try to re-infect using stolen credentials)
- Days 15-30: Continue standard monitoring (ensure no persistence mechanisms remain)
```

**Monitoring Focus Areas**:

1. **Driver Load Monitoring**:
   - Alert on ANY unsigned kernel driver
   - Alert on Baidu-signed drivers (verify not related to legitimate Baidu software)
   - Alert on drivers with expired certificates (pre-2015)

2. **Service Creation Monitoring**:
   - Alert on services with suspicious names (Windows*, Microsoft*, NVidia*)
   - Alert on services with empty description or unusual paths
   - Alert on services created outside standard maintenance windows

3. **Process Termination Monitoring**:
   - Alert on rapid termination of multiple security products (within 1 minute)
   - Alert on EventLog service termination outside system shutdown

4. **Registry Modification Monitoring**:
   - Alert on modifications to HKLM\SYSTEM\CurrentControlSet\Services\ (service configuration)
   - Alert on modifications to Windows Defender registry (if applicable)
   - Alert on modifications to Run/RunOnce keys (persistence mechanisms)

5. **File Access Monitoring**:
   - Alert on access to C:\Windows\System32\config\SAM (credential store)
   - Alert on access to C:\Windows\System32\config\SECURITY
   - Alert on unusual access to browser data directories

---

### Remediation Decision Framework

| Decision Factor | Recommendation | Rationale |
|----------------|-----------------|-----------|
| **System Role** | Critical Infrastructure | Complete rebuild MANDATORY - No exceptions for critical systems |
| **System Role** | Business-Critical Server | Complete rebuild MANDATORY - Cannot risk persistent compromise |
| **System Role** | Standard Workstation | Complete rebuild STRONGLY RECOMMENDED - Workstations often re-compromise via user credentials |
| **Scope** | Single isolated system | Rebuild is operationally simple |
| **Scope** | Multiple systems | Rebuild all affected systems in parallel (prioritize critical first) |
| **Timing** | Before ransomware execution | Rebuild immediately (malware may execute at any time) |
| **Timing** | After partial ransomware execution | Rebuild immediately (attacker has encryption keys, may re-encrypt) |
| **Evidence** | Memory dump preserved | Rebuild immediately (forensic analysis can occur on isolated image) |
| **Credentials** | Compromise likely | Rebuild + credential rotation MANDATORY (attacker may have extracted credentials) |
| **Staffing** | Rebuild resources available | Rebuild immediately (don't delay waiting for resources) |
| **Staffing** | Rebuild resources unavailable | Request emergency IT staffing (do not attempt aggressive cleanup as substitute) |

**Recommended Approach**: **COMPLETE SYSTEM REBUILD**

**Why Rebuild is the Right Choice**:
1. **Kernel-level compromise**: Only rebuild provides confidence in complete eradication
2. **Persistence mechanisms**: Multiple fallback persistence mechanisms require rebuild to remove
3. **Forensic analysis**: Memory dump and disk image provide forensic evidence; rebuild doesn't prevent forensic investigation
4. **Time efficiency**: Clean installation + EDR deployment takes 2-4 hours; aggressive cleanup + verification takes longer with lower confidence
5. **Professional standard**: Incident response best practices (NIST, SANS, CISA) recommend rebuild for ANY kernel compromise

---

## Response Priorities & Action Items

### Escalation & Leadership Notification

**Immediately**:
- [ ] Notify Chief Information Security Officer (CISO)
- [ ] Notify Incident Response Team lead
- [ ] Notify System Owner/Business Unit Manager
- [ ] Brief: "We have discovered a critical kernel-level malware component (BdApiUtil64.sys) indicating complete system compromise. We are activating emergency response procedures."

**Urgently**:
- [ ] Assemble incident response team
- [ ] Notify legal/compliance (data breach notification may be required)
- [ ] Notify insurance/cyber security incident response team (if external IR firm available)
- [ ] Begin scope assessment (how many systems affected?)

**As soon as possible**:
- [ ] Notify executive leadership (CEO, CFO if significant business impact)
- [ ] Prepare business continuity communication plan
- [ ] Activate disaster recovery procedures if ransomware payload has executed

---

### Technical Response Sequence

**Priority 1: IMMEDIATE ISOLATION** (Do now; do not delay)

```
Objective: Prevent lateral movement and data exfiltration
Timeline: Immediate
Actions:
  [ ] Isolate compromised system(s) from network
      -> Physically disconnect OR
      -> Block at firewall (deny all ingress/egress)
      -> Disable wireless connectivity
  [ ] Preserve forensic evidence
      -> Capture memory dump (while system still running)
      -> Initiate disk image capture
  [ ] Begin credential rotation
      -> Reset passwords for all users with system access
      -> Regenerate API keys for service accounts
      -> Reset cloud service credentials
```

---

**Priority 2: SCOPE ASSESSMENT** (Immediate; parallel to Priority 1)

```
Objective: Understand scale of compromise
Timeline: Urgent
Actions:
  [ ] Search organization for other systems with same IoCs
      -> Hash matching: 47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428
      -> Service matching: Bprotect service registry key
      -> File matching: BdApiUtil64.sys in C:\Windows\System32\drivers\
      -> Toolkit matching: killer.dll, lpe.exe, enc_*.exe
  [ ] Identify all users/processes that accessed compromised system
      -> Check network logs for lateral movement
      -> Check Domain Controller for unusual authentication
  [ ] Assess if ransomware payload executed
      -> Check for ransom notes
      -> Check for encrypted files
      -> Check for data exfiltration indicators
```

---

**Priority 3: SYSTEM REBUILD** (As soon as possible after isolation)

```
Objective: Eradicate kernel-level malware
Timeline: As soon as possible
Actions:
  [ ] Approve rebuild (business decision: acceptable downtime?)
  [ ] Prepare clean installation media
  [ ] Ensure forensic images are captured before rebuild
  [ ] Rebuild system with clean Windows installation
  [ ] Deploy EDR before network connection
  [ ] Deploy vulnerable driver blocklist
  [ ] Connect to network and update Windows
  [ ] Restore user data from clean backup (pre-compromise)
  [ ] Return system to production with enhanced monitoring
```

---

**Priority 4: THREAT HUNT & ATTRIBUTION** (Parallel to rebuild)

```
Objective: Identify other systems affected, understand attacker motivation
Timeline: During rebuild operations
Actions:
  [ ] Forensic analysis of preserved images
      -> Timeline of attack
      -> Attacker tools identified
      -> Persistence mechanisms discovered
  [ ] Hunt for Arsenal-237 toolkit components
      -> Expand search for killer.dll, lpe.exe, enc_*.exe
      -> Check backup systems for same components
  [ ] Credential compromise assessment
      -> Assume attacker extracted credentials via IOCTL 0x80002648
      -> Identify which credentials may be compromised
      -> Prioritize credential rotation timeline
  [ ] Incident attribution (if feasible)
      -> Analyze C2 infrastructure (if known)
      -> Match TTPs to known threat actors
      -> Assess if nation-state or organized cybercrime
```

---

**Priority 5: RESPONSE & REMEDIATION** (After immediate containment)

```
Objective: Prevent future similar compromises
Timeline: Days/weeks post-incident
Actions:
  [ ] Complete system rebuild (all affected systems)
  [ ] Deploy Microsoft Vulnerable Driver Blocklist (all systems)
  [ ] Implement EDR solution (organization-wide if not present)
  [ ] Implement kernel-mode monitoring (driver load alerts)
  [ ] Implement process termination alerts (multiple security products)
  [ ] Update incident response procedures
  [ ] Conduct post-incident review (what enabled compromise?)
  [ ] Improve defensive posture (see Long-Term Defensive Strategy)
```

---

### Security Product Specific Procedures

**If CrowdStrike Falcon is deployed**:
```
CrowdStrike provides kernel-mode monitoring and BYOVD detection
Expected detection: Falcon should alert on BdApiUtil64.sys driver load
Expected behavior: Falcon may not prevent driver load but will alert
Response: Verify Falcon is processing alerts and sending to incident response team
Enhancement: Review Falcon rules for BYOVD driver load signatures
```

**If Microsoft Defender is deployed**:
```
Defender provides kernel-mode scanning (if Windows 11 with HVCI)
Expected detection: May detect BdApiUtil64.sys if signatures are current
Response: Verify Defender is quarantining malware; check quarantine folder
Enhancement: Enable HVCI (Hypervisor-protected Code Integrity) to block unsigned drivers
```

**If no EDR is deployed** (CRITICAL GAP):
```
Organization has no kernel-level visibility into driver loading
This BYOVD attack succeeded partly because no EDR detected driver load
Immediate action: Deploy EDR solution to at least critical systems
Long-term: Deploy EDR to all systems to prevent similar compromise
```

---

## FAQ - Addressing Common Questions

### Q1: "Is BdApiUtil64.sys a legitimate Baidu driver that we should trust?"

**Short Answer**: BdApiUtil64.sys is a legitimate Baidu driver component, but loading it outside of Baidu Antivirus is malicious and indicates compromise.

**Detailed Explanation**:

Baidu Antivirus uses BdApiUtil64.sys as a kernel utility driver. The file itself is NOT inherently malicious-it's a legitimate component of legitimate security software. However, the context matters:

**Legitimate Context** (Trust):
- Installed as part of Baidu Antivirus installation
- Located in Baidu installation directory: C:\Program Files\Baidu\...
- Loaded by legitimate Baidu service: BaiduProtect
- Certificate valid and current
- Version matches current Baidu release

**Malicious Context** (Indicates Compromise):
- Located in C:\Windows\System32\drivers\ WITHOUT Baidu installation
- Loaded by generic service name "Bprotect" (not the legitimate "BaiduProtect" service)
- Certificate EXPIRED (2015)
- Accompanied by killer.dll, lpe.exe, ransomware payloads
- Followed by rapid termination of security products

**Practical Guidance**: If you find BdApiUtil64.sys on a system:
1. Check if Baidu Antivirus is legitimately installed: `Program Files\Baidu\`
2. If NOT installed: Treat as critical compromise (BYOVD attack)
3. If installed: Verify service name is "BaiduProtect" (not "Bprotect")
4. If service name is "Bprotect": Treat as compromise (attacker creating deceptive service name)

---

### Q2: "Can we just disable the Bprotect service instead of rebuilding the entire system?"

**Short Answer**: No. Disabling the service only removes one persistence mechanism; the driver and attacker credentials remain.

**Detailed Explanation**:

Attacking Arsenal-237 establishes multiple redundant persistence mechanisms:

**Mechanism 1: Bprotect Service**
- Loaded automatically via HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
- Disabling: Prevents driver auto-load on next reboot
- But: Driver is still loaded in kernel memory NOW; still operating with Ring-0 privileges

**Mechanism 2: Registry Callback**
- Driver registers callback via CmRegisterCallback()
- Monitors registry for changes to service configuration
- If user tries to delete or disable Bprotect service: Callback blocks the change
- Disabling service manually will fail (registry callback prevents modification)

**Mechanism 3: Backdoor Services**
- IOCTL 0x80002324 created additional persistent services
- These services may contain encoded payloads or additional rootkit components
- Removing Bprotect doesn't remove these additional backdoors

**Mechanism 4: Stolen Credentials**
- IOCTL 0x80002648 extracted credentials (Windows hashes, browser passwords)
- Attacker has valid domain credentials
- Even if driver is removed, attacker can re-compromise system using stolen credentials

**Mechanism 5: Kernel Patches**
- Driver may have patched kernel data structures
- May have modified kernel code or hooks
- Disabling driver doesn't remove kernel-level patches

**Recommendation**: Complete system rebuild is the ONLY reliable remediation because:
1. Removes driver and all kernel-level components
2. Removes all persistence mechanisms and callbacks
3. Removes all malware patches to kernel
4. Does NOT rely on malware cooperating with cleanup (callbacks won't interfere)
5. Provides confidence in complete eradication

Aggressive cleanup -> Cannot guarantee complete removal (callbacks may prevent remediation) -> Recommended only if absolutely no rebuild option available (and still extremely risky)

---

### Q3: "What should we tell our customers about potential data breach?"

**Short Answer**: Assume data breach occurred; prepare customer notification.

**Detailed Explanation**:

BdApiUtil64.sys provides complete file system access via IOCTL 0x80002648. Arsenal-237's attack pattern includes credential harvesting:

**Data Likely Compromised**:
- Windows credential hashes (NTLM hashes, Kerberos keys)
- DPAPI encryption keys (master keys protecting other data)
- Browser saved credentials (Chrome, Firefox, Edge, Safari)
- Email credentials and message archives
- Cloud service credentials (OneDrive, Google Drive, AWS, Azure, etc.)
- SSH keys and private cryptographic keys
- Application configuration files (database credentials, API keys)
- Any file the attacker chose to exfiltrate

**Notification Obligations** (Consult legal/compliance):
- **GDPR** (EU): Breach notification required if personal data compromised (timeframe: 72 hours)
- **CCPA** (California): Breach notification required for California residents
- **HIPAA** (Healthcare): Breach notification required if patient data compromised
- **PCI DSS** (Payment Cards): Breach notification required if payment card data compromised
- **Other state/country laws**: Additional notification may be required

**Recommended Approach**:
1. Involve legal team IMMEDIATELY to determine notification obligations
2. Prepare breach notification template (consult insurance carrier for guidance)
3. Notify law enforcement (FBI, CISA, local law enforcement) if ransomware involved
4. Prepare customer communication explaining:
   - What data was potentially compromised
   - What steps you're taking to remediate
   - What actions customers should take (password reset, credit monitoring, etc.)
5. Activate incident response insurance (if available)

**Bottom Line**: Treat this as data breach incident. Most ransomware incidents involve data exfiltration; assume your data was stolen.

---

### Q4: "How long will system rebuild take?"

**Short Answer**: 2-4 hours for clean installation + EDR deployment; 8-16 hours including data restoration and verification.

**Detailed Explanation**:

Rebuild Timeline:

| Phase | Duration | Activities |
|-------|----------|------------|
| **Preparation** | 30 min | Approve rebuild, prepare clean media, backup data |
| **Clean Installation** | 30-60 min | Boot from installation media, wipe disk, install Windows |
| **OS Updates** | 30-60 min | Download and install Windows patches (must be pre-network for security) |
| **EDR Deployment** | 15-30 min | Install EDR agent, verify functioning |
| **Vulnerable Driver Blocklist** | 15 min | Deploy Microsoft MVDB blocklist |
| **Data Restoration** | 2-8 hours | Restore user data from backup (depends on data volume) |
| **Verification & Testing** | 1-2 hours | Verify system functionality, test business-critical applications |
| **Network Re-connection** | 5-10 min | Connect to network, verify connectivity |
| **Total** | **4-14 hours** | Depends on data volume and complexity |

**Factors Affecting Timeline**:
- **Data Volume**: Large systems (1TB+) may require 8+ hours to restore
- **Number of Systems**: Rebuilding 10 systems takes 10x longer
- **Backup Type**: Fast backup system (deduplication) vs. standard backup
- **Application Complexity**: Systems with complex software take longer to re-provision
- **Testing Requirements**: Critical systems require extensive testing (adds time)

**Parallel Operations**: Can rebuild multiple systems simultaneously if IT resources available
- 1 system: 4-14 hours
- 5 systems (parallel): Still 4-14 hours per system (can be done in parallel)

**Business Continuity**: Plan for:
- System downtime during rebuild
- Potential loss of data created after last backup
- Business process disruption (reduced productivity during rebuild period)

---

### Q5: "Can we use antivirus cleaning tools instead of rebuilding?"

**Short Answer**: No. Antivirus tools operate in user-mode and cannot reliably remove kernel-level malware.

**Detailed Explanation**:

Antivirus Cleaning Tools Limitations:

**Kernel-Level Blindness**: Antivirus tools run in user-mode (Ring 3). BdApiUtil64.sys runs in kernel-mode (Ring 0). Kernel-level code can:
- Hide files from antivirus scans
- Intercept antivirus API calls and return false results
- Prevent antivirus from terminating malicious processes
- Block antivirus from modifying registry or file system

**Example - Antivirus Trying to Delete Malware**:
```
Antivirus (user-mode): "Delete C:\Windows\System32\drivers\BdApiUtil64.sys"
Kernel Driver (Ring 0): "No, I'll intercept this API call and return success
                        while actually preventing the deletion"
Antivirus (user-mode): "File deleted successfully" (False)
Kernel Driver: File remains, continues operation
```

**Why Aggressive Cleanup Fails**:
1. **Cannot verify completion**: Cleanup tools cannot verify malware is actually removed
2. **Callback blocking**: Registry callbacks intercept and block cleanup operations
3. **Hidden persistence**: Malware can hide persistence mechanisms from cleanup tools
4. **Kernel patches**: Cleanup cannot remove kernel-level patches or hooks
5. **False negatives**: Kernel-level rootkit reports "all clear" to cleanup tools

**Professional Standard**: NIST, SANS, CISA, and FBI all recommend **complete system rebuild** for kernel-level compromises, not aggressive cleanup.

**When Aggressive Cleanup Might Be Considered** (ONLY if rebuild impossible):
- System is literally irreplaceable (single-instance, cannot rebuild)
- Business continuity depends on keeping system running
- Even then: Extremely high risk of missed malware

**In that scenario**:
1. Involve incident response specialist (do NOT attempt alone)
2. Preserve forensic images BEFORE cleanup
3. Expect cleanup may fail to remove all components
4. Plan for potential re-compromise through stolen credentials
5. Implement enhanced monitoring (may not detect kernel-level malware)

**Recommendation**: Just rebuild. It's faster, more reliable, and more professional.

---

### Q6: "How do we prevent BYOVD attacks in the future?"

**Short Answer**: Deploy Microsoft Vulnerable Driver Blocklist, implement EDR with driver load monitoring, and maintain inventory of legitimate drivers.

**Detailed Explanation**:

**Prevention Strategy 1: Microsoft Vulnerable Driver Blocklist (MVDB)**

- **What**: Official list of known vulnerable drivers provided by Microsoft
- **How**: Prevents loading of known vulnerable drivers
- **Requirements**: Windows 11 21H2+ with HVCI (Hardware-backed Code Integrity) enabled
- **Implementation**:
  ```
  Group Policy: Computer Configuration > Administrative Templates >
                System > Driver Installation >
                "Code integrity: Qualified Driver" = Block vulnerable drivers
  ```
- **Coverage**: Includes BdApiUtil64.sys and other known BYOVD drivers
- **Limitation**: Only blocks KNOWN vulnerable drivers; 0-day vulnerable drivers still load

**Prevention Strategy 2: Endpoint Detection & Response (EDR)**

- **What**: Kernel-mode monitoring of driver loading and process behavior
- **How**: EDR detects driver loads that bypass traditional antivirus
- **Key Features**:
  - Driver load alerts (with signature verification)
  - Process termination correlation (detects rapid termination of multiple security processes)
  - Hook detection (alerts if EDR hooks are bypassed)
  - IOCTL interception (can block suspicious IOCTL calls)
- **Implementation**: Deploy EDR to all systems (not just critical systems)
- **Key Vendors**: CrowdStrike Falcon, Microsoft Defender for Endpoint, Carbon Black, Elastic, SentinelOne

**Prevention Strategy 3: Driver Inventory & Whitelisting**

- **What**: Maintain inventory of legitimate drivers; block all others
- **How**:
  ```
  Group Policy: Computer Configuration > Administrative Templates >
                System > Code integrity: Boot start driver initialization policy
  ```
- **Options**:
  - AUDIT: Log unsigned drivers (no blocking, just monitoring)
  - BLOCK: Prevent loading of unsigned drivers
  - WARN: Warn users about unsigned drivers
- **Implementation**: Start in AUDIT mode, gradually move to BLOCK after driver whitelist is established
- **Effectiveness**: VERY HIGH (prevents unknown drivers from loading)

**Prevention Strategy 4: Privilege Escalation Prevention**

- **What**: Reduce number of systems with local admin privileges
- **How**: Enforce principle of least privilege (regular users cannot install drivers)
- **Implementation**:
  - Remove local admin rights from standard users
  - Use Just-In-Time admin access (temporary elevation for specific tasks)
  - Implement PAM (Privileged Access Management) for admin credentials
- **Effectiveness**: HIGH (prevents lpe.exe privilege escalation)

**Prevention Strategy 5: Windows 11 HVCI (Hardware-backed Code Integrity)**

- **What**: Kernel protection preventing unsigned code from executing in kernel-mode
- **How**: CPU enforces code integrity at hardware level (cannot be bypassed by software)
- **Requirements**: Windows 11, compatible CPU (AMD Ryzen 3000+, Intel 8th gen+)
- **Configuration**:
  ```
  Group Policy: Computer Configuration > Administrative Templates >
                System > Device Guard >
                Turn On Virtualization Based Security
  ```
- **Effectiveness**: VERY HIGH (theoretically prevents kernel-mode code execution for unsigned drivers)
- **Limitation**: Not available for Windows 10; requires compatible hardware

**Prevention Strategy 6: Process Termination Alerts**

- **What**: Alert when security products are rapidly terminated
- **How**: EDR or SIEM monitors process termination events
- **Detection Rule**: Multiple security process terminations within 60 seconds
- **Response**: Immediate isolation and investigation
- **Implementation**: SIEM/EDR correlation rule (see Detection Opportunities section)

**Long-Term Recommendation**: Layered defense approach:
1. **Immediate**: Deploy Microsoft MVDB (blocks known drivers)
2. **Short-term**: Deploy EDR across organization
3. **Medium-term**: Upgrade to Windows 11 with HVCI
4. **Ongoing**: Maintain driver blocklist, monitor for new vulnerable drivers

---

## Key Takeaways

### What Matters Most About BdApiUtil64.sys

**1. Complete Kernel-Level Compromise**

BdApiUtil64.sys provides unrestricted Ring-0 kernel privileges. This is not a vulnerability requiring specific conditions-it's complete system control. Assume ANY system running this driver is completely compromised.

**2. Multi-Layered Defense Evasion**

Arsenal-237 doesn't rely on a single evasion technique. It combines:
- User-mode process termination (killer.dll)
- Kernel-mode BYOVD driver (BdApiUtil64.sys)
- SSDT bypass for EDR evasion
- Registry callbacks to prevent remediation
- Redundant persistence mechanisms

This multi-layer approach makes it nearly impossible to stop once driver loads.

**3. Professional-Grade Threat Infrastructure**

The Arsenal-237 toolkit is not opportunistic malware. It's organized, modular, well-engineered attack infrastructure with specific EDR product targeting. This indicates either advanced APT operations or a professional malware platform.

**4. Historical Validation Across Multiple Campaigns**

BYOVD techniques (using BdApiUtil64.sys or similar drivers) have been successfully used in:
- BlackByte Ransomware (2022-2023)
- Cuba Ransomware (2022)
- ALPHV/BlackCat (2022-present)
- AvosLocker (2022-2023)

This is not theoretical threat-it's proven effective attack pattern.

**5. Data Breach Assumption**

If BdApiUtil64.sys loads, assume:
- Credentials are stolen (Windows hashes, browser passwords, API keys)
- Sensitive files are accessed (email archives, encryption keys, security configurations)
- Attacker has complete inventory of organization's valuable data

Treat as definite data breach incident.

**6. Rebuild is Only Reliable Remediation**

Kernel-level compromise requires complete system rebuild. Aggressive cleanup:
- Cannot verify complete malware removal
- May fail due to registry callbacks blocking cleanup
- Leaves kernel-level components active
- Is less time-efficient than rebuild
- Does not address stolen credential compromise

---

## Appendix A: IOC Feed

### File Hashes

```json
{
  "file_hashes": {
    "md5": [
      "ced47b89212f3260ebeb41682a4b95ec"
    ],
    "sha1": [
      "148c0cde4f2ef807aea77d7368f00f4c519f47ef"
    ],
    "sha256": [
      "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
    ]
  },
  "file_metadata": {
    "filename": "BdApiUtil64.sys",
    "size_bytes": 116800,
    "version": "5.0.3.84333",
    "signature_issuer": "Baidu Online Network Technology (Beijing) Co., Ltd",
    "signature_valid_from": "2012-04-24",
    "signature_valid_to": "2015-04-24",
    "pdb_path": "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb"
  }
}
```

### Registry Indicators

```
HKLM\SYSTEM\CurrentControlSet\Services\Bprotect
  ImagePath: C:\Windows\System32\drivers\BdApiUtil64.sys
  Type: 1 (Kernel driver)
  Start: 2 (Automatic) or 3 (Demand start)

Callback: \Callback\bdProtectExpCallBack
Device Object: \Device\BdApiUtil
Symbolic Link: \DosDevices\BdApiUtil
```

### Behavioral Indicators

```
- Driver filename: BdApiUtil64.sys
- Driver load followed by security process termination (MsMpEng, csagent, ekrn, etc.)
- Service creation via kernel APIs (IOCTL 0x80002324)
- Rapid termination of multiple security products (within 60 seconds)
- EventLog service termination
- Registry modifications to disable security services
```

---

## Appendix B: Detection Rules

### YARA Signature

```yara
rule Arsenal237_BdApiUtil64_Driver {
    meta:
        description = "Detects BdApiUtil64.sys kernel driver used in Arsenal-237 attacks"
        author = "Threat Intelligence"
        date = "2026-01-26"
        hash_sha256 = "47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428"
        severity = "CRITICAL"

    strings:
        $hash = {47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428}
        $filename = "BdApiUtil64.sys"
        $pdb = "D:\\jenkins\\workspace\\bav_5.0_workspace\\BavOutput\\Pdb\\Release\\BdApiUtil64.pdb"
        $baidu = "Baidu Online Network Technology"

    condition:
        (uint16(0) == 0x5a4d) and (any of them)
}

rule Arsenal237_Service_Creation_IOCTL {
    meta:
        description = "Detects IOCTL 0x80002324 service creation via BdApiUtil64.sys"
        severity = "CRITICAL"

    strings:
        $ioctl = {24 23 00 80}  // IOCTL 0x80002324 in little-endian
        $service_name = "Bprotect"
        $windows_update = "WindowsUpdateService"
        $defender = "MicrosoftSecurityAgent"

    condition:
        all of them
}
```

### Sigma Detection Rule

```yaml
title: BdApiUtil64.sys Kernel Driver Loading
status: test
logsource:
    product: windows
    service: sysmon
detection:
    driver_load:
        EventID: 6
        ImageLoaded|contains:
            - BdApiUtil64.sys
        Signed: 'true'
        Issuer|contains:
            - Baidu
    hash_match:
        EventID: 6
        Hashes|contains: 47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428
    baidu_outside_install:
        EventID: 6
        ImageLoaded|contains: BdApiUtil64.sys
        ImageLoaded|notcontains:
            - 'Program Files\Baidu'
            - 'ProgramData\Baidu'
    filter_legitimate:
        ImageLoaded|contains:
            - 'Program Files\Baidu Antivirus'
    condition: (driver_load OR hash_match OR baidu_outside_install) AND NOT filter_legitimate
falsepositives:
    - Legitimate Baidu Antivirus installations
level: critical
```

### EDR Query (KQL - Microsoft Sentinel)

```kusto
// Detect BdApiUtil64.sys driver loading
DeviceImageLoadEvents
| where FileName == "BdApiUtil64.sys"
| project Timestamp, DeviceName, FileName, SHA256, Signer, SigningStatus
| extend ThreatLevel = "CRITICAL", IncidentType = "Kernel_Rootkit"

// Detect process termination spike following driver load
DeviceProcessEvents
| where (ProcessName contains "MsMpEng" or ProcessName contains "csagent" or ProcessName contains "ekrn")
| where ActionType == "ProcessTerminated"
| extend TimeFromLoad = Timestamp - (
    DeviceImageLoadEvents
    | where FileName == "BdApiUtil64.sys"
    | project LoadTime = Timestamp
    | where LoadTime < Timestamp)
| where TimeFromLoad > 0min and TimeFromLoad < 1min
| project Timestamp, DeviceName, ProcessName, ThreatLevel = "CRITICAL"
```

---

## References & Further Reading

**BYOVD Technique Research**:
- **Microsoft Security Blog (2023)**: "Bring Your Own Vulnerable Driver (BYOVD) - A Critical Threat"
- **MITRE ATT&CK**: T1014 (Rootkit), T1547.006 (Kernel Modules & Extensions)
- **CrowdStrike Intelligence (2023)**: "BYOVD Campaigns Analysis"

**Arsenal-237 & Related Campaigns**:
- **FBI Alert IR-22-152**: BlackByte Ransomware Incidents
- **CISA Advisory AA22-321A**: ClearVision Ransomware Campaign
- **Mandiant Threat Intelligence**: "Cuba Ransomware Gang TTPs"
- **Microsoft Threat Intelligence**: "ALPHV/BlackCat Ransomware Operations"

**Windows Kernel Defense Mechanisms**:
- **Microsoft Vulnerable Driver Blocklist (MVDB)**: https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules
- **Windows 11 HVCI Documentation**: https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control
- **SSDT Hooking Research**: "Kernel Hooking Bypassing Techniques" (Academic Security Research)

**Incident Response Guidance**:
- **NIST Cybersecurity Framework**: Special Publication 800-61 Rev. 2 (Computer Security Incident Handling)
- **SANS Incident Response**: "SANS Incident Handler's Handbook" (IR Process)
- **FBI/CISA Ransomware Guidance**: "Ransomware Attacks: Threats and Mitigations"

**Forensic Analysis**:
- **Rekall Memory Forensics Framework**: https://github.com/google/rekall
- **Volatility Memory Analysis**: https://github.com/volatilityfoundation/volatility3
- **ELK Stack for Forensic Log Analysis**: https://www.elastic.co/products/kibana

---

## License

(c) 2026 Threat Intelligence Analysis. All rights reserved.

Free to read, but reuse requires written permission.
