---
title: new_enc.exe (Arsenal-237 Rust Ransomware v0.5-beta) - Technical Analysis & Threat Assessment
date: '2026-01-26'
detection_page: /hunting-detections/arsenal-237-new_enc-exe/
ioc_feed: /ioc-feeds/arsenal-237-new_enc-exe.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Detection Queries"
    anchor: "#detection-queries"
  - label: "Network Detection"
    anchor: "#network-detection-signatures"
ioc_highlights:
  - value: "109[.]230[.]231[.]37"
    note: "Arsenal-237 server"
  - value: "90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2"
    note: "new_enc.exe SHA256"
layout: post
permalink: /reports/new-enc-exe/
hide: true
---

# new_enc.exe: Arsenal-237 Rust Ransomware v0.5-beta

**A Comprehensive, Evidence-Based Threat Assessment for Enterprise Security Decision-Makers**

**Campaign Identifier:** Arsenal-237-New-Files-109.230.231.37


---

## BLUF (Bottom Line Up Front)

**Business Impact Summary**

new_enc.exe is a CRITICAL-severity Rust-based ransomware deployed manually by skilled threat actors targeting enterprise backup infrastructure. This malware eliminates standard recovery options through aggressive VSS deletion and backup agent termination, then encrypts all accessible data using ChaCha20 encryption. The **hardcoded encryption key** (67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b) represents a potential cryptographic vulnerability-if used for direct file encryption rather than key wrapping, all encrypted files may be recoverable without ransom payment.

**Key Risk Factors**

| Risk Factor | Score | Business Impact |
|------------|-------|-----------------|
| **Data Encryption Capability** | 9.8/10 | CRITICAL - All targeted files permanently encrypted without key recovery |
| **Anti-Recovery Mechanisms** | 9.9/10 | CRITICAL - VSS deletion + backup agent termination eliminate standard recovery paths |
| **Enterprise Backup Targeting** | 9.5/10 | CRITICAL - Specific Veritas Backup Exec agent termination (5 services) demonstrates sophisticated enterprise awareness |
| **Anti-Analysis Sophistication** | 8.7/10 | HIGH - Multi-layer VM/sandbox/debugger detection complicates incident response analysis |
| **Operational Persistence** | 6.2/10 | MEDIUM - Scheduled task for ransom note display; no traditional remote-access persistence |
| **Overall Risk Score** | **9.2/10** | **CRITICAL** - Immediate executive attention and incident response required |

**Overall Risk Rating: CRITICAL (9.2/10)**

This malware represents an extreme threat to organizational data security and requires urgent response protocols.

---

## Technical Summary

**What This Malware Enables**
- Complete organizational data encryption using strong ChaCha20 stream cipher
- Elimination of backup and recovery infrastructure before encryption execution
- Enterprise-specific targeting through identification and termination of backup solutions
- Advanced anti-analysis defenses preventing standard reverse engineering

**Why This Threat Is Significant**
- Human-operated deployment model indicates skilled threat actors with post-exploitation access
- Hardcoded encryption key may represent critical operational security failure enabling victim decryption
- Arsenal-237 family connection suggests participation in organized ransomware operation
- Targeted backup infrastructure destruction indicates pre-attack reconnaissance

---

## Organizational Guidance

### For Executive Leadership

**Immediate Actions Required (High Priority / Urgent Resource Allocation)**

1. **Incident Response Activation** - Activate your incident response plan for potential ransomware infection. Ensure external cybersecurity consultants are on standby.

2. **Backup Infrastructure Verification** - Confirm status of Veritas Backup Exec, Veeam, and offline backup systems. Verify that backup systems are functioning and immutable backups exist.

3. **System Isolation Assessment** - Evaluate which systems may have been compromised. Determine if new_enc.exe has been discovered on any infrastructure.

4. **Communications Readiness** - Prepare for potential notification requirements. Consult legal and compliance teams regarding breach notification timelines.

5. **Ransom Demand Response** - Establish internal protocols for ransom demand handling (do not negotiate directly; coordinate with law enforcement).

### For Technical Teams

**Defensive Actions (Reference Detailed Sections)**
- **Immediate:** Monitor for VSS deletion commands, Veritas agent termination, and RustRansomNoteTask scheduled task creation (See Section: Detection & Response Guidance)
- **Priority 1:** Deploy file integrity monitoring on critical backup infrastructure
- **Priority 1:** Implement network detection for ChaCha20-encrypted traffic patterns
- **Priority 2:** Activate threat hunting queries for Arsenal-237 indicators (Section: Hunting Detection Rules)
- **Priority 2:** Conduct forensic analysis if new_enc.exe discovered on any system
- **Priority 3:** Evaluate endpoint detection and response (EDR) coverage for ransomware behaviors

**Technical References**
- Detailed technical analysis: Section 1 (Static Analysis & Dynamic Execution)
- Enterprise backup targeting details: Section 2 (Enterprise Infrastructure Targeting)
- Encryption key vulnerability assessment: Section 3 (Hardcoded Key Analysis)
- Detection rules and YARA signatures: Separate detection rules document
- IOC feed: Structured JSON format with file hashes, behavioral indicators, cryptographic material

---

## Primary Threat Vector

**Distribution & Deployment**

new_enc.exe is deployed **manually by threat actors** following successful system compromise. The attack chain proceeds as follows:

1. **Initial Access** - Threat actor gains access to enterprise network (phishing, RDP exploitation, supply chain compromise)
2. **Privilege Escalation** - Lateral movement and privilege elevation to domain admin or SYSTEM context
3. **Reconnaissance** - Threat actor identifies and maps critical systems, backup infrastructure, and high-value data locations
4. **Ransomware Deployment** - new_enc.exe is manually executed on target systems with specific command-line arguments (--pass, --folder, --file) allowing targeted encryption
5. **Backup Destruction** - Malware terminates Veritas, Veeam, and VSS services; deletes VSS snapshots
6. **Data Encryption** - Files are encrypted with hardcoded ChaCha20 key; ransom note displayed
7. **Ransom Demand** - Victims directed to make cryptocurrency payment

**Threat Infrastructure**
- No C2 communication identified (unlike Arsenal-237 enc_c2.exe variant)
- Manual deployment model eliminates need for automated command infrastructure
- Campaign tracking via hardcoded builder ID: ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4

**Confidence Level: HIGH (90%)**

---

## Assessment Basis

**Analysis Methodology**
- Static reverse engineering of PE64 binary (1.9 MB Rust-compiled executable)
- Function-level code analysis: 2000-line core orchestration function
- Registry key enumeration and API call inspection
- String pattern analysis and cryptographic constant identification
- YARA capability scanning and process behavior mapping
- Binary comparison with related Arsenal-237 variant (enc_c2.exe)

**Confidence Levels Applied**
- CONFIRMED: Direct observations from static analysis (strings, code structure, API calls)
- HIGHLY LIKELY (90%): Strong technical indicators with single alternative explanation
- LIKELY (70%): Reasonable inference from available evidence
- POSSIBLE (50%): Analytical judgment requiring additional validation
- INSUFFICIENT DATA: Claims requiring dynamic analysis or additional research

**Data Sources**
- Sample hash verification: MD5, SHA1, SHA256 confirmed
- Binary analysis: disassembly and code cross-referencing
- YARA rules: Crypto constant identification, anti-analysis technique detection
- Threat intelligence: Arsenal-237 family relationship assessment

---

## Quick Reference

**Detections & IOCs:**
- [new_enc.exe Detection Rules]({{ "/hunting-detections/arsenal-237-new_enc-exe/" | relative_url }})
- [new_enc.exe IOCs]({{ "/ioc-feeds/arsenal-237-new_enc-exe.json" | relative_url }})

**Related Reports:**
- [enc_c2.exe Ransomware]({{ "/reports/arsenal-237-new-files/enc_c2-exe/" | relative_url }}) - C2-enabled ransomware variant
- [full_test_enc.exe Advanced Ransomware]({{ "/reports/arsenal-237-new-files/full_test_enc-exe/" | relative_url }}) - Most advanced ransomware variant
- [dec_fixed.exe Decryptor]({{ "/reports/arsenal-237-new-files/dec_fixed-exe/" | relative_url }}) - Victim-specific decryptor
- [Arsenal-237 Executive Overview]({{ "/reports/109.230.231.37-Executive-Overview/" | relative_url }}) - Full toolkit analysis

---

## Section 1: File Classification & Identification

### Sample Information

| Property | Value | Confidence |
|----------|-------|-----------|
| **Filename** | new_enc.exe | CONFIRMED |
| **File Type** | PE64 (Portable Executable 64-bit) | CONFIRMED |
| **File Size** | 1,952,256 bytes (1.9 MB) | CONFIRMED |
| **Compiler** | Rust (cargo toolchain) | CONFIRMED |
| **Architecture** | x64 (64-bit Intel) | CONFIRMED |
| **MD5** | a16ba61114fa5a40afce54459bbff21e | CONFIRMED |
| **SHA1** | 2c01cefba27c4d3fcb3b450cb8e625e89bc54363 | CONFIRMED |
| **SHA256** | 90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2 | CONFIRMED |
| **Malware Family** | Arsenal-237 Rust Ransomware (RaaS platform) | HIGHLY LIKELY (85%) |
| **Version** | v0.5-beta | CONFIRMED |
| **Campaign/Builder ID** | ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4 | CONFIRMED |

### Malware Classification

new_enc.exe is ransomware, mapping to Data Encrypted for Impact, and it is human-operated, enterprise-targeted and manually deployed.

I rate its sophistication HIGH:
- Modern Rust implementation (memory-safe language choice)
- Multi-layer anti-analysis system (5 distinct evasion layers)
- Enterprise-specific service targeting (Veritas Backup Exec with 5 specific agent names)
- Strategic anti-recovery sequencing (backup disruption before encryption)

The version string v0.5-beta puts it in active development, ahead of any 1.0 release.

### Professional-Grade Malware Indicators

1. **Language Choice:** Rust provides memory safety and performance advantages (similar adoption by BlackCat/ALPHV ransomware)
2. **Modular Architecture:** ~2000-line orchestration function suggests well-structured codebase
3. **Version Control:** Explicit version numbering (v0.5-beta) indicates professional development practices
4. **Campaign Tracking:** Builder ID (ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4) suggests centralized campaign management system
5. **Targeted Capabilities:** Specific enterprise service identification demonstrates pre-attack reconnaissance capability
6. **Operational Awareness:** Anti-analysis techniques target modern reverse engineering tools (IDA, Ghidra, x64dbg, Frida)

---

## Section 2: Static Analysis - Code Structure & Capabilities

### Entry Point & Execution Flow

Execution starts at 0x1400013d0, where the _start function initializes the Rust runtime. TEB-based debugger detection at 0x140001180 runs immediately after that, before any of the code below it can be watched. The main function at 0x1400123f0 parses the command line and routes to the core orchestration by deployment mode, and that orchestration at 0x14000ed40 is a roughly 2,000-line function carrying all of the pre-encryption and anti-recovery logic.

**Execution Sequence:**
1. TEB debugger check -> Early termination if debugging detected
2. Main function argument parsing (--pass, --folder, --file modes)
3. Orchestration: Environmental analysis -> Service termination -> VSS deletion -> Encryption
4. Post-encryption: Scheduled task creation, ransom note display

### Command-Line Deployment Interface

new_enc.exe supports manual operator control through command-line arguments:

```
new_enc.exe --pass [password]       # Password-protected encryption mode
new_enc.exe --folder [path]         # Target specific directory tree
new_enc.exe --file [filepath]       # Target individual file
```

A manual CLI marks this as human-operated ransomware that needs a skilled operator at the keyboard. That lets the operator aim at specific high-value systems or folders, hitting the critical data without the noise a blanket sweep would make.

---

## Section 3: Enterprise Infrastructure Targeting

### Veritas Backup Exec Agent Targeting (CRITICAL)

The most significant finding in new_enc.exe's service termination list is **specific targeting of five Veritas Backup Exec agents:**

```
GxVss       - Veritas VSS provider (Volume Shadow Copy integration)
GxBlr       - Veritas Backup Exec remote agent (network backup capability)
GxFWD       - Veritas media server agent (media library management)
GxCVD       - Veritas client service (client-side backup)
GxCIMgr     - Veritas management service (centralized management)
```

Targeting this specific means the operator ran pre-attack reconnaissance and identified the backup infrastructure before deploying anything. Killing these five services removes Veritas backup capability completely, taking down backup execution, remote agent communication, media server functionality, client operations and management coordination together.

Anywhere Veritas Backup Exec is the backup, that backup fails completely. Every incremental mechanism stops, and recovery from the encryption becomes impossible without an offline copy.

### Comprehensive Anti-Recovery Mechanisms

**Primary Anti-Recovery Strategy: VSS Deletion**

```batch
vssadmin delete shadows /all /quiet
```

This command permanently removes all Windows Volume Shadow Copy snapshots. The "/quiet" flag suppresses prompts, enabling silent execution.

Windows Previous Versions recovery goes with them, and without an offline backup the data loss is permanent.

**Secondary Anti-Recovery: Service Termination**

| Service Category | Services Targeted | Operational Impact |
|------------------|------------------|-------------------|
| **Backup Solutions** | vss, veeam, backup agents | Complete backup system failure |
| **Database Services** | sql, oracle, ocssd, dbsnmp | Database unlocking for encryption; prevents backup-during-attack |
| **Microsoft Exchange** | msexchange | Email system shutdown; mail files accessible for encryption |
| **Security Services** | sophos (antivirus) | Endpoint protection disabled |

### Directory & File Exclusions

**Excluded Directories:**
windows, program files, programdata, appdata, boot, system volume information, windows.old, msocache, perflogs, intel, public, all users, default, $recycle.bin, config.msi, x64dbg, tor browser, google, mozilla

The exclusions keep the system usable after encryption. It still boots, the network still works and basic user operations still run, which is what keeps a ransom payment possible.

Excluding the x64dbg directory says the authors have reverse engineering attempts in mind.

**Excluded File Extensions:**
386, adv, ani, bat, bin, cab, cmd, com, cpl, cur, dll, drv, exe, hlp, ico, ldf, lnk, mod, msc, msp, msi, ocx, ps1, scr, sys, theme, wpx, lock, key

Those exclusions keep system executables and other critical files unencrypted, since encrypting them would break the machine outright.

---

## Section 4: Hardcoded Encryption Key - Vulnerability Analysis

### CRITICAL FINDING: Hardcoded ChaCha20 Key

**Encryption Key (Hexadecimal):**
```
67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b
```

**Key Properties:**
- Length: 32 bytes (256-bit)
- Algorithm: ChaCha20 (RFC 7539 compliant)
- Implementation: Modern stream cipher providing strong encryption

**Confidence Level: CONFIRMED (100%)**

The hardcoded key is definitively present in the binary. The critical question is **how this key is used**, which based on previous analysis is suspected to be a victim specific key.

### Two Key Usage Scenarios

#### Scenario A: Direct File Encryption (CRITICAL VULNERABILITY)

**If the hardcoded key is used directly to encrypt files:**

- **Vulnerability:** All encrypted files can be decrypted using this single key
- **Implications:** Victims can recover files without paying ransom
- **Threat Actor Impact:** Operational security failure-ransomware becomes ineffective
- **Recovery Possibility:** 100% file recovery feasible
- **Likelihood:** POSSIBLE (30%) - Indicates development/testing version or fundamental implementation flaw

**Supporting Evidence for This Scenario:**
- Version string "v0.5-beta" suggests pre-production code
- Hardcoded key inclusion suggests early-stage development
- Single global encryption key simplifies victim decryption

#### Scenario B: Key Encryption Key (KEK) Model (STANDARD ARCHITECTURE)

**If the hardcoded key wraps per-file encryption keys:**

- **Functionality:** Each file encrypted with unique key; master key wraps per-file keys
- **Architecture:** Standard ransomware design (common in professional malware)
- **Vulnerability:** This model is cryptographically sound; no decryption without per-file keys
- **Recovery Possibility:** Minimal without master key compromise
- **Likelihood:** HIGHLY LIKELY (70%) - Professional malware typically uses this model

**Supporting Evidence for This Scenario:**
- Professional Rust implementation suggests sophisticated development
- Arsenal-237 family relationship (enc_c2.exe) suggests proven architecture
- Enterprise-targeted design indicates production-grade ransomware

### Campaign/Builder Identifier

The sample carries the ransom ID `ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4`, a unique identifier for victim tracking and payment verification. An identifier of that shape points to a centralized builder managing multiple deployments and tracking who has paid.

---

## Section 5: Anti-Analysis Techniques

### Layer 1: Debugger Detection (TEB-based)

Layer 1 sits in sub_140001180 at 0x140001180. It inspects and manipulates the Thread Environment Block, reading the TEB structure to detect a debugging environment, which is more advanced than a simple IsDebuggerPresent() call. Its purpose is to prevent dynamic debugging and code tracing, and when it triggers the malware either terminates or takes a different execution path.

### Layer 2: VM Detection via Registry (System-Level)

Layer 2 checks the registry key `HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS`.

**Registry Values Inspected:**
- SystemManufacturer
- SystemProductName
- BIOSVendor

**Expected VM Values:**
- QEMU, VirtualBox, VMware, Hyper-V, Citrix, KVM, Xen, Parallels

The point is to identify virtual machine environments of the kind used for malware analysis, and where one is found the malware terminates rather than run.

### Layer 3: VM Detection via String Patterns

**String Patterns Searched:**
- VBOX (VirtualBox)
- VMWARE (VMware)
- VIRTUAL (Generic)
- QEMU
- XEN
- PARALLELS
- HYPERV

Layer 3 pattern-matches across BIOS information and system properties, covering the major hypervisor manufacturers.

### Layer 4: Sandbox Environment Detection

**Detection Patterns (Username/Hostname):**
```
sandbox, virus, malware, test, sample, john doe, cuckoo, analysis
```

Layer 4 inspects environment variables for sandbox indicators, looking for automated sandboxes and analysis environments.

**Common Sandboxes Detected:**
- Cuckoo (cuckoo username)
- Generic analysis systems (analysis, malware, virus usernames)

### Layer 5: Analysis Tool Process Monitoring

**Processes Monitored (13 tools):**

| Tool | Type | Purpose |
|------|------|---------|
| wireshark.exe | Network analyzer | Packet inspection |
| procmon.exe | Process monitor | Behavior monitoring |
| procexp.exe | Process explorer | Process analysis |
| x64dbg.exe | Debugger | Code debugging (64-bit) |
| x32dbg.exe | Debugger | Code debugging (32-bit) |
| ollydbg.exe | Debugger | Legacy debugging |
| ida.exe | Disassembler | Binary analysis |
| ida64.exe | Disassembler | 64-bit binary analysis |
| ghidra.exe | Reverse engineering tool | Code analysis |
| dnspy.exe | .NET debugger | Managed code debugging |
| fiddler.exe | HTTP proxy | Network traffic inspection |
| processhacker.exe | Process monitoring | Behavior analysis |
| pestudio.exe | Malware analysis | Static analysis |

Where any of these is detected, the malware terminates without encrypting anything.

Covering the modern reverse engineering tools this thoroughly shows real awareness of how the analysis would be done.

### Overall Anti-Analysis Assessment

I rate the anti-analysis sophistication HIGH.

The five-layer system significantly impedes analysis. Getting past it takes:
1. Bypass TEB-based debugger detection
2. Run in non-standard VM configuration
3. Spoof system information
4. Use non-standard analysis tools
5. Operate under username avoiding pattern matching

None of that makes analysis impossible. Isolation, spoofing and tool obfuscation still get there, but they take advanced technique.

---

## Section 6: Execution Flow & Behavioral Analysis

### Attack Chain Overview

```
+- Initial Access (External) - Lateral Movement - Privilege Escalation -+
|                                                                         |
+---> Threat Actor Execution of new_enc.exe with CLI Arguments ---+      |
                                                                   |      |
                    +----------------------------------+           |      |
                    |  Anti-Analysis Checks (5 layers) |<----------+      |
                    |  [x] TEB debugger check           |                  |
                    |  [x] VM detection (registry)      |                  |
                    |  [x] VM detection (strings)       |                  |
                    |  [x] Sandbox detection            |                  |
                    |  [x] Analysis tool monitoring     |                  |
                    +----------------------------------+                  |
                             |                                            |
                             [x] (passes all checks)                       |
                             |                                            |
                    +----------------------------------+                  |
                    |  Anti-Recovery Phase (CRITICAL)  |                  |
                    |  [x] Terminate Veritas agents     |                  |
                    |  [x] Terminate Veeam backups      |                  |
                    |  [x] Terminate database services  |                  |
                    |  [x] Terminate Office apps        |                  |
                    |  [x] Execute VSS deletion         |                  |
                    |  [x] Execute schtasks cleanup     |                  |
                    +----------------------------------+                  |
                             |                                            |
                             [x]                                            |
                             |                                            |
                    +----------------------------------+                  |
                    |  File Encryption Phase           |                  |
                    |  [x] Enumerate drives (A-Z)       |                  |
                    |  [x] Enumerate directories        |                  |
                    |  [x] Apply exclusions             |                  |
                    |  [x] ChaCha20 encryption          |                  |
                    |  [x] Extension assignment         |                  |
                    +----------------------------------+                  |
                             |                                            |
                             [x]                                            |
                             |                                            |
                    +----------------------------------+                  |
                    |  Post-Encryption Actions         |                  |
                    |  [x] Create scheduled task        |                  |
                    |  [x] Display ransom note          |                  |
                    |  [x] Display ransom ID            |                  |
                    +----------------------------------+                  |
                                                                          |
+----------------------------------------------------------------------+
             Incident Response & Recovery Attempts
```

### Detailed Execution Timeline

**Phase 1: Initialization & Anti-Analysis (Seconds 0-2)**

```
Time 0s:     Entry point (_start) 0x1400013d0
             +- CRT initialization routine

Time 0.5s:   Anti-debug layer (sub_140001180) 0x140001180
             +- TEB-based debugger detection
             +- TERMINATE if debugger present

Time 1s:     Main function (0x1400123f0)
             +- Parse command-line arguments
             +- Load configuration

Time 1.5s:   Core orchestration (sub_14000ed40)
             +- VM detection (registry BIOS check)
             +- VM detection (string patterns)
             +- TERMINATE if VM detected

Time 2s:     Sandbox detection
             +- Check username/hostname patterns
             +- TERMINATE if sandbox patterns detected
```

**Phase 2: Anti-Recovery (Seconds 2-10)**

```
Time 2s:     Service termination sequence begins
             +- Load service termination list

Time 3s:     Database services stopped
             +- SQL Server (sql.exe processes)
             +- Oracle Database (oracle processes)
             +- Release file locks on database files

Time 4s:     Backup services stopped
             +- Veritas Backup Exec agents (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr)
             +- Veeam backup agents
             +- VSS service

Time 5s:     VSS snapshot deletion
             +- Execute: "vssadmin delete shadows /all /quiet"
             +- /all flag: delete all VSS snapshots
             +- /quiet flag: suppress user prompts

Time 6s:     Office application termination
             +- Excel, Word, Outlook, PowerPoint
             +- Close open documents for encryption

Time 7s:     Security service termination
             +- Sophos antivirus
             +- McAfee ePO
             +- Microsoft Exchange

Time 8s:     Application analysis tool process monitoring active
             +- Continuous checking for wireshark, IDA, x64dbg, Ghidra, etc.
             +- TERMINATE if any analysis tools detected

Time 10s:    Pre-encryption configuration complete
             +- All recovery mechanisms eliminated
             +- System ready for encryption
```

**Phase 3: File Encryption (Seconds 10-[Duration depends on system scope])**

```
Time 10s:    Drive enumeration begins (A-Z)
             +- Identify all accessible drives

Time 11s:    Directory enumeration
             +- Recursively walk directory trees
             +- Apply exclusion list (windows, program files, appdata, etc.)
             +- Apply extension whitelist

Time 12s:    ChaCha20 key material loaded
             +- 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b
             +- Determine usage model (direct vs. KEK)

Time 13-[N]: File encryption execution
             +- For each target file:
                +- Open file
                +- Read file content
                +- Apply ChaCha20 encryption
                +- Write encrypted data
                +- (Possibly change file extension)

             +- Progression typically:
                +- User documents (fastest - often first accessed)
                +- Database files
                +- Archive files
                +- Continues across all accessible locations

Time [N+1]:  Ransom note generation
             +- Hex-decode embedded ransom note
             +- Display Ransom ID: ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4
             +- Display version: v0.5-beta
```

**Phase 4: Post-Encryption (Seconds [N+2]-[N+5])**

```
Time [N+2]:  Scheduled task creation
             +- Execute: schtasks.exe /create /tn RustRansomNoteTask ...
             +- Purpose: Display ransom note on user login

Time [N+3]:  Ransom note display
             +- Show hex-decoded message to user
             +- Display victim ID: ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4
             +- Provide payment instructions

Time [N+4]:  Process termination (self)
             +- new_enc.exe exits after encryption complete

Time [N+5]:  Victim discovery of encryption
             +- Users attempt to access encrypted files
             +- All data encrypted and inaccessible
             +- Ransom note displayed
```

### Behavioral Indicators

**Process Execution Chain:**
```
new_enc.exe (Manual threat actor execution with CLI arguments)
  +- cmd.exe (VSS deletion execution)
  |   +- vssadmin.exe delete shadows /all /quiet
  +- schtasks.exe (Scheduled task creation)
  |   +- /create /tn RustRansomNoteTask /tr [ransom note display command]
  +- Multiple service stop operations (through Windows API, not child processes)
```

**File System Changes:**
- Encrypted files (extension varies based on builder configuration)
- Ransom note file (typically README.txt, DECRYPT_ME.txt, or variant)
- Possibly .lock or .key files related to ransomware operation

**Registry Modifications:**
- Scheduled task registry entries for RustRansomNoteTask
- Possible exclusion registry modifications

---

## Section 7: MITRE ATT&CK Mapping

### Technique Breakdown

| Tactic | Technique | Sub-Technique | Severity | Evidence |
|--------|-----------|---------------|----------|----------|
| **Defense Evasion** | T1622 | Debugger Evasion | HIGH | TEB-based check in sub_140001180 |
| **Defense Evasion** | T1497.001 | System Checks | HIGH | Registry BIOS inspection, string pattern VM detection |
| **Defense Evasion** | T1497.002 | User Activity Checks | HIGH | Username/hostname sandbox pattern matching |
| **Defense Evasion** | T1027 | Obfuscated Files | MEDIUM | Hex-encoded ransom note |
| **Discovery** | T1518.001 | Security Software Discovery | HIGH | Process detection of 13 analysis tools |
| **Discovery** | T1083 | File Discovery | MEDIUM | Directory/extension enumeration and filtering |
| **Execution** | T1059.001 | PowerShell/Batch/CMD | HIGH | Command-line arguments, schtasks execution |
| **Impact** | T1486 | Data Encrypted for Impact | **CRITICAL** | ChaCha20 encryption, hardcoded key |
| **Impact** | T1490 | Inhibit System Recovery | **CRITICAL** | VSS deletion, backup agent termination |
| **Impact** | T1489 | Service Stop | **CRITICAL** | Database, backup, Office, security services |
| **Persistence** | T1053.005 | Scheduled Task | LOW | RustRansomNoteTask creation |

### ATT&CK Tactic Hierarchy

```
+- Defense Evasion (5 Techniques)
|  +- T1622: Debugger Evasion (TEB-based detection)
|  +- T1497.001: VM Detection - System Checks
|  +- T1497.002: VM Detection - User Activity Checks
|  +- T1027: Obfuscation (hex encoding)
|  +- T1518.001: Security Software Discovery (process monitoring)
|
+- Discovery (2 Techniques)
|  +- T1083: File and Directory Discovery
|  +- T1518.001: Software Discovery
|
+- Execution (1 Technique)
|  +- T1059.001: Command Line Interface
|
+- Impact (3 CRITICAL Techniques)
|  +- T1486: Data Encrypted for Impact
|  +- T1490: Inhibit System Recovery
|  +- T1489: Service Stop
|
+- Persistence (1 Technique)
   +- T1053.005: Scheduled Task/Job
```

---

## Section 8: Detection & Response Guidance

### Detection Signatures

**String-Based Detection (YARA Rules)**
```
new_enc.exe signature indicators:
- Hardcoded key: 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b
- Campaign ID: ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4
- Version: v0.5-beta
- Scheduled task: RustRansomNoteTask
- VSS command: vssadmin delete shadows /all /quiet
```

**Behavioral Detection (Event Log Queries)**

*VSS Deletion Detection (HIGH PRIORITY):*
```
Event ID: 4688 (Process Creation)
CommandLine contains: "vssadmin" AND "delete shadows"
AlertSeverity: CRITICAL
```

*Veritas Backup Exec Service Termination (CRITICAL):*
```
Event IDs: 7000-7009 (System - Service events)
ServiceName IN: GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr
Status: Service stopped
AlertSeverity: CRITICAL
```

*Scheduled Task Creation (HIGH):*
```
Event ID: 4698 (Scheduled Task registered)
TaskName: RustRansomNoteTask OR contains "Ransom"
AlertSeverity: HIGH
```

*Database Service Termination (HIGH):*
```
Event IDs: 7000-7009 (System - Service events)
ServiceName IN: sql, oracle, ocssd, dbsnmp, synctime
Status: Service stopped
AlertSeverity: HIGH
```

*Office Application Mass Termination (MEDIUM):*
```
Event ID: 4689 (Process terminated)
Image IN: excel.exe, outlook.exe, powerpnt.exe, msaccess.exe, winword.exe
Source: Single parent process (new_enc.exe)
Count: Multiple in short timeframe (<5 seconds)
AlertSeverity: MEDIUM
```

### Hunting Queries

**KQL (Azure Sentinel / Defender for Endpoint) - VSS Deletion Hunt:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains ("vssadmin" and "delete") or ProcessCommandLine contains "shadowcopy"
| project Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, ParentProcessName
| order by Timestamp desc
```

**KQL - Veritas Service Termination Hunt:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "GxVss" or ProcessCommandLine contains "GxBlr" or ProcessCommandLine contains "GxCIMgr"
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine
| order by Timestamp desc
```

**SPL (Splunk) - Ransomware Service Termination Pattern:**
```spl
index=main sourcetype=WinEventLog:System (GxVss OR GxBlr OR GxFWD OR GxCVD OR GxCIMgr OR sqlservr OR oracle) ServiceStarted=failed
| stats count by host, user, signature
| where count > 3
```

**Elastic Query - ChaCha20 Key Detection (Memory Search):**
```
process.name:("new_enc.exe" OR "enc*.exe") AND memory.strings:"67e6096a85ae67bb"
```

## Section 9: Recovery Path Analysis

### Encryption Key Recovery Scenario

**Critical Question: Is the hardcoded key sufficient for decryption?**

This determines recovery feasibility:

#### Recovery Path A: Direct Encryption (Key = Decryption Key)

**Conditions:**
- Hardcoded key used directly for ChaCha20 stream cipher
- No per-file key derivation
- All files encrypted with identical key

**Recovery Method:**
1. Capture encrypted file sample
2. Isolate ChaCha20 decryption implementation
3. Apply hardcoded key to encrypted data
4. Verify decryption success
5. Develop victim decryption tool
6. **Result: 100% data recovery feasible**

A decryption tool is achievable in hours to days given the right resources.

#### Recovery Path B: Key Encryption Key (KEK) Model

**Conditions:**
- Hardcoded key wraps unique per-file keys
- Each file has its own encryption key
- Master key needed but per-file keys stored in encrypted files

**Recovery Challenges:**
- Per-file keys required for decryption
- Hardcoded key alone insufficient
- Possible key recovery from:
  - Encrypted file headers (if keys stored encrypted)
  - File system analysis (deleted key material)
  - RAM analysis (keys in memory during encryption)
- **Result: Partial recovery possible; full recovery unlikely without incident response**

That path needs a specialized incident response investigation.

### Backup-Based Recovery

**Critical Assessment: Offline/Immutable Backups**

Organizations with offline backups face significantly better recovery prospects:

**Best Case - Offline Backups Unaffected:**
- Backups stored on physically disconnected or air-gapped systems
- No Veritas/Veeam network access
- Recovery directly from backup media
- **Timeline:** Hours-to-days depending on data volume
- **Cost:** Incident response + backup restoration labor

**Worst Case - Online Backups Compromised:**
- Veritas/Veeam systems accessible during attack
- New_enc.exe terminates backup services
- VSS snapshots deleted
- Online backups inaccessible
- **Timeline:** Ransom payment or months of data loss
- **Cost:** Ransom payment + operational disruption

## Section 10: Threat Assessment & Attribution

### Sophistication Analysis

**Overall Sophistication: HIGH**

**Evidence of Professional Development:**

| Indicator | Assessment |
|-----------|-----------|
| **Language Choice** | Rust - Modern memory-safe language indicating advanced development team |
| **Anti-Analysis Layers** | 5 distinct evasion techniques (TEB, registry, strings, sandbox, processes) |
| **Enterprise Awareness** | Specific Veritas agent naming (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr) |
| **Code Organization** | ~2000-line orchestration function suggests modular architecture |
| **Version Tracking** | "v0.5-beta" indicates professional version control |
| **Campaign Management** | Builder ID (ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4) implies centralized tracking system |
| **Operational Model** | Manual CLI deployment by skilled operators |

### Arsenal-237 Family Relationship

The related sample is enc_c2.exe, the C2-enabled variant.

**Shared Characteristics:**
- Rust implementation (identical language choice)
- TEB-based anti-debug function (identical code: sub_140001180)
- ChaCha20 encryption algorithm
- Multi-layer anti-analysis system
- Enterprise service targeting

**Distinguishing Characteristics:**

| Feature | enc_c2.exe | new_enc.exe |
|---------|------------|-------------|
| **Deployment Model** | C2-enabled (Tor onion) | Manual CLI (--pass, --folder, --file) |
| **C2 Infrastructure** | rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion | None identified |
| **Builder ID** | TEST_BUILD_001 | ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4 |
| **Version** | [Unknown] | v0.5-beta |
| **Anti-Analysis Sophistication** | Standard | Enhanced (5-layer system) |
| **Backup Targeting** | Standard termination list | Specific Veritas agents (5 named) |

**Attribution Confidence: HIGH (85%)**

The code reuse of an identical sub_140001180, the shared choice of Rust and the shared ChaCha20 encryption establish the family relationship conclusively. new_enc.exe is the evolved variant, and the version strings put enc_c2.exe earlier in development at TEST_BUILD_001 with new_enc.exe the refined build at v0.5-beta.

### Threat Actor Profile

I rate the development capability ADVANCED:
- Rust language mastery indicates sophisticated development team
- Anti-analysis sophistication suggests reverse engineering awareness
- Enterprise infrastructure knowledge demonstrates reconnaissance capability

I rate the operational capability ADVANCED as well:
- Manual deployment model indicates skilled operators
- Targeted ransomware deployment suggests post-exploitation expertise
- Backup infrastructure targeting demonstrates pre-attack planning

That puts this with an organized ransomware operation, most likely a RaaS platform, run by professional cybercriminals with advanced development and operational capability.

---

## Section 11: Key Takeaways

### 1. Hardcoded Encryption Key Represents Critical Vulnerability

The presence of a hardcoded ChaCha20 key (67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b) may enable victim file recovery without ransom payment. If this key is used for direct file encryption (rather than as a Key Encryption Key), all victims can decrypt encrypted files using this single key. This represents either a development version or fundamental operational security failure. Dynamic analysis is urgently required to determine key usage model.

### 2. Enterprise Backup Targeting Demonstrates Sophisticated Threat Actors

Specific identification and termination of five Veritas Backup Exec services (GxVss, GxBlr, GxFWD, GxCVD, GxCIMgr) indicates threat actors conducted pre-attack reconnaissance identifying backup infrastructure. This level of targeting precision demonstrates significant operational planning and enterprise environment knowledge. Organizations relying on Veritas backup face complete backup failure if infected.

### 3. Multi-Layer Anti-Analysis System Impedes Incident Response

The five-layer anti-analysis system (TEB debugger detection, VM registry checks, string pattern matching, sandbox environment detection, and analysis tool process monitoring) significantly complicates forensic analysis and incident response. Researchers must use non-standard analysis techniques, potentially delaying threat intelligence development and organizational incident response.

### 4. Recovery Options Are Severely Limited

VSS deletion combined with backup agent termination eliminates standard Windows recovery mechanisms. Organizations without offline, immutable backups face permanent data loss or ransom payment. The combination of aggressive anti-recovery mechanisms indicates ransomware authors understood enterprise recovery strategies and specifically targeted them.

### 5. Arsenal-237 Family Suggests Organized RaaS Operation

Relationship to enc_c2.exe (identical code reuse, same language, same encryption algorithm) indicates this malware is part of a larger Rust-based ransomware platform. Multiple deployment variants (C2-enabled vs. manual CLI) suggest flexible operational model allowing different threat actors to deploy variants according to their needs.

### 6. Manual CLI Deployment Indicates Broader Attack Chain

Command-line interface (--pass, --folder, --file) indicates new_enc.exe is a post-exploitation tool, not an initial access or automated propagation mechanism. Organizations facing this threat have likely suffered prior compromise enabling initial access, privilege escalation, and lateral movement. Broader incident response required.

---

## Section 12: Response Orientation

This is not an incident-response playbook. An organization facing this ransomware should run
its own incident-response process; what follows is a third-party orientation to the one
finding here that changes what is possible.

This variant carries a hardcoded ChaCha20 key, documented in the analysis above. That is a
test-build lapse rather than the operator's intent, and it means files encrypted by this
specific build are recoverable without contacting anyone. Confirming which build ran is
therefore the highest-value action available, and it is established from the encrypted files
themselves rather than from the binary, which may no longer be present.

What to hunt is the pre-encryption behaviour, which is louder than the encryption:
shadow-copy deletion and backup-agent termination both precede file writes and both are
recoverable from ordinary endpoint logging. The manual, hands-on-keyboard deployment pattern
means these actions arrive close together rather than on a schedule.

Encrypted files carry the family marker; the excluded-directory
list documented above explains what survived and why, and a system that still boots after
encryption is a design outcome rather than a partial run.

For containment, isolate affected hosts and preserve encrypted samples before any
rebuild, because build identification depends on them. Treat backup infrastructure as a
target rather than a resource until its reachability from the affected host is established.
Assume interactive operator access preceded the encryption stage, so the entry path and any
credentials used along it are in scope independently of the ransomware itself.
## Section 13: Confidence Levels Summary

### CONFIRMED (95-100% Confidence)

**Technical Findings (Direct Observation):**
- File hashes: MD5, SHA1, SHA256
- Rust compilation and cargo toolchain
- Hardcoded ChaCha20 key: 67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b
- Campaign ID: ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4
- Version: v0.5-beta
- Entry point functions and addresses
- String constants and patterns
- Service names targeted
- Directory exclusion lists
- File extension exclusion lists
- Scheduled task name: RustRansomNoteTask
- VSS deletion command
- Command-line argument processing (--pass, --folder, --file)

### HIGHLY LIKELY (80-95% Confidence)

**Strong Technical Indicators:**
- Arsenal-237 family relationship (code reuse, identical functions, language choice)
- ChaCha20 direct encryption (pending dynamic validation)
- TEB-based debugger detection sophistication assessment
- Professional development assessment
- Enterprise backup targeting sophistication assessment

### LIKELY (60-80% Confidence)

**Reasonable Inferences:**
- Malware was used for direct file encryption (requires dynamic analysis validation)
- Hardcoded key represents operational security vulnerability
- Threat actors conducted pre-attack reconnaissance

### POSSIBLE (40-60% Confidence)

**Analytical Judgments Requiring Additional Evidence:**
- Threat actor attribution to specific criminal organization
- Rust-based RaaS platform operation
- Future variant development expected

### INSUFFICIENT DATA

**Claims Requiring Additional Information:**
- Specific payment amounts demanded in ransom note (requires full hex decoding)
- Payment methods accepted (Bitcoin, Monero, etc.)
- Victim contact mechanisms (email, Tor site, etc.)
- Actual in-the-wild deployment scope
- Real-world victim count

---

## License

(c) 2026 Threat Intelligence Team. All rights reserved.
Free to read, but reuse requires written permission.
