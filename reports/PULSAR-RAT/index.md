--- 
title: PULSAR RAT (server.exe) - Technical Analysis & Business Risk Assessment
date: '2025-12-01'
layout: post
permalink: /reports/PULSAR-RAT/
hide: true
---

# PULSAR RAT (server.exe): Technical Analysis & Business Risk Assessment

# A Comprehensive, Evidence-Based Guide for Security Decision-Makers

---

# BLUF (Bottom Line Up Front)

Pulsar RAT (server.exe) represents a CRITICAL threat that provides attackers with comprehensive remote control over infected systems. The malware employs sophisticated techniques including advanced persistence mechanisms, encrypted C2 infrastructure, and hidden virtual desktop capabilities (HVNC) that enable covert unauthorized access while evading security controls.

>This assessment is based on static code analysis, behavioral indicators, and correlation with known RAT families-confidence levels are provided throughout to distinguish confirmed findings from analytical judgments. 

>This investigation is still on going with further reverse engineering, code analysis, and dynamic sandbox analysis. Will update the report if there are any new findings of note. 

---

# 1. EXECUTIVE SUMMARY

## The Threat in Clear Terms - Open Directory hxxp://185[.]208[.]159[.]182/d/server[.]exe

- **Complete remote control** of that system (CONFIRMED - static analysis)
- **Surveillance capabilities** including keylogging, screen capture, webcam, and microphone access (CONFIRMED - code inspection)
- **Credential theft** targeting browsers, applications, and typed passwords (CONFIRMED - modules present)
- **Advanced persistence** including potential recovery partition abuse (LIKELY - techniques present, verification required)
- **Network pivot capabilities** to use infected systems as entry points for lateral movement (CONFIRMED - SOCKS proxy module)

## IP Address 185[.]208[.]159[.]182: OSINT Profile

### OSINT analysis confirms that the IP address **185[.]208[.]159[.]182** is a high-confidence malicious infrastructure node. Key findings include:

- **RedLine Stealer C2:** This IP has been identified as an active Command and Control (C2) server for the RedLine Stealer malware, often operating on port `1912`.
- **QuasarRAT Distribution Point:** It has also served as a distribution point for QuasarRAT, hosting **server[.]exe**`** payloads.
- **Network & Attribution:** The IP belongs to Autonomous System (AS) **AS42624**, with registered entities including "NOAVARAN SHABAKEH SABZ MEHREGAN (Ltd.)" and "SETEL CONECTA S.L.". The presence of multiple entities suggests a complex hosting setup, possibly involving resellers or leased IP blocks.
- **"Bad Neighborhood" Indicator:** Other IP addresses within the same **185.208.15x.xxx** range are heavily reported for various malicious activities across threat intelligence platforms (e.g., AbuseIPDB), indicating that this IP operates within a network block favored by threat actors.

This additional context confirms the critical nature of any connection to this IP address.
**server.exe** is a professional-grade Remote Access Trojan (RAT) identified as **Pulsar RAT**, a sophisticated variant of the open-source Quasar RAT family. If this malware executes on a system in your environment, attackers gain:

## Risk Rating: CRITICAL

| Risk Factor | Score | Justification |
|-------------|-------|---------------|
| **Data Exfiltration** | 10/10 | Full filesystem access + automated credential harvesting modules confirmed in code |
| **System Compromise** | 10/10 | Complete remote control capabilities with administrative privilege escalation |
| **Persistence Difficulty** | 9/10 | Advanced techniques including recovery partition abuse (requires verification per system) |
| **Evasion Capability** | 9/10 | Multi-layered anti-analysis confirmed (VM, debugger, sandbox detection) |
| **Lateral Movement** | 8/10 | SOCKS proxy + credential theft + network tunneling capabilities present |
| **Encryption/Detection** | 9/10 | BCrypt encryption + dynamic C2 infrastructure complicates network detection |
| **OVERALL RISK** | **9.2/10** | **CRITICAL** |

---

# 2. BUSINESS RISK ASSESSMENT

## Understanding the Real-World Impact

Before diving into technical details, it's important to understand what this malware means for your organization in business terms.

## Financial Impact Scenarios

| Scenario | Likelihood | Potential Cost Range | Explanation |
|----------|-----------|---------------------|-------------|
| **Credential theft leading to financial fraud** | HIGH | $50K - $500K+ | Stolen banking, payment, or corporate credentials used for unauthorized transactions |
| **Data breach/regulatory penalties** | HIGH | $100K - $5M+ | Exfiltrated PII/PHI triggering GDPR, HIPAA, or other compliance violations |
| **Business disruption during remediation** | VERY HIGH | $10K - $200K per day | System rebuilds, incident response, productivity loss during investigation |
| **Intellectual property theft** | MEDIUM | $500K - $50M+ | Depends on value of accessible data; most impactful for R&D, manufacturing |
| **Ransomware deployment (follow-on)** | MEDIUM | $100K - $10M+ | RAT access often precedes ransomware; attackers assess value before deploying |
| **Reputational damage** | MEDIUM-HIGH | Unquantifiable | Customer trust erosion, media coverage, competitive disadvantage |

## Operational Impact Timeline

**If infection confirmed:**

- **Hour 0-4**: Emergency response, system isolation, evidence preservation
- **Day 1-3**: Forensic analysis, credential rotation, threat hunting across environment
- **Week 1-2**: System rebuilds or intensive cleanup, continued monitoring
- **Month 1-3**: Enhanced monitoring, security control improvements, compliance reporting
- **Ongoing**: Potential long-term monitoring if data breach confirmed

**Total organizational effort:** Typically 200-500 person-hours depending on scope.

---

## 3. WHAT IS server.exe?

## Classification & Identification

| Attribute | Value | Confidence Level |
|-----------|-------|------------------|
| **Malware Type** | Remote Access Trojan (RAT) | CONFIRMED |
| **Family** | Pulsar RAT / Quasar Derivative | HIGHLY CONFIDENT (95%) |
| **Sophistication** | Advanced / Professional-Grade | CONFIRMED |
| **Development** | .NET Framework 4.7.2, Microsoft Visual Studio | CONFIRMED |
| **Status** | Active - ongoing development and variants | LIKELY (based on recent variants in threat intelligence) |

## File Identifiers

| Hash Type | Value |
|-----------|-------|
| **MD5** | b5491b58348600c2766f86a5af2b867f |
| **SHA1** | dc795961c8e63782fc0f53c08e7ca2e593df99fa |
| **SHA256** | 2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766 |
| **File Size** | 1,571,840 bytes (1.5 MB) |
| **Compilation** | PE32 .NET Executable (32-bit x86) |

## Why This Is Professional-Grade Malware

**Not commodity crimeware - not script-kiddie code**

Evidence of professional development (CONFIRMED through static analysis):

- ✓ **Modular architecture** - 30+ functional modules organized by purpose (Surveillance, Admin, Networking, Persistence, Evasion)
- ✓ **Proper software engineering** - Exception handling, async/await patterns, organized namespaces matching professional development practices
- ✓ **Custom cryptography** - Windows CNG (BCryptEncrypt, BCryptImportKey) for secure communications
- ✓ **Advanced persistence techniques** - Multiple mechanisms including recovery partition manipulation
- ✓ **Sophisticated evasion** - Multi-layered anti-analysis targeting VMs, debuggers, sandboxes
- ✓ **HVNC implementation** - Complex covert remote desktop technique
- ✓ **MessagePack serialization** - Efficient binary C2 protocol (not basic HTTP)

### 3.1 Internal String Analysis: Unveiling Pulsar's Architecture

Based on analysis of embedded strings and YARA rule matches, **server.exe** is confirmed to be **Pulsar RAT**, a sophisticated variant derived from the open-source Quasar RAT family. The strings, appearing as internal .NET namespaces and class names (e.g., `Pulsar.Common.Messages.Administration.RemoteShell`, `Pulsar.Common.Messages.Monitoring.KeyLogger`), directly reveal the malware's extensive capabilities and modular architecture. These include:

*   **Administration & Control**: Remote shell, file management, task management, registry editing.
*   **Surveillance**: Keylogging, remote desktop, webcam access, password harvesting, clipboard monitoring, and Hidden Virtual Network Computing (HVNC).
*   **Networking & Communication**: Use of encrypted channels (`BCryptEncrypt`) and efficient `MessagePackSerializer` for Command & Control (C2) communication, dynamically fetching C2 configurations.
*   **System Interaction**: Utilities for User Account Control (UAC) manipulation and Windows Recovery Environment (WinRE) persistence.

>This detailed internal naming scheme provides strong evidence of the malware's design for comprehensive remote system compromise and further reinforces its classification as a professional-grade threat.

---

# 4. TECHNICAL CAPABILITIES DEEP-DIVE

## 4.1 PERSISTENCE MECHANISMS - Critical Finding: Recovery Partition Persistence - Understanding the Risks

>CONFIDENCE LEVEL: HIGHLY LIKELY (technique present in code) - VERIFICATION REQUIRED FOR SPECIFIC SYSTEMS

### What is WinRE and How Can It Be Abused?

**Windows Recovery Environment (WinRE)** is a minimal operating system stored on a separate partition that loads when Windows detects system problems. IT professionals use it for system recovery and troubleshooting.

**The Persistence Technique:**

The malware contains code to:
1. Elevate to Administrator privileges
2. Access the recovery partition (typically hidden from normal file system view)
3. Place malicious files in the recovery partition directory structure
4. Modify boot configuration to execute malware during recovery processes

**Why This Matters - But With Important Caveats:**

Standard OS reinstallation typically reformats only the primary Windows partition (C:), leaving the recovery partition untouched. **However**, this persistence technique has important limitations:

### Reality Check: When This Technique Works vs. Doesn't Work

**Scenarios Where Persistence SURVIVES:**
- ✓ Standard Windows "Reset this PC" function (keeps recovery partition)
- ✓ Quick format and reinstall on C: drive only
- ✓ Many OEM recovery processes (Dell, HP, Lenovo recovery tools)
- ✓ Upgrade installations that preserve recovery partitions

**Scenarios Where Persistence FAILS:**
- ✗ Complete disk wipe including all partitions (secure erase)
- ✗ UEFI Secure Boot with recovery partition integrity checks (if properly configured)
- ✗ BitLocker-encrypted recovery partitions with TPM verification
- ✗ Installation from external clean media with full repartitioning
- ✗ Disk replacement (new physical drive)
- ✗ Modern Windows 11 systems with hardware-backed recovery verification

**Research Context:**

Recovery partition abuse is documented in security research but remains relatively uncommon compared to registry-based persistence:

- **ESET Research (2020)**: Documented FinSpy malware using UEFI bootkit persistence (similar concept, different location)
- **Kaspersky (2020)**: Reported MosaicRegressor malware abusing UEFI firmware for persistence
- **Microsoft Security (2022)**: Advisory on boot partition malware noting detection complexity

**Why this technique is serious but not "undefeatable":**

While this is an advanced technique, calling it "survives all remediation" overstates the reality. Many organizations already use remediation procedures that would eliminate this persistence:
- Enterprise imaging processes that repartition drives
- MDT/SCCM deployments from network images
- Compliance-mandated secure wipe procedures

### Verification Steps for Your Environment

**Safe verification process (READ-ONLY - does not modify system):**

```
# Check if WinRE partition is accessible (requires Administrator)
# This is a READ-ONLY check - safe to run

Write-Host "Checking WinRE configuration..." -ForegroundColor Cyan

# Check WinRE status
reagentc /info

# Check for recovery partition
Get-Partition | Where-Object {$_.Type -eq 'Recovery'} |
    Select-Object DiskNumber, PartitionNumber, Size, Type

# If recovery partition exists, check for suspicious files (mounting required)
# NOTE: Only proceed with mounting if you have forensic training
Write-Host "`nWARNING: Mounting recovery partition for inspection should only be done by trained personnel" -ForegroundColor Yellow
Write-Host "Consider imaging the partition first for forensic preservation" -ForegroundColor Yellow
```

**For thorough verification, engage forensics specialists who can:**
- Create forensic images before any inspection
- Mount recovery partitions in read-only mode
- Analyze boot configuration safely
- Document chain of custody if evidence preservation needed

### Evidence Supporting This Assessment

**Code Analysis Findings (CONFIRMED):**
- WinRE-related string references: `Recovery\OEM\` directory paths
- Boot configuration manipulation functions
- Partition mounting utilities referenced in imports

**Actual exploitation success rate (UNKNOWN):
- Code presence ≠ guaranteed execution
- Requires administrative privileges
- May fail on hardened systems
- Real-world success rate requires incident data

>Recommendation: Assume capability exists, but verify on specific systems rather than assume all infected systems have active WinRE persistence.

---

### Secondary Persistence: Registry RunOnce

**CONFIDENCE LEVEL: CONFIRMED (standard technique, well-documented)**

**Location:**
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` (system-wide)
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` (current user)

**How it works:**
- Entry executes once at next login/boot, then automatically deletes itself
- Helps evade simple autorun scanners looking for persistent `Run` keys
- Malware recreates the entry each time it runs (self-perpetuating)

**Why this is the more common persistence method:**
- Survives reboots (but NOT OS reinstallation)
- Requires only user-level privileges for HKCU variant
- Well-understood and reliable
- Detected by most EDR solutions

**Detection:** Standard registry monitoring will catch this. Any competent EDR/endpoint security solution monitors RunOnce modifications.

---

### 4.2 COMMAND & CONTROL (C2) INFRASTRUCTURE

#### The Encrypted, Dynamic C2 Protocol

>CONFIDENCE LEVEL: CONFIRMED (code analysis + behavioral indicators) Traditional C2 detection relies on identifying suspicious domains or IP addresses. Pulsar defeats this through a multi-layered approach:

**Architecture:**

```
1. INFECTED SYSTEM STARTUP
   ↓
2. Retrieves C2 configuration from public paste site
   (e.g., pastebin.com/raw/[attacker-specified-ID])
   ↓
3. Decrypts configuration using embedded keys to get C2 server IP/domain
   ↓
4. Establishes BCrypt-encrypted connection to C2 server
   ↓
5. Attacker sends commands via MessagePack binary protocol
   ↓
6. Malware executes commands, returns encrypted results
```

**Why This Complicates Detection:**

- **No hardcoded C2 servers** - Addresses retrieved dynamically, changing infrastructure doesn't require new malware variants
- **Encrypted communications** - Windows CNG (BCrypt) encryption makes network traffic analysis difficult
- **MessagePack binary protocol** - Not HTTP/JSON, harder to pattern-match with standard IDS rules
- **Legitimate infrastructure abuse** - Paste sites like Pastebin are legitimate services (see blocking discussion below)

**Secondary Network Indicators (CONFIRMED in code):**
- `https://ipwho.is/` - Victim IP geolocation (attacker reconnaissance)
- `https://www.amyuni.com/downloads/usbmmidd_v2.zip` - Virtual display driver for HVNC functionality

---

### 4.3 SURVEILLANCE & DATA THEFT CAPABILITIES - Hidden Virtual Network Computing (HVNC) - Covert Access with Realistic Detection Considerations

>CONFIDENCE LEVEL: HIGHLY LIKELY (code present, requires driver installation to function)

### What Is HVNC?

A technique that creates an invisible virtual desktop session, allowing attackers to control a system without the victim seeing desktop activity.

#### Comparison:

```
NORMAL REMOTE DESKTOP (RDP/VNC):
User sees:    Desktop flicker, mouse moving, applications opening
User can:     Disconnect, close applications, observe attacker activity
Detection:    Process monitor shows rdp/vnc processes, network shows connections

HVNC (Hidden Virtual Network Computing):
User sees:    Normal desktop - no visible changes
User can:     Nothing - virtual session is separate from visible desktop
Detection:    Requires specialized monitoring (see below)
```

#### Reality Check: Is HVNC Truly "Undetectable"?

**Short answer: No, but it's harder to detect than normal remote access.**

**What makes detection difficult:**
- No visible UI changes (victim doesn't see it)
- Runs in separate virtual desktop context
- Legitimate driver (usbmmsvc64.exe) may be digitally signed
- Activity appears to originate from victim's computer

**Detection IS possible through:**

1. **Process Monitoring:**
   - Virtual display driver processes (usbmmsvc64.exe)
   - Unusual desktop creation (virtual desktops)
   - Memory analysis showing hidden desktop sessions

2. **Network Traffic Analysis:**
   - Encrypted traffic to unknown destinations
   - Unusual bandwidth patterns during "idle" periods
   - Connections to C2 infrastructure (if identified)

3. **System Performance Indicators:**
   - CPU usage during supposed idle time
   - Memory consumption for hidden desktop session
   - Disk I/O from virtual desktop activity

4. **Event Log Analysis (Often Overlooked):**
   - Security Event 4688 (Process Creation) - shows driver installation
   - Logon events (4624) for new session types
   - Driver installation events (Service Control Manager logs)

5. **EDR and Behavioral Detection:**
   - Modern EDR can detect virtual desktop creation
   - Monitors desktop session enumeration
   - Alerts on suspicious desktop window patterns

**Industry Research on HVNC Detection:**

- **CrowdStrike (2021)**: Published detection methods for HVNC-based RATs, noting process and memory indicators
- **Sophos (2022)**: Detailed HVNC analysis showing network traffic patterns and behavioral signatures
- **SANS (2023)**: Training material on detecting hidden remote access including HVNC techniques

**Realistic Assessment:**

HVNC is **hard to detect** but not **impossible to detect**. It's particularly effective against:
- Organizations without EDR
- Environments relying only on antivirus
- Systems without comprehensive logging

It's less effective against:
- Modern EDR with behavioral detection
- Security operations teams actively threat hunting
- Environments with comprehensive logging and SIEM correlation

>The activity is **harder to detect** because it appears to come from the legitimate user, but it's not invisible to comprehensive security monitoring.

---

#### Keystroke Logging - Complete Credential Capture

>CONFIDENCE LEVEL: CONFIRMED (keylogging module present in code)**

**What's Captured:**
- All keyboard input including passwords, even if not displayed on screen
- Corporate credentials (Active Directory, VPN, email)
- Banking and financial credentials
- Social media and personal account passwords
- Cryptocurrency wallet passwords
- Two-factor authentication codes (if typed or copy/pasted)

**Why It's Effective:**

Even with password managers, users often:
- Type master passwords
- Copy/paste credentials (captured via clipboard monitoring)
- Manually enter verification codes
- Use keyboard shortcuts that reveal information

**Detection Methods:**
- EDR behavioral monitoring for keylogging API calls (GetAsyncKeyState, SetWindowsHookEx)
- Monitoring for suspicious input capture libraries
- Behavioral analytics detecting keystroke logging patterns

---

### Browser Password Theft - Automated Extraction

>CONFIDENCE LEVEL: CONFIRMED (code modules present)

**How It Works:**

```
1. Identify browser installations (Chrome, Firefox, Edge, Opera, Brave)
2. Locate credentials database:
   - Chrome: %LocalAppData%\Google\Chrome\User Data\Default\Login Data
   - Firefox: %AppData%\Mozilla\Firefox\Profiles\[profile]\logins.json
3. Use Windows DPAPI (Data Protection API) to decrypt passwords
4. Extract username/password pairs for all saved credentials
5. Transmit to attacker via encrypted C2 channel
```

**Why This Is Effective:**
- Fully automated - runs without user interaction
- Comprehensive - extracts ALL stored passwords from ALL browsers
- Scalable - affects all user profiles on compromised system
- Difficult to prevent - browsers must store credentials to auto-fill them

**Targets (CONFIRMED):**
- Google Chrome / Chromium-based browsers (Edge, Brave, Vivaldi, Opera)
- Mozilla Firefox
- Legacy Internet Explorer

**Mitigation:**
- Hardware security keys for critical accounts (FIDO2/WebAuthn)
- Separate credential management solutions with encryption
- Limit credential storage in browsers for sensitive accounts

---

### Clipboard Hijacking - Cryptocurrency Theft

>CONFIDENCE LEVEL: CONFIRMED (clipboard monitoring code present)

**The Attack Scenario:**

```
Victim:     "I'll send Bitcoin to my friend"
Victim:     Copies friend's wallet address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Malware:    Detects Bitcoin address format in clipboard
Malware:    Replaces with attacker's address: 1AttackerWalletAddress...
Victim:     Pastes into transaction field (doesn't notice change)
Victim:     Confirms transaction
Result:     Funds sent to attacker instead of intended recipient
```

**Specific Evidence (CONFIRMED in code):**

Bitcoin Cash address detection regex:
```
^(bitcoincash:)?(q|p)[a-z0-9]{41}$
```

This shows the attacker specifically targets Bitcoin Cash transactions. Code inspection reveals similar patterns for Bitcoin (BTC), Ethereum (ETH), and other cryptocurrencies.

**Why Cryptocurrency Theft Is Permanent:**

Unlike bank transfers (reversible) or credit cards (chargeback protection), blockchain transactions are:
- Irreversible once confirmed
- Anonymous (difficult to trace to real-world identity)
- Permanent (no authority can reverse the transaction)

**Real-World Impact:**
- Individual losses: $100 - $500,000+ per incident (documented cases)
- Organizational treasury theft: Multi-million dollar losses possible
- No recovery mechanism exists

---

### Screen Capture & Video Recording

>CONFIDENCE LEVEL: CONFIRMED (modules present)**

**Capabilities:**
- Continuous screen capture at configurable intervals
- Video encoding with JPEG compression (bandwidth efficiency)
- Webcam access and image capture
- Microphone/audio recording

**Attacker Use Cases:**
- Visual surveillance of user activity
- Capture sensitive documents displayed on screen
- Reconnaissance to understand network layout from visible applications
- Evidence gathering for social engineering or extortion

**Detection:**
- EDR monitoring of screen capture APIs (BitBlt, GDI+)
- Webcam/microphone usage indicators (modern OS shows camera usage)
- Unusual CPU usage during idle periods

---

## 4.4 PRIVILEGE ESCALATION & LATERAL MOVEMENT

#### UAC Bypass

**CONFIDENCE LEVEL: LIKELY (UAC bypass techniques referenced, specific method requires dynamic analysis)**

Pulsar includes UAC (User Account Control) bypass capabilities, allowing it to:
- Elevate from standard user to Administrator privileges
- Modify system-wide settings and protected registry keys
- Install advanced persistence mechanisms requiring admin rights (WinRE)

**Common UAC bypass methods in similar malware:**
- DLL hijacking of auto-elevated processes
- Token manipulation
- COM interface abuse
- Windows registry manipulation

**Detection:** Modern EDR monitors UAC bypass attempts through behavioral analysis.

---

#### Token Manipulation & Impersonation

>CONFIDENCE LEVEL: CONFIRMED (API calls present)

The malware uses Windows security token manipulation:
- `AdjustTokenPrivileges` - Modify security tokens to gain additional permissions
- `ImpersonateLoggedOnUser` - Assume identity of another logged-in user

**Impact:**
- Can impersonate domain administrators if they've logged into compromised system
- Can access resources using service account identities
- Can escalate privileges beyond initial infection context

**Detection:** Security Event 4672 (Special privileges assigned to new logon) can indicate token manipulation when correlated with other suspicious activity.

---

#### Process Injection

>CONFIDENCE LEVEL: CONFIRMED (injection code present)

Injects malicious code into legitimate system processes:
- Target processes: explorer.exe, svchost.exe, other trusted Windows processes
- Hides malware presence (malicious code runs under legitimate process name)
- Evades process-based detection and application whitelisting

**Detection Methods:**
- EDR monitoring for CreateRemoteThread API calls
- Memory scanning for unsigned or anomalous code in process space
- Behavioral monitoring for legitimate processes exhibiting unusual network activity

---

#### SOCKS Proxy & Network Tunneling

>CONFIDENCE LEVEL: CONFIRMED (SOCKS proxy module present)

Configures infected system as a network relay/proxy:

**Capabilities:**
- Attackers can route traffic through infected system
- Enables access to internal network segments not directly reachable from internet
- Makes attacker traffic appear to originate from trusted internal system

**Lateral Movement Scenario:**

```
Internet → Infected Workstation (SOCKS Proxy) → Internal Database Server
         Appears as legitimate internal traffic ↑
```

**Why this matters for network segmentation:**
- Even segmented networks can be accessed if one system in the segment is compromised
- Firewall rules allowing internal communication become attacker pathways
- Difficult to distinguish from legitimate internal access

**Detection:**
- Monitor for unexpected SOCKS proxy services
- Network traffic analysis showing internal connections from unexpected sources
- Behavioral analysis of systems acting as network relays

---

## 5. EVASION & ANTI-ANALYSIS TECHNIQUES

### Why Attackers Use Evasion

When malware includes comprehensive evasion techniques, it indicates:
- Professional development team
- Intent to avoid security analysis
- Targeting of specific environments
- Effort to maximize operational lifespan

Pulsar includes **multi-layered evasion** targeting analysis environments, making it harder for security researchers to analyze and for automated sandboxes to detect malicious behavior.

### Anti-VM Detection

>CONFIDENCE LEVEL: CONFIRMED (VM detection code present)**

**What Pulsar Checks For:**

| VM Type | Detection Method | Reliability |
|---------|------------------|-------------|
| **VMware** | Registry keys, vmtoolsd.exe process, MAC address patterns | High |
| **VirtualBox** | VBoxGuest.sys, VBoxService.exe, hardware IDs | High |
| **QEMU** | QEMU-specific DLLs, device names | Medium |
| **Hyper-V** | WMI queries, specific registry keys | High |

**Why This Matters:**

Most malware analysis occurs in virtual machines. When malware detects a VM environment:
- May refuse to execute (analysis gets no results)
- May enter "harmless mode" (appears benign)
- May intentionally crash (disrupts analysis)

**Defender Perspective:**
- This is why "just run it in a VM" isn't always effective
- Requires sophisticated sandbox solutions that hide VM indicators
- May require bare-metal analysis for full behavioral understanding

---

### Anti-Debugger Detection

>CONFIDENCE LEVEL: CONFIRMED (debugger detection code present)**

**Techniques Used:**

1. `IsDebuggerPresent()` - Windows API check for attached debugger
2. `NtQueryInformationProcess()` - Lower-level kernel query
3. Timing checks - Detects slowdown caused by single-stepping
4. Thread manipulation detection - Identifies debugging activity

**Impact on Analysis:**

When security researchers attempt to step through code line-by-line, malware:
- Detects debugging and alters behavior
- May take different code paths hiding malicious functionality
- Can intentionally crash or terminate

**Why this matters for defenders:**
- Makes understanding full malware capabilities more difficult
- Requires more sophisticated analysis techniques
- Indicates professional development and serious intent

---

### Sandbox Evasion

>CONFIDENCE LEVEL: CONFIRMED (sandbox detection code present)**

**Detects:**
- **Sandboxie** - Checks for SbieDll.dll
- **ThreatExpert** - Looks for dbghelp.dll in specific configurations
- **Generic sandbox indicators** - Unusual environment variables, specific registry keys

**Methods:**
- DLL enumeration to detect sandbox-injected libraries
- Registry key checks for sandbox-specific entries
- Environment variable analysis

**Real-world impact:**
- Automated sandbox analysis may not reveal full capabilities
- "File is clean" verdict from automated analysis may be incorrect
- Requires manual analysis or advanced sandbox solutions

---

### Cryptographic Obfuscation

**CONFIDENCE LEVEL: CONFIRMED (cryptographic code present)**

The malware uses:
- **RSA/large integer constants** - Asymmetric encryption for key exchange
- **Base64 encoding** - String obfuscation
- **SipHash** - Fast cryptographic hashing for integrity verification

**Impact:**
- Static analysis (reading the code) is difficult without decryption
- Configuration data and C2 addresses are encrypted
- Complicates signature-based detection

---

## IOCs
- [PULSAR RAT IOCs]({{ "/ioc-feeds/PULSAR-RAT.json" | relative_url }})

## Detections
- [PULSAR RAT Detections]({{ "/hunting-detections/PULSAR-RAT/" | relative_url }})

---

## License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.
