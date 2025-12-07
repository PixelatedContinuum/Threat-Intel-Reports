---
title: Dual-RAT Analysis: Quasar RAT vs. NjRAT/XWorm - Technical Deep-Dive
date: '2025-12-06'
layout: post
permalink: /reports/dual-rat-analysis/
hide: true
---

> **Investigation Continuation Note**: This analysis is a continuation of the original [PULSAR RAT (server.exe)]({{ "/reports/PULSAR-RAT/" | relative_url }}) investigation. While analyzing the original server.exe sample over several weeks, two additional files appeared in the investigation directory at IP `185.208.159.182`. These new samples (client.exe and server (1).exe) suggest the threat actors may be testing or retooling their capabilities with different RAT implementations.

---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
This analysis examines two sophisticated .NET Remote Access Trojans (RATs) discovered during an ongoing investigation of a [PULSAR RAT sample]({{ "/reports/PULSAR-RAT/" | relative_url }}), representing fundamentally different operational philosophies. **Quasar RAT** demonstrates professional-grade espionage capabilities with stealth-focused design, while **NjRAT/XWorm** employs aggressive resilience mechanisms for mass deployment. Both samples enable complete system compromise but differ significantly in their approach to persistence, detection evasion, and infrastructure management.

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
1. **ISOLATE** systems showing scheduled task creation with suspicious names (RuntimeBroker, conhost)
2. **BLOCK** C2 infrastructure: 185.208.159.182 and Pastebin dead-drop URLs
3. **DEPLOY** behavioral detection rules for process injection and triple persistence
4. **AUDIT** PowerShell logs for mark-of-the-web removal and suspicious script execution
5. **ENHANCE** EDR monitoring for VB.NET processes with network activity
6. **IMPLEMENT** network monitoring for Pastebin access followed by arbitrary TCP connections

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [Sample 1: Quasar RAT Analysis](#sample-1-quasar-rat-analysis)
  - [Executive Technical Summary](#executive-technical-summary)
  - [Deep Technical Analysis](#deep-technical-analysis)
  - [Dynamic Sandbox Analysis](#dynamic-sandbox-analysis)
- [Sample 2: NjRAT/XWorm Analysis](#sample-2-njratxworm-analysis)
  - [Executive Technical Summary](#executive-technical-summary-1)
  - [Deep Technical Analysis](#deep-technical-analysis-1)
  - [Dynamic Sandbox Analysis](#dynamic-sandbox-analysis-1)
- [Delivery Method Analysis & Initial Access Vectors](#delivery-method-analysis--initial-access-vectors)
- [Future Evolution & Threat Trends](#future-evolution--threat-trends)
- [Comparative Technical Analysis](#comparative-technical-analysis)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Frequently Asked Questions](#frequently-asked-questions)
- [IOCs](#iocs)
- [Detections](#detections)

---

## Quick Reference

**Detections & IOCs:**
- [Dual-RAT Analysis Detections]({{ "/hunting-detections/dual-rat-analysis/" | relative_url }})
- [Dual-RAT Analysis IOCs]({{ "/ioc-feeds/dual-rat-analysis.json" | relative_url }})

---

# Sample 1: Quasar RAT Analysis

## File Identification
- **Original Filename**: client.exe
- **SHA256**: 2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766
- **File Size**: 1,571,840 bytes
- **Type**: C# .NET executable
- **Family**: Quasar RAT (open-source, formerly xRAT)
- **YARA Detection**: HKTL_NET_GUID_Quasar

**Discovery Context**: This sample appeared in the investigation directory at IP 185.208.159.182 during analysis of the original [PULSAR RAT server.exe]({{ "/reports/PULSAR-RAT/" | relative_url }}), suggesting the threat actors were actively deploying multiple RAT variants.

## Executive Technical Summary

### Business Context
Quasar RAT represents a **professional-grade espionage tool** frequently associated with APT10 and sophisticated threat actors. Its design prioritizes **stealth and long-term access** over aggressive persistence, making it particularly dangerous for high-value targets where detection could compromise broader operations.

### Key Business Impacts
- **Long-term Espionage**: 134 detected capabilities enable comprehensive intelligence gathering
- **Stealth Operations**: Process injection and anti-analysis make detection extremely difficult
- **Credential Harvesting**: Sophisticated browser password theft threatens corporate accounts
- **Network Pivoting**: SOCKS proxy capabilities enable lateral movement through compromised endpoints

### Detection Challenges
- **Process Injection**: Malicious code hidden within legitimate system processes
- **Encrypted C2**: Custom encryption prevents network-based detection
- **Anti-Analysis**: VM, debugger, and sandbox evasion defeat security research
- **Minimal Persistence**: Single scheduled task reduces event log footprint

### Executive Risk Assessment
**HIGH RISK** - Quasar RAT's professional development and APT10 association suggest targeted espionage operations. The combination of comprehensive capabilities and stealth-focused design creates significant risk for intellectual property theft and long-term compromise.

---

## Deep Technical Analysis

### Code Architecture & Design Philosophy

#### Deep Technical Analysis
Quasar RAT is compiled as a C# .NET assembly with sophisticated modular architecture. The analysis revealed a structured namespace organization with dedicated modules for core functionality, surveillance, system control, and network operations. CAPA analysis detected 134 distinct functions, including process injection capabilities, privilege escalation mechanisms, surveillance functions like keylogging and screenshot capture, and credential harvesting from web browsers. The malware also includes extensive anti-analysis features, such as VM detection for VirtualBox, VMware, and QEMU environments, debugger evasion techniques, and sandbox detection methods.

#### Executive Technical Context
**What This Means**: Quasar's modular C# architecture allows threat actors to customize capabilities for specific operations. The 134 detected functions indicate a comprehensive feature set comparable to commercial remote access software.

**Business Impact**: The professional code quality and extensive anti-analysis features suggest state-sponsored or highly sophisticated criminal operations. This isn't opportunistic malware—it's a purpose-built espionage tool.

**Detection Implications**: Traditional signature-based detection is ineffective due to easy recompilation with modified signatures, process injection hiding malicious activity in legitimate processes, and encrypted C2 communications preventing network inspection.

**Resource Allocation**: Defending against Quasar requires behavioral EDR solutions with process injection detection, advanced network monitoring for encrypted C2 patterns, and security research team with reverse engineering capabilities.

### Persistence Mechanism Analysis

#### Deep Technical Analysis
Quasar RAT establishes persistence through a single, well-camouflaged scheduled task. The analysis observed the creation of a task named "RuntimeBroker" that executes on user logon with highest privileges, running the malware from a user-writable directory. Registry artifacts were created in the TaskCache, including the task GUID and execution parameters.

#### Executive Technical Context
**What This Means**: The "RuntimeBroker" task name mimics a legitimate Windows process, attempting to blend in with normal system operations. However, legitimate RuntimeBroker is a system process, not a scheduled task, making this detectable with proper baseline knowledge.

**Business Impact**: Single persistence mechanism creates lower event log noise but also provides single point of failure for defenders. If identified and removed, the malware loses persistence completely.

**Detection Strategy**: Monitor for scheduled task named "RuntimeBroker" (T1053.005) executing from a user-writable directory. Monitor for task actions executing from "%AppData%\SubDir\Client.exe". Monitor for ONLOGON triggers with HIGHEST privilege requests.

**Remediation Complexity**: **MEDIUM** - Single persistence mechanism makes cleanup straightforward, but thorough forensics required to determine dwell time and data exfiltration scope.

### Command & Control Infrastructure

#### Deep Technical Analysis
Quasar RAT uses direct TCP connection to fixed C2 infrastructure. The analysis observed connections to IP address 185.208.159.182 on port 4782 with custom encryption. The malware includes pre-beacon reconnaissance capabilities, making HTTP requests to external IP discovery services like ipwho.is and api.ipify.org before establishing the C2 connection.

#### Executive Technical Context
**What This Means**: Direct IP connection creates single point of failure for C2 infrastructure. If defenders block 185.208.159.182, the malware loses all communication capabilities.

**Business Impact**: Fixed C2 infrastructure makes network-based blocking effective, but the custom encryption prevents Deep Packet Inspection (DPI) from identifying malicious payloads.

**Detection Strategy**: Monitor for outbound TCP connections to 185.208.159.182:4782. Monitor for processes making HTTP requests to IP geolocation services like ipwho.is or api.ipify.org before establishing unusual TCP connections. Monitor for encrypted traffic patterns consistent with C2 beacons (regular intervals, small payloads).

**Infrastructure Resilience**: **LOW** - Bullet-proof hosting provider but fixed IP address enables effective blocking through network security controls.

### Mark of the Web Removal Capability

#### Deep Technical Analysis
Quasar RAT implements Zone.Identifier stream removal to bypass Windows security warnings. The analysis observed the malware using the DeleteFile API to remove the alternate data stream ":Zone.Identifier" from downloaded files, effectively removing the "mark of the web" that Windows uses to identify potentially dangerous downloads.

#### Executive Technical Context
**What This Means**: The malware actively removes security markers that Windows uses to warn users about downloaded files, making the malware appear as if it originated locally.

**Business Impact**: This technique increases user deception and can bypass basic security awareness training. Users may execute files they would otherwise avoid due to security warnings.

**Detection Strategy**: Monitor for processes deleting the alternate data stream ":Zone.Identifier" from downloaded files. Monitor for files that lose their Zone.Identifier after being written to disk. Monitor for security tool logs showing missing download source information.

**Security Control Implications**: This technique bypasses Windows SmartScreen filtering, application reputation systems, and user security awareness based on download warnings.

---

## Dynamic Sandbox Analysis

### Execution Timeline (Noriben Analysis)

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
**What This Timeline Shows**: Quasar RAT executes a methodical, multi-phase infection with clear separation between installation, persistence, reconnaissance, and C2 establishment.

**Key Behavioral Indicators**:
1. **Security Bypass**: Immediate Zone.Identifier removal
2. **Stealth Installation**: Copy to AppData rather than system directories
3. **Legitimate Process Mimicry**: RuntimeBroker task name
4. **Pre-C2 Reconnaissance**: IP discovery before contacting C2
5. **Delayed C2 Contact**: ~4 minutes between execution and C2 connection

**Business Impact**: The methodical approach suggests professional development with clear operational phases. The delay in C2 contact may be designed to evade dynamic analysis with short timeouts.

**Detection Windows**:
- **Initial Execution**: File creation and Zone.Identifier removal
- **Persistence**: Scheduled task creation events
- **Reconnaissance**: HTTP requests to IP geolocation services
- **C2 Establishment**: TCP connection to unusual port

---

# Sample 2: NjRAT/XWorm Analysis

## File Identification
- **Original Filename**: server (1).exe
- **SHA256**: 950aadba6993619858294599b3458d5d2221f10fe72b3db3e49883d496a705bb
- **File Size**: 37,888 bytes (26x smaller than Quasar)
- **Type**: VB.NET executable
- **Family**: NjRAT/XWorm (Bladabindi variant)
- **Version**: XWorm 3.0-5.0 (DiE confirmed)
- **YARA Detection**: Njrat, BlackWorm

**Discovery Context**: This sample also appeared in the investigation directory at IP 185.208.159.182 alongside the Quasar sample, indicating the threat actors were simultaneously deploying multiple RAT families during the [PULSAR RAT investigation]({{ "/reports/PULSAR-RAT/" | relative_url }}).

## Executive Technical Summary

### Business Context
NjRAT/XWorm represents a commodity malware optimized for mass deployment with aggressive resilience mechanisms. Its compact size (37KB) and triple-redundant persistence make it ideal for opportunistic attacks where some detections are acceptable if overall access is maintained.

### Key Business Impacts
- **Rapid Deployment**: Small file size enables fast distribution and evasion of file-size-based detection
- **Resilient Access**: Triple persistence mechanisms make complete removal extremely difficult
- **Real-time Surveillance**: Emphasis on webcam/microphone streaming for immediate intelligence
- **Infrastructure Flexibility**: Pastebin dead-drop enables rapid C2 pivoting without malware updates

### Detection Advantages
- **Aggressive Behavior**: 1-minute scheduled task creates obvious detection opportunities
- **Triple Persistence**: Multiple persistence mechanisms increase detection surface
- **Network Pattern**: Pastebin access followed by arbitrary TCP connection is behavioral signature
- **Process Characteristics**: VB.NET processes with network activity are relatively uncommon

### Executive Risk Assessment
**HIGH RISK** - While considered commodity malware, NjRAT/XWorm's aggressive persistence and real-time surveillance capabilities create significant risk for privacy violations and data theft. Its prevalence in H1 2025 (18,459+ infections) indicates widespread effectiveness.

---

## Deep Technical Analysis

### Code Architecture & Design Philosophy

#### Deep Technical Analysis
NjRAT/XWorm is compiled as a VB.NET executable with compact, efficient design. The analysis revealed a module-based structure with dedicated components for client-server communication, surveillance operations, and persistence mechanisms. CAPA analysis detected 62 distinct functions, including persistence via registry keys and scheduled tasks, surveillance capabilities like webcam streaming and keylogging, data compression using GZip, and C2 infrastructure resolution through Pastebin dead-drops. The malware also includes critical process protection and anti-sleep mechanisms to maintain operational continuity.

#### Executive Technical Context
**What This Means**: The VB.NET codebase and compact 37KB size indicate efficiency-focused design prioritizing rapid deployment over feature breadth. The 62 detected functions represent core RAT capabilities without the extensive feature set of Quasar.

**Business Impact**: NjRAT's prevalence (18,459+ infections H1 2025) demonstrates high effectiveness despite simplicity. The compact size enables evasion of file-size-based detection heuristics and rapid distribution through phishing campaigns.

**Detection Advantages**: VB.NET compilation creates distinct runtime characteristics that can be identified through behavioral monitoring. The smaller codebase also makes static analysis somewhat easier than heavily obfuscated C# variants.

**Resource Allocation**: Defending against NjRAT requires scheduled task monitoring for unusual intervals, registry change alerting for Run key modifications, network monitoring for Pastebin dead-drop patterns, and process monitoring for VB.NET executables with network activity.

### Triple-Redundant Persistence Mechanism

#### Deep Technical Analysis
NjRAT/XWorm establishes three simultaneous persistence mechanisms. The analysis observed the creation of a high-frequency scheduled task named "conhost" that executes every minute, a registry Run key entry pointing to the malware executable, and a startup folder shortcut file. This triple-redundant approach ensures the malware can survive individual persistence mechanism removal.

#### Executive Technical Context
**What This Means**: Triple-redundant persistence creates self-healing capability - even if defenders remove one or two mechanisms, the third re-establishes the others. The 1-minute scheduled task is particularly aggressive and unusual.

**Business Impact**: This persistence strategy makes complete removal extremely difficult and increases dwell time significantly. The aggressive approach suggests the malware prioritizes maintaining access over stealth.

**Detection Strategy**: Monitor for scheduled task "conhost" with an interval of 1 minute (T1053.005). Monitor for simultaneous creation of "conhost" scheduled task, "conhost" Run key, and "conhost.lnk" in Startup folder. Monitor for new Run key entries pointing to user directories. Monitor for startup folder additions from non-installer processes.

**Remediation Complexity**: **HIGH** - Requires systematic removal of all three mechanisms plus thorough hunting for additional copies or reinfection vectors.

### Pastebin Dead-Drop C2 Architecture

#### Deep Technical Analysis
NjRAT/XWorm uses Pastebin as C2 infrastructure resolver. The analysis observed HTTP GET requests to "https://pastebin.com/raw/bzg5zj8n" with a mobile device user-agent string, followed by parsing of the response to extract the actual C2 endpoint for TCP connection establishment.

#### Executive Technical Context
**What This Means**: Pastebin dead-drop architecture creates infrastructure resilience - threat actors can change C2 servers without updating malware by simply editing Pastebin content.

**Business Impact**: Traditional IOC-based blocking (IP/domain blacklists) is ineffective against this architecture. Organizations must either block Pastebin entirely (causing business impact) or implement behavior-based detection.

**Detection Strategy**: Monitor for HTTP GET requests to "https://pastebin.com/raw/bzg5zj8n". Monitor for non-browser processes making web requests followed by arbitrary TCP connections. Monitor for mobile device user-agent string "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" from desktop processes. Monitor for network patterns of web request followed by unusual port connections.

**Infrastructure Resilience**: **HIGH** - C2 infrastructure can be changed in seconds through Pastebin editing, making takedown operations ineffective.

### Critical Process Protection & Anti-Sleep

#### Deep Technical Analysis
NjRAT/XWorm implements system-level protection mechanisms. The analysis observed the use of RtlSetProcessIsCritical API to mark the process as critical to system operation, which would trigger a BSOD if terminated. Additionally, SetThreadExecutionState API calls were detected to prevent system sleep during surveillance operations, ensuring continuous monitoring capabilities.

#### Executive Technical Context
**What This Means**: Critical process protection makes standard termination dangerous - killing the process causes system crash (BSOD). Anti-sleep functionality ensures continuous surveillance during long operations.

**Business Impact**: These mechanisms complicate incident response procedures and may force system reboots for remediation, increasing business disruption. The anti-sleep feature ensures continuous privacy violation during surveillance operations.

**Detection Strategy**: Monitor for API call "RtlSetProcessIsCritical" (T1489) from non-system processes like "conhost.exe". Monitor for SetThreadExecutionState calls from non-system processes. Monitor for system crashes following process termination attempts. Monitor for unusual power management API usage patterns.

**Remediation Implications**: Requires specialized tools and techniques to safely remove critical process protection before termination.

---

## Dynamic Sandbox Analysis

### Execution Timeline (Behavioral Observation)

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
**What This Timeline Shows**: NjRAT/XWorm executes aggressive, multi-pronged persistence immediately upon execution, followed by flexible C2 resolution and system protection mechanisms.

**Key Behavioral Indicators**:
1. **Process Masquerading**: Drops payload as "conhost.exe"
2. **Aggressive Persistence**: Three mechanisms established simultaneously
3. **Infrastructure Flexibility**: Pastebin dead-drop for C2 resolution
4. **System Protection**: Critical process and anti-sleep features
5. **Mobile Spoofing**: iPhone user-agent for Pastebin requests

**Detection Windows**:
- **Initial Execution**: File dropping and process creation
- **Persistence**: Multiple simultaneous persistence mechanisms
- **Network**: Pastebin access followed by arbitrary TCP connections
- **System Protection**: Critical process API calls

**Business Impact**: The aggressive persistence and system protection make this malware difficult to remove and dangerous to terminate without proper tools and procedures.

---

# Delivery Method Analysis & Initial Access Vectors

## Common Infection Vectors

Both Quasar RAT and NjRAT/XWorm primarily reach victims through **phishing and social engineering attacks**, though their delivery mechanisms reflect their different operational philosophies.

### Quasar RAT Delivery Patterns
**Targeted Delivery Approach**:
- **Spear-phishing emails** with malicious Office documents (Word, Excel) containing macros
- **Weaponized PDFs** with embedded exploits or malicious JavaScript
- **ZIP archives** containing infected executables disguised as legitimate files
- **PowerShell droppers** for fileless execution and defense evasion
- **Software vulnerability exploitation** in targeted environments

**Typical Victim Profile**: High-value targets in government, defense, energy, and manufacturing sectors where APT10 operates.

### NjRAT/XWorm Delivery Patterns
**Mass-Delivery Approach**:
- **Bulk phishing campaigns** with infected attachments distributed widely
- **Malvertising** through compromised websites serving drive-by downloads
- **USB drive propagation** (particularly prevalent in Middle East/Asia regions)
- **Trojanized software** distributed through underground forums
- **Exploit kit integration** for automated infection of vulnerable systems

**Typical Victim Profile**: Broad targeting across industries, with highest prevalence in opportunistic infections.

### Key Risk Factors
- **Email remains the primary vector** for both families, requiring robust email security controls
- **USB propagation** creates air-gapped network risks for NjRAT variants
- **Fileless techniques** (PowerShell droppers) bypass traditional file-based detection
- **Supply chain compromise** potential for both, given their widespread use

### Prevention Recommendations
1. **Email Security**: Advanced filtering, user training, and attachment sandboxing
2. **USB Controls**: Disable AutoRun, implement USB device restrictions
3. **Application Whitelisting**: Prevent unauthorized executable execution
4. **Network Segmentation**: Limit lateral movement opportunities
5. **Endpoint Detection**: Behavioral monitoring for suspicious process creation

---

# Future Evolution & Threat Trends

## Emerging Capabilities to Watch

As commodity RAT development continues, both Quasar and NjRAT families are likely to evolve with enhanced capabilities that challenge current detection approaches.

### Technical Evolution Trends
**Enhanced Evasion Techniques**:
- **AI/ML-powered anti-analysis** using machine learning to detect sandbox environments
- **Advanced obfuscation** with polymorphic code generation and runtime decryption
- **Living-off-the-land** increased reliance on legitimate system tools and APIs
- **Fileless execution** expanded memory-only operation techniques

**New Surveillance Capabilities**:
- **Cross-platform variants** targeting macOS and Linux environments
- **Advanced audio/video capture** with compression and streaming optimization
- **Browser extension integration** for enhanced credential harvesting
- **Cloud service integration** targeting SaaS applications and API tokens

### Operational Evolution Trends
**Infrastructure Modernization**:
- **Dynamic C2 infrastructure** with AI-generated domain names and IP rotation
- **Decentralized command structure** using peer-to-peer communication models
- **Blockchain-based C2** for resilient, censorship-resistant control channels
- **Satellite/5G integration** for remote areas with limited internet connectivity

**Integration with Advanced Threats**:
- **Ransomware bundling** combining RAT access with encryption capabilities
- **Supply chain weaponization** embedding RATs in legitimate software updates
- **Zero-day exploitation** faster weaponization of newly discovered vulnerabilities
- **AI-assisted targeting** using machine learning for victim profiling and attack optimization

### Detection Challenges Ahead
**Adaptive Evasion**:
- **Behavioral mimicry** learning legitimate user patterns to blend in
- **Anti-forensic techniques** automatic evidence destruction and timeline manipulation
- **Multi-stage deployment** complex infection chains that evade single-point detection

**Response Implications**:
- **Memory forensics requirements** will increase as fileless techniques proliferate
- **Network traffic analysis** must evolve to detect encrypted and obfuscated C2
- **AI-assisted detection** may be necessary to counter AI-enhanced evasion

### Strategic Preparation
Organizations should prepare for these trends by:
1. **Investing in behavioral analytics** that can detect novel evasion techniques
2. **Building memory forensics capabilities** for advanced threat investigation
3. **Implementing zero-trust networking** to limit lateral movement opportunities
4. **Developing threat hunting programs** focused on emerging TTP patterns

---

# Comparative Technical Analysis

**Investigation Context**: The discovery of these two distinct RAT families during the [PULSAR RAT investigation]({{ "/reports/PULSAR-RAT/" | relative_url }}) reveals a more complex threat ecosystem than initially apparent, with threat actors deploying multiple specialized tools for different operational objectives.

## Design Philosophy Comparison

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

# MITRE ATT&CK Mapping

## Quasar RAT - ATT&CK Mapping

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

## NjRAT/XWorm - ATT&CK Mapping

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

# Frequently Asked Questions

## Technical Questions

**Q: Why does Quasar RAT use process injection while NjRAT/XWorm doesn't?**  
A: Quasar's stealth-focused design prioritizes evading detection by hiding malicious code within legitimate processes. NjRAT's resilience-focused design accepts higher detection risk in favor of aggressive persistence and rapid recovery.

**Q: How effective is Pastebin dead-drop architecture for C2 resilience?**  
A: Highly effective - threat actors can change C2 infrastructure in seconds by editing Pastebin content, making takedown operations ineffective. Defenders must either block Pastebin entirely (causing business impact) or implement behavior-based detection.

**Q: What makes the 1-minute scheduled task so unusual?**  
A: Legitimate software rarely uses sub-5-minute intervals for scheduled tasks. This aggressive frequency ensures rapid recovery from process termination but creates obvious detection opportunities for security monitoring.

**Q: How does the "mark of the web" removal work technically?**  
A: Windows stores download source information in alternate data streams (file:Zone.Identifier). The malware uses DeleteFile API to remove this stream, bypassing SmartScreen warnings and making the file appear locally created.

## Business Questions

**Q: Which malware poses greater business risk?**  
A: Quasar RAT poses greater risk for high-value targets due to its stealth capabilities and APT10 association. NjRAT/XWorm poses greater risk for mass compromise due to its prevalence and resilience.

**Q: Should we rebuild systems compromised by these RATs?**  
A: **REBUILD** is strongly recommended for both, but especially for Quasar RAT due to its sophisticated capabilities and potential for long-term, stealthy access.

**Q: How can we detect these threats if they evade traditional antivirus?**  
A: Implement behavioral EDR solutions, monitor for scheduled task anomalies, track Pastebin access patterns, and deploy the provided YARA/Sigma detection rules.

**Q: What are the compliance implications of these infections?**  
A: Significant - both RATs enable comprehensive data theft and surveillance, potentially violating multiple compliance frameworks (GDPR, HIPAA, PCI-DSS) depending on the data handled.

---

## IOCs
- [Dual-RAT Analysis IOCs]({{ "/ioc-feeds/dual-rat-analysis.json" | relative_url }})

## Detections
- [Dual-RAT Analysis Detections]({{ "/hunting-detections/dual-rat-analysis/" | relative_url }})

---

## License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.