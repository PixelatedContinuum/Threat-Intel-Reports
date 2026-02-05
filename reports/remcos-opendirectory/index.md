---
title: Remcos RAT OpenDirectory Campaign - Technical Analysis & Business Risk Assessment
date: '2026-02-04'
layout: post
permalink: /reports/remcos-opendirectory/
hide: true
---

## A Comprehensive, Evidence-Based Guide for Security Decision-Makers

**Campaign Identifier:** OpenDirectory-203.159.90.147-Remcos
**Last Updated:** February 4, 2026

---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
This report documents a sophisticated multi-stage Remcos Remote Access Trojan (RAT) campaign discovered through an openly accessible directory at IP address **203[.]159[.]90[.]147**. The attack chain deploys a Visual Basic 6 obfuscated dropper that extracts and executes the main Remcos RAT payload, establishing comprehensive surveillance capabilities, persistent access, and complete system control over compromised endpoints. This represents a critical threat requiring immediate executive review and organizational response.

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
      <td class="numeric critical"><strong>9.5/10</strong></td>
      <td class="critical"><strong>CRITICAL</strong></td>
    </tr>
    <tr>
      <td><strong>Data Exfiltration</strong></td>
      <td class="numeric critical">10/10</td>
      <td>Complete surveillance: screenshots, microphone recording, keylogging, clipboard monitoring, credential theft</td>
    </tr>
    <tr>
      <td><strong>System Compromise</strong></td>
      <td class="numeric critical">10/10</td>
      <td>Full system control with UAC bypass, five redundant persistence mechanisms, remote command execution</td>
    </tr>
    <tr>
      <td><strong>Persistence Difficulty</strong></td>
      <td class="numeric critical">10/10</td>
      <td>Five persistence mechanisms including rare Winlogon Userinit hijacking and UAC bypass</td>
    </tr>
    <tr>
      <td><strong>Evasion Capability</strong></td>
      <td class="numeric high">9/10</td>
      <td>Multi-stage obfuscation, anti-VM detection, process injection with novel desktop.ini timing triggers</td>
    </tr>
    <tr>
      <td><strong>Active C2 Infrastructure</strong></td>
      <td class="numeric critical">10/10</td>
      <td>Dual-purpose distribution and C2 server at 203[.]159[.]90[.]147 actively operational</td>
    </tr>
  </tbody>
</table>

### Technical Summary
**What This Malware Enables:**
- **Multi-Stage Attack Chain:** VB6 dropper → Remcos RAT with heavy obfuscation and anti-debugging
- **Five Persistence Mechanisms:** UAC bypass, Winlogon Userinit hijacking, three registry Run keys, shell hijack
- **Comprehensive Surveillance:** Screenshots (periodic + on-demand), microphone recording, keylogging with context, clipboard monitoring
- **Credential Theft:** Chrome/Firefox saved passwords and session cookies for account takeover
- **Process Injection:** Explorer.exe and msedge.exe targeting with possible novel desktop.ini timing triggers
- **Anti-Forensics:** File melting, hidden attributes, evidence removal, sandbox detection

**Why This Threat Is Significant:**
- **Global Threat:** 11% of all infostealer incidents in Q3 2025, nearly 150 organizations impacted
- **Active Campaigns:** SHADOW#REACTOR (January 2026), multi-continental targeting (Ukraine, Colombia, South Korea, Turkey, South Asia)
- **Threat Actor Spectrum:** Weaponized by nation-state APT groups (UAC-0184/Hive0156, Gamaredon, SideWinder) and cybercriminal operations
- **Critical OPSEC Failure:** Consolidated distribution and C2 on single IP creates takedown opportunity

### Organizational Guidance

#### For Executive Leadership
- **Resource Allocation:** Immediate incident response team deployment required; assess system rebuild requirements
- **Business Continuity:** Credential compromise necessitates immediate password resets; plan for potential disruption
- **Regulatory Compliance:** Data exfiltration triggers GDPR, HIPAA reporting obligations if PII/PHI accessed
- **Stakeholder Communication:** Internal notification for credential resets; external notification if breach confirmed
- **Strategic Security:** Infrastructure consolidation indicates cybercriminal/initial access broker (not sophisticated APT)

#### For Technical Teams
**Immediate Actions (0-24 hours):**
1. Block 203[.]159[.]90[.]147 at network perimeter (all protocols)
2. Hunt for mutex "Remcos_Mutex_Inj" across all endpoints
3. Search for file: C:\Users\*\AppData\Roaming\remcos\remcos.exe
4. Monitor registry key HKLM\SOFTWARE\...\Policies\System\EnableLUA for value 0
5. Deploy YARA rules to endpoint security platforms

**Short-Term Actions (24-72 hours):**
1. Enable registry monitoring for Winlogon\Userinit modifications
2. Reset credentials for all users on potentially compromised systems
3. Conduct memory forensics on suspected infections
4. Deploy Sigma rules to SIEM platforms

**Strategic Actions (1-4 weeks):**
1. Implement EDR behavioral detection for process injection (WriteProcessMemory from AppData executables)
2. Baseline Winlogon\Userinit registry values and alert on deviations
3. Deploy network monitoring for encrypted HTTP POST/PUT with binary payloads
4. Security awareness training on malicious email attachments and download risks

**For Detailed Technical Procedures:**
- Detection methods: See [Remcos OpenDirectory Detections]({{ "/hunting-detections/remcos-opendirectory/" | relative_url }})
- Machine-readable IOCs: See [Remcos OpenDirectory IOC Feed]({{ "/ioc-feeds/remcos-opendirectory-campaign.json" | relative_url }})
- Malware capabilities: See Section 3 (Technical Analysis)
- MITRE ATT&CK mapping: See Section 6
- Incident response: See Section 7

### Primary Threat Vector
- **Distribution Point:** OpenDirectory at hxxp://203[.]159[.]90[.]147/ hosting Payload.exe and Backdoor.exe
- **C2 Infrastructure:** Same IP (203[.]159[.]90[.]147)
- **Confidence Level:** CRITICAL based on dual-purpose infrastructure, active campaign, and confirmed malware samples

> **Assessment Basis:** Static code analysis, dynamic behavioral analysis, string analysis, and correlation with global Remcos threat intelligence. Confidence levels provided throughout to distinguish confirmed findings from analytical judgments. Attribution assessed as cybercriminal/initial access broker operation (MODERATE confidence) based on poor OPSEC and infrastructure consolidation.

### Quick Reference:
- [Remcos OpenDirectory Detections]({{ "/hunting-detections/remcos-opendirectory/" | relative_url }})
- [Remcos OpenDirectory IOC Feed]({{ "/ioc-feeds/remcos-opendirectory-campaign.json" | relative_url }})

---

## Table of Contents

- [BLUF (Bottom Line Up Front)](#bluf-bottom-line-up-front)
  - [Executive Summary](#executive-summary)
  - [Organizational Guidance](#organizational-guidance)
- [1. CAMPAIGN OVERVIEW](#1-campaign-overview)
  - [Attack Infrastructure](#attack-infrastructure)
  - [Threat Level Assessment](#threat-level-assessment)
  - [Global Context](#global-context)
- [2. ATTACK CHAIN ARCHITECTURE](#2-attack-chain-architecture)
  - [Multi-Stage Execution Flow](#multi-stage-execution-flow)
  - [Stage 1: VB6 Dropper (Payload.exe)](#stage-1-vb6-dropper-payloadexe)
  - [Stage 2: Remcos RAT Payload (Backdoor.exe)](#stage-2-remcos-rat-payload-backdoorexe)
- [3. PERSISTENCE MECHANISMS](#3-persistence-mechanisms)
  - [Mechanism 1: UAC Bypass via EnableLUA Registry Modification](#mechanism-1-uac-bypass-via-enablelua-registry-modification)
  - [Mechanism 2: Winlogon Userinit Hijacking](#mechanism-2-winlogon-userinit-hijacking)
  - [Mechanism 3: File Installation and "Melting"](#mechanism-3-file-installation-and-melting)
  - [Mechanism 4-5: Standard Registry Autorun](#mechanism-4-5-standard-registry-autorun)
- [4. SURVEILLANCE AND DATA COLLECTION](#4-surveillance-and-data-collection)
  - [Screenshot Capture](#screenshot-capture)
  - [Audio Recording](#audio-recording)
  - [Keylogging and Clipboard Monitoring](#keylogging-and-clipboard-monitoring)
  - [Browser Credential Theft](#browser-credential-theft)
- [5. EVASION AND ANTI-ANALYSIS TECHNIQUES](#5-evasion-and-anti-analysis-techniques)
  - [Process Injection](#process-injection)
  - [Anti-VM/Sandbox Detection](#anti-vmsandbox-detection)
  - [Stealth Mechanisms](#stealth-mechanisms)
- [6. COMMAND & CONTROL INFRASTRUCTURE](#6-command--control-infrastructure)
  - [Primary C2 Server](#primary-c2-server)
  - [Data Exfiltration Mechanisms](#data-exfiltration-mechanisms)
- [7. MITRE ATT&CK FRAMEWORK MAPPING](#7-mitre-attck-framework-mapping)
- [8. THREAT INTELLIGENCE CONTEXT](#8-threat-intelligence-context)
  - [Remcos RAT Global Threat Landscape](#remcos-rat-global-threat-landscape)
  - [Geographic Targeting Patterns](#geographic-targeting-patterns)
  - [Threat Actor Spectrum](#threat-actor-spectrum)
- [9. ATTRIBUTION ANALYSIS](#9-attribution-analysis)
  - [Campaign Sophistication Assessment](#campaign-sophistication-assessment)
  - [Threat Actor Profile](#threat-actor-profile)
- [10. REMEDIATION GUIDANCE](#10-remediation-guidance)
  - [Immediate Actions](#immediate-actions)
  - [Malware Removal](#malware-removal)
  - [Post-Remediation](#post-remediation)
- [References](#references)

---

# 1. CAMPAIGN OVERVIEW

## Attack Infrastructure

**Primary IP Address:** 203[.]159[.]90[.]147

**Dual-Purpose Infrastructure:**
- **Distribution:** OpenDirectory hosting Payload.exe, Backdoor.exe, and related malware samples
- **Command and Control:** TCP-based C2 communication for victim tasking and data exfiltration

**Operational Security Assessment:**

This infrastructure consolidation represents a **possible OPSEC failure** by the threat actor:

- Single IP blocking disrupts both distribution and C2 operations
- OpenDirectory exposure reveals malware samples for analysis
- Server logs may contain victim IP addresses for notification
- Reduces attacker anonymity and creates attribution opportunities


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/opendir.png" | relative_url }}" alt="Hunt.io Open Directory">
  <figcaption><em>Figure 1: Hunt.io Open Directory</em></figcaption>
</figure>


**Historical Context:**

OpenDirectory malware distribution is a documented Remcos TTP since 2021:
- Threat actors stage binaries in open directories on compromised servers
- Infrastructure frequently rotated when blocked by defenders
- Recent campaigns show ongoing use of this distribution method through 2025-2026

## Threat Level Assessment

**Immediate Threats:**
- **Credential Compromise:** Browser-saved passwords (Chrome, Firefox), session cookies stolen for account takeover
- **Data Exfiltration:** Screenshots, audio recordings, keystrokes, clipboard data transmitted to attacker infrastructure
- **Privilege Escalation:** UAC completely disabled system-wide, enabling silent administrative operations
- **Persistent Access:** Five redundant autorun mechanisms ensure malware survives reboots and basic removal attempts
- **Full System Control:** Remote command execution, file management, registry manipulation, system shutdown capabilities

**Strategic Risks:**
- **Initial Access for Ransomware:** Remcos frequently used by initial access brokers to establish footholds sold to ransomware operators
- **Corporate Espionage:** Complete visibility into user activity, communications, and sensitive documents
- **Financial Fraud:** Real-time credential theft enables unauthorized transactions and wire fraud
- **Regulatory Compliance:** Data breach involving PII/PHI triggers GDPR, HIPAA, and other regulatory obligations

## Global Context

Remcos RAT remains a **critical and actively exploited threat** in 2025-2026:

- **11% of all infostealer incidents** in Q3 2025 attributed to Remcos (CyberProof Research)
- **Nearly 150 organizations** globally impacted by recent Remcos campaigns (Proofpoint)
- **Multi-continental targeting:** Active campaigns in Ukraine (Russian APT groups), Colombia (Blind Eagle APT-C-36), South Korea, Turkey, and South Asia
- **Threat actor spectrum:** Weaponized by nation-state APT groups (UAC-0184/Hive0156, Gamaredon, SideWinder) and cybercriminal operations
- **Current campaigns:** SHADOW#REACTOR (January 2026) demonstrates ongoing evolution with evasive multi-stage chains using LOLBins

---

# 2. ATTACK CHAIN ARCHITECTURE

## Multi-Stage Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Stage 1: Initial Delivery (OpenDirectory Download)              │
│ User downloads Payload.exe from 203[.]159[.]90[.]147            │
│ - File Size: 172,159 bytes                                      │
│ - MD5: 3d7b442573acf64c3aad17b23d224dc9                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 2: VB6 Dropper Execution (Payload.exe)                    │
│ - Visual Basic 6 obfuscated dropper                             │
│ - Heavy string obfuscation, anti-debugging                      │
│ - Extracts embedded Backdoor.exe as %TEMP%\0.dll                │
│ - Executes payload and self-terminates (anti-forensics)         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 3: Remcos RAT Installation (Backdoor.exe / 0.dll)         │
│ - File Size: 94,208 bytes                                       │
│ - MD5: 04693af3b0a7c9788daba8e35f429ba6                         │
│ - Creates mutex: "Remcos_Mutex_Inj"                             │
│ - Installs to: C:\Users\[USER]\AppData\Roaming\remcos\          │
│ - Sets Hidden+System+Read-only attributes                       │
│ - Creates install.bat for file melting                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 4: Persistence Establishment                              │
│ - UAC Bypass: HKLM\...\EnableLUA = 0                            │
│ - Run Keys: HKCU\Run, HKLM\Run                                  │
│ - Winlogon Hijack: Userinit value modification                  │
│ - Policies\Explorer\Run                                         │
│ - Shell Hijack (optional)                                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 5: Surveillance & C2                                      │
│ - Process injection (explorer.exe, msedge.exe)                  │
│ - Screenshot capture (periodic + on-demand)                     │
│ - Microphone recording (continuous)                             │
│ - Keylogging with context                                       │
│ - Credential theft (Chrome, Firefox)                            │
│ - C2 communication to 203[.]159[.]90[.]147                      │
│ - Encrypted data exfiltration via HTTP                          │
└─────────────────────────────────────────────────────────────────┘
```

## Stage 1: VB6 Dropper (Payload.exe)

**File Metadata:**
- Filename: Payload.exe
- Size: 172,159 bytes
- Architecture: x86 (32-bit)
- Language: Visual Basic 6 (MSVBVM60.DLL dependency)
- MD5: 3d7b442573acf64c3aad17b23d224dc9
- SHA1: d71f4efb31786ae71bdd5e7e32531a2698455954
- SHA256: db218dd5f53fbcf39a6db043c8455667c3dbef44abe14865e8b962b4c676372e

**Functionality:**

The dropper serves as the initial infection vector with sophisticated evasion techniques:

1. **Payload Extraction:** Extracts embedded Backdoor.exe from internal resources, writes to %TEMP%\0.dll
2. **Obfuscation:** Heavy string obfuscation conceals operational parameters (C2 addresses, file paths, execution commands)
3. **Anti-Debugging:** Debugger detection causes premature termination under analysis environments
4. **Execution Chain:** Uses VB6 runtime functions (rtcShell, rtcCreateObject2) to execute payload via cmd.exe
5. **Self-Termination:** Exits immediately after payload execution to minimize forensic footprint

**MITRE ATT&CK:**
- T1027 (Obfuscated Files or Information) - Heavy string obfuscation
- T1204.002 (User Execution: Malicious File) - Requires user to execute dropper


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Payload.exe/multi stage dropper.png" | relative_url }}" alt="dropped 0.dll">
  <figcaption><em>Figure 2: Dropped 0.dll</em></figcaption>
</figure>


>ANALYST NOTE: I might not be super clear in the data here but, 0.dll was dropped and when comparing it to file hashes already investigated I found that this 0.dll files has the same hash as Backdoor.exe which will be covered next, making them the same malware file.

## Stage 2: Remcos RAT Payload (Backdoor.exe)

**File Metadata:**
- Filename: Backdoor.exe (persists as remcos.exe)
- Size: 94,208 bytes
- Architecture: x86 (32-bit)
- Compiler: Microsoft Visual C++
- MD5: 04693af3b0a7c9788daba8e35f429ba6
- SHA1: 45aa592f3b30ef526e380978338718f540cff5d2
- SHA256: ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82
- Entropy: 6.0211 (moderate obfuscation/packing)


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/file deleted and started remcos.png" | relative_url }}" alt="persists as remcos.exe">
  <figcaption><em>Figure 3: Final Stage After Backdoor.exe Runs, Removes Itself and All Other Files</em></figcaption>
</figure>


**Execution Flow:**

1. **Initialization:** Checks GetStartupInfoA for hidden launch, creates mutex "Remcos_Mutex_Inj"
2. **Configuration:** Reads internal configuration block containing C2 addresses, encryption keys, persistence settings
3. **System Fingerprinting:** Collects OS version, architecture, user privileges, installed software
4. **Installation:** Copies to C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe with Hidden+System attributes
5. **Persistence:** Establishes five autorun mechanisms
6. **Surveillance:** Launches screenshot, audio, keylogging, clipboard monitoring threads
7. **C2 Connection:** Establishes TCP connection to 203[.]159[.]90[.]147 for command receipt

---

# 3. PERSISTENCE MECHANISMS

## Mechanism 1: UAC Bypass via EnableLUA Registry Modification

**Technique:** System-wide UAC disablement

**Command Executed:**


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg key to remove UAC.png" | relative_url }}" alt="UAC Removal Reg Key">
  <figcaption><em>Figure 4: Setting Registry Key to Disable User Account Control</em></figcaption>
</figure>


**What EnableLUA=0 Does:**

1. **Disables UAC Prompts Globally:** All UAC consent dialogs suppressed for all users
2. **Eliminates Admin Approval Mode:** Administrators run with full privileges by default
3. **Removes Security Boundary:** No separation between standard user and admin contexts
4. **Persistent Impact:** Survives reboots until manually re-enabled

**Security Implications (CRITICAL):**
- Malware performs privileged operations silently (no user prompts)
- Other malware on system also benefits from disabled UAC
- Persistence mechanisms established without triggering alerts
- Social engineering attacks more effective (no UAC warnings)

**Detection Indicators:**
- Command line: cmd.exe spawning reg.exe with EnableLUA arguments
- Registry monitoring: Write to HKLM\...\Policies\System\EnableLUA
- Event ID 4657 (registry value modification), Event ID 4688 (process creation)

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg key to remove UAC popup.png" | relative_url }}" alt="UAC Removal popup">
  <figcaption><em>Figure 5: UAC Disabled Popup</em></figcaption>
</figure>


## Mechanism 2: Winlogon Userinit Hijacking

**Technique:** Winlogon helper executable hijacking

**Registry Modification:**
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit

Original:  "C:\WINDOWS\system32\userinit.exe,"
Modified:  "C:\WINDOWS\system32\userinit.exe, "C:\Users\[USER]\AppData\Roaming\remcos\remcos.exe""
```


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/Userinit Hijack.png" | relative_url }}" alt="Userinit Hijack">
  <figcaption><em>Figure 6: Userinit Hijack</em></figcaption>
</figure>


**Why This Technique Is Particularly Dangerous:**

1. **Execution Timing:** Runs at EVERY user logon before desktop appears
2. **Privilege Level:** Inherits privileges from winlogon.exe process
3. **Stealth:** No visible process start during logon splash screen
4. **Persistence Reliability:** SYSTEM-level registry key, survives Safe Mode
5. **Multi-User Impact:** Triggers for EVERY user account on system

**Detection Methods:**
- Registry monitoring: HKLM\...\Winlogon\Userinit value changes
- Process monitoring: Suspicious children of winlogon.exe
- Baseline: Legitimate value should ONLY contain "C:\WINDOWS\system32\userinit.exe,"

**MITRE ATT&CK:** T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL)

## Mechanism 3: File Installation and "Melting"

**Installation Process:**

1. **Copy to Persistent Location:** C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe
2. **Set File Attributes:** Hidden + System + Read-only (blends with legitimate Windows system files)
3. **Apply Directory Attributes:** Containing directory also receives Hidden+System attributes
4. **Create Self-Deleting Batch Script:** %TEMP%\install.bat


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/Create Self-Deleting Batch Script.png" | relative_url }}" alt="Create Self-Deleting Batch Script">
  <figcaption><em>Figure 7: Create Self-Deleting Batch Script</em></figcaption>
</figure>


**install.bat Technical Analysis:**

```batch
PING 127.0.0.1 -n 2
DEL "[ORIGINAL_PATH]\Backdoor.exe"
start "" "C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe"
DEL "%TEMP%\install.bat"
```

**Anti-Forensics Impact:**
- Original dropper file (Payload.exe) deleted
- Temporary 0.dll deleted
- install.bat self-deletes
- Only persistent copy (remcos.exe) remains on disk
- Initial execution artifacts completely removed
- Forensic timeline analysis disrupted

**MITRE ATT&CK:**
- T1070.004 (Indicator Removal: File Deletion)
- T1564.001 (Hide Artifacts: Hidden Files and Directories)

## Mechanism 4-5: Standard Registry Autorun

**HKCU Run Key (User-Level):**
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Value: "remcos"
Data: "C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe"
```

**HKLM Run Key (System-Level):**
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
Value: "remcos"
Data: "C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe"
```

**Additional Persistence Options (Configuration-Dependent):**
- Shell Hijack: HKLM\...\Winlogon\Shell (appends malware path alongside explorer.exe)
- Policies Explorer Run: HKLM\...\Policies\Explorer\Run

**MITRE ATT&CK:** T1547.001 (Boot or Logon Autostart: Registry Run Keys)


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg keys for persistence.png" | relative_url }}" alt="setting reg keys for persistence">
  <figcaption><em>Figure 8: Setting Registry Keys for Persistence</em></figcaption>
</figure>


---

# 4. SURVEILLANCE AND DATA COLLECTION

## Screenshot Capture

**Module 1: Periodic Capture**
- Initializes GDI+ graphics library
- Captures full screen at configurable intervals
- Saves as PNG to local directory
- Monitors user activity via GetLastInputInfo (avoids capturing idle screens)
- Calls exfiltration routine after each capture
- Local files deleted after successful upload

**Module 2: On-Demand Capture**
- Returns raw BMP image data in memory
- No disk write (anti-forensics)
- Likely used for real-time "live view" commanded by operator

**Exfiltration Method:**
- Encrypted PNG files uploaded via HTTP
- Uses Windows URL Monikers (COM) for stealthy HTTP requests
- CreateURLMoniker API for HTTP POST/PUT operations
- Encryption key stored in configuration

**MITRE ATT&CK:** T1113 (Screen Capture)

## Audio Recording

**Recording Module:**
- Dedicated thread for continuous recording
- Windows Multimedia API: waveInOpen, waveInAddBuffer, waveInStart
- Audio format: 8kHz, 8-bit, mono PCM (low quality, small file size)
- Timestamped WAV filenames (e.g., "2026-02-03 15.30.wav")
- Local storage in configurable directory
- Likely batch exfiltration mechanism

**MITRE ATT&CK:** T1123 (Audio Capture)

## Keylogging and Clipboard Monitoring

**Keylogger Capabilities:**
- Windows hooks via SetWindowsHookExA (global keyboard hook)
- Captures keystrokes with context (active window titles)
- Logs special keys: [Enter], [Ctrl+V], [Print], [PagDw], [Tab], [Backspace]
- Tracks idle time: "{ User has been idle for X minutes }"
- Online/offline logging modes for network-disconnected operation
- Log file formats: "onlinelogs" (real-time transmission), "offlinelogs" (local cache)

**Clipboard Operations:**
- **GetClipboardData:** Captures copied content (passwords, text, file paths)
- **SetClipboardData:** Can inject malicious content into clipboard
- Logs clipboard activity with context

**MITRE ATT&CK:**
- T1056.001 (Input Capture: Keylogging)
- T1115 (Clipboard Data)

> ANALYST NOTE: When I was doing dymanic analysis and debugging of these files I noticed that my clipboard stopped working. When copy and pasting outside the analysis lab VM everything worked but, inside copy and paste did not work once the files were running on the host. This can be a good indicator if users are reporting to the helpdesk that their clipboards are not working or copy and paste is not working. 

## Browser Credential Theft

**Chrome Credential Theft:**
```
Targets:
- %UserProfile%\AppData\Local\Google\Chrome\User Data\Default\Login Data (passwords)
- %UserProfile%\AppData\Local\Google\Chrome\User Data\Default\Cookies (session cookies)

Indicators:
- "[Chrome StoredLogins found, cleared!]"
- "[Chrome Cookies found, cleared!]"
```

**Firefox Credential Theft:**
```
Targets:
- %UserProfile%\AppData\Roaming\Mozilla\Firefox\Profiles\*\key3.db (encryption keys)
- %UserProfile%\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json (passwords)
- %UserProfile%\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite (session cookies)

Indicators:
- "[Firefox StoredLogins cleared!]"
- "[Firefox Cookies not found]"
```


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/browser passwords.png" | relative_url }}" alt="Stolen password file">
  <figcaption><em>Figure 9: Stolen Password File</em></figcaption>
</figure>


**Impact:**
- Exfiltrates saved passwords for email, banking, corporate systems
- Steals authentication cookies enabling session hijacking (bypass 2FA)
- "Cleared" messages suggest theft followed by evidence removal

**MITRE ATT&CK:**
- T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)
- T1539 (Steal Web Session Cookie)

---

# 5. EVASION AND ANTI-ANALYSIS TECHNIQUES

## Process Injection

**Injection Technique:** Process Hollowing / Classic DLL Injection

**API Call Sequence:**
```
Core Injection APIs:
- VirtualAllocEx       → Allocate memory in target process
- WriteProcessMemory   → Write malicious code to allocated memory
- CreateRemoteThread   → Execute injected code in target process
- GetThreadContext     → Retrieve thread state (for hollowing)
- SetThreadContext     → Modify thread execution context
- ResumeThread         → Resume suspended thread
- ReadProcessMemory    → Read target process memory
```

**Target Process Analysis:**

**Target 1: explorer.exe (Windows Explorer)**
- Long-running process (shell - always active)
- Highly trusted by security software
- Network activity appears as Windows shell communication
- Difficult to distinguish from legitimate file operations

**Target 2: msedge.exe (Microsoft Edge Browser)**
- Masquerade C2 traffic as legitimate web browsing
- HTTP/HTTPS communication appears normal from browser process
- Bypasses network filters that allow browser traffic

**Novel Technique: desktop.ini Timing Trigger**

**Discovery:** desktop.ini file paths found on stack during WriteProcessMemory calls


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/desktopini proc injection 3.png" | relative_url }}" alt="desktopini proc injection">
  <figcaption><em>Figure 10: Possible Use of Desktop.ini for Process Injection</em></figcaption>
</figure>


>ANALYST NOTE: During analysis I found Desktop.ini files being scattered all throughout that file system. From user locations like music or documents, to system locations like system32. Information below is based on this behavior identified and infered from the rest of the data. 

**Hypothesis:**
- Malware monitors explorer.exe file access operations to desktop.ini files
- Uses desktop.ini access as opportunistic timing trigger for injection
- Blends injection activity with legitimate folder customization operations
- Forensic analysis shows normal file access, hiding injection evidence

**Detection Methods:**

**Host-Based:**
- Monitor: CreateProcess with CREATE_SUSPENDED flag from AppData executables
- Alert: WriteProcessMemory from non-system processes targeting system processes
- Monitor: Memory protection changes (VirtualAllocEx with PAGE_EXECUTE_READWRITE)

**Memory Forensics:**
- Examine: explorer.exe and msedge.exe memory regions
- Look for: Executable memory not backed by legitimate DLL
- Verify: Thread start addresses pointing to non-module memory

**MITRE ATT&CK:**
- T1055 (Process Injection)
- T1055.012 (Process Hollowing)
- T1055.001 (Dynamic-link Library Injection)

## Anti-VM/Sandbox Detection

**String Artifacts:**
```
HARDWARE\ACPI\DSDT\VBOX__
PROCMON_WINDOW_CLASS
PROCEXPL
```

**Detection Logic:**
- Checks for VirtualBox ACPI signatures in registry
- Detects Process Monitor (PROCMON_WINDOW_CLASS window)
- Detects Process Explorer (PROCEXPL process)
- Likely alters behavior or terminates if VM/analysis tools detected

**MITRE ATT&CK:** T1497.001 (Virtualization/Sandbox Evasion)

## Stealth Mechanisms

**Hidden Window Operations:**
- Creates message-only window (class: "MsgWindowClass")
- No visible GUI - background operations only
- System tray icon created (likely hidden control interface)
- GetStartupInfoA check for SW_HIDE flag

**File Attribute Manipulation:**
- Hidden + System + Read-only attributes
- Blends with legitimate system files
- Requires "Show hidden files" + "Show system files" to view in Explorer


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting file attributes.png" | relative_url }}" alt="Setting file attributes">
  <figcaption><em>Figure 11: Setting File Attributes</em></figcaption>
</figure>


**Stealthy Networking:**
- URL Monikers for HTTP traffic (blends with legitimate web requests)
- Direct IP C2 (avoids DNS monitoring)
- Potential use of injected browser process for C2

**MITRE ATT&CK:**
- T1564.001 (Hide Artifacts: Hidden Files and Directories)
- T1027 (Obfuscated Files or Information)

---

# 6. COMMAND & CONTROL INFRASTRUCTURE

## Primary C2 Server

**IP Address:** 203[.]159[.]90[.]147
**Protocol:** TCP (SOCK_STREAM)
**Discovery Method:** Dynamic analysis breakpoint on ws2_32.gethostbyname

**C2 Characteristics:**
- Direct IP connection (no DNS resolution observed for primary C2)
- TCP socket communication
- Likely custom binary protocol
- Keep-alive mechanism with configurable timeout

**Network Indicators:**
```
Connected to C2!
[DataStart]
[KeepAlive] Enabled! (Timeout: %i seconds)
```


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/C2 IP found.png" | relative_url }}" alt="C2 IP found">
  <figcaption><em>Figure 12: C2 Server Found During Dynamic Analysis</em></figcaption>
</figure>


**Analysis Limitation:**
This analysis did not capture live C2 traffic during the infection window, as the malware was analyzed in an isolated environment without granting network access to the malicious infrastructure. Deep protocol dissection would require live C2 server interaction with packet capture, which was not performed due to operational security constraints.

## Data Exfiltration Mechanisms

**Screenshot Exfiltration:**
- Encrypted PNG files uploaded via HTTP
- Uses Windows URL Monikers (COM) for stealthy HTTP requests
- CreateURLMoniker API for HTTP POST/PUT operations
- Encryption key stored in configuration (data_415950)
- Local screenshots deleted after successful upload


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/screenshot capability using GDI windows call.png" | relative_url }}" alt="screenshot GDI windows call">
  <figcaption><em>Figure 13: Screenshot Capability</em></figcaption>
</figure>


**Audio Exfiltration:**
- WAV files stored locally with timestamps
- Likely batch exfiltration mechanism


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/microphone recording.png" | relative_url }}" alt="microphone recording">
  <figcaption><em>Figure 14: Microphone Recording and Exfiltration</em></figcaption>
</figure>


**MITRE ATT&CK:**
- T1041 (Exfiltration Over C2 Channel)
- T1071.001 (Application Layer Protocol: Web Protocols)

---

# 7. MITRE ATT&CK FRAMEWORK MAPPING

### Execution
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

### Persistence
- T1547.001 - Boot or Logon Autostart: Registry Run Keys (5 methods)
- T1547.004 - Boot or Logon Autostart: Winlogon Helper DLL (Userinit hijack)

### Privilege Escalation
- T1548.002 - Abuse Elevation Control Mechanism: Bypass UAC

### Defense Evasion
- T1070.004 - Indicator Removal: File Deletion (melt technique)
- T1027 - Obfuscated Files or Information (VB6 string obfuscation)
- T1055 - Process Injection (explorer.exe, msedge.exe)
- T1055.012 - Process Hollowing
- T1497.001 - Virtualization/Sandbox Evasion (VM detection)
- T1564.001 - Hide Artifacts: Hidden Files and Directories

### Credential Access
- T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
- T1539 - Steal Web Session Cookie

### Discovery
- T1010 - Application Window Discovery
- T1057 - Process Discovery
- T1082 - System Information Discovery
- T1083 - File and Directory Discovery
- T1033 - System Owner/User Discovery

### Collection
- T1056.001 - Input Capture: Keylogging
- T1113 - Screen Capture (2 methods)
- T1115 - Clipboard Data
- T1123 - Audio Capture
- T1005 - Data from Local System

### Command and Control
- T1071.001 - Application Layer Protocol: Web Protocols (HTTP)
- T1573 - Encrypted Channel (encrypted screenshots)
- T1001 - Data Obfuscation

### Exfiltration
- T1041 - Exfiltration Over C2 Channel

### Impact
- T1529 - System Shutdown/Reboot

**Total Techniques:** 27 distinct MITRE ATT&CK techniques across 10 tactics

---

# 8. THREAT INTELLIGENCE CONTEXT

## Remcos RAT Global Threat Landscape

**Threat Severity:** CRITICAL

**Current Activity (2025-2026):**
- **September-October 2025:** 11% of all infostealer incidents attributed to Remcos (CyberProof Research)
- **January 2026:** SHADOW#REACTOR campaign using evasive multi-stage chains with MSBuild.exe LOLBin
- **Global Impact:** Nearly 150 organizations impacted in Shipping/Logistics, Manufacturing, Industry, Energy sectors

**Distribution Methods (Current Campaigns):**
1. Phishing emails with malicious Office documents
2. Multi-stage loaders (VBScript/VB6 droppers, PowerShell downloaders)
3. Steganography (bitmap images hiding malicious DLLs)
4. Living-off-the-Land Binaries (MSBuild.exe, aspnet_compiler.exe)
5. OpenDirectory staging (2021-present ongoing tactic)

## Threat Actor Spectrum

**Nation-State APT Groups:**
- UAC-0184 (Hive0156) - Russian APT targeting Ukraine
- Gamaredon - Russian APT (active since 2014)
- UAC-0050 - Ukrainian targeting APT (active since 2020)
- Blind Eagle (APT-C-36) - Colombia targeting espionage/cybercrime
- SideWinder - South Asian APT (Operation SouthNet)
- Mysterious Elephant (APT-K-47) - South Asian government targeting

**Cybercrime Operations:**
- Initial Access Brokers (IABs) obtaining footholds for ransomware operators
- Financial fraud targeting institutions
- Cryptocurrency theft operations
- Illegal gambling platform targeting

**Assessment:** Remcos serves as a multi-purpose tool across the threat actor spectrum, from low-skill cybercriminals to sophisticated nation-state APT groups. Attribution based solely on Remcos usage is unreliable without additional infrastructure, TTP, or targeting analysis.

---

# 9. ATTRIBUTION ANALYSIS

## Campaign Sophistication Assessment

**Technical Sophistication:** Medium-High
- Multi-stage VB6 dropper with obfuscation
- Five persistence mechanisms (including rare Userinit hijack)
- Process injection with novel desktop.ini timing trigger
- UAC bypass via EnableLUA registry modification
- Anti-VM/sandbox detection

**Operational Security:** Low-Medium
- **CRITICAL OPSEC FAILURE:** Consolidated distribution and C2 on single IP
- **OpenDirectory Exposure:** Public malware hosting reduces anonymity
- **Infrastructure Reuse:** OpenDirectory hosting suggests long-term infrastructure

**Targeting:** Opportunistic (Likely)
- OpenDirectory distribution suggests broad, non-targeted distribution
- Could be repurposed for targeted attacks if customized per victim

## Threat Actor Profile

**Most Likely Attribution:** Cybercriminal / Initial Access Broker

**Reasoning:**
1. OpenDirectory distribution consistent with opportunistic cybercrime
2. Consolidated infrastructure suggests resource constraints
3. Commercial RAT use aligns with cybercriminal reliance on purchased tools
4. Credential theft capabilities likely for financial fraud or IAB access sales
5. Poor OPSEC inconsistent with nation-state APT tradecraft

**Assessment Confidence:** Moderate
- Attribution based on TTPs, infrastructure patterns, and targeting
- No definitive indicators linking to known threat groups
- Cannot rule out APT false-flag operations entirely

---

# 10. REMEDIATION GUIDANCE

## Immediate Actions

**1. Isolate Infected Systems**
- Disconnect from network (disable network adapters)
- Do NOT shutdown (preserves memory-resident evidence)
- Tag system for forensic collection

**2. Block C2 Infrastructure**
```
Firewall Rule: DENY all traffic to/from 203[.]159[.]90[.]147
Network Perimeter: Block IP at edge firewalls
IDS/IPS: Deploy signatures for Remcos traffic patterns
```

**3. Collect Forensic Evidence**
```
Priority 1: Memory dump (captures injected code, decrypted config)
Priority 2: Disk image
Priority 3: Registry hives export (HKLM\SOFTWARE, HKLM\SYSTEM, HKCU)
Priority 4: Network traffic capture (if ongoing C2 observable)
Priority 5: Event logs (Security, System, Application)
```

## Malware Removal

**Manual Removal Steps:**

```
Step 1: Kill Process
- Terminate remcos.exe process
- Check for injected processes (explorer.exe, msedge.exe) - may require reboot

Step 2: Delete Files
- Remove: C:\Users\[USERNAME]\AppData\Roaming\remcos\ (entire directory)
- Search and delete: %TEMP%\0.dll (if present)
- Search and delete: timestamped .wav files (audio recordings)

Step 3: Remove Registry Keys
- Delete: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\remcos
- Delete: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\remcos
- Delete: HKLM\...\Policies\Explorer\Run\remcos
- Restore: HKLM\...\Winlogon\Userinit to "C:\WINDOWS\system32\userinit.exe,"
- Restore: HKLM\...\Policies\System\EnableLUA to 1
- Check: HKLM\...\Winlogon\Shell for modifications (should be blank or "explorer.exe")

Step 4: Verify Removal
- Reboot to Safe Mode
- Re-verify file and registry artifacts removed
- Check for mutex "Remcos_Mutex_Inj" (should not exist)
- Review autoruns with Microsoft Autoruns tool

Step 5: Restore Security Settings
- Re-enable UAC (reboot required for full effect)
- Verify UAC prompts appear after reboot
```


<figure style="text-align: center;">
  <img src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/mutex.png" | relative_url }}" alt="Mutex found">
  <figcaption><em>Figure 15: Visual of Mutex Found in the Code</em></figcaption>
</figure>


**Automated Removal:**
- Antivirus/EDR should detect as "Remcos RAT" family
- Update definitions if not detected
- Deploy YARA rules for detection across environment
- Consider full system reimage for high-value systems (RECOMMENDED)

## Post-Remediation

**1. Credential Reset (Critical)**
```
Priority 1: All passwords for accounts accessed from infected system
Priority 2: Browser-saved passwords (assume all compromised)
Priority 3: Domain credentials if system was domain-joined
Priority 4: Email accounts, banking, financial services
Priority 5: Two-factor authentication re-enrollment (if SMS-based)
```

**2. Session Invalidation**
```
- Force logoff of all web sessions for affected users
- Revoke all active authentication tokens/cookies
- Invalidate API keys and service account credentials
- Reset VPN credentials
```

**3. Monitoring (30+ days)**
```
Enhanced monitoring for:
- C2 reinfection attempts to 203[.]159[.]90[.]147
- Lateral movement from compromised credentials
- Anomalous authentication attempts
- Data exfiltration patterns
- Registry modifications matching Remcos TTPs
```

---

**MITRE ATT&CK:**
- [Remcos Malware Profile](https://attack.mitre.org/software/S0332/)
- 27 techniques across 10 tactics documented

---

## License
© 2026 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.
