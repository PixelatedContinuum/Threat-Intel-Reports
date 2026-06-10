---
title: "Remcos OpenDirectory Campaign"
date: '2026-02-04'
last_updated: '2026-02-06'
detection_page: /hunting-detections/remcos-opendirectory/
ioc_feed: /ioc-feeds/remcos-opendirectory-campaign.json
ioc_highlights:
  - value: "203[.]159[.]90[.]147"
    note: "C2 server — open directory, payload delivery"
  - value: "04693af3b0a7c9788daba8e35f429ba6"
    note: "Remcos RAT main payload (MD5)"
  - value: "3d7b442573acf64c3aad17b23d224dc9"
    note: "VB6 dropper — Payload.exe (MD5)"
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules-for-endpoint-detection"
  - label: "Sigma Rules"
    anchor: "#sigma-rules-siem-detection"
  - label: "Network Detection"
    anchor: "#network-detection-signatures"
layout: post
permalink: /reports/remcos-opendirectory/
thumbnail: /assets/images/cards/remcos-opendirectory.png
category: "Remote Access Trojan"
hide: true
description: "A CRITICAL-rated Remcos RAT campaign distributed via an open directory at 203.159.90.147, using a VB6-obfuscated dropper as the initial stage. The deployed RAT provides full remote control, continuous keylogging, screenshot capture, microphone recording, clipboard monitoring, and automated credential theft from browsers and system stores."
---


**Campaign Identifier:** OpenDirectory-203.159.90.147-Remcos<br>
**Last Updated:** February 6, 2026<br>
**Threat Level:** CRITICAL


---

## BLUF (Bottom Line Up Front)

An open directory at **203[.]159[.]90[.]147** hosts a two-stage Remcos RAT campaign: a Visual Basic 6 obfuscated dropper (Payload.exe, MD5 `3d7b442573acf64c3aad17b23d224dc9`) extracts and executes the Remcos payload (Backdoor.exe, MD5 `04693af3b0a7c9788daba8e35f429ba6`), which establishes five redundant persistence mechanisms, disables UAC system-wide, injects into explorer.exe and msedge.exe, and exfiltrates screenshots, audio recordings, keystrokes, clipboard contents, and browser credentials to the same IP. The threat actor consolidated distribution and Command and Control (C2) on a single IP — a poor-OPSEC pattern consistent with cybercriminal or initial access broker operations (MODERATE confidence). Overall risk: **9.5/10 CRITICAL**. Block 203[.]159[.]90[.]147 at the network perimeter immediately; see Section 9 for detection guidance and the [IOC feed](/ioc-feeds/remcos-opendirectory-campaign.json) for machine-readable indicators.

---

## 1. Executive Summary

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
      <td>Multi-stage obfuscation, anti-VM detection, process injection with desktop.ini timing triggers</td>
    </tr>
    <tr>
      <td><strong>Active C2 Infrastructure</strong></td>
      <td class="numeric critical">10/10</td>
      <td>Dual-purpose distribution and C2 server at 203[.]159[.]90[.]147 actively operational</td>
    </tr>
  </tbody>
</table>

### Findings at a Glance

This campaign deploys Remcos RAT through a two-stage chain: a VB6 obfuscated dropper extracts the RAT payload, which establishes five persistence mechanisms (including the rarely-seen Winlogon Userinit hijack), disables UAC system-wide, and launches continuous surveillance — keylogging, screenshot capture, microphone recording, clipboard monitoring, and browser credential theft. The RAT injects into explorer.exe and msedge.exe to blend C2 traffic with legitimate Windows activity. Attack chain details are in Section 2; persistence mechanisms in Section 3; surveillance capabilities in Section 4; evasion techniques in Section 5; C2 infrastructure in Section 6.

The campaign's primary risk is complete, persistent access to every compromised endpoint. Credential theft targets Chrome and Firefox saved passwords and session cookies, enabling account takeover across corporate and personal services. The Userinit hijack survives Safe Mode and activates for every user account on the system — standard Run-key removal leaves the infection intact. Threat intelligence context is in Section 8; attribution assessment in Section 9.

Operationally, the threat actor's consolidation of distribution and C2 on a single IP creates a high-value blocking target. Blocking 203[.]159[.]90[.]147 disrupts both payload delivery and post-compromise tasking. Response guidance is in Section 10; YARA, Sigma, and network detection rules are in the [detection file](/hunting-detections/remcos-opendirectory/).

### Primary Threat Vector

- **Distribution Point:** Open directory at hxxp://203[.]159[.]90[.]147/ hosting Payload.exe and Backdoor.exe
- **C2 Infrastructure:** Same IP (203[.]159[.]90[.]147)

> **Assessment Basis:** Static code analysis, dynamic behavioral analysis, string analysis, and correlation with global Remcos threat intelligence. Confidence levels distinguish confirmed findings from analytical judgments. Attribution assessed as cybercriminal/initial access broker operation (MODERATE confidence) based on poor OPSEC and infrastructure consolidation.

### Attack Infrastructure

**Primary IP Address:** 203[.]159[.]90[.]147

**Dual-Purpose Infrastructure:**
- **Distribution:** Open directory hosting Payload.exe, Backdoor.exe, and related samples
- **Command and Control:** TCP-based C2 for victim tasking and data exfiltration

**Operational Security Assessment:**

This infrastructure consolidation represents a likely OPSEC failure by the threat actor: a single IP block disrupts both distribution and C2, the open directory exposes samples for analysis, and server logs may contain victim IP addresses.


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/opendir.png" | relative_url }}" alt="Hunt.io Open Directory">
  <figcaption><em>Figure 1: Hunt.io Open Directory</em></figcaption>
</figure>


**Historical Context:**

Open-directory malware distribution is a documented Remcos tactic since 2021. Threat actors stage binaries on compromised servers, rotating infrastructure when defenders block it. Recent campaigns confirm ongoing use through 2025–2026.

### Threat Level Assessment

**Immediate Threats:**
- **Credential Compromise:** Browser-saved passwords (Chrome, Firefox) and session cookies stolen for account takeover
- **Data Exfiltration:** Screenshots, audio recordings, keystrokes, and clipboard data transmitted to attacker infrastructure
- **Privilege Escalation:** UAC disabled system-wide, enabling silent administrative operations
- **Persistent Access:** Five redundant autorun mechanisms survive reboots and standard removal attempts
- **Full System Control:** Remote command execution, file management, registry manipulation, system shutdown

**Strategic Risks:**
- **Initial Access for Ransomware:** Remcos is frequently used by initial access brokers to sell footholds to ransomware operators
- **Corporate Espionage:** Complete visibility into user activity, communications, and sensitive documents
- **Financial Fraud:** Real-time credential theft enables unauthorized transactions and wire fraud
- **Regulatory Risk:** Data exfiltration involving personal or protected health information triggers notification obligations under applicable regulations

### Global Context

Remcos RAT remains a critical and actively exploited threat in 2025–2026. Security research attributed 11% of all infostealer incidents in Q3 2025 to Remcos (CyberProof Research), with nearly 150 organizations globally impacted in Shipping/Logistics, Manufacturing, Industry, and Energy sectors (Proofpoint). Active campaigns span multiple continents — Ukraine, Colombia, South Korea, Turkey, and South Asia — and the threat actor spectrum ranges from nation-state APT groups (UAC-0184/Hive0156, Gamaredon, SideWinder) to cybercriminal operations. The January 2026 SHADOW#REACTOR campaign demonstrates continued Remcos evolution, using evasive multi-stage chains with LOLBins (MSBuild.exe).

---

## 2. ATTACK CHAIN ARCHITECTURE

### Multi-Stage Execution Flow

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

### Stage 1: VB6 Dropper (Payload.exe)

> **Analyst note:** This section covers the first stage of the attack — a Visual Basic 6 program that conceals the actual malware and installs it without triggering obvious alerts. Understanding how it hides itself explains why standard antivirus may not catch the infection at the point of entry.

**File Metadata:**
- Filename: Payload.exe
- Size: 172,159 bytes
- Architecture: x86 (32-bit)
- Language: Visual Basic 6 (MSVBVM60.DLL dependency)
- MD5: 3d7b442573acf64c3aad17b23d224dc9
- SHA1: d71f4efb31786ae71bdd5e7e32531a2698455954
- SHA256: db218dd5f53fbcf39a6db043c8455667c3dbef44abe14865e8b962b4c676372e

**Functionality:**

1. **Payload Extraction:** Extracts embedded Backdoor.exe from internal resources, writes to %TEMP%\0.dll
2. **Obfuscation:** Heavy string obfuscation conceals C2 addresses, file paths, and execution commands
3. **Anti-Debugging:** Debugger detection causes premature termination under analysis environments
4. **Execution Chain:** Uses VB6 runtime functions (rtcShell, rtcCreateObject2) to execute the payload via cmd.exe
5. **Self-Termination:** Exits immediately after payload execution to minimize forensic footprint

**MITRE ATT&CK:**
- T1027 (Obfuscated Files or Information) — Heavy string obfuscation
- T1204.002 (User Execution: Malicious File) — Requires user to execute dropper


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Payload.exe/multi stage dropper.png" | relative_url }}" alt="dropped 0.dll">
  <figcaption><em>Figure 2: Dropped 0.dll</em></figcaption>
</figure>


> **Analyst note:** Dynamic analysis confirmed that the dropped 0.dll shares the same file hash as Backdoor.exe — they are the same binary delivered under two different names. The dropper writes the payload to a `.dll` extension to reduce suspicion before executing it.

### Stage 2: Remcos RAT Payload (Backdoor.exe)

> **Analyst note:** Backdoor.exe is the Remcos RAT itself — the component that gives the attacker full, persistent control over the infected system. This section documents its installation sequence and post-installation behavior in the order observed during dynamic analysis.

**File Metadata:**
- Filename: Backdoor.exe (persists as remcos.exe)
- Size: 94,208 bytes
- Architecture: x86 (32-bit)
- Compiler: Microsoft Visual C++
- MD5: 04693af3b0a7c9788daba8e35f429ba6
- SHA1: 45aa592f3b30ef526e380978338718f540cff5d2
- SHA256: ebdd31a7622288b15439396a5758ffb0133d28b4bb11e9386187661a4b7d5f82
- Entropy: 6.0211 (moderate obfuscation/packing)


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/file deleted and started remcos.png" | relative_url }}" alt="persists as remcos.exe">
  <figcaption><em>Figure 3: Final Stage After Backdoor.exe Runs, Removes Itself and All Other Files</em></figcaption>
</figure>


**Execution Flow:**

1. **Initialization:** Checks GetStartupInfoA for hidden launch, creates mutex "Remcos_Mutex_Inj"
2. **Configuration:** Reads internal configuration block containing C2 addresses, encryption keys, persistence settings
3. **System Fingerprinting:** Collects OS version, architecture, user privileges, installed software
4. **Installation:** Copies to C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe with Hidden+System attributes
5. **Persistence:** Establishes five autorun mechanisms
6. **Surveillance:** Launches screenshot, audio, keylogging, and clipboard monitoring threads
7. **C2 Connection:** Establishes TCP connection to 203[.]159[.]90[.]147 for command receipt

---

## 3. PERSISTENCE MECHANISMS

> **Analyst note:** Persistence mechanisms are the techniques malware uses to survive a reboot and remain installed even after the user closes the application. This Remcos sample deploys five overlapping methods — removing only one leaves the infection active.

### Mechanism 1: UAC Bypass via EnableLUA Registry Modification

**Technique:** System-wide UAC disablement


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg key to remove UAC.png" | relative_url }}" alt="UAC Removal Reg Key">
  <figcaption><em>Figure 4: Setting Registry Key to Disable User Account Control</em></figcaption>
</figure>


**What EnableLUA=0 Does:**

1. **Disables UAC Prompts Globally:** All UAC consent dialogs suppressed for all users
2. **Eliminates Admin Approval Mode:** Administrators run with full privileges by default
3. **Removes Security Boundary:** No separation between standard user and admin contexts
4. **Persistent Impact:** Survives reboots until manually re-enabled

**Security Implications (CRITICAL):**
- Malware performs privileged operations silently (no user prompts)
- Other malware on the system also benefits from the disabled UAC
- Persistence mechanisms established without triggering alerts
- Social engineering attacks become more effective (no UAC warnings)

**Detection Indicators:**
- Command line: cmd.exe spawning reg.exe with EnableLUA arguments
- Registry monitoring: Write to HKLM\...\Policies\System\EnableLUA
- Event ID 4657 (registry value modification), Event ID 4688 (process creation)

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg key to remove UAC popup.png" | relative_url }}" alt="UAC Removal popup">
  <figcaption><em>Figure 5: UAC Disabled Popup</em></figcaption>
</figure>


### Mechanism 2: Winlogon Userinit Hijacking

**Technique:** Winlogon helper executable hijacking

**Registry Modification:**
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit

Original:  "C:\WINDOWS\system32\userinit.exe,"
Modified:  "C:\WINDOWS\system32\userinit.exe, "C:\Users\[USER]\AppData\Roaming\remcos\remcos.exe""
```


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/Userinit Hijack.png" | relative_url }}" alt="Userinit Hijack">
  <figcaption><em>Figure 6: Userinit Hijack</em></figcaption>
</figure>


**Why This Technique Is Particularly Dangerous:**

1. **Execution Timing:** Runs at every user logon before the desktop appears
2. **Privilege Level:** Inherits privileges from the winlogon.exe process
3. **Stealth:** No visible process start during the logon splash screen
4. **Persistence Reliability:** SYSTEM-level registry key, survives Safe Mode
5. **Multi-User Impact:** Triggers for every user account on the system

**Detection Methods:**
- Registry monitoring: HKLM\...\Winlogon\Userinit value changes
- Process monitoring: Suspicious children of winlogon.exe
- Baseline: Legitimate value should contain only "C:\WINDOWS\system32\userinit.exe,"

**MITRE ATT&CK:** T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL)

### Mechanism 3: File Installation and "Melting"

**Installation Process:**

1. **Copy to Persistent Location:** C:\Users\[USERNAME]\AppData\Roaming\remcos\remcos.exe
2. **Set File Attributes:** Hidden + System + Read-only (blends with legitimate Windows system files)
3. **Apply Directory Attributes:** Containing directory also receives Hidden+System attributes
4. **Create Self-Deleting Batch Script:** %TEMP%\install.bat


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/Create Self-Deleting Batch Script.png" | relative_url }}" alt="Create Self-Deleting Batch Script">
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

### Mechanism 4-5: Standard Registry Autorun

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


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting reg keys for persistence.png" | relative_url }}" alt="setting reg keys for persistence">
  <figcaption><em>Figure 8: Setting Registry Keys for Persistence</em></figcaption>
</figure>


---

## 4. SURVEILLANCE AND DATA COLLECTION

### Screenshot Capture

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
- Used for real-time operator "live view"

**Exfiltration Method:**
- Encrypted PNG files uploaded via HTTP
- Uses Windows URL Monikers (COM) for HTTP POST/PUT operations
- CreateURLMoniker API carries the request
- Encryption key stored in configuration

**MITRE ATT&CK:** T1113 (Screen Capture)

### Audio Recording

**Recording Module:**
- Dedicated thread for continuous recording
- Windows Multimedia API: waveInOpen, waveInAddBuffer, waveInStart
- Audio format: 8kHz, 8-bit, mono PCM (low quality, small file size)
- Timestamped WAV filenames (e.g., "2026-02-03 15.30.wav")
- Local storage in configurable directory
- Batch exfiltration mechanism

**MITRE ATT&CK:** T1123 (Audio Capture)

### Keylogging and Clipboard Monitoring

> **Analyst note:** Keyloggers record every key a user presses — passwords, messages, search queries — and can also intercept the clipboard (the temporary memory used for copy-paste). A compromised clipboard can silently replace a password or bank account number the user copied before they paste it.

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

> **Analyst note:** During dynamic analysis, clipboard operations (copy-paste) inside the analysis VM became non-functional once Backdoor.exe was running. Clipboard failure on an endpoint — especially when reported by users to a helpdesk — is a behavioral indicator of active Remcos infection worth investigating.

**MITRE ATT&CK:**
- T1056.001 (Input Capture: Keylogging)
- T1115 (Clipboard Data)

### Browser Credential Theft

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


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/browser passwords.png" | relative_url }}" alt="Stolen password file">
  <figcaption><em>Figure 9: Stolen Password File</em></figcaption>
</figure>


**Impact:**
- Exfiltrates saved passwords for email, banking, and corporate systems
- Steals authentication cookies enabling session hijacking (bypasses multi-factor authentication)
- The "cleared" log messages indicate theft followed by evidence removal

**MITRE ATT&CK:**
- T1555.003 (Credentials from Password Stores: Credentials from Web Browsers)
- T1539 (Steal Web Session Cookie)

---

## 5. EVASION AND ANTI-ANALYSIS TECHNIQUES

### Process Injection

> **Analyst note:** Process injection is a technique where malware inserts its own code into a legitimate running program — like Windows Explorer — so that its activity appears to come from that trusted program. This lets Remcos hide its network connections and file operations inside processes that security tools are configured to trust.

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
- Long-running process (shell — always active)
- Highly trusted by security software
- Network activity appears as Windows shell communication
- Difficult to distinguish from legitimate file operations

**Target 2: msedge.exe (Microsoft Edge Browser)**
- Masks C2 traffic as legitimate web browsing
- HTTP/HTTPS communication appears normal from browser process
- Bypasses network filters that allow browser traffic

**Novel Technique: desktop.ini Timing Trigger**

**Discovery:** desktop.ini file paths found on the stack during WriteProcessMemory calls


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/desktopini proc injection 3.png" | relative_url }}" alt="desktopini proc injection">
  <figcaption><em>Figure 10: Possible Use of Desktop.ini for Process Injection</em></figcaption>
</figure>


> **Analyst note:** During analysis, desktop.ini files (Windows folder-customization markers) appeared scattered across the file system — from user directories like Music and Documents to system locations including System32. The injection hypothesis below is inferred from this observed behavior and the stack data captured at WriteProcessMemory calls.

**Hypothesis:**
- Malware monitors explorer.exe file access operations to desktop.ini files
- Uses desktop.ini access as an opportunistic timing trigger for injection
- Blends injection activity with legitimate folder customization operations
- Forensic analysis records normal file access, hiding injection evidence

**Detection Methods:**

**Host-Based:**
- Monitor: CreateProcess with CREATE_SUSPENDED flag from AppData executables
- Alert: WriteProcessMemory from non-system processes targeting system processes
- Monitor: Memory protection changes (VirtualAllocEx with PAGE_EXECUTE_READWRITE)

**Memory Forensics:**
- Examine: explorer.exe and msedge.exe memory regions for executable code not backed by a legitimate DLL
- Verify: Thread start addresses pointing to non-module memory

**MITRE ATT&CK:**
- T1055 (Process Injection)
- T1055.012 (Process Hollowing)
- T1055.001 (Dynamic-link Library Injection)

### Anti-VM/Sandbox Detection

**String Artifacts:**
```
HARDWARE\ACPI\DSDT\VBOX__
PROCMON_WINDOW_CLASS
PROCEXPL
```

**Detection Logic:**
- Checks for VirtualBox ACPI signatures in registry
- Detects process monitoring tool (PROCMON_WINDOW_CLASS window class) — behavioral analysis tool for Windows
- Detects process exploration tool (PROCEXPL process) — real-time process viewer for Windows
- Likely alters behavior or terminates when a VM or analysis tool is detected

**MITRE ATT&CK:** T1497.001 (Virtualization/Sandbox Evasion)

### Stealth Mechanisms

**Hidden Window Operations:**
- Creates message-only window (class: "MsgWindowClass")
- No visible GUI — background operations only
- System tray icon created (likely hidden control interface)
- GetStartupInfoA check for SW_HIDE flag

**File Attribute Manipulation:**
- Hidden + System + Read-only attributes
- Blends with legitimate system files
- Requires "Show hidden files" and "Show system files" enabled in Explorer to view


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/setting file attributes.png" | relative_url }}" alt="Setting file attributes">
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

## 6. COMMAND & CONTROL INFRASTRUCTURE

> **Analyst note:** Command and Control (C2) is the communication channel between the malware and the attacker — it is how the attacker issues new commands and receives stolen data. This section covers the C2 protocol observed in Remcos and the mechanisms it uses to exfiltrate captured material.

### Primary C2 Server

**IP Address:** 203[.]159[.]90[.]147
**Protocol:** TCP (SOCK_STREAM)
**Discovery Method:** Dynamic analysis breakpoint on ws2_32.gethostbyname

**C2 Characteristics:**
- Direct IP connection (no DNS resolution observed for primary C2)
- TCP socket communication
- Custom binary protocol
- Keep-alive mechanism with configurable timeout

**Network Indicators:**
```
Connected to C2!
[DataStart]
[KeepAlive] Enabled! (Timeout: %i seconds)
```


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/C2 IP found.png" | relative_url }}" alt="C2 IP found">
  <figcaption><em>Figure 12: C2 Server Found During Dynamic Analysis</em></figcaption>
</figure>


**Analysis Limitation:**
Live C2 traffic was not captured during analysis: the malware was analyzed in an isolated environment without network access to the malicious infrastructure. Full protocol dissection would require live C2 server interaction with packet capture.

### Data Exfiltration Mechanisms

**Screenshot Exfiltration:**
- Encrypted PNG files uploaded via HTTP
- Uses Windows URL Monikers (COM) for stealthy HTTP requests
- CreateURLMoniker API for HTTP POST/PUT operations
- Encryption key stored in configuration (data_415950)
- Local screenshots deleted after successful upload


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/screenshot capability using GDI windows call.png" | relative_url }}" alt="screenshot GDI windows call">
  <figcaption><em>Figure 13: Screenshot Capability</em></figcaption>
</figure>


**Audio Exfiltration:**
- WAV files stored locally with timestamps
- Batch exfiltration mechanism


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/Backdoor.exe/microphone recording.png" | relative_url }}" alt="microphone recording">
  <figcaption><em>Figure 14: Microphone Recording and Exfiltration</em></figcaption>
</figure>


**MITRE ATT&CK:**
- T1041 (Exfiltration Over C2 Channel)
- T1071.001 (Application Layer Protocol: Web Protocols)

---

## 7. MITRE ATT&CK FRAMEWORK MAPPING

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

## 8. THREAT INTELLIGENCE CONTEXT

### Remcos RAT Global Threat Landscape

**Threat Severity:** CRITICAL

**Current Activity (2025-2026):**
- **September–October 2025:** 11% of all infostealer incidents attributed to Remcos (CyberProof Research)
- **January 2026:** SHADOW#REACTOR campaign using evasive multi-stage chains with MSBuild.exe LOLBin
- **Global Impact:** Nearly 150 organizations impacted in Shipping/Logistics, Manufacturing, Industry, and Energy sectors (Proofpoint)

**Distribution Methods (Current Campaigns):**
1. Phishing emails with malicious Office documents
2. Multi-stage loaders (VBScript/VB6 droppers, PowerShell downloaders)
3. Steganography (bitmap images hiding malicious DLLs)
4. Living-off-the-Land Binaries (MSBuild.exe, aspnet_compiler.exe)
5. Open-directory staging (2021–present)

### Threat Actor Spectrum

**Nation-State APT Groups:**
- UAC-0184 (Hive0156) — Russian APT targeting Ukraine
- Gamaredon — Russian APT (active since 2014)
- UAC-0050 — Ukrainian targeting APT (active since 2020)
- Blind Eagle (APT-C-36) — Colombia targeting espionage/cybercrime
- SideWinder — South Asian APT (Operation SouthNet)
- Mysterious Elephant (APT-K-47) — South Asian government targeting

**Cybercrime Operations:**
- Initial Access Brokers (IABs) obtaining footholds for ransomware operators
- Financial fraud targeting institutions
- Cryptocurrency theft operations
- Illegal gambling platform targeting

**Assessment:** Remcos serves as a multi-purpose tool across the threat actor spectrum, from low-skill cybercriminals to nation-state APT groups. Attribution based solely on Remcos usage is unreliable without additional infrastructure, TTP, or targeting analysis.

---

## 9. ATTRIBUTION ANALYSIS

### Campaign Sophistication Assessment

**Technical Sophistication:** Medium-High
- Multi-stage VB6 dropper with obfuscation
- Five persistence mechanisms (including rare Userinit hijack)
- Process injection with desktop.ini timing trigger
- UAC bypass via EnableLUA registry modification
- Anti-VM/sandbox detection

**Operational Security:** Low-Medium
- **CRITICAL OPSEC FAILURE:** Distribution and C2 consolidated on a single IP
- **Open-Directory Exposure:** Public malware hosting reduces anonymity
- **Infrastructure Reuse:** Open-directory hosting suggests long-term infrastructure

**Targeting:** Opportunistic (likely)
- Open-directory distribution suggests broad, non-targeted distribution
- Could be repurposed for targeted attacks if customized per victim

### Threat Actor Profile

**Most Likely Attribution:** Cybercriminal / Initial Access Broker

**Reasoning:**
1. Open-directory distribution consistent with opportunistic cybercrime
2. Consolidated infrastructure suggests resource constraints
3. Commercial RAT use aligns with cybercriminal reliance on purchased tools
4. Credential theft capabilities consistent with financial fraud or IAB access sales
5. Poor OPSEC inconsistent with nation-state APT tradecraft

**Assessment Confidence:** MODERATE
- Attribution based on TTPs, infrastructure patterns, and targeting
- No definitive indicators linking to known threat groups
- Cannot rule out APT false-flag operations entirely

---

## 10. REMEDIATION GUIDANCE

### Immediate Actions

**1. Isolate Affected Systems**
- Disconnect from network
- Preserve memory state for forensic collection

**2. Block C2 Infrastructure**
- Block all traffic to/from 203[.]159[.]90[.]147 at the network perimeter
- Deploy IDS/IPS signatures for Remcos traffic patterns

**3. Collect Forensic Evidence**
- Priority 1: Memory dump (captures injected code, decrypted configuration)
- Priority 2: Disk image
- Priority 3: Registry hives (HKLM\SOFTWARE, HKLM\SYSTEM, HKCU)
- Priority 4: Network traffic capture if active C2 is observable
- Priority 5: Event logs (Security, System, Application)

### Malware Removal

Endpoint detection platforms should identify this sample as "Remcos RAT" family. Update definitions if not detected, and deploy the YARA rules from the [detection file](/hunting-detections/remcos-opendirectory/) across the environment. For high-value systems, full reimaging is recommended.

Manual remediation requires removing the Remcos executable from `C:\Users\[USERNAME]\AppData\Roaming\remcos\`, restoring the Winlogon Userinit registry value to `C:\WINDOWS\system32\userinit.exe,`, removing Remcos Run key entries from HKCU and HKLM, re-enabling UAC (EnableLUA=1), and checking for Shell hijack modifications. Verify removal by confirming mutex "Remcos_Mutex_Inj" is absent after reboot.

### Post-Remediation

**Credential Reset (Critical):**
- Reset all passwords for accounts accessed from affected systems; assume all browser-saved passwords compromised
- Invalidate active web sessions, authentication tokens, cookies, and API keys
- Re-enroll multi-factor authentication where applicable

**Monitoring (30+ days):**
- C2 reinfection attempts to 203[.]159[.]90[.]147
- Lateral movement from compromised credentials
- Anomalous authentication attempts
- Registry modifications matching Remcos TTPs


<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/OpenDirectory-203.159.90.147-Remcos/mutex.png" | relative_url }}" alt="Mutex found">
  <figcaption><em>Figure 15: Visual of Mutex Found in the Code</em></figcaption>
</figure>


---

**MITRE ATT&CK:**
- [Remcos Malware Profile](https://attack.mitre.org/software/S0332/)
- 27 techniques across 10 tactics documented

---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.
