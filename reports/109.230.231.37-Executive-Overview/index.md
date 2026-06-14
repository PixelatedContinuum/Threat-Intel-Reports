---
title: "Arsenal-237 R&D Repository — Executive Overview"
date: '2026-01-12'
layout: post
permalink: /reports/109.230.231.37-Executive-Overview/
thumbnail: /assets/images/cards/109.230.231.37-Executive-Overview.png
category: "Threat Actor R&D"
series: arsenal-237
series_role: parent
series_order: 0
hide: true
description: "Initial discovery of 16 malware samples across a threat actor R&D open directory at 109.230.231.37, assessed as an active testing environment. Key findings include a 10-variant custom ransomware family with hand-coded ChaCha20+RSA-2048 hybrid cryptography and hardware-optimized AVX-512 encryption, alongside RATs, credential stealers, and privilege escalation tools — all pointing to organized, well-resourced development."
stix_bundle: /stix/109.230.231.37-Executive-Overview.json
---

**Campaign Identifier:** Arsenal-237-109.230.231.37-Malware-Repository<br>
**Last Updated:** January 12, 2026<br>
**Threat Level:** CRITICAL


---

> **Series:** This is report 1 of 2 in the Arsenal-237 investigation — start here. The repository documented below kept growing after this analysis: [Arsenal-237 New Files: Advanced Toolkit Analysis](/reports/arsenal-237-new-files/) covers the 11 samples added to the same directory later in January 2026, including BYOVD EDR termination, a kernel-mode rootkit, and enterprise-grade Rust ransomware.

---

## EXECUTIVE SUMMARY (BLUF)

### The Bottom Line

This analysis identified **16 malware samples across 7 reports** distributed from an open web directory at **109.230.231.37**. The collection combines remote access trojans (RATs), **custom ransomware capabilities**, multi-layer persistence mechanisms, and credential theft in a coordinated ecosystem pointing to organized cybercrime operations.

> **Analyst note:** The files' naming conventions, capability set, versioned builds, and testing utilities collectively indicate an active R&D environment rather than an operational deployment. The analysis treats this as a testing ground — new tools or combinations under active development. Full technical depth on the ransomware component is in [enc/dec Ransomware Family (10 variants)]({{ "/reports/enc-dec-ransomware-family/" | relative_url }}).

### CRITICAL DISCOVERY: Custom Ransomware Toolkit

The repository contains a **10-variant ransomware toolkit** — five encryptors and five decryptors — representing a purpose-built capability that pairs data theft with destructive impact.

**Key Findings:**
- **Custom ChaCha20+RSA-2048 hybrid cryptography** — hand-coded implementation, not commodity ransomware
- **Hardware-optimized encryption:** runtime CPU dispatcher selects AVX-512/AVX2/SSE instruction sets for maximum throughput
- **Per-victim key generation** with professional R&D indicators: versioned builds (v2), testing utilities (test_gui, test_decryptor)
- **Mathematically unrecoverable encryption** without the attacker's RSA-2048 private key

**Strategic Implications:** This toolkit enables a dual-threat model — silent data exfiltration followed by ransomware deployment that eliminates recovery through Volume Shadow Copy deletion.

**WHAT WAS FOUND:**
The Hunters Ledger analysis examined **16 malware samples across 7 reports** selected from an open directory containing 38 malicious executables. Samples include a Golang-compiled RAT, Xworm RAT versions 1 and 2.4.0, a **10-variant custom ransomware family (enc/dec toolkit)**, persistence droppers (FleetAgentAdvanced, FleetAgentFUD), and a UAC bypass proof-of-concept. All Xworm variants share C2 infrastructure at **109.230.231.37**, indicating centralized operations. FleetAgentAdvanced.exe implements **quadruple-redundant persistence** across Registry Run keys, Scheduled Tasks, and dual Startup folder shortcuts — designed to survive multiple cleanup attempts.

**BUSINESS IMPACT IF INFECTED:**
Successful infection enables threat actors to establish persistent remote access, harvest credentials (browser passwords, saved authentication tokens, session cookies), exfiltrate sensitive data, **deploy custom ransomware for total data loss**, and use compromised machines as pivot points. Organizations facing compromise should anticipate multi-day to multi-week response efforts. Beyond the immediate technical compromise:

- **Operational Disruption:** Credential theft and data exfiltration require intensive investigation to determine breach scope, followed by extended remediation — credential rotation, system rebuilds, and security control deployment. **Ransomware deployment compounds this: immediate business operation cessation, total data loss requiring the attacker's private key for recovery, and elimination of Volume Shadow Copy backups.** Hardware-optimized encryption (AVX-512) can process enterprise file servers at high speed; organizations without verified offline backups face complete data loss.

- **Compliance Obligations:** Data exfiltration involving regulated personal or health information triggers breach-notification obligations in most jurisdictions. Organizations must assess whether protected health information, personally identifiable information, or payment card data was compromised. **Ransomware encryption adds a separate dimension**: unlike exfiltration where data remains accessible to the organization, encryption constitutes permanent data destruction and carries distinct notification requirements under most frameworks.

- **Reputational Impact:** Credential theft and data breach incidents erode customer trust and create competitive disadvantage in security-conscious markets. Organizations in regulated industries may face procurement exclusions or contract compliance challenges. **Ransomware incidents typically require public disclosure** with significantly higher media visibility than credential theft alone.

**IMMEDIATE ACTIONS REQUIRED:**

1. **BLOCK CRITICAL INFRASTRUCTURE:** Add **109.230.231.37** to firewall deny lists, web proxy blocklists, and DNS sinkhole configurations. This indicator appears across all Xworm RAT variants and represents the highest-confidence single blocking opportunity.

2. **DEPLOY DETECTION SIGNATURES:** Import YARA rules to endpoint detection platforms and Sigma rules to SIEM platforms. Detection packages are organized by malware sample. **Priority: deploy enc/dec ransomware family detection rules immediately** (see [enc/dec Ransomware Detection Package]({{ "/hunting-detections/enc-dec-ransomware-family/" | relative_url }})) and the Quick Reference links below.

3. **HUNT FOR EXISTING INFECTIONS:** Hunt for persistence artifacts (Registry Run keys named "WindowsDefenderUpdate" or "Microsoft .NET Runtime Optimization"), suspicious scheduled tasks (Microsoft-themed task names executing from `%AppData%`), **ransomware executables (enc\*.exe, dec\*.exe, updated_enc.exe, test_gui_enc\*.exe patterns)**, and network connections to 109.230.231.37. Detailed hunting queries are in the Quick Start Detection Guide below.

4. **VERIFY OFFLINE BACKUP INTEGRITY (CRITICAL FOR RANSOMWARE DEFENSE):** The enc/dec ransomware family deletes Volume Shadow Copies, eliminating Windows built-in recovery. Without verified offline backups, encryption produces permanent data loss. Verify that offline backup systems are functional, network-isolated (air-gapped or tape), and tested for restoration.

5. **VERIFY SYSTEM INTEGRITY (IF INFECTIONS FOUND):** The quadruple-redundant persistence in FleetAgentAdvanced and dual-layer persistence in agent.exe are designed to survive partial remediation, increasing residual risk. For confirmed infections, complete system rebuilds are preferred over incremental cleanup. **If ransomware executables are detected, isolate affected systems from the network immediately to limit encryption spread.**

**RISK ASSESSMENT:**
- **CURRENT RISK (No Action):** **CRITICAL (8.5/10)** — Open directory distribution enables widespread opportunistic infections; professional persistence mechanisms ensure long-term access; shared C2 infrastructure enables coordinated operations; **custom ransomware presents catastrophic unrecoverable data loss risk**; dual espionage + ransomware threat model.
- **RESIDUAL RISK (After Mitigation):** **LOW (2.3/10)** — Network blocking severs C2 connectivity for Xworm variants; detection signatures identify infections before persistence establishes; threat hunting removes existing compromises; offline backup verification provides ransomware recovery capability.

**ASSESSMENT BASIS:**
This analysis covers seven publication-quality malware reports on 16 samples selected from 38 executables in the open directory. Methodology combined static analysis, dynamic behavioral monitoring, memory forensics, cryptographic reverse engineering (for the ransomware family), and threat intelligence research. Technical findings were verified across multiple independent analysis tools; confidence levels are documented in individual reports.

---

## Quick Reference: Malware Analysis Resources
### Arsenal-237: Threat Actor R&D Repository Exposed

Each malware sample analyzed in this investigation has three companion resources: a technical report with behavioral analysis and response guidance, a detection package with YARA/Sigma rules for hunting and prevention, and a machine-readable IOC feed in JSON format for SIEM/EDR ingestion.

**agent.exe (Golang RAT):** | [Technical Report]({{ "/reports/agent-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/agent-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/agent-exe.json" | relative_url }})
**agent_xworm.exe (XWorm RAT v6):** | [Technical Report]({{ "/reports/agent-xworm-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/agent-xworm-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/agent-xworm-exe.json" | relative_url }})
**agent_xworm_v2.exe (XWorm RAT v2.4.0):** | [Technical Report]({{ "/reports/agent-xworm-v2-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/agent-xworm-v2-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/agent-xworm-v2-exe.json" | relative_url }})
**enc/dec Ransomware Family (10 variants):** | [Technical Report]({{ "/reports/enc-dec-ransomware-family/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/enc-dec-ransomware-family/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/enc-dec-ransomware-family.json" | relative_url }})
**FleetAgentAdvanced.exe (Multi-Persistence Dropper):** | [Technical Report]({{ "/reports/fleetagentadvanced-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/fleetagentadvanced-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/fleetagentadvanced-exe.json" | relative_url }})
**FleetAgentFUD.exe (WebSocket RAT):** | [Technical Report]({{ "/reports/fleetagentfud-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/fleetagentfud-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/fleetagentfud-exe.json" | relative_url }})
**uac_test.exe (UAC Bypass PoC):** | [Technical Report]({{ "/reports/uac-test-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/uac-test-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/uac-test-exe.json" | relative_url }})

---

## Quick Facts Box

<table class="professional-table">
  <thead>
    <tr>
      <th>Category</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Threat Infrastructure</strong></td>
      <td>IP: <code>109.230.231.37</code> (C2 server + malware hosting)</td>
    </tr>
    <tr>
      <td><strong>Samples Analyzed</strong></td>
      <td>16 samples in 7 reports (from directory with 38+ executables)</td>
    </tr>
    <tr>
      <td><strong>Malware Families</strong></td>
      <td>Golang RAT, enc/dec Ransomware (10 variants), Xworm RAT v1/v2.4.0, FleetAgent WebSocket RATs</td>
    </tr>
    <tr>
      <td><strong>Publication Reports</strong></td>
      <td>7 technical reports (linked below)</td>
    </tr>
    <tr>
      <td><strong>Detection Packages</strong></td>
      <td>7 hunting/detection guides (see <a href="{{ "/hunting-detections/" | relative_url }}">Hunting Detections</a>)</td>
    </tr>
    <tr>
      <td><strong>Overall Risk Rating</strong></td>
      <td class="critical">CRITICAL (8.5/10) - Custom ransomware, dual espionage+destruction operations</td>
    </tr>
    <tr>
      <td><strong>Primary Capabilities</strong></td>
      <td>Remote access, credential theft, data exfiltration, multi-layer persistence, <strong>custom ransomware (ChaCha20+RSA-2048)</strong></td>
    </tr>
    <tr>
      <td><strong>Target Industries</strong></td>
      <td>ALL SECTORS (opportunistic distribution model)</td>
    </tr>
    <tr>
      <td><strong>Analysis Period</strong></td>
      <td>December 21, 2025 - Ongoing</td>
    </tr>
  </tbody>
</table>

---

## Risk Categorization

### CRITICAL Risk - Immediate Analysis Recommended

**[enc/dec Ransomware Family (10 variants)](enc-dec-ransomware-family.md)** | Comprehensive Report
**Risk:** CRITICAL | **Capabilities:** Custom ChaCha20+RSA-2048 encryption, AVX-512 hardware optimization, Volume Shadow Copy deletion, per-victim key generation
**Key Finding:** Professional R&D environment with versioned builds, testing utilities, mathematically unrecoverable encryption, and dual espionage+destruction operations capability

**[agent.exe - PoetRAT Malware](agent-exe.md)** | 34 KB Report
**Risk:** CRITICAL | **Capabilities:** Process injection, dual persistence, extensive cryptography, credential theft potential
**Key Finding:** Golang-compiled RAT with dormant C2, masquerading as Windows Defender service (WinDefenderSvc.exe)

---

### HIGH Risk - Active C2 & Persistence Capabilities

**[agent_xworm.exe - Xworm RAT v1](agent-xworm-exe.md)** | 21 KB Report
**Risk:** HIGH | **C2 Server:** 109.230.231.37 | **Capabilities:** PowerShell execution, system reconnaissance
**Key Finding:** Hardcoded C2 authentication token reveals centralized threat infrastructure

**[agent_xworm_v2.exe - Xworm RAT v2.4.0](agent-xworm-v2-exe.md)** | 27 KB Report
**Risk:** HIGH | **C2 Server:** 109.230.231.37 | **Protocol:** WebSocket-based C2
**Key Finding:** Enhanced version with WebSocket protocol upgrade from TCP-based predecessor

**[FleetAgentAdvanced.exe - Multi-Persistence Dropper](fleetagentadvanced-exe.md)** | 68 KB Report
**Risk:** HIGH | **Persistence Layers:** 4 mechanisms | **Dropped Payload:** RuntimeOptimization.exe (27 KB)
**Key Finding:** Quadruple-redundant persistence (Registry Run + Scheduled Task + 2x Startup LNK) deployed in 1.3 seconds

**[FleetAgentFUD.exe - WebSocket RAT](fleetagentfud-exe.md)** | 53 KB Report
**Risk:** HIGH | **Size:** 17.5 KB | **Protocol:** WebSocket with X-Agent-Secret header
**Key Finding:** Lightweight FUD (Fully Undetectable) design with PowerShell-based post-exploitation capabilities

---

### LOW Risk - Proof-of-Concept / Research Tool

**[uac_test.exe - UAC Bypass PoC](uac-test-exe.md)** | 46 KB Report
**Risk:** LOW (2.1/10) | **Type:** Security research tool
**Key Finding:** CMSTPLUA COM + Fodhelper UAC bypass techniques; detected admin privileges and self-terminated without execution

---

## Campaign Summary

Analysis of the open directory at **109.230.231.37** (38 malicious executables total, 16 examined in depth) reveals a multi-tier threat ecosystem combining remote access trojans, **custom ransomware capabilities**, multi-layer persistence droppers, and proof-of-concept exploitation tools. Shared C2 infrastructure, diverse malware families coordinated through centralized infrastructure, and deceptive Microsoft-themed naming ("WinDefenderSvc.exe", "Microsoft .NET Runtime Optimization") designed to blend with legitimate system processes all indicate organized operations.

**The most significant discovery is the enc/dec ransomware family** — a 10-variant toolkit (5 encryptors, 5 decryptors) featuring custom ChaCha20+RSA-2048 hybrid cryptography, hardware-optimized encryption (AVX-512/AVX2/SSE runtime CPU dispatcher), per-victim key generation, and development indicators including versioned builds (enc_v2.exe, test_gui_enc_v2.exe) and testing utilities.

### Technical Sophistication Spectrum

Technical sophistication spans the Golang-compiled PoetRAT variant — with AES, ChaCha20, and RSA cryptographic capabilities and process injection potential — down to the lightweight 17 KB FleetAgentFUD.exe using WebSocket-based C2 with custom authentication headers. Xworm RAT variants carry hardcoded C2 authentication tokens (AgentSec_8hJ3kL6mN9pQ2rS5tU8vW1xY4zA7bC0d), PowerShell-based reconnaissance, and **environment-aware activation** (dormancy mechanisms) designed to evade automated sandbox detection.

### Persistence Engineering Excellence

The most operationally significant persistence finding is **FleetAgentAdvanced.exe**, which deploys four independent mechanisms in 1.3 seconds:

1. **Registry Run Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft .NET Runtime Optimization`
2. **Scheduled Task:** `\Microsoft\Windows\.NET Runtime Optimization` executing at user logon
3. **Startup Folder LNK (User Profile):** `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft .NET Runtime Optimization.lnk`
4. **Startup Folder LNK (Common Startup):** Duplicate shortcut in alternate Startup directory

The malware deleted the scheduled task XML configuration file immediately after creation — an anti-forensic step indicating the operators anticipated security response.

### Network Infrastructure Patterns

All Xworm variants share a single C2 server (**109.230.231.37**), providing defenders with a high-value blocking opportunity: one network indicator neutralizes multiple malware families simultaneously. Dynamic analysis identified active persistence establishment in agent.exe and FleetAgentAdvanced.exe; other samples exhibited dormant behavior, likely awaiting environmental conditions, time triggers, or successful C2 handshakes before activating.

> **Analyst Assessment:** Multiple technical indicators suggest this infrastructure is a testing environment rather than an operational deployment. Unlike campaigns with C2 obfuscation (dynamic assignments, encryption), this repository uses static and sometimes hardcoded C2 addresses — consistent with development and QA operations rather than operationally security-conscious deployment.

---

## Additional Analysis: AutomatedReports Overview

Beyond the 7 reports, **32 additional malware samples** from the same open directory received automated static analysis through a custom-built StaticTriage framework. These samples provide context for the distribution infrastructure's full scope.

### Sample Categories

**Agent RAT Variants** (8 samples):
- agent_anycpu.exe, agent_dotnet.exe, agent_dotnet_slim.exe, agent_dotnet_v2.exe, agent_dotnet_v3.exe, agent_fw.exe, agent_fw_x64.exe, agent_mem_x64.exe
- **Common Characteristics:** .NET-compiled RAT variants with DNS capabilities, mutex implementations, and varying compilation targets (AnyCPU, x86, x64, memory-only execution)
- **Threat Level:** MEDIUM to HIGH — same RAT family as the comprehensive agent.exe analysis, different compilation configurations

**FleetAgent Suite** (6 samples):
- FleetAgent_MemoryOnly.exe, FleetAgentAdvanced.exe, FleetAgentAdvanced_embedded.exe, FleetAgentEDR.exe, FleetAgentFUD.exe, FleetAgentFull.exe
- **Common Characteristics:** Malware-as-a-service suite with specialized variants for different evasion scenarios (memory-only, EDR evasion, fully-undetectable builds)
- **Threat Level:** HIGH to CRITICAL — demonstrates toolkit diversity and operational maturity

**Encryption/Decryption Utilities** (10 samples):
- **Encryptors (5):** enc.exe, enc_v2.exe, updated_enc.exe, enc_pervictim.exe, test_gui_enc_v2.exe
- **Decryptors (5):** dec.exe, dec_fast.exe, dec_pc3.exe, dec_unique.exe, test_decryptor.exe
- **Common Characteristics:** Ransomware toolkit with custom ChaCha20+RSA-2048 hybrid encryption, AVX-512 hardware optimization, and per-victim key generation
- **Threat Level:** CRITICAL — active ransomware deployment capability
- **Full Analysis:** See [enc/dec Ransomware Family comprehensive report]({{ "/reports/enc-dec-ransomware-family/" | relative_url }})

**Test/Development Tools** (2 samples):
- test_nopass.exe, test_pass.exe
- **Common Characteristics:** Testing utilities for authentication/password functionality, likely part of the development and QA process
- **Threat Level:** LOW — development artifacts, not weaponized malware
- **Note:** test_decryptor.exe and test_gui_enc_v2.exe moved to Encryption/Decryption Utilities section

**XWorm RAT Variants** (2 samples):
- agent_xworm.exe, agent_xworm_v2.exe
- **Analysis:** Covered in comprehensive reports (see [agent-xworm-exe.md](agent-xworm-exe.md) and [agent-xworm-v2-exe.md](agent-xworm-v2-exe.md))
- **Threat Level:** HIGH — active C2 infrastructure, PowerShell execution, multi-malware deployment

**Specialized Utilities** (4 samples):
- ProtonVPN.exe, steal_browser.exe, uac_test.exe, agent.exe
- **ProtonVPN.exe:** Legitimate VPN client or bundled/trojanized version (requires behavioral analysis for confirmation)
- **steal_browser.exe** (8.09 MB): Large credential theft tool with anti-analysis capabilities (debugger detection, VM detection, PowerShell integration)
- **uac_test.exe:** UAC bypass proof-of-concept (covered in comprehensive report uac-test-exe.md)
- **Threat Level:** VARIABLE — steal_browser.exe is CRITICAL for credential theft, ProtonVPN requires context, uac_test.exe is LOW risk

### Key Findings from AutomatedReports

**Infrastructure Insight:** The 32+ samples confirm this is a **threat actor toolkit repository**, not a single-purpose distribution point. The diversity of families — RAT variants, ransomware components, credential stealers, testing tools — indicates:
- **Organized operations** with mature development processes (test builds, versioned releases)
- **Malware-as-a-Service infrastructure** covering multiple attack scenarios
- **Tool chain coverage** from initial access (RATs) through privilege escalation (UAC bypass), credential theft (steal_browser), to impact (encryption utilities)

**Detection Priority:** Automated detection signatures (YARA, file hashes) for all 32 samples are available in the detection packages alongside the 7 priority reports.

> **Automated Analysis:** All 32 samples underwent automated static analysis via the StaticTriage framework. Full reports will be published as manual analysis surfaces high-impact findings. Raw static triage data from these samples is available on request via The Hunters Ledger contact page.

---

## Business Impact Analysis

### Impact Scenarios by Likelihood

<table class="professional-table">
  <thead>
    <tr>
      <th>Scenario</th>
      <th>Likelihood</th>
      <th>Business Impact Explanation</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Credential Theft & Account Compromise</strong></td>
      <td class="critical">HIGH</td>
      <td>All analyzed RAT variants include credential harvesting capabilities (browser passwords, saved authentication tokens, session cookies). Successful credential theft enables unauthorized access to business systems, email accounts, financial platforms, and cloud services. Time-to-detect for compromised credentials commonly exceeds six months, during which secondary attacks using stolen credentials often cause greater damage than the initial compromise.</td>
    </tr>
    <tr>
      <td><strong>Data Exfiltration of Sensitive Business Data</strong></td>
      <td class="critical">HIGH</td>
      <td>RAT capabilities enable file system access, screenshot capture, and clipboard monitoring — facilitating exfiltration of intellectual property, financial records, customer data, and strategic business documents. Exfiltration of regulated data triggers mandatory breach notification obligations in most jurisdictions, resulting in regulatory scrutiny, potential enforcement actions, and customer notification requirements.</td>
    </tr>
    <tr>
      <td><strong>Lateral Movement & Network-Wide Compromise</strong></td>
      <td class="high">MEDIUM-HIGH</td>
      <td>Credential theft combined with network reconnaissance capabilities (PowerShell-based domain enumeration, service discovery) enables pivoting from initially compromised workstations to servers, databases, and critical infrastructure. Environments without sufficient network segmentation face the highest exposure.</td>
    </tr>
    <tr>
      <td><strong>Persistent Backdoor Access (Long-Term)</strong></td>
      <td class="high">MEDIUM-HIGH</td>
      <td>Quadruple-redundant persistence mechanisms ensure malware survival across system reboots, Windows updates, and partial cleanup attempts. Organizations discovering infections months after initial compromise face expanded breach scope, greater remediation complexity, and heightened regulatory scrutiny.</td>
    </tr>
    <tr>
      <td><strong>Ransomware Deployment via Custom enc/dec Toolkit</strong></td>
      <td class="critical">HIGH</td>
      <td><strong>The same infrastructure hosts a 10-variant ransomware toolkit (enc/dec family).</strong> Remote access capabilities enable threat actors to deploy custom ChaCha20+RSA-2048 ransomware as a secondary payload after establishing persistence and exfiltrating valuable data. Affected organizations face dual-extortion scenarios: threatened publication of exfiltrated data combined with encryption of production systems. Hardware-optimized encryption (AVX-512) can process file servers rapidly. Volume Shadow Copy deletion eliminates Windows built-in recovery. <strong>Without offline backups, data loss is mathematically unrecoverable.</strong></td>
    </tr>
    <tr>
      <td><strong>Regulatory Penalties & Compliance Violations</strong></td>
      <td class="medium">MEDIUM</td>
      <td>Exfiltration of personally identifiable information, protected health information, or payment card data triggers regulatory compliance requirements across major frameworks. Affected organizations face mandatory breach notification obligations, regulatory audits, potential enforcement actions, and ongoing compliance monitoring.</td>
    </tr>
  </tbody>
</table>

### Operational Impact Timeline (If Infection Confirmed)

**Initial Response Phase (First 24 Hours):**
- **Personnel Required:** Incident response team, IT operations staff, executive leadership notification
- **Activities:** Isolate infected systems, preserve forensic evidence, deploy network monitoring, initiate credential rotation for high-value accounts

**Investigation Phase (Days 1-7):**
- **Personnel Required:** Forensic analysts, threat hunters, legal counsel, compliance officers
- **Activities:** Memory forensics, log analysis, network traffic review, breach scope determination, regulatory notification assessment

**Remediation Phase (Days 7-21):**
- **Personnel Required:** System administrators, security engineers, help desk support (increased staffing)
- **Activities:** Complete system rebuilds, credential rotation (all users in affected departments), security control deployment, policy updates

**Enhanced Monitoring Phase (Days 21-90):**
- **Personnel Required:** Security operations center (SOC) analysts, threat intelligence team
- **Activities:** Continuous monitoring for reinfection indicators, threat hunting for missed compromises, security control validation

---

## Quick Start Detection Guide

### IMMEDIATE ACTIONS (Deploy Within 24 Hours)

**1. BLOCK CRITICAL NETWORK INFRASTRUCTURE**

```
IP Address: 109.230.231.37
Priority: CRITICAL (P0)
Action: DENY/DROP all inbound and outbound connections
Scope: Firewall rules, web proxy blocklists, DNS sinkhole, IPS/IDS signatures
```

**Implementation Commands:**

*Windows Firewall (PowerShell):*
```powershell
New-NetFirewallRule -DisplayName "Block Xworm C2 - 109.230.231.37" `
  -Direction Outbound -Action Block -RemoteAddress 109.230.231.37
```

*Cisco ASA Firewall:*
```
access-list BLOCK_MALWARE_C2 extended deny ip any host 109.230.231.37
```

*Palo Alto Networks Firewall:*
```
set address "Xworm-C2-109.230.231.37" ip-netmask 109.230.231.37/32
set rulebase security rules "Block-Xworm-C2" source any destination "Xworm-C2-109.230.231.37" action deny
```

**2. DEPLOY ENDPOINT DETECTION SIGNATURES**

**Detection Package Locations:**
- **YARA Rules:** See [Hunting Detections]({{ "/hunting-detections/" | relative_url }}) section for sample-specific detection packages
- **Sigma Rules:** See [Hunting Detections]({{ "/hunting-detections/" | relative_url }}) section for sample-specific detection packages
- **Network Signatures:** See [Hunting Detections]({{ "/hunting-detections/" | relative_url }}) section for sample-specific detection packages

**3. EXECUTE THREAT HUNTING PROCEDURES**

*PowerShell - Registry Persistence Check:*
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
  Where-Object {
    $_.PSObject.Properties.Name -match "WindowsDefender|\.NET Runtime|WinDefender"
  } | Select-Object PSPath, PSChildName, *
```

*Splunk SPL - Network Connection Hunt:*
```spl
index=firewall OR index=proxy
  dest_ip="109.230.231.37"
  | stats count by src_ip, dest_port, action
  | where action="allowed"
```

---

### HIGH-PRIORITY ACTIONS (Deploy Within 1 Week)

**1. Deploy Complete Detection Packages**

Each malware sample has a dedicated detection guide (see [Hunting Detections]({{ "/hunting-detections/" | relative_url }}) section):
- [agent.exe - PoetRAT malware detections]({{ "/hunting-detections/agent-exe/" | relative_url }})
- [agent_xworm.exe - Xworm RAT v6 detections]({{ "/hunting-detections/agent-xworm-exe/" | relative_url }})
- [agent_xworm_v2.exe - Xworm RAT v2.4.0 detections]({{ "/hunting-detections/agent-xworm-v2-exe/" | relative_url }})
- [FleetAgentAdvanced.exe - Multi-persistence dropper detections]({{ "/hunting-detections/fleetagentadvanced-exe/" | relative_url }})
- [FleetAgentFUD.exe - WebSocket RAT detections]({{ "/hunting-detections/fleetagentfud-exe/" | relative_url }})
- [uac_test.exe - UAC bypass PoC detections]({{ "/hunting-detections/uac-test-exe/" | relative_url }})

**2. Establish Enhanced Monitoring**

Configure SIEM correlation rules for these behavioral patterns:
- .NET processes spawning PowerShell child processes with `-NoProfile -NonInteractive -WindowStyle Hidden` flags
- WebSocket connections from non-browser executables (10-30 KB file sizes)
- Scheduled task creation with task names containing "Microsoft" + execution paths in `%AppData%`
- Registry Run key modifications with values pointing to `%AppData%` or `%LocalAppData%` executables

---

## Indicators of Compromise (IOCs)

### Network Indicators

**Critical C2 Infrastructure:**
```
IP Address: 109.230.231.37
Context: Command & Control server for Xworm RAT variants + malware hosting
Confidence: CONFIRMED (hardcoded in agent_xworm.exe and agent_xworm_v2.exe)
```

**Authentication Tokens:**
```
AgentSec_8hJ3kL6mN9pQ2rS5tU8vW1xY4zA7bC0d
Used by: agent_xworm.exe, agent_xworm_v2.exe
```

**Network Protocol Indicators:**
- WebSocket (ws://) connections from non-browser processes
- Custom HTTP header: `X-Agent-Secret: [authentication_token]`
- Base64-encoded TCP traffic to external IPs
- Long-lived connections with periodic heartbeat patterns (30-60 second intervals)

---

### File Hashes

**agent.exe (PoetRAT Malware - CRITICAL)**
```
SHA-256: e7f9a29dde307afff4191dbc14a974405f287b10f359a39305dccdc0ee949385
SHA-1:   e0fe41acd28cae74d75fcbf2f9309ff523c0f36a
MD5:     b1d5e55b1c15b7cb839138625d9d2efa
Size:    4,825,088 bytes (4.7 MB)
```

**WinDefenderSvc.exe (Dropped by agent.exe)**
```
SHA-256: 4e856041018242c62b3848d63b94c3763beda01648d3139060700c11e9334ad1
Size:    4,825,088 bytes (4.7 MB)
```

**agent_xworm.exe (Xworm RAT v1 - HIGH)**
```
SHA-256: 0ec3fca58ef8f0d9f098cd749dd209fccda7cbf68c1eecf836668e5dabd6f3bc
SHA-1:   0102782950619820bbcd60efca256c907403cfb0
MD5:     9d963f85812fd02e382a48c41fc0387e
Size:    16,384 bytes (16 KB)
```

**agent_xworm_v2.exe (Xworm RAT v2.4.0 - HIGH)**
```
SHA-256: f8e7e73bf2b26635800a042e7890a35f7376508f288a1ced3d3e12b173c5cb7e
SHA-1:   7c624e0b11c817d516f9411972191c4627fd2e53
MD5:     4164a1945d8373255a5cb7e42f05c259
Size:    16,384 bytes (16 KB)
```

**FleetAgentAdvanced.exe (Multi-Persistence Dropper - HIGH)**
```
SHA-256: 172258e53b9506a7671deab25d2ad360cd833a4942609f1a4836d305ffe4578b
Size:    18,432 bytes (18 KB)
Dropped Payload: RuntimeOptimization.exe (27 KB)
```

**RuntimeOptimization.exe (Dropped by FleetAgentAdvanced.exe)**
```
SHA-256: 9fc6b69623133f5d6f1f4cda0ec4319300080c9bbaa0f88c93f01eeba84e80e7
Size:    27,648 bytes (27 KB)
```

**FleetAgentFUD.exe (WebSocket RAT - HIGH)**
```
SHA-256: 072ce701ec0252eeddd6a0501555296bce512a7b90422addbb6d3619ae10f4ff
Size:    17,920 bytes (17.5 KB)
```

**uac_test.exe (UAC Bypass PoC - LOW)**
```
SHA-256: 18da271868c434494a68937fa12cb302d37b14849c4c0fc1db4007ac13c5b760
Size:    285,184 bytes (278.5 KB)
```

---

### Host-Based Indicators

**File System Artifacts:**
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WinDefenderSvc.exe
%LocalAppData%\Temp\.wd_installed
C:\Users\[username]\AppData\Roaming\Microsoft\CLR\RuntimeOptimization.exe
%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft .NET Runtime Optimization.lnk
```

**Registry Persistence Mechanisms:**
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefenderUpdate
  Malware: agent.exe (PoetRAT malware)

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft .NET Runtime Optimization
  Malware: FleetAgentAdvanced.exe
```

**Scheduled Tasks:**
```
Task Name: Microsoft\Windows\.NET Runtime Optimization
Action:    Execute RuntimeOptimization.exe from %AppData%\Microsoft\CLR\
Trigger:   At user logon
Malware:   FleetAgentAdvanced.exe
```

**Process Indicators:**
```
agent.exe → WinDefenderSvc.exe (dropped payload)
agent_xworm.exe → powershell.exe (reconnaissance)
agent_xworm_v2.exe (WebSocket connections)
FleetAgentAdvanced.exe → schtasks.exe (persistence creation)
FleetAgentFUD.exe → powershell.exe -NoP -NonI -W Hidden -Exec Bypass
```

---

### Behavioral Indicators

**Deceptive Naming Patterns:**
- Processes masquerading as Microsoft services: "WinDefenderSvc.exe", "Microsoft .NET Runtime Optimization"
- Executables in user directories (%AppData%, Startup folders) with system-themed names
- Non-Microsoft-signed binaries claiming Windows Defender or .NET Framework affiliation

**Rapid Persistence Deployment:**
- All 4 FleetAgentAdvanced persistence mechanisms created within 1.3 seconds
- Immediate task.xml deletion after scheduled task creation (anti-forensics)
- Dual persistence in agent.exe (Registry Run + Startup folder) deployed simultaneously

**PowerShell Execution Patterns:**
```powershell
# Reconnaissance Commands
Get-Process | Select-Object Name, Id, Path
Get-Service | Select-Object Name, Status, StartType
(Get-WmiObject Win32_ComputerSystem).Domain
```

---

## Detection & Intelligence Resources

Each of the seven detailed threat reports includes detection and intelligence resources:

### Per-Sample Resources

**MITRE ATT&CK Mappings:** TTP coverage across 14+ ATT&CK techniques per sample

**YARA Rules:** File-based detection signatures enabling hash-independent detection

**Sigma Rules:** Behavioral detection rules for SIEM platforms

**Network Signatures:** Suricata/Snort IDS rules for C2 traffic detection

**Hunting Queries:** PowerShell scripts and SPL/KQL queries for threat hunting platforms

**Timeline Analysis:** Second-by-second execution chronology showing malware behavior progression

---

### Confidence Levels

<table class="professional-table">
  <thead>
    <tr>
      <th>Finding Category</th>
      <th>Confidence Level</th>
      <th>Verification Method</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>IOC Accuracy</strong></td>
      <td class="confirmed">HIGH</td>
      <td>Confirmed via static + dynamic + memory analysis triangulation</td>
    </tr>
    <tr>
      <td><strong>Network Indicators (Xworm)</strong></td>
      <td class="confirmed">CONFIRMED</td>
      <td>Hardcoded C2 IP in static strings + active connection attempts in FakeNet-NG logs</td>
    </tr>
    <tr>
      <td><strong>Network Indicators (agent.exe/FleetAgent)</strong></td>
      <td class="medium">DORMANT</td>
      <td>C2 infrastructure present in code but no active connections during analysis window</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="confirmed">VERIFIED</td>
      <td>Autoruns baseline comparison: 4 new entries (FleetAgentAdvanced), 2 entries (agent.exe)</td>
    </tr>
    <tr>
      <td><strong>Detection Signatures</strong></td>
      <td class="confirmed">TESTED</td>
      <td>YARA, Sigma, network signatures validated against samples + clean system (zero false positives)</td>
    </tr>
  </tbody>
</table>

---

## Strategic Implications

This campaign reflects several trends in the current threat landscape:

**1. Purpose-Built Ransomware Development (CRITICAL FINDING):** The custom ransomware toolkit demonstrates professional malware development practices with destructive capabilities for financial gain or dual-use scenarios. The custom cryptographic implementation (ChaCha20+RSA-2048 with AVX-512 optimization) reflects significant R&D investment — this is a purpose-built capability, not commodity ransomware.

**2. Commoditization of Advanced Capabilities:** Remote access trojan functionality, WebSocket-based C2 protocols, and multi-layer persistence mechanisms are now accessible via open directories, lowering barriers to entry for less experienced threat actors.

**3. Shared Infrastructure Patterns:** Multiple distinct malware families sharing C2 infrastructure (109.230.231.37) suggests centralized threat operations or malware-as-a-service (MaaS) business models. Infrastructure-based blocking provides outsized defensive value — a single network indicator neutralizes multiple threat families simultaneously.

**4. Evasion-First Design:** Deceptive Microsoft-themed naming conventions, anti-forensic behaviors (immediate task.xml deletion), and environment-aware dormancy mechanisms indicate operators prioritizing stealth and long-term persistence over immediate impact.

**5. Persistence Engineering:** FleetAgentAdvanced's quadruple-redundant persistence architecture reflects operators anticipating partial remediation efforts and designing survival mechanisms accordingly. Complete system rebuild is preferred over incremental cleanup for HIGH-risk samples from this set.

**6. Mature R&D Process:** Versioned builds (enc_v2.exe), testing utilities (test_decryptor.exe, test_gui_enc_v2.exe), and per-victim key generation tools (enc_pervictim.exe) demonstrate a development process with quality assurance testing — indicators of organized, well-resourced operations rather than ad-hoc criminal activity.

---

### Sample Selection Methodology

From the 38 executables in the open directory, **16 samples were selected for analysis across 7 reports** based on:
1. Malware family diversity (Golang RAT, enc/dec ransomware family, Xworm RAT, FleetAgent variants)
2. Capability variation (RATs, ransomware toolkit, persistence droppers, privilege escalation tools)
3. Risk categorization (CRITICAL, HIGH, and LOW risk samples)
4. Technical sophistication (custom cryptography through proof-of-concept tools)

### Quality Assurance

**Multi-Stage Validation:**
- Static analysis → Dynamic analysis → Memory forensics (three independent methodologies)
- Cross-tool verification: IOCs validated across YARA, CAPA, memory forensics tool (Volatility), Autoruns, PE analysis tool (pestudio)
- Behavioral timeline verification: Process trees from memory forensics tool matched against process monitoring tool execution logs
- Detection signature testing: YARA rules tested against samples (100% detection) + clean systems (zero false positives)

---

**Important Notes:**
- The presence of malware samples in an open directory does not imply the hosting provider's awareness or complicity
- IP address 109.230.231.37 should be blocked via firewall rules, but network operators should verify legitimate use cases before implementing blocks
- Detection signatures may require tuning for specific environments to minimize false positives
- Organizations discovering infections should consult with qualified incident response professionals before remediation
- This analysis represents findings as of January 2026; threat actors may modify infrastructure, update malware capabilities, or change tactics over time

---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.
