---
title: QuasarRAT + Xworm + PowerShell Loader
date: '2025-10-17'
layout: post
permalink: /reports/quasar-xworm-powershell/
hide: true
---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
The QuasarRAT + Xworm + PowerShell campaign represents a sophisticated multi-stage attack combining commodity remote access trojans with advanced fileless execution techniques. The attack systematically disables security controls and establishes persistent remote access, creating significant data theft and system control risks.

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
      <td><strong>Security Control Disabling</strong></td>
      <td class="numeric high">9/10</td>
      <td>Complete Microsoft Defender bypass enabling unrestricted malicious activity</td>
    </tr>
    <tr>
      <td><strong>Fileless Execution</strong></td>
      <td class="numeric high">8/10</td>
      <td>Memory-based execution evades traditional file-based detection methods</td>
    </tr>
    <tr>
      <td><strong>Remote Access Trojans</strong></td>
      <td class="numeric high">8/10</td>
      <td>Full system control with data theft, surveillance, and lateral movement capabilities</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="numeric medium">7/10</td>
      <td>Long-term unauthorized access with multiple RAT deployment options</td>
    </tr>
  </tbody>
</table>

### Recommended Actions
1. **ISOLATE** potentially compromised systems from network immediately
2. **RESTORE** Microsoft Defender functionality and remove all exclusions
3. **SCAN** all systems for QuasarRAT and Xworm binaries
4. **AUDIT** PowerShell execution logs for suspicious script blocks
5. **BLOCK** access to known malicious infrastructure (dns4up.duckdns.org, 193.233.164.21)
6. **RESET** all credentials for potentially compromised accounts

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [BLUF (Bottom Line Up Front)](#bluf-bottom-line-up-front)
  - [Executive Summary](#executive-summary)
  - [Recommended Actions](#recommended-actions)
- [Technical Analysis](#technical-analysis)
  - [Infrastructure Overview](#infrastructure-overview)
  - [Attack Chain Components](#attack-chain-components)
  - [Tactics, Techniques, and Procedures (TTPs)](#tactics-techniques-and-procedures-ttps)
  - [Pivoting Strategy](#pivoting-strategy)
  - [Final Summary](#final-summary)
- [Attack Tactics & Procedures](#attack-tactics--procedures)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
  - [Threat Hunting Indicators](#threat-hunting-indicators)
- [Incident Response Procedures](#incident-response-procedures)
  - [Priority 1: Initial Response (First 60 Minutes)](#priority-1-initial-response-first-60-minutes)
  - [Priority 2: Investigation & Analysis (Hours 1-6)](#priority-2-investigation--analysis-hours-1-6)
  - [Priority 3: Remediation & Recovery (Hours 6-24)](#priority-3-remediation--recovery-hours-6-24)
- [Operational Impact Assessment](#operational-impact-assessment)
  - [Impact Scenarios](#impact-scenarios)
  - [Operational Impact Timeline](#operational-impact-timeline)
- [Long-term Defensive Strategy](#long-term-defensive-strategy)
  - [Technology Enhancements](#technology-enhancements)
  - [Process Improvements](#process-improvements)
  - [Organizational Measures](#organizational-measures)
  - [Resource Investment Summary](#resource-investment-summary)
- [Frequently Asked Questions](#frequently-asked-questions)
  - [Technical Questions](#technical-questions)
  - [Business Questions](#business-questions)
- [IOCs](#iocs)
- [Detections](#detections)

---

## Quick Reference

**Detections & IOCs:**
- [Quasar + Xworm + PowerShell Detections]({{ "/hunting-detections/quasar-xworm-powershell/" | relative_url }})
- [Quasar + Xworm + PowerShell IOCs]({{ "/ioc-feeds/quasar-xworm-powershell.json" | relative_url }})

---

## Overview
This campaign combines commodity RATs (QuasarRAT and Xworm) with a VBScript + PowerShell loader.  
The loader disguises its payload as an image (`update.png`) but actually downloads and executes a PowerShell script in memory.  
That script disables Microsoft Defender by adding broad exclusions, then facilitates RAT deployment.

---

## Loader Mechanism
- **VBScript stager** constructs a PowerShell command string.  
- **PowerShell execution** uses `.NET System.Net.Http.HttpClient` to fetch `update.png` from a remote server.  
- Despite the `.png` extension, the file is a **text‑based PowerShell script**, not an image.  
- The script is read into memory, compiled into a `[ScriptBlock]`, and executed immediately with `.Invoke()`.  

---

## Defense Evasion
The PowerShell payload disables Microsoft Defender by adding exclusions for:
- Entire `C:\` drive.  
- Processes: `powershell.exe`, `wscript.exe`, `cmd.exe`, `cvtres.exe`.  

This effectively blinds Defender to subsequent malicious activity.

---

## RAT Deployment
Once exclusions are in place, the loader hands off to RAT binaries:
- **QuasarRAT**: .NET‑based remote access trojan, ~2–3 MB, often with configs embedded in resources.  
- **Xworm**: smaller (~70 KB), obfuscated strings, commodity RAT functionality.  
Both provide persistence, remote control, and data theft capabilities.

---

# Technical Analysis

## Infrastructure Overview
<table class="professional-table">
  <thead>
    <tr>
      <th>Infrastructure Component</th>
      <th>Value</th>
      <th>Role in Attack Chain</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Dynamic DNS Domain</strong></td>
      <td>dns4up.duckdns[.]org</td>
      <td>Primary C2 domain for RAT communication</td>
    </tr>
    <tr>
      <td><strong>Hosting IP</strong></td>
      <td>193.233.164.21</td>
      <td>Infrastructure hosting malicious payloads</td>
    </tr>
    <tr>
      <td><strong>Payload Disguise</strong></td>
      <td>update.png</td>
      <td>PowerShell script disguised as image file</td>
    </tr>
  </tbody>
</table>

## Attack Chain Components
<table class="professional-table">
  <thead>
    <tr>
      <th>Component</th>
      <th>Technology</th>
      <th>Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Initial Loader</strong></td>
      <td>VBScript</td>
      <td>Constructs PowerShell execution command</td>
    </tr>
    <tr>
      <td><strong>Delivery Mechanism</strong></td>
      <td>PowerShell + .NET HttpClient</td>
      <td>Downloads and executes malicious script in memory</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>PowerShell exclusions</td>
      <td>Disables Microsoft Defender completely</td>
    </tr>
    <tr>
      <td><strong>Primary RAT</strong></td>
      <td>QuasarRAT (.NET)</td>
      <td>Full-featured remote access trojan (~2-3 MB)</td>
    </tr>
    <tr>
      <td><strong>Secondary RAT</strong></td>
      <td>Xworm</td>
      <td>Lightweight commodity RAT (~70 KB)</td>
    </tr>
  </tbody>
</table>

---

## Tactics, Techniques, and Procedures (TTPs)
- **Fileless execution**: PowerShell loads and executes script content directly in memory.  
- **Defense evasion**: Microsoft Defender exclusions.  
- **Remote access**: RAT deployment for persistence and control.  
- **Living off the land**: Abuse of legitimate scripting engines (VBScript, PowerShell).  

---

## Pivoting Strategy
Analysts can pivot on:
- **File names**: `update.png`, `update.ps1`.  
- **Strings**: `Add-MpPreference`, `ExclusionPath`, `HttpClient.GetAsync`.  
- **Domains/IPs**: DuckDNS subdomains, `193.233.164.21`.  
- **Malware traits**: QuasarRAT’s embedded configs, Xworm’s obfuscation patterns.  

---

## Final Summary
This campaign demonstrates a layered loader strategy:
1. VBScript launches PowerShell.  
2. PowerShell fetches a disguised payload (`update.png`).  
3. Payload disables Defender and executes in memory.  
4. RATs (QuasarRAT, Xworm) are deployed for persistence and remote control.  

Key insight: the `.png` extension is a deliberate misdirection — the payload is a PowerShell script, not an image.  
This is a classic “living off the land” technique, leveraging native scripting tools for stealth and evasion.

---

# Attack Tactics & Procedures

## MITRE ATT&CK Mapping
<table class="professional-table">
  <thead>
    <tr>
      <th>Tactic</th>
      <th>Technique ID</th>
      <th>Technique Name</th>
      <th>Implementation</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Execution</strong></td>
      <td>T1059.001</td>
      <td>PowerShell</td>
      <td>Fileless PowerShell script execution in memory</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1562.001</td>
      <td>Disable or Modify Tools</td>
      <td>Microsoft Defender exclusions via Add-MpPreference</td>
    </tr>
    <tr>
      <td><strong>Persistence</strong></td>
      <td>T1543.003</td>
      <td>Windows Service</td>
      <td>RAT deployment for long-term access</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1071.001</td>
      <td>Application Layer Protocol: Web Protocols</td>
      <td>HTTP/HTTPS communication with C2 infrastructure</td>
    </tr>
    <tr>
      <td><strong>Living off the Land</strong></td>
      <td>T1218.005</td>
      <td>System Tools</td>
      <td>Abuse of legitimate VBScript and PowerShell</td>
    </tr>
  </tbody>
</table>

## Threat Hunting Indicators
<table class="professional-table">
  <thead>
    <tr>
      <th>Indicator Type</th>
      <th>Value</th>
      <th>Hunting Method</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>File Names</strong></td>
      <td>update.png, update.ps1</td>
      <td>File system monitoring, EDR alerts</td>
    </tr>
    <tr>
      <td><strong>PowerShell Strings</strong></td>
      <td>Add-MpPreference, ExclusionPath, HttpClient.GetAsync</td>
      <td>PowerShell logging, script block analysis</td>
    </tr>
    <tr>
      <td><strong>Network Indicators</strong></td>
      <td>dns4up.duckdns.org, 193.233.164.21</td>
      <td>DNS monitoring, network traffic analysis</td>
    </tr>
    <tr>
      <td><strong>Malware Signatures</strong></td>
      <td>QuasarRAT configs, Xworm obfuscation</td>
      <td>Memory analysis, YARA rules</td>
    </tr>
  </tbody>
</table>

---

## Incident Response Procedures

### Priority 1: Initial Response (First 60 Minutes)
1. **ISOLATE** potentially compromised systems from network
2. **RESTORE** Microsoft Defender functionality and remove all exclusions
3. **BLOCK** access to known malicious infrastructure at network perimeter
4. **SCAN** all systems for QuasarRAT and Xworm binaries
5. **AUDIT** PowerShell execution logs for suspicious script blocks
6. **DOCUMENT** all potentially compromised systems and user accounts

### Priority 2: Investigation & Analysis (Hours 1-6)
1. **FORENSIC ANALYSIS** of PowerShell logs for script block execution
2. **MEMORY ANALYSIS** for fileless execution artifacts
3. **NETWORK ANALYSIS** for connections to C2 infrastructure
4. **MALWARE ANALYSIS** of recovered RAT binaries
5. **THREAT HUNTING** for additional compromised systems and lateral movement

### Priority 3: Remediation & Recovery (Hours 6-24)
1. **REBUILD** compromised systems from known-good images
2. **RESET** all credentials for potentially compromised accounts
3. **IMPLEMENT** PowerShell logging and monitoring
4. **DEPLOY** application whitelisting for script execution
5. **ESTABLISH** enhanced endpoint detection and response capabilities

---

## Operational Impact Assessment

### Impact Scenarios
<table class="professional-table">
  <thead>
    <tr>
      <th>Impact Category</th>
      <th>Severity Level</th>
      <th>Recovery Time</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Data Compromise</strong></td>
      <td class="high">HIGH</td>
      <td>2-4 months</td>
    </tr>
    <tr>
      <td><strong>System Compromise</strong></td>
      <td class="high">HIGH</td>
      <td>1-2 weeks</td>
    </tr>
    <tr>
      <td><strong>Operational Disruption</strong></td>
      <td class="medium">MEDIUM</td>
      <td>1-3 weeks</td>
    </tr>
    <tr>
      <td><strong>Security Control Recovery</strong></td>
      <td class="high">HIGH</td>
      <td>1-2 weeks</td>
    </tr>
    <tr>
      <td><strong>Long-term Monitoring</strong></td>
      <td class="medium">MEDIUM</td>
      <td>6-12 months</td>
    </tr>
    <tr>
      <td><strong>Compliance Impact</strong></td>
      <td class="high">HIGH</td>
      <td>6-18 months</td>
    </tr>
  </tbody>
</table>

### Operational Impact Timeline
- **Immediate (0-24 hours):** System isolation, security control restoration, emergency response
- **Short-term (1-7 days):** System rebuilding, enhanced monitoring deployment, credential rotation
- **Medium-term (1-4 weeks):** Process improvements, security hardening, user training
- **Long-term (1-6 months):** Security architecture review, compliance activities
- **Extended (6-18 months):** Ongoing monitoring, regulatory compliance

### Operational Impact Timeline
- **Immediate (0-24 hours):** System isolation, security control restoration, emergency response
- **Short-term (1-7 days):** System rebuilding, enhanced monitoring deployment
- **Medium-term (1-4 weeks):** Process improvements, security hardening
- **Long-term (1-3 months):** Security architecture review, compliance activities

---

## Long-term Defensive Strategy

### Technology Enhancements
1. **Endpoint Detection & Response (EDR)** with fileless execution capabilities and behavioral analysis
2. **Application Control** to prevent unauthorized script execution and unknown software deployment
3. **PowerShell Constrained Language Mode** with restrictive execution policies and enhanced logging
4. **Advanced Threat Protection** with real-time fileless attack detection and memory forensics
5. **Network Traffic Analysis** for C2 communication detection and anomaly identification
6. **Security Information and Event Management (SIEM)** with PowerShell integration and correlation rules
7. **Cloud Access Security Broker (CASB)** for monitoring cloud-based exfiltration attempts

### Process Improvements
1. **PowerShell Logging** with script block logging, module logging, and transcription capabilities
2. **Application Whitelisting** for script execution, file downloads, and PowerShell commands
3. **Regular Security Assessments** including penetration testing of endpoint defenses and fileless attack simulations
4. **Incident Response Playbooks** specific to fileless malware attacks and RAT remediation
5. **Change Management** procedures with security approval requirements and rollback capabilities
6. **Threat Hunting Program** with regular hunts for fileless attack indicators and RAT infrastructure

### Organizational Measures
1. **Security Awareness Training** on social engineering, malicious scripts, and RAT detection
2. **Regular Security Assessments** including red team exercises and fileless attack scenarios
3. **Threat Intelligence Subscription** for emerging fileless malware threats and RAT infrastructure monitoring
4. **Executive Security Briefings** on living-off-the-land attack techniques and business impact
5. **Investment in Security Tools** and personnel training for advanced threat detection and response
6. **Security Champions Program** to promote security culture and incident reporting

### Resource Investment Summary
- **Technology Investment:** EDR and advanced protection deployment across endpoints
- **Training Investment:** Security awareness and specialized training for personnel
- **Process Investment:** Security program development and maintenance activities
- **Total Investment:** Comprehensive fileless attack protection capabilities
- **Expected Outcome:** Prevention of fileless attack incidents and improved detection capabilities

---

## Frequently Asked Questions

### Technical Questions
**Q: Why is fileless execution particularly dangerous?**  
A: It evades traditional file-based detection methods, leaves minimal forensic artifacts, and can bypass many security controls that rely on file scanning.

**Q: How does PowerShell exclusion mechanism work?**  
A: The script uses `Add-MpPreference` to add exclusions for the entire C: drive and specific processes, effectively blinding Microsoft Defender to all subsequent activity.

**Q: What makes the .png disguise effective?**  
A: Many security tools and network monitoring systems may not inspect files with image extensions as closely as executable files, allowing the PowerShell script to bypass initial filters.

### Business Questions
**Q: What are the regulatory implications of security control disabling?**  
A: Significant - disabling security controls can be considered willful negligence and may impact compliance with various security frameworks and regulations.

**Q: Should we rebuild or patch compromised systems?**  
A: **REBUILD** is strongly recommended due to the sophistication of fileless attacks and the potential for additional hidden compromise mechanisms.

**Q: How can we prevent similar fileless attacks?**  
A: Implement PowerShell logging, application control, endpoint detection with fileless execution capabilities, and user education on malicious scripts.

---

## IOCs
- [QuasarRAT + Xworm + PowerShell Loader IOCs]({{ "/ioc-feeds/quasar-xworm-powershell.json" | relative_url }})

## Detections
- [QuasarRAT + Xworm + PowerShell Loader Detections]({{ "/hunting-detections/quasar-xworm-powershell/" | relative_url }})

---

## License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.
