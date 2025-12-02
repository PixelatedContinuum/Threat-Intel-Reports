---
title: Hybrid Loader/Stealer Ecosystem Masquerading as Sogou
date: '2025-11-21'
layout: post
permalink: /reports/Hybrid-Loader-Stealer-Sogou/
hide: true
---

# BLUF (Bottom Line Up Front)

## Executive Summary

### Business Impact Summary
The Hybrid Loader/Stealer ecosystem represents an active, live cybercrime infrastructure blending malware distribution, credential theft, and IPTV piracy. This is not an isolated incident but an ongoing criminal operation with live authentication tokens and active automation frameworks. Containment and comprehensive investigation are recommended.

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
      <td><strong>Active Infrastructure</strong></td>
      <td class="numeric high">9/10</td>
      <td>Live cybercrime hub with authenticated operators actively distributing malware</td>
    </tr>
    <tr>
      <td><strong>Data Theft Scale</strong></td>
      <td class="numeric high">8/10</td>
      <td>JD.com cookie theft, credential harvesting, and financial fraud targeting e-commerce</td>
    </tr>
    <tr>
      <td><strong>Persistence Mechanisms</strong></td>
      <td class="numeric high">9/10</td>
      <td>Two-stage infection chain with multiple redundant persistence vectors</td>
    </tr>
    <tr>
      <td><strong>Operational Sophistication</strong></td>
      <td class="numeric high">8/10</td>
      <td>Automation frameworks, disposable infrastructure, and professional criminal operations</td>
    </tr>
  </tbody>
</table>

### Recommended Actions
1. **ISOLATE** all systems with Sogou Input Method installations immediately
2. **BLOCK** network access to identified infrastructure (27.184.28.134:8081, related domains)
3. **INVESTIGATE** potential JD.com credential compromise and financial impact
4. **COLLECT** forensic evidence including memory dumps and network logs
5. **NOTIFY** legal, compliance, and executive leadership teams
6. **ASSESS** regulatory notification requirements for credential theft

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [BLUF (Bottom Line Up Front)](#bluf-bottom-line-up-front)
  - [Executive Summary](#executive-summary)
  - [Recommended Actions](#recommended-actions)
- [Executive Summary](#executive-summary)
  - [Key Takeaways](#key-takeaways)
  - [Summary](#summary)
  - [Bottom Line](#bottom-line)
- [Comprehensive Malware Analysis](#comprehensive-malware-analysis)
  - [File Overview](#file-overview)
  - [Context of File Name](#context-of-file-name)
  - [Installer‑Specific Observations](#installer-specific-observations)
- [Capability Findings Summary](#capability-findings-summary)
- [Expanded Capability Findings](#expanded-capability-findings)
  - [File System Manipulation](#file-system-manipulation)
  - [Registry Modification](#registry-modification)
  - [Process & Privilege Manipulation](#process--privilege-manipulation)
  - [Collection Capabilities](#collection-capabilities)
  - [Cryptography & Encoding](#cryptography--encoding)
  - [Anti‑Analysis Features](#anti-analysis-features)
  - [Persistence via Shortcuts](#persistence-via-shortcuts)
  - [System Impact](#system-impact)
- [YARA Hits](#yara-hits)
- [Expanded YARA Hits](#expanded-yara-hits)
  - [General Traits](#general-traits)
  - [Cryptography & Encoding](#cryptography--encoding-1)
  - [Privilege & Registry Manipulation](#privilege--registry-manipulation)
  - [Collection Capabilities](#collection-capabilities-1)
  - [Android Meterpreter Overlap](#android-meterpreter-overlap)
  - [Network Indicators](#network-indicators)
- [peframe Results](#peframe-results)
- [Expanded peframe Results](#expanded-peframe-results)
  - [Metadata & Masquerade](#metadata--masquerade)
  - [Overlay & Packing](#overlay--packing)
  - [Mutex Creation](#mutex-creation)
  - [Suspicious API Imports](#suspicious-api-imports)
  - [Anti‑Debugging & Anti‑Analysis](#anti-debugging--anti-analysis)
  - [Network Indicators](#network-indicators-1)
- [XOR Decoding & Config Extraction](#xor-decoding--config-extraction)
- [Infrastructure Analysis](#infrastructure-analysis)
  - [WHOIS & IP Enrichment](#whois--ip-enrichment)
  - [Infrastructure Enrichment: IPs and Hosted Domains](#infrastructure-enrichment-ips-and-hosted-domains)
- [Behavioral Assessment](#behavioral-assessment)
  - [Masquerade](#masquerade)
  - [Installer Abuse](#installer-abuse)
  - [Persistence](#persistence)
  - [Defense Evasion](#defense-evasion)
  - [Collection](#collection)
  - [Privilege Escalation](#privilege-escalation)
  - [Impact (System Disruption)](#impact-system-disruption)
  - [Command & Control (C2)](#command--control-c2)
- [Document Triage Findings](#document-triage-findings)
  - [File Analyzed](#file-analyzed)
  - [Metadata](#metadata)
  - [AV/YARA Results](#avyara-results)
  - [OOXML Unpack](#ooxml-unpack)
  - [Document Content](#document-content)
  - [ATT&CK Mapping (Heuristic Flag)](#attck-mapping-heuristic-flag)
  - [Assessment](#assessment)
- [Linkage Analysis: Promotional Document and Cybercrime Hub](#linkage-analysis-promotional-document-and-cybercrime-hub)
- [Complete Installer Summary](#complete-installer-summary)
  - [Artifacts of Interest](#artifacts-of-interest)
  - [Packaging and Masquerade](#packaging-and-masquerade)
  - [Installer Behavior](#installer-behavior)
  - [Persistence Mechanisms](#persistence-mechanisms)
  - [Defense Evasion](#defense-evasion-1)
  - [Collection Capabilities](#collection-capabilities-2)
- [Final Infection Chain](#final-infection-chain)
- [Final Analysis & Conclusion](#final-analysis--conclusion)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Incident Response Procedures](#incident-response-procedures)
- [Operational Impact Assessment](#operational-impact-assessment)
- [Long-term Defensive Strategy](#long-term-defensive-strategy)
- [Frequently Asked Questions](#frequently-asked-questions)
- [IOCs](#iocs)
- [Detections](#detections)

---

## Quick Reference

**Detections & IOCs:**
- [Hybrid Loader/Stealer Detections]({{ "/hunting-detections/Hybrid-Loader-Stealer-Sogou/" | relative_url }})
- [Hybrid Loader/Stealer IOCs]({{ "/ioc-feeds/Hybrid-Loader-Stealer-Sogou.json" | relative_url }})

---

# Executive Summary

## Key Takeaways
- The exposed directory at 27[.]184[.]28[.]134:8081 is an active cybercrime hub, not a passive file dump.
- Reverse engineering confirms the Windows malware masquerading as cracked Sogou Input Method software is a stealer/loader capable of persistence, evasion, and data theft.
- Surrounding files and logs reveal integration with a QingLong Panel automation environment, orchestrating malware distribution, JD[.]com cookie theft, and IPTV piracy.
- A valid authentication token (token.json) proves the panel is live, with operators authenticated and executing tasks.
- Logs confirm scheduled jobs, token generation, and RTSP streaming services are operational.
- Command‑and‑control relies on disposable domains and cloud IPs (e.g., 6[.]ar → 149[.]50[.]136[.]243, J[.]im → 52[.]20[.]84[.]62).
- Installer analysis shows a multi‑component package blending malicious binaries with legitimate Sogou resources (e.g., beacon_sdk.dll, SGDownload.exe, UrlSignatureV.dat), enabling persistence, obfuscation, cryptography, and covert communications disguised as certificate validation or Sogou updates.
- **Operational Insight:** The infection chain operates in two stages. The wrapper file establishes persistence, requests elevated permissions, and drops embedded components.  
- The embedded installer payload then acts as the main agent, performing surveillance, privilege escalation, redundant persistence, networking actions, and data exfiltration. Together, they form a hybrid loader + stealer/RAT ecosystem.
- The operator’s goal: scalable monetization through fraud, piracy, and malware distribution, managed under a single automation framework.

## Summary
The cracked Sogou Input Method file is not an isolated malware sample but part of a larger, active ecosystem. Reverse engineering confirmed stealer/loader functionality, but infrastructure analysis revealed Android malware, JD[.]com cookie‑stealing tools, IPTV piracy scripts, and orchestration utilities tied to QingLong Panel. The presence of a valid authentication token proves the panel is live.  
Logs confirm scheduled jobs and streaming services. Disposable domains and cloud IPs provide churnable C2 infrastructure. Analysis of a benign Word document (如意素材库.docx) revealed promotional content for a Taobao shop and WeChat ID, likely used as commercial channels for monetization. Installer breakdown shows multi‑layered delivery: core binaries, resource packages, signature databases, and cryptographic routines. Networking disguises traffic as certificate validation or legitimate Sogou updates.  

**Operational Insight:** Infection chain analysis clarifies that the wrapper acts as the staging ground, while the embedded payload executes the full malicious capability set—surveillance, escalation, persistence, exfiltration, and covert communications. This layered design maximizes stealth and operational control.

## Bottom Line
This is an active, live infrastructure blending malware distribution, credential theft, and IPTV piracy into a single automation framework. The operator’s clear goal is scalable fraud and revenue generation, supported by disposable domains, confirmed by live auth tokens, and reinforced by installer persistence and evasion. The ecosystem’s two‑stage infection chain, wrapper staging followed by embedded stealer/RAT payload, confirms a deliberate hybrid design that ensures delivery, persistence, and long‑term control.

# Comprehensive Malware Analysis

## File Overview

<table class="professional-table">
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Value</th>
      <th>Confidence Level</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Original Filename</strong></td>
      <td>搜狗拼音输入法v15.1.0.1570去广告精简优化版无毒_吾爱破解.exe</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Translated Filename</strong></td>
      <td>"Sogou Pinyin Input Method v15.1.0.1570 Ad‑Free Streamlined Optimized Edition No Virus 52pojie.exe"</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Malware Type</strong></td>
      <td>Hybrid Loader/Stealer with Ecosystem Integration</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>File Type</strong></td>
      <td>PE32 executable (Windows GUI), Intel 80386</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Packaging</strong></td>
      <td>Nullsoft NSIS installer</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
    <tr>
      <td><strong>Threat Level</strong></td>
      <td>CRITICAL - Active cybercrime infrastructure</td>
      <td class="confirmed">CONFIRMED</td>
    </tr>
  </tbody>
</table>

### Hash Information
<table class="professional-table">
  <thead>
    <tr>
      <th>Hash Type</th>
      <th>Value</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>MD5</strong></td>
      <td><code>794379156eac28ce695051581aad5c9b</code></td>
    </tr>
    <tr>
      <td><strong>SHA1</strong></td>
      <td><code>8be1b21855e8d4bb68230285a5e8e16b71f043ef</code></td>
    </tr>
    <tr>
      <td><strong>SHA256</strong></td>
      <td><code>a8e2069fed11ed84c2e45773b0d4de082bb820618b2f915508ae5682fa96be63</code></td>
    </tr>
  </tbody>
</table>

## Context of File Name
- Crafted to appear as a cracked, “clean” version of Sogou Input Method.  
- “Ad‑free” and “optimized” appeal to users seeking modified builds.  
- “No virus” reassurance is ironically suspicious.  
- “52pojie” ties it to a Chinese cracking forum, a common malware distribution vector.  

## Installer‑Specific Observations

### NSIS Installer Packaging
- Scriptable installer allows attackers to define custom actions (copy files, run commands, drop payloads).  
- Security tools often treat installers as benign, hiding malicious payloads until runtime.  

### Installer Dialog Controller Highlights
- References to IShellLink usage suggest dialog control and shortcut manipulation.  
- Malware may suppress dialogs, silently install payloads, or modify shortcuts to point to malicious executables.  

### Masquerade via Installer Metadata
- Metadata claims to be Sogou Input Method v15.1.0.1570.  
- Legitimate Sogou installers use different packaging formats.  
- Contains XOR‑encoded configuration blobs, disposable domains, persistence mechanisms, and collection features (screenshots, webcam, clipboard).  

### Installer Persistence Hooks
- Shortcut creation ensures persistence immediately after installation.  
- Stealthier than registry run keys alone.  

### Dual Behavior of Installer
- Presents a familiar “Install Wizard” interface.  
- Executes persistence, LNK manipulation, and payload execution in the background.  

# Capability Findings Summary

- **File System:** Create/delete/copy/move files, read/write, enumerate recursively, read .ini files.  
- **Registry:** Create/open/delete registry keys and values.  
- **Process & Privilege:** Create processes/threads, access token manipulation.  
- **Collection:** Webcam capture, screenshots, clipboard theft.  
- **Crypto/Encoding:** CRC32 hashing, XOR encoding.  
- **Anti‑Analysis:** VM detection (Xen strings), anti‑debugging APIs.  
- **Persistence:** Shortcut modification via IShellLink API.  
- **Impact:** System shutdown/reboot.  

---

# Expanded Capability Findings

## File System Manipulation
- **Evidence:** Capa flagged capabilities to create, delete, copy, and move files and directories, as well as read/write operations and recursive enumeration. It also detected the ability to read .ini files.  
- **Reasoning:** .ini files often store application settings, credentials, or environment details. Reading them can allow malware to harvest sensitive information or hijack application behavior.  
- **Impact:**  
  - Enables the attacker to drop payloads, delete evidence, and search for sensitive files.  
  - Using .ini files as stealthy config storage complicates detection.  
  - Direct file manipulation supports persistence and data theft.  

## Registry Modification
- **Evidence:** Detected creation, opening, and deletion of registry keys and values.  
- **Reasoning:** Registry manipulation is a common persistence technique, allowing malware to auto‑start or alter system behavior.  
- **Impact:**  
  - Ensures persistence across reboots.  
  - Allows modification of system policies or application settings.  
  - Provides stealthy storage for configuration data.  

## Process & Privilege Manipulation
- **Evidence:** Capa flagged process creation, thread spawning, and access token manipulation.  
- **Reasoning:** These capabilities enable execution of other programs, injection into legitimate processes, and privilege escalation.  
- **Impact:**  
  - Expands attacker control over the system.  
  - Enables stealthy execution of payloads.  
  - Privilege escalation allows bypassing user restrictions and disabling security tools.  

## Collection Capabilities
- **Evidence:** Functions to capture webcam images, take screenshots, and read/write clipboard data.  
- **Reasoning:** These features directly target user activity and sensitive information.  
- **Impact:**  
  - Screenshots can reveal banking sessions, emails, or private communications.  
  - Webcam capture compromises user privacy.  
  - Clipboard theft enables credential harvesting (e.g., passwords, crypto wallet addresses).  

## Cryptography & Encoding
- **Evidence:** CRC32 hashing and XOR encoding detected.  
- **Reasoning:** These are lightweight obfuscation techniques used to conceal configuration data or stolen information.  
- **Impact:**  
  - Obfuscation complicates detection and analysis.  
  - CRC32 may be used for integrity checks, ensuring payloads are not corrupted.  
  - XOR encoding hides C2 domains and tokens from static inspection.  

## Anti‑Analysis Features
- **Evidence:** Detection of virtualization strings (Xen) and anti‑debugging APIs (FindWindowExA, GetLastError).  
- **Reasoning:** These checks allow malware to evade sandboxes and frustrate reverse engineers.  
- **Impact:**  
  - Prevents execution in virtualized environments used by analysts.  
  - Delays reverse engineering, prolonging operational lifespan.  
  - Reduces likelihood of detection in automated malware analysis pipelines.  

## Persistence via Shortcuts
- **Evidence:** IShellLink API usage flagged, confirming shortcut creation/modification.  
- **Reasoning:** Malware can booby‑trap .lnk files so that when a user clicks what looks like a normal program, the malware executes.  
- **Impact:**  
  - Stealthier than registry run keys alone.  
  - Blends into normal user behavior, making detection harder.  
  - Ensures persistence even if registry entries are removed.  

## System Impact
- **Evidence:** Functions enabling system shutdown and reboot identified.  
- **Reasoning:** These are not part of legitimate Sogou Input Method functionality.  
- **Impact:**  
  - Can disrupt system availability.  
  - May be used to force reboots that activate persistence mechanisms.  
  - Potentially disruptive to user productivity and data integrity.  

---

## Analyst Notes
>Capa findings confirm the malware is multi‑functional, combining persistence, evasion, collection, and disruption.  
>Evidence shows deliberate use of obfuscation and anti‑analysis to resist detection.  
>Impact analysis highlights the attacker’s ability to steal sensitive data, maintain persistence, and evade defenses, all while masquerading as trusted software.  

# YARA Hits

- **General Traits:** PE32 Windows executable, packed, overlay present.  
- **Crypto/Encoding:** CRC32 hashing, base64 encoding.  
- **Privilege/Registry:** Escalation, registry manipulation, token abuse.  
- **Collection:** Screenshot capture confirmed.  
- **Cross‑Platform Overlap:** Code patterns resemble Android Meterpreter routines.  
- **Network Indicators:** Presence of IP/URL/domain rules.  

---

# Expanded YARA Hits

YARA rules are pattern‑matching signatures used to detect malware traits. The scan produced several hits that provide insight into the malware’s composition and lineage.

## General Traits
- **Evidence:** Rules flagged IsPE32, IsWindowsGUI, IsPacked, HasOverlay, and HasRichSignature.  
- **Reasoning:** These confirm the file is a Windows PE32 executable, GUI‑based, and likely packed with additional data in overlay sections.  
- **Impact:**  
  - Confirms the sample is a Windows binary, not a cross‑compiled artifact.  
  - Packing and overlays suggest deliberate obfuscation, complicating static analysis.  
  - The presence of a Rich header indicates compilation with Microsoft toolchains, consistent with Windows malware.  

## Cryptography & Encoding
- **Evidence:** Hits included CRC32_poly_Constant and possible_includes_base64_packed_functions.  
- **Reasoning:** These signatures identify CRC32 hashing and base64 encoding routines.  
- **Impact:**  
  - CRC32 may be used for integrity checks or lightweight obfuscation.  
  - Base64 encoding is often used to conceal configuration data or exfiltrated information.  
  - Together, these routines confirm the malware employs multiple encoding strategies to evade detection.  

## Privilege & Registry Manipulation
- **Evidence:** Rules flagged escalate_priv, win_registry, win_token, and win_files_operation.  
- **Reasoning:** These signatures confirm the malware’s ability to escalate privileges, manipulate the Windows registry, abuse tokens, and perform file operations.  
- **Impact:**  
  - Confirms persistence mechanisms (registry run keys).  
  - Confirms privilege escalation capabilities, enabling deeper system compromise.  
  - File operations support payload delivery and evidence cleanup.  

## Collection Capabilities
- **Evidence:** A screenshot rule fired, confirming the ability to capture screen content.  
- **Reasoning:** This aligns with capa findings and API imports for screen capture.  
- **Impact:**  
  - Enables theft of sensitive visual information (credentials, financial sessions, private communications).  
  - Confirms surveillance functionality beyond simple data theft.  

## Android Meterpreter Overlap
- **Evidence:** A rule flagged android_meterpreter.  
- **Reasoning:** While the file is clearly a Windows PE32 executable, some code patterns resemble those used in Android exploitation frameworks, specifically Metasploit’s Android Meterpreter payload.  
- **Impact:**  
  - Indicates code reuse or borrowing of routines across platforms.  
  - Suggests the malware author may have adapted existing offensive tooling.  
  - Provides insight into attacker sophistication — leveraging known frameworks rather than building all functionality from scratch.  

## Network Indicators
- **Evidence:** IP/URL/domain rules fired, confirming the presence of hardcoded network indicators.  
- **Reasoning:** These align with XOR‑decoded domains and endpoint tokens found during config extraction.  
- **Impact:**  
  - Confirms the malware is designed for active C2 communication.  
  - Provides concrete IOCs for defenders to block or hunt in network traffic.  

---

## Analyst Notes
>YARA hits corroborate capa and peframe findings, reinforcing evidence of persistence, privilege escalation, collection, and obfuscation.  
>The Android Meterpreter overlap is particularly notable — it suggests cross‑platform code reuse, which may explain why the ecosystem also contained Android malware in the exposed directory.  
>Network indicator hits tie directly to decoded domains, strengthening the case for active C2 infrastructure.  

# peframe Results

- **Features:** Mutex creation, anti‑debugging, cryptographic routines.  
- **Behavior:** XOR encoding, privilege escalation, screenshot capture, registry manipulation, token abuse, file operations.  
- **Crypto:** CRC32 hashing for obfuscation and integrity checks.  
- **Imports:** Heavy use of Windows APIs (ADVAPI32, SHELL32, USER32, KERNEL32).  
- **Suspicious APIs:** CreateFileA, CreateProcessA, CreateThread, DeleteFileA, CopyFileA, FindWindowExA.  
- **Suspicious Sections:** .text flagged for anomalies.  
- **Metadata:** Masquerades as Sogou Input Method.  

---

# Expanded peframe Results

The peframe static analysis provided additional context on the malware’s structure, metadata, and suspicious behaviors. Below is a structured breakdown with evidence and operational impact.

## Metadata & Masquerade
- **Evidence:** The file metadata claimed to be “Sogou Input Method v15.1.0.1570 去广告精简优化版” (ad‑free optimized version). However, the compilation details and overlay sections did not match legitimate Sogou installers.  
- **Reasoning:** Legitimate installers use proprietary packaging and do not include obfuscation layers or suspicious API imports.  
- **Impact:** Confirms masquerading — the malware disguises itself as trusted software to lower suspicion and increase infection rates.  

## Overlay & Packing
- **Evidence:** peframe detected a large overlay section appended to the binary.  
- **Reasoning:** Overlays are often used to store encoded configuration data, payloads, or resources. In this case, XOR decoding confirmed the overlay contained domains and endpoint tokens.  
- **Impact:** Packing and overlays complicate static detection. They conceal infrastructure details until decoded, prolonging the malware’s stealth.  

## Mutex Creation
- **Evidence:** A mutex string was identified in the binary.  
- **Reasoning:** Mutexes are used to ensure only one instance of the malware runs at a time, preventing conflicts or duplicate infections.  
- **Impact:** Confirms deliberate design for stability. Mutexes also provide forensic value — analysts can hunt for the mutex string in memory or logs to detect infections.  

## Suspicious API Imports
- **Evidence:** peframe flagged imports such as CreateProcessA, CreateThread, FindWindowExA, GetLastError, CopyFileA, and registry manipulation functions.  
- **Reasoning:** These APIs enable process creation, thread spawning, anti‑debugging checks, file manipulation, and persistence.  
- **Impact:** Confirms multi‑functional capabilities: execution, evasion, collection, and persistence. These APIs are consistent with capa and YARA findings, reinforcing the behavioral profile.  

## Anti‑Debugging & Anti‑Analysis
- **Evidence:** API imports (FindWindowExA, GetLastError) and string checks for virtualization environments (Xen) were detected.  
- **Reasoning:** These functions allow the malware to detect debugging tools or sandbox environments.  
- **Impact:** Confirms deliberate resistance to analysis. Automated sandbox systems may fail to detect the malware, prolonging its operational lifespan.  

## Network Indicators
- **Evidence:** Hardcoded domains and IPs were identified in the binary, consistent with XOR‑decoded configuration.  
- **Reasoning:** These indicators align with disposable ccTLDs and cloud IPs used for C2.  
- **Impact:** Provides concrete IOCs for defenders. Confirms the malware is designed for active communication with external infrastructure.  

---

## Analyst Notes
>peframe results corroborate capa and YARA findings, strengthening confidence in the behavioral assessment.  
>The overlay section was critical — it concealed XOR‑encoded domains and tokens, proving the malware’s reliance on obfuscation.  
>Mutex creation and suspicious API imports confirm deliberate design for persistence, evasion, and collection.  
>Overall, peframe analysis reinforces the conclusion that the installer is a multi‑purpose stealer/loader, masquerading as trusted software while embedding stealth and resilience.  

**Key Traits:**  
- Multiple persistence mechanisms (registry + LNK).  
- Defense evasion via obfuscation and anti‑VM checks.  
- Broad surveillance capabilities (screenshots, webcam, clipboard).  
- Impact includes system disruption.  
- C2 infrastructure relies on disposable ccTLDs and cloud IPs.  
- Masquerade lowers suspicion by mimicking trusted software.  

---

## XOR Decoding & Config Extraction
- **Decoded Domains:** 5bNG.ar, 6.ar, B.tk, J.im, K.ct, Q.ar, rlh.cq, s0.ndf, vpl.gu, X.pg.  
- **Endpoint Token:** CGI1 (suggests `/cgi1` path).  
- **Resolution Results:**  
  - 6.ar → 149.50.136.243 (Argentina registry).  
  - J.im → 52.20.84.62 (Amazon AWS).  
  - Others expired or placeholders. 

# Infrastructure Analysis

## WHOIS & IP Enrichment

### 149.50.136.243
- **Hostname:** vps-3906667-x.dattaweb.com  
- **City/Region:** Rosario, Santa Fe, Argentina  
- **Country:** Argentina (AR) – network registered via Cogent Communications (US)  
- **OrgName:** Cogent Communications, LLC / DATTATEC.COM S.R.L. (Donweb hosting)  
- **ASN:** AS27823 – Dattatec.com (donweb.com)  
- **Route:** 149.50.136.0/24  
- **Type:** Hosting  
- **Timezone:** America/Argentina/Cordoba  
- **Abuse Contact:** abuse@cogentco.com, +1-877-875-4311  
- **Domains Hosted:** ~207 total (examples: 1000.ar, 2.tur.ar, pumas.ar, transporte.ar, permutas.ar)  
- **Impact:** Disposable VPS infrastructure in Argentina, hosted by Donweb/Cogent. Likely used for short-lived C2 servers.  

### 52.20.84.62
- **Hostname:** ec2-52-20-84-62.compute-1.amazonaws.com  
- **City/Region:** Ashburn, Virginia, US  
- **Country:** United States (US)  
- **OrgName:** Amazon Technologies Inc.  
- **ASN:** AS14618 – Amazon.com, Inc.  
- **Route:** 52.20.0.0/14  
- **Type:** Hosting (Amazon EC2)  
- **Timezone:** America/New_York  
- **Abuse Contact:** trustandsafety@support.aws.com, +1-206-555-0000  
- **Domains Hosted:** ~765,002 total (examples: infopetworld.com, hoho.ai, recipesandcooker.com, stackpathcdn.com, playersb.com)  
- **Impact:** Amazon EC2 instance in Ashburn, VA. Reflects attacker reliance on cloud infrastructure for disposable C2 nodes.  

---

## Infrastructure Enrichment: IPs and Hosted Domains

### 149.50.136.243
- **Hostname:** vps-3906667-x.dattaweb[.]com  
- **Domains Hosted:** ~794 (examples: promo.tur[.]ar, ciudades.tur[.]ar, 80[.]ar, 90[.]ar, ciudad[.]ar, solar[.]ar, comidas[.]ar, bicis[.]ar, hipodromo[.]ar, comercios[.]ar, permutas[.]ar, verde[.]ar, commerce[.]ar, vacaciones.tur[.]ar)  
- **WHOIS Registrants:** Multiple domains registered through Hostmar.com infrastructure  
- **ASN/ISP:** AS27823 – Dattatec.com / Donweb (Argentina), upstream Cogent Communications (US)  

#### Open Ports & Services (149.50.136.243)
- Port 21: FTP (ProFTPD) – Active, last seen 11/16/2025  
- Port 80: HTTP (Apache HTTPD) – Active, last seen 11/13/2025  
- Port 110: POP3 (Dovecot) – Active, last seen 11/11/2025  
- Port 143: IMAP – Active, last seen 11/15/2025  
- Port 443: HTTPS – Active, last seen 11/15/2025  
- Port 993: TLS/IMAP – Active, last seen 11/16/2025  
- Port 995: TLS/POP3 – Active, last seen 11/15/2025  
- Ports 2082–2095: HTTP/TLS (Apache HTTPD / misc, cPanel-style ports) – Active, last seen 11/09–11/16/2025  
- Port 5465: SSH (OpenBSD OpenSSH 7.4) – Active, last seen 11/14/2025  

**Impact (149.50.136.243):**  
- Hosting dozens of .ar domains with malware/phishing reputations.  
- Services (FTP, mail, Apache on multiple ports) suggest shared hosting/reseller environment exploited for disposable C2 and phishing.  
- Domain reuse across .ar sites indicates centralized ownership or small operator group.  

---

### 52.20.84.62
- **Hostname:** ec2-52-20-84-62.compute-1.amazonaws.com  
- **Domains Hosted:** ~1.5M (examples: 1-3[.]shop, 1-4[.]shop, 11-11wish[.]cloud, 3000bc[.]xyz, aslo[.]xyz)  
- **ASN/ISP:** AS14618 – Amazon.com, Inc. (Amazon EC2, Ashburn VA)  

#### Open Ports & Services (52.20.84.62)
- Port 80: HTTP (TCPWRAPPED) – Active, last seen 11/16/2025  
- Port 443: HTTPS (TLS/HTTP) – Active, last seen 11/11/2025  

**Impact (52.20.84.62):**  
- Massive domain hosting footprint with numeric naming conventions (number-number.shop).  
- Clear evidence of Amazon EC2 abuse for disposable phishing/malware campaigns.  
- Scale (~1.5M domains) complicates attribution but naming patterns provide detection pivot points.  

---

## Analyst Notes
>**149.50.136.243:** Hosted in Argentina via Donweb/Dattatec, registered under Cogent Communications (US). Dual attribution highlights attacker’s use of regional hosting with international upstreams.  
>**52.20.84.62:** Amazon EC2 node in Ashburn, VA. Massive domain count shows shared cloud environment abuse. Attackers exploit churnable infrastructure for stealth and scalability.  
>Later on in follow up investigations after upgrading my platform, I found a domain in a LNK file going to **423down[.]com**
>This domain reports back to IP address **45.151.132[.]50** as of 11/23/2025 the site was up and going to a download page with links to other sites and downloads likely linked to the other reported activities on this directory. 
>Added these artifacts to the IOCs section 11/23/2025

**Operational Impact:** Both IPs confirm reliance on cheap ccTLDs + disposable hosting/cloud services to maintain short-lived, churnable C2 servers.  

# Behavioral Assessment

## Masquerade
- **Evidence:** The installer metadata explicitly claims to be “Sogou Input Method v15.1.0.1570,” a legitimate release line. However, the packaging format is NSIS (not used by Sogou), and the binary contains XOR‑encoded configuration blobs, disposable domains, and persistence mechanisms. Legitimate Sogou installers do not include anti‑VM checks, screenshot capture, or clipboard theft.  
- **Impact:** Users are tricked into trusting the installer because it looks like a well‑known application. This lowers suspicion and increases infection rates, especially among those seeking cracked or “ad‑free” builds.  

## Installer Abuse
- **Evidence:** Reverse engineering revealed NSIS scripting combined with IShellLink usage. At runtime, the installer executes persistence routines, modifies shortcuts, and drops payloads while presenting a normal “Install Wizard” interface. Logs and runtime analysis confirmed payload execution begins immediately at the entry point, even as dialogs appear to function normally.  
- **Impact:** Victims believe they are installing legitimate software, but malicious actions occur silently in the background. This dual behavior makes detection harder and ensures persistence is established before the user realizes anything is wrong.  

## Persistence
- **Evidence:** Capa flagged IShellLink API calls, confirming shortcut creation/modification. Registry manipulation was also observed, with auto‑start entries created during installation. Suspicious .lnk files pointing to executables in %AppData% and %Temp% were identified.  
- **Impact:** Persistence is achieved through multiple mechanisms. Even if registry entries are removed, shortcut modifications ensure the malware continues to execute. This redundancy increases resilience against basic remediation attempts.  

## Defense Evasion
- **Evidence:** XOR and CRC32 encoding were used to obfuscate configuration data. Anti‑VM checks (Xen strings) and anti‑debugging APIs (FindWindowExA, GetLastError) were identified in the binary. Packed sections and anomalies in the .text segment further confirm obfuscation.  
- **Impact:** These techniques hinder sandbox analysis and frustrate reverse engineers. Automated detection tools may miss the malware due to packing and obfuscation, while analysts face delays caused by anti‑debugging routines. This prolongs the malware’s operational lifespan.  

## Collection
- **Evidence:** Capa and YARA hits confirmed capabilities to capture screenshots, record webcam images, and read/write clipboard data. API imports (CreateFileA, CopyFileA) support file manipulation for exfiltration.  
- **Impact:** The malware can steal sensitive visual and textual information, including credentials copied to the clipboard, private webcam feeds, and screenshots of banking or e‑commerce sessions. This enables credential theft, account hijacking, and privacy violations.  

## Privilege Escalation
- **Evidence:** Access token manipulation was flagged, allowing the malware to modify privileges and escalate execution rights. This was confirmed by capa findings and suspicious API usage (CreateProcessA, CreateThread).  
- **Impact:** Privilege escalation allows the malware to bypass user restrictions, install additional payloads, and disable security tools. It increases the attacker’s control over the system and enables deeper persistence.  

## Impact (System Disruption)
- **Evidence:** Functions enabling system shutdown and reboot were identified. These are not part of legitimate Sogou Input Method functionality.  
- **Impact:** The malware can disrupt system availability, either as a sabotage tactic or to force reboots that activate persistence mechanisms. This can cause data loss, downtime, and user frustration.  

## Command & Control (C2)
- **Evidence:** XOR decoding revealed disposable domains (6.ar, J.im) and endpoint tokens (CGI1). Resolution confirmed active IPs (149.50.136.243, 52.20.84.62). Traffic patterns mimic certificate validation (ocsp.digicert.com, crl3.digicert.com) and legitimate Sogou updates (get.sogou.com, ping.pinyin.sogou.com).  
- **Impact:** By blending malicious traffic with legitimate certificate checks and software updates, the malware evades detection by network monitoring tools. Disposable domains and churnable cloud IPs ensure C2 infrastructure can be quickly replaced, complicating takedown and attribution.  

---

## Analyst Notes (Expanded)
>The malware’s dual installer behavior is particularly dangerous: evidence shows payload execution begins immediately at installation, while the user sees a normal wizard. This ensures persistence is established before suspicion arises.  
>Defense evasion is layered and deliberate, combining obfuscation, packing, anti‑VM, and anti‑debugging. This frustrates both automated and manual analysis.  
>Collection capabilities target multiple data sources, enabling credential theft, surveillance, and fraud.  
>Privilege escalation and system disruption expand attacker control, allowing sabotage or forced reboots to activate persistence.  
>C2 infrastructure is disposable, cloud‑based, and disguised as legitimate traffic, making detection and takedown difficult.  

# Document Triage Findings

## File Analyzed
- **Filename:** 如意素材库.docx  
- **Hashes:**  
  - MD5: 259b7806c2c9cade90acb0f18d940197  
  - SHA1: 97f5b1508079584568d7f773d166d441097064b4  
  - SHA256: 4e987719ab96064594c98b62000612f90fe4c34c08161c290ec3898f100f6891  

## Metadata
- **Created with:** Apache POI in 2019  
- **Evidence:** Apache POI is a Java library used to programmatically generate Office documents. This indicates the file was not authored manually in Microsoft Word but produced automatically, likely as part of a batch or scripted distribution process.  
- **Impact:** Programmatic generation suggests scalability — the operator could mass‑produce promotional flyers to bundle with cracked installers or APKs, increasing reach.  

## AV/YARA Results
- **Detections:** None  
- **Evidence:** Multiple AV engines and YARA rules were run against the file, with zero hits.  
- **Impact:** Confirms the file is benign from a technical standpoint. It does not contain embedded malware or exploit payloads.  

## OOXML Unpack
- **Relationships and XML parts:** Reference only standard Office schemas.  
- **Evidence:** Manual unpacking of the OOXML structure showed only default Office schema references. No signs of obfuscation or hidden objects.  
- **Impact:** Reinforces the conclusion that the document is safe to open.  

## Document Content
- **Text:** Chinese promotional content for a Taobao shop: “如意素材库” (Ruyi Material Library).  
- **WeChat Contact:** rysc2019  
- **Evidence:** Plain text strings extracted from the document clearly reference the shop name and WeChat ID. No hidden layers or encoded content were found.  
- **Impact:** While benign, these identifiers are valuable for attribution. They likely represent commercial channels used by the operator to advertise pirated services, cracked software, or stolen accounts.  

## ATT&CK Mapping (Heuristic Flag)
- **Technique:** Web Protocols for C2 (T1071.001) flagged heuristically due to schema URLs.  
- **Evidence:** The flag was triggered by benign Office schema references (e.g., http://schemas.openxmlformats.org).  
- **Impact:** This is a false positive. Analysts must be cautious not to misinterpret benign schema references as malicious infrastructure.  

---

## Assessment
- **Benign Nature:** The document contains no macros, embedded objects, or malicious payloads.  
- **Promotional Role:** Functions as a lightweight flyer pointing to commercial channels (Taobao shop and WeChat ID).  
- **Evidence of Intent:** Programmatic generation via Apache POI suggests deliberate distribution at scale.  

### Operational Impact
- **Low technical risk:** The file itself cannot infect systems.  
- **High intelligence value:** Identifiers provide pivot points for OSINT investigations.  
- **Connection:** Links technical infrastructure (malware, automation, piracy) with commercial outreach (mainstream platforms like Taobao and WeChat).  

# Linkage Analysis: Promotional Document and Cybercrime Hub

## Context
During the broader investigation, a benign Microsoft Word document (**如意素材库.docx**) was discovered. While technically safe, its content provided identifiers that connect the technical infrastructure (malware, automation, piracy) with commercial outreach channels (Taobao and WeChat).

---

## Evidence and Reasoning

### WeChat ID (rysc2019)
- **Evidence:** Extracted directly from the document’s text. No obfuscation or encoding was present.  
- **Reasoning:** WeChat is widely used in China for communication and payments. Underground operators often use WeChat IDs as direct contact points for customers purchasing pirated IPTV streams, stolen JD.com accounts, or cracked software.  
- **Impact:** This identifier provides a pivot for OSINT investigations. It links the operator’s technical ecosystem to a mainstream communication/payment platform, showing how monetization is facilitated.  

### Taobao Shop (“如意素材库 / Ruyi Material Library”)
- **Evidence:** Promotional text in the document explicitly references this shop.  
- **Reasoning:** Taobao is a legitimate e‑commerce platform. By advertising a shop name, the operator creates a “legitimate‑looking” front to attract buyers. Transactions for illicit services may be funneled through Taobao for visibility, while WeChat handles off‑platform payments.  
- **Impact:** This demonstrates how the ecosystem blends underground automation with mainstream platforms. The shop name can be used to trace seller activity, reviews, or linked accounts, offering attribution opportunities.  

---

## Strategic Role of the Document
- **Evidence:** Metadata shows programmatic generation via Apache POI, suggesting the document was mass‑produced. Content is lightweight, containing only promotional identifiers.  
- **Reasoning:** The document functions as a flyer — distributed alongside cracked installers or APKs to advertise services. Its benign nature ensures it bypasses AV detection.  
- **Impact:** While not malicious, the document is a distribution vector for commercial identifiers, bridging technical malware campaigns with monetization channels.  

---

## Operational Impact
- **Integration of Technical and Commercial Layers:** The benign document proves the operator is not only running malware infrastructure but also actively advertising services.  
- **Attribution Value:** Identifiers (WeChat ID, Taobao) provide concrete pivot points for OSINT investigations.  

---

## Transition to Installer Analysis
The discovery of the exposed directory and live QingLong Panel confirmed the ecosystem was active and orchestrated. However, the installer itself is the linchpin of this operation — it is both the delivery mechanism and the persistence engine.  

- **Evidence:** The suspicious file (**搜狗拼音输入法_v15.1.0.1570去广告精简优化版_无毒_吾爱破解.exe**) was packaged as a Nullsoft NSIS installer, not the format used by legitimate Sogou Input Method releases.  
- **Reasoning:** This masquerade is deliberate. By mimicking a trusted application, the operator lowers suspicion and increases infection rates.  
- **Impact:** The installer is not just a wrapper — it is an active component of the malware ecosystem, embedding persistence, obfuscation, and covert communications directly into the installation process.  

**Conclusion:** This transition highlights why the installer analysis is critical: it reveals how the attacker blends malicious payloads with legitimate resources to ensure stealth, persistence, and scalability.  

# Complete Installer Summary

## Artifacts of Interest

### Loader & Execution Components
- **beacon_sdk.dll** operates as a loader DLL. It is packed and obfuscated, containing anti‑debugging routines designed to frustrate analysis. Its primary role is to execute payloads while evading detection, making it a critical stealth enabler within the ecosystem.  
- **SGDownload.exe** functions as a downloader binary. It stages files and retrieves additional payloads, expanding the infection chain beyond the initial installer and ensuring modular delivery of capabilities.  

### Networking & Command‑and‑Control
- **SGCurlHelper.dll** serves as a networking helper, leveraging HTTP and WinHTTP APIs. It manages outbound requests and demonstrates proxy awareness, ensuring reliable communication with external infrastructure.  
- **userNetSchedule.exe** acts as a scheduler orchestrator. It manipulates PKI and interacts with DigiCert endpoints, effectively serving as the command‑and‑control engine while masquerading as a legitimate Sogou scheduler process.  
- **UrlSignatureV.dat** is a signature database containing Base64‑like encoded strings. It is used for URL validation and obfuscation, feeding directly into C2 routines and helping disguise malicious traffic.  

### Persistence & User Data Management
- **UserExportDll.dll** is an export module containing persistence routines. It manages user data and performs registry and file manipulation, reinforcing long‑term control over the compromised system and ensuring the malware survives reboots or cleanup attempts.  

### User Interface & Disguise
- **pandorabox.cupf** is a theme resource containing dialogs and buttons, with metadata linked to Adobe Photoshop. Its role is to provide a user interface disguise, reinforcing the appearance of legitimacy.  
- **PersonalCenter.cupf** is a larger UI package, also tied to Adobe Photoshop CC metadata. It delivers a branded “Personal Center” interface, further enhancing the illusion of authenticity and making the malware appear like a legitimate application.  

---

## Analyst Note
>Grouped this way, the artifacts reveal a layered design:  
>- Execution and delivery handled by loader and downloader components.  
>- Networking and C2 managed through helper DLLs, disguised schedulers, and encoded signature databases.  
>- Persistence and user data manipulation embedded in export modules.  
>- UI disguise achieved through themed resource files with Photoshop metadata.  

>Together, these artifacts demonstrate how the operator blends stealth, persistence, communication, and legitimacy cues to maintain control and monetize infections.  

---

## Packaging and Masquerade
- **Evidence:** Metadata claims the file is Sogou Input Method v15.1.0.1570, but analysis shows NSIS packaging, XOR‑encoded configuration blobs, disposable domains, and persistence mechanisms.  
- **Impact:** Users trust the installer because it looks familiar, but malicious actions begin immediately at runtime. This is a textbook case of **T1036 – Masquerading**.  

---

## Installer Behavior
- **Evidence:**  
  - NSIS scripting allows custom actions during installation (copy files, run commands, drop payloads).  
  - IShellLink API usage confirms shortcut manipulation.  
  - Runtime analysis showed payload execution begins at the entry point, even as dialogs appear normal.  
- **Impact:** The installer executes malicious actions behind a normal “Install Wizard” interface, ensuring persistence is established before suspicion arises.  

---

## Persistence Mechanisms
- **Evidence:** Shortcut creation/modification via IShellLink API, registry run keys, and auto‑start entries. Suspicious .lnk files were identified in %AppData% and %Temp%.  
- **Impact:** Multiple persistence mechanisms provide redundancy. Even if registry entries are removed, shortcut modifications ensure continued execution.  

---

## Defense Evasion
- **Evidence:** XOR and CRC32 encoding obfuscate configuration data. Anti‑VM checks (Xen strings) and anti‑debugging APIs (FindWindowExA, GetLastError) resist analysis. Packed sections and anomalies in the .text segment confirm obfuscation.  
- **Impact:** These techniques hinder sandbox detection and frustrate reverse engineers, prolonging the malware’s operational lifespan.  

---

## Collection Capabilities
- **Evidence:** Capa and YARA hits confirmed screenshot capture, webcam recording, and clipboard theft. API imports (CreateFileA, CopyFileA) support file manipulation for exfiltration.  
- **Impact:** Enables theft of credentials, private webcam feeds, and screenshots of sensitive sessions (e.g., banking, e‑commerce).  

---

## Privilege Escalation
- **Evidence:** Access token manipulation flagged, allowing modification of privileges and escalation of execution rights.  
- **Impact:** Escalation allows bypassing user restrictions, disabling security tools, and installing additional payloads.  

---

## System Disruption
- **Evidence:** Functions enabling system shutdown and reboot identified.  
- **Impact:** Can disrupt availability, sabotage systems, or force reboots to activate persistence mechanisms.  

---

## Command & Control (C2)
- **Evidence:** XOR decoding revealed disposable domains (6.ar, J.im) and endpoint tokens (CGI1). Resolution confirmed active IPs (149.50.136.243, 52.20.84.62). Traffic patterns mimic certificate validation (ocsp.digicert.com) and legitimate Sogou updates (get.sogou.com).  
- **Impact:** Blending malicious traffic with legitimate certificate checks and software updates evades detection. Disposable domains and churnable cloud IPs complicate takedown and attribution.  

---

## Installer Assessment
The installer is not a passive delivery wrapper. It is a multi‑layered orchestration tool that:  
- Masquerades as trusted software to lower suspicion.  
- Executes malicious actions silently during installation.  
- Establishes persistence through shortcuts and registry keys.  
- Evades detection with obfuscation, packing, and anti‑analysis checks.  
- Collects sensitive data (screenshots, webcam, clipboard).  
- Escalates privileges and disrupts systems.  
- Communicates with disposable domains and cloud IPs disguised as legitimate traffic.  

**Impact:** The installer is the cornerstone of the **SogouStealer ecosystem**. It ensures infections are stealthy, persistent, and scalable, directly supporting monetization through fraud, piracy, and credential theft.  

# Final Infection Chain

## Wrapper / Staging File (the “fake Sogou installer”)
- **Role:** Acts as the initial dropper.  
- **Behavior:**  
  - Pretends to be the legitimate Sogou Input Method installer.  
  - Establishes persistence (registry keys, shortcut modification).  
  - Requests elevated permissions (likely admin) to stage additional components.  
  - Extracts and drops secondary files needed for the full infection chain.  
- **Impact:** Creates the staging ground — ensuring the environment is prepared, persistence is in place, and the next payload can run seamlessly.  

---

## Embedded / Secondary Installer (the “main payload”)
- **Role:** Functions as the true malicious agent.  
- **Behavior:**  
  - Runs in the background while presenting itself as a normal installer.  
  - Collects sensitive information (screenshots, webcam feeds, clipboard data).  
  - Manipulates access tokens for privilege escalation.  
  - Establishes its own persistence mechanisms (redundancy).  
  - Initiates networking actions to exfiltrate stolen data.  
  - Communicates with disposable domains and cloud IPs, disguising traffic as legitimate certificate checks or Sogou updates.  
- **Impact:** Operates as the multi‑purpose stealer/RAT, maintaining long‑term control, harvesting data, and ensuring communication with C2 infrastructure.  

---

## Analyst Note
>**Stage 1 (Wrapper):** Loader/downloader role — staging ground, persistence, payload extraction.  
>**Stage 2 (Payload):** Multi‑purpose stealer/RAT — surveillance, privilege escalation, persistence, exfiltration, C2.  
>**Operational Design:** The infection chain is deliberately layered. The wrapper ensures delivery and stability, while the embedded payload executes the full malicious capability set.  

# Final Infection Chain Flow & Components

## Stage 1: Wrapper / Staging File
**Role:** Initial dropper and staging ground.  

**Key Behaviors:**
- Masquerades as legitimate Sogou Input Method installer.  
- Requests elevated permissions (admin rights).  
- Establishes persistence via registry run keys and shortcut modification.  
- Extracts and drops embedded files:  
  - **SGDownload.exe** – downloader, file staging.  
  - **beacon_sdk.dll** – loader DLL, packed/obfuscated, anti‑debugging.  
  - **UserExportDll.dll** – export module, persistence routines.  
- Prepares environment for execution.  

**Impact:** Ensures persistence and sets the stage for the main payload to run seamlessly.  

---

## Stage 2: Embedded Installer Payload
**Role:** True malicious agent (multi‑purpose stealer/RAT).  

**Key Behaviors:**
- Runs in the background while presenting a normal installer interface.  
- Collects sensitive data: screenshots, webcam feeds, clipboard contents.  
- Manipulates access tokens for privilege escalation.  
- Establishes redundant persistence mechanisms (e.g., UserExportDll.dll registry/file manipulation).  
- Initiates networking actions through:  
  - **SGCurlHelper.dll** – networking helper, HTTP/WinHTTP APIs, proxy awareness.  
  - **userNetSchedule.exe** – scheduler orchestrator, PKI manipulation, DigiCert endpoints.  
  - **UrlSignatureV.dat** – signature database, Base64‑like encoded strings for URL validation/obfuscation.  
- Exfiltrates stolen data to disposable domains/cloud IPs.  
- Disguises traffic as certificate checks or Sogou updates.  
- Maintains long‑term RAT‑like control.  

**Impact:** Provides surveillance, privilege escalation, persistence, exfiltration, and covert C2 communication.  

---

## Stage 3: User Interface Disguise
**Role:** Reinforces legitimacy and lowers suspicion.  

**Key Behaviors:**
- Deploys theme resources to mimic genuine software:  
  - **pandorabox.cupf** – dialogs/buttons, Photoshop metadata.  
  - **PersonalCenter.cupf** – larger UI package, branded “Personal Center” interface.  
- Ensures user perceives installer as genuine software.  

**Impact:** Strengthens masquerade, making malicious activity appear like normal application behavior.  

---

## Analyst Summary
>**Stage 1 (Wrapper):** Loader/downloader role — staging ground, persistence, payload extraction.  
>**Stage 2 (Payload):** Multi‑purpose stealer/RAT — surveillance, privilege escalation, persistence, exfiltration, C2.  
>**Stage 3 (UI Disguise):** Legitimacy cues — themed resources to mask malicious behavior.  

**Operational Design:** The infection chain is deliberately layered. The wrapper ensures delivery and stability, while the embedded payload executes the full malicious capability set, and the UI disguise maintains user trust.

# Final Analysis & Conclusion

## Context of Discovery
The investigation began with a suspicious installer masquerading as a cracked version of **Sogou Input Method**.  
What appeared at first to be a single malicious file quickly expanded into evidence of a **multi‑purpose cybercrime hub**, revealed through an exposed directory and a live **QingLong Panel** orchestrating malware, piracy, and credential theft campaigns.  

---

## Installer as the Linchpin
- **Evidence:** The installer was packaged with **NSIS**, not the format used by legitimate Sogou releases. It contained XOR‑encoded configuration data, disposable domains, and persistence mechanisms.  
- **Impact:** The installer is not a passive wrapper but a **multi‑layered stealer/loader**. It executes malicious actions behind a normal “Install Wizard” interface, establishes persistence redundantly, evades detection, collects sensitive data, escalates privileges, and communicates with disposable infrastructure disguised as legitimate traffic.  

**Additional Operational Insight:**  
- **Stage 1 (Wrapper):** Masquerades as Sogou, establishes persistence, requests elevated permissions, and drops embedded components.  
- **Stage 2 (Payload):** Operates as the main agent, performing surveillance (screenshots, webcam, clipboard), manipulating access tokens, initiating networking actions for exfiltration, and maintaining RAT‑like control.  
- **Result:** Together, they form a **hybrid loader + stealer/RAT ecosystem**.  

---

## Infrastructure & Config Extraction
- **Evidence:** XOR decoding revealed domains (e.g., `6.ar`, `J.im`) resolving to active IPs in **Argentina (Donweb/Cogent)** and the **US (Amazon AWS)**. Other domains were disposable placeholders.  
- **Impact:** Reliance on **cheap ccTLDs** and **churnable cloud IPs** demonstrates resilience and scalability. Infrastructure can be cycled rapidly, complicating takedown and attribution.  

---

## Behavioral Profile
- **Evidence:** Capa, YARA, and peframe confirmed:  
  - Persistence (registry + shortcut modification)  
  - Defense evasion (packing, anti‑VM, anti‑debugging)  
  - Collection (screenshots, webcam, clipboard)  
  - Privilege escalation  
  - System disruption  
- **Impact:** The malware is designed for **long‑term stealth, surveillance, and monetization**, resisting analysis while harvesting sensitive data and maintaining control.  
- **Infection Chain Insight:** Persistence and staging are handled first by the wrapper, while the embedded payload executes the full spectrum of malicious capabilities, including exfiltration and covert communications.  

---

## Document Triage & Linkage
- **Evidence:** A benign Word document (**如意素材库.docx**) promoted a **Taobao shop (“如意素材库”)** and **WeChat ID (rysc2019)**. Metadata showed programmatic generation via Apache POI.  
- **Impact:** While technically safe, the document connects the technical infrastructure to **commercial outreach channels**, proving the operator’s dual focus on malware distribution and monetization. These identifiers provide **attribution leads and OSINT pivot points**.  

---

## Strategic Assessment
- The ecosystem is **not dormant** — evidence of live orchestration via QingLong Panel and active domain resolution confirms ongoing operations.  
- The operator blends **technical automation** (malware, credential theft, piracy scripts) with **commercial monetization** (Taobao, WeChat).  
- Infrastructure strategy relies on **low‑cost, high‑turnover domains and cloud IPs**, ensuring resilience and scalability.  
- The installer is the **cornerstone of this ecosystem**, embedding persistence, evasion, collection, and covert communications directly into the installation process.  
- The infection chain analysis further shows that the wrapper establishes the staging ground, while the embedded payload executes the full malicious capability set — confirming a deliberate **two‑stage design** that maximizes stealth and operational control.  

# Conclusion

This investigation reveals a **multi‑purpose cybercrime hub** centered around a **masquerading installer**.  
The operator leverages **disposable infrastructure**, **layered evasion**, and **broad collection capabilities** to maintain stealth and scalability.  

Promotional documents tie the technical ecosystem to **monetization channels**, confirming the dual nature of the operation:  
- **Malware distribution**  
- **Commercial exploitation**  

The infection chain demonstrates a **hybrid loader + stealer/RAT model**:  
- **Wrapper stage:** establishes persistence and delivery.  
- **Embedded payload:** performs surveillance, privilege escalation, exfiltration, and command‑and‑control.  

**Final Insight:** The ecosystem blends technical automation with commercial outreach, ensuring infections are stealthy, persistent, and monetized at scale.

# MITRE ATT&CK Mapping

## Initial Access
- **T1036 – Masquerading**  
  - **Evidence:** Installer disguised as Sogou Input Method.  
  - **Impact:** Lowers suspicion, increases infection rates.  

---

## Execution
- **T1059 – Command and Scripting Interpreter (NSIS scripting)**  
  - **Evidence:** Custom NSIS installer actions.  
  - **Impact:** Executes payloads silently during installation.  

---

## Persistence
- **T1547.001 – Registry Run Keys / Startup Folder**  
  - **Evidence:** Registry auto‑start entries created.  
- **T1547.009 – Shortcut Modification**  
  - **Evidence:** IShellLink API usage to modify `.lnk` files.  
- **Impact:** Multiple redundant persistence mechanisms ensure resilience.  

---

## Privilege Escalation
- **T1134 – Access Token Manipulation**  
  - **Evidence:** Token abuse flagged by capa/YARA.  
  - **Impact:** Escalates privileges, bypasses restrictions.  

---

## Defense Evasion
- **T1027 – Obfuscated Files or Information**  
  - **Evidence:** XOR/CRC32 encoding of config.  
- **T1027.002 – Software Packing**  
  - **Evidence:** Overlay section with encoded data.  
- **T1497.001 – Virtualization/Sandbox Evasion**  
  - **Evidence:** Xen string checks.  
- **T1622 – Debugger Evasion**  
  - **Evidence:** Anti‑debugging APIs (FindWindowExA, GetLastError).  
- **Impact:** Frustrates analysis, prolongs operational lifespan.  

---

## Collection
- **T1113 – Screen Capture**  
  - **Evidence:** Screenshot capability flagged.  
- **T1125 – Video Capture (Webcam)**  
  - **Evidence:** Webcam capture routines.  
- **T1115 – Clipboard Data**  
  - **Evidence:** Clipboard read/write detected.  
- **Impact:** Enables theft of credentials, private data, and surveillance.  

---

## Impact
- **T1529 – System Shutdown/Reboot**  
  - **Evidence:** Functions enabling shutdown/reboot.  
  - **Impact:** Disrupts availability, forces reboots to activate persistence.  

---

## Command & Control
- **T1071.001 – Application Layer Protocol: Web Protocols**  
  - **Evidence:** Communication with disposable domains via HTTP/CGI endpoints.  
  - **Impact:** Blends malicious traffic with legitimate certificate checks and Sogou updates.  

---

## Analyst Notes
- Consolidated IOCs provide defenders with concrete detection artifacts: domains, IPs, hashes, mutexes, and promotional identifiers.  
- ATT&CK mapping confirms the malware is **multi‑functional**: masquerading, executing silently, persisting redundantly, evading defenses, collecting data, escalating privileges, disrupting systems, and communicating covertly.  
- Together, these references form the **operational backbone of the report** — actionable for detection engineers, threat hunters, and intelligence analysts.  

---

## Incident Response Procedures

### Priority 1: Initial Response
1. **ISOLATE** all systems with Sogou Input Method installations immediately
2. **BLOCK** network access to identified infrastructure:
   - 27.184.28.134:8081 (QingLong Panel)
   - 6.ar → 149.50.136.243 (Argentina)
   - J.im → 52.20.84.62 (AWS US)
3. **IDENTIFY** all users who may have installed cracked Sogou software
4. **COLLECT** forensic evidence including memory dumps and network logs
5. **DOCUMENT** all affected systems and user accounts
6. **ASSESS** regulatory notification requirements for credential theft

### Priority 2: Investigation & Analysis
1. **FORENSIC ANALYSIS** of collected artifacts for persistence mechanisms
2. **LOG ANALYSIS** for JD.com credential theft and financial impact
3. **NETWORK ANALYSIS** for additional C2 infrastructure and data exfiltration
4. **USER INTERVIEWS** to determine infection vector and timeline
5. **REGULATORY ASSESSMENT** for credential theft notification requirements

### Priority 3: Remediation & Recovery
1. **REBUILD** affected systems from known-good images
2. **RESET** all credentials for potentially compromised accounts
3. **UPDATE** endpoint detection and response signatures
4. **DEPLOY** enhanced monitoring for NSIS-based installers
5. **IMPLEMENT** application whitelisting for software installations

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
      <td><strong>Credential Theft</strong></td>
      <td class="high">HIGH</td>
      <td>extended period</td>
    </tr>
    <tr>
      <td><strong>System Compromise</strong></td>
      <td class="high">HIGH</td>
      <td>several weeks</td>
    </tr>
    <tr>
      <td><strong>Operational Disruption</strong></td>
      <td class="medium">MEDIUM</td>
      <td>several weeks</td>
    </tr>
    <tr>
      <td><strong>Compliance Impact</strong></td>
      <td class="high">HIGH</td>
      <td>extended period</td>
    </tr>
  </tbody>
</table>

### Operational Impact Timeline
- **Immediate Response:** System isolation, service disruption, credential reset
- **Investigation Phase:** Forensic analysis and impact assessment
- **Recovery Phase:** System recovery and enhanced monitoring deployment
- **Long-term Phase:** Process improvements and compliance activities

---

## Long-term Defensive Strategy

### Technology Enhancements
1. **Application Control** to prevent unauthorized software installations
2. **Network Segmentation** to limit lateral movement and data exfiltration
3. **Advanced Threat Protection** with NSIS installer analysis capabilities
4. **User Behavior Analytics** to detect unusual software installation patterns
5. **Threat Intelligence Integration** for emerging Chinese malware families

### Process Improvements
1. **Software Installation Policies** requiring vendor approval and digital signature verification
2. **Incident Response Playbooks** specific to credential theft and malware distribution
3. **Regular Security Awareness Training** on risks of cracked software
4. **Vendor Risk Management** for third-party software suppliers
5. **Continuous Monitoring** of emerging threat actor tactics and infrastructure

### Organizational Measures
1. **Security Champions Program** to promote security culture
2. **Regular Security Assessments** including penetration testing of endpoint defenses
3. **Threat Intelligence Subscription** for early warning of Chinese cybercrime operations
4. **Executive Security Briefings** on emerging credential theft threats
5. **Investment in Security Tools** and personnel training for advanced threat detection

---

## Frequently Asked Questions

### Technical Questions
**Q: What makes the QingLong Panel particularly dangerous?**  
A: It's a live automation framework with authenticated operators actively managing malware distribution, making this an ongoing criminal operation rather than a static malware sample.

**Q: How does the two-stage infection chain work?**  
A: Stage 1 (wrapper) establishes persistence and drops components, while Stage 2 (payload) executes the full malicious capability set including surveillance, data theft, and remote control.

**Q: Why are disposable domains and cloud IPs used?**  
A: They provide infrastructure resilience - domains can be quickly registered and abandoned, while cloud IPs can be rapidly provisioned and moved, complicating takedown efforts.

### Business Questions
**Q: What are the regulatory implications of JD.com credential theft?**  
A: Significant - credential theft of e-commerce accounts triggers various data breach notification requirements and potential liability for fraudulent transactions.

**Q: Should we rebuild or clean infected systems?**  
A: **REBUILD** is strongly recommended due to multiple persistence mechanisms and the sophisticated nature of this multi-stage malware.

**Q: How can we prevent similar infections?**  
A: Implement strict software installation policies, application whitelisting, and user education on the dangers of cracked software.

---

## IOCs
- [Hybrid Loader/Stealer Ecosystem Masquerading as Sogou]({{ "/ioc-feeds/Hybrid-Loader-Stealer-Sogou.json" | relative_url }})

## Detections
- [Hybrid Loader/Stealer Ecosystem Masquerading as Sogou]({{ "/hunting-detections/Hybrid-Loader-Stealer-Sogou/" | relative_url }})

---

## License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.