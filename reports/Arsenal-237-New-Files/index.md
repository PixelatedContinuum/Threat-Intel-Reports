---
title: "Arsenal-237 New Files Analysis"
date: '2026-01-27'
layout: post
permalink: /reports/arsenal-237-new-files/
thumbnail: /assets/images/cards/arsenal-237-new-files.png
category: "Ransomware Toolkit"
series: arsenal-237
series_role: member
series_order: 1
hide: true
description: "Follow-up analysis of 11 new samples added to the Arsenal-237 open directory at 109.230.231.37, documenting a significant capability jump from the original 16 samples. New additions include BYOVD kernel driver abuse via a vulnerable Baidu antivirus driver, a kernel-mode rootkit with file hiding and API hooking, a CrowdStrike-specific EDR terminator, and enterprise-grade Rust ransomware targeting backup systems with ChaCha20 encryption."
---

**Campaign Identifier:** Arsenal-237-New-Files-109.230.231.37<br>
**Last Updated:** January 27, 2026<br>
**Threat Level:** CRITICAL


---

> **Part of series:** This is report 2 of 2 in the Arsenal-237 investigation. The original report — [Arsenal-237: Threat Actor R&D Repository Exposed](/reports/109.230.231.37-Executive-Overview/) — documents the first 16 samples found in the same open directory (109.230.231.37) and is the recommended starting point; this follow-up analyzes the 11 samples added after that discovery.

---

## Report Context: New Files from Arsenal-237 Directory

This report analyzes **11 new malware samples** added to the same open directory (109.230.231.37) documented in early January 2026. These samples represent a significant capability jump from the original 16: the new additions introduce BYOVD kernel driver abuse, a kernel-mode rootkit, a CrowdStrike-specific EDR terminator, and enterprise-grade Rust ransomware — capabilities absent from the first wave.

---

## BLUF: The Arsenal-237 Threat

Arsenal-237 is a modular ransomware toolkit built for enterprise compromise across three sequential phases: privilege escalation and defense disablement, persistence and credential access, then ransomware deployment.

**Phase 1 — Privilege escalation and defense disablement.** lpe.exe achieves NT AUTHORITY\SYSTEM through five techniques: token impersonation from lsass.exe and winlogon.exe, registry UAC bypass via fodhelper.exe hijacking, and SYSTEM-level scheduled tasks. With SYSTEM privileges, killer.dll and its CrowdStrike-specific variant killer_crowdstrike.dll load the signed but vulnerable BdApiUtil64.sys (Baidu antivirus driver) and issue kernel-mode IOCTL commands (e.g., 0x800024B4) to terminate CSFalconService.exe, csagent.exe, and more than 20 other security products. rootkit.dll extends this by adding Unicode-based file hiding, API hooking for call interception, PowerShell integration, and anti-forensics measures that target process-monitoring and packet-analysis tools.

**Phase 2 — Persistence and credential access.** nethost.dll establishes persistence via DLL hijacking, beacons to hardcoded TCP targets (8.8.8.8:53 and 127.0.0.1:53), and supports PowerShell execution, system enumeration, and Base64-encoded exfiltration. chromelevator.exe uses reflective DLL injection and direct syscalls to extract cookies, passwords, and payment data from Chrome, Brave, and Edge credential stores.

**Phase 3 — Ransomware deployment.** new_enc.exe targets Veritas Backup Exec agents and VSS snapshots using a hardcoded ChaCha20 key (67e6096a...) — a test-variant operational security lapse. full_test_enc.exe deploys multi-threaded hybrid encryption (RSA-OAEP + ChaCha20) across all accessible drives and network shares without C2 dependence, making decryption impossible without the operator's RSA private key. dec_fixed.exe — a victim-specific decryptor carrying a distinct hardcoded key (1e0d8597...) — confirms per-victim key management and an active RaaS model (CONFIRMED).

### The Organizational Threat in Plain Terms

When Arsenal-237 reaches a target environment, attackers gain the ability to:
1. Disable security products using rootkit techniques (malware that hides at the deepest system level, defeating standard antivirus detection)
2. Escalate privileges to SYSTEM level (gaining complete administrative control)
3. Establish persistent backdoor access (maintaining control even after system reboots)
4. Steal credentials from web browsers and credential stores
5. Deploy ransomware that encrypts critical business data with hybrid cryptography (encryption so strong that even expert cryptographers cannot break it without the attacker's private decryption key)
6. Negotiate ransom demands with per-victim decryption capabilities as leverage

**Evidence of active development** (test builds recovered) indicates imminent deployment campaigns.

### Executive Risk Summary

| **Risk Factor** | **Score (1-10)** | **Business Impact** |
|---|---|---|
| **Overall Toolkit Risk** | **9.5/10** | CRITICAL - Requires immediate attention from executive leadership |
| **Data Encryption Risk** | 10/10 | All enterprise data at risk; recovery requires external decryption keys |
| **System Compromise** | 9.5/10 | Complete infrastructure control possible; kernel-level persistence |
| **Detection Evasion** | 9/10 | Kernel rootkit defeats most detection systems; backup targeting |
| **Operational Resilience** | 9/10 | Distributed across multiple components; difficult to fully remediate |
| **Ransomware Recovery** | 8.5/10 | RSA-OAEP + ChaCha20 hybrid encryption; recovery without the operator's private key is not possible |

**Overall Risk Assessment: CRITICAL (9.5/10)** - Executive escalation and immediate defensive action required.

### Confidence Level Framework

- **DEFINITE / CONFIRMED**: Malware functionality directly observed in static/dynamic analysis
- **HIGH (90%+)**: Multiple samples confirm behavior; attacks probable
- **MODERATE (75-90%)**: Reasonable inference from code and attack patterns
- **LOW (50-75%)**: Analytical judgment; requires additional evidence

---

## Analysis Components — New Files

### Arsenal-237 New Files — Recently Added Malware

Each sample has three companion resources: a technical report with behavioral analysis and response guidance, a detection package with YARA/Sigma rules, and a machine-readable IOC feed for SIEM/EDR ingestion.

**killer.dll (BYOVD Process Termination):** | [Technical Report]({{ "/reports/arsenal-237-new-files/killer-dll/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-killer-dll/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-killer-dll.json" | relative_url }})
**killer_crowdstrike.dll (CrowdStrike Variant):** | [Technical Report]({{ "/reports/arsenal-237-new-files/killer-crowdstrike-dll/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-killer-crowdstrike-dll/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-killer-crowdstrike-dll.json" | relative_url }})
**lpe.exe (Privilege Escalation):** | [Technical Report]({{ "/reports/arsenal-237-lpe-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-lpe-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-lpe-exe.json" | relative_url }})
**BdApiUtil64.sys (Vulnerable Baidu Driver):** | [Technical Report]({{ "/reports/bdapiutil64-sys/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-BdApiUtil64-sys/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-BdApiUtil64-sys.json" | relative_url }})
**rootkit.dll (Kernel-Mode Rootkit):** | [Technical Report]({{ "/reports/arsenal-237/rootkit-dll/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-rootkit-dll/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-rootkit-dll.json" | relative_url }})
**nethost.dll (DLL Hijacking Persistence):** | [Technical Report]({{ "/reports/arsenal-237/nethost-dll/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-nethost-dll/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-nethost-dll.json" | relative_url }})
**chromelevator.exe (Browser Credential Theft):** | [Technical Report]({{ "/reports/arsenal-237-new-files/chromelevator-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-chromelevator-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-chromelevator-exe.json" | relative_url }})
**enc_c2.exe (Rust Ransomware with Tor C2):** | [Technical Report]({{ "/reports/arsenal-237-new-files/enc_c2-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-enc_c2-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-enc_c2-exe.json" | relative_url }})
**new_enc.exe (Human-Operated Ransomware):** | [Technical Report]({{ "/reports/new-enc-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-new_enc-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-new_enc-exe.json" | relative_url }})
**dec_fixed.exe (Ransomware Decryptor):** | [Technical Report]({{ "/reports/arsenal-237-new-files/dec_fixed-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-dec_fixed-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-dec_fixed-exe.json" | relative_url }})
**full_test_enc.exe (Advanced Rust Ransomware):** | [Technical Report]({{ "/reports/arsenal-237-new-files/full_test_enc-exe/" | relative_url }}) | [Detection Package]({{ "/hunting-detections/arsenal-237-full_test_enc-exe/" | relative_url }}) | [IOC Feed]({{ "/ioc-feeds/arsenal-237-full_test_enc-exe.json" | relative_url }})

---

## Toolkit Component Overview

This landing page indexes 11 detailed analysis reports covering the complete Arsenal-237 attack chain. Each component report includes file hashes (MD5, SHA1, SHA256), IOC feeds, YARA/Sigma detection rules, behavioral analysis, and MITRE ATT&CK mappings.

### Phase 1: Defense Evasion & Privilege Escalation (5 Components)
Five components disable security products and elevate attacker privileges to kernel level.

### Phase 2: Persistence & Credential Access (2 Components)
Two components maintain access and harvest credentials from browsers.

### Phase 3: Impact - Ransomware Deployment (4 Components)
Four components perform file encryption and provide victim-specific decryption capabilities.

---

## Toolkit Architecture Overview

### Design Philosophy: Professional Ransomware-as-a-Service

Arsenal-237 carries five markers of a mature **Ransomware-as-a-Service (RaaS)** operation:

- **Modular architecture** for flexible deployment
- **Per-victim key management** enabling affiliate tracking and decryption licensing
- **Multiple evasion techniques** targeting different security products
- **Test/beta variants** showing active pre-deployment iteration
- **Rust implementation** delivering cross-platform capability and memory safety

### Toolkit Structure: Three Operational Phases

```
PHASE 1: Defense Evasion & Privilege Escalation
+-----------------------------------------------------+
| killer.dll / killer_crowdstrike.dll                 | Terminate security products
| lpe.exe                                             | Escalate to SYSTEM
| BdApiUtil64.sys (vulnerable Baidu driver)           | Acquire kernel access
| rootkit.dll                                         | Hide malware from detection
+-----------------------------------------------------+
                        |
                        v
PHASE 2: Persistence & Credential Access
+-----------------------------------------------------+
| nethost.dll (masquerading .NET loader)              | DLL hijacking persistence
| chromelevator.exe                                   | Browser credential theft
+-----------------------------------------------------+
                        |
                        v
PHASE 3: Impact - Ransomware Deployment
+-----------------------------------------------------+
| enc_c2.exe / new_enc.exe / full_test_enc.exe        | Encrypt critical data
| dec_fixed.exe                                       | Victim-specific decryption
+-----------------------------------------------------+
```

### Key Technical Characteristics

**Cryptographic Foundation:**
- **RSA-OAEP + ChaCha20 hybrid encryption** in advanced variants — decryption requires the operator's RSA private key
- **Per-victim key architecture** enabling the RaaS affiliate model
- **Hardcoded keys in test variants** (67e6096a... in new_enc.exe; 1e0d8597... in dec_fixed.exe) — operational security lapses that distinguish test builds from deployment variants
- **Different keys across samples** indicating builder/deployment tracking

**Evasion Techniques:**
- Kernel-mode rootkit hiding processes, threads, and drivers
- BYOVD kernel access via BdApiUtil64.sys
- CrowdStrike-specific variant (killer_crowdstrike.dll) indicating targeted EDR research
- Anti-VM and anti-analysis detection

**Rust Implementation:**
- Multi-threaded encryption via the Rayon library
- Memory safety that limits exploitation of the ransomware itself
- Cross-platform build capability

---

## Component Analysis Index

All 11 components have individual detailed reports with full technical analysis, IOCs, and detection rules.

### PHASE 1: DEFENSE EVASION & PRIVILEGE ESCALATION

#### 1. [killer.dll - Basic BYOVD Process Termination](./killer-dll.md)

**Component Type:** Security Product Disabler (BYOVD-based)

**Technical Summary:** Driver-level process terminator that loads BdApiUtil64.sys for kernel access and terminates security product processes. Serves as the foundation for the CrowdStrike-specific variant.

**File Identifiers:**
- MD5: `c031054f6140e2c366eaf4263f827dbf`
- SHA256: `10eb1fbb2be3a09eefb3d97112e42bb06cf029e6cac2a9fb891b8b89a25c788d`

**Confidence Level:** CONFIRMED (static and behavioral analysis)

**Link to Full Report:** [./killer-dll.md](./killer-dll.md)

---

#### 2. [killer_crowdstrike.dll - CrowdStrike-Specific Process Termination](./killer_crowdstrike-dll.md)

**Component Type:** EDR-Specific Defense Disabler

**Technical Summary:** killer.dll variant with product-specific targeting of CSFalconService.exe and csagent.exe. The CrowdStrike-specific function names and driver interactions confirm the threat actor researched enterprise EDR deployments before building this variant.

**File Identifiers:**
- MD5: `6926ea1b4c4bff01a23b7e1728583348`
- SHA256: `e26e9221f4e9a437716a28c08c5f74c6a2ecae2c47b77091db7d21f36ed2f7d3`

**Confidence Level:** CONFIRMED (product-specific function names and driver interactions)

**Link to Full Report:** [./killer_crowdstrike-dll.md](./killer_crowdstrike-dll.md)

---

#### 3. [lpe.exe - Privilege Escalation Wrapper](./lpe-exe.md)

**Component Type:** Privilege Escalation Tool

**Technical Summary:** Privilege escalation wrapper using five techniques — token impersonation from lsass.exe and winlogon.exe, registry UAC bypass via fodhelper.exe hijacking, and SYSTEM-level scheduled tasks — to reach NT AUTHORITY\SYSTEM. All kernel-mode operations in Phase 1 depend on the privileges this component delivers.

**File Identifiers:**
- MD5: `47400a6b7c84847db0513e6dbc04e469`
- SHA256: `c4dda7b5c5f6eab49efc86091377ab08275aa951d956a5485665954830d1267e`

**Confidence Level:** CONFIRMED (API calls and capability testing)

**Link to Full Report:** [./lpe-exe.md](./lpe-exe.md)

---

#### 4. [BdApiUtil64.sys - Vulnerable Baidu Driver (BYOVD)](./BdApiUtil64-sys.md)

**Component Type:** Vulnerable Driver for Kernel Access

**Technical Summary:** Signed Baidu antivirus driver with a known privilege escalation vulnerability. Arsenal-237 loads this driver via BYOVD — abusing its legitimate Windows signature to pass kernel protection checks, then exploiting the vulnerability for kernel-mode code execution. This driver loading precedes rootkit injection.

**File Identifiers:**
- MD5: `ced47b89212f3260ebeb41682a4b95ec`
- SHA256: `47ec51b5f0ede1e70bd66f3f0152f9eb536d534565dbb7fcc3a05f542dbe4428`

**Confidence Level:** CONFIRMED (known CVE and exploitation pattern)

**Link to Full Report:** [./BdApiUtil64-sys.md](./BdApiUtil64-sys.md)

---

#### 5. [rootkit.dll - Kernel-Mode Rootkit](./rootkit-dll.md)

**Component Type:** Kernel-Mode Persistence and Hiding

**Technical Summary:** Kernel-mode rootkit installed via BYOVD exploitation. Hides malware processes, threads, and drivers from user-mode enumeration; maintains persistence across reboots; and adds Unicode-based file hiding, API hooking, PowerShell integration, and anti-forensics targeting process-monitoring and packet-analysis tools. User-mode detection tools cannot see objects this rootkit conceals — infected systems require kernel-mode forensics or a full rebuild.

**File Identifiers:**
- MD5: `674795d4d4ec09372904704633ea0d86`
- SHA256: `e71240f26af1052172b5864cdddb78fcb990d7a96d53b7d22d19f5dfccdf9012`

**Confidence Level:** CONFIRMED (kernel driver analysis)

**Link to Full Report:** [./rootkit-dll.md](./rootkit-dll.md)

---

### PHASE 2: PERSISTENCE & CREDENTIAL ACCESS

#### 6. [nethost.dll - Masquerading .NET Loader (DLL Hijacking)](./nethost-dll.md)

**Component Type:** Persistence Mechanism (DLL Hijacking)

**Technical Summary:** Masquerades as the legitimate .NET runtime component nethost.dll. Loaded by legitimate .NET processes, it establishes DLL-hijacking persistence that survives reboots, beacons to hardcoded TCP targets (8.8.8.8:53 and 127.0.0.1:53), and supports PowerShell execution, system enumeration, and Base64-encoded exfiltration.

**File Identifiers:**
- MD5: `f91ff1bb5699524524fff0e2587af040`
- SHA256: `158f61b6d10ea2ce78769703a2ffbba9c08f0172e37013de960d9efe5e9fde14`

**Confidence Level:** CONFIRMED (file analysis and hijacking patterns)

**Link to Full Report:** [./nethost-dll.md](./nethost-dll.md)

---

#### 7. [chromelevator.exe - Browser Credential Theft](./chromelevator-exe.md)

**Component Type:** Credential Harvesting Tool

**Technical Summary:** Uses reflective DLL injection and direct syscalls to extract cookies, passwords, and payment data from Chrome, Edge, and Brave credential stores. Direct syscalls bypass EDR hooks that would normally flag credential-store access. Stolen credentials enable lateral movement without additional exploitation.

**File Identifiers:**
- MD5: `bc376c951eacb36bf0909a43588e6444`
- SHA256: `92c4f4b7748f23d6dcd5af43595f34e4bb8e284a85d2c1647b189c1bb59a784a`

**Confidence Level:** CONFIRMED (static analysis and behavioral observation)

**Link to Full Report:** [./chromelevator-exe.md](./chromelevator-exe.md)

---

### PHASE 3: IMPACT - RANSOMWARE DEPLOYMENT

#### 8. [enc_c2.exe - Rust Ransomware with Tor C2](./enc_c2-exe.md)

**Component Type:** Ransomware Encryptor (Remote-Controlled Variant)

**Technical Summary:** Rust ransomware with real-time Tor-based C2 control and ChaCha20 file encryption. Builder ID tracking in the binary enables RaaS affiliate attribution. The Tor C2 channel lets the operator monitor encryption progress and coordinate ransom negotiation; network-level blocking of the C2 IP is ineffective against Tor hidden services.

**File Identifiers:**
- MD5: `32a3497e57604e1037f1ff9993a8fdaa`
- SHA256: `613d4d0f1612686742889e834ebc9ebff6ae021cf81a4c50f66369195ca01899`

**Confidence Level:** CONFIRMED (Rust code analysis and C2 communication)

**Link to Full Report:** [./enc_c2-exe.md](./enc_c2-exe.md)

---

#### 9. [new_enc.exe - Human-Operated Rust Ransomware (v0.5-beta)](./new_enc-exe.md)

**Component Type:** Advanced Ransomware Encryptor

**Technical Summary:** Rust ransomware (v0.5-beta) targeting Veritas Backup Exec agents and VSS snapshots with a hardcoded ChaCha20 key (67e6096a...). The hardcoded key is an operational security lapse: files encrypted by this test variant are potentially decryptable without ransom payment. The v0.5-beta designation and backup-targeting logic confirm a development iteration, not a deployment-ready build. Operational deployments use enc_c2.exe or full_test_enc.exe instead.

**File Identifiers:**
- MD5: `a16ba61114fa5a40afce54459bbff21e`
- SHA256: `90d223b70448d68f7f48397df6a9e57de3a6b389d5d8dc0896be633ca95720f2`

**Confidence Level:** CONFIRMED (binary analysis confirms hardcoded key and targeting logic)

**Link to Full Report:** [./new_enc-exe.md](./new_enc-exe.md)

---

#### 10. [dec_fixed.exe - Ransomware Decryptor](./dec_fixed-exe.md)

**Component Type:** Victim-Specific Decryption Tool

**Technical Summary:** Victim-specific decryptor carrying a key (1e0d8597...) distinct from all other Arsenal-237 samples — CONFIRMED evidence of per-victim key management. The per-victim key model is the operational signature of a RaaS platform: it enables affiliate tracking, victim-specific negotiations, and decryption licensing control.

**File Identifiers:**
- MD5: `7c5493a0a5df52682a5c2ba433634601`
- SHA256: `d73c4f127c5c0a7f9bf0f398e95dd55c7e8f6f6a5783c8cb314bd99c2d1c9802`

**Confidence Level:** CONFIRMED (key analysis and decryption verification)

**Link to Full Report:** [./dec_fixed-exe.md](./dec_fixed-exe.md)

---

#### 11. [full_test_enc.exe - Advanced Rust Ransomware (RSA+ChaCha20)](./full_test_enc-exe.md)

**Component Type:** Enterprise-Grade Ransomware Encryptor

**Technical Summary:** The most capable Arsenal-237 variant recovered. Deploys multi-threaded hybrid encryption (RSA-OAEP + ChaCha20) across all accessible drives and network shares without C2 dependence. RSA-OAEP wraps each file's ChaCha20 symmetric key with the operator's public key; only the operator's RSA private key can recover it. Brute-force is cryptographically infeasible. Recovery without the operator's private key or unencrypted offline backups is not possible. Binary size: 15.5 MB (bundled cryptographic libraries).

**File Identifiers:**
- MD5: `1fe8b9a14f9f8435c5fb5156bcbc174e`
- SHA256: `4d1fe7b54a0ce9ce2082c167b662ec138b890e3f305e67bdc13a5e9a24708518`

**Confidence Level:** CONFIRMED (cryptographic analysis and hybrid encryption verification)

**Link to Full Report:** [./full_test_enc-exe.md](./full_test_enc-exe.md)

---

## Attack Chain Integration

### How Components Work Together: A Complete Attack Scenario

Arsenal-237 executes in four sequential stages, each enabled by the previous.

**STAGE 1: Initial Access (pre-toolkit)**
The attacker gains an initial foothold (phishing, RDP, supply chain) with user-level privileges.

**STAGE 2: Defense Evasion**
1. **lpe.exe** escalates to NT AUTHORITY\SYSTEM
2. BdApiUtil64.sys loads via the BYOVD technique, granting kernel-mode execution
3. **rootkit.dll** hides malware processes, threads, and drivers from user-mode tools
4. **killer.dll** or **killer_crowdstrike.dll** terminates security products via IOCTL 0x800024B4

**STAGE 3: Persistence and Credential Access**
1. **nethost.dll** establishes DLL-hijacking persistence in legitimate .NET processes
2. **chromelevator.exe** extracts cookies, passwords, and payment data from Chrome, Edge, and Brave

**STAGE 4: Ransomware Deployment**
1. **enc_c2.exe** (Tor-based variant) or **new_enc.exe** / **full_test_enc.exe** begins file encryption
2. Backups, databases, and documents across all accessible drives and network shares are encrypted
3. **dec_fixed.exe** is issued to the victim only after ransom payment

### Multi-Phase Attack Characteristics

| **Phase** | **Objective** | **Components** | **Success Criteria** |
|---|---|---|---|
| **Phase 1** | Establish control, disable defenses | killer.dll, lpe.exe, BdApiUtil64.sys, rootkit.dll | Security products disabled, malware hidden |
| **Phase 2** | Persist and gather intelligence | nethost.dll, chromelevator.exe | Credentials stolen, persistence established |
| **Phase 3** | Execute impact and extort | enc_c2.exe, new_enc.exe, full_test_enc.exe, dec_fixed.exe | Data encrypted, ransom demand leverage |

### Operational Maturity Indicators

Seven observed characteristics mark Arsenal-237 as a mature, professionally developed operation:

1. **Modular design** — components deploy independently and compose into a full kill chain
2. **Product-specific variants** — killer_crowdstrike.dll targets CSFalconService.exe and csagent.exe by name, confirming prior EDR research
3. **Hybrid cryptography** — RSA-OAEP + ChaCha20 in full_test_enc.exe reflects expert cryptographic implementation
4. **Rust across the ransomware tier** — a consistent modern language choice across enc_c2.exe, new_enc.exe, and full_test_enc.exe
5. **Per-victim key management** — dec_fixed.exe carries a key (1e0d8597...) distinct from all encryptors, proving the RaaS model (CONFIRMED)
6. **Active beta iteration** — v0.5-beta designation in new_enc.exe and "test" designation in full_test_enc.exe show iterative pre-deployment testing
7. **Hardcoded keys in test variants only** — the operational security lapse in new_enc.exe is absent from enc_c2.exe and full_test_enc.exe, indicating intentional separation of test and deployment builds

---

## Threat Intelligence Summary

### Arsenal-237 Attribution Context

**Threat Tier:** Professional ransomware operation — likely RaaS provider

**Operational Model:** HIGH confidence — Ransomware-as-a-Service (RaaS). Evidence: per-victim key architecture in dec_fixed.exe enables affiliate tracking; builder ID in enc_c2.exe ties builds to affiliates; multiple scenario-specific variants support flexible affiliate deployment.

**Geographic Origin:** INSUFFICIENT — Rust implementation and English-language strings are common globally and do not support geographic attribution. The Tor-based C2 in enc_c2.exe intentionally obscures the developer's location.

**Threat Activity Timeline:** MODERATE — Active development underway. Multiple test/beta variants (new_enc.exe v0.5-beta, full_test_enc.exe test version) confirm an active pre-deployment testing phase; operational campaigns appear imminent or recently initiated.

### Infrastructure Assessment

**C2 Infrastructure:** Tor-based (enc_c2.exe) — CONFIRMED by observed beaconing. MODERATE confidence that multiple hidden service addresses provide redundancy; this architecture defeats ISP- and network-level blocking.

**Hosting Model:** MODERATE — Infrastructure resilience indicators suggest abuse-tolerant hosting, consistent with standard RaaS operational practice.

---

## Strategic Defensive Recommendations

### For Executive Leadership

Arsenal-237 encrypts critical data with cryptography that cannot be broken, disables security products before encryption begins, persists through cleanup attempts, enables lateral movement, and provides ransom leverage through credible threat of permanent data loss.

**Recommended Strategic Actions:**

1. **Treat this as a business continuity risk** — Arsenal-237 is an operational attack platform, not a single malware variant. Response requires cross-functional coordination between security, legal, and business leadership.

2. **Prioritize offline backup capability** — if Arsenal-237 encrypts data, offline backups are the only recovery path that does not require ransom payment. Air-gapped or immutable-snapshot backup infrastructure must be isolated from production networks. Validate recovery procedures regularly.

3. **Validate the incident response plan** — IR plans should address ransomware-specific scenarios, define escalation authority, and include tabletop exercises that test decision-making under time pressure.

4. **Review cyber insurance coverage** — confirm coverage addresses ransomware response, forensic investigation, and extortion threats.

5. **Prepare stakeholder communication plans** — a successful Arsenal-237 deployment triggers breach-notification obligations under applicable data protection regulations. Coordinate legal, PR, and compliance postures before an incident, not during one.

### For Security Leadership & CISOs

**Defensive Priority Framework:**

**Priority 1: Detection and Prevention**
- Behavioral EDR with kernel-mode visibility
- Network-level detection for Tor traffic
- Process injection monitoring (CreateRemoteThread, QueueUserAPC)
- Privileged process elevation monitoring (lpe.exe activity)

**Priority 2: Threat Hunting (Assume Breach)**
- Hunt for BYOVD exploitation attempts (BdApiUtil64.sys loading)
- Monitor for driver loading from non-system locations
- Hunt for security product termination behavior
- Detect DLL hijacking (nethost.dll outside expected system paths)

**Priority 3: Isolation and Containment**
- Network isolation of affected systems
- Credential rotation for compromised accounts
- C2 blocking at network perimeter
- Forensic evidence preservation before remediation

**Priority 4: Recovery Readiness**
- Validated offline backup and recovery procedures
- System rebuild runbooks pre-staged
- Critical data and system prioritization for recovery ordering
- Business continuity for critical functions identified in advance

### For Security Operations Center (SOC) Teams

Individual component reports contain specific YARA signatures, Sigma rules, and hunting queries. Key detection areas:

1. **BYOVD detection** (Phase 1, components 3-4) — monitor BdApiUtil64.sys loading; alert on kernel driver installation from non-system locations; track lpe.exe execution patterns

2. **Security product termination** (Phase 1, components 1-2) — detect kernel-mode process termination targeting EDR/antivirus processes; flag IOCTL 0x800024B4 dispatch

3. **Persistence indicators** (Phase 2, components 6-7) — detect nethost.dll in user-writable locations; monitor .NET processes loading unexpected DLLs; hunt for reflective DLL injection by chromelevator.exe

4. **Ransomware behavior** (Phase 3, components 8-11) — alert on high-entropy bulk writes, file extension changes, and backup system read-ahead patterns; detect Tor traffic from non-Tor-user systems (enc_c2.exe C2)

**Detection-to-response priorities:**

- **killer.dll / killer_crowdstrike.dll detected** → isolate immediately; treat as Phase 1 chain in progress; begin forensic preservation
- **lpe.exe or BYOVD activity detected** → assume kernel-level access; standard user-mode tools are inadequate; plan for system rebuild rather than cleanup
- **chromelevator.exe or credential-access indicators detected** → credential rotation for affected accounts; expand hunt for lateral movement
- **File encryption behavior detected** → isolate immediately; preserve encrypted files for forensic analysis before any decryption attempt; identify offline backups

### For Threat Hunting Teams

**Hunt Scenarios:**

1. **BYOVD exploitation** — BdApiUtil64.sys loading from non-system paths; kernel callback registrations from unsigned or low-reputation drivers ([BdApiUtil64-sys.md](./BdApiUtil64-sys.md))

2. **Rootkit persistence** — process and thread enumeration gaps indicating hidden objects; kernel API hooking anomalies; driver installation from unexpected locations ([rootkit-dll.md](./rootkit-dll.md))

3. **DLL hijacking** — nethost.dll present outside system directories; .NET processes loading DLLs from user-writable paths; anomalous DLL version signatures ([nethost-dll.md](./nethost-dll.md))

4. **Browser credential theft** — reflective DLL injection into browser processes; SQLite reads of Chrome/Edge credential stores via direct syscalls ([chromelevator-exe.md](./chromelevator-exe.md))

5. **Ransomware encryption** — bulk file access with high-entropy writes; file extension changes; backup system enumeration patterns (Phase 3 component reports)

---

## FAQ - Addressing Common Questions

### Technical Questions

**Q1: "How is Arsenal-237 different from other ransomware families?"**

Arsenal-237 is a complete operational attack platform, not a ransomware-only tool. Most ransomware families focus on encryption. Arsenal-237 adds a kernel-mode rootkit (rootkit.dll) that operates below standard security tools, hiding malware from user-mode detection and making cleanup inadequate — affected systems require a full rebuild rather than a scan-and-remove approach.

The operational sequence distinguishes Arsenal-237 further: security products are terminated before encryption begins, persistence survives reboots via DLL hijacking, and credentials are stolen for lateral movement before the ransomware stage. This makes it an end-to-end compromise platform rather than a standalone encryptor.

---

**Q2: "Can we decrypt files encrypted with full_test_enc.exe?"**

No. full_test_enc.exe uses RSA-OAEP + ChaCha20 hybrid encryption: each file's ChaCha20 symmetric key is wrapped with the operator's RSA public key. Decryption requires the operator's RSA private key, which only the attacker holds. Brute-force is cryptographically infeasible (2^256 key space). External decryption services cannot help.

Recovery paths without the private key: offline backups, or law enforcement obtaining the key (uncommon). Ransom payment in exchange for dec_fixed.exe is the only other route.

---

**Q3: "Does the hardcoded key in new_enc.exe mean we can decrypt those files?"**

Possibly — but only if the attack used new_enc.exe specifically. The hardcoded ChaCha20 key (67e6096a...) is a test-variant operational security lapse: files encrypted by this build may be decryptable without ransom payment.

Important caveats: new_enc.exe is a v0.5-beta development build. Operational deployments likely use enc_c2.exe or full_test_enc.exe, which do not have hardcoded keys. Forensic analysis of encrypted files can confirm which variant was used — early-stage testing may have involved the beta build, but later deployments almost certainly did not.

---

**Q4: "What is RaaS (Ransomware-as-a-Service) and why does it matter?"**

RaaS is a criminal services model: a core developer builds and maintains the ransomware platform; affiliates access it to conduct attacks; the core developer takes a share of each ransom payment. Each victim receives unique encryption keys tied to that affiliate's deployment.

Arsenal-237's RaaS evidence: per-victim key architecture in dec_fixed.exe (key 1e0d8597... differs from all encryptors), and builder ID tracking in enc_c2.exe enabling per-affiliate attribution.

For defenders, RaaS means: multiple affiliates with varied targeting patterns; per-victim keys ensuring ransom payment is the only decryption path outside offline recovery; and sustainable revenue driving continuous platform development.

---

**Q5: "The reports mention 'test builds' — does this mean the threat isn't real yet?"**

No. Test builds indicate active development and imminent or recent operational deployment, not that the threat is theoretical. The v0.5-beta designation on new_enc.exe and "test version" on full_test_enc.exe confirm the toolkit is under active iteration. Multiple variants under simultaneous development suggest an operational timeline measured in weeks to months, not years. The threat is active (MODERATE confidence).

---

### Operational Questions

**Q6: "What should we do immediately if we detect Arsenal-237?"**

Immediate priorities on any Arsenal-237 detection: network isolation of affected systems, credential rotation for affected accounts, forensic preservation before remediation, and threat hunting across the environment for lateral movement indicators. Assume the worst-case phase (ransomware deployed) until investigation rules it out. See individual component reports for component-specific detection guidance and the [Incident Response Procedures](#incident-response-procedures) section below for the response priority framework.

---

**Q7: "Should we rebuild systems or attempt cleanup if Arsenal-237 is detected?"**

Rebuild. rootkit.dll operates at the kernel level and hides itself from user-mode tools — cleanup cannot verify the rootkit was fully removed. Standard scan-and-remove approaches are inadequate for kernel-mode malware. A system rebuild from clean media is the only reliable remediation path for any system where Phase 1 components (rootkit.dll, BYOVD exploitation) are confirmed.

---

**Q8: "How long will it take to recover from an Arsenal-237 attack?"**

Recovery time depends on backup strategy and ransomware variant. With validated offline backups, recovery follows a rebuild-then-restore sequence whose duration scales with environment size and data volume. Without offline backups, options reduce to ransom payment for the decryption key or data loss. The offline backup strategy is the single largest determinant of recovery speed and outcome.

---

**Q9: "What is 'offline backup' and how do we implement it?"**

Offline backup means storage that is not accessible from the production network and therefore cannot be encrypted by ransomware. Arsenal-237's new_enc.exe specifically targets Veritas Backup Exec agents and VSS snapshots, confirming that network-connected backup infrastructure is within the attack scope.

Two categories of offline backup offer protection:

1. **Air-gapped storage** — backup writes to external media that is physically disconnected after each job. Ransomware cannot reach storage that has no network path to it.

2. **Immutable cloud snapshots** — cloud-provider snapshot policies that prevent modification or deletion after creation. Requires proper permission segregation so ransomware cannot reach backup management APIs.

Both strategies require periodic recovery testing to confirm the backups are actually usable. An untested backup strategy is not a recovery strategy.

---

**Q10: "Can we detect Arsenal-237 before the ransomware phase?"**

Yes — detection opportunities exist at every phase. Phase 1 offers the best window: BYOVD exploitation, kernel driver loading from non-system paths, privilege escalation activity, and security product termination are all observable with kernel-mode EDR visibility. Phase 2 offers DLL hijacking indicators and credential store access patterns. Phase 3 — file encryption and Tor C2 traffic — is the last opportunity before data loss.

Detection before Phase 3 depends on behavioral EDR with kernel-mode visibility, active threat hunting, and network monitoring for Tor traffic. Mature detection programs will identify Arsenal-237 at Phase 1 or Phase 2 (HIGH confidence).

---

### Business/Risk Questions

**Q11: "What is the business risk if we're attacked with Arsenal-237?"**

A successful Arsenal-237 deployment affects organizations across four impact dimensions:

1. **Ransom payment risk** — per-victim key architecture means ransom is the only decryption path without offline backups; the negotiated amount scales with organizational size and sector
2. **Incident response burden** — forensic investigation, legal/compliance consultation, and breach notification require specialized resources and extended timelines
3. **Operational disruption** — recovery from a full-kit deployment requires system rebuilds across affected infrastructure, with downtime duration proportional to environment size and backup posture
4. **Regulatory and reputational consequences** — a successful deployment triggers breach-notification obligations under applicable data protection frameworks; contractual and regulatory consequences follow from confirmed data exposure

The offline backup strategy is the largest single variable in business impact: organizations with validated offline backups can rebuild and restore; those without face the ransom payment decision.

---

## Key Takeaways

**1. Arsenal-237 is an operational attack platform, not a standalone encryptor.**
It coordinates privilege escalation, kernel-mode defense disablement, persistence, credential theft, and ransomware across 11 components. Standard single-layer remediation and signature-based detection are insufficient against a toolkit built to disable those defenses before impact begins.

---

**2. Offline backups are the only reliable recovery path.**
full_test_enc.exe's RSA-OAEP + ChaCha20 hybrid encryption cannot be broken without the operator's private key. No external decryption service can help. Without validated offline backups, affected organizations face the ransom payment decision — with no third alternative. Backup strategy is the dominant variable in recovery outcome.

---

**3. Detection at Phase 1 or Phase 2 prevents encryption.**
Arsenal-237 exposes observable indicators at every phase. BYOVD exploitation, kernel driver loading, security product termination, and DLL hijacking are all detectable with behavioral EDR and kernel-mode visibility — hours to days before the ransomware stage. Detection programs that catch Phase 1 or Phase 2 activity avoid the data loss scenario entirely.

---

**4. Targeted industries face elevated risk.**
Enterprise backup targeting (new_enc.exe hitting Veritas Backup Exec and VSS), a CrowdStrike-specific EDR terminator, and per-victim key management all indicate Arsenal-237 is designed for environments where ransomware disruption translates to maximum leverage: healthcare, financial services, manufacturing, and large enterprises. Organizations in these sectors should prioritize Arsenal-237 in their threat models.

---

**5. Technical compensating controls are non-negotiable.**
BYOVD techniques abuse legitimately signed drivers that bypass signature-based detection. chromelevator.exe uses direct syscalls to defeat EDR hooks. rootkit.dll hides from user-mode tools entirely. User training addresses only one attack vector. Defense-in-depth — behavioral EDR, kernel-mode visibility, threat hunting, and network monitoring — is the required baseline against this toolkit.

---

## Confidence Levels Summary

### Findings Organized by Confidence Level

**CONFIRMED / DEFINITE (Direct observation)**

- Arsenal-237 toolkit contains 11 distinct malware components
- BYOVD exploitation using BdApiUtil64.sys confirmed
- rootkit.dll hides processes, threads, and drivers at the kernel level
- full_test_enc.exe uses RSA-OAEP + ChaCha20 hybrid encryption — decryption without the operator's private key is not possible
- new_enc.exe contains a hardcoded ChaCha20 key (67e6096a...) — a test-variant operational security lapse
- dec_fixed.exe carries a distinct key (1e0d8597...) confirming per-victim key management
- enc_c2.exe beacons to Tor C2 infrastructure
- Rust implementation across enc_c2.exe, new_enc.exe, and full_test_enc.exe
- killer.dll and killer_crowdstrike.dll terminate security products via kernel-mode IOCTL
- nethost.dll establishes persistence via DLL hijacking

**HIGH confidence (Strong corroborating evidence)**

- Arsenal-237 operates as a RaaS platform — per-victim key architecture and builder ID tracking in enc_c2.exe both support this
- Active development underway: v0.5-beta and test-version designations confirm a pre-deployment iteration cycle
- killer_crowdstrike.dll's product-specific targeting of CSFalconService.exe and csagent.exe indicates prior EDR research

**MODERATE confidence (Reasonable inference)**

- Multiple affiliates deploying the platform in decentralized campaigns
- Enterprise organizations are primary targets — backup targeting in new_enc.exe and CrowdStrike-specific disabler both align with high-value enterprise environments
- Tor infrastructure suggests sustained operations, not a single campaign
- Operational deployment timeline: weeks to months from report date

**LOW confidence (Analytical judgment, insufficient evidence)**

- Attribution to a specific named threat actor group — INSUFFICIENT evidence across this sample set
- Development team size estimation — not determinable from current evidence

---

## Incident Response Procedures

### If Arsenal-237 Has Been Detected (CONFIRMED Infection)

**Immediate actions (any component detected):**
- Network isolation of affected systems before any other action
- Credential rotation for accounts on affected systems
- Forensic preservation — do not reboot; begin memory and disk imaging
- Block identified C2 infrastructure at network perimeter
- Activate incident response procedures

**Investigation priorities:**
- Determine which Arsenal-237 phase is present (Phase 1, 2, or 3)
- Scope lateral movement: search for other systems with the same attack patterns or affected user accounts
- If Phase 3 detected: do not attempt decryption; preserve encrypted files for forensic analysis
- Hunt for Phase 1 and Phase 2 indicators across the environment in parallel

**Containment:**
- Isolate affected systems and disable compromised accounts
- Hunt for BYOVD indicators, kernel driver loading from non-system paths, DLL hijacking in .NET processes, and Tor traffic
- Forensic imaging of affected systems before remediation begins

**Remediation decision:**
- Any system where Phase 1 components (rootkit.dll, BYOVD) are confirmed requires a full system rebuild. Cleanup is not reliable for kernel-mode malware.
- If Phase 3 is active: isolate backup systems immediately to prevent encryption spread; initiate restoration from offline backups.

| Factor | Rebuild | Cleanup |
|---|---|---|
| Kernel-mode rootkit confirmed | Mandatory | Inadequate — rootkit hides itself from cleanup tools |
| Phase 3 ransomware detected | Preferred | Higher risk; only if no rootkit confirmed |
| Offline backups available | Rebuild + restore | Parallel option |
| No backups available | Still recommended | Only option outside ransom payment |

---

## Related Resources & Further Reading

### Individual Component Reports

Access detailed technical analysis for each toolkit component:

1. **Phase 1 - Defense Evasion Components:**
   - [killer.dll - Basic BYOVD Process Termination](./killer-dll.md)
   - [killer_crowdstrike.dll - CrowdStrike-Specific Termination](./killer_crowdstrike-dll.md)
   - [lpe.exe - Privilege Escalation Wrapper](./lpe-exe.md)
   - [BdApiUtil64.sys - Vulnerable Baidu Driver](./BdApiUtil64-sys.md)
   - [rootkit.dll - Kernel-Mode Rootkit](./rootkit-dll.md)

2. **Phase 2 - Persistence & Credential Access Components:**
   - [nethost.dll - DLL Hijacking Persistence](./nethost-dll.md)
   - [chromelevator.exe - Browser Credential Theft](./chromelevator-exe.md)

3. **Phase 3 - Ransomware Components:**
   - [enc_c2.exe - Tor C2 Ransomware](./enc_c2-exe.md)
   - [new_enc.exe - Rust Ransomware v0.5-beta](./new_enc-exe.md)
   - [dec_fixed.exe - Ransomware Decryptor](./dec_fixed-exe.md)
   - [full_test_enc.exe - Advanced RSA+ChaCha20 Ransomware](./full_test_enc-exe.md)

### Detection & Hunting Resources

- **IOC Feeds:** See individual component reports for file hashes, C2 infrastructure, and behavioral indicators
- **YARA Rules:** See individual component reports for malware detection signatures
- **Hunting Queries:** See individual component reports for SIEM/EDR hunting procedures
- **Network Signatures:** See individual component reports for Suricata/Snort rules

### External References

- **MITRE ATT&CK:** Framework for mapping Arsenal-237 techniques to standard threat categories
  - Privilege Escalation (T1134, T1543)
  - Persistence (T1547, T1574, T1547.014)
  - Credential Access (T1555, T1040)
  - Impact (T1486, T1491)

- **Ransomware-as-a-Service Research:**
  - Provides context for Arsenal-237's operational model
  - Documents typical RaaS platform architecture and affiliate structures

---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.
