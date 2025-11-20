---
title: AdvancedRouterScanner - A Custom Python Tool for Global Router Exploitation
date: '2025-10-25'
layout: page
permalink: /reports/AdvancedRouterScanner/
hide: true
---

# 1. Executive Summary
## Key Takeaways
- This is not commodity malware, it is a custom exploitation framework with unique fingerprints, making it highly attributable.
- The campaign is global in scope, but disproportionately impacts Latin America, Southeast Asia, and parts of Africa.
- Attackers could have or soon will transition from research (PoC) to full operationalization (hub infrastructure, payload hosting, reverse shells).
- The end goal is botnet recruitment, enabling DDoS, proxy abuse, and potential resale of access.
- Immediate defensive actions include blocking known infrastructure, auditing exposed devices, and monitoring for exploitation patterns.

---

## Summary

This investigation uncovered a coordinated exploitation campaign targeting embedded network devices (Huawei/Four‑Faith and similar OEMs) through exposed CGI endpoints and weak/default credentials. The campaign demonstrates a clear progression from proof‑of‑concept (PoC) research into fully weaponized exploitation infrastructure, with evidence of both opportunistic scanning and operationalized attack hubs.

The first discovery, an open directory on 185[.]38[.]150[.]7:9999, contained a Python script (poc[.]py) named AdvancedRouterScanner. This tool is not publicly available and appears to be custom or semi‑private. It combines global opportunistic scanning with vendor‑specific exploitation logic. Its capabilities include threaded scanning, service enumeration (FTP, SSH, Telnet), vendor fingerprinting, brute forcing of default credentials, and exploitation.

The second discovery, an exposed directory on 176[.]65[.]137[.]13:80, revealed a far more mature operator hub. Artifacts including .bash_history and exploit_log.txt provided direct insight into attacker tradecraft. These scripts automated credential brute forcing, endpoint probing, and command injection via the adj_time_year parameter. Payload delivery was confirmed. This host functioned as a launchpad for mass exploitation, bridging reconnaissance into active botnet recruitment.

Enrichment of ~65,000 IPs targeted by this campaign revealed ~50,000 successfully resolved with ASN/ISP/Country metadata. The geographic distribution was heavily skewed toward Brazil (45.5%), followed by Vietnam, South Africa, Colombia, and Argentina. ASN analysis showed concentration within a handful of regional ISPs, underscoring systemic exposure in specific markets. Approximately 15,000 IPs could not be enriched, highlighting coverage gaps but also reinforcing the scale of attempted exploitation.

---

# 2. Tool Overview (poc.py)
Name: poc.py (generic filename).  
Unique Class: AdvancedRouterScanner.  
Capabilities:
- Parallel scanning with ThreadPoolExecutor.
- Service detection (HTTP/HTTPS, SSH, Telnet, FTP).
- Vendor fingerprinting via HTML keyword checks.
- Default credential brute attempts per vendor.
- Vendor‑specific endpoint probing (Huawei).  

Output:
- Results stored in results/advanced_scan_<timestamp>/results.txt.
- Format: `[HH:MM:SS] <IP>:<Port> - <Vendor/Service> - <Vulnerability>` followed by a 60‑dash separator.  

Note: This file was not found in VirusTotal and when uploaded, came back with no detections and was clean.

---

# 3. Targeting (ips.txt)
Scope: Global, ~954 KB of IPs.  
Regional Clusters:
- Southeast Asia (Vietnam, Bangladesh, India).
- Latin America (Brazil, Chile, Argentina, Mexico).
- Europe (Poland, Italy, Germany, Turkey).
- Africa (Nigeria, Kenya, Tanzania).
- North America (US broadband + AWS).  

Characteristics:
- Sequential ranges (CIDR sweeps).
- Duplicates.
- Inclusion of private IPs (10.x, 192.168.x) → sloppy aggregation.  

Assessment: Aggregated from multiple sources (scan dumps, ISP sweeps, configs). Opportunistic, not curated.

---

# 4. Results Analysis
File 1: Huawei Exploitation  
- Region: Vietnam (117.x.x.x ranges).  
- Findings: Default credentials (`admin:admin`) successful. Exposed endpoints accessible: `/api/system/execute_command`, `/web_shell_cmd.gch`, `/shell`.  
- Impact: Full remote control of routers possible.  
- Pattern: Multiple consecutive IPs vulnerable → systemic ISP misconfiguration.  

File 2: Service Enumeration  
- Regions: Vietnam, Bangladesh, India.  
- Findings: FTP (21), SSH (22), Telnet (23) open across many IPs.  
- Impact: Confirms widespread exposure of insecure services.  
- Role: Likely Stage 1 mapping before exploitation.  

Timeline Analysis  
- Scan cadence: Entries logged every 1–2 seconds → consistent threaded scanning.  
- Sequential IPs: Many consecutive IPs in 117.x.x.x exploited → confirms systemic ISP misconfiguration.  
- Stage separation: One results file shows service enumeration only, another shows Huawei exploitation → suggests modular workflow.  

---

# 5. Campaign Flow
[Aggregated IP List]  
   └─ Global ISP ranges (Asia, LATAM, EU, Africa, NA, private IPs)  

[Stage 1: Service Enumeration]  
   └─ Identify open FTP (21), SSH (22), Telnet (23)  

[Stage 2: Vendor Fingerprinting]  
   └─ Parse HTML banners for vendor keywords  

[Stage 3: Exploitation Attempts]  
   └─ Default credentials per vendor  
   └─ Huawei-specific endpoints  

[Stage 4: Results Collection]  
   └─ Results stored in results/advanced_scan_<timestamp>/results.txt  

[Stage 5: Operational Use]  
   └─ Compromised routers leveraged for botnet recruitment, proxy infrastructure, resale of access  

---

# 6. Unique Fingerprints (Pivot Anchors)
- High‑Fidelity: AdvancedRouterScanner, run_advanced_scan, advanced_scan_, telecomadmin:admintelecom, Huawei endpoint trio.  
- Medium‑Fidelity: Vendor combo (Huawei, ZTE, Raisecom), output format with 60‑dash separator.  
- Broad Discovery: Vendor names alone, generic creds.  
- Attribution Value: High — unique enough to track as a distinct campaign family.  

---

# 7. External Search Findings
- GitHub: Many unrelated poc.py files, but none with AdvancedRouterScanner or the same vendor logic.  
- Router scanning repos: Exist, but do not use the same class names, results format, or Huawei endpoint trio.  
- Huawei research repos: Confirm known defaults, but not packaged into this scanner.  
- Exploit write‑ups: Mention endpoints, but not in Python scanners.  
- Conclusion: This script is not public; it appears custom or semi‑private.  

---

# 8. Threat Assessment
- Nature: Custom/semi‑private router exploitation tool.  
- Scope: Global IP list, confirmed exploitation in Vietnam.  
- Intent: Botnet recruitment, proxy infrastructure, or resale of access.  
- Attribution Value: High.  

---

# 9. Defensive Recommendations
- ISPs: Audit router fleets for defaults and exposed endpoints.  
- Enterprises: Monitor outbound connections to unusual IPs in these ranges, especially on ports 21/22/23.  
- Defenders: Build detection rules for repeated default login attempts, flag Huawei endpoint traffic, watch for parallel outbound connections.  

---

# 10. Key Takeaways
- The poc.py script is a unique campaign artifact.  
- Combines global opportunistic scanning with vendor‑specific exploitation.  
- Results confirm Huawei routers in Vietnam were compromised.  
- Unique fingerprints (class names, results format, Huawei endpoint trio, Raisecom inclusion, rare creds) make it a high‑value pivot.  
- External searches confirm this is not commodity — if seen again, it’s almost certainly the same actor.  

---

# Enrichment and Analysis of Target IPs
Source: ~65,000 IPs.  
Enriched: ~50,000 IPs successfully resolved with ASN/ISP/Country metadata.  
Unknown: ~15,000 IPs lacked enrichment.  
Encoding issues: CSV standardized to UTF‑8; legacy Windows codepage handled with Latin1/CP1252 fallback.  

**Country Distribution**
- BR: 45.5%  
- VN: 15.1%  
- ZA: 14.2%  
- CO: 13.7%  
- AR: 11.6%  

**Top ASNs**
- AS198949 WPT Corp — 1,557  
- AS7348 Vecell Group — 1,282  
- AS1740 Comnet Limited — 987  
- AS1511 UNINET — 880  
- AS26622 T-E-S-MI — 864  
- AS12389 Rostelecom-Argentina S.A. — 562  
- AS27831 Colombia Móvil S.A. — 539  
- AS28118 BIGNET SERVICIOS DE TELECOMUNICACIONES — 513  
- AS10620 CORPORACION NACIONAL DE TELECOMUNICACIONES — 464  
- AS25773 Cato Networks Ltda — 441  

Interpretation: Concentration across specific ISPs; normalization gaps should be remediated.  

---

# Follow-Up: Certificate Pivot

PoC host now presents TLS cert Issuer CN `yuyu`, seen on only three hosts:
- 185[.]38[.]150[.]7 (PoC)
- 39[.]97[.]249[.]120 (RDP open)
- 219[.]151[.]188[.]41 (RDP open)

**Why it matters:** Shared cert + RDP exposure suggests linked infrastructure or victims.  
**Defensive actions:** Monitor for CN `yuyu`, RDP traffic, and block if observed.

---

# Additional Findings After Pivots (176[.]65[.]137[.]13)

The second exposed directory (176[.]65[.]137[.]13:80) revealed a more operationalized attacker hub compared to the PoC host.

**Key observations**
- Artifacts: `.bash_history` and `exploit_log.txt` files captured operator activity. This operator also used a similar very large IP list file as targets.
- Environment prep: Installed Python 3.11, pip, SSL libraries, and zmap.
- Scanning: Used zmap to sweep port 90, feeding results into exploit scripts.

**Exploitation**
- Targeted endpoints: `/web_shell_cmd.gch`, `/apply.cgi`, `/boaform/admin/formLogin`, `/cgi-bin/config.cgi`.
- Default credential brute forcing (`admin:admin`, `admin:password`, `admin:1234`, `root:root`, etc.).
- Injection via `adj_time_year` parameter.

**Payload delivery**
- Downloaded binaries (`boatnet.*`, `main_mpsl`) from 107[.]189[.]4[.]201 and bot[.]gribostress[.]pro.
- Reverse shell established to 107[.]189[.]4[.]201:3778.

**Exploit logs**
- Showed thousands of attempts, mostly failed (404s, resets, refused).
- Some successes indicated by HTTP 200 responses and ARM architecture detection.

**Assessment**
This host functioned as an operator hub, staging tools, scanning, and launching exploitation at scale.  
**Note:** The exploit file was not found in VirusTotal and when uploaded, came back with no detections and was clean.

---

# MITRE ATT&CK Mapping

- **Initial Access**
  - T1190 – Exploit Public-Facing Application
  - T1078 – Valid Accounts
- **Execution**
  - T1059 – Command and Scripting Interpreter
  - T1203 – Exploitation for Client Execution
- **Persistence**
  - T1547 – Boot or Logon Autostart Execution
- **Privilege Escalation**
  - T1068 – Exploitation for Privilege Escalation
- **Defense Evasion**
  - T1036 – Masquerading
- **Credential Access**
  - T1110 – Brute Force
- **Discovery**
  - T1046 – Network Service Scanning
  - T1082 – System Information Discovery
- **Lateral Movement**
  - T1021 – Remote Services
- **Command and Control**
  - T1071 – Application Layer Protocol
  - T1095 – Non-Application Layer Protocol
- **Exfiltration / Impact**
  - T1041 – Exfiltration Over C2 Channel
  - T1499 – Endpoint Denial of Service


---

## IOCs
- [AdvancedRouterScanner IOCs]({{ "/ioc-feeds/AdvancedRouterScanner.json" | relative_url }})

## Detections
- [AdvancedRouterScanner Detections]({{ "/hunting-detections/AdvancedRouterScanner/" | relative_url }})

---

# License
© 2025 Joseph. All rights reserved.  
Free to read, but reuse requires written permission.