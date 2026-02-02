---
title: Hunting Detections
layout: page
permalink: /hunting-detections/
position: 3
---

# Overview
This section contains detection logic for SIEM/EDR platforms, including Sigma and YARA rules.  
Rules are mapped to MITRE ATT&CK techniques for triage and hunting.

---

## Available Detections

### Arsenal-237: Original Analysis (16 samples)
- [Arsenal-237: agent.exe (PoetRAT)](agent-exe.md)
- [Arsenal-237: agent_xworm.exe (XWorm RAT v6)](agent-xworm-exe.md)
- [Arsenal-237: agent_xworm_v2.exe (XWorm RAT v2.4.0)](agent-xworm-v2-exe.md)
- [Arsenal-237: FleetAgentAdvanced.exe](fleetagentadvanced-exe.md)
- [Arsenal-237: FleetAgentFUD.exe](fleetagentfud-exe.md)
- [Arsenal-237: uac_test.exe](uac-test-exe.md)
- [Arsenal-237: enc/dec Ransomware Family](enc-dec-ransomware-family.md)

### Arsenal-237: New Files - Advanced Toolkit (11 samples)
- [Arsenal-237 New Files: killer.dll (BYOVD Process Termination)](arsenal-237-killer-dll.md)
- [Arsenal-237 New Files: killer_crowdstrike.dll (CrowdStrike-Specific Termination)](arsenal-237-killer-crowdstrike-dll.md)
- [Arsenal-237 New Files: lpe.exe (Privilege Escalation)](arsenal-237-lpe-exe.md)
- [Arsenal-237 New Files: BdApiUtil64.sys (Vulnerable Baidu Driver)](arsenal-237-BdApiUtil64-sys.md)
- [Arsenal-237 New Files: rootkit.dll (Kernel-Mode Rootkit)](arsenal-237-rootkit-dll.md)
- [Arsenal-237 New Files: nethost.dll (DLL Hijacking Persistence)](arsenal-237-nethost-dll.md)
- [Arsenal-237 New Files: chromelevator.exe (Browser Credential Theft)](arsenal-237-chromelevator-exe.md)
- [Arsenal-237 New Files: enc_c2.exe (Rust Ransomware with Tor C2)](arsenal-237-enc_c2-exe.md)
- [Arsenal-237 New Files: new_enc.exe (Human-Operated Rust Ransomware)](arsenal-237-new_enc-exe.md)
- [Arsenal-237 New Files: dec_fixed.exe (Ransomware Decryptor)](arsenal-237-dec_fixed-exe.md)
- [Arsenal-237 New Files: full_test_enc.exe (Advanced Rust Ransomware)](arsenal-237-full_test_enc-exe.md)

### Other Threat Intelligence Reports
- [NsMiner Cryptojacker - Detection Rules](nsminer-cryptojacker.md)
- [Detection Rules - Dual-RAT Analysis: Pulsar RAT vs. NjRAT/XWorm](dual-rat-analysis.md)
- [Detection Rules - PULSAR RAT (server.exe)](PULSAR-RAT.md)
- [Hybrid Loader/Stealer Ecosystem Masquerading as Sogou](Hybrid-Loader-Stealer-Sogou.md)
- [Houselet.exe - The Go-Based Loader Masquerading as PlayStation Remote Play](malware-analysis-houselet.md)
- [AdvancedRouterScanner](AdvancedRouterScanner.md)
- [From Webshells to The Cloud](webshells-to-the-cloud.md)
- [QuasarRAT + Xworm + PowerShell Loader](quasar-xworm-detections.md)

---

## Usage
- Deploy Sigma/YARA rules in your SIEM/EDR.  
- Map detections to ATT&CK techniques for triage.  
- Adapt rules for your environment’s telemetry sources.  

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.  
Free to use in your environment, but not for commercial purposes.
