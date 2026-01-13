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
- [Arsenal-237: agent.exe (PoetRAT)](agent-exe.md)
- [Arsenal-237: agent_xworm.exe (XWorm RAT v6)](agent-xworm-exe.md)
- [Arsenal-237: agent_xworm_v2.exe (XWorm RAT v2.4.0)](agent-xworm-v2-exe.md)
- [Arsenal-237: FleetAgentAdvanced.exe](fleetagentadvanced-exe.md)
- [Arsenal-237: FleetAgentFUD.exe](fleetagentfud-exe.md)
- [Arsenal-237: uac_test.exe](uac-test-exe.md)
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
