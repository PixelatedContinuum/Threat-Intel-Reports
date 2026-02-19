# The Hunter's Ledger

This is a repository of original threat intelligence research — malware analysis, reverse engineering findings, detection rules, and validated IOC feeds — produced by a solo analyst and published for the broader defender community.

Every report on this site starts with hands-on analysis: sandbox runs, static examination, behavioral observation, network captures. What comes out the other end is structured, evidence-based intelligence written to be technically deep enough to trust and clear enough to act on. Not surface-level summaries, and not dense academic papers — something in between that a SOC analyst, detection engineer, or threat hunter can actually use.

---

## Mission
- Share reproducible research and technical reports from my own investigations and hunting
- Provide IOCs formatted for direct ingestion into threat hunting and detection engineering workflows
- Map findings to MITRE ATT&CK techniques to give defenders a common language for what they're looking at
- Publish detection logic — Sigma, YARA, Suricata — written to public repository submission standards
- Above all, publish findings while they're still relevant, not months after threats are already active

> **Note:** This is original research, not a collection of open-source intel reports, IOCs, or TTPs. Findings are from my own analysis, though they may overlap with known threats. Looking for an open-source collection? Reach out — I can point you in the right direction.

---

## How the Intelligence Is Produced

The reports on this site are produced using a custom-built AI-assisted workflow — a multi-agent system I researched, built, and refined over months of real analysis work. It handles the structured, repeatable parts of intelligence production so that my time stays focused on the analytical work that actually requires human judgment.

[Behind the Reports: How a Solo Analyst Uses AI Agents to Produce Timely, Trustworthy Threat Intelligence](https://pixelatedcontinuum.github.io/Threat-Intel-Reports/behind-the-reports/)

---

## About Me
- [About Me](https://pixelatedcontinuum.github.io/Threat-Intel-Reports/about-me/)

---

## Repository Structure
- [Reports](/reports) → Full threat intelligence reports: technical analysis, MITRE mapping, attribution assessment, and defender guidance
  *License: All Rights Reserved — free to read, but reuse requires written permission.*

- [Hunting Detections](/hunting-detections) → YARA, Sigma, and Suricata rules written to public repository submission standards
  *License: Creative Commons BY-NC — free to use in your environment, but not for commercial use.*

- [IOC Feeds](/ioc-feeds) → Validated indicators of compromise (hashes, domains, IPs, registry keys) in structured JSON feeds
  *License: Creative Commons BY-NC — free to use in your environment, but not for commercial use.*

---

## Usage
- Import IOC feeds directly into your SIEM, EDR, or CTI platform
- Deploy detection rules as-is or adapt them for your environment's telemetry
- Use ATT&CK mappings for threat modeling, detection gap analysis, or attack simulation
- Reference technical analysis for deeper investigation or incident context

---

## Contributing
Contributions are welcome.
- Fork the repo and submit a PR with new reports, detections, or IOCs
- Follow the report format for consistency
- Or reach out directly — I'm happy to collaborate and post on your behalf as co-author

---

## Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [YARA](https://virustotal.github.io/yara/)

---

## License

**Reports:** © 2025 Joseph. All rights reserved. Free to read and reference, but reuse requires written permission.

**Detections and IOC Feeds:** Licensed under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). Free to use in your environment, not for commercial purposes. Attribution required.

Please credit as: "Threat Intelligence Reports by Joseph" (https://github.com/PixelatedContinuum/Threat-Intel-Reports/)
