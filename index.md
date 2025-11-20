---
layout: page
permalink: /
position: 1
---

<img src="{{ "/assets/images/header.png" | relative_url }}" 
     alt="The Hunter's Ledger Banner" 
     style="width:100%; max-height:300px; object-fit:cover; display:block; margin-bottom:-5rem;">

Welcome to my repository of threat hunting, malware analysis, and reverse engineering reports.  
The goal is to present findings from my own research and hunting that are actionable for detection engineering, threat hunting, and incident response teams. Feel free to contribute or just reach out with information, questions, or suggestions!

---

## 🎯 Mission
- Share reproducible research and technical reports from my own investigations and hunting  
- Provide IOCs that can be used in threat hunting or detection engineering (Indicators of Compromise)  
- Map findings to MITRE ATT&CK techniques to assist in making findings as useful as possible to anyone  
- Publish detection logic for the threats in my reports where possible (Sigma, YARA, Splunk, etc.)  
- Above all, enable community collaboration and knowledge transfer so everyone is safer

> **Note:** This is not a collection of open source intel reports, IOCs, or TTPs.  
> These findings are from my own research and hunting as well as others that contribute, though they may overlap with known threats.  
> If you are looking for an open source collection of intel, let me know — I can help point you to sources or to learn how to make your own!

---

## 📂 Repository Structure
- [Reports](/reports/) → Detailed malware analysis and reverse engineering notes.  
  *License: All Rights Reserved — free to read, but reuse requires written permission.*

- [Hunting Detections](/hunting-detections/) → Sigma/YARA rules and detection logic for SIEM/EDR platforms.  
  *License: Creative Commons BY-NC — free to use in your environment, but not for commercial use.*

- [IOC Feeds](/ioc-feeds/) → Indicators of Compromise (hashes, domains, IPs, paths) in JSON/CSV feeds.  
  *License: Creative Commons BY-NC — free to use in your environment, but not for commercial use.*

- [Report Templates](/report-templates/) → Consistent format for reports.

---

## 📝 Report Format
Each report follows a consistent structure: [Report Templates](/report-templates/)

---

## ⚡ Usage
- Import IOC feeds into your SIEM/EDR and threat hunting workflows  
- Adapt detection logic for your environment or use them for quick hunts  
- Use ATT&CK mappings for threat modeling or attack simulation  
- Reference reverse engineering notes for deeper analysis  
- Import into your CTI platform of choice  

---

## 🤝 Contributing
Contributions are welcome!  
- Fork the repo and submit a PR with new reports, detections, or IOCs.  
- Follow the report format for consistency.  
- Or simply reach out to me and we can discuss — I can post something on your behalf as a co-author.

---

## 🔗 Resources
- [MITRE ATT&CK](https://attack.mitre.org/)  
- [Sigma Rules](https://github.com/SigmaHQ/sigma)  
- [YARA](https://virustotal.github.io/yara/)  

---

## 📜 License

### License for Reports Section
© 2025 Joseph. All rights reserved.  
The reports in [Reports](/reports/) are made publicly available for **reading and reference purposes only**.  
They may not be reproduced, redistributed, modified, or incorporated into other projects without **prior written permission** from the author.

**Permissions**
- You may view and reference the reports for personal or organizational research.  
- You may cite the reports in academic or professional work with proper attribution.  

**Restrictions**
- Redistribution of the reports in whole or in part is prohibited without written consent.  
- Commercial use, including incorporation into products, services, or paid publications, is prohibited without written consent.  
- Modification or derivative works based on these reports are prohibited without written consent.  

---

### License for Detections and IOCs Sections
The detection rules in [Hunting Detections](/hunting-detections/) and IOC feeds in [IOC Feeds](/ioc-feeds/) are licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.

**Permissions**
- You are free to use, adapt, and share the detection rules and IOC feeds for **non-commercial purposes**.  
- You must provide appropriate attribution to the author when using or adapting the work.  

**Restrictions**
**Commercial use is prohibited.** You may not sell, license, or incorporate these detections/IOCs into paid products or services without prior written permission.  
- Redistribution must include attribution and a link back to this repository.  

**Attribution**
Please credit as:  
“Threat Intelligence Reports by Joseph” (https://github.com/PixelatedContinuum/Threat-Intel-Reports/)
