---
title: Report Templates
layout: page
permalink: /report-templates/
position: 5
---

# Report Templates

---

## 📌 Purpose
This section provides a **standardized template** for creating new reports in *The Hunter’s Ledger*.  
All reports can follow this format to ensure consistency, reproducibility, and presentation. Feel free to contribute your own report templates!

---

## 📝 Report Structure

### Executive Summary
High‑level overview for quick triage.

### Technical Details
- File structure analysis (PE headers, offsets, payloads)
- Reverse engineering notes (entry points, obfuscation, persistence)
- Behavior observed (networking, privilege escalation, anti‑analysis)
- MITRE ATT&CK mapping to observed behaviors

### IOCs
| Type   | Value                   |
|--------|-------------------------|
| SHA256 | abc123...               |
| Domain | malicious-example[.]com |
| IP     | 192.168.1.50            |

### Detection Opportunities
- Sigma/YARA rules
- Splunk/Elastic queries

---

## ⚡ Usage
- Copy this template into a new folder under `/reports/` (e.g., `/reports/malware-sample-1/`).
- Replace placeholder content with your actual findings.
- Add cross‑links to related IOC feeds and detections.

---

## 📜 License
- Reports are © 2025 Joseph. All rights reserved.
- Free to read, but reuse requires written permission.
