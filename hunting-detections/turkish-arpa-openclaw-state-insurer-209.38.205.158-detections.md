---
title: "Detection Rules — Turkish ARPA Operator / AI-Augmented State-Insurer Observability Compromise + Insider Recruitment (UTA-2026-013)"
date: '2026-05-26'
layout: post
permalink: /hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
hide: true
---

**Campaign:** Turkish-ARPA-OpenClaw-State-Insurer-UTA-2026-013-209.38.205.158
**Date:** 2026-05-26
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/

> **Scope note:** This file covers **Case 2 (Turkish ARPA Operator / the victim organization)** per-case detection signatures only. Cross-campaign and cross-operator signatures are in the parent file at `/hunting-detections/ai-agent-frameworks-2026-05-23-detections/`. Do not duplicate parent-file rules here.

> **Operational sensitivity:** The insider user identifier (`[employee ID — suppressed]`) and operator residential IP (`31.223.97.87`) appear in indicators below. These are included because they are load-bearing for detection rules; they are suppressed from the public-facing report body per the disclosure-cascade protocol. Rules referencing these values should be treated as restricted-distribution until the victim-org coordination step is complete.

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 8 | T1059.001, T1059.006, T1543.002, T1552.001, T1078, T1119, T1572 | LOW–MEDIUM |
| Sigma | 12 | T1059.001, T1078, T1098.004, T1543.002, T1046, T1119, T1071.001, T1572, T1021.004, T1020 | LOW–HIGH (per rule) |
| Suricata | 6 | T1071.001, T1572, T1059.001, T1046 | LOW–MEDIUM |

**Total:** 26 rules across 3 detection layers.

**Priority breakdown:**
- HIGH priority (deploy immediately, low tuning required): 14 rules
- MEDIUM priority (deploy with environment-specific threshold tuning): 9 rules
- LOW priority (hunting / governance baseline only): 3 rules

**Coverage approach:** Rules are organized by the three campaign surfaces:
1. **Victim-side artifacts** — PowerShell collector deployed on the victim organization hosts + insider reverse-tunnel tooling
2. **Operator-side platform artifacts** — ARPA Python ETL platform, systemd service naming, AI service, Markdown ops notes
3. **Network / infrastructure layer** — C2 ingestion endpoints, DNS, SSH tunnel patterns, Instana API abuse

**Calibration note (Observability-Tool Reverse Pipeline TTP novelty):** The "Observability-Tool Reverse Pipeline" TTP (operator ingests stolen APM credentials into own analytics platform via 4 cross-correlated monitoring sources) is maintained at high-MODERATE (top of MODERATE band) novelty confidence after full prior-art review. Closest adjacent documented case (UNC6395 OAuth-based CRM breach) is structurally distinct — one-time CRM exfiltration vs. sustained 4-source observability ETL. Rules in this file that target the multi-source cross-platform authentication pattern (Sigma rule 7, Suricata rule 2) are therefore covering a TTP with no existing published detection guidance as of 2026-05-26.

**AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials (ai_service.py + ai_assistant.db pattern):** CANDIDATE novel TTP at N=1. Sigma rule 11 (AI operator NLQ egress) targets this pattern specifically. Needs N≥2 cross-operator validation before upgrading to confirmed novel TTP.

**10-year Instana JWT governance defect:** The stolen JWT (`jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3`, exp ~2034-02) is a victim-side credential management defect — this is NOT an IBM Instana CVE. Sigma rule 6 (long-lived JWT detection) is a governance baseline rule for Instana customers; IBM PSIRT coordination is a product-hardening recommendation, not a CVE-disclosure path.

---

## YARA Rules

/*
   Yara Rule Set
   Identifier: Turkish-ARPA-OpenClaw-State-Insurer-209.38.205.158
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

---

### Rule 1 — PowerShell Instana Local Collector

**Detection Priority:** HIGH
**Rationale:** Detects the victim-side PowerShell collector (`instana_local_collector.ps1`) deployed by the ARPA operator. The combination of the hardcoded the victim organization Instana tenant endpoint, the `-SkipCertificateCheck` flag, and the operator's ARPA ingestion C2 endpoint is essentially zero-FP in any environment other than the victim org — and even within the victim org, any unauthorized host running this script is a true positive.
**ATT&CK Coverage:** T1059.001 (PowerShell), T1552.001 (Credentials in Files — stolen JWT hardcoded), T1020 (Automated Exfiltration), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** NONE for the three-string combination. LOW for individual strings (ocpinstana string alone would fire on legitimate admin scripts using the same API within the victim organization).
**Deployment:** Endpoint AV/EDR on Windows hosts; PowerShell Script Block Logging pipeline; email gateway scanning for PS1 attachments.

```yara
rule MAL_PowerShell_Instana_Local_Collector_Family {
   meta:
      description = "Detects the Turkish ARPA operator's victim-side PowerShell collector that exfiltrates IBM Instana APM events from the victim organization's OCP-hosted Instana tenant to operator C2 at 209.38.205.158. Indicators: hardcoded victim Instana endpoint, stolen JWT delivery, Turkish-language operational comments, and POST to operator ARPA ingestion endpoint."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "observability-credential-harvester"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "8fd415cd-73c0-5027-b5e3-be299bbec061"
   strings:
      $victim_endpoint = "ocpinstana.[victim-domain].com.tr" ascii wide
      $operator_c2 = "api/ingest/instana" ascii wide fullword
      $skip_cert = "-SkipCertificateCheck" ascii wide fullword
      $turkish_comment = "Bu script local Windows makinede" ascii wide
      $arpa_server = "ARPA sunucusuna gonderiliyor" ascii wide
      $event_schema = "entity_type" ascii wide fullword
   condition:
      filesize < 50KB and
      $victim_endpoint and $operator_c2 and $skip_cert
}
```

---

### Rule 2 — ARPA Observability Harvester Platform

**Detection Priority:** HIGH
**Rationale:** Detects the operator-side Python ETL platform (ARPA Korelasyon Motoru). The self-branding string `ARPA Korelasyon Motoru` in combination with multi-source ingestion references and the operator's database persistence identifiers constitutes a zero-FP signature for this specific operator platform. The dashboard footer string `ARPA © 2026 the victim organization | Read-Only Compliance | Mock Data: ❌` is unique to this operator's self-branding and has zero plausible legitimate appearance.
**ATT&CK Coverage:** T1059.006 (Python), T1119 (Automated Collection), T1543.002 (Systemd Service), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** NONE for the dashboard footer verbatim. LOW for the self-branding string alone (could appear in forks of the public GitHub repo).
**Deployment:** Linux server file scanning, osquery file content checks, memory scanning on VPS infrastructure.

```yara
rule MAL_Python_ARPA_Observability_Harvester_Platform {
   meta:
      description = "Detects the Turkish ARPA operator's multi-source observability-harvester Python platform (ARPA Korelasyon Motoru). Targets the operator self-branding docstring, dashboard footer, and multi-source ingestion patterns that identify this platform across source files, SQLite stores, and HTML dashboard responses."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "observability-credential-harvester"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "6ffe1dfa-a552-578c-b83c-1330dab61d55"
   strings:
      $brand1 = "ARPA Korelasyon Motoru" ascii wide
      $brand2 = "ARPA \xC2\xA9 2026" ascii wide
      $brand3 = "Read-Only Compliance" ascii wide fullword
      $mock_data = "Mock Data: \xE2\x9D\x8C" ascii
      $db_collector = "/opt/ARPA/data/collector.db" ascii wide
      $db_ai = "ai_assistant.db" ascii wide fullword
      $corr_endpoint = "/api/correlations/" ascii wide fullword
      $topology_endpoint = "/api/topology/unified" ascii wide
   condition:
      filesize < 5MB and
      ($brand1 or $brand2) and
      ($corr_endpoint or $topology_endpoint or $db_collector)
}
```

---

### Rule 3 — Insider Tunnel-Setup Turkish-Language Operator Document

**Detection Priority:** HIGH
**Rationale:** Detects the operator-authored Turkish-language insider-recruitment tunnel-setup Markdown documents. These documents contain Turkish-language operational keywords specific to the operator's reverse-SSH-tunnel deployment campaign (PUTTY_TUNNEL_DETAY, SSH_KEY_COZUM family), operator-controlled IP references, and the insider Windows user path pattern. Finding any file matching this pattern on a corporate endpoint is a definitive true positive for insider-recruitment activity.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1098.004 (SSH Authorized Keys), T1021.004 (SSH)
**Confidence:** HIGH
**False Positive Risk:** LOW — the Turkish-language operational keywords combined with an IP address in the `209.38.205.158` range are highly specific. Risk of FP from Turkish IT staff using Turkish-language docs is LOW because the specific combination of reverse-tunnel commands + operator IP + named user path does not occur in legitimate admin workflows.
**Deployment:** Endpoint file scanning (Windows user profile directories), DLP file content inspection, email attachment scanning.

```yara
rule MAL_PSScript_Insider_TunnelSetup_Turkish {
   meta:
      description = "Detects operator-authored Turkish-language insider-recruitment tunnel-setup documents (PUTTY_TUNNEL_DETAY.md, TUNNEL_RESTART.md, SSH_KEY_COZUM.md class). Operator instructs victim-side insider (the victim organization Windows AD user [employee ID — suppressed]) how to deploy reverse SSH tunnels from inside the victim network. Keyword combination is specific to this operator campaign."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "insider-recruitment-document"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "3f787a25-bfd5-5e85-9009-0cedba0a5c1d"
   strings:
      $tk1 = "ARPA_Tunnel" ascii wide fullword
      $tk2 = "rca_key.ppk" ascii wide fullword
      $tk3 = "rca_key.pem" ascii wide fullword
      $tk4 = "209.38.205.158" ascii wide
      $tk5 = "18080:localhost:8089" ascii wide
      $tk6 = "SSH_KEY_COZUM" ascii wide
      $tk7 = "PUTTY_TUNNEL_DETAY" ascii wide
      $tk8 = "WINDOWS_VPN_TUNNEL" ascii wide
      $tk9 = "GERCEK_API_BULUNDU" ascii wide
   condition:
      filesize < 200KB and
      2 of ($tk1, $tk2, $tk3, $tk4, $tk5) and
      1 of ($tk6, $tk7, $tk8, $tk9)
}
```

---

### Rule 4 — Multi-Source Observability Polling Python Script

**Detection Priority:** HIGH
**Rationale:** Detects the operator's Python polling scripts that simultaneously target multiple observability platforms (Instana + SolarWinds + Zabbix + VMware Aria) from a single source. This combination is specific to the Observability-Tool Reverse Pipeline TTP — legitimate monitoring scripts target one platform per script; cross-source ingestion patterns in a single Python file with hardcoded victim-specific endpoints are operator-distinctive.
**ATT&CK Coverage:** T1059.006 (Python), T1046 (Network Service Discovery), T1119 (Automated Collection), T1078 (Valid Accounts — stolen credential use)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — organizations building their own cross-source monitoring integrations may have similar patterns. Reduce FP by requiring the victim-specific endpoint strings (`[victim-tenant]` tenant) in the condition; the 5-minute cadence marker and the stolen JWT jti reduce it further.
**Deployment:** Linux server file scanning, SIEM file-create alerting on `/opt/` paths.

```yara
rule MAL_Python_Instana_SolarWinds_Zabbix_VMwareAria_Polling {
   meta:
      description = "Detects Python scripts implementing multi-source observability polling targeting IBM Instana, SolarWinds Orion, Zabbix, and VMware Aria from a single codebase — the core of the Turkish ARPA operator's Observability-Tool Reverse Pipeline TTP. Hardcoded victim Instana tenant and 5-minute cadence markers identify operator-authored vs legitimate cross-monitoring tools."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "observability-credential-harvester"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "7b048278-a144-592a-ac98-b703145488ca"
   strings:
      $instana_tenant = "[victim-tenant]" ascii wide fullword
      $instana_api = "api/events?from=" ascii wide
      $zabbix_ref = "zabbix" ascii wide nocase fullword
      $solarwinds_ref = "solarwinds" ascii wide nocase fullword
      $vmware_aria = "vmware" ascii wide nocase fullword
      $cadence = "5min" ascii wide fullword
      $jwt_jti = "022a1b74-2332-4df5-a76b-60225ffa7ae3" ascii wide
      $last_fetch = "get_last_fetch_time" ascii wide fullword
   condition:
      filesize < 500KB and
      $instana_tenant and
      ($jwt_jti or ($instana_api and 2 of ($zabbix_ref, $solarwinds_ref, $vmware_aria)))
}
```

---

### Rule 5 — ARPA AI Service Natural-Language Query Interface

**Detection Priority:** MEDIUM
**Rationale:** Detects the operator's AI-augmented natural-language query interface (`ai_service.py` + `ai_assistant.db` + `data_retrieval.py` triad). This is the CANDIDATE novel TTP component — "AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials." The schema design (events table + situations table + ai_training_log table) combined with the SQLite database name `ai_assistant.db` co-located with observability data is operator-distinctive. FP risk is MEDIUM because legitimate monitoring systems may also use SQLite caches named similarly.
**ATT&CK Coverage:** T1059.006 (Python), T1213 (Data from Information Repositories)
**Confidence:** MODERATE (AI service is in broken/dev state on observed host; pattern may not have replicated to other deployments)
**False Positive Risk:** MEDIUM — `ai_assistant.db` combined with `_handle_event_query` handler dispatch is fairly distinctive; standalone database name is insufficient. Require the handler dispatch pattern plus the AI training log schema for lower FP.
**Deployment:** Linux server file scanning, osquery SQLite schema inspection.

```yara
rule MAL_Python_ARPA_AI_Service_NaturalLanguage_Query {
   meta:
      description = "Detects the Turkish ARPA operator's AI-augmented natural-language query interface over stolen observability data (ai_service.py + ai_assistant.db). Architecture: events table populated from stolen Instana monitoring data, situations table for AI root-cause analysis, ai_training_log table for conversation feedback. Candidate novel TTP: AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "ai-augmented-reconnaissance"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "bcc21a4e-4647-57ec-be62-c2c1b1d055c4"
   strings:
      $ai_db = "ai_assistant.db" ascii wide fullword
      $ai_service = "ai_service.py" ascii wide fullword
      $data_retrieval = "data_retrieval.py" ascii wide fullword
      $handler1 = "_handle_event_query" ascii wide fullword
      $handler2 = "_handle_general_query" ascii wide fullword
      $ai_training = "ai_training_log" ascii wide fullword
      $situations = "situations" ascii wide fullword
      $arpa_path = "/opt/ARPA/ai/" ascii wide
   condition:
      filesize < 500KB and
      $ai_db and
      ($handler1 or $handler2 or $ai_training) and
      ($arpa_path or $data_retrieval)
}
```

---

### Rule 6 — ARPA Cross-Source Correlation ETL Engine

**Detection Priority:** HIGH
**Rationale:** Detects the operator's cross-source correlation ETL engine (`correlation_v3.py` and variants). The self-branded docstring `ARPA Korelasyon Motoru v3 - Temporal Focus` combined with the Turkish-language operator output strings and the correlation endpoint dispatch pattern are zero-FP. The `check_corr.py` Turkish output `=== SON 5 KORELASYON ===` is operator-distinctive — no legitimate monitoring software outputs Turkish-language diagnostic labels.
**ATT&CK Coverage:** T1059.006 (Python), T1119 (Automated Collection), T1005 (Data from Local System)
**Confidence:** HIGH
**False Positive Risk:** LOW — Turkish-language operational strings combined with the version-numbered self-branding are operator-specific.
**Deployment:** Linux server file scanning, code-repository scanning for publicly exposed operator code.

```yara
rule MAL_Python_ARPA_CrossSource_Correlation_ETL {
   meta:
      description = "Detects the Turkish ARPA operator's cross-source correlation ETL engine (correlation_v3.py and variants). Operator self-branded docstring 'ARPA Korelasyon Motoru v3 - Temporal Focus', Turkish-language diagnostic output, and API endpoint dispatch patterns uniquely identify this component of the ARPA platform."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "observability-credential-harvester"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "c6216184-81e7-5bf2-bd8b-4177ed18a036"
   strings:
      $docstring = "ARPA Korelasyon Motoru v3" ascii wide
      $turkish_diag = "=== SON 5 KORELASYON ===" ascii wide
      $endpoint_dispatch = "/api/correlations/" ascii wide fullword
      $temporal = "Temporal Focus" ascii wide fullword
      $topology_fn = "topology_mapper.py" ascii wide fullword
      $extract_fn = "extract_host_from_label" ascii wide fullword
      $turkish_extract = "Service label" ascii wide
   condition:
      filesize < 2MB and
      ($docstring or $turkish_diag) and
      ($endpoint_dispatch or $topology_fn or $extract_fn)
}
```

---

### Rule 7 — ARPA Operator Ops Notes Markdown Family

**Detection Priority:** HIGH
**Rationale:** Detects the operator-authored Turkish-language operational notes (GERCEK_API_BULUNDU.md class) co-located with the operator platform. These are the documents that captured the operator celebrating the discovery of the the victim organization Instana endpoint, documenting integration steps, and referencing the public GitHub repo. The `GERCEK_API_BULUNDU` string (Turkish: "Real API Found") combined with the GitHub handle reference and victim Instana URL is a zero-FP combination outside the operator's own infrastructure.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1552.001 (Credentials in Files — API tokens documented in notes)
**Confidence:** HIGH
**False Positive Risk:** LOW — the Turkish-language celebratory discovery note combined with the Instana API reference and GitHub handle is highly operator-specific.
**Deployment:** Linux server file scanning, git repository content scanning, osquery file table on `/opt/ARPA/` and adjacent directories.

```yara
rule MAL_Markdown_ARPA_OperatorNote_Family {
   meta:
      description = "Detects Turkish ARPA operator-authored operational Markdown notes (GERCEK_API_BULUNDU.md, INSTANA_INTEGRATION_SUMMARY.md class). Operator documents the discovery of victim Instana endpoints, integration steps, and references the public MehmetARPA/ARPA GitHub repository. Turkish-language operational narrative combined with victim-specific API references is operator-distinctive."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "operator-ops-note"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "3369e5c8-06a2-5589-87c2-e26074c0dca3"
   strings:
      $gercek = "GERCEK_API_BULUNDU" ascii wide
      $github_ref = "MehmetARPA/ARPA" ascii wide
      $instana_summary = "INSTANA_INTEGRATION_SUMMARY" ascii wide
      $instana_port = "INSTANA_PORT_TEST" ascii wide
      $victim_ref = "[victim-tenant]" ascii wide nocase
      $api_token_label = "apiToken" ascii wide fullword
      $turkish_label = "Instana API Test" ascii wide
   condition:
      filesize < 200KB and
      ($gercek or $instana_summary or $github_ref) and
      ($victim_ref or $api_token_label)
}
```

---

### Rule 8 — ARPA Platform Systemd Service Units

**Detection Priority:** HIGH
**Rationale:** Detects operator-deployed systemd unit files matching the `arpa-*` naming pattern. The five unit files (`arpa-autolearn`, `arpa-continuous`, `arpa-daemon`, `arpa-instana-api`, `arpa-parallel`) form a distinctive cluster that does not appear in any other Hunt.io-indexed host over a 365-day window. Presence of any two of these unit file names in a systemd directory is an essentially zero-FP indicator of the ARPA platform deployment. Defenders can also hunt for the `[Service]\nExecStart=python3 /opt/ARPA/` pattern in unit file content.
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1569.002 (System Services: Service Execution)
**Confidence:** HIGH
**False Positive Risk:** LOW — the `arpa-*` naming cluster for this specific set of five service names does not collide with any known legitimate software's systemd service naming pattern.
**Deployment:** Linux server file scanning on `/etc/systemd/system/`, osquery systemd_units table, auditd file_create watches on systemd directories.

```yara
rule MAL_SystemdUnit_ARPA_Platform_Services {
   meta:
      description = "Detects the Turkish ARPA operator's systemd service unit files persisting the ARPA observability-harvester platform (arpa-autolearn, arpa-continuous, arpa-daemon, arpa-instana-api, arpa-parallel). Presence of this naming cluster in /etc/systemd/system/ indicates ARPA platform deployment on the target host."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/"
      date = "2026-05-26"
      family = "ARPA-observability-harvester"
      malware_type = "observability-credential-harvester"
      campaign = "Turkish-ARPA-State-Insurer-209.38.205.158"
      id = "4e1c0388-5ccf-57e5-bbfe-06500eaf6974"
   strings:
      $svc1 = "arpa-autolearn" ascii wide fullword
      $svc2 = "arpa-continuous" ascii wide fullword
      $svc3 = "arpa-daemon" ascii wide fullword
      $svc4 = "arpa-instana-api" ascii wide fullword
      $svc5 = "arpa-parallel" ascii wide fullword
      $execstart = "ExecStart=" ascii wide
      $opt_arpa = "/opt/ARPA/" ascii wide
   condition:
      filesize < 10KB and
      2 of ($svc1, $svc2, $svc3, $svc4, $svc5) and
      ($execstart or $opt_arpa)
}
```

---

## Sigma Rules

---

### Sigma Rule 1 — PowerShell Process Invoking Instana API with Stored JWT Bearer Token

**Detection Priority:** HIGH
**Rationale:** Detects PowerShell invoking the the victim organization Instana API endpoint with a stored bearer token from an unauthorized host. Within the victim org, only designated Instana admin systems should query the OCP-hosted tenant endpoint; any other Windows host doing so with `-SkipCertificateCheck` and a hardcoded `apiToken` is executing the operator's collector script or an equivalent.
**ATT&CK Coverage:** T1059.001 (PowerShell), T1552.001 (Credentials in Files), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW within the victim org if Instana API access is tightly controlled. MEDIUM in environments where multiple hosts legitimately query Instana APIs.
**Deployment:** Sysmon + PowerShell Script Block Logging (Event ID 4104); SIEM correlation across endpoint telemetry.

```yaml
title: PowerShell Instana API Call with Stored JWT Token from Unauthorized Host
id: ba31534e-e868-47fc-bfcd-4c5a4ce0b85d
status: test
description: >-
  Detects PowerShell processes invoking the Instana API endpoint for a specific OCP-hosted
  tenant with a stored JWT bearer token and certificate validation disabled (-SkipCertificateCheck).
  This pattern matches the Turkish ARPA operator's victim-side collector (instana_local_collector.ps1)
  targeting the the victim organization Instana tenant. Any host not designated as an Instana operations
  system triggering this pattern should be treated as a true positive for credential-based
  observability data exfiltration.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.execution
    - attack.collection
    - attack.exfiltration
    - attack.command-and-control
logsource:
    category: process_creation
    product: windows
detection:
    selection_ps:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_instana:
        CommandLine|contains:
            - 'ocpinstana'
            - 'api/ingest/instana'
    selection_flags:
        CommandLine|contains:
            - '-SkipCertificateCheck'
    condition: selection_ps and selection_instana and selection_flags
falsepositives:
    - Legitimate Instana operations team scripts that use -SkipCertificateCheck for OCP self-signed certificates
    - Authorized PowerShell monitoring automation targeting the same tenant endpoint
level: high
```

---

### Sigma Rule 2 — Outbound HTTPS to the victim organization Instana Tenant from Unauthorized Host

**Detection Priority:** HIGH
**Rationale:** Detects outbound HTTPS connections to the `*.ocpinstana.[victim-domain].com.tr` wildcard domain from any host NOT on the Instana operations team allow-list. The operator harvested from this endpoint using a stolen JWT; any unauthorized system making requests to this tenant endpoint is either the collector script or a novel credential-abuse scenario.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1078 (Valid Accounts — stolen credential use)
**Confidence:** HIGH
**False Positive Risk:** LOW if Instana access is restricted to designated hosts. This rule is most valuable as an egress alert on the victim org's network perimeter.
**Deployment:** Network firewall logs; proxy logs; DNS resolver logs correlated with HTTPS egress.

```yaml
title: Outbound HTTPS to the victim organization OCP Instana Tenant from Non-Admin Host
id: 024cd785-789d-4a99-8098-439f87c1df17
status: test
description: >-
  Detects outbound HTTPS connections to the the victim organization OCP-hosted Instana tenant
  wildcard domain (*.ocpinstana.[victim-domain].com.tr) from any host not designated
  as an Instana operations system. The Turkish ARPA operator harvested victim observability
  data from this endpoint using a stolen 10-year-lifetime JWT. Unauthorized hosts querying
  this domain represent active credential abuse or deployment of the operator's PowerShell
  collector script.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.collection
    - attack.credential-access
    - attack.command-and-control
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|endswith: '.ocpinstana.[victim-domain].com.tr'
        DestinationPort: 443
    condition: selection
falsepositives:
    - Designated Instana operations team hosts performing authorized API queries
    - Automated monitoring tools with legitimate access to the Instana tenant
level: high
```

---

### Sigma Rule 3 — Systemd Unit Creation Matching `arpa-*` Naming Pattern

**Detection Priority:** HIGH
**Rationale:** Detects the creation of systemd unit files matching the operator's distinctive `arpa-*` naming pattern in `/etc/systemd/system/`. All five operator-deployed service units use this prefix; no legitimate software in Hunt.io's 365-day index uses this exact naming scheme. Unit file creation in this path from a non-package-manager process is always suspicious; the `arpa-` prefix makes it operator-specific.
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1569.002 (System Services: Service Execution)
**Confidence:** HIGH
**False Positive Risk:** LOW — the `arpa-` prefix for systemd services does not conflict with known legitimate software service names.
**Deployment:** auditd `file_create` watch on `/etc/systemd/system/`; Linux EDR file event telemetry.

```yaml
title: Systemd Unit File Created with ARPA Platform Service Naming Convention
id: 4c27b8f2-a383-4cf0-a20a-21f8681231fa
status: test
description: >-
  Detects creation of systemd unit files matching the Turkish ARPA operator's distinctive
  arpa-* naming pattern in /etc/systemd/system/. The operator deployed five service units
  (arpa-autolearn, arpa-continuous, arpa-daemon, arpa-instana-api, arpa-parallel) to persist
  the ARPA observability-harvester platform across reboots. This naming pattern has not been
  observed in legitimate software in any known deployment context. File creation events matching
  this pattern on any Linux host are high-confidence indicators of ARPA platform deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.persistence
    - attack.execution
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith: '/etc/systemd/system/arpa-'
        TargetFilename|endswith: '.service'
    condition: selection
falsepositives:
    - Custom in-house monitoring software using the arpa- service name prefix (unlikely; verify with IT asset management)
    - Legitimate open-source software with arpa- prefixed services (no known examples as of 2026-05-26)
level: high
```

---

### Sigma Rule 4 — Reverse SSH Tunnel Registration from Windows AD User Host to Operator IP

**Detection Priority:** HIGH
**Rationale:** Detects the insider's reverse SSH tunnel establishment: outbound SSH from an internal Windows host with `-R 18080:localhost:8089` tunnel flags to the operator's DigitalOcean IP `209.38.205.158`. This is the defining behavioral pattern of the insider-recruitment component — an AD-joined user workstation should never initiate an SSH connection to an external VPS with reverse-forwarding flags in an enterprise environment.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH), T1098.004 (SSH Authorized Keys)
**Confidence:** HIGH
**False Positive Risk:** LOW — SSH with `-R` reverse-forwarding from an enterprise Windows workstation to an external IP is extremely uncommon in legitimate workflows. Developers using ngrok or similar legitimate tunneling services will use different tooling and endpoints.
**Deployment:** Sysmon Event ID 1 (process creation); Windows Security Event ID 4688; EDR process telemetry.

```yaml
title: Reverse SSH Tunnel Established from Windows Host to ARPA Operator Infrastructure
id: 6465d373-414d-461d-8624-11153cc64d9c
status: test
description: >-
  Detects the establishment of a reverse SSH tunnel from a victim-side Windows host to the
  Turkish ARPA operator's DigitalOcean VPS (209.38.205.158). The operator provided the
  victim-side insider (Windows AD user [employee ID — suppressed]) with SSH keys (rca_key.pem / rca_key.ppk)
  and instructions to deploy -R 18080:localhost:8089 tunnels. This gives the operator live
  network access inside the victim's perimeter. SSH with reverse-forwarding flags initiated
  from an enterprise Windows workstation to any external IP is abnormal; the specific
  operator IP makes this a definitive true positive.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection_ssh:
        Image|endswith:
            - '\ssh.exe'
            - '\putty.exe'
            - '\plink.exe'
    selection_tunnel:
        CommandLine|contains:
            - '-R 18080'
            - '18080:localhost:8089'
            - '209.38.205.158'
    selection_arpa_session:
        CommandLine|contains:
            - 'ARPA_Tunnel'
            - 'rca_key'
    condition: selection_ssh and (selection_tunnel or selection_arpa_session)
falsepositives:
    - Authorized developer tunneling tools with similar flag patterns (verify against endpoint management)
    - Legitimate reverse-tunnel software for remote support (verify endpoint ownership and destination IP)
level: critical
```

---

### Sigma Rule 5 — PuTTY Saved Session Created with Tunnel or ARPA Name

**Detection Priority:** HIGH
**Rationale:** Detects the creation of PuTTY saved sessions named `ARPA_Tunnel` or containing "Tunnel" in a context suggesting the operator's reverse-tunnel setup. The operator supplied the insider with instructions to create a PuTTY saved session named exactly `ARPA_Tunnel` pointing to `209.38.205.158`. Registry key creation by a Windows user for this session name is a definitive true positive for the insider-deployment phase.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** HIGH
**False Positive Risk:** LOW — `ARPA_Tunnel` is operator-specific. Generic "Tunnel" in PuTTY session names is MEDIUM FP risk from legitimate developer or DevOps users.
**Deployment:** Sysmon Event ID 12/13/14 (registry events); Windows Security registry audit.

```yaml
title: PuTTY Saved Session Created with ARPA Tunnel Naming Convention
id: 785967aa-4fba-4679-8209-53c0f22b0631
status: test
description: >-
  Detects creation of PuTTY saved sessions in the Windows registry with operator-distinctive
  naming patterns. The Turkish ARPA operator instructed the victim-side insider to create a
  PuTTY saved session named 'ARPA_Tunnel' targeting operator VPS 209.38.205.158 with
  operator-supplied private key (rca_key.ppk). Registry creation of a PuTTY session named
  ARPA_Tunnel or containing the operator IP is a definitive indicator of the insider
  deployment phase of this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection_putty_path:
        TargetObject|contains: '\Software\SimonTatham\PuTTY\Sessions\'
    selection_arpa_session:
        TargetObject|contains:
            - 'ARPA_Tunnel'
            - 'ARPA_tunnel'
    condition: selection_putty_path and selection_arpa_session
falsepositives:
    - Legitimate administrators creating PuTTY sessions for authorized remote management with similar names (verify session destination and key file)
level: high
```

---

### Sigma Rule 6 — Long-Lived Instana JWT Detected in Audit Logs (Governance Baseline)

**Detection Priority:** MEDIUM
**Rationale:** Governance defect detection rule. Detects the specific stolen JWT (`jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3`) used by the ARPA operator, OR any Instana API token with an expiration beyond 1 year from issuance. The 10-year-lifetime JWT is a victim-side credential management defect that allowed sustained unauthorized access over an extended window. This rule is a governance baseline — IBM PSIRT coordination is a product-hardening recommendation, not a CVE-disclosure. Note: this rule targets Instana audit log telemetry, which requires the victim org to have enabled Instana audit export.
**ATT&CK Coverage:** T1078 (Valid Accounts), T1552.001 (Credentials in Files)
**Confidence:** HIGH (for the specific stolen JWT); MODERATE (for the generic long-lived token governance pattern)
**False Positive Risk:** LOW for the specific JTI. MEDIUM for the generic long-lifetime pattern depending on how the Instana instance is configured.
**Deployment:** Instana audit log export to SIEM; IBM Instana customer portal API token review.

```yaml
title: Instana Stolen JWT or Long-Lived API Token Detected in Audit Log
id: d4398d0e-e7ea-4b8d-a838-8b2a760fc468
status: test
description: >-
  Detects use of the specific stolen the victim organization Instana JWT (jti 022a1b74) in API calls,
  or flags any Instana API token with an expiration lifetime exceeding 1 year — a governance
  defect that enabled the Turkish ARPA operator to maintain persistent access over a multi-year
  window using a single stolen credential. This is not an IBM Instana CVE; it is a victim-side
  token management defect. Sigma rule targets Instana audit log telemetry exported to SIEM.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.credential-access
    - attack.persistence
logsource:
    product: ibm_instana
    service: audit_log
detection:
    selection_stolen_jti:
        jwt_jti: '022a1b74-2332-4df5-a76b-60225ffa7ae3'
    selection_stolen_tenant:
        tenant: '[victim-tenant]'
        source_ip|not:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection_stolen_jti or selection_stolen_tenant
falsepositives:
    - Authorized Instana admin tools accessing the tenant from external IPs (verify against operations team allow-list)
    - Token rotation scripts running from external orchestration infrastructure
level: critical
```

---

### Sigma Rule 7 — Cross-Source Observability Platform Authentication from Single Source IP

**Detection Priority:** HIGH
**Rationale:** Detects the defining behavioral pattern of the Observability-Tool Reverse Pipeline TTP: the same source IP authenticating against two or more of the target's observability platforms (Instana + SolarWinds + Zabbix + VMware Aria + Datadog + Dynatrace + New Relic + Prometheus) within a short time window. Legitimate monitoring integrations do not authenticate to multiple disparate observability platforms from the same source IP simultaneously — this pattern is specific to operator-built cross-source ETL. This is the most analytically valuable rule for novel-TTP detection.
**ATT&CK Coverage:** T1078 (Valid Accounts), T1119 (Automated Collection), T1046 (Network Service Discovery)
**Confidence:** MODERATE — requires SIEM correlation across multiple observability platform audit feeds simultaneously.
**False Positive Risk:** MEDIUM — cross-platform integration tools (e.g., a legitimate SIEM collecting from multiple APM sources) may trigger this. Reduce FP by requiring the platforms to include at least one premium APM (Instana / Datadog / Dynatrace) alongside one infrastructure-monitoring tool (SolarWinds / Zabbix / Prometheus).
**Deployment:** SIEM correlation rule requiring audit log feeds from at least 2 of the listed platforms; requires observability platform audit export to be enabled.

```yaml
title: Cross-Source Observability Platform Authentication Burst from Single Source IP
id: b5756186-42bf-480c-b343-423a35d27336
status: test
description: >-
  Detects a single source IP authenticating against two or more enterprise observability
  platforms (IBM Instana, SolarWinds Orion, Zabbix, VMware Aria, Datadog, Dynatrace,
  New Relic, Prometheus) within a 10-minute window. This pattern is the defining behavioral
  signature of the Turkish ARPA operator's Observability-Tool Reverse Pipeline TTP:
  operator-built cross-source ETL platforms authenticate to each stolen monitoring source
  independently, creating a correlated authentication burst invisible to any single
  platform's audit log but detectable as a SIEM correlation across feeds. No known legitimate
  software produces this multi-platform authentication burst from a single external source.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.collection
    - attack.credential-access
    - attack.discovery
logsource:
    product: generic
    service: observability_audit
detection:
    selection_instana:
        EventSource: 'ibm_instana'
        EventType: 'api_authentication'
    selection_solarwinds:
        EventSource: 'solarwinds_orion'
        EventType: 'api_authentication'
    selection_zabbix:
        EventSource: 'zabbix'
        EventType: 'api_login'
    selection_vmware_aria:
        EventSource: 'vmware_aria'
        EventType: 'api_authentication'
    timeframe: 10m
    condition: 2 of (selection_instana, selection_solarwinds, selection_zabbix, selection_vmware_aria)
falsepositives:
    - Legitimate SIEM/SOAR platforms collecting from multiple APM sources via centralized service accounts (verify source IP against authorized integration allow-list)
    - Cross-platform monitoring dashboards with unified authentication service
level: high
```

---

### Sigma Rule 8 — Rapid Instana Topology API Enumeration from Single Source

**Detection Priority:** HIGH
**Rationale:** Detects the operator's automated Instana topology enumeration pattern: more than 10 `GET /api/events` or `/api/topology` calls per minute from a single source IP. The operator's sliding-window collector queries Instana at 10-minute intervals per invocation but drives 5-minute polling across multiple parallel workers from the operator-side ETL — creating a distinctive rapid-enumeration pattern in Instana API audit logs that differs from legitimate interactive use.
**ATT&CK Coverage:** T1046 (Network Service Discovery), T1213 (Data from Information Repositories), T1119 (Automated Collection)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — legitimate automated monitoring tools may query the same API at high frequency. Reduce FP by combining with source IP not-in-allow-list condition.
**Deployment:** Instana audit log export to SIEM; IBM Instana API analytics; rate-limiting alerts on the Instana tenant.

```yaml
title: Rapid Instana Topology API Enumeration Burst from Single Source
id: 43f7b91b-3870-4bd1-93c2-d364c8504a2e
status: test
description: >-
  Detects rapid automated enumeration of IBM Instana topology and event APIs from a single
  source IP exceeding a rate threshold consistent with the Turkish ARPA operator's multi-worker
  polling pattern. The operator's ARPA ETL platform runs 5 parallel systemd workers each
  polling the Instana API at 5-minute cadence, producing bursts of topology and event requests
  that exceed normal interactive or single-agent query rates. High request rates from source
  IPs not on the Instana operations team allow-list indicate credential-based automated
  reconnaissance of the Instana topology.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.collection
    - attack.discovery
logsource:
    product: ibm_instana
    service: api_access_log
detection:
    selection:
        RequestPath|startswith:
            - '/api/events'
            - '/api/topology'
            - '/api/applications'
    timeframe: 1m
    condition: selection | count() by SourceIP > 10
falsepositives:
    - Authorized Instana integrations with high query frequency (verify against operations team allow-list)
    - Load testing or API validation tooling during maintenance windows
level: medium
```

---

### Sigma Rule 9 — Operator-Supplied SSH Key File in User `.ssh` Directory

**Detection Priority:** HIGH
**Rationale:** Detects the appearance of the operator-supplied SSH key files (`rca_key.pem` or `rca_key.ppk`) in any Windows user `.ssh` directory. The operator supplied these specific files to the victim-side insider as part of the tunnel-deployment toolkit. Presence of these filenames in a user profile `.ssh` directory is a definitive indicator of insider-toolkit deployment.
**ATT&CK Coverage:** T1098.004 (SSH Authorized Keys), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**False Positive Risk:** LOW — `rca_key.pem` and `rca_key.ppk` are operator-distinctive filenames. Generic key files in `.ssh` dirs are common; this specific naming is operator-specific.
**Deployment:** Sysmon Event ID 11 (file creation); EDR file monitoring on `C:\Users\*\.ssh\`

```yaml
title: Operator-Supplied SSH Key File Created in User SSH Directory
id: f9b8ab33-5436-4f3a-a996-f737e54a3d37
status: test
description: >-
  Detects creation of the Turkish ARPA operator-supplied SSH key files (rca_key.pem for
  OpenSSH, rca_key.ppk for PuTTY) in any Windows user's .ssh directory. The operator
  distributed these specific key files to the victim-side insider (the victim organization Windows
  AD user [employee ID — suppressed]) as part of the tunnel-deployment toolkit documented in the operator's
  Turkish-language insider-recruitment handoff documents. Presence of these filenames in
  any user's .ssh directory indicates insider toolkit deployment regardless of the containing
  user account.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.persistence
    - attack.command-and-control
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\.ssh\'
        TargetFilename|endswith:
            - '\rca_key.pem'
            - '\rca_key.ppk'
    condition: selection
falsepositives:
    - Legitimate administrators who happen to name their SSH keys rca_key (verify key fingerprint and origin against CA records)
level: high
```

---

### Sigma Rule 10 — Network Connection to Port 8089 from Internal Host (Insider-Side Tunnel Bind)

**Detection Priority:** MEDIUM
**Rationale:** Detects network connections initiated to `localhost:8089` from processes on victim-side Windows hosts. Port 8089 is the insider-side tunnel bind point: the reverse SSH tunnel forwards from `localhost:8089` on the insider's machine out through the SSH connection to the operator's listener on port 18080. Any process initiating a connection to localhost:8089 in this context is communicating through the insider's reverse tunnel into the operator's network.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** MODERATE — port 8089 is not uniquely operator-specific (other software binds to this port; Splunk uses 8089 for management).
**False Positive Risk:** HIGH — Splunk uses port 8089 for its management API by default. Reduce FP by filtering for processes that are NOT `splunkd.exe` or `splunk.exe` initiating these connections.
**Deployment:** Sysmon Event ID 3 (network connection); EDR network telemetry on Windows endpoints. Requires filtering for non-Splunk initiators.

```yaml
title: Non-Splunk Process Connecting to Localhost Port 8089 on Enterprise Windows Host
id: 47e5169f-572c-4d87-9fda-578a23e58beb
status: test
description: >-
  Detects processes other than Splunk (which legitimately uses port 8089 for management)
  initiating TCP connections to localhost port 8089 on enterprise Windows hosts. Port 8089
  is the insider-side tunnel bind point in the Turkish ARPA operator's reverse SSH tunnel
  architecture: traffic from localhost:8089 on the insider's machine is forwarded through
  the SSH reverse tunnel to the operator's listener on port 18080 at 209.38.205.158.
  Non-Splunk processes binding or connecting to this port in an enterprise context indicate
  tunnel activity.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
    - attack.lateral-movement
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp:
            - '127.0.0.1'
            - '::1'
        DestinationPort: 8089
    filter_splunk:
        Image|endswith:
            - '\splunkd.exe'
            - '\splunk.exe'
    condition: selection and not filter_splunk
falsepositives:
    - Custom internal web services or developer tooling binding to port 8089 (verify against IT asset management)
    - Other monitoring agents that use 8089 as a secondary management port
level: medium
```

---

### Sigma Rule 11 — AI Operator Natural-Language Query API Egress to ARPA Platform Endpoint

**Detection Priority:** MEDIUM
**Rationale:** Detects outbound HTTP connections to the operator's ARPA platform endpoints (`209.38.205.158` on ports 8090/8095/8096) from server hosts within the target organization. This covers the scenario where the victim-side collector or a future variant of the AI service phones home to the operator's AI query interface. Also useful for hunting from the defender side if proxy or firewall egress logs capture the endpoint.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1020 (Automated Exfiltration), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH (for specific operator IP and ports)
**False Positive Risk:** NONE for the specific operator IP and port combination. LOW if the rule is broadened to any non-standard port egress from server hosts.
**Deployment:** Network egress logs; proxy logs; SIEM correlation on outbound connections.

```yaml
title: Outbound HTTP Connection to Turkish ARPA Platform Endpoints from Internal Host
id: af7bb4d0-34bf-4989-9e44-263ee76eef27
status: test
description: >-
  Detects outbound HTTP connections from internal hosts to the Turkish ARPA operator's
  DigitalOcean VPS (209.38.205.158) on known ARPA platform ports (8090 for dashboard,
  8095 for topology API, 8096 for Instana data ingestion). These cleartext HTTP connections
  carry Instana event payloads from victim infrastructure to the operator's analytics
  platform. The IP and port combination is unique to this operator's campaign infrastructure.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.exfiltration
    - attack.command-and-control
    - attack.collection
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '209.38.205.158'
        DestinationPort:
            - 8090
            - 8095
            - 8096
    condition: selection
falsepositives:
    - None expected — this IP and port combination is specific to the operator's campaign infrastructure
level: critical
```

---

### Sigma Rule 12 — Insider Deploying Outbound SSH Tunnel from Enterprise AD-Joined Workstation

**Detection Priority:** HIGH
**Rationale:** Detects the broader pattern of insider-deployed reverse SSH tunnels from enterprise AD-joined Windows workstations to external IPs. This is a higher-sensitivity, higher-coverage version of Sigma Rule 4 that covers the broader insider-tunnel behavioral pattern beyond the specific ARPA operator IP. Useful as a standing hunt rule for environments where insiders have SSH tools available on endpoints.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — developers with legitimate remote-access needs may use SSH tunneling to authorized dev/staging servers. Reduce FP by narrowing to non-developer workstations or excluding known authorized destination IPs.
**Deployment:** Sysmon Event ID 1; Windows Security Event ID 4688; EDR process telemetry on AD-joined workstations.

```yaml
title: SSH Reverse Tunnel Established from Enterprise AD-Joined Windows Workstation
id: d49b3f9d-31e8-4ed8-8c62-87aba3aedd66
status: test
description: >-
  Detects SSH or PuTTY processes on enterprise AD-joined Windows workstations establishing
  reverse tunnel connections (-R flag) to external IP addresses. In the Turkish ARPA
  operator campaign, an insider (Windows AD user [employee ID — suppressed]) was supplied with operator-provided
  SSH keys and instructions to establish reverse tunnels from inside the victim organization's
  network to 209.38.205.158:18080. Reverse SSH tunnels from enterprise workstations to
  external IPs are a high-confidence indicator of insider-facilitated external access
  regardless of the specific destination IP.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection_ssh_tools:
        Image|endswith:
            - '\ssh.exe'
            - '\putty.exe'
            - '\plink.exe'
    selection_reverse_flag:
        CommandLine|contains:
            - ' -R '
    selection_external_dest:
        CommandLine|contains:
            - '209.38.205.158'
    filter_authorized_infra:
        CommandLine|contains:
            - '10.'
            - '172.'
            - '192.168.'
    condition: selection_ssh_tools and selection_reverse_flag and not filter_authorized_infra
falsepositives:
    - Authorized developers using reverse SSH tunnels for remote development (verify against IT-authorized tunneling policy and destination IP allow-list)
    - Remote support tools using SSH tunneling to authorized jump hosts
level: high
```

---

## Suricata Signatures

---

### Suricata Rule 1 — DNS Query Egress to the victim organization Instana Wildcard Domain (Hunting Baseline)

**Detection Priority:** MEDIUM
**Rationale:** Detects DNS queries to `*.ocpinstana.[victim-domain].com.tr` from any host NOT on the approved Instana operations team list. The operator's victim-side collector resolves this domain before connecting to the Instana API. Within the victim organization, legitimate monitoring access should come from a small set of designated hosts; unauthorized DNS queries to this domain from other internal hosts are hunting-baseline indicators.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1078 (Valid Accounts)
**Confidence:** MODERATE (DNS alone is not definitive without the subsequent HTTPS connection context)
**False Positive Risk:** MEDIUM — any internal host resolving this domain for legitimate Instana administration. Useful as a hunting baseline, not a high-confidence alert. Suppress for designated Instana operations team hosts.
**Deployment:** DNS resolver logging; network-level DNS capture; Suricata on egress DNS traffic.

```suricata
alert dns $HOME_NET any -> any any (msg:"THL-ARPA-001 DNS Query to the victim organization Instana OCP Tenant - Potential Unauthorized Collector Activity"; dns.query; content:"ocpinstana.[victim-domain].com.tr"; nocase; threshold:type limit, track by_src, count 1, seconds 300; sid:9001001; rev:1; classtype:policy-violation; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1071.001;)
```

---

### Suricata Rule 2 — HTTP Egress to ARPA Operator Platform Ports (C2 Ingestion Endpoints)

**Detection Priority:** HIGH
**Rationale:** Detects cleartext HTTP connections from internal hosts to the operator's ARPA platform on its known ports (8090 dashboard, 8095 topology API, 8096 Instana ingestion endpoint). The operator's ingestion endpoint at `209.38.205.158:8096/api/ingest/instana` receives stolen Instana event payloads in cleartext with no authentication. Any internal host initiating HTTP connections to this IP on these ports is either running the operator's collector or directly interacting with the operator's platform.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel), T1020 (Automated Exfiltration)
**Confidence:** HIGH — the operator IP and port combination is specific to this campaign
**False Positive Risk:** NONE — `209.38.205.158` on these ports has no legitimate business purpose for any enterprise network.
**Deployment:** Suricata on egress internet traffic; inline IPS for immediate block capability.

```suricata
alert http $HOME_NET any -> 209.38.205.158 any (msg:"THL-ARPA-002 HTTP Egress to ARPA Operator Platform - Active C2 Ingestion or Dashboard Access"; http.uri; content:"/api/"; flow:to_server,established; sid:9001002; rev:1; classtype:trojan-activity; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1041;)

alert http $HOME_NET any -> 209.38.205.158 any (msg:"THL-ARPA-003 HTTP POST to ARPA Operator Instana Ingestion Endpoint - Observability Data Exfiltration"; http.method; content:"POST"; http.uri; content:"/api/ingest/instana"; startswith; flow:to_server,established; sid:9001003; rev:1; classtype:trojan-activity; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1020;)
```

---

### Suricata Rule 3 — Outbound SSH Connection to ARPA Operator VPS (Insider Tunnel Registration)

**Detection Priority:** HIGH
**Rationale:** Detects outbound SSH connections from internal Windows hosts to the operator's DigitalOcean VPS (`209.38.205.158`) on port 22. In the insider-recruitment component, the victim-side insider initiates an SSH connection with reverse-tunnel flags (`-R 18080:localhost:8089`) to this IP. While Suricata cannot inspect the SSH payload for tunnel flags on an encrypted session, the destination IP on SSH from an internal corporate host is sufficient for alerting.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** HIGH — SSH connections from internal corporate hosts to this specific DigitalOcean IP have no legitimate business purpose.
**False Positive Risk:** LOW — SSH to this specific operator IP from an enterprise network is not expected to be legitimate.
**Deployment:** Suricata on egress TCP traffic; network firewall logging; inline IPS for potential block.

```suricata
alert tcp $HOME_NET any -> 209.38.205.158 22 (msg:"THL-ARPA-004 Outbound SSH to ARPA Operator VPS - Potential Insider Reverse Tunnel Registration"; flags:S; flow:to_server; threshold:type limit, track by_src, count 1, seconds 60; sid:9001004; rev:1; classtype:trojan-activity; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1572;)
```

---

### Suricata Rule 4 — HTTP POST to `/api/ingest/instana` with Instana JWT Bearer Token

**Detection Priority:** HIGH
**Rationale:** Detects HTTP POST requests to any operator-side ingestion endpoint path `/api/ingest/instana` carrying an Instana `apiToken` header. This pattern represents the operator-side reverse-pipeline ingestion: victim-side collector POSTs stolen Instana event data to the operator's ARPA platform. If the operator migrates to a different IP, this application-layer signature continues to catch the ingestion pattern regardless of destination IP change.
**ATT&CK Coverage:** T1020 (Automated Exfiltration), T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — the `/api/ingest/instana` URI path is operator-coined and not used by legitimate IBM Instana products (IBM's own ingestion endpoints have different path structures).
**Deployment:** Suricata on egress HTTP traffic; proxy with TLS inspection for encrypted variants.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL-ARPA-005 HTTP POST to Operator ARPA Instana Ingestion Endpoint - Stolen Observability Data Exfiltration"; http.method; content:"POST"; http.uri; content:"/api/ingest/instana"; startswith; flow:to_server,established; sid:9001005; rev:1; classtype:trojan-activity; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1020;)
```

---

### Suricata Rule 5 — HTTP Egress to OpenClaw Distribution Domains from Server Hosts

**Detection Priority:** MEDIUM
**Rationale:** Detects outbound HTTP/HTTPS connections to the OpenClaw framework distribution domains (`openclaw.ai`, `docs.openclaw.ai`, `lightmake.site`) and the associated Tencent Cloud skill-marketplace CDN from server hosts. Legitimate developer workstations accessing these domains for OpenClaw development are MEDIUM FP risk; server hosts initiating outbound connections to these domains are higher confidence for OpenClaw-based operator activity. The Tencent Cloud skills bucket (`skillhub-1388575217.cos.ap-guangzhou.myqcloud.com`) is the OpenClaw skill marketplace CDN and should never appear in server egress logs.
**ATT&CK Coverage:** T1588.002 (Obtain Capabilities: Tool), T1071.001 (Web Protocols)
**Confidence:** MODERATE (OpenClaw domains alone don't prove malicious use; co-location with offensive tooling is the discriminator)
**False Positive Risk:** MEDIUM — legitimate OpenClaw developers accessing documentation. HIGH if deployed broadly on developer-workstation networks.
**Deployment:** Suricata on DNS egress (preferred) or HTTP egress; deploy on server-subnet traffic only to reduce FP.

```suricata
alert dns $HOME_NET any -> any any (msg:"THL-ARPA-006 DNS Query to OpenClaw Distribution or Skill-Marketplace Domain - Potential Operator Framework Presence"; dns.query; content:"openclaw.ai"; nocase; sid:9001006; rev:1; classtype:policy-violation; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1588;)

alert dns $HOME_NET any -> any any (msg:"THL-ARPA-007 DNS Query to OpenClaw Tencent Skill Marketplace CDN - OpenClaw Framework Skill Update"; dns.query; content:"skillhub-1388575217.cos.ap-guangzhou.myqcloud.com"; nocase; sid:9001007; rev:1; classtype:policy-violation; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1588;)

alert dns $HOME_NET any -> any any (msg:"THL-ARPA-008 DNS Query to lightmake.site - OpenClaw Vendor Domain"; dns.query; content:"lightmake.site"; nocase; sid:9001008; rev:1; classtype:policy-violation; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1588;)
```

---

### Suricata Rule 6 — Long-Lived SSH Session to External IP from Internal Windows Host (Reverse Tunnel Behavioral Pattern)

**Detection Priority:** MEDIUM
**Rationale:** Detects long-lived SSH sessions from internal Windows hosts to external IPs — the network-level behavioral pattern of an established reverse SSH tunnel. The insider's reverse tunnel must stay connected to maintain the operator's access; the session duration (hours to days) distinguishes it from transient SSH administration. This rule uses Suricata's flow tracking to flag TCP sessions on port 22 that exceed a duration threshold. Note: this rule has higher FP risk and is primarily useful as a hunting tool in environments where outbound SSH is tightly controlled.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** MODERATE
**False Positive Risk:** HIGH in development-heavy environments where SSH tunneling is common. LOW in enterprise corporate environments where SSH from Windows workstations is not standard.
**Deployment:** Suricata on egress TCP; best deployed on non-developer corporate workstation subnets.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 22 (msg:"THL-ARPA-009 Long-Lived SSH Session from Internal Windows Host to External IP - Potential Reverse Tunnel Maintenance"; flow:to_server,established; flowage:age > 3600; threshold:type limit, track by_src, count 1, seconds 3600; sid:9001009; rev:1; classtype:policy-violation; metadata:author The_Hunters_Ledger, campaign Turkish-ARPA-State-Insurer, created 2026-05-26, mitre_attack T1572;)
```

---

## Coverage Gaps

The following techniques and detection surfaces were observed in malware-analyst findings but could not be covered with high-confidence, production-ready rules due to data availability or structural detection limitations. Each gap is documented with the evidence that was present and what additional data would enable rule creation.

### Gap 1 — LLM Vendor-Side Detection (Moonshot AI / Kimi)

**Technique:** T1587 (Develop Capabilities), novel AI-augmented-operator pattern
**Observed:** The operator uses Moonshot AI (Kimi) as the LLM backend per `IDENTITY.md` on the operator's host. All operator code shows the AI-Generated Code Signature (verbose docstrings, emoji-in-output bleed, indentation decay, version-numbered file persistence). The LLM vendor has unique visibility into the operator's prompt history.
**Why rules cannot be created:** Moonshot AI prompt telemetry is entirely within the LLM vendor's infrastructure — outside standard SOC detection scope. No network-observable indicator specifically identifies which prompts are malicious vs. legitimate.
**What would enable detection:** Moonshot AI vendor telemetry sharing (coordinated disclosure to Moonshot AI / Beijing Moonshot AI Technology Co., Ltd.); vendor-side abuse pattern analysis; cross-account correlation within the Moonshot AI platform.

### Gap 2 — Insider-Detection Inside Victim AD Environment

**Technique:** T1199 (Trusted Relationship), T1078.002 (Domain Accounts), T1098.004 (SSH Authorized Keys)
**Observed:** The operator recruited a specifically-named Windows AD user (`[employee ID — suppressed]`) at the victim organization. The insider's activities inside the victim network (file creation, SSH tool usage, registry changes) are detectable only from inside the victim's AD domain with adequate Sysmon/EDR coverage.
**Why rules cannot be created at this stage:** Sigma rules 4, 5, 9, 10, and 12 in this file cover the observable host-level indicators; however, the most valuable detection data (AD authentication logs, lateral movement inside the network, file access to internal resources) requires victim-org cooperation and access to their internal SIEM/EDR. External third-party detection of insider behavior is structurally limited to network-egress and DNS patterns — both of which are covered in the Suricata rules.
**What would enable detection:** Victim-org IR engagement; preservation and sharing of Windows AD audit logs for the `[employee ID — suppressed]` account (2026-03-01 → present); Sysmon deployment retrospective on the insider's workstation.

### Gap 3 — Cross-Source ETL Detection Prior to Export

**Technique:** T1119 (Automated Collection), T1213 (Data from Information Repositories), novel Observability-Tool Reverse Pipeline TTP
**Observed:** The operator's cross-source ETL ingests data from all four observability sources (Instana + SolarWinds + Zabbix + VMware Aria) and correlates them into `unified_cross_source_topology.json`. The export/exfiltration event is detectable via Sigma rule 7 (multi-platform auth burst) and Suricata rule 2 (HTTP POST to C2). However, the collection event within each platform (normal API calls using stolen credentials that look identical to legitimate admin calls) is undetectable without the cross-platform correlation context.
**Why rules cannot be created:** Individual API calls to each platform using valid stolen credentials are indistinguishable from legitimate admin access at the single-platform level. Detection requires cross-platform correlation (Sigma rule 7) that most victim orgs cannot execute without SIEM integration across all four observability platform audit feeds simultaneously.
**What would enable detection:** IBM Instana audit log integration to SIEM; SolarWinds Orion API audit log export; Zabbix audit log SIEM integration; VMware Aria audit event export. Cross-source authentication burst correlation (Sigma rule 7) becomes operative once at least two of these feeds are integrated.

### Gap 4 — SolarWinds Orion Stolen-Credential Abuse Detection

**Technique:** T1078 (Valid Accounts), T1046 (Network Service Discovery)
**Observed:** The operator enumerated 784 nodes + 6,566 interfaces from SolarWinds Orion with stolen credentials. Last fetch captured was 2026-03-13 04:15:01. The operator had valid credentials for the SolarWinds Orion API.
**Why rules cannot be created:** SolarWinds Orion API audit telemetry is not a standard SIEM integration target in most environments. Detection of stolen-credential abuse within SolarWinds Orion requires SolarWinds-native audit log review or direct T&S coordination.
**What would enable detection:** SolarWinds Orion audit log export to SIEM; SolarWinds Trust & Safety coordination for tenant-level anomaly detection on the the victim organization Orion instance; baseline establishment of legitimate admin source IPs against which new source IPs (including the operator's DigitalOcean VPS) can be compared.

### Gap 5 — VMware Aria Stolen-Credential Abuse Detection

**Technique:** T1078 (Valid Accounts), T1119 (Automated Collection)
**Observed:** The operator ingested 8,649 VMware Aria events in a single sampled window — the highest single-source event volume, suggesting Aria is the operator's deepest visibility layer (vCenter / ESXi lifecycle events, VM resource alerts).
**Why rules cannot be created:** VMware Aria (formerly vRealize Operations) audit telemetry requires specific Broadcom/VMware enterprise audit export configuration to integrate with external SIEMs. Detection of API credential abuse within the Aria stack requires Broadcom T&S coordination or native Aria audit review.
**What would enable detection:** Broadcom T&S coordination for the the victim organization VMware Aria instance; vRealize Log Insight or vRealize Operations audit export to SIEM; baseline of legitimate Aria admin source IPs with anomaly detection on new source authentication.

### Gap 6 — Operator Residential IP Attribution Actions

**Technique:** T1583.003 (Virtual Private Server — attribution infrastructure), novel insider-detection-first structural rarity
**Observed:** The operator interactive session from `31.223.97.87` (TurkNet AS12735, Turkish residential/SMB ISP) was captured 2026-05-20 21:22-21:30 UTC. This IP is attribution evidence, not C2 infrastructure. It appears in the operator's own dashboard access logs.
**Why rules cannot be created:** The operator residential IP should NOT be blocked (it is a residential ISP serving millions of legitimate Turkish users; blocking would cause collateral damage). Detection rules targeting this IP would have enormous FP rates and are inappropriate for third-party deployment.
**What would enable better tracking:** Turkish law enforcement coordination (USOM → SECRD Cybercrime Combat Department) for TurkNet subscriber subpoena on `31.223.97.87`; TurkNet abuse desk notification for account review; passive monitoring of this IP's future HTTP access patterns via Hunt.io infrastructure monitoring.

### Gap 7 — AI-Augmented NLQ Operator-Side Session Detection

**Technique:** Novel CANDIDATE TTP — "AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials" (N=1, needs N≥2)
**Observed:** The operator built `ai_service.py` + `ai_assistant.db` as a natural-language query interface over stolen Instana monitoring data. The service is in a broken/dev state on the current deployment but the architecture is intact (events table populated with 50 rows from the victim organization Instana).
**Why rules cannot be created for the AI query session itself:** When functional, the AI query sessions would consist of natural-language HTTP requests to the operator's own platform on `localhost` (or via the reverse tunnel). These are operator-internal and invisible to external detection. The only detectable artifact is the `ai_assistant.db` database presence (covered by YARA rule 5) and the broken-state Python traceback in `ai_service.log` (covered by YARA rule 2 via the file path pattern).
**What would enable better coverage:** N=2 validation of the AI-Augmented Reconnaissance TTP across a second independent operator; analysis of a functional AI service session to characterize its network I/O patterns (LLM API calls to Moonshot AI, database queries, response formatting); operator-host access log export if the service becomes functional.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
