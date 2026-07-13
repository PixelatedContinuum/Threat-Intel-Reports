---
title: "Detection Rules — Turkish ARPA Operator / AI-Augmented State-Insurer Observability Compromise + Insider Recruitment (UTA-2026-013)"
date: '2026-05-26'
layout: post
permalink: /hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
thumbnail: /assets/images/cards/turkish-arpa-openclaw-state-insurer-209.38.205.158.png
hide: true
---

**Campaign:** Turkish-ARPA-OpenClaw-State-Insurer-UTA-2026-013-209.38.205.158
**Date:** 2026-05-26
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/turkish-arpa-openclaw-state-insurer-209.38.205.158/

> **Scope note:** This file covers **Case 2 (Turkish ARPA Operator / the victim organization)** per-case detection signatures only. Cross-campaign and cross-operator signatures are in the parent file at `/hunting-detections/ai-agent-frameworks-2026-05-23-detections/`. Do not duplicate parent-file rules here.

> **Operational sensitivity:** The insider user identifier (`[employee ID — suppressed]`) and operator residential IP (`31.223.97.87`) appear in indicators below. These are included because they are load-bearing for detection rules; they are suppressed from the public-facing report body per the disclosure-cascade protocol. Rules referencing these values should be treated as restricted-distribution until the victim-org coordination step is complete.

---

## Detection Coverage Summary

This backfill re-tiers the original 29-rule set (8 YARA, 12 Sigma, 9 Suricata) into Detection / Hunting per the project's four-gate tiering rubric. One Sigma rule and five Suricata rules are pure atomics — a bare C2 IP or a bare ecosystem domain with no surviving behavioral discriminator once the literal is removed — and are retired as standalone rules; their literals are already present in the campaign's IOC feed. Two Suricata rules are cut outright (one pre-existing overbroad withdrawal, one redundant duplicate of a broader surviving rule). One Sigma rule (`Sigma Rule 7`) contained dead detection logic — an impossible same-event `AND` across four mutually-exclusive `EventSource` values that could never be true on a single log record — and has been corrected to a satisfiable single-event selection, consistent with this file's own established pattern (see `Sigma Rule 8`) of surfacing a per-event signal and documenting the SIEM-side correlation it requires in prose rather than inventing unsupported correlation syntax.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 7 | 1 | T1005, T1020, T1021.004, T1046, T1059.001, T1059.006, T1071.001, T1078, T1098.004, T1119, T1213, T1543.002, T1552.001, T1569.002, T1572, T1587 | 0 |
| Sigma | 6 | 5 | T1021.004, T1046, T1059.001, T1071.001, T1078, T1098.004, T1119, T1213, T1543.002, T1552.001, T1569.002, T1572 | 1 |
| Suricata | 1 | 1 | T1020, T1041, T1071.001, T1078 | 5 |

**Total:** 21 rules across 3 detection layers (14 Detection, 7 Hunting), plus 6 atomics already carried in the IOC feed and 2 rules cut outright.

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Coverage approach (unchanged from original analysis):** Rules are organized by the three campaign surfaces:
1. **Victim-side artifacts** — PowerShell collector deployed on the victim organization's hosts + insider reverse-tunnel tooling
2. **Operator-side platform artifacts** — ARPA Python ETL platform, systemd service naming, AI service, Markdown ops notes
3. **Network / infrastructure layer** — C2 ingestion endpoints, DNS, SSH tunnel patterns, Instana API abuse

**Highest-confidence anchors:**
- The operator's self-branded strings (`ARPA Korelasyon Motoru`, the dashboard footer, the versioned `correlation_v3.py` docstring) — durable, near-zero FP; rebranding the entire platform is the only evasion path (YARA Detection).
- The `arpa-*` systemd naming cluster and prefix pattern — five observed unit names plus a durable directory+prefix pattern that also catches unnamed future units (YARA + Sigma Detection).
- The Turkish-language insider-recruitment Markdown filename family (`GERCEK_API_BULUNDU`, `PUTTY_TUNNEL_DETAY`, `SSH_KEY_COZUM`, etc.) combined with the `ARPA_Tunnel` session name and `rca_key` artifacts (YARA + Sigma Detection).

**Atomics routed to the IOC feed (already present — no new feed entries required):** the operator C2 IP `209.38.205.158` (with its documented ports 8090/8095/8096) and the OpenClaw ecosystem domains (`openclaw.ai`, `docs.openclaw.ai`, `lightmake.site`, the Tencent skill-marketplace CDN) were each the sole discriminator of a rule with no surviving behavior once the literal is removed. All are already present in [`turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json`](/ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json) — no feed edits were made.

**Victim-domain exception (Hunting, not atomic-routed):** two rules (Sigma Rule 2, Suricata Rule 1) key on the victim organization's own redacted Instana tenant hostname (`*.ocpinstana.[victim-domain].com.tr`) with no additional behavioral filter. Structurally this is an atomic pattern, but the underlying literal is the *victim's own asset* rather than attacker infrastructure — and the campaign's disclosure policy explicitly excludes victim infrastructure from the public IOC feed, so it cannot be routed there. Both rules are retained as **Hunting** tier for the victim organization's own internal/IR use (this file is already restricted-distribution per the Operational Sensitivity note above), not as general public-feed-eligible atomics. See Coverage Gaps for the full rationale.

**Calibration notes carried forward from original analysis:**
- **Observability-Tool Reverse Pipeline TTP novelty:** maintained at high-MODERATE (top of MODERATE band) novelty confidence after full prior-art review. Closest adjacent documented case (UNC6395 OAuth-based CRM breach) is structurally distinct — one-time CRM exfiltration vs. sustained 4-source observability ETL. The Sigma rule targeting the multi-source cross-platform authentication pattern (Sigma Rule 7, corrected below) is Hunting-tier — it surfaces the qualifying per-event signal but still requires SIEM-side correlation to realize the full novel-TTP detection value.
- **AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials** (`ai_service.py` + `ai_assistant.db` pattern): CANDIDATE novel TTP at N=1. YARA Rule 5 targets this pattern specifically and is Hunting-tier pending N≥2 cross-operator validation.
- **10-year Instana JWT governance defect:** the stolen JWT (`jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3`, exp ~2034-02) is a victim-side credential management defect — this is NOT an IBM Instana CVE. Sigma Rule 6 (long-lived JWT detection) is a Detection-tier governance baseline rule for Instana customers; IBM PSIRT coordination is a product-hardening recommendation, not a CVE-disclosure path.

---

## YARA Rules

### Detection Rules

#### Rule 1 — PowerShell Instana Local Collector

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1552.001 (Credentials in Files), T1020 (Automated Exfiltration), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Requires three anchors simultaneously — the victim organization's own Instana tenant endpoint fragment, the operator's specific `api/ingest/instana` C2 ingestion path, and the `-SkipCertificateCheck` flag — plus one of two Turkish-language markers or the event-schema field name. No single anchor carries the rule alone.
**False Positives:** None known for the full combination. The victim tenant substring alone would also appear in legitimate internal admin scripts calling the same API — this is why the rule requires it in combination with the operator's ingestion path and the cert-bypass flag, not alone.
**Blind Spots:** A rewritten collector that renames the operator's ingestion path AND drops `-SkipCertificateCheck` (e.g., using a properly-signed certificate) would evade; scoped to the victim organization's own environment by design (a per-case rule, not a general family signature).
**Validation:** Run the collector script or an equivalent test file carrying all three anchors — must match; a legitimate internal Instana admin script lacking the operator's ingestion path must NOT fire.
**Deployment:** Endpoint AV/EDR on Windows hosts; PowerShell Script Block Logging pipeline; email gateway scanning for PS1 attachments.

```yara
/*
   Yara Rule Set
   Identifier: Turkish-ARPA-OpenClaw-State-Insurer-209.38.205.158
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_PowerShell_Instana_Local_Collector_Family {
   meta:
      description = "Detects the Turkish ARPA operator's victim-side PowerShell collector that exfiltrates IBM Instana APM events from the victim organization's OCP-hosted Instana tenant to operator C2 at 209.38.205.158. Indicators: hardcoded victim Instana endpoint, stolen JWT delivery, Turkish-language operational comments, and POST to operator ARPA ingestion endpoint."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      $victim_endpoint and $operator_c2 and $skip_cert and
      (1 of ($turkish_comment, $arpa_server) or $event_schema)
}
```

#### Rule 2 — ARPA Observability Harvester Platform

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.006 (Python), T1119 (Automated Collection), T1543.002 (Systemd Service), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Anchored on the operator's self-branded strings (`ARPA Korelasyon Motoru`, the dashboard footer, `Read-Only Compliance`) — durable across builds since renaming them means de-branding the entire platform, not editing a single file.
**False Positives:** None known for the dashboard footer verbatim; low for the self-branding string alone (could appear in unauthorized forks of the operator's public GitHub repo).
**Blind Spots:** A full de-branding of the ARPA platform (new project name, new dashboard footer, new file/endpoint paths) would evade; targets on-disk/in-memory artifacts of the operator-side platform, not the victim-side collector.
**Validation:** Scan the operator's platform files or a memory dump carrying the branding strings — must match; unrelated Flask/Python monitoring dashboards must NOT fire.
**Deployment:** Linux server file scanning, osquery file content checks, memory scanning on VPS infrastructure.

```yara
rule MAL_Python_ARPA_Observability_Harvester_Platform {
   meta:
      description = "Detects the Turkish ARPA operator's multi-source observability-harvester Python platform (ARPA Korelasyon Motoru). Targets the operator self-branding docstring, dashboard footer, and multi-source ingestion patterns that identify this platform across source files, SQLite stores, and HTML dashboard responses."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      (
         ($brand2 and $brand3 and $mock_data) or
         (
            ($brand1 or $brand2) and
            ($corr_endpoint or $topology_endpoint or $db_collector or $db_ai)
         )
      )
}
```

#### Rule 3 — Insider Tunnel-Setup Turkish-Language Operator Document

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1098.004 (SSH Authorized Keys), T1021.004 (Remote Services: SSH)
**Confidence:** HIGH
**Rationale:** Requires 2-of-5 tunnel-setup markers (session name, key filenames, C2 IP, or port combo) AND 1-of-4 distinctive Turkish-language document filenames from the operator's insider-recruitment playbook. No single marker — including the C2 IP, which is only one of five alternatives — carries the rule alone.
**False Positives:** Low — the combination of Turkish-language operational keywords, ARPA-branded tunnel naming, and the specific port-forward configuration does not occur in legitimate admin workflows, even among Turkish-speaking IT staff.
**Blind Spots:** A future insider-recruitment campaign by the same operator using entirely renamed documents and a different tunnel port would evade; targets the on-disk documents, not the tunnel traffic itself (see the Sigma/Suricata rules below for the network-side behavior).
**Validation:** Scan a copy of the operator's insider-recruitment document set — must satisfy both clauses; an unrelated Turkish-language IT document must NOT fire.
**Deployment:** Endpoint file scanning (Windows user profile directories), DLP file content inspection, email attachment scanning.

```yara
rule MAL_PSScript_Insider_TunnelSetup_Turkish {
   meta:
      description = "Detects operator-authored Turkish-language insider-recruitment tunnel-setup documents (PUTTY_TUNNEL_DETAY.md, TUNNEL_RESTART.md, SSH_KEY_COZUM.md class). Operator instructs victim-side insider (the victim organization Windows AD user [employee ID — suppressed]) how to deploy reverse SSH tunnels from inside the victim network. Keyword combination is specific to this operator campaign."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

#### Rule 4 — Multi-Source Observability Polling Python Script

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1046 (Network Service Discovery), T1119 (Automated Collection), T1078 (Valid Accounts)
**Confidence:** HIGH
**Rationale:** Always requires the victim's own Instana tenant identifier, combined with either the stolen JWT's unique `jti` value, the Instana API path plus 2-of-3 competing-platform references, or the cadence/last-fetch function-name pair. The mandatory victim-tenant anchor scopes this correctly to the victim's own environment (a per-case rule).
**False Positives:** MEDIUM — organizations building their own in-house cross-source monitoring integrations against the same victim tenant could share this pattern; the stolen-JWT branch has effectively no FP since it keys on a specific known-compromised credential value.
**Blind Spots:** A rewritten polling script targeting a different subset of platforms, or one that drops the cadence/last-fetch function names, could evade the weaker branches (the stolen-JWT branch remains durable as long as that credential is reused).
**Validation:** Scan the operator's multi-source polling script — must match at least one branch; an unrelated single-platform monitoring script must NOT fire.
**Deployment:** Linux server file scanning, SIEM file-create alerting on `/opt/` paths.

```yara
rule MAL_Python_Instana_SolarWinds_Zabbix_VMwareAria_Polling {
   meta:
      description = "Detects Python scripts implementing multi-source observability polling targeting IBM Instana, SolarWinds Orion, Zabbix, and VMware Aria from a single codebase — the core of the Turkish ARPA operator's Observability-Tool Reverse Pipeline TTP. Hardcoded victim Instana tenant and 5-minute cadence markers identify operator-authored vs legitimate cross-monitoring tools."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      (
         $jwt_jti or
         ($instana_api and 2 of ($zabbix_ref, $solarwinds_ref, $vmware_aria)) or
         ($cadence and $last_fetch)
      )
}
```

#### Rule 6 — ARPA Cross-Source Correlation ETL Engine

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.006 (Python), T1119 (Automated Collection), T1005 (Data from Local System)
**Confidence:** HIGH
**Rationale:** Anchored on the operator's versioned, self-branded docstring (`ARPA Korelasyon Motoru v3 - Temporal Focus`) and Turkish-language diagnostic output (`=== SON 5 KORELASYON ===`) — no legitimate monitoring software emits Turkish-language diagnostic labels under this self-branding.
**False Positives:** None known — the version-numbered self-branding and Turkish-language output are specific to this operator's toolkit.
**Blind Spots:** A future version bump that also drops the Turkish-language diagnostic strings (an English-only refactor) would fall back to the weaker `extract_host_from_label` + `Service label` combination.
**Validation:** Scan the correlation engine script — must match the docstring or Turkish diagnostic string; unrelated correlation/ETL tooling must NOT fire.
**Deployment:** Linux server file scanning, code-repository scanning for publicly exposed operator code.

```yara
rule MAL_Python_ARPA_CrossSource_Correlation_ETL {
   meta:
      description = "Detects the Turkish ARPA operator's cross-source correlation ETL engine (correlation_v3.py and variants). Operator self-branded docstring 'ARPA Korelasyon Motoru v3 - Temporal Focus', Turkish-language diagnostic output, and API endpoint dispatch patterns uniquely identify this component of the ARPA platform."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      ($endpoint_dispatch or $topology_fn or ($extract_fn and $turkish_extract) or ($docstring and $temporal))
}
```

#### Rule 7 — ARPA Operator Ops Notes Markdown Family

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1552.001 (Credentials in Files)
**Confidence:** HIGH
**Rationale:** Requires one of four operator-specific note-filename/GitHub-handle markers AND one of three secondary markers (victim tenant reference, the generic `apiToken` field label, or a Turkish-language test label). The generic `apiToken` fallback alone is weak, but it never fires without one of the four distinctive primary markers also present.
**False Positives:** Low — the combination of Turkish-language celebratory discovery notes, the specific GitHub handle, and victim-specific API references is operator-specific.
**Blind Spots:** A future campaign by the same operator using an entirely different GitHub identity and non-Turkish note filenames would evade.
**Validation:** Scan the operator's ops-notes directory — must satisfy both clauses; an unrelated Markdown file referencing a generic `apiToken` field must NOT fire alone.
**Deployment:** Linux server file scanning, git repository content scanning, osquery file table on `/opt/ARPA/` and adjacent directories.

```yara
rule MAL_Markdown_ARPA_OperatorNote_Family {
   meta:
      description = "Detects Turkish ARPA operator-authored operational Markdown notes (GERCEK_API_BULUNDU.md, INSTANA_INTEGRATION_SUMMARY.md class). Operator documents the discovery of victim Instana endpoints, integration steps, and references the public MehmetARPA/ARPA GitHub repository. Turkish-language operational narrative combined with victim-specific API references is operator-distinctive."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      ($gercek or $instana_summary or $github_ref or $instana_port) and
      ($victim_ref or $api_token_label or $turkish_label)
}
```

#### Rule 8 — ARPA Platform Systemd Service Units

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1569.002 (System Services: Service Execution)
**Confidence:** HIGH
**Rationale:** Requires 2 of 5 distinctive `arpa-*` service names plus either `ExecStart=` or the `/opt/ARPA/` path — an operator would need to rename at least 4 of the 5 unit files to drop below the 2-of-5 threshold, and no legitimate software collides with this naming cluster.
**False Positives:** Low — the `arpa-*` naming cluster for this specific set of five service names does not collide with any known legitimate software's systemd service naming pattern.
**Blind Spots:** A full platform rebrand that renames all five unit files (and any successors) would evade; the companion Sigma file-creation rule (Sigma Rule 3) additionally catches the bare `arpa-*.service` prefix pattern for any single new unit, which is broader than this YARA rule's 2-of-5 requirement.
**Validation:** Scan `/etc/systemd/system/` on a host running the ARPA platform — must match 2+ unit names; an unrelated Linux host's systemd directory must NOT fire.
**Deployment:** Linux server file scanning on `/etc/systemd/system/`, osquery systemd_units table, auditd file_create watches on systemd directories.

```yara
rule MAL_SystemdUnit_ARPA_Platform_Services {
   meta:
      description = "Detects the Turkish ARPA operator's systemd service unit files persisting the ARPA observability-harvester platform (arpa-autolearn, arpa-continuous, arpa-daemon, arpa-instana-api, arpa-parallel). Presence of this naming cluster in /etc/systemd/system/ indicates ARPA platform deployment on the target host."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

### Hunting Rules

#### Rule 5 — ARPA AI Service Natural-Language Query Interface

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1213 (Data from Information Repositories)
**Confidence:** MODERATE — the AI service was observed in a broken/dev state on the single analyzed host; the pattern may not have replicated to other deployments.
**Rationale:** The `ai_assistant.db` filename combined with a handler/training-log marker and an ARPA-specific path or filename is a reasonably distinctive combination, but a database literally named `ai_assistant.db` is not inherently unique on its own. This is the file's own explicitly self-assessed moderate-confidence, medium-FP component — a Hunting lead rather than an alerting-grade Detection rule.
**False Positives:** MEDIUM — `ai_assistant.db` combined only with the generic `_handle_event_query`/`_handle_general_query` handler names (without the ARPA-specific path or filename) could occur in unrelated Python projects using similar SQLite-backed dispatch patterns.
**Deployment:** Linux server file scanning, osquery SQLite schema inspection; triage hits against the co-located ARPA platform artifacts (YARA Rules 2, 6, 8) before escalating.

```yara
rule MAL_Python_ARPA_AI_Service_NaturalLanguage_Query {
   meta:
      description = "Detects the Turkish ARPA operator's AI-augmented natural-language query interface over stolen observability data (ai_service.py + ai_assistant.db). Architecture: events table populated from stolen Instana monitoring data, situations table for AI root-cause analysis, ai_training_log table for conversation feedback. Candidate novel TTP: AI-Augmented Infrastructure Reconnaissance Using Stolen APM Credentials."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      ($handler1 or $handler2 or $ai_training or $situations) and
      ($arpa_path or $data_retrieval or $ai_service)
}
```

---

## Sigma Rules

### Detection Rules

#### Sigma Rule 1 — PowerShell Process Invoking Instana API with Stored JWT Bearer Token

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1552.001 (Credentials in Files), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Requires a PowerShell/pwsh process AND an Instana-related command-line reference AND the `-SkipCertificateCheck` flag. The cert-bypass flag is generic alone, but ANDed with the more specific Instana-endpoint reference and the PowerShell-family image, the combination is durable for this environment.
**False Positives:** LOW within the victim org if Instana API access is tightly controlled; legitimate Instana operations-team scripts that also use `-SkipCertificateCheck` for OCP self-signed certificates would collide.
**Blind Spots:** A rewritten collector using a signed certificate (no `-SkipCertificateCheck`) or invoking the API from a non-PowerShell interpreter would evade.
**Validation:** Execute the collector script (or an equivalent PowerShell test invoking the same three conditions) — must fire; an authorized Instana operations script using a different API path must NOT fire.
**Deployment:** Sysmon + PowerShell Script Block Logging (Event ID 4104); SIEM correlation across endpoint telemetry.

```yaml
title: PowerShell Instana API Call with Stored JWT Token from Unauthorized Host
id: ba31534e-e868-47fc-bfcd-4c5a4ce0b85d
status: experimental
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
date: '2026-05-26'
tags:
    - attack.execution
    - attack.t1059.001
    - attack.credential-access
    - attack.t1552.001
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
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

#### Sigma Rule 3 — Systemd Unit Creation Matching `arpa-*` Naming Pattern

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1569.002 (System Services: Service Execution)
**Confidence:** HIGH
**Rationale:** Matches ANY file matching the `/etc/systemd/system/arpa-*.service` prefix pattern — broader than the YARA equivalent's fixed 2-of-5 enumeration, since it also catches unnamed future units sharing the same prefix. No legitimate software in a 365-day infrastructure index uses this exact naming scheme.
**False Positives:** Low — the `arpa-` prefix for systemd services does not conflict with known legitimate software service names.
**Blind Spots:** A platform rebrand that drops the `arpa-` prefix entirely would evade; targets file-creation telemetry only, not the resulting running service.
**Validation:** Create a test file matching `/etc/systemd/system/arpa-test.service` — must fire; an unrelated `*.service` unit file must NOT fire.
**Deployment:** auditd `file_create` watch on `/etc/systemd/system/`; Linux EDR file event telemetry.

```yaml
title: Systemd Unit File Created with ARPA Platform Service Naming Convention
id: 4c27b8f2-a383-4cf0-a20a-21f8681231fa
status: experimental
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
date: '2026-05-26'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.002
    - attack.execution
    - attack.t1569.002
    - detection.emerging-threats
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

#### Sigma Rule 4 — Reverse SSH Tunnel Registration from Windows AD User Host to Operator IP

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH), T1098.004 (SSH Authorized Keys)
**Confidence:** HIGH
**Rationale:** Requires an SSH-family tool AND (a tunnel-specific flag/port/IP OR the operator's session-name/key-file markers). Neither branch depends solely on the C2 IP — the `selection_arpa_session` branch fires on the operator's naming convention alone. Level demoted from the original `critical` to `high`: the rule is a strong process-creation combination, not a never-FP indicator (developer tunneling tools can share the same flags), matching this file's Gate-4 discipline of reserving `critical` for near-certain, immediate-incident signals.
**False Positives:** LOW — SSH with `-R` reverse-forwarding from an enterprise Windows workstation to an external IP is extremely uncommon in legitimate workflows; developers using ngrok or similar legitimate tunneling services use different tooling and endpoints.
**Blind Spots:** A future insider-recruitment iteration using a different reverse-tunnel port and renamed session/key artifacts would evade both branches.
**Validation:** Launch `ssh.exe`/`putty.exe`/`plink.exe` with the `-R 18080:localhost:8089` flag toward the operator IP, or referencing `ARPA_Tunnel`/`rca_key` — must fire; an unrelated SSH connection with no reverse flag must NOT fire.
**Deployment:** Sysmon Event ID 1 (process creation); Windows Security Event ID 4688; EDR process telemetry.

```yaml
title: Reverse SSH Tunnel Established from Windows Host to ARPA Operator Infrastructure
id: 6465d373-414d-461d-8624-11153cc64d9c
status: experimental
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
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.004
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098.004
    - detection.emerging-threats
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
level: high
```

#### Sigma Rule 5 — PuTTY Saved Session Created with Tunnel or ARPA Name

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** HIGH
**Rationale:** Requires BOTH the PuTTY saved-sessions registry path AND the operator's `ARPA_Tunnel` session name — a recurring, brand-consistent element the operator instructed the insider to use, not an arbitrary one-off string.
**False Positives:** Low — `ARPA_Tunnel` is operator-specific; generic "Tunnel" in PuTTY session names is not matched by this rule (only the exact `ARPA_Tunnel` substring is).
**Blind Spots:** A future campaign instructing the insider to use a different session name would evade.
**Validation:** Create a PuTTY saved session named `ARPA_Tunnel` — must fire; an unrelated PuTTY session name must NOT fire.
**Deployment:** Sysmon Event ID 12/13/14 (registry events); Windows Security registry audit.

```yaml
title: PuTTY Saved Session Created with ARPA Tunnel Naming Convention
id: 785967aa-4fba-4679-8209-53c0f22b0631
status: experimental
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
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.004
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection_putty_path:
        TargetObject|contains: '\Software\SimonTatham\PuTTY\Sessions\'
    selection_arpa_session:
        TargetObject|contains: 'ARPA_Tunnel'
    condition: selection_putty_path and selection_arpa_session
falsepositives:
    - Legitimate administrators creating PuTTY sessions for authorized remote management with similar names (verify session destination and key file)
level: high
```

#### Sigma Rule 6 — Long-Lived Instana JWT Detected in Audit Logs (Governance Baseline)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1078 (Valid Accounts), T1552.001 (Credentials in Files)
**Confidence:** HIGH (for the specific stolen JWT); MODERATE (for the generic long-lived-token governance branch)
**Rationale:** The first branch keys on the exact `jti` of a specific, known-compromised credential — a durable indicator that does not "rotate" the way attacker C2 infrastructure does, since it identifies known-bad evidence rather than active attacker infrastructure. The second branch requires the victim tenant identifier AND a genuine behavioral filter (source not in RFC1918 ranges), unlike the bare tenant-only match in Sigma Rule 2 below. Level demoted from the original `critical` to `high`: the condition mixes a near-certain branch (known-stolen JTI) with a MODERATE-confidence governance branch (external access to the tenant) under one rule-level field, so `high` is the honest ceiling for the combined rule.
**False Positives:** LOW for the specific JTI; MEDIUM for the generic long-lived-token governance pattern depending on how the Instana instance is configured — authorized Instana admin tools or token-rotation scripts running from external orchestration infrastructure could trigger the second branch.
**Blind Spots:** If the victim rotates away from the stolen JWT (recommended remediation), the first branch stops matching by design; the second branch depends on the Instana instance exporting audit telemetry with a `source_ip` field.
**Validation:** Replay an API call using the known stolen `jti` — must fire; replay a call using an internal-source IP against the same tenant — must NOT fire the second branch.
**Deployment:** Instana audit log export to SIEM; IBM Instana customer portal API token review.

```yaml
title: Instana Stolen JWT or Long-Lived API Token Detected in Audit Log
id: d4398d0e-e7ea-4b8d-a838-8b2a760fc468
status: experimental
description: >-
  Detects use of the specific stolen the victim organization Instana JWT (jti 022a1b74) in API calls,
  or flags any Instana API token with an expiration lifetime exceeding 1 year — a governance
  defect that enabled the Turkish ARPA operator to maintain persistent access over a multi-year
  window using a single stolen credential. This is not an IBM Instana CVE; it is a victim-side
  token management defect. Sigma rule targets Instana audit log telemetry exported to SIEM.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.credential-access
    - attack.stealth
    - attack.persistence
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1078
    - attack.t1552.001
    - detection.emerging-threats
logsource:
    product: ibm_instana
    service: audit_log
detection:
    selection_stolen_jti:
        jwt_jti: '022a1b74-2332-4df5-a76b-60225ffa7ae3'
    selection_stolen_tenant:
        tenant: '[victim-tenant]'
    filter_internal_source:
        source_ip|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection_stolen_jti or (selection_stolen_tenant and not filter_internal_source)
falsepositives:
    - Authorized Instana admin tools accessing the tenant from external IPs (verify against operations team allow-list)
    - Token rotation scripts running from external orchestration infrastructure
level: high
```

#### Sigma Rule 9 — Operator-Supplied SSH Key File in User `.ssh` Directory

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1098.004 (SSH Authorized Keys), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**Rationale:** Requires the `.ssh` directory path context AND one of two key filenames (`rca_key.pem`/`rca_key.ppk`). These filenames recur across the operator's own SSH-key naming convention documented elsewhere in this investigation (`rca_key.ppk`, `rca_key.pem`, `rc_deploy_key.ppk`, `rca_deploy_key` all share the same "rc(a)" root, tracing back to the operator's earlier `/opt/rca-platform/` deployment) rather than being an arbitrary one-off choice.
**False Positives:** LOW — `rca_key.pem`/`rca_key.ppk` are operator-distinctive filenames; generic key files in `.ssh` directories are common, but this specific naming is operator-specific.
**Blind Spots:** A future campaign iteration that abandons the "rc(a)" naming convention entirely would evade.
**Validation:** Create a file named `rca_key.pem` or `rca_key.ppk` inside any user's `.ssh` directory — must fire; an unrelated key file in the same directory must NOT fire.
**Deployment:** Sysmon Event ID 11 (file creation); EDR file monitoring on `C:\Users\*\.ssh\`.

```yaml
title: Operator-Supplied SSH Key File Created in User SSH Directory
id: f9b8ab33-5436-4f3a-a996-f737e54a3d37
status: experimental
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
date: '2026-05-26'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098.004
    - attack.command-and-control
    - attack.t1572
    - detection.emerging-threats
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

### Hunting Rules

#### Sigma Rule 2 — Outbound HTTPS to the Victim Organization Instana Tenant

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1078 (Valid Accounts)
**Confidence:** MODERATE
**Rationale:** As written, this rule keys solely on the victim's own Instana tenant hostname plus the generic port 443 — no host-based discriminator despite the original title's "Non-Admin Host" claim. Durability governs over as-written precision (per the tiering rubric's tie-breaker): this fires identically for the victim organization's own designated Instana admin hosts and for any unauthorized host. Retained as Hunting rather than routed to the IOC feed, because the underlying literal is the victim's own asset and the campaign's disclosure policy excludes victim infrastructure from the public feed (see Coverage Gaps). Level demoted from `high` to `medium` to reflect the absence of any behavioral filter.
**False Positives:** MEDIUM-HIGH — this rule fires on every connection to the tenant domain, including the victim organization's own designated Instana operations hosts; an analyst must cross-reference hits against the operations team allow-list before treating any hit as suspicious.
**Deployment:** Network firewall logs; proxy logs; DNS resolver logs correlated with HTTPS egress. Deploy only within the victim organization's own environment.

```yaml
title: Outbound HTTPS to the Victim Organization OCP Instana Tenant
id: 024cd785-789d-4a99-8098-439f87c1df17
status: experimental
description: >-
  Detects outbound HTTPS connections to the the victim organization OCP-hosted Instana tenant
  wildcard domain (*.ocpinstana.[victim-domain].com.tr). The Turkish ARPA operator harvested
  victim observability data from this endpoint using a stolen 10-year-lifetime JWT. This
  selection has no host-based filter — it fires identically for designated Instana operations
  hosts and for unauthorized hosts — so hits must be triaged against the operations team
  allow-list before escalation. Scoped to the victim organization's own environment; the
  underlying hostname is excluded from the public IOC feed per the campaign's disclosure policy.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.stealth
    - attack.persistence
    - attack.privilege-escalation
    - attack.initial-access
    - attack.t1078
    - detection.emerging-threats
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|endswith: '.ocpinstana.[victim-domain].com.tr'
        DestinationPort: 443
    condition: selection
falsepositives:
    - Designated Instana operations team hosts performing authorized API queries — this rule does not distinguish them from unauthorized hosts and requires analyst triage against the allow-list
    - Automated monitoring tools with legitimate access to the Instana tenant
level: medium
```

#### Sigma Rule 7 — Observability Platform Authentication Event (Cross-Source Burst Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1078 (Valid Accounts), T1119 (Automated Collection), T1046 (Network Service Discovery)
**Confidence:** MODERATE — requires SIEM correlation across multiple observability platform audit feeds to realize the full novel-TTP detection value.
**Rationale:** The original rule's condition ANDed together four selections that each pin a different, mutually-exclusive value of the same `EventSource` field (e.g. `selection_instana and selection_solarwinds`) — a single log record cannot simultaneously carry two different `EventSource` values, so the original condition could never evaluate true on any event. This is dead logic, not merely broad logic, and has been corrected here to a satisfiable single-event selection (`1 of selection_*`) matching an authentication event on any one of the four platforms. Consistent with this file's own established pattern for Sigma Rule 8, this rule surfaces the per-event building block; the cross-platform correlation itself (the same source IP authenticating to 2+ of these platforms within a 10-minute window) still requires a SIEM-native correlation layer grouped by source IP, since this is broader and requires no proof of a second platform.
**False Positives:** MEDIUM — cross-platform integration tools (e.g., a legitimate SIEM or SOAR platform collecting from multiple APM sources via a centralized service account) will also match a single-platform authentication event; this rule is not meant to be alerted on standalone.
**Deployment:** SIEM correlation rule requiring audit log feeds from at least 2 of the listed platforms; requires observability platform audit export to be enabled. Deploy alongside a SIEM-native rule that counts distinct `EventSource` values per source IP within a 10-minute window — this Sigma rule alone only confirms that a qualifying event type occurred.

```yaml
title: Observability Platform API Authentication Event (Cross-Source Burst Building Block)
id: b5756186-42bf-480c-b343-423a35d27336
status: experimental
description: >-
  Detects an authentication event against one of four enterprise observability platforms
  (IBM Instana, SolarWinds Orion, Zabbix, VMware Aria). This is a single-event building block:
  the Turkish ARPA operator's Observability-Tool Reverse Pipeline TTP is defined by the SAME
  source IP authenticating against 2 or more of these platforms within a 10-minute window,
  which requires cross-event correlation that this per-event Sigma rule cannot itself express.
  Deploy alongside a SIEM-native correlation counting distinct EventSource values per source IP
  within a 10-minute window; a single match on this rule alone is common and not indicative of
  malicious activity. (Corrected from the original rule, whose condition ANDed together four
  selections that each require a different, mutually exclusive EventSource value on the SAME
  event record — logic that could never evaluate true on any single log event.)
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.collection
    - attack.t1119
    - attack.credential-access
    - attack.discovery
    - attack.t1046
    - detection.emerging-threats
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
    condition: 1 of selection_*
falsepositives:
    - Legitimate SIEM/SOAR platforms collecting from multiple APM sources via centralized service accounts — a single hit is common and requires the companion cross-source correlation before treating as suspicious
    - Any single legitimate authentication event to one of these platforms — this rule is a building block and should not be alerted on standalone
level: low
```

#### Sigma Rule 8 — Rapid Instana Topology API Enumeration from Single Source

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1046 (Network Service Discovery), T1213 (Data from Information Repositories), T1119 (Automated Collection)
**Confidence:** MODERATE — a single request is not by itself anomalous.
**Rationale:** Matches ANY request to Instana's own legitimate topology/event API paths — necessarily broad, since these are the platform's normal REST endpoints. The rule's own description already documents that it requires a SIEM-side rate threshold (10+ requests/minute from one source) to distinguish enumeration from ordinary interactive or single-agent use; unchanged from the original, which already carried an honest MEDIUM FP self-assessment.
**False Positives:** MEDIUM — legitimate automated monitoring tools may query the same API at high frequency; any single legitimate topology or event API query also matches this selection.
**Deployment:** Instana audit log export to SIEM; IBM Instana API analytics; rate-limiting alerts on the Instana tenant.

```yaml
title: Rapid Instana Topology API Enumeration Requests from Single Source
id: 43f7b91b-3870-4bd1-93c2-d364c8504a2e
status: experimental
description: >-
  Detects requests to IBM Instana topology and event APIs, the endpoints targeted by the
  Turkish ARPA operator's multi-worker polling pattern. A single request is not by itself
  anomalous; the operator's ARPA ETL platform runs 5 parallel systemd workers each polling
  the Instana API at 5-minute cadence, producing a burst that exceeds 10 requests per minute
  from a single source IP — well above normal interactive or single-agent query rates. This
  rule surfaces the underlying event for rate-based correlation in the SIEM layer — deploy
  alongside a per-source-IP request-rate threshold (10+/min) since Sigma's non-correlation
  rule format cannot itself express a count-over-time aggregation.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.collection
    - attack.t1119
    - attack.t1213
    - attack.discovery
    - attack.t1046
    - detection.emerging-threats
logsource:
    product: ibm_instana
    service: api_access_log
detection:
    selection:
        RequestPath|startswith:
            - '/api/events'
            - '/api/topology'
            - '/api/applications'
    condition: selection
falsepositives:
    - Authorized Instana integrations with high query frequency (verify against operations team allow-list)
    - Load testing or API validation tooling during maintenance windows
    - Any single legitimate topology or event API query — this rule requires rate-based correlation (10+ requests/min from one source IP) to distinguish enumeration activity from normal API use
level: medium
```

#### Sigma Rule 10 — Non-Splunk Process Connecting to Localhost Port 8089

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** MODERATE — port 8089 is not uniquely operator-specific.
**Rationale:** Keys on a single generic port literal (8089) with only a Splunk-process exclusion filter; other legitimate custom services can bind to the same port beyond just Splunk, which the original author already flagged as HIGH FP risk.
**False Positives:** HIGH — Splunk uses port 8089 for its management API by default (excluded here), but custom internal web services or other monitoring agents commonly use 8089 as a secondary management port too.
**Deployment:** Sysmon Event ID 3 (network connection); EDR network telemetry on Windows endpoints. Requires filtering for non-Splunk initiators; cross-reference hits against known internal services using this port before escalation.

```yaml
title: Non-Splunk Process Connecting to Localhost Port 8089 on Enterprise Windows Host
id: 47e5169f-572c-4d87-9fda-578a23e58beb
status: experimental
description: >-
  Detects processes other than Splunk (which legitimately uses port 8089 for management)
  initiating TCP connections to localhost port 8089 on enterprise Windows hosts. Port 8089
  is the insider-side tunnel bind point in the Turkish ARPA operator's reverse SSH tunnel
  architecture: traffic from localhost:8089 on the insider's machine is forwarded through
  the SSH reverse tunnel to the operator's listener on port 18080 at 209.38.205.158.
  Non-Splunk processes binding or connecting to this port in an enterprise context indicate
  tunnel activity, but the port is not unique to this campaign and requires triage.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.004
    - detection.emerging-threats
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

#### Sigma Rule 12 — Insider Deploying Outbound SSH Tunnel from Enterprise AD-Joined Workstation

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1021.004 (Remote Services: SSH)
**Confidence:** MODERATE
**Rationale:** A generalized, campaign-agnostic version of Sigma Rule 4 — no hardcoded operator IP, matching any SSH-family tool with a reverse-forwarding flag excluding naive RFC1918-ish substrings. The original author explicitly framed this as a "standing hunt rule," which this file's own MEDIUM FP self-assessment supports; level demoted from `high` to `medium` because the exclusion filter is a loose substring match (not a proper CIDR check) and legitimate developer tunneling can share the same flag pattern.
**False Positives:** MEDIUM — developers with legitimate remote-access needs may use SSH tunneling with the `-R` flag to authorized dev/staging servers; the naive substring exclusion (`10.`, `172.`, `192.168.`) can both under- and over-exclude destinations.
**Deployment:** Sysmon Event ID 1; Windows Security Event ID 4688; EDR process telemetry on AD-joined workstations.

```yaml
title: SSH Reverse Tunnel Established from Enterprise AD-Joined Windows Workstation
id: d49b3f9d-31e8-4ed8-8c62-87aba3aedd66
status: experimental
description: >-
  Detects SSH or PuTTY processes on enterprise AD-joined Windows workstations establishing
  reverse tunnel connections (-R flag) to external IP addresses. In the Turkish ARPA
  operator campaign, an insider (Windows AD user [employee ID — suppressed]) was supplied with operator-provided
  SSH keys and instructions to establish reverse tunnels from inside the victim organization's
  network to 209.38.205.158:18080. Reverse SSH tunnels from enterprise workstations to
  external IPs are a hunting-grade indicator of insider-facilitated external access
  regardless of the specific destination IP, but require triage against authorized
  developer tunneling use.
references:
    - https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.004
    - detection.emerging-threats
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
    filter_authorized_infra:
        CommandLine|contains:
            - '10.'
            - '172.'
            - '192.168.'
    condition: selection_ssh_tools and selection_reverse_flag and not filter_authorized_infra
falsepositives:
    - Authorized developers using reverse SSH tunnels for remote development (verify against IT-authorized tunneling policy and destination IP allow-list)
    - Remote support tools using SSH tunneling to authorized jump hosts
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### HTTP POST to ARPA Instana Ingestion Endpoint (IP-Agnostic)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1020 (Automated Exfiltration), T1041 (Exfiltration Over C2 Channel), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** Anchored on the operator-coined URI path `/api/ingest/instana`, not used by legitimate IBM Instana products. Retained without a destination-IP restriction so it continues to catch the ingestion pattern regardless of infrastructure rotation — strictly broader than (and here replaces) the original file's IP-scoped duplicate of the same signature (see Coverage Gaps).
**False Positives:** None known — the `/api/ingest/instana` URI path is operator-coined and not used by legitimate IBM Instana products (IBM's own ingestion endpoints use a different path structure).
**Blind Spots:** A rewritten collector using a different ingestion path, or TLS-only delivery (this rule matches cleartext HTTP), would evade; proxy TLS inspection is required for an encrypted variant.
**Validation:** Replay a cleartext HTTP POST to `/api/ingest/instana` against any destination — must fire; an unrelated HTTP POST to a different API path must NOT fire.
**Deployment:** Suricata on egress HTTP traffic; proxy with TLS inspection for encrypted variants.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL Turkish-ARPA-State-Insurer HTTP POST to ARPA Instana Ingestion Endpoint (Observability Data Exfiltration)"; http.method; content:"POST"; http.uri; content:"/api/ingest/instana"; startswith; flow:to_server,established; classtype:trojan-activity; sid:9001005; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/;)
```

### Hunting Rules

#### DNS Query Egress to the Victim Organization Instana Tenant

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1078 (Valid Accounts)
**Confidence:** MODERATE
**Rationale:** Keys solely on the victim's own redacted Instana tenant domain plus a threshold — no host-based discriminator. Structurally an atomic pattern, but the underlying literal is the victim's own asset and cannot be published to the public IOC feed per the campaign's disclosure policy (see Coverage Gaps). Retained as Hunting for the victim organization's own internal detection use; the original author already labeled this a "Hunting Baseline."
**False Positives:** MEDIUM — any internal host resolving this domain for legitimate Instana administration; suppress for designated Instana operations team hosts during triage.
**Deployment:** DNS resolver logging; network-level DNS capture; Suricata on egress DNS traffic. Deploy only within the victim organization's own environment.

```suricata
alert dns $HOME_NET any -> any any (msg:"THL Turkish-ARPA-State-Insurer DNS Query to Victim Instana OCP Tenant (Potential Unauthorized Collector Activity)"; dns.query; content:"ocpinstana.[victim-domain].com.tr"; nocase; threshold:type limit,track by_src,count 1,seconds 300; classtype:policy-violation; sid:9001001; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/turkish-arpa-openclaw-state-insurer-209.38.205.158-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (already present — no feed edits made).** Six rules from the original file keyed solely on one hard-coded, rotation-prone literal with no surviving behavioral discriminator once that literal is removed:
- **Sigma Rule 11** (`Outbound HTTP Connection to Turkish ARPA Platform Endpoints`) — bare match on the operator IP `209.38.205.158` plus a fixed port list (8090/8095/8096). Both the IP and its ports are already documented in [`turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json`](/ioc-feeds/turkish-arpa-openclaw-state-insurer-209.38.205.158-iocs.json) (`network_indicators.ipv4`).
- **Suricata sid 9001002** (`HTTP Egress to ARPA Operator Platform`) — matched the same operator IP plus a generic `/api/` URI substring, which adds no discriminating value on its own (it matches virtually any REST API traffic).
- **Suricata sid 9001004** (`Outbound SSH Connection to ARPA Operator VPS`) — matched the operator IP plus a bare port-22 SYN, with no application-layer discriminator (Suricata cannot inspect payload inside an encrypted SSH session).
- **Suricata sids 9001006, 9001007, 9001008** (`HTTP/DNS Egress to OpenClaw Distribution Domains`) — bare `content` matches on `openclaw.ai`, the Tencent skill-marketplace CDN, and `lightmake.site`. All three domains are already present in the feed's `network_indicators.domains` with `action: MONITOR`; the original author's own MODERATE confidence / MEDIUM-HIGH FP self-assessment ("OpenClaw domains alone don't prove malicious use") supports routing rather than retaining as standalone signatures.

**Cut outright (not routed to feed — no residual detection value).**
- **Suricata sid 9001003** (bundled under the original "Suricata Rule 2") duplicated the `/api/ingest/instana` URI-based POST detection with an unnecessary destination-IP restriction to `209.38.205.158`. The surviving Suricata Detection rule above (sid 9001005) implements the identical URI-based logic without that restriction and is therefore strictly broader — retaining both provided no additional coverage.
- **Suricata sid 9001009** (`Long-Lived SSH Session from Internal Windows Host to External IP`) was already withdrawn by a prior edit (2026-06-19) as overbroad — a flow-only `$HOME_NET -> $EXTERNAL_NET:22` match fires on all outbound SSH, including legitimate git-over-SSH and administration. It remains commented out in the source; no further action taken here beyond confirming the withdrawal rationale still holds.

**Victim-domain exception — why Sigma Rule 2 and the Suricata DNS rule are Hunting rather than atomic-routed.** Both key on the victim organization's own redacted Instana tenant hostname (`*.ocpinstana.[victim-domain].com.tr`) with no additional behavioral filter — structurally the same "bare domain" pattern as the routed atomics above. The difference: this hostname is the *victim's own asset*, not attacker-controlled infrastructure, and the campaign's disclosure policy (see the IOC feed's `metadata.notes`) explicitly excludes victim infrastructure from the public feed. Cutting these rules entirely would discard real governance/access-anomaly value for the one audience this restricted-distribution, per-case file explicitly serves — the victim organization's own IR team. Both rules are retained as Hunting with an explicit false-positives note that designated Instana admin hosts will also match and require triage.

The following techniques and detection surfaces were observed in malware-analyst findings but could not be covered with high-confidence, production-ready rules due to data availability or structural detection limitations. Each gap is documented with the evidence that was present and what additional data would enable rule creation.

### Gap 1 — LLM Vendor-Side Detection (Moonshot AI / Kimi)

**Technique:** T1587 (Develop Capabilities), novel AI-augmented-operator pattern
**Observed:** The operator uses Moonshot AI (Kimi) as the LLM backend per `IDENTITY.md` on the operator's host. All operator code shows the AI-Generated Code Signature (verbose docstrings, emoji-in-output bleed, indentation decay, version-numbered file persistence). The LLM vendor has unique visibility into the operator's prompt history.
**Why rules cannot be created:** Moonshot AI prompt telemetry is entirely within the LLM vendor's infrastructure — outside standard SOC detection scope. No network-observable indicator specifically identifies which prompts are malicious vs. legitimate.
**What would enable detection:** Moonshot AI vendor telemetry sharing (coordinated disclosure to Moonshot AI / Beijing Moonshot AI Technology Co., Ltd.); vendor-side abuse pattern analysis; cross-account correlation within the Moonshot AI platform.

### Gap 2 — Insider-Detection Inside Victim AD Environment

**Technique:** T1199 (Trusted Relationship), T1078.002 (Domain Accounts), T1098.004 (SSH Authorized Keys)
**Observed:** The operator recruited a specifically-named Windows AD user (`[employee ID — suppressed]`) at the victim organization. The insider's activities inside the victim network (file creation, SSH tool usage, registry changes) are detectable only from inside the victim's AD domain with adequate Sysmon/EDR coverage.
**Why rules cannot be created at this stage:** Sigma Rules 4, 5, and 9 (Detection tier) and Sigma Rules 10 and 12 (Hunting tier) in this file cover the observable host-level indicators; however, the most valuable detection data (AD authentication logs, lateral movement inside the network, file access to internal resources) requires victim-org cooperation and access to their internal SIEM/EDR. External third-party detection of insider behavior is structurally limited to network-egress and DNS patterns — both of which are covered in the Suricata rules.
**What would enable detection:** Victim-org IR engagement; preservation and sharing of Windows AD audit logs for the `[employee ID — suppressed]` account (2026-03-01 → present); Sysmon deployment retrospective on the insider's workstation.

### Gap 3 — Cross-Source ETL Detection Prior to Export

**Technique:** T1119 (Automated Collection), T1213 (Data from Information Repositories), novel Observability-Tool Reverse Pipeline TTP
**Observed:** The operator's cross-source ETL ingests data from all four observability sources (Instana + SolarWinds + Zabbix + VMware Aria) and correlates them into `unified_cross_source_topology.json`. The export/exfiltration event is detectable via the Suricata Detection rule above (HTTP POST to the ARPA ingestion endpoint). However, the collection event within each platform (normal API calls using stolen credentials that look identical to legitimate admin calls) is undetectable without cross-platform correlation context.
**Why rules cannot be created:** Individual API calls to each platform using valid stolen credentials are indistinguishable from legitimate admin access at the single-platform level. Detection requires cross-platform correlation that most victim orgs cannot execute without SIEM integration across all four observability platform audit feeds simultaneously. Sigma Rule 7 (Hunting tier, corrected in this backfill) surfaces the qualifying per-event building block but cannot itself express the cross-event, cross-platform correlation — that requires a SIEM-native rule counting distinct `EventSource` values per source IP within a time window, layered on top of Sigma Rule 7.
**What would enable detection:** IBM Instana audit log integration to SIEM; SolarWinds Orion API audit log export; Zabbix audit log SIEM integration; VMware Aria audit event export. The cross-source authentication-burst correlation becomes operative once at least two of these feeds are integrated and a SIEM-native correlation rule is layered on top of Sigma Rule 7.

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
**Why rules cannot be created for the AI query session itself:** When functional, the AI query sessions would consist of natural-language HTTP requests to the operator's own platform on `localhost` (or via the reverse tunnel). These are operator-internal and invisible to external detection. The only detectable artifact is the `ai_assistant.db` database presence (covered by YARA Rule 5, Hunting tier) and the broken-state Python traceback in `ai_service.log` (covered by YARA Rule 2, Detection tier, via the file path pattern).
**What would enable better coverage:** N=2 validation of the AI-Augmented Reconnaissance TTP across a second independent operator; analysis of a functional AI service session to characterize its network I/O patterns (LLM API calls to Moonshot AI, database queries, response formatting); operator-host access log export if the service becomes functional.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
