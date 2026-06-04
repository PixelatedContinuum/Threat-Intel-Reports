---
title: "Detection Rules — Russian Gemini Credential Mill (213.165.51.115)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
hide: true
---

**Campaign:** Russian-Gemini-Credential-Mill-UTA-2026-012-213.165.51.115
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/russian-gemini-credential-mill-213.165.51.115/

> **Calibration / Prior-Art Note:** Trend Micro (TrendAI Research) published independent coverage of this same operator on 2026-05-22 ("One Man, One AI, One Fake Persona: Inside the 5-Year Influence and Fraud 'Patriot Bait' Campaign"; operator tracked as "bandcampro"). Cross-identification is DEFINITE via five-point IOC match: `@americanpatriotus` Telegram channel, 73 stolen Gemini API keys in operator inventory, 20-mutation-per-target generation, Quantum Patriot pipeline branding, and `GEMINI.md` jailbreak-persistence file. Rules in this file complement the Trend Micro coverage with per-case source-code-derived signatures not previously published. **AI Operator Handoff Document novelty MAINTAINED** (Trend Micro covers `GEMINI.md` jailbreak persistence; architecturally distinct from the operator-authored `C2_INFRA_TRANSFER.md / DEPLOYED_TOOLS.md / C2_MIGRATION_GUIDE.md` structured session-handoff documents). **LLM Credential Mutation novelty REFRAMED** as first source-code analysis with verbatim prompt reproduction (operational pattern independently confirmed by Trend Micro). **Unauthenticated Python-stdlib C2**: no prior art found in either publication.

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 8 | T1587, T1059.006, T1027, T1071.001, T1547.001 | LOW–MEDIUM |
| Sigma | 12 | T1071.001, T1547.001, T1090.004, T1110.003, T1555.005, T1003.002, T1041, T1102 | LOW–MEDIUM |
| Suricata | 6 | T1071.001, T1090.004, T1572, T1568 | LOW |

**Total rules:** 26 across 3 detection layers.

**Deployment priority:** Rules marked HIGH should be deployed first and are suitable for production alerting. Rules marked MEDIUM require environment-specific tuning (particularly server-class host scoping). Rules marked LOW are hunting baselines that produce meaningful signal only in targeted threat-hunting campaigns.

**Cross-campaign deduplication:** Rules already covered at the parent campaign level (`ai-agent-frameworks-2026-05-23-detections.md`) are not duplicated here. This file goes deeper on Case 1 operator-specific indicators: `A2A C2 MULTI-AGENT CONSOLE` string, Gemini role-priming prompts, `X-Agent-ID` header format, `tralalarkefe.com` infrastructure, Russian-language operator persona strings, and AntiPublic.one integration.

---

## YARA Rules

/*
   Yara Rule Set
   Identifier: Russian Gemini Credential Mill — UTA-2026-012 (Case 1, ai-agent-frameworks-2026-05-23)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

### Rule 1 — LLM-Personalized Credential Mutator Family

**Detection Priority:** HIGH
**Rationale:** Detects `ai_sniper_brute.py`-class scripts by the distinctive combination of the Gemini API import, the verbatim role-priming prompt fragment, the per-target input structure (email + domain + password), and the operator-self-named output file convention. The "Act as an expert red-team password analyst" phrase combined with a Gemini API import is the highest-signal single-artifact indicator of this novel TTP — it has not appeared in any prior public YARA rule corpus.
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python), T1587 (Develop Capabilities)
**Confidence:** HIGH
**False Positive Risk:** LOW — The combination of a Gemini API client import, the exact role-priming phrase, and an AI mutation output filename pattern has negligible legitimate-software overlap. Red-team tools that use LLMs for password mutation are themselves malicious tradecraft; the rule intentionally covers that broader class.
**Deployment:** Endpoint AV/EDR file scan, SIEM file-creation alert, git-hook pre-commit scan on CI/CD pipelines, developer workstation endpoint protection

```yara
rule MAL_Python_LLMPersonalized_Credential_Mutator_Family {
   meta:
      description = "Detects ai_sniper_brute.py-class Python scripts using Gemini API for LLM-personalized per-target password mutation — verbatim role-priming prompt + AI_SNIPER output naming convention captured from UTA-2026-012 open-directory 213.165.51.115"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "LLM-Personalized-Credential-Mutator"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "be090723-71dc-5fb3-955b-c006a4228b56"
   strings:
      $gemini_import  = "google.generativeai" ascii
      $role_prime     = "Act as an expert red-team password analyst" ascii
      $prompt_field1  = "Most Recent Password from dump:" ascii
      $prompt_field2  = "generate exactly 20 likely current mutations" ascii
      $output_sniper  = "AI_SNIPER_GOODS" ascii
      $output_mutants = "AI_ADMIN_MUTANTS" ascii
      $target_file    = "ULTRA_GOLD_TARGETS" ascii
      $success_fmt    = "[+++ AI SUPER GOOD +++]" ascii
   condition:
      filesize < 1MB and
      $gemini_import and
      ($role_prime or $prompt_field1 or $prompt_field2) and
      1 of ($output_sniper, $output_mutants, $target_file, $success_fmt)
}
```

---

### Rule 2 — AI Operator Handoff Document Family

**Detection Priority:** HIGH
**Rationale:** Detects the three documented AI Operator Handoff Document exemplars (`C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md`, `DEPLOYED_TOOLS.md`) and the broader pattern of operator-authored Markdown files intended for AI session priming. The combination of a session-start load directive with operational content (C2 endpoints or credential tables) is the novel-TTP detection signature. This class has no prior YARA coverage.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1071.001 (Web Protocols — C2 endpoint references within the document)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — AI-assisted documentation that contains `When starting a new session` is used by legitimate AI-augmented development workflows (e.g., `CLAUDE.md` project files). The rule is tuned to require co-occurrence with operational content markers (C2 endpoint patterns or credential-table indicators) to suppress these FPs. Deploy with content-type filter: `.md` files in `~/.gemini/`, `~/.claude/`, `~/.codex/` directories on server-class hosts are higher-risk than on developer workstations.
**Deployment:** Endpoint file-creation monitoring, filesystem hunt on server-class Linux hosts, git-repo secret-scanning pipeline

```yara
rule MAL_Markdown_AI_Operator_Handoff_Document_Family {
   meta:
      description = "Detects operator-authored AI Operator Handoff Documents — Markdown files containing session-start load directives co-occurring with C2 endpoint references or credential-table patterns. Three exemplars from UTA-2026-012: C2_MIGRATION_GUIDE.md, C2_INFRA_TRANSFER.md, DEPLOYED_TOOLS.md"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "AI-Operator-Handoff-Document"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "5cc8d013-d78a-5b62-982a-b92fc7ff0a55"
   strings:
      $session_directive  = "When starting a new session, refer to this file" ascii nocase
      $knowledge_xfer     = "KNOWLEDGE TRANSFER:" ascii nocase
      $to_gemini_cli      = "**To:** Gemini CLI" ascii
      $from_gemini_cli    = "**From:** Gemini CLI" ascii
      $migration_guide    = "C2_MIGRATION_GUIDE" ascii
      $infra_transfer     = "C2_INFRA_TRANSFER" ascii
      $deployed_tools     = "DEPLOYED_TOOLS" ascii
      $api_v1_update      = "/api/v1/update" ascii
      $api_v1_interact    = "/api/v1/interact" ascii
      $cf_tunnel_pattern  = "cloudflared access tcp" ascii
      $agent_id_format    = "X-Agent-ID" ascii
   condition:
      filesize < 100KB and
      (
         ($to_gemini_cli and $from_gemini_cli) or
         $session_directive or
         ($knowledge_xfer and ($migration_guide or $infra_transfer or $deployed_tools))
      ) and
      1 of ($api_v1_update, $api_v1_interact, $cf_tunnel_pattern, $agent_id_format)
}
```

---

### Rule 3 — Stolen LLM API Key Validator

**Detection Priority:** HIGH
**Rationale:** Detects `check_keys.py`-class scripts containing bulk Gemini API key inventories (40+ keys in a triple-quoted Python string block) validated against the Generative Language API model-listing endpoint. The `AIzaSy` prefix regex combined with the validation endpoint string and MD5-based key-state tracking is the operator's own pattern for rotating stolen keys without re-testing already-confirmed ones.
**ATT&CK Coverage:** T1078 (Valid Accounts — stolen API keys), T1059.006 (Python), T1552.001 (Unsecured Credentials in Files)
**Confidence:** HIGH
**False Positive Risk:** LOW — A script containing 40+ Gemini API keys in a block string with a validation loop against Google's models endpoint is not a legitimate development pattern. Legitimate SDK usage embeds one key per configuration; bulk-key validators are intrinsically malicious tooling. Narrow FP surface: internal key-rotation test harnesses at API-reseller companies; these can be allowlisted by path/author.
**Deployment:** Endpoint AV/EDR file scan, SIEM file-creation monitoring, developer workstation endpoint protection, CI/CD secret scanning

```yara
rule MAL_Python_Stolen_LLM_Key_Validator {
   meta:
      description = "Detects check_keys.py-class Python scripts: bulk Gemini API key inventory (AIzaSy-prefixed keys in block string) validated against generativelanguage.googleapis.com/v1beta/models — stolen-key validation pipeline from UTA-2026-012"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "Stolen-LLM-Key-Validator"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "37ec0969-e2c8-5e91-b5a1-40d75c43d590"
   strings:
      $key_prefix_re    = "AIzaSy[0-9a-zA-Z_-]" ascii
      $raw_keys_block   = "raw_keys" ascii fullword
      $validation_ep    = "generativelanguage.googleapis.com/v1beta/models" ascii
      $findall_pattern  = "re.findall" ascii
      $valid_keys_out   = "valid_gemini_keys" ascii
      $openai_key       = "sk-proj-" ascii
      $venice_key       = "VENICE_ADMIN_KEY" ascii
      $retest_pattern   = "retest_keys" ascii
   condition:
      filesize < 500KB and
      $key_prefix_re and
      ($raw_keys_block or $findall_pattern) and
      ($validation_ep or $valid_keys_out or $retest_pattern) and
      2 of ($key_prefix_re, $raw_keys_block, $validation_ep, $valid_keys_out, $openai_key, $venice_key, $retest_pattern)
}
```

---

### Rule 4 — A2A C2 Server (Unauthenticated Python stdlib)

**Detection Priority:** HIGH
**Rationale:** Detects `c2_server.py`-class scripts — operator-built Python stdlib HTTP C2 servers with zero authentication, the operator's bespoke `/api/v1/` endpoint set, base64+UTF-16LE encoding, and `BaseHTTPRequestHandler` as the server base class. The combination of the five specific endpoint paths, the "A2A C2 MULTI-AGENT CONSOLE" banner string, and the UTF-16LE decode call is essentially a fingerprint of this specific operator's framework.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1087 (Account Discovery — `/api/v1/agents` dumps all beacons)
**Confidence:** HIGH
**False Positive Risk:** LOW — No legitimate web application framework uses `BaseHTTPServer.BaseHTTPRequestHandler` with this exact set of `/api/v1/` paths and UTF-16LE body decoding. The banner string "A2A C2 MULTI-AGENT CONSOLE" is the operator's own term for their framework and has no legitimate-software counterpart.
**Deployment:** Endpoint AV/EDR file scan, server-side file integrity monitoring, threat hunting on Linux server filesystems

```yara
rule MAL_Python_A2A_C2_Server_Unauthenticated {
   meta:
      description = "Detects c2_server.py-class Python stdlib unauthenticated C2 servers — BaseHTTPRequestHandler with /api/v1/{update,agents,interact,telemetry} endpoints, base64+UTF-16LE body decoding, zero auth — operator-built A2A C2 framework from UTA-2026-012"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "A2A-C2-Server-Unauthenticated"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "a153389d-4f2f-5432-888b-f920813c333a"
   strings:
      $banner        = "A2A C2 MULTI-AGENT CONSOLE" ascii fullword
      $handler_base  = "BaseHTTPRequestHandler" ascii
      $ep_update     = "/api/v1/update" ascii
      $ep_agents     = "/api/v1/agents" ascii
      $ep_interact   = "/api/v1/interact" ascii
      $ep_telemetry  = "/api/v1/telemetry" ascii
      $ep_results    = "/api/v1/get_results" ascii
      $utf16_decode  = "decode('utf-16le')" ascii
      $b64_decode    = "base64.b64decode" ascii
      $payload_dir   = "PAYLOAD_DIR" ascii
   condition:
      filesize < 500KB and
      ($banner or ($handler_base and 3 of ($ep_update, $ep_agents, $ep_interact, $ep_telemetry, $ep_results))) and
      ($utf16_decode or $b64_decode) and
      1 of ($ep_update, $ep_agents, $ep_interact, $ep_telemetry)
}
```

---

### Rule 5 — A2A C2 Client Console / Exec Tool

**Detection Priority:** HIGH
**Rationale:** Detects `console.py` and `exec.py`-class operator-side C2 client tools. The diagnostic combination is the `X-Agent-ID` bespoke header, UTF-16LE encoding of commands before POST, and polling of `/api/v1/get_results`. The `HOSTNAME_user` agent-ID format combined with the "A2A C2" banner is essentially unique to this operator framework.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1059.006 (Python)
**Confidence:** HIGH
**False Positive Risk:** LOW — The `X-Agent-ID` header name combined with the `HOSTNAME_user` format string and UTF-16LE encoding before HTTP POST is not a pattern found in any legitimate Python HTTP client library or application framework.
**Deployment:** Endpoint AV/EDR file scan, server-side file integrity monitoring, threat hunting on Linux operator-side hosts

```yara
rule MAL_Python_A2A_C2_Client_Console {
   meta:
      description = "Detects console.py/exec.py-class operator-side C2 client tools — X-Agent-ID header, HOSTNAME_user agent-ID format, base64+UTF-16LE command encoding, /api/v1/interact POST + /api/v1/get_results polling — A2A C2 framework from UTA-2026-012"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "A2A-C2-Client-Console"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "a96925a2-ef70-50d3-ab9b-1bd8581523e3"
   strings:
      $agent_id_header   = "X-Agent-ID" ascii fullword
      $encode_utf16le    = "encode('utf-16le')" ascii
      $ep_interact       = "/api/v1/interact" ascii
      $ep_get_results    = "/api/v1/get_results" ascii
      $ep_agents         = "/api/v1/agents" ascii
      $banner            = "A2A C2 MULTI-AGENT CONSOLE" ascii
      $hostname_user_fmt = "HOSTNAME_user" ascii
      $poll_sleep        = "time.sleep(2)" ascii
   condition:
      filesize < 200KB and
      $agent_id_header and
      ($encode_utf16le or $ep_interact or $ep_get_results) and
      1 of ($banner, $hostname_user_fmt, $ep_agents, $poll_sleep)
}
```

---

### Rule 6 — C2_INFRA_TRANSFER Explicit AI-to-AI Header (Narrow / Highest Fidelity)

**Detection Priority:** HIGH
**Rationale:** Narrowest and highest-fidelity rule in this set. The literal `**To:** Gemini CLI` / `**From:** Gemini CLI` header combination on a Markdown file is first-publication as a named YARA signature for the AI Operator Handoff Document TTP. This exact header pattern is specific to the `C2_INFRA_TRANSFER.md` exemplar from UTA-2026-012 and its descendants. Any file matching this pattern warrants immediate investigation — it is a deliberate operator artifact, not an incidental string.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1071.001 (Web Protocols — C2 references)
**Confidence:** HIGH
**False Positive Risk:** LOW — The `**To:** Gemini CLI` / `**From:** Gemini CLI` combination is not used by any legitimate Gemini CLI documentation, Google SDK examples, or standard developer workflow. Markdown inter-document correspondence using the Gemini CLI as both sender and recipient is a novel operator-invented convention.
**Deployment:** Endpoint file-creation monitoring, SIEM filesystem alert, threat hunting in `~/.gemini/`, `~/.claude/`, `~/.codex/` directories on server-class hosts

```yara
rule MAL_Markdown_C2_INFRA_TRANSFER_Pattern {
   meta:
      description = "Narrow high-fidelity detection on the explicit 'To: Gemini CLI / From: Gemini CLI' header convention from C2_INFRA_TRANSFER.md — first-publication YARA signature for the AI Operator Handoff Document TTP (UTA-2026-012)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "AI-Operator-Handoff-Document"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "e1a18404-2ded-5aec-93f6-33180c0f5499"
   strings:
      $to_gemini   = "**To:** Gemini CLI" ascii
      $from_gemini = "**From:** Gemini CLI" ascii
      $subject_kw  = "**Subject:**" ascii
      $new_session = "When starting a new session" ascii
      $bro_ru      = "\xd0\x91\xd1\x80\xd0\xbe" /* "Бро" UTF-8 */ ascii wide
   condition:
      filesize < 100KB and
      (
         ($to_gemini and $from_gemini) or
         ($new_session and ($to_gemini or $from_gemini or $subject_kw))
      )
}
```

---

### Rule 7 — PowerShell WindowsUpdateManager Stealer Loader

**Detection Priority:** HIGH
**Rationale:** Detects the operator's persistence-layer PowerShell script (`WindowsUpdateManager.ps1`) based on the operator-bespoke registry value name, the `%LOCALAPPDATA%\Microsoft\` deployment path, and the Cloudflare Tunnel C2 callback pattern. `WindowsUpdateManager` under `HKCU\Run` is a deliberate Windows Update component masquerade; legitimate Windows Update processes do not run under HKCU Run keys. The co-occurrence of this value name with a `tralalarkefe.com` or `payloads.*` URL fetch is high-confidence operator-bound persistence.
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036 (Masquerading), T1105 (Ingress Tool Transfer), T1059.001 (PowerShell)
**Confidence:** HIGH
**False Positive Risk:** LOW — `WindowsUpdateManager` as an HKCU\Run value name with a Cloudflare Tunnel C2 URL is not a pattern found in any legitimate Windows Update or Windows Defender component. The operator chose this masquerade name deliberately; its presence in a Run key combined with any C2 callback URL is a detection-grade signal.
**Deployment:** Endpoint AV/EDR file scan, PowerShell script-block logging (Event 4104), file integrity monitoring on `%LOCALAPPDATA%\Microsoft\`

```yara
rule MAL_PowerShell_WindowsUpdateManager_Stealer_Loader {
   meta:
      description = "Detects WindowsUpdateManager.ps1 — operator-bespoke persistence script masquerading as Windows Update component; HKCU Run key value + %LOCALAPPDATA%\\Microsoft\\ path + Cloudflare Tunnel C2 callback to tralalarkefe.com — UTA-2026-012"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "A2A-C2-PowerShell-Loader"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "e7afacdf-0b30-5da9-830f-e8a17a4d7214"
   strings:
      $reg_value       = "WindowsUpdateManager" ascii wide fullword
      $local_path      = "Microsoft\\WindowsUpdateManager.ps1" ascii wide
      $run_key         = "CurrentVersion\\Run" ascii wide
      $c2_domain       = "tralalarkefe.com" ascii wide
      $payload_domain  = "payloads.tralalarkefe.com" ascii wide
      $tls12_set       = "SecurityProtocol" ascii wide
      $invoke_rest     = "Invoke-RestMethod" ascii wide
      $agent_id_hdr    = "X-Agent-ID" ascii wide
      $update_endpoint = "/api/v1/update" ascii wide
   condition:
      filesize < 2MB and
      $reg_value and
      ($local_path or $run_key) and
      1 of ($c2_domain, $payload_domain, $update_endpoint, $agent_id_hdr)
}
```

---

### Rule 8 — Russian Operator Persona Strings

**Detection Priority:** MEDIUM
**Rationale:** Detects operator-authored files containing Cyrillic persona strings observed in handoff documents and session JSONs — `Братух` (informal "Bro" used to address Gemini), `Комп Доктора` ("Doctor's PC" referring to a victim machine), `Погнали` ("Let's go" — operator's session-start idiom), `тачка` ("machine/computer" slang). These strings co-occurring with operational content (C2 endpoint references, API key patterns, credential formats) in a single file is a high-confidence attribution signal for UTA-2026-012 activity specifically. Standalone these strings appear in legitimate Russian-language content; the operational co-occurrence is the detection trigger.
**ATT&CK Coverage:** T1587 (Develop Capabilities — operator infrastructure docs)
**Confidence:** MODERATE
**False Positive Risk:** HIGH (standalone), LOW (with operational co-occurrence condition). Deploy only with the composite condition — the rule is structured to require Cyrillic persona strings co-occurring with C2 or credential indicators.
**Deployment:** Threat hunting on server-class Linux hosts, forensic investigation of seized operator infrastructure, post-incident artifact analysis

```yara
rule MAL_Russian_Operator_Persona_Strings {
   meta:
      description = "Detects UTA-2026-012 operator-authored files via Cyrillic persona strings (Братух/Бро addressing of Gemini, Комп Доктора victim-machine reference) co-occurring with C2 endpoint or API key indicators — high-specificity attribution aid for post-incident forensics"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/"
      date = "2026-05-25"
      family = "A2A-C2-Operator-Attribution"
      campaign = "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115"
      id = "cc850da5-6d7d-51f3-8d01-7c5024b30ba1"
   strings:
      /* Cyrillic persona strings — UTF-8 encoded */
      $bro_bratukh     = "\xd0\x91\xd1\x80\xd0\xb0\xd1\x82\xd1\x83\xd1\x85" /* "Братух" */
      $comp_doktora    = "\xd0\x9a\xd0\xbe\xd0\xbc\xd0\xbf \xd0\x94\xd0\xbe\xd0\xba\xd1\x82\xd0\xbe\xd1\x80\xd0\xb0" /* "Комп Доктора" */
      $pognali         = "\xd0\x9f\xd0\xbe\xd0\xb3\xd0\xbd\xd0\xb0\xd0\xbb\xd0\xb8" /* "Погнали" */
      $quantum_patriot = "quantum_patriot" ascii
      $gemini_api_key  = "AIzaSy" ascii
      $api_endpoint    = "/api/v1/" ascii
      $cf_tunnel       = "tralalarkefe.com" ascii
      $sniper_goods    = "AI_SNIPER_GOODS" ascii
   condition:
      filesize < 5MB and
      1 of ($bro_bratukh, $comp_doktora, $pognali) and
      1 of ($gemini_api_key, $api_endpoint, $cf_tunnel, $sniper_goods, $quantum_patriot)
}

---

## Sigma Rules

### Rule 1 — Gemini API Egress from Server-Class Hosts

**Detection Priority:** HIGH
**Rationale:** Outbound HTTPS to `generativelanguage.googleapis.com` from server infrastructure (not developer workstations) is the stolen-key validation signature for `check_keys.py` and the LLM credential mutation pipeline. Legitimate server-side use of the Gemini API exists (ML inference services, chatbot backends) but is expected to use a single stable API key, not a rotating pool. High-frequency model-listing endpoint queries (`/v1beta/models`) from the same source IP with key diversity are the operator's validation pattern. This rule fires on any server-class egress to this domain as a hunting baseline — tune to alert only for key-rotation-frequency patterns in enriched environments.
**ATT&CK Coverage:** T1078 (Valid Accounts — stolen API key validation), T1059.006 (Python)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Legitimate ML inference backend servers make outbound calls to this domain. Tune by adding allowlist for known ML-service hosts and by alerting only when the same source IP queries the `/v1beta/models` endpoint more than 10 times within 60 seconds (key-rotation pattern vs single-key legitimate use).
**Deployment:** Network proxy logs, Zeek ssl.log, DNS resolver logs

```yaml
title: Gemini API Egress from Server-Class Infrastructure Host
id: 173cf9ee-97c5-4d51-8487-856f63894ad5
status: test
description: >-
  Detects outbound HTTPS connections to generativelanguage.googleapis.com from server-class
  hosts (non-developer workstations). From server infrastructure, this pattern indicates
  stolen Gemini API key validation (check_keys.py-class tools) or LLM-personalized credential
  mutation (ai_sniper_brute.py-class tools) — both documented in UTA-2026-012 open-directory
  213.165.51.115. Legitimate ML inference backend servers should be added to an allowlist.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.credential-access
    - attack.resource-development
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationHostname|endswith:
            - 'generativelanguage.googleapis.com'
            - '.generativelanguage.googleapis.com'
    filter_known_ml_services:
        Image|contains:
            - '/usr/bin/python'
            - 'jupyter'
            - 'notebook'
    condition: selection and not filter_known_ml_services
falsepositives:
    - Legitimate ML inference backend services calling the Gemini API — add known ML-service hosts to allowlist
    - Google Cloud SDK operations on GCP-hosted infrastructure
    - Developer workstations (scope rule to server-class hosts by IP range or asset tag)
level: medium
```

---

### Rule 2 — Gemini CLI Directory Created on Server Host

**Detection Priority:** HIGH
**Rationale:** The `~/.gemini/` directory being created on a server-class Linux host is an operator-side installation signal. The operator's AI Operator Handoff Documents reference `~/.gemini/skills/cf-c2-manager/`, `~/.gemini/GEMINI.md`, and `~/.gemini/tmp/root/chats/` (session JSON storage). None of these paths exist in legitimate server deployments. Executable content (`.sh`, `.py`) created within `~/.gemini/` on a server is a higher-confidence sub-indicator.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python)
**Confidence:** HIGH
**False Positive Risk:** LOW on server-class hosts. MEDIUM on developer workstations (Gemini CLI is a legitimate developer tool). Scope this rule to server-class infrastructure by asset group or IP range.
**Deployment:** Sysmon (Linux), auditd, file-integrity monitoring

```yaml
title: Gemini CLI Directory Creation with Executable Contents on Server Host
id: dca5d3c0-5b22-453e-a36f-7696d927a739
status: test
description: >-
  Detects creation of ~/.gemini/ directory containing executable scripts (.sh, .py) or
  AI-priming documents on server-class Linux hosts. The UTA-2026-012 operator stores C2
  management skills (~/.gemini/skills/cf-c2-manager/SKILL.md), session handoff documents
  (~/.gemini/GEMINI.md), and Gemini CLI session JSONs (~/.gemini/tmp/root/chats/) on the
  C2 server itself. Legitimate Gemini CLI usage on servers is uncommon; co-location with
  operational scripts is a high-confidence operator signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.persistence
    - attack.resource-development
logsource:
    category: file_event
    product: linux
detection:
    selection_gemini_dir:
        TargetFilename|contains: '/.gemini/'
    selection_executable:
        TargetFilename|endswith:
            - '.sh'
            - '.py'
            - '.ps1'
            - 'GEMINI.md'
            - 'SKILL.md'
    condition: selection_gemini_dir and selection_executable
falsepositives:
    - Legitimate Gemini CLI usage by developers on developer workstations — scope rule to server-class hosts only
    - Google Cloud Workstations with Gemini CLI installed by default
level: medium
```

---

### Rule 3 — Cloudflare Tunnel Registration to tralalarkefe.com

**Detection Priority:** HIGH
**Rationale:** `cloudflared access tcp --hostname *.tralalarkefe.com` process execution on any host is a direct indicator of UTA-2026-012 operator infrastructure activity — either the operator's own server registering a victim-access tunnel or a victim-side beacon re-registration event. `tralalarkefe.com` is the operator's bespoke domain with no legitimate use.
**ATT&CK Coverage:** T1090.004 (Domain Fronting — Cloudflare Tunnel), T1572 (Protocol Tunneling)
**Confidence:** HIGH
**False Positive Risk:** LOW — `tralalarkefe.com` has no documented legitimate use. Any `cloudflared` invocation referencing this domain warrants immediate investigation.
**Deployment:** Sysmon Event ID 1 / auditd execve, EDR process-creation telemetry

```yaml
title: Cloudflare Tunnel Registration to tralalarkefe.com Operator Infrastructure
id: 1003c111-2038-43bc-b463-b5895cd6f408
status: test
description: >-
  Detects cloudflared process invocations referencing the UTA-2026-012 operator's bespoke
  Cloudflare Tunnel domain tralalarkefe.com or its documented subdomains (c2, payloads,
  windows_server, gil_dr1, catchall1, 10101). cloudflared access tcp --hostname *.tralalarkefe.com
  was observed in operator-side ps output captured from session JSON 2026-03-19T22-26-389c5d67.
  Any host executing cloudflared with this domain should be treated as compromised or operator-side.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.command-and-control
    - attack.defense-evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/cloudflared'
        CommandLine|contains: 'tralalarkefe.com'
    condition: selection
falsepositives:
    - None expected — tralalarkefe.com has no documented legitimate use
level: high
```

---

### Rule 4 — cloudflared access tcp to Unapproved Hostname (Org Allowlist Bypass)

**Detection Priority:** MEDIUM
**Rationale:** The operator uses `cloudflared access tcp --hostname <victim-tunnel>.tralalarkefe.com` to maintain persistent reverse-access tunnels to victim machines without exposing the victim IP. This Sigma rule fires on any `cloudflared access tcp` invocation on server-class Linux hosts where the hostname argument does not match an organizational allowlist. Defenders can populate the allowlist filter with their known legitimate Cloudflare Tunnel hostnames.
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1572 (Protocol Tunneling), T1021.001 (RDP via tunnel), T1021.004 (SSH via tunnel)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — Organizations with legitimate Cloudflare Tunnel deployments will generate FPs. Tune by populating the allowlist filter with known-legitimate tunnel hostnames. Alert only on `cloudflared access tcp` (the operator's victim-access tunnel command) rather than `cloudflared tunnel run` (the service-side registration command).
**Deployment:** auditd execve, Sysmon (Linux), EDR process-creation on server-class hosts

```yaml
title: Cloudflared Access TCP Tunnel to Potentially Unauthorized Hostname
id: 57ce00ce-d1ee-4621-9654-cefb4bf3b60d
status: test
description: >-
  Detects cloudflared access tcp invocations on Linux server-class hosts referencing hostnames
  outside an organizational allowlist. The UTA-2026-012 operator used cloudflared access tcp
  --hostname windows_server.tralalarkefe.com and --hostname gil_dr1.tralalarkefe.com to
  maintain persistent reverse-TCP tunnels to the victim machines for RDP and SSH.
  This pattern allows persistent victim access without victim-side firewall rule changes.
  Tune by adding your organization's known legitimate Cloudflare Tunnel hostnames to the
  allowlist filter below.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.command-and-control
    - attack.lateral-movement
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/cloudflared'
        CommandLine|contains|all:
            - 'access'
            - 'tcp'
            - '--hostname'
    filter_known_legit:
        CommandLine|contains:
            - 'your-org-tunnel.example.com'  # REPLACE with org's known CF Tunnel hostnames
    condition: selection and not filter_known_legit
falsepositives:
    - Legitimate organizational Cloudflare Tunnel deployments — populate the allowlist filter with known tunnel hostnames
    - Developer workstations running cloudflared for legitimate service exposure
level: medium
```

---

### Rule 5 — PowerShell WindowsUpdateManager Registry Run Key Persistence

**Detection Priority:** HIGH
**Rationale:** Registry write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager` is the operator's victim-side persistence mechanism documented in `C2_INFRA_TRANSFER.md`. Legitimate Windows Update components do not create HKCU Run keys; the `WindowsUpdateManager` value name is the operator's own masquerade choice. The file path `%LOCALAPPDATA%\Microsoft\WindowsUpdateManager.ps1` pointing to a PowerShell script in a Microsoft-named subfolder amplifies the masquerade.
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036 (Masquerading), T1059.001 (PowerShell)
**Confidence:** HIGH
**False Positive Risk:** LOW — No legitimate Windows component writes `WindowsUpdateManager` to a HKCU Run key. The name is intentionally close to legitimate Windows Update services but structurally incorrect (HKCU scope, PowerShell script, non-standard path format). Alert with HIGH priority on first match.
**Deployment:** Sysmon Event ID 13 (registry value set), Windows Event ID 4657, EDR registry monitoring

```yaml
title: WindowsUpdateManager PowerShell Beacon Registry Run Key Persistence
id: 833c2659-c255-4e42-a6b8-2cfd8b0b8ac1
status: test
description: >-
  Detects registry write to HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager
  pointing to %LOCALAPPDATA%\Microsoft\WindowsUpdateManager.ps1 — the operator-bespoke
  victim-side persistence mechanism for the UTA-2026-012 PowerShell C2 beacon documented
  in C2_INFRA_TRANSFER.md. Legitimate Windows Update components do not create HKCU Run keys.
  The WindowsUpdateManager value name is the operator's deliberate masquerade of Windows Update.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager'
    condition: selection
falsepositives:
    - None expected — WindowsUpdateManager is not a legitimate Windows Update component registry value
level: high
```

---

### Rule 6 — Outbound to AntiPublic.one Credential-DB API from Non-Research Host

**Detection Priority:** HIGH
**Rationale:** HTTP POST to `antipublic.one/api/v2/search` from any non-security-research infrastructure is a high-confidence credential-operator signal. The operator integrates AntiPublic.one (Russian paid breach-data lookup service) via a JWT in `mass_wp_mutator.py` to cross-check targets against historical credential corpora before live brute-force. Legitimate organizations do not query AntiPublic.one from production infrastructure.
**ATT&CK Coverage:** T1213 (Data from Information Repositories), T1078 (Valid Accounts — credential pre-validation)
**Confidence:** HIGH
**False Positive Risk:** LOW — AntiPublic.one is a known Russian carding/credential-validation service. Legitimate security research tools that query this service (OSINT analysts, credential-monitoring platforms) can be added to an allowlist by source IP. Production and server infrastructure has no legitimate reason to call this endpoint.
**Deployment:** Proxy logs, Zeek http.log, WAF egress rules

```yaml
title: Outbound HTTP to AntiPublic.one Credential Database API from Non-Research Host
id: 163023b7-5615-4c9f-9e30-60af0bd2cd8e
status: test
description: >-
  Detects outbound HTTP connections to antipublic.one/api/v2/search from non-security-research
  infrastructure. The UTA-2026-012 operator integrates this Russian paid breach-data lookup
  service (mass_wp_mutator.py ANTIPUBLIC_API_URL constant) to cross-check target email/password
  combinations against historical credential corpora before live WordPress brute-force.
  Production and server infrastructure has no legitimate reason to query this endpoint.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.credential-access
    - attack.collection
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationHostname|endswith: 'antipublic.one'
        DestinationPort:
            - 443
            - 80
    condition: selection
falsepositives:
    - Legitimate OSINT analysts or credential-monitoring platforms querying AntiPublic.one — allowlist by source IP
    - Security vendor threat-intel feeds querying the service for breach-data correlation
level: high
```

---

### Rule 7 — Python HTTP Server with UTF-16LE Encoding in Process Command Line

**Detection Priority:** MEDIUM
**Rationale:** Python process spawning an HTTP server on a non-standard port combined with `utf-16le` or `utf16le` in the process environment or command line arguments is the runtime signature of the operator's `c2_server.py` deployment. The UTF-16LE encoding is the C2's body encoding scheme; `BaseHTTPServer` on a non-standard port (8081/8090/10101 vs the standard 8000/8080) is the deployment pattern.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1059.006 (Python)
**Confidence:** MODERATE
**False Positive Risk:** HIGH (standalone, broad Python HTTP server detection). MEDIUM with the UTF-16LE co-condition. Deploy as a hunting query rather than a production alert without additional tuning. Combine with network-layer detection (Suricata Rule 3) for higher-fidelity composite alerting.
**Deployment:** EDR process-creation telemetry, auditd execve, threat hunting

```yaml
title: Python HTTP Server on Non-Standard Port with UTF-16LE Encoding (A2A C2 Pattern)
id: 253e1a6a-f4f3-4227-9106-94e9fdb4f949
status: test
description: >-
  Detects Python processes launching HTTP servers on non-standard ports (8081, 8090, 10101)
  co-occurring with utf-16le string in command line or script path — runtime signature of the
  UTA-2026-012 operator's c2_server.py BaseHTTPServer deployment. The UTF-16LE encoding is the
  C2's body encoding scheme for PowerShell beacon commands. Non-standard ports (8081/8090/10101)
  are the operator's documented multi-instance deployment pattern from c2_server.log filenames.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.command-and-control
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection_python:
        Image|endswith:
            - '/python3'
            - '/python'
    selection_c2_server:
        CommandLine|contains:
            - 'c2_server'
            - 'BaseHTTPServer'
    selection_port_indicators:
        CommandLine|contains:
            - ':8081'
            - ':8090'
            - ':10101'
    condition: selection_python and (selection_c2_server or selection_port_indicators)
falsepositives:
    - Legitimate Python web services on non-standard ports (Django dev server, Flask, etc.) — tune by excluding known-legitimate service paths and process owners
    - Security testing frameworks (Impacket, Responder) that use similar port patterns
level: low
```

---

### Rule 8 — Mass WordPress Credential Validation Rate (Brute-Force Spray)

**Detection Priority:** HIGH
**Rationale:** More than 500 HTTP POST requests to `/wp-login.php` from a single source IP within a 60-second window is the mass-credential-validation signature of `mass_wp_mutator.py` and the operator's nuclei `wp_admin_hunter.yaml` template. Legitimate WordPress authentication does not generate this volume from a single source. This threshold is derived from the operator's ThreadPoolExecutor 3-worker configuration — at 3 concurrent workers, even a slow mutation pipeline generates hundreds of POSTs per minute against a target list.
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Load-testing tools, penetration testers, and automated performance testing may trigger this threshold. Tune the threshold upward (to 1000+/min) for environments with known load-testing activity; downward (to 100+/min) for environments where any WordPress brute-force activity is anomalous.
**Deployment:** Web Application Firewall, reverse proxy access logs, Zeek http.log

```yaml
title: Mass WordPress wp-login.php Credential Validation Rate — Possible A2A Credential Mill
id: c6ff58ec-caa8-43e8-a73d-7869abcae0eb
status: test
description: >-
  Detects high-volume HTTP POST requests to /wp-login.php from a single source IP exceeding
  500 requests per 60-second window — signature of mass_wp_mutator.py and nuclei wp_admin_hunter.yaml
  credential validation used by UTA-2026-012. The operator's ThreadPoolExecutor 3-worker
  configuration generates high POST volume against target lists of 30,000+ WordPress sites.
  Threshold tuning guidance: 500/min is conservative; adjust based on environment baseline.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.credential-access
    - attack.initial-access
logsource:
    product: apache
    service: access
detection:
    selection:
        cs-uri-stem|contains: '/wp-login.php'
        cs-method: 'POST'
    condition: selection | count(c-ip) by c-ip > 500
falsepositives:
    - Authorized load-testing or penetration testing against WordPress installations
    - WordPress security scanner tools (WPScan, Jetpack Protect) — these generally use lower rates
level: high
```

---

### Rule 9 — 1Password Vault Export or Download Pattern

**Detection Priority:** HIGH
**Rationale:** The operator's `CREDENTIALS.md` ledger references a 1Password vault export dated 2026-03-20 from an unidentified victim — one of multiple credential stores compromised in the operation. File creation events matching 1Password vault export formats (`.1pux`, `.1pif`, `1Password Export*`) combined with immediate access from a Python or PowerShell process (rather than the 1Password application itself) is a high-confidence data-theft signal.
**ATT&CK Coverage:** T1555.005 (Credentials from Password Stores — Password Managers), T1005 (Data from Local System)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Legitimate 1Password vault exports by authorized users (for migration, backup) will trigger this rule. Tune by suppressing alerts where the accessing process is the 1Password application or a known backup agent. Alert when the accessing process is Python, PowerShell, or an unrecognized binary.
**Deployment:** Sysmon Event ID 11 (file creation), EDR file-access monitoring

```yaml
title: 1Password Vault Export File Created or Accessed by Non-1Password Process
id: 0ced06f4-f028-44fa-b7fc-4f1a96c3076d
status: test
description: >-
  Detects creation or access of 1Password vault export files (.1pux, .1pif) by processes
  other than the 1Password application. The UTA-2026-012 operator's credential ledger
  (CREDENTIALS.md) references a complete 1Password vault export dated 2026-03-20 from an
  unidentified victim, indicating successful extraction of a victim's entire password manager
  vault via stolen access. Accessing process being Python or PowerShell rather than 1Password
  is the key discrimination signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.credential-access
    - attack.collection
logsource:
    category: file_event
    product: windows
detection:
    selection_vault_files:
        TargetFilename|endswith:
            - '.1pux'
            - '.1pif'
            - '1Password Export'
    filter_legitimate_1password:
        Image|endswith:
            - '\1Password.exe'
            - '\1Password 7.exe'
            - '\1Password 8.exe'
    condition: selection_vault_files and not filter_legitimate_1password
falsepositives:
    - Legitimate authorized 1Password vault migration or backup workflows by IT staff
    - 1Password CLI (op.exe) used for authorized scripted access — allowlist op.exe Image path
level: high
```

---

### Rule 10 — NTLM Hash Dump Followed by Cloudflare Tunnel Egress (Correlation)

**Detection Priority:** HIGH
**Rationale:** The operator dumped NTLM hashes from the the victim domain (local SAM hashes from multiple machines across two internal subnets) and then exfiltrated them via the Cloudflare Tunnel C2 (`c2.tralalarkefe.com` or `windows_server.tralalarkefe.com`). Detection of NTLM dump tooling (lsass access, SAM dump commands) followed within 10 minutes by outbound connections to `*.trycloudflare.com` or `*.tralalarkefe.com` is a high-confidence exfiltration-via-tunnel composite signal.
**ATT&CK Coverage:** T1003.001 (LSASS Memory), T1003.002 (SAM), T1041 (Exfiltration Over C2 Channel), T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**False Positive Risk:** LOW on the composite condition. The NTLM-dump-to-Cloudflare-Tunnel sequence within a 10-minute window is not a legitimate administrator pattern.
**Deployment:** EDR correlation rules, SIEM temporal correlation queries, Sysmon Event ID 10 (lsass access) + network log correlation

```yaml
title: NTLM Hash Dump Followed by Cloudflare Tunnel Exfiltration Within 10 Minutes
id: f4e6c9ce-7511-4e5e-9e52-adba3f0ae030
status: test
description: >-
  Detects the sequence of NTLM credential dumping (lsass access or SAM hive read) followed
  within 10 minutes by outbound connections to Cloudflare Tunnel infrastructure
  (*.trycloudflare.com or *.tralalarkefe.com). This sequence was observed in the UTA-2026-012
  the healthcare-victim compromise where local SAM NTLM hashes were dumped and exfiltrated via
  Cloudflare Tunnel C2 — confirmed by the operator's own credential ledger containing
  plaintext NTLM hashes from two internal subnets. This is a temporal-correlation rule
  requiring SIEM event-chain logic.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.credential-access
    - attack.exfiltration
    - attack.command-and-control
logsource:
    category: process_access
    product: windows
detection:
    selection_lsass_access:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1fffff'
    condition: selection_lsass_access
falsepositives:
    - Legitimate AV/EDR processes accessing lsass.exe for telemetry — filter by trusted Image paths (CrowdStrike, Defender, Carbon Black sensors)
    - Domain controller synchronization operations
    - Note: this rule captures only the first event in the sequence; Cloudflare Tunnel egress correlation requires a SIEM temporal join rule (window 10 min) against DNS/network logs for *.trycloudflare.com or *.tralalarkefe.com
level: high
```

---

### Rule 11 — AI Operator Handoff Document Filename on Filesystem

**Detection Priority:** HIGH
**Rationale:** File creation events matching the operator's documented handoff document naming convention (`C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md`, `DEPLOYED_TOOLS.md`, `CLOUDFLARE_INFRA.md`) anywhere on a server filesystem is a high-confidence indicator of operator-authored AI priming documents. These specific filenames are not used by any known legitimate software.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1071.001 (Web Protocols — C2 references within documents)
**Confidence:** HIGH
**False Positive Risk:** LOW — These specific filenames (`C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md`) are not used by any known legitimate software. `DEPLOYED_TOOLS.md` and `CLOUDFLARE_INFRA.md` are more generic but when combined with the `~/.gemini/` directory path are highly specific.
**Deployment:** File integrity monitoring, Sysmon Event ID 11, EDR file-creation telemetry

```yaml
title: AI Operator Handoff Document Filename Created on Server Filesystem
id: 0532e874-0106-4db7-9fc7-2e44939eae23
status: test
description: >-
  Detects file creation events matching the UTA-2026-012 operator's documented AI Operator
  Handoff Document naming conventions on server filesystems. Three exemplars confirmed:
  C2_MIGRATION_GUIDE.md (Russian-language C2 redeployment guide for new Gemini CLI sessions),
  C2_INFRA_TRANSFER.md (explicit To/From Gemini CLI header — AI-to-AI knowledge transfer),
  DEPLOYED_TOOLS.md (When starting a new session load directive). Any of these filenames
  on server infrastructure warrants immediate investigation.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.persistence
    - attack.resource-development
logsource:
    category: file_event
    product: linux
detection:
    selection_specific_names:
        TargetFilename|endswith:
            - '/C2_MIGRATION_GUIDE.md'
            - '/C2_INFRA_TRANSFER.md'
    selection_gemini_dir_context:
        TargetFilename|contains:
            - '/.gemini/'
        TargetFilename|endswith:
            - 'DEPLOYED_TOOLS.md'
            - 'CLOUDFLARE_INFRA.md'
            - 'SKILL.md'
            - 'GEMINI.md'
    condition: selection_specific_names or selection_gemini_dir_context
falsepositives:
    - C2_MIGRATION_GUIDE.md and C2_INFRA_TRANSFER.md — no known legitimate use; alert unconditionally
    - DEPLOYED_TOOLS.md and CLOUDFLARE_INFRA.md in ~/.gemini/ context — low FP; investigate any match on server hosts
    - SKILL.md and GEMINI.md in ~/.gemini/ — tune by adding operator-side allowlist for authorized Gemini CLI developer installations
level: high
```

---

### Rule 12 — Telegram API Egress with Americanpatriotus Channel Reference

**Detection Priority:** MEDIUM
**Rationale:** Outbound API calls to `api.telegram.org` from server infrastructure combined with the `@americanpatriotus` channel identifier or Telegram Bot API `sendMessage` calls is the runtime signature of `quantum_patriot.py` — the operator's co-located Telegram disinformation content machine. Detecting automated Telegram API posting from server infrastructure (vs user workstations) is the key discrimination.
**ATT&CK Coverage:** T1102 (Web Service — Telegram as C2/dissemination channel), T1059.006 (Python)
**Confidence:** MODERATE
**False Positive Risk:** HIGH (Telegram API egress from servers is common in legitimate bot deployments). MEDIUM with `americanpatriotus` string in traffic content (not easily inspectable on TLS without proxy inspection). Deploy as a DNS-level alert for `api.telegram.org` from server-class hosts combined with the channel-ID pattern where content inspection is available.
**Deployment:** Proxy with TLS inspection, DNS resolver logs (server-class hosts), network egress monitoring

```yaml
title: Telegram API Egress from Server Host with Americanpatriotus Channel Indicator
id: 8be13baf-aa35-422c-8757-9cfea720af53
status: test
description: >-
  Detects automated Telegram Bot API connections from server-class infrastructure, hunting
  for the UTA-2026-012 operator's quantum_patriot.py Telegram disinformation posting script
  which sends to the @americanpatriotus channel. The americanpatriotus channel was independently
  confirmed by Trend Micro (TrendAI Research, 2026-05-22) as a UTA-2026-012 / bandcampro
  attribution IOC. Correlate server-class Telegram API egress with process name python or
  quantum_patriot in command line for higher-confidence detection.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
    - https://www.trendmicro.com/ (TrendAI Research, 2026-05-22 — bandcampro operator coverage)
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.impact
    - attack.command-and-control
logsource:
    category: network_connection
    product: linux
detection:
    selection_telegram_api:
        DestinationHostname|endswith: 'api.telegram.org'
    selection_python_process:
        Image|endswith:
            - '/python3'
            - '/python'
    condition: selection_telegram_api and selection_python_process
falsepositives:
    - Legitimate Telegram bot deployments on server infrastructure (customer notification bots, alert bots, CI/CD bots) — allowlist by source IP or process path
    - Authorized social media management tools using Telegram APIs
level: low
```

---

## Suricata Signatures

### Rule 1 — DNS Query to *.tralalarkefe.com (Any Host)

**Detection Priority:** HIGH
**Rationale:** Any DNS query resolving `tralalarkefe.com` or any subdomain is a high-confidence indicator of either operator-side infrastructure activity or victim-side C2 beacon activity. The domain has no documented legitimate use. The operator's documented subdomains include `c2`, `payloads`, `windows_server`, `gil_dr1`, `catchall1`, and `10101` — any new subdomain should also be treated as operator-controlled.
**ATT&CK Coverage:** T1568 (Dynamic Resolution), T1090.004 (Domain Fronting — Cloudflare Tunnel), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — `tralalarkefe.com` has no documented legitimate use outside this operator's infrastructure.
**Deployment:** Network DNS monitoring, Zeek dns.log, SIEM ingestion from DNS resolver logs

```suricata
alert dns $HOME_NET any -> any any (
    msg:"THL - DNS Query to UTA-2026-012 Operator C2 Domain tralalarkefe.com";
    dns.query; content:"tralalarkefe.com"; nocase; endswith;
    classtype:trojan-activity;
    sid:9000001; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "command-and-control",
              mitre_technique "T1568 T1090.004 T1071.001",
              confidence HIGH, created_at 2026-05-25;
)
```

---

### Rule 2 — DNS Query to generativelanguage.googleapis.com from Server-Class Hosts (Hunting Baseline)

**Detection Priority:** MEDIUM
**Rationale:** DNS queries to `generativelanguage.googleapis.com` from server-class hosts (defined via `$SERVER_NET` variable — tune for your environment) are the network-layer indicator of stolen Gemini API key validation or LLM-personalized credential mutation tooling. This is a hunting baseline, not a production alert — legitimate ML inference services query this domain. Deploy with a frequency threshold or combine with the YARA file detection for composite alerting.
**ATT&CK Coverage:** T1078 (Valid Accounts — stolen API key reuse), T1059.006 (Python)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — Any server-side ML inference backend using the Gemini API will trigger this. Tune by scoping `$SERVER_NET` to infrastructure where Gemini API calls are not expected, and by adding a rate threshold (>10 queries/minute from a single source = key-rotation pattern).
**Deployment:** DNS resolver monitoring on server-class host segments, Zeek dns.log with server-IP filter

```suricata
alert dns $HOME_NET any -> any any (
    msg:"THL - Gemini Generative Language API DNS Query from Server-Class Host (Stolen Key Hunting Baseline)";
    dns.query; content:"generativelanguage.googleapis.com"; nocase; endswith;
    classtype:policy-violation;
    sid:9000002; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "credential-access resource-development",
              mitre_technique "T1078 T1059.006",
              confidence MODERATE, created_at 2026-05-25,
              note "hunting-baseline-tune-to-server-segments-only";
)
```

---

### Rule 3 — HTTP POST to A2A C2 Endpoints with X-Agent-ID Header

**Detection Priority:** HIGH
**Rationale:** HTTP POST to the operator's documented C2 endpoint paths (`/api/v1/update`, `/api/v1/interact`, `/api/v1/telemetry`, `/api/v1/get_results`) carrying the `X-Agent-ID` header is the victim-side beacon signature. The `X-Agent-ID` header is operator-bespoke; no legitimate web application framework uses this header name in this endpoint naming pattern.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — The combination of `/api/v1/update` or `/api/v1/interact` paths with the `X-Agent-ID` header is operator-bespoke and has no known legitimate-software counterpart.
**Deployment:** Inline or passive HTTP inspection, Zeek http.log, WAF/proxy with content inspection

```suricata
alert http $HOME_NET any -> any any (
    msg:"THL - A2A C2 Beacon POST to Operator C2 Endpoint with X-Agent-ID Header";
    flow:established,to_server;
    http.method; content:"POST";
    http.header_names; content:"X-Agent-ID"; nocase;
    pcre:"/\/api\/v1\/(update|interact|telemetry|get_results)/U";
    classtype:trojan-activity;
    sid:9000003; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "command-and-control exfiltration",
              mitre_technique "T1071.001 T1132.001 T1041",
              confidence HIGH, created_at 2026-05-25;
)
```

---

### Rule 4 — HTTP Egress to antipublic.one /api/v2/search

**Detection Priority:** HIGH
**Rationale:** HTTP GET or POST to `antipublic.one/api/v2/search` from any internal host is the network-layer indicator of the operator's paid breach-data lookup integration. `antipublic.one` is a known Russian credential-database service; its `/api/v2/search` endpoint is the bulk-lookup API used by `mass_wp_mutator.py`. No legitimate enterprise application queries this endpoint.
**ATT&CK Coverage:** T1213 (Data from Information Repositories), T1078 (Valid Accounts)
**Confidence:** HIGH
**False Positive Risk:** LOW — No legitimate enterprise application queries the AntiPublic breach-data API from production infrastructure. Security research tools that use this service generate low-volume single-query patterns distinct from the operator's bulk-query pattern.
**Deployment:** Egress proxy, WAF, Zeek http.log

```suricata
alert http $HOME_NET any -> any any (
    msg:"THL - Outbound to AntiPublic.one Credential-DB API /api/v2/search (Credential Operator Tool)";
    flow:established,to_server;
    http.host; content:"antipublic.one"; nocase; endswith;
    http.uri; content:"/api/v2/search"; startswith;
    classtype:policy-violation;
    sid:9000004; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "credential-access collection",
              mitre_technique "T1213 T1078",
              confidence HIGH, created_at 2026-05-25;
)
```

---

### Rule 5 — trycloudflare.com Tunnel Bootstrap DNS from Server Hosts

**Detection Priority:** MEDIUM
**Rationale:** DNS queries resolving `*.trycloudflare.com` from server-class hosts are a hunting baseline for Cloudflare quick-tunnel bootstrap activity. The operator used `tenant-upcoming-great-descending.trycloudflare.com` as the bootstrap channel for seeding new VPS instances via `install_c2_bundle.sh`. Legitimate use of trycloudflare.com by developer workstations is common; server-class hosts querying this domain is anomalous.
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1572 (Protocol Tunneling), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — Developers using `cloudflared tunnel --url` for local development tunnel testing generate legitimate trycloudflare.com queries. Server-class hosts are the correct scope; developer workstations should be excluded.
**Deployment:** DNS resolver monitoring (server-class host segments), Zeek dns.log

```suricata
alert dns $HOME_NET any -> any any (
    msg:"THL - Cloudflare Quick-Tunnel Bootstrap DNS Query from Server-Class Host (trycloudflare.com)";
    dns.query; content:"trycloudflare.com"; nocase; endswith;
    classtype:policy-violation;
    sid:9000005; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "command-and-control",
              mitre_technique "T1090.004 T1572 T1105",
              confidence MODERATE, created_at 2026-05-25,
              note "tune-to-server-segments-exclude-developer-workstations";
)
```

---

### Rule 6 — cloudflared QUIC/UDP Egress from Server Hosts (Hunting Baseline)

**Detection Priority:** LOW
**Rationale:** cloudflared uses QUIC (UDP 443) as its preferred tunnel transport when available. Outbound UDP/443 from server-class hosts to Cloudflare infrastructure IP ranges is a hunting baseline for cloudflared tunnel-establishment activity. Combined with DNS detection of `tralalarkefe.com` or `trycloudflare.com`, this provides a transport-layer confirmation layer. Deploy as a hunting query, not a production alert.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1090.004 (Domain Fronting)
**Confidence:** LOW
**False Positive Risk:** HIGH (standalone — many legitimate applications use QUIC to Cloudflare infrastructure). Deploy only as part of a multi-indicator hunting workflow, not as a standalone production alert. Combine with the DNS rules above for composite confidence.
**Deployment:** Network flow telemetry, Zeek conn.log with UDP/443 filter on server-class host segments

```suricata
alert udp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"THL - Outbound QUIC/UDP 443 Cloudflare Infrastructure (cloudflared Tunnel Hunting Baseline)";
    classtype:policy-violation;
    sid:9000006; rev:1;
    metadata:author "The Hunters Ledger",
              campaign "OpenDirectory-RussianGeminiCredentialMill-213.165.51.115",
              mitre_tactic "command-and-control",
              mitre_technique "T1572 T1090.004",
              confidence LOW, created_at 2026-05-25,
              note "hunting-baseline-high-FP-combine-with-DNS-rules-9000001-9000005";
)
```

---

## Coverage Gaps

### Techniques Observed But Not Fully Covered

**1. LLM-Vendor-Side Detection (Gemini API abuse telemetry)**
The operator's `check_keys.py` validates 40+ stolen Gemini API keys against Google's model-listing endpoint with high key-diversity from a single source IP. Detection of this key-rotation pattern requires server-side telemetry from Google's Generative Language API — specifically, `/v1beta/models` calls where a single source IP cycles through >10 distinct `?key=` values within 60 seconds. This is beyond standard defender scope. **Coordination path:** Google Trust & Safety (`trust-and-safety@google.com`) with the operator's full key inventory from `Evidence/russian-check_keys.py`. The Suricata Rule 2 provides a network-layer hunting baseline but cannot discriminate single-key legitimate use from 40-key rotation at the protocol level without server-side telemetry.

**2. Telegram Disinformation Content Detection**
The `quantum_patriot.py` script posts AI-rewritten RSS content to `@americanpatriotus` via the Telegram Bot API. Detecting the content of specific disinformation posts (to distinguish this channel's AI-generated content from organic political posting) requires semantic content classification beyond standard SOC capability. The Sigma Rule 12 provides a process-level signal (Python → Telegram API egress) but cannot inspect TLS-encrypted message bodies without a transparent proxy. **Coordination path:** Telegram Trust & Safety for the `@americanpatriotus` channel, independently corroborated by Trend Micro (2026-05-22).

**3. GitHub PAT Abuse Correlation**
The operator's GitHub PAT (`ghp_tdcX...G4PDaRW` for `oravepo546-stack`) is used for repository management and potentially exfiltration of victim artifacts via GitHub as an exfil channel. Per-PAT API call correlation across GitHub infrastructure requires GitHub Trust & Safety coordination — the specific PAT can be revoked and its API call history audited server-side. MITRE technique covered: T1567.002 (Exfiltration to Cloud Storage). **Coordination path:** GitHub Trust & Safety with the operator's account identifiers `sonner1337` and `oravepo546-stack`.

**4. Per-Victim Cloudflare Tunnel Access Detection**
The operator's `windows_server.tralalarkefe.com` and `gil_dr1.tralalarkefe.com` Cloudflare Tunnel endpoints provided persistent RDP and SSH access to the victim machines at the time of capture. Detecting specific victim-machine beacon activity on these tunnels from the defender's side requires either (a) the victim's network egress logs showing outbound connections to Cloudflare infrastructure or (b) Cloudflare PSIRT coordination to identify which Cloudflare account is operating the `tralalarkefe.com` tunnels. **Coordination path:** Cloudflare PSIRT with the operator's Cloudflare API token (`pBkv...BztGF2`, defanged — full token in `Evidence/russian-arsenal-CREDENTIALS.md`). Suricata Rule 1 and Rule 5 provide network-layer signals for environments with DNS logging.

**5. agent_final.ps1 PowerShell Beacon (Binary Not Captured)**
The PowerShell beacon `agent_final.ps1` is referenced extensively in the operator's handoff documents as the victim-side agent component, but the binary itself was not extractable from Hunt.io (PS1 content is not object-stored). YARA and Sigma rules for the victim-side beacon are derived from the endpoint-contract specification in handoff documents rather than direct code analysis. Confidence: HIGH (behavioral reconstruction from C2 server source + operator documentation); DEFINITE requires direct binary capture. If the beacon is later recovered from a victim-side forensic investigation, the following indicators from the C2 server source code should enable high-confidence matching: `X-Agent-ID: HOSTNAME_username` header format, 5-second beacon interval to `/api/v1/update`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` User-Agent, `base64(UTF-16LE)` body encoding on `/api/v1/telemetry` POST.

**6. WMI EventConsumer Fileless Persistence (stealth.ps1)**
The operator's `C2_MIGRATION_GUIDE.md` references a `stealth.ps1` script providing WMI EventConsumer + EventFilter + FilterToConsumerBinding triplet persistence in addition to the HKCU Registry Run key. The `stealth.ps1` binary was not extractable from Hunt.io. Generic WMI subscription persistence detection (Sysmon Event ID 19/20/21 matching `\\.\root\subscription`) covers this technique pattern but cannot provide the operator-specific file/value-name signatures without direct binary access.

**7. OpenDental MySQL Hash Reuse / Database Access**
The operator holds the OpenDental MySQL root hash (value redacted — held offline). Detection of unauthorized OpenDental database access would require MySQL audit logging at the the victim practice-management server — out of scope for a third-party detection provider. **Coordination path:** Direct victim notification (via HC3/HHS OCR HIPAA track) is the correct response path; database-level detection is the practice's own security team scope.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
