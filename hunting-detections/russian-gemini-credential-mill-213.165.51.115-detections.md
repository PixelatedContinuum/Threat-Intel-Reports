---
title: "Detection Rules — Russian Gemini Credential Mill (213.165.51.115)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
thumbnail: /assets/images/cards/russian-gemini-credential-mill-213.165.51.115.png
hide: true
---

**Campaign:** Russian-Gemini-Credential-Mill-UTA-2026-012-213.165.51.115
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/russian-gemini-credential-mill-213.165.51.115/

> **Calibration / Prior-Art Note:** Trend Micro (TrendAI Research) published independent coverage of this same operator on 2026-05-22 ("One Man, One AI, One Fake Persona: Inside the 5-Year Influence and Fraud 'Patriot Bait' Campaign"; operator tracked as "bandcampro"). Cross-identification is DEFINITE via five-point IOC match: `@americanpatriotus` Telegram channel, 73 stolen Gemini API keys in operator inventory, 20-mutation-per-target generation, Quantum Patriot pipeline branding, and `GEMINI.md` jailbreak-persistence file. Rules in this file complement the Trend Micro coverage with per-case source-code-derived signatures not previously published. **AI Operator Handoff Document novelty MAINTAINED** (Trend Micro covers `GEMINI.md` jailbreak persistence; architecturally distinct from the operator-authored `C2_INFRA_TRANSFER.md / DEPLOYED_TOOLS.md / C2_MIGRATION_GUIDE.md` structured session-handoff documents). **LLM Credential Mutation novelty REFRAMED** as first source-code analysis with verbatim prompt reproduction (operational pattern independently confirmed by Trend Micro). **Unauthenticated Python-stdlib C2**: no prior art found in either publication.

---

## Detection Coverage Summary

This operator runs a custom Python A2A ("agent-to-agent") C2 stack combined with a Gemini-CLI-augmented credential mill. Coverage below is reorganized by tier: **Detection** rules are precise/durable enough to alert on; **Hunting** rules are broader scoping leads that need analyst triage. Rules keyed solely on one of the operator's rotatable domains (or a third-party service domain being abused) are retired as standalone signatures — those atomics already live in the campaign's IOC feed.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 7 | 1 | T1110.003, T1059.006, T1587, T1078, T1552.001, T1071.001, T1132.001, T1087, T1547.001, T1036 | 0 |
| Sigma | 4 | 6 | T1555.005, T1005, T1003.001, T1003.002, T1587, T1071.001, T1090.004, T1572, T1036.005, T1547.001, T1059.001, T1110.003 | 3 |
| Suricata | 1 | 1 | T1071.001, T1132.001, T1041, T1090.004, T1572 | 4 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The A2A C2 endpoint set (`/api/v1/update`, `/api/v1/interact`, `/api/v1/telemetry`) plus the operator-bespoke `X-Agent-ID` header — survives full domain/IP rotation, and anchors both a YARA rule and the Suricata Detection signature.
- The LLM-personalized credential-mutation prompt fragments (`"Act as an expert red-team password analyst"`, `"generate exactly 20 likely current mutations"`) paired with operator-bespoke output filenames (`AI_SNIPER_GOODS`, `AI_ADMIN_MUTANTS`) — first-publication signature for a novel TTP.

**Atomics routed to the IOC feed:** `tralalarkefe.com` (and its `c2.` / `payloads.` / `windows_server.` / `gil_dr1.` / `catchall1.` / `10101.` subdomains), `generativelanguage.googleapis.com`, `antipublic.one`, and the `tenant-upcoming-great-descending.trycloudflare.com` bootstrap subdomain are transient indicators already carried in [`russian-gemini-credential-mill-213.165.51.115-iocs.json`](/ioc-feeds/russian-gemini-credential-mill-213.165.51.115-iocs.json) — no feed edits were required for this backfill (all four domains were already present). 7 of the original file's rules (3 Sigma, 4 Suricata) each keyed solely on one of these domains with no distinguishing filter surviving its removal; they are retired as standalone signatures below and cross-referenced in Coverage Gaps.

**Salvage note:** two originally single-object rules were split during tiering to separate a high-confidence, low-FP core from a broader, real-FP-bearing branch that was folded into the same `condition:` — see the AI Operator Handoff Document Sigma pair and the WordPress credential-mill rate rule (rewritten as a proper Sigma `event_count` correlation) below.

---

## YARA Rules

### Detection Rules

#### LLM-Personalized Credential Mutator Family

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python), T1587 (Develop Capabilities)
**Confidence:** HIGH
**Rationale:** Requires the Gemini API import AND one of three verbatim role-priming prompt fragments AND one of four operator-bespoke output filenames. The prompt wording and filenames are bespoke enough that no legitimate software plausibly combines them with a Gemini API import; an operator would need to both reword every prompt fragment and rename every output file to evade.
**False Positives:** None known — the combination of a Gemini API client import, the exact role-priming phrase, and an AI-mutation output filename pattern has negligible legitimate-software overlap.
**Blind Spots:** A full prompt rewrite plus output-filename rename evades detection; the rule targets on-disk Python source, not an in-memory or compiled variant.
**Validation:** Scan `ai_sniper_brute.py` or a functional equivalent — the three-clause combination must match; a benign script that merely imports `google.generativeai` (with no role-priming prompt or bespoke output filename) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, SIEM file-creation alert, git-hook pre-commit scan on CI/CD pipelines, developer workstation endpoint protection.

```yara
/*
   Yara Rule Set
   Identifier: Russian Gemini Credential Mill — UTA-2026-012 (Case 1, ai-agent-frameworks-2026-05-23)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_Python_LLMPersonalized_Credential_Mutator_Family {
   meta:
      description = "Detects ai_sniper_brute.py-class Python scripts using Gemini API for LLM-personalized per-target password mutation — verbatim role-priming prompt + AI_SNIPER output naming convention captured from UTA-2026-012 open-directory 213.165.51.115"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

#### AI Operator Handoff Document Family

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1071.001 (Web Protocols — C2 endpoint references within the document)
**Confidence:** HIGH
**Rationale:** Requires a session-priming marker (the To/From Gemini CLI header pair, a session-start load directive, or a knowledge-transfer marker paired with a named handoff-document filename) AND co-occurrence with an operational C2 artifact (an `/api/v1/` endpoint, the `cloudflared access tcp` fragment, or the `X-Agent-ID` header). The co-occurrence requirement is what keeps this Detection-eligible despite the broader "AI-assisted documentation" surface being real.
**False Positives:** AI-augmented developer documentation (e.g., a project's own `CLAUDE.md`) can contain a session-start directive, but will not also carry a C2 endpoint pattern or the `X-Agent-ID` header — the required co-occurrence suppresses this class of FP.
**Blind Spots:** A handoff document that omits any of the four C2-artifact markers (e.g., references C2 infrastructure only by IP, with no `/api/v1/` path or bespoke header) evades the second clause.
**Validation:** Scan a captured AI Operator Handoff Document (`C2_INFRA_TRANSFER.md`, `DEPLOYED_TOOLS.md`) — both clauses must match; a legitimate `CLAUDE.md`/`AGENTS.md` project file with no C2 content must NOT fire.
**Deployment:** Endpoint file-creation monitoring, filesystem hunt on server-class Linux hosts, git-repo secret-scanning pipeline. Recommended additional scoping: prioritize `.md` files under `~/.gemini/`, `~/.claude/`, `~/.codex/` on server-class hosts over developer workstations.

```yara
rule MAL_Markdown_AI_Operator_Handoff_Document_Family {
   meta:
      description = "Detects operator-authored AI Operator Handoff Documents — Markdown files containing session-start load directives co-occurring with C2 endpoint references or credential-table patterns. Three exemplars from UTA-2026-012: C2_MIGRATION_GUIDE.md, C2_INFRA_TRANSFER.md, DEPLOYED_TOOLS.md"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

#### Stolen LLM API Key Validator

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1078 (Valid Accounts — stolen API keys), T1059.006 (Python), T1552.001 (Unsecured Credentials in Files)
**Confidence:** HIGH
**Rationale:** Requires the `AIzaSy` key-prefix regex literal AND a bulk-storage or search marker (`raw_keys`/`re.findall`) AND a validation-pipeline marker (the models endpoint, a valid-keys output, or a retest marker), with a 2-of-N reinforcement across all seven anchors. A single-key legitimate SDK usage cannot satisfy this combination — bulk-key validators are themselves malicious tooling regardless of family.
**False Positives:** None known — a script containing 40+ Gemini API keys in a block string with a validation loop against Google's models endpoint is not a legitimate development pattern.
**Blind Spots:** A rewrite that stores keys in a different structure (e.g., one per line in an external file, loaded without the `raw_keys`/`findall` marker in-code) evades the second clause.
**Validation:** Scan `check_keys.py` or a functional equivalent — all four condition clauses must be satisfied; a legitimate single-key SDK integration must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, SIEM file-creation monitoring, developer workstation endpoint protection, CI/CD secret scanning.

```yara
rule MAL_Python_Stolen_LLM_Key_Validator {
   meta:
      description = "Detects check_keys.py-class Python scripts: bulk Gemini API key inventory (AIzaSy-prefixed keys in block string) validated against generativelanguage.googleapis.com/v1beta/models — stolen-key validation pipeline from UTA-2026-012"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

#### A2A C2 Server (Unauthenticated Python stdlib)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1087 (Account Discovery — `/api/v1/agents` dumps all beacons)
**Confidence:** HIGH
**Rationale:** The operator's own banner string ("A2A C2 MULTI-AGENT CONSOLE"), or the combination of `BaseHTTPRequestHandler` with three of five bespoke `/api/v1/` endpoint paths, is essentially a fingerprint of this specific framework — no legitimate web application framework pairs `BaseHTTPServer.BaseHTTPRequestHandler` with this exact endpoint set and UTF-16LE body decoding.
**False Positives:** None known.
**Blind Spots:** A rewrite onto a different HTTP framework (Flask/FastAPI) with renamed endpoints and a dropped banner string evades detection.
**Validation:** Scan `c2_server.py` or a functional equivalent — the banner or endpoint-combination clause, plus the encoding clause, must both match; an unrelated `BaseHTTPRequestHandler`-based Python service with different endpoints must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, server-side file integrity monitoring, threat hunting on Linux server filesystems.

```yara
rule MAL_Python_A2A_C2_Server_Unauthenticated {
   meta:
      description = "Detects c2_server.py-class Python stdlib unauthenticated C2 servers — BaseHTTPRequestHandler with /api/v1/{update,agents,interact,telemetry} endpoints, base64+UTF-16LE body decoding, zero auth — operator-built A2A C2 framework from UTA-2026-012"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      1 of ($ep_update, $ep_agents, $ep_interact, $ep_telemetry) and
      ($payload_dir or $handler_base)
}
```

#### A2A C2 Client Console / Exec Tool

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1059.006 (Python)
**Confidence:** HIGH
**Rationale:** The `X-Agent-ID` bespoke header combined with UTF-16LE command encoding and `/api/v1/get_results` polling is not a pattern found in any legitimate Python HTTP client library — it is required alongside one of four corroborating operator-specific markers.
**False Positives:** None known.
**Blind Spots:** A rewrite that renames the header and drops the UTF-16LE encoding scheme evades detection.
**Validation:** Scan `console.py`/`exec.py` or a functional equivalent — the header clause plus one corroborating marker must match; a generic Python HTTP client with a custom header name (but not `X-Agent-ID` specifically) must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, server-side file integrity monitoring, threat hunting on Linux operator-side hosts.

```yara
rule MAL_Python_A2A_C2_Client_Console {
   meta:
      description = "Detects console.py/exec.py-class operator-side C2 client tools — X-Agent-ID header, HOSTNAME_user agent-ID format, base64+UTF-16LE command encoding, /api/v1/interact POST + /api/v1/get_results polling — A2A C2 framework from UTA-2026-012"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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

#### C2_INFRA_TRANSFER Explicit AI-to-AI Header (Narrow / Highest Fidelity)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1071.001 (Web Protocols — C2 references)
**Confidence:** HIGH
**Rationale:** The literal `**To:** Gemini CLI` / `**From:** Gemini CLI` header combination on a Markdown file — or that pairing with a Cyrillic operator-persona marker — has no known use in legitimate Gemini CLI documentation, Google SDK examples, or standard developer workflow. First-publication signature for the AI Operator Handoff Document TTP.
**False Positives:** None known.
**Blind Spots:** A reformatted handoff document that drops the exact `**To:**`/`**From:**` bold-markdown convention evades this narrow rule (the broader Family rule above provides fallback coverage via the session-start directive).
**Validation:** Scan `C2_INFRA_TRANSFER.md` or a functional equivalent — the header pair must match; unrelated Markdown documentation referencing "Gemini CLI" in prose (not as a To/From header) must NOT fire.
**Deployment:** Endpoint file-creation monitoring, SIEM filesystem alert, threat hunting in `~/.gemini/`, `~/.claude/`, `~/.codex/` directories on server-class hosts.

```yara
rule MAL_Markdown_C2_INFRA_TRANSFER_Pattern {
   meta:
      description = "Narrow high-fidelity detection on the explicit 'To: Gemini CLI / From: Gemini CLI' header convention from C2_INFRA_TRANSFER.md — first-publication YARA signature for the AI Operator Handoff Document TTP (UTA-2026-012)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
         ($new_session and ($to_gemini or $from_gemini or $subject_kw)) or
         ($bro_ru and ($to_gemini or $from_gemini or $subject_kw))
      )
}
```

#### PowerShell WindowsUpdateManager Stealer Loader

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036 (Masquerading), T1105 (Ingress Tool Transfer), T1059.001 (PowerShell)
**Confidence:** HIGH
**Rationale:** Requires the `WindowsUpdateManager` masquerade value name AND a corroborating path/key context AND one of four C2-artifact markers (domain, payload-domain, endpoint path, or bespoke header — three of which do not depend on the operator's specific domain) AND a PowerShell networking primitive. Because the C2-artifact clause has non-domain fallback options, the rule still fires after full domain rotation.
**False Positives:** None known — `WindowsUpdateManager` as an HKCU\Run value name combined with any of the four C2-artifact markers is not a pattern found in any legitimate Windows Update or Windows Defender component.
**Blind Spots:** A rebuild that renames the registry value AND replaces all four C2-artifact markers with something outside this anchor set evades detection.
**Validation:** Scan `WindowsUpdateManager.ps1` or a functional equivalent — all four clauses must match; a legitimate PowerShell script using `Invoke-RestMethod` with no `WindowsUpdateManager` reference must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, PowerShell script-block logging (Event 4104), file integrity monitoring on `%LOCALAPPDATA%\Microsoft\`.

```yara
rule MAL_PowerShell_WindowsUpdateManager_Stealer_Loader {
   meta:
      description = "Detects WindowsUpdateManager.ps1 — operator-bespoke persistence script masquerading as Windows Update component; HKCU Run key value + %LOCALAPPDATA%\\Microsoft\\ path + Cloudflare Tunnel C2 callback to tralalarkefe.com — UTA-2026-012"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      1 of ($c2_domain, $payload_domain, $update_endpoint, $agent_id_hdr) and
      ($tls12_set or $invoke_rest)
}
```

### Hunting Rules

#### Russian Operator Persona Strings

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities — operator infrastructure docs)
**Confidence:** MODERATE
**Rationale:** Requires one of three Cyrillic persona strings (informal address terms for Gemini, a victim-machine nickname, or a session-start idiom) AND one of five operational markers. Two of the five operational markers (`/api/v1/` and the bare `AIzaSy` key prefix) are individually generic — they appear across many unrelated APIs and any project with a legitimate Gemini key — so the composite condition carries real, analyst-triage-worthy FP risk rather than alerting-grade precision. Framed by design as a forensic/attribution aid, not a production detection.
**False Positives:** Standalone, the Cyrillic persona strings appear in ordinary Russian-language content; combined with the generic `/api/v1/` path fragment or a bare `AIzaSy` key prefix (present in any legitimate Gemini-integrated codebase authored in Russian), the composite condition can still produce non-operator hits.
**Deployment:** Threat hunting on server-class Linux hosts, forensic investigation of seized operator infrastructure, post-incident artifact analysis. Deploy only with the full composite condition — never on the persona strings alone.

```yara
rule MAL_Russian_Operator_Persona_Strings {
   meta:
      description = "Detects UTA-2026-012 operator-authored files via Cyrillic persona strings (Братух/Бро addressing of Gemini, Комп Доктора victim-machine reference) co-occurring with C2 endpoint or API key indicators — high-specificity attribution aid for post-incident forensics"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
```

---

## Sigma Rules

### Detection Rules

#### 1Password Vault Export File Created or Accessed by Non-1Password Process

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1555.005 (Credentials from Password Stores — Password Managers), T1005 (Data from Local System)
**Confidence:** HIGH
**Rationale:** Requires a 1Password vault-export file extension/name pattern AND a filter excluding the legitimate 1Password application images. This combination — export artifact plus a non-1Password accessing process — is a durable technique signal independent of any campaign-specific domain or filename.
**False Positives:** Legitimate authorized 1Password vault migration or backup workflows by IT staff; the 1Password CLI (`op.exe`) used for authorized scripted access is not excluded by the current filter and should be allowlisted per-deployment.
**Blind Spots:** A theft routine that renames the exported file before it touches disk (avoiding the `.1pux`/`.1pif`/`1Password Export` pattern) evades detection.
**Validation:** Trigger a 1Password vault export from a non-1Password process (e.g., a Python script reading the export directory) — must match; a export created and immediately handled by `1Password.exe` itself must NOT fire.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (file-creation telemetry).

```yaml
title: 1Password Vault Export File Created or Accessed by Non-1Password Process
id: 0ced06f4-f028-44fa-b7fc-4f1a96c3076d
status: experimental
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
date: '2026-05-25'
tags:
    - attack.credential-access
    - attack.t1555.005
    - attack.collection
    - attack.t1005
    - detection.emerging-threats
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

#### Suspicious LSASS Process Access via High-Privilege GrantedAccess Mask

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1003.001 (LSASS Memory), T1003.002 (SAM)
**Confidence:** MODERATE
**Rationale:** **Retitled during tiering** — the original title ("NTLM Hash Dump Followed by Cloudflare Tunnel Exfiltration Within 10 Minutes") described a two-stage correlation, but the YAML logic below only ever implemented the first stage (LSASS process-access with credential-dumping-associated `GrantedAccess` masks); the Cloudflare Tunnel egress half was never encoded and would require a separate SIEM temporal join (see Coverage Gaps). The title now matches the logic that actually ships. The GrantedAccess-mask pattern itself is a well-established, durable LSASS-credential-access signature independent of this campaign's specific infrastructure.
**False Positives:** Legitimate AV/EDR processes accessing lsass.exe for telemetry (filtered by trusted Image path); domain controller synchronization operations.
**Blind Spots:** Captures only the LSASS-access stage; does not by itself confirm exfiltration occurred. Credential-dumping tools that request a narrower access mask than the three listed evade this rule.
**Validation:** Run a credential-dumping tool against `lsass.exe` — the GrantedAccess mask match must fire; a trusted EDR/AV sensor accessing lsass.exe for its own telemetry must NOT fire (verify the Image filter covers your deployed sensor).
**Deployment:** EDR correlation rules, SIEM temporal correlation queries, Sysmon Event ID 10 (lsass access) + network log correlation (pair with DNS/network monitoring for `*.trycloudflare.com` / `*.tralalarkefe.com` egress within a 10-minute window for the full two-stage signal — see Coverage Gaps).

```yaml
title: Suspicious LSASS Process Access via High-Privilege GrantedAccess Mask
id: f4e6c9ce-7511-4e5e-9e52-adba3f0ae030
status: experimental
description: >-
  Detects LSASS process access using GrantedAccess masks associated with credential-dumping
  tooling (0x1010, 0x1410, 0x1fffff). This is the first stage of a sequence observed in the
  UTA-2026-012 healthcare-victim compromise, where local SAM NTLM hashes were dumped and then
  exfiltrated via Cloudflare Tunnel C2 — confirmed by the operator's own credential ledger
  containing plaintext NTLM hashes from two internal subnets. This rule captures only the
  LSASS-access stage; the follow-on Cloudflare Tunnel egress requires a separate SIEM temporal
  join (not expressible in a single non-correlation Sigma selection) — see the companion
  report's Coverage Gaps.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1003.002
    - detection.emerging-threats
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
level: high
```

#### AI Operator Handoff Document Bespoke Filename Created on Server Filesystem

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities)
**Confidence:** HIGH
**Rationale:** **Salvage-split from the original combined rule** — the original `condition: selection_specific_names or selection_gemini_dir_context` OR'd this bespoke-filename branch together with a broader `~/.gemini/` + generic-tooling-filename branch that includes `GEMINI.md`/`SKILL.md` (the *standard* legitimate Gemini CLI config filenames). Splitting isolates the two bespoke, no-known-legitimate-collision filenames (`C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md`) into a Detection-grade rule; the broader/generic branch is now its own Hunting rule below.
**False Positives:** None known — these specific filenames are not used by any known legitimate software.
**Blind Spots:** A rebuild that renames both exemplar filenames evades detection (the broader Hunting-tier companion rule below provides fallback coverage for the `~/.gemini/` directory context).
**Validation:** Create a file named `C2_INFRA_TRANSFER.md` or `C2_MIGRATION_GUIDE.md` anywhere on a monitored filesystem — must match; creation of an unrelated Markdown file must NOT fire.
**Deployment:** File integrity monitoring, Sysmon Event ID 11, EDR file-creation telemetry.

```yaml
title: AI Operator Handoff Document Bespoke Filename Created on Server Filesystem
id: 0532e874-0106-4db7-9fc7-2e44939eae23
status: experimental
description: >-
  Detects file creation events matching the UTA-2026-012 operator's two confirmed
  bespoke AI Operator Handoff Document filenames: C2_MIGRATION_GUIDE.md (Russian-language
  C2 redeployment guide for new Gemini CLI sessions) and C2_INFRA_TRANSFER.md (explicit
  To/From Gemini CLI header — AI-to-AI knowledge transfer). Neither filename has a known
  legitimate-software use. Split from the original combined rule during tiering to isolate
  this no-known-collision branch from the broader ~/.gemini/ directory-context branch,
  which includes the standard legitimate Gemini CLI config filenames GEMINI.md/SKILL.md
  and carries meaningfully higher false-positive risk (see the companion Hunting rule).
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1587
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_specific_names:
        TargetFilename|endswith:
            - '/C2_MIGRATION_GUIDE.md'
            - '/C2_INFRA_TRANSFER.md'
    condition: selection_specific_names
falsepositives:
    - Unlikely — C2_MIGRATION_GUIDE.md and C2_INFRA_TRANSFER.md have no known legitimate use; investigate any match
level: high
```

#### Mass WordPress wp-login.php Credential Validation Rate Exceeded (Correlation)

**Tier:** Detection (correlation) / base selection below is Hunting — non-alerting, tallied separately
**Robustness:** 2
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python)
**Confidence:** HIGH
**Rationale:** **Salvage-rewrite from a bare selection to a proper Sigma `event_count` correlation.** The original rule's `detection:` block matched any single POST to `/wp-login.php` with no aggregation — as written it fires on ordinary, ubiquitous WordPress login traffic, since a single request to this endpoint is not itself anomalous (the original text acknowledged this in prose but never encoded the threshold). This entry contains **two Sigma objects, tallied separately, co-located in one block per correlation-rule convention**: the base selection (below, tier Hunting on its own — non-alerting, informational, exists only to feed the correlation) and the correlation itself (tier Detection — the actual alert). The correlation encodes the operator's real signature: 500+ requests to `/wp-login.php` from one source within 60 seconds, derived from the operator's 3-worker `ThreadPoolExecutor` pipeline against 30,000+ target sites. Volume-based, so it survives target-list and infrastructure rotation entirely.
**False Positives:** Authorized load-testing or offensive-security assessments against WordPress installations at or above the threshold; tune the count threshold upward for environments with known legitimate load-testing activity.
**Blind Spots:** An operator who throttles below the 500/60s threshold (e.g., reduces worker count) evades the correlation; the `c-ip` group-by field name assumes a W3C-extended-format webserver log — adjust the field name to match your log source's actual client-IP field.
**Validation:** Replay 500+ POSTs to `/wp-login.php` from one source within 60 seconds — the correlation must fire; fewer than 500 requests, or the same volume spread across many source IPs, must NOT fire.
**Deployment:** Web Application Firewall, reverse proxy access logs, Zeek http.log, SIEM with Sigma correlation-rule support.

```yaml
title: WordPress wp-login.php POST Request (Correlation Base)
id: c6ff58ec-caa8-43e8-a73d-7869abcae0eb
status: experimental
description: >-
  Base selection for the Mass WordPress Credential Validation Rate correlation rule below.
  Matches individual HTTP POST requests to /wp-login.php — not alerting-grade on its own
  (a single login POST is ordinary WordPress traffic); tier Hunting/informational, serves
  only as the correlation's input event.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.credential-access
    - attack.t1110.003
    - detection.emerging-threats
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/wp-login.php'
        cs-method: 'POST'
    condition: selection
falsepositives:
    - Any single legitimate login attempt to a WordPress site — not anomalous in isolation; see the correlation rule for the rate-based signal
level: informational
---
title: Mass WordPress wp-login.php Credential Validation Rate Exceeded — Possible A2A Credential Mill
id: a3f5c8e2-6b4d-4a91-8f2e-5d7c9b1a4e63
status: experimental
description: >-
  Fires when the base wp-login.php POST selection exceeds 500 events from a single source IP
  within a 60-second window — the mass-credential-validation signature of mass_wp_mutator.py
  and the operator's nuclei wp_admin_hunter.yaml template for UTA-2026-012 credential
  validation at scale (driven by a ThreadPoolExecutor 3-worker pipeline against target lists
  of 30,000+ WordPress sites). Replaces the original non-aggregating selection, which fired
  on any single POST and had no meaningful precision without this threshold.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.credential-access
    - attack.t1110.003
    - detection.emerging-threats
correlation:
    type: event_count
    rules:
        - c6ff58ec-caa8-43e8-a73d-7869abcae0eb
    group-by:
        - c-ip
    timespan: 60s
    condition:
        gte: 500
falsepositives:
    - Authorized load-testing or authorized offensive-security assessments against WordPress installations at or above the threshold
    - WordPress security scanner tools (WPScan, Jetpack Protect) — these generally use lower rates than 500/60s
level: high
```

### Hunting Rules

> **Tally note:** this subsection has 5 physical entries. A 6th Hunting-tallied object — the `wp-login.php` POST correlation *base* selection (id `c6ff58ec-caa8-43e8-a73d-7869abcae0eb`) — is co-located with its correlation rule under Detection Rules above, per the correlation co-location convention, rather than duplicated here.

#### Gemini CLI Directory Creation with Executable Contents on Server Host

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python)
**Confidence:** MODERATE
**Rationale:** The `~/.gemini/` directory paired with executable content is a genuine operator-side installation signal, but the selection logic itself does not encode a server-vs-workstation distinction (that scoping is deployment guidance, not detection logic) — and `GEMINI.md`/`SKILL.md` are the *standard* filenames the legitimate Gemini CLI itself creates on any developer machine. Scored on the logic as written, not the title: this is a broad directory+extension combination with a real legitimate-tool collision, not a durable Detection anchor.
**False Positives:** Legitimate Gemini CLI usage by developers on developer workstations — any project-init creates `GEMINI.md`; Google Cloud Workstations with Gemini CLI installed by default.
**Deployment:** Sysmon (Linux), auditd, file-integrity monitoring. Scope to server-class hosts by asset group or IP range before treating hits as high-confidence.

```yaml
title: Gemini CLI Directory Creation with Executable Contents on Server Host
id: dca5d3c0-5b22-453e-a36f-7696d927a739
status: experimental
description: >-
  Detects creation of ~/.gemini/ directory containing executable scripts (.sh, .py) or
  AI-priming documents on server-class Linux hosts. The UTA-2026-012 operator stores C2
  management skills (~/.gemini/skills/cf-c2-manager/SKILL.md), session handoff documents
  (~/.gemini/GEMINI.md), and Gemini CLI session JSONs (~/.gemini/tmp/root/chats/) on the
  C2 server itself. Legitimate Gemini CLI usage on servers is uncommon, but GEMINI.md and
  SKILL.md are the tool's own standard config filenames created on any developer machine —
  scope this rule to server-class infrastructure before treating hits as high-confidence.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1587
    - attack.execution
    - attack.t1059.006
    - detection.emerging-threats
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

#### Cloudflared Access TCP Tunnel to Potentially Unauthorized Hostname

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1572 (Protocol Tunneling), T1021.001 (RDP via tunnel), T1021.004 (SSH via tunnel)
**Confidence:** MODERATE
**Rationale:** Anchored on the technique (`cloudflared access tcp --hostname`, the interactive reverse-tunnel-to-arbitrary-host command form) rather than any specific domain, so it survives full rotation of the operator's infrastructure — but it requires an organization-specific allowlist to be populated before deployment, and ships with only a placeholder value.
**False Positives:** Organizations with legitimate Cloudflare Tunnel deployments using the `access tcp` command form (as opposed to the more common `tunnel run` service registration); developer workstations running cloudflared for legitimate service exposure.
**Deployment:** auditd execve, Sysmon (Linux), EDR process-creation on server-class hosts. Populate `filter_known_legit` with your organization's known Cloudflare Tunnel hostnames before deployment.

```yaml
title: Cloudflared Access TCP Tunnel to Potentially Unauthorized Hostname
id: 57ce00ce-d1ee-4621-9654-cefb4bf3b60d
status: experimental
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
date: '2026-05-25'
tags:
    - attack.command-and-control
    - attack.t1090.004
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.001
    - attack.t1021.004
    - detection.emerging-threats
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
        CommandLine|contains: 'your-org-tunnel.example.com'  # REPLACE with org's known CF Tunnel hostnames
    condition: selection and not filter_known_legit
falsepositives:
    - Legitimate organizational Cloudflare Tunnel deployments — populate the allowlist filter with known tunnel hostnames
    - Developer workstations running cloudflared for legitimate service exposure
level: medium
```

#### WindowsUpdateManager PowerShell Beacon Registry Run Key Persistence

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys), T1036 (Masquerading)
**Confidence:** MODERATE
**Rationale:** Keyed on a single operator-chosen literal — the `WindowsUpdateManager` masquerade value name — with no combinatorial fallback in the Sigma logic itself (unlike the YARA loader rule, which pairs this same value name with an additional C2-artifact clause). A rebuild that renames this one value fully evades. Today's false-positive rate is low (no legitimate Windows component uses this exact value name), but durability, not current precision, caps the tier here — **level recalibrated from the original `high` to `medium`** to match the Hunting tier per the level-discipline gate, since the rule does not survive a rename.
**False Positives:** None known today — `WindowsUpdateManager` is not a legitimate Windows Update component registry value; risk is entirely in the rule going stale after a rebuild, not in false alarms against current builds.
**Deployment:** Sysmon Event ID 13 (registry value set), Windows Event ID 4657, EDR registry monitoring. Pair with the YARA PowerShell-loader rule (which requires a corroborating C2-artifact clause) for higher-confidence composite alerting.

```yaml
title: WindowsUpdateManager PowerShell Beacon Registry Run Key Persistence
id: 833c2659-c255-4e42-a6b8-2cfd8b0b8ac1
status: experimental
description: >-
  Detects registry write to HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager
  pointing to %LOCALAPPDATA%\Microsoft\WindowsUpdateManager.ps1 — the operator-bespoke
  victim-side persistence mechanism for the UTA-2026-012 PowerShell C2 beacon documented
  in C2_INFRA_TRANSFER.md. Legitimate Windows Update components do not create HKCU Run keys.
  The WindowsUpdateManager value name is the operator's deliberate masquerade of Windows Update,
  but is a single renameable literal with no fallback anchor in this selection — a rebuild
  that renames the value evades detection entirely, so this is scoped as a Hunting signal
  rather than a Detection one despite today's low false-positive rate.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - attack.stealth
    - attack.t1036
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateManager'
    condition: selection
falsepositives:
    - Unlikely today — WindowsUpdateManager is not a legitimate Windows Update component registry value; a future rebuild renaming this value would evade rather than false-positive
level: medium
```

#### Python HTTP Server on Non-Standard Port with UTF-16LE Encoding (A2A C2 Pattern)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1059.006 (Python)
**Confidence:** MODERATE
**Rationale:** Keyed on the `c2_server`/`BaseHTTPServer` command-line substring — a script-naming/library-usage literal that a rebuild can trivially rename or replace. Retained as a hunting query, not a production alert, per the original assessment.
**False Positives:** Legitimate Python web services on non-standard ports (Django dev server, Flask, etc.); security testing frameworks (Impacket, Responder) using similar port patterns.
**Deployment:** EDR process-creation telemetry, auditd execve, threat hunting. Combine with the network-layer Suricata signature for higher-fidelity composite alerting.

```yaml
title: Python HTTP Server on Non-Standard Port with UTF-16LE Encoding (A2A C2 Pattern)
id: 253e1a6a-f4f3-4227-9106-94e9fdb4f949
status: experimental
description: >-
  Detects Python processes launching HTTP servers on non-standard ports (8081, 8090, 10101)
  co-occurring with utf-16le string in command line or script path — runtime signature of the
  UTA-2026-012 operator's c2_server.py BaseHTTPServer deployment. The UTF-16LE encoding is the
  C2's body encoding scheme for PowerShell beacon commands. Non-standard ports (8081/8090/10101)
  are the operator's documented multi-instance deployment pattern from c2_server.log filenames.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1132.001
    - attack.execution
    - attack.t1059.006
    - detection.emerging-threats
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
    condition: selection_python and selection_c2_server
falsepositives:
    - Legitimate Python web services on non-standard ports (Django dev server, Flask, etc.) — tune by excluding known-legitimate service paths and process owners
    - Security testing frameworks (Impacket, Responder) that use similar port patterns
level: low
```

#### Gemini CLI Directory Tooling Filename Created on Server Host

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1587 (Develop Capabilities)
**Confidence:** MODERATE
**Rationale:** **Salvage-split from the original combined rule** (companion to the Detection-tier bespoke-filename rule above) — isolates the broader `~/.gemini/` directory-context branch, which matches `DEPLOYED_TOOLS.md`/`CLOUDFLARE_INFRA.md`/`SKILL.md`/`GEMINI.md`. `SKILL.md` and `GEMINI.md` are the Gemini CLI's own standard configuration filenames, created by any legitimate developer install — this branch carries meaningfully higher FP than the bespoke-filename Detection rule it was split from, so it is scoped here as a hunting lead requiring analyst review, with **level recalibrated from the original `high` to `medium`**.
**False Positives:** `SKILL.md` and `GEMINI.md` in `~/.gemini/` — real collision with legitimate, authorized Gemini CLI developer installations; `DEPLOYED_TOOLS.md`/`CLOUDFLARE_INFRA.md` are more generic than the Detection-tier exemplars but still uncommon outside this operator's convention.
**Deployment:** File integrity monitoring, Sysmon Event ID 11, EDR file-creation telemetry. Add an operator-side allowlist for authorized Gemini CLI developer installations before treating `SKILL.md`/`GEMINI.md` hits as investigation-worthy.

```yaml
title: Gemini CLI Directory Tooling Filename Created on Server Host
id: b7d2e4f1-9a3c-4e58-b1d6-3f8a2c5e9d74
status: experimental
description: >-
  Detects file creation events matching the UTA-2026-012 operator's broader AI Operator
  Handoff Document naming conventions co-located in the ~/.gemini/ directory: DEPLOYED_TOOLS.md
  (When starting a new session load directive), CLOUDFLARE_INFRA.md, SKILL.md, and GEMINI.md.
  Split from the original combined rule during tiering because SKILL.md and GEMINI.md are
  the Gemini CLI's own standard configuration filenames, created by any legitimate developer
  installation — this branch carries real false-positive risk and is scoped as a hunting
  lead requiring an operator-side allowlist, distinct from the no-known-collision bespoke
  filenames covered by the companion Detection-tier rule.
references:
    - https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1587
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_gemini_dir_context:
        TargetFilename|contains: '/.gemini/'
        TargetFilename|endswith:
            - 'DEPLOYED_TOOLS.md'
            - 'CLOUDFLARE_INFRA.md'
            - 'SKILL.md'
            - 'GEMINI.md'
    condition: selection_gemini_dir_context
falsepositives:
    - >-
      SKILL.md and GEMINI.md in ~/.gemini/ — real collision with legitimate, authorized
      Gemini CLI developer installations; tune by adding an operator-side allowlist
    - DEPLOYED_TOOLS.md and CLOUDFLARE_INFRA.md in ~/.gemini/ context — lower FP; investigate any match on server hosts
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### A2A C2 Beacon POST to Operator Endpoint with X-Agent-ID Header

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**Rationale:** Anchors on the operator-bespoke `X-Agent-ID` header name, the POST method, and the `/api/v1/` endpoint family — none of which reference the operator's specific domain, so the rule survives complete infrastructure rotation. No legitimate web application framework uses this header name in this endpoint naming pattern. Added a literal `content` prefilter ahead of the URI `pcre` (not present in the original) so the regex is gated behind a content match per current formatting standards.
**False Positives:** None known — the combination of `/api/v1/update` or `/api/v1/interact` paths with the `X-Agent-ID` header is operator-bespoke and has no known legitimate-software counterpart.
**Blind Spots:** A rewrite that renames the header and endpoint family evades detection; TLS-encrypted traffic without inline decryption is not inspectable at the HTTP layer by this signature alone (pair with the TLS/JA-fingerprint layer if available).
**Validation:** Replay a PCAP of an A2A C2 beacon check-in — must alert; an unrelated HTTP POST carrying neither the header nor the endpoint pattern must NOT fire.
**Deployment:** Inline or passive HTTP inspection, Zeek http.log, WAF/proxy with content inspection.

```suricata
alert http $HOME_NET any -> any any (msg:"THL - A2A C2 Beacon POST to Operator C2 Endpoint with X-Agent-ID Header"; flow:established,to_server; http.method; content:"POST"; http.header_names; content:"X-Agent-ID"; nocase; http.uri; content:"/api/v1/"; pcre:"/\/api\/v1\/(update|interact|telemetry|get_results)/"; classtype:trojan-activity; sid:9000003; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/;)
```

### Hunting Rules

#### cloudflared Tunnel QUIC Egress to Cloudflare Edge (UDP 7844)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**Rationale:** Cloudflare Tunnel's control-plane connects to Cloudflare's edge over UDP/TCP 7844 specifically — Cloudflare's dedicated tunnel port, not general web QUIC (443) — so this is meaningfully narrower than matching all UDP/443 and does not fire on ordinary browsing or Cloudflare WARP. It is still a port-based signal that any Cloudflare Tunnel deployment (legitimate or not) will trigger, so it stays a hunting lead rather than an alert.
**False Positives:** Legitimate Cloudflare Tunnel deployments also use UDP 7844.
**Deployment:** Network flow telemetry / IDS on egress; Zeek conn.log with a UDP/7844 filter. Corroborate with DNS visibility for `*.tralalarkefe.com` and the campaign's Cloudflare quick-tunnel subdomain (both carried in the IOC feed) and/or scope the source to segments where Cloudflare Tunnel is not expected.

```suricata
alert udp $HOME_NET any -> $EXTERNAL_NET 7844 (msg:"THL - cloudflared Tunnel QUIC Egress to Cloudflare Edge (UDP 7844 Hunting)"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:policy-violation; sid:9000006; rev:3; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/russian-gemini-credential-mill-213.165.51.115-detections/;)
```

---

## Coverage Gaps

### Atomics Retired to the IOC Feed (7 rules: 3 Sigma, 4 Suricata)

Every rule below keyed solely on one hard-coded domain, with no combinatorial or behavioral clause surviving its removal — per the routing test, these are IOC-feed entries, not standalone rules. All underlying domains were **already present** in [`russian-gemini-credential-mill-213.165.51.115-iocs.json`](/ioc-feeds/russian-gemini-credential-mill-213.165.51.115-iocs.json); no feed edits were required.

- **Sigma — Gemini API Egress from Server-Class Infrastructure Host** (`173cf9ee-97c5-4d51-8487-856f63894ad5`): keyed on `generativelanguage.googleapis.com` (DestinationHostname match). The accompanying filter excluded, rather than isolated, the likely-Python accessing process, so it added no real precision beyond the bare domain match. The domain is preserved in the feed with a `MONITOR` action and an explicit `high` false-positive-risk note (it is Google's own legitimate API domain, abused rather than owned by the operator).
- **Sigma — Cloudflare Tunnel Registration to tralalarkefe.com Operator Infrastructure** (`1003c111-2038-43bc-b463-b5895cd6f408`): keyed on `tralalarkefe.com` in a `cloudflared` command line. Removing the domain leaves "any cloudflared execution," which is not malicious on its own — the durable, non-domain-specific version of this technique lead is retained as the Hunting-tier "Cloudflared Access TCP Tunnel to Potentially Unauthorized Hostname" rule above.
- **Sigma — Outbound HTTP to AntiPublic.one Credential Database API from Non-Research Host** (`163023b7-5615-4c9f-9e30-60af0bd2cd8e`): keyed on `antipublic.one` (DestinationHostname match). Preserved in the feed with a `MONITOR` action.
- **Suricata — DNS Query to \*.tralalarkefe.com** (sid `9000001`): keyed on the same root domain as the Sigma entry above; retired for the same reason.
- **Suricata — DNS Query to generativelanguage.googleapis.com from Server-Class Hosts** (sid `9000002`): keyed on the same domain as the Sigma entry above; retired for the same reason.
- **Suricata — HTTP Egress to antipublic.one /api/v2/search** (sid `9000004`): the `/api/v2/search` URI clause is a generic-sounding REST path with no specificity of its own once the `antipublic.one` host anchor is removed; retired for the same reason as the Sigma AntiPublic entry.
- **Suricata — trycloudflare.com Tunnel Bootstrap DNS from Server Hosts** (sid `9000005`): keyed on the bare `trycloudflare.com` suffix — Cloudflare's entire free quick-tunnel product surface, not an operator-specific atomic. The campaign's actual atomic (the specific bootstrap subdomain `tenant-upcoming-great-descending.trycloudflare.com`) is already in the feed; the bare-suffix version added no incremental value and would have been a needlessly broad new feed entry, so it was retired rather than generalized into a new block entry.

### Cut Rule

**Telegram API Egress with Americanpatriotus Channel Reference** (original Sigma rule `8be13baf-aa35-422c-8757-9cfea720af53`). The rule's title and rationale describe detecting posting activity to the `@americanpatriotus` channel, but the YAML `detection:` logic never actually references that channel identifier anywhere — Sigma cannot inspect TLS-encrypted message bodies, so the channel name was never encodable in the first place. As written, the logic reduces to "`api.telegram.org` DNS/network match AND a Python process," which the original text itself acknowledged is common in legitimate bot deployments ("False Positive Risk: HIGH"). With the channel-specific claim removed, nothing distinguishing survives — this fires on ubiquitous, legitimate Telegram-bot activity with no pivot value, and does not clear the precision bar even for Hunting. **What would enable a rule:** TLS-inspecting proxy visibility into the message body, or a Telegram Bot API token/chat-ID specific to this operator's bot (neither was recovered from this investigation).

### Techniques Observed But Not Fully Covered

**1. LLM-Vendor-Side Detection (Gemini API abuse telemetry).** The operator's `check_keys.py` validates 40+ stolen Gemini API keys against Google's model-listing endpoint with high key-diversity from a single source IP. Detecting this key-rotation pattern requires server-side telemetry from Google's Generative Language API — specifically, `/v1beta/models` calls where a single source IP cycles through >10 distinct `?key=` values within 60 seconds. This is beyond standard defender scope, and beyond what a domain-match Sigma/Suricata rule can encode (see the retired Gemini-egress entries above). **Coordination path:** Google Trust & Safety, with the operator's full key inventory.

**2. Telegram Disinformation Content Detection.** The `quantum_patriot.py` script posts AI-rewritten RSS content to `@americanpatriotus` via the Telegram Bot API. Distinguishing this channel's AI-generated content from organic political posting requires semantic content classification beyond standard SOC capability and beyond what any network-layer Sigma/Suricata rule can encode — see the Cut rule above. **Coordination path:** Telegram Trust & Safety for the `@americanpatriotus` channel, independently corroborated by Trend Micro (2026-05-22).

**3. GitHub PAT Abuse Correlation.** The operator's GitHub PAT is used for repository management and potentially exfiltration of victim artifacts via GitHub as an exfil channel (T1567.002). Per-PAT API call correlation across GitHub infrastructure requires GitHub Trust & Safety coordination. **Coordination path:** GitHub Trust & Safety, with the operator's account identifiers.

**4. Per-Victim Cloudflare Tunnel Access Detection.** The operator's `windows_server.tralalarkefe.com` and `gil_dr1.tralalarkefe.com` Cloudflare Tunnel endpoints provided persistent RDP and SSH access to the victim machines at capture time. Detecting specific victim-machine beacon activity on these tunnels from the defender's side requires either victim-side egress logs or Cloudflare PSIRT coordination. The domain-level DNS signal for these subdomains lives in the IOC feed rather than as a standalone rule (see Atomics Retired above); the port-based QUIC/7844 Hunting rule above provides a domain-independent fallback signal.

**5. agent_final.ps1 PowerShell Beacon (Binary Not Captured).** The victim-side PowerShell beacon `agent_final.ps1` is referenced extensively in the operator's handoff documents, but the binary itself was not recovered — rules for it are derived from the C2 server's endpoint-contract specification rather than direct code analysis. If the beacon is later recovered, the following indicators should enable high-confidence matching: `X-Agent-ID: HOSTNAME_username` header format, 5-second beacon interval to `/api/v1/update`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` User-Agent, `base64(UTF-16LE)` body encoding on `/api/v1/telemetry` POST.

**6. WMI EventConsumer Fileless Persistence (stealth.ps1).** The operator's `C2_MIGRATION_GUIDE.md` references a `stealth.ps1` script providing WMI EventConsumer + EventFilter + FilterToConsumerBinding triplet persistence, in addition to the HKCU Registry Run key covered above. The `stealth.ps1` binary was not recovered; generic WMI subscription persistence detection (Sysmon Event ID 19/20/21 matching `\\.\root\subscription`) covers the technique pattern but cannot provide operator-specific file/value-name signatures without direct binary access.

**7. NTLM Dump → Cloudflare Tunnel Exfiltration (Full Temporal Correlation).** The Detection-tier "Suspicious LSASS Process Access via High-Privilege GrantedAccess Mask" Sigma rule above captures only the LSASS-access stage of the operator's documented two-stage sequence (dump, then exfiltrate via Cloudflare Tunnel within roughly 10 minutes). A full `temporal_ordered` Sigma correlation joining LSASS access to Cloudflare Tunnel/`trycloudflare.com` egress by host within a 10-minute window was not attempted in this backfill — the cross-event-type `group-by` field alignment (process-access telemetry vs. network-connection telemetry) needs validation against a live SIEM schema before publication. **What would enable this:** confirming the common host-identifier field name across both log sources in the target deployment.

**8. OpenDental MySQL Hash Reuse / Database Access.** The operator holds the OpenDental MySQL root hash from the primary named victim. Detection of unauthorized OpenDental database access would require MySQL audit logging at the victim's practice-management server — out of scope for a third-party detection provider. **Coordination path:** Direct victim notification (via HC3/HHS OCR HIPAA track).

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
