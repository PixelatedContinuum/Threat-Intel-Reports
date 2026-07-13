---
title: "Detection Rules — Rovodev AI Co-Authored Pandora-Mirai Variant + Matrix C2 Framework"
date: '2026-05-26'
layout: post
permalink: /hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/
thumbnail: /assets/images/cards/rovodev-mirai-matrix-c2-87.106.143.220.png
hide: true
---

**Campaign:** UTA-2026-014 / rovodev-mirai-matrix-c2-87.106.143.220
**Date:** 2026-05-26
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/

> **Note:** This is the per-case detection file for Sub-report 4 of 5 (Case 3) in the parent series `ai-agent-frameworks-2026-05-23`. Cross-operator AI-Generated Code Signature rules are in `ai-agent-frameworks-2026-05-23-detections.md` and are not duplicated here.

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 4 | T1014, T1027, T1037.004, T1053.003, T1059.004, T1059.006, T1059.007, T1071.001, T1095, T1497.001, T1498.001, T1498.002, T1543.002, T1546.004, T1584.004, T1587.001 | 0 |
| Sigma | 4 | 6 | T1014, T1027, T1037.004, T1053.003, T1059.004, T1059.007, T1095, T1190, T1498.001, T1543.002, T1546.004, T1564.001, T1587.001 | 2 |
| Suricata | 2 | 8 | T1027, T1059.007, T1071.001, T1095, T1190, T1498.001, T1584.004, T1587.001, T1588.001 | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Retiering note (this revision):** this file was re-tiered against the `detection-rule-tiering` 4-gate rubric (durability → precision → level; novelty not applied at site scope). Original rule bodies are preserved wherever the gates supported Detection or Hunting as originally written. Five rules whose entire detection logic reduced to a single hardcoded IP with no surviving behavioral content — two Sigma network-connection rules and three Suricata rules — are removed as standalone rules; the underlying IPs were already present in the campaign IOC feed, so no feed edits were required. Several brittle-but-real rules (three YARA, one Sigma, seven Suricata) were salvaged via capability-abstraction rewrites — most commonly, dropping a mandatory hardcoded-IP condition term or broadening a Suricata destination from a single operator IP to `$EXTERNAL_NET` — so the underlying behavioral/structural signal survives infrastructure rotation. Each salvage is called out in the affected rule's Rationale.

**Highest-confidence anchors:**
- The operator-bespoke 22-char charset (`1gba4cdom53nhp12ei0kfj`, XOR-0x54 encoded) present in all 11 Naku/Pandora-Mirai architectures, combined with the Sora-fork `/bin/busybox SORA` marker and canonical Mirai debug symbols — cross-arch YARA coverage with near-zero FP.
- The Matrix C2 Python framework's AI-authored banner/docstring/emoji-branding combination and the Discord-bot 13-method attack dispatch table — both structurally unique to this operator's build and resistant to single-string rename.
- The `/etc/cron.d/.` hidden-prefix cron persistence Sigma rule — a pure technique-level signal (T1564.001) carrying zero operator-specific literals, so it survives complete infrastructure and binary-naming rotation.

**Atomics routed to the IOC feed:** the Matrix C2 JSON-over-TCP/1337 channel (`87.106.143.220:1337`), the parasitic Naku CNC (`165.227.175.161:23`), and the two IONOS VPS IPs used as bare TLS-pivot destinations (`87.106.143.220`, `87.106.54.213`) were each the sole discriminator of a standalone Sigma or Suricata rule with no surviving behavioral content once the IP was mentally removed. All four IPs were already present with rich context in [`rovodev-mirai-matrix-c2-87.106.143.220-iocs.json`](/ioc-feeds/rovodev-mirai-matrix-c2-87.106.143.220-iocs.json) prior to this revision — no feed edits were required.

**Calibration note — prior art:**
- Pandora-Mirai variant family traces to Doctor Web September 2023 (Tier 2 / B2); original scope was Android-TV only. The 11-architecture IoT extension documented here is first public characterization.
- AI-Generated Offensive Code Structural Signature: Google GTIG documents "verbose docstrings" + "textbook Pythonic format" for individual exploit scripts; the 5-criteria universal-subset signature confirmed cross-3-operators is net-new public characterization.
- Atlassian Rovodev abuse: first publicly-documented case (no prior art found in Tier 1–3 sources).
- MaaS hypothesis REFUTED (Phase 11): Pandora-Mirai is open-source shared ecosystem. This operator is a downstream adopter, not the variant author.

---

## Multi-Family Organization

This campaign spans three operator-artifact groups, each labeled inline within the Detection/Hunting subsections below:

- **Pandora-Mirai (Naku ELF Bot Suite)** — the 11-architecture IoT botnet binaries and their bash dropper.
- **Matrix C2 Framework** — the AI-co-authored Python DDoS-as-a-Service framework and its Discord-bot customer interface.
- **Rovodev Operator Artifacts** — the operator's AI-agent session artifacts and natural-language prompts exposed via open directory.

---

## YARA Rules

### Detection Rules

**Pandora-Mirai (Naku ELF Bot Suite)**

#### MAL_ELF_Naku_Pandora_Mirai_Family

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1095 (Non-Application Layer Protocol), T1498.001 (Direct Network Flood)
**Confidence:** HIGH
**Rationale:** The operator-bespoke 22-char charset `1gba4cdom53nhp12ei0kfj` is present in all 11 architectures; combined with the Sora-fork `/bin/busybox SORA` marker, the `PandoraNet` botnet ID, and canonical Mirai debug symbols (`add_auth_entry`, `resolve_cnc_addr`), no single renameable literal carries the rule — an operator would need to regenerate the charset, rename the Sora-fork marker, and strip debug symbols simultaneously to evade. Unchanged from the original file.
**False Positives:** None known — the 22-char charset is operator-bespoke and not found on any other host in Hunt.io's 365-day index; `/bin/busybox SORA` is Sora-fork-specific and absent from stock Mirai or generic IoT tools; `PandoraNet` is unique to this operator.
**Blind Spots:** A full rebrand that regenerates the charset AND renames the Sora-fork marker AND strips debug symbols would evade; targets on-disk/in-memory ELF, not a live network capture.
**Validation:** Scan a Naku/Pandora-Mirai sample across any of the 11 architectures — at least one condition branch must match; a benign or stock-Mirai ELF binary must NOT fire.
**Deployment:** Endpoint ELF scanner, network sandbox detonation, IoT device firmware scanner, memory scanner on compromised Linux hosts.

```yara
/*
   Yara Rule Set
   Identifier: Naku/Pandora-Mirai 11-arch IoT botnet (UTA-2026-014)
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MAL_ELF_Naku_Pandora_Mirai_Family {
   meta:
      description = "Detects Naku/Pandora-Mirai 11-architecture IoT botnet based on operator-bespoke 22-char random-string charset, Sora-fork /bin/busybox SORA derivative marker (XOR-0x54 encoded), and canonical Mirai botnet symbols. Operator uses triple XOR keys (0x54/0x42/0x45); charset is present in all 11 release architectures and acts as cross-arch tracking signature."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      $charset_xor = { 65 33 36 35 60 37 30 3B 39 61 67 3A 3C 24 65 66 31 3D 64 3F 32 3E }
      // Sora-fork derivative: /bin/busybox SORA XOR-0x54 encoded
      $sora_xor = { 7B 36 3D 3A 36 21 27 36 3B 2C 74 24 27 20 61 }
      // PandoraNet operator botnet ID (plaintext in arm7 debug build and process args)
      $pandoranet = "PandoraNet" ascii fullword
      // Mirai canonical function symbols (arm7 debug build; DEFINITE Mirai-lineage markers)
      $sym_auth = "add_auth_entry" ascii fullword
      $sym_resolve = "resolve_cnc_addr" ascii fullword
      // .anime operator-bespoke marker (XOR-0x54 decoded)
      $anime_xor = { 7F 61 59 97 }
   condition:
      uint32(0) == 0x464C457F and
      filesize < 200KB and
      (
         ($charset_xor and $sora_xor) or
         ($charset_xor and $pandoranet) or
         ($sym_auth and $sym_resolve and $charset_xor) or
         ($pandoranet and $sym_auth and $sym_resolve) or
         ($charset_xor and $anime_xor)
      )
}
```

#### MAL_Bash_Pandora_Dropper_Family

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1059.004 (Unix Shell), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH
**Rationale:** Salvaged from the original — every condition branch required a hardcoded operator IP (`87.106.143.220` or `80.211.94.16`), so the rule would stop detecting entirely the moment the operator rotated VPS (Gate 1 durability failure; both IPs are already carried in the campaign IOC feed). Rewritten to drop the IP dependency and anchor purely on the 11-arch dropper's structural signature: ≥3 of a 6-member IoT-architecture suffix set combined with `Naku.`/`Pandora.` binary naming, or the operator's specific execution-tag/cleanup command sequence. This survives full infrastructure rotation; an operator would need to rename every dropped binary and change the exec-tag convention to evade.
**False Positives:** None known — the arch-suffix-set-plus-naming combination and the `pandora_bot PandoraNet` / `./nig realtek` exec-tag patterns have no legitimate collision.
**Blind Spots:** A rebrand that renames the arch-tagged binaries AND drops the `Naku.`/`Pandora.` prefix AND changes the exec-tag convention would evade; targets the on-disk dropper script, not network delivery.
**Validation:** Scan the dropper script (`hash1` below) — the arch-count/naming branch or an exec-tag branch must match; a benign multi-arch build/CI script must NOT fire.
**Deployment:** Linux filesystem scanner (bash scripts), web proxy log scanning for outbound fetches matching this pattern.

```yara
rule MAL_Bash_Pandora_Dropper_Family {
   meta:
      description = "Detects pandora.sh / Naku.sh dropper class fetching 11-architecture Pandora-Mirai ELF binaries via wget/curl loop. Operator-specific arch-set (arm5/arm6/m68k/mpsl/sh4/spc), Naku./Pandora. binary naming, execution-with-arch-tag pattern, and cleanup sequence identify this dropper family independent of current distribution-host IP."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      // Binary naming conventions
      $bin_naku    = "Naku." ascii
      $bin_pandora = "Pandora." ascii
      // Execution-with-arch-tag pattern (argv-source-tagging) — IP-independent
      $exec_tag_r  = "./nig realtek" ascii
      $exec_tag_n  = "pandora_bot PandoraNet" ascii
      // Cleanup pattern
      $cleanup     = "rm -rf nig" ascii
   condition:
      filesize < 50KB and
      (
         (3 of ($arch_*) and ($bin_naku or $bin_pandora)) or
         ($exec_tag_r and $cleanup) or
         $exec_tag_n
      )
}
```

**Matrix C2 Framework**

#### MAL_Python_Matrix_C2_Framework_Family

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.006 (Python), T1498.001 (Direct Network Flood), T1498.002 (Reflection Amplification), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH
**Rationale:** Direct AI-authored strings captured from Rovodev session_context.json file_write payloads. The MATRIX C2 ASCII-banner header, `mass_infection` docstring, emoji-branded attack-method names, and the operator-marketing `50Gbps+` comment form multiple independent phrase anchors — no single renameable literal carries the rule. Unchanged from the original file.
**False Positives:** None known — the banner + emoji-branded attack-method names + `50Gbps+` marketing comment combination is specific to this operator's framework; no known legitimate tool uses this combination.
**Blind Spots:** A full source rewrite that strips all banner/docstring/emoji strings would evade; targets on-disk/in-memory Python source, not compiled/obfuscated builds.
**Validation:** Scan `master_control.py` / `attack_engine.py` / `multi_vector_agent.py` (hashes below) — at least one condition branch must match; unrelated legitimate DDoS-testing or load-testing tools must NOT fire.
**Deployment:** Linux filesystem scanner (Python scripts), network sandbox detonation, SIEM content search on analyst workstations.

```yara
rule MAL_Python_Matrix_C2_Framework_Family {
   meta:
      description = "Detects Matrix C2 Python DDoS-as-a-Service framework files authored via Atlassian Rovodev AI coding agent. Identifies master_control.py, attack_engine.py, and multi_vector_agent.py via AI-generated banner strings, operator-marketing comments, emoji-branded attack method catalog entries, and mass-infection docstring captured directly from Rovodev session file_write tool call payloads."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
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
      $banner     = "MATRIX C2 - IMPLEMENTATION PLAN" ascii
      $docstring  = "Launch mass infection campaign" ascii
      $emoji_icmp = "\xf0\x9f\x94\xa5 ICMP Hell" ascii
      $emoji_udp  = "\xf0\x9f\x9a\x80 UDP Bypass" ascii
      $gbps_claim = "Increased default threads for 50Gbps+" ascii
      $final_doc  = "FINAL_DEPLOYMENT_COMPLETE" ascii
      $ultimate   = "ULTIMATE_DEPLOYMENT" ascii
      $llm_close  = "Let me start Phase 1 now" ascii
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

#### MAL_Discord_Bot_DDoSasService_Customer_Interface

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood), T1498.002 (Reflection Amplification)
**Confidence:** HIGH
**Rationale:** The JavaScript attack-method dispatch table requires renaming or removing most of an 8-entry bespoke method catalog (`udp-star`, `syn-storm`, `tcp-matrix`, `tcp-rst`, `udp-bypass`, `icmp-hell`, `multi-vector`, `http-flood`, `mass_infection`, `frag-storm`, `dns-rain`, `ovh-nuke`, `http-star`) plus the tier/GBPS/emoji branding to evade — a substantial rewrite. Unchanged from the original file.
**False Positives:** None known — the specific combination of 13+ DDoS attack-method names with VIP tier model and GBPS estimates is not found in legitimate Discord bots; emoji branding narrows further.
**Blind Spots:** A full dispatch-table rewrite under new method names would evade; targets the on-disk/in-memory JS source.
**Validation:** Scan the Discord bot JS source (`hash1` below) — at least one condition branch must match; unrelated legitimate Discord moderation/utility bots must NOT fire.
**Deployment:** JavaScript/Node.js file scanner, Discord bot code review, web application code analysis.

```yara
rule MAL_Discord_Bot_DDoSasService_Customer_Interface {
   meta:
      description = "Detects Matrix C2 Discord-bot customer interface JavaScript dispatch table for DDoS-as-a-Service. Identifies the 13-attack-method catalog (udp-star, syn-storm, tcp-matrix, tcp-rst, udp-bypass, icmp-hell, multi-vector, http-flood, mass_infection, frag-storm, dns-rain, ovh-nuke, http-star) combined with VIP/free tier branding, GBPS capability estimates, and AI-Generated Code Signature emoji branding."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "81748f0236319c678db39945ec77fffe1b33e84ffa9731b2836b911f8e83a5cc"
      family = "Matrix C2"
      malware_type = "DDoS-as-a-Service Bot Interface"
      campaign = "UTA-2026-014"
      id = "0f9967aa-bd3f-5fba-be62-bf75b119989b"
   strings:
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
      $tier_vip   = "vip: true" ascii
      $tier_free  = "vip: false" ascii
      $gbps_field = "gbps:" ascii
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

**Rovodev Operator Artifacts**

#### MAL_JSON_Rovodev_SessionContext_FileWrite_Authoring

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH
**Rationale:** Salvaged from the original — one condition branch matched on either of two literal Rovodev session UUIDs alone (`257b6faf-...` / `8b911ec6-...`), a single-sample identifier with zero generalizability (equivalent to a hash match, not a signature). Removed that branch and tightened the remaining "session artifact" branch to require a malicious-content marker (`mass_infection` docstring or `MATRIX C2` header) rather than firing on any Rovodev session that merely writes a Python file — the untightened version would have matched any benign Rovodev coding session.
**False Positives:** Low — `session_context`/`file_write`/`initial_content`/`rovodev.log` are all legitimate Atlassian Rovodev artifact names, but every surviving condition branch requires a co-occurring malicious content marker (`Launch mass infection campaign` docstring or `MATRIX C2` banner), which have no legitimate collision.
**Blind Spots:** A future AI-authoring session that produces equivalent malicious capability without ever writing the exact `mass_infection`/`MATRIX C2` phrases would evade; requires the operator's OPSEC failure of exposing the session artifact.
**Validation:** Scan an exposed Rovodev session_context.json/rovodev.log containing the Matrix C2 authoring session — must match; a benign Rovodev session writing unrelated Python code must NOT fire.
**Deployment:** Web crawler for open-directory detection, filesystem scanner on suspected operator hosts.

```yara
rule MAL_JSON_Rovodev_SessionContext_FileWrite_Authoring {
   meta:
      description = "Detects operator-exposed Atlassian Rovodev AI coding agent session artifacts (session_context.json / rovodev.log) containing file_write tool calls with offensive Python initial_content payloads, gated on a co-occurring Matrix C2 content marker to exclude benign Rovodev sessions."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "9eece9f46bc420b53884d4292622621c9960459c1d7a73635420771e7d0aa1fa"
      family = "Rovodev Operator Artifacts"
      malware_type = "AI Coding Agent Session Artifact"
      campaign = "UTA-2026-014"
      id = "826c0fe7-b1fc-5689-9fd7-69e2abc40277"
   strings:
      $session_key = "session_context" ascii
      $tool_call   = "file_write" ascii
      $init_content = "initial_content" ascii
      $rovo_log    = "rovodev.log" ascii
      $py_shebang  = "#!/usr/bin/env python3" ascii
      $mass_infect = "Launch mass infection campaign" ascii
      $c2_header   = "MATRIX C2" ascii
   condition:
      filesize < 2MB and
      (
         ($session_key and $tool_call and $init_content and $py_shebang and ($mass_infect or $c2_header)) or
         ($tool_call and $mass_infect) or
         ($rovo_log and $c2_header)
      )
}
```

#### MAL_Python_Persistent_Bot_DualChannel_CNC

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1059.004 (Unix Shell), T1071.001 (Web Protocols), T1543.002 (Systemd Service), T1546.004 (Unix Shell Configuration Modification)
**Confidence:** HIGH
**Rationale:** Multi-branch rule where 3 of 5 branches (hidden cron entry + masquerade init.d/systemd names; heartbeat message + port + hidden cron; JSON field-name structure) carry no dependency on the operator's C2 IP, so the rule survives infrastructure rotation even though two branches additionally reference the hardcoded IP as a strengthening (not sole) anchor. Unchanged from the original file.
**False Positives:** None known — the hidden `.cache_update` cron filename, the `sysupdate`/`system-update.service` masquerade pair, and the `bot_register`/`arch`/`vendor` JSON wire-format fields have no plausible legitimate collision in combination.
**Blind Spots:** A rebuild that renames the masquerade persistence files AND changes the JSON wire-format field names would evade; targets the on-disk installer script.
**Validation:** Scan `persistent_bot.sh` (hash below) — at least one condition branch must match; a benign system-update or configuration-management script must NOT fire.
**Deployment:** Linux filesystem scanner (bash scripts), EDR persistence monitoring for cron/init.d/systemd creation events.

```yara
rule MAL_Python_Persistent_Bot_DualChannel_CNC {
   meta:
      description = "Detects persistent_bot.sh-class operator scripts implementing 5-vector Linux persistence and dual-channel CNC architecture. Identifies operator-specific JSON wire format (bot_register + heartbeat messages with bot_type/arch/vendor fields), hidden cron entry /etc/cron.d/.cache_update, and masquerade persistence (sysupdate init.d service + system-update.service systemd unit)."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "4809a7ee9f5dbcbe86cfbd77a45e2a268a37bcc947e8e1621164df653597948b"
      family = "Matrix C2"
      malware_type = "Persistence Installer (AI-authored)"
      campaign = "UTA-2026-014"
      id = "91f7bf1a-6620-50cf-81c0-ff7faf1328e3"
   strings:
      $wire_reg   = "\"type\":\"bot_register\"" ascii
      $wire_arch  = "\"arch\":\"$arch\"" ascii
      $wire_vendor = "\"vendor\":\"$vendor\"" ascii
      $wire_hb    = "\"type\":\"heartbeat\"" ascii
      $cnc_ep     = "87.106.143.220" ascii
      $cnc_port   = "1337" ascii
      $cron_hidden = "/etc/cron.d/.cache_update" ascii
      $initd_mask  = "/etc/init.d/sysupdate" ascii
      $systemd_mask = "/etc/systemd/system/system-update.service" ascii
      $reseed     = "wget -qO- http://87.106.143.220/bot.sh" ascii
      $kill_comp  = "pkill -9 -f \"(mirai|qbot|tsunami|gafgyt|bashlite|kaiten)\"" ascii
   condition:
      filesize < 50KB and
      (
         ($wire_reg and $cnc_ep) or
         ($cron_hidden and ($initd_mask or $systemd_mask)) or
         ($reseed and $kill_comp) or
         ($wire_hb and $cnc_port and $cron_hidden) or
         ($wire_arch and $wire_vendor and ($wire_reg or $wire_hb))
      )
}
```

### Hunting Rules

**Matrix C2 Framework**

#### MAL_Python_AIGenerated_OffensiveCode_Universal_Subset

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE (HIGH for the universal-subset criteria as a class; MODERATE for any individual file match without corroborating context)
**Rationale:** Cross-3-operator confirmed universal subset (verbose docstrings, bare-except handlers, educational variable names, emoji-in-output bleed, version-numbered file chains) of the AI-Generated Code Structural Signature. The structural criteria are durable (survive renaming, target code structure not literal names), but verbose docstrings and bare-except are common in legitimate Python code — the original author explicitly flagged this for analyst triage rather than automated block, which is the definition of the Hunting tier. Unchanged from the original file.
**False Positives:** Verbose docstrings and bare-except handlers are common in legitimate Python code; the multi-criteria co-occurrence gate reduces but does not eliminate this. Deploy for analyst triage, not automated block.
**Deployment:** Code repository scanner, Python script analyst triage, threat hunting in developer-accessible environments. Do NOT deploy as automated block.

```yara
rule MAL_Python_AIGenerated_OffensiveCode_Universal_Subset {
   meta:
      description = "Cross-operator detection for AI-generated offensive Python code using the 5-criteria universal subset confirmed across 3 independent operators (Russian Gemini, Turkish ARPA, English Rovodev). Detects co-occurrence of verbose docstrings, bare-except handlers, educational variable naming, emoji-in-output bleed, and version-numbered iteration chains. High FP risk in isolation; requires multi-criteria co-occurrence gate — analyst triage, not automated block."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "64ca12cae6f5e520abb4158da3bbc14e909c2128748ae0c5806fa4206cc14260"
      family = "AI-Generated Offensive Code"
      malware_type = "Offensive Python (AI-authored)"
      campaign = "ai-agent-frameworks-2026-05-23"
      id = "38aeca8a-3dad-5b61-9787-a14edf92a250"
   strings:
      $bare_except1 = "except:" ascii
      $bare_except2 = "except Exception:" ascii
      $bare_pass    = /except[^\n]*:\s*\n\s*pass/ ascii
      $doc_attack   = /def \w+_attack\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_flood    = /def \w+_flood\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_scan     = /def \w+_scan\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $doc_infect   = /def \w+_infect\w*\(.*\):\s*\n\s+\"\"\"/ ascii
      $emoji_fire   = "\xf0\x9f\x94\xa5" ascii
      $emoji_rocket = "\xf0\x9f\x9a\x80" ascii
      $emoji_check  = "\xe2\x9c\x85"     ascii
      $ver_chain_v2 = "_v2." ascii
      $ver_chain_v3 = "_v3." ascii
      $ver_chain_v4 = "_v4." ascii
      $ctx_ddos  = "ddos" nocase ascii
      $ctx_flood = "flood" nocase ascii
      $ctx_brute = "brute" nocase ascii
      $ctx_infect = "infect" nocase ascii
      $ctx_cnc   = "cnc" nocase ascii
   condition:
      filesize < 500KB and
      (uint16(0) == 0x2123 or $bare_except1 or $bare_except2) and
      (1 of ($ctx_*)) and
      (
         ($bare_pass and 1 of ($doc_*)) or
         (1 of ($emoji_*) and 1 of ($doc_*)) or
         (2 of ($ver_chain_v2, $ver_chain_v3, $ver_chain_v4) and 1 of ($doc_*))
      )
}
```

#### MAL_Python_StealthAgent_AntiDebug_AntiVM_AI_Authored

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1014 (Rootkit), T1059.006 (Python), T1497.001 (System Checks — MODERATE), T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE
**Rationale:** Salvaged from the original — the condition mandated the hardcoded C2 endpoint `87.106.143.220` as an AND-gate across every branch, so the rule died the instant the operator rotated infrastructure (the IP is already carried in the IOC feed). Removed the IP/port strings and condition dependency entirely, leaving a pure anti-analysis feature-bucket signature (anti_debug + anti_vm + sandbox keyword co-occurrence with rootkit/self-destruct, or the AES-GCM+PBKDF2+handshake crypto framing, or polymorphic+bare-except). These are generic English feature-name strings individually (per the "no generic API-name `any of them`" YARA anti-pattern), so co-occurrence is required but the combination is still not goodware-validated to zero FP — Hunting, not Detection.
**False Positives:** Legitimate Python security/red-team tooling that legitimately implements anti-debug/anti-VM checks alongside self-destruct or rootkit-adjacent terminology (uncommon but not impossible); the AES-GCM+PBKDF2+handshake branch alone is common to many encrypted-messaging implementations.
**Deployment:** Linux filesystem scanner (Python scripts), EDR behavioral monitoring for Python processes with anti-VM API calls; corroborate with the family-specific YARA/Sigma rules above before high-confidence attribution.

```yara
rule MAL_Python_StealthAgent_AntiDebug_AntiVM_AI_Authored {
   meta:
      description = "Detects stealth_agent.py-class AI-authored Python backdoors combining anti-debug, anti-VM, sandbox evasion, process hiding, rootkit install, systemd/cron persistence, self-destruct, and polymorphic payload generation with bare-except AI-code signature. Family-generic anti-analysis feature bucket — deploy as a hunting/triage lead, not standalone attribution."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d1086ab3c06764ffd81492b4c723bda83bac19dc101c8542bc566e5888c92da3"
      family = "Matrix C2"
      malware_type = "Stealth Agent (AI-authored backdoor)"
      campaign = "UTA-2026-014"
      id = "d4482d80-a943-5693-86d2-773c22063b33"
   strings:
      $anti_debug = "anti_debug" ascii nocase
      $anti_vm    = "anti_vm" ascii nocase
      $sandbox_chk = "sandbox" ascii nocase
      $rootkit    = "rootkit" ascii nocase
      $self_dest  = "self_destruct" ascii nocase
      $polymorphic = "polymorphic" ascii nocase
      $aes_gcm    = "AES-256-GCM" ascii
      $pbkdf2     = "PBKDF2" ascii
      $handshake  = "handshake" ascii nocase
      $bare_exc   = "except:" ascii
   condition:
      filesize < 500KB and
      (
         (2 of ($anti_debug, $anti_vm, $sandbox_chk) and ($rootkit or $self_dest)) or
         ($aes_gcm and $pbkdf2 and $handshake) or
         ($polymorphic and $bare_exc)
      )
}
```

**Rovodev Operator Artifacts**

#### MAL_Markdown_Rovodev_WhatINeed_OperatorPrompt

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware), T1059.006 (Python)
**Confidence:** HIGH for this operator's specific artifact; MODERATE for class-level detection
**Rationale:** Detects the literal phrasing of one operator's natural-language prompt file to Rovodev. The value here is narrow-but-real pivot/hunting utility (re-uploads of this exact artifact, or this operator reusing phrasing elsewhere) rather than a generalizable technique — a different operator phrasing an equivalent request would not match. Retiered to Hunting per the single-artifact durability profile; the original author's own MEDIUM detection-priority framing already signaled this. Unchanged detection logic.
**False Positives:** Low but not zero — the combination of C2-debugging + credential-harvesting + Discord-integration phrasing in one file is not a legitimate developer pattern, but this rule cannot generalize past this operator's specific artifact.
**Deployment:** Filesystem scanner on suspected operator hosts, web crawler for open-directory detection (pivot/hunting use, not automated alerting).

```yara
rule MAL_Markdown_Rovodev_WhatINeed_OperatorPrompt {
   meta:
      description = "Detects whatineed.txt-class operator natural-language prompts to AI coding agents specifying offensive capability development. Pattern includes C2 debugging request, GitHub C2-leak repository reference, automatic credential harvesting ('automatic give me login'), Discord integration request, and operator user-ID disclosure. This operator's exact file captured from 87.106.143.220 open-directory."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d888a16cd6aa76f62a329906db4f241e6bc23ff5f21d61e754ade8ccab6da0d0"
      family = "Rovodev Operator Artifacts"
      malware_type = "Operator Prompt (AI-Augmented Offensive Operations)"
      campaign = "UTA-2026-014"
      id = "3e3d1343-158e-5030-b682-3a90eb4966ef"
   strings:
      $c2_debug   = "c2 doesn't connect" ascii nocase
      $c2_leak    = "C2-Leak" ascii
      $auto_login = "automatic give me login" ascii nocase
      $discord_req = "make discord live" ascii nocase
      $discord_id  = "1441591352927326259" ascii
      $cleanup_req = "clean files not needed" ascii nocase
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

#### MAL_Discord_OperatorID_Snowflake_PandoraNet

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1584.004 (Compromise Infrastructure: Server)
**Confidence:** HIGH for the artifact itself; the underlying pivot value degrades if the operator rotates the Discord account
**Rationale:** The rule's primary discriminator is the operator's literal 19-digit Discord snowflake ID (`1441591352927326259`) — a single-account artifact an operator can abandon at will (Gate 1 durability: mutex/ID-class single literal). The original author's own rationale already framed this as "a pivot/hunting rule rather than high-confidence detection," which is the Hunting-tier definition; retained here unchanged.
**False Positives:** Low — the specific 19-digit snowflake combined with `PandoraNet` or the operator's IONOS IPs reduces FP surface to near-zero for this operator's artifacts, but the rule has no value once the operator rotates identity.
**Deployment:** Filesystem scanner on suspected operator hosts, open-directory crawler, OSINT pivot hunting.

```yara
rule MAL_Discord_OperatorID_Snowflake_PandoraNet {
   meta:
      description = "Narrow detection on the literal Discord operator snowflake ID 1441591352927326259 as it appears in operator artifacts (whatineed.txt prompt, Discord bot configs, operator notes). Snowflake decodes to account creation timestamp 2025-11-22T00:49:22 UTC. Also detects PandoraNet botnet ID co-occurrence in operator-exposed files. Pivot/hunting rule, not high-confidence detection."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/"
      date = "2026-05-26"
      hash1 = "d888a16cd6aa76f62a329906db4f241e6bc23ff5f21d61e754ade8ccab6da0d0"
      family = "Rovodev Operator Artifacts"
      malware_type = "Operator Identity Artifact"
      campaign = "UTA-2026-014"
      id = "584bfc4c-dccc-5e4e-ad2c-7d0d16e6832c"
   strings:
      $discord_id  = "1441591352927326259" ascii
      $pandoranet  = "PandoraNet" ascii fullword
      $ionos_ip    = "87.106.143.220" ascii
      $backup_ip   = "87.106.54.213" ascii
      $my_user     = "my user ID is" ascii nocase
      $discord_ctx = "discord" nocase ascii
   condition:
      filesize < 5MB and
      (
         ($discord_id and $my_user) or
         ($discord_id and $pandoranet) or
         ($discord_id and ($ionos_ip or $backup_ip)) or
         ($pandoranet and ($ionos_ip or $backup_ip) and $discord_ctx)
      )
}
```

---

## Sigma Rules

### Detection Rules

**Pandora-Mirai (Naku ELF Bot Suite)**

#### ELF IoT Arch-Tagged Filename Execution on Linux Server — Naku/Pandora Mirai Family

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1190 (Exploit Public-Facing Application)
**Confidence:** HIGH
**Rationale:** IoT-targeted architecture-tag suffixes (`.arm5`, `.m68k`, `.mpsl`, `.spc`, etc.) on ELF binaries executing on a Linux SERVER host are never a legitimate pattern — arch-tagged filenames only make sense on IoT/embedded build or distribution systems. Evading requires renaming the entire 11-binary set, which raises the bar beyond a single literal. Unchanged from the original file.
**False Positives:** Cross-compilation test environments deploying IoT firmware — limit to production server hosts and IoT-adjacent network segments; IoT development workstations building multi-arch toolchains.
**Blind Spots:** A rename of the entire arch-tagged binary set evades; scoped to `product: linux` process_creation telemetry only.
**Validation:** Execute a Naku/Pandora binary with an arch-tag filename on a monitored Linux host — must match; a legitimate cross-compilation toolchain building the same arch set under different naming must NOT fire.
**Deployment:** EDR/Sysmon-equivalent process-creation telemetry on Linux server fleets and IoT-adjacent segments.

```yaml
title: ELF IoT Arch-Tagged Filename Execution on Linux Server — Naku/Pandora Mirai Family
id: c4495249-9b11-406c-b4ca-5c099eb8ca81
status: experimental
description: >-
  Detects execution of ELF binaries with IoT-targeted architecture-tag suffixes (arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc) associated with the Naku/Pandora-Mirai 11-architecture IoT botnet family (UTA-2026-014). These filenames (Naku.{arch}, pandora.{arch}, nig) are specific to the Pandora-Mirai dropper's payload distribution and execution pattern. Execution of such binaries on server-class hosts indicates active compromise and botnet payload staging.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
    - https://vms.drweb.com/virus/?i=22410691&lng=en
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.execution
    - attack.t1059.004
    - attack.initial-access
    - attack.t1190
    - attack.command-and-control
    - detection.emerging-threats
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

#### Hidden-Prefix Cron Entry Creation in /etc/cron.d — Pandora-Mirai Persistence Pattern

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.003 (Cron), T1564.001 (Hidden Files and Directories)
**Confidence:** HIGH
**Rationale:** A pure technique-level signal — dot-prefix hidden cron entries in `/etc/cron.d/` — with zero operator-specific literals (no IP, no domain, no bespoke filename). Survives complete infrastructure rotation and full binary/campaign rebrand; only a change in the persistence *technique itself* would evade. Unchanged from the original file.
**False Positives:** Extremely rare legitimate administration scripts that use dot-prefix cron files — review all instances; configuration management tools (Puppet, Chef, Ansible) deploying hidden cron entries — verify against known CM policy.
**Blind Spots:** Persistence via a non-hidden cron filename, or via a different mechanism entirely, is not covered by this rule.
**Validation:** Trigger creation of a dot-prefix file under `/etc/cron.d/` — must match; a legitimate `.placeholder` file (or your environment's known CM hidden-file convention) must NOT fire once filtered.
**Deployment:** EDR/Sysmon-equivalent file-creation telemetry on Linux hosts.

```yaml
title: Hidden-Prefix Cron Entry Creation in /etc/cron.d — Pandora-Mirai Persistence Pattern
id: 6625f3f7-4e6f-40cb-905b-039786de8561
status: experimental
description: >-
  Detects creation of dot-prefix hidden-filename cron entries in /etc/cron.d/ as used by the Pandora-Mirai (UTA-2026-014) persistent_bot.sh 5-vector persistence installer. The specific entry /etc/cron.d/.cache_update is the operator's primary cron persistence vector, scheduled to wget-pipe bot.sh from the operator's infrastructure every 5 minutes. Hidden-prefix filenames in this directory evade simple cron audits and are not a standard administration pattern.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.003
    - attack.stealth
    - attack.t1564.001
    - detection.emerging-threats
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

#### Pandora-Mirai Persistence Pattern — Multi-Mechanism Installer (Init.d, Systemd, Hidden Cron)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1037.004 (RC Scripts), T1053.003 (Cron), T1543.002 (Systemd Service)
**Confidence:** HIGH
**Rationale:** Salvaged from the original — the original rule OR'd in `/etc/rc.local` as a fourth persistence vector, but `/etc/rc.local` modification is routine for many legitimate deployment/provisioning tools and contributed no discriminating value on its own, while the rule's stated "60-second time window" was never actually implemented in the Sigma `condition` (a static OR of pairs has no timeframe). Removed the rc.local vector and the un-implemented timing claim from the description; retiered to require 2-of-3 of the three genuinely distinctive persistence artifacts (masquerade init.d name, masquerade systemd unit name, hidden cron entry).
**False Positives:** Legitimate system update scripts that use similar naming — verify service content references known-good update infrastructure; security tooling (OSSEC, Wazuh agent) that creates init.d and systemd units at install time.
**Blind Spots:** A rebuild that renames two or more of the three masquerade/hidden-persistence artifacts evades; no time-window correlation is implemented, so the three artifacts may be observed across a broad search window rather than a tight installer-execution burst.
**Validation:** Trigger `persistent_bot.sh` — at least 2 of the 3 vectors must be created and match; a host running only one of the three (e.g., just a `sysupdate` init.d script from unrelated legitimate tooling) must NOT fire.
**Deployment:** EDR/Sysmon-equivalent file-creation telemetry on Linux hosts.

```yaml
title: Pandora-Mirai Persistence Pattern — Multi-Mechanism Installer (Init.d, Systemd, Hidden Cron)
id: 311787eb-af20-4ec5-90b3-ef3cb6797771
status: experimental
description: >-
  Detects 2-of-3 co-occurrence of the distinctive Linux persistence vectors used by the Pandora-Mirai (UTA-2026-014) persistent_bot.sh installer — masquerade-named init.d service (/etc/init.d/sysupdate), masquerade systemd unit (/etc/systemd/system/system-update.service), and a hidden dot-prefix cron entry under /etc/cron.d/. Corrected from the original: the ubiquitous /etc/rc.local vector was removed (routine target for many legitimate deployment tools with no discriminating value alone), and the rule no longer claims an un-implemented 60-second time-window correlation.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1037.004
    - attack.t1053.003
    - attack.t1543.002
    - detection.emerging-threats
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
    condition: >-
        (selection_sysupdate and selection_systemd) or
        (selection_sysupdate and selection_cron_hidden) or
        (selection_systemd and selection_cron_hidden)
falsepositives:
    - Legitimate system update scripts that use similar naming — verify service content references known-good update infrastructure
    - Security tooling (OSSEC, Wazuh agent) that creates init.d and systemd units at install time
level: high
```

#### BusyBox SORA Marker Execution — Sora-Derivative Mirai-Fork Active on Host

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**Rationale:** `/bin/busybox SORA` is not a valid busybox applet invocation and has no legitimate use — it is a Sora-lineage self-identification marker used by this operator's Naku/Pandora build and by other Sora-derivative Mirai forks generally, making it a tool-family artifact rather than a single-build literal (an operator would need to recompile from a divergent source tree to remove it, which most downstream Sora-lineage adopters do not do). Unchanged from the original file.
**False Positives:** Unlikely — `/bin/busybox SORA` is not a valid busybox applet call and has no legitimate use.
**Blind Spots:** A Sora-lineage fork that has genuinely renamed this self-identification string would evade; scoped to `product: linux` process_creation telemetry.
**Validation:** Execute a Sora-derivative Mirai bot's competitor-kill/process-enumeration routine — must match; legitimate busybox invocations with any other applet argument must NOT fire.
**Deployment:** EDR/Sysmon-equivalent process-creation telemetry on Linux hosts.

```yaml
title: BusyBox SORA Marker Execution — Sora-Derivative Mirai-Fork Active on Host
id: 625a0af0-2c6e-48b5-89ea-0c7e6b191147
status: experimental
description: >-
  Detects execution of the '/bin/busybox SORA' command, which is the Sora-fork Mirai-derivative lineage signature. Decoded from XOR-0x54 region in all 11 Naku/Pandora-Mirai architectures (UTA-2026-014), replacing stock Mirai's '/bin/busybox MIRAI'. The Mirai bot calls this as part of its process enumeration and competitor-kill routine. Any process executing '/bin/busybox SORA' indicates active Sora-derivative bot execution on the host.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.execution
    - attack.t1059.004
    - attack.command-and-control
    - attack.t1095
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '/bin/busybox SORA'
    condition: selection
falsepositives:
    - Unlikely — '/bin/busybox SORA' is not a valid busybox applet call and has no legitimate use
level: high
```

### Hunting Rules

**Pandora-Mirai (Naku ELF Bot Suite)**

#### PandoraNet Botnet ID in Process Command Line — Active Pandora-Mirai Infection

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1059.004 (Unix Shell)
**Confidence:** HIGH for the artifact; retiered on durability
**Rationale:** `PandoraNet` is a single operator-chosen botnet-ID literal — durable against accidental FP today (not observed on any other host in Hunt.io's 365-day index) but trivially evaded by a rename in a future build (Gate 1: mutex/ID-class single literal → Robustness 1). The original `level: critical` was inflated for a single-selector rule with no combination logic; demoted to `medium` per level-discipline (Gate 4) and retiered to Hunting.
**False Positives:** Unlikely — `PandoraNet` is an operator-bespoke botnet identifier not used by any known legitimate software, but the rule provides no value once the operator renames the string.
**Deployment:** EDR/Sysmon-equivalent process-creation telemetry; treat a hit as a high-confidence active-infection lead requiring rapid triage rather than an auto-actioned alert.

```yaml
title: PandoraNet Botnet ID in Process Command Line — Active Pandora-Mirai Infection
id: 481ee321-8631-4a9d-b1b6-87e8a5676690
status: experimental
description: >-
  Detects the PandoraNet operator-bespoke botnet ID string in process command line arguments, indicating active execution of the Pandora-Mirai IoT botnet (UTA-2026-014). The format is 'pandora_bot PandoraNet.{arch}' where arch is one of 11 IoT CPU architectures. This string is not observed in any other host in threat intelligence indexing and indicates active bot process on the monitored system, but is a single renameable literal — treat as a hunting lead, not an auto-actioned detection.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.execution
    - attack.t1059.004
    - attack.command-and-control
    - attack.t1095
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'PandoraNet'
    condition: selection
falsepositives:
    - Unlikely — PandoraNet is an operator-bespoke botnet identifier not used by any known legitimate software
level: medium
```

#### Non-Watchdog Process Opening /dev/watchdog — Mirai-Canonical Persistence Tactic

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1014 (Rootkit), T1053.003 (Cron)
**Confidence:** HIGH
**Rationale:** A fully behavioral, zero-literal technique signal — a technique chokepoint by Gate 1's own definition (highest durability tier). Retained at Hunting rather than promoted to Detection: the honest false-positive assessment is genuinely mixed across deployment context (LOW on server hosts, MEDIUM on IoT-class devices with legitimate custom watchdog daemons the 3-name `filter_legit` list cannot exhaustively cover), and the rule's own `level: medium` reflects that — per level-discipline, a rule that honestly sits at medium belongs in Hunting. Unchanged detection logic.
**False Positives:** Embedded system watchdog management tools on IoT/embedded Linux — tune `filter_legit` for your environment; custom watchdog wrapper scripts in industrial control environments; hardware monitoring agents on servers with watchdog hardware support.
**Deployment:** EDR/Sysmon-equivalent process-creation telemetry; highest-confidence on server-class hosts where the FP scenarios above are least likely.

```yaml
title: Non-Watchdog Process Opening /dev/watchdog — Mirai-Canonical Persistence Tactic
id: 716bce61-4dcb-4479-b815-1391f5c7cd43
status: experimental
description: >-
  Detects processes other than known watchdog daemons (watchdogd, systemd-watchdog) opening /dev/watchdog or /dev/misc/watchdog. This is a canonical Mirai botnet persistence mechanism — the bot opens the watchdog device and continuously pets it (ioctl WDIOC_KEEPALIVE) to prevent IoT device auto-reboot, keeping the infection persistent across watchdog-triggered reset cycles. Observed in Naku.arm (Pandora-Mirai family, UTA-2026-014) and generic to all Mirai/Sora derivative bots. FP profile varies by deployment context (low on servers, higher on IoT/embedded hosts) — deploy as a hunting lead.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.stealth
    - attack.t1014
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.003
    - detection.emerging-threats
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

#### Naku/Pandora-Mirai Operator-Bespoke 22-Char Charset String — Family Tracking Signature

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH for the artifact; narrow applicability
**Rationale:** The 22-char charset is a single-build random-string constant (Gate 1: mutex/charset-class single literal → Robustness 1) — a future build regenerating the charset evades entirely. It is also questionable whether this internally-used obfuscation constant would ever literally surface in a process `CommandLine` (as opposed to binary content, which the companion YARA rule already covers); this Sigma rule has narrower practical hit-rate than its YARA counterpart. Demoted level from `high` to `medium` and retiered to Hunting.
**False Positives:** Unlikely — this specific character set in this order is operator-bespoke and not found in any other host in Hunt.io's 365-day index; near-zero probability of accidental match. Practical yield may be low if the string never appears in a literal command line.
**Deployment:** EDR/Sysmon-equivalent process-creation telemetry with full command-line capture; the companion YARA rule (`MAL_ELF_Naku_Pandora_Mirai_Family`) is the primary detection surface for this indicator.

```yaml
title: Naku/Pandora-Mirai Operator-Bespoke 22-Char Charset String — Family Tracking Signature
id: c9d201aa-2fbb-4e1e-b269-76cf28670998
status: experimental
description: >-
  Detects the operator-bespoke 22-character random-string charset '1gba4cdom53nhp12ei0kfj' in process command lines. This string is present in all 11 architectures of the Naku/Pandora-Mirai ELF botnet (UTA-2026-014) — both XOR-0x54 encoded in stripped production builds and in plaintext in the arm7 debug build. It is not observed in any other host in threat intelligence indexing, but is a single-build constant that a future release would regenerate, and its practical appearance in a literal process command line (versus binary content) is unconfirmed — treat as a hunting lead; the companion YARA rule is the primary detection surface.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.stealth
    - attack.t1027
    - attack.command-and-control
    - attack.t1095
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: '1gba4cdom53nhp12ei0kfj'
    condition: selection
falsepositives:
    - Unlikely — this string is operator-bespoke and not used in any known legitimate software
level: medium
```

**Matrix C2 Framework**

#### Discord Bot API Egress with Attack-Method Dispatch Payload from Server Host

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood)
**Confidence:** MODERATE
**Rationale:** `discord.com` is a stable, non-operator-controlled domain (durable — Discord will not relocate it), but this is fundamentally a "legitimate SaaS egress from an unusual host class" anomaly rule: Discord bot hosting on servers is common in legitimate developer/SaaS environments, and the original author explicitly notes MEDIUM FP risk requiring process context to disambiguate. Unchanged detection logic.
**False Positives:** Legitimate Discord bots hosted on server infrastructure — all Discord bot deployments on production servers; SaaS applications integrating Discord notifications; developer environments testing Discord integrations.
**Deployment:** Network/EDR telemetry correlating egress with process context; requires tuning `filter_known_dev` to your environment's legitimate Discord bot inventory before triage.

```yaml
title: Discord Bot API Egress with Attack-Method Dispatch Payload from Server Host
id: 7e3175bc-9a74-4c93-b358-de78d84250f4
status: experimental
description: >-
  Detects Discord API (discord.com/api/v9/) egress traffic from non-developer server hosts, indicative of the Matrix C2 DDoS-as-a-Service Discord-bot customer interface (UTA-2026-014). The Discord bot dispatches DDoS attack commands on behalf of paying customers via a JavaScript bot running on the operator's VPS. Discord bot traffic from production server hosts in non-developer environments is anomalous and warrants investigation, but Discord bot hosting is also a common legitimate pattern — treat as a hunting lead requiring process-context correlation, not a standalone alert.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.command-and-control
    - attack.impact
    - attack.t1498.001
    - attack.execution
    - attack.t1059.007
    - detection.emerging-threats
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

**Rovodev Operator Artifacts**

#### Rovodev AI Agent Sessions Directory Creation on Server Host — Potential AI-Augmented Offensive Operations

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE
**Rationale:** Detects the mere presence of a legitimate Atlassian Rovodev AI agent session on a server host, with no malicious-content qualifier in the detection logic — Rovodev is a legitimate enterprise product, and the original author explicitly notes MEDIUM FP risk (DevOps automation use is real). This is a scoping/inventory lead ("who is running Rovodev on server infrastructure"), not an alerting-grade signal. Unchanged detection logic.
**False Positives:** Legitimate DevOps teams using Rovodev on server hosts for infrastructure automation; CI/CD pipeline hosts running Rovodev for code generation tasks; developer workstations (this rule is most useful on production server hosts; tune to exclude known developer environments).
**Deployment:** EDR/Sysmon-equivalent file-creation telemetry; pair a hit with content inspection of the session artifact before escalation.

```yaml
title: Rovodev AI Agent Sessions Directory Creation on Server Host — Potential AI-Augmented Offensive Operations
id: 273f8eea-72b3-48c7-a134-cdc5a65064d7
status: experimental
description: >-
  Detects creation of Atlassian Rovodev AI coding agent session artifacts (~/.rovodev/sessions/ directory, session_context.json files exceeding 100KB) on server hosts. In the UTA-2026-014 case, the operator used Rovodev on their VPS to author a complete offensive framework (Matrix C2). Rovodev session directories on production server hosts outside of known DevOps pipelines warrant investigation, particularly when co-located with an offensive-framework-looking working directory, but Rovodev is a legitimate enterprise product — treat as a scoping/inventory lead.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.resource-development
    - attack.t1587.001
    - detection.emerging-threats
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

#### Rovodev Log File_Write Tool-Call Pattern — AI-Augmented Offensive Operations Evidence

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE
**Rationale:** Fires on the mere presence of `rovodev.log` — every Rovodev installation generates this file, malicious or benign, so the rule has essentially zero standalone discriminating power. Retained as a Hunting-tier scoping lead (inventorying every host running Rovodev is a legitimate step when hunting for AI-agent-assisted offensive activity in this investigation), consistent with the original author's already-honest `level: low`. Unchanged detection logic.
**False Positives:** All Rovodev installations generate rovodev.log — this rule fires on any host running Rovodev; tune to server hosts outside known DevOps pipelines; CI/CD pipeline hosts running Rovodev legitimately.
**Deployment:** EDR/Sysmon-equivalent file-creation telemetry; use strictly as a starting point for subsequent log-content inspection, never as a standalone alert.

```yaml
title: Rovodev Log File_Write Tool-Call Pattern — AI-Augmented Offensive Operations Evidence
id: 817e5ca2-7265-41b3-b344-bbf36afc3193
status: experimental
description: >-
  Detects creation of the Atlassian Rovodev AI coding agent runtime log (rovodev.log). In the UTA-2026-014 case, the 8.5 MB rovodev.log captured file_write calls producing attack_engine.py, master_control.py, stealth_agent.py, and the Discord bot JavaScript dispatch table. Every Rovodev installation generates this file regardless of intent — use strictly as a scoping starting point for subsequent content inspection of the log for offensive capability markers, not as a standalone alert.
references:
    - https://the-hunters-ledger.com/reports/rovodev-mirai-matrix-c2-87.106.143.220/
author: The Hunters Ledger
date: '2026-05-26'
tags:
    - attack.resource-development
    - attack.t1587.001
    - detection.emerging-threats
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

## Suricata Signatures

> **Metadata modernization note:** the original file's Suricata rules predate the `suricata-rule-formatting` skill and used a non-standard `metadata:` schema (`affected_product`/`attack_target`/`created_at`/`deployment`/`signature_severity`/`tag`) and a `"THL - "` (hyphenated) `msg` prefix. All rules below are reformatted to the canonical `metadata:author The_Hunters_Ledger, date, reference` schema and the `"THL <CampaignTag> ..."` `msg` convention. `sid` values are preserved unchanged from the original (9001002–9001014) to avoid retiring any existing feed-generator SID mapping; `rev` is bumped to `2` on every rule whose detection logic changed (destination broadened) and left at `1` where logic is unchanged. The withdrawn DNS rule (`sid:9001001`, commented out in the original file since 2026-06-19 for matching all `github.com` DNS lookups) remains withdrawn and is not reproduced here.

### Detection Rules

**Pandora-Mirai (Naku ELF Bot Suite)**

#### Pandora-Mirai Naku Binary Distribution URI Path

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH
**Rationale:** Salvaged from the original — the rule required the destination to be the operator's specific IONOS IP (`87.106.143.220`), so it would stop firing the moment the operator rotated VPS. Broadened destination to `$EXTERNAL_NET`, keeping the distinctive `/bins/Naku.` URI-path content anchor (a bespoke arch-tagged binary distribution convention, not a generic path). Survives infrastructure rotation while retaining meaningful precision.
**False Positives:** None known — `/bins/Naku.` as a URI path prefix has no plausible legitimate collision.
**Blind Spots:** A rebrand that changes the distribution path convention evades; HTTPS-channel fetches are opaque to this rule without TLS interception.
**Validation:** Replay a PCAP of a Naku binary fetch over this URI convention — must alert; ordinary HTTP traffic to unrelated paths must NOT.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Pandora-Mirai Naku Binary Distribution URI Path (IoT Botnet Payload Delivery)"; flow:established,to_server; http.uri; content:"/bins/Naku."; startswith; classtype:trojan-activity; sid:9001003; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

#### Pandora-Mirai Pandoras-Box Binary Distribution URI Path

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1587.001 (Develop Capabilities: Malware)
**Confidence:** HIGH
**Rationale:** Same salvage as the Naku URI-path rule above — broadened from a hardcoded IONOS destination to `$EXTERNAL_NET`, retaining the bespoke `/Pandoras_Box/Pandora.` URI-path content anchor.
**False Positives:** None known — `/Pandoras_Box/Pandora.` as a URI path prefix has no plausible legitimate collision.
**Blind Spots:** A rebrand that changes the distribution path convention evades; HTTPS-channel fetches are opaque to this rule without TLS interception.
**Validation:** Replay a PCAP of a Pandora binary fetch over this URI convention — must alert; ordinary HTTP traffic to unrelated paths must NOT.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Pandora-Mirai Pandoras-Box Binary Distribution URI Path (IoT Botnet Payload Delivery)"; flow:established,to_server; http.uri; content:"/Pandoras_Box/Pandora."; startswith; classtype:trojan-activity; sid:9001005; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

### Hunting Rules

**Pandora-Mirai (Naku ELF Bot Suite)**

#### Pandora-Mirai bot.sh Reseed Download URI Pattern

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1587.001 (Develop Capabilities: Malware)
**Confidence:** MODERATE
**Rationale:** Salvaged (destination broadened from the hardcoded IONOS IP to `$EXTERNAL_NET`), but `bot.sh` is a widely-reused generic dropper/reseed script filename across the broader Mirai-fork ecosystem, not bespoke to this operator — the content anchor alone carries meaningfully less discriminating power than the Naku/Pandoras_Box path rules above.
**False Positives:** Any unrelated Mirai-fork or generic IoT dropper reusing the common `bot.sh` filename convention (uncommon collision with unrelated legitimate software, but not campaign-specific).
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Pandora-Mirai bot.sh Reseed Download URI Pattern (IoT Botnet Reseed Channel)"; flow:established,to_server; http.uri; content:"/bot.sh"; endswith; classtype:trojan-activity; sid:9001004; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

#### Naku Binary Reference in HTTP URI (Bare Substring)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1587.001 (Develop Capabilities: Malware)
**Confidence:** LOW–MODERATE
**Rationale:** Salvaged (destination broadened from the hardcoded backup IONOS IP to `$EXTERNAL_NET`), but the content anchor is a bare, unqualified `"Naku."` substring with no `startswith`/`endswith` path qualifier — the weakest anchor among this campaign's Naku-related Suricata rules. Retained as a distinct Hunting entry (rather than merged with the Aruba-distribution variants below) to preserve rule-count accounting for this revision; a future revision should consider consolidating all three bare-`"Naku."` rules into one.
**False Positives:** Any unrelated URI path or query string containing the 4-character substring "Naku." (uncommon but not impossible).
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Naku Binary Reference in HTTP URI - Backup Channel Convention (Bare Substring Anchor)"; flow:established,to_server; http.uri; content:"Naku."; nocase; classtype:trojan-activity; sid:9001006; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

**Rovodev Operator Artifacts**

#### keyosbuff C2-Leak Repository Reference in HTTP URI

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1588.001 (Obtain Capabilities: Malware), T1584.004 (Compromise Infrastructure: Server)
**Confidence:** MODERATE
**Rationale:** Single-literal GitHub-handle anchor (`keyosbuff`) with an acknowledged practical detection gap — GitHub is TLS-terminated, so the URL path is normally invisible to a network sensor without TLS interception; this rule only fires on unusual non-TLS references to the handle. Narrow pivot value, not alerting-grade.
**False Positives:** Any unrelated HTTP traffic referencing the `keyosbuff` GitHub handle for a different (non-C2-Leak) reason.
**Deployment:** Network IDS/IPS at perimeter; primarily useful with TLS interception or proxy logging capability.

```suricata
alert http $HOME_NET any -> any any (msg:"THL UTA-2026-014 keyosbuff C2-Leak Repository Reference in HTTP URI (Operator OPSEC Artifact)"; flow:established,to_server; http.uri; content:"keyosbuff"; nocase; classtype:trojan-activity; sid:9001002; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

**Campaign-Level**

#### Naku Binary Fetch URI Pattern — Historical Aruba Distribution Convention

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1190 (Exploit Public-Facing Application)
**Confidence:** LOW–MODERATE
**Rationale:** Salvaged (destination broadened from the hardcoded Aruba Italy primary distribution IP to `$EXTERNAL_NET`), but shares the same bare unqualified `"Naku."` substring weakness as the backup-channel rule above; both Aruba distribution servers were confirmed offline/dark as of the underlying investigation, further limiting current operational value beyond the pattern's reuse potential if the operator revives a similar distribution convention.
**False Positives:** Any unrelated URI path or query string containing the 4-character substring "Naku." (uncommon but not impossible).
**Deployment:** Network IDS/IPS at perimeter; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Naku Binary Fetch URI Pattern - Historical Aruba Primary Distribution Convention (Bare Substring Anchor)"; flow:established,to_server; http.uri; content:"Naku."; nocase; classtype:trojan-activity; sid:9001008; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

#### Naku Binary Fetch URI Pattern — Historical Aruba Backup Distribution Convention

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1190 (Exploit Public-Facing Application)
**Confidence:** LOW–MODERATE
**Rationale:** Same salvage and weak-anchor profile as the Aruba primary rule above, against the sibling backup distribution IP (now also confirmed dark).
**False Positives:** Any unrelated URI path or query string containing the 4-character substring "Naku." (uncommon but not impossible).
**Deployment:** Network IDS/IPS at perimeter; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL UTA-2026-014 Naku Binary Fetch URI Pattern - Historical Aruba Backup Distribution Convention (Bare Substring Anchor)"; flow:established,to_server; http.uri; content:"Naku."; nocase; classtype:trojan-activity; sid:9001009; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

#### Naku-Pandora Mirai Operator-Bespoke CNC Protocol (Length-Prefixed String Option Keys)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1095 (Non-Application Layer Protocol), T1027 (Obfuscated Files or Information)
**Confidence:** MODERATE — heuristic, unvalidated against live traffic
**Rationale:** Salvaged (destination broadened from the hardcoded parasitic-CNC IP to `$EXTERNAL_NET`, keeping port 23), which meaningfully improves durability for what is otherwise a genuine protocol-structure signature (Naku's length-prefixed-string CNC option-key modification, which defeats stock Mirai-protocol IDS rules). Held at Hunting because the PCRE heuristic was never validated against live traffic — the original author explicitly flagged "deploy with threshold or alert-only before promoting to block," which is the Hunting-tier definition.
**False Positives:** Any unrelated TCP/23 traffic that incidentally matches the byte-pattern heuristic (unvalidated against live traffic — tune before alerting).
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; alert-only until validated against live traffic.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 23 (msg:"THL UTA-2026-014 Naku-Pandora Mirai Operator-Bespoke CNC Protocol - Length-Prefixed String Option Keys (Defeats Stock Mirai IDS Rules, Unvalidated Heuristic)"; flow:established,to_server; dsize:>8; content:"|00 00|"; depth:2; offset:0; pcre:"/^.{4}.[\x01-\x14][A-Za-z0-9_]/"; classtype:trojan-activity; sid:9001010; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

**Matrix C2 Framework**

#### Matrix C2 Discord Bot Attack-Method Dispatch — ovh-nuke

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood)
**Confidence:** MODERATE
**Rationale:** No hardcoded operator IP (destination is `discord.com`, a stable third-party SaaS domain), and the `ovh-nuke` method-name string is fairly bespoke — but the rule requires plaintext inspection of the HTTPS request body, which needs TLS interception in most deployments; the original author explicitly flagged this as a MODERATE-confidence, interception-dependent detection.
**False Positives:** Any legitimate Discord bot traffic that happens to reference the string "ovh-nuke" for an unrelated reason (unlikely but not zero without body-content verification).
**Deployment:** Network IDS/IPS with TLS interception or proxy logging capability; not effective against opaque HTTPS without interception.

```suricata
alert http $HOME_NET any -> any any (msg:"THL UTA-2026-014 Matrix C2 Discord Bot Attack-Method Dispatch ovh-nuke (DDoS-as-a-Service Customer Interface, Requires TLS Interception)"; flow:established,to_server; http.host; content:"discord.com"; http.request_body; content:"ovh-nuke"; nocase; classtype:trojan-activity; sid:9001011; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

#### Matrix C2 Discord Bot Attack-Method Dispatch — syn-storm/frag-storm/udp-bypass/icmp-hell

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.007 (JavaScript), T1498.001 (Direct Network Flood)
**Confidence:** MODERATE
**Rationale:** Same profile as the `ovh-nuke` rule above — durable domain anchor, bespoke method-name PCRE, but requires TLS interception to inspect the HTTPS request body in most deployments.
**False Positives:** Any legitimate Discord bot traffic that happens to reference one of these four strings for an unrelated reason (unlikely but not zero without body-content verification).
**Deployment:** Network IDS/IPS with TLS interception or proxy logging capability; not effective against opaque HTTPS without interception.

```suricata
alert http $HOME_NET any -> any any (msg:"THL UTA-2026-014 Matrix C2 Discord Bot Attack-Method Dispatch syn-storm-frag-storm (DDoS-as-a-Service Customer Interface, Requires TLS Interception)"; flow:established,to_server; http.host; content:"discord.com"; http.request_body; pcre:"/(?:syn-storm|frag-storm|udp-bypass|icmp-hell)/i"; classtype:trojan-activity; sid:9001012; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-26, reference https://the-hunters-ledger.com/hunting-detections/rovodev-mirai-matrix-c2-87.106.143.220-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (5 rules removed from this revision).** Two Sigma `network_connection` rules (outbound TCP/1337 to `87.106.143.220`, outbound TCP/23 to `165.227.175.161`) and three Suricata rules (the pure TCP/23 CNC-connection rule against `165.227.175.161`, and the two bare-TLS-connection "pivot" rules against `87.106.143.220`/`87.106.54.213` — the latter's own original commentary already conceded "actual JARM matching should be implemented via threat intel feeds") each reduced, once the hardcoded IP was mentally removed, to no surviving behavioral content. All four underlying IPs were already present with rich context in [`rovodev-mirai-matrix-c2-87.106.143.220-iocs.json`](/ioc-feeds/rovodev-mirai-matrix-c2-87.106.143.220-iocs.json) — no feed edits were required. **What would enable a rule:** a distinctive, destination-agnostic protocol or content signature for either channel (see the salvaged CNC-protocol Suricata rule above for the Naku channel, which does carry such a signature for the parasitic CNC's *command structure* — the pure-IP connection rule for the same IP was still separately routed to the feed since it added no signal beyond the address itself).

**Suricata rule redundancy — three overlapping bare-`"Naku."` substring rules.** After salvaging the destination-hardcoded Aruba and IONOS-backup rules to `$EXTERNAL_NET`, three Hunting-tier Suricata rules (sid 9001006, 9001008, 9001009) now carry functionally identical detection logic (`http.uri; content:"Naku."; nocase`) distinguished only by `msg`/`sid`. They are preserved as three separate entries in this revision to keep the rule-count accounting auditable against the original file. **What would enable consolidation:** a future revision merging these into one Hunting rule (retiring two `sid`s) once historical per-VPS attribution is no longer needed for the — now largely dark — Aruba Italy distribution servers.

**github.com/keyosbuff/C2-Leak — deleted upstream source gap.** The operator's declared upstream Mirai code source is now 404/deleted. Without access to that repository, a direct code-diff comparison between the upstream source and the operator's Naku variant cannot be performed; all operator-bespoke modifications documented here (triple XOR keys, double Huawei scanner, 22-char charset, string-length-prefixed option keys, `.anime` marker) were discovered independently via binary analysis. **What would enable closure:** a GitHub Archive scrape capturing the repo before deletion, or a second operator referencing the same repository.

**Matrix C2 Python protocol — no public reference for comparison.** The Matrix C2 JSON-over-TCP protocol has no documented reference implementation to compare against; the operator built it from scratch (AI-co-authored). Detection coverage is IP/port-level only (routed to the IOC feed per above); no deep-packet-inspection signature exists for the JSON payload itself. **What would enable a rule:** passive capture of an actual C2 session from a compromised victim host, yielding a payload-structure content anchor independent of the current C2 IP.

**Pandora 11-arch IoT evolution — no prior public documentation for the extended family.** Prior public documentation of the Pandora-Mirai family (Doctor Web, September 2023) covers only the Android-TV scope; the 11-architecture IoT extension is first public characterization here. If a second downstream operator adopts the IoT-extended codebase with different naming/charset conventions, the family-specific rules in this file will not transfer. **Current coverage:** HIGH for this specific operator's build; MODERATE for the broader Pandora-Mirai IoT-extended family class.

**Parasitic-CNC-on-legitimate-VPS OPSEC pattern — no Mirai-family literature precedent.** The operator's use of a compromised legitimate tourism VPS specifically for the Naku CNC, while reserving operator-owned infrastructure for the higher-value Matrix C2 customer service, is a documented-here split-channel OPSEC pattern with no Mirai-family literature precedent found in Tier 1–3 sources. Behavioral detection of this OPSEC strategy (versus the IP-level indicators, now in the feed) would require network telemetry correlating a CNC process with co-located legitimate web-hosting traffic on the same host — standard IDS setups do not surface this. **Current coverage:** LOW (network-level detection only via the feed; no class-level behavioral detection).

**Rovodev session JSON detection — requires Atlassian-side telemetry for non-exposed operators.** The on-disk session artifacts detected by the YARA and Sigma rules above are only visible when the operator makes an OPSEC error (exposing the session JSON via open directory). In a non-exposed deployment, the operator's use of Rovodev for offensive code authoring is invisible to standard endpoint/network tooling. **Current coverage:** LOW — endpoint artifact detection only (requires operator OPSEC failure); zero coverage of in-progress Rovodev offensive sessions that are never exposed.

**Discord operator account — vendor channel required for termination.** The Discord operator account snowflake is detected via the Hunting-tier YARA rule above (artifact exposure only). Account termination and bot takedown require direct coordination with Discord Trust & Safety; there is no standard detection-engineering workflow for this action. **Current coverage:** DETECTION present (Hunting-tier artifact match); remediation is out of scope for a detection rule.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
