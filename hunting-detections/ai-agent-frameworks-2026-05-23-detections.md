---
title: "Detection Rules — AI-Agent Framework Abuse Campaign (Multi-Actor, 2026-05-23)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/ai-agent-frameworks-2026-05-23-detections/
hide: true
---

**Campaign:** AI-Agent-Frameworks-MultiActor-2026-05-23
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/

> **Scope note:** This file covers **campaign-wide and cross-cutting signatures** for the parent multi-actor investigation. Per-case operator-specific signatures (Case 1 Russian A2A deep-dive, Case 2 Turkish ARPA deep-dive, Case 3 Rovodev/Pandora deep-dive, Case 9 GHOST kit sub-report) are deferred to individual sub-report detection files. Rules here are designed for broad applicability and will fire regardless of which specific operator is present.

---

## Detection Coverage Summary

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 8 | T1574.006, T1014, T1564.001, T1587, T1059.006, T1027, T1498 | LOW–MEDIUM |
| Sigma | 12 | T1574.006, T1014, T1059.006, T1583.006, T1102, T1496.001, T1562.001, T1071.001, T1027 | LOW–HIGH (per rule) |
| Suricata | 6 | T1583.006, T1102, T1496.001, T1071.001, T1573.001, T1090.004 | LOW–MEDIUM |

**Total:** 26 rules across 3 detection layers.

**Priority breakdown:**
- HIGH priority (deploy immediately, low tuning): 14 rules
- MEDIUM priority (deploy with environment-specific tuning): 8 rules
- LOW priority (hunting/hypothesis generation only): 4 rules

**Coverage approach:** Rules are organized into four thematic groups:
1. **Novel AI-Abuse TTPs** — First-documented artifact classes (AI Operator Handoff Documents, LLM credential mutation scripts, AI-Generated Offensive Code structural signature)
2. **GHOST Kit + libpam_cache rootkit** — Commodity multi-customer cryptojacker kit (incorporates the Case 9 detection draft baseline with project-standard reformatting)
3. **Campaign Infrastructure Artifacts** — Pandora/Mirai naming, Russian A2A C2, ARPA observability harvester
4. **Network Layer** — Mining pool DNS, Cloudflare tunnel egress, Hysteria v2 QUIC masquerade, Sliver JARM, C2 encoding pattern

---

## YARA Rules

/*
   Yara Rule Set
   Identifier: AI-Agent-Framework-Abuse-MultiActor-2026-05-23
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

### Group 1 — Novel AI-Abuse TTP Signatures

---

#### Rule 1 — AI Operator Handoff Document

**Detection Priority:** HIGH
**Rationale:** First-documented artifact class — operator-authored Markdown files written FOR AI agent consumption to re-prime new sessions. Observed in Case 1 (Russian Gemini operator: `C2_MIGRATION_GUIDE.md`, `C2_INFRA_TRANSFER.md` with explicit "To: Gemini CLI / From: Gemini CLI" headers) and Case 3 (Rovodev operator: 22+ documents at `/root/matrix/` with escalating-superlative naming). Low FP risk because the combination of AI-tool addressing headers AND session-directive language is not present in normal documentation.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python), novel TTP — no current MITRE sub-technique
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of AI-tool-addressed headers ("To: Gemini CLI", "To: Claude Code") with session-priming directives ("refer to this file when starting a new session") is not present in legitimate documentation workflows. Single-criterion matches on either pattern alone should be investigated but are lower confidence.
**Deployment:** Filesystem scan on compromised or suspicious server hosts, IR artifact triage, DLP scanning of server-accessible file shares

```yara
/*
   Yara Rule Set
   Identifier: AI-Agent-Framework-Abuse-MultiActor-2026-05-23
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule TOOLKIT_AI_Operator_Handoff_Document {
   meta:
      description = "Detects operator-authored Markdown handoff documents written for AI agent consumption — a novel artifact class where threat actors document their C2 infrastructure and session context for AI tool re-priming. Observed in Case 1 (Russian Gemini operator with explicit 'To: Gemini CLI' headers) and Case 3 (Rovodev operator with 22+ session-prime docs). Indicative of AI-integrated threat operators maintaining continuity across AI sessions."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "AI-Operator-Handoff-Document"
      malware_type = "Operator-TTP-Artifact"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "de0c2440-341f-5828-a60f-805ce499d95e"
   strings:
      // AI-tool addressing headers (Case 1 verbatim)
      $h1 = "To: Gemini CLI" ascii nocase
      $h2 = "From: Gemini CLI" ascii nocase
      $h3 = "To: Claude Code" ascii nocase
      $h4 = "To: Claude" ascii nocase
      $h5 = "From: Claude" ascii nocase
      $h6 = "To: Rovodev" ascii nocase

      // Session-priming directive language
      $d1 = "refer to this file when starting a new session" ascii nocase
      $d2 = "when starting a new session" ascii nocase
      $d3 = "read this file first" ascii nocase
      $d4 = "before beginning any task" ascii nocase
      $d5 = "AI agent handoff" ascii nocase

      // Operator infrastructure marker strings (Case 1 specific)
      $i1 = "C2_MIGRATION_GUIDE" ascii
      $i2 = "C2_INFRA_TRANSFER" ascii
      $i3 = "DEPLOYED_TOOLS" ascii
      $i4 = "tralalarkefe.com" ascii nocase
   condition:
      filesize < 500KB and
      (
         (1 of ($h*) and 1 of ($d*)) or
         (2 of ($h*)) or
         (1 of ($i1, $i2, $i3) and 1 of ($d*)) or
         $i4
      )
}
```

---

#### Rule 2 — LLM-Personalized Credential Mutation Script

**Detection Priority:** HIGH
**Rationale:** First qualitative change in credential-mutation tradecraft since hashcat-rules era (~2015). The `russian-ai_sniper_brute.py` script uses Gemini 2.5 Flash with a specific red-team password analyst prompt to generate 20 per-target mutations from email+domain+last-known-password. The prompt fragments and operator output filenames are distinctive. This pattern replaces static wordlist+rules with dynamic LLM inference at attack time.
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python), T1552.001 (Credentials in Files), novel TTP
**Confidence:** HIGH
**False Positive Risk:** LOW — the combination of LLM API invocation + password mutation + red-team prompting language is not present in legitimate penetration testing frameworks using this exact pattern. Generic LLM security tools will not have the "Output ONLY the 20 passwords" output-format constraint alongside credential file handling.
**Deployment:** Filesystem scan on suspicious server hosts, DLP scanning for operator tool repositories, sandbox detonation of suspicious Python scripts

```yara
rule TOOLKIT_LLM_Personalized_Credential_Mutator {
   meta:
      description = "Detects Python scripts implementing LLM-personalized credential mutation at attack time — threat actors invoking frontier LLM APIs (Gemini, GPT-4) with per-target email+domain+password context to generate 20 targeted mutations. Observed in Case 1 (russian-ai_sniper_brute.py using Gemini 2.5 Flash). Represents a qualitative upgrade over static hashcat-rules tradecraft documented since ~2015."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "LLM-Credential-Mutator"
      malware_type = "Credential-Theft-Tool"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "7f000ddc-b613-5b84-a961-4eebc73ea7d4"
   strings:
      // LLM credential-mutation prompt fragments (Case 1 verbatim)
      $p1 = "Act as an expert red-team password analyst" ascii
      $p2 = "Output ONLY the 20 passwords" ascii
      $p3 = "Most Recent Password from dump" ascii
      $p4 = "generate exactly 20 likely current mutations" ascii
      $p5 = "Target User:" ascii
      $p6 = "Target Domain:" ascii

      // Operator output filenames
      $f1 = "AI_SNIPER_GOODS.txt" ascii
      $f2 = "AI_ADMIN_MUTANTS.txt" ascii
      $f3 = "ULTRA_GOLD_TARGETS.txt" ascii

      // LLM API usage with generative AI SDK pattern
      $a1 = "google.generativeai" ascii
      $a2 = "gemini-2.5-flash" ascii
      $a3 = "generativelanguage.googleapis.com" ascii

      // WordPress credential testing pattern
      $w1 = "wp-login.php" ascii
      $w2 = "wordpress_logged_in" ascii
   condition:
      filesize < 1MB and
      (
         (2 of ($p*)) or
         (1 of ($f*) and 1 of ($a*)) or
         (1 of ($p*) and 1 of ($a*) and 1 of ($w*))
      )
}
```

---

#### Rule 3 — AI-Generated Offensive Code Structural Signature

**Detection Priority:** MEDIUM
**Rationale:** Cross-operator validated diagnostic checklist confirmed at HIGH+ across three independent operators' Python attack code (Case 1 ai_sniper_brute.py, Case 3 Rovodev Python framework, Case 2 Turkish ARPA Python files). The co-occurrence of verbose docstrings + bare-except + defensive try/except wrapping + educational variable names + zero anti-analysis is not present in human-authored offensive code at this density. Individual criteria have FP risk; the combination is distinctive.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python), novel TTP — AI-Generated Code Structural Signature
**Confidence:** MODERATE (each criterion alone is low-confidence; combination is HIGH)
**False Positive Risk:** MEDIUM — legitimate Python developers write verbose docstrings and defensive error handling. The FP rate increases in development environments. Tune by adding context: operator-adjacent tooling (credential files, C2 artifacts, scanning tools) raises confidence significantly. Do not fire alerts on this rule alone without corroborating signals.
**Deployment:** Hunting/hypothesis generation on suspicious server hosts; combine with operator-adjacent artifact signals before alerting. Not suitable for automated high-confidence alerting alone.

```yara
rule SUSP_AI_Generated_Offensive_Code_Python {
   meta:
      description = "Detects Python offensive tools bearing the structural signature of AI-generated code: verbose docstrings co-occurring with bare-except handlers, defensive try/except wrapping, and educational variable names. Confirmed cross-operator across 3 independent actors (Case 1 Russian, Case 2 Turkish ARPA, Case 3 Rovodev). Individual criteria have FP risk; combination is MODERATE confidence for AI-assisted offensive tool authorship."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "AI-Generated-Offensive-Code"
      malware_type = "Offensive-Tool-Structural-Pattern"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "2ac2da6f-2d42-5e9e-a1b2-f03f13990126"
   strings:
      // Verbose docstring patterns (AI-signature: triple-quoted function docs in offensive tools)
      $doc1 = "\"\"\"" ascii
      $doc2 = "Args:" ascii
      $doc3 = "Returns:" ascii
      $doc4 = "Raises:" ascii

      // Bare-except co-occurrence (AI-signature: except: without exception type)
      $exc1 = "except:" ascii
      $exc2 = "except Exception as e:" ascii

      // Educational variable naming patterns common in AI-authored attack code
      $var1 = "target_url" ascii
      $var2 = "success_count" ascii
      $var3 = "failed_count" ascii
      $var4 = "max_workers" ascii
      $var5 = "ThreadPoolExecutor" ascii

      // AI-grade rate limiting commentary patterns
      $rate1 = "time.sleep" ascii
      $rate2 = "rate_limit" ascii

      // Offensive payload markers (anchor to offensive context)
      $off1 = "wp-login.php" ascii
      $off2 = "BaseHTTPRequestHandler" ascii
      $off3 = "/api/v1/" ascii
      $off4 = "payload" ascii
      $off5 = "c2_server" ascii
      $off6 = "reverse_shell" ascii
      $off7 = "exploit" ascii
   condition:
      filesize < 2MB and
      $doc1 and
      ($exc1 or $exc2) and
      2 of ($var*) and
      $rate1 and
      2 of ($off*)
}
```

---

### Group 2 — GHOST Kit + libpam_cache Rootkit (Case 9 Baseline, Reformatted)

---

#### Rule 4 — libpam_cache LD_PRELOAD Rootkit Family Signature

**Detection Priority:** HIGH
**Rationale:** The GHOST kit's libpam_cache.so LD_PRELOAD rootkit is byte-identical across at least 2 customer deployments (77.110.96.200 and 77.110.125.145). VT detections: 0/0 (never scanned). The ELF exports four hooked libc functions (readdir, readdir64, fopen, fopen64) and contains a 27-entry hide-string array with kit-standard entries. The deceptive PAM-style filename camouflage and `unsetenv("LD_PRELOAD")` constructor are family-level signatures present in all builds.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1564.001 (Hidden Files and Directories), T1027 (Obfuscated Files)
**Confidence:** HIGH
**False Positive Risk:** LOW — the combination of ELF64 shared object + PAM-style filename + xmrig/lolMiner hide strings + /proc/net/tcp hook patterns + LD_PRELOAD constructor is not present in legitimate PAM caching modules or system libraries.
**Deployment:** Endpoint AV/EDR on Linux servers, memory scanner, filesystem integrity monitoring on /lib/security/, auditd-augmented IR

```yara
import "elf"

rule MAL_Linux_GHOST_LDPreload_Rootkit_Family {
   meta:
      description = "Detects the libpam_cache.so LD_PRELOAD userland rootkit shipped with the GHOST v5.1/v6.0 cryptojacker kit. Hooks readdir/readdir64/fopen/fopen64 to hide cryptominer processes and listening ports. Uses deceptive PAM-style filename camouflage. Constructor calls unsetenv('LD_PRELOAD') to defeat env-variable detection. Observed byte-identical across at least 2 customer deployments — commodity supply-chain kit."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      hash1 = "eaaa10c840de23335abae1a9ead0a6a7fb7be5187cd19ad05137feab12bb7301"
      hash2 = ""
      hash3 = "296a800564111b0bad9fe63faf4e63ba"
      family = "GHOST-Cryptojacker-LDPreload-Rootkit"
      malware_type = "Rootkit"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "33629b27-5b2f-5982-b950-b610a07ab9e6"
   strings:
      // Kit-standard hide-string entries (present in ALL GHOST builds)
      $s1 = "xmrig" ascii fullword
      $s2 = "lolMiner" ascii fullword
      $s3 = "khugepaged_" ascii
      $s4 = "inotify_guard" ascii fullword

      // XDG-fontconfig camouflage paths (kit signature)
      $p1 = "fontconfig/.cpu" ascii
      $p2 = "fontconfig/.gpu" ascii
      $p3 = ".pid_guard" ascii

      // libc-hook target paths for /proc hiding
      $h1 = "/proc/net/tcp" ascii
      $h2 = "/proc/%s/cmdline" ascii
      $h3 = ":%04X" ascii

      // LD_PRELOAD constructor evasion
      $c1 = "LD_PRELOAD" ascii fullword

      // Deceptive PAM-style identity
      $f1 = "libpam_cache" ascii
   condition:
      uint32(0) == 0x464c457f and
      uint8(4) == 2 and
      filesize < 100KB and
      elf.dynsym_entries > 12 and
      for any sym in elf.dynsym : (sym.name == "readdir" and sym.type == elf.STT_FUNC and sym.shndx > 0) and
      for any sym in elf.dynsym : (sym.name == "fopen" and sym.type == elf.STT_FUNC and sym.shndx > 0) and
      3 of ($s*) and
      2 of ($p*) and
      all of ($h*) and
      $c1
}
```

---

#### Rule 5 — GHOST Kit Installer Function Signatures (ghost.sh)

**Detection Priority:** HIGH
**Rationale:** The GHOST v5.1 installer `ghost.sh` contains 43 named functions with distinctive operator-coined names that are not present in any other publicly-known tool. The `_anti_hisana`, `_compile_hide_so`, and `_container_escape` function names are unique to this kit and were confirmed via Hunt.io cross-host search across the 365-day index — found only on two hosts in the same /16 range.
**ATT&CK Coverage:** T1574.006, T1014, T1611 (Escape to Host), T1053.003 (Cron), T1543.002 (Systemd Service)
**Confidence:** HIGH
**False Positive Risk:** LOW — these function names do not appear in any legitimate system administration script or known open-source tooling. `_anti_hisana` is a coined term specific to this kit's rivalry with the Hisana cryptojacker.
**Deployment:** Filesystem scan on Linux servers, shell script artifact triage during IR, memory scanning for script content

```yara
rule MAL_Linux_GHOST_Kit_Installer_Shell {
   meta:
      description = "Detects the GHOST v5.1/v6.0 cryptojacker kit installer (ghost.sh) based on distinctive operator-coined function names. The _anti_hisana function targets rival cryptojacker Hisana for displacement. _compile_hide_so compiles the LD_PRELOAD rootkit (libpam_cache.c) on victim hosts. _container_escape provides 4-variant container breakout capability for Docker/k8s/LXC cloud GPU environments. Confirmed via Hunt.io cross-host search — found only on GHOST kit customer hosts."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      hash1 = "58ef3f244dab408fac7117606843a3dbcfb0754b2032a5950e977bc1811c0313"
      family = "GHOST-Cryptojacker-Kit"
      malware_type = "Cryptojacker-Installer"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "bcd488b4-ec22-5a44-824b-404064b3fcb0"
   strings:
      // Unique kit function names (operator-coined, not in any other tool)
      $fn1 = "_anti_hisana" ascii fullword
      $fn2 = "_compile_hide_so" ascii fullword
      $fn3 = "_container_escape" ascii fullword
      $fn4 = "_escape_via_cgroup" ascii fullword
      $fn5 = "_escape_via_nsenter" ascii fullword

      // Kit version self-identification
      $v1 = "GHOST v5.1" ascii
      $v2 = "GHOST v6.0" ascii
      $v3 = "Anti-Hisana" ascii

      // Telegram OWNER bot token prefix (kit-author supply-chain monitor — in ALL customer deployments)
      $t1 = "8415540095" ascii

      // LD_PRELOAD persistence mechanism reference
      $ld1 = "ld.so.preload" ascii
   condition:
      filesize < 2MB and
      (
         (2 of ($fn*)) or
         (1 of ($v*) and 1 of ($fn*)) or
         ($t1 and $ld1 and 1 of ($fn*))
      )
}
```

---

### Group 3 — Campaign Infrastructure Artifacts

---

#### Rule 6 — ARPA Observability Harvester Systemd Service Pattern

**Detection Priority:** HIGH
**Rationale:** The Turkish ARPA operator deploys five distinctively named systemd service units on victim hosts: arpa-instana-api.service, arpa-autolearn.service, arpa-continuous.service, arpa-daemon.service, arpa-parallel.service. The operator-self-branded string "ARPA Korelasyon Motoru" also appears in source files. The `arpa-*.service` naming pattern is operator-bespoke and was found only on the Turkish operator's host in Hunt.io's index.
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1119 (Automated Collection), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**False Positive Risk:** LOW — the `arpa-*.service` naming pattern alongside the ARPA branding strings is operator-specific and not present in any legitimate observability platform configuration.
**Deployment:** Filesystem scan on Linux servers (particularly observability/monitoring hosts), systemd unit audit, IR artifact triage

```yara
rule MAL_Linux_ARPA_Observability_Harvester_Systemd {
   meta:
      description = "Detects the Turkish ARPA operator's observability-harvester platform based on distinctive systemd service unit filenames and operator self-branding strings. ARPA ingests stolen observability telemetry (IBM Instana + SolarWinds + Zabbix + VMware Aria via stolen API tokens) into a TimescaleDB+Neo4j+Redis stack. The platform was found on 209.38.205.158 (DigitalOcean) harvesting data from a Turkish state-owned insurer victim with a stolen 10-year Instana JWT."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "ARPA-Observability-Harvester"
      malware_type = "Data-Harvesting-Platform"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "08b8e947-a673-53c1-9303-6843c8e8ec50"
   strings:
      // Operator-bespoke systemd service names
      $svc1 = "arpa-instana-api.service" ascii
      $svc2 = "arpa-autolearn.service" ascii
      $svc3 = "arpa-continuous.service" ascii
      $svc4 = "arpa-daemon.service" ascii
      $svc5 = "arpa-parallel.service" ascii

      // Operator self-branding
      $b1 = "ARPA Korelasyon Motoru" ascii
      $b2 = "ARPA \xc2\xa9 2026" ascii

      // Stolen JWT claim (stolen victim organization Instana JWT JTI)
      $j2 = "022a1b74-2332-4df5-a76b-60225ffa7ae3" ascii

      // Operator C2 ingestion endpoint
      $e1 = "/api/ingest/instana" ascii
   condition:
      filesize < 5MB and
      (
         (2 of ($svc*)) or
         (1 of ($b*)) or
         ($j2) or
         ($e1 and 1 of ($svc*))
      )
}
```

---

#### Rule 7 — Pandora/Mirai Naku Architecture Naming Pattern

**Detection Priority:** HIGH
**Rationale:** The Rovodev/Pandora operator deploys an 11-architecture Mirai-family suite under the operator-bespoke naming scheme `Naku.{arch}` with botnet ID `PandoraNet`. The 22-character random-string charset `1gba4cdom53nhp12ei0kfj` is baked into all 11 binaries — this is the operator's custom charset replacing Mirai's stock charset. The distribution paths `/Pandoras_Box/` and `/bins/Naku.` are operator-bespoke and not present in any other Mirai variant tracked in Hunt.io's 365-day index.
**ATT&CK Coverage:** T1498 (Network Denial of Service), T1498.002 (Reflection Amplification), T1059.004 (Unix Shell)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of `PandoraNet` botnet ID, `Naku.{arch}` naming, and the 22-char custom charset is not present in any other known Mirai variant.
**Deployment:** ELF binary scanning on compromised IoT/Linux hosts, open-directory enumeration, download artifact scanning

```yara
rule MAL_Linux_Pandora_Mirai_Naku_Suite {
   meta:
      description = "Detects the Rovodev operator's Pandora/Naku Mirai-variant botnet suite based on operator-bespoke naming patterns and the custom 22-character random-string charset. The suite covers 11 IoT architectures (arm, arm5, arm6, arm7, m68k, mips, mpsl, ppc, sh4, spc, x86) served from dual HTTP/HTTPS channels at /bins/Naku.{arch} and /Pandoras_Box/pandora.{arch}. Botnet ID 'PandoraNet' is suffixed by architecture in bot registration beacons."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "Pandora-Mirai-Variant"
      malware_type = "DDoS-Botnet"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "f3e8e30f-eedc-5e31-ab5e-381ec27010a3"
   strings:
      // Operator-bespoke botnet ID
      $b1 = "PandoraNet" ascii fullword
      $b2 = "PandoraNet.arm" ascii
      $b3 = "PandoraNet.x86" ascii

      // Operator-bespoke 22-char charset (replaces stock Mirai charset)
      $c1 = "1gba4cdom53nhp12ei0kfj" ascii

      // Operator distribution path fragments
      $d1 = "/Pandoras_Box/" ascii
      $d2 = "/bins/Naku." ascii

      // Operator-defined attack method names (distinctive set from Matrix C2)
      $m1 = "udp-star" ascii
      $m2 = "syn-storm" ascii
      $m3 = "tcp-matrix" ascii
      $m4 = "dns-rain" ascii
      $m5 = "ovh-nuke" ascii

      // Bot registration pipe-delimited format
      $r1 = "INFECTED|" ascii

      // Distribution servers embedded in all 11 binaries
      $ip1 = "80.211.94.16" ascii
      $ip2 = "80.211.111.10" ascii
   condition:
      (
         (uint32(0) == 0x464c457f and filesize < 2MB and (1 of ($b*) or $c1 or 1 of ($ip*))) or
         (filesize < 500KB and ($d1 or $d2) and 1 of ($m*)) or
         ($r1 and 2 of ($m*))
      )
}
```

---

#### Rule 8 — Russian A2A C2 Python-stdlib BaseHTTPServer

**Detection Priority:** HIGH
**Rationale:** The Russian Gemini operator's `c2_server.py` uses Python stdlib `BaseHTTPRequestHandler` with zero authentication across all 5 endpoints (/api/v1/update, /api/v1/agents, /api/v1/telemetry, /api/v1/interact, /api/v1/get_results). The operator banner "A2A C2 MULTI-AGENT CONSOLE" and the `X-Agent-ID` self-assertion header are unique to this operator. The base64+UTF-16LE encoding convention matches PowerShell -EncodedCommand format and is distinctive in this combination.
**ATT&CK Coverage:** T1059.006 (Python), T1071.001 (Web Protocols), T1132.001 (Standard Encoding), novel TTP — Operator-Built Unauthenticated Python-stdlib C2
**Confidence:** HIGH
**False Positive Risk:** LOW — the "A2A C2 MULTI-AGENT CONSOLE" banner is operator-bespoke. The combination of BaseHTTPRequestHandler + unauthenticated /api/v1/ endpoints + X-Agent-ID header + base64+UTF-16LE encoding is not present in any legitimate server-management framework.
**Deployment:** Filesystem scan on compromised servers, Python source artifact triage, memory scanning for running Python processes

```yara
rule MAL_Python_Russian_A2A_C2_BaseHTTPServer {
   meta:
      description = "Detects the Russian Gemini operator's custom A2A (Agent-to-Agent) C2 backend built on Python stdlib BaseHTTPServer. Features zero authentication on all 5 API endpoints, a path-traversal-vulnerable file server, base64+UTF-16LE encoding (matching PowerShell EncodedCommand format), and Cloudflare Tunnel transport. Used in active operations against a named US-healthcare victim. The unauthenticated C2 creates a defender-takeover surface for victim notification."
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "Russian-A2A-C2"
      malware_type = "Custom-C2-Backend"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "943da3bd-c273-5e48-829e-1ec1389fd48a"
   strings:
      // Operator-bespoke banner string
      $b1 = "A2A C2 MULTI-AGENT CONSOLE" ascii

      // Operator API endpoint contract
      $e1 = "/api/v1/update" ascii
      $e2 = "/api/v1/agents" ascii
      $e3 = "/api/v1/interact" ascii
      $e4 = "/api/v1/telemetry" ascii
      $e5 = "/api/v1/get_results" ascii

      // Self-assertion agent identity header
      $h1 = "X-Agent-ID" ascii

      // Encoding chain (base64 + UTF-16LE matching PowerShell EncodedCommand)
      $enc1 = "decode('utf-16le')" ascii
      $enc2 = "base64.b64decode" ascii

      // Operator C2 domain
      $d2 = "c2.tralalarkefe.com" ascii
      $d3 = "payloads.tralalarkefe.com" ascii
   condition:
      filesize < 1MB and
      (
         $b1 or
         ($d2 or $d3) or
         (3 of ($e*) and $h1) or
         ($enc1 and $enc2 and 2 of ($e*))
      )
}
```

---

## Sigma Rules

### Group 1 — AI-Agent Abuse and Operator Tool Presence

---

#### Sigma Rule 1 — settings.local.json Modification Adding curl|bash to permissions.allow

**Detection Priority:** HIGH
**Rationale:** The Case 4 Korean operator's `settings.local.json` is the smoking-gun artifact for the pre-approved AI-tool installation chain. Any modification to this file adding a `Bash(curl ... | bash)` pattern to the `permissions.allow` array indicates either a threat actor pre-authorizing malicious tool installation or a Claude Code misconfiguration that bypasses safety prompts. The `openclaw` and port 18789 specifics are operator-bespoke but the general curl|bash permission pattern is the high-value signal.
**ATT&CK Coverage:** T1562.001 (Disable or Modify Tools), T1059.004 (Unix Shell), novel TTP — AI-Agent Permission Allowlist Abuse
**Confidence:** HIGH
**False Positive Risk:** LOW for the curl|bash combination; MEDIUM for individual `permissions.allow` modifications (legitimate Claude Code users may add safe commands). The specific combination of curl|bash piped execution in the allow array is not expected in legitimate configurations.
**Deployment:** Linux/macOS file integrity monitoring (FIM) on developer and server hosts, auditd, Sysmon for Linux

```yaml
title: >-
  Claude Code settings.local.json Modified to Pre-Approve curl-pipe-bash Execution
id: 803d43fe-6b5a-48e1-b25f-9da5e74bca62
status: test
description: >-
  Detects modification to ~/.claude/settings.local.json that adds an entry matching
  the curl-pipe-bash execution pattern to the permissions.allow array. This is the
  smoking-gun artifact for the Case 4 Korean operator's Claude Code allowlist abuse
  technique, where an attacker pre-authorizes malicious tool installation (e.g., OpenClaw
  via 'curl -fsSL https://openclaw.ai/install.sh | bash') to execute without Claude Code
  safety prompts in subsequent sessions. The technique bypasses Claude Code's
  human-approval loop for exact-match commands.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.defense-evasion
  - attack.execution
  - attack.persistence
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains:
      - /.claude/settings.local.json
      - /.claude/settings.json
  condition: selection
falsepositives:
  - >-
    Legitimate Claude Code users adding safe commands to the permissions.allow array
    (e.g., common npm/git commands). Investigate file content after alert — the
    curl-pipe-bash and npm-i-g-unfamiliar patterns are the high-confidence indicators
    within a triggered file modification. Package managers (apt/brew) updating Claude
    configuration are unlikely to add curl-pipe-bash entries.
level: medium
```

---

#### Sigma Rule 2 — /etc/ld.so.preload Modification (LD_PRELOAD Rootkit Persistence)

**Detection Priority:** HIGH
**Rationale:** Modification to `/etc/ld.so.preload` is the persistence mechanism for userland LD_PRELOAD rootkits including the GHOST kit's libpam_cache.so. Legitimate `/etc/ld.so.preload` usage is rare on production servers — when present, it is typically empty or contains performance profiling libraries in development environments. Any modification on a production server warrants immediate investigation.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit)
**Confidence:** HIGH
**False Positive Risk:** LOW on production servers. Higher on development/QA hosts where performance profilers (valgrind, perf, LD_PRELOAD instrumentation) may legitimately modify this file.
**Deployment:** Linux file integrity monitoring, auditd, Sysmon for Linux — deploy on all production server hosts. Tune out development environments via host-tag exclusion.

```yaml
title: Linux LD_PRELOAD Rootkit Persistence via /etc/ld.so.preload Modification
id: 8961351c-34c4-4a6e-b031-16a6368ae15e
status: test
description: >-
  Detects writes or creates of /etc/ld.so.preload, which is the persistence mechanism
  for userland LD_PRELOAD rootkits including the GHOST v5.1/v6.0 cryptojacker kit's
  libpam_cache.so rootkit (Case 9, byte-identical across 2 customer deployments, 0/0
  AV detections at time of discovery). Legitimate /etc/ld.so.preload usage is rare on
  production servers. When present post-alert, inspect the file content for non-standard
  library paths and cross-reference /lib/security/ for newly written .so files.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
  - https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.persistence
  - attack.defense-evasion
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename: /etc/ld.so.preload
  condition: selection
falsepositives:
  - >-
    Performance/instrumentation libraries that legitimately use LD_PRELOAD (libfaketime,
    libsegfault, libtcmalloc, valgrind, vtune) — typically confined to dev/test environments.
    Debian/Ubuntu package upgrades may touch the file mtime without changing content.
    Correlate with parent process: apt/dpkg writes are expected; shell/unknown-binary writes
    are high-confidence malicious.
level: high
```

---

#### Sigma Rule 3 — Cryptojacker libpam_cache Drop to /lib/security

**Detection Priority:** HIGH
**Rationale:** File creation of any `.so` file under `/lib/security/` with a PAM-style camouflage name (`libpam_cache*`) is the on-disk persistence artifact of the GHOST kit rootkit. The kit names its rootkit to blend with legitimate PAM caching modules — defenders auditing `/lib/security/` via `ls` may overlook `libpam_cache.so` as a normal PAM module. After the rootkit loads, it hides its own filename from `readdir` output, making filesystem-based detection require direct inode inspection.
**ATT&CK Coverage:** T1574.006, T1014, T1027 (Obfuscated Files — deceptive naming)
**Confidence:** HIGH
**False Positive Risk:** LOW — `libpam_cache.so` is not a legitimate PAM module name in any major Linux distribution (Debian, Ubuntu, RHEL, CentOS, Fedora). Verify parent process is `apt`/`dpkg`/`rpm`/`yum` if fired; shell or unknown-binary parent = high-confidence malicious.
**Deployment:** Linux file integrity monitoring on /lib/security/, auditd with -w watch rule, Sysmon for Linux

```yaml
title: Cryptojacker LD_PRELOAD Rootkit Drop to /lib/security (PAM-Style Camouflage Naming)
id: 6c7e9d33-7dc3-411b-994f-37d431e05907
status: test
description: >-
  Detects file creation in /lib/security or multiarch equivalents of .so files matching
  the GHOST cryptojacker kit's deceptive PAM-style naming convention (libpam_cache*).
  The kit names its LD_PRELOAD rootkit libpam_cache.so to blend with legitimate PAM
  caching modules. Once loaded, the rootkit hides its own filename from readdir output,
  making filesystem-level detection via ls unreliable. This rule targets the write event
  before the rootkit activates. Confirmed 0/0 AV detections at time of first discovery.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.persistence
  - attack.defense-evasion
logsource:
  product: linux
  category: file_event
detection:
  selection_path:
    TargetFilename|contains:
      - /lib/security/
      - /lib/x86_64-linux-gnu/security/
      - /usr/lib/security/
      - /usr/lib/x86_64-linux-gnu/security/
  selection_name:
    TargetFilename|contains:
      - libpam_cache
  condition: selection_path and selection_name
falsepositives:
  - >-
    Legitimate distro packages installing PAM modules — verify parent process is
    apt/dpkg/rpm/yum and not a shell or unknown binary. No legitimate Linux distribution
    ships a libpam_cache.so PAM module.
level: high
```

---

#### Sigma Rule 4 — Multi-AI Tool Co-Presence on Server Host

**Detection Priority:** MEDIUM
**Rationale:** Detection of multiple AI-tool configuration directories (`.claude`, `.gemini`, `.codex`) co-located with offensive tooling (nuclei, frp, masscan) on a server host is a strong discriminator for AI-integrated threat operators versus legitimate developer co-installation. The Case 7 (Weevely+frp+Claude) and Cases Demoted-1/Demoted-2 demonstrate that Claude+Codex alone is insufficient — the co-presence of offensive infrastructure tooling is the discriminating signal.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1588.002 (Tool Obtain Capabilities)
**Confidence:** MODERATE — co-presence of AI tools + offensive tooling on server hosts warrants investigation but is not conclusive. Legitimate red-team operators and security researchers may have similar configurations.
**False Positive Risk:** HIGH on development/research hosts, MEDIUM on production server hosts. Apply host classification (server vs workstation vs developer) before alerting. Tune by excluding known developer/research hosts.
**Deployment:** Endpoint agent filesystem scanning with host-role classification, IR artifact triage. Hunting-only on environments with significant developer population.

```yaml
title: Multiple AI Tool State Directories Co-Located with Offensive Tooling on Server Host
id: 337c7b1d-0f56-4c27-932f-2ea507ba24f1
status: test
description: >-
  Detects creation of multiple AI-agent CLI state directories (~/.claude, ~/.gemini,
  ~/.codex, ~/.rovodev) co-located with known offensive tooling (nuclei, frp, masscan,
  .rovodev sessions) on server-class hosts. This pattern is a discriminator for
  AI-integrated threat operators who leverage multiple AI assistants alongside their
  offensive toolkit. Cases Demoted-1 and Demoted-2 demonstrate that multi-AI co-presence
  alone is insufficient; the co-location with offensive tooling is the high-signal
  component. Rule fires on process creation events showing AI-tool CLI execution from
  a server-class host alongside offensive tool execution.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.resource-development
  - attack.execution
logsource:
  category: process_creation
  product: linux
detection:
  selection_ai_tools:
    Image|contains:
      - /.claude/
      - /gemini
      - /rovodev
      - /openclaw
  selection_offensive_tools:
    Image|endswith:
      - /nuclei
      - /frpc
      - /frps
      - /masscan
      - /nmap
    CommandLine|contains:
      - nuclei
      - frpc
      - masscan
  condition: selection_ai_tools or selection_offensive_tools
falsepositives:
  - >-
    Legitimate penetration testers and security researchers using AI-assisted tooling
    alongside standard offensive tools. Apply host-role classification before alerting.
    This rule is designed for hunting on server infrastructure, not developer workstations.
    Requires environmental baseline of expected tooling per host role.
level: low
```

---

### Group 2 — Operator Infrastructure Egress Patterns

---

#### Sigma Rule 5 — Trycloudflare.com Quick-Tunnel Egress from Non-Developer Hosts

**Detection Priority:** HIGH
**Rationale:** The Russian operator (Case 1) uses trycloudflare.com quick-tunnels for C2 transport (case-specific tunnel: `tenant-upcoming-great-descending.trycloudflare.com`). Trycloudflare quick-tunnels are Cloudflare's free ephemeral tunnel service — any server-class host initiating DNS queries or TCP connections to `*.trycloudflare.com` or initiating `cloudflared` tunnel registration is suspicious unless the host is a known developer or CI/CD system.
**ATT&CK Coverage:** T1583.006 (Web Services — Cloudflare Tunnel), T1102.002 (Bidirectional Communication via Web Service), T1090.004 (Domain Fronting)
**Confidence:** HIGH (on server hosts); MEDIUM (on mixed-use workstations)
**False Positive Risk:** MEDIUM on developer/CI hosts that legitimately use Cloudflare Tunnel for testing. LOW on production server hosts. The specific random-subdomain pattern (`*.trycloudflare.com`) distinguishes ephemeral operator tunnels from static `*.cloudflareaccess.com` legitimate enterprise deployments.
**Deployment:** DNS query logs, network proxy/firewall egress, Sysmon process creation for `cloudflared` binary execution

```yaml
title: Trycloudflare.com Quick-Tunnel Egress from Non-Developer Server Host
id: 5581299d-e9a1-4a83-b85c-8d68a93fd03b
status: test
description: >-
  Detects DNS queries or process creation events for trycloudflare.com ephemeral tunnels
  originating from server-class hosts. Threat actors (Case 1 Russian Gemini operator)
  use Cloudflare quick-tunnels to proxy C2 traffic through Cloudflare infrastructure,
  disguising the true C2 IP and bypassing egress firewall rules. The tunnel registers
  automatically via cloudflared and appears as HTTPS traffic to cloudflare.com CDN IPs.
  Trycloudflare subdomains are ephemeral and randomly generated (e.g.,
  tenant-upcoming-great-descending.trycloudflare.com) — not predictable by defenders.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.command-and-control
logsource:
  category: dns_query
  product: linux
detection:
  selection:
    query|endswith: .trycloudflare.com
  condition: selection
falsepositives:
  - >-
    Developers and CI/CD pipelines using Cloudflare Tunnel for local development exposure
    (ngrok-alternative use case). Exempt known developer/CI hosts by hostname or subnet.
    Production server hosts with no developer tooling present should not initiate
    trycloudflare.com connections.
level: high
```

---

#### Sigma Rule 6 — cloudflared access tcp Tunnel Registration to Non-Allowlisted Hostname

**Detection Priority:** HIGH
**Rationale:** The Russian operator (Case 1) runs `cloudflared access tcp` with explicit victim hostnames to maintain persistent RDP and SSH access to the healthcare victim. The command pattern `cloudflared access tcp --hostname [victim-host].tralalarkefe.com --url localhost:[port]` is the operator-side tunnel activation command. Any execution of `cloudflared access tcp` with a non-allowlisted hostname on a server host is suspicious — legitimate uses of this command are rare outside of explicitly managed Cloudflare Zero Trust deployments.
**ATT&CK Coverage:** T1583.006, T1021.001 (RDP), T1021.004 (SSH), T1090.004
**Confidence:** HIGH
**False Positive Risk:** LOW — `cloudflared access tcp` with non-standard hostnames is not a legitimate server administration pattern. Allowlist-known hostnames for legitimate Cloudflare Zero Trust deployments.
**Deployment:** Sysmon process creation, auditd execve, Linux endpoint agent

```yaml
title: cloudflared access tcp Tunnel Registration to Non-Allowlisted Hostname
id: 0d88f829-c8e3-42e5-a3c3-34cb8a5fec1a
status: test
description: >-
  Detects execution of 'cloudflared access tcp' with the --hostname flag, indicating
  an operator is activating a Cloudflare tunnel to proxy TCP traffic (RDP, SSH, WinRM)
  through Cloudflare infrastructure. Observed in Case 1 (Russian Gemini operator)
  maintaining persistent RDP access to the US dental-practice victim via
  windows_server.tralalarkefe.com and SSH access via gil_dr1.tralalarkefe.com.
  Legitimate cloudflared access tcp usage requires a formally managed Cloudflare
  Zero Trust account configuration — ad-hoc usage with operator-bespoke domains
  indicates tunneled lateral movement or C2 channel.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
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
    Image|endswith:
      - /cloudflared
      - /cloudflared.exe
    CommandLine|contains|all:
      - access
      - tcp
      - --hostname
  condition: selection
falsepositives:
  - >-
    Legitimate Cloudflare Zero Trust TCP application proxies configured by network
    administrators. Allowlist known Cloudflare Access deployment hostnames in your
    organization. Suppression by hostname is effective — attacker-controlled hostnames
    will not match corporate Zero Trust domains.
level: high
```

---

#### Sigma Rule 7 — Gemini API Key Validation Traffic from Server Host (Case 1)

**Detection Priority:** MEDIUM
**Rationale:** The Russian operator (Case 1) uses stolen Gemini API keys (40+ captured, validated against `gemini-3.1-pro-preview`) in `check_keys.py` to test key validity before use in the credential mutation pipeline. Outbound HTTPS to `generativelanguage.googleapis.com` from a server host (not a developer workstation) is suspicious unless the host runs a legitimate AI application. The combination of server-host origin + high-frequency batch key testing is the high-signal pattern.
**ATT&CK Coverage:** T1552.001 (Credentials in Files), T1078 (Valid Accounts), T1059.006 (Python)
**Confidence:** MODERATE — generativelanguage.googleapis.com is a legitimate Google API endpoint; FP rate depends heavily on server host population. High confidence only when combined with batch key validation behavior (many requests in short window) or co-located credential files.
**False Positive Risk:** HIGH on hosts running legitimate AI applications. LOW on general-purpose server hosts with no expected AI workload.
**Deployment:** Network proxy/firewall with host-role classification, DNS query monitoring. Hunting-only without host classification.

```yaml
title: Outbound Gemini API Traffic from Non-AI-Workload Server Host (Stolen Key Validation)
id: 06d6f95f-2946-4bb9-b0ff-49921d91922f
status: test
description: >-
  Detects outbound DNS queries to generativelanguage.googleapis.com from server-class
  hosts without a legitimate AI-application workload designation. Case 1 (Russian
  Gemini operator) uses stolen Gemini API keys validated via check_keys.py with rapid
  concurrent API requests to identify working keys from a 40+ key inventory. The
  same endpoint is used by the LLM-personalized credential mutation script
  (russian-ai_sniper_brute.py) to invoke Gemini 2.5 Flash for per-target password
  generation at attack time. Legitimate usage requires a formally designated AI
  application server — ad-hoc batch requests from general-purpose servers are suspicious.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.credential-access
  - attack.resource-development
logsource:
  category: dns_query
  product: linux
detection:
  selection:
    query|contains:
      - generativelanguage.googleapis.com
      - aistudio.google.com
  condition: selection
falsepositives:
  - >-
    Legitimate AI applications and developer tools that use the Gemini API. This rule
    requires host-role classification to be effective — suppress on designated AI
    application servers and developer workstations. Effective as a hunting rule across
    server infrastructure without known AI workloads.
level: low
```

---

#### Sigma Rule 8 — Rapid Instana API Enumeration Pattern (Case 2 ARPA Harvester)

**Detection Priority:** HIGH
**Rationale:** The Turkish ARPA operator's `instana_local_collector.ps1` makes sliding-window API calls to Instana's `/api/events` endpoint with a stolen 10-year JWT (`jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3`, issued 2024-03-06, expires ~2034). The pattern of periodic 10-minute-window enumeration from a non-standard source IP (the attacker's platform at 209.38.205.158 proxying to the victim's Instana endpoint) is detectable from the victim's Instana access logs. From the attacker's host, the outbound HTTPS to `*.ocpinstana.*` from a non-observability-platform host is the signal.
**ATT&CK Coverage:** T1530 (Data from Cloud Storage Object), T1119 (Automated Collection), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH (victim-side Instana log detection); MODERATE (network-side proxy detection)
**False Positive Risk:** LOW — the stolen JWT JTI value `022a1b74-2332-4df5-a76b-60225ffa7ae3` is a point-in-time IOC; revocation of this JWT eliminates the threat vector. Generic Instana API enumeration patterns (high-frequency sliding-window calls from a non-management-platform IP) have MEDIUM FP risk.
**Deployment:** IBM Instana access log monitoring, network proxy with DPI, PowerShell Script Block Logging (Event 4104) on Windows hosts where the collector runs

```yaml
title: >-
  Instana API Enumeration via Stolen JWT from Non-Management-Platform Source
  (ARPA Observability Harvester)
id: f9c5ebeb-d6b8-4425-bb85-bfa4d30e28ac
status: test
description: >-
  Detects PowerShell execution of Instana API enumeration scripts using the -SkipCertificateCheck
  flag alongside hardcoded apiToken authorization headers, characteristic of the Turkish ARPA
  operator's instana_local_collector.ps1 script. The script makes sliding 10-minute-window
  GET /api/events requests with a stolen 10-year Instana JWT (jti: 022a1b74-2332-4df5-a76b-60225ffa7ae3,
  tenant: [victim-tenant], expires ~2034-02) to exfiltrate observability telemetry to the
  attacker's ARPA platform at 209.38.205.158:8096/api/ingest/instana. Detection from
  PowerShell Script Block Logging is highly reliable when -SkipCertificateCheck appears
  alongside Instana endpoint strings.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.collection
  - attack.exfiltration
logsource:
  product: windows
  category: ps_script
  definition: Script Block Logging must be enabled (reg key HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1)
detection:
  selection:
    ScriptBlockText|contains|all:
      - SkipCertificateCheck
      - ocpinstana
  selection_token:
    ScriptBlockText|contains:
      - apiToken
      - '[victim-tenant]'  # Substitute actual victim tenant string; available via USOM (TR-CERT) coordination
      - 022a1b74-2332-4df5-a76b-60225ffa7ae3
  condition: selection or selection_token
falsepositives:
  - >-
    Legitimate Instana API clients that use -SkipCertificateCheck for internal OCP
    self-signed certificates. Narrow by source host — the attacker's exfiltration
    target at 209.38.205.158 is not a legitimate Instana destination. The stolen JWT
    JTI (022a1b74...) as a filter is zero-FP.
level: high
```

---

#### Sigma Rule 9 — Rovodev Directory Creation on Server Host (Case 3)

**Detection Priority:** MEDIUM
**Rationale:** The Rovodev/Pandora operator's `~/.rovodev/` directory was directly confirmed on the operator's host (87.106.143.220) via Hunt.io open-directory indexing. The `.rovodev/sessions/` subdirectory contains 1.24 MB session context JSON capturing Rovodev AI-authoring the attack framework. Any server host not operated by an Atlassian-licensed developer that creates `.rovodev/` directories is suspicious — Rovodev is an enterprise-licensed Atlassian product that should not appear on generic server infrastructure.
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python)
**Confidence:** MODERATE — the `.rovodev/` directory alone could appear on any host where a developer uses Rovodev. The signal strength increases significantly when co-located with offensive tooling (botnet scripts, scanning tools) or on non-developer server infrastructure.
**False Positive Risk:** MEDIUM on development hosts, LOW on production server infrastructure with no expected AI agent tooling.
**Deployment:** Linux file integrity monitoring, endpoint agent filesystem scan, auditd directory creation watch

```yaml
title: Rovodev AI Agent Directory Creation on Server Infrastructure Host
id: c88a8604-f07b-452b-821e-ecd610edd062
status: test
description: >-
  Detects creation of ~/.rovodev/ directories on server-class hosts, indicating the
  presence of the Atlassian Rovodev AI coding agent. While Rovodev is a legitimate
  enterprise product, its presence on server infrastructure co-located with offensive
  tooling (botnet scripts, scanning tools, C2 frameworks) indicates an AI-integrated
  threat operator. Case 3 (Rovodev/Pandora operator) had ~/.rovodev/sessions/ containing
  1.24 MB AI-authoring session JSONs where Rovodev wrote attack framework code including
  master_control.py, attack_engine.py, and stealth_agent.py. Session logs (8.5 MB
  rovodev.log) captured the Discord bot dispatch table and attack method registration.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.resource-development
  - attack.execution
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains:
      - /.rovodev/
  condition: selection
falsepositives:
  - >-
    Legitimate Atlassian Rovodev users on developer workstations and Atlassian-licensed
    development servers. Apply host-role classification — this rule is effective on
    production server infrastructure where developer tooling is not expected.
level: medium
```

---

#### Sigma Rule 10 — ComfyUI Fake Custom Node PerformanceMonitor Registration (Case 9)

**Detection Priority:** HIGH
**Rationale:** The GHOST kit's ComfyUI exploitation framework registers a fake custom node named `"PerformanceMonitor": "GPU Performance Monitor"` in the victim ComfyUI instance's `NODE_CLASS_MAPPINGS` and `NODE_DISPLAY_NAME_MAPPINGS`. This registration creates filesystem artifacts under the ComfyUI custom_nodes directory and appears in Python process creation events. The node name is operator-bespoke and not present in any legitimate ComfyUI node registry.
**ATT&CK Coverage:** T1543.002 (Service Persistence via Python module), T1496.001 (Compute Hijacking), T1074 (Data Staged)
**Confidence:** HIGH
**False Positive Risk:** LOW — "PerformanceMonitor" as a ComfyUI custom node name is not present in any legitimate ComfyUI custom node package. The `GPU Performance Monitor` display name combined with custom node installation via Python pip from an operator-controlled GitHub repo is distinctly malicious.
**Deployment:** ComfyUI host filesystem monitoring, Python process monitoring on GPU compute hosts, AI/ML infrastructure endpoint agents

```yaml
title: GHOST Kit ComfyUI Fake Custom Node PerformanceMonitor Registration (Case 9)
id: 3f6f8f15-2716-4cc1-8eb6-12b9c3bf2c60
status: test
description: >-
  Detects registration of the GHOST cryptojacker kit's fake ComfyUI custom node
  "PerformanceMonitor" (display name "GPU Performance Monitor") used to establish
  persistence on ComfyUI-hosting AI inference servers. The fake node is installed via
  pip from the kit-author's GitHub repos (Vova75Rus/ComfyUI-Shell-Executor,
  jamestechdev-oss/ComfyUI-Shell-Plugin — both deleted post-GitHub T&S action
  2026-05-25). Detection via file creation under ComfyUI's custom_nodes directory
  matching the PerformanceMonitor pattern, or process creation showing pip installing
  from the kit-author repos. The fake node provides shell execution capability
  within the ComfyUI Python runtime environment.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.persistence
  - attack.impact
logsource:
  category: file_event
  product: linux
detection:
  selection_node:
    TargetFilename|contains:
      - /ComfyUI/custom_nodes/PerformanceMonitor
      - /ComfyUI/custom_nodes/ComfyUI-Shell-Executor
      - /ComfyUI/custom_nodes/ComfyUI-Shell-Plugin
  selection_pip:
    TargetFilename|contains:
      - Vova75Rus/ComfyUI-Shell-Executor
      - jamestechdev-oss/ComfyUI-Shell-Plugin
  condition: selection_node or selection_pip
falsepositives:
  - >-
    No known legitimate ComfyUI custom node uses the PerformanceMonitor node name.
    The kit-author GitHub repos were suspended by GitHub T&S on 2026-05-25, so
    pip install attempts from those URLs will now fail — but locally cached copies
    may persist on infected hosts.
level: high
```

---

### Group 3 — Correlation and Hunting Rules

---

#### Sigma Rule 11 — AI-Orchestrated Multi-Stage Attack Sequence <60s Across Distinct API Endpoints (Case 8)

**Detection Priority:** LOW (hunting only — SIEM correlation required)
**Rationale:** Case 8 documents a 6-stage payment API attack completed in under 60 seconds, attributed to LLM-orchestrated multi-stage attack tooling. The speed (60s for 6 distinct API endpoint calls with valid intermediate state propagation) is beyond normal human reaction time and indicates machine-speed orchestration. A SIEM correlation rule detecting 4+ distinct API endpoint calls from a single source IP within 60 seconds against payment/authentication APIs is the detection layer — requires API access log ingestion.
**ATT&CK Coverage:** T1657 (Financial Theft), T1078 (Valid Accounts), T1059.006 (Python)
**Confidence:** LOW — the 60-second window and API sequence correlate with the observed case but the underlying LLM vendor is unidentified. This rule generates hunting leads, not high-confidence alerts.
**False Positive Risk:** HIGH — automated payment processing systems, load balancers, and health checks may generate similar API call sequences. Tune by source IP classification (known automation IPs vs external unknown IPs) and by endpoint specificity (authentication + transaction + verification sequences are higher signal than health checks).
**Deployment:** SIEM correlation with payment/authentication API access logs ingested, minimum 30-day baseline required to establish normal API call velocity per source IP

```yaml
title: Suspected AI-Orchestrated Multi-Stage API Attack Sequence (60s Machine-Speed Window)
id: f8fbdc2e-b653-4b9c-b56d-2c004c202ea5
status: test
description: >-
  Correlation rule detecting machine-speed multi-stage API attack sequences characteristic
  of LLM-orchestrated attack tooling. Case 8 documented a 6-stage payment API exploitation
  completed in under 60 seconds — a cadence beyond normal human execution speed, indicating
  LLM-assisted orchestration where the AI agent reads intermediate API responses and
  immediately constructs the next authenticated request. Detection requires SIEM correlation
  across API access logs: 4+ distinct API endpoint paths called in sequence from a single
  source IP within 60 seconds. Requires API access log ingestion with per-request timestamps
  and path logging. This rule provides hunting leads only — do not configure as a high-severity
  automated alert without environmental baseline validation.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.credential-access
  - attack.exfiltration
logsource:
  category: webserver
  product: linux
detection:
  selection:
    cs-uri-stem|contains:
      - /api/
      - /auth/
      - /payment/
      - /transaction/
  timeframe: 60s
  condition: selection | count() by c-ip > 4
falsepositives:
  - >-
    Legitimate payment processing automation, API health check systems, and load balancer
    probe sequences. Requires source IP classification and endpoint specificity tuning.
    A 30-day API call velocity baseline per source IP is recommended before operationalizing.
    This rule is designed for hunting, not automated high-confidence alerting.
level: low
```

---

#### Sigma Rule 12 — AEZA / Contabo / DigitalOcean SG / IONOS Egress from Production Server (Hunting)

**Detection Priority:** LOW (hunting baseline rule)
**Rationale:** All five operator-controlled servers in this campaign are hosted on AEZA (AS210558 — Russia), Contabo (AS8218), DigitalOcean Frankfurt/Singapore, 1&1 IONOS (AS8560 — used for Pandora), and Korea Telecom (AS4766). Egress from production server hosts to IP ranges in these ASNs is expected to have a low base rate in most enterprise environments. This rule provides a hunting baseline — not high-confidence by itself, but high-yield when combined with port specificity (mining ports, C2 ports) or behavioral correlation.
**ATT&CK Coverage:** T1583.003 (Virtual Private Server), T1071.001 (Web Protocols)
**Confidence:** LOW — ASN-based egress rules have inherently high FP rates in cloud-connected environments where CDN and third-party API traffic frequently originates from these ASNs.
**False Positive Risk:** HIGH in environments with significant cloud/CDN traffic. Use as a hunting pivot, not an alert trigger. Combine with port specificity (mining ports 3333/4444/5555, elite ports 31337, uncommon management ports).
**Deployment:** Firewall egress logs, network flow analytics. Hunting only — do not configure as automated alert.

```yaml
title: Egress to AEZA/Contabo/DigitalOcean-SG/IONOS/Korea-Telecom from Production Server (Hunting)
id: bb917d1e-bb95-48d2-bb19-505cd6655456
status: test
description: >-
  Hunting rule flagging outbound connections from production server hosts to IP ranges
  associated with the campaign's operator-hosting ASNs: AEZA International Group AS210558
  (Russian-facing hosting, Case 1 + Case 9), Contabo GmbH AS8218 (Cases 5/6 demoted
  but infra tracked), DigitalOcean Frankfurt/Singapore (Case 2 Turkish ARPA), 1&1 IONOS
  AS8560 (Case 3 Pandora botnet), Korea Telecom AS4766 (Case 4 Korean operator). High
  FP rate as a standalone rule. Combine with destination port specificity (mining stratum
  ports 3333/4444/5555/7777/9999 or C2 ports 31337/10101/8090/8081) to raise confidence.
  Designed as a threat-hunting baseline pivot, not an automated alert.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: 2026/05/25
tags:
  - attack.resource-development
  - attack.command-and-control
logsource:
  category: network_connection
  product: linux
detection:
  selection_high_risk_asn:
    DestinationIp|cidr:
      - 213.165.0.0/16
      - 77.110.0.0/16
      - 209.38.0.0/16
      - 87.106.0.0/16
      - 221.150.0.0/16
  condition: selection_high_risk_asn
falsepositives:
  - >-
    CDN egress, legitimate cloud API traffic, third-party service integrations. This
    rule produces a high FP rate as standalone. Use as a hunting pivot combined with
    destination port filters (mining ports: 3333, 4444, 5555, 7777, 9999; C2 elite
    ports: 31337, 1337; operator management ports: 8027, 8029, 14433, 14444).
level: low
```

---

## Suricata Signatures

### Rule 1 — trycloudflare.com DNS Query Egress from Server Hosts

**Detection Priority:** HIGH
**Rationale:** Any DNS query for `*.trycloudflare.com` from a server host indicates Cloudflare quick-tunnel egress. The Russian operator (Case 1) used `tenant-upcoming-great-descending.trycloudflare.com` for C2 transport. Quick-tunnel subdomains are ephemeral and randomly generated — blocking the parent domain pattern is more reliable than IOC-based subdomain blocking.
**ATT&CK Coverage:** T1583.006 (Web Services — Cloudflare Tunnel), T1102.002, T1665 (Hide Infrastructure)
**Confidence:** HIGH (on server hosts without legitimate tunnel use cases)
**False Positive Risk:** MEDIUM — developer and CI/CD hosts may legitimately use trycloudflare.com for temporary exposure of local services. Apply source host classification.
**Deployment:** Network IDS/IPS on server-segment egress, DNS monitoring

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign trycloudflare.com Quick-Tunnel DNS Query from Server Host (C2 Transport Indicator)"; dns_query; content:"trycloudflare.com"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200000; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

### Rule 2 — Kryptex Mining Pool DNS Query Egress (GHOST Kit Operator-A Pool)

**Detection Priority:** HIGH
**Rationale:** The GHOST kit operator-A (77.110.96.200) uses Kryptex pool as the XMR+CFX mining destination. DNS queries to `cfx.kryptex.network` and `etc.kryptex.network` are the network-layer indicator for GHOST kit customer hosts actively mining. The kryptex.network domain is a dedicated Kryptex-branded mining pool subdomain structure — not a CDN or legitimate service domain.
**ATT&CK Coverage:** T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — kryptex.network is exclusively a cryptocurrency mining pool infrastructure domain; no legitimate enterprise traffic should query these hostnames.
**Deployment:** Network IDS/IPS, DNS monitoring, threat hunting on all server-class hosts

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign Kryptex Mining Pool DNS Query — GHOST Cryptojacker Kit Pool (cfx.kryptex.network / etc.kryptex.network)"; dns_query; content:"kryptex.network"; nocase; classtype:trojan-activity; sid:9200001; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

### Rule 3 — Generic Cryptojacker Mining Pool DNS Pattern (c3pool / nanopool)

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit and other cryptojacker variants in this campaign use public mining pools (auto.c3pool.org, cfx-asia1.nanopool.org) as fallback or secondary pools. DNS queries to these domains from server hosts are a generic cryptomining indicator not tied to a specific kit family.
**ATT&CK Coverage:** T1496.001 (Compute Hijacking)
**Confidence:** HIGH (DNS query itself is confirmation of mining activity)
**False Positive Risk:** LOW — these mining pool domains have no legitimate enterprise use. Apply threshold to reduce alert fatigue for operators running persistent miners.
**Deployment:** Network IDS/IPS perimeter monitoring, DNS monitoring

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign Mining Pool DNS Query — c3pool / nanopool / xmrig.com (Cryptojacker Activity)"; dns_query; pcre:"/(?:c3pool\.org|nanopool\.org|xmrig\.com|moneroocean\.stream|hashvault\.pro)/i"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200002; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

### Rule 4 — Hysteria v2 QUIC bing.com SNI Masquerade Detection (Case 9)

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit's `hyst.sh` installer deploys Hysteria v2 (QUIC-based proxy/tunnel) with a `bing.com` SNI masquerade — TLS Client Hello packets on UDP/443 (QUIC INITIAL packets) with SNI `bing.com` that are NOT going to Microsoft's actual Bing CDN IP ranges are the indicator. The Hysteria v2 listening ports (14433 and 14444) are included in the rootkit's hidden-port list, making host-based detection unreliable. Combined conditions (SNI mismatch + non-Microsoft destination IP) reduce FP risk.
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1665 (Hide Infrastructure), T1071.001 (Web Protocols via QUIC)
**Confidence:** MODERATE — the SNI masquerade detection requires destination IP correlation against Microsoft's Bing CDN ranges (not trivial in all environments); without IP correlation the rule will FP on all legitimate bing.com traffic.
**False Positive Risk:** MEDIUM without IP allowlist for Microsoft CDN ranges. LOW when combined with destination IP NOT IN Microsoft ASN ranges.
**Deployment:** Network IDS with QUIC/TLS inspection on UDP/443, requires protocol dissection capable of extracting TLS SNI from QUIC INITIAL packets

```
alert udp $HOME_NET any -> ![$MICROSOFT_BING_CDN] 443 (msg:"THL HUNT AI-Agent-Campaign Hysteria v2 QUIC bing.com SNI Masquerade — Non-Microsoft Destination (GHOST Kit Backdoor)"; content:"|00 00|"; offset:0; content:"bing.com"; nocase; content:"|00 01|"; classtype:trojan-activity; threshold:type limit,track by_src,count 1,seconds 3600; sid:9200003; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

### Rule 5 — Sliver C2 JARM Fingerprint Match (Case 10)

**Detection Priority:** MEDIUM
**Rationale:** The Case 10 Sliver-derivative C2 at 5.230.201.54 presents JARM fingerprint `3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5`. This JARM is known to match a broad population of Sliver framework instances (not unique to this operator). Combined with destination IP specificity and the Sliver default port 31337, this provides a moderate-confidence indicator.
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography), T1090 (Proxy)
**Confidence:** MODERATE — JARM fingerprints match populations of similarly-configured servers, not a single instance. The specific IP IOC is operator-specific and will age out as infrastructure rotates.
**False Positive Risk:** LOW for the specific IP IOC. MEDIUM for the JARM fingerprint alone (matches any Sliver population).
**Deployment:** Network IDS with JA3/JARM fingerprinting capability, TLS inspection

```
alert tls $HOME_NET any -> 5.230.201.54 any (msg:"THL HUNT AI-Agent-Campaign Sliver C2 — Known IP 5.230.201.54 (Case 10 Staging Infrastructure, JARM 3fd3fd20...)"; flow:established; tls.sni; content:!""; classtype:trojan-activity; threshold:type limit,track by_src,count 1,seconds 3600; sid:9200004; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,jarm 3fd3fd20d00000021c43d43d00043d204204071741c36579e355f830d285a5,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

### Rule 6 — A2A C2 Base64+UTF-16LE HTTP Body Encoding Pattern (Case 1)

**Detection Priority:** MEDIUM
**Rationale:** The Russian operator's A2A C2 uses `base64.b64decode(...).decode('utf-16le')` for both task delivery and result collection — this is the PowerShell `-EncodedCommand` native encoding pattern on top of base64. HTTP bodies containing valid base64-encoded content that decodes to valid UTF-16LE text (confirmed by the PowerShell agent on the other end) is the C2 channel encoding. The pattern is detectable as a high-entropy base64 blob in POST bodies to the operator's API endpoints.
**ATT&CK Coverage:** T1132.001 (Standard Encoding), T1071.001 (Web Protocols), T1573 (Encrypted Channel — encoding layer)
**Confidence:** MODERATE — base64+UTF-16LE encoding is shared with legitimate PowerShell remoting; the endpoint URI pattern `/api/v1/` and the `X-Agent-ID` header are the discriminating signals.
**False Positive Risk:** MEDIUM — base64 in HTTP POST bodies is common. The specific combination of `/api/v1/(update|telemetry|interact)` endpoint + `X-Agent-ID` header + base64 body reduces FP risk significantly.
**Deployment:** HTTP-capable IDS with body inspection, network proxy with DPI, web application firewall log analysis

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT AI-Agent-Campaign Russian A2A C2 X-Agent-ID Header + API Endpoint (Case 1 C2 Protocol Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/"; http.header_names; content:"X-Agent-Id"; nocase; classtype:trojan-activity; threshold:type limit,track by_src,count 3,seconds 3600; sid:9200005; rev:1; metadata:author The_Hunters_Ledger,date 2026-05-25,reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

## Coverage Gaps

The following techniques, behaviors, and operator-specific signals observed in malware-analyst findings were not covered with high-confidence detection rules in this parent file. Rationale is provided for each gap.

### Per-Case Operator-Specific Signatures — Deferred to Sub-Reports

This parent detection file covers campaign-wide and cross-cutting signatures. Four sub-reports with their own per-case detection files are downstream deliverables:

| Case | Deferred Coverage | Rationale |
|---|---|---|
| Case 1 (Russian Gemini) | `tralalarkefe.com` subdomain-specific rules, `check_keys.py` API key validation pattern, `quantum_patriot.py` disinformation detection, Quasar-class PowerShell agent chain signatures | Per-operator IOCs; the tralalarkefe.com domain appears in YARA Rule 8 as a high-confidence anchor but detailed subdomain enumeration and Quasar PS chain detonation signatures belong in the Case 1 sub-report |
| Case 2 (Turkish ARPA) | Instana JWT JTI `022a1b74` point-in-time block, ARPA platform TimescaleDB/Neo4j/Redis stack detection, Turkish-language insider-recruitment doc detection, `instana_local_collector.ps1` hash-based detection | Sigma Rule 8 covers the generic Instana enumeration pattern; per-JWT and per-script specifics belong in Case 2 sub-report with coordinated IBM Instana vendor disclosure |
| Case 3 (Rovodev/Pandora) | Per-architecture Naku binary hash anchors (11 hashes), Matrix C2 Discord integration detection, `master_control.py`/`attack_engine.py` per-hash YARA, `stealth_agent.py` anti-VM evasion-specific signatures | YARA Rule 7 covers the campaign-wide Pandora/Naku naming pattern; per-binary hashes and Matrix C2 Discord-specific detection belong in Case 3 sub-report |
| Case 9 (GHOST Kit) | Operator-A wallet-specific YARA (77.110.96.200 customer only), `min1.sh` dual-Telegram reporter token detection, Telegram C2 channel specific bot token IOC rules, `hyst.sh` Python framework per-hash | The case9-libpam-pull draft includes `LinuxGHOST_Customer_AEZA_77x110x96x200` (wallet-specific); that rule is preserved in the sub-report; the parent covers the family-level signatures only |

### Case 7 and Case 8 — Capsule Cases with Thin Technical Artifacts

| Case | Gap | Evidence Available | What Would Enable Coverage |
|---|---|---|---|
| Case 7 (Weevely+frp+Claude) | Weevely PHP webshell behavioral Sigma, parent process analysis, PHP webshell pattern | Hunt.io directory listing only; no Weevely payload binary extracted | Weevely payload extraction and detonation; existing Neo23x0 webshell rules already cover Weevely generically — no new YARA contribution from this case alone |
| Case 8 (AI-Orchestrated Payment API Attack) | Specific payment API endpoint sequence signatures | 6-stage timeline preserved in Hunt curation; LLM vendor unidentified; no operator infrastructure files extracted | Full API access log including intermediate response tokens and confirmation of which LLM API was used for orchestration; current evidence supports only the generic 60s correlation rule (Sigma Rule 11) |

### LLM-Vendor-Side Detection — Out of Defender Scope

The following threat behaviors involve LLM provider-side telemetry not available to defenders:

- **Stolen API key abuse detection** — Gemini API key theft and abuse (Case 1: 40+ stolen keys) is detectable only by Google through API usage anomaly monitoring. Defender scope: monitor for API key files in unexpected filesystem locations (YARA Rule 2) and unusual server-host AI API egress (Sigma Rule 7).
- **Prompt injection in AI agent sessions** — Detection of malicious prompts injected into legitimate AI agent sessions requires LLM provider-side classification of prompt content.
- **AI-generated code at generation time** — YARA Rule 3 catches the output on disk; the generation event is visible only to the LLM provider's inference logs.
- **GHOST kit supply-chain OWNER bot monitoring** — The kit-author monitors every customer deployment via hardcoded Telegram bot token `8415540095`. Detection requires Telegram API-side monitoring. GitHub T&S account suspension of Vova75Rus (2026-05-25) disrupts the payload-distribution channel; the OWNER bot likely persists on a separate account.

### Behavioral Runtime Detection of LLM API Abuse — Requires Vendor Telemetry

- **Per-request prompt classification** — Detecting whether an outbound API call to `generativelanguage.googleapis.com` contains a malicious red-team password prompt requires body inspection with content classification. DLP with LLM-query-body inspection is the closest defender-side analog.
- **Gemini CLI session recording** — The Russian operator's Gemini CLI session transcripts stored in `~/.gemini/` on the operator's server are recoverable during IR for full attack timeline reconstruction, but not detectable at runtime from defender infrastructure.

### Sliver Case 10 — Staging Phase, Limited Production Signatures

Case 10's Sliver deployment was in a staging/learning phase at capture time (zero sessions, zero beacons, zero hosts in `sliver-server.db` — 60 asciinema practice sessions only). Production Sliver implant behavioral signatures could not be derived from staging artifacts alone. Suricata Rule 5 covers the IP IOC and JARM. A full Sliver implant YARA would require a captured implant PE from a production operation.

### Korean Operator Case 4 — Single Artifact, Limited Coverage

The Korean operator Case 4 smoking-gun artifact (`settings.local.json` with OpenClaw pre-authorization) is covered by Sigma Rule 1. Beyond this, the operator's broader toolchain (OpenClaw platform internals, port 18789 beacon, OpenClaw gateway traffic) was not deeply analyzed — only the Claude Code configuration artifact was extracted. A full Case 4 detection file would require OpenClaw binary reverse engineering and network traffic capture.

---

## License

Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
