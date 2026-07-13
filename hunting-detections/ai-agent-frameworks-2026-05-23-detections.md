---
title: "Detection Rules — AI-Agent Framework Abuse Campaign (Multi-Actor, 2026-05-23)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/ai-agent-frameworks-2026-05-23-detections/
thumbnail: /assets/images/cards/ai-agent-frameworks-2026-05-23.png
hide: true
---

**Campaign:** AI-Agent-Frameworks-MultiActor-2026-05-23
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/

---

## Detection Coverage Summary

> **Scope note:** This file covers **campaign-wide and cross-cutting signatures** for the parent multi-actor investigation. Per-case operator-specific signatures (Case 1 Russian A2A deep-dive, Case 2 Turkish ARPA deep-dive, Case 3 Rovodev/Pandora deep-dive, Case 9 GHOST kit sub-report) are deferred to individual sub-report detection files. Rules here are designed for broad applicability and fire regardless of which specific operator is present.

This campaign spans 8 active operator cases plus 5 novel AI-abuse TTPs first documented here. Coverage below is retiered from the original draft: every rule was re-scored for durability (does it survive infrastructure rotation and renaming?), precision (documented false-positive profile), and level discipline, per the project's Detection/Hunting split.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 7 | 1 | T1574.006, T1014, T1587, T1059.006, T1543.002, T1498, T1071.001 | 0 |
| Sigma | 6 | 8 | T1574.006, T1090.004, T1587, T1685, T1496.001, T1119, T1657 | 0 |
| Suricata | 1 | 7 | T1090.004, T1496.001, T1071.001, T1665 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The GHOST kit's `libpam_cache.so` LD_PRELOAD rootkit — ELF structural validation (dynsym hook enumeration for `readdir`/`fopen`) combined with kit-standard hide-strings and camouflage paths; byte-identical across 2 customer deployments, 0/0 AV at discovery (YARA Detection).
- The Russian operator's A2A C2 protocol — the `X-Agent-Id` custom header paired with the `/api/v1/` URI prefix in the same HTTP request; an operator-bespoke combination not seen in legitimate server-management frameworks (Suricata Detection).

**Atomics routed to the IOC feed:** the Case 10 Sliver-derivative C2 IP (`5.230.201.54`) and its JARM fingerprint had no additional network discriminator beyond the bare IP match — both were already captured in [`ai-agent-frameworks-2026-05-23-iocs.json`](/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json); the standalone Suricata signature has been retired in favor of the feed entry.

---

## Multi-Family Organization

This campaign spans 8 operator cases rather than distinct malware families, so rules are grouped by **theme/case** (bold labels) inside each tier, mirroring the original draft's thematic grouping: **Novel AI-Abuse TTPs** (cross-case), **GHOST Kit** (Case 9), **Campaign Infrastructure Artifacts** (Cases 1–3), and per-case network/hunting groupings. A rule covering behavior common to multiple cases carries a **Campaign-Level** label.

---

## YARA Rules

### Detection Rules

**Novel AI-Abuse TTPs**

#### AI Operator Handoff Document

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python) — novel TTP, no dedicated MITRE sub-technique
**Confidence:** HIGH
**Rationale:** First-documented artifact class — operator-authored Markdown files written FOR AI agent consumption to re-prime new sessions (Case 1 Russian Gemini operator: `C2_MIGRATION_GUIDE.md`; Case 3 Rovodev operator: 22+ documents at `/root/matrix/`). *Fix applied during retiering:* the original condition let the bare domain string `tralalarkefe.com` ($i4) trigger the rule alone, an atomic-only path; it now requires the domain to co-occur with an AI-addressing header, session-priming directive, or infrastructure marker — the domain itself is already in the IOC feed.
**False Positives:** None known — the combination of AI-tool-addressed headers ("To: Gemini CLI", "To: Claude Code") with session-priming directives is not present in legitimate documentation workflows.
**Blind Spots:** An operator who stops using this exact heading/directive convention evades; single-criterion matches (header OR directive alone) are lower confidence and not covered here.
**Validation:** Scan a captured operator handoff document (e.g. `C2_MIGRATION_GUIDE.md`) — must match; a legitimate project README or runbook must NOT fire.
**Deployment:** Filesystem scan on compromised or suspicious server hosts, IR artifact triage, DLP scanning of server-accessible file shares.

```yara
/*
   Yara Rule Set
   Identifier: AI-Agent-Framework-Abuse-MultiActor-2026-05-23
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule TOOLKIT_AI_Operator_Handoff_Document {
   meta:
      description = "Detects operator-authored Markdown handoff documents written for AI agent consumption — a novel artifact class where threat actors document their C2 infrastructure and session context for AI tool re-priming. Observed in Case 1 (Russian Gemini operator with explicit 'To: Gemini CLI' headers) and Case 3 (Rovodev operator with 22+ session-prime docs)."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "AI-Operator-Handoff-Document"
      malware_type = "Operator-TTP-Artifact"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "de0c2440-341f-5828-a60f-805ce499d95e"
   strings:
      $h1 = "To: Gemini CLI" ascii nocase
      $h2 = "From: Gemini CLI" ascii nocase
      $h3 = "To: Claude Code" ascii nocase
      $h4 = "To: Claude" ascii nocase
      $h5 = "From: Claude" ascii nocase
      $h6 = "To: Rovodev" ascii nocase
      $d1 = "refer to this file when starting a new session" ascii nocase
      $d2 = "when starting a new session" ascii nocase
      $d3 = "read this file first" ascii nocase
      $d4 = "before beginning any task" ascii nocase
      $d5 = "AI agent handoff" ascii nocase
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
         ($i4 and (1 of ($h*) or 1 of ($d*) or 1 of ($i1, $i2, $i3)))
      )
}
```

#### LLM-Personalized Credential Mutation Script

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python), T1552.001 (Credentials in Files) — novel TTP
**Confidence:** HIGH
**Rationale:** First qualitative change in credential-mutation tradecraft since the hashcat-rules era (~2015). `russian-ai_sniper_brute.py` invokes Gemini 2.5 Flash with a red-team password analyst prompt to generate 20 per-target mutations from email+domain+last-known-password — the prompt fragments and operator output filenames are distinctive and require no single renameable literal alone.
**False Positives:** None known — the combination of LLM API invocation, password-mutation prompt language, and the "Output ONLY the 20 passwords" output-format constraint is not present in legitimate penetration-testing frameworks.
**Blind Spots:** A rebuild using different prompt wording or a different LLM SDK evades; the rule targets on-disk script artifacts, not in-memory-only execution.
**Validation:** Scan the captured `russian-ai_sniper_brute.py`-class script — must match; a benign password-policy or generic LLM-integration script must NOT fire.
**Deployment:** Filesystem scan on suspicious server hosts, DLP scanning for operator tool repositories, sandbox detonation of suspicious Python scripts.

```yara
rule TOOLKIT_LLM_Personalized_Credential_Mutator {
   meta:
      description = "Detects Python scripts implementing LLM-personalized credential mutation at attack time — threat actors invoking frontier LLM APIs (Gemini, GPT-4) with per-target email+domain+password context to generate 20 targeted mutations. Observed in Case 1 (russian-ai_sniper_brute.py using Gemini 2.5 Flash)."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "LLM-Credential-Mutator"
      malware_type = "Credential-Theft-Tool"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "7f000ddc-b613-5b84-a961-4eebc73ea7d4"
   strings:
      $p1 = "Act as an expert red-team password analyst" ascii
      $p2 = "Output ONLY the 20 passwords" ascii
      $p3 = "Most Recent Password from dump" ascii
      $p4 = "generate exactly 20 likely current mutations" ascii
      $p5 = "Target User:" ascii
      $p6 = "Target Domain:" ascii
      $f1 = "AI_SNIPER_GOODS.txt" ascii
      $f2 = "AI_ADMIN_MUTANTS.txt" ascii
      $f3 = "ULTRA_GOLD_TARGETS.txt" ascii
      $a1 = "google.generativeai" ascii
      $a2 = "gemini-2.5-flash" ascii
      $a3 = "generativelanguage.googleapis.com" ascii
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

**GHOST Kit + libpam_cache Rootkit (Case 9)**

#### libpam_cache LD_PRELOAD Rootkit Family Signature

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1564.001 (Hidden Files and Directories), T1027 (Obfuscated Files)
**Confidence:** HIGH
**Rationale:** Byte-identical across at least 2 customer deployments (77.110.96.200, 77.110.125.145); VT 0/0 at discovery. The rule requires ELF64 structural validation (dynsym enumeration confirming `readdir`/`fopen` are hooked) AND multiple kit-standard string buckets AND the LD_PRELOAD constructor AND the PAM-style camouflage name — no single element carries the rule alone.
**False Positives:** None known — the combination of ELF64 shared object + PAM-style filename + xmrig/lolMiner hide strings + `/proc/net/tcp` hook patterns + LD_PRELOAD constructor is not present in legitimate PAM caching modules or system libraries.
**Blind Spots:** A full rebuild hooking different libc functions or dropping the PAM-style name would evade; the rule targets the on-disk `.so`, not a memory-only injection.
**Validation:** Scan `libpam_cache.so` (hash below) — must match; a legitimate PAM module (e.g. `pam_unix.so`) must NOT fire.
**Deployment:** Endpoint AV/EDR on Linux servers, memory scanner, filesystem integrity monitoring on `/lib/security/`, auditd-augmented IR.

```yara
import "elf"

rule MAL_Linux_GHOST_LDPreload_Rootkit_Family {
   meta:
      description = "Detects the libpam_cache.so LD_PRELOAD userland rootkit shipped with the GHOST v5.1/v6.0 cryptojacker kit. Hooks readdir/readdir64/fopen/fopen64 to hide cryptominer processes and listening ports. Uses deceptive PAM-style filename camouflage. Constructor calls unsetenv('LD_PRELOAD') to defeat env-variable detection. Observed byte-identical across at least 2 customer deployments."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      hash1 = "eaaa10c840de23335abae1a9ead0a6a7fb7be5187cd19ad05137feab12bb7301"
      hash3 = "296a800564111b0bad9fe63faf4e63ba"
      family = "GHOST-Cryptojacker-LDPreload-Rootkit"
      malware_type = "Rootkit"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "33629b27-5b2f-5982-b950-b610a07ab9e6"
   strings:
      $s1 = "xmrig" ascii fullword
      $s2 = "lolMiner" ascii fullword
      $s3 = "khugepaged_" ascii
      $s4 = "inotify_guard" ascii fullword
      $p1 = "fontconfig/.cpu" ascii
      $p2 = "fontconfig/.gpu" ascii
      $p3 = ".pid_guard" ascii
      $h1 = "/proc/net/tcp" ascii
      $h2 = "/proc/%s/cmdline" ascii
      $h3 = ":%04X" ascii
      $c1 = "LD_PRELOAD" ascii fullword
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
      $c1 and
      $f1
}
```

#### GHOST Kit Installer Function Signatures (ghost.sh)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1611 (Escape to Host), T1053.003 (Cron), T1543.002 (Systemd Service)
**Confidence:** HIGH
**Rationale:** `ghost.sh` contains 43 named functions with distinctive operator-coined names not present in any other publicly-known tool; `_anti_hisana`, `_compile_hide_so`, and `_container_escape` were confirmed via cross-host search to appear only on two hosts in the same /16 range.
**False Positives:** None known — these function names do not appear in any legitimate system administration script or known open-source tooling.
**Blind Spots:** A rebrand renaming the kit's function-naming convention evades; targets the on-disk installer script only.
**Validation:** Scan `ghost.sh` (hash below) — must match; unrelated shell installers must NOT fire.
**Deployment:** Filesystem scan on Linux servers, shell script artifact triage during IR, memory scanning for script content.

```yara
rule MAL_Linux_GHOST_Kit_Installer_Shell {
   meta:
      description = "Detects the GHOST v5.1/v6.0 cryptojacker kit installer (ghost.sh) based on distinctive operator-coined function names. The _anti_hisana function targets rival cryptojacker Hisana for displacement. _compile_hide_so compiles the LD_PRELOAD rootkit (libpam_cache.c) on victim hosts. _container_escape provides 4-variant container breakout capability for Docker/k8s/LXC cloud GPU environments."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      hash1 = "58ef3f244dab408fac7117606843a3dbcfb0754b2032a5950e977bc1811c0313"
      family = "GHOST-Cryptojacker-Kit"
      malware_type = "Cryptojacker-Installer"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "bcd488b4-ec22-5a44-824b-404064b3fcb0"
   strings:
      $fn1 = "_anti_hisana" ascii fullword
      $fn2 = "_compile_hide_so" ascii fullword
      $fn3 = "_container_escape" ascii fullword
      $fn4 = "_escape_via_cgroup" ascii fullword
      $fn5 = "_escape_via_nsenter" ascii fullword
      $v1 = "GHOST v5.1" ascii
      $v2 = "GHOST v6.0" ascii
      $v3 = "Anti-Hisana" ascii
      $t1 = "8415540095" ascii
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

**Campaign Infrastructure Artifacts**

#### ARPA Observability Harvester Systemd Service Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1119 (Automated Collection), T1041 (Exfiltration Over C2 Channel)
**Confidence:** HIGH
**Rationale:** The Turkish ARPA operator deploys five distinctively named systemd units and a self-branded string ("ARPA Korelasyon Motoru") found only on the operator's host. *Fix applied during retiering:* the original condition included a bare-OR path on the stolen victim JWT JTI value alone — a single-victim atomic that would never recur for a different ARPA deployment. That string has been removed from the rule (it remains in the IOC feed as a victim indicator); the rule now anchors only on the operator's own durable service names, branding, and ingestion endpoint.
**False Positives:** None known — the `arpa-*.service` naming pattern alongside the ARPA branding strings is operator-specific and not present in any legitimate observability platform configuration.
**Blind Spots:** A rebrand renaming all five service units and the branding string would evade; targets on-disk/installed-unit artifacts.
**Validation:** Scan a captured ARPA systemd unit file or platform binary — must match; unrelated observability-platform tooling must NOT fire.
**Deployment:** Filesystem scan on Linux servers (particularly observability/monitoring hosts), systemd unit audit, IR artifact triage.

```yara
rule MAL_Linux_ARPA_Observability_Harvester_Systemd {
   meta:
      description = "Detects the Turkish ARPA operator's observability-harvester platform based on distinctive systemd service unit filenames and operator self-branding strings. ARPA ingests stolen observability telemetry (IBM Instana + SolarWinds + Zabbix + VMware Aria via stolen API tokens) into a TimescaleDB+Neo4j+Redis stack."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "ARPA-Observability-Harvester"
      malware_type = "Data-Harvesting-Platform"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "08b8e947-a673-53c1-9303-6843c8e8ec50"
   strings:
      $svc1 = "arpa-instana-api.service" ascii
      $svc2 = "arpa-autolearn.service" ascii
      $svc3 = "arpa-continuous.service" ascii
      $svc4 = "arpa-daemon.service" ascii
      $svc5 = "arpa-parallel.service" ascii
      $b1 = "ARPA Korelasyon Motoru" ascii
      $b2 = "ARPA \xc2\xa9 2026" ascii
      $e1 = "/api/ingest/instana" ascii
   condition:
      filesize < 5MB and
      (
         (2 of ($svc*)) or
         (1 of ($b*)) or
         ($e1 and 1 of ($svc*))
      )
}
```

#### Pandora/Mirai Naku Architecture Naming Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1498 (Network Denial of Service), T1498.002 (Reflection Amplification), T1059.004 (Unix Shell)
**Confidence:** HIGH
**Rationale:** The Rovodev/Pandora operator's 11-architecture Mirai suite uses the bespoke `Naku.{arch}` naming scheme, botnet ID `PandoraNet`, and a custom 22-character charset baked into every binary. *Fix applied during retiering:* the original condition let a bare match on either of two hardcoded distribution-server IPs trigger the ELF branch alone; those IPs (already in the IOC feed) have been removed so the rule anchors only on the operator-coined botnet ID, charset, path fragments, and attack-method names.
**False Positives:** None known — the specific combination of `PandoraNet` botnet ID, `Naku.{arch}` naming, and the 22-char custom charset is not present in any other known Mirai variant.
**Blind Spots:** A full rebrand of the botnet ID and charset would evade; targets ELF binaries and dropper scripts, not a live network protocol.
**Validation:** Scan a captured `Naku.{arch}` binary or `pandora.sh` dropper — must match; an unrelated Mirai variant must NOT fire.
**Deployment:** ELF binary scanning on compromised IoT/Linux hosts, open-directory enumeration, download artifact scanning.

```yara
rule MAL_Linux_Pandora_Mirai_Naku_Suite {
   meta:
      description = "Detects the Rovodev operator's Pandora/Naku Mirai-variant botnet suite based on operator-bespoke naming patterns and the custom 22-character random-string charset. The suite covers 11 IoT architectures served from dual HTTP/HTTPS channels at /bins/Naku.{arch} and /Pandoras_Box/pandora.{arch}. Botnet ID 'PandoraNet' is suffixed by architecture in bot registration beacons."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "Pandora-Mirai-Variant"
      malware_type = "DDoS-Botnet"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "f3e8e30f-eedc-5e31-ab5e-381ec27010a3"
   strings:
      $b1 = "PandoraNet" ascii fullword
      $b2 = "PandoraNet.arm" ascii
      $b3 = "PandoraNet.x86" ascii
      $c1 = "1gba4cdom53nhp12ei0kfj" ascii
      $d1 = "/Pandoras_Box/" ascii
      $d2 = "/bins/Naku." ascii
      $m1 = "udp-star" ascii
      $m2 = "syn-storm" ascii
      $m3 = "tcp-matrix" ascii
      $m4 = "dns-rain" ascii
      $m5 = "ovh-nuke" ascii
      $r1 = "INFECTED|" ascii
   condition:
      (
         (uint32(0) == 0x464c457f and filesize < 2MB and (1 of ($b*) or $c1)) or
         (filesize < 500KB and ($d1 or $d2) and 1 of ($m*)) or
         ($r1 and 2 of ($m*))
      )
}
```

#### Russian A2A C2 Python-stdlib BaseHTTPServer

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.006 (Python), T1071.001 (Web Protocols), T1132.001 (Standard Encoding) — novel TTP, Operator-Built Unauthenticated Python-stdlib C2
**Confidence:** HIGH
**Rationale:** `c2_server.py` uses Python stdlib `BaseHTTPRequestHandler` with zero authentication across 5 endpoints, the operator banner "A2A C2 MULTI-AGENT CONSOLE", and an `X-Agent-ID` self-assertion header. *Fix applied during retiering:* the original condition let a bare match on either C2 domain (`c2.tralalarkefe.com` / `payloads.tralalarkefe.com` — both already in the IOC feed) trigger the rule alone; the domain-only path now requires co-occurrence with at least one API endpoint string.
**False Positives:** None known — the "A2A C2 MULTI-AGENT CONSOLE" banner is operator-bespoke, and the combination of `BaseHTTPRequestHandler` + unauthenticated `/api/v1/` endpoints + `X-Agent-ID` header + base64/UTF-16LE encoding is not present in legitimate server-management frameworks.
**Blind Spots:** A rebuild dropping the banner string and renaming all endpoints/header would evade; targets on-disk Python source, not a compiled/obfuscated variant.
**Validation:** Scan the captured `c2_server.py` — must match; unrelated Python HTTP servers must NOT fire.
**Deployment:** Filesystem scan on compromised servers, Python source artifact triage, memory scanning for running Python processes.

```yara
rule MAL_Python_Russian_A2A_C2_BaseHTTPServer {
   meta:
      description = "Detects the Russian Gemini operator's custom A2A (Agent-to-Agent) C2 backend built on Python stdlib BaseHTTPServer. Features zero authentication on all 5 API endpoints, a path-traversal-vulnerable file server, base64+UTF-16LE encoding (matching PowerShell EncodedCommand format), and Cloudflare Tunnel transport."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "Russian-A2A-C2"
      malware_type = "Custom-C2-Backend"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "943da3bd-c273-5e48-829e-1ec1389fd48a"
   strings:
      $b1 = "A2A C2 MULTI-AGENT CONSOLE" ascii
      $e1 = "/api/v1/update" ascii
      $e2 = "/api/v1/agents" ascii
      $e3 = "/api/v1/interact" ascii
      $e4 = "/api/v1/telemetry" ascii
      $e5 = "/api/v1/get_results" ascii
      $h1 = "X-Agent-ID" ascii
      $enc1 = "decode('utf-16le')" ascii
      $enc2 = "base64.b64decode" ascii
      $d2 = "c2.tralalarkefe.com" ascii
      $d3 = "payloads.tralalarkefe.com" ascii
   condition:
      filesize < 1MB and
      (
         $b1 or
         (3 of ($e*) and $h1) or
         ($enc1 and $enc2 and 2 of ($e*)) or
         (($d2 or $d3) and 1 of ($e*))
      )
}
```

### Hunting Rules

**Novel AI-Abuse TTPs**

#### AI-Generated Offensive Code Structural Signature

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python) — novel TTP, AI-Generated Code Structural Signature
**Confidence:** MODERATE (each criterion alone is low-confidence; the combination is higher)
**Rationale:** Cross-operator validated across three independent operators' Python attack code (Case 1, Case 2, Case 3). The co-occurrence of verbose docstrings + bare-except + defensive try/except + educational variable names + zero anti-analysis is common in benign, actively-developed Python, so this is explicitly not suitable for automated alerting alone.
**False Positives:** Legitimate Python developers routinely write verbose docstrings and defensive error handling; the FP rate increases meaningfully in active development environments.
**Deployment:** Hunting/hypothesis generation on suspicious server hosts; combine with operator-adjacent artifact signals (credential files, C2 artifacts, scanning tools) before treating a hit as actionable.

```yara
rule SUSP_AI_Generated_Offensive_Code_Python {
   meta:
      description = "Detects Python offensive tools bearing the structural signature of AI-generated code: verbose docstrings co-occurring with bare-except handlers, defensive try/except wrapping, and educational variable names. Confirmed cross-operator across 3 independent actors (Case 1 Russian, Case 2 Turkish ARPA, Case 3 Rovodev)."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      family = "AI-Generated-Offensive-Code"
      malware_type = "Offensive-Tool-Structural-Pattern"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "2ac2da6f-2d42-5e9e-a1b2-f03f13990126"
   strings:
      $doc1 = "\"\"\"" ascii
      $doc2 = "Args:" ascii
      $doc3 = "Returns:" ascii
      $doc4 = "Raises:" ascii
      $exc1 = "except:" ascii
      $exc2 = "except Exception as e:" ascii
      $var1 = "target_url" ascii
      $var2 = "success_count" ascii
      $var3 = "failed_count" ascii
      $var4 = "max_workers" ascii
      $var5 = "ThreadPoolExecutor" ascii
      $rate1 = "time.sleep" ascii
      $rate2 = "rate_limit" ascii
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
      1 of ($doc2, $doc3, $doc4) and
      ($exc1 or $exc2) and
      2 of ($var*) and
      1 of ($rate*) and
      2 of ($off*)
}
```

---

## Sigma Rules

### Detection Rules

**GHOST Kit + libpam_cache Rootkit (Case 9)**

#### /etc/ld.so.preload Modification (LD_PRELOAD Rootkit Persistence)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit)
**Confidence:** HIGH
**Rationale:** `/etc/ld.so.preload` is THE system-wide LD_PRELOAD persistence chokepoint — a technique-level invariant an attacker cannot avoid touching to achieve this exact persistence mechanism, including the GHOST kit's `libpam_cache.so` rootkit (byte-identical across 2 customer deployments, 0/0 AV at discovery). *Tag fix applied during retiering:* added the missing `attack.t1574.006` technique tag, plus the `attack.execution` tactic tag `sigma check` requires alongside it (the original carried tactic-only tags with no technique).
**False Positives:** Performance/instrumentation libraries that legitimately use LD_PRELOAD (libfaketime, libsegfault, libtcmalloc, valgrind, vtune) — typically confined to dev/test environments.
**Blind Spots:** Misses persistence mechanisms other than LD_PRELOAD (services, cron, `.bashrc`); requires file-event telemetry on `/etc/`.
**Validation:** Trigger the GHOST installer's rootkit-registration step — the write must match; a `dpkg`/`apt` package upgrade touching the same file's mtime without content change should be reviewed by parent-process, not auto-suppressed.
**Deployment:** Linux file integrity monitoring, auditd, Sysmon for Linux — deploy on all production server hosts; tune out development environments via host-tag exclusion.

```yaml
title: Linux LD_PRELOAD Rootkit Persistence via /etc/ld.so.preload Modification
id: 8961351c-34c4-4a6e-b031-16a6368ae15e
status: experimental
description: >-
  Detects writes or creates of /etc/ld.so.preload, which is the persistence mechanism
  for userland LD_PRELOAD rootkits including the GHOST v5.1/v6.0 cryptojacker kit's
  libpam_cache.so rootkit. Legitimate /etc/ld.so.preload usage is rare on production
  servers. When present post-alert, inspect the file content for non-standard library
  paths and cross-reference /lib/security/ for newly written .so files.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
    - https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.persistence
    - attack.stealth
    - attack.execution
    - attack.t1574.006
    - detection.emerging-threats
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
      Correlate with parent process: apt/dpkg writes are expected; shell/unknown-binary writes
      are high-confidence malicious.
level: high
```

#### Cryptojacker libpam_cache Drop to /lib/security

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1027 (Obfuscated Files — deceptive naming)
**Confidence:** HIGH
**Rationale:** Requires the PAM-style path AND the `libpam_cache` name component together — no legitimate distro ships a module by that name. *Fixes applied during retiering:* added the missing `attack.t1574.006` technique tag plus the `attack.execution` tactic tag `sigma check` requires alongside it, and converted the `selection_name` single-item list to a scalar (`sigma check`'s single-value-list rule).
**False Positives:** Legitimate distro packages installing PAM modules — verify parent process is `apt`/`dpkg`/`rpm`/`yum` and not a shell or unknown binary.
**Blind Spots:** A rebuild renaming the rootkit away from the `libpam_cache` convention evades; the rule targets the write event, not post-load hiding.
**Validation:** Trigger the rootkit drop step — must match; a genuine distro PAM-module package install must NOT fire (parent process check).
**Deployment:** Linux file integrity monitoring on `/lib/security/`, auditd with `-w` watch rule, Sysmon for Linux.

```yaml
title: Cryptojacker LD_PRELOAD Rootkit Drop to /lib/security (PAM-Style Camouflage Naming)
id: 6c7e9d33-7dc3-411b-994f-37d431e05907
status: experimental
description: >-
  Detects file creation in /lib/security or multiarch equivalents of .so files matching
  the GHOST cryptojacker kit's deceptive PAM-style naming convention (libpam_cache*).
  Once loaded, the rootkit hides its own filename from readdir output, making
  filesystem-level detection via ls unreliable. This rule targets the write event
  before the rootkit activates.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.persistence
    - attack.stealth
    - attack.execution
    - attack.t1574.006
    - detection.emerging-threats
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
        TargetFilename|contains: libpam_cache
    condition: selection_path and selection_name
falsepositives:
    - >-
      Legitimate distro packages installing PAM modules — verify parent process is
      apt/dpkg/rpm/yum and not a shell or unknown binary. No legitimate Linux distribution
      ships a libpam_cache.so PAM module.
level: high
```

#### GHOST Kit ComfyUI Fake Custom Node PerformanceMonitor Registration (Case 9)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1543.002 (Systemd Service — Python module persistence analog), T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**Rationale:** "PerformanceMonitor" is not present in any legitimate ComfyUI custom node package; the display name "GPU Performance Monitor" plus installation from the kit-author's now-suspended GitHub repos is distinctly malicious. *Tag fix applied during retiering:* added the missing `attack.t1496.001` technique tag.
**False Positives:** No known legitimate ComfyUI custom node uses the PerformanceMonitor node name.
**Blind Spots:** A rebrand of the fake node's name would evade; the kit-author repos are now suspended (new pip installs fail) but locally cached copies may persist on already-infected hosts.
**Validation:** Trigger the ComfyUI custom-node installation step — must match; installation of an unrelated, legitimately-named ComfyUI node must NOT fire.
**Deployment:** ComfyUI host filesystem monitoring, Python process monitoring on GPU compute hosts, AI/ML infrastructure endpoint agents.

```yaml
title: GHOST Kit ComfyUI Fake Custom Node PerformanceMonitor Registration (Case 9)
id: 3f6f8f15-2716-4cc1-8eb6-12b9c3bf2c60
status: experimental
description: >-
  Detects registration of the GHOST cryptojacker kit's fake ComfyUI custom node
  "PerformanceMonitor" (display name "GPU Performance Monitor") used to establish
  persistence on ComfyUI-hosting AI inference servers. The fake node is installed via
  pip from the kit-author's GitHub repos. Detection via file creation under ComfyUI's
  custom_nodes directory matching the PerformanceMonitor pattern, or process creation
  showing pip installing from the kit-author repos.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.persistence
  - attack.impact
  - attack.t1496.001
  - detection.emerging-threats
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
    The kit-author GitHub repos were suspended by GitHub T&S, so new pip install
    attempts from those URLs will now fail — but locally cached copies may persist.
level: high
```

**Campaign Infrastructure Artifacts**

#### Cloudflared Access TCP Tunnel Registration to Non-Allowlisted Hostname

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1021.001 (RDP), T1021.004 (SSH)
**Confidence:** HIGH
**Rationale:** The exact combination of the `cloudflared` binary with `access`, `tcp`, and `--hostname` flags is a specific, narrow command pattern rarely used outside a formally managed Cloudflare Zero Trust deployment; the Russian operator (Case 1) used it to maintain persistent RDP/SSH access to a US healthcare victim. *Tag fix applied during retiering:* added the missing `attack.t1090.004` technique tag.
**False Positives:** Legitimate Cloudflare Zero Trust TCP application proxies configured by network administrators — allowlist known deployment hostnames.
**Blind Spots:** Legitimate enterprise Zero Trust deployments using this exact command are a real, if allowlist-manageable, population; the rule does not itself enforce a hostname allowlist (Sigma has no environment-aware NOT-IN-list mechanism).
**Validation:** Trigger a `cloudflared access tcp --hostname <host> --url localhost:<port>` command — must match; a plain `cloudflared tunnel run` (no `access tcp`) must NOT fire.
**Deployment:** Sysmon process creation, auditd execve, Linux endpoint agent.

```yaml
title: Cloudflared Access TCP Tunnel Registration to Non-Allowlisted Hostname
id: 0d88f829-c8e3-42e5-a3c3-34cb8a5fec1a
status: experimental
description: >-
  Detects execution of 'cloudflared access tcp' with the --hostname flag, indicating
  an operator is activating a Cloudflare tunnel to proxy TCP traffic (RDP, SSH, WinRM)
  through Cloudflare infrastructure. Observed in Case 1 (Russian Gemini operator)
  maintaining persistent RDP access via windows_server.tralalarkefe.com and SSH access
  via gil_dr1.tralalarkefe.com. Legitimate usage requires a formally managed Cloudflare
  Zero Trust account configuration — ad-hoc usage with operator-bespoke domains
  indicates tunneled lateral movement or a C2 channel.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.command-and-control
  - attack.lateral-movement
  - attack.t1090.004
  - detection.emerging-threats
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
    administrators. Allowlist known Cloudflare Access deployment hostnames — attacker-
    controlled hostnames will not match corporate Zero Trust domains.
level: high
```

#### Instana API Enumeration via Stolen JWT (ARPA Observability Harvester, Case 2)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1119 (Automated Collection), T1530 (Data from Cloud Storage Object — MODERATE)
**Confidence:** HIGH (PowerShell Script Block Logging detection); MODERATE (network-side proxy detection)
**Rationale:** The specific combination of `-SkipCertificateCheck` with `ocpinstana` endpoint references in a PowerShell script block is characteristic of the Turkish ARPA operator's `instana_local_collector.ps1`. *Fixes applied during retiering:* removed a bare `apiToken` OR-path (an extremely common, generic variable/header name in legitimate API scripts that would have fired this HIGH-level rule on ordinary REST-API automation) and a literal, never-filled-in placeholder string `'[victim-tenant]'` that could never match real telemetry. The stolen JWT JTI remains available in the IOC feed as a victim indicator rather than as a rule OR-path.
**False Positives:** Legitimate Instana API clients that use `-SkipCertificateCheck` for internal OCP self-signed certificates — narrow by source host.
**Blind Spots:** A script avoiding `-SkipCertificateCheck` (e.g. using a properly-trusted cert) evades; PowerShell Script Block Logging must be enabled for this telemetry to exist at all.
**Validation:** Trigger a PowerShell script combining `-SkipCertificateCheck` and an `ocpinstana`-referencing endpoint — must match; an unrelated PowerShell script using `-SkipCertificateCheck` alone (e.g. against a different internal API) must NOT fire.
**Deployment:** PowerShell Script Block Logging (Event 4104) on Windows hosts where the collector runs.

```yaml
title: >-
  Instana API Enumeration via Stolen JWT from Non-Management-Platform Source
  (ARPA Observability Harvester)
id: f9c5ebeb-d6b8-4425-bb85-bfa4d30e28ac
status: experimental
description: >-
  Detects PowerShell execution of Instana API enumeration scripts using the -SkipCertificateCheck
  flag alongside references to the ocpinstana endpoint pattern, characteristic of the
  Turkish ARPA operator's instana_local_collector.ps1 script. The script makes sliding
  10-minute-window GET /api/events requests with a stolen 10-year Instana JWT to
  exfiltrate observability telemetry to the attacker's ARPA platform. Detection from
  PowerShell Script Block Logging is highly reliable when -SkipCertificateCheck appears
  alongside Instana endpoint strings.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.collection
  - attack.exfiltration
  - attack.t1119
  - detection.emerging-threats
logsource:
  product: windows
  category: ps_script
  definition: Script Block Logging must be enabled (reg key HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1)
detection:
  selection:
    ScriptBlockText|contains|all:
      - SkipCertificateCheck
      - ocpinstana
  condition: selection
falsepositives:
  - >-
    Legitimate Instana API clients that use -SkipCertificateCheck for internal OCP
    self-signed certificates. Narrow by source host — the attacker's exfiltration
    target is not a legitimate Instana destination.
level: high
```

**Campaign-Level — AI-Tool + Offensive-Tool Co-Location (Correlation)**

#### AI Coding-Agent Tooling Co-Located with Offensive Tooling on the Same Host

**Tier:** Detection (correlation rule) — bundled below with its 2 required Hunting-grade base rules, which do not alert on their own
**Robustness:** 2 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1588.002 (Obtain Capabilities: Tool)
**Confidence:** MODERATE — co-presence of AI tools and offensive tooling on a server host warrants investigation but is not conclusive by itself
**Rationale:** Neither base selector is meaningful alone — AI coding-agent execution and generic scanning/tunneling tool execution are both common on legitimate developer and security-research hosts. The temporal correlation (both signals on the *same host* within 24 hours) is what discriminated the real Case 7 (Weevely+frp+Claude) operator from two demoted false positives (a legitimate SaaS-security consultant and a HuggingFace researcher) where only one signal type was present. *Tag fixes applied during retiering:* added the missing technique-ID tags to all three rules (`attack.t1587` on both the AI-tool base and the correlation; `attack.t1588.002` on both the offensive-tool base and the correlation).
**False Positives:** The two base rules alone are extremely broad (any AI-coding-agent user; any admin running `nmap`/`masscan`). The correlation rule itself: "a host legitimately used both for AI-assisted development and authorized security testing" — narrower, but real in security-research environments.
**Blind Spots:** An operator running AI-tool and offensive-tool sessions more than 24 hours apart, or split across separate hosts, evades the correlation.
**Validation:** Replay both base selectors against the same `host.name` within the 24-hour window — the correlation must fire; a host showing only one signal type must NOT trigger the correlation.
**Deployment:** Endpoint agent filesystem/process scanning with host-role classification feeding a SIEM correlation engine (24h temporal join on `host.name`).

```yaml
title: AI Coding-Agent Binary Execution on Server Host
id: 67cd7a66-7487-4bc2-94b5-2db9ffbf2080
name: ai_agent_tooling_exec_serverhost
status: experimental
description: >-
    Base rule (not alerting on its own): execution of an AI coding-agent binary
    from its state directory (Claude Code, Gemini CLI, RovoDev, OpenClaw) on a
    server host. Paired with the correlation rule below, which flags co-location
    with offensive tooling.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1587
    - detection.emerging-threats
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
    condition: selection_ai_tools
falsepositives:
    - Legitimate developer or operator use of AI coding agents on the host
level: informational
---
title: Offensive Tooling Execution on Server Host
id: 2fa74c68-e65d-46b3-b516-cc12400ddaee
name: offensive_tooling_exec_serverhost
status: experimental
description: >-
    Base rule (not alerting on its own): execution of offensive/network tooling
    (nuclei, frpc/frps, masscan, nmap). Paired with the correlation rule below.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1588.002
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_offensive_tools:
        Image|endswith:
            - /nuclei
            - /frpc
            - /frps
            - /masscan
            - /nmap
    condition: selection_offensive_tools
falsepositives:
    - Authorized security testing or network administration on the host
level: low
---
title: AI Coding-Agent Tooling Co-Located with Offensive Tooling on the Same Host
id: 337c7b1d-0f56-4c27-932f-2ea507ba24f1
status: experimental
description: >-
    Fires when both AI coding-agent execution and offensive-tooling execution
    are observed on the same host within 24 hours. This co-location — not either
    signal alone — is the indicator of AI-orchestrated attack infrastructure.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
    - attack.resource-development
    - attack.t1587
    - attack.t1588.002
    - detection.emerging-threats
correlation:
    type: temporal
    rules:
        - ai_agent_tooling_exec_serverhost
        - offensive_tooling_exec_serverhost
    group-by:
        - host.name
    timespan: 24h
falsepositives:
    - A host legitimately used both for AI-assisted development and authorized security testing
level: high
```

### Hunting Rules

**Novel AI-Abuse TTPs**

#### Claude Code settings.local.json or settings.json Modified

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Impair Defenses)
**Confidence:** MODERATE — the rule's own description states this is a hunting lead, not an alert
**Rationale:** File-event telemetry cannot inspect file content, so a hit only means "this permissions file changed" — it cannot itself distinguish an operator pre-authorizing a curl-to-shell pattern from a routine, legitimate settings edit. *Tag fixes applied during retiering, verified against the real `sigma check` tool:* the original carried tactic-only tags with no technique; `attack.t1562.001` was tried first but the tool rejects it as invalid — MITRE renumbered Impair Defenses to the top-level technique **T1685** (no longer a Defense Evasion sub-technique tree under T1562) — and the tool then required the new ATT&CK v19 `attack.defense-impairment` (TA0112) tactic tag alongside it, which has been added. An unpaired `attack.execution` tactic tag (unsupported by the file-modification-only logic) was dropped.
**False Positives:** Routine or legitimate edits to Claude Code settings are common — review the added permission entries after the alert fires.
**Deployment:** Linux/macOS file integrity monitoring (FIM) on developer and server hosts, auditd, Sysmon for Linux.

```yaml
title: >-
  Claude Code settings.local.json or settings.json Modified
id: 803d43fe-6b5a-48e1-b25f-9da5e74bca62
status: experimental
description: >-
  Detects modification of a Claude Code permissions file (settings.local.json /
  settings.json). File-event telemetry cannot inspect the file content, so this is
  a hunting lead: after it fires, review whether the change added an auto-approved
  dangerous command (for example a curl-to-shell pattern) to the permissions
  allow-list.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.stealth
  - attack.persistence
  - attack.defense-impairment
  - attack.t1685
  - detection.emerging-threats
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
    Routine or legitimate edits to Claude Code settings (common) — review the
    added permission entries. Investigate file content after alert — the
    curl-pipe-bash and npm-i-g-unfamiliar patterns are the high-confidence indicators
    within a triggered file modification.
level: medium
```

#### Outbound Gemini API Traffic from Non-AI-Workload Server Host (Stolen Key Validation)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1552.001 (Credentials in Files)
**Confidence:** MODERATE
**Rationale:** `generativelanguage.googleapis.com` is Google's own legitimate API domain — durable (attacker can't rotate it), but shared by an enormous population of legitimate AI applications, so precision fails the Detection bar without host-role classification. *Tag fix applied during retiering:* added the missing `attack.t1552.001` technique tag.
**False Positives:** High on hosts running legitimate AI applications; low on general-purpose server hosts with no expected AI workload.
**Deployment:** Network proxy/firewall with host-role classification, DNS query monitoring. Hunting-only without host classification.

```yaml
title: Outbound Gemini API Traffic from Non-AI-Workload Server Host (Stolen Key Validation)
id: 06d6f95f-2946-4bb9-b0ff-49921d91922f
status: experimental
description: >-
  Detects outbound DNS queries to generativelanguage.googleapis.com from server-class
  hosts without a legitimate AI-application workload designation. Case 1 (Russian
  Gemini operator) uses stolen Gemini API keys validated via check_keys.py, and the
  same endpoint is used by the LLM-personalized credential mutation script to invoke
  Gemini 2.5 Flash for per-target password generation at attack time.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.credential-access
  - attack.t1552.001
  - detection.emerging-threats
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
    Legitimate AI applications and developer tools that use the Gemini API. Requires
    host-role classification to be effective — suppress on designated AI application
    servers and developer workstations.
level: low
```

**Campaign Infrastructure Artifacts**

#### Rovodev AI Agent Directory Creation on Server Infrastructure Host

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1587 (Develop Capabilities)
**Confidence:** MODERATE — the `.rovodev/` directory alone could appear on any host where a developer legitimately uses Rovodev
**Rationale:** Signal strength increases significantly when co-located with offensive tooling or on non-developer server infrastructure, but the rule as written is a single directory-path selector with no such co-location check. *Fixes applied during retiering:* converted the single-item `TargetFilename|contains` list to a scalar, and added the missing `attack.t1587` technique tag.
**False Positives:** Medium on development hosts, low on production server infrastructure with no expected AI agent tooling.
**Deployment:** Linux file integrity monitoring, endpoint agent filesystem scan, auditd directory creation watch.

```yaml
title: Rovodev AI Agent Directory Creation on Server Infrastructure Host
id: c88a8604-f07b-452b-821e-ecd610edd062
status: experimental
description: >-
  Detects creation of ~/.rovodev/ directories on server-class hosts, indicating the
  presence of the Atlassian Rovodev AI coding agent. While Rovodev is a legitimate
  enterprise product, its presence on server infrastructure co-located with offensive
  tooling indicates an AI-integrated threat operator. Case 3 (Rovodev/Pandora operator)
  had ~/.rovodev/sessions/ containing 1.24 MB AI-authoring session JSONs.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
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
  selection:
    TargetFilename|contains: /.rovodev/
  condition: selection
falsepositives:
  - >-
    Legitimate Atlassian Rovodev users on developer workstations and Atlassian-licensed
    development servers. Apply host-role classification.
level: medium
```

**Campaign-Level — Operator Infrastructure Egress**

#### Trycloudflare.com Quick-Tunnel Egress from Server Host

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**Rationale:** The `*.trycloudflare.com` suffix keys on Cloudflare's ephemeral-tunnel *service* rather than a rotatable attacker-owned domain, so it survives subdomain rotation — but it is also Cloudflare's genuinely free, widely-used developer tunnel product, so a meaningful legitimate population exists. *Retiered from Detection to Hunting during this pass:* the original `level: high` overstated confidence — Sigma has no host-role field to restrict this selector to server-class hosts, so as written it fires identically on any developer or CI host using the same free service; demoted to `level: medium`. Tag fix: added the missing `attack.t1090.004` technique tag.
**False Positives:** Developers and CI/CD pipelines using Cloudflare Tunnel for local development exposure (ngrok-alternative use case) — exempt known developer/CI hosts by hostname or subnet.
**Deployment:** DNS query logs, network proxy/firewall egress, Sysmon process creation for `cloudflared` binary execution.

```yaml
title: Trycloudflare.com Quick-Tunnel Egress from Non-Developer Server Host
id: 5581299d-e9a1-4a83-b85c-8d68a93fd03b
status: experimental
description: >-
  Detects DNS queries or process creation events for trycloudflare.com ephemeral tunnels.
  Threat actors (Case 1 Russian Gemini operator) use Cloudflare quick-tunnels to proxy
  C2 traffic through Cloudflare infrastructure, disguising the true C2 IP and bypassing
  egress firewall rules. Trycloudflare subdomains are ephemeral and randomly generated
  (e.g. tenant-upcoming-great-descending.trycloudflare.com) — not predictable by defenders.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.command-and-control
  - attack.t1090.004
  - detection.emerging-threats
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
level: medium
```

#### Egress to Operator-Hosting ASNs from Production Server (Baseline Pivot)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1583.003 (Virtual Private Server)
**Confidence:** LOW — ASN-based egress rules have inherently high FP rates in cloud-connected environments
**Rationale:** All five operator-controlled servers in this campaign are hosted on AEZA, Contabo, DigitalOcean, 1&1 IONOS, and Korea Telecom; the rule's own title already flags it as a hunting baseline, not an alert. *Tag fix applied during retiering:* added the missing `attack.t1583.003` technique tag.
**False Positives:** High in environments with significant cloud/CDN traffic — CDN egress, legitimate cloud API traffic, and third-party service integrations routinely originate from these ASNs.
**Deployment:** Firewall egress logs, network flow analytics. Hunting only — do not configure as an automated alert.

```yaml
title: Egress to AEZA/Contabo/DigitalOcean-SG/IONOS/Korea-Telecom from Production Server (Hunting)
id: bb917d1e-bb95-48d2-bb19-505cd6655456
status: experimental
description: >-
  Hunting rule flagging outbound connections from production server hosts to IP ranges
  associated with the campaign's operator-hosting ASNs: AEZA International Group (Case 1
  + Case 9), Contabo GmbH (Cases 5/6 demoted but infra tracked), DigitalOcean Frankfurt/
  Singapore (Case 2 Turkish ARPA), 1&1 IONOS (Case 3 Pandora botnet), Korea Telecom
  (Case 4 Korean operator). High FP rate as a standalone rule — combine with destination
  port specificity to raise confidence.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.resource-development
  - attack.t1583.003
  - detection.emerging-threats
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
    CDN egress, legitimate cloud API traffic, third-party service integrations. Use as
    a hunting pivot combined with destination port filters (mining ports, C2 elite ports).
level: low
```

**Case 8 — AI-Orchestrated Payment API Attack**

#### Suspected AI-Orchestrated Multi-Stage API Attack Sequence (Machine-Speed Window)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1657 (Financial Theft)
**Confidence:** LOW — the 60-second window and API sequence correlate with the observed case but the underlying LLM vendor is unidentified
**Rationale:** The rule is explicitly a selection-only building block for a SIEM correlation search (4+ distinct API endpoints from one source IP within 60 seconds) — the URI-substring selector alone matches enormous volumes of ordinary web traffic on any API-driven site. *Tags replaced during retiering:* the original `attack.credential-access` + `attack.exfiltration` tactic tags had no matching technique-ID tag and don't cleanly correspond to a generic `/api/`, `/auth/`, `/payment/`, `/transaction/` URI-substring selector; replaced with `attack.impact` + `attack.t1657` (Financial Theft), the technique already named in the rule's own evidence.
**False Positives:** High — automated payment processing systems, health checks, and load-balancer probes generate similar API call sequences.
**Deployment:** SIEM correlation with payment/authentication API access logs ingested, minimum 30-day baseline required to establish normal API call velocity per source IP.

```yaml
title: Suspected AI-Orchestrated Multi-Stage API Attack Sequence (Machine-Speed Window)
id: f8fbdc2e-b653-4b9c-b56d-2c004c202ea5
status: experimental
description: >-
  Detects requests to payment/authentication/transaction API endpoints characteristic of
  the reconnaissance and exploitation stages in a machine-speed, multi-stage API attack
  sequence tied to LLM-orchestrated attack tooling. Case 8 documented a 6-stage payment
  API exploitation completed in under 60 seconds. This selection-only rule flags
  individual requests; operationalizing the full 60-second/4+-endpoint velocity
  signature requires a SIEM correlation search across API access logs, not expressible
  as a single Sigma detection rule. Hunting leads only.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
  - attack.impact
  - attack.t1657
  - detection.emerging-threats
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
  condition: selection
falsepositives:
  - >-
    Legitimate payment processing automation, API health check systems, and load
    balancer probe sequences. A 30-day API call velocity baseline per source IP is
    recommended before operationalizing.
level: low
```

---

## Suricata Signatures

### Detection Rules

**Case 1 — Russian A2A C2**

#### A2A C2 X-Agent-Id Header + API Endpoint Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding — encoding layer, not itself matched)
**Confidence:** HIGH
**Rationale:** Requires the POST method, the `/api/v1/` URI prefix, and the `X-Agent-Id` custom header name in the same request — an operator-bespoke combination not present in legitimate server-management frameworks. An attacker would need to change the URI convention AND the header name simultaneously to evade.
**False Positives:** None known — `X-Agent-Id` is not a standard or common custom header name; `/api/v1/` alone is generic but is never the sole anchor in this rule.
**Blind Spots:** Evaded by a protocol rewrite dropping the `X-Agent-Id` header or the `/api/v1/` URI convention; does not cover the Cloudflare-Tunnel-fronted variant of this same channel once the tunnel terminates the visible HTTP layer.
**Validation:** Replay a captured A2A C2 HTTP POST request — must alert; an unrelated API request using a generic `/api/v1/` path without the `X-Agent-Id` header must NOT fire.
**Deployment:** Network IDS/IPS on server-segment egress, HTTP-capable IDS with header inspection.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL AI-Agent-Campaign Russian A2A C2 X-Agent-Id Header + API Endpoint (Case 1 C2 Protocol Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/"; http.header_names; content:"X-Agent-Id"; nocase; classtype:trojan-activity; threshold:type limit,track by_src,count 3,seconds 3600; sid:9200007; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

### Hunting Rules

**Campaign-Level — Operator Infrastructure Egress**

#### trycloudflare.com DNS Query Egress from Server Hosts

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1583.006 (Web Services — Cloudflare Tunnel), T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**Rationale:** Keys on Cloudflare's ephemeral-tunnel service suffix rather than an attacker-rotatable literal, so it survives subdomain rotation — but the same free service is widely used by legitimate developers and CI/CD pipelines.
**False Positives:** Developer and CI/CD hosts legitimately using `trycloudflare.com` for temporary exposure of local services.
**Deployment:** Network IDS/IPS on server-segment egress, DNS monitoring.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign trycloudflare.com Quick-Tunnel DNS Query from Server Host (C2 Transport Indicator)"; dns_query; content:"trycloudflare.com"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200000; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

**GHOST Kit + libpam_cache Rootkit (Case 9)**

#### Kryptex Mining Pool DNS Query Egress (GHOST Kit Operator-A Pool)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1496.001 (Compute Hijacking)
**Confidence:** MODERATE
**Rationale:** `kryptex.network` is a third-party mining-pool domain the GHOST kit operator does not control — durable in that rotating the operator's own infrastructure does not change it — but a bare domain match with no other discriminator is kept at Hunting for consistency with this file's other DNS-only signatures. *Fix applied during retiering:* added a `threshold` clause (absent from the original) to cap alert volume from a persistently-beaconing miner.
**False Positives:** Any legitimate, consented use of the Kryptex platform (a real consumer mining service) from a corporate network would also match — uncommon outside a strict acceptable-use environment.
**Deployment:** Network IDS/IPS, DNS monitoring, threat hunting on all server-class hosts.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign Kryptex Mining Pool DNS Query — GHOST Cryptojacker Kit Pool (cfx.kryptex.network / etc.kryptex.network)"; dns_query; content:"kryptex.network"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200001; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

#### Generic Cryptojacker Mining Pool DNS Pattern (c3pool / nanopool / moneroocean / hashvault)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1496.001 (Compute Hijacking)
**Confidence:** MODERATE — generic cryptomining indicator not tied to a specific kit family; both the GHOST kit and unrelated cryptojackers use these public pools as fallback destinations
**Rationale:** *Fix applied during retiering:* the original was a single PCRE-only rule (`pcre:"/(?:c3pool\.org|nanopool\.org|xmrig\.com|moneroocean\.stream|hashvault\.pro)/i"`) with no `content` prefilter — a named Suricata anti-pattern that forces regex evaluation on every DNS packet. Split into 4 individual `content`-anchored rules, one per pool domain, eliminating the PCRE entirely. `xmrig.com` was dropped from the set — it is the legitimate XMRig mining-software project's own homepage domain, not a pool destination, and its inclusion in the original PCRE list appears to be a data-quality error (see Coverage Gaps).
**False Positives:** These pool domains have no legitimate enterprise use; the per-rule `threshold` limits alert volume for hosts running a persistent miner.
**Deployment:** Network IDS/IPS perimeter monitoring, DNS monitoring.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign c3pool.org Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"c3pool.org"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200002; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign nanopool.org Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"nanopool.org"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200003; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign moneroocean.stream Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"moneroocean.stream"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200004; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign hashvault.pro Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"hashvault.pro"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200005; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

#### Hysteria v2 QUIC bing.com SNI Masquerade Detection (Case 9)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1665 (Hide Infrastructure)
**Confidence:** MODERATE
**Rationale:** SNI masquerade (presenting `bing.com` while tunneling GHOST kit backdoor traffic over Hysteria v2/QUIC) is a durable evasion *technique*, but the specific masquerade domain choice is trivially changed in a future build. *Fixes applied during retiering:* the original rule matched the SNI via raw byte-offset `content` on the QUIC packet (`content:"|00 00|"; offset:0; content:"bing.com"; content:"|00 01|"`) with no sticky buffer at all. QUIC Initial packets are encrypted per RFC 9001, so a literal ASCII "bing.com" match at a fixed byte offset is unlikely to fire against real traffic as intended. First rewritten to the `tls.sni` sticky buffer, but the real `suricata -T` engine (8.0.5) rejected that combination; Suricata exposes QUIC-derived fields through their own dedicated `quic.*` buffers rather than reusing `tls.*`, so the rule now uses `quic.sni` — confirmed passing against the live engine.
**False Positives:** Medium without a destination-IP allowlist for Microsoft's real Bing CDN ranges — legitimate `bing.com` QUIC connections will also match on SNI alone.
**Deployment:** Network IDS with QUIC/TLS inspection enabled (`app-layer.protocols.quic.enabled: yes`).

```
alert quic $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign Hysteria v2 QUIC bing.com SNI Masquerade (GHOST Kit Backdoor Non-Microsoft Destination)"; quic.sni; content:"bing.com"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:9200006; rev:1; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/;)
```

---

## Coverage Gaps

### Retiering Fixes Applied (2026-07-13 Backfill)

This file was re-scored against the project's four-gate Detection/Hunting/Cut rubric. Beyond re-tiering, the following defects were corrected — each was either an atomic-only trigger path masquerading as a durable signature, a missing/invalid Sigma tag, or a technically unsound network match:

- **YARA bare-literal OR-paths removed (4 rules).** The AI Operator Handoff Document, ARPA Observability Harvester, Pandora/Naku Suite, and Russian A2A C2 rules each originally let one hardcoded, atomic value (a domain, a victim-specific JWT JTI, or two distribution IPs) trigger the whole rule alone via a bare OR branch. Each has been tightened to require the atomic to co-occur with a genuine behavioral/structural indicator; every underlying value was already present in the IOC feed, so no feed edits were required.
- **Sigma missing technique-ID tags (12 of 12 rule-headings).** Every Sigma rule in the original file carried tactic tags only, with no matching `attack.tXXXX` technique tag — a SigmaHQ validation failure. Each rule now carries at least one technique tag drawn from its own documented ATT&CK Coverage evidence, verified against the real `sigma check` tool rather than assumed: the tool required an added `attack.execution` tactic tag alongside `attack.t1574.006` on the two LD_PRELOAD rules; rejected `attack.t1562.001` outright as invalid (MITRE renumbered Impair Defenses to the top-level **T1685**); and then required the new ATT&CK v19 `attack.defense-impairment` (TA0112) tactic tag alongside `attack.t1685` on the settings.local.json rule. All three rounds of feedback came from the tool, not guesswork — `sigma check` returns 0 errors and 0 issues on the final file.
- **Sigma8 (Instana enumeration) broken selector removed.** The original `selection_token` block included a literal, never-filled-in placeholder string `'[victim-tenant]'` (non-functional — it could never match real telemetry) and a bare `apiToken` OR-path (a generic term common in legitimate API scripts, which would have fired this HIGH-level rule broadly). Both were removed; the rule now anchors solely on the `-SkipCertificateCheck` + `ocpinstana` combination.
- **Sigma3 and Sigma9 single-value lists converted to scalars**, per SigmaHQ's list-of-one convention.
- **Sigma11 tags replaced**, not merely supplemented — the original tactic tags didn't correspond to any technique the rule's own evidence named; replaced with `attack.impact` + `attack.t1657` (Financial Theft), which the rule's rationale already cited.
- **Sigma5 (trycloudflare.com) demoted from `level: high` to `level: medium`** — Sigma cannot restrict a DNS-query selector to server-class hosts, so the rule fires identically on any developer/CI host using the same free tunnel service; the original level overstated confidence.
- **Suricata Rule 3 (mining-pool PCRE) split into 4 content-anchored rules**, eliminating a PCRE-only match with no `content` prefilter (a named anti-pattern). `xmrig.com` was dropped from the domain set — it is the legitimate XMRig project's own homepage, not a mining-pool destination, and its presence in the original list appears to be a data-quality error rather than an observed indicator.
- **Suricata Rule 4 (Hysteria bing.com SNI) rewritten** from raw byte-offset `content` matching (unlikely to match real, RFC-9001-encrypted QUIC Initial packets) to the `quic` protocol keyword with the `quic.sni` sticky buffer — the real `suricata -T` (8.0.5) engine rejected an initial `tls.sni` attempt, confirming Suricata exposes QUIC-derived fields via dedicated `quic.*` buffers rather than `tls.*`.
- **Suricata Rule 5 (Sliver JARM/IP) cut to the IOC feed.** The rule had no content, TLS, or JA3/JA4 anchor beyond the destination IP (`5.230.201.54`) — the `jarm` value appeared only in `metadata`, which Suricata does not evaluate as a match condition, not as an actual filter. Both the IP and the JARM fingerprint were already present in the IOC feed; the rule added no detection value beyond the feed entry and has been retired.

### Per-Case Operator-Specific Signatures — Deferred to Sub-Reports

This parent detection file covers campaign-wide and cross-cutting signatures. Four sub-reports with their own per-case detection files are downstream deliverables:

| Case | Deferred Coverage | Rationale |
|---|---|---|
| Case 1 (Russian Gemini) | `tralalarkefe.com` subdomain-specific rules, `check_keys.py` API key validation pattern, `quantum_patriot.py` disinformation detection, Quasar-class PowerShell agent chain signatures | Per-operator IOCs; the tralalarkefe.com domain appears as a corroborating anchor in the A2A C2 YARA rule but detailed subdomain enumeration and Quasar PS chain detonation signatures belong in the Case 1 sub-report |
| Case 2 (Turkish ARPA) | Instana JWT JTI `022a1b74` point-in-time block, ARPA platform TimescaleDB/Neo4j/Redis stack detection, Turkish-language insider-recruitment doc detection, `instana_local_collector.ps1` hash-based detection | The Sigma Instana rule covers the generic enumeration pattern; per-JWT and per-script specifics belong in Case 2 sub-report with coordinated IBM Instana vendor disclosure |
| Case 3 (Rovodev/Pandora) | Per-architecture Naku binary hash anchors (11 hashes), Matrix C2 Discord integration detection, `master_control.py`/`attack_engine.py` per-hash YARA, `stealth_agent.py` anti-VM evasion-specific signatures | The Pandora/Naku YARA rule covers the campaign-wide naming pattern; per-binary hashes and Matrix C2 Discord-specific detection belong in Case 3 sub-report |
| Case 9 (GHOST Kit) | Operator-A wallet-specific YARA (77.110.96.200 customer only), `min1.sh` dual-Telegram reporter token detection, Telegram C2 channel specific bot token IOC rules, `hyst.sh` Python framework per-hash | The case9-libpam-pull draft includes a wallet-specific rule preserved in the sub-report; this parent file covers the family-level signatures only |

### Case 7 and Case 8 — Capsule Cases with Thin Technical Artifacts

| Case | Gap | Evidence Available | What Would Enable Coverage |
|---|---|---|---|
| Case 7 (Weevely+frp+Claude) | Weevely PHP webshell behavioral Sigma, parent process analysis, PHP webshell pattern | Directory-listing observation only; no Weevely payload binary extracted | Weevely payload extraction and detonation; existing public webshell rules already cover Weevely generically — no new YARA contribution from this case alone |
| Case 8 (AI-Orchestrated Payment API Attack) | Specific payment API endpoint sequence signatures | 6-stage timeline preserved; LLM vendor unidentified; no operator infrastructure files extracted | Full API access log including intermediate response tokens and confirmation of which LLM API was used for orchestration; current evidence supports only the generic 60s correlation rule (Hunting-tier Sigma) |

### LLM-Vendor-Side Detection — Out of Defender Scope

The following threat behaviors involve LLM provider-side telemetry not available to defenders:

- **Stolen API key abuse detection** — Gemini API key theft and abuse (Case 1: 40+ stolen keys) is detectable only by Google through API usage anomaly monitoring. Defender scope: monitor for API key files in unexpected filesystem locations (YARA rule) and unusual server-host AI API egress (Sigma rule).
- **Prompt injection in AI agent sessions** — detection of malicious prompts injected into legitimate AI agent sessions requires LLM provider-side classification of prompt content.
- **AI-generated code at generation time** — the Hunting-tier YARA rule catches the output on disk; the generation event itself is visible only to the LLM provider's inference logs.
- **GHOST kit supply-chain OWNER bot monitoring** — the kit-author monitors every customer deployment via a hardcoded Telegram bot token. Detection requires Telegram API-side monitoring; the kit-author's GitHub account suspension disrupts the payload-distribution channel but the OWNER bot likely persists on a separate account.

### Behavioral Runtime Detection of LLM API Abuse — Requires Vendor Telemetry

- **Per-request prompt classification** — detecting whether an outbound API call to `generativelanguage.googleapis.com` contains a malicious red-team password prompt requires body inspection with content classification. DLP with LLM-query-body inspection is the closest defender-side analog.
- **Gemini CLI session recording** — the Russian operator's Gemini CLI session transcripts stored under `~/.gemini/` on the operator's server are recoverable during IR for full attack-timeline reconstruction, but are not detectable at runtime from defender infrastructure.

### Sliver Case 10 — Staging Phase, Feed-Only Coverage

Case 10's Sliver deployment was in a staging/learning phase at capture time (zero sessions, zero beacons — 60 practice recordings only). Production Sliver implant behavioral signatures could not be derived from staging artifacts alone. The prior draft's Suricata signature for this case matched only the destination IP (with the JARM fingerprint present in `metadata` but not evaluated as a filter); that signature added no detection value over the IOC feed entry and has been retired (see Retiering Fixes above) — Case 10 is presently feed-only coverage (`5.230.201.54`, JARM `3fd3fd20d0...`). A full Sliver implant YARA rule would require a captured implant PE from a production operation.

### Korean Operator Case 4 — Single Artifact, Limited Coverage

The Korean operator Case 4 smoking-gun artifact (`settings.local.json` with OpenClaw pre-authorization) is covered by the Hunting-tier Sigma rule in this file. Beyond this, the operator's broader toolchain (OpenClaw platform internals, port 18789 beacon, OpenClaw gateway traffic) was not deeply analyzed — only the Claude Code configuration artifact was extracted. A full Case 4 detection file would require OpenClaw binary reverse engineering and network traffic capture.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

