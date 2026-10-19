---
title: "Detection Rules — AI-Agent Framework Abuse Campaign (Multi-Actor, 2026-05-23)"
description: "Detection rules for multi-actor AI-agent framework abuse across 8 operators. Eight YARA, fourteen Sigma and eight Suricata rules for broad coverage."
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
| YARA | 6 | 2 | T1574.006, T1014, T1587, T1059.006, T1543.002, T1498, T1071.001 | 0 |
| Sigma | 6 documents (1 bundle) | 8 documents (1 bundle) | T1574.006, T1036.005, T1090.004, T1587, T1685, T1496.001, T1119, T1657 | 0 |
| Suricata | 1 | 4 | T1090.004, T1496.001, T1071.001, T1665 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting. Expect to review the hits.

**Highest-confidence anchors:**
- The GHOST kit's `libpam_cache.so` LD_PRELOAD rootkit: ELF structural validation (dynsym hook enumeration for `readdir`/`fopen`) combined with kit-standard hide-strings and camouflage paths; byte-identical across 2 customer deployments, 0/0 AV at discovery (YARA Detection).
- The Russian operator's A2A C2 protocol: the `X-Agent-Id` custom header paired with the `/api/v1/` URI prefix in the same HTTP request; an operator-bespoke combination not seen in legitimate server-management frameworks (Suricata Detection).

**Atomics routed to the IOC feed:** the Case 10 Sliver-derivative C2 IP (`5.230.201.54`) and its JARM fingerprint had no additional network discriminator beyond the bare IP match; both were already captured in [`ai-agent-frameworks-2026-05-23-iocs.json`](/ioc-feeds/ai-agent-frameworks-2026-05-23-iocs.json); the standalone Suricata signature has been retired in favor of the feed entry.

---

## Multi-Family Organization

This campaign spans 8 operator cases rather than distinct malware families, so rules are grouped by **theme/case** (bold labels) inside each tier, mirroring the original draft's thematic grouping: **Novel AI-Abuse TTPs** (cross-case), **GHOST Kit** (Case 9), **Campaign Infrastructure Artifacts** (Cases 1 to 3), and per-case network/hunting groupings. A rule covering behavior common to multiple cases carries a **Campaign-Level** label.

---

## YARA Rules

### Detection Rules

**Novel AI-Abuse TTPs**

#### LLM-Personalized Credential Mutation Script

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1110.003 (Password Spraying), T1059.006 (Python), T1552.001 (Credentials in Files)
**ATT&CK Note:** Novel TTP.
**Confidence:** HIGH
**Rationale:** First qualitative change in credential-mutation tradecraft since the hashcat-rules era (~2015). `russian-ai_sniper_brute.py` invokes Gemini 2.5 Flash with a red-team password analyst prompt to generate 20 per-target mutations from email+domain+last-known-password — the prompt fragments and operator output filenames are distinctive and require no single renameable literal alone.
**False Positives:** None known. *Logic fix (round 2, 2026-10-10):* the generic labels `Target User:` and `Target Domain:` ($p5, $p6) alone satisfied the first branch, so a file with just those two lines fired. They now count only beside one of the four distinctive prompt fragments ($p1 to $p4). The rule fires on any two of the four prompt fragments, on one prompt fragment with both labels, on one of the three operator output filenames together with a Gemini API string, or on one prompt fragment together with a Gemini API string and a WordPress login string; it does not require the LLM API call, the prompt and the "Output ONLY the 20 passwords" constraint together. No benign-corpus run was made, so "none known" means none observed, not none measured.
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
      modified = "2026-10-10"
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
         (2 of ($p1, $p2, $p3, $p4)) or
         (1 of ($p1, $p2, $p3, $p4) and $p5 and $p6) or
         (1 of ($f*) and 1 of ($a*)) or
         (1 of ($p1, $p2, $p3, $p4) and 1 of ($a*) and 1 of ($w*))
      )
}
```

**GHOST Kit + libpam_cache Rootkit (Case 9)**

#### libpam_cache LD_PRELOAD Rootkit Family Signature

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1564.001 (Hidden Files and Directories), T1027 (Obfuscated Files)
**Confidence:** HIGH
**Rationale:** Byte-identical across at least 2 customer deployments (77.110.96.200, 77.110.125.145); VT 0/0 at discovery. The rule requires ELF64 structural validation (dynsym enumeration confirming `readdir`/`fopen` are hooked) AND multiple kit-standard string buckets AND the string `LD_PRELOAD` AND the string `libpam_cache` — no single element carries the rule alone. No ELF type, constructor or file-name test is made: the two strings are searched in the file body.
**False Positives:** None known — the combination of an ELF64 file that defines `readdir` and `fopen` as dynamic-symbol functions, three of the four hide strings (`xmrig`, `lolMiner`, `khugepaged_`, `inotify_guard`), two of the three miner path strings, all three `/proc` net-hook strings, the string `LD_PRELOAD` and the string `libpam_cache` is not present in legitimate PAM caching modules or system libraries. No `elf.type`, file-name or constructor test is made.
**Blind Spots:** A full rebuild hooking different libc functions or dropping the PAM-style name would evade; the rule targets the on-disk `.so` (and saved memory dumps of it), not a memory-only injection.
**Validation:** Scan `libpam_cache.so` (hash below) — must match; a legitimate PAM module (e.g. `pam_unix.so`) must NOT fire.
**Deployment:** Endpoint AV/EDR file scans on Linux servers and scans of saved dumps (the `filesize < 100KB` condition does not match in a live process-memory scan), filesystem integrity monitoring on `/lib/security/`, auditd-augmented IR.

```yara
import "elf"

rule MAL_Linux_GHOST_LDPreload_Rootkit_Family {
   meta:
      description = "Detects the libpam_cache.so LD_PRELOAD userland rootkit shipped with the GHOST v5.1/v6.0 cryptojacker kit. Matches an ELF64 file under 100 KB that defines readdir and fopen as dynamic-symbol functions and holds the kit's miner-hiding strings, miner path strings and /proc net-hook strings, plus LD_PRELOAD and libpam_cache. The report describes the sample as also hooking readdir64 and fopen64 and calling unsetenv('LD_PRELOAD') in a constructor; the rule tests neither. Observed byte-identical across at least 2 customer deployments."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      modified = "2026-10-11"
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
**Deployment:** Filesystem scan on Linux servers, shell script artifact triage during IR, scanning of saved dumps that hold the script text. Live process-memory scanning does not match: the condition's `filesize` test is undefined there, so only files and saved dumps are scanned.

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
**Rationale:** The Turkish ARPA operator deploys five distinctively named systemd units and a self-branded string ("ARPA Korelasyon Motoru") found only on the operator's host. *Fix applied during retiering:* the original condition included a bare-OR path on the stolen victim JWT JTI value alone — a single-victim atomic that would never recur for a different ARPA deployment. That string has been removed from the rule (it remains in the IOC feed as a victim indicator); the rule now anchors only on the operator's own durable service names, branding, and ingestion endpoint. *Fix applied in T-0222:* the footer string `ARPA © 2026` no longer fires alone; it needs one unit name beside it, because an unrelated organisation named ARPA could carry that footer.
**False Positives:** None known — the five literal unit names (`arpa-instana-api`, `arpa-autolearn`, `arpa-continuous`, `arpa-daemon`, `arpa-parallel`, each with `.service`) and the branding string `ARPA Korelasyon Motoru` are operator-specific and not present in any legitimate observability platform configuration. The rule fires on any two unit names, on the branding string alone, or on one unit name beside the ingestion endpoint `/api/ingest/instana` or the footer `ARPA © 2026`; no `arpa-*.service` wildcard is tested, only these literals, and the footer string alone does not fire.
**Blind Spots:** A rebuild that drops the `ARPA Korelasyon Motoru` string and keeps fewer than two of the five unit names (and no unit name beside the endpoint or footer string) would evade; targets on-disk/installed-unit artifacts.
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
         $b1 or
         (1 of ($svc*) and ($e1 or $b2))
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
**ATT&CK Coverage:** T1059.006 (Python), T1071.001 (Web Protocols), T1132.001 (Standard Encoding)
**ATT&CK Note:** Novel TTP: operator-built, unauthenticated Python-stdlib C2.
**Confidence:** HIGH
**Rationale:** `c2_server.py` uses Python stdlib `BaseHTTPRequestHandler` with zero authentication across 5 endpoints, the operator banner "A2A C2 MULTI-AGENT CONSOLE", and an `X-Agent-ID` self-assertion header. *Fix applied during retiering:* the original condition let a bare match on either C2 domain (`c2.tralalarkefe.com` / `payloads.tralalarkefe.com` — both already in the IOC feed) trigger the rule alone; the domain-only path now requires co-occurrence with at least one API endpoint string. *Logic fix 2026-10-10:* the heading and rule name claim a Python-stdlib `BaseHTTPServer` implementation, but no branch tested for it (the operator banner alone fired). Every branch now also requires the `BaseHTTPRequestHandler` string, which the captured `c2_server.py` subclasses (see the Russian Gemini credential-mill report). This was not re-run against the captured file, which is not held on the workstation.
**False Positives:** None known — the "A2A C2 MULTI-AGENT CONSOLE" banner is operator-bespoke, and the combinations of `BaseHTTPRequestHandler` with the `/api/v1/` endpoint path strings and the `X-Agent-ID` header (or with the two decode strings) are not known to appear in legitimate server-management frameworks, but no goodware corpus was measured and the rule does not test that the endpoints are unauthenticated.
**Blind Spots:** A rebuild dropping the banner string and renaming all endpoints/header would evade; targets on-disk Python source, not a compiled/obfuscated variant.
**Validation:** Scan the captured `c2_server.py` — must match; unrelated Python HTTP servers must NOT fire.
**Deployment:** Filesystem scan on compromised servers, Python source artifact triage, scanning of saved dumps of Python processes. Live process-memory scanning does not match: the condition's `filesize` test is undefined there, so only files and saved dumps are scanned.

```yara
rule MAL_Python_Russian_A2A_C2_BaseHTTPServer {
   meta:
      description = "Detects the Russian Gemini operator's custom A2A (Agent-to-Agent) C2 backend built on Python stdlib BaseHTTPServer: the string BaseHTTPRequestHandler together with the banner A2A C2 MULTI-AGENT CONSOLE, or three of the five /api/v1/ endpoint paths with the X-Agent-ID header, or the decode strings decode('utf-16le') and base64.b64decode with two endpoint paths, or a C2 domain with one endpoint path. The report describes the sample as unauthenticated on all 5 endpoints, with a path-traversal-vulnerable file server and Cloudflare Tunnel transport; the rule tests none of that."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      modified = "2026-10-11"
      family = "Russian-A2A-C2"
      malware_type = "Custom-C2-Backend"
      campaign = "AI-Agent-Framework-Abuse-MultiActor-2026-05-23"
      id = "943da3bd-c273-5e48-829e-1ec1389fd48a"
   strings:
      $py1 = "BaseHTTPRequestHandler" ascii
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
      $py1 and
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
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python)
**ATT&CK Note:** Novel TTP: AI-generated code structural signature.
**Confidence:** MODERATE (each criterion alone is low-confidence; the combination is higher)
**Rationale:** Cross-operator validated across three independent operators' Python attack code (Case 1, Case 2, Case 3). The co-occurrence of verbose docstrings + bare-except or defensive try/except (the condition accepts either handler form, 2026-10-10 wording fix) + educational variable names + a rate-limiting marker (zero anti-analysis is observed in the cases but is not tested by the rule) is common in benign, actively-developed Python, so this is explicitly not suitable for automated alerting alone.
**False Positives:** Legitimate Python developers routinely write verbose docstrings and defensive error handling; the FP rate increases meaningfully in active development environments.
**Deployment:** Hunting/hypothesis generation on suspicious server hosts; combine with operator-adjacent artifact signals (credential files, C2 artifacts, scanning tools) before treating a hit as actionable.

```yara
rule SUSP_AI_Generated_Offensive_Code_Python {
   meta:
      description = "Detects Python offensive tools bearing the structural signature of AI-generated code: verbose docstrings co-occurring with a bare `except:` handler or a defensive `except Exception as e:` handler (either one satisfies the rule), educational variable names, a rate-limiting marker (time.sleep or rate_limit), and offensive-tool terms. The rule does not test for the absence of anti-analysis. Confirmed cross-operator across 3 independent actors (Case 1 Russian, Case 2 Turkish ARPA, Case 3 Rovodev)."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/"
      date = "2026-05-25"
      modified = "2026-10-10"
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

#### AI Operator Handoff Document

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1059.006 (Python)
**ATT&CK Note:** Novel TTP; no dedicated MITRE sub-technique exists for this specific behavior.
**Confidence:** MODERATE
**Rationale:** First-documented artifact class — operator-authored Markdown files written FOR AI agent consumption to re-prime new sessions (Case 1 Russian Gemini operator: `C2_MIGRATION_GUIDE.md`; Case 3 Rovodev operator: 22+ documents at `/root/matrix/`). *Fix applied during retiering:* the original condition let the bare domain string `tralalarkefe.com` ($i4) trigger the rule alone, an atomic-only path; it now requires the domain to co-occur with an AI-addressing header, session-priming directive, or infrastructure marker — the domain itself is already in the IOC feed. *Logic fix 2026-10-10:* `$h4` ("To: Claude") is a substring of `$h3` ("To: Claude Code"), so one "To: Claude Code" line satisfied the `2 of ($h*)` branch alone, which is the header-only match the Blind Spots below say is not covered. That branch now counts only distinct header forms (`$h1`, `$h2`, `$h3`, `$h5`, `$h6`, plus the Markdown-bold forms below); `$h4` still counts as a header in the branch that pairs a header with a directive. *Round 2 (2026-10-10):* the companion report quotes the exemplar header as `**To:** Gemini CLI` and `**From:** Gemini CLI` (Markdown bold, colon inside the bold), which the plain `To: Gemini CLI` strings do not match, so `$h1b` and `$h2b` were added for that form. The rule was re-tiered from Detection to Hunting: two header lines, or a header plus a directive, fire on benign AI-assisted documentation, and the report itself names operational content as the disambiguator.
**False Positives:** Legitimate AI-assisted project documentation. A file with `To: Gemini CLI` and `From: Gemini CLI` lines, or an AI-addressed header with a session-priming directive such as "read this file first", fires without any C2 or credential content (confirmed on a synthetic benign fixture, round 2, 2026-10-10). The companion report rates this artifact class MEDIUM false-positive risk and names operational content (C2 endpoint patterns, credential tables) as the disambiguator, which the condition does not test. Triage a hit by that content.
**Blind Spots:** An operator who stops using this exact heading/directive convention evades; single-criterion matches (header OR directive alone) are lower confidence and not covered here.
**Validation:** Scan a captured operator handoff document (e.g. `C2_MIGRATION_GUIDE.md`) — must match. A legitimate project README or runbook that carries an AI-addressed header and a session directive also matches; telling them apart takes the operational-content review above. Not run against the captured exemplars (not on this workstation).
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
      modified = "2026-10-10"
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
      $h1b = "**To:** Gemini CLI" ascii nocase
      $h2b = "**From:** Gemini CLI" ascii nocase
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
         (2 of ($h1, $h2, $h3, $h5, $h6, $h1b, $h2b)) or
         (1 of ($i1, $i2, $i3) and 1 of ($d*)) or
         ($i4 and (1 of ($h*) or 1 of ($d*) or 1 of ($i1, $i2, $i3)))
      )
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
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1036.005 (Match Legitimate Resource Name or Location)
**ATT&CK Note:** T1036.005 replaces the earlier T1027 line, which carried no tag: the PAM-style name is masquerading, not obfuscation.
**Confidence:** HIGH
**Rationale:** Requires the PAM-style path AND the `libpam_cache` name component together — no legitimate distro ships a module by that name. *Fixes applied during retiering:* added the missing `attack.t1574.006` technique tag plus the `attack.execution` tactic tag `sigma check` requires alongside it, and converted the `selection_name` single-item list to a scalar (`sigma check`'s single-value-list rule).
**False Positives:** Legitimate distro packages installing PAM modules — verify parent process is `apt`/`dpkg`/`rpm`/`yum` and not a shell or unknown binary.
**Blind Spots:** A rebuild renaming the rootkit away from the `libpam_cache` convention evades; the rule targets the write event, not post-load hiding.
**Validation:** Trigger the rootkit drop step — must match; a genuine distro PAM-module package install must NOT fire (parent process check).
**Deployment:** Sysmon for Linux file-creation events or an EDR file-event feed that supplies the full path as `TargetFilename`, plus file integrity monitoring on `/lib/security/`. Raw auditd `-w` watch records carry PATH items rather than a `TargetFilename` and would need normalising to a full-path field first; this page declares no such normalisation.

```yaml
title: Cryptojacker LD_PRELOAD Rootkit Drop to /lib/security (PAM-Style Camouflage Naming)
id: 6c7e9d33-7dc3-411b-994f-37d431e05907
status: experimental
description: >-
  Detects a Linux file event whose path contains one of the PAM module directories
  (/lib/security/, /usr/lib/security/ or their x86_64-linux-gnu variants) and the string
  libpam_cache, the GHOST cryptojacker kit's deceptive PAM-style name. The rule tests
  two path substrings only: no .so extension, no test that libpam_cache starts the file
  name, and any file event on the path (create or write) counts.
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
    - attack.t1036.005
    - detection.emerging-threats
    - stp.3
logsource:
    product: linux
    category: file_event
    definition: 'Requires Linux file events that carry the full path in TargetFilename, for example Sysmon for Linux file creation or an EDR file-event feed. Raw auditd watch records need normalising to a full-path field first.'
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
**Rationale:** "PerformanceMonitor" is not present in any legitimate ComfyUI custom node package; the display name "GPU Performance Monitor" plus installation from the kit-author's now-suspended GitHub repos is distinctly malicious. *Tag fix applied during retiering:* added the missing `attack.t1496.001` technique tag. *Description fix 2026-10-10:* the description also claimed process-creation detection of the pip install, but the logsource is `file_event` and both selections test `TargetFilename`; the description now says file creation only.
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
    pip from the kit-author's GitHub repos. Detection is by file creation only: a file under
    ComfyUI's custom_nodes directory matching the PerformanceMonitor or kit-author node
    names, or a created file whose path contains a kit-author repo name. The rule does not
    inspect process creation, so a pip command line is not matched.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
modified: '2026-10-10'
tags:
    - attack.persistence
    - attack.impact
    - attack.t1496.001
    - detection.emerging-threats
    - stp.3
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

#### Cloudflared Access TCP Tunnel Registration

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1021.001 (RDP), T1021.004 (SSH)
**Confidence:** HIGH
**Rationale:** The exact combination of the `cloudflared` binary with `access`, `tcp`, and `--hostname` flags is a specific, narrow command pattern rarely used outside a formally managed Cloudflare Zero Trust deployment; the Russian operator (Case 1) used it to maintain persistent RDP/SSH access to a US healthcare victim. *Tag fix applied during retiering:* added the missing `attack.t1090.004` technique tag. *Title fix 2026-10-10:* the title said "to Non-Allowlisted Hostname", but the rule has no hostname allowlist and matches any `cloudflared access tcp --hostname` invocation; the title now says that, and the allowlist stays a local tuning step.
**False Positives:** Legitimate Cloudflare Zero Trust TCP application proxies configured by network administrators — allowlist known deployment hostnames.
**Blind Spots:** Legitimate enterprise Zero Trust deployments using this exact command are a real, if allowlist-manageable, population; the rule does not itself enforce a hostname allowlist (Sigma has no environment-aware NOT-IN-list mechanism).
**Validation:** Trigger a `cloudflared access tcp --hostname <host> --url localhost:<port>` command — must match; a plain `cloudflared tunnel run` (no `access tcp`) must NOT fire.
**Deployment:** Sysmon process creation, auditd execve, Linux endpoint agent.

```yaml
title: Cloudflared Access TCP Tunnel Registration
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
modified: '2026-10-10'
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.t1090.004
    - detection.emerging-threats
    - stp.3
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

#### Instana API Enumeration Script via -SkipCertificateCheck to an ocpinstana Endpoint (ARPA Observability Harvester, Case 2)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1119 (Automated Collection), T1530 (Data from Cloud Storage Object — MODERATE)
**Confidence:** HIGH (PowerShell Script Block Logging detection); MODERATE (network-side proxy detection)
**Rationale:** The specific combination of `-SkipCertificateCheck` with `ocpinstana` endpoint references in a PowerShell script block is characteristic of the Turkish ARPA operator's `instana_local_collector.ps1`. *Fixes applied during retiering:* removed a bare `apiToken` OR-path (an extremely common, generic variable/header name in legitimate API scripts that would have fired this HIGH-level rule on ordinary REST-API automation) and a literal, never-filled-in placeholder string `'[victim-tenant]'` that could never match real telemetry. The stolen JWT JTI remains available in the IOC feed as a victim indicator rather than as a rule OR-path. *Title fix 2026-10-10:* the title claimed detection "via Stolen JWT from Non-Management-Platform Source", but the logic is two `ScriptBlockText` substrings with no token or source-host test; the title now describes those substrings.
**False Positives:** Legitimate Instana API clients that use `-SkipCertificateCheck` for internal OCP self-signed certificates — narrow by source host.
**Blind Spots:** A script avoiding `-SkipCertificateCheck` (e.g. using a properly-trusted cert) evades; PowerShell Script Block Logging must be enabled for this telemetry to exist at all.
**Validation:** Trigger a PowerShell script combining `-SkipCertificateCheck` and an `ocpinstana`-referencing endpoint — must match; an unrelated PowerShell script using `-SkipCertificateCheck` alone (e.g. against a different internal API) must NOT fire.
**Deployment:** PowerShell Script Block Logging (Event 4104) on Windows hosts where the collector runs.

```yaml
title: >-
    Instana API Enumeration Script via -SkipCertificateCheck to an Ocpinstana
    Endpoint (ARPA Observability Harvester)
id: f9c5ebeb-d6b8-4425-bb85-bfa4d30e28ac
status: experimental
description: >-
    Detects PowerShell execution of Instana API enumeration scripts using the -SkipCertificateCheck
    flag alongside references to the ocpinstana endpoint pattern, characteristic of the
    Turkish ARPA operator's instana_local_collector.ps1 script. The script makes sliding
    10-minute-window GET /api/events requests with a stolen 10-year Instana JWT to
    exfiltrate observability telemetry to the attacker's ARPA platform. Detection from
    PowerShell Script Block Logging is highly reliable when -SkipCertificateCheck appears
    alongside Instana endpoint strings. The rule matches those two strings in the script block
    text; it does not inspect the JWT or the source host.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
modified: '2026-10-10'
tags:
    - attack.collection
    - attack.exfiltration
    - attack.t1119
    - detection.emerging-threats
    - stp.3
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

**Campaign-Level: AI-Tool + Offensive-Tool Co-Location (Correlation)**

#### AI Coding-Agent Tooling Co-Located with Offensive Tooling on the Same Host

**Tier:** Detection (correlation rule) — bundled below with its 2 required Hunting-grade base rules, which do not alert on their own
**Robustness:** 2 (correlation) / 1 (each base rule individually)
**ATT&CK Coverage:** T1587 (Develop Capabilities), T1588.002 (Obtain Capabilities: Tool)
**Confidence:** MODERATE — co-presence of AI tools and offensive tooling on a server host warrants investigation but is not conclusive by itself
**Rationale:** Neither base selector is meaningful alone — AI coding-agent execution and generic scanning/tunneling tool execution are both common on legitimate developer and security-research hosts. The temporal correlation (both signals on the *same host* within 24 hours) is what discriminated the real Case 7 (Weevely+frp+Claude) operator from two demoted false positives (a legitimate SaaS-security consultant and a HuggingFace researcher) where only one signal type was present. *Title fix 2026-10-10:* the two base rules were titled "on Server Host", but no selection tests host role (Sigma has no such field), so they now say "on a Linux Host"; scoping to server-class hosts is done in the SIEM correlation engine, as the Deployment line says. *Tag fixes applied during retiering:* added the missing technique-ID tags to all three rules (`attack.t1587` on both the AI-tool base and the correlation; `attack.t1588.002` on both the offensive-tool base and the correlation).
**False Positives:** The two base rules alone are extremely broad (any AI-coding-agent user; any admin running `nmap`/`masscan`). The correlation rule itself: "a host legitimately used both for AI-assisted development and authorized security testing" — narrower, but real in security-research environments.
**Blind Spots:** In Sigma semantics, an operator running AI-tool and offensive-tool sessions more than 24 hours apart, or split across separate hosts, evades the correlation. The `temporal` type is unordered, and `sigma convert -t eql -p sysmon` renders it as `sample by host.name` with no time bound, so on an Elastic EQL deployment the 24-hour window is not enforced and the two signals correlate across whatever interval the query searches. Lucene cannot convert a correlation at all, so there is no Lucene form of this set.
**Validation:** Replay both base selectors against the same `host.name` — the correlation must fire; a host showing only one signal type must NOT trigger the correlation. Whether events further apart than 24 hours also fire depends on the backend: a backend that implements `timespan` suppresses them, the EQL conversion does not.
**Deployment:** Endpoint agent filesystem/process scanning with host-role classification feeding a SIEM correlation engine (temporal join on `host.name`; 24h in Sigma, unbounded in the EQL conversion).

```yaml
title: AI Coding-Agent Binary Execution on a Linux Host
id: 67cd7a66-7487-4bc2-94b5-2db9ffbf2080
name: ai_agent_tooling_exec_serverhost
status: experimental
description: >-
    Base rule (not alerting on its own): execution of an AI coding-agent binary
    from its state directory (Claude Code, Gemini CLI, RovoDev, OpenClaw) on a
    Linux host; the rule does not test whether the host is a server. Paired with the correlation rule below, which flags co-location
    with offensive tooling.
references:
    - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
modified: '2026-10-10'
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
title: Offensive Tooling Execution on a Linux Host
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
modified: '2026-10-10'
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
modified: '2026-10-10'
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
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** MODERATE — the rule's own description states this is a hunting lead, not an alert
**Rationale:** File-event telemetry cannot inspect file content, so a hit only means "this permissions file changed"; it cannot itself distinguish an operator pre-authorizing a curl-to-shell pattern from a routine, legitimate settings edit. *Tag fixes applied during retiering, verified against the real `sigma check` tool:* the original carried tactic-only tags with no technique; `attack.t1562.001` was tried first but the tool rejects it as invalid (MITRE renumbered Disable or Modify Tools to the top-level technique **T1685**, no longer a Defense Evasion sub-technique tree under T1685), and the tool then required the new ATT&CK v19 `attack.defense-impairment` (TA0112) tactic tag alongside it, which has been added. An unpaired `attack.execution` tactic tag (unsupported by the file-modification-only logic) was dropped. *FP remediation (2026-09-07):* the deployed selector also matched inside third-party npm packages' own vendored `node_modules` trees and a Docker container's overlay diff (observed: `es-abstract`, `selfsigned`), none of which Claude Code ever reads as a settings file, so a `filter_vendor` exclusion on `node_modules` was added. Measured over a 14-day window against the rule's own source index: 50 events matched before the fix, 47 after, removing exactly those 3 vendored-tree/overlay matches and nothing else, at zero coverage cost. The `claude` and `git` writers that account for the remaining volume are deliberately NOT excluded here: a `claude`-driven write to its own settings file is indistinguishable at the file-event layer from a malicious one, which is precisely the T1685 scenario this rule exists to catch, and `git` checking out or removing the tracked `settings.json` during routine worktree lifecycle is specific to how heavily one environment uses git worktrees, not a defect in the rule. Both are handled as local Kibana exceptions scoped by `file.path` to the git-tracked `settings.json` only, because that file's content is independently reviewable via `git diff`/`git log` regardless of whether this rule fires, while the untracked `settings.local.json` has no such backstop, so every subscriber's rule, and this environment's own coverage of that file, is unchanged. *FP remediation (2026-09-30, run `2026-09-30-0212`):* the selector used `contains`, which also matched sibling files Claude Code never reads as settings, namely the atomic-save temporaries `settings.json.tmp.<pid>.<hex>`, `.bak*` copies and `.pre-*` copies. Any install produces the temporaries on every atomic save, so this fires in any environment. The two entries now use `endswith`. Measured on the rule's own source index (size 1000, control at the cap): over 30 days 122 matching events before and 92 after, over 14 days 66 before and 52 after, and all 30 removed events over 30 days were sibling files. The index holds 18 claude `settings.json.tmp.*` creations and 16 renames onto the real path. 16 of the 18 measured tmp creations were followed by a rename onto the real path, which still alerts. The other 2 (09-05 `...388086.88bc1ecf1413` and 09-26 `...2443957.4e4baacd47cc`) left no recorded rename and no recorded deletion, so they were either aborted writes or events Defend lost, and that is undetermined. Under the new rule those 2 produce no event. A tmp file Claude Code never reads is not itself a settings change, so the practical cost is limited to those unobserved writes, but it is not zero. The `claude` binary is deliberately still NOT excluded at source, for the reason recorded above: a prompt-injected session editing its own permissions is the T1685 case this rule exists to catch, and that matches the 2026-09-07 decision.
**False Positives:** Routine or legitimate edits to Claude Code settings are common; review the added permission entries after the alert fires. Third-party npm packages occasionally ship a fixture file at this path fragment inside their own `node_modules` tree (observed: `es-abstract`, `selfsigned`); these have no effect on Claude Code's real configuration and are excluded via `filter_vendor`. Sibling files such as `settings.json.tmp.<pid>.<hex>`, `.bak*` and `.pre-*` no longer match, because the selector anchors on the real filename with `endswith`.
**Deployment:** Linux file-event telemetry (file integrity monitoring, auditd, Sysmon for Linux) on developer and server hosts. The logsource is `product: linux`, so macOS hosts are not covered by this rule as written.

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
modified: '2026-09-30'
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
    TargetFilename|endswith:
      - /.claude/settings.local.json
      - /.claude/settings.json
  filter_vendor:
    TargetFilename|contains: /node_modules/
  condition: selection and not filter_vendor
falsepositives:
  - >-
    Routine or legitimate edits to Claude Code settings (common) — review the
    added permission entries. Investigate file content after alert — the
    curl-pipe-bash and npm-i-g-unfamiliar patterns are the high-confidence indicators
    within a triggered file modification.
  - >-
    Third-party npm packages occasionally ship a fixture file at a path fragment
    matching this rule (observed: es-abstract, selfsigned) inside their own
    node_modules tree. These have no effect on Claude Code's real configuration and
    are excluded.
level: medium
```

#### Linux DNS Query to the Gemini API or AI Studio Domain (Hunting Lead)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** None
**ATT&CK Note:** T1552.001 (Credentials in Files) was withdrawn: a DNS-query rule observes a lookup, not a credential file.
**Confidence:** MODERATE
**Rationale:** `generativelanguage.googleapis.com` is Google's own legitimate API domain — durable (attacker can't rotate it), but shared by an enormous population of legitimate AI applications, so precision fails the Detection bar without host-role classification. The earlier `attack.t1552.001` tag was removed because a DNS query observes no credential file.
**False Positives:** High on hosts running legitimate AI applications; low on general-purpose server hosts with no expected AI workload.
**Deployment:** Network proxy/firewall with host-role classification, DNS query monitoring. Hunting-only without host classification.

```yaml
title: Linux DNS Query to the Gemini API or AI Studio Domain (Hunting Lead)
id: 06d6f95f-2946-4bb9-b0ff-49921d91922f
status: experimental
description: >-
  Detects DNS queries from Linux hosts for generativelanguage.googleapis.com or
  aistudio.google.com. The rule has no host-role field and no view of what a query is
  for, so it fires on every Linux host that resolves either name and cannot show that a
  key was validated. Case 1 (Russian Gemini operator) uses stolen Gemini API keys
  validated via check_keys.py, and the same endpoint is used by the LLM-personalized
  credential mutation script to invoke Gemini 2.5 Flash for per-target password
  generation at attack time. A deployment that knows which hosts have an expected AI
  workload scopes those out locally.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
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

#### Linux File Event Under a .rovodev Directory (Atlassian Rovodev Agent Presence Lead)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** None
**ATT&CK Note:** T1587 (Develop Capabilities) was withdrawn: a directory path of a legitimate agent does not observe capability development.
**Confidence:** MODERATE — the `.rovodev/` directory alone could appear on any host where a developer legitimately uses Rovodev
**Rationale:** Signal strength increases significantly when co-located with offensive tooling or on non-developer server infrastructure, but the rule as written is a single directory-path selector with no such co-location check. *Fix applied during retiering:* converted the single-item `TargetFilename|contains` list to a scalar. The earlier `attack.t1587` tag was removed because the path observes no capability development.
**False Positives:** Medium on development hosts, low on production server infrastructure with no expected AI agent tooling.
**Deployment:** Sysmon for Linux file events or an EDR file-event feed that supplies the full path as `TargetFilename`; file integrity monitoring and an endpoint agent filesystem scan can supply the same lead. Raw auditd directory watches would need normalising to a full-path field first; this page declares no such normalisation.

```yaml
title: Linux File Event Under a .rovodev Directory (Atlassian Rovodev Agent Presence Lead)
id: c88a8604-f07b-452b-821e-ecd610edd062
status: experimental
description: >-
  Detects any Linux file event whose path contains /.rovodev/, the directory where the
  Atlassian Rovodev AI coding agent keeps its state. The rule tests the path substring
  only: no directory-creation event, no home-directory anchor and no host role. While
  Rovodev is a legitimate enterprise product, its presence on server infrastructure co-located with offensive
  tooling indicates an AI-integrated threat operator. Case 3 (Rovodev/Pandora operator)
  had ~/.rovodev/sessions/ containing 1.24 MB AI-authoring session JSONs.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
tags:
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

**Campaign-Level: Operator Infrastructure Egress**

#### Trycloudflare.com Quick-Tunnel DNS Query

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**Rationale:** The `*.trycloudflare.com` suffix keys on Cloudflare's ephemeral-tunnel *service* rather than a rotatable attacker-owned domain, so it survives subdomain rotation — but it is also Cloudflare's genuinely free, widely-used developer tunnel product, so a meaningful legitimate population exists. *Retiered from Detection to Hunting during this pass:* the original `level: high` overstated confidence — Sigma has no host-role field to restrict this selector to server-class hosts, so as written it fires identically on any developer or CI host using the same free service; demoted to `level: medium`. Tag fix: added the missing `attack.t1090.004` technique tag. *Title fix 2026-10-10:* the title still said "from Non-Developer Server Host" and the description claimed process-creation coverage; the logic is one `dns_query` selection, so both now say DNS query on any Linux host.
**False Positives:** Developers and CI/CD pipelines using Cloudflare Tunnel for local development exposure (ngrok-alternative use case) — exempt known developer/CI hosts by hostname or subnet.
**Deployment:** Linux DNS query telemetry (`dns_query`) only. The selector is `query|endswith: .trycloudflare.com`, so it matches queries for subdomains (the quick-tunnel names) and not a query for the bare apex name; it does not read proxy or firewall logs and does not inspect process creation or `cloudflared` execution.

```yaml
title: Trycloudflare.com Quick-Tunnel DNS Query
id: 5581299d-e9a1-4a83-b85c-8d68a93fd03b
status: experimental
description: >-
  Detects DNS queries for trycloudflare.com ephemeral tunnels from any Linux host (the rule has no host-role or developer-host test, and does not inspect process creation).
  Threat actors (Case 1 Russian Gemini operator) use Cloudflare quick-tunnels to proxy
  C2 traffic through Cloudflare infrastructure, disguising the true C2 IP and bypassing
  egress firewall rules. Trycloudflare subdomains are ephemeral and randomly generated
  (e.g. tenant-upcoming-great-descending.trycloudflare.com) — not predictable by defenders.
references:
  - https://the-hunters-ledger.com/reports/ai-agent-frameworks-2026-05-23/
author: The Hunters Ledger
date: '2026-05-25'
modified: '2026-10-10'
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

#### Egress to Operator-Hosting ASN Ranges from a Linux Host (Baseline Pivot)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1583.003 (Virtual Private Server)
**Confidence:** LOW — ASN-based egress rules have inherently high FP rates in cloud-connected environments
**Rationale:** All five operator-controlled servers in this campaign are hosted on AEZA, Contabo, DigitalOcean, 1&1 IONOS, and Korea Telecom; the rule's own title already flags it as a hunting baseline, not an alert. *Tag fix applied during retiering:* added the missing `attack.t1583.003` technique tag.

*Scope reviewed against live telemetry 2026-08-06 and deliberately left at all five ranges.* A 14-day measurement was expected to show the two mainstream-hosting ranges (DigitalOcean `209.38.0.0/16`, 1&1 IONOS `87.106.0.0/16`) generating most of the volume, which would have justified dropping them. The measurement showed the opposite. Across 2,371 matching events, every one came from a single internet-scanning process on one host, and the two mainstream ranges accounted for 207 of them, under 9 percent. Contabo (1,067) and AEZA (1,089) carried the volume, and those are precisely the ranges worth keeping. Removing the mainstream ranges would therefore have surrendered the Case 2 and Case 3 infrastructure coverage while barely moving the noise floor. Where a deployment sees high volume from this rule, identify the source process first: a host that scans or crawls the internet will match all five ranges by design, and that is an exclusion to write locally, not a reason to narrow a published rule.
**False Positives:** High in environments with significant cloud/CDN traffic — CDN egress, legitimate cloud API traffic, and third-party service integrations routinely originate from these ASNs. Any host performing internet-wide scanning or crawling will match continuously; scope such hosts out locally by source process rather than narrowing the ranges.
**Deployment:** Linux endpoint network-connection telemetry that records the destination address (the rule's `network_connection` logsource); firewall or flow logs can ask the same address question but carry no process attribution, which the Rationale's source-process triage needs. Hunting only; do not configure as an automated alert.

```yaml
title: Egress to AEZA/Contabo/DigitalOcean-SG/IONOS/Korea-Telecom Address Ranges from a Linux Host (Hunting)
id: bb917d1e-bb95-48d2-bb19-505cd6655456
status: experimental
description: >-
  Hunting rule flagging outbound connections from any Linux host to IP ranges
  associated with the campaign's operator-hosting ASNs (the selection has no source-host
  or host-role filter, so limiting it to production servers is a deployment scoping
  decision, not a test in the rule): AEZA International Group (Case 1
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

**Case 8: AI-Orchestrated Payment API Attack**

#### Web Request to API, Auth, Payment or Transaction URI Path (Machine-Speed Sequence Building Block)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1657 (Financial Theft)
**Confidence:** LOW — the 60-second window and API sequence correlate with the observed case but the underlying LLM vendor is unidentified
**Rationale:** The rule is explicitly a selection-only building block for a SIEM correlation search (4+ distinct API endpoints from one source IP within 60 seconds) — the URI-substring selector alone matches enormous volumes of ordinary web traffic on any API-driven site. *Tags replaced during retiering:* the original `attack.credential-access` + `attack.exfiltration` tactic tags had no matching technique-ID tag and don't cleanly correspond to a generic `/api/`, `/auth/`, `/payment/`, `/transaction/` URI-substring selector; replaced with `attack.impact` + `attack.t1657` (Financial Theft), the technique already named in the rule's own evidence.
**False Positives:** High — automated payment processing systems, health checks, and load-balancer probes generate similar API call sequences.
**Deployment:** SIEM correlation with payment/authentication API access logs ingested, minimum 30-day baseline required to establish normal API call velocity per source IP.

```yaml
title: Web Request to API, Auth, Payment or Transaction URI Path (Machine-Speed Sequence Building Block)
id: f8fbdc2e-b653-4b9c-b56d-2c004c202ea5
status: experimental
description: >-
  Flags individual web requests whose URI stem contains /api/, /auth/, /payment/ or
  /transaction/, the kind of endpoints touched in the stages of a machine-speed,
  multi-stage API attack tied to LLM-orchestrated attack tooling. Case 8 documented a
  6-stage payment API exploitation completed in under 60 seconds. The rule tests no
  count, window or sequence: operationalizing the 60-second/4+-endpoint velocity
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

**Case 1: Russian A2A C2**

#### A2A C2 X-Agent-Id Header + API Endpoint Pattern

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding — encoding layer, not itself matched)
**Confidence:** HIGH
**Rationale:** Requires the POST method, the `/api/v1/` URI prefix (anchored at the start of the URI with `startswith`; a URI that carries `/api/v1/` further along, such as `/proxy/api/v1/x`, no longer matches), and the `X-Agent-Id` custom header name in the same request — an operator-bespoke combination not present in legitimate server-management frameworks. An attacker would need to change the URI convention AND the header name simultaneously to evade.
**False Positives:** None known — `X-Agent-Id` is not a standard or common custom header name; `/api/v1/` alone is generic but is never the sole anchor in this rule.
**Blind Spots:** Evaded by a protocol rewrite dropping the `X-Agent-Id` header or the `/api/v1/` URI convention; does not cover the Cloudflare-Tunnel-fronted variant of this same channel once the tunnel terminates the visible HTTP layer.
**Validation:** Replay a captured A2A C2 HTTP POST request — must alert; an unrelated API request using a generic `/api/v1/` path without the `X-Agent-Id` header must NOT fire.
**Deployment:** Network IDS/IPS on server-segment egress, HTTP-capable IDS with header inspection.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT AI-Agent-Campaign Russian A2A C2 X-Agent-Id Header + API Endpoint (Case 1 C2 Protocol Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/v1/"; startswith; http.header_names; content:"X-Agent-Id"; nocase; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; threshold:type limit,track by_src,count 3,seconds 3600; sid:9200007; rev:3; metadata:author The_Hunters_Ledger, date 2026-05-25;)
```

### Hunting Rules

**Campaign-Level: Operator Infrastructure Egress**

#### trycloudflare.com DNS Query Egress

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1583.006 (Web Services — Cloudflare Tunnel), T1090.004 (Domain Fronting)
**Confidence:** MODERATE
**Rationale:** Keys on Cloudflare's ephemeral-tunnel service suffix rather than an attacker-rotatable literal, so it survives subdomain rotation — but the same free service is widely used by legitimate developers and CI/CD pipelines. *Title fix 2026-10-10:* the heading and `msg` said "from Server Hosts", but a Suricata rule on `$HOME_NET` cannot tell a server from a workstation; both now describe the DNS query only, and server scope comes from where the sensor sits (see Deployment). `rev` 2 to 3.
**False Positives:** Developer and CI/CD hosts legitimately using `trycloudflare.com` for temporary exposure of local services.
**Deployment:** Network IDS/IPS on server-segment egress, DNS monitoring.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign trycloudflare.com Quick-Tunnel DNS Query (C2 Transport Indicator)"; dns_query; content:"trycloudflare.com"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200000; rev:3; metadata:author The_Hunters_Ledger, date 2026-05-25;)
```

**GHOST Kit + libpam_cache Rootkit (Case 9)**

#### Kryptex Mining Pool DNS Query (Any kryptex.network Subdomain)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1496.001 (Compute Hijacking)
**Confidence:** MODERATE
**Rationale:** `kryptex.network` is a third-party mining-pool domain the GHOST kit operator does not control — durable in that rotating the operator's own infrastructure does not change it — but a domain match with no other discriminator is kept at Hunting for consistency with this file's other DNS-only signatures. *Fix applied during retiering:* added a `threshold` clause (absent from the original) to cap alert volume from a persistently-beaconing miner.
**False Positives:** The rule matches any subdomain of `kryptex.network` (a query for `cfx.kryptex.network`, `etc.kryptex.network` or `www.kryptex.network` all fire; the bare apex and look-alikes such as `notkryptex.network` do not). Any legitimate, consented use of the Kryptex platform (a real consumer mining service) from a corporate network would also match — uncommon outside a strict acceptable-use environment.
**Deployment:** Network IDS/IPS, DNS monitoring, threat hunting on all server-class hosts.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign Kryptex Mining Pool DNS Query (Any kryptex.network Subdomain, Includes cfx. and etc. Pool Hosts)"; dns_query; content:".kryptex.network"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200001; rev:3; metadata:author The_Hunters_Ledger, date 2026-05-25;)
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
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign c3pool.org Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"c3pool.org"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200002; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign nanopool.org Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"nanopool.org"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200003; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign moneroocean.stream Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"moneroocean.stream"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200004; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25;)
alert dns $HOME_NET any -> any any (msg:"THL HUNT AI-Agent-Campaign hashvault.pro Mining Pool DNS Query (Cryptojacker Activity)"; dns_query; content:"hashvault.pro"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200005; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25;)
```

#### QUIC SNI Containing bing.com on UDP 14433/14444 (Hysteria v2 Masquerade Lead, Case 9)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1090.004 (Domain Fronting), T1665 (Hide Infrastructure)
**Confidence:** MODERATE
**Rationale:** SNI masquerade (presenting `bing.com` while tunneling GHOST kit backdoor traffic over Hysteria v2/QUIC) is a durable evasion *technique*, but the specific masquerade domain choice is trivially changed in a future build. *Fixes applied during retiering:* the original rule matched the SNI via raw byte-offset `content` on the QUIC packet (`content:"|00 00|"; offset:0; content:"bing.com"; content:"|00 01|"`) with no sticky buffer at all. QUIC Initial packets are encrypted per RFC 9001, so a literal ASCII "bing.com" match at a fixed byte offset is unlikely to fire against real traffic as intended. First rewritten to the `tls.sni` sticky buffer, but the real `suricata -T` engine (8.0.5) rejected that combination; Suricata exposes QUIC-derived fields through their own dedicated `quic.*` buffers rather than reusing `tls.*`, so the rule now uses `quic.sni` — confirmed passing against the live engine.
**False Positives:** Low as of rev 2. Previously Medium, and in practice worse than that: with no destination constraint the rule matched every legitimate `bing.com` QUIC connection.
**Deployment:** Network IDS with QUIC/TLS inspection enabled (`app-layer.protocols.quic.enabled: yes`). Confirm the QUIC parser probes non-standard UDP ports on your build, since the destination constraint below is off-443.

**FP remediation note (2026-08-20):** the rule's `msg` promised a "Non-Microsoft Destination" and the rule implemented no destination test whatsoever, matching `-> any any` on the SNI string alone. Every routine Bing, Edge, Windows Search and Copilot QUIC connection matched it, in any environment. Production confirmed this: 71 alerts across five ordinary internal clients, every one of them to port 443 against CDN infrastructure, none on the operator ports.

The gap was documented before it shipped (the False Positives line above already named the missing destination allowlist), and the original analyst finding specified the correct construction from the start, as "Hysteria v2 protocol detection on UDP 14433/14444 with TLS SNI bing.com (combined-condition rule)". The port half of that combined condition was never implemented, neither at authoring nor during the later `tls.sni` to `quic.sni` rewrite. Rev 2 implements it. Measured 71 to 0.

The anchor is the GHOST kit's own Hysteria listener ports rather than a negated Microsoft range, for two reasons. Microsoft's ranges rotate, so a hardcoded snapshot decays in both directions at once. And a subscriber-populated Suricata address variable is worse than it appears: an undefined address-group variable is a load error, not a silent no-op, which would turn "too broad" into "does not load for most subscribers". The port pair is grounded in the investigation itself: `hyst.sh` hardcodes it, the kit's LD_PRELOAD rootkit hides the same pair, and two separate customer deployments differ only in a config block that does not include the port settings, so it is a kit-template default rather than a per-operator value.

Coverage cost, stated plainly: a Hysteria masquerade on any other port is now missed, and publishing the port pair in a rule invites the operator to move off it. Only a genuine Hysteria handshake fingerprint would survive a port change, and none was captured in the investigation, so none is asserted here.

**Tier deliberately unchanged at Hunting / Robustness 1.** The combined condition is a real improvement in precision and would ordinarily support a promotion, but durability is genuinely contested and the tiering framework ranks durability above as-written precision. The case for a promotion is that `hyst.sh` hardcodes this port pair, the kit's own rootkit hides the same pair, and two separate customer deployments ship identical port configuration, which reads as a kit-template default. The case against is that the same port pair is described in the GHOST cryptojacker file (rule `9100103`) as "this operator's specific configuration choice, not a kit-wide structural constant". Both readings come from the same evidence and cannot both be right.

Until that is resolved against a live capture, a promotion would rest on a paper clearance: no Hysteria connection was ever observed to validate the rule against, and the masquerade domain is separately acknowledged above as trivially changed. Hunting is the honest tier for a rule that has never fired on the thing it detects.

```
alert quic $HOME_NET any -> any [14433,14444] (msg:"THL HUNT AI-Agent-Campaign QUIC SNI Containing bing.com on GHOST Kit Operator Ports 14433 and 14444 (Hysteria v2 Masquerade Lead)"; flow:to_server; quic.sni; content:"bing.com"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/ai-agent-frameworks-2026-05-23-detections/; classtype:trojan-activity; sid:9200006; rev:4; metadata:author The_Hunters_Ledger, date 2026-05-25, modified 2026-08-20;)
```

---

## Coverage Gaps

### Retiering Fixes Applied (2026-07-13 Backfill)

This file was re-scored against the project's four-gate Detection/Hunting/Cut rubric. Beyond re-tiering, the following defects were corrected: each was either an atomic-only trigger path masquerading as a durable signature, a missing/invalid Sigma tag, or a technically unsound network match:

- **YARA bare-literal OR-paths removed (4 rules).** The AI Operator Handoff Document, ARPA Observability Harvester, Pandora/Naku Suite, and Russian A2A C2 rules each originally let one hardcoded, atomic value (a domain, a victim-specific JWT JTI, or two distribution IPs) trigger the whole rule alone via a bare OR branch. Each has been tightened to require the atomic to co-occur with a genuine behavioral/structural indicator; every underlying value was already present in the IOC feed, so no feed edits were required.
- **Sigma missing technique-ID tags (12 of 12 rule-headings).** Every Sigma rule in the original file carried tactic tags only, with no matching `attack.tXXXX` technique tag, a SigmaHQ validation failure. Each rule now carries at least one technique tag drawn from its own documented ATT&CK Coverage evidence, verified against the real `sigma check` tool rather than assumed: the tool required an added `attack.execution` tactic tag alongside `attack.t1574.006` on the two LD_PRELOAD rules; rejected `attack.t1562.001` outright as invalid (MITRE renumbered Impair Defenses to the top-level **T1685**); and then required the new ATT&CK v19 `attack.defense-impairment` (TA0112) tactic tag alongside `attack.t1685` on the settings.local.json rule. All three rounds of feedback came from the tool, not guesswork; `sigma check` returns 0 errors and 0 issues on the final file.
- **Sigma8 (Instana enumeration) broken selector removed.** The original `selection_token` block included a literal, never-filled-in placeholder string `'[victim-tenant]'` (non-functional; it could never match real telemetry) and a bare `apiToken` OR-path (a generic term common in legitimate API scripts, which would have fired this HIGH-level rule broadly). Both were removed; the rule now anchors solely on the `-SkipCertificateCheck` + `ocpinstana` combination.
- **Sigma3 and Sigma9 single-value lists converted to scalars**, per SigmaHQ's list-of-one convention.
- **Sigma11 tags replaced**, not merely supplemented; the original tactic tags didn't correspond to any technique the rule's own evidence named; replaced with `attack.impact` + `attack.t1657` (Financial Theft), which the rule's rationale already cited.
- **Sigma5 (trycloudflare.com) demoted from `level: high` to `level: medium`**: Sigma cannot restrict a DNS-query selector to server-class hosts, so the rule fires identically on any developer/CI host using the same free tunnel service; the original level overstated confidence.
- **Suricata Rule 3 (mining-pool PCRE) split into 4 content-anchored rules**, eliminating a PCRE-only match with no `content` prefilter (a named anti-pattern). `xmrig.com` was dropped from the domain set; it is the legitimate XMRig project's own homepage, not a mining-pool destination, and its presence in the original list appears to be a data-quality error rather than an observed indicator.
- **Suricata Rule 4 (Hysteria bing.com SNI) rewritten** from raw byte-offset `content` matching (unlikely to match real, RFC-9001-encrypted QUIC Initial packets) to the `quic` protocol keyword with the `quic.sni` sticky buffer; the real `suricata -T` (8.0.5) engine rejected an initial `tls.sni` attempt, confirming Suricata exposes QUIC-derived fields via dedicated `quic.*` buffers rather than `tls.*`.
- **Suricata Rule 5 (Sliver JARM/IP) cut to the IOC feed.** The rule had no content, TLS, or JA3/JA4 anchor beyond the destination IP (`5.230.201.54`); the `jarm` value appeared only in `metadata`, which Suricata does not evaluate as a match condition, not as an actual filter. Both the IP and the JARM fingerprint were already present in the IOC feed; the rule added no detection value beyond the feed entry and has been retired.

### Per-Case Operator-Specific Signatures: Deferred to Sub-Reports

This parent detection file covers campaign-wide and cross-cutting signatures. Four sub-reports with their own per-case detection files are downstream deliverables:

| Case | Deferred Coverage | Rationale |
|---|---|---|
| Case 1 (Russian Gemini) | `tralalarkefe.com` subdomain-specific rules, `check_keys.py` API key validation pattern, `quantum_patriot.py` disinformation detection, Quasar-class PowerShell agent chain signatures | Per-operator IOCs; the tralalarkefe.com domain appears as a corroborating anchor in the A2A C2 YARA rule but detailed subdomain enumeration and Quasar PS chain detonation signatures belong in the Case 1 sub-report |
| Case 2 (Turkish ARPA) | Instana JWT JTI (withheld) point-in-time block, ARPA platform TimescaleDB/Neo4j/Redis stack detection, Turkish-language insider-recruitment doc detection, `instana_local_collector.ps1` hash-based detection | The Sigma Instana rule covers the generic enumeration pattern; per-JWT and per-script specifics belong in Case 2 sub-report with coordinated IBM Instana vendor disclosure |
| Case 3 (Rovodev/Pandora) | Per-architecture Naku binary hash anchors (11 hashes), Matrix C2 Discord integration detection, `master_control.py`/`attack_engine.py` per-hash YARA, `stealth_agent.py` anti-VM evasion-specific signatures | The Pandora/Naku YARA rule covers the campaign-wide naming pattern; per-binary hashes and Matrix C2 Discord-specific detection belong in Case 3 sub-report |
| Case 9 (GHOST Kit) | Operator-A wallet-specific YARA (77.110.96.200 customer only), `min1.sh` dual-Telegram reporter token detection, Telegram C2 channel specific bot token IOC rules, `hyst.sh` Python framework per-hash | The case9-libpam-pull draft includes a wallet-specific rule preserved in the sub-report; this parent file covers the family-level signatures only |

### Case 7 and Case 8: Capsule Cases with Thin Technical Artifacts

| Case | Gap | Evidence Available | What Would Enable Coverage |
|---|---|---|---|
| Case 7 (Weevely+frp+Claude) | Weevely PHP webshell behavioral Sigma, parent process analysis, PHP webshell pattern | Directory-listing observation only; no Weevely payload binary extracted | Weevely payload extraction and detonation; existing public webshell rules already cover Weevely generically — no new YARA contribution from this case alone |
| Case 8 (AI-Orchestrated Payment API Attack) | Specific payment API endpoint sequence signatures | 6-stage timeline preserved; LLM vendor unidentified; no operator infrastructure files extracted | Full API access log including intermediate response tokens and confirmation of which LLM API was used for orchestration; current evidence supports only the generic 60s correlation rule (Hunting-tier Sigma) |

### LLM-Vendor-Side Detection: Out of Defender Scope

The following threat behaviors involve LLM provider-side telemetry not available to defenders:

- **Stolen API key abuse detection**: Gemini API key theft and abuse (Case 1: 40+ stolen keys) is detectable only by Google through API usage anomaly monitoring. Defender scope: monitor for API key files in unexpected filesystem locations (YARA rule) and unusual server-host AI API egress (Sigma rule).
- **Prompt injection in AI agent sessions**: detection of malicious prompts injected into legitimate AI agent sessions requires LLM provider-side classification of prompt content.
- **AI-generated code at generation time**: the Hunting-tier YARA rule catches the output on disk; the generation event itself is visible only to the LLM provider's inference logs.
- **GHOST kit supply-chain OWNER bot monitoring**: the kit-author monitors every customer deployment via a hardcoded Telegram bot token. Detection requires Telegram API-side monitoring; the kit-author's GitHub account suspension disrupts the payload-distribution channel but the OWNER bot likely persists on a separate account.

### Behavioral Runtime Detection of LLM API Abuse: Requires Vendor Telemetry

- **Per-request prompt classification**: detecting whether an outbound API call to `generativelanguage.googleapis.com` contains a malicious red-team password prompt requires body inspection with content classification. DLP with LLM-query-body inspection is the closest defender-side analog.
- **Gemini CLI session recording**: the Russian operator's Gemini CLI session transcripts stored under `~/.gemini/` on the operator's server are recoverable during IR for full attack-timeline reconstruction, but are not detectable at runtime from defender infrastructure.

### Sliver Case 10: Staging Phase, Feed-Only Coverage

Case 10's Sliver deployment was in a staging/learning phase at capture time (zero sessions, zero beacons, 60 practice recordings only). Production Sliver implant behavioral signatures could not be derived from staging artifacts alone. The prior draft's Suricata signature for this case matched only the destination IP (with the JARM fingerprint present in `metadata` but not evaluated as a filter); that signature added no detection value over the IOC feed entry and has been retired (see Retiering Fixes above); Case 10 is presently feed-only coverage (`5.230.201.54`, JARM `3fd3fd20d0...`). A full Sliver implant YARA rule would require a captured implant PE from a production operation.

### Korean Operator Case 4: Single Artifact, Limited Coverage

The Korean operator Case 4 smoking-gun artifact (`settings.local.json` with OpenClaw pre-authorization) is covered by the Hunting-tier Sigma rule in this file. Beyond this, the operator's broader toolchain (OpenClaw platform internals, port 18789 beacon, OpenClaw gateway traffic) was not deeply analyzed; only the Claude Code configuration artifact was extracted. A full Case 4 detection file would require OpenClaw binary reverse engineering and network traffic capture.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

