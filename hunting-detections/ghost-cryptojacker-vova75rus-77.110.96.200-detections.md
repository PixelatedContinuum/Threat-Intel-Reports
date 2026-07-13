---
title: "Detection Rules — GHOST Cryptojacker Kit Family (Vova75Rus / 77.110.96.200)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
thumbnail: /assets/images/cards/ghost-cryptojacker-vova75rus-77.110.96.200.png
hide: true
---

**Campaign:** GHOST-Cryptojacker-Vova75Rus-77.110.96.200
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/ghost-cryptojacker-vova75rus-77.110.96.200/

> **Sub-report context:** This is the GHOST-kit-specific detection file. GHOST Case 9 is sub-report 1 of the parent series `ai-agent-frameworks-2026-05-23`. The parent detection file (`ai-agent-frameworks-2026-05-23-detections.md`) covers cross-campaign rules for all five cases in that series. Rules here go **deeper on Case 9** only — do not duplicate parent-level general coverage.

---

## Calibration Notes

The following corrections from the investigation apply to detection rule derivation and should be understood before deploying these rules:

**T1556.003 mis-mapping retraction (Phase 7 → Phase 15 §23):** The initial Phase 7 session-start framing categorized `libpam_cache.so` as a PAM authentication backdoor (T1556.003 — Modify Authentication Process: PAM). Direct source-code inspection of the 98-line C source refutes this entirely — the file contains zero PAM symbols, zero `pam_authenticate`/`pam_handle_t`/`pam_acct_mgmt` references, and zero authentication-flow code. The correct technique mapping is **T1014 (Rootkit) + T1574.006 (Dynamic Linker Hijacking) + T1564.001 (Hide Artifacts: Hidden Files and Directories) + T1027 (Obfuscated Files or Information)**. Detection rules in this file are mapped accordingly. No PAM-auth-backdoor detection logic applies.

**VT "dropped_files" retraction:** VT's `dropped_files` relationship for `ghost.sh` (sha `e943b581...`) and `min1.sh` (sha `008bc5ab...`) surfaces SHA-256s `44a3bab2c338e3bca24c00f7c3da1301eb4a5a889f1c667cc781e1bdacd3b9e7` and `ac941ead01d5451a7a9fd4be4ba9b60b2d3e4138670ae868e655b3b393253227`. Direct VT lookup confirms these are `/var/log/auth.log.1.gz` and `/var/log/kern.log.1.gz` — sandbox-host log archives the scripts touched during log-clearing tradecraft, NOT operator miner binaries. These hashes are excluded from detection rules and IOC feeds.

**Prior public coverage calibration:** The claim "first public documentation of GHOST kit" was retracted after user review. Censys (Mark Ellzey, 2026-04-07) is the primary public disclosure. This sub-report extends Censys coverage with: sibling host 77.110.125.145, byte-identical .so refuting per-victim compilation, full hide-string/hide-port inventory, Vova75Rus kit-author identity, OWNER Telegram bot supply-chain architecture, structured detection rules, and VT detection landscape snapshot (6-weeks post-Censys, AV community has still not shipped GHOST family signatures).

---

## Detection Coverage Summary

GHOST is a commodity Linux cryptojacker kit distributed by kit-author Vova75Rus as a Bash-orchestrated installer suite (`ghost.sh`) with an LD_PRELOAD userland rootkit (`libpam_cache.so`), a Hysteria v2 covert-tunnel operator wrapper (`hyst.sh`), a miner-only installer with a kit-wide Telegram supply-chain callback (`min1.sh`), and a Python ComfyUI exploitation/persistence framework. This retiering pass re-sorts the original 30 rule objects (10 YARA, 12 Sigma, 8 Suricata alert objects across 6 published headings) into Detection/Hunting tiers, routes 5 atomic indicators already present in the IOC feed out of the rule set, and cuts 3 rule objects that fire on ubiquitous benign activity or were already retired.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 5 | 4 | T1014, T1574.006, T1564.001, T1059.004, T1611, T1480.002, T1102.002, T1496.001, T1059.006, T1595.002, T1554, T1543.002 | 1 |
| Sigma | 6 | 4 | T1574.006, T1027, T1014, T1554, T1571, T1059.004, T1543.002, T1036.005, T1222.002, T1620, T1572 | 1 |
| Suricata | 1 | 2 | T1059.004, T1574.006, T1105, T1572, T1571, T1102.002, T1496.001 | 3 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- `/etc/ld.so.preload` write/create by a non-package-manager process (Sigma Detection) — the single most durable signature in this file; the file's modification is the persistent global-load trigger for GHOST's LD_PRELOAD rootkit and has essentially no legitimate production-server use case.
- The GHOST rootkit's combined hook-export + hide-list-string + port-format-string + proc-hook fingerprint (YARA Detection) — byte-identical across both known customer deployments, requiring a genuine recompile (not just a rename) to evade.
- The GHOST installer's `_anti_hisana` competitor-displacement function name (YARA Detection) — unique to this kit family, confirmed via 16 cross-host Hunt.io hits.

**Atomics routed to the IOC feed:** the kit-author OWNER Telegram bot token prefix `8415540095` (and operator MIRROR bot `8315596543`), the Kryptex/c3pool/nanopool mining-pool domains, and the Hysteria admin-panel host `77.110.96.200` were each the sole discriminator of one or more rules below — all five are already present in [`ghost-cryptojacker-vova75rus-77.110.96.200-iocs.json`](/ioc-feeds/ghost-cryptojacker-vova75rus-77.110.96.200-iocs.json); no feed edits were required by this pass. Per the tiering rubric's cryptojacker-specific guidance, a mining-pool domain or a kit-wide callback token is an atomic — a distinctive config/loader constant (like the rootkit's hide-list array) is the durable anchor instead.

**Retiering summary:** 3 rule objects were cut outright — a pre-existing withdrawn Suricata signature (already retired 2026-06-19 for overbreadth), a redundant/misleadingly-labeled Telegram-SNI Suricata duplicate, and a Sigma `inotify_add_watch` rule that cannot express its intended path filter in a single detection block and as literally written fires on all inotify usage system-wide. One YARA rule (the dual-Telegram `min1.sh` wrapper) was salvaged via capability-abstraction — its condition no longer mandatorily gates on the kit-wide bot token, so it survives bot rotation. One Sigma rule (the ComfyUI fake-node planter) was tightened to remove an overbroad selector branch that would have matched any legitimate custom-node installation.

---

## YARA Rules

```
/*
   Yara Rule Set
   Identifier: GHOST Cryptojacker Kit Family — Vova75Rus / 77.110.96.200
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/
```

### Detection Rules

#### MAL_Linux_GHOST_libpam_cache_Rootkit_Family

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1014 (Rootkit), T1574.006 (Dynamic Linker Hijacking), T1564.001 (Hide Artifacts: Hidden Files and Directories)
**Confidence:** HIGH
**Rationale:** Byte-identical across all known GHOST kit customer deployments (SHA-256 `eaaa10c8...` on both 77.110.96.200 and 77.110.125.145). The combination of hook-function exports, hide-list array strings, and the hide-port format string is unique to this rootkit family and requires an actual recompile — not a rename — to evade. ELF64 shared-object structural check eliminates PE/script false positives.
**False Positives:** None known — the specific combination of `readdir`/`fopen` libc exports plus GHOST-specific hide-list strings (`khugepaged_`, `nv_uvm_`, `inotify_guard`, `libpam_cache`) does not appear in any legitimate shared library.
**Blind Spots:** A full kit-source recompile that renames every hide-list entry and hook export would evade; the rule targets the on-disk shared object, not a memory-only injected variant.
**Validation:** Scan the analyzed sample (`hash1` below) — all clauses must match; a legitimate PAM module or unrelated shared library must NOT fire.
**Deployment:** Linux endpoint AV/EDR file scanning, memory scanner, auditd-triggered on-write scan of `/lib/security/`.

```yara
rule MAL_Linux_GHOST_libpam_cache_Rootkit_Family {
   meta:
      description = "Detects GHOST cryptojacker kit LD_PRELOAD rootkit libpam_cache.so — ELF64 shared object hooking readdir/readdir64/fopen/fopen64 to hide miner processes, kit paths, and operator wallet prefixes from /proc listings; byte-identical across all known GHOST kit customer deployments"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "eaaa10c840de23335abae1a9ead0a6a7fb7be5187cd19ad05137feab12bb7301"
      hash2 = "edafde0d33ff1a169c0c4eeaeec12d1759818c7cf4950fcee91c687e811e6cff"
      hash3 = "296a800564111b0bad9fe63faf4e63ba"
      family = "GHOST-cryptojacker-kit"
      malware_type = "LD_PRELOAD Rootkit"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "ca987dcd-ca0e-5e71-a3b1-cab19fd7a851"
   strings:
      // Hook function exports — the four libc symbols this .so overrides
      $export_readdir    = "readdir" ascii fullword
      $export_fopen      = "fopen" ascii fullword
      // GHOST-specific hide-list strings from H[] array — operator-deployment-path artifacts
      $hide_khugepaged   = "khugepaged_" ascii
      $hide_nv_uvm       = "nv_uvm_" ascii
      $hide_inotify      = "inotify_guard" ascii fullword
      $hide_libpam_self  = "libpam_cache" ascii
      $hide_fontcpu      = "fontconfig/.cpu" ascii
      $hide_fontgpu      = "fontconfig/.gpu" ascii
      $hide_pid_guard    = ".pid_guard" ascii
      $hide_ghost_sh     = "ghost.sh" ascii fullword
      // LD_PRELOAD removal constructor — unsetenv called at load time
      $unsetenv_preload  = "LD_PRELOAD" ascii fullword
      // Port-filter format string — uppercase hex zero-padded matching /proc/net/tcp native format
      $port_fmt          = ":%04X" ascii
      // /proc hooking targets
      $proc_net_tcp      = "/proc/net/tcp" ascii
      $proc_cmdline      = "/proc/%s/cmdline" ascii
      $proc_exe          = "/proc/%s/exe" ascii
      // ELF magic bytes for shared object detection (7f 45 4c 46 = ELF magic)
      $elf_magic         = { 7F 45 4C 46 02 01 01 00 }
   condition:
      // ELF64 shared object (magic + ELFCLASS64 + ELFDATA2LSB)
      $elf_magic at 0 and
      // File size: 14,568 bytes exact for known sample; allow up to 50KB for compiled variants
      filesize < 50KB and
      // Require hook exports + multiple hide-list strings + port format string + proc hooks
      ($export_readdir and $export_fopen) and
      $port_fmt and
      ($proc_net_tcp or $proc_cmdline or $proc_exe) and
      ($unsetenv_preload) and
      3 of ($hide_*)
}
```

#### MAL_Linux_GHOST_libpam_cache_Source

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1014 (Rootkit), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**Rationale:** The 98-line C source `libpam_cache.c` is shipped alongside the compiled binary on the kit-author's distribution server. The combination of `_GNU_SOURCE` plus libc hook function names plus the `unsetenv("LD_PRELOAD")` constructor pattern plus GHOST-specific hide-list contents is unique and requires the same recompile-level effort to evade as Rule 1.
**False Positives:** None known — the specific combination of abbreviated single-char helper names (`_sh`, `_ph`, `_fn`) plus `RTLD_NEXT` resolver plus GHOST hide-list strings does not appear in legitimate PAM development.
**Blind Spots:** A rewritten source using different helper-function naming conventions and a fully rotated hide-list would evade; this rule only matches the source text, not the compiled binary (Rule 1 covers that).
**Validation:** Scan the analyzed sample (`hash1` below) — all clauses must match; unrelated C source implementing `RTLD_NEXT` hooking (e.g., a legitimate LD_PRELOAD shim) without the GHOST hide-list strings must NOT fire.
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection.

```yara
rule MAL_Linux_GHOST_libpam_cache_Source {
   meta:
      description = "Detects GHOST cryptojacker kit LD_PRELOAD rootkit C source file libpam_cache.c — 98-line dense hand-written C with single-char identifiers, RTLD_NEXT hook resolution, unsetenv LD_PRELOAD constructor, and GHOST-specific hide-list contents; shipped alongside compiled .so on kit-author distribution server"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "edafde0d33ff1a169c0c4eeaeec12d1759818c7cf4950fcee91c687e811e6cff"
      family = "GHOST-cryptojacker-kit"
      malware_type = "LD_PRELOAD Rootkit Source"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "9f7d2a2c-c893-5f7f-a3c0-ab6fac644947"
   strings:
      // GNU source define enabling RTLD_NEXT
      $gnu_source        = "#define _GNU_SOURCE" ascii
      // RTLD_NEXT hook resolution pattern
      $rtld_next         = "RTLD_NEXT" ascii fullword
      // Constructor pattern — unsetenv called with LD_PRELOAD at constructor time
      $constructor_attr  = "__attribute__((constructor))" ascii
      $unsetenv_call     = "unsetenv(\"LD_PRELOAD\")" ascii
      // Hook function identifiers (dense single-char style from this author's code)
      $helper_sh         = "static int _sh(" ascii
      $helper_ph         = "static int _ph(" ascii
      $helper_fn         = "static FILE *_fn(" ascii
      // GHOST-specific hide-list entries in the H[] array
      $hide_inotify      = "inotify_guard" ascii fullword
      $hide_khugepaged   = "khugepaged_" ascii
      $hide_ghost        = "ghost.sh" ascii fullword
      // Port filter format string
      $port_fmt          = ":%04X" ascii
   condition:
      // No ELF magic — this is C source text
      filesize < 10KB and
      $gnu_source and
      $rtld_next and
      $constructor_attr and
      $unsetenv_call and
      $port_fmt and
      2 of ($helper_*) and
      2 of ($hide_*)
}
```

#### MAL_Linux_GHOST_Kit_Shell_Installer

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1611 (Escape to Host), T1480.002 (Mutual Exclusion), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**Rationale:** The `ghost.sh` installer contains highly distinctive function names unique to the GHOST kit — particularly the container-escape suite (`_container_escape`, `_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`), the competitor-displacement function `_anti_hisana`, and the rootkit-build function `_compile_hide_so`. These function names appear in no other known malware family and were confirmed via 16 Hunt.io cross-host hits.
**False Positives:** None known — the specific combination of `_anti_hisana` plus `_container_escape`-family functions plus `_compile_hide_so`/`_install_preload` plus the GHOST version banner is unique to GHOST kit deployments.
**Blind Spots:** A rebranded fork that renames the entire function inventory and drops the version banner would evade; the rule targets the installer script text, not runtime behavior.
**Validation:** Scan the analyzed sample (`hash1` below) — all clauses must match; an unrelated Bash installer or container-escape PoC lacking the `_anti_hisana` function must NOT fire.
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection, email gateway.

```yara
rule MAL_Linux_GHOST_Kit_Shell_Installer {
   meta:
      description = "Detects GHOST cryptojacker kit primary Bash installer ghost.sh — 1338-line English-language Bash script containing GHOST v5.1/v6.0 codename banner, competitor-displacement function _anti_hisana, 4 container-escape variants, LD_PRELOAD rootkit build/install functions, and multi-vector persistence; function names unique to GHOST kit family"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "e943b58112f58517b95424dba9334bf97c5dc2dd2f069dca04b9e75b9fec56ba"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Bash Installer/Orchestrator"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "e3af0826-0aba-54ee-90ae-f49c95fb66ba"
   strings:
      // GHOST kit version banners (in first-line comment of ghost.sh)
      $banner_v51        = "GHOST v5.1" ascii
      $banner_v60        = "GHOST v6.0" ascii
      // Competitor-displacement function — kills Hisana kit (16 cross-host hits confirmed in Hunt.io)
      $fn_anti_hisana    = "_anti_hisana" ascii fullword
      // Rootkit build/install functions
      $fn_compile_so     = "_compile_hide_so" ascii fullword
      $fn_install_preload = "_install_preload" ascii fullword
      // Container-escape suite — all 4 variants
      $fn_container_esc  = "_container_escape" ascii fullword
      $fn_esc_cgroup     = "_escape_via_cgroup" ascii fullword
      $fn_esc_mount      = "_escape_via_mount" ascii fullword
      $fn_esc_nsenter    = "_escape_via_nsenter" ascii fullword
      $fn_esc_socket     = "_escape_via_socket" ascii fullword
      // Python kit builder function
      $fn_build_py       = "_build_python_fetcher" ascii fullword
      // Resurrection watchdog function
      $fn_resurrection   = "_resurrection_loop" ascii fullword
   condition:
      filesize < 200KB and
      ($banner_v51 or $banner_v60) and
      $fn_anti_hisana and
      ($fn_compile_so or $fn_install_preload) and
      ($fn_container_esc or ($fn_esc_cgroup and $fn_esc_mount) or ($fn_esc_nsenter and $fn_esc_socket)) and
      ($fn_build_py or $fn_resurrection)
}
```

#### MAL_Linux_GHOST_ComfyUI_Python_Kit

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1595.002 (Active Scanning: Vulnerability Scanning), T1554 (Compromise Host Software Binary)
**Confidence:** HIGH
**Rationale:** The Python exploitation framework (`py.py` + `scan.py`) contains distinctive function names unique to the GHOST kit's ComfyUI targeting component. `_build_python_fetcher`, the `PerformanceMonitor` fake-node class, and the `PIP_PAYLOAD_REPO` variable are not produced by legitimate ComfyUI development tooling, and the rule requires the class plus at least one config/registration marker plus a ComfyUI-specific fingerprint together.
**False Positives:** None known for the required combination; a single string (e.g. `PerformanceMonitor` alone, or `8188` alone) would carry meaningful FP risk in isolation, which is why none of them is a standalone anchor in the condition.
**Blind Spots:** A rebuild that renames `PerformanceMonitor`, drops `PIP_PAYLOAD_REPO`, and removes the ComfyUI port/stats fingerprint would evade.
**Validation:** Scan the analyzed sample (`hash1`/`hash2`/`hash3` below) — must match; an unrelated legitimate ComfyUI custom node lacking the fetcher/config functions must NOT fire.
**Deployment:** Linux endpoint file scanning, ComfyUI `custom_nodes` directory scanning, download monitoring.

```yara
rule MAL_Linux_GHOST_ComfyUI_Python_Kit {
   meta:
      description = "Detects GHOST cryptojacker kit Python ComfyUI exploitation framework (py.py + scan.py) — Python scripts containing _build_python_fetcher downloader builder, PerformanceMonitor fake custom-node class, PIP_PAYLOAD_REPO GitHub URL config variable, and NODE_CLASS_MAPPINGS registration for ComfyUI persistence; 74KB+63KB kit shipped to both GHOST customer operators"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "dc232b55329d95fe2a47a8d637b7bffea06f18e3d8332ba94b042b1862213a1d"
      hash2 = "9023734a70ee6a05d4ecd5466d0c5803f293601836deb00cc417a3add04bd93e"
      hash3 = "6e5d897c7fd0060c7da2394ad1bb3584827c216f8aadac4f6ed41b2d915f0070"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Python ComfyUI Exploitation Framework"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "a4d3ff71-b85c-58f2-9e0e-c6f9300289f1"
   strings:
      // Core exploitation functions unique to GHOST Python kit
      $fn_build_fetcher  = "_build_python_fetcher" ascii fullword
      $fn_plant_node     = "plant_backdoor_node" ascii fullword
      $fn_find_nodes     = "find_target_nodes" ascii fullword
      // Fake custom-node class — persistence mechanism
      $class_perfmon     = "PerformanceMonitor" ascii fullword
      // Kit supply-chain config variable
      $pip_payload_repo  = "PIP_PAYLOAD_REPO" ascii fullword
      // ComfyUI node registration dicts
      $node_mappings     = "NODE_CLASS_MAPPINGS" ascii fullword
      $node_display      = "NODE_DISPLAY_NAME_MAPPINGS" ascii fullword
      // ComfyUI targeting fingerprint
      $comfyui_port      = "8188" ascii
      $comfyui_stats     = "system_stats" ascii
   condition:
      filesize < 200KB and
      ($fn_build_fetcher or $fn_plant_node or $fn_find_nodes) and
      $class_perfmon and
      ($pip_payload_repo or $node_mappings or $node_display) and
      ($comfyui_port or $comfyui_stats)
}
```

#### MAL_Linux_GHOST_ComfyUI_Fake_PerformanceMonitor_Node

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1554 (Compromise Host Software Binary), T1059.006 (Python), T1574.006 (Dynamic Linker Hijacking analog for Python runtime)
**Confidence:** HIGH
**Rationale:** Narrow detection on the malicious "PerformanceMonitor" custom node registered into ComfyUI's `NODE_CLASS_MAPPINGS`. This fires on post-compromise persistence regardless of delivery mechanism — it catches the installed artifact, not just the dropper. The mandatory combination of an actual class *definition* (`class PerformanceMonitor`) plus the registration-dict literal is more specific than a bare filename or import match.
**False Positives:** Low — "PerformanceMonitor" is a generic name in isolation, but its appearance as a class definition registered into `NODE_CLASS_MAPPINGS` is specific; legitimate ComfyUI custom-node developers follow community naming conventions with more-specific identifiers (e.g. "ImageMonitor", "GPUMonitor").
**Blind Spots:** A legitimately-named "PerformanceMonitor" custom node from an unrelated, unvetted developer would still fire — treat a hit as a compromise indicator requiring publisher/source verification, not an automatic block.
**Validation:** Scan a ComfyUI installation with the planted node present — must match; a stock ComfyUI installation with only official custom nodes must NOT fire.
**Deployment:** ComfyUI `custom_nodes` directory file scan (scheduled or on-write), Linux endpoint EDR.

```yara
rule MAL_Linux_GHOST_ComfyUI_Fake_PerformanceMonitor_Node {
   meta:
      description = "Detects GHOST cryptojacker kit post-compromise persistence via malicious ComfyUI custom node — Python file registering class PerformanceMonitor into NODE_CLASS_MAPPINGS; catches the installed persistence artifact regardless of delivery mechanism; hunt rule for ComfyUI custom-node integrity audits"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      family = "GHOST-cryptojacker-kit"
      malware_type = "ComfyUI Custom Node Persistence Artifact"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "17a43202-fdd1-5051-8085-9456351ca024"
   strings:
      // Malicious custom-node class registration — both dict assignments required
      $class_def         = "class PerformanceMonitor" ascii
      $node_class_reg    = "NODE_CLASS_MAPPINGS" ascii fullword
      $node_display_reg  = "NODE_DISPLAY_NAME_MAPPINGS" ascii fullword
      // Ghost kit function that installs the node
      $fn_plant          = "plant_backdoor_node" ascii fullword
   condition:
      filesize < 500KB and
      $class_def and
      $node_class_reg and
      ($node_display_reg or $fn_plant)
}
```

### Hunting Rules

#### MAL_Linux_GHOST_Hysteria_Operator_Wrapper

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1059.004 (Unix Shell), T1543.002 (Create or Modify System Process: Systemd Service)
**Confidence:** MODERATE
**Rationale:** Hysteria v2 is legitimate open-source software, and "bing.com" as an SNI-masquerade choice is a common domain-fronting convention used broadly across the censorship-circumvention tooling ecosystem — not unique to this operator. The rule's real distinguishing power comes from requiring the mandatory `bing.com` string alongside two of the `.hy2_password`/`.hy2_port`/`.hy2_uri` credential-cache file references, but those cache filenames may originate from the upstream `get.hy2.sh` Hysteria installer itself rather than being GHOST-kit-bespoke, so a host that ran the vanilla Hysteria v2 installer for any legitimate tunneling purpose could plausibly satisfy this combination. Durable enough to hunt on, not tight enough to alert on.
**False Positives:** Legitimate Hysteria v2 deployments (VPN/censorship-circumvention use) that happen to use a `bing.com`-style SNI masquerade and are scanned alongside their own installer cache files; any host running the stock `get.hy2.sh` installer for non-malicious tunneling.
**Deployment:** Linux endpoint file scanning, download directory scanning; treat hits as a hunting lead requiring correlation with the operator wrapper's Russian-language comments and the `:3301` panel/`api_vpn_report` markers before escalation.

```yara
rule MAL_Linux_GHOST_Hysteria_Operator_Wrapper {
   meta:
      description = "Detects GHOST cryptojacker kit Hysteria v2 operator wrapper hyst.sh — Russian-language Bash script installing Hysteria v2 QUIC/UDP backdoor with bing.com SNI masquerade, per-victim TLS cert generation, /tmp/.hy2_* credential cache, and HTTP admin panel callback to :3301; operator-authored component of GHOST kit; broad hunting rule as bing.com SNI masquerade and .hy2_* cache filenames are shared with legitimate Hysteria v2 deployments"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "822afb1fb29f22df8c951726d492021df2940223ed719881dafb40cda3894c5c"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Hysteria v2 Installer Wrapper"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "13a9762c-4653-5feb-8227-fc15eea54a4a"
   strings:
      // Hysteria v2 bing.com SNI masquerade — common domain-fronting convention, not GHOST-exclusive
      $sni_masquerade    = "bing.com" ascii fullword
      // Hysteria credential cache file pattern in /tmp
      $hy2_password      = ".hy2_password" ascii
      $hy2_port          = ".hy2_port" ascii
      $hy2_uri           = ".hy2_uri" ascii
      // Admin panel port reference (3301 = Hysteria panel)
      $panel_port        = "3301" ascii
      // Hysteria installer download source
      $hy2_installer     = "get.hy2.sh" ascii
      // Russian operator comments (Cyrillic — confirming operator-authored)
      $ru_installs       = "\xD0\x9D\xD0\x90\xD0\xA1\xD0\xA2\xD0\xA0\xD0\x99\xD0\x9A\xD0\x98" ascii  // НАСТРОЙКИ
      // Operator panel API callback function name
      $api_vpn_report    = "api_vpn_report" ascii fullword
   condition:
      filesize < 30KB and
      $sni_masquerade and
      2 of ($hy2_*) and
      ($panel_port or $hy2_installer or $api_vpn_report or $ru_installs)
}
```

#### MAL_Linux_GHOST_min1_DualTelegram_Wrapper

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1059.004 (Unix Shell), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** MODERATE
**Rationale:** **Salvaged from the original condition.** The prior version mandatorily gated on the kit-author OWNER Telegram bot token prefix `8415540095:` — a single external identifier the kit author could rotate at zero cost, which would silently break detection for every future customer deployment (the bot token itself is an atomic, already carried in the IOC feed). This rewrite makes the bot token one of three independent paths: the token match (unchanged, still useful today), OR the paired bilingual Russian "TELEGRAM (OWNER)"/"TELEGRAM (MIRROR)" comment-label structure (a kit-authorship pattern independent of any specific bot ID), OR a `function tg` definition combined with a Kryptex pool domain or the `install_xmrig` function name. The rule now survives bot rotation; tiered Hunting rather than Detection because the salvage introduces a rewritten condition not independently goodware-validated, and two of the three paths (Kryptex pool domain, bot token) remain operator-configuration values rather than kit-structural artifacts.
**False Positives:** Low but not zero for the bot-token and pool-domain paths (both are operator/kit-author-controlled values that could theoretically appear in unrelated Telegram/mining tooling); the dual-comment-label path has no known legitimate collision but has not been validated against a broad goodware corpus.
**Deployment:** Linux endpoint file scanning, download directory scanning, email gateway, web proxy content inspection; corroborate a hit with the YARA rootkit/installer Detection rules above before treating as confirmed GHOST kit activity.

```yara
rule MAL_Linux_GHOST_min1_DualTelegram_Wrapper {
   meta:
      description = "Detects GHOST cryptojacker kit miner installer wrapper min1.sh via three independent paths: the kit-author OWNER Telegram bot token prefix 8415540095:, OR the paired bilingual Russian TELEGRAM (OWNER)/TELEGRAM (MIRROR) comment-label structure, OR a function tg definition combined with a Kryptex pool domain or install_xmrig; salvaged from a bot-token-only condition so detection survives bot-token rotation"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "008bc5ab73e75bb76131f91d68a3792d9e4393137c14afe8c44d44be2a2c46f6"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Miner Installer / Dual-Telegram Supply-Chain Wrapper"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "8dc8ca76-896a-58b9-b88c-4ab6cf8c7e6c"
   strings:
      // Path 1: kit-author OWNER bot token prefix (atomic; already in IOC feed) — kept as one of three OR-paths, not the sole gate
      $owner_bot_prefix  = "8415540095:" ascii
      // Path 2: dual-Telegram bilingual comment-label structure (Russian: OWNER + MIRROR) — kit-authorship pattern, bot-ID-independent
      $tg_owner_comment  = "TELEGRAM (\xD0\x92\xD0\x9B\xD0\x90\xD0\x94\xD0\x95\xD0\x9B\xD0\x95\xD0\xA6)" ascii  // TELEGRAM (ВЛАДЕЛЕЦ)
      $tg_mirror_comment = "TELEGRAM (\xD0\x97\xD0\x95\xD0\xA0\xD0\x9A\xD0\x90\xD0\x9B\xD0\x9E)" ascii  // TELEGRAM (ЗЕРКАЛО)
      // Path 3: function tg + Kryptex pool domain or install_xmrig function name
      $pool_xmr_kryptex  = "xmr.kryptex.network" ascii
      $pool_etc_kryptex  = "etc.kryptex.network" ascii
      $fn_install_xmrig  = "install_xmrig" ascii fullword
      $fn_tg             = "function tg" ascii
   condition:
      filesize < 30KB and
      (
        $owner_bot_prefix or
        ($tg_owner_comment and $tg_mirror_comment) or
        ($fn_tg and ($pool_xmr_kryptex or $pool_etc_kryptex or $fn_install_xmrig))
      )
}
```

#### MAL_Linux_GHOST_check_comfyui_Scanner

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1595.002 (Active Scanning: Vulnerability Scanning), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** The `check_comfyui.sh` scanner combines a ComfyUI port-8188 HTTP probe, `/object_info`/`system_stats`/`/queue` endpoint checks, and a four-category output-file naming convention (`sc_comfy`, `sc_manager`, `sc_nodes`, `sc_vuln`) distinctive to this kit's reconnaissance component — but basic ComfyUI health-check scripts exist in legitimate admin tooling, and MODERATE (not HIGH) confidence in the original assessment reflects that the differentiator (output filenames) is not a structural code artifact the way the rootkit hide-list is.
**False Positives:** Legitimate ComfyUI health-check or monitoring scripts that happen to use a similar port-probe pattern; the `sc_*` output-filename convention reduces but does not eliminate this.
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection.

```yara
rule MAL_Linux_GHOST_check_comfyui_Scanner {
   meta:
      description = "Detects GHOST cryptojacker kit ComfyUI target verification script check_comfyui.sh — Bash script probing port 8188 /system_stats and /queue for ComfyUI identification, classifying results into sc_comfy/sc_manager/sc_nodes/sc_vuln output files; Russian-language comments; scanning component of GHOST ComfyUI exploitation pipeline"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "9023734a70ee6a05d4ecd5466d0c5803f293601836deb00cc417a3add04bd93e"
      family = "GHOST-cryptojacker-kit"
      malware_type = "ComfyUI Target Scanner"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "39b7fb48-31ec-5b1d-b787-2935cad5a60e"
   strings:
      // ComfyUI probe endpoints
      $probe_system_stats = "system_stats" ascii
      $probe_object_info  = "object_info" ascii
      $probe_queue        = "/queue" ascii
      // GHOST-specific output file naming convention
      $out_sc_comfy       = "sc_comfy" ascii
      $out_sc_manager     = "sc_manager" ascii
      $out_sc_nodes       = "sc_nodes" ascii
      $out_sc_vuln        = "sc_vuln" ascii
      // ComfyUI port
      $port_8188          = "8188" ascii
   condition:
      filesize < 10KB and
      $port_8188 and
      ($probe_system_stats or $probe_object_info or $probe_queue) and
      2 of ($out_*)
}
```

#### MAL_Linux_GHOST_get_all_ranges_CloudEnumerator

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1595.002 (Active Scanning: Vulnerability Scanning), T1018 (Remote System Discovery), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** The `get_all_ranges.sh` cloud IP-range scraper targets the bgpview.io public API with a specific set of cloud-provider ASN queries. The `bgpview.io` + `bgpview.io/asn/` pair is effectively one signal expressed twice (not two independent anchors), and the provider name list (Lambda Labs, Nebius, Datacrunch, Contabo, Hetzner) consists of literal company names that could appear together in legitimate cloud-inventory, IaC, or network-documentation tooling. As explicitly assessed in the original analysis: false-positive risk is HIGH for any individual provider name and only LOW for the full combination — a genuine but brittle signal.
**False Positives:** Legitimate cloud-inventory, asset-discovery, or infrastructure-as-code tooling that queries bgpview.io for the same or an overlapping set of cloud-provider ASNs, particularly ML/GPU-focused inventory scripts.
**Deployment:** Linux endpoint file scanning, download directory scanning; use as a scoping lead rather than an alert.

```yara
rule MAL_Linux_GHOST_get_all_ranges_CloudEnumerator {
   meta:
      description = "Detects GHOST cryptojacker kit cloud-provider IP-range enumeration script get_all_ranges.sh — Bash script querying bgpview.io ASN API for 14+ cloud providers including ML-GPU-specific providers (Lambda Labs, Nebius, Datacrunch); reconnaissance prequel to ComfyUI exploitation pipeline targeting GPU-cloud environments"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Cloud IP-Range Enumerator"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "61f9da50-05bf-5c1c-933a-2a65a73eeae3"
   strings:
      // bgpview.io API source (used for ASN-to-IP-range lookups)
      $bgpview_api        = "bgpview.io" ascii
      // ML-GPU-cloud-specific providers — GHOST-kit targeting signature
      // These rarely appear together in legitimate IP-range tools
      $provider_lambda    = "Lambda Labs" ascii
      $provider_nebius    = "Nebius" ascii
      $provider_datacrunch = "Datacrunch" ascii
      // Additional providers from get_all_ranges.sh ASN list
      $provider_contabo   = "Contabo" ascii
      $provider_hetzner   = "Hetzner" ascii
      // bgpview.io API structure specific to this script
      $bgpview_ips_prefix = "bgpview.io/asn/" ascii
   condition:
      filesize < 15KB and
      $bgpview_api and
      $bgpview_ips_prefix and
      2 of ($provider_*)
}
```

---

## Sigma Rules

### Detection Rules

#### Linux LD_PRELOAD Persistence File Modification

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**Rationale:** `/etc/ld.so.preload` is the single most durable signature in this file — its modification is the persistent global-load trigger for every process on the system, and it is rarely touched in legitimate production environments outside package-manager operations, which are explicitly excluded.
**False Positives:** System administrators manually adding a legitimate preload library for debugging or performance purposes (rare; verify path added to the file); package post-install scripts using `ldconfig`/`update-alternatives` to register new shared libraries (excluded by the filter, but confirm the filter is effective in your environment).
**Blind Spots:** A rootkit that writes this file through a process image renamed to match one of the excluded package-manager binaries would evade; memory-only variants that never persist via this file are not covered (see Rule 3 non-`/etc/ld.so.preload` variant coverage gap).
**Validation:** Trigger the rootkit's install routine — the write/create event on `/etc/ld.so.preload` must match; a `dpkg`/`apt`/`rpm` package install that touches the same file must NOT fire.
**Deployment:** auditd + Sysmon for Linux (`file_event` on Linux).

```yaml
title: Linux LD_PRELOAD Persistence File Modification
id: f67e016e-dcd7-4ee3-a2ee-9477ad7f75c2
status: experimental
description: >-
    Detects write or create operations on /etc/ld.so.preload by non-package-manager
    processes. The GHOST cryptojacker kit writes this file to globally load
    libpam_cache.so into all system processes for LD_PRELOAD rootkit persistence.
    Modification of this file by a shell, curl, or miner process is a high-confidence
    indicator of LD_PRELOAD rootkit installation.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.persistence
    - attack.stealth
    - attack.execution
    - attack.t1574.006
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename: '/etc/ld.so.preload'
    filter_pkg_mgr:
        Image|endswith:
            - '/dpkg'
            - '/apt'
            - '/apt-get'
            - '/ldconfig'
            - '/update-alternatives'
            - '/rpm'
            - '/yum'
            - '/dnf'
    condition: selection_path and not filter_pkg_mgr
falsepositives:
    - >-
      System administrators manually adding a legitimate preload library for
      debugging or performance purposes (rare; verify path added to the file)
    - Package post-install scripts using ldconfig or update-alternatives to
      register new shared libraries
level: high
```

#### Suspicious Shared Library Created in PAM Security Directory

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1027 (Obfuscated Files or Information), T1014 (Rootkit)
**Confidence:** HIGH
**Rationale:** Legitimate PAM module installation is exclusively done through package managers; direct `.so` file creation in `/lib/security/`-family directories from a shell, curl, or wget is not a legitimate PAM deployment pattern under any normal operational scenario.
**False Positives:** Legitimate PAM module installation by package manager (filtered by the exclusion above — confirm the filter is working in your environment); manual PAM plugin deployment by a system administrator (require change-management verification).
**Blind Spots:** A rootkit dropped by a process image renamed to match an excluded package-manager binary would evade; a `.so` dropped under a non-standard PAM directory path outside the four listed prefixes is not covered.
**Validation:** Trigger the rootkit's install routine — the `.so` creation event under `/lib/security/` must match; a `dpkg`-driven PAM module install must NOT fire.
**Deployment:** auditd + Sysmon for Linux (`file_event` on Linux).

```yaml
title: Suspicious Shared Library Created in PAM Security Directory
id: 21b2646a-7e0b-4d6c-8392-d976b8388fa3
status: experimental
description: >-
    Detects creation of a .so shared library file in /lib/security/ or similar PAM
    module directories by non-package-manager processes. The GHOST cryptojacker kit
    drops libpam_cache.so into /lib/security/ using PAM-style filename camouflage as
    a deceptive LD_PRELOAD rootkit. Legitimate PAM modules are always installed via
    package management — direct file creation from a shell or download tool indicates
    rootkit deployment.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.stealth
    - attack.persistence
    - attack.execution
    - attack.t1574.006
    - attack.t1014
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_path:
        TargetFilename|startswith:
            - '/lib/security/'
            - '/lib/x86_64-linux-gnu/security/'
            - '/usr/lib/security/'
            - '/usr/lib/x86_64-linux-gnu/security/'
        TargetFilename|endswith: '.so'
    filter_pkg_mgr:
        Image|endswith:
            - '/dpkg'
            - '/apt'
            - '/apt-get'
            - '/rpm'
            - '/yum'
            - '/dnf'
            - '/ldconfig'
    condition: selection_path and not filter_pkg_mgr
falsepositives:
    - >-
      Legitimate PAM module installation by package manager (filtered by
      exclusion above — confirm filter is working)
    - Manual PAM plugin deployment by system administrator (require change
      management verification)
level: high
```

#### Auditd - PAM Security Library Directory Write by Non-Package-Manager

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit)
**Confidence:** HIGH
**Rationale:** Auditd PATH-record equivalent of the Sysmon file-event rule above, for environments running auditd without Sysmon for Linux. Same precision rationale — legitimate PAM module writes to this directory only occur through package managers, which are excluded.
**False Positives:** Package manager post-install hooks installing legitimate PAM modules (filtered above); a system administrator manually copying a verified PAM module during maintenance.
**Blind Spots:** Requires the `-w /lib/security -p wa -k pam_module_write` auditd rule to be active; without it, this rule produces no events at all (a silent gap, not a false negative on a specific evasion).
**Validation:** Confirm the auditd watch rule is active, then trigger the rootkit's install routine — the PATH record must match; a package-manager-driven PAM install must NOT fire.
**Deployment:** auditd (PATH record type).

```yaml
title: Auditd - PAM Security Library Directory Write by Non-Package-Manager
id: f26bb12b-dca1-4b62-adf1-9186d5d31560
status: experimental
description: >-
    Detects auditd file write events (PATH record type with OPEN_W flag or CREATE)
    on the /lib/security/ directory. Requires auditd rule "-w /lib/security -p wa
    -k pam_module_write" to be active. The GHOST cryptojacker kit writes
    libpam_cache.so to this directory using PAM-style filename camouflage; any
    write from a non-package-manager process is a high-confidence rootkit drop.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.stealth
    - attack.persistence
    - attack.execution
    - attack.t1574.006
    - attack.t1014
    - detection.emerging-threats
logsource:
    product: linux
    service: auditd
detection:
    selection_key:
        type: 'PATH'
        key: 'pam_module_write'
        nametype:
            - 'CREATE'
            - 'DELETE'
    filter_pkg_mgr:
        exe|endswith:
            - '/dpkg'
            - '/rpm'
            - '/ldconfig'
            - '/update-alternatives'
    condition: selection_key and not filter_pkg_mgr
falsepositives:
    - Package manager post-install hooks installing legitimate PAM modules (filtered above)
    - System administrator manually copying a verified PAM module during maintenance
level: high
```

#### GHOST ComfyUI Fake PerformanceMonitor Custom Node Planted

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1554 (Compromise Host Software Binary)
**Confidence:** HIGH
**Rationale:** **Tightened from the original selector.** The prior version matched `TargetFilename|contains` against EITHER the specific `/custom_nodes/PerformanceMonitor` substring OR the generic `/ComfyUI/custom_nodes/` directory path — the second branch would fire on the creation of ANY `.py` file anywhere under a ComfyUI custom-node directory, which is exactly what happens every time a user installs any legitimate custom node. That branch has been removed; the rule now requires the distinctive `PerformanceMonitor` filename component specifically.
**False Positives:** A legitimately-named custom node literally called "PerformanceMonitor" installed by an authorized user (verify publisher and source repository before dismissing); development environments where a test node happens to share this name.
**Blind Spots:** A rebuild that renames the planted node file would evade; this rule inspects the file path only, not the file's content (the YARA rule above inspects content — the class definition — for a stronger anchor).
**Validation:** Trigger the kit's `plant_backdoor_node()` routine — the file-creation event must match; installation of an unrelated, differently-named legitimate custom node must NOT fire.
**Deployment:** Linux `file_event` monitoring (auditd or Sysmon for Linux) on ComfyUI `custom_nodes` directory.

```yaml
title: GHOST ComfyUI Fake PerformanceMonitor Custom Node Planted
id: df247923-595c-4760-9a97-f0722dbf664d
status: experimental
description: >-
    Detects GHOST cryptojacker kit persistence via malicious ComfyUI custom node
    installation. The GHOST Python kit's plant_backdoor_node() function creates a
    Python file with "PerformanceMonitor" in its path within the victim's ComfyUI
    custom_nodes/ directory. Tightened from an earlier selector that also matched
    any .py file under a ComfyUI custom_nodes/ path regardless of filename, which
    would have fired on every legitimate custom-node installation.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.persistence
    - attack.t1554
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_comfyui_node:
        TargetFilename|contains: '/custom_nodes/PerformanceMonitor'
        TargetFilename|endswith: '.py'
    condition: selection_comfyui_node
falsepositives:
    - >-
      Legitimate custom ComfyUI node named PerformanceMonitor installed by
      authorized user (verify publisher and source repository before dismissing)
    - >-
      Development environments where a test custom node happens to share this
      name (scope exclusion for known dev hosts recommended)
level: high
```

#### GHOST Kit Systemd Camouflage Service Unit Creation

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1543.002 (Create or Modify System Process: Systemd Service), T1036.005 (Masquerading: Match Legitimate Name or Location)
**Confidence:** HIGH
**Rationale:** These specific camouflage names are part of the kit's structural hide-list/process-disguise inventory (the same array referenced by the YARA rootkit rule) — changing them requires a kit-level rebuild, not a per-deployment rename. None of these names are used by any standard Linux distribution package.
**False Positives:** A custom legitimate service deployment using a similar name (extremely unlikely for `fontconfig-cache.service` or `gnome-shell-ext-updater.service` as systemd units); a desktop environment package that legitimately provides `gnome-shell-ext-updater` — verify package ownership via `dpkg -S`/`rpm -qf` before treating as confirmed.
**Blind Spots:** A future kit version that renames the entire camouflage-name inventory would evade; this rule inspects unit-file creation only, not runtime service state.
**Validation:** Trigger the kit's systemd persistence install — the unit-file creation event must match one of the listed names; installation of an unrelated, differently-named systemd unit must NOT fire.
**Deployment:** Linux `file_event` monitoring on systemd unit directories, auditd.

```yaml
title: GHOST Kit Systemd Camouflage Service Unit Creation
id: 16fce30a-b59f-461c-87fc-89ae2d736527
status: experimental
description: >-
    Detects creation of systemd service unit files using GHOST cryptojacker kit
    camouflage names. The GHOST kit installs fontconfig-cache.service (user-level
    systemd persistence disguised as fontconfig caching) and systemd-journal-flush
    override; operator processes are renamed to dbus-session-monitor (xmrig) and
    gnome-shell-ext-updater (lolMiner). Creation of unit files with these names
    by non-package-manager processes indicates GHOST kit systemd persistence.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1543.002
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: file_event
    product: linux
detection:
    selection_ghost_unit_names:
        TargetFilename|contains:
            - 'fontconfig-cache.service'
            - 'inotify_guard'
            - 'dbus-session-monitor.service'
            - 'gnome-shell-ext-updater.service'
            - 'archivist-daemon.service'
            - 'journald-svc.service'
            - 'systemd-guard.service'
    condition: selection_ghost_unit_names
falsepositives:
    - >-
      Custom legitimate service deployments using similar names (extremely
      unlikely for fontconfig-cache.service or gnome-shell-ext-updater.service
      as systemd units)
    - >-
      Desktop environment package that legitimately provides
      gnome-shell-ext-updater (verify package manager ownership with dpkg -S
      or rpm -qf)
level: medium
```

#### Chattr Immutable Bit Set on Linux Persistence Target Paths

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1222.002 (File and Directory Permissions Modification: Linux), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**Rationale:** Setting the immutable bit on LD_PRELOAD-related or PAM-security-directory files is exclusively an anti-forensics/anti-removal technique with no legitimate use case in standard Linux operations — this is a technique chokepoint, not a family-specific artifact, so it survives any GHOST kit rebuild entirely.
**False Positives:** System hardening scripts that legitimately use `chattr +i` on selected configuration files (review CIS benchmark hardening scripts); container image build processes that lock certain system files (rare; typically not in `/lib/security` paths).
**Blind Spots:** A variant using an alternative anti-removal mechanism (e.g. a kernel-level rootkit hook rather than the filesystem immutable bit) would evade; this rule only covers the four listed sensitive-path prefixes.
**Validation:** Trigger the kit's `_lock_files` routine — the `chattr +i` invocation against a sensitive path must match; a CIS-hardening script locking an unrelated configuration file must NOT fire.
**Deployment:** Linux `process_creation` monitoring (auditd EXECVE or Sysmon for Linux Event ID 1).

```yaml
title: Chattr Immutable Bit Set on Linux Persistence Target Paths
id: f83a039f-885d-4759-a89c-2156a54e7ea5
status: experimental
description: >-
    Detects chattr +i (set immutable bit) invoked against system persistence file
    paths. The GHOST cryptojacker kit's _lock_files function uses chattr +i on
    /etc/ld.so.preload, /lib/security/libpam_cache.so, and miner binary copies
    to block rm operations by defenders and automated cleanup scripts. Setting the
    immutable bit on LD_PRELOAD-related or PAM-security-directory files is
    exclusively an anti-removal tradecraft technique — no legitimate use case exists.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.stealth
    - attack.defense-impairment
    - attack.persistence
    - attack.execution
    - attack.t1222.002
    - attack.t1574.006
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_chattr:
        Image|endswith: '/chattr'
        CommandLine|contains: '+i'
    selection_sensitive_paths:
        CommandLine|contains:
            - '/etc/ld.so.preload'
            - '/lib/security/'
            - '/etc/init.d/'
            - '/etc/systemd/system/'
    condition: selection_chattr and selection_sensitive_paths
falsepositives:
    - >-
      System hardening scripts that legitimately use chattr +i on selected
      configuration files (review CIS benchmark hardening scripts)
    - >-
      Container image build processes that lock certain system files (rare;
      typically not in /lib/security paths)
level: high
```

### Hunting Rules

#### Suspicious LD_PRELOAD Set to Non-Standard Library Path

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**Rationale:** `LD_PRELOAD` set to a non-standard path is a broad technique-level indicator — legitimate debugging (`ltrace`, `faketime`), performance tooling, and some container-runtime initialization patterns use exactly this pattern, so this is a scoping lead requiring analyst triage rather than an auto-alert.
**False Positives:** Debugging or performance-testing tools (`ltrace`, `strace` wrappers, `faketime`) using `LD_PRELOAD` with temporary paths; software build systems that test custom shared libraries from temp directories; some container runtimes that set `LD_PRELOAD` during container initialization.
**Deployment:** auditd `PROCESS_TITLE` (requires `name_format=hex`) or Sysmon for Linux (`process_creation`).

```yaml
title: Suspicious LD_PRELOAD Set to Non-Standard Library Path
id: 5cd034e9-ac04-4178-8a16-95f291c5d805
status: experimental
description: >-
    Detects Linux processes launched with LD_PRELOAD environment variable pointing to
    non-standard shared library paths such as /tmp/, /var/tmp/, /home/, or custom
    XDG cache paths. The GHOST cryptojacker kit's _compile_hide_so and _install_preload
    functions may set LD_PRELOAD during rootkit deployment before writing the persistent
    /etc/ld.so.preload entry. Legitimate LD_PRELOAD usage targets well-known system
    library paths only.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.stealth
    - attack.persistence
    - attack.execution
    - attack.t1574.006
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_env:
        CommandLine|contains:
            - 'LD_PRELOAD=/tmp/'
            - 'LD_PRELOAD=/var/tmp/'
            - 'LD_PRELOAD=/home/'
            - 'LD_PRELOAD=/root/'
            - 'LD_PRELOAD=./lib'
            - 'LD_PRELOAD=/dev/shm/'
    condition: selection_env
falsepositives:
    - >-
      Debugging or performance testing tools (ltrace, strace wrappers,
      faketime) using LD_PRELOAD with temporary paths
    - >-
      Software build systems that test custom shared libraries from temp
      directories
    - Some container runtimes that set LD_PRELOAD during container initialization
level: medium
```

#### High-Frequency Ncat Listener Creation on Linux Host

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1571 (Non-Standard Port)
**Confidence:** MODERATE
**Rationale:** `ncat`/`nc`/`netcat` are legitimate, widely-used administration tools, and the "high-frequency" qualifier described in the original analysis (>20 invocations/hour) is not implemented as a Sigma correlation/threshold in the detection logic below — as written, this fires on any single `ncat -l` invocation. It is a genuine scoping lead (chronic listener creation is real operator tradecraft observed in this campaign's bash history) but requires SIEM-side aggregation to realize the "high-frequency" framing, and single-hit review by an analyst in the meantime.
**False Positives:** Authorized network testing activities using `ncat` in controlled environments; security engineers running port-testing scripts on network infrastructure hosts.
**Deployment:** Linux `process_creation` monitoring (auditd EXECVE or Sysmon for Linux Event ID 1); pair with SIEM-side frequency aggregation to realize the intended "high-frequency" framing.

```yaml
title: High-Frequency Ncat Listener Creation on Linux Host
id: 4639e400-9a7d-495f-b7a3-a06de5f3c7db
status: experimental
description: >-
    Detects ncat -l listener creation on a Linux host. The GHOST cryptojacker
    Operator-A showed 83 ncat invocations in bash history — the highest
    command frequency — indicating chronic use of ncat for port testing, makeshift
    backdoor channels, and lateral-movement probing. As written this rule matches
    any single ncat -l invocation; more than 20 invocations per hour on a single
    production server is the anomaly threshold observed in this campaign and
    requires SIEM-side aggregation logic beyond this rule's single-event scope.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.command-and-control
    - attack.execution
    - attack.t1059.004
    - attack.t1571
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_ncat_listener:
        Image|endswith:
            - '/ncat'
            - '/nc'
            - '/netcat'
        CommandLine|contains: ' -l'
    condition: selection_ncat_listener
falsepositives:
    - Authorized network testing activities using ncat in controlled environments
    - Security engineers running port testing scripts on network infrastructure hosts
level: medium
```

#### Hysteria V2 QUIC Proxy Process Execution on Linux Server

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling)
**Confidence:** MODERATE
**Rationale:** Hysteria v2 is legitimate dual-use software with real censorship-circumvention and VPN use cases; this rule fires on mere presence/execution of the Hysteria binary with no GHOST-specific qualifier (no SNI check, no specific port, no installation-path anchor). Demoted from the original `level: high` — an inflated level on a generic dual-use-tool selector — to `medium`/Hunting, reflecting that this is a "any Hysteria usage on a host type where it's unexpected" lead, not a malware-specific detection.
**False Positives:** Legitimate Hysteria v2 usage for censorship circumvention by employees in restrictive-internet regions (rare in corporate GPU environments; verify with owner); authorized network testing using Hysteria for VPN/proxy research purposes.
**Deployment:** Linux `process_creation` monitoring (auditd EXECVE or Sysmon for Linux Event ID 1); scope to production GPU/ML hosts where Hysteria has no expected business purpose.

```yaml
title: Hysteria V2 QUIC Proxy Process Execution on Linux Server
id: e01c6689-1d47-4f6c-bf23-a71b32d88375
status: experimental
description: >-
    Detects execution of Hysteria v2 process on a Linux host. The GHOST cryptojacker
    kit installs Hysteria v2 as a covert QUIC/UDP backdoor with bing.com SNI masquerade
    (ports 14433/14444 UDP) using hyst.sh installer. Hysteria v2 is legitimate dual-use
    software; execution on a production GPU server or ML workload host with no expected
    business purpose is a scoping lead for GHOST kit compromise, not a malware-specific
    signature on its own. The process is installed as systemd service
    hysteria-server.service with binaries in /usr/local/bin/hysteria.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.command-and-control
    - attack.t1572
    - detection.emerging-threats
logsource:
    category: process_creation
    product: linux
detection:
    selection_hysteria:
        Image|endswith: '/hysteria'
    selection_hysteria_service:
        CommandLine|contains: 'hysteria-server'
    condition: selection_hysteria or selection_hysteria_service
falsepositives:
    - >-
      Legitimate Hysteria v2 usage for censorship circumvention by employees
      in restrictive-internet regions (rare in corporate GPU environments;
      verify with owner)
    - Authorized network testing using Hysteria for VPN / proxy research purposes
level: medium
```

#### High-Frequency memfd_create Syscall from Non-JVM Process on Linux Server

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** MODERATE
**Rationale:** `memfd_create` is used by a broad legitimate ecosystem beyond the JVM/browser/Node filter in this rule — systemd, container runtimes, sandboxing tools (`bubblewrap`, `firejail`), and various self-updating or FFI-based tooling all use it for anonymous memory regions. Like the ncat rule above, the "high-frequency" framing is described in prose but not implemented as a correlation/threshold in the detection logic — as written, this fires on any single non-JVM/browser `memfd_create` call.
**False Positives:** JVM-based applications (Java, Kotlin, Groovy) using `memfd_create` for native library loading not captured by the filter's exact substrings; Python FFI libraries (`ctypes`, `cffi`) using `memfd_create` for anonymous shared memory; container runtimes, sandboxing tools, and other legitimate fileless-deployment tooling not covered by the filter.
**Deployment:** auditd syscall monitoring (requires `-a always,exit -F arch=b64 -S memfd_create -k fileless_exec`) or Sysmon for Linux; tune with process-ancestry filters for the expected parent-process chain on your GPU servers before treating hits as actionable.

```yaml
title: High-Frequency memfd_create Syscall from Non-JVM Process on Linux Server
id: 3d5c184d-4937-4ab0-93d6-778760e59b9c
status: experimental
description: >-
    Detects memfd_create() syscall invocations from a single non-JVM process on a
    Linux server. The GHOST cryptojacker kit's _memfd_exec function uses
    memfd_create to create anonymous in-memory file descriptors for fileless xmrig and
    lolMiner execution via execveat(), bypassing on-disk file scanning. Requires
    auditd syscall monitoring with "-a always,exit -F arch=b64 -S memfd_create -k
    fileless_exec" rule active. memfd_create is also used by a broad legitimate
    ecosystem (systemd, container runtimes, sandboxing tools, FFI libraries) beyond
    the JVM/browser/Node filter below, so this is a scoping lead requiring
    process-ancestry tuning rather than an auto-alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026-05-25
tags:
    - attack.stealth
    - attack.t1620
    - detection.emerging-threats
logsource:
    product: linux
    service: auditd
detection:
    selection_memfd:
        type: 'SYSCALL'
        syscall: 'memfd_create'
    filter_expected:
        exe|contains:
            - 'java'
            - 'chrome'
            - 'chromium'
            - 'firefox'
            - 'node'
    condition: selection_memfd and not filter_expected
falsepositives:
    - >-
      JVM-based applications (Java, Kotlin, Groovy) using memfd_create for
      native library loading — excluded by filter above
    - >-
      Python FFI libraries (ctypes, cffi) using memfd_create for anonymous
      shared memory
    - Legitimate fileless deployment tools used by authorized DevOps processes
level: medium
```

---

## Suricata Signatures

### Detection Rules

#### GHOST Kit Distribution File Download from AEZA Hosting Range

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1574.006 (Dynamic Linker Hijacking), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**Rationale:** The URI filename set (`libpam_cache.so`, `ghost.sh`, `hyst.sh`, `min1.sh`, `libpam_cache.c`) is a durable kit-structural artifact — these names are consistent across the toolkit's architecture and don't rotate per-victim — combined with a destination restriction to the /16 hosting range where both confirmed GHOST operator servers reside. No legitimate use of a `.so` file literally named `libpam_cache` exists on this hosting range.
**False Positives:** None known — these specific URI paths have no legitimate usage on AEZA hosting infrastructure.
**Blind Spots:** If GHOST kit distribution moves off the 77.110.0.0/16 range, the destination restriction requires updating even though the filename pattern itself would still be valid; a customer serving these files from a different hosting range would evade until the CIDR is refreshed.
**Validation:** Replay a PCAP of a victim downloading `ghost.sh` from an in-range host — must alert; an unrelated `.sh`/`.so` download from the same range must NOT fire.
**Deployment:** Network IDS/IPS at perimeter, HTTP proxy inspection.

```suricata
alert http $HOME_NET any -> 77.110.0.0/16 any (msg:"THL GHOST Cryptojacker Kit Distribution File Download from AEZA Hosting Range"; flow:established,to_server; http.uri; pcre:"/\/(libpam_cache\.so|ghost\.sh|hyst\.sh|min1\.sh|libpam_cache\.c)$/"; classtype:trojan-activity; sid:9100104; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/, tag Dropper, tag GHOST_kit;)
```

### Hunting Rules

#### GHOST Cryptojacker Kit Hysteria v2 QUIC Backdoor Egress — Known Operator Ports

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1571 (Non-Standard Port)
**Confidence:** MODERATE
**Rationale:** UDP ports 14433/14444 are this operator's specific configuration choice (part of the GHOST rootkit's hide-port list), not a kit-wide structural constant — a future deployment or kit update could pick different ports, so this is durability-limited compared to the filename-anchored rule above. No content/host anchor is possible since this is opaque QUIC traffic; the rule relies on the port pairing plus a threshold for noise control.
**False Positives:** Any legitimate or unrelated service that happens to use UDP 14433–14444 (uncommon but not impossible); the `threshold` limits alert volume per source.
**Deployment:** Network IDS/IPS at perimeter, server egress monitoring; hunt-tune before alerting, and corroborate with the AEZA-range Detection rule above before escalating.

```suricata
alert udp $HOME_NET any -> any 14433:14444 (msg:"THL GHOST Cryptojacker Kit Hysteria v2 QUIC Backdoor Egress - Known Operator Ports"; threshold:type threshold,track by_src,count 5,seconds 60; classtype:trojan-activity; sid:9100103; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/, tag Backdoor, tag GHOST_kit, tag Hysteria_v2;)
```

#### GHOST Cryptojacker Kit Telegram API Egress from Production Server — Covert Mining Report

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** LOW–MODERATE
**Rationale:** **Consolidated from two near-duplicate rules.** The original file carried two `tls.sni` rules matching `api.telegram.org` — one (sid 9100107) labeled "Critical" and titled as an "OWNER Telegram Bot Token" indicator despite its own inline comment admitting the bot-token specificity is unachievable over TLS SNI and the logic only matches generic Telegram API contact; the other (sid 9100108, kept here) carried the same logic with an honest title and a noise-reducing threshold. TLS SNI to `api.telegram.org` is a weak indicator on its own — legitimate applications also use the Telegram Bot API — so this is a scoping lead for production/GPU-server hosts with no expected Telegram business use, not an alerting-grade signature.
**False Positives:** Any legitimate monitoring, alerting, or chatbot integration on the same host that uses the Telegram Bot API for unrelated purposes.
**Deployment:** TLS-decryption-capable inline IDS/IPS or proxy with DLP inspection for genuine bot-token-level specificity; this SNI-only fallback should be scoped to production server IP ranges with no expected Telegram use and treated as a hunting lead, not an alert.

```suricata
alert tls $HOME_NET any -> any any (msg:"THL GHOST Cryptojacker Kit Telegram API Egress from Production Server - Covert Mining Report"; tls.sni; content:"api.telegram.org"; endswith; nocase; threshold:type threshold,track by_src,count 5,seconds 300; classtype:policy-violation; sid:9100108; rev:2; metadata:author The_Hunters_Ledger, date 2026-05-25, reference https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/, tag GHOST_kit, tag Telegram_reporting;)
```

---

## Coverage Gaps

### Rules cut or routed to the IOC feed in this retiering pass

**Atomics routed to the IOC feed (5 total; no feed edits required — all already present).** Per the tiering rubric's cryptojacker-specific guidance, a mining-pool domain or a kit-wide callback token is an atomic, not a rule anchor:

- **Kit-author OWNER Telegram bot token `8415540095`** — previously the sole rule (YARA `MAL_GHOST_OWNER_Telegram_Bot_Token_Indicator`) and a mandatory co-anchor in the `min1.sh` wrapper rule. Removing the token from the standalone rule left only generic Telegram-API context (`api.telegram.org`) or a single generic Russian word with no independent GHOST-specific signal — nothing behavioral survives, so the standalone rule is cut. Already present in the IOC feed's `telegram_bot_ids` array.
- **Operator MIRROR Telegram bot token `8315596543`** — same disposition; already in the feed.
- **Kryptex/c3pool/nanopool mining-pool domains** (`xmr.kryptex.network`, `etc.kryptex.network`, `cfx.kryptex.network`, `auto.c3pool.org`, `cfx-asia1.nanopool.org`) — previously two rules (Sigma `DNS Query to GHOST Cryptojacker Mining Pool Domains` and Suricata sid 9100101/9100102) matched these domains with no other behavioral qualifier. Already present in the feed's `network_indicators.domains` with per-domain false-positive annotations (kryptex domains: low FP; c3pool/nanopool: medium FP, both are legitimate public mining pools also used by non-malicious miners).
- **Hysteria admin-panel host `77.110.96.200`** — the Suricata `Hysteria Admin Panel Callback` rule (sid 9100106) keyed on this single IP plus the generic `/api/` URI prefix; removing the IP leaves "any HTTP request starting with /api/ to any destination," which is meaningless. Already present in the feed's `network_indicators.ipv4` with role "Hysteria admin panel."

**Cut: Sigma `Inotify Watch Created on LD_PRELOAD Persistence File` (id `d89cc92a-b3e0-4760-93cd-54d4b609c837`).** The rule's own inline comment admits that auditd's `SYSCALL` record type does not carry the watched path directly — that requires correlating with a separate `PATH` record, which a single Sigma selection cannot express. As literally written, the condition (`selection_inotify_preload`) matches `inotify_add_watch` calls system-wide with no path filter at all — an operation used constantly by desktop environments, IDEs, file-sync clients, log-tailing tools, and build systems. This fires on ubiquitous benign activity with zero discriminating value, which fails the precision gate even for a Hunting tier (there is no pivot value in reviewing thousands of daily inotify events). **What would enable a rule:** a Sigma `correlation` construct joining the `SYSCALL` record (syscall=`inotify_add_watch`) with the subsequent `PATH` record naming `/etc/ld.so.preload`, which requires confirming the exact auditd PATH-record field schema in the target environment before authoring.

**Cut: Suricata sid 9100107 (Telegram SNI, "OWNER Telegram Bot Token" title).** Duplicate of sid 9100108's detection logic (both match `tls.sni` on `api.telegram.org`) but titled and severity-labeled as though it retained bot-token-level specificity — the rule's own inline comment says otherwise ("The bot-token specificity is lost... this is a WEAK indicator"). Consolidated into sid 9100108, which carries an honest title, a noise-reducing threshold, and is tiered Hunting rather than presented as a Critical-severity signature.

**Cut: Suricata sid 9100105 (pre-existing withdrawal, carried forward unchanged).** This rule — a `tls.sni` match on `raw.githubusercontent.com` intended to catch GHOST Python kit payload fetches — was already withdrawn 2026-06-19, prior to this retiering pass, because TLS SNI cannot see the (encrypted) repository path the rule needed, and the SNI is shared by all `raw.githubusercontent.com` traffic. This retiering pass carries that withdrawal forward as a Cut rather than reintroducing it.

### Technique-level gaps (from the original investigation; unchanged by this retiering pass)

The following MITRE ATT&CK techniques observed in the GHOST kit analysis could not be covered with high-confidence rules, along with the evidence gaps that prevent rule creation:

**T1611 (Escape to Host) — container-escape behavioral rules not written.** The four escape variants (`_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`) are documented in `ghost.sh` source but behavioral detection requires runtime monitoring of the specific syscall sequences (e.g., writes to `/sys/fs/cgroup/.../release_agent`, bind-mount namespace operations). Container-escape detection is also highly environment-specific (Falco/kube-bench/sysdig are the appropriate tools, not generic Sigma rules). The function names in `ghost.sh` are covered as a proxy by the YARA `Kit_Shell_Installer` Detection rule above.

**T1552.004 (Unsecured Credentials: Private Keys) — SSH key harvest rule not written.** The `ghost.sh` `_harvest_keys` function reads `~/.ssh/known_hosts` and SSH private key files for lateral movement. A generic Sigma rule for SSH key file access is high-FP (legitimate SSH tools access the same files constantly), and no specific command-line pattern distinguishes the GHOST kit's harvest from legitimate SSH client activity. **What would raise confidence:** a specific variable name or grep pattern unique to `ghost.sh`'s key-harvest code.

**T1021.004 (Remote Services: SSH) — lateral movement Sigma rule not written.** The `ghost.sh` `_lateral_move`, `_discover_targets`, and `_spread_to_host` functions implement SSH lateral movement using harvested keys. Detection requires correlating SSH connections from a known-compromised host to new targets combined with the kit's specific `StrictHostKeyChecking=no` flag pattern — multi-event SIEM logic beyond a single Sigma rule's scope, with a high FP rate from legitimate `StrictHostKeyChecking=no` admin usage absent additional context.

**Censys JA3/JA3S/JA4 fingerprint — TLS fingerprint Suricata rule not written.** The Censys disclosure (2026-04-07) referenced general infrastructure fingerprints (JARM/JA4X) for 77.110.96.200, but the specific JA3/JA3S hash values were not captured in this investigation's artifact set. **What would enable a rule:** a live TLS connection to 77.110.96.200 with capture and `ja3`/`ja3s` analysis to extract the exact hash values.

**T1070.002 / T1070.003 (Clear Linux Logs / Clear Command History) — log-clearing rule not written.** The `ghost.sh` `_cloak` function touches or clears `/var/log/{auth,boot,cron,daemon,kern,messages,secure,syslog}.log` and runs `history -c`. A Sigma rule for log truncation would fire on every legitimate `logrotate` event; distinguishing GHOST kit log clearing would require detecting rapid sequential truncation of multiple log files in a short window — a SIEM aggregation query, not a Sigma rule. **What would enable a rule:** a log-clearing command pattern in `_cloak` more specific than the generic log-file paths.

**ComfyUI exploitation CVE/mechanism — no exploit-signature rule possible.** The specific CVE or vulnerability mechanism that `py.py`'s `find_target_nodes()` exploits for initial code execution in ComfyUI has not been identified. **What would enable a rule:** ComfyUI-side analysis identifying which API endpoint or deserialization vulnerability the kit exploits for initial payload execution.

**Operator-B behavioral indicators — insufficient unique signatures.** Operator-B (77.110.125.145) is confirmed abandoned (40+ days inactive, last on-chain activity 2026-04-12). `New_scanner.py` contains distinctive Cyrillic strings, but no unique behavioral indicator beyond the shared kit-level rules was identified. If reactivated, the kit-level YARA and Sigma rules in this file will catch the deployment.

**`memfd_create`/`execveat` fileless execution — incomplete coverage.** The Hunting-tier `memfd_create` rule detects the syscall but cannot distinguish GHOST kit miner execution from legitimate use of the same pattern without process-ancestry correlation (see the rule's own Deployment note above).

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
