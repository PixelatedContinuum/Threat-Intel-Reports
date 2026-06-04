---
title: "Detection Rules — GHOST Cryptojacker Kit Family (Vova75Rus / 77.110.96.200)"
date: '2026-05-25'
layout: post
permalink: /hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
hide: true
---

**Campaign:** GHOST-Cryptojacker-Vova75Rus-77.110.96.200
**Date:** 2026-05-25
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
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

| Rule Type | Count | MITRE Techniques Covered | Overall FP Risk |
|---|---|---|---|
| YARA | 10 | T1014, T1574.006, T1564.001, T1027, T1059.004, T1059.006, T1572, T1102.002, T1595.002 | LOW–MEDIUM |
| Sigma | 12 | T1574.006, T1222.002, T1543.002, T1053.003, T1554, T1480.002, T1620, T1495, T1070.002, T1057, T1595.002, T1102.002 | LOW–MEDIUM |
| Suricata | 6 | T1496.001, T1572, T1071.001, T1071.004, T1102.002, T1595.002 | LOW |

**Priority distribution:** 4 HIGH, 6 MEDIUM, 12 LOW across all rule types.

**Highest-priority single rule:** `MAL_GHOST_OWNER_Telegram_Bot_Token_Indicator` — the kit-author OWNER Telegram bot token prefix `8415540095:` is baked into every GHOST customer deployment globally. A single string match catches ALL downstream operators regardless of wallet, pool, or host configuration. This is the supply-chain detection string for the GHOST commodity kit family.

**Detection gap acknowledgment:** 6-week post-Censys VT snapshot confirms zero AV vendor has shipped GHOST family signatures as of 2026-05-25. Rules in this file fill that gap for the YARA/Sigma/Suricata-capable defender.

---

## YARA Rules

```
/*
   Yara Rule Set
   Identifier: GHOST Cryptojacker Kit Family — Vova75Rus / 77.110.96.200
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/
```

### Rule 1: MAL_Linux_GHOST_libpam_cache_Rootkit_Family

**Detection Priority:** HIGH
**Rationale:** Byte-identical across all known GHOST kit customer deployments (SHA-256 eaaa10c8... on both 77.110.96.200 and 77.110.125.145). Combination of hook function exports + hide-array strings + hide-port format string is unique to this rootkit family. ELF64 shared object condition eliminates PE/script FPs.
**ATT&CK Coverage:** T1014 (Rootkit), T1574.006 (Dynamic Linker Hijacking), T1564.001 (Hide Artifacts: Hidden Files and Directories)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of `readdir`/`fopen` libc exports + GHOST-specific hide-list strings (khugepaged_, nv_uvm_, inotify_guard, libpam_cache) does not appear in any legitimate shared library
**Deployment:** Linux endpoint AV/EDR file scanning, memory scanner, auditd-triggered on-write scan of /lib/security/

```yara
rule MAL_Linux_GHOST_libpam_cache_Rootkit_Family {
   meta:
      description = "Detects GHOST cryptojacker kit LD_PRELOAD rootkit libpam_cache.so — ELF64 shared object hooking readdir/readdir64/fopen/fopen64 to hide miner processes, kit paths, and operator wallet prefixes from /proc listings; byte-identical across all known GHOST kit customer deployments"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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
      ($proc_net_tcp or $proc_cmdline) and
      ($unsetenv_preload) and
      3 of ($hide_*)
}
```

---

### Rule 2: MAL_Linux_GHOST_libpam_cache_Source

**Detection Priority:** HIGH
**Rationale:** The 98-line C source `libpam_cache.c` is shipped alongside the compiled binary on the kit-author's distribution server. Defenders can detect the source file in downloads, temporary directories, or on compromised hosts. The combination of `_GNU_SOURCE` + libc hook function names + the `unsetenv("LD_PRELOAD")` constructor pattern is unique.
**ATT&CK Coverage:** T1014 (Rootkit), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of abbreviated single-char helper names (_sh, _ph, _fn, _i) + RTLD_NEXT resolver + GHOST hide-list strings does not appear in legitimate PAM development
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection

```yara
rule MAL_Linux_GHOST_libpam_cache_Source {
   meta:
      description = "Detects GHOST cryptojacker kit LD_PRELOAD rootkit C source file libpam_cache.c — 98-line dense hand-written C with single-char identifiers, RTLD_NEXT hook resolution, unsetenv LD_PRELOAD constructor, and GHOST-specific hide-list contents; shipped alongside compiled .so on kit-author distribution server"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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
      2 of ($helper_*) and
      2 of ($hide_*)
}
```

---

### Rule 3: MAL_Linux_GHOST_Kit_Shell_Installer

**Detection Priority:** HIGH
**Rationale:** The `ghost.sh` installer contains highly distinctive function names unique to the GHOST kit — particularly the container-escape suite (`_container_escape`, `_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`), the competitor-displacement function `_anti_hisana`, and the rootkit-build function `_compile_hide_so`. These function names appear in no other known malware family and were confirmed via 16 Hunt.io cross-host hits.
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1611 (Escape to Host), T1480.002 (Mutual Exclusion), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — the specific combination of _anti_hisana + _container_escape + _compile_hide_so + GHOST banner string is unique to GHOST kit deployments
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection, email gateway

```yara
rule MAL_Linux_GHOST_Kit_Shell_Installer {
   meta:
      description = "Detects GHOST cryptojacker kit primary Bash installer ghost.sh — 1338-line English-language Bash script containing GHOST v5.1/v6.0 codename banner, competitor-displacement function _anti_hisana, 4 container-escape variants, LD_PRELOAD rootkit build/install functions, and multi-vector persistence; function names unique to GHOST kit family"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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
      $fn_compile_so and
      ($fn_container_esc or ($fn_esc_cgroup and $fn_esc_mount)) and
      ($fn_build_py or $fn_resurrection)
}
```

---

### Rule 4: MAL_Linux_GHOST_Hysteria_Operator_Wrapper

**Detection Priority:** MEDIUM
**Rationale:** The Russian-language operator wrapper `hyst.sh` contains distinctive strings: the Hysteria v2 bing.com SNI masquerade configuration, per-victim TLS certificate generation, /tmp/.hy2_* credential cache file pattern, and the 3301 admin panel port reference. These are specific to this operator's Hysteria deployment pattern.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1059.004 (Unix Shell), T1543.002 (Create or Modify System Process: Systemd Service)
**Confidence:** HIGH
**False Positive Risk:** MEDIUM — Hysteria v2 is legitimate open-source software; the bing.com SNI masquerade string is the differentiator. Legitimate Hysteria deployments do not use bing.com as their SNI masquerade target by default.
**Deployment:** Linux endpoint file scanning, download directory scanning

```yara
rule MAL_Linux_GHOST_Hysteria_Operator_Wrapper {
   meta:
      description = "Detects GHOST cryptojacker kit Hysteria v2 operator wrapper hyst.sh — Russian-language Bash script installing Hysteria v2 QUIC/UDP backdoor with bing.com SNI masquerade, per-victim TLS cert generation, /tmp/.hy2_* credential cache, and HTTP admin panel callback to :3301; operator-authored component of GHOST kit"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "822afb1fb29f22df8c951726d492021df2940223ed719881dafb40cda3894c5c"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Hysteria v2 Installer Wrapper"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "13a9762c-4653-5feb-8227-fc15eea54a4a"
   strings:
      // Hysteria v2 bing.com SNI masquerade — distinctive covert configuration
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
      ($panel_port or $hy2_installer or $api_vpn_report)
}
```

---

### Rule 5: MAL_Linux_GHOST_min1_DualTelegram_Wrapper

**Detection Priority:** HIGH
**Rationale:** The dual-Telegram OWNER/MIRROR architecture baked into `min1.sh` is the GHOST kit's supply-chain monitoring signature. Any script containing both the OWNER bot token prefix `8415540095` AND the OWNER/MIRROR Telegram variable naming pattern is definitively linked to the GHOST kit supply chain. This rule catches min1.sh regardless of which operator deployed it.
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1059.004 (Unix Shell), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — the OWNER bot token prefix `8415540095` is unique to Vova75Rus's kit monitoring channel; the dual OWNER/MIRROR Telegram variable pattern within a single script is not produced by legitimate software
**Deployment:** Linux endpoint file scanning, download directory scanning, email gateway, web proxy content inspection

```yara
rule MAL_Linux_GHOST_min1_DualTelegram_Wrapper {
   meta:
      description = "Detects GHOST cryptojacker kit miner installer wrapper min1.sh — Russian-language Bash script with dual-Telegram OWNER/MIRROR architecture baked in; kit-author OWNER bot token prefix 8415540095 is baked into every GHOST customer deployment globally; catches all GHOST kit operators via single string match"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      hash1 = "008bc5ab73e75bb76131f91d68a3792d9e4393137c14afe8c44d44be2a2c46f6"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Miner Installer / Dual-Telegram Supply-Chain Wrapper"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "8dc8ca76-896a-58b9-b88c-4ab6cf8c7e6c"
   strings:
      // GHOST kit OWNER bot token prefix — baked into every customer deployment by kit author
      // HIGHEST-VALUE SUPPLY-CHAIN DETECTION STRING
      $owner_bot_prefix  = "8415540095:" ascii
      // Dual-Telegram architecture comment strings (Russian: ВЛАДЕЛЕЦ = OWNER, ЗЕРКАЛО = MIRROR)
      $tg_owner_comment  = "TELEGRAM (\xD0\x92\xD0\x9B\xD0\x90\xD0\x94\xD0\x95\xD0\x9B\xD0\x95\xD0\xA6)" ascii  // TELEGRAM (ВЛАДЕЛЕЦ)
      $tg_mirror_comment = "TELEGRAM (\xD0\x97\xD0\x95\xD0\xA0\xD0\x9A\xD0\x90\xD0\x9B\xD0\x9E)" ascii  // TELEGRAM (ЗЕРКАЛО)
      // Kryptex mining pool domains (min1.sh pools)
      $pool_xmr_kryptex  = "xmr.kryptex.network" ascii
      $pool_etc_kryptex  = "etc.kryptex.network" ascii
      // Function names in min1.sh
      $fn_install_xmrig  = "install_xmrig" ascii fullword
      $fn_tg             = "function tg" ascii
   condition:
      filesize < 30KB and
      $owner_bot_prefix and
      ($tg_owner_comment or $tg_mirror_comment or ($fn_tg and $pool_xmr_kryptex))
}
```

---

### Rule 6: MAL_Linux_GHOST_ComfyUI_Python_Kit

**Detection Priority:** MEDIUM
**Rationale:** The Python exploitation framework (py.py + scan.py) contains distinctive function names unique to the GHOST kit's ComfyUI targeting component. The `_build_python_fetcher` function name, `PerformanceMonitor` class, and `PIP_PAYLOAD_REPO` variable naming are not produced by legitimate ComfyUI development tooling.
**ATT&CK Coverage:** T1059.006 (Python), T1595.002 (Active Scanning: Vulnerability Scanning), T1554 (Compromise Host Software Binary)
**Confidence:** HIGH
**False Positive Risk:** LOW for `_build_python_fetcher` + `PerformanceMonitor` + `PIP_PAYLOAD_REPO` combination; MEDIUM for any single string in isolation
**Deployment:** Linux endpoint file scanning, ComfyUI custom_nodes directory scanning, download monitoring

```yara
rule MAL_Linux_GHOST_ComfyUI_Python_Kit {
   meta:
      description = "Detects GHOST cryptojacker kit Python ComfyUI exploitation framework (py.py + scan.py) — Python scripts containing _build_python_fetcher downloader builder, PerformanceMonitor fake custom-node class, PIP_PAYLOAD_REPO GitHub URL config variable, and NODE_CLASS_MAPPINGS registration for ComfyUI persistence; 74KB+63KB kit shipped to both GHOST customer operators"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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
      ($fn_build_fetcher or $fn_plant_node) and
      $class_perfmon and
      ($pip_payload_repo or $node_mappings) and
      ($comfyui_port or $comfyui_stats)
}
```

---

### Rule 7: MAL_Linux_GHOST_ComfyUI_Fake_PerformanceMonitor_Node

**Detection Priority:** HIGH
**Rationale:** Narrow detection on the malicious "PerformanceMonitor" custom node registered into ComfyUI's NODE_CLASS_MAPPINGS. This rule fires on post-compromise persistence regardless of how the kit was delivered — catches the installed artifact, not just the dropper. Any ComfyUI installation with a Python file registering `PerformanceMonitor` into NODE_CLASS_MAPPINGS should be treated as a high-confidence compromise indicator.
**ATT&CK Coverage:** T1554 (Compromise Host Software Binary), T1059.006 (Python), T1574.006 (Dynamic Linker Hijacking analog for Python runtime)
**Confidence:** HIGH
**False Positive Risk:** LOW — "PerformanceMonitor" is a generic name, but its appearance IN the NODE_CLASS_MAPPINGS registration context is specific; legitimate ComfyUI custom node developers do not name GPU performance monitoring nodes "PerformanceMonitor" (standard names include "ImageMonitor", "GPUMonitor" etc. with more-specific naming conventions)
**Deployment:** ComfyUI custom_nodes directory file scan (scheduled or on-write), Linux endpoint EDR

```yara
rule MAL_Linux_GHOST_ComfyUI_Fake_PerformanceMonitor_Node {
   meta:
      description = "Detects GHOST cryptojacker kit post-compromise persistence via malicious ComfyUI custom node — Python file registering class PerformanceMonitor into NODE_CLASS_MAPPINGS; catches the installed persistence artifact regardless of delivery mechanism; hunt rule for ComfyUI custom-node integrity audits"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

---

### Rule 8: MAL_Linux_GHOST_check_comfyui_Scanner

**Detection Priority:** MEDIUM
**Rationale:** The `check_comfyui.sh` scanner script contains a specific combination of ComfyUI port-8188 HTTP probe + /object_info endpoint + four-category output file naming (sc_comfy, sc_manager, sc_nodes, sc_vuln) that is distinctive to this kit's reconnaissance component. The output-file naming convention is GHOST-kit-specific.
**ATT&CK Coverage:** T1595.002 (Active Scanning: Vulnerability Scanning), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — basic ComfyUI health-check scripts exist in legitimate admin tooling; the sc_comfy/sc_manager/sc_nodes/sc_vuln output file naming is the differentiator
**Deployment:** Linux endpoint file scanning, download directory scanning, web proxy content inspection

```yara
rule MAL_Linux_GHOST_check_comfyui_Scanner {
   meta:
      description = "Detects GHOST cryptojacker kit ComfyUI target verification script check_comfyui.sh — Bash script probing port 8188 /system_stats and /queue for ComfyUI identification, classifying results into sc_comfy/sc_manager/sc_nodes/sc_vuln output files; Russian-language comments; scanning component of GHOST ComfyUI exploitation pipeline"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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
      ($probe_system_stats or $probe_object_info) and
      2 of ($out_*)
}
```

---

### Rule 9: MAL_Linux_GHOST_get_all_ranges_CloudEnumerator

**Detection Priority:** LOW
**Rationale:** The `get_all_ranges.sh` cloud IP-range scraper is a reconnaissance tool; it targets bgpview.io API endpoints with a specific set of cloud-provider ASN queries. The specific ASN list (14+ providers including Lambda Labs, Nebius, Datacrunch — ML-GPU-cloud-specific providers rarely targeted by commodity malware) combined with the bgpview.io API call structure is distinctive.
**ATT&CK Coverage:** T1595.002 (Active Scanning: Vulnerability Scanning), T1018 (Remote System Discovery), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**False Positive Risk:** HIGH for any individual provider name; LOW for the full combination (Lambda Labs + Nebius + Datacrunch together indicate ML-GPU targeting context specific to GHOST kit)
**Deployment:** Linux endpoint file scanning, download directory scanning

```yara
rule MAL_Linux_GHOST_get_all_ranges_CloudEnumerator {
   meta:
      description = "Detects GHOST cryptojacker kit cloud-provider IP-range enumeration script get_all_ranges.sh — Bash script querying bgpview.io ASN API for 14+ cloud providers including ML-GPU-specific providers (Lambda Labs, Nebius, Datacrunch); reconnaissance prequel to ComfyUI exploitation pipeline targeting GPU-cloud environments"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
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

### Rule 10: MAL_GHOST_OWNER_Telegram_Bot_Token_Indicator

**Detection Priority:** HIGH
**Rationale:** The kit-author OWNER Telegram bot token prefix `8415540095:` is baked into every GHOST customer deployment by the kit author via `min1.sh`. This is the highest-value supply-chain detection string for the GHOST commodity kit — a single string match catches ALL downstream operators regardless of their wallet, pool, IP, or operational configuration. Any host or file containing this specific bot token prefix is participating in the GHOST kit supply chain.
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1585.001 (Establish Accounts: Social Media)
**Confidence:** HIGH
**False Positive Risk:** LOW — Telegram bot token prefixes are globally unique assigned by the Telegram Bot API; `8415540095` is the specific numeric ID assigned to Vova75Rus's OWNER monitoring bot. No legitimate software shares this token prefix.
**Deployment:** Linux endpoint file scanning, memory scanning, network DLP (plaintext TLS-decryption-capable proxies), email gateway, SIEM log search

```yara
rule MAL_GHOST_OWNER_Telegram_Bot_Token_Indicator {
   meta:
      description = "Detects GHOST cryptojacker kit via kit-author Vova75Rus OWNER Telegram bot token prefix 8415540095: — baked into every GHOST customer deployment globally in min1.sh; single string match catches all downstream GHOST operators regardless of wallet, pool, or host configuration; supply-chain detection string covering entire GHOST kit customer base"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/"
      date = "2026-05-25"
      family = "GHOST-cryptojacker-kit"
      malware_type = "Supply-Chain Indicator"
      campaign = "OpenDirectory-GHOST-Cryptojacker-Vova75Rus-77.110.96.200"
      id = "f80c179f-1eb9-5088-87ac-05e44eccc4f2"
   strings:
      // Kit-author OWNER bot token prefix — globally unique Telegram bot ID
      // DO NOT alert on this in isolation from api.telegram.org contexts
      $owner_bot_prefix  = "8415540095:" ascii
      // Telegram API context strings — require at least one for confidence
      $tg_api_url        = "api.telegram.org" ascii
      $tg_bot_path       = "/bot8415540095:" ascii
      // GHOST dual-telegram context markers
      $tg_owner_ru       = "\xD0\x92\xD0\x9B\xD0\x90\xD0\x94\xD0\x95\xD0\x9B\xD0\x95\xD0\xA6" ascii  // ВЛАДЕЛЕЦ (OWNER in Russian)
   condition:
      filesize < 200KB and
      $owner_bot_prefix and
      ($tg_api_url or $tg_bot_path or $tg_owner_ru)
}
```

---

## Sigma Rules

### Sigma 1: ld.so.preload Modification — GHOST Rootkit Installation

**Detection Priority:** HIGH
**Rationale:** `/etc/ld.so.preload` is modified by non-package-manager processes on compromised hosts. This is the most critical single detection for the GHOST LD_PRELOAD rootkit — the file's modification is the persistent global-load trigger for every process on the system. Low-volume on production servers; package managers rarely touch this file.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — `/etc/ld.so.preload` is rarely modified in legitimate production environments. Package manager operations (dpkg/apt) do create it in some configurations; tune by excluding `dpkg`, `apt`, `ldconfig`, `update-alternatives` as parent processes.
**Deployment:** auditd + Sysmon for Linux (file_event on Linux)

```yaml
title: Linux LD_PRELOAD Persistence File Modification
id: f67e016e-dcd7-4ee3-a2ee-9477ad7f75c2
status: test
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
date: 2026/05/25
tags:
    - attack.persistence
    - attack.defense-evasion
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
    - System administrators manually adding a legitimate preload library for debugging or performance purposes (rare; verify path added to the file)
    - Package post-install scripts using ldconfig or update-alternatives to register new shared libraries
level: high
```

---

### Sigma 2: Malicious .so Created in PAM Library Directory

**Detection Priority:** HIGH
**Rationale:** The GHOST kit drops `libpam_cache.so` into `/lib/security/` using PAM-style naming camouflage. Creation of a `.so` file in `/lib/security/` or equivalent directories by a non-package-manager process is high-confidence malicious activity — legitimate PAM modules are always installed via package managers.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1027 (Obfuscated Files or Information), T1014 (Rootkit)
**Confidence:** HIGH
**False Positive Risk:** LOW — legitimate PAM module installation is exclusively done through package managers (dpkg, rpm); direct file creation from curl/bash/wget is not a legitimate PAM module deployment pattern
**Deployment:** auditd + Sysmon for Linux (file_event on Linux)

```yaml
title: Suspicious Shared Library Created in PAM Security Directory
id: 21b2646a-7e0b-4d6c-8392-d976b8388fa3
status: test
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
date: 2026/05/25
tags:
    - attack.defense-evasion
    - attack.persistence
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
    - Legitimate PAM module installation by package manager (filtered by exclusion above — confirm filter is working)
    - Manual PAM plugin deployment by system administrator (require change management verification)
level: high
```

---

### Sigma 3: LD_PRELOAD Environment Variable Set by Non-System Process

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit uses `/etc/ld.so.preload` for global persistence (not per-process LD_PRELOAD env var), but the env var path may appear in operator scripts or test deployments. More broadly, any production Linux server process starting with `LD_PRELOAD` pointing to a non-standard path is suspicious.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1059.004 (Unix Shell)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — LD_PRELOAD is legitimately used by `faketime`, `tsocks`, and various debugging/instrumentation tools; tune by excluding known-legitimate preload paths
**Deployment:** auditd PROCESS_TITLE (requires `name_format=hex`) or Sysmon for Linux (process_creation)

```yaml
title: Suspicious LD_PRELOAD Set to Non-Standard Library Path
id: 5cd034e9-ac04-4178-8a16-95f291c5d805
status: test
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
date: 2026/05/25
tags:
    - attack.defense-evasion
    - attack.persistence
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
    - Debugging or performance testing tools (ltrace, strace wrappers, faketime) using LD_PRELOAD with temporary paths
    - Software build systems that test custom shared libraries from temp directories
    - Some container runtimes that set LD_PRELOAD during container initialization
level: medium
```

---

### Sigma 4: auditd Watch — Shared Library Written to PAM Directory by Non-Package-Manager

**Detection Priority:** HIGH
**Rationale:** Specific auditd rule targeting the write-path detection for `/lib/security/*.so` creation. Complements Sigma 2 with a different log-source perspective (auditd PATH events vs Sysmon file_event). Useful for environments with auditd but no Sysmon for Linux deployment.
**ATT&CK Coverage:** T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit)
**Confidence:** HIGH
**False Positive Risk:** LOW — requires auditd `-w /lib/security -p wa -k pam_module_write` rule active
**Deployment:** auditd (auditd PATH record type)

```yaml
title: auditd - PAM Security Library Directory Write by Non-Package-Manager
id: f26bb12b-dca1-4b62-adf1-9186d5d31560
status: test
description: >-
    Detects auditd file write events (PATH record type with OPEN_W flag or CREATE)
    on the /lib/security/ directory. Requires auditd rule "-w /lib/security -p wa
    -k pam_module_write" to be active. The GHOST cryptojacker kit writes
    libpam_cache.so to this directory using PAM-style filename camouflage; any
    write from a non-package-manager process is a high-confidence rootkit drop.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.defense-evasion
    - attack.persistence
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

---

### Sigma 5: ComfyUI Fake PerformanceMonitor Custom Node Installed

**Detection Priority:** HIGH
**Rationale:** The GHOST kit plants a fake "PerformanceMonitor" Python custom node in the victim's ComfyUI installation for persistent execution. File creation events in ComfyUI's `custom_nodes/` directory with filenames containing "PerformanceMonitor" or content containing `class PerformanceMonitor` and `NODE_CLASS_MAPPINGS` are high-confidence indicators of GHOST kit persistence.
**ATT&CK Coverage:** T1554 (Compromise Host Software Binary), T1059.006 (Python)
**Confidence:** HIGH
**False Positive Risk:** LOW — "PerformanceMonitor" is not a standard ComfyUI custom node name; legitimate ComfyUI node development follows community naming conventions that include more-specific identifiers
**Deployment:** Linux file_event monitoring (auditd or Sysmon for Linux) on ComfyUI custom_nodes directory

```yaml
title: GHOST ComfyUI Fake PerformanceMonitor Custom Node Planted
id: df247923-595c-4760-9a97-f0722dbf664d
status: test
description: >-
    Detects GHOST cryptojacker kit persistence via malicious ComfyUI custom node
    installation. The GHOST Python kit's plant_backdoor_node() function creates a
    Python file containing class PerformanceMonitor registered into NODE_CLASS_MAPPINGS
    within the victim's ComfyUI custom_nodes/ directory. Any file creation event
    matching this pattern in a ComfyUI installation directory is a high-confidence
    indicator of GHOST kit compromise and should trigger immediate node audit.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.persistence
    - attack.execution
logsource:
    category: file_event
    product: linux
detection:
    selection_comfyui_node:
        TargetFilename|contains:
            - '/custom_nodes/PerformanceMonitor'
            - '/ComfyUI/custom_nodes/'
        TargetFilename|endswith: '.py'
    condition: selection_comfyui_node
falsepositives:
    - Legitimate custom ComfyUI node named PerformanceMonitor installed by authorized user (verify publisher and source repository before dismissing)
    - Development environments where test custom nodes are created in custom_nodes/ (scope exclusion for known dev hosts recommended)
level: high
```

---

### Sigma 6: High-Frequency ncat Listener Creation on Production Server

**Detection Priority:** MEDIUM
**Rationale:** The operator's bash history for 77.110.96.200 shows 83 `ncat` invocations — the highest-frequency command in the history. Chronic `ncat -l` listener creation on production Linux servers is an OPSEC-failure indicator of an active threat actor using the server for port testing, pivoting, or makeshift backdoors. A threshold of >20 ncat invocations per hour on a single host is anomalous.
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1571 (Non-Standard Port)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — ncat is a legitimate administration tool; high-frequency usage in isolation may reflect a busy administrator. The listener flag (`-l`) combined with high frequency is the key differentiator.
**Deployment:** Linux process_creation monitoring (auditd EXECVE or Sysmon for Linux Event ID 1)

```yaml
title: High-Frequency ncat Listener Creation on Linux Host
id: 4639e400-9a7d-495f-b7a3-a06de5f3c7db
status: test
description: >-
    Detects frequent ncat -l listener creation on a Linux host. The GHOST
    cryptojacker Operator-A showed 83 ncat invocations in bash history — the highest
    command frequency — indicating chronic use of ncat for port testing, makeshift
    backdoor channels, and lateral-movement probing. More than 20 ncat -l invocations
    per hour on a single production server is anomalous and indicates operator
    tradecraft activity. Requires aggregation / threshold logic in SIEM.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.command-and-control
    - attack.execution
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

---

### Sigma 7: Hysteria v2 Process Execution on Linux Server

**Detection Priority:** HIGH
**Rationale:** Hysteria v2 is a legitimate UDP/QUIC proxy tool repurposed here as a covert backdoor with bing.com SNI masquerade. Execution of a binary named `hysteria` on a production Linux server (particularly one hosting GPU workloads) is a high-confidence indicator of compromise. The GHOST kit installs it as a systemd service named `hysteria-server.service`.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1543.002 (Create or Modify System Process: Systemd Service)
**Confidence:** HIGH
**False Positive Risk:** LOW — Hysteria v2 is rarely used as a legitimate corporate tunneling tool on production GPU servers; its primary use cases are censorship circumvention (consumer) or covert C2 (threat actors)
**Deployment:** Linux process_creation monitoring (auditd EXECVE or Sysmon for Linux Event ID 1)

```yaml
title: Hysteria v2 QUIC Proxy Process Execution on Linux Server
id: e01c6689-1d47-4f6c-bf23-a71b32d88375
status: test
description: >-
    Detects execution of Hysteria v2 process on a Linux host. The GHOST cryptojacker
    kit installs Hysteria v2 as a covert QUIC/UDP backdoor with bing.com SNI masquerade
    (ports 14433/14444 UDP) using hyst.sh installer. Hysteria v2 execution on a
    production GPU server or ML workload host is a high-confidence indicator of GHOST
    kit compromise. The process is installed as systemd service hysteria-server.service
    with binaries in /usr/local/bin/hysteria.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
    - https://censys.com/ghost-cryptojacker-targeting-ai
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.command-and-control
    - attack.defense-evasion
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
    - Legitimate Hysteria v2 usage for censorship circumvention by employees in restrictive-internet regions (rare in corporate GPU environments; verify with owner)
    - Authorized network testing using Hysteria for VPN / proxy research purposes
level: high
```

---

### Sigma 8: DNS Query to Cryptomining Pool Domains

**Detection Priority:** HIGH
**Rationale:** DNS queries to `xmr.kryptex.network`, `etc.kryptex.network`, `cfx.kryptex.network`, `auto.c3pool.org`, and `cfx-asia1.nanopool.org` from any non-designated mining host indicate active cryptominer operation. These are the specific pool domains used by GHOST kit operators A and B respectively.
**ATT&CK Coverage:** T1496.001 (Resource Hijacking: Compute Hijacking), T1071.004 (Application Layer Protocol: DNS)
**Confidence:** HIGH
**False Positive Risk:** LOW — no legitimate corporate applications resolve these specific mining pool domains; any DNS resolution from production GPU/ML hosts is malicious
**Deployment:** DNS server logs, network DNS monitoring (Zeek dns.log, Pi-hole, Infoblox)

```yaml
title: DNS Query to GHOST Cryptojacker Mining Pool Domains
id: 9fc9cb2d-c3b6-4907-b92c-0e9ccee92d82
status: test
description: >-
    Detects DNS queries to mining pool domains used by GHOST cryptojacker kit
    operators. Kryptex.network domains (xmr/etc/cfx) are used by Operator-A;
    auto.c3pool.org and cfx-asia1.nanopool.org are used by Operator-B. Any DNS
    resolution of these domains from production ML/GPU servers is a high-confidence
    indicator of GHOST kit active mining operation or initial infection stage.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.impact
    - attack.command-and-control
logsource:
    category: dns_query
    product: linux
detection:
    selection_mining_pools:
        QueryName|endswith:
            - '.kryptex.network'
            - 'auto.c3pool.org'
            - 'cfx-asia1.nanopool.org'
    condition: selection_mining_pools
falsepositives:
    - Authorized cryptocurrency mining operations on designated mining hardware (scope exclusion for known mining hosts recommended)
    - Security researchers investigating these pools from sandbox environments
level: high
```

---

### Sigma 9: Systemd Unit Creation with GHOST Kit Camouflage Names

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit installs systemd services using camouflage names designed to blend with legitimate services. The specific names `fontconfig-cache.service`, `inotify_guard`, `dbus-session-monitor`, and `gnome-shell-ext-updater` appear in the rootkit hide-list and process disguise inventory — creation of systemd unit files with these names is a high-confidence indicator.
**ATT&CK Coverage:** T1543.002 (Create or Modify System Process: Systemd Service), T1036.005 (Masquerading: Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positive Risk:** LOW — these specific service names are not used by any standard Linux distribution package; `fontconfig-cache.service` and `gnome-shell-ext-updater` as systemd units are GHOST-kit-specific
**Deployment:** Linux file_event monitoring on systemd unit directories, auditd

```yaml
title: GHOST Kit Systemd Camouflage Service Unit Creation
id: 16fce30a-b59f-461c-87fc-89ae2d736527
status: test
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
date: 2026/05/25
tags:
    - attack.persistence
    - attack.defense-evasion
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
    - Custom legitimate service deployments using similar names (extremely unlikely for fontconfig-cache.service or gnome-shell-ext-updater.service as systemd units)
    - Desktop environment package that legitimately provides gnome-shell-ext-updater (verify package manager ownership with dpkg -S or rpm -qf)
level: medium
```

---

### Sigma 10: chattr Immutable Bit Set on Persistence Files

**Detection Priority:** HIGH
**Rationale:** The GHOST kit's `_lock_files` function uses `chattr +i` to set the immutable bit on persistence files including `/etc/ld.so.preload`, `/lib/security/libpam_cache.so`, and miner binary copies. `chattr +i` on system-level files by a non-root expected process, especially on `/etc/ld.so.preload`, is a high-confidence anti-removal tradecraft indicator.
**ATT&CK Coverage:** T1222.002 (File and Directory Permissions Modification: Linux), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — `chattr +i` on `/etc/ld.so.preload` or `/lib/security/` paths has no legitimate use case in standard Linux operations; immutable-bit locking of these files is exclusively an anti-forensics/anti-removal technique
**Deployment:** Linux process_creation monitoring (auditd EXECVE or Sysmon for Linux Event ID 1)

```yaml
title: chattr Immutable Bit Set on Linux Persistence Target Paths
id: f83a039f-885d-4759-a89c-2156a54e7ea5
status: test
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
date: 2026/05/25
tags:
    - attack.defense-evasion
    - attack.persistence
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
    - System hardening scripts that legitimately use chattr +i on selected configuration files (review CIS benchmark hardening scripts)
    - Container image build processes that lock certain system files (rare; typically not in /lib/security paths)
level: high
```

---

### Sigma 11: memfd_create High Frequency — Fileless Miner Execution

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit uses `memfd_create()` syscall for fileless miner execution — writing xmrig or lolMiner to an anonymous in-memory file descriptor and executing via `execveat()`. High-frequency `memfd_create` from a single process (>10 per minute) from a non-JVM/non-browser process on a Linux server is anomalous. Requires auditd syscall monitoring or Sysmon for Linux.
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** MODERATE
**False Positive Risk:** MEDIUM — `memfd_create` is used by legitimate JVM (Java), browser (Chromium), and some Python FFI libraries; scope to production ML/GPU servers where JVM and browsers are not expected
**Deployment:** auditd syscall monitoring (requires -a always,exit -F arch=b64 -S memfd_create -k fileless_exec) or Sysmon for Linux

```yaml
title: High-Frequency memfd_create Syscall from Non-JVM Process on Linux Server
id: 3d5c184d-4937-4ab0-93d6-778760e59b9c
status: test
description: >-
    Detects high-frequency memfd_create() syscall invocations from a single non-JVM
    process on a Linux server. The GHOST cryptojacker kit's _memfd_exec function uses
    memfd_create to create anonymous in-memory file descriptors for fileless xmrig and
    lolMiner execution via execveat(), bypassing on-disk file scanning. Requires
    auditd syscall monitoring with "-a always,exit -F arch=b64 -S memfd_create -k
    fileless_exec" rule active. Frequency threshold: >5 memfd_create calls from a
    single process within 60 seconds from a non-JVM/browser executable.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.defense-evasion
    - attack.execution
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
    - JVM-based applications (Java, Kotlin, Groovy) using memfd_create for native library loading — excluded by filter above
    - Python FFI libraries (ctypes, cffi) using memfd_create for anonymous shared memory
    - Legitimate fileless deployment tools used by authorized DevOps processes
level: medium
```

---

### Sigma 12: inotify Watch Created on /etc/ld.so.preload — Resurrection Loop

**Detection Priority:** MEDIUM
**Rationale:** The GHOST kit's `_inotify_guard` watchdog creates an inotify watch on persistence paths including `/etc/ld.so.preload`. A user-space process creating an inotify watch specifically on `/etc/ld.so.preload` is a near-unique indicator of a rootkit resurrection watchdog — no legitimate software monitors this file via inotify.
**ATT&CK Coverage:** T1547 (Boot or Logon Autostart Execution — via watchdog resurrection), T1574.006 (Dynamic Linker Hijacking)
**Confidence:** MODERATE
**False Positive Risk:** LOW — monitoring `/etc/ld.so.preload` via inotify has no standard legitimate use case; security monitoring tools (osquery, Falco) use different mechanisms
**Deployment:** auditd syscall monitoring (inotify_add_watch), Falco (if available)

```yaml
title: inotify Watch Created on LD_PRELOAD Persistence File — Rootkit Watchdog Indicator
id: d89cc92a-b3e0-4760-93cd-54d4b609c837
status: test
description: >-
    Detects user-space process creating inotify watch on /etc/ld.so.preload. The GHOST
    cryptojacker kit's _inotify_guard function creates a persistent watchdog process
    (hidden by the rootkit as inotify_guard) that monitors persistence file paths via
    Linux inotify API. Upon detecting defender removal attempts (IN_DELETE, IN_MODIFY,
    IN_MOVED_FROM events), the watchdog immediately re-writes the deleted persistence
    file. inotify watching of /etc/ld.so.preload by a non-security-monitoring process
    is a near-unique resurrection-loop indicator.
references:
    - https://the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/
author: The Hunters Ledger
date: 2026/05/25
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    product: linux
    service: auditd
detection:
    selection_inotify_preload:
        type: 'SYSCALL'
        syscall: 'inotify_add_watch'
    # Note: auditd records the path argument to inotify_add_watch in PATH records;
    # correlate SYSCALL record with subsequent PATH record containing /etc/ld.so.preload
    condition: selection_inotify_preload
falsepositives:
    - Security monitoring agents (Falco, osquery, auditd itself) that monitor ld.so.preload for integrity checking (add image-path exclusions for known security tools)
    - System integrity monitoring tools using inotify for file change detection
level: medium
```

---

## Suricata Signatures

### Suricata 1: DNS Query Egress to Kryptex/C3Pool/Nanopool Mining Domains

**Detection Priority:** HIGH
**Rationale:** DNS queries to GHOST kit mining pool domains from non-designated mining hosts. Covers both Operator-A pools (kryptex.network subdomain family) and Operator-B pools (auto.c3pool.org, cfx-asia1.nanopool.org). Threshold of 3 queries per 60 seconds reduces alert fatigue from normal DNS retry behavior while catching sustained mining operation.
**ATT&CK Coverage:** T1496.001 (Resource Hijacking: Compute Hijacking), T1071.004 (Application Layer Protocol: DNS)
**Confidence:** HIGH
**False Positive Risk:** LOW — no legitimate corporate applications resolve kryptex.network, c3pool.org, or nanopool.org mining endpoints
**Deployment:** Network IDS/IPS at perimeter, DNS monitoring tap

```suricata
alert dns $HOME_NET any -> any any (
    msg:"THL GHOST Cryptojacker Kit DNS Query to Mining Pool Domains";
    dns.query;
    content:".kryptex.network"; endswith; nocase;
    threshold: type threshold, track by_src, count 3, seconds 60;
    classtype:policy-violation;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity High, tag Cryptojacking, tag GHOST_kit;
    sid:9100101; rev:1;
)

alert dns $HOME_NET any -> any any (
    msg:"THL GHOST Cryptojacker Kit DNS Query to C3Pool/Nanopool Mining Domains";
    dns.query;
    pcre:"/^(auto\.c3pool\.org|cfx-asia1\.nanopool\.org|cfx\.kryptex\.network)$/i";
    threshold: type threshold, track by_src, count 2, seconds 60;
    classtype:policy-violation;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity High, tag Cryptojacking, tag GHOST_kit;
    sid:9100102; rev:1;
)
```

---

### Suricata 2: Hysteria v2 QUIC/UDP Egress with bing.com SNI from Server

**Detection Priority:** HIGH
**Rationale:** The GHOST kit's Hysteria v2 backdoor uses QUIC (UDP) on ports 14433/14444 with a TLS SNI of `bing.com` as covert masquerade. Outbound QUIC to these non-standard ports with a bing.com SNI from a production server host is a near-unique signature — legitimate bing.com QUIC traffic uses standard ports (443). Note: Deep TLS/QUIC inspection required for SNI visibility; this rule catches the UDP traffic pattern to the known operator ports as a coarser fallback.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1571 (Non-Standard Port)
**Confidence:** HIGH
**False Positive Risk:** LOW — UDP traffic to ports 14433/14444 from production servers is not associated with legitimate enterprise applications; the port combination matches the GHOST kit hide-port list exactly
**Deployment:** Network IDS/IPS at perimeter, server egress monitoring

```suricata
alert udp $HOME_NET any -> any 14433:14444 (
    msg:"THL GHOST Cryptojacker Kit Hysteria v2 QUIC Backdoor Egress — Known Operator Ports";
    threshold: type threshold, track by_src, count 5, seconds 60;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity Critical, tag Backdoor, tag GHOST_kit, tag Hysteria_v2;
    sid:9100103; rev:1;
)
```

---

### Suricata 3: HTTP GET for GHOST Kit Distribution Files from AEZA IP Range

**Detection Priority:** HIGH
**Rationale:** HTTP GET requests for known GHOST kit distribution filenames (`/libpam_cache.so`, `/ghost.sh`, `/hyst.sh`, `/min1.sh`) from the AEZA hosting range (77.110.0.0/16) where both confirmed operator servers reside. This catches victims downloading kit components during active GHOST kit installation.
**ATT&CK Coverage:** T1059.004 (Unix Shell), T1574.006 (Dynamic Linker Hijacking), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positive Risk:** LOW — these specific URI paths (`/libpam_cache.so`, `/ghost.sh`) have no legitimate usage on AEZA hosting infrastructure; any download of a `.so` file named `libpam_cache` is malicious
**Deployment:** Network IDS/IPS at perimeter, HTTP proxy inspection

```suricata
alert http $HOME_NET any -> 77.110.0.0/16 any (
    msg:"THL GHOST Cryptojacker Kit Distribution File Download from AEZA Hosting Range";
    http.uri;
    pcre:"/\/(libpam_cache\.so|ghost\.sh|hyst\.sh|min1\.sh|libpam_cache\.c)$/";
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity Critical, tag Dropper, tag GHOST_kit;
    sid:9100104; rev:1;
)
```

---

### Suricata 4: TLS to GitHub Fetching GHOST Kit ComfyUI Payload Repos

**Detection Priority:** MEDIUM
**Rationale:** Outbound TLS connections to `raw.githubusercontent.com` fetching paths matching `Vova75Rus/ComfyUI-Shell-Executor` or `jamestechdev-oss/ComfyUI-Shell-Plugin` indicate GHOST Python kit payload delivery. Both repos are deleted post-Censys but may be re-activated under different names; this rule catches the known-deleted repo paths as well as monitoring for GitHub SNI to these specific repo patterns. Note: the GitHub repos are deleted, so live traffic to these paths is unlikely from new campaigns, but may appear in compromised hosts replaying cached kit URLs.
**ATT&CK Coverage:** T1059.006 (Python), T1105 (Ingress Tool Transfer), T1554 (Compromise Host Software Binary)
**Confidence:** MODERATE
**False Positive Risk:** LOW for the specific repo paths (deleted repos); MEDIUM if GitHub SNI alone is used as filter
**Deployment:** Network IDS/IPS at perimeter, TLS inspection proxy

```suricata
alert tls $HOME_NET any -> any any (
    msg:"THL GHOST Cryptojacker Kit ComfyUI Payload Repo Download from GitHub";
    tls.sni; content:"raw.githubusercontent.com"; endswith; nocase;
    http.uri; pcre:"/(Vova75Rus\/ComfyUI-Shell-Executor|jamestechdev-oss\/ComfyUI-Shell-Plugin)/";
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity High, tag ComfyUI_exploit, tag GHOST_kit;
    sid:9100105; rev:1;
)
```

---

### Suricata 5: Outbound HTTP/HTTPS to GHOST Kit Operator Admin Panel Port 3301

**Detection Priority:** MEDIUM
**Rationale:** The Hysteria admin panel runs on port 3301 (HTTP) at `77.110.96.200:3301`. Victim hosts that have been compromised by Operator-A's GHOST kit will make callback requests to `77.110.96.200:3301/api/*` for Hysteria VPN registration (via `hyst.sh`'s `api_vpn_report` function). This catches victim callbacks to the admin panel.
**ATT&CK Coverage:** T1572 (Protocol Tunneling), T1102.002 (Web Service: Bidirectional Communication)
**Confidence:** HIGH
**False Positive Risk:** LOW — port 3301 HTTP traffic to 77.110.96.200 from corporate environments has no legitimate purpose
**Deployment:** Network IDS/IPS at perimeter

```suricata
alert http $HOME_NET any -> 77.110.96.200 any (
    msg:"THL GHOST Cryptojacker Kit Operator-A Hysteria Admin Panel Callback";
    http.uri; content:"/api/"; startswith;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity Critical, tag C2, tag GHOST_kit;
    sid:9100106; rev:1;
)
```

---

### Suricata 6: Telegram API Egress Containing GHOST OWNER Bot Token Prefix

**Detection Priority:** HIGH
**Rationale:** The GHOST kit OWNER Telegram bot token prefix `8415540095:` appears in HTTP POST bodies to `api.telegram.org`. This is the highest-value supply-chain network detection — any host sending a Telegram bot API request with this specific token prefix is a confirmed GHOST kit victim. Requires TLS-decryption-capable IDS deployment (inline proxy or network tap with certificate pinning bypass). On environments without TLS decryption, the `tls.sni` match on `api.telegram.org` combined with destination filtering provides coarser coverage.
**ATT&CK Coverage:** T1102.002 (Web Service: Bidirectional Communication), T1496.001 (Resource Hijacking: Compute Hijacking)
**Confidence:** HIGH
**False Positive Risk:** LOW — the numeric Telegram bot ID prefix `8415540095` is globally unique; no legitimate application shares this bot token
**Deployment:** TLS-decryption-capable inline IDS/IPS or proxy with DLP inspection; fallback TLS SNI rule for environments without decryption

```suricata
# Rule A: TLS-decryption-capable environments (plaintext HTTP body inspection)
alert http $HOME_NET any -> any any (
    msg:"THL GHOST Cryptojacker Kit OWNER Telegram Bot Token in API Request — Supply Chain Indicator";
    tls.sni; content:"api.telegram.org"; endswith; nocase;
    http.request_body; content:"8415540095:"; nocase;
    classtype:trojan-activity;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Internal, performance_impact Medium, signature_severity Critical, tag Supply_Chain, tag GHOST_kit, tag Telegram_C2;
    sid:9100107; rev:1;
)

# Rule B: Coarser fallback for environments without TLS decryption — Telegram egress from production GPU/ML server
alert tls $HOME_NET any -> any any (
    msg:"THL GHOST Cryptojacker Kit Telegram API Egress from Production Server — Covert Mining Report";
    tls.sni; content:"api.telegram.org"; endswith; nocase;
    threshold: type threshold, track by_src, count 5, seconds 300;
    classtype:policy-violation;
    reference:url,the-hunters-ledger.com/hunting-detections/ghost-cryptojacker-vova75rus-77.110.96.200-detections/;
    metadata:affected_product Linux, attack_target Server, deployment Perimeter, performance_impact Low, signature_severity High, tag GHOST_kit, tag Telegram_reporting;
    sid:9100108; rev:1;
)
```

---

## Coverage Gaps

The following MITRE ATT&CK techniques observed in the GHOST kit analysis could not be covered with high-confidence rules, along with the evidence gaps that prevent rule creation:

**T1611 (Escape to Host) — container-escape behavioral rules not written**
The four escape variants (`_escape_via_cgroup`, `_escape_via_mount`, `_escape_via_nsenter`, `_escape_via_socket`) are documented in ghost.sh source but behavioral detection requires PCAP capture or runtime monitoring of the specific syscall sequences (e.g., writes to `/sys/fs/cgroup/.../release_agent`, bind-mount namespace operations). No PCAP capture was performed in this investigation (open-directory artifact pull only). Container-escape detection is also highly environment-specific (Falco / kube-bench / sysdig are the appropriate tools, not generic Sigma rules). The function names in ghost.sh can be detected via YARA Rule 3 (Kit Shell Installer) as a proxy.

**T1552.004 (Unsecured Credentials: Private Keys) — SSH key harvest rule not written**
The ghost.sh `_harvest_keys` function reads `~/.ssh/known_hosts` and SSH private key files for lateral movement. A generic Sigma rule for SSH key file access is high-FP (legitimate SSH tools access the same files constantly). No specific command-line pattern or access sequence distinguishes the GHOST kit's SSH key harvest from legitimate SSH client activity. Evidence needed: specific process or command-line pattern that makes the harvest unique (e.g., a specific variable name or grep pattern that appears in ghost.sh's key-harvest code).

**T1021.004 (Remote Services: SSH) — lateral movement Sigma rule not written**
The ghost.sh `_lateral_move`, `_discover_targets`, and `_spread_to_host` functions implement SSH lateral movement using harvested keys. Detection requires correlating SSH connections from a known-compromised host to new targets combined with the specific `StrictHostKeyChecking=no` SSH flag pattern used by the kit. This behavioral correlation requires multi-event SIEM logic beyond a single Sigma rule scope, and the FP rate from legitimate `StrictHostKeyChecking=no` admin usage would be high without additional context.

**Censys JA3/JA3S/JA4 fingerprint — TLS fingerprint Suricata rule not written**
The task specification requested a Suricata rule based on "ReconProject TLS thumbprint match (per Censys 2026-04-07): JA3/JA3S/JA4 fingerprint." The Censys disclosure referenced general infrastructure fingerprints (JARM/JA4X) for the server at 77.110.96.200, but the specific JA3/JA3S hash values were not captured in this investigation's artifact set. Writing a Suricata `ja3.hash` or `ja3s.hash` rule requires the exact hash values computed from a live TLS session or PCAP capture. No PCAP was captured. Evidence needed: live TLS connection to 77.110.96.200 with PCAP capture + ja3print/ja3s analysis to extract the exact hash values.

**T1070.002 / T1070.003 (Clear Linux Logs / Clear Command History) — log clearing rule not written**
The ghost.sh `_cloak` function touches or clears `/var/log/{auth,boot,cron,daemon,kern,messages,secure,syslog}.log` and runs `history -c`. A Sigma rule for log truncation would fire on every legitimate log rotation event (logrotate). Distinguishing GHOST kit log clearing from legitimate `logrotate` would require detecting rapid sequential truncation of multiple log files in a short window — a SIEM aggregation query rather than a Sigma rule. Evidence needed: specific log clearing command pattern in ghost.sh's `_cloak` function that is more specific than the generic log-file paths.

**ComfyUI exploitation CVE/mechanism — no exploit-signature rule possible**
The specific CVE or vulnerability mechanism that `py.py`'s `find_target_nodes()` exploits to gain initial code execution in ComfyUI has not been identified (marked as deferred to follow-up investigation requiring detonation in isolated ComfyUI environment). No exploit signature rule can be written without understanding the exploitation path. Evidence needed: ComfyUI-side detonation analysis identifying which API endpoint or deserialization vulnerability the kit exploits for initial payload execution.

**Operator-B behavioral indicators — insufficient unique signatures**
Operator-B (77.110.125.145) is confirmed abandoned (40+ days inactive, last on-chain activity 2026-04-12). The operator's `New_scanner.py` contains distinctive Cyrillic strings but the operator-B host has been offline and no unique behavioral indicators beyond the shared kit-level rules were identified. Rules targeting 77.110.125.145 specifically were omitted since the host is confirmed inactive; if reactivated, the kit-level YARA and Sigma rules in this file will catch the deployment.

**Memfd_create / execveat fileless execution — incomplete coverage**
The `memfd_create` + `execveat` fileless execution pattern (Sigma 11) detects the syscall but cannot distinguish GHOST kit miner execution from legitimate use of the same pattern by JVM, browsers, or other applications without additional context (process ancestry, CPU/GPU usage spike correlation). Defenders deploying Sigma 11 should tune by adding process-ancestry filters for the specific expected parent process chain on their GPU servers.

---

## License
Detection rules are licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.
Free to use in your environment, but not for commercial purposes.
