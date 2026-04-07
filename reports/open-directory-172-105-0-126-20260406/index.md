---
title: "OpenStrike Beacon Toolkit — Open Directory 172.105.0.126"
date: '2026-04-06'
last_updated: '2026-04-07'
layout: post
permalink: /reports/open-directory-172-105-0-126-20260406/
hide: true
category: "Cybercrime Toolkit"
description: "First public analysis of OpenStrike, a novel multi-implant C2 toolkit recovered from an open directory on 172.105.0.126 before any known compromise, featuring a tripwired Cobalt Strike DLL and cross-platform Python beacon sharing an identical RSA-2048 key."
detection_page: /hunting-detections/open-directory-172-105-0-126-20260406-detections/
ioc_feed: /ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "172.105.0[.]126"
    note: "C2 server — all beacon variants, port 8443"
  - value: "7d6a17754f086b53ee294f5ccd60b0127f921520ce7b64fea0aebb47114fb5d2"
    note: "beacon.exe — custom C beacon (SHA256)"
  - value: "7a1a7659ec4201ecbca782bcedf9d4079265137279a490368309df3bd39297a4"
    note: "beacon_universal.py — Python beacon (SHA256)"
  - value: "eed84220ed7365b87d504f7709bd89ba2e255159d52f214f40a435ff78696eb6"
    note: "beacon_patched.x64.dll — CS DLL (SHA256)"
---

**Campaign Identifier:** OpenStrike-CSBeacon-Toolkit-172.105.0.126<br>
**Last Updated:** April 7, 2026<br>
**Threat Level:** HIGH<br>
**Investigation Status:** ONGOING — expanded toolkit discovery under analysis (see [Section 13](#13-ongoing-investigation-expanded-toolkit-discovery))

---

## Bottom Line Up Front

- **What it is:** A novel, previously undocumented multi-implant C2 toolkit self-named **"OpenStrike"** by its author (from source code docstrings, not an analyst designation) — three beacon variants (custom C, Python, cracked Cobalt Strike DLL), five shellcode loaders, and nine operator utility scripts — recovered from an open directory before any known compromise
- **Risk level:** HIGH (7.5/10 overall) — no persistence, but evasion mechanisms create blind spots in GET-based exfil detection and standard CS injection defenses
- **Deployment status:** No victims identified; toolkit recovered pre-compromise via infrastructure-first discovery
- **Top hunt indicator:** `GET /qz99` on port 8443 — short, non-standard, minimal false-positive risk in enterprise proxy logs
- **Immediate action:** Block `172.105.0.126` at perimeter (all ports, bidirectional); deploy YARA/Sigma rules from the detection file
- **Investigation status:** ONGOING — 116 additional files (full CS deployment including Mimikatz, artifact kit, DNS/SMB beacons) discovered on April 7 and under analysis ([Section 13](#13-ongoing-investigation-expanded-toolkit-discovery))

---

## 1. Executive Summary

This investigation documents a novel, previously undocumented multi-implant C2 toolkit called **"OpenStrike"** — a name chosen by the toolkit's author, not by this publication. The name appears in the Python beacon's source code docstring: `"OpenStrike Universal Beacon — Single-File Cross-Platform Implant"` and in the BOF executor module: `"OpenStrike BOF Executor"`. The toolkit was recovered from an open directory on a Linode VPS at `172.105.0.126`, had zero VirusTotal coverage at time of discovery, and its C2 protocol internals — an AES-128-CBC + HMAC-SHA256 cryptographic envelope shared across three distinct beacon variants via a single RSA-2048 key, here termed the "Trinity Protocol" — were not previously documented in public threat research. This report closes that gap, providing defenders with the first full technical analysis of OpenStrike's architecture, detection surface, and protocol internals.

**What Was Found**

A complete attacker operator kit recovered before any known compromise: three beacon implant variants (a custom C Windows beacon, a cross-platform Python implant, and a cracked Cobalt Strike 3.x DLL), five shellcode loaders forming a progressive development chain, and nine Python utility scripts covering EDR reconnaissance through beacon deployment. All seven binary samples share a single build environment (MinGW-w64 GCC 15, released April 2025), placing active development in late 2025 or early 2026. The discovery was made via hunt.io's open directory capture system — an infrastructure-first discovery method that identified the toolkit before any victim could be identified.

**Why This Threat Is Significant**

OpenStrike is notable for three reasons that create specific defender blind spots. First, the cracked Cobalt Strike DLL component has its `ReflectiveLoader` export patched to three bytes (`66 90 CC` — NOP + INT3), crashing every standard reflective injection tool that attempts to load it; this forces use of the operator's custom loader chain, which means standard CS injection defenses do not apply. Second, the DLL beacon routes all command output via HTTP GET requests through a 17-opcode Malleable C2 bytecode virtual machine — not via POST. Detection infrastructure tuned to "POST = data exfiltration" will silently miss this traffic. Third, all three implant variants share an identical RSA-2048 public key, meaning a single C2 server manages all beacon types simultaneously and memory-forensic session key recovery at documented offsets enables retroactive decryption of all captured traffic.

**Key Risk Factors**

<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Dimension</th>
      <th class="numeric">Score</th>
      <th>Rationale</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Data Exfiltration</strong></td>
      <td class="numeric high">7.5/10</td>
      <td>Arbitrary file read (CMD_DOWNLOAD, up to 10 MB), full shell execution enabling credential tooling, SOCKS4a proxy in Python beacon for lateral pivot</td>
    </tr>
    <tr>
      <td><strong>System Compromise</strong></td>
      <td class="numeric high">8.0/10</td>
      <td>Full remote shell (cmd.exe /c), file upload/download, process enumeration, cross-platform reach via Python beacon (Windows, Linux, macOS)</td>
    </tr>
    <tr>
      <td><strong>Evasion Capability</strong></td>
      <td class="numeric high">8.5/10</td>
      <td>Tripwired ReflectiveLoader defeats standard injection tooling; GET-based exfil evades POST detection rules; TLS on non-standard port 8443; EDR hook detection utility (check_ntdll.py)</td>
    </tr>
    <tr>
      <td><strong>Persistence Difficulty</strong></td>
      <td class="numeric medium">3.0/10</td>
      <td>No persistence mechanisms observed across all samples; toolkit requires operator-controlled redeployment (favors defenders — beacon stops if host reboots)</td>
    </tr>
    <tr>
      <td><strong>Detection Difficulty</strong></td>
      <td class="numeric high">7.5/10</td>
      <td>Zero prior AV/TI coverage; non-standard port; GET-based exfil blind spot; no disk artifacts beyond operator-placed payload files</td>
    </tr>
    <tr>
      <td><strong>Infrastructure Flexibility</strong></td>
      <td class="numeric medium">5.0/10</td>
      <td>Single hardcoded C2 IP with no DGA or fallback; partially offset by multi-implant diversity and cross-platform reach</td>
    </tr>
  </tbody>
</table>

**Overall Risk Score: 7.5/10 — HIGH**

**Threat Actor**

Attribution is INSUFFICIENT (<50% confidence). The operator is tracked internally as UTA-2026-004 *(an internal tracking label used by The Hunters Ledger — see [Section 7](#7-threat-actor-assessment))*. Technical behavioral indicators (cracked CS watermark=0, GCC 15.1 build environment, single shared RSA key, open directory OPSEC failure) are most consistent with an independent skilled developer or small private group, not a nation-state APT or MaaS operator.

**For Technical Teams**

- The most distinctive single indicator is the GET request to `/qz99` on port 8443 (shellcode staging endpoint) — hunt this in proxy and firewall logs first
- The hardcoded AES IV `abcdefghijklmnop` (hex: `6162636465666768696a6b6c6d6e6f70`) is present in process memory of any active beacon and serves as a reliable in-memory hunt indicator
- Session keys at documented offsets (`image_base + 0x40430` AES, `image_base + 0x40440` HMAC) enable retroactive decryption of all captured C2 traffic if memory is preserved prior to remediation
- See [Section 10](#10-detection-rules--hunting-queries) for full detection rules (YARA, Sigma, Suricata) and [Section 9](#9-indicators-of-compromise) for the IOC feed
- The tripwired ReflectiveLoader (`66 90 CC` at DLL export target) is YARA-detectable as a static signature on disk

---

## 2. Sample Inventory & Static Analysis

### 2.1 Sample Inventory

> **Analyst note:** This section catalogs the seven binary samples and nine Python scripts recovered from the open directory. Each entry includes the original filename, cryptographic hash, compiler, and analysis status. The binary samples are Windows PE executables; Python scripts require the Python interpreter to run and are cross-platform.

All samples were recovered from an open directory on `172.105.0.126` via hunt.io's AttackCapture system (a continuous internet scanning service that indexes misconfigured servers and automatically downloads exposed files). No dynamic sandbox analysis was performed; all behavioral inferences are derived from static reverse engineering.

<table class="professional-table">
  <thead>
    <tr>
      <th>Filename</th>
      <th>SHA256 (truncated)</th>
      <th>Size</th>
      <th>Compiler</th>
      <th>Analysis Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>beacon.exe</strong></td>
      <td><code>7d6a1775...fb5d2</code></td>
      <td>298,884 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="confirmed">Fully reversed</td>
    </tr>
    <tr>
      <td><strong>beacon_patched.x64.dll</strong></td>
      <td><code>7a1a7659...297a4</code></td>
      <td>265,728 B</td>
      <td>MSVC 2012 17.00.61219</td>
      <td class="confirmed">Fully reversed</td>
    </tr>
    <tr>
      <td><strong>stager.exe</strong></td>
      <td><code>eed84220...6eb6</code></td>
      <td>122,792 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="confirmed">Fully reversed</td>
    </tr>
    <tr>
      <td><strong>dbg_loader.exe</strong></td>
      <td><code>74d1b5b8...b279</code></td>
      <td>261,302 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="confirmed">Fully reversed</td>
    </tr>
    <tr>
      <td><strong>veh_loader.exe</strong></td>
      <td><code>ab68ce00...d3c3</code></td>
      <td>260,711 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="confirmed">Fully reversed</td>
    </tr>
    <tr>
      <td><strong>run.exe</strong></td>
      <td><code>821f815f...d273</code></td>
      <td>258,250 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="likely">Triaged</td>
    </tr>
    <tr>
      <td><strong>sc_loader.exe</strong></td>
      <td><code>544b59fe...ee5f</code></td>
      <td>259,892 B</td>
      <td>MinGW GCC 15-win32</td>
      <td class="likely">Triaged</td>
    </tr>
  </tbody>
</table>

**Build environment uniformity:** All six EXEs share identical compiler flags (`-m64 -masm=att -mtune=generic -march=x86-64 -g -O2 -fno-builtin -fno-PIE`), confirming a single build workstation. The GCC 15 release date (April 25, 2025) establishes a hard floor for toolkit development: all custom binaries were compiled no earlier than late 2025. The DLL uses MSVC 2012 — the canonical compiler for Cobalt Strike 3.x — confirming it was sourced from a pre-existing cracked distribution, not built by the OpenStrike operator.

**Overlay data:** Five of the six EXEs carry PE overlays (43–62 KB appended after the legitimate PE end). These contain COFF metadata or shellcode blobs and represent an additional payload layer; standard PE parsers do not process overlay data by default.

**Python scripts recovered (9 total):**

| Script | Role |
|---|---|
| `beacon_universal.py` | Core cross-platform implant (687 lines) |
| `bof_executor.py` | BOF execution engine with embedded C source (438 lines) |
| `loader.py` / `loader2.py` | Minimal shellcode loaders (`C:\payload.bin` / `C:\payload.dat`) |
| `run_beacon.py` | Named beacon shellcode runner |
| `py_thread_loader.py` | Production loader (8 MB stack, 30 s timeout, `C:\cs_final.dat`) |
| `py_debug_loader.py` | Debug loader with ReflectiveLoader offset scanner |
| `test_sc.py` | Shellcode test harness (RET sanity check + payload) |
| `check_ntdll.py` | ntdll.dll hook detection utility |

---

### 2.2 Beacon Implant Analysis

#### 2.2.1 beacon_patched.x64.dll — Cracked Cobalt Strike 3.x DLL Beacon

> **Analyst note:** This section covers the Cobalt Strike DLL component — a pre-existing cracked implant that the OpenStrike operator sourced and then modified. Cobalt Strike is a legitimate commercial penetration testing framework (sold by Fortra) that is widely abused by cybercriminals and nation-state actors. Two critical structural modifications were made to this specific DLL: a tripwired export that crashes analysis tools, and a Malleable C2 bytecode interpreter that routes command output through HTTP GET rather than POST.

**DEFINITE (config extraction via config extraction tool (1768.py)) — CS 3.x cracked beacon**

Extracted configuration via the config extraction tool:

| Config Field | Value | Significance |
|---|---|---|
| XOR config key | `0x2E` | CS 3.x encoding scheme |
| C2 server | `172.105.0.126:8443` | Non-standard HTTPS port |
| Staging URI | `/updates` (GET) | Task poll endpoint |
| Submission URI | `/submit` (POST) | Bulk-data exfil endpoint |
| Sleep interval | 5,000 ms | 5-second beacon interval |
| Jitter | 10% | Effective range: 4,500–5,500 ms |
| Watermark | `0` | Cracked/license-stripped identifier |
| Config fields total | 10 of ~40 standard | Dramatically trimmed minimal config |
| Spawn-to process | `%windir%\sysnative\rundll32.exe` | Standard CS post-exploitation masquerade |
| User-Agent | `Mozilla/5.0 ... MALC` | "MALC" suffix — Malleable C2 profile marker |

**Watermark=0:** The CS license watermark uniquely identifies each licensed installation. Zero is the most commonly observed value in cracked deployments and reliably indicates a pirated/license-stripped build. This confirms the operator did not use a commercially licensed CS installation.

**Trimmed config:** With only 10 config fields versus the standard 25–40+, the DLL lacks many of the encoding patterns that CS-specific detection tools scan for. This reduces — at MODERATE confidence — the beacon's detectable surface area against config-pattern-matching detection strategies.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-config-extraction.png" | relative_url }}" alt="Terminal output from the 1768.py config extraction tool showing the decoded Cobalt Strike 3.x configuration including watermark value zero, C2 server address 172.105.0.126 on port 8443, staging URI /updates, submission URI /submit, GET and POST verb assignments, Mozilla user-agent string, and license-id zero confirming a cracked build.">
  <figcaption><em>Figure 1: Cobalt Strike configuration extracted via 1768.py showing watermark=0 (cracked), the /qz99 staging URI on port 8443, and the CS version 3 identifier. Only 10 of the standard 25–40+ config fields are populated — a deliberately trimmed configuration that reduces the beacon's detectable surface area.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-config-decoder-xor2e.png" | relative_url }}" alt="Ghidra decompilation showing the XOR 0x2E configuration decoding loop in beacon_patched.x64.dll, with highlighted memcpy calls copying decoded config fields from the XOR-encrypted blob into working memory structures used by the beacon at runtime.">
  <figcaption><em>Figure 2: The XOR 0x2E configuration decoding loop inside the CS DLL. Each config field is XOR-decoded from the embedded blob at DLL initialization — this is the mechanism that produces the configuration values shown in Figure 1. The 0x2E key is a reliable CS 3.x version fingerprint.</em></figcaption>
</figure>

#### The Tripwired ReflectiveLoader — DEFINITE

> **Analyst note:** The ReflectiveLoader is a function exported from every Cobalt Strike DLL. Its purpose is to load the DLL's code directly into memory, bypassing the operating system's normal DLL loading mechanism. Dozens of security tools and attack frameworks automatically call this export when loading CS beacons. The OpenStrike operator replaced the export's target with three bytes that cause an immediate crash — trapping any tool that tries to use it.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-symbol-tree-exports.png" | relative_url }}" alt="Ghidra Symbol Tree panel showing the beacon_patched.x64.dll exports folder containing only two entries: the standard entry point and the ReflectiveLoader export — confirming that the DLL exposes the minimum possible attack surface with only the ReflectiveLoader available for external callers to invoke.">
  <figcaption><em>Figure 3: The CS DLL's export table in Ghidra — only two exports exist: the standard PE entry point and ReflectiveLoader. Every injection tool that attempts to load this DLL will call ReflectiveLoader, walking directly into the tripwire shown in Figure 4.</em></figcaption>
</figure>

The `ReflectiveLoader` DLL export was modified via a single 4-byte edit to the PE export directory. The export entry point was redirected to three existing bytes already in the PE:

```
66 90    ; xchg ax, ax  (2-byte NOP — harmless padding instruction)
CC       ; int3          (software breakpoint — triggers EXCEPTION_BREAKPOINT)
```

Any tool that calls `ReflectiveLoader` — including sRDI, Cobalt Strike's own reflective injection, Donut, and generic post-exploitation frameworks — triggers `EXCEPTION_BREAKPOINT` and crashes the host process.

**Three compounding consequences:**

1. The DLL cannot be loaded via any standard injection tool that honors the ReflectiveLoader convention
2. All five custom loader EXEs are mandatory to load the DLL correctly — the tripwire enforces use of the operator's specific toolchain
3. `DllMain` on `PROCESS_ATTACH` only decodes the XOR config and returns; it does not spawn the beacon thread. This makes the loader EXEs mandatory for a second independent reason

**Detection on disk:** The byte sequence `66 90 CC` at the `ReflectiveLoader` export target is reliably detectable by YARA on disk and in memory. This is documented in the detection file.

**Novelty:** Redirecting the export directory RVA to existing NOP+INT3 padding bytes — rather than writing new code — is not documented in public threat research as of 2026-04-06. It is a structurally elegant minimal-edit technique.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-reflective-loader-tripwire.png" | relative_url }}" alt="Ghidra disassembly view showing the ReflectiveLoader export at address 0x1709c with the tripwire byte sequence: 66 90 (xchg ax,ax two-byte NOP) followed by CC (INT3 software breakpoint), alongside the decompiled view showing swi(3) — the Ghidra representation of the INT3 instruction that crashes any tool attempting to call the export.">
  <figcaption><em>Figure 4: The tripwired ReflectiveLoader — Ghidra disassembly showing the 3-byte sequence (66 90 CC) at the export target address. The decompiled swi(3) call confirms the INT3 breakpoint that crashes any standard reflective injection tool attempting to load this DLL.</em></figcaption>
</figure>

#### Malleable C2 Transform VM — DEFINITE

> **Analyst note:** Cobalt Strike allows operators to customize their network traffic's appearance using a feature called Malleable C2. Operators write a "profile" describing how traffic should be formatted — which headers to include, how data should be encoded, whether to use GET or POST. This profile is compiled into a small bytecode program that runs inside the beacon. The beacon executes this program before sending any network request. Stage 1 analysis fully reversed this bytecode interpreter.

Function `FUN_180015838` (2,188 bytes) in `beacon_patched.x64.dll` is a complete bytecode VM implementing the CS Malleable C2 transform system. It reads operator-configurable bytecode from the config blob and transforms HTTP request components (headers, URI, query parameters) per the profile.

**17 opcodes identified** — publicly available reverse engineering has documented 7–8 opcodes from this VM (usualsuspect.re, Tier 3 / C2; cross-referenced with official CS documentation). The 17-opcode count represents extended documentation coverage for this component, derived from this analysis and not previously documented publicly.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-transform-vm-dispatch.png" | relative_url }}" alt="Ghidra decompilation of the Malleable C2 transform VM dispatch function FUN_180015838 showing local variables for opcode processing, loop control structures, and the conditional branching that routes execution through 17 distinct opcode handlers for transforming HTTP request components.">
  <figcaption><em>Figure 5: The 17-opcode Malleable C2 transform VM dispatch loop (FUN_180015838, 2,188 bytes). This bytecode interpreter reads operator-configurable transforms from the config blob and reshapes HTTP request components — enabling the GET-based exfiltration pattern that inverts standard CS detection assumptions.</em></figcaption>
</figure>

**Critical finding — GET-based exfiltration:** The transform VM routes all command output through HTTP **GET** requests, not POST. This is a documented CS capability (Malleable C2 controls GET vs POST behavior) but is not the default pattern analysts and detection tools expect.

**Why this creates a blind spot:** The DFIR Report's CS Defender's Guide (Tier 2 / B2) establishes the baseline defensive expectation: "Beacons typically use GET requests to retrieve tasking and POST requests to exfiltrate command results." The OpenStrike DLL beacon deliberately inverts this. The 2 MB output accumulator fills records before flushing, producing a bimodal GET size pattern — small heartbeat GETs (task polls) alternating with large flush GETs (command output) to the same URI — that is detectable with size distribution analytics but not by simple GET/POST heuristics.

**Session key recovery offsets** (for memory forensics during incident response):

```
AES-128 session key:    image_base + 0x40430  (16 bytes)
HMAC-SHA256 key:        image_base + 0x40440  (16 bytes)
IV (hardcoded static):  image_base + 0x40450  ("abcdefghijklmnop")
Beacon-ready flag:      image_base + 0x3D004  (1 = registered and active)
Output accumulator ptr: image_base + 0x3F480  (pointer to 2 MB plaintext buffer)
```

---

#### 2.2.2 beacon.exe — Custom C OpenStrike Beacon

> **Analyst note:** Unlike the Cobalt Strike DLL, beacon.exe is entirely custom-written in C by the OpenStrike operator. It implements the same cryptographic protocol as the DLL but uses a simpler 11-command set. It is best understood as a lightweight reconnaissance and file transfer tool — it can run shell commands, list files and processes, and transfer files, but lacks the advanced post-exploitation capabilities of the full CS toolkit.

**DEFINITE (static analysis) — custom C implementation of the OpenStrike wire protocol**

Compiled with MinGW-w64 GCC 15, debug symbols partially intact (function names visible in the binary). Not a Cobalt Strike beacon — config extraction returns no valid CS structure.

**Command set (11 commands):**

| CMD ID | Name | Capability |
|---|---|---|
| `0x02` | CMD_SHELL | `cmd.exe /c` via CreatePipe + CreateProcessA, 30 s timeout |
| `0x03` | CMD_EXIT | Clear running flag, send exit acknowledgement |
| `0x04` | CMD_SLEEP | Update sleep interval and jitter parameters |
| `0x05` | CMD_CD | Change working directory |
| `0x06` | CMD_NOP | No-operation (keepalive) |
| `0x0A` | CMD_UPLOAD | Write operator-supplied file to disk |
| `0x0B` | CMD_DOWNLOAD | Read file from disk (up to 10 MB) |
| `0x1B` | CMD_GETUID | Return `hostname\username` |
| `0x20` | CMD_PS | Process list via CreateToolhelp32Snapshot |
| `0x27` | CMD_PWD | Return current working directory |
| `0x35` | CMD_LS | Directory listing via FindFirstFileA / FindNextFileA |

**Wire protocol (DEFINITE — fully reversed):**

```
Frame structure:
  [length: 4 bytes, big-endian]
  [sequence: 4 bytes, big-endian]
  [reserved: 00 00 00]
  [response_type: 1 byte]
  [data: N bytes]

Encryption:
  1. AES-128-CBC(aes_key, IV="abcdefghijklmnop", plaintext_frame) → ciphertext
  2. HMAC-SHA256(hmac_key, ciphertext)[:16] → 16-byte MAC appended

Transmission:
  POST /submit?id=<beacon_id_hex8>
```

**Cryptographic functions (DEFINITE):**

- `aes_cbc_encrypt`: Windows BCrypt API, AES-128-CBC, hardcoded IV `abcdefghijklmnop`, PKCS#7 padding
- `hmac_sha256_trunc16`: Windows BCrypt HMAC-SHA256, output truncated to 16 bytes
- `aes_encrypt_mac`: Encrypt-then-MAC composite — the more secure construction order
- `aes_decrypt_verify`: Verify-then-decrypt with non-constant-time 64-bit tag comparison (timing side-channel present; LOW practical risk over network)

**Operational gaps indicating development/testing artifact:**

- Internal IP hardcoded to `127.0.0.1` (no real interface enumeration)
- Process name hardcoded as `"beacon.exe"` regardless of filename after rename
- No anti-analysis, anti-debug, sleep mask, or sandbox evasion
- Single hardcoded C2 with no DGA or fallback

These gaps suggest `beacon.exe` is a development-phase artifact. The DLL beacon is the production-grade implant.

---

#### 2.2.3 beacon_universal.py — Cross-Platform Python Implant

> **Analyst note:** This Python script implements a full beacon that runs on Windows, Linux, and macOS without recompilation. It implements 23 commands — a superset of beacon.exe's capabilities — including a SOCKS4a proxy that enables network pivoting (routing the attacker's traffic through the compromised host to reach other internal systems) and a BOF executor that compiles C code on the target at runtime using the system's installed GCC compiler.

**DEFINITE (source code analysis) — self-described "OpenStrike Universal Beacon"**

Source code self-identification: `"OpenStrike Universal Beacon — Single-File Cross-Platform Implant"`. 687 lines of Python. CS-protocol-compatible design by operator intent.

**Extended command set (23 commands):** Full superset of beacon.exe capabilities, adding SOCKS4a proxy, TCP connect shell, BOF execution, process kill/spawn, and graceful reconnect with configurable retry logic.

**Transport protocol (source code analysis):**

```
Registration:  GET /register    Cookie: session=<b64(RSA-enc(metadata))>
Task poll:     GET /updates?id=<beacon_id_hex8>
Result post:   POST /submit?id=<beacon_id_hex8>
```

SSL certificate verification is disabled (`verify=False`) — the Python beacon connects regardless of certificate validity.

**Dual crypto backend:** Supports both `cryptography` and `pycryptodome` Python libraries with runtime detection and automatic fallback. This indicates an operator designing for operational reliability across varied target Python installations.

#### BOF Runtime Compilation (bof_executor.py)

> **Analyst note:** BOFs (Beacon Object Files) are small compiled programs that run inside a Cobalt Strike beacon's own process without creating a new process, making them harder to detect. Standard BOF execution requires a pre-compiled binary file. The OpenStrike approach is unusual: it ships C source code directly and compiles it at runtime using GCC on the target system. This creates characteristic forensic artifacts that defenders can detect.

`bof_executor.py` ships embedded C source code and compiles it at runtime via the target's GCC installation. This approach enables the Python beacon to execute BOF-style code without a native COFF loader.

**Forensic artifacts created:**

- `bof_runner.c` — C source file written to disk in temporary directory
- `bof_runner.dll` / `bof_runner.so` — compiled output files
- `python.exe` → `gcc.exe` parent-child process chain (high-confidence detection indicator — unusual in standard environments)

---

### 2.3 Trinity Protocol — Single-Operator Cryptographic Proof

> **Analyst note:** RSA-2048 is a type of asymmetric encryption using paired keys: the public key (embedded in the beacon) encrypts data, and only the matching private key (on the C2 server) can decrypt it. Finding the identical public key embedded in three different beacon types — written in different programming languages with different compilers — is definitive evidence that a single entity operates all three.

**DEFINITE (static analysis — cross-sample comparison)**

All three beacon variants embed the identical RSA-2048 public key modulus, beginning:

```
9f12c9cb6582f379088600e6cdb7ac80...
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/c-beacon-rsa-pubkey-modulus.png" | relative_url }}" alt="Ghidra hex dump view of the RSA-2048 public key bytes embedded in beacon.exe, with the modulus prefix 9f12c9cb6582f379088600e6cdb7ac80 highlighted in the raw byte array, confirming the key is stored as a contiguous 256-byte big-endian modulus in the .rdata section.">
  <figcaption><em>Figure 6: RSA-2048 public key modulus bytes embedded in the C beacon (beacon.exe). The highlighted prefix 9f12c9cb... serves as the definitive cross-implant fingerprint — this identical modulus appears in all three beacon variants, proving single-operator control.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/python-beacon-rsa-pubkey-source.png" | relative_url }}" alt="Python source code showing the RSA public key in PEM format embedded in the beacon_universal.py cross-platform implant, with the same RSA-2048 key present as a base64-encoded PEM block assigned to a variable used for session establishment.">
  <figcaption><em>Figure 7: The identical RSA-2048 public key in PEM format within the Python beacon source (beacon_universal.py). Cross-referencing with Figure 6 confirms cryptographic unity across the C and Python implant families — the Trinity Protocol's single-operator proof.</em></figcaption>
</figure>

**Operational implications:**

1. A single operator controls all three implant types from one C2 server — the matching private key resides at `172.105.0.126`
2. The RSA modulus serves as a cross-implant attribution indicator: any beacon carrying this modulus is part of the OpenStrike toolkit
3. Private key recovery (via server seizure or memory dump) enables retroactive decryption of all historic registration traffic
4. Single-key architecture rules out MaaS operation — separate customers would require separate key pairs

**AES IV hardcoding:** The shared IV `abcdefghijklmnop` across all three implants makes AES-CBC encryption deterministic. Identical plaintext + identical session key → identical first ciphertext block. This enables network IDS signature matching on first-block patterns once a session key is recovered, and means all historically captured sessions can be retroactively decrypted.

---

### 2.4 Loader Chain Analysis

> **Analyst note:** The five loader executables form a development chain from the simplest possible shellcode runner to a full network-staged deployment system. Because the DLL beacon's ReflectiveLoader export is tripwired (Section 2.2.1), these loaders are not optional — they are the only mechanism that can correctly activate the DLL beacon.

**DEFINITE (static analysis) — five loaders, single build environment**

| Stage | Filename | Technique | Key Feature |
|---|---|---|---|
| 1 — Simplest | `run.exe` | Direct call | File → RWX alloc → call rax; zero instrumentation |
| 2 — Mid-tier | `sc_loader.exe` | SEH exception handling | CreateThread + SEH crash dump + 30 s timeout |
| 3 — Advanced | `veh_loader.exe` | VEH (Vectored Exception Handling) | VEH crash handler + module resolution + 30 s timeout |
| 4 — Specialized | `dbg_loader.exe` | INT3 entry-point discovery | Scans 50 bytes for `FF D0` → patches to `CC` → reads RAX from VEH crash record |
| 5 — Production | `stager.exe` | Network delivery | `GET /qz99` → growable RWX buffer → CreateThread(INFINITE) |

#### VEH and SEH-Based Shellcode Execution

> **Analyst note:** Windows provides two error-handling systems: SEH (Structured Exception Handling, per-thread) and VEH (Vectored Exception Handling, process-wide). Malware abuses both by deliberately triggering errors so that malicious code runs inside the error-handler — a context that some security tools do not monitor as closely as normal code execution. VEH fires before SEH and covers the entire process, making it the more powerful technique.

`veh_loader.exe` registers a Vectored Exception Handler before executing shellcode. If shellcode crashes, the VEH handler catches the exception and logs full crash context including register values and loaded module list. This doubles as a development diagnostic for debugging the beacon loading sequence.

`sc_loader.exe` uses Structured Exception Handling in a parallel pattern as the mid-tier test harness.

**Security detection:** VEH registration followed by RWX shellcode execution is a detectable behavioral pattern. EDR products monitoring the VEH list for handlers pointing to non-module (unbacked) memory regions can flag this activity.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/veh-loader-exception-handler.png" | relative_url }}" alt="Ghidra decompilation of veh_loader.exe showing the AddVectoredExceptionHandler API call registering a custom exception handler, followed by conditional logic that loads shellcode from the hardcoded path C:\\cs_final.dat when no command-line argument is provided, or from a user-specified path otherwise.">
  <figcaption><em>Figure 8: veh_loader.exe — the VEH registration call and hardcoded payload path "C:\\cs_final.dat". The default path reveals the operator's local development convention: shellcode payloads are staged at the filesystem root with a descriptive name indicating Cobalt Strike final-stage shellcode.</em></figcaption>
</figure>

#### Entry-Point Discovery via CALL RAX Patching — `dbg_loader.exe`

> **Analyst note:** When a DLL beacon is converted to shellcode for delivery, it loses the named exports that normally indicate where to start execution. dbg_loader.exe solves this problem automatically by scanning shellcode for the CPU instruction "call rax" (which jumps to the address stored in the RAX register), replacing it with a breakpoint instruction, running the shellcode, and then reading the RAX value from the resulting crash — revealing the actual beacon entry point.

Automated entry-point discovery algorithm:

```
1. Load shellcode from C:\cs_final.dat into RWX memory
2. Scan first 50 bytes for FF D0 (CALL RAX opcode)
3. Patch found FF D0 → CC (INT3 software breakpoint)
4. Register VEH handler
5. Execute shellcode via CreateThread
6. VEH catches EXCEPTION_BREAKPOINT
7. Read RAX value from exception context
8. RAX = beacon entry point address
9. Print: "[*] INT3 set at offset %lu (RVA 0x%llX)"
```

This automation combines VEH crash handling, INT3 breakpoint injection, and register-state reading into an operator utility that functions as a semi-debugger without requiring an attached debugger. The technique is not previously documented in the context of automated C2 loader chains.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/dbg-loader-int3-patch.png" | relative_url }}" alt="Ghidra decompilation of dbg_loader.exe showing the INT3 patching logic: a loop scanning the first 50 bytes of loaded shellcode for the FF D0 opcode (CALL RAX), patching the found byte to CC (INT3 breakpoint), then executing the shellcode and reading the RAX register value from the VEH exception context to discover the beacon entry point.">
  <figcaption><em>Figure 9: dbg_loader.exe INT3 patching logic — the code scans loaded shellcode for the CALL RAX (FF D0) opcode, patches it to INT3 (CC), and reads the RAX value from the resulting VEH crash record. This automated entry-point discovery solves the problem of locating the beacon's start address in position-independent shellcode without requiring an attached debugger.</em></figcaption>
</figure>

#### Network Stager — `stager.exe` (Production Delivery)

> **Analyst note:** stager.exe is the "production" loader — the one that would be deployed to a real target. Instead of reading a shellcode file from disk, it downloads the beacon payload over an encrypted HTTPS connection from the C2 server. The /qz99 URI it requests is the single most distinctive network indicator in the entire toolkit.

```
1. HTTPS connect to 172.105.0.126:8443 (SSL verification disabled)
2. GET /qz99 → receive shellcode payload (variable size)
3. Allocate RWX memory buffer (grows dynamically with download)
4. Write received shellcode to RWX buffer
5. CreateThread(INFINITE) → beacon runs indefinitely
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/stager-winhttp-c2-chain.png" | relative_url }}" alt="Ghidra decompilation of stager.exe showing the complete WinHTTP C2 connection chain: WinHttpOpen with Mozilla/5.0 user-agent string, WinHttpConnect to the hardcoded IP address 172.105.0.126 on port 0x20FB (8443 decimal), WinHttpOpenRequest to the /qz99 staging URI, followed by WinHttpSendRequest, WinHttpReceiveResponse, and VirtualAlloc for payload memory allocation.">
  <figcaption><em>Figure 10: The stager.exe production delivery chain — Ghidra decompilation showing the complete WinHTTP sequence with the hardcoded C2 address 172.105.0.126:8443 and the /qz99 staging URI. This is the network stager that would be deployed to real targets, downloading the beacon payload over HTTPS with SSL verification disabled.</em></figcaption>
</figure>

The `/qz99` URI is the highest-priority network IOC in the toolkit — short, non-standard, and with negligible false-positive risk in enterprise proxy logs.

---

### 2.5 Python Utility Script Suite

> **Analyst note:** Beyond the beacons and loaders, the open directory contained a complete operator toolbox. The most security-significant of these is check_ntdll.py — a pre-deployment reconnaissance script that checks whether the target system's security software has modified Windows system libraries to intercept API calls. An operator who uses this script before deploying the main beacon gains intelligence about what security monitoring is in place.

#### check_ntdll.py — EDR Hook Detection

**HIGH confidence (code analysis)**

`check_ntdll.py` reads `C:\Windows\System32\ntdll.dll` directly from disk using a raw file handle (not via LoadLibrary) at RVA `0x316FE`, then compares the bytes to the memory-mapped version of ntdll loaded in the current process. Modified bytes indicate EDR inline hooks — typically 5-byte JMP instructions patched by security software to redirect Windows API calls through the EDR's monitoring layer.

**Operator workflow context:** This is a pre-deployment reconnaissance tool. The operator checks for EDR hooks before deploying the main beacon, then adjusts approach based on results. Detection of this script's access pattern provides early warning of operator pre-positioning.

**Detection indicator:** `python.exe` opening `C:\Windows\System32\ntdll.dll` with a direct file handle — not via LoadLibrary or GetModuleHandle — is detectable via Sysmon file access monitoring or EDR file handle telemetry. This is an anomalous pattern in normal environments.

---

## 3. C2 Protocol Architecture

> **Analyst note:** This section describes how all three beacon types communicate with their C2 server. The protocol has three layers: an outer RSA handshake to establish a unique session key, an inner AES+HMAC envelope that encrypts and authenticates every message, and an HTTP transport layer that can be reshaped by the Malleable C2 system. The hardcoded IV is a critical weakness that enables defenders to retroactively decrypt captured traffic once a session key is recovered.

### 3.1 Session Establishment (RSA-2048 Handshake)

**DEFINITE (static analysis — all three beacon variants)**

```
Beacon → Server:
  GET /register
  Cookie: session=<base64(RSA-PKCS1v15-encrypt(metadata_blob, public_key))>

Metadata blob format:
  [0x0000BEEF: 4 bytes, big-endian magic identifier]
  [hostname: variable]
  [username: variable]
  [PID: 4 bytes]
  [OS version: variable]
  [codepage: variable]
```

The `0x0000BEEF` magic is a beacon-protocol frame identifier detectable in memory. RSA-2048 PKCS#1 v1.5 is used for key establishment — a classical but not modern approach. The practical risk of Bleichenbacher-style attacks against this implementation is LOW (custom C2 servers typically discard invalid messages without distinguishable error responses).

### 3.2 Symmetric Encryption Envelope

**DEFINITE (static analysis — all three beacon variants)**

```
Plaintext → AES-128-CBC(session_key, IV="abcdefghijklmnop") → ciphertext
Ciphertext → HMAC-SHA256(hmac_key, ciphertext)[:16] → 16-byte MAC tag
Wire format: [ciphertext || MAC]
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/c-beacon-aes-hardcoded-iv.png" | relative_url }}" alt="Ghidra decompilation of the AES-CBC encryption function in beacon.exe showing memcpy calls that copy the hardcoded initialization vector abcdefghijklmnop into the encryption context, with the IV string highlighted in green boxes alongside the BCRYPT_BLOCK_LENGTH and BCRYPT_KEY_HANDLE constants.">
  <figcaption><em>Figure 11: Hardcoded AES-128-CBC initialization vector in the C beacon — the string "abcdefghijklmnop" (highlighted) is copied into the encryption context via memcpy. This static IV makes AES-CBC deterministic: identical plaintext with the same session key always produces identical ciphertext, enabling network-level signature matching once a session key is recovered.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/c-beacon-hmac-sha256-truncated.png" | relative_url }}" alt="Ghidra decompilation showing the HMAC-SHA256 implementation using BCryptOpenAlgorithmProvider with the SHA256 algorithm identifier, BCryptCreateHash, BCryptHashData, and BCryptFinishHash writing a 0x20 (32 byte) digest to local_38, followed by truncation where only 0x10 (16 bytes) are used as the MAC tag.">
  <figcaption><em>Figure 12: HMAC-SHA256 MAC computation in the C beacon using the Windows BCrypt API. The full 32-byte SHA256 digest (0x20) is computed via BCryptFinishHash, then truncated to 16 bytes (0x10) for the wire format — a space-saving design that still provides adequate authentication strength for C2 traffic.</em></figcaption>
</figure>

The encrypt-then-MAC construction (ciphertext authenticated before decryption) is the more secure ordering — it prevents chosen-ciphertext attacks by requiring MAC verification before any decryption occurs. The operator implemented this correctly while simultaneously undermining it with the hardcoded IV. This suggests intentional architectural choices around simplicity rather than ignorance of cryptographic principles.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-key-derivation-sha256.png" | relative_url }}" alt="Ghidra decompilation of the CS DLL's key derivation function FUN_180018c60 showing SHA256 hash computation via PTR_s_sha256 reference, session key derivation from the RSA-decrypted handshake blob, and a swi(3) call that triggers the INT3 tripwire if the key installation path is reached through the ReflectiveLoader rather than the operator's custom loaders.">
  <figcaption><em>Figure 13: SHA256 session key derivation in the CS DLL — the function computes session keys from the RSA handshake material using SHA256. The swi(3) call (INT3 tripwire) at the end of the derivation path provides a second layer of anti-analysis protection: even if an analyst bypasses the ReflectiveLoader trap, the key installation path contains its own crash trigger.</em></figcaption>
</figure>

### 3.3 HTTP Transport Layer

**DEFINITE (code analysis)**

| Endpoint | Method | Beacon | Purpose |
|---|---|---|---|
| `/register` | GET (Cookie) | All three | Session establishment |
| `/updates?id=XXXXXXXX` | GET | All three | Task polling (8 hex-char beacon ID) |
| `/submit?id=XXXXXXXX` | POST | beacon.exe, Python | Result submission |
| `/submit.php` | GET (via transform VM) | DLL beacon | Result submission — detection blind spot |
| `/qz99` | GET | stager.exe | Shellcode download |

The GET-based exfiltration from the DLL beacon is the critical detection gap: command output travels in GET request bodies transformed by the Malleable C2 VM. The 2 MB accumulator buffer produces a bimodal GET size pattern detectable via analytics but not by simple method-based rules.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-output-accumulator.png" | relative_url }}" alt="Ghidra decompilation showing the CS DLL's output accumulator function with malloc and memcpy calls that build up command output in a growing memory buffer before flushing it through the HTTP transport layer, creating the bimodal GET size pattern described in the analysis.">
  <figcaption><em>Figure 14: The CS DLL's output accumulator — command results are collected in a dynamically allocated memory buffer via malloc/memcpy before being flushed through the Malleable C2 transform VM. This buffering mechanism produces the bimodal GET size pattern (small heartbeat polls vs. large output flushes) that serves as a network-level detection opportunity.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-172-105-0-126-20260406/cs-dll-encrypt-and-submit.png" | relative_url }}" alt="Ghidra decompilation of function FUN_18000ceb0 showing the encrypt-then-submit flow: the function checks the DAT_18003d004 beacon-ready flag, then calls the encryption function FUN_18000dac0 to encrypt the accumulated output, and conditionally submits it via FUN_18000e440 to the C2 server.">
  <figcaption><em>Figure 15: The encrypt-and-submit function tying the cryptographic envelope to C2 transmission. The DAT_18003d004 beacon-ready flag (set during initialization, shown in §2.2.1) gates whether encrypted output is submitted — ensuring no data is transmitted before the beacon has fully initialized and established its session key.</em></figcaption>
</figure>

---

## 4. MITRE ATT&CK Mapping

<table class="professional-table">
  <thead>
    <tr>
      <th>Tactic</th>
      <th>Technique ID</th>
      <th>Technique Name</th>
      <th>Confidence</th>
      <th>Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Resource Development</td>
      <td>T1587.001</td>
      <td>Develop Capabilities: Malware</td>
      <td class="confirmed">HIGH</td>
      <td>OpenStrike custom C beacon, Python beacon, and full loader chain operator-developed (GCC 15 build artifacts, debug symbols intact)</td>
    </tr>
    <tr>
      <td>Resource Development</td>
      <td>T1588.002</td>
      <td>Obtain Capabilities: Tool</td>
      <td class="confirmed">HIGH</td>
      <td>Cracked CS 3.x DLL, watermark=0, MSVC 2012 toolchain — sourced from pre-existing cracked distribution</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1059.003</td>
      <td>Windows Command Shell</td>
      <td class="confirmed">HIGH</td>
      <td><code>cmd.exe /c</code> shell execution via CMD_SHELL in beacon.exe; CreatePipe + CreateProcessA</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1059.006</td>
      <td>Python</td>
      <td class="confirmed">DEFINITE</td>
      <td>beacon_universal.py is a Python-based cross-platform implant (source code)</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1106</td>
      <td>Native API</td>
      <td class="confirmed">DEFINITE</td>
      <td>VirtualAlloc(RWX) + CreateThread across all loaders; BCrypt API for crypto in beacon.exe</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1129</td>
      <td>Shared Modules</td>
      <td class="confirmed">HIGH</td>
      <td>Loader chain dynamically resolves and loads beacon DLL into process memory; all five loaders share module-resolution logic (static analysis)</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1055</td>
      <td>Process Injection</td>
      <td class="confirmed">HIGH</td>
      <td>All loaders map beacon DLL into process via VirtualAlloc RWX + CreateThread; VEH-based shellcode execution in veh_loader.exe</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1027.002</td>
      <td>Obfuscated Files: Software Packing</td>
      <td class="confirmed">HIGH</td>
      <td>PE overlays (43–62 KB) on loader EXEs contain encoded shellcode blobs; XOR 0x2E config packing in DLL beacon (static analysis)</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1027.009</td>
      <td>Embedded Payloads</td>
      <td class="confirmed">HIGH</td>
      <td>PE overlays (43–62 KB) appended to loader EXEs contain COFF metadata / shellcode blobs</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1620</td>
      <td>Reflective Code Loading</td>
      <td class="confirmed">HIGH</td>
      <td>Custom PE mapper in loader chain; tripwired ReflectiveLoader export in DLL beacon</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1140</td>
      <td>Deobfuscate/Decode Files</td>
      <td class="confirmed">DEFINITE</td>
      <td>XOR 0x2E config decryption in DLL; base64 encoding of RSA-encrypted Cookie header</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1036.005</td>
      <td>Match Legitimate Name/Location</td>
      <td class="likely">MODERATE</td>
      <td>Mozilla/5.0 User-Agent mimicking legitimate browser; spawn-to `rundll32.exe`</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1622</td>
      <td>Debugger Evasion</td>
      <td class="confirmed">HIGH</td>
      <td>check_ntdll.py reads raw ntdll.dll from disk to detect EDR inline hooks; dbg_loader.exe uses INT3 breakpoint injection to probe execution context (code analysis)</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1497.001</td>
      <td>System Checks</td>
      <td class="likely">MODERATE</td>
      <td>check_ntdll.py reads raw ntdll.dll from disk to detect EDR inline hooks (operator pre-deployment utility)</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1033</td>
      <td>System Owner/User Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>CMD_GETUID returns hostname\username string; hostname and username also collected in 0x0000BEEF registration metadata (static analysis)</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1082</td>
      <td>System Information Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>Hostname, username, PID, OS version, codepage collected in 0x0000BEEF registration metadata</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1057</td>
      <td>Process Discovery</td>
      <td class="confirmed">DEFINITE</td>
      <td>CreateToolhelp32Snapshot + Process32First/Next in CMD_PS</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1083</td>
      <td>File and Directory Discovery</td>
      <td class="confirmed">DEFINITE</td>
      <td>FindFirstFileA + FindNextFileA in CMD_LS</td>
    </tr>
    <tr>
      <td>Collection</td>
      <td>T1005</td>
      <td>Data from Local System</td>
      <td class="confirmed">HIGH</td>
      <td>CMD_DOWNLOAD reads arbitrary files up to 10 MB; CMD_LS indexes directory contents</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1071.001</td>
      <td>Web Protocols</td>
      <td class="confirmed">DEFINITE</td>
      <td>HTTP/HTTPS GET and POST over TLS to /register, /updates, /submit, /qz99</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1132.002</td>
      <td>Non-Standard Encoding</td>
      <td class="confirmed">HIGH</td>
      <td>Base64 encoding of RSA-encrypted session cookie; 17-opcode Malleable C2 VM transforms HTTP request components with custom encoding (static analysis)</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1573.001</td>
      <td>Symmetric Cryptography</td>
      <td class="confirmed">DEFINITE</td>
      <td>AES-128-CBC + HMAC-SHA256 encrypt-then-MAC; shared across all three beacon variants</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1573.002</td>
      <td>Asymmetric Cryptography</td>
      <td class="confirmed">DEFINITE</td>
      <td>RSA-2048 PKCS#1 v1.5 for session key establishment; identical public key across all three implants</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1571</td>
      <td>Non-Standard Port</td>
      <td class="confirmed">HIGH</td>
      <td>HTTPS on port 8443 (standard HTTPS: 443)</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1105</td>
      <td>Ingress Tool Transfer</td>
      <td class="confirmed">DEFINITE</td>
      <td>stager.exe downloads shellcode payload from /qz99 staging endpoint</td>
    </tr>
    <tr>
      <td>Exfiltration</td>
      <td>T1041</td>
      <td>Exfiltration Over C2 Channel</td>
      <td class="confirmed">HIGH</td>
      <td>All command output submitted via C2 channel (GET for DLL beacon via transform VM; POST for C and Python beacons)</td>
    </tr>
  </tbody>
</table>

*Table shows only HIGH/MODERATE/DEFINITE confidence mappings. Five techniques (T1129, T1027.002, T1622, T1033, T1132.002) were present in the stage1 analysis at HIGH/DEFINITE confidence and are included above. Additional coverage gaps for these techniques are documented in the detection file.*

---

## 5. Threat Intelligence Context

### 5.1 OpenStrike — Novel Toolkit, Zero Prior Coverage

**Name provenance:** "OpenStrike" is the toolkit author's self-chosen name, embedded in the source code — not a designation assigned by this publication. It appears in two distinct locations within the recovered Python source files:

```
beacon_universal.py docstring:  "OpenStrike Universal Beacon — Single-File Cross-Platform Implant"
bof_executor.py docstring:      "OpenStrike BOF Executor — Native BOF execution via compiled C helper library"
```

The C beacon (`beacon.exe`) prints `"[*] OpenStrike Beacon starting..."` at initialization, confirming the name is used consistently across implant variants. This self-identification by the author provides a reliable tracking label grounded in the artifact evidence itself.

**Pre-publication verification:** No public threat intelligence exists for "OpenStrike" as of 2026-04-07. Targeted searches were conducted across open-source threat intelligence feeds, vendor threat reports, malware repositories, and security research publications. The exact string `"OpenStrike Universal Beacon"` returned zero results. Searches for the custom sample SHA256 hashes returned no matches in any indexed database. All seven binary samples were absent from VirusTotal at time of discovery. The tripwired ReflectiveLoader technique (export RVA redirected to `66 90 CC` NOP+INT3 padding bytes) is not documented in any prior public research on Cobalt Strike modifications. The C2 protocol internals documented in this report are the first public documentation of this toolkit.

**Classification confidence: HIGH (85%)** — Self-branded in source code and debug strings; novel architecture; zero prior TI footprint; GCC 15 build artifacts confirm development no earlier than late 2025.

**Defender implication:** Standard threat intelligence platforms and AV signatures will not identify OpenStrike. Behavioral and protocol-based detection — the `/qz99` URI, AES IV `abcdefghijklmnop` in memory, GET requests to port 8443 from non-browser processes — is the only reliable detection path until signatures propagate into vendor products.

---

### 5.2 Cracked Cobalt Strike 3.x — Context

The DLL beacon component is a cracked Cobalt Strike 3.x artifact. Cobalt Strike is a commercially licensed penetration testing framework first released in 2012. Cracked versions have circulated continuously since early CS releases.

**Key threat landscape facts relevant to this case:**

- **Google Cloud Threat Intelligence (2022, Tier 2 / B1):** Identified 34 distinct cracked CS versions spanning CS 1.44 through CS 4.7 — confirming an active and persistent cracked distribution ecosystem
- **Operation Morpheus (June 2024):** Multi-government law enforcement operation across 27 countries disrupted 593 malicious CS servers. Continued post-operation activity confirms the cracked ecosystem was not eliminated
- **Linode (AS63949) CS context:** Recorded Future's 2022 Adversary Infrastructure Report (Tier 2 / B2) documented 291 C2 servers on Linode infrastructure with Cobalt Strike as the top malware family — directly contextualizing the operator's choice of this provider

**CS 3.x vs 4.x significance:** CS 3.x reached end-of-life in 2019. The presence of MSVC 2012 compiler artifacts and XOR 0x2E config encoding identifies this DLL as from the older cracked distribution pool. The use of a 3.x artifact rather than the more common 4.x cracked builds — at LOW confidence — may reflect preference for a known-stable artifact, operator familiarity with older builds, or unavailability of a suitable 4.x crack.

---

### 5.3 Infrastructure: 172.105.0.126 Profile

**Network context: HIGH confidence (4-source validated)**

| Attribute | Value | Source |
|---|---|---|
| ASN | AS63949 (LINODE-AP) | BGP.he.net, IPinfo.io |
| Provider | Linode LLC (Akamai Connected Cloud) | WHOIS, ARIN |
| Geography | Toronto, Canada | IPinfo.io, WHOIS |
| C2 port status | Offline at analysis date | Shodan |
| Bulletproof hosting | NOT DETECTED (0/6 indicators) | Infrastructure analysis |

**Specific IP reputation: INSUFFICIENT** — No threat intelligence found for `172.105.0.126` specifically in open-source feeds. Consistent with a recently provisioned VPS aligned with GCC 15 build timing (late 2025–early 2026). Infrastructure pivoting not viable from open-source data: single IP, no domain layer, no SSL certificate data accessible (port offline).

**Hosting pattern context:** Linode is a legitimate commercial provider with a documented history of C2 abuse due to accessible pricing and easy provisioning. Recorded Future's 2022 data places Linode 8th globally among C2 hosting providers. The choice reflects a common pattern among commodity operators seeking low-cost, low-commitment infrastructure.

#### Passive DNS History (DomainTools Iris, 2026-04-06)

> **Analyst note:** Passive DNS records show every domain name that has pointed to an IP address over time. Because commercial cloud IPs are reassigned between tenants, passive DNS reveals the history of who else used this IP — helping establish whether the IP has prior malicious use history and how the current threat actor fits into that timeline.

DomainTools Iris passive DNS export reveals this IP has been continuously allocated within Linode's Toronto pool since at least 2019-02-05, cycling through multiple independent tenants. The C2 operator used the raw IP address exclusively — no actor-registered domains point to this IP.

| Domain | Period | Duration | Assessment |
|---|---|---|---|
| li1953-126.members.linode.com | Feb 2019 – Feb 2022 | ~3 years | Linode default PTR — IP in pool since at least 2019 |
| ceres.woodengatecider.ca | Oct 2023 – Sep 2024 | ~337 days | Canadian artisan cider brand — legitimate prior tenant |
| cap03.ddns.net | May 2024 – Sep 2024 | ~85 days | Dynamic DNS (No-IP); purpose ambiguous from PDNS alone; prior tenant |
| jessicahelpdesk.work | Apr 14, 2025 | 1 day | SUSPICIOUS — helpdesk social engineering lure pattern; prior tenant |
| *.pr.edgegap.net (~30 entries) | May 12–20, 2025 | ~9 days | Edgegap game server routing pool — definitively benign prior tenant |
| coolify.jbforge.ca | Dec 2025 – Apr 2, 2026 | ~99 days | SIGNIFICANT — see below |

**coolify.jbforge.ca (Dec 2025 – Apr 2, 2026):** This domain points to a self-hosted Coolify installation — Coolify is an open-source self-hosted PaaS (Platform-as-a-Service) used by developers to manage application deployments, comparable to Heroku. The subdomain structure (`coolify.jbforge.ca`) is consistent with a Canadian developer (handle "jbforge") exposing a Coolify admin panel on a personal subdomain. The domain was last seen 2026-04-02 — four days before analysis. The most parsimonious interpretation is sequential tenancy: the jbforge tenant's lease ended or they migrated, and the threat actor subsequently rented the same IP. The alternative — that jbforge IS the threat actor using Coolify as a backend management interface — is assessed as LOW likelihood given the open directory and debug-loader OPSEC failures observed throughout the kit. Attribution impact: NONE direct. This is a separable OSINT lead; WHOIS on `jbforge.ca` would confirm tenant distinctness.

**jessicahelpdesk.work (Apr 2025):** Resolved to this IP for a single day approximately eleven months before the C2 window. The personal-name + "helpdesk" + generic TLD pattern is documented in tech-support scam and vishing infrastructure used to impersonate corporate helpdesks. This event is attributable to a separate prior tenant, not the OpenStrike operator. Its significance is confirming the IP has prior malicious use history from a different actor, which — at MODERATE confidence — explains why it does not appear in open-source reputation databases despite that earlier incident.

**Temporal summary:** The C2 operator's tenancy on this IP began at an undated point before discovery and ended before or at analysis date (port 8443 offline by 2026-04-06). The IP has been in continuous Linode allocation since at least 2019 with multiple sequential tenants — a normal pattern for commercial datacenter IP blocks. The threat actor registered no domains pointing to this IP; the C2 operated exclusively over the raw IP address.

**PDNS confidence: MODERATE** — DomainTools Iris provides a clear multi-year tenancy picture; the precise start and end of the threat actor's tenancy window remains undated from infrastructure data alone.

---

### 5.4 Ecosystem Exposure

**Software targeted or abused:**

- **Microsoft Windows** — primary platform for all custom EXEs and loader chain; all C-language components Windows-only
- **Python runtime** — cross-platform beacon delivery vector; `beacon_universal.py` targets any Python 3.x installation (Windows, Linux, macOS)
- **Windows BCrypt / CNG API** — cryptographic subsystem abused for AES-128-CBC and HMAC-SHA256 in beacon.exe
- **Windows WinHTTP / WinInet** — HTTP transport stack used by the CS DLL beacon for C2 communication
- **GCC/MinGW toolchain** — required on target for BOF runtime compilation via `bof_executor.py`; an unusual environmental dependency that constrains deployment to targets with developer tools installed

**Provider risk:**

- **Linode / Akamai Connected Cloud (AS63949)** — the C2 hosting provider; a legitimate mainstream commercial provider, not bulletproof. Formal abuse reporting is available at `linode.com/legal-abuse/`. The provider is subject to US and Canadian jurisdiction, both cooperative Five Eyes members, enabling law enforcement takedown requests.
- **Port 8443** — non-standard HTTPS port that may bypass legacy proxy inspection rules or policies that only inspect traffic on port 443

**Supply chain implications:** None observed. No trojanized legitimate software was identified; no supply chain delivery vector is in evidence. The discovery method (open directory, infrastructure-first) provides no visibility into intended delivery mechanisms.

---

### 5.5 Technique Context

**GET-based exfiltration:** The DFIR Report CS Defender's Guide (Tier 2 / B2) establishes the standard defensive expectation that CS beacons use GET for task retrieval and POST for result submission. The OpenStrike DLL beacon deliberately inverts this. The bimodal GET size pattern (heartbeat GETs + accumulator flush GETs) is the correct detection anchor for this technique. In practice, detection requires proxy or WAF logging configured to flag when GET request sizes to port 8443 alternate between small (<1 KB heartbeat) and large (>100 KB accumulator flush) within a short observation window — a size distribution analytic rather than a simple method rule.

**VEH-based shellcode execution:** Documented in GuLoader (SonicWall, Tier 2 / B2) and general defense evasion research (IBM X-Force 2023, Tier 2 / B2). The OpenStrike implementation uses VEH primarily as a development diagnostic harness, not as a primary evasion mechanism — a development-oriented application of a well-known technique.

**ntdll hook detection:** Reading ntdll.dll from disk to detect EDR hooks is a well-documented 2024–2025 technique confirmed effective against major EDR products in security research (MalwareTech Tier 2 / B2; Palo Alto Networks Tier 2 / B2). OpenStrike's use as an operator pre-deployment reconnaissance tool — rather than an automated beacon capability — indicates deliberate pre-compromise planning.

**Cross-platform Python implant context:** JPCERT documented CrossC2 (Tier 2 / B1) bringing CS-compatible beacons to Linux and macOS. Elastic Security Labs documented the Axios supply chain compromise's cross-platform framework using identical wire protocol across implants (Tier 2 / B1) — an architectural pattern shared by OpenStrike's Trinity Protocol.

**SOCKS4a proxy (Python beacon):** The Python beacon's SOCKS4a proxy capability enables network pivoting — routing the attacker's traffic through the compromised host to reach other internal systems. If the SOCKS4a proxy is activated, the resulting traffic pattern is distinctive: a Python process establishing outbound connections on behalf of inbound proxy clients, typically to non-web ports. Defenders can hunt for `python.exe` (or the Python interpreter equivalent) with unusual outbound connection patterns to multiple internal hosts or non-standard ports as a proxy activation indicator.

---

## 6. Discovery Method: hunt.io Open Directory Capture

Samples were recovered via hunt.io's AttackCapture system, which continuously scans the internet for misconfigured servers exposing directory listings. When discovered, files are automatically downloaded and indexed. This is a pre-compromise intelligence source — recovery occurred before any victim was identified.

**Intelligence value of open directory capture:** This discovery method provided the complete operator toolkit including development utilities (`dbg_loader.exe`), test harnesses, operator scripts, and debug-symbol-enabled binaries. These artifacts are rarely available from post-compromise forensics, where adversaries typically clean up or only deploy operational components. The completeness of the recovered kit is a direct consequence of the open directory exposure.

**Operator error:** The open directory was almost certainly a configuration mistake (misconfigured web server with directory listing enabled) rather than intentional exposure.

---

## 7. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-004 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

**Designation:** UTA-2026-004
**Attribution Confidence: INSUFFICIENT (<50%)**

Attribution is not possible with available evidence. No infrastructure overlaps, code similarity corpus, targeting pattern, or external attribution sources exist to link this activity to any named threat actor or tracked group.

**ACH (Analysis of Competing Hypotheses) result:**

| Hypothesis | Evidence Consistency | Assessment |
|---|---|---|
| H1: Independent skilled developer or small private group | HIGH — consistent with all evidence | Best fit |
| H2: Nation-state APT | LOW — open directory OPSEC failure and cracked CS contradict nation-state resources and tradecraft | Ruled out |
| H3: MaaS operator | LOW — single shared RSA key indicates single-operator control, inconsistent with multi-customer architecture | Ruled out |
| H4: False flag / infrastructure reuse | INSUFFICIENT data | Cannot assess |

**Operator profile (UTA-2026-004):**

- **Build environment:** GCC 15.1 (MinGW), released April 25, 2025; activity window late 2025 onward
- **Capability tier:** Advanced — custom bytecode VM, novel anti-analysis techniques, multi-language C2 architecture, BOF runtime compilation
- **Tooling:** Custom OpenStrike toolkit (C beacon + Python beacon) + cracked Cobalt Strike 3.x DLL
- **Infrastructure:** Single commercial VPS (Linode AS63949), no domain layer, no bulletproof hosting
- **OPSEC:** Poor — open directory exposure of the full toolkit
- **Targeting:** Unknown — no victims identified

**Report language:** The threat actor behind this toolkit cannot be attributed to any known named group. The operator profile is most consistent with an independent skilled developer or small private group rather than a state-sponsored actor or MaaS operator, but this characterization is based on behavioral indicators rather than confirmed identity. Attribution remains open pending additional evidence.

---

## 8. Confidence Levels Summary & Gaps

### DEFINITE (Direct Evidence — No Ambiguity)

- All three beacon variants share RSA-2048 public key modulus `9f12c9cb6582f379...` (static analysis, cross-sample)
- AES-128-CBC with hardcoded IV `abcdefghijklmnop` present in all three beacon variants (static analysis)
- Encrypt-then-MAC construction (AES-128-CBC + 16-byte truncated HMAC-SHA256) across all implants (static analysis)
- `ReflectiveLoader` export redirected to `66 90 CC` (NOP+INT3) — tripwire confirmed (static analysis of PE export directory)
- CS 3.x DLL: watermark=0, XOR config key `0x2E`, C2 `172.105.0.126:8443` (config extraction via the config extraction tool)
- beacon.exe CMD_SHELL uses `cmd.exe /c` via CreatePipe + CreateProcessA (static analysis)
- stager.exe downloads payload from GET `/qz99` on port 8443 (static analysis)
- All six EXEs compiled with MinGW-w64 GCC 15-win32 (compiler strings in PE)
- Malleable C2 VM (`FUN_180015838`) implements 17-opcode bytecode interpreter (static analysis)
- `0x0000BEEF` magic used as beacon metadata frame identifier (static analysis)
- beacon_universal.py self-described as "OpenStrike Universal Beacon" (source code)

### HIGH (Strong Evidence, Minor Gaps)

- GET-based exfiltration from DLL beacon via transform VM (code path confirmed; execution not live-tested in sandbox)
- 2 MB output accumulator producing bimodal GET size pattern (code path confirmed; behavior inferred from static analysis)
- check_ntdll.py detects EDR hooks by reading raw ntdll.dll at RVA 0x316FE (code analysis)
- bof_executor.py runtime GCC compilation producing python.exe → gcc.exe chain and temporary files (code analysis)
- dbg_loader.exe entry-point discovery via `FF D0 → CC` patch and RAX recovery from VEH context (code analysis)
- PE overlays (43–62 KB) on loader EXEs contain COFF metadata/shellcode blobs (static analysis)
- CS 3.x DLL sourced from pre-existing cracked distribution (MSVC 2012 toolchain — not GCC 15)
- Development window: late 2025 or 2026 (GCC 15 release constraint)

### MODERATE (Reasonable Evidence, Notable Gaps)

- VEH in veh_loader.exe provides module resolution context not available in SEH loader (code confirmed; EDR bypass effectiveness not tested)
- Python beacon SSL verification disabled for C2 connection (source code confirmed; C2 certificate not accessible)
- Non-constant-time HMAC tag comparison in beacon.exe creates timing side-channel (code analysis; LOW practical exploitability over network)

### INSUFFICIENT (Cannot Assess)

- Attribution to any named threat actor
- Targeting profile or victimology
- Whether toolkit has been deployed against real targets
- Historical IP use before open directory discovery
- Whether additional toolkit components exist

### Gaps & Assumptions

The following assumptions underlie high-stakes conclusions in this report. Each is explicitly flagged because its failure would change the assessment:

**Assumption 1 — GCC 15 compiler string is authentic (HIGH sensitivity)**
The "late 2025 or early 2026" development window rests on the GCC 15.1 release date (April 25, 2025) appearing in PE compiler strings. If an actor spoofed these strings, the development timeline collapses. Evidence against spoofing: all six EXEs share identical compiler flags consistent with a real GCC 15 toolchain invocation; spoofing would require fabricating matching build artifacts across multiple binaries. Assessment: authentic with HIGH confidence.

**Assumption 2 — Single shared RSA key means single-operator control (HIGH sensitivity)**
The Trinity Protocol conclusion (one operator controls all three beacon types) rests on a single shared RSA-2048 key. If the operator distributed this key as part of a builder kit, H3 (MaaS) would be revived. Evidence against kit distribution: no kit infrastructure, licensing system, or multi-customer design patterns are observed anywhere in the recovered files; the key is hardcoded directly into source. Assessment: single-operator with HIGH confidence, but MaaS cannot be definitively ruled out without additional evidence.

**Assumption 3 — Watermark=0 indicates a cracked build (DEFINITE)**
Watermark=0 in CS config reliably indicates a license-stripped build per NCC Group research (Tier 2 / B2). No legitimate CS licensing produces a zero watermark. This assumption is DEFINITE.

**Alternative assessments considered but not adopted:**
- H2 (Nation-state APT): The combination of open directory OPSEC failure, cracked CS (not custom), and single commercial VPS is inconsistent with nation-state resources. Not adopted.
- H3 (MaaS): Ruled out by single RSA key, though HIGH-sensitivity assumption 2 above is the load-bearing evidence.

**Evidence that would change these conclusions:**
- Discovery of a builder application distributing the RSA key → would revive H3 (MaaS)
- Code similarity match to a known actor's prior tools → would enable attribution upgrade from INSUFFICIENT
- Victim artifacts linking this toolkit to confirmed intrusions → would confirm the toolkit is operational, not merely developmental

---

## 9. Indicators of Compromise

Machine-readable IOC feed: [`/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json`](/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json)

The feed contains 13 file hashes (SHA256 / SHA1 / MD5 for 7 binaries including overlay-stripped variants), 4 network indicators, host-based file path indicators, behavioral indicators, and protocol-level signatures. All hashes validated; confidence HIGH for all network and file indicators derived from static analysis.

**Highest-value indicators for immediate hunting:**

| Indicator | Type | Hunt Priority | Detection Method |
|---|---|---|---|
| `GET /qz99` on port 8443 | Network URI | P1 — most distinctive | Proxy / firewall logs |
| `abcdefghijklmnop` in process memory | AES IV string | P1 — in-memory beacon hunt | Memory scanning, YARA |
| `0x0000BEEF` in network traffic | Protocol magic | P1 — wire-level | IDS / Suricata |
| `172.105.0.126` on port 8443 | C2 IP | P1 — block immediately | Firewall, proxy |
| GET `/updates?id=[0-9a-f]{8}` | URI pattern | P2 — beacon poll | Proxy / firewall logs |
| `66 90 CC` at ReflectiveLoader export | Static DLL signature | P2 — file scan | YARA on disk |
| `[*] OpenStrike Beacon starting...` | Debug string | P1 — family ID | YARA on disk / memory |
| `GCC: (GNU) 15-win32` compiler string | Loader family | P3 — loader variant | YARA on disk |
| Python → GCC parent-child chain | Process behavior | P2 — BOF executor | EDR process tree |
| `python.exe` opening ntdll.dll as raw file | File access | P2 — pre-deploy recon | EDR file telemetry |

---

## 10. Detection Rules & Hunting Queries

Full detection rule set — YARA, Sigma, Suricata, EDR hunting queries — is available in the separate detection file:

**Detection file:** [`/hunting-detections/open-directory-172-105-0-126-20260406-detections/`](/hunting-detections/open-directory-172-105-0-126-20260406-detections/) (`open-directory-172-105-0-126-20260406-detections.md`)

**Coverage summary:**

| Area | Rules | MITRE |
|---|---|---|
| OpenStrike C beacon (beacon.exe) | YARA | T1071.001, T1573.001 |
| Loader chain (run/sc_loader/veh_loader/dbg_loader/stager) | YARA + Sigma | T1059.006, T1055.001 |
| CS 3.x tripwired ReflectiveLoader (beacon_patched.x64.dll) | YARA + Sigma (proxy) | T1620, T1055.001 |
| Python beacon (beacon_universal.py) | YARA + Sigma | T1059.006, T1071.001 |
| C2 network (all endpoints) | Sigma + Suricata | T1071.001, T1041, T1105 |

**Detection gaps to address locally:**

- GET-based exfiltration bimodal size pattern requires size distribution analytics — no single-rule detection possible. In practice, configure proxy or WAF logs to alert when GET request payload sizes to port 8443 alternate between small (<1 KB heartbeat) and large (>100 KB accumulator flush) within a sliding observation window
- Memory-resident AES key detection at fixed offsets requires EDR memory scanning capability
- Runtime GCC compilation by Python process is detectable via parent-child process monitoring in EDR (`python.exe` → `gcc.exe`)
- SOCKS4a proxy activation by the Python beacon produces unusual outbound connection patterns from the Python interpreter process — hunt for `python.exe` establishing connections to multiple internal hosts or non-standard ports in a short time window

---

## 11. Key Takeaways

- **Trinity Protocol proves single-operator control.** The identical RSA-2048 public key embedded across three beacon variants written in different languages and compiled by different toolchains is definitive evidence of single-operator control. Any beacon carrying the documented modulus (`9f12c9cb6582f379...`) belongs to this operator's infrastructure. This finding also rules out MaaS operation and enables retroactive traffic decryption if memory is preserved.

- **The tripwired ReflectiveLoader is a structurally novel anti-analysis technique.** Redirecting the `ReflectiveLoader` export to existing `66 90 CC` padding bytes — rather than writing new code — crashes every standard CS injection tool that honors the export convention. This technique is not documented in public threat research as of 2026-04-06 and forces defenders to update their assumptions about CS DLL loading behavior.

- **GET-based exfiltration creates a silent blind spot in POST-focused detection.** The DLL beacon routes all command output through HTTP GET requests via a 17-opcode bytecode VM. Detection infrastructure tuned to "POST = exfiltration" will silently miss this traffic. The bimodal size pattern (small heartbeat GETs alternating with large accumulator-flush GETs) is the correct detection anchor, but requires size distribution analytics — not simple method-based rules.

- **Zero prior AV or threat intelligence coverage means no passive protection.** Every binary sample had zero VirusTotal coverage at discovery. Standard signature-based defenses provide no protection against OpenStrike. The only reliable detection paths are behavioral (the `/qz99` URI, the hardcoded AES IV in memory, the `66 90 CC` byte pattern) and protocol-level (the `0x0000BEEF` magic in network traffic).

- **Cross-platform reach extends risk to Linux and macOS.** The Python beacon runs without recompilation on Windows, Linux, and macOS — environments where CS DLL beacons cannot run. Organizations with mixed operating system environments cannot limit their detection and response posture to Windows-only coverage.

- **No persistence is the single most favorable characteristic for defenders.** No persistence mechanisms were observed across all samples. An active beacon stops if the host reboots or the operator disconnects. This significantly reduces dwell time risk compared to rootkit or firmware-level implants, and means containment (network block + host reboot) is a viable short-term response if an active beacon is detected before memory capture.

- **Memory forensics at documented offsets enables retroactive decryption.** AES session keys are recoverable at documented static offsets in the DLL beacon's image (`image_base + 0x40430`). If a compromised host's memory is preserved before termination, all captured C2 traffic from that session can be retroactively decrypted. This is an unusually strong forensic recovery opportunity compared to most advanced implants.

---

## 12. Response Orientation

**Detection priorities — hunt these first:**

- GET requests to `/qz99` on port 8443 in proxy and firewall logs (most distinctive indicator; minimal false-positive risk)
- Outbound HTTPS to port 8443 from non-browser processes (Sysmon Event ID 3, image not in approved browser list)
- String `abcdefghijklmnop` in process memory of suspected hosts

**Persistence targets:**

- No persistence mechanisms observed; toolkit requires operator-controlled redeployment
- File artifacts: `C:\cs_final.dat`, `C:\payload.dat`, `C:\payload.bin` (shellcode staging paths)
- BOF artifacts: `bof_runner.c`, `bof_runner.dll`, `bof_runner.so` in temporary directories
- If beacon process identified: capture memory before termination — AES session keys recoverable at documented offsets

**Containment categories:**

- Block `172.105.0.126` at perimeter (all ports, bidirectional)
- Isolate any host exhibiting 5-second polling pattern to port 8443
- Preserve memory of suspected hosts before remediation
- Deploy YARA and Sigma rules from detection file across endpoint and log infrastructure

---

## 13. Ongoing Investigation: Expanded Toolkit Discovery

**Status:** UNDER INVESTIGATION<br>
**Discovered:** April 7, 2026<br>
**Files identified:** 116 additional files

On April 7, 2026 — one day after the initial discovery — a follow-up review of the open directory on `172.105.0.126` revealed a significant expansion of the exposed toolkit. The directory on port 8888 now contains **116 additional files** that were not present during the original analysis. Initial triage indicates this is a **complete Cobalt Strike operator deployment** including the full post-exploitation module suite, artifact kit, and multiple additional custom beacon builds.

This section documents what has been identified at a triage level. Full analysis of these files is ongoing, and this report will be updated with detailed findings as they become available.

### What Was Found

**Additional custom OpenStrike beacons (7 files):**

Seven new GCC-compiled beacon executables matching the original toolkit's MinGW-w64 build environment: `beacon_cs_debug.exe`, `beacon_debug.exe`, `beacon_ip.exe`, `beacon_min.exe`, `beacon_patched.exe`, `beacon_x64_patched.exe`, and `beacon_x64_sniff.exe`. The naming conventions suggest iterative development variants — debug builds, architecture-specific builds, and a network sniffing variant. These are high-priority for follow-up analysis as they may reveal additional OpenStrike capabilities beyond what was documented in Sections 2–3.

**Full Cobalt Strike beacon suite (36 DLLs across 6 protocol families):**

| Protocol Family | Files | Variants |
|---|---|---|
| HTTP beacon | `beacon.dll`, `beacon.x64.dll` | Standard + `.rl0k` (no reflective loader) + `.rl100k` (100 KB loader) |
| DNS beacon | `dnsb.dll`, `dnsb.x64.dll` | Same three variants |
| External C2 | `extc2.dll`, `extc2.x64.dll` | Same three variants |
| WinHTTP beacon | `winhttpb.dll`, `winhttpb.x64.dll` | Same three variants |
| SMB pivot beacon | `pivot.dll`, `pivot.x64.dll` | Same three variants |
| Port 80 beacon | `beacon80.dll`, `beacon_port80.x64.dll` | MSVC 2012 compiled |

The `.rl0k` and `.rl100k` suffixes are standard Cobalt Strike naming for reflective loader size variants. The presence of DNS, ExternalC2, and SMB pivot beacons significantly expands the operator's confirmed protocol capabilities beyond the HTTP/HTTPS beacons analyzed in this report.

**Complete CS artifact kit (12 executables):**

The artifact kit is Cobalt Strike's payload generation framework — it produces the initial-access executables and DLLs that deliver the beacon. All 12 artifacts are GNU linker compiled (consistent with the OpenStrike build environment), covering 32-bit and 64-bit architectures in standard, big (staged payload embedded), and service (Windows service) variants.

**Post-exploitation modules (18 DLLs):**

| Module | Purpose | Architectures |
|---|---|---|
| `mimikatz-full` | Credential extraction (full Mimikatz) | x86, x64 |
| `mimikatz-min` | Credential extraction (minimal) | x86, x64 |
| `mimikatz-chrome` | Browser credential theft | x86, x64 |
| `hashdump` | SAM database hash extraction | x86, x64 |
| `keylogger` | Keystroke capture | x86, x64 |
| `screenshot` | Screen capture | x86, x64 |
| `browserpivot` | Browser session hijacking | x86, x64 |
| `bypassuac` | UAC privilege escalation | x86, x64 |
| `invokeassembly` | In-memory .NET assembly execution | x86, x64 |
| `sshagent` | SSH agent hijacking | x86, x64 |
| `netview` | Network enumeration | x86, x64 |
| `portscan` | Internal port scanning | x86, x64 |
| `powershell` | PowerShell execution | x86, x64 |
| `covertvpn` | VPN pivoting (MSVC compiled) | x86 |

This is a complete CS operator toolkit for post-compromise operations — credential theft, lateral movement, persistence escalation, and data collection.

**Operator scripts and templates (13 files):**

Delivery templates (`template.x64.ps1`, `template.x86.ps1`, `template.hint.x64.ps1`, `template.hint.x86.ps1`, `template.vbs`), social engineering JavaScript payloads (`analytics.js`, `autoexploit.js`, `keylogger.js`, `reader.js`, `redirect.js`, `stay.js`), a jQuery library (`jquery-1.7.1.min.js`), and a compression utility (`compress.ps1`).

**Additional loader and stager variants (8 files):**

Small executables including `dll_exec.exe`, `dll_loader.exe`, `mini_beacon.exe`, `mini_beacon2.exe`, `stager_http_x64.exe` (1,024 bytes — a minimal staged payload), `stager_http_x64.ps1`, and a .NET `hello.exe` test binary.

### What This Means

The expanded discovery transforms the assessment of this operator's capability. The original analysis documented a toolkit in development — custom beacons, loaders, and utility scripts. The 116 additional files reveal that this is a **fully operational deployment** with complete post-compromise capabilities: credential theft (Mimikatz), lateral movement (SMB pivot beacons, portscan, netview), privilege escalation (bypassuac), and data collection (keylogger, screenshot, browser pivoting).

The presence of DNS and External C2 beacon variants indicates the operator has fallback communication channels beyond the HTTP/HTTPS beacons documented in this report — a capability that defenders should account for when deploying detection rules.

### What Comes Next

The following analysis is planned:

- Full static analysis of the 7 custom GCC-compiled beacon variants to identify additional OpenStrike capabilities
- Configuration extraction from all CS beacon DLLs to map the operator's full C2 infrastructure
- Analysis of JavaScript payloads for social engineering delivery indicators
- Updated IOCs and detection rules covering the expanded sample set
- Updated MITRE ATT&CK mapping reflecting the full post-exploitation capability

This report will be updated with these findings as analysis is completed. The "Last Updated" date at the top of this report will reflect the most recent revision.

**Want to be notified when the updated analysis drops?** Subscribe to The Hunters Ledger mailing list at the bottom of this page — subscribers receive email notifications when new reports and major updates are published, so you will not miss the follow-up to this investigation.

---

## 14. Appendices

### Appendix A: Cryptographic Architecture Reference

**Memory forensics offsets for beacon_patched.x64.dll (runtime):**

```
AES-128 session key:    [image_base + 0x40430]  (16 bytes)
HMAC-SHA256 key:        [image_base + 0x40440]  (16 bytes)
IV (always static):     [image_base + 0x40450]  ("abcdefghijklmnop")
Beacon-ready flag:      [image_base + 0x3D004]  (1 = registered)
Output accumulator ptr: [image_base + 0x3F480]  (pointer to 2 MB plaintext buffer)
```

**Retroactive traffic decryption:** The fixed IV means AES session key recovery from memory enables decryption of all historically captured traffic for that session. With the 16-byte AES key extracted from the documented offset, any pcap captured during beacon operation can be retroactively decrypted.

**Wire envelope construction:**

```
Session establishment:
  RSA-PKCS1v15-encrypt(metadata_blob, public_key) → base64
  → Cookie: session=<base64_value> → GET /register

Per-message:
  plaintext → AES-128-CBC(key, IV=b"abcdefghijklmnop") → ciphertext
  HMAC-SHA256(hmac_key, ciphertext)[:16] → MAC tag
  Wire: ciphertext || MAC
```

### Appendix B: Loader Chain Execution Flow

```
Production path (stager.exe → beacon_patched.x64.dll):
  1. stager.exe: HTTPS GET /qz99 → receive shellcode
  2. VirtualAlloc(RWX) + write shellcode
  3. CreateThread(INFINITE) → shellcode executes
  4. DllMain(PROCESS_ATTACH): decode XOR config only (no beacon thread spawned)
  5. Loader calls beacon entry point directly (ReflectiveLoader is tripwired)
  6. Beacon GET /register → RSA-encrypt metadata → send Cookie
  7. Task poll loop: GET /updates every 5 s ± 10% jitter
  8. Command output: GET /submit.php via Malleable C2 transform VM

Development path (dbg_loader.exe — entry-point discovery):
  1. Load shellcode from C:\cs_final.dat
  2. Scan first 50 bytes for FF D0 (CALL RAX)
  3. Patch FF D0 → CC (INT3 breakpoint)
  4. Register VEH handler
  5. Execute shellcode via CreateThread
  6. VEH catches EXCEPTION_BREAKPOINT
  7. Read RAX from exception context → beacon entry point address
```

### Appendix C: Research References

**Tier 1 (Authoritative):**
- Cobalt Strike official documentation and release notes (HelpSystems/Fortra)
- NIST SP 800-107: "Recommendation for Applications Using Approved Hash Algorithms"
- GCC 15.1 Release Announcement, gcc.gnu.org (April 25, 2025)

**Tier 2 (Reputable):**
- Google Cloud Threat Intelligence (2022): "Making Cobalt Strike Harder for Threat Actors to Abuse"
- Recorded Future (2022): "2022 Adversary Infrastructure Report"
- DFIR Report: "Cobalt Strike: A Defender's Guide"
- Unit 42 (Palo Alto Networks): "Cobalt Strike Analysis and Tutorial: How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect"
- NCC Group: "Mining Data from Cobalt Strike Beacons"
- IBM X-Force: "Using Vectored Exception Handling (VEH) for Defense Evasion and Process Injection" (2023)
- IBM X-Force: "Defining the Cobalt Strike Reflective Loader"
- SonicWall: "GuLoader Demystified: Unraveling its Vectored Exception Handler Approach"
- MalwareTech: "An Introduction to Bypassing User Mode EDR Hooks"
- Palo Alto Networks: "A Deep Dive Into Malicious Direct Syscall Detection"
- Elastic Security Labs: "Extracting Cobalt Strike Beacon Configurations"
- Elastic Security Labs: "Inside the Axios Supply Chain Compromise"
- JPCERT: "CrossC2: Expanding Cobalt Strike Beacon to Cross-Platform Attacks" (August 2025)
- Core Security: "Writing Beacon Object Files"
- DomainTools: Iris passive DNS export for 172.105.0.126 (2026-04-06)

**Tier 3 (Community):**
- usualsuspect.re: "Cobalt Strike's Malleable C2 Under the Hood" (7–8 opcodes documented; cross-referenced with official CS docs)
- hunt.io: AttackCapture system documentation
- GBHackers: "Python-Based PyRAT Emerges as Cross-Platform Threat" (2025)

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
