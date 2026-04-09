---
title: OpenStrike Expanded Toolkit — 106 New Files, Complete CS Arsenal Exposed
date: '2026-04-08'
layout: post
permalink: /reports/new-files-found-20260408/
hide: true
category: Custom RAT Toolkit
description: 'Continued analysis of UTA-2026-004 open directory reveals 106 additional files including a complete cracked Cobalt Strike 4.9.1 installation, a four-generation custom implant evolution chain (OpenStrike), CovertVPN Layer 2 tunneling, and an EAX-redirect process hollowing variant that bypasses standard EDR detection logic.'
detection_page: /hunting-detections/new-files-found-20260408-detections/
ioc_feed: /ioc-feeds/new-files-found-20260408-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "172[.]105[.]0[.]126"
    note: "C2 and staging server (ports 80, 809, 8443, 50050)"
  - value: "042761408e83155d24884a72291d9f10803becd790fbcfa6ff65e9e72eb44446"
    note: "Gen-4 OpenStrike beacon (SHA256)"
  - value: "701b4f60411a26abfb137f476c9328900843ee5a49780f2fcd23a5cb15498f16"
    note: "Artifact Kit EAX-redirect service (SHA256)"
  - value: "af688b120db0a3b324e2cd468cfead71b7895a3c815f4026d51ac7fca0cb8ab4"
    note: "CovertVPN L2 tunneling module (SHA256)"
---

**Campaign Identifier:** OpenStrike-CSBeacon-Toolkit-172.105.0.126<br>
**Last Updated:** April 8, 2026<br>
**Threat Level:** HIGH

---

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-004 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

---

## 1. Executive Summary

**Bottom Line Up Front:** A previously identified threat actor (UTA-2026-004 *(an internal tracking label used by The Hunters Ledger — see Section 8)*) was found staging a complete offensive toolkit across 106 files on the same open directory documented April 6, 2026. The toolkit includes cracked Cobalt Strike 4.9.1, a four-generation custom implant development chain (the newest generation still work-in-progress), and a Layer 2 network tunneling module. Overall risk: HIGH (7.5/10). The toolkit is assessed as pre-deployment — no confirmed victims. The highest-priority defensive finding is an EAX-redirect process injection technique that bypasses the detection logic most endpoint security products use for this attack class. 72 of 98 samples submitted to VirusTotal had no prior submissions and no prior public reporting.

**What Was Found**

Continued monitoring of the open directory at `172.105.0.126:8888` surfaced 106 additional files not present in the original investigation. Triage and deep-dive analysis across 18 selected samples revealed the full scope of the operator's toolkit: a 4-generation custom implant family (OpenStrike), the complete CS 4.9.1 "Pwn3rs" cracked installation with all post-exploitation capability modules, a CovertVPN Layer 2 bridge module with ICMP tunneling, an Artifact Kit service variant using EAX-redirect process hollowing, and six loader variants from a shared GCC 15 codebase. 72 of 98 samples submitted to VirusTotal had no prior submissions, indicating these samples had not been publicly reported on before this investigation.

**Why This Report Was Written**

The original April 6 report documented the existence of OpenStrike and confirmed UTA-2026-004's custom implant development. It did not have visibility into the complete CS installation, the full beacon development chain from prototype to current work-in-progress, the CovertVPN network tunneling capability, or the EAX-redirect process hollowing technique embedded in the Artifact Kit service variant. This report closes those gaps.

**Key Risk Factors**

<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Dimension</th>
      <th>Rating</th>
      <th>Assessment</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Custom Implant Development</strong></td>
      <td class="high">HIGH</td>
      <td>4-generation evolution chain documents active iteration toward an RSA-independent custom beacon. Gen-4 is a confirmed work-in-progress with correct crypto but missing key exchange.</td>
    </tr>
    <tr>
      <td><strong>Process Injection Evasion</strong></td>
      <td class="high">HIGH</td>
      <td>EAX-redirect hollowing via SetThreadContext (no NtUnmapViewOfSection) creates a documented detection gap in EDR products anchored on traditional process hollowing signals.</td>
    </tr>
    <tr>
      <td><strong>Network Tunneling</strong></td>
      <td class="high">HIGH</td>
      <td>CovertVPN L2 bridge with 5 transport channels including ICMP covert channel enables Layer 2 network pivoting invisible to most network monitoring infrastructure.</td>
    </tr>
    <tr>
      <td><strong>Toolkit Completeness</strong></td>
      <td class="high">HIGH</td>
      <td>Complete CS 4.9.1 installation: 5 transport types, 13 post-ex modules (encrypted), Artifact Kit, social engineering kit, multiple loader variants, payload templates.</td>
    </tr>
    <tr>
      <td><strong>Deployment Status</strong></td>
      <td class="medium">MEDIUM</td>
      <td>Pre-deployment assessment: team server freshly deployed or wiped (7 beacons, 0 activity), gen-4 beacon is WIP, open directory exposure suggests pre-operational staging.</td>
    </tr>
    <tr>
      <td><strong>Attribution Clarity</strong></td>
      <td class="medium">MEDIUM</td>
      <td>INSUFFICIENT confidence for named actor attribution. UTA-2026-004 maintained. Operator sourced tools from Chinese-language cracked CS ecosystem (MODERATE confidence).</td>
    </tr>
  </tbody>
</table>

**Overall Risk Score: 7.5/10 — HIGH**

**Threat Actor:** UTA-2026-004 (maintained from April 6 report). No attribution upgrade warranted — see Section 8 for full assessment.

**For Technical Teams**

- The EAX-redirect hollowing detection gap (Section 4.2) is the highest-priority defensive finding: EDR rules anchored on `NtUnmapViewOfSection` will miss the Artifact Kit service variant entirely. Anchor detection on `SetThreadContext` called against suspended-state threads from service processes.
- CovertVPN's ICMP tunnel is detectable by the 0xDD/0xCC frame markers in ICMP payloads >128 bytes (Section 4.3). Most perimeter monitoring tools will miss this without deep packet inspection.
- The OpenStrike gen-4 beacon's C2 polling pattern (HTTP GET `/updates?id=%08x` every 4,500–5,500ms, POST `/submit?id=%08x`) is the highest-fidelity network detection for the custom implant family (Section 4.1).
- IOC feed (new indicators only, not duplicating April 6 feed): [/ioc-feeds/new-files-found-20260408-iocs.json](/ioc-feeds/new-files-found-20260408-iocs.json)
- Detection rules (YARA, Sigma, Suricata): [/hunting-detections/new-files-found-20260408-detections/](/hunting-detections/new-files-found-20260408-detections/)

**For Executives**

No immediate incident response is required — this toolkit is assessed as pre-operational with no confirmed victim intrusions. Priority actions are detection deployment and extension of existing network blocks (documented in Section 13). Risk is elevated from the April 6 assessment because the expanded toolkit reveals capabilities (CovertVPN Layer 2 tunneling, EAX-redirect process injection) not visible in the original 7-sample analysis.

---

## 2. Relationship to April 6 Report

> **Analyst note:** This report is a continuation of the original OpenStrike analysis published April 6, 2026. Readers unfamiliar with the original report are strongly encouraged to read it first — it establishes the OpenStrike family name, the Trinity Protocol cryptographic architecture, and the initial infrastructure profile for 172.105.0.126. This report documents only what was new in the expanded file set.

The April 6 report ([/reports/open-directory-172-105-0-126-20260406/](/reports/open-directory-172-105-0-126-20260406/)) documented 7 custom samples recovered from an open directory at `172.105.0.126:8888`. The investigation used an infrastructure-first discovery method that identified the toolkit before any victim could be confirmed. That report covered:

- OpenStrike gen-3 beacon (`beacon.exe`, 299KB, 11 commands, RSA-2048 Trinity Protocol)
- 5 shellcode loader variants from a shared GCC 15 codebase
- A cracked CS 3.x DLL with tripwired ReflectiveLoader
- The "Trinity Protocol" cryptographic architecture (AES-128-CBC + HMAC-SHA256 + RSA-2048)
- C2 infrastructure on ports 80, 8443 at `172.105.0.126`

**What this report adds:**

| Finding | April 6 Report | This Report |
|---|---|---|
| OpenStrike development chain | Gen-3 only | Gens 1–4 fully documented |
| Gen-4 beacon | Not known | Fully reversed (20+ functions, 10 commands, SHA256 crypto) |
| CS installation scope | Unknown | CS 4.9.1 "Pwn3rs" confirmed, all components mapped |
| EAX-redirect process hollowing | Not present | Artifact Kit service variant fully analyzed |
| CovertVPN | Not present | 5-channel L2 bridge fully analyzed |
| Loader count | 5 custom loaders | 6 loaders (5 in-memory + 1 disk-drop) |
| RSA key ecosystems | 1 (Trinity, RSA-2048) | 2 (Trinity RSA-2048 + CS 4.4 RSA-1024) |
| C2 listener profiles | 2 (ports 80/8443) | 3 profiles, ports 80/809/8443 |
| VirusTotal coverage | 0/7 (first-reports) | 72/98 new submissions were first-reports |
| Watermarks | Not documented | Watermarks 0 and 987654321 both documented |

---

## 3. Malware Classification & Sample Inventory

### 3.1 Classification

<table class="professional-table">
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Value</th>
      <th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Primary Family</strong></td>
      <td>OpenStrike (custom)</td>
      <td class="confirmed">DEFINITE — banner string "[*] OpenStrike Beacon starting..."</td>
    </tr>
    <tr>
      <td><strong>Secondary Family</strong></td>
      <td>Cobalt Strike 4.9.1 (cracked)</td>
      <td class="confirmed">DEFINITE — cs_ts.log team server log "Pwn3rs" tag confirmed</td>
    </tr>
    <tr>
      <td><strong>Tertiary Components</strong></td>
      <td>CS 3.x and 4.4 beacon DLLs</td>
      <td class="confirmed">DEFINITE — config extraction, RSA key ecosystem analysis</td>
    </tr>
    <tr>
      <td><strong>Type</strong></td>
      <td>Custom RAT + Complete Cracked CS Installation</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
    <tr>
      <td><strong>Sophistication</strong></td>
      <td>Intermediate</td>
      <td class="likely">HIGH — custom crypto correct but WIP; intermediate CS internals knowledge</td>
    </tr>
    <tr>
      <td><strong>Build Environment</strong></td>
      <td>GCC 15/15.2.0 (custom tools), GCC 9.2 (Artifact Kit), MSVC VS2012 (CS DLLs)</td>
      <td class="confirmed">DEFINITE — compiler signatures in PE headers</td>
    </tr>
    <tr>
      <td><strong>Compiler Fingerprint</strong></td>
      <td>MinGW-w64 GCC 15.2.0 (gen-4 beacon)</td>
      <td class="confirmed">DEFINITE — PE rich header analysis</td>
    </tr>
    <tr>
      <td><strong>Deployment Status</strong></td>
      <td>Pre-operational / capability staging</td>
      <td class="likely">MODERATE — team server freshly deployed, gen-4 WIP, no victims identified</td>
    </tr>
  </tbody>
</table>

### 3.2 Sample Inventory by Category

| Category | Count | Compiler | Analysis Priority |
|---|---|---|---|
| Custom operator tooling (GCC 15/15.2.0) | 10 | MinGW-w64 | HIGHEST |
| Unencrypted CS beacon DLLs (MSVC 2012) | 4 | VS 2012 | HIGH |
| CS Artifact Kit wrappers (GCC 9.2) | 18 | MinGW-w64 | MEDIUM |
| Scripts and templates (JS/PS1/VBS) | 15 | N/A | MEDIUM |
| Test/utility files | 3 | Mixed | LOW |
| Encrypted CS post-ex modules (AES-128-CBC) | 56 | Unknown (encrypted) | INVENTORY ONLY |
| **Total** | **106** | | |

**Note on encrypted sleeve DLLs:** 56 of 106 files are AES-128-CBC encrypted post-exploitation modules (Cobalt Strike "sleeve" DLLs including mimikatz, hashdump, and browser credential theft). Decryption was blocked by an auth/JAR keypair mismatch — the operator assembled their toolkit from multiple cracked CS distributions (see Section 5.3). Based on the CS 4.9.1 installation structure, these are stock CS post-ex modules. No custom intelligence was lost.

---

## 4. Technical Analysis

### 4.1 The OpenStrike 4-Generation Implant Evolution

> **Analyst note:** This section traces the development arc of a custom C2 implant built from scratch — progressing from a bare HTTP polling stub to a fully cryptographically implemented beacon. Each generation represents a discrete engineering milestone. Understanding this progression matters for defenders because it reveals an operator actively building toward an implant that would be independent of Cobalt Strike's RSA key infrastructure — and therefore invisible to CS-specific detection signatures.

The expanded file set exposed three generations of OpenStrike development that predated the gen-3 beacon documented in the April 6 report. Together, the four generations document the operator's entire development arc.

**Development Chain:**

```
Gen-1: mini_beacon.exe (16KB, GCC 15)
  SHA256: 03492f128fcc3910bda15f393c30ad3e04f5a50de36464d1e24038f49d889324
  - HTTP-only poller, no crypto, no commands
  - C2: Cookie: SESSIONID=%d on port 80
  - Beacon ID: PID XOR GetTickCount() — random per run, not trackable
  - Sleep: 4,500–5,500ms (GetTickCount jitter)
  - Purpose: Proof-of-concept HTTP callback with no operational capability
        |
Gen-2: mini_beacon2.exe (46KB, GCC 15)
  SHA256: 9bdb680d4368713273509e8c104c1903b9790ee725cc2319997e1da705af5ca0
  - Adds RSA-1024 beacon registration via BCrypt CNG
  - Structured binary registration packet (magic header 0xEFBE0000)
  - Host fingerprinting: elevation check, internal IP enumeration, process masquerade ("svchost.exe")
  - RSA-1024 key byte-for-byte identical to CS 4.4 ecosystem (Key B)
  - Still no commands — pure registration + poll loop
  - Sleep: fixed 5,000ms (jitter removed)
  - Purpose: Registration protocol development, CS key ecosystem integration
        |
Gen-3: beacon.exe (299KB, GCC 15) — PUBLISHED APRIL 6
  SHA256: 7d6a17754f086b53ee294f5ccd60b0127f921520ce7b64fea0aebb47114fb5d2
  - 11 commands, RSA-2048 key exchange (Trinity Protocol)
  - AES-128-CBC + HMAC-SHA256, hardcoded IV "abcdefghijklmnop"
  - Operational with documented gaps (see April 6 report)
  - Switched from RSA-1024 (Key B) to RSA-2048 (Trinity Key A)
        |
Gen-4: beacon_windows_x64.exe (30KB, GCC 15.2.0) — NEW
  SHA256: 042761408e83155d24884a72291d9f10803becd790fbcfa6ff65e9e72eb44446
  - Rewritten: 10x smaller than gen-3
  - 10 active commands + NOP handler
  - SHA256(nonce) symmetric key derivation — NO RSA dependency
  - AES-128-CBC + HMAC-SHA256-128 (Encrypt-then-MAC pattern)
  - CRITICAL: Nonce never transmitted to server — key exchange incomplete
  - WIP/development artifact with correct crypto, broken protocol
```

**What the Crypto Migration Tells Us:**

```
Gen-1: No crypto
Gen-2: RSA-1024 Key B (imported from CS 4.4 distribution)
Gen-3: RSA-2048 Trinity Key A (imported from CS 3.x distribution)
Gen-4: SHA256 symmetric — no RSA from any source
```

The operator deliberately progressed through two CS RSA key ecosystems before abandoning RSA entirely. The key migration from CS 4.4's RSA-1024 (gen-2) to the Trinity RSA-2048 (gen-3) demonstrates the operator understood how to extract RSA keys from beacon DLLs and embed them in custom code — an intermediate CS internals skill. The elimination of RSA in gen-4 shows intentional architectural independence: the operator is designing a custom C2 that does not require a CS team server to function.

If a gen-5 implementation resolves the missing key exchange mechanism, it would produce a fully functional custom beacon independent of all cracked CS infrastructure — and invisible to every CS-specific network and behavioral detection signature.

---

### 4.1.1 Gen-4 Full Technical Reversal: beacon_windows_x64.exe

> **Analyst note:** This section documents the complete function-level reversal of the gen-4 custom beacon using a disassembler (Ghidra). Every function was reversed. The level of detail matters because gen-4 represents the operator's current development target — understanding its architecture now means defenders can build detection signatures before it becomes operational.

**File Properties:**

| Field | Value |
|---|---|
| Filename | `beacon_windows_x64.exe` |
| SHA256 | `042761408e83155d24884a72291d9f10803becd790fbcfa6ff65e9e72eb44446` |
| MD5 | `b6e01011e2d38855dd6a4b10a79acffe` |
| Size | 29,696 bytes |
| Architecture | PE64 (x86-64) |
| Compiler | GCC 15.2.0 MinGW-w64 |
| Sections | .text (16KB), .data (~4KB), .bss, .rdata |
| Imports | WinHTTP, BCrypt (minimal surface) |

**Complete Reversed Function Map:**

| Function Address | Name | Purpose |
|---|---|---|
| `0x140004500` | `beacon_main` | Main loop: init, poll tasks, dispatch commands |
| `0x140001b80` | `crypto_derive_keys` | SHA256(nonce) → split into AES key + HMAC key |
| `0x140002380` | `crypto_decrypt` | Verify HMAC-SHA256 tag then AES-CBC decrypt |
| `0x140002240` | `crypto_aes_encrypt` | AES-128-CBC encrypt, append HMAC-SHA256-128 tag |
| `0x140002120` | `crypto_hmac` | HMAC-SHA256 truncated to 16 bytes |
| `0x140001ee0` | `crypto_aes_decrypt` | AES-128-CBC decrypt, PKCS#7 unpad, reinit IV |
| `0x1400014e0` | `crypto_encrypt_send` | Build TLV frame, encrypt, POST to /submit |
| `0x1400026d0` | `http_session_init` | WinHTTP synchronous session setup |
| `0x140002810` | `http_get_tasks` | GET /updates?id=%08x — 200 response gating |
| `0x140002a60` | `http_post` | POST to /submit with application/octet-stream |
| `0x1400016d0` | `cmd_shell` | cmd.exe /c via anonymous pipe, 30-second timeout |
| `0x140001a70` | `cmd_ps` | Process listing: PID, PPID, process name |
| `0x1400018f0` | `cmd_ls` | Directory listing: type, size, filename |

**Command Dispatch Table (10 active commands + NOP):**

| Cmd ID | Name | Implementation |
|---|---|---|
| `0x00` | NOP | Skip — no operation |
| `0x01` | Sleep | Update sleep_ms and jitter_pct in beacon config |
| `0x02` | Shell | cmd.exe /c via CreatePipe with CREATE_NO_WINDOW (0x08000000) |
| `0x03` | Exit | Send acknowledgment (callback type 0x0D), clear running flag |
| `0x04` | CD | SetCurrentDirectoryA, falls through to PWD response |
| `0x09` | Download | CreateFileA(GENERIC_READ) → ReadFile → encrypted POST |
| `0x1B` | Whoami | ComputerName\\UserName via GetComputerNameA + GetUserNameA |
| `0x20` | PS | CreateToolhelp32Snapshot — process list with PID/PPID/Name |
| `0x21` | LS | FindFirstFileA directory enumeration |
| `0x27` | PWD | GetCurrentDirectoryA response |
| `0x2C` | Upload | Nested TLV: filename_len + filename + file data |

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-command-dispatch.png" | relative_url }}" alt="Ghidra decompiler output showing the gen-4 beacon's main command dispatch function with a switch-case structure routing ten command IDs to their respective handler functions including sleep, shell, exit, download, whoami, and process listing">
  <figcaption><em>Figure 1: Gen-4 beacon command dispatch table in Ghidra, showing the switch-case structure that routes incoming command IDs (0x00 through 0x2C) to individual handler functions — the architectural core of the implant's tasking system.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-shell-exec-createprocess.png" | relative_url }}" alt="Ghidra decompiler output showing the Shell command handler calling CreateProcessA with cmd.exe /c argument, anonymous pipe creation via CreatePipe for stdout and stderr capture, and the CREATE_NO_WINDOW flag 0x08000000">
  <figcaption><em>Figure 2: Shell command handler (command ID 0x02) implementation showing CreateProcessA invocation with cmd.exe /c, anonymous pipe redirection for stdout/stderr capture, and the CREATE_NO_WINDOW flag (0x08000000) that suppresses visible console windows during command execution.</em></figcaption>
</figure>

**Beacon ID Generation:**

The beacon generates a deterministic host identifier using a djb2 hash variant (multiplier 0x1f = 31) of the host's ComputerName, XOR'd with the current process ID. Unlike gen-1's random PID-based ID, this is consistent across restarts — the same host will report the same beacon ID, enabling the operator to track reconstituted implants after host reboots.

```
beacon_id = djb2(ComputerName, multiplier=31) XOR PID
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-beacon-id-generation.png" | relative_url }}" alt="Ghidra decompiler output showing the beacon ID generation routine using GetCurrentProcessId XOR'd with a djb2 hash of the computer name, followed by User-Agent string construction with the resulting hex-formatted beacon identifier">
  <figcaption><em>Figure 3: Beacon ID generation routine showing GetCurrentProcessId XOR'd with the djb2 hash of the host's ComputerName. The resulting deterministic identifier is embedded in the User-Agent string and all subsequent HTTP requests, enabling the operator to track reconstituted implants across host reboots.</em></figcaption>
</figure>

**C2 Protocol Wire Format:**

The beacon uses a custom TLV (Type-Length-Value) framing wrapped in an Encrypt-then-MAC envelope:

```
Inbound (task delivery from server):
  [4B header/sequence] [4B cmd_type big-endian] [4B data_len big-endian] [N bytes data] ...

Outbound (callback to server):
  [4B sequence_counter BE] [4B payload_len+4 BE] [2B zero] [1B zero] [1B callback_type] [N bytes payload]
  → AES-128-CBC encrypt → append HMAC-SHA256-128 tag
  → HTTP POST /submit?id=%08x
```

**C2 Polling Pattern:**
- HTTP GET to `/updates?id=%08x` approximately every 4,500–5,500ms (5,000ms base, 10% jitter via `GetTickCount()`)
- Server must return HTTP 200; any other status code is ignored
- POST to `/submit?id=%08x` with `Content-Type: application/octet-stream`

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-tlv-byteswap-parser.png" | relative_url }}" alt="Ghidra decompiler output showing the TLV parser function performing big-endian byte-swap operations on 4-byte command type and data length fields using shift and OR bitwise operations before dispatching to command handlers">
  <figcaption><em>Figure 4: TLV (Type-Length-Value) parser performing big-endian byte-swap on the 4-byte command type and data length fields. The explicit byte-order conversion confirms this is a custom wire protocol — standard x86 programs use little-endian natively, so the big-endian encoding is a deliberate design choice inherited from network protocol conventions.</em></figcaption>
</figure>

---

### 4.1.2 Gen-4 Cryptographic Architecture

> **Analyst note:** This section describes how the gen-4 beacon protects its network communications. The core idea: each session generates a random secret, derives encryption keys from it, and uses those keys to encrypt all traffic. The critical flaw: the server never receives the secret, so it cannot decrypt anything. This is why gen-4 is assessed as a work-in-progress rather than a deployed implant.

**Key Derivation:**

```
1. BCryptGenRandom(16 bytes) → session nonce
2. BCryptDeriveKey(SHA256, nonce) → 32-byte digest
   [0:16]  = AES-128 encryption key
   [16:32] = HMAC-SHA256 authentication key
3. Secure wipe: intermediate digest zeroed byte-by-byte
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-sha256-key-derivation.png" | relative_url }}" alt="Ghidra decompiler output showing the crypto_derive_keys function calling BCryptOpenAlgorithmProvider with the string L SHA256, then BCryptDeriveKey to produce a 32-byte digest that is split into a 16-byte AES key and a 16-byte HMAC key">
  <figcaption><em>Figure 5: Key derivation function calling BCryptOpenAlgorithmProvider with L"SHA256" to derive a 32-byte digest from the session nonce. The first 16 bytes become the AES-128 encryption key and the second 16 bytes become the HMAC-SHA256 authentication key — mirroring Cobalt Strike's documented key derivation pattern but eliminating the RSA dependency.</em></figcaption>
</figure>

**Encryption (outbound traffic):**

```
1. AES-128-CBC(key=derived[0:16], IV="abcdefghijklmnop", PKCS#7 pad) → ciphertext CT
2. HMAC-SHA256(key=derived[16:32], data=CT) → truncate to 16 bytes → tag TAG
3. Wire format: [CT][TAG]
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-aes-cbc-iv-hardcoded.png" | relative_url }}" alt="Ghidra decompiler output showing the AES encryption setup with BCryptOpenAlgorithmProvider called with L AES string, BCryptSetProperty setting ChainingModeCBC, and the hardcoded 16-byte initialization vector string abcdefghijklmnop visible in the data reference">
  <figcaption><em>Figure 6: AES-128-CBC encryption setup showing BCryptOpenAlgorithmProvider with L"AES", ChainingModeCBC mode selection, and the hardcoded initialization vector "abcdefghijklmnop" — a static IV that produces identical ciphertext blocks for identical plaintext headers across sessions, representing a cryptographic design weakness.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-hmac-sha256-truncated.png" | relative_url }}" alt="Ghidra decompiler output showing the HMAC-SHA256 computation chain using BCryptCreateHash, BCryptHashData over the ciphertext buffer, BCryptFinishHash producing a 32-byte digest, and truncation to the first 16 bytes for the authentication tag">
  <figcaption><em>Figure 7: HMAC-SHA256 authentication tag computation showing the BCrypt hash chain (BCryptCreateHash → BCryptHashData → BCryptFinishHash) over the ciphertext buffer, with the resulting 32-byte digest truncated to 16 bytes. This truncation halves the tag length but still provides 128 bits of authentication strength — sufficient for integrity verification.</em></figcaption>
</figure>

**Decryption (inbound tasks):**

```
1. Split: CT = data[0:len-16], TAG = data[len-16:len]
2. Verify: HMAC-SHA256(key, CT) == TAG  ← non-constant-time compare (two 8-byte qword ==)
3. Decrypt: AES-128-CBC(key, IV="abcdefghijklmnop", CT) → plaintext
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-decrypt-etm-verify.png" | relative_url }}" alt="Ghidra decompiler output showing the Encrypt-then-MAC verification function that splits the incoming buffer into ciphertext and authentication tag, recomputes HMAC-SHA256 over the ciphertext portion, and compares the result against the received tag using two 8-byte quadword equality checks before proceeding to AES-CBC decryption">
  <figcaption><em>Figure 8: Encrypt-then-MAC verification in the decryption path — the function splits incoming data into ciphertext and HMAC tag, recomputes HMAC-SHA256 over the ciphertext, and performs a non-constant-time comparison (two 8-byte quadword == checks) before decrypting. The non-constant-time comparison is a theoretical timing oracle, though low practical risk over HTTP.</em></figcaption>
</figure>

**Encrypt-then-MAC Pattern:** This is the cryptographically correct ordering — authenticate the ciphertext, not the plaintext. Standard Cobalt Strike uses a similar split (SHA256 → [AES key][HMAC key]) documented by Elastic Security Labs and Unit42. The operator replicated CS's key derivation pattern while eliminating the RSA dependency — indicating study of CS internals (MODERATE confidence, based on architectural similarity to documented CS crypto design).

**Three Identified Crypto Weaknesses:**

1. **Static IV** — `"abcdefghijklmnop"` is a 16-byte ASCII string used as the AES-CBC initialization vector for every session. Identical plaintext headers across sessions will produce identical ciphertext blocks. Partially mitigated by per-session random keys, but the static IV is a design flaw.

2. **Non-constant-time HMAC compare** — The MAC verification compares two 8-byte quadwords using the `==` operator. Theoretically exploitable as a timing oracle for HMAC forgery. Low practical risk over HTTP due to network jitter masking timing differences.

3. **No TLS enforcement** — `WINHTTP_FLAG_SECURE` is not set on the WinHTTP session. If port 8443 serves plain HTTP rather than HTTPS, the encrypted payload travels without outer TLS — leaving only the inner AES encryption.

**The Fatal WIP Flaw — Missing Key Exchange:**

The session nonce is generated locally by `BCryptGenRandom` and never transmitted to the server. Without the nonce, the server cannot derive the AES and HMAC keys. No beacon session established by gen-4 can be successfully decrypted by the team server. This definitively marks gen-4 as a development artifact, not a deployed implant.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-gen4-encrypt-submit-no-nonce.png" | relative_url }}" alt="Ghidra decompiler output showing the encrypt-and-submit function constructing the URL string /submit?id=%08x with the beacon identifier, encrypting the payload buffer with AES-CBC, but with no code path transmitting the session nonce to the server — the nonce generated by BCryptGenRandom stays local">
  <figcaption><em>Figure 9: The encrypt-and-submit function showing the L"/submit?id=%08x" URL construction and payload encryption — critically, the session nonce generated by BCryptGenRandom is never transmitted to the server. Without the nonce, the server cannot derive the AES/HMAC keys, making gen-4 unable to establish a functional encrypted session. This is the definitive evidence marking gen-4 as a work-in-progress.</em></figcaption>
</figure>

---

### 4.2 EAX-Redirect Process Hollowing: Artifact Kit Service Variant

> **Analyst note:** This section explains a process injection technique that bypasses the detection mechanism most endpoint security (EDR) products use to catch the standard version of this attack. "Process hollowing" means launching a legitimate Windows program, then redirecting execution to malicious code so the malicious code runs inside the legitimate program's identity. Most security products watch for one specific API call — `NtUnmapViewOfSection` — that is characteristic of the classic technique. This variant never makes that call. It achieves the same end result through a different path, creating a detection blind spot that will persist until EDR vendors update their detection logic.

**Analyzed Files:**

| File | SHA256 | Architecture |
|---|---|---|
| `artifact32svc.exe` | `701b4f60411a26abfb137f476c9328900843ee5a49780f2fcd23a5cb15498f16` | PE32 (x86) |
| `artifact64svc.exe` | `6797ba96336c64648d6bcccdbead8d9ab6f18d77f0108239e31a063b32665770` | PE64 (x86-64) |

Both are Cobalt Strike Artifact Kit service templates — stock components included in the CS Artifact Kit for generating custom payloads that execute as Windows services. The GCC 9.2 compiler signature (distinct from the operator's custom GCC 15 tooling) identifies these as stock CS components.

**Full Execution Chain:**

```
Step 1: Register as Windows service "DceRpcSs"
        → Masquerades as legitimate Windows Remote Procedure Call service (RpcSs)
        → Windows Security Event ID 7045 fires with ServiceName: DceRpcSs

Step 2: Create named pipe \\.\pipe\MSSE-{N}-server
        → N = GetTickCount() % 9898 (range 0–9897)
        → Sysmon Event ID 17 (pipe created) fires

Step 3: Server thread writes XOR-encoded shellcode to the pipe
        → 4-byte rolling XOR key applied to shellcode bytes
        → Shellcode travels through kernel pipe buffer, bypassing some AV hooks

Step 4: Reader thread reads shellcode back from the pipe
        → 4-byte rolling XOR reverse decode
        → Patch GetModuleHandleA and GetProcAddress addresses into shellcode bootstrap

Step 5: Create rundll32.exe with CREATE_SUSPENDED
        → rundll32.exe spawned with no command-line arguments
        → Thread is suspended — execution not yet begun

Step 6: VirtualAllocEx(PAGE_READWRITE) in rundll32 process
        → Memory region is NOT executable at this stage
        → WriteProcessMemory copies decoded shellcode into that region

Step 7: VirtualProtectEx(PAGE_EXECUTE_READ) — two-stage RW→RX
        → Memory protection changed from write-only to execute-only
        → Memory is never simultaneously writable AND executable

Step 8: GetThreadContext → ctx.Eax = shellcode base address → SetThreadContext
        → EAX register (the x86 entry point / return address register) pointed at shellcode
        → Original rundll32.exe image remains mapped and untouched

Step 9: ResumeThread
        → rundll32.exe resumes execution from EAX = shellcode base
        → Shellcode runs inside rundll32.exe's process identity
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/artifact-kit-svc-dcerpcss-registration.png" | relative_url }}" alt="Ghidra decompiler output showing the Artifact Kit service registration function with lpServiceName set to the string DceRpcSs, masquerading as the legitimate Windows DCE/RPC Subsystem service for persistence and defense evasion">
  <figcaption><em>Figure 10: Artifact Kit service registration with lpServiceName = "DceRpcSs" (Step 1), masquerading as the legitimate Windows DCE/RPC Subsystem service (RpcSs). This produces a Windows Security Event ID 7045 with an unusual service name that is a reliable pre-execution detection indicator.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/artifact-kit-svc-msse-pipe-staging.png" | relative_url }}" alt="Ghidra decompiler output showing the named pipe creation with the format string MSSE-%d-server where the numeric value is derived from GetTickCount modulo 9898, followed by CreateThread to start the server thread and a Sleep loop maintaining the pipe connection">
  <figcaption><em>Figure 11: Named pipe staging (Steps 2–4) showing the pipe name format MSSE-%d-server (where %d = GetTickCount() % 9898), the server thread creation, and the Sleep-based keepalive loop. The pipe carries XOR-encoded shellcode between writer and reader threads, using the kernel pipe buffer to bypass some usermode AV hooks.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/artifact-kit-svc-rundll32-injection.png" | relative_url }}" alt="Ghidra decompiler output showing the process injection setup function calling CreateProcessA with rundll32.exe as the target, CREATE_SUSPENDED flag, followed by VirtualAllocEx and WriteProcessMemory to inject decoded shellcode into the suspended process memory space">
  <figcaption><em>Figure 12: Injection setup (Steps 5–6) showing CreateProcessA spawning rundll32.exe with CREATE_SUSPENDED, followed by VirtualAllocEx(PAGE_READWRITE) and WriteProcessMemory to inject decoded shellcode. The target process is suspended — execution has not yet begun, and the original rundll32 image remains fully mapped.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/artifact-kit-svc-eax-redirect-hijack.png" | relative_url }}" alt="Ghidra decompiler output showing the critical EAX-redirect sequence: GetThreadContext retrieves the suspended thread context, the Eax register field is overwritten with the shellcode base address parameter, SetThreadContext applies the modified context, and ResumeThread starts execution from the redirected address">
  <figcaption><em>Figure 13: The EAX-redirect hijack (Steps 8–9) — the critical detection-evasion technique. GetThreadContext retrieves the suspended thread's register state, the Eax field is overwritten with the shellcode base address (param_6), SetThreadContext applies the modification, and ResumeThread starts execution from the redirected address. NtUnmapViewOfSection is never called — this is what defeats most T1055.012-focused EDR detections.</em></figcaption>
</figure>

**The Critical Distinction from Classic Process Hollowing:**

<table class="professional-table">
  <thead>
    <tr>
      <th>Characteristic</th>
      <th>Classic Hollowing (standard T1055.012)</th>
      <th>EAX-Redirect (this Artifact Kit variant)</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>NtUnmapViewOfSection</strong></td>
      <td>Called — original PE is unmapped</td>
      <td class="confirmed">Never called — original PE stays mapped</td>
    </tr>
    <tr>
      <td><strong>Original process image</strong></td>
      <td>Removed and replaced with malicious PE</td>
      <td>Intact and unmolested throughout</td>
    </tr>
    <tr>
      <td><strong>Memory layout</strong></td>
      <td>Unmapped sections; replaced image at original base</td>
      <td>Original PE + separate suspicious RX allocation</td>
    </tr>
    <tr>
      <td><strong>Memory protection sequence</strong></td>
      <td>Typically RWX or single-stage write then execute</td>
      <td>RW write → RX execute (never simultaneous RWX)</td>
    </tr>
    <tr>
      <td><strong>Thread injection method</strong></td>
      <td>SetThreadContext after unmapping/replacing image</td>
      <td>SetThreadContext on suspended thread, no image replacement</td>
    </tr>
    <tr>
      <td><strong>EDR hooks missed</strong></td>
      <td>CreateRemoteThread (Sysmon Event 8)</td>
      <td class="critical">NtUnmapViewOfSection hook, ETW image-unmap trace, RWX allocation rules</td>
    </tr>
    <tr>
      <td><strong>Correct detection anchor</strong></td>
      <td>NtUnmapViewOfSection, ZwUnmapViewOfSection</td>
      <td class="critical">SetThreadContext on suspended-state threads from service processes</td>
    </tr>
  </tbody>
</table>

**Why This Detection Gap Is Systematic:**

The Cobalt Strike Artifact Kit service variant is a stock CS component — not a modification by UTA-2026-004. This means the EAX-redirect detection gap affects every CS deployment using the default Artifact Kit service template, not just this campaign. Organizations relying on NtUnmapViewOfSection monitoring for T1055.012 coverage should audit whether their EDR coverage extends to SetThreadContext-based variants.

The two-stage RW→RX memory protection sequence additionally defeats single-stage RWX allocation detection rules, which commonly flag `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` as high-confidence malicious. This variant never creates a RWX region.

**How to Detect EAX-Redirect:**

- Monitor `SetThreadContext` API calls targeting threads in a suspended state — especially when the calling process is a service binary and the target process is `rundll32.exe` with no command-line arguments
- Alert on the call chain: `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx(RX)` → `SetThreadContext` all originating from the same PID within a short time window
- Sysmon Event ID 10 (process access) catches the cross-process memory operations. Sysmon Event ID 8 (CreateRemoteThread) will NOT fire — this variant uses SetThreadContext, not CreateRemoteThread.
- Pre-execution indicators: service name `DceRpcSs` (Security Event 7045) and named pipe pattern `MSSE-*-server` (Sysmon Events 17/18) are reliable early warning signals

**Named Pipe Default — Stock Indicator:**

The named pipe `\\.\pipe\MSSE-%d-server` (where `%d` = GetTickCount() % 9898) is a well-documented default Artifact Kit indicator. CS hunting guides describe this as a "dead giveaway" for operators who deploy the Artifact Kit without modifying default configurations. UTA-2026-004 has not changed this default.

---

### 4.3 CovertVPN: Layer 2 Network Tunneling

> **Analyst note:** CovertVPN is a Cobalt Strike module that creates a bridge between the attacker's machine and the victim's internal network, operating at the raw Ethernet frame level. Standard proxy pivoting (SOCKS) lets an attacker reach specific services. CovertVPN hands the attacker full Layer 2 network access — ARP scanning, raw protocol attacks, VLAN traversal, and any network capability routable through the victim host. It is a specialized capability that requires administrator access and silently installs a kernel-mode driver on the victim system.

**File Properties:**

| Field | Value |
|---|---|
| Filename | `covertvpn.dll` |
| SHA256 | `af688b120db0a3b324e2cd468cfead71b7895a3c815f4026d51ac7fca0cb8ab4` |
| Size | ~556KB (including embedded WinPcap 4.1.3 stack) |
| Type | Reflective DLL |
| Config template | `"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"` — unpatched placeholder |

**Five Transport Channels:**

| Char Code | Transport | Description |
|---|---|---|
| `t` | TCP connect | Outbound TCP tunnel to operator-controlled server |
| `b` | TCP bind | Listening TCP server on victim host |
| `u` | UDP | UDP datagram tunnel |
| `h` | HTTP | WinINet connection via `/receive{session_id}` endpoint |
| `i` | ICMP | ICMP echo request/reply tunnel (most covert channel) |

**ICMP Tunnel Protocol:**

The ICMP transport is the most operationally interesting channel because ICMP is routinely permitted through network perimeters and rarely inspected at payload depth.

```
ICMP payload frame structure:
  [2B big-endian frame length] [frame data]
  → Multiple frames packed per ICMP packet (maximum ~8KB)

Frame type markers (at payload offset 4-5):
  0xDD = data frame (Ethernet frame data follows)
  0xCC = keepalive heartbeat (no data)

Direction: Bidirectional — both ICMP echo request (client→server)
           and ICMP echo reply (server→client) carry data/keepalive
```

**Detection indicators for ICMP tunnel:**
- ICMP echo request/reply packets with payload size exceeding 128 bytes
- Bytes 0xDD or 0xCC appearing at payload offset 4–5
- High-frequency ICMP exchange between the same endpoint pair (keepalive cadence)
- Anomalously high total ICMP byte volume from a Windows workstation

**Embedded WinPcap 4.1.3 Deployment:**

CovertVPN is self-contained — no WinPcap pre-installation is required. The DLL's `.data` section embeds the full WinPcap 4.1.3 package (x86 and amd64 `npf.sys` kernel driver, `wpcap.dll`, `Packet.dll`). An architecture-aware dropper selects the appropriate `npf.sys`, writes it to `%TEMP%\npf.sys`, and installs it as a kernel driver service via the Windows Service Control Manager. Administrator-level access is required.

**Detection indicators for WinPcap deployment:**
- Sysmon Event ID 6 (driver loaded) from path `%TEMP%\npf.sys`
- Windows Event 7045 (new service installed) with service name `npf`
- `wpcap.dll` and `Packet.dll` written to the `%TEMP%` directory

**Unpatched Config Template:**

The AES key placeholder string `"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"` at config offset `0x100a2b58` is present in the recovered sample, indicating the CovertVPN module was not fully configured for operational deployment. A deployed operational instance would have this placeholder replaced with an actual AES-128 key. The placeholder is a YARA-detectable indicator (see detection file) that differentiates undeployed templates from operational instances.

---

### 4.4 Six Custom Loader Variants

> **Analyst note:** A loader is a small program whose sole purpose is to load a larger malicious program into memory and execute it. The operator built six of these using a shared code template, each with a slightly different execution mechanism. Detecting the loader is often the first and best opportunity to catch an attack before the main payload runs — the loaders are simpler than the beacons and leave more predictable behavioral traces.

Five loaders share a common GCC 15 codebase with progressively specialized execution paths. A sixth uses a fundamentally different disk-based approach:

| Loader | Execution Method | Payload Type | SHA256 |
|---|---|---|---|
| `beacon_loader.exe` | VirtualAlloc(RWX) → indirect call | Shellcode | `04720e01f059...` |
| `beacon_rdi.exe` | VirtualAlloc(RWX) → call buf+0x1649c | Reflective DLL | `f0fc7d3b3f7b...` |
| `beacon_srdi2.exe` | VirtualAlloc(RWX) → indirect call | sRDI v2 shellcode | `7c643568b321...` |
| `beacon_dl.exe` | VirtualAlloc(RWX) → CreateThread | Shellcode (download mode) | `820cf45c92b9...` |
| `beacon_full.exe` | VirtualAlloc(RWX) → CreateThread | Shellcode (full mode) | `89ec81f862be...` |
| `dll_loader.exe` | LoadLibraryA(hardcoded path) | Disk DLL | `b0f0fe97b653...` |

**Code Reuse Tree:**

```
beacon_loader.exe (base — 6,048 bytes .text)
  |-- beacon_srdi2.exe (identical .text, 310KB sRDI payload embedded)
  |-- beacon_rdi.exe (+240 bytes — RDI bootstrap, call at offset 0x1649c)
  |-- beacon_dl.exe (+304 bytes — CreateThread + WaitForSingleObject)
  |-- beacon_full.exe (+304 bytes — CreateThread, different payload)

dll_loader.exe (separate codebase — 30,720 bytes .text)
```

**dll_loader.exe — The Disk-Based Outlier:**

`dll_loader.exe` writes a beacon DLL to the hardcoded path `C:\Windows\Temp\beacon.dll` and loads it via `LoadLibraryA`. An infinite `Sleep(60000)` loop maintains the host process as a keepalive for the loaded DLL. This is the simplest loader in the set and the easiest to detect via file system monitoring.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-dll-loader-hardcoded-path.png" | relative_url }}" alt="Ghidra decompiler output showing dll_loader.exe with the hardcoded file path string C:\Windows\Temp\beacon.dll passed to LoadLibraryA, followed by an infinite Sleep(60000) loop that keeps the host process alive as a keepalive for the loaded beacon DLL">
  <figcaption><em>Figure 14: dll_loader.exe showing the hardcoded path "C:\Windows\Temp\beacon.dll" passed to LoadLibraryA, followed by an infinite Sleep(60000) loop. This disk-based approach is the simplest and most detectable loader variant — file system monitoring for DLL writes to %WINDIR%\Temp\ followed by LoadLibraryA provides a high-confidence detection anchor.</em></figcaption>
</figure>

**Shared Behavioral Pattern (all five in-memory loaders):**

All five share a detectable behavioral sequence:
1. Single `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)` — single-stage RWX allocation (contrast with Artifact Kit's two-stage approach)
2. `memcpy` from `.data` section (embedded payload) into the RWX region
3. Execution via indirect function call (three loaders) or `CreateThread` (two loaders)

The single-stage RWX allocation is detectable by EDR behavioral monitoring for `VirtualAlloc(PAGE_EXECUTE_READWRITE)` followed by code execution from the allocated region.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/new-files-found-20260408/openstrike-loader-virtualalloc-indirect-call.png" | relative_url }}" alt="Ghidra decompiler output showing the base loader pattern shared across five variants: VirtualAlloc called with MEM_COMMIT and PAGE_EXECUTE_READWRITE flags allocating a single RWX memory region, followed by memcpy copying the embedded payload from the .data section, and an indirect function call transferring execution to the shellcode">
  <figcaption><em>Figure 15: Shared loader pattern across all five in-memory variants — VirtualAlloc(MEM_COMMIT | PAGE_EXECUTE_READWRITE) allocates a single RWX region, memcpy copies the embedded payload from the .data section, and an indirect call transfers execution. The single-stage RWX allocation (contrast with Artifact Kit's two-stage RW→RX approach in Section 4.2) is the primary behavioral detection anchor for this loader family.</em></figcaption>
</figure>

---

### 4.5 Complete CS 4.9.1 Installation Overview

The `cs_ts.log` recovered from the open directory confirmed the team server operational profile:

```
Version:         CS 4.9.1 (Pwn3rs) — cracked/patched license
Team Server:     0.0.0.0:50050 (externally accessible)
SSL Cert SHA256: 6e8efd85110de376426cde809f25d50ffcbb1d0e39d11c82913757cb277e15dd
HTTP Listener:   x86 + x64, WinInet, Exit Function: Process
Active Beacons:  7 loaded; 0 keystrokes/screenshots/downloads recorded
Status:          Freshly deployed or recently wiped
```

**Three Malleable C2 Profiles Confirmed:**

| Profile | GET URI | POST URI | Port | User-Agent | Beacon |
|---|---|---|---|---|---|
| A | `/updates` | `/submit` | 80 / 8443 | Default | beacon_full.x64.dll, beacon_port80.x64.dll |
| B | `/ga.js` | `/submit.php` | 80 / 809 | Default | beacon_min.exe, beacon_cs_debug.exe, beacon_x64_sniff.exe |
| C | `/en_US/all.js` | `/submit.php` | 80 | IE9 (BOIE9;ENUSSEM) | beacon80.dll |

Profile C impersonates Google Analytics and Internet Explorer 9 — the `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUSSEM)` user-agent string is a distinctive detection indicator, as IE9 is no longer in active use.

**Stager Shellcode:**

| File | Type | URI | Port | SHA256 |
|---|---|---|---|---|
| `stager_http_x64.exe` | PE stager (~1KB) | `/au2U` | 80 | `86b581e40a9ff9...` |
| `stager_http_x64.ps1` | PowerShell wrapper | `/msI4` | 80 | `f618c8073bbc1...` |

Both implement standard CS HTTP reverse stager behavior: PEB-walk API resolution, `VirtualAlloc(RWX)`, `InternetReadFile` loop. The PowerShell stager uses `AllocHGlobal` + `GetDelegateForFunctionPointer` for shellcode execution — the standard PowerShell shellcode execution pattern.

**Social Engineering Kit (stock, undeployed):**

Six JavaScript templates recovered: `analytics.js` (credential harvester), `keylogger.js` (browser keypress capture with obfuscated variables), `deployJava.js` (Java plugin detection), `reader.js` (PDF reader detection), `redirect.js`, `stay.js`. All contain unsubstituted template placeholders — not customized for deployment.

---

## 5. Infrastructure Analysis

### 5.1 Server Architecture: 172.105.0.126

The single VPS at `172.105.0.126` serves five distinct operational roles:

| Port | Role | Evidence |
|---|---|---|
| 80 | HTTP C2 + stager delivery | Multiple beacon configs, stager URIs /au2U and /msI4 |
| 809 | Secondary HTTP C2 (debug/sniffer) | beacon_cs_debug.exe and beacon_x64_sniff.exe configs |
| 8443 | HTTPS C2 | Published April 6 (beacon_patched.x64.dll, gen-3 OpenStrike) |
| 8888 | Open directory / staging server | Complete toolkit exposure |
| 50050 | CS team server management | cs_ts.log confirmed CS 4.9.1, externally accessible |

**OPSEC finding — port 50050 external exposure:** The CS team server management interface is externally accessible. This exposes the operator's team server to scanning, fingerprinting, and potential exploitation by third parties, and makes the installation trivially confirmable via Shodan.

**Hosting context:** Linode/Akamai Technologies (AS63949), Canadian jurisdiction (ARIN). Commercial mainstream VPS — zero bulletproof hosting indicators. Canadian jurisdiction significantly lowers the barrier for abuse reporting and law enforcement coordination relative to non-cooperative jurisdictions.

### 5.2 RSA Key Ecosystem Mapping

Two distinct RSA key ecosystems co-exist across 10 recovered beacon DLLs:

**Key A — RSA-2048 "Trinity Protocol":**
- Modulus prefix: `9f12c9cb6582f379...`
- Present in: CS 3.x beacon (watermark 0), CS 4.4 beacons (watermark 987654321)
- Custom beacon import: gen-3 OpenStrike — byte-for-byte identical key

**Key B — RSA-1024:**
- Modulus prefix: `008cadd72dbf3cc108...`
- Present in: CS 4.4 beacons (watermarks 0 and 987654321), 5 artifact-wrapped beacons
- Custom beacon import: gen-2 OpenStrike (mini_beacon2.exe) — byte-for-byte identical

The operator extracted RSA keys from existing beacon DLLs and embedded them in custom implant code, then migrated from Key B → Key A → no RSA across the custom beacon generations. This demonstrates active tracking of and engagement with CS's internal key architecture.

### 5.3 Auth/JAR Keypair Mismatch — OPSEC Finding

The `.auth` file on the open directory does not match the private key corresponding to the CS 4.9.1 JAR's `authkey.pub` (RSA-2048, MD5: `8bb4df00c120881a1945a43e2bb2379e`). This mismatch prevents decryption of all 56 encrypted sleeve DLLs. The full Java key derivation chain (`Authorization`, `AuthCrypto`, `SleeveSecurity` classes) was reverse-engineered to confirm the mismatch mechanism.

The mismatch is evidence of toolkit assembly from at least two different cracked distributions. This is an OPSEC failure pointing to opportunistic rather than systematic tool acquisition — an operator with a single trusted supply source would not produce this inconsistency.

---

## 6. Threat Intelligence Context

### 6.1 CS 4.9.1 "Pwn3rs" Cracked Distribution

**Confidence: HIGH (85%)**

"Pwn3rs" / "Pwn3rzs" is the branding of the most widely distributed cracked CS 4.9/4.9.1 package currently in active use. Distribution documentation:

- **Origin date:** Approximately 2023-10-09 via Telegram and Kanxue forum (bbs.kanxue.com threads 279166, 279348, 280276)
- **SSL pivot:** Shodan query `ssl:"Pwn3rs Striked"` identifies active deployments sharing this distribution — documented by researcher Chris Duggan (@TLP_R3D, September 2024)
- **Attribution status:** "Pwn3rs" is distribution branding, NOT an operator persona. Attributing this campaign to an actor named "Pwn3rs" would misrepresent the evidence.

**Infrastructure pivot result:** The specific SSL cert SHA256 `6e8efd85...` returned no hits in either open-source or paid threat intelligence platforms (Shodan and Censys paid queries both yielded zero results). This confirms the team server was either not indexed by internet scanners prior to the April 6 discovery, actively blocked scan traffic, or the cert is unique to this single deployment. This pivot is closed — no additional infrastructure was identified through certificate correlation.

### 6.2 CS Watermark 987654321 — Distribution-Level Indicator

**Confidence: HIGH (88%) — distribution association, NOT operator identity**

Watermark 987654321 is a high-prevalence pirated CS watermark found in multiple independent hunting datasets. Key documented associations:

- svch0st's beacon hunting study (2021): among the most common non-zero watermarks in threat hunting datasets alongside 666666666 (Tier 3 source)
- Intel Dalal / Medium: identified on infrastructure pointing to Tencent API Gateway (`service-owedaeao-1304783326.gz.tencentapigw.com.cn/api/x`) — suggestive of Chinese-nexus origin (Tier 3 source)
- CybersecurityNews (DFIR Report attribution, 2024): found alongside `红队版.zip` containing TaoWu, Landon (CS extension frameworks), and Viper C2 — characteristic of Chinese-language red team toolkit packaging

**Critical finding — You Dun attribution rejected:** The You Dun group has been documented using watermark 987654321. The infrastructure analyst explicitly assessed this attribution as INSUFFICIENT: Canadian Linode hosting (atypical for documented You Dun infrastructure), zero Chinese-language strings in 106 samples, no Chinese domestic C2 patterns, and no key overlaps with documented You Dun infrastructure. The shared watermark is explained by shared distribution availability, not operational linkage.

**Prevalence caveat:** Watermark 987654321 appears in hundreds of active CS deployments. Presence of this watermark alone is not a clustering signal — additional technical evidence is required to link deployments sharing this watermark.

### 6.3 EAX-Redirect in the Broader CS Ecosystem

**Confidence: DEFINITE (95%) for technique classification**

The EAX-redirect hollowing in the Artifact Kit service variant is stock CS behavior documented in Cobalt Strike's official blog ("Cobalt Strike's Process Injection: The Details"). The detection gap arises from the gap between what CS stock components do and what most EDR T1055.012 rules monitor — it is a systematic gap affecting all CS deployments using the Artifact Kit service template, not a UTA-2026-004-specific innovation.

CrowdStrike's 2024 research on HijackLoader confirmed that EAX register redirect (SetThreadContext without NtUnmapViewOfSection) is observed in modern crimeware and remains a detection gap in endpoint products that rely on traditional API-based hollowing signatures.

### 6.4 Ecosystem Exposure

**Software abused or embedded:**

| Component | Source | Exposure Category |
|---|---|---|
| Cobalt Strike 4.9.1 (cracked) | Pwn3rzs distribution, Kanxue/Telegram | Cracked commercial offensive tooling |
| Cobalt Strike 3.x / 4.4 artifacts | Older cracked distributions | Legacy cracked tooling |
| WinPcap 4.1.3 (npf.sys + wpcap.dll) | Embedded in CovertVPN DLL | Legitimate packet capture driver repurposed |

**Hosting provider:** Linode/Akamai Technologies (AS63949), Canada. Commercial legitimate VPS — no bulletproof hosting indicators. Canadian jurisdiction lowers the barrier for abuse reporting and law enforcement coordination. Downstream abuse risk to other Linode customers is limited to shared-IP reputation effects.

**Supply chain implications:** UNKNOWN — the toolkit is assessed as pre-deployment. No trojanized delivery vector or software supply chain compromise has been observed. The social engineering kit templates (analytics.js, keylogger.js) remain undeployed with template placeholders intact. No downstream victims or compromised legitimate software packages have been identified.

**Developer ecosystem risk:** The OpenStrike custom implant is a novel, undocumented family. If the operator completes gen-5 (resolving the missing key exchange), the resulting implant would be invisible to all CS-specific detection signatures and would represent an independent capability that other actors could potentially adopt or adapt if the operator's development files were themselves leaked or shared.

### 6.5 Mixed CS Version Sourcing Pattern

**Confidence: HIGH (87%)**

CS 3.x + 4.4 + 4.9.1 co-existence with two RSA key ecosystems is characteristic of multi-distribution toolkit assembly over time. When a CS distribution is cracked and distributed, each distribution defines its own auth file, watermark, and RSA key pair. Mixing artifacts from two distributions creates the observable keypair mismatch documented here.

The inference: UTA-2026-004 accumulated artifacts from CS 3.x-era material (pre-2016 watermark 0), CS 4.4-era material (2021-era, watermark 987654321), and the 4.9.1 "Pwn3rs" team server (2023-era) — spanning participation in the cracked CS ecosystem over at least 2–3 years. The operator is a consumer of this ecosystem, not a producer.

---

## 7. VirusTotal Intelligence: 72-of-98 First Reports

| Category | Submitted | First-Reports | Previously Known |
|---|---|---|---|
| Custom GCC 15 tools (OpenStrike) | 10 | 10 | 0 |
| CS beacon DLLs (unencrypted) | 4 | 3 | 1 |
| CS Artifact Kit wrappers | 18 | 15 | 3 |
| Scripts/templates | 15 | 13 | 2 |
| Other PE utilities | 7 | 7 | 0 |
| Encrypted sleeve DLLs (sampled) | 44 | 24 | 20 |
| **Total** | **98** | **72 (73.5%)** | **26** |

All 10 custom GCC 15 operator tools — including all four OpenStrike beacon generations — were first-reports. OpenStrike has no prior public threat intelligence. The 26 previously known files were primarily Artifact Kit templates and the gen-3 beacon from the April 6 report.

---

## 8. Threat Actor Assessment: UTA-2026-004

> **Analyst note:** This section addresses who is behind this campaign and what we can and cannot determine about their identity. The short answer is: we cannot identify a specific named actor. The longer answer explains what the evidence does tell us — and why the evidence that might suggest a Chinese-linked actor is insufficient for that conclusion.

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-004 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

**Attribution Decision:** UTA-2026-004 — maintained. No upgrade warranted.

**Confidence:** INSUFFICIENT for any named actor (<50%).

**"Pwn3rs" as actor persona — REJECTED:** Pwn3rs/Pwn3rzs is cracked CS distribution branding originating from bbs.kanxue.com (October 2023), confirmed by multiple Tier 3 and forum-level sources. The name appears in team server logs because the cracked JAR's license emulation code generates it — not because the operator chose it.

**"You Dun" attribution — INSUFFICIENT:** Watermark 987654321 overlap with documented You Dun cases is explained by shared distribution availability. Six technical dimensions contradict a You Dun/UTA-2026-004 linkage: hosting geography, language artifacts, C2 architecture, compiler toolchain, RSA key sets, and operational timing.

**Alternative Hypotheses:**

| Hypothesis | Evidence Consistency | Ruling Evidence |
|---|---|---|
| H1: Pre-operational capability development | HIGH | WIP gen-4, 0 victims, fresh/wiped server, open directory OPSEC failure |
| H2: Non-Chinese actor using Chinese-sourced tools | MODERATE | Canadian hosting, no Chinese strings, shared watermark widely available |
| H3: Chinese-nexus actor | MODERATE | Watermark 987654321, Pwn3rs from Kanxue — but these are distribution indicators |
| H4: Named APT (You Dun, other) | LOW | No credible technical overlaps beyond shared distribution |

H1/H2/H3 cannot be distinguished with available evidence. The pre-operational assessment (H1) is the most consistent with the full evidence set.

**Updated UTA-2026-004 Actor Profile:**

Building on the April 6 profile, the following characteristics are now confirmed:
- CS 4.9.1 Pwn3rzs distribution as current team server
- Second cracked CS distribution watermark 987654321 (CS 4.4 components)
- GCC 15.2.0 as current build environment (newest toolchain observed)
- 4-generation beacon evolution chain — began with CS key B, migrated to key A, now building RSA-independent
- Mixed cracked CS distribution assembly (auth/JAR keypair mismatch)
- JAR authkey.pub MD5: `8bb4df00c120881a1945a43e2bb2379e`

**What would increase attribution confidence:**
- A second OpenStrike campaign sighting — even one reuse would enable actor clustering
- SSL cert `6e8efd85...` pivot — searched in paid Shodan and Censys with no results (closed)
- Language artifacts or operational timing analysis (UTC+8 window would be significant)
- Victim identification or targeting pattern

---

## 9. MITRE ATT&CK Coverage

*Table shows only HIGH confidence technique mappings. LOW confidence techniques omitted.*

| Tactic | Technique ID | Technique Name | Confidence | Key Evidence |
|---|---|---|---|---|
| Resource Development | T1587.001 | Develop Capabilities: Malware | HIGH | 4-generation OpenStrike implant development chain |
| Execution | T1059.001 | PowerShell | HIGH | stager_http_x64.ps1 AllocHGlobal + GetDelegateForFunctionPointer |
| Execution | T1059.003 | Windows Command Shell | HIGH | cmd.exe /c via CreatePipe in gen-4 beacon Shell (0x02) |
| Execution | T1059.007 | JavaScript | HIGH | keylogger.js browser capture; analytics.js credential harvester |
| Execution | T1106 | Native API | HIGH | Direct VirtualAlloc, CreateThread, WinHTTP, BCrypt API calls |
| Execution | T1569.002 | Service Execution | HIGH | artifact32svc.exe registers DceRpcSs service |
| Persistence | T1543.003 | Windows Service | HIGH | DceRpcSs service; npf.sys kernel driver service |
| Defense Evasion | T1055.002 | PE Injection | HIGH | VirtualAlloc(RWX) + memcpy + execute across 5 in-memory loaders |
| Defense Evasion | T1055.012 | Process Hollowing | HIGH | EAX-redirect via SetThreadContext — no NtUnmapViewOfSection |
| Defense Evasion | T1036.004 | Masquerade Task or Service | HIGH | DceRpcSs mimics legitimate Windows RpcSs |
| Defense Evasion | T1036.005 | Match Legitimate Name or Location | HIGH | C:\Windows\Temp\beacon.dll; rundll32.exe as hollowing target |
| Defense Evasion | T1027 | Obfuscated Files or Information | HIGH | XOR-encoded shellcode in Artifact Kit; AES-encrypted sleeve DLLs |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | HIGH | 4-byte rolling XOR decode in artifact32svc pipe reader |
| Defense Evasion | T1620.001 | Reflective Code Loading | HIGH | beacon_rdi.exe hardcoded-offset ReflectiveLoader call |
| Defense Evasion | T1218.011 | Rundll32 | HIGH | rundll32.exe spawned with no arguments as hollowing target |
| Discovery | T1082 | System Information Discovery | HIGH | GetComputerNameA, GetUserNameA across all beacon generations |
| Discovery | T1057 | Process Discovery | HIGH | CreateToolhelp32Snapshot in gen-4 cmd_ps (0x20) |
| Discovery | T1033 | System Owner/User Discovery | HIGH | Whoami (0x1B) — ComputerName\\UserName |
| Discovery | T1083 | File and Directory Discovery | HIGH | FindFirstFileA in gen-4 cmd_ls (0x21) |
| Collection | T1005 | Data from Local System | HIGH | Download (0x09) — CreateFileA + ReadFile + encrypted POST |
| Command and Control | T1071.001 | Web Protocols | HIGH | HTTP GET/POST via WinHTTP (gen-4) and WinInet (CS DLLs) |
| Command and Control | T1573.001 | Symmetric Cryptography | HIGH | AES-128-CBC + HMAC-SHA256 (gen-4); AES-128-CBC (CovertVPN) |
| Command and Control | T1132.001 | Standard Encoding | HIGH | Base64 in PS1 stager; RSA ciphertext encoding in gen-2 |
| Command and Control | T1095 | Non-Application Layer Protocol | HIGH | ICMP echo tunnel in CovertVPN (0xDD/0xCC frame markers) |
| Command and Control | T1572 | Protocol Tunneling | HIGH | CovertVPN L2 bridge — Ethernet frames over ICMP/TCP/UDP/HTTP |
| Command and Control | T1105 | Ingress Tool Transfer | HIGH | Stager downloads beacon via /au2U (EXE) and /msI4 (PS1) |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | HIGH | Download command sends file contents via encrypted POST /submit |
| Execution | T1129 | Shared Modules | HIGH | dll_loader.exe LoadLibraryA(C:\Windows\Temp\beacon.dll) |

*T1056.001 (Keylogging via keylogger.js) and T1112 (Registry modification via template.vbs) omitted — MODERATE confidence only, pending deployment evidence.*

---

## 10. Indicators of Compromise

IOCs are provided in structured machine-readable format. This feed contains only new indicators from the April 8 expanded analysis — not duplicating the April 6 feed.

- **New IOC feed:** [/ioc-feeds/new-files-found-20260408-iocs.json](/ioc-feeds/new-files-found-20260408-iocs.json)
- **Original IOC feed (April 6):** [/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json](/ioc-feeds/open-directory-172-105-0-126-20260406-iocs.json)

**IOC Summary (new indicators from this investigation):**

| Category | Count |
|---|---|
| SHA256 hashes | 22 |
| MD5 hashes | 6 |
| SHA1 hashes | 4 |
| IPv4 + port combinations | 3 (ports 80, 809, 50050 on 172.105.0.126) |
| URLs | 6 |
| Windows services | 2 (DceRpcSs, npf) |
| User-Agent strings | 1 (IE9 BOIE9;ENUSSEM) |
| Cryptographic indicators | 5 (RSA modulus, AES IV, watermark, SSL cert, JAR authkey) |
| Behavioral process patterns | 4 |
| File access patterns | 3 |

**High-Priority Indicators for Immediate Action:**

| Indicator | Type | Action |
|---|---|---|
| `172.105.0.126` — extend block to ports 809/50050 | IPv4 | Block (already in April 6 feed) |
| Service name `DceRpcSs` | Service | Hunt/alert — not a legitimate Windows service |
| `\\.\pipe\MSSE-*-server` | Named pipe | Alert on creation (Sysmon Event 17) |
| `C:\Windows\Temp\beacon.dll` | File path | Alert on creation (Sysmon Event 11) |
| `npf.sys` from `%TEMP%` | Driver load | Alert (Sysmon Event 6) |
| HTTP `*?id=[0-9a-f]{8}` GET at ~5s intervals | URI pattern | Network detection (gen-4 beacon) |
| ICMP payload >128B with 0xDD/0xCC | Network pattern | Alert at perimeter |
| UA: MSIE 9.0 … BOIE9;ENUSSEM | User-Agent | Alert (Profile C Malleable C2) |
| SSL SHA256: `6e8efd85110de376...` | TLS cert | Alert at TLS inspection points |

---

## 11. Detection Rules

**[/hunting-detections/new-files-found-20260408-detections/](/hunting-detections/new-files-found-20260408-detections/)**

| Rule Type | Count | Coverage |
|---|---|---|
| YARA | 5 | Gen-4 OpenStrike beacon; CovertVPN unpatched template; Artifact Kit service; GCC 15 loader family; CS mixed-distribution pattern |
| Sigma | 8 | EAX-redirect hollowing; DceRpcSs service; MSSE pipe; npf.sys temp load; Gen-4 C2 polling; CovertVPN ICMP; dll_loader path; rundll32 no-args |
| Suricata | 6 | Gen-4 beaconing; stager downloads; Malleable C2 profiles B and C; CovertVPN HTTP; CovertVPN ICMP |

**Companion file for original samples:** [/hunting-detections/open-directory-172-105-0-126-20260406-detections/](/hunting-detections/open-directory-172-105-0-126-20260406-detections/)

Deploy both detection files for full campaign coverage. Review for deduplication before production deployment.

---

## 12. Intelligence Gaps and Confidence Summary

### Findings by Confidence Level

**DEFINITE:**
- OpenStrike family identification (banner string confirmed)
- CS 4.9.1 "Pwn3rs" team server (cs_ts.log direct evidence)
- 4-generation implant evolution chain (gen-1 through gen-4)
- Gen-4 complete function-level reversal
- Gen-4 WIP status — nonce not transmitted, key exchange broken
- EAX-redirect technique classification (SetThreadContext, no NtUnmapViewOfSection)
- Two RSA key ecosystems mapped across 10 beacon DLLs
- Auth/JAR keypair mismatch confirmed (Java class reverse engineering)
- CovertVPN 5-channel transport documentation
- 5-port server architecture confirmed

**HIGH:**
- Pre-operational staging assessment
- "Pwn3rs" as distribution branding, not operator persona
- Watermark 987654321 as distribution-level Chinese-nexus indicator
- GCC 15.2.0 as current operator build environment
- Intermediate-level CS internals knowledge

**MODERATE:**
- Pre-operational motive over espionage or financial crime
- 2-3 year participation in cracked CS ecosystem
- Chinese-language cracked CS ecosystem as toolkit source

**INSUFFICIENT:**
- Named actor or geographic origin attribution
- Current infrastructure status
- Sleeve DLL contents (encrypted)

### Open Intelligence Gaps

| Gap | Priority | Recommended Action |
|---|---|---|
| SSL cert `6e8efd85...` — no results in paid tools | CLOSED | Searched Shodan and Censys paid platforms — zero results. Cert is unique to this deployment or was never indexed. |
| 172.105.0.126 infrastructure overview | CLOSED | Covered in the [April 6 report](/reports/open-directory-172-105-0-126-20260406/) infrastructure analysis. See original report Section 5 for full IP reputation and hosting details. |
| Open directory current status | MEDIUM | Active probe or Shodan `ip:172.105.0.126 port:8888` |
| Trinity RSA-2048 key origin distribution | MEDIUM | Compare modulus `9f12c9cb...` against known CS 3.x cracks |
| Watermark 987654321 auth file hash | LOW | Would confirm single vs. multiple distribution source |

### Gaps & Assumptions (ACH/KAC)

**ACH Runner-Ups by Conclusion Category**

**Malware family classification (winner: H1 — Novel OpenStrike + cracked CS, DEFINITE confidence)**

- Runner-up: H2 — Previously known toolkit variant. Status: ELIMINATED. The OpenStrike banner string `[*] OpenStrike Beacon starting...` does not match any indexed malware family, all 10 custom GCC 15 tools were VirusTotal first-reports, and no public threat intelligence references this family name. The runner-up is eliminated rather than merely deferred.
- Assumption underlying H1: The banner string is not a deliberate false flag planted to mislead investigators into labeling this a novel family. Sensitivity: LOW. No evidence suggests deliberate misdirection; the four-generation development chain is internally consistent and would not be necessary for a false-flag operation.

**Threat actor motive (winner: H3 — Pre-operational capability development, MODERATE confidence)**

- Runner-up: H2 — Espionage preparation. Status: POSSIBLE but unresolvable with current data. CovertVPN (Layer 2 network pivoting) and a complete post-exploitation toolkit are consistent with both espionage and capability staging for any intrusion type. No specific espionage targeting indicators were observed, but the capability set exceeds what is typically assembled for opportunistic financial crime.
- Evidence needed to distinguish: Victim identification, targeting pattern, or language/timing artifacts pointing to specific sector focus.

**Threat actor attribution (winner: H1/H2 tied — Chinese-nexus or non-Chinese actor using Chinese-sourced tools, INSUFFICIENT confidence for any named actor)**

- Runner-up: H4 — Named APT (You Dun or other). Status: LOW. Six specific technical dimensions contradict the You Dun linkage documented in Section 8. No Tier 1 or Tier 2 source attributes this campaign to any named actor.

**Key Assumptions (KAC)**

| Assumption | Stakes | Sensitivity | Evidence That Would Invalidate |
|---|---|---|---|
| Gen-4 nonce omission is a development bug, not intentional out-of-band key exchange | Gen-4 WIP assessment | HIGH — if wrong, gen-4 may already be deployable | Out-of-band key delivery mechanism (e.g., pre-shared config, SMS, separate channel not observed in samples) |
| The Pwn3rzs distribution is widely available to any actor with Kanxue forum access | Attribution INSUFFICIENT status | HIGH — if distribution is restricted, operator pool is smaller | Evidence of access controls, subscriber vetting, or private-only distribution |
| Custom OpenStrike toolchain is operator-authored, not a shared development within a small group | Actor profiling | MODERATE — if shared, the actor cluster is broader | Second campaign using identical banner string or GCC 15 fingerprint from a separate IP |

---

## 13. Response Orientation

**Detection priorities (highest-fidelity behavioral indicators):**

- EAX-redirect hollowing: `rundll32.exe` spawned with no command-line arguments by a service process, followed by cross-process `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx(RX)` → `SetThreadContext`. Detection anchor must be `SetThreadContext`, NOT `NtUnmapViewOfSection` — the latter is never called.
- Named pipe pattern: `\\.\pipe\MSSE-*-server` creation (Sysmon Event IDs 17/18) — stock Artifact Kit indicator the operator has not changed.
- ICMP anomaly: echo request/reply with payload >128 bytes containing 0xDD or 0xCC markers — CovertVPN tunnel traffic.

**Persistence artifacts to locate and remove:**

- Windows service `DceRpcSs` (masquerades as legitimate `RpcSs` — different name)
- Kernel driver service `npf` installed from `%TEMP%\npf.sys`
- File at `C:\Windows\Temp\beacon.dll`
- Active named pipe `\\.\pipe\MSSE-[0-9]+-server`

**Containment categories:**

- Block `172.105.0.126` at perimeter for all ports — extend existing April 6 block to ports 809 and 50050
- Alert or block SSL certificate SHA256 `6e8efd85110de376426cde809f25d50ffcbb1d0e39d11c82913757cb277e15dd` at TLS inspection points
- Hunt for ICMP tunneling indicators on network egress monitoring
- Deploy detection rules from [/hunting-detections/new-files-found-20260408-detections/](/hunting-detections/new-files-found-20260408-detections/)
- Rotate credentials on any host confirmed to have communicated with 172.105.0.126

---

## 14. References

**Primary Sources (Tier 1):**

- MITRE ATT&CK — T1055.012 (Process Hollowing), T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling), T1543.003 (Windows Service): https://attack.mitre.org
- Cobalt Strike Official Documentation: "Covert VPN — Layer 2 Pivoting"; "Cobalt Strike's Process Injection: The Details"; "Why is rundll32.exe connecting to the internet?"
- Microsoft Documentation: BCryptDeriveKey API reference: https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey

**Threat Intelligence Research (Tier 2):**

- Elastic Security Labs: "Extracting Cobalt Strike Beacon Configurations" — CS crypto architecture (SHA256 key split documentation)
- Unit42 (Palo Alto Networks): "Cobalt Strike Analysis and Tutorial: CS Metadata Encryption and Decryption" — RSA + AES beacon crypto
- hunt.io: "Rare Watermark Links Cobalt Strike 4.10 Team Servers to Ongoing Suspicious Activity" — watermark methodology
- hunt.io: "Guide to Hunting Cobalt Strike, Part 1 (Open Directories)" — open directory hunting context
- thedfirreport.com: "Cobalt Strike, a Defender's Guide" — named pipe and rundll32 detection
- Recorded Future: "Multi-Method Approach to Identifying Rogue Cobalt Strike Servers" — SSL cert fingerprinting methodology
- CrowdStrike: "HijackLoader Expands Techniques" (2024) — EAX redirect in modern malware
- CybersecurityNews (DFIR Report attribution): "Chinese Hackers Toolkit Uncovered" (October 28, 2024) — watermark 987654321 and 红队版.zip case

**Community Research (Tier 3):**

- Chris Duggan (@TLP_R3D, Twitter/X, September 7, 2024): "Pwn3rs Striked" SSL cert Shodan pivot documentation
- Intel Dalal / Medium: "Part 1: Digging into ASNs for Threat Hunting: Cobalt Strike" — watermark 987654321 infrastructure detail
- svch0st / Medium: "Stats from Hunting Cobalt Strike Beacons" (2021) — watermark prevalence data
- Cyphur Blog: "Hunting for Leaked Cobalt Strike v4.9" — Pwn3rzs leak origin documentation
- Sidechannel.blog: "Cobalt Strike: Infrastructure Analysis" — mixed watermark operator patterns

**Forum Documentation (Tier 4 — distribution provenance only):**

- bbs.kanxue.com threads 279166, 279348, 280276 — Pwn3rzs CS 4.9/4.9.1 distribution documentation (Chinese security forum, primary evidence of distribution origin date and channel)

---

## 15. Related Investigation

**Original April 6 Report:** [/reports/open-directory-172-105-0-126-20260406/](/reports/open-directory-172-105-0-126-20260406/)

The original investigation established the OpenStrike family name, the Trinity Protocol cryptographic architecture, UTA-2026-004 designation, and the initial infrastructure profile for 172.105.0.126. Both reports together constitute the complete public technical record of the OpenStrike campaign through April 8, 2026. Deploy IOC feeds and detection rules from both investigations for full coverage.

---

© 2026 Joseph. All rights reserved. See LICENSE for terms.
