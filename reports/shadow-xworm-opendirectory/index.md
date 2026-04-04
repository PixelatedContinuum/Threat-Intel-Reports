---
title: "Shadow RAT & XWorm Open Directory Campaign"
date: '2026-04-04'
detection_page: /hunting-detections/shadow-xworm-opendirectory-detections/
ioc_feed: /ioc-feeds/shadow-xworm-opendirectory-iocs.json
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "151[.]245[.]112[.]70"
    note: "C2 server — Shadow RAT (8990) and XWorm (7007)"
  - value: "harrismanlieb[.]ink"
    note: "Active C2 domain with ScreenConnect"
  - value: "epgoldsecurity[.]com"
    note: "Payload delivery — open directory"
  - value: "240e2575f20c75c6b5e2ea69bc0f0d9675ffd3fea315ca818bcbee2572ee972f"
    note: "ShadowClient.exe production build (SHA256)"
  - value: "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
    note: "XWormClient.exe builder output (SHA256)"
layout: post
permalink: /reports/shadow-xworm-opendirectory/
category: "MaaS Operation"
hide: true
description: "An exposed open directory at epgoldsecurity.com revealed a single operator running Shadow RAT v2.6.4.0 and XWorm 3.0-5.0 from the same C2 server, targeting US victims with tax-season lures during February 2026."
---

**Campaign ID:** OpenDirectory-DualRAT-MaaS-151.245.112.70
**Last Updated:** April 4, 2026
**Threat Level:** HIGH

---

## Bottom Line Up Front

An exposed open directory at `epgoldsecurity.com` revealed a financially-motivated threat actor (UTA-2026-003) operating both Shadow RAT v2.6.4.0 and XWorm 3.0-5.0 against US victims during the 2026 tax season, with all four malware builds connecting to a single C2 server at 151.245.112.70. Shadow RAT is the primary risk: it disables Windows' two main malware detection mechanisms (AMSI and ETW) before any malicious activity begins, and carries a persistence capability that survives OS reinstallation — making detection and remediation significantly harder than a standard RAT infection. Both families must be fully removed for a confirmed infection to be cleared; removing one while the other persists leaves the attacker with full access. Block 151.245.112.70 immediately and check all endpoints for the persistence artifacts documented in Section 10.

---


## Quick Reference

| Resource | Link |
|---|---|
| IOC Feed (machine-readable) | [ioc-feeds/shadow-xworm-opendirectory-iocs.json](/ioc-feeds/shadow-xworm-opendirectory-iocs.json) |
| Detection Rules (YARA, Sigma, Suricata) | [hunting-detections/shadow-xworm-opendirectory-detections.md](/hunting-detections/shadow-xworm-opendirectory-detections.md) |
| Threat Actor Profile | UTA-2026-003 (see Section 8) |

---

# 1. Executive Summary

This investigation documents an active dual-RAT campaign operated by a single, unattributed financially-motivated threat actor (designated UTA-2026-003 *(an internal tracking label used by The Hunters Ledger — see Section 8)*) who deployed both Shadow RAT v2.6.4.0 and XWorm 3.0-5.0 from an exposed open directory at `epgoldsecurity.com`. The combined capability set gives this operator full remote control, credential theft, cryptocurrency clipping, and surveillance capability against US victims, with the advanced persistence and evasion features of Shadow RAT representing the most significant detection and remediation challenge.

This report fills a documented gap: no public threat intelligence exists for the "Shadow RAT v2.6.4.0" branding, this operator's infrastructure cluster, or the `epgoldsecurity.com`/`harrismanlieb.ink` campaign. The analysis is based on static code examination, configuration decryption, and passive DNS pivoting of all five recovered samples.

**What Was Found**

An open directory at `epgoldsecurity.com` exposed four malware binaries across two families deployed by the same operator against US victims during the 2026 tax season. Shadow RAT v2.6.4.0 — assessed with HIGH confidence as a private fork of the open-source Pulsar RAT (itself a Quasar RAT derivative) — is the primary threat: a 50+ capability .NET RAT with AMSI/ETW bypass, HVNC, WinRE persistence, a cryptocurrency clipper, integrated Kematian stealer, and AES-256-CBC encrypted C2. XWorm 3.0-5.0, a commercially available MaaS RAT purchased by the operator, provides redundant access with triple persistence and a six-layer anti-analysis suite. Both families connect to the same C2 IP (151.245.112.70) on separate ports, confirming single-operator control. ScreenConnect was deployed to the C2 server on March 1, 2026, providing the operator a legitimate-looking persistent access channel alongside the malware.

**Why This Threat Is Significant**

Shadow RAT's WinRE persistence capability places it in a category that most standard endpoint remediation processes fail to address — a compromised system with active WinRE persistence can survive an OS reinstallation. The dual-family deployment doubles the operator's persistence surface: both families must be fully remediated for the infection to be cleared. The combination of AMSI bypass (which blinds .NET in-memory scanning) and ETW bypass (which silences event tracing used by EDR telemetry pipelines) creates a detection gap that signatures and behavioral baselines alone cannot fully close. The Kematian stealer integration exfiltrates credentials through Shadow RAT's encrypted C2 channel rather than a separate Discord webhook, reducing the forensic footprint.

**Key Risk Factors**

<table class="professional-table">
  <thead>
    <tr>
      <th>Risk Dimension</th>
      <th class="numeric">Score</th>
      <th>Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Data Exfiltration Risk</strong></td>
      <td class="numeric critical">9/10</td>
      <td>Browser credentials, keylogging, clipboard theft, crypto clipper, Steam tokens, Kematian stealer, webcam/microphone capture</td>
    </tr>
    <tr>
      <td><strong>System Compromise Risk</strong></td>
      <td class="numeric critical">9/10</td>
      <td>Full remote shell, HVNC, process injection, ScreenConnect RMM — complete attacker-controlled access</td>
    </tr>
    <tr>
      <td><strong>Persistence Difficulty</strong></td>
      <td class="numeric high">8/10</td>
      <td>WinRE persistence (survives OS reinstall), triple-redundant XWorm persistence, Registry Run keys across both families</td>
    </tr>
    <tr>
      <td><strong>Evasion Capability</strong></td>
      <td class="numeric high">8/10</td>
      <td>AMSI bypass, ETW bypass, .NET Reactor packing, string obfuscation, hidden window, Zone.Identifier removal, 6-layer anti-analysis (XWorm)</td>
    </tr>
    <tr>
      <td><strong>Detection Difficulty</strong></td>
      <td class="numeric high">7/10</td>
      <td>ETW bypass silences CLR event tracing; AMSI bypass defeats .NET in-memory scanning; AES-256 encrypted C2 channel</td>
    </tr>
    <tr>
      <td><strong>Overall Risk Score</strong></td>
      <td class="numeric critical">8.2/10 — HIGH</td>
      <td>Active infrastructure, US-targeted financial campaign, advanced persistence and evasion, confirmed credential theft capabilities</td>
    </tr>
  </tbody>
</table>

**Threat Actor**

UTA-2026-003 is assessed with LOW confidence (55%) as an independent, financially motivated MaaS consumer — a single operator using commodity and open-source tooling, not a named organized threat group. Infrastructure analysis found zero overlaps with any documented APT or crimeware group. Poor operational security (stable C2 IP for 80+ days, exposed administrative ports, unpatched CVE-2020-0796) is inconsistent with organized group tradecraft.

**For Technical Teams**

- The AMSI + ETW bypass chain executes at Shadow RAT startup before any RAT functionality loads — detection requires targeting the shellcode byte pattern or the runtime string deobfuscation behavior, not API name strings (see Section 5.2)
- XWorm's ip-api.com pre-flight check (`http://ip-api.com/line/?fields=hosting`) is the most reliable behavioral detection trigger — it fires before C2 connection on every execution (see Section 6.2)
- Shadow RAT's WinRE persistence (`DoAddWinREPersistence`) survives standard OS reinstallation — scope assessment must specifically check WinRE modification status (see Section 5.4)
- Detection rules (7 YARA, 10 Sigma, 6 Suricata) are available at the detection file linked in Quick Reference
- Block 151.245.112.70 at perimeter and monitor for all five associated domains

---

# 2. Key Takeaways

- **Dual-RAT, single operator — both families must be remediated together.** Shadow RAT and XWorm share the same C2 IP and are operated by the same actor. Removing one while the other persists leaves the attacker with full access. Any confirmed infection must treat both families as a single, coordinated threat.

- **Shadow RAT's AMSI and ETW bypass fires before any malicious activity begins.** The bypass chain runs as the first two actions in the malware's entry point, neutralizing Windows in-memory scanning (AMSI) and EDR event telemetry (ETW) before the RAT's capabilities load. Detection based on in-process behavioral telemetry is blind after this point; defenders must rely on pre-execution indicators, network telemetry, and host artifacts.

- **WinRE persistence is the highest-priority remediation risk.** Shadow RAT includes a command-activated capability to persist in the Windows Recovery Environment — a partition that survives standard OS reinstallation. If deployed by the operator, a full OS reinstall does not clear the infection. Every confirmed compromise must include a dedicated WinRE modification check.

- **XWorm's ip-api.com pre-flight check is a high-confidence detection signal.** XWorm calls `http://ip-api.com/line/?fields=hosting` before every C2 connection, on every execution. This specific API call followed by a TCP connection to port 7007 is a reliable, low-false-positive behavioral pattern that can be detected at the network layer without requiring endpoint visibility.

- **Credential exposure scope may be wider than malware artifacts indicate.** Shadow RAT harvests browser passwords, Steam tokens, and cryptocurrency wallet data; the integrated Kematian stealer adds Discord tokens and additional credential sources. Credential rotation must address all account types accessible from the compromised endpoint, not only those with direct evidence of access.

- **ScreenConnect deployed on the C2 server may provide attacker access independent of malware.** If the operator installed ScreenConnect on victim machines (in addition to deploying it on the C2 server), ScreenConnect sessions can survive malware removal because security tools typically allow legitimate RMM software. Any confirmed infection must include a ScreenConnect client search on affected endpoints.

- **The open directory exposure is a double-edged finding.** The operator's OPSEC failure (exposed payload directory) provided complete visibility into the toolset, enabling this analysis. The same failure means the operator has likely rotated or modified their toolkit since discovery. The IOC feed and detection rules target the observed samples; organizations should also monitor for behavioral patterns that do not depend on static file artifacts.

---

# 3. Business Risk Assessment

This section translates the technical findings into business-facing risk language. The goal is to equip decision-makers with enough context to prioritize response actions without requiring deep technical knowledge.

### Understanding the Real-World Impact

This investigation uncovered a financially-motivated attacker who has built a functional malware operation using two separate RAT families running simultaneously on the same server. Think of it as two separate break-in tools operated by the same person — if defenders remove one, the other remains active. The attacker's primary goals, as evidenced by the tooling, are stealing login credentials (banking, crypto wallets, Steam gaming accounts, browser passwords), silently monitoring victims (keylogging, webcam, microphone, screen capture), and replacing cryptocurrency wallet addresses during transactions to redirect funds to the attacker.

### Impact Scenarios

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
      <td><strong>Credential theft from browser-stored passwords</strong></td>
      <td class="high">HIGH</td>
      <td>Shadow RAT includes dedicated browser password recovery targeting Chrome, Firefox, Edge and other Chromium-based browsers. This is an always-available capability requiring no operator interaction once the malware runs.</td>
    </tr>
    <tr>
      <td><strong>Cryptocurrency theft via clipboard replacement</strong></td>
      <td class="high">HIGH</td>
      <td>The crypto clipper monitors clipboard contents and replaces Bitcoin, Litecoin, and Ethereum wallet addresses with attacker-controlled addresses during any copy-paste action. A victim copying a crypto payment address to make a transfer would unknowingly send funds to the attacker.</td>
    </tr>
    <tr>
      <td><strong>Silent surveillance (keylogging, screen/webcam/mic capture)</strong></td>
      <td class="high">HIGH</td>
      <td>All surveillance capabilities operate invisibly. The malware creates no visible window or system tray notification. A victim's keyboard input, screen content, webcam feed, and microphone audio can be captured without any behavioral indicator visible to the user.</td>
    </tr>
    <tr>
      <td><strong>Tax document and financial credential theft</strong></td>
      <td class="high">HIGH</td>
      <td>The operator's delivery lures (Form 1040.msi, 2026_Benefits_Enroll) specifically target tax-season activity. Victims who open these files during tax preparation may expose IRS credentials, financial institution logins, and Social Security Numbers to the attacker.</td>
    </tr>
    <tr>
      <td><strong>Persistence surviving standard remediation</strong></td>
      <td class="medium">MEDIUM</td>
      <td>Shadow RAT's WinRE persistence mechanism survives standard OS reinstallation — a remediation action many IT teams consider a "clean slate." If this persistence is activated on a victim machine, a reinstall alone is insufficient to clear the infection. The technique is command-activated (operator must explicitly issue the command), so its presence in the codebase does not guarantee deployment on every victim.</td>
    </tr>
    <tr>
      <td><strong>Lateral movement via Ngrok tunneling</strong></td>
      <td class="medium">MEDIUM</td>
      <td>Shadow RAT includes Ngrok tunneling capability (NgrokPath, NgrokToken config fields), which can establish outbound tunnels that bypass firewall egress controls, potentially enabling the attacker to reach other systems on the same network through the compromised host. Configuration of this capability is operator-initiated.</td>
    </tr>
    <tr>
      <td><strong>Persistent access via ScreenConnect after malware removal</strong></td>
      <td class="medium">MEDIUM</td>
      <td>ScreenConnect (ConnectWise) was deployed to the attacker's C2 server on March 1, 2026. If the attacker used Shadow RAT to install ScreenConnect on victim machines before discovery, ScreenConnect sessions could survive malware removal because it is a legitimate RMM tool that security tools typically do not block.</td>
    </tr>
    <tr>
      <td><strong>Steam gaming account theft</strong></td>
      <td class="medium">MEDIUM</td>
      <td>Shadow RAT includes a dedicated Steam namespace for token theft. Compromised Steam accounts can be sold on underground markets or used for financial fraud (Steam wallet, game items).</td>
    </tr>
  </tbody>
</table>

---

# 4. Malware Classification & Identity

### Sample Inventory

<table class="professional-table">
  <thead>
    <tr>
      <th>Filename</th>
      <th>Family</th>
      <th>SHA256 (truncated)</th>
      <th>Size</th>
      <th>Role</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>ShadoClient.exe</code></td>
      <td>Shadow RAT v2.6.4.0</td>
      <td><code>3a4b0f50...626ab32</code></td>
      <td>2,182,144 bytes</td>
      <td>Staging/test build (most features disabled)</td>
    </tr>
    <tr>
      <td><code>ShadowClient.exe</code></td>
      <td>Shadow RAT v2.6.4.0</td>
      <td><code>240e2575...ee972f</code></td>
      <td>2,181,120 bytes</td>
      <td>Production build (8 feature flags enabled)</td>
    </tr>
    <tr>
      <td><code>Shadow.Common.dll</code></td>
      <td>Shadow RAT (shared library)</td>
      <td><code>6682f3b4...aaab0c</code></td>
      <td>109,568 bytes</td>
      <td>Shared message types, crypto, DNS utilities</td>
    </tr>
    <tr>
      <td><code>XWormClient.exe</code></td>
      <td>XWorm 3.0-5.0</td>
      <td><code>b7fa1e5c...fc4531</code></td>
      <td>74,752 bytes</td>
      <td>Builder output #1 (key: PdqPY2fw6ffCVLQ8)</td>
    </tr>
    <tr>
      <td><code>XWormClient2.exe</code></td>
      <td>XWorm 3.0-5.0</td>
      <td><code>291543374...fd42a</code></td>
      <td>63,488 bytes</td>
      <td>Builder output #2 (key: ZdoNsjYfT6begqDl)</td>
    </tr>
  </tbody>
</table>

Full hashes are available in the [IOC feed](/ioc-feeds/shadow-xworm-opendirectory-iocs.json).

### Classification Summary

<table class="professional-table">
  <thead>
    <tr>
      <th>Attribute</th>
      <th>Shadow RAT v2.6.4.0</th>
      <th>XWorm 3.0-5.0</th>
      <th>Confidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Malware Type</strong></td>
      <td>Remote Access Trojan (RAT)</td>
      <td>Remote Access Trojan (RAT)</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
    <tr>
      <td><strong>Lineage</strong></td>
      <td>Quasar RAT fork; assessed private fork of Pulsar RAT</td>
      <td>Commercial MaaS RAT (XCoder/XCoderTools builder)</td>
      <td class="likely">HIGH</td>
    </tr>
    <tr>
      <td><strong>Language / Framework</strong></td>
      <td>.NET 4.7.2, C#, AnyCPU</td>
      <td>.NET VB.NET, x86</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
    <tr>
      <td><strong>Packer</strong></td>
      <td>.NET Reactor + Costura.Fody (28 embedded assemblies)</td>
      <td>None (obfuscated names only)</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
    <tr>
      <td><strong>Sophistication</strong></td>
      <td>Advanced — significant custom development over open-source base</td>
      <td>Intermediate — commodity builder output</td>
      <td class="likely">HIGH</td>
    </tr>
    <tr>
      <td><strong>Primary Motivation</strong></td>
      <td colspan="2">Financial gain: credential theft, cryptocurrency theft, surveillance</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
    <tr>
      <td><strong>Target Profile</strong></td>
      <td colspan="2">US individuals (tax-season lures: Form 1040.msi, 2026_Benefits_Enroll)</td>
      <td class="likely">HIGH</td>
    </tr>
    <tr>
      <td><strong>C2 Server</strong></td>
      <td>151.245.112.70:8990</td>
      <td>151.245.112.70:7007</td>
      <td class="confirmed">DEFINITE</td>
    </tr>
  </tbody>
</table>

### Analytical Methods: Configuration Decryption

> **Analyst note:** This subsection explains how we extracted the configuration data that underpins the findings throughout this report. The C2 addresses, encryption keys, feature flags, and operator identity links presented in subsequent sections all originate from this decryption work.

Many of the key findings in this report — C2 addresses, shared infrastructure, operator feature flags, and single-operator attribution — were established through manual configuration decryption performed during this investigation. Both Shadow RAT and XWorm store their configurations in encrypted form within the compiled binaries, meaning the raw samples cannot simply be opened and read.

**Shadow RAT config decryption:** The encrypted configuration was extracted from a binary resource embedded in the .NET assembly. A custom Python decryptor was written to replicate the malware's PBKDF2 key derivation (50,000 iterations with a static 32-byte salt extracted from `Shadow.Common.dll`) and AES-256-CBC decryption. The wire format for each config field — `[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-256-CBC ciphertext]` — was reverse-engineered from decompiled code (see Section 5.3 for full technical detail). This process was applied independently to both builds (`ShadoClient.exe` and `ShadowClient.exe`), producing a field-by-field comparison that confirmed identical C2 infrastructure and divergent feature flags between the staging and production variants.

**XWorm config decryption:** XWorm's configuration uses a weaker scheme — Rijndael-256-ECB with a key derived from a non-standard overlapping MD5 construction (see Section 6.4). A separate Python decryptor was written to replicate this derivation and decrypt the config class fields. This was applied to both XWorm builds (`XWormClient.exe` and `XWormClient2.exe`), each of which used a different builder-generated AES key but resolved to the same C2 address.

**Why this matters:** The decrypted configurations from all four samples independently resolved to the same C2 IP address (`151.245.112.70`) — Shadow RAT on port 8990, XWorm on port 7007. This is the primary evidence establishing DEFINITE confidence that a single operator controls both malware families. Without this decryption work, the connection between the two RAT families would have remained unconfirmed, as no plaintext configuration data is visible in the packed binaries.

### Two Shadow RAT Builds: Staging vs. Production

> **Analyst note:** Recovery of both a staging and a production build from the same open directory is an unusual intelligence windfall. The two builds reveal the operator's testing workflow and confirm which capabilities are enabled in actual deployments against victims. The feature flag comparison below is directly relevant to scoping any confirmed infection.

A key finding from the open directory exposure is the recovery of both a staging (test) build and a production build of Shadow RAT. This distinction is operationally significant.

`ShadoClient.exe` (staging) and `ShadowClient.exe` (production) share identical core configuration: same AES key (`97DC71A09A26EAF63C56B6FF2BA582AA3A994D6F`), same C2 address (151.245.112.70:8990), same mutex GUID (`4c7e33e6-3f73-4b4c-a411-89fe63cdfa1e`), and same version string (`2.6.4.0`). The shared mutex means only one can run at a time — they are mutually exclusive variants for different deployment contexts.

The production build enables 8 boolean feature flags (obfuscated names: `bool_2`, `I9iF`, `jU8I`, `cmoY`, `kflb`, `Jjq`, `x9Tg`, `Cm5a`) that activate specific capabilities. The staging build runs in a minimal mode likely used by the operator for testing before deployment. The production install path uses `$77Client.exe` — an unusual filename prefix that may serve as a versioning or identification marker for the operator.

### Two XWorm Builds: Same Campaign, Different Passes

`XWormClient.exe` and `XWormClient2.exe` are both XWorm builder outputs targeting the same C2 (151.245.112.70:7007) but with different builder-generated AES encryption keys (`PdqPY2fw6ffCVLQ8` vs. `ZdoNsjYfT6begqDl`). This indicates the operator ran the XWorm builder twice — a standard operational pattern, likely to have differently-keyed variants for different target batches or to reduce signature correlation between builds.

---

# 5. Technical Analysis — Shadow RAT v2.6.4.0

### 5.1 Static Analysis: File Characteristics

`ShadowClient.exe` and `ShadoClient.exe` are .NET 4.7.2 executables compiled for AnyCPU (64-bit preferred), targeting CLR v4.0.30319. Both are packed with .NET Reactor (a commercial .NET code protection tool) and use Costura.Fody (an embedded resource loader) to bundle 28 dependent assemblies into a single deployable executable. This packaging approach results in high binary entropy (7.663) and makes static analysis significantly more difficult without first unpacking.

A disassembler (Binary Ninja) with .NET Reactor Slayer (a deobfuscation tool) was used to recover the 28 embedded assemblies, inline 2 obfuscated methods, and partially restore symbol names. The recovered assemblies confirm the full capability set through library fingerprinting:

| Library | Purpose |
|---|---|
| `AForge.Video` / `AForge.Video.DirectShow` | Webcam capture (DirectShow API) |
| `NAudio` (Core, Wasapi, WinForms, WinMM) | Microphone/audio capture |
| `SharpDX` (Direct3D11, DXGI, Direct2D1, D3DCompiler, Mathematics) | GPU-accelerated screen capture |
| `Gma.System.MouseKeyHook` | Keylogger and mouse hook |
| `protobuf-net` / `protobuf-net.Core` | C2 message serialization |
| `Shadow.Common.dll` | Shared message types, cryptography, DNS utilities |
| `System.Buffers`, `System.Memory` | Performance/memory utilities |

The entry point after deobfuscation is `mzugzeoqhnabysgpche.KOwpTYUq38OZkEm4OsqXZ8pyS7Gu.Main` — the outer obfuscated class wrapper from .NET Reactor. The binary is not digitally signed.

**Extraction workflow and what it produced:** .NET Reactor Slayer was run against `ShadoClient.exe` to strip the outer packer layer, producing an unpacked working copy (`ShadoClient_Slayed.exe`). The tool also dumped the 28 Costura.Fody-embedded assemblies to disk as standalone DLL files — these assemblies are stored inside the original binary as compressed resources and are never written to disk during normal execution, so dumping them is the only way to inspect their code statically. Cross-assembly analysis in dnSpy (a .NET decompiler) required explicitly loading each extracted DLL alongside the main binary to resolve references; without this, decompiled methods that call into the embedded libraries appear as unresolved symbols. `Shadow.Common.dll` in particular holds the shared message types, the PBKDF2 salt and derivation logic, and the AES/HMAC cryptographic primitives — decompiling this DLL in isolation was what enabled the config decryption described in Section 4.

**What this means for detection:** The presence of `AForge.Video.DirectShow`, `NAudio`, and `SharpDX` in a process that has no legitimate UI visible to the user is a strong behavioral anomaly. A process loading webcam and audio capture libraries while invisible to the user should be treated as suspicious even without signature matches. Critically, defenders will not find the 28 embedded DLLs as separate files on disk during a live investigation — Costura.Fody loads them from compressed resources directly into memory at runtime. File-based scanning and disk forensics alone will only see the single packed executable. Observing the actual loaded assemblies (including `Shadow.Common.dll`) requires memory forensics: enumerating loaded .NET modules in the suspect process (e.g., via `Get-Process | Select-Object -ExpandProperty Modules`, Process Hacker, or a memory-forensics tool's module-listing plugin) or dumping the managed heap. Hash-based IOC matching against the 28 extracted DLL SHA256 values — published in the companion IOC feed — will only match if the DLLs have been dumped from memory or extracted from a captured sample; it will not match the running process's on-disk footprint.

---

### 5.2 AMSI + ETW Bypass Chain

> **Analyst note:** This section describes how Shadow RAT disables two of Windows' primary malware detection mechanisms before running its main features. AMSI (Antimalware Scan Interface) is the Windows system that allows security software to scan code running in memory. ETW (Event Tracing for Windows) is the telemetry infrastructure that security tools use to log and monitor process activity. Disabling both effectively creates a blind spot in the security tooling of the compromised system.

Shadow RAT executes a dual-bypass chain as the first three actions in its `Main()` entry point, before any RAT functionality initializes. This sequence is DEFINITE (direct code inspection):

**Execution sequence:**
1. `smethod_0()` — captures the current thread's desktop handle (HVNC preparation)
2. `smethod_1()` — executes the AMSI bypass
3. `UbNsyes1TwqggpSnHERugShqd7TR()` — executes the ETW bypass

**AMSI Bypass (DEFINITE):**

The bypass loads `amsi.dll` into the process, resolves the export `AmsiScanBuffer`, changes its memory page permissions to writable (using `VirtualProtect`), then overwrites the function's first 15 bytes with shellcode that causes it to return `E_INVALIDARG` (0x80070057) without performing any scan:

```asm
B8 57 00 07 80    mov eax, 0x80070057    ; E_INVALIDARG — "scan failed/invalid"
48 8B 04 24       mov rax, [rsp]         ; recover return address
48 83 C4 08       add rsp, 8             ; clean up stack
FF E4             jmp rsp                ; return to caller
```

After this patch, any call to `AmsiScanBuffer` from the Shadow RAT process returns a permanent "invalid argument" result. Security software that relies on AMSI to scan .NET assemblies loaded into memory will receive this false result and pass the malicious code unchecked.

**String obfuscation used to evade static detection:** The API names are embedded with asterisk padding and deobfuscated at runtime using `.Replace("*", "")`:
- `"a*m*s*i.***dl******l*"` → `amsi.dll`
- `"A**m*siS**c*a*******n*Buf*f*er"` → `AmsiScanBuffer`
- `"n***t**d***ll*.*d*****l*l"` → `ntdll.dll`
- `"**E****t*wEv*e***n*******t**Wr*i*****t**e"` → `EtwEventWrite`

This obfuscation defeats static YARA rules looking for literal API name strings. Detection must instead target the AMSI shellcode byte sequence (`B8 57 00 07 80 48 8B 04 24 48 83 C4 08 FF E4`) or the asterisk-padding deobfuscation pattern.

**ETW Bypass (DEFINITE):**

The ETW bypass is simpler: `EtwEventWrite` in `ntdll.dll` is resolved and its first byte overwritten with `0xC3` (the x86/x64 RET instruction). This causes `EtwEventWrite` to return immediately without writing any event to the ETW infrastructure. The consequence: Sysmon, Windows Defender, and any EDR tool consuming CLR ETW events will receive no telemetry from the Shadow RAT process after this point.

**Detection impact summary:** After these two bypasses fire, Shadow RAT becomes effectively invisible to:
- AMSI-based in-memory scanning (antivirus/EDR)
- CLR ETW events (Sysmon EID 8, process-level .NET activity)
- Security tools that rely on ETW consumers for behavioral detection

Detection must rely on the pre-bypass window (process creation), network telemetry, or registry/file system artifacts — not in-process telemetry.

---

### 5.3 Configuration Encryption & Anti-Tampering

> **Analyst note:** This section explains how Shadow RAT protects its configuration (the settings that tell it which server to connect to and how to behave). The protection is designed both to hide the configuration from analysis and to prevent security researchers from redirecting the malware to a controlled server — a technique called "sinkholing."

Shadow RAT stores its configuration in an AES-256-CBC encrypted binary resource embedded in the executable at build time. The decryption process uses PBKDF2 (Password-Based Key Derivation Function 2) with 50,000 iterations and a static 32-byte salt embedded in `Shadow.Common.dll`:

```
PBKDF2 salt (hex): 5A 23 F8 39 46 40 CB 9E 40 65 84 46 A0 4C 0B BA
                   E8 2D C9 3D 04 70 E1 B2 A4 06 A9 0F D2 52 03 82
```

The master key used as PBKDF2 input is: `97DC71A09A26EAF63C56B6FF2BA582AA3A994D6F`

Wire format for each config field: `[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-256-CBC ciphertext]`

The HMAC is verified before decryption (encrypt-then-MAC ordering — cryptographically correct and stronger than MAC-then-encrypt). This means any modification to the ciphertext is detected before decryption is attempted.

**Anti-tampering via RSA signature (DEFINITE):** After decrypting the config, Shadow RAT performs an additional RSA signature verification: `SHA256(AES_key)` is verified against an embedded RSA signature using an X.509 certificate baked into the binary. If this verification fails, the client exits immediately. This design means:

1. An analyst cannot modify the C2 address in the encrypted config without the operator's RSA private key
2. Sinkholing (redirecting malware to a researcher-controlled server) requires the private key
3. The anti-tampering is inherited from Quasar RAT's design but remains effective against standard config manipulation approaches

**Decrypted config values (confirmed):**

| Field | Value |
|---|---|
| Host | `151.245.112.70` |
| Port | `8990` |
| Version | `2.6.4.0` |
| Mutex | `4c7e33e6-3f73-4b4c-a411-89fe63cdfa1e` |
| Install Sub-Directory | `SubDir` |
| Install Name (production) | `$77Client.exe` |
| Install Name (staging) | `Client.exe` |
| Pastebin mode | `false` (disabled) |

---

### 5.4 Persistence Mechanisms

> **Analyst note:** "Persistence" means the techniques malware uses to survive system restarts and remain active on a compromised machine. Shadow RAT uses two standard techniques and one advanced technique. The advanced technique (WinRE persistence) is notable because it can survive actions that most people assume will completely remove malware, including reinstalling Windows.

**Standard persistence (DEFINITE):**

Shadow RAT installs itself via a `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` registry entry:
- Value name: `Shadow Client Startup`
- Value data: `%APPDATA%\SubDir\$77Client.exe` (production) or `%APPDATA%\SubDir\Client.exe` (staging)

This causes the RAT to launch automatically on user login. The registry key location and value name are distinctive detection indicators.

**WinRE persistence (HIGH confidence — code present, command-activated):**

Shadow RAT includes a `Shadow.Common.Messages.ClientManagement.WinRE` namespace with two operator commands:
- `DoAddWinREPersistence`
- `DoRemoveWinREPersistence`

The Windows Recovery Environment (WinRE) is the pre-boot recovery system used when Windows fails to start. It exists in a protected partition separate from the main OS. Malware that establishes persistence in WinRE can survive a complete OS reinstallation because the WinRE partition is typically not wiped during standard reinstall procedures.

This technique is uncommon: very few EDR products monitor WinRE for modification, and most incident response playbooks do not include WinRE checks. Its presence in this codebase elevates the remediation complexity for any confirmed compromise.

**Important caveat:** This capability is command-activated — the operator must explicitly issue the `DoAddWinREPersistence` command against a compromised host. Its presence in the recovered samples does not confirm deployment on every victim; it confirms the operator has the capability to deploy it selectively. Scope assessment for any confirmed infection must include a WinRE modification check.

**Startup item management (HIGH confidence):**

Additional persistence APIs are present in the codebase for managing HKCU, HKLM, RunOnce, and RunX86 registry keys — giving the operator flexibility to install under multiple registry locations depending on the privilege level available.

---

### 5.5 Command & Control Architecture

> **Analyst note:** This section describes how Shadow RAT communicates with the attacker's server and how it protects that communication channel. The design uses multiple layers of encryption to hide both the communication content and the server address.

**Primary C2 channel (DEFINITE):**

Shadow RAT connects to `151.245.112.70:8990` over TLS 1.2 (TCP). The TLS layer provides transport encryption, but Shadow RAT adds an additional application-layer encryption:

- Wire format: `[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-256-CBC ciphertext]`
- Message serialization: protobuf-net (Google Protocol Buffers for .NET)
- 37 distinct message handler registrations via `IMessageProcessor` interface

This dual-encryption design means network security tools that perform TLS inspection would see the AES-CBC encrypted protobuf payload — not plaintext commands — even if TLS is terminated at a proxy.

**Pastebin dead drop resolver (MODERATE — code present, disabled in samples):**

Shadow RAT implements a dual-mode C2 resolution strategy. The Pastebin mode (`YuMK50gqNyIF4mYC6wcG2HeN` boolean) is `false` in both recovered builds, but the infrastructure is functional. If enabled, Shadow RAT fetches the actual C2 server address from a URL embedded in the config (dead drop pattern — the URL stores a pointer to the real C2 address). This provides the operator a fallback mechanism to redirect compromised hosts if the primary C2 IP is blocked, without redeploying the malware.

**Ngrok tunneling (MODERATE — config fields present):**

Config fields `NgrokPath` and `NgrokToken` indicate Ngrok tunneling capability, which can establish outbound tunnel connections through firewalls using Ngrok's relay infrastructure. If activated by the operator, this creates an outbound connection to Ngrok servers rather than directly to the C2 IP, bypassing IP-based blocking.

**ScreenConnect RMM (HIGH — deployed on C2 server):**

ScreenConnect (ConnectWise) was deployed to the C2 server at 151.245.112.70 on or around March 1, 2026, replacing the Apache-based open directory server (the server now runs IIS/10.0). Port 8040 serves as the ScreenConnect relay port. ScreenConnect is a legitimate remote management tool; its deployment on the C2 server indicates the operator may be using it to manage victim machines through a "legitimate" remote access channel alongside the RAT, reducing the forensic visibility of their access.

---

### 5.6 Surveillance & Data Theft Capabilities

> **Analyst note:** This section documents the operator's collection capabilities — what information Shadow RAT can steal or observe from a compromised machine. All capabilities listed here are confirmed via static code analysis of the Shadow.Common.Messages namespace and the embedded library set.

**Credential theft (DEFINITE):**
- Browser password recovery (`GetPasswordsResponse`, `GetBrowsersResponse`, `CustomBrowserPath`) — targets Chrome, Firefox, Edge, and other Chromium-based browsers
- Kematian stealer integration (`KematianZipMessage`) — a dedicated credential stealer (see Section 9.4) invoked through Shadow RAT's encrypted C2 channel rather than a separate exfiltration path
- Steam token theft (`Shadow.Client.Steam` namespace)
- Wallet detection (cryptocurrency wallet enumeration)

**Cryptocurrency theft (DEFINITE):**
- Crypto clipper: `BitcoinAddress`, `LitecoinAddress`, `EthereumAddress` config fields combined with `SetClipboardMonitoringEnabled` and `SendClipboardData` message handlers implement real-time clipboard monitoring and address substitution
- When active, any BTC/LTC/ETH address copied to clipboard is silently replaced with an attacker-controlled address before the user pastes it

**Surveillance (DEFINITE):**
- Keylogger: `Gma.System.MouseKeyHook` library with obfuscated log file output
- Screen capture: desktop capture + SharpDX Direct3D11/DXGI GPU-accelerated capture (`GetDesktopScreenshot`, `GetDesktopResponse`)
- HVNC (Hidden VNC): `GetHVNCDesktopResponse` — establishes a completely separate hidden desktop session for the operator, invisible to the victim. The operator can interact with applications on this hidden desktop without the victim seeing any mouse or keyboard movement
- Webcam: `AForge.Video.DirectShow` library (`GetWebcamBrowserResponse`, `GetWebcamResponse`)
- Microphone/audio: NAudio library stack (Wasapi, WinForms, WinMM) (`GetMicrophoneAudioResponse`)
- Clipboard monitoring: `GetClipboardTextResponse`, `SendClipboardData`

**HVNC deeper context:** HVNC (Hidden VNC) is more invasive than standard screen capture. Standard screen capture shows what the victim sees. HVNC creates a separate hidden desktop session the victim cannot see at all. An operator using HVNC can open browsers, log into accounts, and conduct transactions on the compromised machine while the victim sees their normal desktop. This capability is particularly relevant for financial fraud — the operator can conduct banking or crypto transactions directly on the victim's machine using the victim's authenticated browser sessions.

---

### 5.7 Evasion & Disruption Capabilities

> **Analyst note:** This section covers the techniques Shadow RAT uses to stay hidden from security tools and to degrade the security controls protecting the compromised system. These capabilities collectively make detection harder, extend the attacker's dwell time, and complicate remediation by removing protective layers that defenders rely on.

**Hidden window (DEFINITE):**
`ShadowClient.exe` sets `this.Visible = false` and `this.ShowInTaskbar = false` in the WinForms `OnLoad` handler. The process runs with a system tray `NotifyIcon` object but shows no taskbar entry or visible window. The process is not a service — it runs as a standard user-space process but with no visual presence.

**Zone.Identifier removal / Mark-of-the-Web bypass (DEFINITE):**
`FileHelper.DeleteZoneIdentifier` removes the `Zone.Identifier` alternate data stream (ADS) from the malware's own executable file. Windows attaches this ADS to files downloaded from the internet; its presence triggers SmartScreen security warnings when the file is executed. Removing it causes the file to appear as if it was not downloaded from the internet, bypassing SmartScreen.

**Firewall disable (HIGH):**
`DoDisableFirewall` command disables the Windows Firewall via `netsh advfirewall` commands, removing a network protection layer on the compromised host.

**AV/Defender disruption (HIGH):**
`DoBlockAVSite` manipulates the Windows hosts file to block antivirus vendor update servers. `DoDefenderOverwrite` is present for Windows Defender disruption.

**UAC bypass (HIGH):**
De-elevation and re-elevation commands in the codebase suggest UAC bypass capability for privilege management, though the specific UAC bypass technique was not isolated in static analysis.

**RunPE/Process Hollowing (MODERATE):**

> **Analyst note:** Process hollowing is a technique where malware launches a legitimate Windows process (such as a system utility), then replaces the legitimate code inside that process's memory with the malicious code. From the outside, it looks like a trusted program is running, but the malicious code is actually executing inside it.

Config fields `UseRunPE`, `RunPETarget`, and `ExecuteInMemoryDotNet` indicate process hollowing capability. The specific target process and trigger conditions are not confirmed from static analysis alone.

**FunStuff/Harassment module (LOW impact — confirmed present):**
A `FunStuff` namespace in `Shadow.Common.Messages` contains non-destructive harassment commands: ransomware-style message display (visual overlay only — no file encryption), screen rotation, GDI graphical effects, jump scare, sound mute/unmute, and forced Windows Update trigger. These are operator-controlled troll/harassment tools and do not represent a serious impact capability.

---

# 6. Technical Analysis — XWorm 3.0-5.0

### 6.1 Static Analysis: File Characteristics

`XWormClient.exe` and `XWormClient2.exe` are .NET executables written in VB.NET, compiled for x86 (32-bit), targeting CLR v4.0.30319. Unlike Shadow RAT, they are not packed with a commercial packer — protection relies entirely on obfuscated class and method names. File entropy is moderate (6.01–6.03), consistent with obfuscated .NET without compression.

The binary structure consists of three sections: `.text` (high entropy, obfuscated code), `.rsrc` (low entropy, standard resources), and `.reloc` (minimal relocation data). Entry classes follow a `Stub.` prefix naming pattern (`Stub.FiNjJdc7MwurRPek8XtW5lm` for build #1, a longer obfuscated string for build #2). The `<Xwormmm>` campaign group tag is embedded in plaintext as a builder-configured identifier.

**Two builds, same configuration, different keys:** Both XWorm builds share identical C2 configuration (host `151.245.112.70`, port `7007`, group `<Xwormmm>`, USB spread filename `USB.exe`) but use different builder-generated AES encryption keys (`PdqPY2fw6ffCVLQ8` for build #1, `ZdoNsjYfT6begqDl` for build #2). The two mutexes (`PdqPY2fw6ffCVLQ8` and `ZdoNsjYfT6begqDl` — the AES keys double as mutex names in XWorm) confirm they cannot run simultaneously on the same host.

---

### 6.2 Anti-Analysis Gauntlet

> **Analyst note:** XWorm runs six checks before doing anything malicious. If any check fails — meaning the malware thinks it's being observed in an analysis environment — it exits silently without leaving any traces. This section documents each check and why it matters for detection and analysis.

XWorm executes six anti-analysis checks in sequence at startup. All checks result in `Environment.Exit(0)` — a clean, silent exit with no error — designed to avoid alerting analysts that the malware has detected the analysis environment.

**Check 1 — VM Detection via WMI:**
Queries `Win32_ComputerSystem` via WMI and inspects `Manufacturer` and `Model` values for strings associated with virtual machine platforms: VMware, VirtualBox, and Hyper-V. Standard hypervisor-based sandbox environments are detected by this check.

**Check 2 & 3 — Debugger Detection:**
`Debugger.IsAttached` (managed .NET property) and `Debugger.IsLogging()` detect .NET debuggers attached to the process. `CheckRemoteDebuggerPresent` (Windows API, called via P/Invoke) detects kernel-mode debuggers. Both an interactive debugger (x64dbg) and remote debugging sessions are targeted.

**Check 4 — Sandboxie Detection:**
Checks for the presence of `SbieDll.dll` in the loaded module list. Sandboxie is a sandbox environment used by security researchers; this check specifically targets it.

**Check 5 — Windows XP Exclusion:**
Exits if `OSVersion.Major == 5` (Windows XP). Modern malware often avoids XP systems because they are unlikely to be productive targets and because XP VMs are commonly used in older analysis labs.

**Check 6 — Hosting/Datacenter Detection (most operationally interesting):**
Makes an HTTP GET request to `http://ip-api.com/line/?fields=hosting` at the start of every execution, before any C2 connection. The ip-api.com API returns `"true"` if the requesting IP address belongs to a hosting provider, datacenter, or cloud service. If the response is `"true"`, XWorm exits.

This check is particularly effective because it uses a legitimate, widely-available public API rather than a custom-built evasion technique. Cloud sandboxes (AWS, Azure, GCP hosted), datacenter-based analysis environments, and any system behind a commercial hosting provider's IP range will be detected. The check fires on every execution, making it a reliable behavioral detection trigger for defenders: legitimate software rarely makes this specific API call before establishing C2 connections.

**Detection opportunity:** The sequence `HTTP GET http://ip-api.com/line/?fields=hosting` followed by a TCP connection to port 7007 within seconds of process creation is a high-fidelity behavioral pattern for this specific XWorm campaign.

---

### 6.3 Triple-Redundant Persistence

> **Analyst note:** XWorm installs itself three different ways simultaneously to ensure it survives even if an IT administrator finds and removes one or two of the persistence methods. All three must be located and removed for a complete clean-up.

XWorm deploys all three persistence mechanisms at install time:

**Mechanism 1 — Scheduled Task (DEFINITE):**
```
schtasks /create /f /sc minute /mo 1 /tn "XWormClient" /tr "'%AppData%\XWormClient.exe'" /rl highest
```
This creates a scheduled task named `XWormClient` that executes every 60 seconds with HIGHEST privilege level. The 60-second interval means that even if the XWorm process is manually killed, it will restart within one minute without any user action.

**Mechanism 2 — Registry Run Key (DEFINITE):**
`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value `XWormClient` = `%AppData%\XWormClient.exe`

This standard Windows autorun key causes XWorm to launch at every user login.

**Mechanism 3 — Startup Folder Shortcut (DEFINITE):**
A `.lnk` shortcut file at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\XWormClient.lnk` is created via the Windows COM `WScript.Shell` object. This provides a third persistence mechanism that also triggers on user login.

**Remediation implication:** All three locations must be confirmed clean before considering XWorm remediated. The scheduled task is the most aggressive — if the registry key and startup shortcut are removed but the scheduled task is missed, XWorm will continue re-launching every 60 seconds.

---

### 6.4 Configuration Encryption

> **Analyst note:** This section describes XWorm's method of protecting its configuration data. The encryption used here is weaker than Shadow RAT's implementation, making it easier for security researchers to extract configuration values — but the configuration is still hidden from casual inspection.

XWorm uses a non-standard key derivation process for config encryption:

1. The raw key string (e.g., `PdqPY2fw6ffCVLQ8`) is hashed with MD5 (16 bytes)
2. The 16-byte MD5 hash is placed at offset 0 and again at offset 15 of a 32-byte array (1-byte overlap at position 15)
3. Byte at position 31 is set to `0x00`
4. The result is used as the Rijndael-256-ECB (128-bit block, 256-bit key) cipher key with PKCS7 padding

**Why this matters:** ECB (Electronic Codebook) mode is the weakest cipher block mode — identical plaintext blocks always produce identical ciphertext blocks. This means config extraction is straightforward once the key is identified. The overlapping MD5 construction is a recognizable signature pattern: the 32-byte key will always show the MD5 hash followed (with a 1-byte shift) by the same MD5 hash, with a trailing null byte.

The runtime C2 communication key `Nothing2hide` uses the same derivation scheme.

---

### 6.5 Command & Control

XWorm communicates with `151.245.112.70:7007` over TCP. The runtime communication is encrypted with Rijndael-256-ECB using the key derived from `Nothing2hide` (see Section 6.4). Unlike Shadow RAT's protobuf-net serialization, XWorm uses a simpler string-based command protocol.

**Anti-analysis pre-flight (DEFINITE):** Before establishing C2 connection, XWorm makes an HTTP GET to `http://ip-api.com/line/?fields=hosting`. This check precedes every C2 connection attempt — it is not a one-time install-time check. This makes it a reliable network-level detection indicator on any execution.

**HWID fingerprinting (DEFINITE):** XWorm generates a hardware identifier by computing MD5 of the concatenation of `ProcessorCount + UserName + MachineName + OSVersion + DriveSize`. This HWID is stored at `HKCU\Software\<HWID>` and transmitted to the C2 server for victim tracking. The registry key path (a 32-character hex string directly under `HKCU\Software`) is a distinctive host indicator.

**USB spread (MODERATE — config present, propagation code not confirmed in static analysis):**
The config field `USB.exe` specifies the filename used when spreading to removable drives. This capability is present in the config; independent confirmation of the propagation code logic was not completed in static analysis.

**Keylogger (DEFINITE):**
XWorm writes keystrokes to `%TEMP%\Log.tmp`. This fixed output path is a reliable host-based indicator.

---

# 7. Infrastructure Analysis

### 7.1 C2 Server: 151.245.112.70

> **Analyst note:** This section profiles the server that the malware connects to for attacker commands. The server's configuration — particularly which ports are open and how it has been set up — reveals details about the operator's operational habits and security practices that help validate the attribution assessment.

**DEFINITE confidence — confirmed via config decryption from all four malware builds**

The C2 server is a Windows VPS hosted at Strike.bz (a budget VPS provider) in AS203662 (3K33 sp. z o.o., Poland). The reverse DNS record is `9wpZAEak.strike.bz`. The server runs Windows (confirmed via SMB/RDP exposure) and has been stable at this IP for over 80 days as of analysis date.

**Observed open ports:**

| Port | Service | Context |
|---|---|---|
| 8990 | Shadow RAT C2 | Confirmed from config decryption |
| 7007 | XWorm C2 | Confirmed from config decryption |
| 3000 | Unknown | Possible Shadow RAT fallback or alternative service |
| 8040 | ScreenConnect relay | Identified post-March 1, 2026 transition |
| 80 | HTTP (ScreenConnect web) | IIS/10.0 server |
| 3389 | RDP | Operator remote administration (exposed to internet) |
| 445 | SMB | Exposed (CVE-2020-0796 / SMBGhost vulnerability unpatched) |
| 135 | MSRPC | Exposed |
| 5985 | WinRM | Exposed |

**Why the port exposure matters:** An attacker-controlled server with RDP (3389), SMB (445), and WinRM (5985) all exposed to the internet — and running unpatched against CVE-2020-0796 (a critical SMB vulnerability) — represents poor operational security. Threat actors with more advanced tradecraft typically restrict remote administration ports and apply security patches to their infrastructure. This exposure profile is consistent with the LOW-confidence assessment of an independent, less-experienced operator rather than a sophisticated organized group.

---

### 7.2 Domain Rotation Timeline

The operator used a systematic domain rotation strategy, maintaining approximately one active domain at a time and rotating on a ~30-35 day cycle. All domains exclusively resolved to 151.245.112.70 during their active periods. Self-hosted nameservers (ns2.latssko.com, ns2.harrismanlieb.ink) both pointing to the C2 IP confirm operator control of DNS infrastructure.

| Domain | Active Period | Status | Role | Notes |
|---|---|---|---|---|
| `breakingsecurity.online` | 2026-01-13 to 2026-01-16 | Inactive | Unknown (3 days) | Remcos RAT brand impersonation |
| `bluewiin.com` | 2026-01-16 (1 day) | Inactive | Staging/brief use | Very brief resolution period |
| `latssko.com` | 2026-01-16 to 2026-02-20 | Inactive | Operational (~35 days) | Self-hosted NS (ns2.latssko.com) |
| `harrismanlieb.ink` | 2026-02-12 to present | **Active** | Primary C2 + payload hosting | Self-hosted NS (ns2.harrismanlieb.ink) |
| `epgoldsecurity.com` | 2026-02-20 to present | **Active** | Payload delivery (open directory) | Migrated from BlazingFast to Hostinger 2026-03-26 |

**DomainTools risk scores:** Both `harrismanlieb.ink` and `epgoldsecurity.com` received 100/100 DomainTools risk scores. Both were weaponized immediately upon registration (0-day registration to malicious use), a pattern consistent with purpose-registered attack infrastructure rather than repurposed legitimate domains.

**breakingsecurity.online — Remcos brand impersonation:** This domain was active for only three days in January 2026, immediately before the operator's infrastructure stabilized. Its name deliberately mimics BreakingSecurity (breakingsecurity.net), the legitimate developer and seller of Remcos RAT. The operator may have used this domain to attract aspiring cybercriminals seeking Remcos access, delivering Shadow RAT or XWorm instead under the guise of a "free" or "cracked" Remcos tool. The specific purpose remains MODERATE confidence — plausible but not confirmed.

---

### 7.3 Payload Delivery Infrastructure

`epgoldsecurity.com` served as the public-facing payload delivery server hosting the open directory that exposed the malware samples. Its infrastructure shows more movement than the C2 server:

- **Initial hosting:** BlazingFast (AS47674, Netherlands) at 185.11.145.145 and 185.11.145.254
- **Current hosting:** Hostinger (AS47583, US) + Cloudflare CDN at 187.124.244.54 — migrated on 2026-03-26
- **Migration timing:** The move to Hostinger/Cloudflare coincides with a pattern typical of abuse response — BlazingFast may have issued a takedown notice, prompting the operator to move to a different provider

The use of Cloudflare as a CDN in front of the payload server adds a layer of infrastructure resilience and makes the real hosting IP less visible in DNS queries.

---

### 7.4 Operational Security Assessment

**Overall OPSEC assessment: POOR (HIGH confidence)**

The operator demonstrates multiple OPSEC failures:

1. **Stable, exposed C2 IP:** 151.245.112.70 has been in use for 80+ days with no IP rotation
2. **Exposed administrative ports:** RDP (3389), SMB (445), WinRM (5985) all accessible from the internet
3. **Unpatched vulnerabilities:** CVE-2020-0796 (SMBGhost) unpatched on the C2 server — a 2020 critical vulnerability that provides unauthenticated remote code execution against the attacker's own infrastructure
4. **Open directory:** The operator exposed their payload server without directory listing disabled, allowing researchers to enumerate and download all four malware samples
5. **Infrastructure fingerprinting:** Self-hosted nameservers (ns2.latssko.com, ns2.harrismanlieb.ink) pointing to the C2 IP create a distinctive infrastructure clustering signal

These failures are consistent with an inexperienced individual operator rather than a sophisticated criminal organization.

---

# 8. Threat Actor Assessment

> **Analyst note:** This section covers what is known about the person or group operating this campaign. Because the domains use WHOIS privacy, no clear identity has been established. The designation "UTA-2026-003" is a tracking label used internally by this publication to refer to this unidentified operator.

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-003 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

### Attribution Statement

**Threat Actor:** Unknown (UTA-2026-003)
**Confidence:** LOW (55%)
**Assessment:** Independent, financially-motivated MaaS consumer — single operator

**Why this confidence:** Zero named-actor infrastructure overlaps were identified across 151.245.112.70, AS203662, and all five operator domains. All tooling is either open-source (Shadow RAT/Pulsar fork, Kematian Stealer) or commercially available MaaS (XWorm). The single-operator profile is DEFINITE (shared C2 IP across all four builds). Financial motivation is DEFINITE (crypto clipper, credential stealer, Steam token theft, browser password recovery). Low OPSEC is inconsistent with organized group tradecraft.

**What's missing:** No operator handle, no forum presence, no email reuse across domains, no code similarity analysis against named-group private tooling, no HUMINT context. All five domains use WHOIS privacy protection preventing registrant analysis.

**What would increase confidence:**
- Operator handle in crimeware forums tied to this infrastructure → MODERATE confidence toward named persona
- Registrant email reuse across domains → infrastructure expansion and possible persona link
- Code similarity (70%+) to confirmed named-group private tooling → HIGH confidence
- Government advisory naming 151.245.112.70 → DEFINITE confidence
- Pastebin account identification → possible operator identity pivot

### Analysis of Competing Hypotheses (ACH)

<table class="professional-table">
  <thead>
    <tr>
      <th>Hypothesis</th>
      <th>Assessment</th>
      <th>Key Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>H1: Independent financially-motivated MaaS consumer</strong></td>
      <td class="confirmed">WINNER — Most consistent</td>
      <td>Poor OPSEC, commodity tooling, no named-actor overlaps, retail financial targeting (credentials + crypto + tax lures), single budget VPS</td>
    </tr>
    <tr>
      <td><strong>H2: Known cybercriminal group using clean infrastructure</strong></td>
      <td class="possible">CANNOT ELIMINATE</td>
      <td>Absence of prior infrastructure reporting could reflect clean-infrastructure tradecraft. However, organized groups typically maintain higher OPSEC and use custom tooling.</td>
    </tr>
    <tr>
      <td><strong>H3: State-sponsored actor</strong></td>
      <td>INCONSISTENT</td>
      <td>Financial targeting (crypto clipper, Steam token theft, tax lures) is inconsistent with state-sponsored objectives. OPSEC failures are inconsistent with state actor tradecraft.</td>
    </tr>
    <tr>
      <td><strong>H4: Penetration tester / red team</strong></td>
      <td>INCONSISTENT</td>
      <td>Tax-season lures targeting real US victims are inconsistent with legitimate authorized testing.</td>
    </tr>
  </tbody>
</table>

### Operator Profile

Based on the totality of evidence, UTA-2026-003 is assessed as a single individual or very small group with the following profile:

- **Motivation:** Financial gain through credential theft and cryptocurrency theft
- **Capability level:** Low-to-intermediate — consumer of available tools, not a malware developer
- **Infrastructure investment:** Minimal — single budget VPS, commercial payload hosting, purpose-registered domains
- **Target scope:** US individuals (tax-season lure specificity consistent with targeted social engineering rather than mass spam)
- **Operational period:** Active since at least January 2026; ScreenConnect transition in March 2026 suggests continued activity
- **OPSEC capability:** Poor — multiple failures suggest limited concern for defensive intelligence collection

---

# 9. Threat Intelligence Context

### 9.1 Shadow RAT Lineage: The Quasar Fork Ecosystem

**Confidence: HIGH (research-confirmed)**

Shadow RAT v2.6.4.0 has no prior public threat intelligence reporting under that specific branding. The name appears to be operator-specific private labeling. The underlying codebase, however, has strong forensic parallels to the documented Quasar RAT fork ecosystem.

**Quasar RAT foundation (DEFINITE — MITRE ATT&CK S0262, Malpedia):**
Quasar RAT is an open-source .NET RAT whose GitHub availability spawned numerous derivative families. Its architectural patterns — AES-encrypted config, RSA anti-tampering, protobuf-net serialization, Costura.Fody assembly embedding, .NET Reactor packing — appear across many named forks including CinaRAT, VenomRAT, and Pulsar RAT.

**Pulsar RAT parallel (HIGH confidence — The Hunters Ledger prior analysis, Malpedia, ThreatMon):**
The closest documented parallel to Shadow RAT is Pulsar RAT (released under the GitHub handle "Chainski", now removed). The capability comparison is striking:

| Capability | Pulsar RAT (documented) | Shadow RAT (observed) |
|---|---|---|
| HVNC | Yes | Yes (`GetHVNCDesktopResponse`) |
| Kematian stealer integration | Yes | Yes (`KematianZipMessage`) |
| Crypto clipper (BTC/multi-currency) | Yes | Yes (`BitcoinAddress`, `LitecoinAddress`, `EthereumAddress`) |
| WinRE persistence | Yes | Yes (`DoAddWinREPersistence`) |
| .NET Reactor packing | Documented | Confirmed |
| Pastebin dead drop C2 | Present | Present (disabled in recovered builds) |
| Namespace format | `Pulsar.Common.Messages.*` | `Shadow.Common.Messages.*` |
| AMSI bypass | Present | Confirmed |
| Costura.Fody embedding | Documented | 28 assemblies confirmed |

The `Shadow.Common.Messages.*` namespace directly mirrors `Pulsar.Common.Messages.*`. This structural similarity — combined with the identical capability set — leads to the HIGH-confidence assessment that Shadow RAT is a private/renamed fork of the Pulsar RAT codebase.

**Developer link via KDot227 (HIGH confidence):**
The Pulsar RAT developer KDot227 (GitHub: Somali-Devs) also authored Kematian Stealer. The presence of Kematian integration in both Pulsar RAT and Shadow RAT creates a documented developer link: KDot227 → Kematian Stealer + Pulsar RAT → both integrated in Shadow RAT.

**No public prior reporting (DEFINITE):**
Searches across Malpedia, ANY.RUN, VirusTotal, BleepingComputer, and Tier 2 vendor databases returned no threat intelligence reports specifically naming "Shadow RAT v2.6.x" as a Quasar-lineage family. The branding is assessed as operator-specific.

Sources: MITRE ATT&CK S0262 (Tier 1); Malpedia win.quasar_rat, win.pulsar_rat (Tier 2); The Hunters Ledger PULSAR RAT Analysis (Tier 2); ThreatMon Pulsar RAT Report 2025-06-13 (Tier 2)

---

### 9.2 XWorm MaaS Landscape

**Confidence: HIGH (ANY.RUN 2025 Annual Report, Cyble, Picus Security, Huntress)**

XWorm is a commercially sold MaaS RAT whose usage surged 174% in 2025 per ANY.RUN's 2025 Annual Threat Report, reflecting broad adoption across the cybercriminal ecosystem. Versions 4.1-5.0 were sold at $400 lifetime; a successor release (v6.0 by XCoderTools) appeared in June 2025.

The version range (3.0-5.0) in this investigation is inferred from feature set and campaign timeline — the exact version string is obfuscated in the builder output and was not confirmed. This is noted as a gap. The 3.0 floor is established by the presence of the triple-redundant persistence mechanism (scheduled task, Registry Run, and startup shortcut combined) and the Rijndael-256-ECB config encryption scheme, both of which were introduced in v3.x builds and are absent from earlier versions documented in public research.

Sources: ANY.RUN 2025 Annual Threat Report (Tier 2); Cyble EvilCoder research (Tier 2); Picus Security XWorm V6 analysis (Tier 2); Huntress XWorm threat library (Tier 2)

---

### 9.3 Tax-Season Campaign Context

**Confidence: HIGH (Microsoft Security Blog, Check Point Research, IRS Dirty Dozen 2026)**

The operator's delivery lures — `Form 1040.msi` and `2026_Benefits_Enroll` — are directly consistent with the documented 2026 tax-season malware wave. Microsoft's Security Blog (March 19, 2026) documented a tax-season campaign that targeted 29,000+ users across 10,000 organizations, peaking on February 10, 2026 — coinciding with this operator's deployment period (`harrismanlieb.ink` registered February 12, `epgoldsecurity.com` registered February 20). MSI installer delivery is a confirmed 2026 attack delivery mechanism documented by Microsoft.

Sources: Microsoft Security Blog — tax season 2026 (March 19, 2026, Tier 2); Check Point Research tax season 2026 (Tier 2); IRS Dirty Dozen 2026 (Tier 1)

---

### 9.4 Kematian Stealer Integration

**Confidence: HIGH (CYFIRMA, K7 Labs, HivePro TA2024269)**

Kematian Stealer is an open-source .NET credential stealer developed by KDot227 (GitHub: Somali-Devs). Its capabilities include browser credential extraction, cryptocurrency wallet enumeration, and Discord token theft.

Shadow RAT's integration of Kematian via the `KematianZipMessage` message class is operationally more sophisticated than standalone Kematian deployment. Standalone Kematian typically exfiltrates stolen data via a Discord webhook — a relatively traceable exfiltration path. When integrated into Shadow RAT, Kematian's output is exfiltrated through Shadow RAT's AES-256-CBC encrypted C2 channel rather than creating a Discord webhook footprint. This reduces the forensic visibility of credential theft activity.

Sources: CYFIRMA Kematian Stealer deep dive (Tier 2); K7 Labs Kematian analysis (Tier 2); HivePro threat advisory TA2024269 (Tier 2)

---

### 9.5 ScreenConnect Abuse Pattern

**Confidence: HIGH (G DATA EvilConwi, Acronis TRU, Forcepoint X-Labs)**

The deployment of ScreenConnect (ConnectWise) to the C2 server on March 1, 2026 follows a documented threat actor pattern. ScreenConnect abuse escalated markedly from March 2025 onward. The EvilConwi campaign (June 2025, documented by G DATA) demonstrated malware delivery via ScreenConnect abuse; Acronis TRU and Forcepoint X-Labs both documented rapid RAT deployment post-ScreenConnect session establishment as a standard post-access pattern.

The specific role of ScreenConnect in this operator's campaign is not confirmed from available evidence — it may serve victim machine management, operator server management, or both.

Sources: G DATA EvilConwi campaign analysis (June 2025, Tier 2); Acronis TRU ScreenConnect trojanized installers (Tier 2); Forcepoint X-Labs ScreenConnect attack analysis (Tier 2)

---

### 9.6 Ecosystem Exposure: MaaS Commodity Tools in the Cybercrime Economy

**Confidence: HIGH (ANY.RUN 2025 Annual Report, Cyble, Malpedia, GitHub documentation)**

This campaign is a concrete example of how the Malware-as-a-Service (MaaS) economy enables threat actors with limited technical capability to deploy sophisticated tooling. UTA-2026-003 assembled a multi-capability attack suite by combining three components, none of which required original malware development:

- **Shadow RAT (Pulsar fork):** An open-source codebase forked and privately rebranded. The base capability set — AMSI/ETW bypass, HVNC, WinRE persistence, Kematian integration — was developed by KDot227 and made available publicly before being removed. Any actor with access to the source code can rename and rebuild it.
- **XWorm:** A commercially sold builder-based RAT available for a flat fee, generating production-ready payloads with configurable C2 and encryption keys. The operator ran the XWorm builder twice, producing two differently-keyed variants — a standard consumer pattern requiring no technical expertise beyond purchasing access.
- **Kematian Stealer:** An open-source stealer with a documented GitHub repository. Its integration into Shadow RAT by the original developer means any fork of Shadow RAT/Pulsar inherits stealer capability automatically.

**What this means for defenders:** The MaaS model decouples capability from skill. A threat actor at the capability level evidenced here — poor OPSEC, commodity tooling, no custom development — can nonetheless deploy a 50+ capability RAT with AMSI/ETW bypass and WinRE persistence. Detection strategies that assume a correlation between attack sophistication and actor skill level will underestimate the threat posed by MaaS consumers. The relevant detection targets are the tools' behavioral fingerprints, not indicators of developer sophistication.

**Supply chain risk:** The open-source Quasar/Pulsar lineage and the Kematian integration mean that any future operator who obtains the Shadow RAT source code inherits the full capability set documented here. If the source is shared or leaked further, additional campaigns with identical technical profiles but different C2 infrastructure should be expected. Detection rules targeting the AMSI shellcode byte sequence, the Shadow.Common.Messages namespace strings, and the XWorm overlapping-MD5 key derivation pattern are more durable than infrastructure-based IOCs.

---

# 10. MITRE ATT&CK Mapping

> **Analyst note:** MITRE ATT&CK is a publicly available framework that categorizes the tactics and techniques used by attackers. This table maps observed Shadow RAT and XWorm behaviors to ATT&CK identifiers, enabling security teams to hunt for these techniques using ATT&CK-based detection tools and threat intelligence platforms.

*Table shows only HIGH/MODERATE confidence mappings. Low-confidence techniques omitted pending deeper analysis.*

### Shadow RAT v2.6.4.0

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
      <td>Defense Evasion</td>
      <td>T1562.001</td>
      <td>Disable or Modify Tools (AMSI)</td>
      <td class="confirmed">DEFINITE</td>
      <td>Patches <code>AmsiScanBuffer</code> with 15-byte shellcode returning E_INVALIDARG — direct code inspection</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1562.006</td>
      <td>Indicator Blocking (ETW)</td>
      <td class="confirmed">DEFINITE</td>
      <td>Patches <code>EtwEventWrite</code> with RET (0xC3) to silence event tracing — direct code inspection</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1027.002</td>
      <td>Software Packing</td>
      <td class="likely">HIGH</td>
      <td>.NET Reactor + Costura.Fody embedding (28 assemblies)</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1027</td>
      <td>Obfuscated Files or Information</td>
      <td class="likely">HIGH</td>
      <td>Asterisk-padded string obfuscation with runtime <code>.Replace("*", "")</code></td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1564.003</td>
      <td>Hidden Window</td>
      <td class="likely">HIGH</td>
      <td>WinForms <code>Visible=false</code>, <code>ShowInTaskbar=false</code> on load</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1553.005</td>
      <td>Mark-of-the-Web Bypass</td>
      <td class="likely">HIGH</td>
      <td><code>FileHelper.DeleteZoneIdentifier</code> removes Zone.Identifier ADS</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1055.012</td>
      <td>Process Hollowing</td>
      <td class="possible">MODERATE</td>
      <td>RunPE capability (<code>UseRunPE</code>, <code>RunPETarget</code>, <code>ExecuteInMemoryDotNet</code>) — code present, trigger conditions not confirmed</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1562.004</td>
      <td>Disable or Modify System Firewall</td>
      <td class="likely">HIGH</td>
      <td><code>DoDisableFirewall</code> command via netsh</td>
    </tr>
    <tr>
      <td>Persistence</td>
      <td>T1547.001</td>
      <td>Registry Run Keys / Startup Folder</td>
      <td class="likely">HIGH</td>
      <td>HKCU/HKLM Run, RunOnce, RunX86 keys; value <code>Shadow Client Startup</code></td>
    </tr>
    <tr>
      <td>Persistence</td>
      <td>T1542.003</td>
      <td>Pre-OS Boot: Bootkit (WinRE) *(closest available ATT&CK mapping; technically recovery-environment persistence, not bootkit)*</td>
      <td class="likely">HIGH</td>
      <td><code>DoAddWinREPersistence</code> / <code>DoRemoveWinREPersistence</code> commands in codebase</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1480</td>
      <td>Execution Guardrails</td>
      <td class="likely">HIGH</td>
      <td>GUID mutex <code>4c7e33e6-3f73-4b4c-a411-89fe63cdfa1e</code> enforces single instance</td>
    </tr>
    <tr>
      <td>Execution</td>
      <td>T1059.003</td>
      <td>Windows Command Shell</td>
      <td class="possible">MODERATE</td>
      <td><code>DoShellExecute</code>, RemoteShell namespace — code present</td>
    </tr>
    <tr>
      <td>Credential Access</td>
      <td>T1056.001</td>
      <td>Keylogging</td>
      <td class="likely">HIGH</td>
      <td>Gma.System.MouseKeyHook library with obfuscated log file output</td>
    </tr>
    <tr>
      <td>Credential Access</td>
      <td>T1555.003</td>
      <td>Credentials from Web Browsers</td>
      <td class="likely">HIGH</td>
      <td><code>GetPasswordsResponse</code>, <code>GetBrowsersResponse</code>, <code>CustomBrowserPath</code></td>
    </tr>
    <tr>
      <td>Collection</td>
      <td>T1113</td>
      <td>Screen Capture</td>
      <td class="likely">HIGH</td>
      <td>Desktop capture + SharpDX GPU-accelerated DirectX capture</td>
    </tr>
    <tr>
      <td>Collection</td>
      <td>T1125</td>
      <td>Video Capture</td>
      <td class="likely">HIGH</td>
      <td>AForge.Video.DirectShow webcam capture</td>
    </tr>
    <tr>
      <td>Collection</td>
      <td>T1123</td>
      <td>Audio Capture</td>
      <td class="likely">HIGH</td>
      <td>NAudio (Wasapi, WinForms, WinMM) microphone capture</td>
    </tr>
    <tr>
      <td>Collection</td>
      <td>T1115</td>
      <td>Clipboard Data</td>
      <td class="likely">HIGH</td>
      <td>Clipboard monitoring + crypto clipper (BTC/LTC/ETH address replacement)</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1082</td>
      <td>System Information Discovery</td>
      <td class="likely">HIGH</td>
      <td>CPU, GPU, RAM, OS, uptime, country collection</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1012</td>
      <td>Query Registry</td>
      <td class="likely">HIGH</td>
      <td>Full registry CRUD operations</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1071.001</td>
      <td>Web Protocols</td>
      <td class="likely">HIGH</td>
      <td>TLS 1.2 C2 over TCP to 151.245.112.70:8990</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1573.001</td>
      <td>Encrypted Channel: Symmetric Cryptography</td>
      <td class="likely">HIGH</td>
      <td>AES-256-CBC with HMAC-SHA256 wire encryption</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1571</td>
      <td>Non-Standard Port</td>
      <td class="likely">HIGH</td>
      <td>C2 on port 8990</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1102.001</td>
      <td>Dead Drop Resolver</td>
      <td class="possible">MODERATE</td>
      <td>Pastebin fallback C2 — code present, boolean disabled in recovered builds</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1572</td>
      <td>Protocol Tunneling (Ngrok)</td>
      <td class="possible">MODERATE</td>
      <td>NgrokPath, NgrokToken config fields — capability present</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1219</td>
      <td>Remote Access Software</td>
      <td class="likely">HIGH</td>
      <td>ScreenConnect deployed on C2 server (port 8040)</td>
    </tr>
  </tbody>
</table>

### XWorm 3.0-5.0

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
      <td>Defense Evasion</td>
      <td>T1497.001</td>
      <td>Virtualization/Sandbox Evasion: System Checks</td>
      <td class="likely">HIGH</td>
      <td>6 checks: VM (WMI), debugger (.NET + kernel), Sandboxie (SbieDll.dll), OS version, datacenter (ip-api.com)</td>
    </tr>
    <tr>
      <td>Defense Evasion</td>
      <td>T1027</td>
      <td>Obfuscated Files or Information</td>
      <td class="likely">HIGH</td>
      <td>Rijndael-256-ECB config encryption, obfuscated class/method names</td>
    </tr>
    <tr>
      <td>Persistence</td>
      <td>T1053.005</td>
      <td>Scheduled Task</td>
      <td class="confirmed">HIGH</td>
      <td><code>schtasks /create /f /sc minute /mo 1 /tn XWormClient /rl highest</code> — every 60 seconds</td>
    </tr>
    <tr>
      <td>Persistence</td>
      <td>T1547.001</td>
      <td>Registry Run Keys / Startup Folder</td>
      <td class="likely">HIGH</td>
      <td>HKCU Run value <code>XWormClient</code></td>
    </tr>
    <tr>
      <td>Persistence</td>
      <td>T1547.009</td>
      <td>Shortcut Modification</td>
      <td class="likely">HIGH</td>
      <td>.lnk shortcut in Startup folder via WScript.Shell COM</td>
    </tr>
    <tr>
      <td>Credential Access</td>
      <td>T1056.001</td>
      <td>Keylogging</td>
      <td class="likely">HIGH</td>
      <td>Output to <code>%TEMP%\Log.tmp</code></td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1082</td>
      <td>System Information Discovery</td>
      <td class="likely">HIGH</td>
      <td>HWID generation from ProcessorCount + UserName + MachineName + OSVersion + DriveSize</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1033</td>
      <td>System Owner/User Discovery</td>
      <td class="likely">HIGH</td>
      <td>UserName in HWID formula</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1012</td>
      <td>Query Registry</td>
      <td class="likely">HIGH</td>
      <td>HWID stored at HKCU\Software\&lt;HWID&gt;</td>
    </tr>
    <tr>
      <td>Discovery</td>
      <td>T1016.001</td>
      <td>Internet Connection Discovery</td>
      <td class="likely">HIGH</td>
      <td>ip-api.com hosting check detects datacenter environments</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1071.001</td>
      <td>Web Protocols</td>
      <td class="likely">HIGH</td>
      <td>C2 communication to 151.245.112.70:7007</td>
    </tr>
    <tr>
      <td>Command and Control</td>
      <td>T1571</td>
      <td>Non-Standard Port</td>
      <td class="likely">HIGH</td>
      <td>C2 on port 7007</td>
    </tr>
    <tr>
      <td>Lateral Movement</td>
      <td>T1091</td>
      <td>Replication Through Removable Media</td>
      <td class="possible">MODERATE</td>
      <td>USB spread config field <code>USB.exe</code> — propagation code not independently confirmed</td>
    </tr>
  </tbody>
</table>

---

# 11. Response Orientation

This section provides a brief orientation for teams who have confirmed or suspect a compromise involving this infrastructure. Detailed procedures are the responsibility of the affected organization's internal incident response team.

**Detection priorities (hunt for these first):**
- TCP connections to 151.245.112.70 on ports 8990, 7007, or 8040 (outbound from any endpoint)
- HTTP GET requests to `http://ip-api.com/line/?fields=hosting` — high-fidelity XWorm execution indicator, fires before every C2 connection
- Process memory access events targeting `amsi.dll` or `ntdll.dll` with write permissions — AMSI/ETW bypass indicator
- Registry value `Shadow Client Startup` under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Scheduled task `XWormClient` (every 60 seconds, HIGHEST privilege)
- File artifact `%TEMP%\Log.tmp` — XWorm keylogger output path

**Persistence targets (what to locate and remove):**
- Shadow RAT: `%APPDATA%\SubDir\$77Client.exe` and `%APPDATA%\SubDir\Client.exe`; registry value `Shadow Client Startup` under HKCU Run; WinRE partition modification (requires dedicated check — not visible via standard OS enumeration)
- XWorm: `%AppData%\XWormClient.exe`; registry value `XWormClient` under HKCU Run; scheduled task `XWormClient`; startup shortcut `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\XWormClient.lnk`; keylogger output at `%TEMP%\Log.tmp`
- Both families: Check for ScreenConnect client installation — may persist independently of malware removal

**Containment categories:**
- Block 151.245.112.70 and all five associated domains at network egress
- Isolate affected endpoints to prevent further C2 communication and lateral movement via Ngrok tunneling
- Rotate credentials for any accounts accessible from the compromised endpoint (browser-stored passwords, Steam, cryptocurrency wallets)
- Review and revoke any ScreenConnect sessions originating from or managed by 151.245.112.70
- Deploy detection signatures across endpoint and network monitoring platforms: 23 detection rules across 3 layers (7 YARA, 10 Sigma, 6 Suricata) — see Section 13 and [/hunting-detections/shadow-xworm-opendirectory-detections.md](/hunting-detections/shadow-xworm-opendirectory-detections.md)

### Operational Impact Timeline

If an endpoint compromise is confirmed, the following response phases apply:

| Phase | Activities | Complexity |
|---|---|---|
| **Initial Response** | Isolate affected hosts, preserve evidence, deploy detection signatures across environment | Moderate effort — standard IR workflow |
| **Scope Assessment** | Identify all affected endpoints, review network logs for C2 connections to 151.245.112.70, assess credential exposure | Significant effort — scales with endpoint count |
| **Persistence Review** | Enumerate all three persistence locations per family (Registry Run, scheduled task, startup shortcut) plus WinRE modification check | Significant effort — WinRE check requires specialized assessment |
| **Remediation** | Remove persistence artifacts, block infrastructure, rotate exposed credentials, rebuild any system with confirmed WinRE persistence | Varies by scope; systems with WinRE persistence require rebuild |
| **Post-Remediation Monitoring** | Verify no re-infection, monitor for ScreenConnect sessions, threat hunt for lateral movement | Extended monitoring — sustained threat hunting required |

---

# 12. Confidence Levels Summary

### DEFINITE (Direct evidence from code inspection / config decryption)
- Shadow RAT family classification (Quasar-lineage .NET RAT)
- XWorm family classification (commercial MaaS RAT)
- C2 server 151.245.112.70 (all four builds hardcode this IP)
- Shadow RAT C2 port 8990; XWorm C2 port 7007 (config decryption confirmed)
- AMSI bypass via AmsiScanBuffer shellcode (code inspection)
- ETW bypass via EtwEventWrite RET patch (code inspection)
- AES-256-CBC + HMAC-SHA256 config encryption (Shadow RAT)
- Rijndael-256-ECB + overlapping-MD5 key derivation (XWorm)
- All 28 embedded libraries (Costura.Fody manifest)
- Triple XWorm persistence (scheduled task, Registry Run, startup shortcut)
- Shadow RAT Registry Run persistence
- Crypto clipper capability (BTC/LTC/ETH fields confirmed)
- Kematian stealer integration (KematianZipMessage class confirmed)
- HVNC capability (GetHVNCDesktopResponse confirmed)
- Browser credential theft (GetPasswordsResponse confirmed)
- Webcam capture (AForge library + message handlers)
- Microphone capture (NAudio library + message handlers)
- Single operator (shared C2 IP across all four builds)
- Financial motivation (crypto clipper, credential stealer, Steam theft — DEFINITE)

### HIGH (Strong evidence — code confirmed, or multiple corroborating sources)
- Shadow RAT is a private fork of Pulsar RAT (namespace/capability overlay, developer link via KDot227)
- WinRE persistence capability (DoAddWinREPersistence code confirmed; activation is operator-initiated)
- Firewall disable, AV/Defender disruption (code confirmed)
- Production vs. staging build distinction (8 feature flags confirmed enabled in ShadowClient.exe)
- C2 server infrastructure: Strike.bz, AS203662, Poland
- harrismanlieb.ink and epgoldsecurity.com as operator-controlled infrastructure
- latssko.com and breakingsecurity.online as previous operator domains
- Tax-season targeting (Form 1040.msi, 2026_Benefits_Enroll)
- ScreenConnect deployment on C2 server (March 2026)
- Poor operator OPSEC (exposed ports, stable IP, CVE-2020-0796)

### MODERATE (Reasonable evidence — code present but activation conditions unclear, or single source)
- Pastebin dead drop C2 resolver (boolean disabled; code functional)
- Ngrok tunneling (config fields present; operator-initiated)
- Process hollowing/RunPE (config fields present; trigger conditions not confirmed)
- XWorm USB spread (USB.exe config field; propagation code not independently confirmed)
- breakingsecurity.online purpose (Remcos impersonation consistent; specific use unconfirmed)

### LOW (Weak/circumstantial evidence)
- UTA-2026-003 attribution as independent operator vs. known group (ZERO named-actor overlaps, but absence of evidence is not evidence of absence)
- XWorm exact version (range 3.0-5.0 inferred from feature set; version field obfuscated)

---

# 13. IOCs & Detections

### IOC Summary

54 total indicators across all categories. Full machine-readable IOC feed: **[/ioc-feeds/shadow-xworm-opendirectory-iocs.json](/ioc-feeds/shadow-xworm-opendirectory-iocs.json)**

| Category | Count |
|---|---|
| File hashes (SHA256) | 5 |
| File hashes (MD5) | 5 |
| File hashes (SHA1) | 5 |
| Network IPs | 4 |
| Network domains | 5 |
| Network URLs | 1 |
| Host mutexes | 3 |
| Host file paths | 5 |
| Host registry keys | 2 |
| Host scheduled tasks | 1 |
| Host startup shortcuts | 1 |
| SSL certificate hashes | 2 |
| Cryptographic artifacts | 6 |

**Critical blocking priorities:**
- **151.245.112.70** (CRITICAL — active C2, all family traffic)
- **harrismanlieb.ink** (HIGH — active C2 front domain)
- **epgoldsecurity.com** (HIGH — active payload delivery)
- **latssko.com**, **breakingsecurity.online**, **bluewiin.com** (MEDIUM — historical; block for completeness)

### Detection Coverage

23 detection rules covering all three detection layers. Full rules: **[/hunting-detections/shadow-xworm-opendirectory-detections.md](/hunting-detections/shadow-xworm-opendirectory-detections.md)**

| Rule Type | Count | Coverage |
|---|---|---|
| YARA rules | 7 | Shadow RAT AMSI shellcode, Shadow.Common namespace strings, XWorm config patterns, PBKDF2 salt, campaign grouping |
| Sigma rules | 10 | AMSI/ETW bypass process access, registry persistence, scheduled task creation, ip-api.com callback, Zone.Identifier removal |
| Suricata signatures | 6 | C2 TCP connections (ports 8990, 7007), ip-api.com pre-flight check, non-standard port alerting |

---

# 14. Appendix: Research References

### A. Shadow RAT / Quasar RAT Lineage

**MITRE ATT&CK (Tier 1):** "S0262: Quasar RAT" — official ATT&CK technique mappings for Quasar lineage. [https://attack.mitre.org/software/S0262/](https://attack.mitre.org/software/S0262/)

**Malpedia (Tier 2 — Fraunhofer FKIE):** `win.quasar_rat` and `win.pulsar_rat` entries. [https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)

**ThreatMon (Tier 2):** "Pulsar RAT Report" (2025-06-13) — technical analysis of Pulsar RAT.

**The Hunters Ledger (Tier 2):** "PULSAR RAT Technical Analysis & Business Risk Assessment" — prior investigation by this publication; namespace/capability comparison baseline.

### B. XWorm MaaS Landscape

**ANY.RUN (Tier 2):** "2025 Annual Threat Report" — documents 174% XWorm detection surge in 2025.

**Cyble (Tier 2):** "EvilCoder / XWorm pricing research" — XWorm v4.1-5.0 pricing; v6.0 by XCoderTools.

**Picus Security (Tier 2):** "XWorm V6 Analysis" — capability breakdown of latest XWorm version.

**Huntress (Tier 2):** "XWorm threat library" — behavioral detection analysis.

### C. Tax-Season Campaign Context

**Microsoft Security Blog (Tier 2):** "Tax-themed phishing campaign targeting organizations" (March 19, 2026) — 29,000+ user targeting, February 2026 peak, MSI installer delivery.

**Check Point Research (Tier 2):** Tax season 2026 campaign analysis.

**IRS Dirty Dozen 2026 (Tier 1):** Official IRS documentation of tax-themed cyberattack campaigns.

### D. Kematian Stealer

**CYFIRMA (Tier 2):** "Kematian Stealer Deep Dive" — technical analysis of credential theft capabilities.

**K7 Labs (Tier 2):** "Kematian Stealer Analysis" — behavioral analysis and detection guidance.

**HivePro (Tier 2):** "Kematian Stealer Threat Advisory TA2024269" — threat actor context and IOC coverage.

### E. ScreenConnect Abuse

**G DATA (Tier 2):** "EvilConwi Campaign Analysis" (June 2025) — ScreenConnect abuse and post-access RAT deployment.

**Acronis TRU (Tier 2):** "ScreenConnect Trojanized Installers" — delivery mechanism analysis.

**Forcepoint X-Labs (Tier 2):** "ScreenConnect Attack Analysis" — post-session deployment timing.

### F. Government & Regulatory Context

**HHS.gov (Tier 1):** "Remcos RAT Advisory" — US government advisory relevant to breakingsecurity.online impersonation context.

---

## License
© 2026 Joseph. All rights reserved. See LICENSE for terms.
