---
title: Detection Rules - Sliver C2 / ScareCrow Loader Open Directory Kit
date: '2026-03-01'
layout: post
permalink: /hunting-detections/sliver-open-directory-detections/
hide: true
---

# Detection Rules — Sliver C2 / ScareCrow Loader Open Directory Kit

**Campaign ID:** WebServer-Compromise-Kit-45.94.31.220
**Generated:** 2026-03-01
**Author:** The Hunters Ledger
**License:** CC BY-NC 4.0
**Reference:** https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
**TLP:** WHITE

---

## Detection Strategy Overview

This rule set provides layered detection coverage across the full kill chain recovered from the open
directory at 45.94.31.220. The toolkit comprises a PowerShell delivery stager, a ScareCrow-wrapped
Go loader (OneDriveSync.exe), a UPX-packed alternate beacon (compressed.exe), and a Sliver C2
implant delivered via Donut shellcode into a hollowed sihost.exe process.

Detection is organized across three layers:

- **File layer (YARA):** Binary identification of the loader, packer artifacts, and build pipeline
  source code markers — targets the malware on disk, in transit, or in memory scans.
- **Behavioral layer (Sigma):** Event-based detection of the stager execution chain and process
  injection sequence — targets actions taken by the malware at runtime.
- **Behavioral guidance (prose):** Memory forensics and live-response procedures for indicators
  that cannot be codified into automated rules without unacceptable false-positive rates.

Because ScareCrow applies polymorphic obfuscation (2,558 encrypted chunks per build), specific
string-based YARA rules targeting OneDriveSync.exe content will degrade across rebuilds. Rules
are therefore structured to target architectural constants — structural features of the build
pipeline that survive polymorphic regeneration — alongside specific-hash rules for the confirmed
samples. Infrastructure indicators (certificate serial, C2 domains) are more durable targets than
file hashes.

---

## Detection Coverage Summary

| Rule ID | Rule Name | Type | Layer | MITRE Techniques | FP Risk |
|---|---|---|---|---|---|
| YARA-01 | MALW_ScareCrow_Go_Loader_OneDriveSync | YARA | File | T1027.002, T1055.012, T1027.013 | LOW |
| YARA-02 | MALW_Fraudulent_VMware_CodeSign_Cert | YARA | File | T1553.002 | LOW |
| YARA-03 | MALW_UPX_Packed_Sliver_Variant | YARA | File | T1027.002 | LOW-MEDIUM |
| YARA-04 | TOOLKIT_ScareCrow_Build_Pipeline_Artifacts | YARA | File | T1027.013, T1106 | LOW |
| SIGMA-01 | Sliver Stager PowerShell AMSI Bypass and Payload Download | Sigma | Behavioral | T1059.001, T1562.001, T1105 | LOW-MEDIUM |
| SIGMA-02 | Windows Defender Real-Time Protection Disabled via PowerShell Stager | Sigma | Behavioral | T1562.001 | LOW |
| SIGMA-03 | Executable Dropped to TEMP and Executed with Hidden Window | Sigma | Behavioral | T1105, T1059.001 | MEDIUM |
| SIGMA-04 | Sliver Process Injection Behavioral Chain — Anonymous RWX Allocation in sihost.exe | Sigma | Behavioral | T1055.012, T1620, T1134.004 | LOW |
| SIGMA-05 | PEB CommandLine Spoofing — MicrosoftEdgeUpdate Masquerade | Sigma | Behavioral | T1036 | LOW |

---

## YARA Rules

---

### YARA-01 — ScareCrow Go Loader (OneDriveSync.exe)

```
# Detection Priority: HIGH
# Rationale: Targets the ScareCrow-wrapped Go loader architecture using three
#   independent signatures: Go build metadata (survives polymorphic rebuilds),
#   the SysWhispers3 hash seed constant embedded in compiled syscall resolution
#   code, and the XZ header mode byte pattern used by the ScareCrow injection
#   dispatcher. Any two of three conditions firing constitutes a HIGH-confidence
#   match. Hash-based rule included for the confirmed sample.
# ATT&CK Coverage: T1027.002 (Software Packing), T1055.012 (Process Hollowing),
#   T1027.013 (Encrypted/Encoded File), T1106 (Native API via SysWhispers3)
# Confidence: HIGH
# False Positive Risk: LOW — the SysWhispers3 seed 0x9DEA8D94 in combination
#   with Go build strings is not expected in legitimate software. The XZ mode
#   byte 0x04 in isolation is common; the full 12-byte XZ header pattern at an
#   anomalous offset within a PE is distinctive.
# Deployment: Endpoint AV/EDR on-access scan; retrospective scan of EDR file
#   inventory; memory scanner targeting anonymous private regions >15MB
```

```yara
rule MALW_ScareCrow_Go_Loader_OneDriveSync
{
    meta:
        description     = "Detects the ScareCrow-wrapped Go loader used in the WebServer-Compromise-Kit-45.94.31.220 campaign. Matches on Go build metadata preserved post-symbol-stripping, the SysWhispers3 HalosGate hash seed compiled into the syscall resolution module, and the XZ stream header pattern used by the ScareCrow injection mode dispatcher."
        author          = "The Hunters Ledger"
        date            = "2026-02-28"
        hash_sha256     = "e2ad6f8202994058cc987cc971698238c2dc63a951dd1e43063cc9b8b138713b"
        hash_md5        = "9559366a6f6874ad914e308a34903c77"
        hash_sha1       = "67bb390c2dad7ebd9e9f706a6f2ba42e4cbcbee7"
        reference       = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/"
        tlp             = "WHITE"
        mitre_attack    = "T1027.002, T1055.012, T1027.013, T1106"

    strings:
        // Go build metadata — present in Go binaries even after -trimpath and
        // --skip-symbols; these strings survive ScareCrow polymorphic obfuscation
        // because they are embedded in the Go runtime metadata section, not the
        // payload body that ScareCrow encrypts.
        $go_build_meta_1 = "-buildmode=exe" ascii wide
        $go_build_meta_2 = "-compiler=gc" ascii wide
        $go_build_meta_3 = "-trimpath=true" ascii wide

        // SysWhispers3 HalosGate hash seed — 0x9DEA8D94 in little-endian byte
        // order. This 32-bit constant is the seed for the ROR8-based rolling hash
        // used to resolve NT function names without string matching. Its presence
        // alongside the Go build strings identifies SysWhispers3 compiled into a
        // Go binary — a combination not expected in legitimate software.
        $sw3_seed = { 94 8D EA 9D }

        // XZ stream header with ScareCrow process hollowing mode byte.
        // Bytes 0-5: XZ magic \xfd7zXZ\x00
        // Byte 6:    0x00 (stream flags byte 1)
        // Byte 7:    0x04 (mode byte = PROCESS HOLLOWING in ScareCrow dispatcher)
        // Bytes 8-11: E6 D6 B4 46 (CRC32 of stream flags)
        // Confirmed at runtime offset 0xC000708000 in dynamic analysis session 3.
        $xz_hollowing_header = { FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 }

        // Argument spoofing hardcoded string — present in all binaries built by
        // this pipeline. Written to PEB CommandLine.Buffer to masquerade the
        // process as a Microsoft Edge updater. Source: arg_spoof.C.
        $peb_spoof_string = "MicrosoftEdgeUpdate.exe --update-check --silent" wide

    condition:
        // PE64 header check
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and uint8(uint32(0x3C) + 24) == 0x64  // PE32+ (64-bit)
        // File size: OneDriveSync.exe is 32,786,672 bytes; allow up to 40MB for
        // polymorphic variants from the same pipeline
        and filesize > 25MB
        and filesize < 40MB
        // Require Go build metadata (all three strings confirm Go binary identity)
        and all of ($go_build_meta_*)
        // Plus at least one of the payload-specific signatures
        and (
            $sw3_seed
            or $xz_hollowing_header
            or $peb_spoof_string
        )
}
```

---

### YARA-02 — Fraudulent VMware Code-Signing Certificate

```
# Detection Priority: HIGH
# Rationale: The fraudulent certificate serial 659EEB5AA4A489FB238993AF259D23F057F6D6D6
#   is a campaign-level durable IOC. Unlike file hashes, this serial persists across
#   all polymorphic rebuilds as long as the same certificate is reused. The cert.pem
#   and key.pem were left unencrypted on the open directory, meaning any third party
#   who downloaded them has full re-signing capability — the serial may appear on
#   binaries not produced by this specific actor.
#   Rule 2a targets PE binaries signed with this certificate (Authenticode embedded
#   signature block contains the serial).
#   Rule 2b targets the raw PEM certificate file itself (for hunting on file servers,
#   email gateways, or backup repositories where the cert artifact may be found).
# ATT&CK Coverage: T1553.002 (Subvert Trust Controls: Code Signing)
# Confidence: HIGH for 2a; DEFINITE for 2b
# False Positive Risk: LOW — certificate serial is globally unique; VMware with
#   L=Redmond is a fraud indicator by definition. No legitimate VMware binary uses
#   a self-signed cert with CA:TRUE.
# Deployment: Endpoint AV/EDR on-access; email gateway attachment scan; file server
#   retrospective scan; network IDS/DLP for binary downloads
```

```yara
rule MALW_Fraudulent_VMware_CodeSign_Cert_PE
{
    meta:
        description     = "Detects PE binaries signed with the fraudulent VMware, Inc. Code Signing certificate used in the WebServer-Compromise-Kit-45.94.31.220 campaign. The certificate (serial 659EEB5AA4A489FB238993AF259D23F057F6D6D6) is self-signed with CA:TRUE and incorrectly lists Redmond, WA as the organization locality. Any binary presenting this Authenticode signature is malicious or signed by a compromised copy of the private key."
        author          = "The Hunters Ledger"
        date            = "2026-02-28"
        hash_sha256     = "e2ad6f8202994058cc987cc971698238c2dc63a951dd1e43063cc9b8b138713b"
        reference       = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/"
        tlp             = "WHITE"
        mitre_attack    = "T1553.002"

    strings:
        // Certificate serial number as it appears in the Authenticode signature
        // block embedded in the PE (PKCS#7 SignedData structure). The serial is
        // stored in DER encoding — these bytes are the raw serial octets in the
        // order they appear in the ASN.1 structure.
        $cert_serial = { 65 9E EB 5A A4 A4 89 FB 23 89 93 AF 25 9D 23 F0 57 F6 D6 D6 }

        // Subject field strings as they appear in the X.509 DER encoding within
        // the embedded PKCS#7 block. These UTF8String/PrintableString values are
        // present verbatim in the binary's Authenticode signature.
        $subject_cn    = "VMware, Inc. Code Signing" ascii
        $subject_l     = "Redmond" ascii
        $subject_o     = "VMware, Inc." ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100MB
        // Serial match is highest-confidence anchor; require it plus at least
        // one subject field to reduce risk of coincidental serial collision
        and $cert_serial
        and 2 of ($subject_cn, $subject_l, $subject_o)
}

rule MALW_Fraudulent_VMware_CodeSign_Cert_PEM
{
    meta:
        description     = "Detects the raw PEM-format fraudulent VMware code-signing certificate artifact from the WebServer-Compromise-Kit-45.94.31.220 campaign. This file (cert.pem) was exposed on the attacker's open directory alongside the unencrypted private key (key.pem). Any instance of this PEM file on a host indicates the signing capability has been distributed. The private key was confirmed unencrypted (PKCS#8 BEGIN PRIVATE KEY header)."
        author          = "The Hunters Ledger"
        date            = "2026-02-28"
        reference       = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/"
        tlp             = "WHITE"
        mitre_attack    = "T1553.002"

    strings:
        // PEM header and subject strings as they appear in the base64-encoded
        // certificate. The serial in hex ASCII form appears in openssl text output
        // but not in the raw PEM base64 — use the subject strings instead.
        $pem_header     = "-----BEGIN CERTIFICATE-----" ascii
        $subject_cn     = "VMware, Inc. Code Signing" ascii
        $subject_l      = "Redmond" ascii
        // Private key PEM header — signals the key.pem artifact or a combined PFX
        // export. Finding this alongside the cert indicates full signing capability.
        $privkey_header = "-----BEGIN PRIVATE KEY-----" ascii

    condition:
        filesize < 10KB
        and $pem_header
        and $subject_cn
        and $subject_l
}
```

---

### YARA-03 — UPX-Packed Sliver Beacon Variant (compressed.exe)

```
# Detection Priority: MEDIUM
# Rationale: The UPX 5.0.2-packed alternate beacon (compressed.exe) shares the same
#   Sliver payload core as OneDriveSync.exe but uses UPX compression instead of
#   ScareCrow polymorphic obfuscation. UPX section name detection is generic;
#   this rule adds specificity via the LZMA/brute filter flag combination documented
#   by radare2 analysis of the confirmed sample, the file size fingerprint (15.1MB
#   packed Â±2MB to account for minor variants), and the presence of Go build strings
#   post-unpack (detectable in memory after UPX self-extraction).
# ATT&CK Coverage: T1027.002 (Software Packing)
# Confidence: MODERATE — UPX section names alone match many legitimate UPX-packed
#   binaries. The combination with Go build strings and file size raises confidence.
# False Positive Risk: MEDIUM — UPX is widely used by legitimate software developers.
#   Tune by adding the Go build string requirement and the file size constraint.
#   Deploy with alert-and-investigate rather than block-and-quarantine posture.
# Deployment: Endpoint AV/EDR on-access; network gateway for downloads >10MB
```

```yara
rule MALW_UPX_Packed_Sliver_Variant
{
    meta:
        description     = "Detects the UPX 5.0.2-packed Sliver C2 beacon variant recovered from the WebServer-Compromise-Kit-45.94.31.220 campaign (compressed.exe). Matches on UPX section naming, the Go build metadata present in the unpacked payload, and the packed file size fingerprint. UPX-packed Go binaries of this size are not common in legitimate enterprise software."
        author          = "The Hunters Ledger"
        date            = "2026-02-28"
        hash_sha256     = "d94c74a6cd6629be66898eaab03ce0446f655689e28e08f0c166eaf4af9d04ea"
        hash_md5        = "f587753c0a46688af2ffea00573192e2"
        hash_sha1       = "8f27695dfd4f29e872c1661cdf225120182dd05b"
        reference       = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/"
        tlp             = "WHITE"
        mitre_attack    = "T1027.002"

    strings:
        // UPX section headers — present in all UPX-packed binaries; provide
        // baseline match, not sufficient alone
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        // UPX version string — specific to UPX 5.0.2 as documented by radare2
        $upx_ver = "UPX 5.0.2" ascii
        // Go build metadata — present in the UPX stub header region before
        // self-extraction; visible without unpacking because Go embeds build
        // info in a non-compressed region of UPX-packed Go binaries
        $go_build_1 = "-buildmode=exe" ascii wide
        $go_build_2 = "-compiler=gc" ascii wide
        // UPX LZMA filter marker — radare2 identified LZMA with brute filter
        // flags in this specific build. The byte sequence appears in the UPX
        // compression header identifying the algorithm and filter combination.
        $upx_lzma_marker = { 03 05 }

    condition:
        uint16(0) == 0x5A4D
        // Packed size: 15,869,168 bytes (Â±2MB for minor variants)
        and filesize > 13MB
        and filesize < 18MB
        and $upx0
        and $upx1
        and ($upx_ver or $upx_lzma_marker)
        and all of ($go_build_*)
}
```

---

### YARA-04 — ScareCrow Build Pipeline Source Code Artifacts

```
# Detection Priority: MEDIUM
# Rationale: Hunt rule designed to detect source code artifacts from this build
#   pipeline if they are re-encountered on compromised hosts, file shares, or
#   forensic images. Targets three distinctive source code markers that are not
#   present in compiled binaries: the XOR key definition from string_obf.C, the
#   Heaven's Gate far-return opcode sequence from heavens_gate.asm, and the
#   SysWhispers3 hash seed define from syscalls.C/syscalls.h. Finding any of
#   these artifacts indicates the build pipeline has been deployed to that host.
# ATT&CK Coverage: T1027.013 (Encrypted/Encoded File), T1106 (Native API)
# Confidence: HIGH — these specific constants in C source or ASM context are
#   distinctive.
# False Positive Risk: LOW — XOR key 0x42 alone is generic, but the specific
#   define name XOR_KEY in combination with the Heaven's Gate opcodes or the
#   SW3_SEED value narrows the match to this toolchain.
# Deployment: Forensic disk image scan; incident response triage scan of suspect
#   hosts; threat hunting scan of developer workstations and build servers
```

```yara
rule TOOLKIT_ScareCrow_Build_Pipeline_Source_Artifacts
{
    meta:
        description     = "Hunt rule detecting source code artifacts from the ScareCrow/SysWhispers3 build pipeline used in the WebServer-Compromise-Kit-45.94.31.220 campaign. Targets three distinctive source code markers: the XOR_KEY 0x42 define from string_obf.C, the Heaven's Gate far-return opcode sequence from heavens_gate.asm (34-byte compiled stub), and the SysWhispers3 SW3_SEED hash constant. Presence of these artifacts on a host indicates the offensive build pipeline has been deployed or is in use."
        author          = "The Hunters Ledger"
        date            = "2026-02-28"
        reference       = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/"
        tlp             = "WHITE"
        mitre_attack    = "T1027.013, T1106"

    strings:
        // string_obf.C marker — #define XOR_KEY 0x42
        // The preprocessor define name and value combination identifies this
        // specific module. XOR key 0x42 is common, but the define name
        // XOR_KEY is specific to this source file.
        $xor_key_define = "#define XOR_KEY 0x42" ascii

        // SysWhispers3 seed define — present in syscalls.h and referenced in
        // syscalls.C. The specific value 0x9DEA8D94 identifies SysWhispers3
        // vs. SysWhispers2 or other variants which use different seeds.
        $sw3_seed_define = "0x9DEA8D94" ascii
        $sw3_seed_name   = "SW3_SEED" ascii

        // Heaven's Gate compiled 34-byte stub (heavens_gate.bin) — opcode sequence
        // for the far-return mode switch from CS=0x23 (32-bit) to CS=0x33 (64-bit).
        // The sequence call+add pattern for position-independent address calculation
        // followed by the far return is the distinctive compilation of this specific
        // NASM source. This matches the pre-assembled binary (heavens_gate.bin) that
        // is suitable for injection into 32-bit processes.
        // Sequence: CALL $ +5 ; ADD [ESP], 5 ; RETF (to 64-bit segment)
        $heavens_gate_stub = { E8 00 00 00 00 83 04 24 05 CB }

        // Build workspace path — appears in build artifacts if the attacker's Linux
        // server path is embedded in any recovered file (e.g., debug symbols,
        // build log, or stager script with hardcoded paths)
        $build_path = "/var/tmp/.cache-1f6a38a2-1771081283" ascii

    condition:
        filesize < 5MB
        and (
            // Source code file match: XOR define plus SW3 seed = two modules present
            ($xor_key_define and $sw3_seed_define and $sw3_seed_name)
            // Or: Heaven's Gate compiled stub in a small binary (heavens_gate.bin)
            or ($heavens_gate_stub and filesize < 100)
            // Or: Build path artifact in any file
            or $build_path
        )
}
```

---

## Sigma Rules

All Sigma rules comply with SigmaHQ submission standards as validated against the
sigmahq-rule-formatting skill. Date format: YYYY/MM/DD. Tags use named tactic strings
with hyphens. UUIDs are v4. logsource categories map to correct Sysmon event IDs.

---

### SIGMA-01 — Sliver Stager PowerShell AMSI Bypass and Payload Download

```
# Detection Priority: HIGH
# Rationale: The stager.ps1 AMSI bypass technique (amsiInitFailed reflection) combined
#   with a DownloadFile call and executable drop to %TEMP% is a three-event chain that
#   uniquely identifies this stager pattern. Script Block Logging (Event ID 4104) is
#   the highest-fidelity source as it captures the full plaintext stager even after
#   AMSI is bypassed, because the bypass fires AFTER the script block is logged.
# ATT&CK Coverage: T1059.001 (PowerShell), T1562.001 (Impair Defenses),
#   T1105 (Ingress Tool Transfer)
# Confidence: HIGH
# False Positive Risk: LOW-MEDIUM — amsiInitFailed in legitimate scripts is extremely
#   rare. Combined with DownloadFile, false positive rate approaches zero in most
#   enterprise environments.
# Deployment: Windows PowerShell Script Block Logging (Event ID 4104). Requires
#   PowerShell Script Block Logging enabled via GPO.
# SigmaHQ file: proc_creation_win_sliver_stager_amsi_bypass_download.yml
```

```yaml
title: Sliver Stager PowerShell AMSI Bypass with Payload Download
id: 3a7f2c91-5e4b-4d8a-b1c9-6f2e1a3d8b07
status: experimental
description: Detects the PowerShell stager used in the WebServer-Compromise-Kit-45.94.31.220 Sliver C2 campaign. The stager uses .NET reflection to access the amsiInitFailed private static field (disabling AMSI for the session), then downloads an executable payload via Net.WebClient.DownloadFile. This specific AMSI bypass technique combined with an executable download is a high-confidence indicator of malicious stager activity. PowerShell Script Block Logging (Event ID 4104) captures the full stager content even when AMSI is subsequently bypassed.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
author: The Hunters Ledger
date: 2026/02/28
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.command-and-control
logsource:
    product: windows
    service: powershell
    definition: 'Requires PowerShell Script Block Logging (Event ID 4104). Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.'
detection:
    selection_amsi_bypass:
        EventID: 4104
        ScriptBlockText|contains|all:
            - 'amsiInitFailed'
            - 'NonPublic,Static'
            - 'SetValue'
    selection_download:
        EventID: 4104
        ScriptBlockText|contains|all:
            - 'DownloadFile'
            - 'Net.WebClient'
    filter_legitimate:
        ScriptBlockText|contains:
            - 'WindowsDefenderApplicationGuard'
    condition: (selection_amsi_bypass or selection_download) and not filter_legitimate
falsepositives:
    - Security research or penetration testing scripts using reflection-based AMSI bypass in authorized environments
    - Red team exercises where PowerShell stagers are simulated
    - Automated patching scripts that coincidentally use WebClient DownloadFile (these will not match amsiInitFailed, so FP limited to download-only selection)
level: high
```

---

### SIGMA-02 — Windows Defender Real-Time Protection Disabled via PowerShell Stager

```
# Detection Priority: HIGH
# Rationale: The stager explicitly calls Set-MpPreference -DisableRealtimeMonitoring $true.
#   If the process runs with administrative privileges, Windows Defender Event ID 5001
#   fires in the Microsoft-Windows-Windows Defender/Operational log. This is a direct
#   telemetry artifact of the stager's defense-disabling action and requires no
#   Script Block Logging configuration.
# ATT&CK Coverage: T1562.001 (Impair Defenses: Disable or Modify Tools)
# Confidence: HIGH
# False Positive Risk: LOW — legitimate Defender disable is done via GPO or Intune in
#   enterprise environments, not via PowerShell at runtime. Manual Set-MpPreference
#   calls are unusual in production.
# Deployment: Windows Defender Operational event log. No additional configuration
#   required — fires whenever Defender real-time protection is disabled.
# SigmaHQ file: file_event_win_sliver_stager_defender_disable.yml
```

```yaml
title: Windows Defender Real-Time Protection Disabled by PowerShell Process
id: 8b4e1f72-9c3a-4e7d-a5b8-2d6f9c1e4a83
status: experimental
description: Detects Windows Defender real-time protection being disabled via a PowerShell process, matching the behavior of the stager.ps1 component of the WebServer-Compromise-Kit-45.94.31.220 Sliver C2 campaign. The stager calls Set-MpPreference -DisableRealtimeMonitoring $true, which generates Windows Defender Event ID 5001 when executed with sufficient privileges. This event in combination with PowerShell as the initiating process is a high-confidence indicator of malicious stager activity rather than legitimate administrative action.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
    - https://attack.mitre.org/techniques/T1562/001/
author: The Hunters Ledger
date: 2026/02/28
tags:
    - attack.defense-evasion
logsource:
    product: windows
    service: windefend
detection:
    selection_defender_disabled:
        EventID: 5001
    filter_admin_tools:
        # Exclude known-legitimate management tools
        # Expand this filter based on environment-specific management tooling
        ProcessName|endswith:
            - '\MpCmdRun.exe'
            - '\msiexec.exe'
    condition: selection_defender_disabled and not filter_admin_tools
falsepositives:
    - Legitimate administrative scripts disabling Defender as part of authorized software installation
    - Enterprise management platforms (SCCM, Intune) that disable Defender via PowerShell during provisioning
    - Security testing in authorized environments
level: high
```

---

### SIGMA-03 — Executable Dropped to TEMP Directory and Executed with Hidden Window

```
# Detection Priority: HIGH
# Rationale: The stager writes OneDriveSync.exe to %TEMP%\update.exe then executes it
#   with -WindowStyle Hidden. Three Sysmon events document this: EID 3 (outbound
#   connection from powershell.exe), EID 11 (file creation in %TEMP%), and EID 1
#   (process creation with hidden window). The combination of all three events with
#   powershell.exe as the common actor is a high-specificity detection that is
#   difficult for this stager to evade without fundamental redesign.
# ATT&CK Coverage: T1105 (Ingress Tool Transfer), T1059.001 (PowerShell Execution)
# Confidence: HIGH
# False Positive Risk: MEDIUM — PowerShell downloading and executing files from %TEMP%
#   is used by some legitimate software installers. The -WindowStyle Hidden flag alone
#   is insufficient. Combine all three conditions to reduce FP rate.
# Deployment: Sysmon with standard configuration (EID 1, 3, 11). File event monitoring
#   on %TEMP% path for .exe creation by powershell.exe.
# SigmaHQ file: file_event_win_sliver_stager_exe_drop_temp.yml
```

```yaml
title: PowerShell Drops Executable to TEMP Directory — Sliver Stager Pattern
id: c2e5a8f3-7b1d-4c9e-8a4f-3e7b2d9c5f16
status: experimental
description: Detects PowerShell creating an executable file in the user TEMP directory, matching the payload delivery behavior of the stager.ps1 component in the WebServer-Compromise-Kit-45.94.31.220 Sliver C2 campaign. The stager downloads OneDriveSync.exe via Net.WebClient and writes it to %TEMP%\update.exe before execution. This Sysmon file event rule targets the file write action specifically, providing detection even if Script Block Logging is unavailable.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
    - https://attack.mitre.org/techniques/T1105/
author: The Hunters Ledger
date: 2026/02/28
tags:
    - attack.execution
    - attack.command-and-control
logsource:
    category: file_event
    product: windows
detection:
    selection_ps_exe_drop:
        Image|endswith: '\powershell.exe'
        TargetFilename|contains: '\AppData\Local\Temp\'
        TargetFilename|endswith: '.exe'
    filter_known_installers:
        # Common legitimate PowerShell-based installer patterns — tune per environment
        TargetFilename|contains:
            - '\AppData\Local\Temp\chocolatey'
            - '\AppData\Local\Temp\scoop'
            - '\AppData\Local\Temp\winget'
    condition: selection_ps_exe_drop and not filter_known_installers
falsepositives:
    - Legitimate software deployment scripts that use PowerShell to download and stage installers to TEMP
    - Package manager scripts (Chocolatey, Scoop, winget) that stage executables during installation
    - IT automation frameworks (Ansible, Salt, Puppet) that deploy via PowerShell to TEMP paths
level: high
```

---

### SIGMA-04 — Sliver Process Injection Behavioral Chain in sihost.exe

```
# Detection Priority: HIGH
# Rationale: The process hollowing sequence produces two observable behavioral events:
#   (1) sihost.exe spawning a child process that is absent from its normal execution
#   tree (PPID spoofing artifact), and (2) sihost.exe establishing outbound network
#   connections that are anomalous for a legitimate sihost.exe instance. The build.log
#   explicitly names sihost.exe as the injection target. Any network connection from
#   sihost.exe to a non-local, non-Microsoft destination on ports 443 or 8443 is a
#   high-confidence Sliver beacon artifact.
# ATT&CK Coverage: T1055.012 (Process Hollowing), T1620 (Reflective Code Loading),
#   T1134.004 (PPID Spoofing), T1071.001 (Web Protocols / C2)
# Confidence: HIGH
# False Positive Risk: LOW — sihost.exe (Shell Infrastructure Host) does not
#   legitimately initiate outbound HTTPS connections to arbitrary external addresses.
#   Any such connection warrants investigation.
# Deployment: Sysmon EID 3 (network connection). Alert when sihost.exe initiates
#   connections to non-Microsoft IP ranges on ports 443 or 8443.
# SigmaHQ file: net_connection_win_sliver_sihost_c2_beacon.yml
```

```yaml
title: sihost.exe Initiating Anomalous Outbound Network Connection — Sliver C2 Beacon
id: 6f1d4b8e-3c2a-4f7b-9e5d-8a1c3f6b9e2d
status: experimental
description: Detects sihost.exe (Shell Infrastructure Host) initiating outbound network connections to non-Microsoft destinations, indicating successful Sliver C2 beacon injection via process hollowing. The WebServer-Compromise-Kit-45.94.31.220 build pipeline explicitly targets sihost.exe for process hollowing (confirmed in build.log). The injected Sliver beacon beacons to mailuxe.net:443, mailmassange.duckdns.org:443, and mailuxe.net:8443 using HTTPS/mTLS. Legitimate sihost.exe does not initiate outbound HTTPS connections; any such connection is high-confidence evidence of process injection.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
    - https://attack.mitre.org/techniques/T1055/012/
author: The Hunters Ledger
date: 2026/02/28
tags:
    - attack.defense-evasion
    - attack.command-and-control
logsource:
    category: network_connection
    product: windows
detection:
    selection_sihost_network:
        Image|endswith: '\sihost.exe'
        Initiated: 'true'
        DestinationPort:
            - 443
            - 8443
    filter_microsoft_infra:
        # sihost.exe may contact Microsoft endpoints during normal Windows Update
        # or telemetry; filter known Microsoft IP ranges and domains
        DestinationHostname|endswith:
            - '.microsoft.com'
            - '.windows.com'
            - '.windowsupdate.com'
            - '.msftconnecttest.com'
    condition: selection_sihost_network and not filter_microsoft_infra
falsepositives:
    - Custom enterprise environments where sihost.exe behavior has been modified by legitimate software
    - Proxy or network security software that injects monitoring DLLs into sihost.exe causing unusual network calls
level: high
```

---

### SIGMA-05 — PEB CommandLine Spoofing — MicrosoftEdgeUpdate Masquerade

```
# Detection Priority: MEDIUM
# Rationale: The arg_spoof.C module overwrites the PEB CommandLine buffer with the
#   hardcoded string "MicrosoftEdgeUpdate.exe --update-check --silent". This creates
#   a detectable mismatch: the process reports itself as MicrosoftEdgeUpdate.exe but
#   the actual binary image path does not match that name. EDRs and Sysmon with
#   ParentImage/Image field logging capture both the reported CommandLine and the
#   true Image path. A mismatch between Image|endswith MicrosoftEdgeUpdate.exe
#   and the binary NOT being located in the Edge update directory is the detection.
#   This specific string is hardcoded in all builds from this pipeline.
# ATT&CK Coverage: T1036 (Masquerading), T1036.005 (Match Legitimate Name/Location)
# Confidence: MODERATE — the PEB CommandLine overwrite requires that the process
#   monitoring tool captures the spoofed value rather than the true process image
#   path. Some EDRs see through PEB spoofing at the kernel level.
# False Positive Risk: LOW — legitimate MicrosoftEdgeUpdate.exe runs from
#   %LOCALAPPDATA%\Microsoft\EdgeUpdate\ or Program Files. A process claiming
#   this CommandLine from any other path warrants investigation.
# Deployment: Sysmon EID 1 with CommandLine logging. EDR process tree.
# SigmaHQ file: proc_creation_win_sliver_loader_peb_cmdline_spoof.yml
```

```yaml
title: PEB CommandLine Spoofing — Process Claims MicrosoftEdgeUpdate Identity
id: 9d3e7a1f-4b8c-4e2a-b6d9-5c1f8e3a7b4d
status: experimental
description: Detects a process whose reported CommandLine claims to be MicrosoftEdgeUpdate.exe but whose Image path does not correspond to a legitimate Microsoft Edge update installation directory. The arg_spoof.C module in the WebServer-Compromise-Kit-45.94.31.220 toolkit hardcodes the string 'MicrosoftEdgeUpdate.exe --update-check --silent' as the PEB CommandLine spoofing value. This technique is cosmetic deception targeting process-tree viewers and EDR rules that inspect CommandLine without cross-referencing the actual binary path. All binaries produced by this pipeline present this same spoofed identity.
references:
    - https://pixelatedcontinuum.github.io/Threat-Intel-Reports/reports/sliver-open-directory/
    - https://attack.mitre.org/techniques/T1036/
author: The Hunters Ledger
date: 2026/02/28
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_spoof_cmdline:
        CommandLine|contains|all:
            - 'MicrosoftEdgeUpdate.exe'
            - '--update-check'
            - '--silent'
    filter_legitimate_edge_update:
        # Legitimate MicrosoftEdgeUpdate.exe runs from these paths only
        Image|contains:
            - '\Microsoft\EdgeUpdate\'
            - '\Microsoft\Edge\Application\'
    condition: selection_spoof_cmdline and not filter_legitimate_edge_update
falsepositives:
    - Legitimate Microsoft Edge update processes running from non-standard installation paths (uncommon but possible in enterprise repackaging scenarios)
    - Security tooling that simulates Edge update processes for testing purposes
level: medium
```

---

## Behavioral Detection Guidance

The following techniques produce indicators that are either too environment-specific
for portable rule development, or require memory forensics tooling that does not
map cleanly to Sigma/YARA. This section provides analyst guidance for manual
investigation and live-response triage.

---

### Guidance 1 — Donut Anonymous Memory Region (18.4MB RWX)

**What it indicates:** The Donut shellcode staging region used to load the Sliver PE
reflectively. Dynamic analysis confirmed an 18.4MB anonymous private memory region
(VadS tag, PageExecuteReadWrite protection) allocated in the target process prior to
Sliver execution. This is the most durable memory artifact of this toolkit — it
persists in memory until the sleep masking cycle re-encrypts it.

**When to look:** During or shortly after suspected beacon activity in sihost.exe.
Sleep masking will encrypt the region during the 300â€“900 second dormancy window,
making it invisible to in-memory YARA scanners. Target the window when beacon
callbacks are expected (every 90â€“510 seconds effective range with 70% jitter).

**Tool:** Volatility 3

**Procedure:**

1. Acquire a memory image from the suspect endpoint during active operation.

2. Run `windows.malfind` to identify anonymous executable regions:
   ```
   vol.exe -f memory.raw windows.malfind --pid <sihost_pid>
   ```
   Look for VAD entries with `VadS` tag, protection `PAGE_EXECUTE_READWRITE`,
   and size approximately 18MB (18,000,000â€“19,500,000 bytes).

3. Confirm the Donut bootstrap entry by examining bytes at offset +0x59 from the
   region base:
   ```
   vol.exe -f memory.raw windows.vadinfo --pid <sihost_pid> --base <vad_base>
   ```
   The confirmed signature at base+0x59 is: NOP sled followed by `0x9A` (CALLF
   opcode — intentionally invalid, triggers Donut's VEH bootstrap handler).

4. Extract the Donut instance at base+0x200 for offline AES-128-CTR decryption:
   ```
   vol.exe -f memory.raw windows.memmap --pid <sihost_pid> --dump
   ```
   The recovered AES-128 key is at instance+0x00 and nonce at instance+0x10
   (values confirmed in Stage 1 dynamic analysis — see Section 5, Sub-stage 5c).
   These may differ in rebuilt versions of the payload.

**Note:** If sleep masking is active, the region will show as `PAGE_READONLY` or
`PAGE_NOACCESS` during dormancy. Scan repeatedly at 30-second intervals to catch
the decryption window.

---

### Guidance 2 — SysWhispers3 Syscall Table in Memory

**What it indicates:** SysWhispers3 builds a sorted runtime lookup table
(`SW3_SYSCALL_LIST`) of up to 600 NT function entries resolved via the PEB LDR
without calling LoadLibrary. The table is keyed by the ROR8-based hash seed
`0x9DEA8D94`. Locating this structure in memory confirms that the process is using
HalosGate-style indirect syscalls to bypass EDR user-mode hooks.

**When to look:** Any time a process is suspected of performing injection operations
without generating corresponding EDR API hook telemetry.

**Tool:** x64dbg or Volatility 3 with memory search

**Procedure (x64dbg):**

1. Attach to the suspect process.
2. Use the Memory Map view to locate private regions in the process address space.
3. Search for the SysWhispers3 seed bytes in little-endian order:
   Binary search for: `94 8D EA 9D`
4. If found, examine the surrounding 2,400 bytes (600 entries Ã— 4-byte syscall
   numbers) for a sorted array of DWORD values. A sorted array of valid NT syscall
   numbers (range 0x0000â€“0x01FF on current Windows) confirms the SW3 table.

**Tool:** Volatility 3

```
vol.exe -f memory.raw windows.vadyarascan --pid <target_pid> --pattern "94 8D EA 9D"
```

---

### Guidance 3 — Process Ghosting Artifact Detection

**What it indicates:** The process_ghosting.c module creates a temporary file at
`%TEMP%\update.tmp` with `FILE_FLAG_DELETE_ON_CLOSE`, writes a PE image, marks it
for deletion, creates a section object from the delete-pending file, and launches a
process from that section. The resulting process has no corresponding image file on
disk at process start.

**When to look:** When a process appears in the process list but cannot be resolved
to a file on disk.

**Tool:** Process Explorer (Sysinternals), Volatility 3

**Procedure (Process Explorer):**
Processes created via ghosting appear with an empty or unresolvable Image Path in
Process Explorer. The Image Path column will show `<non-existent path>` or be empty.
Legitimate processes always have a resolvable image path unless a DLL injection has
corrupted the PEB.

**Procedure (Volatility 3):**
```
vol.exe -f memory.raw windows.pstree
vol.exe -f memory.raw windows.dlllist --pid <suspect_pid>
```
A ghosted process will appear in `pstree` but `dlllist` will show an anomalous or
absent path for the main executable module (entry with base address matching the
process image base, but no resolvable file path).

**Procedure (ETW / EDR):**
The five-step ghosting sequence generates a specific API call chain that ETW kernel
callbacks capture:
```
CreateFile(FILE_FLAG_DELETE_ON_CLOSE) â†’
SetFileInformationByHandle(FileDispositionInfo) â†’
NtCreateSection(SEC_IMAGE) â†’
NtCreateProcessEx(section_handle)
```
Any EDR or ETW consumer that captures process creation events with the section object
as the image source (rather than a file path) will log an anomalous process creation
event. Alert on `NtCreateProcessEx` calls where the image source is a section object
derived from a delete-pending file.

---

### Guidance 4 — Call Stack Spoofing Detection

**What it indicates:** The stack_spoof.C module temporarily overwrites the caller's
return address on the stack with one of three legitimate Windows function addresses
(`BaseThreadInitThunk`, `RtlUserThreadStart`, or `Sleep`) before invoking a target
function. EDRs inspecting call stacks see a plausible-looking chain that originates
from a legitimate Windows function.

**Detection approach:** This technique is detectable by correlating that the function
at the return address is being "called" from a context that is semantically impossible
— for example, `Sleep` returning to shellcode memory, or `BaseThreadInitThunk`
appearing mid-call-stack rather than at the base. Tools that perform full call stack
unwinding with PE bounds validation will catch this.

**Practical analyst approach:** During dynamic analysis in x64dbg, set a breakpoint on
`VirtualProtect` (or its NT-level equivalent) and examine the call stack when it hits.
If the top-level return address is `BaseThreadInitThunk` or `Sleep` but the current
execution context is in a non-image-backed memory region (anonymous allocation), the
stack has been spoofed. Check the memory map for the current instruction pointer — if
it is in private memory rather than a mapped PE section, the stack return addresses
are spoofed.

---

### Guidance 5 — ETW Silence in sihost.exe as Injection Indicator

**What it indicates:** ScareCrow patches `EtwEventWrite` in the injected process's
ntdll copy with `ret 0`, silencing all ETW events from that process. A legitimately
running sihost.exe generates a continuous stream of ETW events covering UI activity,
window management, and system service interactions. Anomalous ETW silence from
sihost.exe is a detectable artifact of the ETW patch.

**Detection approach:** Monitor ETW event volume per process using a consumer
(PerfView, ETW consumer, or Windows Event Tracing). A sharp drop to zero events from
sihost.exe that previously generated normal event volume is consistent with ETW
patching having occurred. This is an environmental baseline-dependent detection —
it requires prior knowledge of normal sihost.exe event rates.

**Volatility confirmation:**
```
vol.exe -f memory.raw windows.dlllist --pid <sihost_pid>
```
Check whether `amsi.dll` appears in the DLL list for sihost.exe. A legitimately
running sihost.exe may or may not load amsi.dll, but its presence with a `.text`
section that has been byte-patched (prologue overwritten with `XOR RAX,RAX; RET`)
confirms AMSI patching.

---

## MITRE ATT&CK Coverage Map

This table maps each detection rule to the ATT&CK techniques it covers, cross-
referenced against the full validated technique list from Stage 1 Section 4.

| ATT&CK Technique | Sub-Technique | Detection Coverage | Rule(s) |
|---|---|---|---|
| T1587.002 | Develop Capabilities: Code Signing Certs | Partial — certificate artifact detection | YARA-02 (cert.pem hunt) |
| T1059.001 | PowerShell | Full — stager script block content | SIGMA-01, SIGMA-03 |
| T1106 | Native API (SysWhispers3) | Partial — memory artifact in compiled binary | YARA-01 (SW3 seed), Guidance 2 |
| T1055.012 | Process Hollowing | Full — network artifact of hollowed sihost.exe | SIGMA-04, Guidance 1 |
| T1055.015 | Process Ghosting | Partial — behavioral chain | Guidance 3 |
| T1134.004 | Parent PID Spoofing | Partial — network artifact of hollow target | SIGMA-04 |
| T1036.005 | Masquerading: Match Legitimate Name | Partial — file naming (update.exe drop) | SIGMA-03 |
| T1036 | Masquerading (PEB CommandLine) | Full — spoofed CommandLine string | SIGMA-05 |
| T1027.002 | Software Packing (UPX + ScareCrow) | Full — both variants | YARA-01, YARA-03 |
| T1027.008 | Stripped Payloads | Partial — Go binary structure still detectable | YARA-01 |
| T1027.013 | Encrypted/Encoded File | Partial — XZ header mode byte | YARA-01, YARA-04 |
| T1140 | Deobfuscate/Decode Files | Not directly detectable via static rules | Coverage Gap |
| T1497.001 | System Checks (VM detection) | Not detectable without sandbox instrumentation | Coverage Gap |
| T1497.003 | Time-Based Evasion | Not detectable via static rules | Coverage Gap |
| T1553.002 | Code Signing (Fraudulent) | Full — cert serial in PE and PEM | YARA-02 (both rules) |
| T1562.001 | Impair Defenses: Disable Tools | Full — Defender Event 5001 + AMSI bypass | SIGMA-01, SIGMA-02 |
| T1620 | Reflective Code Loading | Partial — memory artifact | Guidance 1 |
| T1070 | Indicator Removal (Process Ghosting) | Partial — post-hoc detection | Guidance 3 |
| T1082 | System Information Discovery | Not detectable via behavioral rules alone | Coverage Gap |
| T1071.001 | Web Protocols (C2) | Full — sihost.exe outbound connections | SIGMA-04 |
| T1573.002 | Encrypted Channel (mTLS) | Partial — network-level; no Suricata rule possible without session decryption | Coverage Gap |
| T1105 | Ingress Tool Transfer | Full — file drop to %TEMP% | SIGMA-03 |

**Coverage summary:** 22 ATT&CK techniques confirmed in Stage 1. Detectable via
rules: 14 (64%). Partially detectable: 5 (23%). Coverage gaps: 4 (18%).

---

## Coverage Gaps

The following techniques from the Stage 1 validated ATT&CK mapping could not be
covered with high-confidence automated rules. Reasons and enabling evidence are
documented for each.

**T1140 — Deobfuscate/Decode Files or Information (XOR 0x42 runtime decode)**
The XOR decode loop executes at runtime in memory and produces no on-disk artifact.
Static YARA rules targeting the decode loop opcodes would be too generic to avoid
significant false positives across legitimate software. Memory scanning for decoded
strings (C2 domains, sihost.exe path) would require live memory access during the
brief decode window before _alloca cleanup. Detection via FLOSS emulation during
dynamic analysis is recommended but cannot be codified as an automated production rule.

**T1497.001 / T1497.003 — Virtualization and Sandbox Evasion (VM checks, uptime)**
The vm_checks.C implementation calls `GetSystemInfo` and `GetTickCount` — both of
which are called by many legitimate applications. Rules targeting these API calls
without additional behavioral context (e.g., immediate process exit if result fails
threshold) would generate unacceptable false positive rates. Detection requires
sandbox instrumentation that observes the conditional exit behavior, not just the API
call. Sandbox operators should configure CPU core count >= 2 and system uptime >= 10
minutes to bypass these checks and reach the injection stage.

**T1573.002 — Encrypted Channel: Asymmetric Cryptography (Sliver mTLS)**
Sliver's mTLS C2 channel over HTTPS (ports 443 and 8443) is indistinguishable from
legitimate HTTPS traffic at the network packet level without session key material.
A Suricata rule targeting TLS certificates from `mailuxe.net` or
`mailmassange.duckdns.org` would be effective but is an IOC-based rule rather than
a behavioral rule, and IOC-based Suricata rules have been excluded from this rule set
in favor of the domain-level IOC feed maintained in `ioc-feeds/sliver-open-directory-iocs.json`.

**T1082 — System Information Discovery**
`GetSystemInfo` is called by thousands of legitimate processes. Without behavioral
context (process exits immediately after, or the result is used in a conditional
branch that leads to termination), this API call cannot be reliably distinguished from
legitimate use.

**T1055.008 — Module Stomping**
Stage 1 analysis determined that the active injection mode was process hollowing
(mode byte 0x04), not module stomping (mode byte 0x0a). Module stomping is a declared
capability in the ScareCrow configuration but was not confirmed as actively exercised
in the analyzed samples. A detection rule for module stomping based on the STATUS_CONFLICTING_ADDRESSES
observation alone would have insufficient behavioral specificity. Evidence needed: a
memory sample where the shellcode is executing from within a mapped signed DLL's
address range rather than an anonymous allocation.

---

## Detection Priority Summary

| Priority | Rule | Rationale |
|---|---|---|
| 1 (Highest) | SIGMA-04 — sihost.exe anomalous outbound connection | Low FP, directly identifies active C2 beacon in injected process |
| 2 | YARA-02 — Fraudulent VMware certificate serial | Campaign-durable IOC; persists across rebuilds; identifies all signed variants |
| 3 | SIGMA-01 — AMSI bypass + DownloadFile Script Block | Captures stager before AMSI bypass takes effect; near-zero FP in enterprise |
| 4 | YARA-01 — ScareCrow Go Loader binary | Targets architectural constants; degrades with major pipeline changes |
| 5 | SIGMA-05 — MicrosoftEdgeUpdate PEB CommandLine spoof | Hardcoded string; detects all pipeline builds; requires PEB-aware monitoring |
| 6 | SIGMA-02 — Defender real-time protection disabled | High FP potential in some environments; valuable where Defender is standard |
| 7 | SIGMA-03 — Executable dropped to TEMP by PowerShell | Broadest behavioral rule; requires tuning per environment |
| 8 | YARA-03 — UPX-packed Sliver variant | Medium FP without Go string filter; deploy with investigation posture |
| 9 | YARA-04 — Build pipeline source code artifacts | Hunt rule; not for production AV deployment |

---

Â© 2025 Joseph. All rights reserved. Detection rules licensed under CC BY-NC 4.0
