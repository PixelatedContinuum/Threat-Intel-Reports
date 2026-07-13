---
title: Detection Rules - Sliver C2 / ScareCrow Loader Open Directory Kit
date: '2026-03-01'
layout: post
permalink: /hunting-detections/sliver-open-directory-detections/
thumbnail: /assets/images/cards/sliver-open-directory.png
hide: true
---

**Campaign:** WebServer-Compromise-Kit-45.94.31.220
**Date:** 2026-02-28
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/sliver-open-directory/

---

## Detection Coverage Summary

An exposed open directory at 45.94.31.220 yielded a complete attacker build workspace for a Sliver C2 implant wrapped in a ScareCrow loader — compiled beacons, build-pipeline source code, a fraudulent VMware code-signing certificate with its private key, and operator build logs. Coverage below spans the compiled-binary layer (YARA) and the stager/injection behavioral chain (Sigma). No standalone Suricata signatures are published: the campaign's C2 domains and IP are transient infrastructure already carried in the IOC feed, and the Sliver mTLS channel is indistinguishable from ordinary TLS at the packet level without a captured JARM/JA3S fingerprint (see Coverage Gaps).

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 2 | T1027.002, T1027.013, T1055.012, T1106, T1553.002 | 0 |
| Sigma | 3 | 3 | T1059.001, T1685, T1105, T1055.012, T1620, T1134.004, T1071.001, T1036, T1036.005 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- `sihost.exe` initiating an outbound HTTPS connection to a non-Microsoft destination — a Shell Infrastructure Host process has no legitimate reason to do this, so any hit is a high-confidence indicator of an injected C2 beacon (Sigma Detection).
- The fraudulent self-signed "VMware, Inc. Code Signing" certificate fraud pattern (CA:TRUE, Redmond location, issuer = subject) — survives the operator regenerating a new certificate serial from the same template (YARA Detection).
- Go build metadata combined with the SysWhispers3 syscall-hash seed or the ScareCrow XZ-mode header — architectural constants that survive ScareCrow's per-build polymorphic obfuscation (YARA Detection).

**Rule reorganized during this pass:** the original "AMSI Bypass and Payload Download" Sigma rule OR'd two selections of very different precision — a rare reflection-based AMSI-bypass technique, and a common `Net.WebClient` download pattern — under one `level: high` rule. It has been split into a Detection-tier AMSI-bypass-only rule and a Hunting-tier download-pattern rule so the download selection's higher false-positive rate is reflected honestly.

**Atomics routed to the IOC feed:** the attacker's Linux build-workspace cache directory path (previously a standalone trigger branch in the ScareCrow build-pipeline source-artifact YARA rule) is a one-off, per-build identifier with no repeatable hunting value beyond the sample hash it already accompanies — it is now carried in [`sliver-open-directory-iocs.json`](/ioc-feeds/sliver-open-directory-iocs.json) instead. This does not change the rule-tier conservation count above (the surrounding rule survives as Hunting); see Coverage Gaps for detail.

---

## YARA Rules

### Detection Rules

#### ScareCrow Go Loader (OneDriveSync.exe)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027.002 (Software Packing), T1055.012 (Process Hollowing), T1027.013 (Encrypted/Encoded File), T1106 (Native API via SysWhispers3)
**Confidence:** HIGH
**Rationale:** Requires Go build metadata — present even after ScareCrow's polymorphic obfuscation, since it lives in the Go runtime metadata section rather than the encrypted payload body — plus at least one of three payload-specific anchors: the SysWhispers3 syscall-hash seed, the ScareCrow XZ-mode header byte, or the hardcoded PEB CommandLine spoof string. No single renameable literal carries the rule; an operator would need to strip Go build metadata (breaking the toolchain) to fully evade.
**False Positives:** None known — the SysWhispers3 seed `0x9DEA8D94` combined with Go build strings is not expected in legitimate software; the XZ mode byte `0x04` alone is common, but the full 12-byte XZ header pattern combined with the Go build requirement is distinctive.
**Blind Spots:** A rebuild that strips Go build metadata entirely (unlikely — breaks the toolchain) or swaps SysWhispers3/XZ/PEB-spoof for different techniques evades this rule; targets on-disk PE files, not memory-only variants.
**Validation:** Scan the analyzed sample (`hash1` below) — all conditions must match; an unrelated Go-compiled binary without SysWhispers3/ScareCrow/PEB-spoofing must NOT fire.
**Deployment:** Endpoint AV/EDR on-access scan, retrospective scan of EDR file inventory, memory scanner targeting anonymous private regions >15MB.

```yara
/*
   Yara Rule Set
   Identifier: Sliver C2 / ScareCrow Loader Open Directory Kit
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MALW_ScareCrow_Go_Loader_OneDriveSync {
   meta:
      description = "Detects the ScareCrow-wrapped Go loader used in the WebServer-Compromise-Kit-45.94.31.220 campaign. Matches on Go build metadata preserved post-symbol-stripping, the SysWhispers3 HalosGate hash seed compiled into the syscall resolution module, and the XZ stream header pattern used by the ScareCrow injection mode dispatcher."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/"
      date = "2026-02-28"
      hash1 = "e2ad6f8202994058cc987cc971698238c2dc63a951dd1e43063cc9b8b138713b"
      hash2 = "67bb390c2dad7ebd9e9f706a6f2ba42e4cbcbee7"
      hash3 = "9559366a6f6874ad914e308a34903c77"
      family = "Sliver"
      malware_type = "C2 Beacon / Loader"
      campaign = "WebServer-Compromise-Kit-45.94.31.220"
      id = "97119e1c-a746-54b7-b127-9ef332b9246f"
   strings:
      $go_build_meta_1 = "-buildmode=exe" ascii wide
      $go_build_meta_2 = "-compiler=gc" ascii wide
      $go_build_meta_3 = "-trimpath=true" ascii wide

      $sw3_seed = { 94 8D EA 9D }

      $xz_hollowing_header = { FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 }

      $peb_spoof_string = "MicrosoftEdgeUpdate.exe --update-check --silent" wide

   condition:
      uint16(0) == 0x5A4D
      and uint32(uint32(0x3C)) == 0x00004550
      and uint8(uint32(0x3C) + 24) == 0x64
      and filesize > 25MB
      and filesize < 40MB
      and all of ($go_build_meta_*)
      and (
         $sw3_seed
         or $xz_hollowing_header
         or $peb_spoof_string
      )
}
```

#### Fraudulent VMware Code-Signing Certificate (PE-Embedded)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1553.002 (Subvert Trust Controls: Code Signing)
**Confidence:** HIGH
**Rationale:** Salvage-rewritten from the original serial-only condition: the rule now fires on EITHER the exact known certificate serial plus one corroborating subject field, OR two of three subject fields alone (`VMware, Inc. Code Signing` + `Redmond` + `VMware, Inc.`) independent of serial. The subject-field combination is itself a fraud tell — no legitimate VMware certificate is self-signed with CA:TRUE, and no legitimate VMware entity is headquartered in Redmond (Microsoft's HQ, not VMware's) — so the rule survives the operator regenerating a new self-signed certificate from the same template, not only re-use of this exact serial.
**False Positives:** None known — the compound phrase "VMware, Inc. Code Signing" paired with "Redmond" is not expected to co-occur in legitimate software.
**Blind Spots:** A rebuild using a wholly different impersonated vendor identity (not VMware/Redmond) evades this rule; targets on-disk PE files, not memory-only variants.
**Validation:** Scan the analyzed sample (`hash1` below) — must match via the serial+subject path; a legitimately-signed VMware binary (issued by an actual CA, not self-signed) must NOT fire.
**Deployment:** Endpoint AV/EDR on-access scan, email gateway attachment scanning, file server retrospective scan, network IDS/DLP for binary downloads.

```yara
rule MALW_Fraudulent_VMware_CodeSign_Cert_PE {
   meta:
      description = "Detects PE binaries signed with the fraudulent self-signed VMware, Inc. Code Signing certificate identity used in the WebServer-Compromise-Kit-45.94.31.220 campaign, either via the known certificate serial or via the self-signed VMware/Redmond subject-field fraud pattern alone, which survives certificate regeneration from the same template"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/"
      date = "2026-02-28"
      hash1 = "e2ad6f8202994058cc987cc971698238c2dc63a951dd1e43063cc9b8b138713b"
      family = "Sliver"
      malware_type = "C2 Beacon / Code-Signing Fraud"
      campaign = "WebServer-Compromise-Kit-45.94.31.220"
      id = "751f1fad-4d99-5c21-a1a1-c04dae743f81"
   strings:
      $cert_serial = { 65 9E EB 5A A4 A4 89 FB 23 89 93 AF 25 9D 23 F0 57 F6 D6 D6 }
      $subject_cn  = "VMware, Inc. Code Signing" ascii
      $subject_l   = "Redmond" ascii
      $subject_o   = "VMware, Inc." ascii
   condition:
      uint16(0) == 0x5A4D
      and filesize < 100MB
      and (
         ($cert_serial and 1 of ($subject_cn, $subject_l, $subject_o))
         or (2 of ($subject_cn, $subject_l, $subject_o))
      )
}
```

#### Fraudulent VMware Code-Signing Certificate (Raw PEM Artifact)

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1553.002 (Subvert Trust Controls: Code Signing)
**Confidence:** DEFINITE
**Rationale:** Targets the raw PEM certificate and private-key artifacts as recovered from the open directory. Either the certificate PEM (header + 2 subject fields) or the private-key PEM (header + 1 subject field) is sufficient — the private-key branch is the higher-value hit, since it indicates the signing capability itself has been distributed, not just a single signed binary.
**False Positives:** None known — the compound phrase "VMware, Inc. Code Signing" paired with "Redmond" inside a PEM certificate or private-key file is not expected in legitimate contexts.
**Blind Spots:** Only fires on the raw PEM artifact itself, not on binaries signed with a DER/PFX-exported form of the same certificate (covered by the PE-embedded rule above); a rebuild using a different impersonated vendor identity evades.
**Validation:** Scan a copy of the recovered `cert.pem` / `key.pem` — must match; an unrelated legitimate PEM certificate must NOT fire.
**Deployment:** File server retrospective scan, email gateway attachment scanning, backup repository scanning.

```yara
rule MALW_Fraudulent_VMware_CodeSign_Cert_PEM {
   meta:
      description = "Detects the raw PEM-format fraudulent VMware code-signing certificate and private key artifacts from the WebServer-Compromise-Kit-45.94.31.220 campaign, recovered unencrypted from the attacker's open directory alongside the signed binaries"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/"
      date = "2026-02-28"
      family = "Sliver"
      malware_type = "Code-Signing Fraud Artifact"
      campaign = "WebServer-Compromise-Kit-45.94.31.220"
      id = "69d3d214-5285-5614-8f41-e1a05f369d22"
   strings:
      $pem_header     = "-----BEGIN CERTIFICATE-----" ascii
      $subject_cn     = "VMware, Inc. Code Signing" ascii
      $subject_l      = "Redmond" ascii
      $privkey_header = "-----BEGIN PRIVATE KEY-----" ascii
   condition:
      filesize < 10KB
      and (
         ($pem_header and $subject_cn and $subject_l)
         or ($privkey_header and ($subject_cn or $subject_l))
      )
}
```

### Hunting Rules

#### UPX-Packed Sliver Beacon Variant (compressed.exe)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027.002 (Software Packing)
**Confidence:** MODERATE
**Rationale:** UPX section markers alone match a large population of legitimate UPX-packed software; the combination with Go build strings and a narrow file-size band raises specificity, but UPX packing of Go binaries in this size range is not rare enough for alert-grade precision. The original analysis explicitly rated this rule MODERATE confidence and MEDIUM false-positive risk — that assessment is preserved rather than inflated.
**False Positives:** UPX is widely used by legitimate software developers; a Go binary packed with UPX 5.0.2 in the 13-18MB range can occur outside this campaign.
**Deployment:** Endpoint AV/EDR on-access scan (investigate, do not auto-quarantine); network gateway inspection for downloads >10MB.

```yara
rule MALW_UPX_Packed_Sliver_Variant {
   meta:
      description = "Detects the UPX 5.0.2-packed Sliver C2 beacon variant recovered from the WebServer-Compromise-Kit-45.94.31.220 campaign (compressed.exe). Matches on UPX section naming, Go build metadata present in the unpacked payload, and the packed file size fingerprint; UPX packing is common in legitimate software so this is a hunting-tier lead, not an alerting rule"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/"
      date = "2026-02-28"
      hash1 = "d94c74a6cd6629be66898eaab03ce0446f655689e28e08f0c166eaf4af9d04ea"
      hash2 = "8f27695dfd4f29e872c1661cdf225120182dd05b"
      hash3 = "f587753c0a46688af2ffea00573192e2"
      family = "Sliver"
      malware_type = "C2 Beacon (UPX-packed variant)"
      campaign = "WebServer-Compromise-Kit-45.94.31.220"
      id = "45a1d524-05ea-5875-9ad3-609a4fe78278"
   strings:
      $upx0 = "UPX0" ascii
      $upx1 = "UPX1" ascii
      $upx_ver = "UPX 5.0.2" ascii
      $go_build_1 = "-buildmode=exe" ascii wide
      $go_build_2 = "-compiler=gc" ascii wide
      $upx_lzma_marker = { 03 05 }
   condition:
      uint16(0) == 0x5A4D
      and filesize > 13MB
      and filesize < 18MB
      and $upx0
      and $upx1
      and ($upx_ver or $upx_lzma_marker)
      and all of ($go_build_*)
}
```

#### ScareCrow Build Pipeline Source Code Artifacts

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027.013 (Encrypted/Encoded File), T1106 (Native API)
**Confidence:** HIGH for the source-code markers matched; this is IR/forensic triage content, not malware-sample detection
**Rationale:** Targets source-code and pre-assembled-stub artifacts from the build toolchain itself (the XOR key + SysWhispers3 seed defines together, or the Heaven's Gate compiled stub) — for scanning developer workstations, build servers, or forensic images, a different use case from detecting the compiled malware. The original rule's standalone build-workspace-path trigger branch (a per-build, non-durable literal) has been removed and routed to the IOC feed instead — see Coverage Gaps.
**False Positives:** Low for the two remaining combination branches — the XOR_KEY/SW3_SEED define-name pairing and the Heaven's Gate opcode sequence are specific to this toolchain; a coincidental match would require both a matching define name and a matching hash seed, or the exact compiled stub bytes.
**Deployment:** Forensic disk image scan, incident response triage of suspect hosts, threat hunting scan of developer workstations and build servers.

```yara
rule TOOLKIT_ScareCrow_Build_Pipeline_Source_Artifacts {
   meta:
      description = "Hunt rule detecting source code and pre-assembled stub artifacts from the ScareCrow/SysWhispers3 build pipeline used in the WebServer-Compromise-Kit-45.94.31.220 campaign: the XOR_KEY 0x42 define paired with the SysWhispers3 SW3_SEED hash constant from string_obf.C/syscalls.C, or the compiled 10-byte Heaven's Gate far-return stub. Presence indicates the offensive build pipeline has been deployed to or is in use on the scanned host"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/"
      date = "2026-02-28"
      family = "ScareCrow Build Pipeline"
      malware_type = "Offensive Toolchain Source Artifacts"
      campaign = "WebServer-Compromise-Kit-45.94.31.220"
      id = "e38d897c-a2bf-5731-b1e0-1e00d4eecb75"
   strings:
      $xor_key_define = "#define XOR_KEY 0x42" ascii
      $sw3_seed_define = "0x9DEA8D94" ascii
      $sw3_seed_name   = "SW3_SEED" ascii
      $heavens_gate_stub = { E8 00 00 00 00 83 04 24 05 CB }
   condition:
      filesize < 5MB
      and (
         ($xor_key_define and $sw3_seed_define and $sw3_seed_name)
         or ($heavens_gate_stub and filesize < 100)
      )
}
```

---

## Sigma Rules

### Detection Rules

#### Sliver Stager PowerShell AMSI Bypass via Reflection

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.001 (PowerShell), T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** Split out from the campaign's original combined "AMSI bypass or download" rule, which OR'd this selection with a much more common download pattern under one `level: high` verdict. Isolated on its own, the reflection-based AMSI bypass — setting the private static `amsiInitFailed` field via `NonPublic,Static` binding flags and `SetValue` — is a distinctive technique combination that is genuinely rare outside AMSI-bypass tooling, purely behavioral, and independent of any campaign-specific artifact.
**False Positives:** Security research or authorized offensive-security assessment scripts using reflection-based AMSI bypass in authorized environments; red team exercises where PowerShell stagers are simulated.
**Blind Spots:** Requires PowerShell Script Block Logging (Event ID 4104) to be enabled; misses AMSI bypasses that use a different technique (patching `amsi.dll` in memory rather than the reflection field, for example).
**Validation:** Trigger the reflection-based bypass in a test PowerShell session with Script Block Logging enabled — must fire; ordinary PowerShell scripts with no AMSI interaction must NOT fire.
**Deployment:** Windows PowerShell Script Block Logging (Event ID 4104); requires Script Block Logging enabled via GPO.

```yaml
title: Sliver Stager PowerShell AMSI Bypass via Reflection
id: 3a7f2c91-5e4b-4d8a-b1c9-6f2e1a3d8b07
status: experimental
description: >-
  Detects the PowerShell AMSI-bypass technique used by the stager
  component of the WebServer-Compromise-Kit-45.94.31.220 Sliver C2
  campaign. The stager uses .NET reflection to set the private static
  amsiInitFailed field to true, disabling AMSI for the PowerShell session.
  PowerShell Script Block Logging (Event ID 4104) captures the full
  stager content even though the bypass fires after the script block is
  logged.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    product: windows
    service: powershell
    definition: >-
      Requires PowerShell Script Block Logging (Event ID 4104). Enable via
      GPO Computer Configuration, Administrative Templates, Windows
      Components, Windows PowerShell, Turn on PowerShell Script Block
      Logging.
detection:
    selection_amsi_bypass:
        EventID: 4104
        ScriptBlockText|contains|all:
            - 'amsiInitFailed'
            - 'NonPublic,Static'
            - 'SetValue'
    filter_legitimate:
        ScriptBlockText|contains:
            - 'WindowsDefenderApplicationGuard'
    condition: selection_amsi_bypass and not filter_legitimate
falsepositives:
    - >-
      Security research or authorized offensive-security assessment
      scripts using reflection-based AMSI bypass in authorized
      environments
    - Red team exercises where PowerShell stagers are simulated
level: high
```

#### Windows Defender Real-Time Protection Disabled

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** Retitled from the original "...by PowerShell Process" — the underlying selection matches Event ID 5001 regardless of which process disabled protection, so it was never actually scoped to PowerShell as the title claimed. Kept as a general defense-impairment detector rather than narrowed to PowerShell, since an attacker disabling Defender by any other means is equally suspicious; disabling real-time protection is a rare, security-relevant event in a properly managed environment and does not depend on any campaign-specific artifact.
**False Positives:** Legitimate administrative scripts disabling Defender as part of authorized software installation; enterprise management platforms (SCCM, Intune) disabling Defender via PowerShell during provisioning; security testing in authorized environments.
**Blind Spots:** Requires the Windows Defender Operational event log; an attacker who disables protection via a method that does not generate Event ID 5001 (e.g., a driver-level tamper) evades this rule.
**Validation:** Disable real-time protection in a test environment — Event ID 5001 must fire and the rule must match; routine Defender scan/update events must NOT fire.
**Deployment:** Windows Defender Operational event log; no additional configuration required.

```yaml
title: Windows Defender Real-Time Protection Disabled
id: 8b4e1f72-9c3a-4e7d-a5b8-2d6f9c1e4a83
status: experimental
description: >-
  Detects Windows Defender real-time protection being disabled (Event ID
  5001), matching the defense-impairment step used by the stager
  component of the WebServer-Compromise-Kit-45.94.31.220 Sliver C2
  campaign, which calls Set-MpPreference -DisableRealtimeMonitoring $true
  from PowerShell. The event fires regardless of which process disabled
  protection, so this rule covers the technique generally rather than
  only the PowerShell vector observed in this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    product: windows
    service: windefend
detection:
    selection_defender_disabled:
        EventID: 5001
    filter_admin_tools:
        ProcessName|endswith:
            - '\MpCmdRun.exe'
            - '\msiexec.exe'
    condition: selection_defender_disabled and not filter_admin_tools
falsepositives:
    - >-
      Legitimate administrative scripts disabling Defender as part of
      authorized software installation
    - >-
      Enterprise management platforms (SCCM, Intune) disabling Defender
      via PowerShell during provisioning
    - Security testing in authorized environments
level: high
```

#### sihost.exe Initiating Anomalous Outbound Network Connection

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1620 (Reflective Code Loading), T1134.004 (Parent PID Spoofing), T1071.001 (Web Protocols)
**Confidence:** HIGH
**Rationale:** `sihost.exe` (Shell Infrastructure Host) has no legitimate reason to initiate outbound HTTPS connections to arbitrary external destinations. The build pipeline explicitly targets `sihost.exe` for process hollowing; this rule generalizes to any injected beacon using the same injection target, not only this campaign's specific C2 domains, so it survives full infrastructure rotation.
**False Positives:** Custom enterprise environments where `sihost.exe` behavior has been modified by legitimate software; proxy or network security software that injects monitoring DLLs into `sihost.exe`, causing unusual network calls.
**Blind Spots:** Misses injection into a different target process; misses a beacon configured to use ports other than 443/8443; requires Sysmon or equivalent network-connection telemetry with process attribution.
**Validation:** Trigger process hollowing of `sihost.exe` with an outbound connection on 443/8443 — must fire; ordinary `sihost.exe` activity and connections to Microsoft-owned domains must NOT fire.
**Deployment:** Sysmon Event ID 3 (network connection) or equivalent EDR network telemetry.

```yaml
title: sihost.exe Initiating Anomalous Outbound Network Connection
id: 6f1d4b8e-3c2a-4f7b-9e5d-8a1c3f6b9e2d
status: experimental
description: >-
  Detects sihost.exe (Shell Infrastructure Host) initiating outbound
  network connections to non-Microsoft destinations on ports 443 or 8443,
  indicating successful C2 beacon injection via process hollowing. The
  WebServer-Compromise-Kit-45.94.31.220 build pipeline explicitly targets
  sihost.exe for process hollowing; the injected Sliver beacon used this
  technique to beacon out over HTTPS/mTLS. Legitimate sihost.exe does not
  initiate outbound HTTPS connections to arbitrary external addresses, so
  this rule generalizes to any injected beacon using the same injection
  target, not only this campaign's specific C2 domains.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.stealth
    - attack.t1055.012
    - attack.privilege-escalation
    - attack.t1620
    - attack.t1134.004
    - attack.command-and-control
    - attack.t1071.001
    - detection.emerging-threats
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
        DestinationHostname|endswith:
            - '.microsoft.com'
            - '.windows.com'
            - '.windowsupdate.com'
            - '.msftconnecttest.com'
    condition: selection_sihost_network and not filter_microsoft_infra
falsepositives:
    - >-
      Custom enterprise environments where sihost.exe behavior has been
      modified by legitimate software
    - >-
      Proxy or network security software that injects monitoring DLLs
      into sihost.exe, causing unusual network calls
level: high
```

### Hunting Rules

#### PowerShell WebClient DownloadFile Execution (Sliver Stager Download Pattern)

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**Rationale:** Split out from the campaign's original combined "AMSI bypass or download" rule. `Net.WebClient.DownloadFile` is one of the most common PowerShell download patterns and is used by a substantial volume of legitimate deployment, patching, and automation scripts — meaningfully noisier than the AMSI-bypass selection it was previously bundled with, so it is scoped here as a hunting/triage lead rather than an alerting rule.
**False Positives:** Automated patching, deployment, or CI/CD scripts that use `Net.WebClient.DownloadFile` to retrieve legitimate installers or updates; IT automation frameworks that stage files via PowerShell WebClient.
**Deployment:** Windows PowerShell Script Block Logging (Event ID 4104); triage hits rather than alert on them directly.

```yaml
title: PowerShell WebClient DownloadFile Execution (Sliver Stager Download Pattern)
id: 7d3f9a52-1c6e-4b8d-9a3f-5e8c2d4b7f91
status: experimental
description: >-
  Detects PowerShell using Net.WebClient.DownloadFile, matching the
  payload retrieval technique used by the stager component of the
  WebServer-Compromise-Kit-45.94.31.220 Sliver C2 campaign. Split out
  from the campaign's original combined AMSI-bypass-or-download rule
  because the download pattern alone is common to many legitimate
  PowerShell deployment and automation scripts; use for hunting and
  triage, not alerting.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    product: windows
    service: powershell
    definition: 'Requires PowerShell Script Block Logging (Event ID 4104).'
detection:
    selection_download:
        EventID: 4104
        ScriptBlockText|contains|all:
            - 'DownloadFile'
            - 'Net.WebClient'
    filter_legitimate:
        ScriptBlockText|contains:
            - 'WindowsDefenderApplicationGuard'
    condition: selection_download and not filter_legitimate
falsepositives:
    - >-
      Automated patching, deployment, or CI/CD scripts that use
      Net.WebClient.DownloadFile to retrieve legitimate installers or
      updates
    - >-
      IT automation frameworks that stage files via PowerShell WebClient
level: medium
```

#### PowerShell Drops Executable to TEMP Directory

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**Rationale:** The original rationale described a three-event chain (network connection, file write, hidden-window process creation) as the intended high-specificity detection, but only the file-write event was ever implemented as detection logic — the rule as published here matches that implementation honestly rather than the aspirational description. "PowerShell writes an .exe to Temp" alone has a real, documented false-positive population (installers, package managers, automation frameworks), consistent with the MEDIUM false-positive risk the original analysis assigned; `level` corrected from `high` to `medium` to match.
**False Positives:** Legitimate software deployment scripts that use PowerShell to download and stage installers to TEMP; package manager scripts (Chocolatey, Scoop, winget) that stage executables during installation; IT automation frameworks (Ansible, Salt, Puppet) that deploy via PowerShell to TEMP paths.
**Deployment:** Sysmon Event ID 11 (file creation) or equivalent EDR file-event telemetry; triage hits rather than alert on them directly.

```yaml
title: PowerShell Drops Executable to TEMP Directory
id: c2e5a8f3-7b1d-4c9e-8a4f-3e7b2d9c5f16
status: experimental
description: >-
  Detects PowerShell creating an executable file in the user TEMP
  directory, matching the payload-staging behavior of the stager
  component in the WebServer-Compromise-Kit-45.94.31.220 Sliver C2
  campaign — the stager writes OneDriveSync.exe to %TEMP%\update.exe
  before execution. This rule implements only the file-write event; the
  campaign's stager also opens a network connection immediately
  beforehand and launches the dropped file with a hidden window, but
  neither of those events is correlated here, so this selector alone is
  broader than the full three-event chain and is scoped as a hunting
  lead rather than an alerting rule.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
    - attack.t1105
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection_ps_exe_drop:
        Image|endswith: '\powershell.exe'
        TargetFilename|contains: '\AppData\Local\Temp\'
        TargetFilename|endswith: '.exe'
    filter_known_installers:
        TargetFilename|contains:
            - '\AppData\Local\Temp\chocolatey'
            - '\AppData\Local\Temp\scoop'
            - '\AppData\Local\Temp\winget'
    condition: selection_ps_exe_drop and not filter_known_installers
falsepositives:
    - >-
      Legitimate software deployment scripts that use PowerShell to
      download and stage installers to TEMP
    - >-
      Package manager scripts (Chocolatey, Scoop, winget) that stage
      executables during installation
    - >-
      IT automation frameworks (Ansible, Salt, Puppet) that deploy via
      PowerShell to TEMP paths
level: medium
```

#### Process Claims MicrosoftEdgeUpdate Identity from Non-Standard Location

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1036 (Masquerading), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**Rationale:** Salvage-rewritten from the original exact-argument match (`CommandLine|contains|all` on the full hardcoded spoof string). The original condition's true discriminator was a single hardcoded literal — trivially changed in a rebuild. Generalized to match any CommandLine referencing `MicrosoftEdgeUpdate.exe` while the Image path is not a legitimate Edge update location, so the rule also covers a rebuild that keeps the masquerade but changes the arguments. This trades campaign-specific precision for durability; kept at `level: medium` (not promoted to Detection) since the broader match increases the false-positive surface relative to the exact-string original.
**False Positives:** Legitimate Microsoft Edge update processes running from non-standard installation paths (uncommon but possible in enterprise repackaging scenarios); security tooling that simulates Edge update processes for testing purposes; any process whose command-line arguments happen to reference MicrosoftEdgeUpdate.exe as a string without impersonating it (rare).
**Deployment:** Sysmon Event ID 1 (process creation) with CommandLine logging, or equivalent EDR process-tree telemetry.

```yaml
title: Process Claims MicrosoftEdgeUpdate Identity from Non-Standard Location
id: 9d3e7a1f-4b8c-4e2a-b6d9-5c1f8e3a7b4d
status: experimental
description: >-
  Detects a process whose reported CommandLine references
  MicrosoftEdgeUpdate.exe while its Image path does not correspond to a
  legitimate Microsoft Edge update installation directory. The
  arg_spoof.C module in the WebServer-Compromise-Kit-45.94.31.220
  toolkit overwrites the PEB CommandLine buffer with the hardcoded
  string 'MicrosoftEdgeUpdate.exe --update-check --silent' to spoof
  process-tree viewers and EDR rules that inspect CommandLine without
  cross-referencing the true binary path. Generalized from the
  campaign's exact hardcoded argument string to the broader
  CommandLine-vs-Image mismatch pattern so the rule also covers a
  rebuild that keeps the masquerade but changes the arguments; this
  trades some campaign specificity for durability, so it is scoped as a
  hunting lead rather than an alerting rule.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_spoof_cmdline:
        CommandLine|contains: 'MicrosoftEdgeUpdate.exe'
    filter_legitimate_edge_update:
        Image|contains:
            - '\Microsoft\EdgeUpdate\'
            - '\Microsoft\Edge\Application\'
    condition: selection_spoof_cmdline and not filter_legitimate_edge_update
falsepositives:
    - >-
      Legitimate Microsoft Edge update processes running from
      non-standard installation paths (uncommon but possible in
      enterprise repackaging scenarios)
    - >-
      Security tooling that simulates Edge update processes for testing
      purposes
    - >-
      Any process whose command-line arguments happen to reference
      MicrosoftEdgeUpdate.exe as a string without impersonating it
      (rare)
level: medium
```

---

## Suricata Signatures

No standalone Suricata signatures are published for this campaign. The C2 domains and IP are transient infrastructure carried in the IOC feed rather than as DNS/IP-match rules, and the Sliver mTLS channel itself is indistinguishable from ordinary TLS at the packet level without a captured JARM/JA3S fingerprint or a distinctive HTTP C2 URI/cookie pattern — neither was recovered from the analyzed build artifacts. See Coverage Gaps below.

---

## Coverage Gaps

**Retired: memory-forensics-only analyst guidance (5 items).** The original analysis included procedural guidance for five indicators that require live memory access or interactive debugging rather than a standard Windows/Sysmon event source, so none convert cleanly to a portable Sigma rule:
- **Donut anonymous memory region (18-19MB, `PAGE_EXECUTE_READWRITE`).** Detectable only via memory forensics — a VAD/malfind-style scan for large anonymous executable regions — during the narrow window before sleep-masking re-encrypts the region; no Windows event log captures this.
- **SysWhispers3 syscall hash table in memory.** Requires a live memory search for the `0x9DEA8D94` hash-seed constant and the surrounding sorted syscall-number array — a debugger/memory-scanner procedure, not an event-log signature.
- **Process Ghosting artifact detection (T1055.015).** The API sequence (`CreateFile` with `FILE_FLAG_DELETE_ON_CLOSE` → `SetFileInformationByHandle` → `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx`) is not captured by standard Sysmon telemetry; it requires ETW kernel callbacks or EDR-native API-sequence logging with a section-object-as-image-source field, which is not a portable Sigma logsource. **What would enable a rule:** an EDR platform that exposes the image-source-type field (file vs. section object) on process-creation events.
- **Call stack spoofing detection.** Identifying a spoofed return address (`BaseThreadInitThunk` / `RtlUserThreadStart` / `Sleep` appearing in a semantically impossible call-stack position) requires interactive call-stack unwinding with PE-bounds validation — an analyst/debugger technique, not a log-source event.
- **ETW silence in sihost.exe as an injection indicator.** Requires a per-process ETW event-volume baseline and a live consumer to detect an anomalous drop to near-zero; this is an environment-specific baselining exercise, not a portable rule.

**T1140 — Deobfuscate/Decode Files or Information (XOR 0x42 runtime decode).** The XOR decode loop executes in memory and leaves no on-disk artifact; a YARA rule targeting the decode loop opcodes would be too generic (the loop structure itself is common) to avoid significant false positives. **What would enable a rule:** captured decoded strings (C2 domains, injection target path) at the moment of decode, which could anchor a memory-scan YARA rule.

**T1497.001 / T1497.003 — Virtualization and Sandbox Evasion (VM checks, uptime).** `GetSystemInfo` and `GetTickCount` are called by large volumes of legitimate software; a rule on the API calls alone, without the conditional-exit behavior that follows them, would generate unacceptable false positives. **What would enable a rule:** telemetry correlating the API call with an immediate process-exit branch, which requires behavioral/EDR sequence analysis rather than a single-event Sigma selector.

**T1573.002 — Encrypted Channel: Asymmetric Cryptography (Sliver mTLS).** Sliver's mTLS C2 channel over HTTPS (ports 443/8443) is indistinguishable from ordinary TLS traffic at the packet level without session key material. A Suricata rule keyed on TLS certificate fields or SNI for the campaign's two C2 domains would work but is a pure atomic indicator, not a behavioral signature — both domains and the resolving IP are carried in the IOC feed instead. **What would enable a Detection-tier network rule:** a captured JARM/JA3S fingerprint or a distinctive HTTP C2 URI/cookie pattern for this Sliver listener configuration; neither was recovered from the analyzed build artifacts.

**T1082 — System Information Discovery.** `GetSystemInfo` is called by a very large population of legitimate processes; without behavioral context (an immediate conditional branch to termination), this API call cannot be reliably distinguished from ordinary use.

**T1055.008 — Module Stomping.** The confirmed injection mode in the analyzed build was process hollowing (XZ mode byte `0x04`), not module stomping (`0x0a`). Module stomping is a declared capability in the ScareCrow configuration but was not confirmed as exercised. **What would enable a rule:** a memory sample showing the shellcode executing from within a mapped, signed DLL's address range rather than an anonymous allocation.

**PowerShell Drops Executable to TEMP — missing correlation.** The original rationale described a three-event chain (network connection, file write, hidden-window process creation) as the intended high-specificity detection, but only the file-write event was ever implemented; the rule as published is scoped as a Hunting lead accordingly (see Sigma Rules). **What would enable a Detection-tier version:** confirmation that `-WindowStyle Hidden` (or an equivalent flag) appears in the launching CommandLine, to add as a correlated `process_creation` selection alongside the file-write event.

**Atomics already routed to the IOC feed.** The campaign's C2 domains (`mailuxe.net`, `mailmassange.duckdns.org`), C2/delivery IP (`45.94.31.220`), payload delivery URLs, and the fraudulent certificate serial were already carried in [`sliver-open-directory-iocs.json`](/ioc-feeds/sliver-open-directory-iocs.json) prior to this pass — no standalone IOC-only Sigma or Suricata rule was ever authored for them, consistent with the tiering approach applied here. One additional atomic was added during this pass: the attacker's Linux build-workspace cache directory path (`/var/tmp/.cache-1f6a38a2-1771081283`), previously a standalone trigger branch inside the ScareCrow build-pipeline source-artifact YARA rule, is a one-off per-build identifier with no repeatable hunting value beyond the sample hash it already accompanies — it is now a `file_paths` entry in the feed instead.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

