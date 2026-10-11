---
title: Detection Rules - Sliver C2 / ScareCrow Loader Open Directory Kit
description: "Detection rules for a Sliver C2 implant build escorted by a ScareCrow loader (45.94.31.220). 5 YARA and 6 Sigma rules on binaries."
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

An exposed open directory at 45.94.31.220 yielded a complete attacker build workspace for a Sliver C2 implant wrapped in a ScareCrow loader, compiled beacons, build-pipeline source code, a fraudulent VMware code-signing certificate with its private key, and operator build logs. Coverage below spans the compiled-binary layer (YARA) and the stager/injection behavioral chain (Sigma). No standalone Suricata signatures are published: the campaign's C2 domains and IP are transient infrastructure already carried in the IOC feed, and the Sliver mTLS channel is indistinguishable from ordinary TLS at the packet level without a captured JARM/JA3S fingerprint (see Coverage Gaps).

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 3 | T1027.002, T1027.013, T1055.012, T1106, T1553.002 | 0 |
| Sigma | 2 | 4 | T1059.001, T1685, T1105, T1055.012, T1071.001, T1036, T1036.005 | 0 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting. Expect to review the hits.

**Highest-confidence anchors:**
- `sihost.exe` initiating an outbound connection on port 443 or 8443 to a destination outside four listed Microsoft hostname suffixes. A Shell Infrastructure Host process has no known reason to do this, so a hit on a host without the documented false-positive software is a lead for an injected C2 beacon (Sigma Detection, Robustness 2; this campaign's own callback was configured but never observed).
- The fraudulent "VMware, Inc. Code Signing" subject paired with a Redmond location in a PE file, which still matches a regenerated certificate serial if the template keeps both strings (YARA Detection, Robustness 2). The rule tests those two subject strings and the certificate serial; it does not test the self-signed or CA:TRUE properties.
- Go build metadata combined with the SysWhispers3 syscall-hash seed or the ScareCrow XZ-mode header, build constants that survived ScareCrow's per-build polymorphic obfuscation in the analyzed sample, though an operator who changes the payload anchors evades the rule, and the four-byte seed branch can match unrelated Go programs (YARA Hunting, Robustness 1).

**Rule reorganized during this pass:** the original "AMSI Bypass and Payload Download" Sigma rule OR'd two selections of very different precision, a rare reflection-based AMSI-bypass technique, and a common `Net.WebClient` download pattern, under one `level: high` rule. It has been split into a Detection-tier AMSI-bypass-only rule and a Hunting-tier download-pattern rule so the download selection's higher false-positive rate is reflected honestly.

**Atomics routed to the IOC feed:** the attacker's Linux build-workspace cache directory path (previously a standalone trigger branch in the ScareCrow build-pipeline source-artifact YARA rule) is a one-off, per-build identifier with no repeatable hunting value beyond the sample hash it already accompanies. It is now carried in [`sliver-open-directory-iocs.json`](/ioc-feeds/sliver-open-directory-iocs.json) instead. This does not change the rule-tier conservation count above (the surrounding rule survives as Hunting); see Coverage Gaps for detail.

---

## YARA Rules

### Detection Rules

#### Fraudulent VMware Code-Signing Certificate (PE-Embedded)

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1553.002 (Subvert Trust Controls: Code Signing)
**Confidence:** HIGH
**Rationale:** Salvage-rewritten from the original serial-only condition: the rule now fires on EITHER the exact known certificate serial plus one corroborating subject string (`VMware, Inc. Code Signing` or `Redmond`), OR both of those two strings together (`VMware, Inc. Code Signing` + `Redmond`) independent of serial. The CN-plus-Redmond pairing is itself a fraud tell: no legitimate VMware certificate is self-signed with CA:TRUE, and no legitimate VMware entity is headquartered in Redmond (Microsoft's HQ, not VMware's), so the rule still matches an operator-regenerated certificate if that certificate keeps both subject strings, not only a re-use of this exact serial. Robustness is 2: it is a combination of mutable certificate-template strings, and a regenerated certificate that changes either one evades the non-serial branch. The bare organisation string `VMware, Inc.` is no longer counted as a third field: it is a substring of the CN, so one occurrence of the CN used to satisfy two of the three fields and fire without Redmond, and a file carrying only `VMware, Inc.` and the word `Redmond` fired as well. The rule tests these strings and the serial anywhere in a PE file; it does not parse the certificate or test the self-signed or CA:TRUE properties.
**False Positives:** None known, but the rule matches three alternatives: the CN `VMware, Inc. Code Signing` with `Redmond`; the exact certificate serial with the CN; or the exact serial with `Redmond` (the serial branch needs only one of the two strings, so the CN and `Redmond` do not have to appear together there). The pairing of the CN with `Redmond` is not expected to co-occur in legitimate software, and a file carrying the shorter `VMware, Inc.` with `Redmond`, or the CN alone, does not match (checked with constructed fixtures). No Windows goodware corpus was scanned, so a measured benign-hit rate is NOT CHECKED.
**Blind Spots:** A rebuild using a wholly different impersonated vendor identity (not VMware/Redmond) evades this rule; targets on-disk PE files, not memory-only variants.
**Validation:** Scan the analyzed sample (`hash1` below) — must match via the serial+subject path. A binary signed by a legitimate VMware certificate is not expected to fire, because that certificate would not carry both `Redmond` and the CN or the fraudulent serial, but the rule does not parse the certificate or test who issued it, so that expectation is untested and a file that merely quotes the strings (a report, a rule file) would match.
**Deployment:** Endpoint AV/EDR on-access scan, email gateway attachment scanning, file server retrospective scan, network IDS/DLP for binary downloads.

```yara
rule MALW_Fraudulent_VMware_CodeSign_Cert_PE {
   meta:
      description = "Detects PE files that contain certificate strings of the fraudulent VMware, Inc. Code Signing identity used in the WebServer-Compromise-Kit-45.94.31.220 campaign: the CN VMware, Inc. Code Signing with Redmond, or the known certificate serial bytes with either the CN or Redmond. A string-level lead, not a certificate parse: it does not test who signed or issued the file."
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
   condition:
      uint16(0) == 0x5A4D
      and filesize < 100MB
      and (
         ($cert_serial and ($subject_cn or $subject_l))
         or ($subject_cn and $subject_l)
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

#### ScareCrow Go Loader (OneDriveSync.exe)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027.002 (Software Packing), T1055.012 (Process Hollowing), T1027.013 (Encrypted/Encoded File), T1106 (Native API via SysWhispers3)
**Confidence:** MODERATE
**Rationale:** Re-tiered from Detection to Hunting in round 2: no Windows goodware check was available for the four-byte seed branch, which can match unrelated Go PE64 programs, so the rule cannot be called precise, and its weakest branch is one operator-chosen constant (Robustness 1). Requires Go build metadata — present even after ScareCrow's polymorphic obfuscation, since it lives in the Go runtime metadata section rather than the encrypted payload body — plus at least one of three payload-specific anchors: the SysWhispers3 syscall-hash seed, the ScareCrow XZ-mode header byte, or the hardcoded PEB CommandLine spoof string. The strongest branches (the 12-byte XZ header, the PEB spoof string) would be a tool and build fingerprint (Robustness 2), but the rule is scored on its weakest branch: the Go build metadata is a common requirement that many unrelated trimmed Go builds also carry, so the three payload-specific anchors do the discriminating work, and an operator who changes all three (a different syscall seed, a different compression header, a different spoofed command line) evades it without touching the Go metadata. The PE check requires a PE32+ optional header (magic `0x020B`), since the report records the loader as PE64; an earlier revision compared that offset to `0x64`, which is not a value a PE32+ header holds there, so the rule could not match a PE64 file. Sample replay of the corrected header test is NOT CHECKED.
**False Positives:** None observed, but Windows goodware is unmeasured: the 6,035-file workstation corpus holds no Windows Go binaries (0 hits there with a known-positive fixture passing). The seed branch is the weakest anchor, a four-byte value (`0x9DEA8D94`) that by byte-count arithmetic for random data appears in a given 25 to 40 MB file with probability near 0.7 percent, and the three Go build strings are carried by many trimmed Go builds, so unrelated PE64 Go programs in that size band can match through the seed branch. The 12-byte XZ header pattern and the PEB spoof string are longer anchors. Before the PE32+ header correction this rule could not match any PE64 file, so it has no field exposure history either way.
**Blind Spots:** A rebuild that swaps the SysWhispers3 seed, the XZ header and the PEB spoof string for different values evades this rule without touching the Go metadata (a rebuild that strips the Go build metadata entirely would also evade it); a 32-bit build fails the PE32+ header test; targets on-disk PE files, not memory-only variants.
**Validation:** Scan the analyzed sample (`hash1` below), which must match because the file is PE64 of 25 to 40 MB, carries all three build flags and at least one of the three anchors (the sample was not available to replay: NOT CHECKED); an unrelated Go-compiled binary without SysWhispers3/ScareCrow/PEB-spoofing must NOT fire.
**Deployment:** Endpoint AV/EDR on-access scan and retrospective scan of EDR file inventory (files on disk, and saved binary copies). The condition tests `filesize` and PE header offsets, which a live process-memory scan does not provide, so the rule does not apply to a memory scanner.

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
      description = "Detects the ScareCrow-wrapped Go loader used in the WebServer-Compromise-Kit-45.94.31.220 campaign: a PE32+ file of 25 to 40 MB carrying three Go build-flag strings plus at least one of the SysWhispers3 HalosGate hash seed, the XZ stream header pattern of the ScareCrow injection mode dispatcher, or the hardcoded PEB command-line spoof string."
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
      and uint16(uint32(0x3C) + 24) == 0x020B // PE32+ optional header magic
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

#### UPX-Packed Go Binary in the 13-18MB Band (Shape of the Sliver compressed.exe)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1027.002 (Software Packing)
**Confidence:** MODERATE
**Rationale:** UPX section markers alone match a large population of legitimate UPX-packed software; the combination with Go build strings and a narrow file-size band raises specificity, but UPX packing of Go binaries in this size range is not rare enough for alert-grade precision. The original analysis explicitly rated this rule MODERATE confidence and MEDIUM false-positive risk — that assessment is preserved rather than inflated. One of the `UPX 5.0.2` version string or the two-byte value `{ 03 05 }` is required. The two-byte value is so short that almost any high-entropy file of this size contains it, so in practice the rule is the `UPX0` and `UPX1` literals (the condition tests those strings, it does not parse PE sections), the two Go build-flag strings and the 13-18MB size band; a file with neither the version string nor the two-byte value (a zero-padded fixture, for example) does not match. Nothing in the condition names Sliver, the file name `compressed.exe` or the packed sample's configuration, which is why the heading no longer does and the robustness is scored 1. The rule scans the packed file, and whether the Go build-flag strings are visible inside the UPX-compressed sample was not re-checked here (the sample is not on the workstation): NOT CHECKED.
**False Positives:** UPX is widely used by legitimate software developers; a Go binary packed with UPX (any version) in the 13-18MB range can occur outside this campaign.
**Deployment:** Endpoint AV/EDR on-access scan (investigate, do not auto-quarantine); network gateway inspection for downloads >10MB.

```yara
rule MALW_UPX_Packed_Sliver_Variant {
   meta:
      description = "Detects a UPX-packed Go binary of 13-18MB, the shape of the UPX 5.0.2-packed Sliver C2 beacon variant (compressed.exe) recovered from the WebServer-Compromise-Kit-45.94.31.220 campaign. Matches on the literals UPX0 and UPX1, the Go build-flag strings -buildmode=exe and -compiler=gc, the packed file size band, and either the UPX 5.0.2 version string or a two-byte value that almost any high-entropy file of this size contains. Not specific to Sliver; UPX packing is common in legitimate software so this is a hunting-tier lead, not an alerting rule"
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
**Rationale:** Targets source-code and pre-assembled-stub artifacts from the build toolchain itself (the XOR key + SysWhispers3 seed defines together, or a standalone Heaven's Gate stub file of under 100 bytes), for scanning developer workstations, build servers, or forensic images, a different use case from detecting the compiled malware. The stub alternative matches a tiny standalone file such as the 34-byte `heavens_gate.bin` recovered from the workspace; the `filesize < 100` gate means a copy of the stub embedded in a larger loader or binary does not match. The original rule's standalone build-workspace-path trigger branch (a per-build, non-durable literal) has been removed and routed to the IOC feed instead — see Coverage Gaps.
**False Positives:** Low for the source branch: the XOR_KEY/SW3_SEED define-name pairing is specific to this toolchain, and a coincidental match would require a matching define name, a matching hash seed and the seed's name. The stub branch is a generic 10-byte call/add/far-return trampoline kept narrow only by its size gate: any file of under 100 bytes that contains those bytes matches, whatever tool produced it, and a larger file never does.
**Deployment:** Forensic disk image scan, incident response triage of suspect hosts, threat hunting scan of developer workstations and build servers.

```yara
rule TOOLKIT_ScareCrow_Build_Pipeline_Source_Artifacts {
   meta:
      description = "Hunt rule detecting source code and pre-assembled stub artifacts from the ScareCrow/SysWhispers3 build pipeline used in the WebServer-Compromise-Kit-45.94.31.220 campaign: the XOR_KEY 0x42 define paired with the SysWhispers3 SW3_SEED hash constant from string_obf.C/syscalls.C, or a standalone file of under 100 bytes holding the compiled 10-byte Heaven's Gate far-return stub (the heavens_gate.bin artifact); a stub embedded in a larger file does not match. A source-file hit indicates the build pipeline source is present on the scanned host; the stub alternative matches only a tiny standalone shellcode file"
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

#### PowerShell AMSI Bypass via amsiInitFailed Reflection

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1059.001 (PowerShell), T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**Rationale:** Split out from the campaign's original combined "AMSI bypass or download" rule, which OR'd this selection with a much more common download pattern under one `level: high` verdict. Isolated on its own, script text that names the private static `amsiInitFailed` field together with the `NonPublic,Static` binding flags and `SetValue` is a distinctive combination that is genuinely rare outside AMSI-bypass tooling and independent of any campaign-specific artifact. The three strings are tested independently: they do not prove that the field is set, or set to true (the stager's example sets it to true, but that argument and data flow are not selected). A script block that also contains the string `WindowsDefenderApplicationGuard` is excluded by the filter even when it holds a complete bypass. The selection carries no Sliver or campaign marker, so it matches this bypass wherever it appears and the rule is titled for the technique, not for the Sliver stager that used it in this campaign.
**False Positives:** Security research or authorized offensive-security assessment scripts using reflection-based AMSI bypass in authorized environments; red team exercises where PowerShell stagers are simulated.
**Blind Spots:** Requires PowerShell Script Block Logging (Event ID 4104) to be enabled; a script block that also contains the string `WindowsDefenderApplicationGuard` is suppressed by the filter, so a bypass pasted into or beside text holding that string is missed; misses AMSI bypasses that use a different technique (patching `amsi.dll` in memory rather than the reflection field, for example).
**Validation:** Trigger the reflection-based bypass in a test PowerShell session with Script Block Logging enabled — must fire, provided the script block does not also contain the string `WindowsDefenderApplicationGuard`; ordinary PowerShell scripts with no AMSI interaction must NOT fire. The rule matches the three strings in any order and place, so it cannot tell a script that sets the field from one that only mentions it.
**Deployment:** Windows PowerShell Script Block Logging (Event ID 4104); requires Script Block Logging enabled via GPO.

```yaml
title: PowerShell AMSI Bypass via amsiInitFailed Reflection
id: 3a7f2c91-5e4b-4d8a-b1c9-6f2e1a3d8b07
status: experimental
description: >-
  Detects a PowerShell script block whose text contains amsiInitFailed,
  NonPublic,Static and SetValue, the text pattern of the reflection-based
  AMSI bypass used by the stager component of the
  WebServer-Compromise-Kit-45.94.31.220 Sliver C2 campaign. The three strings
  are tested independently, so the rule does not prove the field is set or
  set to true, and a script block that also contains
  WindowsDefenderApplicationGuard is excluded. The selection is
  technique-level: nothing in it is specific to that campaign or to Sliver.
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

#### sihost.exe Initiating Anomalous Outbound Network Connection

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1055.012 (Process Hollowing), T1071.001 (Web Protocols)
**ATT&CK Note:** The build chain behind the hollowing target also uses reflective code loading (T1620) and parent PID spoofing (T1134.004), but a network-connection event observes neither, so neither id is claimed here or in the tags. T1055.012 stays because the rule keys on the process the campaign hollows.
**Confidence:** HIGH
**Rationale:** `sihost.exe` (Shell Infrastructure Host) has no known reason to initiate outbound connections on 443 or 8443 to destinations outside Microsoft's own hostnames. The build pipeline explicitly targets `sihost.exe` for process hollowing; this rule generalizes to any injected beacon using the same injection target, not only this campaign's specific C2 domains, so it survives full infrastructure rotation. The campaign's own network realization was not observed: the C2 was offline before the beacon connected, and the report records the callback behavior as configured, not observed, so no live `sihost.exe` connection from this campaign backs the rule. Robustness is 2: the hollowing target is an implementation choice of this build (an operator can pick another process or another port), not an invariant of the technique. The Microsoft exclusion is a list of four hostname suffixes (`.microsoft.com`, `.windows.com`, `.windowsupdate.com`, `.msftconnecttest.com`) tested against `DestinationHostname`, not a test of who owns the destination: a connection to any other hostname fires, including other Microsoft-operated hostnames, and a connection whose hostname was not resolved (empty `DestinationHostname`) is not excluded and fires.
**False Positives:** Custom enterprise environments where `sihost.exe` behavior has been modified by legitimate software; proxy or network security software that injects monitoring DLLs into `sihost.exe`, causing unusual network calls; `sihost.exe` connections to Microsoft-operated hostnames outside the four excluded suffixes, or logged without a hostname.
**Blind Spots:** Misses injection into a different target process; misses a beacon configured to use ports other than 443/8443; requires Sysmon or equivalent network-connection telemetry with process attribution.
**Validation:** Trigger process hollowing of `sihost.exe` with an outbound connection on 443/8443 to a hostname outside the four listed suffixes: must fire; ordinary `sihost.exe` activity and connections to hostnames ending in one of the four listed Microsoft suffixes must NOT fire. A connection to a Microsoft-operated hostname outside those four suffixes, or one logged with no hostname, fires by design; extend the exclusion list from your own baseline.
**Deployment:** Sysmon Event ID 3 (network connection) or equivalent EDR network telemetry.

```yaml
title: sihost.exe Initiating Anomalous Outbound Network Connection
id: 6f1d4b8e-3c2a-4f7b-9e5d-8a1c3f6b9e2d
status: experimental
description: >-
  Detects sihost.exe (Shell Infrastructure Host) initiating a network
  connection on port 443 or 8443 to a destination whose hostname does not
  end in .microsoft.com, .windows.com, .windowsupdate.com or
  .msftconnecttest.com (a connection with no logged hostname is not
  excluded). That is the pattern expected from a C2 beacon injected into
  sihost.exe by process hollowing. The
  WebServer-Compromise-Kit-45.94.31.220 build pipeline explicitly targets
  sihost.exe for process hollowing and the beacon is configured to call out
  over HTTPS/mTLS, but the C2 was offline and no external connection was
  observed, so this is an anomaly lead and not a recorded campaign event.
  Legitimate sihost.exe is not
  known to connect to arbitrary external addresses, so this rule
  generalizes to any injected beacon using the same injection target, not
  only this campaign's specific C2 domains.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
tags:
    - attack.stealth
    - attack.t1055.012
    - attack.privilege-escalation
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

#### Windows Defender Real-Time Protection Disabled

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** MODERATE
**Rationale:** Retitled from the original "...by PowerShell Process": the selection is Event ID 5001 alone, so it fires whichever process or action disabled protection and was never scoped to PowerShell as the title claimed. An earlier revision also excluded `ProcessName` values ending in `\MpCmdRun.exe` or `\msiexec.exe`; Event ID 5001 does not carry a process name (SigmaHQ's own rule for this event notes that it "doesn't contain a lot of information on who initiated this action"), so that filter never evaluated true and was removed, which leaves the rule's behaviour unchanged. Re-tiered from Detection to Hunting, and `level` lowered from `high` to `medium`: the event shows only that real-time protection went off, from any cause, and the false-positive list below names routine causes (software installation, provisioning by management platforms, authorized testing) that the rule cannot tell apart from an attacker. It is a scoping lead for defense-impairment hunting, to be read beside the PowerShell script-block hits for `Set-MpPreference`, not an alert.
**False Positives:** Legitimate administrative scripts disabling Defender as part of authorized software installation; enterprise management platforms (SCCM, Intune) disabling Defender via PowerShell during provisioning; security testing in authorized environments. The rule cannot distinguish these from an attacker because the event carries no initiator.
**Blind Spots:** Requires the Windows Defender Operational event log; an attacker who disables protection via a method that does not generate Event ID 5001 (e.g., a driver-level tamper) evades this rule.
**Validation:** Disable real-time protection in a test environment: Event ID 5001 must fire and the rule must match; routine Defender scan/update events must NOT fire. A disable performed by any process or by an administrator through the Defender settings also fires; that is expected.
**Deployment:** Windows Defender Operational event log; no additional configuration required. Hunting lead for scoping, not an alerting rule.

```yaml
title: Windows Defender Real-Time Protection Disabled
id: 8b4e1f72-9c3a-4e7d-a5b8-2d6f9c1e4a83
status: experimental
description: >-
  Detects Windows Defender real-time protection being disabled (Event ID
  5001), matching the defense-impairment step used by the stager
  component of the WebServer-Compromise-Kit-45.94.31.220 Sliver C2
  campaign, which calls Set-MpPreference -DisableRealtimeMonitoring $true
  from PowerShell. Event ID 5001 carries no initiator, so the rule fires
  regardless of which process or person disabled protection and covers the
  technique generally rather than only the PowerShell vector observed in
  this campaign. Administrative and management-platform disables also
  fire, so use it for hunting and triage, not alerting.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-open-directory-detections/
author: The Hunters Ledger
date: 2026-02-28
modified: 2026-10-11
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
    condition: selection_defender_disabled
falsepositives:
    - >-
      Legitimate administrative scripts disabling Defender as part of
      authorized software installation
    - >-
      Enterprise management platforms (SCCM, Intune) disabling Defender
      via PowerShell during provisioning
    - Security testing in authorized environments
level: medium
```

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
**Rationale:** Salvage-rewritten from the original exact-argument match (`CommandLine|contains|all` on the full hardcoded spoof string). The original condition's true discriminator was a single hardcoded literal — trivially changed in a rebuild. Generalized to match any CommandLine referencing `MicrosoftEdgeUpdate.exe` while the Image path does not start with one of the machine-wide Edge update roots listed in the filter, so the rule also covers a rebuild that keeps the masquerade but changes the arguments. The filter paths are anchored at the start of the Image path (`C:\Program Files (x86)\...` and `C:\Program Files\...`); the original filter used unanchored substrings, so a user-writable path that merely contained `\Microsoft\Temp\EU` or `\Microsoft\EdgeUpdate\` was excluded as well. This trades campaign-specific precision for durability; kept at `level: medium` (not promoted to Detection) since the broader match increases the false-positive surface relative to the exact-string original.
**False Positives:** Security tooling that simulates Edge update processes for testing; any process whose command-line arguments happen to reference MicrosoftEdgeUpdate.exe as a string without impersonating it (rare). Note the third filter path: Edge's own updater self-stages a copy into `C:\Program Files (x86)\Microsoft\Temp\EU<hex>.tmp\MicrosoftEdgeUpdate.exe` and runs it from there during an updater refresh, launched by the signed `MicrosoftEdgeUpdateSetup_X86_*.exe` under `\Microsoft\EdgeUpdate\Install\`. That path is neither of the two obvious install directories, so a version of this rule filtering only those two fires on every Windows host each time Edge updates its updater. The staging directory sits under `Program Files (x86)` and so requires administrative rights to write; because the filter is now anchored at `C:\Program Files (x86)\Microsoft\Temp\EU` rather than matching the segment anywhere in the path, a user-writable directory that only contains that segment is no longer excluded. The anchoring assumes Windows is installed on `C:`, and a per-user Edge or EdgeUpdate install under a profile directory is not excluded: both fire and need a local tuning entry.
**Deployment:** Sysmon Event ID 1 (process creation) with CommandLine logging, or equivalent EDR process-tree telemetry.

```yaml
title: Process Claims MicrosoftEdgeUpdate Identity from Non-Standard Location
id: 9d3e7a1f-4b8c-4e2a-b6d9-5c1f8e3a7b4d
status: experimental
description: >-
  Detects a process whose reported CommandLine references
  MicrosoftEdgeUpdate.exe while its Image path does not start with one of
  the machine-wide Microsoft Edge update installation directories under
  C:\Program Files (x86) or C:\Program Files. The
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
modified: 2026-10-11
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
        Image|startswith:
            # sourced: documented platform default, machine-wide Edge and EdgeUpdate install roots
            - 'C:\Program Files (x86)\Microsoft\EdgeUpdate\'
            - 'C:\Program Files (x86)\Microsoft\Edge\Application\'
            - 'C:\Program Files\Microsoft\EdgeUpdate\'
            - 'C:\Program Files\Microsoft\Edge\Application\'
            # sourced: Edge updater self-staging path described in the false-positive note above
            - 'C:\Program Files (x86)\Microsoft\Temp\EU'
    condition: selection_spoof_cmdline and not filter_legitimate_edge_update
falsepositives:
    - >-
      Legitimate Microsoft Edge update processes running from
      non-standard installation paths, including a per-user install under
      a profile directory or Windows installed on a drive other than C:
      (uncommon but possible in enterprise repackaging scenarios)
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

No standalone Suricata signatures are published for this campaign. The C2 domains and IP are transient infrastructure carried in the IOC feed rather than as DNS/IP-match rules, and the Sliver mTLS channel itself is indistinguishable from ordinary TLS at the packet level without a captured JARM/JA3S fingerprint or a distinctive HTTP C2 URI/cookie pattern. Neither was recovered from the analyzed build artifacts. See Coverage Gaps below.

---

## Coverage Gaps

**Retired: memory-forensics-only analyst guidance (5 items).** The original analysis included procedural guidance for five indicators that require live memory access or interactive debugging rather than a standard Windows/Sysmon event source, so none convert cleanly to a portable Sigma rule:
- **Donut anonymous memory region (18-19MB, `PAGE_EXECUTE_READWRITE`).** Detectable only via memory forensics (a VAD/malfind-style scan for large anonymous executable regions) during the narrow window before sleep-masking re-encrypts the region; no Windows event log captures this.
- **SysWhispers3 syscall hash table in memory.** Requires a live memory search for the `0x9DEA8D94` hash-seed constant and the surrounding sorted syscall-number array, a debugger/memory-scanner procedure, not an event-log signature.
- **Process Ghosting artifact detection (T1055.015).** The API sequence (`CreateFile` with `FILE_FLAG_DELETE_ON_CLOSE` → `SetFileInformationByHandle` → `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx`) is not captured by standard Sysmon telemetry; it requires ETW kernel callbacks or EDR-native API-sequence logging with a section-object-as-image-source field, which is not a portable Sigma logsource. **What would enable a rule:** an EDR platform that exposes the image-source-type field (file vs. section object) on process-creation events.
- **Call stack spoofing detection.** Identifying a spoofed return address (`BaseThreadInitThunk` / `RtlUserThreadStart` / `Sleep` appearing in a semantically impossible call-stack position) requires interactive call-stack unwinding with PE-bounds validation, an analyst/debugger technique, not a log-source event.
- **ETW silence in sihost.exe as an injection indicator.** Requires a per-process ETW event-volume baseline and a live consumer to detect an anomalous drop to near-zero; this is an environment-specific baselining exercise, not a portable rule.

**T1140 Deobfuscate/Decode Files or Information (XOR 0x42 runtime decode).** The XOR decode loop executes in memory and leaves no on-disk artifact; a YARA rule targeting the decode loop opcodes would be too generic (the loop structure itself is common) to avoid significant false positives. **What would enable a rule:** captured decoded strings (C2 domains, injection target path) at the moment of decode, which could anchor a memory-scan YARA rule.

**T1497.001 / T1497.003 Virtualization and Sandbox Evasion (VM checks, uptime).** `GetSystemInfo` and `GetTickCount` are called by large volumes of legitimate software; a rule on the API calls alone, without the conditional-exit behavior that follows them, would generate unacceptable false positives. **What would enable a rule:** telemetry correlating the API call with an immediate process-exit branch, which requires behavioral/EDR sequence analysis rather than a single-event Sigma selector.

**T1573.002 Encrypted Channel: Asymmetric Cryptography (Sliver mTLS).** Sliver's mTLS C2 channel over HTTPS (ports 443/8443) is indistinguishable from ordinary TLS traffic at the packet level without session key material. A Suricata rule keyed on TLS certificate fields or SNI for the campaign's two C2 domains would work but is a pure atomic indicator, not a behavioral signature. Both domains and the resolving IP are carried in the IOC feed instead. **What would enable a Detection-tier network rule:** a captured JARM/JA3S fingerprint or a distinctive HTTP C2 URI/cookie pattern for this Sliver listener configuration; neither was recovered from the analyzed build artifacts.

**T1082 System Information Discovery.** `GetSystemInfo` is called by a very large population of legitimate processes; without behavioral context (an immediate conditional branch to termination), this API call cannot be reliably distinguished from ordinary use.

**T1055.008 Module Stomping.** The confirmed injection mode in the analyzed build was process hollowing (XZ mode byte `0x04`), not module stomping (`0x0a`). Module stomping is a declared capability in the ScareCrow configuration but was not confirmed as exercised. **What would enable a rule:** a memory sample showing the shellcode executing from within a mapped, signed DLL's address range rather than an anonymous allocation.

**PowerShell Drops Executable to TEMP: missing correlation.** The original rationale described a three-event chain (network connection, file write, hidden-window process creation) as the intended high-specificity detection, but only the file-write event was ever implemented; the rule as published is scoped as a Hunting lead accordingly (see Sigma Rules). **What would enable a Detection-tier version:** confirmation that `-WindowStyle Hidden` (or an equivalent flag) appears in the launching CommandLine, to add as a correlated `process_creation` selection alongside the file-write event.

**Atomics already routed to the IOC feed.** The campaign's C2 domains (`mailuxe.net`, `mailmassange.duckdns.org`), C2/delivery IP (`45.94.31.220`), payload delivery URLs, and the fraudulent certificate serial were already carried in [`sliver-open-directory-iocs.json`](/ioc-feeds/sliver-open-directory-iocs.json) prior to this pass. No standalone IOC-only Sigma or Suricata rule was ever authored for them, consistent with the tiering approach applied here. One additional atomic was added during this pass: the attacker's Linux build-workspace cache directory path (`/var/tmp/.cache-1f6a38a2-1771081283`), previously a standalone trigger branch inside the ScareCrow build-pipeline source-artifact YARA rule, is a one-off per-build identifier with no repeatable hunting value beyond the sample hash it already accompanies. It is now a `file_paths` entry in the feed instead.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

