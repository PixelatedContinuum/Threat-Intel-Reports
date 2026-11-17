---
title: "Detection Rules — Sliver and NimPlant operator on 169.58.165.63 (cytomate.xyz front): Active Directory intrusion of a Pakistani university"
date: '2026-11-16'
layout: post
permalink: /hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
hide: true
unlisted: true
sitemap: false
---

**Campaign:** INV-2026-084
**Date:** 2026-11-16
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 1 | 4 | T1071.001, T1573.002, T1105, T1620, T1572 | 1 |
| Sigma | 3 | 9 | T1553.004, T1557.002, T1040, T1059.001, T1095, T1003.002, T1557.001, T1087.002, T1069.002, T1552.001, T1555, T1071.001, T1543.003, T1105, T1005 | 1 |
| Suricata | 1 | 5 | T1071.001, T1105 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader or key on a name the operator can change, for scoping and threat-hunting. Expect to review the hits.

The file carries 23 rules (5 Detection, 18 Hunting): 5 YARA, 12 Sigma and 6 Suricata. The five Detection rules are one YARA rule on the Sliver protobuf accessor names, three Sigma rules (a certificate added to the TrustedPublisher store from a user-writable path, the bettercap attack tool, and a raw-TCP PowerShell reverse shell read from the script block) and one Suricata rule on a NimPlant server banner. Most of the file is Hunting because the operator's own script and folder names carry the case, and a renamed script escapes them. A "Coverage Gaps" section at the end lists every behaviour I looked at and did not write a rule for, with the reason.

---

## What these rules do not claim

These rules come from a static reading of an operator's open directory: eight Sliver builds, six Meterpreter stagers, three builds of the chisel tunnel, the operator's attack scripts and their logs. I did not execute anything, and I found no victim-side telemetry in the capture. No Sigma rule was confirmed against a victim log, and no Suricata rule was replayed against a capture, because the case holds no capture of the operator's traffic.

- **Sigma rules are written from the operator's scripts and command lines, not from observed events.** A rule that depends on how Windows or Sysmon logs an event (a script block split across events, the image of a child process) is derived from the artifact and from how the public technique works. None was replayed against SigmaHQ's benign event baseline, so its false-positive behaviour on ordinary logs is NOT CHECKED.
- **The YARA rules were scanned, not only compiled.** Each fires on the sample it was written from, and each was scanned on an isolated Windows host over its `C:\Windows\System32`, `C:\Program Files` and a dual-use `C:\Tools` folder. The counts are in each rule's Validation line and in the case Notes. A zero over those folders is a count over that disk on 2026-11-16, not a claim about other systems.
- **Upstream coverage was read, not searched exhaustively.** I read the SigmaHQ clone (dated 2026-09-12) for the Sigma rules and ran the one signature-base Sliver file on a scan host for the Sliver YARA rule. Suricata upstream coverage is NOT CHECKED.
- **Garbled Sliver builds hide their strings, so no string rule can name them.** The one rule that matches all eight Sliver builds keys on protobuf accessor names that garble leaves in clear. The recovered command-and-control addresses and certificate values are indicators, so they are in the indicator feed and not in any rule here.
- **No victim value appears in any rule.** The directory-service account names, host names and addresses the operator's scripts carry are withheld. Where a script held a hard-coded credential, no rule uses it.

Each YARA rule names the held sample it was written from by hash prefix. The plain Sliver build is `sp.exe` (sha256 `bd1a1437...5b01d`), the garbled build is `sliver.exe` (`0d3415e8...de24`), the stager is `meter4444.exe` (`da4172c7...8659`), the stageless Meterpreter loader is `meter5555_183.exe` (`a5111c36...304f`) and chisel is `chisel.exe` (`ca5f8e52...3738`).

---

## YARA Rules

### Detection Rules

**Sliver (eight builds)**

#### MAL_WIN_INV2026084_Sliver_ProtobufReflectionNames_GoImplant

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** partially_covered
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.002 (Asymmetric Cryptography)
**ATT&CK Note:** The rule describes the implant's own protocol code. The mTLS scheme and the age and minisign keys sit in garble-encrypted literals in five builds, so none is used here.
**Confidence:** HIGH
**False Positives:** None known. The rule needs at least seven of eight Sliver protobuf accessor names (GetBeaconInterval, GetReconnectInterval, GetActiveC2, GetPeerID, GetBeaconID, GetConfigID, GetPollInterval, GetBeaconJitter) plus BeaconRegister in one PE or ELF under 60 MB. I know of no program other than a Sliver implant or a Sliver-derived tool that carries them. A defender's own Sliver test binary will match.
**Blind Spots:** Misses a Sliver fork that renames the protobuf accessors, which means rebuilding the protocol definitions. Misses a packed or encrypted copy on disk. Does not name the family when the accessors are present in a Sliver server or client binary, which is also a match.
**Validation:** Written from the garbled `sliver.exe` and scanned on an isolated Windows host: compiles with yarac, passes its known-positive self-test, FIRES on `sliver.exe`, and scans 0 hits over 33,061 files in System32, 32,993 in Program Files and 62,829 in C:\Tools. A sweep of the 63 held files from 5 KB to 60 MB fires on 8 of the 8 Sliver builds (`sliver.exe`, `u131.exe`, `u218.exe`, `u237.exe`, `esxi_implant`, `sp.exe`, `spadc1.exe`, `vmupd.exe`) and on neither chisel build nor `bettercap.exe`, so the control varies garbled against plain and Windows against Linux. The Go population in the benign folders is small, so the false-positive evidence rests on the names being Sliver-specific: NOT CHECKED against a large benign Go population. Upstream: signature-base's Sliver_Implant_32bit and Sliver_Implant_64bit, run on the scan host, fire on 5 of the 8 builds and miss `vmupd.exe`, `spadc1.exe` and `esxi_implant`. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Endpoint AV and EDR file scan of Windows and Linux hosts, and a hunt of any folder the operator staged tools in. The rule tests `filesize`, so it does not match inside process memory.
**Basis:** The implant report's accessor counts for `sliver.exe` (GetBeaconInterval, GetReconnectInterval, GetActiveC2, GetPeerID, GetBeaconID, GetConfigID, BeaconRegister) in the implant analysis, and the lab sweep above.

```yara
rule MAL_WIN_INV2026084_Sliver_ProtobufReflectionNames_GoImplant {
   meta:
      description = "Detects a Sliver Go implant, including builds compiled with garble that hide the package names and every string literal, by the protobuf accessor names that reflection forces garble to leave in clear (GetBeaconInterval, GetReconnectInterval, GetActiveC2, GetPeerID and the rest) together with the mTLS transport scheme and the yamux multiplexer preamble"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/"
      date = "2026-11-16"
      hash1 = "0d3415e8d45de96f426e77d388097b4af86f70572ac4bf5f010c3e29d7bede24"
      hash2 = "9ba72a851aef02f07edc4eb7a28e785edf226924"
      hash3 = "2848164d54edd740f054c071ec1776f7"
      family = "Sliver"
      id = "42d49095-8ec0-5009-9c01-5bbb7503303f"
   strings:
      $g1 = "GetBeaconInterval" ascii
      $g2 = "GetReconnectInterval" ascii
      $g3 = "GetActiveC2" ascii
      $g4 = "GetPeerID" ascii
      $g5 = "GetBeaconID" ascii
      $g6 = "GetConfigID" ascii
      $g7 = "GetPollInterval" ascii
      $g8 = "GetBeaconJitter" ascii
      $r1 = "BeaconRegister" ascii
   condition:
      (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
      filesize < 60MB and
      7 of ($g*) and
      $r1
}
```

### Hunting Rules

**Sliver, plain builds**

#### MAL_WIN_INV2026084_Sliver_MasqueradedGvisorModuleRoot_PlainBuild

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.002 (Asymmetric Cryptography)
**ATT&CK Note:** The module root is Sliver's default rewrite; it hides the family in a package listing and does not hide it from this rule.
**Confidence:** HIGH
**False Positives:** None known. gVisor has no `runc/cgroup` implant package and no `protobuf/sliverpb` package, and the three strings sit together in no other file I scanned. The rule is Hunting for durability, not for noise.
**Blind Spots:** The module root is not the operator's choice: Sliver's own build code rewrites the Go module to `github.com/google/gvisor` for non-debug builds (BishopFox/sliver `server/generate/binaries.go`, line 1047 on the default branch), so this rule finds plain Sliver builds of that generation from any operator, not this operator. A debug build, a build from a Sliver version without that rewrite, or a garbled build escapes it, and the five garbled builds in this case do. The reflection-name rule covers them.
**Validation:** Written from the plain build `sp.exe` and scanned on an isolated Windows host: compiles, passes its self-test, FIRES on `sp.exe`, and scans 0 hits over 33,060 files in System32, 32,993 in Program Files and 62,829 in C:\Tools. The sweep fires on `sp.exe`, `spadc1.exe` and `vmupd.exe` (3 of the 3 plain builds) and on none of the garbled five. Upstream coverage is recorded for Detection-tier rules only. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Endpoint AV and EDR file scan, and a hunt of operator staging folders.
**Basis:** The Go package names in `sp.exe`, `vmupd.exe` and `spadc1.exe` (`github.com/google/gvisor/runc/cgroup/...` and `.../protobuf/sliverpb`), from the implant analysis.

```yara
rule MAL_WIN_INV2026084_Sliver_MasqueradedGvisorModuleRoot_PlainBuild {
   meta:
      description = "Detects a plain (non-garbled) Sliver implant built for Windows whose Go module root was rewritten to look like the gVisor container library: the implant sub-packages sit under github.com/google/gvisor/runc/cgroup and the protobuf package is github.com/google/gvisor/protobuf/sliverpb, neither of which exists in gVisor"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/"
      date = "2026-11-16"
      hash1 = "bd1a14378f3b067f36808098b4571bede03e40545e4eb237f9cfdef345a5b01d"
      hash2 = "bd5856cf4aa87f8deed09139b4980782aa62cffe"
      hash3 = "be931f64c13c0df8de1d89200cf467de"
      family = "Sliver"
      id = "aeb347df-2cf5-5b73-9e57-efb8aa5f8d3e"
   strings:
      $m1 = "github.com/google/gvisor/runc/cgroup/" ascii
      $m2 = "github.com/google/gvisor/protobuf/sliverpb" ascii
      $m3 = "github.com/google/gvisor/protobuf/commonpb" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 60MB and
      $m2 and
      $m1 and
      $m3
}
```

**Metasploit stagers and loader**

#### HKTL_WIN_INV2026084_Meterpreter_MsfTemplateStager_PayloadMarker

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Another Metasploit executable built from the same template, by any operator, will match, and so will a red team's own stager. I found no benign file with the unreplaced `PAYLOAD:` marker, `VirtualProtect` and the block_api prologue together.
**Blind Spots:** Misses a stager built without the template's `PAYLOAD:` placeholder, a stager encoded by an encoder, and one whose prologue is reordered more than the five held builds are. The block_api prologue and the marker are Metasploit defaults, not this operator's.
**Validation:** Written from `meter4444.exe` and scanned on an isolated Windows host: compiles, passes its self-test, FIRES on `meter4444.exe`, and scans 0 hits over 33,061 files in System32, 32,993 in Program Files and 62,829 in C:\Tools. The held-file sweep fires on all five stager files (`meter4444.exe`, `meter4446.exe`, `meter64.exe`, `meter86.exe` and `met183.exe`) and not on `meter5555_183.exe`. The x64 builds reorder the block_api instructions, so the 64-bit pattern stops after 15 bytes. signature-base's `gen_metasploit_payloads.yar`, run on the scan host, did not fire on any of the stagers, but I did not run the rest of the repository. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Endpoint AV and EDR file scan, and a hunt of operator staging folders and web roots.
**Basis:** The five stager rows in the stager analysis (the block_api prologue at file offset 0x1A00, `ws2_32` at 0x1AD9 and `PAYLOAD:` at 0x800).

```yara
rule HKTL_WIN_INV2026084_Meterpreter_MsfTemplateStager_PayloadMarker {
   meta:
      description = "Detects the small Windows (x64 or x86) reverse_tcp stager the operator built from the Metasploit executable template: a single KERNEL32 import (VirtualProtect), the shellcode block_api prologue stored in the last section (64-bit, or the 32-bit form without the ws2_32 string), and the unreplaced PAYLOAD: placeholder of the template's data section"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/"
      date = "2026-11-16"
      hash1 = "da4172c7816d9ec15801c46dacb077dd883f7629c3f101c1e7e2928bba7e8659"
      hash2 = "94d97fa0aa3cc61907c666543806870d7e57cb87"
      hash3 = "dd597a4dbdf9338814ebe71bca7b4883"
      family = "Metasploit"
      id = "f616e70b-b465-58f8-8c17-7119b04bcd73"
   strings:
      $stub64 = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 }
      $stub32 = { FC E8 ?? 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
      $ws2 = "ws2_32" ascii
      $marker = "PAYLOAD:" ascii
      $vp = "VirtualProtect" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20KB and
      $marker and
      $vp and
      (($stub64 and $ws2) or $stub32)
}
```

#### SUSP_WIN_INV2026084_Meterpreter_ReflectiveStub_EmbeddedDll

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1620 (Reflective Code Loading)
**ATT&CK Note:** The carved configuration names `tcp://169.58.165.63:5555`. That address belongs in the indicator feed and not in a rule.
**Confidence:** MODERATE
**False Positives:** Any small loader that embeds a reflective DLL with this bootstrap matches, including other red-team tools and sRDI-style packers. I found no hit among the scanned benign files, but the bootstrap is not unique to this operator.
**Blind Spots:** Misses a loader with a different bootstrap. Does not read the embedded DLL's configuration, which is XOR-encoded with a four-byte key that changes per build.
**Validation:** Written from `meter5555_183.exe` and scanned on an isolated Windows host: compiles, passes its self-test, FIRES on `meter5555_183.exe`, and scans 0 hits over 33,062 files in System32, 32,993 in Program Files and 62,829 in C:\Tools. The held-file sweep fires on that file only. The first version of the rule used a count and an offset condition that the text self-test fixture cannot meet; I simplified it and the self-test passed. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Endpoint AV and EDR file scan.
**Basis:** The stageless loader in the stager analysis (MZARUH bootstrap at the start of the last section) and the carved configuration in the configuration recovery.

```yara
rule SUSP_WIN_INV2026084_Meterpreter_ReflectiveStub_EmbeddedDll {
   meta:
      description = "Detects a small Windows loader that carries a Metasploit-style stageless server DLL: a reflective bootstrap that starts with the MZARUH header trick (MZ, push r10, push rbp, mov rbp, rsp) and calls into the embedded image, inside a PE no larger than a few hundred kilobytes"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/"
      date = "2026-11-16"
      hash1 = "a5111c366fad5fdbbc7407419427bf3eacdaedebcaeb590eb79412e3605a304f"
      hash2 = "27dad366952cdd0ebb323bdf66c14dea31f4d42a"
      hash3 = "01bb88716813dd152326b0c978ca6f93"
      family = "Metasploit"
      id = "bdc866e2-78ad-5421-b25b-e0a53753de30"
   strings:
      $boot = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 83 E4 F0 E8 00 00 00 00 5B 48 81 C3 ?? ?? 00 00 FF D3 }
   condition:
      uint16(0) == 0x5A4D and
      filesize < 1MB and
      $boot
}
```

**Chisel tunnel**

#### HKTL_GEN_INV2026084_Chisel_GoTunnel_UpstreamBuild

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1572 (Protocol Tunneling)
**Confidence:** HIGH
**False Positives:** Authorized administrators and testers use chisel, and a build of an unmodified upstream checkout matches. Any Go program that vendors the chisel module with its help text also matches. C:\Tools on the scan host holds no chisel build, so the dual-use column is empty.
**Blind Spots:** Misses a renamed or modified build that changes the protocol string, and a build that strips the help text. It says nothing about how the tool was run: the server address and fingerprint were not in the binaries.
**Validation:** Written from `chisel.exe` and scanned on an isolated Windows host: compiles, passes its self-test, FIRES on `chisel.exe`, and scans 0 hits over 33,062 files in System32, 32,993 in Program Files and 62,829 in C:\Tools. The sweep fires on all three held builds (`chisel.exe`, `chisel6.exe`, `chisel_linux`). The first version used a count condition the text fixture cannot meet; I simplified it. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Endpoint AV and EDR file scan of Windows and Linux hosts, and egress review where chisel is not an approved tool.
**Basis:** The three Go build-info blobs in the implant analysis (upstream v1.12.0, v1.11.5 and a 2024 commit, all `vcs.modified=false`).

```yara
rule HKTL_GEN_INV2026084_Chisel_GoTunnel_UpstreamBuild {
   meta:
      description = "Detects an unmodified upstream build of the chisel TCP-over-HTTP tunnel (jpillora/chisel), for Windows or Linux, by its module path, its WebSocket sub-protocol string and its command-line help text"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/"
      date = "2026-11-16"
      hash1 = "ca5f8e5247f1a044b8be45ef03187726b9af3ac30fd93fb5bb54144e34ed3738"
      hash2 = "fd4e45f26bbaa0a2fc904fd9e6cb4e5fcfca9f25"
      hash3 = "af70e9375b692630768294b98e272a37"
      family = "Chisel"
      id = "65297bea-5445-5467-8b18-bea4ac5b1e72"
   strings:
      $mod = "github.com/jpillora/chisel" ascii
      $proto = "chisel-v3" ascii
      $help = "--fingerprint" ascii
      $h2 = "chisel server" ascii
   condition:
      (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
      filesize < 30MB and
      $mod and
      $proto and
      ($help or $h2)
}
```

---

## Sigma Rules

### Detection Rules

#### Certutil Adds A Certificate To The TrustedPublisher Store From A User-Writable Path

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** partially_covered
**ATT&CK Coverage:** T1553.004 (Install Root Certificate)
**ATT&CK Note:** ATT&CK v19 places T1553.004 under Defense Impairment, so the rule carries `attack.defense-impairment`. SigmaHQ's certificate-installation rule matches only the `root` store; I read its condition in the clone dated 2026-09-12, and it does not match TrustedPublisher.
**Confidence:** HIGH
**False Positives:** An administrator who imports a vendor code-signing certificate from a Downloads folder, and a deployment package that stages a publisher certificate in Temp before a driver install. Both are rare on a server.
**Blind Spots:** Misses a certificate added through the Windows certificate console, PowerShell `Import-Certificate` or a registry write. Misses a certificate placed in a path outside the five listed. A host without command-line auditing cannot see the arguments.
**Validation:** Operator evidence: `npcap_cert.bat` ran `certutil -addstore TrustedPublisher` on two certificates it had just fetched into `C:\Users\Public\npcap131\`. The Public path is from the script. The other four paths are my broadening to the same class and are not from the case. `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml` on the SigmaHQ clone returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run the same `certutil -addstore TrustedPublisher` from a Public or Temp folder on a test host and the rule fires; run it on a certificate in `C:\Windows\System32` and it must not (neither run made).
**Deployment:** Sysmon Event ID 1 or Security Event ID 4688 with command-line auditing, forwarded to the SIEM.
**Basis:** `npcap_cert.bat` (sha256 prefix `0763f31d`) in the script analysis, and the staging folder it creates.

```yaml
title: Certutil Adds A Certificate To The TrustedPublisher Store From A User-Writable Path
id: 545a26c4-8407-46eb-8796-b5cb9311cc0a
status: experimental
description: >-
    Detects certutil adding a certificate file to the TrustedPublisher store when the file sits in a folder any user can write, such as the Public profile, AppData, Temp or ProgramData.
    An operator did this before installing an unsigned-chain packet-capture driver on a victim host, so that the driver install would not prompt.
    The certificate files had just been fetched from the operator's server with certutil.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.defense-impairment
    - attack.t1553.004
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine, for example Sysmon Event ID 1 or Security Event ID 4688 with command line auditing enabled.'
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_add:
        CommandLine|contains|windash: '-addstore'
    selection_store:
        CommandLine|contains: 'TrustedPublisher'
    selection_path:
        CommandLine|contains:
            - '\Users\Public\'
            - '\AppData\'
            - '\Temp\'
            - '\ProgramData\'
            - '\Downloads\'
    condition: all of selection_*
falsepositives:
    - An administrator importing a vendor code-signing certificate from a Downloads folder
    - A software deployment package that stages a publisher certificate in Temp before installing a driver
level: high
```

#### Bettercap Man-In-The-Middle Modules Started From The Command Line

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1557.002 (ARP Cache Poisoning), T1040 (Network Sniffing)
**Confidence:** HIGH
**False Positives:** Authorized red-team or lab use of bettercap on a managed host. Bettercap has no routine use on a production Windows server or workstation.
**Blind Spots:** Misses a bettercap build renamed and launched with a caplet file or an interactive session, where the modules are switched on after start. Misses a host that does not log command lines. The `-eval` string is the tool's own syntax, so a renamed binary still matches the second selection.
**Validation:** Operator evidence: `bc_mitm_long.bat`, `bc_mitm_loop.bat` and `bc_passive.bat` ran `C:\Users\Public\bettercap.exe -eval` with `arp.spoof on`, `net.sniff on`, `http.proxy on` and `https.proxy on`. Resilience outcomes: `OriginalFileName` omitted because the Go binary carries no version resource; the renamed-binary gap is recorded above; no `|windash` needed for `-eval` (bettercap takes that single form); the OR group is one level deep. `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml` on the SigmaHQ clone returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: start bettercap with the held `-eval` string on a test host and the rule fires; run an unrelated tool with `-eval` and no module name and it must not (neither run made). Upstream: I grepped SigmaHQ `rules`, `rules-threat-hunting` and `rules-emerging-threats` for `bettercap` and found no file.
**Deployment:** Sysmon Event ID 1 or Security Event ID 4688 with command-line auditing.
**Basis:** Five bettercap batch files in the script analysis (`bc_mitm_long.bat`, `bc_mitm_loop.bat`, `bc_passive.bat`, `bc_recon.bat`, `bc_test.bat`) and `bettercap.exe` among the held tools.

```yaml
title: Bettercap Man-In-The-Middle Modules Started From The Command Line
id: c5662194-b2f4-4b65-b0f7-7c85dac521d3
status: experimental
description: >-
    Detects the bettercap network attack tool, either by its executable name or by an eval string on the command line that switches on its ARP spoofing, packet sniffing or HTTP and HTTPS proxy modules.
    An operator ran bettercap from the Public profile folder on a victim host with ARP spoofing against a fixed host list, then looped the same sniffing and proxy modules for hours.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
    - https://www.bettercap.org/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1557.002
    - attack.discovery
    - attack.t1040
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates Image and CommandLine, for example Sysmon Event ID 1 or Security Event ID 4688 with command line auditing enabled.'
detection:
    selection_img:
        Image|endswith: '\bettercap.exe'
    selection_eval:
        CommandLine|contains: ' -eval '
    selection_module:
        CommandLine|contains:
            - 'arp.spoof on'
            - 'net.sniff on'
            - 'http.proxy on'
            - 'https.proxy on'
    condition: selection_img or (selection_eval and selection_module)
falsepositives:
    - Authorized red-team or lab use of bettercap on a managed host
level: high
```

#### PowerShell Script Block Opens A Raw TCP Stream And Runs Each Received Command With Iex

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** partially_covered
**ATT&CK Coverage:** T1059.001 (PowerShell), T1095 (Non-Application Layer Protocol)
**Confidence:** HIGH
**False Positives:** A hand-written network diagnostic script that evaluates what a trusted internal service returns. A script that opens a TCPClient, reads the stream, evaluates the text and returns the output is the shape of a reverse shell, and I know of no routine administration script of that shape.
**Blind Spots:** Misses a reverse shell that uses `[Net.Sockets.TcpClient]::new` split across statements the script block log breaks apart, one that decodes the command before evaluation without `iex` or `Invoke-Expression`, and a host without script block logging. The condition looks for the strings in one block.
**Validation:** Operator evidence: `r.ps1` loops on a TCPClient to a fixed operator endpoint, sends a banner, evaluates each received command with iex and returns the output with a prompt, and retries every three seconds. `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml` on the SigmaHQ clone returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run a script of that shape on a test host with script block logging and the rule fires on the 4104 event; a script that opens a TCPClient only to test a port must not (neither run made). Upstream: SigmaHQ's `proc_creation_win_powershell_reverse_shell_connection` matches the same pattern in a process command line; I found no script-block rule for it in the clone.
**Deployment:** PowerShell Operational log Event ID 4104 forwarded to the SIEM.
**Basis:** `r.ps1` (sha256 prefix `40691f99`) in the script analysis.

```yaml
title: PowerShell Script Block Opens A Raw TCP Stream And Runs Each Received Command With Iex
id: 5e004b76-d0b4-4626-a14b-1f0bf589a881
status: experimental
description: >-
    Detects a PowerShell script block that opens a TCPClient, reads from its stream and runs what it reads with iex or Invoke-Expression, returning the output through Out-String.
    This is the shape of a hand-written reverse shell. An operator served one from its open directory that connected out to the operator's server on a fixed port and retried every three seconds.
    SigmaHQ already matches the same pattern in a process command line; this rule matches the script block, which covers a script run from a file.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.execution
    - attack.command-and-control
    - attack.t1059.001
    - attack.t1095
    - stp.3
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell script block logging (Event ID 4104) to be enabled.'
detection:
    selection_tcp:
        ScriptBlockText|contains|all:
            - 'Net.Sockets.TCPClient'
            - '.GetStream('
            - '.Read('
            - 'Out-String'
    selection_exec:
        ScriptBlockText|contains:
            - 'iex '
            - 'Invoke-Expression'
    condition: all of selection_*
falsepositives:
    - A hand-written network diagnostic script that evaluates what a trusted internal service returns
level: high
```

### Hunting Rules

#### Registry Hive Copies Written To A Public Profile Hives Folder

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1003.002 (Security Account Manager)
**Confidence:** HIGH
**False Positives:** A forensic or backup job that saves registry hives to a folder with these names. A person who copies the SAM file for a legitimate recovery into the Public profile.
**Blind Spots:** The folder and file names are the operator's, so a renamed folder passes. The process-creation side (`reg save`, `esentutl /vss`) is already covered upstream and is not repeated here. A host without file-creation logging cannot see it.
**Validation:** Operator evidence: `dump2.ps1` saved `hklm\sam`, `hklm\system` and `hklm\security` to `C:\Users\Public\hives\*.save` and `dump3.ps1` copied the same three hives from a volume shadow copy into the same folder with esentutl; `dl.rc` then downloaded them over the Meterpreter session. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run `reg save hklm\sam C:\Users\Public\hives\sam.save` on a test host with Sysmon Event ID 11 and the rule fires; a save to a backup volume must not (neither run made).
**Deployment:** Sysmon Event ID 11 or an EDR file-creation feed.
**Basis:** `dump2.ps1`, `dump3.ps1`, `dump2.rc`, `dump3.rc` and `dl.rc` in the script analysis.

```yaml
title: Registry Hive Copies Written To A Public Profile Hives Folder
id: 95d37ac2-b5be-4ac2-93f6-380da21ec2f2
status: experimental
description: >-
    Detects a SAM, SYSTEM or SECURITY registry hive copy written to a folder named hives under the Public profile, or a file with one of the sam.save, system.save or security.save names the operator's script used.
    An operator saved the three hives on a victim server with reg save and again with esentutl from a volume shadow copy, then downloaded them over its Meterpreter session.
    The folder name and the .save names are operator choices, so a renamed folder passes; process-creation rules for reg save and esentutl cover the command itself.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.credential-access
    - attack.t1003.002
    - stp.1
logsource:
    category: file_event
    product: windows
    definition: 'Requires file creation logging, for example Sysmon Event ID 11.'
detection:
    selection_folder:
        TargetFilename|contains: '\Users\Public\hives\'
        TargetFilename|endswith:
            - '\SAM'
            - '\SYSTEM'
            - '\SECURITY'
            - '.save'
    selection_names:
        TargetFilename|endswith:
            - '\sam.save'
            - '\system.save'
            - '\security.save'
    condition: 1 of selection_*
falsepositives:
    - A forensic or backup job that saves registry hives to a folder with these names
level: medium
```

#### Inveigh Capture Files Created In A Public Profile Folder

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
**Confidence:** HIGH
**False Positives:** A security assessment run from the Public profile with the tool in a folder of this name.
**Blind Spots:** The folder name is the operator's. SigmaHQ's Inveigh artefact rule matches the tool's default file names (`Inveigh-Log.txt` and the others); the operator's log is named `Microsoft-Log.txt`, so that rule would not match this operator's log, but I did not replay either rule. A host without file-creation logging cannot see it.
**Validation:** Operator evidence: `check.rc` reads `C:\Users\Public\inveigh\Microsoft-Log.txt` on a victim session for NTLMv2, basic-authentication and cleartext lines, and `inveigh-hashes.txt` holds 19 capture lines from one victim host on 2026-11-05. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: create a file under `C:\Users\Public\inveigh\` on a test host with Sysmon Event ID 11 and the rule fires; an unrelated Public file must not (neither run made).
**Deployment:** Sysmon Event ID 11 or an EDR file-creation feed.
**Basis:** `check.rc` (sha256 prefix `cc01dce1`) in the script analysis, and the capture timeline in the timeline.

```yaml
title: Inveigh Capture Files Created In A Public Profile Folder
id: 467a380b-fdde-4dc2-b3a5-4f9db7b0893a
status: experimental
description: >-
    Detects files created in a folder named inveigh under the Public profile, including the log file the operator renamed to Microsoft-Log.txt.
    An operator ran the Inveigh LLMNR, NBNS and SMB capture tool from that folder on a victim host and kept a poller on its own server watching the hash file for new captures.
    The folder and file names are operator choices.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
    - https://github.com/Kevin-Robertson/Inveigh
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1557.001
    - stp.1
logsource:
    category: file_event
    product: windows
    definition: 'Requires file creation logging, for example Sysmon Event ID 11.'
detection:
    selection:
        TargetFilename|contains: '\Users\Public\inveigh\'
    condition: selection
falsepositives:
    - A security assessment run from the Public profile with the tool in a folder of this name
level: medium
```

#### PowerShell Script Block Enumerates Admin Accounts SPN Accounts And Privileged Groups Over LDAP

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1087.002 (Domain Account), T1069.002 (Domain Groups)
**Confidence:** MODERATE
**False Positives:** A directory hygiene or audit script run by the identity team, and tools such as ADRecon that run the same queries. An authorized assessment.
**Blind Spots:** Misses an enumeration done through the ActiveDirectory module, ADSI with other filters or a compiled tool. Script block logging splits a long script into several events, so the three strings can fall in different events.
**Validation:** Operator evidence: `adenum.ps1` uses `DirectorySearcher` to list the members of Domain Admins, Enterprise Admins and the built-in Administrators, then the `adminCount=1` accounts, the accounts with `servicePrincipalName=*` and the domain controller computer accounts, and writes `C:\Windows\Temp\adenum.txt`. The script embeds a directory account and its password in plain text; neither is used in any rule. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run the three filters through `DirectorySearcher` on a test host and the rule fires on the 4104 event; one filter alone must not (neither run made).
**Deployment:** PowerShell Operational log Event ID 4104 forwarded to the SIEM.
**Basis:** `adenum.ps1`, `adenum.bat` and `adenum.rc` in the script analysis.

```yaml
title: PowerShell Script Block Enumerates Admin Accounts SPN Accounts And Privileged Groups Over LDAP
id: ec8aa95d-1e65-4d16-ad23-76932ee39223
status: experimental
description: >-
    Detects a PowerShell script block that uses DirectorySearcher to list accounts with adminCount=1 and accounts that carry a servicePrincipalName, the two lists a Kerberoasting and privilege-mapping pass starts from.
    An operator ran a script of this shape against a victim domain controller to dump the members of Domain Admins, Enterprise Admins and the built-in Administrators group, the adminCount accounts, the SPN accounts and the domain controller computer accounts.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.t1069.002
    - stp.2
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell script block logging (Event ID 4104) to be enabled.'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'DirectorySearcher'
            - 'adminCount=1'
            - 'servicePrincipalName=*'
    condition: selection
falsepositives:
    - A directory hygiene or audit script run by the identity team
level: medium
```

#### PowerShell Script Block Audits DACLs For Write And Control Rights On Domain Objects

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1069.002 (Domain Groups)
**Confidence:** MODERATE
**False Positives:** An identity or security team script that reviews delegated permissions on privileged objects.
**Blind Spots:** Misses a DACL audit written with other cmdlets or run from a compiled tool, and one logged in separate events.
**Validation:** Operator evidence: `acl_ps.ps1` reads the access rules of 13 directory objects (the domain root, Domain Admins, Enterprise Admins, krbtgt, the built-in Administrators, Domain Controllers, Server, Backup and Account Operators, DnsAdmins and Group Policy Creator Owners) and lists the Allow rules that carry GenericAll, GenericWrite, WriteDacl, WriteOwner and related rights, writing `C:\Windows\Temp\acl.txt` and `acldone.txt`. The script holds a hard-coded directory account and password; neither is used. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run a script that filters `GetAccessRules` output for those rights on a test host and the rule fires (not run).
**Deployment:** PowerShell Operational log Event ID 4104 forwarded to the SIEM.
**Basis:** `acl_ps.ps1` (sha256 prefix `7e93eb88`) in the script analysis.

```yaml
title: PowerShell Script Block Audits DACLs For Write And Control Rights On Domain Objects
id: 14f00548-0029-4192-ad72-91b79017f6ef
status: experimental
description: >-
    Detects a PowerShell script block that reads the access rules of directory objects and filters them for dangerous Active Directory rights such as GenericAll, WriteDacl and WriteOwner.
    An operator ran a script of this shape against a victim domain controller for 13 objects, among them the domain root, Domain Admins, Enterprise Admins, krbtgt and Backup Operators, looking for an account that could change them.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.discovery
    - attack.t1069.002
    - stp.2
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell script block logging (Event ID 4104) to be enabled.'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'GetAccessRules'
            - 'ActiveDirectoryRights]::GenericAll'
            - 'ActiveDirectoryRights]::WriteDacl'
            - 'ActiveDirectoryRights]::WriteOwner'
    condition: selection
falsepositives:
    - An identity or security team script that reviews delegated permissions on privileged objects
level: medium
```

#### PowerShell Script Block Surveys Autologon Cmdkey And Windows Vault Credentials Together

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1552.001 (Credentials In Files), T1555 (Credentials from Password Stores)
**Confidence:** MODERATE
**False Positives:** A support or migration script that inventories saved credentials on a workstation.
**Blind Spots:** The three strings must land in one script block, and script block logging splits a script of this length across events, so a real run can miss the rule. Misses a survey that uses other commands.
**Validation:** Operator evidence: `hunt.ps1` reads the Winlogon `DefaultPassword`, runs `cmdkey /list` and `vaultcmd /list`, then widens to non-system services, scheduled-task run-as accounts, unattend files, Oracle `tnsnames.ora`, environment variables, PowerShell history, browser Login Data paths and web-root secrets, writing `C:\Windows\Temp\hunt_out.txt`. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run the three commands in one script on a test host and the rule fires on the event that holds them; a script that runs only `cmdkey /list` must not (neither run made).
**Deployment:** PowerShell Operational log Event ID 4104 forwarded to the SIEM.
**Basis:** `hunt.ps1`, `hunt2.ps1` to `hunt5.ps1`, `confhunt2.ps1` and the encoded `.rc` copies in the script analysis.

```yaml
title: PowerShell Script Block Surveys Autologon Cmdkey And Windows Vault Credentials Together
id: e8ade874-68cc-499f-a987-267aaf9180bf
status: experimental
description: >-
    Detects a PowerShell script block that reads the Winlogon DefaultPassword value, lists saved credentials with cmdkey /list and lists the Windows Vault with vaultcmd /list in one script.
    An operator ran a host survey of this shape on victim servers, then widened it to web-root configuration files, PowerShell history and browser Login Data paths.
    Script block logging splits a long script into several events, so the three parts can land in different events.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.credential-access
    - attack.t1552.001
    - attack.t1555
    - stp.2
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell script block logging (Event ID 4104) to be enabled.'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'DefaultPassword'
            - 'cmdkey /list'
            - 'vaultcmd /list'
    condition: selection
falsepositives:
    - A support or migration script that inventories saved credentials on a workstation
level: medium
```

#### PowerShell Script Block Polls An HTTP Endpoint For Commands Runs Them And Posts The Base64 Output

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1071.001 (Web Protocols)
**Confidence:** MODERATE
**False Positives:** A hand-written monitoring script that runs a command supplied by an internal management endpoint.
**Blind Spots:** Misses a loop that uses `Invoke-WebRequest` for the poll, `iex` for the evaluation or a different encoding, and a host without script block logging.
**Validation:** Operator evidence: `loop.ps1` polls a path on the operator's server every five seconds, runs any answer other than `none` with `Invoke-Expression`, base64-encodes the output and posts it to a second path. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run a script of that shape against a lab web server and the rule fires (not run). The same loop's network side is covered by the two Suricata Hunting rules on its two paths.
**Deployment:** PowerShell Operational log Event ID 4104 forwarded to the SIEM.
**Basis:** `loop.ps1` (sha256 prefix `bec9fef3`) in the script analysis.

```yaml
title: PowerShell Script Block Polls An HTTP Endpoint For Commands Runs Them And Posts The Base64 Output
id: a9f23659-1ed8-4c0a-a605-ef34d846f32e
status: experimental
description: >-
    Detects a PowerShell script block that fetches text with Invoke-RestMethod, runs it with Invoke-Expression, base64-encodes the result and sends it back with an Invoke-WebRequest POST.
    An operator served a loop of this shape from its open directory: it polled a path on the operator's server every five seconds and posted the result to a second path.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.execution
    - attack.command-and-control
    - attack.t1059.001
    - attack.t1071.001
    - stp.3
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell script block logging (Event ID 4104) to be enabled.'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Invoke-RestMethod'
            - 'Invoke-Expression'
            - 'ToBase64String'
            - 'Invoke-WebRequest'
            - '-Method POST'
    condition: selection
falsepositives:
    - A hand-written monitoring script that runs a command supplied by an internal management endpoint
level: medium
```

#### Operator Recon Output Files Created In Windows Temp

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1087.002 (Domain Account), T1005 (Data from Local System)
**Confidence:** HIGH
**False Positives:** A local script that happens to write one of these names to Windows Temp.
**Blind Spots:** The names are the operator's, so a renamed script escapes. The rule is a scoping lead, and the five names would be a thin signal alone. A host without file-creation logging cannot see it.
**Validation:** Operator evidence: `adenum.ps1`, `acl_ps.ps1` and `hunt.ps1` write `adenum.txt`, `acl.txt` with `acldone.txt` and `hunt_out.txt`, and `hunt2.ps1` writes `hunt2.txt`, all under `C:\Windows\Temp\`. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run any of the scripts on a test host with Sysmon Event ID 11 and the rule fires (not run). Atomic file names would normally go to the feed; the Hunting tier is used because the names also show which script ran.
**Deployment:** Sysmon Event ID 11 or an EDR file-creation feed.
**Basis:** The `files_created` column of the script analysis for `adenum.ps1`, `acl_ps.ps1`, `hunt.ps1` and `hunt2.ps1`.

```yaml
title: Operator Recon Output Files Created In Windows Temp
id: a4775446-948c-4ebc-83b9-f9d21ce69310
status: experimental
description: >-
    Detects creation of the output files the operator's recon scripts wrote under the Windows Temp folder on victim hosts: adenum.txt, acl.txt, acldone.txt, hunt_out.txt and hunt2.txt.
    The names are operator choices and a renamed script passes; the rule is a lead for scoping, not a durable signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.discovery
    - attack.collection
    - attack.t1087.002
    - attack.t1005
    - stp.1
logsource:
    category: file_event
    product: windows
    definition: 'Requires file creation logging, for example Sysmon Event ID 11.'
detection:
    selection:
        TargetFilename|endswith:
            - '\Windows\Temp\adenum.txt'
            - '\Windows\Temp\acl.txt'
            - '\Windows\Temp\acldone.txt'
            - '\Windows\Temp\hunt_out.txt'
            - '\Windows\Temp\hunt2.txt'
    condition: selection
falsepositives:
    - A local script that happens to write one of these file names to Windows Temp
level: medium
```

#### Pnputil Installs A Driver Package From A User-Writable Path

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1543.003 (Windows Service)
**ATT&CK Note:** ATT&CK has no Windows technique for installing a kernel driver as such. I tagged the service the driver creates, T1543.003, and the tag is a judgement.
**Confidence:** MODERATE
**False Positives:** A vendor driver installer that unpacks its package to Temp and installs it with pnputil. Printer and peripheral installers do this routinely.
**Blind Spots:** SigmaHQ already matches pnputil driver installs at medium without a path condition, so this is a narrower rule and not new coverage. Misses an install through DISM, the Setup API or a service created directly. A host without command-line auditing cannot see the arguments.
**Validation:** Operator evidence: `npcap_install.bat` and `npcap_cert.bat` ran `pnputil -i -a C:\Users\Public\npcap131\npcap.inf` after fetching a packet-capture driver package from the operator's server, so that bettercap could capture on the victim's network card. Only the Public path is from the case; the other four are my broadening. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: run `pnputil -i -a` on an INF in a Public or Temp folder on a test host and the rule fires (not run); an INF in `C:\Windows\INF` must not.
**Deployment:** Sysmon Event ID 1 or Security Event ID 4688 with command-line auditing.
**Basis:** `npcap_install.bat` (sha256 prefix `f45d4f19`) and `npcap_cert.bat` in the script analysis.

```yaml
title: Pnputil Installs A Driver Package From A User-Writable Path
id: 7f1f3656-d54b-4f1e-9959-77bb89bc2aba
status: experimental
description: >-
    Detects pnputil adding or installing a driver package whose INF sits in a folder any user can write, such as the Public profile, AppData, Temp or ProgramData.
    An operator staged a packet-capture driver package in a folder under the Public profile on a victim host and installed it with pnputil -i -a, so that bettercap could capture on the host's network card.
    SigmaHQ already matches pnputil driver installs in general at medium; this rule narrows to a staging path.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
    - stp.2
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates Image and CommandLine, for example Sysmon Event ID 1 or Security Event ID 4688 with command line auditing enabled.'
detection:
    selection_img:
        - Image|endswith: '\pnputil.exe'
        - OriginalFileName: 'pnputil.exe'
    selection_install:
        CommandLine|contains:
            - ' -i '
            - ' /install '
            - ' -a '
            - ' /add-driver '
    selection_path:
        CommandLine|contains:
            - '\Users\Public\'
            - '\AppData\'
            - '\Temp\'
            - '\ProgramData\'
            - '\Downloads\'
    condition: all of selection_*
falsepositives:
    - A vendor driver installer that unpacks its package to Temp and installs it with pnputil
level: medium
```

#### Driver Package Files Created In The Public Profile

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** A vendor support tool that unpacks a driver package to the Public profile before an install.
**Blind Spots:** Misses a package unpacked elsewhere. Only the Public profile and the three extensions come from the case; widening the folder list would add noise.
**Validation:** Operator evidence: `npcap_install.bat` fetched `npcap.sys`, `npcap.inf` and `npcap.cat` with `certutil -urlcache` into `C:\Users\Public\npcap131\`. `sigma check` with SigmaHQ's own validation config returned 0 errors, 0 condition errors and 0 issues for the twelve Sigma rules together. The rule was not replayed against SigmaHQ's benign event baseline or a lab host: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED. Test: download an INF into the Public profile on a test host and the rule fires (not run); an install under `C:\Windows\System32\drivers` must not.
**Deployment:** Sysmon Event ID 11 or an EDR file-creation feed.
**Basis:** `npcap_install.bat` in the script analysis and the Npcap package rows in the inventory.

```yaml
title: Driver Package Files Created In The Public Profile
id: 87fa8058-2a19-4bd0-b60b-a15dbd651756
status: experimental
description: >-
    Detects creation of a .sys, .inf or .cat file under the Public profile, where an operator staged a downloaded packet-capture driver package (npcap.sys, npcap.inf, npcap.cat) before installing it on a victim host.
    Ordinary driver installs write to the system driver folders and the driver store, not to the Public profile.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/
author: The Hunters Ledger
date: 2026-11-16
tags:
    - attack.command-and-control
    - attack.t1105
    - stp.2
logsource:
    category: file_event
    product: windows
    definition: 'Requires file creation logging, for example Sysmon Event ID 11.'
detection:
    selection:
        TargetFilename|contains: '\Users\Public\'
        TargetFilename|endswith:
            - '.sys'
            - '.inf'
            - '.cat'
    condition: selection
falsepositives:
    - A vendor support tool that unpacks a driver package to the Public profile before an install
level: medium
```

---

## Suricata Signatures

All six rules were accepted by `suricata -T` on the firewall sensor in one run. The case holds no capture of the operator's traffic, so none has been replayed or seen to fire: NOT CHECKED. Suricata upstream coverage is NOT CHECKED for every rule. The operator's address, its listener ports (31337, 8000, 8888, 8445, 5555 and the stager ports) and the Sliver certificate values are atomics and go to the indicator feed; none is a rule here.

### Detection Rules

#### THL DETECT INV-2026-084 NimPlant C2 Server Banner In HTTP Response Header (C2 Server Indicator)

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**ATT&CK Note:** A listener answering with this banner sits on the operator's host. Beyond the host, the rule finds any server that sends the banner, which is what makes it more durable than the address.
**Confidence:** MODERATE
**False Positives:** A research honeypot or a defender's own NimPlant test server that answers with this header. I know of no legitimate service that names itself this way.
**Blind Spots:** Sees plaintext HTTP only. A NimPlant server behind TLS, behind a reverse proxy that rewrites the `Server` header, or with the header edited in its source passes. The banner was seen once, on one port of the case host, in a third-party scan; I did not reproduce it.
**Validation:** The banner comes from VirusTotal's report of `http://169.58.165.63:8445/` (first analysed 2026-11-16 about 08:15Z, HTTP 404, a 23-byte JSON body), recorded in the infrastructure analysis section 2 pivot 3. I did not confirm that the header is NimPlant's default or that the port is open now. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Egress sensor on client-to-internet HTTP, port-agnostic, and on any sensor in front of a server an intruder could reach back to.
**Basis:** the infrastructure analysis section 2 (pivot 3) and section 4 (the 8445 row).

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"THL DETECT INV-2026-084 NimPlant C2 Server Banner In HTTP Response Header (C2 Server Indicator)"; flow:established,to_client; http.header; content:"Server|3a 20|NimPlant C2 Server"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

### Hunting Rules

#### THL HUNT INV-2026-084 PowerShell HTTP Tasking Loop Command Poll (Operator Beacon Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**False Positives:** An internal service that happens to expose a `/t/cmd` path and is polled by a client. The request carries no other anchor, so the false-positive rate is not measured.
**Blind Spots:** The path is the operator's choice. The rule is an HTTP rule, so TLS hides it; the operator's `loop.ps1` used plain HTTP to its own server.
**Validation:** `loop.ps1` polls `http://<operator server>/t/cmd` every five seconds and posts the result to `/o/out`. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Egress sensor on client-to-internet HTTP, port-agnostic.
**Basis:** `loop.ps1` in the script analysis.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-084 PowerShell HTTP Tasking Loop Command Poll (Operator Beacon Indicator)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/t/cmd"; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

#### THL HUNT INV-2026-084 PowerShell HTTP Tasking Loop Base64 Result Post (Operator Beacon Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**False Positives:** An internal service with an `/o/out` upload path. Same limit as the poll rule.
**Blind Spots:** The path is the operator's choice, and TLS hides it.
**Validation:** The post half of the same loop. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Egress sensor on client-to-internet HTTP, port-agnostic.
**Basis:** `loop.ps1` in the script analysis.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-084 PowerShell HTTP Tasking Loop Base64 Result Post (Operator Beacon Indicator)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/o/out"; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

#### THL HUNT INV-2026-084 Operator Front Domain cytomate.xyz DNS Query (C2 Front Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** A user who visits the domain out of curiosity, and a security researcher resolving it. A defender should not block the Cloudflare addresses it resolves to, which are shared.
**Blind Spots:** Matches any name ending in `cytomate.xyz`. The domain is registered through a privacy service and sits behind Cloudflare, so the operator can move to a new name in minutes. The same indicator is in the indicator feed.
**Validation:** `cytomate.xyz` and `breach.cytomate.xyz` front the case host: the host serves a Cloudflare Origin Certificate for `cytomate.xyz` and `*.cytomate.xyz`, its port 443 page is titled "Cytomate Cloud - Maintenance", and Linux Sliver samples dial `breach.cytomate.xyz` (the infrastructure analysis section 3, HIGH that the domain is operator-controlled). The name is also that of a Doha security vendor; the case treats the lookalike as HIGH and the vendor's non-involvement as MODERATE. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** DNS sensor or resolver log.
**Basis:** the infrastructure analysis sections 2 and 3, and the vendor-lookalike check.

```suricata
alert dns $HOME_NET any -> any any (msg:"THL HUNT INV-2026-084 Operator Front Domain cytomate.xyz DNS Query (C2 Front Indicator)"; dns.query; content:"cytomate.xyz"; nocase; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

#### THL HUNT INV-2026-084 Operator Front Domain cytomate.xyz TLS SNI (C2 Front Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** A user who visits the domain, and a researcher. The Cloudflare addresses are shared, so block by name and never by address.
**Blind Spots:** Does not see an Encrypted Client Hello connection, and the operator can change the name. Same indicator as the DNS rule.
**Validation:** Same evidence as the DNS rule. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** TLS sensor on egress.
**Basis:** the infrastructure analysis sections 2 and 3.

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-084 Operator Front Domain cytomate.xyz TLS SNI (C2 Front Indicator)"; flow:established,to_server; tls.sni; content:"cytomate.xyz"; nocase; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

#### THL HUNT INV-2026-084 Npcap Driver Package Fetch From Operator Staging Path (Tool Staging Indicator)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** A deployment that serves its own copy of Npcap from a path starting `/npcap131/`. The rule anchors on the start of the path.
**Blind Spots:** The path is the operator's. A fetch over TLS is invisible. The operator's address is the better pivot and is in the indicator feed.
**Validation:** `npcap_install.bat` and `npcap_cert.bat` fetch `npcap.sys`, `npcap.inf`, `npcap.cat`, `npcap_wfp.inf`, `wpcap.dll`, `Packet.dll` and two certificate files from `/npcap131/` on the operator's port 8444 with `certutil -urlcache`. `suricata -T` on the firewall sensor accepted all six rules in one run. No capture of the operator's traffic exists in the case, so the rule has not been seen to fire: NOT CHECKED against a replay. Upstream coverage: NOT CHECKED. The page-level validator (yarac, sigma check and convert, suricata -T, prior-art and reference-URL checks) returned PASS with 0 errors and 6 warnings, all Suricata prevalence checks marked NOT CHECKED.
**Deployment:** Egress sensor on client-to-internet HTTP, port-agnostic.
**Basis:** `npcap_install.bat` and `npcap_cert.bat` in the script analysis.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-084 Npcap Driver Package Fetch From Operator Staging Path (Tool Staging Indicator)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/npcap131/"; startswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-169-58-165-63-ad-intrusion-vs-pakistani-university-20261116-detections/; classtype:trojan-activity; sid:1000006; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-16;)
```

---

## Coverage Gaps

This file carries 23 rules. The nearest comparable cases in the same corpus carry 24 rules (INV-2026-080) and 25 rules (INV-2026-083), and the two closest Sliver cases carry 12 and 19, against a corpus median of 12 rules per file across 64 files, so this file is not thin for its kind. Every behaviour I left without a rule is listed here with its reason.

### Atomics routed to the indicator feed, not written as rules

A rule whose only discriminator is one of these would stop detecting anything the day the value changes, so each belongs in the indicator feed for this case.

- **The operator's address and listeners.** `169.58.165.63` with 31337 (Sliver mTLS), 8000 (Sliver HTTPS), 8888 and 8445 (NimPlant banner), 5555 (the stageless Meterpreter loader), 4444, 4446, 4447 and 8444 (the stagers), 9001 (the raw-shell listener) and the HTTP paths. A rule on any one of them is an IP match. The two domain rules above are the exception: a domain-only signature may be written at Hunting, and the same names are also in the feed.
- **Sliver certificate and key values.** The mTLS certificate authority (sha256 `59eb3f044d9d2811c2664e9cd86bc7d1d39042978125bf043394647c7d343539`, subject key identifier `b8fdca9d56f76de964eca3a4d058abb0f4a7418f`), the minisign key identifier `20F1D34CD5D8E2ED` and the five implant certificate names (`spweb1` and four others). The five mTLS builds carry the same authority and the minisign key sits in seven of the eight builds, so each value identifies the one server from any capture. Sliver backdates a certificate's start date by a random 0 to 364 days, so no date is read from them.
- **The Meterpreter payload UUID** `3ae7126587cf73f3cef0cff2a41a799c` in the stageless loader's configuration, and the four-byte key that XORs it.
- **Sample hashes.** The eight Sliver builds, the five stagers, the stageless loader and the three chisel builds. The YARA rules name each family without needing a hash, and the feed holds the hashes.
- **Hash-only drivers and killers.** Six drivers and six user-mode killer or cleaner programs (`killav`, `kclean`, `killloop` and their variants) were listed by the operator's directory and not held. Four of the six drivers match LOLDrivers by hash (`GoFly64.sys`, `MonProcessEX.sys`, the process-explorer driver renamed `p152.sys`, and `xkpsm.sys`). I found no event showing any was loaded on a victim host, so a driver-load rule would be a hash match, which SigmaHQ's LOLDrivers rule already is.

### Behaviour observed or prepared, but not covered by a rule

- **Registry-hive dumping by command.** `reg save` of the SAM, SYSTEM and SECURITY hives and an `esentutl /y /vss` copy of the same three from the config folder are both in the operator's scripts. SigmaHQ's `proc_creation_win_reg_dumping_sensitive_hives` and `proc_creation_win_esentutl_sensitive_file_copy` already match these command lines; I read both conditions in the clone dated 2026-09-12 and did not repeat them. The one rule above is on the operator's output folder.
- **The password spray, the account-by-account SMB credential tests and the AS-REP roast.** The operator's logs show a spray of about 3,800 account names with one password, a threaded SMB test of user and password pairs that kept 121 valid lines, and a Kerberos probe of 110 names. They ran from the operator's side and the case holds no domain-controller log, so I have no event to derive a rule from. INV-2026-083's detection file already carries correlation rules for many failed logons and many unknown accounts from one source, and I did not copy them. The thresholds there are starting values, and this case's scale (about 3,800 accounts) would only lift them.
- **Zero-credential Netlogon probes.** `zt_np.py` makes up to 2,000 attempts against a controller, and the result in the case is a probe, not a success. I have no evidence of the event it leaves on a domain controller, so no rule.
- **The VMware ESXi OpenSLP exploit.** `cve.py` is a public-class exploit for CVE-2021-21974 with libc offsets for one ESXi build, and the case shows it staged, with no attempt against an ESXi or vCenter host. A Suricata rule would key on the exploit's own packet bytes, which I did not derive. Upstream coverage for that CVE is NOT CHECKED.
- **Pass-the-hash execution.** `Invoke-SMBExec.ps1` is the public PowerSploit function, held as a tool, and nothing shows it run. A rule on its function name would match every copy.
- **The Meterpreter session's child processes.** The resource scripts start PowerShell through `execute -o -t` with `-NoProfile -ExecutionPolicy Bypass -EncodedCommand`. The case holds no process tree, so I do not know the parent image, and a command-line rule on those flags alone is the generic one SigmaHQ already ships.
- **The Sliver traffic.** No capture of the mTLS or HTTPS sessions exists, so I have no TLS client fingerprint, no HTTP profile for `vmupd.exe` and no beacon interval (integer constants, not recovered). A TLS-fingerprint rule would be Detection-eligible and would survive a change of server. It needs one lab capture of an implant handshake.
- **The NimPlant implant.** Only the server's banner is known. No NimPlant binary is held, so there is no implant rule.
- **The TCP pivot parent.** `spadc1.exe` dials a victim-internal address on tcp/9898, so a listener on that port exists inside the victim network. A rule on a bare port is an un-anchored match; the finding goes to the victim notification as a hunt.
- **The packet-capture driver itself.** The Npcap package is genuine and signed. The two Sigma rules on its staging path and the certificate import cover the operator's use of it; a rule on the package would match every legitimate Npcap install.
- **The `:8091` directory.** Its 157 names are known from a listing and no bytes were obtainable, so nothing in it has a rule.
- **Sigma baseline.** None of the twelve Sigma rules was run through SigmaHQ's check-baseline replay of benign Windows events. That run is part of any upstream submission and is NOT CHECKED here.

### What would let me write more

- A lab capture of one Sliver mTLS handshake and one HTTPS session, for a TLS-fingerprint rule, an HTTP-profile rule for `vmupd.exe` and a beacon interval.
- The victim's domain-controller and server logs for 2026-11-05 onward, which would give the spray and Kerberos rules measured thresholds, show the parent of the Meterpreter children, and say which of the Sigma rules actually fired.
- A NimPlant implant sample from the 8445 listener.
- A second operator server presenting the same Sliver certificate authority, which would move the certificate-based indicators toward a rule.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
