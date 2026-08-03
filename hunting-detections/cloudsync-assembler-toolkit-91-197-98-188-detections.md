---
title: "Detection Rules: CloudSync Assembler Toolkit"
date: '2026-08-03'
layout: post
permalink: /hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
hide: true
unlisted: true
---

**Campaign:** CloudSync-Assembler-Toolkit-91.197.98.188
**Date:** 2026-08-03
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/cloudsync-assembler-toolkit-91-197-98-188/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 1 | T1046, T1055, T1620, T1027, T1140, T1136.002, T1098, T1105, T1091, T1071, T1571, T1090.003, T1036.005 | 14 |
| Sigma | 17 | 1 | T1136.001, T1543.003, T1090.003, T1036.005, T1127.001, T1055, T1562.001, T1053.005, T1070.004, T1136.002, T1098.007, T1564.002, T1505.003, T1059.001, T1219.002, T1090, T1547.001 | 3 |
| Suricata | 4 | 0 | T1071, T1571, T1071.001 | 2 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, so they are safe to alert on. *Hunting rules* are broader, intended for scoping and threat-hunting, so expect to review the hits.

This is a five-component assembled toolkit, not a single malware family, so coverage is organized by component below (CloudSync, the SvchostPayload/.NET RAT chain, the ab.exe deployment orchestrator, the ct.bat deployment stub, and SentinelStealer as a sourced, separately-tiered commodity stealer). Two case-specific cautions bind every rule in this file: the operator binaries statically link Tor and use the MinGW-w64 CRT, which produces a documented class of stock-component false positives (subtracted throughout, see Coverage Gaps for what was deliberately excluded), and CloudSync itself ships in at least two build generations that differ in C2 message terminator and panel feature set, both of which are covered explicitly rather than assumed to be interchangeable.

Every rule below cleared its authoring validation gate before being written here: all 18 Sigma rules pass `sigma check` (0 errors, 0 issues) and `yamllint` against the SigmaHQ validator set; all 7 YARA rules compile clean (0 errors, 0 warnings) under `yarac`; all 4 Suricata rules pass `suricata -T` against the production rule-parsing engine.

---

## Multi-Family Organization

Each rule-type section below is organized **type → tier → component**. Within each tier subsection, rules are grouped under a bold component label:

- **CloudSync**, the operator's custom C++ Tor-hidden-service panel RAT (both build generations)
- **SvchostPayload / .NET RAT Chain**, the fileless `svhost.js` loader, the sourced Paralell injector, and the custom `SvchostPayload`/`cls.exe` .NET RAT it delivers into `MSBuild.exe`
- **Deployment Orchestrator (ab.exe)**, the post-compromise tool that drops a web shell, plants an Active Directory backdoor account, and installs AnyDesk
- **Deployment Stub (ct.bat)**, the infection stub that downloads CloudSync, bypasses AMSI, and opportunistically spreads over USB
- **SentinelStealer (Sourced, Separate Tier)**, a commodity credential/crypto-wallet stealer the operator collected and parked; not integrated into the intrusion, and never presented alongside the operator's own infrastructure

Rules covering behavior common to more than one component are labeled at the campaign level rather than duplicated.

---

## YARA Rules

### Detection Rules

**CloudSync**

#### CloudSync Tor Panel: Netscan Build

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1046 (Network Service Discovery)
**Confidence:** HIGH
**False Positives:** None known, this exact combination of panel API route and CIDR-scanner placeholder text is unique to the later CloudSync build generation
**Blind Spots:** Misses the earlier CloudSync build generation entirely (`bk.exe`/`svhost4.exe`), which does not carry a network-scanner panel tab at all, see the companion C2-protocol rule below for coverage of that generation
**Validation:** Scan the binary directly; a genuine hit requires 3 of the 5 embedded panel strings to be present in the file's resource section. A clean Windows or third-party remote-access tool installer must not fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of the implant process, scanning of any recovered staging directory

```yara
/*
   Yara Rule Set
   Identifier: CloudSync Assembler Toolkit - 91.197.98.188
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_CloudSync_TorPanel_NetscanBuild {
   meta:
      description = "Detects the later-build CloudSync Tor-panel RAT (client.exe/q.exe/s.exe) via embedded HTML/JS markup for its CIDR+port network scanner panel tab, unique to the later of two known CloudSync build generations"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "62aa8e470e60aa9fa77df6e6e63b7c253657e95d6018240b1752a9ca9fe389fa"
      family = "CloudSync"
      malware_type = "RAT"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "b14306ec-cdfb-5107-bf6f-156ea821ae75"
   strings:
      $api1 = "/api/netscan" ascii
      $html1 = "id='scan-cidr'" ascii
      $html2 = "placeholder='Target CIDR (e.g. 192.168.1.0/24)'" ascii
      $html3 = "id='netscan-output'" ascii
      $html4 = "showTab('netscan'" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 60MB and
      3 of them
}
```

#### CloudSync C2 Protocol: Dual Build Coverage

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
**Confidence:** HIGH
**False Positives:** None known, the combination of two or more of these six strings is not expected in unrelated software; the AUTO UPDATE banner and bracketed terminators are CloudSync-specific
**Blind Spots:** A future CloudSync build that changes both the terminator tokens and every field name simultaneously would evade this rule; it does not detect the protocol on the wire (see the companion Suricata rules for network-layer coverage of the same protocol)
**Validation:** Confirm on both `svhost4.exe` (uses `[C2_END]`) and `bk.exe` (uses `[END]`) that at least 2 of the 6 strings are present. A benign network utility or Tor client alone must not fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of the dropped implant process

```yara
rule RAT_CloudSync_C2Protocol_DualBuild {
   meta:
      description = "Detects CloudSync's cleartext TCP C2 registration/heartbeat protocol strings across both observed build generations, which differ in message terminator ([C2_END] vs [END]) and registration field names"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "9744c12a06b4562e175d4aeb7b8fd5c1e1877ac30222af8243eeaae16df324b0"
      family = "CloudSync"
      malware_type = "RAT"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "df292c17-07ad-5292-9f33-206ab7582bdd"
   strings:
      $autoupd = "=== AUTO UPDATE ===" ascii
      $heartbeat = "[Shares]" ascii
      $term1 = "[C2_END]" ascii
      $term2 = "[END]" ascii
      $field1 = "AnyDesk Pass:" ascii
      $field2 = "AD Pwd:" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 60MB and
      2 of them
}
```

**SvchostPayload / .NET RAT Chain**

#### Paralell Injector and SvchostPayload Type Names

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1055 (Process Injection), T1620 (Reflective Code Loading)
**Confidence:** HIGH
**False Positives:** None known, the debug PDB path fragment is a build-specific artifact, and the obfuscated member names (`VoidNexus`, `ShadowWeave`, `CrystalCore`, `UmbraGate`) are not generic .NET or Crypto Obfuscator output
**Blind Spots:** A rebuild that strips debug information or renames the obfuscated members would defeat this rule; it applies most directly to the on-disk `cls.exe` sibling build, the in-memory `Crystal-Monk.dll`/`SvchostPayload` assemblies require a memory-resident scan to reach, since they never touch disk on a victim
**Validation:** Confirm the rule fires on `cls.exe`. A generic Crypto-Obfuscator-protected .NET binary unrelated to this toolkit must not fire, since the match requires the PDB fragment or 2 of the 7 distinctive member-name strings together.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of `MSBuild.exe` process space during or after a suspected injection event

```yara
rule RAT_SvchostPayload_ParalellInjector_TypeNames {
   meta:
      description = "Detects the sourced Paralell (Blind Eagle-associated) reflective injector and the custom SvchostPayload .NET RAT via debug PDB path fragment and distinctive obfuscated/cleartext type and member names; matches the on-disk cls.exe sibling build and, when captured, in-memory dumps of Crystal-Monk.dll and SvchostPayload"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "79b6f2eb6583a83aabe590264de08c0ad1eb7e960ae9a4bdbc6ed84142ce95a9"
      hash3 = "135877ecc663ee47340a4726078234f0"
      family = "SvchostPayload"
      malware_type = "RAT"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "5d097282-dcf6-58bf-a8e8-17d97cff3ec2"
   strings:
      $pdb = "Paralell\\Paralell\\bin\\x64\\Debug\\CryptoObfuscator_Output\\Crystal-Monk.pdb" ascii
      $t1 = "SvchostPayload" ascii wide fullword
      $t2 = "BrowserCredentialRecovery" ascii fullword
      $t3 = "Crystal-Monk" ascii wide
      $t4 = "VoidNexus" ascii fullword
      $t5 = "ShadowWeave" ascii fullword
      $t6 = "CrystalCore" ascii fullword
      $t7 = "UmbraGate" ascii fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      ($pdb or 2 of ($t*))
}
```

#### svhost.js Fileless Loader: Custom Alphabet

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH
**False Positives:** None known, the 16-character custom substitution alphabet is operator-chosen and not a published or reused encoding scheme
**Blind Spots:** A recompiled loader using a different substitution alphabet and different decoder-shape strings would evade this rule; it detects the on-disk loader file only, not the payloads it decrypts in memory
**Validation:** Confirm the rule fires on `svhost.js`. A benign WSH script or an unrelated obfuscated JavaScript sample must not fire, since the alphabet string alone is the primary anchor and is not expected to appear by chance.
**Deployment:** Endpoint AV/EDR file scan, email/web gateway script scanning, scheduled-task and Startup-folder script sweeps

```yara
rule Loader_SvchostJS_CustomAlphabet {
   meta:
      description = "Detects the svhost.js WSH JScript fileless loader via its custom 16-character substitution alphabet used in a layered base16-XOR plus AES/ChaCha/permutation decoder, and the loader's distinctive function-constructor string-decode shape"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "4b115a9f745219e3f3abdea275da89f35e4ec5f3d43286e5efc58eaf8049f3f7"
      family = "SvchostPayload"
      malware_type = "Loader"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "2b39854f-a2dc-535f-824f-b28af4328b35"
   strings:
      $alpha = "5v_qoKAku06M^ZW1" ascii
      $shape1 = "(function(){})[\"constructor\"]" ascii
      $shape2 = "String.fromCharCode" ascii
   condition:
      filesize < 1MB and
      ($alpha or all of ($shape*))
}
```

**Deployment Orchestrator (ab.exe)**

#### Deployment Orchestrator Console Banners

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1136.002 (Create Account: Domain Account), T1098 (Account Manipulation)
**Confidence:** HIGH
**False Positives:** None known, the fixed console-banner sequence and the combination of `New-ADUser`/`Guest$` with German-localized privileged-group names is not expected in legitimate deployment tooling
**Blind Spots:** A recompiled orchestrator with reworded banners or a different target-locale group-name set would evade this rule; it does not fire on the AD/web-shell/AnyDesk actions themselves, see the companion Sigma rules for that behavioral coverage
**Validation:** Confirm the rule fires on `ab.exe`. A generic PowerShell AD-administration script that references `New-ADUser` alone, without the console banners or German group names, must not fire (the rule requires 3 of 10 strings together).
**Deployment:** Endpoint AV/EDR file scan, download/attachment gateway scanning

```yara
rule Loader_ABExe_DeploymentOrchestrator_Banners {
   meta:
      description = "Detects the ab.exe post-compromise deployment orchestrator via its fixed-sequence console banner strings and the German-localized Active Directory privileged-group names it targets when creating a hidden backdoor account"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "d25a3a858e28faa68ca6c624d7d19350c11ac798c346be3067307463e40aaff1"
      family = "CloudSync"
      malware_type = "Orchestrator"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "bcfebc4f-1273-566e-8121-19cd9dc91272"
   strings:
      $b1 = "Starting deployment - WebShell First" ascii wide
      $b2 = "=== WEB SHELL ===" ascii wide
      $b3 = "=== USER ===" ascii wide
      $b4 = "=== ANYDESK ===" ascii wide
      $b5 = "All tasks completed successfully!" ascii wide
      $grp1 = "Organisations-Admins" ascii wide
      $grp2 = "Schema-Admins" ascii wide
      $grp3 = "Administratoren" ascii wide fullword
      $adu = "New-ADUser" ascii wide
      $guest = "Guest$" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 2MB and
      3 of them
}
```

**Deployment Stub (ct.bat)**

#### ct.bat Proxy-Aware USB Worm Stub

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1091 (Replication Through Removable Media)
**Confidence:** HIGH
**False Positives:** None known in combination, any single one of the five strings could plausibly appear in unrelated scripts, but 2 or more together inside a file under 5 KB is not an expected legitimate pattern
**Blind Spots:** A trivially reworded stub (renamed Run value, restructured WMIC query) would evade this rule; it does not require the AMSI-bypass string, which is present but not solely relied upon given the type-name reversal noted in the companion Sigma rule
**Validation:** Confirm the rule fires on `ct.bat`. A benign proxy-aware PowerShell download script that does not also reference USB enumeration or autorun.inf must not fire on its own.
**Deployment:** Email/web gateway attachment scanning, endpoint AV/EDR file scan, USB-drop analysis

```yara
rule Loader_CtBat_ProxyAwareUSBWormStub {
   meta:
      description = "Detects the ct.bat infection stub via a combination of its distinctive command fragments: proxy-credential-inheriting WebClient download, USB drive enumeration for its worm loop, autorun.inf propagation, and its AMSI-bypass field name"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "0ff0cee1fbf1050fbe3ab91918e56334a93269265e5614717ec0441baa8c42df"
      family = "CloudSync"
      malware_type = "Loader"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "21d45221-9c71-50e5-89fa-a7b3d0ea4e76"
   strings:
      $proxy = "DefaultCredentials" ascii
      $wmic = "wmic logicaldisk where" ascii
      $autorun = "autorun.inf" ascii
      $amsi = "amsiInitFailed" ascii
      $sysupd = "SystemUpdate" ascii
   condition:
      filesize < 5KB and
      2 of them
}
```

### Hunting Rules

**CloudSync**

#### CloudSync Public-Profile Working Directory Artifacts

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1090.003 (Multi-hop Proxy), T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**False Positives:** The individual strings (`config.json`, `first_run.flag`, generic path fragments) are common enough in isolation that this rule is scoped to hunting rather than alerting; review each hit rather than auto-blocking
**Blind Spots:** Broader and lower-precision than the dedicated panel and protocol Detection rules above by design, intended to catch variants that changed the panel markup or protocol strings but kept the working-directory and mutex conventions
**Validation:** Confirm the rule fires on `bk.exe`. Run against a sample of benign software installers to confirm the 3-of-7 threshold does not fire on unrelated Windows utilities that happen to reference `C:\Users\Public\`.
**Deployment:** Threat hunting sweep across endpoint file inventories; not recommended for auto-block

```yara
rule RAT_CloudSync_PublicWorkdir_Artifacts {
   meta:
      description = "Detects CloudSync working-directory, dropped-Tor-binary, and mutex string artifacts common to droppers and implants across both build generations; broader and lower-precision than the dedicated panel and protocol rules, intended for hunting"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188/"
      date = "2026-08-03"
      hash1 = "6bd0366372b7d765e76c5a888d68a4991ad04ee614bdb589a20ffbe433db58fc"
      family = "CloudSync"
      malware_type = "RAT"
      campaign = "CloudSync-Assembler-Toolkit-91.197.98.188"
      id = "d226bb58-e0bc-5f2e-8846-d8b3cb415bc2"
   strings:
      $wd1 = "C:\\Users\\Public\\fs\\" ascii
      $wd2 = "C:\\Users\\Public\\filesystem" ascii
      $hs = "hidden_service" ascii
      $thw = "taskhostw.exe" ascii
      $frf = "first_run.flag" ascii
      $mtx1 = "Global\\WUDFHost" ascii wide
      $mtx2 = "Global\\WinUpdateSvcMutex" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 60MB and
      3 of them
}
```

---

## Sigma Rules

### Detection Rules

**CloudSync**

#### CloudSync Guest Dollar Local Account Persistence Command

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1136.001 (Create Account: Local Account)
**Confidence:** HIGH
**False Positives:** Unlikely, local accounts ending in a literal dollar sign are not a standard Windows naming convention; the `not /domain` filter also excludes the unrelated domain-level backdoor activity covered separately below
**Blind Spots:** Requires process-creation command-line visibility; an implant that creates the account via a Win32 API call rather than shelling out to `net user` would not be caught by this rule
**Validation:** Trigger with `net user Guest$ <password> /add` from a command prompt (no `/domain` switch) on a test host and confirm the alert fires. A legitimate `net user` command targeting a domain account with `/domain` present must NOT fire.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent EDR command-line logging)

```yaml
title: CloudSync RAT Guest Dollar Local Account Persistence Command
id: 301385e1-0331-459e-b547-6229cf0788ff
status: experimental
description: >-
    Detects a "net user" command targeting a local account named "Guest$" without
    the "/domain" switch. CloudSync's implant re-issues this command on a short cycle
    to keep a local machine-account-masquerade backdoor present; the trailing dollar
    sign mimics a computer-account naming convention that most admins never use for a
    local user.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'net user'
            - 'Guest$'
    filter_domain:
        CommandLine|contains: '/domain'
    condition: selection and not filter_domain
falsepositives:
    - Unlikely, local accounts ending in a literal dollar sign are not a standard Windows naming convention
level: high
```

#### CloudSync Windows Update Service Masquerade Installation

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1543.003 (Windows Service)
**Confidence:** HIGH
**False Positives:** Unlikely, the genuine Windows Update service display name is "Windows Update" (short form); "Windows Update Service" does not occur in stock Windows
**Blind Spots:** Only fires on the `svhost4` build's exact display-name choice; a rebuilt CloudSync variant using a different masquerade name would not be caught, pair with the companion working-directory rule for broader coverage
**Validation:** Install a test service with display name exactly "Windows Update Service" and confirm Event ID 7045 triggers the rule. Confirm the genuine `wuauserv` service (display name "Windows Update") does NOT fire.
**Deployment:** Windows Service Control Manager event log (Event ID 7045)

```yaml
title: CloudSync RAT Windows Update Service Masquerade Installation
id: 0ae91cbf-e335-4060-9283-8862790a7c0e
status: experimental
description: >-
    Detects installation of a Windows service whose display name is "Windows Update
    Service". The genuine Windows Update service display name is "Windows Update"
    (short form), the extra word is CloudSync's masquerade convention for its
    svhost4 implant's persistence service, and does not occur in stock Windows.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName: 'Windows Update Service'
    condition: selection
falsepositives:
    - Unlikely, the genuine Windows Update service display name is "Windows Update", not "Windows Update Service"
level: high
```

#### CloudSync Tor Hidden Service Staging Under Public Profile

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1090.003 (Multi-hop Proxy), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** Unlikely, legitimate software does not write an executable named `taskhostw.exe` or create a `hidden_service` directory under the shared Public profile
**Blind Spots:** Misses a rebuild that renames both the dropped Tor binary and the hidden-service directory; does not require the specific `\fs\` or `\filesystem\` working-directory name, which is deliberate given that name is build-variant
**Validation:** Drop a file named `taskhostw.exe` under `C:\Users\Public\` (or create a `\hidden_service\` subdirectory with a file inside it) and confirm the alert fires. Legitimate software installation under `C:\Users\Public\Desktop\` or similar standard subfolders must NOT fire.
**Deployment:** Endpoint file-creation telemetry (Sysmon Event ID 11 or equivalent)

```yaml
title: CloudSync RAT Tor Hidden Service Staging Under Public Profile
id: 4a7f8a52-bc79-48d2-8776-550cad2455af
status: experimental
description: >-
    Detects file creation consistent with CloudSync standing up a per-victim Tor
    hidden service from a working directory under the shared Public profile, a
    masqueraded Tor binary named taskhostw.exe, or any file written inside a
    hidden_service subdirectory of C:\Users\Public\. The build-variant working
    directory name (fs vs filesystem) is not required; the anchor is the Public-path
    root paired with the Tor hidden-service artifact.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.command-and-control
    - attack.t1090.003
    - attack.stealth
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection_taskhostw:
        TargetFilename|contains: '\Users\Public\'
        TargetFilename|endswith: '\taskhostw.exe'
    selection_hiddensvc:
        TargetFilename|contains|all:
            - '\Users\Public\'
            - '\hidden_service\'
    condition: 1 of selection_*
falsepositives:
    - Unlikely, legitimate software does not write an executable named taskhostw.exe or create a hidden_service directory under the shared Public profile
level: high
```

**SvchostPayload / .NET RAT Chain**

#### Wscript To PowerShell To MSBuild Execution Chain Without Project File

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1127.001 (Trusted Developer Utilities: MSBuild), T1055 (Process Injection)
**Confidence:** HIGH
**False Positives:** Developer or CI tooling that launches MSBuild from a hidden PowerShell wrapper without a visible project path on the command line, rare, but review any hit from a build server before escalating
**Blind Spots:** An attacker who passes any string containing one of the filtered project-file extensions (even a decoy) would evade the filter; the rule also depends on the parent process being `powershell.exe` directly, an intermediate `cmd.exe` hop would need a chained/correlated rule
**Validation:** Launch `powershell -w hidden -ep bypass -c "Start-Process MSBuild.exe"` with no project argument on a test host and confirm the alert fires. Launching MSBuild against a real `.csproj` file from the same PowerShell invocation must NOT fire.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent), prioritized for triage given this is the hardest-to-detect chain in the case

```yaml
title: Wscript To PowerShell To MSBuild Execution Chain Without Project File
id: 4f593a7e-a980-452a-bc36-25db2acf2c7c
status: experimental
description: >-
    Detects MSBuild.exe launched directly by a hidden, execution-policy-bypassed
    PowerShell process with no build-project argument (no .csproj/.vbproj/.sln/.xml/
    .proj/.targets path on the command line). Legitimate MSBuild invocations, even
    from a shell, almost always pass a project or target path; a bare invocation is
    consistent with using MSBuild as a hollow injection target rather than as a
    build tool. Observed as the final stage of a wscript-launched fileless loader
    chain that injects a custom .NET RAT into the resulting process.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.stealth
    - attack.privilege-escalation
    - attack.execution
    - attack.t1127.001
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\MSBuild.exe'
        - OriginalFileName: 'MSBuild.exe'
    selection_parent:
        ParentImage|endswith: '\powershell.exe'
        ParentCommandLine|contains:
            - '-w hidden'
            - '-windowstyle hidden'
            - '-ep bypass'
            - '-ExecutionPolicy Bypass'
    filter_project_file:
        CommandLine|contains:
            - '.csproj'
            - '.vbproj'
            - '.sln'
            - '.proj'
            - '.targets'
            - '.xml'
    condition: all of selection_* and not filter_project_file
falsepositives:
    - Developer or CI tooling that launches MSBuild from a hidden PowerShell wrapper without a visible project path on the command line
level: high
```

#### MSBuild Process Making a Direct Outbound Network Connection

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1127.001 (Trusted Developer Utilities: MSBuild)
**Confidence:** HIGH
**False Positives:** Not exhaustively surveyed across all CI/build-server configurations; review any hit from a known build host before escalating
**Blind Spots:** Requires network-connection telemetry with process attribution; a proxy-routed or tunneled connection that changes the observed process identity would evade this
**Validation:** Inject a network-capable payload into a test `MSBuild.exe` process and confirm an outbound connection triggers the alert. A NuGet-restore build that uses a separate `dotnet.exe`/`nuget.exe` client process (not MSBuild itself) making the connection must NOT fire.
**Deployment:** Endpoint network-connection telemetry (Sysmon Event ID 3 or equivalent), deliberately not port-restricted since this campaign's beacon uses port 4443 rather than 80/443

```yaml
title: MSBuild Process Making a Direct Outbound Network Connection
id: 9629ebb5-35e9-4e2c-b209-c66eee51f0ea
status: experimental
description: >-
    Detects MSBuild.exe itself initiating an outbound TCP connection. MSBuild does
    not make direct network connections as part of normal build activity (NuGet
    restore and package operations run through separate client processes); an
    outbound connection from MSBuild.exe is consistent with a RAT running inside an
    injected MSBuild process beaconing to its command-and-control server.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.stealth
    - attack.execution
    - attack.t1127.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\MSBuild.exe'
        Initiated: 'true'
    condition: selection
falsepositives:
    - Unknown, MSBuild network activity is rare in normal build environments but has not been exhaustively surveyed across all CI configurations
level: high
```

#### Windows Defender Tampering Via Set-MpPreference Disable Switches

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1562.001 (Impair Defenses: Disable or Modify Tools)
**Confidence:** HIGH
**False Positives:** Administrative hardening or troubleshooting scripts that legitimately toggle Defender preferences
**Blind Spots:** An attacker using the WMI `MSFT_MpPreference` class directly (bypassing the PowerShell cmdlet wrapper) would not produce this exact command line and would evade the rule
**Validation:** Run `Set-MpPreference -DisableRealtimeMonitoring $true` on a test host and confirm the alert fires. A benign Defender status query (`Get-MpPreference`) must NOT fire.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent); PowerShell Script Block Logging (Event ID 4104) is a useful supplementary source when the command line itself is further obfuscated

```yaml
title: Windows Defender Tampering Via Set-MpPreference Disable Switches
id: 3b3283c2-d047-402f-b46d-b6fb43faebf3
status: experimental
description: >-
    Detects a PowerShell Set-MpPreference or Add-MpPreference command disabling
    Windows Defender real-time protection, IOAV protection, or behavior monitoring.
    Observed issued from inside an injected MSBuild.exe process immediately after a
    fileless .NET RAT loads, to blind Defender ahead of further activity.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
    - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdlet:
        CommandLine|contains:
            - 'Set-MpPreference'
            - 'Add-MpPreference'
    selection_option:
        CommandLine|contains:
            - 'DisableRealtimeMonitoring'
            - 'DisableIOAVProtection'
            - 'DisableBehaviorMonitoring'
    condition: selection_cmdlet and selection_option
falsepositives:
    - Administrative hardening or troubleshooting scripts that legitimately toggle Defender preferences
level: high
```

#### Photo Studio Masquerade Loader Files Under LocalAppData

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** Unlikely, no common legitimate application installs script files under a "Photo Studio" LocalAppData folder
**Blind Spots:** A rebuild that changes the masquerade folder name would evade this rule entirely; pair with the wscript-to-MSBuild chain rule for coverage of a renamed variant
**Validation:** Create a `.js` or `.vbs` file inside `%LOCALAPPDATA%\Photo Studio\` on a test host and confirm the alert fires. Script files created under an unrelated, genuinely-installed application's LocalAppData folder must NOT fire.
**Deployment:** Endpoint file-creation telemetry (Sysmon Event ID 11 or equivalent)

```yaml
title: Photo Studio Masquerade Loader Files Under LocalAppData
id: d570d892-64b5-4eb9-ad99-2b615230bbdf
status: experimental
description: >-
    Detects creation of a JScript or VBScript file inside a "Photo Studio" directory
    under the user's LocalAppData folder. This is the on-disk persistence copy and
    windowless relaunch wrapper for a fileless .NET RAT loader; no legitimate "Photo
    Studio" application is installed by this path convention.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Photo Studio\'
        TargetFilename|endswith:
            - '.js'
            - '.vbs'
    condition: selection
falsepositives:
    - Unlikely, no common legitimate application installs script files under a "Photo Studio" LocalAppData folder
level: high
```

#### WindowsUpdateService Scheduled Task Creation By Dotnet RAT Chain

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**False Positives:** Unlikely, "WindowsUpdateService" is not a task name used by any genuine Windows Update component
**Blind Spots:** This scheduled-task mechanism is specific to the .NET RAT chain, CloudSync itself persists only via a registry Run key and a Windows service and does not use this task, so this rule must not be read as covering CloudSync as well
**Validation:** Run `schtasks /create /tn "WindowsUpdateService" /tr notepad.exe /sc onlogon` on a test host and confirm the alert fires. A genuine Windows Update-related scheduled task under the standard `\Microsoft\Windows\WindowsUpdate\` task path must NOT fire, since it will not match this literal task name via `schtasks`.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent)

```yaml
title: WindowsUpdateService Scheduled Task Creation By Dotnet RAT Chain
id: 07502798-ce21-4812-86ca-3368b6f9f38c
status: experimental
description: >-
    Detects creation of a scheduled task named "WindowsUpdateService" configured to
    run at logon. This is the fileless .NET RAT chain's second persistence layer,
    created from inside the injected MSBuild.exe process after the Defender tamper
    step. This task name and mechanism are specific to the .NET RAT chain, the
    unrelated CloudSync Tor-panel RAT in the same toolkit persists only via a
    registry Run key and a Windows service, never a scheduled task.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'schtasks'
            - '/tn'
            - 'WindowsUpdateService'
            - 'onlogon'
    condition: selection
falsepositives:
    - Unlikely, "WindowsUpdateService" is not a task name used by any genuine Windows Update component
level: high
```

#### Temp Log File Deleted Matching Fileless Loader Staging Pattern

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1070.004 (File Deletion)
**Confidence:** HIGH
**False Positives:** A coincidental temp filename matching the `log_<digits>_<digits>` shape from unrelated software has not been surveyed, though the pattern is distinctive
**Blind Spots:** This detects the deletion, not the earlier read, pair with the Photo Studio and wscript-chain rules above to catch the loader earlier in its lifecycle
**Validation:** Create and delete a file named `log_12345_67890` inside `%TEMP%` on a test host and confirm the alert fires. Deletion of an unrelated temp file with a different naming shape must NOT fire.
**Deployment:** Endpoint file-deletion telemetry (Sysmon Event ID 23/26 or equivalent)

```yaml
title: Temp Log File Deleted Matching Fileless Loader Staging Pattern
id: b237faa4-ae89-4f42-b5c7-d6c2d8b7f15b
status: experimental
description: >-
    Detects deletion of a temp file named "log_<digits>_<digits>" from the user's
    Temp folder. The fileless .NET RAT loader decrypts its staged payload into a
    file of this name, reads it back into memory with PowerShell, then deletes it as
    anti-forensic cleanup, a temp file of this exact naming shape is not a pattern
    used by common legitimate logging utilities.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.stealth
    - attack.t1070.004
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Temp\log_'
        TargetFilename|re: '_[0-9]+_[0-9]+$'
    condition: selection
falsepositives:
    - Unknown, a coincidental temp filename matching the log_<digits>_<digits> shape from unrelated software has not been surveyed
level: high
```

**Deployment Orchestrator (ab.exe)**

#### Active Directory Tier-0 Backdoor Account Creation Or Privileged Group Addition

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1136.002 (Create Account: Domain Account), T1098.007 (Additional Local or Domain Groups)
**Confidence:** HIGH
**False Positives:** Legitimate onboarding of a new privileged administrator, or a genuine computer/service account naming collision with the dollar-sign check
**Blind Spots:** Windows security auditing must be enabled for account-management and group-management events; a host without domain-controller audit logging in place will not generate the source events this rule depends on
**Validation:** Create a test user account with a name ending in `$` (Event ID 4720) or add a test account to the local Administrators group (Event ID 4732) and confirm the alert fires. Creating a genuine computer account (which logs under a different event ID, not 4720) must NOT fire this rule.
**Deployment:** Windows Security event log on domain controllers and member servers (Event IDs 4720, 4728, 4732, 4756); locale-independent by design, matched by well-known group SIDs and RID suffixes rather than group display names, so it generalizes beyond this campaign's German-localized target

```yaml
title: Active Directory Tier-0 Backdoor Account Creation Or Privileged Group Addition
id: b66c823b-08d3-4e03-8259-78257e98439c
status: experimental
description: >-
    Detects either the creation of a user account (not a computer account) whose
    sAMAccountName ends in a literal dollar sign, or the addition of any account to
    a Tier-0 privileged group (local Administrators, or the well-known Domain
    Admins/Enterprise Admins/Schema Admins relative IDs, matched by SID suffix so
    the rule is independent of OS locale and does not require the victim's domain
    name). Windows logs true computer-account creation under a separate event ID,
    so a dollar-suffixed name arriving via the user-account-creation event is itself
    the discriminator for a machine-account masquerade. Observed as an orchestrator
    tool's one-shot creation of a hidden "Guest$" account escalated into all four
    groups to build a forest-level backdoor.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1136.002
    - attack.t1098.007
logsource:
    product: windows
    service: security
detection:
    selection_create:
        EventID: 4720
        SamAccountName|contains: '$'
    selection_privgroup_domain:
        EventID:
            - 4728
            - 4756
        TargetSid|endswith:
            - '-512'
            - '-518'
            - '-519'
    selection_privgroup_local:
        EventID: 4732
        TargetSid: 'S-1-5-32-544'
    filter_main_homegroup:
        EventID: 4720
        TargetUserName: 'HomeGroupUser$'
    condition: 1 of selection_* and not 1 of filter_main_*
falsepositives:
    - Legitimate onboarding of a new privileged administrator, or a genuine computer/service account naming collision with the dollar-sign check
level: high
```

#### Winlogon SpecialAccounts UserList Registry Write

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1564.002 (Hidden Users)
**Confidence:** HIGH
**False Positives:** Deliberate administrative hiding of a legitimate local service account from the logon screen
**Blind Spots:** None significant, this key is written almost exclusively for account-hiding purposes; requires registry-value telemetry on the relevant Winlogon hive path
**Validation:** Write any value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` on a test host and confirm the alert fires. Registry writes elsewhere under `Winlogon\` that do not touch `SpecialAccounts\UserList` must NOT fire.
**Deployment:** Endpoint registry telemetry (Sysmon Event ID 12/13 or equivalent)

```yaml
title: Winlogon SpecialAccounts UserList Registry Write
id: 2966dbb8-8da1-492d-aeea-9921679ed4b6
status: experimental
description: >-
    Detects a write to the Winlogon SpecialAccounts\UserList registry key, which
    hides the named account from the Windows logon screen and User Manager tile.
    This key is written almost exclusively to hide a newly created backdoor
    account, legitimate use (hiding a genuine service account) is rare enough that
    any write to this key merits review regardless of which account is targeted.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.stealth
    - attack.t1564.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\SpecialAccounts\UserList'
    condition: selection
falsepositives:
    - Deliberate administrative hiding of a legitimate local service account from the logon screen
level: high
```

#### ASPX File Written to IIS aspnet_client Directory

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.003 (Web Shell)
**Confidence:** HIGH
**False Positives:** Unlikely, the aspnet_client directory does not normally receive new .aspx files after IIS/ASP.NET installation
**Blind Spots:** A web shell dropped to a different IIS directory (outside `aspnet_client`) would not be caught by this rule; pair with the w3wp.exe-spawns-shell rule below for behavioral coverage of web-shell use regardless of drop location
**Validation:** Create a test `.aspx` file inside a local IIS installation's `aspnet_client` directory and confirm the alert fires. New `.aspx` files created elsewhere in the web root during normal application deployment must NOT fire.
**Deployment:** Endpoint file-creation telemetry on IIS web servers (Sysmon Event ID 11 or equivalent)

```yaml
title: ASPX File Written to IIS aspnet_client Directory
id: da35ea9d-176c-412e-9325-3df4f98a7033
status: experimental
description: >-
    Detects creation of an .aspx file inside an IIS aspnet_client directory. This
    path is reserved for a fixed set of Microsoft-shipped ASP.NET AJAX support
    files, not for uploaded or authored pages, any new .aspx file there is
    consistent with a web shell drop. Observed with the Sharp4WebCmd command-console
    web shell, dropped as the first stage of a post-compromise orchestrator tool.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\aspnet_client\'
        TargetFilename|endswith: '.aspx'
    condition: selection
falsepositives:
    - Unlikely, the aspnet_client directory does not normally receive new .aspx files after IIS/ASP.NET installation
level: high
```

#### IIS Worker Process Spawning A Command Shell

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1505.003 (Web Shell), T1059.001 (PowerShell)
**Confidence:** HIGH
**False Positives:** Rare IIS management or deployment automation that legitimately spawns a shell from the worker process
**Blind Spots:** A web shell that executes commands via .NET reflection or an in-process runspace rather than spawning a child process (as Sharp4WebCmd itself is capable of, since it embeds a PowerShell runspace) would not be caught by this rule
**Validation:** From a test IIS host, have the worker process spawn `cmd.exe` or `powershell.exe` (e.g., via a deliberately vulnerable test page) and confirm the alert fires. Normal IIS request handling with no shell child process must NOT fire.
**Deployment:** Endpoint process-creation telemetry on IIS web servers (Sysmon Event ID 1 or equivalent)

```yaml
title: IIS Worker Process Spawning A Command Shell
id: efdf846f-4879-4ee6-99e9-45a7203503a4
status: experimental
description: >-
    Detects the IIS worker process (w3wp.exe) spawning powershell.exe or cmd.exe.
    An IIS application pool process does not normally launch an interactive shell;
    this is the classic behavioral signal of a web shell being used to execute
    commands, observed here immediately after an ASPX web shell is dropped into the
    aspnet_client directory.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.execution
    - attack.t1505.003
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\w3wp.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    condition: selection
falsepositives:
    - Rare IIS management or deployment automation that legitimately spawns a shell from the worker process
level: high
```

#### AnyDesk Unattended Password Piped Over Stdin By Non-AnyDesk Process

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1219.002 (Remote Desktop Software)
**Confidence:** HIGH
**False Positives:** Legitimate IT automation that pipes a password to AnyDesk during scripted unattended deployment
**Blind Spots:** A deployment script that reads the password from a file or environment variable rather than an inline `echo` pipe would evade this rule
**Validation:** Run `echo testpassword | AnyDesk.exe --set-password` on a test host and confirm the alert fires. A manual, interactive AnyDesk password change through the GUI must NOT fire, since it never appears as a process-creation command line.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent), the password value itself never touches the command line, so this rule detects the pipeline shape, not the credential

```yaml
title: AnyDesk Unattended Password Piped Over Stdin By Non-AnyDesk Process
id: 944c365c-8565-4097-8d18-4e9a5f74aafe
status: experimental
description: >-
    Detects a command piping text into AnyDesk.exe with the --set-password flag
    the password value itself never appears on the command line, so the pipeline
    shape is the anchor. Observed issued by an orchestrator tool immediately after a
    silent, unattended AnyDesk install, to set a remote-access password without
    leaving the credential in process-creation logs.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
    - https://redcanary.com/blog/misbehaving-rats/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'echo'
            - 'AnyDesk.exe'
            - '--set-password'
    condition: selection
falsepositives:
    - Legitimate IT automation that pipes a password to AnyDesk during scripted unattended deployment
level: medium
```

**Deployment Stub (ct.bat)**

#### PowerShell WebClient Download Inheriting Default Proxy Credentials

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1090 (Proxy)
**Confidence:** HIGH
**False Positives:** Unlikely, legitimate proxy-aware download scripts rarely combine WebClient with explicit DefaultCredentials proxy inheritance in this exact form
**Blind Spots:** The download URL itself is not required by this rule (deliberately, since the staging IP is perishable); a script using `Invoke-WebRequest` instead of `Net.WebClient` with the same proxy-inheritance intent would evade this specific pattern
**Validation:** Run a PowerShell one-liner constructing `New-Object Net.WebClient` with `.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials` on a test host and confirm the alert fires. A WebClient download with no explicit proxy-credential configuration must NOT fire.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent), this is the stub's always-present stage, firing even on runs where the subsequent payload write fails, so it is the highest-yield single anchor for this component

```yaml
title: PowerShell WebClient Download Inheriting Default Proxy Credentials
id: 80dee74f-6c3d-4947-81bc-4fe1bb14f919
status: experimental
description: >-
    Detects a PowerShell Net.WebClient object configured with Proxy.Credentials set
    to DefaultCredentials, which inherits the logged-on user's authenticated proxy
    session so a payload download succeeds from inside an authenticated enterprise
    proxy. This is the deployment stub's always-present download stage, it fires
    even on runs where the subsequent payload write fails, since the stub gates its
    later stages on a successful save rather than a successful connection.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.command-and-control
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Net.WebClient'
            - 'Proxy.Credentials'
            - 'DefaultCredentials'
    condition: selection
falsepositives:
    - Unlikely, legitimate proxy-aware download scripts rarely combine WebClient with explicit DefaultCredentials proxy inheritance in this exact form
level: high
```

#### AMSI Bypass Via AmsiUtils AmsiInitFailed Field SetValue

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1562.001 (Impair Defenses: Disable or Modify Tools)
**Confidence:** HIGH
**False Positives:** Unlikely, legitimate scripts do not reflectively clear the AMSI initialization-failed field
**Blind Spots:** Deliberately does NOT key on the literal "AmsiUtils" type-name string, since this campaign's stub constructs that string from a reversed literal specifically to evade signature matching on it; a variant that also renames or obfuscates the field name "amsiInitFailed" itself would evade this rule
**Validation:** Run a PowerShell one-liner combining `amsiInitFailed`, `SetValue`, and `NonPublic` (the standard AMSI-bypass-via-reflection shape) on a test host and confirm the alert fires. Unrelated PowerShell reflection code that does not touch AMSI must NOT fire.
**Deployment:** Endpoint process-creation telemetry (Sysmon Event ID 1 or equivalent); PowerShell Script Block Logging (Event ID 4104) is a useful supplementary source for heavily obfuscated variants

```yaml
title: AMSI Bypass Via AmsiUtils AmsiInitFailed Field SetValue
id: f539cc09-bd50-4675-9119-08c09fb2ac24
status: experimental
description: >-
    Detects a PowerShell command that reflects into the AmsiUtils type and calls
    SetValue against a non-public static field to blind in-process AMSI scanning.
    Matched on the amsiInitFailed field name and the SetValue/NonPublic reflection
    call shape rather than the AmsiUtils type-name string, since the deployment stub
    observed in this campaign constructs that type name from a reversed string
    literal specifically to evade signature matching on the literal "AmsiUtils"
    substring.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
    - https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'amsiInitFailed'
            - 'SetValue'
            - 'NonPublic'
    condition: selection
falsepositives:
    - Unlikely, legitimate scripts do not reflectively clear the AMSI initialization-failed field
level: high
```

#### Run Key SystemUpdate Value Pointing To Startup Folder Tilde Executable

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** HIGH
**False Positives:** Unlikely, the combination of the SystemUpdate value name and a Startup-folder tilde-prefixed target is not a known legitimate pattern
**Blind Spots:** This rule fires only once the stub's download and drop stages have already succeeded, the proxy-WebClient rule above is the anchor that fires even on incomplete runs
**Validation:** Set an `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemUpdate` value pointing to a test file inside the Startup folder named `~12345.exe` and confirm the alert fires. A Run value named SystemUpdate pointing anywhere outside the Startup folder must NOT fire.
**Deployment:** Endpoint registry telemetry (Sysmon Event ID 13 or equivalent)

```yaml
title: Run Key SystemUpdate Value Pointing To Startup Folder Tilde Executable
id: 3598bf78-f702-4ab3-b8ba-9d38f62eab80
status: experimental
description: >-
    Detects an HKCU Run value named "SystemUpdate" whose data points at a
    tilde-prefixed executable inside the user's Startup folder. This is the
    deployment stub's persistence step, added immediately after it copies its
    downloaded payload into Startup under a randomized ~<digits>.exe name.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\SystemUpdate'
        Details|contains: '\Startup\~'
    condition: selection
falsepositives:
    - Unlikely, the combination of the SystemUpdate value name and a Startup-folder tilde-prefixed target is not a known legitimate pattern
level: high
```

### Hunting Rules

**Deployment Stub (ct.bat)**

#### Tilde Prefixed Executable Written To User Startup Folder

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** MODERATE
**False Positives:** Installer temp-extraction artifacts that transiently use tilde-prefixed names, and legitimate portable applications that place a randomly-named launcher shortcut in Startup
**Blind Spots:** Broader and weaker in isolation than the paired Run-key rule above, a tilde-prefixed filename in Startup is a real but not conclusive signal on its own; intended for triage alongside the SystemUpdate Run-key rule, not standalone alerting
**Validation:** Copy any executable with a tilde-prefixed filename into a test Startup folder and confirm the alert fires. Review hits for the co-occurring SystemUpdate Run-key rule before treating a hit as confirmed malicious.
**Deployment:** Threat hunting sweep of Startup folder contents; not recommended for auto-block

```yaml
title: Tilde Prefixed Executable Written To User Startup Folder
id: 818f62ed-fba7-4252-97fd-234961f88eb5
status: experimental
description: >-
    Detects an executable with a tilde-prefixed filename written directly into a
    user's Startup folder. Broader and weaker in isolation than the paired
    SystemUpdate Run-key rule in this set, some installers briefly use
    tilde-prefixed temp names, though rarely inside the Startup folder itself, so
    this is intended for hunting and triage rather than standalone alerting.
references:
    - https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
author: The Hunters Ledger
date: 2026-08-03
tags:
    - attack.persistence
    - attack.stealth
    - attack.t1036.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Start Menu\Programs\Startup\~'
        TargetFilename|endswith: '.exe'
    condition: selection
falsepositives:
    - Installer temp-extraction artifacts that transiently use tilde-prefixed names
    - Legitimate portable applications that place a randomly-named launcher shortcut in Startup
level: medium
```

---

## Suricata Signatures

### Detection Rules

**CloudSync**

#### CloudSync C2 Registration Marker

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
**Confidence:** HIGH
**False Positives:** None known, this exact 20-character banner is not expected in unrelated TCP traffic
**Blind Spots:** Detects only the registration/auto-update message type; does not fire on heartbeat-only traffic (see the companion heartbeat rule below), and is defeated entirely if the operator moves the protocol behind TLS
**Validation:** Confirmed via the real rule-parsing engine against a captured session containing the literal string. A benign TLS or unrelated cleartext TCP session must not contain this exact banner.
**Deployment:** Network IDS/IPS at the perimeter or internal segmentation boundary; deliberately not IP/port-pinned so the rule survives infrastructure rotation

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT CloudSync-Assembler-Toolkit AUTO UPDATE C2 Registration Marker (C2 Registration)"; flow:established,to_server; content:"=== AUTO UPDATE ==="; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-08-03, reference https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/;)
```

#### CloudSync C2 Heartbeat And Terminator Marker

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
**Confidence:** HIGH
**False Positives:** None known, the combination of the `[Shares]` heartbeat header with either terminator token is not expected in unrelated traffic
**Blind Spots:** The terminator alternation covers both known build generations ([C2_END] and [END]); a future build changing both the heartbeat header and the terminator simultaneously would evade this rule; opaque once the protocol runs over the Tor hidden service rather than the direct staging-host ports
**Validation:** Confirmed via the real rule-parsing engine, including the PCRE alternation. A session containing `[Shares]` without either terminator token, or either terminator without `[Shares]`, must not fire.
**Deployment:** Network IDS/IPS at the perimeter or internal segmentation boundary

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT CloudSync-Assembler-Toolkit Shares Heartbeat Terminator Marker (C2 Heartbeat)"; flow:established,to_server; content:"[Shares]"; pcre:"/\[(C2_END|END)\]/"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-08-03, reference https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/;)
```

**SentinelStealer (Sourced, Separate Tier)**

#### SentinelStealer c3lestial.fun TLS SNI

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**False Positives:** The domain sits on shared/Hostinger hosting with 20+ unrelated communicating files observed, so a hit may indicate a different malware family sharing the same hosting rather than SentinelStealer specifically, a "something malicious" signal even when the specific family attribution is uncertain
**Blind Spots:** This domain is not operator-owned, so it could stop resolving to SentinelStealer's infrastructure at any time without notice; it belongs to a separately-tracked, sourced commodity component and must never be presented alongside the operator's own CloudSync/.NET-chain infrastructure
**Validation:** Confirmed via the real rule-parsing engine against a session presenting the domain in the TLS ClientHello SNI extension. An unrelated TLS session to a different domain must not fire.
**Deployment:** Network IDS/IPS at the perimeter; survives IP rotation since it matches on the TLS SNI rather than a destination address

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT CloudSync-Assembler-Toolkit SentinelStealer c3lestial.fun TLS SNI (Sourced Commodity Stealer C2)"; flow:established,to_server; tls.sni; content:"c3lestial.fun"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-08-03, reference https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/;)
```

#### SentinelStealer c3lestial.fun DNS Query

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** MODERATE
**False Positives:** Same shared-hosting caveat as the TLS SNI rule above; DNS resolution alone is a slightly weaker signal than a completed TLS session since it does not confirm subsequent communication
**Blind Spots:** Useful in environments where TLS inspection is unavailable but DNS logging is; pair with the TLS SNI rule above where both log sources are available
**Validation:** Confirmed via the real rule-parsing engine against a DNS query for the domain. A query for an unrelated domain must not fire.
**Deployment:** Network IDS/IPS or DNS sinkhole/monitoring at the perimeter

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT CloudSync-Assembler-Toolkit SentinelStealer c3lestial.fun DNS Query (Sourced Commodity Stealer C2)"; dns_query; content:"c3lestial.fun"; nocase; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-08-03, reference https://the-hunters-ledger.com/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/;)
```

---

## Coverage Gaps

**Tor-wrapped C2 traffic is opaque once the hidden service is running.** Both the CloudSync C2 protocol content signatures above target the direct staging-host ports (`91.197.98.188:5555`/`:7777`). Once a victim's per-victim Tor hidden service is up and the operator reaches the implant purely through the onion address, the wire traffic is standard Tor cell traffic, indistinguishable at the network layer from any other Tor circuit. No content-based Suricata signature can reach inside that channel. Detection at that point falls back entirely to host-based coverage (the working-directory and service-masquerade Sigma rules, and generic "a workstation is running Tor at all" network telemetry, which is a policy signal rather than a malware-specific one and was intentionally left out of this file).

**The fileless in-memory .NET stages have no on-disk artifact to hash.** `Crystal-Monk.dll` and `SvchostPayload` exist only inside an injected `MSBuild.exe` process on a live victim; there is no dropped file to compute a production hash from, and no guarantee that any two memory captures of the same stage yield an identical byte layout. The YARA rule for this component is written to work against a memory-resident scan, but that requires tooling capable of scanning live process memory. It will not fire against a standard file-system AV sweep. The behavioral Sigma rules (the wscript-to-MSBuild chain, the MSBuild outbound-connection rule, and the Defender-tamper rule) are the more durable coverage for this component precisely because they do not depend on ever recovering the payload itself.

**SentinelStealer's ConfuserEx2 protection makes string-level YARA anchors unreliable.** ConfuserEx2 (`Confuser.Core 1.6.0+447341964f`) encrypts string literals inside the protected assembly body. While external framework and API member references survive, which is what makes the stealer's capability surface readable at all despite the protection, the same guarantee does not extend to arbitrary string constants such as the `Google Chromekey1` identifier or the stealer's own name in in-code strings. Those may or may not survive a rebuild with a different Crypto Obfuscator seed. No YARA rule for SentinelStealer is included in this file for that reason; the two Suricata network rules above (TLS SNI and DNS query for `c3lestial.fun`) are the coverage that exists for this component, and they detect the network destination rather than the binary.

**No rule was built for the raw-IP `.NET` RAT beacon to `2.27.248.138:4443`.** No completed TLS handshake was ever observed on this connection, so there is no ClientHello, SNI, or JA3/JA4 fingerprint to anchor a signature on, only a bare IP and port remain. That is an IOC-feed entry, not a rule (removing the hard-coded IP leaves nothing for a Suricata signature to detect). The same reasoning excludes the CloudSync Flask control panel ports (`91.92.43.221:5000`-`5003`), which are operator-side infrastructure rather than traffic a compromised host would generate.

**Several string-worthy identifiers were deliberately withheld rather than turned into weak rules.** `C:\Users\Public\fs\c.cfg` was attempted by the malware but never successfully created, so a file-presence rule for it may not fire even on a genuinely infected host. The `/receive.php` endpoint recovered from SentinelStealer's process memory was never observed with a confirmed HTTP method, so no method-bound HTTP rule was written against it. The registry `Svc_<name>` value and `Global\<name>_Mutex` naming convention used by the .NET RAT chain varies per build (only `Svc_cls`/`cls_Mutex` is confirmed), which resists precise pattern-matching without either over-fitting to one observed instance or under-fitting to a wildcard broad enough to lose all value. No rule was built for it. The static 32-character CloudSync C2 authentication key was excluded as a detection string entirely, because the implant's command channel does not authenticate its peer, publishing that key in a plaintext signature would hand any reader the ability to issue commands to a live infected host, with no detection benefit over the message-framing signatures already covering the same protocol.

**Generic, widely-used legitimate services were left as context-only IOC-feed entries rather than standalone rules.** `api.telegram.org` (CloudSync's first-run victim notification channel), `download.anydesk.com` (fetched legitimately by the deployment orchestrator before a silent unattended install), and `ip-api.com` (queried by SentinelStealer for geolocation, using the .NET default WebClient behavior of sending no User-Agent header) are all used heavily by benign software. Each is present in the companion IOC feed with an explicit hunt/context flag; none would clear the false-positive bar for a standalone Detection or Hunting rule in this file without a correlation signal this rule set cannot cleanly express (for example, pairing the AnyDesk CDN fetch with the non-AnyDesk parent process that made it). That sequence is exactly what the AnyDesk piped-password Sigma rule above already covers, from the more reliable side.

**One German-localized string was intentionally excluded from the YARA orchestrator rule.** `Domänen-Admins` (Domain Admins) was dropped from the string set for `Loader_ABExe_DeploymentOrchestrator_Banners` because its exact byte encoding inside the compiled binary (UTF-8, a Windows code page, or UTF-16) could not be confirmed from the available evidence, and a mismatched literal would silently weaken the rule rather than strengthen it. The ASCII-safe sibling group names (`Organisations-Admins`, `Schema-Admins`, `Administratoren`) carry the same detection value without that risk.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
