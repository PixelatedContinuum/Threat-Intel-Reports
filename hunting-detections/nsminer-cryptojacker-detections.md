---
title: "Detection Rules — NsMiner Cryptojacker"
date: '2026-02-02'
layout: post
permalink: /hunting-detections/nsminer-cryptojacker-detections/
hide: true
redirect_from: /hunting-detections/nsminer-cryptojacker
thumbnail: /assets/images/cards/nsminer-cryptojacker.png
---

**Campaign:** NsMiner-125.19.150.122-Cryptojacking
**Date:** 2026-02-02
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/nsminer-cryptojacker/

---

## Detection Coverage Summary

NsMiner is a multi-stage cryptojacking operation delivered via a trojanized NSIS installer (`IMG001.exe`) that stages a custom FTP downloader (`tftp.exe`) conducting credential-stuffing attacks against third-party FTP servers, ultimately deploying a VMProtect-packed CryptoNight (Monero) miner. Coverage here spans the dropper/downloader components and the family's persistence-directory staging pattern; the HTTP C2 beacon to `hrtests.ru` keyed on a single hardcoded URL with no other selector and is routed to the IOC feed rather than published as a standalone signature.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 2 | 0 | T1105, T1071.002, T1496 | 0 |
| Sigma | 0 | 2 | T1547.001, T1071.002 | 1 |
| Suricata | 0 | 0 | — | 0 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- `NsMiner` fullword-wide branding string paired with the Nullsoft installer marker (YARA Detection) — survives C2/infrastructure rotation since it lives in the dropper build itself, not in network configuration.
- Persistence-directory path (`\AppData\Roaming\NsMiner\`) combined with a shipped component filename (YARA Detection) — file-based coverage that needs no network visibility.

**Atomics routed to the IOC feed:** the HTTP C2 beacon endpoint `http://hrtests.ru/S.php` is a transient network indicator with no other selector in its original rule (a bare domain/URL match) — it is already carried in [`nsminer-cryptojacker-iocs.json`](/ioc-feeds/nsminer-cryptojacker-iocs.json) rather than published as a standalone DNS/proxy signature (removing the domain/URL leaves nothing behind to detect). Block it via the feed.

---

## YARA Rules

### Detection Rules

#### NsMiner_Dropper_Downloader

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1071.002 (File Transfer Protocols)
**Confidence:** HIGH
**False Positives:** None known — the fullword wide `NsMiner` branding string does not appear in legitimate NSIS installers, and the FTP-downloader branch requires the hardcoded C2 URL and credential strings alongside the generic FTP API names, not the API names alone.
**Blind Spots:** The FTP-downloader branch (`FtpGetFileA`/`InternetConnectA` API strings + C2 URL/credential strings) stops matching once the operator rotates the `hrtests.ru` C2 domain and FTP credentials — a low-effort operator change. The NSIS-dropper branch (`Nullsoft Scriptable Install System` + `NsMiner` fullword wide) is durable to infrastructure rotation but would be evaded by a full rebrand that removes the `NsMiner` name from the dropper build.
**Validation:** Scan the analyzed dropper (hash1) and downloader (hash2) samples — both must match; a benign NSIS-packaged freeware installer must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, static triage of unknown NSIS-packed binaries.

```yara
/*
   Yara Rule Set
   Identifier: NsMiner Cryptojacker
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule NsMiner_Dropper_Downloader {
   meta:
      description = "Detects the NsMiner NSIS dropper (IMG001.exe) via its Nullsoft installer marker paired with the NsMiner branding string, and/or the FTP downloader component (tftp.exe) via its FTP/WinINet API usage combined with the hardcoded C2 URL and FTP credential strings"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/nsminer-cryptojacker-detections/"
      date = "2026-02-02"
      hash1 = "e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145"
      hash2 = "40fe74d3a1116ed8ca64c62feb694327a414059eeaef62c28bc5917e2e991b3d"
      family = "NsMiner"
      malware_type = "Cryptojacker"
      campaign = "NsMiner-125.19.150.122-Cryptojacking"
      id = "2c885404-1e39-5625-8669-655511ea27a5"
   strings:
      // From IMG001.exe (NSIS Dropper)
      $nsis1 = "Nullsoft Scriptable Install System" fullword ascii
      $nsis2 = "NsMiner" fullword wide

      // From tftp.exe (Downloader)
      $ftp1 = "FtpGetFileA" fullword ascii
      $ftp2 = "InternetConnectA" fullword ascii
      $c2_http = "http://hrtests.ru/S.php" fullword ascii
      $c2_ftp_user = "DIOSESFIEL" fullword ascii
      $c2_ftp_pass = "BLUEAIRWOLF" fullword ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         (all of ($nsis*)) or
         (2 of ($ftp*) and 2 of ($c2*))
      )
}
```

#### NsMiner_Persistence_Directory

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1496 (Resource Hijacking)
**Confidence:** HIGH
**False Positives:** None known — no legitimate software embeds the literal path `\AppData\Roaming\NsMiner\` combined with one of the three family-specific filenames; the generic `C:\Users\` clause is required alongside the distinctive path and adds negligible additional risk on its own.
**Blind Spots:** Requires both the `NsMiner`-branded persistence path and at least one of the three shipped filenames (`NsCpuCNMiner32.exe`, `NsCpuCNMiner64.exe`, `tftp.exe`) to survive unmodified — a rebrand that renames both the install directory and every shipped binary would evade this rule. The generic `C:\Users\` clause contributes no real specificity on its own.
**Validation:** Scan the analyzed dropper referencing the persistence path — must match; a benign installer writing to an unrelated `%AppData%` subdirectory must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanning of processes referencing the NsMiner install path.

```yara
rule NsMiner_Persistence_Directory {
   meta:
      description = "Detects PE files referencing the NsMiner persistence directory path in AppData\\Roaming combined with one of the family's shipped component filenames (the CryptoNight miner binaries or the FTP downloader)"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/nsminer-cryptojacker-detections/"
      date = "2026-02-02"
      family = "NsMiner"
      malware_type = "Cryptojacker"
      campaign = "NsMiner-125.19.150.122-Cryptojacking"
      id = "cb48acba-6ef6-5170-9fac-a711dd034878"
   strings:
      $path1 = "\\AppData\\Roaming\\NsMiner\\" wide ascii
      $path2 = "C:\\Users\\" wide ascii
      $file1 = "NsCpuCNMiner32.exe" fullword wide ascii
      $file2 = "NsCpuCNMiner64.exe" fullword wide ascii
      $file3 = "tftp.exe" fullword wide ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 10MB and
      ($path1 and $path2 and ($file1 or $file2 or $file3))
}
```

---

## Sigma Rules

### Hunting Rules

#### NsMiner Persistence Directory Creation

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder — MODERATE; only the persistence-staging directory is confirmed, the specific autostart mechanism was not directly observed)
**Confidence:** HIGH (directory-creation behavior); MODERATE for the T1547.001 sub-technique mapping specifically.
**Rationale:** `\AppData\Roaming\NsMiner\` is a distinctive, family-branded path with near-zero FP today, but it is a single operator-chosen literal — any rebuild that renames the install directory evades this rule entirely. Durability governs over as-written precision, so this is a Hunting anchor rather than a Detection one.
**False Positives:** Unlikely — no legitimate software has been observed creating a directory literally named `NsMiner` under `%AppData%\Roaming`.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (Event ID 11 File Creation telemetry).

```yaml
title: NsMiner Persistence Directory Creation
id: 4ecdd6e1-c381-4c53-a92f-a1e688accdfb
status: experimental
description: >-
  Detects creation of a file within the NsMiner cryptojacker's persistence
  directory in %AppData%\Roaming. The directory name is derived from the
  malware family's own branding and is not a location used by legitimate
  software.
references:
    - https://the-hunters-ledger.com/hunting-detections/nsminer-cryptojacker-detections/
author: The Hunters Ledger
date: 2026-02-02
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\AppData\Roaming\NsMiner\'
    condition: selection
falsepositives:
    - >-
      Unlikely — no legitimate software has been observed creating a
      directory literally named NsMiner under %AppData%\Roaming
level: medium
```

#### Suspicious FTP Connection from Non-Standard Application

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1071.002 (File Transfer Protocols)
**Confidence:** HIGH for the technique pattern; the rule is a generic FTP-usage heuristic, not family-specific.
**Rationale:** Port 21 plus a non-standard-application heuristic is a durable, technique-level signal — it survives infrastructure rotation and binary renaming trivially since it keys on behavior rather than identity. But the filter list excludes only three applications (`filezilla.exe`, `winscp.exe`, `explorer.exe`), omitting the built-in Windows `ftp.exe` client and many other legitimate FTP consumers, so the false-positive rate is meaningfully higher than Detection tier tolerates. This keeps it a genuine Hunting lead for FTP credential-stuffing activity like NsMiner's downloader, not an alerting-grade signature.
**False Positives:** Legitimate FTP clients not covered by the filter exclusion list (including the built-in Windows `ftp.exe` command-line client, browser FTP support, backup/sync software); scripts or automation tooling using FTP for legitimate file transfer.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (Event ID 3 Network Connection telemetry); tune the filter exclusion list to the environment before broader deployment.

```yaml
title: Suspicious FTP Connection from Non-Standard Application
id: ef8bac38-0045-4f03-abe3-dcd7c1389be7
status: experimental
description: >-
  Detects outbound network connections to TCP port 21 (FTP) initiated by
  processes other than common legitimate FTP clients. Observed as the
  transport used by the NsMiner cryptojacker's tftp.exe downloader
  component, which conducts credential-stuffing attacks against FTP
  servers to stage payloads; this is a broad heuristic that also fires
  on other applications using FTP for unrelated, legitimate purposes.
references:
    - https://the-hunters-ledger.com/hunting-detections/nsminer-cryptojacker-detections/
author: The Hunters Ledger
date: 2026-02-02
tags:
    - attack.command-and-control
    - attack.t1071.002
    - detection.emerging-threats
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationPort: 21
        Initiated: 'true'
    filter:
        Image|endswith:
            - '\filezilla.exe'
            - '\winscp.exe'
            - '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - >-
      Legitimate FTP clients not covered by the filter exclusion list,
      including the built-in Windows ftp.exe command-line client, browser
      FTP support, and backup or file-sync software using FTP transport
    - >-
      Scripts, scheduled tasks, or automation tooling that use FTP for
      legitimate file transfer
level: medium
```

---

## Coverage Gaps

**HTTP C2 beacon routed to the IOC feed, not a rule.** The original Sigma rule "NsMiner HTTP C2 Beacon to hrtests.ru" (`c-uri|contains: 'hrtests.ru/S.php'` paired only with `cs-method: 'GET'`, a non-discriminating filter matched by any browser request) keyed solely on the domain/URL literal — removing it leaves no behavioral signal. `hrtests.ru`, `testswork.ru`, and `http://hrtests.ru/S.php` are already carried in [`nsminer-cryptojacker-iocs.json`](/ioc-feeds/nsminer-cryptojacker-iocs.json) (`network_indicators`). No feed edit was required — both were already present from the original analysis.

**EDR/SIEM vendor-syntax queries consolidated, not carried forward.** The prior version of this file included CrowdStrike, Microsoft Defender (KQL), and SentinelOne EDR queries plus Splunk SPL and Elastic KQL SIEM rules. These duplicated the same underlying indicators now expressed as the Sigma/YARA rules above (filenames, the NsMiner persistence path, the `hrtests.ru` C2 beacon) in vendor-specific syntax, and are dropped in favor of the vendor-neutral Sigma/YARA rules, consistent with this file's standard section layout. The one item of unique content — a Splunk query for FTP connections to 18 hardcoded target IPs — was not a detection of attacker-controlled infrastructure but a hunt for credential-stuffing *targets* (third-party FTP servers being brute-forced, not C2); all 18 IPs are already present in the IOC feed's `network_indicators.ips` list and remain available there for hunting use. A Suricata signature was not authored for them: a bare destination-IP match with no content anchor is a pure IOC-match per the tiering rubric's Suricata Cut criteria, not a signature.

**VMProtect-packed miner binary has no dedicated byte-level rule.** The final-stage CryptoNight miner (`NsCpuCNMiner32.exe` / `NsCpuCNMiner64.exe`) is reported as VMProtect-packed; string/byte-pattern YARA detection is unreliable against a commercial packer's obfuscated code section. `NsMiner_Persistence_Directory` provides indirect, filename-based coverage for these binaries but does not inspect packed content. **What would raise confidence:** unpacked or memory-dumped samples of the miner binary would support a structural/byte-pattern rule independent of the packer.

**Specific persistence mechanism (Registry Run key / Scheduled Task / Service) not confirmed.** The malware is known to stage files in `%AppData%\Roaming\NsMiner\`, but no specific registry value name, scheduled task name, or service name was documented to support a higher-confidence T1547.001 rule beyond the directory-creation heuristic already published. **What would raise confidence:** endpoint telemetry capturing the specific autostart artifact (registry value, task name, or service name) the dropper writes.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
