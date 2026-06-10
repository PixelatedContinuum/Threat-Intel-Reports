---
title: "NsMiner: Multi-Stage Operation"
date: '2026-02-02'
detection_page: /hunting-detections/nsminer-cryptojacker/
ioc_feed: /ioc-feeds/nsminer-cryptojacker.json
detection_sections:
  - label: "YARA Detection Rules"
    anchor: "#yara-detection-rules"
  - label: "Sigma Detection Rules"
    anchor: "#sigma-detection-rules"
  - label: "EDR Hunting Queries"
    anchor: "#edr-hunting-queries"
  - label: "SIEM Detection Rules"
    anchor: "#siem-detection-rules"
ioc_highlights:
  - value: "125[.]19[.]150[.]122"
    note: "Open directory hosting NsMiner"
  - value: "hrtests[.]ru"
    note: "Cryptojacker C2 domain"
  - value: "e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145"
    note: "IMG001.exe dropper SHA256"
layout: post
permalink: /reports/nsminer-cryptojacker/
thumbnail: /assets/images/cards/nsminer-cryptojacker.png
category: "Cryptojacking"
hide: true
description: "A multi-stage cryptojacking campaign distributed from an open directory at 125.19.150.122, using a trojanized NSIS installer to drop a VMProtect-packed Monero miner and a persistent downloader that pivots compromised FTP servers for payload distribution. The downloader component represents an ongoing secondary payload risk beyond cryptomining."
---

**Campaign Identifier:** NsMiner-125.19.150.122-Cryptojacking<br>
**Last Updated:** February 2, 2026<br>
**Threat Level:** HIGH


---

## Malware Analysis Report: NsMiner Cryptojacker

## 1. Executive Summary

**Threat Identified:** A multi-stage cryptojacking campaign distributes the **NsMiner** payload from an open directory at 125.19.150.122. The initial infection vector is a trojanized NSIS (Nullsoft Scriptable Install System) installer, `IMG001.exe`.

**Business Impact:** The dropper hijacks CPU and electrical resources for the attacker's cryptocurrency mining, causing system slowdowns and hardware strain. The downloader component (`tftp.exe`) poses a compounding risk: it can fetch secondary payloads — including ransomware or data stealers — at any time after initial infection.

**Key Findings:**
*   **Attack Chain:** `IMG001.exe` establishes persistence under `%APPDATA%\NsMiner`, then extracts and runs `tftp.exe`, which fetches the final miner payload by credential-stuffing over a dozen FTP servers.
*   **Final Payload:** `NsCpuCNMiner32.exe` and `NsCpuCNMiner64.exe` mine a CryptoNight-based currency — almost certainly Monero (XMR) — using the victim's CPU.
*   **C2 Infrastructure:** `tftp.exe` beacons to `hrtests.ru` over HTTP and cycles hardcoded FTP credentials against 18 target IPs. Servers that accept the credentials become secondary payload distribution points.
*   **Evasion:** The miner binaries are packed with VMProtect (a commercial binary protector), defeating signature-based detection and complicating static analysis.

**Overall Risk Assessment:**
*   **Severity:** **HIGH.** The primary payload hijacks resources rather than destroying data, but the active downloader can pivot to ransomware or stealers with a single C2 update.
*   **Sophistication:** **MEDIUM-HIGH.** Multi-stage delivery, FTP-based resilient payload distribution, and VMProtect packing indicate a deliberate, organized operation.

**Recommendations:**
1.  **Block** all network indicators in the IOCs section at the firewall and DNS level.
2.  **Deploy** the provided YARA rule and SIEM queries to detect and hunt for this threat.
3.  **Scan** for the persistence directory (`%APPDATA%\NsMiner`) on all endpoints.
4.  **Isolate and re-image** any confirmed-infected systems to ensure complete removal.

---

**Malware Family:** NsMiner Cryptojacker
**Primary Threat:** Resource Hijacking (Cryptomining)
**Risk Level:** HIGH

---

## 2. Malware and Campaign Analysis

**NsMiner** is a Trojan Coin Miner named for the persistence directory it creates (`NsMiner`) and its final binaries (`NsCpuCNMiner*.exe`). The family is designed exclusively for cryptojacking.

The NSIS installer dropper bundles malicious scripts and payloads inside a structure that resembles legitimate software packaging, lowering user suspicion at execution.

`hrtests.ru` carries historical ties to miner activity dating to at least 2016, suggesting the actors reuse aging infrastructure or run a long-running operation. The hardcoded list of 18 FTP IPs with credential pairs reflects a **credential stuffing** strategy — the malware cycles through targets likely identified by prior scanning. Any server that accepts a credential pair becomes a payload distribution point for the miner binaries.

## 3. Technical Deep-Dive

> **Analyst note:** This section walks the three-stage infection chain — dropper, downloader, and miner. Each stage hands off to the next and adds a layer of resilience or evasion. Understanding all three is necessary to scope containment, because removing only the miner leaves `tftp.exe` active and able to re-fetch it.

### 3.1. Initial Dropper: `IMG001.exe`

*   **SHA256:** `e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145`
*   **Type:** NSIS Installer
*   **Purpose:** Acts as the initial dropper and establishes persistence.

**Behavior:**
1.  **Drops Payload:** Upon execution, it writes a `info.zip` file to the user's temporary directory.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/nsminer/nsminer-payload-drop.png" | relative_url }}" alt="Payload Drop - tftp.exe and info.zip">
  <figcaption><em>Figure 1: Dynamic analysis showing tftp.exe and info.zip being dropped during execution</em></figcaption>
</figure>

2.  **Establishes Persistence:** It creates the directory `C:\Users\<user>\AppData\Roaming\NsMiner` and copies itself into it. It then executes this new copy to ensure it runs from a persistent location.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/nsminer/nsminer-persistence-directory.png" | relative_url }}" alt="Persistence Directory Creation">
  <figcaption><em>Figure 2: Dynamic analysis showing malware copying itself to the NsMiner persistence directory</em></figcaption>
</figure>

3.  **Executes Downloader:** It extracts and runs the second-stage payload, `tftp.exe`, from the `info.zip` archive.

### 3.2. Second-Stage Downloader: `tftp.exe`

*   **SHA256:** `40fe74d3a1116ed8ca64c62feb694327a414059eeaef62c28bc5917e2e991b3d`
*   **Type:** Custom Downloader
*   **Purpose:** To contact the C2 network and download the final miner payload.

**Behavior:**
1.  **C2 Beacon:** Sends an initial "phone home" beacon to `http://hrtests.ru/S.php`, exfiltrating basic system and user information.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/nsminer/nsminer-static-analysis-urls.png" | relative_url }}" alt="Static Analysis - Extracted URLs">
  <figcaption><em>Figure 3: URLs discovered through custom static analysis script, showing C2 beacon endpoint</em></figcaption>
</figure>

2.  **FTP Credential Stuffing:** `tftp.exe` iterates through a hardcoded list of 18 FTP server IPs, cycling username/password combinations in a **credential stuffing** loop. Dynamic analysis shows the malware systematically testing different credential pairs against each IP — these are attack targets, not pre-compromised infrastructure.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/nsminer/nsminer-ftp-credential-stuffing-small.png" | relative_url }}" alt="FTP Credential Stuffing - Small Sample">
  <figcaption><em>Figure 4: Dynamic analysis showing initial credential stuffing attempts against FTP servers</em></figcaption>
</figure>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/nsminer/nsminer-ftp-credential-stuffing-full.png" | relative_url }}" alt="FTP Credential Stuffing - Full Sequence">
  <figcaption><em>Figure 5: Extended view of password guessing behavior, showing multiple credential combinations being tested</em></figcaption>
</figure>

3.  **Payload Drop:** Once a successful FTP connection is made to any accessible server, it downloads the final payload components (`NsCpuCNMiner32.exe` and `NsCpuCNMiner64.exe`) into the persistence directory (`%APPDATA%\NsMiner`).

### 3.3. Final Payload: `NsCpuCNMiner` (32 & 64-bit)

*   **SHA256 (32-bit):** `a0eba3fda0d7b22a5d694105ec700df7c7012ddc4ae611c3071ef858e2c69f08`
*   **SHA256 (64-bit):** `d0326f0ddce4c00f93682e3a6f55a3125f6387e959e9ed6c5e5584e78e737078`
*   **Type:** Cryptocurrency Miner (CryptoNight)
*   **Purpose:** The ultimate goal of the infection: to use the victim's CPU resources to mine cryptocurrency.

**Analysis:**
*   The "CN" filename suffix strongly indicates the **CryptoNight** algorithm, historically favored for **Monero (XMR)** mining due to its CPU-friendly design.
*   Automated analysis confirms both binaries are packed with VMProtect (a commercial protector that uses virtualization and obfuscation), which defeats signature-based detection and blocks static reverse engineering of the miner configuration.

**Analysis Note:** Full unpacking of the VMProtect layer was not completed in this analysis pass. A dedicated unpacking effort is required to recover the miner's embedded configuration and confirm the mining pool and wallet address.

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence | 
| --- | --- | --- | --- |
| **Execution** | T1204.002 | User Execution: Malicious File | User runs `IMG001.exe`. |
| **Persistence** | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | (Implied by persistence mechanism, common for NSIS) |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | Final miner payloads are packed with VMProtect. |
| **Defense Evasion** | T1218.011 | System Binary Proxy Execution: Rundll32 | NSIS installers often use plugins that are DLLs. |
| **Command and Control**| T1071.001 | Application Layer Protocol: Web Protocols | Beaconing to `hrtests.ru` over HTTP. |
| **Command and Control**| T1071.002 | Application Layer Protocol: File Transfer Protocols| Use of multiple FTP servers for payload download. |
| **Impact** | T1496 | Resource Hijacking | The final payload is a cryptominer that hijacks CPU resources. |


## 5. Detection and Hunting

### YARA Rule
This rule targets unique strings and properties of the dropper and downloader components.

```yara
rule NsMiner_Dropper_Downloader {
    meta: 
        description = "Detects the NsMiner NSIS dropper and the FTP downloader component."
        author = "The Hunters Ledger"
        date = "2026-02-02"
        hash1 = "e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145"
        hash2 = "40fe74d3a1116ed8ca64c62feb694327a414059eeaef62c28bc5917e2e991b3d"

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
        uint16(0) == 0x5A4D and // PE file
        (
            (all of ($nsis*)) or
            (3 of ($ftp*) and 2 of ($c2*))
        )
}
```

### SIEM Hunting Query
This query hunts for the HTTP beaconing activity from `tftp.exe`. The syntax is Splunk SPL; adapt field names to your SIEM platform.

```splunk
index=proxy OR index=firewall 
http_method=GET 
url="*hrtests.ru/S.php*" 
| stats count by src_ip, user_agent, url
```

## 6. Indicators of Compromise (IOCs)

### File Hashes
| Filename | SHA256 | 
| --- | --- |
| `IMG001.exe` | `e06aa8ce984b22dd80a60c1f818b781b05d1c07facc91fec8637b312a728c145` |
| `tftp.exe` | `40fe74d3a1116ed8ca64c62feb694327a414059eeaef62c28bc5917e2e991b3d` |
| `NsCpuCNMiner32.exe` | `a0eba3fda0d7b22a5d694105ec700df7c7012ddc4ae611c3071ef858e2c69f08` |
| `NsCpuCNMiner64.exe` | `d0326f0ddce4c00f93682e3a6f55a3125f6387e959e9ed6c5e5584e78e737078` |
| `ExecDos.dll` | `42422d912b9c626ad93eb8c036ad82ee67cfa48cf75259c20c327eddd4cc376f` |
| `inetc.dll` | `67eff17c53a78c8ec9a28f392b9bb93df3e74f96f6ecd87a333a482c36546b3e` |
| `makensis.exe` | `572a6f9cb5b37b6eec13b578d346c2568ce3ec88bb711d75dac9e82fc01c8860` |

### File Paths
*   `C:\Users\<user>\AppData\Roaming\NsMiner\`
*   `C:\Users\<user>\AppData\Local\Temp\info.zip`
*   `C:\Users\<user>\AppData\Local\Temp\tftp.exe`

### Network Indicators

**Domains:**
*   `hrtests.ru` (Primary C2)
*   `testswork.ru` (Secondary C2)

**Full URL:**
*   `http://hrtests.ru/S.php` (C2 Beacon Endpoint)

**FTP Target Server IPs (Credential Stuffing Targets):**
*   `162.150.119.10`
*   `136.0.88.10`
*   `45.156.140.10`
*   `214.192.190.10`
*   `235.31.147.10`
*   `56.255.40.10`
*   `85.230.83.10`
*   `251.46.111.10`
*   `63.192.224.10`
*   `202.24.217.10`
*   `134.211.96.10`
*   `223.50.252.10`
*   `13.180.6.10`
*   `116.62.22.10`
*   `94.158.41.10`
*   `252.158.2.10`
*   `110.188.25.10`
*   `141.227.248.10`

---

## License

© 2026 Joseph. All rights reserved. See LICENSE for terms.
