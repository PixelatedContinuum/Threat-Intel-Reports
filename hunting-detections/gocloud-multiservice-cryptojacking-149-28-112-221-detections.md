---
title: "Detection Rules — GOCLOUD Multi-Service Cryptojacking"
date: '2026-07-26'
layout: post
permalink: /hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
hide: true
---

**Campaign:** GOCLOUD-MultiService-Cryptojacking-149.28.112.221
**Date:** 2026-07-26
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/gocloud-multiservice-cryptojacking-149-28-112-221/

---

## Detection Coverage Summary

GOCLOUD is a two-node commodity cryptojacking operation: a payload host and exploit engine on one server, and an OmniHunter orchestrator plus reverse-shell C2 on a second. Both hosts are now partly or fully dark, the wallet is public, and the Windows branch mines to a checksum-invalid address. The durable value for defenders is therefore the behavioural tradecraft, which generalises across this entire commodity-cryptojacking tier, not the atomics. Every rule below is anchored on a behaviour, a protocol shape, or a distinctive multi-string toolkit fingerprint. Hard-coded IP, hash, single-domain, and wallet indicators are routed to the companion IOC feed rather than authored as rules, per the detection-rule-tiering standard.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 7 | 0 | T1036.005, T1564.001, T1496.001, T1071.001, T1190, T1596.005, T1021.002, T1053.005, T1543.002, T1571, T1685, T1105 | 40+ file hashes |
| Sigma | 6 | 5 | T1036.005, T1685, T1105, T1140, T1053.005, T1564.001, T1496.001, T1059.005, T1021.002, T1059.001, T1543.002 | task names, Run key, dropped paths |
| Suricata | 4 | 1 | T1071.001, T1021.002, T1570, T1105 | 2 operator IPs, 9 URLs, 4 pool domains |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting, and expect to review the hits.

**Validation status.** Every YARA rule compiles clean on `yarac` (0 errors). Every Sigma rule passes SigmaHQ `sigma check` (0 errors, 0 issues) against the ATT&CK v19 validator config and yamllint. Every Suricata rule was accepted by the real `suricata -T` engine on the sensor.

---

## Multi-Family Organization

This is one operation assembled from several named components, so rules are grouped type → tier → component. The component labels used below:

- **GOCLOUD Windows worm + miner (凌凯矿机)**, the internet-cafe deployment and LAN-propagation chain (`deploy.ps1`, `allinone.ps1`, `winminer.ps1`, `worm.vbs`, `infect.ps1`).
- **GOCLOUD Linux miner**, the cross-platform XMRig deployer and its heartbeat (`miner.sh`, GOCLOUD miner v7).
- **GOCLOUD / OmniHunter exploitation tooling**, the mass-exploitation dispatchers (`batch_exploit.py`, `fofa_batch.py`, `omnihunter.py`).
- **GOCLOUD node-2 C2 + LAN probe**, the reverse-shell control plane and the lateral-movement probe (`listener2.py`, `a.py`).

Where a behaviour is common to more than one component, a **Campaign-Level** label is used.

---

## YARA Rules

All node-1 samples are plain-text scripts, so these rules carry no PE or ELF magic check and instead anchor on distinctive multi-string combinations bounded by a file-size ceiling. No rule is written for the node-2 `xmrig.exe` or `WinRing0x64.sys`, which are stock binaries a content rule would false-positive on across every legitimate XMRig install.

### Detection Rules

**GOCLOUD Windows worm + miner (凌凯矿机)**

#### GOCLOUD_Windows_Deploy_Worm_Lingkai

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1036.005 (Masquerading), T1053.005 (Scheduled Task), T1021.002 (SMB Admin Shares), T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**False Positives:** None known. The combination of the operator's mining-estate brand, the TimeService masquerade path, and the checksum-invalid typo wallet is unique to this toolkit.
**Blind Spots:** Misses variants that rebrand the estate name and change all three scheduled-task names; a fully rewritten deployer with a different wallet would not match.
**Validation:** Fire it against `deploy.ps1` / `allinone.ps1` / `setup.bat`; a benign PowerShell installer or a legitimate XMRig config must NOT fire.
**Deployment:** Endpoint file scan, script-drop monitoring on `%APPDATA%` and `%TEMP%`, mail and web gateway.

```yara
rule GOCLOUD_Windows_Deploy_Worm_Lingkai {
   meta:
      description = "Detects the GOCLOUD Windows internet-cafe miner deployment and LAN-propagation scripts (deploy.ps1 / allinone.ps1 / setup.bat, self-branded 凌凯矿机 v3.0) by the combination of the operator's mining-estate brand, its svchost/TimeService masquerade triad, and the checksum-invalid typo Monero wallet live in the runtime config"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "f4c5ab27bceb6ab6c6ec8f48b3b84701a0ba6966e30042bf5765a5d97018b5d2"
      hash2 = "f42af99f65f1edeb5ed13b3f68643e7d8abacfceb878ba7e79581caedbd7f09f"
      hash3 = "6780e9cc6cad66975bb7d895cd0944b72c5a843b80f6c4fef3cc4ebeb1ce628a"
      family = "GOCLOUD"
      malware_type = "Cryptojacking deployer / LAN worm"
      id = "5fec8734-b59b-5046-9a52-36e8061fb674"
   strings:
      $brand    = "凌凯矿机" ascii wide
      $netbar   = "网吧" ascii wide
      $task1    = "WindowsTimeSync" ascii wide fullword
      $task2    = "WindowsWatchdog" ascii wide fullword
      $path     = "Microsoft\\Windows\\TimeService" ascii wide nocase
      $wallettp = "42CThVKA9SxeeQDT8EcBK7UHNFFREDw3q7W5ZyyoGvGufDVPbKzYb3Bap9z9qor7jwAU23r3jKHyoZCSYH8eK4a9BUyTRrE" ascii wide
      $pool     = "pool.supportxmr.com:443" ascii wide nocase
      $attr     = "attrib +H +S" ascii wide nocase
   condition:
      filesize < 80KB and
      ( $wallettp or 3 of them )
}
```

#### GOCLOUD_Windows_Miner_WinJenkins

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1685 (Disable or Modify Tools), T1071.001 (Web Protocols), T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**False Positives:** None known. The WinJenkinsHeartbeat task name paired with the `win_jenkins_` pool-password convention and the pre-download Defender disable is specific to this deployer.
**Blind Spots:** Misses a rebuilt deployer that renames the heartbeat task and abandons the `win_jenkins_` worker convention.
**Validation:** Fire it against `winminer.ps1`; a benign miner-management script must NOT fire.
**Deployment:** Endpoint file scan, PowerShell script-drop monitoring.

```yara
rule GOCLOUD_Windows_Miner_WinJenkins {
   meta:
      description = "Detects the GOCLOUD winminer.ps1 Windows XMRig deployer by its WinJenkinsHeartbeat scheduled-task persistence, the per-host win_jenkins_ pool-password convention, pre-download Defender real-time-monitoring disable, and the fixed-order /r?host= mining heartbeat"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "004315d53cc4e68b16f0a1acb1f09d9501ea26e6fde1686b2018cd677a346c5c"
      hash2 = "446fedd99169500bbd34de06bc5890de445d7280"
      hash3 = "dbfc0b53520ad8ef434b38f322a91388"
      family = "GOCLOUD"
      malware_type = "Cryptojacking deployer"
      id = "2bf3f5bb-c1e9-5399-836e-8d4ed6b0bf60"
   strings:
      $task   = "WinJenkinsHeartbeat" ascii wide fullword
      $pass   = "win_jenkins_" ascii wide
      $defoff = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
      $hb     = "/r?host=" ascii wide
      $worker = "winjenkins_" ascii wide
      $donate = "\"donate-level\": 0" ascii wide
   condition:
      filesize < 40KB and
      3 of them
}
```

**GOCLOUD Linux miner**

#### GOCLOUD_Linux_Miner_v7

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1564.001 (Hidden Files and Directories), T1071.001 (Web Protocols), T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**False Positives:** None known. The dot-suffixed X11-socket-lookalike directory string and the GOCLOUD miner v7 banner do not appear in the legitimate c3pool installer.
**Blind Spots:** Misses a rebuilt deployer that drops the banner and changes the hiding-directory naming; the served static `config.json` fast path carries a `WORKER` placeholder and will not match the worker-label string.
**Validation:** Fire it against `miner.sh`; a stock c3pool `setup_c3pool_miner.sh` must NOT fire.
**Deployment:** Linux endpoint file scan, `/tmp` write monitoring.

```yara
rule GOCLOUD_Linux_Miner_v7 {
   meta:
      description = "Detects the GOCLOUD miner.sh Linux XMRig deployer (GOCLOUD miner v7) by its self-branded banner, the /tmp/.X11-unix. dot-suffixed X11-socket-lookalike hiding directory, the c3pool_miner.service persistence unit, the gocloud_ worker-label convention, and the fixed-order /r?host= heartbeat"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "5194aa67974a69549f1f839c973ca17cc0ce8c6ca41ab199d74599befba08db7"
      hash2 = "5fe34b31fe3e3c741456ae6d3c55677cd1aff608"
      hash3 = "6177ab813f6bfeba9c3ec6aeeeb5780a"
      family = "GOCLOUD"
      malware_type = "Cryptojacking deployer"
      id = "fd42d64a-f3ac-51b4-b450-523467161f37"
   strings:
      $banner = "GOCLOUD miner v7" ascii nocase
      $x11    = "/tmp/.X11-unix." ascii
      $svc    = "c3pool_miner.service" ascii
      $worker = "gocloud_" ascii
      $hb     = "/r?host=" ascii
      $pool   = "auto.c3pool.org:19999" ascii nocase
   condition:
      filesize < 40KB and
      ( ( $x11 and 2 of them ) or ( 4 of them ) )
}
```

**GOCLOUD / OmniHunter exploitation tooling**

#### GOCLOUD_BatchExploit_Dispatcher

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1596.005 (Scan Databases), T1059.006 (Python), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. The GOCLOUD BatchExploit self-brand and the operator's live FOFA API key are not shared by benign scanning tooling.
**Blind Spots:** Misses a fork that rotates the FOFA key and drops the brand string; the FOFA key alone is an atomic and is also carried in the IOC feed.
**Validation:** Fire it against `batch_exploit.py` / `fofa_batch.py`; a generic FOFA client library must NOT fire.
**Deployment:** Server-side file scan on suspected staging hosts, retro-hunt across script corpora.

```yara
rule GOCLOUD_BatchExploit_Dispatcher {
   meta:
      description = "Detects the GOCLOUD BatchExploit central exploit dispatcher and its FOFA targeting engine (batch_exploit.py / fofa_batch.py) by the self-brand string, the operator's live FOFA API key, the ex_ prefixed exploit function family, and the miner.sh|bash delivery one-liner"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "55aec7f75af2e0489ff72c28322eccdfbc946cc00f539c2051382877cac03426"
      hash2 = "a4f85666972d0d2714153df0e74e3547ae304f3d"
      hash3 = "03164fbe18dde4df7d2838875de0b3f3"
      family = "GOCLOUD"
      malware_type = "Mass-exploitation dispatcher"
      id = "7500809e-561b-5ad7-99e7-5b77da81cce5"
   strings:
      $brand   = "GOCLOUD BatchExploit" ascii
      $fofakey = "b435f2336553ea069d3848ac2c4574aa" ascii
      $ex1     = "def ex_redis" ascii
      $ex2     = "def ex_jenkins" ascii
      $deliver = "miner.sh|bash" ascii
      $dict    = "EXPLOIT = {" ascii
      $cn      = "country=\"CN\"" ascii
   condition:
      filesize < 200KB and
      ( $brand or $fofakey ) and
      2 of ($ex1, $ex2, $deliver, $dict, $cn)
}
```

#### GOCLOUD_OmniHunter_v4_Orchestrator

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1190 (Exploit Public-Facing Application), T1596.005 (Scan Databases), T1505.003 (Web Shell)
**Confidence:** HIGH
**False Positives:** None known. The tomcatwar.jsp webshell name and the hard-coded Hikvision iSecure session cookie are operator artefacts, not generic scanner strings.
**Blind Spots:** Misses OmniHunter v1/v2 (untraced) and any v5 that renames its modules or rotates the Hikvision cookie.
**Validation:** Fire it against `omnihunter.py`; a benign vulnerability scanner must NOT fire.
**Deployment:** Server-side file scan, retro-hunt across script corpora.

```yara
rule GOCLOUD_OmniHunter_v4_Orchestrator {
   meta:
      description = "Detects the GOCLOUD OmniHunter v4 exploitation orchestrator (omnihunter.py, node 2) by its self-brand, the operator's shared FOFA API key, the tomcatwar.jsp webshell filename, the hardcoded Hikvision iSecure session cookie, and the rce_ prefixed module naming that distinguishes it from the ex_ GOCLOUD dispatcher"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "cee14e449b9da683734b1f4122a40f1d6e478fe93015702137b62a79a5414ad3"
      family = "GOCLOUD"
      malware_type = "Mass-exploitation orchestrator"
      id = "feb7afed-e952-5d6f-9b20-ff4e070e0bf6"
   strings:
      $brand   = "OmniHunter" ascii
      $fofakey = "b435f2336553ea069d3848ac2c4574aa" ascii
      $shell   = "tomcatwar.jsp" ascii nocase
      $hik     = "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169" ascii
      $rce     = "def rce_" ascii
      $meta    = "def rce_metabase" ascii
   condition:
      filesize < 200KB and
      $brand and
      2 of ($fofakey, $shell, $hik, $rce, $meta)
}
```

**GOCLOUD node-2 C2 + LAN probe**

#### GOCLOUD_Listener2_Control_Plane

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1571 (Non-Standard Port), T1059.006 (Python), T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. The CONTROL_PORT 9997 interface with `list` / `all:` broadcast verbs and the auto-pushed `id` on connect is distinctive controller code.
**Blind Spots:** Misses the co-resident listener variants (`listener.py`, `fast_listener.py`) that were never captured, and any rewrite that changes the control port and verbs.
**Validation:** Fire it against `listener2.py`; a benign netcat-style listener must NOT fire.
**Deployment:** Server-side file scan on suspected C2 hosts.

```yara
rule GOCLOUD_Listener2_Control_Plane {
   meta:
      description = "Detects the GOCLOUD node-2 reverse-shell control plane (listener2.py) by its unauthenticated CONTROL_PORT 9997 operator interface, the list / all: broadcast verbs, the fixed 4444-8888 shell-catch port set, and the id command auto-pushed on every reverse-shell connect"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "f800c809dfdc0ce22be0fe638734212380d99293fc466242b3fea6e6e858e9df"
      family = "GOCLOUD"
      malware_type = "Reverse-shell C2 controller"
      id = "986a37d8-3e5f-511e-b6f7-3569e89a1c54"
   strings:
      $ctl     = "CONTROL_PORT" ascii
      $port    = "9997" ascii
      $verb1   = "all:" ascii
      $verb2   = "list" ascii
      $ports   = "4444" ascii
      $auto    = "id\\n" ascii
   condition:
      filesize < 60KB and
      $ctl and $port and 2 of ($verb1, $verb2, $ports, $auto)
}
```

#### GOCLOUD_LAN_Probe_Attack_Banner

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1021.002 (SMB Admin Shares), T1570 (Lateral Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. The cleartext `=== ATTACK ===` banner with SMB / WMI / SCHTASKS result markers is unique to this probe.
**Blind Spots:** `a.py` writes only canary payloads (`calc.exe`, text files), so a match confirms the probe, not an active miner drop; a renamed banner would not match.
**Validation:** Fire it against `a.py`; a benign SMB administration script must NOT fire.
**Deployment:** Server-side file scan, retro-hunt across script corpora.

```yara
rule GOCLOUD_LAN_Probe_Attack_Banner {
   meta:
      description = "Detects the GOCLOUD node-2 LAN lateral-movement probe (a.py) by its cleartext === ATTACK === report banner, the SMB / WMI / SCHTASKS OK result markers it posts back to the operator, and its sequential net use against C$ / ADMIN$ / IPC$ administrative shares"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/"
      date = "2026-07-26"
      hash1 = "44a14aafec8482f691801e28a3893c1ae1fdfbbed4dce963b002b7095f6cb120"
      family = "GOCLOUD"
      malware_type = "LAN lateral-movement probe"
      id = "e8cbbcc2-83b7-59dd-8e4e-b80ea72a5a4f"
   strings:
      $banner = "=== ATTACK ===" ascii
      $smb    = "SMB" ascii
      $wmi    = "WMI" ascii
      $sch    = "SCHTASKS" ascii
      $ok     = "OK!" ascii
      $c      = "ADMIN$" ascii
      $ipc    = "IPC$" ascii
   condition:
      filesize < 60KB and
      $banner and 3 of ($smb, $wmi, $sch, $ok, $c, $ipc)
}
```

---

## Sigma Rules

All rules use ATT&CK v19 tactic tags and pass SigmaHQ `sigma check` with 0 issues. Rules are `status: experimental`; promotion to `test` happens upstream after production exposure.

### Detection Rules

**GOCLOUD Windows worm + miner (凌凯矿机)**

#### Svchost Executed From Non-System Directory

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** Rare third-party software that ships a bundled binary literally named svchost.exe outside the system tree.
**Blind Spots:** Misses a miner that keeps the binary inside System32 or masquerades under a different system-process name.
**Validation:** Run a renamed XMRig from `%APPDATA%\Microsoft\Windows\TimeService\svchost.exe` and confirm it fires; a genuine `C:\Windows\System32\svchost.exe` must NOT fire.
**Deployment:** EDR / Sysmon Event ID 1.

```yaml
title: Svchost.EXE Executed From Non-System Directory
id: d1fb7553-97d4-45f2-a10b-3f36ed4a242b
status: experimental
description: >-
    Detects svchost.exe executing from a path outside System32 or SysWOW64. The GOCLOUD
    cryptojacking toolkit renames its XMRig miner to svchost.exe and runs it from a
    TimeService folder under the user AppData tree, a masquerade legitimate Windows service
    host processes never perform.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.stealth
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter_main_legit_path:
        Image|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
    condition: selection and not filter_main_legit_path
falsepositives:
    - Third-party software that ships a bundled binary named svchost.exe outside the system tree
level: high
```

#### Defender Real-Time Monitoring Disabled With Exclusion Added

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Disable or Modify Tools)
**Confidence:** HIGH
**False Positives:** Endpoint-management scripts that intentionally reconfigure Defender.
**Blind Spots:** Requires Script Block Logging; misses tampering performed through the registry or WMI rather than the Set-MpPreference cmdlet pairing.
**Validation:** Run the GOCLOUD miner install and confirm both the disable and the exclusion-add fire together; a single legitimate `Set-MpPreference` with no exclusion-add must NOT fire.
**Deployment:** PowerShell Script Block logging (Event ID 4104).

```yaml
title: Defender Real-Time Monitoring Disabled With Exclusion Added
id: 11c51f72-48bd-43d5-9a5d-2d0da40f5ccf
status: experimental
description: >-
    Detects a PowerShell script block that both disables Windows Defender real-time monitoring
    and adds a scan exclusion path. The GOCLOUD Windows miner performs both actions before any
    payload download so the miner it drops is never scanned.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: ps_script
    product: windows
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_disable:
        ScriptBlockText|contains: 'Set-MpPreference -DisableRealtimeMonitoring'
    selection_exclude:
        ScriptBlockText|contains: 'Add-MpPreference -ExclusionPath'
    condition: all of selection_*
falsepositives:
    - Endpoint-management scripts that intentionally reconfigure Defender
level: high
```

#### Certutil Download Cradle Fetching Remote Payload

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files or Information)
**Confidence:** HIGH
**False Positives:** Rare administrative use of certutil to retrieve certificate revocation data.
**Blind Spots:** Misses payload delivery via BITS, curl, or PowerShell download methods rather than certutil.
**Validation:** Run the GOCLOUD WMI LAN-spread step and confirm the `certutil -urlcache -split -f http://...` fetch fires; benign certutil certificate operations must NOT fire.
**Deployment:** EDR / Sysmon Event ID 1.

```yaml
title: Certutil Download Cradle Fetching Remote Payload
id: 28a3b008-b1d3-4eab-bb33-d31c35e62973
status: experimental
description: >-
    Detects certutil.exe used as a download cradle with the urlcache and split flags to fetch
    a remote file over HTTP. The GOCLOUD Windows worm uses this to pull deploy.bat to the temp
    directory during WMI-based LAN propagation.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.command-and-control
    - attack.stealth
    - attack.t1105
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_urlcache:
        CommandLine|contains:
            - '-urlcache'
            - '/urlcache'
    selection_split:
        CommandLine|contains:
            - '-split'
            - '/split'
    selection_http:
        CommandLine|contains: 'http'
    condition: selection_img and selection_urlcache and selection_split and selection_http
falsepositives:
    - Rare administrative use of certutil to retrieve certificate revocation data
level: high
```

#### Remote Scheduled Task Creation Running As SYSTEM

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**False Positives:** Enterprise administration tools that provision SYSTEM scheduled tasks on remote hosts.
**Blind Spots:** Misses lateral movement via WMI, service creation, or WinRM rather than remote schtasks; a token-riding worm that already holds admin on the target may still trip it.
**Validation:** Run the GOCLOUD worm's LAN-spread against a lab host and confirm the remote `schtasks /create /s <host> /ru SYSTEM` fires; routine local task creation must NOT fire.
**Deployment:** EDR / Sysmon Event ID 1 on the source host.

```yaml
title: Remote Scheduled Task Creation Running As SYSTEM
id: 95400021-9144-4baf-9e25-6519fe2ef868
status: experimental
description: >-
    Detects creation of a scheduled task on a remote host running as SYSTEM via schtasks with
    the remote server and run-as SYSTEM flags. The GOCLOUD Windows worm registers a SYSTEM task
    on each freshly reached LAN host and immediately runs it to spread the miner.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_create:
        CommandLine|contains: '/create'
    selection_remote:
        CommandLine|contains: '/s '
    selection_system:
        CommandLine|contains: '/ru SYSTEM'
    condition: all of selection_*
falsepositives:
    - Enterprise administration tools that provision SYSTEM scheduled tasks on remote hosts
level: high
```

#### Scheduled Task Registering SYSTEM Action In User AppData

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1053.005 (Scheduled Task), T1036.005 (Match Legitimate Name or Location)
**Confidence:** HIGH
**False Positives:** Unusual installers that register SYSTEM tasks pointing at per-user AppData paths.
**Blind Spots:** Misses persistence registered through the Task Scheduler API or an XML import that does not pass the AppData path on the schtasks command line.
**Validation:** Run `deploy.ps1` and confirm the WindowsTimeSync task creation with a `%APPDATA%` action and `/ru SYSTEM` fires; a normal per-user task must NOT fire.
**Deployment:** EDR / Sysmon Event ID 1.

```yaml
title: Scheduled Task Registering SYSTEM Action In User AppData
id: ec66df96-4699-45b5-9edd-fbf21d195240
status: experimental
description: >-
    Detects schtasks creating a task whose action runs a binary under a user AppData path with
    SYSTEM privileges. The GOCLOUD miner persists as WindowsTimeSync or WindowsWatchdog pointing
    at a renamed XMRig under the AppData TimeService folder running as SYSTEM.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1053.005
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_create:
        CommandLine|contains: '/create'
    selection_action:
        CommandLine|contains:
            - '\AppData\'
            - '%APPDATA%'
    selection_system:
        CommandLine|contains: '/ru SYSTEM'
    condition: all of selection_*
falsepositives:
    - Unusual installers that register SYSTEM tasks pointing at per-user AppData paths
level: high
```

**GOCLOUD Linux miner**

#### Process Executed From X11-Socket-Lookalike Temp Directory

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories), T1496.001 (Compute Hijacking)
**Confidence:** HIGH
**False Positives:** Unlikely. The standard X11 socket directory `/tmp/.X11-unix/` carries no trailing dot and suffix.
**Blind Spots:** Misses a variant that changes the hiding directory name; requires process-execution telemetry (Sysmon for Linux or auditd) that captures the full image path.
**Validation:** Run `miner.sh` and confirm the XMRig launch from `/tmp/.X11-unix.<rand>` fires; a normal X11 server referencing `/tmp/.X11-unix/` must NOT fire.
**Deployment:** Sysmon for Linux / auditd execve telemetry.

```yaml
title: Process Executed From X11-Socket-Lookalike Temp Directory
id: 03268048-2fb3-40e2-9c26-b3afd233005c
status: experimental
description: >-
    Detects a process executing from a /tmp/.X11-unix. directory carrying a random suffix.
    Legitimate X11 uses the exact directory name without a trailing dot and suffix, so the
    dot-suffixed variant is the GOCLOUD Linux miner hiding location for its XMRig binary.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.stealth
    - attack.impact
    - attack.t1564.001
    - attack.t1496.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: '/tmp/.X11-unix.'
    condition: selection
falsepositives:
    - Unlikely; the standard X11 socket directory does not carry a dot suffix
level: high
```

### Hunting Rules

**GOCLOUD Windows worm + miner (凌凯矿机)**

#### Hidden And System Attributes Set On User AppData Path

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories)
**Confidence:** MODERATE
**False Positives:** Some legitimate applications hide per-user data directories with attrib. Review the target path and the parent process before acting.
**Deployment:** EDR / Sysmon Event ID 1, analyst triage.

```yaml
title: Hidden And System Attributes Set On User AppData Path
id: c9ae87a9-4e58-4daf-8f9c-a8bd074d0510
status: experimental
description: >-
    Detects attrib.exe applying the hidden and system attributes to a path under the user
    AppData tree. The GOCLOUD miner conceals its dropped TimeService directory this way. Broad
    enough that it is intended for hunting rather than direct alerting.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.stealth
    - attack.t1564.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\attrib.exe'
        - OriginalFileName: 'ATTRIB.EXE'
    selection_hidden:
        CommandLine|contains: '+h'
    selection_system:
        CommandLine|contains: '+s'
    selection_path:
        CommandLine|contains: '\AppData\'
    condition: selection_img and selection_hidden and selection_system and selection_path
falsepositives:
    - Some legitimate applications hide per-user data directories
level: medium
```

#### Script Host Executing VBScript From Windows Temp

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.005 (Visual Basic)
**Confidence:** MODERATE
**False Positives:** Legitimate setup scripts occasionally stage a VBScript in a temporary directory. Pivot on the script name and the child processes.
**Deployment:** EDR / Sysmon Event ID 1, analyst triage.

```yaml
title: Script Host Executing VBScript From Windows Temp
id: 5a64b8ea-2ab7-49f8-a202-f4d3b9f2bbc6
status: experimental
description: >-
    Detects wscript.exe or cscript.exe running a VBScript from the Windows Temp folder or a
    public directory. The GOCLOUD worm launches worm.vbs from the Windows Temp folder for its
    subnet LAN sweep. Broad; intended for hunting.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.execution
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\wscript.exe'
        - Image|endswith: '\cscript.exe'
    selection_path:
        CommandLine|contains:
            - '\Windows\Temp\'
            - '\Users\Public\'
    selection_ext:
        CommandLine|contains: '.vbs'
    condition: all of selection_*
falsepositives:
    - Legitimate setup scripts staged in temporary directories
level: medium
```

#### Net Use Mapping Administrative Share With Explicit Credential

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1021.002 (SMB / Windows Admin Shares)
**Confidence:** MODERATE
**False Positives:** Administrative scripts routinely map admin shares for management. The GOCLOUD signal is a blank-password Administrator against C$, ADMIN$, or IPC$ in sequence; triage on the credential and the share set.
**Deployment:** EDR / Sysmon Event ID 1, analyst triage.

```yaml
title: Net Use Mapping Administrative Share With Explicit Credential
id: 4e1b4b06-a18b-46f4-8eed-d1f7baf9e61e
status: experimental
description: >-
    Detects net.exe mapping an administrative share (C$, ADMIN$, IPC$) with an explicit
    credential. The GOCLOUD infect.ps1 and node-2 a.py probe test flat LANs for a shared
    blank-password local administrator before dropping the miner. Broad; intended for hunting.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\net.exe'
        - Image|endswith: '\net1.exe'
    selection_use:
        CommandLine|contains: ' use '
    selection_share:
        CommandLine|contains:
            - 'C$'
            - 'ADMIN$'
            - 'IPC$'
    selection_cred:
        CommandLine|contains: '/u:'
    condition: all of selection_*
falsepositives:
    - Administrative scripts mapping admin shares for legitimate management
level: medium
```

#### PowerShell IEX Download Cradle From Remote Host

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Provisioning and bootstrap scripts legitimately fetch and run remote code. Pivot on the URL and the calling context.
**Deployment:** PowerShell Script Block logging (Event ID 4104), analyst triage.

```yaml
title: PowerShell IEX Download Cradle From Remote Host
id: d8c4a085-a8d2-44ae-a76c-eb509ca19067
status: experimental
description: >-
    Detects a PowerShell download-and-execute cradle combining Invoke-Expression with a web
    request. The GOCLOUD one-click installer uses an iex plus Invoke-WebRequest cradle to pull
    and run allinone.ps1. Broad; intended for hunting.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.execution
    - attack.command-and-control
    - attack.t1059.001
    - attack.t1105
logsource:
    category: ps_script
    product: windows
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_iex:
        ScriptBlockText|contains:
            - 'IEX '
            - 'Invoke-Expression'
    selection_web:
        ScriptBlockText|contains:
            - 'iwr '
            - 'Invoke-WebRequest'
            - 'DownloadString'
    condition: all of selection_*
falsepositives:
    - Provisioning scripts that fetch and run remote code
level: medium
```

**GOCLOUD Linux miner**

#### Systemd Or Cron Executing Binary From Tmp

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1543.002 (Systemd Service), T1496.001 (Compute Hijacking)
**Confidence:** MODERATE
**False Positives:** Some legitimate software executes helper binaries from /tmp. A systemd or cron parent launching a `/tmp` binary is the GOCLOUD miner-persistence shape; triage the binary.
**Deployment:** Sysmon for Linux / auditd execve telemetry, analyst triage.

```yaml
title: Systemd Or Cron Executing Binary From Tmp
id: db92c228-ae52-4960-9957-0a8474cdf072
status: experimental
description: >-
    Detects a process launched directly from /tmp by systemd or cron. The GOCLOUD Linux miner
    persists as a systemd unit and an @reboot crontab entry whose action points at an XMRig
    binary under /tmp. Broad; intended for hunting.
references:
    - https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/
author: The Hunters Ledger
date: 2026-07-26
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.impact
    - attack.t1543.002
    - attack.t1496.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/systemd'
            - '/cron'
            - '/crond'
        Image|startswith: '/tmp/'
    condition: selection
falsepositives:
    - Some legitimate software executes helper binaries from /tmp
level: medium
```

---

## Suricata Signatures

Each signature is one physical line and was accepted by the real `suricata -T` engine. The `sid` values are local placeholders in the 1000000 range; the consolidated public feed maps each rule to a stable published SID. No signature hard-codes an operator IP or domain (those route to the IOC feed), so every rule survives infrastructure rotation.

### Detection Rules

**Campaign-Level (XMRig deployment heartbeat)**

#### GOCLOUD XMRig Heartbeat, Fixed Parameter Order

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known. The `/r?host=` prefix followed by the `&status=OK&ts=` tail in one URI is a distinctive parameter order.
**Blind Spots:** Fires only on the plaintext HTTP heartbeat; a TLS-wrapped or parameter-reordered beacon evades the URI match.
**Validation:** Replay a captured heartbeat GET and confirm it fires; ordinary web browsing must NOT fire.
**Deployment:** IDS / IPS at the network egress.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT GOCLOUD-Cryptojacking XMRig Deployment Heartbeat GET (Fixed Parameter Order to Payload Host)"; flow:established,to_server; http.uri; content:"/r?host="; startswith; nocase; content:"&status=OK&ts="; distance:0; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-26, reference https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/;)
```

#### GOCLOUD XMRig Worker-Label Heartbeat

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known. The `gocloud_` and `winjenkins_` worker-name prefixes are toolkit conventions, not generic query parameters.
**Blind Spots:** A rebuilt deployer that renames its worker prefixes evades; TLS hides the URI. Complements the parameter-order rule so a beacon still trips if the operator reorders parameters.
**Validation:** Replay a heartbeat carrying `worker=gocloud_...` or `worker=winjenkins_...` and confirm it fires.
**Deployment:** IDS / IPS at the network egress.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT GOCLOUD-Cryptojacking XMRig Worker-Label Heartbeat (gocloud_ or winjenkins_ Naming Convention)"; flow:established,to_server; http.uri; content:"worker="; nocase; pcre:"/worker=(gocloud|winjenkins)_/i"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-26, reference https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/;)
```

**GOCLOUD node-2 LAN probe**

#### GOCLOUD LAN Lateral-Movement Report Banner

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1021.002 (SMB / Windows Admin Shares), T1570 (Lateral Tool Transfer)
**Confidence:** HIGH
**False Positives:** None known. The literal `=== ATTACK ===` banner followed by an `OK!` result marker is unique to the `a.py` probe.
**Blind Spots:** Covers only the cleartext report path; an encrypted or reformatted banner evades.
**Validation:** Replay the `a.py` report to the listener and confirm it fires.
**Deployment:** IDS / IPS, internal segment monitoring.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT GOCLOUD-Cryptojacking LAN Lateral-Movement Report Banner (=== ATTACK === Cleartext to Operator)"; flow:established,to_server; content:"=== ATTACK ==="; content:"OK!"; distance:0; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-26, reference https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/;)
```

**GOCLOUD Windows worm (凌凯矿机)**

#### GOCLOUD Windows Worm Component Retrieval

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** HIGH
**False Positives:** Near zero. A legitimate file literally named worm.vbs served over HTTP would be required.
**Blind Spots:** A renamed worm component evades; TLS hides the URI. Sibling filenames `infect.ps1` / `allinone.ps1` / `deploy.ps1` are less distinctive and are left to the IOC-feed URLs rather than a rule.
**Validation:** Request `/worm.vbs` over HTTP and confirm it fires.
**Deployment:** IDS / IPS at the network egress.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT GOCLOUD-Cryptojacking Windows Worm Component Retrieval (worm.vbs over HTTP)"; flow:established,to_server; http.uri; content:"worm.vbs"; endswith; nocase; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-26, reference https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/;)
```

### Hunting Rules

**Campaign-Level (miner delivery)**

#### GOCLOUD Linux Miner Delivery One-Liner

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Any traffic carrying the literal `miner.sh|bash` string, which is rare but possible in benign automation discussion or logs. Triage the flow direction and the surrounding request.
**Deployment:** IDS / IPS, analyst triage.

```
alert tcp any any -> any any (msg:"THL HUNT GOCLOUD-Cryptojacking Linux Miner Delivery One-Liner (miner.sh Piped To Bash)"; flow:established; content:"miner.sh|7c|bash"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-07-26, reference https://the-hunters-ledger.com/hunting-detections/gocloud-multiservice-cryptojacking-149-28-112-221-detections/;)
```

---

## Coverage Gaps

**Most of the node-2 C2 stack was never captured, so the reverse-shell protocol coverage rests on `listener2.py` alone.** The `GOCLOUD_Listener2_Control_Plane` YARA rule and the reasoning behind the `:9997` control verbs come from that single file. The co-resident `payload_server.py`, `listener.py`, `fast_listener.py`, `interact.py`, `shell_cmd.py`, and `start_omni.sh` were not read, so a listener variant that binds different ports or uses different verbs would not be caught, and there is no network signature for the control plane itself because the on-the-wire verb set beyond `list` and `all:` is not fully known. The `id\n` auto-push on connect is too short (three bytes) to anchor a network rule without heavy false positives, so it stays a YARA and host-behaviour signal rather than a Suricata one.

**The deployed OmniHunter v4 code was never captured.** `/opt/omnihunter_v4.py` lives off the served path. The `GOCLOUD_OmniHunter_v4_Orchestrator` YARA rule is anchored on the node-2 `omnihunter.py` sibling, which shares the FOFA key, the webshell name, and the Hikvision cookie but may diverge from the running v4 in module naming. OmniHunter v1 and v2 are untraced on either host, so nothing here covers earlier generations.

**The `:8888` HTML C2 dashboard is uncaptured.** Only its row colours (`#0a0` online, `#a00` dead) are known, inferred from the `redrop.py` and `watchdog2.py` scrapers. No rule covers the dashboard's HTML or its request pattern, so a defender who stood up passive HTTP capture against the panel would have no signature to match.

**The exploitation-request layer is deliberately not duplicated as CVE-labelled rules.** The report documents the request shapes OmniHunter uses (the Metabase setup-token flow, Confluence OGNL in the URI, the Yonyou-NC upload path, Redis unauthenticated cron injection, XXL-Job Groovy). Those grounded N-days already have mature public IDS and WAF coverage, and the toolkit fingerprints above catch the operator's own code directly. Critically, no rule asserts a CVE for Harbor, Seafile, Kibana, Grafana, Splunk, Django debug mode, or Dahua: the investigation established that several of these functions are success-check laxity artefacts (returning true on a 404, a 401, or a 500) rather than working exploits, so a CVE-labelled signature for them would be wrong. Where those services are covered at all, it is through the observed request pattern in the report, not a vulnerability claim.

**Two observed techniques have no high-confidence standalone rule.** Default-account exploitation (T1078.001, the `root:root` / `nacos:nacos` / `admin:Harbor12345` credential set) is an initial-access behaviour with no host or network signature that is not product-specific, so it is left to the credential-hardening guidance in the report. The Windows Run-key persistence (T1547.001, the `WindowsWatchdog` value pointing at `wscript.exe C:\Windows\Temp\worm.vbs`) keys entirely on operator-chosen literals, so it is carried as an atomic in the IOC feed and surfaced behaviourally by the wscript-from-Windows-Temp hunting rule rather than a renameable registry-value rule. WMI-based LAN spread (T1047) is covered only indirectly, through the certutil download cradle the WMI method invokes, not the `Invoke-WmiMethod` call itself.

**Encrypted and third-party-pool traffic is not signatured.** The Windows branch mines over TLS to `pool.supportxmr.com:443` and `xmrpool.eu:443`, which a content rule cannot inspect, and those pools are legitimate third-party services shared by many benign miners, so they are routed to the IOC feed with a MONITOR disposition rather than authored as blocking rules. The typo Monero wallet is checksum-invalid and receives nothing; both wallet variants are matched only as toolkit fingerprint strings inside the multi-string YARA rules, never as a standalone indicator, and never described as an address that credits the operator.

**Both operator hosts are partly or fully dark.** The mature-generation ports on node 1 and all of node 2, including SSH, were unreachable at last check, so the network signatures above are best exercised against captured traffic or a controlled replay rather than live infrastructure. This does not reduce their value for retro-hunting or for the next operator who reuses this widely-copied tradecraft.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.

