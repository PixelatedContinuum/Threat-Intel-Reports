---
title: "Detection Rules — Shadow RAT & XWorm Open Directory Campaign"
date: '2026-04-04'
layout: post
permalink: /hunting-detections/shadow-xworm-opendirectory-detections/
thumbnail: /assets/images/cards/shadow-xworm-opendirectory.png
hide: true
---

**Campaign:** OpenDirectory-DualRAT-MaaS-151.245.112.70
**Date:** 2026-04-04
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/shadow-xworm-opendirectory/

---

## Detection Coverage Summary

Shadow RAT v2.6.4.0 and XWorm 3.0-5.0 are two distinct RAT families distributed from the same open-directory infrastructure (`151.245.112.70`) as part of a dual-family malware-as-a-service operation. Shadow RAT is a heavily modified Quasar RAT fork carrying HVNC, WinRE persistence, and a cryptocurrency clipper; XWorm is a widely-distributed commodity RAT builder configured here with triple-redundant persistence and anti-sandbox checks. Coverage below is reorganized into Detection/Hunting tiers; the campaign's C2 IP:port pairs and delivery/C2 domains are carried in the IOC feed rather than as standalone network signatures.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 1 | T1027, T1027.002, T1573.001, T1542.003, T1685, T1115, T1497.001, T1053.005, T1091 | 0 |
| Sigma | 1 | 9 | T1547.001, T1547.009, T1053.005, T1685, T1686.003, T1553.005, T1497.001, T1082 | 0 |
| Suricata | 0 | 1 | T1497.001 | 5 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient — safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting — expect to review the hits.

**Highest-confidence anchors:**
- The `Shadow.Common.*` namespace root and Costura-embedded `costura.shadow.common.dll.compressed` asset — survive the .NET Reactor packing pass intact, near-zero FP (YARA Detection, both the client and shared-DLL rules).
- XWorm's combination of a 1-minute scheduled-task interval, HIGHEST privilege, and an AppData execution path — a behavioral chokepoint independent of any build-specific literal, so it survives a rebuild that renames the install file, mutex, or task name (Sigma Detection).

**Atomics routed to the IOC feed:** five of the original file's six Suricata rules keyed solely on one hardcoded value — the two C2 IP:port pairs (`151.245.112.70:8990` Shadow RAT, `151.245.112.70:7007` XWorm), the unconfirmed fallback (`151.245.112.70:3000`), and the two delivery/C2 domains (`harrismanlieb.ink`, `epgoldsecurity.com`) — and removing the literal leaves no behavior to detect. All five values were already present in [`shadow-xworm-opendirectory-iocs.json`](/ioc-feeds/shadow-xworm-opendirectory-iocs.json) from the original analysis; no feed edits were required.

---

## Multi-Family Organization

This campaign distributes two unrelated RAT families from one open-directory server. Per-type sections below (YARA / Sigma / Suricata) are **not** duplicated per family — each stays a single H2 section, split into Detection/Hunting tier subsections, with families distinguished by a bold **Shadow RAT v2.6.4.0** / **XWorm 3.0-5.0** label inside each subsection. The one rule that covers behavior common to both families (Zone.Identifier ADS self-deletion) is labeled **Campaign-Level**.

---

## YARA Rules

### Detection Rules

**Shadow RAT v2.6.4.0**

#### Shadow RAT v2.6.4.0 Client — Namespace + Costura Fingerprint

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027.002 (Software Packing — .NET Reactor), T1573.001 (Symmetric Cryptography — AES-256 encrypted C2)
**Confidence:** HIGH
**Rationale:** `Shadow.Common.*` is the namespace root of this Quasar-fork codebase and survives the sample's .NET Reactor packing pass intact; renaming it would require re-architecting the client across every message-handling class. The Costura.Fody marker, the pinned version constant, and the single-instance mutex GUID provide three independent corroborating anchors, so no single renameable literal carries the rule alone.
**False Positives:** None known — the `Shadow.Common.*` namespace hierarchy and `costura.shadow.common.dll.compressed` asset name are distinctive compiled identifiers not present in any known legitimate .NET software.
**Blind Spots:** A full rebrand that renames the `Shadow.*` namespace root and the Costura asset simultaneously would evade; the rule targets the on-disk/in-memory client, not a hypothetical script-only loader.
**Validation:** Scan a Shadow RAT client build (either `hash1` below) — the namespace/version/mutex combination must match; a benign Costura-packed .NET application must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, memory scanner, email gateway attachment scan.

```yara
/*
   Yara Rule Set
   Identifier: Shadow RAT v2.6.4.0 & XWorm 3.0-5.0 — OpenDirectory 151.245.112.70
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule RAT_ShadowRAT_v2640_Client {
   meta:
      description = "Detects Shadow RAT v2.6.4.0 client based on characteristic namespace strings, version constant, and Costura.Fody embedded assembly markers. Shadow RAT is a heavily modified Quasar RAT fork with HVNC, WinRE persistence, crypto clipper, and Kematian stealer integration."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "3a4b0f50ea3eac55e22cbf24d873f9a1632d8f71e1fba91178c539030626ab32"
      hash2 = "ad4e81b84f3c6f8b30863f90e8a09631112b0f5b"
      hash3 = "f162419fce4eb4dff92be342c47662c2"
      family = "ShadowRAT"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "70a5875f-aff5-5059-8daa-5bede1500425"
   strings:
      $s1 = "Shadow.Common.Messages" ascii wide
      $s2 = "Shadow.Common.Cryptography" ascii wide
      $s3 = "Shadow.Client.Steam" ascii wide
      $s4 = "2.6.4.0" ascii wide
      $s5 = "4c7e33e6-3f73-4b4c-a411-89fe63cdfa1e" ascii wide
      $s6 = "costura.shadow.common.dll.compressed" ascii wide nocase
      $s7 = "Shadow Client" ascii wide
      $s8 = "Shadow Client Startup" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         3 of ($s1, $s2, $s3, $s6) or
         ($s4 and $s5) or
         ($s7 and $s8 and 1 of ($s1, $s2, $s3))
      )
}
```

#### Shadow RAT v2.6.4.0 — Shadow.Common.dll Shared Library

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1573.001 (Symmetric Cryptography — AES-256 crypto), T1542.003 (Bootkit — WinRE namespace presence)
**Confidence:** HIGH
**Rationale:** `Shadow.Common.Cryptography.Aes256` is a distinctive, family-specific class name required alongside two of four message-namespace strings drawn from separate functional areas (HVNC, GDI, WinRE client-management, DNS) — an operator would need to rename the crypto class and rework multiple unrelated namespace branches simultaneously to evade.
**False Positives:** None known — `Shadow.Common.Cryptography.Aes256` does not appear in any known legitimate .NET library.
**Blind Spots:** Misses a rebrand that renames the crypto class and strips the namespace strings; a memory-only extraction that never touches disk needs the memory-scan deployment path.
**Validation:** Scan `Shadow.Common.dll` (`hash1` below) — the crypto class plus 2-of-4 namespace requirement must match; a benign .NET library implementing AES independently must NOT fire.
**Deployment:** Endpoint file scan, memory scanner (for extracted Costura.Fody assemblies).

```yara
rule RAT_ShadowRAT_CommonDLL {
   meta:
      description = "Detects Shadow.Common.dll, the shared library component of Shadow RAT containing core message types, AES-256 crypto, and protobuf-net serialization. This DLL is embedded via Costura.Fody and extracted at runtime. Matches on disk and in memory."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
      hash2 = "3ef537af9aad6edc6792d53e25124a1649e5f655"
      hash3 = "e4736090733ca81eeabdb16b4b8f9cc3"
      family = "ShadowRAT"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "1410182a-22e9-5c3e-a7f6-4506067f23f1"
   strings:
      $s1 = "Shadow.Common.Messages.Monitoring.HVNC" ascii
      $s2 = "Shadow.Common.Messages.FunStuff.GDI" ascii
      $s3 = "Shadow.Common.Messages.ClientManagement.WinRE" ascii
      $s4 = "Shadow.Common.DNS.HostsManager" ascii
      $s5 = "Shadow.Common.Cryptography.Aes256" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      $s5 and 2 of ($s1, $s2, $s3, $s4)
}
```

#### Shadow RAT v2.6.4.0 — AMSI + ETW Bypass Chain

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Disable or Modify Tools — AMSI + ETW bypass), T1027 (Obfuscated Files or Information — asterisk-padding obfuscation)
**Confidence:** HIGH
**Rationale:** The 15-byte AMSI patch shellcode is a technique chokepoint (the exact bytes needed to make `AmsiScanBuffer` return `E_INVALIDARG`) — legitimate software never embeds this sequence. The two OR'd string-combination branches add corroborating coverage from the asterisk-padding deobfuscation pattern used to hide the `amsi`/`Buffer`/`EtwEv`/`ntdll` literals from static string scanners.
**False Positives:** None known from the byte pattern itself. The third branch (`.Replace("*","") + "EtwEv" + "ntdll"`) carries modest residual risk since `ntdll` alone is a common substring in P/Invoke-heavy .NET code, but requiring all three terms together makes an incidental benign collision unlikely.
**Blind Spots:** A build using a different register/opcode encoding to achieve the same `E_INVALIDARG` return, or one that strips the asterisk-obfuscated literals entirely, evades the corresponding branch (though the byte pattern branch stands independently).
**Validation:** Scan a Shadow RAT client build (`hash1` below) — the shellcode bytes or the obfuscated-string combination must match; a benign .NET binary referencing `ntdll.dll` in ordinary P/Invoke declarations must NOT fire on that branch alone (it also requires `.Replace("*","")` and `EtwEv`).
**Deployment:** Endpoint AV/EDR file scan, memory scanner.

```yara
rule RAT_ShadowRAT_AMSI_ETW_Bypass {
   meta:
      description = "Detects Shadow RAT v2.6.4.0 AMSI and ETW bypass chain. AMSI bypass patches AmsiScanBuffer with a 15-byte shellcode returning E_INVALIDARG (0x80070057). ETW bypass patches EtwEventWrite with a single RET instruction. Both API names are obfuscated using asterisk-padding with runtime Replace() deobfuscation to evade static analysis."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "3a4b0f50ea3eac55e22cbf24d873f9a1632d8f71e1fba91178c539030626ab32"
      hash2 = "ad4e81b84f3c6f8b30863f90e8a09631112b0f5b"
      hash3 = "f162419fce4eb4dff92be342c47662c2"
      family = "ShadowRAT"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "ea233024-9c51-5881-a0a3-482fac88cb2f"
   strings:
      // AMSI bypass shellcode: mov eax,0x80070057; mov rax,[rsp]; add rsp,8; jmp rsp
      $b1 = { B8 57 00 07 80 48 8B 04 24 48 83 C4 08 FF E4 }
      // Asterisk-padding deobfuscation pattern
      $s1 = ".Replace(\"*\", \"\")" ascii
      // Obfuscated amsi.dll string fragment
      $s2 = "m*s*i" ascii
      // Obfuscated AmsiScanBuffer string fragment
      $s3 = "Buf*f*er" ascii
      // Obfuscated EtwEventWrite string fragment
      $s4 = "EtwEv" ascii
      // Obfuscated ntdll.dll string fragment
      $s5 = "ntdll" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 5MB and
      (
         $b1 or
         ($s1 and $s2 and $s3) or
         ($s1 and $s4 and $s5)
      )
}
```

#### Shadow RAT v2.6.4.0 — Cryptocurrency Clipper Module

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1115 (Clipboard Data)
**Confidence:** HIGH
**Rationale:** `SetClipboardMonitoringEnabled` and `SendClipboardData` are custom message-handler method names, not Windows APIs — no legitimate software implements these exact identifiers. Requiring both plus two of three currency-address field names means an operator would need to rename the clipper's entire method-naming convention to evade.
**False Positives:** None known — `SetClipboardMonitoringEnabled` is not a Windows API; it is a custom Shadow RAT message handler method name.
**Blind Spots:** A rebuild that renames both handler methods and the currency field names evades; targets the on-disk client/DLL, not a memory-only injected variant.
**Validation:** Scan `Shadow.Common.dll` (`hash1` below) — both handler names plus 2-of-3 currency fields must match; a benign clipboard-utility application must NOT fire.
**Deployment:** Endpoint file scan, memory scanner.

```yara
rule RAT_ShadowRAT_Crypto_Clipper {
   meta:
      description = "Detects Shadow RAT crypto clipper module via clipboard monitoring method names paired with multi-currency address fields (BTC/LTC/ETH) in Shadow.Common.dll. Enables real-time substitution of victim cryptocurrency addresses during financial transactions."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
      hash2 = "3ef537af9aad6edc6792d53e25124a1649e5f655"
      hash3 = "e4736090733ca81eeabdb16b4b8f9cc3"
      family = "ShadowRAT"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "bfad2681-f3ae-59ca-81ac-8bab2eabf913"
   strings:
      $s1 = "SetClipboardMonitoringEnabled" ascii wide
      $s2 = "SendClipboardData" ascii wide
      $s3 = "BitcoinAddress" ascii wide
      $s4 = "LitecoinAddress" ascii wide
      $s5 = "EthereumAddress" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      $s1 and $s2 and
      2 of ($s3, $s4, $s5)
}
```

#### Shadow RAT v2.6.4.0 — WinRE Persistence Module

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1542.003 (Bootkit — WinRE persistence)
**Confidence:** HIGH
**Rationale:** `DoAddWinREPersistence`/`DoRemoveWinREPersistence` and the `Shadow.Common.Messages.ClientManagement.WinRE` namespace string are unique compiled identifiers to this family. WinRE persistence survives OS reinstallation and has limited EDR behavioral coverage, making file-level detection the primary viable layer.
**False Positives:** None known — method names and namespace are specific to Shadow RAT; no known legitimate software uses these identifiers.
**Blind Spots:** A rebrand that renames both the method names and the namespace evades; does not cover the WinRE persistence mechanism at runtime (no dynamic confirmation of the actual boot-time hook).
**Validation:** Scan `Shadow.Common.dll` (`hash1` below) — one of the two method names plus the namespace string must match; unrelated WinRE-management tooling (e.g., legitimate recovery utilities) must NOT fire.
**Deployment:** Endpoint file scan, memory scanner.

```yara
rule RAT_ShadowRAT_WinRE_Persistence {
   meta:
      description = "Detects Shadow RAT WinRE persistence module via command handler method names and namespace string in Shadow.Common.dll. WinRE persistence survives OS reinstallation and is an uncommon technique with limited EDR behavioral coverage — file-level detection is the primary viable layer."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "6682f3b4568807b0e57acbf2acd627e25be44304cac9241f2b51efa892aaab0c"
      hash2 = "3ef537af9aad6edc6792d53e25124a1649e5f655"
      hash3 = "e4736090733ca81eeabdb16b4b8f9cc3"
      family = "ShadowRAT"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "fd61e389-8b85-5701-9449-0b9230e9157c"
   strings:
      $s1 = "DoAddWinREPersistence" ascii wide
      $s2 = "DoRemoveWinREPersistence" ascii wide
      $s3 = "Shadow.Common.Messages.ClientManagement.WinRE" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      ($s1 or $s2) and $s3
}
```

**XWorm 3.0-5.0**

#### XWorm 3.0-5.0 — Config and Builder Markers

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information — config encryption), T1497.001 (Virtualization/Sandbox Evasion: System Checks — hosting detection), T1053.005 (Scheduled Task — schtask persistence), T1091 (Replication Through Removable Media — USB spread)
**Confidence:** HIGH
**Rationale:** Only the first OR-branch depends on this campaign's build-specific config keys; the second and third branches (`<Xwormmm>` group tag + `ip-api.com` hosting check; hosting check + 1-minute schtask flag + `USB.exe`) key entirely on default XWorm 3.0-5.0 builder markers that persist across builds and operators, so the rule keeps detecting this family even if the campaign-specific config keys rotate on a rebuild.
**False Positives:** None known — the config keys double as process mutexes unique to XWorm builder output, and the `USB.exe`/hosting-check/schtask combination has no known legitimate collision. `USB.exe` alone is a generic filename, but the 3-way AND requirement mitigates that.
**Blind Spots:** A heavily customized fork that changes the group tag, removes the ip-api.com hosting check, and renames `USB.exe` simultaneously would evade all three branches.
**Validation:** Scan an XWorm 3.0-5.0 build (either `hash1` below) — at least one branch must match; a benign remote-access or hosting-diagnostic tool must NOT fire.
**Deployment:** Endpoint AV/EDR file scan, email gateway attachment scan.

```yara
rule RAT_XWorm_30_50_Config {
   meta:
      description = "Detects XWorm 3.0-5.0 builder output based on campaign-specific config AES keys, the group tag <Xwormmm>, ip-api.com hosting detection string, and triple persistence indicators. The config key strings double as process mutexes in XWorm's implementation."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
      hash2 = "e69e32522835f37f18095e219385057b6bbdc959"
      hash3 = "7e2fe58934874e442cfa183a34ceb24c"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "763299ce-a94a-533d-b3bf-7bbd804769ae"
   strings:
      // Campaign-specific config AES keys (also used as process mutexes)
      $s1 = "PdqPY2fw6ffCVLQ8" ascii wide
      $s2 = "ZdoNsjYfT6begqDl" ascii wide
      // Runtime C2 encryption key decrypted from config
      $s3 = "Nothing2hide" ascii wide
      // Builder group tag
      $s4 = "<Xwormmm>" ascii wide
      // Anti-analysis hosting check URL
      $s5 = "ip-api.com/line/?fields=hosting" ascii wide
      // Scheduled task persistence argument
      $s6 = "/create /f /sc minute /mo 1" ascii wide
      // USB spread filename
      $s7 = "USB.exe" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      (
         (1 of ($s1, $s2) and ($s3 or $s4)) or
         ($s4 and $s5) or
         ($s5 and $s6 and $s7)
      )
}
```

### Hunting Rules

**XWorm 3.0-5.0**

#### XWorm 3.0-5.0 — Rijndael-256-ECB Config Crypto Pattern

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1027 (Obfuscated Files or Information — config encryption), T1497.001 (Virtualization/Sandbox Evasion: System Checks — anti-analysis checks)
**Confidence:** MODERATE
**Rationale:** All four mandatory strings (`RijndaelManaged`, `ECB`, `MD5CryptoServiceProvider`, `FromBase64String`) are standard .NET Framework class/method names used by countless legitimate and unrelated malicious crypto implementations — this is a common "insecure but simple" pattern copied broadly across many code bases, not a Shadow/XWorm-specific construction on its own. Two of the three corroborating anti-analysis strings (`Win32_ComputerSystem`, `IsAttached`) are themselves generic terms; only `SbieDll` is genuinely distinctive. This durable-but-generic technique pattern belongs in Hunting, matching the original analysis's own framing as a supporting indicator.
**False Positives:** Individual strings appear routinely in legitimate .NET applications using cryptography or WMI/system queries; the combination is more distinctive but not unique — any application combining basic AES/MD5 crypto with a WMI computer-system check and an unrelated "IsAttached" property could coincidentally satisfy this rule.
**Deployment:** Endpoint AV/EDR file scan; treat as a supporting/corroborating indicator alongside the Detection-tier XWorm config rule above, not as standalone confirmation.

```yara
rule RAT_XWorm_Rijndael256ECB_Crypto {
   meta:
      description = "Detects XWorm 3.0-5.0 variants using the characteristic Rijndael-256-ECB config encryption with non-standard overlapping MD5 key derivation, combined with anti-analysis indicators. The MD5 hash is copied to a 32-byte key array at offsets 0 and 15 with a single overlap byte — a distinctive non-standard construction consistent across XWorm 3.0-5.0 variants."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/"
      date = "2026-04-04"
      hash1 = "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
      hash2 = "e69e32522835f37f18095e219385057b6bbdc959"
      hash3 = "7e2fe58934874e442cfa183a34ceb24c"
      family = "XWorm"
      malware_type = "RAT"
      campaign = "OpenDirectory-DualRAT-MaaS-151.245.112.70"
      id = "7c53be1a-c635-593f-9763-1e81230698ee"
   strings:
      $s1 = "RijndaelManaged" ascii wide
      $s2 = "ECB" ascii wide
      $s3 = "MD5CryptoServiceProvider" ascii wide
      $s4 = "FromBase64String" ascii wide
      // Anti-analysis check strings
      $s5 = "Win32_ComputerSystem" ascii wide
      $s6 = "SbieDll" ascii wide
      $s7 = "IsAttached" ascii wide
   condition:
      uint16(0) == 0x5A4D and
      filesize < 500KB and
      $s1 and $s2 and $s3 and $s4 and
      2 of ($s5, $s6, $s7)
}
```

---

## Sigma Rules

### Detection Rules

**XWorm 3.0-5.0**

#### XWorm Scheduled Task Persistence with One-Minute Execution Interval

**Tier:** Detection
**Robustness:** 3
**ATT&CK Coverage:** T1053.005 (Scheduled Task)
**Confidence:** HIGH
**Rationale:** The combination of a 1-minute recurrence interval, HIGHEST privilege level, and execution from a user-writable AppData path is a technique-level chokepoint that does not depend on any XWorm-specific literal — no task name, mutex, or install filename is required. An attacker would have to abandon the near-instant-respawn design itself, not merely rename a string, to evade this rule.
**False Positives:** No known legitimate software creates a one-minute-interval, HIGHEST-privilege scheduled task launching a binary from `AppData\Roaming`; IT deployment tools that use short-interval tasks typically run from Program Files, not AppData.
**Blind Spots:** A slower respawn interval or a lower privilege level evades this specific rule (though doing so would also blunt the malware's own persistence goal); does not cover persistence mechanisms other than scheduled tasks.
**Validation:** Trigger the malware's persistence routine — the `schtasks.exe` invocation must match; a legitimate IT deployment script scheduling a task from Program Files at a longer interval must NOT fire.
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR.

```yaml
title: XWorm Scheduled Task Persistence with One-Minute Execution Interval
id: 94b6c01a-db65-4aa1-82c5-46eebc0c8ee5
status: experimental
description: |
    Detects XWorm 3.0-5.0 creating a scheduled task that runs every one minute at HIGHEST
    privilege level. This is the most aggressive of XWorm's three redundant persistence
    mechanisms — the one-minute interval provides near-instant re-execution after process
    termination and the HIGHEST privilege flag requests elevated execution context. The task
    name is derived from the install filename (typically "XWormClient") and the action points
    to the malware binary in %AppData%.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1053.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/sc minute'
            - '/mo 1'
            - '/rl highest'
    selection_path:
        CommandLine|contains:
            - '\AppData\Roaming\'
    condition: selection_cmd and selection_path
falsepositives:
    - No known legitimate software creates one-minute interval scheduled tasks at HIGHEST privilege from AppData
level: high
```

### Hunting Rules

**Shadow RAT v2.6.4.0**

#### Shadow RAT Registry Run Key Persistence

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** HIGH (behavior); brittle as a rule
**Rationale:** The registry value name `Shadow Client Startup` and the `\SubDir\` install-path fragment are each single build-chosen literals joined by OR, not AND — either alone is sufficient to fire, and a rebuild that renames either the value name or the install directory evades. Durability governs over the rule's currently clean false-positive profile, so this is a Hunting anchor rather than a Detection one.
**False Positives:** Unlikely today — no known legitimate software uses the value name "Shadow Client Startup" or a "\SubDir\" install path in this combination; a future rebuild renaming either evades entirely.
**Deployment:** SIEM (Sysmon Event ID 13 / registry_set), EDR registry monitoring.

```yaml
title: Shadow RAT Registry Run Key Persistence
id: ff8d332d-4f1f-44d7-89ac-5d4373f4a341
status: experimental
description: |
    Detects Shadow RAT v2.6.4.0 creating a registry Run key for persistence with the
    characteristic value name "Shadow Client Startup". This value points to the malware
    install path at %APPDATA%\SubDir\Client.exe or %APPDATA%\SubDir\$77Client.exe depending
    on the build variant (staging vs production). Presence of this key indicates an active
    Shadow RAT infection with established persistence.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection_key:
        TargetObject|endswith: '\CurrentVersion\Run\Shadow Client Startup'
    selection_data:
        Details|contains:
            - '\SubDir\Client.exe'
            - '\SubDir\$77Client.exe'
    condition: selection_key or selection_data
falsepositives:
    - No known legitimate software uses the registry value name "Shadow Client Startup"
level: medium
```

#### AMSI Bypass via Suspicious amsi.dll Load from Non-Standard Path

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1685 (Disable or Modify Tools — AMSI Bypass)
**Confidence:** HIGH (technique); MEDIUM precision as written
**Rationale:** This rule keys on no Shadow-RAT-specific literal at all — it is a durable, generic technique signal (any non-standard process loading `amsi.dll`) that would also catch other AMSI-patching malware. Durability is high, but the process exclusion list does not filter the many legitimate developer tools, custom .NET applications, and non-Program-Files installs that load `amsi.dll` during ordinary work, so this is a meaningfully noisy selector requiring analyst triage rather than auto-alerting.
**False Positives:** Custom development tools, non-standard .NET installations, or portable applications built by developers running from user profile paths; security research tools that explicitly load `amsi.dll` for testing purposes.
**Deployment:** SIEM (Sysmon Event ID 7 / image_load), EDR.

```yaml
title: AMSI Bypass via Suspicious amsi.dll Load from Non-Standard Path
id: b02fa532-5fdd-4307-9a33-0d5935ffc4d0
status: experimental
description: |
    Detects potential AMSI bypass attempts where a process loads amsi.dll from outside standard
    system directories. Shadow RAT v2.6.4.0 loads amsi.dll to resolve and patch AmsiScanBuffer
    with 15-byte shellcode returning E_INVALIDARG (0x80070057), effectively blinding in-memory
    .NET scanning. Legitimate AMSI consumers (PowerShell, .NET host processes) load amsi.dll
    from System32 or are explicitly filtered; a non-system, non-IDE process loading amsi.dll
    from a user-writable path is a strong indicator of an AMSI patching attempt.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
    filter_legitimate:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\dotnet.exe'
            - '\csc.exe'
            - '\msbuild.exe'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not (filter_legitimate or filter_system)
falsepositives:
    - Legitimate .NET applications or IDE tooling loading amsi.dll from non-standard installation paths
    - Custom development environments or build pipelines running outside Program Files
    - Security research tools that explicitly load amsi.dll for testing purposes
level: medium
```

#### ETW Bypass via Process Access to ntdll.dll Memory Region

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1685 (Disable or Modify Tools — ETW Bypass)
**Confidence:** HIGH (technique); LOW precision as written
**Rationale:** Full-rights process access (`PROCESS_ALL_ACCESS`) with `ntdll.dll` in the call trace is the correct mechanism for ETW patching, but `ntdll.dll` routes almost every `OpenProcess` call on Windows, so the `CallTrace` clause has close to zero discriminating power on its own; the 5-name source-image exclusion list does not filter EDR/AV agents, debuggers, or process-inspection tools, all of which routinely acquire full access to other processes. This selector would very likely fire on ordinary endpoint activity — a broad hunting lead for injection/ETW-patching activity, not an alerting-grade signal by itself.
**False Positives:** EDR/antivirus agents, debugging tools and performance profilers, and process-inspection tools (Process Explorer, Task Manager "show details") that legitimately request full process access as part of normal operation; application compatibility shims that modify ntdll behavior at runtime.
**Deployment:** SIEM (Sysmon Event ID 10 / process_access), EDR — correlate with other Shadow RAT indicators before treating a hit as confirmed.

```yaml
title: ETW Bypass via Process Access to ntdll.dll Memory Region
id: 7e1f94cd-ed21-4cc9-b3d4-4b14308210c0
status: experimental
description: |
    Detects processes acquiring full memory access rights to another process with call stack
    activity in ntdll.dll, consistent with ETW patching. Shadow RAT v2.6.4.0 patches
    ntdll.dll!EtwEventWrite with a single RET instruction (0xC3) via WriteProcessMemory,
    causing all ETW events from the process to silently return without logging. This blinds
    EDR tools and security monitoring products that rely on ETW for .NET CLR event visibility.
    The GrantedAccess value 0x1FFFFF indicates full process access including write permissions.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.defense-impairment
    - attack.t1685
    - detection.emerging-threats
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x1F0FFF'
        CallTrace|contains: 'ntdll.dll'
    filter_self:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\lsass.exe'
            - '\csrss.exe'
            - '\services.exe'
            - '\winlogon.exe'
            - '\wininit.exe'
    condition: selection and not filter_self
falsepositives:
    - Debugging tools and performance profilers legitimately requesting full process access
    - Application compatibility shims that modify ntdll behavior at runtime
    - Security products performing integrity verification on ntdll.dll
    - Process monitoring tools with deep inspection capabilities
level: medium
```

#### Windows Firewall Disabled via Netsh Opmode Command

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1686.003 (Windows Host Firewall — refined from the parent T1686 for specificity)
**Confidence:** MODERATE
**Rationale:** The `netsh firewall set opmode disable` syntax is the specific, durable command chokepoint for this technique and is not tied to any Shadow-RAT-specific literal, but the command itself is routinely used by administrators and IT automation during legitimate maintenance windows — a real, not theoretical, source of false positives per the original analysis.
**False Positives:** Legitimate administrators disabling Windows Firewall during planned maintenance or network reconfiguration; IT automation scripts that manage firewall state as part of policy enforcement workflows; software installers that temporarily disable the firewall during service installation.
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR — correlate with other Shadow RAT indicators for confirmation.

```yaml
title: Windows Firewall Disabled via Netsh Opmode Command
id: d7b42f19-3a58-4c82-9e31-0f5b8c2a6d94
status: experimental
description: |
    Detects Windows Firewall being disabled via netsh.exe using the "firewall set opmode disable"
    command sequence. Shadow RAT v2.6.4.0 includes explicit firewall disable capability in its
    command handler set, allowing operators to suppress host-based network filtering to enable
    unrestricted C2 communication or lateral movement. This command disables all Windows Firewall
    profiles simultaneously and is rarely issued in managed enterprise environments outside of
    explicit maintenance windows.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.defense-impairment
    - attack.t1686.003
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netsh.exe'
        CommandLine|contains|all:
            - 'firewall'
            - 'set'
            - 'opmode'
            - 'disable'
    condition: selection
falsepositives:
    - Legitimate administrators disabling Windows Firewall during planned maintenance or network reconfiguration
    - IT automation scripts that manage firewall state as part of policy enforcement workflows
    - Software installers that temporarily disable the firewall during service installation
level: medium
```

**XWorm 3.0-5.0**

#### XWorm Registry Run Key Persistence Using Malware Install Name

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1547.001 (Registry Run Keys / Startup Folder)
**Confidence:** HIGH (behavior); brittle as a rule
**Rationale:** Both AND-ed clauses (`TargetObject` suffix and `Details` substring) test the same operator-chosen install name ("XWormClient") rather than two independent signals, so the combination adds no durability beyond a single renamed literal. XWorm's install filename is a builder configuration option any operator can set arbitrarily; a differently-named build evades this rule entirely.
**False Positives:** Unlikely today — no known legitimate software uses the value name "XWormClient"; a differently-configured XWorm build (or a different operator's build) evades entirely.
**Deployment:** SIEM (Sysmon Event ID 13 / registry_set), EDR registry monitoring.

```yaml
title: XWorm Registry Run Key Persistence Using Malware Install Name
id: 68182796-ac58-45fa-a2c9-ed2843b5398f
status: experimental
description: |
    Detects XWorm 3.0-5.0 establishing registry Run key persistence using the value name
    "XWormClient", which matches the malware's default install filename. XWorm uses the
    install filename (without extension) as both the registry value name and the process mutex,
    creating a consistent and distinctive artifact. This is one of three redundant persistence
    mechanisms deployed simultaneously. The value data points to the malware binary in
    %AppData%\Roaming\.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.001
    - detection.emerging-threats
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\CurrentVersion\Run\XWormClient'
        Details|contains: '\AppData\Roaming\XWormClient.exe'
    condition: selection
falsepositives:
    - No known legitimate software uses the registry value name "XWormClient"
level: medium
```

#### Executable Shortcut Created in Windows Startup Folder by Non-System Process

**Tier:** Hunting
**Robustness:** 3
**ATT&CK Coverage:** T1547.009 (Shortcut Modification — Startup Folder persistence)
**Confidence:** HIGH (technique); MEDIUM precision as written
**Rationale:** This is a durable, XWorm-independent technique signal (any `.lnk` written to the Startup folder by a non-system-path process) rather than a keyed-on malware literal, but the original analysis already documented real legitimate collisions (staging-directory installers, non-Program-Files update managers) that make this a triage lead rather than an alerting-grade rule.
**False Positives:** Software installers running from user-writable staging directories that create startup shortcuts as part of setup; legitimate update managers or tray applications deployed outside Program Files that add startup shortcuts.
**Deployment:** SIEM (Sysmon Event ID 11 / file_event), EDR.

```yaml
title: Executable Shortcut Created in Windows Startup Folder by Non-System Process
id: a3c91e72-8f44-4b19-bd52-1f6a3c9d7e08
status: experimental
description: |
    Detects creation of a .lnk shortcut file inside the Windows Startup folder by a process
    outside system-managed directories. XWorm 3.0-5.0 creates a startup shortcut at
    %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\XWormClient.lnk via WScript.Shell
    COM automation as one of three redundant persistence mechanisms. Legitimate software
    installers creating startup shortcuts typically run from Program Files; a shortcut created
    by a process running from a user-writable path is a strong indicator of malware persistence.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1547.009
    - detection.emerging-threats
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\Microsoft\Windows\Start Menu\Programs\Startup\'
        TargetFilename|endswith: '.lnk'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_legitimate
falsepositives:
    - Software installers running from user-writable staging directories that create startup shortcuts as part of setup
    - Legitimate update managers or tray applications deployed outside Program Files that add startup shortcuts
level: medium
```

#### Non-Browser Process DNS Query to ip-api.com Hosting Detection Endpoint

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion: System Checks)
**Confidence:** HIGH (behavior — this URL/parameter combination is documented XWorm 3.0-5.0 builder behavior); the campaign's own IOC feed independently flags the domain as high FP risk
**Rationale:** `ip-api.com` is a popular free geolocation API used broadly by legitimate scripts, monitoring tools, and desktop applications. DNS-layer visibility cannot see the `/line/?fields=hosting` path that narrows the companion Suricata signature for the same behavior, so a browser-only exclusion filter leaves substantial non-browser legitimate traffic unfiltered.
**False Positives:** Legitimate applications using ip-api.com for geolocation or network diagnostics; network monitoring and IT asset management tools that use ip-api.com as a data source; weather, travel, or location-aware desktop applications performing connectivity checks.
**Deployment:** SIEM (Sysmon Event ID 22 / dns_query), EDR, DNS monitoring.

```yaml
title: Non-Browser Process DNS Query to ip-api.com Hosting Detection Endpoint
id: ce5a51b5-1221-4843-ac57-3fa2b15ffb69
status: experimental
description: |
    Detects a non-browser process resolving ip-api.com, consistent with XWorm's anti-analysis
    hosting detection check. XWorm 3.0-5.0 queries http://ip-api.com/line/?fields=hosting at
    startup to determine whether the infected machine runs on hosting or datacenter infrastructure.
    If the API returns "true", the malware silently exits via Environment.Exit(0) to evade sandbox
    and researcher environments. A non-browser, non-network-tool process querying this specific
    API is a strong indicator of sandbox evasion behavior.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.stealth
    - attack.discovery
    - attack.t1497.001
    - detection.emerging-threats
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|contains: 'ip-api.com'
    filter_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
            - '\brave.exe'
            - '\opera.exe'
    condition: selection and not filter_browser
falsepositives:
    - Legitimate applications using ip-api.com for geolocation or network diagnostics
    - Network monitoring and IT asset management tools that use ip-api.com as a data source
    - Weather, travel, or location-aware desktop applications performing connectivity checks
level: medium
```

#### WMI Win32_ComputerSystem Query from User-Writable Directory

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion: System Checks), T1082 (System Information Discovery)
**Confidence:** MODERATE
**Rationale:** `Win32_ComputerSystem` is one of the most common WMI classes referenced by legitimate system-information and inventory tooling, and AppData/Temp-hosted parent processes are common for legitimate portable and Electron-based applications (auto-updaters, chat/collaboration clients) that also perform WMI queries during normal operation — the combination narrows but does not eliminate benign hits.
**False Positives:** Legitimate system inventory or asset management tools running WMI queries from user-writable paths (unusual but possible in portable tool deployments); IT automation scripts placed in AppData by software deployment systems; portable or Electron-based applications performing routine WMI queries from AppData.
**Deployment:** SIEM (Sysmon Event ID 1 / process_creation), EDR.

```yaml
title: WMI Win32_ComputerSystem Query from User-Writable Directory
id: e82e90ce-c1fd-46df-83af-91d73094a63f
status: experimental
description: |
    Detects WMI queries referencing Win32_ComputerSystem originating from a process whose parent
    executable resides in a user-writable directory (AppData or Temp). XWorm 3.0-5.0 queries
    Win32_ComputerSystem at startup to check the Manufacturer and Model fields for virtual machine
    indicators (VMware, VirtualBox, Hyper-V strings). This is one of six anti-analysis checks
    performed before any malicious behavior executes. Legitimate WMI inventory tools run from
    managed system paths, not user-writable locations.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.stealth
    - attack.discovery
    - attack.t1497.001
    - attack.t1082
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmi:
        CommandLine|contains: 'Win32_ComputerSystem'
    selection_suspicious:
        ParentImage|contains:
            - '\AppData\Roaming\'
            - '\AppData\Local\Temp\'
    condition: selection_wmi and selection_suspicious
falsepositives:
    - Legitimate system inventory or asset management tools running WMI queries from user-writable paths (unusual but possible in portable tool deployments)
    - IT automation scripts placed in AppData by software deployment systems
level: medium
```

**Campaign-Level**

#### Zone.Identifier Alternate Data Stream Removal for SmartScreen Bypass

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1553.005 (Subvert Trust Controls: Mark-of-the-Web Bypass)
**Confidence:** HIGH (behavior, both families); logsource category corrected from the original
**Rationale:** Re-anchored on the **deletion** event (`category: file_delete`, corrected from the original rule's `file_event`/creation category) — a plain `:Zone.Identifier` file-creation selector matches every downloaded file system-wide, since Windows creates this ADS automatically on every download, and is pure baseline noise. Scoping to deletion turns this into a genuine hunting lead for MOTW-clearing behavior specifically, though self-updating legitimate software also clears its own MOTW, so an analyst triages the hits.
**False Positives:** Self-updating legitimate software (browsers, some installers) that clears its own Zone.Identifier stream after a user-consented first run; administrative scripts that bulk-clear MOTW on downloaded files; software deployment and packaging tools that remove MOTW from downloaded installers during staging.
**Deployment:** Endpoint EDR / Sysmon-fed SIEM (FileDelete telemetry), correlated with process creation for the same image.

```yaml
title: Zone.Identifier Alternate Data Stream Removal for SmartScreen Bypass
id: b78a5718-03c3-4e99-ab50-7fd048a70872
status: experimental
description: |
    Detects deletion of the Zone.Identifier alternate data stream (ADS) from executable files
    by non-browser, non-system processes. Both Shadow RAT and XWorm remove the Mark-of-the-Web
    (MOTW) from their own executables after installation to suppress Windows SmartScreen warnings
    on subsequent executions. Shadow RAT uses FileHelper.DeleteZoneIdentifier; XWorm performs a
    direct ADS stream deletion. Anchored on the file-delete event rather than file creation —
    file creation would match every downloaded file system-wide, since the ADS is created
    automatically on every download, and would be pure baseline noise.
references:
    - https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/
author: The Hunters Ledger
date: '2026-04-04'
tags:
    - attack.defense-impairment
    - attack.t1553.005
    - detection.emerging-threats
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
    filter_browser:
        Image|endswith:
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\iexplore.exe'
    filter_system:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
    condition: selection and not (filter_browser or filter_system)
falsepositives:
    - Download managers or file transfer utilities that strip Zone.Identifier after checksum verification
    - Software deployment and packaging tools that remove MOTW from downloaded installers during staging
    - Self-updating legitimate software that clears its own Zone.Identifier stream after a user-consented first run
level: medium
```

---

## Suricata Signatures

### Hunting Rules

**XWorm 3.0-5.0**

#### XWorm Anti-Analysis Hosting Detection via ip-api.com

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1497.001 (Virtualization/Sandbox Evasion: System Checks)
**Confidence:** HIGH for the behavior (documented XWorm 3.0-5.0 builder feature); the campaign's own IOC feed flags the underlying domain as high FP risk
**Rationale:** The `http.host` + `http.uri` combination (`ip-api.com` + `/line/` + `fields=hosting`) is a family-wide default builder marker, not a campaign-specific literal, and is more precise than a bare domain match since it requires the specific hosting-check URL path. It remains Hunting rather than Detection because `ip-api.com` is a popular free geolocation service used broadly by legitimate scripts, monitoring tools, and desktop software — the underlying IOC feed entry for this URL is explicitly flagged `false_positive_risk: HIGH` with a note not to block it outright.
**False Positives:** Legitimate applications, scripts, or monitoring dashboards using ip-api.com for IP geolocation or network diagnostics — this is a widely-used free API with substantial legitimate traffic.
**Deployment:** Network IDS/IPS at perimeter and internal segmentation points; hunt-tune before alerting.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL TROJAN XWorm Anti-Analysis Hosting Check via ip-api.com"; flow:established,to_server; http.host; content:"ip-api.com"; http.uri; content:"/line/"; content:"fields=hosting"; threshold:type limit,track by_src,count 1,seconds 3600; classtype:trojan-activity; sid:2026040403; rev:2; metadata:author The_Hunters_Ledger, date 2026-04-04, reference https://the-hunters-ledger.com/hunting-detections/shadow-xworm-opendirectory-detections/;)
```

---

## Coverage Gaps

**Atomics routed to the IOC feed (5 of the original file's 6 Suricata rules).** Every pure IP:port rule and pure single-domain DNS rule keyed solely on one hardcoded value with no behavioral qualifier surviving the literal's removal — per the tiering rubric's routing test, these are IOC-feed entries, not rules:

- `151.245.112.70:8990` (Shadow RAT C2) and `151.245.112.70:7007` (XWorm C2) — direct IP:port matches with no content anchor.
- `151.245.112.70:3000` (Shadow RAT unconfirmed fallback port) — same pattern, and the original analysis itself could not confirm the port's purpose.
- `harrismanlieb.ink` and `epgoldsecurity.com` — pure `dns.query` domain-literal matches.

All five values were already present in [`shadow-xworm-opendirectory-iocs.json`](/ioc-feeds/shadow-xworm-opendirectory-iocs.json) (`network_indicators.ipv4` and `network_indicators.domains`) from the original analysis; no feed edits were required. The remaining Suricata rule (ip-api.com hosting-check) retains real content anchors beyond a single atomic value and is carried forward as a Hunting-tier signature above.

**Corrections made during this re-tiering pass:**
- **Zone.Identifier rule logsource category** — corrected from `file_event` (Sysmon file-creation) to `file_delete`. As originally written, the rule would have matched every downloaded file system-wide (Windows creates the Zone.Identifier ADS automatically on every download), which is pure baseline noise rather than a MOTW-bypass signal. Anchoring on deletion instead — matching the actual documented behavior (both families delete their own ADS post-install) — is what gives this rule genuine Hunting value.
- **ATT&CK tag/ID refresh to the currently-installed ATT&CK v19 data** — `T1562.001`/`T1562.004`/`T1562.006` no longer exist as technique IDs (verified against the installed pySigma `mitre_attack` module); the AMSI/ETW bypass rules already correctly used `T1685` (Disable or Modify Tools) and are unchanged. The netsh firewall-disable rule's `attack.t1686` tag was valid but generic; refined to the more specific `attack.t1686.003` (Windows Host Firewall), the exact sub-technique matching `netsh firewall set opmode disable`.
- **Suricata rule 3 (ip-api.com check)** — reformatted to a single physical line (matching the engine's expected `.rules` format), added a `threshold` to bound alert volume, and updated `metadata` to the current `author`/`date`/`reference` convention. `rev` bumped to 2 to reflect the body change; `sid` and `msg` text preserved unchanged for feed-quarantine stability.
- **No rules were Cut.** Every rule from the original 23 (7 YARA + 10 Sigma + 6 Suricata) retained analytical value as either a Detection or Hunting rule, or was preserved as an existing IOC-feed entry.

**T1055.012 — Process Hollowing (Shadow RAT RunPE).** Shadow RAT includes `UseRunPE`, `RunPETarget`, and `ExecuteInMemoryDotNet` fields in its config and message handlers. However, behavioral analysis was conducted statically — no confirmed observation of which processes are hollowed or under what command conditions. A behavioral Sigma rule for process hollowing requires observed parent-child process pairs and hollow-process characteristics. **What would enable a rule:** the specific target-process/parent-process pairing from an executed hollowing command.

**T1572 — Protocol Tunneling via Ngrok.** Shadow RAT includes Ngrok tunnel management capability (path and token config fields). The Ngrok binary is not embedded — it must be downloaded or pre-installed by the operator. A detection rule would require the Ngrok binary hash or the specific API endpoint used for tunnel establishment. **What would enable a rule:** observation of Ngrok deployment in an active incident.

**T1091 — Replication Through Removable Media (XWorm USB spread).** XWorm has `USB.exe` as a config field and the USB spread capability is documented in the codebase (covered by the YARA config rule above as a corroborating string), but the propagation mechanism code was not independently confirmed in static analysis of the recovered samples. A dedicated file-based or process-based Sigma rule for the spread mechanism itself requires dynamic analysis confirmation. **What would enable a rule:** the specific file-write or process-execution pattern from an observed USB-spread event.

**T1102.001 — Dead Drop Resolver (Pastebin fallback).** Shadow RAT includes a Pastebin dead-drop C2 fallback, but the boolean controlling it (`YuMK50gqNyIF4mYC6wcG2HeN`) was `false` in both recovered builds, and no Pastebin URLs were observed. **What would enable a rule:** observation of an active Pastebin-based C2 URL in a future campaign build.

**T1219 — Remote Access Tools (ScreenConnect).** ScreenConnect was deployed on the C2 server on 2026-03-01 for persistent victim access. ScreenConnect is a legitimate RMM product, so a detection rule targeting its binary hashes or known relay ports (port 8040) would generate excessive false positives in environments that legitimately use ConnectWise ScreenConnect. Detection should instead focus on network anomalies — unexpected ScreenConnect traffic from endpoints with no managed-IT justification — which is outside the scope of a static signature.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.

