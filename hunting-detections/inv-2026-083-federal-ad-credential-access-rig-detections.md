---
title: "Detection Rules — An Active Directory credential-access rig aimed at a US federal agriculture department, with a Linux HTTPS agent and a signed OneDrive side-load"
date: '2026-11-15'
layout: post
permalink: /hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
hide: true
---

**Campaign:** INV-2026-083
**Date:** 2026-11-15
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/

---

## Detection Coverage Summary

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 3 | 3 | T1071.001, T1573.001, T1001.003, T1105, T1041, T1574.001, T1102.002, T1553.002 | 1 |
| Sigma | 4 | 9 | T1574.001, T1610, T1611, T1036.005, T1620, T1553.002, T1102.002, T1480, T1558.003, T1087.002, T1110.003, T1557.001 | 2 |
| Suricata | 1 | 5 | T1572, T1071.001, T1001.003, T1102.002 | 1 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader or key on a name the operator can change, for scoping and threat-hunting. Expect to review the hits.

The file carries 25 rules (8 Detection, 17 Hunting): 6 YARA, 13 Sigma (three of them correlation rules, each with its own base rule) and 6 Suricata. A "Coverage Gaps" section at the end lists what I looked at and did not write, with the reason for each. The rules tag 18 ATT&CK techniques, 15 of the 37 techniques the report's mapping holds as observed (41%); of the other three, Kerberoasting is held as inferred because the ticket request is not shown, and the two pod techniques are held as prepared only. Two of the 15 are the spray and the relay, which the mapping holds as observed but refused.

---

## What these rules do not claim

These rules come from a static reading of an operator's open directory: two implants (a stripped Linux ELF agent and a signed Windows DLL loader), the operator's attack scripts and logs, and thirteen prepared Kubernetes pod manifests. The operator's files hold 239 harvested Kerberos service tickets, whose acquisition route is unknown, and show a password spray, an account-enumeration sweep and an NTLM relay and capture setup, all aimed at a US federal agriculture department's Active Directory. I found no victim-side telemetry in the capture. No rule below was confirmed against a victim log.

Five limits apply to every rule here.

- **Nothing was executed.** A rule that depends on how Windows, Linux or Kubernetes logs an event (a Sysmon image-load field, an auditd path, an audit-log field name) is derived from the artifact and from how the public technique works, and is marked NOT CHECKED against live telemetry. None of the Windows Sigma rules was replayed against SigmaHQ's benign event baseline, so their false-positive behaviour on ordinary logs is NOT CHECKED.
- **The grades behind the rules are not all equal.** The two implants are read in code (HIGH). The Kerberoast harvest of 239 service tickets for 89 accounts is in a captured file (HIGH). The pod manifests are prepared-only: nothing shows a pod was created. The spray, the relay and the capture servers were exercised and refused or captured nothing in the held logs. A rule says which of these it rests on.
- **The Kerberoast and spray thresholds are not derived from the case.** The harvest files carry no timestamps and the spray log carries none either, so how fast the operator ran is not known. The thresholds in the correlation rules are starting values to tune, and each rule says so.
- **Upstream coverage was read from local clones.** The SigmaHQ clone is dated 2026-09-12. I read the upstream conditions of the rules named in each Sigma rule's Upstream Coverage line and nothing else. A broader upstream rule may exist for the others. Suricata and YARA upstream coverage is NOT CHECKED.
- **No victim value appears in any rule.** The spray and relay targets, the realm, the account names and the node and namespace names are withheld. The agency's own public image name is left out of every rule.

Each YARA rule names the held sample it was written from by hash prefix. The agent is the `agent.bin` ELF (sha256 `a04a7326...d096`). The loader DLL is `msedge.dll` (sha256 `f2d86abb...a13b`), and two byte-identical copies of it were held.

---

## YARA Rules

### Detection Rules

**Linux HTTPS agent (`agent.bin`)**

#### MAL_LNX_INV2026083_HTTPSJsonAgent_RequestTemplates

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography), T1001.003 (Protocol or Service Impersonation), T1105 (Ingress Tool Transfer), T1041 (Exfiltration Over C2 Channel)
**ATT&CK Note:** The templates are the agent's request builder and its register, poll, fetch and file-send bodies. The XOR layer and the file-send path are read in code at HIGH; the WordPress-looking paths are per-deployment configuration and are not used here.
**Confidence:** HIGH
**False Positives:** None known. The request template is a single printf format with a `Host: %s:%s` line, a JSON content type and no User-Agent, followed by a JSON key and data envelope. I know of no legitimate ELF that carries that format together with two or more of the JSON body templates and the re-register reply string.
**Blind Spots:** Misses a build that changes the HTTP or JSON templates, which is a source change and not a re-configuration; the host, port, paths and sleep values are configuration slots and change without touching these strings. Misses a packed or encrypted copy. Misses the plugin ELFs the agent loads, which are not in the capture.
**Validation:** Written from the held `agent.bin` sample (sha256 prefix `a04a7326`). I counted each string in that file: every string in the rule is present exactly once, at the offsets in the analysis (request template at 0x2ee5, register template at 0x477, re-register reply at 0xbcb4). Scanning the sample and a benign Windows corpus with the rule has not been done: NOT CHECKED. Upstream: a string-set comparison against signature-base found no rule sharing a string with this one; I did not read any upstream condition.
**Deployment:** Endpoint AV and EDR file scan of Linux hosts, container image scanning, and a hunt of any directory the agent could have been dropped in. The rule tests `filesize`, so it does not match inside process memory.
**Basis:** The agent's request builder, body templates and protocol strings, from `agent.bin_analysis.md` sections 3, 4 and 8.

```yara
rule MAL_LNX_INV2026083_HTTPSJsonAgent_RequestTemplates {
   meta:
      description = "Detects the stripped static Linux ELF HTTPS agent by its HTTP request template (Host header carrying the port, JSON content type, no User-Agent) together with its JSON register, poll, fetch and file-send body templates and protocol reply strings, all stored in clear in .rodata"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096"
      hash2 = "25f21b4614e03250dec788bbc0f1beb8c43828d4"
      hash3 = "6804216bf8ae869a7253482c69cae553"
      family = "INV-2026-083-HTTPS-Agent"
      id = "372c7ce6-758d-56dd-a957-8c029f95a028"
   strings:
      $post = "POST /%s HTTP/1.1\r\nHost: %s:%s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s" ascii
      $j1 = "{\"Hostname\":\"%s\",\"Osname\":\"%s\",\"Username\":\"%s\",\"Innerip\":\"%s\",\"Pid\":\"%d\",\"Processname\":\"%s\",\"Sleep\":%d,\"Groupid\":1}" ascii
      $j2 = "{\"key\":\"%d\",\"data\":\"check\"}" ascii
      $j3 = "{\"key\":\"%d\",\"data\":\"download\",\"token\":\"%s\"}" ascii
      $j4 = "{\"key\":\"%d\",\"data\":\"%s\",\"token\":\"%s\",\"path\":\"%s\"}" ascii
      $j5 = "{\"key\":\"%s\",\"data\":\"%s\"}" ascii
      $re = "\"status\":\"re_register\"" ascii
      $sl = "Sleep: %ds, Jitter: %d%%" ascii
   condition:
      uint32(0) == 0x464c457f and
      filesize < 2MB and
      $post and
      2 of ($j*) and
      ($re or $sl)
}
```

**Windows DLL loader (`msedge.dll`)**

#### MAL_WIN_INV2026083_Msedge_SideloadLoader_ExportSpartanCookies

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1574.001 (DLL)
**ATT&CK Note:** The DLL is the vehicle for the side-load of Microsoft's `cookie_exporter.exe`. ATT&CK v20 lists the DLL technique T1574.001 with the tactics Stealth and Execution; the older side-loading sub-technique id is revoked.
**Confidence:** HIGH
**False Positives:** None known. The genuine `msedge.dll` is tens of megabytes and exports no `ExportSpartanCookies`; the genuine `cookie_exporter.exe` that calls that name is an executable and contains the name once. The three one-byte-lower API constants and the loader head must all be present as well.
**Blind Spots:** Misses a rebuild that stops shifting the API names by one, or that renames the export. Misses a DLL that keeps the payload but uses a different export name for another host executable. Does not cover the payload itself, which is a separate rule.
**Validation:** Written from the held `msedge.dll` sample (sha256 prefix `f2d86abb`; two byte-identical copies were held). I counted every string in the rule in both copies: each is present exactly once, at 0x3a543 (export name), 0x30420, 0x30430, 0x30440 (the constants) and 0x400 (the loader head). Scanning the sample and a benign Windows corpus with the rule has not been done: NOT CHECKED. The same `edge.exe` (genuine Microsoft `cookie_exporter.exe`) is a negative control: it carries the export name but none of the other strings.
**Deployment:** Endpoint file scan of user-writable directories, mail and web gateway attachment scanning, and a hunt for any `msedge.dll` outside an Edge install directory.
**Basis:** The side-load analysis and the loader code read in the disassembly, from `msedge.dll_analysis.md` sections 2, 3 and 6.

```yara
rule MAL_WIN_INV2026083_Msedge_SideloadLoader_ExportSpartanCookies {
   meta:
      description = "Detects the side-load DLL named msedge.dll that exports ExportSpartanCookies for Microsoft's cookie_exporter.exe and carries a loader whose API names (VirtualAlloc, VirtualProtect, kernel32.dll) are stored one byte lower and rebuilt at run time"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b"
      hash2 = "d622367246c391631ae2b28d3510150ef50f4000"
      hash3 = "f8e93dccfa28c649887925c67fc0697b"
      family = "INV-2026-083-OneDrive-Loader"
      id = "950d2ea8-0f2c-5c1b-a8fb-e3a20fbbe039"
   strings:
      $exp = "ExportSpartanCookies" ascii fullword
      $c1 = { 55 68 71 73 74 60 6B 40 6B 6B 6E 62 }
      $c2 = { 55 68 71 73 74 60 6B 4F 71 6E 73 64 62 73 }
      $c3 = { 6A 64 71 6D 64 6B 32 31 2D 63 6B 6B }
      $head = { 48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 48 8D 6C 24 C0 48 81 EC }
   condition:
      uint16(0) == 0x5A4D and
      filesize < 2MB and
      $exp and $head and
      all of ($c*)
}
```

#### MAL_WIN_INV2026083_OneDriveGraphBeacon_Shellcode_Immediates

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1102.002 (Bidirectional Communication)
**ATT&CK Note:** The implant's command channel is a OneDrive folder reached through Microsoft Graph, which maps to the two rows above. The in-process execution through the `EnumWindows` callback is Stealth (T1620 in the case mapping) and is not what this rule keys on.
**Confidence:** HIGH
**False Positives:** None known. The rule needs the two fragments of the OAuth client id, loaded as 64-bit immediates, together with three of the five command verbs loaded the same way and either the shellcode prologue or the `Global\O` mutex prefix. A compiler emits that pattern only when the author builds strings on the stack, and no ordinary program builds this set.
**Blind Spots:** Misses a build that stores its strings in a different layout, one that changes the client id (the id is Microsoft's public Office client, so an operator can swap it for another public client), and an encrypted or compressed payload. A process-memory scan only matches while the decrypted shellcode is mapped.
**Validation:** Written from the held `msedge.dll` sample (sha256 prefix `f2d86abb`). In the sample, every byte pattern in the rule is present in both copies at the offsets in the analysis (prologue 0x3bc60, client-id fragments 0x3bcd8 and 0x3bce2, mutex prefix 0x3d048, verbs 0x3bd2d to 0x3bdd9). The rule has no `filesize` or PE test so that it can scan process memory or an extracted blob. Scanning the sample with the rule has not been done: NOT CHECKED.
**Deployment:** Endpoint file scan, and a memory scan of `edge.exe` or `cookie_exporter.exe` processes that run from a non-Edge directory.
**Basis:** The embedded 49,696-byte shellcode, read as raw x64 code, from `msedge.dll_analysis.md` sections 3, 5 and 6.

```yara
rule MAL_WIN_INV2026083_OneDriveGraphBeacon_Shellcode_Immediates {
   meta:
      description = "Detects the plaintext x64 shellcode implant that talks to Microsoft Graph and OneDrive, by the immediate-loaded fragments of its OAuth client id and its command verbs (the strings are built eight bytes at a time on the stack, so none is contiguous ASCII), in the DLL's data section, an extracted blob or process memory"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b"
      hash2 = "d622367246c391631ae2b28d3510150ef50f4000"
      hash3 = "f8e93dccfa28c649887925c67fc0697b"
      family = "INV-2026-083-OneDrive-Loader"
      id = "665ee881-1bb9-555d-92e1-defd48ac849b"
   strings:
      $pro = { 55 48 89 E5 53 B8 D8 16 00 00 E8 F2 36 00 00 48 29 C4 48 B8 63 6F 6E 66 69 67 2E 62 }
      $glob = { 48 B8 47 6C 6F 62 61 6C 5C 4F }
      $cid1 = { 48 B8 64 33 35 39 30 65 64 36 }
      $cid2 = { 48 BA 2D 35 32 62 33 2D 34 31 }
      $v1 = { 48 B8 64 6F 77 6E 6C 6F 61 64 }
      $v2 = { 48 B8 77 68 65 72 65 61 6D 69 }
      $v3 = { 48 B8 64 65 61 63 74 69 76 65 }
      $v4 = { 48 B8 73 63 68 74 61 73 6B 73 }
      $v5 = { 48 B8 4D 6F 7A 69 6C 6C 61 }
   condition:
      $cid1 and $cid2 and
      3 of ($v*) and
      ($pro or $glob)
}
```

### Hunting Rules

**Linux HTTPS agent (`agent.bin`)**

#### MAL_LNX_INV2026083_HTTPSJsonAgent_StaticKeyString

**Tier:** Hunting
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1573.001 (Symmetric Cryptography)
**ATT&CK Note:** The string is the constant half of the agent's repeating-key XOR key. The other half is a 32-letter session token sent in clear in every register request.
**Confidence:** MODERATE
**False Positives:** None known in the held corpus. A 44-character base64-shaped constant is high-entropy, but the rule matches only 12 of its 44 characters, so an unrelated file that happens to carry the same 8-character prefix and 4-character suffix around 32 base64 characters would hit. I have not measured that rate.
**Blind Spots:** A pivot, not a detector: it finds only builds that reuse this exact string. No second sample has been compared, so whether the string is shared across builds or campaigns is NOT CHECKED. It would miss a build with a new key.
**Validation:** Written from the held `agent.bin` sample (sha256 prefix `a04a7326`). The pattern matches exactly once, at file offset 0xa71d0, and the match is 44 bytes long. The sha256 of the full 44 bytes, `642fedfa569003ed5427715a9b6a8ea6365f8e10edc935758e0017aeb17aa0d0`, is the handle for anyone holding another copy. Scanning the sample with the rule has not been done: NOT CHECKED.
**Deployment:** A retro-hunt over an ELF corpus held by a partner or a repository of Linux samples, and a one-off scan of any Linux host that shows the agent's other traces. Not for continuous alerting.
**Basis:** The `.data` configuration block, from `agent.bin_analysis.md` section 5, and the key string handle from `infrastructure.md` section 7. The full string is not printed here; the rule uses its first eight and last four characters only.

```yara
rule MAL_LNX_INV2026083_HTTPSJsonAgent_StaticKeyString {
   meta:
      description = "Hunts for the 44-character static string that the Linux HTTPS agent appends to its session token to form its XOR key, matched on its first eight and last four characters; a second build carrying the same string would come from the same builder"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096"
      hash2 = "25f21b4614e03250dec788bbc0f1beb8c43828d4"
      hash3 = "6804216bf8ae869a7253482c69cae553"
      family = "INV-2026-083-HTTPS-Agent"
      id = "5e63b9a3-36b0-55fe-99c3-1b50649b027b"
   strings:
      $key = /5p\+6P7rR[A-Za-z0-9+\/]{32}Sps=/ ascii
   condition:
      uint32(0) == 0x464c457f and
      filesize < 4MB and
      $key
}
```

#### SUSP_LNX_ZigLLVM19_MbedTLS36_StaticELF_Toolchain

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** None
**ATT&CK Note:** This is a build fingerprint and maps to no technique.
**Confidence:** LOW
**False Positives:** Any static ELF linked by a Zig toolchain on LLVM 19.1.7 that also embeds Debian GCC 15.2.0-7 objects and mbed TLS 3.6.0 compiled from `/tmp`. That is a build recipe, not an actor mark, and other developers who build the same way will match.
**Blind Spots:** Misses any build that strips the `.comment` section or uses another toolchain version. Says nothing about intent: a hit is a binary to look at, not a finding.
**Validation:** Written from the held `agent.bin` sample (sha256 prefix `a04a7326`). In the sample, all three `.comment` strings are present once each (at 0xa7508, 0xa7526 and 0xa758f) and the mbed TLS source path occurs nine times. Scanning the sample with the rule has not been done: NOT CHECKED. No second sample built this way was held, so the rate at which the recipe appears elsewhere is NOT CHECKED.
**Deployment:** Retro-hunt over a Linux ELF corpus to size how common the build recipe is, before relying on it for anything.
**Basis:** The `.comment` section and the library source-path strings, from `agent.bin_analysis.md` sections 1 and 8, where I tier them as hunting only.

```yara
rule SUSP_LNX_ZigLLVM19_MbedTLS36_StaticELF_Toolchain {
   meta:
      description = "Hunts for a static ELF whose .comment section records both Debian GCC 15.2.0-7 and a Zig-bundled clang and LLD 19.1.7, and that embeds nine mbed TLS 3.6.0 library source paths under /tmp; a build fingerprint shared by any binary built the same way, not specific to one actor"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "a04a732678f95f80a6361ef95312b995b0336898cb66d9ffce63b9ed7803d096"
      hash2 = "25f21b4614e03250dec788bbc0f1beb8c43828d4"
      hash3 = "6804216bf8ae869a7253482c69cae553"
      family = "INV-2026-083-HTTPS-Agent"
      id = "60ad0f83-e319-5347-8db9-766ad366999c"
   strings:
      $gcc = "GCC: (Debian 15.2.0-7) 15.2.0" ascii
      $llvm = "clang version 19.1.7" ascii
      $lld = "Linker: LLD 19.1.7" ascii
      $mbed = "/tmp/mbedtls-3.6.0/library/" ascii
   condition:
      uint32(0) == 0x464c457f and
      filesize < 4MB and
      $gcc and $llvm and $lld and
      #mbed >= 3
}
```

**Windows DLL loader (`msedge.dll`)**

#### SUSP_WIN_RockstarGames_ExpiredCert_SmallDLL

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1553.002 (Code Signing)
**ATT&CK Note:** The loader's signature digests match its bytes (Authenticode, both the SHA-1 and SHA-256 signatures), which shows that someone holding the Rockstar Games certificate's private key signed the file. Who acquired the key, how and when (theft by this operator, a rented signing service, an insider or an earlier leak) is not shown, and whether the certificate is publicly known as leaked or revoked is NOT CHECKED.
**Confidence:** MODERATE
**False Positives:** Small legitimate DLLs signed with the same Rockstar Games certificate while it was valid (2016-03-04 to 2017-03-20), for example components of older Rockstar titles or the Social Club client. I have not enumerated them. A hit signed in that window and built before it is expected; a hit built after 2017 is not.
**Blind Spots:** Keys on the certificate bytes in the file, so it misses a build signed with a different stolen certificate, an unsigned build, and a copy with the certificate table stripped. It cannot see the build date, which is why the rule is a hunt and not a detection.
**Validation:** Written from the held `msedge.dll` sample (sha256 prefix `f2d86abb`). In the sample the rule's three strings are each present in both copies (the company name four times, the serial four times, the issuing CA six times). Scanning the sample with the rule, and a benign Windows corpus, has not been done: NOT CHECKED.
**Deployment:** Hunt over user-writable directories and mail attachments, then compare each hit's PE timestamp with the certificate validity window.
**Basis:** The signer details read from the DLL's certificate table, from `msedge.dll_analysis.md` section 1, and the signature-verification result in the case triage summary.

```yara
import "pe"

rule SUSP_WIN_RockstarGames_ExpiredCert_SmallDLL {
   meta:
      description = "Hunts for a small Windows DLL that carries the Rockstar Games code-signing certificate (serial 5057286E4033FCB0000000005565F5AC, Entrust OVCS1, expired 2017-03-20) in its certificate table; the one known instance is a 2026 build, so a small DLL with this signer is worth a look at its build date and purpose"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/"
      date = "2026-11-14"
      hash1 = "f2d86abbb8f49cf19be5d910e87bfce5e1f62525a46a2da833e7daf04809a13b"
      hash2 = "d622367246c391631ae2b28d3510150ef50f4000"
      hash3 = "f8e93dccfa28c649887925c67fc0697b"
      family = "INV-2026-083-OneDrive-Loader"
      id = "ccadac64-ffc0-556e-bd51-d71bcefcc7b4"
   strings:
      $rock = "Rockstar Games, Inc." ascii
      $serial = { 50 57 28 6E 40 33 FC B0 00 00 00 00 55 65 F5 AC }
      $ent = "Entrust Code Signing CA - OVCS1" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 2MB and
      pe.characteristics & pe.DLL and
      $rock and $serial and $ent
}
```

---

## Sigma Rules

### Detection Rules

**Windows OneDrive side-load (`msedge.dll`, `cookie_exporter.exe`)**

#### Msedge.dll Loaded Without a Microsoft Signature

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1574.001 (DLL)
**ATT&CK Note:** ATT&CK v20 lists T1574.001 under the tactics Stealth and Execution, so the rule carries both tactic tags.
**Confidence:** HIGH
**False Positives:** None known. Every Microsoft Edge channel and the Edge WebView2 runtime ship a Microsoft-signed `msedge.dll`. A hit is a module that borrowed the name.
**Blind Spots:** Misses a side-load vehicle that uses a different DLL name. Misses a host that does not log image loads. A stolen Microsoft signature would pass the filter, and I know of none in this case.
**Validation:** Load `msedge.dll` from the case's `i44864` directory through `edge.exe` on a lab host with Sysmon image-load logging, and the rule fires on the DLL's Rockstar Games signature. Load the Microsoft-signed `msedge.dll` from an Edge install directory, and it must not. Neither run was made for this file: NOT CHECKED against live telemetry. Upstream: I grepped the SigmaHQ clone (2026-09-12) for `msedge.dll`, `cookie_exporter` and `ExportSpartan` across `rules`, `rules-threat-hunting` and `rules-emerging-threats` and found no match.
**Deployment:** Sysmon Event ID 7 forwarded to the SIEM, or any EDR that exposes module loads with the signer.
**Basis:** The loader's `LoadLibraryExA("msedge.dll")` with the application-directory search flag and the DLL's Rockstar Games signature, from `msedge.dll_analysis.md` sections 1 and 2.

```yaml
title: Msedge.dll Loaded Without a Microsoft Signature
id: c0c26c39-6c2b-45c3-8798-646d2550fd34
status: experimental
description: >-
    Detects a library named msedge.dll that is loaded into a process without a Microsoft signature.
    Microsoft's cookie_exporter.exe helper loads msedge.dll from its own directory and calls the export ExportSpartanCookies,
    so a copy of that helper placed beside a look-alike DLL runs the DLL's code under a trusted process name.
    The DLL in the case this rule is written from carried an expired Rockstar Games signature.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.execution
    - attack.t1574.001
    - stp.3
logsource:
    category: image_load
    product: windows
    definition: 'Requires image-load logging that records the signer, for example Sysmon Event ID 7 with the Signed and Signature fields. The default Sysmon configuration does not log module loads.'
detection:
    selection:
        ImageLoaded|endswith: '\msedge.dll'
    filter_main_microsoft:
        # sourced: documented platform default, Microsoft signs the msedge.dll it ships
        Signed: 'true'
        Signature: 'Microsoft Corporation'
    condition: selection and not filter_main_microsoft
falsepositives:
    - A developer build of a Chromium-based browser that reuses the msedge.dll name without a Microsoft signature
level: high
```

#### Edge Cookie Exporter Helper Running Outside the Edge Install Directory

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1574.001 (DLL)
**ATT&CK Note:** The helper is the trusted host process for the side-load. In the case it had been renamed to `edge.exe`, so the rule keys on the version-resource name and not on the file name.
**Confidence:** HIGH
**False Positives:** A per-user Edge install outside Program Files, if one exists, runs the helper from its own directory and will hit. I have not confirmed whether any Edge channel installs per user.
**Blind Spots:** Misses a host that does not log the original file name (Sysmon 10 or later fills `OriginalFileName` from the version resource; Security Event ID 4688 does not). Misses a side-load that uses a different Microsoft helper. The path filter cannot be spoofed without administrator rights, because the Edge roots sit under Program Files.
**Validation:** Run the case's `edge.exe` from any user-writable directory, and the rule fires on its `cookie_exporter.exe` original name; run Microsoft's `cookie_exporter.exe` from an Edge install directory, and it must not. Not run: NOT CHECKED against live telemetry. Upstream: same grep as the rule above, no match.
**Deployment:** Sysmon Event ID 1 (version 10 or later) or an EDR process-creation feed that carries the original file name.
**Basis:** The helper's version resource (internal name `cookie_exporter_exe`, original file name `cookie_exporter.exe`) and the case's renamed copy, from `msedge.dll_analysis.md` sections 1 and 2.

```yaml
title: Edge Cookie Exporter Helper Running Outside the Edge Install Directory
id: 069e1f8a-bb1c-40aa-a114-b8c1816a8e37
status: experimental
description: >-
    Detects a process whose original file name is cookie_exporter.exe running from a directory that is not a Microsoft Edge install.
    The helper is a genuine Microsoft binary that loads msedge.dll from its own directory, which makes it a usable host for a side-loaded DLL.
    The case this rule is written from ran the helper renamed to edge.exe beside a malicious msedge.dll.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.execution
    - attack.t1574.001
    - stp.3
logsource:
    category: process_creation
    product: windows
    definition: 'Requires process-creation logging that carries the original file name from the version resource, for example Sysmon Event ID 1 from version 10. Security Event ID 4688 does not carry it.'
detection:
    selection:
        OriginalFileName: 'cookie_exporter.exe'
    filter_main_edge_install:
        # sourced: documented platform default, per-machine Microsoft Edge install roots for every channel (Edge, Edge Beta, Edge Dev)
        Image|startswith:
            - 'C:\Program Files (x86)\Microsoft\Edge'
            - 'C:\Program Files\Microsoft\Edge'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - A per-user Microsoft Edge install that keeps the helper outside Program Files
level: high
```

**Kubernetes pod creation (prepared-only in the case)**

#### Kubernetes Pod Created With Privileged Host Root Mount and Staged Base64 Script

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** covered
**ATT&CK Coverage:** T1611 (Escape to Host), T1610 (Deploy Container)
**ATT&CK Note:** The case holds thirteen complete pod specifications of this shape and no evidence that any was submitted to a cluster, so both techniques are prepared-only in the case mapping. The rule detects the creation event, not a successful escape.
**Confidence:** MODERATE
**False Positives:** None expected from administrators, who do not normally pass a base64-encoded script through `sh`. A software installer or a node-maintenance operator that stages a script the same way would hit.
**Blind Spots:** Misses a pod that delivers its script another way (an image entrypoint, a mounted config map, a long argument without `base64 -d`). Misses a cluster whose audit policy does not record request bodies for pod creation, which is the common setting. The field names are the flattened form of the audit event's request object and differ between log pipelines: NOT CHECKED against a live audit log.
**Validation:** Submit one of the case's pod specifications (privileged, node-root `hostPath` mounted at `/host`, an `sh -c` command that decodes a base64 script into `/tmp` and runs it) to a test cluster with request-body audit logging, and the rule fires. A pod with only `hostPath: /` or only a privileged container must not. Not run. Upstream: the SigmaHQ rules "Privileged Container Deployed" and "Container With A hostPath Mount Created" both match any pod creation that carries the field at all, at level low, so this activity already evaluates true on them; this rule is the narrow, higher-level version.
**Deployment:** Kubernetes API-server audit log at request-body level for `pods` creation, forwarded to the SIEM.
**Basis:** The thirteen manifests, which share one common shape in every manifest.

```yaml
title: Kubernetes Pod Created With Privileged Host Root Mount and Staged Base64 Script
id: 682eeb5a-e28d-4e60-b382-e971f9699bae
status: experimental
description: >-
    Detects creation of a pod that runs a privileged container, mounts the node's root filesystem through a hostPath volume,
    and runs a shell command that decodes a base64 string and executes the result from /tmp.
    The combination gives the pod the node's own filesystem, and the staged script runs against it.
    The case this rule is written from contained thirteen manifests of exactly this shape, none shown to have been submitted.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.privilege-escalation
    - attack.t1611
    - attack.execution
    - attack.t1610
    - stp.3
logsource:
    category: application
    product: kubernetes
    service: audit
    definition: 'Requires the Kubernetes API-server audit log at request-body level (RequestResponse) for pod creation. The field names are the flattened request object; adapt them to your log pipeline.'
detection:
    selection:
        verb: 'create'
        objectRef.resource: 'pods'
        requestObject.spec.containers.securityContext.privileged: true
        requestObject.spec.volumes.hostPath.path: '/'
        requestObject.spec.containers.args|contains|all:
            - 'base64 -d'
            - 'sh /tmp/'
    condition: selection
falsepositives:
    - A node-maintenance operator or installer that stages a decoded script from /tmp inside a privileged pod with the node root mounted
level: high
```

**Linux agent host traces**

#### Linux Process Executed From an In-Memory File With a Systemd Command Line

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1036.005 (Match Legitimate Resource Name or Location), T1620 (Reflective Code Loading)
**ATT&CK Note:** The agent re-executes itself from an anonymous memory file with argument zero set to a systemd command line. ATT&CK has no memfd sub-technique, so T1620 is the nearest.
**Confidence:** MODERATE
**False Positives:** None known. A real `systemd --user` runs from `/usr/lib/systemd/systemd`, not from a memory file or a file-descriptor path. Container runtimes that re-execute from a memory file do not use a systemd command line.
**Blind Spots:** The spoof string is a configuration slot in the agent, so a build that changes it (to any other name) escapes the command-line condition. Whether your telemetry reports the image as `/memfd:` or as `/proc/self/fd/N` depends on the sensor; the rule lists both. A host with no process-creation feed is not covered. Nothing was executed, so the image-path form is NOT CHECKED against a live sensor.
**Validation:** Run the agent on a lab Linux host, and a process-creation event with an image of `/memfd:` (or `/proc/self/fd/N`) and the command line `/lib/systemd/systemd --user` appears; the rule fires. A normal `systemd --user` must not. Not run. Upstream: the SigmaHQ clone holds one auditd rule that mentions `memfd`, an audio-capture rule, so this behaviour is not covered.
**Deployment:** Linux EDR or auditd with a process-creation feed that records the image path and the full command line.
**Basis:** The agent's start-up sequence (`memfd_create`, then `execl("/proc/self/fd/N", "/lib/systemd/systemd --user")`), from `agent.bin_analysis.md` section 2 steps 5 and 7, and the host anchors in section 8.

```yaml
title: Linux Process Executed From an In-Memory File With a Systemd Command Line
id: 714e0182-7abc-4ad7-812d-7f75b5555508
status: experimental
description: >-
    Detects a Linux process started from a memory-backed file or a file-descriptor path whose command line is a systemd user instance.
    A genuine systemd user manager runs from the systemd binary on disk.
    The Linux agent in the case this rule is written from copies itself into an anonymous memory file and re-executes with this command line to look like a service manager.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.t1036.005
    - attack.t1620
    - stp.3
logsource:
    category: process_creation
    product: linux
    definition: 'Requires a Linux process-creation feed (an EDR, or auditd with execve logging) that records the executed image path and the full command line.'
detection:
    selection_image:
        Image|startswith:
            - '/memfd:'
            - '/proc/self/fd/'
    selection_cmd:
        CommandLine|startswith: '/lib/systemd/systemd --user'
    condition: all of selection_*
falsepositives:
    - A custom init or sandbox tool that re-executes itself from a memory file while keeping a systemd-style argument zero
level: high
```

### Hunting Rules

**Windows OneDrive side-load (`msedge.dll`, `cookie_exporter.exe`)**

#### Image Loaded With an Expired Rockstar Games Signature

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1553.002 (Code Signing)
**ATT&CK Note:** ATT&CK v20 lists T1553.002 under Defense Impairment, so the rule carries that tactic tag; the case mapping files the same technique under Stealth. The signature digests match the loader's bytes, which shows the signer held the certificate's key. Whether that key is publicly known as leaked or the certificate revoked is NOT CHECKED.
**Confidence:** MODERATE
**False Positives:** Older Rockstar Games titles and the Social Club client load DLLs signed with this certificate, and Windows reports the signature as expired. A hit on a machine that runs those games is expected. I have not enumerated the legitimate DLLs.
**Blind Spots:** Keys on the signer name and the expired status, so it misses a build signed with another certificate and an unsigned build. The case's loader is one DLL; I know of no other binary signed with this certificate by the operator.
**Validation:** Load the case's `msedge.dll` with Sysmon image-load logging and the rule fires. A Rockstar Games title launched from its install directory fires it too, which is the false positive above. Not run: NOT CHECKED against live telemetry. Upstream: the SigmaHQ clone has no rule that mentions Rockstar.
**Deployment:** Sysmon Event ID 7 in the SIEM, reviewed by an analyst who then checks the DLL's path and whether the host plays the game.
**Basis:** The signature details and the build date nine years after the certificate expired, from `msedge.dll_analysis.md` section 1.

```yaml
title: Image Loaded With an Expired Rockstar Games Signature
id: 374c0e91-da88-479a-9d57-cff5120d588d
status: experimental
description: >-
    Detects a module load of a DLL whose signature is a Rockstar Games certificate that Windows reports as expired.
    The certificate expired in March 2017, and the loader in the case this rule is written from was built in 2026 with that certificate's key.
    A process that is not a Rockstar game loading such a DLL is worth a look at the DLL's path and build date.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.defense-impairment
    - attack.t1553.002
    - stp.2
logsource:
    category: image_load
    product: windows
    definition: 'Requires image-load logging that records the signer and the signature status, for example Sysmon Event ID 7 with the Signature and SignatureStatus fields. The default Sysmon configuration does not log module loads.'
detection:
    selection:
        Signature|contains: 'Rockstar Games'
        SignatureStatus: 'Expired'
        ImageLoaded|endswith: '.dll'
    condition: selection
falsepositives:
    - Legacy Rockstar Games titles and the Social Club client that load DLLs signed with this certificate
level: medium
```

#### OneDrive Command Folder Requests To Microsoft Graph With a Bare Mozilla User-Agent

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1102.002 (Bidirectional Communication)
**ATT&CK Note:** The implant reads a command file and writes an output file in a OneDrive folder named `cmd` through Microsoft Graph, and uploads files to the same folder.
**Confidence:** MODERATE
**False Positives:** A script or tool that calls Graph with the same bare agent string and keeps files in a OneDrive folder named `cmd`. I know of none.
**Blind Spots:** Needs a proxy that decrypts TLS, because the path is inside the encrypted session. The folder name `cmd` and the file names are operator choices and change without a rebuild. The agent string `Mozilla` is the WinINet agent set in the implant's code, and a rebuild can change it. Hosts that reach Graph directly rather than through the proxy are not covered.
**Validation:** Run the implant against a lab tenant behind a decrypting proxy and the GET for `command.txt` and the PUT for `output.txt` fire the rule. Not run, and I did not present the case's token to Microsoft: NOT CHECKED. Upstream: the SigmaHQ clone has no rule on the Graph `me/drive/root` path with this agent.
**Deployment:** Web-proxy logs from a TLS-decrypting proxy, with the URL path and the User-Agent.
**Basis:** The Graph request builders (`FUN_10004bbe`, `FUN_10005321`, `FUN_100047d0`) and the WinINet agent string, from `msedge.dll_analysis.md` sections 5 and 6.

```yaml
title: OneDrive Command Folder Requests To Microsoft Graph With a Bare Mozilla User-Agent
id: 0aa8af50-f75c-4cd7-a62f-0c0869210c78
status: experimental
description: >-
    Detects a request to Microsoft Graph for a file under a OneDrive folder named cmd at the drive root, sent with the bare User-Agent Mozilla and no version.
    The implant in the case this rule is written from reads its commands from cmd/command.txt, writes its output to cmd/output.txt and uploads files into the same folder.
    No browser or Microsoft client sends a bare Mozilla agent.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.command-and-control
    - attack.t1102.002
    - stp.2
logsource:
    category: proxy
    definition: 'Requires web-proxy logs from a proxy that decrypts TLS, with the full URL path and the User-Agent.'
detection:
    selection:
        cs-host: 'graph.microsoft.com'
        c-useragent: 'Mozilla'
        c-uri|contains: '/me/drive/root:/cmd/'
    condition: selection
falsepositives:
    - A script that calls Microsoft Graph with the same bare agent string and keeps files in a OneDrive folder named cmd
level: medium
```

#### Install-Window File Created Beside a Side-Loaded Edge Helper

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1480 (Execution Guardrails)
**ATT&CK Note:** The implant keeps an encrypted install-window timestamp in `cbt.bin`. Which side of the time comparison makes it exit is not settled, which is why the case mapping holds this at MODERATE.
**Confidence:** MODERATE
**False Positives:** Any other program that writes a file named `cbt.bin` from a process named `edge.exe` or `cookie_exporter.exe`. I know of none.
**Blind Spots:** Keys on two operator-chosen names, the file `cbt.bin` and the process names, so it misses a rebuild that renames either. It misses a host with no file-creation logging. The `edge.exe` image name is the name the case's copy used and is not fixed.
**Validation:** Run the case's `edge.exe` with Sysmon file-creation logging and `cbt.bin` appears in its directory, which fires the rule. Not run: NOT CHECKED against live telemetry. Upstream: no `cbt.bin` match in the SigmaHQ clone (not searched for that name specifically, only for the DLL and helper names above).
**Deployment:** Sysmon Event ID 11 in the SIEM.
**Basis:** The `cbt.bin` routine (`FUN_10004374`, `FUN_10004041`), from `msedge.dll_analysis.md` section 3 step 4 and section 6.

```yaml
title: Install-Window File Created Beside a Side-Loaded Edge Helper
id: fda2d5e2-3996-4050-b897-cd5e11f4a015
status: experimental
description: >-
    Detects the creation of a file named cbt.bin by a process named edge.exe or cookie_exporter.exe.
    The OneDrive implant in the case this rule is written from creates this file on first run to hold an encrypted install-window time beside its configuration file.
    Microsoft's cookie_exporter.exe helper has no reason to write it.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.t1480
    - stp.2
logsource:
    category: file_event
    product: windows
    definition: 'Requires file-creation logging, for example Sysmon Event ID 11.'
detection:
    selection:
        TargetFilename|endswith: '\cbt.bin'
        Image|endswith:
            - '\edge.exe'
            - '\cookie_exporter.exe'
    condition: selection
falsepositives:
    - Unknown software that writes a file named cbt.bin from a process with one of these names
level: medium
```

**Kubernetes pod creation (prepared-only in the case)**

#### Kubernetes Pod Created With Privileged Host Namespaces and the Node Root Mounted

**Tier:** Hunting
**Robustness:** 2
**Upstream Coverage:** covered
**ATT&CK Coverage:** T1611 (Escape to Host), T1610 (Deploy Container)
**ATT&CK Note:** Prepared-only in the case, as for the rule above. This is the same pod shape without the staged-script condition.
**Confidence:** MODERATE
**False Positives:** Administrators who open a node-level debug session with a sysadmin profile get a pod of this shape (privileged, host process, network and IPC namespaces, the node root mounted at `/host`). That is my understanding of how the standard Kubernetes node-debug command builds its pod, from background knowledge and not verified here. Node-maintenance and storage agents may also match.
**Blind Spots:** Needs request-body audit logging for pod creation, which is not the default policy in many clusters. A pod that drops one of the five properties (for example no host IPC namespace) is not matched, so a variant is missed. The field names are the flattened request object and differ between pipelines: NOT CHECKED against a live audit log.
**Validation:** Submit one of the case's pod specifications to a test cluster with request-body audit logging, and the rule fires. A pod with `hostPath: /` alone must not. Not run. Upstream: the SigmaHQ rules "Privileged Container Deployed" and "Container With A hostPath Mount Created" already evaluate true on this activity at level low, because each matches the presence of the field.
**Deployment:** Kubernetes API-server audit log at request-body level, with the node-debug and maintenance accounts on an allow list after a baseline.
**Basis:** The common shape of the thirteen manifests, identical in all 13.

```yaml
title: Kubernetes Pod Created With Privileged Host Namespaces and the Node Root Mounted
id: ca159c16-dda1-49de-a3a6-ff5d93ceeb87
status: experimental
description: >-
    Detects creation of a pod that is privileged, joins the node's process, network and IPC namespaces, and mounts the node's root filesystem through a hostPath volume.
    That combination hands the pod the whole node.
    The case this rule is written from contained thirteen manifests of exactly this shape, none shown to have been submitted.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.privilege-escalation
    - attack.t1611
    - attack.execution
    - attack.t1610
    - stp.3
logsource:
    category: application
    product: kubernetes
    service: audit
    definition: 'Requires the Kubernetes API-server audit log at request-body level (RequestResponse) for pod creation. The field names are the flattened request object; adapt them to your log pipeline.'
detection:
    selection:
        verb: 'create'
        objectRef.resource: 'pods'
        requestObject.spec.hostPID: true
        requestObject.spec.hostNetwork: true
        requestObject.spec.hostIPC: true
        requestObject.spec.containers.securityContext.privileged: true
        requestObject.spec.volumes.hostPath.path: '/'
    condition: selection
falsepositives:
    - An administrator opening a node-level debug session with a sysadmin profile
    - Node-maintenance or storage agents that run privileged with the node root mounted
level: medium
```

**Linux agent host traces**

#### Linux Process Executed From an In-Memory Plugin File

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** not_covered
**ATT&CK Coverage:** T1620 (Reflective Code Loading)
**ATT&CK Note:** The agent's plugin command downloads an ELF into a memory file and executes it, so any capability beyond the agent's eight commands arrives this way. The plugin ELFs are not in the capture.
**Confidence:** MODERATE
**False Positives:** Other software that names its own memory file `plugin` and executes it. I know of none. The memory-file name is a literal in the agent, and a rebuild can change it.
**Blind Spots:** Keys on the name `plugin`, so it misses a rebuild that renames it. The image-path form depends on the sensor and is NOT CHECKED against a live one.
**Validation:** Issue the plugin command to a lab copy of the agent, and the plugin child's image path contains `/memfd:plugin`. Not run. Upstream: no match in the SigmaHQ clone for `memfd`-named execution.
**Deployment:** Linux EDR or auditd with a process-creation feed that records the image path.
**Basis:** The plugin handler (`0x1035f60`), from `agent.bin_analysis.md` section 4 command 16 and the host anchors in section 8.

```yaml
title: Linux Process Executed From an In-Memory Plugin File
id: d14e72ef-4a98-4051-84b1-7dfee4a744c1
status: experimental
description: >-
    Detects a Linux process whose executable is a memory-backed file named plugin.
    The Linux agent in the case this rule is written from downloads an ELF from its server, writes it to a memory file with that name and executes it, which is how it receives any capability beyond its built-in commands.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.stealth
    - attack.t1620
    - stp.2
logsource:
    category: process_creation
    product: linux
    definition: 'Requires a Linux process-creation feed (an EDR, or auditd with execve logging) that records the executed image path.'
detection:
    selection:
        Image|contains: '/memfd:plugin'
    condition: selection
falsepositives:
    - Unknown software that names its own memory file plugin
level: medium
```

**Active Directory spray, enumeration, Kerberoast and relay**

#### Impacket NTLM Relay Server Started on a Linux Host

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** partially_covered
**ATT&CK Coverage:** T1557.001 (Name Resolution Poisoning and SMB Relay)
**ATT&CK Note:** Both relay start-ups in the case were exercised and received no authentication, and the node-side relay in the pod manifests is prepared-only. The case mapping holds the technique as observed but refused.
**Confidence:** MODERATE
**False Positives:** A red-team exercise running the tool, or anyone testing relay exposure.
**Blind Spots:** Keys on the script name and one option, so it misses a renamed script and a build that drops the option. It sees only a Linux host that reports process command lines. A relay run from the operator's own server, as in this case, produces no telemetry on the victim.
**Validation:** Run the tool with the two option sets seen in the case on a lab host with a Linux process-creation feed, and the rule fires. Not run: NOT CHECKED. Upstream: the SigmaHQ rules "HackTool - Impacket Tools Execution" and "Potential SMB Relay Attack Tool Execution" match Windows image names including `\ntlmrelayx`; I found no Linux command-line rule for it.
**Deployment:** Linux EDR or auditd process-creation feed on servers and container nodes, where a relay tool has no business reason to run.
**Basis:** The two operator launch lines, from `i43616_relay.sh` (a proxied launch with a target file and `--no-http-server`) and the node-side runner in the `man_i45014r1` pod manifest. Both pass `-smb2support`.

```yaml
title: Impacket NTLM Relay Server Started on a Linux Host
id: bfb9a933-1fb4-46c5-bd63-5fed032ef3fe
status: experimental
description: >-
    Detects a command line that starts the Impacket NTLM relay script with SMB2 support on a Linux host.
    The operator in the case this rule is written from launched the script this way twice, once from their own server and once from a runner prepared for a victim node.
    A relay server on a production server or container node is rarely legitimate.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1557.001
    - stp.2
logsource:
    category: process_creation
    product: linux
    definition: 'Requires a Linux process-creation feed that records the full command line.'
detection:
    selection:
        CommandLine|contains|all:
            - 'ntlmrelayx'
            - '-smb2support'
    condition: selection
falsepositives:
    - Authorized red-team exercises that run the relay tool
level: medium
```

#### Many Distinct Kerberos Service Tickets Requested From One Host

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** partially_covered
**ATT&CK Coverage:** T1558.003 (Kerberoasting)
**ATT&CK Note:** The case holds the harvest, not the requester: 239 AES-256 service tickets for 239 distinct service principal names across 89 accounts in one realm. No ticket-requesting tool is in the corpus, so the rule describes the volume pattern and does not claim a method.
**Confidence:** MODERATE
**False Positives:** Service-discovery and monitoring tools, vulnerability scanners, and a jump host or terminal server where many users reach many services from one address. Internal tools that enumerate SPNs.
**Blind Spots:** The threshold is a starting value and not derived from the case: the harvest file carries no timestamps, so how fast the operator requested the tickets is unknown. A slow harvest below the threshold passes. The base rule drops machine-account service names and requesters, so Kerberoasting of a computer account is missed. Unlike the common RC4 rule, this one does not filter on the encryption type, because every harvested ticket in the case was AES-256 (etype 18) and an RC4-only rule would not have seen it.
**Validation:** Request 25 service tickets for 25 distinct user-account service names from one lab host inside ten minutes and the correlation fires; request tickets for three services and it must not. Not run: NOT CHECKED against live telemetry. Upstream: the SigmaHQ rule "Kerberoasting Activity - Initial Query" is the same Event ID 4769 base but requires encryption type `0x17` and leaves the volume threshold to the user, so it would have missed this harvest; the rule "Suspicious Kerberos RC4 Ticket Encryption" is RC4-only as well.
**Deployment:** Domain-controller Security log, Event ID 4769, in a SIEM that supports correlation (the threshold and window are the tuning knobs; baseline against the busiest legitimate hosts first).
**Basis:** The Kerberoast harvest file's shape (239 tickets, 89 accounts, 239 distinct SPNs, etype 18 only, at most 16 tickets for one account).

```yaml
title: Kerberos Service Ticket Granted For a User Service Account
id: c1ce9762-eca1-4ad3-b8b3-b8cf40bb31bd
name: kerberos_service_ticket_user_account_base
status: experimental
description: >-
    Base rule for the correlation rule below. Matches a successful Kerberos service-ticket request for a service that is not the ticket-granting service and not a computer account.
    It carries no encryption-type condition on purpose, because the harvest in the case this rule is written from used AES-256 tickets only.
    Not meant to be alerted on by itself.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1558.003
    - stp.1
logsource:
    product: windows
    service: security
    definition: 'Requires the domain-controller Security log with Kerberos service ticket operations auditing enabled (Event ID 4769).'
detection:
    selection:
        EventID: 4769
        Status: '0x0'
    filter_main_service_names:
        # sourced: documented platform default, the ticket-granting service and computer accounts are the bulk of genuine Kerberos traffic
        ServiceName|endswith:
            - 'krbtgt'
            - '$'
    filter_main_machine_requesters:
        # sourced: documented platform default, computer accounts request tickets as part of normal domain operation
        TargetUserName|contains: '$@'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Every normal service-ticket request for a user service account; this base rule is for correlation only
level: informational
---
title: Many Distinct Kerberos Service Tickets Requested From One Host
id: 8436f81d-034a-474f-affe-06aecfc9b9fc
status: experimental
description: >-
    Fires when one client address is granted service tickets for 25 or more distinct user-account service names within 10 minutes, the volume shape of a Kerberoast harvest.
    The harvest in the case this rule is written from covered 239 service names for 89 accounts, though the time it took is not known.
    The threshold and window are starting values to tune against the busiest legitimate hosts.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1558.003
    - stp.1
correlation:
    type: value_count
    rules:
        - kerberos_service_ticket_user_account_base
    group-by:
        - IpAddress
    timespan: 10m
    condition:
        field: ServiceName
        gte: 25
falsepositives:
    - A jump host, terminal server or monitoring tool that legitimately reaches many services from one address
level: medium
```

#### Many Unknown Accounts Probed Over Kerberos From One Host

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1087.002 (Domain Account)
**ATT&CK Note:** The case's enumeration sent 253 authentication requests without pre-authentication, one per candidate account, and read the key distribution centre's error code: 138 answered "pre-authentication required", 112 answered "client not found" and 3 answered "revoked or disabled". None answered without pre-authentication.
**Confidence:** MODERATE
**False Positives:** A misconfigured application or a stale service account list that retries many retired user names, and a directory-migration tool. A password-spray run on a list that contains many wrong names also fires.
**Blind Spots:** The threshold is a starting value, and the case's log does not time the sweep. A sweep that keeps most names valid produces few "client not found" results, and the 138 existing accounts the operator found raise no event with this status. It sees only requests that reach a domain controller with account-logon auditing on.
**Validation:** Request authentication for 30 non-existent user names from one lab host within ten minutes and the correlation fires. Not run: NOT CHECKED against live telemetry. Upstream not searched for this pattern.
**Deployment:** Domain-controller Security log, Event ID 4768 with the result code, in a SIEM that supports correlation.
**Basis:** The enumeration script and its result file (`probe253.jsonl`: 253 lines, 138 / 112 / 3).

```yaml
title: Kerberos Authentication Request For an Unknown Account
id: 610f563b-5eb8-422d-b9f3-4e75bf0ade96
name: kerberos_asreq_unknown_account_base
status: experimental
description: >-
    Base rule for the correlation rule below. Matches a Kerberos authentication request for an account that does not exist in the directory (result code 0x6).
    Not meant to be alerted on by itself.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.discovery
    - attack.t1087.002
    - stp.1
logsource:
    product: windows
    service: security
    definition: 'Requires the domain-controller Security log with Kerberos authentication service auditing enabled (Event ID 4768, failures included).'
detection:
    selection:
        EventID: 4768
        Status: '0x6'
    condition: selection
falsepositives:
    - A single mistyped user name; this base rule is for correlation only
level: informational
---
title: Many Unknown Accounts Probed Over Kerberos From One Host
id: dfaccdba-57e1-4c75-8132-1220f2400b5f
status: experimental
description: >-
    Fires when one client address sends Kerberos authentication requests for 20 or more distinct accounts that do not exist within 10 minutes, the shape of a user-name enumeration sweep.
    The sweep in the case this rule is written from probed 253 names and 112 came back as unknown, though the time it took is not known.
    The threshold and window are starting values to tune.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.discovery
    - attack.t1087.002
    - stp.1
correlation:
    type: value_count
    rules:
        - kerberos_asreq_unknown_account_base
    group-by:
        - IpAddress
    timespan: 10m
    condition:
        field: TargetUserName
        gte: 20
falsepositives:
    - A directory-migration tool or an application with a stale account list that retries many retired names
level: medium
```

#### Many Accounts Failing a Network Logon With a Wrong Password From One Host

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1110.003 (Password Spraying)
**ATT&CK Note:** The case's spray made 136 LDAP simple binds, one per account, cycling eight candidate passwords, and every bind was rejected with the directory's wrong-password code. The Kerberos twin of the spray crashed after one attempt. The technique is observed but refused.
**Confidence:** LOW
**False Positives:** A shared workstation or a terminal server where many users mistype passwords after a password-policy change, a misconfigured service that retries across accounts, and a gateway that proxies logons from many users through one address.
**Blind Spots:** I do not know which Windows event a failed LDAP simple bind raises on a domain controller, so whether this rule sees the case's spray at all is NOT CHECKED. The directory error in the operator's log is the wrong-password code, which matches the sub-status below, but the log shows the operator's side only. The threshold is a starting value, and the case's spray log carries no timestamps.
**Validation:** Fail a network logon for 20 distinct accounts from one lab host within ten minutes, and the correlation fires. Fail one LDAP simple bind and check which event the domain controller writes before relying on the rule for LDAP sprays. Not run: NOT CHECKED. Upstream not searched for password-spray correlations.
**Deployment:** Domain-controller Security log, Event ID 4625, in a SIEM that supports correlation.
**Basis:** The spray script and its logs (136 planned, 135 rejected with the bad-password code, 1 session error, 0 successes).

```yaml
title: Failed Network Logon With a Wrong Password
id: 63ef0bc4-6b6e-47a4-aa68-abcd299ff22a
name: failed_network_logon_wrong_password_base
status: experimental
description: >-
    Base rule for the correlation rule below. Matches a failed network logon whose sub-status is the wrong-password code.
    Not meant to be alerted on by itself.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1110.003
    - stp.1
logsource:
    product: windows
    service: security
    definition: 'Requires the domain-controller Security log with logon failure auditing enabled (Event ID 4625).'
detection:
    selection:
        EventID: 4625
        LogonType: 3
        SubStatus: '0xc000006a'
    condition: selection
falsepositives:
    - A single mistyped password; this base rule is for correlation only
level: informational
---
title: Many Accounts Failing a Network Logon With a Wrong Password From One Host
id: d953ea41-0fb9-41f1-8282-d450a1635177
status: experimental
description: >-
    Fires when one client address fails a network logon with the wrong-password code for 20 or more distinct accounts within 10 minutes, the shape of a password spray that tries one password per account.
    The spray in the case this rule is written from made 136 attempts, one per account, cycling eight passwords.
    The threshold and window are starting values to tune.
references:
    - https://the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/
author: The Hunters Ledger
date: 2026-11-14
tags:
    - attack.credential-access
    - attack.t1110.003
    - stp.1
correlation:
    type: value_count
    rules:
        - failed_network_logon_wrong_password_base
    group-by:
        - IpAddress
    timespan: 10m
    condition:
        field: TargetUserName
        gte: 20
falsepositives:
    - A shared workstation, terminal server or authentication gateway where many users fail at once
level: medium
```

---

## Suricata Signatures

All six rules were accepted by `suricata -T` on the firewall sensor in one run. No rule was replayed against a capture, because the case holds no capture that carries these payloads (`i47769.pcap` is 163 packets of scanner traffic), so none has been seen to fire: NOT CHECKED. Suricata upstream coverage is NOT CHECKED for every rule.

### Detection Rules

#### THL DETECT INV-2026-083 Chisel v3 WebSocket Tunnel Client Upgrade

**Tier:** Detection
**Robustness:** 2
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1572 (Protocol Tunneling)
**ATT&CK Note:** The operator started a chisel server with reverse tunnelling and user authentication on port 80, and a host in the agency's address range held a long, symmetric, self-reconnecting session to that port. The case holds that session as MODERATE, because which program listened on port 80 during it is NOT CHECKED, and the session payload was not decoded. This rule keys on the tool's protocol string, which the held chisel binary contains.
**Confidence:** MODERATE
**False Positives:** An administrator or contractor who uses chisel to reach a service through a firewall, and a red-team exercise. Chisel has no routine use inside most corporate networks.
**Blind Spots:** Sees only plaintext HTTP. Chisel wrapped in TLS, or run behind a reverse proxy that strips the header, passes. A fork that changes the protocol string passes, and the string is fixed by the chisel major version, not by this operator.
**Validation:** Run a chisel client against a chisel server on a lab port with no TLS, and the client's upgrade request carries `Sec-WebSocket-Protocol: chisel-v3`. The held binary (sha256 prefix `0a76c28f5452`) contains that string once. The rule has not been replayed: NOT CHECKED. A normal browser WebSocket upgrade, which carries other protocol names, must not fire.
**Deployment:** Egress sensor on client-to-internet HTTP, port-agnostic.
**Basis:** The chisel binary and its server start-up log.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT INV-2026-083 Chisel v3 WebSocket Tunnel Client Upgrade (Tunnel Transport Indicator)"; flow:established,to_server; http.header; content:"Sec-WebSocket-Protocol|3a 20|chisel-v3"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000001; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

### Hunting Rules

#### THL HUNT INV-2026-083 Agent C2 Zone customerlop.top DNS Query

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**ATT&CK Note:** The agent's configured server is `www[.]customerlop[.]top` (HIGH, read from the config slot). The zone also has two unproxied subdomains, `mail` and `update`, that resolve to two rented-server addresses. The case holds the DNS records as HIGH, that the hosts behind them belong to the operator as LOW (the addresses are shared rental slots with earlier unrelated tenants), and the cluster of zone and hosts as MODERATE. The rule matches the whole zone and so covers all three names.
**Confidence:** MODERATE
**False Positives:** None known. The zone was registered on 2026-05-22 and no legitimate use is established. A security team or a sinkhole that resolves the name will hit.
**Blind Spots:** One domain: if the operator repoints the agent's host slot to another name, which needs no rebuild, the rule goes silent. It says nothing about the three newer domains (`robonode[.]shop`, `transportdustry[.]my`, `healthgenius[.]icu`). The case ties `robonode[.]shop` to the zone at MODERATE through a Cloudflare Origin certificate served from the zone's mail host (a single-source subject, with a shared-host alternative open), and it is in the indicator feed at MODERATE. It ties `transportdustry[.]my` and `healthgenius[.]icu` to the zone only through `robonode[.]shop`, registrar, hosting and a mail address, each shared by many unrelated customers (LOW), so I leave all three out of this rule and hold the other two.
**Validation:** Resolve `www.customerlop.top` from a lab resolver behind the sensor and the rule fires. Not run (no packet was sent to the actor's infrastructure in this work, and none is needed to run this check against a lab resolver): NOT CHECKED. A lookup of an unrelated zone must not fire.
**Deployment:** DNS sensor or resolver log. Alert-grade only with analyst triage, and the same indicator belongs in the IOC feed for blocking.
**Basis:** The agent's host slot (`agent.bin_analysis.md` section 3) and the zone's records (`infrastructure.md` sections 2 and 10).

```suricata
alert dns $HOME_NET any -> any any (msg:"THL HUNT INV-2026-083 Agent C2 Zone customerlop.top DNS Query (C2 Domain Indicator)"; dns.query; dotprefix; content:".customerlop.top"; nocase; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000002; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

#### THL HUNT INV-2026-083 Agent C2 Zone customerlop.top TLS SNI

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**ATT&CK Note:** The agent sends the configured name as the TLS server name on every beacon. The agent speaks TLS 1.2 and does not check the server certificate, so the sensor sees a normal ClientHello from an mbed TLS 3.6.0 client; its TLS fingerprint was not computed.
**Confidence:** MODERATE
**False Positives:** None known, as for the DNS rule.
**Blind Spots:** The same single-name limit as the DNS rule. A client using Encrypted Client Hello hides the name. The agent beacons about every 54 to 66 seconds by default, a pace the rule's one-alert-per-hour threshold hides on purpose, and the pace itself is not matched.
**Validation:** Open a TLS session with SNI `www.customerlop.top` from a lab host behind the sensor and the rule fires. Not run: NOT CHECKED.
**Deployment:** Egress TLS sensor. Same indicator in the IOC feed.
**Basis:** The agent's host slot and TLS setup, from `agent.bin_analysis.md` section 3.

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-083 Agent C2 Zone customerlop.top TLS SNI (C2 Domain Indicator)"; flow:established,to_server; tls.sni; dotprefix; content:".customerlop.top"; nocase; endswith; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000003; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

#### THL HUNT INV-2026-083 HTTPS Agent JSON Key And Data Beacon With No User-Agent

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1071.001 (Web Protocols), T1001.003 (Protocol or Service Impersonation)
**ATT&CK Note:** Inside TLS the agent sends HTTP POSTs to stock-looking WordPress theme, AJAX and jQuery paths with a JSON body of a key and a data field. The paths are configuration slots; the body shape and the missing User-Agent are fixed in the code.
**Confidence:** MODERATE
**False Positives:** Other custom clients that post a JSON body with `key` and `data` fields to a path under `/wp-` with no User-Agent header. That is an unusual combination, but I have not measured it.
**Blind Spots:** Needs the traffic decrypted, which most sensors do not have. A rebuild that adds a User-Agent or changes the body templates passes. The rule does not match the path set exactly, only the `/wp-` prefix, so it also covers a re-configured path under that prefix.
**Validation:** Run the agent against a lab server behind a decrypting proxy mirror and the register request fires the rule. Not run: NOT CHECKED. An ordinary WordPress admin POST carries a User-Agent and a form body and must not fire.
**Deployment:** A sensor that receives decrypted HTTP (a TLS-inspecting proxy's mirror port), or an endpoint HTTP telemetry feed.
**Basis:** The agent's request builder, body templates and path slots, from `agent.bin_analysis.md` sections 3 and 5.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-083 HTTPS Agent JSON Key And Data Beacon With No User-Agent (Decrypted C2 Traffic)"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/wp-"; startswith; http.header_names; content:!"|0d 0a|User-Agent|0d 0a|"; nocase; http.request_body; content:"{|22|key|22 3a 22|"; startswith; content:"|22 2c 22|data|22 3a 22|"; distance:0; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000004; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

#### THL HUNT INV-2026-083 OneDrive cmd Folder Request To Graph With Bare Mozilla User-Agent

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1102.002 (Bidirectional Communication)
**ATT&CK Note:** The same condition as the Sigma proxy rule, written for a sensor that sees decrypted HTTP.
**Confidence:** MODERATE
**False Positives:** A script that calls Graph with a bare `Mozilla` agent and keeps files in a OneDrive folder named `cmd`. I know of none.
**Blind Spots:** Needs decrypted traffic. The folder name and the agent string are literals in the implant and change with a rebuild. Blocking the Graph hostname is not an option, so this is a hunt only.
**Validation:** As the Sigma proxy rule. Not run: NOT CHECKED.
**Deployment:** Decrypted HTTP mirror or proxy log.
**Basis:** The Graph request builders and the agent string, from `msedge.dll_analysis.md` sections 5 and 6.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-083 OneDrive cmd Folder Request To Graph With Bare Mozilla User-Agent (Decrypted C2 Traffic)"; flow:established,to_server; http.host; content:"graph.microsoft.com"; bsize:19; http.user_agent; content:"Mozilla"; bsize:7; http.uri; content:"/me/drive/root|3a|/cmd/"; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000005; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

#### THL HUNT INV-2026-083 Refresh-Token Grant With Office Client Id And Bare Mozilla User-Agent

**Tier:** Hunting
**Robustness:** 1
**Upstream Coverage:** NOT CHECKED
**ATT&CK Coverage:** T1102.002 (Bidirectional Communication)
**ATT&CK Note:** The implant refreshes its access token every 15 minutes with a refresh-token grant to the version-1 token endpoint. The client id in the request is, from my own background knowledge, a Microsoft first-party Office public client (MODERATE, not verified in this work), which needs no application registration by the operator.
**Confidence:** MODERATE
**False Positives:** Another tool that uses the same public client id with a bare `Mozilla` agent, such as a script that refreshes Microsoft 365 tokens. I know of none.
**Blind Spots:** Needs decrypted traffic. An operator can swap the client id for another public client. In the Entra sign-in logs of the token's own tenant, which may not be the victim's, the same activity appears as non-interactive sign-ins by the Microsoft Office application about every 15 minutes, and that is a better place to look than the wire.
**Validation:** Run the implant behind a decrypting mirror in a lab with a throwaway tenant, and the first token request fires the rule. I did not present the case's token to Microsoft and did not run this: NOT CHECKED.
**Deployment:** Decrypted HTTP mirror or proxy log, and the Entra non-interactive sign-in log of any tenant whose tokens may be involved.
**Basis:** The token request builder (`FUN_1000372b`), from `msedge.dll_analysis.md` section 5.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THL HUNT INV-2026-083 Refresh-Token Grant With Office Client Id And Bare Mozilla User-Agent (Decrypted C2 Traffic)"; flow:established,to_server; http.method; content:"POST"; http.host; content:"login.microsoftonline.com"; bsize:25; http.user_agent; content:"Mozilla"; bsize:7; http.uri; content:"/oauth2/token?api-version=1.0"; endswith; http.request_body; content:"client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c"; content:"grant_type=refresh_token"; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/inv-2026-083-federal-ad-credential-access-rig-detections/; classtype:trojan-activity; sid:1000006; rev:1; metadata:author The_Hunters_Ledger, date 2026-11-14;)
```

---

## Coverage Gaps

This file carries 25 rules. Every behaviour I left without a rule is listed here with its reason.

### Atomics routed to the indicator feed, not written as rules

A rule whose only discriminator is one of these would stop detecting anything the day the value changes, so each belongs in the indicator feed for this case.

- **Sample hashes.** The agent, the loader DLL, its encrypted configuration file and the chisel binary. The agent's static key string is also a handle: the sha256 of the full 44 bytes is `642fedfa569003ed5427715a9b6a8ea6365f8e10edc935758e0017aeb17aa0d0`. These are the YARA group in the summary table.
- **The command-and-control zone and its addresses.** `customerlop[.]top` (registered 2026-05-22), its unproxied `mail` and `update` names, and the two rented-server addresses they resolve to. Of the three newer zones, `robonode[.]shop` goes to the feed at MODERATE (a Cloudflare Origin certificate served from the zone's mail host, single-source subject), and `transportdustry[.]my` and `healthgenius[.]icu` are held back because the case ties them only through shared registrar, hosting and a mail address; the name-server leg is withdrawn. These are the Suricata group.
- **Operator-chosen literals in the prepared pod scripts.** The engagement number in the working directory, the label and the systemd unit name. Nothing shows the pods ran, so a file-event rule on them would key on a name no held artifact has created. These and the mutex `Global\OdMutex` (no mutex log source is common; the YARA rule that keys on the mutex prefix covers memory) are the Sigma group.
- **Cloud identifiers with no wire or host rule.** The Microsoft Entra tenant identifier in the loader's configuration and the Rockstar Games certificate serial and thumbprint. The tenant identifier is the highest-value takedown target in the case, because the tenant holds the command folder; it needs a report to Microsoft, not a rule.
- **The fixed NTLM server challenge.** The operator's capture path used one server challenge for all 111,559 captured responses. It is an operator value, and a rule on it would be an indicator.

### Behaviour observed or prepared, but not covered by a rule

- **NTLM capture servers and the relay's victim-side effect.** The operator's HTTP capture servers took 43,317 connections and captured no authentication, and the SMB capture server rejected every SMB2 negotiation. The relay listeners received nothing. All of that runs on the operator's side, so it produces no victim-side event that I could derive a rule from. The one rule here is the Linux relay command line.
- **Kerberos service-ticket requests by method.** The case holds the 239 harvested tickets and no requesting tool, no ticket-request log and no crack result, so I cannot say whether the requester used an authenticated account or an account without pre-authentication. The Kerberoast rule describes volume only, and its threshold is not derived from the case.
- **The password spray's success and the Kerberos spray.** The LDAP spray never succeeded, and the Kerberos twin of it crashed after one attempt. The failed-logon correlation is the only rule, and which Windows event an LDAP simple-bind failure raises on a domain controller is NOT CHECKED.
- **Zero-credential Netlogon probes.** Twenty probes on six controllers all failed at the challenge request. I have no evidence of the event they leave on a domain controller, so no rule.
- **Pod-side execution.** Nothing in the case shows any of the thirteen pod specifications was submitted to a cluster or that any node-side step ran, so the two Kubernetes rules detect creation of a pod of that shape and nothing about its effect. The node-side relay, coercion and registry-save steps in the scripts are prepared-only, and a rule on their command lines would key on text no victim has been shown to run.
- **The forged cluster-admin client certificate.** The operator holds a client certificate with the cluster-admin group, signed under the key of the agency's web host certificate. Whether any cluster accepted it is NOT CHECKED. A cluster audit-log rule on the cluster-admin group from an unexpected address would be a reasonable hunt, but the case has no acceptance event to derive it from, so I did not write it.
- **The loader's scheduled-task persistence and its uninstall command chain.** The `schtasks` routine and the exact uninstall command line were not read; only their existence from the verb strings. A command-line rule would be a guess at text.
- **The loader's `fsys` and `download` handlers.** Not read, so I wrote nothing about how files are listed or taken.
- **Chisel on the command line.** The case holds the server's start-up log and no client or server command line. SigmaHQ already carries rules for chisel by Windows image name. The Suricata rule above covers the tool's protocol string instead.
- **The two web-shell and upload files in the agency's web application.** They are prepared-only in the case mapping, with no execution output, and the upload primitive is NOT CHECKED, so I wrote nothing on them.
- **A TLS fingerprint for the Linux agent.** The agent's client fingerprint (JA3 or JA4) was not computed. A fingerprint rule would be Detection-eligible and would survive a change of C2 host. It needs a lab capture of one handshake from the agent, which would also confirm the TLS 1.2 and no-certificate-check reading that is currently from the code only.
- **The configuration blob and the install-window file.** Both are AES-256-CBC output with the key stored in the same file, so they have no magic bytes or structure beyond their length, and a rule on them would match high-entropy data.
- **Plugin ELFs and exfiltrated content.** The agent's plugin command can load any capability, and no plugin or collected file is in the capture.

### What would let me write more

- A lab capture of the Linux agent's handshake, for a TLS-fingerprint rule.
- The agency's domain-controller Security log for the window from 2026-10-29, which would turn the three Active Directory correlation rules from starting thresholds into measured ones, and would show which event a failed LDAP simple bind raises.
- The cluster's API-server audit log, which would show whether any of the pod specifications or the forged certificate was used.
- A second sample carrying the same static key string or the same Rockstar Games signature, which would move both Hunting YARA pivots toward Detection.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Free to use, including commercially, with attribution to The Hunters Ledger.
