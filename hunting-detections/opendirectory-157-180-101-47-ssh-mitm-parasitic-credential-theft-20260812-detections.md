---
title: "Detection Rules — SSH Interception and Parasitic Credential Theft, 157.180.101.47"
description: "Hunting and detection rules for an SSH interception credential-theft platform (157.180.101.47). 6 YARA, 15 Sigma, 3 Suricata rules."
date: '2026-08-12'
layout: post
permalink: /hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
thumbnail: /assets/images/cards/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812.png
hide: true
unlisted: true
---

**Campaign:** SSHInterception-ParasiticCredentialTheft-157.180.101.47
**Date:** 2026-08-12
**Author:** The Hunters Ledger
**License:** CC BY 4.0
**Reference:** https://the-hunters-ledger.com/reports/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812/

---

## Detection Coverage Summary

> **Who these rules are for.** The 41 third-party relays carrying this interceptor are compromised victims, not attacker infrastructure. Every host-side rule below exists so a hosting provider or a sysadmin can find the interceptor running on their own box, not so a defender can profile the operator. The relay's listener is dropped for every non-loopback packet, so port scanning a compromised node returns nothing regardless of how many nodes are live; detection has to be host-side or traffic-side. See Coverage Gaps for the full operational caveat.

| Rule Type | Detection | Hunting | MITRE Techniques Covered | Atomics → feed |
|---|---|---|---|---|
| YARA | 6 | 0 | T1557, T1071.001, T1021.004, T1083, T1686, T1056 | 9 |
| Sigma | 3 documents | 12 documents (2 bundles) | T1557, T1686, T1480, T1059.006, T1105, T1082, T1059, T1564.001, T1571 | 0 |
| Suricata | 2 | 1 | T1557, T1071.001 | 11 |

> **Detection vs Hunting:** *Detection rules* are high-fidelity and evasion-resilient, safe to alert on. *Hunting rules* are broader, for scoping and threat-hunting, and the hits need review.

The operator's six infrastructure addresses (plus loopback, recorded only so it is not mistaken for a victim), the nine file hashes for the interceptor, receiver, orchestrator, and both payload scripts, the receiver's TLS certificate hashes, its JARM, and its JA4X value all live in `opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-iocs.json` rather than anchoring a rule in this file. The operator has already rotated his reporting token once and rebuilt his estate after a prior compromise of his own infrastructure. Every rule below is built to survive him doing that again, because each one keys on the shape of the interception mechanism rather than on where it currently lives.

Two constraints govern every rule in this file. The 41 relays are externally silent by design (`iptables -I INPUT 1 -p tcp --dport 19923 ! -i lo -j DROP`), so nothing here is a network scan of the listener port; every network-side rule targets either the relay's *outbound* reporting traffic or a connecting client's view of the fake SSH server, never an unsolicited probe of the relay itself. And everything the interceptor touches except two package-manager traces lives in `/dev/shm` (tmpfs), so a reboot destroys the volatile evidence before it destroys the infection. Rules built on the two reboot-surviving traces are marked accordingly below.

---

## YARA Rules

All six rules below target the platform's own Python, Perl, and shell source, or a leaked copy of its session-recording output. This is a source-available, operator-written toolkit rather than a packed or obfuscated binary, so PE/ELF structural checks do not apply; every condition below is a filesize bound plus a specific string combination instead. Each rule is written to be evaluated against a captured file (a forensic disk image, a paste-cache export, a `/dev/shm` snapshot taken before the platform's own three-second self-wipe, or a process-memory dump saved as a file). Every condition tests `filesize`, which is undefined in a libyara live process-memory scan, so none of these rules matches a live process; scan a saved dump instead.

### Detection Rules

#### MITM_Interceptor_SourceStrings

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**Confidence:** HIGH
**False Positives:** None known. Every anchor string is either a literal constant unique to this codebase (the `0x4D49544D` SO_MARK value, which has no legitimate use anywhere) or a log/webhook string with no plausible collision in unrelated software.
**Blind Spots:** Requires 4 of 7 anchors to survive in whatever is being scanned, so a heavily truncated capture or a hand-edited fork that renames its log strings can evade this. Fires only on the interceptor component itself, not on the receiver, orchestrator, or payload scripts (see the companion rules below). The condition tests `filesize`, which is undefined in a libyara process-memory scan, so the rule matches files and saved dumps only and never a live process.
**Validation:** Run against a full copy of the interceptor source (captured from `/dev/shm` before the self-wipe, from a paste-cache export, or from a process-memory dump saved as a file) and confirm at least 4 of the 7 strings match. A clean host running an unrelated Python SSH tool, including the public `ssh-mitm` project this platform's log paths echo, must not fire, since none of those tools use this SO_MARK value or these exact log-line formats.
**Deployment:** Forensic scanning of captured filesystem images and `/dev/shm` snapshots; scanning of process-memory dumps saved as files on hosts already suspected of compromise. Live process-memory scanning is not covered, because the `filesize` test cannot match there.

```yara
/*
   Yara Rule Set
   Identifier: SSH Interception and Parasitic Credential Theft Platform - 157.180.101.47
   Author: The Hunters Ledger
   Source: https://the-hunters-ledger.com/
   License: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/
*/

rule MITM_Interceptor_SourceStrings {
   meta:
      description = "Detects the Python interceptor component of a self-hosted SSH adversary-in-the-middle platform, based on its startup log line, host-key pool warmup message, loop-prevention SO_MARK constant, and the plaintext-password title format written into its session recordings"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      hash1 = "44e259bef730a408bbdb0e07d3c421439fe30c9a2b8a27019b1b40fe6d031013"
      family = "SSH MITM Interception Platform"
      malware_type = "Adversary-in-the-Middle credential interceptor"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "da315918-ed4b-5563-b6a5-d315e90d80b6"
   strings:
      $s1 = "MITM_LOCAL listen=0.0.0.0:19923 webhook=" ascii
      $s2 = "KEY_POOL warmup done loaded=" ascii
      $s3 = "0x4D49544D" ascii
      $s4 = "pubkey_probe" ascii fullword
      $s5 = "cast_gz_b64" ascii fullword
      $s6 = "MITM {client_ip} -> {target_ip}:{target_port} {user}:{password}" ascii
      $s7 = "MITM PID=" ascii
   condition:
      filesize < 150KB and
      4 of them
}
```

#### MITM_Receiver_SourceStrings

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1071.001 (Web Protocols)
**Confidence:** HIGH
**False Positives:** None known. `self.headers.get('X-Token', '')` alone is a common auth idiom, so it cannot fire the rule alone. The condition is `3 of them` over four strings and does not make the X-Token line mandatory: the forbidden response plus both table names also fires with no auth string, and the X-Token line plus any two others fires too. The two table names (`pubkey_probes`, `hostkeys`) carry the specificity.
**Blind Spots:** Targets the receiver's own source, which sits on operator-owned infrastructure rather than a victim host, so this rule is most useful for confirming a suspected receiver or finding a successor deployed with the same code rather than for triaging a compromised relay.
**Validation:** Run against a captured copy of the receiver script and confirm at least 3 of the 4 strings match. A generic Python HTTP server implementing unrelated bearer-token auth must not fire: the auth idiom and a forbidden response are only two of the four strings, and the table-name strings (`pubkey_probes`, `hostkeys`) are specific to this schema. A file holding the forbidden response and both table names with no auth line is a deliberate positive.
**Deployment:** Forensic scanning of infrastructure suspected of hosting a receiver or successor receiver; not applicable to relay-side triage.

```yara
rule MITM_Receiver_SourceStrings {
   meta:
      description = "Detects the Python receiver component of a self-hosted SSH adversary-in-the-middle platform, based on its single shared static-token authentication check, its exact unauthenticated JSON error response, and the database table names it creates for harvested public keys and fake host keys"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      hash1 = "16ecc69027371c47a27296702c78dbd48013a98605989d5e5c2c4cc8159020ef"
      hash3 = "fae41061a152b85bceaa6ca4482bf7ca"
      family = "SSH MITM Interception Platform"
      malware_type = "Adversary-in-the-Middle credential interceptor"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "f1d23ddb-d903-597a-b50d-5eee70fdce10"
   strings:
      $s1 = "self.headers.get('X-Token', '')" ascii
      $s2 = "{\"error\": \"forbidden\"}" ascii
      $s3 = "pubkey_probes" ascii fullword
      $s4 = "hostkeys" ascii fullword
   condition:
      filesize < 100KB and
      3 of them
}
```

#### MITM_Orchestrator_SourceStrings

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1021.004 (SSH)
**Confidence:** HIGH
**False Positives:** None known. `PERL_SCRIPT`, `seen.db` and `MAX_PARALLEL` are generic names, so the condition requires three of the five strings and at least one of the two family-specific names, `black_auto.ip` or `pwned.log`; three generic names alone no longer fire. A partial capture that lost both specific names does not match.
**Blind Spots:** Detects the orchestrator's source, not its runtime behavior; a copy that never executes still matches. A capture missing both `black_auto.ip` and `pwned.log` evades. Says nothing about how many credentials were actually replayed.
**Validation:** Run against a captured copy of the orchestrator script and confirm at least 3 of the 5 strings match, including `black_auto.ip` or `pwned.log` (replay against the captured script is NOT CHECKED). A generic SSH automation script (Ansible, Fabric, a homegrown fleet tool) must not fire; a file holding only `PERL_SCRIPT`, `seen.db` and `MAX_PARALLEL` is the negative case.
**Deployment:** Forensic scanning of infrastructure suspected of running the automated credential re-use step; relevant to operator-side infrastructure rather than relay triage.

```yara
rule MITM_Orchestrator_SourceStrings {
   meta:
      description = "Detects the orchestrator component of a self-hosted SSH adversary-in-the-middle platform, which tails the interceptor's capture log and automatically replays each captured credential against its own target before delivering a fingerprinting payload"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      hash1 = "bd028737b383dc15e8524074892497660acb2d4dcb33aab91a096a2419b4780d"
      family = "SSH MITM Interception Platform"
      malware_type = "Automated credential re-use orchestrator"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "8fbbe38f-510d-56ea-8f02-d0dfff8f5aa1"
   strings:
      $s1 = "PERL_SCRIPT" ascii fullword
      $s2 = "seen.db" ascii fullword
      $s3 = "black_auto.ip" ascii fullword
      $s4 = "pwned.log" ascii fullword
      $s5 = "MAX_PARALLEL" ascii fullword
   condition:
      filesize < 30KB and
      3 of them and
      ($s3 or $s4)
}
```

#### MITM_Payload_Perl_Fingerprint

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1083 (File and Directory Discovery)
**ATT&CK Note:** The payload checks whether `/root/.ssh/authorized_keys` has content and reports `ssh_keys=yes` or `ssh_keys=none`. That file holds public authorization keys, so Private Keys (T1552.004) is not claimed.
**Confidence:** HIGH
**False Positives:** None known. The full command text `authorized_keys 2>/dev/null | head -3` is distinctive enough on its own; requiring it alongside the `ssh_keys=` output-flag string leaves essentially no room for accidental collision.
**Blind Spots:** At 597 to 598 bytes this script is trivial to rewrite; an operator who changes the output-flag naming or the exact head command defeats this rule immediately. It covers only the root-privileged `payload.pl`: the unprivileged `payload_user.pl` is described in the report as omitting `authorized_keys` and `ssh_keys`, so it does not match.
**Validation:** Run against a captured copy of the privileged `payload.pl` and confirm both strings match; `payload_user.pl` should not match (neither claim has been run against a captured copy, NOT CHECKED). A generic system-fingerprinting one-liner that happens to read `authorized_keys` for an unrelated reason (a key-audit script, for instance) is very unlikely to also emit a `ssh_keys=` flag in this exact form.
**Deployment:** Forensic scanning of `/dev/shm` snapshots and any staging location on a relay; scanning of captured payloads recovered from network capture or a saved process-memory dump, written out as files.

```yara
rule MITM_Payload_Perl_Fingerprint {
   meta:
      description = "Detects the small Perl fingerprinting payload delivered over the SSH exec channel immediately after an automated credential replay succeeds, which reports only whether root SSH keys are present without exfiltrating their contents"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      hash1 = "ad3f7e4835e91de5e237c319550450815ec5b8b42bbcfc6c1eccdd7bf7b5f933"
      hash2 = "356a8a171e96f5c69e4e2bb1d778f10909632df69663947d1887f4a6f6cd37ba"
      family = "SSH MITM Interception Platform"
      malware_type = "Post-exploitation fingerprint payload"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "85fc18ee-2e06-5416-9af7-c034b23966b8"
   strings:
      $s1 = "ssh_keys=" ascii
      $s2 = "authorized_keys 2>/dev/null | head -3" ascii
   condition:
      filesize < 2KB and
      all of them
}
```

#### MITM_Deploy_Firewall_Script

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1686 (Disable or Modify System Firewall)
**Confidence:** HIGH
**False Positives:** None known. All four anchors are exact, multi-token command lines; requiring only 2 of 4 tolerates a deploy script edited to add or reorder VPN-scheme branches without losing detection, while still needing genuine overlap with this exact firewall sequence.
**Blind Spots:** The deploy script is a small shell file that is trivial to reword without changing its effect. The four strings are unordered literals matched anywhere in the file, so reordering the lines or splitting them across functions does not evade; changing the text of a line does (a different mark value, set name, `maxelem` or find expression removes that line's match), and rewording three of the four lines drops the file below the 2-of-4 threshold. This rule catches the script text as currently written, not the underlying technique; the companion Sigma rules look at the executed commands instead.
**Validation:** Run against a captured copy of the deploy or self-wipe script and confirm at least 2 of the 4 lines match verbatim. A generic firewall-hardening script that happens to use `iptables` and `ipset` in the same file must not fire, since the exact mark value, exclusion-set name, and self-wipe find command are specific to this tool.
**Deployment:** Forensic scanning of `/dev/shm` snapshots taken before the self-wipe runs, paste-cache exports, and any staging location recovered from a relay under active investigation.

```yara
rule MITM_Deploy_Firewall_Script {
   meta:
      description = "Detects the shell deployment script that installs the netfilter rule chain of a self-hosted SSH adversary-in-the-middle platform: a loop-prevention mark exemption, an exclusion-list ipset, and a delayed self-wipe of the staging directory"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      family = "SSH MITM Interception Platform"
      malware_type = "Deployment and firewall-installation script"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "5f5e6363-fa0a-573a-bcad-aea6c095c04a"
   strings:
      $s1 = "iptables -t nat -I OUTPUT 1 -m mark --mark 0x4D49544D -j RETURN" ascii
      $s2 = "ipset create mitm_exclude hash:ip maxelem 1000000 -exist" ascii
      $s3 = "find \"$SCRIPT_DIR\" -mindepth 1 ! -name stop.sh -delete" ascii
      $s4 = "iptables -I INPUT 1 -p tcp --dport 19923 ! -i lo -j DROP" ascii
   condition:
      filesize < 20KB and
      2 of them
}
```

#### MITM_Leaked_Session_Recording

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1056 (Input Capture)
**Confidence:** HIGH
**False Positives:** Unrelated software does not produce the `MITM <ip> -> <ip>:<port> <user>:<password>` title shape by coincidence, but the rule tests only that substring, with no asciinema header or JSON-lines structure, so a report, ticket, paste or rule file that quotes the format also matches. Treat a hit as a title-format lead and establish provenance independently before calling it a leaked recording.
**Blind Spots:** This is the one rule in the set whose operational value is conditional rather than routine. The platform gzips, base64-encodes, ships, and unlinks every recording within the session's lifetime by design, so a match requires a copy that escaped that cleanup: a crash before the unlink, a copy pulled from swap, a backup snapshot that captured `/dev/shm`, or a dump of the receiver's own `sessions` table. On a healthy production relay, this rule will usually find nothing to find. A live recording that exists during a session also matches. The scan reads plaintext only; the gzip plus base64 form the platform ships needs extraction first.
**Validation:** Construct a synthetic asciinema v2 file with a title line in the exact `MITM client -> target:port user:password` shape and confirm it matches; confirm an ordinary asciinema recording from an unrelated terminal session does not. A text file that merely quotes the title format is a known positive.
**Deployment:** Forensic scanning of `/dev/shm` snapshots, swap and hibernation files, backup archives, and any recovered copy of the receiver's session-recording storage.

```yara
rule MITM_Leaked_Session_Recording {
   meta:
      description = "Detects plaintext containing the title-field format that a self-hosted SSH adversary-in-the-middle platform writes into its asciinema session recordings, where the plaintext intercepted credential is embedded in a fixed MITM client-target-user-password format. The platform gzips, base64-encodes, ships, and deletes each recording within the session's lifetime, so a match on a real recording is a copy that escaped that cleanup or a live copy caught during the session; the rule tests only the title-shaped text, so documents that quote the format also match"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/"
      date = "2026-08-12"
      family = "SSH MITM Interception Platform"
      malware_type = "Leaked session-capture artifact (asciinema v2)"
      campaign = "SSHInterception-ParasiticCredentialTheft-157.180.101.47"
      id = "5b7c5b21-8fa1-519c-83a5-cad637a18019"
   strings:
      $title_re = /"title": "MITM [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} -> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5} [^"]+:[^"]+"/ ascii
   condition:
      filesize < 50MB and
      $title_re
}
```

---

## Sigma Rules

Every rule below targets Linux telemetry, using `product: linux` with either the normalized `process_creation`/`file_event`/`network_connection` categories or the raw `service: auditd` and its positional `a0`/`a1`/… execve arguments. None of these are Windows Sysmon rules; a Windows-shaped ruleset would find nothing here.

Two rules use Sigma's `correlation` type to combine a pair of individually broad selectors into one high-confidence signal. Per SigmaHQ convention, each correlation and its base rule(s) are co-located in the same YAML block, separated by `---`, because the correlation resolves its base rules by `id` and cannot do so if they are split across separate blocks. Both correlation groups are placed under Detection, since the correlation itself is the actionable, alertable rule; the individual base selectors inside each group are Hunting-grade on their own and are not intended to be alerted on independently. The Detection/Hunting counts in the Coverage Summary above reflect this: 7 Detection includes both correlations, and 7 Hunting includes the four base selectors that feed them plus the three standalone Hunting rules listed later in this section.

### Detection Rules

#### Netfilter Loop-Prevention Mark Consistent with Self-Hosted SSH Interception

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1686 (Disable or Modify System Firewall), T1557 (Adversary-in-the-Middle)
**Confidence:** HIGH
**False Positives:** Unlikely. This exact mark value (`0x4D49544D`, ASCII "MITM") has no known legitimate use; a host using SO_MARK-based policy routing for its own purposes would use a value tied to that scheme, not this one.
**Blind Spots:** Requires the operator to keep this exact mark value. He has already rotated other configuration values (his reporting token) once; if he rotates this too on a future rebuild, this specific rule stops matching even though the mechanism (a loop-prevention exemption paired with a self-redirect) persists. Requires auditd `execve` visibility into `iptables` invocations; a host without command-line auditing enabled produces nothing for this rule to see. The mark value and `RETURN` are matched as separate tokens, so the rule works on raw auditd EXECVE records (one argument per aN field) as well as on a joined command line, but it does not bind the mark to `--mark` or `RETURN` to `-j`.
**Validation:** Trigger by running the exact deploy sequence documented in this campaign against a lab host and confirming the rule fires on the `iptables -t nat -I OUTPUT 1 -m mark --mark 0x4D49544D -j RETURN` invocation (not replayed on a lab host, NOT CHECKED). An unrelated host running ordinary firewall administration (accepting, dropping, or NATing traffic without this mark value) must not fire.
**Deployment:** Linux EDR or SIEM ingesting auditd `execve` records; periodic `iptables -t nat -S OUTPUT` config inventory as a complementary check that does not depend on audit coverage.

```yaml
title: Netfilter Loop-Prevention Mark Consistent with Self-Hosted SSH Interception
id: b48cef4b-c00a-455f-85a8-b9f0fac6f618
status: experimental
description: >-
  Detects an iptables command line carrying the firewall mark value 0x4D49544D together
  with a RETURN target, consistent with the nat OUTPUT exemption a self-hosted SSH
  adversary-in-the-middle platform installs so its own upstream validation connections
  skip its own transparent redirect of port 22. The mark value and the word RETURN are
  tested as separate tokens; the rule does not test the nat table, the OUTPUT chain, or
  that the mark is passed to a mark match.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.defense-impairment
    - attack.t1686
    - attack.credential-access
    - attack.collection
    - attack.t1557
    - stp.3
logsource:
    product: linux
    service: auditd
    definition: 'Requires auditd with an execve audit rule installed so iptables invocations are logged as type=EXECVE records. Raw EXECVE records carry each argument in its own aN field; this rule tests single tokens, so it does not depend on argv reconstruction.'
detection:
    cmd:
        type: 'EXECVE'
        a0|endswith: 'iptables'
    kw_mark:
        - '0x4D49544D'
    kw_return:
        - 'RETURN'
    condition: cmd and kw_mark and kw_return
falsepositives:
    - Unlikely, this mark value has no known legitimate use
level: high
```

#### Command Line Consistent With SSH Interceptor Component Launch

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1059.006 (Python), T1557 (Adversary-in-the-Middle)
**Confidence:** HIGH
**False Positives:** Unlikely. The interceptor selector requires the script to be the interpreter's direct execution target rather than merely present on the command line, and the sniffer selector's flag combination is specific to this toolkit, though it tests only command text (no Image) and matches in any process.
**Blind Spots:** The interceptor selector keys on a filename the operator can rename on redeploy; only the sniffer selector's flag combination survives that. Both components are double-forked and daemonized after this initial launch, so this rule only has one moment (the original `execve`) to catch them; a process-creation feed with gaps will miss it. Requiring the script to be the interpreter's direct positional target also means a shell-wrapped launch, such as `sh -c "python3 mitm_local.py"` where the top-level command line begins with `sh` rather than `python3`, will not fire. The interceptor selector also requires the Image to contain `python3` (so `python3.11` matches; an Image path without `python3`, such as a bare `python` symlink, does not). *Regex fixes 2026-10-11:* on Elastic a `|re` value must match the whole field and the pattern began with `python`, so an interpreter started by absolute path (`/usr/bin/python3 -u mitm_local.py`) did not match; the pattern now accepts an optional leading path before `python`. A second pass made the script a path-bounded basename (so `python3 notmitm_local.py` no longer matches) and excluded `-c` and `-m` as the first option (so `python3 -c mitm_local.py` no longer matches); a flag cluster that contains `c` or `m` later, such as `-Bc`, is not excluded. A launch through a wrapper such as `env`, `sh -c` or `nohup` still does not match. The sniffer selector has no Image test, so an `sh -c` wrapper around the sniffer does match it.
**Validation:** Trigger `sel_interceptor` by launching `python3 -u mitm_local.py` or `python3 /dev/shm/.x9k2/mitm_local.py` on a lab host and confirm it fires; trigger `sel_sniffer` separately with `python3 -u sniffer.py --iface eth0 --mitm-port 19923 --skip-ports 22 --own-ips 10.0.0.5 --output-only --backend auto` and confirm it fires. A command line that only references the interceptor's filename without executing it as the interpreter's direct target, such as `python3 pyc_strings.py ./mitm_local.py`, `sha256sum mitm_local.py`, or `cp mitm_local.py /tmp/`, must not fire; nor must `python3 -c mitm_local.py` or `python3 notmitm_local.py`, nor an unrelated Python script that happens to share one sniffer flag (`--output-only`, for instance) but not the full three-flag combination.
**Deployment:** Linux EDR or SIEM ingesting normalized process-creation telemetry (auditd, Sysmon for Linux, or an EDR's native process feed).

```yaml
title: Command Line Consistent With SSH Interceptor Component Launch
id: 15646ca3-99b5-4a3f-a25f-61f15cc3707c
status: experimental
description: >-
  Detects process launch command lines matching the interceptor or sniffer components of
  a self-hosted SSH adversary-in-the-middle platform observed deployed fileless from tmpfs.
  The interceptor selector requires a Python interpreter to execute mitm_local.py directly,
  as its own positional script argument (an optional leading path, and not through -c or -m,
  and not as the tail of a longer file name), rather than merely mentioning the filename
  elsewhere on the command line, which is what a file read, hash, or copy operation would
  otherwise trigger. The sniffer selector anchors on its flag combination rather than its
  filename, since a filename alone is trivial for an operator to rename on redeploy; it
  tests no Image, so it is a command-text lead that matches the flag combination in any
  process's command line.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.execution
    - attack.t1059.006
    - attack.credential-access
    - attack.collection
    - attack.t1557
    - stp.3
logsource:
    category: process_creation
    product: linux
detection:
    sel_interceptor:
        Image|contains: 'python3'
        CommandLine|re: '([^ ]*/)?python[0-9.]*( -(-[^ ]*|[^\-cm ][^ ]*))* ([^ ]*/)?mitm_local\.py( .*)?'
    sel_sniffer:
        CommandLine|contains|all:
            - '--skip-ports 22'
            - '--output-only'
            - '--backend auto'
    condition: 1 of sel_*
falsepositives:
    - >-
      Unlikely. The interceptor selector requires the script to be the interpreter's
      direct execution target rather than merely present on the command line, and the
      sniffer selector's flag combination is specific to this toolkit, though it tests
      only command text (no Image) and matches in any process
level: high
```

#### Distinctive Dot-Prefixed Artifacts Written Directly Under Tmpfs Shared Memory

**Tier:** Detection
**Robustness:** 2
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories)
**Confidence:** HIGH
**False Positives:** Unlikely. None of these three names are standard or default artifact names produced by any known legitimate tool.
**Blind Spots:** Everything under `/dev/shm` is gone at reboot. The report's tmpfs artifact map shows all three named files sitting at the root of `/dev/shm`, outside the staging directory the three-second self-wipe deletes, and surviving that wipe; the transient files are the ones inside the staging directory, which this rule does not cover (see the hidden-staging rule). The match is on the exact full path, so a copy of the same name in another directory, or a renamed file, does not fire. File-creation telemetry with a gap around the moment of compromise will miss the creation event itself.
**Validation:** Trigger by creating a file at `/dev/shm/.ipt.bak`, `/dev/shm/.payload.pl`, or `/dev/shm/.payload_user.pl` on a lab host and confirm the rule fires on each. Ordinary tmpfs usage by browsers, databases, or IPC mechanisms, none of which use these three names, must not fire; neither must a file named `.payload.pl` anywhere other than the root of `/dev/shm`.
**Deployment:** Linux EDR or SIEM ingesting file-creation telemetry with tmpfs coverage (many default configurations exclude `/dev/shm` from file-integrity monitoring, so confirm coverage before relying on this rule).

```yaml
title: Distinctive Dot-Prefixed Artifacts Written Directly Under Tmpfs Shared Memory
id: bf7c0d63-543c-4c37-9963-943ace0dfa7e
status: experimental
description: >-
  Detects creation of three specifically named, dot-prefixed files directly under
  /dev/shm, the firewall snapshot, and the two fingerprinting payload scripts of a
  self-hosted SSH interception platform deployed fileless into tmpfs. All three names are
  distinctive enough on their own that no combination requirement is needed; each has no
  known legitimate use.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.stealth
    - attack.t1564.001
    - stp.3
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename:
            - '/dev/shm/.ipt.bak'
            - '/dev/shm/.payload.pl'
            - '/dev/shm/.payload_user.pl'
    condition: selection
falsepositives:
    - Unlikely, these are not standard or default artifact names produced by any known legitimate tool
level: high
```

### Hunting Rules

#### Bare Uname and Bare Perl Command Lines on One Host (Possible Automated Credential Re-Use)

This heading covers three co-located Sigma documents in one YAML block: two Hunting-tier base selectors and the correlation that combines them, which is also Hunting-tier, kept together for the same rule-resolution reason as the group above.

**Base rule: Bare Uname Fingerprint Command**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1082 (System Information Discovery)
**Confidence:** MODERATE
**False Positives:** Ansible fact-gathering, Nagios or Icinga host checks, and other legitimate fleet-inventory scripts that run a bare `uname -a` over SSH. Not intended to be alerted on alone; see the correlation below.

**Base rule: Bare Perl Interpreter Reading From Stdin**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059 (Command and Scripting Interpreter, parent technique; no Perl-specific sub-technique exists)
**Confidence:** MODERATE
**False Positives:** Interactive debugging or configuration-management tooling that legitimately pipes a Perl script to a remote interpreter over stdin. Not intended to be alerted on alone; see the correlation below.

**Correlation: Bare Uname and Bare Perl Command Lines on One Host**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1082 (System Information Discovery)
**ATT&CK Note:** The rule tests no SSH login, session or user, so Remote Services: SSH (T1021.004) is not claimed; the automated re-use that the report describes is context for the pairing.
**Confidence:** MODERATE
**False Positives:** A configuration-management run that happens to execute both a bare `uname -a` check and a separate bare Perl invocation against the same host, and any unrelated activity on a shared host (a typed `uname -a`, a cron job, a Perl one-liner) that lands in the same search interval; neither command line is tied to an SSH session. This is the one pairing in the whole platform that is visible to a victim's own host telemetry regardless of which relay, proxy, or Tor exit the connection transited, because it happens on the target being re-used, not on the interception infrastructure.
**Blind Spots:** Depends on the target host having process-creation visibility into non-interactive SSH exec sessions, which not every environment logs by default. The rule tests neither an SSH login, a user or session, the order of the two commands, nor the stdin contents; the 30-second window is Sigma-level semantics that the converted EQL (an unordered `sample by Hostname` with no time bound) does not apply, and Lucene has no correlation support. The window matches the observed "seconds after" timing of the automated re-use, but a slower automation pipeline elsewhere could exceed it.
**Validation:** Trigger by running `ssh user@target 'uname -a'` immediately followed by piping a small script into `ssh user@target perl` on the same target within 30 seconds, and confirm the correlation fires (a backend that applies the 30-second `timespan` is needed for the window to hold). A single bare `uname -a` health check with no companion bare-Perl invocation on the host, or vice versa, must not trigger the correlation. An unordered pair with no SSH involved also fires; that is a known limit, not a negative case.
**Deployment:** Linux EDR or SIEM on the potential *target* of credential reuse (not the relay), with process-creation telemetry and a backend that applies Sigma's correlation `timespan`. It is a lead from the receiving end of a possible re-use attempt, when a defender has no visibility at all into the relay that originated it; a hit needs SSH session context from elsewhere before it is read as credential re-use.

```yaml
title: Bare Uname Fingerprint Command Base
id: a8cd99d8-af90-4376-a003-4f13836e56b2
status: experimental
description: >-
  Base rule (Hunting alone) detecting a process whose entire command line is exactly
  "uname -a" (the rule tests no SSH session, parent or user, so a typed or cron uname -a
  also matches). Observed in the platform as the
  fingerprinting step an automated credential-verification tool runs immediately after
  replaying a captured password against a target. Legitimate health-check and inventory
  scripts also run bare uname -a, so this selector alone is broad; see the paired
  correlation rule for the higher-confidence combined signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine: 'uname -a'
    condition: selection
falsepositives:
    - Ansible fact-gathering, Nagios or Icinga host checks, and other legitimate fleet-inventory scripts that run a bare uname -a over SSH
level: low
---
title: Bare Perl Interpreter Reading From Stdin Base
id: 5eb73b78-1f5d-40a3-a489-a8deae25d89e
status: experimental
description: >-
  Base rule (Hunting alone) detecting a perl interpreter invoked with no script path or
  inline code argument, consistent with a script being piped into it over stdin rather
  than read from disk. Observed as the payload-delivery step immediately following a
  successful automated credential-verification connection, where a small fingerprinting
  script is piped to a remote perl on the exec channel rather than written to disk first.
  The rule tests only the bare command line (Image ending /perl, command line exactly
  perl), not that anything is on stdin. A bare perl invocation is uncommon but not unique
  to this activity, so this selector alone is broad; see the paired correlation rule for the higher-confidence combined signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/perl'
        CommandLine: 'perl'
    condition: selection
falsepositives:
    - Interactive debugging or configuration-management tooling that legitimately pipes a Perl script to a remote interpreter over stdin
level: low
---
title: Bare Uname and Bare Perl Command Lines on One Host (Possible Automated Credential Re-Use)
id: 14a09f4a-e4c6-47c9-9a1a-70f841c0fd58
status: experimental
description: >-
  Correlates a bare "uname -a" command line with a bare perl command line on the same host
  (Sigma semantics: within 30 seconds, unordered; the converted EQL is a sample by Hostname
  with no time bound, and Lucene has no correlation support). The rule tests no SSH login,
  user, session or stdin contents. Individually both are common enough to be unremarkable;
  the pairing is the shape of an automated tool that replays a just-captured credential,
  fingerprints the target, and pipes a small reconnaissance payload to a remote interpreter
  on the same non-interactive exec channel, but unrelated activity on a shared host can
  satisfy it too. It is a lead visible to the victim's own host telemetry regardless of
  which relay, proxy, or exit node the connection transited.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.discovery
    - attack.t1082
correlation:
    type: temporal
    rules:
        - a8cd99d8-af90-4376-a003-4f13836e56b2
        - 5eb73b78-1f5d-40a3-a489-a8deae25d89e
    group-by:
        - Hostname
    timespan: 30s
    condition:
        gte: 2
falsepositives:
    - >-
      A configuration-management run that happens to execute both a bare uname -a check and
      a separate bare Perl invocation against the same host within the correlation window
level: medium
```

#### Paramiko and Ipset Install Commands on One Host (Reboot-Surviving Toolkit Setup)

This heading covers three co-located Sigma documents in one YAML block: two Hunting-tier base selectors and the correlation that combines them, which is also Hunting-tier. SigmaHQ's correlation syntax resolves a correlation's base rules by `id` from within the same document collection, so the three are kept together here rather than split across the Detection and Hunting subsections.

**Base rule: Paramiko Pip Install**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Ansible control nodes, network-automation scripts, and other legitimate tooling installing paramiko on a PEP 668 externally-managed Python environment. Not intended to be alerted on alone; see the correlation below.

**Base rule: Ipset Package Install**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** Legitimate provisioning of ipset for firewall, routing, or DDoS-mitigation tooling unrelated to this platform. Not intended to be alerted on alone; see the correlation below.

**Correlation: Paramiko and Ipset Install Commands on One Host**
**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1105 (Ingress Tool Transfer)
**Confidence:** MODERATE
**False Positives:** A host being freshly provisioned by legitimate configuration-management tooling that happens to install both packages as part of an unrelated baseline image build. This is the only rule in the set built specifically because it survives what nothing else here does: a reboot. Everything else in this platform lives in tmpfs and is gone the moment the host restarts; the pip and package-manager traces are the two exceptions, which is exactly why this pairing matters most to a provider investigating a customer report days after the fact.
**Blind Spots:** The 5-minute correlation window is a judgment call and applies only where the backend honours Sigma's `timespan`. The converted EQL is an unordered `sample by Hostname` with no time bound, so on that backend any host with both command lines inside the searched interval qualifies; the Lucene converter does not support correlation rules. The two installs happen within the same shell script in practice, so they should land far inside the window, but a slower package-manager run (a cold apt cache, a busy host) could push the gap wider than modeled here. Each base rule tests command-line text (the word `install` between spaces, plus the package name), not that the install succeeded; `uninstall` and `reinstall` do not match.
**Validation:** Trigger by running `pip3 install paramiko --break-system-packages -q` followed within a few minutes by `apt-get install -y ipset` (or the `yum`/`dnf` equivalent) on a lab host and confirm the correlation fires. A host installing only one of the two packages must not trigger the correlation (though each base selector may still fire individually as a lower-confidence Hunting lead), and `apt-get remove ipset` must not fire the ipset base rule. Installs more than five minutes apart do not trigger the correlation only on a backend that applies the `timespan`; the converted EQL does not.
**Deployment:** Linux EDR or SIEM with process-creation telemetry and a backend that applies Sigma's correlation `timespan` (the converted EQL does not); this is the lead to run first against a host suspected of compromise where the volatile tmpfs evidence is already gone.

```yaml
title: Paramiko Pip Install Base
id: 13df30b5-cc29-4786-a170-3375899bb175
status: experimental
description: >-
  Base rule (Hunting alone) detecting a command line that contains install, paramiko and
  --break-system-packages (no pip image is tested), one of two artifacts observed surviving a reboot in a self-hosted
  SSH interception platform that is otherwise deployed entirely from tmpfs. Legitimate
  automation tooling installs paramiko this way too, so this selector is broad on its own;
  see the paired correlation rule for the higher-confidence combined signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - ' install '
            - 'paramiko'
            - '--break-system-packages'
    condition: selection
falsepositives:
    - Ansible control nodes, network-automation scripts, and other legitimate tooling installing paramiko on a PEP 668 externally-managed Python environment
level: low
---
title: Ipset Package Install Base
id: d4215f8e-80b1-4de6-9d7e-251c8dc80d98
status: experimental
description: >-
  Base rule (Hunting alone) detecting an apt, apt-get, yum or dnf command line that
  contains install and ipset, the second of two artifacts observed surviving a reboot in a
  self-hosted SSH interception platform that is otherwise deployed entirely from tmpfs.
  ipset has legitimate uses, so this selector is broad on its own; see the paired
  correlation rule for the higher-confidence combined signal.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/apt-get'
            - '/apt'
            - '/yum'
            - '/dnf'
        CommandLine|contains|all:
            - ' install '
            - 'ipset'
    condition: selection
falsepositives:
    - Legitimate provisioning of ipset for firewall, routing, or DDoS-mitigation tooling unrelated to this platform
level: low
---
title: Paramiko and Ipset Install Commands on One Host (Reboot-Surviving Toolkit Setup)
id: 83e569b9-7383-453e-938d-cf887e516580
status: experimental
description: >-
  Correlates the paramiko install command line with the ipset install command line on the
  same host (Sigma semantics: within 5 minutes; the converted EQL is an unordered sample
  by Hostname with no time bound, and Lucene has no correlation support). Neither action alone is unusual, but a host that acquires both a
  paramiko-based SSH library and ipset in quick succession matches the dependency-install
  step of a self-hosted SSH adversary-in-the-middle platform observed deploying every
  other component fileless from tmpfs. These two package-manager traces are the only
  artifacts confirmed to survive a reboot, which makes this correlation valuable evidence
  after the volatile tmpfs artifacts are gone.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.command-and-control
    - attack.t1105
correlation:
    type: temporal
    rules:
        - 13df30b5-cc29-4786-a170-3375899bb175
        - d4215f8e-80b1-4de6-9d7e-251c8dc80d98
    group-by:
        - Hostname
    timespan: 5m
    condition:
        gte: 2
falsepositives:
    - >-
      A host being freshly provisioned by legitimate configuration-management tooling
      that happens to install both packages as part of an unrelated baseline image build
level: medium
```

#### Iptables NAT Redirect of Destination Port 22 to a Local Listener

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**Confidence:** MODERATE
**False Positives:** Legitimate SSH port remapping for load balancing or protocol inspection exists, and a deliberate local SSH-inspection proxy produces the same command line; redirecting destination port 22 specifically to a listener on the *same* host is unusual outside an intentional interception or debugging proxy, which is why this is a Hunting lead rather than an alert.
**Blind Spots:** Requires auditd visibility into `iptables` invocations and a pipeline that joins the argument vector into one string; raw auditd EXECVE records split `--dport` and `22` into separate fields and do not match. The `--dport 22 ` token is followed by a space, so it does not match `--dport 2222`, but a `22` that ends the command line would not match either (REDIRECT and `--to-port` always follow in practice). The chain and direction are not tested. Does not by itself distinguish this platform from a legitimate local SSH-inspection proxy a defender set up deliberately.
**Validation:** Trigger on a lab host with any of the eleven observed deployment schemes (the base OUTPUT-chain redirect, or a VPN/container variant using PREROUTING on `wg0`/`tun0`/`awg0`/`docker0`) and confirm the rule fires regardless of which local port is the redirect target (not replayed, NOT CHECKED; requires the argument-joining pipeline named above). A rule that only matched the specific port 19923 would miss every scheme that uses a different target port; this one does not, because it anchors on the REDIRECT-of-port-22 mechanism rather than a fixed destination.
**Deployment:** Linux EDR or SIEM that joins auditd `execve` arguments into one command-line string; periodic `iptables -t nat -S` config inventory as a complementary check that does not depend on audit coverage.

```yaml
title: Iptables NAT Redirect of Destination Port 22 to a Local Listener
id: 481b1e63-bd30-4fcb-ab4f-ef3a902c19bb
status: experimental
description: >-
  Detects an iptables command line that adds a REDIRECT with a --dport 22 match and a
  --to-port, which redirects destination port 22 traffic to a local port on the same host
  (REDIRECT exists only in the nat table, so the table is implied). It does not test the
  chain or the direction, and it cannot tell this platform from a deliberate local
  SSH-inspection proxy. Observed as the core mechanism of a self-hosted, transparent SSH
  adversary-in-the-middle platform that intercepts a host's own outbound SSH sessions
  into a local fake server before forwarding validated credentials upstream. The
  redirect target port and chain (OUTPUT, or PREROUTING on a VPN or container interface)
  vary by deployment scheme, so this anchors on the REDIRECT-of-port-22 mechanism itself
  rather than a fixed port number.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1557
    - stp.3
logsource:
    product: linux
    service: auditd
    definition: 'Requires auditd with an execve audit rule installed, and a pipeline that joins the EXECVE argument vector into one command-line string. Raw EXECVE records carry each argument in its own aN field (--dport and 22 separately), where the multi-token string in this rule does not occur. No such profile has been demonstrated for this rule.'
detection:
    cmd:
        type: 'EXECVE'
        a0|endswith: 'iptables'
    kw_dport:
        - '--dport 22 '
    kw_redirect:
        - 'REDIRECT'
    kw_toport:
        - '--to-port'
    condition: cmd and kw_dport and kw_redirect and kw_toport
falsepositives:
    - >-
      Legitimate SSH port remapping for load balancing or protocol inspection, though
      redirecting port 22 specifically to a LOCAL listener on the same host (rather than
      to a different host) is unusual outside of an intentional interception or debugging
      proxy
level: medium
```

#### Ipset Named mitm_exclude Created

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1480 (Execution Guardrails)
**Confidence:** MODERATE
**False Positives:** Unlikely. `mitm_exclude` is not a standard or default set name used by any known legitimate firewall or DDoS-mitigation tool.
**Blind Spots:** Depends on the operator keeping this set name; a rename on redeploy defeats it, and one freely renamed literal is the only discriminator, which is why this is a Hunting lead rather than a durable Detection. The rule sees one ipset invocation: the iptables rule that references the set, the redirect, and their order are not tested (the deploy script establishes that sequence, see `MITM_Deploy_Firewall_Script`). Requires auditd visibility into `ipset` invocations.
**Validation:** Trigger by running `ipset create mitm_exclude hash:ip maxelem 1000000 -exist` on a lab host and confirming the rule fires. A host provisioning an unrelated ipset for legitimate routing or mitigation purposes, using any other set name, must not fire.
**Deployment:** Linux EDR or SIEM ingesting auditd `execve` records; periodic `ipset list` config inventory.

```yaml
title: Ipset Named mitm_exclude Created
id: 580b377c-7566-4bc9-a78b-546c7c273ac5
status: experimental
description: >-
  Detects an ipset command line that contains create and the set name mitm_exclude, the
  exclusion list a self-hosted SSH interception platform checks before its redirect so
  specific destinations are skipped. The rule tests that one ipset invocation only: the
  iptables rule that references the set, the redirect, and their order are not tested.
  The name is operator-chosen and has no known legitimate use, but it can be changed on
  redeploy.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.stealth
    - attack.t1480
    - stp.2
logsource:
    product: linux
    service: auditd
detection:
    cmd:
        type: 'EXECVE'
        a0|endswith: 'ipset'
    kw_create:
        - 'create'
    kw_name:
        - 'mitm_exclude'
    condition: cmd and kw_create and kw_name
falsepositives:
    - Unlikely, this ipset name is not a standard or default name used by any known legitimate tool
level: medium
```

The four base selectors that feed the two correlation rules above (paramiko pip install, ipset package install, bare `uname -a`, bare `perl`) are Hunting-grade in their own right, but they are co-located with their correlations in the Detection subsection above rather than repeated here, because SigmaHQ's correlation syntax resolves its base rules by `id` from within the same document collection. The four rules below are the platform's remaining standalone Hunting-tier coverage.

#### Python Interpreter Directly Executing exclude_puller.py

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1059.006 (Python), T1557 (Adversary-in-the-Middle)
**Confidence:** MODERATE
**False Positives:** The exclude_puller.py filename is generic and plausible for unrelated exclusion-list or allow-list tooling outside this platform; requiring genuine execution rather than a mere reference on the command line removes the noisiest source of false hits but does not remove the risk of a name collision with unrelated software using the same filename.
**Blind Spots:** Keys on a filename the operator can rename on redeploy, unlike the sniffer's flag-combination anchor in the companion Detection-tier rule above. This component is also double-forked and daemonized shortly after launch, so this rule only has one moment (the original `execve`) to catch it. *Regex fixes 2026-10-11:* on Elastic a `|re` value must match the whole field and the pattern began with `python`, so an interpreter started by absolute path (`/usr/bin/python3 -u exclude_puller.py`) did not match; the pattern now accepts an optional leading path before `python`. A second pass made the script a path-bounded basename (so `python3 notexclude_puller.py` no longer matches) and excluded `-c` and `-m` as the first option (so `python3 -c exclude_puller.py` no longer matches); a flag cluster that contains `c` or `m` later, such as `-Bc`, is not excluded. A launch through a wrapper such as `env`, `sh -c` or `nohup` still does not match.
**Deployment:** Linux EDR or SIEM ingesting normalized process-creation telemetry (auditd, Sysmon for Linux, or an EDR's native process feed); review hits manually rather than routing to automated response.

```yaml
title: Python Interpreter Directly Executing exclude_puller.py
id: fa0e8562-33e9-47fd-8057-d81654bce447
status: experimental
description: >-
  Detects a Python interpreter executing exclude_puller.py as its direct target,
  observed as the exclusion-list poller component of a self-hosted SSH
  adversary-in-the-middle platform that otherwise deploys fileless from tmpfs.
  Requiring the script as the interpreter's own positional argument rather than a mere
  reference on the command line (not through -c or -m, and not as the tail of a longer
  file name) removes hits from tooling that reads, hashes, or copies the file by name, but the
  filename itself is generic enough that this remains a hunting-grade selector rather
  than a high-confidence one; see the companion Detection-tier rule for the platform's
  interceptor and sniffer components.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.execution
    - attack.t1059.006
    - attack.credential-access
    - attack.collection
    - attack.t1557
logsource:
    category: process_creation
    product: linux
detection:
    sel_puller:
        Image|contains: 'python3'
        CommandLine|re: '([^ ]*/)?python[0-9.]*( -(-[^ ]*|[^\-cm ][^ ]*))* ([^ ]*/)?exclude_puller\.py( .*)?'
    condition: sel_puller
falsepositives:
    - >-
      The exclude_puller.py filename is generic and plausible for unrelated
      exclusion-list or allow-list tooling outside this platform; requiring genuine
      execution rather than a mere reference on the command line removes the
      noisiest source of false hits but does not remove the risk of a name collision
      with unrelated software using the same filename
level: medium
```

#### Iptables INPUT Drop Rule for Non-Loopback Traffic to a Specific Port

**Tier:** Hunting
**Robustness:** 1 standalone (gains precision when correlated locally against a matching REDIRECT target port)
**ATT&CK Coverage:** T1686 (Disable or Modify System Firewall)
**Confidence:** MODERATE
**False Positives:** Deliberate loopback-only hardening of an internal admin or monitoring service using DROP-based iptables rules rather than a bind-to-127.0.0.1 restriction. This is a real and not-uncommon pattern outside this platform, which is why this rule is Hunting rather than Detection.
**Blind Spots:** Needs the argument-joining pipeline named in the logsource definition (raw auditd EXECVE records split `-j` and `DROP` into separate fields and do not match). Tests that a `--dport` match is present but not its value, so says nothing about *which* port is being hidden; an analyst reviewing a hit should cross-reference it against the REDIRECT rule detected by the earlier `Iptables NAT Redirect of Destination Port 22 to a Local Listener` rule to confirm the two share the same target port before treating a hit as high-confidence.
**Deployment:** Linux EDR or SIEM that joins auditd `execve` arguments into one command-line string; review hits manually rather than routing to automated response.

```yaml
title: Iptables INPUT Drop Rule for Non-Loopback Traffic to a Specific Port
id: 1ced014b-28fa-4ead-af00-af46a1b931c9
status: experimental
description: >-
  Detects an iptables command line adding an INPUT-chain DROP with a --dport match and a
  non-loopback input-interface match (! -i lo), the shape of a rule that drops all
  non-loopback traffic to a specific port. The port number, and whether it is a high
  port, are not tested. This is the exact mechanism a self-hosted SSH interception platform uses to keep its
  redirect-target listener invisible to external port scanning while still accepting the
  host's own locally redirected connections. This selector alone is broad, since internal-only
  service hardening can produce a similar rule shape, so it is tiered for hunting rather
  than alerting. It gains precision when the dropped port matches a port seen in a
  companion REDIRECT --to-port rule on the same host.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.defense-impairment
    - attack.t1686
logsource:
    product: linux
    service: auditd
    definition: 'Requires auditd with an execve audit rule installed, and a pipeline that joins the EXECVE argument vector into one command-line string. Raw EXECVE records carry each argument in its own aN field (-j and DROP separately, ! -i lo as three fields), where the multi-token strings in this rule do not occur. No such profile has been demonstrated for this rule.'
detection:
    cmd:
        type: 'EXECVE'
        a0|endswith: 'iptables'
    kw_input:
        - 'INPUT'
    kw_dport:
        - '--dport'
    kw_drop:
        - '-j DROP'
    kw_notlo:
        - '! -i lo'
    condition: cmd and kw_input and kw_dport and kw_drop and kw_notlo
falsepositives:
    - Deliberate loopback-only hardening of an internal admin or monitoring service using DROP-based iptables rules rather than a bind-to-127.0.0.1 restriction
level: medium
```

#### Hidden Staging Directories or Files Created at the Root of Tmpfs Shared Memory

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1564.001 (Hidden Files and Directories)
**Confidence:** MODERATE
**False Positives:** Browsers and other software that place short dot-prefixed shared-memory segments directly at the root of `/dev/shm` (Chromium-family browsers are the most common source).
**Blind Spots:** The short names here (`.run`, `.bl`, and the directory prefixes) are genuinely more collision-prone than the platform's most distinctive artifacts, which is why this rule is Hunting and its companion `Distinctive Dot-Prefixed Artifacts` rule (Detection tier, above) exists separately for the three names with no legitimate use.
**Deployment:** Linux EDR or SIEM ingesting file-creation telemetry with tmpfs coverage; treat hits as a lead to triage, not an alert to action directly.

```yaml
title: Hidden Staging Directories or Files Created at the Root of Tmpfs Shared Memory
id: f6dbbebc-528a-4bc1-a209-cb31b78cb6b1
status: experimental
description: >-
  Detects files created inside a small set of dot-prefixed staging directories, or as
  dot-prefixed files, directly at the root of /dev/shm. Observed as the session-recording,
  fake-host-key, launcher, and blocklist storage locations of a self-hosted SSH
  interception platform. These names are shorter and more generic than the platform's
  most distinctive artifacts, so this is tiered for hunting: some legitimate software
  also creates short dot-prefixed entries at the root of /dev/shm (most notably browser
  shared-memory segments), so review each hit rather than alert on it directly.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.stealth
    - attack.t1564.001
logsource:
    category: file_event
    product: linux
detection:
    selection_dirs:
        TargetFilename|startswith:
            - '/dev/shm/.local/'
            - '/dev/shm/.s/'
            - '/dev/shm/.k/'
    selection_files:
        TargetFilename:
            - '/dev/shm/.run'
            - '/dev/shm/.bl'
    condition: 1 of selection_*
falsepositives:
    - Browsers and other software that place short dot-prefixed shared-memory segments directly at the root of /dev/shm
level: medium
```

#### Python Process Making an Outbound Connection to a Non-Standard High Port

**Tier:** Hunting
**Robustness:** 1
**ATT&CK Coverage:** T1571 (Non-Standard Port)
**ATT&CK Note:** The event carries no protocol or TLS field, so Web Protocols (T1071.001) is not claimed.
**Confidence:** LOW alone; raised by combining with the process-launch and file-artifact indicators above
**False Positives:** Any legitimate Python service or client communicating with an unrelated API or management interface bound to port 8443 or 8444. These are common enough alternate HTTPS ports that this selector is broad by design; any TCP connection to them matches, TLS or not.
**Blind Spots:** Cannot see the `X-Token` header, the request body, or the specific endpoint path, since those sit inside the TLS payload; this rule sees only that a Python process initiated a connection to one of two ports; whether TLS follows is not tested. It also cannot see the reporting cadence (roughly 300 seconds for a heartbeat, 600 seconds for an exclusion-list poll), which would otherwise raise confidence, because that requires longer-window correlation this rule does not attempt.
**Deployment:** Linux EDR or SIEM with process-to-network correlation; use as a pivot alongside the process-launch and file-artifact rules above rather than as a standalone alert.

```yaml
title: Python Process Making an Outbound Connection to a Non-Standard High Port
id: 770ec23a-3204-437f-8560-c8610c68e2b0
status: experimental
description: >-
  Detects a python3 process initiating an outbound connection to destination port 8443 or
  8444 (the event does not show whether TLS follows), consistent with a relay component of a self-hosted SSH interception
  platform reporting captured credentials to its receiver and polling for target and
  exclusion-list updates. This selector is intentionally broad, since many legitimate
  services and management APIs also run on these ports, so it is tiered for hunting;
  process-attribution context (a python3 process with no on-disk backing script, per the
  companion host-side indicators) is what raises confidence on a given hit.
references:
    - https://the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/
author: The Hunters Ledger
date: 2026-08-12
tags:
    - attack.command-and-control
    - attack.t1571
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        Image|contains: 'python3'
        DestinationPort:
            - 8443
            - 8444
        Initiated: true
    condition: selection
falsepositives:
    - Any legitimate Python service or client communicating with an unrelated API or management interface bound to port 8443 or 8444
level: low
```

---

## Suricata Signatures

The interception itself happens over an unmodified, fully encrypted SSH session, so it is not a Suricata-visible event. The tractable network surface here is narrower than it first appears, since the relay-to-receiver reporting channel is also TLS with certificate verification disabled, which hides the `X-Token` header, the request bodies, and the endpoint paths from passive inspection just as effectively as if it were configured correctly. What remains observable without decryption is the TLS handshake metadata (the certificate itself) and, on the interception side, the SSH banner a connecting client actually receives. Both rules below compile against Suricata 8.0.5.

### Detection Rules

#### THL HUNT SSH-MITM-ParasiticCredentialTheft Paramiko Server Banner On Standard SSH Port

**Tier:** Detection
**Robustness:** 3 (technique-level: fires on the fundamental mechanism, independent of the operator's IP, port, or token configuration)
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**Confidence:** HIGH
**False Positives:** Security-research honeypots and red-team engagement infrastructure deliberately impersonating SSH on port 22 using paramiko, and rare CI or embedded systems running a paramiko-based mock SSH server on the standard port for testing. Every one of these is also worth an analyst's attention regardless of whether it turns out to be this specific platform.
**Blind Spots:** Only fires on traffic actually reaching a redirected port 22, so it requires the monitoring point to sit on the path between a client and the compromised relay (at the relay's own network edge, or upstream of it). Says nothing about relays whose interception a monitored client never happens to traverse.
**Validation:** To functionally validate, connect an SSH client to a paramiko-based server bound to port 22 in a lab and confirm the rule fires on the server's banner; connect to an ordinary OpenSSH server on port 22 and confirm it does not.
**Deployment:** Network sensor positioned at the boundary of a network whose hosts might be, or might connect through, a compromised relay; this is the deployment point that gives a hosting provider or sysadmin the best chance of finding the interceptor from outside the box itself, as a complement to the host-side Sigma rules above.

```
alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"THL DETECT SSH-MITM-ParasiticCredentialTheft Paramiko Server Banner On Standard SSH Port (AiTM Interception Indicator)"; flow:established,to_client; ssh.software; content:"paramiko"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/; classtype:trojan-activity; sid:9301701; rev:2; metadata:author The_Hunters_Ledger, date 2026-08-12;)
```

*Note on port pinning:* this rule intentionally pins destination port 22, which departs from the usual guidance to leave the destination port unrestricted on an app-layer protocol match. Here the port itself is the signal, since the anomaly is a Python SSH server library answering where a standard SSH daemon is expected; leaving the port open would also catch legitimate paramiko servers running on their own intentionally-chosen ports, which is a materially different and much noisier signal (see the Hunting-tier rule below for that broader net).

#### THL HUNT SSH-MITM-ParasiticCredentialTheft Self-Signed CN=receiver Certificate

**Tier:** Detection
**Robustness:** 2 (depends on the operator's current certificate naming convention; breaks if he regenerates under a different CN)
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**Confidence:** HIGH
**False Positives:** None known. A self-signed certificate whose subject and issuer are both the literal string `CN=receiver` is not a pattern seen in legitimate infrastructure.
**Blind Spots:** This is the single most fragile Detection-tier rule in the set. The report on this campaign explicitly notes that no successor has been found in a year of public certificate-transparency data, but a successor deployed with a regenerated certificate under a different common name would not appear here at all. Treat a lack of hits as inconclusive, not as evidence of no successor infrastructure.
**Validation:** To functionally validate, present a self-signed certificate with subject and issuer both set to `CN=receiver` during a TLS handshake in a lab and confirm the rule fires; present any other self-signed certificate and confirm it does not.
**Deployment:** Network sensor with TLS certificate inspection at any network egress point; most useful for a hosting provider scanning its own address space for a redeployed or successor receiver, since the certificate structure (unlike the specific hash, which is in the IOC feed instead) survives a same-configuration redeploy.

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"THL DETECT SSH-MITM-ParasiticCredentialTheft Self-Signed CN=receiver Certificate (AiTM C2 Reporting Channel)"; flow:established,to_server; tls.cert_subject; content:"CN=receiver"; tls.cert_issuer; content:"CN=receiver"; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/; classtype:trojan-activity; sid:9301702; rev:2; metadata:author The_Hunters_Ledger, date 2026-08-12;)
```

### Hunting Rules

#### THL HUNT SSH-MITM-ParasiticCredentialTheft Paramiko SSH Banner Either Direction On Any Port

**Tier:** Hunting
**Robustness:** 2
**ATT&CK Coverage:** T1557 (Adversary-in-the-Middle)
**Confidence:** MODERATE
**False Positives:** Legitimate use of the public `ssh-mitm` project and other paramiko-based SSH tooling, paramiko-based honeypots deployed for research rather than as this platform, and any legitimate paramiko client library making outbound SSH connections for automation purposes. This platform's own relays run `paramiko_3.5.1` and its receiver runs `paramiko_5.0.0`; anchoring on the bare `paramiko_` prefix rather than either full version string is what lets this one rule cover both, at the cost of casting a wider net than the port-22-scoped Detection rule above.
**Blind Spots:** Provides no attribution to this specific platform versus any other paramiko-based tool; every hit needs analyst review before action.
**Deployment:** Network sensor at any monitoring point; use for broad scoping and hunting, not for automated blocking or alerting.

```
alert ssh $HOME_NET any <> $EXTERNAL_NET any (msg:"THL HUNT SSH-MITM-ParasiticCredentialTheft Paramiko SSH Banner Either Direction On Any Port (Toolkit-Family Indicator)"; ssh.software; content:"paramiko_"; nocase; threshold:type limit,track by_src,count 1,seconds 3600; reference:url,the-hunters-ledger.com/hunting-detections/opendirectory-157-180-101-47-ssh-mitm-parasitic-credential-theft-20260812-detections/; classtype:misc-activity; sid:9301703; rev:2; metadata:author The_Hunters_Ledger, date 2026-08-12;)
```

---

## Coverage Gaps

A port scan of a compromised relay finds nothing, no matter how many nodes are live, and this is the single most important operational fact in this file. Every relay drops every inbound packet to its interception listener that does not arrive on loopback (`iptables -I INPUT 1 -p tcp --dport 19923 ! -i lo -j DROP`). The paramiko banner that identifies the platform is exposed only to a client whose own outbound port-22 traffic gets internally redirected into the listener.

Only on the operator's own receiver, a management box rather than a relay, does the same banner appear to an ordinary unsolicited connection. No scan a defender could run from outside will surface a compromised relay by probing it. Detection has to be host-side (auditd, file telemetry, process telemetry, the Sigma rules above) or traffic-side at a point the interception's own outbound or inbound traffic actually crosses (the Suricata rules above). A negative scan result proves nothing.

The relay-to-receiver reporting channel is also genuinely opaque to passive inspection. It is real TLS, not plaintext, so the `X-Token` authentication header, the JSON request and response bodies, and the specific endpoint paths (`/report`, `/api`, `/targets`, `/hostkey/<ip>`, `/observed`, `/servers`, `/excludes`, `/credentials`, `/payload`) are invisible to a network sensor without a decrypting intercept, which is not something to expect on adversary-controlled infrastructure. The two Suricata rules above work around this by inspecting only what TLS exposes without decryption, the certificate presented during the handshake and the plaintext SSH banner.

The retry pattern (3 attempts on a 0, 2, 4-second backoff) and the polling cadence (roughly 300 seconds for a heartbeat, 600 seconds for an exclusion-list pull) are both documented behaviors of this platform, but neither is independently encoded as a rule here. Both would need counting repeated connection attempts against the same destination over a multi-minute window, which a SIEM's own beacon-detection analytics can do against the connection log the Suricata rules above already generate, better than a single signature could.

JARM is not expressible as a Suricata signature at all. It is an active-scanning fingerprint computed by sending crafted TLS ClientHellos and hashing the server's responses, not something a passive sensor can derive from observed traffic. The receiver's JARM lives in the IOC feed as a pivot value for tools built for that purpose, not as a detection rule here.

The `prctl(PR_SET_NAME)` kernel-thread masquerade (`kworker/2:0H`, `kworker/2:1H`) has no single-event Sigma signature. The rename happens as an ongoing syscall from within the already-running process, after the initial `execve` that the process-launch Sigma rule above catches, so an audit trail built on `execve` records alone shows the process launching as `python3` and never shows the later rename to a kernel-thread-styled name. Finding this reliably needs point-in-time process-table inspection, comparing a process's `comm` field against whether it actually has a userland executable, which is the kind of check a Velociraptor or EDR process-inventory hunt does well and a log-based correlation rule does not.

The same applies to confirming a process's backing script shows as deleted (`/proc/<pid>/exe` reading `(deleted)`) with `cwd` under `/dev/shm/.local`. It is real, strong evidence, but a process-state fact rather than a loggable event.

The single failed `sudo` entry immediately after a successful login, with no interactive follow-up, is not covered by a rule here either. The behaviour is well evidenced (the operator explicitly accepted this forensic cost for the `sudo -S` password-replay escalation mode), but expressing "no other activity happened in this window" is a negative condition Sigma's correlation types are not built to test. No standard normalized logsource maps cleanly to a `sudo` PAM authentication failure as distinct from the process-creation event of `sudo` itself being invoked, which fires regardless of whether the password behind it was right. A defender chasing this signal directly should grep `auth.log`/`secure` for a `sudo` failure with no corresponding command output in the same session, rather than expect a packaged rule for it.

The freshly generated RSA-2048 host key where a modern server would offer ED25519 is the clearest tell available to a victim, and it is also not rule-able in the usual sense. It is exactly what SSH's own host-key verification already exists to catch; the platform's whole approach depends on a client connecting with host-key checking disabled or bypassed (`StrictHostKeyChecking=no`) in the first place. The defensive answer here is procedural, never disable host-key checking, keep `known_hosts` intact and alert on changes, rather than a new detection artifact this file could add.

`sniffer.py` and `exclude_puller.py` have command-line coverage through the process-launch Sigma rule above but no dedicated YARA rule. The evidence available for their own source content, beyond the sniffer's invocation flags, is thin, just a byte-size figure and a general description of what each does, not the kind of distinctive internal strings the other five YARA rules anchor on. Building a rule from a filename and a plausible-sounding string would produce a fabricated indicator, so this is recorded as a gap rather than papered over. Recovering more of either script's literal source text would close it.

One ATT&CK identifier has moved, and it is worth flagging for anyone cross-referencing older material. Firewall-modification behaviour was historically mapped to `T1562.004` (Disable or Modify System Firewall). That identifier no longer resolves against the current ATT&CK dataset; the technique now lives at `T1686` with the same name, under the `defense-impairment` tactic rather than the former `defense-evasion`. Every Sigma rule in this file that covers firewall-modification behavior is tagged `attack.t1686`, not `attack.t1562.004`, because that is what currently passes SigmaHQ's validator, and the two identifiers should be read as the same finding.

Two operational caveats apply to every rule above. On a host where the interceptor runs inside a VPN container (the Amnezia scheme and similar), a host-level firewall check comes back clean, because the redirect rules live inside the container's own network namespace; checking `iptables -t nat -S` from the host misses them entirely, and the check has to run inside the container's namespace instead. The operator also maintains an exclusion list of 1,507 addresses (as of 2026-07-17) that are deliberately never intercepted, so a clean result against any single target host says nothing about any other host. Absence of interception against one address is not evidence of absence anywhere else in an operator's reach.

---

## License
Detection rules are licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)**.  
Free to use, including commercially, with attribution to The Hunters Ledger.
