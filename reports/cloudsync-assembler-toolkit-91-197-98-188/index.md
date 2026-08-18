---
title: "CloudSync: An Assembler's Intrusion Toolkit"
date: '2026-08-03'
layout: post
permalink: /reports/cloudsync-assembler-toolkit-91-197-98-188/
thumbnail: /assets/images/cards/cloudsync-assembler-toolkit-91-197-98-188.png
hide: true
category: "Intrusion Toolkit"
description: "A 22-file intrusion toolkit staged on a live open directory, built almost entirely from other people's tooling. Three named threat actors' tools sit in the kit, and the operator is none of them."
detection_page: /hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/
ioc_feed: /ioc-feeds/cloudsync-assembler-toolkit-91-197-98-188-iocs.json
detection_sections:
  - label: "Detection Coverage Summary"
    anchor: "#detection-coverage-summary"
  - label: "YARA Rules"
    anchor: "#yara-rules"
  - label: "Sigma Rules"
    anchor: "#sigma-rules"
  - label: "Suricata Signatures"
    anchor: "#suricata-signatures"
  - label: "Coverage Gaps"
    anchor: "#coverage-gaps"
ioc_highlights:
  - "91[.]197[.]98[.]188"
  - "91[.]92[.]43[.]221"
  - "2[.]27[.]248[.]138"
  - "62aa8e470e60aa9fa77df6e6e63b7c253657e95d6018240b1752a9ca9fe389fa"
  - "d25a3a858e28faa68ca6c624d7d19350c11ac798c346be3067307463e40aaff1"
stix_bundle: /stix/cloudsync-assembler-toolkit-91-197-98-188.json
figure_nav:
  - image: cloudsync-assembly-map.svg
    parts:
      - label: "What they wrote"
        anchor: "#7-cloudsync-the-tor-hidden-service-panel-rat"
      - label: "What they acquired"
        anchor: "#the-sourced-components-tool-by-tool"
      - label: "The five buckets"
        anchor: "#the-five-buckets"
      - label: "The three named actors"
        anchor: "#111-the-three-threads-in-one-frame"
      - label: "The orchestrator"
        anchor: "#9-the-orchestrator-the-stub-and-the-parked-stealer"
  - image: cloudsync-per-victim-tor-panel.svg
    parts:
      - label: "Working directory"
        anchor: "#host-side-artifacts"
      - label: "Why Tor per victim"
        anchor: "#why-the-tor-architecture-is-the-interesting-choice"
      - label: "The C2 protocol"
        anchor: "#the-c2-protocol"
      - label: "Unauthenticated peer"
        anchor: "#the-command-channel-does-not-authenticate-its-peer"
  - image: cloudsync-abexe-deployment-chain.svg
    parts:
      - label: "Stage by stage"
        anchor: "#abexe-stage-by-stage"
      - label: "ct.bat self-gating"
        anchor: "#ctbat-and-why-the-self-gating-matters"
      - label: "The parked stealer"
        anchor: "#sentinelstealers-capability-profile-and-the-locker-question"
---

**Campaign Identifier:** CloudSync-Assembler-Toolkit-91.197.98.188<br>
**Last Updated:** August 3, 2026<br>
**Threat Level:** HIGH

---

## 1. Executive Summary

An assembler-model operator looks like this. Twenty-two files staged on one open web directory, of which the operator plausibly wrote three. Around those three sit a delivery loader bought or borrowed from a criminal builder service, an ASPX web shell from a Chinese .NET security community, a commodity credential stealer they collected and never even wired in, six separate public offensive-tooling ecosystems, and three unrelated commercial remote-desktop products.

The answer to the second half of the question, how you detect one, follows directly from the first half. You stop hunting the components. Every borrowed part in this kit already has somebody else's detections written for it, and the operator gains nothing by being caught on those. What has no coverage anywhere is the glue, meaning the sequence in which the parts get called, the constants reused across them, and the persistence the operator plants once the borrowed tools have done their job. That is the only part they own, and it is the part that survives them swapping suppliers.

The case makes that argument three times in one breath, which is why I lead with it. Three separately named threat actors' tooling sits in this single kit. The delivery loader belongs to the "Paralell" family that LevelBlue attributes to Blind Eagle (APT-C-36). The RAT builder hardcodes a Telegram notification id that KELA maps to the GDLockerSec persona. The web shell is Sharp4WebCmd, which AhnLab documents in a campaign it attributes to Larva-26009. **None of the three is the operator.** Each match is a receipt from a different supplier, and a receipt tells you where somebody shopped, not who they are.

I track this operator as **UTA-2026-021** *(an internal tracking label used by The Hunters Ledger, see Section 11)*, and I cannot put a name on them. That is a conclusion rather than a shortfall. Because the three named candidates are mutually exclusive as operators, at most one of the three tool matches could ever have been an identity claim, so once two of them have to be provenance there is no principled reason to treat the third any differently. Every tool match drops out of the identity column at once, and what is left behind is not a blank but a set of positive separations. Named-actor attribution here is INSUFFICIENT by refutation, which is a stronger place to stand than INSUFFICIENT by absence, because one more tool match will not overturn it.

What the kit is aimed at is not ambiguous. An operator-built deployment orchestrator, `ab.exe`, hardcodes the Active Directory domain of **a German outpatient healthcare provider** inside a `New-ADUser` command that creates a hidden, non-expiring backdoor account and escalates it into Domain, Enterprise and Schema Admins. Targeting that organization is DEFINITE. Whether the operator ever achieved the privileged access that command requires is a separate question and I hold it at MODERATE, because nothing shows the command running, no victim-side telemetry exists, no second artifact ties to the organization, and no incident has been reported. The word I use is targeted, not compromised, and the distinction matters both to what can be published and to what a disclosure notice can responsibly say.

Underneath the borrowed layer sit two custom remote-access toolchains. **CloudSync** is a C++ RAT that stands each victim up as its own Tor hidden service hosting a browser control panel with a command shell, PowerShell, a file manager and an internal CIDR and port scanner, then notifies the operator over a Telegram bot. It is undocumented in public threat intelligence under any name, which is the gap this report exists to close. The second toolchain is a **fileless .NET RAT** delivered through a JScript loader that decrypts everything in memory and injects into signed `MSBuild.exe`, disabling Microsoft Defender on the way past. Both are wired into the same operator constants and the same hosting.

I rate this campaign **HIGH**, at 8.3/10 in Section 2. The justification is capability plus intent against a healthcare target with a complete kill chain from initial access through forest-level domain persistence to internal reconnaissance, with three attacker-controlled hosts and a demonstrated ability to run in memory and turn Defender off. It is not CRITICAL because achieved privileged access is unconfirmed and, on a full sweep of the recovered files, **no file-encryption or locker capability** exists anywhere in the kit. Extortion is a coherent motive for this target and it is never evidenced as deployed.

### Key takeaways

- The operator assembles, they do not author. The honest list of candidates for their own work runs to three items out of twenty-two files. That imbalance is the operative fact about this actor and it is why tool matches cannot carry an actor judgment here even in principle.
- Three named-actor tool matches, zero named-actor attribution. Blind Eagle, GDLockerSec and Larva-26009 are all kit sources. Attributing on tool matches would have been wrong three separate times in this one case, in three different directions.
- A per-victim Tor hidden service is the standout architecture. The implant provisions its own `.onion` on the victim host and reports the address back to the C2 as a named registration field, which removes the operator's need for any proxy or VPN infrastructure of their own. An exit-node blocklist is useless against it, because a hidden service never touches an exit node.
- The delivery chain is the sophistication, the payloads are not. Custom multi-primitive JScript crypto, in-memory .NET injection into a signed build tool, AMSI patching and Defender tampering sit in front of a conventional browser-credential stealer and keylogger. The operator invested where detection actually happens.
- The CloudSync command channel does not authenticate its peer. The implant sends its own auth key up to the server, then executes whatever comes back through `cmd.exe` without ever checking who it is talking to. Any host that can answer on that port gets code execution on the victim.
- Detection lives in the seams. The highest-value anchors are an Active Directory user object whose `sAMAccountName` ends in `$` while its `objectClass` is `user`, a `wscript.exe` to `powershell.exe` to `MSBuild.exe` chain with no project file, and a roughly 10 MB `taskhostw.exe` sitting in `C:\Users\Public\fs\`. All three survive the operator rotating every IP and rebuilding every binary.

This report exists because CloudSync has no public documentation anywhere and because the case turned into a working demonstration of how to separate toolkit attribution from actor attribution, in a situation where the intuitive call is wrong in all three directions. Detection rules are published separately in the [companion detection file](/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/), and the validated machine-readable indicators in the [IOC feed](/ioc-feeds/cloudsync-assembler-toolkit-91-197-98-188-iocs.json).

---

## 2. Business Risk Assessment

The toolkit scores **8.3/10, HIGH**. What drives that number is not any single capability but the completeness of the chain, running from a proxy-aware delivery stub through fileless execution, forest-level domain persistence, internal network mapping and a full lateral-movement toolset, aimed at an organization that holds patient data.

<table>
<colgroup>
<col style="width: 24%;">
<col style="width: 10%;">
<col style="width: 10%;">
<col style="width: 56%;">
</colgroup>
<thead>
<tr><th>Risk Dimension</th><th>Weight</th><th>Score</th><th>Rationale</th></tr>
</thead>
<tbody>
<tr><td>Data Exfiltration</td><td>20%</td><td>7/10</td><td>Browser credential theft through DPAPI and NSS, a low-level keylogger, microphone capture, and a panel file manager with arbitrary download. What holds it below 9 is that no bulk staging or archive routine exists in any recovered build, and no exfiltration was ever observed on the wire.</td></tr>
<tr><td>System Compromise</td><td>20%</td><td>9/10</td><td>Full interactive remote control over a command shell and a PowerShell runspace, plus the tooling to plant a hidden Active Directory account escalated into Domain, Enterprise and Schema Admins, plus a staged privilege-escalation exploit. Forest-level access is the ceiling of what a Windows estate has to lose.</td></tr>
<tr><td>Persistence Difficulty</td><td>15%</td><td>9/10</td><td>Five independent footholds planted by design rather than by accident, spanning a directory account, an IIS web shell, unattended remote-desktop software, a Windows service and scheduled tasks. Removing any one leaves the others intact, and the directory account survives a full workstation rebuild.</td></tr>
<tr><td>Evasion Capability</td><td>15%</td><td>9/10</td><td>Nothing malicious is written to disk in cleartext. The payload decrypts through four custom crypto primitives, loads reflectively into signed <code>MSBuild.exe</code>, patches AMSI in process, turns off Defender real-time monitoring, and cleans up its own staging artifacts afterwards.</td></tr>
<tr><td>Lateral Movement</td><td>15%</td><td>8/10</td><td>A CIDR and port scanner built into the victim-side panel, plus NetExec for credential spraying, PsExec for service execution over SMB, PrintSpoofer for local escalation, and four separate tunnelling utilities. This is a credential-entry-and-pivot profile rather than an exploitation one.</td></tr>
<tr><td>Detection Challenge</td><td>15%</td><td>8/10</td><td>Custom crypto defeats the encoding patterns most content rules key on, and Tor-wrapped panel traffic is opaque once the hidden service is up. It is not a 10 because the operator left durable behavioral anchors in the chain shape, the working directory and the account masquerade.</td></tr>
<tr><td><strong>Overall</strong></td><td>100%</td><td><strong>8.3/10</strong></td><td><strong>HIGH.</strong> A complete kill chain with live infrastructure against a healthcare target. Held below CRITICAL by two things, both of which are absences rather than mitigations: achieved privileged access is unconfirmed at MODERATE, and no file-encryption or locker capability exists anywhere in the recovered kit.</td></tr>
</tbody>
</table>

### What this means for an organization that finds it

The exposure worth planning around is the durability of the foothold, not the malware. If the orchestrator ran to completion on a domain-joined host, the operator holds a directory account with permanent membership in the three most privileged groups in the forest, disguised so that a casual audit reads it as a machine account, hidden from the logon screen by a registry write, and set never to expire. Resetting user passwords does not touch it. Reimaging the entry workstation does not touch it. It persists until somebody queries the directory for it specifically.

Around that sit four more footholds that fail independently of each other. A web shell in the IIS content tree gives command execution as the web-server identity. Unattended remote-desktop software gives an interactive session with an operator-set password. A service and a scheduled task each restore the RAT after reboot. An organization that finds one of these and stops has removed one foothold out of five, not the operation.

The data at risk is what a small care provider holds, which is patient records and staff personal data, and the tooling to reach it is present rather than inferred. Browser credential theft, keylogging and a file manager are all in the recovered builds. What I cannot tell you is whether any of it was used, because that evidence lives on the victim's side and I do not have it.

The one piece of genuinely good news is that the kit contains no ransomware. I checked for it properly rather than assuming, because an earlier read in this investigation got it wrong in both directions before it settled. Section 9.4 lays out the evidence in full; in short, the stealer carries every marker of a credential thief and none of a file encryptor. That is a near-DEFINITE negative on this kit as recovered, and it is worth stating plainly because a healthcare victim's first question is always whether this was a ransomware attack.

---

## 3. Campaign Scope and Target Landscape

The scope is wider than one victim, and finding that out changed how urgent this became. The organization named in the tooling is a German outpatient healthcare provider, but that organization does not run its own perimeter. Its internet-facing services sit behind an edge operated by a small regional IT provider, and the same edge fronts several other customers.

Published without naming anyone, the same internet-facing edge fronts two related corporate groups in the same social-care sector, a law firm, and the IT provider that administers all of it, across two separate Active Directory forests. Twelve apex domains resolve to it. The IT provider's own terminal server sits on that same perimeter alongside every client environment it manages.

> **Analyst note:** when I first found this I was genuinely surprised. Up to that point I thought I was looking at one victim. Then I went looking for how the operator got in, and the situation got worse rather than clearer, because the likely way in was a small IT provider running old unpatched servers, which means anyone else connected to that same edge could be exposed too. That is what turned a single-victim finding into a notification that had to go out immediately, and to a different recipient than I had planned. It is also disappointing to see, as a practitioner in a threat landscape this vulnerability-heavy, that a provider serving organizations like these is not taking basic precautions.

### How they got in, and why I will not rank the two candidates

I put initial access through an internet-facing Microsoft Exchange server at **MODERATE**, and I put remote desktop genuinely level with it. I am presenting them unranked because the evidence does not separate them, and pretending otherwise would be false precision.

What supports the Exchange reading is the operator's own behaviour rather than any scan result. The very first thing `ab.exe` does is write its web shell to `C:\inetpub\wwwroot\aspnet_client\`, which is the canonical ProxyLogon and ProxyShell drop path. An operator who reaches for that path first is an operator whose mental model of the target starts at Exchange. Supporting it is the fact that the victim's own mail server hands its Active Directory domain name to any unauthenticated internet scan, so no inside access was needed to learn the domain that ends up hardcoded in the orchestrator.

What weakens it is equally real, and I want it visible. A tool that runs after you are already inside tells you what the operator wanted next, not how they got in, and `aspnet_client` exists on any IIS host whether or not Exchange is involved. An earlier version of this assessment leaned on a server version string to argue the target was running years-old unpatched Exchange. That read was retracted, because the version evidence contradicted itself across sources and I could not resolve which snapshot was current. **No CVE claim** of any kind is supportable here. The Exchange build is unresolved, and anyone reading a specific vulnerability into this campaign is reading something I did not find.

The remote-desktop candidate is co-equal on straightforward grounds. Two domain-joined terminal servers were directly internet-facing on non-standard high ports, an IKE endpoint was exposed alongside them, and there was no protective layer in front of any of it. Set that against a toolkit whose composition is a credential-entry-and-pivot profile rather than an exploitation one, and credential reuse or spraying against an exposed terminal server is exactly as plausible as an Exchange exploit. Both are consistent with everything observed.

### A working hypothesis about the order of operations, held at LOW

The operator built for a German target deliberately. The group names compiled into `ab.exe` are `Domänen-Admins`, `Organisations-Admins`, `Schema-Admins` and `Administratoren`, which are the standard localized names in any German-language Active Directory, so a command using the English names would simply have failed.

My read is that the exposed server came first and the target followed from it, rather than the other way round. Under that ordering the operator finds an exposed edge, gets access, discovers what is behind it, customizes their tooling for a German environment, and then works outward to the organizations sharing that perimeter. It explains why so little reconnaissance was needed, why the localization sits in a post-access consolidation tool rather than in anything used to get in, and why the estate behind the edge matters at all.

I hold that at **LOW**, and I want to be precise about why rather than dressing it up. The test I first proposed for it does not work. I argued that `ab.exe` compiling on 2026-03-29 with the victim domain already inside it means access predates the build, but both orderings predict exactly that, so the compile date discriminates nothing. Two supporting strands are also weaker than they look, because the localization and the hardcoded domain are two properties of one customization of one binary rather than two independent signals, and the pre-authentication domain disclosure shows that reconnaissance was cheap rather than that it was skipped. What would actually separate the two orderings is an earlier un-localized build of the same orchestrator, or other victims on that edge sharing the internet-facing-server property rather than a sector or a geography. Neither exists in what I have.

---

## 4. Technical Classification

This is a toolkit, not a sample, and reading it as a sample is how an analyst ends up attributing it to the wrong person. Twenty-two files were staged on one open directory, and they fall into five buckets whose provenance runs from operator-authored to entirely off the shelf.

| Attribute | Assessment |
|---|---|
| Campaign type | Assembled multi-family intrusion toolkit, loader chain plus hands-on-keyboard |
| Primary family | **CloudSync**, a custom C++ Tor-hidden-service panel RAT with no public documentation under any name |
| Secondary families | `SvchostPayload`, a custom .NET RAT delivered by a sourced Paralell-family loader; SentinelStealer, a commodity stealer collected and parked |
| Family confidence | CloudSync one-builder linkage DEFINITE; two toolchains one operator MODERATE; the families themselves HIGH to DEFINITE on direct artifact evidence |
| Sophistication | Advanced tradecraft in delivery and evasion, conventional payloads |
| Threat level | **HIGH** (8.3/10) |
| Threat category | Cybercrime, intrusion set, assembler operator |
| Active window | Operator tooling compiled from November 2025, target-specific builds spanning March to June 2026, staging directory reachable and unchanged for three-plus months |

### The five buckets

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/cloudsync-assembler-toolkit-91-197-98-188/cloudsync-assembly-map.svg" | relative_url }}" alt="A six-panel grid infographic titled 'What the Operator Actually Wrote', splitting a 22-file toolkit into what was authored and what was acquired. Top-left, a red panel labelled AUTHORED lists the operator's own code: the CloudSync RAT across five builds written in C plus plus with MinGW-w64, a target-specific deployment orchestrator localized to one forest, and a deployment stub, with the note that this is the whole of it and the rest was acquired. Top-right, a deep red panel labelled SOURCED, from named actors, lists three items: the CloudSync kit tying to GDLockerSec through a hardcoded Telegram notify id, a Paralell loader from the Blind Eagle toolkit identified by a nested-misspelled PDB path and base28 loader, and Sharp4WebCmd associated with Larva-26009, noting that these artifacts belong to the kit authors. Middle-left, a yellow panel lists sourced public offensive tooling including NetExec, PrintSpoofer, PsExec, Nishang, chisel, bore, ssh and Tor. Middle-right, a grey panel lists legitimate software including three commercial remote-access products and signed Microsoft components. Bottom-left, a grey panel covers a commodity stealer collected but never wired in. Bottom-right, an orange panel titled 'The trap, why all three fail' explains that the three named actors are mutually exclusive, so at most one tool match could ever have been an identity, and concludes that named-actor attribution is INSUFFICIENT by refutation. The footer records tracking as UTA-2026-021, anchored on the infrastructure estate and the target-specific orchestrator rather than on shared constants.">
  <figcaption><em>Figure 1: The whole argument in one image. The red panel is everything the operator wrote; every other panel was acquired. The three named actors sit together in the deep red panel for a reason, because each supplies tooling and none of them supplies an identity. A reader who takes only one thing from this report should take this: in a kit assembled this way, the identity artifacts you recover belong to whoever built the component, not to whoever deployed it.</em></figcaption>
</figure>

CloudSync accounts for five samples, being `client.exe`, `q.exe` and `s.exe` (one build, config-only variants) plus `bk.exe` (a dropper) and `svhost4.exe` (a standalone implant). The .NET chain accounts for one file on disk, `svhost.js`, which unpacks two more assemblies that never touch disk at all. The orchestrator is `ab.exe`, and the deployment stub is `ct.bat`. Everything else is sourced or commodity, meaning NetExec, PrintSpoofer, Nishang, chisel, bore, Win32-OpenSSH, Tor, PsExec renamed to `exec.exe`, AnyDesk, RustDesk, Radmin VPN, a stock signed LibreSSL library, the SentinelStealer build `v.exe`, and `rr.exe`, which turned out to be a near-empty MinGW stub whose every suspicious-looking signal is compiler output.

That last one is worth a sentence on its own, because it was the fourth stock-component false positive in this case and it is why the analysis carries a standing rule. These binaries statically link Tor and use the MinGW-w64 C runtime, and both produce strings that read like tradecraft if you do not subtract the baseline first. Section 7 lists the specific misreadings so nobody repeats them.

### Build lineage

The compiler artifacts order the builds in time, and the ordering is useful because it shows an operator iterating rather than deploying once and walking away.

| Sample | Size (bytes) | imphash | Toolchain | Compiled (UTC) |
|---|---|---|---|---|
| `ab.exe` | 974,336 | `b318706357aecc6715c617608ee7e411` | GCC 15.2.0 / mingw-w64 v13.0.0 | 2026-03-29 |
| `svhost4.exe` | 44,634,624 | `1709c1b06eaaf503f70b4d39e7cf131b` | GCC 15.2.0 / mingw-w64 v13.0.0 | 2026-04-26 |
| `bk.exe` | 44,640,256 | `0f59f07585bd3695d4c8fce4a8e46998` | GCC 15.2.0 / mingw-w64 v13.0.0 | 2026-06-09 |
| `client.exe` | 36,668,416 | `631b2c5416914cfd00211b30a94c2e93` | GCC 16.1.0 / mingw-w64 v14.0.0 | 2026-06-20 |
| `q.exe` | 36,668,416 | `631b2c5416914cfd00211b30a94c2e93` | GCC 16.1.0 / mingw-w64 v14.0.0 | 2026-06-21 |
| `s.exe` | 36,668,416 | `631b2c5416914cfd00211b30a94c2e93` | GCC 16.1.0 / mingw-w64 v14.0.0 | 2026-06-21 |

The `client`/`q`/`s` cohort is **latest at HIGH**, which rests on two things that really are independent, a newer compiler generation and a larger feature set. An operator does not adopt an older compiler going forward. The `svhost4`-before-`bk` ordering inside the earlier cohort is only **MODERATE**, resting on a single naming-convention axis, and I have dropped the stronger "monotonic refinement" framing this case used to carry because the endpoint-count evidence behind it turned out to be partly an artifact of how the two builds were examined rather than a property of the builds.

### What sophistication means here, precisely

Almost none of the sophistication is in what the payloads do. Browser credential theft, keylogging, screen capture and a remote shell are commodity capabilities that have been in every RAT for fifteen years. The sophistication is concentrated entirely in getting those payloads onto a host and past detection, and that is a deliberate allocation of effort rather than an accident of what the operator could build.

I read this as a specialist who buys or borrows the parts they are not good at, and invests heavily in the one part where they genuinely are. They have a sharp, distinct method for making sure the payload executes, and several ways of hiding it that only make sense if you understand how defenders actually work, meaning what gets logged, what gets alerted on, and what counts as normal for this kind of payload. Then they do something different from all of it. An operator who thought an over-engineered delivery chain was not worth the effort would not have built one, so the fact that they did tells you they can, and probably have before.

---

## 5. The Attack Chain, End to End

The operator runs two toolchains that reach the same place by different routes, and the useful way to read them is side by side. Both end with durable remote access plus credential theft on a host the operator can return to.

| Stage | CloudSync route | .NET route |
|---|---|---|
| Delivery | `ct.bat` fetches `client.exe` from the staging host over a proxy-aware download | `svhost.js` arrives as a WSH JScript file |
| Execution | The dropper writes `svchost.exe` beside itself and launches it | `wscript.exe` decrypts in memory and hands a stage to hidden PowerShell |
| Evasion | AMSI patched in process before launch | Reflective injection into signed `MSBuild.exe`, Defender real-time monitoring turned off |
| Persistence | Run key, or a service named "Windows Update Service" | A `PhotoStudioJS` logon task, plus a second `WindowsUpdateService` task |
| C2 | Cleartext TCP to the staging host, plus a per-victim Tor onion panel | Raw-IP TCP beacon, no domain involved at all |
| Objective | Interactive control, internal scanning, file transfer | Browser credentials, keystrokes, hidden desktop, microphone |
| Spread | Copies itself to removable drives with an `autorun.inf` | Same USB routine, independently implemented |

Once either route lands and the operator has privileged access, `ab.exe` runs and converts a foothold into an estate. It writes an ASPX web shell into the IIS content tree, creates the hidden `Guest$` directory account and escalates it to forest level, then installs AnyDesk with an unattended password. It does those three in a fixed order, web shell first, and it continues past any stage that fails.

### The chronology of a CloudSync infection

Reading the implant's own operational log, the sequence is tight and it does the noisy things first, which is unusual and worth noticing.

First it profiles the host, collecting computer name, username, operating system, external address and domain membership into a cleartext JSON record it writes to `config.json` in its working directory under `C:\Users\Public\`.

Then it stands up its own Tor hidden service. The implant launches a roughly 10 MB `taskhostw.exe`, which is a statically compiled Tor binary wearing a Windows system-process name, points it at a generated `torrc`, and lets Tor mint a fresh `.onion` address for this specific victim. No `.onion` is hardcoded in any build, because the address is created on the victim rather than assigned by the operator.

Then it tells the operator it has landed, over `api.telegram.org`, to the hardcoded chat id `8116056430`. This is a first-run notification only, not the control channel.

Then it registers with the C2, sending a 32-character static authentication key as the first line, followed by a keyed profile block that includes the freshly generated onion address, the AnyDesk credentials, and the `Guest$` backdoor account name and password as named protocol fields.

Then it serves the panel and settles into a heartbeat. The operator browses to the victim's onion address and gets an HTML control panel with tabs for a command shell, a PowerShell runspace, a file manager, process listing and termination, connection enumeration, download-and-execute, and a CIDR and port scanner for the internal network. The implant heartbeats roughly every minute, shipping raw `net share` output up to the C2 each time.

That ordering matters for a defender because the loudest event, a workstation initiating Tor, happens within seconds of first execution and before any hands-on-keyboard activity. It is the earliest reliable signal available and it does not depend on catching the operator doing anything.

### Why the Tor architecture is the interesting choice

The operator does not connect to the victim through their own infrastructure. The victim connects into Tor and publishes a service there, and the operator reaches that service as a client. Standing that up means the operator never needs proxies, VPNs or a reverse-connect listener of their own, and the panel is reachable from anywhere without exposing a single operator-controlled address to the victim's network telemetry.

I had not seen this before and I have not found it documented anywhere, which is a large part of why this report exists. My first reaction was that it is a lot of engineering for something plenty of organizations neutralize by blocking Tor outright, and I still think that tension is real. But a blocklist of Tor exit nodes does nothing here, because a hidden service never touches an exit node, and that catches out a lot of people who think they have Tor covered. The detectable event is a workstation speaking the Tor protocol outbound at all, plus a `hidden_service` directory sitting on local disk. Anyone whose Tor control is an exit-node list has no coverage of this whatsoever.

The other thing the architecture tells you is how much work went into it. Statically compiling Tor into a 36 MB binary, generating per-victim onions, and serving a full browser panel from an embedded HTTP server is a serious build. Nobody does that speculatively, so I read it as a design somebody has been getting results from.

---

## 6. Threat Intelligence: Where the Kit Came From

The supply chain behind this operation is the intelligence, so this section walks the sourcing rather than the threat landscape. Every component below is somebody else's work, which is what makes the composition itself the operator's signature.

### CloudSync has no public documentation, and that is a finding rather than a gap

I re-ran the prior-art check from a clean state across three separate channels specifically to test whether the negative held, because an empty search result is not the same as an undocumented tool. It held. The primary CloudSync sample returns "file not found" on VirusTotal, meaning that exact file had never been submitted to the platform under any name. Searches combining CloudSync with Tor hidden services, RAT panels, onion Telegram notification and RAT builder returned nothing describing this toolkit, surfacing instead unrelated families that merely also use Tor for C2. A targeted search on the in-memory `Crystal-Monk` assembly name and its build-path fragment returned only legitimate obfuscator product pages.

I state that as **no public documentation found**, not as "undocumented", and the distinction is deliberate. Paywalled, non-English or vendor-internal reporting could exist without being visible. What I can say at HIGH confidence is that as of this research pass, nothing public describes this architecture.

Zero VirusTotal submissions across five-plus months of build history is worth reading on its own terms. For a toolkit with builds dating to March 2026, that absence is consistent with narrow, deliberate deployment rather than broad opportunistic distribution. It is a targeted-deployment read, not a claim about how many victims exist.

### The sourced components, tool by tool

| Component | Origin | Status |
|---|---|---|
| Paralell / `Crystal-Monk` .NET injector | A shared builder toolkit that LevelBlue SpiderLabs attributes to Blind Eagle (APT-C-36), 2026-07-17 | Sourced; that actor is not the operator, Section 11 |
| `Sharp4WebCmd` ASPX web shell | A circulating .NET tool documented by AhnLab ASEC, 2026-07-25 | Sourced; that actor is not the operator, Section 11 |
| NetExec (`nxc.exe`) | Community continuation of CrackMapExec, originally byt3bl33d3r | Off the shelf, open source |
| PrintSpoofer | itm4n (Clément Labro), published 2020-05-02 | Off the shelf, public LPE proof of concept |
| Nishang `Invoke-PowerShellTcp.ps1` | samratashok's offensive PowerShell collection | Off the shelf, open source |
| chisel | jpillora, a Go TCP/UDP tunnel over HTTP | Off the shelf; Malpedia catalogs it as `win.chisel` due to sustained abuse |
| bore | ekzhang, a minimal Rust TCP tunnel | Off the shelf, open source |
| `ssh.exe` | Microsoft's own Win32-OpenSSH port | Off the shelf, Microsoft-signed |
| PsExec, renamed `exec.exe` | Sysinternals, Microsoft-signed | Off the shelf, renamed only |
| Tor | The Tor Project, statically linked into the operator's own binaries | Off the shelf, embedded |
| AnyDesk, RustDesk, Radmin VPN | Three unrelated commercial remote-desktop vendors | Off the shelf, legitimate software |
| SentinelStealer (`v.exe`) | A commodity credential and wallet stealer, ConfuserEx2-protected | Sourced, collected and never integrated |

Six distinct public offensive-tooling ecosystems, drawn on for one operation. That is the number that makes the characterization stick, because a developer with a settled toolkit does not shop this widely.

The three commercial remote-desktop products are the tell I find most persuasive, and it is a small one. An operator with a preference stages one. Staging AnyDesk, RustDesk and Radmin VPN side by side is what collecting looks like, not what choosing looks like. Abusing legitimate remote-management software is not itself novel, and CISA, the FBI and MS-ISAC have published joint advisories on exactly this pattern (AA23-025A on RMM abuse generally, and AA24-109A documenting Akira operators deploying AnyDesk after initial access). Third-party tracking cited by Halcyon.ai counted 17 distinct ransomware operations using AnyDesk as of mid-2024. What is specific to this operator is not the abuse, it is the redundancy.

One caveat I will keep honest. Radmin VPN is a different product from Famatech's separate Radmin remote-control software, and the documented abuse history I found belongs to the remote-control product. No source I found names Radmin VPN specifically as an abuse vector. I record that as a gap rather than collapsing the two.

### The clearest single artifact of collecting behaviour

`v.exe` is the file that settles the question, and it does it on its own. It is a ConfuserEx2-packed SentinelStealer build sitting on the operator's staging directory, and it shares no constant with any other binary in the kit. Its configuration grabs cryptocurrency wallet seeds, `wallet.dat` files and Steam Desktop Authenticator secrets, which is commodity crimeware targeting and has nothing to do with a healthcare intrusion. Its Telegram exfiltration fields are declared and never referenced by any code in the assembly, meaning nobody ever wired them up.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/cloudsync-assembler-toolkit-91-197-98-188/sentinelstealer-assembly-metadata.png" | relative_url }}" alt="Decompiled .NET assembly attributes for the v.exe sample, showing AssemblyTitle and AssemblyProduct both set to the string SentinelStealer, a build GUID, an AssemblyFileVersion of 1.0.0.0, and a TargetFramework of .NET Framework 4.7.2.">
  <figcaption><em>Figure 2: The stealer names itself. Its assembly attributes carry <code>SentinelStealer</code> in both <code>AssemblyTitle</code> and <code>AssemblyProduct</code>, and that is worth more here than it usually would be. No public reporting on this family was found under any name, so the operator's own build metadata is currently the only basis anyone has for what to call it. The same block also settles the protector question, declaring .NET Framework 4.7.2 rather than the decade-old runtime a scanner's family label implied.</em></figcaption>
</figure>

Its C2 closes it. The stealer geolocates the victim through `ip-api.com` and then opens TLS to `c3lestial.fun`, a domain on Hostinger parking nameservers, registered in September 2025, six months before any of this campaign's infrastructure existed, carrying 16 detections out of 91 engines and more than twenty unrelated communicating files. The operator's own two dedicated C2s are on a single small hosting allocation, flagged by nothing, with no sample cluster at all. Those are not the same kind of infrastructure and they do not belong to the same person.

So `v.exe` is a tool the operator picked up and staged and never integrated. I originally read it as sourced-but-integrated and the evidence moved me to sourced-and-separate, which is a local correction that leaves the wider thesis stronger rather than weaker. It is the assembler behaviour pattern one step further along, a purchase that never became part of the operation.

That correction also produced a rule I now apply generally. `c3lestial.fun` still belongs in the published indicators, in its own labelled tier. My first instinct was to leave it out because it is not this operator's infrastructure, and that instinct was wrong, because it would equally have stripped the Paralell loader, PsExec, NetExec, Nishang, chisel, the web shell and the panel skin. If the central finding is that this actor assembles other people's kit, then documenting the sourced components **is** documenting the actor. The fix is provenance labels, not omission.

### The hosting, and a precision worth keeping

The estate is three attacker-controlled hosts split across two jurisdictions by function. Russia carries staging and delivery, on `91.197.98.188` (AS197695, REG.RU), which simultaneously serves the open directory on port 8000 and two implant C2 listeners on 5555 and 7777. Germany carries both dedicated C2s, `91.92.43.221` for the CloudSync panel and `2.27.248.138` for the second toolchain's beacon, panel and operator remote desktop, both on AS207043 (Dedik Services Limited, a UK-registered company).

Read the split as an operational choice and not as a nationality signal. Nothing here indicates where the operator sits, and inferring a nationality from where somebody rents servers is the same category of error as inferring an identity from whose tools they bought.

One claim this report deliberately does not make. Bulletproof status for the German hosting stays **SUSPECTED** rather than confirmed. Dedik Services Limited is not among the seven entities the US Treasury's OFAC named across its July 2025 and November 2025 Aeza-related sanctions actions (Aeza Group LLC, Aeza International Ltd., Aeza Logistics LLC, Cloud Solutions LLC, Hypercore Ltd., Smart Digital Ideas DOO and Datavice MCHJ), and no corporate, ownership or operational link between Dedik and any designated entity was established. An earlier framing in this case had the C2 sitting on OFAC-sanctioned infrastructure. That framing is not supportable as stated and I have withdrawn it. Two scanning platforms disagreed on the ASN attribution for these addresses and I could not reproduce the alternative, which is an unresolved discrepancy rather than a finding in either direction.

The one thing the hosting does tell you is tempo. The staging host has SSH continuity reaching back to September 2025, the directory sat unchanged and reachable for over three months, there is no domain rotation anywhere in the estate, and the second-toolchain C2 was fresh within hours of the last check. This is a persistent operation, not a burst.

---

*The **technical teardown** starts here. The reverse engineering runs from this point, with deep-dive blocks collapsed, so open whichever ones interest you and leave the rest shut. Indicators, detection guidance and the confidence summary are waiting in Sections 12 to 14.*

---

## 7. CloudSync: The Tor-Hidden-Service Panel RAT

CloudSync is one builder's output across five recovered samples, written in C++ and cross-compiled from Linux with MinGW-w64, and it is genuinely unusual in one respect. Rather than calling home to a panel the operator hosts, it turns the victim into the panel. The implant carries a statically linked Tor build, provisions a hidden service on the victim host, and serves an HTML control interface from an embedded HTTP server reachable only through that per-victim onion address.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/cloudsync-assembler-toolkit-91-197-98-188/cloudsync-per-victim-tor-panel.svg" | relative_url }}" alt="A four-step vertical chain infographic titled 'One Tor Hidden Service Per Victim', showing how CloudSync turns the victim host into its own control panel. Step 1, a yellow card, covers the working directory: the implant creates its own directory under the shared Public profile containing hidden_service and downloads subdirectories, and drops an embedded Tor binary rather than downloading one, with a note that two builds use two different directory names so the durable pattern is the shape rather than the name. Step 2, a red card, covers hidden service generation: Tor runs under a masqueraded name against a written torrc mapping HiddenServicePort 80 to a local loopback port, no build hardcodes an onion address, each victim generates its own, and the implant reads the resulting hostname file back. Step 3, a red card, covers the local panel: the implant serves the browser control panel itself on a local listener and opens the Windows firewall with a netsh rule named WinUpdateSvc, where the port is generated at runtime and differs every execution but the rule name does not. Step 4, a deep red card, covers registration: the implant registers to a dedicated panel host over cleartext TCP transmitting a host profile, the onion URL and stored credentials closed by a bracketed literal, after which the operator reaches the victim's own panel over Tor with no inbound port exposed.">
  <figcaption><em>Figure 3: Why this design is awkward to detect and awkward to disrupt. The control channel terminates on the victim rather than on infrastructure anyone can seize, and once the hidden service is running the traffic is opaque on the wire. That pushes all the detection value into the setup sequence, which is noisy and specific: a Tor binary dropped under a false name, a firewall rule opened by a fixed name on a randomised port, and a directory under the Public profile containing <code>hidden_service</code>.</em></figcaption>
</figure>

The family ships in two shapes, which matters more for detection than it sounds. `client.exe`, `q.exe`, `s.exe` and `bk.exe` are **droppers** that write a payload named `svchost.exe` beside themselves, launch it and exit, in `bk`'s case in under half a second. `svhost4.exe` **is** the implant and beacons from its own process. A rule keyed on the dropper pattern alone misses `svhost4` entirely.

The panel itself is a full remote-control and internal-reconnaissance platform rather than a simple shell. The later build exposes eight tabs backed by eleven API endpoints, covering a command shell, a PowerShell runspace, file browse, download, upload, delete and create, process listing and termination, connection enumeration, download-and-execute, and a CIDR plus port scanner aimed at the internal network. The operator can map and stage against the rest of the estate from the victim, over the victim's own onion.

The command channel has a structural weakness that is worth more to a defender than any indicator in this report, and it is covered in the teardown below.

<details markdown="1" class="hl-teardown">
<summary>Full teardown: language identification, the build split, the panel endpoint inventory, and the C2 protocol on the wire</summary>

### 7.1 Language and toolchain, identified positively

The language call is **DEFINITE** and it rests on positive identification rather than elimination. The binaries carry a `GCC: (GNU) 16.1.0` version stamp and a `Mingw-w64 runtime failure:` handler. They carry Itanium C++ ABI name mangling, with `St16invalid_argument` and `St9bad_alloc` visible in the symbol residue, and those forms are structurally impossible from an MSVC build. The import set is the `api-ms-win-crt-*` UCRT family, and the section layout is GNU-style with a discrete `.bss`.

The 36 MB image is not a large runtime. `.rsrc` accounts for 96.4 percent of the file at 35.4 MB, carrying the statically compiled Tor build plus the embedded HTML, JavaScript and CSS panel. Executable code is roughly 1.2 MB of `.text`. Anyone triaging one of these on size alone will mis-bucket it as a bloated installer.

One build-environment string is recorded and deliberately dropped as a pivot. The winpthreads path `/home/vm/mingw/src/mingw-w64-v14.0.0/.../rwlock.c` is baked in by the toolchain, and whether it is operator-specific or a property of a public mingw-w64 distribution is **INCONCLUSIVE**. It is not a selector and it must not be reintroduced as one.

### 7.2 One builder, two cohorts

`client.exe`, `q.exe` and `s.exe` are **config-only variants of a single build**. Identical file size at 36,668,416 bytes, identical entropy, identical section sizes, identical imphash `631b2c5416914cfd00211b30a94c2e93`, three distinct file hashes, and the only difference between them is the C2 port inside an ASCII-hex-encoded configuration block. `client` points at port 5000, `s` at 5001, `q` at 5002.

`bk.exe` and `svhost4.exe` are a related but separate lineage, carrying different imphashes from each other and from the `client` trio. Their near-identical file sizes invite reading them as a matched pair, and that reading does not survive the imphashes. They are consecutive builds, not twins, and the distinction matters because one is a dropper and the other is the implant itself.

A fourth panel port, 5003, was confirmed live with no matching build ever recovered. **That obliges a bound** on everything else in this report. The 22-file inventory is a snapshot of what was staged, not a demonstrated-complete enumeration of the operator's toolkit, and every claim of the form "only", "no other" or "a complete sweep found nothing else" holds for the files in hand and no further.

### 7.3 The panel endpoint inventory, and what the difference between builds tells you

The later `client`/`q`/`s` build exposes eleven endpoints: `/api/cmd` for the shell, `/api/ps1` for PowerShell, `/api/dl` and `/api/psdl` for download and download-and-execute, `/api/exec` and `/api/runfile` for execution, `/api/ps` for process listing, `/api/kill` for termination, `/api/net` for connection enumeration, `/api/netscan` for the network scanner, and `/api/info` for host detail, alongside a files tab handling browse, download, delete, upload and create.

The earlier `bk`/`svhost4` build exposes seven, lacking `netscan`, `exec`, `psdl` and `runfile` entirely, and carrying no Telegram channel at all. The scanner and the notification were added later in the lineage. That is a feature set growing over time on a live toolkit rather than a static product, and it is one of the two independent axes supporting the build ordering.

The panel markup differs too, in a way that is directly usable for rules. The later build carries `showTab('netscan'`, `id='scan-cidr'`, the placeholder text `Target CIDR (e.g. 192.168.1.0/24)` and `id='netscan-output'`. The earlier build uses terser markup, with `st('dash')` and `id='b1'`.

### 7.4 Host-side artifacts

The implant works out of `C:\Users\Public\fs\`, which in earlier builds is `C:\Users\Public\filesystem`. Inside it sit `config.json` holding the cleartext victim profile, `a.dat`, `b.log`, `first_run.flag`, an empty `dl\` directory, an empty `hidden_service\` directory, and `taskhostw.exe`, which is the roughly 10 MB Tor binary wearing a Windows system-process name. A Tor configuration file is written to `%APPDATA%\tor\torrc` with a `HiddenServiceDir` pointing back under `C:\Users\Public\`.

Persistence differs by build. `bk`'s dropped implant writes an `HKCU\...\Run` value named `WUS` pointing at the dropped `svchost.exe`. `svhost4` installs a service named `WinUpdateService` with the display name "Windows Update Service", plus a `WinUpdateSvc` Run value under `WOW6432Node`. Both hold a named mutex, `Global\WUDFHost` for `bk` and `Global\WinUpdateSvcMutex` for `svhost4`.

Scope any mutex rule to the full object name. A bare `WUDFHost` token collides with legitimate Windows driver-framework telemetry and will generate noise indefinitely.

One naming detail catches people out. The dropped payload is `svchost.exe`, spelled correctly, while the staged sample is `svhost4.exe` and the JScript loader is `svhost.js`, both missing the `c`. A rule keyed on the misspelling alone misses the actual implant on disk.

### 7.5 The C2 protocol

The protocol is cleartext TCP with no TLS and no encoding, which is why its full shape is known rather than inferred. Both listeners answer the TCP handshake and then wait for the client to speak, returning no banner, so a scanner sweeping the port sees an open socket and nothing else.

Three message types run over it.

The **heartbeat** fires every 60 seconds and ships a `[Shares]` header followed by raw `net share` output, then the terminator. An implant that reports the victim's share list on a one-minute cadence is telling you exactly what the operator is shopping for.

The **registration and auto-update** message sends a 32-character static authentication key as its first line (`X9kL2mP5...hJ0`, cut shorter than the standard defang given the risk explained in Section 7.6), then `=== AUTO UPDATE ===`, then a keyed host profile using the field names `Victim ID:`, `Host:`, `OS:`, `AnyDesk ID:`, `AnyDesk Pass:`, `Guest User:`, `Guest Pass:` and `Onion URL:`.

The **command result** is whatever `cmd.exe` produced, returned as stdout and stderr.

That registration block is structurally important and it is easy to skim past. The panel is **built to receive** the Active Directory backdoor account name and password and the AnyDesk credentials, as named protocol fields. The two toolchains are not merely co-staged, they are wired together at the protocol layer, and `ab.exe`'s AD backdoor is a designed input to the CloudSync control plane rather than a separate activity that happens to share a host.

### 7.6 The command channel does not authenticate its peer

The implant sends its own authentication key **up** to the server and then executes whatever the server sends **back**, through `cmd.exe`, without ever validating that the peer is its real controller. Any host that can answer on that port gets code execution on the victim.

This is a structural property of the implant rather than a configuration mistake, which means it persists across builds until the operator rewrites the protocol. It is also why the 32-character key is defanged everywhere in this publication and deliberately excluded from every detection rule. Publishing it in a plaintext signature would hand any reader the ability to issue commands to a live infected host, and it buys no detection advantage over the message framing, which is already covered.

I flag it here because it is a disruption lever rather than a curiosity. It gives a national CERT or an infrastructure operator something concrete and it gives an incident responder a way to reason about what the operator could have done from a given foothold.

### 7.7 The terminator is build-specific, and a rule that ignores that ships broken

`svhost4`, the later build, terminates every message with `[C2_END]`, appearing 11 times in its message set. `bk`'s dropped implant, the earlier build, terminates with **`[END]`**, appearing 21 times, with zero occurrences of `[C2_END]`. The registration field names differ too, with the earlier build using `ID:`, `PC:`, `AD ID:`, `AD Pwd:` and `Onion:` where the later one uses the longer forms above.

This case very nearly published `[C2_END]` as the infrastructure-independent family signature. It is not. A rule keyed on it alone misses one of the two builds already in hand, and the published Suricata coverage ships an alternation over both terminators for that reason.

The terminator framing is still the right anchor, because it survives the operator rotating hosts in a way the hardcoded IP and port will not. It just has to cover both generations.

### 7.8 Stock-component false positives, and why this section exists

These binaries statically link Tor and use the MinGW-w64 C runtime, and both produce artifacts that read as tradecraft to anyone who has not subtracted the baseline. The following are documented false positives and must not be read as operator behaviour.

The string `ad_setup` matches Tor's own `circpad_setup_machine_on_circ`. Only `bk.exe` carries a genuine `\ad_setup.exe`, and that is an **AnyDesk installer**, because `AD` means AnyDesk throughout this family and not Active Directory. The ten 20-byte values that look like operator constants are stock Tor consensus values. The `VirtualProtect` plus `VirtualQuery` plus pseudo-relocation pattern that reads as a shellcode loader is MinGW-w64 runtime output, and a stock `tor.exe` fails the identical control test. `NetShareAdd` and `NetShareEnum` imports, `HTTP/1.0 4xx` strings, and a set of FreePBX-shaped ports on the staging host all belong to stock components or to a prior tenant of the address.

`Authorization: Basic` is flagged as un-baselined against stock Tor and is contradicted by the C2 protocol itself, which carries no authentication header at all. Treat it with the same suspicion, and at most scope it to the local panel listener rather than the C2 path.

</details>

---

## 8. The Fileless .NET Chain

This is the part of the toolkit that changed my view of the operator, and it is worth saying why before the mechanics.

Malware today mostly hits a wall at execution rather than at delivery. Getting a file onto a host is comparatively easy now. Getting it to run without generating the artifacts that logging, alerting and behavioural blocking are built to catch is the hard problem, and most commodity families do not solve it. This chain solves it. It runs without doing anything obviously malicious, decrypting rather than dropping, persisting under an ordinary-looking name before it does anything else, and handing the actual execution to `wscript.exe` and `powershell.exe`, which are already on every Windows host. Catching this before execution takes a genuinely good security stack and a team that knows what to look for.

The layer underneath is what makes it stick. The payload runs in memory, and in-memory execution is something almost everyone in this industry knows about and comparatively few actually understand well enough to detect. Wrapped around that is custom crypto that exists for exactly one reason, which is that defenders are tuned for base64 with a simple XOR, or for the output of the common public obfuscators. Nobody is tuned for a hand-rolled stack of AES, a ChaCha-style stream cipher and a keyed byte permutation. It slows down analysis too, which is a second benefit the operator gets for free.

The chain is `svhost.js`, a 545,642-byte Windows Script Host JScript file rather than a Node script, unpacking through two custom crypto layers into a PowerShell stage that never touches disk in cleartext. That stage decrypts two .NET assemblies and injects them into `MSBuild.exe`, a Microsoft-signed developer tool, running with no project file. From inside MSBuild, the payload turns off Defender's real-time monitoring, plants a second scheduled task, and beacons out to a raw IP address with no domain involved at all.

The payload itself is ordinary. Browser credential theft, a keylogger, a hidden desktop and microphone capture are commodity capabilities. The delivery is the operator's signature, and that asymmetry is the single most useful thing in this section for detection planning, because the stealer is the interchangeable part and the chain shape is not.

<details markdown="1" class="hl-teardown">
<summary>Full teardown: the two crypto layers, the Paralell injector and its build path, the SvchostPayload RAT, and the runtime chain</summary>

### 8.1 The loader's two crypto layers

Layer one is a keyed base16-XOR using a position-dependent keystream, wrapped in a decoder built from `(function(){})["constructor"]` and `String.fromCharCode` with a 16-character custom alphabet, `5v_qoKAku06M^ZW1`.

Layer two is where it stops looking like commodity JScript. It is a hand-rolled stack combining **AES-256-CBC, a ChaCha-style stream cipher, a keyed byte permutation and a feedback XOR**, hiding a payload of roughly 258 KB. Four primitives composed by hand is far past what malicious `.js` normally carries, and it is engineered specifically against the encoding patterns that content-based rules key on.

One correction from this investigation belongs here because it is instructive. An earlier read treated several large blobs in the script as decoys planted to waste an analyst's time. They were not decoys. They were the real payload store, and that only became visible on decoding the second layer. Assuming padding is padding is exactly the mistake this construction is built to induce.

### 8.2 Persistence before payload

Before anything executes, the loader writes itself into `%LOCALAPPDATA%\Photo Studio\` as `PhotoStudio.js` alongside a `PhotoStudio.vbs` that relaunches it windowless, and registers a logon-triggered scheduled task named `PhotoStudioJS`. The task is created from an XML file dropped to `%TEMP%\Task_<digits>.xml`, which the loader deletes immediately after import.

Persisting first and detonating second is a deliberate ordering. If anything downstream fails or gets blocked, the foothold is already planted and fires again at next logon.

The "Photo Studio" masquerade is itself a provenance marker rather than an operator invention, and it recurs identically across three independently obfuscated loader families in the vendor sample set that documents this toolkit.

### 8.3 The Paralell injector

The first assembly is `Crystal-Monk.dll`, 95,744 bytes, in-memory SHA-256 `e924acdb4aea72bdf1db5ab121a2bcbfddd33fd2d3d8c8907441ce3a6dfef10b`. It is a reflective injector, carrying `InjectIntoTarget` and `GetDelegateForFunctionPointer` alongside obfuscated member names `VoidNexus`, `ShadowWeave`, `CrystalCore` and `UmbraGate`, and it injects into `MSBuild.exe`.

Its RSDS debug directory carries a build path the developer never stripped, because this is a Debug build:

```
C:\Users\PC\source\repos\Paralell\Paralell\bin\x64\Debug\CryptoObfuscator_Output\Crystal-Monk.pdb
```

Three idiosyncratic fragments sit in that one path. The nested, misspelled `Paralell\Paralell` directory duplication. The `CryptoObfuscator_Output` folder, from a commercial .NET protector. And a developer account named `PC`. A publicly documented sibling build carries `...\JC-46\JC-46\Paralell\Paralell\...\Paralell.pdb`, which is the same builder producing a different build.

This is a **sourced toolkit**, and the finding forced retracting an earlier call in this case that the loader was operator-built. The sophistication in the delivery chain is bought, not written. Section 11 handles what that does and does not license as an attribution claim, and the short version is that it identifies a shelf the operator shopped from rather than who they are.

The injection target choice is not arbitrary and the vendor documenting this toolkit says so explicitly, describing MSBuild as chosen because most endpoint-detection baselines whitelist it by default. That rationale is worth carrying to defenders independently of this campaign, because it applies wherever the toolkit is sold.

The encoding layer corroborates the same source. The toolkit is documented using a custom **base28** alphabet, being the 26 uppercase Latin letters plus lowercase `a` and `b`, chosen so the output reads as random capitalized text rather than carrying the recognizable padding and alphabet of base64. The alphabet recovered from this sample matches exactly.

One honest point of difference. The documented toolkit describes AES-256 in ECB and CBC modes plus a custom stream cipher built from an XOR accumulator and rotation tables. This sample's stack is described here as including a ChaCha-style component, which is architecturally the same category of hand-rolled construction but is not a byte-for-byte published match. The fingerprint is strong on structure, naming and encoding, and unverified down to the cipher implementation itself.

### 8.4 The payload

The second assembly is `SvchostPayload`, 54,272 bytes, in-memory SHA-256 `7a5c5d1e41d5e2c8c0f09d5dccb78932de535963d21350b2581716c8a753fd66`, internal name `svhost.exe`. It is lightly obfuscated, and its cleartext type names make the capability set **DEFINITE** rather than inferred.

Browser credential theft runs through `BrowserCredentialRecovery`, handling Chromium stores via DPAPI `CryptUnprotectData` and Firefox via the NSS `TSECItem` interface. Keylogging runs through a `LowLevelKeyboardProc` hook with a `KL:OK:` response protocol. Defender tampering calls `DisableRealtimeMonitoring`. Persistence writes an `HKCU\...\CurrentVersion\Svc_<name>` value and holds a `Global\<name>_Mutex`. A USB routine drops an `autorun.inf` with `open=svchost.exe`.

A `#XLOADER` comment appears on the PowerShell stage. That is the operator's or the crypter's label, **not the Formbook/XLoader family**, and reporting it as XLoader would be wrong. It is exactly the kind of string that gets a sample mis-bucketed by a hurried triage.

A sibling build, `cls.exe` (`79b6f2eb6583a83aabe590264de08c0ad1eb7e960ae9a4bdbc6ed84142ce95a9`, flagged by Microsoft as `Trojan:MSIL/Zilla` at 47 of 70 engines), confirms the family is live and extends the capability set with a hidden desktop (`hiddenDesktop`) and microphone capture (`mic_record`). It beacons to `2.27.248.138:4443` and shares the `Svc_<name>` and `<name>_Mutex` builder conventions, which establishes one builder across both. It surfaced through the C2 rather than independently, so it corroborates that infrastructure without being a separate discovery of it.

### 8.5 The chain at runtime

`wscript.exe` starts the JScript. It creates the `PhotoStudioJS` scheduled task from the temporary XML and drops the "Photo Studio" masquerade copy. A hidden `powershell.exe` reads an encrypted blob from `%TEMP%\log_<digits>_<digits>`. That stage injects into `MSBuild.exe` **with no project file argument**, and `SvchostPayload` runs inside MSBuild from there.

From inside MSBuild come three observable actions. A Defender tamper, running `Set-MpPreference -DisableRealtimeMonitoring -DisableIOAVProtection -DisableBehaviorMonitoring $true`. A second persistence, `schtasks /create /tn "WindowsUpdateService" /tr "...\svchost.exe" /sc onlogon /delay 0000:30 /rl highest`. And an outbound beacon to `2.27.248.138:4443`. There is no C2 domain anywhere in this toolchain, only the raw address.

The loader then cleans up after itself, deleting both the task XML and the staged payload blob once they have been consumed.

`MSBuild.exe` opening a network connection, spawning a `schtasks` child, or spawning a `Set-MpPreference` child is close to zero false positive in a normal estate. It is also the single hardest thing in this case to catch, because by the time MSBuild does any of it, nothing malicious has been written to disk at any point in the chain.

One tempting cross-toolchain link does not exist, and it is worth stating plainly because building on it would produce a broken rule. This chain persists through a scheduled task, and it is natural to look for the same template in CloudSync and to believe you have found a shared idiom tying the two toolchains together. **There is no such template.** Across all 22 staged files, `schtasks`, `onlogon` and `delay 0000` return **zero matches in any CloudSync binary**. CloudSync persists through Run keys and a service, and nothing else. The only defensible observation spanning both toolchains is that each masquerades as Windows Update, which a great many unrelated families also do.

</details>

---

## 9. The Orchestrator, the Stub, and the Parked Stealer

Three smaller files complete the kit, and one of them is the most important artifact in the case.

`ab.exe` is the post-compromise deployment orchestrator, and it is the strongest candidate for operator-authored work anywhere in the toolkit. It runs three deployments in a fixed order, planting an ASPX web shell in the IIS content tree, then creating a hidden forest-level Active Directory backdoor account, then installing AnyDesk with an operator-set unattended password. It narrates its own plan in English console banners as it goes, and it continues past any stage that fails rather than aborting.

That failure tolerance is a design decision and it tells you something. An operator who builds a deployment tool that shrugs off a missing IIS root or an absent domain and presses on to the next stage is an operator who expects to run it against environments they have not fully mapped, and who does not want a partial one to cost them the whole deployment.

`ab.exe` is also where the victim identification came from. Its `New-ADUser` command hardcodes the target's Active Directory domain, and no shelf product ships localized for one specific victim's forest. That is what makes it provably the operator's own work rather than something they acquired.

`ct.bat` is the infection stub, 1,488 bytes, and it does six things in sequence: a proxy-aware download of the CloudSync dropper, an AMSI bypass, launch, a Run-key persistence, a USB enumeration loop, and an infinite re-download cycle. Its important property is that **it self-gates**, and that changes how you hunt it, which the teardown covers.

`v.exe` is the SentinelStealer build the operator collected and never wired in. Section 6 covers why it is not part of this operation. What matters technically is its capability profile, and specifically the one thing it does not have.

There is no ransomware in this kit. `v.exe` is a credential-recovery and cryptocurrency-wallet stealer with an injection capability, and I hold "no file-encryption capability" at near-DEFINITE on positive evidence rather than on a failure to find any. That determination got it wrong twice before it settled, which is why the teardown shows the working rather than asserting the result.

<details markdown="1" class="hl-teardown">
<summary>Full teardown: the AD backdoor command, the AnyDesk stage, ct.bat's self-gating control flow, and the no-locker determination</summary>

### 9.1 `ab.exe` stage by stage

The tool is 974,336 bytes, PE64, compiled 2026-03-29 on GCC 15.2.0 with mingw-w64 v13.0.0. Its own console strings lay out the sequence, and it prints them as it runs: `[+] Starting deployment - WebShell First`, then `=== WEB SHELL ===`, then `=== USER ===`, then `=== ANYDESK ===`, closing with `[+] All tasks completed successfully!`. Those banners are distinctive enough to serve as a rule anchor in their own right.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/cloudsync-assembler-toolkit-91-197-98-188/cloudsync-abexe-deployment-chain.svg" | relative_url }}" alt="A three-stage vertical chain infographic titled 'The Deployment Orchestrator', showing a consolidate-access tool built for one target and run after entry. Stage 1, a red card headed 'Web shell first', shows a sourced ASPX shell written into the IIS web root at inetpub wwwroot aspnet_client as a.aspx alongside a log.txt, identified as Sharp4WebCmd, a documented and openly available tool carrying a PowerShell runspace and file-upload form, and explicitly not operator-written; its detection hint is a file created in aspnet_client or the IIS worker process spawning PowerShell. Stage 2, a deep red card headed 'A directory account shaped like a machine', shows New-ADUser creating an account named Guest with a trailing dollar sign, with a defanged password and no expiry, added to Domain, Enterprise and Schema Admins and then hidden from the sign-in screen, with German-localized group names in this build; its detection hint is a user object whose name ends in a dollar sign but which is not a computer. Stage 3, a deep red card headed 'Commercial remote access, installed quietly', shows AnyDesk fetched from the genuine vendor CDN and installed unattended, with a defanged password piped over stdin so it never appears on a command line, and two observed install paths; its detection hint is the pipeline itself, a non-AnyDesk parent piping into AnyDesk. The footer notes the order is fixed and the tool is failure-tolerant, so a failed stage is logged and skipped and the run continues.">
  <figcaption><em>Figure 4: The failure tolerance is the part with operational consequence. Because a stage that fails is logged and skipped rather than aborting the run, a defender may find any single stage present without the other two, and finding none of them does not clear a host. Note also that only the middle stage is operator-written: the shell is a sourced tool and the remote-access product is commercial software fetched from its real vendor.</em></figcaption>
</figure>

#### The web shell stage

It writes to `C:\inetpub\wwwroot\aspnet_client\a.aspx`, alongside a `log.txt`. The shell is self-titled `Sharp4WebCmd Command Console`, a `System.Management.Automation` runspace shell with a file-upload pane. It is a **sourced** tool rather than operator-written, and Section 11 covers the actor that fact does and does not implicate. When this stage cannot complete, the tool prints `[!] Failed to create web shell` and moves on to the next stage anyway.

There is a trap on this stage worth naming, because it is easy to fall into and I nearly did. When the shell is caught in memory, what surfaces first is its directive header, and a header alone looks like a fresh discovery. It is not. The body is `Sharp4WebCmd`, a documented and openly available tool, and recognising it changes what the observation is worth: not a new web shell, but confirmation that `ab.exe` deploys a sourced one. That is a smaller claim, and the smaller claim is the true one.

#### The account stage

This is the one that identified the victim. The command, published here with the user principal name substituted, is:

```powershell
$password = ConvertTo-SecureString 'Admin@20...9n@@' -AsPlainText -Force; New-ADUser -Name 'Guest$' -SamAccountName 'Guest$' -UserPrincipalName 'Guest$@<victim-ad-domain>' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -ErrorAction SilentlyContinue; Write-Host 'User created'
```

In the original, `<victim-ad-domain>` is the hardcoded Active Directory domain of a specific German organization. The password is defanged. Everything else is verbatim.

Read what is in that one line. The account name ends in `$`, so most directory audits and most human reviewers read it as a machine account rather than a user. The password never expires and cannot be forced to change at logon. Errors are silenced, so the tool leaves no failure noise behind. The account is then escalated into **Domain Admins, Enterprise Admins, Schema Admins and local Administrators**, using the German-localized group names `Domänen-Admins`, `Organisations-Admins`, `Schema-Admins` and `Administratoren`, and hidden from the logon screen through a Winlogon `SpecialAccounts\UserList` registry write.

The same playbook appears at local scope inside the CloudSync implants, which print `Creating Hidden Admin User` and run `net localgroup Administrators` with the identical Winlogon write. One technique, executed consistently at two different scopes, is a signature rather than a coincidence.

#### The AnyDesk stage

It fetches the installer from the legitimate vendor CDN at `download.anydesk.com`, installs silently with `--install C:\ProgramData\AnyDesk --start-with-win --silent`, sets the unattended password **over stdin** with `echo <token> | AnyDesk.exe --set-password` so it never appears on AnyDesk's command line, and reads the assigned ID back with `--get-id`. Note the install path, because the CloudSync implants install to `C:\Program Files\AnyDesk` instead. A path-based hunt has to cover both.

The AnyDesk download from the real vendor CDN is a **sequence** signal, not an infrastructure one. The domain is legitimate and heavily used. What is anomalous is a non-AnyDesk binary fetching it and then piping a password into it.

### 9.2 The contrast that reframes the operator's OPSEC

There is an obvious tension in this tool. The account masquerade is careful, deliberate tradecraft. The same binary carries two plaintext passwords and the victim's own domain name, and it sat in an open directory reachable by anyone for over three months.

I do not read that as incompetence, and I think reading it that way is the mistake. The operator clearly has the knowledge and the tradecraft to hide an account properly, so the failure to hide the infrastructure is not a knowledge gap. It is that they do not care to, because not many people are looking at open directories like this one. The evidence supports the calculation rather than undercutting it. Three months open, still live, still unflagged by every feed checked. They are not failing to hide, they are correctly judging that nobody is looking.

Hiding an artifact and hiding infrastructure are separate skills with separate incentives, and this operator invested in the first only. For a defender that is useful rather than merely interesting, because the `Guest$`-style machine-account masquerade is the durable detection here precisely because it is the part they did care about.

### 9.3 `ct.bat`, and why the self-gating matters

Six stages run in order.

1. The script downloads `client.exe` from `http://91.197.98.188:8000/client.exe` with a proxy-aware PowerShell `WebClient` call, inheriting the logged-in user's `DefaultWebProxy` and `DefaultCredentials` and spoofing a browser User-Agent, so delivery works from inside an authenticated enterprise proxy.
2. It drops the file into the user's Startup folder under a `~<RANDOM>.exe` name.
3. It runs an obfuscated AMSI bypass that flips the `amsiInitFailed` field on a string-reversed `AmsiUtils` reference, blinding in-process script scanning.
4. It launches the dropped file with `start "" /B`.
5. It writes an `HKCU\...\Run\SystemUpdate` value pointing at the dropped file.
6. It loops indefinitely, running `wmic logicaldisk where "DriveType=2"` to enumerate removable drives, dropping a `sysupd.exe` and an `autorun.inf` onto any it finds, sleeping 20 seconds, and re-downloading each cycle.

Everything after the download sits behind a single gate, `if not exist "%t%" exit /b`. If the payload cannot be fetched and saved, the AMSI bypass never runs, the Run key is never written, the Startup drop never happens, and the USB routine never fires. The sample leaves almost no trace at all.

That is a significant hunting problem and it changes where the anchor has to go. Every loud indicator in this stub is **conditional**, existing only on hosts where delivery actually succeeded. The one thing that always fires is the download attempt itself, meaning the `cmd.exe` to `powershell.exe` chain running a `Net.WebClient` with `Proxy.Credentials = DefaultCredentials` and a spoofed browser User-Agent pointed at the staging host. That is where the rule belongs.

It also says something about the operator's posture. Self-gating trades spread for stealth. It only persists where delivery worked, and it stays quiet everywhere else. That is a targeting posture rather than an opportunistic one, and it fits the rest of the picture, which is an actor who is calculated and persistent rather than one spraying commodity malware at a million hosts and working whichever one lands.

The USB routine, by contrast, I read as a bolt-on. It looks thrown in to see whether it worked, a nice bit of extra spread if it happened to land, rather than something the operation depends on. The alternative reading is that they know some of their targets move files on removable media and aimed it at that. Either way it feels added on the fly rather than designed in, and the wider chain around it is not new or complex, it is fairly standard now.

### 9.4 SentinelStealer's capability profile, and the locker question

`v.exe` is 772,096 bytes, .NET, protected with ConfuserEx2 declaring `Confuser.Core 1.6.0+447341964f`. It names itself `SentinelStealer` in its version resource and forges its compilation timestamp to the year 2075.

A note on the protector, because this case got it wrong first. A scanner labelled it as a 2013-era Confuser lineage, and an entire "old tool, new capability" line of reasoning got built on that. The assembly's own metadata declares a current ConfuserEx2 build, as Figure 2 shows. A scanner's family label is not a version, and the artifact's self-declaration should have been read first.

ConfuserEx2 encrypts string literals but cannot rename external framework member references, which is why the API surface reads reliably even though the string constants do not. What that surface shows is **Chrome App-Bound Encryption key unwrapping** (`Google Chromekey1` alongside `NCryptOpenStorageProvider`, `NCryptOpenKey` and `NCryptDecrypt`), DPAPI credential decryption, a file grabber matching `*seed*`, `*.dat`, `*.mafile` and `*.txt` with a 5 MB per-file cap at depth 2, plus injection primitives and reflective assembly loading.

The Chrome App-Bound Encryption targeting sets a floor on the build. That capability cannot predate Chrome v127, released July 2024, and keeping it working requires active maintenance.

#### The locker determination

A file encryptor requires a specific set of primitives, and `v.exe` declares none of them. There is no `CreateEncryptor`, no `RmShutdown` or `RmRestart`, no `GenerateKey` or `GenerateIV`, no RSA key-wrap surface, and no bulk write-back path. Their decryption counterparts are all present. Its Restart Manager usage runs `RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmEndSession` and stops there, which **discovers** which process holds a file open without ever closing it. That is the stealer pattern for reaching a browser credential store the browser has open, not the locker pattern for releasing locks before encryption. A full memory sweep returned zero for `vssadmin`, `.locked` and `ransom`, and the `bcdedit`, shadow-copy, ChaCha and Rijndael string hits are all .NET framework strings.

This sample should not be mapped to **T1486** in any form, and it is worth being blunt about why, because the misreading is an inviting one. The Restart Manager API sequence here looks like the pattern lockers use to release file handles before encrypting, and reading it that way produces a confident ransomware call. It is wrong. What the sequence actually does is unlock browser credential stores the browser is holding open, which is ordinary stealer behaviour. A detection rule built on it would fire on that behaviour routinely and, worse, would train whoever triages the alert to read a stealer as a locker precursor.

Its configuration completes the picture. The `BotToken` and `ChatID` fields are declared and **never referenced by any code in the assembly**, so the exfiltration credentials were never wired up. They are unused builder defaults rather than working Telegram credentials. The grabber targets are live, but they hunt wallet seeds and Steam authenticator secrets, which is commodity crimeware targeting with no relationship to a healthcare intrusion.

<figure style="text-align: center; margin: 2em 0;">
  <img loading="lazy" src="{{ "/assets/images/cloudsync-assembler-toolkit-91-197-98-188/sentinelstealer-recovered-config.png" | relative_url }}" alt="The recovered SentinelStealer.Config.Settings class, showing a FilePatterns list containing the wildcards star-dot-txt, star-seed-star, star-dot-dat and star-dot-mafile, a GrabberFileSize of 5, a GrabberDepth of 2, and two 64-character hexadecimal string fields named BotToken and ChatID whose middle sections are truncated for publication.">
  <figcaption><em>Figure 5: The stealer's configuration class, recovered intact because the protector left it unrenamed for JSON serialization. <code>FilePatterns</code> is the load-bearing detail: it hunts wallet seed phrases and Steam authenticator files (<code>*.mafile</code>), which is commodity crimeware targeting and bears no relationship to an intrusion against a healthcare provider. The <code>BotToken</code> and <code>ChatID</code> fields below it are declared and never referenced by any code in the assembly, making them dead builder defaults rather than live exfiltration credentials. Both values are truncated here for publication.</em></figcaption>
</figure>

On the network side it queries `http://ip-api.com/json/` over plain HTTP with **no User-Agent header**, which is a .NET `WebClient` default, then resolves `c3lestial.fun` and opens TLS to port 443 presenting that hostname in SNI. The endpoint `https://c3lestial.fun/receive.php` was recovered from process memory, but **no HTTP method was ever observed**, so no method-bound rule was written against it and I do not say the stealer "exfiltrates to" that path.

</details>

---

## 10. MITRE ATT&CK Mapping

Coverage spans 12 of the 14 enterprise tactics, which is what a complete intrusion kit rather than a single family looks like. Reconnaissance and Resource Development are absent because both describe operator activity that is not visible from the staged files.

Two things about this mapping are worth reading before the table. **No Impact / T1486 is mapped**, because the toolkit carries no file-encryption capability anywhere, for the reasons set out in Section 9.4. And the mapping covers the sourced components as the operator deploys them rather than only the operator-authored code, because in an assembled kit the deployment is the operator's contribution and the sourced tool is just the mechanism.

The techniques that carry the most detection value are concentrated in Defense Evasion and Persistence, which follows directly from where the operator put their effort. T1127.001 (MSBuild as a trusted developer utility), T1620 (reflective code loading), T1564.002 (hidden users) and T1136.002 (domain account creation) are the four that a defender should treat as the spine of any hunt built from this report.

<details markdown="1" class="hl-teardown">
<summary>Full ATT&CK table: 54 technique mappings across 12 tactics, with per-row evidence</summary>

> **Confidence note:** all rows below are HIGH confidence unless explicitly marked `(MODERATE)` or `(DEFINITE)`. The Confidence Summary in Section 14 organizes the load-bearing findings by level.

| Tactic / Technique | Name | Evidence |
|---|---|---|
| Initial Access / T1091 | Replication Through Removable Media | `ct.bat` + `SvchostPayload` drop `autorun.inf`, `open=svchost.exe` |
| Execution / T1059.007 | JavaScript | `svhost.js` WSH JScript loader |
| Execution / T1059.001 | PowerShell | fileless `powershell ... iex`; `ct.bat`; panel `/api/ps1` |
| Execution / T1059.003 | Windows Command Shell | panel `/api/cmd`; `cmd /C net share`; `ct.bat` |
| Execution / T1059.005 | Visual Basic | `PhotoStudio.vbs` windowless relaunch |
| Execution / T1053.005 | Scheduled Task | `PhotoStudioJS`, `WindowsUpdateService` |
| Execution / T1106 | Native API | panel `/api/exec`, `/api/runfile`; reflective inject |
| Execution / T1047 | Windows Management Instrumentation | `ct.bat` `wmic logicaldisk`; `v.exe` WMI |
| Persistence / T1547.001 | Registry Run Keys / Startup Folder | `Run\WUS`; `Run\SystemUpdate` to Startup `~<RANDOM>.exe` |
| Persistence / T1543.003 | Windows Service | `WinUpdateService`, display "Windows Update Service" |
| Persistence / T1136.002 | Create Account: Domain Account | `New-ADUser 'Guest$'` (targeting DEFINITE, achieved MODERATE) |
| Persistence / T1136.001 | Create Account: Local Account | implant `Creating Hidden Admin User` + `net localgroup` |
| Persistence / T1505.003 | Web Shell | `Sharp4WebCmd` ASPX to `aspnet_client\a.aspx` |
| Persistence / T1098 | Account Manipulation | `Guest$` into Domänen-/Organisations-/Schema-Admins |
| Persistence / T1133 | External Remote Services | AnyDesk `--start-with-win`, unattended password |
| Persistence / T1219 | Remote Access Software | AnyDesk deployed; RustDesk, Radmin VPN staged |
| Priv. Escalation / T1078.002 | Valid Accounts: Domain Accounts | forest-level `Guest$` backdoor for privileged reuse |
| Priv. Escalation / T1134 | Access Token Manipulation | `svhost4` `SeDebugPrivilege`; `v.exe` `AdjustTokenPrivileges` |
| Priv. Escalation / T1068 | Exploitation for Privilege Escalation | `PrintSpoofer` SeImpersonate LPE (sourced) |
| Defense Evasion / T1055 | Process Injection | `Crystal-Monk` into `MSBuild.exe` (also Priv. Esc) |
| Defense Evasion / T1127.001 | Trusted Developer Utilities: MSBuild | signed `MSBuild.exe` target, no project file |
| Defense Evasion / T1620 | Reflective Code Loading | in-memory .NET assembly load of both stages |
| Defense Evasion / T1140 | Deobfuscate/Decode Files | base16 to base28 to AES layered decode |
| Defense Evasion / T1027 | Obfuscated Files or Information | custom JScript crypto; Crypto Obfuscator; ConfuserEx2 |
| Defense Evasion / T1562.001 | Impair Defenses: Disable or Modify Tools | `Set-MpPreference -DisableRealtimeMonitoring`; AMSI patch |
| Defense Evasion / T1036.005 | Match Legitimate Name or Location | `Guest$`; `taskhostw.exe` is Tor; `svchost`/`svhost` |
| Defense Evasion / T1564.002 | Hidden Users | Winlogon `SpecialAccounts\UserList` write (DEFINITE) |
| Defense Evasion / T1112 | Modify Registry | Defender exclusion keys; `UserList` hide |
| Defense Evasion / T1070 | Indicator Removal | loader deletes task XML + `%TEMP%\log_*` blob |
| Defense Evasion / T1497 | Virtualization/Sandbox Evasion | `v.exe`/`cls` anti-debug, long sleeps (MODERATE) |
| Credential Access / T1555.003 | Credentials from Web Browsers | DPAPI + NSS; Chrome ABE unwrap in `v.exe` |
| Credential Access / T1056.001 | Keylogging | `LowLevelKeyboardProc`, `KL:OK:` protocol |
| Credential Access / T1110 | Brute Force | NetExec credential spraying (sourced) |
| Credential Access / T1539 | Steal Web Session Cookie | `cookies.sqlite`; Telegram `tdata` (MODERATE) |
| Discovery / T1046 | Network Service Discovery | panel `/api/netscan` CIDR + port scanner |
| Discovery / T1135 | Network Share Discovery | `net share`, `[Shares]` heartbeat block |
| Discovery / T1049 | System Network Connections Discovery | panel `/api/net` |
| Discovery / T1057 | Process Discovery | panel `/api/ps` |
| Discovery / T1082 | System Information Discovery | panel `/api/info`; host/user/disk recon |
| Discovery / T1614 | System Location Discovery | `v.exe` `ip-api.com/json/` geolocation |
| Lateral Movement / T1021.002 | SMB/Windows Admin Shares | PsExec renamed `exec.exe`, ADMIN$ copy plus service |
| Lateral Movement / T1570 | Lateral Tool Transfer | PsExec; panel `/api/dl` |
| Collection / T1113 | Screen Capture | `CopyFromScreen` to `.jpg`; `SvchostPayload` |
| Collection / T1123 | Audio Capture | `cls` `mic_record` (MODERATE) |
| Collection / T1005 | Data from Local System | `v.exe` grabber: `*seed*`, `*.dat`, `*.mafile` |
| Command and Control / T1071 | Application Layer Protocol | CloudSync cleartext TCP; .NET RAT raw-IP TCP |
| Command and Control / T1090.003 | Multi-hop Proxy | per-victim Tor hidden service, statically linked Tor |
| Command and Control / T1571 | Non-Standard Port | `:5555`, `:7777`, `:4443`, `:5000-5003` |
| Command and Control / T1105 | Ingress Tool Transfer | panel `/api/dl`; `ct.bat` `WebClient`; AnyDesk fetch |
| Command and Control / T1102 | Web Service | `api.telegram.org` first-run notify |
| Command and Control / T1090 | Proxy | `ct.bat` `DefaultWebProxy` + `DefaultCredentials` |
| Command and Control / T1572 | Protocol Tunneling | chisel, bore, ssh (sourced) |
| Exfiltration / T1041 | Exfiltration Over C2 Channel | panel file-manager download; .NET RAT (MODERATE) |
| Impact / T1489 | Service Stop | panel `/api/kill` process termination (MODERATE) |

</details>

---

## 11. Threat Actor Assessment

> **Note on UTA identifiers:** "UTA" stands for Unattributed Threat Actor. UTA-[YEAR]-[###] is an internal tracking designation assigned by The Hunters Ledger to actors observed across analysis who cannot yet be linked to a publicly named threat group. This label will not appear in external threat intelligence feeds or vendor reports, it is specific to this publication. If future evidence links this activity to a known named actor, the designation will be retired and updated accordingly.

I cannot name this operator, and I want to be clear that this is a conclusion rather than a shortfall.

> This operator's kit contains tooling publicly tied to three separate named threat actors, and the operator is none of them. That is not a failure to attribute, it is what attribution looks like when the subject is an assembler. Each tool match is a receipt from a different supplier, and a receipt tells you where somebody shopped, not who they are.

### 11.1 The three threads, in one frame

| Component | Named actor it is publicly tied to | Source | What the tie actually is | Is that actor the operator? |
|---|---|---|---|---|
| The `Crystal-Monk` / Paralell .NET injector | Blind Eagle / APT-C-36 | LevelBlue SpiderLabs, 2026-07-17 (Tier 2) | A build-artifact fingerprint in a shared loader family | **No.** Separated on infrastructure, victimology and malware stable. |
| CloudSync's hardcoded Telegram notify id `8116056430` | GDLockerSec | KELA Cyber, 2025-01-27 (Tier 2) | A numeric chat id compiled into the builder's notification routine | **No.** Separated on victimology, sector, sophistication and product. |
| The `Sharp4WebCmd` ASPX web shell | Larva-26009 | AhnLab ASEC, 2026-07-25 (Tier 2) | A self-titled, circulating web shell used in a separately attributed campaign | **No.** Separated on entry vector, objective and every other tool. |

Three components. Three unrelated named actors. Three separate Tier-2 vendors. Zero shared infrastructure between any of them and this operator, and zero shared infrastructure between any two of them.

### 11.2 Why three matches settle what one could not

A single tool match is genuinely ambiguous. If this case had turned up only the Paralell loader, "the operator is Blind Eagle" would have been a hypothesis worth taking seriously, and refuting it would have depended on softer secondary evidence like a targeting mismatch.

Three simultaneous matches are not ambiguous, because **the three named actors are mutually exclusive as operators.** Blind Eagle is a Latin American espionage-flavoured group running commodity RATs. GDLockerSec is a small Telegram-based leak-site extortion brand. Larva-26009 is an MS-SQL-entry cryptomining operation. No coherent single actor is all three.

So at most one of the three matches could ever have been an identity claim, and the other two would have to be provenance. Once you accept that two of them must be provenance, there is no principled basis left for treating the third differently, and every tool match leaves the identity column at the same moment. The parsimonious reading, and the only one that survives, is that all three are provenance and the operator is a fourth party who obtained tooling from all three ecosystems.

That argument does not depend on any of the per-actor separating evidence below. The separating evidence is corroboration stacked on top of a structural argument that already stands.

This is the reader takeaway I would keep if you kept nothing else from this report. Attributing on tool matches misleads, and this case demonstrates it three times over in a single kit. When you find a named actor's tool in a sample, what you have learned is where somebody shopped.

### 11.3 The identity artifacts belong to the kit authors

Two of the artifacts in this kit look exactly like operator selectors and are not.

The Telegram chat id is compiled into the CloudSync builder's notification routine rather than configured per victim, so it travels with the builder to whoever obtains it. The PDB path is baked into the Paralell injector's Debug build by the toolkit author's own compiler, and no operator-authored binary in this kit references it. Neither identifies the person who staged this operation, and treating either as though it did is the central error this case exists to demonstrate.

The only identity-adjacent artifact that is unambiguously the operator's own is the German localization in `ab.exe`, and that points at a victim rather than at an actor.

### 11.4 Each thread, assessed twice

#### Blind Eagle and the Paralell loader

The loader highly likely belongs to the same builder toolkit family as the sample LevelBlue published, and I hold that at **HIGH, around 88 percent**. It rests on one distinctive fingerprint with corroboration, and I want that count stated correctly because this case previously inflated it. The fingerprint is the nested, misspelled `Paralell\Paralell` build path. The corroboration is the exact base28 alphabet and the "Photo Studio" installer naming, and of those only the installer naming is genuinely separable, because the alphabet ships inside the same injector project as the path. This is **one distinctive fingerprint plus corroboration**, never three or five independent points, and the HIGH survives on the path alone.

The second step in that chain is weaker and has to be stated separately. Saying the Paralell family is Blind Eagle's rests on **LevelBlue alone**, and I checked whether anyone else labels their own published sample. Forty-two engines flag it with entirely generic names, no vendor family-labels it, and VirusTotal records no threat-actor association at all. So I hold "this build belongs to the Paralell family" at HIGH and "the Paralell family is Blind Eagle's" at **MODERATE**, and any chained statement is bounded by the weaker of the two.

Blind Eagle is not the operator, and I hold that separation at **HIGH as a negative finding**, which puts them at ten percent or below. The strongest item is a direct overlap test rather than an inherited claim. Hunt.io's published APT-C-36 IP IOC corpus runs to 97 rows spanning October 2024 to July 2026 and includes the four addresses from the very article that supplies the toolkit attribution. **None of this operator's three IPs appears in it**, with no shared ASN and no shared hosting company. Beyond that, two independently maintained catalogues record Blind Eagle's victimology as Latin-America-exclusive with no Germany and no healthcare, and both record its malware stable as entirely commodity RATs against a bespoke .NET RAT here. The vendor supplying the attribution describes the toolkit itself as an external builder-as-a-service.

One caution on the naming. Blind Eagle, APT-C-36, TAG-144, Blind Spider, AguilaCiega, APT-Q-98 and Prospero are **one actor under seven names**. Seeing several of those in search results is not independent corroboration.

#### GDLockerSec and the Telegram id

The chat id `8116056430` maps to the @GDLockerSec persona, and I hold that mapping at **MODERATE, around 75 to 80 percent**. It sits there because KELA is the only source that publishes it, every repetition traces back to that one article, and the tracker that profiles the group most fully does not publish the numeric id at all. Hunt.io holds no record for the name in any form, checked three separate times. The mapping is worth having, because numeric ids are the stable key while handles migrate between accounts, and it is still one vendor.

That find is a good one and it is worth naming why. It links an otherwise undocumented toolkit to a known group doing this exact kind of operation, and it is the sort of connection that is genuinely hard to make alone. It only exists because somebody else published the id-to-handle chain, which is the whole intelligence community working the way it should. The right way to carry it is to cite KELA rather than launder their work into our own claim.

GDLockerSec is not the operator either, and I hold that separation at **HIGH as a negative finding**, which puts them at ten percent or below. The claim fails mechanically before any separating evidence is reached, because the id is compiled into the builder rather than configured per victim. On top of that sit a victimology with no German entity and no healthcare organization anywhere on it, a stated policy excluding non-profit hospitals, a kit with no locker capability at all against an extortion brand, and a characterization from KELA themselves describing the group as amateur with poor operational security, which sits awkwardly against custom multi-primitive crypto engineered to defeat detection.

Those victimology facts used to be carried in this case as unresolved frictions needing explanation. They are not frictions. That is **GDLockerSec's own victimology**, and this is not GDLockerSec's campaign, so a group's target selection and rules of engagement were never in conflict with anything observed here. They are two more items of separating evidence, and they make a clean worked example of the cost of the mistake, because an analyst who read the Telegram id as an identity would have burned real effort reconciling a German care provider against a victim list with no German entity on it.

#### Larva-26009 and the Sharp4WebCmd shell

This one has to be stated explicitly, because a reader who finds AhnLab's Sharp4WebCmd reporting will find a named actor attached to it and will otherwise infer a connection to this campaign. There is none. **Larva-26009 has no connection to this operator beyond both having obtained a copy of the same circulating web shell**, and I hold that non-link at **HIGH, around 90 percent**.

The divergence is total apart from that one shell. Larva-26009 enters through poorly managed MS-SQL servers and deploys XMRig cryptocurrency mining, escalating in some cases to VShell, GotoHTTP and SoftEther VPN. This operator enters through an internet-facing server on a healthcare provider's perimeter and builds forest-level Active Directory persistence with unattended remote desktop. Entry vector, objective, follow-on tooling, second web shell, sector and infrastructure all differ. AhnLab's own phrasing describes the shell as sitting on a download server, which reads as a circulating utility rather than an exclusive development. Finding a commodity tool in two campaigns is **evidence the tool circulates, nothing more**.

### 11.5 What the operator actually is

The characterization I can support is that this is an **assembler**, an actor whose tradecraft is composition rather than authorship, and I hold that at **HIGH, around 85 percent**.

It rests on directly observed artifacts rather than on anyone's assertion. Three named-actor components sit alongside six further public offensive-tooling ecosystems and three commercial remote-desktop products in one kit, and a commodity stealer was collected and parked without ever being integrated, sharing no constant with anything else and beaconing to its own unrelated infrastructure. Against fourteen sourced and commodity binaries in a twenty-two-file kit, the honest list of candidates for the operator's own work runs to three items.

What holds it below DEFINITE is that CloudSync's own authorship is unresolved, covered in 11.7. The characterization survives either answer, because the loader, the web shell, the stealer, the tunnelling tools, the AD tooling and the remote-desktop products are provably somebody else's under any reading. That is why this sits at HIGH while the authorship question sits at MODERATE.

The sourcing is also **cross-ecosystem**, which sharpens the read rather than pointing anywhere. A Chinese .NET web shell, a Latin-America-associated loader toolkit, Western commercial remote-management software and a commodity stealer, all in one kit. No single ecosystem accounts for it, and tool availability is not authorship. A Chinese web shell no more makes this operator Chinese than the Blind Eagle toolkit made them APT-C-36, and that is the third instance of the same rule in this one case.

### 11.6 The operator's own signature, which is what a future sighting matches against

Declining to name an actor is not the same as having nothing to say about one. Five characteristics support the designation, four of them technical or infrastructure, and the first four hold regardless of how the authorship question resolves.

- A per-victim Tor hidden service hosting a browser-accessible RAT panel, with the `.onion` reported back as a named C2 registration field. Undocumented publicly under any name, and no actor in either the Hunt.io or MITRE catalogues runs this architecture.
- A three-IP attacker-controlled estate, function-split across two jurisdictions, config-linked into recovered builds so the link is direct rather than inferred. Multi-month, exclusive, no domain rotation, raw-IP C2 throughout.
- A forest-level Active Directory backdoor shaped as a machine account, with the Winlogon hide, executed at the same time at local scope inside the implants. A deliberate and uncommon masquerade, applied consistently at two scopes.
- The `ab.exe` orchestrator itself, German-localized to one victim's forest, printing operator-composed English console banners, with fixed stage ordering that continues past failures. Provably not a shelf component, because no builder ships localized for one specific victim's Active Directory.
- The assembly pattern itself, which is behavioral rather than technical but is repeatedly observed rather than inferred.

Underneath those sit the smaller reusable constants: the CloudSync imphashes, the build-variant terminators, the `C:\Users\Public\fs\` working directory with its oversized `taskhostw.exe`, the `Svc_<name>` registry and `<name>_Mutex` convention, and the `svchost` and `svhost` misspelling tic that recurs across both toolchains.

Cluster on those, not on the borrowed toolkits. Two named-actor threads on one open directory is itself the tell that you are looking at an assembler rather than at either group.

### 11.7 The one question I am leaving open

Whether this operator authored CloudSync or bought it as a builder is **unresolved at MODERATE**, and I am declining to resolve it rather than guessing. The supportable phrasing is a **shared builder-or-operator constant set**, wired into the CloudSync C2 protocol as named registration fields.

Two observations bear on it and neither settles it. The localization split, with an English-localized CloudSync family against a German-localized `ab.exe`, looks like a generic product plus a customer's own tooling, and it is equally what one competent operator produces writing a general-purpose RAT in English and a per-victim orchestrator in the target's locale. The AnyDesk password being constant across two CloudSync builds six weeks apart while differing only for `ab.exe` is a tool boundary rather than per-build variation, which cuts toward a builder default, and is still explicable as one operator setting a value once per codebase and never revisiting it.

Both tilt very slightly toward the sold-builder reading. Neither discriminates cleanly, so the label does not move.

I held that line against my own enthusiasm twice, and it is worth saying why. The CloudSync registration message transmitting the AD backdoor credentials as named protocol fields is a genuinely exciting finding, and it moves the **integration** question a long way, because it shows the two toolchains are one operational system by protocol design. It does not move the **single-operator** question at all, because a sold builder would ship the same fields and, if a buyer never changed the defaults, the same values. Letting an exciting finding upgrade an adjacent claim is how this case went wrong before.

The settling test exists and is currently blocked. A retrohunt on the shared AnyDesk password and the CloudSync imphash would resolve it, because constants appearing in samples outside this estate would prove a shared builder. I attempted it and the query returned zero. Before recording that as a negative I ran a control on an import hash carried by millions of .NET samples, and **that also returned zero**, which proves the query modifier is not entitled on the available key rather than proving anything about the operator. The zero result **carries no information** and must not be cited as a negative anywhere. A second, independent obstacle applies regardless, which is that none of these 22 files had ever been submitted to VirusTotal before this investigation, so even an entitled retrohunt may find the corpus simply lacks the operator's other builds.

### 11.8 What I can say about how they operate

The build lineage matures visibly across three generations, with plain descriptive names giving way to progressively abbreviated and masqueraded ones, and the feature set growing rather than churning. The dropper self-gates so it only persists where delivery actually worked. The deployment orchestrator is failure-tolerant by design. The Chrome App-Bound Encryption capability only functions if kept current. Both C2 estates were live at last check across a four-month-plus window.

My read is that they are skilled, have real tradecraft knowledge, and iterate, fix and continue their operations over time. They are determined, and they are not the kind of actor who picks up commodity malware, blasts it at as many victims as possible, works the one that lands and stops. This is somebody actively engaged and iterating, which points to a level of commitment and persistence that most actors out there simply do not display.

I want to be clear that the second half of that is a characterization by contrast rather than a measured fact. What the evidence carries hard is three builds with an evolving feature set and naming convention, a four-month-plus active window with both C2s live, and a capability that requires maintenance. The "not spray-and-pray" reading is my assessed view of their posture, well grounded in the iteration evidence, and it should be read as that.

For a defender the practical consequence is that this toolkit will keep changing. Any detection built on a single build's strings has a short shelf life, and the durable coverage is structural, meaning the C2 message framing, the persistence naming scheme, the runspace web shell and the account masquerade.

### 11.9 Motive stays open

The **access-broker** reading is the leading one and I hold it at **MODERATE, around 70 percent**. It follows from durable credentialed access, a built-in internal network scanner and a full lateral-movement toolkit, set against no observed exfiltration and no locker anywhere in the kit. Durable, mapped, credentialed access is a product in its own right.

Extortion remains a coherent alternative and is genuinely unevidenced. A small regional care provider handling patient data and personal information is a classic extortion profile, and healthcare has historically paid. But nothing in the recovered files encrypts anything, no ransom note exists, no leak-site listing names this victim, and no exfiltration was observed. I am not going to infer a motive from a victim's sector.

The honest caveat on both readings is the same bound stated in Section 7.2. The 22-file inventory is a snapshot rather than a demonstrated-complete enumeration, and one CloudSync panel port was live with no corresponding build in hand, so a monetization component this investigation never captured remains possible.

---

## 12. Indicators of Compromise

The validated, machine-readable feed is published separately at **[`cloudsync-assembler-toolkit-91-197-98-188-iocs.json`](/ioc-feeds/cloudsync-assembler-toolkit-91-197-98-188-iocs.json)**, marked TLP:CLEAR and formatted for direct ingestion. Network indicators in the feed are not defanged, because a defanged value breaks the parser that is supposed to consume it.

What is in it, by category:

- 11 staged binaries with on-disk SHA-256 hashes, spanning both CloudSync build generations, the orchestrator, the stub, the JScript loader and the parked stealer
- 3 in-memory reconstructions for the Paralell injector, the `SvchostPayload` RAT and its `cls.exe` sibling, which exist only inside a running process on a victim and must be hunted behaviorally rather than by disk hash
- 8 operator-estate network indicators, covering three attacker-controlled hosts and the specific ports each service runs on
- 2 commodity-stealer network indicators, in a deliberately separate tier
- 17 host-artifact classes, covering registry values, services, scheduled tasks, mutexes, working directories, the web shell path and the Active Directory backdoor shape
- 6 defanged operator credentials, carried as context rather than as blocking indicators

### Two tiers, and why the separation is load-bearing

The feed keeps the **operator estate** and the **sourced commodity-stealer service** in separate tiers so nothing reads them as one infrastructure. `c3lestial.fun` belongs to a stealer service that predates this campaign by six months and has more than twenty unrelated communicating files. Publishing it as campaign infrastructure would send defenders after the wrong operator.

It is still published, deliberately. My first instinct was to leave it out because it is not this operator's, and that instinct was wrong for the reason Section 6 sets out. Provenance labels, not exclusion. Keep operator-owned and sourced-component indicators in separate tiers and a reader can act on both without confusing them.

The same labelling applies to the sourced commodity binaries, which are carried as path-and-hash pairs with an explicit false-positive flag, because a bare hash for PsExec or a stock Tor build flags every legitimate copy in the estate.

### Perishability, and what to prioritise

The atomic indicators here have a short shelf life and the behavioral ones do not. Publishing this may trigger rotation, the operator is live, and the IP addresses and file hashes are the first things that will change. The durable value is in the tradecraft, meaning the `Guest$` account shape, the `aspnet_client` web shell path, the `wscript` to `powershell` to `MSBuild` chain, the CloudSync working directory, and the C2 message framing. Those survive a rebuild.

### Investigated and ruled out

These are published with their reasons because they save other researchers the same dead ends, and they are explicitly **not** indicators to block or alert on.

- `46.36.217.3`, with `stolotov.org` and `stolotov.net`. Swept in on a shared panel title, then severed on a detailed host view showing a different operating system, no SSH host-key overlap, and a simpler login page that never ran the real RAT panel. Suspicious infrastructure, but not demonstrably this operator's. LOW association.
- `65.20.90.34`. Reverse DNS shows a proxy and relay footprint unrelated to this operator, and the panel title differs from the tracked one. Probable false positive.
- The "CloudSync Dashboard" panel title itself is a commodity SaaS-admin template, not an operator fingerprint. A legitimate commercial web-development agency surfaced during this work purely because its portfolio site uses the same template, and it is not named here for exactly that reason. This is why title-based sweeps threw false positives throughout this case, and it is the single most useful negative finding for anyone trying to pivot on the panel.
- A shared JARM fingerprint carried as a candidate pivot. Closed as non-distinctive, with more than 50 unrelated IPs across unrelated ASNs sharing it inside a 30-day window.
- `CN=localhost` self-signed certificates appear on both this operator's and Blind Eagle's infrastructure. Different certificates, and the commonest default in existence. Not a link.
- Prior-tenant passive DNS on both dedicated C2 addresses, including domain-generation-algorithm and mail-spam residue. The providers recycle addresses and these records predate the operator.

Credentials are defanged throughout to first eight and last four characters, because a full value in a public report is a disclosure hazard rather than an indicator. The Telegram **chat id `8116056430` is published whole**, because it is the attribution artifact, it is already public, and it is a tracking key rather than a secret.

---

## 13. Detection and Response Guidance

The full rule set is published separately at **[`cloudsync-assembler-toolkit-91-197-98-188-detections.md`](/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/)**, organized by component rather than by campaign, because each component needs to attribute correctly for the rules to stay useful when the operator swaps one out. Coverage is **7 YARA rules, 18 Sigma rules and 4 Suricata signatures**, split into Detection tier for the high-fidelity alerting-grade rules and Hunting tier for the broader ones that expect analyst review.

### Where to start

Three chains carry most of the value, and none of them depends on an IP address or a file hash.

The MSBuild chain is the highest-fidelity signal in the case and the hardest thing here to catch. Look for `wscript.exe` spawning `powershell.exe` with hidden window and bypassed execution policy, spawning `MSBuild.exe` **with no project-file argument**, followed by MSBuild opening a network connection or spawning a child. Pair it with `Set-MpPreference -DisableRealtimeMonitoring` from MSBuild or PowerShell. In a normal estate that combination is close to zero false positive, and by the time it fires nothing malicious has been written to disk at any point.

The Active Directory account shape generalizes far beyond this operator. Query for a user object whose `sAMAccountName` ends in `$` while its `objectClass` is `user` rather than `computer`. Pair it with any file creation in `C:\inetpub\wwwroot\aspnet_client\`, and with `w3wp.exe` spawning `powershell.exe`. This is cheap to check, it is low noise, and it is the confirmation the victim in this case can run in minutes.

The CloudSync working directory is near-unmistakable. A roughly 10 MB `taskhostw.exe` under `C:\Users\Public\fs\` alongside `config.json`, `a.dat`, `b.log` and a `hidden_service\` directory, with a `%APPDATA%\tor\torrc` pointing back at it. Add a workstation speaking the Tor protocol outbound at all, which is a policy signal rather than a malware-specific one but is the right co-signal here.

Below those, the reliable anchors are the deployment banners in `ab.exe`, an AnyDesk password piped over stdin by a non-AnyDesk parent, the `ct.bat` proxy-aware download attempt, and the CloudSync C2 message framing shipped as an alternation over both terminators.

### What the rules deliberately do not cover

Four gaps are worth knowing about before you rely on this set.

Tor-wrapped panel traffic is opaque. Once the victim's hidden service is up and the operator works through the onion, the wire traffic is ordinary Tor cell traffic and no content signature reaches inside it. Coverage falls back entirely to host-based rules at that point.

The in-memory .NET stages have no file to hash. The YARA rule for that component is written for a memory-resident scan and will not fire on a standard filesystem sweep. The behavioral Sigma rules are the durable coverage there precisely because they never need the payload recovered.

ConfuserEx2 makes string anchors unreliable for the stealer, so no YARA rule ships for it and its coverage is the two network signatures only.

Several string-worthy identifiers were withheld rather than turned into weak rules. A configuration file the malware attempts but never successfully creates would produce a rule that fails to fire on genuinely infected hosts. An endpoint recovered from memory with no observed HTTP method would produce a method-bound rule that may never match real traffic. The 32-character C2 authentication key was excluded entirely, because the implant does not authenticate its peer and publishing that key in a plaintext signature would hand any reader command execution on a live infected host, with no detection benefit over the message framing already covered.

### Response orientation

Not a runbook. This is what to look at, for an organization that finds any of it.

#### Detection priorities, in order

- The `wscript` to `powershell` to `MSBuild`-with-no-project-file chain, plus Defender-setting tampering from either
- An Active Directory user object whose `sAMAccountName` ends in `$` but whose `objectClass` is `user`, and any file at all in `C:\inetpub\wwwroot\aspnet_client\`
- The CloudSync working directory under `C:\Users\Public\`, and any workstation speaking Tor outbound

#### Persistence targets to look for and remove, by name

- Active Directory account `Guest$`, and its membership in the Domain, Enterprise, Schema and local Administrators groups
- The Winlogon `SpecialAccounts\UserList` hidden-account entry
- Web shell `aspnet_client\a.aspx` and its `log.txt`
- Scheduled tasks `PhotoStudioJS` and `WindowsUpdateService`
- Service `WinUpdateService`, and Run values `WUS`, `WinUpdateSvc` and `SystemUpdate`
- Registry `Svc_<name>` values and any Defender exclusion keys
- Unattended AnyDesk installs, in both `C:\Program Files\AnyDesk` and `C:\ProgramData\AnyDesk`
- The `%LOCALAPPDATA%\Photo Studio\` drop and the `C:\Users\Public\fs\` directory

#### Containment categories

- Isolate hosts showing the CloudSync working directory or the MSBuild injection chain
- Block the operator C2 estate at the perimeter, treating the addresses as perishable
- Audit remote-management software inventory, including software nobody deployed
- Review remote-desktop connection logs for operator session identifiers and times
- Treat any shared perimeter as in scope, not just the host where the artifact was found

---

## 14. Confidence Summary and Evidence Gaps

| Finding | Confidence |
|---|---|
| CloudSync is one builder's output across five samples | DEFINITE |
| CloudSync's language and toolchain (C++, MinGW-w64, GCC) | DEFINITE |
| The Winlogon `SpecialAccounts\UserList` hidden-account write | DEFINITE |
| `ab.exe` targeted a German healthcare provider's AD domain, with intent to create a forest-level backdoor | DEFINITE |
| Every C2 endpoint in the map | HIGH to DEFINITE |
| `v.exe` has no file-encryption capability | HIGH (near-DEFINITE) |
| The earlier-to-later build ordering across compiler generations | HIGH |
| The per-victim onion, local panel and Telegram notify architecture has no public documentation | HIGH |
| Two toolchains staged from one operator-controlled directory | HIGH |
| The assembler characterization | HIGH (~85%) |
| The toolkit uses the Paralell loader family | HIGH (~88%) |
| Blind Eagle is not the operator | HIGH as a negative (~90%) |
| GDLockerSec is not the operator | HIGH as a negative (~90%) |
| Larva-26009 has no connection beyond a shared circulating web shell | HIGH as a negative (~90%) |
| Sharp4WebCmd, the Paralell loader and the panel skin are sourced components | DEFINITE to HIGH |
| The Paralell family belongs to Blind Eagle | MODERATE (~75%) |
| The Telegram chat id maps to the GDLockerSec persona | MODERATE (~78%) |
| Operator achieved privileged Active Directory access | MODERATE |
| One individual operator authored and ran both toolchains | MODERATE |
| A shared builder-or-operator constant set, single operator versus sold builder | MODERATE, deliberately unresolved |
| `svhost.js` belongs to this operator rather than a co-staging second party | MODERATE |
| Initial access through internet-facing Exchange, with remote desktop co-equal | MODERATE |
| The operation's sequence, exposed server found before target selected | LOW |
| Attribution to any named threat actor as the operator | INSUFFICIENT (~15% or below per candidate) |

### The three that matter most, in plain terms

Targeting is DEFINITE and access is MODERATE, and the gap between those two words is the whole story. What is beyond doubt is that a specific German healthcare provider's Active Directory domain is compiled into a backdoor-creation command inside an operator tool. What is not established is whether the operator ever achieved the privileged access that command requires, or ever ran it. There is no victim-side telemetry, no second artifact tying to the organization, no reported incident, and no appearance on any leak site. The word I use is targeted.

Named-actor attribution is INSUFFICIENT by refutation rather than by absence, which is a stronger position than it sounds. Each of the three candidates is positively separated, so one more tool match will not overturn the conclusion.

The single-operator question is genuinely open and I am leaving it that way. The settling test exists, it was attempted, and it is blocked on a platform entitlement rather than on a lack of ideas.

### What is missing

- No second independent source exists for the Telegram chat id to persona mapping. That search turned up nothing, which sets a hard ceiling on this thread; the remaining paths to a second source are closed or edge into active operations.
- No independent source labels the Paralell family as Blind Eagle's. One vendor makes that call, and their own published sample carries generic engine labels with no threat-actor association.
- The Sharp4 tool family's broader origin is not established. No canonical repository or named author turned up across multiple search framings, so this is recorded as a gap rather than inferred from the naming convention.
- The settling test is not runnable with the available entitlement, and the operator's other builds may be absent from the corpus regardless.
- The 22-file inventory is a snapshot, not a complete enumeration. One CloudSync panel port was live with no matching build recovered, and a further sample communicating with the staging host was surfaced but never analyzed.
- An unresolved ASN discrepancy sits on the two dedicated C2 addresses, where two scanning platforms disagreed and the alternative attribution could not be reproduced.
- The CloudSync panel's current liveness is unresolved. It has not been passively observed since mid-July 2026, while the host's SSH service remained live. That is an open status question rather than a resolved rotation or takedown.
- A host-key reuse sweep is capped at 30 days by the platform, so a full historical sweep is infeasible with available tooling.
- `svhost.js` ownership is unresolved at MODERATE, leaving a two-operator co-staging alternative live. The assembler characterization is unaffected either way.
- The available characterization of GDLockerSec is roughly 18 months older than this campaign's build window, with no 2026 activity update found.

### Calibration, and the corrections that got made

This case reversed itself repeatedly and I would rather publish that record than a clean-looking narrative, because the reversals are where the useful lessons are.

The ransomware question needed real correction before it settled. I first asserted there was no locker anywhere in the toolkit, which was an absence claim made across a 22-file corpus on the strength of the two families I had written up, hours after discovering a third file I had not read properly. Then I over-corrected, reading Restart Manager and hybrid crypto signals against a packed binary as a ransomware capability profile, and proposed a detection rule around them. Both were wrong. The settled position rests on positive evidence, being the absence of six specific encryption APIs against the presence of their decryption counterparts, and a Restart Manager surface that only discovers file holders. Absence claims need the same coverage discipline as presence claims, and a capability inference from tags against a packed binary is not evidence.

The delivery chain was called operator-built before it was identified as sourced. The Paralell match forced retracting that, and it is the finding that turned this case into a report about assembly.

Three separate infrastructure calls were wrong on first read. A nameserver pivot that looked like operator infrastructure turned out to be a hosting provider's shared DNS. A second panel that looked like a sibling instance turned out to be a commodity template lookalike with a different operating system and no shared host key. And one of the operator's own C2 addresses was nearly dismissed on a shallow enrichment that labelled it benign. The lesson from that last one is the one worth keeping. Enrich before believing, and do not dismiss on a shallow or wrong enrichment either, because a one-line "clean" verdict nearly buried the operation's second C2.

A cross-toolchain link was fabricated and withdrawn. A shared scheduled-task template was claimed as evidence tying the two toolchains together, and a direct check across all 22 samples returned zero matches. It would have shipped a broken rule.

A build-specific string was nearly published as the family signature. The C2 terminator differs between build generations, and a rule keyed on the later one alone misses a build already in hand.

An evidence stack was over-counted. The Paralell match was presented as five distinctive points when four of them are properties of one shipped artifact. The confidence label survives on the strongest single item, and the count was the defect.

A confidence label that is not on the scale appeared 25 times across the investigation before it was caught. Everything in this report resolves to DEFINITE, HIGH, MODERATE, LOW or INSUFFICIENT.

A supporting detail was retracted without the conclusion collapsing. A server version reading that would have shown years-old unpatched software contradicted itself across sources and was withdrawn. The initial-access hypothesis rests on the operator's own behaviour rather than on a scanner's version string, so it survives the retraction, and I carry both the hypothesis and the withdrawn detail rather than quietly dropping one.

---

## 15. References

### Primary sources for kit provenance

- LevelBlue SpiderLabs (formerly Trustwave SpiderLabs), Serhii Melnyk, *"Still Circling: Blind Eagle's Toolkit Keeps Evolving"*, 2026-07-17. Tier 2. Source for the Paralell loader family, the base28 alphabet, the MSBuild injection rationale and the builder-as-a-service characterization.
- AhnLab ASEC, Sharp4WebCmd and Larva-26009 reporting, `asec.ahnlab.com/en/94685` and `asec.ahnlab.com/ko/94684/`, 2026-07-25. Tier 2. Source for the web shell's provenance and for the targeting comparison behind the explicit non-link.
- KELA Cyber, *"Is GDLockerSec Really Targeting AWS?"*, 2025-01-27. Tier 2. Sole published source for the Telegram chat id to persona mapping, and for the group's characterization and victim scale.
- MITRE ATT&CK Group G0099 (APT-C-36 / Blind Eagle). Tier 3. Used as a stable cross-vendor reference for the alias set and targeting profile.
- Hunt.io threat-actor catalogue and IP IOC corpus. Tier 2. Source for the 97-row APT-C-36 overlap test and for three independent confirmations that no GDLockerSec record exists.
- VirusTotal. Tier 1. Source for IP reports, threat-actor association negatives, and the entitlement testing that invalidated the retrohunt result.
- ransomware.live group tracker. Tier 4. Used only as a secondary victim-profile data point, never as an attribution basis.

### Regulatory and advisory context

- U.S. Department of the Treasury, OFAC press release SB0185 (Aeza Group designation), 2025-07-01, and the follow-up November 2025 action (SB0319). Tier 1, accessed through corroborating secondary reporting after the primary fetch was blocked. Used to establish that the hosting entity behind this operator's C2s is **not** among the designated entities.
- CISA, FBI and MS-ISAC joint advisory AA23-025A on remote monitoring and management software abuse, and CISA advisory AA24-109A on Akira ransomware. Tier 1, cited via secondary reporting that reproduces them. Used for the remote-management abuse pattern context in Section 6.

### Sourced tooling origins

- NetExec (`github.com/Pennyw0rth/NetExec`), the community continuation of CrackMapExec, originally authored by byt3bl33d3r.
- PrintSpoofer (`github.com/itm4n/PrintSpoofer`), itm4n (Clément Labro), published 2020-05-02.
- Nishang (`github.com/samratashok/nishang`), samratashok.
- chisel (`github.com/jpillora/chisel`), jpillora. Catalogued by Malpedia as `win.chisel` due to sustained abuse.
- bore (`github.com/ekzhang/bore`), ekzhang.
- Win32-OpenSSH (`github.com/PowerShell/Win32-OpenSSH`), Microsoft.
- PsExec, Sysinternals, Microsoft.
- Tor, The Tor Project.

### Companion publications

- [Detection rules for this campaign](/hunting-detections/cloudsync-assembler-toolkit-91-197-98-188-detections/), covering 7 YARA rules, 18 Sigma rules and 4 Suricata signatures.
- [Machine-readable IOC feed](/ioc-feeds/cloudsync-assembler-toolkit-91-197-98-188-iocs.json), TLP:CLEAR.

---

© 2026 Joseph, The Hunters Ledger. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), free to republish and adapt, including commercially, with attribution to The Hunters Ledger and a link to the original.
